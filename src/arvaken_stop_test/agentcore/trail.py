"""The run's own audit trail, for the moment a session was ended (`--trail`; arvaken/mark, AGENTCORE-MEASUREMENT.md,
section 4; the founder's five conditions, D618). Its setup is kept here, as code, so that a later measurement makes it
again the same way.

Why it is needed: Arvaken counts a run only where its firing moment comes from the cloud's own audit record (D569).
StopRuntimeSession is a call to AgentCore's data plane, which CloudTrail records as a data event, and its event history
holds management events alone. So a run that ends a session makes a trail of its own, records the call there, and
removes the trail when it is done.

The founder's conditions, each as the kit meets it:
1. **Data events only, for the test runtime's ARN alone**: one advanced event selector (selectors): the data category,
   AgentCore's runtime type, and `resources.ARN` equal to the run's runtime's. With advanced selectors, a trail logs no
   management events unless one asks for them; none does.
2. **Its bucket private and encrypted, public access blocked, writable only by CloudTrail** (bucket_policy): made as the
   run's own bucket is (stack.private_bucket), and its policy lets CloudTrail alone write, for this trail alone
   (`aws:SourceArn`), and denies every other write.
3. **Before the trail and its bucket are deleted, their records are copied and fingerprinted** (keep): logging is
   stopped, the kit waits until no more files arrive, then copies every object to a folder beside the result, with a
   SHA-256 of each in its SHA256SUMS, and reads each copy back against what it downloaded. Only then are the trail and
   its bucket deleted; where any of it fails, they are left, and named as left. Sealing the copies with the
   measurement's evidence is Arvaken's record's step. Log file validation is on, so any digest file CloudTrail delivers
   before the trail is deleted, signed by AWS, is copied with them.
4. **One trial run first**: a run's details say, for each repeat, whether its StopRuntimeSession was found in the
   trail's records and when, and count the trail's records by the call (run.py).
5. **Times as ranges**: CloudTrail's records are whole seconds, so a moment from them is taken as known to a second.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import time
from collections import Counter
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

from arvaken_stop_test.agentcore.stack import PREFIX, TAG, private_bucket

SOURCE = "bedrock-agentcore.amazonaws.com"
QUIET = 120.0               # seconds with no new file, after logging stops, before the records are copied
QUIET_LIMIT = 900.0         # and the longest the kit waits for that
POLL = 30.0


def names(run: str) -> dict[str, str]:
    return {"trail": f"{PREFIX}-{run}", "bucket": f"{PREFIX}-{run}-trail"}


def trail_arn(run: str, region: str, account: str, partition: str = "aws") -> str:
    return f"arn:{partition}:cloudtrail:{region}:{account}:trail/{names(run)['trail']}"


def selectors(runtime_arn: str) -> list[dict[str, Any]]:
    """Data events, of the run's runtime alone."""
    return [{"Name": "The stop test's runtime alone", "FieldSelectors": [
        {"Field": "eventCategory", "Equals": ["Data"]},
        {"Field": "resources.type", "Equals": ["AWS::BedrockAgentCore::Runtime"]},
        {"Field": "resources.ARN", "Equals": [runtime_arn]}]}]


def bucket_policy(run: str, region: str, account: str, partition: str = "aws") -> str:
    """CloudTrail may check the bucket and write this trail's files to it; no one else may write to it."""
    bucket = f"arn:{partition}:s3:::{names(run)['bucket']}"
    trail = trail_arn(run, region, account, partition)
    return json.dumps({"Version": "2012-10-17", "Statement": [
        {"Sid": "CloudTrailChecksTheBucket", "Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"},
         "Action": "s3:GetBucketAcl", "Resource": bucket, "Condition": {"StringEquals": {"aws:SourceArn": trail}}},
        {"Sid": "CloudTrailWritesThisTrailsFiles", "Effect": "Allow",
         "Principal": {"Service": "cloudtrail.amazonaws.com"}, "Action": "s3:PutObject",
         "Resource": f"{bucket}/AWSLogs/{account}/*",
         "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control", "aws:SourceArn": trail}}},
        {"Sid": "NoOneElseWrites", "Effect": "Deny", "Principal": "*", "Action": "s3:PutObject",
         "Resource": f"{bucket}/*", "Condition": {"StringNotEquals": {"aws:SourceArn": trail}}}]},
        separators=(",", ":"))


def make(cloudtrail: Any, s3: Any, run: str, region: str, account: str, runtime_arn: str,
         partition: str = "aws") -> dict[str, str]:
    """The trail and its bucket, logging the runtime's data events. Returns their names."""
    n = names(run)
    private_bucket(s3, n["bucket"], region, run)
    s3.put_bucket_policy(Bucket=n["bucket"], Policy=bucket_policy(run, region, account, partition))
    cloudtrail.create_trail(Name=n["trail"], S3BucketName=n["bucket"], IsMultiRegionTrail=False,
                            IncludeGlobalServiceEvents=False, EnableLogFileValidation=True,
                            TagsList=[{"Key": TAG, "Value": run}])
    cloudtrail.put_event_selectors(TrailName=n["trail"], AdvancedEventSelectors=selectors(runtime_arn))
    cloudtrail.start_logging(Name=n["trail"])
    return n


def listed(s3: Any, bucket: str) -> dict[str, int]:
    """Every object in the bucket, by its key, with its size."""
    found: dict[str, int] = {}
    token = None
    while True:
        page = s3.list_objects_v2(Bucket=bucket, **({"ContinuationToken": token} if token else {}))
        found.update({o["Key"]: o["Size"] for o in page.get("Contents", [])})
        token = page.get("NextContinuationToken")
        if not token:
            return found


def records(s3: Any, bucket: str) -> list[dict[str, Any]]:
    """Every record in the trail's log files (not its digests)."""
    out: list[dict[str, Any]] = []
    for key in sorted(listed(s3, bucket)):
        if "/CloudTrail/" in key and key.endswith(".json.gz"):
            body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
            out += json.loads(gzip.decompress(body)).get("Records", [])
    return out


def _at(t: str) -> float:
    return datetime.fromisoformat(t.replace("Z", "+00:00")).timestamp()


def find(found: list[dict[str, Any]], event: str, session: str, before: float, after: float) -> float | None:
    """The time of AgentCore's record of `event` on the session, made between the kit's two readings around its call
    (five seconds either side, for the clocks); None if there is none."""
    for e in found:
        params = e.get("requestParameters") or {}
        if e.get("eventSource") != SOURCE or e.get("eventName") != event:
            continue
        if params.get("runtimeSessionId") not in (None, session):
            continue
        at = _at(e["eventTime"])
        if before - 5 <= at <= after + 5:
            return at
    return None


def counted(found: list[dict[str, Any]]) -> dict[str, int]:
    """The trail's records by the call, and by whether AWS refused it, for the details."""
    return dict(Counter(e.get("eventName", "") + (f" ({e['errorCode']})" if e.get("errorCode") else "")
                        for e in found))


def _code(e: Exception) -> str:
    return str(getattr(e, "response", {}).get("Error", {}).get("Code") or type(e).__name__)


def _unless(codes: set[str], call: Callable[[], Any]) -> Any:
    """The call, where a thing never made, or already gone, answers with one of `codes`: then None."""
    try:
        return call()
    except Exception as e:
        if _code(e) not in codes:
            raise
        return None


def keep(cloudtrail: Any, s3: Any, run: str, folder: Path, now: Callable[[], float] = time.time,
         sleep: Callable[[float], None] = time.sleep, quiet: float = QUIET,
         limit: float = QUIET_LIMIT) -> dict[str, Any]:
    """Stop logging, wait until no new file has come for `quiet` seconds (up to `limit`), then copy every object to
    `folder`, with SHA256SUMS, each copy read back against what was downloaded. Returns what was kept. A trail or bucket
    an interrupted run never made has nothing to keep."""
    n = names(run)
    _unless({"TrailNotFoundException"}, lambda: cloudtrail.stop_logging(Name=n["trail"]))
    seen = _unless({"NoSuchBucket"}, lambda: listed(s3, n["bucket"]))
    if seen is None:
        return {"folder": None, "files": 0, "sha256sums": None}
    end, since = now() + limit, now()
    while now() < end and now() - since < quiet:
        sleep(POLL)
        again = listed(s3, n["bucket"])
        if again != seen:
            seen, since = again, now()
    folder.mkdir(parents=True, exist_ok=True)
    sums, found = [], []
    for key in sorted(seen):
        if key.endswith("/"):           # a folder CloudTrail marks with an empty object (AWSLogs/<account>/...)
            folder.joinpath(*key.split("/")).mkdir(parents=True, exist_ok=True)
            sums.append(f"{hashlib.sha256(b'').hexdigest()}  {key}\n")
            continue
        body = s3.get_object(Bucket=n["bucket"], Key=key)["Body"].read()
        path = folder.joinpath(*key.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
        if path.read_bytes() != body or len(body) != seen[key]:
            raise OSError(f"the copy of {key} does not read back as it was downloaded")
        sums.append(f"{hashlib.sha256(body).hexdigest()}  {key}\n")
        if "/CloudTrail/" in key and key.endswith(".json.gz"):
            found += json.loads(gzip.decompress(body)).get("Records", [])
    text = "".join(sums).encode("utf-8")
    (folder / "SHA256SUMS").write_bytes(text)
    return {"folder": folder.as_posix(), "files": len(sums), "sha256sums": hashlib.sha256(text).hexdigest(),
            "records": counted(found)}


def remove(cloudtrail: Any, s3: Any, run: str) -> None:
    """Delete the trail, then empty and delete its bucket. Call only once its records are kept."""
    n = names(run)
    _unless({"TrailNotFoundException"}, lambda: cloudtrail.delete_trail(Name=n["trail"]))
    while True:
        keys = list(_unless({"NoSuchBucket"}, lambda: listed(s3, n["bucket"])) or {})[:1000]
        if not keys:
            break
        s3.delete_objects(Bucket=n["bucket"], Delete={"Objects": [{"Key": k} for k in keys]})
    _unless({"NoSuchBucket"}, lambda: s3.delete_bucket_policy(Bucket=n["bucket"]))
    _unless({"NoSuchBucket"}, lambda: s3.delete_bucket(Bucket=n["bucket"]))
