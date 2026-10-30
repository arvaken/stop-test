"""The stop test on AgentCore (agentcore/; arvaken/mark, AGENTCORE-MEASUREMENT.md; D618), against a fake AWS.

The fake holds what the run depends on, as this file's own assumptions, not AWS's behaviour: a policy on the runtime's
role denies the session's own calls DELAY seconds after the call; the runtime's resource policy refuses new calls
DENY_DELAY seconds after it is written and, with `linger`, still refuses one in ten of the `linger` new calls after its
removal (in r58051bd3, 29 October 2026, a removed deny went on refusing some new calls for minutes); with
`writes_after_close`, a session whose stream the kit closed goes on writing to the run's bucket until its watch ends, as
sessions did in rbfb0d77a and rcd4c16ca; StopRuntimeSession ends the session and its stream at once; CloudTrail's event
history shows a management call TRAIL_DELAY seconds after it, IAM's in us-east-1 and AgentCore's in the run's region; a
trail delivers its data events to its bucket DELIVERY seconds after each. StopRuntimeSession on a session already ended
is refused as ResourceNotFoundException (`ended_answer`): the kit's confirmation, which Arvaken's trial checks against
AWS (the founder, 30 October 2026).

What a deny of calls does to a session already running, AWS's pages do not say (the founder, 28 October 2026: no AWS
claim either way). It is what the run measures. The fake leaves the stream open by default, and with
`deny_cuts_stream=True` ends it once the deny refuses calls; the run is tested both ways.

The running session's stream is the fake's own (FakeStream), polled on the run's fake clock; the real stream is tested
on its own, against bytes as AgentCore sends them (test_the_stream_*), and the agent against its own server.
"""
from __future__ import annotations

import copy
import gzip
import hashlib
import io
import json
import re
import threading
import urllib.parse
import urllib.request
from concurrent.futures import Future
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from arvaken_stop_test import report, result
from arvaken_stop_test.agentcore import agent, fire, stack, trail
from arvaken_stop_test.agentcore import run as running
from arvaken_stop_test.aws.stack import boundary_document

T0 = 1_761_620_000.0
ACCOUNT, REGION = "111122223333", "eu-central-1"
DENY_ALL = "arn:aws:iam::aws:policy/AWSDenyAll"
ENDPOINT = "https://stop-test.example"
DELAY, DENY_DELAY, TRAIL_DELAY, DELIVERY = 8.0, 3.0, 120.0, 300.0
TRAIL_START = 151.0             # a new trail's first data event came 2 minutes 31 seconds after logging began
SKEW = 0.05                     # the agent's clock ahead of the kit's


class Error(Exception):
    def __init__(self, code: str, message: str = ""):
        super().__init__(message or code)
        self.response = {"Error": {"Code": code, "Message": message}}


class Clock:
    def __init__(self):
        self.t = T0

    def now(self) -> float:
        return self.t

    def sleep(self, d: float) -> None:
        self.t += d


class Inline:
    """An executor that makes each call at once, on the fake clock."""

    def submit(self, fn):
        f = Future()
        fn()
        f.set_result(None)
        return f

    def shutdown(self, wait=True, cancel_futures=False):
        pass


def _iso(t: float) -> str:
    return datetime.fromtimestamp(int(t), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class FakeStream:
    def __init__(self, aws, c, r, session, seconds, clock):
        self.aws, self.r, self.session, self.clock = aws, r, session, clock
        self.start, self.end = clock.now(), clock.now() + seconds
        self.next, self.n, self.ended, self.sent_first = clock.now() + 1.0, 0, None, False
        aws.sessions[session] = {"ended": None}

    def poll(self):
        out = []
        if not self.sent_first:
            out.append({"at": self.start + SKEW, "session_expires": self.start + 3600 + SKEW})
            self.sent_first = True
        while self.next <= self.clock.now() and self.next <= self.end:
            t = self.next
            ended = self.aws.sessions[self.session]["ended"]
            if self.aws.deny_cuts_stream and self.aws.deny_in_effect(t):
                cut = self.aws.runtime["policy_at"] + DENY_DELAY
                ended = cut if ended is None else min(ended, cut)
            if self.aws.breaks_in is not None and t >= self.start + self.aws.breaks_in:
                if self.ended is None:
                    self.ended = (self.start + self.aws.breaks_in, "ResponseStreamingError")
            if ended is not None and t >= ended:
                if self.ended is None:
                    self.ended = (ended, "ResponseStreamingError")
                if not self.aws.writes_after_end:
                    break
            if self.aws.dies_in is not None and t >= self.start + self.aws.dies_in:
                if self.ended is None:
                    self.ended = (self.start + self.aws.dies_in, "RuntimeClientError")
                break
            own = not self.aws.role_denied(t)
            if own:
                self.aws.buckets[stack.names(self.r.run)["bucket"]][f"own/{self.session}/{self.n}"] = (b"x", t + SKEW)
            if self.ended is None:
                out.append({"at": t + SKEW, "n": self.n, "beats": {
                    "own_calls": {"at": t + SKEW, "ok": own, **({} if own else {"error": "AccessDenied"})},
                    "another_identity": {"at": t + SKEW, "ok": True},
                    "outside_key": {"at": t + SKEW, "ok": True},
                    "open_internet": {"at": t + SKEW, "ok": True}}})
            self.n += 1
            self.next += 1.0
        return out

    def close(self):
        if self.aws.writes_after_close and self.ended is None:
            self.aws.writing.append(self)


class FakeAWS:
    def __init__(self, clock: Clock, *, boundary=True, trail_records_stop=True, deny_cuts_stream=False,
                 trail_records=True, ended_answer="ResourceNotFoundException"):
        self.clock = clock
        self.ended_answer = ended_answer          # StopRuntimeSession's answer for a session already ended; None: done
        self.roles: dict[str, dict] = {}
        self.buckets: dict[str, dict[str, tuple[bytes, float]]] = {}
        self.bucket_policies: dict[str, str] = {}
        self.runtime: dict | None = None
        self.runtime_history: list[dict] = []
        self.identity_left = False
        self.sessions: dict[str, dict] = {}
        self.events: list[dict] = []            # management calls, as event history shows them
        self.data_events: list[dict] = []
        self.delivered = 0
        self.trail: dict | None = None
        self.trail_history: list[dict] = []
        self.boundary = boundary
        self.deny_cuts_stream = deny_cuts_stream
        self.trail_records_stop = trail_records_stop
        self.trail_records = trail_records
        # seconds after a session opens: its stream breaks while the session goes on; or the session dies
        self.breaks_in: float | None = None
        self.dies_in: float | None = None
        self.new_calls: list[tuple[float, bool]] = []
        self.invoke_error: str | None = None
        # how many new calls after a deny's removal it still refuses one in ten of
        self.linger = 0
        self.lingering = 0
        self.removed_at: list[float] = []
        # a session whose stream the kit closed goes on with its watch, writing every second, until it ends
        self.writes_after_close = False
        self.writes_after_end = False           # a session that goes on writing after AWS ended it: the cross-check
        self.writing: list[FakeStream] = []
        self.last_write: float | None = None
        self.bucket_deleted_at: float | None = None

    # -- what the fake decides
    def role_denied(self, t: float) -> bool:
        role = self.roles.get(stack.names(self.run)["agent_role"])
        if not role:
            return False
        fired = [at for name, at in role["inline_at"].items() if name == fire.INLINE] + \
                [at for arn, at in role["attached_at"].items() if arn == DENY_ALL]
        return any(t >= at + DELAY for at in fired)

    def deny_in_effect(self, t: float) -> bool:
        at = self.runtime.get("policy_at") if self.runtime else None
        return at is not None and t >= at + DENY_DELAY

    @property
    def run(self) -> str:
        return self._run

    # -- sts
    def get_caller_identity(self):
        return {"Account": ACCOUNT, "Arn": f"arn:aws:iam::{ACCOUNT}:user/tester"}

    # -- iam
    def get_policy(self, PolicyArn):
        if PolicyArn.endswith(":policy/arvaken-stop-test-boundary") and not self.boundary:
            raise Error("NoSuchEntity")
        return {"Policy": {"DefaultVersionId": "v1"}}

    def get_policy_version(self, PolicyArn, VersionId):
        if PolicyArn.endswith(":policy/arvaken-stop-test-boundary"):
            return {"PolicyVersion": {"Document": json.dumps(boundary_document())}}
        return {"PolicyVersion": {"Document": '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*",'
                                              '"Resource":"*"}]}'}}

    def simulate_custom_policy(self, PolicyInputList, ActionNames, ResourceArns):
        return {"EvaluationResults": [{"EvalActionName": a, "EvalDecision": "explicitDeny"} for a in ActionNames]}

    def create_role(self, RoleName, AssumeRolePolicyDocument, PermissionsBoundary, Tags):
        self.roles[RoleName] = {"trust": json.loads(AssumeRolePolicyDocument), "boundary": PermissionsBoundary,
                                "tags": {t["Key"]: t["Value"] for t in Tags}, "inline": {}, "attached": set(),
                                "inline_at": {}, "attached_at": {}}
        return {"Role": {"Arn": f"arn:aws:iam::{ACCOUNT}:role/{RoleName}"}}

    def _role(self, RoleName):
        if RoleName not in self.roles:
            raise Error("NoSuchEntity")
        return self.roles[RoleName]

    def put_role_policy(self, RoleName, PolicyName, PolicyDocument):
        role = self._role(RoleName)
        role["inline"][PolicyName] = json.loads(PolicyDocument)
        role["inline_at"][PolicyName] = self.clock.now()
        self.events.append({"region": "us-east-1", "name": "PutRolePolicy", "at": self.clock.now(),
                            "resource": RoleName, "params": {"roleName": RoleName}})

    def delete_role_policy(self, RoleName, PolicyName):
        role = self._role(RoleName)
        role["inline"].pop(PolicyName)
        role["inline_at"].pop(PolicyName, None)

    def list_role_policies(self, RoleName):
        return {"PolicyNames": sorted(self._role(RoleName)["inline"])}

    def attach_role_policy(self, RoleName, PolicyArn):
        role = self._role(RoleName)
        role["attached"].add(PolicyArn)
        role["attached_at"][PolicyArn] = self.clock.now()
        self.events.append({"region": "us-east-1", "name": "AttachRolePolicy", "at": self.clock.now(),
                            "resource": RoleName, "params": {"roleName": RoleName}})

    def detach_role_policy(self, RoleName, PolicyArn):
        role = self._role(RoleName)
        role["attached"].discard(PolicyArn)
        role["attached_at"].pop(PolicyArn, None)

    def list_attached_role_policies(self, RoleName):
        return {"AttachedPolicies": [{"PolicyArn": a} for a in sorted(self._role(RoleName)["attached"])]}

    def list_role_tags(self, RoleName):
        return {"Tags": [{"Key": k, "Value": v} for k, v in self._role(RoleName)["tags"].items()]}

    def get_role(self, RoleName):
        return {"Role": self._role(RoleName)}

    def delete_role(self, RoleName):
        role = self._role(RoleName)
        if role["inline"] or role["attached"]:
            raise Error("DeleteConflict")
        del self.roles[RoleName]

    # -- s3
    def create_bucket(self, Bucket, **kw):
        self.buckets[Bucket] = {}

    def put_public_access_block(self, Bucket, PublicAccessBlockConfiguration):
        assert all(PublicAccessBlockConfiguration.values())

    def put_bucket_encryption(self, Bucket, ServerSideEncryptionConfiguration):
        pass

    def put_bucket_tagging(self, Bucket, Tagging):
        pass

    def put_bucket_policy(self, Bucket, Policy):
        self.bucket_policies[Bucket] = Policy

    def delete_bucket_policy(self, Bucket):
        self._bucket(Bucket)
        self.bucket_policies.pop(Bucket, None)

    def _bucket(self, Bucket):
        self._keep_writing()
        if Bucket not in self.buckets:
            raise Error("NoSuchBucket")
        self._deliver()
        return self.buckets[Bucket]

    def _keep_writing(self, one_more: bool = False) -> None:
        """What the sessions still writing have written by now; with `one_more`, the write a session still writing
        puts in the bucket before a DeleteBucket gets there."""
        if not self.writing:
            return
        bucket = self.buckets.get(stack.names(self.run)["bucket"])
        for s in self.writing:
            ended = self.sessions[s.session]["ended"]
            until = min(s.end, ended if ended is not None else s.end)
            times = []
            while s.next <= min(until, self.clock.now()):
                times.append(s.next)
                s.next += 1.0
            if one_more and self.clock.now() < until:
                times.append(self.clock.now())
            for t in times:
                if bucket is None:
                    continue
                if not self.role_denied(t):
                    bucket[f"own/{s.session}/{s.n}"] = (b"x", t + SKEW)
                bucket[f"another/{s.session}/{s.n}"] = (b"x", t + SKEW)
                s.n += 1
                self.last_write = t

    def put_object(self, Bucket, Key, Body):
        self._bucket(Bucket)[Key] = (Body, self.clock.now())

    def get_object(self, Bucket, Key):
        return {"Body": io.BytesIO(self._bucket(Bucket)[Key][0])}

    def head_object(self, Bucket, Key):
        if Key not in self._bucket(Bucket):
            raise Error("404")

    def head_bucket(self, Bucket):
        self._bucket(Bucket)

    def list_objects_v2(self, Bucket, Prefix="", ContinuationToken=None):
        found = sorted((k, v) for k, v in self._bucket(Bucket).items() if k.startswith(Prefix))
        start = int(ContinuationToken or 0)
        page = found[start:start + 1000]
        out = {"Contents": [{"Key": k, "Size": len(v[0]),
                             "LastModified": datetime.fromtimestamp(v[1], tz=timezone.utc)} for k, v in page]}
        if start + 1000 < len(found):
            out["NextContinuationToken"] = str(start + 1000)
        return out

    def delete_objects(self, Bucket, Delete):
        for o in Delete["Objects"]:
            self._bucket(Bucket).pop(o["Key"], None)

    def delete_bucket(self, Bucket):
        self._keep_writing(one_more=True)
        if self._bucket(Bucket):
            raise Error("BucketNotEmpty")
        del self.buckets[Bucket]
        self.bucket_deleted_at = self.clock.now()

    # -- bedrock-agentcore-control
    def create_agent_runtime(self, **req):
        rid = f"{req['agentRuntimeName']}-AbCdE12345"
        self.runtime = {"id": rid, "arn": f"arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT}:runtime/{rid}",
                        "name": req["agentRuntimeName"], "tags": dict(req["tags"]), "status": "CREATING",
                        "policy": None, "policy_at": None, "request": req}
        self.runtime_history.append(self.runtime)
        return {"agentRuntimeArn": self.runtime["arn"], "agentRuntimeId": rid, "agentRuntimeVersion": "1",
                "status": "CREATING", "workloadIdentityDetails": {"workloadIdentityArn": (
                    f"arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT}:workload-identity-directory/default/"
                    f"workload-identity/{rid}")}}

    def _runtime(self, rid=None, arn=None):
        if self.runtime is None or (rid and rid != self.runtime["id"]) or (arn and arn != self.runtime["arn"]):
            raise Error("ResourceNotFoundException")
        return self.runtime

    def get_agent_runtime(self, agentRuntimeId):
        rt = self._runtime(rid=agentRuntimeId)
        status, rt["status"] = rt["status"], "READY"
        return {"status": status, "agentRuntimeArn": rt["arn"]}

    def list_agent_runtimes(self, nextToken=None):
        return {"agentRuntimes": [] if self.runtime is None else [
            {"agentRuntimeName": self.runtime["name"], "agentRuntimeId": self.runtime["id"],
             "agentRuntimeArn": self.runtime["arn"]}]}

    def list_agent_runtime_endpoints(self, agentRuntimeId):
        self._runtime(rid=agentRuntimeId)
        return {"runtimeEndpoints": [{"name": "DEFAULT"}]}

    def delete_agent_runtime(self, agentRuntimeId):
        self._runtime(rid=agentRuntimeId)
        self.runtime = None

    def get_workload_identity(self, name):
        if not self.identity_left:
            raise Error("ResourceNotFoundException")

    def delete_workload_identity(self, name):
        self.identity_left = False

    def list_tags_for_resource(self, resourceArn):
        return {"tags": self._runtime(arn=resourceArn)["tags"]}

    def put_resource_policy(self, resourceArn, policy):
        rt = self._runtime(arn=resourceArn)
        rt["policy"], rt["policy_at"] = json.loads(policy), self.clock.now()
        self.events.append({"region": REGION, "name": "PutResourcePolicy", "at": self.clock.now(),
                            "resource": resourceArn,
                            "params": {"resourceArn": urllib.parse.quote(resourceArn, safe="")}})

    def get_resource_policy(self, resourceArn):
        rt = self._runtime(arn=resourceArn)
        if rt["policy"] is None:
            raise Error("ResourceNotFoundException")
        return {"policy": json.dumps(rt["policy"])}

    def delete_resource_policy(self, resourceArn):
        rt = self._runtime(arn=resourceArn)
        if rt["policy"] is None:
            raise Error("ResourceNotFoundException")
        rt["policy"], rt["policy_at"] = None, None
        self.lingering = self.linger
        self.removed_at.append(self.clock.now())

    # -- bedrock-agentcore
    def invoke_agent_runtime(self, agentRuntimeArn, runtimeSessionId, qualifier, contentType, accept, payload):
        now = self.clock.now()
        if self.invoke_error:
            raise Error(self.invoke_error)
        rt = self._runtime(arn=agentRuntimeArn)
        assert len(runtimeSessionId) >= 33 and json.loads(payload) == {"action": "answer"}
        denied = self.deny_in_effect(now)
        if not denied and self.lingering:       # the removed deny still refuses every tenth call
            self.lingering -= 1
            denied = (self.linger - self.lingering) % 10 == 0
        self._data("InvokeAgentRuntime", runtimeSessionId, now, "AccessDenied" if denied else None)
        self.new_calls.append((now, not denied))
        if denied:
            raise Error("AccessDeniedException")
        assert rt["status"] == "READY"
        return {"response": io.BytesIO(json.dumps({"at": now + SKEW}).encode())}

    def stop_runtime_session(self, agentRuntimeArn, runtimeSessionId, qualifier):
        self._runtime(arn=agentRuntimeArn)
        if self.sessions[runtimeSessionId].get("ended") is not None:
            if self.ended_answer:
                raise Error(self.ended_answer)
            return
        self.sessions[runtimeSessionId]["ended"] = self.clock.now()
        if self.trail_records_stop:
            self._data("StopRuntimeSession", runtimeSessionId, self.clock.now(), None)

    def _data(self, name, session, at, error):
        if self.trail and self.trail["logging"] and self.trail_records and at >= self.trail["started"] + TRAIL_START:
            self.data_events.append({"eventSource": "bedrock-agentcore.amazonaws.com", "eventName": name,
                                     "eventTime": _iso(at), "requestParameters": None,
                                     **({"errorCode": error} if error else {}), "_at": at})

    def _deliver(self):
        if not self.trail:
            return
        due = [e for e in self.data_events if e["_at"] + DELIVERY <= self.clock.now()]
        if not due:
            return
        self.data_events = [e for e in self.data_events if e not in due]
        self.delivered += 1
        key = (f"AWSLogs/{ACCOUNT}/CloudTrail/{REGION}/2026/10/28/"
               f"{ACCOUNT}_CloudTrail_{REGION}_{self.delivered:04d}.json.gz")
        body = gzip.compress(json.dumps({"Records": [{k: v for k, v in e.items() if k != "_at"} for e in due]})
                             .encode(), mtime=0)
        self.buckets[self.trail["bucket"]][key] = (body, self.clock.now())

    # -- cloudtrail: event history, and the run's trail
    def lookup_events_in(self, region, LookupAttributes, StartTime, EndTime):
        [attribute] = LookupAttributes
        out = []
        for e in self.events:
            if e["region"] != region or not StartTime <= e["at"] <= EndTime or e["at"] + TRAIL_DELAY > self.clock.now():
                continue
            if attribute["AttributeKey"] == "ResourceName" and attribute["AttributeValue"] != e["resource"]:
                continue
            if attribute["AttributeKey"] == "EventName" and attribute["AttributeValue"] != e["name"]:
                continue
            out.append({"EventName": e["name"], "EventTime": datetime.fromtimestamp(int(e["at"]), tz=timezone.utc),
                        "CloudTrailEvent": json.dumps({"requestParameters": e["params"]})})
        return {"Events": out}

    def create_trail(self, Name, S3BucketName, IsMultiRegionTrail, IncludeGlobalServiceEvents,
                     EnableLogFileValidation, TagsList):
        assert S3BucketName in self.buckets and S3BucketName in self.bucket_policies
        self.trail = {"name": Name, "bucket": S3BucketName, "logging": False, "selectors": None,
                      "validation": EnableLogFileValidation, "multi": IsMultiRegionTrail,
                      "global": IncludeGlobalServiceEvents}
        self.trail_history.append(self.trail)
        for marker in ("CloudTrail/", "CloudTrail-Digest/"):     # as CloudTrail marks them, with empty objects
            self.buckets[S3BucketName][f"AWSLogs/{ACCOUNT}/{marker}"] = (b"", self.clock.now())

    def put_event_selectors(self, TrailName, AdvancedEventSelectors):
        self.trail["selectors"] = AdvancedEventSelectors

    def start_logging(self, Name):
        self.trail["logging"], self.trail["started"] = True, self.clock.now()

    def stop_logging(self, Name):
        if not self.trail:
            raise Error("TrailNotFoundException")
        self.trail["logging"] = False

    def get_trail(self, Name):
        if not self.trail:
            raise Error("TrailNotFoundException")

    def delete_trail(self, Name):
        if not self.trail:
            raise Error("TrailNotFoundException")
        self.trail = None

    # -- tagging, logs
    def get_resources(self, TagFilters):
        return {"ResourceTagMappingList": []}

    def describe_log_groups(self, logGroupNamePrefix):
        return {"logGroups": []}


class Regional:
    """A view of the fake's CloudTrail from one region."""

    def __init__(self, aws: FakeAWS, region: str):
        self.aws, self.region = aws, region

    def lookup_events(self, **kw):
        return self.aws.lookup_events_in(self.region, **kw)

    def __getattr__(self, name):
        return getattr(self.aws, name)


def clients(aws: FakeAWS) -> running.Clients:
    return running.Clients(iam=aws, s3=aws, control=aws, data=aws, cloudtrail=Regional(aws, REGION),
                           iam_trail=Regional(aws, "us-east-1"), tagging=aws, region=REGION, logs=aws, sts=aws,
                           stream=lambda c, r, session, seconds, clock: FakeStream(aws, c, r, session, seconds, clock),
                           executor=Inline)


def a_run(aws: FakeAWS, clock: Clock, stop: str, tmp_path: Path | None = None, **over):
    run_name = over.pop("run_name", "r0a1b2c3d")
    aws._run = run_name
    return running.run(clients(aws), stop, endpoint=ENDPOINT, window=over.pop("window", 120.0), clock=clock,
                       run_name=run_name, trail_folder=(tmp_path / "trail") if tmp_path else None, **over)


def outcomes(doc: dict, i: int = 0) -> dict[str, str]:
    return {p: part["outcome"] for p, part in doc["repeats"][i].items()}


def test_deny_and_end_refuses_new_calls_from_the_deny_and_ends_the_session_from_its_own_moment(tmp_path):
    clock = Clock()
    aws = FakeAWS(clock)
    r, doc = a_run(aws, clock, fire.DENY_AND_END, tmp_path, trail=True)
    assert result.check(doc) is doc
    assert doc["stop"] == {"kind": "deny calls to an AgentCore agent and end its sessions", "fired_by": "the kit",
                           "ref": fire.DENY_AND_END}
    assert doc["agent"]["kind"] == "aws-agentcore-runtime" and doc["agent"]["runtime"] == "PYTHON_3_13"
    assert outcomes(doc) == {p: "stopped" for p in running.PATHS}
    d = running.details(r, doc)
    rep = d["repeats"][0]
    # new calls from the deny, in event history; the session's paths from StopRuntimeSession, in the run's trail
    assert rep["new_calls"]["fired_source"] == running.AUDIT_RECORD
    assert all(rep[p]["fired_source"] == running.TRAIL_RECORD for p in running.SESSION_PATHS)
    assert all(rep[p]["fired_source"].startswith("CloudTrail's record of the call") for p in running.PATHS)
    low, high = rep["new_calls"]["effect_between_seconds"]
    assert 0 <= low <= DENY_DELAY <= high <= DENY_DELAY + 2
    assert all(rep[p]["successes_after_first_refusal"] == 0 for p in running.PATHS)
    assert d["trail"]["end_session_found"] == [True]
    assert d["trail"]["records"]["StopRuntimeSession"] == 1
    assert d["trail"]["records"]["InvokeAgentRuntime (AccessDenied)"] > 100
    assert d["sessions"][0]["stream_ended_by"] == "ResponseStreamingError"
    assert d["sessions"][0]["writes_after_stream_ended"] == 0


def test_the_trails_records_are_kept_and_fingerprinted_before_it_and_its_bucket_are_deleted(tmp_path):
    clock = Clock()
    aws = FakeAWS(clock)
    r, doc = a_run(aws, clock, fire.DENY_AND_END, tmp_path, trail=True)
    kept = r.trail_kept
    folder = tmp_path / "trail"
    sums = (folder / "SHA256SUMS").read_bytes()
    assert kept["files"] >= 1 and kept["sha256sums"] == hashlib.sha256(sums).hexdigest()
    for line in sums.decode().splitlines():
        digest, key = line.split("  ")
        if key.endswith("/"):           # CloudTrail's empty marker of a folder, kept as the folder
            assert folder.joinpath(*key.split("/")).is_dir() and digest == hashlib.sha256(b"").hexdigest()
            continue
        assert hashlib.sha256(folder.joinpath(*key.split("/")).read_bytes()).hexdigest() == digest
    assert aws.trail is None and trail.names(r.run)["bucket"] not in aws.buckets
    assert not doc["run"]["left_anything"]
    assert {f"the trail {trail.names(r.run)['trail']}", f"the bucket {trail.names(r.run)['bucket']}"} <= \
        set(r.checked_gone)


def test_the_trail_records_the_runtimes_data_events_alone_into_a_bucket_only_cloudtrail_writes(tmp_path):
    clock = Clock()
    aws = FakeAWS(clock)
    r, _ = a_run(aws, clock, fire.DENY_AND_END, tmp_path, trail=True)
    [made] = aws.trail_history
    assert made["selectors"] == [{"Name": "The stop test's runtime alone", "FieldSelectors": [
        {"Field": "eventCategory", "Equals": ["Data"]},
        {"Field": "resources.type", "Equals": ["AWS::BedrockAgentCore::Runtime"]},
        {"Field": "resources.ARN", "Equals": [r.outputs["Runtime"]]}]},
        # and the run's bucket's objects alone, for the cross-check after a session ended (the founder, 30 Oct 2026)
        {"Name": "The stop test's bucket's objects alone", "FieldSelectors": [
            {"Field": "eventCategory", "Equals": ["Data"]},
            {"Field": "resources.type", "Equals": ["AWS::S3::Object"]},
            {"Field": "resources.ARN", "StartsWith": [f"arn:aws:s3:::{stack.names(r.run)['bucket']}/"]}]}]
    assert made["validation"] and not made["multi"] and not made["global"]
    policy = json.loads(trail.bucket_policy(r.run, REGION, ACCOUNT))
    arn = trail.trail_arn(r.run, REGION, ACCOUNT)
    allows = [s for s in policy["Statement"] if s["Effect"] == "Allow"]
    assert all(s["Principal"] == {"Service": "cloudtrail.amazonaws.com"} and
               s["Condition"]["StringEquals"]["aws:SourceArn"] == arn for s in allows)
    [deny] = [s for s in policy["Statement"] if s["Effect"] == "Deny"]
    assert deny == {"Sid": "NoOneElseWrites", "Effect": "Deny", "Principal": "*", "Action": "s3:PutObject",
                    "Resource": f"arn:aws:s3:::{trail.names(r.run)['bucket']}/*",
                    "Condition": {"StringNotEquals": {"aws:SourceArn": arn}}}


def test_a_deny_alone_refuses_new_calls_and_the_running_session_keeps_going(tmp_path):
    clock = Clock()
    aws = FakeAWS(clock)
    r, doc = a_run(aws, clock, fire.DENY)
    assert doc["stop"]["kind"] == "deny calls to an AgentCore agent"
    assert outcomes(doc) == {"own_calls": "not stopped", "another_identity": "not stopped",
                             "outside_key": "not stopped", "open_internet": "not stopped", "new_calls": "stopped"}
    d = running.details(r, doc)
    assert d["repeats"][0]["another_identity"]["keeps_working_until"] is not None
    assert d["sessions"][0]["stream_ended"] is None and "trail" not in d
    # the session's paths are timed from the deny, the only call
    assert d["repeats"][0]["own_calls"]["fired_at"] == d["repeats"][0]["new_calls"]["fired_at"]


def test_a_deny_alone_that_ends_the_running_session_counts_nothing_on_it_and_the_page_expected_nothing():
    """The founder's refusal ruling of 29 October 2026, item 2: under a deny of calls alone, "On the running session's
    four paths nothing counts as stopped": a stream that closed is probe silence."""
    clock = Clock()
    aws = FakeAWS(clock, deny_cuts_stream=True)
    r, doc = a_run(aws, clock, fire.DENY)
    assert outcomes(doc) == {**{p: "not measured" for p in running.SESSION_PATHS}, "new_calls": "stopped"}
    d = running.details(r, doc)
    assert d["sessions"][0]["stream_ended_by"] == "ResponseStreamingError"
    assert d["sessions"][0]["writes_after_stream_ended"] == 0
    page = report.page(doc, [x for _, x in running.results(r)])
    assert 'class="differs"' not in page
    assert page.count(report.NOT_KNOWN) == 4


def test_no_stop_is_fired_until_the_runs_trail_records_the_agents_calls(tmp_path):
    clock = Clock()
    aws = FakeAWS(clock)
    r, doc = a_run(aws, clock, fire.DENY_AND_END, tmp_path, trail=True)
    d = running.details(r, doc)
    recording = datetime.fromisoformat(d["trail"]["recording_from"].replace("Z", "+00:00")).timestamp()
    assert recording >= aws.trail_history[0]["started"] + TRAIL_START
    assert r.repeats[0].fired_before > recording
    assert d["trail"]["end_session_found"] == [True]


def test_a_trail_that_records_nothing_ends_the_run_before_any_stop_and_is_kept_then_removed(tmp_path):
    clock = Clock()
    aws = FakeAWS(clock, trail_records=False)
    with pytest.raises(running.NotStarted) as e:
        a_run(aws, clock, fire.DENY_AND_END, tmp_path, trail=True)
    assert "Nothing was fired" in str(e.value)
    assert all(rt["policy"] is None and rt["policy_at"] is None for rt in aws.runtime_history)
    assert not any(ev["name"] == "PutResourcePolicy" for ev in aws.events)
    assert e.value.run.left_behind == [] and aws.trail is None and not aws.buckets
    assert (tmp_path / "trail" / "AWSLogs" / ACCOUNT / "CloudTrail-Digest").is_dir()


def test_the_deny_is_every_principal_denied_all_six_calls_to_the_runtime_with_no_condition():
    arn = f"arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT}:runtime/arvaken_stop_test_r0a1b2c3d-AbCdE12345"
    assert json.loads(fire.deny_document(arn)) == {"Version": "2012-10-17", "Statement": [{
        "Sid": "ArvakenStopTestDenyCalls", "Effect": "Deny", "Principal": "*", "Resource": arn,
        "Action": ["bedrock-agentcore:InvokeAgentRuntime", "bedrock-agentcore:InvokeAgentRuntimeCommand",
                   "bedrock-agentcore:InvokeAgentRuntimeCommandShell", "bedrock-agentcore:InvokeAgentRuntimeForUser",
                   "bedrock-agentcore:InvokeAgentRuntimeWithWebSocketStream",
                   "bedrock-agentcore:InvokeAgentRuntimeWithWebSocketStreamForUser"]}]}


@pytest.mark.parametrize("stop, event", [(DENY_ALL, "AttachRolePolicy"), (fire.INLINE, "PutRolePolicy")])
def test_a_policy_on_the_role_stops_the_sessions_own_calls_and_new_calls_are_still_answered(stop, event):
    clock = Clock()
    aws = FakeAWS(clock)
    r, doc = a_run(aws, clock, stop, repeats=2)
    assert doc["stop"]["kind"] == "policy on an AgentCore agent's role" and doc["stop"]["ref"] == stop
    for i in range(2):
        assert outcomes(doc, i) == {"own_calls": "stopped", "another_identity": "not stopped",
                                    "outside_key": "not stopped", "open_internet": "not stopped",
                                    "new_calls": "not stopped"}
    rep = running.details(r, doc)["repeats"][0]
    assert rep["own_calls"]["fired_source"] == running.AUDIT_RECORD     # from us-east-1's event history
    low, high = rep["own_calls"]["effect_between_seconds"]
    assert low <= DELAY <= high
    assert not doc["run"]["left_anything"] and stop not in str(aws.roles)


def test_without_a_trail_ending_the_session_is_timed_from_the_kits_own_clock_and_said_so():
    clock = Clock()
    aws = FakeAWS(clock)
    r, doc = a_run(aws, clock, fire.DENY_AND_END)
    rep = running.details(r, doc)["repeats"][0]
    assert rep["new_calls"]["fired_source"] == running.AUDIT_RECORD
    assert all(rep[p]["fired_source"].startswith("the kit's own clock") for p in running.SESSION_PATHS)


def test_where_the_trail_has_no_record_of_ending_the_session_the_details_say_so(tmp_path):
    clock = Clock()
    aws = FakeAWS(clock, trail_records_stop=False)
    r, doc = a_run(aws, clock, fire.DENY_AND_END, tmp_path, trail=True, trail_wait=600.0)
    d = running.details(r, doc)
    assert d["trail"]["end_session_found"] == [False]
    assert "StopRuntimeSession" not in d["trail"]["records"]
    assert all(d["repeats"][0][p]["fired_source"].startswith("the kit's own clock") for p in running.SESSION_PATHS)


def test_a_stream_that_closes_while_the_session_goes_on_writing_is_never_read_as_stopped():
    clock = Clock()
    aws = FakeAWS(clock)
    aws.breaks_in = 30.0                    # after the stop, while the deny leaves the session going
    r, doc = a_run(aws, clock, fire.DENY)
    d = running.details(r, doc)
    assert d["sessions"][0]["writes_after_stream_ended"] > 0
    assert outcomes(doc)["own_calls"] == "not stopped"


def test_a_session_that_dies_before_its_stop_reads_not_run_never_stopped():
    clock = Clock()
    aws = FakeAWS(clock)
    aws.dies_in = 5.0                        # its own calls worked by 3 seconds in; the stop comes 5 seconds later
    r, doc = a_run(aws, clock, fire.DENY)
    assert all(outcomes(doc)[p] == "not run" for p in running.SESSION_PATHS)
    assert outcomes(doc)["new_calls"] == "stopped"


def test_between_repeats_the_kit_waits_until_the_removed_deny_holds_before_the_next_stop():
    clock = Clock()
    aws = FakeAWS(clock)
    aws.linger = 60                         # five answered in a row come long before the removal holds
    r, doc = a_run(aws, clock, fire.DENY_AND_END, repeats=2)
    assert outcomes(doc, 1) == {p: "stopped" for p in running.PATHS}
    removed = aws.removed_at[0]
    refused = [t for t, ok in aws.new_calls if not ok and removed <= t < r.repeats[1].opened]
    assert refused and r.repeats[1].opened - max(refused) >= running.RECOVERED


def test_new_calls_refused_just_before_the_stop_read_not_run_and_name_that_refusal(monkeypatch):
    clock = Clock()
    aws = FakeAWS(clock)
    aws.linger = 60
    monkeypatch.setattr(running, "RECOVERED", 4.0)     # five answered in a row, as the kit once waited for
    r, doc = a_run(aws, clock, fire.DENY, repeats=2)
    assert outcomes(doc, 1)["new_calls"] == "not run"
    new = running.details(r, doc)["repeats"][1]["new_calls"]
    # the calls before it were answered: the last call sent before the stop, refused, is the path's error
    assert new["reason"] == "the path could not be set up" and new["errors"] == {"AccessDeniedException": 1}


def test_the_bucket_is_emptied_only_once_the_sessions_have_stopped_writing_to_it():
    clock = Clock()
    aws = FakeAWS(clock)
    aws.writes_after_close = True           # the session writes on after its repeat, to its watch's end
    r, doc = a_run(aws, clock, fire.DENY)
    assert not doc["run"]["left_anything"]
    assert aws.last_write is not None and aws.bucket_deleted_at > aws.last_write


def test_a_session_the_kit_ended_writes_no_more_and_the_bucket_does_not_wait_for_its_watch_to_end():
    clock = Clock()
    aws = FakeAWS(clock)
    aws.writes_after_close = True
    r, doc = a_run(aws, clock, fire.DENY_AND_END)
    assert not doc["run"]["left_anything"]
    assert aws.bucket_deleted_at < r.watched_until


def test_the_kits_own_credentials_expiring_ends_the_run_and_is_never_read_as_stopped():
    clock = Clock()
    aws = FakeAWS(clock)
    real = aws.put_resource_policy

    def expire(**kw):
        real(**kw)
        aws.invoke_error = "ExpiredTokenException"
    aws.put_resource_policy = expire
    with pytest.raises(Error):
        a_run(aws, clock, fire.DENY)
    assert aws.runtime is None and not aws.roles


def test_without_the_kits_boundary_nothing_is_made():
    clock = Clock()
    aws = FakeAWS(clock, boundary=False)
    with pytest.raises(fire.Refused):
        a_run(aws, clock, fire.DENY)
    assert aws.runtime is None and not aws.roles and not aws.buckets


def test_what_the_run_makes_trusts_agentcore_for_this_runs_runtime_alone_under_the_kits_boundary():
    clock = Clock()
    aws = FakeAWS(clock)
    seen = {}
    real = aws.create_agent_runtime

    def keep(**req):
        seen.update(roles=copy.deepcopy(aws.roles), request=req)
        return real(**req)
    aws.create_agent_runtime = keep
    r, _ = a_run(aws, clock, fire.DENY)
    n = stack.names(r.run)
    agent_role, second = seen["roles"][n["agent_role"]], seen["roles"][n["second_role"]]
    assert agent_role["boundary"] == second["boundary"] == f"arn:aws:iam::{ACCOUNT}:policy/arvaken-stop-test-boundary"
    [statement] = agent_role["trust"]["Statement"]
    assert statement["Principal"] == {"Service": "bedrock-agentcore.amazonaws.com"}
    assert statement["Condition"] == {"StringEquals": {"aws:SourceAccount": ACCOUNT}, "ArnLike": {
        "aws:SourceArn": f"arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT}:runtime/arvaken_stop_test_{r.run}-*"}}
    own = agent_role["inline"]["own-calls"]["Statement"]
    assert {json.dumps(s["Resource"]) for s in own} == {
        json.dumps(f"arn:aws:s3:::{n['bucket']}/own/*"), json.dumps(f"arn:aws:iam::{ACCOUNT}:role/{n['second_role']}")}
    req = seen["request"]
    assert req["agentRuntimeName"] == n["runtime"] and req["tags"] == {"arvaken-stop-test": r.run}
    assert req["agentRuntimeArtifact"]["codeConfiguration"] == {
        "code": {"s3": {"bucket": n["bucket"], "prefix": "code/agent.zip"}}, "runtime": "PYTHON_3_13",
        "entryPoint": ["main.py"]}
    assert req["networkConfiguration"] == {"networkMode": "PUBLIC"}
    assert req["protocolConfiguration"] == {"serverProtocol": "HTTP"}
    assert req["lifecycleConfiguration"] == {"idleRuntimeSessionTimeout": 60, "maxLifetime": 3600}
    assert running.details(r, a_result(r))["agent"]["max_lifetime_seconds"] == 3600


def a_result(r):
    return running.the_result(r)


def test_everything_made_is_checked_gone_by_its_identifier_and_a_workload_identity_left_is_removed():
    clock = Clock()
    aws = FakeAWS(clock)
    aws.identity_left = True
    r, doc = a_run(aws, clock, fire.DENY)
    n = stack.names(r.run)
    assert not doc["run"]["left_anything"]
    gone = " | ".join(r.checked_gone)
    for what in (f"the runtime {r.outputs['Runtime']}", "the runtime's endpoints", "the workload identity",
                 f"the code s3://{n['bucket']}/code/agent.zip", f"the bucket {n['bucket']}",
                 f"the role {n['agent_role']}", f"the role {n['second_role']}"):
        assert what in gone
    assert not aws.identity_left


def test_clean_finds_an_interrupted_runs_runtime_by_its_name_and_takes_its_stop_off(tmp_path):
    clock = Clock()
    aws = FakeAWS(clock)
    aws._run = "r0a1b2c3d"
    c = clients(aws)
    r = running.Run(run="r0a1b2c3d", stop_ref=fire.DENY, window=120.0, region=REGION, account=ACCOUNT)
    running.make(c, r, ENDPOINT, clock)
    aws.put_resource_policy(resourceArn=r.outputs["Runtime"], policy=fire.deny_document(r.outputs["Runtime"]))
    interrupted = running.Run(run="r0a1b2c3d", stop_ref=fire.INLINE, window=0.0, region=REGION, account=ACCOUNT,
                              trail=True)
    assert running.runtime_id(c, interrupted) == r.outputs["RuntimeId"]
    assert fire.remove(aws, aws, interrupted.run, fire.DENY, interrupted.outputs["Runtime"])
    running.tear_down(c, interrupted, clock, trail_folder=tmp_path / "trail")
    assert interrupted.left_behind == [] and aws.runtime is None and not aws.roles and not aws.buckets


@pytest.mark.parametrize("reason", ["a reason AWS gives", None])
def test_a_runtime_agentcore_did_not_make_ready_is_named_with_awss_own_reason_where_it_gives_one(reason):
    clock = Clock()
    aws = FakeAWS(clock)
    aws._run = "r0a1b2c3d"
    aws.get_agent_runtime = lambda agentRuntimeId: {"status": "CREATE_FAILED", **(
        {"failureReason": reason} if reason else {})}
    r = running.Run(run="r0a1b2c3d", stop_ref=fire.DENY, window=120.0, region=REGION, account=ACCOUNT)
    with pytest.raises(RuntimeError) as e:
        running.make(clients(aws), r, ENDPOINT, clock)
    assert str(e.value) == "the runtime arvaken_stop_test_r0a1b2c3d is CREATE_FAILED, not ready" + (
        f": {reason}" if reason else "")


def test_the_runtime_must_be_the_runs_own_before_any_deny_is_written_on_it():
    clock = Clock()
    aws = FakeAWS(clock)
    aws._run = "r0a1b2c3d"
    c = clients(aws)
    r = running.Run(run="r0a1b2c3d", stop_ref=fire.DENY, window=120.0, region=REGION, account=ACCOUNT)
    running.make(c, r, ENDPOINT, clock)
    with pytest.raises(fire.Refused):
        fire.fire(aws, aws, "r9f9f9f9f", fire.DENY, r.outputs["Runtime"])
    aws.runtime["tags"] = {}
    with pytest.raises(fire.Refused):
        fire.fire(aws, aws, "r0a1b2c3d", fire.DENY, r.outputs["Runtime"])
    assert aws.runtime["policy"] is None


def test_the_code_is_the_agent_as_main_py_with_boto3_beside_it_the_same_bytes_every_time():
    import zipfile
    code = stack.code_zip()
    assert stack.code_zip() == code
    z = zipfile.ZipFile(io.BytesIO(code))
    names = z.namelist()
    assert z.read("main.py").decode("utf-8") == stack.agent_source()
    assert {"boto3/__init__.py", "botocore/__init__.py", "six.py", "urllib3/__init__.py"} <= set(names)
    assert not any("__pycache__" in n or n.endswith(".pyc") for n in names)
    assert all((i.external_attr >> 16) == 0o100644 for i in z.infolist())


def test_the_page_says_what_each_agentcore_kind_is_expected_to_stop():
    clock = Clock()
    aws = FakeAWS(clock)
    r, doc = a_run(aws, clock, fire.DENY)
    page = report.page(doc, [d for _, d in running.results(r)])
    assert "This kind of stop would be expected" in page and "new calls to the agent" in page
    assert report.expected("deny calls to an AgentCore agent", "new_calls") == "stopped"
    assert report.expected("deny calls to an AgentCore agent", "own_calls") is None
    assert report.expected("deny calls to an AgentCore agent and end its sessions", "own_calls") == "stopped"
    assert report.expected("policy on an AgentCore agent's role", "new_calls") is None
    assert page.count(report.NOT_KNOWN) == 4 and 'class="differs"' not in page


# -- the real stream, against bytes as AgentCore sends them

class Body:
    def __init__(self, lines: list[bytes], fails: Exception | None = None):
        self.lines, self.fails, self.closed = lines, fails, False

    def iter_lines(self, chunk_size=1024):
        yield from self.lines
        if self.fails:
            raise self.fails

    def close(self):
        self.closed = True


class Data:
    def __init__(self, body: Body):
        self.body, self.asked = body, None

    def invoke_agent_runtime(self, **kw):
        self.asked = kw
        return {"response": self.body}


def _a_stream(body: Body) -> tuple[running.Stream, Data]:
    data = Data(body)
    c = running.Clients(iam=None, s3=None, control=None, data=data, cloudtrail=None, iam_trail=None, tagging=None,
                        region=REGION)
    r = running.Run(run="r0a1b2c3d", stop_ref=fire.DENY, window=120.0, outputs={"Runtime": "arn:runtime"})
    stream = running.Stream(c, r, "r0a1b2c3d-session-" + "0" * 32, 300.0, Clock())
    stream.thread.join(timeout=5)
    return stream, data


def test_the_stream_reads_each_event_and_a_watch_done_is_not_a_session_ended():
    events = [{"at": 1.0, "session_expires": 3601.0}, {"at": 2.0, "beats": {"own_calls": {"at": 2.0, "ok": True}}},
              {"at": 3.0, "done": True}]
    stream, data = _a_stream(Body([b"data: " + json.dumps(e).encode() for e in events] + [b""]))
    assert stream.poll() == events
    assert stream.ended[1] == "done"
    assert data.asked["accept"] == "text/event-stream" and json.loads(data.asked["payload"])["action"] == "watch"


def test_the_stream_closing_early_says_how():
    stream, _ = _a_stream(Body([b'data: {"at": 1.0}'], fails=Error("ResponseStreamingError")))
    assert stream.ended[1] == "ResponseStreamingError"


class Held(Body):
    """A stream that stays open until the kit closes it, then fails as a closed connection does."""

    def __init__(self):
        super().__init__([])
        self.gate = threading.Event()

    def iter_lines(self, chunk_size=1024):
        yield b'data: {"at": 1.0}'
        self.gate.wait(5)
        raise Error("ConnectionClosed")

    def close(self):
        self.closed = True
        self.gate.set()


def test_the_kit_closing_the_stream_itself_is_not_a_session_ended():
    data = Data(Held())
    c = running.Clients(iam=None, s3=None, control=None, data=data, cloudtrail=None, iam_trail=None, tagging=None,
                        region=REGION)
    r = running.Run(run="r0a1b2c3d", stop_ref=fire.DENY, window=120.0, outputs={"Runtime": "arn:runtime"})
    stream = running.Stream(c, r, "r0a1b2c3d-session-" + "0" * 32, 300.0, Clock())
    while stream.body is None:
        pass
    stream.close()
    assert stream.ended is None and stream.body.closed and stream.poll() == [{"at": 1.0}]


# -- the agent, on its own server

def test_the_agent_answers_a_new_call_says_it_is_healthy_and_streams_a_watch(monkeypatch):
    monkeypatch.setattr(agent, "assume", lambda: {"key": "k", "secret": "s", "token": "t", "expires": 4000.0})
    monkeypatch.setattr(agent.boto3, "client", lambda *a, **kw: object())
    monkeypatch.setattr(agent, "probe", lambda s3, other, tag, n: {"own_calls": {"at": 1.0, "ok": True}})
    monkeypatch.setattr(agent, "EVERY", 0.01)
    server = ThreadingHTTPServer(("127.0.0.1", 0), agent.Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        ping = json.loads(urllib.request.urlopen(f"{base}/ping", timeout=5).read())
        assert ping == {"status": "Healthy"}
        asked = urllib.request.Request(f"{base}/invocations", data=b'{"action": "answer"}', method="POST",
                                       headers={"Content-Type": "application/json"})
        assert set(json.loads(urllib.request.urlopen(asked, timeout=5).read())) == {"at"}
        asked = urllib.request.Request(f"{base}/invocations", data=b'{"action": "watch", "seconds": 0.05, "tag": "x"}',
                                       method="POST", headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(asked, timeout=5) as response:
            assert response.headers["Content-Type"] == "text/event-stream"
            events = [json.loads(line[6:]) for line in response.read().decode().splitlines()
                      if line.startswith("data: ")]
        assert events[0]["session_expires"] == 4000.0 and events[-1]["done"] is True
        assert all(e["beats"] == {"own_calls": {"at": 1.0, "ok": True}} for e in events[1:-1]) and len(events) > 2
    finally:
        server.shutdown()


# -- the module's permissions, held to what it does

# The runtime's policy and the harness's, as IAM reads them attached together: a harness run needs both.
POLICIES = ("aws-agentcore-policy.json", "aws-agentcore-harness-policy.json")
POLICY = {"Version": "2012-10-17", "Statement": [
    s for p in POLICIES for s in json.loads((Path(__file__).resolve().parents[1] / "permissions" / p)
                                            .read_text(encoding="utf-8"))["Statement"]]}
SOURCE = Path(__file__).resolve().parents[1] / "src" / "arvaken_stop_test" / "agentcore"
PREFIX = {"iam": "iam", "s3": "s3", "control": "bedrock-agentcore", "data": "bedrock-agentcore",
          "cloudtrail": "cloudtrail", "lookups": "cloudtrail", "tagging": "tag", "logs": "logs", "bedrock": "bedrock"}
# a boto3 method whose IAM action is not its own name
ACTION_OF = {("s3", "head_bucket"): "s3:ListBucket", ("s3", "list_objects_v2"): "s3:ListBucket",
             ("s3", "delete_objects"): "s3:DeleteObject", ("s3", "head_object"): "s3:GetObject",
             ("s3", "put_bucket_encryption"): "s3:PutEncryptionConfiguration",
             ("s3", "put_public_access_block"): "s3:PutBucketPublicAccessBlock"}
# what the module asks of aws/fire.py: firing and removing a policy on the role, and reading the kit's boundary
FROM_AWS_FIRE = {"iam:ListRoleTags", "iam:PutRolePolicy", "iam:AttachRolePolicy", "iam:ListRolePolicies",
                 "iam:DeleteRolePolicy", "iam:ListAttachedRolePolicies", "iam:DetachRolePolicy", "iam:GetPolicy",
                 "iam:GetPolicyVersion"}
# what AWS asks of the caller beside each call's own action: passing the role, and the tags given when a thing is made
BESIDE = {"iam:PassRole", "iam:TagRole", "bedrock-agentcore:TagResource", "cloudtrail:AddTags",
          # what AWS lists as required to make and delete a harness, though the kit's harness has no memory
          # (PROVIDER-SOURCES: aws-sar-agentcore-create-harness, aws-agentcore-harness-delete-permissions)
          "bedrock-agentcore:CreateMemory", "bedrock-agentcore:GetMemory", "bedrock-agentcore:DeleteMemory",
          # what AWS lists as required to make, delete and call a runtime (aws-sar-agentcore-create-agent-runtime,
          # -delete-agent-runtime, -invoke-agent-runtime); and AgentCore makes a runtime's workload identity with the
          # caller's own credentials (CloudTrail, 29 October 2026: CreateWorkloadIdentity, invoked by AgentCore)
          "bedrock-agentcore:CreateAgentRuntimeEndpoint", "bedrock-agentcore:DeleteAgentRuntimeEndpoint",
          "bedrock-agentcore:InvokeAgentRuntimeForUser", "bedrock-agentcore:CreateWorkloadIdentity"}


def _calls() -> set[str]:
    import re
    found = set()
    for path in SOURCE.glob("*.py"):
        if path.name in ("agent.py", "probe.py"):   # the test agent's own calls are its role's, not yours
            continue
        for client, method in re.findall(r"\b(iam|s3|control|data|cloudtrail|lookups|tagging|logs|bedrock)\."
                                         r"([a-z0-9_]+)\(", path.read_text(encoding="utf-8")):
            camel = "".join(w.capitalize() for w in method.split("_"))
            found.add(ACTION_OF.get((client, method), f"{PREFIX[client]}:{camel}"))
    return found


def test_every_call_the_agentcore_module_makes_is_in_its_policy_and_the_policy_holds_nothing_else():
    allowed = set()
    for s in POLICY["Statement"]:
        assert s["Effect"] == "Allow"
        allowed |= set(s["Action"] if isinstance(s["Action"], list) else [s["Action"]])
    needed = _calls() | FROM_AWS_FIRE | BESIDE
    assert "bedrock-agentcore:InvokeAgentRuntime" in needed and "cloudtrail:CreateTrail" in needed
    assert needed - allowed == set()
    assert allowed - needed == set()


def _by_the_runs_tag(s: dict) -> bool:
    """Whether a statement holds only for a thing that carries, or is being made with, the run's tag."""
    null = s.get("Condition", {}).get("Null", {})
    return any(null.get(f"aws:{kind}/arvaken-stop-test") == "false" for kind in ("RequestTag", "ResourceTag"))


def test_each_of_the_kits_agentcore_policies_fits_in_one_managed_policy():
    # IAM's limit for a managed policy, white space not counted (PROVIDER-SOURCES: aws-iam-managed-policy-size)
    for p in POLICIES:
        text = (Path(__file__).resolve().parents[1] / "permissions" / p).read_text(encoding="utf-8")
        assert len(re.sub(r"\s", "", text)) <= 6144, p


def test_the_policy_reaches_only_the_runs_own_things():
    for s in POLICY["Statement"]:
        resources = s["Resource"] if isinstance(s["Resource"], list) else [s["Resource"]]
        for resource in resources:
            # yours, read; and the directory AWS checks beside each of the run's identities, which carries no tag
            # of the run's to limit it by (the founder's ruling, 29 October 2026; PROVIDER-SOURCES:
            # aws-sar-agentcore-delete-workload-identity, aws-sar-agentcore-get-workload-identity)
            named = {("arn:aws:iam::*:policy/*", "YourStopReadAndChecked"),
                     ("arn:aws:bedrock:*:*:inference-profile/*", "YourModelsInferenceProfileRead"),
                     ("arn:aws:bedrock-agentcore:*:*:workload-identity-directory/default",
                      "TheWorkloadIdentityDirectoryAWSChecksBesideTheRunsIdentity")}
            assert resource == "*" or "arvaken-stop-test-" in resource or "arvaken_stop_test_" in resource or \
                (resource, s["Sid"]) in named or _by_the_runs_tag(s), resource
        if resources == ["*"]:
            assert s["Sid"] == "ReadsAwsTakesOnEveryResourceOnly" or _by_the_runs_tag(s), s["Sid"]


# -- ending the session counts only once AWS confirms it (the founder's refusal ruling of 29 October 2026, item 3) -----

def test_ending_the_session_counts_from_awss_confirmation_and_the_details_say_the_test_address_was_not_checked():
    clock = Clock()
    aws = FakeAWS(clock)
    r, doc = a_run(aws, clock, fire.DENY_AND_END)
    assert outcomes(doc) == {p: "stopped" for p in running.PATHS}
    rep = r.repeats[0]
    found = running.results(r)[0][1]["own_calls"]
    # from the confirmation (the fake's clock stands still within a call, so its first second falls on the stop's own
    # moment, which is not after it)
    assert rep.end_confirmed is not None
    assert rep.end_confirmed + r.offset <= found.stopped_at <= rep.end_confirmed + r.offset + 1.0
    session = running.details(r, doc)["sessions"][0]
    assert session["confirm_answers"] == {"ResourceNotFoundException": 1} and session["test_address_checked"] is False
    assert session["seen_after_confirmation"] == {}


def test_ending_the_session_without_awss_confirmation_is_not_measured_on_its_four_paths():
    """Probe silence without AWS confirmation never counts: here StopRuntimeSession, asked again, answers each time."""
    clock = Clock()
    aws = FakeAWS(clock, ended_answer=None)
    r, doc = a_run(aws, clock, fire.DENY_AND_END)
    assert outcomes(doc) == {**{p: "not measured" for p in running.SESSION_PATHS}, "new_calls": "stopped"}
    assert r.repeats[0].end_confirmed is None
    assert set(running.details(r, doc)["sessions"][0]["confirm_answers"]) == {"answered"}


def test_a_path_seen_calling_after_the_confirmation_is_not_stopped():
    """The cross-check: "Any call seen after it means the path is not stopped". Here the session goes on writing its
    own objects after AWS ended it."""
    clock = Clock()
    aws = FakeAWS(clock)
    aws.writes_after_end = True
    r, doc = a_run(aws, clock, fire.DENY_AND_END)
    assert outcomes(doc)["own_calls"] == "not stopped"
    assert outcomes(doc)["another_identity"] == "stopped" and outcomes(doc)["open_internet"] == "stopped"
    assert running.details(r, doc)["sessions"][0]["seen_after_confirmation"]["own_calls"]


def test_a_deny_alone_records_any_access_denied_on_the_session_for_jeff_and_amanda():
    clock = Clock()
    aws = FakeAWS(clock)
    r, doc = a_run(aws, clock, fire.DENY)
    assert "access_denied_on_the_session" in running.details(r, doc)["sessions"][0]


def test_botocore_errors_whose_response_is_none_are_read_by_their_name():
    """botocore's ReadTimeoutError and ConnectionClosedError carry `response`, as None, so reading their code with
    getattr(e, "response", {}) raised AttributeError instead (found on arvaken/stop-test#19, 30 October 2026): a new
    call or a check of the teardown's that timed out raised that, where it was to be recorded or named. Each place
    reads it now as (getattr(e, "response", None) or {})."""
    import botocore.exceptions as b
    from arvaken_stop_test.agentcore import fire as agentcore_fire
    from arvaken_stop_test.agentcore import run as agentcore_run
    from arvaken_stop_test.agentcore import trail
    from arvaken_stop_test.aws import fire as aws_fire
    from arvaken_stop_test.aws import run as aws_run
    url = "https://bedrock-agentcore.eu-central-1.amazonaws.com/"
    for e in (b.ReadTimeoutError(endpoint_url=url), b.ConnectionClosedError(endpoint_url=url)):
        name = type(e).__name__
        assert e.response is None                                       # as botocore makes them

        def raising(*_, e=e, **__):
            raise e
        assert agentcore_run.code(e) == name and trail._code(e) == name
        assert aws_run._gone(raising) == name                           # named as could not be checked
        # the error itself goes on, as any but the one each place looks for
        control = type("Control", (), {"delete_resource_policy": staticmethod(raising)})()
        with pytest.raises(type(e)):
            agentcore_fire.remove(None, control, "r0123abcd", agentcore_fire.DENY, "arn:aws:bedrock-agentcore:x")
        iam = type("IAM", (), {"get_policy": staticmethod(raising)})()
        sts = type("STS", (), {"get_caller_identity": staticmethod(
            lambda: {"Account": "123456789012", "Arn": "arn:aws:sts::123456789012:assumed-role/runner/you"})})()
        with pytest.raises(type(e)):
            aws_fire.why_no_boundary(iam, sts)
