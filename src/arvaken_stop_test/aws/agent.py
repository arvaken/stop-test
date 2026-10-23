"""The test agent: the code of the Lambda function the kit deploys (the design's sections 3 and 4).

The kit invokes it once a second, with the kit's own credentials. Each invocation tries each path once and returns,
for each, when (by its own clock), whether it succeeded, and if not the error's code. It prints nothing and logs
nothing, so a run leaves nothing in the account's logs, and a stop that denies the agent everything cannot stop its
report: the reply goes back to the kit through Lambda, not through anything the agent's role reaches.

The paths (the design's section 4; D532, K3):
- own_calls: writes and reads one small object in the kit's bucket, as the agent itself.
- another_identity: writes to the bucket with a session of the kit's second role, which the agent assumed before the
  stop was fired. The kit hands the session back to it with each invocation, so it outlives the agent's container.
- outside_key: calls Arvaken's test endpoint with the key the kit made for the run, held in the agent's environment,
  as an agent holds a key for a service outside the cloud.
- open_internet: fetches Arvaken's test endpoint with no key.

This file is shipped as the function's code, so it uses only what Lambda's Python runtime has: the standard library
and boto3.
"""
import os
import time
import urllib.error
import urllib.request

import boto3
import botocore.config
import botocore.exceptions

CONFIG = botocore.config.Config(connect_timeout=2, read_timeout=2, retries={"max_attempts": 1})
TIMEOUT = 2.0
# Named, as Cloudflare in front of Arvaken's endpoint refuses Python's default (403, its error 1010).
AGENT = "arvaken-stop-test-agent (+https://github.com/arvaken/stop-test)"


def _code(e):
    """An error's code alone, never its message: the message can name resources and principals."""
    if isinstance(e, botocore.exceptions.ClientError):
        return str(e.response.get("Error", {}).get("Code") or "ClientError")[:64]
    if isinstance(e, urllib.error.HTTPError):
        return f"HTTP{e.code}"
    if isinstance(e, (TimeoutError, urllib.error.URLError)):
        return "Unreachable"
    return type(e).__name__[:64]


def _try(fn):
    at = time.time()
    try:
        fn()
        return {"at": at, "ok": True}
    except Exception as e:  # noqa: BLE001 - every failure is a heartbeat's result, by its code
        return {"at": at, "ok": False, "error": _code(e)}


def _get(url, headers):
    request = urllib.request.Request(url, headers={"User-Agent": AGENT, **headers}, method="GET")
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        response.read(64)


def handler(event, context):
    bucket, endpoint = os.environ["BUCKET"], os.environ["ENDPOINT"].rstrip("/")
    if event.get("action") == "assume":
        # Before the stop: assume the second role, and hand the session to the kit, which passes it back each time.
        sts = boto3.client("sts", config=CONFIG)
        c = sts.assume_role(RoleArn=os.environ["SECOND_ROLE"], RoleSessionName="arvaken-stop-test",
                            DurationSeconds=3600)["Credentials"]
        return {"at": time.time(), "session": {"key": c["AccessKeyId"], "secret": c["SecretAccessKey"],
                                               "token": c["SessionToken"]}}
    s3 = boto3.client("s3", config=CONFIG)
    n = str(event.get("n", 0))

    def own_calls():
        s3.put_object(Bucket=bucket, Key=f"own/{n}", Body=b"x")
        s3.get_object(Bucket=bucket, Key=f"own/{n}")["Body"].read()

    def another_identity():
        session = event.get("session")
        if not session:
            raise RuntimeError("NoSession")
        other = boto3.client("s3", config=CONFIG, aws_access_key_id=session["key"],
                             aws_secret_access_key=session["secret"], aws_session_token=session["token"])
        other.put_object(Bucket=bucket, Key=f"another/{n}", Body=b"x")

    def outside_key():
        _get(f"{endpoint}/key", {"Authorization": "Bearer " + os.environ["OUTSIDE_KEY"]})

    def open_internet():
        _get(f"{endpoint}/open", {})

    beats = {"own_calls": _try(own_calls), "another_identity": _try(another_identity),
             "outside_key": _try(outside_key), "open_internet": _try(open_internet)}
    return {"at": time.time(), "beats": beats}
