"""AWS's own part of the probe (D575, AWS first): the run's settings that name AWS resources, the clients that make
AWS's calls, AWS's paths, and AWS's failure records. Each is the kit's own test agent's (the kit's aws/agent.py), so a
copy makes the calls the kit's agent makes.

- own_calls: writes and reads one small object in the run's bucket, as the copy itself (the role made for the run, KC1).
- another_identity: writes to the bucket with a session of the run's second role, which the probe assumed before the
  stop was fired (`assume`). The kit hands the session back to it with each invocation.
- model, where the kit names one: one Bedrock Runtime Converse call, one user message, "1", and one token of output.
  Its answer is never kept or returned.

The settings come in the kit's marker, as the kit never sets a copy's environment, and are taken only where they name
the run: its bucket (CloudFormation names it after the run's stack) and its second role.

**Clients (KC2).** `make` is the customer's function that makes a client as boto3.client does, where they pass one;
else boto3's own (runtime_client). A client is made the first time a path is tried and kept for as long as the process
lives, as a real agent's are (D655).
"""
from __future__ import annotations

import re
import time

from arvaken_stop_test_probe import core
from arvaken_stop_test_probe.core import NotTheKits

PREFIX = "arvaken-stop-test"                 # the kit's stack.PREFIX
MODEL_ID = re.compile(r"[a-z0-9-]{1,63}(\.[a-z0-9-]{1,63}){1,2}(:[a-z0-9-]{1,63}){0,2}")  # the kit's stack.MODEL_ID
TUNNEL = re.compile(r"Tunnel connection failed: (\d{3})(?: .*)?")
LIBRARIES = ("botocore", "urllib3")
_MADE: dict = {}


def settings(m) -> dict:
    """AWS's settings from the kit's marker, each checked to name the run; else NotTheKits."""
    base = f"{PREFIX}-{m['run']}"
    bucket, role, model = m.get("bucket"), m.get("second_role"), m.get("model")
    # CloudFormation names the run's bucket after its stack: the stack's name, the bucket's own, and a suffix of its own
    if not (isinstance(bucket, str) and len(bucket) <= 63 and re.fullmatch(re.escape(base) + r"-[a-z0-9-]+", bucket)):
        raise NotTheKits("bucket")
    if not (isinstance(role, str) and re.fullmatch(r"arn:aws(-[a-z]+)*:iam::\d{12}:role/" + re.escape(base + "-second"),
                                                   role)):
        raise NotTheKits("second_role")
    if model is not None and not (isinstance(model, str) and MODEL_ID.fullmatch(model)):
        raise NotTheKits("model")
    if m.get("action") not in (None, "assume"):
        raise NotTheKits("action")
    return {"bucket": bucket, "second_role": role, "model": model, "n": str(m.get("n", 0)), "action": m.get("action"),
            "session": m.get("session")}


def _errors():
    try:
        import botocore.exceptions
    except ImportError:
        return None
    return botocore.exceptions


def _tunnel(e):
    seen, todo = set(), [e]
    while todo:
        x = todo.pop()
        if x is None or id(x) in seen:
            continue
        seen.add(id(x))
        found = isinstance(x, OSError) and TUNNEL.fullmatch(str(x))
        if found:
            return int(found.group(1))
        todo += [getattr(x, "kwargs", {}).get("error"), x.__cause__, x.__context__]
        todo += [a for a in getattr(x, "args", ()) if isinstance(a, BaseException)]
    return None


def record(e) -> dict:
    """AWS's failure record, as the kit's agent's _record: a ClientError's code, status and reason; a gateway's refusal
    of a tunnel, its status alone; anything else, the core's."""
    x = _errors()
    if x is not None and isinstance(e, x.ProxyConnectionError):
        return {"error": type(e).__name__[:64], "status": _tunnel(e), "reason": None}
    if x is not None and isinstance(e, x.ClientError):
        reason = e.response.get("Reason") or e.response.get("reason")
        if not (isinstance(reason, str) and reason.replace("_", "").isalnum()):
            reason = None
        return {"error": str(e.response.get("Error", {}).get("Code") or "ClientError")[:64],
                "status": e.response.get("ResponseMetadata", {}).get("HTTPStatusCode"), "reason": reason and reason[:64]}
    return core.record(e)


def _config():
    import botocore.config
    return botocore.config.Config(connect_timeout=2, read_timeout=2, retries={"max_attempts": 1})


def runtime_client(name, **kw):
    """The runtime's own client: boto3's."""
    import boto3
    return boto3.client(name, **kw)


def _client(make, name, ctx=None, **kw):
    key = (make, name, kw.get("aws_access_key_id"))
    if key not in _MADE:
        _MADE[key] = (make(name, config=_config(), **kw), time.time())
    if ctx is not None:
        ctx["client_at"] = _MADE[key][1]
    return _MADE[key][0]


def assume(s, make) -> dict:
    """The second role's session, assumed before the stop, for the kit to hand back with each invocation."""
    c = _client(make, "sts").assume_role(RoleArn=s["second_role"], RoleSessionName=PREFIX,
                                         DurationSeconds=3600)["Credentials"]
    return {"key": c["AccessKeyId"], "secret": c["SecretAccessKey"], "token": c["SessionToken"],
            "expires": c["Expiration"].timestamp()}


def identity_paths(s, make) -> list:
    """own_calls and another_identity."""
    bucket, n = s["bucket"], s["n"]

    def own_calls(ctx):
        s3 = _client(make, "s3", ctx)
        s3.put_object(Bucket=bucket, Key=f"own/{n}", Body=b"x")
        s3.get_object(Bucket=bucket, Key=f"own/{n}")["Body"].read()

    def another_identity(ctx):
        session = s["session"]
        if not isinstance(session, dict):
            raise RuntimeError("NoSession")
        other = _client(make, "s3", ctx, aws_access_key_id=session["key"], aws_secret_access_key=session["secret"],
                        aws_session_token=session["token"])
        other.put_object(Bucket=bucket, Key=f"another/{n}", Body=b"x")

    return [("own_calls", own_calls), ("another_identity", another_identity)]


def model_paths(s, make) -> list:
    """model, where the kit names one; else none."""
    def model(ctx):
        _client(make, "bedrock-runtime", ctx).converse(modelId=s["model"], inferenceConfig={"maxTokens": 1},
                                                       messages=[{"role": "user", "content": [{"text": "1"}]}])

    return [("model", model)] if s["model"] else []
