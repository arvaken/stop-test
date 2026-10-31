"""The test agent: the code of the Lambda function the kit deploys (the design's sections 3 and 4).

The kit invokes it once a second, with the kit's own credentials. Each invocation tries each path once and returns,
for each, when (by its own clock), whether it succeeded, and if not its failure record (D646): the error's code, the HTTP
status AWS answered with, and AWS's own reason field where the error has one (Lambda's TooManyRequestsException and
AgentCore's ValidationException do; S3's errors have none). Never a message: it can name resources and principals. The
credentials the agent's own calls use are its role's, which Lambda gives it without their issue or expiry time: the
agent hands back their access key ID with each reply, for the kit to find their times (run.own_tokens); the session it
works under for another identity is the kit's to time (run.py). It prints nothing and writes no
logs of its own (the account's CloudTrail still records what the kit does), and a stop that denies the agent everything
cannot stop its report: the reply goes back to the kit through Lambda, not through anything the agent's role reaches.

The paths (the design's section 4; D532, K3):
- own_calls: writes and reads one small object in the kit's bucket, as the agent itself.
- another_identity: writes to the bucket with a session of the kit's second role, which the agent assumed before the
  stop was fired. The kit hands the session back to it with each invocation, so it outlives the agent's container.
- outside_key: calls Arvaken's test endpoint with the key the kit made for the run, held in the agent's environment,
  as an agent holds a key for a service outside the cloud.
- open_internet: fetches Arvaken's test endpoint with no key.
- model (the optional fifth row, the kit's `--model`; the design's section 4): where the function's environment names a
  model (MODEL, a Bedrock model's ID or an inference profile's), one Bedrock Runtime Converse call to it, as the agent
  itself, through the gateway where there is one, as its other calls to AWS. It asks the least a call can: one user
  message, "1", and one token of output. Its answer is never kept or returned: as on every path, only whether it
  succeeded, and if not the error's code. Without MODEL, the agent makes no such call and its reply has no "model".

**Through a gateway (the kit's `--via`; D561, section 5).** Where the kit's invocation names a gateway (`via`), the
calls of the paths it names (`through`: those the gateway's declared attachment covers) go through it as an HTTPS proxy,
and the others go directly: its own calls to AWS, its work under the other identity (the session's own calls, which the
agent makes itself; the design's section 3 judges them as its own calls) with the session taken for it, its call with a
key and its open-internet call. The last two still go to Arvaken's test endpoint, never to
a real third party's service. Where the invocation carries the customer's certificate bundle (`ca`, for a gateway that
inspects TLS and presents its own certificate), the agent trusts it beside the default ones for those calls alone, and
for the gateway's own certificate where its address is https. The gateway and the bundle come with each invocation, as
the session does, and are never in the function's code or environment, so neither is in the stack's template; an
address with a user name and password is used as given, to sign in to the gateway. The calls to the endpoint through a
gateway are made with botocore's own HTTP session, which speaks to an https gateway as boto3's clients do; without a
gateway, with the standard library, as before.

The agent names itself (AGENT), as Cloudflare in front of Arvaken's endpoint refuses Python's default user agent (403,
its error 1010). Asked to "assume", before the stop, it assumes the second role and hands the session to the kit, which
passes it back each time. `_gateway` gives the proxy settings and the bundle to verify with, where the kit names a
gateway; else none.

`_code` gives an error's code alone, never its message: the message can name resources and principals. `_try` catches
every failure, as each is a heartbeat's result, by its code.

**The gateway's own refusal** (the founder's ruling on a gateway's refusal, D655, 30 October 2026). Where a gateway
refuses the CONNECT for a call through it, botocore raises ProxyConnectionError, and the gateway's status is only in the
text of the error beneath it: "Tunnel connection failed: <three digits>", the reason phrase after them the gateway's
own. `_tunnel` reads the three digits from that text, strictly (TUNNEL, the whole text or nothing), and keeps the status
alone, never the phrase; any other text reads as no status. Each reply names the Python, botocore and urllib3 the agent
ran on (VERSIONS), so a failure's record holds what read it.

**Its clients are kept** (D655, open tunnels 1 to 3): one client a path, made the first time the path is tried and kept
for as long as Lambda keeps the agent's environment, with the connection reuse the SDK gives by default, as a real
agent's are; through a gateway, its tunnel is reused too. Each try names when its client was made (`client_at`), so the
kit can tell a client made before the mark from one made after it, as when Lambda gave the agent a new environment.

This file is shipped as the function's code, so it uses only what Lambda's Python runtime has: the standard library
and boto3 (with botocore, and urllib3 beneath it). CloudFormation takes a function's inline code to 8,192 characters as
the kit holds it (stack.INLINE_LIMIT): what explains it is here, in the docstring, which is not shipped, nor are the
comments; the code is shipped indented two spaces a level, the same program (stack.agent_code).
"""
import json
import os
import re
import sys
import tempfile
import time
import urllib.error
import urllib.request

import boto3
import botocore
import botocore.config
import botocore.exceptions
import urllib3
from botocore.awsrequest import AWSRequest
from botocore.httpsession import URLLib3Session, get_cert_path

CONFIG = botocore.config.Config(connect_timeout=2, read_timeout=2, retries={"max_attempts": 1})
TIMEOUT = 2.0
AGENT ="arvaken-stop-test-agent (+https://github.com/arvaken/stop-test)"
CA = os.path.join(tempfile.gettempdir(), "arvaken-stop-test-ca.pem")
VERSIONS = [sys.version.split()[0], botocore.__version__, urllib3.__version__]
TUNNEL = re.compile(r"Tunnel connection failed: (\d{3})(?: .*)?")
_MADE = {}


def _code(e):
    if isinstance(e, botocore.exceptions.ClientError):
        return str(e.response.get("Error", {}).get("Code") or "ClientError")[:64]
    if isinstance(e, urllib.error.HTTPError):
        return f"HTTP{e.code}"
    if isinstance(e, (TimeoutError, urllib.error.URLError)):
        return "Unreachable"
    return type(e).__name__[:64]


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


def _record(e):
    status = reason = None
    if isinstance(e, botocore.exceptions.ProxyConnectionError):
        status = _tunnel(e)
    elif isinstance(e, botocore.exceptions.ClientError):
        status = e.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        reason = e.response.get("Reason") or e.response.get("reason")
    elif isinstance(e, urllib.error.HTTPError):
        status = e.code
    if not (isinstance(reason, str) and reason.replace("_", "").isalnum()):
        reason = None
    return {"error": _code(e), "status": status, "reason": reason and reason[:64]}


def _try(fn):
    at, ctx = time.time(), {}
    try:
        fn(ctx)
        return {"at": at, "ok": True, **ctx}
    except Exception as e:  # noqa: BLE001 - every failure is a heartbeat's result, by its record
        return {"at": at, "ok": False, **_record(e), **ctx}


def _gateway(event):
    via, ca = event.get("via"), None
    if not via:
        return {}, None
    if event.get("ca"):
        with open(get_cert_path(True)) as f, open(CA, "w") as out:
            out.write(f.read() + "\n" + event["ca"])
        ca = CA
    return {"proxies": {"http": via, "https": via}, "proxies_config": {"proxy_ca_bundle": ca} if ca else None}, ca


def _kept(key, make, ctx):
    if key not in _MADE:
        _MADE[key] = (make(), time.time())
    if ctx is not None:
        ctx["client_at"] = _MADE[key][1]
    return _MADE[key][0]


def _client(name, gw, ctx=None, **kw):
    proxies, ca = gw
    key = ("client", name, json.dumps(proxies, sort_keys=True), ca, kw.get("aws_access_key_id"))
    return _kept(key, lambda: boto3.client(name, config=CONFIG.merge(botocore.config.Config(**proxies)), verify=ca,
                                           **kw), ctx)


def _get(url, headers, gw=({}, None), ctx=None):
    proxies, ca = gw
    headers = {"User-Agent": AGENT, **headers}
    if proxies:
        key = ("session", json.dumps(proxies, sort_keys=True), ca)
        session = _kept(key, lambda: URLLib3Session(verify=ca or True, timeout=TIMEOUT, **proxies), ctx)
        answer = session.send(AWSRequest("GET", url, headers=headers).prepare())
        if answer.status_code >= 400:
            raise urllib.error.HTTPError(url, answer.status_code, "", None, None)
        return
    request = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        response.read(64)


def handler(event, context):
    bucket, endpoint = os.environ["BUCKET"], os.environ["ENDPOINT"].rstrip("/")
    gw, by = _gateway(event), event.get("through", ())
    g = lambda p: gw if p in by else ({}, None)  # noqa: E731
    if event.get("action") == "assume":
        sts = _client("sts", g("another_identity"))
        c = sts.assume_role(RoleArn=os.environ["SECOND_ROLE"], RoleSessionName="arvaken-stop-test",
                            DurationSeconds=3600)["Credentials"]
        return {"at": time.time(), "session": {"key": c["AccessKeyId"], "secret": c["SecretAccessKey"],
                                               "token": c["SessionToken"], "expires": c["Expiration"].timestamp()}}
    n = str(event.get("n", 0))

    def own_calls(ctx):
        s3 = _client("s3", g("own_calls"), ctx)
        s3.put_object(Bucket=bucket, Key=f"own/{n}", Body=b"x")
        s3.get_object(Bucket=bucket, Key=f"own/{n}")["Body"].read()

    def another_identity(ctx):
        session = event.get("session")
        if not session:
            raise RuntimeError("NoSession")
        other = _client("s3", g("another_identity"), ctx, aws_access_key_id=session["key"],
                        aws_secret_access_key=session["secret"], aws_session_token=session["token"])
        other.put_object(Bucket=bucket, Key=f"another/{n}", Body=b"x")

    def outside_key(ctx):
        _get(f"{endpoint}/key", {"Authorization": "Bearer " + os.environ["OUTSIDE_KEY"]}, g("outside_key"), ctx)

    def open_internet(ctx):
        _get(f"{endpoint}/open", {}, g("open_internet"), ctx)

    def model(ctx):
        _client("bedrock-runtime", g("model"), ctx).converse(modelId=os.environ["MODEL"],
                                                             inferenceConfig={"maxTokens": 1},
                                                             messages=[{"role": "user", "content": [{"text": "1"}]}])

    beats = {"own_calls": _try(own_calls), "another_identity": _try(another_identity),
             "outside_key": _try(outside_key), "open_internet": _try(open_internet)}
    if os.environ.get("MODEL"):
        beats["model"] = _try(model)
    return {"at": time.time(), "beats": beats, "key": os.environ.get("AWS_ACCESS_KEY_ID"), "v": VERSIONS}
