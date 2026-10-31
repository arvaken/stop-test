"""The probe in an AgentCore harness's running session: the code the kit runs there with InvokeAgentRuntimeCommand, as
one command for the whole watch (harness.py; arvaken/mark, AGENTCORE-MEASUREMENT.md, section 7; D618).

A harness is AWS's own agent loop, and it runs a tool only when its model chooses one: "Tools run only as a result of
model reasoning." [source: aws-agentcore-harness-tools-reasoning] So the four paths are not tried by the harness's model
but by this script, in the session's microVM, with no model in between [source: aws-agentcore-harness-execute-command].
The microVM runs as the harness's execution role [source: aws-agentcore-harness-execution-role], so this script's calls
to AWS are that role's, as the runtime's agent's are its role's (agent.py).

The commands' environment includes Python and bash [source: aws-agentcore-harness-base-environment], and nothing more
is promised of it, boto3 among it, so the script uses Python's standard library alone. It takes the role's credentials
as the microVM gives them (CREDENTIAL_ORDER) and signs its own calls to AWS with Signature Version 4 (sign), which the
kit's tests check against botocore's signer.

It tries the runtime agent's four paths about once a second, each as the runtime's agent tries it:
- own_calls: writes and reads one small object in the run's bucket, as the harness's role;
- another_identity: writes to the bucket with the session it took for the second role before the stop;
- outside_key: calls Arvaken's test endpoint with the run's key, held in the harness's environment;
- open_internet: fetches Arvaken's test endpoint with no key.

It prints one line of JSON for each try, as the runtime's watch sends one event: first the second role's session (when
it expires, or the error's code), then each try's results, then `{"done": true}` once the watch's seconds are over. Each
object it writes is named by the watch's tag and the try's number, as the runtime's agent names them. It prints nothing
else, and an error is reported by its code alone, never its message, which can name resources and principals.

Run as: python3 probe.py <seconds> <tag> <region> <bucket> <endpoint> <second role>, or python3 probe.py clock. The
run's key is the one thing it reads from the harness's environment (OUTSIDE_KEY): AgentCore logs each command's text, so
the command names nothing that is a secret.
"""
import datetime
import hashlib
import hmac
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

TIMEOUT = 2.0
EVERY = 1.0                 # seconds between a watch's tries
AGENT = "arvaken-stop-test-agent (+https://github.com/arvaken/stop-test)"
IMDS = "http://169.254.169.254"
CONTAINER = "http://169.254.170.2"
# Where the role's credentials are looked for, in order: as AWS's SDKs look for them.
CREDENTIAL_ORDER = ("environment", "container", "instance")
REFRESH = 300.0             # seconds before credentials expire that they are taken again
UNRESERVED = "-_.~"


class Failed(Exception):
    """A try's failure, by its code alone."""

    def __init__(self, code):
        super().__init__(code)
        self.code = str(code)[:64]


def _code(e):
    if isinstance(e, Failed):
        return e.code
    if isinstance(e, urllib.error.HTTPError):
        return f"HTTP{e.code}"
    if isinstance(e, (TimeoutError, urllib.error.URLError, OSError)):
        return "Unreachable"
    return type(e).__name__[:64]


def _try(fn):
    at = time.time()
    try:
        fn()
        return {"at": at, "ok": True}
    except Exception as e:  # noqa: BLE001 - each failure is a try's result
        return {"at": at, "ok": False, "error": _code(e)}


def _open(request, timeout=TIMEOUT):
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


# -- the role's credentials, as the microVM gives them
def _expiry(text):
    """An expiry as the credentials give it, "2026-10-29T18:00:00Z", with or without a fraction of a second."""
    if not text:
        return None
    whole = re.sub(r"(\.\d+)?(Z|[+-]00:?00)?$", "", text.strip())
    return datetime.datetime.strptime(whole, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=datetime.timezone.utc).timestamp()


def from_environment(env):
    if env.get("AWS_ACCESS_KEY_ID") and env.get("AWS_SECRET_ACCESS_KEY"):
        return {"key": env["AWS_ACCESS_KEY_ID"], "secret": env["AWS_SECRET_ACCESS_KEY"],
                "token": env.get("AWS_SESSION_TOKEN"), "expires": None}
    return None


def from_container(env, opener=_open):
    url = env.get("AWS_CONTAINER_CREDENTIALS_FULL_URI") or (
        CONTAINER + env["AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"] if env.get("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
        else None)
    if not url:
        return None
    headers = {}
    token = env.get("AWS_CONTAINER_AUTHORIZATION_TOKEN")
    if env.get("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE"):
        with open(env["AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE"], encoding="utf-8") as f:
            token = f.read().strip()
    if token:
        headers["Authorization"] = token
    got = json.loads(opener(urllib.request.Request(url, headers=headers)))
    return {"key": got["AccessKeyId"], "secret": got["SecretAccessKey"], "token": got.get("Token"),
            "expires": _expiry(got.get("Expiration"))}


def from_instance(opener=_open):
    token = opener(urllib.request.Request(f"{IMDS}/latest/api/token", method="PUT",
                                          headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"})).decode()
    headers = {"X-aws-ec2-metadata-token": token}
    base = f"{IMDS}/latest/meta-data/iam/security-credentials/"
    role = opener(urllib.request.Request(base, headers=headers)).decode().split()[0]
    got = json.loads(opener(urllib.request.Request(base + role, headers=headers)))
    return {"key": got["AccessKeyId"], "secret": got["SecretAccessKey"], "token": got.get("Token"),
            "expires": _expiry(got.get("Expiration"))}


class Credentials:
    """The harness's role's credentials, taken again REFRESH seconds before they expire. `source` says where they
    came from."""

    def __init__(self, env=None, opener=_open):
        self.env, self.opener, self.current, self.source = env if env is not None else os.environ, opener, None, None

    def get(self):
        if self.current and (self.current["expires"] is None or self.current["expires"] - time.time() > REFRESH):
            return self.current
        for source in CREDENTIAL_ORDER:
            try:
                found = (from_environment(self.env) if source == "environment" else
                         from_container(self.env, self.opener) if source == "container" else
                         from_instance(self.opener))
            except Exception:  # noqa: BLE001 - the next place is looked in
                continue
            if found:
                self.current, self.source = found, source
                return found
        raise Failed("NoCredentials")


# -- Signature Version 4
def _quote(text, safe=UNRESERVED):
    return urllib.parse.quote(text, safe=safe)


def sign(method, url, region, service, creds, body=b"", headers=None, now=None):
    """The headers that sign this request with Signature Version 4, the request's own among them."""
    parts = urllib.parse.urlsplit(url)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(time.time() if now is None else now))
    day = stamp[:8]
    payload = hashlib.sha256(body).hexdigest()
    signed_headers = {k.lower(): str(v) for k, v in (headers or {}).items()}
    signed_headers.update({"host": parts.netloc, "x-amz-date": stamp})
    if service == "s3":
        signed_headers["x-amz-content-sha256"] = payload
    if creds.get("token"):
        signed_headers["x-amz-security-token"] = creds["token"]
    names = sorted(signed_headers)
    query = sorted(urllib.parse.parse_qsl(parts.query, keep_blank_values=True))
    canonical = "\n".join([
        method,
        _quote(parts.path or "/", safe=UNRESERVED + "/"),
        "&".join(f"{_quote(k)}={_quote(v)}" for k, v in query),
        "".join(f"{k}:{' '.join(signed_headers[k].split())}\n" for k in names),
        ";".join(names),
        payload])
    scope = f"{day}/{region}/{service}/aws4_request"
    to_sign = "\n".join(["AWS4-HMAC-SHA256", stamp, scope, hashlib.sha256(canonical.encode()).hexdigest()])
    key = ("AWS4" + creds["secret"]).encode()
    for part in (day, region, service, "aws4_request"):
        key = hmac.new(key, part.encode(), hashlib.sha256).digest()
    signature = hmac.new(key, to_sign.encode(), hashlib.sha256).hexdigest()
    signed_headers["authorization"] = (f"AWS4-HMAC-SHA256 Credential={creds['key']}/{scope}, "
                                       f"SignedHeaders={';'.join(names)}, Signature={signature}")
    return signed_headers


def _aws_error(e):
    """An AWS answer's error code, from its XML body; else the HTTP status."""
    try:
        found = re.search(rb"<Code>([A-Za-z0-9.]{1,64})</Code>", e.read())
    except Exception:  # noqa: BLE001
        found = None
    return Failed(found.group(1).decode() if found else f"HTTP{e.code}")


def call(method, url, region, service, creds, body=b"", headers=None, opener=_open):
    request = urllib.request.Request(url, data=body if method != "GET" else None, method=method,
                                     headers=sign(method, url, region, service, creds, body, headers))
    try:
        return opener(request)
    except urllib.error.HTTPError as e:
        raise _aws_error(e) from None


def s3_url(bucket, key, region):
    return f"https://{bucket}.s3.{region}.amazonaws.com/{_quote(key, safe=UNRESERVED + '/')}"


def assume(role, region, creds, opener=_open):
    """The second role's session, taken once before the stop: its keys and when it expires."""
    body = urllib.parse.urlencode({"Action": "AssumeRole", "Version": "2011-06-15", "RoleArn": role,
                                   "RoleSessionName": "arvaken-stop-test", "DurationSeconds": "3600"}).encode()
    answer = call("POST", f"https://sts.{region}.amazonaws.com/", region, "sts", creds, body,
                  {"content-type": "application/x-www-form-urlencoded; charset=utf-8"}, opener)
    found = {el.tag.rpartition("}")[2]: el.text for el in ET.fromstring(answer).iter()}
    return {"key": found["AccessKeyId"], "secret": found["SecretAccessKey"], "token": found["SessionToken"],
            "expires": _expiry(found["Expiration"])}


def probe(role, other, tag, n, run, opener=_open):
    """One try of each path."""
    bucket, endpoint, region = run["bucket"], run["endpoint"].rstrip("/"), run["region"]

    def own_calls():
        url = s3_url(bucket, f"own/{tag}/{n}", region)
        call("PUT", url, region, "s3", role.get(), b"x", opener=opener)
        call("GET", url, region, "s3", role.get(), opener=opener)

    def another_identity():
        if other is None:
            raise Failed("NoSession")
        call("PUT", s3_url(bucket, f"another/{tag}/{n}", region), region, "s3", other, b"x", opener=opener)

    def outside_key():
        if not run.get("key"):
            raise Failed("NoKey")
        opener(urllib.request.Request(f"{endpoint}/key", headers={"User-Agent": AGENT,
                                                                  "Authorization": "Bearer " + run["key"]}))

    def open_internet():
        opener(urllib.request.Request(f"{endpoint}/open", headers={"User-Agent": AGENT}))

    return {"own_calls": _try(own_calls), "another_identity": _try(another_identity),
            "outside_key": _try(outside_key), "open_internet": _try(open_internet)}


def _say(event, out):
    out.write(json.dumps(event) + "\n")
    out.flush()


def watch(seconds, tag, region, bucket, endpoint, second_role, env=None, opener=_open, out=None):
    env, out = env if env is not None else os.environ, out or sys.stdout
    run = {"bucket": bucket, "endpoint": endpoint, "region": region, "key": env.get("OUTSIDE_KEY")}
    role = Credentials(env, opener)
    try:
        other, error = assume(second_role, region, role.get(), opener), None
    except Exception as e:  # noqa: BLE001 - the path then reads as not set up
        other, error = None, _code(e)
    _say({"at": time.time(), "session_expires": other and other["expires"], "error": error,
          "credentials_from": role.source}, out)
    end, n, due = time.time() + seconds, 0, time.time()
    while time.time() < end:
        _say({"at": time.time(), "n": n, "beats": probe(role, other, tag, n, run, opener)}, out)
        n, due = n + 1, due + EVERY
        time.sleep(max(0.0, due - time.time()))
    _say({"at": time.time(), "done": True}, out)


def clock():
    """The microVM's clock, for the kit's warm-up."""
    print(json.dumps({"at": time.time()}), flush=True)


if __name__ == "__main__":
    if sys.argv[1:2] == ["clock"]:
        clock()
    else:
        watch(float(sys.argv[1]), *sys.argv[2:7])
