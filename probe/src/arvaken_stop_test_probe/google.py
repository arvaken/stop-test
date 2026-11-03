"""Google Cloud's own part of the probe (D575, Google Cloud after AWS, as its section 7 orders it): the run's settings
that name Google's resources, the calls Google's paths make, and Google's failure records. Each is the kit's own Google
test agent's (the kit's google/agent.py), so a copy on Cloud Run makes the calls the kit's agent makes.

- own_calls: writes and reads one small object in the run's bucket, as the copy itself (the service account made for
  the run, KC1). Its access token comes from the metadata server and is kept until shortly before it expires, as
  Google's client libraries keep one: a stop that leaves a token already issued working is measured as it would be on
  a real agent.
- another_identity: writes to the bucket with a token of the run's second service account, which the probe took before
  the stop was fired (`assume`, IAM Credentials' generateAccessToken). The kit hands it back with each call.

The settings come in the kit's marker, as on AWS, and are taken only where they name the run: its bucket, named as the
run (the kit's google/stack.names), and its second account, named as the run's.

**Clients (KC2).** `request` is the customer's function that makes an HTTPS request as these calls need one,
`request(method, url, headers, body, timeout)`, giving back the answer's HTTP status and its body; else the standard
library's (runtime_request). Every Google call of the probe's goes through it, the metadata server's among them.
"""
from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime

from arvaken_stop_test_probe import core
from arvaken_stop_test_probe.core import NotTheKits

CLOUD = "google_cloud"                      # the marker's cloud, as the kit's result names it
PREFIX = "arvaken-stop-test"                # the kit's google/stack.PREFIX
PROJECT = r"[a-z][a-z0-9-]{4,28}[a-z0-9]"   # a project's ID, as Google allows one
METADATA = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
STORAGE = "https://storage.googleapis.com"
CREDENTIALS = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/"
REFRESH = 225.0     # seconds before expiry a token is fetched again, as Google's Python client does (the kit's agent.py)
READ = 4096         # bytes of an answer read, at most, as the kit's agent reads them
WORD = 64           # a reason or a status is a word of Google's, at most this long; anything else is not kept
_OWN = {"token": None, "until": 0.0, "issued": 0.0}


class Answered(Exception):
    """A Google call answered with an HTTP status of 400 or more: its status, and the body Google gave with it, which
    record() reads for Google's reason and status alone."""

    def __init__(self, status, body):
        super().__init__(f"HTTP{status}")
        self.status, self.body = status, body


def settings(m) -> dict:
    """Google's settings from the kit's marker, each checked to name the run; else NotTheKits."""
    run = m["run"]
    bucket, second, action = m.get("bucket"), m.get("second_account"), m.get("action")
    if bucket != f"{PREFIX}-{run}":
        raise NotTheKits("bucket")
    if not (isinstance(second, str) and
            re.fullmatch(re.escape(f"arvaken-st-{run}-b@") + PROJECT + r"\.iam\.gserviceaccount\.com", second)):
        raise NotTheKits("second_account")
    if action not in (None, "assume"):
        raise NotTheKits("action")
    return {"bucket": bucket, "second_account": second, "action": action, "n": str(m.get("n", 0)),
            "session": m.get("session")}


def runtime_request(method, url, headers, body, timeout):
    """The runtime's own request: the standard library's. The HTTP status, and the answer's body, READ bytes at most."""
    request = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read(READ)
    except urllib.error.HTTPError as e:
        return e.code, e.read(READ)


def _call(request, method, url, headers, body=None):
    status, answer = request(method, url, {"User-Agent": core.AGENT, **headers}, body, core.TIMEOUT)
    if int(status) >= 400:
        raise Answered(int(status), answer)
    return answer


def _word(v):
    return v if isinstance(v, str) and 0 < len(v) <= WORD and v.replace("_", "").isalnum() else None


def record(e) -> dict:
    """Google's failure record, as the kit's agent's _record: an answer's code and HTTP status, and Google's reason and
    status from its body, where it has them; anything else, the core's."""
    if not isinstance(e, Answered):
        return core.record(e)
    reason = google = None
    try:
        error = json.loads(e.body or b"{}").get("error") or {}
    except Exception:  # noqa: BLE001 - a body that is not Google's JSON error has no reason or status
        error = {}
    if isinstance(error, dict):
        # Storage's reason is its errors[0].reason; an API's in Google's newer format, its ErrorInfo's
        listed = [x for k in ("errors", "details") if isinstance(error.get(k), list) for x in error[k]]
        found = [x for x in listed if isinstance(x, dict)
                 and ("@type" not in x or str(x["@type"]).endswith("google.rpc.ErrorInfo"))]
        reason, google = _word(found[0].get("reason") if found else None), _word(error.get("status"))
    return {"error": f"HTTP{e.status}", "status": e.status, "reason": reason, "provider_status": google}


def own_token(request) -> str:
    """The copy's own access token, from the metadata server, kept until REFRESH seconds before it expires."""
    if _OWN["token"] is None or time.time() >= _OWN["until"] - REFRESH:
        body = json.loads(_call(request, "GET", METADATA, {"Metadata-Flavor": "Google"}))
        now = time.time()
        _OWN.update(token=body["access_token"], until=now + float(body["expires_in"]), issued=now)
    return _OWN["token"]


def _seconds(text) -> float:
    """An RFC 3339 time, as Google writes one, in seconds: its whole seconds as Python 3.9 reads them, then its fraction,
    of any length."""
    found = re.fullmatch(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(\.\d+)?(Z|[+-]\d\d:\d\d)", str(text))
    if not found:
        raise ValueError("NotATime")
    whole, fraction, zone = found.groups()
    return datetime.fromisoformat(whole + ("+00:00" if zone == "Z" else zone)).timestamp() + float("0" + (fraction or ""))


def assume(s, request) -> dict:
    """Before the stop: a token of the run's second account, which the kit hands back with each call."""
    url = CREDENTIALS + urllib.parse.quote(s["second_account"], safe="@.") + ":generateAccessToken"
    body = json.dumps({"scope": ["https://www.googleapis.com/auth/devstorage.read_write"], "lifetime": "3600s"})
    answer = json.loads(_call(request, "POST", url, {"Authorization": f"Bearer {own_token(request)}",
                                                     "Content-Type": "application/json"}, body.encode()))
    return {"token": answer["accessToken"], "expires": answer["expireTime"], "issued": time.time()}


def _put(request, bucket, token, name):
    url = f"{STORAGE}/upload/storage/v1/b/{bucket}/o?" + urllib.parse.urlencode({"uploadType": "media", "name": name})
    _call(request, "POST", url, {"Authorization": f"Bearer {token}", "Content-Type": "text/plain"}, b"x")


def _get(request, bucket, token, name):
    _call(request, "GET", f"{STORAGE}/storage/v1/b/{bucket}/o/{urllib.parse.quote(name, safe='')}?alt=media",
          {"Authorization": f"Bearer {token}"})


def identity_paths(s, request) -> list:
    """own_calls and another_identity, each naming the objects it writes by the heartbeat's number, as the kit's agent
    names them."""
    bucket, n = s["bucket"], s["n"]

    def own_calls(ctx):
        ctx["step"] = "token"
        token = own_token(request)
        ctx.update(step="write", token_issued=_OWN["issued"], token_expires=_OWN["until"])
        _put(request, bucket, token, f"own/{n}")
        ctx["step"] = "read"
        _get(request, bucket, token, f"own/{n}")

    def another_identity(ctx):
        session = s["session"] if isinstance(s["session"], dict) else {}
        if not session.get("token"):
            raise RuntimeError("NoSession")
        ctx.update(step="write", token_issued=session.get("issued"), token_expires=_seconds(session.get("expires")))
        _put(request, bucket, session["token"], f"another/{n}")

    return [("own_calls", own_calls), ("another_identity", another_identity)]
