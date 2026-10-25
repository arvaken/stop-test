"""The test agent on Google Cloud: the code of the Cloud Run service the kit deploys (the design's sections 3 and 4).

The kit calls it once a second, with the kit's own identity. Each call tries each path once and returns, for each, when
(by its own clock), whether it succeeded, and if not the error's code. It prints nothing and writes no logs of its own
(Cloud Run's request logs and Cloud Audit Logs still record the kit's calls and acts), and a stop that denies the agent
everything cannot stop its report: the reply goes back to the kit through Cloud Run, not through anything the agent's identity reaches.

The paths (the design's section 4; D532, K3):
- own_calls: writes and reads one small object in the kit's bucket, as the agent's own service account. Its access
  token comes from the metadata server and is kept until shortly before it expires, as Google's client libraries keep
  one: a stop that leaves a token already issued working is measured as it would be on a real agent.
- another_identity: writes to the bucket with a token of the kit's second service account, which the agent made
  before the stop was fired (IAM Credentials' generateAccessToken). The kit hands it back with each call.
- outside_key: calls Arvaken's test endpoint with the key the kit made for the run, held in the agent's environment.
- open_internet: fetches Arvaken's test endpoint with no key.

This file is the service's code, run by Python's own image with nothing added: the standard library alone.
"""
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

TIMEOUT = 2.0
AGENT = "arvaken-stop-test-agent (+https://github.com/arvaken/stop-test)"
METADATA = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
STORAGE = "https://storage.googleapis.com"
REFRESH = 225.0          # seconds before expiry a token is fetched again, as Google's Python client does
_own = {"token": None, "until": 0.0}


def _code(e):
    """An error's code alone, never its message: the message can name resources and principals."""
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


def _call(url, headers=None, data=None, method="GET"):
    request = urllib.request.Request(url, data=data, method=method, headers={"User-Agent": AGENT, **(headers or {})})
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        return response.read(4096)


def own_token():
    if _own["token"] is None or time.time() >= _own["until"] - REFRESH:
        body = json.loads(_call(METADATA, {"Metadata-Flavor": "Google"}))
        _own["token"], _own["until"] = body["access_token"], time.time() + float(body["expires_in"])
    return _own["token"]


def _put(token, name):
    bucket = os.environ["BUCKET"]
    url = f"{STORAGE}/upload/storage/v1/b/{bucket}/o?" + urllib.parse.urlencode({"uploadType": "media", "name": name})
    _call(url, {"Authorization": f"Bearer {token}", "Content-Type": "text/plain"}, b"x", "POST")


def _get(token, name):
    bucket = os.environ["BUCKET"]
    _call(f"{STORAGE}/storage/v1/b/{bucket}/o/{urllib.parse.quote(name, safe='')}?alt=media",
          {"Authorization": f"Bearer {token}"})


def take_second_identity():
    """Before the stop: a token for the second service account, which the kit passes back with each call."""
    second = os.environ["SECOND_ACCOUNT"]
    url = f"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{second}:generateAccessToken"
    body = json.dumps({"scope": ["https://www.googleapis.com/auth/devstorage.read_write"], "lifetime": "3600s"})
    answer = json.loads(_call(url, {"Authorization": f"Bearer {own_token()}", "Content-Type": "application/json"},
                              body.encode(), "POST"))
    return {"token": answer["accessToken"], "expires": answer["expireTime"]}


def beat(event):
    endpoint = os.environ["ENDPOINT"].rstrip("/")
    n = str(event.get("n", 0))

    def own_calls():
        token = own_token()
        _put(token, f"own/{n}")
        _get(token, f"own/{n}")

    def another_identity():
        session = event.get("session") or {}
        if not session.get("token"):
            raise RuntimeError("NoSession")
        _put(session["token"], f"another/{n}")

    def outside_key():
        _call(f"{endpoint}/key", {"Authorization": "Bearer " + os.environ["OUTSIDE_KEY"]})

    def open_internet():
        _call(f"{endpoint}/open")

    return {"own_calls": _try(own_calls), "another_identity": _try(another_identity),
            "outside_key": _try(outside_key), "open_internet": _try(open_internet)}


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802 - http.server's name
        event = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
        try:
            if event.get("action") == "assume":
                out = {"at": time.time(), "session": take_second_identity()}
            else:
                out = {"at": time.time(), "beats": beat(event)}
            status = 200
        except Exception as e:  # noqa: BLE001 - said by its code, as a path's error is
            out, status = {"at": time.time(), "error": _code(e)}, 500
        body = json.dumps(out).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):          # prints nothing
        pass


def serve():
    HTTPServer(("", int(os.environ.get("PORT", "8080"))), Handler).serve_forever()


if __name__ == "__main__":
    serve()
