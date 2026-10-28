"""The test agent on AgentCore: the code of the AgentCore runtime the kit makes, shipped as its main.py (arvaken/mark,
AGENTCORE-MEASUREMENT.md, sections 1 and 2; D618).

AgentCore runs it in a session of its own and hands it each call made to that session, as AWS's HTTP protocol contract
says: it listens on 0.0.0.0, port 8080, takes calls on POST /invocations and answers health checks on GET /ping
[source: aws-agentcore-http-container]. It answers two kinds of call:

- "answer": a new call to the agent. It answers at once, with its own clock and nothing else. What is timed on this path
  is whether AgentCore lets a new call reach the agent at all, so it tries none of its paths.
- "watch": the running session. It assumes the kit's second role once, before the stop, then tries each of its four
  paths about once a second, as the Lambda agent does (aws/agent.py), and reports each try as one event of the call's
  streaming response (text/event-stream), for as many seconds as the kit asks. AWS keeps a streaming response open up to
  60 minutes [source: aws-agentcore-streaming-limit], so one call holds the whole window. Its reports go back through
  AgentCore, never through anything the agent's role reaches, so a stop that denies the role everything cannot silence
  them; a stop that ends the session ends the stream.

The paths (the design's section 1):
- own_calls: writes and reads one small object in the run's bucket, as the runtime's own role;
- another_identity: writes to the bucket with the session it took for the second role before the stop;
- outside_key: calls Arvaken's test endpoint with the run's key, held in the runtime's environment;
- open_internet: fetches Arvaken's test endpoint with no key.

Each object it writes is named by the watch's tag (the kit's name for the session) and the try's number, so the kit can
tell afterwards whether a session went on writing once its stream had closed (run.py).

/ping says "HealthyBusy" while a watch is streaming, so AgentCore keeps the session (AWS: "While the status is
HealthyBusy, the runtime session is considered active and is kept alive"), and "Healthy" otherwise. It never sends
time_of_last_update, which AWS says not to set to the current time on every ping [source: aws-agentcore-healthy-busy,
aws-agentcore-ping-last-update].

It prints nothing and writes no logs of its own: http.server's line for each request is turned off, and the runtime's
role may not write logs. An error is reported by its code alone, never its message, which can name resources and
principals; every failure is caught, as each is a try's result.

The kit ships boto3 and botocore beside it in the zip, from its own installation (stack.py): AgentCore's Python runtime
is not promised to hold them, and they are pure Python.
"""
import json
import os
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import boto3
import botocore.config
import botocore.exceptions

CONFIG = botocore.config.Config(connect_timeout=2, read_timeout=2, retries={"max_attempts": 1})
TIMEOUT = 2.0
AGENT = "arvaken-stop-test-agent (+https://github.com/arvaken/stop-test)"
EVERY = 1.0                 # seconds between a watch's tries
# The longest watch: AWS keeps a streaming response up to 60 minutes [source: aws-agentcore-streaming-limit].
LONGEST = 3540.0
PORT = 8080

_busy = 0
_lock = threading.Lock()


def _code(e):
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
    except Exception as e:  # noqa: BLE001
        return {"at": at, "ok": False, "error": _code(e)}


def _get(url, headers):
    request = urllib.request.Request(url, headers={"User-Agent": AGENT, **headers}, method="GET")
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        response.read(64)


def assume():
    """The second role's session, taken once as the watch begins, before the stop: its keys and when it expires; or
    the error's code."""
    try:
        c = boto3.client("sts", config=CONFIG).assume_role(RoleArn=os.environ["SECOND_ROLE"],
                                                          RoleSessionName="arvaken-stop-test",
                                                          DurationSeconds=3600)["Credentials"]
    except Exception as e:  # noqa: BLE001 - the path then reads as not set up
        return {"error": _code(e)}
    return {"key": c["AccessKeyId"], "secret": c["SecretAccessKey"], "token": c["SessionToken"],
            "expires": c["Expiration"].timestamp()}


def probe(s3, other, tag, n):
    """One try of each path."""
    bucket, endpoint = os.environ["BUCKET"], os.environ["ENDPOINT"].rstrip("/")

    def own_calls():
        s3.put_object(Bucket=bucket, Key=f"own/{tag}/{n}", Body=b"x")
        s3.get_object(Bucket=bucket, Key=f"own/{tag}/{n}")["Body"].read()

    def another_identity():
        if other is None:
            raise RuntimeError("NoSession")
        other.put_object(Bucket=bucket, Key=f"another/{tag}/{n}", Body=b"x")

    def outside_key():
        _get(f"{endpoint}/key", {"Authorization": "Bearer " + os.environ["OUTSIDE_KEY"]})

    def open_internet():
        _get(f"{endpoint}/open", {})

    return {"own_calls": _try(own_calls), "another_identity": _try(another_identity),
            "outside_key": _try(outside_key), "open_internet": _try(open_internet)}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):          # the agent writes no logs of its own
        pass

    def _json(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path != "/ping":
            return self._json(404, {})
        with _lock:
            busy = _busy > 0
        self._json(200, {"status": "HealthyBusy" if busy else "Healthy"})

    def _body(self):
        """The call's body, sent with its length or in chunks."""
        if "chunked" not in (self.headers.get("Transfer-Encoding") or "").lower():
            return self.rfile.read(int(self.headers.get("Content-Length") or 0))
        data = b""
        while True:
            size = int(self.rfile.readline().split(b";")[0].strip() or b"0", 16)
            if not size:
                self.rfile.readline()
                return data
            data += self.rfile.read(size)
            self.rfile.readline()

    def do_POST(self):
        if self.path != "/invocations":
            return self._json(404, {})
        try:
            body = json.loads(self._body() or b"{}")
        except ValueError:
            return self._json(400, {"error": "NotJSON"})
        if body.get("action") == "answer":
            return self._json(200, {"at": time.time()})
        if body.get("action") == "watch":
            return self.watch(min(float(body.get("seconds") or 0), LONGEST), str(body.get("tag") or "watch"))
        return self._json(400, {"error": "UnknownAction"})

    def _event(self, body):
        data = b"data: " + json.dumps(body).encode() + b"\n\n"
        self.wfile.write(b"%X\r\n%s\r\n" % (len(data), data))
        self.wfile.flush()

    def watch(self, seconds, tag):
        global _busy
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        with _lock:
            _busy += 1
        try:
            s3 = boto3.client("s3", config=CONFIG)
            session = assume()
            other = None if "error" in session else boto3.client(
                "s3", config=CONFIG, aws_access_key_id=session["key"], aws_secret_access_key=session["secret"],
                aws_session_token=session["token"])
            self._event({"at": time.time(), "session_expires": session.get("expires"), "error": session.get("error")})
            end, n, due = time.time() + seconds, 0, time.time()
            while time.time() < end:
                self._event({"at": time.time(), "n": n, "beats": probe(s3, other, tag, n)})
                n, due = n + 1, due + EVERY
                time.sleep(max(0.0, due - time.time()))
            self._event({"at": time.time(), "done": True})
            self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()
        except OSError:                     # the stream was closed: the watch ends with it
            self.close_connection = True
        finally:
            with _lock:
                _busy -= 1


def serve():
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    server.daemon_threads = True
    server.serve_forever()


if __name__ == "__main__":
    serve()
