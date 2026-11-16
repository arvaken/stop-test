"""The host's own part of the probe: a test copy of your agent on a host you control (D709; mark's
docs/platform/STOP-TEST-ANY-HOST-DESIGN.md, sections 1 to 4). It shares the probe's core (core.py): its beats, its
failure records and its User-Agent are the core's.

On a host there is no cloud for the kit to call the copy through, so the probe beats on its own, once a second, in a
thread of the copy's own process (`start`, which heartbeat.on_host calls), until the run is over. Each beat tries these
paths, in order (the design's section 2):

- outside_key: an HTTPS GET to the observer's keyed address, `/key`, with the run's own key;
- open_internet: an HTTPS GET to the observer's open address, `/open/<run>`, with no key. The run's name in the address
  is not a key: it keeps a stray request to the observer's port from counting as the copy's;
- model, only where the run's settings turn it on (KH7): one call through the function you pass (`model`), which calls
  your model provider with a key you made for the run. The probe keeps nothing of its answer;
- its work on the host itself: nothing. Whether it kept working there can't be seen from outside the host (KH4).

After its paths, each beat sends the observer the probe's report, on a call of its own with the run's key: each path's
outcome by the copy's clock and its failure record (core.record: a code and an HTTP status, never a message). The
observer times every path by its own clock alone (KH5): the two calls to it by their arrivals, and the model by the
reports that say its call worked.

**The run's settings** come from the file the kit writes for the run (`settings`): the observer's address, the
certificate it presents for the run, the run's name and key, until when the probe may beat, and whether the model path
is on. The probe reads nothing else: never the copy's environment, its credentials or a proxy set there. The observer
is reached only at the address in the settings, and only if it presents the run's certificate (`pinned`): the probe
trusts no other.

**When it stops:** when the observer answers its report with 410 (the run is over), when `stop` is called, or at the
settings' `until`, whichever is first. A stop of your host's that ends the process or cuts its network stops it too,
which is what the kit times.

Its code keeps to Python 3.9's grammar and uses the standard library alone.
"""
from __future__ import annotations

import ipaddress
import json
import re
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from arvaken_stop_test_probe import core
from arvaken_stop_test_probe.core import NotTheKits

EVERY = 1.0                         # seconds between beats
OVER = 410                          # the observer's answer once the run is over: the probe stops
CERTIFICATE_LIMIT = 8192            # characters of the run's certificate, at most
REPORT_LIMIT = 4096                 # bytes of a report, at most, as the observer takes it
WORD = 64                           # an error's code, at most this long
PEM = re.compile(r"-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\r?\n?")
HOSTNAME = re.compile(r"(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}"
                      r"[A-Za-z0-9])?)*")


def observer_address(text) -> str | None:
    """The observer's address as the settings hold it, `https://host:port`, with a host name, an IPv4 address or a
    bracketed IPv6 one, and a port; nothing more. None where it is not one."""
    if not isinstance(text, str) or len(text) > 300:
        return None
    try:
        parts = urllib.parse.urlsplit(text)
        port = parts.port
    except ValueError:
        return None
    host = parts.hostname or ""
    if parts.scheme != "https" or not port or parts.username or parts.password or parts.path or parts.query or \
            parts.fragment:
        return None
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not HOSTNAME.fullmatch(host):
            return None
    return text if text == f"https://{parts.netloc}" else None


def _settings(doc, secret: str) -> dict:
    """The settings the kit wrote for the run, checked; `secret` is the key's field: the probe's "key", the witness's
    "witness_key". Else NotTheKits, naming the first setting that is not the run's."""
    if not core.is_mine(doc):
        raise NotTheKits("run")
    m = doc[core.MARKER]
    if not (isinstance(m.get(secret), str) and core.KEY.fullmatch(m[secret])):
        raise NotTheKits(secret)
    h = m.get("host")
    if not isinstance(h, dict):
        raise NotTheKits("host")
    observer = observer_address(h.get("observer"))
    if observer is None:
        raise NotTheKits("observer")
    cert = h.get("certificate")
    if not (isinstance(cert, str) and len(cert) <= CERTIFICATE_LIMIT and PEM.fullmatch(cert)):
        raise NotTheKits("certificate")
    until = h.get("until")
    if not (isinstance(until, (int, float)) and not isinstance(until, bool) and until > 0):
        raise NotTheKits("until")
    model = h.get("model", False)
    if not isinstance(model, bool):
        raise NotTheKits("model")
    return {"run": m["run"], "key": m[secret], "observer": observer, "certificate": cert, "until": float(until),
            "model": model}


def settings(doc) -> dict:
    """The probe's settings, from the file the kit wrote for the run (or its JSON, already read)."""
    return _settings(_read(doc), "key")


def witness_settings(doc) -> dict:
    """The witness's settings, from the file the kit wrote for it."""
    return _settings(_read(doc), "witness_key")


def _read(doc):
    if isinstance(doc, dict):
        return doc
    with open(doc, encoding="utf-8") as f:
        return json.load(f)


def pinned(certificate: str) -> ssl.SSLContext:
    """A TLS context that trusts the run's certificate alone, checks the observer's name against it, and nothing
    else: no system store."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_verify_locations(cadata=certificate)
    return context


def opener(context: ssl.SSLContext) -> urllib.request.OpenerDirector:
    """urllib's opener with the run's TLS context and no proxy: never one from the copy's environment."""
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))


def runtime_get(context: ssl.SSLContext):
    """The runtime's own GET, to the observer alone: `get(url, headers, timeout)` gives back the HTTP status; urllib
    raises for one of 400 or more."""
    through = opener(context)

    def get(url, headers, timeout):
        request = urllib.request.Request(url, headers=headers, method="GET")
        with through.open(request, timeout=timeout) as response:
            response.read(64)
            return response.status
    return get


def runtime_post(context: ssl.SSLContext):
    """The probe's own POST of its report, and the witness's of its beat: the HTTP status, a refusal's included."""
    through = opener(context)

    def post(url, headers, body, timeout):
        request = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with through.open(request, timeout=timeout) as response:
                response.read(64)
                return response.status
        except urllib.error.HTTPError as e:
            return e.code
    return post


def record(e) -> dict:
    """A failure's record on a host: the core's, with a refused certificate named as such, and a model client's own
    HTTP status where its error carries one as a number."""
    if isinstance(e, urllib.error.URLError) and isinstance(getattr(e, "reason", None), ssl.SSLError):
        return {"error": "TLSRefused", "status": None, "reason": None}
    found = core.record(e)
    if found["status"] is None:
        for name in ("status_code", "status"):
            status = getattr(e, name, None)
            if isinstance(status, int) and not isinstance(status, bool) and 100 <= status <= 599:
                found["status"] = status
                break
    found["error"] = str(found["error"])[:WORD]
    return found


def paths(s: dict, get, model=None) -> list:
    """The beat's paths, in order: the observer's keyed and open addresses, and the model where it is on."""
    def outside_key(ctx):
        core._get(get, f"{s['observer']}/key", {"Authorization": "Bearer " + s["key"]})

    def open_internet(ctx):
        core._get(get, f"{s['observer']}/open/{s['run']}", {})

    found = [("outside_key", outside_key), ("open_internet", open_internet)]
    if s["model"]:
        def call_model(ctx):
            model()
        found.append(("model", call_model))
    return found


def report(n: int, beats: dict, http: str = "runtime") -> bytes:
    """The probe's report of one beat: each path's time by the copy's clock, whether it worked, and its failure
    record's code and status; and whose client made its two calls to the observer, "customer" or "runtime" (KC2);
    nothing else."""
    body = {"n": n, "http": http,
            "beats": {p: {"at": round(b["at"], 3), "ok": bool(b["ok"]),
                          "error": None if b["ok"] else b.get("error"),
                          "status": None if b["ok"] else b.get("status")} for p, b in beats.items()}}
    return json.dumps(body, separators=(",", ":")).encode()


class Probe:
    """The probe's beats, in a thread of the copy's own process, which never keeps the process alive."""

    def __init__(self, s: dict, get, post, model=None, clock=time, http: str = "runtime"):
        self.s, self.get, self.post, self.model, self.clock, self.http = s, get, post, model, clock, http
        self.stopping, self.beats, self.over = threading.Event(), 0, False
        self.thread = threading.Thread(target=self.run, name="arvaken-stop-test-probe", daemon=True)

    def beat(self, n: int) -> int:
        """One beat: each path tried once, then the report; the observer's answer to the report."""
        found = core.beats(paths(self.s, self.get, self.model), record)
        try:
            return int(self.post(f"{self.s['observer']}/report",
                                 {"User-Agent": core.AGENT, "Authorization": "Bearer " + self.s["key"],
                                  "Content-Type": "application/json"}, report(n, found, self.http), core.TIMEOUT))
        except Exception:  # noqa: BLE001 - a report that could not be sent is a beat the observer never hears of
            return 0

    def run(self) -> None:
        n, due = 0, self.clock.time()
        while not self.stopping.is_set() and self.clock.time() < self.s["until"]:
            if self.beat(n) == OVER:
                self.over = True
                break
            n, due = n + 1, due + EVERY
            self.beats = n
            self.stopping.wait(max(0.0, due - self.clock.time()))

    def stop(self) -> None:
        self.stopping.set()


def start(doc, http=None, model=None) -> Probe:
    """The probe for a run on a host: its settings from the file the kit wrote (`doc`, its path or its JSON); `http`,
    your own GET where an SDK of yours wraps only its own clients (`http(url, headers, timeout)`, giving back the HTTP
    status), which must trust the run's certificate; `model`, a function that makes one call to your model provider with
    the key you made for the run, needed where the settings turn the model path on and never called otherwise. Its
    thread is started, and it is given back, so that `stop` can end it."""
    s = settings(doc)
    if s["model"] and not callable(model):
        raise NotTheKits("model")
    context = pinned(s["certificate"])
    probe = Probe(s, http or runtime_get(context), runtime_post(context), model if s["model"] else None,
                  http="customer" if http else "runtime")
    probe.thread.start()
    return probe
