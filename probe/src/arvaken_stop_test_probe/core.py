"""The probe's core: the kit's heartbeat, whatever the copy runs on (D575). It knows no cloud: each cloud's own paths,
settings, clients and error records are its own module (aws.py), so a host the kit does not deploy to can bring its own
set beside them.

A heartbeat is a list of paths, each tried once, in order. For each, the reply says when (by the copy's clock), whether
it succeeded, and if not its failure record (D646): the error's code, its HTTP status, and the provider's own reason
field where the error has one. Never a message: it can name resources and principals. Two paths are the same wherever
the copy runs, and are here: Arvaken's test endpoint, called with the run's key (outside_key) and with none
(open_internet). The endpoint is fixed (ENDPOINT) and never taken from the invocation.

The kit's marker names its run (is_mine). A marked invocation whose settings do not name the run is refused
(NotTheKits) before any call is made.
"""
from __future__ import annotations

import re
import sys
import time
import urllib.error
import urllib.request

MARKER = "arvaken_stop_test"
ENDPOINT = "https://stop-test.arvaken.com"   # Arvaken's test endpoint (the kit's cli.ENDPOINT), never the invocation's
AGENT = "arvaken-stop-test-probe (+https://github.com/arvaken/stop-test)"
TIMEOUT = 2.0
RUN = re.compile(r"r[0-9a-f]{8}")            # a run's name, as the kit's stack.new_run makes one
KEY = re.compile(r"[0-9a-f]{32}")            # the run's key, as the kit makes it and the endpoint takes it


class NotTheKits(ValueError):
    """A marked invocation whose settings do not name the run: refused before any call is made. Its argument names the
    first setting that did not."""


def is_mine(event) -> bool:
    """Whether this invocation is the kit's: it carries the kit's marker, naming a run."""
    m = event.get(MARKER) if isinstance(event, dict) else None
    return isinstance(m, dict) and isinstance(m.get("run"), str) and RUN.fullmatch(m["run"]) is not None


def marker(event) -> dict:
    """The kit's marker, its run's key and count checked; else NotTheKits."""
    if not is_mine(event):
        raise NotTheKits("run")
    m = event[MARKER]
    if not (isinstance(m.get("key"), str) and KEY.fullmatch(m["key"])):
        raise NotTheKits("key")
    n = m.get("n", 0)
    if not isinstance(n, int) or isinstance(n, bool) or n < 0:
        raise NotTheKits("n")
    return m


def code(e) -> str:
    """An error's code alone, where its cloud's module has not named it."""
    if isinstance(e, urllib.error.HTTPError):
        return f"HTTP{e.code}"
    if isinstance(e, (TimeoutError, urllib.error.URLError)):
        return "Unreachable"
    return type(e).__name__[:64]


def record(e) -> dict:
    """An error's failure record, where its cloud's module has not named it: its code, and an HTTP error's status."""
    return {"error": code(e), "status": e.code if isinstance(e, urllib.error.HTTPError) else None, "reason": None}


def attempt(fn, record=record) -> dict:
    at, ctx = time.time(), {}
    try:
        fn(ctx)
        return {"at": at, "ok": True, **ctx}
    except Exception as e:  # noqa: BLE001 - every failure is a heartbeat's result, by its record
        return {"at": at, "ok": False, **record(e), **ctx}


def beats(paths, record=record) -> dict:
    """Each path tried once, in order: (name, fn) pairs, each fn given a dict for what it adds to its own beat."""
    return {name: attempt(fn, record) for name, fn in paths}


def runtime_get(url, headers, timeout):
    """The runtime's own GET: the standard library's. Its HTTP status; urllib raises for one of 400 or more."""
    request = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        response.read(64)
        return response.status


def _get(get, url, headers):
    status = get(url, {"User-Agent": AGENT, **headers}, TIMEOUT)
    if isinstance(status, int) and status >= 400:
        raise urllib.error.HTTPError(url, status, "", None, None)


def endpoint_paths(m, get) -> list:
    """outside_key and open_internet: Arvaken's test endpoint, with the run's key and with none, by `get`."""
    def outside_key(ctx):
        _get(get, f"{ENDPOINT}/key", {"Authorization": "Bearer " + m["key"]})

    def open_internet(ctx):
        _get(get, f"{ENDPOINT}/open", {})

    return [("outside_key", outside_key), ("open_internet", open_internet)]


def versions(*libraries) -> list:
    """The Python and each library's version the probe ran on, so a failure's record holds what read it; None for a
    library the copy does not have."""
    found = [sys.version.split()[0]]
    for name in libraries:
        try:
            found.append(__import__(name).__version__)
        except ImportError:
            found.append(None)
    return found
