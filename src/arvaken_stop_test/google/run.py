"""One run of the stop test on Google Cloud: deploy, warm up, fire and time, remove, tear down, and the signed result
(the design's sections 3 to 8; D532; D518, G2). As aws/run.py, with Google's own pieces.

Every call to Google goes through `Google` (api.py), which the command line makes from gcloud and the tests from a
fake. Every wait goes through `Clock`, so a test runs a fifteen-minute window in no time.

**The firing moment** is Cloud Audit Logs' record of the firing call (the deny policy made, or the account disabled),
read once the windows are over; its time is Google's, to the microsecond. Where it is not recorded by then, the moment
is the kit's own clock when the call returned, moved onto the test agent's clock by the difference measured during the
warm-up.

**What was made is checked gone by its own name:** the service, the bucket, both accounts and the run's deny policy.
"""
from __future__ import annotations

import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone

from arvaken_stop_test import __version__, result
from arvaken_stop_test.google import fire as firing
from arvaken_stop_test.google.api import Google, GoogleError
from arvaken_stop_test.google.stack import IAM, MEMORY_MB, RUN, RUNTIME, STORAGE, deploy, names, quoted
from arvaken_stop_test.timing import HOLD, PATH_WORDS, WINDOWS, Beat, PathResult, judge

GOOGLE_PATHS = ("own_calls", "another_identity", "outside_key", "open_internet")
WARM_UP = 10
RECOVERY = 300.0
DELETERS = 32                  # objects deleted at once at teardown: a five-repeat run leaves thousands in its bucket
TRANSIENT_TRIES = 4            # a check Google answers 429 or 5xx is made this many times in all before it is said
LOG_WAIT = 600.0               # seconds to wait, after the last window, for Cloud Audit Logs to record each firing
LOGGING = "https://logging.googleapis.com/v2/entries:list"
# Cloud Run's own refusals to reach the test agent: while it refuses, the agent makes no call on any path, so each path
# counts each refusal as refused, by its status. Anything else is not the stop, and ends the run.
REFUSED_STATUSES = (429, 500, 503)
REFUSED = "Cloud Run refused: "


@dataclass
class Clock:
    now: Callable[[], float] = time.time
    sleep: Callable[[float], None] = time.sleep


@dataclass
class Repeat:
    fired_before: float = 0.0
    fired_after: float = 0.0
    fired_at: float | None = None
    fired_precision: float = 0.0
    session_expires: float | None = None
    beats: dict[str, list[Beat]] = field(default_factory=lambda: {p: [] for p in GOOGLE_PATHS})


@dataclass
class Run:
    run: str
    stop_ref: str
    fired_by: str
    window: float
    project: str = ""
    region: str = ""
    permissions: list[str] = field(default_factory=list)      # a declared deny policy's, copied for the run
    began_at: float = 0.0
    ended_at: float = 0.0
    outputs: dict[str, str] = field(default_factory=dict)
    offset: float = 0.0
    calls: int = 0
    working: set[str] = field(default_factory=set)
    setup_errors: dict[str, dict[str, int]] = field(default_factory=dict)
    repeats: list[Repeat] = field(default_factory=list)
    left_behind: list[str] = field(default_factory=list)
    checked_gone: list[str] = field(default_factory=list)

    @property
    def stop_kind(self) -> str:
        return firing.kind_of(self.stop_ref)


def _invoke(g: Google, r: Run, payload: dict, clock: Clock) -> tuple[dict, float, float]:
    sent = clock.now()
    body = g.call("POST", r.outputs["Uri"].rstrip("/") + "/", payload, identity=True)
    return body, sent, clock.now()


ASSUME_WAIT = 300.0           # seconds a new grant may take to reach IAM Credentials: the second account's token


def assume(g: Google, r: Run, clock: Clock, wait: float = ASSUME_WAIT) -> dict:
    """The second account's token, taken by the agent. A grant made seconds ago may not yet be seen everywhere (Google
    says IAM changes take up to minutes), so a refusal is asked again until `wait` seconds have passed."""
    end = clock.now() + wait
    while True:
        try:
            body, _, _ = _invoke(g, r, {"action": "assume"}, clock)
            return body["session"]
        except GoogleError as e:
            if e.status != 500 or clock.now() >= end:
                raise
            clock.sleep(10.0)


def _seconds(text: str | None) -> float | None:
    if not text:
        return None
    return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()


def heartbeat(g: Google, r: Run, n: int, session: dict,
              clock: Clock) -> tuple[dict[str, Beat], float, float, float | None]:
    sent = clock.now()
    try:
        body, sent, received = _invoke(g, r, {"n": n, "session": session}, clock)
    except GoogleError as e:
        if e.status not in REFUSED_STATUSES:
            raise
        received = clock.now()
        at = (sent + received) / 2 + r.offset
        return {p: Beat(at, False, f"{REFUSED}HTTP{e.status}") for p in GOOGLE_PATHS}, sent, received, None
    beats = {p: Beat(float(b["at"]), bool(b["ok"]), b.get("error")) for p, b in (body.get("beats") or {}).items()}
    r.calls += len(beats)
    return beats, sent, received, float(body["at"])


def warm_up(g: Google, r: Run, session: dict, clock: Clock) -> None:
    best = None
    for i in range(WARM_UP):
        beats, sent, received, agent_at = heartbeat(g, r, -1 - i, session, clock)
        r.working |= {p for p, b in beats.items() if b.ok}
        for p, b in beats.items():
            if not b.ok:
                codes = r.setup_errors.setdefault(p, {})
                codes[b.error or "unknown"] = codes.get(b.error or "unknown", 0) + 1
        trip = received - sent
        if agent_at is not None and (best is None or trip < best[0]):
            best = (trip, agent_at - (sent + received) / 2)
        clock.sleep(1.0)
    r.offset = best[1] if best else 0.0


def time_one(g: Google, r: Run, clock: Clock, watch_own_trigger: bool, n0: int) -> Repeat:
    rep = Repeat()
    session = assume(g, r, clock)
    rep.session_expires = _seconds(session.get("expires"))
    n = n0
    if watch_own_trigger:
        seen = firing.watch(g, r.run, until=clock.now() + r.window, now=clock.now, sleep=clock.sleep)
        if seen is None:
            return rep
        rep.fired_before = rep.fired_after = seen
    else:
        rep.fired_before, rep.fired_after = firing.fire(g, r.run, r.stop_ref, r.permissions or None, now=clock.now)
    end = rep.fired_after + r.window + HOLD
    while clock.now() < end:
        beats, _, _, _ = heartbeat(g, r, n, session, clock)
        for p, b in beats.items():
            rep.beats.setdefault(p, []).append(b)
        n += 1
        clock.sleep(1.0)
    return rep


def recover(g: Google, r: Run, clock: Clock) -> None:
    """Between repeats: take the stop off, then wait until the agent's own calls work again."""
    firing.remove(g, r.run, r.stop_ref)
    end, good = clock.now() + RECOVERY, 0
    while clock.now() < end and good < 5:
        beats, _, _, _ = heartbeat(g, r, 0, {}, clock)
        good = good + 1 if beats.get("own_calls") and beats["own_calls"].ok else 0
        clock.sleep(1.0)


def _audit_filter(r: Run, rep: Repeat) -> str:
    """The firing call's record in Cloud Audit Logs, as Google writes it (read in Arvaken's sandbox, 24 October 2026):
    a deny policy's creation names the project's attachment point as its resource, and the policy by its ID in its
    request; an account's disabling names the account by its unique ID, never its email."""
    n = names(r.run, r.project)
    method = firing.METHODS[r.stop_kind]
    which = (f'protoPayload.resourceName="projects/-/serviceAccounts/{r.outputs.get("AgentAccountId", "")}"'
             if r.stop_kind == firing.DISABLE_KIND else f'protoPayload.request.policyId="{n["deny_policy"]}"')
    since = datetime.fromtimestamp(rep.fired_before - 5, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    until = datetime.fromtimestamp(rep.fired_after + 5, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    return (f'logName="projects/{r.project}/logs/cloudaudit.googleapis.com%2Factivity" '
            f'AND protoPayload.methodName="{method}" AND {which} '
            f'AND timestamp>="{since}" AND timestamp<="{until}"')


def firing_moments(g: Google, r: Run, clock: Clock, wait: float = LOG_WAIT) -> None:
    """Each repeat's firing moment: Cloud Audit Logs' record of its call, waited for up to `wait` seconds; else the
    kit's own clock, moved onto the agent's."""
    if r.fired_by != "the kit":
        for rep in r.repeats:
            if rep.fired_after:
                rep.fired_at = rep.fired_after + r.offset
        return
    pending = [rep for rep in r.repeats if rep.fired_after]
    end = clock.now() + wait
    while pending and clock.now() < end:
        for rep in list(pending):
            found = g.call("POST", LOGGING, {"resourceNames": [f"projects/{r.project}"], "filter": _audit_filter(r, rep),
                                             "orderBy": "timestamp asc", "pageSize": 5}).get("entries") or []
            if found:
                rep.fired_at, rep.fired_precision = _seconds(found[0]["timestamp"]), 0.001
                pending.remove(rep)
        if pending:
            clock.sleep(30.0)
    for rep in pending:
        rep.fired_at, rep.fired_precision = rep.fired_before + r.offset, rep.fired_after - rep.fired_before


def _quiet(call: Callable[[], object]) -> bool:
    """Whether the call was answered; a refusal is left to the check that follows (check_gone)."""
    try:
        call()
        return True
    except GoogleError:
        pass


def tear_down(g: Google, r: Run, clock: Clock) -> None:
    """Remove the stop the kit fired and everything it made; name anything left (D532, K4)."""
    n = names(r.run, r.project)
    _quiet(lambda: firing.remove(g, r.run, firing.DENY_ALL))      # the run's deny policy, whichever kind fired
    _quiet(lambda: g.call("DELETE", f"{RUN}/projects/{r.project}/locations/{r.region}/services/{n['service']}"))
    # The agent writes an object on every heartbeat, so a run leaves thousands: deleted many at once, page by page,
    # until a page has none or none of a page could be deleted (then the bucket stays, and check_gone names it)
    try:
        with ThreadPoolExecutor(max_workers=DELETERS) as pool:
            while True:
                items = g.call("GET", f"{STORAGE}/b/{n['bucket']}/o?fields=items(name),nextPageToken&maxResults=1000"
                               ).get("items") or []
                def delete(name: str) -> bool:
                    return _quiet(lambda: g.call("DELETE", f"{STORAGE}/b/{n['bucket']}/o/{quoted(name)}"))
                deleted = list(pool.map(delete, [i["name"] for i in items]))
                if not any(deleted):
                    break
    except GoogleError:
        pass
    _quiet(lambda: g.call("DELETE", f"{STORAGE}/b/{n['bucket']}"))
    for which in ("agent_account", "second_account"):
        _quiet(lambda w=which: g.call("DELETE", f"{IAM}/projects/-/serviceAccounts/{n[w]}"))
    r.left_behind, r.checked_gone = check_gone(g, r, clock)


def _transient(found: bool | str) -> bool:
    """A check Google could not answer just then (429, or 5xx), which is asked again before it is said."""
    return isinstance(found, str) and (found.startswith("429 ") or found[:1] == "5")


def _gone(call: Callable[[], object]) -> bool | str:
    try:
        call()
        return False
    except GoogleError as e:
        return True if e.status == 404 else f"{e.status} {e.code}"


def check_gone(g: Google, r: Run, clock: Clock, wait: float = 120.0) -> tuple[list[str], list[str]]:
    """Each thing the run made, checked gone by its own name. Cloud Run deletes a service as an operation, so the
    service is asked again for up to `wait` seconds before it is named as left."""
    n = names(r.run, r.project)
    attachment = quoted(f"cloudresourcemanager.googleapis.com/projects/{r.project}")
    def listed(email: str) -> Callable[[], object]:
        """An account, asked for in the project's list of accounts: Google answers 403, not 404, for an account that
        is gone (\"or it may not exist\"), so a missing account is read from the list, never from that answer."""
        def find() -> object:
            token, emails = None, set()
            while True:
                page = g.call("GET", f"{IAM}/projects/{r.project}/serviceAccounts?pageSize=100"
                              + (f"&pageToken={quoted(token)}" if token else ""))
                emails |= {a.get("email") for a in page.get("accounts") or []}
                token = page.get("nextPageToken")
                if not token:
                    break
            if email not in emails:
                raise GoogleError(404, "NOT_IN_THE_LIST")
            return email
        return find

    things = [
        (f"the service {n['service']}", lambda: g.call("GET", f"{RUN}/projects/{r.project}/locations/{r.region}/services/{n['service']}")),
        (f"the bucket {n['bucket']}", lambda: g.call("GET", f"{STORAGE}/b/{n['bucket']}")),
        (f"the account {n['agent_account']}", listed(n["agent_account"])),
        (f"the account {n['second_account']}", listed(n["second_account"])),
        (f"the deny policy {n['deny_policy']}",
         lambda: g.call("GET", f"https://iam.googleapis.com/v2/policies/{attachment}/denypolicies/{n['deny_policy']}")),
    ]
    left, gone = [], []
    for what, call in things:
        found, end = _gone(call), clock.now() + (wait if what.startswith(("the service", "the account")) else 0)
        tries = 1
        while (found is False and clock.now() < end) or (_transient(found) and tries < TRANSIENT_TRIES):
            clock.sleep(10.0)
            found, tries = _gone(call), tries + 1
        if found is True:
            gone.append(what)
        else:
            left.append(what if found is False else f"{what} (could not be checked: {found})")
    return left, gone


def _one(r: Run, rep: Repeat, p: str) -> PathResult:
    found = judge(rep.beats.get(p, []), rep.fired_at, window=r.window, tried=p in r.working,
                  setup_errors=r.setup_errors.get(p), fired_precision=rep.fired_precision)
    keeps = rep.session_expires if p == "another_identity" and found.outcome == "not stopped" else None
    source = ("Cloud Audit Logs' record of the call" if rep.fired_precision == 0.001 else
              f"the kit's own clock, moved onto the agent's; the call took {rep.fired_precision:.3f} seconds")
    return replace(found, fired_source=source if rep.fired_at is not None else None, keeps_working_until=keeps,
                   fired_at=rep.fired_at)


def results(r: Run) -> list[tuple[float | None, dict[str, PathResult]]]:
    return [(rep.fired_at, {p: _one(r, rep, p) for p in GOOGLE_PATHS}) for rep in r.repeats]


def _iso(t: float | None) -> str | None:
    return None if t is None else datetime.fromtimestamp(t, tz=timezone.utc).isoformat(
        timespec="milliseconds").replace("+00:00", "Z")


def details(r: Run, doc: dict) -> dict:
    """What the page shows, beside the result: each path's time to effect as a range, with what the teardown checked."""
    repeats = []
    for rep, (_, found) in zip(r.repeats, results(r)):
        repeats.append({p: {
            "outcome": f.outcome, "fired_at": _iso(rep.fired_at), "fired_source": f.fired_source,
            "effect_between_seconds": list(f.effect_between) if f.effect_between else None,
            "successes_after_first_refusal": f.successes_after_first_refusal,
            "first_refused": _iso(f.first_failure_after), "stopped_from": _iso(f.stopped_at),
            "last_success": _iso(f.last_success_after), "tries_after": f.tries_after, "failures_after": f.failures_after,
            "errors": f.errors, "reason": f.reason, "keeps_working_until": _iso(f.keeps_working_until)}
            for p, f in found.items()})
    return {"format": "stop-test-details/1", "run": r.run, "result_signature": doc["signature"],
            "stop_kind": r.stop_kind, "window_seconds": r.window, "left_behind": r.left_behind,
            "checked_gone": r.checked_gone, "repeats": repeats}


def the_result(r: Run, key=None) -> dict:
    doc = result.build(
        kit_version=__version__, cloud="google_cloud", region=r.region,
        began_at=r.began_at, ended_at=r.ended_at, window=r.window, clock_gap_ms=int(round(abs(r.offset) * 1000)),
        calls=r.calls, left_behind=r.left_behind, stop_kind=r.stop_kind, fired_by=r.fired_by, stop_ref=r.stop_ref,
        agent={"kind": "google-cloud-run-service", "runtime": RUNTIME, "memory_mb": MEMORY_MB, "private_network": False,
               "ref": r.outputs.get("Agent", ""), "role_ref": r.outputs.get("AgentAccount", "")},
        repeats=results(r))
    return result.sign(doc, key or result.new_key())


def run(g: Google, stop_ref: str, *, endpoint: str, fired_by: str = "the kit", window: float = WINDOWS["google_cloud"],
        repeats: int = 1, clock: Clock | None = None, run_name: str | None = None, log_wait: float = LOG_WAIT,
        say: Callable[[str], None] = lambda _: None) -> tuple[Run, dict]:
    """A whole run, torn down whatever happens. Returns the run's record and its signed result."""
    from arvaken_stop_test.google.stack import new_run
    clock = clock or Clock()
    if fired_by not in result.FIRED_BY:
        raise ValueError(f"the stop is fired by one of {result.FIRED_BY}")
    permissions: list[str] = []
    if fired_by == "the kit":
        reason = firing.why_not(stop_ref)
        if reason:
            raise firing.Refused(reason)
        if stop_ref not in (firing.DENY_ALL, firing.DISABLE):
            permissions = firing.denied_permissions(g, stop_ref)       # before anything is made
            if not firing.covers(permissions):
                raise firing.Refused(firing.NOT_COVERED)
    if not 1 <= repeats <= 5:
        raise ValueError("a run repeats one to five times")
    if fired_by == "your own trigger" and repeats != 1:
        raise ValueError("with your own trigger a run fires once: only you can take your own stop off between repeats")
    r = Run(run=run_name or new_run(), stop_ref=stop_ref, fired_by=fired_by, window=window, project=g.project,
            region=g.region, permissions=permissions)
    r.began_at = clock.now()
    try:
        r.outputs = deploy(g, r.run, endpoint, sleep=clock.sleep)
        warm_up(g, r, assume(g, r, clock), clock)
        for p in GOOGLE_PATHS:
            if p not in r.working:
                codes = ", ".join(f"{code} {k}" for code, k in sorted(r.setup_errors.get(p, {}).items()))
                say(f"Before the stop, {PATH_WORDS[p]} did not work ({codes or 'no answer'}): it will be reported as "
                    "not run.")
        n = 0
        for i in range(repeats):
            if i:
                recover(g, r, clock)
            rep = time_one(g, r, clock, fired_by == "your own trigger", n)
            r.repeats.append(rep)
            n += sum(len(b) for b in rep.beats.values())
        firing_moments(g, r, clock, wait=log_wait)
    finally:
        tear_down(g, r, clock)
        r.ended_at = clock.now()
    return r, the_result(r)
