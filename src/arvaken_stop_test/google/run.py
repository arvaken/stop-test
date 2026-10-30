"""One run of the stop test on Google Cloud: deploy, warm up, fire and time, remove, tear down, and the signed result
(the design's sections 3 to 8; D532; D518, G2). As aws/run.py, with Google's own pieces.

Every call to Google goes through `Google` (api.py), which the command line makes from gcloud and the tests from a
fake. Every wait goes through `Clock`, so a test runs a fifteen-minute window in no time.

**The firing moment** is Cloud Audit Logs' record of the firing call (the deny policy made, or the account disabled),
read once the windows are over; its time is Google's, to the microsecond. Where it is not recorded by then, the moment
is the kit's own clock when the call returned, moved onto the test agent's clock by the difference measured during the
warm-up.

**What was made is checked gone by its own name:** the service, the bucket, both accounts and the run's deny policy.

**What counts as the stop's refusal** is refusals.py's, by the kind of stop: for your own trigger, the kind Cloud Audit
Logs' record of your action shows (`identify`), or none, and then nothing counts. Cloud Run refusing to reach the agent
(429, 500, 503) is recorded on every path and never counted: a throttle or a server error is not the stop's refusal (the
founder, 29 October 2026). Each path is judged from its heartbeats before the firing moment as well as after it.
"""
from __future__ import annotations

import http.client
import json
import time
import urllib.error
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone

from arvaken_stop_test import __version__, refusals, result
from arvaken_stop_test.google import fire as firing
from arvaken_stop_test.google.api import Google, GoogleError
from arvaken_stop_test.google.stack import IAM, MEMORY_MB, RUN, RUNTIME, STORAGE, deploy, names, quoted
from arvaken_stop_test.timing import HOLD, NOT_MEASURED, PATH_WORDS, WINDOWS, Beat, PathResult, judge

GOOGLE_PATHS = ("own_calls", "another_identity", "outside_key", "open_internet")
WARM_UP = 10
RECOVERY = 300.0
DELETERS = 32                  # objects deleted at once at teardown: a five-repeat run leaves thousands in its bucket
DELETE_TRIES = 3               # an object's deletion that got no answer is asked this many times in all
LIST_TRIES = 3                 # and a page of the bucket's objects, asked for at teardown, that got no answer
TRANSIENT_TRIES = 4            # a check Google answers 429 or 5xx is made this many times in all before it is said
LOG_WAIT = 600.0               # seconds to wait, after the last window, for Cloud Audit Logs to record each firing
LOGGING = "https://logging.googleapis.com/v2/entries:list"
# Cloud Run's own refusals to reach the test agent: while it refuses, the agent makes no call on any path, so each path
# records each refusal, by its status, as not counted. Anything else is not the stop, and ends the run.
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
    watched_from: float = 0.0           # your own trigger: the kit's clock when it began to watch for it
    seen: list[tuple[str, str]] = field(default_factory=list)   # and what it saw: the account disabled, or a policy
    # each path's heartbeats: those since the stop before it was taken off (or the warm-up's), then the repeat's own
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
    lost: list[tuple[float, str]] = field(default_factory=list)     # heartbeats with no answer: sent, by the kit's clock
    working: set[str] = field(default_factory=set)
    setup_errors: dict[str, dict[str, int]] = field(default_factory=dict)
    repeats: list[Repeat] = field(default_factory=list)
    left_behind: list[str] = field(default_factory=list)
    checked_gone: list[str] = field(default_factory=list)
    warm_beats: dict[str, list[Beat]] = field(default_factory=dict)     # the warm-up's heartbeats
    # your own trigger: the kind of stop Cloud Audit Logs' record of your action shows, or None, and that record
    trigger_kind: str | None = None
    trigger_record: dict[str, str] | None = None

    @property
    def stop_kind(self) -> str:
        if self.fired_by == "your own trigger" and self.trigger_kind:
            return self.trigger_kind
        return firing.kind_of(self.stop_ref)

    @property
    def counted_kind(self) -> str | None:
        """The kind of stop whose refusals count: the kit's own; for your own trigger, the one identified, or None."""
        return self.trigger_kind if self.fired_by == "your own trigger" else firing.kind_of(self.stop_ref)


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


def unreached(e: Exception) -> str:
    """The name of what failed, for a call that got no answer: what urllib's URLError wraps, as the TLS handshake that
    timed out in run r37f2ed13, or else the error's own, as the socket's or http.client's while reading the answer."""
    if isinstance(e, urllib.error.URLError) and isinstance(e.reason, BaseException):
        return type(e.reason).__name__
    return type(e).__name__


def heartbeat(g: Google, r: Run, n: int, session: dict,
              clock: Clock) -> tuple[dict[str, Beat], float, float, float | None]:
    """One heartbeat, as aws/run.py's. Where the call got no answer, the network having failed or timed out on the way
    to the test agent or back (unreached), nothing of the agent's was seen: no path has a beat, the heartbeat is kept as
    lost, by its code, for the details, and the run goes on (the founder's answer of 30 October 2026, after run
    r37f2ed13 ended on one). Google's own answer, a refusal among them, is a GoogleError."""
    sent = clock.now()
    try:
        body, sent, received = _invoke(g, r, {"n": n, "session": session}, clock)
    except GoogleError as e:
        if e.status not in REFUSED_STATUSES:
            raise
        received = clock.now()
        at = (sent + received) / 2 + r.offset
        return {p: Beat(at, False, f"{REFUSED}HTTP{e.status}", status=e.status) for p in GOOGLE_PATHS}, sent, received, None
    except (urllib.error.URLError, http.client.HTTPException, OSError) as e:
        r.lost.append((sent, unreached(e)))
        return {}, sent, clock.now(), None
    beats = {p: Beat(float(b["at"]), bool(b["ok"]), b.get("error"), status=b.get("status"), reason=b.get("reason"),
                     provider_status=b.get("provider_status"), step=b.get("step"), token_issued=b.get("token_issued"),
                     token_expires=b.get("token_expires"))
             for p, b in (body.get("beats") or {}).items()}
    r.calls += len(beats)
    return beats, sent, received, float(body["at"])


def warm_up(g: Google, r: Run, session: dict, clock: Clock) -> None:
    best = None
    for i in range(WARM_UP):
        beats, sent, received, agent_at = heartbeat(g, r, -1 - i, session, clock)
        for p, b in beats.items():
            r.warm_beats.setdefault(p, []).append(b)
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


def time_one(g: Google, r: Run, clock: Clock, watch_own_trigger: bool, n0: int,
             before: dict[str, list[Beat]] | None = None) -> Repeat:
    """One repeat, as aws/run.py's: `before` is each path's heartbeats before the firing."""
    rep = Repeat()
    for p, beats in (before or {}).items():
        rep.beats.setdefault(p, []).extend(beats)
    session = assume(g, r, clock)
    rep.session_expires = _seconds(session.get("expires"))
    n = n0
    if watch_own_trigger:
        rep.watched_from = clock.now()
        seen = firing.watch(g, r.run, until=clock.now() + r.window, now=clock.now, sleep=clock.sleep, found=rep.seen)
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


def recover(g: Google, r: Run, clock: Clock) -> dict[str, list[Beat]]:
    """Between repeats: take the stop off, then wait until the agent's own calls work again. Returns each path's
    heartbeats meanwhile, which come before the next repeat's firing."""
    firing.remove(g, r.run, r.stop_ref)
    end, good, seen = clock.now() + RECOVERY, 0, {}
    while clock.now() < end and good < 5:
        beats, _, _, _ = heartbeat(g, r, 0, {}, clock)
        for p, b in beats.items():
            seen.setdefault(p, []).append(b)
        good = good + 1 if beats.get("own_calls") and beats["own_calls"].ok else 0
        clock.sleep(1.0)
    return seen


def _audit_filter(r: Run, rep: Repeat) -> str:
    """The firing call's record in Cloud Audit Logs, as Arvaken read it in its sandbox (24 October 2026):
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
        identify(g, r, clock, wait)
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


# CUSTOMER TEXT: approved by the founder, word for word, 30 October 2026
NOT_IDENTIFIED = ("Cloud Audit Logs hold no record of your trigger as a kind of stop the kit counts, so nothing counts "
                  "as stopped")
# The calls whose record shows your own trigger's kind (the founder's refusal ruling of 29 October 2026, item 5): the
# test agent's account disabled, or a deny policy made or changed that the kit saw naming it.
DENY_METHODS = ("google.iam.v2.Policies.CreatePolicy", "google.iam.v2.Policies.UpdatePolicy")


def identify(g: Google, r: Run, clock: Clock, wait: float = LOG_WAIT) -> None:
    """Your own trigger's kind of stop: the last record in Cloud Audit Logs, from when the kit began to watch to just
    after it saw the change, of the test agent's account disabled, or of the deny policy the kit saw naming it made or
    changed, where the call was not refused. Waited for up to `wait` seconds. Where there is none, the kind is None and
    nothing counts as stopped."""
    rep = next((x for x in r.repeats if x.fired_after), None)
    if rep is None:
        return
    since = datetime.fromtimestamp(rep.watched_from + r.offset - 5, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    until = datetime.fromtimestamp(rep.fired_after + r.offset + 5, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    account = r.outputs.get("AgentAccountId", "")
    policies = [name.rsplit("/", 1)[-1] for what, name in rep.seen if what == "deny policy"]
    methods = " OR ".join(f'"{m}"' for m in (firing.METHODS[firing.DISABLE_KIND], *DENY_METHODS))
    query = (f'logName="projects/{r.project}/logs/cloudaudit.googleapis.com%2Factivity" '
             f'AND protoPayload.methodName=({methods}) AND timestamp>="{since}" AND timestamp<="{until}"')
    end = clock.now() + wait
    while True:
        entries = g.call("POST", LOGGING, {"resourceNames": [f"projects/{r.project}"], "filter": query,
                                           "orderBy": "timestamp asc", "pageSize": 100}).get("entries") or []
        found = []
        for e in entries:
            payload = e.get("protoPayload") or {}
            if (payload.get("status") or {}).get("code"):
                continue                                    # a refused call changed nothing
            if payload.get("methodName") == firing.METHODS[firing.DISABLE_KIND]:
                if account and payload.get("resourceName") == f"projects/-/serviceAccounts/{account}":
                    found.append((e, firing.DISABLE_KIND))
            elif any(pid in json.dumps(payload) for pid in policies):
                found.append((e, firing.DENY_KIND))
        if found or clock.now() >= end:
            break
        clock.sleep(30.0)
    if found:
        e, kind = found[-1]
        r.trigger_kind = kind
        r.trigger_record = {"source": "Cloud Audit Logs", "insert_id": e.get("insertId", ""),
                            "method": (e.get("protoPayload") or {}).get("methodName", ""), "timestamp": e.get("timestamp", "")}


def _quiet(call: Callable[[], object]) -> bool:
    """Whether the call was answered. Anything else, a refusal or no answer at all, is left to the check that follows
    (check_gone): no step of the teardown ends the run, as none of aws/run.py's does (the founder's answer of 30
    October 2026, after run r5a229643's result was lost to a TLS handshake that timed out in its teardown)."""
    try:
        call()
        return True
    except Exception:  # noqa: BLE001 - each thing is checked gone below, and named where it is still there
        return False


def _deleted(g: Google, url: str) -> bool:
    """An object's deletion, asked again where it got no answer, up to DELETE_TRIES in all: whether it was done. A 404
    to a later try is an earlier try's deletion done, its answer lost."""
    for tries in range(1, DELETE_TRIES + 1):
        try:
            g.call("DELETE", url)
            return True
        except GoogleError as e:
            return tries > 1 and e.status == 404
        except Exception:  # noqa: BLE001 - no answer: asked again
            continue
    return False


def _listed(g: Google, url: str) -> list[dict]:
    """A page of the bucket's objects, asked for again where it got no answer, up to LIST_TRIES in all. Google's own
    refusal, and no answer to the last try, are raised: the teardown then empties no more, and names the bucket."""
    for tries in range(1, LIST_TRIES + 1):
        try:
            return g.call("GET", url).get("items") or []
        except GoogleError:
            raise
        except Exception:  # noqa: BLE001 - no answer: asked again
            if tries == LIST_TRIES:
                raise
    return []


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
                items = _listed(g, f"{STORAGE}/b/{n['bucket']}/o?fields=items(name),nextPageToken&maxResults=1000")
                def delete(name: str) -> bool:
                    return _deleted(g, f"{STORAGE}/b/{n['bucket']}/o/{quoted(name)}")
                deleted = list(pool.map(delete, [i["name"] for i in items]))
                if not any(deleted):
                    break
    except Exception:  # noqa: BLE001 - what cannot be emptied is named below as left
        pass
    _quiet(lambda: g.call("DELETE", f"{STORAGE}/b/{n['bucket']}"))
    for which in ("agent_account", "second_account"):
        _quiet(lambda w=which: g.call("DELETE", f"{IAM}/projects/-/serviceAccounts/{n[w]}"))
    r.left_behind, r.checked_gone = check_gone(g, r, clock)


class _Unanswered(str):
    """A check that got no answer, or failed otherwise than by Google's answer, by what failed (unreached)."""


def _transient(found: bool | str) -> bool:
    """A check Google could not answer just then (429, or 5xx), or that got no answer at all, which is asked again
    before it is said."""
    return isinstance(found, _Unanswered) or (isinstance(found, str) and (found.startswith("429 ") or found[:1] == "5"))


def _gone(call: Callable[[], object]) -> bool | str:
    try:
        call()
        return False
    except GoogleError as e:
        return True if e.status == 404 else f"{e.status} {e.code}"
    except Exception as e:  # noqa: BLE001 - asked again, then named as could not be checked
        return _Unanswered(unreached(e))


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
    kind = r.counted_kind
    found = judge(rep.beats.get(p, []), rep.fired_at, window=r.window, tried=p in r.working,
                  setup_errors=r.setup_errors.get(p), fired_precision=rep.fired_precision,
                  counts=lambda b, before: refusals.counts(kind, p, b, before))
    if kind is None and found.outcome == NOT_MEASURED:
        found = replace(found, reason=NOT_IDENTIFIED)
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
            "errors": f.errors, "not_counted": f.not_counted, "reason": f.reason,
            "keeps_working_until": _iso(f.keeps_working_until), "failures": result.failure_records(f)}
            for p, f in found.items()})
    return {"format": "stop-test-details/1", "run": r.run, "result_signature": doc["signature"],
            "stop_kind": r.stop_kind, "window_seconds": r.window, "left_behind": r.left_behind,
            "checked_gone": r.checked_gone, "repeats": repeats,
            "heartbeats_lost": result.heartbeats_lost([(at + r.offset, code) for at, code in r.lost]),
            "trigger": {"kind": r.trigger_kind, "record": r.trigger_record} if r.fired_by == "your own trigger" else None}


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
        n, before = 0, r.warm_beats
        for i in range(repeats):
            if i:
                before = recover(g, r, clock)
            rep = time_one(g, r, clock, fired_by == "your own trigger", n, before)
            r.repeats.append(rep)
            n += sum(len(b) for b in rep.beats.values())
        firing_moments(g, r, clock, wait=log_wait)
    finally:
        tear_down(g, r, clock)
        r.ended_at = clock.now()
    return r, the_result(r)
