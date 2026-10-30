"""One run of the stop test on AWS: deploy, warm up, fire and time, remove, tear down, and the signed result (the
design's sections 3 to 8; D532).

Every call to AWS goes through `Clients`, which the command line makes from the customer's own credentials and the
tests make from fakes. Every wait goes through `Clock`, so a test runs a fifteen-minute window in no time.

**The firing moment** is CloudTrail's record of the attach call, as the design says (section 6), read once the windows
are over. Where CloudTrail has not recorded it by then, the moment is the kit's own clock when the call returned,
moved onto the test agent's clock by the difference measured during the warm-up.

**What was made is checked gone by its own identifier** (the founder, 23 October 2026): the stack, the function, both
roles, the bucket, the function's log group (which Lambda makes where a function may write logs; the test agent may
not, so none is expected), and the stop the kit fired. The run's tag is asked as well, to catch anything else.

**What counts as the stop's refusal** is refusals.py's, by the kind of stop: for your own trigger, the kind CloudTrail's
record of your action shows (`identify`), or none, where the kit finds no such record, and then nothing counts. Each path
is judged from its heartbeats before the firing moment as well as after it: a refusal counts only on a path that
succeeded before it, and Lambda's KMSAccessDeniedException only where the agent ran before the stop and it first came
after.
"""
from __future__ import annotations

import json
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any

from arvaken_stop_test import __version__, refusals, result
from arvaken_stop_test.aws import fire as firing
from arvaken_stop_test.aws.stack import MEMORY_MB, RUNTIME, TAG, names, template_body
from arvaken_stop_test.timing import HOLD, NOT_MEASURED, PATH_WORDS, WINDOWS, Beat, PathResult, judge

AWS_PATHS = ("own_calls", "another_identity", "outside_key", "open_internet")
WARM_UP = 10                 # heartbeats before the first firing
RECOVERY = 300.0             # seconds to wait, between repeats, for the agent's own calls to work again
TRAIL_WAIT = 900.0           # seconds to wait, after the last window, for CloudTrail to record each firing


@dataclass
class Clock:
    now: Callable[[], float] = time.time
    sleep: Callable[[float], None] = time.sleep


@dataclass
class Clients:
    cloudformation: Any
    iam: Any
    lambda_: Any
    s3: Any
    cloudtrail: Any
    tagging: Any
    region: str
    logs: Any = None
    sts: Any = None


@dataclass
class Repeat:
    fired_before: float = 0.0           # the kit's clock just before the attach call
    fired_after: float = 0.0            # and just after it returned
    fired_at: float | None = None       # on the test agent's clock: CloudTrail's, or the kit's moved onto it
    fired_precision: float = 0.0        # how far after fired_at the call may have been: 1 second for CloudTrail's
    # revoking sessions fires on the role the agent became too: when, for the path that runs under it
    second_fired_before: float = 0.0
    second_fired_after: float = 0.0
    second_fired_at: float | None = None
    second_fired_precision: float = 0.0
    session_expires: float | None = None    # the session the agent took for the second role: when it expires
    watched_from: float = 0.0           # your own trigger: the kit's clock when it began to watch for it
    # each path's heartbeats: those since the stop before it was taken off (or the warm-up's), then the repeat's own
    beats: dict[str, list[Beat]] = field(default_factory=lambda: {p: [] for p in AWS_PATHS})


@dataclass
class Run:
    run: str
    stop_ref: str
    fired_by: str
    window: float
    region: str = ""
    began_at: float = 0.0
    ended_at: float = 0.0
    outputs: dict[str, str] = field(default_factory=dict)
    offset: float = 0.0                 # the test agent's clock minus the kit's, from the warm-up
    calls: int = 0
    working: set[str] = field(default_factory=set)      # the paths that worked in the warm-up
    setup_errors: dict[str, dict[str, int]] = field(default_factory=dict)   # and the errors of those that did not
    repeats: list[Repeat] = field(default_factory=list)
    left_behind: list[str] = field(default_factory=list)
    checked_gone: list[str] = field(default_factory=list)       # each identifier the teardown found gone
    warm_beats: dict[str, list[Beat]] = field(default_factory=dict)     # the warm-up's heartbeats
    # your own trigger: the kind of stop CloudTrail's record of your action shows, or None, and that record
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


def _wait_for_stack(cf: Any, stack: str, clock: Clock, want: str, limit: float = 900.0) -> dict | None:
    end = clock.now() + limit
    while clock.now() < end:
        try:
            found = cf.describe_stacks(StackName=stack)["Stacks"][0]
        except Exception:  # noqa: BLE001 - a deleted stack is no longer described
            return None if want == "DELETE_COMPLETE" else {}
        status = found["StackStatus"]
        if status == want:
            return found
        if status.endswith("_FAILED") or status in ("ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_COMPLETE"):
            raise RuntimeError(f"the stack {stack} ended as {status}")
        clock.sleep(5.0)
    raise TimeoutError(f"the stack {stack} did not reach {want} in {int(limit)} seconds")


def deploy(c: Clients, r: Run, endpoint: str, clock: Clock) -> None:
    n = names(r.run)
    c.cloudformation.create_stack(StackName=n["stack"], TemplateBody=template_body(r.run, endpoint),
                                  Capabilities=["CAPABILITY_NAMED_IAM"], Tags=[{"Key": TAG, "Value": r.run}])
    found = _wait_for_stack(c.cloudformation, n["stack"], clock, "CREATE_COMPLETE")
    r.outputs = {o["OutputKey"]: o["OutputValue"] for o in (found or {}).get("Outputs", [])}


def outputs_of(c: Clients, run: str) -> dict[str, str]:
    """An interrupted run's stack outputs, for cleaning it up; none if its stack is gone."""
    try:
        found = c.cloudformation.describe_stacks(StackName=names(run)["stack"])["Stacks"][0]
    except Exception:  # noqa: BLE001 - a deleted stack is no longer described
        return {}
    return {o["OutputKey"]: o["OutputValue"] for o in found.get("Outputs", [])}


# Lambda's own refusals to run the test agent. While Lambda refuses, the agent makes no call on any path, so each path
# counts each refusal as refused, by Lambda's code: the stop has stopped the agent itself. Arvaken's inline measurement
# found the first (23 October 2026): with a deny-all policy written on the agent's role, once Lambda needed a new
# environment for the agent, it refused the invocation, as it decrypts the agent's environment as that role. A function
# your own trigger deleted, or set to no concurrency, is refused the same way. Anything else from Invoke (the kit's own
# credentials expiring, say) is not the stop, and ends the run as before: it must never read as a path stopped.
# Of these, only KMSAccessDeniedException counts as the stop's refusal (refusals.py; the founder, 29 and 30 October 2026):
# the others are recorded on every path, not counted.
LAMBDA_REFUSED = ("KMSAccessDeniedException", "KMSDisabledException", "KMSInvalidStateException",
                  "KMSNotFoundException", "ResourceNotFoundException")
NO_CONCURRENCY = "ReservedFunctionConcurrentInvocationLimitExceeded"
REFUSED = refusals.LAMBDA_REFUSED     # the prefix of such a beat's error, so the page can say what it was


def refused_by_lambda(e: Exception) -> str | None:
    """Lambda's code, where an Invoke error is Lambda refusing to run the agent; else None."""
    response = getattr(e, "response", None) or {}
    code = response.get("Error", {}).get("Code")
    if code in LAMBDA_REFUSED or (code == "TooManyRequestsException" and response.get("Reason") == NO_CONCURRENCY):
        return code
    return None


def _invoke(c: Clients, r: Run, payload: dict, clock: Clock) -> tuple[dict, float, float]:
    sent = clock.now()
    response = c.lambda_.invoke(FunctionName=names(r.run)["function"], Payload=json.dumps(payload).encode())
    body = json.loads(response["Payload"].read())
    return body, sent, clock.now()


def assume(c: Clients, r: Run, clock: Clock) -> dict:
    """The second role's session, taken by the agent, and when it took it, by its clock: AssumeRole gives a session's
    expiry, not its issue time."""
    body, _, _ = _invoke(c, r, {"action": "assume"}, clock)
    return {**body["session"], "issued": float(body["at"])}


def heartbeat(c: Clients, r: Run, n: int, session: dict,
              clock: Clock) -> tuple[dict[str, Beat], float, float, float | None]:
    """One heartbeat: each path's result, the kit's clock when it was asked and answered, and the agent's own clock.
    Where Lambda refused to run the agent, each path's beat is that refusal, at the kit's clock moved onto the agent's,
    and the agent's own clock is None: it did not run."""
    sent = clock.now()
    try:
        body, sent, received = _invoke(c, r, {"n": n, "session": session}, clock)
    except Exception as e:
        code = refused_by_lambda(e)
        if code is None:
            raise
        received = clock.now()
        at = (sent + received) / 2 + r.offset
        response = getattr(e, "response", None) or {}
        status = response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return {p: Beat(at, False, REFUSED + code, status=status, reason=response.get("Reason"))
                for p in AWS_PATHS}, sent, received, None
    beats = {p: _beat(p, b, session) for p, b in (body.get("beats") or {}).items()}
    r.calls += len(beats)
    return beats, sent, received, float(body["at"])


def _beat(path: str, b: dict, session: dict) -> Beat:
    """A path's heartbeat from the agent's reply, with its failure record; under another identity, with the times of
    the session it used."""
    timed = path == "another_identity" and bool(session)
    return Beat(float(b["at"]), bool(b["ok"]), b.get("error"), status=b.get("status"), reason=b.get("reason"),
                token_issued=session.get("issued") if timed else None,
                token_expires=session.get("expires") if timed else None)


def warm_up(c: Clients, r: Run, session: dict, clock: Clock) -> None:
    """Heartbeats before any firing: which paths work, and how far apart the kit's clock and the agent's are."""
    best = None
    for i in range(WARM_UP):
        beats, sent, received, agent_at = heartbeat(c, r, -1 - i, session, clock)
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


def time_one(c: Clients, r: Run, clock: Clock, watch_own_trigger: bool, n0: int,
             before: dict[str, list[Beat]] | None = None) -> Repeat:
    """One repeat: fire (or wait for the customer's own trigger), then a heartbeat a second through the window and the
    hold. `before` is each path's heartbeats before the firing: the warm-up's, or those since the last stop was taken
    off."""
    rep = Repeat()
    for p, beats in (before or {}).items():
        rep.beats.setdefault(p, []).extend(beats)
    session = assume(c, r, clock)
    rep.session_expires = session.get("expires")
    n = n0
    if watch_own_trigger:
        rep.watched_from = clock.now()
        seen = firing.watch(c.iam, c.lambda_, r.run, until=clock.now() + r.window, now=clock.now, sleep=clock.sleep)
        if seen is None:
            return rep
        rep.fired_before = rep.fired_after = seen
    elif r.stop_ref == firing.REVOKE:
        clock.sleep(5.0)                # the session just taken is then seconds older than the moment revoked before
        done = firing.revoke(c.iam, r.run, before=clock.now() + r.offset, now=clock.now)
        rep.fired_before, rep.fired_after = done["agent_role"]
        rep.second_fired_before, rep.second_fired_after = done["second_role"]
    else:
        rep.fired_before, rep.fired_after = firing.fire(c.iam, r.run, r.stop_ref, now=clock.now)
    end = max(rep.fired_after, rep.second_fired_after) + r.window + HOLD
    while clock.now() < end:
        beats, _, _, _ = heartbeat(c, r, n, session, clock)
        for p, b in beats.items():
            rep.beats.setdefault(p, []).append(b)
        n += 1
        clock.sleep(1.0)
    return rep


def recover(c: Clients, r: Run, clock: Clock) -> dict[str, list[Beat]]:
    """Between repeats: remove the stop, then wait until the agent's own calls work again. Returns each path's
    heartbeats meanwhile, which come before the next repeat's firing."""
    firing.remove(c.iam, r.run, r.stop_ref)
    session = assume_or_none(c, r, clock)
    end = clock.now() + RECOVERY
    good, seen = 0, {}
    while clock.now() < end and good < 5:
        beats, _, _, _ = heartbeat(c, r, 0, session or {}, clock)
        for p, b in beats.items():
            seen.setdefault(p, []).append(b)
        good = good + 1 if beats.get("own_calls") and beats["own_calls"].ok else 0
        clock.sleep(1.0)
    return seen


def assume_or_none(c: Clients, r: Run, clock: Clock) -> dict | None:
    try:
        return assume(c, r, clock)
    except Exception:  # noqa: BLE001 - the stop may still be taking itself off
        return None


def firing_moments(c: Clients, r: Run, clock: Clock, wait: float = TRAIL_WAIT) -> None:
    """Each repeat's firing moment: CloudTrail's record of its attach call, waited for up to `wait` seconds; else the
    kit's own clock when the call returned, moved onto the agent's clock."""
    n = names(r.run)
    event_name = firing.KINDS[r.stop_kind]
    if r.fired_by != "the kit":
        # the customer's own trigger made no attach call of the kit's: its moment is when the kit saw the change
        for rep in r.repeats:
            if rep.fired_after:
                rep.fired_at = rep.fired_after + r.offset
        identify(c, r, clock, wait)
        return
    # (repeat, its moment's prefix, the role its call named): the agent's role, and for revoking, the role it became
    pending = [(rep, "", n["agent_role"]) for rep in r.repeats if rep.fired_after]
    pending += [(rep, "second_", n["second_role"]) for rep in r.repeats if rep.second_fired_after]
    end = clock.now() + wait
    while pending and clock.now() < end:
        for item in list(pending):
            rep, prefix, role = item
            before, after = getattr(rep, prefix + "fired_before"), getattr(rep, prefix + "fired_after")
            events = c.cloudtrail.lookup_events(
                LookupAttributes=[{"AttributeKey": "ResourceName", "AttributeValue": role}],
                StartTime=before - 5, EndTime=after + 5).get("Events", [])
            for e in events:
                if e.get("EventName") == event_name:
                    when = e["EventTime"]
                    setattr(rep, prefix + "fired_at", when.timestamp() if hasattr(when, "timestamp") else float(when))
                    setattr(rep, prefix + "fired_precision", 1.0)     # CloudTrail gives the whole second
                    pending.remove(item)
                    break
        if pending:
            clock.sleep(30.0)
    for rep, prefix, _ in pending:
        before, after = getattr(rep, prefix + "fired_before"), getattr(rep, prefix + "fired_after")
        setattr(rep, prefix + "fired_at", before + r.offset)          # the call was made between the two readings
        setattr(rep, prefix + "fired_precision", after - before)


# CUSTOMER TEXT: approved by the founder, word for word, 30 October 2026
NOT_IDENTIFIED = ("CloudTrail holds no record of your trigger as a kind of stop the kit counts, so nothing counts as "
                  "stopped")
# Your own trigger's kind of stop, by the call CloudTrail records of your action on the test agent's role (the founder's
# refusal ruling of 29 October 2026, item 5). A policy written on the role named AWSRevokeOlderSessions is revoking its
# sessions. Nothing else on the role or the function (deleting it, or setting its concurrency) is a kind whose refusals
# the kit counts.
TRIGGER_CALLS = {"AttachRolePolicy": refusals.AWS_POLICY, "PutRolePolicy": refusals.AWS_INLINE}


def identify(c: Clients, r: Run, clock: Clock, wait: float = TRAIL_WAIT) -> None:
    """Your own trigger's kind of stop: the last call CloudTrail records on the test agent's role that makes a kind the
    kit counts, from when the kit began to watch to just after it saw the change, made by anyone but CloudFormation and
    not refused. Waited for up to `wait` seconds. Sets the run's trigger kind and the record it came from; where there is
    none, the kind is None, and nothing counts as stopped."""
    rep = next((x for x in r.repeats if x.fired_after), None)
    if rep is None:
        return
    role = names(r.run)["agent_role"]
    start, end = rep.watched_from + r.offset - 5, rep.fired_after + r.offset + 5
    deadline = clock.now() + wait
    while True:
        calls, token = [], None
        while True:
            page = c.cloudtrail.lookup_events(LookupAttributes=[{"AttributeKey": "ResourceName", "AttributeValue": role}],
                                              StartTime=start, EndTime=end, **({"NextToken": token} if token else {}))
            for e in page.get("Events", []):
                detail = json.loads(e.get("CloudTrailEvent") or "{}")
                by = (detail.get("sourceIPAddress"), (detail.get("userIdentity") or {}).get("invokedBy"))
                if e.get("EventName") in TRIGGER_CALLS and not detail.get("errorCode") \
                        and "cloudformation.amazonaws.com" not in by:
                    calls.append((e, detail))
            token = page.get("NextToken")
            if not token:
                break
        if calls or clock.now() >= deadline:
            break
        clock.sleep(30.0)
    if not calls:
        return
    e, detail = max(calls, key=lambda x: _seconds_of(x[0]["EventTime"]))
    kind = TRIGGER_CALLS[e["EventName"]]
    if (detail.get("requestParameters") or {}).get("policyName") == firing.REVOKE_POLICY:
        kind = refusals.AWS_REVOKE
    r.trigger_kind = kind
    r.trigger_record = {"source": "CloudTrail", "event_id": e.get("EventId", ""), "event_name": e["EventName"],
                        "event_time": _iso(_seconds_of(e["EventTime"]))}


def _seconds_of(when: Any) -> float:
    return when.timestamp() if hasattr(when, "timestamp") else float(when)


def tear_down(c: Clients, r: Run, clock: Clock) -> None:
    """Remove the stop the kit fired and everything it made; name anything left (D532, K4)."""
    n = names(r.run)
    try:
        firing.remove(c.iam, r.run, r.stop_ref)
    except Exception:  # noqa: BLE001 - a role already gone has no stop on it
        pass
    bucket = r.outputs.get("Bucket")
    if bucket:
        try:
            while True:
                listed = c.s3.list_objects_v2(Bucket=bucket).get("Contents", [])
                if not listed:
                    break
                c.s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in listed]})
        except Exception:  # noqa: BLE001 - what cannot be emptied is named below as left
            pass
    try:
        c.cloudformation.delete_stack(StackName=n["stack"])
        _wait_for_stack(c.cloudformation, n["stack"], clock, "DELETE_COMPLETE")
    except Exception:  # noqa: BLE001 - what the stack could not delete is named below as left
        pass
    r.left_behind, r.checked_gone = check_gone(c, r)


NOT_FOUND = {"NoSuchEntity", "ResourceNotFoundException", "NoSuchBucket", "404", "NotFound"}


def _gone(call: Callable[[], Any]) -> bool | str:
    """True where the call answers that the thing does not exist; False where it exists; else the error's code, for a
    thing that could not be checked."""
    try:
        call()
        return False
    except Exception as e:  # noqa: BLE001 - each answer is sorted below
        code = str(getattr(e, "response", {}).get("Error", {}).get("Code") or type(e).__name__)
        if code in NOT_FOUND or (code == "ValidationError" and "does not exist" in str(e)):
            return True
        return code


class _NotFound(Exception):
    response = {"Error": {"Code": "NotFound"}}


def check_gone(c: Clients, r: Run) -> tuple[list[str], list[str]]:
    """Each thing the run made, checked gone by its own identifier; then the run's tag, for anything else. Returns what
    is left (each named, and why where it could not be checked) and what was checked gone."""
    n = names(r.run)
    log_group = f"/aws/lambda/{n['function']}"

    def log_groups() -> list[str]:
        found = c.logs.describe_log_groups(logGroupNamePrefix=log_group).get("logGroups", [])
        return [g["logGroupName"] for g in found if g["logGroupName"] == log_group]

    if c.logs is not None:
        try:
            if log_groups():
                c.logs.delete_log_group(logGroupName=log_group)
        except Exception:  # noqa: BLE001 - checked below, and named if it is still there
            pass

    def log_group_is_there() -> None:
        if not log_groups():
            raise _NotFound()

    things: list[tuple[str, Callable[[], Any]]] = [
        (f"the stack {n['stack']}", lambda: c.cloudformation.describe_stacks(StackName=n["stack"])),
        (f"the function {n['function']}", lambda: c.lambda_.get_function(FunctionName=n["function"])),
        (f"the role {n['agent_role']}", lambda: c.iam.get_role(RoleName=n["agent_role"])),
        (f"the role {n['second_role']}", lambda: c.iam.get_role(RoleName=n["second_role"])),
    ]
    if r.outputs.get("Bucket"):
        things.append((f"the bucket {r.outputs['Bucket']}", lambda: c.s3.head_bucket(Bucket=r.outputs["Bucket"])))
    if c.logs is not None:
        things.append((f"the log group {log_group}", log_group_is_there))
    left, gone = [], []
    for what, call in things:
        found = _gone(call)
        if found is True:
            gone.append(what)
        else:
            left.append(what if found is False else f"{what} (could not be checked: {found})")
    # the stop itself, on a role that is still there
    for which in ("agent_role", "second_role"):
        role = n[which]
        if not any(x.startswith(f"the role {role}") for x in left):
            continue
        try:
            if r.stop_ref in (firing.REVOKE, firing.INLINE):
                name = firing.REVOKE_POLICY if r.stop_ref == firing.REVOKE else firing.INLINE
                if (which == "agent_role" or r.stop_ref == firing.REVOKE) and \
                        name in c.iam.list_role_policies(RoleName=role).get("PolicyNames", []):
                    left.append(f"the stop {name} on the role {role}")
            elif which == "agent_role" and r.stop_ref in {
                    a["PolicyArn"] for a in c.iam.list_attached_role_policies(RoleName=role).get("AttachedPolicies", [])}:
                left.append(f"the stop {r.stop_ref} attached to the role {role}")
        except Exception as e:  # noqa: BLE001 - named, unchecked
            left.append(f"the stop on the role {role} (could not be checked: {type(e).__name__})")
    named = " ".join(left)
    tagged = c.tagging.get_resources(TagFilters=[{"Key": TAG, "Values": [r.run]}]).get("ResourceTagMappingList", [])
    left += sorted(m["ResourceARN"] for m in tagged if m["ResourceARN"].split(":")[-1].split("/")[-1] not in named)
    return left, gone


def _source(precision: float) -> str:
    return ("CloudTrail's record of the call, to the whole second" if precision == 1.0 else
            f"the kit's own clock, moved onto the agent's; the call took {precision:.3f} seconds")


def _moment(rep: Repeat, p: str) -> tuple[float | None, float]:
    """A path's firing moment and its precision: under the role the agent became, the call that revoked that role's
    sessions; else the call on the agent's own role."""
    if p == "another_identity" and rep.second_fired_after:
        return rep.second_fired_at, rep.second_fired_precision
    return rep.fired_at, rep.fired_precision


def _one(r: Run, rep: Repeat, p: str) -> PathResult:
    at, precision = _moment(rep, p)
    kind = r.counted_kind
    found = judge(rep.beats.get(p, []), at, window=r.window, tried=p in r.working, setup_errors=r.setup_errors.get(p),
                  fired_precision=precision, counts=lambda b, before: refusals.counts(kind, p, b, before))
    if kind is None and found.outcome == NOT_MEASURED:
        found = replace(found, reason=NOT_IDENTIFIED)
    keeps = rep.session_expires if p == "another_identity" and found.outcome == "not stopped" else None
    return replace(found, fired_source=_source(precision) if at is not None else None, keeps_working_until=keeps,
                   fired_at=at)


def results(r: Run) -> list[tuple[float | None, dict[str, PathResult]]]:
    """Each repeat's paths, each judged from its own firing moment."""
    return [(rep.fired_at, {p: _one(r, rep, p) for p in AWS_PATHS}) for rep in r.repeats]


def _iso(t: float | None) -> str | None:
    if t is None:
        return None
    return datetime.fromtimestamp(t, tz=timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def details(r: Run, doc: dict) -> dict:
    """What the page shows, as a file beside the result: each path's time to effect as a range, its successes after its
    first refusal, a session's expiry, the errors seen and each failure's record (result.failure_records), counted or
    not, with what the teardown checked gone and, for your own trigger, the record its kind came from. It stays with the
    one who ran it; the result file is what may be submitted. Arvaken keeps its own runs' as its measurement (K9)."""
    repeats = []
    for rep, (_, found) in zip(r.repeats, results(r)):
        repeats.append({p: {
            "outcome": f.outcome, "fired_at": _iso(_moment(rep, p)[0]), "fired_source": f.fired_source,
            "effect_between_seconds": list(f.effect_between) if f.effect_between else None,
            "successes_after_first_refusal": f.successes_after_first_refusal,
            "first_refused": _iso(f.first_failure_after), "stopped_from": _iso(f.stopped_at),
            "last_success": _iso(f.last_success_after), "tries_after": f.tries_after, "failures_after": f.failures_after,
            "errors": f.errors, "not_counted": f.not_counted, "reason": f.reason,
            "keeps_working_until": _iso(f.keeps_working_until), "failures": result.failure_records(f)}
            for p, f in found.items()})
    # each repeat's refusals by Lambda to run the agent at all, after the stop, by Lambda's code
    refused = []
    for rep in r.repeats:
        at = rep.fired_at if rep.fired_at is not None else float("inf")
        refused.append(dict(Counter(b.error.removeprefix(REFUSED) for b in rep.beats.get("own_calls", [])
                                    if b.error and b.error.startswith(REFUSED) and b.at > at)))
    return {"format": "stop-test-details/1", "run": r.run, "result_signature": doc["signature"],
            "stop_kind": r.stop_kind, "window_seconds": r.window, "left_behind": r.left_behind,
            "checked_gone": r.checked_gone, "repeats": repeats, "lambda_refused": refused,
            "trigger": {"kind": r.trigger_kind, "record": r.trigger_record} if r.fired_by == "your own trigger" else None}


def the_result(r: Run, key=None) -> dict:
    """The run's result, signed with a key made for it (result.py)."""
    doc = result.build(
        kit_version=__version__, cloud="aws", region=r.region,
        began_at=r.began_at, ended_at=r.ended_at, window=r.window, clock_gap_ms=int(round(abs(r.offset) * 1000)),
        calls=r.calls, left_behind=r.left_behind, stop_kind=r.stop_kind, fired_by=r.fired_by,
        stop_ref=r.stop_ref,
        agent={"kind": "aws-lambda-function", "runtime": RUNTIME, "memory_mb": MEMORY_MB, "private_network": False,
               "ref": r.outputs.get("Agent", ""), "role_ref": r.outputs.get("AgentRole", "")},
        repeats=results(r))
    return result.sign(doc, key or result.new_key())


def run(c: Clients, stop_ref: str, *, endpoint: str, fired_by: str = "the kit", window: float = WINDOWS["aws"],
        repeats: int = 1, clock: Clock | None = None, run_name: str | None = None,
        trail_wait: float = TRAIL_WAIT, say: Callable[[str], None] = lambda _: None) -> tuple[Run, dict]:
    """A whole run, torn down whatever happens. Returns the run's record and its signed result. `say` is told, as the
    run goes, of a path that did not work before the stop."""
    from arvaken_stop_test.aws.stack import new_run
    clock = clock or Clock()
    if fired_by not in result.FIRED_BY:
        raise ValueError(f"the stop is fired by one of {result.FIRED_BY}")
    if fired_by == "the kit":
        reason = firing.why_not(stop_ref)
        if reason:
            raise firing.Refused(reason)            # before anything is made
    the_name = run_name or new_run()
    if fired_by == "the kit" and stop_ref not in (firing.REVOKE, firing.INLINE) \
            and not firing.covers(c.iam, stop_ref, the_name):
        raise firing.Refused(firing.NOT_COVERED)    # before anything is made
    reason = firing.why_no_boundary(c.iam, c.sts)
    if reason:
        raise firing.Refused(reason)                # before anything is made
    if not 1 <= repeats <= 5:
        raise ValueError("a run repeats one to five times")
    if fired_by == "your own trigger" and repeats != 1:
        raise ValueError("with your own trigger a run fires once: only you can take your own stop off between repeats")
    r = Run(run=the_name, stop_ref=stop_ref, fired_by=fired_by, window=window, region=c.region)
    r.began_at = clock.now()
    try:
        deploy(c, r, endpoint, clock)
        warm_up(c, r, assume(c, r, clock), clock)
        for p in AWS_PATHS:
            if p not in r.working:
                codes = ", ".join(f"{code} {k}" for code, k in sorted(r.setup_errors.get(p, {}).items()))
                say(f"Before the stop, {PATH_WORDS[p]} did not work ({codes or 'no answer'}): it will be reported as "
                    "not run.")
        n, before = 0, r.warm_beats
        for i in range(repeats):
            if i:
                before = recover(c, r, clock)
            rep = time_one(c, r, clock, fired_by == "your own trigger", n, before)
            r.repeats.append(rep)
            n += sum(len(b) for b in rep.beats.values())
        firing_moments(c, r, clock, wait=trail_wait)
    finally:
        tear_down(c, r, clock)
        r.ended_at = clock.now()
    return r, the_result(r)
