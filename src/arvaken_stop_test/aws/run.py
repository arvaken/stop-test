"""One run of the stop test on AWS: deploy, warm up, fire and time, remove, tear down, and the signed result (the
design's sections 3 to 8; D532).

Every call to AWS goes through `Clients`, which the command line makes from the customer's own credentials and the
tests make from fakes. Every wait goes through `Clock`, so a test runs a fifteen-minute window in no time.

**The firing moment** is CloudTrail's record of the attach call, as the design says (section 6), read once the windows
are over. Where CloudTrail has not recorded it by then, the moment is the kit's own clock when the call returned,
moved onto the test agent's clock by the difference measured during the warm-up.
"""
from __future__ import annotations

import json
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from arvaken_stop_test import __version__, result
from arvaken_stop_test.aws import fire as firing
from arvaken_stop_test.aws.stack import MEMORY_MB, RUNTIME, TAG, names, template_body
from arvaken_stop_test.timing import HOLD, WINDOW, Beat, PathResult, judge

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


@dataclass
class Repeat:
    fired_before: float = 0.0           # the kit's clock just before the attach call
    fired_after: float = 0.0            # and just after it returned
    fired_at: float | None = None       # on the test agent's clock: CloudTrail's, or the kit's moved onto it
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
    repeats: list[Repeat] = field(default_factory=list)
    left_behind: list[str] = field(default_factory=list)


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


def _invoke(c: Clients, r: Run, payload: dict, clock: Clock) -> tuple[dict, float, float]:
    sent = clock.now()
    response = c.lambda_.invoke(FunctionName=names(r.run)["function"], Payload=json.dumps(payload).encode())
    body = json.loads(response["Payload"].read())
    return body, sent, clock.now()


def assume(c: Clients, r: Run, clock: Clock) -> dict:
    body, _, _ = _invoke(c, r, {"action": "assume"}, clock)
    return body["session"]


def heartbeat(c: Clients, r: Run, n: int, session: dict, clock: Clock) -> tuple[dict[str, Beat], float, float, float]:
    """One heartbeat: each path's result, the kit's clock when it was asked and answered, and the agent's own clock."""
    body, sent, received = _invoke(c, r, {"n": n, "session": session}, clock)
    beats = {p: Beat(float(b["at"]), bool(b["ok"]), b.get("error")) for p, b in (body.get("beats") or {}).items()}
    r.calls += len(beats)
    return beats, sent, received, float(body["at"])


def warm_up(c: Clients, r: Run, session: dict, clock: Clock) -> None:
    """Heartbeats before any firing: which paths work, and how far apart the kit's clock and the agent's are."""
    best = None
    for i in range(WARM_UP):
        beats, sent, received, agent_at = heartbeat(c, r, -1 - i, session, clock)
        r.working |= {p for p, b in beats.items() if b.ok}
        trip = received - sent
        if best is None or trip < best[0]:
            best = (trip, agent_at - (sent + received) / 2)
        clock.sleep(1.0)
    r.offset = best[1] if best else 0.0


def time_one(c: Clients, r: Run, clock: Clock, watch_own_trigger: bool, n0: int) -> Repeat:
    """One repeat: fire (or wait for the customer's own trigger), then a heartbeat a second through the window and the
    hold."""
    rep = Repeat()
    session = assume(c, r, clock)
    n = n0
    if watch_own_trigger:
        seen = firing.watch(c.iam, c.lambda_, r.run, until=clock.now() + r.window, now=clock.now, sleep=clock.sleep)
        if seen is None:
            return rep
        rep.fired_before = rep.fired_after = seen
    else:
        rep.fired_before, rep.fired_after = firing.fire(c.iam, r.run, r.stop_ref, now=clock.now)
    end = rep.fired_after + r.window + HOLD
    while clock.now() < end:
        beats, _, _, _ = heartbeat(c, r, n, session, clock)
        for p, b in beats.items():
            rep.beats.setdefault(p, []).append(b)
        n += 1
        clock.sleep(1.0)
    return rep


def recover(c: Clients, r: Run, clock: Clock) -> None:
    """Between repeats: remove the stop, then wait until the agent's own calls work again."""
    firing.remove(c.iam, r.run, r.stop_ref)
    session = assume_or_none(c, r, clock)
    end = clock.now() + RECOVERY
    good = 0
    while clock.now() < end and good < 5:
        beats, _, _, _ = heartbeat(c, r, 0, session or {}, clock)
        good = good + 1 if beats.get("own_calls") and beats["own_calls"].ok else 0
        clock.sleep(1.0)


def assume_or_none(c: Clients, r: Run, clock: Clock) -> dict | None:
    try:
        return assume(c, r, clock)
    except Exception:  # noqa: BLE001 - the stop may still be taking itself off
        return None


def firing_moments(c: Clients, r: Run, clock: Clock, wait: float = TRAIL_WAIT) -> None:
    """Each repeat's firing moment: CloudTrail's record of its attach call, waited for up to `wait` seconds; else the
    kit's own clock when the call returned, moved onto the agent's clock."""
    role = names(r.run)["agent_role"]
    if r.fired_by != "the kit":
        # the customer's own trigger made no attach call of the kit's: its moment is when the kit saw the change
        for rep in r.repeats:
            if rep.fired_after:
                rep.fired_at = rep.fired_after + r.offset
        return
    pending = [rep for rep in r.repeats if rep.fired_after and rep.fired_at is None]
    end = clock.now() + wait
    while pending and clock.now() < end:
        for rep in list(pending):
            events = c.cloudtrail.lookup_events(
                LookupAttributes=[{"AttributeKey": "ResourceName", "AttributeValue": role}],
                StartTime=rep.fired_before - 5, EndTime=rep.fired_after + 5).get("Events", [])
            for e in events:
                if e.get("EventName") == "AttachRolePolicy":
                    when = e["EventTime"]
                    rep.fired_at = when.timestamp() if hasattr(when, "timestamp") else float(when)
                    pending.remove(rep)
                    break
        if pending:
            clock.sleep(30.0)
    for rep in pending:
        rep.fired_at = rep.fired_after + r.offset


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
    left = c.tagging.get_resources(TagFilters=[{"Key": TAG, "Values": [r.run]}]).get("ResourceTagMappingList", [])
    r.left_behind = sorted(m["ResourceARN"] for m in left)


def results(r: Run) -> list[tuple[float | None, dict[str, PathResult]]]:
    return [(rep.fired_at, {p: judge(rep.beats.get(p, []), rep.fired_at, window=r.window, tried=p in r.working)
                            for p in AWS_PATHS}) for rep in r.repeats]


def the_result(r: Run, key=None) -> dict:
    """The run's result, signed with a key made for it (result.py)."""
    doc = result.build(
        kit_version=__version__, cloud="aws", region=r.region,
        began_at=r.began_at, ended_at=r.ended_at, window=r.window, clock_gap_ms=int(round(abs(r.offset) * 1000)),
        calls=r.calls, left_behind=r.left_behind, stop_kind="policy on a role", fired_by=r.fired_by,
        stop_ref=r.stop_ref,
        agent={"kind": "aws-lambda-function", "runtime": RUNTIME, "memory_mb": MEMORY_MB, "private_network": False,
               "ref": r.outputs.get("Agent", ""), "role_ref": r.outputs.get("AgentRole", "")},
        repeats=results(r))
    return result.sign(doc, key or result.new_key())


def run(c: Clients, stop_ref: str, *, endpoint: str, fired_by: str = "the kit", window: float = WINDOW,
        repeats: int = 1, clock: Clock | None = None, run_name: str | None = None,
        trail_wait: float = TRAIL_WAIT) -> tuple[Run, dict]:
    """A whole run, torn down whatever happens. Returns the run's record and its signed result."""
    from arvaken_stop_test.aws.stack import new_run
    clock = clock or Clock()
    if fired_by not in result.FIRED_BY:
        raise ValueError(f"the stop is fired by one of {result.FIRED_BY}")
    if fired_by == "the kit":
        reason = firing.why_not(stop_ref)
        if reason:
            raise firing.Refused(reason)            # before anything is made
    if not 1 <= repeats <= 5:
        raise ValueError("a run repeats one to five times")
    if fired_by == "your own trigger" and repeats != 1:
        raise ValueError("with your own trigger a run fires once: only you can take your own stop off between repeats")
    r = Run(run=run_name or new_run(), stop_ref=stop_ref, fired_by=fired_by, window=window, region=c.region)
    r.began_at = clock.now()
    try:
        deploy(c, r, endpoint, clock)
        warm_up(c, r, assume(c, r, clock), clock)
        n = 0
        for i in range(repeats):
            if i:
                recover(c, r, clock)
            rep = time_one(c, r, clock, fired_by == "your own trigger", n)
            r.repeats.append(rep)
            n += sum(len(b) for b in rep.beats.values())
        firing_moments(c, r, clock, wait=trail_wait)
    finally:
        tear_down(c, r, clock)
        r.ended_at = clock.now()
    return r, the_result(r)
