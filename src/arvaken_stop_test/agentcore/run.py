"""One run of the stop test on AgentCore: make the test agent, time both of what is measured around each stop, remove
the stop, tear down, and the signed result (arvaken/mark, AGENTCORE-MEASUREMENT.md; D618).

Every call to AWS goes through `Clients`, which the command line makes from your own credentials and the tests make
from fakes; every wait goes through `Clock`, as on Lambda (aws/run.py).

**Two things are measured for every kind of stop, in every repeat** (the founder, D618: "the running session must
stop"; "Measure both kinds, recording both results for each"):

1. **New calls to the agent** (the path NEW_CALLS). About once a second the kit makes a fresh InvokeAgentRuntime call,
   each in a session of its own, as a client starting new work would, and the agent answers at once (agent.py). A
   call is answered or refused by AgentCore between the moment the kit sent it and the moment the answer came back, so
   an answered call is timed when it was sent and a refused one when its refusal came back, each on the kit's clock
   moved onto the agent's: a time to effect then errs wider, never narrower. A new session can take seconds to start,
   so the calls overlap, each on a thread of its own (NEW_CALL_WORKERS).
2. **The running session.** One session the kit opens before the stop, by its own runtimeSessionId, whose agent tries
   its four paths about once a second and reports each on the call's streaming response (agent.py), read by the kit on
   a thread of its own (Stream). Its tries are timed by the agent's own clock, as the Lambda agent's are. Where the
   stream closes before the watch is done, the session has ended: from then on, each of its four paths reads as
   refused every second (SESSION_ENDED), as the design has it, "its session ends (the stream closes and no probe
   answers)". Unless the session went on writing its objects after its stream closed, which the kit checks in the
   bucket: then nothing is assumed after the close, and what was seen before it is judged as it is.

**Before each stop**, the session's paths must work: the kit waits for its own calls to succeed READY_TRIES times in a
row, up to READY_WAIT, opening a new session if one does not get there (READY_SESSIONS). A path whose last try before
the stop failed reads "not run", as on Lambda. New calls are made from LEAD seconds before the stop, and the path is
tried only where the last call sent before the stop was answered; where it was refused, the path's errors are each
refusal of a call sent before the stop, the last call's among them.

**The firing moment** comes from CloudTrail's record of the call (D569):
- a policy on the role: AttachRolePolicy or PutRolePolicy, in event history in us-east-1, where IAM's calls are
  recorded (aws/boto.py);
- the deny: PutResourcePolicy, in event history in the run's own region, as AgentCore's control plane is regional,
  matched by the runtime's ARN in the call's parameters;
- ending the session: StopRuntimeSession is a data event, which event history does not hold
  [source: aws-cloudtrail-event-history]: with `--trail`, from the run's own trail (trail.py); without it, the kit's own
  clock, moved onto the agent's, and the details say so.
Each path is timed from the call that acts on it: where the deny is followed by ending the session, new calls are
timed from the deny and the session's four paths from StopRuntimeSession. Where CloudTrail has no record of a call by
TRAIL_WAIT, its moment is the kit's own clock.

**Between repeats** the kit removes the stop and waits until its removal holds: every new call answered for RECOVERED
seconds in a row, up to RECOVERY (recover). Each repeat opens a new session, which must work before its stop. The kit
never calls a repeat's session again once the repeat is over.

**What was made is checked gone by its own identifier** (the founder, 23 October 2026, as on Lambda): the runtime, its
endpoints, its workload identity, its code in S3, the bucket, both roles, any log group AgentCore made for the runtime
(none is expected: its role may not write logs), the stop, and with `--trail` the trail and its bucket, once its records
are kept. Then the run's tag is asked, to catch anything else.
"""
from __future__ import annotations

import json
import queue
import threading
import time
import urllib.parse
import uuid
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, wait as wait_for
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from arvaken_stop_test import __version__, result
from arvaken_stop_test.agentcore import fire as firing
from arvaken_stop_test.agentcore import trail as trailing
from arvaken_stop_test.agentcore.agent import LONGEST
from arvaken_stop_test.agentcore.stack import (CODE_KEY, IDLE, MAX_LIFETIME, NETWORK_MODE, PROTOCOL, RUNTIME, TAG,
                                               boundary_arn, code_sha256, code_zip, names, own_policy, private_bucket,
                                               runtime_request, second_policy, second_trust, to_json, trust)
from arvaken_stop_test.aws import fire as aws_fire
from arvaken_stop_test.timing import HOLD, NOT_STOPPED, PATH_WORDS, WINDOWS, Beat, PathResult, judge

SESSION_PATHS = ("own_calls", "another_identity", "outside_key", "open_internet")
NEW_CALLS = "new_calls"
PATHS = (*SESSION_PATHS, NEW_CALLS)
AGENT_KIND = "aws-agentcore-runtime"
WARM_UP = 10                 # calls before the first stop, to read the agent's clock
READY_WAIT = 180.0           # seconds a session has to show its own calls working before its stop
READY_TRIES = 3              # how many tries in a row of its own calls must succeed
READY_SESSIONS = 3           # how many sessions the kit opens for one repeat before it fires without its own calls
LEAD = 5.0                   # seconds of new calls before the stop
SLACK = 30.0                 # seconds a watch runs past what the kit needs
RECOVERY = 900.0             # seconds to wait, between repeats, for the stop's removal to hold
RECOVERED = 120.0            # seconds in which every new call must be answered for the removal to hold
TRAIL_WAIT = 900.0           # seconds to wait, after the last window, for CloudTrail to record each firing
TRAIL_READY_WAIT = 1500.0    # seconds to wait, before the first stop, for the run's trail to record the agent's calls
TRAIL_READY_EVERY = 10.0     # how often the kit calls the agent while it waits
MAKE_WAIT = 600.0            # seconds to wait for the runtime to be ready, or deleted
ROLE_WAIT = 120.0            # seconds to retry while IAM has not yet made a new role known everywhere
NEW_CALL_WORKERS = 64
NEW_CALL_WAIT = 40.0         # seconds to wait, after the window, for new calls still answering
WRITE_GRACE = 2.0            # seconds after a stream closed in which a write still counts as before it
SESSION_ENDED = "SessionEnded"
# Codes that are the kit's own credentials failing, never the stop: a run that meets one ends, as on Lambda.
KIT_CREDENTIALS = {"ExpiredToken", "ExpiredTokenException", "UnrecognizedClientException", "InvalidClientTokenId",
                   "InvalidSignatureException"}
NOT_FOUND = {"NoSuchEntity", "ResourceNotFoundException", "NoSuchBucket", "NoSuchKey", "404", "NotFound",
             "TrailNotFoundException"}
AUDIT_RECORD = "CloudTrail's record of the call, to the whole second"
TRAIL_RECORD = "CloudTrail's record of the call, a data event in the run's own trail, to the whole second"
POLL_TRAIL = 30.0            # how often the kit looks in the trail's bucket


class NotStarted(aws_fire.Refused):
    """The run was torn down before anything was timed. `run` is its record, with anything it left."""

    def __init__(self, message: str, run: Run):
        super().__init__(message)
        self.run = run


@dataclass
class Clock:
    now: Callable[[], float] = time.time
    sleep: Callable[[float], None] = time.sleep


@dataclass
class Clients:
    iam: Any
    s3: Any
    control: Any                        # bedrock-agentcore-control: the runtime and its resource policy
    data: Any                           # bedrock-agentcore: calls to the agent, and ending a session
    cloudtrail: Any                     # in the run's region: AgentCore's control plane, and the run's trail
    iam_trail: Any                      # where IAM's calls are recorded (aws/boto.py)
    tagging: Any
    region: str
    logs: Any = None
    sts: Any = None
    stream: Callable[..., Any] | None = None            # the running session's stream: Stream, unless a test's
    executor: Callable[[], Any] | None = None           # where new calls are made: threads, unless a test's


@dataclass
class Repeat:
    session: str = ""
    opened: float = 0.0                 # the kit's clock when its session was opened
    ready: float | None = None          # and when the session's own calls worked
    working: set[str] = field(default_factory=set)
    setup_errors: dict[str, dict[str, int]] = field(default_factory=dict)
    session_expires: float | None = None    # the session the agent took for the second role: when it expires
    fired_before: float = 0.0
    fired_after: float = 0.0
    fired_at: float | None = None
    fired_precision: float = 0.0
    fired_source: str | None = None
    # where the deny is followed by ending the session: that call
    end_before: float = 0.0
    end_after: float = 0.0
    end_at: float | None = None
    end_precision: float = 0.0
    end_source: str | None = None
    stream_ended: float | None = None   # the kit's clock when the session's stream closed before its watch was done
    stream_ended_by: str | None = None  # "done", or how it closed
    writes_after_close: int | None = None
    new_calls: int = 0
    beats: dict[str, list[Beat]] = field(default_factory=lambda: {p: [] for p in PATHS})


@dataclass
class Run:
    run: str
    stop_ref: str
    window: float
    region: str = ""
    account: str = ""
    partition: str = "aws"
    trail: bool = False
    began_at: float = 0.0
    ended_at: float = 0.0
    outputs: dict[str, str] = field(default_factory=dict)
    code_sha256: str = ""
    offset: float = 0.0                 # the test agent's clock minus the kit's, from the warm-up
    calls: int = 0
    repeats: list[Repeat] = field(default_factory=list)
    left_behind: list[str] = field(default_factory=list)
    checked_gone: list[str] = field(default_factory=list)
    trail_kept: dict[str, Any] | None = None
    trail_recording: float | None = None    # the kit's clock when the run's trail was seen recording the agent's calls
    trail_records: dict[str, int] = field(default_factory=dict)

    @property
    def stop_kind(self) -> str:
        return firing.kind_of(self.stop_ref)

    @property
    def fired_by(self) -> str:
        return "the kit"


def code(e: Exception) -> str:
    return str(getattr(e, "response", {}).get("Error", {}).get("Code") or type(e).__name__)[:64]


def _retrying(call: Callable[[], Any], codes: set[str], clock: Clock, limit: float = ROLE_WAIT) -> Any:
    """The call, made again every 5 seconds while it fails with one of `codes`, up to `limit` seconds: IAM makes a new
    role known everywhere only after a few seconds."""
    end = clock.now() + limit
    while True:
        try:
            return call()
        except Exception as e:
            if code(e) not in codes or clock.now() >= end:
                raise
            clock.sleep(5.0)


def _session(r: Run, what: str) -> str:
    """A session's ID: the run, what it is for, and 32 random hex digits (AgentCore takes 33 characters or more)."""
    return f"{r.run}-{what}-{uuid.uuid4().hex}"


def make(c: Clients, r: Run, endpoint: str, clock: Clock) -> None:
    """Make the run's roles, bucket, code and runtime, in that order, and wait for the runtime to be ready."""
    n = names(r.run)
    tags = [{"Key": TAG, "Value": r.run}]
    boundary = boundary_arn(r.account, r.partition)
    r.outputs["AgentRole"] = c.iam.create_role(
        RoleName=n["agent_role"], AssumeRolePolicyDocument=to_json(trust(r.run, r.region, r.account, r.partition)),
        PermissionsBoundary=boundary, Tags=tags)["Role"]["Arn"]
    c.iam.put_role_policy(RoleName=n["agent_role"], PolicyName="own-calls",
                          PolicyDocument=to_json(own_policy(r.run, r.account, r.partition)))
    r.outputs["SecondRole"] = _retrying(lambda: c.iam.create_role(
        RoleName=n["second_role"], AssumeRolePolicyDocument=to_json(second_trust(r.outputs["AgentRole"])),
        PermissionsBoundary=boundary, Tags=tags), {"MalformedPolicyDocument"}, clock)["Role"]["Arn"]
    c.iam.put_role_policy(RoleName=n["second_role"], PolicyName="another-identity",
                          PolicyDocument=to_json(second_policy(r.run, r.partition)))
    private_bucket(c.s3, n["bucket"], r.region, r.run)
    r.outputs["Bucket"] = n["bucket"]
    zipped = code_zip()
    r.code_sha256 = code_sha256(zipped)
    c.s3.put_object(Bucket=n["bucket"], Key=CODE_KEY, Body=zipped)
    made = _retrying(lambda: c.control.create_agent_runtime(**runtime_request(
        r.run, r.region, r.outputs["AgentRole"], endpoint, r.outputs["SecondRole"])),
        {"ValidationException", "AccessDeniedException"}, clock)
    r.outputs["Runtime"], r.outputs["RuntimeId"] = made["agentRuntimeArn"], made["agentRuntimeId"]
    r.outputs["WorkloadIdentity"] = (made.get("workloadIdentityDetails") or {}).get("workloadIdentityArn", "")
    end = clock.now() + MAKE_WAIT
    while True:
        got = c.control.get_agent_runtime(agentRuntimeId=r.outputs["RuntimeId"])
        if got["status"] == "READY":
            return
        if got["status"].endswith("FAILED") or clock.now() >= end:
            raise RuntimeError(f"the runtime {n['runtime']} is {got['status']}, not ready")
        clock.sleep(5.0)


def _invoke(c: Clients, r: Run, session: str, payload: dict, accept: str = "application/json") -> dict:
    return c.data.invoke_agent_runtime(agentRuntimeArn=r.outputs["Runtime"], runtimeSessionId=session,
                                       qualifier="DEFAULT", contentType="application/json", accept=accept,
                                       payload=json.dumps(payload).encode())


def answer(c: Clients, r: Run, session: str) -> float:
    """One call the agent answers at once: its clock when it answered."""
    body = json.loads(_invoke(c, r, session, {"action": "answer"})["response"].read())
    return float(body["at"])


def warm_up(c: Clients, r: Run, clock: Clock) -> None:
    """Calls before any stop, in one session: whether the agent answers, and how far apart the kit's clock and the
    agent's are, from the quickest call. Where it never answers, the run ends before anything is fired."""
    session, best, errors = _session(r, "clock"), None, {}
    for _ in range(WARM_UP):
        sent = clock.now()
        try:
            at = answer(c, r, session)
        except Exception as e:  # noqa: BLE001 - each is said below, by its code
            errors[code(e)] = errors.get(code(e), 0) + 1
            clock.sleep(1.0)
            continue
        received = clock.now()
        r.calls += 1
        if best is None or received - sent < best[0]:
            best = (received - sent, at - (sent + received) / 2)
        clock.sleep(1.0)
    if best is None:
        codes = ", ".join(f"{k} {v}" for k, v in sorted(errors.items()))
        # CUSTOMER TEXT: approved by the founder, 04:44 UTC on 28 October 2026 (D618)
        raise NotStarted(f"The test agent did not answer before the stop ({codes}), so nothing was timed.", r)
    r.offset = best[1]


class Stream:
    """The running session: the watch's streaming response, read on a thread of its own. `poll` gives the events that
    have come; `ended` is the kit's clock when the stream closed, and how, unless the kit closed it itself."""

    def __init__(self, c: Clients, r: Run, session: str, seconds: float, clock: Clock):
        self.c, self.r, self.session, self.seconds, self.clock = c, r, session, seconds, clock
        self.events: queue.SimpleQueue = queue.SimpleQueue()
        self.ended: tuple[float, str] | None = None
        self.closing = False
        self.body = None
        self.thread = threading.Thread(target=self._read, daemon=True)
        self.thread.start()

    def _read(self) -> None:
        how = "StreamEnded"
        try:
            self.body = _invoke(self.c, self.r, self.session,
                                {"action": "watch", "seconds": self.seconds, "tag": self.session},
                                accept="text/event-stream")["response"]
            for line in self.body.iter_lines(chunk_size=128):
                if line.startswith(b"data:"):
                    event = json.loads(line[5:].strip())
                    self.events.put(event)
                    if event.get("done"):
                        how = "done"
        except Exception as e:  # noqa: BLE001 - how the stream closed, by its code
            how = code(e)
        if not self.closing:
            self.ended = (self.clock.now(), how)

    def poll(self) -> list[dict]:
        out = []
        while True:
            try:
                out.append(self.events.get_nowait())
            except queue.Empty:
                return out

    def close(self) -> None:
        self.closing = True
        if self.body is not None:
            try:
                self.body.close()
            except Exception:  # noqa: BLE001 - closed already
                pass
        self.thread.join(timeout=10.0)


def _take(r: Run, rep: Repeat, events: list[dict]) -> None:
    """The session's events into the repeat: when its second role's session expires, and each try."""
    for e in events:
        if "session_expires" in e:
            rep.session_expires = e.get("session_expires")
            if e.get("error"):              # the second role's session could not be taken
                rep.setup_errors.setdefault("another_identity", {})[f"AssumeRole: {e['error']}"] = 1
        for p, b in (e.get("beats") or {}).items():
            if p in SESSION_PATHS:
                rep.beats[p].append(Beat(float(b["at"]), bool(b["ok"]), b.get("error")))
                r.calls += 1


def open_session(c: Clients, r: Run, rep: Repeat, clock: Clock, seconds: float) -> Any:
    """The repeat's running session, once its own calls work: READY_TRIES in a row within READY_WAIT, in at most
    READY_SESSIONS sessions; else the last, as it is. Which paths work is read from each path's last try."""
    stream = None
    for _ in range(READY_SESSIONS):
        rep.session, rep.opened, rep.beats = _session(r, "session"), clock.now(), {p: [] for p in PATHS}
        stream = (c.stream or Stream)(c, r, rep.session, seconds, clock)
        end = clock.now() + READY_WAIT
        while clock.now() < end and stream.ended is None:
            _take(r, rep, stream.poll())
            own = rep.beats["own_calls"][-READY_TRIES:]
            if len(own) == READY_TRIES and all(b.ok for b in own):
                rep.ready = clock.now()
                break
            clock.sleep(1.0)
        _take(r, rep, stream.poll())
        if rep.ready is not None:
            break
        if stream.ended is None:
            stream.close()
    rep.working = {p for p in SESSION_PATHS if rep.beats[p] and rep.beats[p][-1].ok}
    for p in SESSION_PATHS:
        for b in rep.beats[p]:
            if not b.ok:
                errors = rep.setup_errors.setdefault(p, {})
                errors[b.error or "unknown"] = errors.get(b.error or "unknown", 0) + 1
    return stream


class NewCalls:
    """New calls to the agent, one each `tick`, each in a session of its own, made on threads (`executor`)."""

    def __init__(self, c: Clients, r: Run, clock: Clock):
        self.c, self.r, self.clock = c, r, clock
        self.pool = (c.executor or (lambda: ThreadPoolExecutor(max_workers=NEW_CALL_WORKERS)))()
        self.lock = threading.Lock()
        self.found: list[tuple[float, Beat]] = []       # each call's sending time on the kit's clock, and its beat
        self.futures: list[Any] = []
        self.fatal: Exception | None = None

    def one(self) -> None:
        sent = self.clock.now()
        try:
            answer(self.c, self.r, _session(self.r, "new"))
            beat = Beat(sent + self.r.offset, True)
        except Exception as e:  # noqa: BLE001 - a refusal is the path's result; the kit's own credentials end the run
            if code(e) in KIT_CREDENTIALS:
                self.fatal = e
                return
            beat = Beat(self.clock.now() + self.r.offset, False, code(e))
        with self.lock:
            self.found.append((sent, beat))

    def tick(self) -> None:
        if self.fatal is not None:
            raise self.fatal
        self.futures.append(self.pool.submit(self.one))

    def finish(self, limit: float = NEW_CALL_WAIT) -> list[tuple[float, Beat]]:
        wait_for(self.futures, timeout=limit)
        self.pool.shutdown(wait=False, cancel_futures=True)
        if self.fatal is not None:
            raise self.fatal
        with self.lock:
            return sorted(self.found, key=lambda f: f[0])


def writes_after(c: Clients, r: Run, rep: Repeat) -> int:
    """How many of the session's own objects were written after its stream closed, by S3's clock."""
    if rep.stream_ended is None:
        return 0
    after = rep.stream_ended + r.offset + WRITE_GRACE
    count, token = 0, None
    while True:
        page = c.s3.list_objects_v2(Bucket=r.outputs["Bucket"], Prefix=f"own/{rep.session}/",
                                    **({"ContinuationToken": token} if token else {}))
        for o in page.get("Contents", []):
            modified = o["LastModified"]
            count += (modified.timestamp() if hasattr(modified, "timestamp") else float(modified)) > after
        token = page.get("NextContinuationToken")
        if not token:
            return count


def time_one(c: Clients, r: Run, clock: Clock, say: Callable[[str], None] = lambda _: None) -> Repeat:
    """One repeat: the running session opened and working, new calls from LEAD seconds before the stop, the stop
    fired, then both through the window and its hold."""
    rep = Repeat()
    seconds = READY_WAIT + LEAD + r.window + HOLD + SLACK
    stream = open_session(c, r, rep, clock, seconds)
    for p in SESSION_PATHS:
        if p not in rep.working:
            say(f"Before the stop, {PATH_WORDS[p]} did not work ({_codes(rep, p)}): it will be reported as not run.")
    new = NewCalls(c, r, clock)
    try:
        lead_end = clock.now() + LEAD
        while clock.now() < lead_end:
            new.tick()
            _take(r, rep, stream.poll())
            clock.sleep(1.0)
        _take(r, rep, stream.poll())        # a path works before the stop where its last try before it worked
        for p in SESSION_PATHS:
            if p in rep.working and not rep.beats[p][-1].ok:
                rep.working.discard(p)
                errors = rep.setup_errors.setdefault(p, {})
                errors[rep.beats[p][-1].error or "unknown"] = errors.get(rep.beats[p][-1].error or "unknown", 0) + 1
        if stream.ended is not None:        # the session ended before its stop: none of its paths was running
            for p in SESSION_PATHS:
                if p in rep.working:
                    rep.working.discard(p)
                    rep.setup_errors.setdefault(p, {})["SessionEndedBeforeTheStop"] = 1
        rep.fired_before, rep.fired_after = firing.fire(c.iam, c.control, r.run, r.stop_ref, r.outputs["Runtime"],
                                                        now=clock.now)
        if r.stop_ref == firing.DENY_AND_END:
            rep.end_before, rep.end_after = firing.end_session(c.data, r.outputs["Runtime"], rep.session,
                                                               now=clock.now)
        end = max(rep.fired_after, rep.end_after) + r.window + HOLD
        while clock.now() < end:
            new.tick()
            _take(r, rep, stream.poll())
            clock.sleep(1.0)
        found = new.finish()
    finally:
        stream.close()
    _take(r, rep, stream.poll())
    rep.new_calls = len(found)
    r.calls += len(found)
    rep.beats[NEW_CALLS] = [b for _, b in found]
    before = [b for sent, b in found if sent < rep.fired_before]
    if before and before[-1].ok:
        rep.working.add(NEW_CALLS)
    else:                                   # each call sent before the stop that was refused, the last among them
        for b in before:
            if not b.ok:
                errors = rep.setup_errors.setdefault(NEW_CALLS, {})
                errors[b.error or "unknown"] = errors.get(b.error or "unknown", 0) + 1
    if stream.ended is not None:
        rep.stream_ended, rep.stream_ended_by = stream.ended
        if rep.stream_ended_by == "done":
            rep.stream_ended = None
        else:
            rep.writes_after_close = writes_after(c, r, rep)
            if not rep.writes_after_close:
                t = rep.stream_ended + r.offset
                while t <= end + r.offset:
                    for p in SESSION_PATHS:
                        rep.beats[p].append(Beat(t, False, SESSION_ENDED))
                    t += 1.0
    return rep


def _codes(rep: Repeat, p: str) -> str:
    return ", ".join(f"{k} {n}" for k, n in sorted(rep.setup_errors.get(p, {}).items())) or "no answer"


def recover(c: Clients, r: Run, clock: Clock) -> None:
    """Between repeats: remove the stop, then wait until its removal holds: every new call answered, from the first
    of them sent, for RECOVERED seconds, up to RECOVERY. A removed deny comes off gradually: in r58051bd3 (29 October
    2026), new calls were answered and refused in turn for one to three minutes after each DeleteResourcePolicy, never
    more than seven answered in a row, and five in a row let the next repeat begin while its new calls were still
    refused."""
    firing.remove(c.iam, c.control, r.run, r.stop_ref, r.outputs.get("Runtime"))
    end, since = clock.now() + RECOVERY, None
    while clock.now() < end:
        sent = clock.now()
        try:
            answer(c, r, _session(r, "recover"))
            since = sent if since is None else since
            if clock.now() - since >= RECOVERED:
                return
        except Exception as e:  # noqa: BLE001 - the stop may still be taking itself off
            if code(e) in KIT_CREDENTIALS:
                raise
            since = None
        clock.sleep(1.0)


def _event_history(lookups: Any, attribute: dict, event: str, before: float, after: float,
                   match: Callable[[dict], bool] = lambda _: True) -> float | None:
    found = lookups.lookup_events(LookupAttributes=[attribute], StartTime=before - 5, EndTime=after + 5)
    for e in found.get("Events", []):
        if e.get("EventName") != event:
            continue
        detail = json.loads(e["CloudTrailEvent"]) if isinstance(e.get("CloudTrailEvent"), str) else {}
        if match(detail):
            when = e["EventTime"]
            return when.timestamp() if hasattr(when, "timestamp") else float(when)
    return None


def _unquoted(arn: Any) -> str:
    """An ARN as a record gives it: AgentCore's PutResourcePolicy records its resourceArn URL-encoded, "arn%3Aaws%3A..."
    (read in event history, 28 October 2026)."""
    return urllib.parse.unquote(arn) if isinstance(arn, str) else ""


def trail_recording(c: Clients, r: Run, clock: Clock, wait: float = TRAIL_READY_WAIT) -> None:
    """Before the first stop, wait until the run's trail has recorded a call to the agent, calling the agent every
    TRAIL_READY_EVERY seconds meanwhile. A trail begins recording a runtime's data events some minutes after it is made
    and started: in the first trial (28 October 2026) its first record came 2 minutes 31 seconds after logging began,
    and a stop fired 30 seconds after it was not recorded. Where none comes by `wait`, nothing is fired."""
    bucket, session, end = trailing.names(r.run)["bucket"], _session(r, "trail"), clock.now() + wait
    while clock.now() < end:
        for _ in range(int(POLL_TRAIL // TRAIL_READY_EVERY)):
            try:
                answer(c, r, session)
                r.calls += 1
            except Exception as e:  # noqa: BLE001 - only the trail's record of a call is waited for
                if code(e) in KIT_CREDENTIALS:
                    raise
            clock.sleep(TRAIL_READY_EVERY)
        if any(e.get("eventSource") == trailing.SOURCE for e in trailing.records(c.s3, bucket)):
            r.trail_recording = clock.now()
            return
    # CUSTOMER TEXT: approved by the founder, 04:44 UTC on 28 October 2026 (D618)
    raise NotStarted(f"The run's trail recorded none of the test agent's calls in {int(wait // 60)} minutes, so ending "
                     "a session could not be timed from it. Nothing was fired.", r)


def firing_moments(c: Clients, r: Run, clock: Clock, wait: float = TRAIL_WAIT) -> None:
    """Each repeat's firing moments from CloudTrail, waited for up to `wait` seconds; else the kit's own clock when the
    call was made, moved onto the agent's."""
    n, arn, event = names(r.run), r.outputs.get("Runtime", ""), firing.event_of(r.stop_ref)

    def fired(rep: Repeat) -> float | None:
        if firing.on_the_role(r.stop_ref):
            return _event_history(c.iam_trail, {"AttributeKey": "ResourceName", "AttributeValue": n["agent_role"]},
                                  event, rep.fired_before, rep.fired_after)
        return _event_history(c.cloudtrail, {"AttributeKey": "EventName", "AttributeValue": event}, event,
                              rep.fired_before, rep.fired_after,
                              match=lambda d: _unquoted((d.get("requestParameters") or {}).get("resourceArn")) == arn)

    def ended(rep: Repeat) -> float | None:
        return trailing.find(trailing.records(c.s3, trailing.names(r.run)["bucket"]), firing.EVENTS["end"],
                             rep.session, rep.end_before, rep.end_after)

    pending = [(rep, "fired", fired, AUDIT_RECORD) for rep in r.repeats if rep.fired_after]
    if r.trail:
        pending += [(rep, "end", ended, TRAIL_RECORD) for rep in r.repeats if rep.end_after]
    end = clock.now() + wait
    while pending and clock.now() < end:
        for item in list(pending):
            rep, prefix, ask, source = item
            at = ask(rep)
            if at is not None:
                setattr(rep, prefix + "_at", at)
                setattr(rep, prefix + "_precision", 1.0)        # CloudTrail gives the whole second
                setattr(rep, prefix + "_source", source)
                pending.remove(item)
        if pending:
            clock.sleep(30.0)
    for rep in r.repeats:
        for prefix in ("fired", "end"):
            before, after = getattr(rep, prefix + "_before"), getattr(rep, prefix + "_after")
            if after and getattr(rep, prefix + "_at") is None:
                setattr(rep, prefix + "_at", before + r.offset)     # the call was made between the two readings
                setattr(rep, prefix + "_precision", after - before)
                setattr(rep, prefix + "_source", f"the kit's own clock, moved onto the agent's; the call took "
                                                  f"{after - before:.3f} seconds")


def _gone(call: Callable[[], Any]) -> bool | str:
    """True where the call answers that the thing does not exist; False where it exists; else the error's code."""
    try:
        call()
        return False
    except Exception as e:  # noqa: BLE001 - each answer is sorted below
        found = code(e)
        return True if found in NOT_FOUND else found


class _NotFound(Exception):
    response = {"Error": {"Code": "NotFound"}}


def runtime_id(c: Clients, r: Run) -> str | None:
    """The run's runtime, by what the run kept, or found by its name for an interrupted run."""
    if r.outputs.get("RuntimeId"):
        return r.outputs["RuntimeId"]
    token = None
    while True:
        page = c.control.list_agent_runtimes(**({"nextToken": token} if token else {}))
        for found in page.get("agentRuntimes", []):
            if found.get("agentRuntimeName") == names(r.run)["runtime"]:
                r.outputs["RuntimeId"], r.outputs["Runtime"] = found["agentRuntimeId"], found["agentRuntimeArn"]
                return found["agentRuntimeId"]
        token = page.get("nextToken")
        if not token:
            return None


def tear_down(c: Clients, r: Run, clock: Clock, trail_folder: Path | None = None,
              say: Callable[[str], None] = lambda _: None) -> None:
    """Remove the stop the kit fired and everything it made; name anything left (D532, K4). With a trail, its records
    are kept first (trail.keep), and the trail and its bucket are deleted only once they are."""
    n = names(r.run)
    try:
        firing.remove(c.iam, c.control, r.run, r.stop_ref, r.outputs.get("Runtime"))
    except Exception:  # noqa: BLE001 - a role or runtime already gone has no stop on it
        pass
    if r.trail:
        try:
            r.trail_kept = trailing.keep(c.cloudtrail, c.s3, r.run, trail_folder or Path(f"stop-test-{r.run}-trail"),
                                         now=clock.now, sleep=clock.sleep)
            r.trail_records = r.trail_kept.pop("records", {})
            trailing.remove(c.cloudtrail, c.s3, r.run)
        except Exception as e:  # noqa: BLE001 - what is not kept is not deleted, and is named below as left
            r.trail_kept = {**(r.trail_kept or {}), "error": code(e)}
    try:
        rid = runtime_id(c, r)
        if rid:
            c.control.delete_agent_runtime(agentRuntimeId=rid)
            end = clock.now() + MAKE_WAIT
            while _gone(lambda: c.control.get_agent_runtime(agentRuntimeId=rid)) is False and clock.now() < end:
                clock.sleep(5.0)
    except Exception:  # noqa: BLE001 - what could not be deleted is named below as left
        pass
    identity = r.outputs.get("WorkloadIdentity", "").rpartition("/")[2]
    if identity and _gone(lambda: c.control.get_workload_identity(name=identity)) is False:
        try:        # AgentCore removes it with the runtime; one still there is removed by its name
            c.control.delete_workload_identity(name=identity)
        except Exception:  # noqa: BLE001 - named below as left
            pass
    try:
        while True:
            listed = c.s3.list_objects_v2(Bucket=n["bucket"]).get("Contents", [])
            if not listed:
                break
            c.s3.delete_objects(Bucket=n["bucket"], Delete={"Objects": [{"Key": o["Key"]} for o in listed]})
        c.s3.delete_bucket(Bucket=n["bucket"])
    except Exception:  # noqa: BLE001 - named below as left
        pass
    for which in ("agent_role", "second_role"):
        role = n[which]
        try:
            for name in c.iam.list_role_policies(RoleName=role).get("PolicyNames", []):
                c.iam.delete_role_policy(RoleName=role, PolicyName=name)
            for attached in c.iam.list_attached_role_policies(RoleName=role).get("AttachedPolicies", []):
                c.iam.detach_role_policy(RoleName=role, PolicyArn=attached["PolicyArn"])
            c.iam.delete_role(RoleName=role)
        except Exception:  # noqa: BLE001 - named below as left
            pass
    if c.logs is not None and r.outputs.get("RuntimeId"):
        try:
            for group in _log_groups(c, r):
                c.logs.delete_log_group(logGroupName=group)
        except Exception:  # noqa: BLE001 - named below as left
            pass
    r.left_behind, r.checked_gone = check_gone(c, r)


def _log_groups(c: Clients, r: Run) -> list[str]:
    prefix = f"/aws/bedrock-agentcore/runtimes/{r.outputs['RuntimeId']}"
    return [g["logGroupName"] for g in c.logs.describe_log_groups(logGroupNamePrefix=prefix).get("logGroups", [])]


def check_gone(c: Clients, r: Run) -> tuple[list[str], list[str]]:
    """Each thing the run made, checked gone by its own identifier; then the run's tag, for anything else. Returns what
    is left (each named, and why where it could not be checked) and what was checked gone."""
    n, t = names(r.run), trailing.names(r.run)
    rid, arn = r.outputs.get("RuntimeId"), r.outputs.get("Runtime", "")

    def there(found: list) -> None:
        if not found:
            raise _NotFound()

    things: list[tuple[str, Callable[[], Any]]] = []
    if rid:
        things += [(f"the runtime {arn or rid}", lambda: c.control.get_agent_runtime(agentRuntimeId=rid)),
                   (f"the runtime's endpoints ({rid})",
                    lambda: there(c.control.list_agent_runtime_endpoints(agentRuntimeId=rid)
                                  .get("runtimeEndpoints", [])))]
    else:
        things.append((f"the runtime {n['runtime']}", lambda: there([runtime_id(c, r)] if runtime_id(c, r) else [])))
    identity = r.outputs.get("WorkloadIdentity", "")
    if identity:
        things.append((f"the workload identity {identity}",
                       lambda: c.control.get_workload_identity(name=identity.rpartition("/")[2])))
    things += [(f"the code s3://{n['bucket']}/{CODE_KEY}", lambda: c.s3.head_object(Bucket=n["bucket"], Key=CODE_KEY)),
               (f"the bucket {n['bucket']}", lambda: c.s3.head_bucket(Bucket=n["bucket"])),
               (f"the role {n['agent_role']}", lambda: c.iam.get_role(RoleName=n["agent_role"])),
               (f"the role {n['second_role']}", lambda: c.iam.get_role(RoleName=n["second_role"]))]
    if c.logs is not None and rid:
        things.append((f"the log groups /aws/bedrock-agentcore/runtimes/{rid}*", lambda: there(_log_groups(c, r))))
    if r.trail:
        things += [(f"the trail {t['trail']}", lambda: c.cloudtrail.get_trail(Name=t["trail"])),
                   (f"the bucket {t['bucket']}", lambda: c.s3.head_bucket(Bucket=t["bucket"]))]
    left, gone = [], []
    for what, call in things:
        found = _gone(call)
        if found is True:
            gone.append(what)
        else:
            left.append(what if found is False else f"{what} (could not be checked: {found})")
    # the stop itself, on a role or a runtime that is still there
    try:
        if firing.on_the_role(r.stop_ref) and any(x.startswith(f"the role {n['agent_role']}") for x in left):
            role = n["agent_role"]
            if r.stop_ref == firing.INLINE:
                if firing.INLINE in c.iam.list_role_policies(RoleName=role).get("PolicyNames", []):
                    left.append(f"the stop {firing.INLINE} on the role {role}")
            elif r.stop_ref in {a["PolicyArn"] for a in
                                c.iam.list_attached_role_policies(RoleName=role).get("AttachedPolicies", [])}:
                left.append(f"the stop {r.stop_ref} attached to the role {role}")
        elif not firing.on_the_role(r.stop_ref) and arn and any(x.startswith("the runtime ") for x in left):
            if _gone(lambda: c.control.get_resource_policy(resourceArn=arn)) is False:
                left.append(f"the stop {r.stop_ref}, the resource policy on the runtime {arn}")
    except Exception as e:  # noqa: BLE001 - named, unchecked
        left.append(f"the stop {r.stop_ref} (could not be checked: {code(e)})")
    named = " ".join(left)
    tagged = c.tagging.get_resources(TagFilters=[{"Key": TAG, "Values": [r.run]}]).get("ResourceTagMappingList", [])
    left += sorted(m["ResourceARN"] for m in tagged if m["ResourceARN"].split(":")[-1].split("/")[-1] not in named
                   and m["ResourceARN"] not in named)
    return left, gone


def _moment(r: Run, rep: Repeat, p: str) -> tuple[float | None, float, str | None]:
    """A path's firing moment, its precision, and where the moment came from: the session's four paths from the call
    that ended the session, where there was one; else the stop's."""
    if p in SESSION_PATHS and rep.end_after:
        return rep.end_at, rep.end_precision, rep.end_source
    return rep.fired_at, rep.fired_precision, rep.fired_source


def _one(r: Run, rep: Repeat, p: str) -> PathResult:
    at, precision, source = _moment(r, rep, p)
    found = judge(rep.beats.get(p, []), at, window=r.window, tried=p in rep.working,
                  setup_errors=rep.setup_errors.get(p), fired_precision=precision)
    keeps = rep.session_expires if p == "another_identity" and found.outcome == NOT_STOPPED else None
    return replace(found, fired_source=source if at is not None else None, keeps_working_until=keeps, fired_at=at)


def results(r: Run) -> list[tuple[float | None, dict[str, PathResult]]]:
    """Each repeat's paths, each judged from its own firing moment."""
    return [(rep.fired_at, {p: _one(r, rep, p) for p in PATHS}) for rep in r.repeats]


def details(r: Run, doc: dict) -> dict:
    """What the page shows, as a file beside the result, with what is particular to AgentCore: the runtime's session
    limits and code, each repeat's running session (when it opened and worked, and how its stream ended), and the
    trail's records. It stays with the one who ran it; the result file is what may be submitted."""
    iso = result.iso
    repeats = []
    for rep, (_, found) in zip(r.repeats, results(r)):
        repeats.append({p: {
            "outcome": f.outcome, "fired_at": iso(_moment(r, rep, p)[0]), "fired_source": f.fired_source,
            "effect_between_seconds": list(f.effect_between) if f.effect_between else None,
            "successes_after_first_refusal": f.successes_after_first_refusal,
            "first_refused": iso(f.first_failure_after), "stopped_from": iso(f.stopped_at),
            "last_success": iso(f.last_success_after), "tries_after": f.tries_after, "failures_after": f.failures_after,
            "errors": f.errors, "reason": f.reason, "keeps_working_until": iso(f.keeps_working_until)}
            for p, f in found.items()})
    sessions = [{"session": rep.session, "opened": iso(rep.opened), "ready": iso(rep.ready),
                 "second_role_session_expires": iso(rep.session_expires),
                 "stream_ended": iso(rep.stream_ended), "stream_ended_by": rep.stream_ended_by,
                 "writes_after_stream_ended": rep.writes_after_close, "new_calls": rep.new_calls,
                 "ended_by_the_kit": iso(rep.end_at) if rep.end_after else None} for rep in r.repeats]
    out = {"format": "stop-test-details/1", "run": r.run, "result_signature": doc["signature"],
           "stop_kind": r.stop_kind, "window_seconds": r.window, "left_behind": r.left_behind,
           "checked_gone": r.checked_gone, "repeats": repeats,
           "agent": {"kind": AGENT_KIND, "runtime": RUNTIME, "network_mode": NETWORK_MODE, "protocol": PROTOCOL,
                     "idle_runtime_session_timeout_seconds": IDLE, "max_lifetime_seconds": MAX_LIFETIME,
                     "code_sha256": r.code_sha256},
           "sessions": sessions}
    if r.trail:
        out["trail"] = {"name": trailing.names(r.run)["trail"], "bucket": trailing.names(r.run)["bucket"],
                        "selectors": trailing.selectors(r.outputs.get("Runtime", "")),
                        "recording_from": iso(r.trail_recording),
                        "end_session_found": [rep.end_source == TRAIL_RECORD for rep in r.repeats if rep.end_after],
                        "records": r.trail_records, "kept": r.trail_kept}
    return out


def the_result(r: Run, key=None) -> dict:
    """The run's result, signed with a key made for it (result.py)."""
    doc = result.build(
        kit_version=__version__, cloud="aws", region=r.region,
        began_at=r.began_at, ended_at=r.ended_at, window=r.window, clock_gap_ms=int(round(abs(r.offset) * 1000)),
        calls=r.calls, left_behind=r.left_behind, stop_kind=r.stop_kind, fired_by=r.fired_by, stop_ref=r.stop_ref,
        agent={"kind": AGENT_KIND, "runtime": RUNTIME, "memory_mb": None, "private_network": False,
               "ref": r.outputs.get("Runtime", ""), "role_ref": r.outputs.get("AgentRole", "")},
        repeats=results(r))
    return result.sign(doc, key or result.new_key())


def run(c: Clients, stop_ref: str, *, endpoint: str, window: float = WINDOWS["aws"], repeats: int = 1,
        clock: Clock | None = None, run_name: str | None = None, trail: bool = False, trail_folder: Path | None = None,
        trail_wait: float = TRAIL_WAIT, say: Callable[[str], None] = lambda _: None) -> tuple[Run, dict]:
    """A whole run, torn down whatever happens. Returns the run's record and its signed result. With `trail`, the run
    makes its own CloudTrail trail for the runtime's data events (trail.py), and keeps its records in `trail_folder`
    before deleting it."""
    from arvaken_stop_test.aws.stack import new_run
    clock = clock or Clock()
    reason = firing.why_not(stop_ref)
    if reason:
        raise firing.Refused(reason)                # before anything is made
    if not 1 <= repeats <= 5:
        raise ValueError("a run repeats one to five times")
    if READY_WAIT + LEAD + window + HOLD + SLACK > LONGEST:
        # CUSTOMER TEXT: approved by the founder, 04:44 UTC on 28 October 2026 (D618); source: aws-agentcore-streaming-limit
        raise ValueError(f"a window on AgentCore is at most {int(LONGEST - READY_WAIT - LEAD - HOLD - SLACK)} seconds: "
                         "the running session is watched on one streaming response, which AWS keeps up to 60 minutes")
    the_name = run_name or new_run()
    if firing.on_the_role(stop_ref) and stop_ref != firing.INLINE and not firing.covers(c.iam, stop_ref, the_name):
        raise firing.Refused(aws_fire.NOT_COVERED)  # before anything is made
    reason = aws_fire.why_no_boundary(c.iam, c.sts)
    if reason:
        raise firing.Refused(reason)                # before anything is made
    caller = c.sts.get_caller_identity()
    r = Run(run=the_name, stop_ref=stop_ref, window=window, region=c.region, account=caller["Account"],
            partition=caller["Arn"].split(":")[1], trail=trail)
    r.began_at = clock.now()
    try:
        make(c, r, endpoint, clock)
        if trail:
            trailing.make(c.cloudtrail, c.s3, r.run, r.region, r.account, r.outputs["Runtime"], r.partition)
        warm_up(c, r, clock)
        if trail:
            trail_recording(c, r, clock)
        for i in range(repeats):
            if i:
                recover(c, r, clock)
            r.repeats.append(time_one(c, r, clock, say=say))
        firing_moments(c, r, clock, wait=trail_wait)
    finally:
        tear_down(c, r, clock, trail_folder=trail_folder, say=say)
        r.ended_at = clock.now()
    return r, the_result(r)
