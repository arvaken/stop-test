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

**Through a gateway (`--via`; D561, section 5).** The stop is a product's control: the kit cannot see a product's change
in the cloud, so the customer fires it themselves, from a mark: the kit asks them to press Enter, then fire their stop,
and each path is timed from that Enter, so a time errs toward slower, never faster. Each invocation carries the
gateway's address and the customer's certificate bundle for the agent's calls through it (agent.py); neither is written
into the stack, the result or the details as given, and the result keeps the address as its scheme, host and port alone
(result.py; D595). Before the stop, each path must work through the gateway: one whose last try in the warm-up did not
reads "not measured", never "stopped". Where none works, there is nothing to time, and the kit asks for no mark.

**In a subnet of the customer's (`--subnet`, `--security-group`).** Lambda makes the function's network interfaces
there, which the kit finds after the stack is made: those in the subnet whose description names the run's function, and
any that appeared in it, with exactly the run's security groups, while the stack was made. AWS removes them some time
after the function is deleted, so the teardown waits for them, up to ENI_WAIT, saying why, before it names any as
left: an interface still there during that wait is waited for, not left. Ctrl-C ends the wait early; the interfaces
still there are then named as left.
"""
from __future__ import annotations

import json
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any

from arvaken_stop_test import __version__, result
from arvaken_stop_test.aws import fire as firing
from arvaken_stop_test.aws.stack import MEMORY_MB, RUNTIME, TAG, names, template_body
from arvaken_stop_test.timing import HOLD, NOT_MEASURED, NOT_RUN, PATH_WORDS, WINDOWS, Beat, PathResult, judge

AWS_PATHS = ("own_calls", "another_identity", "outside_key", "open_internet")
WARM_UP = 10                 # heartbeats before the first firing
RECOVERY = 300.0             # seconds to wait, between repeats, for the agent's own calls to work again
TRAIL_WAIT = 900.0           # seconds to wait, after the last window, for CloudTrail to record each firing
ENI_WAIT = 1800.0            # seconds to wait, once the function is deleted, for AWS to remove its network interfaces
ENI_POLL = 30.0              # and how often to ask

# What a run through a gateway says, as it goes. The first is the founder's own words (D561, section 5).
# CUSTOMER TEXT: approved by the founder, 04:23:21 UTC on 27 October 2026 (D602)
MARK_PROMPT = "Press Enter, then fire your stop."
# CUSTOMER TEXT: approved by the founder, 04:23:21 UTC on 27 October 2026 (D602)
MARKED = "Marked. Each path is timed from your mark, so a time it gives errs toward slower, never faster."
# CUSTOMER TEXT: approved by the founder, 04:23:21 UTC on 27 October 2026 (D602)
SWITCH_OFF = "The timing is done: you can turn your gateway's switch off now. The kit never turns it off itself."
# CUSTOMER TEXT: approved by the founder, 04:23:21 UTC on 27 October 2026 (D602)
NOT_THROUGH_THE_GATEWAY = ("Before the stop, {path} did not work through your gateway ({codes}): it will be reported "
                           "as not measured, never as stopped.")
# CUSTOMER TEXT: approved by the founder, 04:23:21 UTC on 27 October 2026 (D602)
NOTHING_THROUGH_THE_GATEWAY = ("No path worked through your gateway before the stop, so there is nothing to time. "
                               "Don't fire your stop: the kit is removing what it made.")
# CUSTOMER TEXT: approved by the founder, 04:23:21 UTC on 27 October 2026 (D602)
NOT_MEASURED_REASON = "it did not work through your gateway before the stop"
# CUSTOMER TEXT: approved by the founder, 04:23:21 UTC on 27 October 2026 (D602)
FROM_THE_MARK = "your mark, the moment you pressed Enter, on the kit's clock moved onto the agent's"
# What the teardown says of the function's network interfaces in a subnet of yours.
# CUSTOMER TEXT: approved by the founder, 04:23:21 UTC on 27 October 2026 (D602)
WAITING_FOR_INTERFACES = (
    "AWS removes a Lambda function's network interfaces some time after the function is deleted, often many minutes "
    "later. The kit is waiting up to {minutes} minutes for the test agent's {count} network interface(s) in your "
    "subnet {subnet} to be removed, before it names anything left for you to delete.")
# CUSTOMER TEXT: approved by the founder, 04:23:21 UTC on 27 October 2026 (D602)
WAIT_STOPPED = "You stopped the wait. The network interfaces still there are named as left; AWS may yet remove them."
# CUSTOMER TEXT: approved by the founder, 04:23:21 UTC on 27 October 2026 (D602)
INTERFACE_GONE = "the network interface {id}"
# CUSTOMER TEXT: approved by the founder, 04:23:21 UTC on 27 October 2026 (D602)
INTERFACE_LEFT = "the network interface {id} in your subnet {subnet}"
# CUSTOMER TEXT: approved by the founder, 04:23:21 UTC on 27 October 2026 (D602)
INTERFACES_UNCHECKED = "the test agent's network interfaces in your subnet {subnet} (could not be checked: {code})"


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
    ec2: Any = None                     # read only: a subnet's network interfaces, where a run names one


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
    # through a gateway: its address as given, a user name and password included, and the customer's certificate
    # bundle, for the agent's calls alone (never shown, never written); and the product, as the customer declared it
    via: str = field(default="", repr=False)
    ca: str = field(default="", repr=False)
    product: dict[str, str] | None = None
    # in a subnet of the customer's: it, its security groups, and the function's network interfaces found there
    subnet: str = ""
    security_groups: list[str] = field(default_factory=list)
    interfaces: list[str] = field(default_factory=list)
    interfaces_gone: list[str] = field(default_factory=list)
    interfaces_left: list[str] = field(default_factory=list)

    @property
    def stop_kind(self) -> str:
        return result.PRODUCT_CONTROL if self.product else firing.kind_of(self.stop_ref)

    @property
    def gateway(self) -> dict[str, str]:
        """What each invocation carries for the agent's calls through the gateway; nothing without one."""
        return {"via": self.via, **({"ca": self.ca} if self.ca else {})} if self.via else {}


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


def deploy(c: Clients, r: Run, endpoint: str, clock: Clock, before: dict[str, dict] | None = None) -> None:
    """Make the run's stack. In a subnet, `before` is its network interfaces before the stack was made, so that those
    Lambda makes for the function are found after it (the_functions)."""
    n = names(r.run)
    c.cloudformation.create_stack(StackName=n["stack"],
                                  TemplateBody=template_body(r.run, endpoint, subnet=r.subnet,
                                                             security_groups=r.security_groups),
                                  Capabilities=["CAPABILITY_NAMED_IAM"], Tags=[{"Key": TAG, "Value": r.run}])
    found = _wait_for_stack(c.cloudformation, n["stack"], clock, "CREATE_COMPLETE")
    r.outputs = {o["OutputKey"]: o["OutputValue"] for o in (found or {}).get("Outputs", [])}
    if r.subnet:
        r.interfaces = sorted(the_functions(r, interfaces_in(c, r.subnet), before))


def interfaces_in(c: Clients, subnet: str) -> dict[str, dict]:
    """The network interfaces in a subnet, by their IDs. Only read: the kit changes nothing of the customer's."""
    found: dict[str, dict] = {}
    token = None
    while True:
        page = c.ec2.describe_network_interfaces(Filters=[{"Name": "subnet-id", "Values": [subnet]}],
                                                 **({"NextToken": token} if token else {}))
        found.update({i["NetworkInterfaceId"]: i for i in page.get("NetworkInterfaces", [])})
        token = page.get("NextToken")
        if not token:
            return found


def the_functions(r: Run, found: dict[str, dict], before: dict[str, dict] | None = None) -> set[str]:
    """Of the interfaces found, the test agent's: each whose description names the run's function (Lambda describes its
    interfaces by the function), and, where the subnet was read before the stack was made, each new since then with
    exactly the run's security groups."""
    function, groups = names(r.run)["function"], set(r.security_groups)
    return {i for i, ni in found.items() if function in (ni.get("Description") or "")
            or (before is not None and i not in before and {g["GroupId"] for g in ni.get("Groups", [])} == groups)}


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
LAMBDA_REFUSED = ("KMSAccessDeniedException", "KMSDisabledException", "KMSInvalidStateException",
                  "KMSNotFoundException", "ResourceNotFoundException")
NO_CONCURRENCY = "ReservedFunctionConcurrentInvocationLimitExceeded"
REFUSED = "Lambda refused: "          # the prefix of such a beat's error, so the page can say what it was


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
    body, _, _ = _invoke(c, r, {"action": "assume", **r.gateway}, clock)
    return body["session"]


def heartbeat(c: Clients, r: Run, n: int, session: dict,
              clock: Clock) -> tuple[dict[str, Beat], float, float, float | None]:
    """One heartbeat: each path's result, the kit's clock when it was asked and answered, and the agent's own clock.
    Where Lambda refused to run the agent, each path's beat is that refusal, at the kit's clock moved onto the agent's,
    and the agent's own clock is None: it did not run."""
    sent = clock.now()
    try:
        body, sent, received = _invoke(c, r, {"n": n, "session": session, **r.gateway}, clock)
    except Exception as e:
        code = refused_by_lambda(e)
        if code is None:
            raise
        received = clock.now()
        at = (sent + received) / 2 + r.offset
        return {p: Beat(at, False, REFUSED + code) for p in AWS_PATHS}, sent, received, None
    beats = {p: Beat(float(b["at"]), bool(b["ok"]), b.get("error")) for p, b in (body.get("beats") or {}).items()}
    r.calls += len(beats)
    return beats, sent, received, float(body["at"])


def warm_up(c: Clients, r: Run, session: dict, clock: Clock) -> None:
    """Heartbeats before any firing: which paths work, and how far apart the kit's clock and the agent's are. Through a
    gateway, a path works before the stop only where its last try in the warm-up worked: one failing as the customer
    fires their stop would otherwise read as stopped."""
    best = None
    last: dict[str, Beat] = {}
    for i in range(WARM_UP):
        beats, sent, received, agent_at = heartbeat(c, r, -1 - i, session, clock)
        r.working |= {p for p, b in beats.items() if b.ok}
        last.update(beats)
        for p, b in beats.items():
            if not b.ok:
                codes = r.setup_errors.setdefault(p, {})
                codes[b.error or "unknown"] = codes.get(b.error or "unknown", 0) + 1
        trip = received - sent
        if agent_at is not None and (best is None or trip < best[0]):
            best = (trip, agent_at - (sent + received) / 2)
        clock.sleep(1.0)
    r.offset = best[1] if best else 0.0
    if r.via:
        r.working = {p for p in r.working if p in last and last[p].ok}


def _codes(r: Run, p: str) -> str:
    return ", ".join(f"{code} {k}" for code, k in sorted(r.setup_errors.get(p, {}).items())) or "no answer"


def time_one(c: Clients, r: Run, clock: Clock, watch_own_trigger: bool, n0: int,
             mark: Callable[[], object] | None = None, say: Callable[[str], None] = lambda _: None) -> Repeat:
    """One repeat: fire (or wait for the customer's own trigger, or their mark), then a heartbeat a second through the
    window and the hold. Through a gateway, the session for the other identity is taken through it, before the mark:
    where it cannot be, that path did not work before the stop."""
    rep = Repeat()
    session = assume_or_none(c, r, clock) if r.via else assume(c, r, clock)
    if session is None:
        if "another_identity" in r.working:
            r.working.discard("another_identity")
            r.setup_errors.setdefault("another_identity", {})["NoSession"] = 1
            say(NOT_THROUGH_THE_GATEWAY.format(path=PATH_WORDS["another_identity"],
                                               codes=_codes(r, "another_identity")))
        session = {}
    rep.session_expires = session.get("expires")
    n = n0
    if mark is not None:
        mark()                          # the customer presses Enter, then fires their stop: timed from the Enter
        rep.fired_before = rep.fired_after = clock.now()
        say(MARKED)
    elif watch_own_trigger:
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
    n = names(r.run)
    if r.fired_by != "the kit":
        # the customer's own trigger made no attach call of the kit's: its moment is when the kit saw the change, or
        # through a gateway the customer's mark
        for rep in r.repeats:
            if rep.fired_after:
                rep.fired_at = rep.fired_after + r.offset
        return
    event_name = firing.KINDS[r.stop_kind]
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


def tear_down(c: Clients, r: Run, clock: Clock, eni_wait: float = ENI_WAIT,
              say: Callable[[str], None] = lambda _: None) -> None:
    """Remove the stop the kit fired and everything it made; name anything left (D532, K4). In a subnet of yours, wait
    for the function's network interfaces to be removed first (wait_for_interfaces)."""
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
    gone, left = wait_for_interfaces(c, r, clock, eni_wait, say) if r.subnet else ([], [])
    r.left_behind, r.checked_gone = check_gone(c, r)
    r.left_behind += left
    r.checked_gone += gone


def _code(e: Exception) -> str:
    return str(getattr(e, "response", {}).get("Error", {}).get("Code") or type(e).__name__)


def wait_for_interfaces(c: Clients, r: Run, clock: Clock, wait: float = ENI_WAIT,
                        say: Callable[[str], None] = lambda _: None) -> tuple[list[str], list[str]]:
    """The function's network interfaces in your subnet, waited for: AWS removes them some time after the function is
    deleted, so one still there is waited for, up to `wait` seconds, asked every ENI_POLL, and the kit says why it
    waits. Only then is one still there named as left. Returns what is gone and what is left. Where the function is
    still there, so are its interfaces: they are named as left at once. Ctrl-C ends the wait early."""
    function = names(r.run)["function"]
    try:
        ids = set(r.interfaces) | the_functions(r, interfaces_in(c, r.subnet))
    except Exception as e:  # noqa: BLE001 - named, unchecked
        return [], [INTERFACES_UNCHECKED.format(subnet=r.subnet, code=_code(e))]
    r.interfaces, present = sorted(ids), set(ids)
    if ids and _gone(lambda: c.lambda_.get_function(FunctionName=function)) is True:
        end, said = clock.now() + wait, False
        try:
            while True:
                present &= set(interfaces_in(c, r.subnet))
                if not present or clock.now() >= end:
                    break
                if not said:
                    say(WAITING_FOR_INTERFACES.format(minutes=int(wait // 60), count=len(present), subnet=r.subnet))
                    said = True
                clock.sleep(ENI_POLL)
        except KeyboardInterrupt:
            say(WAIT_STOPPED)
        except Exception as e:  # noqa: BLE001 - those not yet seen gone are named, unchecked
            r.interfaces_gone = sorted(ids - present)
            r.interfaces_left = sorted(present)
            return ([INTERFACE_GONE.format(id=i) for i in r.interfaces_gone],
                    [INTERFACE_LEFT.format(id=i, subnet=r.subnet) + f" (could not be checked: {_code(e)})"
                     for i in r.interfaces_left])
    r.interfaces_gone, r.interfaces_left = sorted(ids - present), sorted(present)
    return ([INTERFACE_GONE.format(id=i) for i in r.interfaces_gone],
            [INTERFACE_LEFT.format(id=i, subnet=r.subnet) for i in r.interfaces_left])


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
    found = judge(rep.beats.get(p, []), at, window=r.window, tried=p in r.working, setup_errors=r.setup_errors.get(p),
                  fired_precision=precision, untried=NOT_MEASURED if r.via else NOT_RUN)
    if found.outcome == NOT_MEASURED:
        found = replace(found, reason=NOT_MEASURED_REASON)
    keeps = rep.session_expires if p == "another_identity" and found.outcome == "not stopped" else None
    source = (FROM_THE_MARK if r.via else _source(precision)) if at is not None else None
    return replace(found, fired_source=source, keeps_working_until=keeps, fired_at=at)


def results(r: Run) -> list[tuple[float | None, dict[str, PathResult]]]:
    """Each repeat's paths, each judged from its own firing moment."""
    return [(rep.fired_at, {p: _one(r, rep, p) for p in AWS_PATHS}) for rep in r.repeats]


def _iso(t: float | None) -> str | None:
    if t is None:
        return None
    return datetime.fromtimestamp(t, tz=timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def details(r: Run, doc: dict) -> dict:
    """What the page shows, as a file beside the result: each path's time to effect as a range, its successes after its
    first refusal, a session's expiry and the errors seen, with what the teardown checked gone. It stays with the one
    who ran it; the result file is what may be submitted. Arvaken keeps its own runs' as its measurement (K9)."""
    repeats = []
    for rep, (_, found) in zip(r.repeats, results(r)):
        repeats.append({p: {
            "outcome": f.outcome, "fired_at": _iso(_moment(rep, p)[0]), "fired_source": f.fired_source,
            "effect_between_seconds": list(f.effect_between) if f.effect_between else None,
            "successes_after_first_refusal": f.successes_after_first_refusal,
            "first_refused": _iso(f.first_failure_after), "stopped_from": _iso(f.stopped_at),
            "last_success": _iso(f.last_success_after), "tries_after": f.tries_after, "failures_after": f.failures_after,
            "errors": f.errors, "reason": f.reason, "keeps_working_until": _iso(f.keeps_working_until)}
            for p, f in found.items()})
    # each repeat's refusals by Lambda to run the agent at all, by Lambda's code: every path counts each one
    refused = [dict(Counter(b.error.removeprefix(REFUSED) for b in rep.beats.get("own_calls", [])
                            if b.error and b.error.startswith(REFUSED))) for rep in r.repeats]
    out = {"format": "stop-test-details/1", "run": r.run, "result_signature": doc["signature"],
           "stop_kind": r.stop_kind, "window_seconds": r.window, "left_behind": r.left_behind,
           "checked_gone": r.checked_gone, "repeats": repeats, "lambda_refused": refused}
    if r.via:       # the gateway as the result keeps it: its scheme, host and port alone, and with no bundle
        out["gateway"] = {"via": result.gateway_address(r.via), "product": r.product}
    if r.subnet:
        out["network"] = network(r)
    return out


def network(r: Run) -> dict[str, Any]:
    """What a run made in your subnet, for its page: the function's network interfaces, and which were seen gone."""
    return {"subnet": r.subnet, "security_groups": list(r.security_groups), "interfaces": list(r.interfaces),
            "gone": list(r.interfaces_gone), "left": list(r.interfaces_left)}


def the_result(r: Run, key=None) -> dict:
    """The run's result, signed with a key made for it (result.py)."""
    doc = result.build(
        kit_version=__version__, cloud="aws", region=r.region,
        began_at=r.began_at, ended_at=r.ended_at, window=r.window, clock_gap_ms=int(round(abs(r.offset) * 1000)),
        calls=r.calls, left_behind=r.left_behind, stop_kind=r.stop_kind, fired_by=r.fired_by,
        stop_ref=r.stop_ref,
        agent={"kind": "aws-lambda-function", "runtime": RUNTIME, "memory_mb": MEMORY_MB,
               "private_network": bool(r.subnet),
               "ref": r.outputs.get("Agent", ""), "role_ref": r.outputs.get("AgentRole", "")},
        repeats=results(r), product=r.product, via=r.via or None)
    return result.sign(doc, key or result.new_key())


def _a_gateway(product: Any) -> bool:
    return isinstance(product, dict) and product.get("kind") == result.GATEWAY and \
        product.get("attachment") in result.PRODUCTS[result.GATEWAY] and \
        isinstance(product.get("name"), str) and 0 < len(product["name"]) <= result.NAME_LIMIT


def run(c: Clients, stop_ref: str, *, endpoint: str, fired_by: str = "the kit", window: float = WINDOWS["aws"],
        repeats: int = 1, clock: Clock | None = None, run_name: str | None = None,
        trail_wait: float = TRAIL_WAIT, say: Callable[[str], None] = lambda _: None, via: str = "", ca: str = "",
        product: dict[str, str] | None = None, subnet: str = "", security_groups: tuple[str, ...] | list[str] = (),
        mark: Callable[[], object] | None = None, eni_wait: float = ENI_WAIT) -> tuple[Run, dict]:
    """A whole run, torn down whatever happens. Returns the run's record and its signed result. `say` is told, as the
    run goes, of a path that did not work before the stop.

    Through a gateway: `via` is its address, `ca` the customer's certificate bundle (its text) for the calls through it
    alone, `product` the declared gateway ({"kind", "attachment", "name"}), and `mark` what waits for the customer's
    Enter. In a subnet of the customer's: `subnet`, with its `security_groups`; `eni_wait` bounds the teardown's wait
    for the function's network interfaces."""
    from arvaken_stop_test.aws.stack import new_run
    clock = clock or Clock()
    if fired_by not in result.FIRED_BY:
        raise ValueError(f"the stop is fired by one of {result.FIRED_BY}")
    if (product or ca) and not via:
        raise ValueError("a product's control, and a certificate bundle, go with a gateway's address (via)")
    if via:
        if fired_by != "your own trigger" or stop_ref:
            raise ValueError("through a gateway the stop is a product's control, fired by your own trigger")
        if not _a_gateway(product):
            raise ValueError("through a gateway the declared stop is a gateway, by its attachment and its name")
        if mark is None:
            raise ValueError("through a gateway each path is timed from your mark")
    if (subnet or security_groups) and not (via and subnet and security_groups):
        raise ValueError("a subnet of yours, with its security groups, is where your gateway is reached: with via")
    if fired_by == "the kit":
        reason = firing.why_not(stop_ref)
        if reason:
            raise firing.Refused(reason)            # before anything is made
    the_name = run_name or new_run()
    if fired_by == "the kit" and stop_ref not in (firing.REVOKE, firing.INLINE) \
            and not firing.covers(c.iam, stop_ref, the_name):
        raise firing.Refused(firing.NOT_COVERED)    # before anything is made
    reason = firing.why_no_boundary(c.iam, c.sts, network=bool(subnet))
    if reason:
        raise firing.Refused(reason)                # before anything is made
    if not 1 <= repeats <= 5:
        raise ValueError("a run repeats one to five times")
    if fired_by == "your own trigger" and repeats != 1:
        raise ValueError("with your own trigger a run fires once: only you can take your own stop off between repeats")
    before = interfaces_in(c, subnet) if subnet else None       # read, before anything is made
    r = Run(run=the_name, stop_ref=stop_ref, fired_by=fired_by, window=window, region=c.region, via=via, ca=ca,
            product=dict(product) if product else None, subnet=subnet, security_groups=list(security_groups))
    r.began_at = clock.now()
    try:
        deploy(c, r, endpoint, clock, before)
        first = assume_or_none(c, r, clock) if via else assume(c, r, clock)
        warm_up(c, r, first or {}, clock)
        for p in AWS_PATHS:
            if p not in r.working:
                say(NOT_THROUGH_THE_GATEWAY.format(path=PATH_WORDS[p], codes=_codes(r, p)) if via else
                    f"Before the stop, {PATH_WORDS[p]} did not work ({_codes(r, p)}): it will be reported as not run.")
        n = 0
        if via and not r.working:
            say(NOTHING_THROUGH_THE_GATEWAY)        # no mark is asked for: every path reads "not measured"
            r.repeats.append(Repeat())
        for i in range(repeats if not r.repeats else 0):
            if i:
                recover(c, r, clock)
            rep = time_one(c, r, clock, fired_by == "your own trigger", n, mark=mark if via else None, say=say)
            r.repeats.append(rep)
            n += sum(len(b) for b in rep.beats.values())
            if via:
                say(SWITCH_OFF)                     # the customer's switch may be stopping everything behind it
        firing_moments(c, r, clock, wait=trail_wait)
    finally:
        tear_down(c, r, clock, eni_wait=eni_wait, say=say)
        r.ended_at = clock.now()
    return r, the_result(r)
