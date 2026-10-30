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
(result.py; D595). Only the calls the declared attachment covers go through the gateway (Run.through,
result.GATEWAY_ROUTES); the others go directly, as the customer's agents' would, and are timed from the same mark. An
attachment that covers none of the run's calls is refused before anything is made, and so is a window under
timing.GATEWAY_WINDOW. Before the stop, each path whose calls go through the gateway must work through it: one whose
last try in the warm-up did not reads "not measured", never "stopped"; a path going directly that did not reads "not
run", as in any run. A path whose first heartbeat after the mark was already refused reads "not measured" too. Where no
path through the gateway works, there is nothing to time, and the kit asks for no mark.

**In a subnet of the customer's (`--subnet`, `--security-group`).** Lambda makes the function's network interfaces
there, which the kit finds after the stack is made: those in the subnet whose description names the run's function, and
any that appeared in it, with exactly the run's security groups, while the stack was made. AWS removes them some time
after the function is deleted, so the teardown waits for them, up to ENI_WAIT, saying why, before it names any as
left: an interface still there during that wait is waited for, not left. Ctrl-C ends the wait early; the interfaces
still there are then named as left. CloudFormation finishes deleting the function only once AWS has removed them, and
deletes the roles and the bucket after it, so where the stack was still being deleted when its own wait ended, the kit
waits for it again once the interfaces are gone, before it checks anything gone (D561's run r6e758a49).

**A call to a model (`--model`; the design's section 4, its optional fifth row).** A run given a model has a fifth
path, "model" (Run.paths): the agent's one call to it with each heartbeat, as its own role (agent.py). It is timed,
judged, written to the result and shown on the page and in the details as its own calls are, from the same firing
moment, and between repeats the kit waits for it to work again as well. Before the stop it must have worked: where it
did not in the warm-up (a model ID that is wrong, or a model not enabled in the account, answers AccessDeniedException
or ValidationException), the kit says so, times nothing, removes what it made and raises NotStarted, which carries the
run's record with anything left; it does not time the other paths without it. Through a gateway where no path worked,
the gateway is said instead, as before. The model's call counts a refusal by its code, as every path does
(refusals.py): a throttle (ThrottlingException) after the stop is not counted. A run without a model has the four
paths, exactly as before.

**What counts as the stop's refusal** is refusals.py's, by the kind of stop: for your own trigger, the kind CloudTrail's
record of your action shows (`identify`), or none, where the kit finds no such record, and then nothing counts. Each path
is judged from its heartbeats before the firing moment as well as after it: a refusal counts only on a path that
succeeded before it, and Lambda's KMSAccessDeniedException only where the agent ran before the stop and it first came
after. Through a gateway the refusal is the gateway's own (the founder's ruling, D655, 30 October 2026): its 403 to the
CONNECT, or its 407 where its address signs in, from a combination the parse was tested on (refusals.gateway_counts);
through an https:// gateway nothing counts yet (Run.counted_kind); and a try made with a client made after the mark is
set aside, never setting the result (new_connections_only).
"""
from __future__ import annotations

import json
import time
import urllib.parse
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any

from arvaken_stop_test import __version__, refusals, result
from arvaken_stop_test.aws import fire as firing
from arvaken_stop_test.aws.stack import MEMORY_MB, RUNTIME, TAG, is_model_id, names, template_body
from arvaken_stop_test.timing import (GATEWAY_WINDOW, HOLD, NOT_MEASURED, NOT_RUN, PATH_WORDS, REFUSED_AT_THE_MARK,
                                      WINDOWS, Beat, PathResult, judge)

AWS_PATHS = ("own_calls", "another_identity", "outside_key", "open_internet")
MODEL = "model"              # the optional fifth path, for a run given a model (timing.PATHS)
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
# CUSTOMER TEXT: approved by the founder, by 17:10:22 UTC on 28 October 2026 (his ten lines)
ALREADY_REFUSED_REASON = "it was already refused at your mark"
# CUSTOMER TEXT: approved by the founder, by 17:10:22 UTC on 28 October 2026 (his ten lines)
NOT_COVERED_BY_THE_ATTACHMENT = ("Your gateway, as you said it is attached ({attachment}), covers none of the test "
                                 "agent's calls in this run, so there is nothing of it to time.")
# CUSTOMER TEXT: approved by the founder, by 17:10:22 UTC on 28 October 2026 (his ten lines)
GATEWAY_WINDOW_TOO_SHORT = "Through your gateway the kit times each path for at least 15 minutes after your mark."
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
# What a run with a model says where the model's call did not work before the stop.
# CUSTOMER TEXT: approved by the founder, by 11:09:43 UTC on 29 October 2026 (D562, F4: his five model lines)
MODEL_DID_NOT_WORK = ("Before the stop, a call to the model {model} did not work ({codes}), so nothing was timed. "
                      "Check that your account can call it in {region}.")


class NotStarted(firing.Refused):
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
    cloudtrail_here: Any = None         # CloudTrail in the run's own region, where it is not `cloudtrail`'s


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
    lost: list[tuple[float, str]] = field(default_factory=list)     # heartbeats with no answer: sent, by the kit's clock
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
    model: str = ""                     # a model's ID or an inference profile's, for the fifth path; else none
    warm_beats: dict[str, list[Beat]] = field(default_factory=dict)     # the warm-up's heartbeats
    # each own call's heartbeat, by its time, and the access key ID of the credentials it used: kept for own_tokens
    # alone, and never written
    own_keys: dict[float, str] = field(default_factory=dict)
    # your own trigger: the kind of stop CloudTrail's record of your action shows, or None, and that record
    trigger_kind: str | None = None
    trigger_record: dict[str, str] | None = None

    @property
    def paths(self) -> tuple[str, ...]:
        """The run's paths: the four, and the model's call where the run was given a model."""
        return (*AWS_PATHS, MODEL) if self.model else AWS_PATHS

    @property
    def stop_kind(self) -> str:
        if self.product:
            return result.PRODUCT_CONTROL
        if self.fired_by == "your own trigger" and self.trigger_kind:
            return self.trigger_kind
        return firing.kind_of(self.stop_ref)

    @property
    def through(self) -> set[str]:
        """The paths whose calls go through the gateway: those its declared attachment covers; none without one."""
        if not (self.via and self.product):
            return set()
        return set(result.GATEWAY_ROUTES[self.product["attachment"]]) & set(self.paths)

    @property
    def gateway(self) -> dict[str, Any]:
        """What each invocation carries for the agent's calls through the gateway: its address, the bundle, and which
        paths' calls go through it; nothing without one."""
        return {"via": self.via, **({"ca": self.ca} if self.ca else {}), "through": sorted(self.through)} \
            if self.via else {}

    @property
    def counted_kind(self) -> str | None:
        """The kind of stop whose refusals count: the kit's own; for your own trigger, the one identified, or None; and
        through a gateway, a product's control, whose refusal is the gateway's own (refusals.gateway_counts), except
        through an https:// gateway, where nothing counts until a test shows the kit can read its refusal (D655, (c))."""
        if self.via:
            return None if self.via.lower().startswith("https://") else refusals.PRODUCT_CONTROL
        return self.trigger_kind if self.fired_by == "your own trigger" else firing.kind_of(self.stop_ref)

    @property
    def signed_in(self) -> bool:
        """Whether the gateway's address carries a user name and password, so its calls go through signed in."""
        return bool(self.via and urllib.parse.urlsplit(self.via).username)


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
                                                             security_groups=r.security_groups, model=r.model),
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


def unreached(e: Exception) -> str | None:
    """botocore's name for an Invoke that got no answer, the network having failed or timed out on the way there or back
    after botocore's retries (its ConnectionError and HTTPClientError: ConnectTimeoutError, ReadTimeoutError and
    EndpointConnectionError among them); else None. Read by class, so the kit needs no botocore to load this module."""
    if any(k.__module__ == "botocore.exceptions" and k.__name__ in ("ConnectionError", "HTTPClientError")
           for k in type(e).__mro__):
        return type(e).__name__
    return None


def _invoke(c: Clients, r: Run, payload: dict, clock: Clock) -> tuple[dict, float, float]:
    sent = clock.now()
    response = c.lambda_.invoke(FunctionName=names(r.run)["function"], Payload=json.dumps(payload).encode())
    body = json.loads(response["Payload"].read())
    return body, sent, clock.now()


def assume(c: Clients, r: Run, clock: Clock) -> dict:
    """The second role's session, taken by the agent (through a gateway, through it), and when it took it, by its
    clock: AssumeRole gives a session's expiry, not its issue time."""
    body, _, _ = _invoke(c, r, {"action": "assume", **r.gateway}, clock)
    return {**body["session"], "issued": float(body["at"])}


def heartbeat(c: Clients, r: Run, n: int, session: dict,
              clock: Clock) -> tuple[dict[str, Beat], float, float, float | None]:
    """One heartbeat: each path's result, the kit's clock when it was asked and answered, and the agent's own clock.
    Where Lambda refused to run the agent, each path's beat is that refusal, at the kit's clock moved onto the agent's,
    and the agent's own clock is None: it did not run. Where the Invoke got no answer (unreached), nothing of the
    agent's was seen: no path has a beat, the heartbeat is kept as lost, by its code, for the details, and the run goes
    on (the founder's answer of 30 October 2026, after Google's run r37f2ed13 ended on one)."""
    sent = clock.now()
    try:
        body, sent, received = _invoke(c, r, {"n": n, "session": session, **r.gateway}, clock)
    except Exception as e:
        code = refused_by_lambda(e)
        if code is None:
            lost = unreached(e)
            if lost is None:
                raise
            r.lost.append((sent, lost))
            return {}, sent, clock.now(), None
        received = clock.now()
        at = (sent + received) / 2 + r.offset
        response = getattr(e, "response", None) or {}
        status = response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return {p: Beat(at, False, REFUSED + code, status=status, reason=response.get("Reason"))
                for p in r.paths}, sent, received, None
    versions = tuple(str(v) for v in body["v"]) if isinstance(body.get("v"), list) else None
    beats = {p: _beat(p, b, session, versions) for p, b in (body.get("beats") or {}).items()}
    if body.get("key") and "own_calls" in beats:
        r.own_keys[beats["own_calls"].at] = str(body["key"])
    r.calls += len(beats)
    return beats, sent, received, float(body["at"])


def _beat(path: str, b: dict, session: dict, versions: tuple[str, ...] | None = None) -> Beat:
    """A path's heartbeat from the agent's reply, with its failure record, when its client was made and what the agent
    ran on; under another identity, with the times of the session it used."""
    timed = path == "another_identity" and bool(session)
    made = b.get("client_at")
    return Beat(float(b["at"]), bool(b["ok"]), b.get("error"), status=b.get("status"), reason=b.get("reason"),
                token_issued=session.get("issued") if timed else None,
                token_expires=session.get("expires") if timed else None,
                client_at=float(made) if made is not None else None, versions=versions)


def warm_up(c: Clients, r: Run, session: dict, clock: Clock) -> None:
    """Heartbeats before any firing: which paths work, and how far apart the kit's clock and the agent's are. Through a
    gateway, a path works before the stop only where its last try in the warm-up worked: one failing as the customer
    fires their stop would otherwise read as stopped."""
    best = None
    last: dict[str, Beat] = {}
    for i in range(WARM_UP):
        beats, sent, received, agent_at = heartbeat(c, r, -1 - i, session, clock)
        for p, b in beats.items():
            r.warm_beats.setdefault(p, []).append(b)
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


def _did_not_work(r: Run, p: str) -> str:
    """What the kit says of a path that did not work before the stop: through the gateway, that it will be not
    measured; else, as in any run, not run."""
    if p in r.through:
        return NOT_THROUGH_THE_GATEWAY.format(path=PATH_WORDS[p], codes=_codes(r, p))
    return f"Before the stop, {PATH_WORDS[p]} did not work ({_codes(r, p)}): it will be reported as not run."


def time_one(c: Clients, r: Run, clock: Clock, watch_own_trigger: bool, n0: int,
             before: dict[str, list[Beat]] | None = None, mark: Callable[[], object] | None = None,
             say: Callable[[str], None] = lambda _: None) -> Repeat:
    """One repeat: fire (or wait for the customer's own trigger, or their mark), then a heartbeat a second through the
    window and the hold. `before` is each path's heartbeats before the firing: the warm-up's, or those since the last
    stop was taken off. Through a gateway, the session for the other identity is taken through it, before the mark:
    where it cannot be, that path did not work before the stop."""
    rep = Repeat()
    for p, beats in (before or {}).items():
        rep.beats.setdefault(p, []).extend(beats)
    session = assume_or_none(c, r, clock) if r.via else assume(c, r, clock)
    if session is None:
        if "another_identity" in r.working:
            r.working.discard("another_identity")
            r.setup_errors.setdefault("another_identity", {})["NoSession"] = 1
            say(_did_not_work(r, "another_identity"))
        session = {}
    rep.session_expires = session.get("expires")
    n = n0
    if mark is not None:
        mark()                          # the customer presses Enter, then fires their stop: timed from the Enter
        rep.fired_before = rep.fired_after = clock.now()
        say(MARKED)
    elif watch_own_trigger:
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
    """Between repeats: remove the stop, then wait until the agent's own calls work again, and with a model its call to
    the model, also made as its own role. Returns each path's heartbeats meanwhile, which come before the next repeat's
    firing."""
    firing.remove(c.iam, r.run, r.stop_ref)
    session = assume_or_none(c, r, clock)
    end = clock.now() + RECOVERY
    good, seen = 0, {}
    own = [p for p in ("own_calls", MODEL) if p in r.paths]
    while clock.now() < end and good < 5:
        beats, _, _, _ = heartbeat(c, r, 0, session or {}, clock)
        for p, b in beats.items():
            seen.setdefault(p, []).append(b)
        good = good + 1 if all(beats.get(p) and beats[p].ok for p in own) else 0
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
    if r.fired_by != "the kit":
        # the customer's own trigger made no attach call of the kit's: its moment is when the kit saw the change, or
        # through a gateway the customer's mark
        for rep in r.repeats:
            if rep.fired_after:
                rep.fired_at = rep.fired_after + r.offset
        if not r.via:                       # through a gateway the stop is a product's control, never identified
            identify(c, r, clock, wait)
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


def _expiry(text: Any) -> float | None:
    """A credential's expiry as CloudTrail writes it in AssumeRole's response, in either of the forms it may take."""
    if not isinstance(text, str):
        return None
    for form in ("%b %d, %Y, %I:%M:%S %p", "%b %d, %Y %I:%M:%S %p"):
        try:
            return datetime.strptime(text, form).replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            pass
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def own_tokens(c: Clients, r: Run) -> None:
    """The times of the credentials the agent's own calls used (D646): Lambda gives the agent its role's credentials
    without their issue or expiry time, so the kit reads them from CloudTrail's record of the call that issued them, an
    AssumeRole of the agent's role, matched by the credentials' access key ID, which the agent hands back. It asks the
    run's own region and the region it reads IAM's calls in. Each own call's failure record then holds its credentials'
    times; where no record is found, they stay empty."""
    keys = set(r.own_keys.values())
    trails = [t for t in {id(x): x for x in (c.cloudtrail_here, c.cloudtrail) if x is not None}.values()]
    if not keys or not trails:
        return
    role = names(r.run)["agent_role"]
    start, end = r.began_at + r.offset - 60, r.ended_at + r.offset + 60
    found: dict[str, tuple[float, float | None]] = {}
    for trail in trails:
        token = None
        while True:
            try:
                page = trail.lookup_events(
                    LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": "AssumeRole"}],
                    StartTime=start, EndTime=end, **({"NextToken": token} if token else {}))
            except Exception:  # noqa: BLE001 - a history the kit cannot read leaves the times empty, never the result
                break
            for e in page.get("Events", []):
                detail = json.loads(e.get("CloudTrailEvent") or "{}")
                made = (detail.get("responseElements") or {}).get("credentials") or {}
                if made.get("accessKeyId") in keys and \
                        str((detail.get("requestParameters") or {}).get("roleArn", "")).endswith(f":role/{role}"):
                    found[made["accessKeyId"]] = (_seconds_of(e["EventTime"]), _expiry(made.get("expiration")))
            token = page.get("NextToken")
            if not token:
                break
    for rep in r.repeats:
        rep.beats["own_calls"] = [
            replace(b, token_issued=found[r.own_keys[b.at]][0], token_expires=found[r.own_keys[b.at]][1])
            if r.own_keys.get(b.at) in found else b for b in rep.beats.get("own_calls", [])]


def tear_down(c: Clients, r: Run, clock: Clock, eni_wait: float = ENI_WAIT,
              say: Callable[[str], None] = lambda _: None) -> None:
    """Remove the stop the kit fired and everything it made; name anything left (D532, K4). In a subnet of yours, wait
    for the function's network interfaces to be removed first (wait_for_interfaces), then, where the stack was still
    being deleted, for the stack again: CloudFormation deletes the rest only once those are gone."""
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
    deleted = False
    try:
        c.cloudformation.delete_stack(StackName=n["stack"])
        deleted = _stack_deleted(c, n["stack"], clock)
    except Exception:  # noqa: BLE001 - what the stack could not delete is named below as left
        pass
    gone, left = wait_for_interfaces(c, r, clock, eni_wait, say) if r.subnet else ([], [])
    if r.subnet and not deleted and not left:
        try:
            _stack_deleted(c, n["stack"], clock)
        except KeyboardInterrupt:
            pass                                # Ctrl-C ends this wait too: what is still there is named below
    r.left_behind, r.checked_gone = check_gone(c, r)
    r.left_behind += left
    r.checked_gone += gone


def _stack_deleted(c: Clients, stack: str, clock: Clock) -> bool:
    """Whether the stack's wait saw it deleted: False where it was still being deleted when the wait ended, or its
    delete failed."""
    try:
        _wait_for_stack(c.cloudformation, stack, clock, "DELETE_COMPLETE")
    except (RuntimeError, TimeoutError):
        return False
    return True


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


def new_connections_only(r: Run, rep: Repeat, p: str) -> list[Beat]:
    """Through a gateway, a path's tries made with a client made after the mark, as when Lambda gave the agent a new
    environment: "new connections only", which never set the path's result (D655, open tunnels 2; the founder's answer
    of 30 October 2026)."""
    at = _moment(rep, p)[0]
    if p not in r.through or at is None:
        return []
    return [b for b in rep.beats.get(p, []) if b.client_at is not None and b.client_at > at]


def _counts(r: Run, kind: str | None, p: str) -> Callable[[Beat, list[Beat]], bool]:
    if kind == refusals.PRODUCT_CONTROL:
        return lambda b, before: refusals.gateway_counts(p in r.through, r.signed_in, b)
    return lambda b, before: refusals.counts(kind, p, b, before)


def _one(r: Run, rep: Repeat, p: str) -> PathResult:
    at, precision = _moment(rep, p)
    kind = r.counted_kind
    fresh = {id(b) for b in new_connections_only(r, rep, p)}
    found = judge(rep.beats.get(p, []), at, window=r.window, tried=p in r.working, setup_errors=r.setup_errors.get(p),
                  fired_precision=precision, counts=_counts(r, kind, p),
                  untried=NOT_MEASURED if p in r.through else NOT_RUN, refused_at_mark=NOT_MEASURED if r.via else None,
                  set_aside=lambda b: id(b) in fresh)
    if r.via:
        if found.outcome == NOT_MEASURED and p not in r.working:
            found = replace(found, reason=NOT_MEASURED_REASON)
        elif found.outcome == NOT_MEASURED and found.reason == REFUSED_AT_THE_MARK:
            found = replace(found, reason=ALREADY_REFUSED_REASON)
    elif kind is None and found.outcome == NOT_MEASURED:
        found = replace(found, reason=NOT_IDENTIFIED)
    keeps = rep.session_expires if p == "another_identity" and found.outcome == "not stopped" else None
    source = (FROM_THE_MARK if r.via else _source(precision)) if at is not None else None
    return replace(found, fired_source=source, keeps_working_until=keeps, fired_at=at)


def results(r: Run) -> list[tuple[float | None, dict[str, PathResult]]]:
    """Each repeat's paths, each judged from its own firing moment."""
    return [(rep.fired_at, {p: _one(r, rep, p) for p in r.paths}) for rep in r.repeats]


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
            "keeps_working_until": _iso(f.keeps_working_until), "failures": result.failure_records(f),
            **({"client": client_mode(r, rep, p)} if p in r.through else {})}
            for p, f in found.items()})
    # each repeat's refusals by Lambda to run the agent at all, after the stop, by Lambda's code
    refused = []
    for rep in r.repeats:
        at = rep.fired_at if rep.fired_at is not None else float("inf")
        refused.append(dict(Counter(b.error.removeprefix(REFUSED) for b in rep.beats.get("own_calls", [])
                                    if b.error and b.error.startswith(REFUSED) and b.at > at)))
    own_trigger = r.fired_by == "your own trigger" and not r.via
    out = {"format": "stop-test-details/1", "run": r.run, "result_signature": doc["signature"],
           "stop_kind": r.stop_kind, "window_seconds": r.window, "left_behind": r.left_behind,
           "checked_gone": r.checked_gone, "repeats": repeats, "lambda_refused": refused,
           "heartbeats_lost": result.heartbeats_lost([(at + r.offset, code) for at, code in r.lost]),
           "trigger": {"kind": r.trigger_kind, "record": r.trigger_record} if own_trigger else None}
    if r.via:       # the gateway as the result keeps it: its scheme, host and port alone, and with no bundle
        out["gateway"] = {"via": result.gateway_address(r.via), "product": r.product}
    if r.subnet:
        out["network"] = network(r)
    if r.model:     # the model the fifth path called, as given
        out["model"] = r.model
    return out


def client_mode(r: Run, rep: Repeat, p: str) -> dict[str, Any]:
    """Which client a path through the gateway was timed with (D655, open tunnels 3): one kept from before the mark, its
    connection and tunnel reused, or None where no client was kept from before the mark (every try after it on a new
    client, or none made); and the tries made with a client made after the mark, "new connections only", shown beside it
    and never setting the result."""
    at = _moment(rep, p)[0]
    made = sorted({b.client_at for b in rep.beats.get(p, []) if b.client_at is not None and (at is None or
                                                                                          b.client_at <= at)})
    fresh = new_connections_only(r, rep, p)
    return {"mode": "kept from before the mark" if made else None, "made": [_iso(m) for m in made],
            "new_connections_only": {"tries": len(fresh), "failures": dict(Counter(b.error or "unknown"
                                                                                    for b in fresh if not b.ok))}}


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
        mark: Callable[[], object] | None = None, eni_wait: float = ENI_WAIT, model: str = "") -> tuple[Run, dict]:
    """A whole run, torn down whatever happens. Returns the run's record and its signed result. `say` is told, as the
    run goes, of a path that did not work before the stop. With `model` (a Bedrock model's ID or an inference
    profile's), the agent also calls it with each heartbeat, as a fifth path; where that call did not work before the
    stop, the run is torn down and NotStarted raised.

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
        if window < GATEWAY_WINDOW:
            raise ValueError(GATEWAY_WINDOW_TOO_SHORT)
        if not set(result.GATEWAY_ROUTES[product["attachment"]]) & {*AWS_PATHS, *([MODEL] if model else [])}:
            raise ValueError(NOT_COVERED_BY_THE_ATTACHMENT.format(attachment=product["attachment"]))
    if (subnet or security_groups) and not (via and subnet and security_groups):
        raise ValueError("a subnet of yours, with its security groups, is where your gateway is reached: with via")
    if model and not is_model_id(model):
        raise ValueError("a model is named by a Bedrock model's ID or an inference profile's")
    if fired_by == "the kit":
        reason = firing.why_not(stop_ref)
        if reason:
            raise firing.Refused(reason)            # before anything is made
    the_name = run_name or new_run()
    if fired_by == "the kit" and stop_ref not in (firing.REVOKE, firing.INLINE) \
            and not firing.covers(c.iam, stop_ref, the_name):
        raise firing.Refused(firing.NOT_COVERED)    # before anything is made
    reason = firing.why_no_boundary(c.iam, c.sts, network=bool(subnet), model=bool(model))
    if reason:
        raise firing.Refused(reason)                # before anything is made
    if not 1 <= repeats <= 5:
        raise ValueError("a run repeats one to five times")
    if fired_by == "your own trigger" and repeats != 1:
        raise ValueError("with your own trigger a run fires once: only you can take your own stop off between repeats")
    before = interfaces_in(c, subnet) if subnet else None       # read, before anything is made
    r = Run(run=the_name, stop_ref=stop_ref, fired_by=fired_by, window=window, region=c.region, via=via, ca=ca,
            product=dict(product) if product else None, subnet=subnet, security_groups=list(security_groups),
            model=model)
    r.began_at = clock.now()
    try:
        deploy(c, r, endpoint, clock, before)
        first = assume_or_none(c, r, clock) if via else assume(c, r, clock)
        warm_up(c, r, first or {}, clock)
        if model and MODEL not in r.working and (r.working or not via):
            said = MODEL_DID_NOT_WORK.format(model=model, codes=_codes(r, MODEL), region=c.region)
            say(said)
            raise NotStarted(said, r)               # torn down below; nothing was fired or asked for
        for p in r.paths:
            if p not in r.working:
                say(_did_not_work(r, p))
        n, before = 0, r.warm_beats
        if via and not r.working & r.through:
            say(NOTHING_THROUGH_THE_GATEWAY)        # no mark is asked for: every path reads "not measured"
            r.repeats.append(Repeat())
        for i in range(repeats if not r.repeats else 0):
            if i:
                before = recover(c, r, clock)
            rep = time_one(c, r, clock, fired_by == "your own trigger", n, before, mark=mark if via else None,
                           say=say)
            r.repeats.append(rep)
            n += sum(len(b) for b in rep.beats.values())
            if via:
                say(SWITCH_OFF)                     # the customer's switch may be stopping everything behind it
        firing_moments(c, r, clock, wait=trail_wait)
    finally:
        tear_down(c, r, clock, eni_wait=eni_wait, say=say)
        r.ended_at = clock.now()
    own_tokens(c, r)
    return r, the_result(r)
