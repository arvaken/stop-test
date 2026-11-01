"""The stop test on a test copy of your own agent, as a Lambda function of yours (D575; mark's
docs/platform/STOP-TEST-YOUR-OWN-AGENT-DESIGN.md, sections 1 to 4). AWS first, as its section 7 orders it.

**The copy is yours.** You deploy it, with the probe (arvaken-stop-test-probe) in it, and name it by its function's
ARN, in the account and region the kit runs in, without a version or an alias: a role change reaches only the
function's unpublished version. The kit never deploys, changes or deletes it, nor its logs.

**What the kit makes** is run.py's stack without the function (stack.template, `copy`): the bucket, the second role,
and the role the copy runs as for the test (KC1), named and permitted as the kit's own test agent's role, under the
kit's boundary. A copy in a VPC of yours gets the network actions Lambda needs for its interfaces, under the boundary a
run in a subnet has. You point the copy at that role for the test, with the command the kit prints, and back afterwards;
the kit checks it runs as the role before anything is timed. CloudFormation keeps the role when the stack is deleted:
the kit deletes it itself once the copy no longer runs as it, and while it still does, leaves it and names it.

**Each invocation carries the run's settings** in the kit's marker (run._invoke): the copy's environment is yours, so
the kit cannot set them there (the founder's answer, 1 November 2026: "Carry them"). The probe takes only settings
named for the run.

**Firing.** The kit fires a cloud stop itself, only on the role made for the run, as its own runs do (fire.py), and only
after the warning before every firing (KC4) and your typing the run's name. Or, for an in-agent SDK's switch (`sdk`,
its name), you fire it yourself from your mark ("Press Enter, then fire your stop."), after the same warning, and the
kit fires nothing: each path is judged by the founder's rule for it (sdk.py; D713), with the kit's witness (Witness)
calling from outside the copy through the window, and the SDK's own record of acting taken from your export afterwards.

**Before anything is made**, you confirm by typing the run's name that the copy is a test copy, not an agent whose
work matters (the terms, 2.1).

What the run keeps of the copy for its result (stop-test-result/3, the design's section 5, which waits for the kit's
terms v5): its ARN, sealed when submitted, and which clients the probe used, by kind (Run.clients). Until then, a run on
a copy writes no result.
"""
from __future__ import annotations

import re
import secrets
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

from arvaken_stop_test import result, sdk
from arvaken_stop_test.aws import fire as firing
from arvaken_stop_test.aws import run as running
from arvaken_stop_test.aws.run import Clients, Clock, NotStarted, Run
from arvaken_stop_test.aws.stack import TAG, is_model_id, names, template_body
from arvaken_stop_test.timing import GATEWAY_WINDOW, NOT_RUN, WINDOWS, PathResult

# A Lambda function's ARN, unqualified: its partition, region, account and name.
FUNCTION_ARN = re.compile(r"arn:(aws(?:-[a-z]+)*):lambda:([a-z0-9-]+):(\d{12}):function:([A-Za-z0-9_-]{1,64})")
SETTLE = 60.0           # seconds to wait for Lambda to finish a change to the copy's configuration

# The warning before every firing, as the founder approved it (D575, KC4: "the warning's words before every firing as
# drafted").
# CUSTOMER TEXT: approved by the founder as drafted, 15:58:47 UTC on 25 October 2026 (D575, KC4)
WARNING = ("Your stop may reach more than this test agent. An SDK's switch can stop every agent that uses the same "
           "account or key; host software can stop everything on the host. Type the run's name to fire it.")
# CUSTOMER TEXT: a draft, for the founder's approval with D575's customer words (step 4)
NOT_A_FUNCTION = ("a test copy is named by its Lambda function's ARN, in the account and region the kit runs in, "
                  "without a version or an alias")
# CUSTOMER TEXT: a draft, for the founder's approval with D575's customer words (step 4)
CONFIRM_COPY = ("The kit will call {copy} once a second, and fire your stop on the role it makes for the run. Run it "
                "only on a test copy, never on an agent whose work matters. Type the run's name, {run}, to confirm "
                "{copy} is a test copy.")
# CUSTOMER TEXT: a draft, for the founder's approval with D575's customer words (step 4)
NOT_CONFIRMED = "The run's name was not typed, so nothing was made."
# CUSTOMER TEXT: a draft, for the founder's approval with D575's customer words (step 4)
POINT_AT = ("Point your copy at the run's role for the test:\n"
            "  aws lambda update-function-configuration --region {region} --function-name {copy} --role {role}\n"
            "Then press Enter.")
# CUSTOMER TEXT: a draft, for the founder's approval with D575's customer words (step 4)
NOT_POINTED = ("Your copy {copy} does not run as the run's role {role}, so nothing was timed. The kit is removing what "
               "it made.")
# CUSTOMER TEXT: a draft, for the founder's approval with D575's customer words (step 4)
NOTHING_WORKED = "No path worked on your copy before the stop, so nothing was timed. The kit is removing what it made."
# CUSTOMER TEXT: a draft, for the founder's approval with D575's customer words (step 4)
NOT_FIRED = "The run's name was not typed, so the stop was not fired. The kit is removing what it made."
# CUSTOMER TEXT: a draft, for the founder's approval with D575's customer words (step 4)
POINT_BACK = ("Point your copy back at its own role:\n"
              "  aws lambda update-function-configuration --region {region} --function-name {copy} --role {own}\n"
              "Then press Enter, and the kit removes what it made.")
# CUSTOMER TEXT: a draft, for the founder's approval with D575's customer words (step 4)
STILL_RUNS_AS = "the role {role}, which your copy {copy} still runs as (point it back, then delete the role)"

# An in-agent SDK's stop (sdk.py; D713). The mark's own words are the gateway's, approved (run.MARK_PROMPT).
ENDPOINT = "https://stop-test.arvaken.com"   # Arvaken's test endpoint, as the probe calls it (the probe's core.ENDPOINT)
WITNESS_AGENT = "arvaken-stop-test-witness (+https://github.com/arvaken/stop-test)"
# CUSTOMER TEXT: a draft, for the founder's approval with D713's build
SDK_MARKED = ("Marked. Each path is timed from your SDK's own record of acting, where it gives the second, else from "
              "your mark, so a time errs toward slower, never faster.")
# CUSTOMER TEXT: a draft, for the founder's approval with D713's build
SDK_SWITCH_OFF = "The timing is done: you can turn your SDK's switch off now. The kit never turns it off itself."
# CUSTOMER TEXT: a draft, for the founder's approval with D713's build
SDK_EXPORT = ("Name the file you exported from your SDK that records it acting. The kit reads it only to take its "
              "SHA-256, and keeps that, never the file:")
# CUSTOMER TEXT: a draft, for the founder's approval with D713's build
SDK_ENTRY_TIME = "The time of the entry in it that records your stop, exactly as the file writes it, in UTC:"
# CUSTOMER TEXT: a draft, for the founder's approval with D713's build
SDK_ENTRY_NAME = "That entry's name, exactly as the file writes it:"
# CUSTOMER TEXT: a draft, for the founder's approval with D713's build
SDK_WINDOW_TOO_SHORT = "For your SDK's stop the kit times each path for at least 15 minutes after your mark."
# CUSTOMER TEXT: a draft, for the founder's approval with D713's build
SDK_NO_MODEL = "With your SDK's stop the kit's witness cannot vouch for a call to a model, so it times none."


class Witness:
    """The kit's witness (D713, (3)): once a second from the mark, the kit's own calls, made from where the kit runs and
    so outside the copy and its SDK: the run's bucket (HeadBucket, as the kit's own credentials) and Arvaken's test
    endpoint, with no key. Each second is kept by when, on the agent's clock, whether both worked, and the first error's
    code (never a message)."""

    def __init__(self, c: Clients, r: Run, clock: Clock, get: Callable[[str, dict], int] | None = None):
        self.c, self.r, self.clock, self.get = c, r, clock, get or _get

    def __call__(self) -> None:
        at, found = self.clock.now() + self.r.offset, None
        try:
            self.c.s3.head_bucket(Bucket=self.r.outputs["Bucket"])
        except Exception as e:  # noqa: BLE001 - the witness's error, by its code
            found = running._code(e)
        if found is None:
            try:
                status = self.get(f"{ENDPOINT}/open", {"User-Agent": WITNESS_AGENT})
                found = f"HTTP{status}" if status >= 400 else None
            except urllib.error.HTTPError as e:
                found = f"HTTP{e.code}"
            except Exception as e:  # noqa: BLE001 - by its type alone
                found = type(e).__name__[:64]
        self.r.witness.append((at, found is None, found))


def _get(url: str, headers: dict) -> int:
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers, method="GET"), timeout=2.0) as response:
        response.read(64)
        return response.status


def take_record(r: Run, ask: Callable[[str], str], read: Callable[[str], bytes]) -> None:
    """The SDK's own record that it acted (D713, (2)), from your export: the file you name, read only for its SHA-256,
    and the entry's time and name as you type them. A file the kit cannot read is no record."""
    where = ask(SDK_EXPORT).strip()
    if not where:
        return
    try:
        export = read(where)
    except Exception:  # noqa: BLE001 - no record: the paths read not measured, and say so
        return
    r.sdk_record = sdk.record(export, ask(SDK_ENTRY_TIME), ask(SDK_ENTRY_NAME))


def sdk_results(r: Run) -> list[tuple[float | None, dict[str, PathResult]]]:
    """Each repeat's paths under D713 (sdk.judge): the firing moment from the SDK's record where it gives the second,
    else the mark; the record and the witness as (2) and (3) have them."""
    out = []
    for rep in r.repeats:
        if not rep.fired_after:
            out.append((None, {p: PathResult(NOT_RUN, r.window, reason="the stop was not fired") for p in r.paths}))
            continue
        mark = rep.fired_after + r.offset
        fired, precision, source = sdk.firing_moment(r.sdk_record, mark, r.window)
        record_why = sdk.record_reason(r.sdk_record, mark, r.window)
        witness_why = sdk.witness_reason(r.witness, mark, fired + r.window)
        found = {}
        for p in r.paths:
            beats = rep.beats.get(p, [])
            before = [b for b in beats if b.at <= mark]
            found[p] = sdk.judge(beats, mark_at=mark, fired_at=fired, window=r.window,
                                 worked_before=p in r.working and bool(before) and before[-1].ok,
                                 fired_precision=precision, record_why=record_why, witness_why=witness_why,
                                 fired_source=source, setup_errors=r.setup_errors.get(p))
        out.append((fired, found))
    return out


def function_arn(copy: str, region: str, account: str) -> re.Match | None:
    """The copy's ARN, where it names a function in this account and region, unqualified; else None."""
    found = FUNCTION_ARN.fullmatch(copy)
    return found if found and found.group(2) == region and found.group(3) == account else None


def configuration(c: Clients, r: Run, clock: Clock, settle: float = SETTLE) -> dict[str, Any]:
    """The copy's configuration once Lambda has finished any change to it, waited for up to `settle` seconds."""
    end = clock.now() + settle
    while True:
        found = c.lambda_.get_function_configuration(FunctionName=r.copy)
        if found.get("LastUpdateStatus") != "InProgress" or clock.now() >= end:
            return found
        clock.sleep(2.0)


def runs_as(c: Clients, r: Run, role_arn: str, clock: Clock, settle: float = SETTLE) -> bool:
    return configuration(c, r, clock, settle).get("Role") == role_arn


def deploy(c: Clients, r: Run, clock: Clock, network: bool) -> None:
    """The run's stack for a copy: no function; the role the copy runs as, kept when the stack is deleted."""
    n = names(r.run)
    c.cloudformation.create_stack(StackName=n["stack"],
                                  TemplateBody=template_body(r.run, "", model=r.model, copy=True, network=network),
                                  Capabilities=["CAPABILITY_NAMED_IAM"], Tags=[{"Key": TAG, "Value": r.run}])
    found = running._wait_for_stack(c.cloudformation, n["stack"], clock, "CREATE_COMPLETE")
    r.outputs = {o["OutputKey"]: o["OutputValue"] for o in (found or {}).get("Outputs", [])}


def remove_the_runs_role(c: Clients, r: Run, clock: Clock, wait: Callable[[str], object]) -> Callable[[], None]:
    """What the teardown does once the stack is deleted: where the copy still runs as the run's role, ask you to point it
    back and check again; then delete the role, its own policies first, only where the copy no longer runs as it. The
    role is known by its name, so one CloudFormation kept from a stack that never finished is removed too."""
    role = names(r.run)["agent_role"]

    def on_it(settle: float) -> bool:
        return str(configuration(c, r, clock, settle).get("Role", "")).endswith(f":role/{role}")

    def after_stack() -> None:
        try:
            if on_it(0.0):
                wait(POINT_BACK.format(region=c.region, copy=r.copy, own=r.copy_role))
                if on_it(SETTLE):
                    return                      # left, and named by what the teardown checks
            for name in c.iam.list_role_policies(RoleName=role).get("PolicyNames", []):
                c.iam.delete_role_policy(RoleName=role, PolicyName=name)
            for a in c.iam.list_attached_role_policies(RoleName=role).get("AttachedPolicies", []):
                c.iam.detach_role_policy(RoleName=role, PolicyArn=a["PolicyArn"])
            c.iam.delete_role(RoleName=role)
        except Exception:  # noqa: BLE001 - a role not deleted is named by what the teardown checks
            pass
    return after_stack


def run(c: Clients, copy: str, stop_ref: str, *, confirm: Callable[[str], str], wait: Callable[[str], object],
        window: float = WINDOWS["aws"], repeats: int = 1, clock: Clock | None = None, run_name: str | None = None,
        trail_wait: float = running.TRAIL_WAIT, say: Callable[[str], None] = lambda _: None, model: str = "",
        sdk_name: str = "", read: Callable[[str], bytes] = lambda where: Path(where).read_bytes(),
        witness_get: Callable[[str, dict], int] | None = None) -> Run:
    """A whole run on a copy of yours, torn down whatever happens. Returns the run's record. `confirm` shows its words
    and gives back what you typed; `wait` shows its words and waits for your Enter. The stop is the kit's to fire, on the
    run's role; with `model`, the probe also calls it, as a fifth path. With `sdk_name`, the stop is that in-agent SDK's
    switch, which you fire from your mark (`stop_ref` is then empty): the kit's witness calls through the window, your
    export is read with `read` afterwards, and the paths are judged by sdk_results."""
    from arvaken_stop_test.aws.stack import new_run
    clock = clock or Clock()
    account = c.sts.get_caller_identity()["Account"]
    if not function_arn(copy, c.region, account):
        raise ValueError(NOT_A_FUNCTION)
    if model and not is_model_id(model):
        raise ValueError("a model is named by a Bedrock model's ID or an inference profile's")
    if not 1 <= repeats <= 5:
        raise ValueError("a run repeats one to five times")
    product = None
    the_name = run_name or new_run()
    if sdk_name:
        if stop_ref:
            raise ValueError("with your SDK's stop the kit fires nothing: you fire it yourself, from your mark")
        if not 0 < len(sdk_name) <= result.NAME_LIMIT:
            raise ValueError(f"an SDK is named in 1 to {result.NAME_LIMIT} characters")
        if repeats != 1:
            raise ValueError("with your own trigger a run fires once: only you can take your own stop off between "
                             "repeats")
        if window < GATEWAY_WINDOW:
            raise ValueError(SDK_WINDOW_TOO_SHORT)
        if model:
            raise ValueError(SDK_NO_MODEL)
        product = {"kind": sdk.SDK, "attachment": sdk.ATTACHMENT, "name": sdk_name}
    else:
        reason = firing.why_not(stop_ref)
        if reason:
            raise firing.Refused(reason)            # before anything is made
        if stop_ref not in (firing.REVOKE, firing.INLINE) and not firing.covers(c.iam, stop_ref, the_name):
            raise firing.Refused(firing.NOT_COVERED)    # before anything is made
    own = c.lambda_.get_function_configuration(FunctionName=copy)
    network = bool((own.get("VpcConfig") or {}).get("SubnetIds"))
    reason = firing.why_no_boundary(c.iam, c.sts, network=network, model=bool(model))
    if reason:
        raise firing.Refused(reason)                # before anything is made
    if confirm(CONFIRM_COPY.format(copy=copy, run=the_name)).strip() != the_name:
        raise firing.Refused(NOT_CONFIRMED)         # before anything is made
    r = Run(run=the_name, stop_ref=stop_ref, fired_by="your own trigger" if product else "the kit", window=window,
            region=c.region, model=model, copy=copy, copy_role=str(own.get("Role", "")),
            outside_key=secrets.token_hex(16), product=product)
    r.began_at = clock.now()
    try:
        deploy(c, r, clock, network)
        wait(POINT_AT.format(region=c.region, copy=copy, role=r.outputs.get("AgentRole", "")))
        if not runs_as(c, r, r.outputs.get("AgentRole", ""), clock):
            said = NOT_POINTED.format(copy=copy, role=r.outputs.get("AgentRole", ""))
            say(said)
            raise NotStarted(said, r)
        warm_up(c, r, clock, say)
        n, before = 0, r.warm_beats
        for i in range(repeats):
            if i:
                before = running.recover(c, r, clock)
            if confirm(WARNING).strip() != r.run:   # before every firing (KC4)
                say(NOT_FIRED)
                break
            if product:                             # you fire your SDK's switch from your mark; the witness calls
                rep = running.time_one(c, r, clock, False, n, before, mark=lambda: wait(running.MARK_PROMPT),
                                       say=say, marked=SDK_MARKED, each_second=Witness(c, r, clock, witness_get))
            else:
                rep = running.time_one(c, r, clock, False, n, before, say=say)
            r.repeats.append(rep)
            n += sum(len(b) for b in rep.beats.values())
        if product and r.repeats:
            say(SDK_SWITCH_OFF)
        running.firing_moments(c, r, clock, wait=trail_wait)
        if product and r.repeats:
            take_record(r, confirm, read)
    finally:
        running.tear_down(c, r, clock, say=say, after_stack=remove_the_runs_role(c, r, clock, wait))
        role = names(r.run)["agent_role"]
        r.left_behind = [STILL_RUNS_AS.format(role=role, copy=copy) if x == f"the role {role}" else x
                         for x in r.left_behind]
        r.ended_at = clock.now()
    running.own_tokens(c, r)
    return r


def warm_up(c: Clients, r: Run, clock: Clock, say: Callable[[str], None]) -> None:
    """The kit's warm-up on the copy (run.warm_up): where no path worked, or the model's call did not, nothing is timed."""
    running.warm_up(c, r, running.assume_or_none(c, r, clock) or {}, clock)
    if r.model and running.MODEL not in r.working and r.working:
        said = running.MODEL_DID_NOT_WORK.format(model=r.model, codes=running._codes(r, running.MODEL),
                                                 region=c.region)
        say(said)
        raise NotStarted(said, r)
    if not r.working:
        say(NOTHING_WORKED)
        raise NotStarted(NOTHING_WORKED, r)
    for p in r.paths:
        if p not in r.working:
            say(running._did_not_work(r, p))
