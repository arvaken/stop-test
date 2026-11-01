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
after the warning before every firing (KC4) and your typing the run's name. A product's control, fired by your own
trigger from a mark, waits for the founder's rule on what counts as its refusal; this module fires none.

**Before anything is made**, you confirm by typing the run's name that the copy is a test copy, not an agent whose
work matters (the terms, 2.1).

What the run keeps of the copy for its result (stop-test-result/3, the design's section 5, which waits for the kit's
terms v5): its ARN, sealed when submitted, and which clients the probe used, by kind (Run.clients). Until then, a run on
a copy writes no result.
"""
from __future__ import annotations

import re
import secrets
from collections.abc import Callable
from typing import Any

from arvaken_stop_test.aws import fire as firing
from arvaken_stop_test.aws import run as running
from arvaken_stop_test.aws.run import Clients, Clock, NotStarted, Run
from arvaken_stop_test.aws.stack import TAG, is_model_id, names, template_body
from arvaken_stop_test.timing import WINDOWS

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
        trail_wait: float = running.TRAIL_WAIT, say: Callable[[str], None] = lambda _: None, model: str = "") -> Run:
    """A whole run on a copy of yours, torn down whatever happens. Returns the run's record. `confirm` shows its words
    and gives back what you typed; `wait` shows its words and waits for your Enter. The stop is the kit's to fire, on the
    run's role; with `model`, the probe also calls it, as a fifth path."""
    from arvaken_stop_test.aws.stack import new_run
    clock = clock or Clock()
    account = c.sts.get_caller_identity()["Account"]
    if not function_arn(copy, c.region, account):
        raise ValueError(NOT_A_FUNCTION)
    if model and not is_model_id(model):
        raise ValueError("a model is named by a Bedrock model's ID or an inference profile's")
    if not 1 <= repeats <= 5:
        raise ValueError("a run repeats one to five times")
    reason = firing.why_not(stop_ref)
    if reason:
        raise firing.Refused(reason)                # before anything is made
    the_name = run_name or new_run()
    if stop_ref not in (firing.REVOKE, firing.INLINE) and not firing.covers(c.iam, stop_ref, the_name):
        raise firing.Refused(firing.NOT_COVERED)    # before anything is made
    own = c.lambda_.get_function_configuration(FunctionName=copy)
    network = bool((own.get("VpcConfig") or {}).get("SubnetIds"))
    reason = firing.why_no_boundary(c.iam, c.sts, network=network, model=bool(model))
    if reason:
        raise firing.Refused(reason)                # before anything is made
    if confirm(CONFIRM_COPY.format(copy=copy, run=the_name)).strip() != the_name:
        raise firing.Refused(NOT_CONFIRMED)         # before anything is made
    r = Run(run=the_name, stop_ref=stop_ref, fired_by="the kit", window=window, region=c.region, model=model,
            copy=copy, copy_role=str(own.get("Role", "")), outside_key=secrets.token_hex(16))
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
            rep = running.time_one(c, r, clock, False, n, before, say=say)
            r.repeats.append(rep)
            n += sum(len(b) for b in rep.beats.values())
        running.firing_moments(c, r, clock, wait=trail_wait)
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
