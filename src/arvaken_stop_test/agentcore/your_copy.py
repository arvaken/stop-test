"""The stop test on a test copy of your own agent, as an AgentCore runtime of yours (D575; the founder's answer of 1
November 2026: "Lambda and AgentCore"). As aws/your_copy.py is for a Lambda function, with AgentCore's run (run.py).

**The copy is yours.** You deploy it with the probe (arvaken-stop-test-probe) in its entrypoint and name it by its
runtime's ARN, in the account and region the kit runs in. The kit never deploys, changes or deletes it, nor its
endpoints, its workload identity or its logs (run.tear_down, run.check_gone).

**What the kit makes:** the run's two roles and its bucket, as run.make makes them, and no code and no runtime. The role
the copy runs as for the test (KC1) trusts AgentCore alone, and only for your copy, by `aws:SourceAccount` and
`aws:SourceArn`, as the kit's own runtime's role trusts it for the run's runtime alone. You point the copy's runtime at
that role for the test and back afterwards; the kit checks the runtime runs as the role, and is ready, before anything is
timed. The kit deletes the role only once the copy no longer runs as it, and while it still does, leaves it and names it.

**What the kit fires:** a policy on the run's role alone (firing.ROLE_KIND). The deny kinds write a resource policy on
the runtime, and ending a session acts on it: on a copy, both would change what is yours, so the kit fires neither. Or,
for an in-agent SDK's switch (`sdk_name`), you fire it yourself from your mark, after the warning, and the kit fires
nothing: each path is judged by the founder's rule for it (sdk.py; D713), with the kit's witness calling from outside
the copy through the window and your SDK's own record of acting taken from your export afterwards, as on Lambda.

**Each call to the copy carries the run's settings** in the kit's marker (run.payload_of), as on Lambda. A new call is
the probe's "answer"; the running session, its "watch", which your entrypoint returns for AgentCore to stream.

Before anything is made, you confirm by typing the run's name that the copy is a test copy; before every firing, the
warning (KC4) and the run's name again. Until stop-test-result/3, a run on a copy writes no result.
"""
from __future__ import annotations

import re
import secrets
from collections.abc import Callable
from pathlib import Path
from typing import Any

from arvaken_stop_test.agentcore import fire as firing
from arvaken_stop_test.agentcore import run as running
from arvaken_stop_test.agentcore.run import Clients, Clock, NotStarted, Run
from arvaken_stop_test.agentcore.stack import (TAG, boundary_arn, names, own_policy, private_bucket, second_policy,
                                               second_trust, to_json)
from arvaken_stop_test.agentcore.agent import LONGEST
from arvaken_stop_test import result, sdk
from arvaken_stop_test.aws import fire as aws_fire
from arvaken_stop_test.aws.run import MARK_PROMPT
from arvaken_stop_test.aws.your_copy import (CONFIRM_COPY, NOT_CONFIRMED, NOT_FIRED, NOT_POINTED, SDK_MARKED,
                                             SDK_SWITCH_OFF, SDK_WINDOW_TOO_SHORT, STILL_RUNS_AS, WARNING, Witness,
                                             take_record)
from arvaken_stop_test.timing import GATEWAY_WINDOW, HOLD, NOT_RUN, WINDOWS, PathResult

# An AgentCore runtime's ARN: its partition, region, account and ID (its name and AgentCore's suffix).
RUNTIME_ARN = re.compile(r"arn:(aws(?:-[a-z]+)*):bedrock-agentcore:([a-z0-9-]+):(\d{12}):runtime/"
                         r"([A-Za-z][A-Za-z0-9_]{0,47}-[A-Za-z0-9]{10})")
SETTLE = 600.0          # seconds to wait for AgentCore to finish a change to the copy's runtime (run.MAKE_WAIT)

# CUSTOMER TEXT: a draft, for the founder's approval with D575's customer words (step 4)
NOT_A_RUNTIME = "a test copy on AgentCore is named by its runtime's ARN, in the account and region the kit runs in"
# CUSTOMER TEXT: a draft, for the founder's approval with D575's customer words (step 4)
ROLE_ONLY = ("On a copy of yours, the kit fires only a policy on the role it makes for the run: a deny of calls, and "
             "ending a session, would change your runtime.")
# CUSTOMER TEXT: a draft, for the founder's approval with D575's customer words (step 4)
POINT_AT = ("Point your copy's runtime {copy} at the run's role for the test: set its role to {role}, keeping the rest "
            "of its configuration as it is (AgentCore's console, or update-agent-runtime). Then press Enter.")
# CUSTOMER TEXT: a draft, for the founder's approval with D575's customer words (step 4)
POINT_BACK = ("Point your copy's runtime {copy} back at its own role, {own}, keeping the rest of its configuration as "
              "it is. Then press Enter, and the kit removes what it made.")


def runtime_arn(copy: str, region: str, account: str) -> re.Match | None:
    """The copy's ARN, where it names a runtime in this account and region; else None."""
    found = RUNTIME_ARN.fullmatch(copy)
    return found if found and found.group(2) == region and found.group(3) == account else None


def trust(copy: str, account: str) -> dict[str, Any]:
    """The run's role trusts AgentCore alone, for your copy's runtime alone."""
    return {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "bedrock-agentcore.amazonaws.com"}, "Action": "sts:AssumeRole",
        "Condition": {"StringEquals": {"aws:SourceAccount": account}, "ArnLike": {"aws:SourceArn": copy}}}]}


def make(c: Clients, r: Run, clock: Clock) -> None:
    """The run's roles and bucket, as run.make makes them; no code and no runtime: the runtime is your copy."""
    n = names(r.run)
    tags = [{"Key": TAG, "Value": r.run}]
    boundary = boundary_arn(r.account, r.partition)
    r.outputs["AgentRole"] = c.iam.create_role(
        RoleName=n["agent_role"], AssumeRolePolicyDocument=to_json(trust(r.copy, r.account)),
        PermissionsBoundary=boundary, Tags=tags)["Role"]["Arn"]
    c.iam.put_role_policy(RoleName=n["agent_role"], PolicyName="own-calls",
                          PolicyDocument=to_json(own_policy(r.run, r.account, r.partition)))
    r.outputs["SecondRole"] = running._retrying(lambda: c.iam.create_role(
        RoleName=n["second_role"], AssumeRolePolicyDocument=to_json(second_trust(r.outputs["AgentRole"])),
        PermissionsBoundary=boundary, Tags=tags), {"MalformedPolicyDocument"}, clock)["Role"]["Arn"]
    c.iam.put_role_policy(RoleName=n["second_role"], PolicyName="another-identity",
                          PolicyDocument=to_json(second_policy(r.run, r.partition)))
    private_bucket(c.s3, n["bucket"], r.region, r.run)
    r.outputs["Bucket"] = n["bucket"]


def configuration(c: Clients, r: Run, clock: Clock, settle: float = SETTLE) -> dict[str, Any]:
    """The copy's runtime once AgentCore has finished any change to it, waited for up to `settle` seconds."""
    end = clock.now() + settle
    while True:
        found = c.control.get_agent_runtime(agentRuntimeId=r.outputs["RuntimeId"])
        if found.get("status") not in ("CREATING", "UPDATING") or clock.now() >= end:
            return found
        clock.sleep(5.0)


def on_the_runs_role(c: Clients, r: Run, clock: Clock, settle: float = SETTLE) -> bool:
    found = configuration(c, r, clock, settle)
    return str(found.get("roleArn", "")).endswith(f":role/{names(r.run)['agent_role']}") and \
        found.get("status") == "READY"


def keeps_the_role(c: Clients, r: Run, clock: Clock, wait: Callable[[str], object]) -> Callable[[], bool]:
    """Whether the teardown keeps the run's role: where the copy still runs as it, you are asked to point it back, and
    it is kept only where the copy runs as it still."""
    role = names(r.run)["agent_role"]

    def on_it(settle: float) -> bool:
        return str(configuration(c, r, clock, settle).get("roleArn", "")).endswith(f":role/{role}")

    def kept() -> bool:
        try:
            if not on_it(0.0):
                return False
            wait(POINT_BACK.format(copy=r.copy, own=r.copy_role))
            return on_it(SETTLE)
        except Exception:  # noqa: BLE001 - a copy the kit cannot read keeps the role: it is named for you to delete
            return True
    return kept


def run(c: Clients, copy: str, stop_ref: str, *, confirm: Callable[[str], str], wait: Callable[[str], object],
        window: float = WINDOWS["aws"], repeats: int = 1, clock: Clock | None = None, run_name: str | None = None,
        trail_wait: float = running.TRAIL_WAIT, say: Callable[[str], None] = lambda _: None, sdk_name: str = "",
        read: Callable[[str], bytes] = lambda where: Path(where).read_bytes(),
        witness_get: Callable[[str, dict], int] | None = None) -> Run:
    """A whole run on a copy of yours, torn down whatever happens. Returns the run's record. `confirm` shows its words
    and gives back what you typed; `wait` shows its words and waits for your Enter. With `sdk_name`, the stop is that
    in-agent SDK's switch, which you fire from your mark (`stop_ref` is then empty), judged by sdk_results."""
    from arvaken_stop_test.aws.stack import new_run
    clock = clock or Clock()
    caller = c.sts.get_caller_identity()
    found = runtime_arn(copy, c.region, caller["Account"])
    if not found:
        raise ValueError(NOT_A_RUNTIME)
    product = None
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
        product = {"kind": sdk.SDK, "attachment": sdk.ATTACHMENT, "name": sdk_name}
    else:
        if not firing.on_the_role(stop_ref):
            raise firing.Refused(ROLE_ONLY)         # before anything is made
        reason = firing.why_not(stop_ref)
        if reason:
            raise firing.Refused(reason)            # before anything is made
    if not 1 <= repeats <= 5:
        raise ValueError("a run repeats one to five times")
    if running.READY_WAIT + running.LEAD + window + HOLD + running.SLACK > LONGEST:
        # CUSTOMER TEXT: approved by the founder, 04:44 UTC on 28 October 2026 (D618); source: aws-agentcore-streaming-limit
        raise ValueError(f"a window on AgentCore is at most "
                         f"{int(LONGEST - running.READY_WAIT - running.LEAD - HOLD - running.SLACK)} seconds: the "
                         "running session is watched on one streaming response, which AWS keeps up to 60 minutes")
    the_name = run_name or new_run()
    if not product and stop_ref != firing.INLINE and not firing.covers(c.iam, stop_ref, the_name):
        raise firing.Refused(aws_fire.NOT_COVERED)  # before anything is made
    reason = aws_fire.why_no_boundary(c.iam, c.sts)
    if reason:
        raise firing.Refused(reason)                # before anything is made
    own = c.control.get_agent_runtime(agentRuntimeId=found.group(4))
    if confirm(CONFIRM_COPY.format(copy=copy, run=the_name)).strip() != the_name:
        raise firing.Refused(NOT_CONFIRMED)         # before anything is made
    r = Run(run=the_name, stop_ref=stop_ref, window=window, region=c.region, account=caller["Account"],
            partition=found.group(1), copy=copy, copy_role=str(own.get("roleArn", "")),
            outside_key=secrets.token_hex(16), product=product)
    r.outputs.update(Runtime=copy, RuntimeId=found.group(4))
    r.began_at = clock.now()
    try:
        make(c, r, clock)
        wait(POINT_AT.format(copy=copy, role=r.outputs["AgentRole"]))
        if not on_the_runs_role(c, r, clock):
            said = NOT_POINTED.format(copy=copy, role=r.outputs["AgentRole"])
            say(said)
            raise NotStarted(said, r)
        running.warm_up(c, r, clock)
        for i in range(repeats):
            if i:
                running.recover(c, r, clock)
            if confirm(WARNING).strip() != r.run:   # before every firing (KC4)
                say(NOT_FIRED)
                break
            if product:                             # you fire your SDK's switch from your mark; the witness calls
                r.repeats.append(running.time_one(c, r, clock, say=say, mark=lambda: wait(MARK_PROMPT),
                                                  marked=SDK_MARKED, each_second=Witness(c, r, clock, witness_get)))
            else:
                r.repeats.append(running.time_one(c, r, clock, say=say))
        if product:                                 # timed from your mark, or your SDK's own record (sdk_results)
            for rep in r.repeats:
                rep.fired_at = rep.fired_after + r.offset
            if r.repeats:
                say(SDK_SWITCH_OFF)
                take_record(r, confirm, read)
        else:
            running.firing_moments(c, r, clock, wait=trail_wait)
    finally:
        running.tear_down(c, r, clock, say=say, keeps_the_role=keeps_the_role(c, r, clock, wait))
        role = names(r.run)["agent_role"]
        r.left_behind = [STILL_RUNS_AS.format(role=role, copy=copy) if x == f"the role {role}" else x
                         for x in r.left_behind]
        r.ended_at = clock.now()
    return r


def sdk_results(r: Run) -> list[tuple[float | None, dict[str, PathResult]]]:
    """Each repeat's paths under D713 (sdk.judge), as aws/your_copy.sdk_results has them: the session's four paths and
    new calls to the copy, each working before the mark where its last try before it worked."""
    out = []
    for rep in r.repeats:
        if not rep.fired_after:
            out.append((None, {p: PathResult(NOT_RUN, r.window, reason="the stop was not fired")
                               for p in running.PATHS}))
            continue
        mark = rep.fired_after + r.offset
        fired, precision, source = sdk.firing_moment(r.sdk_record, mark, r.window)
        record_why = sdk.record_reason(r.sdk_record, mark, r.window)
        witness_why = sdk.witness_reason(r.witness, mark, fired + r.window)
        found = {}
        for p in running.PATHS:
            beats = rep.beats.get(p, [])
            before = [b for b in beats if b.at <= mark]
            found[p] = sdk.judge(beats, mark_at=mark, fired_at=fired, window=r.window,
                                 worked_before=p in rep.working and bool(before) and before[-1].ok,
                                 fired_precision=precision, record_why=record_why, witness_why=witness_why,
                                 fired_source=source, setup_errors=rep.setup_errors.get(p))
        out.append((fired, found))
    return out
