"""Firing a stop on the AgentCore test agent: the three kinds, as Arvaken's record names them (arvaken/mark, 0169;
AGENTCORE-MEASUREMENT.md, section 3; D618).

- **A policy on the agent's role** (ROLE_KIND): a managed policy attached to the runtime's role, as AWSDenyAll is in
  Arvaken's measurement, or the kit's own policy written on it denying every action (`--inline-deny`), five repeats
  each, as M2 measured Lambda's (D538). The roles are named as the Lambda agent's, so this is aws/fire.py's firing,
  with its checks: a managed policy's ARN, fired on the run's own role alone, found by its name and its tag.
- **A deny of calls to the agent** (DENY_KIND): the runtime's resource policy (PutResourcePolicy), denying every
  principal ("*") all six of the calls that reach a runtime (INVOKE_ACTIONS, as Arvaken's job host reads them:
  arvaken/mark, agent_policy.py), with no condition, so the job host's rule reads it as denying every call. Removed by
  DeleteResourcePolicy.
- **That deny, and the running session ended** (DENY_AND_END_KIND): the same deny, then StopRuntimeSession on the
  session the kit opened before the stop. AWS: it "instantly terminates the specified session and stops any ongoing
  streaming responses" [source: aws-agentcore-stop-session-terminates].

The kit fires on the run's own runtime alone: before any resource policy is written, the runtime is checked to be the
run's by its name and its tag (the_runs_own_runtime), as a role is.

Each kind's declared stop (`stop.ref` in the result) is a name of the kit's for the stop it writes: a resource policy
has no name of its own.
"""
from __future__ import annotations

import json
import time
from collections.abc import Callable
from typing import Any

from arvaken_stop_test.agentcore.stack import TAG, names
from arvaken_stop_test.aws import fire as aws_fire

ROLE_KIND = "policy on an AgentCore agent's role"
DENY_KIND = "deny calls to an AgentCore agent"
DENY_AND_END_KIND = "deny calls to an AgentCore agent and end its sessions"
INLINE = aws_fire.INLINE                        # the kit's policy written on the agent's role, denying every action
DENY = "arvaken-stop-test-deny-calls"
DENY_AND_END = "arvaken-stop-test-deny-calls-and-end-sessions"
INVOKE_ACTIONS = ("bedrock-agentcore:InvokeAgentRuntime", "bedrock-agentcore:InvokeAgentRuntimeCommand",
                  "bedrock-agentcore:InvokeAgentRuntimeCommandShell", "bedrock-agentcore:InvokeAgentRuntimeForUser",
                  "bedrock-agentcore:InvokeAgentRuntimeWithWebSocketStream",
                  "bedrock-agentcore:InvokeAgentRuntimeWithWebSocketStreamForUser")
# The call CloudTrail records for each kind's firing, and for ending the session.
EVENTS = {"attached": "AttachRolePolicy", "inline": "PutRolePolicy", "deny": "PutResourcePolicy",
          "end": "StopRuntimeSession"}


class Refused(aws_fire.Refused):
    """The kit refuses to fire this stop. The message says why, in words for the person running it."""


def kind_of(stop_ref: str) -> str:
    return DENY_KIND if stop_ref == DENY else DENY_AND_END_KIND if stop_ref == DENY_AND_END else ROLE_KIND


def on_the_role(stop_ref: str) -> bool:
    return kind_of(stop_ref) == ROLE_KIND


def event_of(stop_ref: str) -> str:
    """The call CloudTrail records for this stop's firing."""
    return EVENTS["deny"] if not on_the_role(stop_ref) else EVENTS["inline" if stop_ref == INLINE else "attached"]


def why_not(stop_ref: str) -> str | None:
    """Why the kit will not fire this declared stop, or None if it will."""
    return None if stop_ref in (INLINE, DENY, DENY_AND_END) else aws_fire.why_not(stop_ref)


def covers(iam: Any, stop_ref: str, run: str) -> bool:
    """Whether your managed policy denies the test agent's own calls, as aws/fire.py asks it, on an object of this run's
    bucket."""
    version = iam.get_policy(PolicyArn=stop_ref)["Policy"]["DefaultVersionId"]
    document = iam.get_policy_version(PolicyArn=stop_ref, VersionId=version)["PolicyVersion"]["Document"]
    document = document if isinstance(document, str) else json.dumps(document)
    found = iam.simulate_custom_policy(PolicyInputList=[document, aws_fire.ALLOW_ALL],
                                       ActionNames=list(aws_fire.OWN_CALLS),
                                       ResourceArns=[f"arn:aws:s3:::{names(run)['bucket']}/own/0"]
                                       ).get("EvaluationResults", [])
    decided = {r["EvalActionName"]: r["EvalDecision"] for r in found}
    return all(decided.get(a) == "explicitDeny" for a in aws_fire.OWN_CALLS)


def deny_document(runtime_arn: str) -> str:
    """The runtime's resource policy: every principal denied every call that reaches it, with no condition."""
    return json.dumps({"Version": "2012-10-17", "Statement": [{
        "Sid": "ArvakenStopTestDenyCalls", "Effect": "Deny", "Principal": "*", "Action": list(INVOKE_ACTIONS),
        "Resource": runtime_arn}]}, separators=(",", ":"))


def the_runs_own_runtime(control: Any, run: str, runtime_arn: str) -> str:
    """The run's own runtime, checked to be its own by name and by tag; else Refused."""
    name = runtime_arn.rpartition(":runtime/")[2].rpartition("-")[0]
    tags = control.list_tags_for_resource(resourceArn=runtime_arn).get("tags", {})
    if name != names(run)["runtime"] or tags.get(TAG) != run:
        raise Refused(f"the runtime {runtime_arn} is not this run's own: it is not named for the run, or does not "
                      f"carry the tag {TAG}={run}")
    return runtime_arn


def fire(iam: Any, control: Any, run: str, stop_ref: str, runtime_arn: str,
         now: Callable[[], float] = time.time) -> tuple[float, float]:
    """Fire the stop: on the role, as aws/fire.py does; else the deny, on the run's own runtime. Returns the kit's clock
    just before the call and just after it returned."""
    reason = why_not(stop_ref)
    if reason:
        raise Refused(reason)
    if on_the_role(stop_ref):
        return aws_fire.fire(iam, run, stop_ref, now=now)
    arn = the_runs_own_runtime(control, run, runtime_arn)
    before = now()
    control.put_resource_policy(resourceArn=arn, policy=deny_document(arn))
    return before, now()


def end_session(data: Any, runtime_arn: str, session: str, now: Callable[[], float] = time.time) -> tuple[float, float]:
    """End the running session. Returns the kit's clock just before the call and just after it returned."""
    before = now()
    data.stop_runtime_session(agentRuntimeArn=runtime_arn, runtimeSessionId=session, qualifier="DEFAULT")
    return before, now()


def remove(iam: Any, control: Any, run: str, stop_ref: str, runtime_arn: str | None) -> bool:
    """Take off the stop the kit fired, where it still is. Returns whether it was there."""
    if on_the_role(stop_ref):
        return aws_fire.remove(iam, run, stop_ref)
    if not runtime_arn:
        return False
    try:
        control.delete_resource_policy(resourceArn=runtime_arn)
    except Exception as e:  # noqa: BLE001 - no resource policy, or no runtime, answers ResourceNotFoundException
        if str(getattr(e, "response", {}).get("Error", {}).get("Code")) == "ResourceNotFoundException":
            return False
        raise
    return True
