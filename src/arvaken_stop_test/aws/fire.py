"""Firing the stop on AWS (the design's section 5; D532, K4).

"When the kit fires the stop, it applies only to the test agent's own identity, made for that run; if the declared stop
would reach any other identity, the kit refuses to fire it and says why. With the customer's own trigger, the kit warns
first that it may stop more than the test agent. At the end, the kit removes the stop it fired and everything it made,
and names anything left for the customer to delete." (D532)

On AWS a declared stop is a managed policy attached to an agent's role. The kit attaches it to the run's own role
alone, so it reaches that role and nothing else. Before it does, it checks:
- that the stop is a managed policy, by its ARN: anything else (an organization's service control policy, a
  permissions boundary, an inline policy) is a stop the kit cannot attach to one role, or one that reaches every
  identity it is set on, and is refused with why;
- that the role is the run's own: named with the run's prefix and tagged with the run.
"""
from __future__ import annotations

import re
import time
from collections.abc import Callable
from typing import Any

from arvaken_stop_test.aws.stack import TAG, names

MANAGED_POLICY = re.compile(r"arn:aws(-[a-z]+)*:iam::(\d{12}|aws):policy/[\w+=,.@/-]{1,512}")
OWN_TRIGGER_WARNING = ("Your own trigger may stop more than the test agent. It runs as you made it, and the kit cannot "
                       "see what else it reaches. Type the run's name to go on.")


class Refused(Exception):
    """The kit refuses to fire this stop. The message says why, in words for the person running it."""


def why_not(stop_ref: str) -> str | None:
    """Why the kit will not fire this declared stop, or None if it will."""
    if re.fullmatch(r"p-[0-9a-z]{8,128}", stop_ref):
        return ("this is an organization's service control policy: it reaches every identity in the accounts it is "
                "attached to, so the kit cannot fire it on the test agent alone")
    if stop_ref.startswith("arn:") and ":policy/" not in stop_ref:
        return "this is not a policy's ARN: on AWS the kit fires a managed policy, attached to the test agent's role"
    if not MANAGED_POLICY.fullmatch(stop_ref):
        return ("this is not a managed policy's ARN: the kit fires a managed policy, attached to the test agent's role "
                "alone; an inline policy or a permissions boundary is not one it can attach that way")
    return None


def the_runs_own_role(iam: Any, run: str) -> str:
    """The run's own role, checked to be its own by name and by tag; else Refused."""
    role = names(run)["agent_role"]
    tags = {t["Key"]: t["Value"] for t in iam.list_role_tags(RoleName=role).get("Tags", [])}
    if tags.get(TAG) != run:
        raise Refused(f"the role {role} is not this run's own: it does not carry the tag {TAG}={run}")
    return role


def fire(iam: Any, run: str, stop_ref: str, now: Callable[[], float] = time.time) -> tuple[float, float]:
    """Attach the declared stop to the run's own role. Returns the kit's clock just before the call and just after it
    returned."""
    reason = why_not(stop_ref)
    if reason:
        raise Refused(reason)
    role = the_runs_own_role(iam, run)
    before = now()
    iam.attach_role_policy(RoleName=role, PolicyArn=stop_ref)
    return before, now()


def remove(iam: Any, run: str, stop_ref: str) -> bool:
    """Detach the stop the kit fired, if it is still attached. Returns whether it was."""
    role = names(run)["agent_role"]
    attached = {p["PolicyArn"] for p in iam.list_attached_role_policies(RoleName=role).get("AttachedPolicies", [])}
    if stop_ref in attached:
        iam.detach_role_policy(RoleName=role, PolicyArn=stop_ref)
        return True
    return False


def snapshot(iam: Any, lambda_: Any, run: str) -> tuple:
    """What the customer's own trigger could change on the test agent: its role's policies, and its function's state."""
    n = names(run)
    attached = sorted(p["PolicyArn"] for p in iam.list_attached_role_policies(RoleName=n["agent_role"])
                      .get("AttachedPolicies", []))
    inline = sorted(iam.list_role_policies(RoleName=n["agent_role"]).get("PolicyNames", []))
    try:
        function = lambda_.get_function(FunctionName=n["function"])
        state = (function["Configuration"].get("State"), function.get("Concurrency", {}).get("ReservedConcurrentExecutions"))
    except Exception as e:  # noqa: BLE001 - a function deleted or unreadable is a change too
        state = ("gone", type(e).__name__)
    return tuple(attached), tuple(inline), state


def watch(iam: Any, lambda_: Any, run: str, until: float, now: Callable[[], float] = time.time,
          sleep: Callable[[float], None] = time.sleep, every: float = 1.0) -> float | None:
    """With the customer's own trigger: the kit's clock when it first sees the test agent change, or None by `until`."""
    first = snapshot(iam, lambda_, run)
    while now() < until:
        sleep(every)
        if snapshot(iam, lambda_, run) != first:
            return now()
    return None
