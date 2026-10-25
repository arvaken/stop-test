"""Firing the stop on AWS (the design's section 5; D532, K4).

"When the kit fires the stop, it applies only to the test agent's own identity, made for that run; if the declared stop
would reach any other identity, the kit refuses to fire it and says why. With the customer's own trigger, the kit warns
first that it may stop more than the test agent. At the end, the kit removes the stop it fired and everything it made,
and names anything left for the customer to delete." (D532) Widened by the founder on 23 October 2026 (17:22:51 UTC):
the kit fires only on identities made for that run, and still never on a customer's own.

On AWS a declared stop is a managed policy attached to an agent's role. The kit attaches it to the run's own role
alone, so it reaches that role and nothing else. Before it does, it checks:
- that the stop is a managed policy, by its ARN: anything else (an organization's service control policy, a
  permissions boundary, an inline policy) is a stop the kit cannot attach to one role, or one that reaches every
  identity it is set on, and is refused with why;
- that the role is the run's own: named with the run's prefix and tagged with the run.

**Revoking active sessions** is a second kind of stop: AWS's own policy for it (AWSRevokeOlderSessions, what the
console's "Revoke active sessions" writes on a role) denies every session issued before a moment. A session the agent
took for another role is that role's, so revoking the agent's role alone never reaches it: the kit revokes the
sessions of the agent's role and of the role it became, both made for the run.
"""
from __future__ import annotations

import re
import time
from collections.abc import Callable
from typing import Any

from datetime import datetime, timezone

from arvaken_stop_test.aws.stack import BOUNDARY, TAG, boundary_document, names

MANAGED_POLICY = re.compile(r"arn:aws(-[a-z]+)*:iam::(\d{12}|aws):policy/[\w+=,.@/-]{1,512}")
OWN_TRIGGER_WARNING = ("Your own trigger may stop more than the test agent. It runs as you made it, and the kit cannot "
                       "see what else it reaches. Type the run's name to go on.")


REVOKE = "revoke active sessions"                     # the second kind's declared stop, in place of a policy's ARN
REVOKE_POLICY = "AWSRevokeOlderSessions"
# The third kind (D538, M2): a policy written on the agent's role itself, denying every action, as a customer's stop
# written inline on a role would be. Its declared stop names it by the policy's name, as the record does (0122).
INLINE = "arvaken-stop-test-deny-all"
INLINE_KIND = "policy written on the role"
INLINE_DOCUMENT = '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'
KINDS = {"policy on a role": "AttachRolePolicy", REVOKE: "PutRolePolicy", INLINE_KIND: "PutRolePolicy"}


def kind_of(stop_ref: str) -> str:
    """Each kind, and the call CloudTrail records for it, in KINDS."""
    return REVOKE if stop_ref == REVOKE else INLINE_KIND if stop_ref == INLINE else "policy on a role"


class Refused(Exception):
    """The kit refuses to fire this stop. The message says why, in words for the person running it."""


def why_not(stop_ref: str) -> str | None:
    """Why the kit will not fire this declared stop, or None if it will."""
    if stop_ref in (REVOKE, INLINE):
        return None
    if re.fullmatch(r"p-[0-9a-z]{8,128}", stop_ref):
        return ("this is an organization's service control policy: it reaches every identity in the accounts it is "
                "attached to, so the kit cannot fire it on the test agent alone")
    if stop_ref.startswith("arn:") and ":policy/" not in stop_ref:
        return "this is not a policy's ARN: on AWS the kit fires a managed policy, attached to the test agent's role"
    if not MANAGED_POLICY.fullmatch(stop_ref):
        return ("this is not a managed policy's ARN: the kit fires a managed policy, attached to the test agent's role "
                "alone; an inline policy or a permissions boundary is not one it can attach that way")
    return None


# The founder, 24 October 2026: before a run with --stop, the kit checks that the stop denies what the test agent does.
# What it does, as its own calls, is write and read the run's bucket: a stop that denies neither tells nothing of itself.
NOT_COVERED = "Your stop doesn't deny what the test agent does, so this test can't tell you about your stop."
OWN_CALLS = ("s3:PutObject", "s3:GetObject")
ALLOW_ALL = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'


NO_BOUNDARY = (f"Your account has no policy {BOUNDARY}, the permissions boundary the kit puts on the roles it makes. "
               "Create it once from permissions/aws-boundary.json, as the README's \"The permissions it needs\" says.")
NOT_THE_BOUNDARY = (f"Your account's policy {BOUNDARY} is not the kit's permissions boundary: its default version "
                    "differs from permissions/aws-boundary.json.")


def why_no_boundary(iam: Any, sts: Any) -> str | None:
    """Why a run cannot make its roles under the kit's permissions boundary, or None: the policy must be in your
    account, and its default version must be the kit's, statement for statement."""
    import json
    caller = sts.get_caller_identity()
    arn = f"arn:{caller['Arn'].split(':')[1]}:iam::{caller['Account']}:policy/{BOUNDARY}"
    try:
        version = iam.get_policy(PolicyArn=arn)["Policy"]["DefaultVersionId"]
    except Exception as e:
        if str(getattr(e, "response", {}).get("Error", {}).get("Code")) == "NoSuchEntity":
            return NO_BOUNDARY
        raise
    document = iam.get_policy_version(PolicyArn=arn, VersionId=version)["PolicyVersion"]["Document"]
    document = json.loads(document) if isinstance(document, str) else document
    statements = lambda d: sorted(json.dumps(s, sort_keys=True) for s in d["Statement"])  # noqa: E731
    return None if statements(document) == statements(boundary_document()) else NOT_THE_BOUNDARY


def covers(iam: Any, stop_ref: str, run: str) -> bool:
    """Whether your managed policy denies the test agent's own calls: its default version, evaluated by IAM's policy
    simulator beside an allow of everything, for each of those calls on an object of the run's bucket. Only an explicit
    deny of each counts."""
    import json
    version = iam.get_policy(PolicyArn=stop_ref)["Policy"]["DefaultVersionId"]
    document = iam.get_policy_version(PolicyArn=stop_ref, VersionId=version)["PolicyVersion"]["Document"]
    document = document if isinstance(document, str) else json.dumps(document)
    bucket_object = f"arn:aws:s3:::{names(run)['stack']}-bucket/own/0"
    found = iam.simulate_custom_policy(PolicyInputList=[document, ALLOW_ALL], ActionNames=list(OWN_CALLS),
                                       ResourceArns=[bucket_object]).get("EvaluationResults", [])
    decided = {r["EvalActionName"]: r["EvalDecision"] for r in found}
    return all(decided.get(a) == "explicitDeny" for a in OWN_CALLS)


def the_runs_own_role(iam: Any, run: str, which: str = "agent_role") -> str:
    """The run's own role, checked to be its own by name and by tag; else Refused."""
    role = names(run)[which]
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
    if stop_ref == INLINE:
        iam.put_role_policy(RoleName=role, PolicyName=INLINE, PolicyDocument=INLINE_DOCUMENT)
    else:
        iam.attach_role_policy(RoleName=role, PolicyArn=stop_ref)
    return before, now()


def revoke_document(before: float) -> str:
    """AWS's policy that revokes every session issued before `before` (seconds since the epoch, by AWS's clock)."""
    moment = datetime.fromtimestamp(int(before), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return ('{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["*"],"Resource":["*"],'
            '"Condition":{"DateLessThan":{"aws:TokenIssueTime":"' + moment + '"}}}]}')


def revoke(iam: Any, run: str, before: float, now: Callable[[], float] = time.time) -> dict[str, tuple[float, float]]:
    """Revoke the sessions of the run's agent role and of its second role issued before `before`. Returns, for each
    role, the kit's clock just before its call and just after it returned."""
    roles = {which: the_runs_own_role(iam, run, which) for which in ("agent_role", "second_role")}
    done = {}
    for which, role in roles.items():
        start = now()
        iam.put_role_policy(RoleName=role, PolicyName=REVOKE_POLICY, PolicyDocument=revoke_document(before))
        done[which] = (start, now())
    return done


def remove(iam: Any, run: str, stop_ref: str) -> bool:
    """Take off the stop the kit fired, where it still is. Returns whether it was there."""
    if stop_ref == REVOKE:
        found = False
        for which in ("agent_role", "second_role"):
            role = names(run)[which]
            if REVOKE_POLICY in iam.list_role_policies(RoleName=role).get("PolicyNames", []):
                iam.delete_role_policy(RoleName=role, PolicyName=REVOKE_POLICY)
                found = True
        return found
    role = names(run)["agent_role"]
    if stop_ref == INLINE:
        if INLINE in iam.list_role_policies(RoleName=role).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role, PolicyName=INLINE)
            return True
        return False
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
