"""Firing the stop on Google Cloud (the design's section 5; D532, K4; D518, G2).

The two kinds of stop D518 approved for Google Cloud, each fired on the run's own service account alone:

- **a deny policy on its identity:** a deny policy attached to the project, naming the test agent's account and no
  other principal. With `--deny-all` it denies what the agent's paths use (Cloud Storage and IAM, every permission of
  each); with `--stop <your deny policy's name>` the kit reads your declared deny policy and makes a copy of its denied
  permissions for the run, naming the test agent alone: your policy itself is never changed. A rule with a condition is
  refused, since a copy without it would stop more than yours does, and one with it is not yours to move.
- **disabling its service account:** the test agent's own account, disabled, and enabled again between repeats.

Both act only on identities made for the run (D532, K4; D536): the account is checked to be the run's by its name and
its description before anything is fired.
"""
from __future__ import annotations

import re
import time
from collections.abc import Callable

from arvaken_stop_test.google.api import Google, GoogleError
from arvaken_stop_test.google.stack import IAM, LABEL, names, quoted

DENY_KIND, DISABLE_KIND = "deny policy on its identity", "disable its service account"
DENY_ALL, DISABLE = "arvaken-stop-test-deny-all", "disable its service account"
DENIED = ["storage.googleapis.com/*.*", "iam.googleapis.com/*.*"]
# Cloud Audit Logs' method for each kind's call, as each service records it
METHODS = {DENY_KIND: "google.iam.v2.Policies.CreatePolicy", DISABLE_KIND: "google.iam.admin.v1.DisableServiceAccount"}
DENY_POLICY = re.compile(r"policies/cloudresourcemanager\.googleapis\.com%2F(projects|folders|organizations)%2F[^/]+"
                         r"/denypolicies/[a-z0-9-]{1,63}")
OWN_TRIGGER_WARNING = ("Your own trigger may stop more than the test agent: a deny policy or a disabled account of yours "
                       "reaches whatever it names. The kit cannot see what else it reaches. Type the run's name to go on.")
V2 = "https://iam.googleapis.com/v2"


class Refused(Exception):
    """The kit refuses to fire this stop. The message says why, in words for the person running it."""


def kind_of(stop_ref: str) -> str:
    return DISABLE_KIND if stop_ref == DISABLE else DENY_KIND


def why_not(stop_ref: str) -> str | None:
    if stop_ref in (DENY_ALL, DISABLE):
        return None
    if not DENY_POLICY.fullmatch(stop_ref):
        return ("this is not a deny policy's name: give it as policies/cloudresourcemanager.googleapis.com%2Fprojects%2F"
                "<project>/denypolicies/<id>, or use --deny-all or --disable-account")
    return None


def denied_permissions(g: Google, stop_ref: str) -> list[str]:
    """Your declared deny policy's denied permissions, read and copied; Refused where a rule has a condition."""
    policy = g.call("GET", f"{V2}/{stop_ref}")
    out: list[str] = []
    for rule in policy.get("rules") or []:
        deny = rule.get("denyRule") or {}
        if deny.get("denialCondition"):
            raise Refused("a rule of your deny policy has a condition: a copy without it would stop more than yours, "
                          "and the kit cannot carry your condition onto the test agent")
        out += [p for p in deny.get("deniedPermissions") or [] if p not in out]
    if not out:
        raise Refused("your deny policy denies no permission the kit can copy")
    return out


def the_runs_own_account(g: Google, run: str) -> str:
    email = names(run, g.project)["agent_account"]
    found = g.call("GET", f"{IAM}/projects/-/serviceAccounts/{email}")
    if f"{LABEL}={run}" not in (found.get("description") or ""):
        raise Refused(f"the account {email} is not this run's own: its description does not say {LABEL}={run}")
    return email


def _attachment(g: Google) -> str:
    return f"{V2}/policies/{quoted(f'cloudresourcemanager.googleapis.com/projects/{g.project}')}/denypolicies"


def fire(g: Google, run: str, stop_ref: str, permissions: list[str] | None = None,
         now: Callable[[], float] = time.time) -> tuple[float, float]:
    """Fire the stop on the run's own account. Returns the kit's clock just before the call and just after."""
    email = the_runs_own_account(g, run)
    if stop_ref == DISABLE:
        before = now()
        g.call("POST", f"{IAM}/projects/-/serviceAccounts/{email}:disable", {})
        return before, now()
    body = {"displayName": f"Arvaken stop test {run}", "rules": [{"denyRule": {
        "deniedPrincipals": [f"principal://iam.googleapis.com/projects/-/serviceAccounts/{email}"],
        "deniedPermissions": permissions or DENIED}}]}
    before = now()
    g.call("POST", f"{_attachment(g)}?policyId={names(run, g.project)['deny_policy']}", body)
    return before, now()


def remove(g: Google, run: str, stop_ref: str) -> None:
    """Take the stop the kit fired off again: the account enabled, or the run's deny policy deleted."""
    n = names(run, g.project)
    if stop_ref == DISABLE:
        g.call("POST", f"{IAM}/projects/-/serviceAccounts/{n['agent_account']}:enable", {})
        return
    try:
        g.call("DELETE", f"{_attachment(g)}/{n['deny_policy']}")
    except GoogleError as e:
        if e.status != 404:
            raise


def watch(g: Google, run: str, until: float, now: Callable[[], float] = time.time,
          sleep: Callable[[float], None] = time.sleep) -> float | None:
    """The customer's own trigger: when the kit first sees the test agent's account disabled, or a deny policy on the
    project naming it. None if neither is seen before `until`."""
    email = names(run, g.project)["agent_account"]
    principal = f"principal://iam.googleapis.com/projects/-/serviceAccounts/{email}"
    while now() < until:
        if g.call("GET", f"{IAM}/projects/-/serviceAccounts/{email}").get("disabled"):
            return now()
        for listed in g.call("GET", _attachment(g)).get("policies") or []:
            policy = g.call("GET", f"{V2}/{listed['name']}") if "rules" not in listed else listed
            if any(principal in ((r.get("denyRule") or {}).get("deniedPrincipals") or []) for r in policy.get("rules") or []):
                return now()
        sleep(1.0)
    return None
