"""What the kit makes for a run on Google Cloud (the design's section 3), each thing named with the run and labelled
`arvaken-stop-test=<run>` where Google lets it be labelled:

- the test agent: a Cloud Run service running agent.py in Python's own image, pinned by its digest, as a service
  account of its own; one instance, kept warm through the run;
- what it acts on: a bucket of the kit's own (uniform access, public access prevented), and a second service account
  the agent may take a token for;
- the grants between them, and nothing else: each account may write the bucket's objects, the agent may take the
  second account's token. Both are granted on those resources alone, never on the project.

There is no stack to delete on Google, so the run deletes each thing itself and checks each gone by its own name
(run.py). The kit touches nothing it did not make, except to fire a stop on the agent's own account (fire.py).
"""
from __future__ import annotations

import ast
import secrets
import time
import urllib.parse
from collections.abc import Callable
from importlib import resources
from typing import Any

from arvaken_stop_test.google.api import Google, GoogleError

PREFIX = "arvaken-stop-test"
LABEL = "arvaken-stop-test"
# Python's own image, by its digest: the agent needs the standard library alone, so nothing of the kit's is built.
IMAGE = "docker.io/library/python:3.12-slim-bookworm@sha256:57d96f71de145a98e7ceca18ee4ade77bba4103a33a72dfaea026b23625c6bf0"
BOOT = "import os; exec(compile(os.environ['AGENT_CODE'], 'agent.py', 'exec'))"
RUNTIME, MEMORY_MB = "python3.12", 512
IAM, STORAGE, RUN = "https://iam.googleapis.com/v1", "https://storage.googleapis.com/storage/v1", "https://run.googleapis.com/v2"
CODE_LIMIT = 32 * 1024        # Cloud Run's limit on one variable's value


def new_run() -> str:
    """A run's name: r and eight hex digits, lower case, as Google's names allow."""
    return "r" + secrets.token_hex(4)


def names(run: str, project: str) -> dict[str, str]:
    base = f"{PREFIX}-{run}"
    return {"service": base, "bucket": base, "deny_policy": base,
            "agent_account": f"arvaken-st-{run}@{project}.iam.gserviceaccount.com",
            "second_account": f"arvaken-st-{run}-b@{project}.iam.gserviceaccount.com"}


def agent_code() -> str:
    """agent.py as the service runs it: without its module docstring, which is for readers of this repository."""
    source = resources.files("arvaken_stop_test.google").joinpath("agent.py").read_text(encoding="utf-8")
    first = ast.parse(source).body[0]
    if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str):
        source = "\n".join(source.splitlines()[first.end_lineno:]).lstrip("\n")
    if len(source.encode()) > CODE_LIMIT:
        raise ValueError(f"the test agent's code is {len(source.encode())} bytes; Cloud Run takes {CODE_LIMIT} in a variable")
    return source


def service_name(g: Google, run: str) -> str:
    return f"projects/{g.project}/locations/{g.region}/services/{names(run, g.project)['service']}"


def service_body(g: Google, run: str, endpoint: str, outside_key: str) -> dict[str, Any]:
    n = names(run, g.project)
    env = {"BUCKET": n["bucket"], "ENDPOINT": endpoint, "SECOND_ACCOUNT": n["second_account"],
           "OUTSIDE_KEY": outside_key, "AGENT_CODE": agent_code()}
    return {"labels": {LABEL: run}, "ingress": "INGRESS_TRAFFIC_ALL",
            "description": f"Arvaken stop test, run {run}: a test agent of the kit's own. Removed when the run ends.",
            "template": {"serviceAccount": n["agent_account"], "timeout": "30s",
                         "scaling": {"minInstanceCount": 1, "maxInstanceCount": 1},
                         "containers": [{"image": IMAGE, "command": ["python", "-c", BOOT],
                                         "env": [{"name": k, "value": v} for k, v in env.items()],
                                         "resources": {"limits": {"cpu": "1", "memory": f"{MEMORY_MB}Mi"}}}]}}


def _retry(call: Callable[[], Any], sleep: Callable[[float], None], tries: int = 12, wait: float = 10.0) -> Any:
    """A call that may meet a thing just made that Google does not yet see everywhere (a new service account, most
    often): tried again on 400 and 404 for about two minutes."""
    for i in range(tries):
        try:
            return call()
        except GoogleError as e:
            if e.status not in (400, 404) or i == tries - 1:
                raise
            sleep(wait)


def _add_binding(policy: dict, role: str, member: str) -> dict:
    bindings = policy.setdefault("bindings", [])
    for b in bindings:
        if b.get("role") == role and "condition" not in b:
            if member not in b.setdefault("members", []):
                b["members"].append(member)
            return policy
    bindings.append({"role": role, "members": [member]})
    return policy


def deploy(g: Google, run: str, endpoint: str, *, outside_key: str | None = None,
           sleep: Callable[[float], None] = time.sleep, wait: float = 600.0) -> dict[str, str]:
    """Make the run's things, in order; returns their names and the test agent's address."""
    n = names(run, g.project)
    made: dict[str, dict] = {}
    for which, words in (("agent_account", "the test agent"), ("second_account", "a second identity")):
        made[which] = g.call("POST", f"{IAM}/projects/{g.project}/serviceAccounts", {
            "accountId": n[which].split("@")[0],
            "serviceAccount": {"displayName": f"Arvaken stop test {run}: {words}",
                               "description": f"{LABEL}={run}. Removed when the run ends."}})
    g.call("POST", f"{STORAGE}/b?project={g.project}", {
        "name": n["bucket"], "location": g.region, "labels": {LABEL: run},
        "iamConfiguration": {"uniformBucketLevelAccess": {"enabled": True}, "publicAccessPrevention": "enforced"}})
    for which in ("agent_account", "second_account"):
        def grant(member=f"serviceAccount:{n[which]}"):
            policy = g.call("GET", f"{STORAGE}/b/{n['bucket']}/iam")
            g.call("PUT", f"{STORAGE}/b/{n['bucket']}/iam", _add_binding(policy, "roles/storage.objectAdmin", member))
        _retry(grant, sleep)

    def token_creator():
        url = f"{IAM}/projects/-/serviceAccounts/{n['second_account']}"
        policy = g.call("POST", f"{url}:getIamPolicy", {})
        g.call("POST", f"{url}:setIamPolicy", {"policy": _add_binding(
            policy, "roles/iam.serviceAccountTokenCreator", f"serviceAccount:{n['agent_account']}")})
    _retry(token_creator, sleep)
    key = outside_key or secrets.token_hex(16)        # 32 hexadecimal characters, as the test endpoint takes one
    parent = f"projects/{g.project}/locations/{g.region}"
    _retry(lambda: g.call("POST", f"{RUN}/{parent}/services?serviceId={n['service']}",
                          service_body(g, run, endpoint, key)), sleep)
    uri, end = "", time.monotonic() + wait
    while time.monotonic() < end:
        found = g.call("GET", f"{RUN}/{service_name(g, run)}")
        state = (found.get("terminalCondition") or {}).get("state")
        if state == "CONDITION_SUCCEEDED" and found.get("uri"):
            uri = found["uri"]
            break
        if state == "CONDITION_FAILED":
            raise RuntimeError(f"the test agent's service did not start: {(found.get('terminalCondition') or {}).get('reason')}")
        sleep(5.0)
    if not uri:
        raise TimeoutError(f"the test agent's service was not ready in {int(wait)} seconds")
    # Cloud Audit Logs name a disabled account by its unique ID, never its email: kept, to find the firing call
    return {"Bucket": n["bucket"], "Agent": service_name(g, run), "AgentAccount": n["agent_account"],
            "AgentAccountId": str(made["agent_account"].get("uniqueId") or ""), "SecondAccount": n["second_account"],
            "Uri": uri}


def quoted(name: str) -> str:
    return urllib.parse.quote(name, safe="")
