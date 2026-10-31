"""The kit's AgentCore policies, tried for real: a run made in install-test as a role holding the kit's policies and
nothing else, recorded beside the policy files that role held (the founder's ruling of 29 October 2026). AgentCore
accepts InvokeAgentRuntime and InvokeAgentRuntimeCommand on a harness's ARN, which IAM's policy simulator refuses, so
no case of permissions/policy-cases.json can vouch for them; a run can.

Each entry of permissions/policy-trial-record.json: the run, its agent's kind, the kit's commit it ran from, the
SHA-256 of each policy file the role held at that commit, how many things the run named left, and the access-denied
refusals CloudTrail's event history holds of that role, or of AgentCore acting for it, between the run's beginning and
its end. An entry passes where the run left nothing and nothing of the role's was refused. A release publishes only
with a passing entry for each kind of agent, for the very policy files it releases (tests/test_policy_cases.py).

The role is made from the commit's own files, by Arvaken's check-role script, and deleted after the run. Run in
install-test, with its sign-in, after the run's events have reached CloudTrail (it makes nothing; it reads the result
and CloudTrail):

    STOP_TEST_CLOUDTRAIL=1 python scripts/policy_trials.py <result.json> <commit> <role name> <policy file>...
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
RECORD = ROOT / "permissions" / "policy-trial-record.json"
# What a customer gives the kit for each kind of agent: the runtime's policy alone, or the harness's beside it
NEEDS = {"aws-agentcore-runtime": ("permissions/aws-agentcore-policy.json",),
         "aws-agentcore-harness": ("permissions/aws-agentcore-policy.json",
                                   "permissions/aws-agentcore-harness-policy.json")}
REFUSED = frozenset({"AccessDenied", "AccessDeniedException"})


def sha256_at(commit: str, path: str) -> str:
    """The SHA-256 of a file as it is at a commit."""
    blob = subprocess.run(["git", "-C", str(ROOT), "show", f"{commit}:{path}"], capture_output=True, check=True).stdout
    return hashlib.sha256(blob).hexdigest()


def _at(stamp: str) -> dt.datetime:
    return dt.datetime.fromisoformat(stamp.replace("Z", "+00:00"))


def refusals(session: Any, role: str, regions: list[str], began: dt.datetime, ended: dt.datetime) -> dict[str, int]:
    """Each call of the role's, or AgentCore's acting for it, that CloudTrail's event history holds as access denied."""
    found: dict[str, int] = {}
    for region in regions:
        pages = session.client("cloudtrail", region_name=region).get_paginator("lookup_events").paginate(
            StartTime=began, EndTime=ended)
        for page in pages:
            for e in page["Events"]:
                event = json.loads(e["CloudTrailEvent"])
                if event.get("errorCode") in REFUSED and f":assumed-role/{role}/" in json.dumps(
                        event.get("userIdentity", {})):
                    name = f"{event['eventSource'].split('.')[0]}:{event['eventName']}"
                    found[name] = found.get(name, 0) + 1
    return found


def entry(run: str, result: dict, commit: str, policies: list[str], refused: dict[str, int]) -> dict:
    left = len(result["run"]["left_behind"])
    return {"run": run, "agent": result["agent"]["kind"], "commit": commit,
            "policies": {p: sha256_at(commit, p) for p in policies},
            "began_at": result["run"]["began_at"], "ended_at": result["run"]["ended_at"],
            "left": left, "refused": refused, "passed": left == 0 and not refused,
            "checked": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")}


def main() -> int:
    if not os.environ.get("STOP_TEST_CLOUDTRAIL"):
        print("Set STOP_TEST_CLOUDTRAIL=1 to read CloudTrail's event history, in install-test.")
        return 1
    import boto3
    path, commit, role, *policies = sys.argv[1:]
    run = Path(path).name.removeprefix("stop-test-").removesuffix(".json")     # a result is stop-test-<run>.json
    result = json.loads(Path(path).read_text(encoding="utf-8"))
    if tuple(policies) != NEEDS[result["agent"]["kind"]]:
        print(f"a {result['agent']['kind']} run is recorded with {', '.join(NEEDS[result['agent']['kind']])}")
        return 1
    commit = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "--verify", f"{commit}^{{commit}}"],
                            capture_output=True, text=True, check=True).stdout.strip()
    began, ended = _at(result["run"]["began_at"]), _at(result["run"]["ended_at"]) + dt.timedelta(minutes=1)
    made = entry(run, result, commit, policies,
                 refusals(boto3.Session(), role, sorted({result["region"], "us-east-1"}), began, ended))
    record = json.loads(RECORD.read_text(encoding="utf-8")) if RECORD.exists() else {
        "about": "The kit's AgentCore policies, each run made in Arvaken's install-test account as a role holding only "
                 "the policy files named; a release publishes only with a passing entry for each kind of agent, for "
                 "its files (scripts/policy_trials.py)",
        "trials": []}
    record["trials"] = [t for t in record["trials"] if t["run"] != made["run"]] + [made]
    RECORD.write_text(json.dumps(record, indent=1) + "\n", encoding="utf-8", newline="\n")
    print("passed" if made["passed"] else "FAILED", made["run"], "-", RECORD.relative_to(ROOT).as_posix())
    return 0 if made["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
