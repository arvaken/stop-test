"""The kit's AgentCore policies, the runtime's and the harness's, held to their cases as one, as IAM holds two policies
attached together: what it must allow of a run's own things, and what it must never allow
of yours (the founder's ruling of 29 October 2026, 13b and its conditions).

One case file, permissions/policy-cases.json, is read twice:
- in CI, by this module's matcher (`decide`), which matches a policy's statements as IAM matches them: an action by
  `*` and `?`, ignoring case; a resource's ARN by `*` and `?`, minding case; and the conditions the policy uses (Null,
  StringEquals, StringLike, ArnLike), against the request context each case gives explicitly;
- in install-test, by IAM's own policy simulator (`simulate`), with the same context. That run writes
  permissions/policy-simulator-record.json: the SHA-256 of each policy and of the case file it checked, and each case's
  expected decision, the simulator's and the matcher's. A release publishes only with a record that passed, every case
  agreeing three ways, for the very files being released (tests/test_policy_cases.py).

Run in install-test, with its sign-in (it makes nothing; it asks the simulator only):

    STOP_TEST_IAM_SIMULATOR=1 python scripts/policy_cases.py
"""
from __future__ import annotations

import datetime as dt
import fnmatch
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CASES = ROOT / "permissions" / "policy-cases.json"
RECORD = ROOT / "permissions" / "policy-simulator-record.json"


def listed(x: Any) -> list:
    return x if isinstance(x, list) else [x]


def load() -> tuple[dict, dict]:
    """The case file, and the policies it names as one: every statement of each, as IAM reads policies attached
    together."""
    cases = json.loads(CASES.read_text(encoding="utf-8"))
    return cases, {"Version": "2012-10-17", "Statement": [
        s for p in cases["policies"] for s in json.loads((ROOT / p).read_text(encoding="utf-8"))["Statement"]]}


def _met(condition: dict, context: dict[str, list[str]]) -> bool:
    """Whether a statement's conditions hold for the request's context: each operator, and each key, must."""
    for operator, keys in condition.items():
        for key, wanted in keys.items():
            have = context.get(key)
            if operator == "Null":
                if (have is None) != (str(wanted).lower() == "true"):
                    return False
            elif operator in ("StringEquals", "ArnEquals"):
                if not have or not any(h == w for h in have for w in listed(wanted)):
                    return False
            elif operator in ("StringLike", "ArnLike"):
                if not have or not any(fnmatch.fnmatchcase(h, w) for h in have for w in listed(wanted)):
                    return False
            else:
                raise ValueError(f"the matcher does not know the condition operator {operator}")
    return True


def decide(policy: dict, case: dict) -> str:
    """"allowed" where a statement allows the case's action on its resource, its conditions met; else "denied"."""
    context = {k: listed(v) for k, v in (case.get("context") or {}).items()}
    for s in policy["Statement"]:
        if s["Effect"] != "Allow":
            continue
        if not any(fnmatch.fnmatch(case["action"].lower(), a.lower()) for a in listed(s["Action"])):
            continue
        if not any(fnmatch.fnmatchcase(case["resource"], r) for r in listed(s["Resource"])):
            continue
        if _met(s.get("Condition") or {}, context):
            return "allowed"
    return "denied"


def simulate(iam: Any, policies: list[dict], case: dict) -> str:
    """IAM's policy simulator's decision for the case, the policies given as attached together, with the case's context
    given explicitly."""
    entries = [{"ContextKeyName": k, "ContextKeyValues": listed(v), "ContextKeyType": "string"}
               for k, v in (case.get("context") or {}).items()]
    found = iam.simulate_custom_policy(PolicyInputList=[json.dumps(p) for p in policies], ActionNames=[case["action"]],
                                       ResourceArns=[case["resource"]], ContextEntries=entries)["EvaluationResults"]
    decisions = {r["EvalDecision"] for r in found}
    return "allowed" if decisions == {"allowed"} else "denied"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def record(iam: Any) -> dict:
    """Every case through the simulator and the matcher, beside the SHA-256 of the files checked."""
    cases, policy = load()
    files = [json.loads((ROOT / p).read_text(encoding="utf-8")) for p in cases["policies"]]
    results = [{"id": c["id"], "expected": c["expected"], "simulator": simulate(iam, files, c),
                "matcher": decide(policy, c)} for c in cases["cases"]]
    return {"about": "IAM's policy simulator and the kit's matcher, each case of permissions/policy-cases.json, run "
                     "in Arvaken's install-test account; a release publishes only when this passed for its files",
            "checked": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            "files": {**{p: sha256(ROOT / p) for p in cases["policies"]},
                      CASES.relative_to(ROOT).as_posix(): sha256(CASES)},
            "cases": results,
            "passed": all(r["expected"] == r["simulator"] == r["matcher"] for r in results)}


def main() -> int:
    if not os.environ.get("STOP_TEST_IAM_SIMULATOR"):
        print("Set STOP_TEST_IAM_SIMULATOR=1 to ask IAM's policy simulator, in install-test.")
        return 1
    import boto3
    found = record(boto3.client("iam"))
    RECORD.write_text(json.dumps(found, indent=1) + "\n", encoding="utf-8", newline="\n")
    for r in found["cases"]:
        if not r["expected"] == r["simulator"] == r["matcher"]:
            print(f"{r['id']}: expected {r['expected']}, the simulator {r['simulator']}, the matcher {r['matcher']}")
    print("passed" if found["passed"] else "FAILED", "-", RECORD.relative_to(ROOT).as_posix())
    return 0 if found["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
