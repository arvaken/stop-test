"""The kit's AgentCore policies, the runtime's and the harness's, held to their cases as one, as IAM holds two policies
attached together: what it must allow of a run's own things, and what it must never allow
of yours (the founder's ruling of 29 October 2026, 13b and its conditions). And the copy's policy
(permissions/aws-copy-policy.json), filled in as a customer fills it at install, held to its own: what it must allow of
their test copy, and that invoking an unmarked function or runtime, or changing the copy, is denied (the founder's
ruling on batch 7, 01:08:36 UTC on 2 November 2026).

Each case file (CASE_FILES: permissions/policy-cases.json, permissions/policy-cases-copy.json) is read twice:
- in CI, by this module's matcher (`decide`), which matches a policy's statements as IAM matches them: an action by
  `*` and `?`, ignoring case; a resource's ARN by `*` and `?`, minding case; and the conditions the policy uses (Null,
  StringEquals, StringLike, ArnLike), against the request context each case gives explicitly;
- in install-test, by IAM's own policy simulator (`simulate`), with the same context. That run writes
  permissions/policy-simulator-record.json: the SHA-256 of each policy and of each case file it checked, and each case's
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
COPY_CASES = ROOT / "permissions" / "policy-cases-copy.json"
CASE_FILES = (CASES, COPY_CASES)
RECORD = ROOT / "permissions" / "policy-simulator-record.json"


def listed(x: Any) -> list:
    return x if isinstance(x, list) else [x]


def policies(cases: dict) -> list[dict]:
    """Each policy the case file names, with its placeholders filled in as the file's `fill` gives them, as a customer
    fills them at install: the longest first, so YOUR-TEST-COPY-ID is never read as YOUR-TEST-COPY."""
    fill = sorted((cases.get("fill") or {}).items(), key=lambda kv: -len(kv[0]))
    out = []
    for p in cases["policies"]:
        text = (ROOT / p).read_text(encoding="utf-8")
        for placeholder, value in fill:
            text = text.replace(placeholder, value)
        out.append(json.loads(text))
    return out


def load(path: Path = CASES) -> tuple[dict, dict]:
    """A case file, and the policies it names as one: every statement of each, as IAM reads policies attached
    together."""
    cases = json.loads(path.read_text(encoding="utf-8"))
    return cases, {"Version": "2012-10-17", "Statement": [s for p in policies(cases) for s in p["Statement"]]}


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


def files_checked() -> dict[str, str]:
    """The SHA-256 of every policy and every case file a record is of."""
    found = {}
    for path in CASE_FILES:
        cases = json.loads(path.read_text(encoding="utf-8"))
        found.update({p: sha256(ROOT / p) for p in cases["policies"]})
        found[path.relative_to(ROOT).as_posix()] = sha256(path)
    return found


def record(iam: Any) -> dict:
    """Every case of every case file through the simulator and the matcher, beside the SHA-256 of the files checked."""
    results = []
    for path in CASE_FILES:
        cases, policy = load(path)
        filled = policies(cases)
        results += [{"id": c["id"], "expected": c["expected"], "simulator": simulate(iam, filled, c),
                     "matcher": decide(policy, c)} for c in cases["cases"]]
    return {"about": "IAM's policy simulator and the kit's matcher, each case of permissions/policy-cases.json and "
                     "permissions/policy-cases-copy.json, run in Arvaken's install-test account; a release publishes "
                     "only when this passed for its files",
            "checked": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            "files": files_checked(),
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
