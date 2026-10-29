"""The kit's AgentCore policies, the runtime's and the harness's, held to their cases (scripts/policy_cases.py; the founder's ruling of 29 October 2026, 13b):
in CI by the matcher; in install-test by IAM's policy simulator; and at release, a record of that simulator run, for
the very files being released, or no release.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("policy_cases", ROOT / "scripts" / "policy_cases.py")
pc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pc)
CASES, POLICY = pc.load()
# What the founder named, each limited by tag or name prefix: runtimes, memories, workload identities, log groups, roles
# and iam:PassRole; and the harness and its making, as the runtime's.
LIMITED = {"TheRunsRuntime", "TheRunsRuntimeMadeWithTheRunsTag", "TheRuntimeAWSRequiresForAHarness",
           "TheMemoryAWSRequiresToMakeAHarnessWithTheRunsTag", "TheMemoryAWSRequiresForAHarnessTaggedWithARun",
           "TheRuntimesWorkloadIdentity", "TheRuntimesLogGroupsIfAny", "TheRunsHarness",
           "TheRunsHarnessMadeWithTheRunsTag", "TheRunsRolesEachUnderTheKitsBoundary", "TheRunsRoles",
           "TheAgentsRoleGivenToItsRuntime", "TaggingWhatTheRunMakesWithTheRunsTag",
           "TheRunsRuntimeEndpointMadeWithTheRunsTag", "TheRunsWorkloadIdentityMadeWithTheRunsTag",
           "TheWorkloadIdentityDirectoryAWSChecksBesideTheRunsIdentity"}


@pytest.mark.parametrize("case", CASES["cases"], ids=[c["id"] for c in CASES["cases"]])
def test_the_matcher_decides_each_case_as_expected(case):
    assert pc.decide(POLICY, case) == case["expected"]


def test_each_limited_statement_has_an_allowed_case_and_a_denied_one():
    sids = {s["Sid"] for s in POLICY["Statement"]}
    assert len(sids) == len(POLICY["Statement"]) and LIMITED <= sids
    assert {c["statement"] for c in CASES["cases"]} <= sids
    for sid in LIMITED:
        found = {c["expected"] for c in CASES["cases"] if c["statement"] == sid}
        assert found == {"allowed", "denied"}, sid


def test_the_cases_name_nothing_of_a_real_account():
    assert "111122223333" in json.dumps(CASES) and len({c["id"] for c in CASES["cases"]}) == len(CASES["cases"])


@pytest.mark.skipif(not os.environ.get("STOP_TEST_IAM_SIMULATOR"),
                    reason="asks IAM's policy simulator: run as install-test does, STOP_TEST_IAM_SIMULATOR=1")
def test_iams_policy_simulator_decides_each_case_as_the_matcher_does():
    import boto3
    found = pc.record(boto3.client("iam"))
    assert [r for r in found["cases"] if not r["expected"] == r["simulator"] == r["matcher"]] == []


@pytest.mark.skipif(not os.environ.get("STOP_TEST_RELEASE"), reason="checked when a release is made (release.yml)")
def test_a_release_has_a_passing_simulator_record_for_the_very_files_it_releases():
    assert pc.RECORD.exists(), "no record of IAM's policy simulator: run scripts/policy_cases.py in install-test"
    record = json.loads(pc.RECORD.read_text(encoding="utf-8"))
    assert record["files"] == {**{p: pc.sha256(ROOT / p) for p in CASES["policies"]},
                               "permissions/policy-cases.json": pc.sha256(pc.CASES)}, \
        "the record is of other files than these: run the simulator again on these"
    assert record["passed"] and {r["id"] for r in record["cases"]} == {c["id"] for c in CASES["cases"]}
    assert all(r["expected"] == r["simulator"] == r["matcher"] for r in record["cases"])
