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
spec = importlib.util.spec_from_file_location("policy_trials", ROOT / "scripts" / "policy_trials.py")
pt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pt)
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


# -- the policies tried for real (scripts/policy_trials.py): what IAM's simulator can't vouch for, a run can

class _Trail:
    """CloudTrail's event history, as lookup_events pages it, holding the given events."""

    def __init__(self, events):
        self.events = events

    def client(self, name, region_name):
        return self

    def get_paginator(self, name):
        return self

    def paginate(self, StartTime, EndTime):
        return [{"Events": [{"CloudTrailEvent": json.dumps(e)} for e in self.events]}]


def _event(name, code, identity):
    return {"eventSource": "bedrock-agentcore.amazonaws.com", "eventName": name, "errorCode": code,
            "userIdentity": {"arn": identity}}


def test_a_trial_counts_only_the_check_roles_own_access_denied_refusals_and_agentcores_for_it():
    role = "arvaken-policy-check-r0a1b2c3d"
    mine = f"arn:aws:sts::111122223333:assumed-role/{role}/arvaken-policy-check"
    events = [_event("CreateAgentRuntime", "AccessDeniedException", mine),      # AgentCore acting for the role
              _event("DeleteWorkloadIdentity", "AccessDenied", mine),
              _event("GetHarness", "ResourceNotFoundException", mine),          # the kit's own check that it's gone
              _event("CreateLogStream", "AccessDenied",                         # the test agent's role, not the caller
                     "arn:aws:sts::111122223333:assumed-role/arvaken-stop-test-r0a1b2c3d-agent/x"),
              _event("CreateHarness", "AccessDenied",                           # another check role
                     "arn:aws:sts::111122223333:assumed-role/arvaken-policy-check-r9f9f9f9f/arvaken-policy-check")]
    found = pt.refusals(_Trail(events), role, ["eu-central-1"], None, None)
    assert found == {"bedrock-agentcore:CreateAgentRuntime": 1, "bedrock-agentcore:DeleteWorkloadIdentity": 1}


def test_a_trial_passes_only_where_the_run_left_nothing_and_nothing_of_the_roles_was_refused():
    result = {"agent": {"kind": "aws-agentcore-runtime"},
              "run": {"left_behind": [], "began_at": "2026-10-29T20:30:43.283Z", "ended_at": "2026-10-29T20:38:22.525Z"}}
    head = pt.subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    policies = list(pt.NEEDS["aws-agentcore-runtime"])
    assert pt.entry("r0a1b2c3d", result, head, policies, {})["passed"]
    assert not pt.entry("r0a1b2c3d", result, head, policies, {"bedrock-agentcore:CreateAgentRuntime": 1})["passed"]
    left = {**result, "run": {**result["run"], "left_behind": ["the harness's runtime"]}}
    made = pt.entry("r0a1b2c3d", left, head, policies, {})
    assert not made["passed"] and made["left"] == 1 and "left_behind" not in made


@pytest.mark.skipif(not os.environ.get("STOP_TEST_RELEASE"), reason="checked when a release is made (release.yml)")
def test_a_release_has_a_passing_trial_of_each_kind_of_agent_for_the_very_policy_files_it_releases():
    assert pt.RECORD.exists(), "no record of the policies tried: run scripts/policy_trials.py in install-test"
    trials = json.loads(pt.RECORD.read_text(encoding="utf-8"))["trials"]
    for kind, files in pt.NEEDS.items():
        now = {p: pc.sha256(ROOT / p) for p in files}
        assert any(t["agent"] == kind and t["passed"] and t["policies"] == now for t in trials), \
            f"no passing trial of an {kind} run as a role holding these very files: {', '.join(files)}"


def test_the_trial_record_names_nothing_of_a_real_account():
    if pt.RECORD.exists():
        assert "arn:" not in pt.RECORD.read_text(encoding="utf-8")
