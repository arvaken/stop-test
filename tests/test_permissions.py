"""The ready-made least-privilege permissions in permissions/ (the founder's README changes, 24 October 2026, item 6),
held to what the kit actually does, so that neither can change without the other:

- AWS: every client call in the AWS module's source, read from the source itself, has its IAM action in
  permissions/aws-policy.json; and so does each action CloudFormation takes for the template's resources.
- Google: every request a whole run makes, read from the fake Google's record of them for each kind of stop, has its
  permission in permissions/google-role.yaml, or is a deny policy's, which Google grants only with the Deny Admin role on
  an organization.
"""
from __future__ import annotations

import json
import re
import urllib.parse
from pathlib import Path

import pytest

from arvaken_stop_test.google import fire as gfire
from test_google_run import DECLARED, Clock, FakeGoogle, a_run

ROOT = Path(__file__).resolve().parents[1]
AWS_POLICY = json.loads((ROOT / "permissions" / "aws-policy.json").read_text(encoding="utf-8"))
GOOGLE_ROLE = [line.strip()[2:] for line in (ROOT / "permissions" / "google-role.yaml").read_text(encoding="utf-8")
               .splitlines() if line.strip().startswith("- ")]
DENY_ADMIN = {"iam.denypolicies.create", "iam.denypolicies.get", "iam.denypolicies.list", "iam.denypolicies.delete"}

PREFIX = {"cloudformation": "cloudformation", "iam": "iam", "lambda_": "lambda", "s3": "s3", "cloudtrail": "cloudtrail",
          "tagging": "tag", "logs": "logs"}
# a boto3 method whose IAM action is not its own name
ACTION_OF = {("s3", "head_bucket"): "s3:ListBucket", ("s3", "list_objects_v2"): "s3:ListBucket",
             ("s3", "delete_objects"): "s3:DeleteObject", ("lambda_", "invoke"): "lambda:InvokeFunction"}
# what CloudFormation does, as the caller, for the template's bucket, two roles and function
TEMPLATE = ["s3:CreateBucket", "s3:DeleteBucket", "s3:PutBucketTagging", "s3:PutEncryptionConfiguration",
            "s3:PutBucketPublicAccessBlock", "iam:CreateRole", "iam:DeleteRole", "iam:GetRole", "iam:TagRole",
            "iam:PutRolePolicy", "iam:GetRolePolicy", "iam:DeleteRolePolicy", "iam:PassRole", "lambda:CreateFunction",
            "lambda:DeleteFunction", "lambda:GetFunction", "lambda:TagResource"]


def allowed() -> set[str]:
    out: set[str] = set()
    for s in AWS_POLICY["Statement"]:
        assert s["Effect"] == "Allow"
        out |= set(s["Action"] if isinstance(s["Action"], list) else [s["Action"]])
    return out


def aws_calls() -> set[str]:
    found = set()
    for path in (ROOT / "src" / "arvaken_stop_test" / "aws").glob("*.py"):
        if path.name == "agent.py":                     # the test agent's own calls are its role's, not yours
            continue
        text = path.read_text(encoding="utf-8")
        for client, method in re.findall(r"\b(cloudformation|iam|lambda_|s3|cloudtrail|tagging|logs)\.([a-z0-9_]+)\(", text):
            camel = "".join(w.capitalize() for w in method.split("_"))
            found.add(ACTION_OF.get((client, method), f"{PREFIX[client]}:{camel}"))
    return found


def test_every_aws_call_the_kit_makes_and_every_action_cloudformation_takes_for_it_is_in_the_policy():
    calls = aws_calls()
    assert {"lambda:InvokeFunction", "iam:AttachRolePolicy", "iam:SimulateCustomPolicy"} <= calls, "the source was read"
    assert calls | set(TEMPLATE) <= allowed(), sorted((calls | set(TEMPLATE)) - allowed())


def test_the_aws_policy_names_the_runs_own_resources_wherever_aws_lets_it():
    for s in AWS_POLICY["Statement"]:
        resources = s["Resource"] if isinstance(s["Resource"], list) else [s["Resource"]]
        if s["Sid"] == "ReadsAwsTakesOnEveryResourceOnly":
            assert resources == ["*"]
        elif s["Sid"] == "YourStopReadAndChecked":
            assert resources == ["arn:aws:iam::*:policy/*"]
        else:
            assert all("arvaken-stop-test-" in r for r in resources), s["Sid"]


def permission_for(method: str, url: str, identity: bool = False) -> str:
    """The permission Google checks for one of the kit's requests."""
    if identity:
        return "run.routes.invoke"
    u = urllib.parse.urlsplit(url)
    path = urllib.parse.unquote(u.path)
    if u.netloc == "logging.googleapis.com":
        return "logging.logEntries.list"
    if "/denypolicies" in path:
        last = path.rstrip("/").rsplit("/", 1)[1]
        return {"POST": "iam.denypolicies.create", "DELETE": "iam.denypolicies.delete"}.get(
            method, "iam.denypolicies.list" if last == "denypolicies" else "iam.denypolicies.get")
    if u.netloc == "iam.googleapis.com":
        for verb in ("disable", "enable", "getIamPolicy", "setIamPolicy"):
            if path.endswith(":" + verb):
                return f"iam.serviceAccounts.{verb}"
        return {"POST": "iam.serviceAccounts.create", "DELETE": "iam.serviceAccounts.delete"}.get(method,
                                                                                                    "iam.serviceAccounts.get")
    if u.netloc == "storage.googleapis.com":
        if path.endswith("/iam"):
            return "storage.buckets.setIamPolicy" if method == "PUT" else "storage.buckets.getIamPolicy"
        if path.endswith("/o"):
            return "storage.objects.list"
        if "/o/" in path:
            return "storage.objects.delete"
        return {"POST": "storage.buckets.create", "DELETE": "storage.buckets.delete"}.get(method, "storage.buckets.get")
    if u.netloc == "run.googleapis.com":
        return {"POST": "run.services.create", "DELETE": "run.services.delete"}.get(method, "run.services.get")
    raise AssertionError(f"no permission known for {method} {url}")


@pytest.mark.parametrize("stop", [gfire.DENY_ALL, gfire.DISABLE, DECLARED])
def test_every_request_a_google_run_makes_is_in_the_role_or_is_a_deny_policys(stop):
    fake = FakeGoogle(Clock())
    a_run(fake, stop)
    needed = {permission_for(m, u) for m, u in fake.calls if u != "https://agent.example/"}
    needed |= {"run.routes.invoke"} if any(u == "https://agent.example/" for _, u in fake.calls) else set()
    needed |= {"iam.serviceAccounts.actAs"}               # deploying a service that runs as an account of the run's
    assert needed - DENY_ADMIN <= set(GOOGLE_ROLE), sorted(needed - DENY_ADMIN - set(GOOGLE_ROLE))
    assert not (set(GOOGLE_ROLE) & DENY_ADMIN), "a deny policy's permissions are the organization's Deny Admin role's"
