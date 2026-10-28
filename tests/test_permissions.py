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
          "tagging": "tag", "logs": "logs", "ec2": "ec2"}
# a boto3 method whose IAM action is not its own name
ACTION_OF = {("s3", "head_bucket"): "s3:ListBucket", ("s3", "list_objects_v2"): "s3:ListBucket",
             ("s3", "delete_objects"): "s3:DeleteObject", ("lambda_", "invoke"): "lambda:InvokeFunction"}
# what CloudFormation does, as the caller, for the template's bucket, two roles and function
TEMPLATE = ["s3:CreateBucket", "s3:DeleteBucket", "s3:PutBucketTagging", "s3:PutEncryptionConfiguration",
            "s3:PutBucketPublicAccessBlock", "iam:CreateRole", "iam:DeleteRole", "iam:GetRole", "iam:TagRole",
            "iam:PutRolePolicy", "iam:GetRolePolicy", "iam:DeleteRolePolicy", "iam:PassRole", "lambda:CreateFunction",
            "lambda:DeleteFunction", "lambda:GetFunction", "lambda:TagResource"]
# and for a function in a subnet of yours (--subnet; D561): Lambda checks, as the caller, the subnet and its security
# groups, and the network they are in (AWS's Lambda guide, its users' permissions to configure a function's VPC)
TEMPLATE_IN_A_SUBNET = ["ec2:DescribeSecurityGroups", "ec2:DescribeSubnets", "ec2:DescribeVpcs"]


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
        for client, method in re.findall(
                r"\b(cloudformation|iam|lambda_|s3|cloudtrail|tagging|logs|ec2)\.([a-z0-9_]+)\(", text):
            camel = "".join(w.capitalize() for w in method.split("_"))
            found.add(ACTION_OF.get((client, method), f"{PREFIX[client]}:{camel}"))
    return found


def test_every_aws_call_the_kit_makes_and_every_action_cloudformation_takes_for_it_is_in_the_policy():
    calls = aws_calls()
    assert {"lambda:InvokeFunction", "iam:AttachRolePolicy", "iam:SimulateCustomPolicy",
            "ec2:DescribeNetworkInterfaces"} <= calls, "the source was read"
    needed = calls | set(TEMPLATE) | set(TEMPLATE_IN_A_SUBNET)
    assert needed <= allowed(), sorted(needed - allowed())
    # of EC2, the kit itself only reads: it changes nothing of a subnet of yours
    assert {a for a in allowed() if a.startswith("ec2:")} == {"ec2:DescribeNetworkInterfaces", *TEMPLATE_IN_A_SUBNET}


def test_the_aws_policy_names_the_runs_own_resources_wherever_aws_lets_it():
    for s in AWS_POLICY["Statement"]:
        resources = s["Resource"] if isinstance(s["Resource"], list) else [s["Resource"]]
        if s["Sid"] == "ReadsAwsTakesOnEveryResourceOnly":
            assert resources == ["*"]
        elif s["Sid"] == "YourStopReadAndChecked":
            assert resources == ["arn:aws:iam::*:policy/*"]
        else:
            assert all("arvaken-stop-test-" in r for r in resources), s["Sid"]


BOUNDARY = json.loads((ROOT / "permissions" / "aws-boundary.json").read_text(encoding="utf-8"))
BOUNDARY_VIA = json.loads((ROOT / "permissions" / "aws-boundary-via.json").read_text(encoding="utf-8"))
BOUNDARIES = {(via, model): json.loads((ROOT / "permissions" / f"aws-boundary{'-via' * via}{'-model' * model}.json")
                                       .read_text(encoding="utf-8"))
              for via in (False, True) for model in (False, True)}
ROLE_CHANGES = {"iam:CreateRole", "iam:PutRolePolicy", "iam:DeleteRolePolicy", "iam:AttachRolePolicy",
                "iam:DetachRolePolicy"}


def test_the_aws_policy_makes_or_changes_a_role_only_under_the_kits_boundary():
    """Whoever holds the policy cannot make a role beyond the boundary: every act that makes a role, or gives one a
    policy, is allowed only where the role's permissions boundary is arvaken-stop-test-boundary, or a run in a
    subnet's, with a model's or with both's (-via, -model, -via-model), and none of them elsewhere; and nothing in the
    policy changes a role's boundary or a boundary policy itself."""
    for s in AWS_POLICY["Statement"]:
        actions = set(s["Action"] if isinstance(s["Action"], list) else [s["Action"]])
        if actions & ROLE_CHANGES:
            assert actions == ROLE_CHANGES and s["Condition"] == {
                "StringLike": {"iam:PermissionsBoundary": [f"arn:aws:iam::*:policy/arvaken-stop-test-boundary{s}"
                                                           for s in ("", "-via", "-model", "-via-model")]}}
    assert not allowed() & {"iam:PutRolePermissionsBoundary", "iam:DeleteRolePermissionsBoundary",
                            "iam:CreatePolicy", "iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion",
                            "iam:DeletePolicy", "iam:DeletePolicyVersion"}


def _granted(t: dict) -> dict[str, set[str]]:
    """Each role's own policies' actions, by the role's resource."""
    return {k: {a for p in r["Properties"]["Policies"] for s in p["PolicyDocument"]["Statement"]
                for a in (s["Action"] if isinstance(s["Action"], list) else [s["Action"]])}
            for k, r in t["Resources"].items() if r["Type"] == "AWS::IAM::Role"}


def _effect(doc: dict, effect: str) -> set[tuple[str, str]]:
    """Each (action, resource) a policy document allows, or denies."""
    as_list = lambda x: x if isinstance(x, list) else [x]  # noqa: E731
    return {(a, r) for s in doc["Statement"] if s["Effect"] == effect for a in as_list(s["Action"])
            for r in as_list(s["Resource"])}


def test_the_boundary_is_the_kits_and_allows_what_the_two_roles_do_and_no_more():
    """With a subnet of yours (--subnet; D561), the agent's role alone may also make its function's network interfaces,
    with AWSLambdaVPCAccessExecutionRole's EC2 actions and none of its logs actions. With a model (--model; the
    design's section 4), the agent's role alone may invoke it. AWS asks for the network actions on every resource, and a
    boundary is the same for every run, so it allows bedrock:InvokeModel on any model and any inference profile: the
    kit's own boundary allows neither, as the kit took it to 0.2.1. A run in a subnet's roles carry
    arvaken-stop-test-boundary-via, which allows the network actions and denies them to a function's own code; a run
    with a model's, arvaken-stop-test-boundary-model, which allows bedrock:InvokeModel and nothing else of Bedrock; a
    run with both's, arvaken-stop-test-boundary-via-model, both."""
    from arvaken_stop_test.aws.stack import MODEL_SID, NETWORK_ACTIONS, boundary_document, boundary_file, template
    for (via, with_model), doc in BOUNDARIES.items():     # permissions/ gives the ones the kit checks for
        assert doc == boundary_document(via, with_model)
        text = (ROOT / boundary_file(via, with_model)).read_text(encoding="utf-8")
        assert text == json.dumps(json.loads(text), indent=1) + "\n"     # as the account holds them: as the kit dumps
    before = {("s3:PutObject", "arn:aws:s3:::arvaken-stop-test-*/*"),
              ("s3:GetObject", "arn:aws:s3:::arvaken-stop-test-*/*"),
              ("sts:AssumeRole", "arn:aws:iam::*:role/arvaken-stop-test-*")}
    network = {(a, "*") for a in NETWORK_ACTIONS}
    model = {("bedrock:InvokeModel", "arn:aws:bedrock:*::foundation-model/*"),
             ("bedrock:InvokeModel", "arn:aws:bedrock:*:*:inference-profile/*")}
    assert _effect(BOUNDARY, "Allow") == before and not _effect(BOUNDARY, "Deny")     # the kit's, as to 0.2.1
    for (via, with_model), doc in BOUNDARIES.items():
        assert _effect(doc, "Allow") == before | (network if via else set()) | (model if with_model else set())
        assert _effect(doc, "Deny") == (network if via else set())
    assert [s["Condition"] for s in BOUNDARY_VIA["Statement"] if s["Effect"] == "Deny"] == [
        {"Null": {"lambda:SourceFunctionArn": "false"}}]  # Lambda's own calls for the interfaces carry no function ARN
    assert [s for s in BOUNDARIES[(False, True)]["Statement"] if s["Sid"] == MODEL_SID] == [{
        "Sid": "TheTestAgentsCallToAModel", "Effect": "Allow", "Action": "bedrock:InvokeModel",
        "Resource": ["arn:aws:bedrock:*::foundation-model/*", "arn:aws:bedrock:*:*:inference-profile/*"]}]
    assert set(NETWORK_ACTIONS) == {"ec2:CreateNetworkInterface", "ec2:DescribeNetworkInterfaces",
                                    "ec2:DescribeSubnets", "ec2:DeleteNetworkInterface",
                                    "ec2:AssignPrivateIpAddresses", "ec2:UnassignPrivateIpAddresses"}
    plain = _granted(template("r0123abcd", "https://e.test"))
    assert set().union(*plain.values()) == {a for a, _ in before}     # each the roles' own policies grant, none more
    in_a_subnet = _granted(template("r0123abcd", "https://e.test", subnet="subnet-0abc1234",
                                    security_groups=["sg-0abc1234"]))
    assert in_a_subnet["AgentRole"] == plain["AgentRole"] | set(NETWORK_ACTIONS)
    assert in_a_subnet["SecondRole"] == plain["SecondRole"]             # the second role is never given them
    assert set().union(*in_a_subnet.values()) == {a for a, _ in _effect(BOUNDARY_VIA, "Allow")}
    with_a_model = _granted(template("r0123abcd", "https://e.test", subnet="subnet-0abc1234",
                                     security_groups=["sg-0abc1234"], model="eu.amazon.nova-micro-v1:0"))
    assert with_a_model["AgentRole"] == in_a_subnet["AgentRole"] | {"bedrock:InvokeModel"}
    assert with_a_model["SecondRole"] == plain["SecondRole"]            # nor the model
    assert set().union(*with_a_model.values()) == {a for a, _ in _effect(BOUNDARIES[(True, True)], "Allow")}


def test_the_kits_own_policy_needs_nothing_for_a_model():
    """The test agent calls the model as its own role, under the boundary; the kit itself never calls Bedrock, and
    giving the agent's role a policy that allows it is iam:PutRolePolicy, already allowed under the boundary."""
    assert not {a for a in allowed() if a.startswith("bedrock:")}
    package = ROOT / "src" / "arvaken_stop_test"
    sources = {p.relative_to(package).as_posix(): p.read_text(encoding="utf-8") for p in package.rglob("*.py")}
    assert [name for name, text in sources.items() if '"bedrock-runtime"' in text] == ["aws/agent.py"]


def test_a_subnet_of_yours_is_named_in_the_functions_network_settings_and_nothing_else_of_yours_is():
    from arvaken_stop_test.aws.stack import template
    t = template("r0123abcd", "https://e.test", subnet="subnet-0abc1234",
                 security_groups=["sg-0abc1234", "sg-0def5678"])
    assert t["Resources"]["Agent"]["Properties"]["VpcConfig"] == {"SubnetIds": ["subnet-0abc1234"],
                                                                  "SecurityGroupIds": ["sg-0abc1234", "sg-0def5678"]}
    text = json.dumps({k: v for k, v in t["Resources"].items() if k != "Agent"})
    assert "subnet-" not in text and "sg-" not in text      # named only where the function is put in it
    assert set(t["Resources"]) == {"Bucket", "AgentRole", "SecondRole", "Agent"}
    assert "VpcConfig" not in json.dumps(template("r0123abcd", "https://e.test"))
    assert "logs:" not in json.dumps(t)                     # still no permission to write logs


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
