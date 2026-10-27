"""What the kit deploys for a run, as one CloudFormation stack (the design's section 3).

Every resource is named with the run's prefix, `arvaken-stop-test-<run>`, and tagged `arvaken-stop-test=<run>`:
- the test agent: a Lambda function with a role of its own, whose code is agent.py;
- what it acts on: a bucket of the kit's own (private, encrypted), and a second role the agent may assume;
- nothing else. The agent's role has no permission to write logs, and the agent prints nothing: it writes no logs
  of its own. The account's CloudTrail still records what the kit does, as it records any change.

The roles' permissions reach only the run's own bucket and the run's own second role. The kit touches nothing it did
not create, except to attach the customer's stop to the agent's role (fire.py).

Both roles carry the permissions boundary `arvaken-stop-test-boundary` (boundary.json), a policy your account holds
once, which allows no more than the roles' own policies need: objects in a run's bucket, and assuming a run's role. The
kit's policy (permissions/aws-policy.json) lets its holder make or change a role only with that boundary on it, so it
cannot make a role that reaches anything else.

**In a subnet the customer names (`--subnet`, `--security-group`; D561, section 5).** Where the customer's gateway is
reached only from their own network, the test agent's function is put in that subnet, with the security groups they
name. Lambda then makes the function's network interfaces there, as the function's role: that role alone is given the
six EC2 actions Lambda needs for it, those of AWS's managed policy AWSLambdaVPCAccessExecutionRole without its logs
actions, and the boundary allows them too (its statement NETWORK_SID). Nothing else of the customer's is attached or
changed: the subnet and the groups are named in the function's network settings, and nothing more. A run without a
subnet makes the role without them, and still takes the boundary as it was before that statement (fire.py).
"""
from __future__ import annotations

import ast
import json
import secrets
from collections.abc import Sequence
from importlib import resources
from typing import Any

PREFIX = "arvaken-stop-test"
TAG = "arvaken-stop-test"
BOUNDARY = f"{PREFIX}-boundary"
RUNTIME, MEMORY_MB, TIMEOUT_S = "python3.12", 128, 15
INLINE_LIMIT = 4096          # CloudFormation's limit on a function's inline code, in characters
# What Lambda needs of a function's role to make its network interfaces in a subnet: AWSLambdaVPCAccessExecutionRole's
# EC2 actions. AWS's Lambda guide says DescribeNetworkInterfaces works only on every resource, so each is on "*".
NETWORK_ACTIONS = ("ec2:CreateNetworkInterface", "ec2:DescribeNetworkInterfaces", "ec2:DescribeSubnets",
                   "ec2:DeleteNetworkInterface", "ec2:AssignPrivateIpAddresses", "ec2:UnassignPrivateIpAddresses")
NETWORK_SID = "TheTestAgentsNetworkInterfacesInASubnetYouName"


def new_run() -> str:
    """A run's name: r and eight hex digits, lower case, as resource names allow."""
    return "r" + secrets.token_hex(4)


def names(run: str) -> dict[str, str]:
    base = f"{PREFIX}-{run}"
    return {"stack": base, "function": f"{base}-agent", "agent_role": f"{base}-agent", "second_role": f"{base}-second"}


def boundary_document(network: bool = True) -> dict[str, Any]:
    """The permissions boundary on both roles, as permissions/aws-boundary.json gives it for your account to hold; with
    `network` False, as it was before its statement for a subnet's network interfaces (the kit's to 0.2.1)."""
    doc = json.loads(resources.files("arvaken_stop_test.aws").joinpath("boundary.json").read_text(encoding="utf-8"))
    if not network:
        doc["Statement"] = [s for s in doc["Statement"] if s.get("Sid") != NETWORK_SID]
    return doc


def agent_code() -> str:
    """agent.py as the function runs it: without its module docstring, which is for readers of this repository."""
    source = resources.files("arvaken_stop_test.aws").joinpath("agent.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    first = tree.body[0]
    if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str):
        source = "\n".join(source.splitlines()[first.end_lineno:]).lstrip("\n")
    if len(source) > INLINE_LIMIT:
        raise ValueError(f"the test agent's code is {len(source)} characters; CloudFormation takes {INLINE_LIMIT}")
    return source


def template(run: str, endpoint: str, outside_key: str | None = None, subnet: str = "",
             security_groups: Sequence[str] = ()) -> dict[str, Any]:
    """The run's stack. With a subnet, the function is in it, with the security groups named, and its role may make its
    network interfaces there; else the function is on Lambda's default network, as before."""
    n = names(run)
    tags = [{"Key": TAG, "Value": run}]
    second_arn = {"Fn::Sub": f"arn:${{AWS::Partition}}:iam::${{AWS::AccountId}}:role/{n['second_role']}"}
    boundary = {"Fn::Sub": f"arn:${{AWS::Partition}}:iam::${{AWS::AccountId}}:policy/{BOUNDARY}"}
    bucket_objects = lambda prefix: {"Fn::Sub": f"${{Bucket.Arn}}/{prefix}/*"}  # noqa: E731
    own = [{"Effect": "Allow", "Action": ["s3:PutObject", "s3:GetObject"], "Resource": bucket_objects("own")},
           {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": second_arn}]
    network: dict[str, Any] = {}
    if subnet:
        own.append({"Effect": "Allow", "Action": list(NETWORK_ACTIONS), "Resource": "*"})
        network = {"VpcConfig": {"SubnetIds": [subnet], "SecurityGroupIds": list(security_groups)}}
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": f"Arvaken stop test, run {run}: a test agent of the kit's own. Removed when the run ends.",
        "Resources": {
            "Bucket": {"Type": "AWS::S3::Bucket", "Properties": {
                "PublicAccessBlockConfiguration": {"BlockPublicAcls": True, "BlockPublicPolicy": True,
                                                   "IgnorePublicAcls": True, "RestrictPublicBuckets": True},
                "BucketEncryption": {"ServerSideEncryptionConfiguration": [
                    {"ServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]},
                "Tags": tags}},
            "AgentRole": {"Type": "AWS::IAM::Role", "Properties": {
                "RoleName": n["agent_role"], "PermissionsBoundary": boundary,
                "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [
                    {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]},
                "Policies": [{"PolicyName": "own-calls",
                              "PolicyDocument": {"Version": "2012-10-17", "Statement": own}}],
                "Tags": tags}},
            "SecondRole": {"Type": "AWS::IAM::Role", "Properties": {
                "RoleName": n["second_role"], "PermissionsBoundary": boundary,
                "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [
                    {"Effect": "Allow", "Principal": {"AWS": {"Fn::GetAtt": ["AgentRole", "Arn"]}},
                     "Action": "sts:AssumeRole"}]},
                "Policies": [{"PolicyName": "another-identity", "PolicyDocument": {"Version": "2012-10-17", "Statement": [
                    {"Effect": "Allow", "Action": "s3:PutObject", "Resource": bucket_objects("another")}]}}],
                "Tags": tags}},
            "Agent": {"Type": "AWS::Lambda::Function", "Properties": {
                "FunctionName": n["function"], "Runtime": RUNTIME, "Handler": "index.handler",
                "MemorySize": MEMORY_MB, "Timeout": TIMEOUT_S, "Role": {"Fn::GetAtt": ["AgentRole", "Arn"]},
                "Code": {"ZipFile": agent_code()},
                "Environment": {"Variables": {"BUCKET": {"Ref": "Bucket"}, "ENDPOINT": endpoint,
                                              "OUTSIDE_KEY": outside_key or secrets.token_hex(16),
                                              "SECOND_ROLE": second_arn}},
                **network, "Tags": tags}},
        },
        "Outputs": {
            "Bucket": {"Value": {"Ref": "Bucket"}},
            "Agent": {"Value": {"Fn::GetAtt": ["Agent", "Arn"]}},
            "AgentRole": {"Value": {"Fn::GetAtt": ["AgentRole", "Arn"]}},
            "SecondRole": {"Value": {"Fn::GetAtt": ["SecondRole", "Arn"]}},
        },
    }


def template_body(run: str, endpoint: str, outside_key: str | None = None, subnet: str = "",
                  security_groups: Sequence[str] = ()) -> str:
    return json.dumps(template(run, endpoint, outside_key, subnet, security_groups), indent=1, sort_keys=True)
