"""What the kit deploys for a run, as one CloudFormation stack (the design's section 3).

Every resource is named with the run's prefix, `arvaken-stop-test-<run>`, and tagged `arvaken-stop-test=<run>`:
- the test agent: a Lambda function with a role of its own, whose code is agent.py;
- what it acts on: a bucket of the kit's own (private, encrypted), and a second role the agent may assume;
- nothing else. The agent's role has no permission to write logs, and the agent prints nothing, so a run leaves
  nothing in the account's logs.

The roles' permissions reach only the run's own bucket and the run's own second role. The kit touches nothing it did
not create, except to attach the customer's stop to the agent's role (fire.py).
"""
from __future__ import annotations

import ast
import json
import secrets
from importlib import resources
from typing import Any

PREFIX = "arvaken-stop-test"
TAG = "arvaken-stop-test"
RUNTIME, MEMORY_MB, TIMEOUT_S = "python3.12", 128, 15
INLINE_LIMIT = 4096          # CloudFormation's limit on a function's inline code, in characters


def new_run() -> str:
    """A run's name: r and eight hex digits, lower case, as resource names allow."""
    return "r" + secrets.token_hex(4)


def names(run: str) -> dict[str, str]:
    base = f"{PREFIX}-{run}"
    return {"stack": base, "function": f"{base}-agent", "agent_role": f"{base}-agent", "second_role": f"{base}-second"}


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


def template(run: str, endpoint: str, outside_key: str | None = None) -> dict[str, Any]:
    n = names(run)
    tags = [{"Key": TAG, "Value": run}]
    second_arn = {"Fn::Sub": f"arn:${{AWS::Partition}}:iam::${{AWS::AccountId}}:role/{n['second_role']}"}
    bucket_objects = lambda prefix: {"Fn::Sub": f"${{Bucket.Arn}}/{prefix}/*"}  # noqa: E731
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
                "RoleName": n["agent_role"],
                "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [
                    {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]},
                "Policies": [{"PolicyName": "own-calls", "PolicyDocument": {"Version": "2012-10-17", "Statement": [
                    {"Effect": "Allow", "Action": ["s3:PutObject", "s3:GetObject"], "Resource": bucket_objects("own")},
                    {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": second_arn}]}}],
                "Tags": tags}},
            "SecondRole": {"Type": "AWS::IAM::Role", "Properties": {
                "RoleName": n["second_role"],
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
                "Tags": tags}},
        },
        "Outputs": {
            "Bucket": {"Value": {"Ref": "Bucket"}},
            "Agent": {"Value": {"Fn::GetAtt": ["Agent", "Arn"]}},
            "AgentRole": {"Value": {"Fn::GetAtt": ["AgentRole", "Arn"]}},
            "SecondRole": {"Value": {"Fn::GetAtt": ["SecondRole", "Arn"]}},
        },
    }


def template_body(run: str, endpoint: str, outside_key: str | None = None) -> str:
    return json.dumps(template(run, endpoint, outside_key), indent=1, sort_keys=True)
