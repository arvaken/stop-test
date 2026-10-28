"""What the kit deploys for a run, as one CloudFormation stack (the design's section 3).

Every resource is named with the run's prefix, `arvaken-stop-test-<run>`, and tagged `arvaken-stop-test=<run>`:
- the test agent: a Lambda function with a role of its own, whose code is agent.py;
- what it acts on: a bucket of the kit's own (private, encrypted), and a second role the agent may assume;
- nothing else. The agent's role has no permission to write logs, and the agent prints nothing: it writes no logs
  of its own. The account's CloudTrail still records what the kit does, as it records any change.

The roles' permissions reach only the run's own bucket and the run's own second role. The kit touches nothing it did
not create, except to attach the customer's stop to the agent's role (fire.py).

Both roles carry the permissions boundary `arvaken-stop-test-boundary` (boundary.json), or in a subnet one of their
own (below): a policy your account holds once, which allows no more than the roles' own policies need: objects in a
run's bucket, and assuming a run's role. The kit's policy (permissions/aws-policy.json) lets its holder make or change a
role only with one of those boundaries on it; under arvaken-stop-test-boundary it cannot make a role that reaches
anything else.

**In a subnet the customer names (`--subnet`, `--security-group`; D561, section 5).** Where the customer's gateway is
reached only from their own network, the test agent's function is put in that subnet, with the security groups they
name. Lambda then makes the function's network interfaces there, as the function's role: that role alone is given the
six EC2 actions Lambda needs for it, those of AWS's managed policy AWSLambdaVPCAccessExecutionRole without its logs
actions. Nothing else of the customer's is attached or changed: the subnet and the groups are named in the function's
network settings, and nothing more. A run without a subnet makes the role without them.

**A call to a model (`--model`; the design's section 4, its optional fifth row).** Where the customer names a model, by
a Bedrock model's ID or a cross-Region inference profile's, the function's environment names it (MODEL) and the agent's
role alone is allowed `bedrock:InvokeModel` (which the agent's Converse call needs) on exactly what that ID needs
(model_resources): for a model's ID, that model in the run's region; for a profile's (its ID begins with its
geography, as `eu.` or `global.`: PROFILE_PREFIXES, from AWS's Bedrock guide on inference profiles), the profile in the
run's region and the model it names in every region, as AWS requires both for a profile that routes calls to other
regions. The second role is never given it. A run without a model makes the stack exactly as before. An ID is checked
for its shape (MODEL_ID) before it is written into the template, so it can name nothing but a model or a profile.

AWS's Lambda guide asks for those network actions on every resource ("allow them on all resources")
[source: aws-lambda-vpc-permissions], so a boundary that allows them lets any role made under it make, delete and
re-address network interfaces anywhere in the account: not what arvaken-stop-test-boundary may do. A run in a subnet's
roles therefore carry a boundary of their own, `arvaken-stop-test-boundary-via` (boundary_name), which your account
holds only where someone made it to run in a subnet: arvaken-stop-test-boundary and the statements NETWORK_STATEMENTS.
They allow the six actions, and deny them to any call from a function's own code, as an explicit deny in a boundary
overrides any allow [source: aws-iam-boundary-explicit-deny]: Lambda puts its function's ARN on those calls, and not on
the calls it makes itself to make a function's network interfaces (its guide, "Using source function ARN to control
function access behavior") [source: aws-lambda-source-function-arn], so the agent's code cannot make them, nor any other
function's under that boundary. Likewise a boundary is the same for every run, so for a model it allows
`bedrock:InvokeModel` on any model and any inference profile (MODEL_STATEMENTS): any role made under it may call any
model, billed to the account. A run with a model's roles carry `arvaken-stop-test-boundary-model`, or in a subnet too
`arvaken-stop-test-boundary-via-model`. A run with neither takes arvaken-stop-test-boundary, as before.
"""
from __future__ import annotations

import ast
import json
import re
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
# EC2 actions, each on "*" as AWS's Lambda guide asks [source: aws-lambda-vpc-permissions].
NETWORK_ACTIONS = ("ec2:CreateNetworkInterface", "ec2:DescribeNetworkInterfaces", "ec2:DescribeSubnets",
                   "ec2:DeleteNetworkInterface", "ec2:AssignPrivateIpAddresses", "ec2:UnassignPrivateIpAddresses")
NETWORK_SID = "TheTestAgentsNetworkInterfacesInASubnetYouName"
MODEL_SID = "TheTestAgentsCallToAModel"
# A Bedrock model's ID (provider.model, with a version after ":") or a cross-Region inference profile's (its geography,
# then a model's ID), and the geographies such a profile's ID begins with.
MODEL_ID = re.compile(r"[a-z0-9-]{1,63}(\.[a-z0-9-]{1,63}){1,2}(:[a-z0-9-]{1,63}){0,2}")
PROFILE_PREFIXES = ("us", "us-gov", "eu", "apac", "au", "jp", "ca", "global")
NETWORK_STATEMENTS = (
    {"Sid": NETWORK_SID, "Effect": "Allow", "Action": list(NETWORK_ACTIONS), "Resource": "*"},
    {"Sid": "NoneOfThemFromAFunctionsOwnCode", "Effect": "Deny", "Action": list(NETWORK_ACTIONS), "Resource": "*",
     "Condition": {"Null": {"lambda:SourceFunctionArn": "false"}}},
)
MODEL_STATEMENTS = (
    {"Sid": MODEL_SID, "Effect": "Allow", "Action": "bedrock:InvokeModel",
     "Resource": ["arn:aws:bedrock:*::foundation-model/*", "arn:aws:bedrock:*:*:inference-profile/*"]},
)


def new_run() -> str:
    """A run's name: r and eight hex digits, lower case, as resource names allow."""
    return "r" + secrets.token_hex(4)


def names(run: str) -> dict[str, str]:
    base = f"{PREFIX}-{run}"
    return {"stack": base, "function": f"{base}-agent", "agent_role": f"{base}-agent", "second_role": f"{base}-second"}


def boundary_name(network: bool = False, model: bool = False) -> str:
    """The permissions boundary a run's roles carry: arvaken-stop-test-boundary, or in a subnet, with a model, or both,
    one of their own."""
    return BOUNDARY + ("-via" if network else "") + ("-model" if model else "")


def boundary_file(network: bool = False, model: bool = False) -> str:
    """Where this repository gives that boundary for your account to hold."""
    return f"permissions/aws-{boundary_name(network, model).removeprefix(PREFIX + '-')}.json"


def boundary_document(network: bool = False, model: bool = False) -> dict[str, Any]:
    """The permissions boundary on both roles, as boundary_file gives it: the kit's (boundary.json, as to 0.2.1); in a
    subnet, that and NETWORK_STATEMENTS; with a model, that and MODEL_STATEMENTS."""
    doc = json.loads(resources.files("arvaken_stop_test.aws").joinpath("boundary.json").read_text(encoding="utf-8"))
    for wanted, more in ((network, NETWORK_STATEMENTS), (model, MODEL_STATEMENTS)):
        if wanted:
            doc["Statement"] += json.loads(json.dumps(more))
    return doc


def is_model_id(model: str) -> bool:
    return bool(MODEL_ID.fullmatch(model))


def model_resources(model: str) -> list[dict[str, str]]:
    """What the agent's role may invoke for this ID: a model in the run's region; or, for a cross-Region inference
    profile, the profile in the run's region and the model it names in every region (AWS requires both)."""
    if not is_model_id(model):
        raise ValueError("a model is named by a Bedrock model's ID or an inference profile's")
    geography, _, named = model.partition(".")
    if geography in PROFILE_PREFIXES and "." in named:
        return [{"Fn::Sub": f"arn:${{AWS::Partition}}:bedrock:${{AWS::Region}}:${{AWS::AccountId}}:inference-profile/"
                            f"{model}"},
                {"Fn::Sub": f"arn:${{AWS::Partition}}:bedrock:*::foundation-model/{named}"}]
    return [{"Fn::Sub": f"arn:${{AWS::Partition}}:bedrock:${{AWS::Region}}::foundation-model/{model}"}]


def agent_code() -> str:
    """agent.py as the function runs it: without its module docstring and its comments, which are for readers of this
    repository, and indented two spaces a level rather than four (_compact), to fit CloudFormation's inline limit. It is
    the same program: tests/test_agent.py holds its syntax tree to agent.py's."""
    source = resources.files("arvaken_stop_test.aws").joinpath("agent.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    first = tree.body[0]
    if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str):
        source = "\n".join(source.splitlines()[first.end_lineno:]).lstrip("\n")
    source = _compact(source)
    if len(source) > INLINE_LIMIT:
        raise ValueError(f"the test agent's code is {len(source)} characters; CloudFormation takes {INLINE_LIMIT}")
    return source


def _compact(source: str) -> str:
    """Python source without its comments, each statement indented half as far (four spaces a level become two), and
    each line continuing a statement moved left as far as its statement's first line, so it keeps its alignment."""
    import io
    import tokenize
    starts: dict[int, int] = {}         # each statement's first line, and how far it is indented
    comments: dict[int, int] = {}       # each comment's line, and its column
    new = True
    for tok in tokenize.generate_tokens(io.StringIO(source).readline):
        if tok.type == tokenize.COMMENT:
            comments[tok.start[0]] = tok.start[1]
        elif tok.type == tokenize.NEWLINE:
            new = True
        elif tok.type not in (tokenize.NL, tokenize.INDENT, tokenize.DEDENT, tokenize.ENDMARKER) and new:
            starts[tok.start[0]] = tok.start[1]
            new = False
    out, shift = [], 0
    for row, line in enumerate(source.splitlines(), 1):
        if row in comments:
            line = line[:comments[row]].rstrip()
            if not line:
                continue                # a line that was a comment alone
        if row in starts:
            shift = starts[row] // 2
        lead = len(line) - len(line.lstrip(" "))
        out.append(line[min(shift, lead):])
    return "\n".join(out)


def template(run: str, endpoint: str, outside_key: str | None = None, subnet: str = "",
             security_groups: Sequence[str] = (), model: str = "") -> dict[str, Any]:
    """The run's stack. With a subnet, the function is in it, with the security groups named, and its role may make its
    network interfaces there; else the function is on Lambda's default network, as before. With a model, the function's
    environment names it, and its role may invoke it (model_resources); else neither, as before."""
    n = names(run)
    tags = [{"Key": TAG, "Value": run}]
    second_arn = {"Fn::Sub": f"arn:${{AWS::Partition}}:iam::${{AWS::AccountId}}:role/{n['second_role']}"}
    boundary_arn = f"arn:${{AWS::Partition}}:iam::${{AWS::AccountId}}:policy/{boundary_name(bool(subnet), bool(model))}"
    boundary = {"Fn::Sub": boundary_arn}
    bucket_objects = lambda prefix: {"Fn::Sub": f"${{Bucket.Arn}}/{prefix}/*"}  # noqa: E731
    own = [{"Effect": "Allow", "Action": ["s3:PutObject", "s3:GetObject"], "Resource": bucket_objects("own")},
           {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": second_arn}]
    network: dict[str, Any] = {}
    if subnet:
        own.append({"Effect": "Allow", "Action": list(NETWORK_ACTIONS), "Resource": "*"})
        network = {"VpcConfig": {"SubnetIds": [subnet], "SecurityGroupIds": list(security_groups)}}
    variables = {"BUCKET": {"Ref": "Bucket"}, "ENDPOINT": endpoint, "OUTSIDE_KEY": outside_key or secrets.token_hex(16),
                 "SECOND_ROLE": second_arn}
    if model:
        own.append({"Effect": "Allow", "Action": "bedrock:InvokeModel", "Resource": model_resources(model)})
        variables["MODEL"] = model
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
                "Environment": {"Variables": variables},
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
                  security_groups: Sequence[str] = (), model: str = "") -> str:
    return json.dumps(template(run, endpoint, outside_key, subnet, security_groups, model), indent=1, sort_keys=True)
