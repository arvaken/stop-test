"""What the kit makes for a run on AgentCore, and its names (arvaken/mark, AGENTCORE-MEASUREMENT.md, section 1; D618).
run.py makes it, in the order below, and removes it.

Every name carries the run, and everything that takes a tag is tagged `arvaken-stop-test=<run>`:
- the test agent: an AgentCore runtime, `arvaken_stop_test_<run>` (AgentCore's names take letters, digits and
  underscores alone), built from code in S3: PYTHON_3_13, entry point main.py, network mode PUBLIC, protocol HTTP;
- its role, `arvaken-stop-test-<run>-agent`, which trusts AgentCore alone and only for this run's runtime, by
  `aws:SourceAccount` and `aws:SourceArn`, as AWS's trust policy for a runtime's role has them;
- a second role, `arvaken-stop-test-<run>-second`, which the agent's role alone may assume;
- a bucket, `arvaken-stop-test-<run>` (private, encrypted), holding the agent's code (CODE_KEY) and the objects its
  paths write.

The roles are named as the Lambda agent's are (aws/stack.py), so the kit fires and removes a policy on the agent's role
the same way (aws/fire.py). Both carry the kit's permissions boundary, and their policies are what the boundary already
allows, objects in a run's bucket and assuming a run's role: AgentCore needs no change to it. The agent's role is given
nothing to read its code and nothing to write logs: it reaches only what the agent's paths use. AWS's pages on direct
code deployment differ on whether a runtime's role must read its code; the trial run in Arvaken's install-test account
(28 October 2026) is where the kit finds out.

**The runtime's session limits are the kit's** (`lifecycleConfiguration`): a session idle for IDLE seconds ends, and none
lives past MAX_LIFETIME, an hour, which is also the longest a streaming response lasts. Each run's details record them
(run.py), as the outcome of a running session is worded with them (the design's section 5).

**The code** is the test agent (agent.py) as main.py, with boto3 and the libraries it needs beside it (SHIPPED), copied
from the kit's own installation: each is pure Python, so it runs on AgentCore's arm64 Python as it is. The zip is made
the same way every time from the same files (sorted, with a fixed date and permissions), so its SHA-256 says which code
ran; each file is readable by all (644), as AgentCore needs.

AgentCore makes the runtime's DEFAULT endpoint and its workload identity itself; deleting the runtime removes them, and
the teardown checks each gone by its own identifier (run.py). Everything is made by AWS's own calls, in order, rather
than as a CloudFormation stack: each thing has a name the kit can find again from the run's name alone, so `clean`
removes what an interrupted run made.
"""
from __future__ import annotations

import hashlib
import importlib
import io
import json
import secrets
import zipfile
from importlib import resources
from pathlib import Path
from typing import Any

from arvaken_stop_test.aws.stack import BOUNDARY, PREFIX, TAG

RUNTIME = "PYTHON_3_13"
ENTRY_POINT = "main.py"
NETWORK_MODE, PROTOCOL = "PUBLIC", "HTTP"
IDLE = 60                   # seconds an idle session lasts: AgentCore's least
MAX_LIFETIME = 3600         # the longest a session lives: an hour, the longest a streaming response lasts
CODE_KEY = "code/agent.zip"
# What the test agent imports beyond the standard library: boto3 and what it needs, each by its import name.
SHIPPED = ("boto3", "botocore", "s3transfer", "jmespath", "dateutil", "six", "urllib3")
ZIP_DATE = (1980, 1, 1, 0, 0, 0)


def names(run: str) -> dict[str, str]:
    base = f"{PREFIX}-{run}"
    return {"runtime": f"{PREFIX.replace('-', '_')}_{run}", "agent_role": f"{base}-agent",
            "second_role": f"{base}-second", "bucket": base}


def _files(name: str) -> list[tuple[str, Path]]:
    """A shipped library's files, each with its path in the zip: its package's, or its one module's."""
    found = Path(importlib.import_module(name).__file__)
    if found.name != "__init__.py":
        return [(found.name, found)]
    root = found.parent
    return [(f"{name}/{p.relative_to(root).as_posix()}", p) for p in root.rglob("*")
            if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc"]


def agent_source() -> str:
    return resources.files("arvaken_stop_test.agentcore").joinpath("agent.py").read_text(encoding="utf-8")


def code_zip() -> bytes:
    """The runtime's code: the test agent as main.py, and the libraries it imports, the same bytes from the same files."""
    entries = [(ENTRY_POINT, agent_source().encode("utf-8"))]
    entries += [(arcname, path.read_bytes()) for name in SHIPPED for arcname, path in _files(name)]
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for arcname, data in sorted(entries):
            info = zipfile.ZipInfo(arcname, ZIP_DATE)
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, data)
    return out.getvalue()


def code_sha256(code: bytes) -> str:
    return hashlib.sha256(code).hexdigest()


def runtime_arn_pattern(run: str, region: str, account: str, partition: str = "aws") -> str:
    """Every ARN the run's runtime may have: AgentCore adds a suffix to its name."""
    return f"arn:{partition}:bedrock-agentcore:{region}:{account}:runtime/{names(run)['runtime']}-*"


def trust(run: str, region: str, account: str, partition: str = "aws") -> dict[str, Any]:
    """The agent's role trusts AgentCore alone, for this run's runtime alone."""
    return {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "bedrock-agentcore.amazonaws.com"}, "Action": "sts:AssumeRole",
        "Condition": {"StringEquals": {"aws:SourceAccount": account},
                      "ArnLike": {"aws:SourceArn": runtime_arn_pattern(run, region, account, partition)}}}]}


def own_policy(run: str, account: str, partition: str = "aws") -> dict[str, Any]:
    """The agent's own calls: its objects in the run's bucket, and assuming the run's second role."""
    n = names(run)
    return {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["s3:PutObject", "s3:GetObject"],
         "Resource": f"arn:{partition}:s3:::{n['bucket']}/own/*"},
        {"Effect": "Allow", "Action": "sts:AssumeRole",
         "Resource": f"arn:{partition}:iam::{account}:role/{n['second_role']}"}]}


def second_trust(agent_role_arn: str) -> dict[str, Any]:
    return {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": agent_role_arn}, "Action": "sts:AssumeRole"}]}


def second_policy(run: str, partition: str = "aws") -> dict[str, Any]:
    return {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "s3:PutObject", "Resource": f"arn:{partition}:s3:::{names(run)['bucket']}/another/*"}]}


def boundary_arn(account: str, partition: str = "aws") -> str:
    return f"arn:{partition}:iam::{account}:policy/{BOUNDARY}"


def runtime_request(run: str, region: str, role_arn: str, endpoint: str, second_role_arn: str,
                    outside_key: str | None = None) -> dict[str, Any]:
    """CreateAgentRuntime's request for the run's test agent."""
    n = names(run)
    return {
        "agentRuntimeName": n["runtime"],
        "description": f"Arvaken stop test, run {run}: a test agent of the kit's own. Removed when the run ends.",
        "agentRuntimeArtifact": {"codeConfiguration": {
            "code": {"s3": {"bucket": n["bucket"], "prefix": CODE_KEY}}, "runtime": RUNTIME,
            "entryPoint": [ENTRY_POINT]}},
        "roleArn": role_arn,
        "networkConfiguration": {"networkMode": NETWORK_MODE},
        "protocolConfiguration": {"serverProtocol": PROTOCOL},
        "lifecycleConfiguration": {"idleRuntimeSessionTimeout": IDLE, "maxLifetime": MAX_LIFETIME},
        "environmentVariables": {"BUCKET": n["bucket"], "ENDPOINT": endpoint,
                                 "OUTSIDE_KEY": outside_key or secrets.token_hex(16), "SECOND_ROLE": second_role_arn},
        "tags": {TAG: run},
    }


def to_json(doc: dict[str, Any]) -> str:
    return json.dumps(doc, separators=(",", ":"))


def private_bucket(s3: Any, bucket: str, region: str, run: str) -> None:
    """A bucket of the run's: in its region, every kind of public access blocked, encrypted at rest, and tagged."""
    s3.create_bucket(Bucket=bucket, **({} if region == "us-east-1" else
                                       {"CreateBucketConfiguration": {"LocationConstraint": region}}))
    s3.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "BlockPublicPolicy": True, "IgnorePublicAcls": True, "RestrictPublicBuckets": True})
    s3.put_bucket_encryption(Bucket=bucket, ServerSideEncryptionConfiguration={
        "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": TAG, "Value": run}]})
