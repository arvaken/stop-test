"""The AWS template for a repeat you schedule (the plan, wave 2, A, part 3; the kit's terms, version 7 draft, 2.4).

    uv run python scripts/scheduled_template.py           # writes templates/aws-scheduled-repeat.json
    uv run python scripts/scheduled_template.py --check   # exit 1 if the committed template differs

A CloudFormation stack the customer deploys in its own account, with its own credentials. Once a day an EventBridge
schedule starts a CodeBuild project. The project installs the kit's release exactly as the README's Install says (its
requirements file checked with Sigstore against this repository's release workflow, then pip with --require-hashes),
asks `stop-test due`, and runs `stop-test aws run` only when a run is due. Its result is kept in a bucket of the stack's
own, in the customer's account; nothing is sent to Arvaken (sending is the customer's, as the app's send page has it).

Its role holds the kit's own policy (permissions/aws-policy.json), word for word, and one more statement: kms:Sign on
the customer's runner's key, for the due question alone (the founder's choice, 17:20:56 UTC on 25 November 2026). It
writes to its own log group and its own bucket. The schedule's role may start that one project and nothing else.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "permissions" / "aws-policy.json"
OUT = ROOT / "templates" / "aws-scheduled-repeat.json"
KIT_VERSION = "0.7.0"                  # the first release with `stop-test due`; the customer may name a later one

# CUSTOMER TEXT, awaiting the founder's approval (the plan, wave 2, A, part 3; A-TEMPLATE-WORDING.md).
DESCRIPTION = ("Arvaken stop test, repeated: once a day, asks Arvaken whether a run is due for one of your agents, and "
               "runs the stop test kit in your account only when it is. Everything here is yours to change or delete.")
PARAMS = {
    "RunnerKeyArn": "Your Arvaken runner's KMS key ARN. The daily question is signed with it, and nothing else is.",
    "EngagementId": "Your engagement's id, as your runner has it.",
    "AgentId": "The agent's id, from its page in the Arvaken app.",
    "StopPolicyArn": "Your declared stop: the managed policy's ARN, as you give it to stop-test aws run --stop.",
    "RunOptions": "More options for stop-test aws run, as you would type them. Leave it as it is for a quick run.",
    "KitVersion": "The stop test kit's release to install, checked against its signature before anything is installed.",
}


def buildspec() -> str:
    """The project's commands: install the release as the README says, ask, and run only when due. Exit 3 from
    `stop-test due` (nothing due) ends the build as a success; exit 1 (no answer) as a failure, so it shows."""
    v = "${KIT_VERSION}"
    lines = [
        "version: 0.2",
        "phases:",
        "  install:",
        "    commands:",
        "      - python3 -m venv /tmp/kit && /tmp/kit/bin/python -m pip install --quiet sigstore",
        f"      - curl -sSfLO https://github.com/arvaken/stop-test/releases/download/v{v}/requirements-{v}.txt",
        f"      - curl -sSfLO https://github.com/arvaken/stop-test/releases/download/v{v}/requirements-{v}.txt.sigstore.json",
        f"      - /tmp/kit/bin/python -m sigstore verify github requirements-{v}.txt --cert-identity "
        f"https://github.com/arvaken/stop-test/.github/workflows/release.yml@refs/tags/v{v}",
        f"      - /tmp/kit/bin/python -m pip install --quiet --require-hashes -r requirements-{v}.txt",
        "  build:",
        "    commands:",
        "      - |",
        "        set +e",
        "        /tmp/kit/bin/stop-test due --key \"$RUNNER_KEY_ARN\" --engagement \"$ENGAGEMENT_ID\" --agent \"$AGENT_ID\"",
        "        asked=$?",
        "        set -e",
        "        if [ \"$asked\" = 3 ]; then exit 0; fi",
        "        if [ \"$asked\" != 0 ]; then exit \"$asked\"; fi",
        "        /tmp/kit/bin/stop-test aws run --region \"$AWS_REGION\" --stop \"$STOP_POLICY_ARN\" $RUN_OPTIONS",
        "  post_build:",
        "    commands:",
        "      - for f in stop-test-*.json stop-test-*.html; do [ -e \"$f\" ] && aws s3 cp \"$f\" "
        "\"s3://$RESULTS_BUCKET/$CODEBUILD_BUILD_NUMBER/$f\"; done; true",
    ]
    return "\n".join(lines) + "\n"


def template() -> dict:
    policy = json.loads(POLICY.read_text(encoding="utf-8"))
    params = {name: {"Type": "String", "Description": text} for name, text in PARAMS.items()}
    params["RunOptions"]["Default"] = "--quick"
    params["KitVersion"]["Default"] = KIT_VERSION
    params["KitVersion"]["AllowedPattern"] = r"[0-9]+\.[0-9]+\.[0-9]+"
    params["RunnerKeyArn"]["AllowedPattern"] = r"arn:aws:kms:[a-z0-9-]+:[0-9]{12}:key/[0-9a-f-]{36}"
    project = "arvaken-stop-test-repeat"
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": DESCRIPTION,
        "Parameters": params,
        "Resources": {
            "Results": {"Type": "AWS::S3::Bucket", "DeletionPolicy": "Retain", "UpdateReplacePolicy": "Retain",
                        "Properties": {"PublicAccessBlockConfiguration": {
                            "BlockPublicAcls": True, "BlockPublicPolicy": True, "IgnorePublicAcls": True,
                            "RestrictPublicBuckets": True},
                            "BucketEncryption": {"ServerSideEncryptionConfiguration": [
                                {"ServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}}},
            "Logs": {"Type": "AWS::Logs::LogGroup",
                     "Properties": {"LogGroupName": f"/aws/codebuild/{project}", "RetentionInDays": 90}},
            "KitsPolicy": {"Type": "AWS::IAM::ManagedPolicy",
                           "Properties": {"Description": "The stop test kit's own policy, permissions/aws-policy.json",
                                          "PolicyDocument": policy}},
            "RunsTheKit": {"Type": "AWS::IAM::Role", "Properties": {
                "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [
                    {"Effect": "Allow", "Principal": {"Service": "codebuild.amazonaws.com"}, "Action": "sts:AssumeRole",
                     "Condition": {"StringEquals": {"aws:SourceAccount": {"Ref": "AWS::AccountId"}}}}]},
                "ManagedPolicyArns": [{"Ref": "KitsPolicy"}],
                "Policies": [{"PolicyName": "ItsQuestionLogsAndResults", "PolicyDocument": {
                    "Version": "2012-10-17", "Statement": [
                        {"Sid": "SignsTheDueQuestionWithTheRunnersKey", "Effect": "Allow", "Action": "kms:Sign",
                         "Resource": {"Ref": "RunnerKeyArn"},
                         "Condition": {"StringEquals": {"kms:SigningAlgorithm": "ECDSA_SHA_256"}}},
                        {"Sid": "WritesItsOwnLogs", "Effect": "Allow",
                         "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
                         "Resource": {"Fn::Sub": "${Logs.Arn}"}},
                        {"Sid": "KeepsItsResults", "Effect": "Allow", "Action": "s3:PutObject",
                         "Resource": {"Fn::Sub": "${Results.Arn}/*"}}]}}]}},
            "Repeat": {"Type": "AWS::CodeBuild::Project", "Properties": {
                "Name": project, "ServiceRole": {"Fn::GetAtt": ["RunsTheKit", "Arn"]}, "TimeoutInMinutes": 120,
                "Source": {"Type": "NO_SOURCE", "BuildSpec": buildspec()},
                "Artifacts": {"Type": "NO_ARTIFACTS"},
                "Environment": {"Type": "LINUX_CONTAINER", "ComputeType": "BUILD_GENERAL1_SMALL",
                                "Image": "aws/codebuild/amazonlinux-x86_64-standard:5.0",
                                "EnvironmentVariables": [
                                    {"Name": "RUNNER_KEY_ARN", "Value": {"Ref": "RunnerKeyArn"}},
                                    {"Name": "ENGAGEMENT_ID", "Value": {"Ref": "EngagementId"}},
                                    {"Name": "AGENT_ID", "Value": {"Ref": "AgentId"}},
                                    {"Name": "STOP_POLICY_ARN", "Value": {"Ref": "StopPolicyArn"}},
                                    {"Name": "RUN_OPTIONS", "Value": {"Ref": "RunOptions"}},
                                    {"Name": "KIT_VERSION", "Value": {"Ref": "KitVersion"}},
                                    {"Name": "RESULTS_BUCKET", "Value": {"Ref": "Results"}}]},
                "LogsConfig": {"CloudWatchLogs": {"Status": "ENABLED", "GroupName": {"Ref": "Logs"}}}}},
            "StartsTheRepeat": {"Type": "AWS::IAM::Role", "Properties": {
                "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [
                    {"Effect": "Allow", "Principal": {"Service": "scheduler.amazonaws.com"}, "Action": "sts:AssumeRole",
                     "Condition": {"StringEquals": {"aws:SourceAccount": {"Ref": "AWS::AccountId"}}}}]},
                "Policies": [{"PolicyName": "StartsThatProjectAlone", "PolicyDocument": {
                    "Version": "2012-10-17", "Statement": [
                        {"Effect": "Allow", "Action": "codebuild:StartBuild",
                         "Resource": {"Fn::GetAtt": ["Repeat", "Arn"]}}]}}]}},
            "Daily": {"Type": "AWS::Scheduler::Schedule", "Properties": {
                "ScheduleExpression": "rate(1 day)", "FlexibleTimeWindow": {"Mode": "FLEXIBLE", "MaximumWindowInMinutes": 60},
                "Target": {"Arn": {"Fn::GetAtt": ["Repeat", "Arn"]},
                           "RoleArn": {"Fn::GetAtt": ["StartsTheRepeat", "Arn"]}}}},
        },
        "Outputs": {"ResultsBucket": {"Value": {"Ref": "Results"}}},
    }


def text() -> str:
    return json.dumps(template(), indent=1) + "\n"


def main(argv: list[str]) -> int:
    if argv[1:] == ["--check"]:
        if not OUT.exists() or OUT.read_text(encoding="utf-8") != text():
            print(f"{OUT.relative_to(ROOT)} differs from what this script makes: run it without --check")
            return 1
        return 0
    OUT.write_text(text(), encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
