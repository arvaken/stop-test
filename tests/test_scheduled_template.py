"""The AWS template for a repeat you schedule (scripts/scheduled_template.py; the plan, wave 2, A, part 3), held to what
it promises: it is the script's own output; its kit role holds the kit's own policy word for word and, beyond it, only
kms:Sign on the runner's key, its own logs and its own bucket; the schedule may start that one project alone; the kit is
installed as the README's Install says; and nothing runs unless `stop-test due` said a run is due.
"""
from __future__ import annotations

import importlib.util
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("scheduled_template", ROOT / "scripts" / "scheduled_template.py")
st = importlib.util.module_from_spec(spec)
spec.loader.exec_module(st)
T = json.loads((ROOT / "templates" / "aws-scheduled-repeat.json").read_text(encoding="utf-8"))
R = T["Resources"]
BUILD = R["Repeat"]["Properties"]["Source"]["BuildSpec"]


def test_the_committed_template_is_the_scripts_output():
    assert (ROOT / "templates" / "aws-scheduled-repeat.json").read_text(encoding="utf-8") == st.text()
    assert subprocess.run(["python", str(ROOT / "scripts" / "scheduled_template.py"), "--check"]).returncode == 0


def test_the_kit_role_holds_the_kits_own_policy_and_three_things_more():
    assert R["KitsPolicy"]["Properties"]["PolicyDocument"] == json.loads(
        (ROOT / "permissions" / "aws-policy.json").read_text(encoding="utf-8"))
    role = R["RunsTheKit"]["Properties"]
    assert role["ManagedPolicyArns"] == [{"Ref": "KitsPolicy"}]
    [inline] = role["Policies"]
    more = inline["PolicyDocument"]["Statement"]
    assert [(s["Action"], s["Resource"]) for s in more] == [
        ("kms:Sign", {"Ref": "RunnerKeyArn"}),
        (["logs:CreateLogStream", "logs:PutLogEvents"], {"Fn::Sub": "${Logs.Arn}"}),
        ("s3:PutObject", {"Fn::Sub": "${Results.Arn}/*"})]
    assert all(s["Effect"] == "Allow" for s in more)
    assert role["AssumeRolePolicyDocument"]["Statement"][0]["Principal"] == {"Service": "codebuild.amazonaws.com"}


def test_the_schedule_may_start_that_one_project_alone():
    role = R["StartsTheRepeat"]["Properties"]
    [inline] = role["Policies"]
    assert inline["PolicyDocument"]["Statement"] == [
        {"Effect": "Allow", "Action": "codebuild:StartBuild", "Resource": {"Fn::GetAtt": ["Repeat", "Arn"]}}]
    assert "ManagedPolicyArns" not in role
    daily = R["Daily"]["Properties"]
    assert daily["ScheduleExpression"] == "rate(1 day)"
    assert daily["Target"] == {"Arn": {"Fn::GetAtt": ["Repeat", "Arn"]},
                               "RoleArn": {"Fn::GetAtt": ["StartsTheRepeat", "Arn"]}}


def test_the_kit_is_installed_as_the_readme_says():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    v = re.search(r"releases/download/v([0-9.]+)/requirements-", readme).group(1)
    for line in readme.splitlines():
        line = line.strip()
        if line.startswith(("curl -LO https://github.com/arvaken/stop-test/releases/download/v" + v + "/requirements-",
                            "stop-test/bin/python -m sigstore verify github requirements-")):
            ours = line.replace(v, "${KIT_VERSION}").replace("curl -LO", "curl -sSfLO").replace(
                "stop-test/bin/python", "/tmp/kit/bin/python")
            assert ours in BUILD, line
    assert "pip install --quiet --require-hashes -r requirements-${KIT_VERSION}.txt" in BUILD


def test_nothing_runs_unless_due_said_so():
    build = BUILD.split("  build:")[1].split("  post_build:")[0]
    asking, running = build.index("stop-test due"), build.index("stop-test aws run")
    assert asking < running
    between = build[asking:running]
    assert 'if [ "$asked" = 3 ]; then exit 0; fi' in between          # nothing due: a quiet success
    assert 'if [ "$asked" != 0 ]; then exit "$asked"; fi' in between   # no answer: the build fails, so it shows
    from arvaken_stop_test import due
    assert (due.DUE, due.NOT_DUE) == (0, 3)


def test_its_results_stay_in_its_own_bucket():
    bucket = R["Results"]["Properties"]
    assert bucket["PublicAccessBlockConfiguration"] == {k: True for k in (
        "BlockPublicAcls", "BlockPublicPolicy", "IgnorePublicAcls", "RestrictPublicBuckets")}
    assert R["Results"]["DeletionPolicy"] == "Retain"
    assert "s3://$RESULTS_BUCKET/" in BUILD and "arvaken.com" not in BUILD


def test_every_parameter_is_explained_and_the_kit_named_carries_due():
    assert set(T["Parameters"]) == set(st.PARAMS)
    assert all(p["Description"] for p in T["Parameters"].values())
    major, minor, _ = (int(x) for x in T["Parameters"]["KitVersion"]["Default"].split("."))
    assert (major, minor) >= (0, 7)                                    # the first release with `stop-test due`
