"""A run on a test copy of the customer's own Lambda function (D575; aws/your_copy.py), against test_aws_run's fake AWS
on its virtual clock, with the real probe (arvaken-stop-test-probe) answering each invocation of the copy.

The fake's copy is a function of the customer's: it runs as its own role until the customer points it at the run's role
(the `wait` it is given does what the customer would, where `points` says so), and back. While it runs as the run's
role, its own calls are refused once a stop on that role takes hold, as the kit's own agent's are; its calls under the
second role's session, once revoked. With `fails_after_stop`, the copy answers every invocation with an error of its
own once the stop takes hold, as an SDK's switch that ends the whole invocation would: Lambda's FunctionError, with
the error's type and a message that names things."""
from __future__ import annotations

import io
import json
import re
from datetime import datetime, timezone
from types import SimpleNamespace

import botocore.exceptions
import pytest

from arvaken_stop_test.aws import fire as firing
from arvaken_stop_test.aws import run as running
from arvaken_stop_test.aws import your_copy
from arvaken_stop_test.aws.stack import COPY_DESCRIPTION, NETWORK_ACTIONS, names, template
from arvaken_stop_test_probe import aws as probe_aws
from arvaken_stop_test_probe import core, heartbeat
from test_aws_run import STOP, ClientError, Clock, FakeAWS, clients

RUN = "r0123abcd"
COPY = "arn:aws:lambda:eu-central-1:123456789012:function:my-agent-test-copy"
OWN_ROLE = "arn:aws:iam::123456789012:role/my-agent-role"
RUNS_ROLE = f"arn:aws:iam::123456789012:role/{names(RUN)['agent_role']}"
SKEW = 0.05


class SwitchEngaged(Exception):
    """An in-agent SDK's own error, as its switch makes each call it guards raise one, its message naming things."""


class CopyClient:
    """A boto3 client in the copy, made by the copy's own cloud function: each call answered as the account would, and
    once the customer's SDK switch is on (`sdk_on_from`), refused by the SDK first."""

    def __init__(self, aws: CopyAWS, name: str, second: bool):
        self.aws, self.name, self.second = aws, name, second

    def _refused(self, op: str) -> None:
        aws = self.aws
        if aws.sdk_on_from is not None and aws.clock.now() >= aws.sdk_on_from:
            raise aws.sdk_raises("the SDK blocked a call as arn:aws:iam::123456789012:role/x")
        refused = (aws.session_issued is not None and aws.revoked_for("-second", aws.session_issued)) if self.second \
            else aws.copy_role == RUNS_ROLE and aws.stopped()
        if refused:
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "User arn:aws:sts::123456789012:assumed-role/x is not"},
                 "ResponseMetadata": {"HTTPStatusCode": 403}}, op)

    def put_object(self, Bucket, Key, Body):
        self._refused("PutObject")
        self.aws.objects.add(Key)

    def get_object(self, Bucket, Key):
        self._refused("GetObject")
        return {"Body": io.BytesIO(b"x")}

    def converse(self, modelId, inferenceConfig, messages):
        self._refused("Converse")
        return {"output": {"message": {"role": "assistant", "content": [{"text": "THE MODEL'S OWN WORDS"}]}}}

    def assume_role(self, RoleArn, RoleSessionName, DurationSeconds):
        self._refused("AssumeRole")
        self.aws.session_issued = self.aws.clock.now() + SKEW
        return {"Credentials": {"AccessKeyId": "k", "SecretAccessKey": "s", "SessionToken": "t",
                                "Expiration": datetime.fromtimestamp(self.aws.session_issued + 3600, tz=timezone.utc)}}


class CopyAWS(FakeAWS):
    """The account, with the customer's copy in it, as a run on a copy sees it."""

    def __init__(self, clock: Clock, *, copy_subnets=(), copy_groups=(), fails_after_stop=None, sdk_raises=SwitchEngaged,
                 **kw):
        super().__init__(clock, **kw)
        self.copy_role, self.copy_subnets, self.fails_after_stop = OWN_ROLE, list(copy_subnets), fails_after_stop
        self.copy_groups = list(copy_groups)
        self.role_deleted = False
        # the customer's in-agent SDK: when its switch is on, and what each call it guards then raises
        self.sdk_on_from: float | None = None
        self.sdk_raises = sdk_raises
        # how Lambda's last change to the copy ended, and the customer's own key for its settings, if any
        self.update_status, self.kms_key = "Successful", None
        self.cloud = lambda name, config=None, **creds: CopyClient(self, name, "aws_access_key_id" in creds)

    def create_stack(self, StackName, TemplateBody, Capabilities, Tags):
        self.stack = {"name": StackName, "template": json.loads(TemplateBody), "status": "CREATE_COMPLETE",
                      "run": Tags[0]["Value"], "body": TemplateBody}

    def describe_stacks(self, StackName):
        if self.gone():
            raise ClientError("ValidationError", f"Stack with id {StackName} does not exist")
        n = names(self.stack["run"])
        return {"Stacks": [{"StackStatus": self.stack["status"], "Outputs": [
            {"OutputKey": "Bucket", "OutputValue": f"{n['stack']}-bucket-abc"},
            {"OutputKey": "AgentRole", "OutputValue": RUNS_ROLE},
            {"OutputKey": "SecondRole", "OutputValue": f"arn:aws:iam::123456789012:role/{n['second_role']}"}]}]}

    def get_function_configuration(self, FunctionName):
        assert FunctionName == COPY, FunctionName
        return {"Role": self.copy_role, "LastUpdateStatus": self.update_status,
                "VpcConfig": {"SubnetIds": self.copy_subnets, "SecurityGroupIds": self.copy_groups},
                **({"KMSKeyArn": self.kms_key} if self.kms_key else {})}

    def get_function(self, FunctionName):
        raise AssertionError("a run on a copy never asks for the kit's own function")

    def get_role(self, RoleName):
        if RoleName.endswith("-agent"):                 # kept by CloudFormation, until the kit deletes it
            if self.stack is None or self.role_deleted:
                raise ClientError("NoSuchEntity", f"The role with name {RoleName} cannot be found.")
            return {"Role": {"RoleName": RoleName}}
        return super().get_role(RoleName)

    def delete_role(self, RoleName):
        assert RoleName.endswith("-agent") and self.copy_role != RUNS_ROLE
        self.role_deleted = True

    def invoke(self, FunctionName, Payload):
        assert FunctionName == COPY, FunctionName
        self.invocations += 1
        self.clock.t += 0.1
        event = json.loads(Payload)
        self.payloads.append(event)
        if self.fails_after_stop and self.copy_role == RUNS_ROLE and self.stopped():
            body = {"errorType": self.fails_after_stop, "errorMessage": "the SDK stopped arn:aws:iam::123456789012"}
            self.clock.t += 0.1
            return {"Payload": io.BytesIO(json.dumps(body).encode()), "FunctionError": "Unhandled"}
        try:
            body = heartbeat.run(event, cloud=self.cloud, http=self.http)
        except Exception as e:  # noqa: BLE001 - the copy's error, as Lambda returns it
            body, self.clock.t = {"errorType": type(e).__name__, "errorMessage": str(e)}, self.clock.t + 0.1
            return {"Payload": io.BytesIO(json.dumps(body).encode()), "FunctionError": "Unhandled"}
        self.clock.t += 0.1
        return {"Payload": io.BytesIO(json.dumps(body).encode())}

    def http(self, url, headers, timeout):
        """The copy's own HTTP client: answered, until the customer's SDK switch refuses it."""
        if self.sdk_on_from is not None and self.clock.now() >= self.sdk_on_from:
            raise self.sdk_raises(f"the SDK blocked a call to {url}")
        return 200


@pytest.fixture(autouse=True)
def fresh_clients(monkeypatch):
    """The probe's clients made anew for each test, as for a copy in a new environment."""
    monkeypatch.setattr(probe_aws, "_MADE", {})
    yield


def a_copy_run(aws: CopyAWS, clock: Clock, monkeypatch, *, typed=RUN, warned=RUN, points=("at", "back"),
               answers: dict | None = None, fires_after: float | None = None, **over):
    stamp = SimpleNamespace(time=lambda: clock.now() + SKEW)
    for module in (core, probe_aws, heartbeat):
        monkeypatch.setattr(module, "time", stamp)
    said, asked = [], []

    def confirm(words: str) -> str:
        asked.append(words)
        if answers and words in answers:             # an answer known only once the run has fired is a function
            return answers[words]() if callable(answers[words]) else answers[words]
        return warned if words == your_copy.WARNING else typed

    def wait(words: str) -> None:
        asked.append(words)
        if words.startswith("Point your copy at") and "at" in points:
            aws.copy_role = RUNS_ROLE
        elif words.startswith("Point your copy back") and "back" in points:
            aws.copy_role = OWN_ROLE
        elif words == running.MARK_PROMPT and fires_after is not None:     # Enter, then the customer fires their SDK's
            aws.sdk_on_from = clock.now() + fires_after

    kw = dict(window=60.0, clock=running.Clock(clock.now, clock.sleep), run_name=RUN, say=said.append,
              confirm=confirm, wait=wait)
    kw.update(over)
    c = clients(aws)
    c.region = "eu-central-1"
    return your_copy.run(c, COPY, over.pop("stop_ref", STOP), **{k: v for k, v in kw.items() if k != "stop_ref"}), \
        said, asked


@pytest.fixture
def an_account(monkeypatch):
    """The fake account's caller is in the copy's account."""
    monkeypatch.setattr(FakeAWS, "get_caller_identity", lambda self: {"Account": "123456789012",
                                                                      "Arn": "arn:aws:sts::123456789012:assumed-role/x"})


def test_a_run_on_a_copy_fires_on_the_runs_role_alone_and_times_the_copys_own_calls(an_account, monkeypatch):
    clock = Clock()
    aws = CopyAWS(clock)
    r, said, asked = a_copy_run(aws, clock, monkeypatch)

    outcomes = {p: f.outcome for p, f in running.results(r)[0][1].items()}
    assert outcomes == {"own_calls": "stopped", "another_identity": "not stopped", "outside_key": "not stopped",
                        "open_internet": "not stopped"}
    # every invocation went to the copy, with the run's settings in the kit's marker, and the probe took them
    assert aws.invocations and all(set(p) == {running.MARKER} for p in aws.payloads)
    marker = aws.payloads[-1][running.MARKER]
    assert (marker["run"], marker["bucket"]) == (RUN, f"arvaken-stop-test-{RUN}-bucket-abc")
    assert re.fullmatch(r"[0-9a-f]{32}", marker["key"]) and r.clients == {"cloud": {"customer"}, "http": {"customer"}}
    # the customer was asked, in order: to confirm a test copy, to point it at the run's role, before firing, and back
    assert [a.split()[0:3] for a in asked] == [["The", "kit", "will"], ["Point", "your", "copy"],
                                               your_copy.WARNING.split()[0:3], ["Point", "your", "copy"]]
    assert asked[2] == your_copy.WARNING
    # nothing of the kit's is left: the stop off, the stack deleted, and the run's role deleted once the copy left it
    assert not aws.attached and aws.stack["status"] == "DELETED" and aws.role_deleted and aws.copy_role == OWN_ROLE
    assert r.left_behind == [] and f"the role {names(RUN)['agent_role']}" in r.checked_gone
    assert not any("function" in x or "log group" in x for x in r.checked_gone)


def test_the_stack_for_a_copy_has_no_function_and_keeps_the_role_for_the_kit_to_remove():
    t = template(RUN, "", copy=COPY)
    assert "Agent" not in t["Resources"] and "Agent" not in t["Outputs"]
    assert t["Resources"]["AgentRole"]["DeletionPolicy"] == "Retain"
    assert t["Description"] == COPY_DESCRIPTION.format(run=RUN, copy=COPY) and len(t["Description"]) <= 1024
    role = t["Resources"]["AgentRole"]["Properties"]
    # its trust is Lambda's alone; what the copy's code uses, it gets only from the copy (the founder's ruling)
    assert role["AssumeRolePolicyDocument"]["Statement"] == [
        {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]
    assert all(s["Condition"] == {"StringEquals": {"lambda:SourceFunctionArn": COPY}}
               for s in role["Policies"][0]["PolicyDocument"]["Statement"])
    second = t["Resources"]["SecondRole"]["Properties"]["AssumeRolePolicyDocument"]["Statement"]
    assert second == [{"Effect": "Allow", "Principal": {"AWS": {"Fn::GetAtt": ["AgentRole", "Arn"]}},
                       "Action": "sts:AssumeRole"}]
    assert template(RUN, "")["Resources"]["AgentRole"].get("DeletionPolicy") is None      # the kit's own, as before
    boundary = t["Resources"]["AgentRole"]["Properties"]["PermissionsBoundary"]["Fn::Sub"]
    assert boundary.endswith(":policy/arvaken-stop-test-boundary")


def test_a_copy_in_a_vpc_has_a_role_with_lambdas_network_actions_under_the_subnet_runs_boundary(an_account,
                                                                                                 monkeypatch):
    clock = Clock()
    aws = CopyAWS(clock, copy_subnets=["subnet-0abc1234", "subnet-0def5678"], copy_groups=["sg-0abc1234"])
    a_copy_run(aws, clock, monkeypatch)
    role = aws.stack["template"]["Resources"]["AgentRole"]["Properties"]
    assert role["PermissionsBoundary"]["Fn::Sub"].endswith(":policy/arvaken-stop-test-boundary-via")
    statements = role["Policies"][0]["PolicyDocument"]["Statement"]
    granted = {a for s in statements for a in ([s["Action"]] if isinstance(s["Action"], str) else s["Action"])}
    assert set(NETWORK_ACTIONS) <= granted
    assert "VpcConfig" not in json.dumps(aws.stack["template"])          # the copy's network is the customer's


def test_a_copys_network_actions_reach_only_its_own_subnets_and_security_groups_where_ec2_lets_a_policy_name_them():
    """The founder's ruling on batch 1's fills: "limited to {copy}'s own subnets and security groups wherever AWS
    supports that condition (sourced). Otherwise they are listed as AWS requires." """
    arn = lambda kind, name: {   # noqa: E731
        "Fn::Sub": f"arn:${{AWS::Partition}}:ec2:${{AWS::Region}}:${{AWS::AccountId}}:{kind}/{name}"}
    vpc = {"SubnetIds": ["subnet-0abc1234", "subnet-0def5678"], "SecurityGroupIds": ["sg-0abc1234"],
           "VpcId": "vpc-0abc1234"}
    statements = template(RUN, "", copy=COPY, network=vpc)["Resources"]["AgentRole"]["Properties"]["Policies"][0][
        "PolicyDocument"]["Statement"]
    network = [s for s in statements if "ec2:" in json.dumps(s["Action"])]
    subnets = [arn("subnet", "subnet-0abc1234"), arn("subnet", "subnet-0def5678")]
    assert network == [
        {"Effect": "Allow", "Action": "ec2:CreateNetworkInterface",
         "Resource": [*subnets, arn("security-group", "sg-0abc1234"), arn("network-interface", "*")]},
        {"Effect": "Allow",
         "Action": ["ec2:DeleteNetworkInterface", "ec2:AssignPrivateIpAddresses", "ec2:UnassignPrivateIpAddresses"],
         "Resource": arn("network-interface", "*"), "Condition": {"ArnEquals": {"ec2:Subnet": subnets}}},
        {"Effect": "Allow", "Action": ["ec2:DescribeNetworkInterfaces", "ec2:DescribeSubnets"], "Resource": "*"}]
    # Lambda's own calls for the interfaces carry no function ARN, so none of them takes the copy's condition; every
    # other statement does
    assert all(s["Condition"] == {"StringEquals": {"lambda:SourceFunctionArn": COPY}}
               for s in statements if s not in network)
    assert not [s for s in template(RUN, "", copy=COPY)["Resources"]["AgentRole"]["Properties"]["Policies"][0][
        "PolicyDocument"]["Statement"] if "ec2:" in json.dumps(s["Action"])]       # a copy in no VPC gets none
    for bad in ({"SubnetIds": ["subnet-0abc1234"], "SecurityGroupIds": ["sg-*"]},
                {"SubnetIds": ["subnet-*"], "SecurityGroupIds": ["sg-0abc1234"]}):
        with pytest.raises(ValueError):
            template(RUN, "", copy=COPY, network=bad)


def test_nothing_is_made_unless_the_runs_name_is_typed_to_confirm_a_test_copy(an_account, monkeypatch):
    clock = Clock()
    aws = CopyAWS(clock)
    with pytest.raises(firing.Refused, match="nothing was made"):
        a_copy_run(aws, clock, monkeypatch, typed="yes")
    assert aws.stack is None and aws.invocations == 0


@pytest.mark.parametrize("arn", [
    "arn:aws:lambda:us-east-1:123456789012:function:my-agent-test-copy",         # another region
    "arn:aws:lambda:eu-central-1:999999999999:function:my-agent-test-copy",      # another account
    "arn:aws:lambda:eu-central-1:123456789012:function:my-agent-test-copy:live",  # an alias
    "my-agent-test-copy",
])
def test_a_copy_not_named_as_a_function_in_this_account_and_region_is_refused_before_anything(an_account, arn):
    clock = Clock()
    aws = CopyAWS(clock)
    c = clients(aws)
    with pytest.raises(ValueError, match="Lambda function's ARN"):
        your_copy.run(c, arn, STOP, confirm=lambda w: RUN, wait=lambda w: None, run_name=RUN)
    assert aws.stack is None


def test_a_copy_not_pointed_at_the_runs_role_is_not_timed_and_the_role_is_removed(an_account, monkeypatch):
    clock = Clock()
    aws = CopyAWS(clock)
    with pytest.raises(running.NotStarted, match="does not run as the run's role"):
        a_copy_run(aws, clock, monkeypatch, points=())
    assert aws.invocations == 0 and not aws.attach_calls and aws.role_deleted and aws.stack["status"] == "DELETED"


def test_without_the_runs_name_typed_before_firing_nothing_is_fired(an_account, monkeypatch):
    clock = Clock()
    aws = CopyAWS(clock)
    r, said, asked = a_copy_run(aws, clock, monkeypatch, warned="")
    assert not aws.attach_calls and r.repeats == [] and your_copy.NOT_FIRED in said
    assert aws.role_deleted and aws.copy_role == OWN_ROLE


def test_a_copy_still_running_as_the_runs_role_keeps_it_and_it_is_named_for_the_customer(an_account, monkeypatch):
    clock = Clock()
    aws = CopyAWS(clock)
    r, _, _ = a_copy_run(aws, clock, monkeypatch, points=("at",))
    role = names(RUN)["agent_role"]
    assert not aws.role_deleted and not aws.attached          # the stop is off; the role stays, as the copy runs as it
    assert r.left_behind == [your_copy.STILL_RUNS_AS.format(role=role, copy=COPY)]


def test_a_copys_own_error_after_the_stop_is_on_every_path_by_its_type_and_never_its_message(an_account,
                                                                                              monkeypatch):
    clock = Clock()
    aws = CopyAWS(clock, fails_after_stop="SwitchEngaged")
    r, _, _ = a_copy_run(aws, clock, monkeypatch)
    after = [b for p in r.paths for b in r.repeats[0].beats[p] if not b.ok]
    assert after and {b.error for b in after} >= {running.COPY_ERROR + "SwitchEngaged"}
    assert "SDK stopped" not in json.dumps([vars(b) for b in after], default=str)


def test_a_copy_whose_probe_refuses_the_marker_has_no_path_working_and_nothing_is_timed(an_account, monkeypatch):
    clock = Clock()
    aws = CopyAWS(clock)
    real = CopyAWS.describe_stacks

    def another_runs_bucket(self, StackName):
        found = real(self, StackName)
        found["Stacks"][0]["Outputs"][0]["OutputValue"] = "someone-elses-bucket"
        return found

    monkeypatch.setattr(CopyAWS, "describe_stacks", another_runs_bucket)
    with pytest.raises(running.NotStarted, match="No path worked"):
        a_copy_run(aws, clock, monkeypatch)
    assert not aws.attach_calls and aws.role_deleted


def test_the_kits_marker_is_the_probes():
    assert running.MARKER == core.MARKER


def test_the_kits_policy_does_not_reach_a_copy_and_the_copys_own_policy_reaches_it_alone():
    """The kit's policy invokes the run's own functions alone. A copy is the customer's, so reading it and calling it
    are a policy of their own (permissions/aws-copy-policy.json, D575 step 4, a draft for the founder), naming the
    customer's copy in place of YOUR-TEST-COPY, and allowing exactly what a run on a copy calls on it."""
    from pathlib import Path
    root = Path(__file__).resolve().parents[1] / "permissions"
    policy = json.loads((root / "aws-policy.json").read_text(encoding="utf-8"))
    reach = {r for s in policy["Statement"] for r in ([s["Resource"]] if isinstance(s["Resource"], str) else
                                                      s["Resource"])
             if "lambda:InvokeFunction" in ([s["Action"]] if isinstance(s["Action"], str) else s["Action"])}
    assert reach and all(":function:arvaken-stop-test-" in r for r in reach)
    copy = json.loads((root / "aws-copy-policy.json").read_text(encoding="utf-8"))
    [lambdas] = [s for s in copy["Statement"] if s["Sid"] == "YourTestCopyOnLambda"]
    assert set(lambdas["Action"]) == {"lambda:GetFunctionConfiguration", "lambda:InvokeFunction"}
    assert lambdas["Resource"] == "arn:aws:lambda:REGION:ACCOUNT:function:YOUR-TEST-COPY"
    source = (Path(your_copy.__file__)).read_text(encoding="utf-8")
    assert set(re.findall(r"c\.lambda_\.([a-z_]+)\(", source)) == {"get_function_configuration"}



def test_a_copy_whose_settings_use_your_own_key_is_refused_before_anything_is_made(an_account, monkeypatch):
    clock = Clock()
    aws = CopyAWS(clock)
    aws.kms_key = "arn:aws:kms:eu-central-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab"
    with pytest.raises(firing.Refused, match="encrypted with your own key"):
        a_copy_run(aws, clock, monkeypatch)
    assert aws.stack is None


def test_a_copy_whose_update_did_not_succeed_is_not_timed(an_account, monkeypatch):
    clock = Clock()
    aws = CopyAWS(clock)
    aws.update_status = "Failed"
    with pytest.raises(running.NotStarted, match="does not run as the run's role"):
        a_copy_run(aws, clock, monkeypatch)
    assert aws.invocations == 0


def test_at_cleanup_the_copy_is_asked_back_before_anything_is_removed(an_account, monkeypatch):
    clock = Clock()
    aws = CopyAWS(clock)
    roles_at_removal = []
    real = CopyAWS.detach_role_policy

    def detach(self, RoleName, PolicyArn):
        roles_at_removal.append(self.copy_role)      # the copy's role when the kit takes the stop off
        return real(self, RoleName=RoleName, PolicyArn=PolicyArn)

    monkeypatch.setattr(CopyAWS, "detach_role_policy", detach)
    r, _, _ = a_copy_run(aws, clock, monkeypatch)
    assert set(roles_at_removal) <= {OWN_ROLE} and aws.role_deleted and r.left_behind == []
