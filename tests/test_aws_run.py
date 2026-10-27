"""A whole run on AWS, against a fake AWS on a virtual clock (the design's sections 3 to 8; D532, K3, K4, K8).

The fake holds what the kit's run depends on, as this file's reading of AWS's documented behaviour, not AWS's own
answer: a managed policy attached to a role takes effect after a propagation delay (8 seconds here); CloudTrail records
the attach call some time later (two minutes here), its time to the second; a deleted stack is no longer described;
anything the stack could not delete keeps its tag. Each case's expectations are worked out by hand from those rules.

What is gone is answered as AWS answers it, by each service's own error code (NoSuchEntity, ResourceNotFoundException,
404, and CloudFormation's ValidationError "does not exist"). Revoking a role's sessions (AWSRevokeOlderSessions) denies
each session of that role issued before its moment, after the same propagation delay; the agent's own session was
issued before the run, and the second role's when the kit asked the agent to assume it.

Through a gateway (--via; D561): an invocation that names the gateway has each path's call made through it; a path the
gateway refuses fails by ProxyConnectionError, and so does every path once the customer's own switch is on, `gw_delay`
seconds after they turn it on (3 here). The session for the other identity is taken through it too: where the gateway
refuses it, the agent answers with Lambda's error payload, and no session. In a subnet: Lambda makes one network
interface for the function, in the subnet with its security groups, described by the function's name; AWS removes it
`eni_after` seconds after the function is deleted (10 minutes here), or never."""
from __future__ import annotations

import io
import json
from datetime import datetime, timezone

import pytest

from arvaken_stop_test import result
from arvaken_stop_test.aws import fire as firing
from arvaken_stop_test.aws import run as running
from arvaken_stop_test.aws.stack import INLINE_LIMIT, TAG, agent_code, names, template

T0 = 1_761_220_000.0
STOP = "arn:aws:iam::111122223333:policy/agent-stop"


class ClientError(Exception):
    """An AWS error as botocore raises it: its code in `response`."""

    def __init__(self, code: str, message: str = "", **fields):
        super().__init__(message or code)
        self.response = {"Error": {"Code": code, "Message": message or code}, **fields}
ENDPOINT = "https://stop-test.example/heartbeat"


class Clock:
    def __init__(self):
        self.t = T0
        self.hooks: list = []

    def now(self) -> float:
        return self.t

    def sleep(self, d: float) -> None:
        self.t += d
        for hook in list(self.hooks):
            hook(self.t)


class FakeAWS:
    """One account, as the kit's run sees it."""

    def __init__(self, clock: Clock, *, delay=8.0, trail_delay=120.0, skew=0.05, left=(), role_tagged=True,
                 endpoint_error=None, log_group=False, bucket_stays=False, cold_after=None, invoke_error=None,
                 stop_denies=("s3:PutObject", "s3:GetObject"), boundary="the kit's", gateway_refuses=(),
                 gateway_breaks=None, gw_delay=3.0, eni_after=600.0, eni_described=True, subnet_has=(),
                 stack_stays=False):
        self.clock, self.delay, self.trail_delay, self.skew = clock, delay, trail_delay, skew
        self.left, self.role_tagged, self.endpoint_error = list(left), role_tagged, endpoint_error
        self.stack = None
        self.attached: dict[str, float] = {}
        self.attach_calls: list[float] = []
        self.objects: set[str] = set()
        self.invocations = 0
        self.revoked: dict[str, tuple[float, float]] = {}      # role -> (sessions before this moment, when it was put)
        self.inline: dict[str, float] = {}                      # role -> when a deny-all policy was written on it
        self.put_calls: list[tuple[str, float]] = []
        self.session_issued: float | None = None
        self.log_groups = [f"/aws/lambda/arvaken-stop-test-r0123abcd-agent"] if log_group else []
        self.bucket_stays = bucket_stays
        # Lambda refusing to run the agent: `cold_after` seconds after a stop on its role took hold, Lambda needs a new
        # environment and cannot decrypt its environment as the role (KMSAccessDeniedException) while the stop is on;
        # a function set to no concurrency is throttled. `invoke_error` is any other error from Invoke after the stop.
        self.cold_after, self.invoke_error = cold_after, invoke_error
        # what the declared managed policy denies, as IAM's policy simulator decides it (the kit's check before a run)
        self.stop_denies = tuple(stop_denies)
        self.stopped_from: float | None = None
        # the account's policy arvaken-stop-test-boundary: the kit's own, another document, or none
        self.boundary = boundary
        self.made_roles: list[dict] = []
        self.concurrency: int | None = None
        # the customer's gateway: paths it refuses throughout; paths it refuses from the nth invocation; when their own
        # switch was turned on; and every invocation's payload, as the kit sent it
        self.gateway_refuses, self.gateway_breaks = set(gateway_refuses), dict(gateway_breaks or {})
        self.gw_delay, self.switch_at = gw_delay, None
        self.payloads: list[dict] = []
        # a subnet of the customer's: its network interfaces, by ID; when the function was deleted; the EC2 calls made
        self.eni_after, self.eni_described = eni_after, eni_described
        self.enis: dict[str, dict] = {i["NetworkInterfaceId"]: dict(i) for i in subnet_has}
        self.function_deleted_at: float | None = None
        self.ec2_calls: list[str] = []
        self.stack_stays = stack_stays

    # cloudformation
    def create_stack(self, StackName, TemplateBody, Capabilities, Tags):
        self.stack = {"name": StackName, "template": json.loads(TemplateBody), "status": "CREATE_COMPLETE",
                      "run": Tags[0]["Value"], "body": TemplateBody}
        network = self.stack["template"]["Resources"]["Agent"]["Properties"].get("VpcConfig")
        if network:                              # Lambda makes the function's interface in the subnet, as its role
            function = names(self.stack["run"])["function"]
            self.enis["eni-0aaa1111"] = {
                "NetworkInterfaceId": "eni-0aaa1111", "SubnetId": network["SubnetIds"][0],
                "Description": f"AWS Lambda VPC ENI-{function}-0f1e2d3c" if self.eni_described else "",
                "Groups": [{"GroupId": g} for g in network["SecurityGroupIds"]], "InterfaceType": "lambda"}

    def gone(self) -> bool:
        return not self.stack or self.stack["status"] == "DELETED"

    def describe_stacks(self, StackName):
        if self.gone():
            raise ClientError("ValidationError", f"Stack with id {StackName} does not exist")
        n = names(self.stack["run"])
        return {"Stacks": [{"StackStatus": self.stack["status"], "Outputs": [
            {"OutputKey": "Bucket", "OutputValue": f"{n['stack']}-bucket-abc"},
            {"OutputKey": "Agent", "OutputValue": f"arn:aws:lambda:eu-central-1:111122223333:function:{n['function']}"},
            {"OutputKey": "AgentRole", "OutputValue": f"arn:aws:iam::111122223333:role/{n['agent_role']}"}]}]}

    def delete_stack(self, StackName):
        if self.stack_stays:
            return
        self.stack["status"] = "DELETED"
        self.function_deleted_at = self.clock.now()

    # ec2, read only
    def describe_network_interfaces(self, Filters, NextToken=None):
        self.ec2_calls.append("describe_network_interfaces")
        if self.function_deleted_at is not None and self.eni_after is not None and \
                self.clock.now() >= self.function_deleted_at + self.eni_after:
            self.enis.pop("eni-0aaa1111", None)          # AWS removes the function's interface, some time after
        (subnet,) = [f["Values"][0] for f in Filters if f["Name"] == "subnet-id"]
        found = [i for _, i in sorted(self.enis.items()) if i["SubnetId"] == subnet]
        at = int(NextToken or 0)                          # one a page, so the kit must read every page
        return {"NetworkInterfaces": found[at:at + 1], **({"NextToken": str(at + 1)} if at + 1 < len(found) else {})}

    # sts
    def get_caller_identity(self):
        return {"Account": "123456789012", "Arn": "arn:aws:sts::123456789012:assumed-role/runner/you"}

    # iam
    def get_policy(self, PolicyArn):
        if PolicyArn.endswith(":policy/arvaken-stop-test-boundary") and self.boundary is None:
            raise ClientError("NoSuchEntity")
        return {"Policy": {"Arn": PolicyArn, "DefaultVersionId": "v1"}}

    def get_policy_version(self, PolicyArn, VersionId):
        if PolicyArn.endswith(":policy/arvaken-stop-test-boundary"):
            from arvaken_stop_test.aws.stack import boundary_document
            document = boundary_document() if self.boundary == "the kit's" else \
                boundary_document(network=False) if self.boundary == "the kit's to 0.2.1" else \
                {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
            return {"PolicyVersion": {"VersionId": VersionId, "Document": document}}
        return {"PolicyVersion": {"VersionId": VersionId, "Document": {"Version": "2012-10-17", "Statement": [
            {"Effect": "Deny", "Action": list(self.stop_denies), "Resource": "*"}]}}}

    def simulate_custom_policy(self, PolicyInputList, ActionNames, ResourceArns):
        denied = set(json.loads(PolicyInputList[0])["Statement"][0]["Action"])
        return {"EvaluationResults": [{"EvalActionName": a, "EvalDecision": "explicitDeny" if a in denied else "allowed"}
                                      for a in ActionNames]}

    def list_role_tags(self, RoleName):
        return {"Tags": [{"Key": TAG, "Value": self.stack["run"]}] if self.role_tagged else []}

    def attach_role_policy(self, RoleName, PolicyArn):
        self.attached[PolicyArn] = self.clock.now()
        self.attach_calls.append(self.clock.now())

    def detach_role_policy(self, RoleName, PolicyArn):
        self.attached.pop(PolicyArn, None)

    def list_attached_role_policies(self, RoleName):
        return {"AttachedPolicies": [{"PolicyArn": a} for a in self.attached]}

    def list_role_policies(self, RoleName):
        return {"PolicyNames": ["own-calls"] + (["AWSRevokeOlderSessions"] if RoleName in self.revoked else [])
                + ([firing.INLINE] if RoleName in self.inline else [])}

    def put_role_policy(self, RoleName, PolicyName, PolicyDocument):
        statement = json.loads(PolicyDocument)["Statement"][0]
        if PolicyName == "AWSRevokeOlderSessions":
            moment = statement["Condition"]["DateLessThan"]["aws:TokenIssueTime"]
            before = datetime.fromisoformat(moment.replace("Z", "+00:00")).timestamp()
            self.revoked[RoleName] = (before, self.clock.now())
        else:                                    # a policy written on the role: it denies what it names, at once
            assert statement == {"Effect": "Deny", "Action": "*", "Resource": "*"}, statement
            self.inline[RoleName] = self.clock.now()
        self.put_calls.append((RoleName, self.clock.now()))

    def delete_role_policy(self, RoleName, PolicyName):
        (self.revoked if PolicyName == "AWSRevokeOlderSessions" else self.inline).pop(RoleName, None)

    def get_role(self, RoleName):
        if self.gone():
            raise ClientError("NoSuchEntity", f"The role with name {RoleName} cannot be found.")
        return {"Role": {"RoleName": RoleName}}

    def revoked_for(self, role_suffix: str, issued: float) -> bool:
        return any(name.endswith(role_suffix) and issued < before and self.clock.now() >= put + self.delay
                   for name, (before, put) in self.revoked.items())

    # lambda
    def stopped(self) -> bool:
        return (any(self.clock.now() >= at + self.delay for at in self.attached.values())
                or self.revoked_for("-agent", T0 - 3600)             # the agent's own session predates the run
                or any(name.endswith("-agent") and self.clock.now() >= at + self.delay
                       for name, at in self.inline.items()))

    def invoke(self, FunctionName, Payload):
        self.invocations += 1
        self.clock.t += 0.1                       # the call's way there; the agent stamps its time; and back (below)
        stopped = self.stopped()
        self.stopped_from = (self.stopped_from or self.clock.now()) if stopped else None
        refusal = None
        if self.concurrency == 0:
            refusal = ClientError("TooManyRequestsException", "Rate Exceeded.",
                                  Reason="ReservedFunctionConcurrentInvocationLimitExceeded")
        elif stopped and self.cold_after is not None and self.clock.now() >= self.stopped_from + self.cold_after:
            refusal = ClientError("KMSAccessDeniedException", "Lambda was unable to decrypt the environment variables "
                                  "because KMS access was denied.")
        elif stopped and self.invoke_error:
            refusal = ClientError(self.invoke_error)
        if refusal:
            self.clock.t += 0.1
            raise refusal
        event = json.loads(Payload)
        self.payloads.append(event)
        agent_now = self.clock.now() + self.skew

        def through(p: str) -> bool:
            """Whether the gateway the invocation names carries this path's call now; True without one."""
            if "via" not in event:
                return True
            return not (p in self.gateway_refuses or self.invocations >= self.gateway_breaks.get(p, 10 ** 9) or
                        (self.switch_at is not None and self.clock.now() >= self.switch_at + self.gw_delay))

        def beat(p: str, ok: bool, error: str | None) -> dict:
            if not through(p):
                return {"at": agent_now, "ok": False, "error": "ProxyConnectionError"}
            return {"at": agent_now, "ok": ok, **({"error": error} if not ok and error else {})}
        if event.get("action") == "assume":
            if self.stopped():
                raise RuntimeError("AccessDenied on sts:AssumeRole")
            if not through("another_identity"):          # the agent's error, as Lambda returns it: no session
                body = {"errorMessage": "Failed to connect to proxy URL", "errorType": "ProxyConnectionError"}
                self.clock.t += 0.1
                return {"Payload": io.BytesIO(json.dumps(body).encode()), "FunctionError": "Unhandled"}
            self.session_issued = agent_now
            body = {"at": agent_now, "session": {"key": "k", "secret": "s", "token": "t", "expires": agent_now + 3600}}
        else:
            body = {"at": agent_now, "beats": {
                "own_calls": beat("own_calls", not self.stopped(), "AccessDenied"),
                "another_identity": beat("another_identity", bool(event.get("session")) and not (
                    self.session_issued is not None and self.revoked_for("-second", self.session_issued)), None),
                **{p: (beat(p, False, self.endpoint_error) if self.endpoint_error else beat(p, True, None))
                   for p in ("outside_key", "open_internet")}}}
            if body["beats"]["own_calls"]["ok"]:
                self.objects.add(f"own/{event['n']}")
        self.clock.t += 0.1
        return {"Payload": io.BytesIO(json.dumps(body).encode())}

    def get_function(self, FunctionName):
        if self.gone():
            raise ClientError("ResourceNotFoundException", f"Function not found: {FunctionName}")
        return {"Configuration": {"State": "Active"},
                **({"Concurrency": {"ReservedConcurrentExecutions": self.concurrency}}
                   if self.concurrency is not None else {})}

    # logs: the function's log group, which Lambda makes only where the function may write logs
    def describe_log_groups(self, logGroupNamePrefix):
        return {"logGroups": [{"logGroupName": g} for g in self.log_groups if g.startswith(logGroupNamePrefix)]}

    def delete_log_group(self, logGroupName):
        self.log_groups.remove(logGroupName)

    # s3
    def list_objects_v2(self, Bucket):
        return {"Contents": [{"Key": k} for k in sorted(self.objects)][:1000]}

    def head_bucket(self, Bucket):
        if self.gone() and not self.bucket_stays:
            raise ClientError("404", "Not Found")
        return {}

    def delete_objects(self, Bucket, Delete):
        for o in Delete["Objects"]:
            self.objects.discard(o["Key"])

    # cloudtrail
    def lookup_events(self, LookupAttributes, StartTime, EndTime):
        role = LookupAttributes[0]["AttributeValue"]
        calls = [("AttachRolePolicy", at) for at in self.attach_calls if role.endswith("-agent")]
        calls += [("PutRolePolicy", at) for name, at in self.put_calls if name == role]
        return {"Events": [{"EventName": name, "EventTime": datetime.fromtimestamp(int(at), tz=timezone.utc)}
                           for name, at in calls if StartTime <= at <= EndTime and self.clock.now() >= at + self.trail_delay]}

    # tagging
    def get_resources(self, TagFilters):
        return {"ResourceTagMappingList": [{"ResourceARN": a} for a in self.left]}


def clients(aws: FakeAWS) -> running.Clients:
    return running.Clients(cloudformation=aws, iam=aws, lambda_=aws, s3=aws, cloudtrail=aws, tagging=aws,
                           region="eu-central-1", logs=aws, sts=aws, ec2=aws)


def a_run(aws: FakeAWS, clock: Clock, **over):
    kw = dict(endpoint=ENDPOINT, window=60.0, clock=running.Clock(clock.now, clock.sleep), run_name="r0123abcd")
    kw.update(over)
    stop = kw.pop("stop_ref", STOP)
    return running.run(clients(aws), stop, **kw)


def test_a_run_fires_the_stop_on_the_test_agent_alone_and_times_each_path():
    clock = Clock()
    aws = FakeAWS(clock)
    r, doc = a_run(aws, clock)
    assert result.check(doc) == doc
    rep = doc["repeats"][0]
    assert {p: v["outcome"] for p, v in rep.items()} == {
        "own_calls": "stopped", "another_identity": "not stopped", "outside_key": "not stopped",
        "open_internet": "not stopped"}
    # the firing moment is CloudTrail's, to the second; the stop took hold 8 seconds after the call
    fired = datetime.fromisoformat(rep["own_calls"]["fired_at"].replace("Z", "+00:00")).timestamp()
    assert fired == int(aws.attach_calls[0])
    refused = datetime.fromisoformat(rep["own_calls"]["first_refused_after"].replace("Z", "+00:00")).timestamp()
    assert 8.0 <= refused - aws.attach_calls[0] <= 8.0 + 1.2 + aws.skew + 0.01
    assert doc["run"]["clock_gap_ms"] == 50 and doc["run"]["window_seconds"] == 60
    assert (doc["run"]["left_anything"], doc["stop"]["fired_by"]) == (False, "the kit")
    # everything it made is gone: the stop off, the bucket emptied, the stack deleted
    assert not aws.attached and not aws.objects and aws.stack["status"] == "DELETED"


def test_a_stop_that_would_reach_beyond_the_test_agent_is_refused_before_anything_is_made():
    for ref, says in (("p-examplescp1", "service control policy"),
                      ("arn:aws:iam::111122223333:role/someone-else", "not a policy's ARN"),
                      ("agent-stop", "not a managed policy's ARN")):
        clock = Clock()
        aws = FakeAWS(clock)
        with pytest.raises(firing.Refused, match=says):
            running.run(clients(aws), ref, endpoint=ENDPOINT, window=60.0,
                        clock=running.Clock(clock.now, clock.sleep), run_name="r0123abcd")
        assert aws.stack is None and aws.invocations == 0


def test_without_the_kits_boundary_in_the_account_nothing_is_made():
    """Both roles are made under the permissions boundary arvaken-stop-test-boundary, which the account holds once:
    a run refuses before anything is made where it is missing, or is not the kit's, whatever stop is fired."""
    for boundary, says in ((None, "has no policy arvaken-stop-test-boundary"),
                           ("another", "is not the kit's permissions boundary")):
        for stop in (STOP, firing.INLINE, firing.REVOKE):
            clock = Clock()
            aws = FakeAWS(clock, boundary=boundary)
            with pytest.raises(firing.Refused, match=says):
                running.run(clients(aws), stop, endpoint=ENDPOINT, window=60.0,
                            clock=running.Clock(clock.now, clock.sleep), run_name="r0123abcd")
            assert aws.stack is None and aws.invocations == 0


def test_both_roles_are_made_under_the_kits_boundary():
    roles = {k: r["Properties"] for k, r in template("r0123abcd", ENDPOINT)["Resources"].items()
             if r["Type"] == "AWS::IAM::Role"}
    assert sorted(roles) == ["AgentRole", "SecondRole"]
    for props in roles.values():
        assert props["PermissionsBoundary"] == {
            "Fn::Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:policy/arvaken-stop-test-boundary"}


def test_a_role_not_the_runs_own_is_never_fired_on_and_the_run_is_still_torn_down():
    clock = Clock()
    aws = FakeAWS(clock, role_tagged=False)
    with pytest.raises(firing.Refused, match="not this run's own"):
        a_run(aws, clock)
    assert not aws.attach_calls and aws.stack["status"] == "DELETED"


def test_anything_left_is_named_for_the_customer_to_delete_by_its_own_identifier():
    """A bucket the stack could not delete is found by its name, and its tag names it only once; anything else with
    the run's tag is named by its ARN."""
    clock = Clock()
    bucket = "arn:aws:s3:::arvaken-stop-test-r0123abcd-bucket-abc"
    other = "arn:aws:ec2:eu-central-1:111122223333:security-group/sg-0abc"
    r, doc = a_run(FakeAWS(clock, left=[bucket, other], bucket_stays=True), clock)
    assert doc["run"]["left_behind"] == sorted(["the bucket arvaken-stop-test-r0123abcd-bucket-abc", other])
    assert doc["run"]["left_anything"] is True


def test_the_teardown_checks_each_thing_gone_by_its_identifier_and_removes_a_log_group():
    """Lambda makes a function's log group only where the function may write logs, which the test agent may not; if
    one is there all the same, the kit deletes it, and checks it gone like everything else it made."""
    clock = Clock()
    aws = FakeAWS(clock, log_group=True)
    r, doc = a_run(aws, clock)
    assert doc["run"]["left_behind"] == [] and aws.log_groups == []
    assert r.checked_gone == ["the stack arvaken-stop-test-r0123abcd", "the function arvaken-stop-test-r0123abcd-agent",
                              "the role arvaken-stop-test-r0123abcd-agent", "the role arvaken-stop-test-r0123abcd-second",
                              "the bucket arvaken-stop-test-r0123abcd-bucket-abc",
                              "the log group /aws/lambda/arvaken-stop-test-r0123abcd-agent"]


def test_time_to_effect_is_a_range_and_successes_after_the_first_refusal_are_counted():
    """CloudTrail gives the attach call's whole second; the stop took hold 8 seconds after the call; the kit's
    heartbeat comes every 1.2 seconds (two 0.1 s legs and a 1 s sleep). So the range runs from the last success before
    the refusals, less the call's second, to the first refusal."""
    clock = Clock()
    aws = FakeAWS(clock)
    r, doc = a_run(aws, clock)
    found = running.results(r)[0][1]["own_calls"]
    fired = int(aws.attach_calls[0])
    low, high = found.effect_between
    assert found.fired_source == "CloudTrail's record of the call, to the whole second"
    assert high == pytest.approx(found.stopped_at - fired, abs=0.001) and 8.0 <= high <= 8.0 + 1.0 + 1.2 + aws.skew
    assert low == pytest.approx(found.last_success_after - (fired + 1.0), abs=0.001) and low < 8.0 + 0.0 < high + 1.0
    assert found.successes_after_first_refusal == 0
    assert running.results(r)[0][1]["another_identity"].keeps_working_until is not None


def test_without_cloudtrails_record_the_firing_moment_is_the_kits_own_clock_moved_onto_the_agents():
    clock = Clock()
    aws = FakeAWS(clock, trail_delay=10_000.0)
    r, doc = a_run(aws, clock, trail_wait=60.0)
    assert r.repeats[0].fired_at == pytest.approx(r.repeats[0].fired_after + 0.05, abs=0.11)
    assert doc["repeats"][0]["own_calls"]["outcome"] == "stopped"


def test_two_repeats_each_fire_time_and_take_the_stop_off_again():
    clock = Clock()
    aws = FakeAWS(clock)
    r, doc = a_run(aws, clock, repeats=2)
    assert len(aws.attach_calls) == 2 and doc["run"]["repeats"] == 2
    assert [rep["own_calls"]["outcome"] for rep in doc["repeats"]] == ["stopped", "stopped"]


def test_with_the_customers_own_trigger_the_kit_times_from_the_change_it_sees_and_fires_nothing_itself():
    clock = Clock()
    aws = FakeAWS(clock)
    pulled = []

    def the_customer(t):                     # 20 seconds into watching, the customer's own trigger attaches a stop
        if not pulled and aws.stack and aws.invocations > running.WARM_UP + 1 and t >= T0 + 40:
            pulled.append(t)
            aws.attached[STOP] = t
    clock.hooks.append(the_customer)
    r, doc = a_run(aws, clock, fired_by="your own trigger")
    assert not aws.attach_calls                                   # the kit attached nothing
    assert doc["stop"]["fired_by"] == "your own trigger"
    assert doc["repeats"][0]["own_calls"]["outcome"] == "stopped"
    with pytest.raises(ValueError, match="fires once"):
        a_run(FakeAWS(Clock()), Clock(), fired_by="your own trigger", repeats=2)


def test_the_stack_holds_the_agent_and_reaches_only_the_runs_own_things():
    t = template("r0123abcd", ENDPOINT, outside_key="k" * 32)
    resources = t["Resources"]
    assert set(resources) == {"Bucket", "AgentRole", "SecondRole", "Agent"}
    assert all({"Key": TAG, "Value": "r0123abcd"} in r["Properties"]["Tags"] for r in resources.values())
    own = resources["AgentRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]
    assert own[0]["Resource"] == {"Fn::Sub": "${Bucket.Arn}/own/*"}
    assert own[1]["Resource"] == {"Fn::Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:role/arvaken-stop-test-r0123abcd-second"}
    assert "logs:" not in json.dumps(t)                           # no permission to write logs
    assert len(agent_code()) <= INLINE_LIMIT and '"""The test agent' not in agent_code()
    assert resources["Agent"]["Properties"]["Environment"]["Variables"]["ENDPOINT"] == ENDPOINT


def test_a_path_that_never_worked_before_the_stop_is_not_run_and_the_page_says_why():
    """The first proof run's endpoint answered the agent 403 throughout (test_agent.py); the page said only "not run"."""
    clock = Clock()
    said = []
    r, doc = a_run(FakeAWS(clock, endpoint_error="HTTP403"), clock, say=said.append)
    assert {p: v["outcome"] for p, v in doc["repeats"][0].items()} == {
        "own_calls": "stopped", "another_identity": "not stopped", "outside_key": "not run", "open_internet": "not run"}
    assert said == [f"Before the stop, {words} did not work (HTTP403 {running.WARM_UP}): it will be reported as not run."
                    for words in ("a key for a service outside the cloud", "the open internet")]
    from arvaken_stop_test import report
    page = report.page(doc, [d for _, d in running.results(r)])
    assert page.count(f"the path could not be set up: HTTP403 {running.WARM_UP}") == 2
    assert "HTTP403" not in json.dumps(doc) and result.check(doc)


def test_revoking_sessions_reaches_the_session_the_agent_took_for_the_role_it_became():
    """The second kind (the founder, 23 October 2026: "both roles, K4 widened"): revoked on the agent's role and on its
    second role, each path is timed from the call on its own role, and both are put back off between repeats."""
    clock = Clock()
    aws = FakeAWS(clock)
    r, doc = a_run(aws, clock, stop_ref=firing.REVOKE, repeats=2)
    assert doc["stop"] == {"kind": "revoke active sessions", "fired_by": "the kit", "ref": "revoke active sessions",
                           "product": None}
    assert [{p: v["outcome"] for p, v in rep.items()} for rep in doc["repeats"]] == [{
        "own_calls": "stopped", "another_identity": "stopped", "outside_key": "not stopped",
        "open_internet": "not stopped"}] * 2
    assert len(aws.put_calls) == 4 and not aws.revoked and not aws.attach_calls
    second = [at for name, at in aws.put_calls if name.endswith("-second")]
    assert doc["repeats"][0]["another_identity"]["fired_at"] == running._iso(float(int(second[0])))
    assert running.results(r)[0][1]["another_identity"].keeps_working_until is None
    details = running.details(r, doc)
    assert details["repeats"][0]["another_identity"]["effect_between_seconds"][1] >= 8.0
    assert details["checked_gone"] and details["left_behind"] == []


def test_a_policy_written_on_the_agents_role_is_a_kind_of_its_own_and_stops_its_own_calls():
    """The third kind (D538, M2): a deny-all policy written on the agent's role, timed from its PutRolePolicy, taken off
    between repeats and checked gone with the role."""
    clock = Clock()
    aws = FakeAWS(clock)
    r, doc = a_run(aws, clock, stop_ref=firing.INLINE, repeats=2)
    assert doc["stop"] == {"kind": "policy written on the role", "fired_by": "the kit", "ref": firing.INLINE,
                           "product": None}
    assert [rep["own_calls"]["outcome"] for rep in doc["repeats"]] == ["stopped", "stopped"]
    assert [rep["another_identity"]["outcome"] for rep in doc["repeats"]] == ["not stopped", "not stopped"]
    assert len(aws.put_calls) == 2 and not aws.inline and not aws.attach_calls
    assert all(name.endswith("-agent") for name, _ in aws.put_calls)
    found = running.results(r)[0][1]["own_calls"]
    assert found.fired_source == "CloudTrail's record of the call, to the whole second" and found.effect_between[1] >= 8.0
    assert doc["run"]["left_behind"] == []


def test_lambda_refusing_to_run_the_agent_is_timed_on_every_path_not_a_crash():
    """Arvaken's inline measurement (23 October 2026): with a deny-all policy written on the agent's role, once Lambda
    needed a new environment for the agent it refused the invocation (KMSAccessDeniedException), and the kit crashed.
    While Lambda refuses, the agent makes no call on any path, so each path counts each refusal as refused."""
    clock = Clock()
    aws = FakeAWS(clock, cold_after=20.0)
    r, doc = a_run(aws, clock, stop_ref=firing.INLINE, repeats=2)
    assert [{p: v["outcome"] for p, v in rep.items()} for rep in doc["repeats"]] == [
        {p: "stopped" for p in running.AWS_PATHS}] * 2
    found = running.results(r)[0][1]
    assert found["own_calls"].effect_between[1] < found["open_internet"].effect_between[1]   # its own calls first
    assert found["open_internet"].errors == {running.REFUSED + "KMSAccessDeniedException": found["open_internet"]
                                             .failures_after}
    details = running.details(r, doc)
    assert [set(d) for d in details["lambda_refused"]] == [{"KMSAccessDeniedException"}] * 2
    assert doc["run"]["calls"] < aws.invocations * 4                  # a refused invocation made no call
    from arvaken_stop_test import report
    page = report.page(doc, [d for _, d in running.results(r)])
    assert ("Lambda refused to run the test agent (KMSAccessDeniedException). While it refused, the agent made no call "
            "on any path, and each path counts each refusal as refused.") in page
    assert "as when a stop on the role denies it while Lambda starts a new environment for the agent" in page
    assert "KMS" not in json.dumps(doc) and "refused:" not in json.dumps(doc) and result.check(doc)
    assert not aws.inline and aws.stack["status"] == "DELETED" and doc["run"]["left_behind"] == []


def test_a_function_your_own_trigger_set_to_no_concurrency_is_timed_as_refused():
    clock = Clock()
    aws = FakeAWS(clock)

    def the_customer(t):                     # 20 seconds into watching, the customer's own trigger stops the function
        if aws.concurrency is None and aws.stack and aws.invocations > running.WARM_UP + 1 and t >= T0 + 40:
            aws.concurrency = 0
    clock.hooks.append(the_customer)
    r, doc = a_run(aws, clock, fired_by="your own trigger")
    assert {p: v["outcome"] for p, v in doc["repeats"][0].items()} == {p: "stopped" for p in running.AWS_PATHS}
    refusals = [b for b in r.repeats[0].beats["own_calls"] if b.error == running.REFUSED + "TooManyRequestsException"]
    assert running.details(r, doc)["lambda_refused"] == [{"TooManyRequestsException": len(refusals)}]
    assert len(refusals) >= running.results(r)[0][1]["own_calls"].failures_after > 0


def test_any_other_error_from_invoke_ends_the_run_and_is_never_read_as_stopped():
    """The kit's own credentials expiring is not the stop: the run ends, torn down, and writes no result."""
    clock = Clock()
    aws = FakeAWS(clock, invoke_error="ExpiredTokenException")
    with pytest.raises(ClientError, match="ExpiredTokenException"):
        a_run(aws, clock, stop_ref=firing.INLINE)
    assert not aws.inline and aws.stack["status"] == "DELETED"
    assert running.refused_by_lambda(ClientError("ExpiredTokenException")) is None
    assert running.refused_by_lambda(ClientError("TooManyRequestsException")) is None           # a throttle, not 0


def test_a_managed_policy_that_does_not_deny_the_agents_own_calls_is_refused_before_anything_is_made():
    """The founder, 24 October 2026: before a run with --stop, the kit checks that the stop denies what the test agent
    does. A policy denying only some other action tells nothing of itself here, and nothing is made."""
    clock = Clock()
    fake = FakeAWS(clock, stop_denies=("ec2:RunInstances",))
    with pytest.raises(firing.Refused) as e:
        a_run(fake, clock)
    assert str(e.value) == "Your stop doesn't deny what the test agent does, so this test can't tell you about your stop."
    assert fake.stack is None and fake.attach_calls == []
    clock2 = Clock()
    half = FakeAWS(clock2, stop_denies=("s3:PutObject",))             # one of the two own calls is not enough
    with pytest.raises(firing.Refused, match="doesn't deny what the test agent does"):
        a_run(half, clock2)
    assert half.stack is None

