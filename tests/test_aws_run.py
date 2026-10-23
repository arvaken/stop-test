"""A whole run on AWS, against a fake AWS on a virtual clock (the design's sections 3 to 8; D532, K3, K4, K8).

The fake holds what the kit's run depends on, as this file's reading of AWS's documented behaviour, not AWS's own
answer: a managed policy attached to a role takes effect after a propagation delay (8 seconds here); CloudTrail records
the attach call some time later (two minutes here), its time to the second; a deleted stack is no longer described;
anything the stack could not delete keeps its tag. Each case's expectations are worked out by hand from those rules."""
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
                 endpoint_error=None):
        self.clock, self.delay, self.trail_delay, self.skew = clock, delay, trail_delay, skew
        self.left, self.role_tagged, self.endpoint_error = list(left), role_tagged, endpoint_error
        self.stack = None
        self.attached: dict[str, float] = {}
        self.attach_calls: list[float] = []
        self.objects: set[str] = set()
        self.invocations = 0

    # cloudformation
    def create_stack(self, StackName, TemplateBody, Capabilities, Tags):
        self.stack = {"name": StackName, "template": json.loads(TemplateBody), "status": "CREATE_COMPLETE",
                      "run": Tags[0]["Value"]}

    def describe_stacks(self, StackName):
        if not self.stack or self.stack["status"] == "DELETED":
            raise RuntimeError("Stack does not exist")
        n = names(self.stack["run"])
        return {"Stacks": [{"StackStatus": self.stack["status"], "Outputs": [
            {"OutputKey": "Bucket", "OutputValue": f"{n['stack']}-bucket-abc"},
            {"OutputKey": "Agent", "OutputValue": f"arn:aws:lambda:eu-central-1:111122223333:function:{n['function']}"},
            {"OutputKey": "AgentRole", "OutputValue": f"arn:aws:iam::111122223333:role/{n['agent_role']}"}]}]}

    def delete_stack(self, StackName):
        self.stack["status"] = "DELETED"

    # iam
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
        return {"PolicyNames": ["own-calls"]}

    # lambda
    def stopped(self) -> bool:
        return any(self.clock.now() >= at + self.delay for at in self.attached.values())

    def invoke(self, FunctionName, Payload):
        self.invocations += 1
        self.clock.t += 0.1                       # the call's way there; the agent stamps its time; and back (below)
        event = json.loads(Payload)
        agent_now = self.clock.now() + self.skew
        if event.get("action") == "assume":
            if self.stopped():
                raise RuntimeError("AccessDenied on sts:AssumeRole")
            body = {"at": agent_now, "session": {"key": "k", "secret": "s", "token": "t"}}
        else:
            own = not self.stopped()
            body = {"at": agent_now, "beats": {
                "own_calls": {"at": agent_now, "ok": own, **({} if own else {"error": "AccessDenied"})},
                "another_identity": {"at": agent_now, "ok": bool(event.get("session"))},
                **{p: ({"at": agent_now, "ok": False, "error": self.endpoint_error} if self.endpoint_error else
                       {"at": agent_now, "ok": True}) for p in ("outside_key", "open_internet")}}}
            if own:
                self.objects.add(f"own/{event['n']}")
        self.clock.t += 0.1
        return {"Payload": io.BytesIO(json.dumps(body).encode())}

    def get_function(self, FunctionName):
        return {"Configuration": {"State": "Active"}}

    # s3
    def list_objects_v2(self, Bucket):
        return {"Contents": [{"Key": k} for k in sorted(self.objects)][:1000]}

    def delete_objects(self, Bucket, Delete):
        for o in Delete["Objects"]:
            self.objects.discard(o["Key"])

    # cloudtrail
    def lookup_events(self, LookupAttributes, StartTime, EndTime):
        return {"Events": [{"EventName": "AttachRolePolicy", "EventTime": datetime.fromtimestamp(int(at), tz=timezone.utc)}
                           for at in self.attach_calls
                           if StartTime <= at <= EndTime and self.clock.now() >= at + self.trail_delay]}

    # tagging
    def get_resources(self, TagFilters):
        return {"ResourceTagMappingList": [{"ResourceARN": a} for a in self.left]}


def clients(aws: FakeAWS) -> running.Clients:
    return running.Clients(cloudformation=aws, iam=aws, lambda_=aws, s3=aws, cloudtrail=aws, tagging=aws,
                           region="eu-central-1")


def a_run(aws: FakeAWS, clock: Clock, **over):
    kw = dict(endpoint=ENDPOINT, window=60.0, clock=running.Clock(clock.now, clock.sleep), run_name="r0123abcd")
    kw.update(over)
    return running.run(clients(aws), STOP, **kw)


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


def test_a_role_not_the_runs_own_is_never_fired_on_and_the_run_is_still_torn_down():
    clock = Clock()
    aws = FakeAWS(clock, role_tagged=False)
    with pytest.raises(firing.Refused, match="not this run's own"):
        a_run(aws, clock)
    assert not aws.attach_calls and aws.stack["status"] == "DELETED"


def test_anything_left_is_named_for_the_customer_to_delete():
    clock = Clock()
    left = "arn:aws:s3:::arvaken-stop-test-r0123abcd-bucket-abc"
    _, doc = a_run(FakeAWS(clock, left=[left]), clock)
    assert (doc["run"]["left_anything"], doc["run"]["left_behind"]) == (True, [left])


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
