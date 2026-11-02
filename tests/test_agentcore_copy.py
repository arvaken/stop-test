"""A run on a test copy of the customer's own AgentCore runtime (D575; agentcore/your_copy.py), against test_agentcore's
fake AWS on its virtual clock, with the real probe (arvaken-stop-test-probe) answering every call to the copy: each new
call (its "answer"), and the running session (its "watch"), whose events the fake's stream pulls from the probe's own
iterator by the copy's clock.

The fake's copy is a runtime of the customer's, already there, running as its own role until the customer points it at
the run's role (the `wait` it is given does what the customer would, where `points` says so), and back. While it runs as
the run's role, its own calls are refused once a policy on that role takes hold (DELAY), as the kit's own runtime's are.
The fake fails the test outright if the kit deletes, changes or reads the logs of the copy's runtime."""
from __future__ import annotations

import io
import json
from datetime import datetime, timezone
from types import SimpleNamespace

import botocore.exceptions
import pytest

from arvaken_stop_test.agentcore import agent as kits_agent
from arvaken_stop_test.agentcore import fire
from arvaken_stop_test.agentcore import run as running
from arvaken_stop_test.agentcore import stack
from arvaken_stop_test.agentcore import your_copy
from arvaken_stop_test.aws import your_copy as lambdas_copy
from arvaken_stop_test.aws.run import MARK_PROMPT
from arvaken_stop_test_probe import aws as probe_aws
from arvaken_stop_test_probe import core, heartbeat
from test_agentcore import ACCOUNT, DENY_ALL, REGION, SKEW, Clock, FakeAWS, Inline, Regional

RUN = "r0a1b2c3d"
COPY_ID = "my_agent_copy-Zx9Yw8Vu7T"
COPY = f"arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT}:runtime/{COPY_ID}"
OWN_ROLE = f"arn:aws:iam::{ACCOUNT}:role/my-agent-role"
RUNS_ROLE = f"arn:aws:iam::{ACCOUNT}:role/{stack.names(RUN)['agent_role']}"


class SwitchEngaged(Exception):
    """An in-agent SDK's own error, as its switch makes each call it guards raise one, its message naming things."""


class CopyClient:
    """A boto3 client in the copy, made by the copy's own cloud function, answering by the copy's clock."""

    def __init__(self, aws: CopyAWS, name: str, second: bool):
        self.aws, self.name, self.second = aws, name, second

    def _refused(self, op: str) -> None:
        aws = self.aws
        if aws.sdk_on(aws.agent_now() - SKEW):
            raise aws.sdk_raises("the SDK blocked a call as arn:aws:iam::111122223333:role/x")
        if not self.second and aws.runtime["roleArn"] == RUNS_ROLE and aws.role_denied(aws.agent_now() - SKEW):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "arn:aws:sts::111122223333:assumed-role/x is not"},
                 "ResponseMetadata": {"HTTPStatusCode": 403}}, op)

    def put_object(self, Bucket, Key, Body):
        self._refused("PutObject")
        self.aws.buckets[Bucket][Key] = (Body, self.aws.agent_now())

    def get_object(self, Bucket, Key):
        self._refused("GetObject")
        return {"Body": io.BytesIO(self.aws.buckets[Bucket][Key][0])}

    def assume_role(self, RoleArn, RoleSessionName, DurationSeconds):
        self._refused("AssumeRole")
        return {"Credentials": {"AccessKeyId": "k", "SecretAccessKey": "s", "SessionToken": "t",
                                "Expiration": datetime.fromtimestamp(self.aws.agent_now() + 3600, tz=timezone.utc)}}


class CopyStream:
    """The running session's stream, as AgentCore streams the copy's watch: the probe's own events, pulled from its
    iterator by the copy's clock, each given to the kit once the kit's clock has reached it."""

    def __init__(self, aws: CopyAWS, c, r, session, seconds, clock):
        self.aws, self.clock, self.session = aws, clock, session
        payload = running.payload_of(r, {"action": "watch", "seconds": seconds, "tag": session})
        aws.payloads.append(payload)
        self.events = heartbeat.run(payload, cloud=aws.cloud, http=aws.http)
        self.t, self.pending, self.ended, self.closed = clock.now() + SKEW, None, None, False
        aws.sessions[session] = {"ended": None}

    def poll(self):
        out = []
        while not self.closed and self.ended is None:
            if self.pending is None:
                self.aws.pulling = self.t
                try:
                    self.pending = next(self.events)
                except StopIteration:
                    self.ended = (self.clock.now(), "done")
                    break
                finally:
                    self.t, self.aws.pulling = self.aws.pulling, None
            if self.pending["at"] > self.clock.now() + SKEW:
                break
            out.append(self.pending)
            self.pending = None
        return out

    def close(self):
        self.closed = True


class CopyAWS(FakeAWS):
    """The account, with the customer's runtime in it."""

    def __init__(self, clock: Clock, **kw):
        super().__init__(clock, **kw)
        self.runtime = {"id": COPY_ID, "arn": COPY, "name": "my_agent_copy", "tags": {}, "status": "READY",
                        "policy": None, "policy_at": None, "roleArn": OWN_ROLE}
        self.payloads: list[dict] = []
        self.pulling: float | None = None       # the copy's clock while its watch's iterator is pulled
        self.cloud = lambda name, config=None, **creds: CopyClient(self, name, "aws_access_key_id" in creds)
        # the customer's in-agent SDK: when its switch is on, by the kit's clock, and what each guarded call raises
        self.sdk_on_from: float | None = None
        self.sdk_raises: type[Exception] = SwitchEngaged

    def sdk_on(self, t: float) -> bool:
        return self.sdk_on_from is not None and t >= self.sdk_on_from

    def http(self, url, headers, timeout):
        """The copy's own HTTP client: answered, until the customer's SDK switch refuses it."""
        if self.sdk_on(self.agent_now() - SKEW):
            raise self.sdk_raises(f"the SDK blocked a call to {url}")
        return 200

    def agent_now(self) -> float:
        return self.pulling if self.pulling is not None else self.clock.now() + SKEW

    def agent_sleep(self, d: float) -> None:
        if self.pulling is not None:
            self.pulling += d

    def get_agent_runtime(self, agentRuntimeId):
        assert agentRuntimeId == COPY_ID, agentRuntimeId
        return {"status": self.runtime["status"], "agentRuntimeArn": COPY, "roleArn": self.runtime["roleArn"]}

    def invoke_agent_runtime(self, agentRuntimeArn, runtimeSessionId, qualifier, contentType, accept, payload):
        assert agentRuntimeArn == COPY and qualifier == "DEFAULT" and len(runtimeSessionId) >= 33
        event = json.loads(payload)
        self.payloads.append(event)
        self.new_calls.append((self.clock.now(), True))
        body = heartbeat.run(event, cloud=self.cloud, http=self.http)
        return {"response": io.BytesIO(json.dumps(body).encode())}

    def _never(self, *a, **kw):
        raise AssertionError("the copy's runtime is the customer's: the kit never deletes, changes or reads its logs")

    create_agent_runtime = delete_agent_runtime = put_resource_policy = delete_resource_policy = _never
    delete_workload_identity = stop_runtime_session = delete_log_group = describe_log_groups = _never


@pytest.fixture(autouse=True)
def fresh_clients(monkeypatch):
    monkeypatch.setattr(probe_aws, "_MADE", {})


def a_copy_run(aws: CopyAWS, clock: Clock, monkeypatch, stop=DENY_ALL, *, typed=RUN, warned=RUN,
               points=("at", "back"), answers: dict | None = None, fires_after: float | None = None, **over):
    stamp = SimpleNamespace(time=aws.agent_now, sleep=aws.agent_sleep)
    for module in (core, probe_aws, heartbeat):
        monkeypatch.setattr(module, "time", stamp)
    aws._run = RUN
    said, asked = [], []

    def confirm(words: str) -> str:
        asked.append(words)
        if answers and words in answers:             # an answer known only once the run has fired is a function
            return answers[words]() if callable(answers[words]) else answers[words]
        return warned if words == lambdas_copy.WARNING else typed

    def wait(words: str) -> None:
        asked.append(words)
        if words.startswith("Point your copy's runtime") and " at the run's role" in words and "at" in points:
            aws.runtime["roleArn"] = RUNS_ROLE
        elif " back at its own role" in words and "back" in points:
            aws.runtime["roleArn"] = OWN_ROLE
        elif words == MARK_PROMPT and fires_after is not None:    # Enter, then the customer fires their SDK's switch
            aws.sdk_on_from = clock.now() + fires_after

    c = running.Clients(iam=aws, s3=aws, control=aws, data=aws, cloudtrail=Regional(aws, REGION),
                        iam_trail=Regional(aws, "us-east-1"), tagging=aws, region=REGION, logs=aws, sts=aws,
                        stream=lambda c, r, session, seconds, clock: CopyStream(aws, c, r, session, seconds, clock),
                        executor=Inline)
    r = your_copy.run(c, over.pop("copy", COPY), stop, confirm=confirm, wait=wait, clock=clock, run_name=RUN,
                      window=over.pop("window", 120.0), say=said.append, **over)
    return r, said, asked


def test_a_run_on_a_copy_stops_the_sessions_own_calls_from_the_policy_on_the_runs_role(monkeypatch):
    clock = Clock()
    aws = CopyAWS(clock)
    r, said, asked = a_copy_run(aws, clock, monkeypatch)

    outcomes = {p: f.outcome for p, f in running.results(r)[0][1].items()}
    assert outcomes["own_calls"] == "stopped"
    assert {outcomes[p] for p in ("another_identity", "outside_key", "open_internet", "new_calls")} == {"not stopped"}
    # every call to the copy carried the run's settings in the kit's marker, which the probe took
    assert aws.payloads and all(set(p) == {running.MARKER} for p in aws.payloads)
    assert {p[running.MARKER]["action"] for p in aws.payloads} == {"answer", "watch"}
    assert r.clients == {"cloud": {"customer"}, "http": {"customer"}}
    assert asked[0].startswith("The kit will call") and asked[2] == lambdas_copy.WARNING
    # nothing of the kit's is left, the copy's runtime is as it was, and back on its own role
    assert aws.runtime["roleArn"] == OWN_ROLE and aws.runtime["status"] == "READY" and aws.runtime["policy"] is None
    assert r.left_behind == [] and not aws.roles and stack.names(RUN)["bucket"] not in aws.buckets
    assert not any("runtime" in x or "code" in x or "log group" in x for x in r.checked_gone)


def test_the_runs_role_trusts_agentcore_for_the_customers_copy_alone_under_the_kits_boundary(monkeypatch):
    clock = Clock()
    aws = CopyAWS(clock)
    made = {}
    real = CopyAWS.create_role

    def keep(self, RoleName, AssumeRolePolicyDocument, PermissionsBoundary, Tags):
        made[RoleName] = (json.loads(AssumeRolePolicyDocument), PermissionsBoundary)
        return real(self, RoleName, AssumeRolePolicyDocument, PermissionsBoundary, Tags)

    monkeypatch.setattr(CopyAWS, "create_role", keep)
    a_copy_run(aws, clock, monkeypatch)
    trust, boundary = made[stack.names(RUN)["agent_role"]]
    assert trust["Statement"] == [{"Effect": "Allow", "Principal": {"Service": "bedrock-agentcore.amazonaws.com"},
                                   "Action": "sts:AssumeRole",
                                   "Condition": {"StringEquals": {"aws:SourceAccount": ACCOUNT},
                                                 "ArnLike": {"aws:SourceArn": COPY}}}]
    assert boundary.endswith(":policy/arvaken-stop-test-boundary")


@pytest.mark.parametrize("stop", [fire.DENY, fire.DENY_AND_END])
def test_a_deny_of_calls_or_ending_a_session_is_never_fired_on_a_copy(monkeypatch, stop):
    clock = Clock()
    aws = CopyAWS(clock)
    with pytest.raises(fire.Refused, match="would change your runtime"):
        a_copy_run(aws, clock, monkeypatch, stop)
    assert not aws.roles and not aws.payloads


@pytest.mark.parametrize("arn", [
    COPY.replace(REGION, "us-east-1"), COPY.replace(ACCOUNT, "999999999999"),
    f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:my-agent", COPY_ID])
def test_a_copy_not_named_as_a_runtime_in_this_account_and_region_is_refused_before_anything(monkeypatch, arn):
    clock = Clock()
    aws = CopyAWS(clock)
    with pytest.raises(ValueError, match="runtime's ARN"):
        a_copy_run(aws, clock, monkeypatch, copy=arn)
    assert not aws.roles


def test_nothing_is_made_unless_the_runs_name_is_typed_to_confirm_a_test_copy(monkeypatch):
    clock = Clock()
    aws = CopyAWS(clock)
    with pytest.raises(fire.Refused, match="nothing was made"):
        a_copy_run(aws, clock, monkeypatch, typed="")
    assert not aws.roles and not aws.buckets


def test_a_copy_not_pointed_at_the_runs_role_is_not_timed_and_everything_made_is_removed(monkeypatch):
    clock = Clock()
    aws = CopyAWS(clock)
    with pytest.raises(running.NotStarted, match="does not run as the run's role"):
        a_copy_run(aws, clock, monkeypatch, points=())
    assert not aws.payloads and not aws.roles and not aws.buckets and aws.runtime["roleArn"] == OWN_ROLE


def test_a_copy_still_running_as_the_runs_role_keeps_it_and_it_is_named_for_the_customer(monkeypatch):
    clock = Clock()
    aws = CopyAWS(clock)
    r, _, _ = a_copy_run(aws, clock, monkeypatch, points=("at",))
    role = stack.names(RUN)["agent_role"]
    assert role in aws.roles and not aws.roles[role]["attached"]     # the stop is off; the role stays
    assert r.left_behind == [lambdas_copy.STILL_RUNS_AS.format(role=role, copy=COPY)]


def test_without_the_runs_name_typed_before_firing_nothing_is_fired(monkeypatch):
    clock = Clock()
    aws = CopyAWS(clock)
    r, said, _ = a_copy_run(aws, clock, monkeypatch, warned="no")
    assert r.repeats == [] and lambdas_copy.NOT_FIRED in said and not aws.roles


def test_the_probes_watch_makes_the_kits_own_agentcore_agents_calls(monkeypatch):
    """One try of the probe's watch is the kit's AgentCore agent's (agent.probe), call for call, under the same tag."""
    from test_probe import Recorder, KEY
    calls, kits = [], []
    monkeypatch.setattr(probe_aws, "_MADE", {})
    monkeypatch.setattr(kits_agent, "_get", lambda url, headers: kits.append(("GET", url, headers)))
    tag = f"{RUN}-session-{'0' * 32}"
    bucket, second = stack.names(RUN)["bucket"], f"arn:aws:iam::{ACCOUNT}:role/{stack.names(RUN)['second_role']}"
    for k, v in {"BUCKET": bucket, "ENDPOINT": core.ENDPOINT, "OUTSIDE_KEY": KEY, "SECOND_ROLE": second}.items():
        monkeypatch.setenv(k, v)
    event = {running.MARKER: {"run": RUN, "bucket": bucket, "second_role": second, "key": KEY, "action": "watch",
                              "seconds": 1, "tag": tag}}
    events = heartbeat.run(event, cloud=lambda name, **kw: Recorder(calls, name, kw),
                           http=lambda url, headers, timeout: calls.append(
                               ("GET", url, {k: v for k, v in headers.items() if k != "User-Agent"})) or 200)
    first, beat = next(events), next(events)
    assert first["error"] is None and set(beat["beats"]) == {"own_calls", "another_identity", "outside_key",
                                                              "open_internet"}
    kits_s3 = Recorder(kits, "s3", {})
    kits_other = Recorder(kits, "s3", {"aws_access_key_id": "k"})
    kits_agent.probe(kits_s3, kits_other, tag, 0)
    ops = lambda found: [c for c in found if c[0] != "client" and c[1] != "assume_role"]  # noqa: E731
    assert ops(calls) == ops(kits)


def test_the_probes_watch_takes_only_a_session_named_for_the_run_and_never_longer_than_agentcore_streams():
    from test_probe import marked
    for tag in ("someone-elses-session", f"r9999ffff-session-{'0' * 32}", None):
        with pytest.raises(core.NotTheKits, match="tag"):
            heartbeat.run(marked(action="watch", seconds=10, tag=tag))
    with pytest.raises(core.NotTheKits, match="seconds"):
        heartbeat.run(marked(action="watch", seconds=0, tag=f"r0123abcd-session-{'0' * 32}"))
    assert heartbeat.LONGEST == kits_agent.LONGEST and heartbeat.EVERY == kits_agent.EVERY


def test_the_kits_agentcore_policy_does_not_reach_a_copy_and_the_copys_own_policy_reaches_it_alone():
    """The kit's policy reads and calls the run's own runtimes alone. A copy is the customer's, so reading it and
    calling it are a policy of their own (permissions/aws-copy-policy.json, D575 step 4, a draft for the founder),
    naming the customer's runtime in place of YOUR-TEST-COPY-ID, its endpoints too, as the kit's own statement has them."""
    from pathlib import Path
    root = Path(__file__).resolve().parents[1] / "permissions"
    policy = json.loads((root / "aws-agentcore-policy.json").read_text(encoding="utf-8"))
    reach = {r for s in policy["Statement"] for r in ([s["Resource"]] if isinstance(s["Resource"], str) else
                                                      s["Resource"])
             if {"bedrock-agentcore:GetAgentRuntime", "bedrock-agentcore:InvokeAgentRuntime"} & set(
                 [s["Action"]] if isinstance(s["Action"], str) else s["Action"])}
    assert reach and all("runtime/arvaken_stop_test_" in r for r in reach)
    copy = json.loads((root / "aws-copy-policy.json").read_text(encoding="utf-8"))
    [agentcore] = [s for s in copy["Statement"] if s["Sid"] == "YourTestCopyOnAgentCore"]
    assert set(agentcore["Action"]) == {"bedrock-agentcore:GetAgentRuntime", "bedrock-agentcore:InvokeAgentRuntime"}
    assert agentcore["Resource"] == [
        "arn:aws:bedrock-agentcore:REGION:ACCOUNT:runtime/YOUR-TEST-COPY-ID",
        "arn:aws:bedrock-agentcore:REGION:ACCOUNT:runtime/YOUR-TEST-COPY-ID/runtime-endpoint/*"]



# -- an in-agent SDK's switch on the copy (D713; sdk.py)

def iso(t: float) -> str:
    return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def an_sdk_run(monkeypatch, *, fires_after: float | None = 2.0, witness=lambda url, headers: 200, **over):
    clock = Clock()
    aws = CopyAWS(clock)

    def time() -> str:
        return iso(aws.sdk_on_from) if aws.sdk_on_from is not None else iso(clock.now())

    answers = {lambdas_copy.SDK_EXPORT: "acme-audit.log", lambdas_copy.SDK_ENTRY_TIME: time,
               lambdas_copy.SDK_ENTRY_NAME: "kill switch engaged"}
    r, said, asked = a_copy_run(aws, clock, monkeypatch, "", sdk_name="Acme Guard", window=900.0, answers=answers,
                                fires_after=fires_after, witness_get=witness,
                                read=lambda where: f"{time()} kill switch engaged by ops@example.com".encode(),
                                **over)
    return r, aws, said, asked


def test_an_sdks_switch_on_an_agentcore_copy_stops_the_sessions_paths_by_its_record_and_the_witness(monkeypatch):
    from arvaken_stop_test import sdk
    from arvaken_stop_test.timing import NOT_MEASURED
    r, aws, said, asked = an_sdk_run(monkeypatch)
    fired, found = your_copy.sdk_results(r)[0]
    assert {p: found[p].outcome for p in running.SESSION_PATHS} == {p: sdk.SDK_STOPPED for p in running.SESSION_PATHS}
    # new calls reach the copy, which answers them whatever its SDK guards: nothing failed, so not measured
    assert (found["new_calls"].outcome, found["new_calls"].reason) == (NOT_MEASURED, sdk.NOTHING_FAILED)
    assert fired == int(aws.sdk_on_from) and found["own_calls"].fired_source == sdk.FROM_THE_RECORD
    # the kit fired nothing itself: no policy attached to the run's role, and only the roles' own written on them
    assert not [e for e in aws.events if e["name"] == "AttachRolePolicy"]
    assert len([e for e in aws.events if e["name"] == "PutRolePolicy"]) == 2
    assert r.fired_by == "your own trigger" and r.product["kind"] == "in-agent SDK"
    assert asked.index(lambdas_copy.WARNING) < asked.index(MARK_PROMPT) < asked.index(lambdas_copy.SDK_EXPORT)
    assert all(ok for _, ok, _ in r.witness) and r.left_behind == [] and aws.runtime["roleArn"] == OWN_ROLE


def test_an_sdks_stop_on_an_agentcore_copy_without_the_witness_working_is_not_measured(monkeypatch):
    from arvaken_stop_test.timing import NOT_MEASURED
    calls = []

    def witness(url, headers):
        calls.append(url)
        if len(calls) == 200:
            raise ConnectionResetError()
        return 200

    r, _, _, _ = an_sdk_run(monkeypatch, witness=witness)
    found = your_copy.sdk_results(r)[0][1]
    assert {found[p].outcome for p in running.SESSION_PATHS} == {NOT_MEASURED}
    assert all(found[p].reason.startswith("the kit's witness did not keep working") for p in running.SESSION_PATHS)
