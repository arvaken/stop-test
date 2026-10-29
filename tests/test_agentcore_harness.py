"""The stop test on an AgentCore harness (agentcore/harness.py, agentcore/probe.py; arvaken/mark,
AGENTCORE-MEASUREMENT.md, section 7; D618), against the runtime's fake AWS with a harness added.

The fake harness holds, as this file's own assumptions, not AWS's behaviour: a policy on the harness's role refuses its
calls to its model DELAY seconds after the call, as it refuses the session's own calls (test_agentcore.py); a command
in a new session is answered whatever the role holds; the running session's probe is the runtime's fake stream, as the
real one reads the probe's lines of JSON as the runtime's stream reads events (tested on its own, CommandStream). The
probe itself is tested against fakes of the microVM's metadata, STS, S3 and the test endpoint, and its signature
against botocore's.
"""
from __future__ import annotations

import ast
import datetime as dt
import io
import json
import sys
import urllib.error
import urllib.parse
from dataclasses import replace
from pathlib import Path

import pytest

import test_agentcore as ta
from arvaken_stop_test import report, result
from arvaken_stop_test.agentcore import fire, harness, probe
from arvaken_stop_test.agentcore import run as running

MODEL = "openai.gpt-oss-20b-1:0"
ROOT = Path(__file__).resolve().parents[1]


class FakeHarnessAWS(ta.FakeAWS):
    def __init__(self, clock, *, harness_boundary=True, model_answers=True, **kw):
        super().__init__(clock, **kw)
        self.harness_boundary = harness_boundary
        self.model_answers = model_answers
        self.harness: dict | None = None
        self.harness_requests: list[dict] = []
        self.turns: list[tuple[float, bool]] = []
        self.commands: list[tuple[float, str]] = []
        self.removed: list[float] = []
        self.profiles_asked: list[str] = []
        self.refused_by = "AccessDeniedException"     # the code a stopped model call's message names
        self.others = []                                # harnesses of yours the kit did not make

    # -- bedrock: an inference profile, and the models it routes to
    def get_inference_profile(self, inferenceProfileIdentifier):
        self.profiles_asked.append(inferenceProfileIdentifier)
        base = inferenceProfileIdentifier.split(".", 1)[1]
        return {"inferenceProfileArn": f"arn:aws:bedrock:{ta.REGION}:{ta.ACCOUNT}:inference-profile/"
                                       f"{inferenceProfileIdentifier}",
                "models": [{"modelArn": f"arn:aws:bedrock:{r}::foundation-model/{base}"}
                           for r in ("eu-west-1", "eu-central-1")]}

    # -- iam: the harness's boundary beside the kit's own
    def get_policy(self, PolicyArn):
        if PolicyArn.endswith(":policy/arvaken-stop-test-boundary-harness") and not self.harness_boundary:
            raise ta.Error("NoSuchEntity")
        return super().get_policy(PolicyArn)

    def get_policy_version(self, PolicyArn, VersionId):
        if PolicyArn.endswith(":policy/arvaken-stop-test-boundary-harness"):
            return {"PolicyVersion": {"Document": json.dumps(harness.boundary_document())}}
        return super().get_policy_version(PolicyArn, VersionId)

    def delete_role_policy(self, RoleName, PolicyName):
        self.removed.append(self.clock.now())
        super().delete_role_policy(RoleName, PolicyName)

    def detach_role_policy(self, RoleName, PolicyArn):
        self.removed.append(self.clock.now())
        super().detach_role_policy(RoleName, PolicyArn)

    # -- bedrock-agentcore-control: the harness, and the runtime AgentCore makes for it
    def create_harness(self, **req):
        self.harness_requests.append(req)
        hid = f"{req['harnessName']}-HaRnEsS123"
        rid = f"harness_{req['harnessName']}-RuNtImE123"
        self.harness = {"harnessId": hid, "harnessName": req["harnessName"], "status": "CREATING",
                        "arn": f"arn:aws:bedrock-agentcore:{ta.REGION}:{ta.ACCOUNT}:harness/{hid}",
                        "runtime": {"id": rid, "gone": False,
                                    "arn": f"arn:aws:bedrock-agentcore:{ta.REGION}:{ta.ACCOUNT}:runtime/{rid}"},
                        "tags": dict(req["tags"])}
        return {"harness": {k: v for k, v in self.harness.items() if k != "runtime"}}

    def _harness(self, hid):
        if self.harness is None or hid != self.harness["harnessId"]:
            raise ta.Error("ResourceNotFoundException")
        return self.harness

    def get_harness(self, harnessId):
        h = self._harness(harnessId)
        status, h["status"] = h["status"], "READY"
        return {"harness": {"harnessId": h["harnessId"], "arn": h["arn"], "status": status, "environment": {
            "agentCoreRuntimeEnvironment": {"agentRuntimeArn": h["runtime"]["arn"],
                                            "agentRuntimeId": h["runtime"]["id"]}}}}

    def delete_harness(self, harnessId):
        h = self._harness(harnessId)
        h["runtime"]["gone"] = True
        self.harness = None

    def list_harnesses(self, nextToken=None):
        return {"harnesses": self.others + ([] if self.harness is None else [
            {"harnessId": self.harness["harnessId"], "harnessName": self.harness["harnessName"],
             "arn": self.harness["arn"]}])}

    def get_agent_runtime(self, agentRuntimeId):
        if agentRuntimeId.startswith("harness_"):
            if self.harness is None or self.harness["runtime"]["id"] != agentRuntimeId:
                raise ta.Error("ResourceNotFoundException")
            return {"status": "READY", "workloadIdentityDetails": {"workloadIdentityArn": (
                f"arn:aws:bedrock-agentcore:{ta.REGION}:{ta.ACCOUNT}:workload-identity-directory/default/"
                f"workload-identity/{agentRuntimeId}")}}
        return super().get_agent_runtime(agentRuntimeId)

    # -- bedrock-agentcore: turns and commands
    def invoke_harness(self, harnessArn, runtimeSessionId, messages):
        now = self.clock.now()
        assert harnessArn == self.harness["arn"] and len(runtimeSessionId) >= 33
        answers = self.model_answers and not self.role_denied(now)
        self.turns.append((now, answers))
        if not answers:     # botocore raises a stream's error event as the call's error, by the event's name
            return {"stream": _raising([{"messageStart": {"role": "assistant"}}], ta.Error(
                "runtimeClientError", f"An error occurred ({self.refused_by}) when calling the ConverseStream "
                "operation: User: arn:aws:sts::111122223333:assumed-role/r/s is not authorized"))}
        return {"stream": [{"messageStart": {"role": "assistant"}},
                           {"contentBlockDelta": {"contentBlockIndex": 0, "delta": {"text": "pong"}}},
                           {"messageStop": {"stopReason": "end_turn"}},
                           {"metadata": {"usage": {"inputTokens": 30, "outputTokens": 1, "totalTokens": 31},
                                         "metrics": {"latencyMs": 400}}}]}

    def invoke_agent_runtime_command(self, agentRuntimeArn, runtimeSessionId, qualifier, contentType, accept, body):
        now = self.clock.now()
        assert agentRuntimeArn == self.harness["arn"] and accept == harness.COMMAND_ACCEPT
        self.commands.append((now, body["command"]))
        out = json.dumps({"at": now + ta.SKEW}) + "\n" if body["command"].endswith(" clock") else ""
        return {"stream": [{"chunk": {"contentStart": {}}}, {"chunk": {"contentDelta": {"stdout": out}}},
                           {"chunk": {"contentStop": {"exitCode": 0, "status": "COMPLETED"}}}]}


def _raising(events, error):
    yield from events
    raise error


def clients(aws) -> running.Clients:
    return replace(ta.clients(aws), bedrock=aws)


def a_run(aws, clock, stop, **over):
    run_name = over.pop("run_name", "r0a1b2c3d")
    aws._run = run_name
    return harness.run(clients(aws), stop, endpoint=ta.ENDPOINT, model=over.pop("model", MODEL),
                       window=over.pop("window", 120.0), clock=clock, run_name=run_name, **over)


@pytest.mark.parametrize("stop, event", [(ta.DENY_ALL, "AttachRolePolicy"), (fire.INLINE, "PutRolePolicy")])
def test_a_policy_on_the_harness_role_stops_its_own_calls_and_its_model_and_new_calls_are_answered(stop, event):
    clock = ta.Clock()
    aws = FakeHarnessAWS(clock)
    r, doc = a_run(aws, clock, stop, repeats=2)
    assert result.check(doc) is doc
    assert doc["stop"] == {"kind": harness.HARNESS_KIND, "fired_by": "the kit", "ref": stop}
    assert doc["agent"]["kind"] == harness.AGENT_KIND and doc["agent"]["ref"].endswith(":harness/arvaken_stop_test_"
                                                                                        "r0a1b2c3d-HaRnEsS123")
    for i in range(2):
        assert ta.outcomes(doc, i) == {"own_calls": "stopped", "another_identity": "not stopped",
                                       "outside_key": "not stopped", "open_internet": "not stopped",
                                       "model": "stopped", "new_calls": "not stopped"}
    rep = harness.details(r, doc)["repeats"][0]
    assert all(rep[p]["fired_source"] == running.AUDIT_RECORD for p in harness.PATHS)
    low, high = rep["model"]["effect_between_seconds"]
    assert low <= ta.DELAY <= high
    assert rep["model"]["errors"] == {"AccessDeniedException": rep["model"]["failures_after"]}
    assert not doc["run"]["left_anything"] and stop not in str(aws.roles) and aws.harness is None
    page = report.page(doc, [d for _, d in harness.results(r)])
    assert page.count(report.NOT_KNOWN) == 4      # its model and new calls, each repeat


def test_the_harness_calls_its_model_and_nothing_else_and_its_role_trusts_agentcore_for_this_run_alone():
    clock = ta.Clock()
    aws = FakeHarnessAWS(clock)
    seen = {}
    real = aws.create_harness

    def keep(**req):
        seen.update(roles=json.loads(json.dumps(aws.roles, default=list)), request=req)
        return real(**req)
    aws.create_harness = keep
    r, _ = a_run(aws, clock, fire.INLINE)
    req, n = seen["request"], harness.harness_names(r.run)
    assert req["harnessName"] == n["harness"] == "arvaken_stop_test_r0a1b2c3d" and req["tags"] == {"arvaken-stop-test":
                                                                                                    r.run}
    assert req["allowedTools"] == [] and "tools" not in req and req["memory"] == {"disabled": {}}
    assert req["maxIterations"] == 1 and req["model"]["bedrockModelConfig"]["modelId"] == MODEL
    # a reasoning model spends its tokens reasoning first: 16 ended every turn as an error (r9e60a621)
    assert req["model"]["bedrockModelConfig"]["maxTokens"] == 512 and req["maxTokens"] == 2048
    assert req["environment"]["agentCoreRuntimeEnvironment"]["networkConfiguration"] == {"networkMode": "PUBLIC"}
    role = seen["roles"][n["agent_role"]]
    assert role["boundary"] == f"arn:aws:iam::{ta.ACCOUNT}:policy/{harness.HARNESS_BOUNDARY}"
    [statement] = role["trust"]["Statement"]
    assert statement["Principal"] == {"Service": "bedrock-agentcore.amazonaws.com"}
    assert statement["Condition"]["ArnLike"]["aws:SourceArn"] == [
        f"arn:aws:bedrock-agentcore:{ta.REGION}:{ta.ACCOUNT}:harness/arvaken_stop_test_{r.run}-*",
        f"arn:aws:bedrock-agentcore:{ta.REGION}:{ta.ACCOUNT}:runtime/harness_arvaken_stop_test_{r.run}-*"]
    own = role["inline"]["own-calls"]["Statement"]
    [model] = [s for s in own if s["Action"] == list(harness.MODEL_CALLS)]
    assert model["Resource"] == [f"arn:aws:bedrock:{ta.REGION}::foundation-model/{MODEL}"]


def _role_model_arns(aws, run) -> list[str]:
    own = aws.roles[harness.harness_names(run)["agent_role"]]["inline"]["own-calls"]["Statement"]
    [model] = [s for s in own if s["Action"] == list(harness.MODEL_CALLS)]
    return model["Resource"]


def test_the_role_may_call_the_runs_model_alone_or_its_profile_and_the_models_the_profile_routes_to():
    # the boundary allows any model, as an outer limit only (the founder, 29 October 2026, ruling 3, 12a)
    clock = ta.Clock()
    aws = FakeHarnessAWS(clock)
    seen = {}
    real = aws.create_harness

    def keep(**req):
        seen["arns"] = _role_model_arns(aws, aws.run)
        return real(**req)
    aws.create_harness = keep
    a_run(aws, clock, fire.INLINE)
    assert seen["arns"] == [f"arn:aws:bedrock:{ta.REGION}::foundation-model/{MODEL}"]
    profile = "eu.amazon.nova-micro-v1:0"
    a_run(aws, clock, fire.INLINE, model=profile, run_name="r1b2c3d4e")
    assert seen["arns"] == [
        f"arn:aws:bedrock:{ta.REGION}:{ta.ACCOUNT}:inference-profile/{profile}",
        "arn:aws:bedrock:eu-central-1::foundation-model/amazon.nova-micro-v1:0",
        "arn:aws:bedrock:eu-west-1::foundation-model/amazon.nova-micro-v1:0"]
    assert aws.profiles_asked == [profile]


@pytest.mark.parametrize("stop, model", [(fire.DENY, MODEL), (fire.DENY_AND_END, MODEL), (fire.INLINE, "not a model"),
                                         (fire.INLINE, "")])
def test_a_harness_takes_a_policy_on_its_role_and_a_model_or_nothing_is_made(stop, model):
    clock = ta.Clock()
    aws = FakeHarnessAWS(clock)
    with pytest.raises(fire.Refused):
        a_run(aws, clock, stop, model=model)
    assert aws.harness is None and not aws.roles and not aws.buckets


def test_without_the_harness_boundary_nothing_is_made():
    clock = ta.Clock()
    aws = FakeHarnessAWS(clock, harness_boundary=False)
    with pytest.raises(fire.Refused) as e:
        a_run(aws, clock, fire.INLINE)
    assert str(e.value) == harness.NO_HARNESS_BOUNDARY
    assert aws.harness is None and not aws.roles and not aws.buckets


def test_a_model_that_does_not_answer_before_the_stop_times_nothing_and_what_was_made_is_removed():
    clock = ta.Clock()
    aws = FakeHarnessAWS(clock, model_answers=False)
    with pytest.raises(running.NotStarted) as e:
        a_run(aws, clock, fire.INLINE)
    assert str(e.value) == harness.MODEL_DID_NOT_WORK.format(model=MODEL, codes="AccessDeniedException",
                                                             region=ta.REGION)
    assert e.value.run.left_behind == [] and aws.harness is None and not aws.roles and not aws.buckets
    assert not any(ev["name"] in ("PutRolePolicy", "AttachRolePolicy") and ev["params"]["roleName"].endswith("-agent")
                   and ev["at"] > aws.turns[0][0] for ev in aws.events)


def test_between_repeats_the_kit_waits_until_turns_are_answered_again_for_the_hold():
    clock = ta.Clock()
    aws = FakeHarnessAWS(clock)
    r, doc = a_run(aws, clock, fire.INLINE, repeats=2)
    removed = aws.removed[0]
    assert r.repeats[1].opened - removed >= running.RECOVERED
    assert all(ok for t, ok in aws.turns if removed + 1 < t < r.repeats[1].opened)
    assert ta.outcomes(doc, 1)["model"] == "stopped"


def test_the_model_is_called_about_once_a_second_while_a_stop_is_watched_and_new_calls_make_none():
    clock = ta.Clock()
    aws = FakeHarnessAWS(clock)
    r, _ = a_run(aws, clock, fire.INLINE)
    rep = r.repeats[0]
    during = [t for t, _ in aws.turns if rep.fired_before <= t <= rep.fired_after + r.window + running.HOLD]
    assert len(during) <= r.window + running.HOLD + 2
    assert all(c == harness.NOOP or c.endswith(" clock") for _, c in aws.commands)
    assert rep.new_calls >= r.window


def test_clean_finds_an_interrupted_runs_harness_by_its_name_and_takes_its_stop_off():
    clock = ta.Clock()
    aws = FakeHarnessAWS(clock)
    aws._run = "r0a1b2c3d"
    c = clients(aws)
    r = harness.HarnessRun(run="r0a1b2c3d", stop_ref=fire.INLINE, window=0.0, region=ta.REGION, account=ta.ACCOUNT,
                           model=MODEL)
    harness.make(c, r, ta.ENDPOINT, clock)
    fire.fire(c.iam, c.control, r.run, fire.INLINE, "")
    found = harness.HarnessRun(run="r0a1b2c3d", stop_ref=fire.INLINE, window=0.0, region=ta.REGION,
                               account=ta.ACCOUNT)
    harness.tear_down(c, found, clock)
    assert found.left_behind == [] and aws.harness is None and not aws.roles and not aws.buckets
    assert any(x.startswith("the harness arn:aws:bedrock-agentcore:") for x in found.checked_gone)
    assert any(x.startswith("the harness's runtime ") for x in found.checked_gone)


def test_a_harness_the_tag_index_names_after_it_is_deleted_is_checked_by_its_own_id():
    clock = ta.Clock()
    aws = FakeHarnessAWS(clock)
    phantom = f"arn:aws:bedrock-agentcore:{ta.REGION}:{ta.ACCOUNT}:harness/arvaken_stop_test_r0a1b2c3d-bTfQWW86KQ"
    aws.get_resources = lambda TagFilters: {"ResourceTagMappingList": [{"ResourceARN": phantom}]}
    r, doc = a_run(aws, clock, fire.INLINE)
    assert not doc["run"]["left_anything"] and f"the harness {phantom}, which the tag index names" in r.checked_gone


# -- a turn, a command, and the probe's stream
class Data:
    def __init__(self, stream):
        self.stream = stream

    def invoke_harness(self, **kw):
        return {"stream": self.stream}

    def invoke_agent_runtime_command(self, **kw):
        self.asked = kw
        return {"stream": self.stream}


def _run_with(stream) -> tuple[running.Clients, running.Run]:
    c = running.Clients(iam=None, s3=None, control=None, data=Data(stream), cloudtrail=None, iam_trail=None,
                        tagging=None, region=ta.REGION)
    r = harness.HarnessRun(run="r0a1b2c3d", stop_ref=fire.INLINE, window=60.0, region=ta.REGION)
    r.outputs.update(Harness=f"arn:aws:bedrock-agentcore:{ta.REGION}:{ta.ACCOUNT}:harness/h-1",
                     Bucket="arvaken-stop-test-r0a1b2c3d", Endpoint=ta.ENDPOINT,
                     SecondRole=f"arn:aws:iam::{ta.ACCOUNT}:role/arvaken-stop-test-r0a1b2c3d-second")
    return c, r


@pytest.mark.parametrize("events, found", [
    ([{"messageStop": {"stopReason": "end_turn"}}, {"metadata": {"usage": {"outputTokens": 1}}}], None),
    ([{"runtimeClientError": {"message": "An error occurred (ThrottlingException) when calling ConverseStream"}}],
     "ThrottlingException"),
    ([{"internalServerException": {"message": "something went wrong"}}], "InternalServerException"),
    ([{"messageStop": {"stopReason": "end_turn"}}, {"metadata": {"usage": {"outputTokens": 0}}}], "NoAnswer"),
    ([{"messageStop": {"stopReason": "end_turn"}}], "NoAnswer"),
    (ta.Error("runtimeClientError", "An error occurred (AccessDeniedException) when calling the ConverseStream "
                                    "operation: User: arn:aws:sts::1:assumed-role/r/s is not authorized"),
     "AccessDeniedException"),
    (ta.Error("runtimeClientError", "Model stopped generating due to maximum token limit. For more information see: "
                                    "https://strandsagents.com/docs/#maxtokensreachedexception"), "runtimeClientError"),
    (ta.Error("ExpiredTokenException", "The security token included in the request is expired"),
     "ExpiredTokenException"),
])
def test_a_turn_worked_only_where_the_model_answered_and_a_failure_keeps_its_code_alone(events, found):
    c, r = _run_with(_raising([{"messageStart": {}}], events) if isinstance(events, Exception) else events)
    if found is None:
        harness.turn(c, r, "s" * 40)
        return
    with pytest.raises(Exception) as e:
        harness.turn(c, r, "s" * 40)
    assert running.code(e.value) == found and "not authorized" not in str(e.value)


class Closable(list):
    closed = False

    def close(self):
        self.closed = True


def _stdout(text: str) -> dict:
    return {"chunk": {"contentDelta": {"stdout": text}}}


def test_the_probes_stream_reads_lines_split_across_chunks_and_a_watch_done_is_not_a_session_ended():
    lines = [{"at": 1.0, "session_expires": 3601.0, "error": None, "credentials_from": "instance"},
             {"at": 2.0, "n": 0, "beats": {"own_calls": {"at": 2.0, "ok": True}}}, {"at": 3.0, "done": True}]
    text = "".join(json.dumps(x) + "\n" for x in lines)
    c, r = _run_with(Closable([{"chunk": {"contentStart": {}}}, _stdout(text[:17]), _stdout(text[17:60]),
                               _stdout(text[60:]), {"chunk": {"contentStop": {"exitCode": 0, "status": "COMPLETED"}}}]))
    stream = harness.CommandStream(c, r, "r0a1b2c3d-session-" + "a" * 32, 600.0, ta.Clock())
    stream.thread.join(timeout=5)
    assert stream.poll() == lines and stream.ended[1] == "done" and stream.credentials_from == "instance"
    body = c.data.asked["body"]
    assert body["timeout"] == 630 and body["command"].endswith(
        f" 600.0 r0a1b2c3d-session-{'a' * 32} {ta.REGION} arvaken-stop-test-r0a1b2c3d {ta.ENDPOINT} "
        f"arn:aws:iam::{ta.ACCOUNT}:role/arvaken-stop-test-r0a1b2c3d-second")
    assert "OUTSIDE_KEY" not in body["command"]


@pytest.mark.parametrize("last, how", [({"chunk": {"contentStop": {"exitCode": 137, "status": "TIMED_OUT"}}},
                                        "CommandEnded:TIMED_OUT"),
                                       ({"accessDeniedException": {"message": "not authorized"}},
                                        "AccessDeniedException")])
def test_the_probes_stream_closing_early_says_how(last, how):
    c, r = _run_with(Closable([_stdout(json.dumps({"at": 2.0, "n": 0, "beats": {}}) + "\n"), last]))
    stream = harness.CommandStream(c, r, "s" * 40, 600.0, ta.Clock())
    stream.thread.join(timeout=5)
    assert stream.ended[1] == how


def test_a_new_call_is_a_command_that_does_nothing_and_fails_by_its_code():
    c, r = _run_with([{"chunk": {"contentStop": {"exitCode": 1, "status": "COMPLETED"}}}])
    calls = harness.NewCommands(c, r, ta.Clock())
    with pytest.raises(Exception) as e:
        calls.call()
    assert running.code(e.value) == "Exit1" and c.data.asked["body"] == {"command": harness.NOOP,
                                                                          "timeout": harness.NOOP_TIMEOUT}


# -- the probe, in the harness's microVM
def test_the_probe_signs_its_calls_as_botocore_does():
    import botocore.auth
    import botocore.awsrequest
    import botocore.credentials
    now = 1_761_750_000.0
    real = botocore.auth.get_current_datetime
    botocore.auth.get_current_datetime = lambda: dt.datetime.fromtimestamp(now, tz=dt.timezone.utc).replace(tzinfo=None)
    try:
        for token in (None, "TOKEN/with+chars="):
            creds = {"key": "AKIDEXAMPLE", "secret": "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "token": token}
            theirs_creds = botocore.credentials.Credentials(creds["key"], creds["secret"], token)
            url = probe.s3_url("arvaken-stop-test-r1", "own/r1-session-ab/7", "eu-central-1")
            for method, at, service, body, headers in [
                    ("PUT", url, "s3", b"x", {}), ("GET", url, "s3", b"", {}),
                    ("POST", "https://sts.eu-central-1.amazonaws.com/", "sts", b"Action=AssumeRole&Version=2011-06-15",
                     {"content-type": "application/x-www-form-urlencoded; charset=utf-8"})]:
                mine = probe.sign(method, at, "eu-central-1", service, creds, body, headers, now=now)
                request = botocore.awsrequest.AWSRequest(method=method, url=at, data=body, headers=dict(headers))
                (botocore.auth.S3SigV4Auth if service == "s3" else botocore.auth.SigV4Auth)(
                    theirs_creds, service, "eu-central-1").add_auth(request)
                assert mine["authorization"] == request.headers["Authorization"], (method, service, token)
    finally:
        botocore.auth.get_current_datetime = real


def test_the_probe_uses_pythons_standard_library_alone():
    tree = ast.parse((ROOT / "src" / "arvaken_stop_test" / "agentcore" / "probe.py").read_text(encoding="utf-8"))
    modules = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    modules |= {n.module.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    assert modules and modules <= set(sys.stdlib_module_names)


class Metadata:
    """The microVM's metadata, STS, S3 and the test endpoint, as the probe reaches them."""

    def __init__(self, denied: bool = False):
        self.denied, self.asked = denied, []

    def __call__(self, request, timeout=probe.TIMEOUT):
        url, method = request.full_url, request.get_method()
        self.asked.append((method, url, dict(request.header_items())))
        if url == f"{probe.IMDS}/latest/api/token":
            return b"imds-token"
        if url == f"{probe.IMDS}/latest/meta-data/iam/security-credentials/":
            return b"arvaken-stop-test-r1-agent\n"
        if url.startswith(f"{probe.IMDS}/latest/meta-data/iam/security-credentials/"):
            return json.dumps({"AccessKeyId": "ASIAROLE", "SecretAccessKey": "secret", "Token": "role-token",
                               "Expiration": "2099-01-01T00:00:00Z"}).encode()
        if url.startswith("https://sts."):
            assert urllib.parse.parse_qs(request.data.decode())["RoleArn"] == ["arn:aws:iam::1:role/second"]
            return (b"<AssumeRoleResponse><AssumeRoleResult><Credentials><AccessKeyId>ASIASECOND</AccessKeyId>"
                    b"<SecretAccessKey>s2</SecretAccessKey><SessionToken>t2</SessionToken>"
                    b"<Expiration>2099-01-01T01:00:00.123Z</Expiration></Credentials></AssumeRoleResult>"
                    b"</AssumeRoleResponse>")
        if ".s3." in url:
            if self.denied and "/own/" in url:
                raise urllib.error.HTTPError(url, 403, "Forbidden", {}, io.BytesIO(
                    b"<Error><Code>AccessDenied</Code><Message>names the role</Message></Error>"))
            return b"x"
        return b"ok"


def test_the_probe_takes_the_roles_keys_from_the_microvm_and_tries_its_four_paths(monkeypatch):
    monkeypatch.setattr(probe, "EVERY", 0.01)
    out, seen = io.StringIO(), Metadata(denied=True)
    probe.watch(0.03, "r1-session-ab", "eu-central-1", "arvaken-stop-test-r1", "https://stop-test.example/",
                "arn:aws:iam::1:role/second", env={"OUTSIDE_KEY": "k"}, opener=seen, out=out)
    lines = [json.loads(x) for x in out.getvalue().splitlines()]
    assert lines[0]["credentials_from"] == "instance" and lines[0]["error"] is None
    assert lines[0]["session_expires"] == dt.datetime(2099, 1, 1, 1, tzinfo=dt.timezone.utc).timestamp()
    assert lines[-1]["done"] is True and len(lines) >= 3
    beats = lines[1]["beats"]
    assert beats["own_calls"] == {"at": beats["own_calls"]["at"], "ok": False, "error": "AccessDenied"}
    assert all(beats[p]["ok"] for p in ("another_identity", "outside_key", "open_internet"))
    own = [h for m, u, h in seen.asked if "/own/" in u]
    assert own and all("ASIAROLE/" in h["Authorization"] and h["X-amz-security-token"] == "role-token" for h in own)
    another = [h for m, u, h in seen.asked if "/another/" in u]
    assert another and all("ASIASECOND/" in h["Authorization"] for h in another)
    keyed = [h for m, u, h in seen.asked if u.endswith("/key")]
    assert keyed and keyed[0]["Authorization"] == "Bearer k"
    assert "names the role" not in out.getvalue()


def test_the_probe_runs_as_one_command_well_within_awss_limit():
    command = harness.probe_command("900.0", "r0a1b2c3d-session-" + "a" * 32, "eu-central-1")
    assert len(command.encode()) < 64 * 1024 and command.startswith("PY=$(command -v python3 || command -v python)")


# -- the harness's boundary
def test_the_harness_boundary_is_the_kits_boundary_and_what_a_harness_needs_beside_it():
    packaged = harness.boundary_document()
    shipped = json.loads((ROOT / "permissions" / "aws-boundary-harness.json").read_text(encoding="utf-8"))
    kits = json.loads((ROOT / "permissions" / "aws-boundary.json").read_text(encoding="utf-8"))
    assert packaged == shipped
    assert shipped["Statement"][:len(kits["Statement"])] == kits["Statement"]
    beside = {s["Sid"]: s for s in shipped["Statement"][len(kits["Statement"]):]}
    actions = {a for s in beside.values() for a in (s["Action"] if isinstance(s["Action"], list) else [s["Action"]])}
    assert actions == {*harness.MODEL_CALLS, harness.IMAGE_TOKEN, harness.BEARER_TOKEN, *harness.WORKLOAD_TOKEN}
    # the bearer token for Amazon ECR Public alone (the founder, 29 October 2026, ruling 3, 12b)
    assert beside["TheHarnessesManagedImageBearerToken"]["Condition"] == harness.BEARER_FOR
    assert "Condition" not in beside["TheHarnessesManagedImage"]


def test_with_your_own_stop_the_kit_only_attaches_it_to_the_test_agents_role_and_detaches_it():
    # it never edits or deletes your policy (the founder, 29 October 2026, ruling 1, b)
    clock = ta.Clock()
    aws = FakeHarnessAWS(clock)
    import inspect
    asked = []
    for name, _ in inspect.getmembers(type(aws), inspect.isfunction):
        if not name.startswith("_"):
            method = getattr(aws, name)

            def watch(*a, _name=name, _method=method, **kw):
                if ta.DENY_ALL in json.dumps([a, kw], default=str):
                    asked.append((_name, kw.get("RoleName")))
                return _method(*a, **kw)
            setattr(aws, name, watch)
    r, _ = a_run(aws, clock, ta.DENY_ALL, repeats=2)
    role = harness.harness_names(r.run)["agent_role"]
    assert {n for n, _ in asked} <= {"attach_role_policy", "detach_role_policy", "get_policy", "get_policy_version",
                                     "simulate_custom_policy", "list_attached_role_policies"}
    assert {who for n, who in asked if n in ("attach_role_policy", "detach_role_policy")} == {role}
    assert sum(n == "attach_role_policy" for n, _ in asked) == sum(n == "detach_role_policy" for n, _ in asked) == 2


def test_a_model_call_refused_for_a_limit_on_your_account_is_never_counted_as_stopped():
    clock = ta.Clock()
    aws = FakeHarnessAWS(clock)
    aws.refused_by = "ThrottlingException"      # the fake refuses the role's model calls under the stop, as throttled
    r, doc = a_run(aws, clock, fire.INLINE)
    assert ta.outcomes(doc)["model"] != "stopped" and ta.outcomes(doc)["own_calls"] == "stopped"
    model = harness.details(r, doc)["repeats"][0]["model"]
    assert model["errors"].get("ThrottlingException", 0) > 0 and model["failures_after"] == 0


def test_no_other_harness_of_yours_is_named_in_the_result_the_page_or_what_the_kit_says():
    clock = ta.Clock()
    aws = FakeHarnessAWS(clock)
    aws.others = [{"harnessId": "your_own_harness-AbC", "harnessName": "your_own_harness",
                   "arn": f"arn:aws:bedrock-agentcore:{ta.REGION}:{ta.ACCOUNT}:harness/your_own_harness-AbC"}]
    said = []
    r, doc = a_run(aws, clock, fire.INLINE, say=said.append)
    found = harness.HarnessRun(run=r.run, stop_ref=fire.INLINE, window=0.0, region=ta.REGION, account=ta.ACCOUNT)
    harness.tear_down(clients(aws), found, clock, say=said.append)      # clean, which lists your harnesses
    written = json.dumps([doc, harness.details(r, doc), found.left_behind, found.checked_gone, said])
    written += report.page(doc, [d for _, d in harness.results(r)])
    assert "your_own_harness" not in written


def _harness_section() -> str:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    return readme[readme.index("### On a harness"):readme.index("## On Google Cloud")]


def test_the_readme_and_the_policy_agree_on_what_a_harness_run_makes():
    policy = json.loads((ROOT / "permissions" / "aws-agentcore-policy.json").read_text(encoding="utf-8"))
    granted = {r for s in policy["Statement"] for r in (s["Resource"] if isinstance(s["Resource"], list)
                                                        else [s["Resource"]]) if "harness_arvaken_stop_test_" in r}
    section = " ".join(_harness_section().split())
    # no memory is made for a harness with memory disabled (r84285f18, r9e60a621, r5a570e9d: no CreateMemory)
    assert not any(":memory/" in r for r in granted) and "has no tools and no memory" in section
    assert any(":runtime/harness_arvaken_stop_test_" in r for r in granted) and "Runtime" in section


# What a run's policy must never reach: an AgentCore runtime, memory, workload identity or log group, or a harness, that
# the run did not make (the founder, 29 October 2026, ruling 3, 13a and 13b).
AC = "arn:aws:bedrock-agentcore:eu-central-1:111122223333:"
IDENTITY = AC + "workload-identity-directory/default/workload-identity/"
LOGS = "arn:aws:logs:eu-central-1:111122223333:log-group:/aws/bedrock-agentcore/runtimes/"
YOURS = [
    ("bedrock-agentcore:DeleteAgentRuntime", AC + "runtime/your_agent-AbC"),
    ("bedrock-agentcore:UpdateAgentRuntime", AC + "runtime/your_agent-AbC"),
    ("bedrock-agentcore:DeleteMemory", AC + "memory/your_memory-AbC"),
    ("bedrock-agentcore:UpdateMemory", AC + "memory/your_memory-AbC"),
    ("bedrock-agentcore:DeleteWorkloadIdentity", IDENTITY + "your_agent-AbC"),
    ("bedrock-agentcore:UpdateWorkloadIdentity", IDENTITY + "your_agent-AbC"),
    ("logs:DeleteLogGroup", LOGS + "your_agent-AbC"),
    ("logs:PutRetentionPolicy", LOGS + "your_agent-AbC"),
    ("bedrock-agentcore:DeleteHarness", AC + "harness/your_harness-AbC"),
    ("bedrock-agentcore:UpdateHarness", AC + "harness/your_harness-AbC"),
]
OURS = [
    ("bedrock-agentcore:DeleteAgentRuntime", AC + "runtime/harness_arvaken_stop_test_r0a1b2c3d-AbC"),
    ("bedrock-agentcore:DeleteHarness", AC + "harness/arvaken_stop_test_r0a1b2c3d-AbC"),
    ("bedrock-agentcore:DeleteWorkloadIdentity", IDENTITY + "harness_arvaken_stop_test_r0a1b2c3d-AbC"),
    ("logs:DeleteLogGroup", LOGS + "harness_arvaken_stop_test_r0a1b2c3d-AbC"),
]


def _allows(policy: dict, action: str, resource: str) -> bool:
    """Whether any statement allows the action on the resource, matched as IAM matches them: `*` and `?` in an action
    or an ARN, case-sensitively for an ARN. A statement with a condition the request does not meet allows nothing."""
    import fnmatch
    listed = lambda x: x if isinstance(x, list) else [x]  # noqa: E731
    for s in policy["Statement"]:
        if s["Effect"] != "Allow" or "Condition" in s:
            continue
        if any(fnmatch.fnmatch(action.lower(), a.lower()) for a in listed(s["Action"])) and \
                any(fnmatch.fnmatchcase(resource, r) for r in listed(s["Resource"])):
            return True
    return False


def test_the_kits_agentcore_policy_reaches_nothing_of_yours_and_does_reach_what_a_run_makes():
    policy = json.loads((ROOT / "permissions" / "aws-agentcore-policy.json").read_text(encoding="utf-8"))
    assert [(a, r) for a, r in YOURS if _allows(policy, a, r)] == []
    assert all(_allows(policy, a, r) for a, r in OURS)


@pytest.mark.skipif(not __import__("os").environ.get("STOP_TEST_IAM_SIMULATOR"),
                    reason="calls IAM's policy simulator in your account: set STOP_TEST_IAM_SIMULATOR=1 to run it")
def test_iams_policy_simulator_denies_the_kits_agentcore_policy_anything_of_yours():
    import boto3
    policy = (ROOT / "permissions" / "aws-agentcore-policy.json").read_text(encoding="utf-8")
    iam = boto3.client("iam")
    for wanted, cases in (("implicitDeny", YOURS), ("allowed", OURS)):
        for action, resource in cases:
            found = iam.simulate_custom_policy(PolicyInputList=[policy], ActionNames=[action],
                                               ResourceArns=[resource])["EvaluationResults"]
            assert [r["EvalDecision"] for r in found] == [wanted], (action, resource)


def test_the_kits_agentcore_policy_lets_it_make_a_harnesss_roles_under_their_own_boundary_alone():
    policy = json.loads((ROOT / "permissions" / "aws-agentcore-policy.json").read_text(encoding="utf-8"))
    [roles] = [s for s in policy["Statement"] if s["Sid"] == "TheRunsRolesEachUnderTheKitsBoundary"]
    assert roles["Condition"]["StringLike"]["iam:PermissionsBoundary"] == [
        "arn:aws:iam::*:policy/arvaken-stop-test-boundary", f"arn:aws:iam::*:policy/{harness.HARNESS_BOUNDARY}"]
