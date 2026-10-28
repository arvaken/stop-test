"""The optional fifth row, a call to a model, on AWS (--model; the design's section 4: "An optional fifth row, off by
default because it costs money: one call to a model"), against test_aws_run.py's fake AWS on its virtual clock.

The model's call is made as the agent's own role, so a stop on that role is expected to reach it as it reaches its own
calls; it is timed, written and shown as they are. Without a model nothing changes: the same four paths, the same
template, the same result."""
from __future__ import annotations

import json

import pytest

from arvaken_stop_test import cli, report, result
from arvaken_stop_test.aws import fire as firing
from arvaken_stop_test.aws import run as running
from arvaken_stop_test.aws.stack import MODEL_ID, is_model_id, model_resources, template, template_body
from arvaken_stop_test.timing import PATH_WORDS
from test_aws_run import ENDPOINT, STOP, Clock, FakeAWS, a_run, clients

MODEL = "eu.amazon.nova-micro-v1:0"
FIVE = ("own_calls", "another_identity", "outside_key", "open_internet", "model")


# The stack
def test_without_a_model_the_template_is_as_before_and_with_one_it_adds_its_variable_one_statement_and_its_boundary():
    plain = template("r0123abcd", ENDPOINT, outside_key="k" * 32)
    code = plain["Resources"]["Agent"]["Properties"]["Code"]["ZipFile"]       # the agent's code, which has the model's
    assert "bedrock" not in json.dumps(plain).replace(json.dumps(code), "")
    assert "MODEL" not in plain["Resources"]["Agent"]["Properties"]["Environment"]["Variables"]
    assert template_body("r0123abcd", ENDPOINT, outside_key="k" * 32) == \
        template_body("r0123abcd", ENDPOINT, outside_key="k" * 32, model="")
    with_one = template("r0123abcd", ENDPOINT, outside_key="k" * 32, model=MODEL)
    agent = with_one["Resources"]["Agent"]["Properties"]["Environment"]["Variables"]
    assert agent.pop("MODEL") == MODEL
    own = with_one["Resources"]["AgentRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]
    assert own.pop() == {"Effect": "Allow", "Action": "bedrock:InvokeModel", "Resource": model_resources(MODEL)}
    for role in ("AgentRole", "SecondRole"):              # both roles under the boundary of a run with a model
        assert with_one["Resources"][role]["Properties"].pop("PermissionsBoundary") == {
            "Fn::Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:policy/arvaken-stop-test-boundary-model"}
        plain["Resources"][role]["Properties"].pop("PermissionsBoundary")
    assert with_one == plain                       # and nothing else: the second role, the bucket, the function's code


def test_a_models_id_is_allowed_on_that_model_in_the_runs_region():
    assert model_resources("amazon.nova-micro-v1:0") == [
        {"Fn::Sub": "arn:${AWS::Partition}:bedrock:${AWS::Region}::foundation-model/amazon.nova-micro-v1:0"}]
    assert model_resources("anthropic.claude-3-haiku-20240307-v1:0") == [
        {"Fn::Sub": "arn:${AWS::Partition}:bedrock:${AWS::Region}::foundation-model/"
                    "anthropic.claude-3-haiku-20240307-v1:0"}]


@pytest.mark.parametrize(("profile", "model"), [
    ("eu.amazon.nova-micro-v1:0", "amazon.nova-micro-v1:0"),
    ("us.anthropic.claude-3-haiku-20240307-v1:0", "anthropic.claude-3-haiku-20240307-v1:0"),
    ("apac.amazon.nova-lite-v1:0", "amazon.nova-lite-v1:0"),
    ("global.anthropic.claude-sonnet-4-20250514-v1:0", "anthropic.claude-sonnet-4-20250514-v1:0"),
    ("us-gov.anthropic.claude-3-haiku-20240307-v1:0", "anthropic.claude-3-haiku-20240307-v1:0")])
def test_an_inference_profiles_id_is_allowed_on_the_profile_and_on_its_model_in_every_region(profile, model):
    """AWS's Bedrock guide (prerequisites for inference profiles): "When you specify an inference profile in the
    Resource field ..., you must also specify the foundation model in each Region associated with it.\""""
    assert model_resources(profile) == [
        {"Fn::Sub": "arn:${AWS::Partition}:bedrock:${AWS::Region}:${AWS::AccountId}:inference-profile/" + profile},
        {"Fn::Sub": f"arn:${{AWS::Partition}}:bedrock:*::foundation-model/{model}"}]


@pytest.mark.parametrize("not_one", ["*", "amazon.*", "${AWS::AccountId}", "amazon.nova/../*", "Amazon.Nova-Micro",
                                     "arn:aws:bedrock:eu-central-1::foundation-model/amazon.nova-micro-v1:0",
                                     "nova-micro", "amazon.nova micro", "amazon.nova-micro-v1:0\n", ""])
def test_anything_but_a_model_or_a_profiles_id_is_never_written_into_the_template(not_one):
    assert not is_model_id(not_one) and not MODEL_ID.fullmatch(not_one)
    if not_one:
        with pytest.raises(ValueError):
            template("r0123abcd", ENDPOINT, model=not_one)


# A run
def test_a_run_with_a_model_times_it_as_a_fifth_path_as_its_own_calls_are():
    clock = Clock()
    aws = FakeAWS(clock)
    r, doc = a_run(aws, clock, model=MODEL)
    assert r.paths == FIVE and result.check(doc) == doc
    rep = doc["repeats"][0]
    assert list(rep) == list(FIVE)
    assert {p: v["outcome"] for p, v in rep.items()} == {
        "own_calls": "stopped", "another_identity": "not stopped", "outside_key": "not stopped",
        "open_internet": "not stopped", "model": "stopped"}
    assert rep["model"]["fired_at"] == rep["own_calls"]["fired_at"]      # from the same firing moment
    found = running.results(r)[0][1]["model"]
    assert found.effect_between and found.fired_source == "CloudTrail's record of the call, to the whole second"
    assert aws.stack["template"]["Resources"]["Agent"]["Properties"]["Environment"]["Variables"]["MODEL"] == MODEL
    # what the page and the details show of it, where the four are shown
    page = report.page(doc, [d for _, d in running.results(r)])
    assert PATH_WORDS["model"] == "a call to a model" and page.count("<td>a call to a model</td>") == 1
    details = running.details(r, doc)
    assert list(details["repeats"][0]) == list(FIVE) and details["repeats"][0]["model"]["outcome"] == "stopped"
    assert details["model"] == MODEL
    assert "AccessDeniedException" in page and "AccessDeniedException" not in json.dumps(doc)
    assert MODEL not in json.dumps(doc)                    # the result's format holds no model, as before (result.py)
    assert doc["run"]["calls"] == sum(len(b) for b in r.repeats[0].beats.values()) + 5 * running.WARM_UP


def test_without_a_model_a_run_is_as_before():
    clock = Clock()
    aws = FakeAWS(clock)
    r, doc = a_run(aws, clock)
    assert r.paths == running.AWS_PATHS and list(doc["repeats"][0]) == list(running.AWS_PATHS)
    assert "model" not in running.details(r, doc) and "model" not in r.repeats[0].beats
    agent = aws.stack["template"]["Resources"]["Agent"]["Properties"]
    assert "MODEL" not in agent["Environment"]["Variables"]
    assert "bedrock" not in json.dumps(aws.stack["template"]["Resources"]["AgentRole"])


def test_with_a_model_each_kind_of_stop_is_expected_to_reach_it_and_the_repeats_wait_for_it_again():
    for stop in (STOP, firing.REVOKE, firing.INLINE):
        clock = Clock()
        aws = FakeAWS(clock)
        r, doc = a_run(aws, clock, stop_ref=stop, repeats=2, model=MODEL)
        assert [rep["model"]["outcome"] for rep in doc["repeats"]] == ["stopped", "stopped"], stop
        assert report.expected(doc["stop"]["kind"], "model") == "stopped"
        assert all(f.successes_after_first_refusal == 0 for f in (d["model"] for _, d in running.results(r)))


def test_lambda_refusing_to_run_the_agent_is_counted_on_the_model_path_too():
    clock = Clock()
    r, doc = a_run(FakeAWS(clock, cold_after=20.0), clock, stop_ref=firing.INLINE, model=MODEL)
    assert {p: v["outcome"] for p, v in doc["repeats"][0].items()} == {p: "stopped" for p in FIVE}
    assert running.REFUSED + "KMSAccessDeniedException" in running.results(r)[0][1]["model"].errors


@pytest.mark.parametrize("code", ["AccessDeniedException", "ValidationException"])
def test_a_model_call_that_did_not_work_before_the_stop_times_nothing_and_says_why(code):
    """A model ID that is wrong, or a model not enabled in the account: the kit says so, fires nothing, times nothing,
    and removes what it made, rather than time the other four without it."""
    clock, said = Clock(), []
    aws = FakeAWS(clock, model_error=code)
    with pytest.raises(running.NotStarted) as e:
        a_run(aws, clock, model=MODEL, say=said.append)
    words = running.MODEL_DID_NOT_WORK.format(model=MODEL, codes=f"{code} {running.WARM_UP}", region="eu-central-1")
    assert str(e.value) == words and said == [words]
    assert words == (f"Before the stop, a call to the model {MODEL} did not work ({code} 10), so nothing was timed. "
                     "Check that your account can call it in eu-central-1.")
    assert isinstance(e.value, firing.Refused)
    assert not aws.attach_calls and not aws.attached and aws.invocations == 1 + running.WARM_UP
    assert aws.stack["status"] == "DELETED" and e.value.run.left_behind == [] and e.value.run.checked_gone
    assert e.value.run.repeats == []


def test_through_a_gateway_a_model_call_that_did_not_work_asks_for_no_mark_and_a_gateway_carrying_nothing_says_so():
    from test_aws_gateway import through
    clock, said = Clock(), []
    aws = FakeAWS(clock, gateway_refuses={"model"})
    with pytest.raises(running.NotStarted):
        through(aws, clock, said=said, model=MODEL)
    assert said == [running.MODEL_DID_NOT_WORK.format(model=MODEL, codes=f"ProxyConnectionError {running.WARM_UP}",
                                                      region="eu-central-1")]
    clock, said = Clock(), []
    nothing = FakeAWS(clock, gateway_refuses=set(FIVE))
    r, doc, marks = through(nothing, clock, said=said, model=MODEL)
    assert running.NOTHING_THROUGH_THE_GATEWAY in said and not marks
    assert {v["outcome"] for v in doc["repeats"][0].values()} == {"not measured"}
    assert list(doc["repeats"][0]) == list(FIVE)
    # and where the gateway carries it, the model's call is timed from the mark as every other path is
    clock = Clock()
    r, doc, marks = through(FakeAWS(clock), clock, model=MODEL)
    assert {p: v["outcome"] for p, v in doc["repeats"][0].items()} == {p: "stopped" for p in FIVE}
    assert {f.fired_source for f in running.results(r)[0][1].values()} == {running.FROM_THE_MARK} and len(marks) == 1


def test_a_run_with_a_model_takes_a_boundary_of_its_own_and_one_without_never_needs_it():
    """A run with a model's roles carry arvaken-stop-test-boundary-model (in a subnet too, -via-model), and it refuses
    before anything is made where that is missing or not the kit's; a run without one takes the boundary it took
    before, in an account that never made the model's."""
    for held in (None, "another"):
        clock = Clock()
        aws = FakeAWS(clock, boundary_model=held)
        with pytest.raises(firing.Refused) as e:
            a_run(aws, clock, model=MODEL)
        said = firing.no_boundary(model=True) if held is None else firing.not_the_boundary(model=True)
        assert str(e.value) == said and aws.stack is None and aws.invocations == 0
    clock = Clock()
    assert result.check(a_run(FakeAWS(clock, boundary=None, boundary_via_model=None), clock, model=MODEL)[1])
    clock = Clock()
    assert result.check(a_run(FakeAWS(clock, boundary_model=None, boundary_via_model=None), clock)[1])
    assert firing.no_boundary(model=True) == (
        "Your account has no policy arvaken-stop-test-boundary-model, the permissions boundary the kit puts on the "
        "roles it makes for a run that calls a model. Create it once from permissions/aws-boundary-model.json, as the "
        "README's \"The permissions it needs\" says.")
    assert firing.not_the_boundary(network=True, model=True) == (
        "Your account's policy arvaken-stop-test-boundary-via-model is not the kit's permissions boundary for a run in "
        "your subnet that calls a model: its default version differs from permissions/aws-boundary-via-model.json.")


def test_the_boundary_check_reads_only_the_boundary_the_run_takes():
    clock = Clock()
    for needs in ({}, {"network": True}, {"model": True}, {"network": True, "model": True}):
        held = {(False, False): "boundary", (True, False): "boundary_via", (False, True): "boundary_model",
                (True, True): "boundary_via_model"}[(needs.get("network", False), needs.get("model", False))]
        others = [k for k in ("boundary", "boundary_via", "boundary_model", "boundary_via_model") if k != held]
        aws = FakeAWS(clock, **{k: "another" for k in others})
        assert firing.why_no_boundary(aws, aws, **needs) is None, needs
        aws = FakeAWS(clock, **{held: "another"})
        assert firing.why_no_boundary(aws, aws, **needs) == firing.not_the_boundary(**needs), needs
        aws = FakeAWS(clock, **{held: None})
        assert firing.why_no_boundary(aws, aws, **needs) == firing.no_boundary(**needs), needs


def test_a_run_refuses_a_model_named_by_anything_but_its_id_before_anything_is_made():
    clock = Clock()
    aws = FakeAWS(clock)
    with pytest.raises(ValueError):
        a_run(aws, clock, model="amazon.*")
    assert aws.stack is None and aws.invocations == 0


# The command line
def test_the_plan_says_the_model_is_called_and_billed_and_without_one_says_nothing_of_it(capsys):
    cli.main(["aws", "plan", "--inline-deny", "--model", MODEL, "--region", "eu-central-1", "--run", "r0123abcd"])
    out = capsys.readouterr().out
    assert cli.PLAN_MODEL.format(model=MODEL) in out
    assert ("- with each invocation, also calls the model eu.amazon.nova-micro-v1:0 once, as the test agent's own "
            "role, asking for one token: AWS bills each call to your account;") in out
    assert out.index("- invokes the test agent about") < out.index(cli.PLAN_MODEL[:30]) < out.index("- then removes")
    cli.main(["aws", "plan", "--inline-deny", "--region", "eu-central-1", "--run", "r0123abcd"])
    plain = capsys.readouterr().out
    assert "model" not in plain and plain == out.replace(cli.PLAN_MODEL.format(model=MODEL) + "\n", "")


def test_the_plan_with_a_model_checks_the_boundary_for_it(capsys, monkeypatch):
    from arvaken_stop_test.aws import boto
    fake = FakeAWS(Clock(), boundary_model=None)
    monkeypatch.setattr(boto, "clients_for", lambda region: type("C", (), {"iam": fake, "sts": fake})())
    args = ["aws", "plan", "--stop", STOP, "--region", "eu-central-1", "--run", "r0123abcd"]
    cli.main([*args, "--model", MODEL])
    assert f"It will not run: {firing.no_boundary(model=True)}\n" in capsys.readouterr().out
    cli.main(args)
    assert "It will not run" not in capsys.readouterr().out


def test_the_command_line_refuses_a_model_that_is_not_an_id_and_any_model_on_google_cloud(capsys):
    for args in (["aws", "plan", "--inline-deny", "--region", "eu-central-1", "--model", "amazon.*"],
                 ["aws", "run", "--inline-deny", "--region", "eu-central-1", "--model", "${AWS::AccountId}"]):
        with pytest.raises(SystemExit):
            cli.main(args)
        assert cli.NOT_A_MODEL in capsys.readouterr().err
    for action in ("plan", "run"):
        with pytest.raises(SystemExit):
            cli.main(["google", action, "--model", MODEL, "--deny-all", "--project", "my-test-project",
                      "--region", "europe-west3"])
        assert cli.GOOGLE_NO_MODEL in capsys.readouterr().err


def test_a_run_given_a_model_passes_it_on_and_one_not_started_says_what_is_left(tmp_path, monkeypatch, capsys):
    from arvaken_stop_test.aws import boto
    clock = Clock()
    aws = FakeAWS(clock, model_error="ValidationException")
    real = running.run
    passed = []
    monkeypatch.setattr(running, "run", lambda c, stop, **kw: passed.append(kw["model"]) or real(
        c, stop, clock=running.Clock(clock.now, clock.sleep), **kw))
    monkeypatch.setattr(boto, "clients_for", lambda region: clients(aws))
    monkeypatch.setattr("builtins.input", lambda prompt="": "r0123abcd")
    monkeypatch.chdir(tmp_path)
    assert cli.main(["aws", "run", "--inline-deny", "--model", MODEL, "--window", "60s", "--region", "eu-central-1",
                     "--run", "r0123abcd"]) == 1
    out = capsys.readouterr().out
    assert passed == [MODEL]
    words = running.MODEL_DID_NOT_WORK.format(model=MODEL, codes=f"ValidationException {running.WARM_UP}",
                                              region="eu-central-1")
    assert words in out and out.rstrip().endswith("Nothing the kit made is left.")
    assert list(tmp_path.iterdir()) == [] and not aws.inline and aws.stack["status"] == "DELETED"
    # without --model, the run is asked for none
    clock2 = Clock()
    aws2 = FakeAWS(clock2)
    monkeypatch.setattr(running, "run", lambda c, stop, **kw: passed.append(kw["model"]) or real(
        c, stop, clock=running.Clock(clock2.now, clock2.sleep), **kw))
    monkeypatch.setattr(boto, "clients_for", lambda region: clients(aws2))
    assert cli.main(["aws", "run", "--inline-deny", "--window", "60s", "--region", "eu-central-1",
                     "--run", "r0123abcd"]) == 0
    assert passed == [MODEL, ""]
    written = json.loads((tmp_path / "stop-test-r0123abcd.json").read_text(encoding="utf-8"))
    assert set(written["repeats"][0]) == set(running.AWS_PATHS)


def test_the_help_names_the_model_option_on_aws_alone(capsys):
    with pytest.raises(SystemExit):
        cli.main(["aws", "run", "--help"])
    out = capsys.readouterr().out
    assert "--model MODEL_ID" in out
    assert "".join(cli.MODEL_HELP.split()) in "".join(out.split())        # as argparse wraps it, at its hyphens too
    with pytest.raises(SystemExit):
        cli.main(["google", "run", "--help"])
    out = capsys.readouterr().out
    assert "--model MODEL_ID" in out and cli.HELP["google_via"] in " ".join(out.split())
