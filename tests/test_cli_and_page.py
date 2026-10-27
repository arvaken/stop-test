"""The command line's plan and verify, and the local page (cli.py, report.py). No AWS: a run's own path is
test_aws_run.py's."""
from __future__ import annotations

import json

from arvaken_stop_test import cli, report, result
from test_aws_run import Clock, FakeAWS, a_run


def test_plan_says_what_a_run_makes_and_refuses_a_stop_it_will_not_fire(capsys, monkeypatch):
    from arvaken_stop_test.aws import boto
    fake = FakeAWS(Clock())
    monkeypatch.setattr(boto, "clients_for", lambda region: type("C", (), {"iam": fake, "sts": fake})())
    assert cli.main(["aws", "plan", "--stop", "arn:aws:iam::111122223333:policy/agent-stop", "--region",
                     "eu-central-1", "--run", "r0123abcd"]) == 0
    out = capsys.readouterr().out
    assert "arvaken-stop-test-r0123abcd" in out and "attaches your stop" in out and "test agent's role alone" in out
    assert "It will not run" not in out
    cli.main(["aws", "plan", "--stop", "p-examplescp1", "--region", "eu-central-1", "--run", "r0123abcd"])
    assert "It will not run: this is an organization's service control policy" in capsys.readouterr().out


def test_plan_with_your_own_trigger_warns_that_it_may_stop_more(capsys):
    cli.main(["aws", "plan", "--own-trigger", "--region", "eu-central-1", "--run", "r0123abcd"])
    assert "Your own trigger may stop more than the test agent" in capsys.readouterr().out


def test_the_calls_a_run_makes_are_counted_for_the_plan():
    assert cli.calls_for(900, 1) == 10 + 930
    assert cli.calls_for(60, 2) == 10 + 2 * 90 + 300


def test_verify_says_what_a_signature_shows_and_refuses_a_changed_file(tmp_path, capsys):
    clock = Clock()
    _, doc = a_run(FakeAWS(clock), clock)
    good = tmp_path / "good.json"
    good.write_text(json.dumps(doc), encoding="utf-8")
    assert cli.main(["verify", str(good)]) == 0
    said = capsys.readouterr().out
    assert "unchanged since it was signed" in said and "not that the kit wrote it, who ran it, or that the run was honest" in said
    doc["repeats"][0]["own_calls"]["outcome"] = "not stopped"
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(doc), encoding="utf-8")
    assert cli.main(["verify", str(bad)]) == 1


def test_a_run_writes_its_three_files_with_lf_on_every_platform(tmp_path, monkeypatch, capsys):
    """The result, its page and its details are written with LF, never the platform's CRLF, so their SHA-256 is the
    same wherever the kit ran (D536). CI runs this on Windows as well as Linux, where Python's default would be CRLF."""
    from arvaken_stop_test.aws import boto
    from arvaken_stop_test.aws import run as running
    clock = Clock()
    made = a_run(FakeAWS(clock), clock)
    monkeypatch.setattr(boto, "clients_for", lambda region: None)
    monkeypatch.setattr(running, "run", lambda *a, **kw: made)
    monkeypatch.setattr("builtins.input", lambda prompt: "r0123abcd")
    monkeypatch.chdir(tmp_path)
    assert cli.main(["aws", "run", "--inline-deny", "--region", "eu-central-1", "--run", "r0123abcd"]) == 0
    said = capsys.readouterr().out
    assert ("Wrote stop-test-r0123abcd.json, its page and its details. Nothing about your account was sent to "
            "Arvaken.") in said
    # its reference, as Arvaken's page shows it when the result is sent: the SHA-256 of its signature's bytes
    written = json.loads((tmp_path / "stop-test-r0123abcd.json").read_text(encoding="utf-8"))
    import base64
    import hashlib
    sha = hashlib.sha256(base64.b64decode(written["signature"]["value"])).hexdigest()
    assert f"Your result's reference: {sha}. It's the SHA-256 of the result's signature." in said
    names = ("stop-test-r0123abcd.json", "stop-test-r0123abcd.html", "stop-test-r0123abcd-details.json")
    assert sorted(p.name for p in tmp_path.iterdir()) == sorted(names)
    for name in names:
        written = (tmp_path / name).read_bytes()
        assert b"\n" in written and b"\r" not in written, name
    assert json.loads((tmp_path / names[0]).read_bytes()) == made[1]


def test_clean_takes_off_the_stops_the_kit_writes_itself_after_an_interrupted_run(monkeypatch, capsys):
    """An interrupted --inline-deny or --revoke-sessions run leaves the kit's own policy on the run's roles; `clean`
    takes it off with no --stop, so the stack's roles can be deleted."""
    from arvaken_stop_test.aws import boto
    from arvaken_stop_test.aws import fire
    from arvaken_stop_test.aws import run as running
    from test_aws_run import ENDPOINT, clients
    for kind in (fire.INLINE, fire.REVOKE):
        clock = Clock()
        aws = FakeAWS(clock)
        c = clients(aws)
        r = running.Run(run="r0123abcd", stop_ref=kind, fired_by="the kit", window=60.0)
        running.deploy(c, r, ENDPOINT, running.Clock(clock.now, clock.sleep))
        if kind == fire.INLINE:
            fire.fire(aws, "r0123abcd", kind, now=clock.now)
        else:
            fire.revoke(aws, "r0123abcd", before=clock.now(), now=clock.now)
        assert aws.inline or aws.revoked                              # interrupted here, the stop still on
        monkeypatch.setattr(boto, "clients_for", lambda region: c)
        assert cli.main(["aws", "clean", "--run", "r0123abcd", "--region", "eu-central-1"]) == 0
        assert not aws.inline and not aws.revoked and aws.stack["status"] == "DELETED", kind
        assert "Nothing the kit made is left." in capsys.readouterr().out


def test_the_page_shows_expected_beside_found_and_keeps_error_codes_off_the_result():
    clock = Clock()
    r, doc = a_run(FakeAWS(clock), clock)
    from arvaken_stop_test.aws.run import results
    page = report.page(doc, [d for _, d in results(r)])
    assert "its own calls to the cloud" in page and "stopped within 1 minute" in page
    assert "AccessDenied" in page and "AccessDenied" not in json.dumps(doc)
    assert "Nothing the kit made was left." in page and "<script" not in page
    assert result.check(doc)


def test_cloudtrail_is_asked_where_iams_calls_are_recorded(monkeypatch):
    """IAM's calls are in us-east-1's event history whatever region the run is in (read in install-test, 23 October
    2026); the fake in test_aws_run.py answers from one account and cannot hold this, so it is held here."""
    from arvaken_stop_test.aws.boto import clients_for, trail_region
    assert trail_region("eu-central-1") == trail_region("us-east-1") == trail_region("ap-southeast-2") == "us-east-1"
    assert trail_region("us-gov-west-1") == "us-gov-west-1" and trail_region("cn-north-1") == "cn-north-1"
    monkeypatch.delenv("AWS_PROFILE", raising=False)              # clients are made without credentials
    c = clients_for("eu-central-1")
    assert c.cloudtrail.meta.region_name == "us-east-1"
    assert c.lambda_.meta.region_name == c.cloudformation.meta.region_name == c.region == "eu-central-1"


def test_a_run_names_one_kind_of_stop_and_revoking_says_what_it_reaches(capsys):
    import pytest
    for both in (["--stop", "arn:aws:iam::aws:policy/AWSDenyAll", "--revoke-sessions"], []):
        with pytest.raises(SystemExit):
            cli.main(["aws", "plan", "--region", "eu-central-1", *both])
    assert "give one of --stop, --revoke-sessions, --inline-deny or --own-trigger" in capsys.readouterr().err
    cli.main(["aws", "plan", "--revoke-sessions", "--region", "eu-central-1", "--run", "r0123abcd"])
    out = capsys.readouterr().out
    assert "revokes the active sessions of the test agent's role and of the role it became" in out
    assert "It will not run" not in out


def test_the_page_gives_time_to_effect_as_a_range_the_successes_after_a_refusal_and_a_sessions_expiry():
    clock = Clock()
    r, doc = a_run(FakeAWS(clock), clock)
    from arvaken_stop_test.aws.run import results
    page = report.page(doc, [d for _, d in results(r)])
    found = results(r)[0][1]["own_calls"]
    low, high = found.effect_between
    assert f"took effect {low:.1f} to {high:.1f} seconds after the stop was fired" in page
    assert "0 successful call(s) after its first refusal" in page
    assert "keeps working until" in page and "when its session expires" in page
    assert "CloudTrail&#x27;s record of the call, to the whole second" in page    # the page escapes what it writes
    assert "took effect" not in json.dumps(doc) and "keeps_working" not in json.dumps(doc)


def test_plan_says_when_your_stop_does_not_deny_what_the_test_agent_does(capsys, monkeypatch):
    from arvaken_stop_test.aws import boto
    fake = FakeAWS(Clock(), stop_denies=("ec2:RunInstances",))
    monkeypatch.setattr(boto, "clients_for", lambda region: type("C", (), {"iam": fake, "sts": fake})())
    cli.main(["aws", "plan", "--stop", "arn:aws:iam::111122223333:policy/agent-stop", "--region", "eu-central-1",
              "--run", "r0123abcd"])
    assert ("It will not run: Your stop doesn't deny what the test agent does, so this test can't tell you about your "
            "stop.") in capsys.readouterr().out



def test_revoking_sessions_is_expected_to_reach_the_role_it_became_and_the_page_says_a_later_session_is_unaffected():
    from arvaken_stop_test.aws import fire as firing
    from arvaken_stop_test.aws import run as running
    clock = Clock()
    r, doc = a_run(FakeAWS(clock), clock, stop_ref=firing.REVOKE)
    out = report.page(doc, [d for _, d in running.results(r)])
    assert report.REVOKE_NOTE in out and report.expected(firing.REVOKE, "another_identity") == "stopped"
    clock2 = Clock()
    _, policy_doc = a_run(FakeAWS(clock2), clock2)
    assert report.REVOKE_NOTE not in report.page(policy_doc)


def test_plan_says_when_the_account_has_no_kits_boundary(capsys, monkeypatch):
    from arvaken_stop_test.aws import boto
    fake = FakeAWS(Clock(), boundary=None)
    monkeypatch.setattr(boto, "clients_for", lambda region: type("C", (), {"iam": fake, "sts": fake})())
    cli.main(["aws", "plan", "--stop", "arn:aws:iam::111122223333:policy/agent-stop", "--region", "eu-central-1",
              "--run", "r0123abcd"])
    assert ("It will not run: Your account has no policy arvaken-stop-test-boundary, the permissions boundary the kit "
            "puts on the roles it makes.") in capsys.readouterr().out


def test_each_cloud_times_its_paths_for_its_own_window_by_default(capsys, monkeypatch):
    """The founder, 25 October 2026: "Set the window per cloud before the Azure module runs." Each cloud the command line
    offers has a default window of its own (timing.WINDOWS), and its plan and its help say it: changing one cloud's
    leaves the other's as it was."""
    from arvaken_stop_test import timing
    assert set(timing.WINDOWS) == {"aws", "google_cloud"}
    monkeypatch.setitem(timing.WINDOWS, "aws", 600.0)
    cli.main(["aws", "plan", "--inline-deny", "--region", "eu-central-1", "--run", "r0123abcd"])
    cli.main(["google", "plan", "--deny-all", "--project", "my-test-project", "--region", "europe-west3",
              "--run", "r0123abcd"])
    said = capsys.readouterr().out
    assert "- times each path for 600 seconds after firing, 1 time(s);" in said
    assert "- times each path for 900 seconds after firing, 1 time(s);" in said
    assert cli._window_help("aws") == "time after firing, e.g. 10m (default)"
    assert cli._window_help("google_cloud") == "time after firing, e.g. 15m (default)"


# The gateway option (--via; D561, section 5), on AWS.
VIA = "https://user:secret@gw.example:8443"
PEM = "-----BEGIN CERTIFICATE-----\nMIIBgateway\n-----END CERTIFICATE-----\n"
A_GATEWAY = ["--via", VIA, "--product-attachment", "all-outbound", "--product-name", "Our egress gateway"]


def test_plan_through_a_gateway_says_what_it_sends_where_and_never_prints_a_password(capsys, tmp_path):
    bundle = tmp_path / "gateway-ca.pem"
    bundle.write_text(PEM, encoding="utf-8")
    assert cli.main(["aws", "plan", *A_GATEWAY, "--ca-bundle", str(bundle), "--subnet", "subnet-0abc1234",
                     "--security-group", "sg-0abc1234", "--security-group", "sg-0def5678", "--region", "eu-central-1",
                     "--run", "r0123abcd"]) == 0
    out = capsys.readouterr().out
    assert "secret" not in out and "user:" not in out
    assert cli.PLAN_SUBNET.format(subnet="subnet-0abc1234", groups="sg-0abc1234, sg-0def5678", minutes=30) in out
    assert cli.PLAN_VIA.format(via="https://gw.example:8443") in out
    assert cli.PLAN_CA.format(file="gateway-ca.pem") in out
    assert cli.PLAN_PRODUCT.format(name="Our egress gateway", attachment="all its outbound traffic") in out
    assert "It will not run" not in out and out.index(cli.PLAN_SUBNET[:30]) < out.index("- times each path")


def test_a_run_through_a_gateway_warns_strongly_asks_the_runs_name_then_your_mark(tmp_path, monkeypatch, capsys):
    """The design: "It asks: 'Press Enter, then fire your stop.' ... The kit warns first, in stronger words than K4's,
    that a gateway's switch may stop every agent behind it, and goes on only when the customer types the run's
    name.\""""
    from arvaken_stop_test.aws import boto, fire
    from arvaken_stop_test.aws import run as running
    from test_aws_run import clients
    clock = Clock()
    aws = FakeAWS(clock)
    prompts, typed = [], iter(["r0123abcd", ""])
    monkeypatch.setattr("builtins.input", lambda prompt="": prompts.append(prompt) or next(typed))

    def the_customer(t):                    # once they press Enter at the mark, they turn their gateway's switch on
        if len(prompts) == 2 and aws.switch_at is None:
            aws.switch_at = t + 5
    clock.hooks.append(the_customer)
    real = running.run
    monkeypatch.setattr(running, "run", lambda c, stop, **kw: real(c, stop, clock=running.Clock(clock.now, clock.sleep),
                                                                   **kw))
    monkeypatch.setattr(boto, "clients_for", lambda region: clients(aws))
    monkeypatch.chdir(tmp_path)
    assert cli.main(["aws", "run", "--via", VIA, "--product-attachment", "model", "--product-name", "Model gateway",
                     "--window", "60s", "--region", "eu-central-1", "--run", "r0123abcd"]) == 0
    out = capsys.readouterr().out
    assert prompts == ["Type r0123abcd to go on: ", "Press Enter, then fire your stop."]
    assert fire.GATEWAY_WARNING in out and fire.OWN_TRIGGER_WARNING not in out
    assert "every agent behind it" in fire.GATEWAY_WARNING and fire.GATEWAY_WARNING.endswith(
        "Type the run's name to go on.")
    assert out.index(fire.GATEWAY_WARNING) < out.index(running.MARKED)
    written = json.loads((tmp_path / "stop-test-r0123abcd.json").read_text(encoding="utf-8"))
    assert result.check(written)["run"]["via"] == "https://gw.example:8443"
    assert written["stop"]["product"] == {"kind": "gateway", "attachment": "its calls to a model",
                                          "name": "Model gateway"}
    assert {v["outcome"] for v in written["repeats"][0].values()} == {"stopped"}
    assert "secret" not in out and all(b"secret" not in f.read_bytes() for f in tmp_path.iterdir())
    assert all(p["via"] == VIA for p in aws.payloads)            # the agent signs in to the gateway as given


def test_a_run_through_a_gateway_goes_on_only_when_you_type_the_runs_name(monkeypatch, capsys):
    import pytest
    from arvaken_stop_test.aws import boto, fire
    from arvaken_stop_test.aws import run as running
    monkeypatch.setattr(boto, "clients_for", lambda region: None)
    monkeypatch.setattr(running, "run", lambda *a, **kw: pytest.fail("the kit made something"))
    monkeypatch.setattr("builtins.input", lambda prompt="": "yes")
    assert cli.main(["aws", "run", *A_GATEWAY, "--region", "eu-central-1", "--run", "r0123abcd"]) == 1
    out = capsys.readouterr().out
    assert fire.GATEWAY_WARNING in out and out.rstrip().endswith("Nothing was made.")


def _refused(args: list[str], capsys) -> str:
    import pytest
    with pytest.raises(SystemExit):
        cli.main(["aws", "plan", "--region", "eu-central-1", *args])
    return capsys.readouterr().err


def test_the_gateway_options_are_checked_before_anything_and_never_print_a_password_back(capsys, tmp_path):
    product = ["--product-attachment", "model", "--product-name", "G"]
    for args, said in (
            ([*A_GATEWAY, "--inline-deny"], cli.VIA_IS_THE_STOP),
            ([*A_GATEWAY, "--own-trigger"], cli.VIA_IS_THE_STOP),
            ([*A_GATEWAY, "--stop", "arn:aws:iam::aws:policy/AWSDenyAll"], cli.VIA_IS_THE_STOP),
            (["--via", VIA, "--product-name", "G"], cli.VIA_NEEDS_PRODUCT),
            (["--via", VIA, "--product-attachment", "model"], cli.VIA_NEEDS_PRODUCT),
            (["--via", VIA, "--product-attachment", "model", "--product-name", "x" * 201], cli.VIA_NEEDS_PRODUCT),
            (["--via", "user:secret@gw.example:8443", *product], cli.NOT_AN_ADDRESS),
            (["--via", "ftp://user:secret@gw.example", *product], cli.NOT_AN_ADDRESS),
            (["--via", "https://user:secret@gw.example:99999", *product], cli.NOT_AN_ADDRESS),
            (["--via", "https://user:secret@[gw.example", *product], cli.NOT_AN_ADDRESS),
            ([*A_GATEWAY, "--repeats", "2"], cli.VIA_ONCE),
            ([*A_GATEWAY, "--subnet", "subnet-0abc1234"], cli.SUBNET_AND_GROUPS),
            ([*A_GATEWAY, "--security-group", "sg-0abc1234"], cli.SUBNET_AND_GROUPS),
            ([*A_GATEWAY, "--subnet", "my-subnet", "--security-group", "sg-0abc1234"], cli.SUBNET_AND_GROUPS),
            ([*A_GATEWAY, "--subnet", "subnet-0abc1234", "--security-group", "default"], cli.SUBNET_AND_GROUPS),
            (["--inline-deny", "--product-name", "G"], cli.GOES_WITH_VIA),
            (["--inline-deny", "--subnet", "subnet-0abc1234", "--security-group", "sg-0abc1234"], cli.GOES_WITH_VIA),
            (["--inline-deny", "--ca-bundle", str(tmp_path / "any.pem")], cli.GOES_WITH_VIA)):
        err = _refused(args, capsys)
        assert said in err and "secret" not in err, (args, err)


def test_a_bundle_that_is_not_one_of_certificates_is_refused(capsys, tmp_path):
    bundle = tmp_path / "bundle.pem"
    for content in ("not a certificate", PEM + "A" * cli.CA_LIMIT):
        bundle.write_text(content, encoding="utf-8")
        assert cli.NOT_A_BUNDLE in _refused([*A_GATEWAY, "--ca-bundle", str(bundle)], capsys)
    assert cli.NOT_A_BUNDLE in _refused([*A_GATEWAY, "--ca-bundle", str(tmp_path / "missing.pem")], capsys)


def test_on_google_cloud_via_is_refused_and_says_why(capsys):
    import pytest
    with pytest.raises(SystemExit):
        cli.main(["google", "plan", "--via", VIA, "--deny-all", "--project", "my-test-project",
                  "--region", "europe-west3"])
    err = capsys.readouterr().err
    assert cli.GOOGLE_NO_VIA in err and "secret" not in err


def test_clean_with_your_subnet_waits_for_the_functions_network_interfaces(monkeypatch, capsys):
    """An interrupted run in a subnet of yours: `clean --subnet` waits for the function's interfaces as a run does."""
    from arvaken_stop_test.aws import boto
    from arvaken_stop_test.aws import run as running
    from test_aws_run import ENDPOINT, clients
    clock = Clock()
    aws = FakeAWS(clock)
    c = clients(aws)
    r = running.Run(run="r0123abcd", stop_ref="", fired_by="your own trigger", window=60.0, subnet="subnet-0abc1234",
                    security_groups=["sg-0abc1234"])
    running.deploy(c, r, ENDPOINT, running.Clock(clock.now, clock.sleep), before={})
    assert "eni-0aaa1111" in aws.enis                            # interrupted here
    real = running.Clock
    monkeypatch.setattr(running, "Clock", lambda: real(clock.now, clock.sleep))
    monkeypatch.setattr(boto, "clients_for", lambda region: c)
    assert cli.main(["aws", "clean", "--run", "r0123abcd", "--region", "eu-central-1", "--subnet",
                     "subnet-0abc1234"]) == 0
    out = capsys.readouterr().out
    assert running.WAITING_FOR_INTERFACES.format(minutes=30, count=1, subnet="subnet-0abc1234") in out
    assert out.rstrip().endswith("Nothing the kit made is left.") and "eni-0aaa1111" not in aws.enis
