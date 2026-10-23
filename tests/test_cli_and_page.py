"""The command line's plan and verify, and the local page (cli.py, report.py). No AWS: a run's own path is
test_aws_run.py's."""
from __future__ import annotations

import json

from arvaken_stop_test import cli, report, result
from test_aws_run import Clock, FakeAWS, a_run


def test_plan_says_what_a_run_makes_and_refuses_a_stop_it_will_not_fire(capsys):
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
    assert "unchanged since the kit wrote it" in capsys.readouterr().out
    doc["repeats"][0]["own_calls"]["outcome"] = "not stopped"
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(doc), encoding="utf-8")
    assert cli.main(["verify", str(bad)]) == 1


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
    assert "give one of --stop, --revoke-sessions or --own-trigger" in capsys.readouterr().err
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
