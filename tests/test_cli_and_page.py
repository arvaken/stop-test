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
