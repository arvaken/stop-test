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
            "Arvaken, except the address the test agent's two calls came from.") in said
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
