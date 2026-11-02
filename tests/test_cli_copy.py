"""The command line for a run on a test copy of your own agent (D575; cli.py's --copy and --sdk): its plan, the flags it
refuses, and a whole run through it against test_aws_copy's fake, with the real probe in the copy. It writes no result
file, as stop-test-result/3 waits for the kit's terms v5."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from arvaken_stop_test import cli
from arvaken_stop_test.aws import boto
from arvaken_stop_test.aws import run as running
from arvaken_stop_test.aws import your_copy
from arvaken_stop_test_probe import aws as probe_aws
from arvaken_stop_test_probe import core, heartbeat
from test_aws_copy import COPY, OWN_ROLE, RUN, RUNS_ROLE, SKEW, CopyAWS, an_account  # noqa: F401 - a fixture
from test_aws_run import STOP, Clock, clients

AGENTCORE_COPY = "arn:aws:bedrock-agentcore:eu-central-1:123456789012:runtime/my_agent_copy-Zx9Yw8Vu7T"


def test_the_plan_for_a_copy_says_what_it_makes_and_that_it_never_changes_the_copy(capsys, monkeypatch):
    monkeypatch.setattr(boto, "clients_for", lambda region: pytest.fail("a plan calls no AWS"))
    assert cli.main(["aws", "plan", "--region", "eu-central-1", "--run", RUN, "--copy", COPY, "--stop", STOP]) == 0
    out = capsys.readouterr().out
    assert out.startswith(f"Run {RUN} in eu-central-1, on your test copy {COPY}:")
    assert f"arvaken-stop-test-{RUN}-agent" in out and STOP in out and "never deploys, changes or deletes" in out
    cli.main(["agentcore", "plan", "--region", "eu-central-1", "--run", RUN, "--copy", AGENTCORE_COPY, "--sdk",
              "Acme Guard"])
    out = capsys.readouterr().out
    assert "your SDK Acme Guard's switch yourself, from your mark" in out and "fires nothing" in out


@pytest.mark.parametrize("argv, says", [
    (["aws", "run", "--sdk", "Acme Guard", "--stop", STOP], cli.SDK_NEEDS_COPY),
    (["aws", "run", "--copy", COPY, "--via", "http://gateway.example:8888"], cli.COPY_GOES_WITH),
    (["aws", "run", "--copy", COPY, "--stop", STOP, "--own-trigger"], cli.COPY_GOES_WITH),
    (["aws", "run", "--copy", COPY, "--sdk", "Acme Guard", "--inline-deny"], cli.SDK_IS_THE_STOP),
    (["aws", "run", "--copy", COPY], "give one of --stop, --revoke-sessions, --inline-deny or --sdk"),
    (["agentcore", "run", "--copy", AGENTCORE_COPY, "--deny-calls"], cli.AGENTCORE_COPY_GOES_WITH),
    (["agentcore", "run", "--copy", AGENTCORE_COPY, "--stop", STOP, "--trail"], cli.AGENTCORE_COPY_GOES_WITH),
    (["agentcore", "run", "--copy", AGENTCORE_COPY], "give one of --stop, --inline-deny or --sdk"),
])
def test_what_a_copy_cannot_go_with_is_refused_before_anything(argv, says, capsys, monkeypatch):
    monkeypatch.setattr(boto, "clients_for", lambda region: pytest.fail("refused before any call"))
    with pytest.raises(SystemExit):
        cli.main([*argv, "--region", "eu-central-1"])
    assert says in capsys.readouterr().err.replace("\n", " ").replace("  ", " ")


def test_a_run_on_a_copy_through_the_command_line_prints_what_it_found_and_writes_no_result(
        an_account, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    clock = Clock()
    aws = CopyAWS(clock)
    c = clients(aws)
    c.region = "eu-central-1"
    monkeypatch.setattr(boto, "clients_for", lambda region: c)
    monkeypatch.setattr(probe_aws, "_MADE", {})
    stamp = SimpleNamespace(time=lambda: clock.now() + SKEW)
    for module in (core, probe_aws, heartbeat):
        monkeypatch.setattr(module, "time", stamp)
    real = your_copy.run
    monkeypatch.setattr(your_copy, "run", lambda c, copy, stop, **kw: real(
        c, copy, stop, clock=running.Clock(clock.now, clock.sleep), **kw))
    asked = []

    def typed(prompt: str = "") -> str:
        asked.append(prompt)
        if prompt.startswith("Point your copy at"):
            aws.copy_role = RUNS_ROLE
        elif prompt.startswith("Point your copy back"):
            aws.copy_role = OWN_ROLE
        return RUN

    monkeypatch.setattr("builtins.input", typed)
    assert cli.main(["aws", "run", "--region", "eu-central-1", "--run", RUN, "--copy", COPY, "--stop", STOP,
                     "--window", "1m"]) == 0
    out = capsys.readouterr().out
    assert cli.COPY_FOUND in out and "- its own calls to the cloud: stopped within 1 minute" in out
    assert "Nothing the kit made is left." in out and list(tmp_path.iterdir()) == []
    # the run's own words asked, in order: the copy confirmed, pointed at the run's role, the warning, and back
    assert [a.split()[:3] for a in asked] == [["The", "kit", "will"], ["Point", "your", "copy"],
                                              your_copy.WARNING.split()[:3], ["Point", "your", "copy"]]
