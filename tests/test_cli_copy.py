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
KINDS = ["--tool", "runs code", "--tool", "calls other services' APIs", "--model-kind", "a model provider's API"]


def test_the_plan_for_a_copy_says_what_it_makes_and_that_it_never_changes_the_copy(capsys, monkeypatch):
    monkeypatch.setattr(boto, "clients_for", lambda region: pytest.fail("a plan calls no AWS"))
    assert cli.main(["aws", "plan", "--region", "eu-central-1", "--run", RUN, "--copy", COPY, "--stop", STOP]) == 0
    out = capsys.readouterr().out
    assert out.startswith(f"Run {RUN} in eu-central-1, on your test copy {COPY}:")
    assert f"arvaken-stop-test-{RUN}-agent" in out and STOP in out and "never deploys, changes or deletes" in out
    cli.main(["agentcore", "plan", "--region", "eu-central-1", "--run", RUN, "--copy", AGENTCORE_COPY, "--sdk",
              "Acme Guard"])
    out = capsys.readouterr().out
    assert "your SDK Acme Guard's switch yourself, after your mark" in out and "fires nothing" in out


@pytest.mark.parametrize("argv, says", [
    (["aws", "run", "--sdk", "Acme Guard", "--stop", STOP], cli.SDK_NEEDS_COPY),
    (["aws", "run", "--copy", COPY, "--via", "http://gateway.example:8888"], cli.COPY_GOES_WITH),
    (["aws", "run", "--copy", COPY, "--stop", STOP, "--own-trigger"], cli.COPY_GOES_WITH),
    (["aws", "run", "--copy", COPY, "--sdk", "Acme Guard", "--inline-deny"], cli.SDK_IS_THE_STOP),
    (["aws", "run", "--copy", COPY, *KINDS], "give one of --stop, --revoke-sessions, --inline-deny or --sdk"),
    (["aws", "run", "--copy", COPY, "--stop", STOP], cli.COPY_NEEDS_KINDS),
    (["aws", "run", "--copy", COPY, "--stop", STOP, "--tool", "no tools", "--tool", "runs code", "--model-kind",
      "no model"], cli.COPY_NEEDS_KINDS),
    (["agentcore", "run", "--copy", AGENTCORE_COPY, "--deny-calls"], cli.AGENTCORE_COPY_GOES_WITH),
    (["agentcore", "run", "--copy", AGENTCORE_COPY, "--stop", STOP, "--trail"], cli.AGENTCORE_COPY_GOES_WITH),
    (["agentcore", "run", "--copy", AGENTCORE_COPY, *KINDS], "give one of --stop, --inline-deny or --sdk"),
])
def test_what_a_copy_cannot_go_with_is_refused_before_anything(argv, says, capsys, monkeypatch):
    monkeypatch.setattr(boto, "clients_for", lambda region: pytest.fail("refused before any call"))
    with pytest.raises(SystemExit):
        cli.main([*argv, "--region", "eu-central-1"])
    assert says in capsys.readouterr().err.replace("\n", " ").replace("  ", " ")


def test_a_run_on_a_copy_through_the_command_line_writes_a_version_3_result_and_prints_what_it_found(
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
                     "--window", "1m", *KINDS]) == 0
    out = capsys.readouterr().out
    assert cli.COPY_FOUND in out and "- its own calls to the cloud: stopped within 1 minute" in out
    assert "Nothing the kit made is left." in out
    # the founder's "Wrote" sentence, word for word, without the witness's part on a run with no SDK
    assert (f"Wrote stop-test-{RUN}.json and its details. Nothing about your account was sent to Arvaken. Arvaken's "
            "test address received only the test calls the plan named, from the address your copy's calls leave from "
            "(your own if your copy runs in a network of yours). The kit gave those calls only its own name as their "
            "user agent and, on the call with a key, the run's test key; an HTTP client of yours, an SDK that wraps "
            "the probe's, or a proxy may add headers of its own. What Arvaken keeps of those addresses, and for how "
            "long, is in the README.\n") in out
    assert cli.COPY_WROTE.format(out="x", witness=cli.COPY_WROTE_WITNESS).count(
        "(your own if your copy runs in a network of yours), and the kit's witness its checks, from the address this "
        "machine's calls leave from. The kit gave") == 1
    assert sorted(f.name for f in tmp_path.iterdir()) == [f"stop-test-{RUN}-details.json", f"stop-test-{RUN}.json"]
    import json
    from arvaken_stop_test import result
    doc = result.check(json.loads((tmp_path / f"stop-test-{RUN}.json").read_text(encoding="utf-8")))
    assert doc["format"] == result.FORMAT_V3 and doc["agent"]["ref"] == COPY and doc["agent"]["whose"] == "yours"
    assert doc["agent"]["tools"] == ["runs code", "calls other services' APIs"]
    assert doc["agent"]["model_kind"] == "a model provider's API" and doc["stop"]["record"] is None
    assert f"Your result's reference: {result.reference(doc)}" in out
    # the run's own words asked, in order: the copy confirmed, pointed at the run's role, the warning, and back
    assert [a.split()[:3] for a in asked] == [["The", "kit", "will"], ["Point", "your", "copy"],
                                              your_copy.WARNING.split()[:3], ["Point", "your", "copy"]]



def test_tool_none_is_the_kits_no_tools(an_account, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(boto, "clients_for", lambda region: pytest.fail("refused before any call"))
    with pytest.raises(SystemExit):
        cli.main(["aws", "run", "--region", "eu-central-1", "--copy", COPY, "--stop", STOP, "--tool", "none",
                  "--tool", "runs code", "--model-kind", "no model"])
    assert cli.COPY_NEEDS_KINDS in " ".join(capsys.readouterr().err.split())
    assert cli.main(["aws", "plan", "--region", "eu-central-1", "--run", RUN, "--copy", COPY, "--stop", STOP,
                     "--tool", "none", "--model-kind", "no model"]) == 0
