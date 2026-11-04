"""The command line for a run on a test copy of your own agent on Google Cloud (D575; cli.py's google --copy and
--sdk): its plan, the flags it refuses, and a whole run through it against test_google_copy's fake, with the real probe
in the copy."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from arvaken_stop_test import cli, result
from arvaken_stop_test.google import api
from arvaken_stop_test.google import run as running
from arvaken_stop_test.google import your_copy
from arvaken_stop_test_probe import core, heartbeat
from arvaken_stop_test_probe import google as probe_google
from test_google_copy import COPY, OWN, SKEW, CopyGoogle, fresh_probe  # noqa: F401 - a fixture
from test_google_run import DECLARED, PROJECT, REGION, RUN_NAME, Clock, N

WHERE = ["--project", PROJECT, "--region", REGION]
KINDS = ["--tool", "runs code", "--model-kind", "a model service of its cloud"]


def no_google(*a, **kw):
    pytest.fail("a plan, or a refusal before anything, calls no Google")


def test_the_plan_for_a_copy_says_what_it_makes_and_that_it_never_changes_the_copy(capsys, monkeypatch):
    monkeypatch.setattr(api, "Google", no_google)
    assert cli.main(["google", "plan", *WHERE, "--run", RUN_NAME, "--copy", COPY, "--deny-all"]) == 0
    out = capsys.readouterr().out
    assert out.startswith(f"Run {RUN_NAME} in {PROJECT}, {REGION}, on your test copy {COPY}:\n")
    assert f"the service account your copy runs as for the test, {N['agent_account']}" in out
    assert "it never deploys, changes or deletes your copy" in out and "Google bills each call" in out
    assert (f"- makes a deny policy, {N['deny_policy']}, naming that account alone and denying what the probe's calls "
            "use (Cloud Storage and IAM), 1 time, and times each path for ") in out
    assert cli.main(["google", "plan", *WHERE, "--run", RUN_NAME, "--copy", COPY, "--disable-account",
                     "--repeats", "3"]) == 0
    assert "- disables that account, 3 times, enabling it again between repeats" in capsys.readouterr().out
    assert cli.main(["google", "plan", *WHERE, "--run", RUN_NAME, "--copy", COPY, "--stop", DECLARED]) == 0
    assert f"what your deny policy {DECLARED} denies (yours is read, never changed)" in capsys.readouterr().out
    assert cli.main(["google", "plan", *WHERE, "--run", RUN_NAME, "--copy", COPY, "--sdk", "Acme Guard",
                     "--window", "15m"]) == 0
    out = capsys.readouterr().out
    assert "your SDK Acme Guard's switch yourself, after your mark" in out and "fires nothing" in out


@pytest.mark.parametrize("argv, says", [
    (["--sdk", "Acme Guard", "--deny-all"], cli.SDK_NEEDS_COPY),
    (["--copy", COPY, "--deny-all", "--own-trigger"], cli.GOOGLE_COPY_GOES_WITH),
    (["--copy", COPY, "--own-trigger", *KINDS], cli.GOOGLE_COPY_GOES_WITH),
    (["--copy", COPY, "--sdk", "Acme Guard", "--disable-account", *KINDS], cli.GOOGLE_SDK_IS_THE_STOP),
    (["--copy", COPY, *KINDS], cli.GOOGLE_COPY_GIVE_ONE),
    (["--copy", COPY, "--deny-all", "--disable-account", *KINDS], cli.GOOGLE_COPY_GIVE_ONE),
    (["--copy", COPY, "--deny-all"], cli.COPY_NEEDS_KINDS),
    (["--copy", COPY, "--deny-all", "--model", "gemini-2.5-flash", *KINDS], cli.GOOGLE_NO_MODEL),
    (["--copy", COPY, "--deny-all", "--via", "http://gateway.example:8888", *KINDS], cli.GOOGLE_NO_VIA.split(":")[0]),
])
def test_what_a_copy_cannot_go_with_is_refused_before_anything(argv, says, capsys, monkeypatch):
    monkeypatch.setattr(api, "Google", no_google)
    with pytest.raises(SystemExit):
        cli.main(["google", "run", *WHERE, *argv])
    assert says in " ".join(capsys.readouterr().err.split())


def test_a_run_on_a_copy_through_the_command_line_writes_a_version_3_result_and_prints_what_it_found(
        tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    clock = Clock()
    g = CopyGoogle(clock)
    monkeypatch.setattr(api, "Google", lambda project, region: g)
    stamp = SimpleNamespace(time=lambda: clock.now() + SKEW)
    for module in (core, probe_google, heartbeat):
        monkeypatch.setattr(module, "time", stamp)
    real = your_copy.run
    monkeypatch.setattr(your_copy, "run", lambda g, copy, stop, **kw: real(
        g, copy, stop, clock=running.Clock(clock.now, clock.sleep), **kw))
    asked = []

    def typed(prompt: str = "") -> str:
        asked.append(prompt)
        if prompt.startswith("Point your copy at"):
            g.point(N["agent_account"])
        elif prompt.startswith("Point your copy back"):
            g.point(OWN)
        return RUN_NAME

    monkeypatch.setattr("builtins.input", typed)
    assert cli.main(["google", "run", *WHERE, "--run", RUN_NAME, "--copy", COPY, "--deny-all", "--window", "1m",
                     *KINDS]) == 0
    out = capsys.readouterr().out
    assert cli.COPY_FOUND in out and "- its own calls to the cloud: stopped within" in out
    assert "Nothing the kit made is left." in out
    assert (f"Wrote stop-test-{RUN_NAME}.json and its details. Nothing about your project was sent to Arvaken. "
            "Arvaken's test address received only the test calls the plan named,") in out
    assert sorted(f.name for f in tmp_path.iterdir()) == [f"stop-test-{RUN_NAME}-details.json",
                                                          f"stop-test-{RUN_NAME}.json"]
    doc = result.check(json.loads((tmp_path / f"stop-test-{RUN_NAME}.json").read_text(encoding="utf-8")))
    assert doc["format"] == result.FORMAT_V3 and doc["agent"]["ref"] == COPY and doc["agent"]["whose"] == "yours"
    assert doc["agent"]["tools"] == ["runs code"] and doc["agent"]["model_kind"] == "a model service of its cloud"
    assert f"Your result's reference: {result.reference(doc)}" in out
    assert [a.split()[:3] for a in asked] == [["The", "kit", "will"], ["Point", "your", "copy"],
                                              your_copy.WARNING.split()[:3], ["Point", "your", "copy"]]


def test_a_copy_refused_before_anything_is_said_in_its_own_words_and_nothing_is_written(tmp_path, monkeypatch,
                                                                                        capsys):
    monkeypatch.chdir(tmp_path)
    g = CopyGoogle(Clock(), ingress="INGRESS_TRAFFIC_INTERNAL_ONLY")
    monkeypatch.setattr(api, "Google", lambda project, region: g)
    monkeypatch.setattr("builtins.input", lambda prompt="": pytest.fail("refused before anything is asked"))
    assert cli.main(["google", "run", *WHERE, "--run", RUN_NAME, "--copy", COPY, "--deny-all", *KINDS]) == 1
    assert your_copy.NOT_FROM_OUTSIDE in capsys.readouterr().out and not list(tmp_path.iterdir())


def interrupted(g: CopyGoogle, *, pointed: bool, disabled: bool = False) -> None:
    """What a run on the copy left when it could not clean up: its accounts and bucket, the copy pointed at the run's
    account or back at its own, and the run's account disabled if the run had fired that."""
    from arvaken_stop_test.google import stack
    stack.identities(g, RUN_NAME, g.clock.sleep, copy=True)
    g.point(N["agent_account"] if pointed else OWN)
    if disabled:
        g.call("POST", f"{stack.IAM}/projects/-/serviceAccounts/{N['agent_account']}:disable", {})


def a_clean(g: CopyGoogle, monkeypatch, *more: str) -> int:
    monkeypatch.setattr(api, "Google", lambda project, region: g)
    real = running.Clock
    monkeypatch.setattr(running, "Clock", lambda: real(g.clock.now, g.clock.sleep))
    return cli.main(["google", "clean", "--run", RUN_NAME, *WHERE, *more])


def test_clean_keeps_the_runs_account_while_your_copy_still_runs_as_it_and_names_it(monkeypatch, capsys):
    g = CopyGoogle(Clock())
    interrupted(g, pointed=True, disabled=True)
    assert a_clean(g, monkeypatch, "--copy", COPY) == 0
    out = capsys.readouterr().out
    assert out == "Left for you to delete:\n" + your_copy.STILL_RUNS_AS.format(account=N["agent_account"], copy=COPY) + "\n"
    # kept, and enabled again, so the copy still running as it works; the rest removed
    assert set(g.accounts) == {N["agent_account"]} and N["agent_account"] not in g.disabled and g.bucket is None


def test_clean_deletes_the_runs_account_once_your_copy_is_pointed_back(monkeypatch, capsys):
    g = CopyGoogle(Clock())
    interrupted(g, pointed=False)
    assert a_clean(g, monkeypatch, "--copy", COPY) == 0
    assert capsys.readouterr().out == "Nothing the kit made is left.\n" and not g.accounts and g.bucket is None


def test_clean_of_a_run_on_a_copy_without_its_name_removes_nothing(monkeypatch, capsys):
    g = CopyGoogle(Clock())
    interrupted(g, pointed=True)
    before = len(g.calls)
    assert a_clean(g, monkeypatch) == 1
    assert capsys.readouterr().out == your_copy.CLEAN_NEEDS_COPY + "\n"
    assert not [m for m, _ in g.calls[before:] if m != "GET"] and len(g.accounts) == 2 and g.bucket is not None


def test_clean_of_the_kits_own_test_agents_run_is_as_before_even_with_a_copy_named(monkeypatch, capsys):
    from arvaken_stop_test.google import stack
    from test_google_run import FakeGoogle
    g = FakeGoogle(Clock())
    stack.identities(g, RUN_NAME, g.clock.sleep)                   # the kit's own: its account names its test agent
    assert not your_copy.made_for_a_copy(g, RUN_NAME)
    assert a_clean(g, monkeypatch, "--copy", COPY) == 0
    assert ("DELETE", f"{stack.RUN}/{stack.service_name(g, RUN_NAME)}") in [(m, u) for m, u in g.calls]
    assert capsys.readouterr().out == "Nothing the kit made is left.\n" and not g.accounts
