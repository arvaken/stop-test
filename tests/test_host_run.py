"""A run on a test copy of your agent on a host you control (D709; host/run.py and `stop-test host`), against a fake
observer that sees your host second by second, by a fake clock. Held here: you confirm the copy and fire the stop
yourself, after D575's warning; the kit makes its folder and the run's settings, waits for your host, times each window
from your mark, then takes your stop product's record, and your host's state where the witness fell silent, keeping
their entries and SHA-256 and never the file (KH6); a process kill with the witness up, and a containment with the
product's record of the host's state, read "stopped, as seen from outside the host"; a host or network that went down,
a silent witness with no record of the host's state, and a missing product record never do; and every way a run ends
removes its folder and closes the observer."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from arvaken_stop_test import cli, result, timing
from arvaken_stop_test.aws.run import MARK_PROMPT
from arvaken_stop_test.aws.your_copy import NAME_HOLDS_EMAIL, SDK_ENTRY_NAME, SDK_ENTRY_TIME, WARNING
from arvaken_stop_test.host import rule
from arvaken_stop_test.host import run as hosting
from arvaken_stop_test.host.observer import check_arrivals
from arvaken_stop_test.host.run import HostRun, NotStarted
from arvaken_stop_test_probe import host as probe_host

RUN = "r0123abcd"
T0 = 1_900_000_000.0
W = 900.0
CERT = "-----BEGIN CERTIFICATE-----\nQUFBQQ==\n-----END CERTIFICATE-----\n"
URL = "https://203.0.113.5:8443"
KINDS = ["--tool", "runs code", "--model-kind", "a model provider's API"]
HOST_ARGS = ["--copy", "my-agent-test", "--host", "test-host-1", "--observer", "203.0.113.5:8443", "--stop-kind",
             "ends-process", "--product-name", "Acme Process Guard", "--os", "linux", "--container", "no"]


def second(t: float) -> str:
    return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Clock:
    def __init__(self):
        self.t = T0

    def now(self) -> float:
        return self.t

    def sleep(self, seconds: float) -> None:
        self.t += max(0.0, seconds)


class Host:
    """Your host, as the observer sees it, a second at a time. Your stop takes hold `after` seconds after each mark and
    holds until 10 seconds after its window, when you undo it. What it silences:
    - "kill": your copy's process (its calls, its reports, its model's calls); the witness keeps beating;
    - "contain": your whole host, the witness with it;
    - "down": everything, for good: your host or its network went down;
    - "model key": only the model's calls fail (a key revoked at the provider); the probe keeps reporting;
    - "nothing": nothing ever reaches the observer."""

    def __init__(self, clock: Clock, how: str = "kill", after: float = 5.0, window: float = W):
        self.clock, self.how, self.after, self.window = clock, how, after, window
        self.marks: list[float] = []

    def stopped(self, t: float) -> bool:
        if self.how == "down":
            return bool(self.marks) and t >= self.marks[0] + self.after
        return any(m + self.after <= t < m + self.window + 10 for m in self.marks)

    def arrives(self, kind: str, t: float) -> bool:
        if self.how == "nothing":
            return False
        if kind == "witness":
            return self.how in ("kill", "model key") or not self.stopped(t)
        if self.how == "model key":
            return kind != "model" or not self.stopped(t)
        return not self.stopped(t)


class FakeObserver:
    """The kit's observer, as the run uses it: made, started, read, closed, signed."""

    def __init__(self, host: Host):
        self.host, self.made, self.closed_at = host, [], None

    def __call__(self, run, key, witness_key, h, port, folder, hours):
        self.made.append((run, key, witness_key, h, port, folder, hours))
        self.run, self.key, self.folder = run, key, folder
        return self

    def start(self):
        self.t0, self.seen, self.upto = self.host.clock.now(), {}, {}
        self.certificate, self.refused_keys = CERT, 0
        (self.folder / "observer-key.pem").write_text("the observer's key for the run", encoding="utf-8")

    def url(self) -> str:
        return URL

    def _times(self, kind: str) -> list[float]:
        end = int(self.closed_at if self.closed_at is not None else self.host.clock.now())
        seen, upto = self.seen.setdefault(kind, []), self.upto.get(kind, int(self.t0) - 1)
        for t in range(upto + 1, end + 1):
            if self.host.arrives(kind, float(t)):
                seen.append(float(t))
        self.upto[kind] = max(upto, end)
        return list(seen)

    def arrivals(self, path: str) -> list[float]:
        return self._times(path)

    def witness(self) -> list[float]:
        return self._times("witness")

    def reports(self) -> list[float]:
        return self._times("report")

    def close(self, wait) -> None:
        self.closed_at = self.host.clock.now()
        wait(5.0)

    def signed(self):
        doc = {"format": "stop-test-arrivals/1", "run": self.run, "clock": "the observer's",
               "paths": {p: [result.iso(t) for t in self._times(p)] for p in ("outside_key", "open_internet")},
               "reports": [], "witness": [result.iso(t) for t in self._times("witness")], "refused_keys": 0}
        signed = result.sign(doc, result.new_key())
        return signed, signed["signature"]["public_key"]

    def source(self) -> str:
        return "198.51.100.7"

    def http_client(self) -> str:
        return result.CLIENTS[1]

    def calls(self) -> int:
        return sum(len(self._times(k)) for k in ("outside_key", "open_internet", "report", "witness"))

    def failures(self, path: str) -> list[dict]:
        return []


class You:
    """You at the kit's prompts, and the files you name: your answers, by what the kit asks."""

    def __init__(self, host: Host, *, confirm=True, confirm_model=True, fire=True, record=True, record_at=5.0,
                 state=False, still_at=W + 60, name="ProcessKilled", at_mark=None):
        self.host, self.confirm, self.fire, self.record, self.record_at = host, confirm, fire, record, record_at
        self.confirm_model = confirm_model
        self.state, self.still_at, self.name, self.at_mark = state, still_at, name, at_mark
        self.asked: list[str] = []
        self.giving = ""

    def __call__(self, words: str) -> str:
        self.asked.append(words)
        mark = self.host.marks[-1] if self.host.marks else None
        if words.startswith("The kit will time"):
            return f" {RUN} " if self.confirm else "yes"
        if words.startswith("With --model"):
            return RUN if self.confirm_model else "yes"
        if words == WARNING:
            return RUN if self.fire else ""
        if words == MARK_PROMPT:
            if self.at_mark:
                raise self.at_mark
            self.host.marks.append(self.host.clock.now())
            return ""
        if words == hosting.EXPORT:
            self.giving = "record"
            return "export.json" if self.record else ""
        if words == SDK_ENTRY_TIME:
            return second(mark + self.record_at)
        if words.startswith("The kit's witness fell silent at"):
            return "state.json" if self.state else ""
        if words == hosting.STATE_CONTAINED:
            self.giving = "contained"
            return second(mark + self.host.after)
        if words.startswith("The time of the entry in it that shows your host still contained"):
            self.giving = "still"
            return second(mark + self.still_at)
        if words in (SDK_ENTRY_NAME, NAME_HOLDS_EMAIL):
            return {"record": self.name, "contained": "HostIsolated", "still": "HostStillIsolated"}[self.giving]
        raise AssertionError(f"not a question the run asks: {words}")

    def read(self, path: str) -> bytes:
        mark = self.host.marks[-1]
        if path == "export.json":
            return json.dumps([{"time": second(mark + self.record_at), "type": "ProcessKilled",
                                "by": "ops-admin@example.com", "note": "a line the kit never keeps"}]).encode()
        if path == "state.json":
            return json.dumps([{"at": second(mark + self.host.after), "event": "HostIsolated"},
                               {"at": second(mark + self.still_at), "event": "HostStillIsolated"},
                               {"note": "another line the kit never keeps"}]).encode()
        raise FileNotFoundError(path)


def a_run(**kw) -> HostRun:
    return HostRun(**{"run": RUN, "copy": "my-agent-test", "host": "test-host-1", "observer": "203.0.113.5:8443",
                      "stop_said": result.HOST_STOPS[0], "product": "Acme Process Guard", "os": result.HOST_OS[0],
                      "container": False, "window": W, "repeats_wanted": 1, **kw})


def run(tmp_path, how="kill", r=None, **you_kw):
    """A whole run against a host that behaves as `how` says: the run, what it said, you, the observer."""
    clock = Clock()
    h = Host(clock, how, window=(r.window if r else W))
    you, observer, said = You(h, **you_kw), FakeObserver(h), []
    r = r or a_run()
    try:
        hosting.run(r, ask=you, say=said.append, clock=clock, observe=observer, read=you.read, where=tmp_path)
    except NotStarted:
        pass
    return r, said, you, observer


def outcomes(r: HostRun, i: int = 0) -> dict[str, str]:
    return {p: f.outcome for p, f in r.repeats[i].found.items()}


def reasons(r: HostRun, i: int = 0) -> set:
    return {f.reason for f in r.repeats[i].found.values()}


# -- what reads stopped, as seen from outside the host -----------------------------------------------------------------
def test_a_process_kill_with_the_witness_up_reads_stopped_as_seen_from_outside_the_host(tmp_path):
    r, said, you, observer = run(tmp_path)
    assert outcomes(r) == {"outside_key": rule.HOST_STOPPED, "open_internet": rule.HOST_STOPPED}
    rep = r.repeats[0]
    assert rep.up.by == rule.BY_WITNESS and rep.state is None
    assert rep.found["outside_key"].effect_between == (4.0, 5.0)
    assert rep.record.name == "ProcessKilled" and rep.record.in_file
    assert not any(w.startswith("The kit's witness fell silent") for w in you.asked)   # not asked: it stayed up
    assert said[0].startswith(f"The run's settings are in {tmp_path / ('arvaken-stop-test-' + RUN)}")
    assert hosting.READY.format(paths="calls out with a key, the open internet") in said
    assert hosting.MARKED in said and hosting.TIMING_DONE in said
    assert [w for w in you.asked if w in (WARNING, MARK_PROMPT)] == [WARNING, MARK_PROMPT]
    doc, details, written = hosting.the_result(r, ["runs code"], "a model provider's API")
    assert result.check(doc) == doc and check_arrivals(json.loads(written))
    assert doc["host"]["observer"]["arrivals_sha256"] == hashlib.sha256(written).hexdigest()
    assert doc["run"]["window_seconds"] == 900 and doc["host"]["address"] == "198.51.100.7"


def test_a_containment_that_silenced_the_witness_reads_stopped_with_the_products_record_of_the_hosts_state(tmp_path):
    r, said, you, _ = run(tmp_path, "contain", state=True)
    assert outcomes(r) == {"outside_key": rule.HOST_STOPPED, "open_internet": rule.HOST_STOPPED}
    rep = r.repeats[0]
    assert rep.up.by == rule.BY_STATE and rep.up.witness_silent_from == rep.mark_at + 4
    assert (rep.state.contained.name, rep.state.still.name) == ("HostIsolated", "HostStillIsolated")
    assert any(w.startswith("The kit's witness fell silent at") for w in you.asked)
    doc, _, _ = hosting.the_result(r, ["runs code"], "a model provider's API")
    result.check(doc)
    assert doc["host"]["evidence"][0]["host_up"]["state"]["from_name"] == "HostIsolated"


# -- what must never read stopped --------------------------------------------------------------------------------------
@pytest.mark.parametrize("how", ["down", "contain"])
def test_a_host_or_network_that_went_down_or_a_silent_witness_with_no_record_of_the_host_never_reads_stopped(
        tmp_path, how):
    r, _, _, _ = run(tmp_path, how, state=False)
    rep = r.repeats[0]
    assert set(outcomes(r).values()) == {timing.NOT_MEASURED}
    assert reasons(r) == {rule.HOST_MAY_BE_DOWN.format(time=rule._clock(rep.mark_at + 4))}
    doc, _, _ = hosting.the_result(r, ["runs code"], "a model provider's API")
    result.check(doc)
    assert doc["host"]["evidence"][0]["host_up"]["by"] is None


def test_a_record_of_the_hosts_state_that_ends_before_the_window_does_leaves_it_not_measured(tmp_path):
    r, _, _, _ = run(tmp_path, "contain", state=True, still_at=300.0)
    assert set(outcomes(r).values()) == {timing.NOT_MEASURED}
    assert reasons(r) == {rule.STATE_SHORT.format(time=rule._clock(r.repeats[0].mark_at + 4))}


def test_with_no_record_from_your_stop_product_no_path_reads_stopped(tmp_path):
    r, _, _, _ = run(tmp_path, record=False)
    assert set(outcomes(r).values()) == {timing.NOT_MEASURED} and reasons(r) == {rule.NO_RECORD}
    doc, _, _ = hosting.the_result(r, ["runs code"], "a model provider's API")
    assert doc["host"]["evidence"][0]["product"] is None


def test_a_record_before_your_mark_is_flagged_and_reads_not_measured(tmp_path):
    r, said, _, _ = run(tmp_path, record_at=-10.0)
    assert hosting.RECORD_BEFORE_MARK in said
    assert reasons(r) == {rule.RECORD_OUTSIDE}
    doc, _, _ = hosting.the_result(r, ["runs code"], "a model provider's API")
    assert doc["host"]["evidence"][0]["product"]["before_mark"] is True


def test_a_path_that_fell_silent_before_the_products_record_reads_not_measured(tmp_path):
    r, _, _, _ = run(tmp_path, record_at=60.0)
    assert reasons(r) == {rule.SILENT_BEFORE_RECORD}


def test_a_name_holding_an_email_address_is_asked_again(tmp_path):
    r, _, you, _ = run(tmp_path, name="kill by ops-admin@example.com")
    assert NAME_HOLDS_EMAIL in you.asked and r.repeats[0].record is None      # still an email: no record


# -- KH6: the export's SHA-256 and the entries you named, never the file -----------------------------------------------
def test_the_kit_keeps_your_exports_sha256_and_the_entries_you_named_never_the_file(tmp_path):
    r, _, you, _ = run(tmp_path, "contain", state=True)
    doc, details, written = hosting.the_result(r, ["runs code"], "a model provider's API")
    text = json.dumps(doc) + json.dumps(details) + written.decode()
    for kept_out in ("ops-admin@example.com", "a line the kit never keeps", "another line the kit never keeps"):
        assert kept_out not in text
    evidence = doc["host"]["evidence"][0]
    assert evidence["product"]["sha256"] == hashlib.sha256(you.read("export.json")).hexdigest()
    assert evidence["host_up"]["state"]["sha256"] == hashlib.sha256(you.read("state.json")).hexdigest()


# -- the model's path (KH7) --------------------------------------------------------------------------------------------
def test_with_a_model_the_kit_asks_you_to_confirm_its_key_was_made_for_the_test(tmp_path):
    r, said, you, observer = run(tmp_path, r=a_run(model="Acme Models"))
    assert hosting.CONFIRM_MODEL_KEY.format(provider="Acme Models", run=RUN) in you.asked
    assert r.paths == ("outside_key", "open_internet", "model")
    assert outcomes(r) == {p: rule.HOST_STOPPED for p in r.paths}
    r, said, you, observer = run(tmp_path, r=a_run(model="Acme Models"), confirm_model=False)
    assert said == [hosting.NOT_CONFIRMED] and not observer.made and not list(tmp_path.iterdir())


def test_a_model_key_revoked_at_the_provider_while_the_probe_keeps_reporting_is_not_your_stop(tmp_path):
    r, _, _, _ = run(tmp_path, "model key", r=a_run(model="Acme Models"))
    found = r.repeats[0].found
    assert (found["model"].outcome, found["model"].reason) == (timing.NOT_MEASURED, rule.MODEL_STILL_REPORTING)
    assert found["outside_key"].outcome == found["open_internet"].outcome == timing.NOT_STOPPED


def test_without_a_model_the_probes_settings_turn_its_path_off(tmp_path):
    files = {}

    def say(words):
        folder = tmp_path / f"arvaken-stop-test-{RUN}"
        if words.startswith("The run's settings are in"):
            files.update({p.name: json.loads(p.read_text(encoding="utf-8")) for p in folder.glob("*.json")})

    clock = Clock()
    h = Host(clock)
    you = You(h)
    hosting.run(a_run(), ask=you, say=say, clock=clock, observe=FakeObserver(h), read=you.read, where=tmp_path)
    probe = probe_host.settings(files[f"stop-test-{RUN}-probe.json"])
    witness = probe_host.witness_settings(files[f"stop-test-{RUN}-witness.json"])
    assert probe["model"] is False and probe["observer"] == witness["observer"] == URL
    assert probe["key"] != witness["key"] and probe["until"] == T0 + hosting.LIFE_HOURS * 3600
    assert "key" not in files[f"stop-test-{RUN}-witness.json"]["arvaken_stop_test"]    # never the run's key


# -- how a run ends: the folder removed, the observer closed -----------------------------------------------------------
def test_a_copy_you_do_not_confirm_makes_nothing(tmp_path):
    r, said, _, observer = run(tmp_path, confirm=False)
    assert said == [hosting.NOT_CONFIRMED] and not observer.made and not list(tmp_path.iterdir())


def test_a_folder_already_there_is_never_taken_or_removed(tmp_path):
    folder = tmp_path / f"arvaken-stop-test-{RUN}"
    folder.mkdir()
    (folder / "yours.txt").write_text("kept", encoding="utf-8")
    r, said, _, observer = run(tmp_path)
    assert said == [hosting.FOLDER_IN_USE.format(folder=folder, run=RUN)] and not observer.made
    assert (folder / "yours.txt").read_text(encoding="utf-8") == "kept"


def test_a_stop_you_do_not_fire_times_nothing_and_leaves_nothing(tmp_path):
    r, said, _, observer = run(tmp_path, fire=False)
    assert hosting.NOT_FIRED in said and not r.repeats
    assert observer.closed_at is not None and not list(tmp_path.iterdir()) and not r.left_behind


def test_a_run_interrupted_at_the_mark_closes_the_observer_and_removes_its_folder(tmp_path):
    clock = Clock()
    h = Host(clock)
    you, observer = You(h, at_mark=KeyboardInterrupt()), FakeObserver(h)
    with pytest.raises(KeyboardInterrupt):
        hosting.run(a_run(), ask=you, say=lambda w: None, clock=clock, observe=observer, read=you.read,
                    where=tmp_path)
    assert observer.closed_at is not None and not list(tmp_path.iterdir())


def test_a_host_that_never_reaches_this_machine_times_nothing(tmp_path):
    r, said, _, observer = run(tmp_path, "nothing")
    assert said[-1] == hosting.NOT_READY.format(minutes=30) and not r.repeats
    assert observer.closed_at is not None and not list(tmp_path.iterdir())


def test_a_window_that_would_outlast_the_runs_settings_is_not_timed(tmp_path):
    r, said, _, _ = run(tmp_path, r=a_run(window=hosting.LIFE_HOURS * 3600))
    assert any(w.startswith("The run's settings end at") for w in said) and not r.repeats


def test_between_repeats_you_undo_your_stop_and_each_repeat_is_judged_from_its_own_mark(tmp_path):
    r, said, you, _ = run(tmp_path, r=a_run(repeats_wanted=2))
    assert hosting.AGAIN.format(n=2) in said and len(r.repeats) == 2
    assert r.repeats[1].mark_at > r.repeats[0].mark_at + W
    assert outcomes(r, 0) == outcomes(r, 1) == {"outside_key": rule.HOST_STOPPED, "open_internet": rule.HOST_STOPPED}
    doc, _, _ = hosting.the_result(r, ["runs code"], "a model provider's API")
    result.check(doc)
    assert len(doc["host"]["evidence"]) == len(doc["repeats"]) == doc["run"]["repeats"] == 2


def test_the_kit_waits_for_the_paths_that_reach_it_and_never_goes_on_without_the_witness():
    clock = Clock()
    h = Host(clock)
    h.arrives = lambda kind, t: kind != "model"
    o = FakeObserver(h)("r0123abcd", "k", "w", "203.0.113.5", 8443, Path("."), 8)
    o.t0, o.seen, o.upto, o.closed_at = clock.now(), {}, {}, None
    # the model never reaches it: after READY_LIMIT, the kit goes on with the two that do
    assert hosting.wait_ready(o, ("outside_key", "open_internet", "model"), clock) == ("outside_key", "open_internet")
    assert clock.now() - T0 >= hosting.READY_LIMIT
    silent = Host(Clock(), "kill")
    silent.arrives = lambda kind, t: kind != "witness"
    q = FakeObserver(silent)("r0123abcd", "k", "w", "203.0.113.5", 8443, Path("."), 8)
    q.t0, q.seen, q.upto, q.closed_at = silent.clock.now(), {}, {}, None
    assert hosting.wait_ready(q, ("outside_key",), silent.clock, limit=300) is None


# -- the command line --------------------------------------------------------------------------------------------------
def test_the_plan_says_what_the_run_makes_and_that_the_kit_fires_nothing(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(hosting, "run", lambda *a, **k: pytest.fail("a plan runs nothing"))
    assert cli.main(["host", "plan", *HOST_ARGS, "--run", RUN]) == 0
    out = capsys.readouterr().out
    assert out.startswith(f"Run {RUN}, on your test copy my-agent-test on your host test-host-1:")
    assert "listening on port 8443" in out and f"arvaken-stop-test-{RUN}" in out
    assert "the kit fires nothing" in out and "Acme Process Guard" in out and "for 900 seconds, 1 time" in out
    assert "keeps the three files it writes here: the result, its details and the observer's arrivals" in out
    assert "calls Acme Models" not in out
    assert cli.main(["host", "plan", *HOST_ARGS, "--model", "Acme Models"]) == 0
    assert "your copy's probe also calls Acme Models once a second" in capsys.readouterr().out
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("argv, says", [
    (["host", "plan", *HOST_ARGS[:5], "203.0.113.5", *HOST_ARGS[6:]], cli.HOST_NOT_AN_ADDRESS),
    (["host", "plan", *HOST_ARGS, "--window", "10m"], cli.HOST_WINDOW),
    (["host", "plan", *HOST_ARGS, "--window", "61m"], cli.HOST_WINDOW),
    (["host", "plan", *HOST_ARGS, "--repeats", "6"], cli.HOST_REPEATS),
    (["host", "plan", "--copy", "  ", *HOST_ARGS[2:]], cli.HOST_NAMES),
    (["host", "plan", *HOST_ARGS, "--model", "  "], cli.HOST_MODEL_NAMED),
    (["host", "run", *HOST_ARGS], cli.COPY_NEEDS_KINDS),
    (["host", "run", *HOST_ARGS, "--tool", "none", "--tool", "runs code", "--model-kind", "no model"],
     cli.COPY_NEEDS_KINDS),
    (["host", "plan", *HOST_ARGS, "--run", "../elsewhere"], cli.HOST_NOT_A_RUN),
    (["host", "clean", "--run", "../elsewhere"], cli.HOST_NOT_A_RUN),
])
def test_what_a_host_run_cannot_take_is_refused_before_anything(argv, says, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(hosting, "run", lambda *a, **k: pytest.fail("refused before anything"))
    with pytest.raises(SystemExit):
        cli.main(argv)
    assert says in capsys.readouterr().err.replace("\n", " ").replace("  ", " ")
    assert not list(tmp_path.iterdir())


def test_the_kit_refuses_to_run_as_root_or_an_administrator(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(hosting, "is_administrator", lambda: True)
    monkeypatch.setattr(hosting, "run", lambda *a, **k: pytest.fail("refused before anything"))
    assert cli.main(["host", "run", *HOST_ARGS, *KINDS]) == 1
    assert hosting.NOT_AS_ROOT in capsys.readouterr().out and not list(tmp_path.iterdir())


def test_a_run_through_the_command_line_writes_its_result_details_and_arrivals_which_verify_takes(
        tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(hosting, "is_administrator", lambda: False)
    clock = Clock()
    h = Host(clock)
    you = You(h)
    real = hosting.run
    monkeypatch.setattr(hosting, "run", lambda r, *, ask, say: real(r, ask=you, say=say, clock=clock,
                                                                    observe=FakeObserver(h), read=you.read))
    assert cli.main(["host", "run", *HOST_ARGS, *KINDS, "--run", RUN]) == 0
    out = capsys.readouterr().out
    written = sorted(p.name for p in tmp_path.iterdir())
    assert written == [f"stop-test-{RUN}-arrivals.json", f"stop-test-{RUN}-details.json", f"stop-test-{RUN}.json"]
    assert cli.COPY_FOUND in out and rule.ON_HOST in out and rule.PRODUCT_CLOCK in out
    assert "- calls out with a key: Stopped within 15 minutes, as seen from outside your host" in out
    assert f'"Acme Process Guard". {hosting.PRODUCT_AS_NAMED}' in out and hosting.HOST_LEFT in out
    # the teardown names the result it keeps (point 4 of the founder's record 739f7db3, 23:54:13 UTC on 14 November)
    assert cli.HOST_REMOVED.format(folder=Path.cwd() / f"arvaken-stop-test-{RUN}") in out
    assert cli.HOST_KEPT.format(out=f"stop-test-{RUN}.json", details=f"stop-test-{RUN}-details.json",
                                arrivals=f"stop-test-{RUN}-arrivals.json") in out
    assert "Nothing the kit made is left." not in out and cli.HOST_NOTHING_SENT in out
    assert cli.main(["verify", f"stop-test-{RUN}.json"]) == 0
    assert "A valid stop-test-result/3" in capsys.readouterr().out
    doc = json.loads((tmp_path / f"stop-test-{RUN}.json").read_text(encoding="utf-8"))
    arrivals = (tmp_path / f"stop-test-{RUN}-arrivals.json").read_bytes()
    assert doc["host"]["observer"]["arrivals_sha256"] == hashlib.sha256(arrivals).hexdigest()
    assert check_arrivals(json.loads(arrivals))["run"] == RUN
    assert doc["host"]["os"] == "Linux" and doc["host"]["stop_said"] == "ends your agent's process"
    assert doc["agent"]["tools"] == ["runs code"] and doc["agent"]["ref"] == "my-agent-test"


def test_clean_removes_the_folder_an_interrupted_run_left(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    folder = tmp_path / f"arvaken-stop-test-{RUN}"
    folder.mkdir()
    (folder / "observer-key.pem").write_text("left", encoding="utf-8")
    assert cli.main(["host", "clean", "--run", RUN]) == 0
    assert "Nothing the kit made is left." in capsys.readouterr().out and not folder.exists()
