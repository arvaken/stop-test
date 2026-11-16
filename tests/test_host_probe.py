"""The probe and the witness on a host you control (D709, sections 1 to 4; the probe's host.py and witness.py), and the
kit's observer they reach (host/observer.py). Held here: that the probe takes its settings only from the run's file and
reaches only the observer, pinned to the run's certificate, never through a proxy of the copy's environment; that the
model's path is off unless the run's settings turn it on (KH7); that each beat's report holds times, outcomes and
failure codes and nothing more; that both stop when the run is over (410); that the witness refuses root, uses its own
key, and removes its own folder; and, over this machine's loopback alone, that the observer keeps each arrival by its
own clock (KH5), refuses a wrong key and a stray address, and signs what it saw."""
from __future__ import annotations

import ast
import json
import ssl
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from arvaken_stop_test import result
from arvaken_stop_test.host import observer as observing
from arvaken_stop_test.host.observer import Observer, check_arrivals
from arvaken_stop_test_probe import core, heartbeat, host, witness
from arvaken_stop_test_probe.core import NotTheKits

ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "probe" / "src" / "arvaken_stop_test_probe"
RUN = "r0123abcd"
KEY, WITNESS_KEY = "0123456789abcdef" * 2, "fedcba9876543210" * 2
CERT = "-----BEGIN CERTIFICATE-----\nQUFBQQ==\n-----END CERTIFICATE-----\n"
URL = "https://203.0.113.5:8443"


def probe_file(**host_kw) -> dict:
    h = {"observer": URL, "certificate": CERT, "until": 4_000_000_000.0, "model": False, **host_kw}
    return {"arvaken_stop_test": {"run": RUN, "key": KEY, "host": h}}


def witness_file(**host_kw) -> dict:
    h = {"observer": URL, "certificate": CERT, "until": 4_000_000_000.0, **host_kw}
    return {"arvaken_stop_test": {"run": RUN, "witness_key": WITNESS_KEY, "host": h}}


class Ticking:
    """A clock that moves a second each time it is read."""

    def __init__(self, t: float = 1_000.0):
        self.t = t

    def time(self) -> float:
        self.t += 1.0
        return self.t

    def sleep(self, seconds: float) -> None:
        self.t += max(0.0, seconds)


# -- its settings ------------------------------------------------------------------------------------------------------
def test_the_probe_takes_the_runs_settings_from_its_file_and_nothing_else(tmp_path):
    s = host.settings(probe_file())
    assert s == {"run": RUN, "key": KEY, "observer": URL, "certificate": CERT, "until": 4_000_000_000.0,
                 "model": False}
    f = tmp_path / "stop-test-r0123abcd-probe.json"
    f.write_text(json.dumps(probe_file()), encoding="utf-8")
    assert host.settings(str(f)) == s


@pytest.mark.parametrize("doc, field", [
    ({"run": RUN}, "run"),
    ({"arvaken_stop_test": {"run": "r123", "key": KEY, "host": {}}}, "run"),
    ({"arvaken_stop_test": {"run": RUN, "key": "short", "host": {}}}, "key"),
    ({"arvaken_stop_test": {"run": RUN, "key": KEY}}, "host"),
    (probe_file(observer="http://203.0.113.5:8443"), "observer"),
    (probe_file(observer="https://203.0.113.5"), "observer"),
    (probe_file(observer="https://203.0.113.5:8443/key"), "observer"),
    (probe_file(observer="https://me:secret@203.0.113.5:8443"), "observer"),
    (probe_file(observer="https://203.0.113.5:8443?x=1"), "observer"),
    (probe_file(observer="https://bad_name:8443"), "observer"),
    (probe_file(certificate="not a certificate"), "certificate"),
    (probe_file(certificate=CERT * 200), "certificate"),
    (probe_file(until=True), "until"),
    (probe_file(until="soon"), "until"),
    (probe_file(model="yes"), "model"),
])
def test_settings_that_are_not_the_runs_are_refused_by_name(doc, field):
    with pytest.raises(NotTheKits) as e:
        host.settings(doc)
    assert e.value.args[0] == field


def test_the_probe_and_the_witness_each_take_only_their_own_file():
    """The witness's file holds its own key and never the run's; each refuses the other's."""
    assert host.witness_settings(witness_file())["key"] == WITNESS_KEY
    with pytest.raises(NotTheKits, match="key"):
        host.settings(witness_file())
    with pytest.raises(NotTheKits, match="witness_key"):
        host.witness_settings(probe_file())


@pytest.mark.parametrize("address, ok", [
    ("https://203.0.113.5:8443", True), ("https://observer.example:443", True), ("https://[2001:db8::5]:8443", True),
    ("https://observer.example", False), ("https://observer.example:0", False), ("https://[2001:db8::5:8443", False),
    ("https://observer.example:8443/", False), ("ftp://observer.example:21", False), (None, False),
])
def test_the_observers_address_is_https_a_host_and_a_port_and_nothing_more(address, ok):
    assert (host.observer_address(address) is not None) == ok


def test_the_observers_address_as_the_kit_takes_it_is_a_host_and_a_port():
    assert observing.address("203.0.113.5:8443") == ("203.0.113.5", 8443)
    assert observing.address("[2001:db8::5]:8443") == ("2001:db8::5", 8443)
    assert observing.address("observer.example:8443") == ("observer.example", 8443)
    for bad in ("203.0.113.5", "2001:db8::5:8443", "[203.0.113.5]:8443", "a/b:1", "me@host:1", "host:0", "host:70000",
                "https://host:1", ""):
        assert observing.address(bad) is None, bad
    assert observing.url("2001:db8::5", 8443) == "https://[2001:db8::5]:8443"
    assert host.observer_address(observing.url("observer.example", 8443)) == "https://observer.example:8443"


# -- its calls ---------------------------------------------------------------------------------------------------------
def test_each_beat_calls_only_the_observer_with_the_runs_key_on_one_call_and_none_on_the_other():
    sent = []
    found = core.beats(host.paths(host.settings(probe_file()), lambda url, headers, timeout: sent.append(
        (url, headers)) or 200), host.record)
    assert sent == [(f"{URL}/key", {"User-Agent": core.AGENT, "Authorization": "Bearer " + KEY}),
                    (f"{URL}/open/{RUN}", {"User-Agent": core.AGENT})]
    assert list(found) == ["outside_key", "open_internet"] and all(b["ok"] for b in found.values())


def test_the_models_path_is_off_unless_the_runs_settings_turn_it_on_and_then_calls_your_function():
    """KH7: off by default; on, one call through the function you pass, with a key you made for the run."""
    called = []
    s = host.settings(probe_file())
    names = [n for n, _ in host.paths(s, lambda *a: 200, model=lambda: called.append(1))]
    assert names == ["outside_key", "open_internet"] and not called
    core.beats(host.paths(s, lambda *a: 200, model=lambda: called.append(1)), host.record)
    assert not called
    on = host.settings(probe_file(model=True))
    found = core.beats(host.paths(on, lambda *a: 200, model=lambda: called.append(1)), host.record)
    assert list(found) == ["outside_key", "open_internet", "model"] and called == [1]
    with pytest.raises(NotTheKits, match="model"):
        host.start(probe_file(model=True))          # on, with no function to call: refused before any beat


def test_a_failures_record_on_a_host_is_a_code_and_a_status_never_a_message():
    refused = urllib.error.URLError(ssl.SSLCertVerificationError("certificate verify failed: a long message"))
    assert host.record(refused) == {"error": "TLSRefused", "status": None, "reason": None}
    assert host.record(urllib.error.HTTPError(URL, 401, "Unauthorized", None, None))["error"] == "HTTP401"

    class RateLimited(Exception):
        status_code = 429

    assert host.record(RateLimited("a provider's message with a secret in it")) == {
        "error": "RateLimited", "status": 429, "reason": None}
    assert host.record(type("E" * 100, (Exception,), {})())["error"] == "E" * 64


def test_the_report_holds_each_paths_time_outcome_and_code_and_nothing_else():
    beats = {"outside_key": {"at": 1.23456, "ok": True, "status": None},
             "open_internet": {"at": 1.5, "ok": False, "error": "Unreachable", "status": None, "reason": "a message"},
             "model": {"at": 2.0, "ok": False, "error": "RateLimited", "status": 429, "detail": "a provider's text"}}
    doc = json.loads(host.report(7, beats, "customer"))
    assert doc == {"n": 7, "http": "customer", "beats": {
        "outside_key": {"at": 1.235, "ok": True, "error": None, "status": None},
        "open_internet": {"at": 1.5, "ok": False, "error": "Unreachable", "status": None},
        "model": {"at": 2.0, "ok": False, "error": "RateLimited", "status": 429}}}
    assert len(host.report(10**9, beats)) < host.REPORT_LIMIT


def test_the_probes_tls_trusts_the_runs_certificate_alone_and_its_opener_no_proxy(monkeypatch):
    pem, _ = observing.certificate("127.0.0.1", 1)
    context = host.pinned(pem)
    assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
    assert context.minimum_version == ssl.TLSVersion.TLSv1_2
    assert len(context.get_ca_certs()) == 1
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("https_proxy", "http://127.0.0.1:9")
    # The control: urllib's default opener takes the environment's proxy.
    default = [h for h in urllib.request.build_opener().handlers if isinstance(h, urllib.request.ProxyHandler)]
    assert default and default[0].proxies.get("https") == "http://127.0.0.1:9"
    # The probe's opener has none: an empty ProxyHandler replaces the default one and, opening nothing, is not kept.
    opener = host.opener(context)
    assert not [h for h in opener.handlers if isinstance(h, urllib.request.ProxyHandler) and h.proxies]
    assert "https" not in getattr(opener, "handle_open", {}) or all(
        not isinstance(h, urllib.request.ProxyHandler) for h in opener.handle_open["https"])


def test_the_probe_beats_until_the_observer_says_the_run_is_over():
    posted = []

    def post(url, headers, body, timeout):
        posted.append((url, headers, json.loads(body)))
        return 410 if len(posted) == 3 else 200

    probe = host.Probe(host.settings(probe_file(until=1_100.0)), lambda *a: 200, post, clock=Ticking())
    probe.run()
    assert probe.over and probe.beats == 2 and len(posted) == 3
    assert [p[2]["n"] for p in posted] == [0, 1, 2]
    url, headers, _ = posted[0]
    assert url == f"{URL}/report" and headers["Authorization"] == "Bearer " + KEY
    assert headers["User-Agent"] == core.AGENT


def test_the_probe_stops_at_its_settings_until_and_a_report_it_could_not_send_is_no_stop():
    def post(url, headers, body, timeout):
        raise urllib.error.URLError("unreachable")

    probe = host.Probe(host.settings(probe_file(until=1_010.0)), lambda *a: 200, post, clock=Ticking())
    probe.run()
    assert not probe.over and 0 < probe.beats <= 10


def test_heartbeat_on_host_is_the_probes_host_start():
    assert "on_host" in heartbeat.__all__
    with pytest.raises(NotTheKits, match="run"):
        heartbeat.on_host({"not": "the kit's"})


def test_the_host_code_needs_only_the_standard_library():
    allowed = {"__future__", "ipaddress", "json", "os", "re", "shutil", "ssl", "sys", "threading", "time", "urllib",
               "pathlib", "ctypes", "arvaken_stop_test_probe"}
    for name in ("host.py", "witness.py"):
        tree = ast.parse((PROBE / name).read_text(encoding="utf-8"), feature_version=(3, 9))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom):
                imported.add((node.module or "").split(".")[0])
        assert imported <= allowed, (name, imported - allowed)


# -- the witness -------------------------------------------------------------------------------------------------------
def test_the_witness_refuses_to_run_as_root_or_an_administrator(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(witness, "is_administrator", lambda: True)
    said = []
    assert witness.main(["any.json"], post=lambda *a: pytest.fail("no beat"), say=said.append, where=tmp_path) == 1
    assert said == [witness.NOT_AS_ROOT] and not list(tmp_path.iterdir())


def test_the_witness_refuses_a_file_that_is_not_its_own(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(witness, "is_administrator", lambda: False)
    f = tmp_path / "probe.json"
    f.write_text(json.dumps(probe_file()), encoding="utf-8")
    said = []
    assert witness.main([str(f)], post=lambda *a: pytest.fail("no beat"), say=said.append, where=tmp_path) == 1
    assert said == [witness.NOT_ITS_FILE.format(field="witness_key")]
    said.clear()
    assert witness.main([str(tmp_path / "missing.json")], say=said.append, where=tmp_path) == 1
    assert said == [witness.NOT_ITS_FILE.format(field="file")]
    assert sorted(p.name for p in tmp_path.iterdir()) == ["probe.json"]


def test_the_witness_beats_with_its_own_key_from_its_own_folder_then_removes_it(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(witness, "is_administrator", lambda: False)
    f = tmp_path / "witness.json"
    f.write_text(json.dumps(witness_file(until=1_100.0)), encoding="utf-8")
    folder = tmp_path / f"arvaken-stop-test-{RUN}-witness"
    posted, where = [], []

    def post(url, headers, body, timeout):
        where.append((Path.cwd().resolve(), folder.is_dir()))
        posted.append((url, headers, json.loads(body)))
        return 410 if len(posted) == 3 else 200

    said = []
    assert witness.main([str(f)], post=post, clock=Ticking(), say=said.append, where=tmp_path) == 0
    assert [p[2] for p in posted] == [{"n": 0}, {"n": 1}, {"n": 2}]
    assert set(where) == {(folder.resolve(), True)}                    # it runs from its own folder
    assert {p[0] for p in posted} == {f"{URL}/witness"}
    assert posted[0][1] == {"User-Agent": core.AGENT, "Authorization": "Bearer " + WITNESS_KEY,
                            "Content-Type": "application/json"}
    assert not folder.exists() and Path.cwd().resolve() == tmp_path.resolve()
    assert said == [witness.STARTED.format(run=RUN, observer=URL), witness.ENDED.format(folder=folder)]


def test_the_witness_stops_at_ctrl_c_and_at_its_settings_until_and_removes_its_folder(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(witness, "is_administrator", lambda: False)
    f = tmp_path / "witness.json"
    f.write_text(json.dumps(witness_file(until=1_100.0)), encoding="utf-8")

    def interrupted(*a):
        raise KeyboardInterrupt

    assert witness.main([str(f)], post=interrupted, clock=Ticking(), say=lambda s: None, where=tmp_path) == 0
    assert not (tmp_path / f"arvaken-stop-test-{RUN}-witness").exists()
    s = host.witness_settings(witness_file(until=1_010.0))
    assert 0 < witness.beats(s, lambda *a: 200, Ticking()) <= 10


def test_the_witness_never_takes_a_folder_that_is_already_there(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(witness, "is_administrator", lambda: False)
    f = tmp_path / "witness.json"
    f.write_text(json.dumps(witness_file()), encoding="utf-8")
    folder = tmp_path / f"arvaken-stop-test-{RUN}-witness"
    folder.mkdir()
    (folder / "yours.txt").write_text("kept", encoding="utf-8")
    said = []
    assert witness.main([str(f)], post=lambda *a: pytest.fail("no beat"), say=said.append, where=tmp_path) == 1
    assert said == [witness.FOLDER_IN_USE.format(folder=folder)]
    assert (folder / "yours.txt").read_text(encoding="utf-8") == "kept"


# -- over this machine's loopback --------------------------------------------------------------------------------------
def _until(check, seconds: float = 20.0) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if check():
            return True
        time.sleep(0.1)
    return False


def _files(o: Observer, model: bool = False) -> tuple[dict, dict]:
    common = {"observer": o.url(), "certificate": o.certificate, "until": time.time() + 600}
    return ({"arvaken_stop_test": {"run": RUN, "key": KEY, "host": {**common, "model": model}}},
            {"arvaken_stop_test": {"run": RUN, "witness_key": WITNESS_KEY, "host": common}})


def test_over_loopback_the_observer_keeps_each_arrival_by_its_own_clock_and_the_run_ends_with_410(tmp_path,
                                                                                                    monkeypatch):
    # a proxy in the copy's environment is never used: these would fail through one
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("https_proxy", "http://127.0.0.1:9")
    o = Observer(RUN, KEY, WITNESS_KEY, "127.0.0.1", 0, tmp_path, 1, listen="127.0.0.1")
    o.start()
    assert (tmp_path / "observer-key.pem").exists() and o.port != 0
    probe_doc, witness_doc = _files(o)
    probe = None
    stopping = threading.Event()
    ws = host.witness_settings(witness_doc)
    beating = threading.Thread(target=witness.beats, args=(ws, host.runtime_post(host.pinned(ws["certificate"]))),
                               kwargs={"stopping": stopping.is_set}, daemon=True)
    try:
        probe = host.start(probe_doc)
        beating.start()
        assert _until(lambda: min(len(o.arrivals("outside_key")), len(o.arrivals("open_internet")),
                                  len(o.witness()), len(o.reports())) >= 2)
        get = host.runtime_get(host.pinned(o.certificate))
        with pytest.raises(urllib.error.HTTPError) as e:        # a key that is not the run's
            get(f"{o.url()}/key", {"Authorization": "Bearer " + "f" * 32}, 2)
        assert e.value.code == 401 and o.refused_keys == 1
        with pytest.raises(urllib.error.HTTPError) as e:        # another run's open address
            get(f"{o.url()}/open/r00000000", {}, 2)
        assert e.value.code == 404
        post = host.runtime_post(host.pinned(o.certificate))     # the run's key is not the witness's
        assert post(f"{o.url()}/witness", {"Authorization": "Bearer " + KEY}, b'{"n": 0}', 2) == 401
        assert o.refused_keys == 2
        other, _ = observing.certificate("127.0.0.1", 1)        # a certificate that is not the run's
        stray = host.settings({"arvaken_stop_test": {"run": RUN, "key": KEY, "host": {
            **probe_doc["arvaken_stop_test"]["host"], "certificate": other}}})
        found = core.beats(host.paths(stray, host.runtime_get(host.pinned(other))), host.record)
        assert {b["error"] for b in found.values()} == {"TLSRefused"}
    finally:
        o.close(wait=lambda s: probe.thread.join(timeout=s) if probe else None)
        stopping.set()
    assert probe.over and not probe.thread.is_alive()           # the observer's 410 ended its beats
    beating.join(timeout=5)
    assert not beating.is_alive()
    assert o.source() == "127.0.0.1" and o.http_client() == result.CLIENTS[1]
    arrived = o.arrivals("outside_key")
    assert arrived == sorted(arrived) and all(abs(t - time.time()) < 120 for t in arrived)
    signed, public = o.signed()
    assert check_arrivals(json.loads(json.dumps(signed)))["signature"]["public_key"] == public
    assert len(signed["paths"]["outside_key"]) == len(arrived) and signed["refused_keys"] == 2
    text = json.dumps(signed)
    assert KEY not in text and WITNESS_KEY not in text


def test_over_loopback_your_own_client_and_the_models_path_are_named_in_what_the_observer_kept(tmp_path):
    o = Observer(RUN, KEY, WITNESS_KEY, "127.0.0.1", 0, tmp_path, 1, listen="127.0.0.1")
    o.start()
    probe_doc, _ = _files(o, model=True)
    runtime = host.runtime_get(host.pinned(o.certificate))
    yours, models = [], []
    probe = None
    try:
        probe = host.start(probe_doc, http=lambda url, headers, timeout: yours.append(url) or runtime(
            url, headers, timeout), model=lambda: models.append(1))
        assert _until(lambda: len(o.arrivals("model")) >= 2 and len(o.arrivals("outside_key")) >= 2)
    finally:
        o.close(wait=lambda s: probe.thread.join(timeout=s) if probe else None)
    assert yours and models and o.http_client() == result.CLIENTS[0]
    assert all(beats["model"]["ok"] for _, _, beats in o.reported if "model" in beats)
