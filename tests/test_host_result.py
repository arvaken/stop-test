"""The result of a run on a host you control (D709, section 5; result.SHAPE_HOST): a stop-test-result/3 whose cloud is
"host", which `check` reads in its own shape. Held here: its shape, field for field, as the README's "On a host you
control" documents it for Arvaken's record and the self-hosted connector (D712, SH8); that each path names the rule
that judged it, and `check` refuses either rule's outcomes under the other; that "stopped, as seen from outside the
host" stands only with the product's record and the host seen up; and that the export is kept by its SHA-256 and the
entries you named, never the file (KH6)."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from arvaken_stop_test import result, sdk, timing
from arvaken_stop_test.host import rule
from arvaken_stop_test.host.observer import Observer, check_arrivals
from arvaken_stop_test.host.rule import HostState
from arvaken_stop_test.host.run import HostRun, Repeat, details, the_result
from arvaken_stop_test.result import NotAResult, iso

ROOT = Path(__file__).resolve().parents[1]
RUN = "r0123abcd"
KEY, WITNESS_KEY = "0123456789abcdef" * 2, "fedcba9876543210" * 2
M = 1_900_000_000.0
W = 900.0
EXPORT = (b'{"events": [{"time": "2030-03-17T17:46:45Z", "type": "ProcessKilled", "by": "ops-admin@example.com", '
          b'"note": "a line of the export the kit never keeps"}]}')
STATE_EXPORT = (b'[{"at": "2030-03-17T17:46:45Z", "event": "HostIsolated"}, '
                b'{"at": "2030-03-17T18:02:40Z", "event": "HostStillIsolated"}, {"secret": "never kept"}]')


def every_second(start: float, stop: float) -> list[float]:
    return [start + i for i in range(int(stop - start))]


def host_run(tmp_path, *, record=True, witness_up=True, arrivals=None, paths=("outside_key", "open_internet"),
             state=False) -> HostRun:
    """A run of one repeat, judged by the rule from the arrivals given: by default a process kill 5 seconds after the
    mark, with the product's record and the witness up through the window."""
    r = HostRun(run=RUN, copy="my-agent-test", host="test-host-1", observer="203.0.113.5:8443",
                stop_said=result.HOST_STOPS[0], product="Acme Process Guard", os=result.HOST_OS[0], container=False,
                window=W, repeats_wanted=1)
    r.paths, r.began_at, r.ended_at, r.source = paths, M - 100, M + W + 10, "198.51.100.7"
    rep = Repeat(mark_at=M)
    rep.record = sdk.record(EXPORT, "2030-03-17T17:46:45Z", "ProcessKilled") if record else None
    if state:
        rep.state = HostState(sdk.record(STATE_EXPORT, "2030-03-17T17:46:45Z", "HostIsolated"),
                              sdk.record(STATE_EXPORT, "2030-03-17T18:02:40Z", "HostStillIsolated"))
    witness = every_second(M - 60, M + W + 5) if witness_up else every_second(M - 60, M + 5)
    rep.up = rule.host_up(witness, rep.state, M, W)
    for p in paths:
        rep.found[p] = rule.judge(arrivals if arrivals is not None else every_second(M - 60, M + 5), mark_at=M,
                                  window=W, record=rep.record, up=rep.up)
    r.repeats = [rep]
    r.arrivals, r.observer_key = Observer(RUN, KEY, WITNESS_KEY, "203.0.113.5", 8443, tmp_path, 8).signed()
    r.calls = 1234
    return r


def made(tmp_path, **kw):
    return the_result(host_run(tmp_path, **kw), ["runs code"], "a model provider's API")


def resigned(doc: dict) -> dict:
    """A changed result, signed again, so that only its contents can be what `check` refuses."""
    return result.sign(doc, result.new_key())


# -- its shape ---------------------------------------------------------------------------------------------------------
def test_a_run_on_a_host_writes_a_version_3_result_that_check_reads_in_the_hosts_own_shape(tmp_path):
    doc, _, _ = made(tmp_path)
    assert result.check(json.loads(json.dumps(doc))) == doc
    assert (doc["format"], doc["cloud"], doc["region"]) == (result.FORMAT_V3, "host", None)
    assert set(doc) == set(result.SHAPE_HOST[""])
    assert doc["agent"]["kind"] == "host-copy" and doc["agent"]["clients"] == {"cloud": None, "http": "the runtime's"}
    assert doc["stop"]["product"] == {"kind": "host software", "attachment": "on its host", "name": "Acme Process Guard"}
    assert doc["stop"]["fired_by"] == "your own trigger" and doc["stop"]["record"] is None
    host = doc["host"]
    assert host["where"] == "a host you control" and host["os"] == "Linux" and host["container"] is False
    assert host["stop_said"] == "ends your agent's process"
    assert host["on_host"] == "not observable from outside the host"            # KH4: no outcome for it
    assert (host["name"], host["address"]) == ("test-host-1", "198.51.100.7")
    assert host["observer"]["address"] == "203.0.113.5:8443"
    for part in doc["repeats"][0].values():
        assert part["outcome"] == rule.HOST_STOPPED and part["rule"] == "host stop"
        assert part["timed_from"] == "your mark" and part["first_refused_after"] is None
        assert part["fired_at"] == iso(M) and part["silent_from"] == iso(M + 5)
        assert part["last_success_after"] == iso(M + 4)
    evidence = host["evidence"][0]
    assert evidence["product"] == {"time": "2030-03-17T17:46:45Z", "entered_by_you": True, "before_mark": False,
                                   "name": "ProcessKilled", "sha256": hashlib.sha256(EXPORT).hexdigest()}
    assert evidence["host_up"] == {"by": rule.BY_WITNESS, "witness_silent_from": None, "state": None}
    assert doc["run"]["clock_gap_ms"] == 0                  # one clock: the mark and every arrival are this machine's


def test_where_the_witness_fell_silent_the_result_holds_the_hosts_state_by_its_entries_and_sha256(tmp_path):
    doc, _, _ = made(tmp_path, witness_up=False, state=True)
    result.check(doc)
    up = doc["host"]["evidence"][0]["host_up"]
    assert up == {"by": rule.BY_STATE, "witness_silent_from": iso(M + 4),
                  "state": {"from": "2030-03-17T17:46:45Z", "from_name": "HostIsolated",
                            "until": "2030-03-17T18:02:40Z", "until_name": "HostStillIsolated",
                            "sha256": hashlib.sha256(STATE_EXPORT).hexdigest()}}
    assert {p["outcome"] for p in doc["repeats"][0].values()} == {rule.HOST_STOPPED}


def test_a_host_that_may_have_gone_down_is_written_not_measured_and_check_takes_it(tmp_path):
    doc, info, _ = made(tmp_path, witness_up=False)
    result.check(doc)
    assert {p["outcome"] for p in doc["repeats"][0].values()} == {timing.NOT_MEASURED}
    assert doc["host"]["evidence"][0]["host_up"] == {"by": None, "witness_silent_from": iso(M + 4), "state": None}
    reason = info["repeats"][0]["paths"]["outside_key"]["reason"]
    assert reason == rule.HOST_MAY_BE_DOWN.format(time=rule._clock(M + 4))


def test_with_no_record_from_the_product_the_result_says_none_and_no_path_reads_stopped(tmp_path):
    doc, info, _ = made(tmp_path, record=False)
    result.check(doc)
    assert doc["host"]["evidence"][0]["product"] is None
    assert {p["outcome"] for p in doc["repeats"][0].values()} == {timing.NOT_MEASURED}
    assert info["repeats"][0]["paths"]["open_internet"]["reason"] == rule.NO_RECORD


def test_the_result_keeps_the_exports_sha256_and_the_entries_you_named_never_the_file(tmp_path):
    """KH6."""
    doc, info, arrivals = made(tmp_path, witness_up=False, state=True)
    text = json.dumps(doc) + json.dumps(info) + arrivals.decode()
    for kept_out in ("ops-admin@example.com", "a line of the export the kit never keeps", "never kept", "secret"):
        assert kept_out not in text
    assert hashlib.sha256(EXPORT).hexdigest() in json.dumps(doc)


def test_the_observers_arrivals_are_signed_and_the_result_holds_their_sha256_and_its_key(tmp_path):
    doc, info, written = made(tmp_path)
    assert doc["host"]["observer"]["arrivals_sha256"] == hashlib.sha256(written).hexdigest()
    arrivals = check_arrivals(json.loads(written))
    assert arrivals["signature"]["public_key"] == doc["host"]["observer"]["public_key"]
    assert arrivals["format"] == "stop-test-arrivals/1" and arrivals["run"] == RUN
    assert KEY not in written.decode() and WITNESS_KEY not in written.decode()       # never the run's keys
    changed = json.loads(written)
    changed["witness"].append(iso(M))
    with pytest.raises(NotAResult, match="has changed"):
        check_arrivals(changed)
    assert info["arrivals_file"] == f"stop-test-{RUN}-arrivals.json"


def test_the_details_say_each_paths_finding_with_why_and_its_time_to_effect(tmp_path):
    doc, info, _ = made(tmp_path)
    assert info["result_reference"] == result.reference(doc)
    path = info["repeats"][0]["paths"]["outside_key"]
    assert path["outcome"] == rule.HOST_STOPPED and path["effect_between"] == [4.0, 5.0]
    assert path["words"].startswith("Stopped within 15 minutes, as seen from outside your host")
    assert path["fired_source"] == rule.FROM_THE_MARK
    assert info["on_host"] == rule.ON_HOST and info["product_clock"] == rule.PRODUCT_CLOCK
    assert info["rule"] == "host stop"


# -- what check refuses ------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("outcome", [timing.STOPPED, timing.FLAPPED, "stopped, by Arvaken's rule for an SDK's stop"])
def test_the_refusal_rules_outcomes_and_the_sdks_are_refused_on_a_host(tmp_path, outcome):
    doc, _, _ = made(tmp_path)
    doc["repeats"][0]["outside_key"]["outcome"] = outcome
    with pytest.raises(NotAResult, match="has an outcome the rule does not give"):
        result.check(resigned(doc))


@pytest.mark.parametrize("outcome", [rule.HOST_STOPPED, rule.HOST_FLAPPED])
def test_the_host_rules_outcomes_are_refused_anywhere_but_on_a_host(tmp_path, outcome):
    doc, _, _ = made(tmp_path)
    cloud = copy.deepcopy(doc)
    cloud["cloud"], cloud["region"] = "aws", "eu-central-1"
    del cloud["host"]
    for part in cloud["repeats"][0].values():
        del part["rule"], part["silent_from"]
        part["outcome"] = outcome
    with pytest.raises(NotAResult, match="has an outcome the rule does not give"):
        result.check(resigned(cloud))
    v2 = copy.deepcopy(cloud)
    v2["format"] = result.FORMAT
    del v2["stop"]["record"]
    for k in ("whose", "tools", "model_kind", "clients"):
        del v2["agent"][k]
    for part in v2["repeats"][0].values():
        del part["timed_from"]
    with pytest.raises(NotAResult, match="has an outcome the rule does not give"):
        result.check(resigned(v2))


def test_a_version_2_result_cannot_say_it_ran_on_a_host(tmp_path):
    doc, _, _ = made(tmp_path)
    doc["format"] = result.FORMAT
    with pytest.raises(NotAResult) as e:
        result.check(resigned(doc))
    assert str(e.value) == result.REFUSALS_HOST["outcomes"]


def test_stopped_as_seen_from_outside_the_host_needs_the_products_record_and_the_host_seen_up(tmp_path):
    doc, _, _ = made(tmp_path)
    no_record = copy.deepcopy(doc)
    no_record["host"]["evidence"][0]["product"] = None
    no_witness = copy.deepcopy(doc)
    no_witness["host"]["evidence"][0]["host_up"] = {"by": None, "witness_silent_from": iso(M + 4), "state": None}
    no_silence = copy.deepcopy(doc)
    no_silence["repeats"][0]["outside_key"]["silent_from"] = None
    another_rule = copy.deepcopy(doc)
    another_rule["repeats"][0]["outside_key"]["rule"] = "refusal"
    from_the_cloud = copy.deepcopy(doc)
    from_the_cloud["repeats"][0]["outside_key"]["timed_from"] = None
    refused = copy.deepcopy(doc)
    refused["repeats"][0]["outside_key"]["first_refused_after"] = iso(M + 5)
    for bad in (no_record, no_witness, no_silence, another_rule, from_the_cloud, refused):
        with pytest.raises(NotAResult) as e:
            result.check(resigned(bad))
        assert str(e.value) == result.REFUSALS_HOST["outcomes"]


def test_a_path_the_host_mode_has_no_way_to_time_is_refused(tmp_path):
    doc, _, _ = made(tmp_path)
    doc["repeats"][0]["own_calls"] = dict(doc["repeats"][0]["outside_key"])
    with pytest.raises(NotAResult) as e:
        result.check(resigned(doc))
    assert str(e.value) == result.REFUSALS_HOST["outcomes"]


@pytest.mark.parametrize("change, refusal", [
    (lambda d: d["host"].update(extra=1), "host holds exactly"),
    (lambda d: d["host"].pop("on_host"), "host holds exactly"),
    (lambda d: d["host"]["observer"].update(key="x"), "host.observer holds exactly"),
    (lambda d: d["host"]["evidence"][0].update(file="x"), "host.evidence holds exactly"),
    (lambda d: d["repeats"][0]["outside_key"].pop("rule"), "repeat.path holds exactly"),
    (lambda d: d.pop("host"), "the result holds exactly"),
    (lambda d: d["host"].update(on_host="stopped"), result.REFUSALS_HOST["host"]),
    (lambda d: d["host"].update(os="Plan 9"), result.REFUSALS_HOST["host"]),
    (lambda d: d["host"].update(stop_said="it stops"), result.REFUSALS_HOST["host"]),
    (lambda d: d["host"].update(container="no"), result.REFUSALS_HOST["host"]),
    (lambda d: d["host"].update(name=""), result.REFUSALS_HOST["host"]),
    (lambda d: d["host"]["observer"].update(public_key="AAAA"), result.REFUSALS_HOST["host"]),
    (lambda d: d["host"]["observer"].update(arrivals_sha256="0" * 63), result.REFUSALS_HOST["host"]),
    (lambda d: d["host"].update(evidence=[]), result.REFUSALS_HOST["evidence"]),
    (lambda d: d["host"]["evidence"][0]["product"].update(entered_by_you=False), result.REFUSALS_HOST["evidence"]),
    (lambda d: d["host"]["evidence"][0]["product"].update(sha256="x"), result.REFUSALS_HOST["evidence"]),
    (lambda d: d["host"]["evidence"][0]["host_up"].update(by="a guess"), result.REFUSALS_HOST["evidence"]),
    (lambda d: d["host"]["evidence"][0]["host_up"].update(by=rule.BY_STATE), result.REFUSALS_HOST["evidence"]),
    (lambda d: d["agent"]["clients"].update(cloud="yours"), result.REFUSALS_HOST["agent"]),
    (lambda d: d["agent"].update(kind="copy"), result.REFUSALS_HOST["agent"]),
    (lambda d: d["agent"].update(runtime="python3.12"), result.REFUSALS_HOST["agent"]),
    (lambda d: d.update(region="eu-central-1"), result.REFUSALS_HOST["stop"]),
    (lambda d: d["stop"]["product"].update(kind="in-agent SDK", attachment="inside its code"),
     result.REFUSALS_HOST["stop"]),
    (lambda d: d["stop"].update(fired_by="the kit", kind="a product's control"), None),
])
def test_a_host_result_that_is_not_exactly_its_shape_is_refused(tmp_path, change, refusal):
    doc, _, _ = made(tmp_path)
    change(doc)
    with pytest.raises(NotAResult) as e:
        result.check(resigned(doc))
    if refusal is not None:
        assert str(e.value).startswith(refusal)


def test_a_host_result_whose_contents_changed_after_it_was_signed_is_refused(tmp_path):
    doc, _, _ = made(tmp_path)
    doc["host"]["name"] = "another-host"
    with pytest.raises(NotAResult, match="signature does not check"):
        result.check(doc)


# -- the format, for Arvaken's record and the self-hosted connector (D712, SH8) ----------------------------------------
def test_every_identifying_field_of_a_hosts_result_is_one_of_its_fields():
    for name in result.IDENTIFYING_HOST:
        part, _, field = name.rpartition(".")
        assert field in result.SHAPE_HOST[part], name
    assert {"host.name", "host.address", "host.observer.address", "host.evidence.product.name",
            "host.evidence.product.sha256", "agent.ref"} <= set(result.IDENTIFYING_HOST)
    assert set(result.IDENTIFYING_V3) <= set(result.IDENTIFYING_HOST)


def test_the_readme_documents_every_field_and_value_a_hosts_result_adds():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    section = readme[readme.index("\n## On a host you control\n"):readme.index("\n## What counts as stopped\n")]
    for part in ("host", "host.observer", "host.evidence", "host.evidence.product", "host.evidence.host_up",
                 "host.evidence.host_up.state"):
        for field in result.SHAPE_HOST[part]:
            assert f"`{field}`" in section, (part, field)
    for value in ("`rule`", "`silent_from`", '"host stop"', '"host"', '"host-copy"', '"host software"',
                  "stop-test-arrivals/1", *(f'"{v}"' for v in (*result.HOST_OS, *result.HOST_STOPS)),
                  f'"{rule.HOST_STOPPED}"', f'"{rule.HOST_FLAPPED}"', f'"{rule.BY_WITNESS}"', f'"{rule.BY_STATE}"',
                  f'"{result.HOST_WHERE}"', f'"{result.HOST_ON_HOST}"'):
        assert value in section, value
