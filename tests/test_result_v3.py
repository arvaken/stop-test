"""stop-test-result/3 (D575; the kit's terms v5, D721): a run on a test copy of the customer's own agent, and an in-agent
SDK's switch on it (D713, D714). What it adds is exactly the terms' 4.4 additions, readable, and 4.2's, sealed; `check`
refuses any other field and any part that does not hold with the rest. The kit's own test agent's runs still write /2."""
from __future__ import annotations

import copy as copying

import pytest

from arvaken_stop_test import result, sdk
from arvaken_stop_test.aws import your_copy
from test_aws_copy import COPY, an_account  # noqa: F401 - a fixture
from test_sdk import an_sdk_run

TOOLS, MODEL_KIND = ["runs code", "reads or writes a database"], "a model service of its cloud"


@pytest.fixture
def an_sdk_result(an_account, monkeypatch):
    r, aws, _, _, files = an_sdk_run(monkeypatch)
    doc, details = your_copy.the_result(r, TOOLS, MODEL_KIND)
    return doc, details, r, aws, files


def test_an_sdks_run_on_a_lambda_copy_writes_a_version_3_result_as_the_terms_4_2_and_4_4_have_it(an_sdk_result):
    doc, details, r, aws, files = an_sdk_result
    assert result.check(doc) == doc and doc["format"] == result.FORMAT_V3
    agent, stop = doc["agent"], doc["stop"]
    # readable (4.4): whose test agent it was, the kinds of its tools and model, and whose clients, by kind
    assert (agent["whose"], agent["tools"], agent["model_kind"]) == ("yours", TOOLS, MODEL_KIND)
    assert agent["clients"] == {"cloud": "yours", "http": "yours"} and agent["ref"] == COPY
    # the SDK's record: the entry's time readable; its name and the file's SHA-256 sealed (4.2); the file never
    import hashlib
    assert stop["record"] == {"time": r.sdk_record.time, "entered_by_you": True, "before_mark": False,
                              "name": "kill switch engaged",
                              "sha256": hashlib.sha256(files["acme-audit.log"]).hexdigest()}
    assert stop["product"] == {"kind": "in-agent SDK", "attachment": "inside its code", "name": "Acme Guard"}
    assert (stop["kind"], stop["fired_by"]) == (result.PRODUCT_CONTROL, "your own trigger")
    # each path, timed from the mark, and stopped by the rule
    for part in doc["repeats"][0].values():
        assert (part["timed_from"], part["outcome"]) == ("your mark", sdk.SDK_STOPPED)
    assert "ops@example.com" not in str(doc) and "ops@example.com" not in str(details)
    assert details["witness"]["failed"] == [] and details["witness"]["calls"] >= 700


def test_what_is_sealed_is_every_identifier_with_the_sdk_entrys_name_and_the_files_sha256():
    assert set(result.IDENTIFYING_V3) == {*result.IDENTIFYING, "stop.record.name", "stop.record.sha256"}
    assert {"agent.ref", "agent.role_ref", "stop.product.name"} <= set(result.IDENTIFYING_V3)
    # and nothing the terms' 4.4 keeps readable is sealed
    assert not {"agent.whose", "agent.tools", "agent.model_kind", "agent.clients", "stop.record.time",
                "repeat.path.timed_from"} & set(result.IDENTIFYING_V3)


def mutated(doc, change):
    body = copying.deepcopy({k: v for k, v in doc.items() if k != "signature"})
    change(body)
    return result.sign(body, result.new_key())


def _set(path, value):
    def change(body):
        *parents, last = path
        for p in parents:
            body = body[p] if not isinstance(p, int) else body[p]
        body[last] = value
    return change


@pytest.mark.parametrize("change, says", [
    (_set(("agent", "whose"), "someone else's"), "a test agent is the kit's"),
    (_set(("agent", "tools"), ["runs code", "flies drones"]), "a test agent is the kit's"),
    (_set(("agent", "tools"), ["no tools", "runs code"]), "a test agent is the kit's"),
    (_set(("agent", "tools"), []), "a test agent is the kit's"),
    (_set(("agent", "tools"), ["runs code", "runs code"]), "a test agent is the kit's"),
    (_set(("agent", "model_kind"), "a big one"), "a test agent is the kit's"),
    (_set(("agent", "clients"), {"cloud": "yours"}), "agent.clients holds exactly"),
    (_set(("agent", "clients"), {"cloud": "mine", "http": "yours"}), "a test agent is the kit's"),
    (_set(("stop", "record"), {"time": "17:31:04Z", "entered_by_you": True, "before_mark": False, "name": "",
                                "sha256": "0" * 64}), "an SDK's own record"),
    (_set(("stop", "record"), {"time": "17:31:04Z", "entered_by_you": True, "before_mark": False, "name": "n",
                                "sha256": "not a hash"}), "an SDK's own record"),
    (_set(("stop", "record"), {"time": "17:31:04Z", "entered_by_you": False, "before_mark": False, "name": "n",
                                "sha256": "0" * 64}), "an SDK's own record"),
    (_set(("stop", "record"), {"time": "17:31:04Z", "entered_by_you": True, "before_mark": False, "name": "n",
                                "sha256": "0" * 64, "file": "..."}), "stop.record holds exactly"),
    # a time Arvaken's record wouldn't keep in clear (sdk.time_fits; the founder's answer, 19:00:00 UTC, 2 November 2026)
    (_set(("stop", "record", "time"), "2026-11-02 17:31 UTC, by ops@example.com"), "an SDK's own record"),
    (_set(("stop", "record", "time"), "x" * 62 + " 26"), "an SDK's own record"),
    (_set(("stop", "record", "time"), "seventeen thirty"), "an SDK's own record"),
    (_set(("stop", "record", "time"), " 17:31:04Z"), "an SDK's own record"),
])
def test_check_refuses_a_version_3_result_whose_parts_do_not_hold(an_sdk_result, change, says):
    doc = an_sdk_result[0]
    with pytest.raises(result.NotAResult, match=says):
        result.check(mutated(doc, change))


def test_check_refuses_an_sdks_outcomes_and_timing_on_any_other_stop(an_sdk_result):
    doc = an_sdk_result[0]

    def not_an_sdk(body):
        body["stop"].update(kind="policy on a role", fired_by="the kit", ref="arn:aws:iam::1:policy/p", product=None,
                            record=None)

    with pytest.raises(result.NotAResult, match="never says your mark"):     # a kit-fired stop claiming the mark
        result.check(mutated(doc, not_an_sdk))

    def not_an_sdk_untimed(body):
        not_an_sdk(body)
        for part in body["repeats"][0].values():
            part["timed_from"] = None

    with pytest.raises(result.NotAResult, match="belong to an SDK's switch alone"):
        result.check(mutated(doc, not_an_sdk_untimed))

    def a_record_beside_a_gateway(body):
        body["stop"]["product"] = {"kind": "gateway", "attachment": "its calls to a model", "name": "G"}
        for part in body["repeats"][0].values():
            part["timed_from"] = None

    with pytest.raises(result.NotAResult, match="only where the stop is an SDK's switch"):
        result.check(mutated(doc, a_record_beside_a_gateway))


ODD = ([], {}, [[1]], [{"a": 1}], [None], 1, 1.5, True, None, "x", {"k": []}, ["no tools", ["runs code"]])


def test_check_refuses_and_never_fails_on_an_odd_value_in_any_place_of_a_result(an_sdk_result):
    """Each place of a signed result, each set to a list, a mapping, a number or text: check refuses it, or takes it,
    and raises nothing else. A list inside agent.tools, or a mapping as the format or a product's kind, once failed
    with a TypeError while they were looked up (console-plan's reading of the customer app's version 3, 2 November
    2026)."""
    doc = an_sdk_result[0]

    def places(node, path=()):
        if path:
            yield path
        for key, value in node.items() if isinstance(node, dict) else enumerate(node) if isinstance(node, list) else ():
            yield from places(value, (*path, key))

    failed = []
    for path in places({k: v for k, v in doc.items() if k != "signature"}):
        for odd in ODD:
            try:
                result.check(mutated(doc, _set(path, copying.deepcopy(odd))))
            except result.NotAResult:
                pass
            except Exception as e:  # noqa: BLE001 - any other is what this finds
                failed.append(f"{'.'.join(map(str, path))} = {odd!r}: {type(e).__name__}: {e}")
    assert not failed, "\n".join(failed)


def test_an_sdks_run_without_its_record_writes_a_result_whose_every_path_is_not_measured(an_account, monkeypatch):
    r, _, _, _, _ = an_sdk_run(monkeypatch, answers={your_copy.SDK_EXPORT: ""})
    doc, _ = your_copy.the_result(r, ["no tools"], "no model")
    assert result.check(doc)["stop"]["record"] is None
    assert {p["outcome"] for p in doc["repeats"][0].values()} == {"not measured"}
    assert {p["timed_from"] for p in doc["repeats"][0].values()} == {"your mark"}


def test_a_version_2_result_cannot_carry_version_3s_fields_and_the_kits_own_runs_still_write_2(an_sdk_result):
    doc = an_sdk_result[0]
    as_two = mutated(doc, lambda body: body.update(format=result.FORMAT))
    with pytest.raises(result.NotAResult, match="holds exactly"):
        result.check(as_two)
    from test_aws_run import Clock, FakeAWS, a_run
    clock = Clock()
    _, kits = a_run(FakeAWS(clock), clock)
    assert kits["format"] == result.FORMAT and "whose" not in kits["agent"]


def test_a_kit_fired_stop_on_an_agentcore_copy_writes_a_version_3_result(monkeypatch):
    from arvaken_stop_test.agentcore import your_copy as agentcore_copy
    from test_agentcore import Clock
    from test_agentcore_copy import COPY as AGENTCORE_COPY, CopyAWS, a_copy_run
    clock = Clock()
    aws = CopyAWS(clock)
    r, _, _ = a_copy_run(aws, clock, monkeypatch)
    doc, _ = agentcore_copy.the_result(r, ["no tools"], "no model")
    assert result.check(doc)["format"] == result.FORMAT_V3
    assert (doc["agent"]["kind"], doc["agent"]["ref"], doc["stop"]["record"]) == (
        "aws-agentcore-runtime", AGENTCORE_COPY, None)
    assert {p["timed_from"] for p in doc["repeats"][0].values()} == {None}



def test_a_gateways_result_timed_from_the_mark_is_accepted_and_an_sdks_shared_outcomes_too(an_sdk_result):
    doc = an_sdk_result[0]

    def a_gateway(body):
        body["stop"].update(product={"kind": "gateway", "attachment": "its calls to a model", "name": "G"},
                            record=None)
        for part in body["repeats"][0].values():
            part["outcome"] = "stopped"

    assert result.check(mutated(doc, a_gateway))["repeats"][0]["own_calls"]["timed_from"] == "your mark"
    for shared in ("not stopped", "stopped, then succeeded again", "not measured"):
        def reads(body, shared=shared):
            for part in body["repeats"][0].values():
                part["outcome"] = shared
        assert result.check(mutated(doc, reads))
