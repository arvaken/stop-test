"""The result's format and signature (result.py; the design's section 8; the kit's submission terms, 3.3, 4.2 and 4.4 as
amended by D532); version 2, for a product's control (D561, section 5), and version 1 still taken."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from arvaken_stop_test import result as r
from arvaken_stop_test.timing import Beat, judge

FIRED = 1_761_220_000.0
AGENT = {"kind": "aws-lambda-function", "runtime": "python3.12", "memory_mb": 128, "private_network": False,
         "ref": "arn:aws:lambda:eu-central-1:111122223333:function:arvaken-stop-test-r1-agent",
         "role_ref": "arn:aws:iam::111122223333:role/arvaken-stop-test-r1-agent"}


def a_result(**over) -> dict:
    stopped = [Beat(FIRED + 1 + i, i < 5, None if i < 5 else "AccessDenied") for i in range(120)]
    open_net = [Beat(FIRED + 1 + i, True) for i in range(120)]
    paths = {"own_calls": judge(stopped, FIRED, window=60), "open_internet": judge(open_net, FIRED, window=60)}
    fields = dict(kit_version="0.1.0", cloud="aws", region="eu-central-1", began_at=FIRED - 60, ended_at=FIRED + 200,
                  window=60, clock_gap_ms=12, calls=240, left_behind=[], stop_kind="policy on a role",
                  fired_by="the kit", stop_ref="arn:aws:iam::111122223333:policy/agent-stop", agent=AGENT,
                  repeats=[(FIRED, paths)])
    fields.update(over)
    return r.build(**fields)


def test_a_signed_result_checks_and_says_what_was_found():
    doc = r.sign(a_result(), r.new_key())
    assert r.check(json.loads(json.dumps(doc))) == doc                 # as it travels
    own = doc["repeats"][0]["own_calls"]
    assert own == {"fired_at": "2025-10-23T11:46:40.000Z", "last_success_after": "2025-10-23T11:46:45.000Z",
                   "first_refused_after": "2025-10-23T11:46:46.000Z", "outcome": "stopped",
                   "failed_before_stop": False}
    assert doc["format"] == "stop-test-result/2"
    assert (doc["stop"]["product"], doc["run"]["via"]) == (None, None)
    assert doc["run"]["timing_from"] == "the kit's firing call"
    assert doc["repeats"][0]["open_internet"]["outcome"] == "not stopped"


@pytest.mark.parametrize("change", ["an outcome", "a time", "the window", "the key", "a field added"])
def test_any_change_after_signing_fails_the_signature_or_the_shape(change):
    doc = r.sign(a_result(), r.new_key())
    bad = copy.deepcopy(doc)
    if change == "an outcome":
        bad["repeats"][0]["own_calls"]["outcome"] = "not stopped"
    elif change == "a time":
        bad["repeats"][0]["own_calls"]["first_refused_after"] = "2025-10-23T11:46:50.000Z"
    elif change == "the window":
        bad["run"]["window_seconds"] = 900
    elif change == "the key":
        bad["signature"]["public_key"] = r.sign(a_result(), r.new_key())["signature"]["public_key"]
    elif change == "a field added":
        bad["agent"]["prompt"] = "anything"
    with pytest.raises(r.NotAResult):
        r.check(bad)


def test_something_left_is_said_and_named():
    doc = r.sign(a_result(left_behind=["arvaken-stop-test-r1-bucket"]), r.new_key())
    assert (doc["run"]["left_anything"], doc["run"]["left_behind"]) == (True, ["arvaken-stop-test-r1-bucket"])
    bad = copy.deepcopy(doc)
    bad["run"]["left_anything"] = False
    with pytest.raises(r.NotAResult):
        r.check(bad)


# The terms' 4.4 as amended (D532, C), phrase by phrase, and the fields that hold each; and 4.2's identifying parts.
# A field added to the format with no phrase here fails below: the format cannot grow past the terms.
TERMS_READABLE = {
    "the kind of stop and how it was fired": {"stop.kind", "stop.fired_by"},
    "the kind of test agent, its runtime, memory and region, whether it ran in a private network":
        {"agent.kind", "agent.runtime", "agent.memory_mb", "region", "agent.private_network"},
    "the cloud": {"cloud"},
    "the kit's version": {"kit.version"},
    "when the test began and ended, its window and repeats": {"run.began_at", "run.ended_at", "run.window_seconds",
                                                             "run.repeats"},
    "how far apart the clocks it read were": {"run.clock_gap_ms"},
    "how many calls it made": {"run.calls"},
    "whether anything it made was left after it ended": {"run.left_anything"},
    "for each path, when the stop was fired, when a call last succeeded after it, when one was first refused, and "
    "the outcome": {"repeat.path.fired_at", "repeat.path.last_success_after", "repeat.path.first_refused_after",
                    "repeat.path.outcome"},
    "the result's signature, with the public half of the key that made it": {"signature.alg", "signature.public_key",
                                                                            "signature.value"},
}
CONTAINERS = {"format", "kit", "run", "stop", "agent", "repeats", "signature"}
# Version 2 (D561, section 5): what it adds, each as the phrase the terms' 4.4 does not yet hold, for the legal track's
# reading (the design's section 8) before a release; and 4.2's new identifying parts, the product's name and the
# gateway's address. Each must be named here, or the test below fails.
V2_READABLE = {
    "for a product's control, the kind of product and how it is attached": {"stop.product.kind",
                                                                             "stop.product.attachment"},
    "where each path's timing starts": {"run.timing_from"},
    "for each path, whether it failed before the stop": {"repeat.path.failed_before_stop"},
}
V2_IDENTIFYING = {"stop.product.name", "run.via"}


def _fields(shape) -> set[str]:
    return {(f"{where}.{k}" if where else k) for where, keys in shape.items() for k in keys} - CONTAINERS


def test_every_field_is_a_phrase_of_the_terms_or_an_identifying_part_and_nothing_else():
    """Version 1 exactly as the terms' 4.4 and 4.2 hold it; version 2 with what it adds named, each part once."""
    named_v1 = set().union(*TERMS_READABLE.values()) | set(r.IDENTIFYING_V1)
    v1 = _fields(r.SHAPE_V1)
    assert v1 == named_v1, (sorted(v1 - named_v1), sorted(named_v1 - v1))
    readable = set().union(*TERMS_READABLE.values(), *V2_READABLE.values())
    fields = _fields(r.SHAPE) - {"stop.product"}                  # a container, or null
    assert fields == readable | set(r.IDENTIFYING), (sorted(fields - readable - set(r.IDENTIFYING)),)
    assert set(r.IDENTIFYING) == set(r.IDENTIFYING_V1) | V2_IDENTIFYING
    assert not readable & set(r.IDENTIFYING)


# A gateway's address, with any user name and password taken out (D595): what is before the last "@" of its authority.
@pytest.mark.parametrize(("given", "kept"), [
    ("https://user:pass@gw.example:8443", "https://gw.example:8443"),
    ("http://only-a-user@10.0.0.5:3128", "http://10.0.0.5:3128"),
    ("https://user:p@ss:w@rd@gw.example", "https://gw.example"),        # an "@" left in a password, unencoded
    ("https://us%40er:p%3Ass@[2001:db8::1]:8443/", "https://[2001:db8::1]:8443/"),
    ("https://gw.example:8443", "https://gw.example:8443"),
])
def test_a_gateways_address_is_kept_without_a_user_name_or_password(given, kept):
    assert r.without_credentials(given) == kept and not r.has_credentials(kept)


GATEWAY = {"kind": "gateway", "attachment": "all its outbound traffic", "name": "Egress <gateway> & co."}


def a_gateway_result(**over) -> dict:
    """A run through a gateway, as the kit's aws/run.py writes one: a product's control, fired by your own trigger, from
    your mark; the key's path failed through the gateway before the stop."""
    stopped = [Beat(FIRED + 1 + i, i < 5, None if i < 5 else "ProxyConnectionError") for i in range(120)]
    paths = {"own_calls": judge(stopped, FIRED, window=60),
             "outside_key": judge([], FIRED, window=60, tried=False, untried="not measured")}
    fields = dict(stop_kind="a product's control", fired_by="your own trigger", stop_ref="", product=GATEWAY,
                  via="https://user:pass@gw.example:8443", repeats=[(FIRED, paths)])
    fields.update(over)
    return a_result(**fields)


def test_a_result_through_a_gateway_keeps_its_product_and_its_address_without_credentials():
    doc = r.sign(a_gateway_result(), r.new_key())
    assert r.check(json.loads(json.dumps(doc))) == doc and doc["format"] == "stop-test-result/2"
    assert doc["stop"] == {"kind": "a product's control", "fired_by": "your own trigger", "ref": "", "product": GATEWAY}
    assert doc["run"]["via"] == "https://gw.example:8443" and "pass" not in json.dumps(doc)
    assert doc["run"]["timing_from"] == "your mark"
    assert doc["repeats"][0]["outside_key"] == {"fired_at": "2025-10-23T11:46:40.000Z", "last_success_after": None,
                                                "first_refused_after": None, "outcome": "not measured",
                                                "failed_before_stop": True}
    assert doc["repeats"][0]["own_calls"]["outcome"] == "stopped"


def _resigned(doc: dict, change) -> dict:
    """The result changed, then signed again: what the signature cannot catch, the shape and its rules must."""
    bad = copy.deepcopy(doc)
    change(bad)
    return r.sign(bad, r.new_key())


@pytest.mark.parametrize("change", [
    lambda d: d["run"].__setitem__("via", "https://user:pass@gw.example:8443"),          # credentials in the address
    lambda d: d["stop"]["product"].__setitem__("kind", "firewall"),
    lambda d: d["stop"]["product"].__setitem__("attachment", "its calls to a model, mostly"),
    lambda d: d["stop"]["product"].__setitem__("attachment", "inside its code"),          # another kind's attachment
    lambda d: d["stop"]["product"].__setitem__("name", "x" * 201),
    lambda d: d["stop"]["product"].__setitem__("name", ""),
    lambda d: d["stop"]["product"].__setitem__("vendor", "anyone"),                        # a field the format lacks
    lambda d: d["stop"].__setitem__("product", None),                                      # a product's control, none
    lambda d: d["stop"].__setitem__("kind", "policy on a role"),                           # a product, another kind
    lambda d: d["stop"].__setitem__("fired_by", "the kit"),
    lambda d: d["run"].__setitem__("timing_from", "the kit's firing call"),
    lambda d: d["stop"]["product"].__setitem__("kind", "in-agent SDK") or
    d["stop"]["product"].__setitem__("attachment", "inside its code"),                     # an address, but no gateway
    lambda d: d["repeats"][0]["outside_key"].__setitem__("outcome", "stopped"),            # failed before, "stopped"
    lambda d: d["repeats"][0]["outside_key"].__setitem__("outcome", "not run"),
    lambda d: d["repeats"][0]["own_calls"].__setitem__("outcome", "not measured"),         # worked, "not measured"
    lambda d: d["repeats"][0]["own_calls"].__setitem__("failed_before_stop", "no"),
    lambda d: d["run"].__delitem__("via"),
])
def test_a_version_2_result_that_breaks_its_rules_is_refused_even_signed_again(change):
    doc = r.sign(a_gateway_result(), r.new_key())
    with pytest.raises(r.NotAResult):
        r.check(_resigned(doc, change))


def test_a_result_of_a_cloud_stop_is_version_2_with_no_product_and_a_path_failed_before_the_stop_not_run():
    paths = {"outside_key": judge([], FIRED, window=60, tried=False)}
    doc = r.sign(a_result(repeats=[(FIRED, paths)]), r.new_key())
    assert r.check(doc)["repeats"][0]["outside_key"]["outcome"] == "not run"
    assert doc["repeats"][0]["outside_key"]["failed_before_stop"] is True
    for change in (lambda d: d["repeats"][0]["outside_key"].__setitem__("outcome", "not measured"),
                   lambda d: d["run"].__setitem__("via", "https://gw.example:8443"),
                   lambda d: d["run"].__setitem__("timing_from", "your mark")):
        with pytest.raises(r.NotAResult):
            r.check(_resigned(doc, change))
    own = r.sign(a_result(fired_by="your own trigger", stop_ref=""), r.new_key())
    assert r.check(own)["run"]["timing_from"] == "the change the kit saw"


V1 = Path(__file__).parent / "data" / "v1-result-0.2.1.json"


def test_a_version_1_result_as_the_kit_wrote_it_to_0_2_1_still_checks():
    """The file was written by the kit at v0.2.1 (c40c1b2), against test_aws_run.py's fake AWS, before version 2."""
    doc = json.loads(V1.read_text(encoding="utf-8"))
    assert doc["format"] == "stop-test-result/1" and doc["kit"]["version"] == "0.2.1"
    assert r.check(doc) == doc
    assert set(doc["run"]) == set(r.SHAPE_V1["run"]) and "failed_before_stop" not in json.dumps(doc)


@pytest.mark.parametrize("change", [
    lambda d: d["repeats"][0]["outside_key"].__setitem__("outcome", "not measured"),       # version 2's outcome
    lambda d: d["repeats"][0]["outside_key"].__setitem__("failed_before_stop", True),
    lambda d: d["run"].__setitem__("via", None) or d["run"].__setitem__("timing_from", "the kit's firing call"),
    lambda d: d["stop"].__setitem__("product", None),
    lambda d: d.__setitem__("format", "stop-test-result/2"),                               # a v1 body called v2
    lambda d: d.__setitem__("format", "stop-test-result/3"),
])
def test_a_version_1_result_holds_its_own_shape_and_nothing_of_version_2(change):
    doc = json.loads(V1.read_text(encoding="utf-8"))
    bad = copy.deepcopy(doc)
    change(bad)
    with pytest.raises(r.NotAResult):
        r.check(bad)
    with pytest.raises(r.NotAResult):                                  # nor once signed again
        r.check(r.sign(bad, r.new_key()))
