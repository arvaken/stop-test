"""The result's format and signature (result.py; the design's section 8; the kit's submission terms, 3.3, 4.2 and 4.4 as
amended by D532); version 2, for a product's control (D561, section 5), and version 1 still taken."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path

import pytest

from arvaken_stop_test import result as r
from arvaken_stop_test.timing import NOT_MEASURED, Beat, judge

FIRED = 1_761_220_000.0
AGENT = {"kind": "aws-lambda-function", "runtime": "python3.12", "memory_mb": 128, "private_network": False,
         "ref": "arn:aws:lambda:eu-central-1:111122223333:function:arvaken-stop-test-r1-agent",
         "role_ref": "arn:aws:iam::111122223333:role/arvaken-stop-test-r1-agent"}


def a_result(**over) -> dict:
    stopped = [Beat(FIRED + 1 + i, i < 5, None if i < 5 else "AccessDenied") for i in range(120)]
    open_net = [Beat(FIRED + 1 + i, True) for i in range(120)]
    counts = lambda b, before: b.error == "AccessDenied"  # noqa: E731 - a policy on a role refuses so
    paths = {"own_calls": judge(stopped, FIRED, window=60, counts=counts),
             "open_internet": judge(open_net, FIRED, window=60, counts=counts)}
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
                   "first_refused_after": "2025-10-23T11:46:46.000Z", "outcome": "stopped"}
    assert doc["format"] == "stop-test-result/2"
    assert (doc["stop"]["product"], doc["run"]["via"]) == (None, None)
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
# Version 2: exactly what the kit's terms v4 (D595; v2 until D615, v3 until D625) add, and nothing more: the product's
# kind and how it is attached, readable; its name and the gateway's address, identifying. A field with no phrase here
# fails below.
V2_READABLE = {
    "for a product's control, the kind of product and how it is attached": {"stop.product.kind",
                                                                             "stop.product.attachment"},
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


def test_version_2_holds_exactly_version_1_and_the_product_and_the_gateways_address():
    assert r.SHAPE == {**r.SHAPE_V1, "run": (*r.SHAPE_V1["run"], "via"), "stop": (*r.SHAPE_V1["stop"], "product"),
                       "stop.product": ("kind", "attachment", "name")}
    assert r.SHAPE["repeat.path"] == ("fired_at", "last_success_after", "first_refused_after", "outcome")


# A gateway's address as the kit keeps it (D595; the legal track's suggestion): its scheme, host and port alone, the
# port as given; any user name, password, path, query and fragment dropped.
@pytest.mark.parametrize(("given", "kept"), [
    ("https://user:pass@gw.example:8443/p?token=x#f", "https://gw.example:8443"),
    ("https://user:pass@gw.example:8443", "https://gw.example:8443"),
    ("http://only-a-user@10.0.0.5:3128", "http://10.0.0.5:3128"),
    ("https://user:p@ss:w@rd@gw.example", "https://gw.example"),        # an "@" left in a password, unencoded
    ("https://us%40er:p%3Ass@[2001:db8::1]:8443/", "https://[2001:db8::1]:8443"),
    ("http://gw.example/?key=x", "http://gw.example"),                  # no port given: none kept
    ("https://gw.example:8443", "https://gw.example:8443"),
])
def test_a_gateways_address_is_kept_as_its_scheme_host_and_port_alone(given, kept):
    assert r.gateway_address(given) == kept and r.is_gateway_address(kept)
    assert r.is_gateway_address(given) is (given == kept)


GATEWAY = {"kind": "gateway", "attachment": "all its outbound traffic", "name": "Egress <gateway> & co."}


def a_gateway_result(**over) -> dict:
    """A run through a gateway, as the kit's aws/run.py writes one: a product's control, fired by your own trigger, from
    your mark; the key's path failed through the gateway before the stop, and the own calls failed through it after
    the mark, which counts nothing until the founder's ruling on a gateway's refusal (30 October 2026) is built."""
    failed = [Beat(FIRED - 1, True)] + [Beat(FIRED + 1 + i, i < 5, None if i < 5 else "ProxyConnectionError")
                                        for i in range(120)]
    paths = {"own_calls": judge(failed, FIRED, window=60, counts=lambda b, before: False),
             "outside_key": judge([], FIRED, window=60, tried=False, untried="not measured",
                                  counts=lambda b, before: False)}
    fields = dict(stop_kind="a product's control", fired_by="your own trigger", stop_ref="", product=GATEWAY,
                  via="https://user:pass@gw.example:8443/p?token=x#f", repeats=[(FIRED, paths)])
    fields.update(over)
    return a_result(**fields)


def test_a_result_through_a_gateway_keeps_its_product_and_its_address_as_scheme_host_and_port():
    doc = r.sign(a_gateway_result(), r.new_key())
    assert r.check(json.loads(json.dumps(doc))) == doc and doc["format"] == "stop-test-result/2"
    assert doc["stop"] == {"kind": "a product's control", "fired_by": "your own trigger", "ref": "", "product": GATEWAY}
    assert doc["run"]["via"] == "https://gw.example:8443"
    assert all(s not in json.dumps(doc) for s in ("pass", "token", "/p?", "#f"))
    assert doc["repeats"][0]["outside_key"] == {"fired_at": "2025-10-23T11:46:40.000Z", "last_success_after": None,
                                                "first_refused_after": None, "outcome": "not measured"}
    assert doc["repeats"][0]["own_calls"]["outcome"] == "not measured"


def _resigned(doc: dict, change) -> dict:
    """The result changed, then signed again: what the signature cannot catch, the shape and its rules must."""
    bad = copy.deepcopy(doc)
    change(bad)
    return r.sign(bad, r.new_key())


@pytest.mark.parametrize("change", [
    lambda d: d["run"].__setitem__("via", "https://user:pass@gw.example:8443"),          # credentials in the address
    lambda d: d["run"].__setitem__("via", "https://gw.example:8443/p"),                   # a path
    lambda d: d["run"].__setitem__("via", "https://gw.example:8443?token=x"),             # a query
    lambda d: d["run"].__setitem__("via", "https://gw.example:8443#f"),                   # a fragment
    lambda d: d["run"].__setitem__("via", "socks5://gw.example:1080"),
    lambda d: d["run"].__setitem__("via", "https://:8443"),                               # no host
    lambda d: d["run"].__setitem__("via", 8443),
    lambda d: d["stop"]["product"].__setitem__("kind", "firewall"),
    lambda d: d["stop"]["product"].__setitem__("attachment", "its calls to a model, mostly"),
    lambda d: d["stop"]["product"].__setitem__("attachment", "inside its code"),          # another kind's attachment
    lambda d: d["stop"]["product"].__setitem__("name", "x" * 201),
    lambda d: d["stop"]["product"].__setitem__("name", ""),
    lambda d: d["stop"]["product"].__setitem__("vendor", "anyone"),                        # a field the format lacks
    lambda d: d["stop"].__setitem__("product", None),                                      # a product's control, none
    lambda d: d["stop"].__setitem__("kind", "policy on a role"),                           # a product, another kind
    lambda d: d["stop"].__setitem__("fired_by", "the kit"),
    lambda d: d["stop"]["product"].__setitem__("kind", "in-agent SDK") or
    d["stop"]["product"].__setitem__("attachment", "inside its code"),                     # an address, but no gateway
    lambda d: d["run"].__delitem__("via"),
    # the two fields version 2 no longer has (the kit's terms v4 list neither): refused wherever they are
    lambda d: d["run"].__setitem__("timing_from", "your mark"),
    lambda d: d["repeats"][0]["outside_key"].__setitem__("failed_before_stop", True),
    lambda d: d["repeats"][0]["own_calls"].__setitem__("failed_before_stop", False),
])
def test_a_version_2_result_that_breaks_its_rules_is_refused_even_signed_again(change):
    doc = r.sign(a_gateway_result(), r.new_key())
    with pytest.raises(r.NotAResult):
        r.check(_resigned(doc, change))


def test_a_result_of_a_cloud_stop_is_version_2_with_no_product_and_a_path_failed_before_the_stop_not_run():
    paths = {"outside_key": judge([], FIRED, window=60, tried=False, counts=lambda b, before: False)}
    doc = r.sign(a_result(repeats=[(FIRED, paths)]), r.new_key())
    assert r.check(doc)["repeats"][0]["outside_key"]["outcome"] == "not run"
    for change in (lambda d: d["run"].__setitem__("via", "https://gw.example:8443"),
                   lambda d: d["run"].__setitem__("timing_from", "the kit's firing call"),
                   lambda d: d["repeats"][0]["outside_key"].__setitem__("failed_before_stop", True)):
        with pytest.raises(r.NotAResult):
            r.check(_resigned(doc, change))
    own = r.sign(a_result(fired_by="your own trigger", stop_ref=""), r.new_key())
    assert set(r.check(own)["run"]) == set(r.SHAPE["run"])


V1 = Path(__file__).parent / "data" / "v1-result-0.2.1.json"


def test_a_version_1_result_as_the_kit_wrote_it_to_0_2_1_still_checks():
    """The file was written by the kit at v0.2.1 (c40c1b2), against test_aws_run.py's fake AWS, before version 2."""
    doc = json.loads(V1.read_text(encoding="utf-8"))
    assert doc["format"] == "stop-test-result/1" and doc["kit"]["version"] == "0.2.1"
    assert r.check(doc) == doc
    assert set(doc["run"]) == set(r.SHAPE_V1["run"]) and "product" not in json.dumps(doc)


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


def test_not_measured_is_an_outcome_a_result_may_give():
    doc = r.sign(a_result(), r.new_key())
    bad = copy.deepcopy(doc)
    bad["repeats"][0]["own_calls"]["outcome"] = NOT_MEASURED
    with pytest.raises(r.NotAResult, match="signature"):             # an outcome the rule gives: only the signature
        r.check(bad)


@pytest.mark.skipif(not os.environ.get("STOP_TEST_RELEASE"), reason="checked when a release is made (release.yml)")
def test_a_release_never_writes_not_measured_in_a_stop_test_result_1():
    """No kit to 0.2.1 gave "not measured", and Arvaken's record refuses it in a stop-test-result/1 (the console's 0185):
    a release that gives it writes a later format."""
    assert NOT_MEASURED not in r.OUTCOMES or r.FORMAT != r.FORMAT_V1, \
        "this kit gives 'not measured' but writes stop-test-result/1: release it with a later format"


# -- the failure record (D646, item 4: the founder, 29 October 2026) ---------------------------------------------------

def test_a_failure_record_holds_every_field_or_this_test_fails():
    """The founder's words: "Every failed call in every run records its full error code, the provider's status and
    reason fields, and the token's issue and expiry times where a token is used. Add a test that fails if any of these
    is missing from a failure record." """
    google = Beat(FIRED + 9, False, "HTTP401", status=401, reason="authError", step="write", token_issued=FIRED - 600,
                  token_expires=FIRED + 3000)
    aws = Beat(FIRED + 9, False, "AccessDenied", status=403)
    for b, counted in ((google, True), (aws, False)):
        record = r.failure_record(b, counted)
        assert tuple(record) == r.FAILURE_RECORD and set(record) == {
            "at", "step", "code", "status", "reason", "reason_given", "provider_status", "token_issued",
            "token_expires", "counted"}
    assert r.failure_record(google, True) == {
        "at": "2025-10-23T11:46:49.000Z", "step": "write", "code": "HTTP401", "status": 401, "reason": "authError",
        "reason_given": True, "provider_status": None, "token_issued": "2025-10-23T11:36:40.000Z",
        "token_expires": "2025-10-23T12:36:40.000Z", "counted": True}
    # S3's errors give no reason: the reason is empty, and the record says none was given
    assert (r.failure_record(aws, False)["reason"], r.failure_record(aws, False)["reason_given"]) == (None, False)
    found = judge([Beat(FIRED - 1, True), aws, google], FIRED, window=60, counts=lambda b, before: b.error == "HTTP401")
    assert [x["counted"] for x in r.failure_records(found)] == [False, True]
