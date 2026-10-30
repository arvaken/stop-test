"""The result's format and signature (result.py; the design's section 8; the kit's submission terms, 3.3, 4.2 and 4.4 as
amended by D532)."""
from __future__ import annotations

import copy
import json
import os

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


def test_every_field_is_a_phrase_of_the_terms_or_an_identifying_part_and_nothing_else():
    fields = {(f"{where}.{k}" if where else k) for where, keys in r.SHAPE.items() for k in keys} - CONTAINERS
    named = set().union(*TERMS_READABLE.values()) | set(r.IDENTIFYING)
    assert fields == named, (sorted(fields - named), sorted(named - fields))
    assert not set().union(*TERMS_READABLE.values()) & set(r.IDENTIFYING)


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
