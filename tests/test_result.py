"""The result's format and signature (result.py; the design's section 8; the kit's submission terms, 3.3, 4.2 and 4.4 as
amended by D532)."""
from __future__ import annotations

import copy
import json

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
