"""`stop-test gate` (the plan, wave 2, D; Arvaken's 0212): the question it signs is Arvaken's own gate question; it
waits while the agent is not on the map, then asks once more with final=1; and only a yes passes a blocking gate."""
from __future__ import annotations

import json
from argparse import Namespace
from datetime import datetime, timezone

from arvaken_stop_test import gate
from arvaken_stop_test.cli import main

KEY = "arn:aws:kms:eu-central-1:123456789012:key/11111111-2222-3333-4444-555555555555"
ENG = "8e7f6d5c-4b3a-4291-8f0e-123456789abc"
AGENT = "arn:aws:lambda:eu-central-1:123456789012:function:refunds"
AT = datetime(2026, 11, 25, 18, 0, tzinfo=timezone.utc)


def test_the_question_is_arvakens_gate_question():
    q = json.loads(gate.question(key_arn=KEY, engagement=ENG, agent=AGENT, on_no="block", run_ref="build 9", at=AT))
    assert q == {"v": 1, "ask": "gate", "key": KEY, "engagement": ENG, "at": "2026-11-25T18:00:00+00:00",
                 "agent": AGENT, "on_no": "block", "run_ref": "build 9"}


def a_world(answers):
    posted, got = [], []

    def post(url, headers, body):
        posted.append((url, headers, body))
        return 200, json.dumps({"asked": True, "gate": "g", "token": "T" * 43}).encode()

    def get(url):
        got.append(url)
        return answers.pop(0)
    clock = iter(range(0, 100000, 15))
    return posted, got, {"sign": lambda b: b"sig", "post": post, "get": get, "sleep": lambda s: None,
                         "clock": lambda: next(clock), "say": lambda s: None}


def args(on_no="block", wait=600):
    return Namespace(key=KEY, engagement=ENG, agent=AGENT, on_no=on_no, run_ref=None, endpoint="https://ingest.test",
                     app="https://app.test", wait=wait)


def told(answer, verdict, reason="Stoppable on every path we check."):
    return 200, json.dumps({"answered": True, "answer": answer, "verdict": verdict, "reason": reason}).encode()


def test_a_yes_passes_and_a_no_blocks_or_warns(capsys):
    posted, got, over = a_world([told("yes", "stoppable")])
    assert gate.run(args(), **over) == gate.PASSED
    assert posted[0][0] == "https://ingest.test/v1/gate" and got == ["https://app.test/gate/" + "T" * 43]
    assert "Yes: this agent can be stopped. Stoppable on every path we check." in capsys.readouterr().out
    _, _, over = a_world([told("no", "not-stoppable", "If you pressed stop right now, this agent could keep acting through 1 path.")])
    assert gate.run(args("block"), **over) == gate.BLOCKED
    assert gate.SAID_BLOCKED in capsys.readouterr().out
    _, _, over = a_world([told("no", "no-stop-declared", "No stop has been declared for this agent.")])
    assert gate.run(args("warn"), **over) == gate.PASSED
    assert gate.SAID_WARNED in capsys.readouterr().out


def test_it_waits_for_the_map_then_asks_once_more_with_final():
    waiting = (202, json.dumps({"answered": False, "waiting": True}).encode())
    _, got, over = a_world([waiting] * 3 + [told("not determined", None, "This agent is not on your stop map yet.")])
    assert gate.run(args(wait=45), **over) == gate.BLOCKED
    assert got[-1].endswith("?final=1") and not any(u.endswith("?final=1") for u in got[:-1])


def test_no_answer_is_not_determined_and_follows_block_or_warn(capsys):
    def refused(url, headers, body):
        return 403, json.dumps({"asked": False, "reason": "not signed by a key in force"}).encode()
    over = {"sign": lambda b: b"sig", "post": refused}
    assert gate.run(args("block"), **over) == gate.BLOCKED
    assert "Arvaken did not answer (not signed by a key in force)." in capsys.readouterr().out
    assert gate.run(args("warn"), **over) == gate.PASSED


def test_the_command_needs_block_or_warn(capsys):
    try:
        main(["gate", "--key", KEY, "--engagement", ENG, "--agent", AGENT])
    except SystemExit as e:
        assert e.code == 2
    assert "--on-no" in capsys.readouterr().err
