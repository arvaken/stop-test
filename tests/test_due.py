"""`stop-test due` (the plan, wave 2, A, part 2; Arvaken's 0211): the question is the one Arvaken's endpoint reads, signed
with the runner's key, and each answer becomes an exit code a scheduled task can chain on."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from arvaken_stop_test import due
from arvaken_stop_test.cli import main

KEY = f"arn:aws:kms:eu-central-1:123456789012:key/{uuid.uuid4()}"
ENGAGEMENT, AGENT = str(uuid.uuid4()), str(uuid.uuid4())


def answering(status: int, body: dict, seen: list):
    def post(url, headers, data):
        seen.append((url, headers, data))
        return status, json.dumps(body).encode()
    return post


def test_the_question_is_version_ones_shape_asking_due_and_is_what_is_signed():
    seen, signed = [], []
    said = due.ask(key_arn=KEY, engagement=ENGAGEMENT, sign=lambda m: signed.append(m) or b"sig",
                   post=answering(200, {"agents": []}, seen), now=datetime(2026, 11, 25, 18, 0, tzinfo=timezone.utc))
    assert said == {"agents": []}
    [(url, headers, body)] = seen
    assert url == "https://ingest.arvaken.com/v1/due" and signed == [body]
    assert json.loads(body) == {"v": 1, "ask": "due", "key": KEY, "engagement": ENGAGEMENT,
                                "at": "2026-11-25T18:00:00+00:00"}
    assert headers["X-Arvaken-Key"] == KEY and headers["X-Arvaken-Signature"] == "c2ln"


@pytest.mark.parametrize("why", sorted(due.WHY))
def test_a_due_agent_exits_0_and_says_why(why):
    code, line = due.decide({"agents": [{"agent": AGENT, "every_days": 30, "last_run": None, "due": why}]}, AGENT)
    assert code == due.DUE and line == due.SAID_DUE.format(why=due.WHY[why])


def test_an_agent_not_due_or_with_no_schedule_exits_3():
    assert due.decide({"agents": [{"agent": AGENT, "every_days": 7, "last_run": "x", "due": None}]}, AGENT) == \
        (due.NOT_DUE, due.SAID_NOT_DUE)
    other = str(uuid.uuid4())
    assert due.decide({"agents": [{"agent": other, "every_days": 7, "last_run": None, "due": "never run"}]}, AGENT) == \
        (due.NOT_DUE, due.SAID_NO_SCHEDULE)


def test_no_answer_runs_nothing_and_exits_1(capsys):
    args = SimpleNamespace(key=KEY, engagement=ENGAGEMENT, agent=AGENT, endpoint=due.DUE_ENDPOINT)
    code = due.run(args, sign=lambda m: b"s", post=answering(403, {"answered": False, "reason": "not signed by a key in force"}, []))
    assert code == due.NO_ANSWER
    assert capsys.readouterr().out.strip() == due.SAID_NO_ANSWER.format(why="not signed by a key in force")


def test_a_key_that_is_not_a_kms_arn_is_refused_before_anything_is_signed():
    with pytest.raises(ValueError):
        due.ask(key_arn="alias/my-key", engagement=ENGAGEMENT, sign=lambda m: pytest.fail("signed"),
                post=lambda *a: pytest.fail("sent"))


def test_the_command_is_on_the_kits_cli(monkeypatch, capsys):
    monkeypatch.setattr(due, "kms_signer", lambda arn: (lambda m: b"s"))
    monkeypatch.setattr(due, "_post", answering(200, {"agents": [{"agent": AGENT, "every_days": 7, "last_run": None,
                                                                   "due": "never run"}]}, []))
    assert main(["due", "--key", KEY, "--engagement", ENGAGEMENT, "--agent", AGENT]) == 0
    assert capsys.readouterr().out.strip() == due.SAID_DUE.format(why=due.WHY["never run"])
