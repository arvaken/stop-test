"""The kit's Google calls and the customer's tokens (google/api.py). gcloud gives back the token it holds, which may be
most of an hour old, so a run asks for one again every few minutes, and at once when Google refuses one: a run kept
one from its start for 50 minutes and ran out 23 minutes in (25 October 2026)."""
from __future__ import annotations

import io
import urllib.error

import pytest

from arvaken_stop_test.google import api


class Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


def test_a_token_is_asked_for_again_after_a_few_minutes_and_once_forgotten():
    clock, asked = Clock(), []
    tokens = api.Tokens(run=lambda args: asked.append(args) or f"t{len(asked)}", clock=clock)
    assert [tokens.access(), tokens.access()] == ["t1", "t1"]
    clock.t += api.TOKEN_LIFE
    assert tokens.access() == "t2"
    tokens.forget("access")
    assert tokens.access() == "t3"
    assert api.TOKEN_LIFE <= 5 * 60 and len(asked) == 3


class Answers:
    """urlopen, answering each request in turn: an HTTP status to refuse with, or a body to return."""

    def __init__(self, *answers: int | bytes) -> None:
        self.answers, self.seen = list(answers), []

    def __call__(self, request, timeout):
        self.seen.append(request.get_header("Authorization"))
        a = self.answers.pop(0)
        if isinstance(a, int):
            raise urllib.error.HTTPError(request.full_url, a, "refused", {},
                                         io.BytesIO(b'{"error": {"status": "UNAUTHENTICATED"}}'))
        return io.BytesIO(a)


@pytest.fixture
def google():
    asked = []
    tokens = api.Tokens(run=lambda args: asked.append(args) or f"t{len(asked)}", clock=Clock())
    return api.Google("my-test-project", "europe-west3", tokens=tokens)


def test_a_call_google_refuses_as_unauthenticated_is_made_once_more_with_a_new_token(google, monkeypatch):
    answers = Answers(401, b'{"ok": true}')
    monkeypatch.setattr(api.urllib.request, "urlopen", answers)
    assert google.call("POST", "https://iam.googleapis.com/v1/x:enable", {}) == {"ok": True}
    assert answers.seen == ["Bearer t1", "Bearer t2"]


def test_a_second_refusal_is_raised_and_nothing_is_asked_a_third_time(google, monkeypatch):
    answers = Answers(401, 401, b"{}")
    monkeypatch.setattr(api.urllib.request, "urlopen", answers)
    with pytest.raises(api.GoogleError, match="401 UNAUTHENTICATED"):
        google.call("GET", "https://iam.googleapis.com/v1/x")
    assert answers.seen == ["Bearer t1", "Bearer t2"]


def test_any_other_refusal_is_raised_at_once(google, monkeypatch):
    answers = Answers(403, b"{}")
    monkeypatch.setattr(api.urllib.request, "urlopen", answers)
    with pytest.raises(api.GoogleError, match="403"):
        google.call("GET", "https://iam.googleapis.com/v1/x")
    assert answers.seen == ["Bearer t1"]
