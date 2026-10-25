"""The timing rule (timing.py; the design's section 6; D532, K8). Each case is worked out by hand from the rule's text:
heartbeats one second apart from the moment the stop is fired at t = 1000, with a 15-minute window and a 30-second
hold unless a case says otherwise."""
from __future__ import annotations

from arvaken_stop_test.timing import (FLAPPED, NOT_RUN, NOT_STOPPED, STOPPED, Beat, judge, window_words, worded)

FIRED = 1000.0
WINDOW = 15 * 60.0


def beats(*spans: tuple[float, float, bool], error: str = "AccessDenied") -> list[Beat]:
    """One heartbeat a second over each span [start, end), ok or failing."""
    out = []
    for start, end, ok in spans:
        t = start
        while t < end:
            out.append(Beat(t, ok, None if ok else error))
            t += 1.0
    return out


def test_a_path_that_fails_from_twelve_seconds_after_firing_to_the_end_stopped_there():
    r = judge(beats((990, 1012, True), (1012, 1930, False)), FIRED, window=WINDOW)
    assert (r.outcome, r.stopped_at, r.last_success_after, r.first_failure_after) == (STOPPED, 1012, 1011, 1012)
    assert r.words() == "stopped within 15 minutes"
    assert r.errors == {"AccessDenied": r.failures_after} and r.tries_after == 929


def test_a_path_that_never_fails_was_not_stopped():
    r = judge(beats((990, 1930, True)), FIRED, window=WINDOW)
    assert (r.outcome, r.stopped_at, r.first_failure_after) == (NOT_STOPPED, None, None)
    assert r.words() == "not stopped within 15 minutes"


def test_a_short_run_of_failures_then_successes_is_not_a_stop():
    # 20 seconds of failures, under the 30-second hold, then succeeding to the end
    r = judge(beats((1001, 1021, False), (1021, 1930, True)), FIRED, window=WINDOW)
    assert r.outcome == NOT_STOPPED and r.first_failure_after == 1001


def test_a_stop_that_held_then_let_a_call_through_is_said_as_such():
    # 40 seconds of failures (a stop by the hold), one success, then failing again to the end
    r = judge(beats((1001, 1041, False), (1041, 1042, True), (1042, 1930, False)), FIRED, window=WINDOW)
    assert (r.outcome, r.stopped_at) == (FLAPPED, 1001)
    assert r.words() == "stopped within 15 minutes, then succeeded again"


def test_a_stop_just_before_the_window_ends_is_confirmed_in_the_hold_after_it():
    # the window ends at 1900; failing from 1890 to 1930 holds 39 seconds, past the window's end
    r = judge(beats((1001, 1890, True), (1890, 1930, False)), FIRED, window=WINDOW)
    assert (r.outcome, r.stopped_at) == (STOPPED, 1890)


def test_a_stop_that_began_after_the_window_is_not_a_stop_within_it():
    # failing only from 1905, after the window: not stopped within it, whatever followed
    r = judge(beats((1001, 1905, True), (1905, 1940, False)), FIRED, window=WINDOW)
    assert r.outcome == NOT_STOPPED


def test_a_run_too_short_to_confirm_at_the_end_is_not_said_stopped():
    # failing from 1915 to 1930: 15 seconds, under the hold, and after the window
    r = judge(beats((1001, 1915, True), (1915, 1930, False)), FIRED, window=WINDOW)
    assert r.outcome == NOT_STOPPED


def test_not_run_says_why():
    assert judge([], FIRED, tried=False, window=WINDOW).reason == "the path could not be set up"
    assert judge(beats((990, 1000, True)), FIRED, window=WINDOW).reason == "no heartbeat came after the stop was fired"
    assert judge(beats((990, 1000, True)), None, window=WINDOW).reason == "the stop was not fired"
    assert judge([], FIRED, tried=False, window=WINDOW).words() == "not run"


def test_heartbeats_before_firing_or_long_after_the_window_do_not_count():
    early_failures = beats((900, 1000, False))
    r = judge(early_failures + beats((1001, 1930, True)), FIRED, window=WINDOW)
    assert (r.outcome, r.failures_after) == (NOT_STOPPED, 0)


def test_errors_are_counted_by_code_alone():
    mixed = beats((1001, 1011, False), error="AccessDenied") + beats((1011, 1061, False), error="Timeout")
    r = judge(mixed, FIRED, window=WINDOW)
    assert r.outcome == STOPPED and r.errors == {"AccessDenied": 10, "Timeout": 50}


def test_an_outcome_is_worded_by_its_window():
    assert window_words(900) == "15 minutes" and window_words(60) == "1 minute" and window_words(90) == "90 seconds"
    assert worded(STOPPED, 1800) == "stopped within 30 minutes"
    r = judge(beats((1001, 1031, False), (1031, 2900, False)), FIRED, window=1800)
    assert r.words() == "stopped within 30 minutes"
