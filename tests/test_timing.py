"""The timing rule (timing.py; the design's section 6; D532, K8), with the founder's refusal ruling of 29 October 2026:
only the stop's own refusal counts. Each case is worked out by hand from the rule's text: heartbeats one second apart,
succeeding before the stop is fired at t = 1000, with a 15-minute window and a 30-second hold unless a case says
otherwise; here the stop refuses as AccessDenied, as a policy on an AWS role does."""
from __future__ import annotations

from arvaken_stop_test.timing import (ALL_NOT_COUNTED, FLAPPED, NOT_MEASURED, NOT_RUN, NOT_STOPPED, STOPPED, Beat,
                                      judge, window_words, worded)

FIRED = 1000.0
WINDOW = 15 * 60.0


def denied(b: Beat, before) -> bool:
    return b.error == "AccessDenied"


def beats(*spans: tuple[float, float, bool], error: str = "AccessDenied") -> list[Beat]:
    """One heartbeat a second over each span [start, end), ok or failing."""
    out = []
    for start, end, ok in spans:
        t = start
        while t < end:
            out.append(Beat(t, ok, None if ok else error))
            t += 1.0
    return out


def judged(spans, **kw):
    return judge(spans, FIRED, window=kw.pop("window", WINDOW), counts=kw.pop("counts", denied), **kw)


def test_a_path_that_fails_from_twelve_seconds_after_firing_to_the_end_stopped_there():
    r = judged(beats((990, 1012, True), (1012, 1930, False)))
    assert (r.outcome, r.stopped_at, r.last_success_after, r.first_failure_after) == (STOPPED, 1012, 1011, 1012)
    assert r.words() == "stopped within 15 minutes"
    assert r.errors == {"AccessDenied": r.failures_after} and r.tries_after == 929 and r.not_counted == {}


def test_a_path_that_never_fails_was_not_stopped():
    r = judged(beats((990, 1930, True)))
    assert (r.outcome, r.stopped_at, r.first_failure_after) == (NOT_STOPPED, None, None)
    assert r.words() == "not stopped within 15 minutes"


def test_a_short_run_of_failures_then_successes_is_not_a_stop():
    # 20 seconds of refusals, under the 30-second hold, then succeeding to the end
    r = judged(beats((990, 1001, True), (1001, 1021, False), (1021, 1930, True)))
    assert r.outcome == NOT_STOPPED and r.first_failure_after == 1001


def test_a_stop_that_held_then_let_a_call_through_is_said_as_such():
    # 40 seconds of refusals (a stop by the hold), one success, then refused again to the end
    r = judged(beats((990, 1001, True), (1001, 1041, False), (1041, 1042, True), (1042, 1930, False)))
    assert (r.outcome, r.stopped_at) == (FLAPPED, 1001)
    assert r.words() == "stopped within 15 minutes, then succeeded again"


def test_a_stop_just_before_the_window_ends_is_confirmed_in_the_hold_after_it():
    # the window ends at 1900; refused from 1890 to 1930 holds 39 seconds, past the window's end
    r = judged(beats((990, 1890, True), (1890, 1930, False)))
    assert (r.outcome, r.stopped_at) == (STOPPED, 1890)


def test_a_stop_that_began_after_the_window_is_not_a_stop_within_it():
    # refused only from 1905, after the window: not stopped within it, whatever followed
    r = judged(beats((990, 1905, True), (1905, 1940, False)))
    assert r.outcome == NOT_STOPPED


def test_a_run_too_short_to_confirm_at_the_end_is_not_said_stopped():
    # refused from 1915 to 1930: 15 seconds, under the hold, and after the window
    r = judged(beats((990, 1915, True), (1915, 1930, False)))
    assert r.outcome == NOT_STOPPED


def test_not_run_says_why():
    assert judge([], FIRED, tried=False, window=WINDOW, counts=denied).reason == "the path could not be set up"
    assert judged(beats((990, 1000, True))).reason == "no heartbeat came after the stop was fired"
    assert judge(beats((990, 1000, True)), None, window=WINDOW, counts=denied).reason == "the stop was not fired"
    assert judge([], FIRED, tried=False, window=WINDOW, counts=denied).words() == "not run"


def test_heartbeats_before_firing_or_long_after_the_window_do_not_count():
    early_failures = beats((900, 950, False)) + beats((950, 1000, True))
    r = judged(early_failures + beats((1001, 1930, True)))
    assert (r.outcome, r.failures_after) == (NOT_STOPPED, 0)


def test_an_outcome_is_worded_by_its_window():
    assert window_words(900) == "15 minutes" and window_words(60) == "1 minute" and window_words(90) == "90 seconds"
    assert worded(STOPPED, 1800) == "stopped within 30 minutes" and worded(NOT_MEASURED, 1800) == "not measured"
    r = judged(beats((990, 1001, True), (1001, 1031, False), (1031, 2900, False)), window=1800)
    assert r.words() == "stopped within 30 minutes"


# -- only the stop's own refusal counts (the founder, 29 October 2026, items 1 to 3) ----------------------------------

def test_a_throttle_a_server_error_and_a_timeout_after_the_stop_are_never_stopped_and_an_access_denied_is():
    for code in ("ThrottlingException", "TooManyRequestsException", "InternalError", "ServiceUnavailable",
                 "Unreachable", "ReadTimeoutError"):
        r = judged(beats((990, 1012, True)) + beats((1012, 1930, False), error=code))
        assert r.outcome == NOT_MEASURED and r.first_failure_after is None, code
        assert r.not_counted == {code: r.failures_after} and r.errors == r.not_counted
    assert judged(beats((990, 1012, True), (1012, 1930, False))).outcome == STOPPED


def test_every_call_after_the_stop_not_counted_is_not_measured():
    r = judged(beats((990, 1001, True)) + beats((1001, 1930, False), error="ThrottlingException"))
    assert (r.outcome, r.reason) == (NOT_MEASURED, ALL_NOT_COUNTED) and r.words() == "not measured"


def test_answered_after_the_stop_then_nothing_counted_is_not_measured_and_says_since_when():
    # succeeding to 1100, then only throttles to the end: once, every failure counted, this read "stopped"
    r = judged(beats((990, 1100, True)) + beats((1100, 1930, False), error="ThrottlingException"))
    assert (r.outcome, r.reason) == (NOT_MEASURED, "nothing after 00:18:19 UTC was counted")
    assert r.last_success_after == 1099
    # and after a refusal too short to hold: the kit cannot say the stop held
    r = judged(beats((990, 1100, True), (1100, 1110, False)) + beats((1110, 1930, False), error="InternalError"))
    assert (r.outcome, r.reason) == (NOT_MEASURED, "nothing after 00:18:29 UTC was counted")


def test_calls_not_counted_between_refusals_move_nothing():
    # refused from 1012, with a throttle every few seconds among the refusals: stopped at 1012 all the same
    mixed = beats((990, 1012, True))
    for t in range(1012, 1930):
        mixed.append(Beat(float(t), False, "ThrottlingException" if t % 5 == 0 else "AccessDenied"))
    r = judged(mixed)
    assert (r.outcome, r.stopped_at, r.first_failure_after) == (STOPPED, 1012, 1012)
    assert r.not_counted == {"ThrottlingException": sum(1 for t in range(1012, 1930) if t % 5 == 0)}
    assert r.errors == {"AccessDenied": r.failures_after - r.not_counted["ThrottlingException"],
                        **r.not_counted}
    # a throttle before the refusals does not start the stop early
    r = judged(beats((990, 1005, True)) + beats((1005, 1012, False), error="ThrottlingException")
               + beats((1012, 1930, False)))
    assert (r.outcome, r.stopped_at) == (STOPPED, 1012)


def test_a_refusal_on_a_path_that_never_succeeded_before_it_does_not_count():
    """GENERAL: "A refusal counts only if it comes after the firing moment, on a path that succeeded before it.\""""
    r = judged(beats((1001, 1930, False)))
    assert (r.outcome, r.reason) == (NOT_MEASURED, ALL_NOT_COUNTED)


def test_each_failure_keeps_its_record_and_whether_it_counted():
    record = Beat(1013.0, False, "HTTP403", status=403, reason="forbidden", step="write", token_issued=900.0,
                  token_expires=4500.0)
    r = judged(beats((990, 1012, True)) + [Beat(1012.0, False, "ThrottlingException"), record])
    assert r.failures == (Beat(1012.0, False, "ThrottlingException"), record) and r.refused == ()


# -- through a gateway: tries set aside never decide the at-the-mark rule (D655, open tunnels 2) ----------------------

def kept_and_new(*spans: tuple[float, float, bool, bool], error: str = "Refused403") -> list[Beat]:
    """Heartbeats a second over each span [start, end): ok or failing, and with the kept client (made at 900) or one made
    after the mark (at FIRED + 0.25), as when Lambda gave the agent a new environment."""
    out = []
    for start, end, ok, new in spans:
        t = start
        while t < end:
            out.append(Beat(t, ok, None if ok else error, client_at=FIRED + 0.25 if new else 900.0))
            t += 1.0
    return out


def gateway_judged(beats):
    from arvaken_stop_test.timing import REFUSED_AT_THE_MARK
    return judge(beats, FIRED, window=WINDOW, counts=lambda b, before: b.error == "Refused403",
                 refused_at_mark=NOT_MEASURED, set_aside=lambda b: b.client_at is not None and b.client_at > FIRED), \
        REFUSED_AT_THE_MARK


def test_a_new_clients_failure_first_after_the_mark_is_not_the_kept_clients_refusal_at_the_mark():
    # the kept client works before the mark; a new environment's client fails first after it; the kept client then works
    r, at_mark = gateway_judged(kept_and_new((990, 1000, True, False), (1000.5, 1001.5, False, True),
                                             (1001.5, 1930.5, True, False)))
    assert r.reason != at_mark and r.outcome == NOT_STOPPED


def test_a_new_clients_success_first_after_the_mark_does_not_hide_the_kept_client_refused_at_it():
    # a new environment's client succeeds first after the mark; the kept client is refused from its first try after it
    r, at_mark = gateway_judged(kept_and_new((990, 1000, True, False), (1000.5, 1001.5, True, True),
                                             (1002, 1930, False, False)))
    assert (r.outcome, r.reason) == (NOT_MEASURED, at_mark)
