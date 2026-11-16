"""The rule for host stops (D709; host/rule.py): a path reads "stopped, as seen from outside the host" only where the
observer saw it stop and stay stopped, the stop product's own record says it acted, and the host was seen to stay up;
every case that is not all three is not measured, not stopped or stopped-then-back, and never the refusal rule's plain
"stopped" (KH2). Kept apart from the refusal rule (D646, D656, D658): it reads arrivals alone, never a refusal.

Times are seconds since the epoch, by the observer's clock; the mark is M; the window, W, 15 minutes."""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from arvaken_stop_test import sdk, timing
from arvaken_stop_test.host import rule
from arvaken_stop_test.host.rule import HostState
from arvaken_stop_test.result import iso
from arvaken_stop_test.sdk import Record

M = 1_900_000_000.0
W = 900.0
SOURCE = Path(__file__).resolve().parents[1] / "src" / "arvaken_stop_test" / "host" / "rule.py"


def every_second(start: float, stop: float) -> list[float]:
    """A beat a second, from `start` up to `stop` (not including it)."""
    return [start + i for i in range(int(stop - start))]


def rec(at: float | None, *, in_file: bool = True, to_the_second: bool = True, name: str = "ProcessKilled") -> Record:
    return Record(time=iso(at) if at is not None else "yesterday", name=name, sha256="0" * 64, at=at,
                  to_the_second=to_the_second, in_file=in_file)


WITNESS_UP = rule.host_up(every_second(M - 60, M + W + 10), None, M, W)
KILLED = every_second(M - 60, M + 5)         # the copy's calls: through the minute before the mark, then 4 after it


def judge(arrivals=KILLED, *, record=rec(M + 5), up=WITNESS_UP, reports=None):
    return rule.judge(arrivals, mark_at=M, window=W, record=record, up=up, reports=reports)


# -- stopped, with all three -------------------------------------------------------------------------------------------
def test_a_path_that_fell_silent_with_the_products_record_and_the_witness_up_reads_stopped_as_seen_from_outside():
    found = judge()
    assert found.outcome == rule.HOST_STOPPED == "stopped, as seen from outside the host"
    assert found.reason is None
    assert found.last_arrival_after == M + 4 and found.arrivals_after == 4
    assert found.silent_from == M + 5                       # the first beat that did not arrive
    assert found.effect_between == (4.0, 5.0)               # a range, from the mark (D536)
    assert found.fired_source == rule.FROM_THE_MARK
    assert WITNESS_UP.by == rule.BY_WITNESS and WITNESS_UP.witness_silent_from is None


def test_its_outcome_is_never_the_refusal_rules_plain_stopped():
    """KH2: the words are the rule's own, and none of the refusal rule's outcomes is ever given."""
    assert rule.HOST_STOPPED not in (timing.STOPPED, timing.FLAPPED)
    assert rule.HOST_FLAPPED not in (timing.STOPPED, timing.FLAPPED)
    cases = [judge(), judge(every_second(M - 60, M + W)), judge(record=None), judge(up=rule.host_up([], None, M, W)),
             judge([*every_second(M - 60, M + 5), *every_second(M + 60, M + 70)])]
    assert not {f.outcome for f in cases} & {timing.STOPPED, timing.FLAPPED}


def test_the_firing_moment_is_the_mark_even_where_the_products_record_gives_one_to_the_second():
    """D722 (batch 3): a product's record is evidence that it acted, not the clock. The record's time is kept beside
    the result as entered; time to effect is from the mark, by the observer's clock."""
    found = judge(record=rec(M + 3))
    assert found.outcome == rule.HOST_STOPPED
    assert found.effect_between == (4.0, 5.0)               # from M, never from the record's M + 3
    assert found.fired_source == rule.FROM_THE_MARK


def test_its_words_say_when_it_fell_silent_and_the_records_time_as_you_entered_it():
    record = rec(M + 5)
    words = rule.worded(judge(record=record), record)
    assert words.startswith("Stopped within 15 minutes, as seen from outside your host: its calls stopped reaching us "
                            "at ")
    assert rule._clock(M + 5) in words and words.endswith(f"The product's own record shows it acted at {record.time}.")
    assert rule.worded(judge(record=None)) == "not measured"
    assert rule.worded(judge(every_second(M - 60, M + W))) == "not stopped within 15 minutes"


# -- (a): seen to stop, and stay stopped -------------------------------------------------------------------------------
def test_a_path_that_kept_arriving_is_not_stopped():
    assert judge(every_second(M - 60, M + W + 1)).outcome == timing.NOT_STOPPED
    # into the window's last HOLD seconds, then silent: still not stopped
    assert judge(every_second(M - 60, M + W - 10)).outcome == timing.NOT_STOPPED


def test_a_path_that_fell_silent_and_came_back_reads_stopped_then_reached_us_again_never_stopped():
    found = judge([*every_second(M - 60, M + 5), *every_second(M + 60, M + 70)])
    assert found.outcome == rule.HOST_FLAPPED == "stopped, then reached us again"
    assert found.silent_from == M + 5 and found.back_at == M + 60
    assert rule.worded(found).startswith("Stopped, then reached us again: its calls stopped reaching us at ")


def test_a_silence_shorter_than_the_hold_that_ends_in_an_arrival_is_not_a_stop():
    """A gap of a few seconds is the network's: the path is judged by its last arrival."""
    arrivals = [*every_second(M - 60, M + 5), *every_second(M + 20, M + 25)]
    found = judge(arrivals, record=rec(M + 25))
    assert found.outcome == rule.HOST_STOPPED and found.silent_from == M + 25


@pytest.mark.parametrize("arrivals", [
    every_second(M - 10, M + 5),                            # it began less than 30 seconds before the mark
    [*every_second(M - 60, M - 20), *every_second(M - 10, M + 5)],      # a silence in the 30 seconds before it
    [],                                                      # it never reached the observer
])
def test_a_path_that_did_not_reach_us_through_the_30_seconds_before_the_mark_is_not_measured(arrivals):
    found = judge(arrivals)
    assert (found.outcome, found.reason) == (timing.NOT_MEASURED, rule.DID_NOT_WORK)


def test_a_path_with_no_arrival_after_the_mark_is_not_measured():
    """The stop may have acted before the mark, or the host gone down at it: either way it isn't seen to stop."""
    found = judge(every_second(M - 60, M + 1))              # its last arrival is at the mark itself
    assert (found.outcome, found.reason) == (timing.NOT_MEASURED, rule.NOTHING_AFTER)


# -- (b): the product's own record, required (KH1) ---------------------------------------------------------------------
@pytest.mark.parametrize("record, reason", [
    (None, rule.NO_RECORD),
    (rec(M + 5, in_file=False), rule.RECORD_NOT_IN_FILE),
    (rec(None), rule.RECORD_NO_TIME),
    (rec(M + W + 5), rule.RECORD_OUTSIDE),                  # after the window
    (rec(M - 2), rule.RECORD_OUTSIDE),                      # before the mark, past its second
    (rec(M - 120, to_the_second=False), rule.RECORD_OUTSIDE),   # before the mark, past its minute
])
def test_a_path_without_the_products_own_record_from_the_window_is_not_measured(record, reason):
    found = judge(record=record)
    assert (found.outcome, found.reason) == (timing.NOT_MEASURED, reason)


def test_a_record_may_be_as_far_before_the_mark_as_its_own_precision():
    assert judge(record=rec(M - 0.5)).outcome == rule.HOST_STOPPED                      # within its second
    assert judge(record=rec(M - 30, to_the_second=False)).outcome == rule.HOST_STOPPED  # within its minute
    assert not rule.before_the_mark(rec(M - 0.5), M) and rule.before_the_mark(rec(M - 2), M)
    assert not rule.before_the_mark(None, M) and not rule.before_the_mark(rec(None), M)


def test_a_path_that_fell_silent_before_the_record_says_the_product_acted_is_not_measured():
    """Something else silenced it: the stop can't be what did."""
    found = judge(record=rec(M + 20))
    assert (found.outcome, found.reason) == (timing.NOT_MEASURED, rule.SILENT_BEFORE_RECORD)


def test_the_record_is_read_from_your_export_as_the_sdks_is():
    export = b'{"events": [{"time": "2030-03-17T17:46:45Z", "type": "ProcessKilled"}]}'
    record = sdk.record(export, "2030-03-17T17:46:45Z", "ProcessKilled")
    assert record.in_file and record.to_the_second and record.at == M + 5
    assert not sdk.record(export, "2030-03-17T17:46:45Z", "HostIsolated").in_file


# -- (c): the host stayed up (KH3) -------------------------------------------------------------------------------------
def test_with_the_witness_silent_and_no_record_of_the_hosts_state_a_path_is_not_measured_as_the_host_may_be_down():
    """A host or a network that went down silences every path at once; it must never count as stopped."""
    up = rule.host_up(every_second(M - 60, M + 5), None, M, W)
    assert up.by is None and up.witness_silent_from == M + 4
    found = judge(up=up)
    assert found.outcome == timing.NOT_MEASURED
    assert found.reason == rule.HOST_MAY_BE_DOWN.format(time=rule._clock(M + 4))
    assert "your host or its network may have gone down" in found.reason


def test_a_witness_that_never_reached_us_is_no_evidence_the_host_stayed_up():
    up = rule.host_up([], None, M, W)
    assert up.by is None and judge(up=up).outcome == timing.NOT_MEASURED


def test_a_witness_with_a_gap_in_the_window_is_silent_from_its_last_beat_before_the_gap():
    up = rule.host_up([*every_second(M - 60, M + 100), *every_second(M + 110, M + W + 5)], None, M, W)
    assert up.by is None and up.witness_silent_from == M + 99


def test_where_the_witness_fell_silent_the_products_record_of_the_hosts_state_through_the_window_can_show_it_up():
    state = HostState(contained=rec(M + 5, name="HostIsolated"), still=rec(M + W + 60, name="HostStillIsolated"))
    up = rule.host_up(every_second(M - 60, M + 5), state, M, W)
    assert up.by == rule.BY_STATE and up.witness_silent_from == M + 4
    assert judge(up=up).outcome == rule.HOST_STOPPED


@pytest.mark.parametrize("contained, still, reason", [
    (rec(M + 5), rec(M + 300), rule.STATE_SHORT),           # not still contained at the window's end
    (rec(M + 100), rec(M + W + 60), rule.STATE_SHORT),      # contained only after the path fell silent
    (rec(M - 120), rec(M + W + 60), rule.STATE_SHORT),      # contained before the mark
    (rec(M + 5, in_file=False), rec(M + W + 60), rule.STATE_NOT_IN_FILE),
    (rec(M + 5), rec(M + W + 60, in_file=False), rule.STATE_NOT_IN_FILE),
    (rec(None), rec(M + W + 60), rule.STATE_NO_TIME),
])
def test_a_record_of_the_hosts_state_that_does_not_cover_the_window_leaves_the_path_not_measured(contained, still,
                                                                                                  reason):
    up = rule.host_up(every_second(M - 60, M + 5), HostState(contained, still), M, W)
    found = judge(up=up)
    assert (found.outcome, found.reason) == (timing.NOT_MEASURED, reason.format(time=rule._clock(M + 4)))


# -- the model's path (KH7) --------------------------------------------------------------------------------------------
def test_the_models_path_is_not_measured_where_the_probe_kept_reporting_after_its_calls_stopped_working():
    """A model key revoked at the provider fails the call; the host still reports: your stop didn't silence it."""
    found = judge(reports=every_second(M - 60, M + W + 1))
    assert (found.outcome, found.reason) == (timing.NOT_MEASURED, rule.MODEL_STILL_REPORTING)
    assert judge(reports=KILLED).outcome == rule.HOST_STOPPED      # the reports fell silent with it


# -- its parts ---------------------------------------------------------------------------------------------------------
def test_silent_from_finds_where_arrivals_stop_arriving_through_a_stretch():
    assert rule.silent_from(every_second(0, 101), 10, 100) is None
    assert rule.silent_from(every_second(50, 101), 10, 100) == 10        # none near its start
    assert rule.silent_from([*every_second(0, 40), *every_second(60, 101)], 10, 100) == 39
    assert rule.silent_from(every_second(0, 90), 10, 100) == 89          # ended before it did
    assert rule.silent_from([], 10, 100) == 10


def test_a_repeat_that_was_not_timed_is_not_run():
    found = rule.not_run(W, "why")
    assert (found.outcome, found.reason, found.fired_source) == (timing.NOT_RUN, "why", rule.FROM_THE_MARK)
    assert rule.worded(found) == "not run"


def test_the_rule_reads_arrivals_alone_never_a_refusal():
    """Kept apart from the refusal rule: rule.py imports neither refusals.py nor the refusal rule's judge."""
    imported = set()
    for node in ast.walk(ast.parse(SOURCE.read_text(encoding="utf-8"))):
        if isinstance(node, ast.ImportFrom):
            imported |= {f"{node.module}.{a.name}" for a in node.names}
        elif isinstance(node, ast.Import):
            imported |= {a.name for a in node.names}
    assert not any("refusals" in name for name in imported)
    assert "arvaken_stop_test.timing.judge" not in imported and "arvaken_stop_test.sdk.judge" not in imported
    assert rule.LEAST_WINDOW == 15 * 60 and (rule.BEFORE, rule.GAP, rule.HOLD, rule.EVERY) == (30, 3, 30, 1)
