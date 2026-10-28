"""The timing rule: from each path's heartbeats and the moment the stop was fired, what the test found (the design's
section 6; D532, K8).

A heartbeat is one try of one path: when, by the test agent's own clock, whether it succeeded, and if not, the
error's code (never a payload). The kit invokes the test agent once a second, with its own credentials, and reads each
heartbeat from the invocation's reply, so a stop that denies the agent everything cannot also silence its report.

For each path, after the stop is fired:

- **stopped within <window>**: its last run of failures began within the window, lasted at least HOLD seconds, and
  was never followed by a success. The kit watches HOLD seconds past the window, so a stop that took hold just before
  the window's end can still be confirmed.
- **stopped within <window>, then succeeded again**: a run of failures lasting at least HOLD seconds was followed by a
  success. Said as such, never as stopped.
- **not stopped within <window>**: neither of the above.
- **not run**: the path was not tried (it could not be set up), or no heartbeat came after the stop was fired.

An outcome is worded by its window (D532: "an outcome is worded by its window ('not stopped within 15 minutes')").

**Time to effect** is a range, never one number (the founder, 23 October 2026). Where a path stopped, the stop took
effect after the last success before its final run of failures and by that run's first failure; and the firing moment
is known only to its precision: CloudTrail records a call to the whole second, so the call was made within the second
after the time it gives. The range is (last success - (fired + precision), first failure of the final run - fired).
**Successes after the first refusal** are counted on every path: where it is not 0, the path was not yet stopped at its
first refusal, and it is timed from the run of failures that stopped it.
"""
from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

HOLD = 30.0                 # seconds a run of failures must last to count as stopped
# Each cloud's default window after firing, in seconds (K8), by the cloud's name in a result: how long each path is
# timed once the stop is fired. Each cloud has its own, set for it before its module runs: a cloud with none here has no
# default, and the command line offers no cloud without one (tests/test_cli_and_page.py).
WINDOWS = {"aws": 15 * 60.0, "google_cloud": 15 * 60.0}

# The stop map's four paths, the optional model call (the design's section 4), and on AgentCore new calls to the agent
# (agentcore/run.py; D618), in their order.
PATHS = ("own_calls", "another_identity", "outside_key", "open_internet", "model", "new_calls")
PATH_WORDS = {
    "own_calls": "its own calls to the cloud",
    "another_identity": "work under another identity",
    "outside_key": "a key for a service outside the cloud",
    "open_internet": "the open internet",
    "model": "a call to a model",
    # CUSTOMER TEXT: approved by the founder, 04:44 UTC on 28 October 2026 (D618)
    "new_calls": "new calls to the agent",
}

STOPPED, FLAPPED, NOT_STOPPED, NOT_RUN = "stopped", "stopped, then succeeded again", "not stopped", "not run"


@dataclass(frozen=True)
class Beat:
    """One try of one path."""
    at: float                       # seconds since the epoch, UTC, by the test agent's own clock
    ok: bool
    error: str | None = None        # the error's code where it failed, e.g. "AccessDenied"; never a message or payload


@dataclass(frozen=True)
class PathResult:
    outcome: str                    # STOPPED, FLAPPED, NOT_STOPPED or NOT_RUN
    window: float
    last_success_after: float | None = None
    first_failure_after: float | None = None
    stopped_at: float | None = None             # the start of the run of failures that stopped it
    tries_after: int = 0
    failures_after: int = 0
    errors: dict[str, int] = field(default_factory=dict)
    reason: str | None = None                   # for NOT_RUN: why
    effect_between: tuple[float, float] | None = None   # where it stopped: seconds after firing, at least and at most
    successes_after_first_refusal: int = 0
    keeps_working_until: float | None = None    # a session that was not stopped: when it expires, by AWS's clock
    fired_source: str | None = None             # where the firing moment came from, and its precision
    fired_at: float | None = None               # the path's own firing moment, where it differs from its repeat's

    def words(self) -> str:
        return worded(self.outcome, self.window)


def window_words(window: float) -> str:
    minutes, seconds = divmod(int(round(window)), 60)
    if seconds == 0:
        return f"{minutes} minute" + ("" if minutes == 1 else "s")
    return f"{int(round(window))} seconds"


def worded(outcome: str, window: float) -> str:
    """The outcome in its words, by its window."""
    w = window_words(window)
    return {STOPPED: f"stopped within {w}", FLAPPED: f"stopped within {w}, then succeeded again",
            NOT_STOPPED: f"not stopped within {w}", NOT_RUN: "not run"}[outcome]


def _runs(beats: Sequence[Beat]) -> list[tuple[float, float, bool]]:
    """The runs of failures, each as (first failure's time, last failure's time, whether a success followed it)."""
    runs: list[tuple[float, float, bool]] = []
    start = last = None
    for b in beats:
        if not b.ok:
            if start is None:
                start = b.at
            last = b.at
        elif start is not None:
            runs.append((start, last, True))
            start = last = None
    if start is not None:
        runs.append((start, last, False))
    return runs


def judge(beats: Iterable[Beat], fired_at: float | None, window: float, hold: float = HOLD,
          tried: bool = True, setup_errors: dict[str, int] | None = None, fired_precision: float = 0.0) -> PathResult:
    """What the test found on one path, from its heartbeats and the moment the stop was fired."""
    if not tried:
        return PathResult(NOT_RUN, window, errors=dict(setup_errors or {}), reason="the path could not be set up")
    if fired_at is None:
        return PathResult(NOT_RUN, window, reason="the stop was not fired")
    end = fired_at + window + hold
    after = sorted((b for b in beats if fired_at < b.at <= end), key=lambda b: b.at)
    if not after:
        return PathResult(NOT_RUN, window, reason="no heartbeat came after the stop was fired")
    successes = [b.at for b in after if b.ok]
    failures = [b for b in after if not b.ok]
    first_failure = min((b.at for b in failures), default=None)
    common = dict(window=window, last_success_after=max(successes, default=None), first_failure_after=first_failure,
                  tries_after=len(after), failures_after=len(failures),
                  errors=dict(Counter(b.error or "unknown" for b in failures)),
                  successes_after_first_refusal=sum(1 for t in successes if first_failure is not None and t > first_failure))

    def effect(stopped_at: float) -> tuple[float, float]:
        before = max((t for t in successes if t < stopped_at), default=None)
        low = max(0.0, before - (fired_at + fired_precision)) if before is not None else 0.0
        return round(low, 3), round(stopped_at - fired_at, 3)
    runs = _runs(after)
    # A run lasts from its first failure to the last heartbeat before the next success, or to the last heartbeat seen.
    last_seen = after[-1].at
    held = [(start, (last if followed else last_seen) - start >= hold, followed) for start, last, followed in runs]
    if any(long_enough and followed for _, long_enough, followed in held):
        flapped_at = next(start for start, long_enough, followed in held if long_enough and followed)
        return PathResult(FLAPPED, stopped_at=flapped_at, effect_between=effect(flapped_at), **common)
    final = held[-1] if held else None
    if final is not None and not final[2] and final[1] and final[0] <= fired_at + window:
        return PathResult(STOPPED, stopped_at=final[0], effect_between=effect(final[0]), **common)
    return PathResult(NOT_STOPPED, **common)
