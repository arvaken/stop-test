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
"""
from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

HOLD = 30.0                 # seconds a run of failures must last to count as stopped
WINDOW = 15 * 60.0          # the default window after firing, in seconds (K8)

# The stop map's four paths, and the optional model call (the design's section 4), in their order.
PATHS = ("own_calls", "another_identity", "outside_key", "open_internet", "model")
PATH_WORDS = {
    "own_calls": "its own calls to the cloud",
    "another_identity": "work under another identity",
    "outside_key": "a key for a service outside the cloud",
    "open_internet": "the open internet",
    "model": "a call to a model",
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


def judge(beats: Iterable[Beat], fired_at: float | None, window: float = WINDOW, hold: float = HOLD,
          tried: bool = True) -> PathResult:
    """What the test found on one path, from its heartbeats and the moment the stop was fired."""
    if not tried:
        return PathResult(NOT_RUN, window, reason="the path could not be set up")
    if fired_at is None:
        return PathResult(NOT_RUN, window, reason="the stop was not fired")
    end = fired_at + window + hold
    after = sorted((b for b in beats if fired_at < b.at <= end), key=lambda b: b.at)
    if not after:
        return PathResult(NOT_RUN, window, reason="no heartbeat came after the stop was fired")
    successes = [b.at for b in after if b.ok]
    failures = [b for b in after if not b.ok]
    common = dict(window=window, last_success_after=max(successes, default=None),
                  first_failure_after=min((b.at for b in failures), default=None), tries_after=len(after),
                  failures_after=len(failures), errors=dict(Counter(b.error or "unknown" for b in failures)))
    runs = _runs(after)
    # A run lasts from its first failure to the last heartbeat before the next success, or to the last heartbeat seen.
    last_seen = after[-1].at
    held = [(start, (last if followed else last_seen) - start >= hold, followed) for start, last, followed in runs]
    if any(long_enough and followed for _, long_enough, followed in held):
        flapped_at = next(start for start, long_enough, followed in held if long_enough and followed)
        return PathResult(FLAPPED, stopped_at=flapped_at, **common)
    final = held[-1] if held else None
    if final is not None and not final[2] and final[1] and final[0] <= fired_at + window:
        return PathResult(STOPPED, stopped_at=final[0], **common)
    return PathResult(NOT_STOPPED, **common)
