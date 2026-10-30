"""The timing rule: from each path's heartbeats and the moment the stop was fired, what the test found (the design's
section 6; D532, K8).

A heartbeat is one try of one path: when, by the test agent's own clock, whether it succeeded, and if not, its failure
record (never a message or payload). The kit invokes the test agent once a second, with its own credentials, and reads
each heartbeat from the invocation's reply, so a stop that denies the agent everything cannot also silence its report.

**Only the stop's own refusal counts** (the founder's refusal ruling of 29 October 2026). A failed call counts as
refused only where it is the stop's own refusal, as refusals.py has it for each kind of stop, after the firing moment,
on a path that succeeded before it. Every other failure, a throttle, a server error, a timeout or a network failure
among them, is "not counted": neither stopped nor succeeded. It moves no time, and the details and the page show it by
its code.

For each path, after the stop is fired, from its successes and counted refusals:

- **stopped within <window>**: its last run of refusals began within the window, lasted at least HOLD seconds, and
  was never followed by a success. The kit watches HOLD seconds past the window, so a stop that took hold just before
  the window's end can still be confirmed. Its stopped time is that run's first refusal: not-counted calls between
  move nothing.
- **stopped within <window>, then succeeded again**: a run of refusals lasting at least HOLD seconds was followed by a
  success. Said as such, never as stopped.
- **not stopped within <window>**: neither of the above.
- **not measured**: every call after the stop was not counted; or the path's last success or counted refusal was
  followed only by not-counted calls, for at least HOLD seconds from within the window, so the kit cannot say whether
  the stop stopped it (the founder, 29 October 2026, items 2 and 3, and his answer to the kit session's proposal).
  Through a gateway (the kit's `--via`; D561), also a path that could not be set up (`untried`), or whose first
  heartbeat after the customer's mark was already refused (`refused_at_mark`; the founder, 28 October 2026: "A path
  already refused at the mark is 'not measured'"): the gateway did not carry it before the stop, or it was refused
  before anything after the mark could be timed, so nothing can say the stop stopped it.
- **not run**: the path was not tried (it could not be set up), or no heartbeat came after the stop was fired.

An outcome is worded by its window (D532: "an outcome is worded by its window ('not stopped within 15 minutes')").

**Time to effect** is a range, never one number (the founder, 23 October 2026). Where a path stopped, the stop took
effect after the last success before its final run of refusals and by that run's first refusal; and the firing moment
is known only to its precision: CloudTrail records a call to the whole second, so the call was made within the second
after the time it gives. The range is (last success - (fired + precision), first refusal of the final run - fired).
**Successes after the first refusal** are counted on every path: where it is not 0, the path was not yet stopped at its
first refusal, and it is timed from the run of refusals that stopped it.
"""
from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone

HOLD = 30.0                 # seconds a run of refusals must last to count as stopped
# Each cloud's default window after firing, in seconds (K8), by the cloud's name in a result: how long each path is
# timed once the stop is fired. Each cloud has its own, set for it before its module runs: a cloud with none here has no
# default, and the command line offers no cloud without one (tests/test_cli_and_page.py).
WINDOWS = {"aws": 15 * 60.0, "google_cloud": 15 * 60.0}
# Through a gateway the window is fixed before the run, and is at least this (the founder, 28 October 2026: "at least
# 15 minutes").
GATEWAY_WINDOW = 15 * 60.0

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
NOT_MEASURED = "not measured"       # the stop's effect could not be counted (the founder, 29 October 2026)
# CUSTOMER TEXT: approved by the founder, word for word, 30 October 2026
ALL_NOT_COUNTED = "every call after the stop was not counted"
NOTHING_COUNTED_AFTER = "nothing after {time} was counted"
REFUSED_AT_THE_MARK = "it was already refused at the mark"   # through a gateway (judge's refused_at_mark)


@dataclass(frozen=True)
class Beat:
    """One try of one path. Where it failed, its failure record (D646, item 4: the founder, 29 October 2026): the error's
    code, the provider's HTTP status and reason, and the token's issue and expiry times where a token is used. A field
    is None where there is none: no HTTP answer, no reason in the provider's error, no token on the call, or (Lambda's
    own role) none the agent is told."""
    at: float                       # seconds since the epoch, UTC, by the test agent's own clock
    ok: bool
    error: str | None = None        # the error's code where it failed, e.g. "AccessDenied"; never a message or payload
    status: int | None = None       # the HTTP status the provider answered with
    reason: str | None = None       # the provider's own reason field, e.g. Storage's "forbidden"
    provider_status: str | None = None      # the provider's own status field, e.g. Google's "PERMISSION_DENIED"
    step: str | None = None         # the step of the path that failed, where it has steps: "token", "write" or "read"
    token_issued: float | None = None       # the token the call used: when it was issued and when it expires, by the
    token_expires: float | None = None      # agent's clock, or for a token taken from AWS or Google, by theirs
    client_at: float | None = None          # when the client the call used was made, by the agent's clock
    versions: tuple[str, ...] | None = None     # the agent's Python, botocore and urllib3, where it names them


@dataclass(frozen=True)
class PathResult:
    outcome: str                    # STOPPED, FLAPPED, NOT_STOPPED, NOT_RUN or NOT_MEASURED
    window: float
    last_success_after: float | None = None
    first_failure_after: float | None = None    # the first counted refusal after the stop
    stopped_at: float | None = None             # the start of the run of refusals that stopped it
    tries_after: int = 0
    failures_after: int = 0                     # every failure after the stop, counted or not
    errors: dict[str, int] = field(default_factory=dict)        # every failure's code
    reason: str | None = None                   # for NOT_RUN and NOT_MEASURED: why
    effect_between: tuple[float, float] | None = None   # where it stopped: seconds after firing, at least and at most
    successes_after_first_refusal: int = 0
    keeps_working_until: float | None = None    # a session that was not stopped: when it expires, by AWS's clock
    fired_source: str | None = None             # where the firing moment came from, and its precision
    fired_at: float | None = None               # the path's own firing moment, where it differs from its repeat's
    not_counted: dict[str, int] = field(default_factory=dict)   # the failures not counted, by code
    refused: tuple[int, ...] = ()               # which of `failures`, by place, were counted refusals
    failures: tuple[Beat, ...] = ()             # each failure after the stop, with its record

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
            NOT_STOPPED: f"not stopped within {w}", NOT_RUN: "not run", NOT_MEASURED: "not measured"}[outcome]


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


def _decide(beats: Sequence[Beat], fired_at: float, window: float, hold: float) -> tuple[str, float | None]:
    """The rule on a path's successes and refusals after the stop, in order: its outcome, and where it stopped, when."""
    # A run lasts from its first failure to the last heartbeat before the next success, or to the last heartbeat seen.
    last_seen = beats[-1].at
    held = [(start, (last if followed else last_seen) - start >= hold, followed)
            for start, last, followed in _runs(beats)]
    if any(long_enough and followed for _, long_enough, followed in held):
        return FLAPPED, next(start for start, long_enough, followed in held if long_enough and followed)
    final = held[-1] if held else None
    if final is not None and not final[2] and final[1] and final[0] <= fired_at + window:
        return STOPPED, final[0]
    return NOT_STOPPED, None


def _clock(t: float) -> str:
    return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%H:%M:%S UTC")


def judge(beats: Iterable[Beat], fired_at: float | None, window: float, hold: float = HOLD,
          tried: bool = True, setup_errors: dict[str, int] | None = None, fired_precision: float = 0.0, *,
          counts: Callable[[Beat, Sequence[Beat]], bool], untried: str = NOT_RUN,
          refused_at_mark: str | None = None, set_aside: Callable[[Beat], bool] | None = None) -> PathResult:
    """What the test found on one path, from its heartbeats, before the stop and after it, and the moment the stop was
    fired. `counts` says whether a failed call is the stop's own refusal (refusals.py), given the path's heartbeats
    before the firing moment; a refusal counts only where the path succeeded before it. A path that could not be set up
    reads `untried`: "not run", or through a gateway "not measured" (D561). Where `refused_at_mark` is given (through a
    gateway, "not measured"), a path whose first heartbeat after the mark was refused reads it. A try `set_aside` says
    to set aside (through a gateway, one made with a client made after the mark: "new connections only", D655) is
    neither a success nor a refusal: it moves nothing, sets nothing, and where it fails it is named, not counted."""
    if not tried:
        return PathResult(untried, window, errors=dict(setup_errors or {}), reason="the path could not be set up")
    if fired_at is None:
        return PathResult(NOT_RUN, window, reason="the stop was not fired")
    end = fired_at + window + hold
    ordered = sorted(beats, key=lambda b: b.at)
    before = [b for b in ordered if b.at <= fired_at]
    after = [b for b in ordered if fired_at < b.at <= end]
    if not after:
        return PathResult(NOT_RUN, window, reason="no heartbeat came after the stop was fired")
    if refused_at_mark is not None and not after[0].ok:
        failed = [b for b in after if not b.ok]
        codes = dict(Counter(b.error or "unknown" for b in failed))
        return PathResult(refused_at_mark, window, tries_after=len(after), failures_after=len(failed), errors=codes,
                          not_counted=codes, failures=tuple(failed), reason=REFUSED_AT_THE_MARK)
    # the successes and counted refusals, in order: a refusal counts only on a path that succeeded before it
    kept: list[Beat] = []
    succeeded = any(b.ok for b in before)
    aside = {id(b) for b in after if set_aside is not None and set_aside(b)}
    for b in after:
        if id(b) in aside:
            continue
        if b.ok or (succeeded and counts(b, before)):
            kept.append(b)
            succeeded = succeeded or b.ok
    failures = [b for b in after if not b.ok]
    refusals = [b for b in kept if not b.ok]
    counted = {id(b) for b in refusals}
    refused = [i for i, b in enumerate(failures) if id(b) in counted]
    successes = [b.at for b in after if b.ok and id(b) not in aside]
    first_refusal = refusals[0].at if refusals else None
    common = dict(window=window, last_success_after=max(successes, default=None), first_failure_after=first_refusal,
                  tries_after=len(after), failures_after=len(failures),
                  errors=dict(Counter(b.error or "unknown" for b in failures)),
                  not_counted=dict(Counter(b.error or "unknown" for b in failures if id(b) not in counted)),
                  successes_after_first_refusal=sum(1 for t in successes
                                                    if first_refusal is not None and t > first_refusal),
                  refused=tuple(refused), failures=tuple(failures))
    if not kept:
        return PathResult(NOT_MEASURED, reason=ALL_NOT_COUNTED, **common)

    def effect(stopped_at: float) -> tuple[float, float]:
        before_it = max((t for t in successes if t < stopped_at), default=None)
        low = max(0.0, before_it - (fired_at + fired_precision)) if before_it is not None else 0.0
        return round(low, 3), round(stopped_at - fired_at, 3)
    outcome, stopped_at = _decide(kept, fired_at, window, hold)
    if outcome != NOT_STOPPED:
        return PathResult(outcome, stopped_at=stopped_at, effect_between=effect(stopped_at), **common)
    # after its last success or counted refusal, only calls not counted: where they lasted the hold from within the
    # window, the kit cannot say whether the stop stopped the path
    tail = [b for b in after if b.at > kept[-1].at]
    if tail and tail[0].at <= fired_at + window and tail[-1].at - tail[0].at >= hold:
        return PathResult(NOT_MEASURED, reason=NOTHING_COUNTED_AFTER.format(time=_clock(kept[-1].at)), **common)
    return PathResult(NOT_STOPPED, **common)
