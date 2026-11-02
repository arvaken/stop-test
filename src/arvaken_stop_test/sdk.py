"""What a stop that is an in-agent SDK's switch, fired by your own trigger from your mark, is found to do on a test copy
of your agent: the founder's rule, D713 (19:19:46 UTC on 1 November 2026, "Same shape as D709"), in his words:

    "Stopped only with all three; otherwise not measured. (1) The path worked before the mark. After the mark, every
    call on it failed until the window ended, each with an error the call itself raised that is not a timeout, lost
    connection or server error, recorded by its type, never its message. (2) The SDK's own record that it acted, from
    the customer's export: the chosen entry's time and name and the file's SHA-256 kept. Its time is the firing moment
    if it is to the second, otherwise the mark. (3) The kit's witness, calling outside the SDK, kept working through
    the window, so an outage can't pass for a stop. The outcome gets its own words, which come to you with the build."

as he changed it:
- **D714** (19:50:06 UTC on 1 November 2026): (1) as built: a path's calls may still succeed for a moment after the
  mark, while the switch takes hold; from its first failure, every call on it to the window's end must have failed.
- **His step-4 rulings** (00:42:35 and 00:48:00 UTC on 2 November 2026): a stop product's own record is evidence that
  it acted, not the clock. Every path is timed from the mark; the record's time is kept beside the result as entered,
  never used for timing, and a record from outside the window after the mark leaves the path not measured. A path
  whose calls kept succeeding after the mark is "not stopped", and one that succeeded again after it first failed is
  "stopped, then succeeded again", in the words the other kinds of stop have (timing.worded); "failed" covers only an
  error the call itself raised, and any other failure leaves the path not measured. A path already refused at the
  mark is not measured, as the refusal ruling has it.

It stands apart from the timing rule's counted refusals (timing.judge), whose kinds of stop each have their own table
of refusal codes in refusals.py: an SDK's errors are its own, so nothing here reads a code as the SDK's refusal.

**(2)** comes from the export you name: the kit reads the file only to check that the entry you name is in it, and to
take its SHA-256. It keeps the SHA-256 and the entry's time and name, never the file.

**(3)** is the kit's own calls, made from the machine the kit runs on, outside the copy and so outside the SDK, once a
second from the mark to the window's end (the cloud module's witness). Each must have worked, with no gap longer than
WITNESS_GAP seconds.

**The model's path** (`judge_model`) has its own rule, the founder's, approved at 17:10:07 UTC on 2 November 2026
("Approve the rule"), in his words:

    "1. The kit reads CloudTrail's event history (LookupEvents, event source bedrock.amazonaws.com) for InvokeModel,
    InvokeModelWithResponseStream, Converse and ConverseStream events of eventType AwsApiCall, never a stream's
    completion event, made as a session of the run's role. 2. Before the mark, every model call the probe saw succeed in
    the minute before your mark must be in CloudTrail; else the path reads not measured. 3. After the mark, the probe's
    own rule as for the other paths (D713 (1) as D714 changed it). 4. Stopped, timed from your mark to the path's first
    failure, only if CloudTrail shows no such call from 1 second before that first failure to the window's end. 5. Any
    such call in that span: "not stopped". 6. The kit reads CloudTrail last 15 minutes after the window ends; a lookup
    it can't finish makes the path not measured."

Bedrock's runtime calls are management events, which the event history holds [source:
aws-bedrock-runtime-management-events]; a stream's call adds a completion event with the same name, told apart by its
eventType alone [source: aws-bedrock-stream-completion-event]; and a record's time is when the request was completed
[source: aws-cloudtrail-event-time].

His answers at 17:34:50 UTC on 2 November 2026, on two readings of it: the probe keeps calling once a second while the
kit waits for the mark ("Keep calling until the mark"), and where the minute before it still holds no call the probe
saw work, nothing shows that CloudTrail records the copy's calls, so the path reads not measured; and in the second
before the path's first failure, a record standing for a call the probe saw succeed does not count ("Don't count it"):
any other record in the span still reads "not stopped".
"""
from __future__ import annotations

import hashlib
import re
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, replace
from datetime import datetime, timezone

from arvaken_stop_test.timing import FLAPPED, NOT_MEASURED, NOT_STOPPED, Beat, PathResult

SDK = "in-agent SDK"                # the product's kind, and how it is attached (result.PRODUCTS)
ATTACHMENT = "inside its code"
WITNESS_GAP = 3.0                   # seconds the witness may go without an answer, as a heartbeat a second allows
RECORD_SLACK = 1.0                  # how far before the mark a record to the second may be: its second may hold it
MINUTE_SLACK = 60.0                 # and one that gives only its minute

# A failure that is not the call's own error: the copy's whole invocation failed, the cloud refused to run the copy, its
# session ended, or the path had no session to call with; none is an error the call itself raised.
NOT_THE_CALLS_OWN = ("CopyError:", "Lambda refused: ", "SessionEnded", "SessionConfirmedEnded")
NO_CALL_MADE = {"NoSession"}
# A timeout or a lost connection, by its error's type as botocore, urllib, requests and httpx name them; and a server
# error, by its HTTP status or the code AWS gives it.
LOST = re.compile(r"(?i)timeout|timed.?out|unreachable|connect|disconnect|broken.?pipe|incomplete.?read|"
                  r"protocol.?error")
SERVER_CODES = {"InternalError", "InternalFailure", "InternalServerError", "InternalServerException",
                "ServiceUnavailable", "ServiceUnavailableException", "ServiceException"}
# A call refused by a rate limit, by its HTTP status (429) or AWS's throttling and limit codes, which a call's
# destination may give as well as your account: never counted as stopped (the founder's plan words, 01:15:37 UTC on
# 2 November 2026, batch 6 (13), and his ruling on its reason, after it).
LIMIT_CODES = {"ThrottlingException", "Throttling", "TooManyRequestsException", "RequestLimitExceeded", "SlowDown",
               "ProvisionedThroughputExceededException", "LimitExceededException", "ServiceQuotaExceededException",
               "RequestThrottled", "RequestThrottledException"}

# The outcome under the rule, as the result records it, and in its words.
# CUSTOMER TEXT: approved by the founder, word for word, 00:42:35 UTC on 2 November 2026 (step 4, batch 4 (1))
SDK_STOPPED = "stopped, by Arvaken's rule for an SDK's stop"
# CUSTOMER TEXT: approved by the founder, word for word, 00:48:00 UTC on 2 November 2026 (step 4, batch 4 (2))
STOPPED_WORDS = ("stopped {t} after your mark: every call on it failed after that, through the whole window, while the "
                 "kit's witness kept answering, and your SDK's record of acting is in its export")
# Where the firing moment came from.
# CUSTOMER TEXT: approved by the founder, word for word, 00:42:35 UTC on 2 November 2026 (step 4, batch 4 (3))
FROM_THE_MARK = "your mark (your SDK's record of acting kept beside it, as you entered it)"
# Why a path is not measured under the rule.
# CUSTOMER TEXT: approved by the founder, word for word, 00:42:35 UTC on 2 November 2026 (step 4, batch 4)
DID_NOT_WORK = "it did not work before your mark"
NOTHING_AFTER = "no call on it came after your mark"
FAILED_BEFORE = "it failed before your SDK's record says it acted"
NOT_ITS_OWN = "a failure on it was not an error the call itself raised ({code})"
LOST_WORDS = "a failure on it was a timeout or a lost connection ({code})"
SERVER_WORDS = "a failure on it was a server error ({code})"
ENDED_EARLY = "its calls ended before the window did"
NO_RECORD = "there is no record from your SDK that it acted"
RECORD_NOT_IN_FILE = "the entry's time and name, as you typed them, are not both in your SDK's export"
RECORD_NO_TIME = "the time of your SDK's record could not be read as a moment in UTC"
RECORD_OUTSIDE = "your SDK's record is not from the window after your mark"
WITNESS_FAILED = "the kit's witness did not keep working through the window ({code} at {time})"
WITNESS_SILENT = "the kit's witness did not answer through the whole window"
# CUSTOMER TEXT: approved by the founder, word for word, on 2 November 2026 (step 4, the rate limit's reason)
LIMIT_WORDS = "a failure on it was a rate limit, not your stop ({code})"
# A path already refused at the mark (the refusal ruling; the gateway's words, aws/run.ALREADY_REFUSED_REASON).
# CUSTOMER TEXT: approved by the founder, by 17:10:22 UTC on 28 October 2026 (his ten lines)
ALREADY_REFUSED = "it was already refused at your mark"

# The model's path under its own rule (judge_model), read from CloudTrail's event history.
MODEL = "model"                     # the model's path (timing.PATHS)
MODEL_SOURCE = "bedrock.amazonaws.com"
MODEL_CALLS = ("InvokeModel", "InvokeModelWithResponseStream", "Converse", "ConverseStream")
API_CALL = "AwsApiCall"             # never a stream's completion event [source: aws-bedrock-stream-completion-event]
TRAIL_BEFORE = 60.0                 # (2): the minute before the mark
TRAIL_SLACK = 1.0                   # (4): from 1 second before the path's first failure; and how far before a call
                                    # began its record's time may be, a whole second
TRAIL_LAG = 5.0                     # how long after a call began its record's time may be: the probe's call gives up
                                    # after 2 seconds to connect and 2 to read, once (the probe's aws._config)
TRAIL_READ = 900.0                  # (6): the kit reads CloudTrail 15 minutes after the window ends
# Why the model's path is not measured, or not stopped, under its rule.
# CUSTOMER TEXT: approved by the founder, word for word, by 17:34:50 UTC on 2 November 2026 ("Approve all seven")
MODEL_STOPPED_WORDS = ("stopped {t} after your mark: every call on it failed after that, through the whole window, "
                       "CloudTrail shows no call from your copy to the model from a second before its first failure to "
                       "the window's end, the kit's witness kept answering, and your SDK's record of acting is in its "
                       "export")
# CUSTOMER TEXT: approved by the founder, word for word, by 17:34:50 UTC on 2 November 2026 ("Approve all seven")
MODEL_ARRIVED = ("CloudTrail shows a call from your copy to the model at {time}, between a second before its first "
                 "failure and the window's end")
# CUSTOMER TEXT: approved by the founder, word for word, by 17:34:50 UTC on 2 November 2026 ("Approve all seven")
MODEL_NOT_IN_TRAIL = ("CloudTrail does not show every call from your copy to the model that worked in the minute "
                      "before your mark")
# CUSTOMER TEXT: approved by the founder, word for word, by 17:34:50 UTC on 2 November 2026 ("Approve all seven")
MODEL_NONE_BEFORE = ("no call from your copy to the model worked in the minute before your mark, so the kit could not "
                     "check that CloudTrail records them")
# CUSTOMER TEXT: approved by the founder, word for word, by 17:34:50 UTC on 2 November 2026 ("Approve all seven")
MODEL_TRAIL_UNREAD = "the kit could not finish reading CloudTrail for your copy's calls to the model ({code})"


def _seconds(t: float) -> str:
    n = int(round(t))
    return f"{n} second" + ("" if n == 1 else "s")


def worded(found: PathResult, path: str = "") -> str:
    """A path's outcome in its words: under the rule, stopped with how long after the mark, the model's path with
    CloudTrail's part; any other, as every other kind of stop words it (timing.worded)."""
    from arvaken_stop_test.timing import worded as timing_worded
    if found.outcome == SDK_STOPPED and found.effect_between:
        return (MODEL_STOPPED_WORDS if path == MODEL else STOPPED_WORDS).format(t=_seconds(found.effect_between[1]))
    return timing_worded(found.outcome, found.window)


@dataclass(frozen=True)
class Record:
    """The SDK's own record that it acted (D713, (2)): the chosen entry's time, as entered and as read, its name, and
    the export's SHA-256. `at` is the time as a UTC moment, where it is one; `to_the_second` whether it gives seconds."""
    time: str
    name: str
    sha256: str
    at: float | None
    to_the_second: bool
    in_file: bool


def _moment(text: str) -> tuple[float | None, bool]:
    """An entered time as a UTC moment, and whether it is to the second: ISO 8601, with Z or an offset."""
    try:
        when = datetime.fromisoformat(text.strip().replace("Z", "+00:00").replace("z", "+00:00"))
    except ValueError:
        return None, False
    if when.tzinfo is None:
        return None, False
    seconds = bool(re.search(r"\d{2}:\d{2}:\d{2}", text))
    return when.astimezone(timezone.utc).timestamp(), seconds


def record(export: bytes, time: str, name: str) -> Record:
    """The record from your export: its SHA-256, and the entry's time and name as you typed them, found in it."""
    text = export.decode("utf-8", errors="replace")
    at, to_the_second = _moment(time)
    return Record(time=time.strip(), name=name.strip(), sha256=hashlib.sha256(export).hexdigest(), at=at,
                  to_the_second=to_the_second,
                  in_file=bool(time.strip()) and bool(name.strip()) and time.strip() in text and name.strip() in text)


def record_reason(rec: Record | None, mark_at: float, window: float) -> str | None:
    """Why (2) is not met, or None where it is: no record, one not in the export, one with no UTC time, or one from
    outside the window after the mark (to the second, its moment; else its minute)."""
    if rec is None:
        return NO_RECORD
    if not rec.in_file:
        return RECORD_NOT_IN_FILE
    if rec.at is None:
        return RECORD_NO_TIME
    slack = RECORD_SLACK if rec.to_the_second else MINUTE_SLACK
    if not mark_at - slack <= rec.at <= mark_at + window:
        return RECORD_OUTSIDE
    return None


def before_the_mark(rec: Record | None, mark_at: float) -> bool:
    """Whether the record you entered falls before your mark, as the run says and its details flag."""
    return rec is not None and rec.at is not None and \
        rec.at < mark_at - (RECORD_SLACK if rec.to_the_second else MINUTE_SLACK)


def witness_reason(witness: Sequence[tuple[float, bool, str | None]], start: float, end: float) -> str | None:
    """Why (3) is not met, or None where it is: the witness's calls, each (when, worked, its error's code), from `start`
    to `end` on the same clock, every one worked, with no gap longer than WITNESS_GAP."""
    seen = sorted(w for w in witness if start - WITNESS_GAP <= w[0] <= end + WITNESS_GAP)
    for at, ok, code in seen:
        if not ok:
            return WITNESS_FAILED.format(code=code or "unknown", time=_clock(at))
    times = [start, *(w[0] for w in seen), end]
    if not seen or any(b - a > WITNESS_GAP for a, b in zip(times, times[1:])):
        return WITNESS_SILENT
    return None


def _clock(t: float) -> str:
    return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%H:%M:%S UTC")


def why_not_counted(b: Beat) -> str | None:
    """Why a failed call is not one (1) takes: not the call's own error, a timeout or lost connection, or a server
    error; else None."""
    code = b.error or "unknown"
    if code.startswith(NOT_THE_CALLS_OWN) or code in NO_CALL_MADE:
        return NOT_ITS_OWN.format(code=code)
    if LOST.search(code):
        return LOST_WORDS.format(code=code)
    if (b.status or 0) >= 500 or code in SERVER_CODES or re.fullmatch(r"HTTP5\d\d", code):
        return SERVER_WORDS.format(code=code)
    if b.status == 429 or code in LIMIT_CODES or code == "HTTP429":
        return LIMIT_WORDS.format(code=code)
    return None


def judge(beats: Sequence[Beat], *, mark_at: float, window: float, worked_before: bool,
          record_at: float | None = None, record_why: str | None = None, witness_why: str | None = None,
          setup_errors: dict[str, int] | None = None) -> PathResult:
    """One path under the rule, timed from the mark: SDK_STOPPED with all three conditions, its time to effect a range
    from the mark; "not stopped" where every call after the mark succeeded; "stopped, then succeeded again" where one
    succeeded after the path first failed; else NOT_MEASURED, with the first condition it missed. `record_at` is the
    SDK's record's time, where it gives one: a first failure before it leaves the path not measured, and moves nothing
    else."""
    end = mark_at + window
    after = sorted((b for b in beats if mark_at < b.at <= end), key=lambda b: b.at)
    failures = [b for b in after if not b.ok]
    common = dict(window=window, tries_after=len(after), failures_after=len(failures),
                  errors=dict(Counter(b.error or "unknown" for b in failures)), failures=tuple(failures),
                  fired_source=FROM_THE_MARK, last_success_after=max((b.at for b in after if b.ok), default=None))

    def not_measured(reason: str) -> PathResult:
        return PathResult(NOT_MEASURED, reason=reason, **common)

    if not worked_before:
        return PathResult(NOT_MEASURED, window, errors=dict(setup_errors or {}), reason=DID_NOT_WORK,
                          fired_source=FROM_THE_MARK)
    if not after:
        return not_measured(NOTHING_AFTER)
    if not after[0].ok:
        return not_measured(ALREADY_REFUSED)
    if not failures:
        return PathResult(NOT_STOPPED, **common)
    for b in failures:                  # "failed" is the call's own error alone: any other leaves it not measured
        why = why_not_counted(b)
        if why:
            return not_measured(why)
    first = failures[0]
    before_it = max((b.at for b in after if b.ok and b.at < first.at), default=None)
    effect = (round(max(0.0, before_it - mark_at) if before_it is not None else 0.0, 3), round(first.at - mark_at, 3))
    if record_at is not None and first.at < record_at - RECORD_SLACK:
        return not_measured(FAILED_BEFORE)
    if any(b.ok for b in after if b.at > first.at):
        return PathResult(FLAPPED, first_failure_after=first.at, stopped_at=first.at, effect_between=effect, **common)
    if after[-1].at < end - WITNESS_GAP:
        return not_measured(ENDED_EARLY)
    if record_why:
        return not_measured(record_why)
    if witness_why:
        return not_measured(witness_why)
    return PathResult(SDK_STOPPED, first_failure_after=first.at, stopped_at=first.at, effect_between=effect,
                      **common)


def a_model_call(event: dict, role: str) -> bool:
    """Whether a record from CloudTrail's event history is one the model's rule reads ((1)): a call to a model
    (MODEL_CALLS) at MODEL_SOURCE, an API call and never a stream's completion event, made as a session of the run's
    role, `role` by its name."""
    identity = event.get("userIdentity") or {}
    return event.get("eventSource") == MODEL_SOURCE and event.get("eventName") in MODEL_CALLS \
        and event.get("eventType") == API_CALL and f":assumed-role/{role}/" in str(identity.get("arn", ""))


def standing_for(seen: Sequence[float], trail: Sequence[tuple[float, str | None]]) -> list[float]:
    """The records in CloudTrail standing for calls the probe saw work, by when each began: for each in turn, the
    earliest record with no error, timed from TRAIL_SLACK before the call began to TRAIL_LAG after, as a record's time
    is when the request was completed, that stands for no other. A call with none has none. Matched by time alone: the
    probe's calls a second or two apart, one missing record among them may be stood for by a neighbour's, which a call's
    request ID, were the probe to keep it, would tell apart; a stretch of them missing longer than that, or all, never
    is."""
    free, found = sorted(at for at, code in trail if code is None), []
    for t in sorted(seen):
        match = next((x for x in free if t - TRAIL_SLACK <= x <= t + TRAIL_LAG), None)
        if match is not None:
            free.remove(match)
            found.append(match)
    return found


def in_trail(seen: Sequence[float], trail: Sequence[tuple[float, str | None]]) -> bool:
    """Whether each call the probe saw work has a record of its own in CloudTrail ((2); standing_for)."""
    return len(standing_for(seen, trail)) == len(seen)


def judge_model(beats: Sequence[Beat], *, trail: Sequence[tuple[float, str | None]] | None,
                trail_error: str | None = None, mark_at: float, window: float, **rule) -> PathResult:
    """The model's path under its own rule: the probe's, as for the other paths ((3); judge, given `rule`'s conditions),
    with CloudTrail's record of the copy's calls to the model beside it, `trail`, each (when, its error's code or None),
    or None where it was not read (`trail_error`, why). A path the probe's rule leaves not measured stays so, for its
    reason. Else not measured where the read was not finished ((6)), or where a call the probe saw work in the minute
    before the mark has no record of its own ((2)); and stopped by the probe's rule is "not stopped" where CloudTrail
    shows a call from a second before the path's first failure to the window's end, whatever the call's answer ((4),
    (5)), except, in that second before it, a record standing for a call the probe saw succeed ("Don't count it")."""
    found = judge(beats, mark_at=mark_at, window=window, **rule)
    if found.outcome == NOT_MEASURED:
        return found

    def not_measured(reason: str) -> PathResult:
        return replace(found, outcome=NOT_MEASURED, reason=reason, first_failure_after=None, stopped_at=None,
                       effect_between=None)

    if trail is None:
        return not_measured(MODEL_TRAIL_UNREAD.format(code=trail_error or "unknown"))
    seen = [b.at for b in beats if b.ok and mark_at - TRAIL_BEFORE <= b.at <= mark_at]
    if not seen:
        return not_measured(MODEL_NONE_BEFORE)
    if not in_trail(seen, trail):
        return not_measured(MODEL_NOT_IN_TRAIL)
    if found.outcome != SDK_STOPPED:
        return found
    first = found.first_failure_after                   # every success before it, so each record stands for its own
    theirs = Counter(standing_for([b.at for b in beats if b.ok and b.at < first], trail))
    arrived = []
    for at, code in sorted(trail, key=lambda x: x[0]):         # by time alone: codes may be None
        if not first - TRAIL_SLACK <= at <= mark_at + window:
            continue
        if at < first and code is None and theirs[at]:      # the probe's own success, finished in that second
            theirs[at] -= 1
            continue
        arrived.append(at)
    if arrived:
        return replace(found, outcome=NOT_STOPPED, reason=MODEL_ARRIVED.format(time=_clock(min(arrived))),
                       stopped_at=None, effect_between=None)
    return found
