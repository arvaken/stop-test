"""The founder's rule for an in-agent SDK's stop (D713; sdk.py): stopped only with all three conditions, otherwise not
measured. First the rule on heartbeats made by hand; then a whole run on a test copy of the customer's Lambda function
(test_aws_copy's fake), with the real probe, the SDK's switch as the fake's own, the kit's witness, and an export."""
from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from arvaken_stop_test import refusals, sdk
from arvaken_stop_test.aws import run as running
from arvaken_stop_test.aws import your_copy
from arvaken_stop_test.timing import NOT_MEASURED, Beat

MARK, WINDOW = 1_000_000.0, 900.0


def beats(fails_from: float | None, *, until: float = MARK + WINDOW + 30, error: str = "SwitchEngaged",
          status: int | None = None, success_at: float | None = None) -> list[Beat]:
    """A heartbeat a second from 10 seconds before the mark: each a success, then from `fails_from` failed with
    `error`, except one success at `success_at`."""
    out, t = [], MARK - 10
    while t <= until:
        failed = fails_from is not None and t >= fails_from and t != success_at
        out.append(Beat(t, not failed, error if failed else None, status=status if failed else None))
        t += 1.0
    return out


def judged(bs, **over):
    kw = dict(mark_at=MARK, fired_at=MARK, window=WINDOW, worked_before=True)
    kw.update(over)
    return sdk.judge(bs, **kw)


def test_with_all_three_a_path_is_stopped_by_the_sdks_rule_and_its_time_to_effect_is_a_range():
    found = judged(beats(MARK + 4.0), fired_at=MARK + 2.0, fired_precision=1.0, fired_source=sdk.FROM_THE_RECORD)
    assert found.outcome == sdk.SDK_STOPPED and found.reason is None
    assert found.effect_between == (0.0, 2.0) and found.first_failure_after == MARK + 4.0
    assert sdk.worded(found.outcome, WINDOW) == sdk.STOPPED_WORDS.format(window="15 minutes")


@pytest.mark.parametrize("bs, over, reason", [
    (beats(MARK + 4), dict(worked_before=False), sdk.DID_NOT_WORK),
    (beats(None), {}, sdk.NOTHING_FAILED),
    (beats(MARK + 4, success_at=MARK + 100), {}, sdk.SUCCEEDED_AFTER.format(time=sdk._clock(MARK + 100))),
    (beats(MARK + 4, error="ReadTimeoutError"), {}, sdk.LOST_WORDS.format(code="ReadTimeoutError")),
    (beats(MARK + 4, error="Unreachable"), {}, sdk.LOST_WORDS.format(code="Unreachable")),
    (beats(MARK + 4, error="EndpointConnectionError"), {}, sdk.LOST_WORDS.format(code="EndpointConnectionError")),
    (beats(MARK + 4, error="HTTP503", status=503), {}, sdk.SERVER_WORDS.format(code="HTTP503")),
    (beats(MARK + 4, error="InternalError", status=500), {}, sdk.SERVER_WORDS.format(code="InternalError")),
    (beats(MARK + 4, error=running.COPY_ERROR + "SwitchEngaged"), {},
     sdk.NOT_ITS_OWN.format(code=running.COPY_ERROR + "SwitchEngaged")),
    (beats(MARK + 4, error=refusals.LAMBDA_REFUSED + "KMSAccessDeniedException"), {},
     sdk.NOT_ITS_OWN.format(code=refusals.LAMBDA_REFUSED + "KMSAccessDeniedException")),
    (beats(MARK + 4, until=MARK + 300), {}, sdk.ENDED_EARLY),
    (beats(MARK + 1), dict(fired_at=MARK + 3), sdk.FAILED_BEFORE),
    (beats(MARK + 4), dict(record_why=sdk.NO_RECORD), sdk.NO_RECORD),
    (beats(MARK + 4), dict(witness_why=sdk.WITNESS_SILENT), sdk.WITNESS_SILENT),
])
def test_without_any_one_of_the_three_a_path_is_not_measured_and_says_which(bs, over, reason):
    found = judged(bs, **over)
    assert (found.outcome, found.reason) == (NOT_MEASURED, reason)


def test_an_sdks_own_error_and_a_clouds_refusal_are_each_the_calls_own_but_a_session_ended_is_not():
    for code in ("SwitchEngaged", "AccessDenied", "HTTP403", "PermissionDenied", "ThrottlingException"):
        assert sdk.why_not_counted(Beat(MARK, False, code)) is None, code
    for code in ("SessionEnded", "NoSession", "CopyError:Unhandled", "ConnectTimeoutError", "ProxyConnectionError"):
        assert sdk.why_not_counted(Beat(MARK, False, code)) is not None, code


def iso(t: float) -> str:
    return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def test_the_record_is_the_exports_sha256_and_the_entry_found_in_it_and_its_time_to_the_second_fires():
    export = json.dumps([{"at": iso(MARK + 2), "event": "kill switch engaged", "by": "someone@example.com"}]).encode()
    rec = sdk.record(export, iso(MARK + 2), "kill switch engaged")
    assert rec.in_file and rec.to_the_second and rec.at == MARK + 2 and len(rec.sha256) == 64
    assert sdk.record_reason(rec, MARK, WINDOW) is None
    assert sdk.firing_moment(rec, MARK, WINDOW) == (MARK + 2, 1.0, sdk.FROM_THE_RECORD)
    assert "someone@example.com" not in json.dumps(vars(rec))           # the file itself is never kept


@pytest.mark.parametrize("time, name, reason, fired", [
    (iso(MARK + 2), "kill switch engaged", None, MARK + 2),
    (iso(MARK + 2)[:16] + "Z", "kill switch engaged", None, MARK),            # to the minute: from the mark
    (iso(MARK + 2), "something else", sdk.RECORD_NOT_IN_FILE, MARK),
    (iso(MARK + 2).rstrip("Z"), "kill switch engaged", sdk.RECORD_NO_TIME, MARK),   # no zone
    (iso(MARK - 120), "kill switch engaged", sdk.RECORD_OUTSIDE, MARK),
    (iso(MARK + WINDOW + 60), "kill switch engaged", sdk.RECORD_OUTSIDE, MARK),
])
def test_a_record_is_this_firings_only_from_the_export_and_from_the_window_after_the_mark(time, name, reason, fired):
    export = f"{time} kill switch engaged\n{iso(MARK - 120)} kill switch engaged\n" \
             f"{iso(MARK + WINDOW + 60)} kill switch engaged\n{iso(MARK + 2)[:16]}Z\n".encode()
    rec = sdk.record(export, time, name)
    assert sdk.record_reason(rec, MARK, WINDOW) == reason
    assert sdk.firing_moment(rec, MARK, WINDOW)[0] == fired
    assert sdk.record_reason(None, MARK, WINDOW) == sdk.NO_RECORD


def test_the_witness_must_work_every_second_through_the_window():
    good = [(MARK + i, True, None) for i in range(0, int(WINDOW) + 1)]
    assert sdk.witness_reason(good, MARK, MARK + WINDOW) is None
    failed = [*good[:100], (MARK + 100, False, "ServiceUnavailable"), *good[101:]]
    assert sdk.witness_reason(failed, MARK, MARK + WINDOW) == sdk.WITNESS_FAILED.format(
        code="ServiceUnavailable", time=sdk._clock(MARK + 100))
    gap = [w for w in good if not MARK + 200 < w[0] < MARK + 210]
    assert sdk.witness_reason(gap, MARK, MARK + WINDOW) == sdk.WITNESS_SILENT
    assert sdk.witness_reason([], MARK, MARK + WINDOW) == sdk.WITNESS_SILENT


def test_what_the_rule_sets_aside_as_not_the_calls_own_names_the_kits_own_prefixes():
    assert running.COPY_ERROR in sdk.NOT_THE_CALLS_OWN and refusals.LAMBDA_REFUSED in sdk.NOT_THE_CALLS_OWN
    assert running.REFUSED == refusals.LAMBDA_REFUSED and your_copy.ENDPOINT == "https://stop-test.arvaken.com"


# -- a whole run on a test copy of the customer's Lambda function, with their SDK's switch

from test_aws_copy import COPY, CopyAWS, a_copy_run, an_account  # noqa: E402,F401 - the fixture is used by name
from test_aws_run import Clock  # noqa: E402

SDK_NAME = "Acme Guard"
EXPORT_NAME = "kill switch engaged"


def an_sdk_run(monkeypatch, *, fires_after: float | None = 2.0, export=None, witness=lambda url, headers: 200,
               **over):
    """A run with the customer's SDK, its switch turned on `fires_after` seconds after their Enter; their export holds
    the entry, at that moment to the second, with a person's address beside it."""
    clock = Clock()
    aws = CopyAWS(clock, **over.pop("aws", {}))

    def time() -> str:
        return iso(aws.sdk_on_from) if aws.sdk_on_from is not None else iso(clock.now())

    files = {}

    def read(where: str) -> bytes:
        files[where] = export(aws) if export else f"{time()} {EXPORT_NAME} by ops@example.com\n".encode()
        return files[where]

    answers = {your_copy.SDK_EXPORT: "acme-audit.log", your_copy.SDK_ENTRY_TIME: time,
               your_copy.SDK_ENTRY_NAME: EXPORT_NAME, **over.pop("answers", {})}
    r, said, asked = a_copy_run(aws, clock, monkeypatch, stop_ref="", sdk_name=SDK_NAME, window=900.0,
                                answers=answers, fires_after=fires_after, read=read, witness_get=witness, **over)
    return r, aws, said, asked, files


def test_an_sdks_switch_fired_from_the_mark_stops_every_path_by_its_own_record_and_the_witness(an_account,
                                                                                                monkeypatch):
    r, aws, said, asked, files = an_sdk_run(monkeypatch)
    fired, found = your_copy.sdk_results(r)[0]
    assert {p: f.outcome for p, f in found.items()} == {p: sdk.SDK_STOPPED for p in r.paths}
    # timed from the SDK's own record, to the second; each path took effect by its next heartbeat
    assert fired == int(aws.sdk_on_from) and all(f.fired_source == sdk.FROM_THE_RECORD for f in found.values())
    assert all(f.effect_between[1] <= 2.5 for f in found.values())
    # the kit fired nothing itself; the customer was warned, marked, and asked for their export
    assert not aws.attach_calls and not aws.put_calls and r.fired_by == "your own trigger"
    assert r.product == {"kind": "in-agent SDK", "attachment": "inside its code", "name": SDK_NAME}
    assert asked.index(your_copy.WARNING) < asked.index(running.MARK_PROMPT) < asked.index(your_copy.SDK_EXPORT)
    assert your_copy.SDK_MARKED in said and your_copy.SDK_SWITCH_OFF in said
    # the record keeps the entry's time and name and the export's SHA-256, never the file
    import hashlib
    assert r.sdk_record.sha256 == hashlib.sha256(files["acme-audit.log"]).hexdigest()
    assert "ops@example.com" not in repr(r) and "acme-audit.log" not in repr(r)
    # the witness called once a second, from outside the copy, through the window, and every call worked
    times = [at for at, _, _ in r.witness]
    assert all(ok for _, ok, _ in r.witness) and max(b - a for a, b in zip(times, times[1:])) < sdk.WITNESS_GAP
    assert times[-1] - times[0] >= 900
    # and nothing of the kit's is left
    assert r.left_behind == [] and aws.role_deleted


def test_where_the_witness_failed_in_the_window_no_path_is_stopped_so_an_outage_cannot_pass_for_a_stop(
        an_account, monkeypatch):
    calls = []

    def witness(url, headers):
        calls.append(url)
        if len(calls) == 300:
            raise TimeoutError()
        return 200

    r, _, _, _, _ = an_sdk_run(monkeypatch, witness=witness)
    found = your_copy.sdk_results(r)[0][1]
    assert {f.outcome for f in found.values()} == {NOT_MEASURED}
    assert all(f.reason.startswith("the kit's witness did not keep working") for f in found.values())


def test_without_the_sdks_own_record_no_path_is_stopped(an_account, monkeypatch):
    r, _, _, _, _ = an_sdk_run(monkeypatch, answers={your_copy.SDK_EXPORT: ""})
    found = your_copy.sdk_results(r)[0][1]
    assert r.sdk_record is None and {(f.outcome, f.reason) for f in found.values()} == {(NOT_MEASURED, sdk.NO_RECORD)}


def test_a_switch_that_cuts_the_copys_connections_is_never_read_as_stopped(an_account, monkeypatch):
    r, _, _, _, _ = an_sdk_run(monkeypatch, aws={"sdk_raises": TimeoutError})
    found = your_copy.sdk_results(r)[0][1]
    assert {f.outcome for f in found.values()} == {NOT_MEASURED}
    assert all("a timeout or a lost connection" in f.reason for f in found.values())


def test_a_switch_never_turned_on_leaves_every_path_not_measured_as_the_rules_otherwise_says(an_account,
                                                                                             monkeypatch):
    r, _, _, _, _ = an_sdk_run(monkeypatch, fires_after=None)
    found = your_copy.sdk_results(r)[0][1]
    assert {(f.outcome, f.reason) for f in found.values()} == {(NOT_MEASURED, sdk.NOTHING_FAILED)}


@pytest.mark.parametrize("over, says", [
    (dict(stop_ref="arn:aws:iam::123456789012:policy/agent-stop"), "fires nothing"),
    (dict(window=600.0), "at least 15 minutes"),
    (dict(model="eu.amazon.nova-micro-v1:0"), "call to a model"),
    (dict(repeats=2), "fires once"),
    (dict(sdk_name="x" * 201), "1 to 200 characters"),
])
def test_an_sdks_stop_is_refused_before_anything_is_made_where_it_cannot_be_judged(an_account, monkeypatch, over,
                                                                                  says):
    clock = Clock()
    aws = CopyAWS(clock)
    kw = dict(stop_ref="", sdk_name=SDK_NAME, window=900.0)
    kw.update(over)
    with pytest.raises(ValueError, match=says):
        a_copy_run(aws, clock, monkeypatch, **kw)
    assert aws.stack is None
