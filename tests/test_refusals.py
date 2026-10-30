"""Which failed call is the stop's own refusal (refusals.py; the founder's refusal rulings of 29 October 2026 and his
answers of 30 October 2026). Each case is a call after the stop, on a path that succeeded before it."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from arvaken_stop_test import refusals as rf
from arvaken_stop_test.aws import fire as aws_fire
from arvaken_stop_test.google import fire as google_fire
from arvaken_stop_test.timing import Beat

AT = 1_000.0
RAN = [Beat(AT - 2, True), Beat(AT - 1, True)]            # the agent ran before the stop, and the path succeeded
ROOT = Path(__file__).resolve().parents[1]


def failed(code, **record) -> Beat:
    return Beat(AT + 5, False, code, **record)


def test_the_kinds_are_the_clouds_own_names_for_them():
    assert {aws_fire.kind_of(x) for x in ("arn:aws:iam::111122223333:policy/p", aws_fire.INLINE, aws_fire.REVOKE)} \
        == {rf.AWS_POLICY, rf.AWS_INLINE, rf.AWS_REVOKE}
    assert {google_fire.DENY_KIND, google_fire.DISABLE_KIND} == {rf.GOOGLE_DENY, rf.GOOGLE_DISABLE}
    assert set(rf.COUNTED) == {rf.AWS_POLICY, rf.AWS_INLINE, rf.AWS_REVOKE, rf.GOOGLE_DENY, rf.GOOGLE_DISABLE}


@pytest.mark.parametrize("kind", [rf.AWS_POLICY, rf.AWS_INLINE, rf.AWS_REVOKE])
def test_a_policy_on_a_role_counts_s3s_access_denied_on_the_paths_that_call_it_and_nothing_outside_the_cloud(kind):
    for path in ("own_calls", "another_identity"):
        assert rf.counts(kind, path, failed("AccessDenied", status=403), RAN)
        for code in ("SlowDown", "InternalError", "ServiceUnavailable", "RequestTimeout", "Unreachable",
                     "ReadTimeoutError", "ConnectTimeoutError", "ExpiredToken"):
            assert not rf.counts(kind, path, failed(code), RAN), code
    for path in ("outside_key", "open_internet"):
        assert not rf.counts(kind, path, failed("HTTP403", status=403), RAN)
        assert not rf.counts(kind, path, failed("AccessDenied"), RAN)


def test_lambdas_kms_access_denied_counts_on_every_path_only_first_after_the_stop_and_where_the_agent_ran_before():
    kms = failed(rf.LAMBDA_KMS, status=502)
    for path in ("own_calls", "another_identity", "outside_key", "open_internet"):
        assert rf.counts(rf.AWS_INLINE, path, kms, RAN)
    assert not rf.counts(rf.AWS_INLINE, "own_calls", kms, RAN + [Beat(AT - 0.5, False, rf.LAMBDA_KMS)])   # before
    assert not rf.counts(rf.AWS_INLINE, "own_calls", kms, [Beat(AT - 1, False, rf.LAMBDA_KMS)])            # never ran
    assert not rf.counts(rf.GOOGLE_DENY, "own_calls", kms, RAN)


def test_lambdas_other_refusals_are_not_counted():
    """The founder's answer of 30 October 2026: only KMSAccessDeniedException, until he approves codes for the kinds of
    stop that give the others."""
    for code in ("KMSDisabledException", "KMSInvalidStateException", "KMSNotFoundException",
                 "ResourceNotFoundException", "TooManyRequestsException"):
        assert not rf.counts(rf.AWS_POLICY, "own_calls", failed(rf.LAMBDA_REFUSED + code), RAN), code


def test_a_google_deny_policy_counts_storages_403_by_its_reason_alone():
    for reason in ("forbidden", "insufficientPermissions"):
        for path, step in (("own_calls", "write"), ("own_calls", "read"), ("another_identity", "write")):
            assert rf.counts(rf.GOOGLE_DENY, path, failed("HTTP403", status=403, reason=reason, step=step), RAN)
    # the ruling's tests: a 403 for a disabled API, a rate limit, disabled billing, VPC Service Controls; none counts
    for reason in ("accessNotConfigured", "SERVICE_DISABLED", "rateLimitExceeded", "userRateLimitExceeded",
                   "accountDisabled", "billingDisabled", "vpcServiceControls", None):
        assert not rf.counts(rf.GOOGLE_DENY, "own_calls", failed("HTTP403", status=403, reason=reason, step="write"),
                             RAN), reason
    assert not rf.counts(rf.GOOGLE_DENY, "own_calls", failed("HTTP401", status=401, reason="authError", step="write",
                                                             token_expires=AT + 600), RAN)
    assert not rf.counts(rf.GOOGLE_DENY, "own_calls", failed("HTTP404", status=404, step="token"), RAN)
    assert not rf.counts(rf.GOOGLE_DENY, "own_calls", failed("HTTP403", status=403, reason="forbidden", step="token"),
                         RAN)


def test_a_disabled_google_account_counts_a_401_only_with_a_token_not_past_its_expiry():
    live = failed("HTTP401", status=401, reason="authError", step="write", token_issued=AT - 600, token_expires=AT + 600)
    expired = failed("HTTP401", status=401, reason="authError", step="write", token_issued=AT - 3600,
                     token_expires=AT - 1)
    unknown = failed("HTTP401", status=401, reason="authError", step="write")
    assert rf.counts(rf.GOOGLE_DISABLE, "own_calls", live, RAN)
    assert not rf.counts(rf.GOOGLE_DISABLE, "own_calls", expired, RAN)      # the ruling's expired-token 401
    assert not rf.counts(rf.GOOGLE_DISABLE, "own_calls", unknown, RAN)      # no expiry to show it was not past it
    assert not rf.counts(rf.GOOGLE_DISABLE, "own_calls", failed("HTTP401", status=401, reason="required",
                                                                step="write", token_expires=AT + 600), RAN)
    assert rf.counts(rf.GOOGLE_DISABLE, "own_calls", failed("HTTP403", status=403, reason="forbidden", step="read"),
                     RAN)


def test_a_disabled_google_accounts_404_counts_on_its_own_token_step_alone():
    """D644: "token:HTTP404 only"; a 404 on the write or the read would mean a missing bucket or object."""
    assert rf.counts(rf.GOOGLE_DISABLE, "own_calls", failed("HTTP404", status=404, step="token"), RAN)
    for step in ("write", "read"):
        assert not rf.counts(rf.GOOGLE_DISABLE, "own_calls", failed("HTTP404", status=404, step=step), RAN)
    assert not rf.counts(rf.GOOGLE_DISABLE, "another_identity", failed("HTTP404", status=404, step="token"), RAN)


def test_cloud_runs_refusals_and_your_unidentified_trigger_count_nothing():
    for status in (429, 500, 503):
        assert not rf.counts(rf.GOOGLE_DISABLE, "own_calls", failed(f"Cloud Run refused: HTTP{status}", status=status),
                             RAN)
    assert not rf.counts(None, "own_calls", failed("AccessDenied", status=403), RAN)
    assert not rf.counts(None, "own_calls", failed(rf.LAMBDA_KMS), RAN)


def test_each_counted_code_names_its_source():
    """GENERAL: "Each counted code has a source entry." The classifier cites each in PROVIDER-SOURCES.json; D644's 404
    is Arvaken's own ruling, from its run, and is cited so."""
    sources = json.loads((ROOT / "PROVIDER-SOURCES.json").read_text(encoding="utf-8"))["sources"]
    text = (ROOT / "src" / "arvaken_stop_test" / "refusals.py").read_text(encoding="utf-8")
    assert "aws-s3-access-denied," in text and "403 Forbidden" in sources["aws-s3-access-denied"]["sentence"]
    cited = {"AccessDenied": ("aws-s3-access-denied-example",),
             "KMSAccessDeniedException": ("aws-lambda-invoke-kms-access-denied",),
             "forbidden": ("google-storage-403-forbidden",),
             "insufficientPermissions": ("google-storage-403-insufficient-permissions",),
             "authError": ("google-storage-401-auth-error",)}
    for code, ids in cited.items():
        for i in ids:
            assert i in sources and i in text and code in sources[i]["sentence"], (code, i)
    assert "D644" in text and "token:HTTP404 only" in text
