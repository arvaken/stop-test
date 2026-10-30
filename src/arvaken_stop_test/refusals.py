"""Which failed call is the stop's own refusal, and so counts, for each kind of stop (the founder's refusal rulings of 29
October 2026, and his answers of 30 October 2026). One classifier for every kind of agent and every path.

His rule: "A call counts as stopped only when refused by the stop's own refusal." Throttles, limits and quotas, server
errors, timeouts and network failures never count: they are "not counted", neither stopped nor succeeded. GENERAL: "A
refusal counts only if it comes after the firing moment, on a path that succeeded before it" (timing.judge sees to
that); "Each counted code has a source entry"; "Anything else is 'not counted'".

**A policy on a role, attached or written on it, and revoking its sessions** (item 1): the denial code of the service
each path calls, by its code. The agent's own calls and its work under another identity call Amazon S3, which refuses
as AccessDenied [source: aws-s3-access-denied, aws-s3-access-denied-example]. Outside the cloud (a key for a service
outside it, the open internet) the agent calls Arvaken's endpoint, which no stop on a role refuses: nothing there counts.
And on every path, Lambda refusing to run the agent at all with KMSAccessDeniedException
[source: aws-lambda-invoke-kms-access-denied], "only if it first appears after the firing moment and the function ran
before it". Lambda's other refusals (a KMS key disabled or gone, the function gone, no concurrency left) are not
counted: the founder's answer of 30 October 2026, until he approves codes for the kinds of stop that give them.

**On Google Cloud** (item 4, and his answer of 30 October 2026): the agent's paths call Cloud Storage's JSON API, whose
errors carry an HTTP code and a reason, and no status [source: google-storage-error-format]. So a deny policy's refusal
is a 403 whose reason is forbidden or insufficientPermissions [source: google-storage-403-forbidden,
google-storage-403-insufficient-permissions]; any other 403 (a rate limit, a disabled API, disabled billing, VPC Service
Controls) is not counted. A disabled account's: those, and a 401 whose reason is authError, only where the token the call
used was not past its expiry when used [source: google-storage-401-auth-error]; a 401 from an expired token is not
counted. And, for a disabled account only, a 404 on the agent's own token step: D644's ruling, "token:HTTP404 only", from
Arvaken's run r9bc29057, where a 404 on the write or the read would mean a missing bucket or object.

**Your own trigger** (item 5): the kit identifies the kind of stop from the cloud's audit record of your own action, and
uses that kind's refusals. Where it cannot identify one, nothing counts as stopped (`counts` with kind None).

The gateway option (`--via`) is outside these: the founder's ruling on the gateway's refusal, 30 October 2026, lives on
its own branch.
"""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from arvaken_stop_test.timing import Beat

# The kinds of stop, as each cloud's fire.py names them
AWS_POLICY, AWS_INLINE, AWS_REVOKE = "policy on a role", "policy written on the role", "revoke active sessions"
GOOGLE_DENY, GOOGLE_DISABLE = "deny policy on its identity", "disable its service account"

LAMBDA_REFUSED = "Lambda refused: "      # the prefix of a beat the kit makes where Lambda refused to run the agent
LAMBDA_KMS = LAMBDA_REFUSED + "KMSAccessDeniedException"


@dataclass(frozen=True)
class Refusal:
    """One code a kind of stop refuses with, on one path: where the provider's reason decides it, only those reasons;
    where one step of a path counts, only those steps; and where the token's expiry decides it, only with a token not
    past its expiry when the call was made."""
    code: str
    reasons: frozenset[str] | None = None
    steps: frozenset[str] | None = None
    unexpired_token: bool = False

    def matches(self, b: Beat) -> bool:
        return (b.error == self.code and (self.reasons is None or b.reason in self.reasons)
                and (self.steps is None or b.step in self.steps)
                and (not self.unexpired_token or (b.token_expires is not None and b.at < b.token_expires)))


S3_DENIED = Refusal("AccessDenied")
STORAGE_DENIED = Refusal("HTTP403", reasons=frozenset({"forbidden", "insufficientPermissions"}),
                         steps=frozenset({"write", "read"}))
STORAGE_UNAUTHENTICATED = Refusal("HTTP401", reasons=frozenset({"authError"}), steps=frozenset({"write", "read"}),
                                  unexpired_token=True)
TOKEN_NOT_FOUND = Refusal("HTTP404", steps=frozenset({"token"}))

_ON_A_ROLE = {"own_calls": (S3_DENIED,), "another_identity": (S3_DENIED,)}
COUNTED: dict[str, dict[str, tuple[Refusal, ...]]] = {
    AWS_POLICY: _ON_A_ROLE,
    AWS_INLINE: _ON_A_ROLE,
    AWS_REVOKE: _ON_A_ROLE,
    GOOGLE_DENY: {"own_calls": (STORAGE_DENIED,), "another_identity": (STORAGE_DENIED,)},
    GOOGLE_DISABLE: {"own_calls": (STORAGE_DENIED, STORAGE_UNAUTHENTICATED, TOKEN_NOT_FOUND),
                     "another_identity": (STORAGE_DENIED, STORAGE_UNAUTHENTICATED)},
}
# Where Lambda's KMSAccessDeniedException counts, on every path
LAMBDA_KINDS = (AWS_POLICY, AWS_INLINE, AWS_REVOKE)


def counts(kind: str | None, path: str, b: Beat, before: Sequence[Beat]) -> bool:
    """Whether a failed call is the stop's own refusal, for a stop of this kind (None: your own trigger's, which the
    kit could not identify), on this path, given the path's heartbeats before the firing moment."""
    if b.ok or kind is None:
        return False
    if b.error == LAMBDA_KMS:
        ran = any(not (x.error or "").startswith(LAMBDA_REFUSED) for x in before)
        return kind in LAMBDA_KINDS and ran and not any(x.error == LAMBDA_KMS for x in before)
    return any(r.matches(b) for r in COUNTED.get(kind, {}).get(path, ()))
