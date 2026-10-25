"""The result: the file a run writes, in the format stop-test-result/1, signed with a key the kit makes for the run (the
design's section 8; D532).

**What it holds is exactly what the kit's submission terms say, and nothing more.** The terms' 4.4 lists everything in
a submitted result that stays readable (D532, amendment C): the kind of stop and how it was fired; the kind of test
agent, its runtime, memory and region, and whether it ran in a private network; the cloud; the kit's version; when the
test began and ended, its window and repeats, how far apart the clocks it read were, how many calls it made, and
whether anything it made was left after it ended; for each path, when the stop was fired, when a call last succeeded
after it, when one was first refused, and the outcome; and the signature, with the public half of its key. The terms'
4.2 names what identifies and is sealed when submitted: here, the stop's and the test agent's identifiers and the names
of anything left. `check` refuses any other field, so the format cannot grow past the terms without both changing.

**What the signature proves:** that the file has not changed since it was signed. Not that the kit wrote it, who ran
it, or that the run was honest (the terms' 3.3; the founder's README wording, 24 October 2026).
"""
from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Mapping
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from arvaken_stop_test.timing import FLAPPED, NOT_RUN, NOT_STOPPED, PATHS, STOPPED, PathResult

FORMAT = "stop-test-result/1"
OUTCOMES = (STOPPED, FLAPPED, NOT_STOPPED, NOT_RUN)
FIRED_BY = ("the kit", "your own trigger")

# Every field, by where it sits, and whether it identifies (sealed when submitted) or stays readable.
SHAPE: dict[str, tuple[str, ...]] = {
    "": ("format", "kit", "cloud", "region", "run", "stop", "agent", "repeats", "signature"),
    "kit": ("version",),
    "run": ("began_at", "ended_at", "window_seconds", "repeats", "clock_gap_ms", "calls", "left_anything",
            "left_behind"),
    "stop": ("kind", "fired_by", "ref"),
    "agent": ("kind", "runtime", "memory_mb", "private_network", "ref", "role_ref"),
    "repeat.path": ("fired_at", "last_success_after", "first_refused_after", "outcome"),
    "signature": ("alg", "public_key", "value"),
}
IDENTIFYING = ("stop.ref", "agent.ref", "agent.role_ref", "run.left_behind")


class NotAResult(ValueError):
    """What was offered is not a stop-test-result/1, or its signature does not check."""


def iso(t: float | None) -> str | None:
    """Seconds since the epoch as an ISO 8601 UTC time to the millisecond, or None."""
    if t is None:
        return None
    from datetime import datetime, timezone
    return datetime.fromtimestamp(t, tz=timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def path_part(r: PathResult, fired_at: float | None) -> dict[str, Any]:
    """One path's part: its own firing moment where it has one (revoking sessions fires on two roles), else its
    repeat's."""
    return {"fired_at": iso(r.fired_at if r.fired_at is not None else fired_at),
            "last_success_after": iso(r.last_success_after),
            "first_refused_after": iso(r.first_failure_after), "outcome": r.outcome}


def build(*, kit_version: str, cloud: str, region: str, began_at: float, ended_at: float, window: float,
          clock_gap_ms: int, calls: int, left_behind: list[str], stop_kind: str, fired_by: str, stop_ref: str,
          agent: Mapping[str, Any], repeats: list[tuple[float | None, Mapping[str, PathResult]]]) -> dict[str, Any]:
    """The unsigned result. `repeats` is each repeat's firing moment and each path's result, in the paths' order."""
    return {
        "format": FORMAT, "kit": {"version": kit_version}, "cloud": cloud, "region": region,
        "run": {"began_at": iso(began_at), "ended_at": iso(ended_at), "window_seconds": int(window),
                "repeats": len(repeats), "clock_gap_ms": int(clock_gap_ms), "calls": int(calls),
                "left_anything": bool(left_behind), "left_behind": sorted(left_behind)},
        "stop": {"kind": stop_kind, "fired_by": fired_by, "ref": stop_ref},
        "agent": {k: agent[k] for k in SHAPE["agent"]},
        "repeats": [{p: path_part(paths[p], fired_at) for p in PATHS if p in paths} for fired_at, paths in repeats],
    }


def canonical(doc: Mapping[str, Any]) -> bytes:
    """The bytes the signature covers: the result without its signature, keys sorted, no spaces, UTF-8."""
    body = {k: v for k, v in doc.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def new_key() -> Ed25519PrivateKey:
    """A key for one run. It is never written to disk: once the result is signed, it is gone."""
    return Ed25519PrivateKey.generate()


def sign(doc: Mapping[str, Any], key: Ed25519PrivateKey) -> dict[str, Any]:
    public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    signed = {k: v for k, v in doc.items() if k != "signature"}
    signed["signature"] = {"alg": "ed25519", "public_key": base64.b64encode(public).decode("ascii"),
                           "value": base64.b64encode(key.sign(canonical(doc))).decode("ascii")}
    return signed


def reference(doc: Mapping[str, Any]) -> str:
    """The result's reference: the SHA-256 of its signature's 64 bytes, as hex. Arvaken's record keeps this alone of a
    signature, and its page shows it when a result is sent: it names the result without testing any guess of what the
    signature covers, which only the run's key, never kept, could sign."""
    return hashlib.sha256(base64.b64decode(doc["signature"]["value"], validate=True)).hexdigest()


def _exactly(d: Any, where: str) -> None:
    keys = SHAPE[where]
    if not isinstance(d, dict) or set(d) != set(keys):
        raise NotAResult(f"{where or 'the result'} holds exactly {', '.join(keys)}")


def check(doc: Any) -> dict[str, Any]:
    """The result, if it is a stop-test-result/1 in exactly its shape and its signature checks; else NotAResult."""
    _exactly(doc, "")
    if doc["format"] != FORMAT:
        raise NotAResult(f"the result is not {FORMAT}")
    for part in ("kit", "run", "stop", "agent", "signature"):
        _exactly(doc[part], part)
    if doc["stop"]["fired_by"] not in FIRED_BY:
        raise NotAResult(f"the stop was fired by one of {', '.join(FIRED_BY)}")
    if not isinstance(doc["repeats"], list) or len(doc["repeats"]) != doc["run"]["repeats"] or not doc["repeats"]:
        raise NotAResult("the repeats are a list, as many as the run says")
    for i, repeat in enumerate(doc["repeats"]):
        if not isinstance(repeat, dict) or not set(repeat) <= set(PATHS) or not repeat:
            raise NotAResult(f"repeat {i} names only the kit's paths")
        for path, part in repeat.items():
            _exactly(part, "repeat.path")
            if part["outcome"] not in OUTCOMES:
                raise NotAResult(f"repeat {i}'s {path} has an outcome the rule does not give")
    if doc["run"]["left_anything"] != bool(doc["run"]["left_behind"]):
        raise NotAResult("the run says something was left exactly where it names what")
    sig = doc["signature"]
    if sig["alg"] != "ed25519":
        raise NotAResult("the signature is ed25519")
    try:
        public = Ed25519PublicKey.from_public_bytes(base64.b64decode(sig["public_key"], validate=True))
        public.verify(base64.b64decode(sig["value"], validate=True), canonical(doc))
    except (InvalidSignature, ValueError) as e:
        raise NotAResult("the signature does not check: the file has changed since the kit wrote it") from e
    return doc
