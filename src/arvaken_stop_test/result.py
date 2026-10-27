"""The result: the file a run writes, in the format stop-test-result/2, signed with a key the kit makes for the run (the
design's section 8; D532; version 2, D561). `check` still takes a stop-test-result/1, as the kit wrote it to 0.2.1.

**What it holds is exactly what the kit's submission terms say, and nothing more.** The terms' 4.4 lists everything in
a submitted result that stays readable (D532, amendment C): the kind of stop and how it was fired; the kind of test
agent, its runtime, memory and region, and whether it ran in a private network; the cloud; the kit's version; when the
test began and ended, its window and repeats, how far apart the clocks it read were, how many calls it made, and
whether anything it made was left after it ended; for each path, when the stop was fired, when a call last succeeded
after it, when one was first refused, and the outcome; and the signature, with the public half of its key. The terms'
4.2 names what identifies and is sealed when submitted: here, the stop's and the test agent's identifiers and the names
of anything left. `check` refuses any other field, so the format cannot grow past the terms without both changing.

**Version 2 (D561, section 5)** adds, for a declared stop that is a product's control: the product's kind and how it is
attached, kept in clear as kinds of stop are; and the product's name and the gateway's address, which identify and are
sealed when submitted. It says where each path's timing starts (`run.timing_from`: through a gateway, the customer's
mark, so a time errs toward slower, never faster), and for each path whether it failed before the stop (a path that did
not work through the gateway before the stop reads "not measured", never "stopped"). The terms' 4.4 and 4.2 name none of
these yet: they are for the legal track's reading (the design's section 8) before a release.

**A gateway's address is written without any user name or password** (the founder, D595: "Until 3.4's sentence ships,
the kit strips any username or password from a gateway's address before it is sealed."), and `check` refuses one that
has them.

**What the signature proves:** that the file has not changed since it was signed. Not that the kit wrote it, who ran
it, or that the run was honest (the terms' 3.3; the founder's README wording, 24 October 2026).
"""
from __future__ import annotations

import base64
import hashlib
import json
import urllib.parse
from collections.abc import Mapping
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from arvaken_stop_test.timing import FLAPPED, NOT_MEASURED, NOT_RUN, NOT_STOPPED, PATHS, STOPPED, PathResult

FORMAT = "stop-test-result/2"
FORMAT_V1 = "stop-test-result/1"
OUTCOMES = (STOPPED, FLAPPED, NOT_STOPPED, NOT_RUN, NOT_MEASURED)
OUTCOMES_V1 = (STOPPED, FLAPPED, NOT_STOPPED, NOT_RUN)
FIRED_BY = ("the kit", "your own trigger")

# A declared stop that is a third party's product (D561): its kind, and each kind's attachments, as the record holds
# them.
# Only a gateway can be tested by the kit's own test agent; an in-agent SDK and host software wait for a test agent of
# the customer's choosing (K10), but a result of one is a version-2 result all the same.
PRODUCT_CONTROL = "a product's control"
GATEWAY = "gateway"
PRODUCTS: dict[str, tuple[str, ...]] = {
    GATEWAY: ("its calls to a model", "its calls to outside services", "all its outbound traffic"),
    "in-agent SDK": ("inside its code",),
    "host software": ("on its host",),
}
NAME_LIMIT = 200                # the product's name, in the customer's own words, kept as text (D561, section 1)

# Where each path's timing starts, by how the stop was fired.
# CUSTOMER TEXT: for the founder's approval (D561)
FROM_THE_KITS_CALL = "the kit's firing call"
# CUSTOMER TEXT: for the founder's approval (D561)
FROM_THE_CHANGE_SEEN = "the change the kit saw"
# CUSTOMER TEXT: for the founder's approval (D561)
FROM_YOUR_MARK = "your mark"
TIMING_FROM = (FROM_THE_KITS_CALL, FROM_THE_CHANGE_SEEN, FROM_YOUR_MARK)

# Every field, by where it sits, and whether it identifies (sealed when submitted) or stays readable: version 1, as the
# kit wrote it to 0.2.1, and version 2.
SHAPE_V1: dict[str, tuple[str, ...]] = {
    "": ("format", "kit", "cloud", "region", "run", "stop", "agent", "repeats", "signature"),
    "kit": ("version",),
    "run": ("began_at", "ended_at", "window_seconds", "repeats", "clock_gap_ms", "calls", "left_anything",
            "left_behind"),
    "stop": ("kind", "fired_by", "ref"),
    "agent": ("kind", "runtime", "memory_mb", "private_network", "ref", "role_ref"),
    "repeat.path": ("fired_at", "last_success_after", "first_refused_after", "outcome"),
    "signature": ("alg", "public_key", "value"),
}
IDENTIFYING_V1 = ("stop.ref", "agent.ref", "agent.role_ref", "run.left_behind")
SHAPE: dict[str, tuple[str, ...]] = {
    **SHAPE_V1,
    "run": (*SHAPE_V1["run"], "via", "timing_from"),
    "stop": (*SHAPE_V1["stop"], "product"),
    "stop.product": ("kind", "attachment", "name"),     # or null, where the stop is not a product's control
    "repeat.path": (*SHAPE_V1["repeat.path"], "failed_before_stop"),
}
IDENTIFYING = (*IDENTIFYING_V1, "stop.product.name", "run.via")
SHAPES = {FORMAT_V1: SHAPE_V1, FORMAT: SHAPE}

# What `check` says of a version-2 result it refuses, beside what it says of any result.
# CUSTOMER TEXT: for the founder's approval (D561)
REFUSALS = {
    "product": "the stop's product is a kind and attachment the format names, with a name of 1 to 200 characters",
    "product_control": ("a stop is a product's control exactly where it names a product, and is fired by your own "
                        "trigger"),
    "via": "a gateway's address is given only for a gateway, as text, with no user name or password",
    "timing_from": "where the timing starts is said, and is the one that goes with how the stop was fired",
    "before_stop": ("a path that failed before the stop is not run, or through a product not measured, and only such "
                    "a path is"),
}


class NotAResult(ValueError):
    """What was offered is not a stop-test-result/2 or /1, or its signature does not check."""


def iso(t: float | None) -> str | None:
    """Seconds since the epoch as an ISO 8601 UTC time to the millisecond, or None."""
    if t is None:
        return None
    from datetime import datetime, timezone
    return datetime.fromtimestamp(t, tz=timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def without_credentials(address: str) -> str:
    """A gateway's address with any user name and password taken out (D595): what is before the last "@" of its
    authority goes, and nothing else changes. `https://user:pass@gw.example:8443` is `https://gw.example:8443`."""
    parts = urllib.parse.urlsplit(address)
    return urllib.parse.urlunsplit(parts._replace(netloc=parts.netloc.rpartition("@")[2]))


def has_credentials(address: str) -> bool:
    return "@" in urllib.parse.urlsplit(address).netloc


def timing_from(fired_by: str, product: Mapping[str, Any] | None) -> str:
    """Where each path's timing starts: a product's control is fired by the customer after their mark; else the kit's
    own call, or the change the kit saw of the customer's own trigger."""
    return FROM_YOUR_MARK if product else FROM_THE_KITS_CALL if fired_by == "the kit" else FROM_THE_CHANGE_SEEN


def path_part(r: PathResult, fired_at: float | None) -> dict[str, Any]:
    """One path's part: its own firing moment where it has one (revoking sessions fires on two roles), else its
    repeat's."""
    return {"fired_at": iso(r.fired_at if r.fired_at is not None else fired_at),
            "last_success_after": iso(r.last_success_after),
            "first_refused_after": iso(r.first_failure_after), "outcome": r.outcome,
            "failed_before_stop": bool(r.failed_before_stop)}


def build(*, kit_version: str, cloud: str, region: str, began_at: float, ended_at: float, window: float,
          clock_gap_ms: int, calls: int, left_behind: list[str], stop_kind: str, fired_by: str, stop_ref: str,
          agent: Mapping[str, Any], repeats: list[tuple[float | None, Mapping[str, PathResult]]],
          product: Mapping[str, Any] | None = None, via: str | None = None) -> dict[str, Any]:
    """The unsigned result. `repeats` is each repeat's firing moment and each path's result, in the paths' order. A
    gateway's address is written without any user name or password."""
    return {
        "format": FORMAT, "kit": {"version": kit_version}, "cloud": cloud, "region": region,
        "run": {"began_at": iso(began_at), "ended_at": iso(ended_at), "window_seconds": int(window),
                "repeats": len(repeats), "clock_gap_ms": int(clock_gap_ms), "calls": int(calls),
                "left_anything": bool(left_behind), "left_behind": sorted(left_behind),
                "via": without_credentials(via) if via else None, "timing_from": timing_from(fired_by, product)},
        "stop": {"kind": stop_kind, "fired_by": fired_by, "ref": stop_ref,
                 "product": {k: product[k] for k in SHAPE["stop.product"]} if product else None},
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


def _exactly(d: Any, where: str, shape: Mapping[str, tuple[str, ...]] = SHAPE) -> None:
    keys = shape[where]
    if not isinstance(d, dict) or set(d) != set(keys):
        raise NotAResult(f"{where or 'the result'} holds exactly {', '.join(keys)}")


def _check_v2(doc: dict[str, Any]) -> None:
    """What version 2 adds, each part consistent with the rest: the product, the gateway's address, where the timing
    starts, and each path that failed before the stop."""
    stop, run = doc["stop"], doc["run"]
    product = stop["product"]
    if product is not None:
        _exactly(product, "stop.product")
        name = product["name"]
        if product["kind"] not in PRODUCTS or product["attachment"] not in PRODUCTS[product["kind"]] or \
                not isinstance(name, str) or not 0 < len(name) <= NAME_LIMIT:
            raise NotAResult(REFUSALS["product"])
    if (product is not None) != (stop["kind"] == PRODUCT_CONTROL) or \
            (product is not None and stop["fired_by"] != "your own trigger"):
        raise NotAResult(REFUSALS["product_control"])
    via = run["via"]
    if via is not None and (not isinstance(via, str) or product is None or product["kind"] != GATEWAY
                            or has_credentials(via)):
        raise NotAResult(REFUSALS["via"])
    if run["timing_from"] != timing_from(stop["fired_by"], product):
        raise NotAResult(REFUSALS["timing_from"])
    untried = NOT_MEASURED if product is not None else NOT_RUN
    for repeat in doc["repeats"]:
        for part in repeat.values():
            failed = part["failed_before_stop"]
            if not isinstance(failed, bool) or (failed and part["outcome"] != untried) or \
                    (part["outcome"] == NOT_MEASURED and not failed):
                raise NotAResult(REFUSALS["before_stop"])


def check(doc: Any) -> dict[str, Any]:
    """The result, if it is a stop-test-result/2 or /1 in exactly its version's shape and its signature checks; else
    NotAResult."""
    if not isinstance(doc, dict) or doc.get("format") not in SHAPES:
        raise NotAResult(f"the result is not {FORMAT}, or {FORMAT_V1}")
    shape = SHAPES[doc["format"]]
    _exactly(doc, "", shape)
    for part in ("kit", "run", "stop", "agent", "signature"):
        _exactly(doc[part], part, shape)
    if doc["stop"]["fired_by"] not in FIRED_BY:
        raise NotAResult(f"the stop was fired by one of {', '.join(FIRED_BY)}")
    if not isinstance(doc["repeats"], list) or len(doc["repeats"]) != doc["run"]["repeats"] or not doc["repeats"]:
        raise NotAResult("the repeats are a list, as many as the run says")
    outcomes = OUTCOMES if shape is SHAPE else OUTCOMES_V1
    for i, repeat in enumerate(doc["repeats"]):
        if not isinstance(repeat, dict) or not set(repeat) <= set(PATHS) or not repeat:
            raise NotAResult(f"repeat {i} names only the kit's paths")
        for path, part in repeat.items():
            _exactly(part, "repeat.path", shape)
            if part["outcome"] not in outcomes:
                raise NotAResult(f"repeat {i}'s {path} has an outcome the rule does not give")
    if doc["run"]["left_anything"] != bool(doc["run"]["left_behind"]):
        raise NotAResult("the run says something was left exactly where it names what")
    if shape is SHAPE:
        _check_v2(doc)
    sig = doc["signature"]
    if sig["alg"] != "ed25519":
        raise NotAResult("the signature is ed25519")
    try:
        public = Ed25519PublicKey.from_public_bytes(base64.b64decode(sig["public_key"], validate=True))
        public.verify(base64.b64decode(sig["value"], validate=True), canonical(doc))
    except (InvalidSignature, ValueError) as e:
        raise NotAResult("the signature does not check: the file has changed since the kit wrote it") from e
    return doc
