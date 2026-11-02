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

**Version 2 (D561, section 5; the kit's terms v4, D595, numbered v2 until D615 and v3 until D625)** adds exactly what
those terms add, for a declared stop that is a product's control: the product's kind and how it is attached, kept in
clear as kinds of stop are; and the product's name and the gateway's address, which identify and are sealed when
submitted. Nothing else: where the timing starts follows from the stop (a product's control is always timed from the
customer's mark, so a time errs toward slower, never faster), and a path that did not work through the gateway before
the stop is its outcome, "not measured" (never "stopped"). Version 2 carries "not measured" on a path of any kind of
stop (the founder, 29 October 2026), as version 1 never does.

**A gateway's address is written as its scheme, host and port alone** (port as given, or none): any user name,
password, path, query and fragment are dropped before it is written or printed (the founder, D595, and the legal
track's suggestion, adopted: the terms' 3.4, "It carries no password: the kit keeps a gateway's address without any
user name or password in it."). `check` refuses an address with anything more.

**What the signature proves:** that the file has not changed since it was signed. Not that the kit wrote it, who ran
it, or that the run was honest (the terms' 3.3; the founder's README wording, 24 October 2026).
"""
from __future__ import annotations

import base64
import hashlib
import json
import urllib.parse
from collections import Counter
from collections.abc import Mapping
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from arvaken_stop_test.timing import FLAPPED, NOT_MEASURED, NOT_RUN, NOT_STOPPED, PATHS, STOPPED, Beat, PathResult

FORMAT = "stop-test-result/2"
FORMAT_V1 = "stop-test-result/1"
# "Not measured" on a path of any kind of stop (the founder, 29 October 2026). The kit's terms keep each path's outcome
# without listing the outcomes (4.4), which the founder ruled is enough (30 October 2026). A stop-test-result/1 never
# carries it, as no kit to 0.2.1 gave it and Arvaken's record refuses it there: a release writes it only in a later
# format (tests/test_result.py, under STOP_TEST_RELEASE), and `check` refuses it in a /1.
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
# Which of the test agent's paths each of a gateway's attachments sends through it (the founder's condition a, 28
# October 2026: "Only calls the declared attachment covers go through --via"): a call to a model; the calls to a
# service outside the cloud, with a key and with none (Arvaken's test address); or every call. The others go directly,
# as the customer's agents' would. An attachment that covers none of a run's calls is not taken (cli.py, aws/run.py).
GATEWAY_ROUTES: dict[str, tuple[str, ...]] = {
    "its calls to a model": ("model",),
    "its calls to outside services": ("outside_key", "open_internet"),
    "all its outbound traffic": PATHS,
}
NAME_LIMIT = 200                # the product's name, in the customer's own words, kept as text (D561, section 1)
SCHEMES = ("http", "https")     # a gateway's address: an HTTPS proxy's, reached over either

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
    "run": (*SHAPE_V1["run"], "via"),                   # the gateway's address, or null
    "stop": (*SHAPE_V1["stop"], "product"),
    "stop.product": ("kind", "attachment", "name"),     # or null, where the stop is not a product's control
}
IDENTIFYING = (*IDENTIFYING_V1, "stop.product.name", "run.via")

# **Version 3** (D575, a test agent the customer chooses; the kit's terms v5, D721) adds exactly what those terms add.
# Readable (4.4): whose test agent it was; for a test copy of yours, the kinds of its tools and of its model, chosen from
# the kit's lists (KC3, D710), and whether the probe used your own clients or the runtime's, for its cloud calls and its
# web calls apart (KC2, D710); for an SDK's switch (D713, D714), the time of the entry you chose in the SDK's record,
# and whether each path was timed from it or from your mark. Sealed (4.2): that entry's name and the SHA-256 of the file
# it came from, beside every identifier the result already seals (the copy's ARN among them, as agent.ref). The kit's
# own test agent's runs write version 2, as before; a run on a copy of yours writes version 3.
FORMAT_V3 = "stop-test-result/3"
# CUSTOMER TEXT: approved by the founder, word for word, by 19:02:12 UTC on 1 November 2026 (D710, KC3)
TOOL_KINDS = ("no tools", "searches or reads the web", "runs code", "reads or writes files", "reads or writes a database",
              "sends email or messages", "makes payments", "changes cloud resources", "calls other services' APIs",
              "something else")
# CUSTOMER TEXT: approved by the founder, word for word, by 19:02:12 UTC on 1 November 2026 (D710, KC3)
MODEL_KINDS = ("no model", "a model service of its cloud", "a model provider's API", "a model it runs itself")
# CUSTOMER TEXT: a draft, for the founder's approval with D575's customer words (step 4)
WHOSE = ("the kit's", "yours")
# CUSTOMER TEXT: a draft, for the founder's approval with D575's customer words (step 4)
CLIENTS = ("yours", "the runtime's")
# CUSTOMER TEXT: a draft, for the founder's approval with D713's build
TIMED_FROM = ("your SDK's own record", "your mark")
SDK_KIND = "in-agent SDK"
SHAPE_V3: dict[str, tuple[str, ...]] = {
    **SHAPE,
    "agent": (*SHAPE["agent"], "whose", "tools", "model_kind", "clients"),
    "agent.clients": ("cloud", "http"),                 # or null, for the kit's own test agent
    "stop": (*SHAPE["stop"], "record"),
    "stop.record": ("time", "name", "sha256"),          # or null, where the stop is not an SDK's switch
    "repeat.path": (*SHAPE["repeat.path"], "timed_from"),   # for an SDK's switch; else null
}
IDENTIFYING_V3 = (*IDENTIFYING, "stop.record.name", "stop.record.sha256")
SHAPES = {FORMAT_V1: SHAPE_V1, FORMAT: SHAPE, FORMAT_V3: SHAPE_V3}

# What `check` says of a version-2 result it refuses, beside what it says of any result.
# CUSTOMER TEXT: approved by the founder, 04:23:21 UTC on 27 October 2026 (D602)
REFUSALS = {
    "product": "the stop's product is a kind and attachment the format names, with a name of 1 to 200 characters",
    "product_control": ("a stop is a product's control exactly where it names a product, and is fired by your own "
                        "trigger"),
    "via": "a gateway's address is given only for a gateway, as its scheme, host and port alone",
}
# What `check` says of a version-3 result it refuses.
# CUSTOMER TEXT: a draft, for the founder's approval with D575's customer words (step 4)
REFUSALS_V3 = {
    "whose": ("a test agent is the kit's, with no tools, model kind or clients given, or yours, with its tools' and "
              "model's kinds from the kit's lists and its clients for each kind of call"),
    "record": ("an SDK's own record is given only where the stop is an SDK's switch, with its entry's time, its name "
               "of 1 to 200 characters and its file's SHA-256"),
    "timed_from": "each path of an SDK's switch is timed from its own record or from your mark, and no other's is",
}


class NotAResult(ValueError):
    """What was offered is not a stop-test-result/2 or /1, or its signature does not check."""


def iso(t: float | None) -> str | None:
    """Seconds since the epoch as an ISO 8601 UTC time to the millisecond, or None."""
    if t is None:
        return None
    from datetime import datetime, timezone
    return datetime.fromtimestamp(t, tz=timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def gateway_address(address: str) -> str:
    """A gateway's address as the kit keeps it: its scheme, host and port alone, the port as given, or none (D595).
    Any user name and password (what is before the last "@" of its authority), path, query and fragment are dropped.
    `https://user:pass@gw.example:8443/p?token=x#f` is `https://gw.example:8443`."""
    parts = urllib.parse.urlsplit(address)
    return f"{parts.scheme}://{parts.netloc.rpartition('@')[2]}"


def is_gateway_address(address: Any) -> bool:
    """Whether this is an address as the kit keeps one: http or https, a host, and nothing beyond its port."""
    if not isinstance(address, str):
        return False
    try:
        parts = urllib.parse.urlsplit(address)
        return parts.scheme in SCHEMES and bool(parts.hostname) and gateway_address(address) == address and \
            (parts.port or 1) > 0
    except ValueError:
        return False


def path_part(r: PathResult, fired_at: float | None) -> dict[str, Any]:
    """One path's part: its own firing moment where it has one (revoking sessions fires on two roles), else its
    repeat's."""
    return {"fired_at": iso(r.fired_at if r.fired_at is not None else fired_at),
            "last_success_after": iso(r.last_success_after),
            "first_refused_after": iso(r.first_failure_after), "outcome": r.outcome}


FAILURE_RECORD = ("at", "step", "code", "status", "reason", "reason_given", "provider_status", "token_issued",
                  "token_expires", "versions", "counted")


def failure_record(b: Beat, counted: bool) -> dict[str, Any]:
    """One failed call's record, for the details beside the result, never the result itself (D532: the result holds no
    error codes), with every field of FAILURE_RECORD (D646, item 4: the founder, 29 October 2026). Where the provider's
    error gave no reason, the reason is empty and the record says none was given (his answer of 30 October 2026). Where
    there is no status, nothing answered; where no token's times, the call used none, or the agent is not told them.
    Its versions are the Python, botocore and urllib3 the agent ran on, where it names them (D655, (a))."""
    return {"at": iso(b.at), "step": b.step, "code": b.error or "unknown", "status": b.status, "reason": b.reason,
            "reason_given": b.reason is not None, "provider_status": b.provider_status,
            "token_issued": iso(b.token_issued), "token_expires": iso(b.token_expires),
            "versions": list(b.versions) if b.versions else None, "counted": counted}


def failure_records(r: PathResult) -> list[dict[str, Any]]:
    """Each failure after the stop on a path, in order, with whether it counted as the stop's refusal."""
    refused = set(r.refused)
    return [failure_record(b, i in refused) for i, b in enumerate(r.failures)]


def heartbeats_lost(lost: list[tuple[float, str]]) -> dict[str, Any]:
    """The heartbeats a run could not complete, for its details: how many by code, and each one's moment, on the agent's
    clock, with its code. None of them is a beat of any path (aws/run.py's and google/run.py's heartbeat)."""
    return {"by_code": dict(Counter(code for _, code in lost)),
            "each": [{"at": iso(at), "code": code} for at, code in sorted(lost)]}


def build(*, kit_version: str, cloud: str, region: str, began_at: float, ended_at: float, window: float,
          clock_gap_ms: int, calls: int, left_behind: list[str], stop_kind: str, fired_by: str, stop_ref: str,
          agent: Mapping[str, Any], repeats: list[tuple[float | None, Mapping[str, PathResult]]],
          product: Mapping[str, Any] | None = None, via: str | None = None,
          copy: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """The unsigned result. `repeats` is each repeat's firing moment and each path's result, in the paths' order. A
    gateway's address is written as its scheme, host and port alone. With `copy` (a run on a test copy of yours), it is
    a version-3 result: `copy` holds its tools' kinds, its model's kind, its clients by kind, and for an SDK's switch
    the SDK's own record (its entry's time, its name and its file's SHA-256)."""
    doc = {
        "format": FORMAT, "kit": {"version": kit_version}, "cloud": cloud, "region": region,
        "run": {"began_at": iso(began_at), "ended_at": iso(ended_at), "window_seconds": int(window),
                "repeats": len(repeats), "clock_gap_ms": int(clock_gap_ms), "calls": int(calls),
                "left_anything": bool(left_behind), "left_behind": sorted(left_behind),
                "via": gateway_address(via) if via else None},
        "stop": {"kind": stop_kind, "fired_by": fired_by, "ref": stop_ref,
                 "product": {k: product[k] for k in SHAPE["stop.product"]} if product else None},
        "agent": {k: agent[k] for k in SHAPE["agent"]},
        "repeats": [{p: path_part(paths[p], fired_at) for p in PATHS if p in paths} for fired_at, paths in repeats],
    }
    if copy is None:
        return doc
    sdk_switch = bool(product) and product["kind"] == SDK_KIND
    record = copy.get("record")
    doc["format"] = FORMAT_V3
    doc["agent"].update(whose=WHOSE[1], tools=list(copy["tools"]), model_kind=copy["model_kind"],
                        clients={k: copy["clients"][k] for k in SHAPE_V3["agent.clients"]})
    doc["stop"]["record"] = {k: record[k] for k in SHAPE_V3["stop.record"]} if record else None
    for part in doc["repeats"]:         # every path of an SDK's switch is timed from your mark (step 4, batch 3)
        for found in part.values():
            found["timed_from"] = TIMED_FROM[1] if sdk_switch else None
    return doc


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
    """What version 2 adds, each part consistent with the rest: the product and the gateway's address."""
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
    if via is not None and (product is None or product["kind"] != GATEWAY or not is_gateway_address(via)):
        raise NotAResult(REFUSALS["via"])


def _check_v3(doc: dict[str, Any]) -> None:
    """What version 3 adds, each part consistent with the rest: whose test agent, its kinds and clients; the SDK's own
    record, exactly for an SDK's switch; and each path's timing source, exactly for one."""
    import re
    agent, stop = doc["agent"], doc["stop"]
    if agent["whose"] == WHOSE[0]:
        if agent["tools"] is not None or agent["model_kind"] is not None or agent["clients"] is not None:
            raise NotAResult(REFUSALS_V3["whose"])
    elif agent["whose"] == WHOSE[1]:
        tools = agent["tools"]
        if not isinstance(tools, list) or not tools or len(set(tools)) != len(tools) or \
                not set(tools) <= set(TOOL_KINDS) or (TOOL_KINDS[0] in tools and len(tools) > 1) or \
                agent["model_kind"] not in MODEL_KINDS:
            raise NotAResult(REFUSALS_V3["whose"])
        _exactly(agent["clients"], "agent.clients", SHAPE_V3)
        if not all(v in CLIENTS for v in agent["clients"].values()):
            raise NotAResult(REFUSALS_V3["whose"])
    else:
        raise NotAResult(REFUSALS_V3["whose"])
    sdk_switch = stop["product"] is not None and stop["product"]["kind"] == SDK_KIND
    record = stop["record"]                 # for an SDK's switch, or null where you gave none (then not measured)
    if record is not None and not sdk_switch:
        raise NotAResult(REFUSALS_V3["record"])
    if record is not None:
        _exactly(record, "stop.record", SHAPE_V3)
        name, digest = record["name"], record["sha256"]
        if not isinstance(record["time"], str) or not isinstance(name, str) or not 0 < len(name) <= NAME_LIMIT or \
                not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise NotAResult(REFUSALS_V3["record"])
    from arvaken_stop_test.sdk import SDK_STOPPED
    # stopped by its rule, not stopped, stopped then succeeded again, not run, else not measured (step 4, batch 4)
    sdk_outcomes = (SDK_STOPPED, NOT_STOPPED, FLAPPED, NOT_MEASURED, NOT_RUN)
    for repeat in doc["repeats"]:
        for part in repeat.values():
            if part["timed_from"] != (TIMED_FROM[1] if sdk_switch else None):     # from your mark, for an SDK's
                raise NotAResult(REFUSALS_V3["timed_from"])
            if (part["outcome"] in sdk_outcomes) != sdk_switch and (sdk_switch or part["outcome"] == SDK_STOPPED):
                raise NotAResult("an SDK's switch has its own outcomes, and no other stop has them")


def check(doc: Any) -> dict[str, Any]:
    """The result, if it is a stop-test-result/3, /2 or /1 in exactly its version's shape and its signature checks;
    else NotAResult."""
    if not isinstance(doc, dict) or doc.get("format") not in SHAPES:
        raise NotAResult(f"the result is not {FORMAT_V3}, {FORMAT}, or {FORMAT_V1}")
    shape = SHAPES[doc["format"]]
    _exactly(doc, "", shape)
    for part in ("kit", "run", "stop", "agent", "signature"):
        _exactly(doc[part], part, shape)
    if doc["stop"]["fired_by"] not in FIRED_BY:
        raise NotAResult(f"the stop was fired by one of {', '.join(FIRED_BY)}")
    if not isinstance(doc["repeats"], list) or len(doc["repeats"]) != doc["run"]["repeats"] or not doc["repeats"]:
        raise NotAResult("the repeats are a list, as many as the run says")
    from arvaken_stop_test.sdk import SDK_STOPPED
    outcomes = {id(SHAPE_V1): OUTCOMES_V1, id(SHAPE): OUTCOMES, id(SHAPE_V3): (*OUTCOMES, SDK_STOPPED)}[id(shape)]
    for i, repeat in enumerate(doc["repeats"]):
        if not isinstance(repeat, dict) or not set(repeat) <= set(PATHS) or not repeat:
            raise NotAResult(f"repeat {i} names only the kit's paths")
        for path, part in repeat.items():
            _exactly(part, "repeat.path", shape)
            if part["outcome"] not in outcomes:
                raise NotAResult(f"repeat {i}'s {path} has an outcome the rule does not give")
    if doc["run"]["left_anything"] != bool(doc["run"]["left_behind"]):
        raise NotAResult("the run says something was left exactly where it names what")
    if shape is not SHAPE_V1:
        _check_v2(doc)
    if shape is SHAPE_V3:
        _check_v3(doc)
    sig = doc["signature"]
    if sig["alg"] != "ed25519":
        raise NotAResult("the signature is ed25519")
    try:
        public = Ed25519PublicKey.from_public_bytes(base64.b64decode(sig["public_key"], validate=True))
        public.verify(base64.b64decode(sig["value"], validate=True), canonical(doc))
    except (InvalidSignature, ValueError) as e:
        raise NotAResult("the signature does not check: the file has changed since the kit wrote it") from e
    return doc
