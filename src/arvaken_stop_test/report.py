"""The page a run writes beside its result, for the customer's own machine (the design's section 8).

It shows each path's outcome in the stop map's words, beside what the stop map predicts for a stop on the agent's role,
and what the result file does not carry because it stays here: the errors seen, by their codes. It is one HTML file
with nothing loaded from anywhere, and it is never sent.
"""
from __future__ import annotations

import html
from collections.abc import Mapping
from typing import Any

from datetime import datetime, timezone

from arvaken_stop_test.result import GATEWAY_ROUTES
from arvaken_stop_test.timing import PATH_WORDS, PathResult, worded


def _clock(t: float) -> str:
    return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%H:%M:%S UTC")


def _found(f: PathResult) -> str:
    """What the page adds to an outcome: where it stopped, when, as a range, and whether it was stopped at its first
    refusal; where a session was not stopped, until when it keeps working."""
    said = []
    if f.effect_between:
        low, high = f.effect_between
        said.append(f"took effect {low:.1f} to {high:.1f} seconds after the stop was fired")
    if f.first_failure_after is not None:
        said.append(f"{f.successes_after_first_refusal} successful call(s) after its first refusal"
                    + ("" if not f.successes_after_first_refusal else ": not yet stopped at its first refusal"))
    if f.keeps_working_until:
        said.append(f"keeps working until {_clock(f.keeps_working_until)}, when its session expires")
    return "; ".join(said)

# What a stop on the agent's own role would be expected to reach (the design's section 4). Revoking sessions is put on
# the role the agent became as well, so it is expected to reach that path too; it denies sessions issued before its
# moment, and a session issued afterwards is unaffected (the founder's README changes, 24 October 2026).
EXPECTED = {"own_calls": "stopped", "another_identity": "not stopped", "outside_key": "not stopped",
            "open_internet": "not stopped", "model": "stopped"}
REVOKE_KIND = "revoke active sessions"
REVOKE_NOTE = ("Revoking sessions denies the sessions issued before the moment it names. A session issued afterwards is "
               "unaffected, so what is expected here is of the sessions the test agent held when the stop was fired.")


EXPECTED_HEADING = "A stop on its role would be expected"
# Through a gateway (--via; D561), only the calls its declared attachment covers are sent through it (result.
# GATEWAY_ROUTES; the founder's condition a, 28 October 2026), so its switch would be expected to stop those paths, and
# not the others, which go directly; a path that did not work through it before the stop, or was already refused at
# the mark, is "not measured".
PRODUCT_KIND = "a product's control"
# CUSTOMER TEXT: approved by the founder, 04:23:21 UTC on 27 October 2026 (D602)
GATEWAY_HEADING = "A stop of your gateway would be expected"
# CUSTOMER TEXT: approved by the founder, 04:23:21 UTC on 27 October 2026 (D602)
GATEWAY_NOTE = ("Your stop: {name}, a gateway attached to {attachment}. Every call the test agent made went through "
                "your gateway at {via}.")
# CUSTOMER TEXT: approved by the founder, by 17:10:22 UTC on 28 October 2026 (his ten lines)
GATEWAY_NOTE_SOME = ("Your stop: {name}, a gateway attached to {attachment}. The test agent's calls it covers "
                     "({paths}) went through your gateway at {via}. Its other calls went directly.")
# CUSTOMER TEXT: approved by the founder, by 17:10:22 UTC on 28 October 2026 (his ten lines)
ALREADY_REFUSED_NOTE = "A path already refused at your mark is not measured either."
# CUSTOMER TEXT: approved by the founder, 04:23:21 UTC on 27 October 2026 (D602)
MARK_NOTE = ("You fired your stop yourself, after your mark. Each time here is from your mark, the moment you pressed "
             "Enter, so it errs toward slower, never faster. A path that did not work through your gateway before the "
             "stop is not measured, never stopped.")
# CUSTOMER TEXT: approved by the founder, 04:23:21 UTC on 27 October 2026 (D602)
NETWORK_NOTE = "The test agent ran in your subnet {subnet}, with your security group(s) {groups}."
# CUSTOMER TEXT: approved by the founder, 04:23:21 UTC on 27 October 2026 (D602)
INTERFACES_NOTE = "Its network interfaces there: {interfaces}. Checked gone: {gone}. Still there: {left}."
# CUSTOMER TEXT: approved by the founder, 04:23:21 UTC on 27 October 2026 (D602)
NO_INTERFACES_NOTE = "The kit found no network interface of the test agent's own in your subnet."
# CUSTOMER TEXT: approved by the founder, word for word, 22:40 UTC on 30 October 2026, shown below the table only where
# a heartbeat was lost
LOST_NOTE = ("The kit got no answer to {count} of its heartbeats to the test agent ({codes}): the network failed or "
             "timed out on the way there or back. No path has a result from them.")


def expected(kind: str, path: str, attachment: str | None = None) -> str:
    """What the declared stop would be expected to do on a path: through a gateway, by how it is attached."""
    if kind == PRODUCT_KIND:
        return "stopped" if path in GATEWAY_ROUTES.get(attachment or "", ()) else "not stopped"
    return "stopped" if kind == REVOKE_KIND and path == "another_identity" else EXPECTED[path]


def _gateway(doc: Mapping[str, Any]) -> str:
    """Through a gateway: the product, as the customer named it, and the gateway's address, as the result keeps it."""
    product = doc["stop"].get("product")
    if not product:
        return ""
    via = doc["run"].get("via") or ""
    routes = GATEWAY_ROUTES.get(product["attachment"], ())
    said = GATEWAY_NOTE.format(name=product["name"], attachment=product["attachment"], via=via) \
        if product["attachment"] == "all its outbound traffic" else \
        GATEWAY_NOTE_SOME.format(name=product["name"], attachment=product["attachment"], via=via,
                                 paths=", ".join(PATH_WORDS[p] for p in routes
                                                 if any(p in rep for rep in doc["repeats"])))
    return f"<p>{html.escape(said)}</p>\n<p>{html.escape(MARK_NOTE + ' ' + ALREADY_REFUSED_NOTE)}</p>\n"


def _network(network: Mapping[str, Any] | None) -> str:
    """In a subnet of yours: it, and the test agent's network interfaces the kit found there, gone or still there."""
    if not network:
        return ""
    said = NETWORK_NOTE.format(subnet=network["subnet"], groups=", ".join(network["security_groups"]))
    ids = lambda key: ", ".join(network[key]) or "none"  # noqa: E731
    said += " " + (INTERFACES_NOTE.format(interfaces=ids("interfaces"), gone=ids("gone"), left=ids("left"))
                   if network["interfaces"] else NO_INTERFACES_NOTE)
    return f"<p>{html.escape(said)}</p>\n"


def _lost(lost: Mapping[str, int] | None) -> str:
    """The heartbeats the kit got no answer to, by code (the details' heartbeats_lost): how many and why; or nothing."""
    if not lost:
        return ""
    codes = ", ".join(f"{code} {n}" for code, n in sorted(lost.items()))
    return f"<p>{html.escape(LOST_NOTE.format(count=sum(lost.values()), codes=codes))}</p>\n"


def _source(details: list[Mapping[str, PathResult]] | None) -> str:
    sources = sorted({f.fired_source for d in details or [] for f in d.values() if f.fired_source})
    if not sources:
        return ""
    return ("Each firing moment is from " + "; and from ".join(sources) + ". A range runs from the last success before "
            "the stop, less that moment's precision, to the first refusal that it held from.")


def _refused(details: list[Mapping[str, PathResult]] | None) -> str:
    """Where Lambda refused to run the test agent: that, and what it means for every path."""
    from arvaken_stop_test.aws.run import REFUSED
    codes = sorted({code.removeprefix(REFUSED) for d in details or [] for f in d.values() for code in f.errors
                    if code.startswith(REFUSED)})
    if not codes:
        return ""
    # CUSTOMER TEXT: approved by the founder, word for word, 30 October 2026 (his refusal ruling of 29 October
    # changed what counts)
    said = (f"Lambda refused to run the test agent ({', '.join(codes)}). While it refused, the agent made no call on "
            "any path. Each path counts KMSAccessDeniedException as refused where it first came after the stop and the "
            "agent ran before it, and no other refusal of Lambda's.")
    if "KMSAccessDeniedException" in codes:
        said += (" Lambda gives KMSAccessDeniedException when it cannot decrypt the agent's environment as the agent's "
                 "role, as when a stop on the role denies it while Lambda starts a new environment for the agent.")
    return said


def page(doc: Mapping[str, Any], details: list[Mapping[str, PathResult]] | None = None,
         network: Mapping[str, Any] | None = None, lost: Mapping[str, int] | None = None) -> str:
    """The page. `network` is what a run in a subnet of yours made there (aws/run.py's network); `lost`, the heartbeats
    the kit got no answer to, by code (the details' heartbeats_lost)."""
    window = float(doc["run"]["window_seconds"])
    attachment = (doc["stop"].get("product") or {}).get("attachment")
    rows = []
    for i, repeat in enumerate(doc["repeats"]):
        for path, part in repeat.items():
            expected_here = worded(expected(doc["stop"]["kind"], path, attachment), window)
            actual = worded(part["outcome"], window)
            errors = ""
            if details and i < len(details) and path in details[i]:
                found = details[i][path]
                counted = {code: n - found.not_counted.get(code, 0) for code, n in found.errors.items()}
                errors = ", ".join(f"{code} {n}" for code, n in sorted(counted.items()) if n)
                if found.not_counted:
                    # CUSTOMER TEXT: approved by the founder, word for word, 30 October 2026
                    rest = ", ".join(f"{code} {n}" for code, n in sorted(found.not_counted.items()))
                    errors = f"{errors}; not counted: {rest}" if errors else f"not counted: {rest}"
                if found.reason and part["outcome"] in ("not run", "not measured"):
                    errors = f"{found.reason}: {errors}" if errors else found.reason
            mark = "" if expected(doc["stop"]["kind"], path, attachment) == part["outcome"] else ' class="differs"'
            if details and i < len(details) and path in details[i] and _found(details[i][path]):
                actual = f"{actual} ({_found(details[i][path])})"
            rows.append(f"<tr{mark}><td>{i + 1}</td><td>{html.escape(PATH_WORDS[path])}</td>"
                        f"<td>{html.escape(expected_here)}</td><td>{html.escape(actual)}</td>"
                        f"<td>{html.escape(part['first_refused_after'] or '')}</td><td>{html.escape(errors)}</td></tr>")
    left = ("Nothing the kit made was left." if not doc["run"]["left_anything"] else
            "Left for you to delete: " + ", ".join(html.escape(x) for x in doc["run"]["left_behind"]))
    heading = GATEWAY_HEADING if doc["stop"]["kind"] == PRODUCT_KIND else EXPECTED_HEADING
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Stop test {html.escape(doc['run']['began_at'] or '')}</title>
<style>body{{font:15px/1.5 system-ui,sans-serif;max-width:60rem;margin:2rem auto;padding:0 1rem}}
table{{border-collapse:collapse;width:100%}}td,th{{border-bottom:1px solid #ccc;padding:.4rem;text-align:left}}
tr.differs td{{font-weight:600}}</style></head><body>
<h1>Your stop test</h1>
<p>Run on {html.escape(doc['cloud'])} in {html.escape(doc['region'])}, from {html.escape(doc['run']['began_at'] or '')}
to {html.escape(doc['run']['ended_at'] or '')}. The stop was fired by {html.escape(doc['stop']['fired_by'])}.
The window was {html.escape(worded('not stopped', window).removeprefix('not stopped within '))}; the kit's clock and the
test agent's were {doc['run']['clock_gap_ms']} ms apart.</p>
{_gateway(doc)}{_network(network)}<table><thead><tr><th>Repeat</th><th>Path</th><th>{html.escape(heading)}</th>
<th>What the test found</th><th>First refused</th><th>Errors seen (this page only)</th></tr></thead><tbody>
{''.join(rows)}
</tbody></table>
{_lost(lost)}<p>{left}</p>
<p>{html.escape(REVOKE_NOTE) if doc['stop']['kind'] == REVOKE_KIND else ''}</p>
<p>{html.escape(_refused(details))}</p>
<p>{html.escape(_source(details))}</p>
<p>This page stays on your machine. The result file beside it holds no error codes and nothing of your agents'
work.</p>
</body></html>
"""
