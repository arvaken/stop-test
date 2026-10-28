"""A sentence that says or implies a cloud provider documents a behaviour names its source, or the build fails.

The founder's ruling of 28 October 2026, item 6, in his words: "New check, all clouds: any sentence, Why? text or
rationale that says or implies the cloud provider documents a behaviour must carry, in the record, the page URL, the
exact quoted sentence and the date read. A test fails the build when a provider-attributed claim has no source entry."
It followed an error in Arvaken's record: a sentence of AWS's about one thing, quoted with an ellipsis, carried across
to another that AWS's pages say nothing about. This is arvaken/mark's check (mark#914,
packages/record/tests/test_provider_claims_name_their_source.py), in the kit's own shape.

The source entries are PROVIDER-SOURCES.json, at the repository's root: for each sentence quoted, its cloud, its page's
URL and title, the sentence whole, what the sentence is about in the provider's own terms, and the date it was read. A
claim cites its entries by id, `[source: id]`, in the README or in a docstring or comment, never in words a customer is
shown.

What is read: the README, and every Python file of the kit (src/), docstrings and comments alike; the tests are not. A
claim is a paragraph, list item or table row, of the README or of a file's docstrings and comments, that holds one of
ATTRIBUTIONS. A blockquote is someone's words as they said them, not a claim of ours, and is not read. A sentence is
quoted whole, never with an ellipsis.

The claims there when the check came are owed a source, in the same file: until DUE and no later. The list may shrink,
never grow; a claim on it whose words change must name its source then.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
from pathlib import Path
from urllib.parse import urlparse

REPO = Path(__file__).resolve().parents[1]
SOURCES_FILE = REPO / "PROVIDER-SOURCES.json"
# His ruling: a week, to 4 November 2026; the most claims the owed list held when the check came.
DUE = dt.date(2026, 11, 4)
OWED_AT_MOST = 0

PROVIDER = r"(?:AWS|Amazon|Google Cloud|Google|Microsoft|Azure|Entra)"
ATTRIBUTIONS = [re.compile(p, re.M) for p in (
    rf"\b{PROVIDER}(?:'s)? (?:own )?(?:documentation|docs|pages?|guides?|examples?|reference|FAQ)\b",
    rf"\b{PROVIDER} (?:says|said|documents|documented|describes|described|states|stated|writes|notes|recommends)\b",
    # the provider named as a sentence's speaker, "AWS: ...", at the start of a line, a comment, a sentence or brackets
    rf"(?:^\s*(?:#|[-+])?|[.;(]|\*\*)\s*{PROVIDER}(?: \([^)]*\))?: ",
    # and as a citation, "... (AWS)."
    rf"\({PROVIDER}\)(?=[.,:;])",
    rf"\baccording to {PROVIDER}\b",
    r"\b(?:Developer|User|Admin|Operator) Guide\b",
    r"\bAPI Reference\b",
    r"\bService Authorization Reference\b",
    r"\bMicrosoft Learn\b",
)]
# "source: a, b", its list free to run on to the next line, past a comment's leading "#" there
CITED = re.compile(r"\bsource:\s+([a-z][a-z0-9-]*(?:,\s*(?:#\s*)?[a-z][a-z0-9-]*)*)")
LEADER = re.compile(r"^\s*#?\s*")
CLOUDS = {"aws": ("amazon.com", "amazonaws.com"), "google_cloud": ("google.com",), "azure": ("microsoft.com",)}
ELLIPSIS = re.compile(r"\.\.\.|…")


def attributed(text: str) -> bool:
    return any(p.search(text) for p in ATTRIBUTIONS)


def cited(text: str) -> list[str]:
    return [LEADER.sub("", i) for m in CITED.finditer(text) for i in m.group(1).split(",")]


def fingerprint(text: str) -> str:
    """A claim's words, whitespace closed up, as the owed list holds them."""
    return hashlib.sha256(" ".join(text.split()).encode()).hexdigest()


# -- the claims --------------------------------------------------------------------------------------------------------
BEGINS = re.compile(r"^\s*(?:[-*+] |\d+\. |#|\|)")


def units_of_markdown(text: str) -> list[tuple[int, str]]:
    """Paragraphs, list items, headings and table rows, each with its first line's number; fenced code and blockquotes
    left out."""
    units: list[tuple[int, list[str]]] = []
    fenced = False
    for n, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith("```"):
            fenced = not fenced
            units.append((n, []))
            continue
        if fenced or not line.strip() or line.lstrip().startswith(">"):
            units.append((n, []))
            continue
        if BEGINS.match(line) or not units or not units[-1][1]:
            units.append((n, [line]))
        else:
            units[-1][1].append(line)
    return [(n, "\n".join(lines)) for n, lines in units if lines]


def units_of_python(text: str) -> list[tuple[int, str]]:
    """A Python file read as prose: a comment's "#" and a docstring's quotes taken off each line, so that its
    docstrings' paragraphs and list items, and its runs of comments, are units as a document's are."""
    lines = []
    for line in text.splitlines():
        line = re.sub(r'^\s*#\s?', "", line) if line.lstrip().startswith("#") else line
        lines.append(line.replace('"""', ""))
    return units_of_markdown("\n".join(lines))


def read_texts() -> list[tuple[str, str, bool]]:
    """(the file, relative to the repository; its text; whether it is Python), for every text the check reads."""
    texts = [("README.md", (REPO / "README.md").read_text(encoding="utf-8"), False)]
    for path in sorted((REPO / "src").rglob("*.py")):
        texts.append((path.relative_to(REPO).as_posix(), path.read_text(encoding="utf-8"), True))
    return texts


def claims() -> list[tuple[str, int, str]]:
    """(the file, the claim's first line, its words) for every claim that attributes a behaviour to a provider."""
    found = []
    for name, text, python in read_texts():
        for n, unit in (units_of_python(text) if python else units_of_markdown(text)):
            if attributed(unit):
                found.append((name, n, unit))
    return found


def register() -> dict:
    return json.loads(SOURCES_FILE.read_text(encoding="utf-8"))


# -- the source entries ------------------------------------------------------------------------------------------------
def test_each_source_names_its_page_its_sentence_whole_and_the_day_it_was_read():
    today = dt.datetime.now(dt.timezone.utc).date()
    bad = []
    for key, s in register()["sources"].items():
        host = urlparse(s.get("url", "")).hostname or ""
        if not re.fullmatch(r"[a-z][a-z0-9-]*", key):
            bad.append(f"{key}: an id is a letter, then lower case, digits and hyphens")
        if s.get("cloud") not in CLOUDS:
            bad.append(f"{key}: cloud is one of {sorted(CLOUDS)}")
        elif not (s["url"].startswith("https://") and any(host == h or host.endswith("." + h)
                                                          for h in CLOUDS[s["cloud"]])):
            bad.append(f"{key}: the URL is an https page of {s['cloud']}'s own")
        if not (s.get("page") or "").strip():
            bad.append(f"{key}: the page's title")
        sentence = (s.get("sentence") or "").strip()
        if not sentence or ELLIPSIS.search(sentence):
            bad.append(f"{key}: the sentence is quoted whole, with no ellipsis")
        if not (s.get("about") or "").strip():
            bad.append(f"{key}: what the sentence is about, in the provider's terms")
        try:
            if dt.date.fromisoformat(s.get("read") or "") > today:
                bad.append(f"{key}: read on a day still to come")
        except ValueError:
            bad.append(f"{key}: the day it was read, as YYYY-MM-DD")
    assert not bad, "\n".join(bad)


def test_every_claim_names_its_source_or_is_owed_one():
    sources = register()["sources"]
    owed = {(o["file"], o["sha256"]) for o in register()["owed"]["claims"]}
    unsourced, unknown = [], []
    for name, n, unit in claims():
        ids = cited(unit)
        unknown += [f"{name}:{n}: no source {i!r} in PROVIDER-SOURCES.json" for i in ids if i not in sources]
        if not ids and (name, fingerprint(unit)) not in owed:
            unsourced.append(f"{name}:{n}: {' '.join(unit.split())[:160]}")
    assert not unknown, "\n".join(unknown)
    assert not unsourced, ("a claim that a provider documents a behaviour names its source ([source: id]):\n"
                           + "\n".join(unsourced))


def test_the_owed_list_only_shrinks_and_ends_on_its_day():
    owed = register()["owed"]
    assert owed["due"] == DUE.isoformat()
    assert len(owed["claims"]) <= OWED_AT_MOST, "the owed list never grows: a new claim names its source"
    standing = {(name, fingerprint(unit)) for name, _, unit in claims() if not cited(unit)}
    gone = [f"{o['file']}: {o['starts']}" for o in owed["claims"] if (o["file"], o["sha256"]) not in standing]
    assert not gone, "a claim sourced or changed comes off the owed list:\n" + "\n".join(gone)
    if dt.datetime.now(dt.timezone.utc).date() > DUE:
        assert not owed["claims"], f"the owed claims were due a source by {DUE}"


def test_every_source_is_cited_somewhere():
    used = {i for _, text, _ in read_texts() for i in cited(text)}
    assert not sorted(set(register()["sources"]) - used)


# -- the check itself --------------------------------------------------------------------------------------------------
def test_the_carried_sentence_would_have_failed():
    carried = ('- **Stopping, as AWS describes it.** `StopRuntimeSession` ends one session, which restarts on the\n'
               '  next call; a Deny on `bedrock-agentcore:InvokeAgentRuntime` refuses new calls to the agent, and\n'
               '  "sessions that are already running ... continue until they end", up to 8 hours.')
    [(_, unit)] = units_of_markdown(carried)
    assert attributed(unit) and not cited(unit)
    assert ELLIPSIS.search('"sessions that are already running ... continue until they end"')


def test_what_counts_as_a_claim_and_a_citation():
    for said in ("AWS's documentation already says a running session keeps going",
                 "Google's pages contradict each other", "AWS: streaming lasts up to 60 minutes",
                 "a stopped session restarts on the next call to it (AWS): each",
                 "(Developer Guide, runtime sessions)", "Microsoft's own pages", "Azure documents it",
                 "as AWS's Service Authorization Reference lists them", "according to Google Cloud"):
        assert attributed(said), said
    for plain in ("Denying calls to this agent refuses new sessions.", "AWS takes no policy on a harness itself",
                  "the terms of AWS's service", "an AWS deny can't stop them"):
        assert not attributed(plain), plain
    assert cited("a deny [source: aws-a, aws-b]") == ["aws-a", "aws-b"]
    assert cited("# source: aws-a,\n#   aws-b") == ["aws-a", "aws-b"]
    python = '"""One.\n\nAWS says it does [source: aws-a].\n"""\nx = 1\n# AWS: it does,\n# as it says\ny = 2\n'
    assert [u for _, u in units_of_python(python) if attributed(u)] == [
        "AWS says it does [source: aws-a].", "x = 1\nAWS: it does,\nas it says\ny = 2"]
