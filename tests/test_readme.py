"""The README says what is kept of the test agent's two calls in Arvaken's one description of what Cloudflare records,
word for word: version 2, as the founder approved it on 24 October 2026 (arvaken/mark,
docs/platform/WHAT-CLOUDFLARE-RECORDS.md). It nowhere says the address keeps nothing."""
import re
from pathlib import Path

README = (Path(__file__).resolve().parents[1] / "README.md").read_text(encoding="utf-8")
DESCRIPTION = (
    "Arvaken's test address (stop-test.arvaken.com) and its verification page (verify.arvaken.com) are served by "
    "Cloudflare, on arvaken.com's Free plan. Arvaken's code at each writes no request log and stores no request; "
    "Cloudflare's request logs for each are turned off, and no Logpush job exists. Cloudflare still keeps its "
    "standard records of each request: the address it came from, for 31 days, in its traffic analytics and in its "
    "record of any request its security checks act on; daily counts of requests, without addresses, for a year; and "
    "operational logs, for a period Cloudflare does not state. For the test address, the address recorded is the "
    "test agent's public address. The kit runs the test agent on the cloud's default network, never in a network of "
    "yours, so the address is never your account's own: on AWS, Lambda's default network, where it is an AWS "
    "address shared with other AWS customers; on Google Cloud, Cloud Run's default network, where it is an address "
    "from Google's dynamic pool, not one of your project's. For the verification page, it is the address of whoever "
    "opens it.")


def flat(text: str) -> str:
    return re.sub(r"\s+", " ", " ".join(re.sub(r"^[\s>]*", "", line) for line in text.splitlines())).strip()


def test_the_readme_quotes_the_one_description_word_for_word():
    assert DESCRIPTION in flat(README)


def test_the_readme_never_says_the_address_keeps_nothing():
    assert "keeps no log or record" not in flat(README)
    assert "keeps nothing" not in flat(README)
