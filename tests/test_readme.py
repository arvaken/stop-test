"""The README says what is kept of the test agent's two calls in Arvaken's one description of what Cloudflare records,
word for word, as the founder approved it on 24 October 2026 (arvaken/mark, docs/platform/WHAT-CLOUDFLARE-RECORDS.md),
and nowhere says the address keeps nothing."""
import re
from pathlib import Path

README = (Path(__file__).resolve().parents[1] / "README.md").read_text(encoding="utf-8")
DESCRIPTION = (
    "Arvaken's test address (stop-test.arvaken.com) and its verification page (verify.arvaken.com) are served by "
    "Cloudflare. Arvaken's code at each writes no request log and stores no request, and Cloudflare's request logs for "
    "each are turned off. Cloudflare still keeps its standard records of each request: the address it came from, for 31 "
    "days, in its traffic and security records; counts of requests, for three months; and operational logs, for a period "
    "Cloudflare does not state. For the test address, the address recorded is the test agent's public address: with "
    "Lambda's default network, an AWS address shared with other AWS customers; through your own NAT gateway, your "
    "account's own address. For the verification page, it is the address of whoever opens it.")


def flat(text: str) -> str:
    return re.sub(r"\s+", " ", " ".join(re.sub(r"^[\s>]*", "", line) for line in text.splitlines())).strip()


def test_the_readme_quotes_the_one_description_word_for_word():
    assert DESCRIPTION in flat(README)


def test_the_readme_never_says_the_address_keeps_nothing():
    assert "keeps no log or record" not in flat(README)
    assert "keeps nothing" not in flat(README)
