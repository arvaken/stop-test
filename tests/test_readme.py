"""The README says what is kept of the test agent's two calls in Arvaken's one description of what Cloudflare records,
word for word: version 3, in force from 27 October 2026, as the founder approved it (arvaken/mark,
docs/platform/WHAT-CLOUDFLARE-RECORDS.md; D614). It nowhere says the address keeps nothing, nor, as version 2 did, that
the address is never your account's own."""
import re
from pathlib import Path

README = (Path(__file__).resolve().parents[1] / "README.md").read_text(encoding="utf-8")
DESCRIPTION = (
    "Arvaken's test address (stop-test.arvaken.com) and its verification page (verify.arvaken.com) are served by "
    "Cloudflare, on arvaken.com's Free plan. Arvaken's code at each writes no request log and stores no request; "
    "Cloudflare's request logs for each are turned off, and no Logpush job exists. Cloudflare still keeps its "
    "standard records of each request: the address it came from, with that address's network and country and the "
    "request's path, query and user agent, for 31 days, in its traffic analytics and in its record of any request its "
    "security checks act on, which also keeps the request's referer; daily counts of requests, without addresses, for "
    "a year; and operational logs, for a period Cloudflare does not state. Each request's time is kept with its "
    "address, so for those 31 days a stop test result you submit, which holds its run's times, could be matched to "
    "the address the test agent's calls came from. For the test address, the address recorded is the one the test "
    "agent's calls come from. Unless you name a gateway or a subnet, the kit runs the test agent on the cloud's "
    "default network, so the address is not your account's own: on AWS, Lambda's default network, where it is an AWS "
    "address shared with other AWS customers; on Google Cloud, Cloud Run's default network, where it is an address "
    "from Google's dynamic pool, not one of your project's. If you name a gateway (`--via`), the calls go through it, "
    "and the address recorded is the one your gateway's calls leave from; if you name a subnet (`--subnet`), it is "
    "the one your network's calls leave from. Either may be your own. For the verification page, it is the address of "
    "whoever opens it.")


def flat(text: str) -> str:
    return re.sub(r"\s+", " ", " ".join(re.sub(r"^[\s>]*", "", line) for line in text.splitlines())).strip()


def test_the_readme_quotes_the_one_description_word_for_word():
    assert DESCRIPTION in flat(README)


def test_the_readme_never_says_the_address_keeps_nothing():
    assert "keeps no log or record" not in flat(README)
    assert "keeps nothing" not in flat(README)
    assert "never your account's own" not in flat(README)
