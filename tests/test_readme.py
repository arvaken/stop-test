"""The README says what is kept of the test agent's two calls in Arvaken's one description of what Cloudflare records,
word for word: version 4, in force from 28 October 2026, as the founder approved it (arvaken/mark,
docs/platform/WHAT-CLOUDFLARE-RECORDS.md; D624). It nowhere says the address keeps nothing, nor, as version 2 did, that
the address is never your account's own, nor, as version 3 did, that on AWS the test agent always runs on Lambda's
default network."""
import re
from pathlib import Path

README = (Path(__file__).resolve().parents[1] / "README.md").read_text(encoding="utf-8")
DESCRIPTION = (
    "Arvaken's test address (stop-test.arvaken.com) and its verification page (verify.arvaken.com) are served by "
    "Cloudflare, on arvaken.com's Free plan. Arvaken's code at each writes no request log and stores no request; "
    "Cloudflare's request logs for each are turned off, and no Logpush job exists. Cloudflare still keeps its "
    "standard records of each request: the address it came from, with that address's network and country and the "
    "request's path, query and user agent, for 31 days, in its traffic analytics and in its record of any request its"
    " security checks act on, which also keeps the request's referer; daily counts of requests, without addresses, "
    "for a year; and operational logs, for a period Cloudflare does not state. Each request's time is kept with its "
    "address, so for those 31 days a stop test result you submit, which holds its run's times, could be matched to "
    "the address the test agent's calls came from. For the test address, the address recorded is the one the test "
    "agent's calls come from. Unless you name a gateway or a subnet, the kit runs the test agent on the cloud's "
    "default network, so the address is not your account's own: on AWS Lambda, Lambda's default network, where it is "
    "an AWS address shared with other AWS customers; on Google Cloud, Cloud Run's default network, where it is an "
    "address from Google's dynamic pool, not one of your project's. If you name a gateway (`--via`), the calls go "
    "through it, and the address recorded is the one your gateway's calls leave from; if you name a subnet "
    "(`--subnet`), it is the one your network's calls leave from. Either may be your own. On Amazon Bedrock "
    "AgentCore, where the kit offers neither, it runs the test agent in AgentCore's public network mode, in no "
    "network of yours, so the address is not your account's own either; in Arvaken's own runs, it was an AWS address "
    "in the agent's region, a different one each run. For the verification page, it is the address of whoever opens "
    'it.')


def flat(text: str) -> str:
    return re.sub(r"\s+", " ", " ".join(re.sub(r"^[\s>]*", "", line) for line in text.splitlines())).strip()


def test_the_readme_quotes_the_one_description_word_for_word():
    assert DESCRIPTION in flat(README)


def test_the_readme_never_says_the_address_keeps_nothing():
    assert "keeps no log or record" not in flat(README)
    assert "keeps nothing" not in flat(README)
    assert "never your account's own" not in flat(README)
    assert "on AWS, Lambda's default network" not in flat(README)


# The founder's approval, word for word, 30 October 2026: what counts as stopped, per kind of stop (his refusal ruling of
# 29 October 2026, GENERAL)
WHAT_COUNTS = (
    "After the stop, a call counts as stopped only where the stop itself refused it. Any other failure, such as a "
    "throttle, a server error, a timeout or a lost connection, is not counted: it is neither stopped nor a success, and "
    "the page shows it by its code. A refusal counts only on a path that worked before it.",
    # the AWS row, with its model path as the founder approved it word for word, 30 October 2026
    "| `--stop`, `--inline-deny` or `--revoke-sessions`, on AWS | `AccessDenied` from Amazon S3, on the test agent's own "
    "calls and its work under another identity; `AccessDeniedException` from Amazon Bedrock, on its call to a model; "
    "and on every path, Lambda refusing to run the test agent with `KMSAccessDeniedException`, where the agent ran "
    "before the stop |",
    "| `--stop` or `--deny-all`, on Google Cloud | a `403` from Cloud Storage whose reason is `forbidden` or "
    "`insufficientPermissions` |",
    "| `--disable-account` | those, a `401` whose reason is `authError` from a token not yet expired, and a `404` when "
    "the test agent asks for its own token |",
    "| `--own-trigger` | those of the kind of stop the cloud's record of your action shows: CloudTrail's on AWS, Cloud "
    "Audit Logs' on Google Cloud. If it shows none of these, nothing counts as stopped |",
    'A path whose calls after the stop were all not counted, or that was answered after the stop and then had nothing '
    'counted until the window ended, reads "not measured": the kit cannot say whether the stop stopped it.',
)


def test_the_readme_says_what_counts_as_stopped_as_the_founder_approved_it():
    for words in WHAT_COUNTS:
        assert words in flat(README), words[:60]
