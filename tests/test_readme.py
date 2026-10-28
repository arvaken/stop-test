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
# The section on Amazon Bedrock AgentCore and its two smaller changes, as the founder approved them word for word at
# 04:44 UTC on 28 October 2026 (arvaken/mark D618).
AGENTCORE = (
    'AWS, with Lambda and Amazon Bedrock AgentCore, and Google Cloud. Azure follows.',
    'Each thing is named with the run and tagged `arvaken-stop-test=<run>`: - the test agent: an AgentCore runtime, '
    "`arvaken_stop_test_<run>`, made from the kit's own code (Python 3.13) in AgentCore's public network mode, with a"
    ' role of its own that AgentCore may take on for this runtime alone. A session of it ends after a minute idle, '
    "and lives at most an hour; - a second role, which only the test agent's role may assume; - an S3 bucket, "
    "`arvaken-stop-test-<run>`, private and encrypted, holding the test agent's code and the objects its paths write.",
    "Both roles carry the kit's permissions boundary, as on Lambda. The test agent writes no logs of its own, and its"
    ' role may not write any. CloudTrail records what the kit does, as it records any change. The kit touches nothing'
    " it did not make, except to attach your stop to the test agent's role when your stop is a policy of yours.",
    'For every stop, the kit measures two things: - **New calls to the agent.** About once a second, the kit calls '
    'the test agent, each call starting a session of its own, and the agent answers at once. - **A session already '
    "running.** Before each stop, the kit opens one session of the test agent's. Its agent tries each of the four "
    "paths about once a second, as on Lambda, and reports each try on the call's streaming response. If the session "
    'ends, each of its paths reads as refused from then on.',
    'When the run ends, the kit takes off the stop it fired, deletes what it made, and checks each thing by its own '
    'identifier: the runtime, its endpoints, its workload identity, its code, the bucket, both roles, any log group '
    'and the stop. Anything still there is named for you to delete.',
    "Name the stop with one of: - `--stop <ARN>`: your declared stop, a managed policy, attached to the test agent's "
    "role alone, as on Lambda. - `--inline-deny`: a policy the kit writes on the test agent's role, denying every "
    'action. - `--deny-calls`: a resource policy the kit writes on the test agent, denying every call to it, from '
    'anyone. - `--deny-calls-and-end-sessions`: the same, then the session the test agent is running ended.',
    '`--window` and `--repeats` work as on Lambda. On AgentCore a window is at most 54 minutes, because the running '
    'session is watched on one streaming response. Each call to the test agent starts a session of its own, about a '
    "thousand in a run of one repeat, and AWS bills each session's use to your account.",
    "The moment each stop was fired is CloudTrail's record of the call: IAM's for a policy on the role, AgentCore's "
    "for the deny. Ending a session is recorded as a data event, which CloudTrail's event history does not hold. With"
    " `--trail`, the kit makes a trail of the run's own, recording only the test agent's data events, into a bucket "
    'only CloudTrail may write to. It fires nothing until the trail has recorded a call to the agent, which can take '
    'some minutes. Before deleting the trail and its bucket, it copies their records into a folder beside the result,'
    " `stop-test-<run>-trail`, each with its SHA-256. Without `--trail`, that moment is the kit's own clock, and the "
    "details say so. AWS charges for a trail's data events.",
    "A run writes the same three files as on Lambda. If a run could not clean up, remove what it made by the run's "
    'name: ``` stop-test agentcore clean --run <run> --region eu-central-1 ```',
    '- **AgentCore:** [`permissions/aws-agentcore-policy.json`](permissions/aws-agentcore-policy.json), an IAM policy'
    ' under the same boundary. Each statement names only what a run makes, except reading your stop policy and the '
    'reads AWS allows only on every resource. Its last two statements are needed only with `--trail`.',
)


def test_the_readme_says_what_the_agentcore_module_does_in_the_approved_words():
    for words in AGENTCORE:
        assert words in flat(README), words[:80]
