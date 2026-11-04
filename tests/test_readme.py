"""The README says what is kept of the test agent's two calls in Arvaken's one description of what Cloudflare records,
word for word: version 5, with the two additions for a test copy and an SDK's switch the founder approved with the kit's
terms version 5 (arvaken/mark D721, 2 November 2026), in force with the release that carries them; version 4 was D624's
(docs/platform/WHAT-CLOUDFLARE-RECORDS.md). It nowhere says the address keeps nothing, nor, as version 2 did, that
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
    "the address the test agent's calls came from, and, when you fire an in-agent SDK's switch yourself, to the one the "
    "kit's own calls came from. For the test address, the address recorded is the one the test "
    "agent's calls come from. Unless you name a gateway or a subnet, the kit runs the test agent on the cloud's "
    "default network, so the address is not your account's own: on AWS Lambda, Lambda's default network, where it is "
    "an AWS address shared with other AWS customers; on Google Cloud, Cloud Run's default network, where it is an "
    "address from Google's dynamic pool, not one of your project's. If you name a gateway (`--via`), the calls go "
    "through it, and the address recorded is the one your gateway's calls leave from; if you name a subnet "
    "(`--subnet`), it is the one your network's calls leave from. Either may be your own. On Amazon Bedrock "
    "AgentCore, where the kit offers neither, it runs the test agent in AgentCore's public network mode, in no "
    "network of yours, so the address is not your account's own either; in Arvaken's own runs, it was an AWS address "
    "in the agent's region, a different one each run. On a test copy of your own agent, the kit does not choose the "
    "network: the address recorded is the one your copy's calls leave from, which is your own if the copy runs in a "
    "network of yours. When you fire an in-agent SDK's switch yourself, the kit's own calls to the test address come "
    "from the machine the kit runs on, and the address recorded for them is the one that machine's calls leave from, "
    "which is your own network's if the machine is in one. For the verification page, it is the address of whoever "
    'opens it.')


def flat(text: str) -> str:
    return re.sub(r"\s+", " ", " ".join(re.sub(r"^[\s>]*", "", line) for line in text.splitlines())).strip()


def test_the_readme_quotes_the_one_description_word_for_word():
    assert DESCRIPTION in flat(README)


def test_the_readme_never_says_the_address_keeps_nothing():
    assert "keeps no log or record" not in flat(README)
    assert "keeps nothing" not in flat(README)
    assert "never your account's own" not in flat(README)
    assert "on AWS, Lambda's default network" not in flat(README)


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
    " `--trail`, the kit makes a trail of the run's own, recording only the data events of the test agent and of its "
    "bucket's objects, into a bucket only CloudTrail may write to. It fires nothing until the trail has recorded a "
    'call to the agent, which can take '
    'some minutes. Before deleting the trail and its bucket, it copies their records into a folder beside the result,'
    " `stop-test-<run>-trail`, each with its SHA-256. Without `--trail`, that moment is the kit's own clock, and the "
    "details say so. AWS charges for a trail's data events.",
    "A run writes the same three files as on Lambda. If a run could not clean up, remove what it made by the run's "
    'name: ``` stop-test agentcore clean --run <run> --region eu-central-1 ```',
    # its first sentence's end reworded by the founder, word for word, at 01:41 UTC on 31 October 2026
    '- **AgentCore:** [`permissions/aws-agentcore-policy.json`](permissions/aws-agentcore-policy.json), an IAM policy'
    " that lets its holder make a role only under the kit's boundary, `arvaken-stop-test-boundary`, or the harness's"
    ' below. Each statement names only what a run makes, except reading your stop policy, the reads'
    ' AWS allows only on every resource, and your default workload-identity directory, which AWS checks beside each '
    'workload identity a run reads or deletes. Its last two statements are needed only with `--trail`.',
    'On a harness, attach a second policy beside it, '
    '[`permissions/aws-agentcore-harness-policy.json`](permissions/aws-agentcore-harness-policy.json). Its statements '
    "name only the run's harness, the runtime AWS makes for it and the memory AWS requires to make it, except reading "
    'inference profiles, which the kit does only for a profile you give as the model. The two are kept apart because '
    'IAM allows a managed policy at most 6,144 characters; create each as a managed policy.',
)


def test_the_readme_says_what_the_agentcore_module_does_in_the_approved_words():
    for words in AGENTCORE:
        assert words in flat(README), words[:80]


ROWS_AGENTCORE = tuple(("| `--stop` or `--inline-deny`, on AgentCore | `AccessDenied` from Amazon S3, on the running session's own calls and its work under another identity; `AccessDeniedException` from AgentCore, on new calls to the agent and, on a harness, on its model |", '| `--deny-calls` | `AccessDeniedException` from AgentCore, on new calls to the agent. On the running session, nothing counts |', "| `--deny-calls-and-end-sessions` | that, on new calls; on the running session, its end, from when AWS confirms it: asked to end the session again, AWS answers that there is no such session. A path seen calling after that, in the bucket or the run's trail, is not stopped. Calls to Arvaken's test address can't be seen, so its two paths rest on that confirmation |"))


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
    # the three AgentCore rows, approved by the founder word for word on 30 October 2026
    *ROWS_AGENTCORE,
    "| `--own-trigger` | those of the kind of stop the cloud's record of your action shows: CloudTrail's on AWS, Cloud "
    "Audit Logs' on Google Cloud. If it shows none of these, nothing counts as stopped |",
    'A path whose calls after the stop were all not counted, or that was answered after the stop and then had nothing '
    'counted until the window ended, reads "not measured": the kit cannot say whether the stop stopped it.',
)


def test_the_readme_says_what_counts_as_stopped_as_the_founder_approved_it():
    for words in WHAT_COUNTS:
        assert words in flat(README), words[:60]


# Through your gateway (D655, the founder's ruling on a gateway's refusal, 30 October 2026): his own words for (b) and open
# tunnels 3, and the words he approved for (c), the table's row, and the model section's sentence on what counts
GATEWAY_WORDS = (
    "Switching your gateway off can't be measured as a stop: to the kit it looks the same as a broken network. Use a "
    "rule on your gateway that refuses calls, such as a filter or a closed port.",
    "A rule on your gateway may not reach a connection already open through it. The kit keeps its connections open, as "
    "AWS's own libraries do, so its times include that.",
    'A refusal from a gateway that inspects TLS (`--ca-bundle`), made inside the connection it opened, and any refusal from a gateway reached over `https://`, read "not measured" for now: the kit can\'t yet tell them from AWS\'s own.',
    "| `--via`, your gateway | its own refusal of the test agent's connection through it: a `403`, or a `407` where your gateway's address carries a user name and password, read only where Lambda runs the test agent on the Python, botocore and urllib3 the kit was tested with |",
    "After the stop, a call counts as stopped only when the stop refused it, as access denied; every other failure, a "
    "throttle among them, is not counted, and the page shows the errors seen.",
    "stop-test aws plan --via http://gateway.example:8888 --product-attachment all-outbound",
    # every run on Lambda, as the founder approved it word for word, 30 October 2026
    "On Lambda, the test agent keeps its clients, and their connections to AWS, from one call to the next while Lambda keeps its environment, as AWS's own libraries do.",
)


def test_the_readme_says_what_counts_through_a_gateway_as_the_founder_approved_it():
    for words in GATEWAY_WORDS:
        assert words in flat(README), words[:60]
    assert "a throttle included" not in flat(README)


# Reloading tinyproxy on Ubuntu (D561's finding, 30 October 2026): the founder's words, approved word for word at 01:22 UTC
# on 31 October 2026
TINYPROXY_WORDS = ("If your gateway is tinyproxy on Ubuntu, load a changed rule with `sudo systemctl reload tinyproxy`, "
                   "which sends it SIGUSR1. A SIGHUP stops it there: Ubuntu's service runs tinyproxy in the foreground "
                   "(`-d`), and tinyproxy 1.11.1 takes SIGHUP as a reload only when it runs as a daemon.")


def test_the_readme_says_how_to_reload_tinyproxy_on_ubuntu_as_the_founder_approved_it():
    assert TINYPROXY_WORDS in flat(README)


# The sentence that said Arvaken could take only Lambda's results (approved at 02:00 UTC on 31 October 2026), deleted
# once Arvaken's record takes AgentCore's and Google Cloud's too (mark's 0187); the deletion, with no new words, approved
# by the founder at 23:36 UTC on 31 October 2026
SEND_FOR_NOW = ("For now, Arvaken can take a result only from AWS Lambda. A result from Amazon Bedrock AgentCore or "
                "Google Cloud can't be sent yet: keep it as your own record.")
SEND_THEN_CLOUDS = ("https://arvaken.com/stop-test/terms.\n\n"
                    "AWS, with Lambda and Amazon Bedrock AgentCore, and Google Cloud. Azure follows.")


def test_the_readme_no_longer_says_only_lambdas_results_can_be_sent():
    assert SEND_FOR_NOW not in flat(README)
    assert "can't be sent yet" not in README
    assert SEND_THEN_CLOUDS in README


# A test copy of your own agent and an in-agent SDK's switch (D575, D713, D714, D722): the opening and the section as
# the founder approved them, word for word, at 18:06:47 UTC on 2 November 2026 ("Approve part 1" to "part 4"), with the
# words he approved before: what the run's role grants and the --sdk line (17:10:07 UTC), the witness paragraph (his own,
# 01:08:36 UTC), the CloudTrail sentence (17:34:43 UTC) and the two lines on the test address (17:50:03 UTC).
COPY_WORDS = (
    "It deploys a test agent of its own, or uses a test copy of one of your own agents, fires the stop you have "
    "declared on that test agent alone, unless you fire your own, and times what actually stops.",
    "Nothing about your account leaves it, unless you name a gateway or a subnet for the test agent's calls, or run it "
    "on a test copy of your own agent.",
    "Two of the kit's tests, of the open internet and of a key for a service outside your cloud, have the test agent "
    "call Arvaken's test address, stop-test.arvaken.com. Neither call carries anything of yours from the kit: the "
    "second carries only a random key the kit makes for the run. When you fire an in-agent SDK's switch yourself, the "
    "kit also calls the address from the machine it runs on, once a second and with no key, to check that the address "
    "still answers.",
    "On AWS, the kit can also run on a test copy of one of your own agents, in place of its own test agent: a Lambda "
    "function or an Amazon Bedrock AgentCore runtime. You deploy the copy with the kit's probe in it. The kit calls the "
    "copy about once a second, and the probe tries the same four paths as the kit's test agent, from inside your copy. "
    "The kit never deploys, changes or deletes your copy. Run it only on a test copy whose settings reach test systems "
    "alone, never on an agent whose work matters: each call runs your copy's own code, which does whatever that code "
    "does with whatever its settings reach.",
    "The probe is a Python package, `arvaken-stop-test-probe`, in each release of the kit. It needs Python 3.9 or "
    "later, and boto3, which Lambda's Python runtime has. Check its signature as you check the kit's, then install it "
    "with your copy's code:",
    "stop-test/bin/python -m pip install --require-hashes --no-deps --target <your copy's code> -r "
    "probe-requirements-0.6.0.txt",
    "Then, in your handler, before your agent's own work, hand the kit's calls to the probe:",
    "if heartbeat.is_mine(event): return heartbeat.run(event)",
    "On AgentCore, do the same in your entrypoint. For the running session, `heartbeat.run` gives back an iterator of "
    "events, which your entrypoint streams as its response.",
    "A call is the kit's only if it carries the kit's marker, naming a run. The probe reads nothing of your agent's "
    "work and writes no log. The address it calls is fixed in its code, never taken from the call.",
    "If an SDK of yours wraps only its own clients, pass them, so that the probe's calls go through it: "
    "`heartbeat.run(event, cloud=..., http=...)`, where `cloud` makes a client as `boto3.client` does, and `http(url, "
    "headers, timeout)` makes a GET request and gives back its status. Otherwise the probe uses the runtime's own "
    "clients, boto3's and Python's urllib. The result says which it used.",
    "On Lambda, one CloudFormation stack, `arvaken-stop-test-<run>`, with no function: the role your copy runs as for "
    "the test, `arvaken-stop-test-<run>-agent`, a second role and a bucket, as for the kit's own test agent. On "
    "AgentCore, the same two roles and a bucket, and no code and no runtime.",
    "For the test, your copy runs as a role the kit makes for the run, not its own. On Lambda, that role grants only "
    "what the test needs, within the kit's boundary: putting and getting its own objects in the run's bucket, and "
    "assuming the run's second role, each only for calls from your copy (`lambda:SourceFunctionArn`); calling the model "
    "you name with `--model`, where you name one; and, for a copy in your VPC, the network actions Lambda needs for its "
    "interfaces, on your copy's own subnets and security groups wherever EC2 lets a policy name them. On AgentCore, it "
    "grants putting and getting its own objects in the run's bucket and assuming the run's second role, and AgentCore "
    "may use it only for your copy (`aws:SourceArn`). Neither grants writing logs. The kit takes these permissions from "
    "its own code, never from your copy's own role.",
    "You point your copy at that role for the test, and back afterwards, as the kit tells you. On Lambda, that is one "
    "command. On AgentCore, set the runtime's role in AgentCore's console, changing nothing else: `update-agent-runtime`"
    " also works, but it needs the runtime's whole configuration again, and anything you leave out is removed. The kit "
    "checks that your copy runs as the run's role before it times anything. When the run ends, it deletes that role "
    "only once your copy no longer runs as it; until then, it names the role for you to delete. On Lambda, a copy whose "
    "settings are encrypted with your own key is refused before anything is made, since the run's role can't use that "
    "key.",
    "With `--copy`, name the stop with `--stop <ARN>` or `--inline-deny`, fired on the run's role alone, or on Lambda "
    "`--revoke-sessions`, on the run's two roles; or with `--sdk` (below). Name also:",
    "- `--tool`: a kind of tool your copy has, from the kit's list; give each that applies, or `--tool none`. The list: "
    "searches or reads the web, runs code, reads or writes files, reads or writes a database, sends email or messages, "
    "makes payments, changes cloud resources, calls other services' APIs, something else. - `--model-kind`: the kind of "
    "model your copy calls, from the kit's list: no model, a model service of its cloud, a model provider's API, a "
    "model it runs itself. - on AgentCore, `--endpoint-name`: the endpoint of your runtime the kit calls, DEFAULT unless"
    " you name another.",
    "On Lambda, `--model` works as for the kit's own test agent: the probe also calls the model you name, as the run's "
    "role. `--window` and `--repeats` work as for the kit's own test agent.",
    "Before it makes anything, the kit asks you to type the run's name, to confirm that your copy is a test copy. Before "
    "every firing, it warns you that your stop may reach more than the test agent, and asks again. A run on a copy "
    "writes two files: the result, in the format `stop-test-result/3`, and its details.",
    "If your stop is an in-agent SDK's switch, name the SDK with `--sdk`, in place of a stop:",
    "- `--sdk`: your in-agent SDK's name, in your own words, 1 to 200 characters. It's shown as you wrote it. The kit "
    "doesn't check it, and the result is your own test, not Arvaken's rating of that product.",
    "You fire the switch yourself, and the kit fires nothing. When it asks, press Enter, then fire it. Each path is "
    "timed from that mark, for at least 15 minutes, once and not repeated, since only you can turn your switch off. When "
    "the timing is done, the kit says so, and you can turn your switch off. Then the kit asks for the file you exported "
    "from your SDK that records it acting, and for the time and name of the entry in it that records your stop. It keeps "
    "only the file's SHA-256 and that entry, never the file.",
    "The kit's witness is a check, from the machine you run the kit on, that the run's bucket and Arvaken's test address "
    "kept answering through the window, so a failure on a path wasn't caused by either of them being down. A failure "
    "counts only if your SDK raised it in the call itself: a timeout or a lost connection, which a fault in your copy's "
    "own network would cause, makes the path not measured. If your SDK refuses calls whenever it can't reach its own "
    "service, that refusal looks the same to the kit as your switch, so check that your SDK's own record shows the "
    "switch acting at your mark.",
    "A path reads stopped only by Arvaken's rule for an SDK's stop: it worked before your mark; from its first failure "
    "after your mark to the window's end, every call on it failed, each with an error the call itself raised; the kit's "
    "witness kept answering; and your SDK's record of acting is in its export. A rate limit is never counted as "
    "stopped. With `--model` on Lambda, the path to the model also reads not stopped if CloudTrail shows a call from "
    "your copy to the model from a second before its first failure to the window's end.",
    "With your SDK's stop, the kit reads CloudTrail for your copy's calls to the model 15 minutes after the window ends, "
    "so the run ends at least that long after the window does.",
    "On a test copy of yours, the probe's call with a key and its open-internet call reach Arvaken's test address from "
    "your copy: the address recorded is the one your copy's calls leave from, which is your own if the copy runs in a "
    "network of yours, and on Lambda's default network an AWS address. With your SDK's switch, the kit's witness also "
    "calls the test address once a second, with no key, from the machine you run the kit on: the address recorded is "
    "the one that machine's calls leave from, which is your own network's if the machine is in one. Cloudflare keeps "
    "each of those addresses, with its network and country, for 31 days, as Arvaken's description of what Cloudflare "
    "records says above.",
    "If you pass the probe your own HTTP client, or an SDK in your copy wraps the runtime's, that client may add its "
    "own headers to the probe's calls, and they may identify you. A proxy that reads the calls, of your copy or of the "
    "machine you run the kit on, may add headers too. Our test address keeps none of them. Of the headers a client or a "
    "proxy could add or change, Cloudflare keeps two: a call's user agent, which the kit sets to its own name, and, "
    "where Cloudflare's security checks act on the call, its referer, which the kit never sends. A client or a proxy "
    "that changes either changes what Cloudflare keeps.",
    "| `--sdk`, on a test copy | an error your SDK raised in the call itself, on each path, from its first failure after "
    "your mark to the window's end, with the kit's witness answering and your SDK's record of acting in its export. A "
    "timeout, a lost connection or a rate limit never counts |",
    "- **A test copy:** the kit's own policy doesn't reach your copy. Attach a second policy beside it, "
    "[`permissions/aws-copy-policy.json`](permissions/aws-copy-policy.json), with your copy's region, account and name, "
    "or runtime ID, in place of the capitals. It lets the kit read your copy's settings and call it, and nothing else.",
)


def test_the_readme_says_what_a_run_on_a_test_copy_does_in_the_approved_words():
    for words in COPY_WORDS:
        assert words in flat(README), words[:80]
    # the words it carries from the kit itself are the kit's own
    from arvaken_stop_test import result
    from arvaken_stop_test.aws import your_copy
    assert your_copy.SDK_MODEL_TRAIL in flat(README)
    assert ", ".join(result.TOOL_KINDS[1:]) + "." in flat(README) and ", ".join(result.MODEL_KINDS) + "." in flat(README)


# A test copy on Google Cloud (D575): the section, the line on the test address and the line on the role, as the founder
# approved them, word for word, by 19:45 UTC on 3 November 2026 ("Approve as written", README (1) to (8)).
GOOGLE_COPY_WORDS = (
    "On Google Cloud, the kit can run on a test copy that is a Cloud Run service, in the project and region you run the "
    "kit in. The probe tries the same four paths as the kit's Google test agent, from inside your copy. On Google Cloud "
    "it needs Python 3.9 or later and nothing else. Check its signature as on AWS, then install it in your copy's image:",
    "pip install --require-hashes --no-deps -r probe-requirements-0.6.0.txt",
    "The kit calls your copy at its address, signed in as you, with a POST to `/` whose JSON body is the kit's call. In "
    "your service's handler for it, before your agent's own work, hand the kit's calls to the probe and send back what "
    "it gives as JSON. In Flask, for one:",
    "@app.post(\"/\") def agent(): body = request.get_json(silent=True) if heartbeat.is_mine(body): return "
    "heartbeat.run(body)",
    "If an SDK of yours wraps only its own clients, pass them, as on AWS. On Google Cloud, `cloud(method, url, headers, "
    "body, timeout)` makes an HTTPS request and gives back the answer's HTTP status and its body. Otherwise the probe "
    "uses Python's urllib, with the token Cloud Run gives your copy.",
    "The kit makes the two service accounts and the bucket it makes for its own test agent, and no service. The account "
    "your copy runs as for the test, `arvaken-st-<run>`, may write, read and delete objects in the run's bucket and take "
    "the second account's token, and nothing else; each grant is on those things alone, never on your project. The kit "
    "takes them from its own code, never from your copy's own account.",
    "You point your copy at that account for the test, and back afterwards, with the `gcloud run services update` "
    "command the kit gives you, which makes a new revision. The kit checks that your copy's latest revision runs as the "
    "run's account, is ready and takes all its traffic before it times anything. When the run ends, it deletes that "
    "account only once your copy no longer runs as it; until then, it names the account for you to delete. Before "
    "anything is made, the kit refuses a copy that takes calls only from your own networks, one that sends its traffic "
    "to a revision you named, and one whose settings read a secret from Secret Manager, which the run's account can't "
    "read.",
    "stop-test google plan --copy projects/my-test-project/locations/europe-west3/services/my-agent-test --deny-all "
    "--tool \"runs code\" --model-kind \"a model provider's API\" --project my-test-project --region europe-west3",
    "With `--copy`, name the stop with `--stop <name>`, `--deny-all` or `--disable-account`, fired on the run's account "
    "alone, or with `--sdk`, as on AWS. Name `--tool` and `--model-kind` as on AWS. `--model` isn't offered on Google "
    "Cloud. `--window` and `--repeats` work as for the kit's own test agent.",
    "On Cloud Run's default network, the address your copy's calls leave from is one from Google's dynamic pool, not one "
    "of your project's.",
    "On a test copy, this role is enough: it lets the kit read and call every Cloud Run service in your test project, "
    "not your copy alone. Pointing your copy at the run's account and back is yours to do, with your own permission to "
    "update your copy and to act as each account.",
)


# And clean's line for a run on a copy, approved by the founder, word for word, by 20:05 UTC on 3 November 2026
# ("Approve as written", clean (3)).
GOOGLE_COPY_CLEAN = ("If a run on your copy could not clean up, give `stop-test google clean` your copy's name with "
                     "`--copy` as well: it deletes the run's account only once your copy no longer runs as it.")


def test_the_readme_says_what_a_run_on_a_google_test_copy_does_in_the_approved_words():
    for words in (*GOOGLE_COPY_WORDS, GOOGLE_COPY_CLEAN):
        assert words in flat(README), words[:80]


def test_the_readmes_google_copy_example_is_the_kits_own_plan(capsys):
    # the command the README gives runs as written, and the role the README says is enough holds what a copy needs
    import shlex
    from arvaken_stop_test import cli
    line = next(w for w in GOOGLE_COPY_WORDS if w.startswith("stop-test google plan"))
    assert cli.main(shlex.split(line)[1:]) == 0
    copy = "projects/my-test-project/locations/europe-west3/services/my-agent-test"
    assert f"on your test copy {copy}:" in capsys.readouterr().out
    role = (Path(__file__).resolve().parents[1] / "permissions" / "google-role.yaml").read_text(encoding="utf-8")
    for permission in ("run.services.get", "run.routes.invoke", "iam.serviceAccounts.list"):
        assert f"- {permission}\n" in role
