# Arvaken stop test

The stop test is a kit you run yourself, in your own cloud account, with your own credentials. It deploys a test agent
of its own, or uses a test copy of one of your own agents, fires the stop you have declared on that test agent alone,
unless you fire your own, and times what actually stops. When it finishes, it removes the stop it fired and everything
it made.

You run it yourself. Arvaken never runs tests in your account. Nothing about your account leaves it, unless you name a
gateway or a subnet for the test agent's calls, or run it on a test copy of your own agent. Then the address they leave
from may be your own, and is recorded as below, and whoever runs your gateway sees the calls that pass through it. Two
of the kit's tests, of the open internet and of a key for a service outside your cloud, have the test agent call
Arvaken's test address, stop-test.arvaken.com. Neither call carries anything of yours from the kit: the second carries
only a random key the kit makes for the run. When you fire an in-agent SDK's switch yourself, the kit also calls the
address from the machine it runs on, once a second and with no key, to check that the address still answers. A gateway
you name may add its own headers to the calls it carries, and they may identify you. Our test address keeps none of
them. Of the headers a gateway could add or change, Cloudflare keeps two: a call's user agent, which the kit sets to its
own name, and, where Cloudflare's security checks act on the call, its referer, which the kit never sends. A gateway
that changes either changes what Cloudflare keeps. The address answers with a fixed reply. What is kept of each call is
Arvaken's one description of what Cloudflare records, word for word:

> Arvaken's test address (stop-test.arvaken.com) and its verification page (verify.arvaken.com) are served by
> Cloudflare, on arvaken.com's Free plan. Arvaken's code at each writes no request log and stores no request;
> Cloudflare's request logs for each are turned off, and no Logpush job exists. Cloudflare still keeps its standard
> records of each request: the address it came from, with that address's network and country and the request's path,
> query and user agent, for 31 days, in its traffic analytics and in its record of any request its security checks act
> on, which also keeps the request's referer; daily counts of requests, without addresses, for a year; and operational
> logs, for a period Cloudflare does not state. Each request's time is kept with its address, so for those 31 days a
> stop test result you submit, which holds its run's times, could be matched to the address the test agent's calls came
> from, and, when you fire an in-agent SDK's switch yourself, to the one the kit's own calls came from. For the test
> address, the address recorded is the one the test agent's calls come from. Unless you name a gateway or a subnet, the
> kit runs the test agent on the cloud's default network, so the address is not your account's own: on AWS Lambda,
> Lambda's default network, where it is an AWS address shared with other AWS customers; on Google Cloud, Cloud Run's
> default network, where it is an address from Google's dynamic pool, not one of your project's. If you name a gateway
> (`--via`), the calls go through it, and the address recorded is the one your gateway's calls leave from; if you name a
> subnet (`--subnet`), it is the one your network's calls leave from. Either may be your own. On Amazon Bedrock
> AgentCore, where the kit offers neither, it runs the test agent in AgentCore's public network mode, in no network of
> yours, so the address is not your account's own either; in Arvaken's own runs, it was an AWS address in the agent's
> region, a different one each run. On a test copy of your own agent, the kit does not choose the network: the address
> recorded is the one your copy's calls leave from, which is your own if the copy runs in a network of yours. When you
> fire an in-agent SDK's switch yourself, the kit's own calls to the test address come from the machine the kit runs on,
> and the address recorded for them is the one that machine's calls leave from, which is your own network's if the
> machine is in one. For the verification page, it is the address of whoever opens it.

If you choose, you can send Arvaken a result at https://app.arvaken.com/stop-test/submit, under the kit's terms:
https://arvaken.com/stop-test/terms.

AWS, with Lambda and Amazon Bedrock AgentCore, and Google Cloud. Azure follows.

## What it makes in your account

One CloudFormation stack, `arvaken-stop-test-<run>`, whose resources are each named with that prefix and tagged
`arvaken-stop-test=<run>`:

- the test agent: a Lambda function (Python 3.12, 128 MB) with a role of its own;
- a second role, which only the test agent may assume;
- an S3 bucket, private and encrypted, which only the two roles may write to.

The test agent writes no logs of its own. Your account's activity log (CloudTrail) records what the kit does, as it
records any change, and the kit cannot remove those records. The kit touches nothing it did not make, except to attach
your stop to the test agent's role when your stop is a policy of yours.

During a run, the kit invokes the test agent about once a second, and each time the agent tries each of four paths:

| Path | What the test agent does |
|---|---|
| Its own calls to AWS | writes and reads a small object in the bucket |
| Work under another identity | writes to the bucket with a session of the second role, taken before the stop |
| A key for a service outside your cloud | calls stop-test.arvaken.com with the random key the kit made for the run |
| The open internet | calls stop-test.arvaken.com with nothing |

With `--model`, it also tries a fifth: a call to a model (see [A call to a model](#a-call-to-a-model)).

<!-- CUSTOMER TEXT: approved by the founder, word for word, 30 October 2026 -->
On Lambda, the test agent keeps its clients, and their connections to AWS, from one call to the next while Lambda keeps
its environment, as AWS's own libraries do.
<!-- [source: aws-lambda-best-practices-clients-outside-handler, aws-botocore-max-pool-connections] -->

When the run ends, the kit takes off the stop it fired, deletes the stack, and checks each thing it made by its own
identifier: the stack, the function, both roles, the bucket, the function's log group and the stop. Anything still
there is named for you to delete.

## Install

You need Python 3.11 or later; for AWS, credentials where the AWS command line finds them; for Google Cloud, the
Google Cloud CLI (`gcloud`), signed in.

Every install is checked first. You check one file's signature, and that file names every file the install takes by its
SHA-256: the kit's own package and each package it needs. pip then installs exactly those files, or nothing.

1. Make a virtual environment, and install Sigstore's checker in it:

   ```
   python -m venv stop-test
   stop-test/bin/python -m pip install sigstore
   ```

   On Windows, use `stop-test\Scripts\python` in place of `stop-test/bin/python`, here and below.

2. Download the release's requirements file and its signature (in Windows PowerShell, type `curl.exe`):

   ```
   curl -LO https://github.com/arvaken/stop-test/releases/download/v0.4.0/requirements-0.4.0.txt
   curl -LO https://github.com/arvaken/stop-test/releases/download/v0.4.0/requirements-0.4.0.txt.sigstore.json
   ```

3. Check that this repository's release workflow signed it, for that version. The signature is also recorded in the
   public Rekor log:

   ```
   stop-test/bin/python -m sigstore verify github requirements-0.4.0.txt --cert-identity https://github.com/arvaken/stop-test/.github/workflows/release.yml@refs/tags/v0.4.0
   ```

4. Install exactly what it names. pip refuses any file whose SHA-256 differs:

   ```
   stop-test/bin/python -m pip install --require-hashes -r requirements-0.4.0.txt
   ```

The kit is then `stop-test/bin/stop-test`. Each release also lists its files' SHA-256 in `SHA256SUMS`, signed the same
way.

### On Windows on Arm

Use an x64 Python. The kit and sigstore need the cryptography package, whose current versions have no build for
Windows on Arm, so under an Arm Python their install tries to build it from source and fails. Windows 11 runs x64
Python on Arm: make the virtual environment with Python from python.org's "Windows installer (64-bit)", not its ARM64
one.

## Run it

Run it in an account you use for testing: it fires a real stop, in whichever account your credentials point to.

`plan` says what a run would make and do, and makes nothing:

```
stop-test aws plan --stop arn:aws:iam::aws:policy/AWSDenyAll --region eu-central-1
```

`run` says the same, asks you to type the run's name, and only then makes anything:

```
stop-test aws run --stop arn:aws:iam::aws:policy/AWSDenyAll --region eu-central-1
```

Name the stop with one of:

- `--stop <ARN>`: your declared stop, a managed policy, attached to the test agent's role alone. The kit refuses a
  stop that would reach any other identity, such as an organization's service control policy, and says why.
- `--inline-deny`: a policy the kit writes on the test agent's role, denying every action.
- `--revoke-sessions`: the policy AWS's console adds when you revoke a role's active sessions
  (`AWSRevokeOlderSessions`), put on the test agent's role and on the role it became, both made for the run. It denies
  sessions issued before the moment it names; a session issued afterwards is unaffected.
- `--own-trigger`: you fire your own stop (a button, an automation, a runbook) at the test agent, and the kit watches
  for the change. Your own trigger may stop more than the test agent, and the kit warns you of that first.

And if you wish:

- `--window`: how long after the stop each path is timed, such as `20m`; 15 minutes by default.
- `--repeats`: 1 to 5. Between repeats, the kit takes the stop off and waits until the agent's own calls work again.

In our own runs, one repeat took about 20 minutes, and five about 80.

A run writes three files where you ran it:

- `stop-test-<run>.json`: the result, in the format `stop-test-result/2`, signed with a key the kit makes for the run.
  The signature shows the file hasn't changed since it was signed. It shows nothing about who ran it, and it isn't
  Arvaken's attestation of anything;
- `stop-test-<run>.html`: a page showing what each path did beside what a stop on the role would be expected to do,
  with the errors seen;
- `stop-test-<run>-details.json`: the details behind the page. It holds your account's identifiers (the names of
  what the run made, and anything left), so keep it as you would any record of your account.

The result holds no error codes and nothing of your agents' work. To check that it has not changed since it was
signed:

```
stop-test verify stop-test-<run>.json
```

That is all a signature shows: not that the kit wrote it, who ran it, or that the run was honest.

The kit cleans up when a run ends, Ctrl-C included. If it could not, as when a shell is lost, remove what the run made
by the run's name, adding `--stop <ARN>` if the run attached a policy of yours:

```
stop-test aws clean --run <run> --region eu-central-1
```

### A call to a model

On AWS, the kit can also time the test agent's calls to a model. Name the model with `--model` and its Bedrock model
ID or inference profile ID:

```
stop-test aws plan --stop arn:aws:iam::aws:policy/AWSDenyAll --model eu.amazon.nova-micro-v1:0 --region eu-central-1
```

With each invocation, the test agent then also calls that model once, as its own role, asking for one token. AWS bills
each call to your account. The test agent keeps none of the model's answer: as on every path, it reports only whether
the call worked and, if not, its error's code. The kit lets only the test agent's role call the model: for a model ID,
that model in the run's region; for an inference profile ID, the profile in the run's region and the model it names in
every region, as AWS requires for a profile that sends calls to other regions. The second role can't call it.
<!-- [source: aws-bedrock-inference-profile-permissions] -->

The call must work before the stop. If it doesn't, as when the ID is wrong or your account can't call that model in
the run's region, the kit says so, times nothing, and removes what it made. After the stop, a call counts as stopped
only when the stop refused it, as access denied; every other failure, a throttle among them, is not counted, and the
page shows the errors seen. Between repeats, the kit also waits until the call to the model works again.

A run that calls a model needs a boundary of its own, `arvaken-stop-test-boundary-model` (see
[The permissions it needs](#the-permissions-it-needs)).

### Through your gateway

If your stop is a gateway's own switch, one your agents' calls go through, the kit can time it on AWS. On Google Cloud,
the gateway option waits for a later version. Name your gateway with `--via` and its address, in place of a stop:

```
stop-test aws plan --via http://gateway.example:8888 --product-attachment all-outbound --product-name "Our test gateway" --region eu-central-1
```

The test agent then sends through your gateway, as an HTTPS proxy, only the calls your gateway is attached to: with
`model`, its call to the model you name with `--model`; with `outside-services`, its call with a key and its
open-internet call; with `all-outbound`, every call it makes: its own calls to AWS, its work under the second role, its
call with a key, its open-internet call and, with `--model`, its call to the model. Its other calls go directly, as your
agents' would. Its call with a key and its open-internet call go to Arvaken's test address. Through your gateway, they
reach it from the address your gateway's traffic leaves from, which is yours, and Arvaken's test address sees that
address. Cloudflare keeps that address, with its network and country, for 31 days, as Arvaken's description of what
Cloudflare records says above.

With `--via`, name your gateway with both of:

- `--product-attachment`: how it is attached: `model` (its calls to a model), only with `--model`, since only then does
  the test agent call one; `outside-services` (its calls to outside services); or `all-outbound` (all its outbound
  traffic);
- `--product-name`: its name, in your own words, up to 200 characters. It's shown as you wrote it. The kit doesn't check
  it, and the result is your own test, not Arvaken's rating of any product.

And if you need them:

- `--ca-bundle <file>`: if your gateway inspects TLS, the certificate authority it uses, as PEM certificates of at most
  64 KB. The kit uses it for the calls through your gateway alone, and never writes it into the result.
- `--subnet <subnet-id>`, with one or more `--security-group <sg-id>`: the subnet the test agent runs in, where your
  gateway is reached only from your network. Lambda makes the test agent's network interfaces there. The kit attaches
  nothing else of yours, and after the run waits up to 30 minutes for AWS to remove those interfaces, then checks them
  gone.

Your gateway's switch may stop every agent behind it, not only the test agent, and the kit cannot see, limit or undo
what it reaches. So the kit warns you, and goes on only when you type the run's name. Use a gateway where stopping
everything behind it is safe, such as one you use only for testing. The kit never fires your switch, and never turns it
off.

When it asks, press Enter, then fire your stop. Each path is timed from that mark, so a time errs toward slower, never
faster. A path whose calls were already refused at your mark is reported as not measured. The kit times each path for 15
minutes after your mark, or longer if you give `--window` (15m or more) before the run. When the timing is done, the kit
says so, and you can turn your switch off. A run through a gateway is timed once and not repeated, since only you can
take its stop off.

<!-- CUSTOMER TEXT: the founder's own words, D655 (b) and open tunnels 3, 30 October 2026 -->
Switching your gateway off can't be measured as a stop: to the kit it looks the same as a broken network. Use a rule on
your gateway that refuses calls, such as a filter or a closed port. A rule on your gateway may not reach a connection
already open through it. The kit keeps its connections open, as AWS's own libraries do, so its times include that.

<!-- CUSTOMER TEXT: approved by the founder, word for word, 01:22 UTC on 31 October 2026 -->
<!-- Sources, read 31 October 2026: tinyproxy 1.11.1's src/main.c, lines 317-318 (-d sets daemonized = FALSE) and
399-400 (SIGHUP's handler is set only if daemonized, SIGUSR1's always; both reload),
https://github.com/tinyproxy/tinyproxy/blob/1.11.1/src/main.c ; Ubuntu noble-updates' debian/tinyproxy.service
(ExecStart=/usr/bin/tinyproxy -d $FLAGS, ExecReload=/bin/kill -USR1 $MAINPID),
https://git.launchpad.net/ubuntu/+source/tinyproxy/tree/debian/tinyproxy.service?h=ubuntu/noble-updates . Seen in
install-test on 30 October 2026 (package 1.11.1-3ubuntu0.1): a SIGHUP stopped the unit; a SIGUSR1 reloaded it. -->
If your gateway is tinyproxy on Ubuntu, load a changed rule with `sudo systemctl reload tinyproxy`, which sends it
SIGUSR1. A SIGHUP stops it there: Ubuntu's service runs tinyproxy in the foreground (`-d`), and tinyproxy 1.11.1 takes
SIGHUP as a reload only when it runs as a daemon.

<!-- CUSTOMER TEXT: approved by the founder, word for word, 30 October 2026 (D655, (c)) -->
A refusal from a gateway that inspects TLS (`--ca-bundle`), made inside the connection it opened, and any refusal
from a gateway reached over `https://`, read "not measured" for now: the kit can't yet tell them from AWS's own.

A path that did not work through your gateway before the stop is reported as not measured, never as stopped. If none
did, there is nothing to time: the kit asks for no mark, and removes what it made. The page shows each path beside what
your gateway's stop should reach, given how you said it is attached. The result and the kit's logs keep your gateway's
address as its scheme, host and port alone, never with a user name, password, path or query.

If a run in your subnet could not clean up, add the subnet, and the kit waits for the test agent's network interfaces
and checks them:

```
stop-test aws clean --run <run> --region eu-central-1 --subnet <subnet-id>
```

## On Amazon Bedrock AgentCore

### What it makes in your account

Each thing is named with the run and tagged `arvaken-stop-test=<run>`:

- the test agent: an AgentCore runtime, `arvaken_stop_test_<run>`, made from the kit's own code (Python 3.13) in
  AgentCore's public network mode, with a role of its own that AgentCore may take on for this runtime alone. A session
  of it ends after a minute idle, and lives at most an hour;
- a second role, which only the test agent's role may assume;
- an S3 bucket, `arvaken-stop-test-<run>`, private and encrypted, holding the test agent's code and the objects its
  paths write.

Both roles carry the kit's permissions boundary, as on Lambda. The test agent writes no logs of its own, and its role
may not write any. CloudTrail records what the kit does, as it records any change. The kit touches nothing it did not
make, except to attach your stop to the test agent's role when your stop is a policy of yours.

For every stop, the kit measures two things:

- **New calls to the agent.** About once a second, the kit calls the test agent, each call starting a session of its
  own, and the agent answers at once.
- **A session already running.** Before each stop, the kit opens one session of the test agent's. Its agent tries each
  of the four paths about once a second, as on Lambda, and reports each try on the call's streaming response. If the
  session ends, each of its paths reads as refused from then on.

When the run ends, the kit takes off the stop it fired, deletes what it made, and checks each thing by its own
identifier: the runtime, its endpoints, its workload identity, its code, the bucket, both roles, any log group and the
stop. Anything still there is named for you to delete.

### Run it

Run it in an account you use for testing.

```
stop-test agentcore plan --deny-calls --region eu-central-1
stop-test agentcore run --deny-calls --region eu-central-1
```

Name the stop with one of:

- `--stop <ARN>`: your declared stop, a managed policy, attached to the test agent's role alone, as on Lambda.
- `--inline-deny`: a policy the kit writes on the test agent's role, denying every action.
- `--deny-calls`: a resource policy the kit writes on the test agent, denying every call to it, from anyone.
- `--deny-calls-and-end-sessions`: the same, then the session the test agent is running ended.

`--window` and `--repeats` work as on Lambda. On AgentCore a window is at most 54 minutes, because the running session
is watched on one streaming response. Each call to the test agent starts a session of its own, about a thousand in a run
of one repeat, and AWS bills each session's use to your account.

The moment each stop was fired is CloudTrail's record of the call: IAM's for a policy on the role, AgentCore's for the
deny. Ending a session is recorded as a data event, which CloudTrail's event history does not hold. With `--trail`, the
kit makes a trail of the run's own, recording only the data events of the test agent and of its bucket's objects, into a
bucket only CloudTrail may write to. It fires nothing until the trail has recorded a call to the agent, which can take some minutes. Before deleting the
trail and its bucket, it copies their records into a folder beside the result, `stop-test-<run>-trail`, each with its
SHA-256. Without `--trail`, that moment is the kit's own clock, and the details say so. AWS charges for a trail's data
events.

A run writes the same three files as on Lambda. If a run could not clean up, remove what it made by the run's name:

```
stop-test agentcore clean --run <run> --region eu-central-1
```

### On a harness

A harness is AgentCore's configured agent: AWS runs its agent loop, with the model you name.
<!-- [source: aws-agentcore-harness-runs-the-loop] --> The kit tests a policy on a harness's role:

```
stop-test agentcore-harness plan --inline-deny --model openai.gpt-oss-20b-1:0 --region eu-central-1
stop-test agentcore-harness run --inline-deny --model openai.gpt-oss-20b-1:0 --region eu-central-1
```

Name the stop with `--stop <ARN>` or `--inline-deny`, as on a runtime. On a harness, the kit times only a policy on its
role. The deny-calls stops it times on a runtime aren't offered. Name its model with `--model` and its Bedrock model ID
or inference profile ID.

The kit makes, each named with the run and tagged `arvaken-stop-test=<run>`:

- the test agent: an AgentCore harness, `arvaken_stop_test_<run>`, which calls your model and has no tools and no
  memory, with a role of its own that AgentCore may take on for this harness alone. A harness runs inside AgentCore
  Runtime, and the kit checks that the runtime it runs in is gone with the harness;
  <!-- [source: aws-agentcore-harness-inside-runtime] -->
- a second role and an S3 bucket, as on a runtime.

Both roles carry a permissions boundary of their own, `arvaken-stop-test-boundary-harness` (see
[The permissions it needs](#the-permissions-it-needs)): a harness's role also calls its model, takes AWS's image for the
harness, and takes the harness's workload token.

For every stop, the kit measures three things:

- **A session already running.** Before each stop, the kit opens one session of the harness's and runs its own probe
  in it, as one command. About once a second, the probe tries each of the four paths as the harness's role. A harness
  runs a tool only when its model chooses one, so the paths are tried by the probe, not by the model.
  <!-- [source: aws-agentcore-harness-tools-reasoning, aws-agentcore-harness-execute-command] -->
- **Its model.** About once a second, the kit asks the harness something in that session, and the harness calls its
  model as its role. <!-- [source: aws-agentcore-harness-bedrock-role] --> AWS bills each call to your account. A call
  refused by a rate limit is never counted as stopped. <!-- CUSTOMER TEXT: this sentence as the founder changed it,
  word for word, by 01:37:35 UTC on 2 November 2026, in place of "A call refused for a limit on your account is never
  counted as stopped." -->
- **New calls to the agent.** About once a second, the kit runs a command that does nothing, each in a new session of
  the harness's.

`--window` and `--repeats` work as on a runtime. A window is at most 3295 seconds, just under 55 minutes: the kit
watches the running session with one command, and AWS lets a command run for at most an hour, which also has to cover
the time before the stop and the report after the window. <!-- [source: aws-agentcore-command-limits] --> The moment
each stop was fired is CloudTrail's record of the IAM call. A run writes the same three files. If a run could not clean
up, remove what it made by the run's name:

```
stop-test agentcore-harness clean --run <run> --region eu-central-1
```

## On Google Cloud

### What it makes in your project

Each thing is named with the run and labelled `arvaken-stop-test=<run>` where Google lets it be labelled:

- the test agent: a Cloud Run service, `arvaken-stop-test-<run>`, running the kit's agent code in Python's own image
  (Python 3.12, pinned by its digest), as a service account of its own, `arvaken-st-<run>`; one instance, kept
  running for the run;
- a second service account, `arvaken-st-<run>-b`, whose token only the test agent may take;
- a Cloud Storage bucket, `arvaken-stop-test-<run>`, with uniform access and public access prevented, which only the
  two accounts may write to.

Each grant is on those things alone, never on your project. The test agent writes no logs of its own. Cloud Run's
request logs record each call the kit makes to it, and Cloud Audit Logs record what the kit does, as they record any
change; the kit cannot remove those records. The kit touches nothing it did not make, except to fire a stop on the test
agent's own account.

During a run, the kit calls the test agent about once a second, and each time the agent tries each of four paths:

| Path | What the test agent does |
|---|---|
| Its own calls to Google Cloud | writes and reads a small object in the bucket, as its own account |
| Work under another identity | writes to the bucket with a token of the second account, taken before the stop |
| A key for a service outside your cloud | calls stop-test.arvaken.com with the random key the kit made for the run |
| The open internet | calls stop-test.arvaken.com with nothing |

When the run ends, the kit takes off the stop it fired, deletes what it made, and checks each by its own name: the
service, the bucket, both accounts and the run's deny policy. Anything still there is named for you to delete.

### Run it

Run it in a project you use for testing. It uses the Google Cloud CLI (`gcloud`), signed in as you; Cloud Shell has
it. The project needs the Cloud Run, IAM, IAM Service Account Credentials, Cloud Logging and Cloud Storage APIs
enabled. To fire a deny policy, you need the Deny Admin role (`roles/iam.denyAdmin`), which Google grants on an
organization only. A project with no organization cannot hold a deny policy: use `--disable-account`.

```
stop-test google plan --deny-all --project my-test-project --region europe-west3
stop-test google run --deny-all --project my-test-project --region europe-west3
```

Name the stop with one of:

- `--stop <name>`: your declared deny policy, by its name
  (`policies/cloudresourcemanager.googleapis.com%2Fprojects%2F<project>/denypolicies/<id>`). The kit reads it and
  makes a copy of its denied permissions for the run, naming the test agent's account alone. Your policy is never
  changed. A rule with a condition is refused, and the kit says why.
- `--deny-all`: a deny policy the kit makes, naming the test agent's account alone and denying what its paths use
  (Cloud Storage and IAM).
- `--disable-account`: the test agent's own service account, disabled, and enabled again between repeats.
- `--own-trigger`: you fire your own stop at the test agent's account, and the kit watches for the account disabled
  or a deny policy naming it. Your own trigger may stop more than the test agent, and the kit warns you of that first.

`--window` and `--repeats` work as on AWS. The moment each stop was fired is Cloud Audit Logs' record of the call. A
run writes the same three files as on AWS.

If a run could not clean up, remove what it made by the run's name:

```
stop-test google clean --run <run> --project my-test-project --region europe-west3
```

## On a test copy of your own agent

<!-- CUSTOMER TEXT: approved by the founder, word for word, 18:06:47 UTC on 2 November 2026 (part 2) -->
On AWS, the kit can also run on a test copy of one of your own agents, in place of its own test agent: a Lambda function
or an Amazon Bedrock AgentCore runtime. You deploy the copy with the kit's probe in it. The kit calls the copy about
once a second, and the probe tries the same four paths as the kit's test agent, from inside your copy. The kit never
deploys, changes or deletes your copy. Run it only on a test copy whose settings reach test systems alone, never on an
agent whose work matters: each call runs your copy's own code, which does whatever that code does with whatever its
settings reach.

### Add the probe

The probe is a Python package, `arvaken-stop-test-probe`, in each release of the kit. It needs Python 3.9 or later, and
boto3, which Lambda's Python runtime has. Check its signature as you check the kit's, then install it with your copy's
code:

```
curl -LO https://github.com/arvaken/stop-test/releases/download/v0.5.0/probe-requirements-0.5.0.txt
curl -LO https://github.com/arvaken/stop-test/releases/download/v0.5.0/probe-requirements-0.5.0.txt.sigstore.json
stop-test/bin/python -m sigstore verify github probe-requirements-0.5.0.txt --cert-identity https://github.com/arvaken/stop-test/.github/workflows/release.yml@refs/tags/v0.5.0
stop-test/bin/python -m pip install --require-hashes --no-deps --target <your copy's code> -r probe-requirements-0.5.0.txt
```

Then, in your handler, before your agent's own work, hand the kit's calls to the probe:

```python
from arvaken_stop_test_probe import heartbeat

def handler(event, context):
    if heartbeat.is_mine(event):
        return heartbeat.run(event)
    ...  # your agent's own work, unchanged
```

On AgentCore, do the same in your entrypoint. For the running session, `heartbeat.run` gives back an iterator of events,
which your entrypoint streams as its response.

A call is the kit's only if it carries the kit's marker, naming a run. The probe reads nothing of your agent's work and
writes no log. The address it calls is fixed in its code, never taken from the call.

If an SDK of yours wraps only its own clients, pass them, so that the probe's calls go through it: `heartbeat.run(event,
cloud=..., http=...)`, where `cloud` makes a client as `boto3.client` does, and `http(url, headers, timeout)` makes a
GET request and gives back its status. Otherwise the probe uses the runtime's own clients, boto3's and Python's urllib.
The result says which it used.

### What it makes in your account

<!-- CUSTOMER TEXT: approved by the founder, word for word, 18:06:47 UTC on 2 November 2026 (part 3); the second
paragraph approved by the founder, word for word, 17:10:07 UTC on 2 November 2026 ((c) (1)) -->
On Lambda, one CloudFormation stack, `arvaken-stop-test-<run>`, with no function: the role your copy runs as for the
test, `arvaken-stop-test-<run>-agent`, a second role and a bucket, as for the kit's own test agent. On AgentCore, the
same two roles and a bucket, and no code and no runtime.

For the test, your copy runs as a role the kit makes for the run, not its own. On Lambda, that role grants only what the
test needs, within the kit's boundary: putting and getting its own objects in the run's bucket, and assuming the run's
second role, each only for calls from your copy (`lambda:SourceFunctionArn`); calling the model you name with `--model`,
where you name one; and, for a copy in your VPC, the network actions Lambda needs for its interfaces, on your copy's own
subnets and security groups wherever EC2 lets a policy name them. On AgentCore, it grants putting and getting its own
objects in the run's bucket and assuming the run's second role, and AgentCore may use it only for your copy
(`aws:SourceArn`). Neither grants writing logs. The kit takes these permissions from its own code, never from your
copy's own role.

You point your copy at that role for the test, and back afterwards, as the kit tells you. On Lambda, that is one
command. On AgentCore, set the runtime's role in AgentCore's console, changing nothing else: `update-agent-runtime` also
works, but it needs the runtime's whole configuration again, and anything you leave out is removed. The kit checks that
your copy runs as the run's role before it times anything. When the run ends, it deletes that role only once your copy
no longer runs as it; until then, it names the role for you to delete. On Lambda, a copy whose settings are encrypted
with your own key is refused before anything is made, since the run's role can't use that key.

<!-- CUSTOMER TEXT: approved by the founder, word for word, 19:00:00 UTC on 2 November 2026 ("Approve as written") -->
A copy in your VPC calls from your network, as your agent does: each path reaches only what your subnets' routes and
endpoints let it reach. A path that doesn't work before the stop is reported as not run; where you name a model, its call
must work before anything is timed. The run's role's network actions aren't limited to calls from your copy: Lambda makes
your copy's interfaces outside its code, and those calls don't name your copy.
<!-- [source: aws-lambda-source-function-arn-not-enis] -->

### Run it

```
stop-test aws plan --copy arn:aws:lambda:eu-central-1:111122223333:function:my-agent-test --inline-deny --tool "runs code" --model-kind "a model provider's API" --region eu-central-1
stop-test agentcore plan --copy arn:aws:bedrock-agentcore:eu-central-1:111122223333:runtime/my_agent_test-abc123 --inline-deny --tool none --model-kind "no model" --region eu-central-1
```

<!-- CUSTOMER TEXT: approved by the founder, word for word, 18:06:47 UTC on 2 November 2026 (part 3); each flag's words
after it are the kit's own help, approved at 01:15:37 UTC on 2 November 2026, and its lists, approved by 19:02:12 UTC on
1 November 2026 -->
With `--copy`, name the stop with `--stop <ARN>` or `--inline-deny`, fired on the run's role alone, or on Lambda
`--revoke-sessions`, on the run's two roles; or with `--sdk` (below). Name also:

- `--tool`: a kind of tool your copy has, from the kit's list; give each that applies, or `--tool none`. The list:
  searches or reads the web, runs code, reads or writes files, reads or writes a database, sends email or messages,
  makes payments, changes cloud resources, calls other services' APIs, something else.
- `--model-kind`: the kind of model your copy calls, from the kit's list: no model, a model service of its cloud, a
  model provider's API, a model it runs itself.
- on AgentCore, `--endpoint-name`: the endpoint of your runtime the kit calls, DEFAULT unless you name another.

On Lambda, `--model` works as for the kit's own test agent: the probe also calls the model you name, as the run's role.
`--window` and `--repeats` work as for the kit's own test agent.

Before it makes anything, the kit asks you to type the run's name, to confirm that your copy is a test copy. Before
every firing, it warns you that your stop may reach more than the test agent, and asks again. A run on a copy writes two
files: the result, in the format `stop-test-result/3`, and its details.

### An in-agent SDK's switch

<!-- CUSTOMER TEXT: approved by the founder, word for word, 18:06:47 UTC on 2 November 2026 (part 4); the --sdk line
approved by the founder, word for word, 17:10:07 UTC on 2 November 2026 ((c) (2)); the witness paragraph, the founder's
own words, 01:08:36 UTC on 2 November 2026 (D722); the CloudTrail sentence approved by the founder, word for word,
17:34:43 UTC on 2 November 2026 -->
If your stop is an in-agent SDK's switch, name the SDK with `--sdk`, in place of a stop:

- `--sdk`: your in-agent SDK's name, in your own words, 1 to 200 characters. It's shown as you wrote it. The kit doesn't
  check it, and the result is your own test, not Arvaken's rating of that product.

You fire the switch yourself, and the kit fires nothing. When it asks, press Enter, then fire it. Each path is timed
from that mark, for at least 15 minutes, once and not repeated, since only you can turn your switch off. When the timing
is done, the kit says so, and you can turn your switch off. Then the kit asks for the file you exported from your SDK
that records it acting, and for the time and name of the entry in it that records your stop. It keeps only the file's
SHA-256 and that entry, never the file.

The kit's witness is a check, from the machine you run the kit on, that the run's bucket and Arvaken's test address kept
answering through the window, so a failure on a path wasn't caused by either of them being down. A failure counts only
if your SDK raised it in the call itself: a timeout or a lost connection, which a fault in your copy's own network would
cause, makes the path not measured. If your SDK refuses calls whenever it can't reach its own service, that refusal
looks the same to the kit as your switch, so check that your SDK's own record shows the switch acting at your mark.

A path reads stopped only by Arvaken's rule for an SDK's stop: it worked before your mark; from its first failure after
your mark to the window's end, every call on it failed, each with an error the call itself raised; the kit's witness
kept answering; and your SDK's record of acting is in its export. A rate limit is never counted as stopped. With
`--model` on Lambda, the path to the model also reads not stopped if CloudTrail shows a call from your copy to the model
from a second before its first failure to the window's end. With your SDK's stop, the kit reads CloudTrail for your
copy's calls to the model 15 minutes after the window ends, so the run ends at least that long after the window does.

### What Arvaken's test address sees

<!-- CUSTOMER TEXT: approved by the founder, word for word, 17:50:03 UTC on 2 November 2026 (lines 1 and 2) -->
On a test copy of yours, the probe's call with a key and its open-internet call reach Arvaken's test address from your
copy: the address recorded is the one your copy's calls leave from, which is your own if the copy runs in a network of
yours, and on Lambda's default network an AWS address. With your SDK's switch, the kit's witness also calls the test
address once a second, with no key, from the machine you run the kit on: the address recorded is the one that machine's
calls leave from, which is your own network's if the machine is in one. Cloudflare keeps each of those addresses, with
its network and country, for 31 days, as Arvaken's description of what Cloudflare records says above.

If you pass the probe your own HTTP client, or an SDK in your copy wraps the runtime's, that client may add its own
headers to the probe's calls, and they may identify you. A proxy that reads the calls, of your copy or of the machine
you run the kit on, may add headers too. Our test address keeps none of them. Of the headers a client or a proxy could
add or change, Cloudflare keeps two: a call's user agent, which the kit sets to its own name, and, where Cloudflare's
security checks act on the call, its referer, which the kit never sends. A client or a proxy that changes either changes
what Cloudflare keeps.

## What counts as stopped

<!-- CUSTOMER TEXT: approved by the founder, word for word, 30 October 2026 (his refusal ruling of 29 October 2026,
GENERAL: "the README lists, per stop kind, which refusals count") -->

After the stop, a call counts as stopped only where the stop itself refused it. Any other failure, such as a throttle,
a server error, a timeout or a lost connection, is not counted: it is neither stopped nor a success, and the page shows
it by its code. A refusal counts only on a path that worked before it.

| Stop | What counts as its refusal |
|---|---|
| `--stop`, `--inline-deny` or `--revoke-sessions`, on AWS | `AccessDenied` from Amazon S3, on the test agent's own calls and its work under another identity; `AccessDeniedException` from Amazon Bedrock, on its call to a model; and on every path, Lambda refusing to run the test agent with `KMSAccessDeniedException`, where the agent ran before the stop |
| `--stop` or `--inline-deny`, on AgentCore | `AccessDenied` from Amazon S3, on the running session's own calls and its work under another identity; `AccessDeniedException` from AgentCore, on new calls to the agent and, on a harness, on its model |
| `--deny-calls` | `AccessDeniedException` from AgentCore, on new calls to the agent. On the running session, nothing counts |
| `--deny-calls-and-end-sessions` | that, on new calls; on the running session, its end, from when AWS confirms it: asked to end the session again, AWS answers that there is no such session. A path seen calling after that, in the bucket or the run's trail, is not stopped. Calls to Arvaken's test address can't be seen, so its two paths rest on that confirmation |
| `--stop` or `--deny-all`, on Google Cloud | a `403` from Cloud Storage whose reason is `forbidden` or `insufficientPermissions` |
| `--disable-account` | those, a `401` whose reason is `authError` from a token not yet expired, and a `404` when the test agent asks for its own token |
| `--via`, your gateway | its own refusal of the test agent's connection through it: a `403`, or a `407` where your gateway's address carries a user name and password, read only where Lambda runs the test agent on the Python, botocore and urllib3 the kit was tested with |
| `--own-trigger` | those of the kind of stop the cloud's record of your action shows: CloudTrail's on AWS, Cloud Audit Logs' on Google Cloud. If it shows none of these, nothing counts as stopped |
| `--sdk`, on a test copy | an error your SDK raised in the call itself, on each path, from its first failure after your mark to the window's end, with the kit's witness answering and your SDK's record of acting in its export. A timeout, a lost connection or a rate limit never counts |

<!-- [source: aws-s3-access-denied-example, aws-lambda-invoke-kms-access-denied, google-storage-403-forbidden,
google-storage-403-insufficient-permissions, google-storage-401-auth-error, aws-bedrock-converse-access-denied,
aws-agentcore-invoke-access-denied, aws-agentcore-invoke-harness-access-denied, aws-agentcore-stop-session-not-found] -->
<!-- CUSTOMER TEXT: the AWS row's model path approved by the founder, word for word, 30 October 2026 -->
<!-- CUSTOMER TEXT: the --via row approved by the founder, word for word, 30 October 2026 (D655) -->
<!-- CUSTOMER TEXT: the three AgentCore rows approved by the founder, word for word, 30 October 2026 -->
<!-- CUSTOMER TEXT: the --sdk row approved by the founder, word for word, 18:06:47 UTC on 2 November 2026 (part 4) -->

A path whose calls after the stop were all not counted, or that was answered after the stop and then had nothing counted
until the window ended, reads "not measured": the kit cannot say whether the stop stopped it.

## The permissions it needs

The kit runs with your own credentials. To give it only what a run needs, use the ready-made policy for your cloud in
[`permissions/`](permissions). The kit's tests hold each to every call the kit makes.

- **AWS:** [`permissions/aws-policy.json`](permissions/aws-policy.json), an IAM policy. Each statement names only what a
  run makes (its stack, roles, function, bucket and log group, each `arvaken-stop-test-*`), except reading your stop
  policy, and eight reads that AWS lets a policy grant only on every resource: CloudTrail's event history, the tag
  listing, the log group listing, IAM's policy simulator, and EC2's listings of network interfaces, subnets, security
  groups and VPCs.

  The two roles a run makes carry a permissions boundary,
  [`permissions/aws-boundary.json`](permissions/aws-boundary.json), which allows only writing and reading a run's own
  bucket and assuming a run's own role. The policy lets its holder make a role, or give one a policy, only under that
  boundary or one of the kit's three below. So in an account that holds only this one, it cannot be used to make a role
  that reaches anything else. Create the boundary once, with an administrator's credentials, under its own name:

  ```
  aws iam create-policy --policy-name arvaken-stop-test-boundary --policy-document file://permissions/aws-boundary.json
  ```

  A run in your subnet (`--subnet`), or one that calls a model (`--model`), needs a boundary of its own instead, which
  allows more. Create one only to use that option, the same way, under the name given here:

  - `arvaken-stop-test-boundary-via`, from [`permissions/aws-boundary-via.json`](permissions/aws-boundary-via.json), for
    a run in your subnet. It also allows the six network actions Lambda takes to make the test agent's network
    interfaces, on every resource, so any role made under it can create and delete network interfaces, and change their
    private addresses, anywhere in your account. It denies them to any call from a function's own code, so neither the
    test agent's code nor any other function's under it can make them. The kit's policy doesn't limit whom such a role
    trusts, so anyone it trusts can do the same. <!-- [source: aws-lambda-vpc-permissions,
    aws-lambda-source-function-arn, aws-lambda-source-function-arn-not-enis] -->
  - `arvaken-stop-test-boundary-model`, from
    [`permissions/aws-boundary-model.json`](permissions/aws-boundary-model.json), for a run that calls a model. It also
    allows calling any Bedrock model, so any role made under it can call any model, billed to your account.
  - `arvaken-stop-test-boundary-via-model`, from
    [`permissions/aws-boundary-via-model.json`](permissions/aws-boundary-via-model.json), for a run that does both. It
    allows what each of the two allows.

  Before a run makes anything, the kit checks that the boundary its options need is there and is the kit's.
- **AgentCore:** [`permissions/aws-agentcore-policy.json`](permissions/aws-agentcore-policy.json), an IAM policy that
  lets its holder make a role only under the kit's boundary, `arvaken-stop-test-boundary`, or the harness's below. Each
  statement names only what a run makes, except reading your stop policy, the reads AWS allows only on every resource,
  and your default workload-identity directory, which AWS checks beside each workload identity a run reads or deletes.
  Its last two statements are needed only with `--trail`.
  <!-- [source: aws-sar-agentcore-create-agent-runtime, aws-sar-agentcore-delete-agent-runtime,
  aws-sar-agentcore-invoke-agent-runtime, aws-sar-agentcore-delete-workload-identity,
  aws-sar-agentcore-get-workload-identity] -->
  <!-- CUSTOMER TEXT: "an IAM policy that lets its holder make a role only under the kit's boundary, ...", in place of
  "an IAM policy under the same boundary", approved by the founder, word for word, 01:41 UTC on 31 October 2026 -->

  On a harness, attach a second policy beside it,
  [`permissions/aws-agentcore-harness-policy.json`](permissions/aws-agentcore-harness-policy.json). Its statements name
  only the run's harness, the runtime AWS makes for it and the memory AWS requires to make it, except reading inference
  profiles, which the kit does only for a profile you give as the model. The two are kept apart because IAM allows a
  managed policy at most 6,144 characters; create each as a managed policy. <!-- [source: aws-iam-managed-policy-size] -->

  A harness's two roles carry a boundary of their own,
  [`permissions/aws-boundary-harness.json`](permissions/aws-boundary-harness.json): the kit's boundary, and calling a
  model, taking AWS's image for a harness and taking a harness's workload token. Create it once, as the kit's:

  ```
  aws iam create-policy --policy-name arvaken-stop-test-boundary-harness --policy-document file://permissions/aws-boundary-harness.json
  ```

  AWS lists permission to create and delete a memory as required to create and delete a harness, so the kit's harness
  policy grants it, for the run's own resources only. The kit's harness has no memory, and after each run the kit checks that
  none is left. <!-- [source: aws-agentcore-harness-create-permissions, aws-agentcore-harness-delete-permissions,
  aws-sar-agentcore-create-harness] -->
- **A test copy:** the kit's own policy doesn't reach your copy. Attach a second policy beside it,
  [`permissions/aws-copy-policy.json`](permissions/aws-copy-policy.json), with your copy's region, account and name, or
  runtime ID, in place of the capitals. It lets the kit read your copy's settings and call it, and nothing else.
  <!-- CUSTOMER TEXT: approved by the founder, word for word, 18:06:47 UTC on 2 November 2026 (part 4) -->
- **Google Cloud:** [`permissions/google-role.yaml`](permissions/google-role.yaml), a custom role for your test project:

  ```
  gcloud iam roles create arvakenStopTest --project=my-test-project --file=permissions/google-role.yaml
  ```

  To fire a deny policy, you also need the Deny Admin role (`roles/iam.denyAdmin`) on your organization.

## Licence

Apache License 2.0. See [LICENSE](LICENSE).
