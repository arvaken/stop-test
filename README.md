# Arvaken stop test

The stop test is a kit you run yourself, in your own cloud account, with your own credentials. It deploys a test
agent of its own, fires the stop you have declared on that test agent alone, unless you fire your own, and times what
actually stops. When it finishes, it removes the stop it fired and everything it made.

You run it yourself. Arvaken never runs tests in your account. Nothing about your account leaves it. Two of the kit's
tests, of the open internet and of a key for a service outside your cloud, have the kit's test agent call Arvaken's test
address, stop-test.arvaken.com. Neither call carries anything of yours: the second carries only a random key the kit
makes for the run. The address answers with a fixed reply. What is kept of each call is Arvaken's one description of
what Cloudflare records, word for word:

> Arvaken's test address (stop-test.arvaken.com) and its verification page (verify.arvaken.com) are served by
> Cloudflare, on arvaken.com's Free plan. Arvaken's code at each writes no request log and stores no request;
> Cloudflare's request logs for each are turned off, and no Logpush job exists. Cloudflare still keeps its standard
> records of each request: the address it came from, with that address's network and country and the request's path,
> query and user agent, for 31 days, in its traffic analytics and in its record of any request its security checks act
> on, which also keeps the request's referer; daily counts of requests, without addresses, for a year; and operational
> logs, for a period Cloudflare does not state. Each request's time is kept with its address, so for those 31 days a
> stop test result you submit, which holds its run's times, could be matched to the address the test agent's calls came
> from. For the test address, the address recorded is the one the test agent's calls come from. Unless you name a
> gateway or a subnet, the kit runs the test agent on the cloud's default network, so the address is not your account's
> own: on AWS, Lambda's default network, where it is an AWS address shared with other AWS customers; on Google Cloud,
> Cloud Run's default network, where it is an address from Google's dynamic pool, not one of your project's. If you name
> a gateway (`--via`), the calls go through it, and the address recorded is the one your gateway's calls leave from; if
> you name a subnet (`--subnet`), it is the one your network's calls leave from. Either may be your own. For the
> verification page, it is the address of whoever opens it.

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
   curl -LO https://github.com/arvaken/stop-test/releases/download/v0.2.1/requirements-0.2.1.txt
   curl -LO https://github.com/arvaken/stop-test/releases/download/v0.2.1/requirements-0.2.1.txt.sigstore.json
   ```

3. Check that this repository's release workflow signed it, for that version. The signature is also recorded in the
   public Rekor log:

   ```
   stop-test/bin/python -m sigstore verify github requirements-0.2.1.txt --cert-identity https://github.com/arvaken/stop-test/.github/workflows/release.yml@refs/tags/v0.2.1
   ```

4. Install exactly what it names. pip refuses any file whose SHA-256 differs:

   ```
   stop-test/bin/python -m pip install --require-hashes -r requirements-0.2.1.txt
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

- `stop-test-<run>.json`: the result, in the format `stop-test-result/1`, signed with a key the kit makes for the run;
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
kit makes a trail of the run's own, recording only the test agent's data events, into a bucket only CloudTrail may write
to. It fires nothing until the trail has recorded a call to the agent, which can take some minutes. Before deleting the
trail and its bucket, it copies their records into a folder beside the result, `stop-test-<run>-trail`, each with its
SHA-256. Without `--trail`, that moment is the kit's own clock, and the details say so. AWS charges for a trail's data
events.

A run writes the same three files as on Lambda. If a run could not clean up, remove what it made by the run's name:

```
stop-test agentcore clean --run <run> --region eu-central-1
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

## The permissions it needs

The kit runs with your own credentials. To give it only what a run needs, use the ready-made policy for your cloud in
[`permissions/`](permissions). The kit's tests hold each to every call the kit makes.

- **AWS:** [`permissions/aws-policy.json`](permissions/aws-policy.json), an IAM policy. Each statement names only what a
  run makes (its stack, roles, function, bucket and log group, each `arvaken-stop-test-*`), except reading your stop
  policy, and four reads AWS allows only on every resource: CloudTrail's event history, the tag listing, the log group
  listing and IAM's policy simulator.

  The two roles a run makes carry a permissions boundary,
  [`permissions/aws-boundary.json`](permissions/aws-boundary.json), which allows only writing and reading a run's own
  bucket and assuming a run's own role. The policy lets its holder make a role, or give one a policy, only under that
  boundary, so it cannot be used to make a role that reaches anything else. Create the boundary once, with an
  administrator's credentials, under its own name:

  ```
  aws iam create-policy --policy-name arvaken-stop-test-boundary --policy-document file://permissions/aws-boundary.json
  ```

  Before a run makes anything, the kit checks that the boundary is there and is the kit's.
- **AgentCore:** [`permissions/aws-agentcore-policy.json`](permissions/aws-agentcore-policy.json), an IAM policy under
  the same boundary. Each statement names only what a run makes, except reading your stop policy and the reads AWS
  allows only on every resource. Its last two statements are needed only with `--trail`.
- **Google Cloud:** [`permissions/google-role.yaml`](permissions/google-role.yaml), a custom role for your test project:

  ```
  gcloud iam roles create arvakenStopTest --project=my-test-project --file=permissions/google-role.yaml
  ```

  To fire a deny policy, you also need the Deny Admin role (`roles/iam.denyAdmin`) on your organization.

## Licence

Apache License 2.0. See [LICENSE](LICENSE).
