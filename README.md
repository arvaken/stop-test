# Arvaken stop test

The stop test is a kit you run yourself, in your own cloud account, with your own credentials. It deploys a test
agent of its own, fires the stop you have declared on that test agent alone, unless you fire your own, and times what
actually stops. When it finishes, it removes the stop it fired and everything it made.

You run it yourself. Arvaken never runs tests in your account. Nothing about your account leaves it, unless you name a
gateway or a subnet for the test agent's calls. Then the address they leave from may be your own, and is recorded as
below, and whoever runs your gateway sees the calls that pass through it. Two of the kit's tests, of the open internet
and of a key for a service outside your cloud, have the kit's test agent call Arvaken's test address,
stop-test.arvaken.com. Neither call carries anything of yours from the kit: the second carries only a random key the kit
makes for the run. A gateway you name may add its own headers to the calls it carries, and they may identify you. Our
test address keeps none of them. Of the headers a gateway could add or change, Cloudflare keeps two: a call's user
agent, which the kit sets to its own name, and, where Cloudflare's security checks act on the call, its referer, which
the kit never sends. A gateway that changes either changes what Cloudflare keeps. The address answers with a fixed
reply. What is kept of each call is Arvaken's one description of what Cloudflare records, word for word:

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
> own: on AWS Lambda, Lambda's default network, where it is an AWS address shared with other AWS customers; on Google
> Cloud, Cloud Run's default network, where it is an address from Google's dynamic pool, not one of your project's. If
> you name a gateway (`--via`), the calls go through it, and the address recorded is the one your gateway's calls leave
> from; if you name a subnet (`--subnet`), it is the one your network's calls leave from. Either may be your own. On
> Amazon Bedrock AgentCore, where the kit offers neither, it runs the test agent in AgentCore's public network mode, in
> no network of yours, so the address is not your account's own either; in Arvaken's own runs, it was an AWS address in
> the agent's region, a different one each run. For the verification page, it is the address of whoever opens it.

If you choose, you can send Arvaken a result at https://app.arvaken.com/stop-test/submit, under the kit's terms:
https://arvaken.com/stop-test/terms.

AWS and Google Cloud. Azure follows.

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

### Through your gateway

If your stop is a gateway's own switch, one your agents' calls go through, the kit can time it on AWS. On Google Cloud,
the gateway option waits for a later version. Name your gateway with `--via` and its address, in place of a stop:

```
stop-test aws plan --via https://gateway.example:8443 --product-attachment all-outbound --product-name "Our test gateway" --region eu-central-1
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

A path that did not work through your gateway before the stop is reported as not measured, never as stopped. If none
did, there is nothing to time: the kit asks for no mark, and removes what it made. The page shows each path beside what
your gateway's stop should reach, given how you said it is attached. The result and the kit's logs keep your gateway's
address as its scheme, host and port alone, never with a user name, password, path or query.

If a run in your subnet could not clean up, add the subnet, and the kit waits for the test agent's network interfaces
and checks them:

```
stop-test aws clean --run <run> --region eu-central-1 --subnet <subnet-id>
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
    trusts, so anyone it trusts can do the same. <!-- [source: aws-lambda-vpc-permissions-all-resources,
    aws-lambda-source-function-arn-injected, aws-lambda-source-function-arn-not-on-eni] -->
  - `arvaken-stop-test-boundary-model`, from
    [`permissions/aws-boundary-model.json`](permissions/aws-boundary-model.json), for a run that calls a model. It also
    allows calling any Bedrock model, so any role made under it can call any model, billed to your account.
  - `arvaken-stop-test-boundary-via-model`, from
    [`permissions/aws-boundary-via-model.json`](permissions/aws-boundary-via-model.json), for a run that does both. It
    allows what each of the two allows.

  Before a run makes anything, the kit checks that the boundary its options need is there and is the kit's.
- **Google Cloud:** [`permissions/google-role.yaml`](permissions/google-role.yaml), a custom role for your test project:

  ```
  gcloud iam roles create arvakenStopTest --project=my-test-project --file=permissions/google-role.yaml
  ```

  To fire a deny policy, you also need the Deny Admin role (`roles/iam.denyAdmin`) on your organization.

## Licence

Apache License 2.0. See [LICENSE](LICENSE).
