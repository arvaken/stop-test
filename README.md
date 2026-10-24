# Arvaken stop test

The stop test is a kit you run yourself, in your own cloud account, with your own credentials. It deploys a test
agent of its own, fires the stop you have declared on that test agent alone, and times what actually stops. When it
finishes, it removes the stop it fired and everything it made.

Arvaken runs nothing in your account. Nothing about your account leaves it. Two of the kit's tests, of the open internet
and of a key for a service outside your cloud, have the kit's test agent call Arvaken's test address,
stop-test.arvaken.com. Neither call carries anything of yours: the second carries only a random key the kit makes for
the run. The address answers with a fixed reply. What is kept of each call is Arvaken's one description of what
Cloudflare records, word for word:

> Arvaken's test address (stop-test.arvaken.com) and its verification page (verify.arvaken.com) are served by
> Cloudflare, on arvaken.com's Free plan. Arvaken's code at each writes no request log and stores no request;
> Cloudflare's request logs for each are turned off, and no Logpush job exists. Cloudflare still keeps its standard
> records of each request: the address it came from, for 31 days, in its traffic analytics and in its record of any
> request its security checks act on; daily counts of requests, without addresses, for a year; and operational logs, for
> a period Cloudflare does not state. For the test address, the address recorded is the test agent's public address. The
> kit runs the test agent on the cloud's default network, never in a network of yours, so the address is never your
> account's own: on AWS, Lambda's default network, where it is an AWS address shared with other AWS customers; on Google
> Cloud, Cloud Run's default network, where it is an address from Google's dynamic pool, not one of your project's. For
> the verification page, it is the address of whoever opens it.

Submitting results to Arvaken is not open yet.

AWS comes first. Google Cloud and Azure follow.

## What it makes in your account

One CloudFormation stack, `arvaken-stop-test-<run>`, whose resources are each named with that prefix and tagged
`arvaken-stop-test=<run>`:

- the test agent: a Lambda function (Python 3.12, 128 MB) with a role of its own;
- a second role, which only the test agent may assume;
- an S3 bucket, private and encrypted, which only the two roles may write to.

The test agent's role may not write logs, and the agent prints nothing, so a run leaves nothing in your account's
logs. The kit touches nothing it did not make, except to attach your stop to the test agent's role when your stop is a
policy of yours.

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

You need Python 3.11 or later, and AWS credentials where the AWS command line finds them. With
[uv](https://docs.astral.sh/uv/):

```
uv tool install "arvaken-stop-test[aws] @ https://github.com/arvaken/stop-test/releases/download/v0.1.1/arvaken_stop_test-0.1.1-py3-none-any.whl"
```

Or with pip, in a virtual environment:

```
python -m pip install "arvaken-stop-test[aws] @ https://github.com/arvaken/stop-test/releases/download/v0.1.1/arvaken_stop_test-0.1.1-py3-none-any.whl"
```

### Check what you download

Each release lists its files' SHA-256 in `SHA256SUMS`. Each file, `SHA256SUMS` included, is signed with Sigstore's
keyless signing by this repository's release workflow: its signature is beside it, as `<file>.sigstore.json`, and is
recorded in the public Rekor log. To check the package before you install it, download it and its `.sigstore.json`
from the release, then:

```
python -m pip install sigstore
python -m sigstore verify github arvaken_stop_test-0.1.1-py3-none-any.whl --cert-identity https://github.com/arvaken/stop-test/.github/workflows/release.yml@refs/tags/v0.1.1
```

and install the file you checked:

```
uv tool install "./arvaken_stop_test-0.1.1-py3-none-any.whl[aws]"
```

### On Windows on Arm

Use an x64 Python. The kit and sigstore need the cryptography package, whose current versions have no build for
Windows on Arm, so under an Arm Python their install tries to build it from source and fails. Windows 11 runs x64
Python on Arm.

With uv, add `--python cpython-3.13-windows-x86_64-none` to each `uv tool install` above, for example:

```
uv tool install --python cpython-3.13-windows-x86_64-none "arvaken-stop-test[aws] @ https://github.com/arvaken/stop-test/releases/download/v0.1.1/arvaken_stop_test-0.1.1-py3-none-any.whl"
```

With pip, make the virtual environment with Python from python.org's "Windows installer (64-bit)", not its ARM64 one,
and install sigstore in it too.

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
- `--revoke-sessions`: AWS's own policy that revokes active sessions (`AWSRevokeOlderSessions`), put on the test
  agent's role and on the role it became, both made for the run.
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
- `stop-test-<run>-details.json`: the details behind the page.

The result holds no error codes and nothing of your agents' work. To check that it has not changed since the kit
wrote it:

```
stop-test verify stop-test-<run>.json
```

That is all a signature shows: not who ran the kit, and not that the run was honest.

The kit cleans up when a run ends, Ctrl-C included. If it could not, as when a shell is lost, remove what the run made
by the run's name, adding `--stop <ARN>` if the run attached a policy of yours:

```
stop-test aws clean --run <run> --region eu-central-1
```

## Licence

Apache License 2.0. See [LICENSE](LICENSE).
