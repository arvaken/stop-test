# Stop test: quick start

The kit puts a test agent of its own in your cloud account, fires your stop on that test agent alone, and times what
actually stops. Then it removes everything it made. Run it in an account you use for testing.

The full guide is [README.md](README.md). This page is the shortest way through it.

## 1. Install (about 5 minutes)

You need Python 3.11 or later and, for AWS, credentials the AWS command line can find. Follow
[Install](README.md#install): it checks the release's signature before pip installs anything.

## 2. Get the command for your stop

If your agents are on an Arvaken stop map, open the agent's card and press **Prove this stop**. It gives you this
command with your stop and region already filled in.

Otherwise, name the stop yourself. On AWS Lambda:

| Your stop | Add |
|---|---|
| A managed policy on the agent's role | `--stop <the policy's ARN>` |
| A policy written on the role that denies everything | `--inline-deny` |
| Revoking the role's active sessions | `--revoke-sessions` |
| Something you fire yourself (a button, a runbook) | `--own-trigger` |

AgentCore and Google Cloud have their own commands: see [On Amazon Bedrock AgentCore](README.md#on-amazon-bedrock-agentcore)
and [On Google Cloud](README.md#on-google-cloud).

## 3. See what it will do

```
stop-test aws plan --stop arn:aws:iam::111122223333:policy/agent-stop --region eu-central-1 --quick
```

The plan lists everything the run will make, and says if it will refuse to run.

## 4. Run it

```
stop-test aws run --stop arn:aws:iam::111122223333:policy/agent-stop --region eu-central-1 --quick
```

`--quick` times each path for 5 minutes after the stop, once. While it runs, the kit says each path's answer as soon as
it is known. A pass the test agent took before the stop, such as a session of another role, may keep working past 5
minutes: only a full run times that. For a full run, leave out `--quick` (15 minutes a repeat; add `--repeats 5` for
five).

## 5. Read the result

The kit writes three files beside you: the signed result (`stop-test-<run>.json`), a page to open in your browser, and
the details. Nothing is sent to Arvaken unless you choose to send it, at
[app.arvaken.com/stop-test/submit](https://app.arvaken.com/stop-test/submit), under the kit's terms.

If a run is interrupted, remove what it made:

```
stop-test aws clean --run <run> --region eu-central-1
```
