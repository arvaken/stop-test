"""One run of the stop test on an AgentCore harness: make the test harness, time what is measured around each stop,
remove the stop, tear down, and the signed result (arvaken/mark, AGENTCORE-MEASUREMENT.md, section 7; D618).

A harness is AWS's own agent loop, configured rather than coded: AWS runs its managed image in an AgentCore runtime of
its own, each session in its own microVM, as the harness's execution role
[source: aws-agentcore-harness-execution-role], and the harness calls its model with that role
[source: aws-agentcore-harness-bedrock-role]. A harness takes one kind of stop, a policy on its role (HARNESS_KIND): it
takes no resource policy of its own, so the deny-calls kinds do not apply (the design's section 6). The founder's
rulings (29 October 2026): its model at about one turn a second; the runtime's four paths and its model; and, as on the
runtime, a running session and new calls; then (A) a new call is a command that does nothing, (B) the model path is the
harness's own turns, (C) both stops, AWSDenyAll and the inline deny-all.

**The test harness** (make): named `arvaken_stop_test_<run>`, with the run's model and nothing else to call: no tools,
and `allowedTools` empty, as the built-in `shell` and `file_operations` are otherwise on in every session
[source: aws-agentcore-harness-default-tools]; memory disabled, so no memory resource is made; one iteration a turn, a
few tokens, and a sliding window over the conversation, so each turn is one small call to the model. Its role is named
as the runtime's (stack.names), so a policy on it is fired, removed and found in CloudTrail exactly as on the runtime.

**Three things are measured, every repeat:**

1. **The running session's four paths.** A harness runs a tool only when its model chooses one
   [source: aws-agentcore-harness-tools-reasoning], so the paths are tried by the kit's probe (probe.py), run in the
   session as one InvokeAgentRuntimeCommand for the whole watch [source: aws-agentcore-harness-execute-command,
   aws-agentcore-command-limits], and read as it streams (CommandStream), as the runtime's watch is (run.Stream).
2. **Its model:** an InvokeHarness turn in the same session about every TURN_EVERY seconds, one after another (Turns).
   Commands and turns run in a session side by side [source: aws-agentcore-command-concurrent]. A turn worked where the
   model answered: its stream counted output tokens and held no error. Each is timed as a new call is.
3. **New calls to it:** about once a second, a command that does nothing (NOOP), each in a new session of its own, made
   on threads as the runtime's new calls are (NewCommands). It reaches the harness without its model.

Before each stop, as on the runtime: the session's own calls must work READY_TRIES in a row; the model and new calls
are tried only where the last before the stop worked. Between repeats the kit removes the stop and waits until its
removal holds: every turn answered for RECOVERED seconds (recover). Teardown deletes the harness, then the bucket once
the session's writes have stopped (run.writes_stopped), and checks each thing gone by its own identifier.

A harness's model calls are billed and rated per minute: the running session's turns, about one a second, are the run's
only calls to the model while a stop is watched; new calls make none.
"""
from __future__ import annotations

import base64
import hashlib
import json
import queue
import re
import shlex
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, wait as wait_for
from dataclasses import dataclass, replace
from importlib import resources
from typing import Any

from arvaken_stop_test import __version__, result
from arvaken_stop_test.agentcore import fire as firing
from arvaken_stop_test.agentcore import run as running
from arvaken_stop_test.agentcore.agent import LONGEST
from arvaken_stop_test.agentcore.run import (KIT_CREDENTIALS, LEAD, NEW_CALL_WAIT, NEW_CALL_WORKERS, READY_WAIT,
                                             RECOVERED, RECOVERY, SESSION_ENDED, SESSION_PATHS, SLACK, Clients, Clock,
                                             NotStarted, Repeat, Run, _gone, _NotFound, _retrying, _session, code,
                                             open_session, writes_after, writes_stopped)
from arvaken_stop_test.agentcore.stack import (IDLE, MAX_LIFETIME, NETWORK_MODE, TAG, names, private_bucket,
                                               second_policy, second_trust, to_json)
from arvaken_stop_test.aws import fire as aws_fire
from arvaken_stop_test.timing import HOLD, PATH_WORDS, WINDOWS, Beat

HARNESS_KIND = "policy on an AgentCore harness's role"
AGENT_KIND = "aws-agentcore-harness"
MODEL, NEW_CALLS = "model", "new_calls"
PATHS = (*SESSION_PATHS, MODEL, NEW_CALLS)
HARNESS_BOUNDARY = "arvaken-stop-test-boundary-harness"
WARM_UP = 10                 # commands before the first stop, to read the microVM's clock
TURN_EVERY = 1.0             # seconds between the starts of the running session's turns
TURN_TOKENS = 16             # the most output tokens a turn may take
TURN_TIMEOUT = 60            # seconds a turn may last (the harness's timeoutSeconds)
WINDOW_MESSAGES = 4          # the sliding window over the session's conversation
SYSTEM_PROMPT = "You are a test agent. Answer every message with one word."
PROMPT = "ping"
NOOP = "true"                # a new call: a command that does nothing
NOOP_TIMEOUT = 60
COMMAND_ACCEPT = "application/vnd.amazon.eventstream"
# The kinds of event a stream from AgentCore ends with when the call failed, beside an exception.
ERROR_EVENTS = ("accessDeniedException", "internalServerException", "resourceNotFoundException",
                "serviceQuotaExceededException", "throttlingException", "validationException", "runtimeClientError")
# An error's code, where AgentCore gives a model's failure as an event's message: the code alone is kept.
ERROR_CODE = re.compile(r"\b((?:[A-Z][a-z]+)+(?:Exception|Error)|AccessDenied|ExpiredToken)\b")
MODEL_ID = re.compile(r"[a-z0-9-]{1,63}(\.[a-z0-9-]{1,63}){1,2}(:[a-z0-9-]{1,63}){0,2}")
# Where the role takes AWS's managed image from, on the public network [source: aws-agentcore-harness-ecr-public].
IMAGE_PULL = ("ecr-public:GetAuthorizationToken", "sts:GetServiceBearerToken")
WORKLOAD_TOKEN = ("bedrock-agentcore:GetWorkloadAccessToken", "bedrock-agentcore:GetWorkloadAccessTokenForJWT")
MODEL_CALLS = ("bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream")

# CUSTOMER TEXT: for the founder's approval, word for word, with the harness module
NO_HARNESS_BOUNDARY = (f"Your account has no policy {HARNESS_BOUNDARY}, the permissions boundary the kit puts on a "
                       "harness's roles. Create it once from permissions/aws-boundary-harness.json, as the README's "
                       "\"The permissions it needs\" says.")
# CUSTOMER TEXT: for the founder's approval, word for word, with the harness module
NOT_THE_HARNESS_BOUNDARY = (f"Your account's policy {HARNESS_BOUNDARY} is not the kit's permissions boundary for a "
                            "harness: its default version differs from permissions/aws-boundary-harness.json.")
# CUSTOMER TEXT: for the founder's approval, word for word, with the harness module
NOT_A_MODEL = "give the model as a Bedrock model ID or inference profile ID, such as openai.gpt-oss-20b-1:0"
# CUSTOMER TEXT: approved by the founder, by 11:09:43 UTC on 29 October 2026 (D562, F4: his five model lines), as the
# AWS module's MODEL_DID_NOT_WORK says it on its branch (model-row 613b18f)
MODEL_DID_NOT_WORK = ("Before the stop, a call to the model {model} did not work ({codes}), so nothing was timed. "
                      "Check that your account can call it in {region}.")


@dataclass
class HarnessRun(Run):
    model: str = ""
    probe_sha256: str = ""
    credentials_from: dict[str, str | None] | None = None   # each session's: where its probe found the role's keys

    @property
    def stop_kind(self) -> str:
        return HARNESS_KIND


# -- what the kit makes
def harness_names(run: str) -> dict[str, str]:
    n = names(run)
    return {**n, "harness": n["runtime"], "harness_runtime": f"harness_{n['runtime']}"}


def is_profile(model: str) -> bool:
    """A Bedrock ID with two dots names an inference profile (eu.amazon.nova-micro-v1:0); one, a model."""
    return model.count(".") == 2


def model_arns(model: str, region: str, account: str, partition: str = "aws") -> list[str]:
    """What the harness's role may call: for a model ID, that model in the run's region; for an inference profile ID,
    the profile in the run's region and the model it names in every region, as a profile may send a call to another."""
    if not is_profile(model):
        return [f"arn:{partition}:bedrock:{region}::foundation-model/{model}"]
    return [f"arn:{partition}:bedrock:{region}:{account}:inference-profile/{model}",
            f"arn:{partition}:bedrock:*::foundation-model/{model.split('.', 1)[1]}"]


def harness_arn_patterns(run: str, region: str, account: str, partition: str = "aws") -> list[str]:
    """Every ARN that may assume the harness's role: the harness, and the runtime AgentCore makes for it."""
    n = harness_names(run)
    return [f"arn:{partition}:bedrock-agentcore:{region}:{account}:harness/{n['harness']}-*",
            f"arn:{partition}:bedrock-agentcore:{region}:{account}:runtime/{n['harness_runtime']}-*"]


def harness_trust(run: str, region: str, account: str, partition: str = "aws") -> dict[str, Any]:
    """The harness's role trusts AgentCore alone, for this run's harness alone."""
    return {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "bedrock-agentcore.amazonaws.com"}, "Action": "sts:AssumeRole",
        "Condition": {"StringEquals": {"aws:SourceAccount": account},
                      "ArnLike": {"aws:SourceArn": harness_arn_patterns(run, region, account, partition)}}}]}


def harness_policy(run: str, region: str, account: str, model: str, partition: str = "aws") -> dict[str, Any]:
    """The harness's own calls: its objects in the run's bucket, assuming the run's second role, its model, AWS's
    managed image, and its workload token."""
    n = harness_names(run)
    directory = f"arn:{partition}:bedrock-agentcore:{region}:{account}:workload-identity-directory/default"
    return {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["s3:PutObject", "s3:GetObject"],
         "Resource": f"arn:{partition}:s3:::{n['bucket']}/own/*"},
        {"Effect": "Allow", "Action": "sts:AssumeRole",
         "Resource": f"arn:{partition}:iam::{account}:role/{n['second_role']}"},
        {"Effect": "Allow", "Action": list(MODEL_CALLS), "Resource": model_arns(model, region, account, partition)},
        {"Effect": "Allow", "Action": list(IMAGE_PULL), "Resource": "*"},
        {"Effect": "Allow", "Action": list(WORKLOAD_TOKEN),
         "Resource": [directory, f"{directory}/workload-identity/{n['harness_runtime']}-*"]}]}


def boundary_document() -> dict[str, Any]:
    """The permissions boundary on a harness's two roles, as permissions/aws-boundary-harness.json gives it for your
    account to hold: the kit's boundary, and what a harness's role needs beside it (its model, AWS's managed image,
    its workload token)."""
    return json.loads(resources.files("arvaken_stop_test.agentcore").joinpath("boundary-harness.json")
                      .read_text(encoding="utf-8"))


def why_no_boundary(iam: Any, sts: Any) -> str | None:
    """Why a run cannot make a harness's roles under the kit's boundary for a harness, or None: the policy must be in
    your account, and its default version must be the kit's, statement for statement, as aws/fire.py checks its own."""
    caller = sts.get_caller_identity()
    arn = f"arn:{caller['Arn'].split(':')[1]}:iam::{caller['Account']}:policy/{HARNESS_BOUNDARY}"
    try:
        version = iam.get_policy(PolicyArn=arn)["Policy"]["DefaultVersionId"]
    except Exception as e:
        if code(e) == "NoSuchEntity":
            return NO_HARNESS_BOUNDARY
        raise
    document = iam.get_policy_version(PolicyArn=arn, VersionId=version)["PolicyVersion"]["Document"]
    document = json.loads(document) if isinstance(document, str) else document
    statements = lambda d: sorted(json.dumps(s, sort_keys=True) for s in d["Statement"])  # noqa: E731
    return None if statements(document) == statements(boundary_document()) else NOT_THE_HARNESS_BOUNDARY


def harness_boundary_arn(account: str, partition: str = "aws") -> str:
    return f"arn:{partition}:iam::{account}:policy/{HARNESS_BOUNDARY}"


def harness_request(run: str, region: str, role_arn: str, endpoint: str, second_role_arn: str, model: str,
                    outside_key: str | None = None) -> dict[str, Any]:
    """CreateHarness's request for the run's test harness."""
    import secrets
    n = harness_names(run)
    return {
        "harnessName": n["harness"],
        "executionRoleArn": role_arn,
        "environment": {"agentCoreRuntimeEnvironment": {
            "lifecycleConfiguration": {"idleRuntimeSessionTimeout": IDLE, "maxLifetime": MAX_LIFETIME},
            "networkConfiguration": {"networkMode": NETWORK_MODE}}},
        "environmentVariables": {"BUCKET": n["bucket"], "ENDPOINT": endpoint,
                                 "OUTSIDE_KEY": outside_key or secrets.token_hex(16), "SECOND_ROLE": second_role_arn},
        "model": {"bedrockModelConfig": {"modelId": model, "maxTokens": TURN_TOKENS, "apiFormat": "converse_stream"}},
        "systemPrompt": [{"text": SYSTEM_PROMPT}],
        "allowedTools": [],
        "memory": {"disabled": {}},
        "truncation": {"strategy": "sliding_window", "config": {"slidingWindow": {"messagesCount": WINDOW_MESSAGES}}},
        "maxIterations": 1,
        "maxTokens": TURN_TOKENS,
        "timeoutSeconds": TURN_TIMEOUT,
        "tags": {TAG: run},
    }


# -- the probe, as a command
def probe_source() -> str:
    return resources.files("arvaken_stop_test.agentcore").joinpath("probe.py").read_text(encoding="utf-8")


def probe_command(*args: str) -> str:
    """The probe as one command: its source, base64 in the command itself, run by the microVM's Python."""
    source = base64.b64encode(probe_source().encode("utf-8")).decode("ascii")
    run_it = f'import base64; exec(base64.b64decode("{source}"))'
    return (f"PY=$(command -v python3 || command -v python) && exec \"$PY\" -c {shlex.quote(run_it)} "
            + " ".join(shlex.quote(a) for a in args))


def _error_of(name: str, event: dict) -> str:
    """A stream's error event, by its code: one named in its message where there is one, else the event's own name."""
    found = ERROR_CODE.search(str((event or {}).get("message") or ""))
    return found.group(1) if found else name[:1].upper() + name[1:]


def command(c: Clients, r: Run, session: str, text: str, timeout: int) -> tuple[str, int | None, str | None]:
    """One command in a session of the harness's: its standard output, its exit code, and an error's code, if any."""
    got = c.data.invoke_agent_runtime_command(agentRuntimeArn=r.outputs["Harness"], runtimeSessionId=session,
                                              qualifier="DEFAULT", contentType="application/json",
                                              accept=COMMAND_ACCEPT, body={"command": text, "timeout": timeout})
    out, exit_code, error = [], None, None
    for event in got["stream"]:
        chunk = event.get("chunk") or {}
        if "contentDelta" in chunk:
            out.append(chunk["contentDelta"].get("stdout") or "")
        if "contentStop" in chunk:
            stop = chunk["contentStop"]
            exit_code = stop.get("exitCode")
            if stop.get("status") not in (None, "COMPLETED"):
                error = error or str(stop["status"])
        for name in ERROR_EVENTS:
            if name in event:
                error = error or _error_of(name, event[name])
    return "".join(out), exit_code, error


def turn(c: Clients, r: Run, session: str) -> None:
    """One turn of the harness's: it worked where the model answered, its stream counting output tokens and holding no
    error; else it raises, with the error's code."""
    got = c.data.invoke_harness(harnessArn=r.outputs["Harness"], runtimeSessionId=session,
                                messages=[{"role": "user", "content": [{"text": PROMPT}]}])
    answered, error = False, None
    for event in got["stream"]:
        if "metadata" in event:
            answered = answered or ((event["metadata"].get("usage") or {}).get("outputTokens") or 0) > 0
        for name in ERROR_EVENTS:
            if name in event:
                error = error or _error_of(name, event[name])
    if error or not answered:
        raise _Failed(error or "NoAnswer")


class _Failed(Exception):
    def __init__(self, found: str):
        super().__init__(found)
        self.response = {"Error": {"Code": found}}


class CommandStream:
    """The running session's probe: one command for the whole watch, read on a thread of its own, its standard output
    a line of JSON for each try. As run.Stream: `poll` gives the events that have come; `ended` is the kit's clock when
    the command's stream closed, and how ("done" once the probe said its watch was over), unless the kit closed it."""

    def __init__(self, c: Clients, r: Run, session: str, seconds: float, clock: Clock):
        self.c, self.r, self.session, self.seconds, self.clock = c, r, session, seconds, clock
        self.events: queue.SimpleQueue = queue.SimpleQueue()
        self.ended: tuple[float, str] | None = None
        self.closing = False
        self.body = None
        self.thread = threading.Thread(target=self._read, daemon=True)
        self.thread.start()

    def _read(self) -> None:
        how, buffer = "StreamEnded", ""
        try:
            got = self.c.data.invoke_agent_runtime_command(
                agentRuntimeArn=self.r.outputs["Harness"], runtimeSessionId=self.session, qualifier="DEFAULT",
                contentType="application/json", accept=COMMAND_ACCEPT,
                body={"command": probe_command(str(self.seconds), self.session, self.r.region,
                                               self.r.outputs["Bucket"], self.r.outputs["Endpoint"],
                                               self.r.outputs["SecondRole"]),
                      "timeout": int(min(self.seconds + SLACK, LONGEST))})
            self.body = got["stream"]
            for event in self.body:
                chunk = event.get("chunk") or {}
                buffer += (chunk.get("contentDelta") or {}).get("stdout") or ""
                *lines, buffer = buffer.split("\n")
                for line in lines:
                    if line.strip():
                        found = json.loads(line)
                        self.events.put(found)
                        if found.get("done"):
                            how = "done"
                if "contentStop" in chunk and how != "done":
                    how = f"CommandEnded:{chunk['contentStop'].get('status')}"
                for name in ERROR_EVENTS:
                    if name in event:
                        how = _error_of(name, event[name])
        except Exception as e:  # noqa: BLE001 - how the stream closed, by its code
            how = code(e)
        if not self.closing:
            self.ended = (self.clock.now(), how)

    def poll(self) -> list[dict]:
        out = []
        while True:
            try:
                out.append(self.events.get_nowait())
            except queue.Empty:
                return out

    def close(self) -> None:
        self.closing = True
        if self.body is not None:
            try:
                self.body.close()
            except Exception:  # noqa: BLE001 - closed already
                pass
        self.thread.join(timeout=10.0)


class _Calls:
    """Calls made on threads, one each `tick`, each timed as a new call to the runtime is (run.NewCalls): an answered
    call when it was sent, a refused one when its refusal came back, each on the kit's clock moved onto the agent's."""

    workers = NEW_CALL_WORKERS

    def __init__(self, c: Clients, r: Run, clock: Clock):
        self.c, self.r, self.clock = c, r, clock
        self.pool = (c.executor or (lambda: ThreadPoolExecutor(max_workers=self.workers)))()
        self.lock = threading.Lock()
        self.found: list[tuple[float, Beat]] = []
        self.futures: list[Any] = []
        self.fatal: Exception | None = None

    def call(self) -> None:
        raise NotImplementedError

    def one(self) -> None:
        sent = self.clock.now()
        try:
            self.call()
            beat = Beat(sent + self.r.offset, True)
        except Exception as e:  # noqa: BLE001 - a refusal is the path's result; the kit's own credentials end the run
            if code(e) in KIT_CREDENTIALS:
                self.fatal = e
                return
            beat = Beat(self.clock.now() + self.r.offset, False, code(e))
        with self.lock:
            self.found.append((sent, beat))

    def tick(self) -> None:
        if self.fatal is not None:
            raise self.fatal
        self.futures.append(self.pool.submit(self.one))

    def finish(self, limit: float = NEW_CALL_WAIT) -> list[tuple[float, Beat]]:
        wait_for(self.futures, timeout=limit)
        self.pool.shutdown(wait=False, cancel_futures=True)
        if self.fatal is not None:
            raise self.fatal
        with self.lock:
            return sorted(self.found, key=lambda f: f[0])


class NewCommands(_Calls):
    """New calls to the harness: a command that does nothing, each in a new session of its own."""

    def call(self) -> None:
        _, exit_code, error = command(self.c, self.r, _session(self.r, "new"), NOOP, NOOP_TIMEOUT)
        if error or exit_code != 0:
            raise _Failed(error or f"Exit{exit_code}")


class Turns(_Calls):
    """The running session's model path: a turn each `tick`, but never two at once, so about one every TURN_EVERY
    seconds, one after another."""

    workers = 1

    def __init__(self, c: Clients, r: Run, clock: Clock, session: str):
        super().__init__(c, r, clock)
        self.session = session

    def call(self) -> None:
        turn(self.c, self.r, self.session)

    def tick(self) -> None:
        if self.fatal is not None:
            raise self.fatal
        if not self.futures or self.futures[-1].done():
            self.futures.append(self.pool.submit(self.one))


# -- the run
def make(c: Clients, r: HarnessRun, endpoint: str, clock: Clock) -> None:
    """Make the run's roles, bucket and harness, in that order, and wait for the harness to be ready."""
    n = harness_names(r.run)
    tags = [{"Key": TAG, "Value": r.run}]
    boundary = harness_boundary_arn(r.account, r.partition)
    r.outputs["AgentRole"] = c.iam.create_role(
        RoleName=n["agent_role"], PermissionsBoundary=boundary, Tags=tags,
        AssumeRolePolicyDocument=to_json(harness_trust(r.run, r.region, r.account, r.partition)))["Role"]["Arn"]
    c.iam.put_role_policy(RoleName=n["agent_role"], PolicyName="own-calls",
                          PolicyDocument=to_json(harness_policy(r.run, r.region, r.account, r.model, r.partition)))
    r.outputs["SecondRole"] = _retrying(lambda: c.iam.create_role(
        RoleName=n["second_role"], AssumeRolePolicyDocument=to_json(second_trust(r.outputs["AgentRole"])),
        PermissionsBoundary=boundary, Tags=tags), {"MalformedPolicyDocument"}, clock)["Role"]["Arn"]
    c.iam.put_role_policy(RoleName=n["second_role"], PolicyName="another-identity",
                          PolicyDocument=to_json(second_policy(r.run, r.partition)))
    private_bucket(c.s3, n["bucket"], r.region, r.run)
    r.outputs["Bucket"] = n["bucket"]
    r.probe_sha256 = hashlib.sha256(probe_source().encode("utf-8")).hexdigest()
    made = _retrying(lambda: c.control.create_harness(**harness_request(
        r.run, r.region, r.outputs["AgentRole"], endpoint, r.outputs["SecondRole"], r.model)),
        {"ValidationException", "AccessDeniedException"}, clock)["harness"]
    r.outputs["Harness"], r.outputs["HarnessId"], r.outputs["Endpoint"] = made["arn"], made["harnessId"], endpoint
    end = clock.now() + running.MAKE_WAIT
    while True:
        got = c.control.get_harness(harnessId=r.outputs["HarnessId"])["harness"]
        if got["status"] == "READY":
            break
        if got["status"].endswith("FAILED") or clock.now() >= end:
            raise RuntimeError(f"the harness {n['harness']} is {got['status']}, not ready")
        clock.sleep(5.0)
    environment = (got.get("environment") or {}).get("agentCoreRuntimeEnvironment") or {}
    r.outputs["Runtime"], r.outputs["RuntimeId"] = environment.get("agentRuntimeArn", ""), environment.get(
        "agentRuntimeId", "")
    if r.outputs["RuntimeId"]:
        runtime = c.control.get_agent_runtime(agentRuntimeId=r.outputs["RuntimeId"])
        r.outputs["WorkloadIdentity"] = (runtime.get("workloadIdentityDetails") or {}).get("workloadIdentityArn", "")


def warm_up(c: Clients, r: HarnessRun, clock: Clock) -> None:
    """Commands before any stop, in one session: whether the harness answers, and how far apart the kit's clock and the
    microVM's are, from the quickest; then one turn, which must work. Where either does not, nothing is fired."""
    session, best, errors = _session(r, "clock"), None, {}
    for _ in range(WARM_UP):
        sent = clock.now()
        try:
            out, exit_code, error = command(c, r, session, probe_command("clock"), NOOP_TIMEOUT)
            if error or exit_code != 0:
                raise _Failed(error or f"Exit{exit_code}")
            at = float(json.loads(out.strip().splitlines()[-1])["at"])
        except Exception as e:  # noqa: BLE001 - each is said below, by its code
            if code(e) in KIT_CREDENTIALS:
                raise
            errors[code(e)] = errors.get(code(e), 0) + 1
            clock.sleep(1.0)
            continue
        received = clock.now()
        r.calls += 1
        if best is None or received - sent < best[0]:
            best = (received - sent, at - (sent + received) / 2)
        clock.sleep(1.0)
    if best is None:
        codes = ", ".join(f"{k} {v}" for k, v in sorted(errors.items()))
        # CUSTOMER TEXT: approved by the founder, 04:44 UTC on 28 October 2026 (D618), as the runtime's warm-up says it
        raise NotStarted(f"The test agent did not answer before the stop ({codes}), so nothing was timed.", r)
    r.offset = best[1]
    try:
        turn(c, r, _session(r, "model"))
        r.calls += 1
    except Exception as e:  # noqa: BLE001 - said, by its code
        if code(e) in KIT_CREDENTIALS:
            raise
        raise NotStarted(MODEL_DID_NOT_WORK.format(model=r.model, codes=code(e), region=r.region), r) from None


def _take(r: HarnessRun, rep: Repeat, events: list[dict]) -> None:
    for e in events:
        if "credentials_from" in e:
            r.credentials_from = {**(r.credentials_from or {}), rep.session: e.get("credentials_from")}
    running._take(r, rep, events)


def _working_before(rep: Repeat, p: str, found: list[tuple[float, Beat]]) -> None:
    """A path of calls is tried only where the last one sent before the stop worked; else its errors are each refusal
    of a call sent before the stop, the last's among them (as run.time_one has it for new calls)."""
    before = [b for sent, b in found if sent < rep.fired_before]
    if before and before[-1].ok:
        rep.working.add(p)
        return
    for b in before:
        if not b.ok:
            errors = rep.setup_errors.setdefault(p, {})
            errors[b.error or "unknown"] = errors.get(b.error or "unknown", 0) + 1


def time_one(c: Clients, r: HarnessRun, clock: Clock, say: Callable[[str], None] = lambda _: None) -> Repeat:
    """One repeat: the running session opened and working, its turns and new calls from LEAD seconds before the stop,
    the stop fired, then all three through the window and its hold."""
    rep = Repeat()
    seconds = READY_WAIT + LEAD + r.window + HOLD + SLACK
    stream = open_session(c, r, rep, clock, seconds)
    rep.beats[MODEL] = []
    for p in SESSION_PATHS:
        if p not in rep.working:
            # CUSTOMER TEXT: approved by the founder, 04:44 UTC on 28 October 2026 (D618), as the runtime says it
            say(f"Before the stop, {PATH_WORDS[p]} did not work ({running._codes(rep, p)}): it will be reported as "
                "not run.")
    new, turns = NewCommands(c, r, clock), Turns(c, r, clock, rep.session)
    try:
        lead_end = clock.now() + LEAD
        while clock.now() < lead_end:
            new.tick()
            turns.tick()
            _take(r, rep, stream.poll())
            clock.sleep(1.0)
        _take(r, rep, stream.poll())
        for p in SESSION_PATHS:
            if p in rep.working and not rep.beats[p][-1].ok:
                rep.working.discard(p)
                errors = rep.setup_errors.setdefault(p, {})
                errors[rep.beats[p][-1].error or "unknown"] = errors.get(rep.beats[p][-1].error or "unknown", 0) + 1
        if stream.ended is not None:
            for p in SESSION_PATHS:
                if p in rep.working:
                    rep.working.discard(p)
                    rep.setup_errors.setdefault(p, {})["SessionEndedBeforeTheStop"] = 1
        rep.fired_before, rep.fired_after = firing.fire(c.iam, c.control, r.run, r.stop_ref, "", now=clock.now)
        end = rep.fired_after + r.window + HOLD
        while clock.now() < end:
            new.tick()
            turns.tick()
            _take(r, rep, stream.poll())
            clock.sleep(1.0)
        found, turned = new.finish(), turns.finish(limit=TURN_TIMEOUT)
    finally:
        stream.close()
    _take(r, rep, stream.poll())
    rep.new_calls = len(found)
    r.calls += len(found) + len(turned)
    rep.beats[NEW_CALLS] = [b for _, b in found]
    rep.beats[MODEL] = [b for _, b in turned]
    _working_before(rep, NEW_CALLS, found)
    _working_before(rep, MODEL, turned)
    if stream.ended is not None:
        rep.stream_ended, rep.stream_ended_by = stream.ended
        if rep.stream_ended_by == "done":
            rep.stream_ended = None
        else:
            rep.writes_after_close = writes_after(c, r, rep)
            if not rep.writes_after_close:
                t = rep.stream_ended + r.offset
                while t <= end + r.offset:
                    for p in SESSION_PATHS:
                        rep.beats[p].append(Beat(t, False, SESSION_ENDED))
                    t += 1.0
    return rep


def recover(c: Clients, r: HarnessRun, clock: Clock) -> None:
    """Between repeats: remove the stop, then wait until its removal holds: every turn answered, from the first of them
    sent, for RECOVERED seconds, up to RECOVERY, as run.recover waits for new calls to the runtime."""
    firing.remove(c.iam, c.control, r.run, r.stop_ref, None)
    end, since, session = clock.now() + RECOVERY, None, _session(r, "recover")
    while clock.now() < end:
        sent = clock.now()
        try:
            turn(c, r, session)
            r.calls += 1
            since = sent if since is None else since
            if clock.now() - since >= RECOVERED:
                return
        except Exception as e:  # noqa: BLE001 - the stop may still be taking itself off
            if code(e) in KIT_CREDENTIALS:
                raise
            since = None
        clock.sleep(TURN_EVERY)


def harness_id(c: Clients, r: Run) -> str | None:
    """The run's harness, by what the run kept, or found by its name for an interrupted run."""
    if r.outputs.get("HarnessId"):
        return r.outputs["HarnessId"]
    token = None
    while True:
        page = c.control.list_harnesses(**({"nextToken": token} if token else {}))
        for found in page.get("harnesses", []):
            if found.get("harnessName") == harness_names(r.run)["harness"]:
                r.outputs["HarnessId"], r.outputs["Harness"] = found["harnessId"], found["arn"]
                return found["harnessId"]
        token = page.get("nextToken")
        if not token:
            return None


def tear_down(c: Clients, r: HarnessRun, clock: Clock, say: Callable[[str], None] = lambda _: None) -> None:
    """Remove the stop the kit fired and everything it made; name anything left (D532, K4). The harness goes first,
    with the runtime AgentCore made for it; the bucket is emptied once the session has stopped writing to it."""
    n = harness_names(r.run)
    try:
        firing.remove(c.iam, c.control, r.run, r.stop_ref, None)
    except Exception:  # noqa: BLE001 - a role already gone has no stop on it
        pass
    try:
        hid = harness_id(c, r)
        if hid:
            if not r.outputs.get("RuntimeId"):
                environment = (c.control.get_harness(harnessId=hid)["harness"].get("environment") or {}).get(
                    "agentCoreRuntimeEnvironment") or {}
                r.outputs["Runtime"] = environment.get("agentRuntimeArn", "")
                r.outputs["RuntimeId"] = environment.get("agentRuntimeId", "")
            c.control.delete_harness(harnessId=hid)
            end = clock.now() + running.MAKE_WAIT
            while _gone(lambda: c.control.get_harness(harnessId=hid)) is False and clock.now() < end:
                clock.sleep(5.0)
    except Exception:  # noqa: BLE001 - what could not be deleted is named below as left
        pass
    rid = r.outputs.get("RuntimeId")
    if rid and _gone(lambda: c.control.get_agent_runtime(agentRuntimeId=rid)) is False:
        try:        # AgentCore removes it with the harness; one still there is removed by its ID
            c.control.delete_agent_runtime(agentRuntimeId=rid)
        except Exception:  # noqa: BLE001 - named below as left
            pass
    identity = r.outputs.get("WorkloadIdentity", "").rpartition("/")[2]
    if identity and _gone(lambda: c.control.get_workload_identity(name=identity)) is False:
        try:
            c.control.delete_workload_identity(name=identity)
        except Exception:  # noqa: BLE001 - named below as left
            pass
    try:
        writes_stopped(c, r, clock)
        while True:
            listed = c.s3.list_objects_v2(Bucket=n["bucket"]).get("Contents", [])
            if not listed:
                break
            c.s3.delete_objects(Bucket=n["bucket"], Delete={"Objects": [{"Key": o["Key"]} for o in listed]})
        c.s3.delete_bucket(Bucket=n["bucket"])
    except Exception:  # noqa: BLE001 - named below as left
        pass
    for which in ("agent_role", "second_role"):
        role = n[which]
        try:
            for name in c.iam.list_role_policies(RoleName=role).get("PolicyNames", []):
                c.iam.delete_role_policy(RoleName=role, PolicyName=name)
            for attached in c.iam.list_attached_role_policies(RoleName=role).get("AttachedPolicies", []):
                c.iam.detach_role_policy(RoleName=role, PolicyArn=attached["PolicyArn"])
            c.iam.delete_role(RoleName=role)
        except Exception:  # noqa: BLE001 - named below as left
            pass
    if c.logs is not None and rid:
        try:
            for group in running._log_groups(c, r):
                c.logs.delete_log_group(logGroupName=group)
        except Exception:  # noqa: BLE001 - named below as left
            pass
    r.left_behind, r.checked_gone = check_gone(c, r)


def check_gone(c: Clients, r: HarnessRun) -> tuple[list[str], list[str]]:
    """Each thing the run made, checked gone by its own identifier; then the run's tag, for anything else."""
    n = harness_names(r.run)
    hid, rid = r.outputs.get("HarnessId"), r.outputs.get("RuntimeId")

    def there(found: list) -> None:
        if not found:
            raise _NotFound()

    things: list[tuple[str, Callable[[], Any]]] = []
    if hid:
        things.append((f"the harness {r.outputs.get('Harness') or hid}", lambda: c.control.get_harness(harnessId=hid)))
    else:
        things.append((f"the harness {n['harness']}", lambda: there([harness_id(c, r)] if harness_id(c, r) else [])))
    if rid:
        things.append((f"the harness's runtime {r.outputs.get('Runtime') or rid}",
                       lambda: c.control.get_agent_runtime(agentRuntimeId=rid)))
    identity = r.outputs.get("WorkloadIdentity", "")
    if identity:
        things.append((f"the workload identity {identity}",
                       lambda: c.control.get_workload_identity(name=identity.rpartition("/")[2])))
    things += [(f"the bucket {n['bucket']}", lambda: c.s3.head_bucket(Bucket=n["bucket"])),
               (f"the role {n['agent_role']}", lambda: c.iam.get_role(RoleName=n["agent_role"])),
               (f"the role {n['second_role']}", lambda: c.iam.get_role(RoleName=n["second_role"]))]
    if c.logs is not None and rid:
        things.append((f"the log groups /aws/bedrock-agentcore/runtimes/{rid}*",
                       lambda: there(running._log_groups(c, r))))
    left, gone = [], []
    for what, call in things:
        found = _gone(call)
        if found is True:
            gone.append(what)
        else:
            left.append(what if found is False else f"{what} (could not be checked: {found})")
    try:
        if any(x.startswith(f"the role {n['agent_role']}") for x in left):
            role = n["agent_role"]
            if r.stop_ref == firing.INLINE:
                if firing.INLINE in c.iam.list_role_policies(RoleName=role).get("PolicyNames", []):
                    left.append(f"the stop {firing.INLINE} on the role {role}")
            elif r.stop_ref in {a["PolicyArn"] for a in
                                c.iam.list_attached_role_policies(RoleName=role).get("AttachedPolicies", [])}:
                left.append(f"the stop {r.stop_ref} attached to the role {role}")
    except Exception as e:  # noqa: BLE001 - named, unchecked
        left.append(f"the stop {r.stop_ref} (could not be checked: {code(e)})")
    named = " ".join(left)
    tagged = c.tagging.get_resources(TagFilters=[{"Key": TAG, "Values": [r.run]}]).get("ResourceTagMappingList", [])
    left += sorted(m["ResourceARN"] for m in tagged if m["ResourceARN"].split(":")[-1].split("/")[-1] not in named
                   and m["ResourceARN"] not in named)
    return left, gone


def results(r: HarnessRun) -> list[tuple[float | None, dict]]:
    """Each repeat's paths, each judged from the stop's moment."""
    return [(rep.fired_at, {p: running._one(r, rep, p) for p in PATHS}) for rep in r.repeats]


def details(r: HarnessRun, doc: dict) -> dict:
    """What the page shows, as a file beside the result, with what is particular to a harness: its model, its session
    limits and the probe's code, and each repeat's running session."""
    iso = result.iso
    repeats = []
    for rep, (_, found) in zip(r.repeats, results(r)):
        repeats.append({p: {
            "outcome": f.outcome, "fired_at": iso(rep.fired_at), "fired_source": f.fired_source,
            "effect_between_seconds": list(f.effect_between) if f.effect_between else None,
            "successes_after_first_refusal": f.successes_after_first_refusal,
            "first_refused": iso(f.first_failure_after), "stopped_from": iso(f.stopped_at),
            "last_success": iso(f.last_success_after), "tries_after": f.tries_after, "failures_after": f.failures_after,
            "errors": f.errors, "reason": f.reason, "keeps_working_until": iso(f.keeps_working_until)}
            for p, f in found.items()})
    sessions = [{"session": rep.session, "opened": iso(rep.opened), "ready": iso(rep.ready),
                 "second_role_session_expires": iso(rep.session_expires),
                 "credentials_from": (r.credentials_from or {}).get(rep.session),
                 "stream_ended": iso(rep.stream_ended), "stream_ended_by": rep.stream_ended_by,
                 "writes_after_stream_ended": rep.writes_after_close, "new_calls": rep.new_calls,
                 "turns": len(rep.beats.get(MODEL, []))} for rep in r.repeats]
    return {"format": "stop-test-details/1", "run": r.run, "result_signature": doc["signature"],
            "stop_kind": r.stop_kind, "window_seconds": r.window, "left_behind": r.left_behind,
            "checked_gone": r.checked_gone, "repeats": repeats,
            "agent": {"kind": AGENT_KIND, "harness": r.outputs.get("Harness", ""),
                      "harness_runtime": r.outputs.get("Runtime", ""), "model": r.model,
                      "network_mode": NETWORK_MODE, "idle_runtime_session_timeout_seconds": IDLE,
                      "max_lifetime_seconds": MAX_LIFETIME, "probe_sha256": r.probe_sha256},
            "sessions": sessions}


def the_result(r: HarnessRun, key=None) -> dict:
    """The run's result, signed with a key made for it (result.py)."""
    doc = result.build(
        kit_version=__version__, cloud="aws", region=r.region,
        began_at=r.began_at, ended_at=r.ended_at, window=r.window, clock_gap_ms=int(round(abs(r.offset) * 1000)),
        calls=r.calls, left_behind=r.left_behind, stop_kind=r.stop_kind, fired_by=r.fired_by, stop_ref=r.stop_ref,
        agent={"kind": AGENT_KIND, "runtime": f"model {r.model}", "memory_mb": None, "private_network": False,
               "ref": r.outputs.get("Harness", ""), "role_ref": r.outputs.get("AgentRole", "")},
        repeats=results(r))
    return result.sign(doc, key or result.new_key())


def run(c: Clients, stop_ref: str, *, endpoint: str, model: str, window: float = WINDOWS["aws"], repeats: int = 1,
        clock: Clock | None = None, run_name: str | None = None,
        trail_wait: float = running.TRAIL_WAIT, say: Callable[[str], None] = lambda _: None) -> tuple[HarnessRun, dict]:
    """A whole run on a harness, torn down whatever happens. Returns the run's record and its signed result."""
    from arvaken_stop_test.aws.stack import new_run
    clock = clock or Clock()
    if not firing.on_the_role(stop_ref):
        raise firing.Refused(f"a harness takes a policy on its role alone, not {stop_ref}")
    reason = firing.why_not(stop_ref)
    if reason:
        raise firing.Refused(reason)                # before anything is made
    if not MODEL_ID.fullmatch(model or ""):
        raise firing.Refused(NOT_A_MODEL)            # before anything is made
    if not 1 <= repeats <= 5:
        raise ValueError("a run repeats one to five times")
    if READY_WAIT + LEAD + window + HOLD + SLACK > LONGEST:
        # CUSTOMER TEXT: for the founder's approval, word for word, with the harness module
        raise ValueError(f"a window on a harness is at most {int(LONGEST - READY_WAIT - LEAD - HOLD - SLACK)} "
                         "seconds: the running session's probe is one command, which AWS lets run up to an hour")
    the_name = run_name or new_run()
    if stop_ref != firing.INLINE and not firing.covers(c.iam, stop_ref, the_name):
        raise firing.Refused(aws_fire.NOT_COVERED)  # before anything is made
    reason = why_no_boundary(c.iam, c.sts)
    if reason:
        raise firing.Refused(reason)                # before anything is made
    caller = c.sts.get_caller_identity()
    r = HarnessRun(run=the_name, stop_ref=stop_ref, window=window, region=c.region, account=caller["Account"],
                   partition=caller["Arn"].split(":")[1], model=model)
    r.began_at = clock.now()
    c = replace(c, stream=c.stream or CommandStream)
    try:
        make(c, r, endpoint, clock)
        warm_up(c, r, clock)
        for i in range(repeats):
            if i:
                recover(c, r, clock)
            r.repeats.append(time_one(c, r, clock, say=say))
        running.firing_moments(c, r, clock, wait=trail_wait)
    finally:
        tear_down(c, r, clock, say=say)
        r.ended_at = clock.now()
    return r, the_result(r)
