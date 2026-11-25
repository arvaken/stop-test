"""`stop-test due`: whether Arvaken says a run is due for one of your agents (the plan, wave 2, A, part 2; Arvaken's
0211). A scheduled task in your own account runs it before `stop-test aws run`, and runs the test only when it says a
run is due:

    stop-test due --key <your runner's KMS key ARN> --engagement <id> --agent <id> && stop-test aws run ...

It asks one question, signed in your account with your runner's KMS key (kms:Sign, ECDSA_SHA_256), the same question in
the same shape your runner asks before each of its passes: nothing else of your account is read, and nothing is sent
but the question. Arvaken answers about the engagement that key belongs to, and nothing else. Exit 0: a run is due;
3: no run is due; 1: no answer (the task runs nothing, and asks again at its next time).
"""
from __future__ import annotations

import base64
import json
import re
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from typing import Callable

DUE_ENDPOINT = "https://ingest.arvaken.com"           # where your runner asks too (Arvaken's endpoint, its /v1/due)
DUE_PATH = "/v1/due"
KEY_ARN = re.compile(r"arn:aws:kms:[a-z0-9-]{1,30}:[0-9]{12}:key/[0-9a-f-]{36}")
DUE, NOT_DUE, NO_ANSWER = 0, 3, 1

# CUSTOMER TEXT, awaiting the founder's approval (the plan, wave 2, A; A-DUE-WORDING.md): what `stop-test due` prints.
DUE_HELP = "whether Arvaken says a scheduled run is due for one of your agents (exit 0 if due, 3 if not)"
WHY = {"never run": "no stop test has run for it yet",
       "schedule": "its newest stop test is older than your schedule",
       "change": "something changed since its newest stop test, so that result may no longer hold"}
SAID_DUE = "A run is due for this agent: {why}."
SAID_NOT_DUE = "No run is due for this agent."
SAID_NO_SCHEDULE = "This agent has no repeat schedule. Set one on its page in the Arvaken app."
SAID_NO_ANSWER = "Arvaken did not answer ({why}). Nothing was run; your schedule asks again next time."


def question(*, key_arn: str, engagement: str, at: datetime) -> bytes:
    """The bytes signed: version 1's question in its shape, asking "due" (Arvaken's envelope.make_due_question)."""
    body = {"v": 1, "ask": "due", "key": key_arn, "engagement": str(uuid.UUID(engagement)),
            "at": at.astimezone(timezone.utc).isoformat()}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def kms_signer(key_arn: str) -> Callable[[bytes], bytes]:
    import boto3  # noqa: PLC0415 - the AWS extra
    region = key_arn.split(":")[3]
    kms = boto3.client("kms", region_name=region)
    return lambda message: kms.sign(KeyId=key_arn, Message=message, MessageType="RAW",
                                    SigningAlgorithm="ECDSA_SHA_256")["Signature"]


def ask(*, key_arn: str, engagement: str, endpoint: str = DUE_ENDPOINT, sign: Callable[[bytes], bytes] | None = None,
        post: Callable[[str, dict, bytes], tuple[int, bytes]] | None = None, now: datetime | None = None) -> dict:
    """Arvaken's answer: {"agents": [...]}. Raises RuntimeError with the reason when there is none."""
    if not KEY_ARN.fullmatch(key_arn):
        raise ValueError("--key is your runner's KMS key ARN: arn:aws:kms:<region>:<account>:key/<id>")
    body = question(key_arn=key_arn, engagement=engagement, at=now or datetime.now(timezone.utc))
    signature = (sign or kms_signer(key_arn))(body)
    headers = {"X-Arvaken-Key": key_arn, "X-Arvaken-Signature": base64.b64encode(signature).decode(),
               "Content-Type": "application/json", "Content-Length": str(len(body))}
    status, raw = (post or _post)(endpoint.rstrip("/") + DUE_PATH, headers, body)
    try:
        said = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise RuntimeError(f"HTTP {status}") from None
    if status != 200 or not isinstance(said, dict) or not isinstance(said.get("agents"), list):
        reason = said.get("reason") if isinstance(said, dict) else None
        raise RuntimeError(reason if isinstance(reason, str) else f"HTTP {status}")
    return said


def _post(url: str, headers: dict, body: bytes) -> tuple[int, bytes]:
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=30) as r:   # noqa: S310 - Arvaken's https endpoint
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def decide(said: dict, agent: str) -> tuple[int, str]:
    """The exit code and the line, for one agent of the answer."""
    agent = str(uuid.UUID(agent))
    mine = [a for a in said["agents"] if isinstance(a, dict) and a.get("agent") == agent]
    if not mine:
        return NOT_DUE, SAID_NO_SCHEDULE
    why = mine[0].get("due")
    if why in WHY:
        return DUE, SAID_DUE.format(why=WHY[why])
    return NOT_DUE, SAID_NOT_DUE


def run(args, **over) -> int:
    try:
        said = ask(key_arn=args.key, engagement=args.engagement, endpoint=args.endpoint, **over)
    except (RuntimeError, OSError) as e:
        print(SAID_NO_ANSWER.format(why=str(e) or type(e).__name__))
        return NO_ANSWER
    code, line = decide(said, args.agent)
    print(line)
    return code
