"""`stop-test gate`: before your pipeline puts an agent live, ask Arvaken whether it can be stopped (the plan, wave 2,
D; Arvaken's 0212). Run it in your release pipeline, after the agent is deployed and before it takes real work:

    stop-test gate --key <your runner's KMS key ARN> --engagement <id> --agent <the agent's ARN> --on-no block

It asks one question, signed in your account with your runner's KMS key (kms:Sign, ECDSA_SHA_256), the same key your
scheduled repeat signs with. Nothing else of your account is read, and nothing is sent but the question. Arvaken
records the question and hands back a one-use token; the gate reads its answer from your Arvaken app with that token.
The answer is the agent's own card on your stop map: yes where it reads Stoppable, no where it reads Not stoppable or No
stop declared, not determined where it reads Not determined. While the agent is not on your stop map yet, the gate
waits for your runner to read it, up to --wait seconds, and then answers not determined.

With --on-no block, anything but yes fails the step (exit 1). With --on-no warn, the gate prints the answer and lets the
step pass (exit 0). If Arvaken does not answer at all, that is not determined too. Each gate is kept in your audit trail.
"""
from __future__ import annotations

import base64
import json
import re
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from typing import Callable

from arvaken_stop_test.due import DUE_ENDPOINT, KEY_ARN, kms_signer, _post

GATE_PATH = "/v1/gate"
APP = "https://app.arvaken.com"
PASSED, BLOCKED = 0, 1
AGENT = re.compile(r"[^\s\x00-\x1f\x7f]{1,2048}")
RUN_REF = re.compile(r"[^\x00-\x1f\x7f]{1,200}")

# CUSTOMER TEXT, approved as written by the founder's click at 18:24:52 UTC on 25 November 2026
# (the plan, wave 2, D; D-GATE-WORDING.md): what `stop-test gate` prints,
# and its help.
GATE_HELP = "before an agent goes live: ask Arvaken whether it can be stopped (exit 1 to block it, with --on-no block)"
SAID_YES = "Yes: this agent can be stopped. {reason}"
SAID_NO = "No: this agent can't be stopped right now. {reason}"
SAID_NOT_DETERMINED = "Not determined: {reason}"
SAID_NO_ANSWER = "Arvaken did not answer ({why})."
SAID_BLOCKED = "The gate blocks this step (--on-no block). See the agent's card in your Arvaken app."
SAID_WARNED = "The gate lets this step pass (--on-no warn). See the agent's card in your Arvaken app."
SAID_WAITING = "This agent is not on your stop map yet. Waiting for your runner to read it..."


def question(*, key_arn: str, engagement: str, agent: str, on_no: str, run_ref: str | None, at: datetime) -> bytes:
    """The bytes signed: version 1's question, asking "gate" (Arvaken's envelope.make_gate_question)."""
    body = {"v": 1, "ask": "gate", "key": key_arn, "engagement": str(uuid.UUID(engagement)),
            "at": at.astimezone(timezone.utc).isoformat(), "agent": agent, "on_no": on_no, "run_ref": run_ref}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def _get(url: str) -> tuple[int, bytes]:
    try:
        with urllib.request.urlopen(urllib.request.Request(url, method="GET"), timeout=30) as r:  # noqa: S310
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def _json(raw: bytes) -> dict:
    try:
        said = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {}
    return said if isinstance(said, dict) else {}


def ask(*, key_arn: str, engagement: str, agent: str, on_no: str, run_ref: str | None, endpoint: str = DUE_ENDPOINT,
        sign: Callable[[bytes], bytes] | None = None, post: Callable[[str, dict, bytes], tuple[int, bytes]] | None = None,
        now: datetime | None = None) -> str:
    """The gate's one-use token. Raises RuntimeError with the reason when Arvaken gives none."""
    if not KEY_ARN.fullmatch(key_arn):
        raise ValueError("--key is your runner's KMS key ARN: arn:aws:kms:<region>:<account>:key/<id>")
    if not AGENT.fullmatch(agent):
        raise ValueError("--agent is the agent's identifier as its cloud gives it, such as its ARN")
    if run_ref is not None and not RUN_REF.fullmatch(run_ref):
        raise ValueError("--run-ref is one line of at most 200 characters")
    body = question(key_arn=key_arn, engagement=engagement, agent=agent, on_no=on_no, run_ref=run_ref,
                    at=now or datetime.now(timezone.utc))
    signature = (sign or kms_signer(key_arn))(body)
    headers = {"X-Arvaken-Key": key_arn, "X-Arvaken-Signature": base64.b64encode(signature).decode(),
               "Content-Type": "application/json", "Content-Length": str(len(body))}
    status, raw = (post or _post)(endpoint.rstrip("/") + GATE_PATH, headers, body)
    said = _json(raw)
    if status != 200 or said.get("asked") is not True or not isinstance(said.get("token"), str):
        reason = said.get("reason")
        raise RuntimeError(reason if isinstance(reason, str) else f"HTTP {status}")
    return said["token"]


def answer(token: str, *, app: str = APP, wait: float = 600, every: float = 15,
           get: Callable[[str], tuple[int, bytes]] | None = None, sleep: Callable[[float], None] = time.sleep,
           clock: Callable[[], float] = time.monotonic, say: Callable[[str], None] = print) -> dict:
    """The gate's answer from the app: asked again while the agent is not on the map, up to `wait` seconds, and then
    once more with final=1, which records not determined. Raises RuntimeError when the app gives none."""
    get = get or _get
    url = f"{app.rstrip('/')}/gate/{token}"
    until, told = clock() + wait, False
    while True:
        last = clock() >= until
        status, raw = get(url + ("?final=1" if last else ""))
        said = _json(raw)
        if status == 200 and said.get("answered") is True:
            return said
        if status != 202 or last:
            reason = said.get("reason")
            raise RuntimeError(reason if isinstance(reason, str) else f"HTTP {status}")
        if not told:
            say(SAID_WAITING)
            told = True
        sleep(min(every, max(0.0, until - clock())))


def run(args, **over) -> int:
    on_no = args.on_no
    try:
        token = ask(key_arn=args.key, engagement=args.engagement, agent=args.agent, on_no=on_no, run_ref=args.run_ref,
                    endpoint=args.endpoint, **{k: v for k, v in over.items() if k in ("sign", "post", "now")})
        said = answer(token, app=args.app, wait=args.wait,
                      **{k: v for k, v in over.items() if k in ("get", "sleep", "clock", "say")})
    except (RuntimeError, OSError) as e:
        print(SAID_NO_ANSWER.format(why=str(e) or type(e).__name__))
        said = None
    reason = str(said.get("reason") or "") if said else ""
    if said and said.get("answer") == "yes":
        print(SAID_YES.format(reason=reason).strip())
        return PASSED
    if said and said.get("answer") == "no":
        print(SAID_NO.format(reason=reason).strip())
    elif said:
        print(SAID_NOT_DETERMINED.format(reason=reason).strip())
    print(SAID_BLOCKED if on_no == "block" else SAID_WARNED)
    return BLOCKED if on_no == "block" else PASSED
