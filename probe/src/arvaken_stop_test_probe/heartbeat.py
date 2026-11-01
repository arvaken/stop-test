"""The kit's heartbeat, for a test copy of your own agent: the probe (D575; mark's
docs/platform/STOP-TEST-YOUR-OWN-AGENT-DESIGN.md, section 1).

You add it to a test copy of one of your agents, never the agent itself in production (the kit's terms, 2.1), and call
it when an invocation carries the kit's marker:

    from arvaken_stop_test_probe import heartbeat

    def handler(event, context):
        if heartbeat.is_mine(event):
            return heartbeat.run(event)   # the four paths, once
        ...                               # the agent's own work, untouched

On AgentCore, the same in your entrypoint: a watch's answer is an iterator of events, which AgentCore streams.

It makes the kit's own test agent's calls (the kit's aws/agent.py; the kit's design, section 4) from inside the copy's
own process, so an in-agent SDK that wraps the runtime's clients, or host software that sees the process's calls, sees
them as it sees the agent's. The paths and what each reports are the core's (core.py) and the cloud's (aws.py; AWS is
the first, D575's section 7).

**What it reports** is what the kit's test agent reports: for each path, when (by the copy's clock), whether it
succeeded, and if not its failure record, never a message. Beside them, the access key ID of the credentials the runtime
gave the copy, for the kit to find their times, as the kit's agent hands back its own; the versions it ran on; and which
clients it used. It reads nothing of the agent's work, its prompts, its tools' results or its model's output, and
writes no log.

**The run's settings come with each invocation.** The kit's own agent reads its bucket, second role and key from the
function's environment, which the kit sets when it deploys it. The kit never deploys or changes a copy of yours, so it
sends them in its marker instead, and the probe takes only what names the run. Arvaken's test endpoint is fixed
(core.ENDPOINT) and never taken from the invocation, so whoever can invoke the copy cannot point it anywhere else.

**Its clients (KC2).** Where an SDK wraps only its own clients, the probe's plain calls would go round it, so `run`
takes the clients to use: `cloud`, a function that makes a client as boto3.client does (`cloud("s3", config=...)`, and
for the second role's session its keys as boto3.client takes them), and `http`, a function that makes a GET request
and gives its HTTP status (`http(url, headers, timeout)`). Each one not passed is the runtime's own: boto3's clients
and the standard library's urllib. The reply says which each was (`clients`: "customer" or "runtime"), for the kit's
result. Pass the same function each time: a client is made once a path and kept, as a real agent's are (D655).

It uses only the standard library, and boto3 where it makes the runtime's own clients or reads a cloud error, so it
adds nothing to a copy that already has boto3, as Lambda's Python runtime does. Its code keeps to Python 3.9's grammar.
"""
from __future__ import annotations

import os
import time

from arvaken_stop_test_probe import aws, core
from arvaken_stop_test_probe.core import NotTheKits, is_mine

__all__ = ["NotTheKits", "is_mine", "run"]

EVERY = 1.0                 # seconds between a watch's tries, as the kit's AgentCore agent's
LONGEST = 3540.0            # the longest watch: AWS keeps a streaming response up to 60 minutes (the kit's agent.LONGEST)


def run(event, http=None, cloud=None):
    """The kit's heartbeat, for a marked invocation. `cloud` and `http` are your own clients, where you pass them.

    On Lambda: each path tried once; or, asked to "assume" before the stop, the second role's session for the kit to
    hand back. On AgentCore, as the kit's own AgentCore agent answers: "answer", the copy's clock at once and nothing
    else (a new call, which is timed by whether it reaches the copy at all); "watch", the running session, as an
    iterator of its events, which your entrypoint returns for AgentCore to stream: the second role's session taken once,
    then each path tried about once a second for as long as the kit asks, then "done"."""
    m = core.marker(event)
    s = aws.settings(m)
    make, get = cloud or aws.runtime_client, http or core.runtime_get
    clients = {"cloud": "customer" if cloud else "runtime", "http": "customer" if http else "runtime"}
    if s["action"] == "answer":
        return {"at": time.time(), "clients": clients}
    if s["action"] == "watch":
        return _watch(s, m, make, get, clients)
    if s["action"] == "assume":
        return {"at": time.time(), "session": aws.assume(s, make), "clients": clients}
    paths = [*aws.identity_paths(s, make), *core.endpoint_paths(m, get), *aws.model_paths(s, make)]
    return {"at": time.time(), "beats": core.beats(paths, aws.record), "key": os.environ.get("AWS_ACCESS_KEY_ID"),
            "v": core.versions(*aws.LIBRARIES), "clients": clients}


def _watch(s, m, make, get, clients):
    """The running session's events (the kit's AgentCore agent's watch): what its own calls and the second role's
    session found as it began, then one try of each path a second, each event by the copy's clock."""
    try:
        session = aws.assume(s, make)
    except Exception as e:  # noqa: BLE001 - the path then reads as not set up, by the error's code alone
        session = {"error": aws.record(e)["error"]}
    yield {"at": time.time(), "session_expires": session.get("expires"), "error": session.get("error"),
           "clients": clients}
    end, n, due = time.time() + min(float(s["seconds"]), LONGEST), 0, time.time()
    while time.time() < end:
        paths = [*aws.identity_paths(s, make, n=n, session=session), *core.endpoint_paths(m, get)]
        yield {"at": time.time(), "n": n, "beats": core.beats(paths, aws.record)}
        n, due = n + 1, due + EVERY
        time.sleep(max(0.0, due - time.time()))
    yield {"at": time.time(), "done": True}
