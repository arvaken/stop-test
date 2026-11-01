"""The kit's heartbeat, for a test copy of your own agent: the probe (D575; mark's
docs/platform/STOP-TEST-YOUR-OWN-AGENT-DESIGN.md, section 1).

You add it to a test copy of one of your agents, never the agent itself in production (the kit's terms, 2.1), and call
it when an invocation carries the kit's marker:

    from arvaken_stop_test_probe import heartbeat

    def handler(event, context):
        if heartbeat.is_mine(event):
            return heartbeat.run(event)   # the four paths, once
        ...                               # the agent's own work, untouched

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


def run(event, http=None, cloud=None) -> dict:
    """The kit's heartbeat, once, for a marked invocation: each path tried once, or, asked to "assume" before the stop,
    the second role's session for the kit to hand back. `cloud` and `http` are your own clients, where you pass them."""
    m = core.marker(event)
    s = aws.settings(m)
    make, get = cloud or aws.runtime_client, http or core.runtime_get
    clients = {"cloud": "customer" if cloud else "runtime", "http": "customer" if http else "runtime"}
    if s["action"] == "assume":
        return {"at": time.time(), "session": aws.assume(s, make), "clients": clients}
    paths = [*aws.identity_paths(s, make), *core.endpoint_paths(m, get), *aws.model_paths(s, make)]
    return {"at": time.time(), "beats": core.beats(paths, aws.record), "key": os.environ.get("AWS_ACCESS_KEY_ID"),
            "v": core.versions(*aws.LIBRARIES), "clients": clients}
