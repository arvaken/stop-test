"""Your gateway's own refusal (the founder's ruling on a gateway's refusal, D655, 30 October 2026, and his answers of the
same day): what the agent reads of it, what counts, and a whole run through a gateway that refuses, against
test_aws_run.py's fake AWS.

The agent reads the gateway's status from botocore itself, through a local gateway that answers the CONNECT as tinyproxy
1.11.1 does (src/html-error.c: the status line, then "Server: tinyproxy/1.11.1"), for the Python, botocore and urllib3
these tests run on. Lambda's own python3.12 is another combination: refusals.TESTED names those the parse was tested on.
"""
from __future__ import annotations

import socket
import sys
import threading

import botocore
import botocore.config
import botocore.exceptions
import boto3
import pytest
import urllib3
from botocore import UNSIGNED

from arvaken_stop_test import refusals
from arvaken_stop_test.aws import agent
from arvaken_stop_test.aws import run as running
from arvaken_stop_test.timing import Beat
from test_aws_gateway import GATEWAY, through
from test_aws_run import Clock, FakeAWS

LAMBDA = ("3.12.15", "1.42.97", "2.8.0")      # Lambda python3.12's, read in install-test on 30 October 2026


def a_gateway(answer: bytes | None):
    """A local gateway answering every CONNECT with `answer`, as tinyproxy does, then closing; with None, a port
    nothing listens on. Returns its address and what it saw."""
    if answer is None:
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        return f"http://127.0.0.1:{port}", []
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(5)
    seen = []

    def serve():
        while True:
            try:
                conn, _ = server.accept()
            except OSError:
                return
            with conn:
                seen.append(conn.recv(4096).split(b"\r\n", 1)[0].decode())
                conn.sendall(answer)
    threading.Thread(target=serve, daemon=True).start()
    return f"http://127.0.0.1:{server.getsockname()[1]}", seen


def through_it(via: str) -> dict:
    """A model call through the gateway, as the agent makes it, unsigned, and the agent's record of its failure."""
    client = boto3.client("bedrock-runtime", region_name="eu-central-1", config=botocore.config.Config(
        signature_version=UNSIGNED, proxies={"https": via}, connect_timeout=2, read_timeout=2,
        retries={"max_attempts": 1}))
    with pytest.raises(Exception) as caught:
        client.converse(modelId="openai.gpt-oss-20b-1:0", messages=[{"role": "user", "content": [{"text": "1"}]}])
    return agent._record(caught.value)


def tinyproxy(status: str) -> bytes:
    return (f"HTTP/1.1 {status}\r\nServer: tinyproxy/1.11.1\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n"
            "<html><head><title>refused</title></head></html>").encode()


@pytest.mark.parametrize("status, read", [("403 Filtered", 403), ("403 Access violation", 403), ("403 ", 403),
                                          ("407 Proxy Authentication Required", 407), ("502 Bad Gateway", 502)])
def test_the_agent_reads_the_gateways_own_status_from_botocore_and_keeps_no_phrase(status, read):
    via, seen = a_gateway(tinyproxy(status))
    record = through_it(via)
    assert record == {"error": "ProxyConnectionError", "status": read, "reason": None}
    assert seen and set(seen) == {"CONNECT bedrock-runtime.eu-central-1.amazonaws.com:443 HTTP/1.1"}
    assert "Filtered" not in repr(record) and "violation" not in repr(record)


def test_a_gateway_that_is_not_there_or_answers_nonsense_gives_no_status():
    """Switched off, or not answering as HTTP: ProxyConnectionError all the same, and no status (D655, (b))."""
    nothing, _ = a_gateway(None)
    assert through_it(nothing) == {"error": "ProxyConnectionError", "status": None, "reason": None}
    nonsense, _ = a_gateway(b"HELLO\r\n\r\n")
    assert through_it(nonsense)["status"] is None


def test_the_status_is_read_from_the_whole_text_or_not_at_all():
    """D655, (a): "Read the status strictly from the chained error ... Text that doesn't match exactly is not counted.\""""
    def chained(text: str) -> botocore.exceptions.ProxyConnectionError:
        return botocore.exceptions.ProxyConnectionError(
            proxy_url="http://gw:8888", error=urllib3.exceptions.ProxyError("Unable to connect to proxy", OSError(text)))
    assert agent._tunnel(chained("Tunnel connection failed: 403 Filtered")) == 403
    assert agent._tunnel(chained("Tunnel connection failed: 403")) == 403
    for text in ("Tunnel connection failed: 4033 Filtered", "Tunnel connection failed: 40 3", "tunnel connection failed: "
                 "403", "Tunnel connection failed:403", "403 Filtered", "Tunnel connection failed: 403 Filtered\nmore",
                 "Tunnel connection failed: abc"):
        assert agent._tunnel(chained(text)) is None, text


def test_this_combination_is_the_one_these_tests_read_on():
    """What the parse above was tested on here, named for the record; Lambda's own is tested in Lambda."""
    here = (sys.version.split()[0], botocore.__version__, urllib3.__version__)
    assert all(isinstance(v, str) and v for v in here)
    assert agent.VERSIONS == list(here)


# -- what counts (refusals.gateway_counts) ------------------------------------------------------------------------------

def refused(status, versions=LAMBDA) -> Beat:
    return Beat(1000.0, False, "ProxyConnectionError", status=status, versions=versions)


def test_only_the_gateways_own_403_counts_or_its_407_where_its_address_signs_in(monkeypatch):
    monkeypatch.setattr(refusals, "TESTED", frozenset({LAMBDA}))
    assert refusals.gateway_counts(True, False, refused(403))
    assert not refusals.gateway_counts(True, False, refused(407))
    assert refusals.gateway_counts(True, True, refused(407))
    for status in (None, 401, 404, 429, 500, 502, 503, 504):
        assert not refusals.gateway_counts(True, True, refused(status)), status
    assert not refusals.gateway_counts(False, False, refused(403))          # a path that goes directly
    assert not refusals.gateway_counts(True, False, Beat(1000.0, False, "AccessDeniedException", status=403,
                                                         versions=LAMBDA))   # AWS's own refusal, inside the tunnel
    # "Count only tested versions": from a combination the parse was not tested on, nothing counts
    assert not refusals.gateway_counts(True, False, refused(403, ("3.12.16", "1.42.99", "2.8.0")))
    assert not refusals.gateway_counts(True, False, refused(403, None))


# -- a whole run through a gateway that refuses --------------------------------------------------------------------------

HTTP_VIA = "http://gw.example:8888"


def outcomes(doc) -> dict[str, str]:
    return {p: v["outcome"] for p, v in doc["repeats"][0].items()}


def test_a_gateway_rule_refusing_with_403_stops_each_path_through_it_from_its_first_refusal(monkeypatch):
    monkeypatch.setattr(refusals, "TESTED", frozenset({LAMBDA}))
    clock = Clock()
    aws = FakeAWS(clock, gw_status=403)
    r, doc, (( marked, _),) = through(aws, clock, via=HTTP_VIA, ca=None)
    assert outcomes(doc) == {p: "stopped" for p in running.AWS_PATHS}
    found = running.results(r)[0][1]["own_calls"]
    assert found.first_failure_after - found.fired_at >= 7.0 + 3.0          # the switch, then its 3 seconds
    record = running.details(r, doc)["repeats"][0]["own_calls"]
    assert record["failures"][0]["status"] == 403 and record["failures"][0]["versions"] == list(LAMBDA)
    assert record["client"]["mode"] == "kept from before the mark"
    assert record["client"]["new_connections_only"] == {"tries": 0, "failures": {}}


def test_the_same_refusal_from_libraries_never_tested_or_through_an_https_gateway_counts_nothing(monkeypatch):
    monkeypatch.setattr(refusals, "TESTED", frozenset({LAMBDA}))
    clock = Clock()
    r, doc, _ = through(FakeAWS(clock, gw_status=403, agent_versions=("3.12.16", "1.43.0", "2.8.1")), clock,
                        via=HTTP_VIA, ca=None)
    assert outcomes(doc) == {p: "not measured" for p in running.AWS_PATHS}
    clock = Clock()
    r, doc, _ = through(FakeAWS(clock, gw_status=403), clock, via="https://gw.example:8443", ca=None)
    assert r.counted_kind is None and outcomes(doc) == {p: "not measured" for p in running.AWS_PATHS}


def test_a_407_counts_only_where_the_gateways_address_signs_in(monkeypatch):
    monkeypatch.setattr(refusals, "TESTED", frozenset({LAMBDA}))
    clock = Clock()
    _, doc, _ = through(FakeAWS(clock, gw_status=407), clock, via=HTTP_VIA, ca=None)
    assert outcomes(doc) == {p: "not measured" for p in running.AWS_PATHS}
    clock = Clock()
    r, doc, _ = through(FakeAWS(clock, gw_status=407), clock, via="http://user:pass@gw.example:8888", ca=None)
    assert r.signed_in and outcomes(doc) == {p: "stopped" for p in running.AWS_PATHS}


def test_tries_with_a_client_made_after_the_mark_never_set_the_result(monkeypatch):
    """D655, open tunnels 2, and the founder's answer: a try whose client was made after the mark, as when Lambda gave
    the agent a new environment, is "new connections only", shown beside the result and never setting it."""
    monkeypatch.setattr(refusals, "TESTED", frozenset({LAMBDA}))
    clock = Clock()
    r, doc, _ = through(FakeAWS(clock, gw_status=403, new_environment_after=1.0), clock, via=HTTP_VIA, ca=None)
    assert outcomes(doc) == {p: "not measured" for p in running.AWS_PATHS}
    client = running.details(r, doc)["repeats"][0]["own_calls"]["client"]
    assert client["new_connections_only"]["tries"] > 0
    assert client["new_connections_only"]["failures"] == {"ProxyConnectionError": client["new_connections_only"]["tries"]
                                                          - sum(1 for b in running.new_connections_only(
                                                              r, r.repeats[0], "own_calls") if b.ok)}
    assert GATEWAY["attachment"] == "all its outbound traffic"
