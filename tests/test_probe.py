"""The probe (D575; probe/ in this repository): the kit's heartbeat for a test copy of the customer's own agent.

Held here: that it makes the kit's own test agent's calls, call for call (agent.py stays as it was measured); that it
takes only settings named for the run, and Arvaken's endpoint never from the invocation; that the customer's own
clients, where passed, make every call and the reply says so (KC2); that its reply holds times, outcomes and failure
records and nothing more; and that it is its own package, under the kit's licence, needing nothing a copy lacks."""
from __future__ import annotations

import ast
import datetime
import io
import json
import os
import subprocess
import sys
import tomllib
from pathlib import Path

import botocore.exceptions
import pytest

from arvaken_stop_test.aws import agent
from arvaken_stop_test_probe import aws, core, heartbeat

ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "probe"
RUN = "r0123abcd"
BUCKET = f"arvaken-stop-test-{RUN}-bucket-abc"
SECOND = f"arn:aws:iam::111122223333:role/arvaken-stop-test-{RUN}-second"
KEY = "0123456789abcdef" * 2
MODEL = "eu.amazon.nova-micro-v1:0"
SESSION = {"key": "k", "secret": "s", "token": "t"}


def marked(**kw):
    return {"arvaken_stop_test": {"run": RUN, "bucket": BUCKET, "second_role": SECOND, "key": KEY, **kw}}


class Recorder:
    """A boto3 client that records each call it is given, by its service; made through `make`."""

    def __init__(self, calls, name, kw, refuse=None):
        self.calls, self.name, self.refuse = calls, name, refuse
        calls.append(("client", name, sorted(k for k in kw if k.startswith("aws_"))))

    def __getattr__(self, op):
        def call(**kw):
            self.calls.append((self.name, op, kw))
            if self.refuse:
                raise self.refuse
            if op == "get_object":
                return {"Body": io.BytesIO(b"x")}
            if op == "assume_role":
                return {"Credentials": {"AccessKeyId": "k", "SecretAccessKey": "s", "SessionToken": "t",
                                        "Expiration": datetime.datetime(2026, 11, 1, tzinfo=datetime.timezone.utc)}}
            return {}
        return call


def without_agent(headers):
    return {k: v for k, v in headers.items() if k != "User-Agent"}


@pytest.fixture
def calls(monkeypatch):
    """The probe with the runtime's own clients faked: every client made, call made and GET sent, in order."""
    seen = []
    monkeypatch.setattr(aws, "_MADE", {})
    monkeypatch.setattr(aws, "runtime_client", lambda name, **kw: Recorder(seen, name, kw))
    monkeypatch.setattr(core, "runtime_get",
                        lambda url, headers, timeout: seen.append(("GET", url, without_agent(headers))) or 200)
    return seen


def test_the_probe_makes_the_kits_own_test_agents_calls_call_for_call(calls, monkeypatch):
    agents = []
    monkeypatch.setattr(agent, "_MADE", {})
    monkeypatch.setattr(agent.boto3, "client", lambda name, **kw: Recorder(agents, name, kw))
    monkeypatch.setattr(agent, "_get", lambda url, headers, gw=({}, None), ctx=None: agents.append(("GET", url, headers)))
    for k, v in {"BUCKET": BUCKET, "ENDPOINT": core.ENDPOINT, "OUTSIDE_KEY": KEY, "SECOND_ROLE": SECOND,
                 "MODEL": MODEL}.items():
        monkeypatch.setenv(k, v)

    assert heartbeat.run(marked(action="assume"))["session"] == agent.handler({"action": "assume"}, None)["session"]
    probe = heartbeat.run(marked(n=3, session=SESSION, model=MODEL))
    kits = agent.handler({"n": 3, "session": SESSION}, None)

    assert calls == agents and len(calls) == 11
    assert {("s3", "put_object"), ("s3", "get_object"), ("sts", "assume_role"),
            ("bedrock-runtime", "converse")} <= {c[:2] for c in calls}
    assert probe["beats"].keys() == kits["beats"].keys() == {"own_calls", "another_identity", "outside_key",
                                                              "open_internet", "model"}
    assert all(b["ok"] for b in probe["beats"].values())


def test_it_names_itself_to_the_endpoint_as_the_probe_and_calls_only_arvakens(monkeypatch):
    sent = []
    monkeypatch.setattr(aws, "_MADE", {})
    monkeypatch.setattr(aws, "runtime_client", lambda name, **kw: Recorder([], name, kw))
    monkeypatch.setattr(core, "runtime_get", lambda url, headers, timeout: sent.append((url, headers)) or 200)
    heartbeat.run(marked(session=SESSION, endpoint="https://somewhere.example"))   # an endpoint is never taken
    assert [url for url, _ in sent] == ["https://stop-test.arvaken.com/key", "https://stop-test.arvaken.com/open"]
    assert all(h["User-Agent"].startswith("arvaken-stop-test-probe") for _, h in sent)
    assert sent[0][1]["Authorization"] == "Bearer " + KEY and "Authorization" not in sent[1][1]


def test_what_it_takes_as_the_runs_is_named_as_the_kit_names_it():
    from arvaken_stop_test import cli
    from arvaken_stop_test.aws import stack
    assert (core.ENDPOINT, aws.PREFIX, aws.MODEL_ID.pattern) == (cli.ENDPOINT, stack.PREFIX, stack.MODEL_ID.pattern)
    assert all(core.RUN.fullmatch(stack.new_run()) for _ in range(20))
    n = stack.names(RUN)
    assert SECOND.endswith(":role/" + n["second_role"]) and BUCKET.startswith(n["stack"] + "-")


def test_an_agentcore_runs_bucket_and_roles_are_taken_as_the_kits_agentcore_module_names_them(calls):
    from arvaken_stop_test.agentcore import stack as agentcore_stack
    n = agentcore_stack.names(RUN)
    reply = heartbeat.run(marked(bucket=n["bucket"], second_role=f"arn:aws:iam::111122223333:role/{n['second_role']}",
                                 session=SESSION))
    assert all(b["ok"] for b in reply["beats"].values())
    assert ("s3", "put_object", {"Bucket": "arvaken-stop-test-r0123abcd", "Key": "own/0", "Body": b"x"}) in calls


def test_only_the_kits_marker_naming_a_run_is_the_kits():
    assert heartbeat.is_mine(marked())
    for other in ({}, None, "r0123abcd", [], {"arvaken_stop_test": RUN}, {"arvaken_stop_test": {"run": "R0123ABCD"}},
                  {"arvaken_stop_test": {"run": "r0123abc"}}, {"arvaken_stop_test": {}}, {"run": RUN}):
        assert not heartbeat.is_mine(other)


@pytest.mark.parametrize("field, value", [
    ("bucket", "arvaken-stop-test-r9999ffff-bucket-abc"),            # another run's
    ("bucket", "my-own-bucket"),
    ("bucket", f"arvaken-stop-test-{RUN}-" + "a" * 60),              # longer than a bucket's name can be
    ("second_role", "arn:aws:iam::111122223333:role/arvaken-stop-test-r9999ffff-second"),
    ("second_role", f"arn:aws:iam::111122223333:role/arvaken-stop-test-{RUN}-agent"),
    ("second_role", "arn:aws:iam::111122223333:role/Admin"),
    ("key", "not-a-key"),
    ("model", "anything at all"),
    ("n", "3"),
    ("n", True),
    ("action", "delete"),
])
def test_a_marked_invocation_naming_anything_not_the_runs_is_refused_before_any_call(calls, field, value):
    with pytest.raises(heartbeat.NotTheKits) as refused:
        heartbeat.run(marked(**{field: value}))
    assert refused.value.args == (field,) and calls == []


def test_the_customers_own_clients_make_every_call_and_the_reply_says_which_each_was(monkeypatch):
    def nowhere(*a, **kw):
        raise AssertionError("the runtime's own client was used")

    monkeypatch.setattr(aws, "_MADE", {})
    monkeypatch.setattr(aws, "runtime_client", nowhere)
    monkeypatch.setattr(core, "runtime_get", nowhere)
    theirs = []
    cloud = lambda name, **kw: Recorder(theirs, name, kw)  # noqa: E731
    http = lambda url, headers, timeout: theirs.append(("GET", url)) or 200  # noqa: E731

    reply = heartbeat.run(marked(session=SESSION, model=MODEL), http=http, cloud=cloud)
    assert all(b["ok"] for b in reply["beats"].values()) and reply["clients"] == {"cloud": "customer", "http": "customer"}
    assert ("GET", "https://stop-test.arvaken.com/key") in theirs and ("s3", "put_object") in {c[:2] for c in theirs}

    monkeypatch.setattr(aws, "runtime_client", lambda name, **kw: Recorder([], name, kw))
    assert heartbeat.run(marked(session=SESSION), http=http)["clients"] == {"cloud": "runtime", "http": "customer"}


def test_a_client_is_made_once_a_path_and_kept_as_a_real_agents_are(calls):
    first = heartbeat.run(marked(n=1, session=SESSION))
    second = heartbeat.run(marked(n=2, session=SESSION))
    assert [c for c in calls if c[0] == "client"] == [("client", "s3", []), ("client", "s3", [
        "aws_access_key_id", "aws_secret_access_key", "aws_session_token"])]
    assert first["beats"]["own_calls"]["client_at"] == second["beats"]["own_calls"]["client_at"]


def test_its_reply_holds_times_outcomes_and_failure_records_and_never_a_message(monkeypatch):
    secret = "User arn:aws:sts::111122223333:assumed-role/x is not authorized"
    denied = botocore.exceptions.ClientError(
        {"Error": {"Code": "AccessDenied", "Message": secret}, "ResponseMetadata": {"HTTPStatusCode": 403}}, "PutObject")
    monkeypatch.setattr(aws, "_MADE", {})
    reply = heartbeat.run(marked(session=SESSION), cloud=lambda name, **kw: Recorder([], name, kw, refuse=denied),
                          http=lambda url, headers, timeout: 401)

    assert reply.keys() == {"at", "beats", "key", "v", "clients"}
    own, key = reply["beats"]["own_calls"], reply["beats"]["outside_key"]
    assert (own["ok"], own["error"], own["status"], own["reason"]) == (False, "AccessDenied", 403, None)
    assert (key["ok"], key["error"], key["status"]) == (False, "HTTP401", 401)
    assert all(b.keys() <= {"at", "ok", "error", "status", "reason", "client_at"} for b in reply["beats"].values())
    assert "authorized" not in json.dumps(reply) and "111122223333" not in json.dumps(reply)


def test_it_is_its_own_package_under_the_kits_licence():
    kit, probe = (tomllib.loads((p / "pyproject.toml").read_text(encoding="utf-8"))["project"] for p in (ROOT, PROBE))
    assert probe["name"] == "arvaken-stop-test-probe" and probe["license"] == kit["license"]
    assert (PROBE / "LICENSE").read_bytes() == (ROOT / "LICENSE").read_bytes()
    assert probe["dependencies"] == []


def test_its_core_knows_no_cloud_so_a_host_the_kit_does_not_deploy_to_can_bring_its_own_paths():
    imported = set()
    for node in ast.walk(ast.parse((PROBE / "src" / "arvaken_stop_test_probe" / "core.py").read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            imported |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            imported.add((node.module or "").split(".")[0])
    assert imported == {"__future__", "re", "sys", "time", "urllib"}
    assert [name for name, _ in core.endpoint_paths({"key": KEY}, lambda *a: 200)] == ["outside_key", "open_internet"]


def test_its_code_keeps_to_python_3_9s_grammar():
    for f in (PROBE / "src").rglob("*.py"):
        ast.parse(f.read_text(encoding="utf-8"), filename=str(f), feature_version=(3, 9))


def test_without_boto3_it_still_runs_and_names_what_it_could_not_make(tmp_path):
    code = ("import sys, json; sys.modules['boto3'] = sys.modules['botocore'] = None\n"
            "from arvaken_stop_test_probe import heartbeat\n"
            f"e = {{'arvaken_stop_test': {{'run': '{RUN}', 'bucket': '{BUCKET}', 'second_role': '{SECOND}', "
            f"'key': '{KEY}'}}}}\n"
            "r = heartbeat.run(e, http=lambda url, headers, timeout: 200)\n"
            "print(json.dumps({p: [b['ok'], b.get('error')] for p, b in r['beats'].items()}))")
    out = subprocess.run([sys.executable, "-I", "-c", f"import sys; sys.path.insert(0, {str(PROBE / 'src')!r})\n" + code],
                         capture_output=True, text=True, cwd=tmp_path, check=True, env={**os.environ})
    assert json.loads(out.stdout) == {"own_calls": [False, "ModuleNotFoundError"],
                                      "another_identity": [False, "RuntimeError"],
                                      "outside_key": [True, None], "open_internet": [True, None]}



def test_the_calls_to_arvakens_test_address_carry_only_the_kits_name_and_on_the_keyed_call_the_runs_test_key():
    """The founder's "Wrote" sentence (2 November 2026): Arvaken's test address receives only the test calls, carrying
    only the kit's name as their user agent and, on the call with a key, the run's test key; the witness's the same,
    with no key. Beside the headers set here, a call carries only those every HTTP call has (Host among them)."""
    from arvaken_stop_test import __version__
    from arvaken_stop_test.aws import your_copy
    sent = []
    for name, fn in core.endpoint_paths({"key": KEY}, lambda url, headers, timeout: sent.append((url, headers)) or 200):
        fn({})
    assert sent == [("https://stop-test.arvaken.com/key", {"User-Agent": core.AGENT, "Authorization": "Bearer " + KEY}),
                    ("https://stop-test.arvaken.com/open", {"User-Agent": core.AGENT})]
    witnessed = []

    class C:
        s3 = type("S3", (), {"head_bucket": lambda self, Bucket: None})()

    r = type("R", (), {"offset": 0.0, "outputs": {"Bucket": "b"}, "witness": []})()
    your_copy.Witness(C(), r, type("K", (), {"now": lambda self: 0.0})(),
                      lambda url, headers: witnessed.append((url, headers)) or 200)()
    assert witnessed == [("https://stop-test.arvaken.com/open", {"User-Agent": your_copy.WITNESS_AGENT})]
    # the kit's name, never its version
    assert __version__ not in core.AGENT and __version__ not in your_copy.WITNESS_AGENT
