"""The probe on Google Cloud (D575, Google Cloud after AWS; probe/src/arvaken_stop_test_probe/google.py).

Held here, as tests/test_probe.py holds them on AWS: that it makes the kit's own Google test agent's calls, call for
call (google/agent.py stays as it was measured); that it takes only settings named for the run; that the customer's own
clients, where passed, make every call and the reply says so (KC2); and that its reply holds times, outcomes and
failure records and never a message."""
from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from arvaken_stop_test.google import agent
from arvaken_stop_test.google import stack
from arvaken_stop_test_probe import core, google, heartbeat

RUN, PROJECT = "r0123abcd", "acme-sandbox-1"
N = stack.names(RUN, PROJECT)
KEY = "0123456789abcdef" * 2
SESSION = {"token": "second-token", "expires": "2026-11-03T21:00:00.123456789Z", "issued": 1_762_200_000.0}
METADATA = {"access_token": "own-token", "expires_in": 3599, "token_type": "Bearer"}
GENERATED = {"accessToken": "second-token", "expireTime": "2026-11-03T21:00:00Z"}


def marked(**kw):
    return {"arvaken_stop_test": {"run": RUN, "cloud": "google_cloud", "bucket": N["bucket"],
                                  "second_account": N["second_account"], "key": KEY, **kw}}


def without_agent(headers):
    return {k: v for k, v in headers.items() if k != "User-Agent"}


def answer(url: str) -> bytes:
    """What Google gives each call, as the fake has it: the metadata server's token, IAM Credentials' token, and nothing
    for a write or a read."""
    if url == google.METADATA:
        return json.dumps(METADATA).encode()
    if url.endswith(":generateAccessToken"):
        return json.dumps(GENERATED).encode()
    return b""


@pytest.fixture
def calls(monkeypatch):
    """The probe with the runtime's own clients faked: each request and GET, in order, without its user agent."""
    seen = []
    monkeypatch.setattr(google, "_OWN", {"token": None, "until": 0.0, "issued": 0.0})

    def request(method, url, headers, body, timeout):
        seen.append((method, url, without_agent(headers), body))
        return 200, answer(url)
    monkeypatch.setattr(google, "runtime_request", request)
    monkeypatch.setattr(core, "runtime_get",
                        lambda url, headers, timeout: seen.append(("GET", url, without_agent(headers), None)) or 200)
    return seen


def test_the_probe_makes_the_kits_own_google_agents_calls_call_for_call(calls, monkeypatch):
    agents = []
    monkeypatch.setattr(agent, "_own", {"token": None, "until": 0.0, "issued": 0.0})

    def call(url, headers=None, data=None, method="GET"):
        agents.append((method, url, dict(headers or {}), data))
        return answer(url)
    monkeypatch.setattr(agent, "_call", call)
    for k, v in {"BUCKET": N["bucket"], "ENDPOINT": core.ENDPOINT, "OUTSIDE_KEY": KEY,
                 "SECOND_ACCOUNT": N["second_account"]}.items():
        monkeypatch.setenv(k, v)

    taken = heartbeat.run(marked(action="assume"))["session"]
    kits = agent.take_second_identity()
    assert (taken["token"], taken["expires"]) == (kits["token"], kits["expires"])
    probe = heartbeat.run(marked(n=3, session=SESSION))
    beats = agent.beat({"n": 3, "session": SESSION})

    assert calls == agents and len(calls) == 7
    assert [c[:2] for c in calls] == [
        ("GET", google.METADATA),
        ("POST", f"{google.CREDENTIALS}{N['second_account']}:generateAccessToken"),
        ("POST", f"{google.STORAGE}/upload/storage/v1/b/{N['bucket']}/o?uploadType=media&name=own%2F3"),
        ("GET", f"{google.STORAGE}/storage/v1/b/{N['bucket']}/o/own%2F3?alt=media"),
        ("POST", f"{google.STORAGE}/upload/storage/v1/b/{N['bucket']}/o?uploadType=media&name=another%2F3"),
        ("GET", f"{core.ENDPOINT}/key"), ("GET", f"{core.ENDPOINT}/open")]
    assert probe["beats"].keys() == beats.keys() == {"own_calls", "another_identity", "outside_key", "open_internet"}
    assert all(b["ok"] for b in probe["beats"].values())
    # the token its own calls used and the second account's, by when each was issued and expires, as the agent's
    assert probe["beats"]["own_calls"]["token_expires"] - probe["beats"]["own_calls"]["token_issued"] == 3599
    expires = datetime(2026, 11, 3, 21, tzinfo=timezone.utc).timestamp() + 0.123456789
    assert probe["beats"]["another_identity"]["token_expires"] == pytest.approx(expires)


def test_what_it_takes_as_the_runs_is_named_as_the_kit_names_it():
    assert (google.PREFIX, google.CLOUD) == (stack.PREFIX, "google_cloud")
    assert N["bucket"] == f"{google.PREFIX}-{RUN}" == google.settings(marked()["arvaken_stop_test"])["bucket"]
    assert (google.METADATA, google.REFRESH) == (agent.METADATA, agent.REFRESH)


@pytest.mark.parametrize("field, value", [
    ("bucket", "arvaken-stop-test-r9999ffff"),                       # another run's
    ("bucket", "my-own-bucket"),
    ("bucket", f"arvaken-stop-test-{RUN}-bucket-abc"),               # the AWS stack's form, not Google's
    ("second_account", f"arvaken-st-r9999ffff-b@{PROJECT}.iam.gserviceaccount.com"),
    ("second_account", N["agent_account"]),                          # the run's own account, not its second
    ("second_account", f"arvaken-st-{RUN}-b@{PROJECT}.example.com"),
    ("second_account", f"arn:aws:iam::111122223333:role/arvaken-stop-test-{RUN}-second"),
    ("action", "watch"),
    ("cloud", "azure"),
    ("key", "not-a-key"),
])
def test_a_marked_call_naming_anything_not_the_runs_is_refused_before_any_call(calls, field, value):
    with pytest.raises(heartbeat.NotTheKits) as refused:
        heartbeat.run(marked(**{field: value}))
    assert refused.value.args == (field,) and calls == []


def test_the_customers_own_clients_make_every_call_and_the_reply_says_which_each_was(monkeypatch):
    def nowhere(*a, **kw):
        raise AssertionError("the runtime's own client was used")

    monkeypatch.setattr(google, "_OWN", {"token": None, "until": 0.0, "issued": 0.0})
    monkeypatch.setattr(google, "runtime_request", nowhere)
    monkeypatch.setattr(core, "runtime_get", nowhere)
    theirs = []

    def cloud(method, url, headers, body, timeout):
        theirs.append((method, url))
        return 200, answer(url)
    http = lambda url, headers, timeout: theirs.append(("GET", url)) or 200  # noqa: E731

    reply = heartbeat.run(marked(session=SESSION), http=http, cloud=cloud)
    assert all(b["ok"] for b in reply["beats"].values()) and reply["clients"] == {"cloud": "customer", "http": "customer"}
    assert ("GET", google.METADATA) in theirs and ("GET", f"{core.ENDPOINT}/key") in theirs

    monkeypatch.setattr(google, "runtime_request", cloud)
    assert heartbeat.run(marked(session=SESSION), http=http)["clients"] == {"cloud": "runtime", "http": "customer"}


def test_its_own_token_is_kept_until_shortly_before_it_expires_as_googles_client_keeps_one(calls, monkeypatch):
    clock = [1_762_200_000.0]
    monkeypatch.setattr(google.time, "time", lambda: clock[0])
    for n in range(5):
        heartbeat.run(marked(n=n, session=SESSION))
        clock[0] += 1000.0          # the fifth is within REFRESH of the token's expiry, so a new one is fetched
    assert [c[1] for c in calls].count(google.METADATA) == 2


def test_its_reply_holds_times_outcomes_and_failure_records_and_never_a_message(monkeypatch):
    secret = "arvaken-st-r0123abcd@acme-sandbox-1.iam.gserviceaccount.com does not have storage.objects.create access"
    storage = json.dumps({"error": {"code": 403, "message": secret,
                                    "errors": [{"message": secret, "domain": "global", "reason": "forbidden"}]}})
    api = json.dumps({"error": {"code": 403, "message": secret, "status": "PERMISSION_DENIED", "details": [
        {"@type": "type.googleapis.com/google.rpc.ErrorInfo", "reason": "IAM_PERMISSION_DENIED", "domain": "iam"}]}})
    monkeypatch.setattr(google, "_OWN", {"token": None, "until": 0.0, "issued": 0.0})

    def cloud(method, url, headers, body, timeout):
        if url == google.METADATA:
            return 200, json.dumps(METADATA).encode()
        return 403, (storage if "storage" in url else api).encode()

    reply = heartbeat.run(marked(session=SESSION), cloud=cloud, http=lambda url, headers, timeout: 401)
    assert reply.keys() == {"at", "beats", "v", "clients"}
    own, other, key = (reply["beats"][p] for p in ("own_calls", "another_identity", "outside_key"))
    assert (own["ok"], own["error"], own["status"], own["reason"], own["provider_status"], own["step"]) == (
        False, "HTTP403", 403, "forbidden", None, "write")
    assert (other["ok"], other["error"], other["reason"], other["step"]) == (False, "HTTP403", "forbidden", "write")
    assert (key["ok"], key["error"], key["status"]) == (False, "HTTP401", 401)
    assert "does not have" not in json.dumps(reply) and "iam.gserviceaccount" not in json.dumps(reply)
    assert google.record(google.Answered(403, api.encode()))["provider_status"] == "PERMISSION_DENIED"
    assert google.record(google.Answered(403, api.encode()))["reason"] == "IAM_PERMISSION_DENIED"
    assert google.record(google.Answered(502, b"<html>Bad gateway</html>")) == {
        "error": "HTTP502", "status": 502, "reason": None, "provider_status": None}


def test_a_session_with_no_token_is_no_session_and_the_own_calls_still_run(calls):
    reply = heartbeat.run(marked(n=1))
    assert reply["beats"]["own_calls"]["ok"] and not reply["beats"]["another_identity"]["ok"]
    assert reply["beats"]["another_identity"]["error"] == "RuntimeError"
