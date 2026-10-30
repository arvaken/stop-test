"""A whole run on Google Cloud, against a fake Google on a virtual clock (the design's sections 3 to 8; D532, K3, K4,
K8; D518, G2).

The fake holds what the kit's run depends on, as this file's reading of Google's documented behaviour, not Google's
own answer: a deny policy naming the agent's account, or the account disabled, stops the agent's own calls after a
propagation delay (8 seconds here); a token the agent took for the second account before the stop keeps working, as
neither stop names that account; Cloud Audit Logs record the firing call some time later (two minutes here), to the
microsecond; a thing deleted answers 404. Each case's expectations are worked out by hand from those rules.

A heartbeat whose call got no answer: `lose` names each by its number (n) and the error urllib, http.client or the
socket raised for it.
"""
from __future__ import annotations

import ast
import http.client
import json
import re
import urllib.error
import urllib.parse
from datetime import datetime, timezone

import pytest

from arvaken_stop_test import result
from arvaken_stop_test.google import fire as firing
from arvaken_stop_test.google import run as running
from arvaken_stop_test.google.api import GoogleError
from arvaken_stop_test.google.stack import CODE_LIMIT, IMAGE, LABEL, agent_code, names

T0 = 1_761_340_000.0
PROJECT, REGION, RUN_NAME = "acme-sandbox-1", "europe-west3", "r0123abcd"
ENDPOINT = "https://stop-test.example"
DECLARED = ("policies/cloudresourcemanager.googleapis.com%2Fprojects%2Facme-sandbox-1/denypolicies/agent-stop")
N = names(RUN_NAME, PROJECT)


class Clock:
    def __init__(self):
        self.t = T0

    def now(self) -> float:
        return self.t

    def sleep(self, d: float) -> None:
        self.t += d


def iso(t: float) -> str:
    return datetime.fromtimestamp(t, tz=timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


class FakeGoogle:
    """One project, as the kit's run sees it through `Google.call`."""

    def __init__(self, clock: Clock, *, delay=8.0, log_delay=120.0, skew=0.05, declared_rules=None, bucket_stays=False,
                 described=True, lose=None):
        self.project, self.region = PROJECT, REGION
        self.clock, self.delay, self.log_delay, self.skew = clock, delay, log_delay, skew
        self.accounts: dict[str, dict] = {}
        self.disabled: dict[str, float] = {}          # account -> when disabled
        self.deny: dict[str, dict] = {}               # policy id -> {"at": made, "body": its body}
        self.calls: list[tuple[str, str]] = []
        self.bucket = None
        self.bucket_stays, self.described = bucket_stays, described
        self.service = None
        self.objects: set[str] = set()
        self.objects_stay = False                      # every object's deletion refused
        self.unavailable: dict[str, int] = {}          # a path's part, and how many more GETs of it Google answers 503
        self.audit: list[tuple[str, str, float]] = []  # (method, resource, when)
        self.declared_rules = declared_rules or [{"denyRule": {
            "deniedPrincipals": ["principal://goog/subject/someone@acme.test"],
            "deniedPermissions": ["storage.googleapis.com/objects.create", "storage.googleapis.com/objects.get"]}}]
        self.bodies: list[dict] = []
        self.customer = None                           # the customer's own trigger, pulled at any call once set
        self.agent_calls, self.pulling = 0, False
        self.lose = dict(lose or {})

    # what stops the agent's own calls, and since when
    def stopped_since(self) -> float | None:
        agent = N["agent_account"]
        moments = [self.disabled[agent]] if agent in self.disabled else []
        principal = f"principal://iam.googleapis.com/projects/-/serviceAccounts/{agent}"
        moments += [p["at"] for p in self.deny.values()
                    if any(principal in r["denyRule"]["deniedPrincipals"] for r in p["body"]["rules"])]
        return min(moments) + self.delay if moments else None

    def agent(self, payload: dict) -> dict:
        self.agent_calls += 1
        at = self.clock.now() + self.skew
        if payload.get("action") == "assume":
            return {"at": at, "session": {"token": "second-token", "expires": iso(self.clock.now() + 3600)}}
        since = self.stopped_since()
        own_ok = since is None or self.clock.now() < since
        another_ok = bool((payload.get("session") or {}).get("token"))
        return {"at": at, "beats": {
            # Storage's refusal on the write, with its reason, as the agent records it, and the token it used
            "own_calls": {"at": at, "ok": own_ok, **({} if own_ok else {
                "error": "HTTP403", "status": 403, "reason": "forbidden", "provider_status": None, "step": "write",
                "token_issued": T0, "token_expires": T0 + 3600})},
            "another_identity": {"at": at, "ok": another_ok, **({} if another_ok else {"error": "NoSession"})},
            "outside_key": {"at": at, "ok": True}, "open_internet": {"at": at, "ok": True}}}

    def call(self, method: str, url: str, body=None, *, identity: bool = False, raw=None):
        if self.customer and not self.pulling:
            self.pulling = True
            try:
                self.customer(self)
            finally:
                self.pulling = False
        self.calls.append((method, url))
        if body is not None:
            self.bodies.append({"method": method, "url": url, "body": body})
        u = urllib.parse.urlsplit(url)
        path = urllib.parse.unquote(u.path)
        for part, more in self.unavailable.items():
            if method == "GET" and part in path and more > 0:
                self.unavailable[part] = more - 1
                raise GoogleError(503, "UNAVAILABLE")
        if identity:
            assert url == "https://agent.example/", url
            if (lost := self.lose.get(body.get("n"))) is not None:
                raise lost
            return self.agent(body)
        if path.endswith("/serviceAccounts") and method == "POST":
            email = f"{body['accountId']}@{PROJECT}.iam.gserviceaccount.com"
            self.accounts[email] = {"email": email, "uniqueId": str(100000000000000000000 + len(self.accounts)),
                                    "description": body["serviceAccount"]["description"]
                                    if self.described else "someone else's"}
            return self.accounts[email]
        if path.endswith("/serviceAccounts") and method == "GET":
            return {"accounts": [{"email": e} for e in self.accounts]}
        if "/serviceAccounts/" in path:
            email = path.split("/serviceAccounts/")[1].split(":")[0]
            if email not in self.accounts:
                raise GoogleError(403, "PERMISSION_DENIED")      # Google's answer for an account that is gone
            if path.endswith(":disable"):
                self.disabled[email] = self.clock.now()
                unique = self.accounts[email]["uniqueId"]       # Cloud Audit Logs name it so, never by its email
                self.audit.append((firing.METHODS[firing.DISABLE_KIND], f'protoPayload.resourceName="projects/-/serviceAccounts/{unique}"',
                                   self.clock.now()))
                return {}
            if path.endswith(":enable"):
                self.disabled.pop(email, None)
                return {}
            if path.endswith(":getIamPolicy") or path.endswith(":setIamPolicy"):
                return {"bindings": []}
            if method == "DELETE":
                del self.accounts[email]
                return {}
            return {**self.accounts[email], "disabled": email in self.disabled}
        if u.netloc == "storage.googleapis.com":
            if path == "/storage/v1/b" and method == "POST":
                self.bucket = body["name"]
                return {"name": self.bucket}
            if self.bucket is None:
                raise GoogleError(404, "notFound")
            if path.endswith("/iam"):
                return {"bindings": []}
            if path.endswith("/o"):
                return {"items": [{"name": o} for o in sorted(self.objects)[:1000]]}      # Google's page: 1000 at most
            if method == "DELETE" and "/o/" in path:
                if self.objects_stay:
                    raise GoogleError(403, "forbidden")
                self.objects.discard(path.split("/o/", 1)[1])
                return {}
            if method == "DELETE" and path == f"/storage/v1/b/{self.bucket}":
                if self.objects:
                    raise GoogleError(409, "conflict")                                 # a bucket with objects stays
                if not self.bucket_stays:
                    self.bucket = None
                return {}
            return {"name": self.bucket}
        if u.netloc == "run.googleapis.com":
            if method == "POST":
                self.service = {"uri": "https://agent.example", "terminalCondition": {"state": "CONDITION_SUCCEEDED"},
                                "body": body}
                return {"name": "operations/1"}
            if self.service is None:
                raise GoogleError(404, "NOT_FOUND")
            if method == "DELETE":
                self.service = None
                return {}
            return self.service
        if u.netloc == "iam.googleapis.com" and "/denypolicies" in path:
            if path.endswith("/agent-stop"):
                return {"name": DECLARED, "rules": self.declared_rules}
            if method == "POST":
                pid = urllib.parse.parse_qs(u.query)["policyId"][0]
                self.deny[pid] = {"at": self.clock.now(), "body": body}
                # the record names the attachment point as its resource, and the policy by its ID in its request
                self.audit.append((firing.METHODS[firing.DENY_KIND], f'protoPayload.request.policyId="{pid}"', self.clock.now()))
                return {"name": "operations/2"}
            pid = path.rsplit("/", 1)[1]
            if path.endswith("/denypolicies"):
                return {"policies": [{"name": f"x/{p}", "rules": v["body"]["rules"]} for p, v in self.deny.items()]}
            if pid not in self.deny:
                raise GoogleError(404, "NOT_FOUND")
            if method == "DELETE":
                del self.deny[pid]
            return {"name": pid}
        if url == running.LOGGING and "methodName=(" in body["filter"]:
            # the kit's search for your own trigger's record: each record of the methods it names, with its payload
            f = body["filter"]
            methods = re.findall(r'"([^"]+)"', f.split("methodName=(")[1].split(")")[0])
            since = datetime.fromisoformat(f.split('timestamp>="')[1].split('"')[0].replace("Z", "+00:00")).timestamp()
            until = datetime.fromisoformat(f.split('timestamp<="')[1].split('"')[0].replace("Z", "+00:00")).timestamp()
            entries = []
            for i, (m, clause, when) in enumerate(self.audit):
                if m in methods and since <= when <= until and self.clock.now() >= when + self.log_delay:
                    key, value = clause.split("=", 1)
                    payload = ({"resourceName": value.strip('"')} if key.endswith("resourceName")
                               else {"request": {"policyId": value.strip('"')}})
                    entries.append({"insertId": f"i{i}", "timestamp": iso(when),
                                    "protoPayload": {"methodName": m, **payload}})
            return {"entries": entries}
        if url == running.LOGGING:
            f = body["filter"]
            method_name = f.split('protoPayload.methodName="')[1].split('"')[0]
            since = datetime.fromisoformat(f.split('timestamp>="')[1].split('"')[0].replace("Z", "+00:00")).timestamp()
            until = datetime.fromisoformat(f.split('timestamp<="')[1].split('"')[0].replace("Z", "+00:00")).timestamp()
            return {"entries": [{"timestamp": iso(when)} for m, clause, when in self.audit
                                if m == method_name and f" AND {clause} AND " in f and since <= when <= until
                                and self.clock.now() >= when + self.log_delay]}
        raise AssertionError(f"a call the fake does not know: {method} {url}")


def a_run(fake: FakeGoogle, stop: str, **kw):
    clock = fake.clock
    return running.run(fake, stop, endpoint=ENDPOINT, window=60.0, clock=running.Clock(clock.now, clock.sleep),
                       run_name=RUN_NAME, **kw)


def test_a_deny_policy_on_the_agents_identity_stops_its_own_calls_and_not_a_token_it_took_before():
    clock = Clock()
    fake = FakeGoogle(clock)
    r, doc = a_run(fake, firing.DENY_ALL)
    [(fired_at, found)] = running.results(r)
    assert found["own_calls"].outcome == "stopped" and found["outside_key"].outcome == "not stopped"
    assert found["another_identity"].outcome == "not stopped" and found["another_identity"].keeps_working_until
    assert found["own_calls"].fired_source == "Cloud Audit Logs' record of the call"
    # the deny policy the kit made names the run's own account alone, and denies what the paths use
    [made] = [b["body"] for b in fake.bodies if b["url"].endswith(f"policyId={N['deny_policy']}")]
    assert made["rules"][0]["denyRule"]["deniedPrincipals"] == [
        f"principal://iam.googleapis.com/projects/-/serviceAccounts/{N['agent_account']}"]
    assert made["rules"][0]["denyRule"]["deniedPermissions"] == firing.DENIED
    assert r.left_behind == [] and len(r.checked_gone) == 5
    checked = result.check(doc)
    assert (checked["cloud"], checked["stop"]["kind"], checked["agent"]["kind"]) == (
        "google_cloud", firing.DENY_KIND, "google-cloud-run-service")
    assert checked["agent"]["role_ref"] == N["agent_account"]


def test_disabling_the_agents_account_is_fired_and_taken_off_between_repeats():
    clock = Clock()
    fake = FakeGoogle(clock)
    r, _ = a_run(fake, firing.DISABLE, repeats=2)
    disables = [u for m, u in fake.calls if u.endswith(":disable")]
    enables = [u for m, u in fake.calls if u.endswith(":enable")]
    assert len(disables) == 2 and len(enables) == 1                  # off again only between the repeats
    assert all(f["own_calls"].outcome == "stopped" for _, f in running.results(r))
    assert r.stop_kind == firing.DISABLE_KIND


def test_your_declared_deny_policy_is_copied_for_the_test_agent_alone_and_never_changed():
    clock = Clock()
    fake = FakeGoogle(clock)
    r, _ = a_run(fake, DECLARED)
    [made] = [b["body"] for b in fake.bodies if b["url"].endswith(f"policyId={N['deny_policy']}")]
    assert made["rules"][0]["denyRule"]["deniedPermissions"] == [
        "storage.googleapis.com/objects.create", "storage.googleapis.com/objects.get"]
    assert made["rules"][0]["denyRule"]["deniedPrincipals"] == [
        f"principal://iam.googleapis.com/projects/-/serviceAccounts/{N['agent_account']}"]
    assert not [u for m, u in fake.calls if m != "GET" and u.endswith("/agent-stop")], "yours is read, never written"


def test_a_conditional_deny_policy_or_something_else_is_refused_before_anything_is_made():
    clock = Clock()
    fake = FakeGoogle(clock, declared_rules=[{"denyRule": {"deniedPrincipals": ["principal://goog/subject/x@acme.test"],
                                                           "deniedPermissions": ["storage.googleapis.com/*.*"],
                                                           "denialCondition": {"expression": "true"}}}])
    with pytest.raises(firing.Refused, match="condition"):
        a_run(fake, DECLARED)
    with pytest.raises(firing.Refused, match="not a deny policy"):
        a_run(FakeGoogle(clock), "projects/acme/roles/stopper")
    assert fake.accounts == {} and fake.bucket is None and fake.service is None


def test_an_account_that_is_not_the_runs_own_is_never_fired_on():
    clock = Clock()
    fake = FakeGoogle(clock, described=False)
    with pytest.raises(firing.Refused, match="not this run's own"):
        a_run(fake, firing.DISABLE)
    assert fake.disabled == {} and fake.accounts == {}, "nothing fired, and the teardown still ran"


def test_with_no_audit_record_the_moment_is_the_kits_clock_moved_onto_the_agents():
    clock = Clock()
    fake = FakeGoogle(clock, log_delay=10_000.0)
    r, _ = a_run(fake, firing.DENY_ALL, log_wait=60.0)
    [rep] = r.repeats
    assert rep.fired_at == pytest.approx(rep.fired_before + r.offset) and rep.fired_precision == rep.fired_after - rep.fired_before


def test_anything_the_teardown_could_not_delete_is_named_left():
    clock = Clock()
    fake = FakeGoogle(clock, bucket_stays=True)
    r, doc = a_run(fake, firing.DENY_ALL)
    assert r.left_behind == [f"the bucket {N['bucket']}"]
    assert result.check(doc)["run"]["left_anything"] is True


def test_the_agent_is_pythons_own_image_by_digest_and_its_code_the_standard_library_alone():
    assert IMAGE.startswith("docker.io/library/python:") and "@sha256:" in IMAGE
    code = agent_code()
    assert len(code.encode()) <= CODE_LIMIT and not code.lstrip().startswith('"""')
    imported = {a.name.split(".")[0] for n in ast.walk(ast.parse(code)) if isinstance(n, ast.Import) for a in n.names}
    imported |= {n.module.split(".")[0] for n in ast.walk(ast.parse(code)) if isinstance(n, ast.ImportFrom)}
    assert imported <= {"datetime", "json", "os", "time", "urllib", "http"}, imported
    assert LABEL == "arvaken-stop-test"
    assert json.loads(json.dumps({"code": code}))["code"] == code


def test_a_declared_deny_that_does_not_deny_the_agents_own_calls_is_refused_before_anything_is_made():
    """The founder, 24 October 2026: before a run with --stop, the kit checks that the copied deny covers what the test
    agent does as its own account. A wildcard Google accepts in a name covers what it stands for."""
    clock = Clock()
    fake = FakeGoogle(clock, declared_rules=[{"denyRule": {"deniedPrincipals": ["principal://goog/subject/x@acme.test"],
                                                           "deniedPermissions": ["compute.googleapis.com/instances.create"]}}])
    with pytest.raises(firing.Refused) as e:
        a_run(fake, DECLARED)
    assert str(e.value) == "Your stop doesn't deny what the test agent does, so this test can't tell you about your stop."
    assert fake.accounts == {} and fake.bucket is None and fake.service is None
    assert firing.covers(["storage.googleapis.com/objects.*"])
    assert not firing.covers(["storage.googleapis.com/objects.create"])


def test_the_teardown_empties_a_bucket_of_thousands_page_by_page_and_names_nothing_left():
    """The agent writes an object on every heartbeat: a five-repeat run left about 12,000 in its bucket (25 October
    2026), which one deletion at a time took half an hour to clear."""
    clock = Clock()
    fake = FakeGoogle(clock)
    fake.objects = {f"own/{i}" for i in range(2500)}
    r, _ = a_run(fake, firing.DENY_ALL)
    assert fake.objects == set() and fake.bucket is None and r.left_behind == []
    assert len([u for m, u in fake.calls if m == "GET" and urllib.parse.urlsplit(u).path.endswith("/o")]) == 4


def test_objects_that_cannot_be_deleted_end_the_teardown_and_the_bucket_is_named_left():
    clock = Clock()
    fake = FakeGoogle(clock)
    fake.objects, fake.objects_stay = {"own/1", "own/2"}, True
    r, _ = a_run(fake, firing.DENY_ALL)
    assert r.left_behind == [f"the bucket {N['bucket']}"] and fake.objects == {"own/1", "own/2"}


def test_a_check_google_cannot_answer_just_then_is_asked_again_before_anything_is_named():
    """A five-repeat run named a deny policy left that was gone: Google had answered the check 503 (25 October 2026)."""
    clock = Clock()
    fake = FakeGoogle(clock)
    r, _ = a_run(fake, firing.DISABLE)
    fake.unavailable["denypolicies"] = running.TRANSIENT_TRIES - 1
    left, gone = running.check_gone(fake, r, running.Clock(clock.now, clock.sleep))
    assert left == [] and f"the deny policy {N['deny_policy']}" in gone
    fake.unavailable["denypolicies"] = running.TRANSIENT_TRIES
    left, _ = running.check_gone(fake, r, running.Clock(clock.now, clock.sleep))
    assert left == [f"the deny policy {N['deny_policy']} (could not be checked: 503 UNAVAILABLE)"]



def after_the_warm_up(g) -> bool:
    return g.agent_calls >= running.WARM_UP + 2 and g.clock.now() >= T0 + 60


def test_your_own_trigger_is_counted_as_the_kind_cloud_audit_logs_record_of_it_shows():
    """The founder's ruling of 29 October 2026, item 5: the kit identifies the kind of stop from the cloud's audit
    record of your own action, records it and its source record, and counts that kind's refusals."""
    for action, kind in ((":disable", firing.DISABLE_KIND), ("deny", firing.DENY_KIND)):
        clock = Clock()
        fake = FakeGoogle(clock)
        pulled = []

        def the_customer(g, action=action, pulled=pulled):
            if not pulled and after_the_warm_up(g):
                pulled.append(g.clock.now())
                if action == ":disable":
                    g.call("POST", f"https://iam.googleapis.com/v1/projects/-/serviceAccounts/{N['agent_account']}"
                           ":disable", {})
                else:
                    attachment = "cloudresourcemanager.googleapis.com%2Fprojects%2F" + PROJECT
                    principal = f"principal://iam.googleapis.com/projects/-/serviceAccounts/{N['agent_account']}"
                    g.call("POST", f"https://iam.googleapis.com/v2/policies/{attachment}/denypolicies?policyId=yours",
                           {"rules": [{"denyRule": {"deniedPrincipals": [principal], "deniedPermissions": ["x"]}}]})
        fake.customer = the_customer
        r, doc = a_run(fake, DECLARED, fired_by="your own trigger")
        assert (r.trigger_kind, doc["stop"]["kind"]) == (kind, kind), action
        assert r.trigger_record["source"] == "Cloud Audit Logs" and r.trigger_record["insert_id"]
        assert doc["repeats"][0]["own_calls"]["outcome"] == "stopped", action
        assert running.details(r, doc)["trigger"]["kind"] == kind


def test_your_own_trigger_with_no_audit_record_counts_nothing_as_stopped_and_says_so():
    clock = Clock()
    fake = FakeGoogle(clock, log_delay=10_000.0)                 # Cloud Audit Logs never record it in time

    def the_customer(g):
        if not g.disabled and after_the_warm_up(g):
            g.call("POST", f"https://iam.googleapis.com/v1/projects/-/serviceAccounts/{N['agent_account']}:disable", {})
    fake.customer = the_customer
    r, doc = a_run(fake, DECLARED, fired_by="your own trigger", log_wait=60.0)
    assert r.trigger_kind is None and doc["repeats"][0]["own_calls"]["outcome"] == "not measured"
    assert running.results(r)[0][1]["own_calls"].reason == running.NOT_IDENTIFIED


def test_cloud_runs_refusals_are_recorded_on_every_path_and_never_counted():
    """A 429 or a 5xx from Cloud Run is a throttle or a server error, never the stop's refusal (the founder, 29
    October 2026), however long it lasts."""
    clock = Clock()
    fake = FakeGoogle(clock)
    real = fake.agent

    def refusing(payload):
        if payload.get("action") != "assume" and fake.stopped_since() is not None:
            raise GoogleError(503, "UNAVAILABLE")
        return real(payload)
    fake.agent = refusing
    r, doc = a_run(fake, firing.DENY_ALL)
    assert {p: v["outcome"] for p, v in doc["repeats"][0].items()} == {p: "not measured" for p in running.GOOGLE_PATHS}
    found = running.results(r)[0][1]["own_calls"]
    assert found.not_counted == {"Cloud Run refused: HTTP503": found.failures_after} and found.failures[0].status == 503


def test_a_heartbeat_that_got_no_answer_is_counted_by_its_code_and_never_ends_the_run():
    """Run r37f2ed13 (30 October 2026) ended on one: a TLS handshake with the test agent timed out, urllib raised it,
    and the kit wrote no result. A heartbeat the kit could not complete gives no beat to any path, is counted in the
    details by its code, and the run goes on (the founder's answer of 30 October 2026). Google's own answer that is not
    Cloud Run's refusal still ends the run."""
    clock = Clock()
    whole, whole_doc = a_run(FakeGoogle(clock), firing.DISABLE)
    handshake = urllib.error.URLError(TimeoutError("_ssl.c:993: The handshake operation timed out"))   # r37f2ed13's
    lose = {-2: handshake, 5: TimeoutError("The read operation timed out"),
            6: http.client.RemoteDisconnected("Remote end closed connection without response"), 20: handshake}
    clock = Clock()
    r, doc = a_run(FakeGoogle(clock, lose=lose), firing.DISABLE)
    assert result.check(doc) == doc
    assert [{p: v["outcome"] for p, v in d["repeats"][0].items()} for d in (doc, whole_doc)] == [
        {"own_calls": "stopped", "another_identity": "not stopped", "outside_key": "not stopped",
         "open_internet": "not stopped"}] * 2
    assert r.calls == whole.calls - 4 * len(running.GOOGLE_PATHS)
    lost = running.details(r, doc)["heartbeats_lost"]
    assert lost["by_code"] == {"TimeoutError": 3, "RemoteDisconnected": 1}
    assert [e["code"] for e in lost["each"]] == ["TimeoutError", "TimeoutError", "RemoteDisconnected", "TimeoutError"]
    assert running.details(whole, whole_doc)["heartbeats_lost"] == {"by_code": {}, "each": []}
    clock = Clock()
    with pytest.raises(GoogleError):
        a_run(FakeGoogle(clock, lose={5: GoogleError(502, "HTTP")}), firing.DISABLE)
