"""A run on a test copy of the customer's own Cloud Run service (D575; google/your_copy.py), against test_google_run's
fake Google on its virtual clock, with the real probe (arvaken-stop-test-probe) answering each call to the copy.

The fake's copy is a service of the customer's: it runs as its own account until the customer points it at the run's
account (the `wait` it is given does what the customer would, where `points` says so), and back; each pointing is a new
revision, and so a new process, whose probe holds no token yet. While it runs as the run's account, its own calls are
refused once a stop on that account takes hold, as the kit's own agent's are (test_google_run's rule); its calls with
the second account's token, taken before the stop, keep working, as neither stop names that account. Once the
customer's SDK switch is on (`sdk_on_from`), each call the SDK guards raises its own error first."""
from __future__ import annotations

import json
import urllib.parse
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from arvaken_stop_test import result
from arvaken_stop_test.aws import your_copy as aws_copy
from arvaken_stop_test.aws.run import MARK_PROMPT
from arvaken_stop_test.google import fire as firing
from arvaken_stop_test.google import run as running
from arvaken_stop_test.google import your_copy
from arvaken_stop_test.google.api import GoogleError
from arvaken_stop_test_probe import core, heartbeat
from arvaken_stop_test_probe import google as probe_google
from test_google_run import DECLARED, PROJECT, REGION, RUN_NAME, Clock, FakeGoogle, N

COPY = f"projects/{PROJECT}/locations/{REGION}/services/support-agent-test"
OWN = f"support-agent@{PROJECT}.iam.gserviceaccount.com"
DEFAULT = "123456789012-compute@developer.gserviceaccount.com"
SKEW = 0.05
DENIED = json.dumps({"error": {"code": 403, "message": f"{N['agent_account']} does not have storage.objects.create",
                               "errors": [{"reason": "forbidden", "message": "names the account"}]}}).encode()


class SwitchEngaged(Exception):
    """An in-agent SDK's own error, as its switch makes each call it guards raise one, its message naming things."""


class CopyGoogle(FakeGoogle):
    """The project, with the customer's copy in it, as a run on a copy sees it."""

    def __init__(self, clock: Clock, *, ingress="INGRESS_TRAFFIC_ALL", traffic=None, own=OWN, vpc=False,
                 memory="1Gi", answers_with=None, env=(), volumes=(), **kw):
        super().__init__(clock, **kw)
        self.copy_account, self.ingress, self.vpc, self.memory = own, ingress, vpc, memory
        self.env, self.volumes = list(env), list(volumes)
        self.traffic = traffic or [{"type": your_copy.LATEST, "percent": 100}]
        self.revision = 1
        self.answers_with = answers_with            # an HTTP status the copy's own code answers every call with
        self.copy_calls: list[dict] = []
        self.sdk_on_from: float | None = None

    def copy_service(self) -> dict:
        latest = f"{COPY}/revisions/support-agent-test-{self.revision:05d}-abc"
        return {"name": COPY, "uri": "https://copy.example", "ingress": self.ingress, "reconciling": False,
                "template": {"serviceAccount": self.copy_account or "",
                             "containers": [{"image": "europe-west3-docker.pkg.dev/acme/agents/support@sha256:0",
                                             "ports": [{"containerPort": 8080}], "env": self.env,
                                             "resources": {"limits": {"cpu": "1", "memory": self.memory}}}],
                             "volumes": self.volumes,
                             **({"vpcAccess": {"connector": "projects/acme/locations/x/connectors/c"}} if self.vpc
                                else {})},
                "traffic": self.traffic, "trafficStatuses": self.traffic, "latestReadyRevision": latest,
                "latestCreatedRevision": latest, "terminalCondition": {"state": "CONDITION_SUCCEEDED"}}

    def point(self, account: str) -> None:
        """The customer's gcloud run services update: a new revision, as the account named, in a new process."""
        self.copy_account, self.revision = account, self.revision + 1
        probe_google._OWN.update(token=None, until=0.0, issued=0.0)

    def refused(self, token: str) -> bool:
        since = self.stopped_since()
        return token == f"token:{N['agent_account']}" and since is not None and self.clock.now() >= since

    def _by_the_sdk(self, what: str) -> None:
        if self.sdk_on_from is not None and self.clock.now() >= self.sdk_on_from:
            raise SwitchEngaged(f"the SDK blocked {what} as {N['agent_account']}")

    def request(self, method, url, headers, body, timeout):
        """The copy's own request function (KC2's `cloud`): Google's answer to each of the probe's calls."""
        self._by_the_sdk(url)
        token = headers.get("Authorization", "").removeprefix("Bearer ")
        if url == probe_google.METADATA:
            return 200, json.dumps({"access_token": f"token:{self.copy_account or DEFAULT}",
                                    "expires_in": 3599}).encode()
        if url.endswith(":generateAccessToken"):
            if self.refused(token):
                return 403, json.dumps({"error": {"code": 403, "status": "PERMISSION_DENIED"}}).encode()
            expires = datetime.fromtimestamp(self.clock.now() + 3600, tz=timezone.utc)
            return 200, json.dumps({"accessToken": "token:second",
                                    "expireTime": expires.isoformat().replace("+00:00", "Z")}).encode()
        assert url.startswith(probe_google.STORAGE) and f"/b/{N['bucket']}/o" in url, url
        if self.refused(token):
            return 403, DENIED
        if method == "POST":
            self.objects.add(urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)["name"][0])
        return 200, b"x" if method == "GET" else b"{}"

    def http(self, url, headers, timeout):
        """The copy's own HTTP client: answered, until the customer's SDK switch refuses it."""
        self._by_the_sdk(url)
        return 200

    def copy_call(self, url: str, body: dict) -> dict:
        assert url == "https://copy.example/", url
        self.copy_calls.append(body)
        self.clock.t += 0.1
        if self.answers_with:
            raise GoogleError(self.answers_with, "HTTP")
        try:
            out = heartbeat.run(body, cloud=self.request, http=self.http)
        except Exception:  # noqa: BLE001 - the customer's server answers the probe's error with its own 500
            self.clock.t += 0.1
            raise GoogleError(500, "HTTP") from None
        self.clock.t += 0.1
        return json.loads(json.dumps(out))

    def call(self, method: str, url: str, body=None, *, identity: bool = False, raw=None):
        if identity:
            self.calls.append((method, url))
            return self.copy_call(url, body)
        if urllib.parse.urlsplit(url).path == f"/v2/{COPY}":
            self.calls.append((method, url))
            assert method == "GET", "the kit never changes a copy"
            return self.copy_service()
        assert "run.googleapis.com" not in url, f"a run on a copy never asks for a service of the kit's: {url}"
        if method == "DELETE" and url.endswith(f"/serviceAccounts/{N['agent_account']}"):
            assert self.copy_account != N["agent_account"], "an account the copy runs as is never deleted"
        return super().call(method, url, body, identity=identity, raw=raw)


@pytest.fixture(autouse=True)
def fresh_probe(monkeypatch):
    """The probe's token cache anew for each test, as for a copy in a new process."""
    monkeypatch.setattr(probe_google, "_OWN", {"token": None, "until": 0.0, "issued": 0.0})
    yield


def a_copy_run(g: CopyGoogle, monkeypatch, *, typed=RUN_NAME, warned=RUN_NAME, points=("at", "back"),
               stop=firing.DENY_ALL, fires_after: float | None = None, answers: dict | None = None, **over):
    clock = g.clock
    stamp = SimpleNamespace(time=lambda: clock.now() + SKEW)
    for module in (core, probe_google, heartbeat):
        monkeypatch.setattr(module, "time", stamp)
    said, asked = [], []

    def confirm(words: str) -> str:
        asked.append(words)
        if answers and words in answers:
            return answers[words]
        return warned if words == your_copy.WARNING else typed

    def wait(words: str) -> None:
        asked.append(words)
        if words.startswith("Point your copy at") and "at" in points:
            g.point(N["agent_account"])
        elif words.startswith("Point your copy back") and "back" in points:
            g.point(OWN if g.copy_account == N["agent_account"] and OWN in words else
                    words.split("--service-account ")[1].split()[0])
        elif words == MARK_PROMPT and fires_after is not None:
            g.sdk_on_from = clock.now() + fires_after

    def wait_calling(words: str, each) -> float:
        end = clock.now() + 30.0
        while clock.now() < end:
            each()
            clock.sleep(1.0)
        wait(words)
        return clock.now()

    kw = dict(window=60.0, clock=running.Clock(clock.now, clock.sleep), run_name=RUN_NAME, say=said.append,
              confirm=confirm, wait=wait, wait_calling=wait_calling, witness_get=lambda url, headers: 200)
    kw.update(over)
    return your_copy.run(g, COPY, stop, **kw), said, asked


def test_a_run_on_a_copy_fires_on_the_runs_account_alone_and_times_the_copys_own_calls(monkeypatch):
    g = CopyGoogle(Clock())
    r, said, asked = a_copy_run(g, monkeypatch)
    [(_, found)] = your_copy.results(r)
    assert found["own_calls"].outcome == "stopped" and found["own_calls"].fired_source == \
        "Cloud Audit Logs' record of the call"
    assert found["another_identity"].outcome == "not stopped" and found["another_identity"].keeps_working_until
    assert found["outside_key"].outcome == found["open_internet"].outcome == "not stopped"
    # the deny policy names the account the copy ran as, and no other
    [made] = [b["body"] for b in g.bodies if b["url"].endswith(f"policyId={N['deny_policy']}")]
    assert made["rules"][0]["denyRule"]["deniedPrincipals"] == [
        f"principal://iam.googleapis.com/projects/-/serviceAccounts/{N['agent_account']}"]
    # each call carried the run's settings in the kit's marker, and the probe answered it
    marker = g.copy_calls[0][running.MARKER]
    assert (marker["run"], marker["cloud"], marker["bucket"], marker["second_account"]) == (
        RUN_NAME, "google_cloud", N["bucket"], N["second_account"])
    assert len(marker["key"]) == 32 and r.outputs["Uri"] == "https://copy.example"
    # asked, in order: the copy confirmed, pointed at the run's account, the warning, pointed back
    assert [a.split(":")[0].split(",")[0] for a in asked] == [
        "The kit will call " + COPY + " once a second", "Point your copy at the run's account for the test",
        your_copy.WARNING.split(",")[0].split(":")[0], "Point your copy back at its own account"]
    assert f"--service-account {N['agent_account']}" in asked[1] and f"--service-account {OWN}" in asked[3]
    assert "gcloud run services update support-agent-test --project acme-sandbox-1 --region europe-west3" in asked[1]
    # the kit made no service and changed nothing of the copy's; everything it made is gone, the copy's account kept
    assert not [u for m, u in g.calls if "run.googleapis.com" in u and m != "GET"]
    assert r.left_behind == [] and r.checked_gone == [
        f"the bucket {N['bucket']}", f"the account {N['agent_account']}", f"the account {N['second_account']}",
        f"the deny policy {N['deny_policy']}"]
    assert g.copy_account == OWN

    doc, details = your_copy.the_result(r, ["searches or reads the web"], "a model provider's API")
    checked = result.check(doc)
    assert checked["format"] == result.FORMAT_V3 and checked["cloud"] == "google_cloud"
    assert checked["agent"] == {
        "kind": "google-cloud-run-service", "runtime": "container", "memory_mb": 1024, "private_network": False,
        "ref": COPY, "role_ref": N["agent_account"], "whose": "yours", "tools": ["searches or reads the web"],
        "model_kind": "a model provider's API", "clients": {"cloud": "yours", "http": "yours"}}
    assert checked["stop"]["kind"] == firing.DENY_KIND and checked["stop"]["record"] is None
    assert details["format"] == "stop-test-details/1" and details["heartbeats_lost"]["by_code"] == {}


def test_disabling_the_copys_account_is_fired_and_taken_off_between_repeats(monkeypatch):
    g = CopyGoogle(Clock())
    r, _, _ = a_copy_run(g, monkeypatch, stop=firing.DISABLE, repeats=2)
    assert len([u for m, u in g.calls if u.endswith(":disable")]) == 2
    assert all(f["own_calls"].outcome == "stopped" for _, f in your_copy.results(r))
    assert r.stop_kind == firing.DISABLE_KIND and N["agent_account"] not in g.disabled


def test_your_declared_deny_policy_is_copied_for_the_copys_account_alone_and_never_changed(monkeypatch):
    g = CopyGoogle(Clock())
    r, _, _ = a_copy_run(g, monkeypatch, stop=DECLARED)
    [made] = [b["body"] for b in g.bodies if b["url"].endswith(f"policyId={N['deny_policy']}")]
    assert made["rules"][0]["denyRule"]["deniedPermissions"] == [
        "storage.googleapis.com/objects.create", "storage.googleapis.com/objects.get"]
    assert not [u for m, u in g.calls if m != "GET" and u.endswith("/agent-stop")]


def test_nothing_is_made_unless_the_runs_name_is_typed_to_confirm_a_test_copy(monkeypatch):
    g = CopyGoogle(Clock())
    with pytest.raises(firing.Refused, match="nothing was made"):
        a_copy_run(g, monkeypatch, typed="no")
    assert not [u for m, u in g.calls if m != "GET"] and not g.accounts and g.bucket is None


@pytest.mark.parametrize("copy", [
    f"projects/someone-else-1/locations/{REGION}/services/support-agent-test",     # another project
    f"projects/{PROJECT}/locations/us-central1/services/support-agent-test",       # another region
    "https://support-agent-test-abc-ey.a.run.app",                                 # its address, not its name
    f"projects/{PROJECT}/locations/{REGION}/jobs/support-agent-test",              # a job takes no calls
    f"projects/{PROJECT}/locations/{REGION}/services/Support_Agent",
])
def test_a_copy_not_named_as_a_service_in_this_project_and_region_is_refused_before_anything(copy):
    g = CopyGoogle(Clock())
    with pytest.raises(ValueError) as refused:
        your_copy.run(g, copy, firing.DENY_ALL, confirm=lambda w: RUN_NAME, wait=lambda w: None)
    assert str(refused.value) == your_copy.NOT_A_SERVICE and g.calls == []


@pytest.mark.parametrize("over, says", [
    ({"ingress": "INGRESS_TRAFFIC_INTERNAL_ONLY"}, your_copy.NOT_FROM_OUTSIDE),
    ({"ingress": "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"}, your_copy.NOT_FROM_OUTSIDE),
    ({"traffic": [{"type": "TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION", "revision": "support-agent-test-00001-abc",
                   "percent": 100}]}, your_copy.NOT_ALL_TRAFFIC),
    ({"traffic": [{"type": your_copy.LATEST, "percent": 90},
                  {"type": "TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION", "revision": "old", "percent": 10}]},
     your_copy.NOT_ALL_TRAFFIC),
    ({"env": [{"name": "API_KEY", "valueSource": {"secretKeyRef": {"secret": "api-key", "version": "latest"}}}]},
     your_copy.NOT_SECRETS),
    ({"volumes": [{"name": "keys", "secret": {"secret": "api-key"}}]}, your_copy.NOT_SECRETS),
])
def test_a_copy_the_kit_could_not_time_as_it_runs_is_refused_before_anything_is_asked_or_made(over, says, monkeypatch):
    g = CopyGoogle(Clock(), **over)
    with pytest.raises(firing.Refused) as refused:
        a_copy_run(g, monkeypatch)
    assert str(refused.value) == says and not [u for m, u in g.calls if m != "GET"]


def test_a_copy_not_pointed_at_the_runs_account_is_not_timed_and_what_was_made_is_removed(monkeypatch):
    g = CopyGoogle(Clock())
    with pytest.raises(your_copy.NotStarted) as stopped:
        a_copy_run(g, monkeypatch, points=())
    said = your_copy.NOT_POINTED.format(copy=COPY, account=N["agent_account"])
    assert str(stopped.value) == said and stopped.value.run.left_behind == [] and not g.copy_calls
    assert not g.accounts and g.bucket is None


def test_a_copy_still_running_as_the_runs_account_keeps_it_and_it_is_named_for_the_customer(monkeypatch):
    g = CopyGoogle(Clock())
    r, _, _ = a_copy_run(g, monkeypatch, points=("at",))
    assert r.left_behind == [your_copy.STILL_RUNS_AS.format(account=N["agent_account"], copy=COPY)]
    assert N["agent_account"] in g.accounts and N["second_account"] not in g.accounts and g.bucket is None


def test_a_copy_on_its_projects_default_account_is_pointed_back_at_it_by_name(monkeypatch):
    g = CopyGoogle(Clock(), own="")
    g.accounts[DEFAULT] = {"email": DEFAULT, "uniqueId": "1", "description": "Compute Engine default service account"}
    r, _, asked = a_copy_run(g, monkeypatch)
    assert r.copy_account == DEFAULT and f"--service-account {DEFAULT}" in asked[-1]
    assert g.copy_account == DEFAULT and r.left_behind == []


def test_a_copy_that_answers_with_its_own_error_has_no_path_working_and_nothing_is_timed(monkeypatch):
    g = CopyGoogle(Clock(), answers_with=500)
    with pytest.raises(your_copy.NotStarted) as stopped:
        a_copy_run(g, monkeypatch)
    r = stopped.value.run
    assert str(stopped.value) == your_copy.NOTHING_WORKED and not r.repeats
    assert r.setup_errors["own_calls"] == {"CopyError:HTTP500": 10}
    assert g.copy_account == OWN and r.left_behind == []


def test_cloud_runs_own_refusals_on_a_copy_are_recorded_and_never_counted(monkeypatch):
    g = CopyGoogle(Clock(), answers_with=503)
    with pytest.raises(your_copy.NotStarted) as stopped:
        a_copy_run(g, monkeypatch)
    assert stopped.value.run.setup_errors["open_internet"] == {f"{running.REFUSED}HTTP503": 10}


def test_without_the_runs_name_typed_before_firing_nothing_is_fired(monkeypatch):
    g = CopyGoogle(Clock())
    r, said, _ = a_copy_run(g, monkeypatch, warned="no")
    assert your_copy.NOT_FIRED in said and not r.repeats and not g.deny and g.copy_account == OWN


def test_an_sdks_switch_on_a_copy_is_fired_by_you_and_judged_by_its_rule_with_the_witness(monkeypatch, tmp_path):
    g = CopyGoogle(Clock())
    clock = g.clock
    stamp = SimpleNamespace(time=lambda: clock.now() + SKEW)
    for module in (core, probe_google, heartbeat):
        monkeypatch.setattr(module, "time", stamp)
    export, entered, asked, witnessed = tmp_path / "sdk-audit.jsonl", {}, [], []

    def confirm(words: str) -> str:
        """The customer's answers: the export written once the switch is on, its entry's time as the file writes it."""
        asked.append(words)
        if words == aws_copy.SDK_EXPORT:
            t = datetime.fromtimestamp(g.sdk_on_from + SKEW + 1, tz=timezone.utc).isoformat().replace("+00:00", "Z")
            entered["time"] = t
            export.write_text(json.dumps({"at": t, "event": "kill_switch.engaged"}) + "\n", encoding="utf-8")
            return str(export)
        return {aws_copy.SDK_ENTRY_TIME: entered.get("time"), aws_copy.SDK_ENTRY_NAME: "kill_switch.engaged"}.get(
            words, RUN_NAME)

    def wait(words: str) -> None:
        asked.append(words)
        if words.startswith("Point your copy at"):
            g.point(N["agent_account"])
        elif words.startswith("Point your copy back"):
            g.point(OWN)

    def wait_calling(words: str, each) -> float:
        """The customer's Enter at the mark, 30 seconds on, the heartbeat made each second till then; then their
        SDK's switch, 5 seconds after it."""
        for _ in range(30):
            each()
            clock.sleep(1.0)
        g.sdk_on_from = clock.now() + 5.0
        return clock.now()

    r = your_copy.run(g, COPY, "", confirm=confirm, wait=wait, window=900.0, clock=running.Clock(clock.now, clock.sleep),
                      run_name=RUN_NAME, sdk_name="Acme Guard", wait_calling=wait_calling,
                      witness_get=lambda url, headers: witnessed.append(url) or 200)
    [(_, found)] = your_copy.results(r)
    assert {p: f.outcome for p, f in found.items()} == {p: "stopped, by Arvaken's rule for an SDK's stop"
                                                         for p in running.GOOGLE_PATHS}
    assert not g.deny and not g.disabled                    # the kit fired nothing
    # the witness called beside each heartbeat from the mark through the window, and each of its calls was answered
    assert len(witnessed) == len(r.witness) and r.witness[-1][0] - r.witness[0][0] >= 900
    assert all(ok for _, ok, _ in r.witness)
    assert asked[0] == your_copy.CONFIRM_COPY_SDK.format(copy=COPY, run=RUN_NAME)
    doc, details = your_copy.the_result(r, ["no tools"], "no model")
    checked = result.check(doc)
    assert checked["stop"]["kind"] == result.PRODUCT_CONTROL and checked["stop"]["fired_by"] == "your own trigger"
    assert checked["stop"]["product"] == {"kind": "in-agent SDK", "attachment": "inside its code", "name": "Acme Guard"}
    assert checked["stop"]["record"]["time"] == entered["time"] and not checked["stop"]["record"]["before_mark"]
    assert details["witness"]["calls"] == len(r.witness) and details["witness"]["failed"] == []


@pytest.mark.parametrize("limit, mb", [("512Mi", 512), ("1Gi", 1024), ("2G", 1907), ("4Gi", 4096), (None, 512),
                                       ("1536M", 1465), ("bad", 512)])
def test_a_copys_memory_is_its_serving_containers_limit_in_lambdas_megabytes(limit, mb):
    assert your_copy.memory_mb(limit) == mb


def test_a_copy_in_a_network_of_yours_says_so_and_its_memory_is_its_containers():
    g = CopyGoogle(Clock(), vpc=True, memory="2Gi")
    found = g.copy_service()
    assert your_copy.memory_mb(your_copy.serving(found)["resources"]["limits"]["memory"]) == 2048
    assert bool(found["template"].get("vpcAccess"))
