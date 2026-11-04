"""The stop test on a test copy of your own agent, as a Cloud Run service of yours (D575; mark's
docs/platform/STOP-TEST-YOUR-OWN-AGENT-DESIGN.md, sections 1 to 4). Google Cloud after AWS, as its section 7 orders it,
with the kit's Google module: as aws/your_copy.py is for a Lambda function, with Google's run (run.py) and stops
(fire.py).

**The copy is yours.** You deploy it, with the probe (arvaken-stop-test-probe) in its handler for the kit's POST to its
address, and name it by its service's full name, in the project and region the kit runs in. The kit never deploys,
changes or deletes it, nor its revisions or its logs (run.tear_down, run.check_gone).

**What the kit makes** is run.py's things without the service (stack.identities, `copy`): the bucket, the second
account, and the account the copy runs as for the test (KC1), named and granted as the kit's own test agent's account.
You point the copy at that account for the test, with the command the kit prints, and back afterwards; the kit checks,
before anything is timed, that the copy's latest revision is ready, runs as that account and takes all its traffic. The
kit deletes the account only once the copy no longer runs as it, and while it still does, leaves it and names it.

**Before anything is made**, the kit reads your copy and refuses one it could not time as it runs: a copy that takes
calls only from your own networks, which the kit's calls do not come from, or one that sends its traffic to a revision
you named, which a revision running as the run's account would not take. Then you confirm by typing the run's name that
the copy is a test copy, not an agent whose work matters (the terms, 2.1).

**Each call carries the run's settings** in the kit's marker (run._invoke): the copy's environment is yours, as on
Lambda. The probe takes only settings named for the run.

**Firing.** The kit fires a stop itself, only on the account made for the run, as its own Google runs do (fire.py): a
deny policy naming that account alone, or the account disabled; only after the warning before every firing (KC4) and
your typing the run's name. Or, for an in-agent SDK's switch (`sdk_name`), you fire it yourself from your mark, after the
same warning, and the kit fires nothing: each path is judged by the founder's rule for it (sdk.py; D713), with the kit's
witness (Witness) calling from outside the copy through the window, and your SDK's own record of acting taken from your
export afterwards, as on Lambda.

**Its result** is a stop-test-result/3, as on Lambda (the_result): the copy's service name, sealed when submitted, as
every identifier is; "container" as its runtime, since a Cloud Run service is one; its memory and whether it reaches a
network of yours; whose test agent it was; the kinds of its tools and model you chose from the kit's lists, and whose
clients the probe used, by kind; for an SDK's switch, your SDK's own record, as on Lambda.
"""
from __future__ import annotations

import re
import secrets
import urllib.error
from collections.abc import Callable
from pathlib import Path
from typing import Any

from arvaken_stop_test import result, sdk
from arvaken_stop_test.aws.run import MARK_PROMPT
from arvaken_stop_test.aws.your_copy import (ENDPOINT, NOT_CONFIRMED, NOT_FIRED, NOTHING_WORKED, RECORD_BEFORE_MARK,
                                             SDK_FIRES_NOTHING, SDK_MARKED, SDK_NAMED, SDK_SWITCH_OFF,
                                             SDK_WINDOW_TOO_SHORT, WARNING, WITNESS_AGENT, Stopped, calling_while,
                                             copy_part, sdk_results, take_record)
from arvaken_stop_test.aws.your_copy import _get as _witness_get
from arvaken_stop_test.aws.your_copy import copy_details as _copy_details
from arvaken_stop_test.google import fire as firing
from arvaken_stop_test.google import run as running
from arvaken_stop_test.google.api import Google, GoogleError, NotAToken
from arvaken_stop_test.google.run import Clock, Run
from arvaken_stop_test.google.stack import (FOR_A_COPY, IAM, RUN, STORAGE, display_name, identities, names,
                                            new_run, quoted)
from arvaken_stop_test.timing import GATEWAY_WINDOW, WINDOWS

# A Cloud Run service's full name: its project, its region and its own name, as Cloud Run allows them.
SERVICE_NAME = re.compile(r"projects/([a-z][a-z0-9-]{4,28}[a-z0-9])/locations/([a-z]+-[a-z]+[0-9]{1,2})"
                          r"/services/([a-z](?:[-a-z0-9]{0,47}[a-z0-9])?)")
DEFAULT_ACCOUNT = re.compile(r"[0-9]{1,20}-compute@developer\.gserviceaccount\.com")   # a project's default account
SETTLE = 120.0          # seconds to wait for Cloud Run to finish a change to the copy, once you have made it
ALL = "INGRESS_TRAFFIC_ALL"
LATEST = "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST"
UNITS = {"": 1 / 1048576, "k": 1000 / 1048576, "M": 1e6 / 1048576, "G": 1e9 / 1048576,
         "Ki": 1 / 1024, "Mi": 1, "Gi": 1024}          # a memory limit's units, in mebibytes, as Lambda's MB are
DEFAULT_MB = 512        # a Cloud Run container's memory where its limit names none

# The words below are the founder's, each approved word for word before any release carries it (D575's customer
# words, as on AWS).
# CUSTOMER TEXT: approved by the founder, word for word, by 19:42 UTC on 3 November 2026 (the Google copy, batch 1 (1))
NOT_A_SERVICE = ("a test copy on Google Cloud is named by its Cloud Run service's full name, "
                 "projects/PROJECT/locations/REGION/services/NAME, in the project and region the kit runs in")
# CUSTOMER TEXT: approved by the founder, word for word, by 19:42 UTC on 3 November 2026 (the Google copy, batch 1 (2)),
# as AWS's CONFIRM_COPY
CONFIRM_COPY = ("The kit will call {copy} once a second, with the run's settings (its bucket, its second account, and a "
                "test key made for the run, which works only with Arvaken's test address), and fire your stop on the "
                "account it makes for the run. Each call runs your copy's own code, which does whatever that code does "
                "with whatever its settings reach: databases, email, payments, other services. As the run's account, it "
                "reaches in Google Cloud only what that account is granted, but anything it reaches with its own keys or "
                "over the internet, it still reaches. Run it only on a test copy whose settings reach test systems alone, "
                "never on an agent whose work matters. Google bills each call, and anything the copy calls, to your "
                "project. Type the run's name, {run}, to confirm {copy} is a test copy.")
# For an SDK's switch the kit fires nothing, so its words say who fires, as on AWS.
CONFIRM_COPY_SDK = CONFIRM_COPY.replace("and fire your stop on the account it makes for the run",
                                        "and you fire your SDK's switch yourself, after your mark")
# CUSTOMER TEXT: approved by the founder, word for word, by 19:42 UTC on 3 November 2026 (the Google copy, batch 1 (3))
NOT_FROM_OUTSIDE = ("Your copy takes calls only from your own networks, and the kit calls it at its address from where "
                    "the kit runs. Nothing was made.")
# CUSTOMER TEXT: approved by the founder, word for word, by 19:42 UTC on 3 November 2026 (the Google copy, batch 1 (4))
NOT_ALL_TRAFFIC = ("Your copy sends its traffic to a revision you named, so a revision of it running as the run's account "
                   "would get none of the kit's calls. Send all its traffic to its latest revision, then run again. "
                   "Nothing was made.")
# CUSTOMER TEXT: approved by the founder, word for word, by 19:42 UTC on 3 November 2026 (the Google copy, batch 1 (9)),
# as AWS's refusal of a copy encrypted with your own key
NOT_SECRETS = ("Your copy's settings read a secret from Secret Manager, which the run's account can't read, so your copy "
               "couldn't start as it. Nothing was made.")
# CUSTOMER TEXT: approved by the founder, word for word, by 19:42 UTC on 3 November 2026 (the Google copy, batch 1 (5)),
# as AWS's POINT_AT
POINT_AT = ("Point your copy at the run's account for the test:\n"
            "  gcloud run services update {service} --project {project} --region {region} --service-account {account}\n"
            "Then press Enter.")
# CUSTOMER TEXT: approved by the founder, word for word, by 19:42 UTC on 3 November 2026 (the Google copy, batch 1 (6)),
# as AWS's NOT_POINTED
NOT_POINTED = ("Your copy {copy} does not run as the run's account {account}, with all its traffic, so nothing was "
               "timed. The kit is removing what it made.")
# CUSTOMER TEXT: approved by the founder, word for word, by 19:42 UTC on 3 November 2026 (the Google copy, batch 1 (7)),
# as AWS's POINT_BACK
POINT_BACK = ("Point your copy back at its own account:\n"
              "  gcloud run services update {service} --project {project} --region {region} --service-account {own}\n"
              "Then press Enter, and the kit removes what it made.")
# CUSTOMER TEXT: approved by the founder, word for word, by 19:42 UTC on 3 November 2026 (the Google copy, batch 1 (8)),
# as AWS's STILL_RUNS_AS
STILL_RUNS_AS = "the account {account}, which your copy {copy} still runs as (point it back, then delete the account)"
# CUSTOMER TEXT: approved by the founder, word for word, by 20:05 UTC on 3 November 2026 (the Google copy, clean (1))
CLEAN_NEEDS_COPY = ("This run was on a test copy of yours. Give your copy's name with --copy, so the kit can check that "
                    "your copy no longer runs as the run's account before it deletes that account. Nothing was removed.")


class Witness:
    """The kit's witness (D713, (3)), as on Lambda: once a second from the mark, the kit's own calls, made from where the
    kit runs and so outside the copy and its SDK: the run's bucket (read, with the kit's own credentials) and Arvaken's
    test endpoint, with no key. Each second is kept by when, on the agent's clock, whether both worked, and the first
    error's code (never a message)."""

    def __init__(self, g: Google, r: Run, clock: Clock, get: Callable[[str, dict], int] | None = None):
        self.g, self.r, self.clock, self.get = g, r, clock, get or _witness_get

    def __call__(self) -> None:
        at, found = self.clock.now() + self.r.offset, None
        try:
            self.g.call("GET", f"{STORAGE}/b/{quoted(self.r.outputs['Bucket'])}?fields=name")
        except GoogleError as e:
            found = f"HTTP{e.status}"
        except Exception as e:  # noqa: BLE001 - by its type alone
            found = running.unreached(e)[:64]
        if found is None:
            try:
                status = self.get(f"{ENDPOINT}/open", {"User-Agent": WITNESS_AGENT})
                found = f"HTTP{status}" if status >= 400 else None
            except urllib.error.HTTPError as e:
                found = f"HTTP{e.code}"
            except Exception as e:  # noqa: BLE001 - by its type alone
                found = type(e).__name__[:64]
        self.r.witness.append((at, found is None, found))


def service_name(copy: str, project: str, region: str) -> re.Match | None:
    """The copy's name, where it names a Cloud Run service in this project and region; else None."""
    found = SERVICE_NAME.fullmatch(copy)
    return found if found and found.group(1) == project and found.group(2) == region else None


def memory_mb(limit: str | None) -> int:
    """A container's memory limit, as Cloud Run takes one ("512Mi", "1Gi", "2G"), in the mebibytes Lambda's MB are."""
    found = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)(Ki|Mi|Gi|k|M|G)?", str(limit or ""))
    if not found:
        return DEFAULT_MB
    return int(round(float(found.group(1)) * UNITS[found.group(2) or ""]))


def serving(found: dict) -> dict:
    """The container that takes the service's calls: the one with a port, or its only one."""
    containers = (found.get("template") or {}).get("containers") or [{}]
    return next((c for c in containers if c.get("ports")), containers[0])


def all_to_latest(found: dict) -> bool:
    """Whether all the service's traffic goes to its latest revision: as it asks, so a new revision takes it all, not a
    revision named, even its latest now; and as Cloud Run serves it, to its latest ready revision."""
    asked = found.get("traffic") or [{"type": LATEST, "percent": 100}]
    if sum(t.get("percent") or 0 for t in asked if t.get("type") == LATEST) != 100:
        return False
    latest = str(found.get("latestReadyRevision") or "").rsplit("/", 1)[-1]
    served = found.get("trafficStatuses") or asked
    return sum(t.get("percent") or 0 for t in served if t.get("type") == LATEST and
               str(t.get("revision") or latest) == latest) == 100


def reads_secrets(found: dict) -> bool:
    """Whether the copy's template reads a Secret Manager secret, in a variable or a volume: Cloud Run reads it as the
    account the revision runs as, which for the test is the run's, granted none."""
    template = found.get("template") or {}
    return (any((e.get("valueSource") or {}).get("secretKeyRef") for c in template.get("containers") or []
                for e in c.get("env") or [])
            or any(v.get("secret") for v in template.get("volumes") or []))


def own_account(g: Google, found: dict) -> str:
    """The account the copy runs as before the run: its template's, or the project's default account where it names
    none, as the project's list of accounts holds it."""
    named = str((found.get("template") or {}).get("serviceAccount") or "")
    if named:
        return named
    token = None
    while True:
        page = g.call("GET", f"{IAM}/projects/{g.project}/serviceAccounts?pageSize=100"
                      + (f"&pageToken={quoted(token)}" if token else ""))
        for a in page.get("accounts") or []:
            if DEFAULT_ACCOUNT.fullmatch(str(a.get("email") or "")):
                return a["email"]
        token = page.get("nextPageToken")
        if not token:
            return ""


def read(g: Google, r: Run) -> dict:
    return g.call("GET", f"{RUN}/{r.copy}")


def settled(g: Google, r: Run, clock: Clock, settle: float = SETTLE) -> dict:
    """The copy's service once Cloud Run has finished any change to it, waited for up to `settle` seconds."""
    end = clock.now() + settle
    while True:
        found = read(g, r)
        if not found.get("reconciling") or clock.now() >= end:
            return found
        clock.sleep(2.0)


def runs_as(found: dict, account: str) -> bool:
    """Whether the copy runs as `account`: its change finished, its latest revision ready and from its template, which
    runs as `account`, and taking all its traffic."""
    template = found.get("template") or {}
    return (not found.get("reconciling") and template.get("serviceAccount") == account
            and (found.get("terminalCondition") or {}).get("state") == "CONDITION_SUCCEEDED"
            and found.get("latestReadyRevision") == found.get("latestCreatedRevision") and all_to_latest(found))


def on_the_runs_account(g: Google, r: Run, clock: Clock, settle: float) -> bool:
    """Whether the copy's template names the run's account now: a revision of it may still run as it."""
    return (settled(g, r, clock, settle).get("template") or {}).get("serviceAccount") == \
        names(r.run, r.project)["agent_account"]


def point_back_first(g: Google, r: Run, clock: Clock, wait: Callable[[str], object]) -> None:
    """At cleanup, before anything is removed: where the copy runs as the run's account, ask you to point it back to its
    own, read from it at the start of the run, before any change."""
    try:
        if on_the_runs_account(g, r, clock, 0.0):
            m = SERVICE_NAME.fullmatch(r.copy)
            wait(POINT_BACK.format(service=m.group(3), project=r.project, region=r.region, own=r.copy_account))
    except Exception:  # noqa: BLE001 - a copy the kit cannot read keeps the account: it is named for you to delete
        pass


def warm_up(g: Google, r: Run, clock: Clock, say: Callable[[str], None]) -> None:
    """The kit's warm-up on the copy (run.warm_up): where no path worked, nothing is timed."""
    running.warm_up(g, r, running.assume_or_none(g, r, clock) or {}, clock)
    if not r.working:
        say(NOTHING_WORKED)
        raise NotStarted(NOTHING_WORKED, r)
    for p in r.paths:
        if p not in r.working:
            say(running._did_not_work(r, p))


class NotStarted(Exception):
    """A run that made its things and timed nothing: why, in its words, and the run's record, its teardown done."""

    def __init__(self, said: str, r: Run):
        super().__init__(said)
        self.run = r


def run(g: Google, copy: str, stop_ref: str, *, confirm: Callable[[str], str], wait: Callable[[str], object],
        window: float = WINDOWS["google_cloud"], repeats: int = 1, clock: Clock | None = None,
        run_name: str | None = None, log_wait: float = running.LOG_WAIT, say: Callable[[str], None] = lambda _: None,
        sdk_name: str = "", read_file: Callable[[str], bytes] = lambda where: Path(where).read_bytes(),
        witness_get: Callable[[str, dict], int] | None = None,
        wait_calling: Callable[[str, Callable[[], None]], float] | None = None) -> Run:
    """A whole run on a copy of yours, torn down whatever happens. Returns the run's record. `confirm` shows its words
    and gives back what you typed; `wait` shows its words and waits for your Enter. The stop is the kit's to fire, on the
    run's account. With `sdk_name`, the stop is that in-agent SDK's switch, which you fire after your mark (`stop_ref`
    is then empty): the kit's witness calls through the window, your export is read with `read_file` afterwards, and the
    paths are judged by sdk_results. While the kit waits for your mark, the probe keeps calling once a second."""
    clock = clock or Clock()
    found = service_name(copy, g.project, g.region)
    if not found:
        raise ValueError(NOT_A_SERVICE)
    if not 1 <= repeats <= 5:
        raise ValueError("a run repeats one to five times")
    product, permissions = None, []
    the_name = run_name or new_run()
    if sdk_name:
        if stop_ref:
            raise ValueError(SDK_FIRES_NOTHING)
        if not 0 < len(sdk_name) <= result.NAME_LIMIT:
            raise ValueError(SDK_NAMED)
        if repeats != 1:
            raise ValueError("with your own trigger a run fires once: only you can take your own stop off between "
                             "repeats")
        if window < GATEWAY_WINDOW:
            raise ValueError(SDK_WINDOW_TOO_SHORT)
        product = {"kind": sdk.SDK, "attachment": sdk.ATTACHMENT, "name": sdk_name}
    else:
        reason = firing.why_not(stop_ref)
        if reason:
            raise firing.Refused(reason)            # before anything is made
        if stop_ref not in (firing.DENY_ALL, firing.DISABLE):
            permissions = firing.denied_permissions(g, stop_ref)
            if not firing.covers(permissions):
                raise firing.Refused(firing.NOT_COVERED)    # before anything is made
    own = g.call("GET", f"{RUN}/{copy}")
    if (own.get("ingress") or ALL) != ALL:
        raise firing.Refused(NOT_FROM_OUTSIDE)      # before anything is made
    if not all_to_latest(own):
        raise firing.Refused(NOT_ALL_TRAFFIC)       # before anything is made
    if reads_secrets(own):
        raise firing.Refused(NOT_SECRETS)           # before anything is made
    asked = CONFIRM_COPY_SDK if product else CONFIRM_COPY
    if confirm(asked.format(copy=copy, run=the_name)).strip() != the_name:
        raise firing.Refused(NOT_CONFIRMED)         # before anything is made
    template = own.get("template") or {}
    r = Run(run=the_name, stop_ref=stop_ref, fired_by="your own trigger" if product else "the kit", window=window,
            project=g.project, region=g.region, permissions=permissions, copy=copy, copy_account=own_account(g, own),
            outside_key=secrets.token_hex(16), product=product,
            copy_config={"runtime": "container", "memory_mb": memory_mb(((serving(own).get("resources") or {})
                                                                         .get("limits") or {}).get("memory")),
                         "private_network": bool(template.get("vpcAccess"))})
    r.began_at = clock.now()
    account = names(r.run, r.project)["agent_account"]
    try:
        r.outputs = {**identities(g, r.run, clock.sleep, copy=True), "Agent": copy, "Uri": str(own.get("uri") or "")}
        wait(POINT_AT.format(service=found.group(3), project=r.project, region=r.region, account=account))
        if not runs_as(settled(g, r, clock), account):
            said = NOT_POINTED.format(copy=copy, account=account)
            say(said)
            raise NotStarted(said, r)
        warm_up(g, r, clock, say)
        n, before = 0, r.warm_beats
        for i in range(repeats):
            if i:
                before = running.recover(g, r, clock)
            if confirm(WARNING).strip() != r.run:   # before every firing (KC4)
                say(NOT_FIRED)
                break
            if product:                             # you fire your SDK's switch after your mark; the witness calls
                ask = wait_calling or calling_while(wait, clock)
                rep = running.time_one(g, r, clock, False, n, before, mark=lambda each: ask(MARK_PROMPT, each),
                                       say=say, marked=SDK_MARKED, each_second=Witness(g, r, clock, witness_get))
            else:
                rep = running.time_one(g, r, clock, False, n, before)
            r.repeats.append(rep)
            n += sum(len(b) for b in rep.beats.values())
        if product and r.repeats:
            say(SDK_SWITCH_OFF)
        running.firing_moments(g, r, clock, wait=log_wait)
        if product and r.repeats:
            take_record(r, confirm, read_file)
            if sdk.before_the_mark(r.sdk_record, r.repeats[0].fired_after + r.offset):
                say(RECORD_BEFORE_MARK)
    except NotStarted:
        raise
    except Exception as e:  # noqa: BLE001 - said by its type alone, or the kit's words, after the teardown below
        raise Stopped(str(e) if isinstance(e, NotAToken) else type(e).__name__, r) from None
    finally:
        point_back_first(g, r, clock, wait)         # before anything is removed
        running.tear_down(g, r, clock, keep_account=lambda: on_the_runs_account(g, r, clock, SETTLE))
        name_kept(r)
        r.ended_at = clock.now()
    return r


def name_kept(r: Run) -> None:
    """The run's account, where the teardown kept it because your copy still runs as it, named as that."""
    account = names(r.run, r.project)["agent_account"]
    r.left_behind = [STILL_RUNS_AS.format(account=account, copy=r.copy) if x == f"the account {account}" else x
                     for x in r.left_behind]


def made_for_a_copy(g: Google, run: str) -> bool:
    """Whether the run's account, where it is still there, was made for a test copy of yours: by the name it was made
    with (stack.identities), as your project's list of accounts holds it."""
    account, token = names(run, g.project)["agent_account"], None
    while True:
        page = g.call("GET", f"{IAM}/projects/{g.project}/serviceAccounts?pageSize=100"
                      + (f"&pageToken={quoted(token)}" if token else ""))
        for a in page.get("accounts") or []:
            if a.get("email") == account:
                return a.get("displayName") == display_name(run, FOR_A_COPY)
        token = page.get("nextPageToken")
        if not token:
            return False


def clean(g: Google, run_name: str, copy: str, clock: Clock, settle: float = SETTLE) -> Run:
    """`stop-test google clean` for a run that was on your copy: what the run made removed as the run's own teardown
    removes it, your copy never touched, and the run's account deleted only once your copy no longer runs as it, else
    named. The account is enabled again first, in case the run had disabled it, so a copy still running as it works."""
    r = Run(run=run_name, stop_ref=firing.DISABLE, fired_by="the kit", window=0.0, project=g.project, region=g.region,
            copy=copy)
    running.tear_down(g, r, clock, keep_account=lambda: on_the_runs_account(g, r, clock, settle))
    name_kept(r)
    return r


def results(r: Run) -> list:
    """Each repeat's paths: by the founder's rule for an SDK's stop (sdk_results), or as the kit's own Google runs'."""
    return sdk_results(r) if r.product else running.results(r)


def copy_details(r: Run, doc: dict, found: list) -> dict[str, Any]:
    """What the run found, as a file beside the result that stays with you, as on Lambda, with the heartbeats that got
    no answer, as the kit's own Google runs keep them."""
    out = _copy_details(r, doc, found)
    out["heartbeats_lost"] = result.heartbeats_lost([(at + r.offset, code) for at, code in r.lost])
    return out


def the_result(r: Run, tools: list[str], model_kind: str, key=None) -> tuple[dict, dict]:
    """The run's result, stop-test-result/3, signed with a key made for it, and its details (copy_details)."""
    from arvaken_stop_test import __version__
    found = results(r)
    doc = result.build(
        kit_version=__version__, cloud="google_cloud", region=r.region, began_at=r.began_at, ended_at=r.ended_at,
        window=r.window, clock_gap_ms=int(round(abs(r.offset) * 1000)), calls=r.calls, left_behind=r.left_behind,
        stop_kind=r.stop_kind, fired_by=r.fired_by, stop_ref=r.stop_ref,
        agent={"kind": "google-cloud-run-service", "runtime": r.copy_config.get("runtime"),
               "memory_mb": r.copy_config.get("memory_mb"),
               "private_network": bool(r.copy_config.get("private_network")),
               "ref": r.copy, "role_ref": r.outputs.get("AgentAccount", "")},
        repeats=found, product=r.product, copy=copy_part(r, tools, model_kind))
    doc = result.sign(doc, key or result.new_key())
    return doc, copy_details(r, doc, found)
