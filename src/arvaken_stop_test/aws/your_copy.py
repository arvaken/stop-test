"""The stop test on a test copy of your own agent, as a Lambda function of yours (D575; mark's
docs/platform/STOP-TEST-YOUR-OWN-AGENT-DESIGN.md, sections 1 to 4). AWS first, as its section 7 orders it.

**The copy is yours.** You deploy it, with the probe (arvaken-stop-test-probe) in it, and name it by its function's
ARN, in the account and region the kit runs in, without a version or an alias: a role change reaches only the
function's unpublished version. The kit never deploys, changes or deletes it, nor its logs.

**What the kit makes** is run.py's stack without the function (stack.template, `copy`): the bucket, the second role,
and the role the copy runs as for the test (KC1), named and permitted as the kit's own test agent's role, under the
kit's boundary. A copy in a VPC of yours gets the network actions Lambda needs for its interfaces, on its own subnets
and security groups where EC2 lets a policy name them, under the boundary a run in a subnet has. You point the copy at that role for the test, with the command the kit prints, and back afterwards;
the kit checks it runs as the role before anything is timed. CloudFormation keeps the role when the stack is deleted:
the kit deletes it itself once the copy no longer runs as it, and while it still does, leaves it and names it.

**Each invocation carries the run's settings** in the kit's marker (run._invoke): the copy's environment is yours, so
the kit cannot set them there (the founder's answer, 1 November 2026: "Carry them"). The probe takes only settings
named for the run.

**Firing.** The kit fires a cloud stop itself, only on the role made for the run, as its own runs do (fire.py), and only
after the warning before every firing (KC4) and your typing the run's name. Or, for an in-agent SDK's switch (`sdk`,
its name), you fire it yourself from your mark ("Press Enter, then fire your stop."), after the same warning, and the
kit fires nothing: each path is judged by the founder's rule for it (sdk.py; D713), with the kit's witness (Witness)
calling from outside the copy through the window, and the SDK's own record of acting taken from your export afterwards.

**Before anything is made**, you confirm by typing the run's name that the copy is a test copy, not an agent whose
work matters (the terms, 2.1).

**Its result** is a stop-test-result/3 (the design's section 5; the kit's terms v5, D721; the_result): the copy's ARN,
sealed when submitted, as every identifier is; its runtime, memory and network; whose test agent it was; the kinds of
its tools and model you chose from the kit's lists, and whose clients the probe used, by kind; for an SDK's switch, the
time of the entry you chose in your SDK's record, readable, and its name and the file's SHA-256, sealed.
"""
from __future__ import annotations

import json
import re
import secrets
import threading
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

from arvaken_stop_test import result, sdk
from arvaken_stop_test.aws import fire as firing
from arvaken_stop_test.aws import run as running
from arvaken_stop_test.aws.run import Clients, Clock, NotStarted, Run
from arvaken_stop_test.aws.stack import TAG, is_model_id, names, template_body
from arvaken_stop_test.timing import GATEWAY_WINDOW, NOT_RUN, WINDOWS, PathResult

# A Lambda function's ARN, unqualified: its partition, region, account and name.
FUNCTION_ARN = re.compile(r"arn:(aws(?:-[a-z]+)*):lambda:([a-z0-9-]+):(\d{12}):function:([A-Za-z0-9_-]{1,64})")
SETTLE = 60.0           # seconds to wait for Lambda to finish a change to the copy's configuration

# The warning before every firing, as the founder approved it (D575, KC4: "the warning's words before every firing as
# drafted").
# CUSTOMER TEXT: approved by the founder as drafted, 15:58:47 UTC on 25 October 2026 (D575, KC4)
WARNING = ("Your stop may reach more than this test agent. An SDK's switch can stop every agent that uses the same "
           "account or key; host software can stop everything on the host. Type the run's name to fire it.")
# Approved by the founder in his step-4 rulings (D575's customer words): batch 1 at 00:42:35 UTC, its fills at 00:48:00
# UTC, on 2 November 2026; batch 3 for an SDK's switch, at 00:42:35 UTC, (3) as he corrected it in batch 4.
# CUSTOMER TEXT: approved by the founder, word for word, 00:42:35 UTC on 2 November 2026 (step 4, batch 1 (2))
NOT_A_FUNCTION = ("a test copy is named by its Lambda function's ARN, in the account and region the kit runs in, "
                  "without a version or an alias")
# CUSTOMER TEXT: approved by the founder, word for word, 00:48:00 UTC on 2 November 2026 (step 4, batch 1 (3), its fill)
CONFIRM_COPY = ("The kit will call {copy} once a second, with the run's settings (its bucket, its second role, and a test "
                "key made for the run, which works only with Arvaken's test address), and fire your stop on the role it "
                "makes for the run. Each call runs your copy's own code, which does whatever that code does with "
                "whatever its settings reach: databases, email, payments, other services. As the run's role, it reaches "
                "in AWS only what that role allows, but anything it reaches with its own keys or over the internet, it "
                "still reaches. Run it only on a test copy whose settings reach test systems alone, never on an agent "
                "whose work matters. AWS bills each call, and anything the copy calls, to your account. Type the run's "
                "name, {run}, to confirm {copy} is a test copy.")
# For an SDK's switch the kit fires nothing, so its words say who fires.
# CUSTOMER TEXT: approved by the founder, word for word, 01:08:36 UTC on 2 November 2026 (step 4, batch 7 (2))
CONFIRM_COPY_SDK = CONFIRM_COPY.replace("and fire your stop on the role it makes for the run",
                                        "and you fire your SDK's switch yourself, after your mark")
# CUSTOMER TEXT: approved by the founder, word for word, 00:42:35 UTC on 2 November 2026 (step 4, batch 1 (4))
NOT_CONFIRMED = "The run's name was not typed, so nothing was made."
# CUSTOMER TEXT: approved by the founder, word for word, 00:48:00 UTC on 2 November 2026 (step 4, batch 1 (1), its fill)
KMS_REFUSED = ("Your copy's settings are encrypted with your own key, which the run's role can't use, so your copy won't "
               "start as it. Nothing was made.")
# CUSTOMER TEXT: approved by the founder, word for word, 00:42:35 UTC on 2 November 2026 (step 4, batch 1 (5))
POINT_AT = ("Point your copy at the run's role for the test:\n"
            "  aws lambda update-function-configuration --region {region} --function-name {copy} --role {role}\n"
            "Then press Enter.")
# CUSTOMER TEXT: approved by the founder, word for word, 00:42:35 UTC on 2 November 2026 (step 4, batch 1 (6))
NOT_POINTED = ("Your copy {copy} does not run as the run's role {role}, so nothing was timed. The kit is removing what "
               "it made.")
# CUSTOMER TEXT: approved by the founder, word for word, 00:42:35 UTC on 2 November 2026 (step 4, batch 1 (7))
NOTHING_WORKED = "No path worked on your copy before the stop, so nothing was timed."
# CUSTOMER TEXT: approved by the founder, word for word, 00:42:35 UTC on 2 November 2026 (step 4, batch 1 (8))
NOT_FIRED = "The run's name was not typed, so the stop was not fired."
# CUSTOMER TEXT: approved by the founder, word for word, 00:42:35 UTC on 2 November 2026 (step 4, batch 1 (9))
POINT_BACK = ("Point your copy back at its own role:\n"
              "  aws lambda update-function-configuration --region {region} --function-name {copy} --role {own}\n"
              "Then press Enter, and the kit removes what it made.")
# CUSTOMER TEXT: approved by the founder, word for word, 00:42:35 UTC on 2 November 2026 (step 4, batch 1 (10))
STILL_RUNS_AS = "the role {role}, which your copy {copy} still runs as (point it back, then delete the role)"

# An in-agent SDK's stop (sdk.py; D713). The mark's own words are the gateway's, approved (run.MARK_PROMPT).
ENDPOINT = "https://stop-test.arvaken.com"   # Arvaken's test endpoint, as the probe calls it (the probe's core.ENDPOINT)
WITNESS_AGENT = "arvaken-stop-test-witness (+https://github.com/arvaken/stop-test)"
# CUSTOMER TEXT: approved by the founder, word for word, 00:42:35 UTC on 2 November 2026 (step 4, batch 3 (1))
SDK_MARKED = ("Marked. Each path is timed from your mark, so a time errs toward slower, never faster. Your SDK's record "
              "of acting is kept beside the result, as you enter it.")
# CUSTOMER TEXT: approved by the founder, word for word, 00:42:35 UTC on 2 November 2026 (step 4, batch 3 (2))
SDK_SWITCH_OFF = "The timing is done: you can turn your SDK's switch off now. The kit never turns it off itself."
# CUSTOMER TEXT: approved by the founder, word for word, 00:42:35 UTC on 2 November 2026 (step 4, batch 3 (3), as he
# corrected it in batch 4), its third sentence as he changed it by 01:28:25 UTC ("It keeps only the SHA-256 and the
# entry you name, never the file.")
SDK_EXPORT = ("Name the file you exported from your SDK that records it acting. The kit reads it to check that the entry "
              "you name is in it, and to take its SHA-256. It keeps only the SHA-256 and the entry you name, never the "
              "file. Keep the file "
              "yourself: its SHA-256 lets you show later that it's the same file:")
# CUSTOMER TEXT: approved by the founder, word for word, 00:42:35 UTC on 2 November 2026 (step 4, batch 3 (4))
SDK_ENTRY_TIME = "The time of the entry in it that records your stop, exactly as the file writes it, with its time zone:"
# CUSTOMER TEXT: approved by the founder, word for word, 00:42:35 UTC on 2 November 2026 (step 4, batch 3 (5)), with
# the words he added at 01:08:36 UTC (batch 5 (5))
SDK_ENTRY_NAME = "That entry's name, exactly as the file writes it: its kind of entry only, never who fired it."
# The kit refuses a name that holds an email address (batch 5 (5)).
# The kit asks once more for a time Arvaken's record wouldn't keep (sdk.time_fits); a second that doesn't fit is no record.
# CUSTOMER TEXT: approved by the founder, word for word, 19:00:00 UTC on 2 November 2026 ("Approve both")
TIME_DOES_NOT_FIT = ("That time is too long or has a character the kit doesn't keep. Give it again, in at most 64 "
                     "characters, with only letters, digits, spaces and . , : + / ( ) _ -.")
# CUSTOMER TEXT: approved by the founder, word for word, 17:10:07 UTC on 2 November 2026 ("Approve as written")
NAME_HOLDS_EMAIL = "That name holds an email address. Give its kind of entry only, never who fired it."
EMAIL = re.compile(r"[^\s@]+@[^\s@]+\.[^\s@]+")
# CUSTOMER TEXT: approved by the founder, word for word, 00:42:35 UTC on 2 November 2026 (step 4, batch 3 (6))
SDK_WINDOW_TOO_SHORT = "For your SDK's stop the kit times each path for at least 15 minutes after your mark."
# With a model, the kit reads CloudTrail for the copy's calls to it, under the founder's rule for its path (sdk.py,
# judge_model, approved at 17:10:07 UTC on 2 November 2026), once, 15 minutes after the window ends (sdk.TRAIL_READ).
# CUSTOMER TEXT: approved by the founder, word for word, at 17:34:43 UTC on 2 November 2026 ("Approve all seven")
SDK_MODEL_TRAIL = ("With your SDK's stop, the kit reads CloudTrail for your copy's calls to the model 15 minutes after "
                   "the window ends, so the run ends at least that long after the window does.")
# CUSTOMER TEXT: approved by the founder, word for word, at 17:34:43 UTC on 2 November 2026 ("Approve all seven")
MODEL_TRAIL_WAIT = "Reading CloudTrail for your copy's calls to the model at {time}, 15 minutes after the window ended."
PAGE_GAP = 0.5      # seconds between pages of the event history: two lookups a second, per account, per region, at
                    # most [source: aws-cloudtrail-lookup-rate]
# CUSTOMER TEXT: approved by the founder, word for word, 00:42:35 UTC on 2 November 2026 (step 4, batch 3 (8))
SDK_FIRES_NOTHING = "with your SDK's stop the kit fires nothing: you fire it yourself, after your mark"
# CUSTOMER TEXT: approved by the founder, word for word, 00:42:35 UTC on 2 November 2026 (step 4, batch 3 (9))
SDK_NAMED = "an SDK is named in 1 to 200 characters"
# The record you entered falls before your mark (batch 3 (4): "flags it if it falls before the mark").
# It blocks only that outcome: a path that kept succeeding still reads not stopped, one that succeeded after failing
# still reads stopped, then succeeded again (batch 7 (3)).
# CUSTOMER TEXT: approved by the founder, word for word, 01:08:36 UTC on 2 November 2026 (step 4, batch 7 (3))
RECORD_BEFORE_MARK = ("The time you entered for your SDK's record is before your mark, so no path reads stopped by "
                      "Arvaken's rule for an SDK's stop. Check that you entered the right entry, and that your SDK's "
                      "host keeps the right time, then run again.")

class Witness:
    """The kit's witness (D713, (3)): once a second from the mark, the kit's own calls, made from where the kit runs and
    so outside the copy and its SDK: the run's bucket (HeadBucket, as the kit's own credentials) and Arvaken's test
    endpoint, with no key. Each second is kept by when, on the agent's clock, whether both worked, and the first error's
    code (never a message)."""

    def __init__(self, c: Clients, r: Run, clock: Clock, get: Callable[[str, dict], int] | None = None):
        self.c, self.r, self.clock, self.get = c, r, clock, get or _get

    def __call__(self) -> None:
        at, found = self.clock.now() + self.r.offset, None
        try:
            self.c.s3.head_bucket(Bucket=self.r.outputs["Bucket"])
        except Exception as e:  # noqa: BLE001 - the witness's error, by its code
            found = running._code(e)
        if found is None:
            try:
                status = self.get(f"{ENDPOINT}/open", {"User-Agent": WITNESS_AGENT})
                found = f"HTTP{status}" if status >= 400 else None
            except urllib.error.HTTPError as e:
                found = f"HTTP{e.code}"
            except Exception as e:  # noqa: BLE001 - by its type alone
                found = type(e).__name__[:64]
        self.r.witness.append((at, found is None, found))


def _get(url: str, headers: dict) -> int:
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers, method="GET"), timeout=2.0) as response:
        response.read(64)
        return response.status


def take_record(r: Run, ask: Callable[[str], str], read: Callable[[str], bytes]) -> None:
    """The SDK's own record that it acted (D713, (2)), from your export: the file you name, read only for its SHA-256,
    and the entry's time and name as you type them. A file the kit cannot read is no record."""
    where = ask(SDK_EXPORT).strip()
    if not where:
        return
    try:
        export = read(where)
    except Exception:  # noqa: BLE001 - no record: the paths read not measured, and say so
        return
    time = ask(SDK_ENTRY_TIME).strip()
    if not sdk.time_fits(time):             # as Arvaken's record keeps it (the founder's answer, 19:00:00 UTC)
        time = ask(TIME_DOES_NOT_FIT).strip()
        if not sdk.time_fits(time):
            return
    name = ask(SDK_ENTRY_NAME)
    if EMAIL.search(name):                  # its kind of entry only, never who fired it (batch 5 (5))
        name = ask(NAME_HOLDS_EMAIL)
        if EMAIL.search(name):
            return
    r.sdk_record = sdk.record(export, time, name)


def runtime_of(own: dict[str, Any]) -> str | None:
    """The copy's runtime, as its result keeps it (4.4): its function's runtime, or "container" for one built from a
    container image, which has none (the founder's answer at 19:00:00 UTC on 2 November 2026, as on AgentCore)."""
    return own.get("Runtime") or ("container" if own.get("PackageType") == "Image" else None)


def clients_of(seen: dict[str, set[str]]) -> dict[str, str]:
    """Whose clients the probe used, by kind (KC2, "Each kind apart"), in the result's words: yours only where every
    reply of the run said so; else the runtime's."""
    return {kind: result.CLIENTS[0] if seen.get(kind) == {"customer"} else result.CLIENTS[1]
            for kind in result.SHAPE_V3["agent.clients"]}


def copy_part(r: Any, tools: list[str], model_kind: str) -> dict[str, Any]:
    """What a version-3 result adds for a copy of yours (result.build's `copy`): its tools' and model's kinds as you
    chose them, its clients by kind, and for an SDK's switch your SDK's own record, its file never."""
    rec = r.sdk_record
    mark = (r.repeats[0].fired_after + r.offset) if r.repeats and r.repeats[0].fired_after else None
    return {"tools": list(tools), "model_kind": model_kind, "clients": clients_of(r.clients),
            "record": None if rec is None else {
                "time": rec.time, "entered_by_you": True, "before_mark": mark is not None and sdk.before_the_mark(rec, mark),
                "name": rec.name, "sha256": rec.sha256}}


def copy_details(r: Any, doc: dict, found: list[tuple[float | None, dict[str, PathResult]]]) -> dict[str, Any]:
    """What the run found, as a file beside the result that stays with you: each path's outcome and why, its time to
    effect, and each failure's record; what the teardown checked; and for an SDK's switch, the kit's witness."""
    out = {"format": "stop-test-details/1", "run": r.run, "result_signature": doc["signature"],
           "stop_kind": r.stop_kind, "window_seconds": r.window, "left_behind": r.left_behind,
           "checked_gone": r.checked_gone, "clients": clients_of(r.clients),
           **({"served": dict(r.served)} if getattr(r, "served", None) else {}),     # AgentCore: endpoint, version
           "repeats": [{p: {"outcome": f.outcome, "reason": f.reason, "fired_source": f.fired_source,
                            "effect_between_seconds": list(f.effect_between) if f.effect_between else None,
                            "first_refused": result.iso(f.first_failure_after),
                            "last_success": result.iso(f.last_success_after), "tries_after": f.tries_after,
                            "failures_after": f.failures_after, "errors": f.errors,
                            "failures": result.failure_records(f)} for p, f in paths.items()}
                       for _, paths in found]}
    if r.product:
        out["witness"] = {"calls": len(r.witness),
                          "failed": [{"at": result.iso(at), "code": code} for at, ok, code in r.witness if not ok]}
        rec, mark = r.sdk_record, (r.repeats[0].fired_after + r.offset) if r.repeats else None
        out["sdk_record"] = None if rec is None else {      # its time as you entered it, flagged before the mark
            "time": rec.time, "entered_by_you": True, "in_file": rec.in_file,
            "before_mark": mark is not None and sdk.before_the_mark(rec, mark)}
        if r.model:                                         # what CloudTrail held of the copy's calls to the model
            trail = r.model_trail or []
            out["model_trail"] = {"read": r.model_trail is not None, "error": r.model_trail_error,
                                  "calls": [{"at": result.iso(at), "code": code} for at, code in trail]}
    return out


def the_result(r: Run, tools: list[str], model_kind: str, key=None) -> tuple[dict, dict]:
    """The run's result, stop-test-result/3, signed with a key made for it, and its details (copy_details)."""
    from arvaken_stop_test import __version__
    found = sdk_results(r) if r.product else running.results(r)
    doc = result.build(
        kit_version=__version__, cloud="aws", region=r.region, began_at=r.began_at, ended_at=r.ended_at,
        window=r.window, clock_gap_ms=int(round(abs(r.offset) * 1000)), calls=r.calls, left_behind=r.left_behind,
        stop_kind=r.stop_kind, fired_by=r.fired_by, stop_ref=r.stop_ref,
        agent={"kind": "aws-lambda-function", "runtime": r.copy_config.get("runtime"),
               "memory_mb": r.copy_config.get("memory_mb"), "private_network": bool(r.copy_config.get("private_network")),
               "ref": r.copy, "role_ref": r.outputs.get("AgentRole", "")},
        repeats=found, product=r.product, copy=copy_part(r, tools, model_kind))
    doc = result.sign(doc, key or result.new_key())
    return doc, copy_details(r, doc, found)


def sdk_results(r: Run) -> list[tuple[float | None, dict[str, PathResult]]]:
    """Each repeat's paths under D713, as the founder's step-4 rulings have it (sdk.judge): each timed from the mark;
    the record and the witness as (2) and (3) have them; a model's call by its own rule, with CloudTrail's record of the
    copy's calls to it beside the probe's (sdk.judge_model)."""
    out = []
    for rep in r.repeats:
        if not rep.fired_after:
            out.append((None, {p: PathResult(NOT_RUN, r.window, reason="the stop was not fired") for p in r.paths}))
            continue
        mark, rec = rep.fired_after + r.offset, r.sdk_record
        record_why = sdk.record_reason(rec, mark, r.window)
        witness_why = sdk.witness_reason(r.witness, mark, mark + r.window)
        found = {}
        for p in r.paths:
            beats = rep.beats.get(p, [])
            before = [b for b in beats if b.at <= mark]
            rule = dict(mark_at=mark, window=r.window, worked_before=p in r.working and bool(before) and before[-1].ok,
                        record_at=rec.at if rec is not None else None, record_why=record_why,
                        witness_why=witness_why, setup_errors=r.setup_errors.get(p))
            if p == running.MODEL:
                found[p] = sdk.judge_model(beats, trail=r.model_trail, trail_error=r.model_trail_error, **rule)
            else:
                found[p] = sdk.judge(beats, **rule)
        out.append((mark, found))
    return out


def function_arn(copy: str, region: str, account: str) -> re.Match | None:
    """The copy's ARN, where it names a function in this account and region, unqualified; else None."""
    found = FUNCTION_ARN.fullmatch(copy)
    return found if found and found.group(2) == region and found.group(3) == account else None


def configuration(c: Clients, r: Run, clock: Clock, settle: float = SETTLE) -> dict[str, Any]:
    """The copy's configuration once Lambda has finished any change to it, waited for up to `settle` seconds."""
    end = clock.now() + settle
    while True:
        found = c.lambda_.get_function_configuration(FunctionName=r.copy)
        if found.get("LastUpdateStatus") != "InProgress" or clock.now() >= end:
            return found
        clock.sleep(2.0)


def runs_as(c: Clients, r: Run, role_arn: str, clock: Clock, settle: float = SETTLE) -> bool:
    """Whether the copy runs as `role_arn`, Lambda's last change to it finished and Successful (batch 1 (5): "the kit
    waits until the copy's update has completed (LastUpdateStatus Successful) and confirms the copy runs as {role}")."""
    found = configuration(c, r, clock, settle)
    return found.get("Role") == role_arn and found.get("LastUpdateStatus") == "Successful"


def on_the_runs_role(c: Clients, r: Run, clock: Clock, settle: float) -> bool:
    """Whether the copy runs as the run's role now, by the role's name: one CloudFormation kept from a stack that never
    finished is the run's too."""
    return str(configuration(c, r, clock, settle).get("Role", "")).endswith(f":role/{names(r.run)['agent_role']}")


def deploy(c: Clients, r: Run, clock: Clock, network: dict) -> None:
    """The run's stack for a copy: no function; the role the copy runs as, kept when the stack is deleted; with the
    copy's VpcConfig (`network`), Lambda's network actions on the copy's own subnets and security groups."""
    n = names(r.run)
    c.cloudformation.create_stack(StackName=n["stack"],
                                  TemplateBody=template_body(r.run, "", model=r.model, copy=r.copy, network=network),
                                  Capabilities=["CAPABILITY_NAMED_IAM"], Tags=[{"Key": TAG, "Value": r.run}])
    found = running._wait_for_stack(c.cloudformation, n["stack"], clock, "CREATE_COMPLETE")
    r.outputs = {o["OutputKey"]: o["OutputValue"] for o in (found or {}).get("Outputs", [])}


def point_back_first(c: Clients, r: Run, clock: Clock, wait: Callable[[str], object]) -> None:
    """At cleanup, before anything is removed (batch 1 (6)): where the copy runs as the run's role, ask you to point it
    back to its own, read from it at the start of the run, before any change (batch 1 (9))."""
    try:
        if on_the_runs_role(c, r, clock, 0.0):
            wait(POINT_BACK.format(region=c.region, copy=r.copy, own=r.copy_role))
    except Exception:  # noqa: BLE001 - a copy the kit cannot read keeps the role: it is named for you to delete
        pass


def remove_the_runs_role(c: Clients, r: Run, clock: Clock) -> Callable[[], None]:
    """What the teardown does once the stack is deleted: the run's role, its own policies first, deleted only where the
    copy no longer runs as it. The kit never deletes a role the copy still runs as: it detaches the stop and leaves the
    role, named (batch 1 (10))."""
    role = names(r.run)["agent_role"]

    def after_stack() -> None:
        try:
            if on_the_runs_role(c, r, clock, SETTLE):
                return                          # left, and named by what the teardown checks
            for name in c.iam.list_role_policies(RoleName=role).get("PolicyNames", []):
                c.iam.delete_role_policy(RoleName=role, PolicyName=name)
            for a in c.iam.list_attached_role_policies(RoleName=role).get("AttachedPolicies", []):
                c.iam.detach_role_policy(RoleName=role, PolicyArn=a["PolicyArn"])
            c.iam.delete_role(RoleName=role)
        except Exception:  # noqa: BLE001 - a role not deleted is named by what the teardown checks
            pass
    return after_stack


def boundary_allows(network: bool, model: bool, action: str) -> bool:
    """Whether the run's roles' boundary, as the kit gives it, allows an action at all."""
    from arvaken_stop_test.aws.stack import boundary_document
    for s in boundary_document(network, model)["Statement"]:
        actions = s["Action"] if isinstance(s["Action"], list) else [s["Action"]]
        if s["Effect"] == "Allow" and any(a in (action, "*", action.split(":")[0] + ":*") for a in actions):
            return True
    return False


def run(c: Clients, copy: str, stop_ref: str, *, confirm: Callable[[str], str], wait: Callable[[str], object],
        window: float = WINDOWS["aws"], repeats: int = 1, clock: Clock | None = None, run_name: str | None = None,
        trail_wait: float = running.TRAIL_WAIT, say: Callable[[str], None] = lambda _: None, model: str = "",
        sdk_name: str = "", read: Callable[[str], bytes] = lambda where: Path(where).read_bytes(),
        witness_get: Callable[[str, dict], int] | None = None,
        wait_calling: Callable[[str, Callable[[], None]], float] | None = None) -> Run:
    """A whole run on a copy of yours, torn down whatever happens. Returns the run's record. `confirm` shows its words
    and gives back what you typed; `wait` shows its words and waits for your Enter. The stop is the kit's to fire, on the
    run's role; with `model`, the probe also calls it, as a fifth path. With `sdk_name`, the stop is that in-agent SDK's
    switch, which you fire after your mark (`stop_ref` is then empty): the kit's witness calls through the window, your
    export is read with `read` afterwards, and the paths are judged by sdk_results, the model's with CloudTrail's
    record of the copy's calls to it, read after the teardown (model_calls). While the kit waits for your mark, the
    probe keeps calling once a second (`wait_calling`; calling_while by default)."""
    from arvaken_stop_test.aws.stack import new_run
    clock = clock or Clock()
    caller = c.sts.get_caller_identity()
    reason = firing.why_not_aws(caller)
    if reason:
        raise firing.Refused(reason)                # before anything is made
    account = caller["Account"]
    if not function_arn(copy, c.region, account):
        raise ValueError(NOT_A_FUNCTION)
    if model and not is_model_id(model):
        raise ValueError("a model is named by a Bedrock model's ID or an inference profile's")
    if not 1 <= repeats <= 5:
        raise ValueError("a run repeats one to five times")
    product = None
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
        if stop_ref not in (firing.REVOKE, firing.INLINE) and not firing.covers(c.iam, stop_ref, the_name):
            raise firing.Refused(firing.NOT_COVERED)    # before anything is made
    own = c.lambda_.get_function_configuration(FunctionName=copy)
    network = bool((own.get("VpcConfig") or {}).get("SubnetIds"))
    if own.get("KMSKeyArn") and not boundary_allows(network, bool(model), "kms:Decrypt"):
        raise firing.Refused(KMS_REFUSED)           # before anything is made (batch 1 (1))
    reason = firing.why_no_boundary(c.iam, c.sts, network=network, model=bool(model))
    if reason:
        raise firing.Refused(reason)                # before anything is made
    asked = CONFIRM_COPY_SDK if product else CONFIRM_COPY
    if confirm(asked.format(copy=copy, run=the_name)).strip() != the_name:
        raise firing.Refused(NOT_CONFIRMED)         # before anything is made
    r = Run(run=the_name, stop_ref=stop_ref, fired_by="your own trigger" if product else "the kit", window=window,
            region=c.region, model=model, copy=copy, copy_role=str(own.get("Role", "")),
            outside_key=secrets.token_hex(16), product=product,
            copy_config={"runtime": runtime_of(own), "memory_mb": own.get("MemorySize"),
                         "private_network": network})
    r.began_at = clock.now()
    try:
        deploy(c, r, clock, own.get("VpcConfig") or {})
        wait(POINT_AT.format(region=c.region, copy=copy, role=r.outputs.get("AgentRole", "")))
        if not runs_as(c, r, r.outputs.get("AgentRole", ""), clock):
            said = NOT_POINTED.format(copy=copy, role=r.outputs.get("AgentRole", ""))
            say(said)
            raise NotStarted(said, r)
        warm_up(c, r, clock, say)
        if product and model:
            say(SDK_MODEL_TRAIL)
        n, before = 0, r.warm_beats
        for i in range(repeats):
            if i:
                before = running.recover(c, r, clock)
            if confirm(WARNING).strip() != r.run:   # before every firing (KC4)
                say(NOT_FIRED)
                break
            if product:                             # you fire your SDK's switch after your mark; the witness calls
                ask = wait_calling or calling_while(wait, clock)
                rep = running.time_one(c, r, clock, False, n, before,
                                       mark=lambda each: ask(running.MARK_PROMPT, each), calling_to_the_mark=True,
                                       say=say, marked=SDK_MARKED, each_second=Witness(c, r, clock, witness_get))
            else:
                rep = running.time_one(c, r, clock, False, n, before, say=say)
            r.repeats.append(rep)
            n += sum(len(b) for b in rep.beats.values())
        if product and r.repeats:
            say(SDK_SWITCH_OFF)
        running.firing_moments(c, r, clock, wait=trail_wait)
        if product and r.repeats:
            take_record(r, confirm, read)
            if sdk.before_the_mark(r.sdk_record, r.repeats[0].fired_after + r.offset):
                say(RECORD_BEFORE_MARK)
    finally:
        point_back_first(c, r, clock, wait)         # before anything is removed (batch 1 (6) to (8))
        running.tear_down(c, r, clock, say=say, after_stack=remove_the_runs_role(c, r, clock))
        role = names(r.run)["agent_role"]
        r.left_behind = [STILL_RUNS_AS.format(role=role, copy=copy) if x == f"the role {role}" else x
                         for x in r.left_behind]
        r.ended_at = clock.now()
    if product and model and r.repeats and r.repeats[0].fired_after:
        model_calls(c, r, clock, say)
    running.own_tokens(c, r)
    return r


def calling_while(wait: Callable[[str], object], clock: Clock) -> Callable[[str, Callable[[], None]], float]:
    """Waiting for your Enter with `wait` while the kit makes a heartbeat once a second, so the minute before your mark
    holds the probe's calls (the founder's answer at 17:34:43 UTC on 2 November 2026, "Keep calling until the mark"):
    the wait in a thread of its own, the heartbeats where the kit runs. Gives back the kit's clock when you pressed
    Enter; what the wait raised, it raises."""

    def wait_calling(words: str, each_second: Callable[[], None]) -> float:
        pressed: list[float] = []
        raised: list[BaseException] = []
        done = threading.Event()

        def ask() -> None:
            try:
                wait(words)
            except BaseException as e:  # noqa: BLE001 - raised where the kit runs, below
                raised.append(e)
            pressed.append(clock.now())
            done.set()
        threading.Thread(target=ask, daemon=True).start()
        while not done.is_set():
            each_second()
            done.wait(1.0)
        if raised:
            raise raised[0]
        return pressed[0]
    return wait_calling


def model_calls(c: Clients, r: Run, clock: Clock, say: Callable[[str], None]) -> None:
    """The copy's calls to the model as CloudTrail's event history in the run's region holds them, for the model's path
    under its rule (sdk.judge_model): read once, sdk.TRAIL_READ seconds after the window ends ((6)), waited for after
    the teardown, from the minute before the mark to the window's end. Each kept by its time and its error's code alone.
    A lookup the kit can't finish leaves them unread, by the error's code, and the path not measured."""
    rep = r.repeats[0]
    due = rep.fired_after + r.window + sdk.TRAIL_READ
    if clock.now() < due:
        say(MODEL_TRAIL_WAIT.format(time=sdk._clock(due)))
        clock.sleep(due - clock.now())
    mark, role = rep.fired_after + r.offset, names(r.run)["agent_role"]
    trail = c.cloudtrail_here or c.cloudtrail
    found, token = [], None
    try:
        while True:
            page = trail.lookup_events(
                LookupAttributes=[{"AttributeKey": "EventSource", "AttributeValue": sdk.MODEL_SOURCE}],
                StartTime=mark - sdk.TRAIL_BEFORE - sdk.TRAIL_SLACK, EndTime=mark + r.window + sdk.TRAIL_LAG,
                **({"NextToken": token} if token else {}))
            for e in page.get("Events", []):
                event = json.loads(e.get("CloudTrailEvent") or "{}")
                if sdk.a_model_call(event, role):
                    found.append((running._seconds_of(e["EventTime"]), event.get("errorCode")))
            token = page.get("NextToken")
            if not token:
                break
            clock.sleep(PAGE_GAP)
    except Exception as e:  # noqa: BLE001 - a read not finished leaves the model's path not measured, by its code
        r.model_trail_error = running._code(e)
        return
    r.model_trail = sorted(found, key=lambda x: x[0])


def warm_up(c: Clients, r: Run, clock: Clock, say: Callable[[str], None]) -> None:
    """The kit's warm-up on the copy (run.warm_up): where no path worked, or the model's call did not, nothing is timed."""
    running.warm_up(c, r, running.assume_or_none(c, r, clock) or {}, clock)
    if r.model and running.MODEL not in r.working and r.working:
        said = running.MODEL_DID_NOT_WORK.format(model=r.model, codes=running._codes(r, running.MODEL),
                                                 region=c.region)
        say(said)
        raise NotStarted(said, r)
    if not r.working:
        say(NOTHING_WORKED)
        raise NotStarted(NOTHING_WORKED, r)
    for p in r.paths:
        if p not in r.working:
            say(running._did_not_work(r, p))
