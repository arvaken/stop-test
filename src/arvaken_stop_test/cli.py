"""The command line: `stop-test aws plan|run|clean`, `stop-test agentcore plan|run|clean`, `stop-test agentcore-harness
plan|run|clean`, `stop-test google plan|run|clean`, and `stop-test verify` (the design's sections 2, 5 and 7; D532; on
AgentCore, D618).

It uses your own credentials: on AWS as the AWS command line would find them, on Google Cloud the Google Cloud CLI's
(gcloud), as Cloud Shell has them. It sends nothing to Arvaken. Before a run
makes anything, it shows what it will make and asks you to type the run's name; with your own trigger, it warns first
that your trigger may stop more than the test agent (D532, K4).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from arvaken_stop_test import report, result
from arvaken_stop_test.timing import HOLD, WINDOWS

ENDPOINT = "https://stop-test.arvaken.com"        # Arvaken's test endpoint (D532, K3); see endpoint/ in this repository


def write(path: Path, text: str) -> None:
    """Every file the kit writes: UTF-8, with LF line endings on every platform, so a result's bytes and their SHA-256
    are the same wherever the kit ran (D536). Python's own default writes CRLF on Windows."""
    path.write_text(text, encoding="utf-8", newline="\n")


def times(n: int) -> str:
    """How many times, in words: "1 time", "5 times". The kit writes no "(s)" (the founder, 29 October 2026)."""
    return "1 time" if n == 1 else f"{n} times"


def _duration(text: str) -> float:
    text = text.strip().lower()
    if text.endswith("m"):
        return float(text[:-1]) * 60
    if text.endswith("s"):
        return float(text[:-1])
    return float(text)


def _window_help(cloud: str) -> str:
    """The window's help, with the cloud's own default (timing.WINDOWS)."""
    return f"time after firing, e.g. {WINDOWS[cloud] / 60:g}m (default)"


def calls_for(window: float, repeats: int) -> int:
    """About how many times a run invokes the test agent: its warm-up, and a heartbeat a second through each window,
    its hold and its recovery. Each invocation makes two calls to the bucket and two to the test endpoint."""
    from arvaken_stop_test.aws.run import RECOVERY, WARM_UP
    return int(WARM_UP + repeats * (window + HOLD) + (repeats - 1) * RECOVERY)


def _stop(args) -> str:
    from arvaken_stop_test.aws import fire
    return fire.REVOKE if args.revoke_sessions else fire.INLINE if args.inline_deny else args.stop


def _plan(args, run_name: str) -> str:
    from arvaken_stop_test.aws import fire
    from arvaken_stop_test.aws.stack import names
    n = names(run_name)
    stop = _stop(args)
    reason = fire.why_not(stop) if not args.own_trigger else None
    if not reason and args.stop:
        from arvaken_stop_test.aws.boto import clients_for
        c = clients_for(args.region)
        if not fire.covers(c.iam, stop, run_name):
            reason = fire.NOT_COVERED.rstrip(".")
        else:
            reason = (fire.why_no_boundary(c.iam, c.sts) or "").rstrip(".") or None
    lines = [f"Run {run_name} in {args.region}:",
             f"- creates one stack, {n['stack']}: a test agent ({n['function']}), its role and a second role, and a",
             "  bucket of its own, each tagged with the run;",
             (f"- waits for your own trigger, then times what stops; {fire.OWN_TRIGGER_WARNING.split('.')[0]}."
              if args.own_trigger else
              "- revokes the active sessions of the test agent's role and of the role it became, both made for the "
              "run, by AWS's own policy (AWSRevokeOlderSessions);" if args.revoke_sessions else
              "- writes a policy denying every action on the test agent's role alone;" if args.inline_deny else
              f"- attaches your stop, {args.stop}, to the test agent's role alone;"),
             f"- times each path for {int(args.window)} seconds after firing, {times(args.repeats)};",
             f"- invokes the test agent about {calls_for(args.window, args.repeats)} times;",
             "- then removes the stop it fired and everything it made, and names anything left."]
    if reason:
        lines.append(f"It will not run: {reason}.")
    return "\n".join(lines)


def _google_stop(args) -> str:
    from arvaken_stop_test.google import fire
    return fire.DISABLE if args.disable_account else fire.DENY_ALL if args.deny_all else args.stop


def _google_plan(args, run_name: str) -> str:
    from arvaken_stop_test.google import fire
    from arvaken_stop_test.google.stack import names
    n = names(run_name, args.project)
    stop = _google_stop(args)
    reason = fire.why_not(stop) if not args.own_trigger else None
    if not reason and args.stop:
        from arvaken_stop_test.google.api import Google
        if not fire.covers(fire.denied_permissions(Google(args.project, args.region), stop)):
            reason = fire.NOT_COVERED.rstrip(".")
    lines = [f"Run {run_name} in {args.project}, {args.region}:",
             f"- creates a test agent, the Cloud Run service {n['service']}, running as its own service account",
             f"  {n['agent_account']}; a second account {n['second_account']}; and a bucket {n['bucket']};",
             (f"- waits for your own trigger, then times what stops; {fire.OWN_TRIGGER_WARNING.split(':')[0]}."
              if args.own_trigger else
              "- disables the test agent's own service account, and enables it again between repeats;"
              if args.disable_account else
              f"- makes a deny policy, {n['deny_policy']}, naming the test agent's account alone and denying "
              + ("what its paths use (Cloud Storage and IAM);" if args.deny_all else
                 f"what your deny policy {args.stop} denies; yours is read, never changed;")),
             f"- times each path for {int(args.window)} seconds after firing, {times(args.repeats)};",
             f"- calls the test agent about {calls_for(args.window, args.repeats)} times;",
             "- then removes the stop it fired and everything it made, and names anything left."]
    if reason:
        lines.append(f"It will not run: {reason}.")
    return "\n".join(lines)


def _google(args, p) -> int:
    from arvaken_stop_test.google import fire
    from arvaken_stop_test.google import run as running
    from arvaken_stop_test.google.api import Google
    from arvaken_stop_test.google.stack import new_run
    if args.action in ("plan", "run"):
        if sum((bool(args.stop), args.own_trigger, args.deny_all, args.disable_account)) != 1:
            p.error("give one of --stop, --deny-all, --disable-account or --own-trigger")
    run_name = args.run_name or new_run()
    if args.action == "plan":
        print(_google_plan(args, run_name))
        return 0
    g = Google(args.project, args.region)
    if args.action == "clean":
        r = running.Run(run=run_name, stop_ref=fire.DENY_ALL, fired_by="the kit", window=0.0, project=args.project,
                        region=args.region)
        running.tear_down(g, r, running.Clock())
        print("Nothing the kit made is left." if not r.left_behind else
              "Left for you to delete:\n" + "\n".join(r.left_behind))
        return 0
    plan = _google_plan(args, run_name)
    print(plan)
    stop = _google_stop(args)
    if not args.own_trigger and "It will not run:" in plan:
        return 1
    if args.own_trigger:
        print(fire.OWN_TRIGGER_WARNING)
    if input(f"Type {run_name} to go on: ").strip() != run_name:
        print("Nothing was made.")
        return 1
    r, doc = running.run(g, stop, endpoint=args.endpoint,
                         fired_by="your own trigger" if args.own_trigger else "the kit", window=args.window,
                         repeats=args.repeats, run_name=run_name, say=print)
    out = Path(f"stop-test-{run_name}.json")
    write(out, json.dumps(doc, indent=1, sort_keys=True))
    write(Path(f"stop-test-{run_name}.html"), report.page(doc, [d for _, d in running.results(r)]))
    write(Path(f"stop-test-{run_name}-details.json"), json.dumps(running.details(r, doc), indent=1))
    print(f"Wrote {out}, its page and its details. Nothing about your project was sent to Arvaken.")
    print(f"Your result's reference: {result.reference(doc)}. It's the SHA-256 of the result's signature.")
    return 0


# On AgentCore (agentcore/; D618): the plan's lines, each kind's, and what is said once the result is written.
# CUSTOMER TEXT: approved by the founder, 04:44 UTC on 28 October 2026 (D618)
AGENTCORE_STOPS = {
    "attached": "- attaches your stop, {stop}, to the test agent's role alone;",
    "inline": "- writes a policy denying every action on the test agent's role alone;",
    "deny": "- writes a resource policy on the test agent denying every call to it, from anyone;",
    "deny_and_end": ("- writes a resource policy on the test agent denying every call to it, from anyone, then ends "
                     "the session the test agent is running;"),
}
# CUSTOMER TEXT: approved by the founder, 04:44 UTC on 28 October 2026 (D618)
AGENTCORE_PLAN = (
    "Run {run} in {region}, on AgentCore:\n"
    "- creates a test agent, the AgentCore runtime {runtime}, from the kit's own code; its role and a second role; and "
    "a bucket of its own, {bucket}, each tagged with the run;\n"
    "{trail}"
    "{stop}\n"
    "- before each stop, opens a session of the test agent's and watches what it can reach, and calls the test agent "
    "about once a second, each call starting a session of its own;\n"
    "- times each path for {window} seconds after firing, {repeats};\n"
    "- calls the test agent about {calls} times. AWS bills each session's use to your account;\n"
    "- then removes the stop it fired and everything it made, and names anything left.")
# CUSTOMER TEXT: approved by the founder, 04:44 UTC on 28 October 2026 (D618)
AGENTCORE_PLAN_TRAIL = (
    "- creates a CloudTrail trail of its own, {trail}, recording only the test agent's data events, and its bucket "
    "{bucket}. Before deleting them, it copies their records beside the result, with the SHA-256 of each;\n")
# CUSTOMER TEXT: approved by the founder, 04:44 UTC on 28 October 2026 (D618)
AGENTCORE_KEPT = "The trail's records are in {folder}, each with its SHA-256 in {folder}/SHA256SUMS."
# CUSTOMER TEXT: approved by the founder, 04:44 UTC on 28 October 2026 (D618)
AGENTCORE_HELP = {
    "stop": "your declared stop: a managed policy's ARN, attached to the test agent's role",
    "inline_deny": "the stop is a policy written on the test agent's role, denying every action",
    "deny_calls": "the stop is a resource policy on the test agent, denying every call to it",
    "deny_calls_and_end_sessions": ("the stop is a resource policy on the test agent, denying every call to it, and "
                                    "ending the session it is running"),
    "trail": ("make a CloudTrail trail of the run's own for the test agent's data events, so that ending a session is "
              "timed from CloudTrail's record; its records are kept beside the result"),
}


# CUSTOMER TEXT: approved by the founder, with his edits, 29 October 2026 (the harness module's words, ruling 1)
HARNESS_PLAN = (
    "Run {run} in {region}, on an AgentCore harness:\n"
    "- creates a test agent, the AgentCore harness {harness}, which calls the model {model} and has no tools; its "
    "role; a second role it is allowed to take on, to time work done under another identity; and a bucket of its own, "
    "{bucket}, for its test calls; each tagged with the run;\n"
    "- {stop}\n"
    "- from before each stop until its timing ends, keeps a session of the test agent's open and tries each path it "
    "has about once a second, including asking its model; and starts a new session about once a second, running a "
    "command that does nothing, to time when new sessions are refused;\n"
    "- times each path for {window} seconds after firing, {repeats};\n"
    "- calls the model about {turns} times and starts about {sessions} sessions. AWS bills each call to the model and "
    "each session's use to your account. A call refused for a limit on your account is never counted as stopped;\n"
    "- changes nothing else in your account;\n"
    "- then takes the stop off the test agent's role, removes everything it made, and names anything left.")
# What the plan says is fired, and where (his ruling 1, condition c).
# CUSTOMER TEXT: approved by the founder, 29 October 2026 (ruling 1, condition c; "inline" in his words, the next round)
HARNESS_STOPS = {
    "attached": "attaches your stop {stop} to the test agent's role, and to nothing else;",
    "inline": "puts a policy on the test agent's role that denies the role every action, and puts it on nothing else;",
}
# CUSTOMER TEXT: approved by the founder, 29 October 2026 (the harness module's words, ruling 1)
HARNESS_HELP = {
    "command": "the stop test on a harness in Amazon Bedrock AgentCore",
    "model": "the harness's model: a Bedrock model ID or inference profile ID",
}


def _harness_plan(args, run_name: str) -> str:
    from arvaken_stop_test.agentcore import fire
    from arvaken_stop_test.agentcore import harness
    from arvaken_stop_test.agentcore.run import LEAD, RECOVERED
    n, stop = harness.harness_names(run_name), fire.INLINE if args.inline_deny else args.stop
    reason = fire.why_not(stop) or (None if harness.MODEL_ID.fullmatch(args.model or "") else harness.NOT_A_MODEL)
    if not reason:
        from arvaken_stop_test.agentcore.boto import clients_for
        c = clients_for(args.region)
        if args.stop and not fire.covers(c.iam, stop, run_name):
            from arvaken_stop_test.aws.fire import NOT_COVERED
            reason = NOT_COVERED.rstrip(".")
        else:
            reason = (harness.why_no_boundary(c.iam, c.sts) or "").rstrip(".") or None
    watched = args.repeats * (args.window + HOLD + LEAD)
    plan = HARNESS_PLAN.format(
        run=run_name, region=args.region, harness=n["harness"], model=args.model, bucket=n["bucket"],
        stop=HARNESS_STOPS["inline" if stop == fire.INLINE else "attached"].format(stop=stop),
        window=int(args.window), repeats=times(args.repeats),
        turns=int(watched / harness.TURN_EVERY + (args.repeats - 1) * RECOVERED + 1),
        sessions=int(watched + args.repeats + 2))
    return plan + (f"\nIt will not run: {reason}." if reason else "")


def _harness(args, p) -> int:
    from arvaken_stop_test.agentcore import fire
    from arvaken_stop_test.agentcore import harness
    from arvaken_stop_test.aws.stack import new_run
    if args.action in ("plan", "run") and sum((bool(args.stop), args.inline_deny)) != 1:
        # CUSTOMER TEXT: approved by the founder, with his edit, 29 October 2026 (ruling 1)
        p.error("give one of --stop or --inline-deny, not both")
    run_name = args.run_name or new_run()
    if args.action == "plan":
        print(_harness_plan(args, run_name))
        return 0
    from arvaken_stop_test.agentcore.boto import clients_for
    c = clients_for(args.region)
    if args.action == "clean":
        caller = c.sts.get_caller_identity()
        r = harness.HarnessRun(run=run_name, stop_ref=args.stop or fire.INLINE, window=0.0, region=args.region,
                               account=caller["Account"], partition=caller["Arn"].split(":")[1])
        try:
            fire.remove(c.iam, c.control, run_name, fire.INLINE, None)
        except Exception:  # noqa: BLE001 - a role already gone has no stop on it
            pass
        harness.tear_down(c, r, harness.Clock(), say=print)
        print("Nothing the kit made is left." if not r.left_behind else
              "Left for you to delete:\n" + "\n".join(r.left_behind))
        return 0
    plan = _harness_plan(args, run_name)
    print(plan)
    if "It will not run:" in plan:
        return 1
    if input(f"Type {run_name} to go on: ").strip() != run_name:
        print("Nothing was made.")
        return 1
    try:
        r, doc = harness.run(c, fire.INLINE if args.inline_deny else args.stop, endpoint=args.endpoint,
                             model=args.model, window=args.window, repeats=args.repeats, run_name=run_name, say=print)
    except harness.NotStarted as e:     # said with why; then what the teardown left, as `clean` says it
        print(str(e))
        print("Nothing the kit made is left." if not e.run.left_behind else
              "Left for you to delete:\n" + "\n".join(e.run.left_behind))
        return 1
    out = Path(f"stop-test-{run_name}.json")
    write(out, json.dumps(doc, indent=1, sort_keys=True))
    write(Path(f"stop-test-{run_name}.html"), report.page(doc, [d for _, d in harness.results(r)]))
    write(Path(f"stop-test-{run_name}-details.json"), json.dumps(harness.details(r, doc), indent=1))
    print(f"Wrote {out}, its page and its details. Nothing about your account was sent to Arvaken.")
    print(f"Your result's reference: {result.reference(doc)}. It's the SHA-256 of the result's signature.")
    return 0


def _agentcore_stop(args) -> str:
    from arvaken_stop_test.agentcore import fire
    return (fire.INLINE if args.inline_deny else fire.DENY if args.deny_calls else
            fire.DENY_AND_END if args.deny_calls_and_end_sessions else args.stop)


def _agentcore_plan(args, run_name: str) -> str:
    from arvaken_stop_test.agentcore import fire, trail
    from arvaken_stop_test.agentcore.run import LEAD
    from arvaken_stop_test.agentcore.stack import names
    n, stop = names(run_name), _agentcore_stop(args)
    which = ("inline" if stop == fire.INLINE else "deny" if stop == fire.DENY else
             "deny_and_end" if stop == fire.DENY_AND_END else "attached")
    reason = fire.why_not(stop)
    if not reason and args.stop:
        from arvaken_stop_test.agentcore.boto import clients_for
        from arvaken_stop_test.aws.fire import NOT_COVERED, why_no_boundary
        c = clients_for(args.region)
        if not fire.covers(c.iam, stop, run_name):
            reason = NOT_COVERED.rstrip(".")
        else:
            reason = (why_no_boundary(c.iam, c.sts) or "").rstrip(".") or None
    t = trail.names(run_name)
    plan = AGENTCORE_PLAN.format(
        run=run_name, region=args.region, runtime=n["runtime"], bucket=n["bucket"],
        trail=AGENTCORE_PLAN_TRAIL.format(trail=t["trail"], bucket=t["bucket"]) if args.trail else "",
        stop=AGENTCORE_STOPS[which].format(stop=stop), window=int(args.window), repeats=times(args.repeats),
        calls=int(args.repeats * (args.window + HOLD + LEAD)))
    return plan + (f"\nIt will not run: {reason}." if reason else "")


def _agentcore(args, p) -> int:
    from arvaken_stop_test.agentcore import fire
    from arvaken_stop_test.agentcore import run as running
    from arvaken_stop_test.aws.stack import new_run
    if args.action in ("plan", "run"):
        if sum((bool(args.stop), args.inline_deny, args.deny_calls, args.deny_calls_and_end_sessions)) != 1:
            # CUSTOMER TEXT: approved by the founder, 04:44 UTC on 28 October 2026 (D618)
            p.error("give one of --stop, --inline-deny, --deny-calls or --deny-calls-and-end-sessions")
    run_name = args.run_name or new_run()
    if args.action == "plan":
        print(_agentcore_plan(args, run_name))
        return 0
    from arvaken_stop_test.agentcore.boto import clients_for
    c = clients_for(args.region)
    folder = Path(f"stop-test-{run_name}-trail")
    if args.action == "clean":
        # Every kind of stop the kit writes itself is taken off, and any trail the run made, its records kept in the
        # folder first, as a run keeps them. A managed policy of yours is named with --stop.
        caller = c.sts.get_caller_identity()
        r = running.Run(run=run_name, stop_ref=args.stop or fire.INLINE, window=0.0, region=args.region,
                        account=caller["Account"], partition=caller["Arn"].split(":")[1], trail=True)
        running.runtime_id(c, r)
        for written in (fire.INLINE, fire.DENY):
            try:
                fire.remove(c.iam, c.control, run_name, written, r.outputs.get("Runtime"))
            except Exception:  # noqa: BLE001 - a role or runtime already gone has no stop on it
                pass
        running.tear_down(c, r, running.Clock(), trail_folder=folder, say=print)
        if (r.trail_kept or {}).get("files"):
            print(AGENTCORE_KEPT.format(folder=folder.as_posix()))
        print("Nothing the kit made is left." if not r.left_behind else
              "Left for you to delete:\n" + "\n".join(r.left_behind))
        return 0
    plan = _agentcore_plan(args, run_name)
    print(plan)
    if "It will not run:" in plan:
        return 1
    if input(f"Type {run_name} to go on: ").strip() != run_name:
        print("Nothing was made.")
        return 1
    try:
        r, doc = running.run(c, _agentcore_stop(args), endpoint=args.endpoint, window=args.window,
                             repeats=args.repeats, run_name=run_name, trail=args.trail, trail_folder=folder, say=print)
    except running.NotStarted as e:     # said with why; then what the teardown left, as `clean` says it
        print(str(e))
        print("Nothing the kit made is left." if not e.run.left_behind else
              "Left for you to delete:\n" + "\n".join(e.run.left_behind))
        return 1
    out = Path(f"stop-test-{run_name}.json")
    write(out, json.dumps(doc, indent=1, sort_keys=True))
    write(Path(f"stop-test-{run_name}.html"), report.page(doc, [d for _, d in running.results(r)]))
    write(Path(f"stop-test-{run_name}-details.json"), json.dumps(running.details(r, doc), indent=1))
    print(f"Wrote {out}, its page and its details. Nothing about your account was sent to Arvaken.")
    if (r.trail_kept or {}).get("files"):
        print(AGENTCORE_KEPT.format(folder=folder.as_posix()))
    print(f"Your result's reference: {result.reference(doc)}. It's the SHA-256 of the result's signature.")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="stop-test", description="Fire your declared stop on a test agent, and time "
                                                               "what actually stops.")
    sub = p.add_subparsers(dest="command", required=True)
    aws = sub.add_parser("aws", help="the stop test on AWS")
    aws_sub = aws.add_subparsers(dest="action", required=True)
    for name in ("plan", "run"):
        a = aws_sub.add_parser(name)
        a.add_argument("--stop", default="", help="your declared stop: a managed policy's ARN")
        a.add_argument("--own-trigger", action="store_true", help="you fire your own stop; the kit watches")
        a.add_argument("--revoke-sessions", action="store_true",
                       help="the stop is revoking the active sessions of the agent's role and the role it became")
        a.add_argument("--inline-deny", action="store_true",
                       help="the stop is a policy written on the agent's role, denying every action")
        a.add_argument("--window", type=_duration, default=WINDOWS["aws"], help=_window_help("aws"))
        a.add_argument("--repeats", type=int, default=1, help="1 to 5")
        a.add_argument("--region", required=True)
        a.add_argument("--run", dest="run_name", help="the run's name, if you are resuming one")
        a.add_argument("--endpoint", default=ENDPOINT, help=argparse.SUPPRESS)
    clean = aws_sub.add_parser("clean", help="remove what an interrupted run left")
    clean.add_argument("--run", dest="run_name", required=True)
    clean.add_argument("--region", required=True)
    clean.add_argument("--stop", default="", help="the policy's ARN, if the run attached your managed policy")
    # CUSTOMER TEXT: approved by the founder, 04:44 UTC on 28 October 2026 (D618)
    agentcore = sub.add_parser("agentcore", help="the stop test on an agent in Amazon Bedrock AgentCore")
    agentcore_sub = agentcore.add_subparsers(dest="action", required=True)
    for name in ("plan", "run"):
        a = agentcore_sub.add_parser(name)
        a.add_argument("--stop", default="", help=AGENTCORE_HELP["stop"])
        a.add_argument("--inline-deny", action="store_true", help=AGENTCORE_HELP["inline_deny"])
        a.add_argument("--deny-calls", action="store_true", help=AGENTCORE_HELP["deny_calls"])
        a.add_argument("--deny-calls-and-end-sessions", action="store_true",
                       help=AGENTCORE_HELP["deny_calls_and_end_sessions"])
        a.add_argument("--trail", action="store_true", help=AGENTCORE_HELP["trail"])
        a.add_argument("--window", type=_duration, default=WINDOWS["aws"], help=_window_help("aws"))
        a.add_argument("--repeats", type=int, default=1, help="1 to 5")
        a.add_argument("--region", required=True)
        a.add_argument("--run", dest="run_name", help="the run's name, if you are resuming one")
        a.add_argument("--endpoint", default=ENDPOINT, help=argparse.SUPPRESS)
    aclean = agentcore_sub.add_parser("clean", help="remove what an interrupted run left")
    aclean.add_argument("--run", dest="run_name", required=True)
    aclean.add_argument("--region", required=True)
    aclean.add_argument("--stop", default="", help="the policy's ARN, if the run attached your managed policy")
    harness = sub.add_parser("agentcore-harness", help=HARNESS_HELP["command"])
    harness_sub = harness.add_subparsers(dest="action", required=True)
    for name in ("plan", "run"):
        a = harness_sub.add_parser(name)
        a.add_argument("--stop", default="", help=AGENTCORE_HELP["stop"])
        a.add_argument("--inline-deny", action="store_true", help=AGENTCORE_HELP["inline_deny"])
        a.add_argument("--model", required=True, help=HARNESS_HELP["model"])
        a.add_argument("--window", type=_duration, default=WINDOWS["aws"], help=_window_help("aws"))
        a.add_argument("--repeats", type=int, default=1, help="1 to 5")
        a.add_argument("--region", required=True)
        a.add_argument("--run", dest="run_name", help="the run's name, if you are resuming one")
        a.add_argument("--endpoint", default=ENDPOINT, help=argparse.SUPPRESS)
    hclean = harness_sub.add_parser("clean", help="remove what an interrupted run left")
    hclean.add_argument("--run", dest="run_name", required=True)
    hclean.add_argument("--region", required=True)
    hclean.add_argument("--stop", default="", help="the policy's ARN, if the run attached your managed policy")
    google = sub.add_parser("google", help="the stop test on Google Cloud")
    google_sub = google.add_subparsers(dest="action", required=True)
    for name in ("plan", "run"):
        a = google_sub.add_parser(name)
        a.add_argument("--stop", default="", help="your declared deny policy, by its name (policies/.../denypolicies/ID)")
        a.add_argument("--deny-all", action="store_true",
                       help="the stop is a deny policy on the agent's identity, denying what its paths use")
        a.add_argument("--disable-account", action="store_true", help="the stop is disabling the agent's service account")
        a.add_argument("--own-trigger", action="store_true", help="you fire your own stop; the kit watches")
        a.add_argument("--window", type=_duration, default=WINDOWS["google_cloud"], help=_window_help("google_cloud"))
        a.add_argument("--repeats", type=int, default=1, help="1 to 5")
        a.add_argument("--project", required=True)
        a.add_argument("--region", required=True)
        a.add_argument("--run", dest="run_name", help="the run's name, if you are resuming one")
        a.add_argument("--endpoint", default=ENDPOINT, help=argparse.SUPPRESS)
    gclean = google_sub.add_parser("clean", help="remove what an interrupted run left")
    gclean.add_argument("--run", dest="run_name", required=True)
    gclean.add_argument("--project", required=True)
    gclean.add_argument("--region", required=True)
    verify = sub.add_parser("verify", help="check a result file's format and signature")
    verify.add_argument("file", type=Path)
    args = p.parse_args(argv)

    if args.command == "verify":
        try:
            doc = result.check(json.loads(args.file.read_text(encoding="utf-8")))
        except (result.NotAResult, ValueError) as e:
            print(f"Not a valid result: {e}", file=sys.stderr)
            return 1
        print(f"A valid {doc['format']}: unchanged since it was signed. That is all a signature shows: not that the kit "
              "wrote it, who ran it, or that the run was honest.")
        return 0
    if args.command == "google":
        return _google(args, p)
    if args.command == "agentcore":
        return _agentcore(args, p)
    if args.command == "agentcore-harness":
        return _harness(args, p)

    from arvaken_stop_test.aws.stack import new_run
    if args.action in ("plan", "run"):
        if sum((bool(args.stop), args.own_trigger, args.revoke_sessions, args.inline_deny)) != 1:
            p.error("give one of --stop, --revoke-sessions, --inline-deny or --own-trigger")
    run_name = args.run_name or new_run()
    if args.action == "plan":
        print(_plan(args, run_name))
        return 0
    from arvaken_stop_test.aws import fire
    from arvaken_stop_test.aws import run as running
    from arvaken_stop_test.aws.boto import clients_for
    c = clients_for(args.region)
    if args.action == "clean":
        r = running.Run(run=run_name, stop_ref=args.stop, fired_by="the kit", window=0.0, region=args.region)
        r.outputs = running.outputs_of(c, run_name)
        # The stops the kit writes itself, on the run's own roles, are taken off whichever kind the run fired: an
        # interrupted run's roles cannot be deleted with them on. A managed policy of yours is named with --stop.
        for written in (fire.INLINE, fire.REVOKE):
            try:
                fire.remove(c.iam, run_name, written)
            except Exception:  # noqa: BLE001 - a role already gone has no stop on it
                pass
        running.tear_down(c, r, running.Clock())
        print("Nothing the kit made is left." if not r.left_behind else
              "Left for you to delete:\n" + "\n".join(r.left_behind))
        return 0
    plan = _plan(args, run_name)
    print(plan)
    stop = _stop(args)
    if not args.own_trigger and "It will not run:" in plan:
        return 1
    if args.own_trigger:
        print(fire.OWN_TRIGGER_WARNING)
    if input(f"Type {run_name} to go on: ").strip() != run_name:
        print("Nothing was made.")
        return 1
    r, doc = running.run(c, stop, endpoint=args.endpoint,
                         fired_by="your own trigger" if args.own_trigger else "the kit", window=args.window,
                         repeats=args.repeats, run_name=run_name, say=print)
    out = Path(f"stop-test-{run_name}.json")
    write(out, json.dumps(doc, indent=1, sort_keys=True))
    write(Path(f"stop-test-{run_name}.html"), report.page(doc, [d for _, d in running.results(r)]))
    write(Path(f"stop-test-{run_name}-details.json"), json.dumps(running.details(r, doc), indent=1))
    print(f"Wrote {out}, its page and its details. Nothing about your account was sent to Arvaken.")
    print(f"Your result's reference: {result.reference(doc)}. It's the SHA-256 of the result's signature.")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
