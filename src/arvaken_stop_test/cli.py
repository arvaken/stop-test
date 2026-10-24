"""The command line: `stop-test aws plan|run|clean`, and `stop-test verify` (the design's sections 2, 5 and 7; D532).

It uses your own AWS credentials, as the AWS command line would find them. It sends nothing to Arvaken. Before a run
makes anything, it shows what it will make and asks you to type the run's name; with your own trigger, it warns first
that your trigger may stop more than the test agent (D532, K4).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from arvaken_stop_test import report, result
from arvaken_stop_test.timing import HOLD, WINDOW

ENDPOINT = "https://stop-test.arvaken.com"        # Arvaken's test endpoint (D532, K3); see endpoint/ in this repository


def write(path: Path, text: str) -> None:
    """Every file the kit writes: UTF-8, with LF line endings on every platform, so a result's bytes and their SHA-256
    are the same wherever the kit ran (D536). Python's own default writes CRLF on Windows."""
    path.write_text(text, encoding="utf-8", newline="\n")


def _duration(text: str) -> float:
    text = text.strip().lower()
    if text.endswith("m"):
        return float(text[:-1]) * 60
    if text.endswith("s"):
        return float(text[:-1])
    return float(text)


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
    lines = [f"Run {run_name} in {args.region}:",
             f"- creates one stack, {n['stack']}: a test agent ({n['function']}), its role and a second role, and a",
             "  bucket of its own, each tagged with the run;",
             (f"- waits for your own trigger, then times what stops; {fire.OWN_TRIGGER_WARNING.split('.')[0]}."
              if args.own_trigger else
              "- revokes the active sessions of the test agent's role and of the role it became, both made for the "
              "run, by AWS's own policy (AWSRevokeOlderSessions);" if args.revoke_sessions else
              "- writes a policy denying every action on the test agent's role alone;" if args.inline_deny else
              f"- attaches your stop, {args.stop}, to the test agent's role alone;"),
             f"- times each path for {int(args.window)} seconds after firing, {args.repeats} time(s);",
             f"- invokes the test agent about {calls_for(args.window, args.repeats)} times;",
             "- then removes the stop it fired and everything it made, and names anything left."]
    if reason:
        lines.append(f"It will not run: {reason}.")
    return "\n".join(lines)


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
        a.add_argument("--window", type=_duration, default=WINDOW, help="time after firing, e.g. 15m (default)")
        a.add_argument("--repeats", type=int, default=1, help="1 to 5")
        a.add_argument("--region", required=True)
        a.add_argument("--run", dest="run_name", help="the run's name, if you are resuming one")
        a.add_argument("--endpoint", default=ENDPOINT, help=argparse.SUPPRESS)
    clean = aws_sub.add_parser("clean", help="remove what an interrupted run left")
    clean.add_argument("--run", dest="run_name", required=True)
    clean.add_argument("--region", required=True)
    clean.add_argument("--stop", default="", help="the policy's ARN, if the run attached your managed policy")
    verify = sub.add_parser("verify", help="check a result file's format and signature")
    verify.add_argument("file", type=Path)
    args = p.parse_args(argv)

    if args.command == "verify":
        try:
            doc = result.check(json.loads(args.file.read_text(encoding="utf-8")))
        except (result.NotAResult, ValueError) as e:
            print(f"Not a valid result: {e}", file=sys.stderr)
            return 1
        print(f"A valid {doc['format']}: unchanged since the kit wrote it. (That is all a signature shows.)")
        return 0

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
    print(_plan(args, run_name))
    stop = _stop(args)
    if not args.own_trigger and fire.why_not(stop):
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
    print(f"Wrote {out}, its page and its details. Nothing about your account was sent to Arvaken, except the address "
          "the test agent's two calls came from.")
    print(f"Your result's reference: {result.reference(doc)}. It's the SHA-256 of the result's signature.")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
