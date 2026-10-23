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


def _plan(args, run_name: str) -> str:
    from arvaken_stop_test.aws import fire
    from arvaken_stop_test.aws.stack import names
    n = names(run_name)
    reason = fire.why_not(args.stop) if not args.own_trigger else None
    lines = [f"Run {run_name} in {args.region}:",
             f"- creates one stack, {n['stack']}: a test agent ({n['function']}), its role and a second role, and a",
             "  bucket of its own, each tagged with the run;",
             (f"- waits for your own trigger, then times what stops; {fire.OWN_TRIGGER_WARNING.split('.')[0]}."
              if args.own_trigger else f"- attaches your stop, {args.stop}, to the test agent's role alone;"),
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
        a.add_argument("--window", type=_duration, default=WINDOW, help="time after firing, e.g. 15m (default)")
        a.add_argument("--repeats", type=int, default=1, help="1 to 5")
        a.add_argument("--region", required=True)
        a.add_argument("--run", dest="run_name", help="the run's name, if you are resuming one")
        a.add_argument("--endpoint", default=ENDPOINT, help=argparse.SUPPRESS)
    clean = aws_sub.add_parser("clean", help="remove what an interrupted run left")
    clean.add_argument("--run", dest="run_name", required=True)
    clean.add_argument("--region", required=True)
    clean.add_argument("--stop", default="")
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
    if args.action in ("plan", "run") and not args.own_trigger and not args.stop:
        p.error("--stop is required unless you use --own-trigger")
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
        running.tear_down(c, r, running.Clock())
        print("Nothing the kit made is left." if not r.left_behind else
              "Left for you to delete:\n" + "\n".join(r.left_behind))
        return 0
    print(_plan(args, run_name))
    if not args.own_trigger and fire.why_not(args.stop):
        return 1
    if args.own_trigger:
        print(fire.OWN_TRIGGER_WARNING)
    if input(f"Type {run_name} to go on: ").strip() != run_name:
        print("Nothing was made.")
        return 1
    r, doc = running.run(c, args.stop, endpoint=args.endpoint,
                         fired_by="your own trigger" if args.own_trigger else "the kit", window=args.window,
                         repeats=args.repeats, run_name=run_name, say=print)
    out = Path(f"stop-test-{run_name}.json")
    out.write_text(json.dumps(doc, indent=1, sort_keys=True), encoding="utf-8")
    Path(f"stop-test-{run_name}.html").write_text(report.page(doc, [d for _, d in running.results(r)]),
                                                  encoding="utf-8")
    print(f"Wrote {out} and its page. Nothing was sent: submitting the result is your choice.")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
