"""The command line: `stop-test aws plan|run|clean`, `stop-test google plan|run|clean`, and `stop-test verify` (the
design's sections 2, 5 and 7; D532).

It uses your own credentials: on AWS as the AWS command line would find them, on Google Cloud the Google Cloud CLI's
(gcloud), as Cloud Shell has them. It sends nothing to Arvaken. Before a run
makes anything, it shows what it will make and asks you to type the run's name; with your own trigger, it warns first
that your trigger may stop more than the test agent (D532, K4).

**Through a gateway (`--via`; D561, section 5), on AWS alone in this version.** Your stop is then a product's control,
your gateway, named by how it is attached and by its name. The plan says that the test agent's calls go through it,
and, with `--subnet`, that its network interfaces are made in your subnet; the kit warns, in stronger words than for
your own trigger, that your gateway's switch may stop every agent behind it, and goes on only when you type the run's
name. It then asks you to press Enter, then fire your stop, and times each path from that mark. The gateway's address is
printed and kept as its scheme, host and port alone: never with a user name, password, path or query (D595).

**A call to a model (`--model`; the design's section 4), on AWS alone in this version.** Off by default, as each call
costs money: given a Bedrock model's ID or an inference profile's, the test agent also calls that model with each
invocation, and its plan says so. The ID is checked for its shape before anything is asked or made.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.parse
from pathlib import Path

from arvaken_stop_test import report, result
from arvaken_stop_test.timing import GATEWAY_WINDOW, HOLD, PATHS, WINDOWS

ENDPOINT = "https://stop-test.arvaken.com"        # Arvaken's test endpoint (D532, K3); see endpoint/ in this repository

# The gateway option: its attachments as the command line takes them, and each as the result holds it (result.PRODUCTS).
ATTACHMENTS = dict(zip(("model", "outside-services", "all-outbound"), result.PRODUCTS[result.GATEWAY]))
CA_LIMIT = 64 * 1024            # a certificate bundle's characters: it travels with each of the agent's invocations
SUBNET = re.compile(r"subnet-[0-9a-f]{8,17}")
SECURITY_GROUP = re.compile(r"sg-[0-9a-f]{8,17}")
# CUSTOMER TEXT: approved by the founder, 04:23:21 UTC on 27 October 2026 (D602); the --via help's example, an http://
# gateway, approved by him word for word on 30 October 2026, as nothing counts through an https:// one yet (D655, (c))
HELP = {
    "via": "your gateway's address, such as http://gateway.example:8888: the test agent's calls go through it, as an "
           "HTTPS proxy, and your stop is your gateway's own switch, which you fire",
    "product_attachment": "how your gateway is attached: model (its calls to a model), outside-services (its calls to "
                          "outside services) or all-outbound (all its outbound traffic)",
    "product_name": "your gateway's name, in your own words, up to 200 characters",
    "ca_bundle": "a file of the certificates your gateway presents, if it inspects TLS: used for the calls through it "
                 "alone, and never written into the result",
    "subnet": "the subnet the test agent runs in, where your gateway is reached only from your network",
    "security_group": "a security group for the test agent in that subnet (one or more)",
    "clean_subnet": "the subnet, if the run's test agent ran in one: its network interfaces are waited for and checked",
    "google_via": "not on Google Cloud in this version",
}
# CUSTOMER TEXT: approved by the founder, 04:23:21 UTC on 27 October 2026 (D602)
VIA_IS_THE_STOP = ("--via is your stop, your gateway's own switch: give it without --stop, --revoke-sessions, "
                   "--inline-deny or --own-trigger.")
# CUSTOMER TEXT: approved by the founder, 04:23:21 UTC on 27 October 2026 (D602)
VIA_NEEDS_PRODUCT = ("With --via, name your gateway: --product-attachment (model, outside-services or all-outbound) "
                     "and --product-name, up to 200 characters.")
# CUSTOMER TEXT: approved by the founder, 04:23:21 UTC on 27 October 2026 (D602)
VIA_ONCE = "--via fires once: only you can take your gateway's stop off, so --repeats is 1."
# CUSTOMER TEXT: approved by the founder, 04:23:21 UTC on 27 October 2026 (D602)
GOES_WITH_VIA = "--product-attachment, --product-name, --ca-bundle, --subnet and --security-group go with --via."
# CUSTOMER TEXT: approved by the founder, 04:23:21 UTC on 27 October 2026 (D602); its example approved by him word for
# word on 30 October 2026, as the --via help's
NOT_AN_ADDRESS = "--via takes your gateway's address, such as http://gateway.example:8888 or http://10.0.0.5:3128."
# CUSTOMER TEXT: approved by the founder, 04:23:21 UTC on 27 October 2026 (D602)
SUBNET_AND_GROUPS = "--subnet takes one subnet's ID (subnet-...), with one or more --security-group (sg-...)."
# CUSTOMER TEXT: approved by the founder, 04:23:21 UTC on 27 October 2026 (D602)
NOT_A_BUNDLE = "--ca-bundle takes a file of PEM certificates (-----BEGIN CERTIFICATE-----), of at most 64 KB."
# CUSTOMER TEXT: approved by the founder, 04:23:21 UTC on 27 October 2026 (D602)
GOOGLE_NO_VIA = ("--via is for AWS in this version of the kit: on Google Cloud, the gateway option waits for a later "
                 "version.")
# The model option (D562, F4): its help, what is said where its ID is not one, on Google Cloud, and in the plan.
# CUSTOMER TEXT: approved by the founder, by 11:09:43 UTC on 29 October 2026 (D562, F4: his five model lines)
MODEL_HELP = ("also time a call to a model: its Bedrock model ID or inference profile ID, such as "
              "eu.amazon.nova-micro-v1:0. Each call is billed to your account")
# CUSTOMER TEXT: approved by the founder, by 11:09:43 UTC on 29 October 2026 (D562, F4: his five model lines)
NOT_A_MODEL = "--model takes a Bedrock model ID or inference profile ID, such as eu.amazon.nova-micro-v1:0."
# CUSTOMER TEXT: approved by the founder, by 11:09:43 UTC on 29 October 2026 (D562, F4: his five model lines)
GOOGLE_NO_MODEL = "--model is for AWS in this version of the kit."
# CUSTOMER TEXT: approved by the founder, by 11:09:43 UTC on 29 October 2026 (D562, F4: his five model lines)
PLAN_MODEL = ("- with each invocation, also calls the model {model} once, as the test agent's own role, asking for one "
              "token: AWS bills each call to your account;")
# What the plan says of a run through a gateway.
# CUSTOMER TEXT: approved by the founder, 04:23:21 UTC on 27 October 2026 (D602)
PLAN_SUBNET = ("- runs the test agent in your subnet {subnet}, with your security group(s) {groups}: Lambda makes the "
               "test agent's network interfaces there. The kit attaches nothing else of yours, and after the run waits "
               "up to {minutes} minutes for AWS to remove those interfaces, then checks them gone;")
# CUSTOMER TEXT: approved by the founder, 04:23:21 UTC on 27 October 2026 (D602)
PLAN_VIA = ("- sends every call the test agent makes through your gateway at {via}, as an HTTPS proxy: its own calls "
            "to AWS, its work under the second role, its call with a key and its open-internet call. The last two "
            "still go to Arvaken's test address;")
# Through a gateway attached to less than all its outbound traffic, the plan names the calls that go through it.
# CUSTOMER TEXT: approved by the founder, by 17:10:22 UTC on 28 October 2026 (his ten lines)
PLAN_VIA_SOME = ("- sends through your gateway at {via}, as an HTTPS proxy, only the test agent's calls it is attached "
                 "to: {calls}. Its other calls go directly, as your agents' would;")
# CUSTOMER TEXT: approved by the founder, by 17:10:22 UTC on 28 October 2026 (his ten lines)
CALL_WORDS = {"own_calls": "its own calls to AWS", "another_identity": "its work under the second role",
              "outside_key": "its call with a key", "open_internet": "its open-internet call",
              "model": "its call to the model"}
# CUSTOMER TEXT: approved by the founder, by 17:10:22 UTC on 28 October 2026 (his ten lines)
ATTACHMENT_WITHOUT_CALLS = ("--product-attachment model goes with --model: only then does the test agent call a "
                            "model.")
# CUSTOMER TEXT: approved by the founder, by 17:10:22 UTC on 28 October 2026 (his ten lines)
VIA_WINDOW = ("--via times each path for at least 15 minutes after your mark: give --window 15m or more, or leave it "
              "out.")
# CUSTOMER TEXT: approved by the founder, 04:23:21 UTC on 27 October 2026 (D602)
PLAN_CA = ("- uses your certificate bundle {file} for the calls through your gateway alone; it is never written into "
           "the result;")
# Through a gateway the kit fires nothing: its plan's last line, and what it says once it has written the result.
# Arvaken's test address sees the key's and the open internet's calls come from the gateway's own address, which is the
# customer's.
# CUSTOMER TEXT: approved by the founder, 04:23:21 UTC on 27 October 2026 (D602)
PLAN_REMOVES = "- then removes everything it made, and names anything left."
# CUSTOMER TEXT: approved by the founder, 04:23:21 UTC on 27 October 2026 (D602)
WROTE_THROUGH_A_GATEWAY = (
    "Wrote {out}, its page and its details. Nothing was sent to Arvaken but the test agent's two calls to Arvaken's "
    "test address, one with the run's key and one with nothing. They reached it from the address your gateway's "
    "traffic leaves from, which is yours.")
# CUSTOMER TEXT: approved by the founder, 04:23:21 UTC on 27 October 2026 (D602)
PLAN_PRODUCT = ("- your stop is your gateway, {name}, attached to {attachment}: you fire it yourself. The kit asks you "
                "to press Enter, then fire your stop, and times each path from that mark;")


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
    from arvaken_stop_test.aws.run import ENI_WAIT
    n = names(run_name)
    stop = _stop(args)
    reason = fire.why_not(stop) if not (args.own_trigger or args.via) else None
    if not reason and args.stop:
        from arvaken_stop_test.aws.boto import clients_for
        c = clients_for(args.region)
        if not fire.covers(c.iam, stop, run_name):
            reason = fire.NOT_COVERED.rstrip(".")
        else:
            reason = (fire.why_no_boundary(c.iam, c.sts, model=bool(args.model)) or "").rstrip(".") or None
    gateway = []
    if args.via and args.subnet:
        gateway.append(PLAN_SUBNET.format(subnet=args.subnet, groups=", ".join(args.security_group),
                                          minutes=int(ENI_WAIT // 60)))
    if args.via:            # the address as the result keeps it: its scheme, host and port alone
        gateway.append(_plan_via(args))
    if args.via and args.ca_bundle:
        gateway.append(PLAN_CA.format(file=args.ca_bundle.name))
    lines = [f"Run {run_name} in {args.region}:",
             f"- creates one stack, {n['stack']}: a test agent ({n['function']}), its role and a second role, and a",
             "  bucket of its own, each tagged with the run;",
             *gateway,
             (PLAN_PRODUCT.format(name=args.product_name, attachment=ATTACHMENTS.get(args.product_attachment))
              if args.via else
              f"- waits for your own trigger, then times what stops; {fire.OWN_TRIGGER_WARNING.split('.')[0]}."
              if args.own_trigger else
              "- revokes the active sessions of the test agent's role and of the role it became, both made for the "
              "run, by AWS's own policy (AWSRevokeOlderSessions);" if args.revoke_sessions else
              "- writes a policy denying every action on the test agent's role alone;" if args.inline_deny else
              f"- attaches your stop, {args.stop}, to the test agent's role alone;"),
             f"- times each path for {int(args.window)} seconds after firing, {args.repeats} time(s);",
             f"- invokes the test agent about {calls_for(args.window, args.repeats)} times;",
             *([PLAN_MODEL.format(model=args.model)] if args.model else []),
             PLAN_REMOVES if args.via else
             "- then removes the stop it fired and everything it made, and names anything left."]
    if reason:
        lines.append(f"It will not run: {reason}.")
    return "\n".join(lines)


def routed(args) -> tuple[str, ...]:
    """The paths whose calls go through the gateway: those its declared attachment covers, of the run's own."""
    from arvaken_stop_test.aws.run import AWS_PATHS, MODEL
    covered = result.GATEWAY_ROUTES[ATTACHMENTS[args.product_attachment]]
    own = (*AWS_PATHS, MODEL) if args.model else AWS_PATHS
    return tuple(q for q in PATHS if q in covered and q in own)


def _plan_via(args) -> str:
    via = result.gateway_address(args.via)
    if ATTACHMENTS[args.product_attachment] == "all its outbound traffic":
        return PLAN_VIA.format(via=via)
    calls = [CALL_WORDS[q] for q in routed(args)]
    return PLAN_VIA_SOME.format(via=via, calls=" and ".join(calls) + (
        ", which still go to Arvaken's test address" if set(routed(args)) <= {"outside_key", "open_internet"} else ""))


def _gateway(args, p) -> str:
    """The gateway option's arguments, checked before anything is asked or made; returns the certificate bundle's text,
    if any. Nothing said here prints the gateway's address back."""
    if not args.via:
        if args.product_attachment or args.product_name or args.ca_bundle or args.subnet or args.security_group:
            p.error(GOES_WITH_VIA)
        return ""
    if args.stop or args.own_trigger or args.revoke_sessions or args.inline_deny:
        p.error(VIA_IS_THE_STOP)
    try:
        parts = urllib.parse.urlsplit(args.via)
        good = parts.scheme in ("http", "https") and bool(parts.hostname) and (parts.port or 1) > 0
    except ValueError:
        good = False
    if not good:
        p.error(NOT_AN_ADDRESS)
    if not args.product_attachment or not (args.product_name or "").strip() or \
            len(args.product_name) > result.NAME_LIMIT:
        p.error(VIA_NEEDS_PRODUCT)
    if args.repeats != 1:
        p.error(VIA_ONCE)
    if not routed(args):
        p.error(ATTACHMENT_WITHOUT_CALLS)
    if args.window < GATEWAY_WINDOW:
        p.error(VIA_WINDOW)
    groups = args.security_group or []
    if bool(args.subnet) != bool(groups) or (args.subnet and not SUBNET.fullmatch(args.subnet)) or \
            not all(SECURITY_GROUP.fullmatch(g) for g in groups):
        p.error(SUBNET_AND_GROUPS)
    if not args.ca_bundle:
        return ""
    try:
        text = args.ca_bundle.read_text(encoding="utf-8") if args.ca_bundle.stat().st_size <= CA_LIMIT else ""
    except (OSError, UnicodeDecodeError):
        text = ""
    if "-----BEGIN CERTIFICATE-----" not in text:
        p.error(NOT_A_BUNDLE)
    return text


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
             f"- times each path for {int(args.window)} seconds after firing, {args.repeats} time(s);",
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
        if args.via:
            p.error(GOOGLE_NO_VIA)
        if args.model:
            p.error(GOOGLE_NO_MODEL)
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
        a.add_argument("--via", default="", metavar="ADDRESS", help=HELP["via"])
        a.add_argument("--product-attachment", choices=sorted(ATTACHMENTS), help=HELP["product_attachment"])
        a.add_argument("--product-name", default="", help=HELP["product_name"])
        a.add_argument("--ca-bundle", type=Path, metavar="FILE", help=HELP["ca_bundle"])
        a.add_argument("--subnet", default="", help=HELP["subnet"])
        a.add_argument("--security-group", action="append", default=[], help=HELP["security_group"])
        a.add_argument("--model", default="", metavar="MODEL_ID", help=MODEL_HELP)
    clean = aws_sub.add_parser("clean", help="remove what an interrupted run left")
    clean.add_argument("--run", dest="run_name", required=True)
    clean.add_argument("--region", required=True)
    clean.add_argument("--stop", default="", help="the policy's ARN, if the run attached your managed policy")
    clean.add_argument("--subnet", default="", help=HELP["clean_subnet"])
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
        a.add_argument("--via", default="", metavar="ADDRESS", help=HELP["google_via"])
        a.add_argument("--model", default="", metavar="MODEL_ID", help=HELP["google_via"])
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

    from arvaken_stop_test.aws.stack import new_run
    ca = ""
    if args.action in ("plan", "run"):
        ca = _gateway(args, p)
        if not args.via and sum((bool(args.stop), args.own_trigger, args.revoke_sessions, args.inline_deny)) != 1:
            p.error("give one of --stop, --revoke-sessions, --inline-deny or --own-trigger")
        from arvaken_stop_test.aws.stack import is_model_id
        if args.model and not is_model_id(args.model):
            p.error(NOT_A_MODEL)
    run_name = args.run_name or new_run()
    if args.action == "plan":
        print(_plan(args, run_name))
        return 0
    from arvaken_stop_test.aws import fire
    from arvaken_stop_test.aws import run as running
    from arvaken_stop_test.aws.boto import clients_for
    c = clients_for(args.region)
    if args.action == "clean":
        r = running.Run(run=run_name, stop_ref=args.stop, fired_by="the kit", window=0.0, region=args.region,
                        subnet=args.subnet)
        r.outputs = running.outputs_of(c, run_name)
        # The stops the kit writes itself, on the run's own roles, are taken off whichever kind the run fired: an
        # interrupted run's roles cannot be deleted with them on. A managed policy of yours is named with --stop.
        for written in (fire.INLINE, fire.REVOKE):
            try:
                fire.remove(c.iam, run_name, written)
            except Exception:  # noqa: BLE001 - a role already gone has no stop on it
                pass
        running.tear_down(c, r, running.Clock(), say=print)
        print("Nothing the kit made is left." if not r.left_behind else
              "Left for you to delete:\n" + "\n".join(r.left_behind))
        return 0
    plan = _plan(args, run_name)
    print(plan)
    stop = _stop(args)
    yours = args.own_trigger or bool(args.via)
    if not yours and "It will not run:" in plan:
        return 1
    if args.via:
        print(fire.GATEWAY_WARNING)
    elif args.own_trigger:
        print(fire.OWN_TRIGGER_WARNING)
    if input(f"Type {run_name} to go on: ").strip() != run_name:
        print("Nothing was made.")
        return 1
    product = ({"kind": result.GATEWAY, "attachment": ATTACHMENTS[args.product_attachment], "name": args.product_name}
               if args.via else None)
    try:
        r, doc = running.run(c, stop, endpoint=args.endpoint,
                             fired_by="your own trigger" if yours else "the kit", window=args.window,
                             repeats=args.repeats, run_name=run_name, say=print, via=args.via, ca=ca, product=product,
                             subnet=args.subnet, security_groups=tuple(args.security_group),
                             mark=(lambda: input(running.MARK_PROMPT)) if args.via else None,
                             model=args.model)
    except running.NotStarted as e:     # why was said as it happened; then what the teardown left, as `clean` says it
        print("Nothing the kit made is left." if not e.run.left_behind else
              "Left for you to delete:\n" + "\n".join(e.run.left_behind))
        return 1
    out = Path(f"stop-test-{run_name}.json")
    write(out, json.dumps(doc, indent=1, sort_keys=True))
    write(Path(f"stop-test-{run_name}.html"), report.page(doc, [d for _, d in running.results(r)],
                                                          network=running.network(r) if r.subnet else None))
    write(Path(f"stop-test-{run_name}-details.json"), json.dumps(running.details(r, doc), indent=1))
    # through a gateway, the calls to Arvaken's test address leave from the gateway's address where they go through it
    print(WROTE_THROUGH_A_GATEWAY.format(out=out) if args.via and "outside_key" in routed(args) else
          f"Wrote {out}, its page and its details. Nothing about your account was sent to Arvaken.")
    print(f"Your result's reference: {result.reference(doc)}. It's the SHA-256 of the result's signature.")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
