"""A run through the customer's gateway, and in a subnet of theirs, on AWS (aws/run.py; D561, section 5; D595), against
test_aws_run.py's fake AWS on its virtual clock.

Through a gateway the stop is a product's control: the customer presses Enter, then fires their gateway's own switch,
and each path is timed from that mark. Here the customer turns their switch on `after` seconds after the mark (7), and
the gateway stops carrying calls 3 seconds after that, so each path's first failure from the mark is at least 10
seconds after it: slower than the switch's own 3, never faster. A gateway that stops carrying calls looks to the kit
like a broken network (ProxyConnectionError), which counts as no refusal: each path through it reads "not measured",
never "stopped" (the founder's ruling on a gateway's refusal, 30 October 2026, (b))."""
from __future__ import annotations

import html
import json
import re

import pytest

from arvaken_stop_test import report, result
from arvaken_stop_test.aws import fire as firing
from arvaken_stop_test.aws import run as running
from arvaken_stop_test.aws.stack import template
from arvaken_stop_test.timing import GATEWAY_WINDOW, NOTHING_COUNTED_AFTER, PATH_WORDS
from test_aws_run import STOP, Clock, FakeAWS, a_run

VIA = "https://user:pass@gw.example:8443/p?token=x#f"      # as the customer gives it
PEM = "-----BEGIN CERTIFICATE-----\nMIIBgateway\n-----END CERTIFICATE-----\n"
GATEWAY = {"kind": "gateway", "attachment": "all its outbound traffic", "name": "Our egress gateway"}
SUBNET, GROUPS = "subnet-0abc1234", ("sg-0abc1234",)
# an interface of the customer's own, in the same subnet with the same group, there before the run
CUSTOMERS = {"NetworkInterfaceId": "eni-0customer", "SubnetId": SUBNET, "Description": "an instance of yours",
             "Groups": [{"GroupId": "sg-0abc1234"}], "InterfaceType": "interface"}


def through(aws: FakeAWS, clock: Clock, *, after: float | None = 7.0, said: list | None = None, **over):
    """A run through the gateway: at the kit's prompt the customer presses Enter, then turns their gateway's switch
    on `after` seconds later. Returns the run, its result, and each mark: the kit's clock then, and the invocations."""
    marks = []

    def mark():
        marks.append((clock.now(), aws.invocations))
        if after is not None:
            aws.switch_at = clock.now() + after
    kw = dict(stop_ref="", fired_by="your own trigger", via=VIA, ca=PEM, product=GATEWAY, mark=mark,
              window=GATEWAY_WINDOW,
              say=said.append if said is not None else (lambda _: None))
    kw.update(over)
    r, doc = a_run(aws, clock, **kw)
    return r, doc, marks


def not_counted_after(reason: str | None) -> bool:
    """Whether a path's reason is that nothing after its last success was counted."""
    return bool(reason and re.fullmatch(NOTHING_COUNTED_AFTER.format(time=r"\d\d:\d\d:\d\d UTC"), reason))


def test_through_a_gateway_each_path_is_timed_from_your_mark_and_the_result_says_so():
    clock, said = Clock(), []
    aws = FakeAWS(clock)
    r, doc, marks = through(aws, clock, said=said)
    assert result.check(doc) == doc and doc["format"] == "stop-test-result/2"
    assert doc["stop"] == {"kind": "a product's control", "fired_by": "your own trigger", "ref": "", "product": GATEWAY}
    assert doc["run"]["via"] == "https://gw.example:8443"           # its scheme, host and port alone
    assert {p: v["outcome"] for p, v in doc["repeats"][0].items()} == {p: "not measured" for p in running.AWS_PATHS}
    # asked once, after the warm-up; the timing starts at the Enter, moved onto the agent's clock
    ((marked, invoked),) = marks
    assert invoked >= running.WARM_UP + 1
    assert r.repeats[0].fired_at == pytest.approx(marked + aws.skew, abs=0.001)
    assert {v["fired_at"] for v in doc["repeats"][0].values()} == {result.iso(marked + aws.skew)}
    # so each time errs toward slower: the switch went on 7 seconds after the mark, and held 3 seconds after that; and
    # none of the failures it gave counts
    found = running.results(r)[0][1]
    assert all(f.failures[0].at - f.fired_at >= 7.0 + 3.0 for f in found.values()), found
    assert all(not_counted_after(f.reason) and not f.refused for f in found.values()), found
    assert {f.fired_source for f in found.values()} == {running.FROM_THE_MARK}
    assert said == [running.MARKED, running.SWITCH_OFF]                 # and, once timed, that it may go off
    # the kit fired nothing itself, and the run is torn down as any other
    assert not aws.attach_calls and not aws.put_calls and not aws.attached
    assert doc["agent"]["private_network"] is False and aws.stack["status"] == "DELETED"
    assert doc["run"]["left_behind"] == [] and not aws.ec2_calls


def test_the_gateway_and_the_bundle_go_with_each_invocation_and_are_written_nowhere():
    """The founder's condition d: "The --via address is cleaned before any log line, terminal output or file is
    written." Each invocation carries it as given, to sign in to the gateway; nothing else holds more than its scheme,
    host and port: what the kit says as the run goes, the result, the details, the page, the run's record."""
    clock, said = Clock(), []
    aws = FakeAWS(clock)
    r, doc, _ = through(aws, clock, said=said)
    assert aws.payloads and all(p["via"] == VIA and p["ca"] == PEM for p in aws.payloads)     # as given, to sign in
    assert sum(p.get("action") == "assume" for p in aws.payloads) == 2
    assert "gw.example" not in aws.stack["body"] and "BEGIN CERTIFICATE" not in aws.stack["body"]
    details = running.details(r, doc)
    assert details["gateway"] == {"via": "https://gw.example:8443", "product": GATEWAY}
    page = report.page(doc, [d for _, d in running.results(r)])
    for written in (json.dumps(doc), json.dumps(details), page, repr(r), "\n".join(said)):
        assert all(s not in written for s in ("user:pass", "pass@", "token=x", "/p?", "BEGIN CERTIFICATE"))
    assert report.GATEWAY_NOTE.format(name=GATEWAY["name"], attachment=GATEWAY["attachment"],
                                      via="https://gw.example:8443") in page
    assert report.MARK_NOTE in page and report.GATEWAY_HEADING in page        # read from the stop's kind


def test_a_cloud_stops_page_says_nothing_of_a_gateway_or_a_mark():
    clock = Clock()
    r, doc = a_run(FakeAWS(clock), clock)
    page = report.page(doc, [d for _, d in running.results(r)])
    assert report.MARK_NOTE not in page and report.GATEWAY_HEADING not in page and report.EXPECTED_HEADING in page


def test_the_products_name_is_shown_as_text_never_as_markup():
    clock = Clock()
    named = {**GATEWAY, "name": '<script>alert("x")</script> & <a href="https://x.example">us</a>'}
    r, doc, _ = through(FakeAWS(clock), clock, product=named)
    assert result.check(doc)["stop"]["product"]["name"] == named["name"]          # kept as given, as text
    page = report.page(doc, [d for _, d in running.results(r)])
    assert "<script" not in page and "<a href" not in page and "&lt;script&gt;" in page


def test_a_path_that_fails_through_the_gateway_before_the_stop_is_not_measured_never_stopped():
    """The gateway refuses the key's call throughout, and the other identity's session; and the open internet from the
    agent's sixth invocation, within the warm-up: it worked, then failed just before the mark, so it would otherwise
    have read as stopped at once."""
    clock, said = Clock(), []
    aws = FakeAWS(clock, gateway_refuses=("outside_key", "another_identity"), gateway_breaks={"open_internet": 6})
    r, doc, marks = through(aws, clock, said=said)
    assert {p: v["outcome"] for p, v in doc["repeats"][0].items()} == {
        "own_calls": "not measured", "another_identity": "not measured", "outside_key": "not measured",
        "open_internet": "not measured"}
    assert len(marks) == 1 and result.check(doc)
    rep = r.repeats[0]                                                      # failing after the mark, never "stopped"
    assert all(not b.ok for b in rep.beats["open_internet"] if b.at > rep.fired_at)
    assert said == [running.NOT_THROUGH_THE_GATEWAY.format(path=PATH_WORDS[p], codes=codes) for p, codes in (
        ("another_identity", "ProxyConnectionError 10"), ("outside_key", "ProxyConnectionError 10"),
        ("open_internet", "ProxyConnectionError 6"))] + [running.MARKED, running.SWITCH_OFF]
    page = report.page(doc, [d for _, d in running.results(r)])
    assert page.count(f"{running.NOT_MEASURED_REASON}: ProxyConnectionError") == 3
    assert "ProxyConnectionError" not in json.dumps(doc)


def test_where_no_path_works_through_the_gateway_no_mark_is_asked_and_nothing_is_measured():
    clock, said = Clock(), []
    aws = FakeAWS(clock, gateway_refuses=running.AWS_PATHS)
    r, doc, marks = through(aws, clock, said=said)
    assert marks == [] and said[-1] == running.NOTHING_THROUGH_THE_GATEWAY
    assert {v["outcome"] for v in doc["repeats"][0].values()} == {"not measured"}
    assert result.check(doc) and doc["run"]["repeats"] == 1 and aws.stack["status"] == "DELETED"


@pytest.mark.parametrize("over", [
    dict(fired_by="the kit"),                       # a product's control is fired by the customer, never by the kit
    dict(stop_ref=STOP),
    dict(product=None),
    dict(product={**GATEWAY, "kind": "in-agent SDK", "attachment": "inside its code"}),     # not testable by the kit
    dict(product={**GATEWAY, "attachment": "everything it does"}),
    dict(product={**GATEWAY, "name": "x" * 201}),
    dict(mark=None),
    dict(via="", product=None, mark=None),          # a bundle with no gateway
    dict(via="", ca="", product=None, mark=None, subnet=SUBNET, security_groups=GROUPS),     # a subnet, no gateway
    dict(subnet=SUBNET),                            # a subnet with no security group
    dict(security_groups=GROUPS),
    dict(repeats=2),
    dict(window=GATEWAY_WINDOW - 1),                # the founder's condition c: at least 15 minutes
    dict(product={**GATEWAY, "attachment": "its calls to a model"}),    # condition a: no call to a model in this run
])
def test_a_gateway_run_that_is_not_one_is_refused_before_anything_is_made(over):
    clock = Clock()
    aws = FakeAWS(clock)
    with pytest.raises(ValueError):
        through(aws, clock, **over)
    assert aws.stack is None and aws.invocations == 0 and not aws.ec2_calls


def test_in_a_subnet_of_yours_the_kit_waits_for_the_functions_network_interfaces_then_checks_them_gone():
    clock, said = Clock(), []
    aws = FakeAWS(clock, subnet_has=[CUSTOMERS])
    r, doc, _ = through(aws, clock, said=said, subnet=SUBNET, security_groups=GROUPS)
    assert aws.stack["template"]["Resources"]["Agent"]["Properties"]["VpcConfig"] == {
        "SubnetIds": [SUBNET], "SecurityGroupIds": list(GROUPS)}
    assert r.interfaces == ["eni-0aaa1111"]                     # the function's, never the customer's own
    # AWS removed it 10 minutes after the function was deleted: waited for, why said once, then checked gone
    assert [s for s in said if s.startswith("AWS removes")] == [
        running.WAITING_FOR_INTERFACES.format(minutes=30, count=1, subnet=SUBNET)]
    assert r.checked_gone[-1] == "the network interface eni-0aaa1111" and doc["run"]["left_behind"] == []
    assert aws.function_deleted_at + 600 <= r.ended_at < aws.function_deleted_at + 600 + 2 * running.ENI_POLL
    assert "eni-0customer" in aws.enis and "eni-0customer" not in json.dumps(running.details(r, doc))
    assert set(aws.ec2_calls) == {"describe_network_interfaces"}         # read only: nothing of yours is changed
    assert doc["agent"]["private_network"] is True and result.check(doc)
    page = report.page(doc, [d for _, d in running.results(r)], network=running.network(r))
    assert report.NETWORK_NOTE.format(subnet=SUBNET, groups="sg-0abc1234") in page
    assert report.INTERFACES_NOTE.format(interfaces="eni-0aaa1111", gone="eni-0aaa1111", left="none") in page
    assert running.details(r, doc)["network"] == {"subnet": SUBNET, "security_groups": list(GROUPS),
                                                  "interfaces": ["eni-0aaa1111"], "gone": ["eni-0aaa1111"],
                                                  "left": []}


def test_a_network_interface_still_there_when_the_wait_ends_is_named_as_left():
    clock, said = Clock(), []
    aws = FakeAWS(clock, eni_after=None)                        # AWS never removes it
    r, doc, _ = through(aws, clock, said=said, subnet=SUBNET, security_groups=GROUPS, eni_wait=120.0)
    assert doc["run"]["left_behind"] == ["the network interface eni-0aaa1111 in your subnet subnet-0abc1234"]
    assert doc["run"]["left_anything"] is True and result.check(doc)
    assert aws.function_deleted_at + 120 <= r.ended_at < aws.function_deleted_at + 120 + 2 * running.ENI_POLL
    assert running.WAITING_FOR_INTERFACES.format(minutes=2, count=1, subnet=SUBNET) in said


def test_ctrl_c_during_the_wait_ends_it_names_what_is_still_there_and_keeps_the_result():
    clock, said = Clock(), []
    aws = FakeAWS(clock, eni_after=None)

    class Interrupted:
        """The fake clock, but Ctrl-C is pressed at the wait's first pause."""
        now = staticmethod(clock.now)

        @staticmethod
        def sleep(d: float) -> None:
            if d == running.ENI_POLL:
                raise KeyboardInterrupt
            clock.sleep(d)
    r, doc, _ = through(aws, Interrupted(), said=said, subnet=SUBNET, security_groups=GROUPS)
    assert said[-2:] == [running.WAITING_FOR_INTERFACES.format(minutes=30, count=1, subnet=SUBNET),
                         running.WAIT_STOPPED]
    assert doc["run"]["left_behind"] == ["the network interface eni-0aaa1111 in your subnet subnet-0abc1234"]
    assert result.check(doc)


def test_an_interface_lambda_describes_otherwise_is_found_by_appearing_with_the_runs_security_groups():
    clock = Clock()
    aws = FakeAWS(clock, eni_described=False, subnet_has=[CUSTOMERS])
    r, doc, _ = through(aws, clock, subnet=SUBNET, security_groups=GROUPS)
    assert r.interfaces == ["eni-0aaa1111"] and r.checked_gone[-1] == "the network interface eni-0aaa1111"
    assert doc["run"]["left_behind"] == []


def test_where_the_function_is_still_there_its_interfaces_are_named_left_without_waiting():
    clock, said = Clock(), []
    aws = FakeAWS(clock, stack_stays=True)                      # the stack could not be deleted
    r, doc, _ = through(aws, clock, said=said, subnet=SUBNET, security_groups=GROUPS)
    left = doc["run"]["left_behind"]
    assert "the function arvaken-stop-test-r0123abcd-agent" in left
    assert "the network interface eni-0aaa1111 in your subnet subnet-0abc1234" in left
    assert not any(s.startswith("AWS removes") for s in said)


def test_a_run_in_a_subnet_takes_a_boundary_of_its_own_and_any_other_run_never_needs_it():
    """A run in a subnet's roles carry arvaken-stop-test-boundary-via, and the run refuses before anything is made
    where it is missing or not the kit's; it does not need arvaken-stop-test-boundary. Any other run takes that alone,
    in an account that never made the subnet's, so the kit's own boundary stays as it was to 0.2.1."""
    for held, says in ((None, firing.NO_BOUNDARY_VIA), ("another", firing.NOT_THE_BOUNDARY_VIA)):
        clock = Clock()
        aws = FakeAWS(clock, boundary_via=held)
        with pytest.raises(firing.Refused) as e:
            through(aws, clock, subnet=SUBNET, security_groups=GROUPS)
        assert str(e.value) == says
        assert aws.stack is None and aws.invocations == 0 and not aws.ec2_calls
    clock = Clock()
    assert result.check(through(FakeAWS(clock, boundary=None), clock, subnet=SUBNET, security_groups=GROUPS)[1])
    for a_kind in (lambda f, c: through(f, c)[1], lambda f, c: a_run(f, c, stop_ref=firing.INLINE)[1]):
        clock = Clock()
        assert result.check(a_kind(FakeAWS(clock, boundary_via=None), clock))
    for subnet, name in (("", "arvaken-stop-test-boundary"), (SUBNET, "arvaken-stop-test-boundary-via")):
        roles = [r["Properties"] for r in template("r0123abcd", "https://e.test", subnet=subnet,
                                                    security_groups=GROUPS if subnet else ())["Resources"].values()
                 if r["Type"] == "AWS::IAM::Role"]
        assert len(roles) == 2 and all(p["PermissionsBoundary"] == {
            "Fn::Sub": f"arn:${{AWS::Partition}}:iam::${{AWS::AccountId}}:policy/{name}"} for p in roles)


# The founder's conditions for the gateway release, 28 October 2026 (his answer in the kit's session).
OUTSIDE = {**GATEWAY, "attachment": "its calls to outside services"}


def test_only_the_calls_the_attachment_covers_go_through_the_gateway_and_the_page_expects_by_it():
    """Condition a: "Only calls the declared attachment covers go through --via". Attached to its calls to outside
    services, the test agent's call with a key and its open-internet call go through the gateway, and its switch stops
    them; its own calls and its work under the second role go directly, as the customer's agents' would, and it does
    not. The page expects each path by the attachment, so neither kind differs from what was expected."""
    clock = Clock()
    aws = FakeAWS(clock)
    r, doc, _ = through(aws, clock, product=OUTSIDE)
    assert result.check(doc) == doc and r.through == {"outside_key", "open_internet"}
    assert aws.payloads and all(p["through"] == ["open_internet", "outside_key"] for p in aws.payloads)
    assert {p: v["outcome"] for p, v in doc["repeats"][0].items()} == {
        "own_calls": "not stopped", "another_identity": "not stopped", "outside_key": "not measured",
        "open_internet": "not measured"}
    page = report.page(doc, [d for _, d in running.results(r)])
    assert page.count('class="differs"') == 2                    # the gateway's two paths: expected stopped, not measured
    assert html.escape(report.GATEWAY_NOTE_SOME.format(
        name=OUTSIDE["name"], attachment=OUTSIDE["attachment"], via="https://gw.example:8443",
        paths="a key for a service outside the cloud, the open internet")) in page
    assert "Every call the test agent made" not in page
    expects = {a: [report.expected("a product's control", p, a) for p in running.AWS_PATHS]
               for a in result.GATEWAY_ROUTES}
    assert expects == {"its calls to a model": ["not stopped"] * 4,
                       "its calls to outside services": ["not stopped", "not stopped", "stopped", "stopped"],
                       "all its outbound traffic": ["stopped"] * 4}


def test_attached_to_all_its_outbound_traffic_every_call_goes_through_the_gateway():
    clock = Clock()
    aws = FakeAWS(clock)
    r, doc, _ = through(aws, clock)
    assert r.through == set(running.AWS_PATHS) and all(set(p["through"]) == set(running.AWS_PATHS)
                                                         for p in aws.payloads)
    assert {v["outcome"] for v in doc["repeats"][0].values()} == {"not measured"}


def test_a_path_going_directly_that_did_not_work_before_the_stop_is_not_run_as_in_any_run():
    r = running.Run(run="r0123abcd", stop_ref="", fired_by="your own trigger", window=GATEWAY_WINDOW, region="x",
                    via=VIA, product=OUTSIDE, setup_errors={"own_calls": {"AccessDenied": 10}})
    assert running._did_not_work(r, "own_calls") == (
        "Before the stop, its own calls to the cloud did not work (AccessDenied 10): it will be reported as not run.")
    assert running._did_not_work(r, "outside_key") == running.NOT_THROUGH_THE_GATEWAY.format(
        path=PATH_WORDS["outside_key"], codes="no answer")


def test_a_path_already_refused_at_your_mark_is_not_measured_never_stopped():
    """Condition b: "A path already refused at the mark is 'not measured'". The customer's switch was on before they
    pressed Enter, so each path through the gateway was refused at its first heartbeat after the mark: no time from the
    mark can be told of it."""
    clock, said = Clock(), []
    aws = FakeAWS(clock)
    r, doc, marks = through(aws, clock, after=-10.0, said=said)
    assert len(marks) == 1 and result.check(doc)
    assert {v["outcome"] for v in doc["repeats"][0].values()} == {"not measured"}
    found = running.results(r)[0][1]
    assert {f.reason for f in found.values()} == {running.ALREADY_REFUSED_REASON}
    assert all(f.effect_between is None for f in found.values())
    page = report.page(doc, [d for _, d in running.results(r)])
    assert report.ALREADY_REFUSED_NOTE in page and page.count(running.ALREADY_REFUSED_REASON) == 4
    # failing only after the first heartbeat after the mark: not refused at the mark, and not counted either
    clock = Clock()
    r, doc, _ = through(FakeAWS(clock), clock, after=2.0)
    assert {v["outcome"] for v in doc["repeats"][0].values()} == {"not measured"}
    assert all(not_counted_after(f.reason) for f in running.results(r)[0][1].values())


def test_the_window_is_the_one_given_before_the_run_and_the_result_records_it():
    """Condition c: "The timing window is fixed before the run, at least 15 minutes, and recorded in the result.\""""
    for window in (GATEWAY_WINDOW, 20 * 60.0):
        clock = Clock()
        r, doc, _ = through(FakeAWS(clock), clock, window=window)
        assert r.window == window and doc["run"]["window_seconds"] == int(window)
    assert GATEWAY_WINDOW == 15 * 60.0
