"""A run through the customer's gateway, and in a subnet of theirs, on AWS (aws/run.py; D561, section 5; D595), against
test_aws_run.py's fake AWS on its virtual clock.

Through a gateway the stop is a product's control: the customer presses Enter, then fires their gateway's own switch,
and each path is timed from that mark. Here the customer turns their switch on `after` seconds after the mark (7), and
the gateway stops carrying calls 3 seconds after that, so each time from the mark is at least 10 seconds: slower than
the switch's own 3, never faster."""
from __future__ import annotations

import json

import pytest

from arvaken_stop_test import report, result
from arvaken_stop_test.aws import fire as firing
from arvaken_stop_test.aws import run as running
from arvaken_stop_test.aws.stack import template
from arvaken_stop_test.timing import PATH_WORDS
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
              say=said.append if said is not None else (lambda _: None))
    kw.update(over)
    r, doc = a_run(aws, clock, **kw)
    return r, doc, marks


def test_through_a_gateway_each_path_is_timed_from_your_mark_and_the_result_says_so():
    clock, said = Clock(), []
    aws = FakeAWS(clock)
    r, doc, marks = through(aws, clock, said=said)
    assert result.check(doc) == doc and doc["format"] == "stop-test-result/2"
    assert doc["stop"] == {"kind": "a product's control", "fired_by": "your own trigger", "ref": "", "product": GATEWAY}
    assert doc["run"]["via"] == "https://gw.example:8443"           # its scheme, host and port alone
    assert {p: v["outcome"] for p, v in doc["repeats"][0].items()} == {p: "stopped" for p in running.AWS_PATHS}
    # asked once, after the warm-up; the timing starts at the Enter, moved onto the agent's clock
    ((marked, invoked),) = marks
    assert invoked >= running.WARM_UP + 1
    assert r.repeats[0].fired_at == pytest.approx(marked + aws.skew, abs=0.001)
    assert {v["fired_at"] for v in doc["repeats"][0].values()} == {result.iso(marked + aws.skew)}
    # so each time errs toward slower: the switch went on 7 seconds after the mark, and held 3 seconds after that
    found = running.results(r)[0][1]
    assert all(f.effect_between[1] >= 7.0 + 3.0 for f in found.values()), found
    assert {f.fired_source for f in found.values()} == {running.FROM_THE_MARK}
    assert said == [running.MARKED, running.SWITCH_OFF]                 # and, once timed, that it may go off
    # the kit fired nothing itself, and the run is torn down as any other
    assert not aws.attach_calls and not aws.put_calls and not aws.attached
    assert doc["agent"]["private_network"] is False and aws.stack["status"] == "DELETED"
    assert doc["run"]["left_behind"] == [] and not aws.ec2_calls


def test_the_gateway_and_the_bundle_go_with_each_invocation_and_are_written_nowhere():
    clock = Clock()
    aws = FakeAWS(clock)
    r, doc, _ = through(aws, clock)
    assert aws.payloads and all(p["via"] == VIA and p["ca"] == PEM for p in aws.payloads)     # as given, to sign in
    assert sum(p.get("action") == "assume" for p in aws.payloads) == 2
    assert "gw.example" not in aws.stack["body"] and "BEGIN CERTIFICATE" not in aws.stack["body"]
    details = running.details(r, doc)
    assert details["gateway"] == {"via": "https://gw.example:8443", "product": GATEWAY}
    page = report.page(doc, [d for _, d in running.results(r)])
    for written in (json.dumps(doc), json.dumps(details), page, repr(r)):
        assert all(s not in written for s in ("user:pass", "pass@", "token", "/p?", "BEGIN CERTIFICATE"))
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
        "own_calls": "stopped", "another_identity": "not measured", "outside_key": "not measured",
        "open_internet": "not measured"}
    assert len(marks) == 1 and result.check(doc)
    assert all(not b.ok for b in r.repeats[0].beats["open_internet"])       # failing after the mark, never "stopped"
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
