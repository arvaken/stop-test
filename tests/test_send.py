"""--send (the plan, stage 3; the founder's decision 3, opt in): the kit sends nothing itself. A run that wrote its
result opens Arvaken's send page with the result's own bytes after '#', which a browser never sends to a server, or
says the address where there is no browser; without --send it opens nothing."""
from __future__ import annotations

import base64
import json

import pytest

from arvaken_stop_test import cli


def test_the_address_holds_the_result_byte_for_byte_after_the_hash(tmp_path):
    out = tmp_path / "stop-test-abc123.json"
    body = json.dumps({"format": "stop-test-result/3", "x": "é"}, indent=1)
    cli.write(out, body)
    address = cli.send_address(out)
    page, _, fragment = address.partition("#")
    assert page == cli.SEND_PAGE == "https://app.arvaken.com/stop-test/submit"
    assert fragment.startswith("result=")
    got = fragment[len("result="):]
    assert base64.urlsafe_b64decode(got + "=" * (-len(got) % 4)) == out.read_bytes()


def test_only_the_result_is_taken_never_its_details_or_arrivals(tmp_path):
    for name in ("stop-test-abc-details.json", "stop-test-abc-arrivals.json", "other.json"):
        assert not cli.RESULT_FILE.fullmatch(name)
    assert cli.RESULT_FILE.fullmatch("stop-test-abc.json")


def test_it_opens_the_page_where_there_is_a_browser_and_says_the_address_where_there_is_none(tmp_path, capsys):
    out = tmp_path / "stop-test-abc.json"
    cli.write(out, "{}")
    opened: list[str] = []
    cli.hand_over(out, opener=lambda a: opened.append(a) or True)
    assert opened == [cli.send_address(out)]
    assert capsys.readouterr().out.strip() == cli.SEND_LINE
    cli.hand_over(out, opener=lambda a: False)
    said = capsys.readouterr().out.strip().splitlines()
    assert said == [cli.SEND_NO_BROWSER, cli.send_address(out)]


def test_without_send_nothing_is_opened(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    opened: list = []
    monkeypatch.setattr(cli, "hand_over", lambda *a, **k: opened.append(a))

    def fake(argv_):
        cli._SEND = False                                     # as _main sets it for a run without --send, or a plan
        cli.write(tmp_path / "stop-test-r1.json", "{}")
        return 0
    monkeypatch.setattr(cli, "_main", fake)
    assert cli.main(["aws", "run"]) == 0
    assert opened == []


def test_send_on_a_run_opens_the_result_it_wrote(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    opened: list = []
    monkeypatch.setattr(cli, "hand_over", lambda path, page: opened.append((path.name, page)))

    def fake(argv_):
        cli._SEND, cli._SEND_PAGE = True, cli.SEND_PAGE      # as _main sets them for `run --send`
        cli.write(tmp_path / "stop-test-r2.json", "{}")
        cli.write(tmp_path / "stop-test-r2-details.json", "{}")
        return 0
    monkeypatch.setattr(cli, "_main", fake)
    assert cli.main(["aws", "run"]) == 0
    assert opened == [("stop-test-r2.json", cli.SEND_PAGE)]


def test_every_run_takes_send_and_says_what_it_does():
    import argparse
    import contextlib
    import io
    for argv in (["aws", "run", "--help"], ["google", "run", "--help"], ["agentcore", "run", "--help"],
                 ["agentcore-harness", "run", "--help"]):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), pytest.raises(SystemExit):
            cli._main(argv)
        assert "--send" in buf.getvalue(), argv
    assert argparse  # noqa
