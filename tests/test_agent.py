"""The test agent's calls to Arvaken's endpoint (agent.py), against a local server: what the endpoint is sent.

Cloudflare, in front of the endpoint, refused Python's default user agent ("Python-urllib/3.12": 403, its error 1010)
on the first proof run, 23 October 2026, so both paths that call it were never set up. The agent names itself."""
from __future__ import annotations

import http.server
import threading

from arvaken_stop_test.aws import agent


def test_the_agent_names_itself_to_the_endpoint_and_sends_the_key_only_where_asked():
    seen = []

    class Endpoint(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - the standard library's name
            seen.append((self.path, self.headers.get("User-Agent"), self.headers.get("Authorization")))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Endpoint)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{server.server_port}"
        agent._get(url + "/open", {})
        agent._get(url + "/key", {"Authorization": "Bearer " + "a" * 32})
    finally:
        server.shutdown()
    assert [path for path, _, _ in seen] == ["/open", "/key"]
    assert all(ua.startswith("arvaken-stop-test-agent") and "Python-urllib" not in ua for _, ua, _ in seen)
    assert (seen[0][2], seen[1][2]) == (None, "Bearer " + "a" * 32)
