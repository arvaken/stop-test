"""The test agent's calls to Arvaken's endpoint (agent.py), against a local server: what the endpoint is sent.

Cloudflare, in front of the endpoint, refused Python's default user agent ("Python-urllib/3.12": 403, its error 1010)
on the first proof run, 23 October 2026, so both paths that call it were never set up. The agent names itself.

Through a gateway (the kit's --via; D561, section 5): every client and call of the agent's goes through it, and the
customer's certificate bundle is used for those calls alone. Held twice: with fakes for boto3's clients, for what each
is made with; and against a real local gateway (an HTTPS proxy, answering CONNECT) in front of a TLS endpoint whose
certificate only the customer's bundle trusts, as a gateway that inspects TLS presents its own."""
from __future__ import annotations

import base64
import datetime
import http.server
import ipaddress
import os
import socket
import socketserver
import ssl
import threading
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

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


VIA = "http://user:pass@gateway.test:3128"
PEM = "-----BEGIN CERTIFICATE-----\nMIIBgateway\n-----END CERTIFICATE-----\n"


class FakeClient:
    def put_object(self, **kw):
        pass

    def get_object(self, **kw):
        return {"Body": type("B", (), {"read": lambda self: b"x"})()}

    def assume_role(self, **kw):
        return {"Credentials": {"AccessKeyId": "k", "SecretAccessKey": "s", "SessionToken": "t",
                                "Expiration": datetime.datetime(2026, 10, 26, tzinfo=datetime.timezone.utc)}}

    conversed: list = []            # each Converse call's request, across clients
    refuse_with: str | None = None  # a Bedrock error code the call fails with, if any

    def converse(self, **kw):
        FakeClient.conversed.append(kw)
        if FakeClient.refuse_with:
            import botocore.exceptions
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": FakeClient.refuse_with, "Message": "the model arn:aws:bedrock:... is secret"}},
                "Converse")
        return {"output": {"message": {"role": "assistant", "content": [{"text": "THE MODEL'S OWN WORDS"}]}},
                "stopReason": "max_tokens", "usage": {"inputTokens": 8, "outputTokens": 1, "totalTokens": 9}}


@pytest.fixture
def an_agent(monkeypatch, tmp_path):
    """The agent's handler with boto3's clients and its endpoint calls faked: what each is made with, and given."""
    made, gets = [], []
    monkeypatch.setattr(agent.boto3, "client", lambda name, **kw: made.append((name, kw)) or FakeClient())
    monkeypatch.setattr(agent, "_get", lambda url, headers, gw=({}, None): gets.append((url, gw)))
    monkeypatch.setattr(agent, "CA", str(tmp_path / "ca.pem"))
    monkeypatch.setattr(FakeClient, "conversed", [])
    monkeypatch.setattr(FakeClient, "refuse_with", None)
    monkeypatch.delenv("MODEL", raising=False)
    for k, v in {"BUCKET": "b", "ENDPOINT": "https://stop-test.example", "OUTSIDE_KEY": "k" * 32,
                 "SECOND_ROLE": "arn:aws:iam::111122223333:role/arvaken-stop-test-r1-second"}.items():
        monkeypatch.setenv(k, v)
    return made, gets


MODEL = "eu.amazon.nova-micro-v1:0"
SESSION = {"key": "k", "secret": "s", "token": "t"}


def test_with_a_model_each_invocation_also_calls_it_once_as_the_agent_and_keeps_nothing_of_its_answer(an_agent,
                                                                                                         monkeypatch):
    """The fifth row (--model; the design's section 4): one Converse call, as the agent's own role (no other
    identity's keys), asking the least a call can; only whether it worked is returned, never what the model said."""
    made, _ = an_agent
    monkeypatch.setenv("MODEL", MODEL)
    out = agent.handler({"n": 3, "session": SESSION}, None)
    assert list(out["beats"]) == ["own_calls", "another_identity", "outside_key", "open_internet", "model"]
    assert out["beats"]["model"] == {"at": out["beats"]["model"]["at"], "ok": True}
    assert FakeClient.conversed == [{"modelId": MODEL, "inferenceConfig": {"maxTokens": 1},
                                     "messages": [{"role": "user", "content": [{"text": "1"}]}]}]
    (bedrock,) = [kw for name, kw in made if name == "bedrock-runtime"]
    assert "aws_access_key_id" not in bedrock and "aws_session_token" not in bedrock      # its own role's
    assert (bedrock["config"].connect_timeout, bedrock["config"].read_timeout) == (2, 2)
    assert bedrock["config"].retries == {"max_attempts": 1}
    assert "WORDS" not in repr(out) and "Tokens" not in repr(out)


def test_a_refused_model_call_is_its_code_alone(an_agent, monkeypatch):
    monkeypatch.setenv("MODEL", MODEL)
    for code in ("AccessDeniedException", "ValidationException", "ThrottlingException"):
        FakeClient.refuse_with = code
        beat = agent.handler({"n": 3, "session": SESSION}, None)["beats"]["model"]
        assert beat == {"at": beat["at"], "ok": False, "error": code}


def test_without_a_model_the_agent_calls_none_and_its_reply_is_as_before(an_agent, monkeypatch):
    made, _ = an_agent
    for unset in (lambda: None, lambda: monkeypatch.setenv("MODEL", "")):
        unset()
        out = agent.handler({"n": 3, "session": SESSION}, None)
        assert list(out["beats"]) == ["own_calls", "another_identity", "outside_key", "open_internet"]
    assert "bedrock-runtime" not in [name for name, _ in made] and FakeClient.conversed == []


def test_through_a_gateway_the_model_call_goes_through_it_with_the_bundle(an_agent, monkeypatch):
    made, _ = an_agent
    monkeypatch.setenv("MODEL", MODEL)
    assert agent.handler({"n": 3, "session": SESSION, "via": VIA, "ca": PEM, "through": ["model"]},
                         None)["beats"]["model"]["ok"]
    (bedrock,) = [kw for name, kw in made if name == "bedrock-runtime"]
    assert bedrock["config"].proxies == {"http": VIA, "https": VIA}
    assert all(kw["config"].proxies is None for name, kw in made if name != "bedrock-runtime")    # the others directly
    assert bedrock["config"].proxies_config == {"proxy_ca_bundle": agent.CA} and bedrock["verify"] == agent.CA


def test_the_agent_with_its_model_call_still_fits_cloudformations_inline_limit():
    from arvaken_stop_test.aws.stack import INLINE_LIMIT, agent_code
    code = agent_code()
    assert len(code) <= INLINE_LIMIT
    assert ".converse(" in code and '"maxTokens": 1' in code and 'os.environ.get("MODEL")' in code
    assert '"""' not in code                        # what explains it is in the module's docstring, not shipped


def test_through_a_gateway_every_client_and_call_of_the_agent_goes_through_it_with_the_bundle(an_agent):
    made, gets = an_agent
    session = {"key": "k", "secret": "s", "token": "t"}
    every = ["another_identity", "open_internet", "outside_key", "own_calls"]
    assert agent.handler({"action": "assume", "via": VIA, "ca": PEM, "through": every}, None)["session"]["key"] == "k"
    out = agent.handler({"n": 3, "session": session, "via": VIA, "ca": PEM, "through": every}, None)
    assert all(b["ok"] for b in out["beats"].values()), out
    # its own calls, the session's for the other identity, and the session taken for it: each client through it
    assert [name for name, _ in made] == ["sts", "s3", "s3"]
    for name, kw in made:
        assert kw["config"].proxies == {"http": VIA, "https": VIA}, name
        assert kw["config"].proxies_config == {"proxy_ca_bundle": agent.CA} and kw["verify"] == agent.CA
        assert (kw["config"].connect_timeout, kw["config"].read_timeout) == (2, 2)
    assert made[2][1]["aws_session_token"] == "t"                   # the other identity's, through it as well
    # its call with a key and its open-internet call: through it, to Arvaken's test endpoint
    assert [url for url, _ in gets] == ["https://stop-test.example/key", "https://stop-test.example/open"]
    assert all(gw == ({"proxies": {"http": VIA, "https": VIA}, "proxies_config": {"proxy_ca_bundle": agent.CA}},
                      agent.CA) for _, gw in gets)
    # the bundle trusted is the customer's, beside the default ones
    written = Path(agent.CA).read_text()
    from botocore.httpsession import get_cert_path
    assert written.endswith(PEM) and written.startswith(Path(get_cert_path(True)).read_text()[:200])


def test_without_a_gateway_the_agent_calls_directly_and_trusts_no_bundle(an_agent):
    made, gets = an_agent
    agent.handler({"n": 3, "session": {"key": "k", "secret": "s", "token": "t"}, "ca": PEM}, None)
    assert made and all(kw["config"].proxies is None and kw["verify"] is None for _, kw in made)
    assert gets and all(gw == ({}, None) for _, gw in gets)
    assert not os.path.exists(agent.CA)                              # a bundle with no gateway is never used


def test_a_gateway_with_no_bundle_is_trusted_as_the_default_ones_are(an_agent):
    made, gets = an_agent
    agent.handler({"n": 3, "session": {"key": "k", "secret": "s", "token": "t"}, "via": VIA,
                   "through": ["another_identity", "open_internet", "outside_key", "own_calls"]}, None)
    assert all(kw["config"].proxies == {"http": VIA, "https": VIA} and kw["verify"] is None for _, kw in made)
    assert all(gw == ({"proxies": {"http": VIA, "https": VIA}, "proxies_config": None}, None) for _, gw in gets)


# A real gateway, on this machine: a proxy answering CONNECT, in front of a TLS endpoint with a certificate of a CA of
# the test's own, which nothing trusts but the bundle the test gives (as a gateway that inspects TLS presents its own).
def _certificates(where: Path) -> tuple[str, Path, Path]:
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key, key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "the customer's gateway CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
          .not_valid_after(now + datetime.timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                       content_commitment=False, key_encipherment=False, data_encipherment=False,
                                       key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))
    leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")]))
            .issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
                           critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    cert, key_file = where / "leaf.pem", where / "leaf.key"
    cert.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    return ca.public_bytes(serialization.Encoding.PEM).decode("ascii"), cert, key_file


class _Gateway(socketserver.ThreadingTCPServer):
    daemon_threads = allow_reuse_address = True


def _gateway(seen: list) -> _Gateway:
    class Tunnel(socketserver.BaseRequestHandler):
        def handle(self):
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = self.request.recv(4096)
                if not chunk:
                    return
                data += chunk
            head, _, rest = data.partition(b"\r\n\r\n")
            lines = head.decode("latin-1").split("\r\n")
            method, target, _ = lines[0].split(" ", 2)
            headers = {k.lower(): v for k, _, v in (line.partition(": ") for line in lines[1:])}
            seen.append((method, target, headers.get("proxy-authorization")))
            host, port = target.rsplit(":", 1)
            upstream = socket.create_connection((host, int(port)), timeout=5)
            self.request.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            if rest:
                upstream.sendall(rest)

            def copy(source, sink):
                try:
                    while chunk := source.recv(65536):
                        sink.sendall(chunk)
                except OSError:
                    pass
                finally:
                    for s in (source, sink):
                        try:
                            s.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass
            back = threading.Thread(target=copy, args=(upstream, self.request), daemon=True)
            back.start()
            copy(self.request, upstream)
            back.join(5)
            upstream.close()

    return _Gateway(("127.0.0.1", 0), Tunnel)


def test_a_real_gateway_carries_the_agents_calls_and_only_the_customers_bundle_lets_them_verify(tmp_path, monkeypatch):
    for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("no_proxy", "nothing.invalid")      # so neither the environment nor Windows' settings bypass it
    monkeypatch.setattr(agent, "CA", str(tmp_path / "ca.pem"))
    pem, cert, key = _certificates(tmp_path)
    reached = []

    class Endpoint(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - the standard library's name
            reached.append((self.path, self.headers.get("User-Agent")))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *args):
            pass

    endpoint = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Endpoint)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    endpoint.socket = context.wrap_socket(endpoint.socket, server_side=True)
    seen: list = []
    gateway = _gateway(seen)
    for server in (endpoint, gateway):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"https://127.0.0.1:{endpoint.server_port}/open"
    via = f"http://user:pass@127.0.0.1:{gateway.server_address[1]}"
    try:
        through = agent._try(lambda: agent._get(url, {}, agent._gateway({"via": via, "ca": pem})))
        unbundled = agent._try(lambda: agent._get(url, {}, agent._gateway({"via": via})))
        tunnels = len(seen)
        direct = agent._try(lambda: agent._get(url, {}))
    finally:
        endpoint.shutdown()
        gateway.shutdown()
    # through the gateway, with the customer's bundle: carried, verified, and signed in to the gateway as given
    assert through["ok"] is True, through
    assert seen[0] == ("CONNECT", f"127.0.0.1:{endpoint.server_port}",
                       "Basic " + base64.b64encode(b"user:pass").decode("ascii"))
    assert reached[0][0] == "/open" and reached[0][1].startswith("arvaken-stop-test-agent")
    # through it without the bundle: refused as the certificate is not one the default bundle trusts
    assert unbundled == {"at": unbundled["at"], "ok": False, "error": "SSLError"}
    # and without a gateway, the call goes straight there, never through it, and no bundle of the customer's is used
    assert len(seen) == tunnels == 2 and direct["ok"] is False and direct["error"] == "Unreachable"
    assert len(reached) == 1


def test_through_a_gateway_only_the_paths_the_invocation_names_go_through_it(an_agent):
    """The founder's condition a (28 October 2026): attached to its calls to outside services, the agent's call with a
    key and its open-internet call go through the gateway; its own calls, the session taken for the other identity and
    that identity's calls go directly."""
    made, gets = an_agent
    outside = ["open_internet", "outside_key"]
    agent.handler({"action": "assume", "via": VIA, "ca": PEM, "through": outside}, None)
    out = agent.handler({"n": 3, "session": {"key": "k", "secret": "s", "token": "t"}, "via": VIA, "ca": PEM,
                         "through": outside}, None)
    assert all(b["ok"] for b in out["beats"].values()), out
    assert [name for name, _ in made] == ["sts", "s3", "s3"]
    assert all(kw["config"].proxies is None and kw["verify"] is None for _, kw in made)
    assert [url for url, _ in gets] == ["https://stop-test.example/key", "https://stop-test.example/open"]
    assert all(gw == ({"proxies": {"http": VIA, "https": VIA}, "proxies_config": {"proxy_ca_bundle": agent.CA}},
                      agent.CA) for _, gw in gets)


def test_the_shipped_agent_is_agent_py_statement_for_statement():
    """What the function runs is agent.py without its docstring, its comments, and half its indentation: the same
    syntax tree, so the same program."""
    import ast
    from arvaken_stop_test.aws.stack import agent_code
    tree = ast.parse(Path(agent.__file__).read_text(encoding="utf-8"))
    tree.body = tree.body[1:]                       # its module docstring, which is not shipped
    shipped = agent_code()
    assert ast.dump(ast.parse(shipped)) == ast.dump(tree)
    assert "#" not in shipped.replace("#{", "") and "\n    def " not in shipped and "\n  def " in shipped
