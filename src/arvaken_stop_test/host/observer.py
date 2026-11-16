"""The observer (D709; mark's docs/platform/STOP-TEST-ANY-HOST-DESIGN.md, section 1; decision KH5): the kit's own
program, on a second machine you control, never the agent's host, reachable from the host at the address you give. It
runs inside the kit's own process, for the run alone, so the mark you give and every arrival are read from one clock,
this machine's.

It is where the paths' calls arrive, and it keeps each arrival's time by its own clock:

- `GET /key`, with the run's key as a bearer token: the keyed path's call. Any other key is answered 401 and is no
  arrival; it is counted (`refused_keys`), never kept.
- `GET /open/<run>`: the open path's call, with no key. The run's name in the address keeps a stray request to the port
  from counting as the copy's.
- `POST /report`, with the run's key: the probe's report of a beat, each path's outcome by the copy's clock and its
  failure record's code and status (the probe's host.report). Only those fields are kept, each checked; the model's
  path is timed by the reports that say its call worked.
- `POST /witness`, with the witness's own key: one beat of the kit's witness on the host.

Anything else is answered 404, and is not kept. The observer writes no log and prints nothing for a request. Once the
run is over it answers every request 410, which ends the probe's and the witness's beats, for GRACE seconds, then stops.

**TLS.** It presents a certificate made for the run (`certificate`), for the address you give, valid for the run's
longest life; the probe and the witness trust that certificate alone (the probe's host.pinned). Its private key is
written only into the run's own folder, which the kit removes when the run ends, and is used for nothing else.

**Signed.** At the end its arrivals are signed with a key it makes for the run (Ed25519), never written to disk; the
signed file's SHA-256 and the key's public half go into the result (the design's section 5). As with the result's own
signature, it shows the file has not changed since it was signed, not who ran the kit or that the run was honest.
"""
from __future__ import annotations

import base64
import hmac
import ipaddress
import json
import re
import socket
import socketserver
import ssl
import threading
import time
from collections import Counter
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from arvaken_stop_test import result

PATHS = ("outside_key", "open_internet")        # the calls that arrive here themselves
REPORTED = ("outside_key", "open_internet", "model")
GRACE = 5.0                 # seconds the observer answers 410 once the run is over, before it stops
CONNECTION_TIMEOUT = 5.0    # seconds a connection may take to send its request
REPORT_LIMIT = 4096         # bytes of a report, at most, as the probe makes it (the probe's host.REPORT_LIMIT)
BEAT_LIMIT = 256            # bytes of a witness's beat, at most
CODE = re.compile(r"[A-Za-z0-9_.:-]{1,64}")      # a failure's code, as the probe's core names one
HOSTNAME = re.compile(r"(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}"
                      r"[A-Za-z0-9])?)*")
FORMAT = "stop-test-arrivals/1"


def address(text: str) -> tuple[str, int] | None:
    """The observer's address as you give it, `host:port` (a host name, an IPv4 address, or a bracketed IPv6 one, and a
    port): its host and port; None where it is not one."""
    found = re.fullmatch(r"(\[[0-9A-Fa-f:.]+\]|[^:\[\]/@\s]+):(\d{1,5})", text.strip()) if isinstance(text, str) else None
    if not found:
        return None
    host, port = found.group(1), int(found.group(2))
    if not 0 < port < 65536:
        return None
    bare = host[1:-1] if host.startswith("[") else host
    try:
        ip = ipaddress.ip_address(bare)
        if host.startswith("[") != (ip.version == 6):
            return None
    except ValueError:
        if host.startswith("[") or not HOSTNAME.fullmatch(host):
            return None
    return bare, port


def url(host: str, port: int) -> str:
    """The observer's address as the probe's settings hold it, `https://host:port`."""
    try:
        bracketed = f"[{host}]" if ipaddress.ip_address(host).version == 6 else host
    except ValueError:
        bracketed = host
    return f"https://{bracketed}:{port}"


def certificate(host: str, hours: float) -> tuple[str, bytes]:
    """A certificate made for the run, for `host`, valid for `hours`, and its private key: the certificate's PEM, which
    the probe and the witness pin, and the key's, which only the observer uses."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "arvaken-stop-test observer")])
    try:
        alt: Any = x509.IPAddress(ipaddress.ip_address(host))
    except ValueError:
        alt = x509.DNSName(host)
    now = datetime.now(timezone.utc)
    ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(hours=hours))
            .add_extension(x509.SubjectAlternativeName([alt]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                         crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(ski, critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski), critical=False)
            .sign(key, hashes.SHA256()))
    pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    return pem, private


def _bearer(header: str | None, key: str) -> bool:
    given = (header or "")[len("Bearer "):] if (header or "").startswith("Bearer ") else ""
    return hmac.compare_digest(given.encode(), key.encode())


def _beat(b: Any) -> dict | None:
    """One path's outcome in a report, as the observer keeps it, or None where it is not one."""
    if not isinstance(b, dict) or not isinstance(b.get("ok"), bool):
        return None
    at, error, status = b.get("at"), b.get("error"), b.get("status")
    if not (isinstance(at, (int, float)) and not isinstance(at, bool)):
        return None
    if error is not None and not (isinstance(error, str) and CODE.fullmatch(error)):
        return None
    if status is not None and not (isinstance(status, int) and not isinstance(status, bool) and 100 <= status <= 599):
        return None
    return {"at": float(at), "ok": b["ok"], "error": None if b["ok"] else error, "status": None if b["ok"] else status}


class Observer:
    """The run's observer: start, then read each path's arrivals as they come, then close."""

    def __init__(self, run: str, key: str, witness_key: str, host: str, port: int, folder: Path, hours: float,
                 listen: str | None = None, clock: Callable[[], float] = time.time):
        from arvaken_stop_test.result import new_key
        self.run, self.key, self.witness_key, self.host, self.port = run, key, witness_key, host, port
        self.folder, self.hours, self.clock = folder, hours, clock
        try:
            v6 = ipaddress.ip_address(host).version == 6
        except ValueError:
            v6 = False
        self.listen = listen if listen is not None else ("::" if v6 else "0.0.0.0")
        self.signing = new_key()
        self.lock = threading.Lock()
        self.arrived: dict[str, list[float]] = {p: [] for p in PATHS}
        self.witnessed: list[float] = []
        self.reported: list[tuple[float, int, dict[str, dict]]] = []
        self.refused_keys = 0
        self.clients: set[str] = set()      # whose client made the probe's calls, as each report said
        self.sources: Counter[str] = Counter()
        self.over = False
        self.server: ThreadingHTTPServer | None = None
        self.thread: threading.Thread | None = None
        self.certificate = ""

    # -- serving --------------------------------------------------------------------------------------------------------
    def start(self) -> None:
        """Its certificate made and written into the run's folder with its key, and its server started."""
        self.certificate, private = certificate(self.host, self.hours)
        cert_file, key_file = self.folder / "observer-certificate.pem", self.folder / "observer-key.pem"
        cert_file.write_text(self.certificate, encoding="utf-8", newline="\n")
        key_file.write_bytes(private)
        try:
            key_file.chmod(0o600)
        except OSError:  # pragma: no cover - where the file system has no such modes, the folder is the run's own
            pass
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(cert_file, key_file)
        observer = self

        class Handler(BaseHTTPRequestHandler):
            timeout = CONNECTION_TIMEOUT
            server_version, sys_version = "arvaken-stop-test-observer", ""

            def log_message(self, *args: Any) -> None:     # no log, nothing printed
                return

            def do_GET(self) -> None:
                observer._get(self)

            def do_POST(self) -> None:
                observer._post(self)

        family = socket.AF_INET6 if ":" in self.listen else socket.AF_INET

        class Server(ThreadingHTTPServer):
            daemon_threads = True
            address_family = family

            def server_bind(self) -> None:          # as HTTPServer's, without looking up this machine's name
                socketserver.TCPServer.server_bind(self)
                self.server_name, self.server_port = str(self.server_address[0]), int(self.server_address[1])

            def handle_error(self, request: Any, client_address: Any) -> None:     # a stray TLS client is no arrival
                return

        server = Server((self.listen, self.port), Handler)
        server.socket = context.wrap_socket(server.socket, server_side=True, do_handshake_on_connect=False)
        self.port = server.server_address[1]
        self.server = server
        self.thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.2},
                                       name="arvaken-stop-test-observer", daemon=True)
        self.thread.start()

    def url(self) -> str:
        return url(self.host, self.port)

    def _answer(self, h: BaseHTTPRequestHandler, status: int) -> None:
        body = b"ok\n" if status == 200 else b""
        h.send_response(status)
        h.send_header("Content-Length", str(len(body)))
        h.send_header("Connection", "close")
        h.end_headers()
        if body:
            h.wfile.write(body)

    def _get(self, h: BaseHTTPRequestHandler) -> None:
        at = self.clock()
        if self.over:
            return self._answer(h, 410)
        if h.path == "/key":
            if not _bearer(h.headers.get("Authorization"), self.key):
                with self.lock:
                    self.refused_keys += 1
                return self._answer(h, 401)
            self._arrive("outside_key", at, h.client_address[0])
            return self._answer(h, 200)
        if h.path == f"/open/{self.run}":
            self._arrive("open_internet", at, h.client_address[0])
            return self._answer(h, 200)
        return self._answer(h, 404)

    def _body(self, h: BaseHTTPRequestHandler, limit: int) -> bytes | None:
        try:
            n = int(h.headers.get("Content-Length") or "-1")
        except ValueError:
            return None
        return h.rfile.read(n) if 0 <= n <= limit else None

    def _post(self, h: BaseHTTPRequestHandler) -> None:
        at = self.clock()
        if self.over:
            return self._answer(h, 410)
        if h.path == "/report":
            if not _bearer(h.headers.get("Authorization"), self.key):
                with self.lock:
                    self.refused_keys += 1
                return self._answer(h, 401)
            body = self._body(h, REPORT_LIMIT)
            try:
                doc = json.loads(body) if body is not None else None
            except ValueError:
                doc = None
            n = doc.get("n") if isinstance(doc, dict) else None
            beats = doc.get("beats") if isinstance(doc, dict) else None
            if not (isinstance(n, int) and not isinstance(n, bool) and isinstance(beats, dict)):
                return self._answer(h, 400)
            kept = {p: b for p, b in ((p, _beat(beats.get(p))) for p in REPORTED if p in beats) if b is not None}
            client = doc.get("http") if doc.get("http") in ("customer", "runtime") else "runtime"
            with self.lock:
                self.reported.append((at, n, kept))
                self.clients.add(client)
                self.sources[h.client_address[0]] += 1
            return self._answer(h, 200)
        if h.path == "/witness":
            if not _bearer(h.headers.get("Authorization"), self.witness_key):
                with self.lock:
                    self.refused_keys += 1
                return self._answer(h, 401)
            if self._body(h, BEAT_LIMIT) is None:
                return self._answer(h, 400)
            with self.lock:
                self.witnessed.append(at)
            return self._answer(h, 200)
        return self._answer(h, 404)

    def _arrive(self, path: str, at: float, source: str) -> None:
        with self.lock:
            self.arrived[path].append(at)
            self.sources[source] += 1

    def close(self, wait: Callable[[float], None] = time.sleep) -> None:
        """The run is over: every request answered 410 for GRACE seconds, which ends the probe's and the witness's
        beats, then the server stopped."""
        self.over = True
        if self.server is None:
            return
        wait(GRACE)
        self.server.shutdown()
        self.server.server_close()
        self.server = None

    # -- reading --------------------------------------------------------------------------------------------------------
    def arrivals(self, path: str) -> list[float]:
        """A path's arrivals, by this machine's clock: its calls, or for the model the reports that say its call
        worked."""
        with self.lock:
            if path in self.arrived:
                return list(self.arrived[path])
            return [at for at, _, beats in self.reported if beats.get(path, {}).get("ok") is True]

    def reports(self) -> list[float]:
        with self.lock:
            return [at for at, _, _ in self.reported]

    def failures(self, path: str) -> list[dict]:
        """The failures the probe reported on a path, each with its arrival here: for the details, never the result."""
        with self.lock:
            return [{"at": at, "n": n, **beats[path]} for at, n, beats in self.reported
                    if path in beats and not beats[path]["ok"]]

    def witness(self) -> list[float]:
        with self.lock:
            return list(self.witnessed)

    def source(self) -> str | None:
        """The address your host's calls came from, as this machine saw it most often; None where none came."""
        with self.lock:
            return self.sources.most_common(1)[0][0] if self.sources else None

    def http_client(self) -> str:
        """Whose client the probe used for its calls here, in the result's words (KC2): yours only where every report
        said so; else the runtime's."""
        with self.lock:
            return result.CLIENTS[0] if self.clients == {"customer"} else result.CLIENTS[1]

    def calls(self) -> int:
        with self.lock:
            return sum(len(v) for v in self.arrived.values()) + len(self.reported) + len(self.witnessed)

    def signed(self) -> tuple[dict, str]:
        """Its arrivals, signed with its own key for the run, and that key's public half."""
        with self.lock:
            doc = {"format": FORMAT, "run": self.run, "clock": "the observer's",
                   "paths": {p: [result.iso(t) for t in self.arrived[p]] for p in PATHS},
                   "reports": [{"at": result.iso(at), "n": n,
                                "beats": {p: {**b, "at": round(b["at"], 3)} for p, b in beats.items()}}
                               for at, n, beats in self.reported],
                   "witness": [result.iso(t) for t in self.witnessed], "refused_keys": self.refused_keys}
        signed = result.sign(doc, self.signing)
        return signed, signed["signature"]["public_key"]


def check_arrivals(doc: Any) -> dict:
    """An arrivals file whose signature checks, else result.NotAResult."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    if not isinstance(doc, dict) or doc.get("format") != FORMAT or not isinstance(doc.get("signature"), dict):
        raise result.NotAResult(f"the file is not {FORMAT}")
    sig = doc["signature"]
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(sig["public_key"], validate=True)).verify(
            base64.b64decode(sig["value"], validate=True), result.canonical(doc))
    except (InvalidSignature, ValueError, KeyError, TypeError) as e:
        raise result.NotAResult("the signature does not check: the file has changed since the observer wrote it") from e
    return doc
