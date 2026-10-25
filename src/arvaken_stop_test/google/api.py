"""Google Cloud's REST API, as the kit calls it: the standard library, with the customer's own credentials from the
Google Cloud CLI (`gcloud`), as Cloud Shell has them. No Google library is needed.

`Google` is what the run is given: the command line makes one from gcloud, and the tests a fake that answers the same
calls. A refusal is raised with Google's status and its reason's code, never its message, which can name what was
asked for.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any

# gcloud gives back the token it holds, which may be most of an hour old, and makes a new one only once that has
# expired: so a token is asked for again every few minutes, and at once when Google refuses one (Google.call). A run
# lasts longer than a token: one kept from its start, for 50 minutes, ran out 23 minutes in (25 October 2026).
TOKEN_LIFE = 4 * 60.0


class GoogleError(Exception):
    def __init__(self, status: int, code: str):
        super().__init__(f"Google answered {status} {code}")
        self.status, self.code = status, code


def gcloud() -> str:
    found = shutil.which("gcloud") or shutil.which("gcloud.cmd")
    if not found:
        raise FileNotFoundError("the Google Cloud CLI (gcloud) is not installed or not on the PATH")
    return found


class Tokens:
    """The customer's access token, and an identity token for calling the test agent, each from gcloud and kept for
    most of its life."""

    def __init__(self, run: Callable[[list[str]], str] | None = None, clock: Callable[[], float] = time.time):
        self._run = run or (lambda args: subprocess.run([gcloud(), *args], capture_output=True, text=True,
                                                         check=True).stdout.strip())
        self._clock = clock
        self._kept: dict[str, tuple[str, float]] = {}

    def _get(self, which: str, args: list[str]) -> str:
        token, until = self._kept.get(which, ("", 0.0))
        if not token or self._clock() >= until:
            token = self._run(args)
            self._kept[which] = (token, self._clock() + TOKEN_LIFE)
        return token

    def forget(self, which: str) -> None:
        """Drop a kept token, so the next call asks gcloud again: for one Google has refused."""
        self._kept.pop(which, None)

    def access(self) -> str:
        return self._get("access", ["auth", "print-access-token"])

    def identity(self) -> str:
        return self._get("identity", ["auth", "print-identity-token"])

    def account(self) -> str:
        return self._run(["config", "get-value", "account"])


class Google:
    """One project's calls, each a REST request with the customer's access token."""

    def __init__(self, project: str, region: str, tokens: Tokens | None = None, timeout: float = 30.0):
        self.project, self.region, self.tokens, self.timeout = project, region, tokens or Tokens(), timeout

    def call(self, method: str, url: str, body: Any = None, *, identity: bool = False,
             raw: bytes | None = None) -> Any:
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        which = "identity" if identity else "access"
        for asked in (1, 2):
            token = self.tokens.identity() if identity else self.tokens.access()
            headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
            request = urllib.request.Request(url, data=data, method=method, headers=headers)
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as r:  # noqa: S310 - https, built here
                    text = r.read()
                break
            except urllib.error.HTTPError as e:
                if e.code == 401 and asked == 1:
                    # the token ran out: gcloud makes a new one once it has, and the call is made once more with it
                    self.tokens.forget(which)
                    continue
                raise _refusal(e) from None
        return json.loads(text) if text else {}


def _refusal(e: urllib.error.HTTPError) -> GoogleError:
    """Google's refusal, by its status and its reason's code, never its message."""
    code = "HTTP"
    try:
        error = json.loads(e.read() or b"{}").get("error", {})
        # Google's own error, by its status or reason; the test agent's, by the code it gives
        code = error if isinstance(error, str) else str(
            error.get("status") or (error.get("errors") or [{}])[0].get("reason") or "HTTP")
    except (ValueError, AttributeError):
        pass
    return GoogleError(e.code, code)
