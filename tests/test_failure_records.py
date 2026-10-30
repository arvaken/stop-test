"""Each test agent's failure record (D646, item 4: the founder, 29 October 2026): every failed call's code, the HTTP
status, the provider's own reason and status where its error has them, and the token's times; never a message, which
can name resources and principals. Errors as botocore and urllib raise them, built here as each library builds them."""
from __future__ import annotations

import io
import json
import urllib.error

import botocore.exceptions

from arvaken_stop_test.aws import agent as aws_agent
from arvaken_stop_test.google import agent as google_agent

SECRET = "arn:aws:iam::111122223333:role/someone-elses"


def client_error(code: str, status: int, **fields) -> botocore.exceptions.ClientError:
    return botocore.exceptions.ClientError(
        {"Error": {"Code": code, "Message": f"User {SECRET} is not authorized"},
         "ResponseMetadata": {"HTTPStatusCode": status}, **fields}, "PutObject")


def http_error(status: int, body: dict | bytes) -> urllib.error.HTTPError:
    raw = body if isinstance(body, bytes) else json.dumps(body).encode()
    return urllib.error.HTTPError("https://storage.googleapis.com/x", status, "Forbidden", {}, io.BytesIO(raw))


def raising(e: Exception):
    def fn(*args):
        raise e
    return fn


def test_the_aws_agent_records_the_code_the_status_and_aws_own_reason_never_a_message():
    beat = aws_agent._try(raising(client_error("AccessDenied", 403)))
    assert {k: v for k, v in beat.items() if k != "at"} == {"ok": False, "error": "AccessDenied", "status": 403,
                                                            "reason": None}
    throttled = aws_agent._try(raising(client_error("TooManyRequestsException", 429,
                                                    Reason="ReservedFunctionConcurrentInvocationLimitExceeded")))
    assert (throttled["status"], throttled["reason"]) == (429, "ReservedFunctionConcurrentInvocationLimitExceeded")
    worded = aws_agent._try(raising(client_error("ValidationException", 400, reason=f"no access for {SECRET}")))
    assert worded["reason"] is None                     # a reason that is not one of AWS's words is not kept
    unreachable = aws_agent._try(raising(TimeoutError("timed out")))
    assert (unreachable["error"], unreachable["status"], unreachable["reason"]) == ("Unreachable", None, None)
    assert SECRET not in json.dumps([beat, throttled, worded, unreachable])


def test_the_google_agent_records_storages_reason_and_googles_status_never_a_message():
    storage = google_agent._record(http_error(403, {"error": {"code": 403, "message": f"{SECRET} does not have access",
                                                              "errors": [{"message": "no", "domain": "global",
                                                                          "reason": "forbidden"}]}}))
    assert storage == {"error": "HTTP403", "status": 403, "reason": "forbidden", "provider_status": None}
    newer = google_agent._record(http_error(403, {"error": {
        "code": 403, "message": SECRET, "status": "PERMISSION_DENIED",
        "details": [{"@type": "type.googleapis.com/google.rpc.Help", "reason": "not this"},
                    {"@type": "type.googleapis.com/google.rpc.ErrorInfo", "reason": "IAM_PERMISSION_DENIED"}]}}))
    assert (newer["reason"], newer["provider_status"]) == ("IAM_PERMISSION_DENIED", "PERMISSION_DENIED")
    plain = google_agent._record(http_error(404, b"Not Found: the service account is disabled"))
    assert plain == {"error": "HTTP404", "status": 404, "reason": None, "provider_status": None}
    assert SECRET not in json.dumps([storage, newer, plain])


def test_the_google_agents_own_calls_record_the_step_that_failed_and_the_token_it_used(monkeypatch):
    monkeypatch.setenv("BUCKET", "b")
    monkeypatch.setenv("ENDPOINT", "https://stop-test.example")
    google_agent._own.update(token=None, until=0.0, issued=0.0)
    answers = {"metadata": http_error(404, b"not found")}

    def call(url, headers=None, data=None, method="GET"):
        if "metadata" in url:
            if "metadata" in answers:
                raise answers.pop("metadata")
            return json.dumps({"access_token": "t", "expires_in": 3599}).encode()
        if method == "POST" and "/upload/" in url:
            raise http_error(401, {"error": {"code": 401, "errors": [{"reason": "authError"}]}})
        return b"ok"
    monkeypatch.setattr(google_agent, "_call", call)
    first = google_agent.beat({"n": 1})["own_calls"]
    assert (first["error"], first["step"]) == ("HTTP404", "token") and "token_expires" not in first
    second = google_agent.beat({"n": 2})["own_calls"]
    assert (second["error"], second["reason"], second["step"]) == ("HTTP401", "authError", "write")
    assert second["token_expires"] - second["token_issued"] == 3599
