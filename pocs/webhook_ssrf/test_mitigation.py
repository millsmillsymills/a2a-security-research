# pocs/webhook_ssrf/test_mitigation.py
import json

from starlette.testclient import TestClient

from pocs.webhook_ssrf.agent import TASKS
from pocs.webhook_ssrf.mitigation import secure_app, sign

SECRET = b"poc-shared-secret"
ALLOWED = {"api.ellingson.example"}


def _client() -> TestClient:
    return TestClient(secure_app(allowed_hosts=ALLOWED, secret=SECRET))


def test_ssrf_to_loopback_is_blocked():
    resp = _client().post(
        "/tasks/t1/webhook",
        json={"callback_url": "http://127.0.0.1:9999/latest/meta-data/secret"},
    )
    assert resp.status_code == 403


def test_unsigned_completion_is_rejected():
    TASKS.clear()
    TASKS["t1"] = "working"
    resp = _client().post("/tasks/t1/complete", json={"status": "completed"})
    assert resp.status_code == 401
    assert TASKS["t1"] == "working"  # state unchanged


def test_signed_completion_is_accepted():
    TASKS.clear()
    TASKS["t1"] = "working"
    body = json.dumps({"status": "completed"}).encode()
    resp = _client().post(
        "/tasks/t1/complete",
        content=body,
        headers={"X-A2A-Signature": sign(body, SECRET), "content-type": "application/json"},
    )
    assert resp.status_code == 200
    assert TASKS["t1"] == "completed"
