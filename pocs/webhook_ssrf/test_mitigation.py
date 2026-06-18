# pocs/webhook_ssrf/test_mitigation.py
import json
import socket

import pytest
from starlette.testclient import TestClient

from pocs.webhook_ssrf.agent import TASKS
from pocs.webhook_ssrf.mitigation import secure_app, sign

SECRET = b"poc-shared-secret"
ALLOWED = {"api.ellingson.example"}


@pytest.fixture(autouse=True)
def _reset_tasks():
    TASKS.clear()
    TASKS["t1"] = "working"
    yield
    TASKS.clear()


def _client() -> TestClient:
    return TestClient(secure_app(allowed_hosts=ALLOWED, secret=SECRET))


def _addrinfo(ip: str):
    def fake(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port))]

    return fake


def test_ssrf_to_loopback_is_blocked(monkeypatch):
    called = {"n": 0}
    monkeypatch.setattr(
        "pocs.webhook_ssrf.mitigation.httpx.get",
        lambda *a, **k: called.__setitem__("n", called["n"] + 1),
    )
    resp = _client().post(
        "/tasks/t1/webhook",
        json={"callback_url": "http://127.0.0.1:9999/latest/meta-data/secret"},
    )
    assert resp.status_code == 403
    assert called["n"] == 0  # blocked before any outbound fetch


def test_allow_listed_host_is_fetched(monkeypatch):
    captured = {}

    def fake_get(url, headers, timeout):
        captured["url"] = url
        captured["host_header"] = headers["Host"]

        class R:
            text = "callback-ack"

        return R()

    monkeypatch.setattr("socket.getaddrinfo", _addrinfo("93.184.216.34"))
    monkeypatch.setattr("pocs.webhook_ssrf.mitigation.httpx.get", fake_get)
    resp = _client().post(
        "/tasks/t1/webhook",
        json={"callback_url": "http://api.ellingson.example/hook"},
    )
    assert resp.status_code == 200
    assert resp.json()["fetched"] == "callback-ack"
    assert "93.184.216.34" in captured["url"]  # connection pinned to the validated IP
    assert captured["host_header"] == "api.ellingson.example"


def test_dns_rebinding_to_loopback_is_blocked(monkeypatch):
    called = {"n": 0}
    monkeypatch.setattr("socket.getaddrinfo", _addrinfo("127.0.0.1"))
    monkeypatch.setattr(
        "pocs.webhook_ssrf.mitigation.httpx.get",
        lambda *a, **k: called.__setitem__("n", called["n"] + 1),
    )
    resp = _client().post(
        "/tasks/t1/webhook",
        json={"callback_url": "http://api.ellingson.example/hook"},
    )
    assert resp.status_code == 403  # allow-listed name resolving to loopback is rejected
    assert called["n"] == 0


def test_non_http_scheme_is_blocked():
    resp = _client().post("/tasks/t1/webhook", json={"callback_url": "file:///etc/passwd"})
    assert resp.status_code == 403


def test_missing_callback_url_is_clean_4xx():
    resp = _client().post("/tasks/t1/webhook", json={"not_a_url": 1})
    assert resp.status_code == 400


def test_unsigned_completion_is_rejected():
    resp = _client().post("/tasks/t1/complete", json={"status": "completed"})
    assert resp.status_code == 401
    assert TASKS["t1"] == "working"  # state unchanged


def test_wrong_signature_is_rejected():
    body = json.dumps({"status": "completed"}).encode()
    resp = _client().post(
        "/tasks/t1/complete",
        content=body,
        headers={"X-A2A-Signature": "deadbeef", "content-type": "application/json"},
    )
    assert resp.status_code == 401
    assert TASKS["t1"] == "working"


def test_signed_completion_is_accepted():
    body = json.dumps({"status": "completed"}).encode()
    resp = _client().post(
        "/tasks/t1/complete",
        content=body,
        headers={"X-A2A-Signature": sign("t1", body, SECRET), "content-type": "application/json"},
    )
    assert resp.status_code == 200
    assert TASKS["t1"] == "completed"


def test_signature_for_one_task_is_rejected_on_another():
    TASKS["t2"] = "working"
    body = json.dumps({"status": "completed"}).encode()
    resp = _client().post(
        "/tasks/t2/complete",
        content=body,
        headers={"X-A2A-Signature": sign("t1", body, SECRET), "content-type": "application/json"},
    )
    assert resp.status_code == 401  # signature bound to t1 cannot complete t2
    assert TASKS["t2"] == "working"
