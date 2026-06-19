# pocs/webhook_ssrf/test_mitigation.py
import json
import socket

import httpx
import pytest
from starlette.testclient import TestClient

from pocs.webhook_ssrf.agent import TASKS
from pocs.webhook_ssrf.mitigation import _resolve_pinned_ip, secure_app, sign

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
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET

    def fake(host, port, *args, **kwargs):
        return [(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port))]

    return fake


def _addrinfo_multi(*ips: str):
    def fake(host, port, *args, **kwargs):
        return [
            (
                socket.AF_INET6 if ":" in ip else socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                (ip, port),
            )
            for ip in ips
        ]

    return fake


def test_ssrf_to_loopback_is_blocked(monkeypatch):
    called = {"n": 0}
    monkeypatch.setattr("socket.getaddrinfo", _addrinfo("127.0.0.1"))
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
    # Full pinned URL: connection pinned to the validated IP, port and path preserved.
    assert captured["url"] == "http://93.184.216.34:80/hook"
    assert captured["host_header"] == "api.ellingson.example"


def test_allow_listed_host_resolving_to_ipv6_is_fetched(monkeypatch):
    captured = {}

    def fake_get(url, headers, timeout):
        captured["url"] = url

        class R:
            text = "callback-ack"

        return R()

    monkeypatch.setattr("socket.getaddrinfo", _addrinfo("2606:2800:220:1:248:1893:25c8:1946"))
    monkeypatch.setattr("pocs.webhook_ssrf.mitigation.httpx.get", fake_get)
    resp = _client().post(
        "/tasks/t1/webhook",
        json={"callback_url": "http://api.ellingson.example/hook"},
    )
    assert resp.status_code == 200
    assert captured["url"] == "http://[2606:2800:220:1:248:1893:25c8:1946]:80/hook"


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


def test_mixed_global_and_loopback_records_is_blocked(monkeypatch):
    # The control hinges on `any(not is_global)` over the *full* resolved set; a
    # regression to "check addresses[0]" would pass every single-address test.
    called = {"n": 0}
    monkeypatch.setattr("socket.getaddrinfo", _addrinfo_multi("93.184.216.34", "127.0.0.1"))
    monkeypatch.setattr(
        "pocs.webhook_ssrf.mitigation.httpx.get",
        lambda *a, **k: called.__setitem__("n", called["n"] + 1),
    )
    resp = _client().post(
        "/tasks/t1/webhook",
        json={"callback_url": "http://api.ellingson.example/hook"},
    )
    assert resp.status_code == 403
    assert called["n"] == 0


def test_unresolvable_allow_listed_host_is_blocked(monkeypatch):
    def boom(*a, **k):
        raise socket.gaierror("name or service not known")

    called = {"n": 0}
    monkeypatch.setattr("socket.getaddrinfo", boom)
    monkeypatch.setattr(
        "pocs.webhook_ssrf.mitigation.httpx.get",
        lambda *a, **k: called.__setitem__("n", called["n"] + 1),
    )
    resp = _client().post(
        "/tasks/t1/webhook",
        json={"callback_url": "http://api.ellingson.example/hook"},
    )
    assert resp.status_code == 403
    assert called["n"] == 0


def test_resolve_pinned_ip_fails_closed_on_resolution_errors(monkeypatch):
    for exc in (socket.gaierror("boom"), UnicodeError("over-long IDNA label")):

        def raise_exc(*a, _e=exc, **k):
            raise _e

        monkeypatch.setattr("socket.getaddrinfo", raise_exc)
        assert _resolve_pinned_ip("api.ellingson.example", 80) is None


def test_ipv6_loopback_literal_is_blocked():
    resp = _client().post("/tasks/t1/webhook", json={"callback_url": "http://[::1]:9999/hook"})
    assert resp.status_code == 403


def test_allow_listed_host_resolving_to_ipv6_loopback_is_blocked(monkeypatch):
    called = {"n": 0}
    monkeypatch.setattr("socket.getaddrinfo", _addrinfo("::1"))
    monkeypatch.setattr(
        "pocs.webhook_ssrf.mitigation.httpx.get",
        lambda *a, **k: called.__setitem__("n", called["n"] + 1),
    )
    resp = _client().post(
        "/tasks/t1/webhook",
        json={"callback_url": "http://api.ellingson.example/hook"},
    )
    assert resp.status_code == 403
    assert called["n"] == 0


def test_allow_listed_host_resolving_to_metadata_ip_is_blocked(monkeypatch):
    # The headline SSRF target: a rebinding allow-listed host pointing at the
    # cloud metadata endpoint must be rejected at the IP-pinning stage.
    called = {"n": 0}
    monkeypatch.setattr("socket.getaddrinfo", _addrinfo("169.254.169.254"))
    monkeypatch.setattr(
        "pocs.webhook_ssrf.mitigation.httpx.get",
        lambda *a, **k: called.__setitem__("n", called["n"] + 1),
    )
    resp = _client().post(
        "/tasks/t1/webhook",
        json={"callback_url": "http://api.ellingson.example/latest/meta-data/"},
    )
    assert resp.status_code == 403
    assert called["n"] == 0


def test_malformed_webhook_body_is_clean_4xx():
    resp = _client().post(
        "/tasks/t1/webhook",
        content=b"not json",
        headers={"content-type": "application/json"},
    )
    assert resp.status_code == 400


def test_outbound_fetch_failure_is_502(monkeypatch):
    def boom(*a, **k):
        raise httpx.ConnectTimeout("timed out")

    monkeypatch.setattr("socket.getaddrinfo", _addrinfo("93.184.216.34"))
    monkeypatch.setattr("pocs.webhook_ssrf.mitigation.httpx.get", boom)
    resp = _client().post(
        "/tasks/t1/webhook",
        json={"callback_url": "http://api.ellingson.example/hook"},
    )
    assert resp.status_code == 502


def test_signed_non_json_completion_is_clean_4xx():
    body = b"not json"
    resp = _client().post(
        "/tasks/t1/complete",
        content=body,
        headers={"X-A2A-Signature": sign("t1", body, SECRET), "content-type": "application/json"},
    )
    assert resp.status_code == 400
    assert TASKS["t1"] == "working"  # state unchanged


def test_signed_completion_missing_status_is_clean_4xx():
    body = json.dumps({"not_status": 1}).encode()
    resp = _client().post(
        "/tasks/t1/complete",
        content=body,
        headers={"X-A2A-Signature": sign("t1", body, SECRET), "content-type": "application/json"},
    )
    assert resp.status_code == 400
    assert TASKS["t1"] == "working"
