from starlette.testclient import TestClient

from pocs.common.cards import benign_skill, build_card
from pocs.common.server import build_app


def _client() -> TestClient:
    card = build_card(
        name="Ellingson FX Agent",
        description="Converts currencies.",
        url="http://127.0.0.1:9101",
        skills=[benign_skill()],
    )
    return TestClient(build_app(card))


def test_card_served_at_well_known_path():
    resp = _client().get("/.well-known/agent-card.json")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/json")
    assert resp.json()["name"] == "Ellingson FX Agent"


def test_hsts_header_present():
    resp = _client().get("/.well-known/agent-card.json")
    assert "strict-transport-security" in {k.lower() for k in resp.headers}
