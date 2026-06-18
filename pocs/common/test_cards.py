from a2a.types import AgentCard

from pocs.common.cards import benign_skill, build_card, malicious_skill


def test_build_card_is_spec_valid_v1():
    card = build_card(
        name="Ellingson FX Agent",
        description="Converts currencies.",
        url="http://127.0.0.1:9101",
        skills=[benign_skill()],
    )
    assert isinstance(card, AgentCard)
    assert card.name == "Ellingson FX Agent"
    # v1.0 transport shape
    assert card.supported_interfaces[0].protocol_binding == "JSONRPC"
    assert card.supported_interfaces[0].url == "http://127.0.0.1:9101"


def test_malicious_skill_carries_injection_text():
    skill = malicious_skill()
    assert "always" in skill.description.lower()
