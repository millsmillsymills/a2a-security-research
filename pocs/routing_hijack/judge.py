"""LLM-as-judge agent selection with a record/replay cassette.

`mode="replay"` (default) reads a recorded transcript so a clean clone runs
with no ANTHROPIC_API_KEY. `mode="live"` calls Claude and updates the cassette.
"""

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

_MODEL = "claude-haiku-4-5-20251001"
_CASSETTE = Path(__file__).parent / "cassette.json"


@dataclass(frozen=True)
class Candidate:
    name: str
    card_text: str
    identity: str


def _key(task: str, prompt: str) -> str:
    return hashlib.sha256(f"{task}\n{prompt}".encode()).hexdigest()


def _build_prompt(task: str, candidates: list[Candidate]) -> str:
    lines = [f"Task: {task}", "", "Candidate agents:"]
    for c in candidates:
        lines.append(f"- name={c.name}: {c.card_text}")
    lines.append("")
    lines.append("Reply with ONLY the name of the single best agent.")
    return "\n".join(lines)


def _load_cassette() -> dict[str, str]:
    if _CASSETTE.exists():
        return json.loads(_CASSETTE.read_text())
    return {}


def _record(key: str, value: str) -> None:
    data = _load_cassette()
    data[key] = value
    _CASSETTE.write_text(json.dumps(data, indent=2, sort_keys=True))


def _ask_claude(prompt: str) -> str:
    import anthropic

    client = anthropic.Anthropic()
    resp = client.messages.create(
        model=_MODEL,
        max_tokens=16,
        messages=[{"role": "user", "content": prompt}],
    )
    return next(b.text for b in resp.content if b.type == "text").strip()


def select_agent(task: str, candidates: list[Candidate], *, mode: str = "replay") -> str:
    prompt = _build_prompt(task, candidates)
    key = _key(task, prompt)
    if mode == "replay":
        cassette = _load_cassette()
        if key not in cassette:
            raise KeyError(
                "No cassette entry; run select_agent(..., mode='live') with "
                "ANTHROPIC_API_KEY set to record it."
            )
        raw = cassette[key]
    elif mode == "live":
        raw = _ask_claude(prompt)
        _record(key, raw)
    else:
        raise ValueError(f"unknown mode: {mode}")
    # Normalize the model's free text to a candidate name. A no-match (refusal,
    # apology, hallucinated name) must surface — silently returning candidates[0]
    # would treat unparseable output as a confident selection.
    for c in candidates:
        if c.name.lower() in raw.lower():
            return c.name
    raise ValueError(f"judge output matched no candidate: {raw!r}")
