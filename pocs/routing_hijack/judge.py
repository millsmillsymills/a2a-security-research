"""LLM-as-judge agent selection with a record/replay cassette.

`mode="replay"` (default) reads a recorded transcript so a clean clone runs
with no ANTHROPIC_API_KEY. `mode="live"` calls Claude and updates the cassette.
"""

import hashlib
import json
import re
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


def _match_candidate(raw: str, candidates: list[Candidate]) -> str:
    """Resolve the judge's free text to exactly one candidate name.

    Match on whole-token boundaries, not substrings. For names that overlap on a
    word character — the realistic case here, since agent names are identifiers
    like ``ellingson_fx`` vs ``ellingson_fx_eu`` — the ``\\b`` boundary lands
    between ``fx`` and ``_eu`` (``_`` is a word char), so the shorter name does
    not match inside the longer one and the correct candidate is returned. For
    names that overlap on a *non-word* character (``agent-a`` vs ``agent-a-b``),
    ``\\b`` matches both, so this raises an ambiguity error rather than guessing
    — it never silently hands back the wrong agent. Output that maps to no
    candidate or to more than one always raises: in a routing PoC the selection
    is the security boundary, so unparseable or ambiguous output cannot be
    treated as a confident pick.
    """
    names = [c.name for c in candidates]
    matched = [n for n in names if re.search(rf"\b{re.escape(n)}\b", raw, re.IGNORECASE)]
    if len(matched) == 1:
        return matched[0]
    if matched:
        raise ValueError(f"judge output ambiguously matched {matched} in {names}: {raw!r}")
    raise ValueError(f"judge output matched no candidate in {names}: {raw!r}")


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
    else:
        raise ValueError(f"unknown mode: {mode}")
    # Validate before recording: a live no-match must not persist a poison
    # cassette entry that then raises forever on replay.
    choice = _match_candidate(raw, candidates)
    if mode == "live":
        _record(key, raw)
    return choice
