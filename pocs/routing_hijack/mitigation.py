"""Mitigation: pin source identity before selection; never let unverified card
text reach the routing prompt."""

from pocs.routing_hijack.judge import Candidate, select_agent


def mitigated_select(
    task: str,
    candidates: list[Candidate],
    *,
    allowlist: set[str],
    mode: str = "replay",
) -> str:
    pinned = [c for c in candidates if c.identity in allowlist]
    if not pinned:
        raise ValueError("no candidate has a pinned, allow-listed source identity")
    if len(pinned) == 1:
        return pinned[0].name
    return select_agent(task, pinned, mode=mode)
