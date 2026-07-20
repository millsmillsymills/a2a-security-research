# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A security research artifact for the A2A (Agent-to-Agent) protocol v1.0.0: a threat
model, a control catalog, and two reproducible local proof-of-concept exploits. It is
not a library or service — the deliverables are the analysis documents plus PoC code
that demonstrates each gap and its mitigation. All analysis is pinned to A2A spec
v1.0.0 and `a2a-sdk==1.1.0`; see `SPEC-VERIFIED.md` and `docs/sdk-surface.md` for the
verified version record and SDK shape notes.

The repository root is this `a2a-threat-model/` directory (a subdirectory of the
`a2a-research` project checkout), not the parent.

## Commands

```
uv sync            # install deps into .venv
make demo          # run both PoC demos (no API key required)
make test          # uv run pytest  (testpaths = pocs/)
make lint          # ruff check + ty check
```

Run one test file or test:

```
uv run pytest pocs/routing_hijack/test_judge.py
uv run pytest pocs/routing_hijack/test_judge.py::test_name -q
```

Run a single PoC directly (each PoC's Makefile just invokes its exploit module):

```
uv run python -m pocs.routing_hijack.exploit
uv run python -m pocs.webhook_ssrf.exploit
```

`-m pocs.…` requires the working directory to be the repo root so the `pocs` package
imports. CI additionally runs `ruff format --check`, `pip-audit`, `zizmor`, and
`actionlint`; run those before pushing to match CI.

## Architecture

Two independent PoCs under `pocs/`, sharing helpers in `pocs/common/`. Each PoC follows
the same three-part shape and each part is a separate module so the exploit and its fix
sit side by side:

- **exploit** (`exploit.py`) — the demo entrypoint (`main()`); shows the vulnerable
  behavior, then the mitigation closing it, and `assert`s both outcomes so the demo
  doubles as a smoke test.
- **mitigation** (`mitigation.py`) — the fix, callable independently of the exploit.
- **vulnerable component** — `judge.py` (PoC #1) or `agent.py` + `metadata_server.py`
  (PoC #2), the deliberately-insecure code under test.

### PoC #1 — routing hijack (`pocs/routing_hijack/`)

An injected instruction in an Agent Card's `description` hijacks an LLM-as-judge router.
`judge.select_agent()` is the vulnerable router; `mitigation.mitigated_select()` pins
source identity (an allow-list of `Candidate.identity`) *before* any card text reaches
the prompt, so untrusted text can never influence selection.

The judge runs against a **record/replay cassette** (`cassette.json`), keyed by a
SHA-256 of `task + prompt`. `mode="replay"` (the default, used everywhere in tests and
demos) needs no `ANTHROPIC_API_KEY`; `mode="live"` calls `claude-haiku-4-5` and updates
the cassette. Live results are validated before being recorded so a no-match never
poisons the cassette. `_match_candidate` resolves free-text model output to exactly one
candidate on `\b` word boundaries and **raises** on no-match or ambiguity — never
guesses, because the selection is the security boundary.

### PoC #2 — webhook SSRF + forged completion (`pocs/webhook_ssrf/`)

`agent.vulnerable_app()` fetches attacker-supplied callback URLs with no allow-list
(SSRF) and accepts unauthenticated state-changing completions (forgery).
`mitigation.secure_app()` closes both: a callback-host allow-list (returns 403) and
HMAC-SHA256 signature verification on completions (returns 401). The exploit spins up a
loopback metadata server (`metadata_server.py`) to demonstrate real exfiltration via
`_server.start/stop` daemon-thread helpers, torn down in a `finally` block.

### Shared helpers (`pocs/common/`)

- `cards.py` — spec-valid v1.0 `AgentCard` construction plus `benign_skill()` /
  `malicious_skill()` fixtures.
- `server.py` — serves a card at the well-known path via plain Starlette for local tests.

## SDK gotchas (critical — see `docs/sdk-surface.md`)

`a2a.types.*` are **protobuf messages, not pydantic models**. Construct with kwargs but
serialize with `google.protobuf.json_format.MessageToJson(card)` — **never**
`.model_dump_json()`. `AgentCard` has **no `protocol_version` field**; version is set
per interface on `AgentInterface.protocol_version`. `security_schemes` is a proto map;
omit it (an empty map serializes to nothing).

## Safety invariants (preserve these)

All network targets are `127.0.0.1`; no external hosts are ever contacted. Demo servers
are operator-owned daemon threads torn down in `finally`; nothing persists after a run.
Keep PoCs hermetic — the default cassette/replay path must run with no API key.

## Conventions

Python 3.12+, `uv` for everything. `ruff` line length 100, lint select `E,F,I,UP,B`.
Type-check with `ty`. Tests are colocated `test_*.py` files next to the code they cover.

## Agent skills

### Issue tracker

Issues and PRDs live as GitHub issues in `millsmillsymills/a2a-security-research`,
managed via the `gh` CLI. See `docs/agents/issue-tracker.md`.

### Triage labels

Five canonical triage roles mapped to default label names; `wontfix` already exists in
the repo. See `docs/agents/triage-labels.md`.

### Domain docs

Convention for if/when domain docs are added: single-context, one `CONTEXT.md` +
`docs/adr/` at the repo root. None exist yet — agents proceed silently when absent. See
`docs/agents/domain.md`.
