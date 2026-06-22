# Domain Docs

How the engineering skills should consume this repo's domain documentation when exploring the codebase.

## Before exploring, read these

- **`CONTEXT.md`** at the repo root, or
- **`CONTEXT-MAP.md`** at the repo root if it exists — it points at one `CONTEXT.md` per context. Read each one relevant to the topic.
- **`docs/adr/`** — read ADRs that touch the area you're about to work in. In multi-context repos, also check `src/<context>/docs/adr/` for context-scoped decisions.

This repo does not currently ship any of these files. If they're absent, **proceed silently** — don't flag their absence or suggest creating them upfront. Treat this doc as the convention to follow if and when domain docs are added.

These docs are produced by the user-invocable `/grill-with-docs` skill (manual invocation only — agents do not auto-create them).

## File structure

The trees below are illustrative layouts (with placeholder filenames), not the current repo contents.

Single-context repo (most repos):

```
/
├── CONTEXT.md
├── docs/adr/
│   ├── 0001-some-decision.md
│   └── 0002-another-decision.md
└── src/
```

Multi-context repo (presence of `CONTEXT-MAP.md` at the root):

```
/
├── CONTEXT-MAP.md
├── docs/adr/                          ← system-wide decisions
└── src/
    ├── <context-a>/
    │   ├── CONTEXT.md
    │   └── docs/adr/                  ← context-specific decisions
    └── <context-b>/
        ├── CONTEXT.md
        └── docs/adr/
```

## Use the glossary's vocabulary

When your output names a domain concept (in an issue title, a refactor proposal, a hypothesis, a test name), use the term as defined in `CONTEXT.md`. Don't drift to synonyms the glossary explicitly avoids.

If the concept you need isn't in the glossary yet, that's a signal — either you're inventing language the project doesn't use (reconsider) or there's a real gap worth resolving before you lean on the term.

## Flag ADR conflicts

If your output contradicts an existing ADR, surface it explicitly rather than silently overriding:

> _Contradicts ADR-NNNN (short title) — but worth reopening because…_
