# CARD-SIGN maintainer response runbook

This runbook turns a maintainer decision on
[a2aproject/a2a-tck#187](https://github.com/a2aproject/a2a-tck/issues/187)
into a bounded update to the CARD-SIGN contributions. It preserves the split
between static reference material and live served-card conformance, keeps all
key resolution offline by default, and prevents unrelated lockfile or legacy
formatting changes from entering the update.

Do not push a TCK change based only on a reaction, merge queue event, or comment
from another contributor. Start this runbook when a maintainer gives a clear
scope decision on issue #187 or PR #204. If the response is ambiguous, ask one
focused follow-up question and stop before changing a public branch.

## Checkpoint

This checkpoint was recorded on 2026-09-01 after posting the revised ownership
proposal. Treat the commit IDs as comparison anchors, not as current state.

| Item | State at checkpoint | Head |
|---|---|---|
| TCK `main` | current | `de6af188d2d65779719c88d4f6bb5b180a4fa91d` |
| PR #194 | open, mergeable | `d366cbc60db21586770c581777818a2bf91bb4f7` |
| PR #196 | open, mergeable | `563fe43aeee44b89c028b9124ffde8135a07d420` |
| PR #204 | open, mergeable | `39fd550e38b23489e443e3298cd07239ac670753` |
| PR #205 | open, mergeable | `1cfdeef074e9a8489734dab6e0538048f331c013` |
| PR #228 | open, mergeable | `11a23d65610284ebfa2040c6581ce05a9ed4f5d1` |
| A2A #2122 | open | last updated 2026-08-20 |

The proposal to which maintainers are responding is
[issue comment 5490110080](https://github.com/a2aproject/a2a-tck/issues/187#issuecomment-5490110080).
The local prototype is on `prototype/pr204-trusted-jwks` at the exact PR #204
head. Its intended delta is staged separately from an unrelated, unstaged
`uv.lock` rewrite. Do not switch branches, merge, or run a formatter in that
worktree until the delta has been preserved.

## Invariants

Every response path keeps these boundaries unless a maintainer explicitly asks
for a different design:

- CARD-SIGN-003 inspects every signature header on the card served by the SUT.
  Static header vectors do not establish live conformance.
- CARD-SIGN-001 and CARD-SIGN-002 verify the served signature against an
  explicitly trusted local key. The card does not choose its own trust root.
- `jku` fetching stays disabled in the shipped compatibility tests.
- An unmatched trusted `kid` is inconclusive. A resolved key with a bad
  signature is a conformance failure.
- Every configured JWK is parsed into a verification key before any SUT
  contact. Malformed trust material is a usage error.
- Canonicalization reads REQUIRED behavior recursively from the pinned v1.0.0
  protobuf descriptors. It retains supplied REQUIRED default-valued fields,
  including `skills: []`.
- A fixed signature from PR #194, attributed to its exact source commit, is the
  independent positive oracle. A fixed signature over a payload missing
  required `skills` is the adversarial oracle.
- CARD-SIGN-004 remains manual because expiry and revocation state is not
  established by a served card alone.
- Network demonstrations target only `127.0.0.1` and always tear down their
  server.

## Revalidate before choosing a path

Run these read-only checks from `a2a-tck-contribution/` and save the URLs, head
commits, states, review decisions, and merge states in the delivery notes:

```bash
git fetch origin main
gh issue view 187 --repo a2aproject/a2a-tck --comments
gh pr view 194 --repo a2aproject/a2a-tck --json state,headRefOid,mergeStateStatus,reviewDecision,url
gh pr view 196 --repo a2aproject/a2a-tck --json state,headRefOid,mergeStateStatus,reviewDecision,url
gh pr view 204 --repo a2aproject/a2a-tck --json state,headRefOid,mergeStateStatus,reviewDecision,url
gh pr view 228 --repo a2aproject/a2a-tck --json state,headRefOid,mergeStateStatus,reviewDecision,url
gh issue view 2122 --repo a2aproject/A2A --comments
```

Read the maintainer's complete comment or review in context. Record the source
URL and map each explicit decision to one row below. Do not infer approval of
an unmentioned layer.

## Response matrix

| Maintainer signal | Delivery action | Public PR shape |
|---|---|---|
| Accepts the four-layer split and live layer | Refresh #204 on current `main`; apply the audited canonicalization, trusted-key, served-card, dependency, and CI corrections | Update PR #204 as one live-conformance PR |
| Lands or selects #194 | Reuse only the needed fixed full-JWS vector with exact-head attribution; avoid duplicating its broader fixture set | Static vectors stay in #194; the live oracle stays in #204 |
| Lands or selects #196 | Drop duplicate static CARD-SIGN-003 vectors; retain CARD-SIGN-003 inspection of the card served by the SUT | Static header cases stay in #196; live inspection stays in #204 |
| Lands or selects #228 | Keep its independent JCS corpus as unit coverage; do not report corpus cases as SUT passes | Corpus stays in #228; live verification stays in #204 |
| Requests separate changes | Split canonicalization correctness from trusted-key live conformance as described below | Two small PRs, with the live PR stacked only when necessary |
| Defers the literal field-presence rule to A2A #2122 | Keep the prototype private and document the blocked assertion; do not weaken the test into a false pass | No code update until the specification decision |
| Declines the live layer | Preserve the local evidence, post one concise disposition note if requested, and stop | Do not push or silently repurpose #204 |
| Gives a partial or ambiguous answer | Ask whether live served-card CARD-SIGN-003 and explicit trusted-key verification remain in scope | No public branch change |

PR #205 is independent. Do not include CARD-EXT changes in any CARD-SIGN branch.

## Preserve the audited delta

Before refreshing the code, confirm that the existing prototype still has only
the 11-file staged CARD-SIGN delta and the separate unstaged `uv.lock` rewrite:

```bash
git status --short
git diff --cached --stat
git diff --stat
```

Create a local snapshot commit containing only the staged delta. Do not add
`uv.lock` to it. Record the snapshot commit in the delivery notes. Build the
maintainer-facing changes in a separate worktree based on freshly fetched
`origin/main`; do not turn the audited prototype worktree into the refresh
worktree.

If updating the existing PR requires rewriting its public branch, stop and get
explicit approval before using `--force-with-lease`. Prefer a normal update
that preserves review history when it can produce the agreed diff.

## Default PR scope

Unless maintainers request a split, update PR #204 as one atomic live feature:

1. Correct recursive canonicalization and its descriptor-driven REQUIRED field
   handling.
2. Add the fixed positive and adversarial signature oracles with exact source
   attribution.
3. Add explicit `--trusted-jwks <path>` configuration and parse all keys before
   SUT contact.
4. Verify CARD-SIGN-001/002 and inspect CARD-SIGN-003 on the card actually
   served by the SUT.
5. Update the optional signing dependency, lockfile, and CI lane together so
   cryptographic tests cannot silently skip.
6. Update the README and PR body with the trust boundary, inconclusive/failure
   distinction, overlap ownership, and verification evidence.

Keep reviewer-facing commits narrow:

1. `fix(card-sign): preserve required default-valued fields`
2. `feat(card-sign): load explicitly trusted verification keys`
3. `test(card-sign): verify served cards against fixed vectors`
4. `build(card-sign): run signing tests in CI`

If maintainers request separate PRs, use this partition:

- Canonicalization PR: descriptor-driven field handling, the exact §8.4.1
  worked example, fixed positive/adversarial vectors, and focused unit tests.
- Live conformance PR: trusted-JWKS CLI and pytest configuration, served-card
  CARD-SIGN-001/002/003 tests, documentation, dependency lock, and CI coverage.

Do not split key loading from the live test that consumes it. That would leave
an unused security boundary in one PR and make the observable behavior harder
to review.

## Lockfile and CI gate

Discard the pre-existing unstaged 939-line `uv.lock` rewrite from the delivery
diff. Regenerate the lock from the accepted base with the uv version agreed by
maintainers. Commit `pyproject.toml`, `uv.lock`, and the CI change together.

The CI lane must install both development and signing dependencies and prove
the crypto imports are present before running the unit suite. The intended
shape is:

```bash
uv sync --extra dev --extra signing --frozen
uv run python -c "import jwcrypto, rfc8785"
make lint unit-test
```

Review pytest's short summary and fail the lane if signing tests are skipped.
A green job with `pytest.importorskip` hiding the cryptographic suite is not
acceptance evidence.

## Verification gate

Run the full gate from the refreshed branch and attach the exact commands and
counts to the PR:

```bash
UV_CACHE_DIR=/private/tmp/a2a-tck-uv-cache make lint
UV_CACHE_DIR=/private/tmp/a2a-tck-uv-cache make unit-test
UV_CACHE_DIR=/private/tmp/a2a-tck-uv-cache uv lock --check
UV_CACHE_DIR=/private/tmp/a2a-tck-uv-cache uv run pytest --collect-only tests/compatibility/agent_card/test_agent_card_signing.py -q
.venv/bin/pytest tests/unit/validators/test_card_signature.py tests/unit/test_trusted_jwks.py tests/unit/validators/test_trusted_jwks_integration.py -q
```

Then run the hermetic loopback harness and retain its JSON output. It must show:

| Case | Required result |
|---|---|
| Fixed PR #194 signature and public key | live compatibility test passes |
| Different valid key under the same `kid` | conformance failure: signature does not verify |
| Malformed configured JWK | pytest usage error before SUT contact |
| Fixed signature over payload missing required `skills` | conformance failure: signature does not verify |

Also inspect the final diff for accidental scope growth:

```bash
git diff --check origin/main...HEAD
git diff --stat origin/main...HEAD
git status --short
```

The branch is ready only when the worktree is clean, all signing tests execute,
the harness contacts loopback only, and the diff contains no CARD-EXT or bulk
formatting changes.

## Response record template

Add a dated record to the delivery PR before changing public TCK state:

```text
Maintainer response URL:
Responder and association:
Response timestamp:
Current TCK main:
Current #194/#196/#204/#228 heads and states:
Accepted ownership layers:
Rejected or deferred layers:
Selected response-matrix row:
Planned PR shape:
History rewrite required: yes/no
Lockfile/uv decision:
Commands and test counts:
Remaining blocker:
```

After pushing, link the resulting PR or updated #204 from issue #187 and avoid
posting duplicate status comments across the overlapping PRs.
