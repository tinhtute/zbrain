# Audit hardening + slim graph

Source: `docs/audit/2026-11-09/` — `01-audit.md` (9 breaks, 13 repros), `02-research.md` (field survey), `03-slim-graph-design.md` (locked design).
Baseline: all repros in `docs/audit/2026-11-09/repro/` reproduce on `master` @ `f519d4f` (2026-11-09).

## Goal

Make "approved" and `ask` hold their stated contract against an agent with file-write access, then add the slim graph layer on top of the verified scan.

## Acceptance (per item)

Each fix turns its repro into a failing integration test first (red), then green. A repro is "fixed" when its script output flips to the fail-closed result noted below.

## Phase 0 — trust fixes (before any graph work)

| # | Break | Fix direction | Repro → expected after fix |
|---|---|---|---|
| 1 | `--as-of` relabels unverified superseded/revoked files as approved (`query.rs:283-288`, `index.rs:1242-1245`, `query.rs:609-611`) | Verify digest + evidence closure for every status that can surface via `--as-of` | `04` → rejected / `gap` |
| 3 | Approval is self-attested: keyless sha256 (`claims.rs:1157-1181`) | **Done** (ADR 0002): Ed25519 owner key file outside `ZBRAIN_HOME`, signature over the verified digest, verified on every trust surface; `key init` + `claim resign` migration | `01` → reindex rejects |
| 5 | `claim approve` bypasses the TTY ceremony (`cli.rs:732-751`, `lifecycle.rs:67`) | Route through the same challenge/TTY gate as `approval grant` (`term.rs:23`) | `02` → refused from a pipe |
| 4 | Viewer, MCP resource, `status`, `memory_status` use `verify_digests=false` (`claims.rs:1680`) | One verified read path for every trust surface | `08`, `09` → tampered claim not served as approved |
| 2 | `--embed` never gaps (`embedder.rs:171-246`, RRF `query.rs:500-508`) | Require a lexical hit (or a similarity floor) for `ready` | `13` → `gap` |
| 6 | Conflicts block only inside top-10 (`query.rs:342, 755-796`) | Check declared conflicts of every returned claim against the whole workspace | `03` → `blocked` for "friday" |
| 7 | Plain `ask` ignores `stale_after` (`query.rs:1020`) | Apply the same staleness rule as `--as-of now` and `doctor` | `10` → `gap` |
| 9 | Non-claim `.md` under `wiki/` bricks `ask` after reindex; freshness doesn't see it | Align freshness scope with rebuild scope; error names the offending file and the fix | `12` → actionable error before reindex |
| 8 | Viewer accepts any `Host` header (`view.rs:128-160`) | Allow only `127.0.0.1:<port>` / `localhost:<port>` | `07` → 4xx |

Order: 1, 3, 5, 4 (trust) → 2, 6, 7 (answer correctness) → 9, 8 (UX / low).
Item 3 changes the on-disk claim format: needs an ADR in `docs/adr/` and a migration story for existing approved claims before code.

## Phase 1–3 — slim graph

Per `03-slim-graph-design.md` (no RAG, no vector DB, no LLM extraction; BM25 stays):

1. Parse `zbrain.about`, load `ontology/subjects.yaml` (outside `wiki/`), build `nodes`/`edges` from the **verified** scan, export `graph.json`; unknown `about` = warning.
2. Queries `search`, `neighbors`, `chain`, `absent`, `conflicts`, `coverage`; unknown `about` = error.
3. Graph UI on the loopback viewer (requires #8).

Measure completeness/absence/supersession queries on the eval suite before phase 2 — value at small scale is unproven.

## Validation gate

`cargo fmt --all -- --check` · `cargo test --workspace` · `cargo clippy --workspace --all-targets -- -D warnings` · `make smoke` · `bash docs/audit/2026-11-09/repro/run_all.sh`.

## Current state

- 2026-11-09: audit + research + design imported; repros made portable and re-run green-as-broken on master. No code changes yet. Next: ADR for signed approvals (#3), then red tests for #1.
- 2026-11-12: #3 landed (ADR 0002, commits `863fccf`..`61ab812`): approved claims carry an Ed25519 signature over the verification digest; `reindex`, `ask`, `--as-of`, `status`, viewer, and MCP reject unsigned or badly signed claims through one path. `01` now reports `approved: 0, invalid: 1, rebuild_state: rejected` and `ask` fails closed. Legacy claims need `zbrain key init` + `zbrain claim resign`; `doctor` names both. Revoke/supersede signing is a follow-up (ADR 0002 "Migration").
