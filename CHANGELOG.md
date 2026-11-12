# CHANGELOG

## Unreleased

### Changed (breaking: approved claims now require an owner signature)
- An approved claim is trusted only when it carries an Ed25519 signature over
  its verification digest, made with the owner key file from ADR 0002. The key
  lives outside the runtime root at `$XDG_CONFIG_HOME/zbrain-keys` (fallback
  `~/.config/zbrain-keys`), directory `0700`, files `0600`; a symlinked key
  path, a path inside `ZBRAIN_HOME`, or a looser mode fails closed.
  `reindex`, `ask`, `ask --as-of`, `status`, the viewer, and the MCP resources
  reject unsigned or badly signed approved claims through one shared path.
  **Existing approved claims are untrusted until re-signed**: run
  `zbrain key init` once, then `zbrain claim resign` (the batch owner ceremony
  lists every approved claim and honors `--exclude`). `doctor` names both
  commands. Revoke and supersede transitions are not signed yet (follow-up),
  so a legacy superseded or revoked claim cannot be restored by re-signing:
  `claim resign` walks approved claims only, and `ask --as-of` therefore
  reports those historical rows as a gap until the follow-up signs
  transitions.
- `verified` gains `alg`, `key_id`, and `sig`. The verification digest blanks
  all `verified.*` fields, so signing a claim never changes its digest and
  legacy files render byte-identically.

### Fixed
- The viewer, MCP claim resource, `status`, and `memory_status` read claims
  through one verified path: an approved claim whose canonical file was
  tampered after approval is dropped or reported as invalid, never served as
  approved. `lint`/`doctor` report invalid claims as findings. Repair and
  owner-ceremony paths still read the canonical file so a tampered claim can
  be revoked or migrated.
- `claim approve` runs the owner ceremony: a piped caller is refused, and
  approval requires confirming the last 16 hex characters of the action digest
  on an interactive TTY — the same challenge/grant path as `approval grant`.
  The TTY check is owner-presence friction, not a security boundary: any pty
  passes it, and owner proof is the planned signed-approval work. `make smoke`
  and the audit repros drive the real ceremony through
  `scripts/owner-approve.py`.

## 0.4.0 (2026-09-06) — Rust cutover

The Go implementation is replaced by a Rust workspace with verified
behavioral parity. Trust contract, file layouts, and CLI surface unchanged.

### Changed
- Runtime rewritten in Rust (`crates/zbrain`): same OKF Markdown claims,
  immutable evidence snapshots, FTS5 index (rusqlite bundled), fail-closed
  trusted retrieval, owner-pinned approval ceremony, stdio MCP gateway,
  loopback viewer
- CI, Makefile, AGENTS.md, and docs are Rust-authoritative (`cargo test`,
  `cargo clippy -D warnings`, `cargo fmt --check`, `cargo audit`)
- Binary shrinks from ~22M to ~4.4M (3.8M stripped)

### Fixed
- Replaced unsound `serde_yml`/`libyml` (RUSTSEC-2025-0067/0068) with
  pure-Rust `yaml-rust2` for frontmatter parsing
- Hardened viewer accepted sockets (blocking mode) and capped MCP frame
  buffer at 8 MiB (session-fatal)

### Notes
- Pre-cutover Go tree preserved under tag `v0.2.0-go-final`
- Decision record: `docs/adr/0001-go-to-rust-cutover.md`

## 0.3.1 (2026-08-26) — docs site + Pages deploy + CI runtime bumps

Docs site and landing page ship to GitHub Pages; CI actions move off the
deprecated Node 20 runtime. No Go runtime or trust contract change.

### Added
- `site/` — static docs site + landing page (vanilla HTML/CSS/JS, Hallmark Garden design, teal primary `#124b68`): landing, getting-started, concepts, CLI reference (from real `--help`), MCP gateway, architecture; deployed by `.github/workflows/pages.yml` to `https://therealtinhtute.github.io/zbrain/`
- `site/assets/` — diagrams copied from `docs/diagrams/` (originals untouched)

### Changed
- Masthead centered with brand on its own row; active nav link bold + 1px underline; main column widened to min 50% of viewport (capped 60rem)

### Fixed
- CI actions pinned to Node 24 runtimes (Node 20 deprecated): `checkout@v6`, `setup-go@v6`, `configure-pages@v6`, `upload-pages-artifact@v5`, `deploy-pages@v5`, `upload-artifact@v6`, `codeql-action@v4`, `golangci-lint-action@v9`

## 0.3.0 (2026-08-25) — MCP protocol era + security gate close

MCP gateway moves to the 2026-07-28 stateless protocol era; phase-5 security
gates close with go1.25.13, lint 0, govulncheck 0.

### Added
- `feat(mcp)`: speak MCP 2026-07-28 era via go-sdk v1.7.0 — stateless handshake, `server/discover`, per-request `_meta`

### Fixed
- `fix(security)`: close phase-5 gates — go1.25.13 toolchain, golangci-lint v2.13, govulncheck 0 affected, CI blocking removed
- `fix(ci)`: golangci-lint-action v7 for golangci-lint v2; smoke cleanup falls back to rm when trash is absent

## 0.2.3 (2026-08-25) — perf+eval harness (Wave 0-3 fanout)

Wave 0 baseline + Wave 1 perf/search + Wave 2 trust/drift/CLI + Wave 3 security/docs. No trust contract change.

### Added
- `scripts/bench-fts5.go` + `docs/benchmark.md` + `docs/proofs/bench-baseline*.json` — FTS5/perf baseline harness (100/1k/10k narrow vocab, temp ZBRAIN_HOME, index time/throughput/DB/heap/p50/p95/p99) — replaces `TestAskP95At100K` single point
- `docs/eval/queries.json` (50 golden: 15 single + 35 composite) + `internal/eval/eval.go` `make eval` — P@10/R@10/MRR/NDCG/MAP/gap/blocked/faith harness (brute-force ground truth, isolated ZBRAIN_HOME)
- `internal/eval/drift.go` + `docs/eval/drift.md` — McNemar delta for retrieval drift
- `internal/runtime/index_benchmark_test.go` `TestAskP50P95P99` wrapper (p50/p95/p99)
- `docs/cli-contract.md` — TE-quiet/TE-no-color skip rationale (JSON-only, zero ANSI)
- `docs/proofs/surface.txt` + `TestSurface` — 13 helps snapshot (RUBRIC 2A.2)

### Changed
- `internal/runtime/index.go` `fts5Query` — phrase `"exact"` + wildcard `foo*` + NEAR reject (was quote-each-token)
- `internal/runtime/query.go` `interleaveClaims` — RRF k=60 (was `Score=float64(i)`)
- `internal/runtime/index.go` `createIndexSchema` — `PRAGMA journal_mode=WAL` + `synchronous=NORMAL` + wal_checkpoint (WAL 1.4-3.5×: 1k 752→2700 doc/s)
- `internal/view/server.go` — `sync.Mutex` on listener/Port/URL (race fix)
- `internal/mcp/tools.go` — 1MB bounds + 5s timeout + audit log `tool/workspace/duration` (MSSS L2) + mutex log
- `trusted-memory-spec.md` — mark gateway `mcp serve`/`view`/`approval` as Shipped 2026-08-13 (was future milestone)
- `docs/README.md` — add benchmark/eval row

### Fixed
- `Makefile` `build` now produces both `dist/zbrain` (22M unstripped) and `dist/zbrain.stripped` (15M, 32% smaller, `ldflags -s -w -trimpath`)
- `workspace_boundary_test.go` fuzz for `../`, `%2e%2e`, `\0`, `//`, etc. + encoded traversal
- `transition_test.go`/`view_test.go`/`index_state_test.go` coverage push `runtime 76.2%→80.0%` `view 69.5%→92.8%`
- `cli.go` typed exit codes 0/1/2 + `cli_test.go` `TestExitCodes` 27 cases

### Perf (measured 2026-08-25 `go1.24.0 linux/amd64`)
- 1k: 1.33s 752 doc/s p50 50ms → 0.37s **2700 doc/s** p50 52ms (+259%)
- 10k: 3.17s 3155 doc/s 50MB p50 484ms (needs Phase 2 RRF tuning — target <100ms)
- Eval 1k: `P@10 1.0 R@10 0.054 MRR 1.0 NDCG 1.0 gap 0%` — no regress

### Security/CI
- `.github/workflows/test.yml` — add `golangci-lint@v1.64` + `govulncheck` + `kyber sarif` + `go-crap --fail-on 15` + SARIF upload (all warn-only)
- `kyber.toml` — `fail_on_threshold false`

## 0.1.1 (2026-08-10)

Go-native rewrite of the CLI. The pre-reset Bun/TypeScript implementation
(2.1.0 and earlier, below) was removed on 2026-07-29 and is kept for history
only.

### Added

- Go command surface: `setup`, `workspace create|current`, `evidence add`,
  `claim draft|approve|supersede|revoke`, `migrate okf`, `reindex`, `ask`,
  `version`
- Embedded runtime assets (`assets/`) extracted by `setup`; `ZBRAIN_HOME`
  override for isolated runs

### Changed

- Trust hardening: content-digest verification at approval, fail-closed
  retrieval on stale/dirty indexes, canonical claim identity binding,
  symlink-safe index paths, coordinated workspace generation
- Runtime file permissions are owner-only: `0700` directories, `0600`
  mutable metadata, `0400` immutable evidence snapshots

## 2.1.0 (2026-07-03)

### Added
- **`zbrain sync <workspace>`**: git-backed workspace sync — commit local changes, `pull --rebase`,
  push, reindex. `zbrain sync init <workspace> [--remote <url>]` turns a workspace into a git repo.
  Cross-machine consistency is git's job; advisory leases/optimistic locking remain the
  same-machine, multi-agent safety net (see README "Team setup").
- **`zbrain note add`**: fast-path write for already-trusted, first-party knowledge directly to
  the wiki, bypassing `learn`/`ingest` staging. Still conflict-checked and governed by the same
  supersede-not-overwrite lifecycle; reserve `learn`/`ingest` for material needing a human review
  step.
- **`zbrain workspace current`**: prints the resolved project→workspace binding as JSON. Replaces
  reading `~/.zbrain/projects.json` directly.
- **Session metadata wired end-to-end**: the `sessions` SQLite table (previously dead) is now
  written on every `zbrain ask` call and every MCP `recall` call (`touchSession`), and surfaced in
  `zbrain doctor`'s idle-session check.
- **`zbrain doctor --fix`**: GCs sessions idle 30+ days (`SESSION_IDLE_GC_DAYS`) before generating
  the doctor report.

### Changed
- **Project registry consolidated to SQLite (AC-P1-9).** `~/.zbrain/projects.json` is no longer
  written. On first run after upgrade, `initDb` imports any existing `projects.json` entries not
  already in SQLite, then renames the file to `projects.json.bak` (never deletes). All bundled
  skills/engine-rules assets now instruct agents to run `zbrain workspace current` instead of
  reading the file.

### Fixed
- **`zbrain sync init --remote <url>` on a workspace whose remote already has history** used to
  always `git init` an unrelated root, so the very first `sync` rebased onto the remote's history
  and conflicted immediately (reproduced end-to-end during this release's smoke test). It now
  fetches first and adopts the existing `main`/`master` branch when present, clearing the
  freshly-scaffolded starter files so they don't block the checkout. A second teammate can now
  join a shared workspace through the documented CLI flow (`workspace create` → `sync init
  --remote`) without a manual `git clone` workaround.

## 2.0.0 (2026-06-23)

### Breaking
- **Storage layout**: tier content moved from `<ws>/<tier>/` to `<ws>/wiki/<tier>/`. Evidence is structurally unindexable (C1 fix).
- **File-first writes**: notes are markdown files with YAML frontmatter; SQLite is a rebuildable cache. `rm zbrain.db && zbrain reindex` is lossless.
- **Retrieval engine**: FTS5 (BM25) replaces external `qmd` dependency. `qmd` remains selectable but is no longer the default.
- **Review→apply**: no longer silent-overwrites. `ingest apply` runs through `noteService` with conflict detection; overlapping writes without `supersedes` are refused.
- **CLI surface**: per-session context files replace shared `current-task.md`. `zbrain note {show,update,archive,forget,restore}`, `zbrain lease {acquire,release,list}`, `zbrain reindex`, `zbrain doctor`, `zbrain mcp serve` are new.
- **MCP server**: ships as a new agent-facing surface. `remember` writes to evidence pipeline only — does NOT auto-apply (the moat is preserved).

### Added
- **Memory lifecycle**: notes have a full state machine (`active → superseded → archived → forgotten → active`). Forgetting is recoverable via tombstone + `.trash/`.
- **Tombstones + .trash**: forget moves file to `.trash/<id>.md.bak`; restore reads `original_tier` / `original_path` from a sidecar tombstone.
- **Advisory write leases**: per-`(workspace, path)` with TTL auto-expiry.
- **Per-session context files**: `projects/<hash>/sessions/<sid>.md`; multiple agents no longer clobber each other.
- **`zbrain doctor`**: 8-check reconciliation (DB↔files, orphan evidence, stale review, broken links, expired leases, idle sessions, schema version, FTS5 sync).
- **`zbrain reindex`**: deterministic file→DB rebuild; disaster-recovery primitive.
- **Optimistic locking**: every mutation accepts `expectedSha`; mismatch throws `ShaMismatchError` instead of clobbering.
- **Tier-weighted ranking**: `BM25 × tier_weight` instead of hard tier sort. Decisions can outrank axioms on relevance.
- **`status='active'` filter** in retrieval: superseded/archived/forgotten structurally excluded.
- **V1→V2 layout migration**: idempotent, runs on every CLI boot via `assertRuntimeReady`.
- **MCP server (JSON-RPC 2.0 over stdio)**: 4 tools — `recall`, `remember`, `list_pending`, `get_note`.

### Changed
- `qmd` global install no longer required.
- `classifyByTier` uses path substring match (still works for `wiki/<tier>/`); explicit `tier` field in frontmatter planned for a future migration.
- Retrieval ranking multiplied by tier weight; relative order within a tier preserved.

### Removed
- `queries` table (V1 speculative; never consumed).
- `current-task.md` shared file (replaced by per-session files).
- `source.yaml` write path (restored as file in `evidence/sources/<id>/`).
- Dependency on global `qmd` install (FTS5 is default; qmd stays selectable).

### Migration
- **V1→V2 layout**: auto on next `zbrain` CLI invocation. Tier content moves from `<ws>/<tier>/` to `<ws>/wiki/<tier>/`; idempotent. Per-workspace failures log a warning, do not block the command.
- **V1 storage**: existing `evidence/sources/<id>/raw.md` is still readable. New notes use frontmatter; old applied-content files (no frontmatter) are tolerated by `readNote` (defaults to `status: active`).

### Test discipline
- Test suite restored: `bun test` exits 0 across 10 files, 70+ tests.
- CI: GitHub Actions matrix (macOS + Ubuntu) runs `bun test` + `bun run typecheck` on every push.

## 0.1.0 (pre-V2)

- V1 MVP. Per-workspaces isolation, evidence pipeline, qmd-backed BM25, tier rerank. Test suite later removed (chore commits `c057fe0`, `fa873e1`); restored in V2 Phase 00.
