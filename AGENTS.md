# AGENTS.md

Rust (stable toolchain via `rust-toolchain.toml`), Rust-native CLI in `crates/zbrain`. Cut over from Go at m8 (pre-cutover Go tree preserved under tag `v0.2.0-go-final`); the Go oracle lives in git history only. Do not reintroduce Bun/Node/TypeScript.

## Layout

- `crates/zbrain/src/main.rs` — binary entrypoint (thin dispatch, delegates to `cli`)
- `crates/zbrain/src/cli.rs` — arg parsing, dispatch, JSON/text output; version `0.3.0`
- `crates/zbrain/src/` — durable logic: paths, config, assets, setup, workspace, claims, evidence, lifecycle, transition, trust validation, lint, index (FTS5 via rusqlite bundled), query, embedder, approval, campaign; unit tests alongside each module
- `crates/zbrain/src/mcp/` — stdio MCP gateway (hand-rolled JSON-RPC)
- `crates/zbrain/src/view.rs` — loopback viewer (std TcpListener)
- `crates/zbrain/tests/` — integration suites (`eval_suite.rs`, `bench_100k.rs`, capture tests) + committed golden fixtures
- `assets/` — embedded source of truth (`include_dir`), copied by `zbrain setup`; never edit extracted runtime directly
- `docs/` — specs and authored docs; `docs/README.md` is the doc map

## Commands — use these exact forms

```bash
cargo test --workspace               # full gate (CI: ubuntu+macos)
cargo test -p zbrain --lib           # unit tests only
cargo test -p zbrain --test eval_suite   # eval suite
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
cargo audit                          # dependency advisories (CI)
make build                           # → dist/zbrain + dist/zbrain.stripped (embeds assets/)
make smoke                           # release binary, full lifecycle in isolated ZBRAIN_HOME (uses trash)
cargo build --release                # CI release-mode build
git diff --check
./scripts/smoke.sh --bin ./dist/zbrain
```

CI order in `.github/workflows/test.yml` (push `master`/`v2/**`, PR→`master`): `cargo fmt --check` → `cargo test --workspace` → `cargo clippy -D warnings` → `cargo audit` → `make build` → stripped verify → `make smoke` → `git diff --check` → `cargo build --release`.

Verify CLI surface: `cargo run -q -p zbrain -- --help` and sub-helps (`workspace`, `evidence`, `claim`, `migrate`, `reindex`, `ask`, `status`, `doctor`, `mcp serve`, `view`, `approval`).

## Workspace & Runtime Gotchas

- `ZBRAIN_HOME` overrides `~/.zbrain` for every command. Must be same value for the whole session; tests and smoke must use a temp dir (`mktemp -d`) and never touch real `~/.zbrain`. `make smoke` does this via `ZBRAIN_HOME=$tmp_home ./dist/zbrain setup`.
- `zbrain setup` extracts `README.md`, `agents/`, `engine/`, `skills/`, `templates/` directly under the runtime root. `workspace create <name>` then sets `default_workspace` in `config.yml`.
- Indexes are disposable SQLite FTS5 at `indexes/<workspace>.sqlite` with a `.dirty` marker during rebuild. Never commit or hand-edit them; rebuild with `zbrain reindex` (or `reindex --embed` for local hybrid). `ask` fails closed on missing/dirty/stale/rejected indexes — check `status`/`doctor` (doctor exits `2` on domain findings).
- `claim draft` reads body from **stdin**; metadata via flags. Lifecycle is `draft -> approved -> superseded|revoked` — approved claims are superseded, never edited in place. `claim approve` records `verified.at/by/digest` and signs them with the owner key; `reindex` validates before publishing.
- Approval signatures (ADR 0002): the owner key is `$XDG_CONFIG_HOME/zbrain-keys` (fallback `~/.config/zbrain-keys`), dir `0700` / files `0600`, created by `zbrain key init`; a symlink, a path inside `ZBRAIN_HOME`, or a loose mode fails closed. `verified` carries `alg`/`key_id`/`sig`; the digest blanks every `verified.*` field, so signing never changes a digest. An approved claim without a valid signature is untrusted everywhere (`reindex`, `ask`, `--as-of`, `status`, viewer, MCP). Legacy approved claims need `zbrain claim resign` (batch TTY ceremony, `--exclude`); `doctor` names it. Legacy superseded/revoked rows are not re-signable yet, so `ask --as-of` gaps on them until transition signing lands. Tests and `make smoke` set a temp `XDG_CONFIG_HOME` outside the temp `ZBRAIN_HOME`.
- `ask` default is lexical; `--embed` opts into local loopback embedding sidecar (also `memory_ask`/`memory_reindex` `embedding: true`). Missing sidecar falls back to lexical, no network calls.
- `mcp serve` is stdio-only (stdout=protocol, stderr=diagnostics). Protocol revisions: legacy handshake `2025-06-18`…`2025-11-25`, stateless `2026-07-28` (`server/discover`, per-request `_meta`); no Tasks/MRTR/subscriptions extensions; schema-invalid tool input → `isError`, oversized/unknown → `-32602`, server faults → `-32603`. `view` binds `127.0.0.1` only, `GET`/`HEAD` only, `Host` must be `127.0.0.1:<port>`/`localhost:<port>` (else 421; missing 400), strict CSP/`nosniff`, no CORS. Owner-pinned lifecycle: `claim_lifecycle prepare` → `approval show <id>` → `approval grant <id>` (TTY, confirm last 16 hex of digest) → `claim_lifecycle apply`. Challenge 15m, token 5m capped by challenge, single-use.
- File modes enforced in `crates/zbrain/src/paths.rs`: dirs `0700`, mutable metadata/canonical Markdown `0600`, evidence snapshots+`source.yaml` `0400`, derived indexes/dirty `0600`. Extracted program assets (`setup`) are non-secret docs at `0644`/`0755`, matching the oracle.

## Trust Rules — do not violate

- Workspace isolation is hard: never read across workspaces without explicit `--include <name>` (read-only secondary).
- Evidence snapshots (`evidence add --file <path> --origin <uri>`) are immutable local copies; raw evidence is untrusted, never indexed.
- Only `type: zbrain.claim` + `zbrain.profile: zbrain.trusted-memory/v1` with `status: approved` and valid digest/closure may enter trusted results. Drafts are `promotion_candidates` only. Conflicts → `status: "blocked"`, no match → `status: "gap"` (not permission to use drafts/evidence).
- `reindex` rejects invalid claims/evidence/broken `support` closures without rewriting canonical files.

## Assets & Style

- After editing `assets/`, rebuild and run tests+smoke — binary embeds them.
- Skill files `assets/skills/*/SKILL.md` require frontmatter `name`, `description`, `version`. Templates use `{{placeholder}}` tokens; claim templates must be OKF Markdown; evidence `source.yaml` must match `evidence.rs`.
- Keep handlers thin, put durable behavior in `crates/zbrain/src/`. Use `trash`, never `rm` (see `Makefile:32,40`). Use `cargo fmt`; no extra linter config beyond clippy `-D warnings`.
- Gitignored: `dist/`, `harness.db*`, `.kit/`, `.opencode/`, `workspaces/`, `.cache/` — never commit runtime output or secrets.

## Commits & Docs

- Conventional Commits: `feat(cli): ...`, `fix(runtime): ...`, `docs(spec): ...` with specific scope.
- Authoritative sources: `README.md`, `CONTRIBUTING.md`, `trusted-memory-spec.md`, `docs/trusted-agent-gateway-spec.md`. If docs conflict with `cargo run -q -p zbrain -- --help` or `crates/zbrain/src/`, trust the executable.

<!-- ZHARNESS:BEGIN -->
## Harness

Start with the requested outcome and use the repository as the system of record.
Read `docs/WORKFLOW.md` and only relevant product, design, plan, code, and
validation material.

- Answers, explanations, reviews, diagnoses, plans, and status reports are
  read-only. Inspect only what is needed; change nothing.
- For a bounded change, inspect affected behavior and proof, implement, and
  validate. No plan file is required.
- Use one `docs/plans/active/` file when work spans sessions, coordinates
  contributors, has dependencies, or needs recovery. Move it to
  `docs/plans/completed/` only after validation.
- Before editing, identify repository authority for each new externally
  observable policy. If materially different choices remain open, stop before
  edits; configurable defaults are not authority.
- Claim completion only with executable or observable evidence. Report outcome,
  changes, validation, and unresolved risks.

The `zharness` binary is install / update / uninstall only. It does not run
the lifecycle. There is no task database. There is no parallel control-plane state.
<!-- ZHARNESS:END -->
