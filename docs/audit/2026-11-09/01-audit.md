# zbrain audit

Repo untouched: the repo tree was written 10:00:06–10:00:52, and `find -newermt '2026-11-09 10:01'` finds 0 files. `~/.zbrain` has 0 files newer than 10:00.
The binary was built to `scratchpad/target`. Each repro uses its own `ZBRAIN_HOME` under `scratchpad/homes`.
Repros are in `repro/NN_*.sh` (portable: `cargo build -p zbrain && bash repro/run_all.sh`); `run_all.sh` runs them all and `run_all.out` holds the captured output.

## What it actually is

zbrain is a Rust CLI ported from a Go oracle (crates/zbrain).

- **Claims** are Markdown files with OKF frontmatter at `workspaces/<ws>/wiki/<tier>/<clm_id>.md`. They are rendered deterministically (claims.rs:741-834).
- **Evidence** snapshots live at `evidence/sources/<evd_id>/{raw,source.yaml}`, mode 0400, and are pinned by a hash (paths.rs:7, evidence.rs:586).
- **`ask`** runs BM25 over a disposable SQLite FTS5 index (index.rs:723-795). It is gated by a freshness check: pending journal → dirty marker → generation → mtime/ctime → sha256 manifest (index.rs:284-481). Each hit is then re-bound to its canonical file before it is returned (query.rs:520-682).
- **Extras:**
  - an MCP server with a "challenge → TTY grant" owner ceremony (term.rs:1-30, cli.rs:390-440);
  - a loopback viewer (view.rs:48);
  - an in-process hashed-token "embedder" (embedder.rs:1-3).

**What it claims:**
- "approved" means the owner attested the claim.
- Files are the only truth, and the index is a cache.
- `ask` fails closed: it returns `gap` or `blocked` and never guesses.

**Threat model, taken from the code itself:**
- The ceremony exists to stop agents approving claims on their own (term.rs:2-3: "the ceremony cannot be scripted").
- Those agents are told to run the CLI (claude-rules.md:35, codex-rules.md:12), and they normally have file-write access.
- So "approved" is meant to hold up against the agent. It doesn't.

## Breaks, ordered by severity

1. **`--as-of` turns a hand-written file into "approved".**
   - Non-approved claims skip the digest and evidence checks in both rebuild (index.rs:1242-1245) and query (query.rs:609-611).
   - Superseded and revoked claims are relabelled "approved" in the output (query.rs:283-288).
   - The `as_of` filter checks only transition timestamps (query.rs:1001-1063).
   - Repro: write a `status: revoked` file with no verified block, a nonexistent evidence ID and a revoke dated 2099. Rebuild is clean, and `ask --as-of` returns `ready` with the claim as approved. [04]
2. **`--embed` never returns a gap.**
   - Vector search keeps the top-N by dot product with no floor (embedder.rs:171-246).
   - RRF then rewrites scores to rank positions (query.rs:500-508).
   - Repro: the query "quantum chromodynamics lattice" against a single claim, "deploy window is tuesday". Lexical returns `gap`; `--embed` returns `ready`. [13]
3. **"approved" is self-attested.**
   - The verification digest is a keyless sha256 of the rendered file (claims.rs:1157-1181).
   - Repro: hand-write a claim with `status: approved` and a recomputed digest. Reindex is clean and `ask` returns `ready`. [01]
4. **Two trust surfaces skip verification.**
   - The viewer's `approved_claims_json` (view.rs:478-481) and the MCP claim resource (mcp/gateway.rs:844-858) read claims through `scan_workspace_for_trust` with `verify_digests=false` (claims.rs:1680-1681).
   - Repro: tamper with a claim body. `ask` fails closed, but the viewer and MCP both serve the tampered text as "approved". [08, 09]
   - `status` (cli.rs:170) and MCP `memory_status` (gateway.rs:299) build their catalog from the same unverified scan.
5. **The ceremony is bypassed by `claim approve`.**
   - `zbrain claim approve` (cli.rs:732-751 → lifecycle.rs:67) has no challenge and no TTY check, unlike `approval grant` (term.rs:23).
   - Repro: approving from a pipe succeeds. [02]
6. **Conflicts block only when both sides are in the returned top-10** (query.rs:342, 755-796).
   - Repro: "deploy window" → `blocked`; "friday" → `ready`, even though the A↔B conflict is declared. [03]
7. **Plain `ask` ignores `stale_after`.** Only the `as_of` path enforces it (query.rs:1020).
   - Repro: at the same instant, plain `ask` returns `ready` and `ask --as-of now` returns `gap`, while `doctor` flags the claim as stale (lint.rs:72-77). [10]
8. **The viewer accepts any `Host` header** (view.rs:128-160), so it is readable through DNS rebinding.
   - Severity is low: the port is ephemeral and `zbrain view` is opt-in. [07]
9. **Freshness and rebuild disagree on what counts as a trust input.**
   - Freshness covers only the known tiers (index.rs:1162-1188). Rebuild scans all of `wiki/` (claims.rs:1718) and adds every non-claim `.md` to `legacy_unindexed`, which makes the index rejected (index.rs:550).
   - A note in `wiki/notes/` goes unnoticed until reindex, then bricks every `ask`. The error says "run zbrain reindex", which can't fix it.
   - This fails closed, so it's a UX and consistency issue. [12]

## Holds

- **Derived state really is disposable.**
  - Drop `indexes/`, the workspace `.zbrain/` (generation, coordination.rs:192-194), or both, and the check fails closed (index.rs:284-481).
  - `reindex` recovers (index.rs:483). [05]
- **Raw evidence edits are caught.**
  - Freshness flags the edit (index.rs:461), and rebuild checks the byte length and hash (evidence.rs:586). [06]
  - Against a deliberate attacker this reduces to break 3, because the evidence, source and claim hashes are all keyless.
- **Symlinked claim files are rejected** (index.rs:922). [11]
- **Nothing reaches the network.** The embedder is in-process (embedder.rs:1-3), and the viewer binds only to 127.0.0.1 (view.rs:48).
