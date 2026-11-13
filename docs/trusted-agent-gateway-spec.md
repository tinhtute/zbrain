# zbrain Trusted Agent Gateway Spec

**Status:** shipped implementation contract · **Created:** 2026-08-13 ·
**Authority:** amended `trusted-memory-spec.md` and the owner-approved
`references/zbrain-knowledge-architecture-brainstorm.md`

## Outcome

Expose zbrain's existing trusted-memory runtime to Codex/Claude through a local
stdio MCP gateway while keeping canonical Markdown and immutable evidence as the
only trust inputs. Agents can capture evidence, create drafts, ask trusted
memory, inspect health, and request a lifecycle challenge. Only a local owner
ceremony can grant approve, supersede, or revoke.

The delivered command surface includes `zbrain mcp serve`,
`zbrain approval show <challenge-id>`, `zbrain approval grant <challenge-id>`,
and `zbrain view`. The gateway is local stdio, the approval ceremony is local
TTY input, and the viewer is local loopback; none is a remote service.

## Non-negotiable invariants

- No LLM, completion, provider SDK, API key, network fetch, remote bind, or
  background daemon in zbrain core.
- Workspace resolver and runtime locks are reused by every surface.
- MCP evidence resource JSON is `{schema_version, trust: "untrusted_evidence", evidence, untrusted_evidence: {raw_content}}`; nested raw bytes are never answer material and never a top-level `raw_content` field.
- Drafts are promotion candidates and are excluded from trusted claims.
- Canonical mutations dirty the derived index and never auto-reindex.
- Challenge action digests bind workspace, operation, claim ID, canonical draft
  digest, superseded IDs, prior verification digest, and revoke reason.
- Challenge lifetime is 15 minutes from `prepare`; `prepare` emits no token and
  persists no token material. The local owner `grant` ceremony issues the
  plaintext token, starts its 5-minute lifetime (capped by challenge expiry),
  records approval without consuming it, and persists only its SHA-256. The
  token is atomically one-time consumed by `apply`.

## MCP surface

Transport is `zbrain mcp serve` over stdio. stdout is protocol-only; diagnostics
go to stderr.

Protocol revisions (SDK `github.com/modelcontextprotocol/go-sdk` v1.7.x):
legacy clients negotiate `2025-06-18` … `2025-11-25` through the `initialize`
handshake; stateless-era clients use `server/discover` plus per-request
`_meta.io.modelcontextprotocol/{protocolVersion,clientCapabilities}` at
`2026-07-28`. The gateway does not advertise the Tasks extension, MRTR
input-required results, or `subscriptions/listen`; the owner lifecycle
ceremony stays CLI-only by design. Tool input that fails generated-schema
validation fails closed as a tool-level `isError` result; oversized inputs
and unknown tools map to `-32602`; server faults map to `-32603`.

The first release exposes exactly these tools:

1. `workspace_current`
2. `memory_ask`
3. `memory_status`
4. `memory_reindex`
5. `evidence_capture`
6. `claim_draft`
7. `claim_lifecycle` with `prepare|apply`
8. `campaign_begin`
9. `campaign_next` (also serves as the campaign status read)
10. `campaign_submit_draft`

Campaign tools let a host agent author claim drafts at scale through a
resumable run file (`workspaces/<workspace>/campaigns/<run-id>.json`). Every
campaign-submitted draft is `status: draft` and visible only as a
`promotion_candidate`; no campaign path can approve, and a malformed run file
is a hard error, never a silent reset. A `prepare` may bind one challenge to
an ordered list of draft digests; the owner confirms or explicitly skips each
item in a single `approval grant` TTY session, one token is issued when at
least one item is granted, and `apply` reports a per-item
applied/skipped/failed result with whole-batch fail-closed token and expiry
semantics.

Resources are read-only:

- `zbrain://workspace/{workspace}/claim/{id}`
- `zbrain://workspace/{workspace}/evidence/{id}`

`memory_reindex` and `memory_ask` accept an explicit `embedding: true` opt-in;
the default is `false`. The opt-in uses the local loopback embedding sidecar
and merges vector and lexical retrieval. A missing or empty sidecar falls back
to lexical retrieval, with no network call and no change to trust validation.

The MCP layer maps domain failures to `isError`, schema-invalid or oversized
tool input to a fail-closed `isError` result (oversized inputs and unknown
tools to `-32602`), and genuine server failures to `-32603`. It does not
expose grant, approval UI, or mutation HTTP endpoints.

## Owner-pinned lifecycle

`claim_lifecycle prepare` returns only a challenge ID, action summary, and
SHA-256 action digest; it never returns a token. The owner runs `zbrain approval
show <challenge-id>` and `zbrain approval grant <challenge-id>`, confirms a
digest suffix in an interactive TTY, and receives the newly issued one-time
token to give to the agent. `apply` validates the challenge, token hash, both
expiries, workspace, action digest, and current canonical draft under the
workspace lock before consuming the token and applying the transition.

The challenge expires 15 minutes after `prepare`; `grant` issues the token and
starts its independent 5-minute lifetime, capped by the challenge expiry. Grant
records owner approval without consuming the token, and `apply` is the sole
atomic consumer. A consumed token cannot be replayed.
Expired challenges or tokens, a different workspace/operation/claim, a changed
canonical draft or bound digest, and any stale state fail closed before a
transition is applied. The caller must prepare a new challenge after such a
failure.

The existing CLI approval path remains compatible and does not require an MCP
challenge. MCP lifecycle writes record `verified.by: owner:mcp` plus transition
authorization metadata containing challenge ID, method, and MCP client.

## Evidence spans

`EvidenceSpan` coordinates are 1-based and inclusive over exact raw UTF-8 bytes.
No CRLF normalization is allowed. The span digest binds the evidence snapshot
digest, `start-end`, and exact bytes. Approval and rebuild reject missing,
moved, out-of-range, binary, or digest-mismatched spans. Existing claims with
only `evidence_ids` render and digest as before.

## Diagnostics and viewer

`status` is machine-readable and includes claim/evidence counts, index state,
pending approvals, embedding coverage, and exact recovery action. `doctor` is
read-only, returns exit 0 for healthy, 2 for domain findings, and 1 for usage or
internal failures; embedding probes require an explicit flag.

CLI retrieval remains lexical by default. `zbrain ask --embed` is an explicit
opt-in to local hybrid retrieval; `zbrain reindex --embed` builds its local
sidecar. The MCP `embedding: true` fields provide the same opt-in. Missing or
empty vectors always fall back to lexical retrieval.

`view` binds only loopback (`127.0.0.1`), serves embedded HTML/CSS/JS, escapes
Markdown and raw evidence, sends the strict CSP
`default-src 'self'; script-src 'none'; object-src 'none'` and
`X-Content-Type-Options: nosniff`, has no CORS headers, and returns 405 for
every method other than `GET` and `HEAD`. It accepts only `Host: 127.0.0.1:<port>`
or `localhost:<port>` for its bound port (missing `Host` is `400`; any other or
repeated `Host` is `421`). It uses
the same runtime services as CLI/MCP and exposes no mutation endpoint.

## Delivered implementation order

The shipped implementation landed in this order:

1. diagnostics and span validation;
2. stdio MCP gateway;
3. owner-pinned challenge lifecycle;
4. optional hybrid retrieval;
5. read-only viewer.

The release gate for every surface is `cargo test --workspace`,
`cargo clippy --workspace --all-targets -- -D warnings`,
`cargo fmt --all -- --check`, `make build`, `make smoke`, `git diff --check`, and
`cargo build --release`.
