# Acceptance Walkthrough

This walkthrough exercises the shipped Rust-native CLI, stdio MCP gateway,
owner-pinned approval ceremony, optional hybrid retrieval, and loopback viewer
in isolated runtime data.

## Command surface

Verify the root help and current command groups:

```bash
cargo run -q -p zbrain -- --help
cargo run -q -p zbrain -- workspace --help
cargo run -q -p zbrain -- evidence --help
cargo run -q -p zbrain -- claim --help
cargo run -q -p zbrain -- migrate --help
cargo run -q -p zbrain -- reindex --help
cargo run -q -p zbrain -- ask --help
cargo run -q -p zbrain -- status --help
cargo run -q -p zbrain -- doctor --help
cargo run -q -p zbrain -- mcp --help
cargo run -q -p zbrain -- mcp serve --help
cargo run -q -p zbrain -- view --help
cargo run -q -p zbrain -- approval --help
cargo run -q -p zbrain -- approval show --help
cargo run -q -p zbrain -- approval grant --help
```

The shipped surface includes `setup`, workspace creation/current selection,
evidence capture, the claim lifecycle, `migrate okf`, `reindex`, `ask`,
`status`, `doctor`, `mcp serve`, `view`, `approval show`, `approval grant`,
and `version`.

## Isolated lifecycle

Use a temporary §ZBRAIN_HOME§ so the run cannot touch the operator's real
§~/.zbrain§ directory:

```bash
export ZBRAIN_HOME=/tmp/zbrain-acceptance
cargo run -q -p zbrain -- setup
cargo run -q -p zbrain -- workspace create research
cargo run -q -p zbrain -- workspace current
```

Capture a source and record its returned evidence ID:

```bash
printf 'trusted source bytes\\n' > /tmp/zbrain-source.txt
cargo run -q -p zbrain -- evidence add \\
  --file /tmp/zbrain-source.txt \\
  --origin file://acceptance \\
  --media-type text/plain
```

Create a claim, approve it, rebuild the index, and query trusted context:

```bash
printf 'trusted acceptance answer\\n' | \\
  cargo run -q -p zbrain -- claim draft \\
    --tier projects \\
    --title 'Acceptance claim' \\
    --basis owner
# Copy the returned id into the next command. Approve runs the owner ceremony:
# type the last 16 hex characters of the printed action digest on the terminal.
cargo run -q -p zbrain -- claim approve <claim-id>
cargo run -q -p zbrain -- reindex
cargo run -q -p zbrain -- status
cargo run -q -p zbrain -- doctor
cargo run -q -p zbrain -- ask trusted acceptance
```

The runtime extracts §README.md§, §agents/§, §engine/§, §skills/§, and
§templates/§ directly under §ZBRAIN_HOME§. Workspace seed assets are not active
workspaces. A new workspace creates the wiki tiers and evidence directories;
§reindex§ creates the disposable index.

## Optional hybrid retrieval

Lexical retrieval is the default. Build a local loopback embedding sidecar and
opt in at query time:

```bash
cargo run -q -p zbrain -- reindex --embed
cargo run -q -p zbrain -- ask --embed trusted acceptance
```

The MCP equivalents are explicit request fields, both defaulting to `false`:

```json
{"tool":"memory_reindex","arguments":{"embedding":true}}
{"tool":"memory_ask","arguments":{"query":"trusted acceptance","embedding":true}}
```

Embedding is local-only and makes no network request. If the sidecar is missing
or empty, an embedding-enabled query falls back to lexical retrieval. A normal
query remains lexical and does not implicitly create or use vectors.

## Trust and recovery gates

The Go tests and rebuild/query paths prove that:

- outside edits, additions, deletions, and symlinks under trust inputs make the
  next query fail closed;
- invalid claims, evidence, and recursive supporting-claim closures are
  rejected during rebuild without mutating canonical files;
- rejected rebuild state is excluded from trusted results;
- restored evidence followed by a clean rebuild restores trusted querying;
- interrupted supersession is journaled and recovered before a later mutation;
- explicit claim conflicts return §blocked§, while no matching approved claim
  returns §gap§.

## Owner-pinned lifecycle walkthrough

Use an MCP client to call `claim_lifecycle` with `operation: "prepare"` for
an approval, supersession, or revocation. The response includes the challenge
ID, action summary, and SHA-256 action digest. The owner then performs this
local ceremony:

```bash
zbrain approval show <challenge-id>
zbrain approval grant <challenge-id>
```

`approval show` prints the bound workspace, operation, claim ID, digest suffix,
and challenge expiry. `approval grant` requires an interactive TTY, confirms the
final 16 hexadecimal digest characters, issues the one-time token, and prints it
as JSON. Give that token back to the agent, which calls `claim_lifecycle` with
`operation: "apply"`. The apply step rechecks the challenge, token hash, both
expiries, workspace, action digest, and current canonical draft under the
workspace lock before applying the transition.

The challenge lifetime is 15 minutes from `prepare`; `prepare` emits no token.
The grant-issued token has a separate lifetime of up to 5 minutes measured from
grant and never outlives the challenge. `approval grant` records owner approval
without consuming the token; `apply` consumes it atomically once. Expired
challenges or tokens, a replayed token, a mismatched digest/workspace/claim, or
stale canonical state fail closed and require a new `prepare`; no stale action
is applied.

## Read-only viewer

Start the viewer in a separate terminal:

```bash
cargo run -q -p zbrain -- view
```

Open the printed `http://127.0.0.1:<port>` URL. The server binds loopback only,
serves embedded HTML/CSS/JS, and escapes Markdown and raw evidence before
rendering. Check responses for the strict CSP
`default-src 'self'; script-src 'none'; object-src 'none'`,
`X-Content-Type-Options: nosniff`, and no `Access-Control-*` headers. Every method other than `GET` and `HEAD` receives `405 Method Not Allowed`;
the viewer has no mutation API.

## Verification gates

Run these from the project root:

```bash
go test ./...
go vet ./...
make build
make smoke
git diff --check
```

The optional focused gates are:

```bash
go test -race ./internal/runtime ./internal/cli ./internal/view ./internal/mcp
CGO_ENABLED=0 go build ./cmd/zbrain
ZBRAIN_BENCH_100K=1 go test ./internal/runtime -run '^TestAskP95At100K$' -count=1 -v
```

The scale benchmark is a release signal for the 100k-claim query path; a p95
above two seconds is a release blocker.
