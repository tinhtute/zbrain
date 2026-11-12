# zbrain

`zbrain` is a Rust-native CLI for local-first trusted memory and
workspace-isolated agent context.

The shipped runtime keeps canonical OKF-style Markdown claims and immutable
local evidence snapshots, builds a disposable SQLite FTS5 index, and returns
trusted context JSON. It does not call an LLM or model provider.

[MIT license](LICENSE) · [Contributing](CONTRIBUTING.md) ·
[Changelog](CHANGELOG.md)

## Features

- Workspace-isolated memory rooted at `~/.zbrain/` or `ZBRAIN_HOME`.
- OKF-style claim concepts in the `axioms`, `mental-models`, `projects`, and
  `decisions` tiers.
- Explicit claim lifecycle: `draft -> approved -> superseded|revoked`.
- Immutable local evidence snapshots with origin, capture time, media type,
  byte length, and SHA-256 metadata.
- Rebuildable per-workspace SQLite FTS5 lexical indexes.
- Fail-closed trusted retrieval with visible `ready`, `gap`, and `blocked`
  outcomes.
- `status` and `doctor` diagnostics for index and embedding configuration.
- Optional local hybrid retrieval through `ask --embed`; lexical retrieval remains the default and fallback.
- A stdio MCP gateway via `zbrain mcp serve`, with an owner-pinned approval ceremony.
- A loopback-only read-only viewer via `zbrain view`.
- Embedded runtime assets extracted by `zbrain setup`.

## Architecture

The CLI keeps argument parsing and output at the edge. Durable behavior lives
in `crates/zbrain/src/`; Markdown and evidence are canonical, while SQLite is a
derived cache that can be discarded and rebuilt.

![zbrain architecture overview](docs/diagrams/architecture-overview.png)

*Architecture overview: CLI, runtime packages, canonical inputs, embedded
assets, disposable index, and JSON outputs.*

![zbrain trust and data flow](docs/diagrams/trust-data-flow.png)

*Trust flow: evidence capture, claim approval, rebuild validation, and trusted
query outcomes.*

### Trust and data flow

1. `evidence add` copies an already-local file into an immutable evidence
   snapshot and records its metadata.
2. `claim draft` writes an OKF claim candidate. The claim body is read from
   stdin; drafts are never trusted answer material.
3. `claim approve` runs the owner ceremony: the owner confirms the last 16
   hex characters of the action digest in an interactive TTY, and the claim
   basis and referenced evidence or supporting claims are validated before
   `verified.at`, `verified.by`, and `verified.digest` are recorded.
4. `reindex` scans canonical Markdown and evidence, validates trust inputs, and
   publishes a clean or rejected disposable index without rewriting canonical
   files.
5. `ask` checks index freshness and the returned claim's canonical binding and
   trust dependencies before returning JSON. Conflicts produce `blocked`; no
   matching approved claim produces `gap`.

### Shipped gateway and viewer

The shipped binary is standalone and Rust-native. It now includes the local
integration surfaces described in [`docs/trusted-agent-gateway-spec.md`](docs/trusted-agent-gateway-spec.md):

- `zbrain mcp serve` runs the trusted-agent gateway over stdio. Protocol frames
  stay on stdout and diagnostics stay on stderr. It speaks the MCP protocol
  revisions `2024-11-05` through `2025-11-25` via the legacy handshake and the
  stateless `2026-07-28` revision (`server/discover`, per-request `_meta`);
  tasks/MRTR/subscriptions extensions are not advertised.
- `zbrain approval show <challenge-id>` and `zbrain approval grant <challenge-id>`
  provide the local owner ceremony for lifecycle actions. The agent receives a
  one-time grant token; the gateway, not an HTTP endpoint, applies the mutation.
  `zbrain claim approve` runs the same ceremony in one step: it binds the
  challenge, walks the owner confirmation, and applies it.
- `zbrain view` serves a read-only embedded viewer on `127.0.0.1` only.

All three surfaces reuse workspace boundaries and fail-closed trust validation;
canonical Markdown and immutable evidence remain the trust inputs.

## Repository structure

```text
crates/zbrain/src/main.rs   CLI binary entrypoint
crates/zbrain/src/cli.rs    command dispatch and user-facing behavior
crates/zbrain/src/          paths, config, assets, workspaces, claims, evidence,
                            trust validation, index, and query
assets/             embedded runtime content copied by setup
docs/               current supporting docs, diagrams, and durable plans
```

## Prerequisites

- Rust stable toolchain (pinned via `rust-toolchain.toml`).
- SQLite with FTS5 support is provided by the bundled `rusqlite` dependency; no external
  database or retrieval service is required.

## Installation

Install the latest published binary:

```bash
cargo install --path crates/zbrain
zbrain setup
```

For local development:

```bash
git clone <repo>
cd zbrain
export ZBRAIN_HOME=/tmp/zbrain-dev
cargo run -q -p zbrain -- setup
```

## Configuration

`ZBRAIN_HOME` overrides the runtime root. Without it, the default is
`~/.zbrain/`. Use it for tests, smoke runs, and isolated experiments:

```bash
ZBRAIN_HOME=/tmp/zbrain-dev cargo run -q -p zbrain -- setup
```

`zbrain setup` creates `config.yml` when needed. The first
`workspace create <name>` sets `default_workspace`; later commands use that
workspace unless they receive `--workspace <name>`.

Runtime layout after setup and `workspace create research`:

```text
<ZBRAIN_HOME>/
  config.yml
  README.md                  # extracted runtime asset
  agents/
  engine/
  skills/
  templates/
  indexes/
    research.sqlite          # disposable SQLite FTS5 index
    research.dirty           # present while rebuild is incomplete
  workspaces/
    research/
      workspace.md
      agents/
      wiki/
        axioms/
        mental-models/
        projects/
        decisions/
      evidence/
        _index.md
        sources/<evd_id>/
          raw
          source.yaml
        analysis/
        qa/
        applied/
        archive/
```

`setup` extracts `README.md`, `agents/`, `engine/`, `skills/`, and `templates/`
from the embedded `assets/` filesystem. It does not activate a workspace seed;
`workspace create` creates the selected workspace and `reindex` creates its
disposable index.

## Local usage

Show the complete shipped command surface:

```bash
cargo run -q -p zbrain -- --help
```

Commands:

```text
zbrain setup
zbrain workspace create <name>
zbrain workspace current
zbrain evidence add --file <path> --origin <uri-or-path> [--media-type <type>] [--workspace <name>]
zbrain evidence check [--workspace <name>]
zbrain claim draft --tier <tier> --title <title> --basis <owner|evidence|derived> [--evidence <id>]... [--support <id>]... [--conflicts-with <id>]... [--workspace <name>]
zbrain claim approve <id> [--workspace <name>]
zbrain claim supersede <id> --tier <tier> --title <title> --basis <owner|evidence|derived> [--evidence <id>]... [--support <id>]... [--conflicts-with <id>]... [--workspace <name>]
zbrain claim revoke <id> --reason <text> [--workspace <name>]
zbrain migrate okf [--workspace <name>]
zbrain reindex [--workspace <name>] [--embed]
zbrain ask [--workspace <name>] [--include <name>]... [--embed] <query>
zbrain status [--workspace <name>]
zbrain doctor [--workspace <name>] [--probe-embedder]
zbrain mcp serve
zbrain view
zbrain approval show <challenge-id>
zbrain approval grant <challenge-id>
zbrain version
```

Create an isolated workspace and capture evidence:

```bash
export ZBRAIN_HOME=/tmp/zbrain-dev
cargo run -q -p zbrain -- setup
cargo run -q -p zbrain -- workspace create research
cargo run -q -p zbrain -- workspace current
cargo run -q -p zbrain -- evidence add \
  --file ./notes.txt \
  --origin file://notes.txt \
  --media-type text/plain
```

Create a claim from stdin, approve it, rebuild, and query it:

```bash
claim_json=$(printf 'The local source is authoritative.\n' | \
  cargo run -q -p zbrain -- claim draft \
    --tier projects \
    --title 'Source authority' \
    --basis owner)
claim_id=$(printf '%s' "$claim_json" | python3 -c \
  'import json,sys; print(json.load(sys.stdin)["id"])')
# The owner ceremony prompts on the terminal: type the last 16 hex characters
# of the printed action digest. A piped caller is refused.
cargo run -q -p zbrain -- claim approve "$claim_id"
cargo run -q -p zbrain -- reindex
cargo run -q -p zbrain -- status
cargo run -q -p zbrain -- ask authoritative source
```

Evidence-based claims must pass an evidence ID from `evidence add` using
`--evidence`. Derived claims must reference approved supporting claims or
verified evidence. `--include <name>` adds an explicit read-only secondary
workspace; it is never implicit.

Use `migrate okf` for legacy `schema: zbrain.claim/v1` files. It reports
whether reapproval is required; migration does not silently make an old
approval trusted.

### Optional hybrid retrieval

Lexical retrieval is the default for both the CLI and the MCP gateway. Pass
`--embed` to `zbrain ask` to opt into local hybrid retrieval, and use
`zbrain reindex --embed` to build the local loopback embedding sidecar. The MCP
`memory_reindex` and `memory_ask` tools expose the same opt-in as
`embedding: true`; their default is `false`. Embedding work is local-only and
never calls a network service. If the sidecar is missing or empty, an embedding
request falls back to lexical results instead of failing or changing trust
semantics.

### Owner-pinned lifecycle

An agent requests a lifecycle transition through the MCP `claim_lifecycle`
tool:

1. `prepare` binds the workspace, operation, claim ID, canonical draft digest,
   superseded IDs, prior verification digest, and revoke reason, then returns a
   challenge ID, action summary, and SHA-256 action digest.
2. The owner runs `zbrain approval show <challenge-id>` to inspect the bound
   action.
3. In an interactive TTY, the owner runs `zbrain approval grant
   <challenge-id>`, confirms the final 16 hexadecimal digest characters, and
   receives the one-time token.
4. The agent calls `claim_lifecycle` with `apply` and the challenge ID/token;
   the gateway revalidates the workspace, token, expiry, and current canonical
   state under the workspace lock before applying the transition.

The challenge is valid for 15 minutes from preparation. `prepare` emits no
plaintext token; the owner grant issues one and starts its own lifetime of up to
5 minutes, capped by the challenge expiry. The grant step records owner approval
without consuming the token; `apply` atomically consumes it once. Replay of a
consumed token, an expired challenge or token, a mismatched digest, workspace,
or claim, and a stale canonical draft all fail closed; the agent must prepare a
fresh challenge rather than retrying a stale action.

## Trust model

Trusted claims are OKF-style Markdown documents with:

```yaml
type: zbrain.claim
zbrain:
  profile: zbrain.trusted-memory/v1
  id: clm_<32 lowercase hex characters>
  tier: axioms | mental-models | projects | decisions
  basis: owner | evidence | derived
status: draft | approved | superseded | revoked
```

- `zbrain.id` is the stable trust identity; the path is not the identity.
- Approved claims are replaced through supersession, not in-place editing.
- Only valid `approved` claims enter trusted results.
- Drafts are returned, when matched, only as `promotion_candidates`.
- Approved claims carry a verification digest over their canonical rendered
  content.
- Evidence snapshots are immutable local copies; raw evidence is not indexed or
  treated as trusted instructions.
- `reindex` rejects invalid claims, invalid evidence, broken supporting-claim
  closures, and stale or legacy-unindexed trust inputs without rewriting them.
- `ask` fails closed for dirty, missing, stale, or rejected indexes.
- Explicit claim conflicts return `status: "blocked"`; no matching trusted
  claim returns `status: "gap"`.

## Testing

Run the repository's standard gates from the project root:

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
make build
make smoke
```

The smoke target uses an isolated temporary `ZBRAIN_HOME`. Useful additional
checks are:

```bash
cargo test -p zbrain --lib
cargo audit
ZBRAIN_BENCH_100K=1 cargo test -p zbrain --test bench_100k
```

Check every documented command group directly:

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

## Build and deployment

Build a standalone binary with:

```bash
make build
./dist/zbrain --help
```

The binary embeds runtime assets; deployment needs no JavaScript runtime,
package manager, hosted database, network crawler, or model provider. Run
`zbrain setup` on the target machine to extract its assets into that machine's
runtime root. Keep runtime data outside the repository and do not package
populated personal workspaces or credentials.

## Troubleshooting

- `no default workspace configured`: run `zbrain workspace create <name>`.
- `index does not exist`, `index is dirty`, `index is stale`, or `index is
  rejected`: run `zbrain reindex`, then inspect `zbrain status` and
  `zbrain doctor`.
- `doctor` reports domain findings with exit code `2`; its JSON includes
  `findings` and `next_action`.
- A `gap` is a trusted-memory miss, not permission to use drafts or raw
  evidence. Add or approve a valid claim, then reindex.
- A `blocked` result means the matched approved claims contain an explicit
  conflict; resolve it through the claim lifecycle.
- If `ZBRAIN_HOME` is set, every command in the session must use the same value
  to inspect the same runtime.

## Limitations

The current slice is intentionally local and minimal. It has no hosted sync,
network crawling, background service, GUI editor, remote or HTTP MCP
transport, hosted vector database, semantic-search requirement, session
transcript store, or model-provider integration. MCP is stdio-only, the viewer
is loopback-only, and optional embeddings are local sidecars rather than a
trust or availability requirement. All surfaces preserve the fail-closed
runtime contract.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a change. Keep command
handlers thin, put durable behavior in `crates/zbrain/src/`, preserve `assets/`
as the embedded runtime source of truth, and run the relevant cargo, build, smoke,
and documentation checks before submitting.

## License

zbrain is MIT-licensed. See [LICENSE](LICENSE).
