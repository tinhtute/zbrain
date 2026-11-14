# CLI Contract — Output, Quiet, and Color

> Audit for Wave 1 D1 per `docs/plans/active/zbrain-optimization-plan.md` §6 4.1.
> Covers `--quiet` / `--no-color` decision and `internal/cli/cli.go:835`.
>
> **Cutover note (m8):** this audit is historical evidence from the Go era.
> The contract itself (stdout = protocol, stderr = diagnostics, no color
> codes) still holds and is enforced by `scripts/cli-parity.sh` equivalents and
> the Rust test suite. Go file/line references below map to the frozen Go tree
> (tag `v0.2.0-go-final`); live equivalents live in `crates/zbrain/src/cli.rs`.
> Verification commands below are Go-era; current commands are
> `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`,
> `cargo run -q -p zbrain -- --help | cat -A`.

## 1. Output streams

zbrain follows **stdout = protocol, stderr = diagnostics** (see `AGENTS.md` Workspace & Runtime Gotchas and `internal/cli/cli.go`).

| Stream | Content | Examples |
|---|---|---|
| `Stdout` | Machine-parseable JSON (via `writeJSON`) and `--help` usage text; each success prints a single JSON document + `\n` | `ask`, `claim draft/approve/resign/supersede/revoke`, `evidence add`, `reindex`, `status`, `doctor`, `migrate okf`, `approval show/grant`, `key init`, `workspace current` |
| `Stderr` | Human diagnostics and TTY prompts only | `approval grant`, `claim approve`, and `claim resign`: `action digest: …` / `confirm the last 16 hex…` (`cli.go:369-380`), `mcp serve` diagnostics (`mcp/…`, `Stderr: app.Stderr` at `cli.go:276`) |

Verification:

```bash
grep -rn "writeJSON\|fmt\.Fprint.*Stdout\|fmt\.Fprint.*Stderr" internal/cli/cli.go
# writeJSON -> Stdout for all mutation/query commands
# Stderr only for approval ceremony prompts and mcp gateway
```

All JSON commands exit `0` on success with `schema_version` and emit no extra chatter to stdout beyond the JSON document. Help (`--help`) deliberately prints to stdout as the protocol for that command.

Two creation confirmations use plain text to stdout (not JSON) for backward compatibility:

* `zbrain setup` — `fmt.Fprintf(app.Stdout, "zbrain setup complete\n…")` at `cli.go:469`
* `zbrain workspace create <name>` — `fmt.Fprintf(app.Stdout, "workspace created: %s\n", rest[0])` at `cli.go:835`

Both are single-line/one-shot creation confirmations, not per-query chatter.

## 2. `--quiet` — not needed

**Decision: do not add `--quiet`.** Rationale:

* zbrain is **JSON-only** for automation. `ask`, `claim`, `evidence`, `reindex`, `status`, `doctor`, `mcp serve`, `approval`, `workspace current` each write exactly one JSON document to stdout. That is already the minimal/quiet form — there is nothing verbose to suppress (no progress bars, spinners, or info logs on stdout).
* Human diagnostics already go to stderr, so piping `zbrain ask … > out.json` captures only JSON without extra flags.
* Adding `--quiet` would only suppress the two plain-text confirmations above (`setup`, `workspace create`). Those are intentional success signals for interactive use; scripts can ignore them by checking exit code or redirecting. Suppressing them behind a flag adds surface without fixing a real pain.

If a future lint requires a flag, the implementation is a guarded global flag around the single human line:

```go
// internal/cli/cli.go:835 — current:
_, err = fmt.Fprintf(app.Stdout, "workspace created: %s\n", rest[0])

// with --quiet (global, parsed before dispatch):
// if !quiet { fmt.Fprintf(app.Stdout, "workspace created: %s\n", rest[0]) }
```

The plan note cites `fmt.Fprintf(Stderr, "workspace created")`; current code writes to `Stdout` (`cli.go:835`), so the guard would wrap that `Stdout` call. `setup` (`cli.go:469`) would receive the same guard if consistency is desired. Help output remains unguarded (`--help` is its own protocol).

## 3. `--no-color` — not needed

**Decision: do not add `--no-color`.** Rationale:

* No command emits ANSI color or escape codes. Verified:

```bash
grep -R --include="*.go" -E '\x1b|\\u001b|ansi|color' internal/ cmd/ | grep -v worktree
# (no output in repository code)
grep -R "color" --include="*.go" internal/cli/cli.go
# (no output)
```

* All stdout JSON and stderr prompts are plain UTF-8. There is no `FORCE_COLOR`, `NO_COLOR` handling or color library imported.
* `--no-color` would be a no-op. Automation never needs to strip color.

## 4. `internal/cli/cli.go:835` audit

```go
// runWorkspace — workspace create branch (cli.go:820-836)
if err := zruntime.CreateWorkspace(app.Paths, rest[0], app.Now()); err != nil {
    return err
}
_, err = fmt.Fprintf(app.Stdout, "workspace created: %s\n", rest[0])
return err
```

* Writes to **Stdout** (not Stderr) — plan text `Stderr` is a doc shorthand; actual is `Stdout`.
* Single line, no JSON. Consistent with `setup` pattern; acceptable because `workspace current` (the scriptable form) already returns JSON (`MarshalCurrent`).
* Not suppressed today. Exit code `0` already signals success; callers needing quiet can `zbrain workspace create foo >/dev/null` or ignore the line.

## 5. `cli-agent-lint` disposition

`cli-agent-lint` category `TE` check `p7-quiet` (`TE-quiet`) expects a `--quiet`/`--silent` flag for CLIs that write human chatter to stdout. zbrain's JSON protocol satisfies the intent without a flag.

```
skip: TE-quiet reason: json-only
```

* `json-only` — every automation-facing command outputs quiet-by-default JSON to stdout; stderr carries diagnostics. No verbose stdout to silence. The two plain-text confirmations (`setup`, `workspace create:835`) are single-line creation acks, not per-invocation verbose logs. Adding `--quiet` would be a flag alias for `>/dev/null` on that one line.

Similarly, `TE` `no-color` check passes vacuously (no color codes emitted).

## 6. Verification

```bash
go vet ./...                                   # 0 warnings
go test ./internal/cli -count=1                # ok
grep -rn "workspace created" internal/cli/cli.go  # cli.go:835 only Stdout line above
go run ./cmd/zbrain --help | cat -A            # no ESC (\x1b) color codes
go run ./cmd/zbrain workspace create --help    # Usage: zbrain workspace create <name>
```

No changes to `internal/cli/cli.go` in this audit. If `--quiet` is later required by a consumer, add a global `quiet` bool parsed in `App.Run` before the `switch args[0]` dispatch and guard `cli.go:835` (and optionally `cli.go:469`) as shown in §2.
