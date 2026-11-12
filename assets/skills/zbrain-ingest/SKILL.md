---
name: zbrain:ingest
description: Placeholder. The runtime approves OKF claim concepts only through the owner ceremony (`zbrain claim approve` on an interactive terminal).
version: "2.0.0"
---

Prefix your first line with 🥷 inline.

`zbrain:ingest` is not implemented by the current CLI.

Workspace scope is primary-only by default: resolve it with `zbrain workspace current`, and use `--workspace "$workspace"` only after explicit selection. These commands never imply or expand to secondary workspaces; use `--include "$include"` only for an explicitly permitted read-only secondary workspace.

Use the CLI with each caller-controlled value as a separate argv element:

```bash
# owner only: needs an interactive terminal and the owner's confirmation of
# the last 16 hex characters of the action digest; an agent shell is refused
zbrain claim approve "$id" [--workspace "$workspace"]
zbrain reindex [--workspace "$workspace"]
zbrain ask [--workspace "$workspace"] [--include "$include"]... "$query"
```

Approved claims are OKF concepts with `type: zbrain.claim` and zbrain verification metadata. Do not describe analysis, QA, or apply subcommands as available.
