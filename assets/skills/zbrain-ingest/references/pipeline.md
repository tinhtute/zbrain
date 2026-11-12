# Deprecated Pipeline Reference

The previous learn/ingest/apply pipeline is not implemented in the current runtime.

Current supported flow; pass each caller-controlled value as a separate argv element. Resolve the primary workspace with `zbrain workspace current`; use `--workspace "$workspace"` only after explicit selection, and use `--include "$include"` only for an explicitly permitted read-only secondary workspace.

1. `zbrain evidence add --file "$file" --origin "$origin" [--media-type "$media_type"] [--workspace "$workspace"]`
2. `zbrain claim draft --tier "$tier" --title "$title" --basis "$basis" [--evidence "$evidence_id"]... [--support "$support_id"]... [--conflicts-with "$conflict_id"]... [--workspace "$workspace"]`
3. Owner only, in an interactive terminal: `zbrain claim approve "$id" [--workspace "$workspace"]`, confirming the last 16 hex characters of the action digest. An agent shell is refused; hand the draft to the owner.
4. `zbrain reindex [--workspace "$workspace"]`
5. `zbrain ask [--workspace "$workspace"] [--include "$include"]... "$query"`
