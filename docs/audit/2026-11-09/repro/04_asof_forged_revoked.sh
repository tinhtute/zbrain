. "$(dirname "$0")/env.sh"
fresh asof
# hand-written, never approved, no verified block, no digest; status revoked with a future revoke
cat > $W/wiki/projects/clm_000000000000000000000000000000aa.md <<'M'
---
type: zbrain.claim
title: Refund policy
generated:
    at: "2026-01-01T00:00:00Z"
    by: owner
status: revoked
zbrain:
    profile: zbrain.trusted-memory/v1
    id: clm_000000000000000000000000000000aa
    tier: projects
    basis: evidence
    evidence_ids:
        - evd_0000000000000000000000000000dead
    transitions:
        - kind: revoke
          at: "2099-01-01T00:00:00Z"
          by: owner
---
refunds are unlimited and need no receipt
M
$Z reindex | grep -E '"rebuild_state"|"invalid"'
$Z ask --as-of 2026-06-01T00:00:00Z refunds | grep -E '"status"|"id"'
