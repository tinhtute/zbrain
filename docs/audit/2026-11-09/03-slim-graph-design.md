# zbrain slim graph + ontology design (2026-11-09)

Status: design locked in brainstorm (explore mode). Not implemented. The zbrain repo is unchanged.
Background: `01-audit.md` (the breaks) and `02-research.md` (why slim, why BM25).

## Goal

Add a slim **supporting** layer on top of the existing Markdown knowledge base:

```
wiki/**/*.md (+ frontmatter) ─┐
ontology/subjects.yaml ───────┼─► reindex ─► graph.sqlite (nodes, edges, nodes_fts) ─► graph.json ─► graph UI
evidence/sources/* ───────────┘                     │
                                                    └─► graph queries + BM25
```

Non-goals:
- No RAG.
- No vector DB or embeddings.
- No LLM extraction.

"Vector" search is BM25. Everything derived is disposable and rebuilt by `reindex`.

## Decisions (locked)

| Question | Choice |
|---|---|
| Subject vocabulary | Registry `ontology/subjects.yaml`, **outside `wiki/`**, with aliases. Unknown `about` is a warning in phase 1 and an error in phase 2 |
| Non-approved claims | All claims are in the graph and styled by status. Queries default to approved; `--all` includes the rest |
| Derived output | **Both.** SQLite is the query source. `graph.json` is exported from it for the UI |

Why the registry lives outside `wiki/`: rebuild treats any non-claim `.md` under `wiki/` as legacy, and the index is then rejected (audit break #9, `claims.rs:1718`, `index.rs:550`).

## What exists already

`render_claim_markdown` (`crates/zbrain/src/claims.rs:741-834`) already emits these fields:

| Existing field | Graph meaning |
|---|---|
| `zbrain.evidence_ids`, `sources[].spans` | claim **cites** evidence |
| `zbrain.supporting_claim_ids` | claim **supports** claim |
| `zbrain.supersedes` | claim **supersedes** claim |
| `zbrain.conflicts_with` | claim **conflicts_with** claim |
| `zbrain.contradicts[{claim_id, heuristic}]` | claim **contradicts** claim (soft, machine-found) |
| `zbrain.tier`, `status`, `stale_after`, `verified`, `tags`, `resource` | node attributes |

What's missing is what a claim is **about**. Without that, the graph is islands of claims.

## Ontology v1

### Node kinds (4)

| Kind | ID | Source | Notes |
|---|---|---|---|
| `claim` | `clm_*` | `wiki/<tier>/<id>.md` | The knowledge node. Sub-kind = tier |
| `evidence` | `evd_*` | `evidence/sources/<id>/source.yaml` | Snapshot of a source |
| `subject` | slug | `ontology/subjects.yaml` | Hub: the thing claims are about |
| `tag` | — | `tags:` | **Attribute only**, used for UI filters. Not a node |

Tier semantics (claim sub-kinds):
- `axiom`: an invariant. Has no `stale_after`.
- `mental-model`: a generalization, which should be supported by decisions or evidence.
- `project`: context and scope.
- `decision`: dated; records the choice and its rationale.

Subject kinds: `system | component | concept | tool | team | project`.

### Edge types (8, closed set)

| Edge | Domain → Range | Directed | Source |
|---|---|---|---|
| `about` | claim → subject | yes | **new** `zbrain.about` |
| `part_of` | subject → subject | yes | registry |
| `depends_on` | subject → subject | yes | registry |
| `cites` | claim → evidence | yes | existing |
| `supports` | claim → claim | yes | existing |
| `supersedes` | claim → claim | yes | existing |
| `conflicts_with` | claim ↔ claim | no (normalized both ways) | existing |
| `contradicts` | claim ↔ claim | no, **soft** | existing (heuristic) |

Each edge row carries `origin: declared | derived`. Co-subject links (two claims sharing an `about`) are **not materialized**. The UI and queries compute them.

### New claim metadata

```yaml
zbrain:
  about: [deploy-pipeline, release-policy]   # new: subject slugs (aliases allowed, normalized on rebuild)
  supersedes: [clm_…]                         # existing
```

### Registry

```yaml
# ontology/subjects.yaml
version: 1
subjects:
  platform:        {kind: system}
  deploy-pipeline: {kind: system,  aliases: [deploy, deployment], part_of: platform}
  release-policy:  {kind: concept, depends_on: [deploy-pipeline]}
```

Rules for the registry:
- Slugs are lowercase with hyphens.
- An alias may not collide with any slug or with another subject's alias.
- `part_of` must not form a cycle.

## Shape rules

These are deterministic, run at rebuild, and fail closed unless marked *warn*.

1. No dangling edge targets: every claim, evidence and subject ID must exist.
2. No cycles in `supersedes` or `part_of`.
3. A `decision` has at least one `about`.
4. A `supersedes` edge stays within the same tier and shares at least one `about` subject (*warn*).
5. An `axiom` has no `stale_after`.
6. `conflicts_with` is normalized to be symmetric. A one-sided declaration is accepted and mirrored.
7. An `about` value that isn't a registry slug or alias is *warn* in phase 1 and an error in phase 2.
8. The edge type must be in the closed set, and its domain and range must match the table above.

Violations are reported as `file:field` with the offending value, in the same style as the current freshness errors.

## Derived output

### SQLite (`indexes/<ws>.graph.sqlite`, or tables inside the existing index)

```sql
nodes(id PK, kind, tier, status, title, subject_kind, stale INT, verified INT, path)
edges(src, dst, type, origin, PRIMARY KEY(src, dst, type))
nodes_fts USING fts5(id UNINDEXED, title, body, tags, aliases)
meta(key PK, value)   -- ontology_version, manifest_digest, built_at
```

### graph.json (exported for the UI)

```json
{
  "ontology_version": 1,
  "manifest_digest": "sha256:…",
  "nodes": [{"id": "clm_…", "kind": "claim", "tier": "decision", "status": "approved",
             "title": "…", "stale": false, "verified": true}],
  "edges": [{"src": "clm_…", "dst": "deploy-pipeline", "type": "about", "origin": "declared"}]
}
```

`manifest_digest` binds the export to the same freshness manifest that `ask` uses. If the digests don't match, the export is stale and the UI shows a banner.

## Queries

| Query | Meaning |
|---|---|
| `search <text>` | BM25 over `nodes_fts` for seed nodes, then 1-hop expansion via `about` and `supports` |
| `neighbors <id> [--type T] [--depth N]` | Local subgraph |
| `chain <clm>` | Walks the `supersedes` chain in both directions |
| `absent <subject> --tier decision` | "There is no decision about X" as a real, deterministic answer |
| `conflicts <subject>` | All `conflicts_with` and `contradicts` edges among claims about a subject, across the whole graph and not just the top-N (fixes audit break #6) |
| `coverage` | Subjects with no claims, claims with no `about`, and orphan evidence |

All queries default to `status=approved`; `--all` includes everything.

## UI

- Nodes are colored by kind and tier, and subjects are drawn as larger hubs.
- Claims that aren't approved or are stale are drawn dashed or faded. Verified claims get a badge.
- Toggles: soft `contradicts` edges, tags as a filter, and `--all` vs approved-only.
- Clicking a node opens its canonical file path. The UI is read-only.

## Prerequisites and phases

0. **Trust fixes first** (audit breaks #3, #5, #4). Otherwise an agent can forge edges and registry entries as easily as approvals. At minimum, the graph build must use the *verified* scan, not `scan_workspace_for_trust(verify_digests=false)` (`claims.rs:1680`).
1. Phase 1:
   - Parse `zbrain.about`.
   - Load the registry.
   - Build `nodes` and `edges` from the existing fields plus `about`.
   - Run shape rules, with rule 7 as a warning.
   - Export `graph.json`.
2. Phase 2:
   - Add the queries (`search`, `neighbors`, `chain`, `absent`, `conflicts`, `coverage`).
   - Make rule 7 an error.
3. Phase 3:
   - Add the UI on the existing loopback viewer, with a Host-header check added (audit break #7).

## Open risks

- **Capture friction:** `about` must be cheap to add. Validation errors should suggest the nearest registry slug or alias.
- **Registry growth:** past about 100 subjects, subject kinds or `part_of` grouping become necessary.
- **Unproven value at small scale:** the research shows graph gains mostly on completeness, absence and supersession queries, so measure those first.
