# Research: agent memory KB + graph/ontology (2026-11-09)

Two parts. Part 1 is the field survey. Part 2 covers graph and ontology evolution.

## Part 1: Agent memory / knowledge base: what it should have (2026-11-09)

This research is the context for the zbrain audit in `01-audit.md`.

Verdict: zbrain's direction matches where the field is heading. Files are canonical, derived state can be rebuilt, and queries fail closed. Its breaks fall on the blind spots the 2026 papers name, the biggest being write-gate validation.

### Must-haves

| # | Must-have | Source |
|---|---|---|
| 1 | Canonical store in human-readable files, with a derived index | Letta filesystem: 74% on LoCoMo with files and grep, vs Mem0's self-reported 68.5% (both are self-reported). Anthropic memory tool (client-side `/memories`). Basic Memory (Markdown + MCP) |
| 2 | Write gate: check provenance, consistency and authorization before commit | Survey 2604.16548 identifies 9 governance primitives. No architecture covers all of them, and "write-gate validation and post-deletion verification are shared blind spots" |
| 3 | Resistance to memory poisoning | MINJA 2503.03704 injects through queries only, at >95% under its benchmark conditions. AgentPoison reports ASR >80%. 2601.05504 finds Llama Guard-style moderation largely ineffective |
| 4 | Immutable provenance per fragment (who wrote it, which source, when) | Collaborative Memory 2505.18279; MemClaw 2606.24535 |
| 5 | Bi-temporal records (valid time vs ingest time), with supersession instead of deletion | Zep/Graphiti 2501.13956; MemClaw "temporal supersession" |
| 6 | Abstention based on context sufficiency, not similarity score | Sufficient Context 2411.06037: models answer wrong instead of abstaining. LongMemEval 2410.10813 tests abstention and knowledge updates |
| 7 | Contradiction handling | MemClaw lists "contradiction persistence" as one of its 4 failure modes |
| 8 | Scope and permissions for teams (private vs shared tiers, separate read/write policies) | Collaborative Memory; GateMem 2606.18829 finds current designs "brittle" with multiple principals |
| 9 | Care during consolidation, because summarizing a poisoned entry gives it authority | Survey 2604.16548 |

### What the big projects do

- **Letta (MemGPT):** in-context memory blocks that the agent edits, plus archival memory and a filesystem outside context.
- **Mem0:** each extracted fact is reconciled against existing memory with ADD/UPDATE/DELETE/NOOP. Reported: −91% p95 latency and −90% tokens vs full context.
- **Zep/Graphiti:** edges carry valid/invalid times, and old facts are invalidated rather than deleted.
- **A-MEM:** Zettelkasten-style atomic notes, with automatic linking and "memory evolution".
- **Basic Memory:** Markdown with frontmatter and relations, opens in Obsidian, rebuildable SQLite index. It is the closest project to zbrain.
- **Anthropic memory tool:** client-side storage restricted to `/memories`. Reported +39% with context editing.

### Mapping to the zbrain audit

| Audit break | Literature | Fix direction |
|---|---|---|
| #3 self-attested approval (keyless sha256) | write-gate blind spot, MINJA | Sign approvals with an owner key the agent can't reach |
| #1 `--as-of` skips verification | Bi-temporal supersession (Zep) | Verify superseded and revoked versions too |
| #2 `--embed` has no floor | Sufficient context | Add a similarity floor, or require a lexical hit for `ready` |
| #6 conflicts only within the top-10 | Contradiction persistence | Check conflicts across the whole graph |
| #4 viewer and MCP read without verification | Scoped retrieval | Route every read through one verified path |
| (missing) team use | Collaborative Memory, GateMem | Private/shared tiers and writer identity |

### Caveats

- There are almost no papers on personal or small-team knowledge bases specifically. That space is mostly practitioner projects (Basic Memory, Obsidian MCP, agentkb).
- Most 2026 papers cited here are preprints.
- The Mem0 and Letta LoCoMo numbers are self-reported and contested.

### Sources

- Surveys: https://arxiv.org/abs/2603.07670 · https://arxiv.org/abs/2605.06716 · https://arxiv.org/pdf/2512.13564 · https://arxiv.org/pdf/2606.30306
- Systems:
  - Zep: https://arxiv.org/html/2501.13956v1
  - Mem0: https://arxiv.org/abs/2504.19413
  - A-MEM: https://arxiv.org/abs/2502.12110
- Evaluation:
  - LongMemEval: https://arxiv.org/pdf/2410.10813
  - Sufficient Context: https://arxiv.org/abs/2411.06037
- Shared memory and governance:
  - Collaborative Memory: https://arxiv.org/html/2505.18279v1
  - MemClaw: https://arxiv.org/abs/2606.24535
  - GateMem: https://arxiv.org/pdf/2606.18829
  - MAP-Graph: https://arxiv.org/html/2608.10509v1
  - Governed Collaborative Memory: https://arxiv.org/pdf/2605.04264
- Security:
  - Security survey: https://arxiv.org/html/2604.16548v1
  - MINJA: https://arxiv.org/html/2503.03704v5
  - Poisoning defense: https://arxiv.org/html/2601.05504v1
- Industry:
  - Letta filesystem benchmark: https://www.letta.com/blog/benchmarking-ai-agent-memory
  - Letta memory blocks: https://www.letta.com/blog/memory-blocks
  - Critique of file-based memory: https://buttondown.com/nicoloboschi/archive/file-based-agent-memory-great-demo-good-luck-in/
  - Anthropic memory tool: https://platform.claude.com/en/docs/agents-and-tools/tool-use/memory-tool
  - Anthropic context management: https://claude.com/blog/context-management
  - Basic Memory: https://mcpservers.org/servers/basicmachines-co/basic-memory
  - agentkb: https://github.com/isaac-flath/agentkb

## Part 2: Evolving the knowledge base: graph + ontology (2026-11-09)

Verdict: don't move to GraphRAG or a graph database. Add a **small typed ontology plus typed edges in the canonical files**, validate them with shapes, and keep the graph as derived state. In this design, the graph exists to answer structural questions: completeness ("list all…"), absence ("is there no decision on X?"), supersession chains, and conflicts. Fuzzy recall stays with BM25.

### Evidence

**Graphs don't help plain retrieval:**
- GraphRAG-Bench (2506.05690, ICLR 2026) reports GraphRAG "frequently underperforms vanilla RAG" on simple fact retrieval and helps on multi-hop reasoning and summarization.
- A third-party summary of that benchmark puts graph indexing at 10–100x the token cost.
- RAG vs GraphRAG (2502.11371) finds the two complementary: RAG is better on fine detail, GraphRAG on diverse summaries.

**BM25 is the scalable default:**
- BM25 Wins at Scale (2607.26497) compared BM25, dense retrieval, graph RAG and a file-system agent.
  - BM25 overtakes the agent at about 10M corpus tokens and leads by ~20 points at full scale.
  - Graph RAG hits "construction walls" before deployment scale.
  - The authors' conclusion: agentic reasoning works best *after* ranked discovery.

**Typed ontology memory wins on structure:**
- MOOSEDev (2608.13662), *Ontology-Grounded Project Memory for Coding Agents*.
- Design:
  - two small OWL ontologies (9 + 11 classes, 51 properties);
  - SHACL-validated typed capture, served over MCP;
  - typed records for decisions, lessons, constraints, rationales and anti-patterns, with supersedes, affects, status, author and timestamp.
- Results vs mem0:

  | Task | MOOSEDev | mem0 |
  |---|---|---|
  | Completeness | 1.00 | 0.18 |
  | Negation | 0.98 | 0.06 |
  | Supersession | 0.98 | 0.27 |
  | Plain relevance | ties | ties |

- Caveats: single author/vendor, self-authored benchmark, one model family, proprietary engine. Capture friction is a real cost: flat capture falls back to free-text parity.

**Extraction should be constrained by an ontology:**
- OG-RAG (2412.15235): ontology-grounded hypergraph, +55% fact recall and +40% correctness.
- Neuro-symbolic post-extraction correction (2605.29168, EMNLP Findings 2026): extract openly, map to the ontology, detect violations *symbolically*, then fix them with targeted LLM calls. This keeps the ontology out of the prompt.

**How existing projects handle the schema:**
- Graphiti supports a prescribed or a learned ontology through Pydantic entity and edge types. Schema changes are additive. Applying new types to old data requires re-ingestion.
- Cognee validates against an optional OWL/RDF file and tags each node as ontology-valid or not. The file is parsed at initialization, so edits need a restart.

**Ontology evolution is still open:**
- 2604.00555 proposes supervised evolution: agents surface unknown concepts, approved extensions are merged with provenance. It is unevaluated (future work).
- SSGM (2603.11768) warns about semantic drift during consolidation.
- I found no paper on SHACL plus schema drift in agent memory.

### What this means for zbrain

zbrain already has a proto-ontology: tiers (axioms, mental-models, projects, decisions), claims, evidence, supersede/revoke, and conflicts. Path, in order:

0. **Fix trust first** (audit breaks #3, #5, #4). Otherwise an agent can rewrite the ontology or the edges just as it can forge approvals.
1. **Ontology as a canonical, versioned file**, for example `ontology.yaml`, or Turtle if OWL tooling is wanted. Keep it small, MOOSEDev-sized (~10–20 classes).
   - Node types are the claim kinds.
   - Edge types include `supersedes`, `conflicts_with`, `depends_on`, `affects`/`about`, `derived_from` (evidence), with domain and range.
2. **Edges live in claim frontmatter**, as in Basic Memory relations. The graph is derived SQLite tables (`nodes` and `edges`) rebuilt by `reindex`, so a schema change is just a rebuild. Graphiti's "re-ingest" problem disappears.
3. **Shape validation at write and at rebuild**, SHACL-like: required properties, cardinality, edge domain/range, no dangling targets. A violation fails closed, the same way legacy files do today.
4. **Deterministic structural queries:** `list`, `absent`, `chain`, `conflicts`. "No decision about X" becomes a real, verifiable answer instead of a `gap`.
   - Conflict checks walk the graph, which fixes break #6.
   - `as_of` walks the supersession chain with verification, which fixes break #1.
5. **Retrieval stays BM25-first.** Graph expansion from the hits (one hop, or HippoRAG-style PPR) applies only to multi-hop questions. Skip GraphRAG community summaries at personal or team scale.
6. **Ontology evolution through the owner ceremony:**
   - agents propose a new type or edge as a candidate;
   - the owner approves it, with provenance recorded;
   - the version is bumped and the index rebuilt.
   - Optionally, LLM extraction can feed candidates through neuro-symbolic correction (2605.29168), never writing canonical files directly.

### Risks

- Capture friction: a strict schema makes agents write less, or write flat records.
- LLM extraction errors become typed errors that look authoritative.
- Graph value is unproven at small scale. MOOSEDev's scale slope CI includes zero.

### Sources

- When to use graphs in RAG: https://arxiv.org/pdf/2506.05690
- RAG vs GraphRAG: https://arxiv.org/pdf/2502.11371
- BM25 Wins at Scale: https://arxiv.org/abs/2607.26497
- MOOSEDev: https://arxiv.org/html/2608.13662v1
- OG-RAG: https://arxiv.org/abs/2412.15235v1
- Neuro-symbolic KG correction: https://arxiv.org/html/2605.29168
- Ontology learning vs RAG: https://arxiv.org/pdf/2511.05991
- LLM KG construction survey: https://arxiv.org/pdf/2510.20345
- Ontology-constrained enterprise agents: https://arxiv.org/html/2604.00555v2
- SSGM: https://arxiv.org/abs/2603.11768
- Automatic ontology construction (SHACL): https://arxiv.org/pdf/2604.20795
- Graph-based personalized memory survey: https://arxiv.org/pdf/2609.08599 (abstract not readable in fetch)
- Graphiti custom types: https://help.getzep.com/graphiti/core-concepts/custom-entity-and-edge-types
- Cognee ontology: https://docs.cognee.ai/guides/ontology-support
- Cognee grounding: https://www.cognee.ai/blog/deep-dives/grounding-ai-memory
