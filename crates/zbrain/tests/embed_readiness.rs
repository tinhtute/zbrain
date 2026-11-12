//! `ask --embed` must not answer `ready` from a vector that has nothing to do
//! with the query. The loopback embedder is a hashed bag-of-words, so a vector
//! only carries evidence when it shares a meaningful token with the query;
//! otherwise the fused result is a hit by collision or by stopword only.
//!
//! Audit repro 13 (`docs/audit/2026-11-09/repro/13_embed_never_gaps.sh`):
//! query "quantum chromodynamics lattice" against the single claim "Deploy
//! window" answered `ready` under `--embed` and `gap` lexically.

use std::sync::Arc;

use chrono::{TimeZone, Utc};

use zbrain::claims::{Claim, ClaimStore, CLAIM_BASIS_OWNER, OKF_CLAIM_TYPE};
use zbrain::clock::FixedClock;
use zbrain::embedder::RebuildOptions;
use zbrain::mcp::transport::MemoryTransport;
use zbrain::mcp::{McpOptions, Server, ZbrainRegistry};
use zbrain::paths::{Options, Paths};
use zbrain::query::{
    trusted_query, TrustedQueryOptions, TrustedQueryResponse, QUERY_STATUS_GAP, QUERY_STATUS_READY,
};

fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 11, 12, 9, 0, 0).unwrap()
}

/// Temp runtime root, temp key directory, and a `research` workspace with the
/// owner key initialised. Never touches `~/.zbrain` or `~/.config`.
fn test_paths(name: &str) -> (std::path::PathBuf, Paths) {
    static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "zbrain-embed-readiness-{}-{}-{name}",
        std::process::id(),
        COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut paths = Paths::resolve(Options {
        cwd: Some(dir.join("project")),
        home_dir: Some(dir.clone()),
        runtime_dir: Some(dir.join(".zbrain")),
    })
    .unwrap();
    paths.key_dir = dir.join("xdg/zbrain-keys");
    zbrain::config::ensure_config(&paths.config_file).unwrap();
    zbrain::assets::extract_bundled_assets(&paths).unwrap();
    zbrain::workspace::create_workspace(&paths, "research", &FixedClock::new(now())).unwrap();
    zbrain::signing::KeyStore::init(&paths, now()).unwrap();
    (dir, paths)
}

fn claim_store(paths: &Paths) -> ClaimStore {
    ClaimStore::with_clock(paths.clone(), Arc::new(FixedClock::new(now())))
}

fn approve_claim(paths: &Paths, id: &str, title: &str, body: &str) {
    let store = claim_store(paths);
    let created = store
        .write_draft(
            "research",
            Claim {
                claim_type: OKF_CLAIM_TYPE.to_string(),
                id: id.to_string(),
                tier: "projects".to_string(),
                status: zbrain::claims::CLAIM_STATUS_DRAFT.to_string(),
                title: title.to_string(),
                basis: CLAIM_BASIS_OWNER.to_string(),
                created_at: "2026-11-12T09:00:00Z".to_string(),
                created_by: "owner".to_string(),
                body: body.to_string(),
                ..Claim::default()
            },
        )
        .unwrap();
    store.approve("research", &created.id).unwrap();
}

fn reindex_with_embeddings(paths: &Paths) {
    zbrain::embedder::rebuild_with_options(paths, "research", RebuildOptions { embedding: true })
        .unwrap();
}

fn ask(paths: &Paths, query: &str, embedding: bool) -> TrustedQueryResponse {
    trusted_query(
        paths,
        TrustedQueryOptions {
            workspace: "research".into(),
            query: query.into(),
            limit: 10,
            embedding,
            ..TrustedQueryOptions::default()
        },
    )
    .unwrap()
}

fn claim_ids(response: &TrustedQueryResponse) -> Vec<String> {
    response
        .claims
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .map(|claim| claim.id.clone())
        .collect()
}

/// Repro 13: a query sharing no token with the only claim must stay a gap.
#[test]
fn embed_does_not_turn_a_miss_into_ready() {
    let (dir, paths) = test_paths("miss");
    approve_claim(
        &paths,
        "clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "Deploy window",
        "the deploy window is tuesday",
    );
    reindex_with_embeddings(&paths);

    let query = "quantum chromodynamics lattice";
    let lexical = ask(&paths, query, false);
    assert_eq!(
        lexical.status, QUERY_STATUS_GAP,
        "lexical baseline must gap: {:?}",
        lexical.claims
    );
    let embedded = ask(&paths, query, true);
    assert_eq!(
        embedded.status, QUERY_STATUS_GAP,
        "an unrelated claim must not answer ready under --embed: {:?}",
        embedded.claims
    );
    assert!(
        claim_ids(&embedded).is_empty(),
        "gap response must carry no claims: {:?}",
        embedded.claims
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// `--embed` keeps its recall: a claim sharing some (not all) query tokens is
/// still returned, so the gate does not collapse `--embed` into lexical.
#[test]
fn embed_keeps_partial_token_overlap_recall() {
    let (dir, paths) = test_paths("overlap");
    let full = "clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let partial = "clm_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    approve_claim(
        &paths,
        full,
        "Quantum Entanglement Observer",
        "quantum entanglement observer discovery",
    );
    approve_claim(
        &paths,
        partial,
        "Entangled Observer",
        "entanglement observer phenomena",
    );
    reindex_with_embeddings(&paths);

    let query = "quantum entanglement observer";
    let lexical = ask(&paths, query, false);
    assert_eq!(claim_ids(&lexical), vec![full.to_string()]);

    let embedded = ask(&paths, query, true);
    assert_eq!(embedded.status, QUERY_STATUS_READY);
    let ids = claim_ids(&embedded);
    assert_eq!(
        ids.first().map(String::as_str),
        Some(full),
        "the full lexical match must rank first: {ids:?}"
    );
    assert!(
        ids.contains(&partial.to_string()),
        "partial token overlap must stay reachable through --embed: {ids:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// loopback-v1 is a hashed bag-of-words: a paraphrase with no shared token has
/// cosine 0.0, so it cannot be answered and must gap. This test documents the
/// embedder's ceiling; a future semantic embedder flips it deliberately.
#[test]
fn embed_cannot_answer_a_paraphrase_without_shared_tokens() {
    let (dir, paths) = test_paths("paraphrase");
    approve_claim(
        &paths,
        "clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "Deploy window",
        "the deploy window is tuesday",
    );
    reindex_with_embeddings(&paths);

    let response = ask(&paths, "when can we ship to prod", true);
    assert_eq!(
        response.status, QUERY_STATUS_GAP,
        "loopback-v1 has no paraphrase recall: {:?}",
        response.claims
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A shared stopword is not evidence. "what is the capital of peru" overlaps
/// the claim only on "is"/"the", which must not answer ready.
#[test]
fn embed_gaps_when_the_only_shared_token_is_a_stopword() {
    let (dir, paths) = test_paths("stopword");
    approve_claim(
        &paths,
        "clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "Deploy window",
        "the deploy window is tuesday",
    );
    reindex_with_embeddings(&paths);

    let query = "what is the capital of peru";
    assert_eq!(ask(&paths, query, false).status, QUERY_STATUS_GAP);
    let embedded = ask(&paths, query, true);
    assert_eq!(
        embedded.status, QUERY_STATUS_GAP,
        "a stopword overlap must not answer ready: {:?}",
        embedded.claims
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The MCP `memory_ask` tool shares `trusted_query`, so it must gap too.
#[test]
fn memory_ask_embedding_shares_the_readiness_rule() {
    let (dir, paths) = test_paths("mcp");
    approve_claim(
        &paths,
        "clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "Deploy window",
        "the deploy window is tuesday",
    );
    reindex_with_embeddings(&paths);

    let requests = format!(
        "{}\n{}\n{}\n",
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"zbrain-embed-readiness","version":"0"}}}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"memory_ask","arguments":{"query":"quantum chromodynamics lattice","workspace":"research","embedding":true}}}"#,
    );
    let registry = ZbrainRegistry::new(paths.clone(), Box::new(FixedClock::new(now())));
    let mut server = Server::new(
        registry,
        McpOptions {
            version: "embed-readiness".to_string(),
            ..Default::default()
        },
    );
    let mut transport = MemoryTransport::with_requests(requests.into_bytes());
    server.run(&mut transport).unwrap();
    let frames: Vec<String> = String::from_utf8(transport.into_writer())
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect();
    let response: serde_json::Value = serde_json::from_str(
        frames
            .iter()
            .find(|frame| frame.contains("\"id\":3"))
            .expect("tools/call response"),
    )
    .unwrap();
    let text = response["result"]["content"][0]["text"]
        .as_str()
        .expect("memory_ask text content");
    let body: serde_json::Value = serde_json::from_str(text).unwrap();
    assert_eq!(
        body["status"], "gap",
        "memory_ask with embedding must gap: {text}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
