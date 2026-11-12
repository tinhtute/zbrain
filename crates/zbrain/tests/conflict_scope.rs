//! Declared conflicts are checked against the whole workspace, not only the
//! returned page (audit 2026-11-09, break 6, repro 03). A claim returned by
//! `ask` blocks when any claim it declares `conflicts_with` is approved and
//! trusted at the query instant, even when that target ranks outside the page.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use chrono::{DateTime, TimeZone, Utc};

use zbrain::assets::extract_bundled_assets;
use zbrain::claims::{
    render_claim_markdown, Claim, ClaimStore, CLAIM_BASIS_OWNER, CLAIM_STATUS_DRAFT, OKF_CLAIM_TYPE,
};
use zbrain::clock::FixedClock;
use zbrain::config::ensure_config;
use zbrain::index::{IndexStore, REBUILD_STATUS_CLEAN};
use zbrain::mcp::transport::MemoryTransport;
use zbrain::mcp::{McpOptions, Server, ZbrainRegistry};
use zbrain::paths::{Options, Paths};
use zbrain::query::{
    trusted_query, TrustedQueryOptions, TrustedQueryResponse, QUERY_STATUS_BLOCKED,
    QUERY_STATUS_READY,
};
use zbrain::workspace::create_workspace;

const DECLARING: &str = "clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const TARGET: &str = "clm_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn conflict_paths(name: &str) -> (PathBuf, Paths) {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "zbrain-conflict-{}-{}-{name}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
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
    ensure_config(&paths.config_file).unwrap();
    extract_bundled_assets(&paths).unwrap();
    create_workspace(
        &paths,
        "research",
        &FixedClock::new(Utc.with_ymd_and_hms(2026, 8, 1, 9, 0, 0).unwrap()),
    )
    .unwrap();
    zbrain::signing::KeyStore::init(&paths, Utc.with_ymd_and_hms(2026, 8, 1, 9, 0, 0).unwrap())
        .unwrap();
    (dir, paths)
}

fn conflict_claim(id: &str, title: &str, body: &str, conflicts_with: &[&str]) -> Claim {
    Claim {
        claim_type: OKF_CLAIM_TYPE.into(),
        id: id.into(),
        tier: "projects".into(),
        status: CLAIM_STATUS_DRAFT.into(),
        title: title.into(),
        basis: CLAIM_BASIS_OWNER.into(),
        created_at: "2026-08-01T09:00:00Z".into(),
        created_by: "owner".into(),
        body: body.into(),
        conflicts_with: conflicts_with.iter().map(|id| (*id).to_string()).collect(),
        ..Claim::default()
    }
}

fn store_at(paths: &Paths, at: DateTime<Utc>) -> ClaimStore {
    ClaimStore::with_clock(paths.clone(), Arc::new(FixedClock::new(at)))
}

fn write_approved(paths: &Paths, at: DateTime<Utc>, claim: &Claim) {
    store_at(paths, at)
        .write_draft("research", claim.clone())
        .unwrap();
    store_at(paths, at).approve("research", &claim.id).unwrap();
}

fn write_claim_file(paths: &Paths, id: &str, contents: &[u8]) {
    let dir = paths.workspaces_dir.join("research/wiki/projects");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(format!("{id}.md")), contents).unwrap();
}

fn rebuild(paths: &Paths) {
    let summary = IndexStore::new(paths.clone()).rebuild("research").unwrap();
    assert_eq!(
        summary.rebuild_state, REBUILD_STATUS_CLEAN,
        "invalid={:?}",
        summary.invalid_claims
    );
}

fn ask(paths: &Paths, query: &str, limit: i64, as_of: &str) -> TrustedQueryResponse {
    trusted_query(
        paths,
        TrustedQueryOptions {
            query: query.into(),
            limit,
            as_of: as_of.into(),
            ..TrustedQueryOptions::default()
        },
    )
    .unwrap()
}

fn mcp_memory_ask(paths: &Paths, query: &str) -> serde_json::Value {
    let call = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{{\"name\":\"memory_ask\",\"arguments\":{{\"workspace\":\"research\",\"query\":{query:?}}}}}}}"
    );
    let requests = format!(
        "{}\n{}\n{}\n",
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"zbrain-conflict","version":"0"}}}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        call,
    );
    let registry = ZbrainRegistry::new(
        paths.clone(),
        Box::new(FixedClock::new(
            Utc.with_ymd_and_hms(2026, 9, 1, 9, 0, 0).unwrap(),
        )),
    );
    let options = McpOptions {
        version: "conflict-scope".to_string(),
        ..Default::default()
    };
    let mut server = Server::new(registry, options);
    let mut transport = MemoryTransport::with_requests(requests.into_bytes());
    server.run(&mut transport).unwrap();
    let frames: Vec<String> = String::from_utf8(transport.into_writer())
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect();
    assert!(frames.len() >= 2, "frames = {frames:?}");
    let response: serde_json::Value = serde_json::from_str(&frames[1]).unwrap();
    let result = &response["result"];
    assert!(
        !result["isError"].as_bool().unwrap_or(false),
        "memory_ask failed: {result}"
    );
    serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap()
}

/// Repro 03: the declaring claim is the only match, so the conflicting target
/// never enters the returned page.
#[test]
fn conflict_target_outside_results_blocks() {
    let (dir, paths) = conflict_paths("outside-results");
    let t1 = Utc.with_ymd_and_hms(2026, 8, 5, 10, 0, 0).unwrap();
    write_approved(
        &paths,
        t1,
        &conflict_claim(TARGET, "Window B", "deploy window is tuesday\n", &[]),
    );
    write_approved(
        &paths,
        t1,
        &conflict_claim(
            DECLARING,
            "Window A",
            "deploy window is friday\n",
            &[TARGET],
        ),
    );
    rebuild(&paths);

    let response = ask(&paths, "friday", 10, "");
    assert_eq!(
        response.status, QUERY_STATUS_BLOCKED,
        "claims={:?}",
        response.claims
    );
    assert_eq!(response.conflicts.len(), 1);
    let mut ids = response.conflicts[0].claim_ids.clone();
    ids.sort();
    assert_eq!(ids, vec![DECLARING.to_string(), TARGET.to_string()]);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The target matches the query too, but ranks outside a one-row page.
#[test]
fn conflict_target_below_page_limit_blocks() {
    let (dir, paths) = conflict_paths("below-limit");
    let t1 = Utc.with_ymd_and_hms(2026, 8, 5, 10, 0, 0).unwrap();
    write_approved(
        &paths,
        t1,
        &conflict_claim(TARGET, "Window B", "deploy window is tuesday\n", &[]),
    );
    write_approved(
        &paths,
        t1,
        &conflict_claim(
            DECLARING,
            "Window A",
            "deploy window is friday\n",
            &[TARGET],
        ),
    );
    rebuild(&paths);

    let response = ask(&paths, "deploy window", 1, "");
    let claims = response.claims.as_ref().expect("one returned claim");
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0].id, DECLARING);
    assert_eq!(
        response.status, QUERY_STATUS_BLOCKED,
        "claims={:?}",
        response.claims
    );
    assert_eq!(response.conflicts.len(), 1);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A draft target is not trusted, so it must not block the answer.
#[test]
fn draft_conflict_target_does_not_block() {
    let (dir, paths) = conflict_paths("draft-target");
    let t1 = Utc.with_ymd_and_hms(2026, 8, 5, 10, 0, 0).unwrap();
    store_at(&paths, t1)
        .write_draft(
            "research",
            conflict_claim(TARGET, "Window B", "deploy window is tuesday\n", &[]),
        )
        .unwrap();
    write_approved(
        &paths,
        t1,
        &conflict_claim(
            DECLARING,
            "Window A",
            "deploy window is friday\n",
            &[TARGET],
        ),
    );
    rebuild(&paths);

    let response = ask(&paths, "friday", 10, "");
    assert_eq!(
        response.status, QUERY_STATUS_READY,
        "claims={:?}",
        response.claims
    );
    assert!(response.conflicts.is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

/// `--as-of` checks the target at the same instant: a target approved later
/// does not block, and the same target blocks once it is approved.
#[test]
fn conflict_target_approved_after_as_of_does_not_block() {
    let (dir, paths) = conflict_paths("as-of-target");
    let t1 = Utc.with_ymd_and_hms(2026, 8, 5, 10, 0, 0).unwrap();
    let t2 = Utc.with_ymd_and_hms(2026, 8, 20, 10, 0, 0).unwrap();
    write_approved(
        &paths,
        t1,
        &conflict_claim(
            DECLARING,
            "Window A",
            "deploy window is friday\n",
            &[TARGET],
        ),
    );
    write_approved(
        &paths,
        t2,
        &conflict_claim(TARGET, "Window B", "deploy window is tuesday\n", &[]),
    );
    rebuild(&paths);

    let before = ask(&paths, "friday", 10, "2026-08-15T00:00:00Z");
    assert_eq!(
        before.status, QUERY_STATUS_READY,
        "claims={:?}",
        before.claims
    );
    assert!(before.conflicts.is_empty());

    let after = ask(&paths, "friday", 10, "2026-08-25T00:00:00Z");
    assert_eq!(
        after.status, QUERY_STATUS_BLOCKED,
        "claims={:?}",
        after.claims
    );
    assert_eq!(after.conflicts.len(), 1);
    let _ = std::fs::remove_dir_all(&dir);
}

/// MCP `memory_ask` runs the same trusted query, so the same conflict blocks.
#[test]
fn memory_ask_blocks_on_conflict_outside_results() {
    let (dir, paths) = conflict_paths("mcp-outside-results");
    let t1 = Utc.with_ymd_and_hms(2026, 8, 5, 10, 0, 0).unwrap();
    write_approved(
        &paths,
        t1,
        &conflict_claim(TARGET, "Window B", "deploy window is tuesday\n", &[]),
    );
    write_approved(
        &paths,
        t1,
        &conflict_claim(
            DECLARING,
            "Window A",
            "deploy window is friday\n",
            &[TARGET],
        ),
    );
    rebuild(&paths);

    let response = mcp_memory_ask(&paths, "friday");
    assert_eq!(response["status"], QUERY_STATUS_BLOCKED, "{response}");
    assert_eq!(response["conflicts"].as_array().map(Vec::len), Some(1));
    let _ = std::fs::remove_dir_all(&dir);
}

/// A conflict target must pass the same approval-signature check as a returned
/// claim (ADR 0002). A superseded target is indexed without signature
/// validation, so its historical approval is verified at query time: signed it
/// blocks, unsigned it does not.
#[test]
fn unsigned_historical_conflict_target_does_not_block() {
    let (dir, paths) = conflict_paths("unsigned-target");
    let t1 = Utc.with_ymd_and_hms(2026, 8, 5, 10, 0, 0).unwrap();
    let t2 = Utc.with_ymd_and_hms(2026, 8, 20, 10, 0, 0).unwrap();
    write_approved(
        &paths,
        t1,
        &conflict_claim(
            DECLARING,
            "Window A",
            "deploy window is friday\n",
            &[TARGET],
        ),
    );
    write_approved(
        &paths,
        t1,
        &conflict_claim(TARGET, "Window B", "deploy window is tuesday\n", &[]),
    );
    let replacement = conflict_claim(
        "clm_cccccccccccccccccccccccccccccccc",
        "Window B replacement",
        "deploy window is thursday\n",
        &[],
    );
    store_at(&paths, t2)
        .write_superseding_draft("research", TARGET, replacement.clone())
        .unwrap();
    store_at(&paths, t2)
        .approve("research", &replacement.id)
        .unwrap();
    rebuild(&paths);

    let signed = ask(&paths, "friday", 10, "2026-08-15T00:00:00Z");
    assert_eq!(
        signed.status, QUERY_STATUS_BLOCKED,
        "claims={:?}",
        signed.claims
    );

    // Strip the approval signature from the superseded target's canonical file.
    let mut target = ClaimStore::new(paths.clone())
        .read("research", TARGET)
        .unwrap();
    target.verified_alg.clear();
    target.verified_key_id.clear();
    target.verified_sig.clear();
    write_claim_file(&paths, TARGET, &render_claim_markdown(&target).unwrap());
    rebuild(&paths);

    let unsigned = ask(&paths, "friday", 10, "2026-08-15T00:00:00Z");
    assert_eq!(
        unsigned.status, QUERY_STATUS_READY,
        "claims={:?}",
        unsigned.claims
    );
    assert!(unsigned.conflicts.is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

/// The existing behaviour still holds when both sides land in the page.
#[test]
fn conflict_inside_page_still_blocks() {
    let (dir, paths) = conflict_paths("inside-page");
    let t1 = Utc.with_ymd_and_hms(2026, 8, 5, 10, 0, 0).unwrap();
    write_approved(
        &paths,
        t1,
        &conflict_claim(TARGET, "Window B", "deploy window is tuesday\n", &[]),
    );
    write_approved(
        &paths,
        t1,
        &conflict_claim(
            DECLARING,
            "Window A",
            "deploy window is friday\n",
            &[TARGET],
        ),
    );
    rebuild(&paths);

    let response = ask(&paths, "deploy window", 10, "");
    assert_eq!(
        response.status, QUERY_STATUS_BLOCKED,
        "claims={:?}",
        response.claims
    );
    assert_eq!(response.conflicts.len(), 1);
    let _ = std::fs::remove_dir_all(&dir);
}
