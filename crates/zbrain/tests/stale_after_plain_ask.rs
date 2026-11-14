//! Plain `ask` (no `--as-of`) must apply the same `stale_after` rule that
//! `ask --as-of` and `doctor` already apply (audit 2026-11-09, repro 10). An
//! approved claim past its `stale_after` is not trusted `ready`; it is a `gap`.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use chrono::{DateTime, TimeZone, Utc};

use zbrain::assets::extract_bundled_assets;
use zbrain::claims::{
    Claim, ClaimStore, CLAIM_BASIS_OWNER, CLAIM_STATUS_APPROVED, CLAIM_STATUS_DRAFT, OKF_CLAIM_TYPE,
};
use zbrain::clock::{rfc3339, FixedClock};
use zbrain::config::ensure_config;
use zbrain::index::{IndexStore, REBUILD_STATUS_CLEAN};
use zbrain::paths::{Options, Paths};
use zbrain::query::{
    trusted_query, TrustedQueryOptions, TrustedQueryResponse, QUERY_STATUS_GAP, QUERY_STATUS_READY,
};
use zbrain::workspace::create_workspace;

fn stale_paths(name: &str) -> (PathBuf, Paths) {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "zbrain-stale-{}-{}-{name}",
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
    let t0 = Utc.with_ymd_and_hms(2026, 8, 1, 9, 0, 0).unwrap();
    create_workspace(&paths, "research", &FixedClock::new(t0)).unwrap();
    zbrain::signing::KeyStore::init(&paths, t0).unwrap();
    (dir, paths)
}

fn store_at(paths: &Paths, at: DateTime<Utc>) -> ClaimStore {
    ClaimStore::with_clock(paths.clone(), Arc::new(FixedClock::new(at)))
}

/// Writes a draft with the given `stale_after` and approves it through the
/// normal signed approval path.
fn approved_claim(paths: &Paths, id: &str, body: &str, stale_after: &str) {
    approved_claim_with_conflicts(paths, id, body, stale_after, Vec::new());
}

fn approved_claim_with_conflicts(
    paths: &Paths,
    id: &str,
    body: &str,
    stale_after: &str,
    conflicts_with: Vec<String>,
) {
    let at = Utc.with_ymd_and_hms(2026, 8, 5, 10, 0, 0).unwrap();
    let claim = Claim {
        claim_type: OKF_CLAIM_TYPE.into(),
        id: id.into(),
        tier: "projects".into(),
        status: CLAIM_STATUS_DRAFT.into(),
        title: "On-call".into(),
        basis: CLAIM_BASIS_OWNER.into(),
        created_at: rfc3339(at),
        created_by: "owner".into(),
        stale_after: stale_after.into(),
        conflicts_with,
        body: body.into(),
        ..Claim::default()
    };
    store_at(paths, at).write_draft("research", claim).unwrap();
    let approved = store_at(paths, at).approve("research", id).unwrap();
    assert_eq!(approved.status, CLAIM_STATUS_APPROVED);
    assert_eq!(approved.stale_after, stale_after);
}

fn rebuild(paths: &Paths) {
    let summary = IndexStore::new(paths.clone()).rebuild("research").unwrap();
    assert_eq!(
        summary.rebuild_state, REBUILD_STATUS_CLEAN,
        "invalid={:?}",
        summary.invalid_claims
    );
}

fn ask(paths: &Paths, query: &str, as_of: &str) -> TrustedQueryResponse {
    trusted_query(
        paths,
        TrustedQueryOptions {
            query: query.into(),
            as_of: as_of.into(),
            limit: 10,
            ..TrustedQueryOptions::default()
        },
    )
    .unwrap()
}

fn claim_ids(response: &TrustedQueryResponse) -> Vec<String> {
    response
        .claims
        .as_ref()
        .map(|claims| claims.iter().map(|claim| claim.id.clone()).collect())
        .unwrap_or_default()
}

const STALE_ID: &str = "clm_000000000000000000000000000000c1";
const FRESH_ID: &str = "clm_000000000000000000000000000000c2";

#[test]
fn plain_ask_returns_gap_for_approved_claim_past_stale_after() {
    let (dir, paths) = stale_paths("plain-stale");
    approved_claim(
        &paths,
        STALE_ID,
        "oncall rotation alice\n",
        "2020-01-01T00:00:00Z",
    );
    rebuild(&paths);

    let response = ask(&paths, "oncall rotation", "");
    assert_eq!(
        response.status, QUERY_STATUS_GAP,
        "stale approved claim returned as trusted: claims={:?}",
        response.claims
    );
    assert!(claim_ids(&response).is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn plain_ask_keeps_non_stale_approved_claim_ready() {
    let (dir, paths) = stale_paths("plain-fresh");
    approved_claim(
        &paths,
        FRESH_ID,
        "oncall rotation bob\n",
        "2099-01-01T00:00:00Z",
    );
    rebuild(&paths);

    let response = ask(&paths, "oncall rotation", "");
    assert_eq!(response.status, QUERY_STATUS_READY);
    assert_eq!(claim_ids(&response), vec![FRESH_ID.to_string()]);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn plain_ask_filters_only_the_stale_claim() {
    let (dir, paths) = stale_paths("plain-mixed");
    approved_claim(
        &paths,
        STALE_ID,
        "oncall rotation alice\n",
        "2020-01-01T00:00:00Z",
    );
    approved_claim(
        &paths,
        FRESH_ID,
        "oncall rotation bob\n",
        "2099-01-01T00:00:00Z",
    );
    rebuild(&paths);

    let response = ask(&paths, "oncall rotation", "");
    assert_eq!(response.status, QUERY_STATUS_READY);
    assert_eq!(claim_ids(&response), vec![FRESH_ID.to_string()]);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn as_of_ask_staleness_unchanged() {
    let (dir, paths) = stale_paths("asof");
    approved_claim(
        &paths,
        STALE_ID,
        "oncall rotation alice\n",
        "2026-09-01T00:00:00Z",
    );
    rebuild(&paths);

    // Before stale_after the claim is trusted at that instant.
    let before = ask(&paths, "oncall rotation", "2026-08-15T00:00:00Z");
    assert_eq!(before.status, QUERY_STATUS_READY);
    assert_eq!(claim_ids(&before), vec![STALE_ID.to_string()]);
    // At or after stale_after it is not.
    let after = ask(&paths, "oncall rotation", "2026-09-01T00:00:00Z");
    assert_eq!(after.status, QUERY_STATUS_GAP);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn plain_ask_stale_conflict_target_does_not_block() {
    // Same rule as `--as-of now`: a stale approved claim is not trusted, so a
    // fresh claim's declared conflict with it does not block the answer.
    let (dir, paths) = stale_paths("plain-conflict");
    approved_claim(
        &paths,
        STALE_ID,
        "pager escalation alice\n",
        "2020-01-01T00:00:00Z",
    );
    approved_claim_with_conflicts(
        &paths,
        FRESH_ID,
        "oncall rotation bob\n",
        "2099-01-01T00:00:00Z",
        vec![STALE_ID.to_string()],
    );
    rebuild(&paths);

    let response = ask(&paths, "oncall rotation", "");
    assert_eq!(
        response.status, QUERY_STATUS_READY,
        "conflicts={:?}",
        response.conflicts
    );
    assert!(response.conflicts.is_empty());
    assert_eq!(claim_ids(&response), vec![FRESH_ID.to_string()]);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn plain_ask_stale_claim_declaring_conflict_does_not_block() {
    // Reverse direction: the stale claim declares the conflict. It is not
    // trusted, so its declaration blocks nothing.
    let (dir, paths) = stale_paths("plain-conflict-reverse");
    approved_claim_with_conflicts(
        &paths,
        STALE_ID,
        "oncall rotation alice\n",
        "2020-01-01T00:00:00Z",
        vec![FRESH_ID.to_string()],
    );
    approved_claim(
        &paths,
        FRESH_ID,
        "oncall rotation bob\n",
        "2099-01-01T00:00:00Z",
    );
    rebuild(&paths);

    let response = ask(&paths, "oncall rotation", "");
    assert_eq!(
        response.status, QUERY_STATUS_READY,
        "conflicts={:?}",
        response.conflicts
    );
    assert!(response.conflicts.is_empty());
    assert_eq!(claim_ids(&response), vec![FRESH_ID.to_string()]);
    let _ = std::fs::remove_dir_all(&dir);
}
