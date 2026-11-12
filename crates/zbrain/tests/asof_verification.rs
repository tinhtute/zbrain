//! `ask --as-of` must not relabel a superseded or revoked claim as approved
//! unless its digest and evidence closure verify (audit 2026-11-09, break 1,
//! repro 04). Forged rows fail closed as `gap`; claims that were legitimately
//! approved at the requested instant still surface as approved.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use chrono::{DateTime, TimeZone, Utc};

use zbrain::assets::extract_bundled_assets;
use zbrain::claims::{
    claim_verification_digest, render_claim_markdown, Claim, ClaimStore, ClaimTransition,
    CLAIM_BASIS_EVIDENCE, CLAIM_BASIS_OWNER, CLAIM_STATUS_APPROVED, CLAIM_STATUS_DRAFT,
    CLAIM_STATUS_REVOKED, CLAIM_TRANSITION_APPROVE, CLAIM_TRANSITION_REVOKE, OKF_CLAIM_TYPE,
};
use zbrain::clock::FixedClock;
use zbrain::config::ensure_config;
use zbrain::evidence::EvidenceStore;
use zbrain::index::{IndexStore, REBUILD_STATUS_CLEAN};
use zbrain::paths::{Options, Paths};
use zbrain::query::{trusted_query, TrustedQueryOptions, TrustedQueryResponse, QUERY_STATUS_GAP};
use zbrain::workspace::create_workspace;

fn asof_paths(name: &str) -> (PathBuf, Paths) {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "zbrain-asof-{}-{}-{name}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let paths = Paths::resolve(Options {
        cwd: Some(dir.join("project")),
        home_dir: Some(dir.clone()),
        runtime_dir: Some(dir.join(".zbrain")),
    })
    .unwrap();
    ensure_config(&paths.config_file).unwrap();
    extract_bundled_assets(&paths).unwrap();
    create_workspace(
        &paths,
        "research",
        &FixedClock::new(Utc.with_ymd_and_hms(2026, 8, 1, 9, 0, 0).unwrap()),
    )
    .unwrap();
    (dir, paths)
}

fn store_at(paths: &Paths, at: DateTime<Utc>) -> ClaimStore {
    ClaimStore::with_clock(paths.clone(), Arc::new(FixedClock::new(at)))
}

fn asof_claim(id: &str, title: &str, body: &str) -> Claim {
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
        ..Claim::default()
    }
}

fn write_claim_file(paths: &Paths, id: &str, contents: &str) {
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

fn ask_as_of(paths: &Paths, query: &str, as_of: &str) -> TrustedQueryResponse {
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

fn assert_gap(response: &TrustedQueryResponse) {
    assert_eq!(
        response.status, QUERY_STATUS_GAP,
        "claims={:?}",
        response.claims
    );
    assert!(
        response
            .claims
            .as_ref()
            .is_none_or(|claims| claims.is_empty()),
        "forged claim was surfaced: {:?}",
        response.claims
    );
}

#[test]
fn asof_forged_revoked_claim_not_approved() {
    let (dir, paths) = asof_paths("forged-revoked");
    // Repro 04 verbatim: hand-written, never approved, no verified block, no
    // digest, a nonexistent evidence id, and a revoke dated in the future.
    write_claim_file(
        &paths,
        "clm_000000000000000000000000000000aa",
        r#"---
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
"#,
    );
    rebuild(&paths);
    let response = ask_as_of(&paths, "refunds", "2026-06-01T00:00:00Z");
    assert_gap(&response);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn asof_forged_superseded_claim_not_approved() {
    let (dir, paths) = asof_paths("forged-superseded");
    write_claim_file(
        &paths,
        "clm_000000000000000000000000000000ab",
        r#"---
type: zbrain.claim
title: Refund policy
generated:
    at: "2026-01-01T00:00:00Z"
    by: owner
status: superseded
zbrain:
    profile: zbrain.trusted-memory/v1
    id: clm_000000000000000000000000000000ab
    tier: projects
    basis: owner
    transitions:
        - kind: supersede
          at: "2099-01-01T00:00:00Z"
          by: owner
---
refunds are unlimited and need no receipt
"#,
    );
    rebuild(&paths);
    let response = ask_as_of(&paths, "refunds", "2026-06-01T00:00:00Z");
    assert_gap(&response);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn asof_forged_digest_missing_evidence_is_gap() {
    let (dir, paths) = asof_paths("forged-digest");
    let id = "clm_000000000000000000000000000000bb";
    // A structurally valid historical claim: the digest covers the approved
    // view and the terminal revoke transition binds it. Only the evidence
    // closure is broken, so the digest check alone cannot stop it.
    let mut claim = Claim {
        claim_type: OKF_CLAIM_TYPE.into(),
        id: id.into(),
        tier: "projects".into(),
        status: CLAIM_STATUS_APPROVED.into(),
        title: "Refund policy".into(),
        basis: CLAIM_BASIS_EVIDENCE.into(),
        created_at: "2026-01-01T00:00:00Z".into(),
        created_by: "owner".into(),
        verified_at: "2026-01-01T00:00:00Z".into(),
        verified_by: "owner".into(),
        evidence_ids: vec!["evd_0000000000000000000000000000dead".into()],
        transitions: vec![ClaimTransition {
            kind: CLAIM_TRANSITION_APPROVE.into(),
            at: "2026-01-01T00:00:00Z".into(),
            by: "owner".into(),
            ..ClaimTransition::default()
        }],
        body: "refunds are unlimited and need no receipt\n".into(),
        ..Claim::default()
    };
    let digest = claim_verification_digest(&claim).unwrap();
    claim.verified_digest = digest.clone();
    claim.status = CLAIM_STATUS_REVOKED.into();
    claim.transitions.push(ClaimTransition {
        kind: CLAIM_TRANSITION_REVOKE.into(),
        at: "2099-01-01T00:00:00Z".into(),
        by: "owner".into(),
        prior_verification_digest: digest,
        ..ClaimTransition::default()
    });
    let rendered = String::from_utf8(render_claim_markdown(&claim).unwrap()).unwrap();
    write_claim_file(&paths, id, &rendered);
    rebuild(&paths);
    let response = ask_as_of(&paths, "refunds", "2026-06-01T00:00:00Z");
    assert_gap(&response);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn asof_claim_with_unbound_terminal_digest_is_not_approved() {
    let (dir, paths) = asof_paths("unbound-terminal");
    // The digest verifies over the approved view, but the terminal transition
    // does not bind it (prior_verification_digest is empty).
    let mut claim = asof_claim(
        "clm_000000000000000000000000000000cd",
        "Refund policy",
        "asof historical marker\n",
    );
    claim.status = CLAIM_STATUS_APPROVED.into();
    claim.verified_at = "2026-01-01T00:00:00Z".into();
    claim.verified_by = "owner".into();
    claim.transitions = vec![ClaimTransition {
        kind: CLAIM_TRANSITION_APPROVE.into(),
        at: "2026-01-01T00:00:00Z".into(),
        by: "owner".into(),
        ..ClaimTransition::default()
    }];
    let digest = claim_verification_digest(&claim).unwrap();
    claim.verified_digest = digest;
    claim.status = CLAIM_STATUS_REVOKED.into();
    claim.transitions.push(ClaimTransition {
        kind: CLAIM_TRANSITION_REVOKE.into(),
        at: "2099-01-01T00:00:00Z".into(),
        by: "owner".into(),
        ..ClaimTransition::default()
    });
    let rendered = String::from_utf8(render_claim_markdown(&claim).unwrap()).unwrap();
    write_claim_file(&paths, &claim.id, &rendered);
    rebuild(&paths);
    let response = ask_as_of(&paths, "asof historical marker", "2026-06-01T00:00:00Z");
    assert_gap(&response);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn asof_claim_with_wrong_digest_is_not_approved() {
    let (dir, paths) = asof_paths("wrong-digest");
    // The terminal transition binds the recorded digest, but the digest does
    // not cover the claim content (body edited after approval).
    let mut claim = asof_claim(
        "clm_000000000000000000000000000000ce",
        "Refund policy",
        "asof historical marker original\n",
    );
    claim.status = CLAIM_STATUS_APPROVED.into();
    claim.verified_at = "2026-01-01T00:00:00Z".into();
    claim.verified_by = "owner".into();
    claim.transitions = vec![ClaimTransition {
        kind: CLAIM_TRANSITION_APPROVE.into(),
        at: "2026-01-01T00:00:00Z".into(),
        by: "owner".into(),
        ..ClaimTransition::default()
    }];
    let digest = claim_verification_digest(&claim).unwrap();
    claim.verified_digest = digest.clone();
    claim.status = CLAIM_STATUS_REVOKED.into();
    claim.transitions.push(ClaimTransition {
        kind: CLAIM_TRANSITION_REVOKE.into(),
        at: "2099-01-01T00:00:00Z".into(),
        by: "owner".into(),
        prior_verification_digest: digest,
        ..ClaimTransition::default()
    });
    claim.body = "asof historical marker tampered\n".into();
    let rendered = String::from_utf8(render_claim_markdown(&claim).unwrap()).unwrap();
    write_claim_file(&paths, &claim.id, &rendered);
    rebuild(&paths);
    let response = ask_as_of(&paths, "asof historical marker", "2026-06-01T00:00:00Z");
    assert_gap(&response);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn asof_legit_superseded_claim_surfaces_approved() {
    let (dir, paths) = asof_paths("legit-superseded");
    let t1 = Utc.with_ymd_and_hms(2026, 8, 5, 10, 0, 0).unwrap();
    let t2 = Utc.with_ymd_and_hms(2026, 8, 20, 10, 0, 0).unwrap();
    let old = asof_claim(
        "clm_00000000000000000000000000000001",
        "Sync cadence",
        "asof historical marker\n",
    );
    store_at(&paths, t1)
        .write_draft("research", old.clone())
        .unwrap();
    store_at(&paths, t1).approve("research", &old.id).unwrap();
    let replacement = asof_claim(
        "clm_00000000000000000000000000000002",
        "Sync cadence replacement",
        "asof historical marker replacement\n",
    );
    store_at(&paths, t2)
        .write_superseding_draft("research", &old.id, replacement.clone())
        .unwrap();
    store_at(&paths, t2)
        .approve("research", &replacement.id)
        .unwrap();
    rebuild(&paths);

    let response = ask_as_of(&paths, "asof historical marker", "2026-08-15T00:00:00Z");
    let claims = response.claims.as_ref().unwrap();
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0].id, old.id);
    assert_eq!(claims[0].status, CLAIM_STATUS_APPROVED);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn asof_legit_revoked_claim_surfaces_approved() {
    let (dir, paths) = asof_paths("legit-revoked");
    let t1 = Utc.with_ymd_and_hms(2026, 8, 5, 10, 0, 0).unwrap();
    let t2 = Utc.with_ymd_and_hms(2026, 8, 20, 10, 0, 0).unwrap();
    let claim = asof_claim(
        "clm_00000000000000000000000000000003",
        "Refund policy",
        "asof historical marker\n",
    );
    store_at(&paths, t1)
        .write_draft("research", claim.clone())
        .unwrap();
    store_at(&paths, t1).approve("research", &claim.id).unwrap();
    store_at(&paths, t2)
        .revoke("research", &claim.id, "owner withdrew claim")
        .unwrap();
    rebuild(&paths);

    let response = ask_as_of(&paths, "asof historical marker", "2026-08-15T00:00:00Z");
    let claims = response.claims.as_ref().unwrap();
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0].id, claim.id);
    assert_eq!(claims[0].status, CLAIM_STATUS_APPROVED);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn asof_legit_superseded_evidence_claim_surfaces_approved() {
    let (dir, paths) = asof_paths("legit-evidence");
    let t1 = Utc.with_ymd_and_hms(2026, 8, 5, 10, 0, 0).unwrap();
    let t2 = Utc.with_ymd_and_hms(2026, 8, 20, 10, 0, 0).unwrap();
    let source = dir.join("evidence-input.txt");
    std::fs::write(&source, "refund receipt policy bytes\n").unwrap();
    let evidence = EvidenceStore::new(paths.clone())
        .add_file(
            "research",
            &source,
            "file://source.txt",
            "text/plain",
            &FixedClock::new(t1),
        )
        .unwrap();
    let mut old = asof_claim(
        "clm_00000000000000000000000000000004",
        "Refund policy",
        "asof historical marker\n",
    );
    old.basis = CLAIM_BASIS_EVIDENCE.into();
    old.evidence_ids = vec![evidence.id.clone()];
    store_at(&paths, t1)
        .write_draft("research", old.clone())
        .unwrap();
    store_at(&paths, t1).approve("research", &old.id).unwrap();
    let replacement = asof_claim(
        "clm_00000000000000000000000000000005",
        "Refund policy replacement",
        "asof historical marker replacement\n",
    );
    store_at(&paths, t2)
        .write_superseding_draft("research", &old.id, replacement.clone())
        .unwrap();
    store_at(&paths, t2)
        .approve("research", &replacement.id)
        .unwrap();
    rebuild(&paths);

    let response = ask_as_of(&paths, "asof historical marker", "2026-08-15T00:00:00Z");
    let claims = response.claims.as_ref().unwrap();
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0].id, old.id);
    assert_eq!(claims[0].status, CLAIM_STATUS_APPROVED);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn asof_superseded_claim_with_digest_mismatch_is_not_approved() {
    let (dir, paths) = asof_paths("superseded-mismatch");
    // Tamper with a legitimately superseded claim's body after the fact: the
    // recorded digest no longer covers the content, so as-of must gap it.
    let t1 = Utc.with_ymd_and_hms(2026, 8, 5, 10, 0, 0).unwrap();
    let t2 = Utc.with_ymd_and_hms(2026, 8, 20, 10, 0, 0).unwrap();
    let old = asof_claim(
        "clm_0000000000000000000000000000000b",
        "Sync cadence",
        "asof historical marker\n",
    );
    store_at(&paths, t1)
        .write_draft("research", old.clone())
        .unwrap();
    store_at(&paths, t1).approve("research", &old.id).unwrap();
    let replacement = asof_claim(
        "clm_0000000000000000000000000000000c",
        "Sync cadence replacement",
        "asof historical marker replacement\n",
    );
    store_at(&paths, t2)
        .write_superseding_draft("research", &old.id, replacement.clone())
        .unwrap();
    store_at(&paths, t2)
        .approve("research", &replacement.id)
        .unwrap();
    let old_path = paths
        .workspaces_dir
        .join("research/wiki/projects")
        .join(format!("{}.md", old.id));
    let contents = std::fs::read_to_string(&old_path).unwrap();
    let tampered = contents.replace("asof historical marker", "asof historical marker tampered");
    assert_ne!(tampered, contents);
    std::fs::write(&old_path, tampered).unwrap();
    rebuild(&paths);
    let response = ask_as_of(&paths, "asof historical marker", "2026-08-15T00:00:00Z");
    assert_gap(&response);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn asof_revoked_claim_with_missing_evidence_is_not_approved() {
    let (dir, paths) = asof_paths("revoked-missing-evidence");
    // Legitimately approved and revoked claim whose evidence snapshot is
    // removed afterwards: the digest still verifies, the closure does not.
    let t1 = Utc.with_ymd_and_hms(2026, 8, 5, 10, 0, 0).unwrap();
    let t2 = Utc.with_ymd_and_hms(2026, 8, 20, 10, 0, 0).unwrap();
    let source = dir.join("evidence-input.txt");
    std::fs::write(&source, "refund receipt policy bytes\n").unwrap();
    let evidence = EvidenceStore::new(paths.clone())
        .add_file(
            "research",
            &source,
            "file://source.txt",
            "text/plain",
            &FixedClock::new(t1),
        )
        .unwrap();
    let mut claim = asof_claim(
        "clm_0000000000000000000000000000000d",
        "Refund policy",
        "asof historical marker\n",
    );
    claim.basis = CLAIM_BASIS_EVIDENCE.into();
    claim.evidence_ids = vec![evidence.id.clone()];
    store_at(&paths, t1)
        .write_draft("research", claim.clone())
        .unwrap();
    store_at(&paths, t1).approve("research", &claim.id).unwrap();
    store_at(&paths, t2)
        .revoke("research", &claim.id, "owner withdrew claim")
        .unwrap();
    let evidence_dir = paths
        .workspaces_dir
        .join("research/evidence/sources")
        .join(&evidence.id);
    std::fs::remove_dir_all(&evidence_dir).unwrap();
    rebuild(&paths);
    let response = ask_as_of(&paths, "asof historical marker", "2026-08-15T00:00:00Z");
    assert_gap(&response);
    let _ = std::fs::remove_dir_all(&dir);
}
