//! The owner grant on a challenge is the only thing that lets `apply` sign a
//! claim with the owner key. The grant lives in a JSON file under the
//! workspace, so it must carry an owner-key signature: a writer of that file
//! must not be able to turn `apply` into a signing oracle (security review
//! before v0.5.0, finding 1).

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use chrono::{TimeZone, Utc};
use sha2::{Digest, Sha256};

use zbrain::approval::{ChallengeItem, ChallengeStore};
use zbrain::assets::extract_bundled_assets;
use zbrain::claims::{Claim, ClaimStore, CLAIM_BASIS_OWNER, CLAIM_STATUS_DRAFT, OKF_CLAIM_TYPE};
use zbrain::clock::FixedClock;
use zbrain::config::ensure_config;
use zbrain::paths::{Options, Paths};
use zbrain::signing::KeyStore;
use zbrain::workspace::create_workspace;

const ATTACKER_TOKEN: &str = "attacker-chosen-token";

struct Fixture {
    dir: PathBuf,
    paths: Paths,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 9, 1, 9, 0, 0).unwrap()
}

fn fixture(name: &str) -> Fixture {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "zbrain-grant-{}-{}-{name}",
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
    create_workspace(&paths, "research", &FixedClock::new(now())).unwrap();
    KeyStore::init(&paths, now() - chrono::Duration::days(1)).unwrap();
    Fixture { dir, paths }
}

fn claims(fx: &Fixture) -> ClaimStore {
    ClaimStore::with_clock(fx.paths.clone(), Arc::new(FixedClock::new(now())))
}

fn challenges(fx: &Fixture) -> ChallengeStore {
    ChallengeStore::with_clock(fx.paths.clone(), Arc::new(FixedClock::new(now())))
}

fn draft(fx: &Fixture, title: &str, body: &str) -> String {
    let id = zbrain::claims::new_claim_id().unwrap();
    claims(fx)
        .write_draft(
            "research",
            Claim {
                claim_type: OKF_CLAIM_TYPE.to_string(),
                id: id.clone(),
                tier: "projects".to_string(),
                status: CLAIM_STATUS_DRAFT.to_string(),
                title: title.to_string(),
                basis: CLAIM_BASIS_OWNER.to_string(),
                created_at: "2026-09-01T08:00:00Z".to_string(),
                created_by: "agent".to_string(),
                body: body.to_string(),
                ..Claim::default()
            },
        )
        .unwrap();
    id
}

fn challenge_file(fx: &Fixture, challenge_id: &str) -> PathBuf {
    fx.paths
        .workspaces_dir
        .join("research/.zbrain/challenges")
        .join(format!("{challenge_id}.json"))
}

/// What an agent with file-write access does: edit the challenge record.
fn edit_challenge(fx: &Fixture, challenge_id: &str, edit: impl Fn(&mut serde_json::Value)) {
    let path = challenge_file(fx, challenge_id);
    let mut record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    edit(&mut record);
    std::fs::write(&path, serde_json::to_vec_pretty(&record).unwrap()).unwrap();
}

fn attacker_token_hash() -> String {
    let digest = Sha256::digest(ATTACKER_TOKEN.as_bytes());
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("sha256:{hex}")
}

fn assert_still_draft(fx: &Fixture, id: &str) {
    let claim = claims(fx).read("research", id).unwrap();
    assert_eq!(claim.status, CLAIM_STATUS_DRAFT, "{claim:?}");
    assert!(claim.verified_sig.is_empty(), "{claim:?}");
}

#[test]
fn forged_grant_does_not_get_an_owner_signature() {
    let fx = fixture("forged-single");
    let id = draft(&fx, "Refunds", "refunds need no receipt\n");
    let store = claims(&fx);
    let prepare = store.approve_challenge_prepare("research", &id).unwrap();
    let prepared = store.prepare_challenge("research", prepare).unwrap();
    let challenge_id = prepared.challenge.id.clone();

    edit_challenge(&fx, &challenge_id, |record| {
        let expires_at = record["expires_at"].clone();
        record["granted"] = true.into();
        record["granted_at"] = "2026-09-01T09:00:00Z".into();
        record["token_sha256"] = attacker_token_hash().into();
        record["token_expires_at"] = expires_at;
    });

    let applied = store.apply_challenge(
        "research",
        &challenge_id,
        ATTACKER_TOKEN,
        Default::default(),
    );
    assert!(applied.is_err(), "forged grant was applied: {applied:?}");
    assert_still_draft(&fx, &id);
}

#[test]
fn swapped_token_hash_on_a_real_grant_is_refused() {
    let fx = fixture("swapped-token");
    let id = draft(&fx, "Refunds", "refunds need no receipt\n");
    let store = claims(&fx);
    let prepare = store.approve_challenge_prepare("research", &id).unwrap();
    let prepared = store.prepare_challenge("research", prepare).unwrap();
    let challenge_id = prepared.challenge.id.clone();
    challenges(&fx).grant("research", &challenge_id).unwrap();

    edit_challenge(&fx, &challenge_id, |record| {
        record["token_sha256"] = attacker_token_hash().into();
    });

    let applied = store.apply_challenge(
        "research",
        &challenge_id,
        ATTACKER_TOKEN,
        Default::default(),
    );
    assert!(applied.is_err(), "swapped token was applied: {applied:?}");
    assert_still_draft(&fx, &id);
}

#[test]
fn forged_batch_grant_and_moved_skip_are_refused() {
    let fx = fixture("forged-batch");
    let a = draft(&fx, "One", "first body\n");
    let b = draft(&fx, "Two", "second body\n");
    let store = claims(&fx);
    let items = vec![
        ChallengeItem {
            claim_id: a.clone(),
            ..ChallengeItem::default()
        },
        ChallengeItem {
            claim_id: b.clone(),
            ..ChallengeItem::default()
        },
    ];

    // Fully forged grant.
    let forged = store
        .prepare_batch_challenge("research", items.clone())
        .unwrap();
    edit_challenge(&fx, &forged.challenge.id, |record| {
        let expires_at = record["expires_at"].clone();
        record["granted"] = true.into();
        record["granted_at"] = "2026-09-01T09:00:00Z".into();
        record["granted_items"] = serde_json::json!([a, b]);
        record["token_sha256"] = attacker_token_hash().into();
        record["token_expires_at"] = expires_at;
    });
    let applied = store.apply_challenge_batch(
        "research",
        &forged.challenge.id,
        ATTACKER_TOKEN,
        Default::default(),
    );
    assert!(applied.is_err(), "forged batch grant applied: {applied:?}");

    // A real grant where the owner skipped `b`; the writer moves it over.
    let real = store.prepare_batch_challenge("research", items).unwrap();
    let granted = challenges(&fx)
        .grant_items(
            "research",
            &real.challenge.id,
            std::slice::from_ref(&a),
            std::slice::from_ref(&b),
        )
        .unwrap();
    edit_challenge(&fx, &real.challenge.id, |record| {
        record["granted_items"] = serde_json::json!([a, b]);
        record["skipped_items"] = serde_json::json!([]);
    });
    let applied = store.apply_challenge_batch(
        "research",
        &real.challenge.id,
        &granted.token,
        Default::default(),
    );
    assert!(applied.is_err(), "moved skip was applied: {applied:?}");
    assert_still_draft(&fx, &a);
    assert_still_draft(&fx, &b);
}

#[test]
fn real_grant_still_applies() {
    let fx = fixture("real");
    let id = draft(&fx, "Refunds", "refunds need a receipt\n");
    let store = claims(&fx);
    let prepare = store.approve_challenge_prepare("research", &id).unwrap();
    let prepared = store.prepare_challenge("research", prepare).unwrap();
    let granted = challenges(&fx)
        .grant("research", &prepared.challenge.id)
        .unwrap();
    let claim = store
        .apply_challenge(
            "research",
            &prepared.challenge.id,
            &granted.token,
            Default::default(),
        )
        .unwrap();
    assert_eq!(claim.status, "approved");
    assert!(!claim.verified_sig.is_empty());
}
