//! An approved claim is trusted only when it carries a valid owner signature
//! over its verification digest (audit 2026-11-09, break 3, repro 01). These
//! tests drive the surfaces a user drives: `reindex`, `ask`, `doctor`, and the
//! `claim approve` ceremony.

use std::cell::RefCell;
use std::io::{Cursor, Write};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};

use chrono::{TimeZone, Utc};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ed25519_dalek::Signer;
use zbrain::assets::extract_bundled_assets;
use zbrain::claims::ClaimStore;
use zbrain::claims::{
    claim_verification_digest, render_claim_markdown, Claim, ClaimTransition, CLAIM_BASIS_OWNER,
    CLAIM_STATUS_APPROVED, CLAIM_TRANSITION_APPROVE, OKF_CLAIM_TYPE,
};
use zbrain::cli::{new_app, App, CliError, PromptSource};
use zbrain::clock::FixedClock;
use zbrain::config::ensure_config;
use zbrain::index::{IndexStore, REBUILD_STATUS_REJECTED};
use zbrain::lifecycle::{ResignCandidate, ResignTarget};
use zbrain::paths::{Options, Paths};
use zbrain::signing::{approval_message_v1, KeyStore, APPROVAL_ALGORITHM};
use zbrain::workspace::create_workspace;

const FORGED_ID: &str = "clm_00000000000000000000000000000bad";

struct Fixture {
    dir: PathBuf,
    paths: Paths,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn fixture(name: &str) -> Fixture {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "zbrain-signed-{}-{}-{name}",
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
    Fixture { dir, paths }
}

#[derive(Clone, Default)]
struct SharedOut(Rc<RefCell<Vec<u8>>>);

impl Write for SharedOut {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.borrow_mut().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct Cli {
    app: App,
    out: SharedOut,
    err: SharedOut,
}

impl Cli {
    fn new(paths: Paths) -> Self {
        let out = SharedOut::default();
        let err = SharedOut::default();
        let mut app = new_app(paths);
        app.stdout = Box::new(out.clone());
        app.stderr = Box::new(err.clone());
        app.stdin = Box::new(Cursor::new(Vec::new()));
        app.prompt = PromptSource::Scripted(Vec::new());
        app.clock = std::sync::Arc::new(FixedClock::new(
            Utc.with_ymd_and_hms(2026, 8, 1, 9, 0, 0).unwrap(),
        ));
        Self { app, out, err }
    }

    fn argv(list: &[&str]) -> Vec<String> {
        list.iter().map(|value| value.to_string()).collect()
    }

    fn run(&mut self, list: &[&str]) -> Result<(), CliError> {
        self.out.0.borrow_mut().clear();
        self.err.0.borrow_mut().clear();
        self.app.run(&Self::argv(list))
    }

    fn run_ok(&mut self, list: &[&str]) -> String {
        self.run(list)
            .unwrap_or_else(|err| panic!("run({list:?}) error = {err}"));
        self.stdout()
    }

    fn stdout(&self) -> String {
        String::from_utf8(self.out.0.borrow().clone()).unwrap()
    }
}

fn claim_path(fx: &Fixture, id: &str) -> PathBuf {
    fx.paths
        .workspaces_dir
        .join("research/wiki/projects")
        .join(format!("{id}.md"))
}

/// Repro 01: no `claim draft`, no `claim approve` — write the file directly
/// with a recomputed digest, exactly what a forger can do today.
fn write_forged_claim(fx: &Fixture, id: &str, title: &str, body: &str) {
    write_forged_claim_with(fx, id, title, body, "2026-01-01T00:00:00Z", "owner");
}

fn write_forged_claim_with(
    fx: &Fixture,
    id: &str,
    title: &str,
    body: &str,
    verified_at: &str,
    verified_by: &str,
) {
    let mut claim = Claim {
        claim_type: OKF_CLAIM_TYPE.into(),
        id: id.into(),
        tier: "projects".into(),
        status: CLAIM_STATUS_APPROVED.into(),
        title: title.into(),
        basis: CLAIM_BASIS_OWNER.into(),
        created_at: "2026-01-01T00:00:00Z".into(),
        created_by: "owner".into(),
        verified_at: verified_at.into(),
        verified_by: verified_by.into(),
        // The transition stays pinned: only the verified block moves, which
        // is exactly what the digest blanks.
        transitions: vec![ClaimTransition {
            kind: CLAIM_TRANSITION_APPROVE.into(),
            at: "2026-01-01T00:00:00Z".into(),
            by: "owner".into(),
            ..ClaimTransition::default()
        }],
        body: body.into(),
        ..Claim::default()
    };
    claim.verified_digest = claim_verification_digest(&claim).unwrap();
    let rendered = render_claim_markdown(&claim).unwrap();
    let dir = fx.paths.workspaces_dir.join("research/wiki/projects");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(claim_path(fx, id), rendered).unwrap();
}

fn draft(cli: &mut Cli, title: &str, body: &str) -> String {
    cli.app.stdin = Box::new(Cursor::new(body.as_bytes().to_vec()));
    let out = cli.run_ok(&[
        "claim", "draft", "--tier", "projects", "--title", title, "--basis", "owner",
    ]);
    let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
    parsed["id"].as_str().unwrap().to_string()
}

/// Answers the owner ceremony with the digest suffix the CLI will ask for.
fn approve_via_cli(cli: &mut Cli, id: &str) -> String {
    use zbrain::approval::{action_digest_suffix, compute_challenge_action_digest};
    let store = ClaimStore::with_clock(cli.app.paths.clone(), cli.app.clock.clone());
    let prepare = store.approve_challenge_prepare("research", id).unwrap();
    let suffix = action_digest_suffix(&compute_challenge_action_digest(&prepare)).to_string();
    cli.app.prompt = PromptSource::Scripted(vec![suffix]);
    cli.run_ok(&["claim", "approve", id])
}

#[test]
fn forged_approved_claim_is_rejected() {
    let fx = fixture("forged");
    write_forged_claim(
        &fx,
        FORGED_ID,
        "Prod DB password policy",
        "rotate never, the root password is hunter2",
    );

    let summary = IndexStore::new(fx.paths.clone())
        .rebuild("research")
        .unwrap();
    assert!(
        summary.invalid >= 1,
        "a forged approved claim must be rejected by reindex: {summary:?}"
    );
    assert_eq!(summary.rebuild_state, REBUILD_STATUS_REJECTED);
    assert_eq!(summary.approved, 0);

    let mut cli = Cli::new(fx.paths.clone());
    let asked = cli.run(&["ask", "root password"]);
    let output = cli.stdout();
    match asked {
        // Fail closed: the rejected index is not served at all.
        Err(_) => {}
        Ok(()) => {
            let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
            assert_ne!(
                parsed["status"], "ready",
                "forged claim must never be served as approved: {output}"
            );
            assert!(
                !output.contains(FORGED_ID),
                "forged claim leaked into results: {output}"
            );
        }
    }
}

#[test]
fn doctor_names_the_supersede_path_for_an_unsigned_claim() {
    let fx = fixture("doctor-unsigned");
    let mut cli = Cli::new(fx.paths.clone());
    cli.run_ok(&["key", "init"]);
    // Written after the key exists: no ceremony ever saw it, so nothing may
    // sign it. The only way out is the owner supersede/revoke ceremony.
    write_forged_claim(
        &fx,
        "clm_00000000000000000000000000000002",
        "Unsigned fact",
        "written after key init",
    );
    let result = cli.run(&["doctor"]);
    let output = cli.stdout();
    assert!(result.is_err(), "{output}");
    assert!(output.contains("supersede or revoke"), "{output}");
    assert!(!output.contains("zbrain claim resign"), "{output}");
}

#[test]
fn doctor_names_the_resign_command_for_a_v1_signature() {
    let fx = fixture("doctor-v1");
    let id = "clm_00000000000000000000000000000003";
    let mut cli = Cli::new(fx.paths.clone());
    cli.run_ok(&["key", "init"]);
    write_v1_signed_claim(&fx, id, "V1 fact", "signed before workspaces were bound\n");
    let result = cli.run(&["doctor"]);
    let output = cli.stdout();
    assert!(result.is_err(), "{output}");
    assert!(output.contains("zbrain claim resign"), "{output}");
}

#[test]
fn claim_approve_records_a_signature() {
    let fx = fixture("approve-signs");
    let mut cli = Cli::new(fx.paths.clone());
    cli.run_ok(&["key", "init"]);
    let id = draft(&mut cli, "Agent fact", "agent wrote this\n");
    approve_via_cli(&mut cli, &id);

    let contents = std::fs::read_to_string(claim_path(&fx, &id)).unwrap();
    assert!(contents.contains("alg: ed25519"), "{contents}");
    assert!(contents.contains("key_id: "), "{contents}");
    assert!(contents.contains("sig: "), "{contents}");
}

fn resign_via_cli(cli: &mut Cli, excludes: &[&str]) -> String {
    let store = ClaimStore::with_clock(cli.app.paths.clone(), cli.app.clock.clone());
    let candidates = store.resign_candidates("research").unwrap();
    cli.app.prompt = PromptSource::Scripted(vec![ceremony_suffix("resign", &candidates, excludes)]);
    let mut argv = vec!["claim", "resign"];
    for id in excludes {
        argv.push("--exclude");
        argv.push(id);
    }
    cli.run_ok(&argv)
}

fn ceremony_suffix(operation: &str, candidates: &[ResignCandidate], excludes: &[&str]) -> String {
    use zbrain::approval::{
        action_digest_suffix, compute_challenge_action_digest, ChallengeItem, ChallengePrepare,
    };
    let items: Vec<ChallengeItem> = candidates
        .iter()
        .filter(|candidate| !excludes.contains(&candidate.id.as_str()))
        .map(|candidate| ChallengeItem {
            claim_id: candidate.id.clone(),
            canonical_draft_digest: candidate.digest.clone(),
        })
        .collect();
    let digest = compute_challenge_action_digest(&ChallengePrepare {
        workspace: "research".to_string(),
        operation: operation.to_string(),
        items,
        ..ChallengePrepare::default()
    });
    action_digest_suffix(&digest).to_string()
}

/// `key init` lists every approved claim and signs what the owner confirms.
fn key_init_via_cli(cli: &mut Cli, excludes: &[&str]) -> Result<String, CliError> {
    let store = ClaimStore::with_clock(cli.app.paths.clone(), cli.app.clock.clone());
    let candidates = store.key_init_candidates("research").unwrap();
    cli.app.prompt =
        PromptSource::Scripted(vec![ceremony_suffix("key-init", &candidates, excludes)]);
    let mut argv = vec!["key", "init"];
    for id in excludes {
        argv.push("--exclude");
        argv.push(id);
    }
    cli.run(&argv)?;
    Ok(cli.stdout())
}

fn targets(candidates: Vec<ResignCandidate>) -> Vec<ResignTarget> {
    candidates
        .into_iter()
        .map(|candidate| ResignTarget {
            id: candidate.id,
            digest: candidate.digest,
            verified_at: candidate.verified_at,
            verified_by: candidate.verified_by,
        })
        .collect()
}

/// A claim signed by the active key under the v1 message, which did not bind
/// the workspace: what a v0.4 `claim approve` wrote.
fn write_v1_signed_claim(fx: &Fixture, id: &str, title: &str, body: &str) {
    write_forged_claim(fx, id, title, body);
    let path = claim_path(fx, id);
    let mut claim = zbrain::claims::parse_claim_markdown(
        "projects",
        &format!("projects/{id}.md"),
        &std::fs::read(&path).unwrap(),
    )
    .unwrap();
    let (key_id, key) = KeyStore::open(&fx.paths)
        .unwrap()
        .active_signing_key()
        .unwrap();
    let signature = key.sign(&approval_message_v1(&claim, &key_id));
    claim.verified_alg = APPROVAL_ALGORITHM.to_string();
    claim.verified_key_id = key_id;
    claim.verified_sig = BASE64.encode(signature.to_bytes());
    std::fs::write(&path, render_claim_markdown(&claim).unwrap()).unwrap();
}

#[test]
fn signed_claim_is_trusted_end_to_end() {
    let fx = fixture("trusted");
    let mut cli = Cli::new(fx.paths.clone());
    cli.run_ok(&["key", "init"]);
    let id = draft(&mut cli, "Agent fact", "signed trusted answer\n");
    approve_via_cli(&mut cli, &id);
    cli.run_ok(&["reindex"]);

    let asked: serde_json::Value =
        serde_json::from_str(&cli.run_ok(&["ask", "signed trusted"])).unwrap();
    assert_eq!(asked["status"], "ready", "{asked}");
    assert_eq!(asked["claims"][0]["id"], id.as_str());

    let status: serde_json::Value = serde_json::from_str(&cli.run_ok(&["status"])).unwrap();
    assert_eq!(status["approved"], 1, "{status}");
    assert_eq!(status["invalid"], 0, "{status}");
    cli.run_ok(&["doctor"]);
}

#[test]
fn tampered_signature_is_rejected_by_every_surface() {
    let fx = fixture("tampered-sig");
    let mut cli = Cli::new(fx.paths.clone());
    cli.run_ok(&["key", "init"]);
    let id = draft(&mut cli, "Agent fact", "tamper target answer\n");
    approve_via_cli(&mut cli, &id);

    let path = claim_path(&fx, &id);
    let contents = std::fs::read_to_string(&path).unwrap();
    let marker = "    sig: ";
    let start = contents.find(marker).unwrap() + marker.len();
    let mut sig: Vec<u8> = contents[start..]
        .chars()
        .take_while(|c| *c != '\n')
        .map(|c| c as u8)
        .collect();
    // Flip one base64 character to a different valid one.
    sig[0] = if sig[0] == b'A' { b'B' } else { b'A' };
    let tampered = format!(
        "{}{}{}",
        &contents[..start],
        String::from_utf8(sig).unwrap(),
        &contents[start + contents[start..].chars().take_while(|c| *c != '\n').count()..]
    );
    std::fs::write(&path, tampered).unwrap();

    let summary = IndexStore::new(fx.paths.clone())
        .rebuild("research")
        .unwrap();
    assert!(summary.invalid >= 1, "{summary:?}");
    assert_eq!(summary.rebuild_state, REBUILD_STATUS_REJECTED);
    assert_eq!(summary.approved, 0);

    let status: serde_json::Value = serde_json::from_str(&cli.run_ok(&["status"])).unwrap();
    assert_eq!(status["approved"], 0, "{status}");
    assert!(status["invalid"].as_i64().unwrap() >= 1, "{status}");

    // `ask` never serves the claim: either it fails closed on the rejected
    // index, or it answers without the claim.
    match cli.run(&["ask", "tamper target"]) {
        Ok(()) => {
            let output = cli.stdout();
            let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
            assert_ne!(parsed["status"], "ready", "{output}");
            let claims = parsed["claims"].as_array().cloned().unwrap_or_default();
            assert!(
                claims.iter().all(|claim| claim["id"] != id.as_str()),
                "{output}"
            );
        }
        Err(err) => assert!(err.to_string().contains("rejected"), "{err}"),
    }
}

#[test]
fn claim_approve_without_a_key_fails_before_the_ceremony() {
    let fx = fixture("no-key");
    let mut cli = Cli::new(fx.paths.clone());
    let id = draft(&mut cli, "Agent fact", "no key answer\n");
    let error = cli
        .run(&["claim", "approve", &id])
        .expect_err("approve must fail without a key");
    assert!(
        error.to_string().contains("signing key unavailable"),
        "{error}"
    );
    let contents = std::fs::read_to_string(claim_path(&fx, &id)).unwrap();
    assert!(contents.contains("status: draft"), "{contents}");
}

#[test]
fn key_init_signs_legacy_claims_and_honors_exclusions() {
    let fx = fixture("key-init-batch");
    let keep = "clm_0000000000000000000000000000000a";
    let exclude = "clm_0000000000000000000000000000000b";
    write_forged_claim(&fx, keep, "Legacy keep", "legacy keep body\n");
    write_forged_claim(&fx, exclude, "Legacy exclude", "legacy exclude body\n");

    let mut cli = Cli::new(fx.paths.clone());
    let out = key_init_via_cli(&mut cli, &[exclude]).unwrap();
    let report: serde_json::Value = serde_json::from_str(&out).unwrap();
    let signed = &report["signed_claims"][0];
    assert_eq!(signed["workspace"], "research", "{report}");
    assert_eq!(signed["signed"], serde_json::json!([keep]), "{report}");
    assert_eq!(signed["excluded"], serde_json::json!([exclude]), "{report}");

    let summary = IndexStore::new(fx.paths.clone())
        .rebuild("research")
        .unwrap();
    assert_eq!(summary.approved, 1, "{summary:?}");
    assert_eq!(summary.invalid, 1, "{summary:?}");
    let kept = std::fs::read_to_string(claim_path(&fx, keep)).unwrap();
    assert!(kept.contains("sig: "), "{kept}");
    let skipped = std::fs::read_to_string(claim_path(&fx, exclude)).unwrap();
    assert!(!skipped.contains("sig:"), "{skipped}");

    let doctor = cli.run(&["doctor"]);
    let output = cli.stdout();
    assert!(doctor.is_err(), "{output}");
    assert!(
        output.contains("1 approved claims have no valid owner signature"),
        "{output}"
    );
}

#[test]
fn key_init_with_a_wrong_suffix_commits_nothing() {
    let fx = fixture("key-init-wrong");
    let id = "clm_0000000000000000000000000000000c";
    write_forged_claim(&fx, id, "Legacy claim", "legacy body\n");
    let mut cli = Cli::new(fx.paths.clone());
    cli.app.prompt = PromptSource::Scripted(vec!["0000000000000000".to_string()]);
    let error = cli
        .run(&["key", "init"])
        .expect_err("a wrong suffix must be refused");
    assert!(
        error.to_string().contains("digest suffix mismatch"),
        "{error}"
    );
    assert!(KeyStore::open(&fx.paths).is_err(), "anchor was committed");
    let contents = std::fs::read_to_string(claim_path(&fx, id)).unwrap();
    assert!(!contents.contains("sig:"), "{contents}");

    // The rerun starts over with a fresh key and signs.
    key_init_via_cli(&mut cli, &[]).unwrap();
    let summary = IndexStore::new(fx.paths.clone())
        .rebuild("research")
        .unwrap();
    assert_eq!(summary.approved, 1, "{summary:?}");
}

#[test]
fn key_init_without_approved_claims_needs_no_prompt() {
    let fx = fixture("key-init-empty");
    let mut cli = Cli::new(fx.paths.clone());
    let out = cli.run_ok(&["key", "init"]);
    assert!(!out.contains("signed_claims"), "{out}");
    KeyStore::open(&fx.paths).unwrap();
}

#[test]
fn resign_upgrades_a_v1_signature() {
    let fx = fixture("resign-v1");
    let id = "clm_0000000000000000000000000000001a";
    let mut cli = Cli::new(fx.paths.clone());
    cli.run_ok(&["key", "init"]);
    write_v1_signed_claim(&fx, id, "V1 claim", "v1 signed body\n");
    let summary = IndexStore::new(fx.paths.clone())
        .rebuild("research")
        .unwrap();
    assert_eq!(summary.approved, 0, "v1 must not verify as v2: {summary:?}");

    let report: serde_json::Value = serde_json::from_str(&resign_via_cli(&mut cli, &[])).unwrap();
    assert_eq!(report["signed"], serde_json::json!([id]), "{report}");
    let summary = IndexStore::new(fx.paths.clone())
        .rebuild("research")
        .unwrap();
    assert_eq!(summary.approved, 1, "{summary:?}");
    assert_eq!(summary.invalid, 0, "{summary:?}");

    let before = std::fs::read_to_string(claim_path(&fx, id)).unwrap();
    let report: serde_json::Value = serde_json::from_str(&resign_via_cli(&mut cli, &[])).unwrap();
    assert_eq!(report["signed"], serde_json::json!([]), "{report}");
    assert_eq!(
        report["already_signed"],
        serde_json::json!([id]),
        "{report}"
    );
    assert_eq!(
        std::fs::read_to_string(claim_path(&fx, id)).unwrap(),
        before
    );
}

/// Security review before v0.5.0, finding 3: after `key init`, a writer
/// strips the signature off an approved claim, rewrites the body, and
/// recomputes the digest. `resign` must not turn that into a signed claim.
#[test]
fn resign_refuses_a_stripped_tampered_claim() {
    let fx = fixture("resign-tampered");
    let mut cli = Cli::new(fx.paths.clone());
    cli.run_ok(&["key", "init"]);
    let id = draft(&mut cli, "Refund policy", "refunds need a receipt\n");
    approve_via_cli(&mut cli, &id);

    let path = claim_path(&fx, &id);
    let mut claim = zbrain::claims::parse_claim_markdown(
        "projects",
        &format!("projects/{id}.md"),
        &std::fs::read(&path).unwrap(),
    )
    .unwrap();
    claim.body = "refunds need no receipt\n".to_string();
    claim.verified_alg.clear();
    claim.verified_key_id.clear();
    claim.verified_sig.clear();
    claim.verified_digest = claim_verification_digest(&claim).unwrap();
    std::fs::write(&path, render_claim_markdown(&claim).unwrap()).unwrap();

    let store = ClaimStore::with_clock(fx.paths.clone(), cli.app.clock.clone());
    assert!(store.resign_candidates("research").unwrap().is_empty());
    let out = cli.run_ok(&["claim", "resign"]);
    let report: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(report["signed"], serde_json::json!([]), "{report}");
    assert!(
        report["skipped"][0]["reason"]
            .as_str()
            .unwrap()
            .contains("supersede or revoke"),
        "{report}"
    );
    // A forged confirmed list cannot sign it either.
    let forged = vec![ResignTarget {
        id: id.clone(),
        digest: claim.verified_digest.clone(),
        verified_at: claim.verified_at.clone(),
        verified_by: claim.verified_by.clone(),
    }];
    let report = store.resign_approved("research", &forged, &[]).unwrap();
    assert!(report.signed.is_empty(), "{report:?}");
    let contents = std::fs::read_to_string(&path).unwrap();
    assert!(!contents.contains("sig:"), "{contents}");
    let summary = IndexStore::new(fx.paths.clone())
        .rebuild("research")
        .unwrap();
    assert_eq!(summary.approved, 0, "{summary:?}");

    // The escape hatch still works: the owner supersedes the claim, later.
    cli.app.clock = std::sync::Arc::new(FixedClock::new(
        Utc.with_ymd_and_hms(2026, 8, 1, 10, 0, 0).unwrap(),
    ));
    cli.app.stdin = Box::new(Cursor::new(b"refunds need a receipt, again\n".to_vec()));
    let out = cli.run_ok(&[
        "claim",
        "supersede",
        &id,
        "--tier",
        "projects",
        "--title",
        "Refund policy",
        "--basis",
        "owner",
    ]);
    let replacement = serde_json::from_str::<serde_json::Value>(&out).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    approve_via_cli(&mut cli, &replacement);
    let old = store.read("research", &id).unwrap();
    assert_eq!(old.status, "superseded", "{old:?}");
    cli.run_ok(&["reindex"]);
    let status: serde_json::Value = serde_json::from_str(&cli.run_ok(&["status"])).unwrap();
    assert_eq!(
        status["catalog"],
        serde_json::json!([{"id": replacement, "tier": "projects", "title": "Refund policy"}]),
        "{status}"
    );
    assert_eq!(status["invalid"], 0, "{status}");

    // Superseding must not launder the tampered body into history: neither
    // the present nor a point in time before the supersede serves it.
    let present: serde_json::Value =
        serde_json::from_str(&cli.run_ok(&["ask", "refunds"])).unwrap();
    assert_eq!(present["status"], "ready", "{present}");
    assert_eq!(
        present["claims"][0]["id"],
        replacement.as_str(),
        "{present}"
    );
    for argv in [
        vec!["ask", "refunds"],
        vec!["ask", "--as-of", "2026-08-01T09:30:00Z", "refunds"],
    ] {
        let result = cli.run(&argv);
        let output = cli.stdout();
        assert!(
            !output.contains("refunds need no receipt"),
            "{argv:?} served the tampered body: {output}"
        );
        if result.is_ok() {
            let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
            let claims = parsed["claims"].as_array().cloned().unwrap_or_default();
            assert!(
                claims.iter().all(|claim| claim["id"] != id.as_str()),
                "{argv:?}: {output}"
            );
        }
    }
}

/// A run that signed claims but died before writing the key leaves claims
/// signed by a key nobody holds. The rerun must re-sign them.
#[test]
fn key_init_rerun_after_an_interrupted_run_re_signs() {
    let fx = fixture("key-init-interrupted");
    let id = "clm_0000000000000000000000000000001c";
    write_forged_claim(&fx, id, "Legacy claim", "legacy interrupted body\n");
    let now = Utc.with_ymd_and_hms(2026, 8, 1, 9, 0, 0).unwrap();
    let store = ClaimStore::with_clock(fx.paths.clone(), std::sync::Arc::new(FixedClock::new(now)));
    let plan = KeyStore::plan_init(&fx.paths, now).unwrap();
    let listed = targets(store.key_init_candidates("research").unwrap());
    let report = store
        .sign_at_key_init("research", &listed, &[], &plan)
        .unwrap();
    assert_eq!(report.signed, vec![id.to_string()], "{report:?}");
    drop(plan);
    assert!(KeyStore::open(&fx.paths).is_err(), "no key was committed");

    let mut cli = Cli::new(fx.paths.clone());
    let out = key_init_via_cli(&mut cli, &[]).unwrap();
    let report: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(
        report["signed_claims"][0]["signed"],
        serde_json::json!([id]),
        "{report}"
    );
    let summary = IndexStore::new(fx.paths.clone())
        .rebuild("research")
        .unwrap();
    assert_eq!(summary.approved, 1, "{summary:?}");
    assert_eq!(summary.invalid, 0, "{summary:?}");
}

#[test]
fn key_init_refused_in_a_later_workspace_commits_nothing() {
    let fx = fixture("key-init-two");
    let first = "clm_0000000000000000000000000000001d";
    let second = "clm_0000000000000000000000000000001e";
    write_forged_claim(&fx, first, "First", "first workspace body\n");
    create_workspace(
        &fx.paths,
        "zeta",
        &FixedClock::new(Utc.with_ymd_and_hms(2026, 8, 1, 9, 0, 0).unwrap()),
    )
    .unwrap();
    let moved = fx.paths.workspaces_dir.join("zeta/wiki/projects");
    std::fs::create_dir_all(&moved).unwrap();
    write_forged_claim(&fx, second, "Second", "second workspace body\n");
    std::fs::rename(claim_path(&fx, second), moved.join(format!("{second}.md"))).unwrap();

    let mut cli = Cli::new(fx.paths.clone());
    let store = ClaimStore::with_clock(fx.paths.clone(), cli.app.clock.clone());
    let research = store.key_init_candidates("research").unwrap();
    assert_eq!(research.len(), 1);
    cli.app.prompt = PromptSource::Scripted(vec![
        ceremony_suffix("key-init", &research, &[]),
        "0000000000000000".to_string(),
    ]);
    let error = cli
        .run(&["key", "init"])
        .expect_err("a wrong suffix in the second workspace must refuse");
    assert!(
        error.to_string().contains("digest suffix mismatch"),
        "{error}"
    );
    assert!(KeyStore::open(&fx.paths).is_err(), "anchor was committed");
    for path in [claim_path(&fx, first), moved.join(format!("{second}.md"))] {
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(!contents.contains("sig:"), "{contents}");
    }
}

#[test]
fn resign_refuses_a_v1_claim_whose_body_was_rewritten() {
    let fx = fixture("resign-v1-rewritten");
    let id = "clm_0000000000000000000000000000001f";
    let mut cli = Cli::new(fx.paths.clone());
    cli.run_ok(&["key", "init"]);
    write_v1_signed_claim(&fx, id, "V1 claim", "v1 original body\n");
    let path = claim_path(&fx, id);
    let mut claim = zbrain::claims::parse_claim_markdown(
        "projects",
        &format!("projects/{id}.md"),
        &std::fs::read(&path).unwrap(),
    )
    .unwrap();
    claim.body = "v1 rewritten body\n".to_string();
    claim.verified_digest = claim_verification_digest(&claim).unwrap();
    std::fs::write(&path, render_claim_markdown(&claim).unwrap()).unwrap();

    let store = ClaimStore::with_clock(fx.paths.clone(), cli.app.clock.clone());
    assert!(store.resign_candidates("research").unwrap().is_empty());
    let forged = vec![ResignTarget {
        id: id.to_string(),
        digest: claim.verified_digest.clone(),
        verified_at: claim.verified_at.clone(),
        verified_by: claim.verified_by.clone(),
    }];
    let report = store.resign_approved("research", &forged, &[]).unwrap();
    assert!(report.signed.is_empty(), "{report:?}");
}

#[test]
fn resign_refuses_a_v1_claim_copied_from_another_workspace() {
    let fx = fixture("resign-v1-copy");
    let id = "clm_0000000000000000000000000000001b";
    let mut cli = Cli::new(fx.paths.clone());
    cli.run_ok(&["key", "init"]);
    cli.run_ok(&["workspace", "create", "other"]);
    write_v1_signed_claim(&fx, id, "V1 claim", "v1 copied body\n");
    let other = fx
        .paths
        .workspaces_dir
        .join("other/wiki/projects")
        .join(format!("{id}.md"));
    std::fs::copy(claim_path(&fx, id), &other).unwrap();

    let store = ClaimStore::with_clock(fx.paths.clone(), cli.app.clock.clone());
    let listed = targets(store.resign_candidates("research").unwrap());
    let report = store.resign_approved("research", &listed, &[]).unwrap();
    assert!(report.signed.is_empty(), "{report:?}");
    assert!(
        report.skipped[0]
            .reason
            .contains("also exists in workspace other"),
        "{report:?}"
    );
}

#[test]
fn key_recover_requires_typing_the_new_key_id() {
    let fx = fixture("recover-cli");
    let mut cli = Cli::new(fx.paths.clone());
    cli.run_ok(&["key", "init"]);
    let id = draft(&mut cli, "Agent fact", "recovery keeps this claim\n");
    approve_via_cli(&mut cli, &id);
    let private_key = fx.paths.key_dir.join("approval.ed25519");
    std::fs::remove_file(&private_key).unwrap();

    // A wrong confirmation writes nothing.
    cli.app.prompt = PromptSource::Scripted(vec!["0000000000000000".to_string()]);
    let error = cli
        .run(&["key", "init", "--recover"])
        .expect_err("a wrong key id must be refused");
    assert!(error.to_string().contains("key id mismatch"), "{error}");
    assert!(!private_key.exists(), "refused recovery wrote a key");

    // Typing the printed id commits, and the claim signed by the old key
    // still verifies because that key is retired, not revoked.
    cli.app.clock = std::sync::Arc::new(FixedClock::new(
        Utc.with_ymd_and_hms(2026, 8, 1, 10, 0, 0).unwrap(),
    ));
    let printed = cli.err.clone();
    cli.app.prompt = PromptSource::Live(Box::new(move || {
        let text = String::from_utf8(printed.0.borrow().clone()).unwrap();
        text.split("new key id: ")
            .nth(1)
            .and_then(|rest| rest.lines().next())
            .expect("the command must print the new key id")
            .trim()
            .to_string()
    }));
    let out = cli.run_ok(&["key", "init", "--recover"]);
    let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(parsed["recovered"], true, "{out}");
    assert!(private_key.exists(), "committed recovery wrote no key");
    assert_eq!(parsed["retired_key_ids"].as_array().unwrap().len(), 1);

    cli.run_ok(&["reindex"]);
    let status: serde_json::Value = serde_json::from_str(&cli.run_ok(&["status"])).unwrap();
    assert_eq!(status["approved"], 1, "{status}");
    assert_eq!(status["invalid"], 0, "{status}");
}

#[test]
fn key_init_signs_only_the_confirmed_list() {
    let fx = fixture("key-init-bound");
    let confirmed = "clm_0000000000000000000000000000000d";
    let added = "clm_0000000000000000000000000000000e";
    let changed = "clm_0000000000000000000000000000000f";
    write_forged_claim(&fx, confirmed, "Confirmed", "confirmed body\n");
    write_forged_claim(&fx, changed, "Changed", "changed body\n");

    let store = ClaimStore::with_clock(
        fx.paths.clone(),
        std::sync::Arc::new(FixedClock::new(
            Utc.with_ymd_and_hms(2026, 8, 1, 9, 0, 0).unwrap(),
        )),
    );
    let plan = KeyStore::plan_init(
        &fx.paths,
        Utc.with_ymd_and_hms(2026, 8, 1, 9, 0, 0).unwrap(),
    )
    .unwrap();
    let listed = targets(store.key_init_candidates("research").unwrap());
    assert_eq!(listed.len(), 2);

    // While the prompt waits: a new approved claim appears, and one listed
    // claim is rewritten with a recomputed digest (what a forger can do).
    write_forged_claim(&fx, added, "Added", "added body\n");
    write_forged_claim(&fx, changed, "Changed", "changed body, rewritten\n");

    let report = store
        .sign_at_key_init("research", &listed, &[], &plan)
        .unwrap();
    plan.commit().unwrap();
    assert_eq!(report.signed, vec![confirmed.to_string()], "{report:?}");
    let skipped: Vec<&str> = report.skipped.iter().map(|skip| skip.id.as_str()).collect();
    assert_eq!(skipped, vec![added, changed], "{report:?}");

    let signed = std::fs::read_to_string(claim_path(&fx, confirmed)).unwrap();
    assert!(signed.contains("sig: "), "{signed}");
    for id in [added, changed] {
        let contents = std::fs::read_to_string(claim_path(&fx, id)).unwrap();
        assert!(
            !contents.contains("sig:"),
            "{id} was signed unseen: {contents}"
        );
    }
}

#[test]
fn key_init_refuses_a_claim_whose_approval_time_or_approver_changed() {
    let fx = fixture("key-init-verified-block");
    let moved = "clm_00000000000000000000000000000010";
    let reattributed = "clm_00000000000000000000000000000011";
    write_forged_claim(&fx, moved, "Moved", "moved body\n");
    write_forged_claim(&fx, reattributed, "Reattributed", "reattributed body\n");

    let store = ClaimStore::with_clock(
        fx.paths.clone(),
        std::sync::Arc::new(FixedClock::new(
            Utc.with_ymd_and_hms(2026, 8, 1, 9, 0, 0).unwrap(),
        )),
    );
    let plan = KeyStore::plan_init(
        &fx.paths,
        Utc.with_ymd_and_hms(2026, 8, 1, 9, 0, 0).unwrap(),
    )
    .unwrap();
    let listed = targets(store.key_init_candidates("research").unwrap());
    assert_eq!(listed.len(), 2);

    // The digest blanks `verified.*`, so both rewrites keep the digest the
    // owner confirmed. Only the approval-time and approver comparison can
    // refuse them.
    write_forged_claim_with(
        &fx,
        moved,
        "Moved",
        "moved body\n",
        "2026-02-02T00:00:00Z",
        "owner",
    );
    write_forged_claim_with(
        &fx,
        reattributed,
        "Reattributed",
        "reattributed body\n",
        "2026-01-01T00:00:00Z",
        "agent",
    );

    let report = store
        .sign_at_key_init("research", &listed, &[], &plan)
        .unwrap();
    assert!(report.signed.is_empty(), "{report:?}");
    assert_eq!(report.skipped.len(), 2, "{report:?}");
    for skip in &report.skipped {
        assert!(
            skip.reason.contains("approval time or approver"),
            "{report:?}"
        );
    }
    for id in [moved, reattributed] {
        let contents = std::fs::read_to_string(claim_path(&fx, id)).unwrap();
        assert!(
            !contents.contains("sig:"),
            "{id} was signed after its verified block changed: {contents}"
        );
    }
}

/// Security review before v0.5.0, finding 2: the signature must bind the
/// workspace, or a signed claim copied into another workspace stays trusted.
#[test]
fn signed_claim_copied_into_another_workspace_is_rejected() {
    let fx = fixture("cross-workspace");
    let mut cli = Cli::new(fx.paths.clone());
    cli.run_ok(&["key", "init"]);
    let id = draft(&mut cli, "Agent fact", "cross workspace replay answer\n");
    approve_via_cli(&mut cli, &id);

    create_workspace(
        &fx.paths,
        "other",
        &FixedClock::new(Utc.with_ymd_and_hms(2026, 8, 1, 9, 0, 0).unwrap()),
    )
    .unwrap();
    let copy = fx
        .paths
        .workspaces_dir
        .join("other/wiki/projects")
        .join(format!("{id}.md"));
    std::fs::copy(claim_path(&fx, &id), &copy).unwrap();

    let summary = IndexStore::new(fx.paths.clone()).rebuild("other").unwrap();
    assert_eq!(summary.approved, 0, "{summary:?}");
    assert!(summary.invalid >= 1, "{summary:?}");
    assert_eq!(summary.rebuild_state, REBUILD_STATUS_REJECTED);

    // The original stays trusted in its own workspace.
    let summary = IndexStore::new(fx.paths.clone())
        .rebuild("research")
        .unwrap();
    assert_eq!(summary.approved, 1, "{summary:?}");
    assert_eq!(summary.invalid, 0, "{summary:?}");
}

/// The v2 signature binds the claim's own workspace, so a secondary
/// workspace read with `--include` must verify against that workspace.
#[test]
fn included_workspace_claim_verifies_against_its_own_workspace() {
    use zbrain::approval::{action_digest_suffix, compute_challenge_action_digest};
    let fx = fixture("include");
    let mut cli = Cli::new(fx.paths.clone());
    cli.run_ok(&["key", "init"]);
    cli.run_ok(&["workspace", "create", "other"]);
    cli.app.stdin = Box::new(Cursor::new(b"secondary included answer\n".to_vec()));
    let out = cli.run_ok(&[
        "claim",
        "draft",
        "--tier",
        "projects",
        "--title",
        "Other fact",
        "--basis",
        "owner",
        "--workspace",
        "other",
    ]);
    let id = serde_json::from_str::<serde_json::Value>(&out).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let store = ClaimStore::with_clock(cli.app.paths.clone(), cli.app.clock.clone());
    let prepare = store.approve_challenge_prepare("other", &id).unwrap();
    let suffix = action_digest_suffix(&compute_challenge_action_digest(&prepare)).to_string();
    cli.app.prompt = PromptSource::Scripted(vec![suffix]);
    cli.run_ok(&["claim", "approve", &id, "--workspace", "other"]);
    cli.run_ok(&["reindex", "--workspace", "other"]);
    cli.run_ok(&["reindex", "--workspace", "research"]);

    let asked: serde_json::Value = serde_json::from_str(&cli.run_ok(&[
        "ask",
        "secondary included",
        "--workspace",
        "research",
        "--include",
        "other",
    ]))
    .unwrap();
    assert_eq!(asked["status"], "ready", "{asked}");
    assert_eq!(asked["claims"][0]["id"], id.as_str(), "{asked}");
}
