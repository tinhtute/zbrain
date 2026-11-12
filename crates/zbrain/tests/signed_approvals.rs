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

use zbrain::assets::extract_bundled_assets;
use zbrain::claims::{
    claim_verification_digest, render_claim_markdown, Claim, ClaimTransition, CLAIM_BASIS_OWNER,
    CLAIM_STATUS_APPROVED, CLAIM_TRANSITION_APPROVE, OKF_CLAIM_TYPE,
};
use zbrain::cli::{new_app, App, CliError, PromptSource};
use zbrain::clock::FixedClock;
use zbrain::config::ensure_config;
use zbrain::index::{IndexStore, REBUILD_STATUS_REJECTED};
use zbrain::paths::{Options, Paths};
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
    let mut claim = Claim {
        claim_type: OKF_CLAIM_TYPE.into(),
        id: id.into(),
        tier: "projects".into(),
        status: CLAIM_STATUS_APPROVED.into(),
        title: title.into(),
        basis: CLAIM_BASIS_OWNER.into(),
        created_at: "2026-01-01T00:00:00Z".into(),
        created_by: "owner".into(),
        verified_at: "2026-01-01T00:00:00Z".into(),
        verified_by: "owner".into(),
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
    use zbrain::claims::ClaimStore;
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
fn doctor_names_the_resign_command() {
    let fx = fixture("doctor");
    // A legacy approved claim: valid digest, no signature. This is what every
    // workspace looks like on the upgrade, and what the re-sign ceremony fixes.
    write_forged_claim(
        &fx,
        "clm_00000000000000000000000000000002",
        "Legacy approved fact",
        "approved before signatures existed",
    );
    let mut cli = Cli::new(fx.paths.clone());
    cli.run_ok(&["key", "init"]);
    cli.run_ok(&["reindex"]);

    // `doctor` reports domain findings by exiting 2 after printing the JSON.
    let result = cli.run(&["doctor"]);
    let output = cli.stdout();
    assert!(
        result.is_err(),
        "doctor must report the unsigned claim: {output}"
    );
    assert!(
        output.contains("zbrain claim resign"),
        "doctor must name the re-sign command: {output}"
    );
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
    use zbrain::approval::{
        action_digest_suffix, compute_challenge_action_digest, ChallengeItem, ChallengePrepare,
    };
    use zbrain::claims::ClaimStore;
    let store = ClaimStore::with_clock(cli.app.paths.clone(), cli.app.clock.clone());
    let candidates = store.resign_candidates("research").unwrap();
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
        operation: "resign".to_string(),
        items,
        ..ChallengePrepare::default()
    });
    cli.app.prompt = PromptSource::Scripted(vec![action_digest_suffix(&digest).to_string()]);
    let mut argv = vec!["claim", "resign"];
    for id in excludes {
        argv.push("--exclude");
        argv.push(id);
    }
    cli.run_ok(&argv)
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

    let asked = cli.run(&["ask", "tamper target"]);
    let output = cli.stdout();
    if asked.is_ok() {
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_ne!(parsed["status"], "ready", "{output}");
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
fn resign_batch_signs_legacy_claims_and_honors_exclusions() {
    let fx = fixture("resign");
    let keep = "clm_0000000000000000000000000000000a";
    let exclude = "clm_0000000000000000000000000000000b";
    write_forged_claim(&fx, keep, "Legacy keep", "legacy keep body\n");
    write_forged_claim(&fx, exclude, "Legacy exclude", "legacy exclude body\n");

    let mut cli = Cli::new(fx.paths.clone());
    cli.run_ok(&["key", "init"]);
    let out = resign_via_cli(&mut cli, &[exclude]);
    let report: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(report["signed"], serde_json::json!([keep]), "{report}");
    assert_eq!(report["excluded"], serde_json::json!([exclude]), "{report}");

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
        output.contains("1 approved claims are unsigned"),
        "{output}"
    );
}

#[test]
fn resign_is_a_noop_when_claims_are_already_signed() {
    let fx = fixture("resign-idempotent");
    let id = "clm_0000000000000000000000000000000c";
    write_forged_claim(&fx, id, "Legacy claim", "legacy body\n");
    let mut cli = Cli::new(fx.paths.clone());
    cli.run_ok(&["key", "init"]);
    resign_via_cli(&mut cli, &[]);
    let before = std::fs::read_to_string(claim_path(&fx, id)).unwrap();

    let out = resign_via_cli(&mut cli, &[]);
    let report: serde_json::Value = serde_json::from_str(&out).unwrap();
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
