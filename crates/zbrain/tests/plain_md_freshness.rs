//! A non-claim Markdown file anywhere under a workspace's `wiki/` makes the
//! rebuild reject the index, so the freshness check must see it before
//! reindex too, and every failure must name the file and the real fix
//! (audit 2026-11-09, item 9, repro 12). Each test drives the binary the way
//! a user does: `ask`, then `reindex`, then `ask` again.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use chrono::{TimeZone, Utc};

use zbrain::assets::extract_bundled_assets;
use zbrain::claims::{
    claim_verification_digest, render_claim_markdown, Claim, ClaimTransition, CLAIM_BASIS_OWNER,
    CLAIM_STATUS_APPROVED, CLAIM_TRANSITION_APPROVE, OKF_CLAIM_TYPE,
};
use zbrain::clock::FixedClock;
use zbrain::config::ensure_config;
use zbrain::index::{IndexStore, REBUILD_STATUS_CLEAN};
use zbrain::paths::{Options, Paths};
use zbrain::workspace::create_workspace;

const CLAIM_ID: &str = "clm_00000000000000000000000000000009";
const FIX: &str = "move it out of wiki/ or make it a valid claim";

struct Fixture {
    dir: PathBuf,
    paths: Paths,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A workspace with one signed, approved claim and a clean index.
fn indexed_workspace(name: &str) -> Fixture {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "zbrain-plainmd-{}-{}-{name}",
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
    let at = Utc.with_ymd_and_hms(2026, 8, 1, 9, 0, 0).unwrap();
    create_workspace(&paths, "research", &FixedClock::new(at)).unwrap();
    zbrain::signing::KeyStore::init(&paths, at).unwrap();

    let mut claim = Claim {
        claim_type: OKF_CLAIM_TYPE.into(),
        id: CLAIM_ID.into(),
        tier: "projects".into(),
        status: CLAIM_STATUS_APPROVED.into(),
        title: "Deploy window".into(),
        basis: CLAIM_BASIS_OWNER.into(),
        created_at: "2026-08-01T09:00:00Z".into(),
        created_by: "owner".into(),
        verified_at: "2026-08-01T09:00:00Z".into(),
        verified_by: "owner".into(),
        transitions: vec![ClaimTransition {
            kind: CLAIM_TRANSITION_APPROVE.into(),
            at: "2026-08-01T09:00:00Z".into(),
            by: "owner".into(),
            ..ClaimTransition::default()
        }],
        body: "the deploy window is tuesday\n".into(),
        ..Claim::default()
    };
    claim.verified_digest = claim_verification_digest(&claim).unwrap();
    let keys = zbrain::signing::KeyStore::open(&paths).unwrap();
    zbrain::signing::sign_claim(&mut claim, &keys).unwrap();
    let projects = paths.workspaces_dir.join("research/wiki/projects");
    std::fs::create_dir_all(&projects).unwrap();
    std::fs::write(
        projects.join(format!("{CLAIM_ID}.md")),
        render_claim_markdown(&claim).unwrap(),
    )
    .unwrap();

    let summary = IndexStore::new(paths.clone()).rebuild("research").unwrap();
    assert_eq!(
        summary.rebuild_state, REBUILD_STATUS_CLEAN,
        "invalid={:?}",
        summary.invalid_claims
    );
    Fixture { dir, paths }
}

/// Runs the binary and returns (success, stdout + stderr).
fn zbrain(fx: &Fixture, args: &[&str]) -> (bool, String) {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_zbrain"))
        .env("ZBRAIN_HOME", &fx.paths.runtime_dir)
        .env("XDG_CONFIG_HOME", fx.paths.key_dir.parent().unwrap())
        .args(args)
        .output()
        .unwrap();
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.success(), text)
}

fn ask(fx: &Fixture) -> (bool, String) {
    zbrain(fx, &["ask", "deploy", "--workspace", "research"])
}

fn assert_actionable(stage: &str, output: &str, wiki_relative: &str) {
    assert!(
        output.contains(wiki_relative),
        "{stage}: output does not name {wiki_relative:?}:\n{output}"
    );
    assert!(
        output.contains(FIX),
        "{stage}: output does not name the fix {FIX:?}:\n{output}"
    );
}

fn plain_note_bricks_with_actionable_error(name: &str, wiki_relative: &str) {
    let fx = indexed_workspace(name);
    let (ok, before) = ask(&fx);
    assert!(ok, "control ask failed:\n{before}");
    assert!(before.contains("\"status\": \"ready\""), "{before}");

    let note = fx
        .paths
        .workspaces_dir
        .join("research/wiki")
        .join(wiki_relative);
    std::fs::create_dir_all(note.parent().unwrap()).unwrap();
    std::fs::write(&note, "# scratch\nunrelated note\n").unwrap();

    let (ok, before_reindex) = ask(&fx);
    assert!(
        !ok && !before_reindex.contains("\"status\": \"ready\""),
        "ask before reindex must fail closed:\n{before_reindex}"
    );
    assert_actionable("ask before reindex", &before_reindex, wiki_relative);

    // doctor must point at the real fix, not at a reindex that cannot clear it.
    let (_, doctor) = zbrain(&fx, &["doctor", "--workspace", "research"]);
    assert_actionable("doctor", &doctor, wiki_relative);
    assert!(
        doctor.contains(
            "\"next_action\": \"move non-claim files out of wiki/, then zbrain reindex\""
        ),
        "doctor next_action must name the wiki fix:\n{doctor}"
    );

    let (_, reindex) = zbrain(&fx, &["reindex", "--workspace", "research"]);
    assert!(
        reindex.contains("\"rebuild_state\": \"rejected\""),
        "{reindex}"
    );
    assert_actionable("reindex", &reindex, wiki_relative);

    let (ok, after_reindex) = ask(&fx);
    assert!(
        !ok && !after_reindex.contains("\"status\": \"ready\""),
        "ask after reindex must fail closed:\n{after_reindex}"
    );
    assert_actionable("ask after reindex", &after_reindex, wiki_relative);

    // Moving the note out of wiki/ is the fix the messages name.
    std::fs::rename(&note, fx.dir.join("todo.md")).unwrap();
    let (_, reindex) = zbrain(&fx, &["reindex", "--workspace", "research"]);
    assert!(
        reindex.contains("\"rebuild_state\": \"clean\""),
        "{reindex}"
    );
    let (ok, fixed) = ask(&fx);
    assert!(ok && fixed.contains("\"status\": \"ready\""), "{fixed}");
}

#[test]
fn plain_note_in_new_wiki_subdirectory_is_named_before_reindex() {
    plain_note_bricks_with_actionable_error("subdir", "notes/todo.md");
}

#[test]
fn plain_note_at_wiki_root_is_named_before_reindex() {
    plain_note_bricks_with_actionable_error("root", "todo.md");
}

#[test]
fn plain_note_inside_claim_tier_is_named_before_reindex() {
    plain_note_bricks_with_actionable_error("tier", "projects/todo.md");
}

/// A rejected index with a non-claim wiki file AND an invalid claim must
/// not present moving the file as the whole fix (audit item 9 follow-up).
#[test]
fn plain_note_does_not_hide_other_invalid_claims() {
    let fx = indexed_workspace("mixed");
    let wiki = fx.paths.workspaces_dir.join("research/wiki");
    std::fs::write(wiki.join("todo.md"), "# scratch\nunrelated note\n").unwrap();
    // A tampered copy of the approved claim: its digest no longer matches.
    let bad_id = "clm_0000000000000000000000000000000a";
    let original = std::fs::read_to_string(wiki.join(format!("projects/{CLAIM_ID}.md"))).unwrap();
    let tampered = original
        .replace(CLAIM_ID, bad_id)
        .replace("tuesday", "friday");
    std::fs::write(wiki.join(format!("projects/{bad_id}.md")), tampered).unwrap();

    let (_, reindex) = zbrain(&fx, &["reindex", "--workspace", "research"]);
    assert!(
        reindex.contains("\"rebuild_state\": \"rejected\""),
        "{reindex}"
    );
    assert!(
        reindex.contains(bad_id),
        "reindex must list the bad claim:\n{reindex}"
    );

    let (ok, after) = ask(&fx);
    assert!(!ok, "ask must fail closed:\n{after}");
    assert_actionable("ask", &after, "todo.md");
    assert!(
        after.contains("1 other invalid trust input"),
        "ask must report the other invalid cause:\n{after}"
    );

    let (_, doctor) = zbrain(&fx, &["doctor", "--workspace", "research"]);
    assert_actionable("doctor", &doctor, "todo.md");
    assert!(
        doctor.contains("1 other invalid trust input"),
        "doctor must report the other invalid cause:\n{doctor}"
    );
    assert!(
        !doctor.contains(
            "\"next_action\": \"move non-claim files out of wiki/, then zbrain reindex\""
        ),
        "doctor must not present moving the file as the whole fix:\n{doctor}"
    );
    assert!(
        doctor.contains("\"next_action\": \"move non-claim files out of wiki/, fix the other invalid trust inputs zbrain reindex lists, then zbrain reindex\""),
        "doctor next_action must name both fixes:\n{doctor}"
    );

    // Moving the note alone leaves the index rejected by the bad claim.
    std::fs::rename(wiki.join("todo.md"), fx.dir.join("todo.md")).unwrap();
    let (_, reindex) = zbrain(&fx, &["reindex", "--workspace", "research"]);
    assert!(
        reindex.contains("\"rebuild_state\": \"rejected\""),
        "{reindex}"
    );
}
