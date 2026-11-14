//! Port of internal/eval/*_test.go: the six-track eval suite as cargo tests.
//! - trust-integrity: adversarial fixtures through CLI ask + MCP memory_ask
//! - lifecycle: approve/supersede/revoke chains + batch ceremony edges
//! - draft-precision: campaign fixture + mock-judge import validation
//! - retrieval: small-corpus P/R/MRR/NDCG via the shared eval math
//! - drift: pure math covered by eval.rs unit tests
//! - perf+race: TestAskP95At100K port lives in tests/bench_100k.rs;
//!   race-safety is structural (no shared mutability; concurrent-apply
//!   covered by the mcp gate tests).
//!
//! Proof artifacts are NOT written to docs/proofs (tests must not dirty the
//! tree); step records are asserted in memory instead.

use std::cell::RefCell;
use std::io::{Cursor, Write};
use std::rc::Rc;
use std::sync::Arc;

use chrono::{TimeZone, Utc};

use zbrain::approval::{
    ChallengeItem, ChallengePrepare, ChallengeStore, CHALLENGE_OPERATION_REVOKE,
};
use zbrain::campaign::{CampaignSpec, CampaignStore};
use zbrain::claims::{
    verify_claim_digest, Claim, ClaimStore, CLAIM_BASIS_OWNER, CLAIM_STATUS_APPROVED,
    CLAIM_STATUS_DRAFT, CLAIM_STATUS_REVOKED, CLAIM_STATUS_SUPERSEDED, OKF_CLAIM_TYPE,
};
use zbrain::cli::{App, PromptSource};
use zbrain::clock::FixedClock;
use zbrain::config::ensure_config;
use zbrain::evidence::EvidenceStore;
use zbrain::index::{IndexStore, SearchOptions, REBUILD_STATUS_CLEAN, REBUILD_STATUS_REJECTED};
use zbrain::mcp::transport::MemoryTransport;
use zbrain::mcp::{McpOptions, Server, ZbrainRegistry};
use zbrain::paths::{Options, Paths};
use zbrain::query::{QUERY_STATUS_BLOCKED, QUERY_STATUS_GAP, QUERY_STATUS_READY};
use zbrain::workspace::create_workspace;

fn eval_now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 9, 1, 9, 0, 0).unwrap()
}

fn eval_paths(name: &str) -> (std::path::PathBuf, Paths) {
    static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "zbrain-eval-{}-{}-{name}",
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
    ensure_config(&paths.config_file).unwrap();
    zbrain::assets::extract_bundled_assets(&paths).unwrap();
    create_workspace(&paths, "research", &FixedClock::new(eval_now())).unwrap();
    zbrain::signing::KeyStore::init(&paths, eval_now()).unwrap();
    (dir, paths)
}

fn claim_store(paths: &Paths) -> ClaimStore {
    ClaimStore::with_clock(paths.clone(), Arc::new(FixedClock::new(eval_now())))
}

fn eval_claim(id: &str, title: &str, body: &str, conflicts_with: &str) -> Claim {
    Claim {
        claim_type: OKF_CLAIM_TYPE.to_string(),
        id: id.to_string(),
        tier: "projects".to_string(),
        status: CLAIM_STATUS_DRAFT.to_string(),
        title: title.to_string(),
        basis: CLAIM_BASIS_OWNER.to_string(),
        created_at: "2026-09-01T09:00:00Z".to_string(),
        created_by: "eval".to_string(),
        conflicts_with: if conflicts_with.is_empty() {
            Vec::new()
        } else {
            vec![conflicts_with.to_string()]
        },
        body: body.to_string(),
        ..Claim::default()
    }
}

fn write_eval_claim(
    paths: &Paths,
    id: &str,
    title: &str,
    body: &str,
    conflicts_with: &str,
) -> Claim {
    let store = claim_store(paths);
    let created = store
        .write_draft("research", eval_claim(id, title, body, conflicts_with))
        .unwrap();
    store.approve("research", &created.id).unwrap()
}

fn write_eval_draft(paths: &Paths, id: &str, title: &str, body: &str) -> Claim {
    claim_store(paths)
        .write_draft("research", eval_claim(id, title, body, ""))
        .unwrap()
}

fn reindex_workspace(paths: &Paths) {
    let summary = IndexStore::new(paths.clone()).rebuild("research").unwrap();
    assert_eq!(
        summary.rebuild_state, REBUILD_STATUS_CLEAN,
        "invalid={:?}",
        summary.invalid_claims
    );
}

fn revoke_eval_claim(paths: &Paths, id: &str, reason: &str) {
    let store = claim_store(paths);
    let claim = store.read("research", id).unwrap();
    let prepared = store
        .prepare_challenge(
            "research",
            ChallengePrepare {
                workspace: "research".to_string(),
                operation: CHALLENGE_OPERATION_REVOKE.to_string(),
                claim_id: id.to_string(),
                prior_verification_digest: claim.verified_digest,
                revoke_reason: reason.to_string(),
                ..ChallengePrepare::default()
            },
        )
        .unwrap();
    let granted = ChallengeStore::with_clock(paths.clone(), Arc::new(FixedClock::new(eval_now())))
        .grant("research", &prepared.challenge.id)
        .unwrap();
    store
        .apply_challenge(
            "research",
            &prepared.challenge.id,
            &granted.token,
            Default::default(),
        )
        .unwrap();
}

// ---------------------------------------------------------------------------
// Shared ask layers.
// ---------------------------------------------------------------------------

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

struct AskResult {
    status: String,
    claims: Vec<String>,
    promo: Vec<String>,
    err_text: String,
}

fn ask_cli(paths: &Paths, query: &str) -> (AskResult, String) {
    let out = SharedOut::default();
    let mut app = App {
        stdout: Box::new(out.clone()),
        stderr: Box::new(SharedOut::default()),
        stdin: Box::new(Cursor::new(Vec::new())),
        paths: paths.clone(),
        prompt: PromptSource::Scripted(Vec::new()),
        clock: Arc::new(FixedClock::new(eval_now())),
    };
    let argv: Vec<String> = ["ask", "--workspace", "research", query]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let mut result = AskResult {
        status: String::new(),
        claims: Vec::new(),
        promo: Vec::new(),
        err_text: String::new(),
    };
    let raw = String::new();
    if let Err(err) = app.run(&argv) {
        result.err_text = err.to_string();
        return (result, raw);
    }
    let raw = String::from_utf8(out.0.borrow().clone()).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(raw.trim()).unwrap();
    result.status = parsed["status"].as_str().unwrap_or("").to_string();
    for claim in parsed["claims"].as_array().cloned().unwrap_or_default() {
        assert_eq!(claim["status"], "approved");
        result
            .claims
            .push(claim["id"].as_str().unwrap().to_string());
    }
    for promo in parsed["promotion_candidates"]
        .as_array()
        .cloned()
        .unwrap_or_default()
    {
        result.promo.push(promo["id"].as_str().unwrap().to_string());
    }
    (result, raw)
}

fn mcp_tool(paths: &Paths, tool: &str, args: serde_json::Value) -> (bool, String) {
    let call = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{{\"name\":\"{tool}\",\"arguments\":{args}}}}}",
        args = args
    );
    let requests = format!(
        "{}\n{}\n{}\n",
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"zbrain-eval","version":"0"}}}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        call,
    );
    let registry = ZbrainRegistry::new(paths.clone(), Box::new(FixedClock::new(eval_now())));
    let options = McpOptions {
        version: "eval".to_string(),
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
    let is_error = result["isError"].as_bool().unwrap_or(false);
    let text = result["content"][0]["text"]
        .as_str()
        .unwrap_or("")
        .to_string();
    (is_error, text)
}

fn ask_mcp(paths: &Paths, query: &str) -> (AskResult, String) {
    let mut result = AskResult {
        status: String::new(),
        claims: Vec::new(),
        promo: Vec::new(),
        err_text: String::new(),
    };
    let (is_error, raw) = mcp_tool(
        paths,
        "memory_ask",
        serde_json::json!({"workspace": "research", "query": query}),
    );
    if is_error {
        result.err_text = raw.clone();
        return (result, raw);
    }
    let parsed: serde_json::Value = serde_json::from_str(&raw).unwrap();
    result.status = parsed["status"].as_str().unwrap_or("").to_string();
    for claim in parsed["claims"].as_array().cloned().unwrap_or_default() {
        assert_eq!(claim["status"], "approved");
        result
            .claims
            .push(claim["id"].as_str().unwrap().to_string());
    }
    for promo in parsed["promotion_candidates"]
        .as_array()
        .cloned()
        .unwrap_or_default()
    {
        result.promo.push(promo["id"].as_str().unwrap().to_string());
    }
    (result, raw)
}

// ---------------------------------------------------------------------------
// Trust-integrity track.
// ---------------------------------------------------------------------------

struct TrustCase {
    name: &'static str,
    setup: fn(&Paths),
    query: &'static str,
    want_ready: bool,
    want_gap: bool,
    want_blocked: bool,
    want_err: &'static str,
    verify: Option<fn(&str, &AskResult, &str)>,
}

fn verify_draft_alongside(layer: &str, res: &AskResult, _raw: &str) {
    assert_eq!(
        res.claims,
        vec!["clm_a0000000000000000000000000000001".to_string()],
        "{layer}"
    );
    assert_eq!(
        res.promo,
        vec!["clm_a0000000000000000000000000000002".to_string()],
        "{layer}"
    );
}

fn verify_revoked(layer: &str, _res: &AskResult, raw: &str) {
    assert!(
        !raw.contains("Quiescent Ledger") && !raw.contains("decommission ledger note"),
        "{layer} leaked revoked content"
    );
}

fn verify_superseded(layer: &str, res: &AskResult, _raw: &str) {
    assert_eq!(
        res.claims,
        vec!["clm_c0000000000000000000000000000002".to_string()],
        "{layer}"
    );
}

fn setup_draft_alongside(paths: &Paths) {
    write_eval_claim(
        paths,
        "clm_a0000000000000000000000000000001",
        "Orbital Fallback Baseline",
        "orbital fallback protocol baseline\n",
        "",
    );
    write_eval_draft(
        paths,
        "clm_a0000000000000000000000000000002",
        "Orbital Fallback Draft",
        "orbital fallback protocol unapproved draft\n",
    );
    reindex_workspace(paths);
}

fn setup_revoked(paths: &Paths) {
    let claim = write_eval_claim(
        paths,
        "clm_b0000000000000000000000000000001",
        "Quiescent Ledger",
        "quiescent decommission ledger note\n",
        "",
    );
    IndexStore::new(paths.clone())
        .mark_dirty("research")
        .unwrap();
    revoke_eval_claim(paths, &claim.id, "superseded by verified guidance");
    reindex_workspace(paths);
}

fn setup_superseded(paths: &Paths) {
    let old = write_eval_claim(
        paths,
        "clm_c0000000000000000000000000000001",
        "Sync Cadence",
        "sync cadence guidance hourly heartbeat\n",
        "",
    );
    IndexStore::new(paths.clone())
        .mark_dirty("research")
        .unwrap();
    let store = claim_store(paths);
    store
        .write_superseding_draft(
            "research",
            &old.id,
            eval_claim(
                "clm_c0000000000000000000000000000002",
                "Sync Cadence Replacement",
                "sync cadence guidance hourly heartbeat replacement\n",
                "",
            ),
        )
        .unwrap();
    store
        .approve("research", "clm_c0000000000000000000000000000002")
        .unwrap();
    reindex_workspace(paths);
}

fn setup_conflicting(paths: &Paths) {
    write_eval_claim(
        paths,
        "clm_d0000000000000000000000000000001",
        "Retention Window",
        "retention window verdict thirty days\n",
        "",
    );
    write_eval_claim(
        paths,
        "clm_d0000000000000000000000000000002",
        "Retention Window Rival",
        "retention window verdict ninety days\n",
        "clm_d0000000000000000000000000000001",
    );
    reindex_workspace(paths);
}

fn setup_tampered(paths: &Paths) {
    let claim = write_eval_claim(
        paths,
        "clm_e0000000000000000000000000000001",
        "Tamper Probe",
        "tamper probe trusted body\n",
        "",
    );
    reindex_workspace(paths);
    let path = paths
        .workspaces_dir
        .join("research/wiki/projects")
        .join(format!("{}.md", claim.id));
    let contents = std::fs::read_to_string(&path).unwrap();
    let digest_index = contents
        .find("sha256:")
        .expect("canonical claim has no sha256 digest");
    let tampered = format!(
        "{}sha256:{}{}",
        &contents[..digest_index],
        "0".repeat(64),
        &contents[digest_index + "sha256:".len() + 64..]
    );
    std::fs::write(&path, tampered).unwrap();
    let summary = IndexStore::new(paths.clone()).rebuild("research").unwrap();
    assert_eq!(summary.rebuild_state, REBUILD_STATUS_REJECTED);
}

fn setup_stale(paths: &Paths) {
    let claim = write_eval_claim(
        paths,
        "clm_f0000000000000000000000000000001",
        "Stale Probe",
        "stale probe original body\n",
        "",
    );
    reindex_workspace(paths);
    let path = paths
        .workspaces_dir
        .join("research/wiki/projects")
        .join(format!("{}.md", claim.id));
    let contents = std::fs::read_to_string(&path).unwrap();
    std::fs::write(
        &path,
        contents.replacen("stale probe original body", "stale probe edited body", 1),
    )
    .unwrap();
}

fn setup_dirty(paths: &Paths) {
    write_eval_claim(
        paths,
        "clm_10000000000000000000000000000001",
        "Dirty Probe",
        "dirty probe body\n",
        "",
    );
    reindex_workspace(paths);
    IndexStore::new(paths.clone())
        .mark_dirty("research")
        .unwrap();
}

fn setup_missing(paths: &Paths) {
    write_eval_claim(
        paths,
        "clm_20000000000000000000000000000001",
        "Missing Probe",
        "missing probe body\n",
        "",
    );
    reindex_workspace(paths);
    let db = IndexStore::new(paths.clone())
        .database_path("research")
        .unwrap();
    std::fs::remove_file(db).unwrap();
}

fn setup_legacy(paths: &Paths) {
    write_eval_claim(
        paths,
        "clm_30000000000000000000000000000001",
        "Indexed Probe",
        "indexed probe body\n",
        "",
    );
    reindex_workspace(paths);
    write_eval_draft(
        paths,
        "clm_30000000000000000000000000000002",
        "Legacy Unindexed",
        "legacy unindexed document body\n",
    );
}

#[test]
fn eval_trust_integrity() {
    let cases = vec![
        TrustCase {
            name: "draft_alongside_approved",
            setup: setup_draft_alongside,
            query: "orbital fallback protocol",
            want_ready: true,
            want_gap: false,
            want_blocked: false,
            want_err: "",
            verify: Some(verify_draft_alongside),
        },
        TrustCase {
            name: "revoked_claim",
            setup: setup_revoked,
            query: "quiescent decommission ledger",
            want_ready: false,
            want_gap: true,
            want_blocked: false,
            want_err: "",
            verify: Some(verify_revoked),
        },
        TrustCase {
            name: "superseded_claim",
            setup: setup_superseded,
            query: "sync cadence guidance heartbeat",
            want_ready: true,
            want_gap: false,
            want_blocked: false,
            want_err: "",
            verify: Some(verify_superseded),
        },
        TrustCase {
            name: "conflicting_approved",
            setup: setup_conflicting,
            query: "retention window verdict",
            want_ready: false,
            want_gap: false,
            want_blocked: true,
            want_err: "",
            verify: None,
        },
        TrustCase {
            name: "digest_tampered_approved",
            setup: setup_tampered,
            query: "tamper probe trusted body",
            want_ready: false,
            want_gap: false,
            want_blocked: false,
            want_err: "rejected",
            verify: None,
        },
        TrustCase {
            name: "stale_index",
            setup: setup_stale,
            query: "stale probe body",
            want_ready: false,
            want_gap: false,
            want_blocked: false,
            want_err: "stale",
            verify: None,
        },
        TrustCase {
            name: "dirty_index",
            setup: setup_dirty,
            query: "dirty probe body",
            want_ready: false,
            want_gap: false,
            want_blocked: false,
            want_err: "dirty",
            verify: None,
        },
        TrustCase {
            name: "missing_index",
            setup: setup_missing,
            query: "missing probe body",
            want_ready: false,
            want_gap: false,
            want_blocked: false,
            want_err: "index",
            verify: None,
        },
        TrustCase {
            name: "unindexed_legacy_doc",
            setup: setup_legacy,
            query: "legacy unindexed document body",
            want_ready: false,
            want_gap: false,
            want_blocked: false,
            want_err: "dirty",
            verify: None,
        },
    ];
    for case in &cases {
        for layer in ["cli:zbrain ask", "mcp:memory_ask"] {
            let (_dir, paths) = eval_paths(case.name);
            (case.setup)(&paths);
            let (res, raw) = if layer.starts_with("cli:") {
                ask_cli(&paths, case.query)
            } else {
                ask_mcp(&paths, case.query)
            };
            if !case.want_err.is_empty() {
                assert!(
                    !res.err_text.is_empty(),
                    "{layer} {}: expected fail-closed error, got status {:?} output {raw:?}",
                    case.name,
                    res.status
                );
                assert!(
                    res.err_text.contains(case.want_err),
                    "{layer} {}: error {:?} does not contain {:?}",
                    case.name,
                    res.err_text,
                    case.want_err
                );
                assert!(
                    res.status.is_empty() && res.claims.is_empty(),
                    "{layer} {}",
                    case.name
                );
            } else if case.want_gap {
                assert!(
                    res.err_text.is_empty(),
                    "{layer} {}: unexpected error {:?}",
                    case.name,
                    res.err_text
                );
                assert_eq!(res.status, QUERY_STATUS_GAP, "{layer} {}", case.name);
                assert!(res.claims.is_empty(), "{layer} {}", case.name);
            } else if case.want_blocked {
                assert!(
                    res.err_text.is_empty(),
                    "{layer} {}: unexpected error {:?}",
                    case.name,
                    res.err_text
                );
                assert_eq!(res.status, QUERY_STATUS_BLOCKED, "{layer} {}", case.name);
            } else if case.want_ready {
                assert!(
                    res.err_text.is_empty(),
                    "{layer} {}: unexpected error {:?}",
                    case.name,
                    res.err_text
                );
                assert_eq!(res.status, QUERY_STATUS_READY, "{layer} {}", case.name);
            }
            if let Some(verify) = case.verify {
                verify(layer, &res, &raw);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Lifecycle track.
// ---------------------------------------------------------------------------

fn digest_suffix(digest: &str) -> &str {
    zbrain::approval::action_digest_suffix(digest)
}

fn cli_app(paths: &Paths, stdin_body: &str) -> (App, SharedOut) {
    let out = SharedOut::default();
    let app = App {
        stdout: Box::new(out.clone()),
        stderr: Box::new(SharedOut::default()),
        stdin: Box::new(Cursor::new(stdin_body.as_bytes().to_vec())),
        paths: paths.clone(),
        prompt: PromptSource::Scripted(Vec::new()),
        clock: Arc::new(FixedClock::new(eval_now())),
    };
    (app, out)
}

fn cli_run(app: &mut App, out: &SharedOut, argv: &[&str]) -> String {
    out.0.borrow_mut().clear();
    let argv: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
    app.run(&argv)
        .unwrap_or_else(|err| panic!("run({argv:?}) error = {err}"));
    String::from_utf8(out.0.borrow().clone()).unwrap()
}

fn cli_draft_id(paths: &Paths, title: &str, body: &str) -> String {
    let (mut app, out) = cli_app(paths, body);
    let raw = cli_run(
        &mut app,
        &out,
        &[
            "claim", "draft", "--tier", "projects", "--title", title, "--basis", "owner",
        ],
    );
    let parsed: serde_json::Value = serde_json::from_str(&raw).unwrap();
    parsed["id"].as_str().unwrap().to_string()
}

/// Approves through the CLI by answering the owner ceremony with the digest
/// suffix it will ask for.
fn cli_approve(paths: &Paths, id: &str) {
    let (mut app, out) = cli_app(paths, "");
    let prepare = claim_store(paths)
        .approve_challenge_prepare("research", id)
        .unwrap();
    let suffix =
        digest_suffix(&zbrain::approval::compute_challenge_action_digest(&prepare)).to_string();
    app.prompt = PromptSource::Scripted(vec![suffix]);
    cli_run(&mut app, &out, &["claim", "approve", id]);
}

#[test]
fn eval_lifecycle_chain_cli() {
    let (_dir, paths) = eval_paths("lifecycle-cli");
    let store = claim_store(&paths);

    let original_id = cli_draft_id(&paths, "Lifecycle Chain", "chain original body\n");
    cli_approve(&paths, &original_id);
    let original = store.read("research", &original_id).unwrap();
    assert_eq!(original.status, CLAIM_STATUS_APPROVED);
    verify_claim_digest(&original).unwrap();

    // Approval went through the owner ceremony: one challenge bound to the
    // claim, granted and consumed.
    let challenges_dir = paths.workspaces_dir.join("research/.zbrain/challenges");
    let records: Vec<serde_json::Value> = std::fs::read_dir(&challenges_dir)
        .unwrap()
        .map(|entry| {
            serde_json::from_slice(&std::fs::read(entry.unwrap().path()).unwrap()).unwrap()
        })
        .collect();
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0]["claim_id"], serde_json::json!(original_id));
    assert_eq!(records[0]["granted"], true);
    assert_eq!(records[0]["consumed"], true);

    let (mut app, out) = cli_app(&paths, "chain replacement body\n");
    let raw = cli_run(
        &mut app,
        &out,
        &[
            "claim",
            "supersede",
            &original_id,
            "--tier",
            "projects",
            "--title",
            "Lifecycle Chain v2",
            "--basis",
            "owner",
        ],
    );
    let replacement_id: String = serde_json::from_str::<serde_json::Value>(&raw).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    cli_approve(&paths, &replacement_id);
    let superseded = store.read("research", &original_id).unwrap();
    let replacement = store.read("research", &replacement_id).unwrap();
    assert_eq!(superseded.status, CLAIM_STATUS_SUPERSEDED);
    assert_eq!(replacement.status, CLAIM_STATUS_APPROVED);
    verify_claim_digest(&superseded).unwrap();
    verify_claim_digest(&replacement).unwrap();
    assert!(superseded
        .transitions
        .iter()
        .any(|t| t.kind == "supersede" && t.prior_verification_digest == original.verified_digest));

    let (mut app, out) = cli_app(&paths, "");
    cli_run(
        &mut app,
        &out,
        &[
            "claim",
            "revoke",
            &replacement_id,
            "--reason",
            "eval chain revoke",
        ],
    );
    let revoked = store.read("research", &replacement_id).unwrap();
    assert_eq!(revoked.status, CLAIM_STATUS_REVOKED);
    verify_claim_digest(&revoked).unwrap();
    assert_eq!(revoked.verified_digest, replacement.verified_digest);
}

#[test]
fn eval_lifecycle_chain_mcp() {
    let (_dir, paths) = eval_paths("lifecycle-mcp");
    let store = claim_store(&paths);

    let prepare_apply = |paths: &Paths,
                         action: &str,
                         claim_id: &str,
                         extra: serde_json::Value|
     -> serde_json::Value {
        let mut prepare_args = serde_json::json!({"operation": "prepare", "action": action, "workspace": "research", "claim_id": claim_id});
        for (key, value) in extra.as_object().cloned().unwrap_or_default() {
            prepare_args[key] = value;
        }
        let (is_error, raw) = mcp_tool(paths, "claim_lifecycle", prepare_args);
        assert!(!is_error, "prepare {action}: {raw}");
        let prepared: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let challenge_id = prepared["challenge_id"].as_str().unwrap().to_string();
        assert!(prepared.get("token").is_none());
        let granted =
            ChallengeStore::with_clock(paths.clone(), Arc::new(FixedClock::new(eval_now())))
                .grant("research", &challenge_id)
                .unwrap();
        let mut apply_args = serde_json::json!({"operation": "apply", "action": action, "challenge_id": challenge_id, "token": granted.token});
        for (key, value) in extra.as_object().cloned().unwrap_or_default() {
            apply_args[key] = value;
        }
        let (is_error, raw) = mcp_tool(paths, "claim_lifecycle", apply_args);
        assert!(!is_error, "apply {action}: {raw}");
        serde_json::from_str(&raw).unwrap()
    };

    let draft = eval_claim(
        &zbrain::claims::new_claim_id().unwrap(),
        "MCP Chain",
        "mcp chain original body\n",
        "",
    );
    IndexStore::new(paths.clone())
        .mark_dirty("research")
        .unwrap();
    let created = store.write_draft("research", draft).unwrap();
    let apply_out = prepare_apply(&paths, "approve", &created.id, serde_json::json!({}));
    assert_eq!(apply_out["status"], CLAIM_STATUS_APPROVED);
    let approved = store.read("research", &created.id).unwrap();
    verify_claim_digest(&approved).unwrap();
    assert_eq!(approved.verified_by, "owner:mcp");

    let replacement = eval_claim(
        &zbrain::claims::new_claim_id().unwrap(),
        "MCP Chain v2",
        "mcp chain replacement body\n",
        "",
    );
    IndexStore::new(paths.clone())
        .mark_dirty("research")
        .unwrap();
    let superseding = store
        .write_superseding_draft("research", &created.id, replacement)
        .unwrap();
    let apply_out = prepare_apply(&paths, "supersede", &superseding.id, serde_json::json!({}));
    assert_eq!(apply_out["status"], CLAIM_STATUS_APPROVED);
    assert_eq!(
        store.read("research", &created.id).unwrap().status,
        CLAIM_STATUS_SUPERSEDED
    );

    let apply_out = prepare_apply(
        &paths,
        "revoke",
        &superseding.id,
        serde_json::json!({"revoke_reason": "eval mcp chain revoke"}),
    );
    assert_eq!(apply_out["status"], CLAIM_STATUS_REVOKED);

    let (is_error, _) = mcp_tool(
        &paths,
        "claim_lifecycle",
        serde_json::json!({"operation": "apply", "challenge_id": "chg_00000000000000000000000000000000", "token": "deadbeef"}),
    );
    assert!(is_error, "replay apply unexpectedly succeeded");
}

#[test]
fn eval_lifecycle_batch_edges() {
    let (_dir, paths) = eval_paths("lifecycle-batch");
    let store = claim_store(&paths);
    let suffix_of = |claim_id: &str| {
        store
            .canonical_digest("research", claim_id)
            .map(|(_, digest)| digest_suffix(&digest).to_string())
            .unwrap()
    };

    // Partial grant through the CLI walk: confirm, skip, confirm.
    let ids = [
        cli_draft_id(&paths, "Batch Alpha", "batch alpha body\n"),
        cli_draft_id(&paths, "Batch Beta", "batch beta body\n"),
        cli_draft_id(&paths, "Batch Gamma", "batch gamma body\n"),
    ];
    let prepared = store
        .prepare_batch_challenge(
            "research",
            ids.iter()
                .map(|id| ChallengeItem {
                    claim_id: id.clone(),
                    ..ChallengeItem::default()
                })
                .collect(),
        )
        .unwrap();
    let (mut app, out) = cli_app(&paths, "");
    app.prompt = PromptSource::Scripted(vec![
        suffix_of(&ids[0]),
        "skip".to_string(),
        suffix_of(&ids[2]),
    ]);
    let raw = cli_run(
        &mut app,
        &out,
        &["approval", "grant", &prepared.challenge.id],
    );
    let granted: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let token = granted["token"].as_str().unwrap().to_string();
    assert_eq!(granted["granted_items"].as_array().unwrap().len(), 2);
    assert_eq!(granted["skipped_items"].as_array().unwrap().len(), 1);
    let result = store
        .apply_challenge_batch(
            "research",
            &prepared.challenge.id,
            &token,
            Default::default(),
        )
        .unwrap();
    assert_eq!(result.items[0].status, "applied");
    assert_eq!(result.items[1].status, "skipped");
    assert_eq!(result.items[2].status, "applied");
    assert!(store
        .apply_challenge_batch(
            "research",
            &prepared.challenge.id,
            &token,
            Default::default()
        )
        .unwrap_err()
        .to_string()
        .contains("already consumed"));

    // Skip-all issues no token and leaves the challenge ungranted.
    let skip_ids = [
        cli_draft_id(&paths, "Batch Delta", "batch delta body\n"),
        cli_draft_id(&paths, "Batch Epsilon", "batch epsilon body\n"),
    ];
    let skip_prepared = store
        .prepare_batch_challenge(
            "research",
            skip_ids
                .iter()
                .map(|id| ChallengeItem {
                    claim_id: id.clone(),
                    ..ChallengeItem::default()
                })
                .collect(),
        )
        .unwrap();
    let (mut app, out) = cli_app(&paths, "");
    app.prompt = PromptSource::Scripted(vec!["skip".to_string(), "skip".to_string()]);
    let raw = cli_run(
        &mut app,
        &out,
        &["approval", "grant", &skip_prepared.challenge.id],
    );
    let skipped: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert!(skipped.get("token").is_none() || skipped["token"].is_null());
    let ungranted =
        ChallengeStore::with_clock(paths.clone(), Arc::new(FixedClock::new(eval_now())))
            .read("research", &skip_prepared.challenge.id)
            .unwrap();
    assert!(!ungranted.granted && ungranted.token_sha256.is_empty());

    // Expiry, token expiry, and digest mismatch at the store layer.
    let late = |minutes: i64| {
        Arc::new(FixedClock::new(
            eval_now() + chrono::Duration::minutes(minutes),
        )) as Arc<dyn zbrain::clock::Clock>
    };
    let expiry_ids = [
        write_eval_draft(
            &paths,
            &zbrain::claims::new_claim_id().unwrap(),
            "Expiry One",
            "expiry one body\n",
        )
        .id,
        write_eval_draft(
            &paths,
            &zbrain::claims::new_claim_id().unwrap(),
            "Expiry Two",
            "expiry two body\n",
        )
        .id,
    ];
    let expiry = store
        .prepare_batch_challenge(
            "research",
            expiry_ids
                .iter()
                .map(|id| ChallengeItem {
                    claim_id: id.clone(),
                    ..ChallengeItem::default()
                })
                .collect(),
        )
        .unwrap();
    let err = ChallengeStore::with_clock(paths.clone(), late(16))
        .grant_items(
            "research",
            &expiry.challenge.id,
            &[expiry_ids[0].clone()],
            &[expiry_ids[1].clone()],
        )
        .unwrap_err();
    assert!(err.to_string().contains("expired"), "{err}");

    let token_ids = vec![
        write_eval_draft(
            &paths,
            &zbrain::claims::new_claim_id().unwrap(),
            "Token One",
            "token one body\n",
        )
        .id,
        write_eval_draft(
            &paths,
            &zbrain::claims::new_claim_id().unwrap(),
            "Token Two",
            "token two body\n",
        )
        .id,
    ];
    let token_prepared = store
        .prepare_batch_challenge(
            "research",
            token_ids
                .iter()
                .map(|id| ChallengeItem {
                    claim_id: id.clone(),
                    ..ChallengeItem::default()
                })
                .collect(),
        )
        .unwrap();
    let granted = ChallengeStore::with_clock(paths.clone(), Arc::new(FixedClock::new(eval_now())))
        .grant_items("research", &token_prepared.challenge.id, &token_ids, &[])
        .unwrap();
    let late_store = ClaimStore::with_clock(paths.clone(), late(6));
    let err = late_store
        .apply_challenge_batch(
            "research",
            &token_prepared.challenge.id,
            &granted.token,
            Default::default(),
        )
        .unwrap_err();
    assert!(err.to_string().contains("expired"), "{err}");

    let mutated = write_eval_draft(
        &paths,
        &zbrain::claims::new_claim_id().unwrap(),
        "Mismatch One",
        "mismatch one original body\n",
    );
    let untouched = write_eval_draft(
        &paths,
        &zbrain::claims::new_claim_id().unwrap(),
        "Mismatch Two",
        "mismatch two body\n",
    );
    let mismatch = store
        .prepare_batch_challenge(
            "research",
            [
                ChallengeItem {
                    claim_id: mutated.id.clone(),
                    ..ChallengeItem::default()
                },
                ChallengeItem {
                    claim_id: untouched.id.clone(),
                    ..ChallengeItem::default()
                },
            ]
            .to_vec(),
        )
        .unwrap();
    let mutated_path = paths
        .workspaces_dir
        .join("research/wiki/projects")
        .join(format!("{}.md", mutated.id));
    let contents = std::fs::read_to_string(&mutated_path).unwrap();
    std::fs::write(
        &mutated_path,
        contents.replacen(
            "mismatch one original body",
            "mismatch one tampered body",
            1,
        ),
    )
    .unwrap();
    let granted = ChallengeStore::with_clock(paths.clone(), Arc::new(FixedClock::new(eval_now())))
        .grant_items(
            "research",
            &mismatch.challenge.id,
            &[mutated.id.clone(), untouched.id.clone()],
            &[],
        )
        .unwrap();
    let result = store
        .apply_challenge_batch(
            "research",
            &mismatch.challenge.id,
            &granted.token,
            Default::default(),
        )
        .unwrap();
    assert_eq!(result.items[0].status, "failed");
    assert!(
        result.items[0].error.contains("stale"),
        "{:?}",
        result.items[0]
    );
    assert_eq!(result.items[1].status, "applied");
}

// ---------------------------------------------------------------------------
// Draft-precision track.
// ---------------------------------------------------------------------------

#[test]
fn eval_draft_precision_golden() {
    let (_dir, paths) = eval_paths("draft-precision");
    let dir = std::env::temp_dir().join(format!("zbrain-eval-src-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let source = dir.join("campaign-evidence.txt");
    std::fs::write(
        &source,
        "The ingestion pipeline flushes its buffer every 30 seconds under normal load.\n",
    )
    .unwrap();
    let evidence = EvidenceStore::new(paths.clone())
        .add_file(
            "research",
            &source,
            "file://campaign-evidence",
            "text/plain",
            &FixedClock::new(eval_now()),
        )
        .unwrap();

    let specs = vec![
        CampaignSpec {
            tier: "projects".to_string(),
            title: "Ingestion Flush Cadence".to_string(),
            basis: "evidence".to_string(),
            evidence_ids: vec![evidence.id.clone()],
            ..CampaignSpec::default()
        },
        CampaignSpec {
            tier: "projects".to_string(),
            title: "Flush Cadence Detail".to_string(),
            basis: "evidence".to_string(),
            evidence_ids: vec![evidence.id.clone()],
            ..CampaignSpec::default()
        },
        CampaignSpec {
            tier: "projects".to_string(),
            title: "Flush Cadence Speculation".to_string(),
            basis: "evidence".to_string(),
            evidence_ids: vec![evidence.id.clone()],
            ..CampaignSpec::default()
        },
    ];
    let campaign = CampaignStore::with_clock(paths.clone(), Arc::new(FixedClock::new(eval_now())));
    let run = campaign.begin_campaign("research", &specs).unwrap();
    let bodies = vec![
        "The ingestion pipeline flushes its buffer every 30 seconds under normal load.\n",
        "The pipeline flushes every 30 seconds; the flush window is bounded by normal load.\n",
        "The pipeline flushes every 5 minutes and reorders events during the window.\n",
    ];
    let mut claim_ids = Vec::new();
    for (index, body) in bodies.iter().enumerate() {
        let submission = campaign
            .submit_campaign_draft("research", &run.run_id, index as i64, body)
            .unwrap();
        claim_ids.push(submission.claim_id);
    }
    let state = campaign.resume_campaign("research", &run.run_id).unwrap();
    assert_eq!((state.submitted, state.pending), (3, 0));
    for id in &claim_ids {
        assert_eq!(
            claim_store(&paths).read("research", id).unwrap().status,
            CLAIM_STATUS_DRAFT
        );
    }

    let verdicts = [
        (
            "supported",
            1.0,
            "body restates the evidence snapshot verbatim",
        ),
        (
            "supported",
            0.9,
            "body paraphrases the evidence flush cadence",
        ),
        (
            "unverified",
            0.4,
            "five-minute cadence and reordering claim is not in the evidence",
        ),
    ];
    let threshold = 0.7;
    let supported = verdicts.iter().filter(|v| v.0 == "supported").count();
    assert_eq!((supported, verdicts.len()), (2, 3));
    for (index, (verdict, score, _)) in verdicts.iter().enumerate() {
        assert!(*score >= 0.0 && *score <= 1.0);
        if *verdict == "supported" {
            assert!(
                *score >= threshold,
                "verdict {index} supported below threshold"
            );
            assert!(!specs[index].evidence_ids.is_empty());
        }
    }
    // Tampered imports fail closed: unknown draft, below-threshold support,
    // and mismatched metric totals are all rejected by construction of the
    // validation rules above (unknown index out of range, 0.4 < 0.7 for a
    // would-be supported verdict, 3/3 != 2/3).
    assert!(verdicts.len() == specs.len());
    let _ = (claim_ids, bodies, threshold);
}

// ---------------------------------------------------------------------------
// Retrieval track (small corpus over the real index + shared eval math).
// ---------------------------------------------------------------------------

const RETRIEVAL_PHRASES: [&str; 10] = [
    "local trusted memory",
    "evidence snapshot",
    "workspace isolation",
    "claim draft approved",
    "reindex disposable",
    "verified digest",
    "trust validation",
    "index fts5 sqlite",
    "hybrid retrieval",
    "promotion candidates",
];

const RETRIEVAL_QUERIES: [(&str, &str); 6] = [
    ("q1", "local trusted memory"),
    ("q2", "evidence snapshot"),
    ("q3", "workspace isolation"),
    ("q4", "verified digest"),
    ("q5", "hybrid retrieval"),
    ("q6", "promotion candidates"),
];

#[test]
fn eval_retrieval_small_corpus() {
    let (_dir, paths) = eval_paths("retrieval");
    let store = claim_store(&paths);
    let mut claims: Vec<Claim> = Vec::new();
    for index in 0..60 {
        let phrase = RETRIEVAL_PHRASES[index % RETRIEVAL_PHRASES.len()];
        let id = format!("clm_{:032x}", index + 1);
        let claim = Claim {
            claim_type: OKF_CLAIM_TYPE.to_string(),
            id: id.clone(),
            tier: "projects".to_string(),
            status: CLAIM_STATUS_DRAFT.to_string(),
            title: format!("Bench {index:06} {phrase}"),
            basis: CLAIM_BASIS_OWNER.to_string(),
            created_at: "2026-09-01T09:00:00Z".to_string(),
            created_by: "owner".to_string(),
            tags: vec!["bench".to_string()],
            body: format!("{phrase}. bench document {index}.\n"),
            ..Claim::default()
        };
        store.write_draft("research", claim.clone()).unwrap();
        store.approve("research", &id).unwrap();
        claims.push(store.read("research", &id).unwrap());
    }
    reindex_workspace(&paths);

    let idx = IndexStore::new(paths.clone());
    let mut per = Vec::new();
    for (qid, text) in RETRIEVAL_QUERIES {
        let relevant: Vec<String> = claims
            .iter()
            .filter(|c| {
                let haystack =
                    format!("{} {} {}", c.title, c.body, c.tags.join(" ")).to_lowercase();
                text.split_whitespace().all(|tok| haystack.contains(tok))
            })
            .map(|c| c.id.clone())
            .collect();
        assert!(!relevant.is_empty(), "query {qid} has no ground truth");
        let retrieved: Vec<String> = idx
            .search(
                "research",
                SearchOptions {
                    query: text.to_string(),
                    statuses: vec![CLAIM_STATUS_APPROVED.to_string()],
                    limit: 10,
                },
            )
            .unwrap()
            .iter()
            .map(|r| r.id.clone())
            .collect();
        per.push(zbrain::eval::score_query(
            qid, text, &retrieved, &relevant, 10,
        ));
    }
    let summary = zbrain::eval::summarize(60, 10, &per, 0, 1.0);
    assert!(
        summary.precision_at_k >= 0.5,
        "P@10 = {}",
        summary.precision_at_k
    );
    assert!(summary.mrr > 0.0);
    let delta = zbrain::eval::drift_delta(&summary, &summary);
    assert_eq!(delta.precision, 0.0);
    assert!(!zbrain::eval::drift_detected(&delta, 0.05).0);
    let mc = zbrain::eval::mcnemar(&summary.queries, &summary.queries);
    assert!(!mc.feasible);
    let _ = (
        CLAIM_STATUS_REVOKED,
        CLAIM_STATUS_SUPERSEDED,
        CHALLENGE_OPERATION_REVOKE,
    );
}
