//! Every trust surface reads claims through one verified path: a claim whose
//! canonical file was tampered after approval is never served as approved
//! (audit 2026-11-09, break 4, repros 08 and 09). Each test drives the surface
//! a user drives — the loopback viewer's HTTP API, the MCP claim resource and
//! `memory_status` tool, and the `status` command — and asserts what that
//! surface shows, not how the read is implemented.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use chrono::{TimeZone, Utc};

use zbrain::assets::extract_bundled_assets;
use zbrain::claims::{
    claim_verification_digest, render_claim_markdown, Claim, ClaimTransition, CLAIM_BASIS_EVIDENCE,
    CLAIM_BASIS_OWNER, CLAIM_STATUS_APPROVED, CLAIM_TRANSITION_APPROVE, OKF_CLAIM_TYPE,
};
use zbrain::clock::{FixedClock, SystemClock};
use zbrain::config::ensure_config;
use zbrain::index::{IndexStore, REBUILD_STATUS_CLEAN};
use zbrain::mcp::{ToolRegistry, ZbrainRegistry};
use zbrain::paths::{Options, Paths};
use zbrain::view::Server as ViewServer;
use zbrain::workspace::create_workspace;

const CONTROL_ID: &str = "clm_00000000000000000000000000000001";
const TAMPERED_ID: &str = "clm_00000000000000000000000000000002";
const BROKEN_CLOSURE_ID: &str = "clm_00000000000000000000000000000003";

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
        "zbrain-trust-{}-{}-{name}",
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
    Fixture { dir, paths }
}

fn approved_claim(id: &str, title: &str, body: &str) -> Claim {
    Claim {
        claim_type: OKF_CLAIM_TYPE.into(),
        id: id.into(),
        tier: "projects".into(),
        status: CLAIM_STATUS_APPROVED.into(),
        title: title.into(),
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
        body: body.into(),
        ..Claim::default()
    }
}

fn claim_path(fx: &Fixture, id: &str) -> PathBuf {
    fx.paths
        .workspaces_dir
        .join("research/wiki/projects")
        .join(format!("{id}.md"))
}

/// Writes the claim the way an approval does: canonical Markdown whose
/// recorded digest covers the approved text.
fn write_claim(fx: &Fixture, claim: &mut Claim) {
    claim.verified_digest = claim_verification_digest(claim).unwrap();
    let keys = zbrain::signing::KeyStore::open(&fx.paths).unwrap();
    zbrain::signing::sign_claim(claim, &keys).unwrap();
    let rendered = render_claim_markdown(claim).unwrap();
    let dir = fx.paths.workspaces_dir.join("research/wiki/projects");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(claim_path(fx, &claim.id), rendered).unwrap();
}

/// Repro 08's tamper step: edit the body after approval, leave the digest.
fn tamper_body(fx: &Fixture, id: &str, from: &str, to: &str) {
    let path = claim_path(fx, id);
    let contents = std::fs::read_to_string(&path).unwrap();
    assert!(contents.contains(from), "tamper target {from:?} missing");
    std::fs::write(&path, contents.replace(from, to)).unwrap();
}

fn rebuild(fx: &Fixture) {
    let summary = IndexStore::new(fx.paths.clone())
        .rebuild("research")
        .unwrap();
    assert_eq!(
        summary.rebuild_state, REBUILD_STATUS_CLEAN,
        "invalid={:?}",
        summary.invalid_claims
    );
}

/// One control claim (untouched) and one claim tampered after approval, in a
/// workspace whose index was clean when the tamper happened.
fn tampered_workspace(name: &str) -> Fixture {
    let fx = fixture(name);
    let mut control = approved_claim(
        CONTROL_ID,
        "Deploy window",
        "the deploy window is tuesday\n",
    );
    let mut tampered = approved_claim(TAMPERED_ID, "Rollback plan", "rollback is manual\n");
    write_claim(&fx, &mut control);
    write_claim(&fx, &mut tampered);
    rebuild(&fx);
    tamper_body(&fx, TAMPERED_ID, "manual", "automatic (tampered)");
    fx
}

fn with_viewer<T>(fx: &Fixture, f: impl FnOnce(&str) -> T) -> T {
    let mut server = ViewServer::new(fx.paths.clone());
    let url = server.listen().unwrap();
    let stop = server.stop_handle();
    let handle = std::thread::spawn(move || server.serve().unwrap());
    let out = f(&url);
    stop.store(true, Ordering::SeqCst);
    handle.join().unwrap();
    out
}

fn http_get(url: &str, path: &str) -> (u16, String) {
    let addr = url.strip_prefix("http://").unwrap();
    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .unwrap();
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut raw = String::new();
    stream.read_to_string(&mut raw).unwrap();
    let status = raw
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    let body = raw.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    (status, body)
}

fn registry(fx: &Fixture) -> ZbrainRegistry {
    ZbrainRegistry::new(fx.paths.clone(), Box::new(SystemClock))
}

fn status_json(fx: &Fixture) -> serde_json::Value {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_zbrain"))
        .env("ZBRAIN_HOME", &fx.paths.runtime_dir)
        .args(["status", "--workspace", "research"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "status failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}

fn assert_tampered_reported_invalid(value: &serde_json::Value) {
    assert_eq!(value["approved"], 1, "approved count: {value}");
    assert_eq!(value["invalid"], 1, "invalid count: {value}");
    let invalid = value["invalid_claims"].as_array().unwrap();
    assert_eq!(invalid.len(), 1, "invalid_claims: {invalid:?}");
    assert_eq!(
        invalid[0]["path"],
        format!("projects/{TAMPERED_ID}.md"),
        "invalid path: {invalid:?}"
    );
    assert!(
        invalid[0]["error"]
            .as_str()
            .unwrap_or_default()
            .contains("verification digest mismatch"),
        "invalid error: {invalid:?}"
    );
    let catalog = value["catalog"].as_array().unwrap();
    assert!(
        catalog.iter().all(|claim| claim["id"] != TAMPERED_ID),
        "catalog served the tampered claim: {catalog:?}"
    );
    assert!(
        catalog.iter().any(|claim| claim["id"] == CONTROL_ID),
        "catalog dropped the untampered claim: {catalog:?}"
    );
}

#[test]
fn viewer_list_omits_tampered_claim() {
    let fx = tampered_workspace("viewer-list");
    let (status, body) = with_viewer(&fx, |url| http_get(url, "/api/claims"));
    assert_eq!(status, 200, "body: {body}");
    assert!(
        !body.contains("automatic (tampered)"),
        "viewer served the tampered body: {body}"
    );
    assert!(
        !body.contains(TAMPERED_ID),
        "viewer served the tampered claim: {body}"
    );
    assert!(
        body.contains(CONTROL_ID),
        "viewer dropped the untampered claim: {body}"
    );
}

#[test]
fn viewer_claim_endpoint_refuses_tampered_claim() {
    let fx = tampered_workspace("viewer-claim");
    let (status, body) = with_viewer(&fx, |url| {
        http_get(url, &format!("/api/claim/{TAMPERED_ID}"))
    });
    assert_eq!(status, 404, "tampered claim body: {body}");
    assert!(
        !body.contains("automatic (tampered)"),
        "viewer served the tampered body: {body}"
    );
    let (status, body) = with_viewer(&fx, |url| {
        http_get(url, &format!("/api/claim/{CONTROL_ID}"))
    });
    assert_eq!(status, 200, "body: {body}");
    assert!(body.contains(CONTROL_ID), "body: {body}");
}

#[test]
fn mcp_claim_resource_refuses_tampered_claim() {
    let fx = tampered_workspace("mcp-resource");
    let registry = registry(&fx);
    let tampered_uri = format!("zbrain://workspace/research/claim/{TAMPERED_ID}");
    assert!(
        registry.read_resource(&tampered_uri).is_none(),
        "MCP resource served the tampered claim"
    );
    let control_uri = format!("zbrain://workspace/research/claim/{CONTROL_ID}");
    let control = registry
        .read_resource(&control_uri)
        .expect("control claim must stay readable");
    assert!(control.contents[0]
        .text
        .as_deref()
        .unwrap_or_default()
        .contains(CONTROL_ID));
}

#[test]
fn status_reports_tampered_claim_as_invalid() {
    let fx = tampered_workspace("status");
    assert_tampered_reported_invalid(&status_json(&fx));
}

#[test]
fn memory_status_reports_tampered_claim_as_invalid() {
    let fx = tampered_workspace("memory-status");
    let result = registry(&fx)
        .call_tool(
            "memory_status",
            Some(&serde_json::json!({"workspace": "research"})),
        )
        .unwrap();
    assert!(!result.is_error, "content: {:?}", result.content);
    let value: serde_json::Value = serde_json::from_str(&result.content[0].text).unwrap();
    assert_tampered_reported_invalid(&value);
}

#[test]
fn viewer_list_omits_claim_with_broken_evidence_closure() {
    let fx = fixture("viewer-closure");
    let mut control = approved_claim(
        CONTROL_ID,
        "Deploy window",
        "the deploy window is tuesday\n",
    );
    write_claim(&fx, &mut control);
    // Digest covers the claim text, so only the evidence closure is broken:
    // the cited snapshot does not exist.
    let mut broken = approved_claim(
        BROKEN_CLOSURE_ID,
        "Vendor SLA",
        "vendor sla is 99.9 percent\n",
    );
    broken.basis = CLAIM_BASIS_EVIDENCE.into();
    broken.evidence_ids = vec!["evd_0000000000000000000000000000dead".into()];
    write_claim(&fx, &mut broken);
    let (status, body) = with_viewer(&fx, |url| http_get(url, "/api/claims"));
    assert_eq!(status, 200, "body: {body}");
    assert!(
        !body.contains(BROKEN_CLOSURE_ID),
        "viewer served a claim with a broken evidence closure: {body}"
    );
    assert!(
        body.contains(CONTROL_ID),
        "viewer dropped the untampered claim: {body}"
    );
}
