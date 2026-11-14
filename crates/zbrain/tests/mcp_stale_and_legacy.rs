//! End-to-end MCP gateway coverage (JSON-RPC `tools/call`) for two trust
//! behaviors previously tested only through the CLI/library path:
//! `memory_ask` applies `stale_after`, and `memory_reindex` reports
//! `legacy_files` for non-claim Markdown under `wiki/`.

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
use zbrain::mcp::transport::MemoryTransport;
use zbrain::mcp::{McpOptions, Server, ZbrainRegistry};
use zbrain::paths::{Options, Paths};
use zbrain::workspace::create_workspace;

const STALE_ID: &str = "clm_000000000000000000000000000000d1";
const FRESH_ID: &str = "clm_000000000000000000000000000000d2";
const PAST: &str = "2020-01-01T00:00:00Z";
const FUTURE: &str = "2099-01-01T00:00:00Z";

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
        "zbrain-mcp-e2e-{}-{}-{name}",
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
    Fixture { dir, paths }
}

fn store_at(paths: &Paths, at: DateTime<Utc>) -> ClaimStore {
    ClaimStore::with_clock(paths.clone(), Arc::new(FixedClock::new(at)))
}

/// Writes a draft and approves it through the normal signed approval path.
fn approved_claim(paths: &Paths, id: &str, body: &str, stale_after: &str) {
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
        body: body.into(),
        ..Claim::default()
    };
    store_at(paths, at).write_draft("research", claim).unwrap();
    let approved = store_at(paths, at).approve("research", id).unwrap();
    assert_eq!(approved.status, CLAIM_STATUS_APPROVED);
}

/// Drives the real MCP server over an in-memory transport with one
/// `tools/call` and returns the parsed tool-result JSON text.
fn mcp_call(paths: &Paths, tool: &str, arguments: &str) -> serde_json::Value {
    let call = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{{\"name\":\"{tool}\",\"arguments\":{arguments}}}}}"
    );
    let requests = format!(
        "{}\n{}\n{}\n",
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"zbrain-mcp-e2e","version":"0"}}}"#,
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
        version: "mcp-stale-and-legacy".to_string(),
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
        "{tool} failed: {result}"
    );
    serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap()
}

fn ask(paths: &Paths) -> serde_json::Value {
    mcp_call(
        paths,
        "memory_ask",
        r#"{"workspace":"research","query":"oncall rotation"}"#,
    )
}

fn reindex(paths: &Paths) -> serde_json::Value {
    mcp_call(paths, "memory_reindex", r#"{"workspace":"research"}"#)
}

fn claim_ids(result: &serde_json::Value) -> Vec<String> {
    result["claims"]
        .as_array()
        .map(|claims| {
            claims
                .iter()
                .map(|claim| claim["id"].as_str().unwrap().to_string())
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn memory_ask_gaps_on_stale_claim() {
    let fx = fixture("stale");
    approved_claim(&fx.paths, STALE_ID, "oncall rotation alice\n", PAST);
    assert_eq!(reindex(&fx.paths)["rebuild_state"], "clean");

    let result = ask(&fx.paths);
    assert_eq!(
        result["status"], "gap",
        "stale approved claim returned as trusted: {result}"
    );
    assert!(claim_ids(&result).is_empty(), "{result}");
}

#[test]
fn memory_ask_returns_fresh_claim() {
    let fx = fixture("fresh");
    approved_claim(&fx.paths, FRESH_ID, "oncall rotation bob\n", FUTURE);
    assert_eq!(reindex(&fx.paths)["rebuild_state"], "clean");

    let result = ask(&fx.paths);
    assert_eq!(result["status"], "ready", "{result}");
    assert_eq!(claim_ids(&result), vec![FRESH_ID.to_string()]);
}

#[test]
fn memory_ask_drops_only_the_stale_claim() {
    let fx = fixture("mixed");
    approved_claim(&fx.paths, STALE_ID, "oncall rotation alice\n", PAST);
    approved_claim(&fx.paths, FRESH_ID, "oncall rotation bob\n", FUTURE);
    assert_eq!(reindex(&fx.paths)["rebuild_state"], "clean");

    let result = ask(&fx.paths);
    assert_eq!(result["status"], "ready", "{result}");
    assert_eq!(claim_ids(&result), vec![FRESH_ID.to_string()]);
}

#[test]
fn memory_reindex_reports_legacy_files() {
    let fx = fixture("legacy");
    approved_claim(&fx.paths, FRESH_ID, "oncall rotation bob\n", FUTURE);
    let note = fx.paths.workspaces_dir.join("research/wiki/notes/todo.md");
    std::fs::create_dir_all(note.parent().unwrap()).unwrap();
    std::fs::write(&note, "# scratch\nunrelated note\n").unwrap();

    let result = reindex(&fx.paths);
    assert_eq!(result["rebuild_state"], "rejected", "{result}");
    let legacy = result["legacy_files"]
        .as_array()
        .unwrap_or_else(|| panic!("legacy_files missing: {result}"));
    assert_eq!(legacy.len(), 1, "{result}");
    let path = legacy[0]["path"].as_str().unwrap();
    assert!(path.ends_with("notes/todo.md"), "path = {path}");
    let error = legacy[0]["error"].as_str().unwrap();
    assert!(!error.is_empty(), "{result}");
    assert!(
        error.contains("move it out of wiki/ or make it a valid claim"),
        "error = {error}"
    );
}

#[test]
fn memory_reindex_omits_legacy_files_when_clean() {
    let fx = fixture("clean");
    approved_claim(&fx.paths, FRESH_ID, "oncall rotation bob\n", FUTURE);

    let result = reindex(&fx.paths);
    assert_eq!(result["rebuild_state"], "clean", "{result}");
    assert!(
        result.get("legacy_files").is_none(),
        "legacy_files must be omitted: {result}"
    );
}
