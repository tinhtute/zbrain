//! TEMPORARY W2.T2 wire-capture harness (not committed): builds a fixture
//! mirroring the Go capture run and writes the Rust gateway's response
//! frames in the same order as the Go capture sessions.
use std::sync::Arc;

use chrono::{TimeZone, Utc};
use zbrain::claims::{ClaimStore, OKF_CLAIM_TYPE};
use zbrain::clock::{rfc3339, Clock, FixedClock};
use zbrain::config::ensure_config;
use zbrain::evidence::EvidenceStore;
use zbrain::index::IndexStore;
use zbrain::mcp::transport::MemoryTransport;
use zbrain::mcp::{McpOptions, Server, ZbrainRegistry};
use zbrain::paths::{Options, Paths};
use zbrain::workspace::create_workspace;

#[test]
fn capture() {
    let out_path = std::env::temp_dir().join("w2t2_rs_wire.txt");
    let dir = std::env::temp_dir().join("w2t2_rs_fixture");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut paths = Paths::resolve(Options {
        cwd: Some(dir.clone()),
        home_dir: Some(dir.clone()),
        runtime_dir: Some(dir.join(".zbrain")),
    })
    .unwrap();
    paths.key_dir = dir.join("xdg/zbrain-keys");
    ensure_config(&paths.config_file).unwrap();
    // Pinned to the Go fixture's wall-clock stamps (evidence captured_at ==
    // claim generated.at == 2026-09-05T15:07:31Z) so derived digests match.
    let clock = FixedClock::new(Utc.with_ymd_and_hms(2026, 9, 5, 15, 7, 31).unwrap());
    create_workspace(&paths, "research", &clock).unwrap();
    zbrain::signing::KeyStore::init(&paths, clock.now()).unwrap();

    let source = dir.join("source.txt");
    std::fs::write(&source, b"source bytes").unwrap();
    let evidence = EvidenceStore::new(paths.clone())
        .add_file("research", &source, "file://source.txt", "", &clock)
        .unwrap();
    let claim = zbrain::claims::Claim {
        claim_type: OKF_CLAIM_TYPE.to_string(),
        id: zbrain::claims::new_claim_id().unwrap(),
        tier: "projects".to_string(),
        title: "Wire Capture Claim".to_string(),
        basis: zbrain::claims::CLAIM_BASIS_EVIDENCE.to_string(),
        created_at: rfc3339(clock.now()),
        created_by: "owner".to_string(),
        evidence_ids: vec![evidence.id.clone()],
        body: "wire capture body\n".to_string(),
        ..Default::default()
    };
    let index = IndexStore::new(paths.clone());
    index.mark_dirty("research").unwrap();
    let created = ClaimStore::new(paths.clone())
        .write_draft("research", claim)
        .unwrap();
    ClaimStore::with_clock(paths.clone(), Arc::new(FixedClock::new(clock.now())))
        .approve("research", &created.id)
        .unwrap();
    index.rebuild("research").unwrap();

    let tool = |id: i64, name: &str, args: &str| {
        format!(
            r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"{name}","arguments":{args}}}}}"#
        )
    };
    let requests = format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"zbrain-test","version":"0.0.0"}}}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        tool(3, "workspace_current", "{}"),
        tool(4, "memory_ask", r#"{"query":"Wire Capture Claim"}"#),
        tool(5, "memory_ask", r#"{"query":"zzz-unmatchable"}"#),
        tool(6, "memory_status", "{}"),
        tool(7, "memory_reindex", "{}"),
        tool(
            8,
            "claim_draft",
            r#"{"tier":"projects","title":"Captured Draft","basis":"evidence","body":"captured draft body"}"#
        ),
        tool(9, "memory_status", "{}"),
        tool(10, "memory_ask", "{}"),
        tool(
            11,
            "memory_ask",
            r#"{"query":"x","workspace":"nonexistent"}"#
        ),
        tool(
            12,
            "claim_draft",
            r#"{"tier":"projects","title":"t","basis":"weird","body":"b"}"#
        ),
        tool(13, "memory_ask", r#"{"query":"x","after":"bad-timestamp"}"#),
    );
    let registry = ZbrainRegistry::new(paths.clone(), Box::new(FixedClock::new(clock.now())));
    let options = McpOptions {
        version: "test".to_string(),
        ..Default::default()
    };
    let mut server = Server::new(registry, options);
    let mut transport = MemoryTransport::with_requests(requests.into_bytes());
    server.run(&mut transport).unwrap();
    let mut frames: Vec<String> = String::from_utf8(transport.into_writer())
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect();
    // Frame 0 is the initialize result; the Go captures hold only the tool
    // responses, so drop it and keep the 11 tool frames in request order.
    frames.remove(0);
    std::fs::write(&out_path, frames.join("\n") + "\n").unwrap();
    println!("wrote {} ({} frames)", out_path.display(), frames.len());
}
