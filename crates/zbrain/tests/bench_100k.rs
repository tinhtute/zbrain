//! Port of internal/runtime/index_benchmark_test.go (TestAskP95At100K /
//! TestAskP50P95P99), gated behind ZBRAIN_BENCH_100K=1 like the Go oracle.
//!
//! The corpus is generated directly as canonical claim files (digest-finalized
//! approved claims on disk, same final state the claim store produces) so
//! corpus construction is linear; Go's store-based construction is
//! O(n^2)-equivalent in scan work and dominates wall time without touching the
//! measured path (Rebuild + TrustedQuery).
//!
//! The full 100k corpus is the orchestrator's release-gate run; a smaller
//! corpus can be proven locally via ZBRAIN_BENCH_CORPUS (e.g. 10000).

use std::path::PathBuf;
use std::time::Instant;

use chrono::{TimeZone, Utc};
use zbrain::claims::{
    claim_verification_digest, write_claim_atomic, Claim, CLAIM_BASIS_OWNER, CLAIM_STATUS_APPROVED,
    OKF_CLAIM_TYPE,
};
use zbrain::clock::{rfc3339, FixedClock};
use zbrain::config::ensure_config;
use zbrain::index::IndexStore;
use zbrain::paths::Options;
use zbrain::query::{trusted_query, TrustedQueryOptions};
use zbrain::workspace::create_workspace;

fn fixed_bench_now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 7, 30, 10, 0, 0).unwrap()
}

fn bench_claim(index: usize) -> Claim {
    let id = format!("clm_{:032x}", index + 1);
    let mut claim = Claim {
        claim_type: OKF_CLAIM_TYPE.into(),
        id,
        tier: "projects".into(),
        status: CLAIM_STATUS_APPROVED.into(),
        title: format!("Benchmark Claim {:06}", index),
        basis: CLAIM_BASIS_OWNER.into(),
        created_at: rfc3339(fixed_bench_now()),
        created_by: "owner".into(),
        tags: vec!["benchmark".into()],
        body: format!(
            "benchmark corpus body shard {:03} repeated local memory retrieval token\n",
            index % 1000
        ),
        ..Claim::default()
    };
    claim.verified_at = rfc3339(fixed_bench_now());
    claim.verified_by = "owner".into();
    claim.verified_digest = claim_verification_digest(&claim).expect("bench claim digest");
    claim
}

#[test]
fn ask_p95_bench() {
    if std::env::var("ZBRAIN_BENCH_100K").ok().as_deref() != Some("1") {
        eprintln!("skipping: set ZBRAIN_BENCH_100K=1 to run the ask p95 bench");
        return;
    }
    let corpus_size: usize = std::env::var("ZBRAIN_BENCH_CORPUS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(100_000);

    let dir = std::env::temp_dir().join(format!("zbrain-bench-{}-100k", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut paths = zbrain::paths::Paths::resolve(Options {
        cwd: Some(dir.clone()),
        home_dir: Some(dir.clone()),
        runtime_dir: Some(dir.join(".zbrain")),
    })
    .unwrap();
    paths.key_dir = dir.join("xdg/zbrain-keys");
    ensure_config(&paths.config_file).unwrap();
    create_workspace(&paths, "research", &FixedClock::new(fixed_bench_now())).unwrap();
    zbrain::signing::KeyStore::init(&paths, fixed_bench_now()).unwrap();
    let keys = zbrain::signing::KeyStore::open(&paths).unwrap();

    let projects_dir = paths.workspaces_dir.join("research/wiki/projects");
    let build_start = Instant::now();
    for index in 0..corpus_size {
        let mut claim = bench_claim(index);
        zbrain::signing::sign_claim(&mut claim, &keys).expect("sign bench claim");
        let path = projects_dir.join(format!("{}.md", claim.id));
        write_claim_atomic(&path, &claim).expect("write bench claim");
    }
    let build_elapsed = build_start.elapsed();

    let idx = IndexStore::new(paths.clone());
    let index_start = Instant::now();
    idx.rebuild("research").expect("Rebuild");
    let index_elapsed = index_start.elapsed();

    let mut durations: Vec<std::time::Duration> = Vec::with_capacity(40);
    for i in 0..40 {
        let start = Instant::now();
        let response = trusted_query(
            &paths,
            TrustedQueryOptions {
                query: format!("shard {:03} local", i % 1000),
                limit: 10,
                ..TrustedQueryOptions::default()
            },
        )
        .expect("TrustedQuery");
        assert!(
            !response
                .claims
                .as_ref()
                .is_none_or(|claims| claims.is_empty()),
            "TrustedQuery({i}) returned no results"
        );
        durations.push(start.elapsed());
    }
    durations.sort();
    let percentile = |fraction: f64| -> std::time::Duration {
        let index = ((durations.len() as f64) * fraction) as usize;
        durations[index.saturating_sub(1).min(durations.len() - 1)]
    };
    let p50 = percentile(0.50);
    let p95 = percentile(0.95);
    let p99 = percentile(0.99);
    let pass = p95 <= std::time::Duration::from_secs(2);
    println!(
        "bench corpus={corpus_size} p50={p50:?} p95={p95:?} p99={p99:?} samples={}",
        durations.len()
    );
    assert!(pass, "ask p95={p95:?}, want <=2s");

    let ms = |d: std::time::Duration| d.as_micros() as f64 / 1000.0;
    let proof = serde_json::json!({
        "schema": "zbrain.eval.perf-100k/v1",
        "corpus_size": corpus_size,
        "samples": durations.len(),
        "p50_ms": ms(p50),
        "p95_ms": ms(p95),
        "p99_ms": ms(p99),
        "target_p95_s": 2,
        "pass": pass,
        "corpus_build_ms": ms(build_elapsed),
        "index_ms": ms(index_elapsed),
        "engine": "rusqlite bundled FTS5",
    });
    let repo_root = find_repo_root();
    let proofs_dir = repo_root.join("docs/proofs");
    std::fs::create_dir_all(&proofs_dir).unwrap();
    let proof_path = proofs_dir.join("rust-bench-100k.json");
    let mut data = serde_json::to_vec_pretty(&proof).unwrap();
    data.push(b'\n');
    std::fs::write(&proof_path, data).unwrap();
    println!("proof written to {}", proof_path.display());
    let _ = std::fs::remove_dir_all(&dir);
}

fn find_repo_root() -> PathBuf {
    // Integration tests run with cwd = crates/zbrain.
    let root = std::env::current_dir()
        .unwrap()
        .ancestors()
        .find(|ancestor| ancestor.join("docs").exists())
        .expect("repo root with docs/ not found")
        .to_path_buf();
    root
}
