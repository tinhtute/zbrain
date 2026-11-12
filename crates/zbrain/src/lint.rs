// Port of internal/runtime/lint.go: read-only workspace hygiene findings.
// Findings are diagnostic strings only; callers must not rewrite canonical
// files from them.
use std::collections::{BTreeMap, HashSet};

use chrono::{DateTime, Utc};

use crate::boundary::resolve_workspace_path;
use crate::claims::{is_evidence_id, ClaimStore, CLAIM_STATUS_APPROVED};
use crate::evidence::EvidenceStore;
use crate::paths::Paths;

pub fn structural_findings(
    paths: &Paths,
    workspace: &str,
) -> Result<Vec<String>, crate::claims::ClaimError> {
    structural_findings_at(paths, workspace, Utc::now())
}

pub fn structural_findings_at(
    paths: &Paths,
    workspace: &str,
    now: DateTime<Utc>,
) -> Result<Vec<String>, crate::claims::ClaimError> {
    let _lock = crate::coordination::acquire_workspace_lock(paths, workspace, false)
        .map_err(crate::claims::message)?;

    let scan = ClaimStore::new(paths.clone()).scan_workspace(workspace)?;
    let mut claim_ids: HashSet<String> = HashSet::new();
    let mut cited_evidence: HashSet<String> = HashSet::new();
    for claim in &scan.claims {
        claim_ids.insert(claim.id.clone());
        for id in &claim.evidence_ids {
            cited_evidence.insert(id.clone());
        }
        for source in &claim.sources {
            if !source.id.is_empty() {
                cited_evidence.insert(source.id.clone());
            }
        }
    }

    let mut findings: Vec<String> = Vec::new();
    for claim in &scan.claims {
        for id in &claim.supporting_claim_ids {
            if !claim_ids.contains(id) {
                findings.push(format!(
                    "claim {} supporting_claim_ids references missing {id}",
                    claim.id
                ));
            }
        }
        for id in &claim.conflicts_with {
            if !claim_ids.contains(id) {
                findings.push(format!(
                    "claim {} conflicts_with references missing {id}",
                    claim.id
                ));
            }
        }
        for id in &claim.evidence_ids {
            if EvidenceStore::new(paths.clone())
                .read(workspace, id)
                .is_err()
            {
                findings.push(format!(
                    "claim {} evidence_ids references missing {id}",
                    claim.id
                ));
            }
        }
        if claim.status == CLAIM_STATUS_APPROVED && !claim.stale_after.is_empty() {
            if let Ok(stale_after) = crate::clock::parse_rfc3339(&claim.stale_after) {
                if stale_after < now {
                    findings.push(format!(
                        "claim {} stale_after {} is in the past",
                        claim.id, claim.stale_after
                    ));
                }
            }
        }
    }

    for invalid in &scan.invalid {
        findings.push(format!(
            "claim {} is invalid: {}",
            invalid.path, invalid.error
        ));
    }

    let (evidence_ids, sha_by_id) = list_evidence_snapshots(paths, workspace)?;
    for id in &evidence_ids {
        if !cited_evidence.contains(id) {
            findings.push(format!("evidence {id} is not cited by any claim"));
        }
    }
    let mut sha_ids: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (id, sha) in &sha_by_id {
        if sha.is_empty() {
            continue;
        }
        sha_ids.entry(sha.clone()).or_default().push(id.clone());
    }
    let mut hashes: Vec<String> = sha_ids
        .iter()
        .filter(|(_, ids)| ids.len() > 1)
        .map(|(sha, _)| sha.clone())
        .collect();
    hashes.sort();
    for sha in &hashes {
        let mut ids = sha_ids[sha].clone();
        ids.sort();
        findings.push(format!(
            "duplicate sha256 {sha} on evidence {}",
            ids.join(", ")
        ));
    }

    findings.sort();
    Ok(findings)
}

fn list_evidence_snapshots(
    paths: &Paths,
    workspace: &str,
) -> Result<(Vec<String>, std::collections::HashMap<String, String>), crate::claims::ClaimError> {
    let sources_dir = resolve_workspace_path(paths, workspace, "evidence/sources")
        .map_err(crate::claims::message)?;
    let entries = match std::fs::read_dir(&sources_dir) {
        Ok(entries) => entries,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            return Ok((Vec::new(), std::collections::HashMap::new()));
        }
        Err(source) => return Err(source.into()),
    };
    let mut ids: Vec<String> = Vec::new();
    let mut sha_by_id = std::collections::HashMap::new();
    let store = EvidenceStore::new(paths.clone());
    for entry in entries.filter_map(|entry| entry.ok()) {
        let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
        if !is_dir {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if !is_evidence_id(&name) {
            continue;
        }
        ids.push(name.clone());
        if let Ok(evidence) = store.read(workspace, &name) {
            sha_by_id.insert(name, evidence.sha256);
        }
    }
    ids.sort();
    Ok((ids, sha_by_id))
}

// ---------------------------------------------------------------------------
// Tests (port of lint_test.go).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claims::{
        new_claim_id, validate_claim_approval, Claim, CLAIM_BASIS_DERIVED, CLAIM_BASIS_EVIDENCE,
        CLAIM_BASIS_OWNER, CLAIM_STATUS_DRAFT, OKF_CLAIM_TYPE,
    };
    use crate::clock::FixedClock;
    use crate::config::ensure_config;
    use crate::evidence::EvidenceStore;
    use crate::paths::Options;
    use chrono::{TimeZone, Utc};
    use std::path::PathBuf;

    fn fixture(name: &str) -> (PathBuf, Paths, FixedClock) {
        let dir = std::env::temp_dir().join(format!("zbrain-lint-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let paths = Paths::resolve(Options {
            cwd: Some(dir.clone()),
            home_dir: Some(dir.clone()),
            runtime_dir: Some(dir.join(".zbrain")),
        })
        .unwrap();
        ensure_config(&paths.config_file).unwrap();
        let clock = FixedClock::new(Utc.with_ymd_and_hms(2026, 7, 30, 9, 0, 0).unwrap());
        crate::workspace::create_workspace(&paths, "research", &clock).unwrap();
        (dir, paths, clock)
    }

    fn valid_owner_claim() -> Claim {
        Claim {
            claim_type: OKF_CLAIM_TYPE.into(),
            id: "clm_0123456789abcdef0123456789abcdef".into(),
            tier: "projects".into(),
            status: CLAIM_STATUS_DRAFT.into(),
            title: "Owner preference".into(),
            basis: CLAIM_BASIS_OWNER.into(),
            created_at: "2026-07-30T09:00:00Z".into(),
            created_by: "owner".into(),
            body: "Body\n".into(),
            ..Claim::default()
        }
    }

    fn write_draft_claim(paths: &Paths, clock: &FixedClock, mut claim: Claim) -> Claim {
        if claim.id.is_empty() {
            claim.id = new_claim_id().unwrap();
        }
        let store =
            crate::claims::ClaimStore::with_clock(paths.clone(), std::sync::Arc::new(*clock));
        store.write_draft("research", claim).unwrap()
    }

    fn add_evidence(paths: &Paths, clock: &FixedClock, body: &[u8]) -> crate::evidence::Evidence {
        let source = std::env::temp_dir().join(format!(
            "zbrain-lint-source-{}-{}.txt",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::write(&source, body).unwrap();
        EvidenceStore::new(paths.clone())
            .add_file(
                "research",
                &source,
                "file://source.txt",
                "text/plain",
                clock,
            )
            .unwrap()
    }

    #[test]
    fn structural_findings_clean_workspace() {
        let (dir, paths, _clock) = fixture("clean");
        let findings = structural_findings(&paths, "research").unwrap();
        assert!(findings.is_empty(), "{findings:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn structural_findings_dangling_support_and_conflicts() {
        let (dir, paths, clock) = fixture("dangling");
        let missing = "clm_ffffffffffffffffffffffffffffffff";
        let mut claim = valid_owner_claim();
        claim.basis = CLAIM_BASIS_DERIVED.into();
        claim.supporting_claim_ids = vec![missing.into()];
        claim.conflicts_with = vec![missing.into()];
        validate_claim_approval(&claim).unwrap();
        write_draft_claim(&paths, &clock, claim);
        let findings = structural_findings(&paths, "research").unwrap();
        let joined = findings.join("\n");
        assert!(
            joined.contains(&format!(
                "supporting_claim_ids references missing {missing}"
            )),
            "{findings:?}"
        );
        assert!(
            joined.contains(&format!("conflicts_with references missing {missing}")),
            "{findings:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn structural_findings_missing_and_orphan_evidence() {
        let (dir, paths, clock) = fixture("orphanevidence");
        let evidence = add_evidence(&paths, &clock, b"orphan bytes");
        let missing_evidence = "evd_ffffffffffffffffffffffffffffffff";
        let mut claim = valid_owner_claim();
        claim.basis = CLAIM_BASIS_EVIDENCE.into();
        claim.evidence_ids = vec![missing_evidence.into()];
        write_draft_claim(&paths, &clock, claim);
        let findings = structural_findings(&paths, "research").unwrap();
        let joined = findings.join("\n");
        assert!(
            joined.contains(&format!(
                "evidence_ids references missing {missing_evidence}"
            )),
            "{findings:?}"
        );
        assert!(
            joined.contains(&format!(
                "evidence {} is not cited by any claim",
                evidence.id
            )),
            "{findings:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn structural_findings_duplicate_sha256() {
        let (dir, paths, clock) = fixture("dupesha");
        let first = add_evidence(&paths, &clock, b"shared bytes");
        let clone_id = "evd_cccccccccccccccccccccccccccccccc";
        let src_dir = paths
            .workspaces_dir
            .join("research/evidence/sources")
            .join(&first.id);
        let dst_dir = paths
            .workspaces_dir
            .join("research/evidence/sources")
            .join(clone_id);
        std::fs::create_dir_all(&dst_dir).unwrap();
        std::fs::copy(src_dir.join("raw"), dst_dir.join("raw")).unwrap();
        let meta = std::fs::read_to_string(src_dir.join("source.yaml")).unwrap();
        std::fs::write(
            dst_dir.join("source.yaml"),
            meta.replacen(&first.id, clone_id, 1),
        )
        .unwrap();
        let findings = structural_findings(&paths, "research").unwrap();
        let joined = findings.join("\n");
        assert!(
            joined.contains(&format!("duplicate sha256 {} on evidence ", first.sha256))
                && joined.contains(&first.id)
                && joined.contains(clone_id),
            "{findings:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn structural_findings_stale_after() {
        let (dir, paths, clock) = fixture("stale");
        let mut claim = valid_owner_claim();
        claim.stale_after = "2020-01-01T00:00:00Z".into();
        let store =
            crate::claims::ClaimStore::with_clock(paths.clone(), std::sync::Arc::new(clock));
        let draft = store.write_draft("research", claim).unwrap();
        store.approve("research", &draft.id).unwrap();
        let now = Utc.with_ymd_and_hms(2026, 8, 30, 0, 0, 0).unwrap();
        let findings = structural_findings_at(&paths, "research", now).unwrap();
        let joined = findings.join("\n");
        assert!(
            joined.contains(&format!(
                "claim {} stale_after 2020-01-01T00:00:00Z is in the past",
                draft.id
            )),
            "{findings:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
