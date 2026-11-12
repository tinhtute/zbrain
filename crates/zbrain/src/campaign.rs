// Port of internal/runtime/campaign.go: resumable bulk authoring of claim
// drafts. It never approves, supersedes, revokes, or reindexes: submission
// reuses the existing claim-draft write path, so every campaign claim is born
// a draft.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::boundary::{path_within, validate_workspace};
use crate::claims::{
    is_claim_id, message, new_claim_id, validate_claim, Claim, ClaimError, ClaimStore,
    CLAIM_STATUS_DRAFT, OKF_CLAIM_TYPE,
};
use crate::clock::{parse_rfc3339, rfc3339, Clock};
use crate::coordination::acquire_workspace_lock;
use crate::paths::{ensure_directory_mode, Paths, RUNTIME_DIRECTORY_MODE};
use crate::transition::recover_pending_transition_for_mutation_unlocked;

/// Resumable authoring run shape. Run files are runtime metadata, never trust
/// inputs: nothing in ask or the derived index reads them, and a malformed run
/// file fails closed instead of discarding resumable work.
pub const CAMPAIGN_SCHEMA_VERSION: &str = "zbrain.campaign/v1";

pub const CAMPAIGN_PHASE_DRAFTING: &str = "drafting";
pub const CAMPAIGN_PHASE_FINISHED: &str = "finished";

pub const CAMPAIGN_DRAFT_STATUS_PENDING: &str = "pending";
pub const CAMPAIGN_DRAFT_STATUS_SUBMITTED: &str = "submitted";
pub const CAMPAIGN_DRAFT_STATUS_SUPERSEDED_BY_OWNER: &str = "superseded-by-owner";

/// One claim draft to author. It carries exactly the fields the existing
/// claim-draft path accepts; the body is supplied at submit time.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignSpec {
    #[serde(default)]
    pub tier: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub basis: String,
    #[serde(default, rename = "evidence", skip_serializing_if = "Vec::is_empty")]
    pub evidence_ids: Vec<String>,
    #[serde(default, rename = "support", skip_serializing_if = "Vec::is_empty")]
    pub supporting_claim_ids: Vec<String>,
    #[serde(
        default,
        rename = "conflicts_with",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub conflicts_with: Vec<String>,
}

/// One ordered entry in a campaign run.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CampaignDraft {
    #[serde(default)]
    pub spec: CampaignSpec,
    #[serde(default)]
    pub status: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub claim_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub submitted_at: String,
}

/// Persisted, resumable campaign run file.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CampaignRun {
    #[serde(default)]
    pub schema: String,
    #[serde(default)]
    pub run_id: String,
    #[serde(default)]
    pub phase: String,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub updated_at: String,
    #[serde(default)]
    pub drafts: Vec<CampaignDraft>,
}

/// Resumable state of a campaign run.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct CampaignState {
    pub run: CampaignRun,
    pub pending: usize,
    pub submitted: usize,
    pub superseded_by_owner: usize,
    pub next_index: i64,
}

/// Reports the claim created by one submitted draft.
#[derive(Debug, Clone, Serialize)]
pub struct CampaignSubmission {
    pub run_id: String,
    pub index: usize,
    pub claim_id: String,
    pub claim_path: String,
    pub claim_status: String,
    pub state: CampaignState,
}

/// Drives resumable bulk authoring of claim drafts.
#[derive(Clone)]
pub struct CampaignStore {
    pub paths: Paths,
    /// Injected clock for deterministic run timestamps; defaults to the
    /// system clock.
    pub now: Option<std::sync::Arc<dyn Clock>>,
}

fn campaign_message(err: impl std::fmt::Display) -> ClaimError {
    message(err.to_string())
}

pub fn new_campaign_run_id() -> Result<String, std::io::Error> {
    Ok("cmp_".to_string() + &crate::claims::random_hex(16)?)
}

fn is_campaign_run_id(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("cmp_") else {
        return false;
    };
    rest.len() == 32
        && rest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl CampaignStore {
    pub fn new(paths: Paths) -> Self {
        Self { paths, now: None }
    }

    pub fn with_clock(paths: Paths, now: std::sync::Arc<dyn Clock>) -> Self {
        Self {
            paths,
            now: Some(now),
        }
    }

    fn now(&self) -> chrono::DateTime<chrono::Utc> {
        match &self.now {
            Some(clock) => clock.now(),
            None => chrono::Utc::now(),
        }
    }

    /// Validates the specs with the claim-draft validators, persists a new
    /// drafting run file, and returns it. No claims are created.
    pub fn begin_campaign(
        &self,
        workspace: &str,
        specs: &[CampaignSpec],
    ) -> Result<CampaignRun, ClaimError> {
        if specs.is_empty() {
            return Err(message("campaign requires at least one draft spec"));
        }
        for (index, spec) in specs.iter().enumerate() {
            validate_campaign_spec(spec)
                .map_err(|err| message(format!("campaign spec {index}: {err}")))?;
        }
        let run_id = new_campaign_run_id().map_err(ClaimError::Io)?;
        let now = rfc3339(self.now());
        let drafts = specs
            .iter()
            .map(|spec| CampaignDraft {
                spec: spec.clone(),
                status: CAMPAIGN_DRAFT_STATUS_PENDING.to_string(),
                ..CampaignDraft::default()
            })
            .collect();
        let run = CampaignRun {
            schema: CAMPAIGN_SCHEMA_VERSION.to_string(),
            run_id,
            phase: CAMPAIGN_PHASE_DRAFTING.to_string(),
            created_at: now.clone(),
            updated_at: now,
            drafts,
        };
        let _lock =
            acquire_workspace_lock(&self.paths, workspace, true).map_err(campaign_message)?;
        self.write_campaign_run_unlocked(workspace, &run)?;
        Ok(run)
    }

    /// Returns the index and spec of the next pending draft in deterministic
    /// order without mutating anything.
    pub fn next_campaign_draft(
        &self,
        workspace: &str,
        run_id: &str,
    ) -> Result<(usize, CampaignSpec), ClaimError> {
        let state = self.resume_campaign(workspace, run_id)?;
        if state.next_index < 0 {
            return Err(message(format!(
                "campaign run {run_id} has no pending drafts"
            )));
        }
        let index = state.next_index as usize;
        Ok((index, state.run.drafts[index].spec.clone()))
    }

    /// Marks the pending draft at index submitted under the workspace lock
    /// and creates the claim through the existing claim-draft write path. An
    /// already-submitted or unknown index fails closed, and the run file is
    /// never advanced when claim creation fails.
    pub fn submit_campaign_draft(
        &self,
        workspace: &str,
        run_id: &str,
        index: i64,
        body: &str,
    ) -> Result<CampaignSubmission, ClaimError> {
        let _lock =
            acquire_workspace_lock(&self.paths, workspace, true).map_err(campaign_message)?;
        let mut run = self.read_campaign_run_unlocked(workspace, run_id)?;
        if run.phase != CAMPAIGN_PHASE_DRAFTING {
            return Err(message(format!(
                "campaign run {run_id} is {}; only drafting runs accept submissions",
                run.phase
            )));
        }
        if index < 0 || index as usize >= run.drafts.len() {
            return Err(message(format!(
                "campaign draft index {index} is out of range for run {run_id}"
            )));
        }
        let index = index as usize;
        if run.drafts[index].status != CAMPAIGN_DRAFT_STATUS_PENDING {
            return Err(message(format!(
                "campaign draft {index} of run {run_id} is {}; only pending drafts can be submitted",
                run.drafts[index].status
            )));
        }
        let claim_id = new_claim_id().map_err(ClaimError::Io)?;
        let claim = Claim {
            claim_type: OKF_CLAIM_TYPE.to_string(),
            id: claim_id,
            tier: run.drafts[index].spec.tier.clone(),
            status: CLAIM_STATUS_DRAFT.to_string(),
            title: run.drafts[index].spec.title.clone(),
            basis: run.drafts[index].spec.basis.clone(),
            created_at: rfc3339(self.now()),
            created_by: "owner:mcp".to_string(),
            evidence_ids: run.drafts[index].spec.evidence_ids.clone(),
            supporting_claim_ids: run.drafts[index].spec.supporting_claim_ids.clone(),
            conflicts_with: run.drafts[index].spec.conflicts_with.clone(),
            body: body.to_string(),
            ..Claim::default()
        };
        let claim_store = ClaimStore {
            paths: self.paths.clone(),
            now: self.now.clone(),
        };
        recover_pending_transition_for_mutation_unlocked(&self.paths, workspace)
            .map_err(campaign_message)?;
        let created = claim_store.write_draft_unlocked(workspace, claim)?;
        run.drafts[index].status = CAMPAIGN_DRAFT_STATUS_SUBMITTED.to_string();
        run.drafts[index].claim_id = created.id.clone();
        run.drafts[index].submitted_at = rfc3339(self.now());
        run.updated_at = run.drafts[index].submitted_at.clone();
        self.write_campaign_run_unlocked(workspace, &run)?;
        let state = campaign_state_from_run(&run);
        Ok(CampaignSubmission {
            run_id: run_id.to_string(),
            index,
            claim_id: created.id.clone(),
            claim_path: crate::claims::claim_rel_path(&created),
            claim_status: created.status,
            state,
        })
    }

    /// Reads and validates a run file and returns its resumable state without
    /// mutating anything.
    pub fn resume_campaign(
        &self,
        workspace: &str,
        run_id: &str,
    ) -> Result<CampaignState, ClaimError> {
        let _lock =
            acquire_workspace_lock(&self.paths, workspace, false).map_err(campaign_message)?;
        let run = self.read_campaign_run_unlocked(workspace, run_id)?;
        Ok(campaign_state_from_run(&run))
    }

    /// Marks a run finished once no pending drafts remain.
    pub fn finish_campaign(
        &self,
        workspace: &str,
        run_id: &str,
    ) -> Result<CampaignRun, ClaimError> {
        let _lock =
            acquire_workspace_lock(&self.paths, workspace, true).map_err(campaign_message)?;
        let mut run = self.read_campaign_run_unlocked(workspace, run_id)?;
        for (index, draft) in run.drafts.iter().enumerate() {
            if draft.status == CAMPAIGN_DRAFT_STATUS_PENDING {
                return Err(message(format!(
                    "campaign run {run_id} still has pending draft {index}; submit every draft before finishing"
                )));
            }
        }
        run.phase = CAMPAIGN_PHASE_FINISHED.to_string();
        run.updated_at = rfc3339(self.now());
        self.write_campaign_run_unlocked(workspace, &run)?;
        Ok(run)
    }

    fn campaign_run_path(&self, workspace: &str, run_id: &str) -> Result<PathBuf, ClaimError> {
        if !is_campaign_run_id(run_id) {
            return Err(message(
                "campaign run id must match cmp_<32 lowercase hex chars>",
            ));
        }
        let root = validate_workspace(&self.paths, workspace).map_err(ClaimError::Boundary)?;
        let directory = root.join("campaigns");
        validate_campaign_directory(&root, &directory)?;
        let path = directory.join(format!("{run_id}.json"));
        crate::approval::validate_workspace_control_file(&path).map_err(ClaimError::Io)?;
        Ok(path)
    }

    /// Loads a run file and fails closed on any malformed shape. A malformed
    /// run file is a hard error that preserves the resumable work on disk:
    /// recovery is an explicit operator decision to remove the file.
    fn read_campaign_run_unlocked(
        &self,
        workspace: &str,
        run_id: &str,
    ) -> Result<CampaignRun, ClaimError> {
        let path = self.campaign_run_path(workspace, run_id)?;
        let contents = std::fs::read(&path).map_err(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                campaign_message(format!(
                    "campaign run {run_id} not found in workspace {workspace:?}"
                ))
            } else {
                ClaimError::Io(err)
            }
        })?;
        let malformed = |cause: String| {
            campaign_message(format!(
                "campaign run file {} is malformed ({cause}); refusing to discard resumable work; remove it explicitly to abandon the run",
                path.display()
            ))
        };
        let run: CampaignRun =
            serde_json::from_slice(&contents).map_err(|err| malformed(err.to_string()))?;
        validate_campaign_run_file(&run, run_id).map_err(|err| malformed(err.to_string()))?;
        Ok(run)
    }

    fn write_campaign_run_unlocked(
        &self,
        workspace: &str,
        run: &CampaignRun,
    ) -> Result<(), ClaimError> {
        validate_campaign_run_file(run, &run.run_id)
            .map_err(|err| message(format!("campaign run {} is invalid: {err}", run.run_id)))?;
        let path = self.campaign_run_path(workspace, &run.run_id)?;
        ensure_directory_mode(
            path.parent().expect("run path has parent"),
            RUNTIME_DIRECTORY_MODE,
        )
        .map_err(|err| message(format!("create campaigns directory: {err}")))?;
        let mut encoded = serde_json::to_vec_pretty(run)
            .map_err(|err| message(format!("marshal campaign run {}: {err}", run.run_id)))?;
        encoded.push(b'\n');
        crate::approval::write_atomic_json(&path, &encoded, &run.run_id, "campaign run")
    }
}

/// Applies the claim-draft validators to a spec without creating any claim.
pub fn validate_campaign_spec(spec: &CampaignSpec) -> Result<(), ClaimError> {
    let probe_id = new_claim_id().map_err(ClaimError::Io)?;
    let probe = Claim {
        claim_type: OKF_CLAIM_TYPE.to_string(),
        id: probe_id,
        tier: spec.tier.clone(),
        status: CLAIM_STATUS_DRAFT.to_string(),
        title: spec.title.clone(),
        basis: spec.basis.clone(),
        created_at: "2026-01-01T00:00:00Z".to_string(),
        created_by: "campaign".to_string(),
        evidence_ids: spec.evidence_ids.clone(),
        supporting_claim_ids: spec.supporting_claim_ids.clone(),
        conflicts_with: spec.conflicts_with.clone(),
        body: "campaign spec".to_string(),
        ..Claim::default()
    };
    validate_claim(&probe)
}

fn campaign_state_from_run(run: &CampaignRun) -> CampaignState {
    let mut state = CampaignState {
        run: run.clone(),
        next_index: -1,
        ..CampaignState::default()
    };
    for (index, draft) in run.drafts.iter().enumerate() {
        match draft.status.as_str() {
            CAMPAIGN_DRAFT_STATUS_PENDING => {
                state.pending += 1;
                if state.next_index < 0 {
                    state.next_index = index as i64;
                }
            }
            CAMPAIGN_DRAFT_STATUS_SUBMITTED => state.submitted += 1,
            CAMPAIGN_DRAFT_STATUS_SUPERSEDED_BY_OWNER => state.superseded_by_owner += 1,
            _ => {}
        }
    }
    state
}

fn validate_campaign_directory(
    root: &std::path::Path,
    directory: &std::path::Path,
) -> Result<(), ClaimError> {
    let info = match std::fs::symlink_metadata(directory) {
        Ok(info) => info,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => return Err(ClaimError::Io(source)),
    };
    if info.file_type().is_symlink() {
        return Err(message("campaigns directory must not be a symlink"));
    }
    if !info.is_dir() {
        return Err(message("campaigns directory is not a directory"));
    }
    let resolved = std::fs::canonicalize(directory).map_err(ClaimError::Io)?;
    let resolved = crate::paths::absolute(&resolved).map_err(ClaimError::Io)?;
    if !path_within(root, &resolved) {
        return Err(message("campaigns directory resolves outside workspace"));
    }
    Ok(())
}

fn validate_campaign_run_file(run: &CampaignRun, expected_run_id: &str) -> Result<(), ClaimError> {
    if run.schema != CAMPAIGN_SCHEMA_VERSION {
        return Err(message(format!(
            "schema {:?} must be {:?}",
            run.schema, CAMPAIGN_SCHEMA_VERSION
        )));
    }
    if !is_campaign_run_id(&run.run_id) || run.run_id != expected_run_id {
        return Err(message(format!(
            "run_id {:?} must match the requested run id {expected_run_id:?}",
            run.run_id
        )));
    }
    match run.phase.as_str() {
        CAMPAIGN_PHASE_DRAFTING | CAMPAIGN_PHASE_FINISHED => {}
        other => return Err(message(format!("phase {other:?} is not supported"))),
    }
    parse_rfc3339(&run.created_at)
        .map_err(|err| message(format!("created_at must be RFC3339: {err}")))?;
    parse_rfc3339(&run.updated_at)
        .map_err(|err| message(format!("updated_at must be RFC3339: {err}")))?;
    if run.drafts.is_empty() {
        return Err(message("campaign run must contain at least one draft"));
    }
    let mut seen_claims = std::collections::HashSet::new();
    let mut pending_seen = false;
    for (index, draft) in run.drafts.iter().enumerate() {
        match draft.status.as_str() {
            CAMPAIGN_DRAFT_STATUS_PENDING => {
                pending_seen = true;
                if !draft.claim_id.is_empty() || !draft.submitted_at.is_empty() {
                    return Err(message(format!(
                        "pending draft {index} must not carry claim or submission metadata"
                    )));
                }
            }
            CAMPAIGN_DRAFT_STATUS_SUBMITTED | CAMPAIGN_DRAFT_STATUS_SUPERSEDED_BY_OWNER => {
                if !is_claim_id(&draft.claim_id) {
                    return Err(message(format!(
                        "draft {index} with status {:?} requires a claim id matching clm_<32 lowercase hex chars>",
                        draft.status
                    )));
                }
                parse_rfc3339(&draft.submitted_at).map_err(|err| {
                    message(format!("draft {index} submitted_at must be RFC3339: {err}"))
                })?;
                if !seen_claims.insert(&draft.claim_id) {
                    return Err(message(format!(
                        "claim id {} is recorded by more than one draft",
                        draft.claim_id
                    )));
                }
            }
            other => {
                return Err(message(format!(
                    "draft {index} status {other:?} is not supported"
                )));
            }
        }
        validate_campaign_spec(&draft.spec)
            .map_err(|err| message(format!("draft {index} spec: {err}")))?;
    }
    if run.phase == CAMPAIGN_PHASE_FINISHED && pending_seen {
        return Err(message(
            "finished campaign run must not contain pending drafts",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests (port of campaign_test.go).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::FixedClock;
    use crate::config::ensure_config;
    use crate::paths::Options;
    use crate::workspace::create_workspace;
    use chrono::{TimeZone, Utc};
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::Arc;

    fn fixed_now() -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 9, 1, 8, 0, 0).unwrap()
    }

    fn fixture(name: &str) -> (PathBuf, Paths, FixedClock) {
        let dir =
            std::env::temp_dir().join(format!("zbrain-campaign-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut paths = Paths::resolve(Options {
            cwd: Some(dir.clone()),
            home_dir: Some(dir.clone()),
            runtime_dir: Some(dir.join(".zbrain")),
        })
        .unwrap();
        paths.key_dir = crate::signing::test_key_dir();
        ensure_config(&paths.config_file).unwrap();
        let clock = FixedClock::new(fixed_now());
        create_workspace(&paths, "research", &clock).unwrap();
        (dir, paths, clock)
    }

    fn store(paths: &Paths, clock: &FixedClock) -> CampaignStore {
        CampaignStore::with_clock(paths.clone(), Arc::new(*clock))
    }

    fn campaign_specs() -> Vec<CampaignSpec> {
        vec![
            CampaignSpec {
                tier: "projects".to_string(),
                title: "Campaign One".to_string(),
                basis: "owner".to_string(),
                ..CampaignSpec::default()
            },
            CampaignSpec {
                tier: "projects".to_string(),
                title: "Campaign Two".to_string(),
                basis: "evidence".to_string(),
                evidence_ids: vec!["evd_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()],
                ..CampaignSpec::default()
            },
        ]
    }

    fn campaign_run_file_path(paths: &Paths, run_id: &str) -> PathBuf {
        paths
            .workspaces_dir
            .join("research/campaigns")
            .join(format!("{run_id}.json"))
    }

    fn require_draft_exists(paths: &Paths, submission: &CampaignSubmission) {
        let claim = ClaimStore::new(paths.clone())
            .read("research", &submission.claim_id)
            .unwrap();
        assert_eq!(claim.status, crate::claims::CLAIM_STATUS_DRAFT);
        assert!(
            claim.verified_at.is_empty()
                && claim.verified_by.is_empty()
                && claim.verified_digest.is_empty()
        );
        assert!(claim.transitions.is_empty());
        assert_eq!(claim.path, submission.claim_path);
    }

    fn read_run_from_disk(paths: &Paths, run_id: &str) -> CampaignRun {
        let contents = std::fs::read(campaign_run_file_path(paths, run_id)).unwrap();
        serde_json::from_slice(&contents).unwrap()
    }

    #[test]
    fn campaign_begin_persists_resumable_run_file() {
        let (dir, paths, _clock) = fixture("begin");
        let store = store(&paths, &FixedClock::new(fixed_now()));
        let run = store.begin_campaign("research", &campaign_specs()).unwrap();
        assert!(is_campaign_run_id(&run.run_id), "{}", run.run_id);
        assert_eq!(run.phase, CAMPAIGN_PHASE_DRAFTING);
        assert_eq!(run.drafts.len(), 2);
        for (index, draft) in run.drafts.iter().enumerate() {
            assert_eq!(draft.status, CAMPAIGN_DRAFT_STATUS_PENDING, "draft {index}");
            assert!(
                draft.claim_id.is_empty() && draft.submitted_at.is_empty(),
                "draft {index}"
            );
        }
        assert_eq!(run.created_at, rfc3339(fixed_now()));
        assert_eq!(run.updated_at, run.created_at);

        let info = std::fs::metadata(campaign_run_file_path(&paths, &run.run_id)).unwrap();
        assert_eq!(info.permissions().mode() & 0o777, 0o600);
        let dir_info = std::fs::metadata(paths.workspaces_dir.join("research/campaigns")).unwrap();
        assert_eq!(dir_info.permissions().mode() & 0o777, 0o700);
        let persisted = read_run_from_disk(&paths, &run.run_id);
        assert_eq!(persisted.run_id, run.run_id);
        assert_eq!(persisted.schema, CAMPAIGN_SCHEMA_VERSION);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn campaign_begin_validates_specs_with_claim_draft_semantics() {
        let (dir, paths, clock) = fixture("beginvalid");
        let store = store(&paths, &clock);
        let invalid = [
            CampaignSpec {
                tier: "not-a-tier".to_string(),
                title: "Bad Tier".to_string(),
                basis: "owner".to_string(),
                ..Default::default()
            },
            CampaignSpec {
                tier: "projects".to_string(),
                title: "Bad Basis".to_string(),
                basis: "guessed".to_string(),
                ..Default::default()
            },
            CampaignSpec {
                tier: "projects".to_string(),
                title: "Bad Evidence".to_string(),
                basis: "evidence".to_string(),
                evidence_ids: vec!["evd_ZZZ".to_string()],
                ..Default::default()
            },
            CampaignSpec {
                tier: "projects".to_string(),
                title: "Bad Support".to_string(),
                basis: "derived".to_string(),
                supporting_claim_ids: vec!["clm_ZZZ".to_string()],
                ..Default::default()
            },
            CampaignSpec {
                tier: "projects".to_string(),
                title: String::new(),
                basis: "owner".to_string(),
                ..Default::default()
            },
        ];
        for (index, spec) in invalid.iter().enumerate() {
            assert!(
                store
                    .begin_campaign("research", std::slice::from_ref(spec))
                    .is_err(),
                "spec {index}"
            );
        }
        assert!(store.begin_campaign("research", &[]).is_err());
        assert!(store.begin_campaign("missing", &campaign_specs()).is_err());
        let campaigns_dir = paths.workspaces_dir.join("research/campaigns");
        let entries = match std::fs::read_dir(&campaigns_dir) {
            Ok(entries) => entries.count(),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => 0,
            Err(source) => panic!("{source}"),
        };
        assert_eq!(entries, 0, "failed begin wrote run files");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn campaign_next_is_deterministic_and_pure() {
        let (dir, paths, clock) = fixture("next");
        let store = store(&paths, &clock);
        let run = store.begin_campaign("research", &campaign_specs()).unwrap();
        let before = std::fs::read(campaign_run_file_path(&paths, &run.run_id)).unwrap();
        for round in 0..2 {
            let (index, spec) = store.next_campaign_draft("research", &run.run_id).unwrap();
            assert_eq!(index, 0, "round {round}");
            assert_eq!(spec.title, "Campaign One", "round {round}");
        }
        let after = std::fs::read(campaign_run_file_path(&paths, &run.run_id)).unwrap();
        assert_eq!(before, after, "next mutated the run file");

        let submission = store
            .submit_campaign_draft("research", &run.run_id, 0, "first body\n")
            .unwrap();
        require_draft_exists(&paths, &submission);
        let (index, spec) = store.next_campaign_draft("research", &run.run_id).unwrap();
        assert_eq!(index, 1);
        assert_eq!(spec.title, "Campaign Two");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn campaign_submit_creates_draft_through_claim_path() {
        let (dir, paths, clock) = fixture("submit");
        let store = store(&paths, &clock);
        let run = store.begin_campaign("research", &campaign_specs()).unwrap();
        let generation_before =
            crate::coordination::ensure_workspace_generation(&paths, "research").unwrap();
        let submission = store
            .submit_campaign_draft("research", &run.run_id, 0, "campaign body\n")
            .unwrap();
        assert_eq!(submission.claim_status, crate::claims::CLAIM_STATUS_DRAFT);
        require_draft_exists(&paths, &submission);
        let generation_after =
            crate::coordination::read_workspace_generation(&paths, "research").unwrap();
        assert_eq!(
            generation_after.published, generation_before.published,
            "campaign submission published the generation"
        );
        assert!(
            generation_after.current > generation_before.current,
            "campaign submission did not advance the canonical generation"
        );
        assert!(
            crate::index::IndexStore::new(paths.clone())
                .dirty_path("research")
                .map(|path| path.exists())
                .unwrap_or(false)
                || std::fs::exists(paths.indexes_dir.join("research.dirty")).unwrap(),
            "campaign submission did not mark the derived index dirty"
        );

        let run_on_disk = read_run_from_disk(&paths, &run.run_id);
        assert_eq!(
            run_on_disk.drafts[0].status,
            CAMPAIGN_DRAFT_STATUS_SUBMITTED
        );
        assert_eq!(run_on_disk.drafts[0].claim_id, submission.claim_id);
        parse_rfc3339(&run_on_disk.drafts[0].submitted_at).unwrap();
        assert_eq!(run_on_disk.drafts[1].status, CAMPAIGN_DRAFT_STATUS_PENDING);
        let _ = std::fs::remove_dir_all(&dir);
        let _ = clock;
    }

    #[test]
    fn campaign_submit_fails_closed() {
        let (dir, paths, clock) = fixture("submitfail");
        let store = store(&paths, &clock);
        let run = store.begin_campaign("research", &campaign_specs()).unwrap();
        store
            .submit_campaign_draft("research", &run.run_id, 0, "body\n")
            .unwrap();
        let before = std::fs::read(campaign_run_file_path(&paths, &run.run_id)).unwrap();

        assert!(store
            .submit_campaign_draft("research", &run.run_id, 0, "again\n")
            .is_err());
        assert!(store
            .submit_campaign_draft("research", &run.run_id, -1, "body\n")
            .is_err());
        assert!(store
            .submit_campaign_draft("research", &run.run_id, 2, "body\n")
            .is_err());
        assert!(store
            .submit_campaign_draft(
                "research",
                "cmp_00000000000000000000000000000000",
                0,
                "body\n"
            )
            .is_err());
        assert!(store
            .submit_campaign_draft("research", "not-a-run-id", 0, "body\n")
            .is_err());
        let after = std::fs::read(campaign_run_file_path(&paths, &run.run_id)).unwrap();
        assert_eq!(before, after, "failed submissions mutated the run file");
        let claims = ClaimStore::new(paths.clone())
            .scan_workspace("research")
            .unwrap();
        let draft_count = claims
            .claims
            .iter()
            .filter(|claim| claim.status == crate::claims::CLAIM_STATUS_DRAFT)
            .count();
        assert_eq!(draft_count, 1, "failed submissions created extra drafts");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn campaign_resume_counts() {
        let (dir, paths, clock) = fixture("resume");
        let store = store(&paths, &clock);
        let run = store.begin_campaign("research", &campaign_specs()).unwrap();
        let state = store.resume_campaign("research", &run.run_id).unwrap();
        assert_eq!(state.pending, 2);
        assert_eq!(state.submitted, 0);
        assert_eq!(state.next_index, 0);
        store
            .submit_campaign_draft("research", &run.run_id, 1, "second body\n")
            .unwrap();
        let state = store.resume_campaign("research", &run.run_id).unwrap();
        assert_eq!(state.pending, 1);
        assert_eq!(state.submitted, 1);
        assert_eq!(state.next_index, 0);
        assert!(store
            .resume_campaign("research", "cmp_00000000000000000000000000000000")
            .is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn campaign_finish_requires_no_pending() {
        let (dir, paths, clock) = fixture("finish");
        let store = store(&paths, &clock);
        let run = store.begin_campaign("research", &campaign_specs()).unwrap();
        assert!(store.finish_campaign("research", &run.run_id).is_err());
        for index in 0..2 {
            store
                .submit_campaign_draft("research", &run.run_id, index, "body\n")
                .unwrap();
        }
        let finished = store.finish_campaign("research", &run.run_id).unwrap();
        assert_eq!(finished.phase, CAMPAIGN_PHASE_FINISHED);
        assert!(store
            .submit_campaign_draft("research", &run.run_id, 0, "late body\n")
            .is_err());
        let state = store.resume_campaign("research", &run.run_id).unwrap();
        assert_eq!(state.pending, 0);
        assert_eq!(state.submitted, 2);
        assert_eq!(state.next_index, -1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn campaign_malformed_run_file_fails_closed() {
        let (dir, paths, clock) = fixture("malformed");
        let store = store(&paths, &clock);
        let run = store.begin_campaign("research", &campaign_specs()).unwrap();
        let path = campaign_run_file_path(&paths, &run.run_id);
        let original = std::fs::read(&path).unwrap();
        let must_json = |value: &serde_json::Value| serde_json::to_vec(value).unwrap();

        let corruptions: Vec<(&str, Vec<u8>)> = vec![
            ("bad json", b"{not json".to_vec()),
            (
                "wrong schema",
                must_json(&serde_json::json!({
                    "schema": "zbrain.campaign/v0", "run_id": run.run_id, "phase": run.phase,
                    "created_at": run.created_at, "updated_at": run.updated_at, "drafts": run.drafts,
                })),
            ),
            (
                "bad phase",
                must_json(&serde_json::json!({
                    "schema": CAMPAIGN_SCHEMA_VERSION, "run_id": run.run_id, "phase": "paused",
                    "created_at": run.created_at, "updated_at": run.updated_at, "drafts": run.drafts,
                })),
            ),
            (
                "bad draft status",
                must_json(&serde_json::json!({
                    "schema": CAMPAIGN_SCHEMA_VERSION, "run_id": run.run_id, "phase": CAMPAIGN_PHASE_DRAFTING,
                    "created_at": run.created_at, "updated_at": run.updated_at,
                    "drafts": [{"spec": run.drafts[0].spec, "status": "approved"}],
                })),
            ),
            (
                "pending with claim",
                must_json(&serde_json::json!({
                    "schema": CAMPAIGN_SCHEMA_VERSION, "run_id": run.run_id, "phase": CAMPAIGN_PHASE_DRAFTING,
                    "created_at": run.created_at, "updated_at": run.updated_at,
                    "drafts": [{"spec": run.drafts[0].spec, "status": CAMPAIGN_DRAFT_STATUS_PENDING,
                                "claim_id": "clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],
                })),
            ),
            (
                "empty drafts",
                must_json(&serde_json::json!({
                    "schema": CAMPAIGN_SCHEMA_VERSION, "run_id": run.run_id, "phase": CAMPAIGN_PHASE_DRAFTING,
                    "created_at": run.created_at, "updated_at": run.updated_at, "drafts": serde_json::Value::Null,
                })),
            ),
        ];
        for (name, contents) in &corruptions {
            std::fs::write(&path, contents).unwrap();
            assert!(
                store.resume_campaign("research", &run.run_id).is_err(),
                "{name}"
            );
            assert!(
                store.next_campaign_draft("research", &run.run_id).is_err(),
                "{name}"
            );
            assert!(
                store
                    .submit_campaign_draft("research", &run.run_id, 0, "body\n")
                    .is_err(),
                "{name}"
            );
            assert!(
                store.finish_campaign("research", &run.run_id).is_err(),
                "{name}"
            );
            let after = std::fs::read(&path).unwrap();
            assert_eq!(&after, contents, "{name}: run file was mutated or reset");
        }

        // A submitted draft without a claim id is malformed, and duplicate
        // claim ids across drafts are malformed.
        let submitted_no_claim = serde_json::json!({
            "schema": CAMPAIGN_SCHEMA_VERSION, "run_id": run.run_id, "phase": CAMPAIGN_PHASE_DRAFTING,
            "created_at": run.created_at, "updated_at": run.updated_at,
            "drafts": [{"spec": run.drafts[0].spec, "status": CAMPAIGN_DRAFT_STATUS_SUBMITTED,
                        "submitted_at": run.created_at}],
        });
        std::fs::write(&path, must_json(&submitted_no_claim)).unwrap();
        assert!(store.resume_campaign("research", &run.run_id).is_err());
        let duplicate_claims = serde_json::json!({
            "schema": CAMPAIGN_SCHEMA_VERSION, "run_id": run.run_id, "phase": CAMPAIGN_PHASE_DRAFTING,
            "created_at": run.created_at, "updated_at": run.updated_at,
            "drafts": [
                {"spec": run.drafts[0].spec, "status": CAMPAIGN_DRAFT_STATUS_SUBMITTED,
                 "claim_id": "clm_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "submitted_at": run.created_at},
                {"spec": run.drafts[1].spec, "status": CAMPAIGN_DRAFT_STATUS_SUBMITTED,
                 "claim_id": "clm_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "submitted_at": run.created_at},
            ],
        });
        std::fs::write(&path, must_json(&duplicate_claims)).unwrap();
        assert!(store.resume_campaign("research", &run.run_id).is_err());
        std::fs::write(&path, &original).unwrap();
        store.resume_campaign("research", &run.run_id).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn campaign_cannot_approve() {
        let (dir, paths, clock) = fixture("cannotapprove");
        let store = store(&paths, &clock);
        let claim_store = ClaimStore::with_clock(paths.clone(), Arc::new(clock));
        crate::index::IndexStore::new(paths.clone())
            .mark_dirty("research")
            .unwrap();
        let mut approved = Claim {
            claim_type: OKF_CLAIM_TYPE.to_string(),
            id: new_claim_id().unwrap(),
            tier: "projects".to_string(),
            status: crate::claims::CLAIM_STATUS_DRAFT.to_string(),
            title: "Approved Baseline".to_string(),
            basis: crate::claims::CLAIM_BASIS_OWNER.to_string(),
            created_at: rfc3339(fixed_now()),
            created_by: "owner".to_string(),
            body: "baseline body\n".to_string(),
            ..Claim::default()
        };
        approved = claim_store.write_draft("research", approved).unwrap();
        approved = claim_store.approve("research", &approved.id).unwrap();
        assert_eq!(approved.status, crate::claims::CLAIM_STATUS_APPROVED);
        let generation_before =
            crate::coordination::ensure_workspace_generation(&paths, "research").unwrap();

        let specs = vec![
            CampaignSpec {
                tier: "projects".to_string(),
                title: "Adversarial Owner".to_string(),
                basis: "owner".to_string(),
                ..Default::default()
            },
            CampaignSpec {
                tier: "projects".to_string(),
                title: "Adversarial Conflicts".to_string(),
                basis: "owner".to_string(),
                conflicts_with: vec![approved.id.clone()],
                ..Default::default()
            },
            CampaignSpec {
                tier: "projects".to_string(),
                title: "Adversarial Support".to_string(),
                basis: "derived".to_string(),
                supporting_claim_ids: vec![approved.id.clone()],
                ..Default::default()
            },
        ];
        let run = store.begin_campaign("research", &specs).unwrap();
        store.next_campaign_draft("research", &run.run_id).unwrap();
        for index in 0..specs.len() {
            store
                .submit_campaign_draft("research", &run.run_id, index as i64, "adversarial body\n")
                .unwrap();
        }
        store.resume_campaign("research", &run.run_id).unwrap();
        store.finish_campaign("research", &run.run_id).unwrap();
        // Every further campaign call on the finished run must fail closed.
        assert!(store.next_campaign_draft("research", &run.run_id).is_err());
        assert!(store
            .submit_campaign_draft("research", &run.run_id, 0, "again\n")
            .is_err());

        let scan = claim_store.scan_workspace("research").unwrap();
        let mut approved_count = 0;
        for claim in &scan.claims {
            if claim.status == crate::claims::CLAIM_STATUS_APPROVED {
                approved_count += 1;
                assert_eq!(claim.id, approved.id, "campaign produced an approved claim");
                assert_eq!(claim.verified_by, approved.verified_by);
                assert_eq!(claim.verified_digest, approved.verified_digest);
                crate::claims::verify_claim_digest(claim).unwrap();
                assert_eq!(claim.transitions.len(), 1);
                assert_eq!(
                    claim.transitions[0].kind,
                    crate::claims::CLAIM_TRANSITION_APPROVE
                );
            } else {
                assert_eq!(
                    claim.status,
                    crate::claims::CLAIM_STATUS_DRAFT,
                    "{}",
                    claim.id
                );
            }
        }
        assert_eq!(approved_count, 1);
        assert_eq!(scan.claims.len(), 4, "workspace claim count");
        let generation_after =
            crate::coordination::read_workspace_generation(&paths, "research").unwrap();
        assert_eq!(
            generation_after.published, generation_before.published,
            "campaign published the generation"
        );

        // The campaigns directory is runtime metadata outside the wiki trust
        // boundary and must never enter the claim scan.
        for claim in &scan.claims {
            assert!(
                !claim.path.starts_with("campaigns/"),
                "campaign run file entered the claim scan at {:?}",
                claim.path
            );
        }

        // The authoring surface must stay drafts-only: no approval, lifecycle,
        // challenge, or reindex references may creep into the module. The scan
        // covers the implementation half only; the test half (below) names the
        // forbidden tokens itself.
        let source = include_str!("campaign.rs")
            .split("// Tests (port of campaign_test.go)")
            .next()
            .unwrap_or_default();
        for forbidden in [
            "net/http",
            "Approve",
            "Revoke",
            "WriteSupersedingDraft",
            "ClaimTransition",
            "ChallengeStore",
            "PrepareChallenge",
            "ApplyChallenge",
            "Rebuild(",
            "VerifiedDigest",
        ] {
            assert!(
                !source.contains(forbidden),
                "campaign.rs must not reference {forbidden:?}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
