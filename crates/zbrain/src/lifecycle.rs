// Port of internal/runtime/lifecycle.go plus the lifecycle half of
// claim_store.go: approve (with verified.at/by/digest), supersede chains (via
// the pending-transition journal), revoke, and OKF migration. The
// challenge-gated entry points (PrepareChallenge/ApplyChallenge[Batch]) stay
// with the approval-campaign phase (m6); these direct owner paths are the
// shareable core.

use serde::Serialize;

use crate::boundary::validate_workspace;
use crate::claims::{
    append_unique_claim_id, claim_verification_digest, message, render_claim_markdown,
    validate_claim_approval, validate_claim_transition_authorization, verify_claim_digest,
    write_claim_atomic, Claim, ClaimError, ClaimSource, ClaimStore, ClaimTransition,
    ClaimTransitionAuthorization, CLAIM_SCHEMA_VERSION, CLAIM_STATUS_APPROVED, CLAIM_STATUS_DRAFT,
    CLAIM_STATUS_REVOKED, CLAIM_STATUS_SUPERSEDED, CLAIM_TRANSITION_APPROVE,
    CLAIM_TRANSITION_REVOKE, CLAIM_TRANSITION_SUPERSEDE, OKF_CLAIM_TYPE,
};
use crate::clock::rfc3339;
use crate::coordination::{
    begin_canonical_mutation_unlocked, run_workspace_generation_test_hook,
    WORKSPACE_GENERATION_HOOK_BEFORE_CANONICAL_WRITE,
};
use crate::evidence::{validate_claim_evidence, EvidenceStore, EvidenceValidator};
use crate::transition::{
    new_pending_transition_id, recover_pending_transition_for_mutation_unlocked,
    recover_pending_transition_unlocked, transition_sha256, write_pending_transition_unlocked,
    PendingTransition, PendingTransitionTarget,
};
use crate::trust::TrustValidator;

/// One approved claim listed by the batch re-sign ceremony.
#[derive(Debug, Clone, Serialize)]
pub struct ResignCandidate {
    pub id: String,
    pub title: String,
    pub verified_at: String,
    pub verified_by: String,
    pub digest: String,
}

/// One claim the owner confirmed in the re-sign ceremony: id, digest, and the
/// `verified.at`/`verified.by` the listing showed. The digest blanks
/// `verified.*`, so those two fields are compared separately; the ceremony
/// signs only exact matches and reports anything else as skipped, never
/// signed unseen.
#[derive(Debug, Clone)]
pub struct ResignTarget {
    pub id: String,
    pub digest: String,
    pub verified_at: String,
    pub verified_by: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResignSkip {
    pub id: String,
    pub reason: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ResignReport {
    pub signed: Vec<String>,
    pub already_signed: Vec<String>,
    pub excluded: Vec<String>,
    pub skipped: Vec<ResignSkip>,
}

/// Provenance for callers that execute a lifecycle transition through a
/// prepared owner challenge. Empty options keep the existing CLI owner
/// provenance and serialized shape.
#[derive(Debug, Clone, Default)]
pub struct ClaimMutationOptions {
    pub verified_by: String,
    pub authorization: Option<ClaimTransitionAuthorization>,
}

impl ClaimMutationOptions {
    fn normalized(self) -> Result<Self, ClaimError> {
        let mut normalized = self;
        if normalized.verified_by.trim().is_empty() {
            normalized.verified_by = "owner".to_string();
        } else {
            normalized.verified_by = normalized.verified_by.trim().to_string();
        }
        validate_claim_transition_authorization(normalized.authorization.as_ref())?;
        Ok(normalized)
    }
}

/// All canonical bytes and validation results needed for one lifecycle
/// mutation. The plan is built before any canonical write and committed
/// afterward while the same workspace lock is held.
pub(crate) struct ClaimMutationPlan {
    pub claim: Claim,
    pub pending: Option<PendingTransition>,
}

fn claim_message(err: impl std::fmt::Display) -> ClaimError {
    message(err.to_string())
}

impl ClaimStore {
    pub fn approve(&self, workspace: &str, id: &str) -> Result<Claim, ClaimError> {
        self.approve_with_options(workspace, id, ClaimMutationOptions::default())
    }

    /// Promotes a draft while preserving the default CLI owner provenance
    /// unless an explicit caller provenance is supplied.
    pub fn approve_with_options(
        &self,
        workspace: &str,
        id: &str,
        options: ClaimMutationOptions,
    ) -> Result<Claim, ClaimError> {
        let _lock = crate::coordination::acquire_workspace_lock(&self.paths, workspace, true)
            .map_err(claim_message)?;
        recover_pending_transition_for_mutation_unlocked(&self.paths, workspace)
            .map_err(claim_message)?;
        let plan = self.prepare_approve_unlocked(workspace, id, options)?;
        self.commit_approve_unlocked(workspace, plan)
    }

    pub(crate) fn prepare_approve_unlocked(
        &self,
        workspace: &str,
        id: &str,
        options: ClaimMutationOptions,
    ) -> Result<ClaimMutationPlan, ClaimError> {
        let normalized_options = options.normalized()?;
        let mut claim = self.read(workspace, id)?;
        if claim.status != CLAIM_STATUS_DRAFT {
            return Err(message(format!(
                "claim {id} is {}; only draft claims can be approved",
                claim.status
            )));
        }
        validate_claim_approval(&claim)?;
        let mut evidence_validator = self.validate_approval_references(workspace, &claim)?;
        let sources =
            self.claim_sources(workspace, &claim.evidence_ids, &mut evidence_validator)?;

        let mut seen_old_ids = std::collections::HashSet::new();
        let mut old_claims: Vec<Claim> = Vec::with_capacity(claim.supersedes.len());
        for old_id in &claim.supersedes {
            if !seen_old_ids.insert(old_id.clone()) {
                return Err(message(format!(
                    "claim {id} supersedes duplicate claim {old_id}"
                )));
            }
            let old = self.read(workspace, old_id)?;
            if old.status != CLAIM_STATUS_APPROVED {
                return Err(message(format!(
                    "claim {old_id} is {}; only approved claims can be superseded",
                    old.status
                )));
            }
            verify_claim_digest(&old)
                .map_err(|err| message(format!("verify superseded claim {old_id}: {err}")))?;
            old_claims.push(old);
        }

        let verified_at = rfc3339(self.now());
        claim.schema = String::new();
        claim.claim_type = OKF_CLAIM_TYPE.to_string();
        claim.status = CLAIM_STATUS_APPROVED.to_string();
        claim.sources = sources;
        claim.verified_at = verified_at.clone();
        claim.verified_by = normalized_options.verified_by.clone();
        claim.verified_digest = String::new();
        let transition_kind = if old_claims.is_empty() {
            CLAIM_TRANSITION_APPROVE
        } else {
            CLAIM_TRANSITION_SUPERSEDE
        };
        claim.transitions.push(ClaimTransition {
            kind: transition_kind.to_string(),
            at: verified_at.clone(),
            by: claim.verified_by.clone(),
            related_claim_ids: claim.supersedes.clone(),
            reason: String::new(),
            prior_verification_digest: String::new(),
            authorization: normalized_options.authorization.clone(),
        });
        let digest = claim_verification_digest(&claim)?;
        claim.verified_digest = digest;
        // The owner ceremony is the only place an approved claim is born:
        // sign the verified block here so every approval path (claim approve,
        // claim_lifecycle apply, supersede) carries a signature. A missing or
        // invalid key fails before the challenge token is consumed.
        let keys = crate::signing::KeyStore::open(&self.paths)
            .map_err(|err| message(format!("approval signing key unavailable: {err}")))?;
        crate::signing::sign_claim(&mut claim, &keys)
            .map_err(|err| message(format!("sign approved claim: {err}")))?;

        for old in &mut old_claims {
            old.status = CLAIM_STATUS_SUPERSEDED.to_string();
            old.transitions.push(ClaimTransition {
                kind: CLAIM_TRANSITION_SUPERSEDE.to_string(),
                at: verified_at.clone(),
                by: claim.verified_by.clone(),
                related_claim_ids: vec![claim.id.clone()],
                prior_verification_digest: old.verified_digest.clone(),
                reason: String::new(),
                authorization: normalized_options.authorization.clone(),
            });
        }
        let pending = if old_claims.is_empty() {
            None
        } else {
            Some(self.pending_supersession(workspace, &claim, &old_claims)?)
        };
        Ok(ClaimMutationPlan { claim, pending })
    }

    pub(crate) fn commit_approve_unlocked(
        &self,
        workspace: &str,
        plan: ClaimMutationPlan,
    ) -> Result<Claim, ClaimError> {
        begin_canonical_mutation_unlocked(&self.paths, workspace).map_err(claim_message)?;
        if let Some(pending) = plan.pending {
            write_pending_transition_unlocked(&self.paths, workspace, pending)
                .map_err(claim_message)?;
            run_workspace_generation_test_hook(WORKSPACE_GENERATION_HOOK_BEFORE_CANONICAL_WRITE);
            recover_pending_transition_unlocked(&self.paths, workspace).map_err(claim_message)?;
            return Ok(plan.claim);
        }
        run_workspace_generation_test_hook(WORKSPACE_GENERATION_HOOK_BEFORE_CANONICAL_WRITE);
        self.write_existing(workspace, &plan.claim)?;
        Ok(plan.claim)
    }

    /// Approved claims the batch re-sign ceremony will walk, in path order.
    pub fn resign_candidates(&self, workspace: &str) -> Result<Vec<ResignCandidate>, ClaimError> {
        let scan = self.scan_workspace_inner(workspace, false)?;
        Ok(scan
            .claims
            .iter()
            .filter(|claim| claim.status == CLAIM_STATUS_APPROVED)
            .map(|claim| ResignCandidate {
                id: claim.id.clone(),
                title: claim.title.clone(),
                verified_at: claim.verified_at.clone(),
                verified_by: claim.verified_by.clone(),
                digest: claim.verified_digest.clone(),
            })
            .collect())
    }

    /// Sign the confirmed `targets` with the active owner key, except
    /// `excludes`. A claim whose current digest differs from the confirmed
    /// one, or that is not in the confirmed list, is skipped and reported.
    /// Re-running is a no-op: a claim already carrying the active key's
    /// signature is reported as already signed and the file is not rewritten.
    pub fn resign_approved(
        &self,
        workspace: &str,
        targets: &[ResignTarget],
        excludes: &[String],
    ) -> Result<ResignReport, ClaimError> {
        let keys = crate::signing::KeyStore::open(&self.paths)
            .map_err(|err| message(format!("approval signing key unavailable: {err}")))?;
        let _lock = crate::coordination::acquire_workspace_lock(&self.paths, workspace, true)
            .map_err(message)?;
        recover_pending_transition_for_mutation_unlocked(&self.paths, workspace)
            .map_err(message)?;
        let scan = self.scan_workspace_inner(workspace, false)?;
        let mut report = ResignReport::default();
        let mut pending: Vec<Claim> = Vec::new();
        for claim in scan
            .claims
            .iter()
            .filter(|claim| claim.status == CLAIM_STATUS_APPROVED)
        {
            if excludes.iter().any(|id| id == &claim.id) {
                report.excluded.push(claim.id.clone());
                continue;
            }
            let Some(target) = targets.iter().find(|target| target.id == claim.id) else {
                report.skipped.push(ResignSkip {
                    id: claim.id.clone(),
                    reason: "not in the confirmed list".to_string(),
                });
                continue;
            };
            if target.digest != claim.verified_digest {
                report.skipped.push(ResignSkip {
                    id: claim.id.clone(),
                    reason: "digest changed since the owner confirmed it".to_string(),
                });
                continue;
            }
            // The digest blanks `verified.*`, so the approval time and
            // approver must be compared on their own: the signature binds
            // whatever values are on disk at signing time.
            if target.verified_at != claim.verified_at || target.verified_by != claim.verified_by {
                report.skipped.push(ResignSkip {
                    id: claim.id.clone(),
                    reason: "approval time or approver changed since the owner confirmed it"
                        .to_string(),
                });
                continue;
            }
            if let Err(err) = verify_claim_digest(claim) {
                report.skipped.push(ResignSkip {
                    id: claim.id.clone(),
                    reason: err.to_string(),
                });
                continue;
            }
            let mut signed = claim.clone();
            crate::signing::sign_claim(&mut signed, &keys)
                .map_err(|err| message(format!("sign claim {}: {err}", claim.id)))?;
            if signed.verified_alg == claim.verified_alg
                && signed.verified_key_id == claim.verified_key_id
                && signed.verified_sig == claim.verified_sig
            {
                report.already_signed.push(claim.id.clone());
                continue;
            }
            pending.push(signed);
        }
        for target in targets {
            let still_approved = scan
                .claims
                .iter()
                .any(|claim| claim.id == target.id && claim.status == CLAIM_STATUS_APPROVED);
            if !still_approved && !report.excluded.contains(&target.id) {
                report.skipped.push(ResignSkip {
                    id: target.id.clone(),
                    reason: "no longer an approved claim".to_string(),
                });
            }
        }
        for id in excludes {
            if !report.excluded.contains(id) {
                report.skipped.push(ResignSkip {
                    id: id.clone(),
                    reason: "no approved claim with this id".to_string(),
                });
            }
        }
        if !pending.is_empty() {
            begin_canonical_mutation_unlocked(&self.paths, workspace).map_err(message)?;
            for claim in &pending {
                self.write_existing(workspace, claim)?;
                report.signed.push(claim.id.clone());
            }
        }
        Ok(report)
    }

    pub fn revoke(&self, workspace: &str, id: &str, reason: &str) -> Result<Claim, ClaimError> {
        self.revoke_with_options(workspace, id, reason, ClaimMutationOptions::default())
    }

    /// Revokes an approved claim while preserving the default CLI owner
    /// provenance unless an explicit caller provenance is supplied.
    pub fn revoke_with_options(
        &self,
        workspace: &str,
        id: &str,
        reason: &str,
        options: ClaimMutationOptions,
    ) -> Result<Claim, ClaimError> {
        let _lock = crate::coordination::acquire_workspace_lock(&self.paths, workspace, true)
            .map_err(claim_message)?;
        recover_pending_transition_for_mutation_unlocked(&self.paths, workspace)
            .map_err(claim_message)?;
        let plan = self.prepare_revoke_unlocked(workspace, id, reason, options)?;
        self.commit_revoke_unlocked(workspace, plan)
    }

    pub(crate) fn prepare_revoke_unlocked(
        &self,
        workspace: &str,
        id: &str,
        reason: &str,
        options: ClaimMutationOptions,
    ) -> Result<ClaimMutationPlan, ClaimError> {
        let normalized_options = options.normalized()?;
        let mut claim = self.read(workspace, id)?;
        if reason.trim().is_empty() {
            return Err(message("revoke reason is required"));
        }
        if claim.status != CLAIM_STATUS_APPROVED {
            return Err(message(format!(
                "claim {id} is {}; only approved claims can be revoked",
                claim.status
            )));
        }
        verify_claim_digest(&claim)
            .map_err(|err| message(format!("verify claim {id} before revoke: {err}")))?;
        claim.status = CLAIM_STATUS_REVOKED.to_string();
        claim.transitions.push(ClaimTransition {
            kind: CLAIM_TRANSITION_REVOKE.to_string(),
            at: rfc3339(self.now()),
            by: normalized_options.verified_by,
            reason: reason.trim().to_string(),
            related_claim_ids: vec![id.to_string()],
            prior_verification_digest: claim.verified_digest.clone(),
            authorization: normalized_options.authorization,
        });
        Ok(ClaimMutationPlan {
            claim,
            pending: None,
        })
    }

    pub(crate) fn commit_revoke_unlocked(
        &self,
        workspace: &str,
        plan: ClaimMutationPlan,
    ) -> Result<Claim, ClaimError> {
        begin_canonical_mutation_unlocked(&self.paths, workspace).map_err(claim_message)?;
        run_workspace_generation_test_hook(WORKSPACE_GENERATION_HOOK_BEFORE_CANONICAL_WRITE);
        self.write_existing(workspace, &plan.claim)?;
        Ok(plan.claim)
    }

    /// Writes a replacement draft bound to supersede an approved claim.
    pub fn write_superseding_draft(
        &self,
        workspace: &str,
        current_id: &str,
        mut replacement: Claim,
    ) -> Result<Claim, ClaimError> {
        let _lock = crate::coordination::acquire_workspace_lock(&self.paths, workspace, true)
            .map_err(claim_message)?;
        recover_pending_transition_for_mutation_unlocked(&self.paths, workspace)
            .map_err(claim_message)?;
        let current = self.read(workspace, current_id)?;
        if current.status != CLAIM_STATUS_APPROVED {
            return Err(message(format!(
                "claim {current_id} is {}; only approved claims can be superseded",
                current.status
            )));
        }
        replacement.supersedes =
            append_unique_claim_id(std::mem::take(&mut replacement.supersedes), current_id);
        self.write_draft_unlocked(workspace, replacement)
    }

    pub(crate) fn write_existing(&self, workspace: &str, claim: &Claim) -> Result<(), ClaimError> {
        let path = self.claim_file_path(workspace, claim)?;
        write_claim_atomic(&path, claim)
    }

    pub(crate) fn pending_supersession(
        &self,
        workspace: &str,
        replacement: &Claim,
        old_claims: &[Claim],
    ) -> Result<PendingTransition, ClaimError> {
        let workspace_root =
            validate_workspace(&self.paths, workspace).map_err(ClaimError::Boundary)?;
        let operation_id = new_pending_transition_id().map_err(ClaimError::Io)?;
        let mut claims: Vec<Claim> = Vec::with_capacity(old_claims.len() + 1);
        claims.push(replacement.clone());
        claims.extend(old_claims.iter().cloned());
        let mut targets = Vec::with_capacity(claims.len());
        for claim in &claims {
            let path = self.claim_file_path(workspace, claim)?;
            let contents = render_claim_markdown(claim)?;
            let preimage = std::fs::read(&path).map_err(|err| {
                message(format!(
                    "read supersession preimage {:?}: {err}",
                    path.display()
                ))
            })?;
            let relative = path
                .strip_prefix(&workspace_root)
                .map_err(message)?
                .to_string_lossy()
                .to_string();
            targets.push(PendingTransitionTarget {
                path: relative,
                preimage_sha256: transition_sha256(&preimage),
                target_sha256: transition_sha256(&contents),
                target_bytes: contents,
            });
        }
        Ok(PendingTransition {
            operation_id,
            kind: CLAIM_TRANSITION_SUPERSEDE.to_string(),
            workspace: workspace.to_string(),
            targets,
        })
    }

    /// Verifies the claim's evidence closure and, when the claim derives from
    /// supporting claims, validates the whole transitive closure against the
    /// same evidence rules.
    pub(crate) fn validate_approval_references(
        &self,
        workspace: &str,
        claim: &Claim,
    ) -> Result<EvidenceValidator, ClaimError> {
        let mut evidence_validator =
            EvidenceValidator::new(self.paths.clone(), workspace).map_err(claim_message)?;
        validate_claim_evidence(&mut evidence_validator, claim)
            .map_err(|err| message(format!("verify claim evidence: {err}")))?;
        if claim.supporting_claim_ids.is_empty() {
            return Ok(evidence_validator);
        }
        let mut validator = TrustValidator::from_store(self, workspace).map_err(claim_message)?;
        validator
            .validate_claim_with_support(claim, &mut |support: &Claim| {
                validate_claim_evidence(&mut evidence_validator, support)
                    .map_err(|err| err.to_string())
            })
            .map_err(|err| {
                message(format!(
                    "validate supporting claims for {}: {err}",
                    claim.id
                ))
            })?;
        Ok(evidence_validator)
    }

    pub(crate) fn claim_sources(
        &self,
        workspace: &str,
        evidence_ids: &[String],
        validator: &mut EvidenceValidator,
    ) -> Result<Vec<ClaimSource>, ClaimError> {
        let mut sources = Vec::with_capacity(evidence_ids.len());
        let evidence_store = EvidenceStore::new(self.paths.clone());
        for evidence_id in evidence_ids {
            let evidence = evidence_store
                .read(workspace, evidence_id)
                .map_err(claim_message)?;
            validator
                .verify(evidence_id)
                .map_err(|verification| ClaimError::Message(verification.to_string()))?;
            sources.push(ClaimSource {
                id: evidence.id.clone(),
                resource: format!("evidence/sources/{}/raw", evidence.id),
                title: evidence.origin,
                digest: validator
                    .snapshot_digest(evidence_id)
                    .cloned()
                    .unwrap_or_default(),
                spans: Vec::new(),
            });
        }
        Ok(sources)
    }

    /// Migrates legacy `schema: zbrain.claim/v1` claims to the OKF envelope.
    /// Approved claims with valid OKF digests are preserved byte-for-byte;
    /// approved claims that cannot be re-verified are demoted to draft and
    /// reported as re-approval candidates.
    pub fn migrate_okf(&self, workspace: &str) -> Result<ClaimMigrationSummary, ClaimError> {
        let _lock = crate::coordination::acquire_workspace_lock(&self.paths, workspace, true)
            .map_err(claim_message)?;
        recover_pending_transition_for_mutation_unlocked(&self.paths, workspace)
            .map_err(claim_message)?;
        let scan = self.scan_workspace_inner(workspace, false)?;
        let mut summary = ClaimMigrationSummary {
            workspace: workspace.to_string(),
            migrated: 0,
            skipped: scan.legacy_unindexed.len(),
            invalid: scan.invalid.len(),
            reapproval_required: 0,
            reapproval_candidates: Vec::new(),
        };
        let mut migrated: Vec<Claim> = Vec::new();
        for claim in &scan.claims {
            if claim.schema != CLAIM_SCHEMA_VERSION {
                if claim.status == CLAIM_STATUS_APPROVED && verify_claim_digest(claim).is_err() {
                    summary.invalid += 1;
                }
                summary.skipped += 1;
                continue;
            }
            let (claim, requires_reapproval) = migrate_legacy_claim(claim);
            if requires_reapproval {
                summary.reapproval_required += 1;
                summary.reapproval_candidates.push(claim.id.clone());
            }
            migrated.push(claim);
        }
        if migrated.is_empty() {
            return Ok(summary);
        }
        begin_canonical_mutation_unlocked(&self.paths, workspace).map_err(claim_message)?;
        run_workspace_generation_test_hook(WORKSPACE_GENERATION_HOOK_BEFORE_CANONICAL_WRITE);
        for claim in &migrated {
            self.write_existing(workspace, claim)?;
            summary.migrated += 1;
        }
        Ok(summary)
    }

    /// Digest of the current canonical claim after resolving it under the
    /// workspace read lock.
    pub fn canonical_digest(
        &self,
        workspace: &str,
        id: &str,
    ) -> Result<(Claim, String), ClaimError> {
        let _lock = crate::coordination::acquire_workspace_lock(&self.paths, workspace, false)
            .map_err(claim_message)?;
        self.canonical_digest_unlocked(workspace, id)
    }

    pub(crate) fn canonical_digest_unlocked(
        &self,
        workspace: &str,
        id: &str,
    ) -> Result<(Claim, String), ClaimError> {
        let claim = self.read(workspace, id)?;
        let digest = crate::claims::claim_canonical_digest(&claim)
            .map_err(|err| message(format!("compute canonical claim digest: {err}")))?;
        Ok((claim, digest))
    }
}

fn migrate_legacy_claim(claim: &Claim) -> (Claim, bool) {
    let mut claim = claim.clone();
    claim.schema = String::new();
    claim.claim_type = OKF_CLAIM_TYPE.to_string();
    if claim.status != CLAIM_STATUS_APPROVED {
        return (claim, false);
    }
    if verify_claim_digest(&claim).is_ok() {
        return (claim, false);
    }
    claim.status = CLAIM_STATUS_DRAFT.to_string();
    claim.verified_at = String::new();
    claim.verified_by = String::new();
    claim.verified_digest = String::new();
    (claim, true)
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ClaimMigrationSummary {
    pub workspace: String,
    pub migrated: usize,
    pub skipped: usize,
    pub invalid: usize,
    pub reapproval_required: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub reapproval_candidates: Vec<String>,
}

// ---------------------------------------------------------------------------
// Tests (port of the lifecycle subset of claim_store_test.go).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claims::{CLAIM_BASIS_DERIVED, CLAIM_BASIS_EVIDENCE, CLAIM_BASIS_OWNER};
    use crate::clock::FixedClock;
    use crate::config::ensure_config;
    use crate::evidence::{evidence_snapshot_digest, Evidence};
    use crate::paths::Options;
    use crate::paths::Paths;
    use chrono::{TimeZone, Utc};
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    fn fixed_now() -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 30, 9, 0, 0).unwrap()
    }

    fn fixture(name: &str) -> (PathBuf, Paths, FixedClock) {
        let dir =
            std::env::temp_dir().join(format!("zbrain-lifecycle-{}-{name}", std::process::id()));
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
        crate::workspace::create_workspace(&paths, "research", &clock).unwrap();
        (dir, paths, clock)
    }

    fn store(paths: &Paths, clock: &FixedClock) -> ClaimStore {
        ClaimStore::with_clock(paths.clone(), Arc::new(*clock))
    }

    fn valid_store_claim(id: &str, basis: &str) -> Claim {
        Claim {
            claim_type: OKF_CLAIM_TYPE.to_string(),
            id: id.to_string(),
            tier: "projects".to_string(),
            status: CLAIM_STATUS_DRAFT.to_string(),
            title: "Store claim".to_string(),
            basis: basis.to_string(),
            created_at: "2026-07-30T09:00:00Z".to_string(),
            created_by: "owner".to_string(),
            body: "Store body\n".to_string(),
            ..Claim::default()
        }
    }

    fn approval_test_claim_id(number: u32) -> String {
        format!("clm_{number:032x}")
    }

    fn finalize_approved_claim(claim: &Claim) -> Claim {
        let mut approved = claim.clone();
        approved.status = CLAIM_STATUS_APPROVED.to_string();
        approved.verified_at = "2026-07-30T09:00:00Z".to_string();
        approved.verified_by = "owner".to_string();
        approved.verified_digest = String::new();
        approved.verified_digest = claim_verification_digest(&approved).unwrap();
        crate::signing::sign_test_claim(&mut approved);
        approved
    }

    fn write_canonical_claim(paths: &Paths, claim: &Claim) {
        let path = paths
            .workspaces_dir
            .join("research/wiki")
            .join(&claim.tier)
            .join(format!("{}.md", claim.id));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        write_claim_atomic(&path, claim).unwrap();
    }

    fn sha256_file(path: &Path) -> String {
        use sha2::{Digest as _, Sha256};
        let mut hash = Sha256::new();
        hash.update(std::fs::read(path).unwrap());
        hash.finalize().iter().map(|b| format!("{b:02x}")).collect()
    }

    fn add_store_evidence(paths: &Paths, clock: &FixedClock, body: &[u8]) -> Evidence {
        let source = std::env::temp_dir().join(format!(
            "zbrain-lifecycle-source-{}-{}.txt",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::write(&source, body).unwrap();
        let store = crate::evidence::EvidenceStore::new(paths.clone());
        store
            .add_file(
                "research",
                &source,
                "file://source.txt",
                "text/plain",
                clock,
            )
            .unwrap()
    }

    fn evidence_raw_path(paths: &Paths, evidence: &Evidence) -> PathBuf {
        paths
            .workspaces_dir
            .join("research/evidence/sources")
            .join(&evidence.id)
            .join("raw")
    }

    fn pending_transition_path(paths: &Paths) -> PathBuf {
        crate::transition::pending_transition_path(paths, "research").unwrap()
    }

    fn authorization(id: &str) -> Option<ClaimTransitionAuthorization> {
        Some(ClaimTransitionAuthorization {
            challenge_id: id.to_string(),
            method: "claim_lifecycle.apply".to_string(),
            mcp_client: "mcp-client/1.0".to_string(),
        })
    }

    #[test]
    fn claim_store_draft_approve_supersede_revoke() {
        let (dir, paths, clock) = fixture("chain");
        let store = store(&paths, &clock);
        let draft = valid_store_claim("clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", CLAIM_BASIS_OWNER);
        let created = store.write_draft("research", draft.clone()).unwrap();
        assert_eq!(created.status, CLAIM_STATUS_DRAFT);
        assert_eq!(
            created.path,
            "projects/clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.md"
        );

        let approved = store.approve("research", &draft.id).unwrap();
        assert_eq!(approved.status, CLAIM_STATUS_APPROVED);
        assert!(!approved.verified_at.is_empty());
        assert_eq!(approved.verified_by, "owner");
        assert!(approved.verified_digest.starts_with("sha256:"));

        let mut replacement =
            valid_store_claim("clm_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", CLAIM_BASIS_OWNER);
        replacement.body = "Replacement body\n".to_string();
        let superseding = store
            .write_superseding_draft("research", &approved.id, replacement.clone())
            .unwrap();
        assert_eq!(superseding.supersedes, vec![approved.id.clone()]);

        let approved_replacement = store.approve("research", &replacement.id).unwrap();
        let old = store.read("research", &approved.id).unwrap();
        assert_eq!(old.status, CLAIM_STATUS_SUPERSEDED);
        assert_eq!(approved_replacement.status, CLAIM_STATUS_APPROVED);

        let prior_digest = approved_replacement.verified_digest.clone();
        let revoked = store
            .revoke("research", &approved_replacement.id, "wrong scope")
            .unwrap();
        assert_eq!(revoked.status, CLAIM_STATUS_REVOKED);
        assert_eq!(revoked.body, replacement.body);
        assert_eq!(revoked.verified_digest, prior_digest);
        assert_eq!(revoked.transitions.len(), 2);
        assert_eq!(revoked.transitions[1].kind, CLAIM_TRANSITION_REVOKE);
        assert_eq!(revoked.transitions[1].reason, "wrong scope");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn approve_transition_graph() {
        let (dir, paths, clock) = fixture("approvegraph");
        let store = store(&paths, &clock);
        let claim = valid_store_claim("clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", CLAIM_BASIS_OWNER);
        store.write_draft("research", claim.clone()).unwrap();
        let approved = store.approve("research", &claim.id).unwrap();
        assert_eq!(approved.transitions.len(), 1);
        assert_eq!(approved.transitions[0].kind, CLAIM_TRANSITION_APPROVE);
        assert!(store.approve("research", &claim.id).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn supersede_transition_graph() {
        let (dir, paths, clock) = fixture("supersede");
        let store = store(&paths, &clock);
        let old_claim =
            valid_store_claim("clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", CLAIM_BASIS_OWNER);
        store.write_draft("research", old_claim.clone()).unwrap();
        let old_approved = store.approve("research", &old_claim.id).unwrap();

        let mut replacement =
            valid_store_claim("clm_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", CLAIM_BASIS_OWNER);
        replacement.body = "Replacement body\n".to_string();
        let draft = store
            .write_superseding_draft("research", &old_approved.id, replacement.clone())
            .unwrap();
        let approved_replacement = store.approve("research", &draft.id).unwrap();
        assert_eq!(approved_replacement.transitions.len(), 1);
        assert_eq!(
            approved_replacement.transitions[0].kind,
            CLAIM_TRANSITION_SUPERSEDE
        );
        assert_eq!(
            approved_replacement.transitions[0].related_claim_ids,
            vec![old_approved.id.clone()]
        );

        let old = store.read("research", &old_approved.id).unwrap();
        assert_eq!(old.status, CLAIM_STATUS_SUPERSEDED);
        assert_eq!(old.body, old_approved.body);
        assert_eq!(old.verified_at, old_approved.verified_at);
        assert_eq!(old.verified_by, old_approved.verified_by);
        assert_eq!(old.verified_digest, old_approved.verified_digest);
        assert_eq!(old.transitions.len(), 2);
        assert_eq!(old.transitions[1].kind, CLAIM_TRANSITION_SUPERSEDE);
        assert_eq!(
            old.transitions[1].prior_verification_digest,
            old_approved.verified_digest
        );
        assert_eq!(
            old.transitions[1].related_claim_ids[0],
            approved_replacement.id
        );
        assert!(store.revoke("research", &old.id, "obsolete").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn revoke_transition_graph() {
        let (dir, paths, clock) = fixture("revokegraph");
        let store = store(&paths, &clock);
        let claim = valid_store_claim("clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", CLAIM_BASIS_OWNER);
        store.write_draft("research", claim.clone()).unwrap();
        assert!(store.revoke("research", &claim.id, "not ready").is_err());
        let approved = store.approve("research", &claim.id).unwrap();
        let revoked = store.revoke("research", &approved.id, "not ready").unwrap();
        assert_eq!(revoked.status, CLAIM_STATUS_REVOKED);
        assert_eq!(revoked.body, approved.body);
        assert_eq!(revoked.verified_digest, approved.verified_digest);
        assert_eq!(revoked.transitions.len(), 2);
        assert_eq!(revoked.transitions[1].kind, CLAIM_TRANSITION_REVOKE);
        assert_eq!(revoked.transitions[1].reason, "not ready");
        assert!(store.revoke("research", &approved.id, "again").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn lifecycle_history_preserved() {
        let (dir, paths, clock) = fixture("history");
        let store = store(&paths, &clock);
        let mut claim =
            valid_store_claim("clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", CLAIM_BASIS_OWNER);
        claim.body = "Original body\n".to_string();
        store.write_draft("research", claim.clone()).unwrap();
        let approved = store.approve("research", &claim.id).unwrap();
        let before_body = approved.body.clone();
        let before_at = approved.verified_at.clone();
        let before_by = approved.verified_by.clone();
        let before_digest = approved.verified_digest.clone();
        store
            .revoke("research", &approved.id, "owner withdrew claim")
            .unwrap();
        let revoked = store.read("research", &approved.id).unwrap();
        assert_eq!(revoked.body, before_body);
        assert_eq!(revoked.verified_at, before_at);
        assert_eq!(revoked.verified_by, before_by);
        assert_eq!(revoked.verified_digest, before_digest);
        assert_eq!(revoked.transitions.len(), 2);
        assert_eq!(
            revoked.transitions[1].prior_verification_digest,
            before_digest
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn claim_store_approve_evidence_claim_verifies_evidence_and_writes_sources() {
        let (dir, paths, clock) = fixture("evapprove");
        let evidence = add_store_evidence(&paths, &clock, b"source bytes");
        let store = store(&paths, &clock);
        let mut claim =
            valid_store_claim("clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", CLAIM_BASIS_EVIDENCE);
        claim.evidence_ids = vec![evidence.id.clone()];
        store.write_draft("research", claim.clone()).unwrap();
        let approved = store.approve("research", &claim.id).unwrap();
        let metadata_path = paths
            .workspaces_dir
            .join("research/evidence/sources")
            .join(&evidence.id)
            .join("source.yaml");
        let metadata = std::fs::read(&metadata_path).unwrap();
        let want_digest = evidence_snapshot_digest(&metadata, &evidence);
        assert_eq!(approved.sources.len(), 1);
        assert_eq!(approved.sources[0].id, evidence.id);
        assert_eq!(approved.sources[0].digest, want_digest);
        let claim_path = paths
            .workspaces_dir
            .join("research/wiki/projects")
            .join(format!("{}.md", claim.id));
        let contents = String::from_utf8(std::fs::read(&claim_path).unwrap()).unwrap();
        assert!(
            contents.contains("sources:") && contents.contains("verified:"),
            "{contents}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn claim_store_approve_rejects_tampered_evidence() {
        let (dir, paths, clock) = fixture("tamperev");
        let evidence = add_store_evidence(&paths, &clock, b"trusted evidence");
        let raw = evidence_raw_path(&paths, &evidence);
        std::fs::set_permissions(&raw, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::write(&raw, b"tampered").unwrap();
        let store = store(&paths, &clock);
        let mut claim =
            valid_store_claim("clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", CLAIM_BASIS_EVIDENCE);
        claim.evidence_ids = vec![evidence.id.clone()];
        store.write_draft("research", claim.clone()).unwrap();
        assert!(store.approve("research", &claim.id).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn claim_store_approve_rejects_draft_supporting_claim() {
        let (dir, paths, clock) = fixture("draftsupport");
        let store = store(&paths, &clock);
        let support = valid_store_claim("clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", CLAIM_BASIS_OWNER);
        store.write_draft("research", support.clone()).unwrap();
        let mut derived =
            valid_store_claim("clm_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", CLAIM_BASIS_DERIVED);
        derived.supporting_claim_ids = vec![support.id.clone()];
        store.write_draft("research", derived).unwrap();
        assert!(store
            .approve("research", "clm_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
            .is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn claim_store_rejects_invalid_approval_basis() {
        let (dir, paths, clock) = fixture("badbasis");
        let store = store(&paths, &clock);
        let claim = valid_store_claim("clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", CLAIM_BASIS_EVIDENCE);
        store.write_draft("research", claim.clone()).unwrap();
        assert!(store.approve("research", &claim.id).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn claim_store_approve_deep_support() {
        let (dir, paths, clock) = fixture("deep");
        let leaf = finalize_approved_claim(&valid_store_claim(
            &approval_test_claim_id(1),
            CLAIM_BASIS_OWNER,
        ));
        write_canonical_claim(&paths, &leaf);
        let mut current = leaf;
        for number in 2..=96u32 {
            let mut next = valid_store_claim(&approval_test_claim_id(number), CLAIM_BASIS_DERIVED);
            next.supporting_claim_ids = vec![current.id.clone()];
            let next = finalize_approved_claim(&next);
            write_canonical_claim(&paths, &next);
            current = next;
        }
        let mut root = valid_store_claim(&approval_test_claim_id(1000), CLAIM_BASIS_DERIVED);
        root.supporting_claim_ids = vec![current.id.clone()];
        let store = store(&paths, &clock);
        store.write_draft("research", root.clone()).unwrap();
        let approved = store.approve("research", &root.id).unwrap();
        assert_eq!(approved.status, CLAIM_STATUS_APPROVED);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn claim_store_approve_invalid_digest() {
        let (dir, paths, clock) = fixture("baddigest");
        let support = finalize_approved_claim(&valid_store_claim(
            &approval_test_claim_id(1),
            CLAIM_BASIS_OWNER,
        ));
        write_canonical_claim(&paths, &support);
        let support_path = paths
            .workspaces_dir
            .join("research/wiki/projects")
            .join(format!("{}.md", support.id));
        let contents = String::from_utf8(std::fs::read(&support_path).unwrap()).unwrap();
        std::fs::write(
            &support_path,
            contents.replacen("Store body", "Tampered body", 1),
        )
        .unwrap();

        let mut root = valid_store_claim(&approval_test_claim_id(2), CLAIM_BASIS_DERIVED);
        root.supporting_claim_ids = vec![support.id.clone()];
        let store = store(&paths, &clock);
        store.write_draft("research", root.clone()).unwrap();
        let root_path = paths
            .workspaces_dir
            .join("research/wiki/projects")
            .join(format!("{}.md", root.id));
        let before = sha256_file(&root_path);
        let err = store.approve("research", &root.id).unwrap_err().to_string();
        assert!(err.contains("verification digest mismatch"), "{err}");
        assert_eq!(sha256_file(&root_path), before);
        let unchanged = store.read("research", &root.id).unwrap();
        assert_eq!(unchanged.status, CLAIM_STATUS_DRAFT);
        assert!(unchanged.verified_at.is_empty());
        assert!(unchanged.verified_by.is_empty());
        assert!(unchanged.verified_digest.is_empty());
        assert!(unchanged.transitions.is_empty());
        assert!(!pending_transition_path(&paths).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn claim_store_approve_revoked() {
        let (dir, paths, clock) = fixture("revsupport");
        let store = store(&paths, &clock);
        let support = valid_store_claim(&approval_test_claim_id(1), CLAIM_BASIS_OWNER);
        store.write_draft("research", support.clone()).unwrap();
        store.approve("research", &support.id).unwrap();
        store.revoke("research", &support.id, "obsolete").unwrap();
        let mut root = valid_store_claim(&approval_test_claim_id(2), CLAIM_BASIS_DERIVED);
        root.supporting_claim_ids = vec![support.id.clone()];
        store.write_draft("research", root.clone()).unwrap();
        let err = store.approve("research", &root.id).unwrap_err().to_string();
        assert!(err.contains("revoked"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn claim_store_approve_superseded() {
        let (dir, paths, clock) = fixture("suppsupport");
        let store = store(&paths, &clock);
        let old = valid_store_claim(&approval_test_claim_id(1), CLAIM_BASIS_OWNER);
        store.write_draft("research", old.clone()).unwrap();
        store.approve("research", &old.id).unwrap();
        let replacement = valid_store_claim(&approval_test_claim_id(2), CLAIM_BASIS_OWNER);
        store
            .write_superseding_draft("research", &old.id, replacement.clone())
            .unwrap();
        store.approve("research", &replacement.id).unwrap();
        let mut root = valid_store_claim(&approval_test_claim_id(3), CLAIM_BASIS_DERIVED);
        root.supporting_claim_ids = vec![old.id.clone()];
        store.write_draft("research", root.clone()).unwrap();
        let err = store.approve("research", &root.id).unwrap_err().to_string();
        assert!(err.contains("superseded"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn claim_store_approve_missing_evidence() {
        let (dir, paths, clock) = fixture("missingev");
        let store = store(&paths, &clock);
        let mut claim = valid_store_claim(&approval_test_claim_id(1), CLAIM_BASIS_EVIDENCE);
        claim.evidence_ids = vec!["evd_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()];
        store.write_draft("research", claim.clone()).unwrap();
        let claim_path = paths
            .workspaces_dir
            .join("research/wiki/projects")
            .join(format!("{}.md", claim.id));
        let before = sha256_file(&claim_path);
        let err = store
            .approve("research", &claim.id)
            .unwrap_err()
            .to_string();
        assert!(err.contains("source.yaml"), "{err}");
        assert_eq!(sha256_file(&claim_path), before);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn claim_store_approve_tampered_evidence_no_write() {
        let (dir, paths, clock) = fixture("tampenowrite");
        let evidence = add_store_evidence(&paths, &clock, b"trusted evidence");
        let raw_path = evidence_raw_path(&paths, &evidence);
        std::fs::set_permissions(&raw_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::write(&raw_path, vec![b'x'; evidence.byte_length as usize]).unwrap();
        let store = store(&paths, &clock);
        let mut claim = valid_store_claim(&approval_test_claim_id(1), CLAIM_BASIS_EVIDENCE);
        claim.evidence_ids = vec![evidence.id.clone()];
        store.write_draft("research", claim.clone()).unwrap();
        let claim_path = paths
            .workspaces_dir
            .join("research/wiki/projects")
            .join(format!("{}.md", claim.id));
        let before = sha256_file(&claim_path);
        let err = store
            .approve("research", &claim.id)
            .unwrap_err()
            .to_string();
        assert!(err.contains("sha256"), "{err}");
        assert_eq!(sha256_file(&claim_path), before);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn claim_store_approve_rejects_supporting_claim_evidence() {
        let (dir, paths, clock) = fixture("supportev");
        let evidence = add_store_evidence(&paths, &clock, b"support evidence");
        let store = store(&paths, &clock);
        let mut support = valid_store_claim(&approval_test_claim_id(1), CLAIM_BASIS_EVIDENCE);
        support.evidence_ids = vec![evidence.id.clone()];
        store.write_draft("research", support.clone()).unwrap();
        store.approve("research", &support.id).unwrap();
        let raw_path = evidence_raw_path(&paths, &evidence);
        std::fs::set_permissions(&raw_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::write(&raw_path, vec![b'x'; evidence.byte_length as usize]).unwrap();
        let mut dependent = valid_store_claim(&approval_test_claim_id(2), CLAIM_BASIS_DERIVED);
        dependent.supporting_claim_ids = vec![support.id.clone()];
        store.write_draft("research", dependent.clone()).unwrap();
        let claim_path = paths
            .workspaces_dir
            .join("research/wiki/projects")
            .join(format!("{}.md", dependent.id));
        let before = sha256_file(&claim_path);
        let err = store
            .approve("research", &dependent.id)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains(&evidence.id) && err.contains("sha256"),
            "{err}"
        );
        assert_eq!(sha256_file(&claim_path), before);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn claim_store_approve_cycle() {
        let (dir, paths, clock) = fixture("cycle");
        let mut first = valid_store_claim(&approval_test_claim_id(1), CLAIM_BASIS_DERIVED);
        let mut second = valid_store_claim(&approval_test_claim_id(2), CLAIM_BASIS_DERIVED);
        first.supporting_claim_ids = vec![second.id.clone()];
        second.supporting_claim_ids = vec![first.id.clone()];
        write_canonical_claim(&paths, &finalize_approved_claim(&first));
        write_canonical_claim(&paths, &finalize_approved_claim(&second));
        let mut root = valid_store_claim(&approval_test_claim_id(3), CLAIM_BASIS_DERIVED);
        root.supporting_claim_ids = vec![first.id.clone()];
        let store = store(&paths, &clock);
        store.write_draft("research", root.clone()).unwrap();
        let err = store.approve("research", &root.id).unwrap_err().to_string();
        assert!(err.contains("dependency cycle detected"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn claim_mutation_authorization_metadata() {
        let (dir, paths, clock) = fixture("authz");
        let store = store(&paths, &clock);

        let first = valid_store_claim("clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", CLAIM_BASIS_OWNER);
        store.write_draft("research", first.clone()).unwrap();
        let approved = store
            .approve_with_options(
                "research",
                &first.id,
                ClaimMutationOptions {
                    verified_by: "owner:mcp".to_string(),
                    authorization: authorization("chg_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                },
            )
            .unwrap();
        assert_eq!(approved.verified_by, "owner:mcp");
        let got = approved.transitions[0].authorization.as_ref().unwrap();
        assert_eq!(got.challenge_id, "chg_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert_eq!(got.method, "claim_lifecycle.apply");
        assert_eq!(got.mcp_client, "mcp-client/1.0");

        let mut replacement =
            valid_store_claim("clm_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", CLAIM_BASIS_OWNER);
        replacement.body = "Replacement body\n".to_string();
        store
            .write_superseding_draft("research", &approved.id, replacement.clone())
            .unwrap();
        let superseded = store
            .approve_with_options(
                "research",
                &replacement.id,
                ClaimMutationOptions {
                    verified_by: "owner:mcp".to_string(),
                    authorization: authorization("chg_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
                },
            )
            .unwrap();
        let got = superseded.transitions[0].authorization.as_ref().unwrap();
        assert_eq!(got.challenge_id, "chg_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        let old = store.read("research", &approved.id).unwrap();
        let got = old.transitions[1].authorization.as_ref().unwrap();
        assert_eq!(got.challenge_id, "chg_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        assert_eq!(got.method, "claim_lifecycle.apply");
        assert_eq!(got.mcp_client, "mcp-client/1.0");

        let revoked = store
            .revoke_with_options(
                "research",
                &superseded.id,
                "wrong scope",
                ClaimMutationOptions {
                    verified_by: "owner:mcp".to_string(),
                    authorization: authorization("chg_cccccccccccccccccccccccccccccccc"),
                },
            )
            .unwrap();
        assert_eq!(revoked.verified_by, "owner:mcp");
        let got = revoked
            .transitions
            .last()
            .unwrap()
            .authorization
            .as_ref()
            .unwrap();
        assert_eq!(got.challenge_id, "chg_cccccccccccccccccccccccccccccccc");
        verify_claim_digest(&revoked).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mutation_recovers_pending_transition() {
        let (dir, paths, clock) = fixture("recovermutation");
        let recovery_path = paths
            .workspaces_dir
            .join("research/wiki/projects/recovery.md");
        std::fs::create_dir_all(recovery_path.parent().unwrap()).unwrap();
        let before = &b"before mutation\n"[..];
        let target = &b"recovered mutation\n"[..];
        std::fs::write(&recovery_path, before).unwrap();
        write_pending_transition_unlocked(
            &paths,
            "research",
            PendingTransition {
                operation_id: "txn_mutation".to_string(),
                kind: CLAIM_TRANSITION_SUPERSEDE.to_string(),
                workspace: "research".to_string(),
                targets: vec![PendingTransitionTarget {
                    path: "wiki/projects/recovery.md".to_string(),
                    preimage_sha256: transition_sha256(before),
                    target_sha256: transition_sha256(target),
                    target_bytes: target.to_vec(),
                }],
            },
        )
        .unwrap();
        let store = store(&paths, &clock);
        let claim = valid_store_claim("clm_cccccccccccccccccccccccccccccccc", CLAIM_BASIS_OWNER);
        store.write_draft("research", claim.clone()).unwrap();
        assert_eq!(std::fs::read(&recovery_path).unwrap(), target);
        assert!(!pending_transition_path(&paths).exists());
        store.read("research", &claim.id).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn claim_store_migrate_okf_converts_legacy_claim() {
        let (dir, paths, clock) = fixture("migrate");
        let id = "clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let claim_path = paths
            .workspaces_dir
            .join("research/wiki/projects")
            .join(format!("{id}.md"));
        let legacy = b"---\nschema: zbrain.claim/v1\nid: clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nstatus: draft\ntitle: Legacy Claim\nbasis: owner\ncreated_at: 2026-07-30T09:00:00Z\ncreated_by: owner\ntags: [legacy]\n---\n\nLegacy body\n";
        std::fs::create_dir_all(claim_path.parent().unwrap()).unwrap();
        std::fs::write(&claim_path, legacy).unwrap();
        let store = store(&paths, &clock);
        let summary = store.migrate_okf("research").unwrap();
        assert_eq!(summary.migrated, 1);
        assert_eq!(summary.invalid, 0);
        assert_eq!(summary.reapproval_required, 0);
        let contents = String::from_utf8(std::fs::read(&claim_path).unwrap()).unwrap();
        assert!(!contents.contains("schema: zbrain.claim/v1"));
        assert!(contents.contains("type: zbrain.claim"));
        assert!(
            contents.contains("profile: zbrain.trusted-memory/v1"),
            "{contents}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn legacy_migration_requires_explicit_reapproval() {
        let (dir, paths, clock) = fixture("reapproval");
        let id = "clm_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let claim_path = paths
            .workspaces_dir
            .join("research/wiki/projects")
            .join(format!("{id}.md"));
        let legacy = b"---\nschema: zbrain.claim/v1\nid: clm_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\nstatus: approved\ntitle: Legacy Approved\nbasis: owner\ncreated_at: 2026-07-30T09:00:00Z\ncreated_by: owner\n---\n\nLegacy approved body\n";
        std::fs::create_dir_all(claim_path.parent().unwrap()).unwrap();
        std::fs::write(&claim_path, legacy).unwrap();

        let store = store(&paths, &clock);
        let summary = store.migrate_okf("research").unwrap();
        assert_eq!(summary.migrated, 1);
        assert_eq!(summary.invalid, 0);
        assert_eq!(summary.reapproval_required, 1);
        assert_eq!(summary.reapproval_candidates, vec![id]);
        let migrated = store.read("research", id).unwrap();
        assert_eq!(migrated.status, CLAIM_STATUS_DRAFT);
        assert_eq!(migrated.id, id);
        assert_eq!(migrated.body, "\nLegacy approved body\n");
        assert!(migrated.verified_at.is_empty());
        assert!(migrated.verified_by.is_empty());
        assert!(migrated.verified_digest.is_empty());
        verify_claim_digest(&migrated).unwrap();

        let approved = store.approve("research", id).unwrap();
        assert_eq!(approved.status, CLAIM_STATUS_APPROVED);
        assert!(!approved.verified_digest.is_empty());
        verify_claim_digest(&approved).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn legacy_migration_preserves_approved_claim_with_valid_okf_digest() {
        let (dir, paths, clock) = fixture("preserve");
        let id = "clm_cccccccccccccccccccccccccccccccc";
        let verified_at = "2026-07-30T09:00:00Z";
        let mut claim = valid_store_claim(id, CLAIM_BASIS_OWNER);
        claim.body = "\nStore body\n".to_string();
        claim.status = CLAIM_STATUS_APPROVED.to_string();
        claim.verified_at = verified_at.to_string();
        claim.verified_by = "owner".to_string();
        let digest = claim_verification_digest(&claim).unwrap();
        let legacy = format!(
            "---\nschema: zbrain.claim/v1\nid: {id}\nstatus: approved\ntitle: Store claim\nbasis: owner\ncreated_at: 2026-07-30T09:00:00Z\ncreated_by: owner\nverified:\n  at: {verified_at}\n  by: owner\n  digest: {digest}\n---\n\nStore body\n"
        );
        let claim_path = paths
            .workspaces_dir
            .join("research/wiki/projects")
            .join(format!("{id}.md"));
        std::fs::create_dir_all(claim_path.parent().unwrap()).unwrap();
        std::fs::write(&claim_path, legacy).unwrap();

        let store = store(&paths, &clock);
        let summary = store.migrate_okf("research").unwrap();
        assert_eq!(summary.migrated, 1);
        assert_eq!(summary.invalid, 0);
        assert_eq!(summary.reapproval_required, 0);
        let migrated = store.read("research", id).unwrap();
        assert_eq!(migrated.status, CLAIM_STATUS_APPROVED);
        assert_eq!(migrated.verified_digest, digest);
        verify_claim_digest(&migrated).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn claim_store_migrate_dirty_barrier_leaves_canonical_bytes_unchanged() {
        let (dir, paths, clock) = fixture("migratedirty");
        let id = "clm_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
        let claim_path = paths
            .workspaces_dir
            .join("research/wiki/projects")
            .join(format!("{id}.md"));
        let legacy = b"---\nschema: zbrain.claim/v1\nid: clm_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\nstatus: draft\ntitle: Legacy Claim\nbasis: owner\ncreated_at: 2026-07-30T09:00:00Z\ncreated_by: owner\n---\n\nLegacy body\n";
        std::fs::create_dir_all(claim_path.parent().unwrap()).unwrap();
        std::fs::write(&claim_path, legacy).unwrap();
        let mut dirty_paths = paths.clone();
        dirty_paths.indexes_dir = dir.join("indexes-blocker");
        std::fs::write(&dirty_paths.indexes_dir, b"not a directory").unwrap();
        let before = sha256_file(&claim_path);
        let store = ClaimStore::with_clock(dirty_paths, Arc::new(clock));
        assert!(store.migrate_okf("research").is_err());
        assert_eq!(sha256_file(&claim_path), before);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn claim_store_duplicate_canonical_id_blocks_lifecycle() {
        let (dir, paths, clock) = fixture("duplifecycle");
        let store = store(&paths, &clock);
        let id = "clm_55555555555555555555555555555555";
        let mut flat = valid_store_claim(id, CLAIM_BASIS_OWNER);
        flat.title = "Flat lifecycle duplicate".to_string();
        flat.body = "flat lifecycle duplicate\n".to_string();
        write_canonical_claim(&paths, &flat);

        let nested_path = "projects/topics/security/clm_55555555555555555555555555555555.md";
        let mut nested = flat.clone();
        nested.title = "Nested lifecycle duplicate".to_string();
        nested.body = "nested lifecycle duplicate\n".to_string();
        nested.path = nested_path.to_string();
        let nested_absolute = paths.workspaces_dir.join("research/wiki").join(nested_path);
        std::fs::create_dir_all(nested_absolute.parent().unwrap()).unwrap();
        write_claim_atomic(&nested_absolute, &nested).unwrap();

        let flat_path = format!("projects/{id}.md");
        let flat_absolute = paths.workspaces_dir.join("research/wiki").join(&flat_path);
        let before_flat = sha256_file(&flat_absolute);
        let before_nested = sha256_file(&nested_absolute);
        let expect_duplicate = |operation: &str, err: String| {
            assert!(
                err.contains("duplicate canonical claim ID")
                    && err.contains(id)
                    && err.contains(&flat_path)
                    && err.contains(nested_path),
                "{operation}: {err}"
            );
        };

        expect_duplicate("Read", store.read("research", id).unwrap_err().to_string());
        let mut flat_mutated = flat.clone();
        flat_mutated.body = "mutated flat duplicate\n".to_string();
        expect_duplicate(
            "WriteDraft(flat)",
            store
                .write_draft("research", flat_mutated)
                .unwrap_err()
                .to_string(),
        );
        let mut nested_mutated = nested.clone();
        nested_mutated.body = "mutated nested duplicate\n".to_string();
        expect_duplicate(
            "WriteDraft(nested)",
            store
                .write_draft("research", nested_mutated)
                .unwrap_err()
                .to_string(),
        );
        expect_duplicate(
            "Approve",
            store.approve("research", id).unwrap_err().to_string(),
        );
        expect_duplicate(
            "Revoke",
            store
                .revoke("research", id, "ambiguous")
                .unwrap_err()
                .to_string(),
        );
        let replacement_id = "clm_66666666666666666666666666666666";
        expect_duplicate(
            "WriteSupersedingDraft",
            store
                .write_superseding_draft(
                    "research",
                    id,
                    valid_store_claim(replacement_id, CLAIM_BASIS_OWNER),
                )
                .unwrap_err()
                .to_string(),
        );

        assert_eq!(sha256_file(&flat_absolute), before_flat);
        assert_eq!(sha256_file(&nested_absolute), before_nested);
        let replacement_path = paths
            .workspaces_dir
            .join("research/wiki/projects")
            .join(format!("{replacement_id}.md"));
        assert!(!replacement_path.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn claim_store_contradicts_preserved_through_approve() {
        // Reindex (IndexStore::Rebuild) is m4; this port covers the approval
        // invariants of TestClaimStoreContradictsPreservedThroughApproveAndReindex.
        let (dir, paths, clock) = fixture("contradictsapprove");
        let store = store(&paths, &clock);

        let mut approved = valid_store_claim(&approval_test_claim_id(1), CLAIM_BASIS_OWNER);
        approved.title = "Node runtime is recommended".to_string();
        store.write_draft("research", approved.clone()).unwrap();
        store.approve("research", &approved.id).unwrap();

        let mut conflicting = valid_store_claim(&approval_test_claim_id(2), CLAIM_BASIS_OWNER);
        conflicting.title = "Node runtime is deprecated".to_string();
        store.write_draft("research", conflicting.clone()).unwrap();
        store.approve("research", &conflicting.id).unwrap();

        let approved_after = store.read("research", &approved.id).unwrap();
        let conflicting_after = store.read("research", &conflicting.id).unwrap();
        assert!(approved_after.contradicts.is_empty());
        assert_eq!(conflicting_after.contradicts.len(), 1);
        assert_eq!(conflicting_after.contradicts[0].claim_id, approved.id);
        assert_eq!(
            conflicting_after.contradicts[0].heuristic,
            crate::claims::CONTRADICTION_STATUS_CHANGE
        );
        verify_claim_digest(&conflicting_after).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn claim_store_write_draft_recovers_pending_journal_before_mutation() {
        // Companion to TestMutationRecoversPendingTransition: approve also
        // recovers the journal before mutating canonical bytes.
        let (dir, paths, clock) = fixture("recoverapprove");
        let recovery_path = paths
            .workspaces_dir
            .join("research/wiki/projects/recovery.md");
        std::fs::create_dir_all(recovery_path.parent().unwrap()).unwrap();
        std::fs::write(&recovery_path, b"before mutation\n").unwrap();
        write_pending_transition_unlocked(
            &paths,
            "research",
            PendingTransition {
                operation_id: "txn_approve".to_string(),
                kind: CLAIM_TRANSITION_SUPERSEDE.to_string(),
                workspace: "research".to_string(),
                targets: vec![PendingTransitionTarget {
                    path: "wiki/projects/recovery.md".to_string(),
                    preimage_sha256: transition_sha256(b"before mutation\n"),
                    target_sha256: transition_sha256(b"recovered approve\n"),
                    target_bytes: b"recovered approve\n".to_vec(),
                }],
            },
        )
        .unwrap();
        let store = store(&paths, &clock);
        let claim = valid_store_claim("clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", CLAIM_BASIS_OWNER);
        store.write_draft("research", claim.clone()).unwrap();
        store.approve("research", &claim.id).unwrap();
        assert_eq!(
            std::fs::read(&recovery_path).unwrap(),
            b"recovered approve\n"
        );
        assert!(!pending_transition_path(&paths).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
