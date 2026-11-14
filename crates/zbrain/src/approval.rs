// Port of internal/runtime/challenge.go plus the challenge-gated lifecycle
// entry points of internal/runtime/lifecycle.go (PrepareChallenge,
// ApplyChallenge[Batch], validateChallengeAgainstClaim,
// firstSupersededVerificationDigest) and the owner grant walk from
// internal/cli (approval show/grant with TTY confirmation).

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::term::ApprovalPrompt;

use crate::boundary::{path_within, validate_workspace};
use crate::claims::{
    is_challenge_id, is_claim_id, message, Claim, ClaimError, ClaimStore, CLAIM_STATUS_APPROVED,
    CLAIM_STATUS_DRAFT,
};
use crate::clock::{parse_rfc3339, rfc3339, Clock};
use crate::coordination::acquire_workspace_lock;
use crate::lifecycle::ClaimMutationOptions;
use crate::paths::{
    ensure_directory_mode, ensure_file_mode, is_safe_workspace_name, Paths, RUNTIME_DIRECTORY_MODE,
    RUNTIME_METADATA_MODE,
};
use crate::transition::recover_pending_transition_for_mutation_unlocked;

/// Security-critical challenge records are fail-closed across schema changes.
pub const CHALLENGE_SCHEMA_VERSION: &str = "zbrain.challenge/v3";

pub const CHALLENGE_OPERATION_APPROVE: &str = "approve";
pub const CHALLENGE_OPERATION_SUPERSEDE: &str = "supersede";
pub const CHALLENGE_OPERATION_REVOKE: &str = "revoke";

/// Per-item outcome statuses reported by ApplyChallengeBatch.
pub const BATCH_APPLY_ITEM_APPLIED: &str = "applied";
pub const BATCH_APPLY_ITEM_SKIPPED: &str = "skipped";
pub const BATCH_APPLY_ITEM_FAILED: &str = "failed";

/// Owner-pinned challenge TTL.
pub fn challenge_lifetime() -> chrono::Duration {
    chrono::Duration::minutes(15)
}

/// Independent from the challenge TTL: a valid challenge may outlive the
/// one-time grant token it carries.
pub fn challenge_token_lifetime() -> chrono::Duration {
    chrono::Duration::minutes(5)
}

/// One ordered approve action bound by a batch challenge.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeItem {
    #[serde(default)]
    pub claim_id: String,
    #[serde(default)]
    pub canonical_draft_digest: String,
}

/// Every input bound by the challenge action digest. A non-empty items list
/// binds an ordered batch of approve items instead of the single-claim fields.
#[derive(Debug, Clone, Default)]
pub struct ChallengePrepare {
    pub workspace: String,
    pub operation: String,
    pub claim_id: String,
    pub canonical_draft_digest: String,
    pub superseded_ids: Vec<String>,
    pub prior_verification_digest: String,
    pub revoke_reason: String,
    pub items: Vec<ChallengeItem>,
}

/// Persisted owner-pinned challenge record. Only the token SHA-256 is stored;
/// the plaintext one-time token is never persisted. The owner-granted marker
/// is persisted so apply cannot bypass the local ceremony.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Challenge {
    pub schema: String,
    pub id: String,
    pub workspace: String,
    pub operation: String,
    pub claim_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub canonical_draft_digest: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub superseded_ids: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub prior_verification_digest: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub revoke_reason: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub items: Vec<ChallengeItem>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub granted_items: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub skipped_items: Vec<String>,
    pub action_digest: String,
    pub token_sha256: String,
    pub expires_at: String,
    pub token_expires_at: String,
    pub granted: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub granted_at: String,
    pub consumed: bool,
}

/// Owner-pinned action summary. No token is issued until the local owner
/// ceremony calls grant.
#[derive(Debug, Clone)]
pub struct PreparedChallenge {
    pub challenge: Challenge,
}

/// Owner-approved challenge plus the plaintext one-time token released exactly
/// once by grant. The token is never persisted.
#[derive(Debug, Clone)]
pub struct GrantedChallenge {
    pub challenge: Challenge,
    pub token: String,
}

/// Per-item outcome of applying a batch challenge.
#[derive(Debug, Clone, Serialize)]
pub struct BatchApplyItemResult {
    pub claim_id: String,
    pub status: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub path: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct BatchApplyResult {
    pub challenge_id: String,
    pub items: Vec<BatchApplyItemResult>,
}

fn claim_message(err: impl std::fmt::Display) -> ClaimError {
    message(err.to_string())
}

fn same_strings(left: &[String], right: &[String]) -> bool {
    left.len() == right.len() && left.iter().zip(right).all(|(a, b)| a == b)
}

pub fn new_challenge_id() -> Result<String, std::io::Error> {
    Ok("chg_".to_string() + &crate::claims::random_hex(16)?)
}

/// Binds workspace, operation, claim ID, canonical draft digest, superseded
/// IDs, prior verification digest, and revoke reason into a deterministic
/// SHA-256 digest. Superseded IDs are sorted so the digest is canonical
/// regardless of caller ordering. A non-empty items list binds an ordered
/// batch of approve items instead; item order is significant.
pub fn compute_challenge_action_digest(prepare: &ChallengePrepare) -> String {
    fn write(hasher: &mut Sha256, value: &str) {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    let mut superseded = prepare.superseded_ids.clone();
    superseded.sort();
    let mut hasher = Sha256::new();
    write(&mut hasher, &prepare.workspace);
    write(&mut hasher, &prepare.operation);
    if !prepare.items.is_empty() {
        hasher.update((prepare.items.len() as u64).to_be_bytes());
        for item in &prepare.items {
            write(&mut hasher, &item.claim_id);
            write(&mut hasher, &item.canonical_draft_digest);
        }
        return format!("sha256:challenge-v1:{}", hex(&hasher.finalize()));
    }
    write(&mut hasher, &prepare.claim_id);
    write(&mut hasher, &prepare.canonical_draft_digest);
    write(&mut hasher, &superseded.join("\u{0}"));
    write(&mut hasher, &prepare.prior_verification_digest);
    write(&mut hasher, &prepare.revoke_reason);
    format!("sha256:challenge-v1:{}", hex(&hasher.finalize()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Prepares and verifies owner-pinned lifecycle challenges.
#[derive(Clone)]
pub struct ChallengeStore {
    pub paths: Paths,
    /// Injected clock for deterministic ceremony timestamps; defaults to the
    /// system clock.
    pub now: Option<std::sync::Arc<dyn Clock>>,
}

impl ChallengeStore {
    pub fn new(paths: Paths) -> Self {
        Self { paths, now: None }
    }

    pub fn with_clock(paths: Paths, now: std::sync::Arc<dyn Clock>) -> Self {
        Self {
            paths,
            now: Some(now),
        }
    }

    pub(crate) fn now(&self) -> chrono::DateTime<chrono::Utc> {
        match &self.now {
            Some(clock) => clock.now(),
            None => chrono::Utc::now(),
        }
    }

    /// Creates a new owner-pinned challenge. It binds every listed input into
    /// the action digest and persists no token until the local owner ceremony
    /// releases one through grant.
    pub fn prepare(
        &self,
        workspace: &str,
        prepare: ChallengePrepare,
    ) -> Result<PreparedChallenge, ClaimError> {
        let _lock = acquire_workspace_lock(&self.paths, workspace, true).map_err(claim_message)?;
        self.prepare_unlocked(workspace, prepare)
    }

    pub(crate) fn prepare_unlocked(
        &self,
        workspace: &str,
        prepare: ChallengePrepare,
    ) -> Result<PreparedChallenge, ClaimError> {
        self.validate_prepare(workspace, &prepare)?;
        let id = new_challenge_id().map_err(ClaimError::Io)?;
        let mut superseded = prepare.superseded_ids.clone();
        superseded.sort();
        let prepared_at = self.now();
        let challenge = Challenge {
            schema: CHALLENGE_SCHEMA_VERSION.to_string(),
            id,
            workspace: workspace.to_string(),
            operation: prepare.operation.clone(),
            claim_id: prepare.claim_id.clone(),
            canonical_draft_digest: prepare.canonical_draft_digest.clone(),
            superseded_ids: superseded,
            prior_verification_digest: prepare.prior_verification_digest.clone(),
            revoke_reason: prepare.revoke_reason.clone(),
            action_digest: compute_challenge_action_digest(&prepare),
            expires_at: rfc3339(prepared_at + challenge_lifetime()),
            ..Challenge::default()
        };
        self.write_challenge(workspace, &challenge)?;
        Ok(PreparedChallenge { challenge })
    }

    /// Creates a new owner-pinned batch challenge binding an ordered list of
    /// approve items. It persists no token until grant_items records the
    /// owner's per-item decisions at the end of the grant walk.
    pub fn prepare_batch(
        &self,
        workspace: &str,
        items: Vec<ChallengeItem>,
    ) -> Result<PreparedChallenge, ClaimError> {
        let _lock = acquire_workspace_lock(&self.paths, workspace, true).map_err(claim_message)?;
        self.prepare_batch_unlocked(workspace, items)
    }

    pub(crate) fn prepare_batch_unlocked(
        &self,
        workspace: &str,
        items: Vec<ChallengeItem>,
    ) -> Result<PreparedChallenge, ClaimError> {
        let normalized = normalize_challenge_items(&items)?;
        let prepare = ChallengePrepare {
            workspace: workspace.to_string(),
            operation: CHALLENGE_OPERATION_APPROVE.to_string(),
            items: normalized.clone(),
            ..ChallengePrepare::default()
        };
        self.validate_prepare(workspace, &prepare)?;
        let id = new_challenge_id().map_err(ClaimError::Io)?;
        let challenge = Challenge {
            schema: CHALLENGE_SCHEMA_VERSION.to_string(),
            id,
            workspace: workspace.to_string(),
            operation: CHALLENGE_OPERATION_APPROVE.to_string(),
            items: normalized,
            action_digest: compute_challenge_action_digest(&prepare),
            expires_at: rfc3339(self.now() + challenge_lifetime()),
            ..Challenge::default()
        };
        self.write_challenge(workspace, &challenge)?;
        Ok(PreparedChallenge { challenge })
    }

    /// Returns a persisted challenge by ID without consuming it.
    pub fn read(&self, workspace: &str, challenge_id: &str) -> Result<Challenge, ClaimError> {
        let _lock = acquire_workspace_lock(&self.paths, workspace, false).map_err(claim_message)?;
        self.read_challenge_unlocked(workspace, challenge_id)
    }

    /// Resolves a challenge ID to its owning workspace by scanning every
    /// workspace directory under the runtime. Challenge IDs are globally
    /// unique, so at most one workspace can own a challenge. A non-missing
    /// read error is surfaced rather than masked by a later workspace.
    pub fn find_challenge(&self, challenge_id: &str) -> Result<(Challenge, String), ClaimError> {
        if !is_challenge_id(challenge_id) {
            return Err(message(
                "challenge id must match chg_<32 lowercase hex chars>",
            ));
        }
        let entries = match std::fs::read_dir(&self.paths.workspaces_dir) {
            Ok(entries) => entries,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                return Err(message(format!(
                    "challenge {challenge_id} not found in any workspace"
                )));
            }
            Err(source) => {
                return Err(message(format!("list workspaces: {source}")));
            }
        };
        for entry in entries {
            let entry = entry.map_err(ClaimError::Io)?;
            let name = entry.file_name().to_string_lossy().to_string();
            if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false)
                || !is_safe_workspace_name(&name)
            {
                continue;
            }
            match self.read(&name, challenge_id) {
                Ok(challenge) => return Ok((challenge, name)),
                Err(err) if err.is_not_found() => {}
                Err(err) => return Err(err),
            }
        }
        Err(message(format!(
            "challenge {challenge_id} not found in any workspace"
        )))
    }

    /// Validates a plaintext token against a fresh, unconsumed challenge
    /// without consuming it.
    pub fn verify(
        &self,
        workspace: &str,
        challenge_id: &str,
        token: &str,
    ) -> Result<Challenge, ClaimError> {
        let _lock = acquire_workspace_lock(&self.paths, workspace, false).map_err(claim_message)?;
        let challenge = self.read_challenge_unlocked(workspace, challenge_id)?;
        self.validate_token(&challenge, token)?;
        Ok(challenge)
    }

    /// Records the local owner's approval and releases a fresh plaintext
    /// token without consuming it. The token hash and its grant-time expiry
    /// are persisted; the plaintext is returned only to the owner ceremony. A
    /// second grant is rejected because the original plaintext cannot be
    /// reconstructed.
    pub fn grant(
        &self,
        workspace: &str,
        challenge_id: &str,
    ) -> Result<GrantedChallenge, ClaimError> {
        let _lock = acquire_workspace_lock(&self.paths, workspace, true).map_err(claim_message)?;
        let mut challenge = self.read_challenge_unlocked(workspace, challenge_id)?;
        if challenge.granted {
            return Err(message(format!(
                "challenge {} has already been owner-granted",
                challenge.id
            )));
        }
        let now = self.now();
        let challenge_expires_at = parse_expiry(&challenge.expires_at).map_err(|err| {
            message(format!(
                "challenge {} has invalid challenge expiry: {err}",
                challenge.id
            ))
        })?;
        if now > challenge_expires_at {
            return Err(message(format!("challenge {} expired", challenge.id)));
        }
        let (token, token_hash) = new_challenge_token().map_err(ClaimError::Io)?;
        let mut token_expires_at = now + challenge_token_lifetime();
        if token_expires_at > challenge_expires_at {
            token_expires_at = challenge_expires_at;
        }
        challenge.token_sha256 = token_hash;
        challenge.token_expires_at = rfc3339(token_expires_at);
        challenge.granted = true;
        challenge.granted_at = rfc3339(now);
        self.write_challenge(workspace, &challenge)?;
        Ok(GrantedChallenge { challenge, token })
    }

    /// Records the owner's per-item decisions for a batch challenge and
    /// releases one plaintext token for the whole batch. The granted claim IDs
    /// together with the skipped claim IDs must partition the bound items
    /// exactly. A walk with no granted items is rejected so a fully skipped
    /// challenge stays ungranted and can never yield a token.
    pub fn grant_items(
        &self,
        workspace: &str,
        challenge_id: &str,
        granted: &[String],
        skipped: &[String],
    ) -> Result<GrantedChallenge, ClaimError> {
        let _lock = acquire_workspace_lock(&self.paths, workspace, true).map_err(claim_message)?;
        let mut challenge = self.read_challenge_unlocked(workspace, challenge_id)?;
        if challenge.items.is_empty() {
            return Err(message(format!(
                "challenge {} is not a batch challenge",
                challenge.id
            )));
        }
        if challenge.granted {
            return Err(message(format!(
                "challenge {} has already been owner-granted",
                challenge.id
            )));
        }
        let item_index: std::collections::HashSet<&str> = challenge
            .items
            .iter()
            .map(|item| item.claim_id.as_str())
            .collect();
        let mut granted_seen = std::collections::HashSet::new();
        for id in granted {
            if !item_index.contains(id.as_str()) {
                return Err(message(format!(
                    "challenge {} granted item {:?} is not bound",
                    challenge.id, id
                )));
            }
            if !granted_seen.insert(id) {
                return Err(message(format!(
                    "challenge {} grants claim {} more than once",
                    challenge.id, id
                )));
            }
        }
        let mut skipped_seen = std::collections::HashSet::new();
        for id in skipped {
            if !item_index.contains(id.as_str()) {
                return Err(message(format!(
                    "challenge {} skipped item {:?} is not bound",
                    challenge.id, id
                )));
            }
            if granted_seen.contains(id) {
                return Err(message(format!(
                    "challenge {} claim {} cannot be both granted and skipped",
                    challenge.id, id
                )));
            }
            if !skipped_seen.insert(id) {
                return Err(message(format!(
                    "challenge {} skips claim {} more than once",
                    challenge.id, id
                )));
            }
        }
        if granted.len() + skipped.len() != challenge.items.len() {
            return Err(message(format!(
                "challenge {} grant decisions do not cover every bound item",
                challenge.id
            )));
        }
        if granted.is_empty() {
            return Err(message(format!(
                "challenge {} granted no items; nothing to record",
                challenge.id
            )));
        }
        let now = self.now();
        let challenge_expires_at = parse_expiry(&challenge.expires_at).map_err(|err| {
            message(format!(
                "challenge {} has invalid challenge expiry: {err}",
                challenge.id
            ))
        })?;
        if now > challenge_expires_at {
            return Err(message(format!("challenge {} expired", challenge.id)));
        }
        let (token, token_hash) = new_challenge_token().map_err(ClaimError::Io)?;
        let mut token_expires_at = now + challenge_token_lifetime();
        if token_expires_at > challenge_expires_at {
            token_expires_at = challenge_expires_at;
        }
        challenge.granted_items = granted.to_vec();
        challenge.skipped_items = skipped.to_vec();
        challenge.token_sha256 = token_hash;
        challenge.token_expires_at = rfc3339(token_expires_at);
        challenge.granted = true;
        challenge.granted_at = rfc3339(now);
        self.write_challenge(workspace, &challenge)?;
        Ok(GrantedChallenge { challenge, token })
    }

    /// Atomically validates a plaintext token, enforces expiry, and marks the
    /// owner-granted challenge consumed under the workspace lock so the token
    /// is one-time.
    pub fn consume(
        &self,
        workspace: &str,
        challenge_id: &str,
        token: &str,
    ) -> Result<Challenge, ClaimError> {
        let _lock = acquire_workspace_lock(&self.paths, workspace, true).map_err(claim_message)?;
        self.consume_unlocked(workspace, challenge_id, token)
    }

    pub(crate) fn consume_unlocked(
        &self,
        workspace: &str,
        challenge_id: &str,
        token: &str,
    ) -> Result<Challenge, ClaimError> {
        let mut challenge = self.read_challenge_unlocked(workspace, challenge_id)?;
        self.validate_token(&challenge, token)?;
        if !challenge.granted {
            return Err(message(format!(
                "challenge {} token has not been owner-granted",
                challenge.id
            )));
        }
        challenge.consumed = true;
        self.write_challenge(workspace, &challenge)?;
        Ok(challenge)
    }

    pub(crate) fn validate_token(
        &self,
        challenge: &Challenge,
        token: &str,
    ) -> Result<(), ClaimError> {
        if !challenge.granted {
            return Err(message(format!(
                "challenge {} has not been owner-granted",
                challenge.id
            )));
        }
        if challenge.consumed {
            return Err(message(format!(
                "challenge {} token already consumed",
                challenge.id
            )));
        }
        let now = self.now();
        let challenge_expires_at = parse_expiry(&challenge.expires_at).map_err(|err| {
            message(format!(
                "challenge {} has invalid challenge expiry: {err}",
                challenge.id
            ))
        })?;
        if now > challenge_expires_at {
            return Err(message(format!("challenge {} expired", challenge.id)));
        }
        let token_expires_at = parse_expiry(&challenge.token_expires_at).map_err(|err| {
            message(format!(
                "challenge {} has invalid token expiry: {err}",
                challenge.id
            ))
        })?;
        if now > token_expires_at {
            return Err(message(format!("challenge {} token expired", challenge.id)));
        }
        let want_hash = format!("sha256:{}", hex(&Sha256::digest(token.as_bytes())));
        if !constant_time_eq(want_hash.as_bytes(), challenge.token_sha256.as_bytes()) {
            return Err(message(format!(
                "challenge {} token mismatch",
                challenge.id
            )));
        }
        Ok(())
    }

    fn validate_prepare(
        &self,
        workspace: &str,
        prepare: &ChallengePrepare,
    ) -> Result<(), ClaimError> {
        if !is_safe_workspace_name(workspace) {
            return Err(message("challenge workspace name is not safe"));
        }
        validate_workspace(&self.paths, workspace).map_err(ClaimError::Boundary)?;
        if prepare.workspace != workspace {
            return Err(message(format!(
                "challenge workspace {:?} does not match {:?}",
                prepare.workspace, workspace
            )));
        }
        if !prepare.items.is_empty() {
            if prepare.operation != CHALLENGE_OPERATION_APPROVE {
                return Err(message(format!(
                    "challenge operation {:?} is not supported for a batch",
                    prepare.operation
                )));
            }
            normalize_challenge_items(&prepare.items)?;
            return Ok(());
        }
        match prepare.operation.as_str() {
            CHALLENGE_OPERATION_APPROVE
            | CHALLENGE_OPERATION_SUPERSEDE
            | CHALLENGE_OPERATION_REVOKE => {}
            other => {
                return Err(message(format!(
                    "challenge operation {other:?} is not supported"
                )));
            }
        }
        if !is_claim_id(&prepare.claim_id) {
            return Err(message(
                "challenge claim id must match clm_<32 lowercase hex chars>",
            ));
        }
        if !prepare.canonical_draft_digest.is_empty()
            && !prepare.canonical_draft_digest.starts_with("sha256:")
        {
            return Err(message(
                "challenge canonical draft digest must use sha256:<hex>",
            ));
        }
        if !prepare.prior_verification_digest.is_empty()
            && !prepare.prior_verification_digest.starts_with("sha256:")
        {
            return Err(message(
                "challenge prior verification digest must use sha256:<hex>",
            ));
        }
        for id in &prepare.superseded_ids {
            if !is_claim_id(id) {
                return Err(message(format!(
                    "challenge superseded id {id:?} must match clm_<32 lowercase hex chars>"
                )));
            }
        }
        if prepare.operation == CHALLENGE_OPERATION_REVOKE
            && prepare.revoke_reason.trim().is_empty()
        {
            return Err(message("revoke challenge requires a revoke reason"));
        }
        Ok(())
    }

    pub(crate) fn read_challenge_unlocked(
        &self,
        workspace: &str,
        challenge_id: &str,
    ) -> Result<Challenge, ClaimError> {
        let path = self.challenge_path(workspace, challenge_id)?;
        let contents = std::fs::read(&path).map_err(ClaimError::Io)?;
        let challenge: Challenge = serde_json::from_slice(&contents)
            .map_err(|err| message(format!("decode challenge {challenge_id}: {err}")))?;
        self.validate_challenge_record(workspace, &challenge)?;
        Ok(challenge)
    }

    /// Enforces the persisted record shape, workspace binding, and digest
    /// integrity so a tampered or misplaced challenge fails closed on every
    /// read.
    pub(crate) fn validate_challenge_record(
        &self,
        workspace: &str,
        challenge: &Challenge,
    ) -> Result<(), ClaimError> {
        let id = &challenge.id;
        if challenge.schema != CHALLENGE_SCHEMA_VERSION {
            return Err(message(format!("challenge {id} schema mismatch")));
        }
        if !is_challenge_id(id) {
            return Err(message(format!(
                "challenge id {id:?} must match chg_<32 lowercase hex chars>"
            )));
        }
        if challenge.workspace != workspace {
            return Err(message(format!(
                "challenge {id} workspace {:?} does not match {:?}",
                challenge.workspace, workspace
            )));
        }
        match challenge.operation.as_str() {
            CHALLENGE_OPERATION_APPROVE
            | CHALLENGE_OPERATION_SUPERSEDE
            | CHALLENGE_OPERATION_REVOKE => {}
            other => {
                return Err(message(format!(
                    "challenge {id} operation {other:?} is not supported"
                )));
            }
        }
        if !challenge.items.is_empty() {
            if challenge.operation != CHALLENGE_OPERATION_APPROVE {
                return Err(message(format!(
                    "challenge {id} operation {:?} is not supported for a batch",
                    challenge.operation
                )));
            }
            if !challenge.claim_id.is_empty()
                || !challenge.canonical_draft_digest.is_empty()
                || !challenge.superseded_ids.is_empty()
                || !challenge.prior_verification_digest.is_empty()
                || !challenge.revoke_reason.is_empty()
            {
                return Err(message(format!(
                    "challenge {id} batch items exclude single-claim fields"
                )));
            }
            normalize_challenge_items(&challenge.items)
                .map_err(|err| message(format!("challenge {id} batch items are invalid: {err}")))?;
        } else if !challenge.granted_items.is_empty() || !challenge.skipped_items.is_empty() {
            return Err(message(format!(
                "challenge {id} item decisions require bound batch items"
            )));
        }
        if challenge.items.is_empty() && !is_claim_id(&challenge.claim_id) {
            return Err(message(format!(
                "challenge {id} claim id must match clm_<32 lowercase hex chars>"
            )));
        }
        if !challenge.canonical_draft_digest.is_empty()
            && !challenge.canonical_draft_digest.starts_with("sha256:")
        {
            return Err(message(format!(
                "challenge {id} canonical draft digest must use sha256:<hex>"
            )));
        }
        if !challenge.prior_verification_digest.is_empty()
            && !challenge.prior_verification_digest.starts_with("sha256:")
        {
            return Err(message(format!(
                "challenge {id} prior verification digest must use sha256:<hex>"
            )));
        }
        for sup in &challenge.superseded_ids {
            if !is_claim_id(sup) {
                return Err(message(format!(
                    "challenge {id} superseded id {sup:?} must match clm_<32 lowercase hex chars>"
                )));
            }
        }
        let challenge_expires_at = parse_expiry(&challenge.expires_at)
            .map_err(|err| message(format!("challenge {id} expires_at must be RFC3339: {err}")))?;
        if challenge.consumed && !challenge.granted {
            return Err(message(format!(
                "challenge {id} is consumed without an owner grant"
            )));
        }
        if challenge.granted {
            if !is_challenge_token_hash(&challenge.token_sha256) {
                return Err(message(format!(
                    "challenge {id} token hash must use sha256:<hex>"
                )));
            }
            if challenge.token_expires_at.trim().is_empty() {
                return Err(message(format!(
                    "challenge {id} token_expires_at is required when granted"
                )));
            }
            let token_expires_at = parse_expiry(&challenge.token_expires_at).map_err(|err| {
                message(format!(
                    "challenge {id} token_expires_at must be RFC3339: {err}"
                ))
            })?;
            if token_expires_at > challenge_expires_at {
                return Err(message(format!(
                    "challenge {id} token expiry must not outlive challenge expiry"
                )));
            }
            if challenge.granted_at.trim().is_empty() {
                return Err(message(format!(
                    "challenge {id} granted_at is required when granted"
                )));
            }
            parse_expiry(&challenge.granted_at).map_err(|err| {
                message(format!("challenge {id} granted_at must be RFC3339: {err}"))
            })?;
        } else {
            if !challenge.token_sha256.is_empty() || !challenge.token_expires_at.is_empty() {
                return Err(message(format!(
                    "challenge {id} token material requires owner grant"
                )));
            }
            if !challenge.granted_at.trim().is_empty() {
                return Err(message(format!(
                    "challenge {id} granted_at requires granted state"
                )));
            }
        }
        if !challenge.items.is_empty() {
            validate_challenge_item_decisions(challenge)?;
        }
        let expected = compute_challenge_action_digest(&ChallengePrepare {
            workspace: challenge.workspace.clone(),
            operation: challenge.operation.clone(),
            claim_id: challenge.claim_id.clone(),
            canonical_draft_digest: challenge.canonical_draft_digest.clone(),
            superseded_ids: challenge.superseded_ids.clone(),
            prior_verification_digest: challenge.prior_verification_digest.clone(),
            revoke_reason: challenge.revoke_reason.clone(),
            items: challenge.items.clone(),
        });
        if expected != challenge.action_digest {
            return Err(message(format!("challenge {id} action digest mismatch")));
        }
        Ok(())
    }

    pub(crate) fn challenge_path(
        &self,
        workspace: &str,
        challenge_id: &str,
    ) -> Result<PathBuf, ClaimError> {
        if !is_challenge_id(challenge_id) {
            return Err(message(
                "challenge id must match chg_<32 lowercase hex chars>",
            ));
        }
        let root = validate_workspace(&self.paths, workspace).map_err(ClaimError::Boundary)?;
        let control_directory = root.join(".zbrain");
        match validate_workspace_control_directory(&root, &control_directory) {
            Ok(()) => {}
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => return Err(ClaimError::Io(source)),
        }
        let directory = control_directory.join("challenges");
        validate_challenge_directory(&root, &directory)?;
        let path = directory.join(format!("{challenge_id}.json"));
        validate_workspace_control_file(&path).map_err(ClaimError::Io)?;
        Ok(path)
    }

    pub(crate) fn write_challenge(
        &self,
        workspace: &str,
        challenge: &Challenge,
    ) -> Result<(), ClaimError> {
        let path = self.challenge_path(workspace, &challenge.id)?;
        ensure_directory_mode(
            path.parent().expect("challenge path has parent"),
            RUNTIME_DIRECTORY_MODE,
        )
        .map_err(|err| message(format!("create challenges directory: {err}")))?;
        self.validate_challenge_record(workspace, challenge)?;
        let mut encoded = serde_json::to_vec_pretty(challenge)
            .map_err(|err| message(format!("marshal challenge {}: {err}", challenge.id)))?;
        encoded.push(b'\n');
        write_atomic_json(&path, &encoded, &challenge.id, "challenge")
    }
}

impl From<&ClaimStore> for ChallengeStore {
    fn from(store: &ClaimStore) -> Self {
        ChallengeStore {
            paths: store.paths.clone(),
            now: store.now.clone(),
        }
    }
}

fn parse_expiry(value: &str) -> Result<chrono::DateTime<chrono::Utc>, String> {
    parse_rfc3339(value).map_err(|err| err.to_string())
}

fn normalize_challenge_items(items: &[ChallengeItem]) -> Result<Vec<ChallengeItem>, ClaimError> {
    if items.is_empty() {
        return Err(message("batch challenge requires at least one item"));
    }
    let mut seen = std::collections::HashSet::new();
    for item in items {
        if !is_claim_id(&item.claim_id) {
            return Err(message(format!(
                "batch challenge claim id {:?} must match clm_<32 lowercase hex chars>",
                item.claim_id
            )));
        }
        if !item.canonical_draft_digest.starts_with("sha256:") {
            return Err(message(format!(
                "batch challenge canonical draft digest for {:?} must use sha256:<hex>",
                item.claim_id
            )));
        }
        if !seen.insert(&item.claim_id) {
            return Err(message(format!(
                "batch challenge binds claim {} more than once",
                item.claim_id
            )));
        }
    }
    Ok(items.to_vec())
}

/// Enforces that a granted batch challenge records granted and skipped claim
/// IDs that partition the bound items exactly.
fn validate_challenge_item_decisions(challenge: &Challenge) -> Result<(), ClaimError> {
    let id = &challenge.id;
    if !challenge.granted {
        if !challenge.granted_items.is_empty() || !challenge.skipped_items.is_empty() {
            return Err(message(format!(
                "challenge {id} item decisions require owner grant"
            )));
        }
        return Ok(());
    }
    let item_index: std::collections::HashSet<&str> = challenge
        .items
        .iter()
        .map(|item| item.claim_id.as_str())
        .collect();
    let mut seen = std::collections::HashSet::new();
    for decided in challenge
        .granted_items
        .iter()
        .chain(challenge.skipped_items.iter())
    {
        if !item_index.contains(decided.as_str()) {
            return Err(message(format!(
                "challenge {id} item decision {decided:?} is not bound"
            )));
        }
        if !seen.insert(decided) {
            return Err(message(format!(
                "challenge {id} records claim {decided} more than once"
            )));
        }
    }
    if challenge.granted_items.len() + challenge.skipped_items.len() != challenge.items.len() {
        return Err(message(format!(
            "challenge {id} item decisions do not cover every bound item"
        )));
    }
    Ok(())
}

pub(crate) fn new_challenge_token() -> Result<(String, String), std::io::Error> {
    let token = crate::claims::random_hex(32)?;
    let sum = Sha256::digest(token.as_bytes());
    Ok((token, format!("sha256:{}", hex(&sum))))
}

pub(crate) fn is_challenge_token_hash(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("sha256:") else {
        return false;
    };
    rest.len() == 32 * 2
        && rest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right) {
        diff |= a ^ b;
    }
    diff == 0
}

fn validate_workspace_control_directory(
    root: &Path,
    directory: &Path,
) -> Result<(), std::io::Error> {
    let info = std::fs::symlink_metadata(directory)?;
    if info.file_type().is_symlink() {
        return Err(std::io::Error::other(
            "workspace control directory must not be a symlink",
        ));
    }
    if !info.is_dir() {
        return Err(std::io::Error::other(
            "workspace control directory is not a directory",
        ));
    }
    let resolved = std::fs::canonicalize(directory)?;
    let resolved = crate::paths::absolute(&resolved)?;
    if !path_within(root, &resolved) {
        return Err(std::io::Error::other(
            "workspace control directory resolves outside workspace",
        ));
    }
    Ok(())
}

pub(crate) fn validate_workspace_control_file(path: &Path) -> Result<(), std::io::Error> {
    let info = match std::fs::symlink_metadata(path) {
        Ok(info) => info,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => return Err(source),
    };
    if info.file_type().is_symlink() {
        return Err(std::io::Error::other(format!(
            "{:?} must not be a symlink",
            path.display()
        )));
    }
    if !info.is_file() {
        return Err(std::io::Error::other(format!(
            "{:?} is not a regular file",
            path.display()
        )));
    }
    let resolved = std::fs::canonicalize(path)?;
    let absolute = crate::paths::absolute(path)?;
    if resolved != absolute {
        return Err(std::io::Error::other(format!(
            "{:?} must not be a symlink",
            path.display()
        )));
    }
    Ok(())
}

fn validate_challenge_directory(root: &Path, directory: &Path) -> Result<(), ClaimError> {
    let Ok(info) = std::fs::symlink_metadata(directory) else {
        return Ok(());
    };
    if info.file_type().is_symlink() {
        return Err(message("challenges directory must not be a symlink"));
    }
    if !info.is_dir() {
        return Err(message("challenges directory is not a directory"));
    }
    let resolved = std::fs::canonicalize(directory).map_err(ClaimError::Io)?;
    let resolved = crate::paths::absolute(&resolved).map_err(ClaimError::Io)?;
    if !path_within(root, &resolved) {
        return Err(message("challenges directory resolves outside workspace"));
    }
    Ok(())
}

/// Atomic metadata write: temp file at 0600 in the target directory, fsync,
/// rename, then re-assert the mode on the final path.
pub(crate) fn write_atomic_json(
    path: &Path,
    encoded: &[u8],
    id: &str,
    what: &str,
) -> Result<(), ClaimError> {
    use std::os::unix::fs::OpenOptionsExt;
    let dir = path.parent().expect("control file path has parent");
    let file_name = path
        .file_name()
        .expect("control file has a name")
        .to_string_lossy()
        .to_string();
    let mut temporary_path = None;
    for attempt in 0..64 {
        let candidate = dir.join(format!(
            ".{file_name}.{}.{}.tmp",
            std::process::id(),
            attempt
        ));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(RUNTIME_METADATA_MODE)
            .open(&candidate)
        {
            Ok(mut file) => {
                file.write_all(encoded)
                    .map_err(|err| message(format!("write {what} {id}: {err}")))?;
                file.sync_all()
                    .map_err(|err| message(format!("sync {what} {id}: {err}")))?;
                drop(file);
                temporary_path = Some(candidate);
                break;
            }
            Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(source) => {
                return Err(message(format!("create {what} temporary file: {source}")));
            }
        }
    }
    let Some(temporary_path) = temporary_path else {
        return Err(message(format!(
            "create {what} temporary file: exhausted attempts"
        )));
    };
    let result = (|| -> Result<(), ClaimError> {
        std::fs::rename(&temporary_path, path)
            .map_err(|err| message(format!("publish {what} {id}: {err}")))?;
        ensure_file_mode(path, RUNTIME_METADATA_MODE).map_err(ClaimError::Io)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary_path);
    }
    result
}

impl ClaimStore {
    /// Binds the owner ceremony for a `claim approve` mutation: the canonical
    /// draft digest, the supersede operation when the draft replaces approved
    /// claims, and the prior verification digest that operation requires. A
    /// pure read; `prepare_challenge` validates it and persists the challenge.
    pub fn approve_challenge_prepare(
        &self,
        workspace: &str,
        id: &str,
    ) -> Result<ChallengePrepare, ClaimError> {
        let (claim, digest) = self.canonical_digest(workspace, id)?;
        if claim.status != CLAIM_STATUS_DRAFT {
            return Err(message(format!(
                "claim {id} is {}; only draft claims can be approved",
                claim.status
            )));
        }
        let mut superseded = claim.supersedes.clone();
        superseded.sort();
        let operation = if superseded.is_empty() {
            CHALLENGE_OPERATION_APPROVE
        } else {
            CHALLENGE_OPERATION_SUPERSEDE
        };
        let prior_verification_digest = if superseded.is_empty() {
            String::new()
        } else {
            self.first_superseded_verification_digest(workspace, &superseded)?
        };
        Ok(ChallengePrepare {
            workspace: workspace.to_string(),
            operation: operation.to_string(),
            claim_id: claim.id.clone(),
            canonical_draft_digest: digest,
            superseded_ids: superseded,
            prior_verification_digest,
            ..ChallengePrepare::default()
        })
    }

    /// Atomically validates the current canonical claim and persists a
    /// challenge under the workspace lock. The general ChallengeStore prepare
    /// method remains available for the local owner ceremony, which does not
    /// require a canonical claim digest.
    pub fn prepare_challenge(
        &self,
        workspace: &str,
        mut prepare: ChallengePrepare,
    ) -> Result<PreparedChallenge, ClaimError> {
        let _lock = crate::coordination::acquire_workspace_lock(&self.paths, workspace, true)
            .map_err(claim_message)?;
        recover_pending_transition_for_mutation_unlocked(&self.paths, workspace)
            .map_err(claim_message)?;
        let (claim, digest) = self.canonical_digest_unlocked(workspace, &prepare.claim_id)?;
        if prepare.canonical_draft_digest.trim().is_empty() {
            prepare.canonical_draft_digest = digest.clone();
        }
        let probe = Challenge {
            workspace: workspace.to_string(),
            operation: prepare.operation.clone(),
            claim_id: prepare.claim_id.clone(),
            canonical_draft_digest: prepare.canonical_draft_digest.clone(),
            superseded_ids: prepare.superseded_ids.clone(),
            prior_verification_digest: prepare.prior_verification_digest.clone(),
            revoke_reason: prepare.revoke_reason.clone(),
            ..Challenge::default()
        };
        self.validate_challenge_against_claim(&probe, &claim, &digest)?;
        ChallengeStore::from(self).prepare_unlocked(workspace, prepare)
    }

    /// Atomically validates every bound draft claim against its current
    /// canonical state and persists one batch challenge under the workspace
    /// lock. An item digest left empty is bound from the current canonical
    /// digest; a non-empty digest must match the canonical state.
    pub fn prepare_batch_challenge(
        &self,
        workspace: &str,
        items: Vec<ChallengeItem>,
    ) -> Result<PreparedChallenge, ClaimError> {
        let _lock = crate::coordination::acquire_workspace_lock(&self.paths, workspace, true)
            .map_err(claim_message)?;
        recover_pending_transition_for_mutation_unlocked(&self.paths, workspace)
            .map_err(claim_message)?;
        let mut bound = items;
        for item in &mut bound {
            let (claim, digest) = self.canonical_digest_unlocked(workspace, &item.claim_id)?;
            if item.canonical_draft_digest.trim().is_empty() {
                item.canonical_draft_digest = digest.clone();
            }
            self.validate_challenge_against_claim(
                &Challenge {
                    id: "batch".to_string(),
                    workspace: workspace.to_string(),
                    operation: CHALLENGE_OPERATION_APPROVE.to_string(),
                    claim_id: claim.id.clone(),
                    canonical_draft_digest: item.canonical_draft_digest.clone(),
                    ..Challenge::default()
                },
                &claim,
                &digest,
            )?;
        }
        ChallengeStore::from(self).prepare_batch_unlocked(workspace, bound)
    }

    /// Validates and consumes a challenge token, then commits the
    /// corresponding claim transition while retaining the same exclusive
    /// workspace lock for the entire operation. Semantic validation completes
    /// before token consumption; commit failures still leave the token
    /// consumed and therefore cannot be retried as an unauthorized mutation.
    pub fn apply_challenge(
        &self,
        workspace: &str,
        challenge_id: &str,
        token: &str,
        options: ClaimMutationOptions,
    ) -> Result<Claim, ClaimError> {
        let _lock = crate::coordination::acquire_workspace_lock(&self.paths, workspace, true)
            .map_err(claim_message)?;
        recover_pending_transition_for_mutation_unlocked(&self.paths, workspace)
            .map_err(claim_message)?;

        let challenge_store = ChallengeStore::from(self);
        let challenge = challenge_store.read_challenge_unlocked(workspace, challenge_id)?;
        challenge_store.validate_token(&challenge, token)?;
        if !challenge.granted {
            return Err(message(format!(
                "challenge {} has not been owner-granted",
                challenge.id
            )));
        }
        let (claim, digest) = self.canonical_digest_unlocked(workspace, &challenge.claim_id)?;
        self.validate_challenge_against_claim(&challenge, &claim, &digest)?;
        if let Some(authorization) = &options.authorization {
            if authorization.challenge_id != challenge.id {
                return Err(message(format!(
                    "claim transition authorization challenge id does not match challenge {}",
                    challenge.id
                )));
            }
        }

        let plan = match challenge.operation.as_str() {
            CHALLENGE_OPERATION_APPROVE | CHALLENGE_OPERATION_SUPERSEDE => {
                self.prepare_approve_unlocked(workspace, &challenge.claim_id, options)?
            }
            CHALLENGE_OPERATION_REVOKE => self.prepare_revoke_unlocked(
                workspace,
                &challenge.claim_id,
                &challenge.revoke_reason,
                options,
            )?,
            other => {
                return Err(message(format!(
                    "challenge {} operation {other:?} is not supported",
                    challenge.id
                )));
            }
        };
        challenge_store.consume_unlocked(workspace, &challenge.id, token)?;
        if challenge.operation == CHALLENGE_OPERATION_REVOKE {
            return self.commit_revoke_unlocked(workspace, plan);
        }
        self.commit_approve_unlocked(workspace, plan)
    }

    /// Validates and consumes a batch challenge token exactly once, then
    /// applies only the owner-granted items while retaining the same exclusive
    /// workspace lock. Every granted item is independently revalidated against
    /// its current canonical state; a failed item never aborts the batch
    /// silently and is reported as failed without being applied. Skipped items
    /// are reported without any mutation. Invalid tokens, expired challenges,
    /// or a mismatched workspace fail closed before any item is applied.
    pub fn apply_challenge_batch(
        &self,
        workspace: &str,
        challenge_id: &str,
        token: &str,
        options: ClaimMutationOptions,
    ) -> Result<BatchApplyResult, ClaimError> {
        let _lock = crate::coordination::acquire_workspace_lock(&self.paths, workspace, true)
            .map_err(claim_message)?;
        recover_pending_transition_for_mutation_unlocked(&self.paths, workspace)
            .map_err(claim_message)?;
        let challenge_store = ChallengeStore::from(self);
        let challenge = challenge_store.read_challenge_unlocked(workspace, challenge_id)?;
        if challenge.items.is_empty() {
            return Err(message(format!(
                "challenge {} is not a batch challenge",
                challenge.id
            )));
        }
        challenge_store.validate_token(&challenge, token)?;
        if let Some(authorization) = &options.authorization {
            if authorization.challenge_id != challenge.id {
                return Err(message(format!(
                    "claim transition authorization challenge id does not match challenge {}",
                    challenge.id
                )));
            }
        }
        let skipped: std::collections::HashSet<&str> = challenge
            .skipped_items
            .iter()
            .map(|id| id.as_str())
            .collect();
        let mut results: Vec<BatchApplyItemResult> = challenge
            .items
            .iter()
            .map(|item| BatchApplyItemResult {
                claim_id: item.claim_id.clone(),
                status: String::new(),
                path: String::new(),
                error: String::new(),
            })
            .collect();
        let mut validated: Vec<(usize, ChallengeItem)> = Vec::with_capacity(challenge.items.len());
        for (index, item) in challenge.items.iter().enumerate() {
            if skipped.contains(item.claim_id.as_str()) {
                results[index].status = BATCH_APPLY_ITEM_SKIPPED.to_string();
                continue;
            }
            let outcome = self
                .canonical_digest_unlocked(workspace, &item.claim_id)
                .and_then(|(claim, digest)| {
                    self.validate_challenge_against_claim(
                        &Challenge {
                            id: challenge.id.clone(),
                            workspace: workspace.to_string(),
                            operation: CHALLENGE_OPERATION_APPROVE.to_string(),
                            claim_id: item.claim_id.clone(),
                            canonical_draft_digest: item.canonical_draft_digest.clone(),
                            ..Challenge::default()
                        },
                        &claim,
                        &digest,
                    )
                });
            if let Err(err) = outcome {
                results[index].status = BATCH_APPLY_ITEM_FAILED.to_string();
                results[index].error = err.to_string();
                continue;
            }
            validated.push((index, item.clone()));
        }
        challenge_store.consume_unlocked(workspace, &challenge.id, token)?;
        for (index, item) in validated {
            let plan =
                match self.prepare_approve_unlocked(workspace, &item.claim_id, options.clone()) {
                    Ok(plan) => plan,
                    Err(err) => {
                        results[index].status = BATCH_APPLY_ITEM_FAILED.to_string();
                        results[index].error = err.to_string();
                        continue;
                    }
                };
            match self.commit_approve_unlocked(workspace, plan) {
                Ok(claim) => {
                    results[index].status = BATCH_APPLY_ITEM_APPLIED.to_string();
                    results[index].path = claim.path;
                }
                Err(err) => {
                    results[index].status = BATCH_APPLY_ITEM_FAILED.to_string();
                    results[index].error = err.to_string();
                }
            }
        }
        Ok(BatchApplyResult {
            challenge_id: challenge.id.clone(),
            items: results,
        })
    }

    pub(crate) fn validate_challenge_against_claim(
        &self,
        challenge: &Challenge,
        claim: &Claim,
        digest: &str,
    ) -> Result<(), ClaimError> {
        let id = &challenge.id;
        if challenge.claim_id != claim.id {
            return Err(message(format!(
                "challenge {id} claim {:?} does not match canonical claim {:?}",
                challenge.claim_id, claim.id
            )));
        }
        if challenge.canonical_draft_digest.trim().is_empty() {
            return Err(message(format!(
                "challenge {id} canonical draft digest is required"
            )));
        }
        if challenge.canonical_draft_digest != digest {
            return Err(message(format!(
                "challenge {id} canonical draft digest is stale"
            )));
        }
        let mut expected_superseded = claim.supersedes.clone();
        expected_superseded.sort();
        let mut actual_superseded = challenge.superseded_ids.clone();
        actual_superseded.sort();
        if !same_strings(&actual_superseded, &expected_superseded) {
            return Err(message(format!(
                "challenge {id} superseded IDs do not match the canonical claim"
            )));
        }
        match challenge.operation.as_str() {
            CHALLENGE_OPERATION_APPROVE => {
                if claim.status != CLAIM_STATUS_DRAFT {
                    return Err(message(format!(
                        "claim {} is {}; only draft claims can be approved",
                        claim.id, claim.status
                    )));
                }
                if !expected_superseded.is_empty() {
                    return Err(message(format!(
                        "challenge {id} approve action has superseded claims; use supersede"
                    )));
                }
                if !challenge.prior_verification_digest.is_empty() {
                    return Err(message(format!(
                        "challenge {id} prior verification digest is not valid for approve"
                    )));
                }
                if !challenge.revoke_reason.is_empty() {
                    return Err(message(format!(
                        "challenge {id} revoke reason is not valid for approve"
                    )));
                }
            }
            CHALLENGE_OPERATION_SUPERSEDE => {
                if claim.status != CLAIM_STATUS_DRAFT {
                    return Err(message(format!(
                        "claim {} is {}; only draft claims can be superseded",
                        claim.id, claim.status
                    )));
                }
                if expected_superseded.is_empty() {
                    return Err(message(format!(
                        "challenge {id} supersede action requires a superseded claim"
                    )));
                }
                let prior = self.first_superseded_verification_digest(
                    &challenge.workspace,
                    &expected_superseded,
                )?;
                if challenge.prior_verification_digest != prior {
                    return Err(message(format!(
                        "challenge {id} prior verification digest is stale"
                    )));
                }
                if !challenge.revoke_reason.is_empty() {
                    return Err(message(format!(
                        "challenge {id} revoke reason is not valid for supersede"
                    )));
                }
            }
            CHALLENGE_OPERATION_REVOKE => {
                if claim.status != CLAIM_STATUS_APPROVED {
                    return Err(message(format!(
                        "claim {} is {}; only approved claims can be revoked",
                        claim.id, claim.status
                    )));
                }
                crate::claims::verify_claim_digest(claim).map_err(|err| {
                    message(format!("verify claim {} before revoke: {err}", claim.id))
                })?;
                if challenge.prior_verification_digest != claim.verified_digest {
                    return Err(message(format!(
                        "challenge {id} prior verification digest is stale"
                    )));
                }
                if challenge.revoke_reason.trim().is_empty() {
                    return Err(message(format!("challenge {id} revoke reason is required")));
                }
            }
            other => {
                return Err(message(format!(
                    "challenge {id} operation {other:?} is not supported"
                )));
            }
        }
        Ok(())
    }

    pub(crate) fn first_superseded_verification_digest(
        &self,
        workspace: &str,
        ids: &[String],
    ) -> Result<String, ClaimError> {
        let Some(first) = ids.first() else {
            return Ok(String::new());
        };
        let claim = self.read(workspace, first)?;
        if claim.status != CLAIM_STATUS_APPROVED {
            return Err(message(format!(
                "claim {} is {}; only approved claims can be superseded",
                claim.id, claim.status
            )));
        }
        crate::claims::verify_claim_digest(&claim)
            .map_err(|err| message(format!("verify superseded claim {}: {err}", claim.id)))?;
        Ok(claim.verified_digest)
    }
}

// ---------------------------------------------------------------------------
// Owner grant walk (port of internal/cli approval show/grant). Prompts go to
// the given diagnostics writer; confirmations come from the injectable
// ApprovalPrompt so the ceremony is drivable without a real terminal.
// ---------------------------------------------------------------------------

/// Last 16 characters of a digest, as confirmed by the owner.
pub fn action_digest_suffix(digest: &str) -> &str {
    if digest.len() < 16 {
        return digest;
    }
    &digest[digest.len() - 16..]
}

fn prompt_line(
    stderr: &mut dyn Write,
    prompt: &mut dyn ApprovalPrompt,
    text: &str,
) -> Result<String, ClaimError> {
    let _ = write!(stderr, "{text}");
    let _ = stderr.flush();
    let confirm = prompt.read_confirmation().map_err(ClaimError::Io)?;
    let _ = writeln!(stderr);
    Ok(confirm)
}

/// One bound item of a batch challenge shown to the owner.
#[derive(Debug, Clone, Serialize)]
pub struct ApprovalShowItem {
    pub claim_id: String,
    pub canonical_draft_digest: String,
    pub digest_suffix: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApprovalShowOutput {
    pub schema_version: u32,
    pub challenge_id: String,
    pub action_digest_suffix: String,
    pub operation: String,
    pub claim_id: String,
    pub workspace: String,
    pub expires_at: String,
    pub token_expires_at: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub items: Vec<ApprovalShowItem>,
}

/// Owner-facing challenge summary for `approval show`.
pub fn approval_show(challenge: &Challenge, workspace: &str) -> ApprovalShowOutput {
    ApprovalShowOutput {
        schema_version: 1,
        challenge_id: challenge.id.clone(),
        action_digest_suffix: action_digest_suffix(&challenge.action_digest).to_string(),
        operation: challenge.operation.clone(),
        claim_id: challenge.claim_id.clone(),
        workspace: workspace.to_string(),
        expires_at: challenge.expires_at.clone(),
        token_expires_at: challenge.token_expires_at.clone(),
        items: challenge
            .items
            .iter()
            .map(|item| ApprovalShowItem {
                claim_id: item.claim_id.clone(),
                canonical_draft_digest: item.canonical_draft_digest.clone(),
                digest_suffix: action_digest_suffix(&item.canonical_draft_digest).to_string(),
            })
            .collect(),
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct GrantSingleOutput {
    pub schema_version: u32,
    pub challenge_id: String,
    pub token: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct GrantBatchOutput {
    pub schema_version: u32,
    pub challenge_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    pub granted_items: Vec<String>,
    pub skipped_items: Vec<String>,
}

/// Single-claim grant walk: the owner confirms the last 16 hex characters of
/// the action digest before the one-time token is released.
pub fn run_grant(
    store: &ChallengeStore,
    challenge: &Challenge,
    workspace: &str,
    stderr: &mut dyn Write,
    prompt: &mut dyn ApprovalPrompt,
) -> Result<GrantSingleOutput, ClaimError> {
    let _ = writeln!(stderr, "action digest: {}", challenge.action_digest);
    let confirm = prompt_line(
        stderr,
        prompt,
        "confirm the last 16 hex characters of the action digest: ",
    )?;
    if confirm.trim() != action_digest_suffix(&challenge.action_digest) {
        return Err(message("approval grant denied: digest suffix mismatch"));
    }
    let _ = writeln!(stderr);
    let granted = store.grant(workspace, &challenge.id)?;
    Ok(GrantSingleOutput {
        schema_version: 1,
        challenge_id: granted.challenge.id,
        token: granted.token,
    })
}

/// Batch grant walk: every bound item must be confirmed by its canonical
/// draft digest suffix or explicitly skipped with the literal input "skip".
/// A mismatched suffix aborts the whole walk before anything is recorded. At
/// the end of the walk one token is issued when at least one item was
/// granted; a fully skipped walk issues no token.
pub fn run_grant_batch(
    store: &ChallengeStore,
    challenge: &Challenge,
    workspace: &str,
    stderr: &mut dyn Write,
    prompt: &mut dyn ApprovalPrompt,
) -> Result<GrantBatchOutput, ClaimError> {
    let mut granted: Vec<String> = Vec::new();
    let mut skipped: Vec<String> = Vec::new();
    for (index, item) in challenge.items.iter().enumerate() {
        let suffix = action_digest_suffix(&item.canonical_draft_digest);
        let _ = writeln!(
            stderr,
            "item {}/{} claim {}",
            index + 1,
            challenge.items.len(),
            item.claim_id
        );
        let _ = writeln!(
            stderr,
            "canonical draft digest: {}",
            item.canonical_draft_digest
        );
        let confirm = prompt_line(
            stderr,
            prompt,
            "confirm the last 16 hex characters of the item digest (or type skip): ",
        )?;
        let input = confirm.trim();
        if input.eq_ignore_ascii_case("skip") {
            skipped.push(item.claim_id.clone());
        } else if input == suffix {
            granted.push(item.claim_id.clone());
        } else {
            return Err(message(format!(
                "approval grant denied: item {} digest suffix mismatch",
                index + 1
            )));
        }
    }
    let _ = writeln!(stderr);
    if granted.is_empty() {
        return Ok(GrantBatchOutput {
            schema_version: 1,
            challenge_id: challenge.id.clone(),
            token: None,
            granted_items: granted,
            skipped_items: skipped,
        });
    }
    let granted_challenge = store.grant_items(workspace, &challenge.id, &granted, &skipped)?;
    Ok(GrantBatchOutput {
        schema_version: 1,
        challenge_id: granted_challenge.challenge.id,
        token: Some(granted_challenge.token),
        granted_items: granted,
        skipped_items: skipped,
    })
}

// ---------------------------------------------------------------------------
// Tests (port of challenge_test.go, challenge_batch_test.go, the challenge
// subset of claim_store_test.go / transition_test.go, and grant-walk cases
// from internal/cli/cli_test.go that are reachable without the m7 CLI).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claims::{
        claim_verification_digest, CLAIM_BASIS_OWNER, CLAIM_STATUS_SUPERSEDED, OKF_CLAIM_TYPE,
    };
    use crate::clock::FixedClock;
    use crate::config::ensure_config;
    use crate::paths::Options;
    use crate::term::{ApprovalPrompt, ScriptedPrompt};
    use crate::workspace::create_workspace;
    use chrono::{TimeZone, Utc};
    use std::path::PathBuf;
    use std::sync::Arc;

    fn fixed_now() -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 30, 9, 0, 0).unwrap()
    }

    fn fixture(name: &str) -> (PathBuf, Paths, FixedClock) {
        let dir =
            std::env::temp_dir().join(format!("zbrain-approval-{}-{name}", std::process::id()));
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

    fn store(paths: &Paths, clock: &FixedClock) -> ClaimStore {
        ClaimStore::with_clock(paths.clone(), Arc::new(*clock))
    }

    fn challenge_store(paths: &Paths, clock: &FixedClock) -> ChallengeStore {
        ChallengeStore::with_clock(paths.clone(), Arc::new(*clock))
    }

    fn clock_at(at: chrono::DateTime<Utc>) -> std::sync::Arc<dyn Clock> {
        Arc::new(FixedClock::new(at))
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

    fn challenge_file(paths: &Paths, id: &str) -> PathBuf {
        paths
            .workspaces_dir
            .join("research/.zbrain/challenges")
            .join(format!("{id}.json"))
    }

    fn hex_repeat(ch: char, count: usize) -> String {
        std::iter::repeat_n(ch, count).collect()
    }

    fn base_prepare(workspace: &str) -> ChallengePrepare {
        ChallengePrepare {
            workspace: workspace.to_string(),
            operation: CHALLENGE_OPERATION_APPROVE.to_string(),
            claim_id: "clm_0123456789abcdef0123456789abcdef".to_string(),
            canonical_draft_digest: format!("sha256:{}", hex_repeat('a', 64)),
            ..ChallengePrepare::default()
        }
    }

    fn write_canonical_claim(paths: &Paths, claim: &Claim) {
        let path = paths
            .workspaces_dir
            .join("research/wiki")
            .join(&claim.tier)
            .join(format!("{}.md", claim.id));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        crate::claims::write_claim_atomic(&path, claim).unwrap();
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

    fn authorization(id: &str) -> Option<ClaimTransitionAuthorization> {
        Some(ClaimTransitionAuthorization {
            challenge_id: id.to_string(),
            method: "claim_lifecycle.apply".to_string(),
            mcp_client: "mcp-client/1.0".to_string(),
        })
    }

    type PrepareMutation<'a> = (&'a str, Box<dyn Fn(&mut ChallengePrepare) + 'a>);
    type ChallengeMutation<'a> = (&'a str, Box<dyn Fn(&mut Challenge) + 'a>);
    use crate::claims::ClaimTransitionAuthorization;

    #[test]
    fn challenge_lifecycle() {
        let (dir, paths, _clock) = fixture("lifecycle");
        let base = Utc.with_ymd_and_hms(2026, 8, 20, 10, 0, 0).unwrap();
        let store = ChallengeStore::with_clock(paths.clone(), clock_at(base));

        let mut prepare = base_prepare("research");
        prepare.superseded_ids = vec!["clm_11111111111111111111111111111111".to_string()];
        prepare.prior_verification_digest = format!("sha256:{}", hex_repeat('b', 64));
        prepare.revoke_reason = "corrected scope".to_string();

        let prepared = store.prepare("research", prepare).unwrap();
        let challenge = &prepared.challenge;
        assert!(is_challenge_id(&challenge.id), "{}", challenge.id);
        assert!(challenge.action_digest.starts_with("sha256:challenge-v1:"));
        assert_eq!(challenge.expires_at, rfc3339(base + challenge_lifetime()));
        assert!(challenge.token_expires_at.is_empty());
        assert!(challenge.token_sha256.is_empty());

        let read = store.read("research", &challenge.id).unwrap();
        assert_eq!(read.action_digest, challenge.action_digest);
        assert!(read.token_sha256.is_empty() && read.token_expires_at.is_empty());
        let err = store
            .verify("research", &challenge.id, "not-issued")
            .unwrap_err();
        assert!(
            err.to_string().contains("has not been owner-granted"),
            "{err}"
        );

        let granted = store.grant("research", &challenge.id).unwrap();
        assert!(
            granted.challenge.granted
                && !granted.challenge.granted_at.is_empty()
                && !granted.token.is_empty()
        );
        let token = granted.token.clone();
        store.verify("research", &challenge.id, &token).unwrap();
        let err = store.grant("research", &challenge.id).unwrap_err();
        assert!(
            err.to_string().contains("already been owner-granted"),
            "{err}"
        );

        store.consume("research", &challenge.id, &token).unwrap();
        assert!(store.consume("research", &challenge.id, &token).is_err());
        assert!(store.verify("research", &challenge.id, &token).is_err());

        let second = store.prepare("research", base_prepare("research")).unwrap();
        assert!(store
            .verify("research", &second.challenge.id, "not-the-token")
            .is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn challenge_lifecycle_no_plaintext_token_on_disk() {
        let (dir, paths, clock) = fixture("notoken");
        let store = challenge_store(&paths, &clock);
        let prepared = store.prepare("research", base_prepare("research")).unwrap();
        let path = challenge_file(&paths, &prepared.challenge.id);
        let before: Challenge = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert!(before.token_sha256.is_empty() && before.token_expires_at.is_empty());
        let granted = challenge_store(&paths, &clock)
            .grant("research", &prepared.challenge.id)
            .unwrap();
        let granted_contents = String::from_utf8(std::fs::read(&path).unwrap()).unwrap();
        assert!(
            !granted_contents.contains(&granted.token),
            "{}",
            granted.token
        );
        let want_hash = format!("sha256:{}", hex(&Sha256::digest(granted.token.as_bytes())));
        assert!(granted_contents.contains(&want_hash), "{granted_contents}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn challenge_lifecycle_digest_binds_all_inputs() {
        let mut base = base_prepare("research");
        base.operation = CHALLENGE_OPERATION_SUPERSEDE.to_string();
        base.superseded_ids = vec!["clm_11111111111111111111111111111111".to_string()];
        base.prior_verification_digest = format!("sha256:{}", hex_repeat('b', 64));
        base.revoke_reason = "corrected scope".to_string();
        let baseline = compute_challenge_action_digest(&base);

        let mutations: Vec<PrepareMutation> = vec![
            (
                "workspace",
                Box::new(|c: &mut ChallengePrepare| c.workspace = "other".to_string()),
            ),
            (
                "operation",
                Box::new(|c: &mut ChallengePrepare| {
                    c.operation = CHALLENGE_OPERATION_REVOKE.to_string()
                }),
            ),
            (
                "claim_id",
                Box::new(|c: &mut ChallengePrepare| {
                    c.claim_id = "clm_22222222222222222222222222222222".to_string()
                }),
            ),
            (
                "canonical_draft_digest",
                Box::new(|c: &mut ChallengePrepare| {
                    c.canonical_draft_digest = format!("sha256:{}", hex_repeat('c', 64))
                }),
            ),
            (
                "superseded_ids",
                Box::new(|c: &mut ChallengePrepare| {
                    c.superseded_ids = vec!["clm_33333333333333333333333333333333".to_string()]
                }),
            ),
            (
                "prior_verification_digest",
                Box::new(|c: &mut ChallengePrepare| {
                    c.prior_verification_digest = format!("sha256:{}", hex_repeat('d', 64))
                }),
            ),
            (
                "revoke_reason",
                Box::new(|c: &mut ChallengePrepare| {
                    c.revoke_reason = "different reason".to_string()
                }),
            ),
        ];
        for (name, mutate) in &mutations {
            let mut got = base.clone();
            mutate(&mut got);
            assert_ne!(
                compute_challenge_action_digest(&got),
                baseline,
                "changing {name} did not change the action digest"
            );
        }

        let mut reordered = base.clone();
        reordered.superseded_ids = vec![base.superseded_ids[0].clone()];
        assert_eq!(compute_challenge_action_digest(&reordered), baseline);
    }

    #[test]
    fn challenge_lifecycle_expiry_enforced() {
        let (dir, paths, _clock) = fixture("expiry");
        let base_time = Utc.with_ymd_and_hms(2026, 8, 20, 10, 0, 0).unwrap();
        let store = ChallengeStore::with_clock(paths.clone(), clock_at(base_time));
        let prepared = store.prepare("research", base_prepare("research")).unwrap();

        let granted = store.grant("research", &prepared.challenge.id).unwrap();
        let token = granted.token;
        let at_token_expiry = ChallengeStore::with_clock(
            paths.clone(),
            clock_at(base_time + challenge_token_lifetime()),
        );
        at_token_expiry
            .verify("research", &prepared.challenge.id, &token)
            .unwrap();
        let after_token_expiry = ChallengeStore::with_clock(
            paths.clone(),
            clock_at(base_time + challenge_token_lifetime() + chrono::Duration::microseconds(1)),
        );
        let err = after_token_expiry
            .verify("research", &prepared.challenge.id, &token)
            .unwrap_err();
        assert!(err.to_string().contains("token expired"), "{err}");

        let after_expiry = ChallengeStore::with_clock(
            paths.clone(),
            clock_at(base_time + challenge_lifetime() + chrono::Duration::microseconds(1)),
        );
        let err = after_expiry
            .verify("research", &prepared.challenge.id, &token)
            .unwrap_err();
        assert!(err.to_string().contains("expired"), "{err}");
        assert!(after_expiry
            .consume("research", &prepared.challenge.id, &token)
            .is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn challenge_token_lifetime_starts_at_grant() {
        let (dir, paths, _clock) = fixture("grantttl");
        let base_time = Utc.with_ymd_and_hms(2026, 8, 20, 10, 0, 0).unwrap();
        let prepare_store = ChallengeStore::with_clock(paths.clone(), clock_at(base_time));
        let prepared = prepare_store
            .prepare("research", base_prepare("research"))
            .unwrap();

        let grant_time = base_time + chrono::Duration::minutes(4);
        let grant_store = ChallengeStore::with_clock(paths.clone(), clock_at(grant_time));
        let granted = grant_store
            .grant("research", &prepared.challenge.id)
            .unwrap();
        assert_eq!(
            granted.challenge.token_expires_at,
            rfc3339(grant_time + challenge_token_lifetime())
        );
        let before_prepare_ttl = ChallengeStore::with_clock(
            paths.clone(),
            clock_at(base_time + chrono::Duration::minutes(6)),
        );
        before_prepare_ttl
            .verify("research", &prepared.challenge.id, &granted.token)
            .unwrap();
        let at_grant_ttl = ChallengeStore::with_clock(
            paths.clone(),
            clock_at(grant_time + challenge_token_lifetime()),
        );
        at_grant_ttl
            .verify("research", &prepared.challenge.id, &granted.token)
            .unwrap();
        let after_grant_ttl = ChallengeStore::with_clock(
            paths.clone(),
            clock_at(grant_time + challenge_token_lifetime() + chrono::Duration::microseconds(1)),
        );
        let err = after_grant_ttl
            .verify("research", &prepared.challenge.id, &granted.token)
            .unwrap_err();
        assert!(err.to_string().contains("token expired"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn challenge_lifecycle_workspace_isolation() {
        let (dir, paths, clock) = fixture("isolation");
        let store = challenge_store(&paths, &clock);
        let prepared = store.prepare("research", base_prepare("research")).unwrap();

        create_workspace(&paths, "second", &clock).unwrap();
        assert!(store.read("second", &prepared.challenge.id).is_err());
        assert!(store.verify("second", &prepared.challenge.id, "").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn challenge_lifecycle_rejects_invalid_prepare() {
        let (dir, paths, clock) = fixture("badprepare");
        let store = challenge_store(&paths, &clock);
        let valid = base_prepare("research");
        let cases: Vec<PrepareMutation> = vec![
            (
                "workspace mismatch",
                Box::new(|c: &mut ChallengePrepare| c.workspace = "other".to_string()),
            ),
            (
                "unsupported operation",
                Box::new(|c: &mut ChallengePrepare| c.operation = "publish".to_string()),
            ),
            (
                "invalid claim id",
                Box::new(|c: &mut ChallengePrepare| c.claim_id = "not-a-claim".to_string()),
            ),
            (
                "invalid draft digest",
                Box::new(|c: &mut ChallengePrepare| {
                    c.canonical_draft_digest = "md5:abc".to_string()
                }),
            ),
            (
                "invalid prior digest",
                Box::new(|c: &mut ChallengePrepare| {
                    c.prior_verification_digest = "not-a-digest".to_string()
                }),
            ),
            (
                "invalid superseded id",
                Box::new(|c: &mut ChallengePrepare| {
                    c.superseded_ids = vec!["../escape".to_string()]
                }),
            ),
            (
                "revoke without reason",
                Box::new(|c: &mut ChallengePrepare| {
                    c.operation = CHALLENGE_OPERATION_REVOKE.to_string();
                    c.revoke_reason = String::new();
                }),
            ),
        ];
        for (name, mutate) in &cases {
            let mut candidate = valid.clone();
            mutate(&mut candidate);
            assert!(store.prepare("research", candidate).is_err(), "{name}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn challenge_rejects_old_schema_and_tampering() {
        let (dir, paths, clock) = fixture("tamper");
        let store = challenge_store(&paths, &clock);
        let prepared = store.prepare("research", base_prepare("research")).unwrap();
        let granted = store.grant("research", &prepared.challenge.id).unwrap();
        let token = granted.token;
        let path = challenge_file(&paths, &prepared.challenge.id);
        let original = std::fs::read(&path).unwrap();
        let write_tampered = |mutate: &dyn Fn(&mut Challenge)| {
            let mut challenge: Challenge = serde_json::from_slice(&original).unwrap();
            mutate(&mut challenge);
            let mut encoded = serde_json::to_vec_pretty(&challenge).unwrap();
            encoded.push(b'\n');
            std::fs::write(&path, encoded).unwrap();
        };
        let restore = || {
            std::fs::write(&path, &original).unwrap();
        };

        write_tampered(&|c| c.schema = "zbrain.challenge/v2".to_string());
        let err = store.read("research", &prepared.challenge.id).unwrap_err();
        assert!(err.to_string().contains("schema mismatch"), "{err}");
        restore();

        write_tampered(&|c| {
            c.granted = true;
            c.granted_at = String::new();
        });
        let err = store.read("research", &prepared.challenge.id).unwrap_err();
        assert!(err.to_string().contains("granted_at is required"), "{err}");
        restore();

        write_tampered(&|c| {
            c.granted = false;
            c.granted_at = rfc3339(fixed_now());
            c.token_sha256 = String::new();
            c.token_expires_at = String::new();
        });
        let err = store.read("research", &prepared.challenge.id).unwrap_err();
        assert!(
            err.to_string()
                .contains("granted_at requires granted state"),
            "{err}"
        );
        restore();

        write_tampered(&|c| {
            c.granted = false;
            c.granted_at = String::new();
            c.token_sha256 = String::new();
            c.token_expires_at = String::new();
            c.consumed = true;
        });
        let err = store.read("research", &prepared.challenge.id).unwrap_err();
        assert!(
            err.to_string().contains("consumed without an owner grant"),
            "{err}"
        );
        restore();

        write_tampered(&|c| c.operation = CHALLENGE_OPERATION_REVOKE.to_string());
        let err = store.read("research", &prepared.challenge.id).unwrap_err();
        assert!(err.to_string().contains("action digest mismatch"), "{err}");
        restore();

        write_tampered(&|c| c.token_sha256 = format!("sha256:{}", hex_repeat('0', 64)));
        let err = store
            .verify("research", &prepared.challenge.id, &token)
            .unwrap_err();
        assert!(err.to_string().contains("token mismatch"), "{err}");
        restore();

        write_tampered(&|c| c.token_expires_at = "not-a-time".to_string());
        let err = store.read("research", &prepared.challenge.id).unwrap_err();
        assert!(err.to_string().contains("token_expires_at"), "{err}");
        restore();

        write_tampered(&|c| {
            let expires = c.expires_at.clone();
            c.token_expires_at = expires;
            c.expires_at = rfc3339(fixed_now() + chrono::Duration::minutes(1));
        });
        let err = store.read("research", &prepared.challenge.id).unwrap_err();
        assert!(err.to_string().contains("must not outlive"), "{err}");
        restore();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn challenge_consume_concurrent_one_winner() {
        let (dir, paths, clock) = fixture("concurrent");
        let store = Arc::new(challenge_store(&paths, &clock));
        let prepared = store.prepare("research", base_prepare("research")).unwrap();
        let granted = store.grant("research", &prepared.challenge.id).unwrap();
        let token = granted.token;
        let attempts = 8;
        let mut handles = Vec::new();
        for _ in 0..attempts {
            let store = Arc::clone(&store);
            let token = token.clone();
            let id = prepared.challenge.id.clone();
            handles.push(std::thread::spawn(move || {
                store.consume("research", &id, &token).is_ok()
            }));
        }
        let mut winners = 0;
        for handle in handles {
            if handle.join().unwrap() {
                winners += 1;
            }
        }
        assert_eq!(
            winners, 1,
            "concurrent consume must have exactly one winner"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- Batch (challenge_batch_test.go) ------------------------------------

    fn batch_claim_ids() -> Vec<String> {
        vec![
            approval_test_claim_id(1),
            approval_test_claim_id(2),
            approval_test_claim_id(3),
        ]
    }

    fn write_batch_drafts(store: &ClaimStore, ids: &[String]) {
        for id in ids {
            store
                .write_draft("research", valid_store_claim(id, CLAIM_BASIS_OWNER))
                .unwrap();
        }
    }

    fn batch_items(ids: &[String]) -> Vec<ChallengeItem> {
        ids.iter()
            .map(|id| ChallengeItem {
                claim_id: id.clone(),
                canonical_draft_digest: String::new(),
            })
            .collect()
    }

    fn batch_item_claim_ids(items: &[ChallengeItem]) -> Vec<String> {
        items.iter().map(|item| item.claim_id.clone()).collect()
    }

    #[test]
    fn batch_challenge() {
        let (dir, paths, clock) = fixture("batch");
        let store = store(&paths, &clock);
        let challenge_store = challenge_store(&paths, &clock);
        let ids = batch_claim_ids();
        write_batch_drafts(&store, &ids);

        let prepared = store
            .prepare_batch_challenge("research", batch_items(&ids))
            .unwrap();
        let challenge = &prepared.challenge;
        assert_eq!(challenge.schema, CHALLENGE_SCHEMA_VERSION);
        assert_eq!(challenge.operation, CHALLENGE_OPERATION_APPROVE);
        assert_eq!(batch_item_claim_ids(&challenge.items), ids);
        for item in &challenge.items {
            let want = store
                .canonical_digest("research", &item.claim_id)
                .map(|(_, digest)| digest)
                .unwrap();
            assert_eq!(item.canonical_draft_digest, want);
        }
        assert_eq!(
            challenge.expires_at,
            rfc3339(fixed_now() + challenge_lifetime())
        );
        assert!(
            challenge.token_sha256.is_empty()
                && challenge.token_expires_at.is_empty()
                && !challenge.granted
        );
        let read = challenge_store.read("research", &challenge.id).unwrap();
        assert_eq!(read.action_digest, challenge.action_digest);

        let reordered = vec![ids[2].clone(), ids[0].clone(), ids[1].clone()];
        let other = store
            .prepare_batch_challenge("research", batch_items(&reordered))
            .unwrap();
        assert_ne!(other.challenge.action_digest, challenge.action_digest);

        let path = challenge_file(&paths, &challenge.id);
        let original = std::fs::read(&path).unwrap();
        let mut tampered: Challenge = serde_json::from_slice(&original).unwrap();
        tampered.items.swap(0, 1);
        let mut encoded = serde_json::to_vec_pretty(&tampered).unwrap();
        encoded.push(b'\n');
        std::fs::write(&path, encoded).unwrap();
        let err = challenge_store.read("research", &challenge.id).unwrap_err();
        assert!(err.to_string().contains("action digest mismatch"), "{err}");

        let single = challenge_store
            .prepare(
                "research",
                ChallengePrepare {
                    workspace: "research".to_string(),
                    operation: CHALLENGE_OPERATION_APPROVE.to_string(),
                    claim_id: ids[0].clone(),
                    canonical_draft_digest: format!("sha256:{}", hex_repeat('a', 64)),
                    ..ChallengePrepare::default()
                },
            )
            .unwrap();
        assert!(single.challenge.items.is_empty() && single.challenge.granted_items.is_empty());
        let read_single = challenge_store
            .read("research", &single.challenge.id)
            .unwrap();
        assert_eq!(read_single.action_digest, single.challenge.action_digest);

        assert!(store
            .prepare_batch_challenge("research", Vec::new())
            .is_err());
        let duplicate = batch_items(&[ids[0].clone(), ids[0].clone()]);
        assert!(store
            .prepare_batch_challenge("research", duplicate)
            .is_err());
        let batch_of_one = store
            .prepare_batch_challenge("research", batch_items(&[ids[1].clone()]))
            .unwrap();
        assert_eq!(batch_of_one.challenge.items.len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn batch_grant() {
        let (dir, paths, clock) = fixture("batchgrant");
        let store = store(&paths, &clock);
        let challenge_store = challenge_store(&paths, &clock);
        let ids = batch_claim_ids();
        write_batch_drafts(&store, &ids);
        let prepare = |order: &[String]| {
            store
                .prepare_batch_challenge("research", batch_items(order))
                .unwrap()
        };

        // grant all issues one token
        let prepared = prepare(&ids);
        let granted = challenge_store
            .grant_items("research", &prepared.challenge.id, &ids, &[])
            .unwrap();
        assert!(
            !granted.token.is_empty()
                && granted.challenge.granted
                && !granted.challenge.granted_at.is_empty()
        );
        assert_eq!(granted.challenge.granted_items, ids);
        assert!(granted.challenge.skipped_items.is_empty());
        challenge_store
            .verify("research", &prepared.challenge.id, &granted.token)
            .unwrap();
        let err = challenge_store
            .grant_items("research", &prepared.challenge.id, &ids, &[])
            .unwrap_err();
        assert!(
            err.to_string().contains("already been owner-granted"),
            "{err}"
        );

        // skip one of three
        let prepared = prepare(&ids);
        let granted = challenge_store
            .grant_items(
                "research",
                &prepared.challenge.id,
                &[ids[0].clone(), ids[2].clone()],
                &[ids[1].clone()],
            )
            .unwrap();
        assert!(!granted.token.is_empty());
        assert_eq!(
            granted.challenge.granted_items,
            vec![ids[0].clone(), ids[2].clone()]
        );
        assert_eq!(granted.challenge.skipped_items, vec![ids[1].clone()]);
        challenge_store
            .read("research", &prepared.challenge.id)
            .unwrap();

        // partial grant issues exactly one token
        let prepared = prepare(&ids);
        let granted = challenge_store
            .grant_items(
                "research",
                &prepared.challenge.id,
                &[ids[1].clone()],
                &[ids[0].clone(), ids[2].clone()],
            )
            .unwrap();
        assert_eq!(granted.token.len(), 64);
        assert_eq!(granted.challenge.granted_items, vec![ids[1].clone()]);
        assert_eq!(
            granted.challenge.skipped_items,
            vec![ids[0].clone(), ids[2].clone()]
        );

        // skip all grants nothing
        let prepared = prepare(&ids);
        let err = challenge_store
            .grant_items("research", &prepared.challenge.id, &[], &ids)
            .unwrap_err();
        assert!(err.to_string().contains("granted no items"), "{err}");
        let unchanged = challenge_store
            .read("research", &prepared.challenge.id)
            .unwrap();
        assert!(
            !unchanged.granted
                && unchanged.token_sha256.is_empty()
                && unchanged.skipped_items.is_empty()
        );

        // decisions must partition the bound items
        let prepared = prepare(&ids);
        assert!(challenge_store
            .grant_items("research", &prepared.challenge.id, &[ids[0].clone()], &[])
            .is_err());
        assert!(challenge_store
            .grant_items(
                "research",
                &prepared.challenge.id,
                &["clm_ffffffffffffffffffffffffffffffff".to_string()],
                &[ids[1].clone(), ids[2].clone()],
            )
            .is_err());
        let unchanged = challenge_store
            .read("research", &prepared.challenge.id)
            .unwrap();
        assert!(!unchanged.granted && unchanged.token_sha256.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn batch_apply() {
        let (dir, paths, clock) = fixture("batchapply");
        let store = store(&paths, &clock);
        let challenge_store = challenge_store(&paths, &clock);
        let ids = batch_claim_ids();
        write_batch_drafts(&store, &ids);

        let prepared = store
            .prepare_batch_challenge("research", batch_items(&ids))
            .unwrap();
        let granted = challenge_store
            .grant_items(
                "research",
                &prepared.challenge.id,
                &[ids[0].clone(), ids[2].clone()],
                &[ids[1].clone()],
            )
            .unwrap();
        let token = granted.token;

        let result = store
            .apply_challenge_batch(
                "research",
                &prepared.challenge.id,
                &token,
                ClaimMutationOptions::default(),
            )
            .unwrap();
        assert_eq!(result.challenge_id, prepared.challenge.id);
        assert_eq!(result.items.len(), 3);
        let want_status = [
            (&ids[0], BATCH_APPLY_ITEM_APPLIED),
            (&ids[1], BATCH_APPLY_ITEM_SKIPPED),
            (&ids[2], BATCH_APPLY_ITEM_APPLIED),
        ];
        for item in &result.items {
            let want = want_status
                .iter()
                .find(|(id, _)| *id == &item.claim_id)
                .unwrap()
                .1;
            assert_eq!(item.status, want, "{}", item.claim_id);
            if item.status == BATCH_APPLY_ITEM_SKIPPED {
                assert!(item.path.is_empty(), "{}", item.claim_id);
            }
        }
        for id in [&ids[0], &ids[2]] {
            let claim = store.read("research", id).unwrap();
            assert_eq!(claim.status, CLAIM_STATUS_APPROVED);
        }
        let skipped_claim = store.read("research", &ids[1]).unwrap();
        assert_eq!(skipped_claim.status, CLAIM_STATUS_DRAFT);
        assert!(skipped_claim.transitions.is_empty());
        let consumed = challenge_store
            .read("research", &prepared.challenge.id)
            .unwrap();
        assert!(consumed.consumed);

        let err = store
            .apply_challenge_batch(
                "research",
                &prepared.challenge.id,
                &token,
                ClaimMutationOptions::default(),
            )
            .unwrap_err();
        assert!(err.to_string().contains("already consumed"), "{err}");

        let candidate = store
            .prepare_batch_challenge("research", batch_items(&[ids[1].clone()]))
            .unwrap();
        let err = store
            .apply_challenge_batch(
                "research",
                &candidate.challenge.id,
                "not-issued",
                ClaimMutationOptions::default(),
            )
            .unwrap_err();
        assert!(
            err.to_string().contains("has not been owner-granted"),
            "{err}"
        );
        let still_draft = store.read("research", &ids[1]).unwrap();
        assert_eq!(still_draft.status, CLAIM_STATUS_DRAFT);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn batch_apply_isolates_failed_items() {
        let (dir, paths, clock) = fixture("batchfail");
        let store = store(&paths, &clock);
        let challenge_store = challenge_store(&paths, &clock);
        let ids = batch_claim_ids();
        write_batch_drafts(&store, &ids);

        let prepared = store
            .prepare_batch_challenge("research", batch_items(&ids))
            .unwrap();
        let granted = challenge_store
            .grant_items("research", &prepared.challenge.id, &ids, &[])
            .unwrap();
        let mut changed = valid_store_claim(&ids[1], CLAIM_BASIS_OWNER);
        changed.body = "Changed after challenge\n".to_string();
        store.write_draft("research", changed).unwrap();

        let result = store
            .apply_challenge_batch(
                "research",
                &prepared.challenge.id,
                &granted.token,
                ClaimMutationOptions::default(),
            )
            .unwrap();
        let mut statuses = std::collections::HashMap::new();
        for item in &result.items {
            statuses.insert(item.claim_id.clone(), item.status.clone());
            if item.status == BATCH_APPLY_ITEM_FAILED {
                assert!(
                    item.error.contains("canonical draft digest is stale"),
                    "{}: {}",
                    item.claim_id,
                    item.error
                );
            }
        }
        assert_eq!(statuses[&ids[1]], BATCH_APPLY_ITEM_FAILED);
        assert_eq!(statuses[&ids[0]], BATCH_APPLY_ITEM_APPLIED);
        assert_eq!(statuses[&ids[2]], BATCH_APPLY_ITEM_APPLIED);
        let failed_claim = store.read("research", &ids[1]).unwrap();
        assert_eq!(failed_claim.status, CLAIM_STATUS_DRAFT);
        for id in [&ids[0], &ids[2]] {
            let claim = store.read("research", id).unwrap();
            assert_eq!(claim.status, CLAIM_STATUS_APPROVED);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn batch_apply_fails_closed_on_expiry_and_wrong_token() {
        let (dir, paths, clock) = fixture("batchclosed");
        let store = store(&paths, &clock);
        let challenge_store = challenge_store(&paths, &clock);
        let ids = batch_claim_ids();
        write_batch_drafts(&store, &ids);

        let prepared = store
            .prepare_batch_challenge("research", batch_items(&ids))
            .unwrap();
        let granted = challenge_store
            .grant_items("research", &prepared.challenge.id, &ids, &[])
            .unwrap();

        let err = store
            .apply_challenge_batch(
                "research",
                &prepared.challenge.id,
                "not-the-token",
                ClaimMutationOptions::default(),
            )
            .unwrap_err();
        assert!(err.to_string().contains("token mismatch"), "{err}");
        for id in &ids {
            let claim = store.read("research", id).unwrap();
            assert_eq!(claim.status, CLAIM_STATUS_DRAFT, "{}", id);
        }
        challenge_store
            .verify("research", &prepared.challenge.id, &granted.token)
            .unwrap();

        let expired_store = ClaimStore::with_clock(
            paths.clone(),
            clock_at(fixed_now() + challenge_lifetime() + chrono::Duration::microseconds(1)),
        );
        let err = expired_store
            .apply_challenge_batch(
                "research",
                &prepared.challenge.id,
                &granted.token,
                ClaimMutationOptions::default(),
            )
            .unwrap_err();
        assert!(err.to_string().contains("expired"), "{err}");
        for id in &ids {
            let claim = store.read("research", id).unwrap();
            assert_eq!(claim.status, CLAIM_STATUS_DRAFT, "{}", id);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn compute_batch_action_digest_covers_items() {
        let items = vec![
            ChallengeItem {
                claim_id: "clm_0123456789abcdef0123456789abcdef".to_string(),
                canonical_draft_digest: format!("sha256:{}", hex_repeat('a', 64)),
            },
            ChallengeItem {
                claim_id: "clm_11111111111111111111111111111111".to_string(),
                canonical_draft_digest: format!("sha256:{}", hex_repeat('b', 64)),
            },
        ];
        let base = ChallengePrepare {
            workspace: "research".to_string(),
            operation: CHALLENGE_OPERATION_APPROVE.to_string(),
            items: items.clone(),
            ..ChallengePrepare::default()
        };
        let baseline = compute_challenge_action_digest(&base);
        assert!(baseline.starts_with("sha256:challenge-v1:"));
        let mutations: Vec<PrepareMutation> = vec![
            (
                "item_digest",
                Box::new(|c: &mut ChallengePrepare| {
                    c.items[1].canonical_draft_digest = format!("sha256:{}", hex_repeat('c', 64));
                }),
            ),
            (
                "item_claim",
                Box::new(|c: &mut ChallengePrepare| {
                    c.items[1].claim_id = "clm_22222222222222222222222222222222".to_string();
                }),
            ),
            (
                "item_order",
                Box::new(|c: &mut ChallengePrepare| {
                    c.items = vec![items[1].clone(), items[0].clone()];
                }),
            ),
            (
                "item_count",
                Box::new(|c: &mut ChallengePrepare| {
                    c.items = items[..1].to_vec();
                }),
            ),
            (
                "workspace",
                Box::new(|c: &mut ChallengePrepare| c.workspace = "other".to_string()),
            ),
        ];
        for (name, mutate) in &mutations {
            let mut got = base.clone();
            mutate(&mut got);
            assert_ne!(
                compute_challenge_action_digest(&got),
                baseline,
                "changing {name} did not change the batch action digest"
            );
        }
        let single = compute_challenge_action_digest(&ChallengePrepare {
            workspace: base.workspace.clone(),
            operation: base.operation.clone(),
            claim_id: items[0].claim_id.clone(),
            canonical_draft_digest: items[0].canonical_draft_digest.clone(),
            ..ChallengePrepare::default()
        });
        assert_ne!(
            single, baseline,
            "batch digest collides with the single-claim digest shape"
        );
    }

    // -- Challenge-gated lifecycle (claim_store_test.go) --------------------

    #[test]
    fn prepare_and_apply_challenge_atomically_authorizes_approval() {
        let (dir, paths, clock) = fixture("applyapprove");
        let store = store(&paths, &clock);
        let claim = valid_store_claim("clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", CLAIM_BASIS_OWNER);
        store.write_draft("research", claim.clone()).unwrap();
        let prepared = store
            .prepare_challenge(
                "research",
                ChallengePrepare {
                    workspace: "research".to_string(),
                    operation: CHALLENGE_OPERATION_APPROVE.to_string(),
                    claim_id: claim.id.clone(),
                    ..ChallengePrepare::default()
                },
            )
            .unwrap();
        let err = store
            .apply_challenge(
                "research",
                &prepared.challenge.id,
                "not-issued",
                ClaimMutationOptions::default(),
            )
            .unwrap_err();
        assert!(
            err.to_string().contains("has not been owner-granted"),
            "{err}"
        );
        let unchanged = store.read("research", &claim.id).unwrap();
        assert_eq!(unchanged.status, CLAIM_STATUS_DRAFT);
        assert!(unchanged.verified_digest.is_empty() && unchanged.transitions.is_empty());
        let unconsumed = challenge_store(&paths, &clock)
            .read("research", &prepared.challenge.id)
            .unwrap();
        assert!(!unconsumed.granted && !unconsumed.consumed);
        let granted = challenge_store(&paths, &clock)
            .grant("research", &prepared.challenge.id)
            .unwrap();
        let token = granted.token;
        let approved = store
            .apply_challenge(
                "research",
                &prepared.challenge.id,
                &token,
                ClaimMutationOptions {
                    verified_by: "owner:mcp".to_string(),
                    authorization: authorization(&prepared.challenge.id),
                },
            )
            .unwrap();
        assert_eq!(approved.status, CLAIM_STATUS_APPROVED);
        assert_eq!(approved.verified_by, "owner:mcp");
        let got = approved.transitions[0].authorization.as_ref().unwrap();
        assert_eq!(got.challenge_id, prepared.challenge.id);
        let err = store
            .apply_challenge(
                "research",
                &prepared.challenge.id,
                &token,
                ClaimMutationOptions::default(),
            )
            .unwrap_err();
        assert!(err.to_string().contains("already consumed"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn apply_challenge_authorizes_supersede_and_revoke() {
        let (dir, paths, clock) = fixture("applysupersede");
        let store = store(&paths, &clock);
        let old = valid_store_claim("clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", CLAIM_BASIS_OWNER);
        store.write_draft("research", old.clone()).unwrap();
        let old_approved = store.approve("research", &old.id).unwrap();
        let replacement =
            valid_store_claim("clm_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", CLAIM_BASIS_OWNER);
        let replacement = store
            .write_superseding_draft("research", &old_approved.id, replacement)
            .unwrap();
        let superseding_digest = store
            .canonical_digest("research", &replacement.id)
            .map(|(_, digest)| digest)
            .unwrap();
        let supersede_challenge = store
            .prepare_challenge(
                "research",
                ChallengePrepare {
                    workspace: "research".to_string(),
                    operation: CHALLENGE_OPERATION_SUPERSEDE.to_string(),
                    claim_id: replacement.id.clone(),
                    canonical_draft_digest: superseding_digest,
                    superseded_ids: replacement.supersedes.clone(),
                    prior_verification_digest: old_approved.verified_digest.clone(),
                    ..ChallengePrepare::default()
                },
            )
            .unwrap();
        let granted_supersede = challenge_store(&paths, &clock)
            .grant("research", &supersede_challenge.challenge.id)
            .unwrap();
        let supersede_token = granted_supersede.token;
        let superseded = store
            .apply_challenge(
                "research",
                &supersede_challenge.challenge.id,
                &supersede_token,
                ClaimMutationOptions {
                    verified_by: "owner:mcp".to_string(),
                    authorization: authorization(&supersede_challenge.challenge.id),
                },
            )
            .unwrap();
        assert_eq!(superseded.status, CLAIM_STATUS_APPROVED);
        assert_eq!(
            superseded.transitions[0].kind,
            crate::claims::CLAIM_TRANSITION_SUPERSEDE
        );
        let old_after = store.read("research", &old.id).unwrap();
        assert_eq!(old_after.status, CLAIM_STATUS_SUPERSEDED);
        let got = old_after.transitions[1].authorization.as_ref().unwrap();
        assert_eq!(got.challenge_id, supersede_challenge.challenge.id);

        let revoke_digest = store
            .canonical_digest("research", &replacement.id)
            .map(|(_, digest)| digest)
            .unwrap();
        let revoke_challenge = store
            .prepare_challenge(
                "research",
                ChallengePrepare {
                    workspace: "research".to_string(),
                    operation: CHALLENGE_OPERATION_REVOKE.to_string(),
                    claim_id: replacement.id.clone(),
                    canonical_draft_digest: revoke_digest,
                    superseded_ids: replacement.supersedes.clone(),
                    prior_verification_digest: superseded.verified_digest.clone(),
                    revoke_reason: "wrong scope".to_string(),
                    ..ChallengePrepare::default()
                },
            )
            .unwrap();
        let granted_revoke = challenge_store(&paths, &clock)
            .grant("research", &revoke_challenge.challenge.id)
            .unwrap();
        let revoked = store
            .apply_challenge(
                "research",
                &revoke_challenge.challenge.id,
                &granted_revoke.token,
                ClaimMutationOptions {
                    verified_by: "owner:mcp".to_string(),
                    authorization: authorization(&revoke_challenge.challenge.id),
                },
            )
            .unwrap();
        assert_eq!(revoked.status, crate::claims::CLAIM_STATUS_REVOKED);
        let got = revoked
            .transitions
            .last()
            .unwrap()
            .authorization
            .as_ref()
            .unwrap();
        assert_eq!(got.challenge_id, revoke_challenge.challenge.id);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn apply_challenge_rejects_stale_canonical_digest_before_consumption() {
        let (dir, paths, clock) = fixture("staledigest");
        let store = store(&paths, &clock);
        let mut claim =
            valid_store_claim("clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", CLAIM_BASIS_OWNER);
        store.write_draft("research", claim.clone()).unwrap();
        let digest = store
            .canonical_digest("research", &claim.id)
            .map(|(_, digest)| digest)
            .unwrap();
        let prepared = store
            .prepare_challenge(
                "research",
                ChallengePrepare {
                    workspace: "research".to_string(),
                    operation: CHALLENGE_OPERATION_APPROVE.to_string(),
                    claim_id: claim.id.clone(),
                    canonical_draft_digest: digest,
                    ..ChallengePrepare::default()
                },
            )
            .unwrap();
        let granted = challenge_store(&paths, &clock)
            .grant("research", &prepared.challenge.id)
            .unwrap();
        let token = granted.token;
        claim.body = "Changed after challenge\n".to_string();
        store.write_draft("research", claim).unwrap();
        let err = store
            .apply_challenge(
                "research",
                &prepared.challenge.id,
                &token,
                ClaimMutationOptions::default(),
            )
            .unwrap_err();
        assert!(
            err.to_string().contains("canonical draft digest is stale"),
            "{err}"
        );
        challenge_store(&paths, &clock)
            .verify("research", &prepared.challenge.id, &token)
            .unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- Coverage helpers (transition_test.go challenge subset) -------------

    #[test]
    fn cover_challenge_low() {
        let (dir, paths, clock) = fixture("coverlow");
        let cstore = challenge_store(&paths, &clock);
        assert!(cstore.challenge_path("research", "bad-id").is_err());
        assert!(cstore
            .challenge_path("../bad", "chg_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .is_err());
        assert!(!is_challenge_token_hash("sha256:zzzz"));
        assert!(is_challenge_token_hash(&format!(
            "sha256:{}",
            hex_repeat('a', 64)
        )));

        let workspace_root = validate_workspace(&paths, "research").unwrap();
        std::fs::create_dir_all(workspace_root.join(".zbrain")).unwrap();
        let control_dir = workspace_root.join(".zbrain/challenges");
        let _ = std::fs::remove_file(&control_dir);
        std::fs::write(&control_dir, b"x").unwrap();
        assert!(cstore
            .challenge_path("research", "chg_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
            .is_err());
        std::fs::remove_file(&control_dir).unwrap();

        let invalid_challenge = Challenge {
            schema: "bad-schema".to_string(),
            id: "chg_cccccccccccccccccccccccccccccccc".to_string(),
            workspace: "research".to_string(),
            operation: CHALLENGE_OPERATION_APPROVE.to_string(),
            claim_id: "clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            expires_at: rfc3339(fixed_now() + challenge_lifetime()),
            ..Challenge::default()
        };
        assert!(cstore
            .write_challenge("research", &invalid_challenge)
            .is_err());

        let claim_store = ClaimStore::with_clock(paths.clone(), clock_at(fixed_now()));
        let claim = valid_store_claim("clm_ffffffffffffffffffffffffffffffff", CLAIM_BASIS_OWNER);
        claim_store.write_draft("research", claim.clone()).unwrap();
        let prepared = cstore
            .prepare(
                "research",
                ChallengePrepare {
                    workspace: "research".to_string(),
                    operation: CHALLENGE_OPERATION_APPROVE.to_string(),
                    claim_id: claim.id,
                    canonical_draft_digest: format!("sha256:{}", hex_repeat('a', 64)),
                    ..ChallengePrepare::default()
                },
            )
            .unwrap();
        let granted = cstore.grant("research", &prepared.challenge.id).unwrap();
        cstore
            .consume("research", &prepared.challenge.id, &granted.token)
            .unwrap();
        cstore.find_challenge(&prepared.challenge.id).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cover_validate_challenge_record_more() {
        let (dir, paths, clock) = fixture("coverrecord");
        let cstore = challenge_store(&paths, &clock);
        let claim_store = ClaimStore::with_clock(paths.clone(), clock_at(fixed_now()));
        let claim = valid_store_claim("clm_99999999999999999999999999999999", CLAIM_BASIS_OWNER);
        claim_store.write_draft("research", claim).unwrap();
        let prepared = cstore
            .prepare(
                "research",
                ChallengePrepare {
                    workspace: "research".to_string(),
                    operation: CHALLENGE_OPERATION_APPROVE.to_string(),
                    claim_id: "clm_99999999999999999999999999999999".to_string(),
                    canonical_draft_digest: format!("sha256:{}", hex_repeat('a', 64)),
                    ..ChallengePrepare::default()
                },
            )
            .unwrap();
        let base = prepared.challenge.clone();
        let cases: Vec<ChallengeMutation> = vec![
            (
                "bad schema",
                Box::new(|c: &mut Challenge| c.schema = "bad".to_string()),
            ),
            (
                "bad id",
                Box::new(|c: &mut Challenge| c.id = "bad".to_string()),
            ),
            (
                "workspace mismatch",
                Box::new(|c: &mut Challenge| c.workspace = "other".to_string()),
            ),
            (
                "bad operation",
                Box::new(|c: &mut Challenge| c.operation = "bad".to_string()),
            ),
            (
                "bad claim id",
                Box::new(|c: &mut Challenge| c.claim_id = "bad".to_string()),
            ),
            (
                "bad expires",
                Box::new(|c: &mut Challenge| c.expires_at = "bad".to_string()),
            ),
            (
                "consumed without granted",
                Box::new(|c: &mut Challenge| {
                    c.consumed = true;
                    c.granted = false;
                }),
            ),
            (
                "granted without token",
                Box::new(|c: &mut Challenge| {
                    c.granted = true;
                    c.token_sha256 = String::new();
                }),
            ),
            (
                "token hash bad",
                Box::new(|c: &mut Challenge| {
                    c.granted = true;
                    c.token_sha256 = "bad".to_string();
                    c.token_expires_at = base.token_expires_at.clone();
                    c.granted_at = base.granted_at.clone();
                }),
            ),
            (
                "action digest mismatch",
                Box::new(|c: &mut Challenge| c.action_digest = "sha256:bad".to_string()),
            ),
        ];
        for (name, mutate) in &cases {
            let mut candidate = base.clone();
            mutate(&mut candidate);
            assert!(
                cstore
                    .validate_challenge_record("research", &candidate)
                    .is_err(),
                "{name}"
            );
        }

        let workspace_root = validate_workspace(&paths, "research").unwrap();
        std::fs::create_dir_all(workspace_root.join(".zbrain")).unwrap();
        let challenges_dir = workspace_root.join(".zbrain/challenges");
        let _ = std::fs::remove_dir_all(&challenges_dir);
        std::fs::write(&challenges_dir, b"x").unwrap();
        assert!(cstore.write_challenge("research", &base).is_err());
        std::fs::remove_file(&challenges_dir).unwrap();

        let expired_store = ChallengeStore::with_clock(
            paths.clone(),
            clock_at(fixed_now() + chrono::Duration::minutes(20)),
        );
        assert!(expired_store.grant("research", &base.id).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn first_superseded_verification_digest_cases() {
        let (dir, paths, clock) = fixture("firstsup");
        let claim_store = store(&paths, &clock);
        let mut approved_claim = valid_store_claim(&approval_test_claim_id(3), CLAIM_BASIS_OWNER);
        approved_claim = finalize_approved_claim(&approved_claim);
        write_canonical_claim(&paths, &approved_claim);
        let got = claim_store
            .first_superseded_verification_digest("research", &[approved_claim.id.clone()])
            .unwrap();
        assert_eq!(got, approved_claim.verified_digest);
        let got = claim_store
            .first_superseded_verification_digest("research", &[])
            .unwrap();
        assert!(got.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- Grant walk (injectable TTY) ----------------------------------------

    fn stderr_of<F>(f: F) -> (String, Result<(), String>)
    where
        F: FnOnce(&mut Vec<u8>) -> Result<(), ClaimError>,
    {
        let mut buffer = Vec::new();
        let result = f(&mut buffer).map_err(|err| err.to_string());
        (String::from_utf8(buffer).unwrap(), result)
    }

    #[test]
    fn grant_walk_single_confirm_and_deny() {
        let (dir, paths, clock) = fixture("grantwalk");
        let store = challenge_store(&paths, &clock);
        let prepared = store.prepare("research", base_prepare("research")).unwrap();
        let challenge = prepared.challenge.clone();
        let suffix = action_digest_suffix(&challenge.action_digest).to_string();

        let (stderr, result) = stderr_of(|out| {
            let mut prompt = ScriptedPrompt::new(&[&suffix]);
            run_grant(&store, &challenge, "research", out, &mut prompt).map(|_| ())
        });
        assert!(result.is_ok(), "{result:?}");
        assert!(stderr.contains("action digest: "), "{stderr}");
        assert!(
            stderr.contains("confirm the last 16 hex characters"),
            "{stderr}"
        );
        store.read("research", &challenge.id).unwrap();

        let prepared = store.prepare("research", base_prepare("research")).unwrap();
        let challenge = prepared.challenge;
        let (_, result) = stderr_of(|out| {
            let mut prompt = ScriptedPrompt::new(&["0000000000000000"]);
            run_grant(&store, &challenge, "research", out, &mut prompt).map(|_| ())
        });
        let err = result.unwrap_err();
        assert!(err.contains("digest suffix mismatch"), "{err}");
        // A denied walk must leave the challenge ungranted.
        let unchanged = store.read("research", &challenge.id).unwrap();
        assert!(!unchanged.granted);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn grant_walk_batch_confirm_skip_and_abort() {
        let (dir, paths, clock) = fixture("grantwalkbatch");
        let claim_store = store(&paths, &clock);
        let store = challenge_store(&paths, &clock);
        let ids = batch_claim_ids();
        write_batch_drafts(&claim_store, &ids);
        let prepared = claim_store
            .prepare_batch_challenge("research", batch_items(&ids))
            .unwrap();
        let challenge = prepared.challenge.clone();
        let suffix_one =
            action_digest_suffix(&challenge.items[0].canonical_draft_digest).to_string();
        let suffix_three =
            action_digest_suffix(&challenge.items[2].canonical_draft_digest).to_string();

        let (stderr, result) =
            batch_walk(&store, &challenge, &[&suffix_one, "skip", &suffix_three]);
        let output = result.unwrap();
        assert_eq!(output.granted_items, vec![ids[0].clone(), ids[2].clone()]);
        assert_eq!(output.skipped_items, vec![ids[1].clone()]);
        assert!(output.token.is_some());
        assert!(
            stderr.contains(&format!(
                "item 1/{} claim {}",
                challenge.items.len(),
                ids[0]
            )),
            "{stderr}"
        );
        assert!(stderr.contains("or type skip"), "{stderr}");
        store.read("research", &challenge.id).unwrap();

        // A fully skipped walk issues no token.
        let prepared = claim_store
            .prepare_batch_challenge("research", batch_items(&[ids[1].clone(), ids[2].clone()]))
            .unwrap();
        let challenge = prepared.challenge;
        let (_, result) = batch_walk(&store, &challenge, &["skip", "skip"]);
        let output = result.unwrap();
        assert!(output.token.is_none());
        assert!(output.granted_items.is_empty());
        let unchanged = store.read("research", &challenge.id).unwrap();
        assert!(!unchanged.granted);

        // A mismatched suffix aborts the whole walk before anything is recorded.
        let prepared = claim_store
            .prepare_batch_challenge("research", batch_items(&[ids[1].clone(), ids[2].clone()]))
            .unwrap();
        let challenge = prepared.challenge;
        let (_, result) = batch_walk(&store, &challenge, &["skip", "zzzz"]);
        let err = result.unwrap_err();
        assert!(err.contains("item 2 digest suffix mismatch"), "{err}");
        let unchanged = store.read("research", &challenge.id).unwrap();
        assert!(!unchanged.granted);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn batch_walk(
        store: &ChallengeStore,
        challenge: &Challenge,
        script: &[&str],
    ) -> (String, Result<GrantBatchOutput, String>) {
        let mut buffer = Vec::new();
        let mut prompt = ScriptedPrompt::new(script);
        let result = run_grant_batch(store, challenge, "research", &mut buffer, &mut prompt)
            .map_err(|err| err.to_string());
        (String::from_utf8(buffer).unwrap(), result)
    }

    #[test]
    fn grant_walk_requires_terminal_prompt_semantics() {
        // The scripted prompt mirrors the injected-reader contract: exhausting
        // the confirmation input fails closed instead of granting.
        let (dir, _paths, _clock) = fixture("grantexhaust");
        let mut prompt = ScriptedPrompt::new(&[]);
        let err = prompt.read_confirmation().unwrap_err();
        assert!(
            err.to_string().contains("requires the confirmation input"),
            "{err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn approval_show_matches_owner_summary_shape() {
        let (dir, paths, clock) = fixture("showshape");
        let claim_store = store(&paths, &clock);
        let store = challenge_store(&paths, &clock);
        let ids = batch_claim_ids();
        write_batch_drafts(&claim_store, &ids);
        let prepared = claim_store
            .prepare_batch_challenge("research", batch_items(&ids))
            .unwrap();
        let shown = approval_show(&prepared.challenge, "research");
        assert_eq!(shown.schema_version, 1);
        assert_eq!(shown.challenge_id, prepared.challenge.id);
        assert_eq!(shown.operation, CHALLENGE_OPERATION_APPROVE);
        assert_eq!(shown.workspace, "research");
        assert_eq!(shown.items.len(), 3);
        assert_eq!(
            shown.items[0].digest_suffix,
            action_digest_suffix(&prepared.challenge.items[0].canonical_draft_digest)
        );

        let single = store.prepare("research", base_prepare("research")).unwrap();
        let shown = approval_show(&single.challenge, "research");
        assert!(shown.items.is_empty());
        assert_eq!(
            shown.action_digest_suffix,
            action_digest_suffix(&single.challenge.action_digest)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
