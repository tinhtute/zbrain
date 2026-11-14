//! evidence.rs — port of internal/runtime/evidence.go (m2 surface): immutable
//! write-once snapshots (raw + source.yaml at 0400), SHA-256 duplicate skip,
//! workspace-boundary reads, verify (tamper/size/hash/metadata), validator
//! cache, and read-only origin drift classification.

use std::collections::{BTreeMap, HashMap};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

use serde::Serialize;
use yaml_rust2::Yaml as YamlValue;

use crate::yaml::de::{self, Error as YamlParseError};
use sha2::{Digest as ShaDigest, Sha256};

use crate::boundary::{resolve_workspace_path, validate_workspace, BoundaryError};
use crate::claims::{is_evidence_id, ClaimError, ClaimStore};
use crate::clock::{parse_rfc3339, Clock};
use crate::coordination::{
    acquire_workspace_lock, begin_canonical_mutation_unlocked, run_workspace_generation_test_hook,
    LockError, MutationError,
};
use crate::paths::{
    ensure_directory_mode, ensure_file_mode, set_permissions, Paths, EVIDENCE_DIRECTORY_MODE,
    EVIDENCE_FILE_MODE,
};
use crate::yaml::{self, Yaml};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Evidence {
    pub id: String,
    pub origin: String,
    pub captured_at: String,
    pub media_type: String,
    pub byte_length: i64,
    pub sha256: String,
    #[serde(skip)]
    pub deduped: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceVerification {
    pub id: String,
    pub path: String,
    pub reason: String,
}

impl std::fmt::Display for EvidenceVerification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "evidence verification failed for {} at {}: {}",
            self.id, self.path, self.reason
        )
    }
}

#[derive(Debug)]
pub enum EvidenceError {
    Boundary(BoundaryError),
    Io(std::io::Error),
    Verification(EvidenceVerification),
    Mutation(MutationError),
    Message(String),
}

impl std::fmt::Display for EvidenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Boundary(source) => write!(f, "{source}"),
            Self::Io(source) => write!(f, "{source}"),
            Self::Verification(source) => write!(f, "{source}"),
            Self::Mutation(source) => write!(f, "{source}"),
            Self::Message(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for EvidenceError {}

impl From<std::io::Error> for EvidenceError {
    fn from(source: std::io::Error) -> Self {
        Self::Io(source)
    }
}

impl From<BoundaryError> for EvidenceError {
    fn from(source: BoundaryError) -> Self {
        Self::Boundary(source)
    }
}

impl From<MutationError> for EvidenceError {
    fn from(source: MutationError) -> Self {
        Self::Mutation(source)
    }
}

impl From<ClaimError> for EvidenceError {
    fn from(source: ClaimError) -> Self {
        Self::Message(source.to_string())
    }
}

impl From<LockError> for EvidenceError {
    fn from(source: LockError) -> Self {
        Self::Message(source.to_string())
    }
}

impl Evidence {
    fn from_map(map: &BTreeMap<String, YamlValue>) -> Result<Self, YamlParseError> {
        Ok(Self {
            id: de::string(map, "id")?,
            origin: de::string(map, "origin")?,
            captured_at: de::string(map, "captured_at")?,
            media_type: de::string(map, "media_type")?,
            byte_length: de::integer(map, "byte_length")?,
            sha256: de::string(map, "sha256")?,
            deduped: false,
        })
    }
}

impl From<YamlParseError> for EvidenceError {
    fn from(source: YamlParseError) -> Self {
        Self::Message(source.to_string())
    }
}

pub fn evidence_metadata_path(id: &str) -> String {
    format!("evidence/sources/{id}/source.yaml")
}

pub fn evidence_raw_path(id: &str) -> String {
    format!("evidence/sources/{id}/raw")
}

pub const EVIDENCE_SNAPSHOT_DIGEST_PREFIX: &str = "sha256:evidence-v1:";

pub fn evidence_snapshot_digest(metadata: &[u8], evidence: &Evidence) -> String {
    let mut hash = Sha256::new();
    hash.update(b"zbrain.evidence/v1\n");
    hash.update(format!("metadata-length:{}\n", metadata.len()));
    hash.update(metadata);
    hash.update(format!(
        "\nraw-byte-length:{}\nraw-sha256:{}\n",
        evidence.byte_length, evidence.sha256
    ));
    format!(
        "{}{}",
        EVIDENCE_SNAPSHOT_DIGEST_PREFIX,
        hex_lower(&hash.finalize())
    )
}

pub fn is_legacy_evidence_digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .map(is_evidence_sha256)
        .unwrap_or(false)
}

pub fn is_evidence_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sha256_hex(contents: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(contents);
    hex_lower(&hash.finalize())
}

pub struct EvidenceStore {
    pub paths: Paths,
}

impl EvidenceStore {
    pub fn new(paths: Paths) -> Self {
        Self { paths }
    }

    pub fn add_file(
        &self,
        workspace: &str,
        source_path: &Path,
        origin: &str,
        media_type: &str,
        clock: &impl Clock,
    ) -> Result<Evidence, EvidenceError> {
        let _lock = acquire_workspace_lock(&self.paths, workspace, true)?;
        crate::transition::recover_pending_transition_for_mutation_unlocked(&self.paths, workspace)
            .map_err(|err| EvidenceError::Message(err.to_string()))?;
        validate_workspace(&self.paths, workspace)?;

        if origin.trim().is_empty() {
            return Err(EvidenceError::Message("evidence origin is required".into()));
        }
        let media_type = if media_type.trim().is_empty() {
            "application/octet-stream".to_string()
        } else {
            media_type.to_string()
        };
        let digest = hash_evidence_source_file(source_path)?;
        if let Some(existing) = self.lookup_evidence_by_sha256(workspace, &digest)? {
            let mut existing = existing;
            existing.deduped = true;
            return Ok(existing);
        }

        let mut source = std::fs::File::open(source_path)?;
        let id = crate::claims::new_evidence_id()?;
        let root = self.evidence_root(workspace, &id)?;
        match std::fs::symlink_metadata(&root) {
            Ok(_) => {
                return Err(EvidenceError::Message(format!(
                    "evidence {id} already exists"
                )))
            }
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => return Err(source.into()),
        }
        begin_canonical_mutation_unlocked(&self.paths, workspace)?;
        for relative in ["evidence", "evidence/sources"] {
            let directory = resolve_workspace_path(&self.paths, workspace, relative)?;
            ensure_directory_mode(&directory, EVIDENCE_DIRECTORY_MODE)?;
        }
        ensure_directory_mode(&root, EVIDENCE_DIRECTORY_MODE)?;
        let created = self.write_snapshot(
            workspace,
            &id,
            &mut source,
            origin,
            &media_type,
            &digest,
            clock,
        );
        match created {
            Ok(evidence) => Ok(evidence),
            Err(err) => {
                let _ = std::fs::remove_dir_all(&root);
                Err(err)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn write_snapshot(
        &self,
        workspace: &str,
        id: &str,
        source: &mut std::fs::File,
        origin: &str,
        media_type: &str,
        digest: &str,
        clock: &impl Clock,
    ) -> Result<Evidence, EvidenceError> {
        let raw_path = self.evidence_file_path(workspace, id, "raw")?;
        run_workspace_generation_test_hook(
            crate::coordination::WORKSPACE_GENERATION_HOOK_BEFORE_CANONICAL_WRITE,
        );
        use std::os::unix::fs::OpenOptionsExt;
        let mut raw = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(EVIDENCE_FILE_MODE)
            .open(&raw_path)?;
        let mut hash = Sha256::new();
        let mut written: u64 = 0;
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let read = source.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            hash.update(&buffer[..read]);
            raw.write_all(&buffer[..read])?;
            written += read as u64;
        }
        drop(raw);
        ensure_file_mode(&raw_path, EVIDENCE_FILE_MODE)?;

        let actual = hex_lower(&hash.finalize());
        if actual != digest {
            return Err(EvidenceError::Message(
                "source file changed during capture".into(),
            ));
        }
        let evidence = Evidence {
            id: id.to_string(),
            origin: origin.to_string(),
            captured_at: crate::clock::rfc3339(clock.now()),
            media_type: media_type.to_string(),
            byte_length: written as i64,
            sha256: digest.to_string(),
            deduped: false,
        };
        let metadata = yaml::emit(&evidence_to_yaml(&evidence));
        let metadata_path = self.evidence_file_path(workspace, id, "source.yaml")?;
        // create_new (not truncate): the fresh evd_* dir is ours, but a
        // racing writer must never silently replace metadata either.
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&metadata_path)
                .map_err(EvidenceError::from)?;
            file.write_all(&metadata).map_err(EvidenceError::from)?;
        }
        set_permissions(&metadata_path, EVIDENCE_FILE_MODE)?;
        ensure_file_mode(&metadata_path, EVIDENCE_FILE_MODE)?;
        Ok(evidence)
    }

    pub fn read(&self, workspace: &str, id: &str) -> Result<Evidence, EvidenceError> {
        if !is_evidence_id(id) {
            return Err(EvidenceError::Message(
                "evidence id must match evd_<32 lowercase hex chars>".into(),
            ));
        }
        let metadata_path = self.evidence_file_path(workspace, id, "source.yaml")?;
        let contents = std::fs::read(&metadata_path)?;
        let evidence = Evidence::from_map(&de::document(&contents)?)?;
        if evidence.id != id {
            return Err(EvidenceError::Message(format!(
                "evidence metadata id {:?} does not match path id {id:?}",
                evidence.id
            )));
        }
        Ok(evidence)
    }

    pub fn verify(&self, workspace: &str, id: &str) -> Result<(), EvidenceError> {
        let mut validator = EvidenceValidator::new(self.paths.clone(), workspace)?;
        validator.verify(id).map_err(EvidenceError::Verification)
    }

    pub fn read_raw(&self, workspace: &str, id: &str) -> Result<Vec<u8>, EvidenceError> {
        if !is_evidence_id(id) {
            return Err(EvidenceError::Message(
                "evidence id must match evd_<32 lowercase hex chars>".into(),
            ));
        }
        let raw_path = self.evidence_file_path(workspace, id, "raw")?;
        Ok(std::fs::read(&raw_path)?)
    }

    /// CheckDrift: strictly read-only re-hash of every locally checkable
    /// origin against its recorded metadata.
    pub fn check_drift(&self, workspace: &str) -> Result<EvidenceDriftReport, EvidenceError> {
        validate_workspace(&self.paths, workspace)?;
        let mut affected: HashMap<String, Vec<String>> = HashMap::new();
        let scan = ClaimStore::new(self.paths.clone()).scan_workspace(workspace)?;
        for claim in &scan.claims {
            for id in &claim.evidence_ids {
                affected
                    .entry(id.clone())
                    .or_default()
                    .push(claim.id.clone());
            }
        }
        let sources_root = resolve_workspace_path(&self.paths, workspace, "evidence/sources")?;
        let entries = match std::fs::read_dir(&sources_root) {
            Ok(entries) => entries,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                return Ok(EvidenceDriftReport {
                    workspace: workspace.to_string(),
                    findings: Vec::new(),
                });
            }
            Err(source) => return Err(source.into()),
        };
        let mut findings = Vec::new();
        for entry in entries.filter_map(|entry| entry.ok()) {
            let name = entry.file_name().to_string_lossy().to_string();
            let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
            if !is_dir || !is_evidence_id(&name) {
                continue;
            }
            let Ok(evidence) = self.read(workspace, &name) else {
                continue;
            };
            let claim_ids = affected.get(&evidence.id).cloned().unwrap_or_default();
            findings.push(classify_evidence_drift(evidence, &claim_ids));
        }
        findings.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(EvidenceDriftReport {
            workspace: workspace.to_string(),
            findings,
        })
    }

    fn evidence_root(&self, workspace: &str, id: &str) -> Result<PathBuf, EvidenceError> {
        if !is_evidence_id(id) {
            return Err(EvidenceError::Message(
                "evidence id must match evd_<32 lowercase hex chars>".into(),
            ));
        }
        resolve_workspace_path(&self.paths, workspace, &format!("evidence/sources/{id}"))
            .map_err(EvidenceError::Boundary)
    }

    fn evidence_file_path(
        &self,
        workspace: &str,
        id: &str,
        name: &str,
    ) -> Result<PathBuf, EvidenceError> {
        if !is_evidence_id(id) {
            return Err(EvidenceError::Message(
                "evidence id must match evd_<32 lowercase hex chars>".into(),
            ));
        }
        resolve_workspace_path(
            &self.paths,
            workspace,
            &format!("evidence/sources/{id}/{name}"),
        )
        .map_err(EvidenceError::Boundary)
    }

    fn lookup_evidence_by_sha256(
        &self,
        workspace: &str,
        digest: &str,
    ) -> Result<Option<Evidence>, EvidenceError> {
        let sources_dir = resolve_workspace_path(&self.paths, workspace, "evidence/sources")?;
        let entries = match std::fs::read_dir(&sources_dir) {
            Ok(entries) => entries,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(source) => return Err(source.into()),
        };
        let mut ids: Vec<String> = entries
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_type().map(|t| t.is_dir()).unwrap_or(false))
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .filter(|name| is_evidence_id(name))
            .collect();
        ids.sort();
        for id in &ids {
            let Ok(evidence) = self.read(workspace, id) else {
                continue;
            };
            if evidence.sha256 == digest {
                return Ok(Some(evidence));
            }
        }
        Ok(None)
    }
}

pub fn evidence_to_yaml(evidence: &Evidence) -> Yaml {
    Yaml::map(vec![
        ("id", Yaml::scalar(&evidence.id)),
        ("origin", Yaml::scalar(&evidence.origin)),
        ("captured_at", Yaml::scalar(&evidence.captured_at)),
        ("media_type", Yaml::scalar(&evidence.media_type)),
        (
            "byte_length",
            Yaml::Scalar {
                value: evidence.byte_length.to_string(),
                style: yaml::YamlStyle::Plain,
            },
        ),
        ("sha256", Yaml::scalar(&evidence.sha256)),
    ])
}

pub struct EvidenceValidator {
    pub(crate) paths: Paths,
    pub(crate) workspace: String,
    cache: HashMap<String, Option<EvidenceVerification>>,
    snapshot_digests: HashMap<String, String>,
    verify_counts: HashMap<String, u32>,
}

impl EvidenceValidator {
    pub fn new(paths: Paths, workspace: &str) -> Result<Self, EvidenceError> {
        validate_workspace(&paths, workspace)?;
        Ok(Self {
            paths,
            workspace: workspace.to_string(),
            cache: HashMap::new(),
            snapshot_digests: HashMap::new(),
            verify_counts: HashMap::new(),
        })
    }

    pub fn snapshot_digest(&self, id: &str) -> Option<&String> {
        self.snapshot_digests.get(id)
    }

    pub fn verify_count(&self, id: &str) -> u32 {
        self.verify_counts.get(id).copied().unwrap_or(0)
    }

    pub fn verify(&mut self, id: &str) -> Result<(), EvidenceVerification> {
        if let Some(cached) = self.cache.get(id) {
            return match cached {
                None => Ok(()),
                Some(verification) => Err(verification.clone()),
            };
        }
        *self.verify_counts.entry(id.to_string()).or_insert(0) += 1;
        let result = self.verify_uncached(id);
        self.cache.insert(id.to_string(), result.clone().err());
        result
    }

    fn verify_uncached(&mut self, id: &str) -> Result<(), EvidenceVerification> {
        let failure = |path: &str, reason: String| EvidenceVerification {
            id: id.to_string(),
            path: path.to_string(),
            reason,
        };
        if !is_evidence_id(id) {
            return Err(failure(
                &evidence_metadata_path(id),
                "evidence id is unsafe".into(),
            ));
        }
        let metadata_path =
            match resolve_workspace_path(&self.paths, &self.workspace, &evidence_metadata_path(id))
            {
                Ok(path) => path,
                Err(err) => {
                    return Err(failure(
                        &evidence_metadata_path(id),
                        format!("resolve metadata path: {err}"),
                    ));
                }
            };
        let contents = match std::fs::read(&metadata_path) {
            Ok(contents) => contents,
            Err(err) => {
                return Err(failure(
                    &evidence_metadata_path(id),
                    format!("read metadata: {err}"),
                ));
            }
        };
        let evidence = match de::document(&contents).and_then(|map| Evidence::from_map(&map)) {
            Ok(evidence) => evidence,
            Err(err) => {
                return Err(failure(
                    &evidence_metadata_path(id),
                    format!("parse metadata: {err}"),
                ));
            }
        };
        if let Err(err) = validate_evidence_metadata(id, &evidence) {
            return Err(failure(&evidence_metadata_path(id), err));
        }

        let raw_path =
            match resolve_workspace_path(&self.paths, &self.workspace, &evidence_raw_path(id)) {
                Ok(path) => path,
                Err(err) => {
                    return Err(failure(
                        &evidence_raw_path(id),
                        format!("resolve raw path: {err}"),
                    ));
                }
            };
        let raw = match std::fs::read(&raw_path) {
            Ok(raw) => raw,
            Err(err) => {
                return Err(failure(
                    &evidence_raw_path(id),
                    format!("read raw bytes: {err}"),
                ));
            }
        };
        if raw.len() as i64 != evidence.byte_length {
            return Err(failure(
                &evidence_raw_path(id),
                format!("byte length = {}, want {}", raw.len(), evidence.byte_length),
            ));
        }
        let actual = sha256_hex(&raw);
        if actual != evidence.sha256 {
            return Err(failure(
                &evidence_raw_path(id),
                format!("sha256 = {actual}, want {}", evidence.sha256),
            ));
        }
        self.snapshot_digests.insert(
            id.to_string(),
            evidence_snapshot_digest(&contents, &evidence),
        );
        Ok(())
    }
}

fn claim_message(err: impl std::fmt::Display) -> ClaimError {
    ClaimError::Message(err.to_string())
}

pub fn evidence_span_digest(
    snapshot_digest: &str,
    start_line: i64,
    end_line: i64,
    raw_bytes: &[u8],
) -> String {
    let mut hash = Sha256::new();
    hash.update(format!(
        "zbrain.span/v1\nsnapshot:{snapshot_digest}\nrange:{start_line}-{end_line}\n"
    ));
    hash.update(raw_bytes);
    format!("sha256:span-v1:{}", hex_lower(&hash.finalize()))
}

fn split_evidence_lines(raw: &[u8]) -> Vec<&[u8]> {
    if raw.is_empty() {
        return vec![&[]];
    }
    let mut lines = Vec::with_capacity(1);
    let mut start = 0usize;
    for (index, byte) in raw.iter().enumerate() {
        if *byte == b'\n' {
            lines.push(&raw[start..index + 1]);
            start = index + 1;
        }
    }
    if start < raw.len() {
        lines.push(&raw[start..]);
    }
    lines
}

/// Port of validateClaimEvidence: the evidence-id set must verify against the
/// snapshot digests, and approved claims must carry a source closure that
/// matches the current metadata exactly.
pub(crate) fn validate_claim_evidence(
    validator: &mut EvidenceValidator,
    claim: &crate::claims::Claim,
) -> Result<(), ClaimError> {
    let mut ids = claim.evidence_ids.clone();
    ids.sort();
    let mut seen_ids = std::collections::HashSet::new();
    for id in &ids {
        if !seen_ids.insert(id.clone()) {
            return Err(ClaimError::Message(format!(
                "claim {} has duplicate evidence id {id}",
                claim.id
            )));
        }
        validator.verify(id).map_err(|verification| {
            ClaimError::Message(format!("evidence {id}: {verification}"))
        })?;
    }
    if claim.status != crate::claims::CLAIM_STATUS_APPROVED {
        return Ok(());
    }

    let mut approved_sources: HashMap<String, &crate::claims::ClaimSource> = HashMap::new();
    for source in &claim.sources {
        if approved_sources.contains_key(&source.id) {
            return Err(ClaimError::Message(format!(
                "claim {} has duplicate evidence source {}",
                claim.id, source.id
            )));
        }
        if !seen_ids.contains(&source.id) {
            return Err(ClaimError::Message(format!(
                "claim {} evidence source closure does not match approved evidence ids",
                claim.id
            )));
        }
        approved_sources.insert(source.id.clone(), source);
    }
    if approved_sources.len() != seen_ids.len() {
        return Err(ClaimError::Message(format!(
            "claim {} evidence source closure does not match approved evidence ids",
            claim.id
        )));
    }
    let store = EvidenceStore::new(validator.paths.clone());
    for id in &ids {
        let evidence = store.read(&validator.workspace, id).map_err(|err| {
            ClaimError::Message(format!("evidence {id}: read current metadata: {err}"))
        })?;
        let source = approved_sources.get(id).ok_or_else(|| {
            ClaimError::Message(format!(
                "claim {} evidence source closure does not match approved evidence ids",
                claim.id
            ))
        })?;
        let expected_resource = format!("evidence/sources/{id}/raw");
        if source.resource != expected_resource || source.title != evidence.origin {
            return Err(ClaimError::Message(format!(
                "evidence {id} source reference does not match current metadata"
            )));
        }
        let current_digest = validator.snapshot_digest(id).cloned().unwrap_or_default();
        if source.digest == current_digest {
            validate_evidence_spans(validator, id, source, &current_digest)?;
            continue;
        }
        if is_legacy_evidence_digest(&source.digest) {
            return Err(ClaimError::Message(format!(
                "evidence {id} uses legacy raw digest; supersede and reapprove claim {} to bind metadata and raw bytes",
                claim.id
            )));
        }
        return Err(ClaimError::Message(format!(
            "evidence {id} digest mismatch: approved {}, current {current_digest}",
            source.digest
        )));
    }
    Ok(())
}

fn validate_evidence_spans(
    validator: &EvidenceValidator,
    evidence_id: &str,
    source: &crate::claims::ClaimSource,
    snapshot_digest: &str,
) -> Result<(), ClaimError> {
    if source.spans.is_empty() {
        return Ok(());
    }
    let raw_path = EvidenceStore::new(validator.paths.clone())
        .evidence_file_path(&validator.workspace, evidence_id, "raw")
        .map_err(claim_message)?;
    let raw = std::fs::read(&raw_path).map_err(|err| {
        ClaimError::Message(format!("evidence {evidence_id}: read span bytes: {err}"))
    })?;
    if std::str::from_utf8(&raw).is_err() {
        return Err(ClaimError::Message(format!(
            "evidence {evidence_id} spans require valid UTF-8 raw evidence"
        )));
    }
    let lines = split_evidence_lines(&raw);
    for span in &source.spans {
        if span.evidence_id != evidence_id {
            return Err(ClaimError::Message(format!(
                "evidence span id {} does not match source {evidence_id}",
                span.evidence_id
            )));
        }
        if span.start_line < 1
            || span.end_line < span.start_line
            || span.end_line > lines.len() as i64
        {
            return Err(ClaimError::Message(format!(
                "evidence {evidence_id} span line range {}-{} is out of range",
                span.start_line, span.end_line
            )));
        }
        let joined: Vec<u8> =
            lines[(span.start_line - 1) as usize..span.end_line as usize].concat();
        let want = evidence_span_digest(snapshot_digest, span.start_line, span.end_line, &joined);
        if span.digest != want {
            return Err(ClaimError::Message(format!(
                "evidence {evidence_id} span digest mismatch"
            )));
        }
    }
    Ok(())
}

pub fn validate_evidence_metadata(id: &str, evidence: &Evidence) -> Result<(), String> {
    if !is_evidence_id(&evidence.id) {
        return Err(format!("metadata id {:?} is unsafe", evidence.id));
    }
    if evidence.id != id {
        return Err(format!(
            "metadata id {:?} does not match requested id {id:?}",
            evidence.id
        ));
    }
    if evidence.origin.trim().is_empty() {
        return Err("metadata origin is required".into());
    }
    if parse_rfc3339(&evidence.captured_at).is_err() {
        return Err("metadata captured_at must be RFC3339".into());
    }
    if let Err(err) = check_media_type(&evidence.media_type) {
        return Err(format!("metadata media_type is invalid: {err}"));
    }
    if evidence.byte_length < 0 {
        return Err("metadata byte_length must be non-negative".into());
    }
    if !is_evidence_sha256(&evidence.sha256) {
        return Err("metadata sha256 must be 64 lowercase hexadecimal characters".into());
    }
    Ok(())
}

/// Subset of Go's mime.ParseMediaType sufficient for snapshot media types:
/// type/subtype tokens plus optional parameters.
fn check_media_type(value: &str) -> Result<(), String> {
    let base = value.split(';').next().unwrap_or("");
    let base = base.trim().to_lowercase();
    check_media_type_disposition(&base)?;
    for param in value.split(';').skip(1) {
        let param = param.trim();
        let Some((key, raw_value)) = param.split_once('=') else {
            return Err("mime: invalid media parameter".into());
        };
        let key = key.trim();
        if key.is_empty()
            || !key
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c))
        {
            return Err("mime: invalid media parameter".into());
        }
        let raw_value = raw_value.trim();
        if raw_value.starts_with('"') {
            if raw_value.len() < 2 || !raw_value.ends_with('"') {
                return Err("mime: invalid media parameter".into());
            }
        } else if raw_value.is_empty()
            || !raw_value
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~:/?@[]".contains(c))
        {
            return Err("mime: invalid media parameter".into());
        }
    }
    Ok(())
}

fn consume_token(value: &str) -> (&str, &str) {
    let end = value
        .find(|c: char| {
            !((c as u32) > 0x20 && (c as u32) < 0x7f && !"()<>@,;:\\\"/[]?=".contains(c))
        })
        .unwrap_or(value.len());
    (&value[..end], &value[end..])
}

fn check_media_type_disposition(value: &str) -> Result<(), String> {
    let (typ, rest) = consume_token(value);
    if typ.is_empty() {
        return Err("mime: no media type".into());
    }
    if rest.is_empty() {
        return Ok(());
    }
    if !rest.starts_with('/') {
        return Err("mime: expected slash after first token".into());
    }
    let (subtype, rest) = consume_token(&rest[1..]);
    if subtype.is_empty() {
        return Err("mime: expected token after slash".into());
    }
    if !rest.is_empty() {
        return Err("mime: unexpected content after media subtype".into());
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum EvidenceDriftStatus {
    Unchanged,
    Changed,
    Missing,
    Uncheckable,
}

pub const EVIDENCE_DRIFT_RECOVERY_ACTION: &str =
    "supersede and re-approve affected claims against a fresh evidence snapshot";

#[derive(Debug, Clone, Serialize)]
pub struct EvidenceDriftFinding {
    pub id: String,
    pub origin: String,
    pub status: EvidenceDriftStatus,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub recorded_sha256: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub recomputed_sha256: String,
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub recorded_byte_length: i64,
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub recomputed_byte_length: i64,
    pub affected_claim_ids: Vec<String>,
    pub recovery_action: String,
}

fn is_zero_i64(value: &i64) -> bool {
    *value == 0
}

#[derive(Debug, Clone, Serialize)]
pub struct EvidenceDriftReport {
    pub workspace: String,
    pub findings: Vec<EvidenceDriftFinding>,
}

fn classify_evidence_drift(
    evidence: Evidence,
    affected_claim_ids: &[String],
) -> EvidenceDriftFinding {
    let mut affected: Vec<String> = affected_claim_ids.to_vec();
    affected.sort();
    let mut finding = EvidenceDriftFinding {
        id: evidence.id.clone(),
        origin: evidence.origin.clone(),
        status: EvidenceDriftStatus::Unchanged,
        recorded_sha256: evidence.sha256.clone(),
        recomputed_sha256: String::new(),
        recorded_byte_length: evidence.byte_length,
        recomputed_byte_length: 0,
        affected_claim_ids: affected,
        recovery_action: "no action required".into(),
    };
    let Some(local_path) = evidence_origin_local_path(&evidence.origin) else {
        finding.status = EvidenceDriftStatus::Uncheckable;
        finding.recovery_action =
            "origin is not locally checkable; supersede and re-approve against a fresh snapshot if drift is suspected"
                .into();
        return finding;
    };
    match hash_local_origin(Path::new(&local_path)) {
        Ok((recomputed, length)) => {
            finding.recomputed_sha256 = recomputed.clone();
            finding.recomputed_byte_length = length;
            if recomputed != evidence.sha256 || length != evidence.byte_length {
                finding.status = EvidenceDriftStatus::Changed;
                finding.recovery_action = EVIDENCE_DRIFT_RECOVERY_ACTION.into();
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            finding.status = EvidenceDriftStatus::Missing;
            finding.recovery_action = EVIDENCE_DRIFT_RECOVERY_ACTION.into();
        }
        Err(_) => {
            finding.status = EvidenceDriftStatus::Uncheckable;
            finding.recovery_action =
                "origin cannot be read locally; supersede and re-approve against a fresh snapshot if drift is suspected"
                    .into();
        }
    }
    finding
}

/// Resolve an origin recorded at evidence add time to a local filesystem path.
/// Non-file URI schemes are reported as uncheckable.
fn evidence_origin_local_path(origin: &str) -> Option<String> {
    if let Some((scheme, rest)) = origin.split_once("://") {
        if scheme.is_empty() || !is_uri_scheme(scheme) {
            return None;
        }
        if !scheme.eq_ignore_ascii_case("file") {
            return None;
        }
        return Some(rest.trim_start_matches("//").to_string());
    }
    Some(origin.to_string())
}

fn is_uri_scheme(value: &str) -> bool {
    for (index, c) in value.chars().enumerate() {
        let ok = c.is_ascii_alphabetic()
            || (index > 0 && (c.is_ascii_digit() || c == '+' || c == '-' || c == '.'));
        if !ok {
            return false;
        }
    }
    true
}

fn hash_local_origin(path: &Path) -> Result<(String, i64), std::io::Error> {
    let mut file = std::fs::File::open(path)?;
    let mut hash = Sha256::new();
    let mut written: u64 = 0;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
        written += read as u64;
    }
    Ok((hex_lower(&hash.finalize()), written as i64))
}

fn hash_evidence_source_file(path: &Path) -> Result<String, EvidenceError> {
    let mut source = std::fs::File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = source.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
    }
    Ok(hex_lower(&hash.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claims::Claim;
    use crate::clock::{rfc3339, FixedClock};
    use crate::config::ensure_config;
    use crate::paths::Options;
    use chrono::{TimeZone, Utc};

    fn fixture(name: &str) -> (PathBuf, Paths, FixedClock) {
        let dir =
            std::env::temp_dir().join(format!("zbrain-evidence-{}-{name}", std::process::id()));
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
        let clock = FixedClock::new(Utc.with_ymd_and_hms(2026, 7, 30, 10, 0, 0).unwrap());
        crate::workspace::create_workspace(&paths, "research", &clock).unwrap();
        (dir, paths, clock)
    }

    fn write_source(dir: &Path, body: &[u8]) -> PathBuf {
        let path = dir.join(format!(
            "source-{}.txt",
            crate::claims::random_hex(6).unwrap()
        ));
        std::fs::write(&path, body).unwrap();
        path
    }

    fn add_evidence(
        paths: &Paths,
        dir: &Path,
        workspace: &str,
        body: &[u8],
        origin: &str,
        media_type: &str,
    ) -> Evidence {
        let source = write_source(dir, body);
        EvidenceStore::new(paths.clone())
            .add_file(workspace, &source, origin, media_type, &fixture_clock())
            .unwrap()
    }

    fn fixture_clock() -> FixedClock {
        FixedClock::new(Utc.with_ymd_and_hms(2026, 7, 30, 10, 0, 0).unwrap())
    }

    #[test]
    fn evidence_snapshot_stores_immutable_local_copy() {
        let (dir, paths, _clock) = fixture("immutable");
        let source = write_source(&dir, b"original evidence");

        let store = EvidenceStore::new(paths.clone());
        let evidence = store
            .add_file(
                "research",
                &source,
                "file://source.txt",
                "text/plain",
                &fixture_clock(),
            )
            .unwrap();
        assert!(is_evidence_id(&evidence.id), "{}", evidence.id);
        assert_eq!(evidence.sha256, sha256_hex(b"original evidence"));

        std::fs::write(&source, b"mutated source").unwrap();
        let loaded = store.read("research", &evidence.id).unwrap();
        assert_eq!(loaded.sha256, evidence.sha256);
        assert_eq!(loaded.byte_length, evidence.byte_length);
        let raw = std::fs::read(
            paths
                .workspaces_dir
                .join("research/evidence/sources")
                .join(&evidence.id)
                .join("raw"),
        )
        .unwrap();
        assert_eq!(raw, b"original evidence");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn evidence_hash_verification_detects_tamper() {
        let (dir, paths, _clock) = fixture("tamper");
        let source = write_source(&dir, b"trusted evidence");
        let store = EvidenceStore::new(paths.clone());
        let evidence = store
            .add_file(
                "research",
                &source,
                source.to_str().unwrap(),
                "text/plain",
                &fixture_clock(),
            )
            .unwrap();
        let raw = paths
            .workspaces_dir
            .join("research/evidence/sources")
            .join(&evidence.id)
            .join("raw");
        unlock_file(&raw);
        std::fs::write(&raw, b"tampered").unwrap();
        assert!(store.verify("research", &evidence.id).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn evidence_workspace_isolation() {
        let (dir, paths, clock) = fixture("isolation");
        crate::workspace::create_workspace(&paths, "personal", &clock).unwrap();
        let store = EvidenceStore::new(paths.clone());
        let evidence = add_evidence(
            &paths,
            &dir,
            "research",
            b"workspace scoped",
            "origin",
            "text/plain",
        );
        assert!(store.read("personal", &evidence.id).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn evidence_workspace_boundary_rejects_symlink_escape() {
        let (dir, paths, _clock) = fixture("escape");
        let store = EvidenceStore::new(paths.clone());
        let id = "evd_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let outside = dir.join("outside-evd");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("source.yaml"), format!("id: {id}\n")).unwrap();
        let root = paths
            .workspaces_dir
            .join("research/evidence/sources")
            .join(id);
        std::os::unix::fs::symlink(&outside, &root).unwrap();
        assert!(store.read("research", id).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn evidence_dirty_barrier_leaves_canonical_tree_unchanged() {
        let (dir, paths, _clock) = fixture("dirtybarrier");
        let mut dirty_paths = paths.clone();
        dirty_paths.indexes_dir = dir.join("indexes-blocker");
        std::fs::write(&dirty_paths.indexes_dir, b"not a directory").unwrap();
        let sources_dir = paths.workspaces_dir.join("research/evidence/sources");
        let before = std::fs::read_dir(&sources_dir).unwrap().count();
        let source = write_source(&dir, b"evidence");
        let result = EvidenceStore::new(dirty_paths.clone()).add_file(
            "research",
            &source,
            "file://source.txt",
            "text/plain",
            &fixture_clock(),
        );
        assert!(result.is_err());
        let after = std::fs::read_dir(&sources_dir).unwrap().count();
        assert_eq!(after, before, "evidence tree changed after dirty failure");
        assert!(!dirty_paths.indexes_dir.join("research.dirty").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn evidence_add_rejects_unsafe_and_missing_workspace_without_mutation() {
        let (dir, paths, _clock) = fixture("unsafews");
        let source = write_source(&dir, b"evidence");
        let store = EvidenceStore::new(paths.clone());
        for workspace in ["../outside", "missing"] {
            assert!(
                store
                    .add_file(
                        workspace,
                        &source,
                        "file://source.txt",
                        "text/plain",
                        &fixture_clock()
                    )
                    .is_err(),
                "{workspace}"
            );
        }
        assert!(!paths.workspaces_dir.join("outside").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn evidence_add_file_skips_duplicate_sha256() {
        let (dir, paths, _clock) = fixture("dedup");
        let store = EvidenceStore::new(paths.clone());
        let source = write_source(&dir, b"original evidence");
        let first = store
            .add_file(
                "research",
                &source,
                "file://source.txt",
                "text/plain",
                &fixture_clock(),
            )
            .unwrap();
        assert!(!first.deduped);
        let metadata = std::fs::read_to_string(
            paths
                .workspaces_dir
                .join("research/evidence/sources")
                .join(&first.id)
                .join("source.yaml"),
        )
        .unwrap();
        assert!(!metadata.contains("deduped"), "{metadata}");
        let before = crate::coordination::read_workspace_generation(&paths, "research").unwrap();

        let second = store
            .add_file(
                "research",
                &source,
                "file://other-origin",
                "application/json",
                &fixture_clock(),
            )
            .unwrap();
        assert_eq!(second.id, first.id);
        assert!(second.deduped);
        assert_eq!(second.origin, first.origin);
        assert_eq!(second.media_type, first.media_type);
        let ids = evidence_source_ids(&paths, "research");
        assert_eq!(ids, vec![first.id.clone()]);
        let raw = std::fs::read(
            paths
                .workspaces_dir
                .join("research/evidence/sources")
                .join(&first.id)
                .join("raw"),
        )
        .unwrap();
        assert_eq!(raw, b"original evidence");
        let after = crate::coordination::read_workspace_generation(&paths, "research").unwrap();
        assert_eq!(
            after.current, before.current,
            "generation current bumped on skip"
        );

        let other = write_source(&dir, b"other evidence");
        let third = store
            .add_file(
                "research",
                &other,
                "file://other.txt",
                "text/plain",
                &fixture_clock(),
            )
            .unwrap();
        assert_ne!(third.id, first.id);
        assert!(!third.deduped);
        assert_eq!(evidence_source_ids(&paths, "research").len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn evidence_source_ids(paths: &Paths, workspace: &str) -> Vec<String> {
        let mut ids = Vec::new();
        for entry in std::fs::read_dir(
            paths
                .workspaces_dir
                .join(workspace)
                .join("evidence/sources"),
        )
        .unwrap()
        .filter_map(|entry| entry.ok())
        {
            let name = entry.file_name().to_string_lossy().to_string();
            if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) && is_evidence_id(&name) {
                ids.push(name);
            }
        }
        ids.sort();
        ids
    }

    #[test]
    fn evidence_check_classifies_origin_drift() {
        let (dir, paths, _clock) = fixture("drift");
        let origin_dir = dir.join("origins");
        std::fs::create_dir_all(&origin_dir).unwrap();
        let write_origin = |name: &str, contents: &[u8]| {
            let path = origin_dir.join(name);
            std::fs::write(&path, contents).unwrap();
            path
        };
        let unchanged_path = write_origin("unchanged.txt", b"unchanged origin");
        let scheme_path = write_origin("scheme.txt", b"scheme origin");
        let changed_path = write_origin("changed.txt", b"changed origin");
        let missing_path = write_origin("missing.txt", b"missing origin");

        let store = EvidenceStore::new(paths.clone());
        let unchanged = add_evidence(
            &paths,
            &dir,
            "research",
            b"unchanged origin",
            unchanged_path.to_str().unwrap(),
            "text/plain",
        );
        let scheme = add_evidence(
            &paths,
            &dir,
            "research",
            b"scheme origin",
            &format!("file://{scheme_path}", scheme_path = scheme_path.display()),
            "text/plain",
        );
        let changed = add_evidence(
            &paths,
            &dir,
            "research",
            b"changed origin",
            changed_path.to_str().unwrap(),
            "text/plain",
        );
        let missing = add_evidence(
            &paths,
            &dir,
            "research",
            b"missing origin",
            missing_path.to_str().unwrap(),
            "text/plain",
        );
        let remote = add_evidence(
            &paths,
            &dir,
            "research",
            b"remote origin",
            "https://example.com/remote.txt",
            "text/plain",
        );

        let claim_id = crate::claims::new_claim_id().unwrap();
        ClaimStore::new(paths.clone())
            .write_draft(
                "research",
                Claim {
                    claim_type: crate::claims::OKF_CLAIM_TYPE.into(),
                    id: claim_id.clone(),
                    tier: "projects".into(),
                    status: crate::claims::CLAIM_STATUS_DRAFT.into(),
                    title: "changed evidence backs this claim".into(),
                    basis: crate::claims::CLAIM_BASIS_EVIDENCE.into(),
                    created_at: rfc3339(fixture_clock().now()),
                    created_by: "owner".into(),
                    evidence_ids: vec![changed.id.clone(), unchanged.id.clone()],
                    body: "The claim body.\n".into(),
                    ..Claim::default()
                },
            )
            .unwrap();

        std::fs::write(&changed_path, b"mutated origin").unwrap();
        std::fs::remove_file(&missing_path).unwrap();

        let report = store.check_drift("research").unwrap();
        let statuses: HashMap<String, &EvidenceDriftFinding> = report
            .findings
            .iter()
            .map(|finding| (finding.id.clone(), finding))
            .collect();
        assert_eq!(report.findings.len(), 5);
        assert_eq!(
            statuses[&unchanged.id].status,
            EvidenceDriftStatus::Unchanged
        );
        assert_eq!(statuses[&scheme.id].status, EvidenceDriftStatus::Unchanged);
        assert_eq!(
            statuses[&remote.id].status,
            EvidenceDriftStatus::Uncheckable
        );
        let changed_finding = statuses[&changed.id];
        assert_eq!(changed_finding.status, EvidenceDriftStatus::Changed);
        assert_eq!(changed_finding.recorded_sha256, changed.sha256);
        assert_ne!(changed_finding.recomputed_sha256, changed.sha256);
        assert!(changed_finding.recovery_action.contains("supersede"));
        assert!(changed_finding.recovery_action.contains("re-approve"));
        assert_eq!(statuses[&missing.id].status, EvidenceDriftStatus::Missing);
        assert!(statuses[&missing.id].recovery_action.contains("supersede"));
        assert_eq!(changed_finding.affected_claim_ids, vec![claim_id.clone()]);
        assert_eq!(
            statuses[&unchanged.id].affected_claim_ids,
            vec![claim_id.clone()]
        );
        assert!(statuses[&remote.id].affected_claim_ids.is_empty());
        assert!(statuses[&scheme.id].affected_claim_ids.is_empty());
        assert_eq!(
            statuses[&unchanged.id].recovery_action,
            "no action required"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn verification_fixture(name: &str) -> (PathBuf, Paths, Evidence, FixedClock) {
        let (dir, paths, _clock) = fixture(name);
        let store = EvidenceStore::new(paths.clone());
        let source = write_source(&dir, b"trusted evidence");
        let evidence = store
            .add_file(
                "research",
                &source,
                source.to_str().unwrap(),
                "text/plain",
                &fixture_clock(),
            )
            .unwrap();
        (dir, paths, evidence, fixture_clock())
    }

    fn rewrite_metadata(paths: &Paths, path_id: &str, evidence: &Evidence) {
        use std::os::unix::fs::PermissionsExt;
        let path = paths
            .workspaces_dir
            .join("research/evidence/sources")
            .join(path_id)
            .join("source.yaml");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::write(&path, yaml::emit(&evidence_to_yaml(evidence))).unwrap();
    }

    fn unlock_file(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
    }

    #[test]
    fn evidence_verify_metadata() {
        type MetadataCase = (&'static str, Box<dyn Fn(&mut Evidence)>, &'static str);
        let cases: Vec<MetadataCase> = vec![
            (
                "id mismatch",
                Box::new(|e: &mut Evidence| e.id = "evd_cccccccccccccccccccccccccccccccc".into()),
                "metadata id",
            ),
            (
                "missing origin",
                Box::new(|e: &mut Evidence| e.origin = String::new()),
                "metadata origin",
            ),
            (
                "invalid capture time",
                Box::new(|e: &mut Evidence| e.captured_at = "not-a-time".into()),
                "captured_at",
            ),
            (
                "invalid media type",
                Box::new(|e: &mut Evidence| e.media_type = "not media".into()),
                "media_type",
            ),
            (
                "negative byte length",
                Box::new(|e: &mut Evidence| e.byte_length = -1),
                "byte_length",
            ),
            (
                "invalid sha256",
                Box::new(|e: &mut Evidence| e.sha256 = "not-a-sha256".into()),
                "sha256",
            ),
        ];
        for (name, mutate, want) in cases {
            let (dir, paths, evidence, _clock) = verification_fixture("verifymetadata");
            let path_id = evidence.id.clone();
            let mut evidence = evidence;
            mutate(&mut evidence);
            rewrite_metadata(&paths, &path_id, &evidence);
            let store = EvidenceStore::new(paths.clone());
            let err = store.verify("research", &path_id).unwrap_err().to_string();
            assert!(err.contains(want), "{name}: {err}");
            let _ = std::fs::remove_dir_all(&dir);
        }

        let (dir, paths, evidence, _clock) = verification_fixture("verifymalformed");
        let metadata_path = paths
            .workspaces_dir
            .join("research/evidence/sources")
            .join(&evidence.id)
            .join("source.yaml");
        unlock_file(&metadata_path);
        std::fs::write(&metadata_path, b"id: [\n").unwrap();
        let store = EvidenceStore::new(paths.clone());
        let err = store
            .verify("research", &evidence.id)
            .unwrap_err()
            .to_string();
        assert!(err.contains("parse metadata"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn evidence_verify_missing() {
        let (dir, paths, evidence, _clock) = verification_fixture("verifymissingmeta");
        let metadata_path = paths
            .workspaces_dir
            .join("research/evidence/sources")
            .join(&evidence.id)
            .join("source.yaml");
        std::fs::rename(&metadata_path, metadata_path.with_extension("yaml.missing")).unwrap();
        let store = EvidenceStore::new(paths.clone());
        let err = store
            .verify("research", &evidence.id)
            .unwrap_err()
            .to_string();
        assert!(err.contains("source.yaml"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);

        let (dir, paths, evidence, _clock) = verification_fixture("verifymissingraw");
        let raw_path = paths
            .workspaces_dir
            .join("research/evidence/sources")
            .join(&evidence.id)
            .join("raw");
        std::fs::rename(&raw_path, raw_path.with_extension("raw.missing")).unwrap();
        let store = EvidenceStore::new(paths.clone());
        let err = store
            .verify("research", &evidence.id)
            .unwrap_err()
            .to_string();
        assert!(err.contains("raw"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn evidence_verify_size() {
        let (dir, paths, evidence, _clock) = verification_fixture("verifysize");
        let mut evidence = evidence;
        evidence.byte_length += 1;
        rewrite_metadata(&paths, &evidence.id, &evidence);
        let store = EvidenceStore::new(paths.clone());
        let err = store
            .verify("research", &evidence.id)
            .unwrap_err()
            .to_string();
        assert!(err.contains("byte length"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn evidence_verify_hash() {
        let (dir, paths, evidence, _clock) = verification_fixture("verifyhashraw");
        let raw_path = paths
            .workspaces_dir
            .join("research/evidence/sources")
            .join(&evidence.id)
            .join("raw");
        let len = evidence.byte_length as usize;
        unlock_file(&raw_path);
        std::fs::write(&raw_path, "x".repeat(len)).unwrap();
        let store = EvidenceStore::new(paths.clone());
        let err = store
            .verify("research", &evidence.id)
            .unwrap_err()
            .to_string();
        assert!(err.contains("sha256"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);

        let (dir, paths, evidence, _clock) = verification_fixture("verifyhashmeta");
        let mut evidence = evidence;
        evidence.sha256 = "0".repeat(64);
        rewrite_metadata(&paths, &evidence.id, &evidence);
        let store = EvidenceStore::new(paths.clone());
        let err = store
            .verify("research", &evidence.id)
            .unwrap_err()
            .to_string();
        assert!(err.contains("sha256"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn evidence_verify_workspace() {
        let (dir, paths, clock) = fixture("verifyws");
        crate::workspace::create_workspace(&paths, "personal", &clock).unwrap();
        let store = EvidenceStore::new(paths.clone());
        let source = write_source(&dir, b"workspace scoped");
        let evidence = store
            .add_file(
                "research",
                &source,
                source.to_str().unwrap(),
                "text/plain",
                &fixture_clock(),
            )
            .unwrap();
        let mut validator = EvidenceValidator::new(paths.clone(), "personal").unwrap();
        let err = validator.verify(&evidence.id).unwrap_err().to_string();
        assert!(err.contains("source.yaml"), "{err}");
        assert!(EvidenceValidator::new(paths.clone(), "../outside").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn evidence_verify_cache() {
        let (dir, paths, evidence, _clock) = verification_fixture("verifycache");
        let mut validator = EvidenceValidator::new(paths.clone(), "research").unwrap();
        validator.verify(&evidence.id).unwrap();

        let raw_path = paths
            .workspaces_dir
            .join("research/evidence/sources")
            .join(&evidence.id)
            .join("raw");
        unlock_file(&raw_path);
        std::fs::write(&raw_path, "x".repeat(evidence.byte_length as usize)).unwrap();
        validator
            .verify(&evidence.id)
            .expect("cached verify must succeed");
        assert_eq!(validator.verify_count(&evidence.id), 1);

        let mut fresh = EvidenceValidator::new(paths.clone(), "research").unwrap();
        assert!(
            fresh.verify(&evidence.id).is_err(),
            "fresh verify must detect the tamper"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn evidence_metadata_fixture_round_trips_byte_identically() {
        let contents = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/evidence-source.yaml"),
        )
        .unwrap();
        let evidence = Evidence::from_map(&de::document(&contents).unwrap()).unwrap();
        assert_eq!(yaml::emit(&evidence_to_yaml(&evidence)), contents);
        let _ = fixture("metafixture");
    }

    #[test]
    fn evidence_snapshot_digest_matches_go_formula() {
        let evidence = Evidence {
            id: "evd_0123456789abcdef0123456789abcdef".into(),
            origin: "file://source.txt".into(),
            captured_at: "2026-07-30T10:00:00Z".into(),
            media_type: "text/plain".into(),
            byte_length: 17,
            sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
            deduped: false,
        };
        let metadata = yaml::emit(&evidence_to_yaml(&evidence));
        // Same formula as the Go evidenceSnapshotDigest; cross-checked by the
        // parity claims op which compares approved source digests.
        let digest = evidence_snapshot_digest(&metadata, &evidence);
        assert!(digest.starts_with("sha256:evidence-v1:"));
        assert_eq!(digest.len(), "sha256:evidence-v1:".len() + 64);
        let _ = parse_rfc3339(&evidence.captured_at).unwrap();
    }
}
