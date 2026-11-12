//! index.rs — port of internal/runtime/index.go: the disposable FTS5 index
//! over wiki-tier claims, its dirty-marker lifecycle, freshness checks, and
//! the FTS query builder.

use std::collections::{HashMap, HashSet};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::Connection;
use serde::Serialize;

use crate::boundary::{safe_relative_path, validate_workspace, BoundaryError};
use crate::claims::{
    is_known_claim_status, Claim, ClaimError, ClaimStore, InvalidClaim, CLAIM_STATUS_APPROVED,
    CLAIM_STATUS_DRAFT, OKF_CLAIM_TYPE,
};
use crate::coordination::{
    acquire_workspace_lock, ensure_workspace_generation, mark_dirty_unlocked,
    read_workspace_generation, run_workspace_generation_test_hook, validated_index_paths,
    write_workspace_generation, GenerationError,
};
use crate::manifest::{build_trust_input_manifest, TrustInputManifest};
use crate::paths::{ensure_directory_mode, set_permissions, Paths, DERIVED_INDEX_MODE};
use crate::workspace::WIKI_TIERS;
use crate::{claims, index_state, transition};

pub const REBUILD_STATUS_CLEAN: &str = index_state::REBUILD_STATUS_CLEAN;
pub const REBUILD_STATUS_REJECTED: &str = index_state::REBUILD_STATUS_REJECTED;

#[derive(Debug)]
pub enum IndexError {
    Boundary(BoundaryError),
    Io(std::io::Error),
    Rusqlite(rusqlite::Error),
    Claim(ClaimError),
    Message(String),
}

impl std::fmt::Display for IndexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Boundary(source) => write!(f, "{source}"),
            Self::Io(source) => write!(f, "{source}"),
            Self::Rusqlite(source) => write!(f, "{source}"),
            Self::Claim(source) => write!(f, "{source}"),
            Self::Message(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for IndexError {}

impl From<std::io::Error> for IndexError {
    fn from(source: std::io::Error) -> Self {
        Self::Io(source)
    }
}

impl From<BoundaryError> for IndexError {
    fn from(source: BoundaryError) -> Self {
        Self::Boundary(source)
    }
}

impl From<rusqlite::Error> for IndexError {
    fn from(source: rusqlite::Error) -> Self {
        Self::Rusqlite(source)
    }
}

impl From<ClaimError> for IndexError {
    fn from(source: ClaimError) -> Self {
        Self::Claim(source)
    }
}

impl From<GenerationError> for IndexError {
    fn from(source: GenerationError) -> Self {
        Self::Message(source.to_string())
    }
}

impl From<transition::TransitionError> for IndexError {
    fn from(source: transition::TransitionError) -> Self {
        Self::Message(source.to_string())
    }
}

impl From<crate::coordination::LockError> for IndexError {
    fn from(source: crate::coordination::LockError) -> Self {
        Self::Message(source.to_string())
    }
}

impl From<crate::coordination::MutationError> for IndexError {
    fn from(source: crate::coordination::MutationError) -> Self {
        Self::Message(source.to_string())
    }
}

impl From<crate::manifest::ManifestError> for IndexError {
    fn from(source: crate::manifest::ManifestError) -> Self {
        Self::Message(source.to_string())
    }
}

impl From<crate::workspace::WorkspaceError> for IndexError {
    fn from(source: crate::workspace::WorkspaceError) -> Self {
        Self::Message(source.to_string())
    }
}

fn msg<T>(message: impl std::fmt::Display) -> Result<T, IndexError> {
    Err(IndexError::Message(message.to_string()))
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct IndexSummary {
    pub workspace: String,
    pub approved: i64,
    pub draft: i64,
    pub invalid: i64,
    pub invalid_count: i64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub invalid_claims: Vec<InvalidClaimSerde>,
    pub legacy: i64,
    #[serde(rename = "rebuild_state")]
    pub rebuild_state: String,
    pub manifest_digest: String,
    pub rebuilt_at: String,
    pub embedding: EmbeddingSummary,
    // Go's zero IndexSummary has a nil catalog (JSON null); Rebuild always
    // sets a non-nil (possibly empty) catalog (JSON []).
    pub catalog: Option<Vec<CatalogClaim>>,
}

// Mirror of InvalidClaim with Go's JSON tags (path/error strings).
#[derive(Debug, Clone, Serialize)]
pub struct InvalidClaimSerde {
    pub path: String,
    pub error: String,
}

impl From<&InvalidClaim> for InvalidClaimSerde {
    fn from(invalid: &InvalidClaim) -> Self {
        Self {
            path: invalid.path.clone(),
            error: invalid.error.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CatalogClaim {
    pub id: String,
    pub title: String,
    pub tier: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub stale_after: String,
}

pub fn approved_catalog(claims: &[Claim]) -> Vec<CatalogClaim> {
    let mut catalog: Vec<CatalogClaim> = claims
        .iter()
        .filter(|claim| claim.status == CLAIM_STATUS_APPROVED)
        .map(|claim| CatalogClaim {
            id: claim.id.clone(),
            title: claim.title.clone(),
            tier: claim.tier.clone(),
            stale_after: claim.stale_after.clone(),
        })
        .collect();
    catalog.sort_by(|left, right| left.id.cmp(&right.id));
    catalog
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct EmbeddingSummary {
    pub strategy: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub model: String,
    pub indexed: i64,
    pub eligible: i64,
    #[serde(rename = "degraded_reason", skip_serializing_if = "String::is_empty")]
    pub degraded: String,
}

#[derive(Debug, Clone)]
pub struct SearchOptions {
    pub query: String,
    pub statuses: Vec<String>,
    pub limit: i64,
}

#[derive(Debug, Clone, Default)]
pub struct IndexedClaim {
    pub id: String,
    pub path: String,
    pub tier: String,
    pub claim_type: String,
    pub status: String,
    pub title: String,
    pub description: String,
    pub stale_after: String,
    pub score: f64,
    pub(crate) indexed_tags: String,
    pub(crate) indexed_body: String,
    pub(crate) verification_digest: String,
}

pub struct IndexStore {
    pub paths: Paths,
}

impl IndexStore {
    pub fn new(paths: Paths) -> Self {
        Self { paths }
    }

    pub fn database_path(&self, workspace: &str) -> Result<PathBuf, IndexError> {
        validate_workspace(&self.paths, workspace)?;
        Ok(self.database_path_unchecked(workspace))
    }

    pub fn dirty_path(&self, workspace: &str) -> Result<PathBuf, IndexError> {
        validate_workspace(&self.paths, workspace)?;
        Ok(self.dirty_path_unchecked(workspace))
    }

    fn database_path_unchecked(&self, workspace: &str) -> PathBuf {
        self.paths.indexes_dir.join(format!("{workspace}.sqlite"))
    }

    fn dirty_path_unchecked(&self, workspace: &str) -> PathBuf {
        self.paths.indexes_dir.join(format!("{workspace}.dirty"))
    }

    pub fn assert_fts5(&self) -> Result<(), IndexError> {
        let conn = Connection::open_in_memory()?;
        let enabled: i64 = conn.query_row(
            "select sqlite_compileoption_used('ENABLE_FTS5')",
            [],
            |row| row.get(0),
        )?;
        if enabled != 1 {
            return msg("sqlite ENABLE_FTS5 compile option is not available");
        }
        conn.execute("create virtual table fts_probe using fts5(body)", [])
            .map_err(|err| IndexError::Message(format!("create FTS5 probe table: {err}")))?;
        Ok(())
    }

    pub fn mark_dirty(&self, workspace: &str) -> Result<(), IndexError> {
        let _lock = acquire_workspace_lock(&self.paths, workspace, true)?;
        self.mark_dirty_unlocked(workspace)?;
        Ok(())
    }

    pub(crate) fn mark_dirty_unlocked(
        &self,
        workspace: &str,
    ) -> Result<(), crate::coordination::MutationError> {
        mark_dirty_unlocked(&self.paths, workspace)
    }

    pub fn check_fresh(&self, workspace: &str) -> Result<(), IndexError> {
        let _lock = acquire_workspace_lock(&self.paths, workspace, false)?;
        self.check_fresh_unlocked_output(workspace)?;
        Ok(())
    }

    pub(crate) fn check_fresh_unlocked(
        &self,
        workspace: &str,
    ) -> Result<TrustInputManifest, IndexError> {
        self.check_fresh_unlocked_output(workspace)
    }

    /// checkFreshUnlockedOutput validates freshness and returns the published
    /// trust-input manifest read from the index.
    pub(crate) fn check_fresh_unlocked_output(
        &self,
        workspace: &str,
    ) -> Result<TrustInputManifest, IndexError> {
        validated_index_paths(&self.paths, workspace)?;
        transition::check_pending_transition_unlocked(&self.paths, workspace)?;
        let dirty_path = self.dirty_path_unchecked(workspace);
        if dirty_path.symlink_metadata().is_ok() {
            return msg(format!(
                "workspace {workspace:?} index is dirty; run zbrain reindex"
            ));
        }
        let database_path = self.database_path_unchecked(workspace);
        if let Err(source) = database_path.symlink_metadata() {
            if source.kind() == std::io::ErrorKind::NotFound {
                return msg(format!(
                    "workspace {workspace:?} index does not exist; run zbrain reindex"
                ));
            }
            return Err(source.into());
        }

        let conn = open_index(&database_path).map_err(|err| {
            IndexError::Message(format!(
                "workspace {workspace:?} index cannot be opened: {err}"
            ))
        })?;
        let (manifest, state) = index_state::read_index_state(&conn).map_err(|err| {
            IndexError::Message(format!(
                "workspace {workspace:?} index state is malformed or missing: {err}"
            ))
        })?;
        if state.status == index_state::REBUILD_STATUS_REJECTED {
            return msg(format!(
                "workspace {workspace:?} index is rejected: {} invalid trust inputs; run zbrain reindex",
                state.invalid_count
            ));
        }
        if state.status != index_state::REBUILD_STATUS_CLEAN {
            return msg(format!(
                "workspace {workspace:?} index state is malformed: unsupported rebuild status {:?}",
                state.status
            ));
        }
        let generation = read_workspace_generation(&self.paths, workspace).map_err(|err| {
            IndexError::Message(format!(
                "workspace {workspace:?} generation state is malformed or missing: {err}; run zbrain reindex"
            ))
        })?;
        if generation.current != generation.published {
            return msg(format!(
                "workspace {workspace:?} index generation is unpublished; run zbrain reindex"
            ));
        }

        let workspace_root = validate_workspace(&self.paths, workspace)?;
        let recorded_mtimes = read_trust_input_mtimes(&conn).map_err(|err| {
            IndexError::Message(format!(
                "workspace {workspace:?} index freshness metadata is missing or malformed: {err}; run zbrain reindex"
            ))
        })?;
        if recorded_mtimes.len() != manifest.entries.len() {
            return msg(format!(
                "workspace {workspace:?} index freshness metadata does not match trust inputs; run zbrain reindex"
            ));
        }
        let directories = read_trust_directories(&conn).map_err(|err| {
            IndexError::Message(format!(
                "workspace {workspace:?} index freshness metadata is missing or malformed: {err}; run zbrain reindex"
            ))
        })?;
        let mut directory_changed = false;
        let mut directory_change_token_unavailable = false;
        for recorded_directory in &directories {
            let directory = workspace_root.join(slash_parts(&recorded_directory.path));
            let info = match std::fs::symlink_metadata(&directory) {
                Ok(info) => info,
                Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                    return msg(format!(
                        "workspace {workspace:?} index is stale; trust directory {:?} is missing; run zbrain reindex",
                        directory.display()
                    ));
                }
                Err(source) => {
                    return Err(IndexError::Message(format!(
                        "workspace {workspace:?} index freshness check failed for {:?}: {source}",
                        directory.display()
                    )));
                }
            };
            if info.file_type().is_symlink() {
                return msg(format!(
                    "workspace {workspace:?} index freshness check failed: trust directory {:?} must not be a symlink",
                    directory.display()
                ));
            }
            if !info.is_dir() {
                return msg(format!(
                    "workspace {workspace:?} index freshness check failed: trust directory {:?} is not a directory",
                    directory.display()
                ));
            }
            let current_change_token = file_change_token(&info);
            if current_change_token < 0 || recorded_directory.change_token < 0 {
                directory_change_token_unavailable = true;
            }
            if info.mtime_nsec_composed() == recorded_directory.modified_at
                && current_change_token == recorded_directory.change_token
            {
                continue;
            }
            directory_changed = true;
            let offender = find_freshness_offender(&workspace_root, &directory, &recorded_mtimes)
                .map_err(|err| {
                IndexError::Message(format!(
                    "workspace {workspace:?} index freshness check failed: {err}"
                ))
            })?;
            if let Some(offender) = offender {
                return msg(format!(
                    "workspace {workspace:?} index is stale; trust input {:?} changed after index; run zbrain reindex",
                    offender.display()
                ));
            }
        }
        let mut change_token_unavailable = false;
        for metadata in recorded_mtimes.values() {
            if metadata.change_token < 0 {
                change_token_unavailable = true;
                break;
            }
        }
        if directory_changed || directory_change_token_unavailable || change_token_unavailable {
            let current_manifest = build_trust_input_manifest(&self.paths, workspace).map_err(|err| {
                IndexError::Message(format!(
                    "workspace {workspace:?} index freshness digest check failed: {err}; run zbrain reindex"
                ))
            })?;
            if !same_trust_input_manifest(&manifest, &current_manifest) {
                let offender = find_trust_input_manifest_offender(&manifest, &current_manifest);
                let Some(offender) = offender else {
                    return msg(format!(
                        "workspace {workspace:?} index manifest is stale; run zbrain reindex"
                    ));
                };
                return msg(format!(
                    "workspace {workspace:?} index is stale; trust input {:?} changed after index; run zbrain reindex",
                    workspace_root.join(slash_parts(&offender)).display()
                ));
            }
        }

        for entry in &manifest.entries {
            let Some(recorded_metadata) = recorded_mtimes.get(&entry.path) else {
                return msg(format!(
                    "workspace {workspace:?} index freshness metadata is missing for {:?}; run zbrain reindex",
                    entry.path
                ));
            };
            let input_path = workspace_root.join(slash_parts(&entry.path));
            let info = match std::fs::symlink_metadata(&input_path) {
                Ok(info) => info,
                Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                    return msg(format!(
                        "workspace {workspace:?} index is stale; trust input {:?} is missing; run zbrain reindex",
                        input_path.display()
                    ));
                }
                Err(source) => {
                    return Err(IndexError::Message(format!(
                        "workspace {workspace:?} index freshness check failed for {:?}: {source}",
                        input_path.display()
                    )));
                }
            };
            if info.file_type().is_symlink() {
                return msg(format!(
                    "workspace {workspace:?} index freshness check failed: trust input {:?} must not be a symlink",
                    input_path.display()
                ));
            }
            if !info.is_file() {
                return msg(format!(
                    "workspace {workspace:?} index freshness check failed: trust input {:?} is not a regular file",
                    input_path.display()
                ));
            }
            if info.mtime_nsec_composed() != recorded_metadata.modified_at
                || file_change_token(&info) != recorded_metadata.change_token
            {
                return msg(format!(
                    "workspace {workspace:?} index is stale; trust input {:?} changed after index; run zbrain reindex",
                    input_path.display()
                ));
            }
        }
        Ok(manifest)
    }

    pub fn rebuild(&self, workspace: &str) -> Result<IndexSummary, IndexError> {
        validated_index_paths(&self.paths, workspace)?;
        let start_lock = acquire_workspace_lock(&self.paths, workspace, true)?;
        ensure_workspace_generation(&self.paths, workspace)
            .map_err(|err| IndexError::Message(format!("prepare workspace generation: {err}")))?;
        transition::recover_pending_transition_for_mutation_unlocked(&self.paths, workspace)?;
        let generation = read_workspace_generation(&self.paths, workspace)
            .map_err(|err| IndexError::Message(format!("read workspace generation: {err}")))?;
        self.mark_dirty_unlocked(workspace)
            .map_err(|err| IndexError::Message(err.to_string()))?;
        let observed_generation = generation.current;
        drop(start_lock);

        self.assert_fts5()?;
        ensure_directory_mode(
            &self.paths.indexes_dir,
            crate::paths::RUNTIME_DIRECTORY_MODE,
        )?;
        let tmp_path = create_temp_file(&self.paths.indexes_dir, &format!("{workspace}.sqlite."))?;

        let cleanup = |tmp_path: &Path| {
            let _ = std::fs::remove_file(tmp_path);
            let _ = std::fs::remove_file(tmp_path.with_file_name(format!(
                "{}-wal",
                tmp_path.file_name().unwrap_or_default().to_string_lossy()
            )));
            let _ = std::fs::remove_file(tmp_path.with_file_name(format!(
                "{}-shm",
                tmp_path.file_name().unwrap_or_default().to_string_lossy()
            )));
        };

        let result = (|| -> Result<IndexSummary, IndexError> {
            let conn = Connection::open(&tmp_path)?;
            create_index_schema(&conn)?;

            let manifest_before = build_trust_input_manifest(&self.paths, workspace)?;
            let mut scan = ClaimStore::new(self.paths.clone())
                .scan_workspace_inner(workspace, false)
                .map_err(IndexError::from)?;
            run_workspace_generation_test_hook(
                crate::coordination::WORKSPACE_GENERATION_HOOK_REBUILD_AFTER_SCAN,
            );
            let manifest = build_trust_input_manifest(&self.paths, workspace)?;
            if !same_trust_input_manifest(&manifest_before, &manifest) {
                return msg("trust inputs changed during rebuild");
            }
            let (valid_claims, dependency_invalid) = ClaimStore::new(self.paths.clone())
                .validate_trusted_claims(workspace, &scan.claims)
                .map_err(IndexError::from)?;
            scan.claims = valid_claims;
            scan.invalid.extend(dependency_invalid);
            scan.invalid.sort_by(|left, right| {
                left.path
                    .cmp(&right.path)
                    .then_with(|| left.error.cmp(&right.error))
            });
            run_workspace_generation_test_hook(
                crate::coordination::WORKSPACE_GENERATION_HOOK_REBUILD_BEFORE_FRESHNESS_CAPTURE,
            );
            let input_mtimes = collect_trust_input_mtimes(&self.paths, workspace, &manifest)?;
            let directories = collect_trust_directories(&self.paths, workspace)?;
            let manifest_after_validation = build_trust_input_manifest(&self.paths, workspace)?;
            if !same_trust_input_manifest(&manifest, &manifest_after_validation) {
                return msg("trust inputs changed during rebuild");
            }
            let manifest = manifest_after_validation;

            let invalid_count = scan.invalid.len() as i64 + scan.legacy_unindexed.len() as i64;
            let rebuild_status = if invalid_count > 0 {
                index_state::REBUILD_STATUS_REJECTED
            } else {
                index_state::REBUILD_STATUS_CLEAN
            };
            let rebuilt_at = crate::clock::rfc3339(chrono::Utc::now());
            let mut summary = IndexSummary {
                workspace: workspace.to_string(),
                invalid: scan.invalid.len() as i64,
                invalid_count,
                invalid_claims: scan.invalid.iter().map(InvalidClaimSerde::from).collect(),
                legacy: scan.legacy_unindexed.len() as i64,
                rebuild_state: rebuild_status.to_string(),
                manifest_digest: manifest.digest.clone(),
                rebuilt_at: rebuilt_at.clone(),
                catalog: Some(approved_catalog(&scan.claims)),
                ..IndexSummary::default()
            };

            let tx = conn.unchecked_transaction()?;
            for claim in &scan.claims {
                match claim.status.as_str() {
                    CLAIM_STATUS_APPROVED => summary.approved += 1,
                    CLAIM_STATUS_DRAFT => summary.draft += 1,
                    _ => {}
                }
                insert_indexed_claim(&tx, claim)?;
            }
            let state = index_state::RebuildState {
                status: rebuild_status.to_string(),
                invalid_count,
                manifest_digest: manifest.digest.clone(),
                rebuilt_at,
            };
            index_state::write_index_state(&tx, &manifest, &state)?;
            write_trust_input_mtimes(&tx, &input_mtimes)?;
            write_trust_directories(&tx, &directories)?;
            tx.commit()?;

            integrity_check(&conn)?;
            conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))?;
            drop(conn);
            let _ = std::fs::remove_file(tmp_wal(&tmp_path));
            let _ = std::fs::remove_file(tmp_shm(&tmp_path));
            run_workspace_generation_test_hook(
                crate::coordination::WORKSPACE_GENERATION_HOOK_REBUILD_BEFORE_PUBLICATION,
            );

            let publication_lock = acquire_workspace_lock(&self.paths, workspace, true)?;
            let publish = (|| -> Result<(), IndexError> {
                validated_index_paths(&self.paths, workspace)?;
                transition::check_pending_transition_unlocked(&self.paths, workspace)?;
                let generation =
                    read_workspace_generation(&self.paths, workspace).map_err(|err| {
                        IndexError::Message(format!(
                            "read workspace generation before publication: {err}"
                        ))
                    })?;
                if generation.current != observed_generation {
                    return msg(format!(
                        "workspace {workspace:?} changed during rebuild; run zbrain reindex"
                    ));
                }
                set_permissions(&tmp_path, DERIVED_INDEX_MODE)?;
                let database_path = self.database_path_unchecked(workspace);
                std::fs::rename(&tmp_path, &database_path)?;
                set_file_times_now(&database_path)
                    .map_err(|err| IndexError::Message(format!("set index mtime: {err}")))?;
                write_workspace_generation(
                    &self.paths,
                    workspace,
                    crate::coordination::WorkspaceGeneration {
                        current: generation.current,
                        published: generation.current,
                    },
                )
                .map_err(|err| {
                    IndexError::Message(format!("publish workspace generation: {err}"))
                })?;
                if let Err(source) = std::fs::remove_file(self.dirty_path_unchecked(workspace)) {
                    if source.kind() != std::io::ErrorKind::NotFound {
                        return Err(source.into());
                    }
                }
                Ok(())
            })();
            match publish {
                Ok(()) => {
                    drop(publication_lock);
                    Ok(summary)
                }
                Err(err) => {
                    let _ = self.mark_dirty_unlocked(workspace);
                    drop(publication_lock);
                    Err(err)
                }
            }
        })();

        match result {
            Ok(summary) => Ok(summary),
            Err(err) => {
                cleanup(&tmp_path);
                Err(err)
            }
        }
    }

    pub fn search(
        &self,
        workspace: &str,
        options: SearchOptions,
    ) -> Result<Vec<IndexedClaim>, IndexError> {
        let _lock = acquire_workspace_lock(&self.paths, workspace, false)?;
        self.search_unlocked(workspace, options)
    }

    pub(crate) fn search_unlocked(
        &self,
        workspace: &str,
        options: SearchOptions,
    ) -> Result<Vec<IndexedClaim>, IndexError> {
        self.search_unlocked_internal(workspace, options, true, true)
    }

    /// claimsByIDsUnlocked returns approved indexed claims matching the given
    /// IDs. IDs that are not present in the index are ignored. The caller
    /// must already hold the workspace lock and have validated freshness.
    pub(crate) fn claims_by_ids_unlocked(
        &self,
        workspace: &str,
        ids: &[String],
    ) -> Result<Vec<IndexedClaim>, IndexError> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let database_path = self.database_path(workspace)?;
        let conn = open_index(&database_path)?;
        let placeholders = vec!["?"; ids.len()].join(",");
        let sql = format!(
            "select id, path, tier, type, status, title, description, stale_after, tags, body, verification_digest
from claims
where status = ? and id in ({placeholders})"
        );
        let mut statement = conn.prepare(&sql)?;
        let mut params: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(CLAIM_STATUS_APPROVED)];
        for id in ids {
            params.push(Box::new(id.clone()));
        }
        let params_ref: Vec<&dyn rusqlite::ToSql> =
            params.iter().map(|param| param.as_ref()).collect();
        let mut rows = statement.query(params_ref.as_slice())?;
        let mut results = Vec::new();
        while let Some(row) = rows.next()? {
            results.push(IndexedClaim {
                id: row.get(0)?,
                path: row.get(1)?,
                tier: row.get(2)?,
                claim_type: row.get(3)?,
                status: row.get(4)?,
                title: row.get(5)?,
                description: row.get(6)?,
                stale_after: row.get(7)?,
                score: 0.0,
                indexed_tags: row.get(8)?,
                indexed_body: row.get(9)?,
                verification_digest: row.get(10)?,
            });
        }
        Ok(results)
    }

    pub(crate) fn search_unlocked_internal(
        &self,
        workspace: &str,
        mut options: SearchOptions,
        check_fresh: bool,
        check_integrity: bool,
    ) -> Result<Vec<IndexedClaim>, IndexError> {
        let database_path = self.database_path(workspace)?;
        if options.limit <= 0 {
            options.limit = 10;
        }
        if options.query.trim().is_empty() {
            return msg("query is required");
        }
        if options.statuses.is_empty() {
            return msg("at least one status filter is required");
        }
        if check_fresh {
            self.check_fresh_unlocked(workspace)?;
        }
        let conn = open_index(&database_path)?;
        if check_integrity {
            integrity_check(&conn)?;
        }

        let mut status_values: Vec<String> = Vec::with_capacity(options.statuses.len());
        for status in &options.statuses {
            if !is_known_claim_status(status) {
                return msg(format!("claim status {status:?} is not supported"));
            }
            status_values.push(status.clone());
        }
        let placeholders = vec!["?"; status_values.len()].join(",");
        let match_query = fts5_query(&options.query);
        if match_query.is_empty() {
            return msg("query is required");
        }
        let sql = format!(
            "select c.id, c.path, c.tier, c.type, c.status, c.title, c.description, c.stale_after, c.tags, c.body, c.verification_digest, rank
from claims_fts
join claims c on c.rowid = claims_fts.rowid
where claims_fts match ? and c.status in ({placeholders})
order by rank, c.path
limit ?"
        );
        let mut params: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(match_query)];
        for status in &status_values {
            params.push(Box::new(status.clone()));
        }
        params.push(Box::new(options.limit));
        let mut statement = conn.prepare(&sql)?;
        let params_ref: Vec<&dyn rusqlite::ToSql> =
            params.iter().map(|param| param.as_ref()).collect();
        let mut rows = statement.query(params_ref.as_slice())?;
        let mut results = Vec::new();
        while let Some(row) = rows.next()? {
            results.push(IndexedClaim {
                id: row.get(0)?,
                path: row.get(1)?,
                tier: row.get(2)?,
                claim_type: row.get(3)?,
                status: row.get(4)?,
                title: row.get(5)?,
                description: row.get(6)?,
                stale_after: row.get(7)?,
                score: row.get(11)?,
                indexed_tags: row.get(8)?,
                indexed_body: row.get(9)?,
                verification_digest: row.get(10)?,
            });
        }
        Ok(results)
    }
}

fn open_index(path: &Path) -> Result<Connection, IndexError> {
    Connection::open(path)
        .map_err(|err| IndexError::Message(format!("index database cannot be opened: {err}")))
}

fn tmp_wal(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push("-wal");
    path.with_file_name(name)
}

fn tmp_shm(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push("-shm");
    path.with_file_name(name)
}

// ---------------------------------------------------------------------------
// Freshness metadata
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub(crate) struct TrustInputMtime {
    pub path: String,
    pub modified_at: i64,
    pub change_token: i64,
}

#[derive(Debug, Clone)]
pub(crate) struct TrustDirectoryMtime {
    pub path: String,
    pub modified_at: i64,
    pub change_token: i64,
}

pub(crate) fn read_trust_input_mtimes(
    conn: &Connection,
) -> Result<HashMap<String, TrustInputMtime>, IndexError> {
    let mut statement = conn
        .prepare("select path, modified_at, change_token from trust_input_mtimes order by path")?;
    let mut rows = statement.query([])?;
    let mut mtimes = HashMap::new();
    let mut previous = String::new();
    while let Some(row) = rows.next()? {
        let metadata = TrustInputMtime {
            path: row.get(0)?,
            modified_at: row.get(1)?,
            change_token: row.get(2)?,
        };
        if metadata.path.contains('\\') || metadata.path.contains('\0') {
            return msg(format!(
                "input path {:?} is not slash-normalized",
                metadata.path
            ));
        }
        if safe_relative_path(&metadata.path).is_err() || !is_trust_input_path(&metadata.path) {
            return msg(format!(
                "input path {:?} is not a canonical trust input",
                metadata.path
            ));
        }
        if !previous.is_empty() && metadata.path <= previous {
            return msg(format!(
                "trust input mtimes are not unique and sorted at {:?}",
                metadata.path
            ));
        }
        previous = metadata.path.clone();
        mtimes.insert(metadata.path.clone(), metadata);
    }
    Ok(mtimes)
}

pub(crate) fn read_trust_directories(
    conn: &Connection,
) -> Result<Vec<TrustDirectoryMtime>, IndexError> {
    let mut statement = conn
        .prepare("select path, modified_at, change_token from trust_directories order by path")?;
    let mut rows = statement.query([])?;
    let mut directories = Vec::new();
    let mut previous = String::new();
    while let Some(row) = rows.next()? {
        let directory = TrustDirectoryMtime {
            path: row.get(0)?,
            modified_at: row.get(1)?,
            change_token: row.get(2)?,
        };
        if directory.path.contains('\\') || directory.path.contains('\0') {
            return msg(format!(
                "directory path {:?} is not slash-normalized",
                directory.path
            ));
        }
        if safe_relative_path(&directory.path).is_err() || !is_trust_directory_path(&directory.path)
        {
            return msg(format!(
                "directory path {:?} is not a canonical trust directory",
                directory.path
            ));
        }
        if !previous.is_empty() && directory.path <= previous {
            return msg(format!(
                "trust directories are not unique and sorted at {:?}",
                directory.path
            ));
        }
        previous = directory.path.clone();
        directories.push(directory);
    }
    Ok(directories)
}

fn find_freshness_offender(
    workspace_root: &Path,
    directory: &Path,
    known_input_mtimes: &HashMap<String, TrustInputMtime>,
) -> Result<Option<PathBuf>, IndexError> {
    let mut offender: Option<PathBuf> = None;
    walk_all(directory, &mut |path, entry_type| {
        if offender.is_some() {
            return Ok(());
        }
        if entry_type.is_symlink() {
            return msg(format!(
                "trust input {:?} must not be a symlink",
                path.display()
            ));
        }
        let relative = path
            .strip_prefix(workspace_root)
            .map_err(|err| IndexError::Io(std::io::Error::other(err)))?
            .to_string_lossy()
            .replace('\\', "/");
        if entry_type.is_dir() {
            if is_trust_input_path(&relative) {
                return msg(format!(
                    "trust input {:?} is not a regular file",
                    path.display()
                ));
            }
            return Ok(());
        }
        if !is_trust_input_path(&relative) {
            return Ok(());
        }
        let info = std::fs::symlink_metadata(path)?;
        if !info.is_file() {
            return msg(format!(
                "trust input {:?} is not a regular file",
                path.display()
            ));
        }
        match known_input_mtimes.get(&relative) {
            Some(recorded)
                if info.mtime_nsec_composed() == recorded.modified_at
                    && file_change_token(&info) == recorded.change_token => {}
            _ => {
                offender = Some(path.to_path_buf());
            }
        }
        Ok(())
    })?;
    Ok(offender)
}

fn find_trust_input_manifest_offender(
    recorded: &TrustInputManifest,
    current: &TrustInputManifest,
) -> Option<String> {
    let mut recorded_index = 0;
    let mut current_index = 0;
    while recorded_index < recorded.entries.len() || current_index < current.entries.len() {
        if recorded_index >= recorded.entries.len() {
            return Some(current.entries[current_index].path.clone());
        }
        if current_index >= current.entries.len() {
            return Some(recorded.entries[recorded_index].path.clone());
        }
        let recorded_entry = &recorded.entries[recorded_index];
        let current_entry = &current.entries[current_index];
        if recorded_entry.path < current_entry.path {
            return Some(recorded_entry.path.clone());
        }
        if current_entry.path < recorded_entry.path {
            return Some(current_entry.path.clone());
        }
        if recorded_entry != current_entry {
            return Some(recorded_entry.path.clone());
        }
        recorded_index += 1;
        current_index += 1;
    }
    None
}

fn collect_trust_input_mtimes(
    paths: &Paths,
    workspace: &str,
    manifest: &TrustInputManifest,
) -> Result<Vec<TrustInputMtime>, IndexError> {
    let root = validate_workspace(paths, workspace)?;
    let mut mtimes = Vec::with_capacity(manifest.entries.len());
    for entry in &manifest.entries {
        safe_relative_path(&entry.path)?;
        let path = root.join(slash_parts(&entry.path));
        let info = std::fs::symlink_metadata(&path)?;
        if info.file_type().is_symlink() || !info.is_file() {
            return msg(format!(
                "trust input {:?} is not a regular file",
                path.display()
            ));
        }
        mtimes.push(TrustInputMtime {
            path: entry.path.clone(),
            modified_at: info.mtime_nsec_composed(),
            change_token: file_change_token(&info),
        });
    }
    Ok(mtimes)
}

pub(crate) const UNAVAILABLE_FILE_CHANGE_TOKEN: i64 = -1;

// Go derives the change token from the inode change time (st_ctim) of the
// file; MetadataExt exposes it as ctime()/ctime_nsec().
pub(crate) fn file_change_token(info: &std::fs::Metadata) -> i64 {
    trust_file_change_token(info)
}

// Go: var trustFileChangeToken = fileChangeToken — a seam tests override to
// simulate platforms without change tokens. Rust equivalent is a thread-local
// override.
use std::cell::Cell;

thread_local! {
    static CHANGE_TOKEN_OVERRIDE: Cell<Option<i64>> = const { Cell::new(None) };
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn set_trust_file_change_token_override(value: Option<i64>) {
    CHANGE_TOKEN_OVERRIDE.with(|slot| slot.set(value));
}

pub(crate) fn trust_file_change_token(info: &std::fs::Metadata) -> i64 {
    if let Some(value) = CHANGE_TOKEN_OVERRIDE.with(Cell::get) {
        return value;
    }
    combine_change_stamp(info.ctime(), info.ctime_nsec())
}

pub(crate) fn combine_change_stamp(seconds: i64, nanoseconds: i64) -> i64 {
    const NANOSECONDS_PER_SECOND: i64 = 1_000_000_000;
    if !(0..NANOSECONDS_PER_SECOND).contains(&nanoseconds) {
        return UNAVAILABLE_FILE_CHANGE_TOKEN;
    }
    if seconds < i64::MIN / NANOSECONDS_PER_SECOND
        || seconds > (i64::MAX - nanoseconds) / NANOSECONDS_PER_SECOND
    {
        return UNAVAILABLE_FILE_CHANGE_TOKEN;
    }
    let token = seconds * NANOSECONDS_PER_SECOND + nanoseconds;
    if token == UNAVAILABLE_FILE_CHANGE_TOKEN {
        return UNAVAILABLE_FILE_CHANGE_TOKEN;
    }
    token
}

fn collect_trust_directories(
    paths: &Paths,
    workspace: &str,
) -> Result<Vec<TrustDirectoryMtime>, IndexError> {
    let root = validate_workspace(paths, workspace)?;
    let mut directory_set: HashMap<String, TrustDirectoryMtime> = HashMap::new();
    let mut add = |path: &Path| -> Result<(), IndexError> {
        let absolute = crate::paths::absolute(path)?;
        if !crate::boundary::path_within(&root, &absolute) {
            return msg(format!(
                "trust directory {:?} is outside workspace",
                path.display()
            ));
        }
        let info = std::fs::symlink_metadata(&absolute)?;
        if info.file_type().is_symlink() || !info.is_dir() {
            return msg(format!(
                "trust directory {:?} is not a directory",
                path.display()
            ));
        }
        let relative = absolute
            .strip_prefix(&root)
            .map_err(|err| IndexError::Io(std::io::Error::other(err)))?
            .to_string_lossy()
            .replace('\\', "/");
        if !is_trust_directory_path(&relative) {
            return msg(format!(
                "trust directory {:?} is not canonical",
                path.display()
            ));
        }
        directory_set.insert(
            relative.clone(),
            TrustDirectoryMtime {
                path: relative,
                modified_at: info.mtime_nsec_composed(),
                change_token: file_change_token(&info),
            },
        );
        Ok(())
    };

    for tier in WIKI_TIERS {
        let tier_root = root.join("wiki").join(tier);
        walk_all(&tier_root, &mut |path, entry_type| {
            if entry_type.is_symlink() {
                return msg(format!(
                    "trust directory {:?} must not be a symlink",
                    path.display()
                ));
            }
            if !entry_type.is_dir() {
                return Ok(());
            }
            add(path)
        })?;
    }

    let sources_root = root.join("evidence").join("sources");
    let info = std::fs::symlink_metadata(&sources_root)?;
    if info.file_type().is_symlink() {
        return msg(format!(
            "trust directory {:?} must not be a symlink",
            sources_root.display()
        ));
    }
    if !info.is_dir() {
        return msg(format!(
            "trust directory {:?} is not a directory",
            sources_root.display()
        ));
    }
    add(&sources_root)?;
    let mut entries: Vec<PathBuf> = std::fs::read_dir(&sources_root)?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .collect();
    entries.sort();
    for path in entries {
        let entry_type = std::fs::symlink_metadata(&path)?.file_type();
        if entry_type.is_symlink() {
            return msg(format!(
                "trust directory {:?} must not be a symlink",
                path.display()
            ));
        }
        if entry_type.is_dir() {
            add(&path)?;
        }
    }

    let mut directories: Vec<TrustDirectoryMtime> = directory_set.into_values().collect();
    directories.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(directories)
}

pub(crate) fn is_trust_directory_path(path: &str) -> bool {
    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() >= 2 && parts[0] == "wiki" && claims::is_known_wiki_tier(parts[1]) {
        return true;
    }
    path == "evidence/sources"
        || (parts.len() == 3
            && parts[0] == "evidence"
            && parts[1] == "sources"
            && !parts[2].is_empty())
}

pub(crate) fn is_trust_input_path(path: &str) -> bool {
    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() >= 3
        && parts[0] == "wiki"
        && claims::is_known_wiki_tier(parts[1])
        && path.ends_with(".md")
    {
        return true;
    }
    parts.len() == 4
        && parts[0] == "evidence"
        && parts[1] == "sources"
        && !parts[2].is_empty()
        && (parts[3] == "source.yaml" || parts[3] == "raw")
}

fn write_trust_input_mtimes(
    tx: &rusqlite::Transaction<'_>,
    mtimes: &[TrustInputMtime],
) -> Result<(), IndexError> {
    tx.execute("delete from trust_input_mtimes", [])
        .map_err(|err| IndexError::Message(format!("clear trust input mtimes: {err}")))?;
    for mtime in mtimes {
        tx.execute(
            "insert into trust_input_mtimes(path, modified_at, change_token) values (?, ?, ?)",
            rusqlite::params![mtime.path, mtime.modified_at, mtime.change_token],
        )
        .map_err(|err| {
            IndexError::Message(format!("write trust input mtime {:?}: {err}", mtime.path))
        })?;
    }
    Ok(())
}

fn write_trust_directories(
    tx: &rusqlite::Transaction<'_>,
    directories: &[TrustDirectoryMtime],
) -> Result<(), IndexError> {
    tx.execute("delete from trust_directories", [])
        .map_err(|err| IndexError::Message(format!("clear trust directories: {err}")))?;
    for directory in directories {
        tx.execute(
            "insert into trust_directories(path, modified_at, change_token) values (?, ?, ?)",
            rusqlite::params![
                directory.path,
                directory.modified_at,
                directory.change_token
            ],
        )
        .map_err(|err| {
            IndexError::Message(format!("write trust directory {:?}: {err}", directory.path))
        })?;
    }
    Ok(())
}

pub fn same_trust_input_manifest(left: &TrustInputManifest, right: &TrustInputManifest) -> bool {
    left.digest == right.digest && left.entries == right.entries
}

// ---------------------------------------------------------------------------
// FTS5 query builder (Go fts5Query): the outer scan is byte-oriented and
// treats Latin-1 NBSP/NEL bytes as separators, while token splitting inside a
// raw word decodes runes. Both quirks are reproduced.
// ---------------------------------------------------------------------------

fn go_is_space_byte(byte: u8) -> bool {
    matches!(
        byte,
        b'\t' | b'\n' | 0x0B | 0x0C | b'\r' | b' ' | 0x85 | 0xA0
    )
}

pub fn fts5_query(query: &str) -> String {
    if query.trim().is_empty() {
        return String::new();
    }
    let mut parts: Vec<String> = Vec::new();
    let bytes = query.as_bytes();
    let n = bytes.len();
    let mut i = 0;
    while i < n {
        while i < n && go_is_space_byte(bytes[i]) {
            i += 1;
        }
        if i >= n {
            break;
        }
        if bytes[i] == b'"' {
            let Some(end) = query[i + 1..].find('"') else {
                return String::new();
            };
            let phrase = &query[i + 1..i + 1 + end];
            let phrase_trim = phrase.trim();
            if !phrase_trim.is_empty() {
                let normalized = phrase_trim
                    .to_lowercase()
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ");
                if !normalized.is_empty() {
                    parts.push(format!("\"{}\"", normalized.replace('"', "\"\"")));
                }
            }
            i += end + 2;
            continue;
        }
        let mut j = i;
        while j < n && !go_is_space_byte(bytes[j]) && bytes[j] != b'"' {
            j += 1;
        }
        let raw = String::from_utf8_lossy(&bytes[i..j]).into_owned();
        i = j;
        if raw.is_empty() {
            continue;
        }
        let is_wildcard = raw.ends_with('*');
        let base = if is_wildcard {
            raw[..raw.len() - 1].to_string()
        } else {
            raw.clone()
        };
        if is_wildcard && base.trim().is_empty() {
            continue;
        }
        let low_base = base.to_lowercase();
        for tok in split_alnum(&low_base) {
            if tok == "near" {
                return String::new();
            }
        }
        if is_wildcard {
            let fields = split_alnum(&low_base);
            if fields.is_empty() {
                continue;
            }
            let last = fields.len() - 1;
            for (idx, field) in fields.iter().enumerate() {
                if field == "near" {
                    return String::new();
                }
                if idx == last {
                    parts.push(format!("{field}*"));
                } else {
                    parts.push(format!("\"{}\"", field.replace('"', "\"\"")));
                }
            }
        } else {
            for field in split_alnum(&raw.to_lowercase()) {
                if field == "near" {
                    return String::new();
                }
                parts.push(format!("\"{}\"", field.replace('"', "\"\"")));
            }
        }
    }
    let mut seen: HashSet<String> = HashSet::with_capacity(parts.len());
    let mut deduped = Vec::with_capacity(parts.len());
    for part in parts {
        if !seen.insert(part.clone()) {
            continue;
        }
        deduped.push(part);
    }
    deduped.join(" ")
}

// Go strings.FieldsFunc over runes with !IsLetter && !IsDigit.
pub(crate) fn split_alnum(input: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    for ch in input.chars() {
        if ch.is_alphabetic() || ch.is_numeric() {
            current.push(ch);
        } else if !current.is_empty() {
            fields.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        fields.push(current);
    }
    fields
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

pub(crate) fn create_index_schema(conn: &Connection) -> Result<(), IndexError> {
    conn.execute_batch(
        r#"
create table claims (
  id text not null unique,
  path text not null unique,
  tier text not null,
  type text not null,
  status text not null,
  title text not null,
  description text not null,
  stale_after text not null,
  tags text not null,
  body text not null,
  verification_digest text not null
);
create virtual table claims_fts using fts5(
  title,
  description,
  tags,
  body,
  content='claims',
  content_rowid='rowid'
);
create trigger claims_ai after insert on claims begin
  insert into claims_fts(rowid, title, description, tags, body) values (new.rowid, new.title, new.description, new.tags, new.body);
end;
create trigger claims_ad after delete on claims begin
  insert into claims_fts(claims_fts, rowid, title, description, tags, body) values ('delete', old.rowid, old.title, old.description, old.tags, old.body);
end;
create trigger claims_au after update on claims begin
  insert into claims_fts(claims_fts, rowid, title, description, tags, body) values ('delete', old.rowid, old.title, old.description, old.tags, old.body);
  insert into claims_fts(rowid, title, description, tags, body) values (new.rowid, new.title, new.description, new.tags, new.body);
end;
create table trust_inputs (
  path text not null primary key,
  kind text not null,
  byte_length integer not null,
  sha256 text not null
);
create table trust_input_mtimes (
  path text not null primary key,
  modified_at integer not null,
  change_token integer not null
);
create table trust_directories (
  path text not null primary key,
  modified_at integer not null,
  change_token integer not null
);
create table rebuild_state (
  id integer not null primary key default 1 check (id = 1),
  status text not null,
  invalid_count integer not null,
  manifest_digest text not null,
  rebuilt_at text not null
);
pragma user_version = 3;
"#,
    )?;
    conn.query_row("PRAGMA journal_mode=WAL", [], |_| Ok(()))?;
    conn.execute("PRAGMA synchronous=NORMAL", [])?;
    Ok(())
}

pub(crate) fn insert_indexed_claim(
    tx: &rusqlite::Transaction<'_>,
    claim: &Claim,
) -> Result<(), IndexError> {
    tx.execute(
        "insert into claims(id, path, tier, type, status, title, description, stale_after, tags, body, verification_digest) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        rusqlite::params![
            claim.id,
            claim.path,
            claim.tier,
            OKF_CLAIM_TYPE,
            claim.status,
            claim.title,
            claim.description,
            claim.stale_after,
            claim.tags.join(" "),
            claim.body,
            claim.verified_digest,
        ],
    )?;
    Ok(())
}

pub(crate) fn integrity_check(conn: &Connection) -> Result<(), IndexError> {
    let result: String = conn.query_row("pragma integrity_check", [], |row| row.get(0))?;
    if result != "ok" {
        return msg(format!("sqlite integrity_check = {result}"));
    }
    conn.execute(
        "insert into claims_fts(claims_fts, rank) values ('integrity-check', 1)",
        [],
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Go os.Chtimes(path, now, now) after index publication.
fn set_file_times_now(path: &Path) -> Result<(), std::io::Error> {
    use std::ffi::CString;
    let c_path = CString::new(path.as_os_str().as_encoded_bytes())?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| std::io::Error::other(err.to_string()))?;
    let stamp = libc::timespec {
        tv_sec: now.as_secs() as libc::time_t,
        tv_nsec: now.subsec_nanos() as libc::c_long,
    };
    let times = [stamp, stamp];
    // SAFETY: c_path is a NUL-free CString alive for the call; times points
    // to a live 2-element array; utimensat retains neither pointer.
    let rc = unsafe { libc::utimensat(libc::AT_FDCWD, c_path.as_ptr(), times.as_ptr(), 0) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

pub(crate) fn create_temp_file(dir: &Path, prefix: &str) -> Result<PathBuf, IndexError> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut attempt: u64 = 0;
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut seed = nanos ^ ((std::process::id() as u128) << 64);
    loop {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let suffix = format!("{:016x}{:02x}", seed, attempt);
        let path = dir.join(format!("{prefix}{suffix}.tmp"));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(_) => return Ok(path),
            Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
                attempt += 1;
                if attempt > 64 {
                    return Err(IndexError::Io(std::io::Error::other(
                        "create temporary index file: exhausted attempts",
                    )));
                }
            }
            Err(source) => return Err(IndexError::Io(source)),
        }
    }
}

// mtime composed the way Go uses it: info.ModTime().UnixNano().
trait MtimeNano {
    fn mtime_nsec_composed(&self) -> i64;
}

impl MtimeNano for std::fs::Metadata {
    fn mtime_nsec_composed(&self) -> i64 {
        self.mtime()
            .saturating_mul(1_000_000_000)
            .saturating_add(self.mtime_nsec())
    }
}

// Go filepath.Join(root, filepath.FromSlash(rel)) — rel uses '/' separators.
fn slash_parts(relative: &str) -> PathBuf {
    relative.split('/').collect::<PathBuf>()
}

// Lexically ordered DFS over all entries, including the root itself (Go
// filepath.WalkDir order).
fn walk_all(
    root: &Path,
    visit: &mut dyn FnMut(&Path, std::fs::FileType) -> Result<(), IndexError>,
) -> Result<(), IndexError> {
    let root_type = std::fs::symlink_metadata(root)?.file_type();
    visit(root, root_type)?;
    if !root_type.is_dir() {
        return Ok(());
    }
    let mut children: Vec<PathBuf> = match std::fs::read_dir(root) {
        Ok(entries) => entries
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .collect(),
        Err(source) => return Err(IndexError::Io(source)),
    };
    children.sort();
    for child in children {
        let entry_type = match std::fs::symlink_metadata(&child) {
            Ok(info) => info.file_type(),
            Err(source) => return Err(IndexError::Io(source)),
        };
        visit(&child, entry_type)?;
        if entry_type.is_dir() {
            walk_all(&child, visit)?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Test support (shared with query/embedder test ports) and the 1:1 port of
// index_test.go.
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use crate::clock::{rfc3339, FixedClock};
    use crate::config::ensure_config;
    use crate::evidence::{Evidence, EvidenceStore};
    use crate::paths::Options;
    use chrono::{TimeZone, Utc};
    use sha2::{Digest as _, Sha256};
    use std::sync::Arc;

    pub fn fixed_index_now() -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 30, 10, 0, 0).unwrap()
    }

    pub fn fixed_index_rfc3339() -> String {
        rfc3339(fixed_index_now())
    }

    // claim_store_test.go fixedClaimStoreNow.
    pub fn fixed_claim_store_now() -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 30, 9, 0, 0).unwrap()
    }

    pub fn index_test_paths(name: &str) -> (PathBuf, Paths) {
        let dir = std::env::temp_dir().join(format!("zbrain-index-{}-{name}", std::process::id()));
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
        crate::workspace::create_workspace(&paths, "research", &FixedClock::new(fixed_index_now()))
            .unwrap();
        (dir, paths)
    }

    pub fn index_claim(id: &str, title: &str, basis: &str) -> Claim {
        Claim {
            claim_type: OKF_CLAIM_TYPE.into(),
            id: id.into(),
            tier: "projects".into(),
            status: CLAIM_STATUS_DRAFT.into(),
            title: title.into(),
            basis: basis.into(),
            created_at: fixed_index_rfc3339(),
            created_by: "owner".into(),
            tags: vec!["memory".into()],
            body: "Local-first memory retrieval body\n".into(),
            ..Claim::default()
        }
    }

    pub fn claim_store(paths: &Paths) -> ClaimStore {
        ClaimStore::with_clock(paths.clone(), Arc::new(FixedClock::new(fixed_index_now())))
    }

    pub fn add_store_evidence(paths: &Paths, body: &str) -> Evidence {
        let source = paths.workspaces_dir.join("evidence-input.txt");
        std::fs::write(&source, body).unwrap();
        EvidenceStore::new(paths.clone())
            .add_file(
                "research",
                &source,
                "file://source.txt",
                "text/plain",
                &FixedClock::new(fixed_claim_store_now()),
            )
            .unwrap()
    }

    pub fn finalize_approved_store_claim(claim: Claim) -> Claim {
        let mut claim = claim;
        claim.status = CLAIM_STATUS_APPROVED.into();
        claim.verified_at = rfc3339(fixed_claim_store_now());
        claim.verified_by = "owner".into();
        claim.verified_digest = String::new();
        let digest = crate::claims::claim_verification_digest(&claim).unwrap();
        claim.verified_digest = digest;
        crate::signing::sign_test_claim(&mut claim);
        claim
    }

    pub fn write_canonical_store_claim(paths: &Paths, claim: &Claim) {
        let path = paths
            .workspaces_dir
            .join("research")
            .join("wiki")
            .join(&claim.tier)
            .join(format!("{}.md", claim.id));
        crate::claims::write_claim_atomic(&path, claim).unwrap();
    }

    pub fn sha256_hex(path: &Path) -> String {
        let contents = std::fs::read(path).unwrap();
        let digest = Sha256::digest(&contents);
        digest.iter().map(|b| format!("{b:02x}")).collect()
    }

    pub fn sha256_string(input: &str) -> String {
        let digest = Sha256::digest(input.as_bytes());
        digest.iter().map(|b| format!("{b:02x}")).collect()
    }

    pub fn indexed_claim_statuses(
        paths: &Paths,
        workspace: &str,
    ) -> std::collections::BTreeMap<String, String> {
        let db_path = IndexStore::new(paths.clone())
            .database_path(workspace)
            .unwrap();
        let conn = Connection::open(&db_path).unwrap();
        let mut statement = conn
            .prepare("select id, status from claims order by id")
            .unwrap();
        let mut rows = statement.query([]).unwrap();
        let mut statuses = std::collections::BTreeMap::new();
        while let Some(row) = rows.next().unwrap() {
            statuses.insert(
                row.get::<_, String>(0).unwrap(),
                row.get::<_, String>(1).unwrap(),
            );
        }
        statuses
    }

    pub fn read_published_index_state(
        store: &IndexStore,
        workspace: &str,
    ) -> (TrustInputManifest, index_state::RebuildState) {
        let db_path = store.database_path(workspace).unwrap();
        let conn = Connection::open(&db_path).unwrap();
        index_state::read_index_state(&conn).unwrap()
    }

    pub fn index_database_path(store: &IndexStore, workspace: &str) -> PathBuf {
        store.database_path(workspace).unwrap()
    }

    pub fn index_dirty_path(store: &IndexStore, workspace: &str) -> PathBuf {
        store.dirty_path(workspace).unwrap()
    }

    pub fn assert_file_bytes(path: &Path, want: &[u8]) {
        let got = std::fs::read(path).unwrap();
        assert_eq!(got, want, "{}", path.display());
    }

    pub fn pending_transition_target(
        path: &str,
        before: &[u8],
        target: &[u8],
    ) -> transition::PendingTransitionTarget {
        transition::PendingTransitionTarget {
            path: path.into(),
            preimage_sha256: transition::transition_sha256(before),
            target_sha256: transition::transition_sha256(target),
            target_bytes: target.to_vec(),
        }
    }

    pub fn rewrite_evidence_metadata(
        paths: &Paths,
        workspace: &str,
        id: &str,
        evidence: &Evidence,
    ) {
        use std::os::unix::fs::PermissionsExt;
        let path = paths
            .workspaces_dir
            .join(workspace)
            .join("evidence/sources")
            .join(id)
            .join("source.yaml");
        let mut permissions = std::fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o644);
        std::fs::set_permissions(&path, permissions).unwrap();
        let contents = crate::yaml::emit(&crate::evidence::evidence_to_yaml(evidence));
        std::fs::write(&path, contents).unwrap();
    }

    // os.Chtimes(path, at, at).
    // Test-only helper (panics instead of returning errors by design).
    #[cfg(test)]
    pub fn set_file_times(path: &Path, at: chrono::DateTime<Utc>) {
        use std::ffi::CString;
        let c_path = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        let stamp = libc::timespec {
            tv_sec: at.timestamp() as libc::time_t,
            tv_nsec: 0,
        };
        let times = [stamp, stamp];
        // SAFETY: same contract as set_file_times_now above; test-only.
        let rc = unsafe { libc::utimensat(libc::AT_FDCWD, c_path.as_ptr(), times.as_ptr(), 0) };
        assert_eq!(rc, 0, "utimensat failed for {}", path.display());
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;
    use crate::claims::{CLAIM_BASIS_DERIVED, CLAIM_BASIS_EVIDENCE, CLAIM_BASIS_OWNER};
    use crate::clock::FixedClock;
    use crate::transition::{PendingTransition, PendingTransitionTarget};
    use chrono::TimeDelta;

    pub(crate) fn store(paths: &Paths) -> IndexStore {
        IndexStore::new(paths.clone())
    }

    #[test]
    fn index_fts5_capability() {
        let (_dir, paths) = index_test_paths("fts5");
        assert!(store(&paths).assert_fts5().is_ok());
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn reindex_publishes_rejected_state_for_legacy_and_evidence() {
        let (_dir, paths) = index_test_paths("rejected-legacy");
        let claim_store = claim_store(&paths);
        let mut approved = index_claim(
            "clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "Approved Local Memory",
            CLAIM_BASIS_OWNER,
        );
        approved.description = "description recall token".into();
        claim_store
            .write_draft("research", approved.clone())
            .unwrap();
        claim_store.approve("research", &approved.id).unwrap();
        let mut draft = index_claim(
            "clm_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "Draft Candidate",
            CLAIM_BASIS_OWNER,
        );
        draft.body = "draft-only recall token\n".into();
        claim_store.write_draft("research", draft).unwrap();
        let legacy_path = paths
            .workspaces_dir
            .join("research/wiki/projects/legacy.md");
        std::fs::write(&legacy_path, b"legacy local memory should not index").unwrap();
        let non_zbrain_okf = paths
            .workspaces_dir
            .join("research/wiki/projects/okf-note.md");
        std::fs::write(
            &non_zbrain_okf,
            b"---\ntype: note\ntitle: Poison Note\n---\n\npoison local memory\n",
        )
        .unwrap();
        let evidence_path = paths
            .workspaces_dir
            .join("research/evidence/sources/raw.md");
        std::fs::write(&evidence_path, b"poison local memory evidence").unwrap();

        let summary = store(&paths).rebuild("research").unwrap();
        assert_eq!(
            (
                summary.approved,
                summary.draft,
                summary.legacy,
                summary.invalid,
                summary.invalid_count,
                summary.rebuild_state.as_str()
            ),
            (1, 1, 2, 0, 2, REBUILD_STATUS_REJECTED)
        );
        let (manifest, state) = read_published_index_state(&store(&paths), "research");
        assert_eq!(state.status, REBUILD_STATUS_REJECTED);
        assert_eq!(state.invalid_count, 2);
        assert_eq!(state.manifest_digest, manifest.digest);
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn rebuild_rejects_duplicate_canonical_claim_ids() {
        let (_dir, paths) = index_test_paths("duplicate-ids");
        let id = "clm_77777777777777777777777777777777";
        let flat = finalize_approved_store_claim(index_claim(
            id,
            "Flat duplicate index marker",
            CLAIM_BASIS_OWNER,
        ));
        write_canonical_store_claim(&paths, &flat);

        let nested_path = "projects/topics/security/".to_string() + id + ".md";
        let mut nested = index_claim(id, "Nested duplicate index marker", CLAIM_BASIS_OWNER);
        nested.body = "nested duplicate index marker\n".into();
        nested.path = nested_path.clone();
        let nested = finalize_approved_store_claim(nested);
        let nested_absolute_path = paths
            .workspaces_dir
            .join("research/wiki")
            .join(&nested_path);
        crate::claims::write_claim_atomic(&nested_absolute_path, &nested).unwrap();

        let flat_path = format!("projects/{id}.md");
        let flat_absolute_path = paths.workspaces_dir.join("research/wiki").join(&flat_path);
        let before_flat = sha256_hex(&flat_absolute_path);
        let before_nested = sha256_hex(&nested_absolute_path);
        let summary = store(&paths).rebuild("research").unwrap();
        assert_eq!(
            (
                summary.approved,
                summary.invalid,
                summary.invalid_count,
                summary.rebuild_state.as_str()
            ),
            (0, 2, 2, REBUILD_STATUS_REJECTED)
        );
        assert_eq!(summary.invalid_claims.len(), 2);
        assert_eq!(summary.invalid_claims[0].path, flat_path);
        assert_eq!(summary.invalid_claims[1].path, nested_path);
        for invalid in &summary.invalid_claims {
            assert!(invalid.error.contains(id));
            assert!(invalid.error.contains(&flat_path));
            assert!(invalid.error.contains(&nested_path));
            assert!(invalid.error.contains("duplicate canonical claim ID"));
        }
        let (manifest, state) = read_published_index_state(&store(&paths), "research");
        assert_eq!(state.status, REBUILD_STATUS_REJECTED);
        assert_eq!(state.invalid_count, 2);
        assert_eq!(state.manifest_digest, manifest.digest);
        assert!(indexed_claim_statuses(&paths, "research").is_empty());
        assert!(!index_dirty_path(&store(&paths), "research").exists());
        assert_eq!(sha256_hex(&flat_absolute_path), before_flat);
        assert_eq!(sha256_hex(&nested_absolute_path), before_nested);
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn rebuild_recovers_pending_transition() {
        let (_dir, paths) = index_test_paths("recover-pending");
        let claim_store = claim_store(&paths);
        let draft = index_claim(
            "clm_99999999999999999999999999999999",
            "Recovered Claim",
            CLAIM_BASIS_OWNER,
        );
        claim_store.write_draft("research", draft.clone()).unwrap();
        let claim_path = paths
            .workspaces_dir
            .join("research/wiki/projects")
            .join(format!("{}.md", draft.id));
        let preimage = std::fs::read(&claim_path).unwrap();
        let mut approved = draft.clone();
        approved.status = CLAIM_STATUS_APPROVED.into();
        approved.verified_at = fixed_index_rfc3339();
        approved.verified_by = "owner".into();
        approved.transitions = vec![crate::claims::ClaimTransition {
            kind: crate::claims::CLAIM_TRANSITION_APPROVE.into(),
            at: approved.verified_at.clone(),
            by: approved.verified_by.clone(),
            ..crate::claims::ClaimTransition::default()
        }];
        approved.verified_digest = crate::claims::claim_verification_digest(&approved).unwrap();
        crate::signing::sign_test_claim(&mut approved);
        let target = crate::claims::render_claim_markdown(&approved).unwrap();
        transition::write_pending_transition(
            &paths,
            "research",
            PendingTransition {
                operation_id: "txn_rebuild".into(),
                kind: crate::claims::CLAIM_TRANSITION_SUPERSEDE.into(),
                workspace: "research".into(),
                targets: vec![PendingTransitionTarget {
                    path: format!("wiki/projects/{}.md", draft.id),
                    preimage_sha256: transition::transition_sha256(&preimage),
                    target_sha256: transition::transition_sha256(&target),
                    target_bytes: target.clone(),
                }],
            },
        )
        .unwrap();

        let summary = store(&paths).rebuild("research").unwrap();
        assert_eq!(
            (summary.approved, summary.rebuild_state.as_str()),
            (1, REBUILD_STATUS_CLEAN)
        );
        store(&paths).check_fresh("research").unwrap();
        assert!(transition::read_pending_transition(&paths, "research")
            .unwrap_err()
            .is_not_found());
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn recovery_leaves_dirty() {
        let (_dir, paths) = index_test_paths("recovery-dirty");
        let path = paths
            .workspaces_dir
            .join("research/wiki/projects/recovery.md");
        let before = b"before\n".to_vec();
        let target = b"after\n".to_vec();
        std::fs::write(&path, &before).unwrap();
        transition::write_pending_transition(
            &paths,
            "research",
            PendingTransition {
                operation_id: "txn_dirty".into(),
                kind: crate::claims::CLAIM_TRANSITION_SUPERSEDE.into(),
                workspace: "research".into(),
                targets: vec![pending_transition_target(
                    "wiki/projects/recovery.md",
                    &before,
                    &target,
                )],
            },
        )
        .unwrap();
        transition::recover_pending_transition_for_mutation(&paths, "research").unwrap();
        assert_file_bytes(&path, &target);
        assert!(index_dirty_path(&store(&paths), "research").exists());
        assert!(transition::read_pending_transition(&paths, "research")
            .unwrap_err()
            .is_not_found());
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn reindex_excludes_tampered_approved_claim() {
        let (_dir, paths) = index_test_paths("tampered");
        let claim_store = claim_store(&paths);
        let mut claim = index_claim(
            "clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "Tampered Search",
            CLAIM_BASIS_OWNER,
        );
        claim.body = "original indexed body\n".into();
        claim_store.write_draft("research", claim.clone()).unwrap();
        claim_store.approve("research", &claim.id).unwrap();

        let claim_path = paths
            .workspaces_dir
            .join("research/wiki/projects")
            .join(format!("{}.md", claim.id));
        let contents = String::from_utf8(std::fs::read(&claim_path).unwrap()).unwrap();
        let contents = contents.replacen("original indexed body", "tampered indexed body", 1);
        std::fs::write(&claim_path, contents).unwrap();

        let summary = store(&paths).rebuild("research").unwrap();
        assert_eq!(
            (
                summary.approved,
                summary.invalid,
                summary.invalid_count,
                summary.rebuild_state.as_str()
            ),
            (0, 1, 1, REBUILD_STATUS_REJECTED)
        );
        let (manifest, state) = read_published_index_state(&store(&paths), "research");
        assert_eq!(state.status, REBUILD_STATUS_REJECTED);
        assert_eq!(state.invalid_count, 1);
        assert_eq!(state.manifest_digest, manifest.digest);
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn rebuild_dependency_canonical_unchanged() {
        let (_dir, paths) = index_test_paths("dependency");
        let claim_store = claim_store(&paths);
        let support = index_claim(
            "clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "Revoked Support",
            CLAIM_BASIS_OWNER,
        );
        claim_store
            .write_draft("research", support.clone())
            .unwrap();
        claim_store.approve("research", &support.id).unwrap();
        let mut dependent = index_claim(
            "clm_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "Dependent Claim",
            CLAIM_BASIS_DERIVED,
        );
        dependent.supporting_claim_ids = vec![support.id.clone()];
        claim_store
            .write_draft("research", dependent.clone())
            .unwrap();
        claim_store.approve("research", &dependent.id).unwrap();
        let unrelated = index_claim(
            "clm_cccccccccccccccccccccccccccccccc",
            "Unrelated Claim",
            CLAIM_BASIS_OWNER,
        );
        claim_store
            .write_draft("research", unrelated.clone())
            .unwrap();
        claim_store.approve("research", &unrelated.id).unwrap();
        claim_store
            .revoke("research", &support.id, "no longer trusted")
            .unwrap();

        let dependent_path = paths
            .workspaces_dir
            .join("research/wiki/projects")
            .join(format!("{}.md", dependent.id));
        let unrelated_path = paths
            .workspaces_dir
            .join("research/wiki/projects")
            .join(format!("{}.md", unrelated.id));
        let dependent_before = sha256_hex(&dependent_path);
        let unrelated_before = sha256_hex(&unrelated_path);
        let summary = store(&paths).rebuild("research").unwrap();
        assert_eq!(
            (
                summary.rebuild_state.as_str(),
                summary.approved,
                summary.invalid,
                summary.invalid_count
            ),
            (REBUILD_STATUS_REJECTED, 1, 1, 1)
        );
        assert_eq!(summary.invalid_claims.len(), 1);
        assert_eq!(
            summary.invalid_claims[0].path,
            format!("projects/{}.md", dependent.id)
        );
        let error = &summary.invalid_claims[0].error;
        assert!(
            error.contains(&dependent.id)
                && error.contains(&support.id)
                && error.contains("revoked")
        );
        let indexed = indexed_claim_statuses(&paths, "research");
        assert!(!indexed.contains_key(&dependent.id));
        assert_eq!(indexed[&unrelated.id], CLAIM_STATUS_APPROVED);
        assert_eq!(sha256_hex(&dependent_path), dependent_before);
        assert_eq!(sha256_hex(&unrelated_path), unrelated_before);
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn evidence_claim_digest_binding() {
        let (_dir, paths) = index_test_paths("evidence-digest");
        let evidence = add_store_evidence(&paths, "original evidence");
        let claim_store = claim_store(&paths);
        let mut support = index_claim(
            "clm_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "Evidence Support",
            CLAIM_BASIS_EVIDENCE,
        );
        support.evidence_ids = vec![evidence.id.clone()];
        claim_store
            .write_draft("research", support.clone())
            .unwrap();
        claim_store.approve("research", &support.id).unwrap();
        let mut dependent = index_claim(
            "clm_ffffffffffffffffffffffffffffffff",
            "Evidence Dependent",
            CLAIM_BASIS_DERIVED,
        );
        dependent.supporting_claim_ids = vec![support.id.clone()];
        claim_store.write_draft("research", dependent).unwrap();
        claim_store
            .approve("research", "clm_ffffffffffffffffffffffffffffffff")
            .unwrap();

        let initial = store(&paths).rebuild("research").unwrap();
        assert_eq!(
            (initial.rebuild_state.as_str(), initial.approved),
            (REBUILD_STATUS_CLEAN, 2)
        );

        let replacement = b"tampered evidence".to_vec();
        let raw_path = paths
            .workspaces_dir
            .join("research/evidence/sources")
            .join(&evidence.id)
            .join("raw");
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = std::fs::metadata(&raw_path).unwrap().permissions();
            permissions.set_mode(0o644);
            std::fs::set_permissions(&raw_path, permissions).unwrap();
        }
        std::fs::write(&raw_path, &replacement).unwrap();
        let mut updated_evidence = evidence.clone();
        updated_evidence.byte_length = replacement.len() as i64;
        updated_evidence.sha256 = sha256_string(&String::from_utf8_lossy(&replacement));
        rewrite_evidence_metadata(&paths, "research", &evidence.id, &updated_evidence);

        let summary = store(&paths).rebuild("research").unwrap();
        assert_eq!(
            (
                summary.rebuild_state.as_str(),
                summary.approved,
                summary.invalid,
                summary.invalid_count
            ),
            (REBUILD_STATUS_REJECTED, 0, 2, 2)
        );
        for invalid in &summary.invalid_claims {
            assert!(invalid.error.contains(&evidence.id));
            assert!(invalid.error.contains("digest mismatch"));
        }
        assert!(indexed_claim_statuses(&paths, "research").is_empty());
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn evidence_claim_metadata_digest_binding() {
        let (_dir, paths) = index_test_paths("evidence-metadata");
        let evidence = add_store_evidence(&paths, "original evidence");
        let claim_store = claim_store(&paths);
        let mut claim = index_claim(
            "clm_11111111111111111111111111111111",
            "Metadata Evidence Claim",
            CLAIM_BASIS_EVIDENCE,
        );
        claim.evidence_ids = vec![evidence.id.clone()];
        claim_store.write_draft("research", claim.clone()).unwrap();
        claim_store.approve("research", &claim.id).unwrap();
        let initial = store(&paths).rebuild("research").unwrap();
        assert_eq!(initial.rebuild_state, REBUILD_STATUS_CLEAN);
        let mut updated_evidence = evidence.clone();
        updated_evidence.media_type = "application/json".into();
        rewrite_evidence_metadata(&paths, "research", &evidence.id, &updated_evidence);

        let summary = store(&paths).rebuild("research").unwrap();
        assert_eq!(
            (
                summary.rebuild_state.as_str(),
                summary.approved,
                summary.invalid,
                summary.invalid_count
            ),
            (REBUILD_STATUS_REJECTED, 0, 1, 1)
        );
        assert_eq!(summary.invalid_claims.len(), 1);
        assert!(summary.invalid_claims[0].error.contains("digest mismatch"));
        assert!(indexed_claim_statuses(&paths, "research").is_empty());
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn rebuild_rejects_legacy_evidence_digest_with_recovery_guidance() {
        let (_dir, paths) = index_test_paths("legacy-digest");
        let evidence = add_store_evidence(&paths, "legacy digest evidence");
        let claim_store = claim_store(&paths);
        let mut claim = index_claim(
            "clm_33333333333333333333333333333333",
            "Legacy Evidence Claim",
            CLAIM_BASIS_EVIDENCE,
        );
        claim.evidence_ids = vec![evidence.id.clone()];
        claim_store.write_draft("research", claim.clone()).unwrap();
        let mut approved = claim_store.approve("research", &claim.id).unwrap();
        approved.sources[0].digest = format!("sha256:{}", evidence.sha256);
        approved.verified_digest = crate::claims::claim_verification_digest(&approved).unwrap();
        crate::signing::sign_test_claim(&mut approved);
        let claim_path = paths
            .workspaces_dir
            .join("research/wiki/projects")
            .join(format!("{}.md", claim.id));
        crate::claims::write_claim_atomic(&claim_path, &approved).unwrap();

        let summary = store(&paths).rebuild("research").unwrap();
        assert_eq!(
            (
                summary.rebuild_state.as_str(),
                summary.approved,
                summary.invalid,
                summary.invalid_count
            ),
            (REBUILD_STATUS_REJECTED, 0, 1, 1)
        );
        assert_eq!(summary.invalid_claims.len(), 1);
        let error = &summary.invalid_claims[0].error;
        assert!(error.contains("legacy raw digest") && error.contains("supersede and reapprove"));
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn rebuild_rejects_evidence_source_closure_mismatch() {
        let (_dir, paths) = index_test_paths("closure-mismatch");
        let evidence = add_store_evidence(&paths, "closure evidence");
        let claim_store = claim_store(&paths);
        let mut claim = index_claim(
            "clm_22222222222222222222222222222222",
            "Closure Evidence Claim",
            CLAIM_BASIS_EVIDENCE,
        );
        claim.evidence_ids = vec![evidence.id.clone()];
        claim_store.write_draft("research", claim.clone()).unwrap();
        let mut approved = claim_store.approve("research", &claim.id).unwrap();
        approved.evidence_ids = vec![evidence.id.clone(), evidence.id.clone()];
        approved.verified_digest = crate::claims::claim_verification_digest(&approved).unwrap();
        crate::signing::sign_test_claim(&mut approved);
        let claim_path = paths
            .workspaces_dir
            .join("research/wiki/projects")
            .join(format!("{}.md", claim.id));
        crate::claims::write_claim_atomic(&claim_path, &approved).unwrap();

        let summary = store(&paths).rebuild("research").unwrap();
        assert_eq!(
            (
                summary.rebuild_state.as_str(),
                summary.approved,
                summary.invalid,
                summary.invalid_count
            ),
            (REBUILD_STATUS_REJECTED, 0, 1, 1)
        );
        assert_eq!(summary.invalid_claims.len(), 1);
        assert!(summary.invalid_claims[0]
            .error
            .contains("duplicate evidence id"));
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn rebuild_evidence_rejected_state() {
        let (_dir, paths) = index_test_paths("evidence-rejected");
        let evidence = add_store_evidence(&paths, "evidence bytes");
        let claim_store = claim_store(&paths);
        let mut claim = index_claim(
            "clm_dddddddddddddddddddddddddddddddd",
            "Tampered Evidence Claim",
            CLAIM_BASIS_EVIDENCE,
        );
        claim.evidence_ids = vec![evidence.id.clone()];
        claim_store.write_draft("research", claim.clone()).unwrap();
        claim_store.approve("research", &claim.id).unwrap();
        let claim_path = paths
            .workspaces_dir
            .join("research/wiki/projects")
            .join(format!("{}.md", claim.id));
        let claim_before = sha256_hex(&claim_path);
        let raw_path = paths
            .workspaces_dir
            .join("research/evidence/sources")
            .join(&evidence.id)
            .join("raw");
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = std::fs::metadata(&raw_path).unwrap().permissions();
            permissions.set_mode(0o644);
            std::fs::set_permissions(&raw_path, permissions).unwrap();
        }
        std::fs::write(&raw_path, "x".repeat(evidence.byte_length as usize)).unwrap();

        let summary = store(&paths).rebuild("research").unwrap();
        assert_eq!(
            (
                summary.rebuild_state.as_str(),
                summary.approved,
                summary.invalid,
                summary.invalid_count
            ),
            (REBUILD_STATUS_REJECTED, 0, 1, 1)
        );
        assert_eq!(summary.invalid_claims.len(), 1);
        let error = &summary.invalid_claims[0].error;
        assert!(error.contains(&evidence.id) && error.contains("raw"));
        assert_eq!(sha256_hex(&claim_path), claim_before);
        assert!(indexed_claim_statuses(&paths, "research").is_empty());
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn rebuild_rejects_dependent_when_supporting_evidence_invalid() {
        let (_dir, paths) = index_test_paths("dependent-evidence");
        let evidence = add_store_evidence(&paths, "support evidence bytes");
        let claim_store = claim_store(&paths);
        let mut support = index_claim(
            "clm_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "Evidence Support",
            CLAIM_BASIS_EVIDENCE,
        );
        support.evidence_ids = vec![evidence.id.clone()];
        claim_store
            .write_draft("research", support.clone())
            .unwrap();
        claim_store.approve("research", &support.id).unwrap();
        let mut dependent = index_claim(
            "clm_ffffffffffffffffffffffffffffffff",
            "Evidence Dependent",
            CLAIM_BASIS_DERIVED,
        );
        dependent.supporting_claim_ids = vec![support.id.clone()];
        claim_store
            .write_draft("research", dependent.clone())
            .unwrap();
        claim_store.approve("research", &dependent.id).unwrap();
        let initial = store(&paths).rebuild("research").unwrap();
        assert_eq!(initial.rebuild_state, REBUILD_STATUS_CLEAN);

        let support_path = paths
            .workspaces_dir
            .join("research/wiki/projects")
            .join(format!("{}.md", support.id));
        let dependent_path = paths
            .workspaces_dir
            .join("research/wiki/projects")
            .join(format!("{}.md", dependent.id));
        let support_before = sha256_hex(&support_path);
        let dependent_before = sha256_hex(&dependent_path);
        let raw_path = paths
            .workspaces_dir
            .join("research/evidence/sources")
            .join(&evidence.id)
            .join("raw");
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = std::fs::metadata(&raw_path).unwrap().permissions();
            permissions.set_mode(0o644);
            std::fs::set_permissions(&raw_path, permissions).unwrap();
        }
        std::fs::write(&raw_path, "x".repeat(evidence.byte_length as usize)).unwrap();

        let summary = store(&paths).rebuild("research").unwrap();
        assert_eq!(
            (
                summary.rebuild_state.as_str(),
                summary.approved,
                summary.invalid,
                summary.invalid_count
            ),
            (REBUILD_STATUS_REJECTED, 0, 2, 2)
        );
        assert_eq!(summary.invalid_claims.len(), 2);
        assert_eq!(
            summary.invalid_claims[0].path,
            format!("projects/{}.md", support.id)
        );
        assert_eq!(
            summary.invalid_claims[1].path,
            format!("projects/{}.md", dependent.id)
        );
        for invalid in &summary.invalid_claims {
            assert!(invalid.error.contains(&evidence.id) && invalid.error.contains("raw"));
        }
        assert!(indexed_claim_statuses(&paths, "research").is_empty());
        assert_eq!(sha256_hex(&support_path), support_before);
        assert_eq!(sha256_hex(&dependent_path), dependent_before);
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn rebuild_cycle_rejected_state() {
        let (_dir, paths) = index_test_paths("cycle");
        let mut first = index_claim(
            "clm_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "Cycle First",
            CLAIM_BASIS_DERIVED,
        );
        let mut second = index_claim(
            "clm_ffffffffffffffffffffffffffffffff",
            "Cycle Second",
            CLAIM_BASIS_DERIVED,
        );
        first.supporting_claim_ids = vec![second.id.clone()];
        second.supporting_claim_ids = vec![first.id.clone()];
        let first = finalize_approved_store_claim(first);
        let second = finalize_approved_store_claim(second);
        write_canonical_store_claim(&paths, &first);
        write_canonical_store_claim(&paths, &second);
        let first_path = paths
            .workspaces_dir
            .join("research/wiki/projects")
            .join(format!("{}.md", first.id));
        let second_path = paths
            .workspaces_dir
            .join("research/wiki/projects")
            .join(format!("{}.md", second.id));
        let first_before = sha256_hex(&first_path);
        let second_before = sha256_hex(&second_path);

        let summary = store(&paths).rebuild("research").unwrap();
        assert_eq!(
            (
                summary.rebuild_state.as_str(),
                summary.approved,
                summary.invalid,
                summary.invalid_count
            ),
            (REBUILD_STATUS_REJECTED, 0, 2, 2)
        );
        assert_eq!(summary.invalid_claims.len(), 2);
        for invalid in &summary.invalid_claims {
            assert!(invalid.error.contains("dependency cycle detected"));
        }
        assert!(indexed_claim_statuses(&paths, "research").is_empty());
        assert_eq!(sha256_hex(&first_path), first_before);
        assert_eq!(sha256_hex(&second_path), second_before);
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn rebuild_manifest() {
        let (_dir, paths) = index_test_paths("manifest");
        let claim_store = claim_store(&paths);
        let claim = index_claim(
            "clm_cccccccccccccccccccccccccccccccc",
            "Manifest Claim",
            CLAIM_BASIS_OWNER,
        );
        claim_store.write_draft("research", claim).unwrap();
        claim_store
            .approve("research", "clm_cccccccccccccccccccccccccccccccc")
            .unwrap();

        let summary = store(&paths).rebuild("research").unwrap();
        let (manifest, state) = read_published_index_state(&store(&paths), "research");
        let expected = build_trust_input_manifest(&paths, "research").unwrap();
        assert!(same_trust_input_manifest(&manifest, &expected));
        assert_eq!(state.status, REBUILD_STATUS_CLEAN);
        assert_eq!(summary.rebuild_state, REBUILD_STATUS_CLEAN);
        assert_eq!(summary.manifest_digest, manifest.digest);
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn rebuild_clean_state() {
        let (_dir, paths) = index_test_paths("clean");
        let summary = store(&paths).rebuild("research").unwrap();
        let (_manifest, state) = read_published_index_state(&store(&paths), "research");
        assert_eq!(summary.rebuild_state, REBUILD_STATUS_CLEAN);
        assert_eq!(summary.invalid_count, 0);
        assert_eq!(state.status, REBUILD_STATUS_CLEAN);
        assert_eq!(state.invalid_count, 0);
        assert!(!index_dirty_path(&store(&paths), "research").exists());
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn check_fresh_accepts_clean_index() {
        let (_dir, paths) = index_test_paths("fresh-clean");
        store(&paths).rebuild("research").unwrap();
        store(&paths).check_fresh("research").unwrap();
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn check_fresh_reports_stale_after_covered_input_edit() {
        let (_dir, paths) = index_test_paths("stale-edit");
        let claim_store = claim_store(&paths);
        let claim = index_claim(
            "clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "Covered Input",
            CLAIM_BASIS_OWNER,
        );
        claim_store.write_draft("research", claim.clone()).unwrap();
        claim_store.approve("research", &claim.id).unwrap();
        store(&paths).rebuild("research").unwrap();
        let claim_path = paths
            .workspaces_dir
            .join("research/wiki/projects")
            .join(format!("{}.md", claim.id));
        let contents = String::from_utf8(std::fs::read(&claim_path).unwrap()).unwrap();
        let contents = contents.replacen("Covered Input", "Changed Covered Input", 1);
        std::fs::write(&claim_path, contents).unwrap();
        let err = store(&paths).check_fresh("research").unwrap_err();
        let message = err.to_string();
        assert!(message.contains("stale"), "{message}");
        assert!(
            message.contains(&claim_path.display().to_string()),
            "{message}"
        );
        assert!(message.contains("run zbrain reindex"), "{message}");
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn check_fresh_reports_stale_after_new_wiki_claim_and_reindex() {
        let (_dir, paths) = index_test_paths("stale-new-claim");
        store(&paths).rebuild("research").unwrap();
        let database_path = index_database_path(&store(&paths), "research");
        let database_info = std::fs::metadata(&database_path).unwrap();
        let claim = index_claim(
            "clm_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "Hand Authored Claim",
            CLAIM_BASIS_OWNER,
        );
        let contents = crate::claims::render_claim_markdown(&claim).unwrap();
        let claim_path = paths
            .workspaces_dir
            .join("research/wiki/projects")
            .join(format!("{}.md", claim.id));
        std::fs::write(&claim_path, contents).unwrap();
        let newer = database_info
            .modified()
            .unwrap()
            .checked_add(TimeDelta::seconds(1).to_std().unwrap())
            .unwrap();
        let newer = chrono::DateTime::<chrono::Utc>::from(newer);
        set_file_times(&claim_path, newer);

        let err = store(&paths).check_fresh("research").unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains(&claim_path.display().to_string()),
            "{message}"
        );
        assert!(message.contains("run zbrain reindex"), "{message}");

        store(&paths).rebuild("research").unwrap();
        store(&paths).check_fresh("research").unwrap();
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn check_fresh_reports_stale_after_trust_input_deletion() {
        let (_dir, paths) = index_test_paths("stale-deletion");
        let claim_store = claim_store(&paths);
        let claim = index_claim(
            "clm_ffffffffffffffffffffffffffffffff",
            "Deleted Claim",
            CLAIM_BASIS_OWNER,
        );
        claim_store.write_draft("research", claim.clone()).unwrap();
        claim_store.approve("research", &claim.id).unwrap();
        store(&paths).rebuild("research").unwrap();
        let claim_path = paths
            .workspaces_dir
            .join("research/wiki/projects")
            .join(format!("{}.md", claim.id));
        std::fs::remove_file(&claim_path).unwrap();
        let err = store(&paths).check_fresh("research").unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains(&claim_path.display().to_string()),
            "{message}"
        );
        assert!(message.contains("run zbrain reindex"), "{message}");
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn file_change_token_metadata_and_combine() {
        // combineChangeStamp cases (1:1 with Go).
        assert_eq!(combine_change_stamp(42, 123), 42 * 1_000_000_000 + 123);
        let unavailable = UNAVAILABLE_FILE_CHANGE_TOKEN;
        assert_eq!(combine_change_stamp(0, -1), unavailable);
        assert_eq!(combine_change_stamp(0, 1_000_000_000), unavailable);
        assert_eq!(combine_change_stamp(i64::MAX, 0), unavailable);
        assert_eq!(combine_change_stamp(i64::MIN, 0), unavailable);
        assert_eq!(combine_change_stamp(-1, 999_999_999), unavailable);

        // On macOS/Linux the stat ctime is always available: the token must
        // match the composed ctime and be positive for a fresh file.
        let (_dir, paths) = index_test_paths("change-token");
        let probe = paths.workspaces_dir.join("research/workspace.md");
        let info = std::fs::symlink_metadata(&probe).unwrap();
        let token = file_change_token(&info);
        assert_eq!(token, combine_change_stamp(info.ctime(), info.ctime_nsec()));
        assert!(token > 0);
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn content_digest_freshness() {
        // claim edit with restored mtime
        let (_dir, paths) = index_test_paths("digest-claim");
        let claim_store = claim_store(&paths);
        let claim = index_claim(
            "clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "Content Digest Claim",
            CLAIM_BASIS_OWNER,
        );
        claim_store.write_draft("research", claim.clone()).unwrap();
        claim_store.approve("research", &claim.id).unwrap();
        store(&paths).rebuild("research").unwrap();
        let claim_path = paths
            .workspaces_dir
            .join("research/wiki/projects")
            .join(format!("{}.md", claim.id));
        let info = std::fs::metadata(&claim_path).unwrap();
        let modified_at = chrono::DateTime::<chrono::Utc>::from(info.modified().unwrap());
        let contents = String::from_utf8(std::fs::read(&claim_path).unwrap()).unwrap();
        let contents = contents.replacen("Content Digest Claim", "Content Digest Delta", 1);
        std::fs::write(&claim_path, contents).unwrap();
        set_file_times(&claim_path, modified_at);
        let err = store(&paths).check_fresh("research").unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains(&claim_path.display().to_string()),
            "{message}"
        );
        assert!(message.contains("run zbrain reindex"), "{message}");
        let _ = std::fs::remove_dir_all(&_dir);

        // evidence edit with restored mtime
        let (_dir, paths) = index_test_paths("digest-evidence");
        let evidence = add_store_evidence(&paths, "original evidence");
        store(&paths).rebuild("research").unwrap();
        let raw_path = paths
            .workspaces_dir
            .join("research/evidence/sources")
            .join(&evidence.id)
            .join("raw");
        let info = std::fs::metadata(&raw_path).unwrap();
        let modified_at = chrono::DateTime::<chrono::Utc>::from(info.modified().unwrap());
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = std::fs::metadata(&raw_path).unwrap().permissions();
            permissions.set_mode(0o644);
            std::fs::set_permissions(&raw_path, permissions).unwrap();
        }
        std::fs::write(&raw_path, b"tampered evidence").unwrap();
        set_file_times(&raw_path, modified_at);
        let err = store(&paths).check_fresh("research").unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains(&raw_path.display().to_string()),
            "{message}"
        );
        assert!(message.contains("run zbrain reindex"), "{message}");
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn content_digest_freshness_fallback_without_change_tokens() {
        set_trust_file_change_token_override(Some(UNAVAILABLE_FILE_CHANGE_TOKEN));
        let (_dir, paths) = index_test_paths("digest-fallback");
        let claim_store = claim_store(&paths);
        let claim = index_claim(
            "clm_12121212121212121212121212121212",
            "Fallback Digest Claim",
            CLAIM_BASIS_OWNER,
        );
        claim_store.write_draft("research", claim.clone()).unwrap();
        claim_store.approve("research", &claim.id).unwrap();
        store(&paths).rebuild("research").unwrap();
        let claim_path = paths
            .workspaces_dir
            .join("research/wiki/projects")
            .join(format!("{}.md", claim.id));
        let info = std::fs::metadata(&claim_path).unwrap();
        let modified_at = chrono::DateTime::<chrono::Utc>::from(info.modified().unwrap());
        let contents = String::from_utf8(std::fs::read(&claim_path).unwrap()).unwrap();
        let contents = contents.replacen("Fallback Digest Claim", "Fallback Digest Delta", 1);
        std::fs::write(&claim_path, contents).unwrap();
        set_file_times(&claim_path, modified_at);
        let err = store(&paths).check_fresh("research").unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains(&claim_path.display().to_string()),
            "{message}"
        );
        assert!(message.contains("run zbrain reindex"), "{message}");
        set_trust_file_change_token_override(None);
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn content_digest_freshness_new_input_with_restored_directory_mtime() {
        let (_dir, paths) = index_test_paths("digest-new-input");
        store(&paths).rebuild("research").unwrap();
        let projects_dir = paths.workspaces_dir.join("research/wiki/projects");
        let info = std::fs::metadata(&projects_dir).unwrap();
        let modified_at = chrono::DateTime::<chrono::Utc>::from(info.modified().unwrap());
        let added_path = projects_dir.join("added.md");
        std::fs::write(&added_path, b"added trust input\n").unwrap();
        set_file_times(&projects_dir, modified_at);
        let err = store(&paths).check_fresh("research").unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains(&added_path.display().to_string()),
            "{message}"
        );
        assert!(message.contains("run zbrain reindex"), "{message}");
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn check_fresh_reports_stale_after_evidence_edit() {
        let (_dir, paths) = index_test_paths("stale-evidence");
        let source_root = paths
            .workspaces_dir
            .join("research/evidence/sources/evd_test");
        std::fs::create_dir_all(&source_root).unwrap();
        let metadata_path = source_root.join("source.yaml");
        let raw_path = source_root.join("raw");
        std::fs::write(&metadata_path, b"id: evd_test\n").unwrap();
        std::fs::write(&raw_path, b"original evidence\n").unwrap();
        store(&paths).rebuild("research").unwrap();
        std::fs::write(&raw_path, b"changed evidence\n").unwrap();
        let err = store(&paths).check_fresh("research").unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains(&raw_path.display().to_string()),
            "{message}"
        );
        assert!(message.contains("run zbrain reindex"), "{message}");
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn check_fresh_rejects_new_wiki_symlink() {
        let (_dir, paths) = index_test_paths("stale-symlink");
        store(&paths).rebuild("research").unwrap();
        let outside_path = _dir.join("outside.md");
        std::fs::write(&outside_path, b"outside\n").unwrap();
        let link_path = paths
            .workspaces_dir
            .join("research/wiki/projects/linked.md");
        std::os::unix::fs::symlink(&outside_path, &link_path).unwrap();
        let err = store(&paths).check_fresh("research").unwrap_err();
        let message = err.to_string();
        assert!(message.contains("symlink"), "{message}");
        assert!(
            message.contains(&link_path.display().to_string()),
            "{message}"
        );
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn outside_edit_does_not_stale_index() {
        let (_dir, paths) = index_test_paths("outside-edit");
        store(&paths).rebuild("research").unwrap();
        let outside_input = paths.workspaces_dir.join("research/workspace.md");
        std::fs::write(&outside_input, b"# edited workspace metadata\n").unwrap();
        store(&paths).check_fresh("research").unwrap();
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn check_fresh_rejects_dirty_missing_rejected_and_malformed_state() {
        // missing
        let (_dir, paths) = index_test_paths("fresh-missing");
        let err = store(&paths).check_fresh("research").unwrap_err();
        assert!(err.to_string().contains("does not exist"), "{err}");
        let _ = std::fs::remove_dir_all(&_dir);

        // dirty
        let (_dir, paths) = index_test_paths("fresh-dirty");
        store(&paths).rebuild("research").unwrap();
        store(&paths).mark_dirty("research").unwrap();
        let err = store(&paths).check_fresh("research").unwrap_err();
        assert!(err.to_string().contains("dirty"), "{err}");
        let _ = std::fs::remove_dir_all(&_dir);

        // rejected
        let (_dir, paths) = index_test_paths("fresh-rejected");
        let legacy_path = paths
            .workspaces_dir
            .join("research/wiki/projects/legacy.md");
        std::fs::write(&legacy_path, b"legacy input\n").unwrap();
        store(&paths).rebuild("research").unwrap();
        let err = store(&paths).check_fresh("research").unwrap_err();
        assert!(err.to_string().contains("rejected"), "{err}");
        let _ = std::fs::remove_dir_all(&_dir);

        // malformed
        let (_dir, paths) = index_test_paths("fresh-malformed");
        store(&paths).rebuild("research").unwrap();
        let database_path = index_database_path(&store(&paths), "research");
        let conn = Connection::open(&database_path).unwrap();
        conn.execute("delete from rebuild_state", []).unwrap();
        drop(conn);
        let err = store(&paths).check_fresh("research").unwrap_err();
        assert!(err.to_string().contains("malformed"), "{err}");
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn rebuild_rejected_state() {
        let (_dir, paths) = index_test_paths("rejected-state");
        let legacy_path = paths
            .workspaces_dir
            .join("research/wiki/projects/legacy.md");
        std::fs::write(&legacy_path, b"legacy input\n").unwrap();
        let summary = store(&paths).rebuild("research").unwrap();
        let (_manifest, state) = read_published_index_state(&store(&paths), "research");
        assert_eq!(summary.rebuild_state, REBUILD_STATUS_REJECTED);
        assert_eq!(summary.invalid_count, 1);
        assert_eq!(state.status, REBUILD_STATUS_REJECTED);
        assert_eq!(state.invalid_count, 1);
        assert!(!index_dirty_path(&store(&paths), "research").exists());
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn rebuild_failure_leaves_dirty() {
        let (_dir, paths) = index_test_paths("failure-dirty");
        let outside = _dir.join("outside.md");
        std::fs::write(&outside, b"outside\n").unwrap();
        let linked = paths
            .workspaces_dir
            .join("research/wiki/projects/linked.md");
        std::os::unix::fs::symlink(&outside, &linked).unwrap();

        assert!(store(&paths).rebuild("research").is_err());
        assert!(index_dirty_path(&store(&paths), "research").exists());
        assert!(
            !index_database_path(&store(&paths), "research").exists(),
            "database must be missing"
        );
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn rebuild_does_not_mutate_canonical() {
        let (_dir, paths) = index_test_paths("canonical-unchanged");
        let claim_store = claim_store(&paths);
        let claim = index_claim(
            "clm_dddddddddddddddddddddddddddddddd",
            "Canonical Claim",
            CLAIM_BASIS_OWNER,
        );
        claim_store.write_draft("research", claim.clone()).unwrap();
        claim_store.approve("research", &claim.id).unwrap();
        let claim_path = paths
            .workspaces_dir
            .join("research/wiki/projects")
            .join(format!("{}.md", claim.id));
        let contents = String::from_utf8(std::fs::read(&claim_path).unwrap()).unwrap();
        let contents = contents.replacen("Canonical Claim", "Tampered Claim", 1);
        std::fs::write(&claim_path, contents).unwrap();
        let before = std::fs::read(&claim_path).unwrap();

        store(&paths).rebuild("research").unwrap();
        let after = std::fs::read(&claim_path).unwrap();
        assert_eq!(before, after);
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn rebuild_recovers_unsupported_index_schema() {
        let (_dir, paths) = index_test_paths("unsupported-schema");
        store(&paths).rebuild("research").unwrap();
        let database_path = store(&paths).database_path("research").unwrap();
        let conn = Connection::open(&database_path).unwrap();
        conn.execute_batch("pragma user_version = 1").unwrap();
        drop(conn);
        let err = store(&paths).check_fresh("research").unwrap_err();
        assert!(
            err.to_string().contains("unsupported index schema version"),
            "{err}"
        );
        store(&paths).rebuild("research").unwrap();
        store(&paths).check_fresh("research").unwrap();
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn index_dirty_marker_blocks_search() {
        let (_dir, paths) = index_test_paths("dirty-blocks-search");
        store(&paths).mark_dirty("research").unwrap();
        let result = store(&paths).search(
            "research",
            SearchOptions {
                query: "anything".into(),
                statuses: vec![CLAIM_STATUS_APPROVED.into()],
                limit: 10,
            },
        );
        assert!(result.is_err(), "Search must fail on dirty index");
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn index_operations_reject_unsafe_or_missing_workspace_before_path_creation() {
        let (_dir, paths) = index_test_paths("unsafe-workspace");
        for workspace in ["../outside", "missing"] {
            assert!(store(&paths).mark_dirty(workspace).is_err(), "{workspace}");
            assert!(store(&paths).check_fresh(workspace).is_err(), "{workspace}");
            assert!(
                store(&paths)
                    .search(
                        workspace,
                        SearchOptions {
                            query: "anything".into(),
                            statuses: vec![CLAIM_STATUS_APPROVED.into()],
                            limit: 10,
                        },
                    )
                    .is_err(),
                "{workspace}"
            );
            assert!(store(&paths).rebuild(workspace).is_err(), "{workspace}");
        }

        std::os::unix::fs::symlink(std::env::temp_dir(), paths.workspaces_dir.join("linked"))
            .unwrap();
        assert!(store(&paths).mark_dirty("linked").is_err());
        assert!(store(&paths).check_fresh("linked").is_err());
        assert!(store(&paths)
            .search(
                "linked",
                SearchOptions {
                    query: "anything".into(),
                    statuses: vec![CLAIM_STATUS_APPROVED.into()],
                    limit: 10,
                },
            )
            .is_err());
        assert!(store(&paths).rebuild("linked").is_err());
        assert!(
            paths.indexes_dir.symlink_metadata().is_err(),
            "invalid index operations created indexes directory"
        );
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn index_operations_reject_symlinked_index_directory() {
        let (_dir, paths) = index_test_paths("symlinked-indexes");
        let outside = _dir.join("outside-indexes");
        std::fs::create_dir_all(&outside).unwrap();
        let linked_indexes = _dir.join("linked-indexes");
        std::os::unix::fs::symlink(&outside, &linked_indexes).unwrap();
        let mut paths = paths;
        paths.indexes_dir = linked_indexes;
        assert!(store(&paths).mark_dirty("research").is_err());
        assert!(store(&paths).check_fresh("research").is_err());
        assert!(store(&paths)
            .search(
                "research",
                SearchOptions {
                    query: "anything".into(),
                    statuses: vec![CLAIM_STATUS_APPROVED.into()],
                    limit: 10,
                },
            )
            .is_err());
        assert!(store(&paths).rebuild("research").is_err());
        assert!(std::fs::read_dir(&outside).unwrap().next().is_none());
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn index_operations_allow_symlinked_ancestor_path() {
        let dir = std::env::temp_dir().join(format!(
            "zbrain-index-{}-symlink-ancestor",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let real_root = dir.join("real");
        std::fs::create_dir_all(&real_root).unwrap();
        let linked_root = dir.join("linked");
        std::os::unix::fs::symlink(&real_root, &linked_root).unwrap();
        let mut paths = crate::paths::Paths::resolve(crate::paths::Options {
            cwd: Some(linked_root.clone()),
            home_dir: Some(linked_root.clone()),
            runtime_dir: Some(linked_root.join(".zbrain")),
        })
        .unwrap();
        paths.key_dir = crate::signing::test_key_dir();
        crate::config::ensure_config(&paths.config_file).unwrap();
        crate::workspace::create_workspace(&paths, "research", &FixedClock::new(fixed_index_now()))
            .unwrap();
        store(&paths).mark_dirty("research").unwrap();
        assert!(index_dirty_path(&store(&paths), "research").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn index_operations_reject_symlinked_index_files() {
        let (_dir, paths) = index_test_paths("symlinked-files");
        store(&paths).rebuild("research").unwrap();

        // database
        {
            let outside = _dir.join("outside.sqlite");
            let before = b"outside database bytes".to_vec();
            std::fs::write(&outside, &before).unwrap();
            std::fs::remove_file(index_database_path(&store(&paths), "research")).unwrap();
            std::os::unix::fs::symlink(&outside, index_database_path(&store(&paths), "research"))
                .unwrap();
            assert!(store(&paths).mark_dirty("research").is_err());
            assert!(store(&paths).check_fresh("research").is_err());
            assert!(store(&paths)
                .search(
                    "research",
                    SearchOptions {
                        query: "anything".into(),
                        statuses: vec![CLAIM_STATUS_APPROVED.into()],
                        limit: 10,
                    },
                )
                .is_err());
            assert!(store(&paths).rebuild("research").is_err());
            assert_eq!(std::fs::read(&outside).unwrap(), before);
        }

        // dirty-marker
        {
            std::fs::remove_file(index_database_path(&store(&paths), "research")).unwrap();
            let outside = _dir.join("outside.dirty");
            let before = b"outside dirty bytes".to_vec();
            std::fs::write(&outside, &before).unwrap();
            std::os::unix::fs::symlink(&outside, index_dirty_path(&store(&paths), "research"))
                .unwrap();
            assert!(store(&paths).mark_dirty("research").is_err());
            assert!(store(&paths).check_fresh("research").is_err());
            assert!(store(&paths)
                .search(
                    "research",
                    SearchOptions {
                        query: "anything".into(),
                        statuses: vec![CLAIM_STATUS_APPROVED.into()],
                        limit: 10,
                    },
                )
                .is_err());
            assert!(store(&paths).rebuild("research").is_err());
            assert_eq!(std::fs::read(&outside).unwrap(), before);
        }
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn reindex_is_deterministic_after_deleting_index() {
        let (_dir, paths) = index_test_paths("deterministic");
        let claim_store = claim_store(&paths);
        let mut claim = index_claim(
            "clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "Deterministic Search",
            CLAIM_BASIS_OWNER,
        );
        claim.body = "alpha beta deterministic body\n".into();
        claim_store.write_draft("research", claim).unwrap();
        claim_store
            .approve("research", "clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .unwrap();
        store(&paths).rebuild("research").unwrap();
        let first = store(&paths)
            .search(
                "research",
                SearchOptions {
                    query: "deterministic".into(),
                    statuses: vec![CLAIM_STATUS_APPROVED.into()],
                    limit: 10,
                },
            )
            .unwrap();
        std::fs::remove_file(index_database_path(&store(&paths), "research")).unwrap();
        store(&paths).rebuild("research").unwrap();
        let second = store(&paths)
            .search(
                "research",
                SearchOptions {
                    query: "deterministic".into(),
                    statuses: vec![CLAIM_STATUS_APPROVED.into()],
                    limit: 10,
                },
            )
            .unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(second.len(), 1);
        assert_eq!(first[0].id, second[0].id);
        assert_eq!(first[0].path, second[0].path);
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn approved_catalog_omits_drafts_and_sorts() {
        let draft = Claim {
            id: "clm_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
            title: "Draft".into(),
            tier: "projects".into(),
            status: CLAIM_STATUS_DRAFT.into(),
            ..Claim::default()
        };
        let second = Claim {
            id: "clm_cccccccccccccccccccccccccccccccc".into(),
            title: "Second".into(),
            tier: "axioms".into(),
            status: CLAIM_STATUS_APPROVED.into(),
            stale_after: "2027-01-01T00:00:00Z".into(),
            ..Claim::default()
        };
        let first = Claim {
            id: "clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            title: "First".into(),
            tier: "projects".into(),
            status: CLAIM_STATUS_APPROVED.into(),
            ..Claim::default()
        };
        let revoked = Claim {
            id: "clm_dddddddddddddddddddddddddddddddd".into(),
            title: "Revoked".into(),
            tier: "projects".into(),
            status: crate::claims::CLAIM_STATUS_REVOKED.into(),
            ..Claim::default()
        };
        let got = approved_catalog(&[draft, second, first, revoked]);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].id, "clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert_eq!(got[0].title, "First");
        assert_eq!(got[0].tier, "projects");
        assert_eq!(got[1].id, "clm_cccccccccccccccccccccccccccccccc");
        assert_eq!(got[1].stale_after, "2027-01-01T00:00:00Z");
    }

    #[test]
    fn rebuild_does_not_write_wiki_catalog() {
        let (_dir, paths) = index_test_paths("no-catalog");
        let claim_store = claim_store(&paths);
        let claim = index_claim(
            "clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "Catalog Claim",
            CLAIM_BASIS_OWNER,
        );
        claim_store.write_draft("research", claim).unwrap();
        claim_store
            .approve("research", "clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .unwrap();
        store(&paths).rebuild("research").unwrap();
        let wiki = paths.workspaces_dir.join("research/wiki");
        let mut files = Vec::new();
        collect_markdown_walk(&wiki, &mut files).unwrap();
        for path in files {
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            assert!(
                !matches!(
                    name.as_str(),
                    "catalog.json" | "_catalog.json" | "index.md" | "_index.md"
                ),
                "unexpected catalog file {}",
                path.display()
            );
        }
        let _ = std::fs::remove_dir_all(&_dir);
    }

    fn collect_markdown_walk(root: &Path, files: &mut Vec<PathBuf>) -> Result<(), IndexError> {
        let mut children: Vec<PathBuf> = std::fs::read_dir(root)?
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .collect();
        children.sort();
        for child in children {
            let info = std::fs::symlink_metadata(&child)?;
            if info.is_dir() {
                collect_markdown_walk(&child, files)?;
                continue;
            }
            files.push(child);
        }
        Ok(())
    }
}
