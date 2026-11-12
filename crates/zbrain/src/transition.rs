// Port of internal/runtime/transition.go: durable pending-transition journal
// for supersession writes. The journal layout is byte-compatible with the Go
// oracle (JSON, struct field order, target bytes base64) so either runtime can
// recover a journal written by the other.
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::boundary::{safe_relative_path, validate_workspace, BoundaryError};
use crate::coordination::{
    begin_canonical_mutation_unlocked, PENDING_TRANSITION_FILE_NAME,
    WORKSPACE_CONTROL_DIRECTORY_NAME,
};
use crate::paths::{ensure_file_mode, Paths, RUNTIME_METADATA_MODE};

pub const CLAIM_TRANSITION_KINDS: [&str; 3] = ["approve", "supersede", "revoke"];

pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingTransition {
    #[serde(rename = "operation_id")]
    pub operation_id: String,
    #[serde(rename = "kind")]
    pub kind: String,
    #[serde(rename = "workspace")]
    pub workspace: String,
    #[serde(rename = "targets")]
    pub targets: Vec<PendingTransitionTarget>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingTransitionTarget {
    #[serde(rename = "path")]
    pub path: String,
    #[serde(rename = "preimage_sha256")]
    pub preimage_sha256: String,
    #[serde(rename = "target_sha256")]
    pub target_sha256: String,
    /// Base64 (standard alphabet, padded) of the target bytes; matches Go's
    /// JSON encoding of []byte.
    #[serde(rename = "target_bytes", with = "base64_bytes")]
    pub target_bytes: Vec<u8>,
}

#[derive(Debug)]
pub enum TransitionError {
    Boundary(BoundaryError),
    Io(std::io::Error),
    Message(String),
    /// The journal does not exist; mirrors os.ErrNotExist handling upstream.
    NotFound,
}

impl TransitionError {
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::NotFound)
    }
}

impl std::fmt::Display for TransitionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Boundary(source) => write!(f, "{source}"),
            Self::Io(source) => write!(f, "{source}"),
            Self::Message(message) => write!(f, "{message}"),
            Self::NotFound => write!(f, "pending transition journal not found"),
        }
    }
}

impl std::error::Error for TransitionError {}

impl From<std::io::Error> for TransitionError {
    fn from(source: std::io::Error) -> Self {
        Self::Io(source)
    }
}

impl From<BoundaryError> for TransitionError {
    fn from(source: BoundaryError) -> Self {
        Self::Boundary(source)
    }
}

pub fn message(err: impl std::fmt::Display) -> TransitionError {
    TransitionError::Message(err.to_string())
}

pub fn new_pending_transition_id() -> Result<String, std::io::Error> {
    let mut buf = [0u8; 16];
    getrandom_fill(&mut buf)?;
    Ok(format!("txn_{}", hex_lower(&buf)))
}

fn getrandom_fill(buf: &mut [u8]) -> std::io::Result<()> {
    // Mirrors crypto/rand.Read: fill from the OS CSPRNG via /dev/urandom.
    use std::io::Read;
    let mut file = std::fs::File::open("/dev/urandom")?;
    file.read_exact(buf)
}

pub fn pending_transition_path(paths: &Paths, workspace: &str) -> Result<PathBuf, TransitionError> {
    let root = validate_workspace(paths, workspace)?;
    let directory = root.join(WORKSPACE_CONTROL_DIRECTORY_NAME);
    validate_pending_transition_directory(&root, &directory)?;
    Ok(directory.join(PENDING_TRANSITION_FILE_NAME))
}

pub fn write_pending_transition(
    paths: &Paths,
    workspace: &str,
    pending: PendingTransition,
) -> Result<(), TransitionError> {
    let _lock =
        crate::coordination::acquire_workspace_lock(paths, workspace, true).map_err(message)?;
    write_pending_transition_unlocked(paths, workspace, pending)
}

pub fn write_pending_transition_unlocked(
    paths: &Paths,
    workspace: &str,
    pending: PendingTransition,
) -> Result<(), TransitionError> {
    let journal_path = pending_transition_path(paths, workspace)?;
    let normalized = normalize_pending_transition(workspace, pending)?;
    let mut encoded = serde_json::to_vec_pretty(&normalized)
        .map_err(|err| message(format!("marshal pending transition: {err}")))?;
    encoded.push(b'\n');

    if let Some(dir) = journal_path.parent() {
        crate::paths::ensure_directory_mode(dir, crate::paths::RUNTIME_DIRECTORY_MODE)
            .map_err(|err| message(format!("create pending transition directory: {err}")))?;
    }
    let dir = journal_path.parent().expect("journal path has parent");
    let file_name = PENDING_TRANSITION_FILE_NAME;
    let mut temporary_path = None;
    for attempt in 0..64 {
        let candidate = dir.join(format!(
            ".{file_name}.{}.{}.tmp",
            std::process::id(),
            attempt
        ));
        use std::os::unix::fs::OpenOptionsExt;
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(RUNTIME_METADATA_MODE)
            .open(&candidate)
        {
            Ok(mut file) => {
                use std::io::Write as _;
                file.write_all(&encoded)
                    .map_err(|err| message(format!("write pending transition journal: {err}")))?;
                file.sync_all()
                    .map_err(|err| message(format!("sync pending transition journal: {err}")))?;
                drop(file);
                temporary_path = Some(candidate);
                break;
            }
            Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(source) => {
                return Err(message(format!(
                    "create pending transition temporary file: {source}"
                )))
            }
        }
    }
    let Some(temporary_path) = temporary_path else {
        return Err(message(
            "create pending transition temporary file: exhausted attempts",
        ));
    };
    let result = (|| -> Result<(), TransitionError> {
        // os.Link fails when the destination exists, which makes the journal
        // exclusive: a second publish while one is pending errors out.
        std::fs::hard_link(&temporary_path, &journal_path)
            .map_err(|err| message(format!("publish pending transition journal: {err}")))?;
        ensure_file_mode(&journal_path, RUNTIME_METADATA_MODE)
            .map_err(|err| message(format!("set pending transition journal permissions: {err}")))?;
        Ok(())
    })();
    let _ = std::fs::remove_file(&temporary_path);
    result
}

pub fn read_pending_transition(
    paths: &Paths,
    workspace: &str,
) -> Result<PendingTransition, TransitionError> {
    let _lock =
        crate::coordination::acquire_workspace_lock(paths, workspace, false).map_err(message)?;
    read_pending_transition_unlocked(paths, workspace)
}

pub fn read_pending_transition_unlocked(
    paths: &Paths,
    workspace: &str,
) -> Result<PendingTransition, TransitionError> {
    let journal_path = pending_transition_path(paths, workspace)?;
    let contents = match std::fs::read(&journal_path) {
        Ok(contents) => contents,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            return Err(TransitionError::NotFound)
        }
        Err(source) => return Err(source.into()),
    };
    let pending: PendingTransition = serde_json::from_slice(&contents)
        .map_err(|err| message(format!("decode pending transition journal: {err}")))?;
    validate_pending_transition_inner(workspace, &pending, true)?;
    Ok(pending)
}

/// CheckPendingTransition is read-only and blocks trust while a journal exists.
pub fn check_pending_transition(paths: &Paths, workspace: &str) -> Result<(), TransitionError> {
    let _lock =
        crate::coordination::acquire_workspace_lock(paths, workspace, false).map_err(message)?;
    check_pending_transition_unlocked(paths, workspace)
}

pub fn check_pending_transition_unlocked(
    paths: &Paths,
    workspace: &str,
) -> Result<(), TransitionError> {
    match read_pending_transition_unlocked(paths, workspace) {
        Ok(pending) => Err(message(format!(
            "workspace {workspace:?} has pending transition {:?}; run zbrain reindex",
            pending.operation_id
        ))),
        Err(err) if err.is_not_found() => Ok(()),
        Err(err) => Err(message(format!(
            "workspace {workspace:?} pending transition is invalid: {err}"
        ))),
    }
}

/// Marks the index dirty before applying a pending journal.
pub fn recover_pending_transition_for_mutation(
    paths: &Paths,
    workspace: &str,
) -> Result<(), TransitionError> {
    let _lock =
        crate::coordination::acquire_workspace_lock(paths, workspace, true).map_err(message)?;
    recover_pending_transition_for_mutation_unlocked(paths, workspace)
}

pub fn recover_pending_transition_for_mutation_unlocked(
    paths: &Paths,
    workspace: &str,
) -> Result<(), TransitionError> {
    let pending = match read_pending_transition_unlocked(paths, workspace) {
        Ok(pending) => pending,
        Err(err) if err.is_not_found() => return Ok(()),
        Err(err) => {
            return Err(message(format!(
                "workspace {workspace:?} pending transition is invalid: {err}"
            )))
        }
    };
    begin_canonical_mutation_unlocked(paths, workspace).map_err(|err| {
        message(format!(
            "mark workspace dirty before pending transition recovery: {err}"
        ))
    })?;
    recover_pending_transition_unlocked(paths, workspace).map_err(|err| {
        message(format!(
            "recover pending transition {:?}: {err}",
            pending.operation_id
        ))
    })
}

pub fn recover_pending_transition(paths: &Paths, workspace: &str) -> Result<(), TransitionError> {
    let _lock =
        crate::coordination::acquire_workspace_lock(paths, workspace, true).map_err(message)?;
    recover_pending_transition_unlocked(paths, workspace)
}

pub fn recover_pending_transition_unlocked(
    paths: &Paths,
    workspace: &str,
) -> Result<(), TransitionError> {
    let pending = match read_pending_transition_unlocked(paths, workspace) {
        Ok(pending) => pending,
        Err(err) if err.is_not_found() => return Ok(()),
        Err(err) => return Err(err),
    };
    let journal_path = pending_transition_path(paths, workspace)?;

    struct TargetState {
        path: PathBuf,
        apply: bool,
    }
    let mut states: Vec<TargetState> = Vec::with_capacity(pending.targets.len());
    for target in &pending.targets {
        let path = resolve_target_path(paths, workspace, &target.path)?;
        let contents = match std::fs::read(&path) {
            Ok(contents) => contents,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                return Err(message(format!(
                    "pending transition target {:?} is missing; expected preimage {}",
                    target.path, target.preimage_sha256
                )))
            }
            Err(source) => {
                return Err(message(format!(
                    "read pending transition target {:?}: {source}",
                    target.path
                )))
            }
        };
        let current = transition_sha256(&contents);
        let apply = if current == target.target_sha256 {
            false
        } else if current == target.preimage_sha256 {
            true
        } else {
            return Err(message(format!(
                "pending transition target {:?} preimage mismatch: got {current}, want {} or {}",
                target.path, target.preimage_sha256, target.target_sha256
            )));
        };
        states.push(TargetState { path, apply });
    }

    for (index, target) in pending.targets.iter().enumerate() {
        if !states[index].apply {
            continue;
        }
        write_transition_bytes_atomic(&states[index].path, &target.target_bytes).map_err(
            |err| {
                message(format!(
                    "apply pending transition target {:?}: {err}",
                    target.path
                ))
            },
        )?;
    }
    for (index, target) in pending.targets.iter().enumerate() {
        let contents = std::fs::read(&states[index].path).map_err(|err| {
            message(format!(
                "verify pending transition target {:?}: {err}",
                target.path
            ))
        })?;
        let got = transition_sha256(&contents);
        if got != target.target_sha256 {
            return Err(message(format!(
                "pending transition target {:?} did not reach target hash: got {got}, want {}",
                target.path, target.target_sha256
            )));
        }
    }
    std::fs::remove_file(&journal_path).map_err(|err| {
        message(format!(
            "remove completed pending transition journal: {err}"
        ))
    })?;
    Ok(())
}

fn resolve_target_path(
    paths: &Paths,
    workspace: &str,
    relative: &str,
) -> Result<PathBuf, TransitionError> {
    crate::boundary::resolve_workspace_path(paths, workspace, relative).map_err(|err| {
        message(format!(
            "resolve pending transition target {relative:?}: {err}"
        ))
    })
}

pub fn validate_pending_transition(
    workspace: &str,
    pending: &PendingTransition,
) -> Result<(), TransitionError> {
    validate_pending_transition_inner(workspace, pending, false)
}

fn normalize_pending_transition(
    workspace: &str,
    pending: PendingTransition,
) -> Result<PendingTransition, TransitionError> {
    validate_pending_transition_inner(workspace, &pending, false)?;
    let mut normalized = pending;
    normalized
        .targets
        .sort_by(|left, right| left.path.cmp(&right.path));
    Ok(normalized)
}

fn validate_pending_transition_inner(
    workspace: &str,
    pending: &PendingTransition,
    require_sorted: bool,
) -> Result<(), TransitionError> {
    if !crate::paths::is_safe_workspace_name(workspace) {
        return Err(message("pending transition workspace is not safe"));
    }
    if pending.workspace != workspace {
        return Err(message(format!(
            "pending transition workspace {:?} does not match {workspace:?}",
            pending.workspace
        )));
    }
    if pending.operation_id.trim().is_empty() {
        return Err(message("pending transition operation_id is required"));
    }
    if !CLAIM_TRANSITION_KINDS.contains(&pending.kind.as_str()) {
        return Err(message(format!(
            "pending transition kind {:?} is not supported",
            pending.kind
        )));
    }
    if pending.targets.is_empty() {
        return Err(message("pending transition targets are required"));
    }
    let mut previous = String::new();
    for target in &pending.targets {
        if safe_relative_path(&target.path).is_err() {
            return Err(message(format!(
                "pending transition target {:?} is unsafe: unsafe relative path",
                target.path
            )));
        }
        if Path::new(&target.path)
            .components()
            .collect::<PathBuf>()
            .to_string_lossy()
            != target.path
        {
            return Err(message(format!(
                "pending transition target {:?} is not slash-normalized",
                target.path
            )));
        }
        if !is_transition_sha256(&target.preimage_sha256) {
            return Err(message(format!(
                "pending transition target {:?} has invalid preimage hash",
                target.path
            )));
        }
        if !is_transition_sha256(&target.target_sha256) {
            return Err(message(format!(
                "pending transition target {:?} has invalid target hash",
                target.path
            )));
        }
        if transition_sha256(&target.target_bytes) != target.target_sha256 {
            return Err(message(format!(
                "pending transition target {:?} target hash does not match target bytes",
                target.path
            )));
        }
        if !previous.is_empty() && target.path <= previous {
            if target.path == previous {
                return Err(message(format!(
                    "pending transition target {:?} is duplicated",
                    target.path
                )));
            }
            if require_sorted {
                return Err(message(format!(
                    "pending transition targets are not sorted at {:?}",
                    target.path
                )));
            }
        }
        previous = target.path.clone();
    }
    Ok(())
}

fn validate_pending_transition_directory(
    root: &Path,
    directory: &Path,
) -> Result<(), TransitionError> {
    let info = match std::fs::symlink_metadata(directory) {
        Ok(info) => info,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => return Err(source.into()),
    };
    if info.file_type().is_symlink() {
        return Err(message(
            "pending transition directory must not be a symlink",
        ));
    }
    if !info.is_dir() {
        return Err(message("pending transition directory is not a directory"));
    }
    let resolved = std::fs::canonicalize(directory)
        .map_err(|err| message(format!("resolve pending transition directory: {err}")))?;
    if !crate::boundary::path_within(root, &resolved) {
        return Err(message(
            "pending transition directory resolves outside workspace",
        ));
    }
    Ok(())
}

pub fn is_transition_sha256(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64
        && hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn transition_sha256(contents: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(contents);
    format!("sha256:{}", hex_lower(&hash.finalize()))
}

pub fn write_transition_bytes_atomic(path: &Path, contents: &[u8]) -> Result<(), TransitionError> {
    let dir = path
        .parent()
        .ok_or_else(|| message("target path has no parent"))?;
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .ok_or_else(|| message("target path has no file name"))?;
    let mut temporary_path = None;
    for attempt in 0..64 {
        let candidate = dir.join(format!(
            ".{file_name}.{}.{}.tmp",
            std::process::id(),
            attempt
        ));
        use std::os::unix::fs::OpenOptionsExt;
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(RUNTIME_METADATA_MODE)
            .open(&candidate)
        {
            Ok(mut file) => {
                use std::io::Write as _;
                file.write_all(contents)?;
                file.sync_all()?;
                drop(file);
                temporary_path = Some(candidate);
                break;
            }
            Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(source) => return Err(source.into()),
        }
    }
    let Some(temporary_path) = temporary_path else {
        return Err(message(
            "create transition temporary file: exhausted attempts",
        ));
    };
    let result = (|| -> Result<(), TransitionError> {
        std::fs::rename(&temporary_path, path)?;
        ensure_file_mode(path, RUNTIME_METADATA_MODE)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary_path);
    }
    result
}

mod base64_bytes {
    //! Minimal standard-alphabet base64 (with padding) matching Go's []byte
    //! JSON encoding.
    use serde::{Deserialize, Deserializer, Serializer};

    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    pub fn encode(input: &[u8]) -> String {
        let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
        for chunk in input.chunks(3) {
            let b0 = chunk[0] as u32;
            let b1 = *chunk.get(1).unwrap_or(&0) as u32;
            let b2 = *chunk.get(2).unwrap_or(&0) as u32;
            let triple = (b0 << 16) | (b1 << 8) | b2;
            out.push(ALPHABET[(triple >> 18) as usize & 0x3f] as char);
            out.push(ALPHABET[(triple >> 12) as usize & 0x3f] as char);
            if chunk.len() > 1 {
                out.push(ALPHABET[(triple >> 6) as usize & 0x3f] as char);
            } else {
                out.push('=');
            }
            if chunk.len() > 2 {
                out.push(ALPHABET[triple as usize & 0x3f] as char);
            } else {
                out.push('=');
            }
        }
        out
    }

    pub fn decode(input: &str) -> Result<Vec<u8>, String> {
        let mut values: Vec<u8> = Vec::with_capacity(input.len());
        for (index, ch) in input.bytes().enumerate() {
            if ch == b'=' {
                let rest = &input[index..];
                if rest.len() > 2 || !rest.bytes().all(|b| b == b'=') {
                    return Err("unexpected padding in base64 value".into());
                }
                break;
            }
            let value = ALPHABET
                .iter()
                .position(|candidate| *candidate == ch)
                .ok_or_else(|| format!("illegal base64 data at input byte {index}"))?;
            values.push(value as u8);
        }
        let mut out = Vec::with_capacity(values.len() * 3 / 4);
        for chunk in values.chunks(4) {
            let mut triple = (chunk[0] as u32) << 18;
            triple |= (chunk.get(1).copied().unwrap_or(0) as u32) << 12;
            triple |= (chunk.get(2).copied().unwrap_or(0) as u32) << 6;
            triple |= chunk.get(3).copied().unwrap_or(0) as u32;
            out.push((triple >> 16) as u8);
            if chunk.len() > 2 {
                out.push((triple >> 8) as u8);
            }
            if chunk.len() > 3 {
                out.push(triple as u8);
            }
        }
        Ok(out)
    }

    pub fn serialize<S: Serializer>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&encode(value))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;
        decode(&text).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// Tests (port of the dedicated transition_test.go set; the Go
// Test*CoverageExtras catch-all files are synthetic coverage tests and are
// not ported).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::FixedClock;
    use crate::config::ensure_config;
    use crate::paths::Options;
    use chrono::{TimeZone, Utc};

    fn fixture(name: &str) -> (PathBuf, Paths) {
        let dir =
            std::env::temp_dir().join(format!("zbrain-transition-{}-{name}", std::process::id()));
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
        let clock = FixedClock::new(Utc.with_ymd_and_hms(2026, 7, 30, 9, 0, 0).unwrap());
        crate::workspace::create_workspace(&paths, "research", &clock).unwrap();
        (dir, paths)
    }

    fn pending_target(path: &str, before: &[u8], target: &[u8]) -> PendingTransitionTarget {
        PendingTransitionTarget {
            path: path.into(),
            preimage_sha256: transition_sha256(before),
            target_sha256: transition_sha256(target),
            target_bytes: target.to_vec(),
        }
    }

    fn assert_file_bytes(path: &Path, want: &[u8]) {
        let got = std::fs::read(path).unwrap();
        assert_eq!(got, want, "{}", path.display());
    }

    fn assert_no_pending_transition(paths: &Paths, workspace: &str) {
        let path = pending_transition_path(paths, workspace).unwrap();
        assert!(!path.exists(), "pending transition journal still exists");
    }

    #[test]
    fn transition_journal_path() {
        let (dir, paths) = fixture("journal-path");
        let journal_path = pending_transition_path(&paths, "research").unwrap();
        let workspace_root = crate::boundary::validate_workspace(&paths, "research").unwrap();
        assert_eq!(
            journal_path,
            workspace_root
                .join(".zbrain")
                .join(PENDING_TRANSITION_FILE_NAME)
        );
        assert!(
            !journal_path.parent().unwrap().exists(),
            "journal directory must not be created by path resolution"
        );
        assert!(pending_transition_path(&paths, "../outside").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn transition_journal() {
        let (dir, paths) = fixture("journal");
        let first_path = paths.workspaces_dir.join("research/wiki/projects/first.md");
        let second_path = paths
            .workspaces_dir
            .join("research/wiki/projects/second.md");
        std::fs::write(&first_path, b"first before\n").unwrap();
        std::fs::write(&second_path, b"second before\n").unwrap();
        let pending = PendingTransition {
            operation_id: "txn_test".into(),
            kind: "supersede".into(),
            workspace: "research".into(),
            targets: vec![
                pending_target(
                    "wiki/projects/second.md",
                    b"second before\n",
                    b"second after\n",
                ),
                pending_target(
                    "wiki/projects/first.md",
                    b"first before\n",
                    b"first after\n",
                ),
            ],
        };
        write_pending_transition(&paths, "research", pending.clone()).unwrap();
        let read = read_pending_transition(&paths, "research").unwrap();
        assert_eq!(read.targets.len(), 2);
        assert_eq!(read.targets[0].path, "wiki/projects/first.md");
        assert_eq!(read.targets[1].path, "wiki/projects/second.md");
        assert_eq!(read.targets[0].target_bytes, b"first after\n");
        assert_eq!(read.targets[1].target_bytes, b"second after\n");
        // Second publish must fail: the journal is exclusive.
        assert!(write_pending_transition(&paths, "research", pending).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn transition_recovery() {
        let (dir, paths) = fixture("recovery");
        let first_path = paths.workspaces_dir.join("research/wiki/projects/first.md");
        let second_path = paths
            .workspaces_dir
            .join("research/wiki/projects/second.md");
        std::fs::write(&first_path, b"first before\n").unwrap();
        std::fs::write(&second_path, b"second before\n").unwrap();
        write_pending_transition(
            &paths,
            "research",
            PendingTransition {
                operation_id: "txn_recovery".into(),
                kind: "supersede".into(),
                workspace: "research".into(),
                targets: vec![
                    pending_target(
                        "wiki/projects/first.md",
                        b"first before\n",
                        b"first after\n",
                    ),
                    pending_target(
                        "wiki/projects/second.md",
                        b"second before\n",
                        b"second after\n",
                    ),
                ],
            },
        )
        .unwrap();
        // Simulate an interruption after the first canonical rename.
        std::fs::write(&first_path, b"first after\n").unwrap();
        recover_pending_transition(&paths, "research").unwrap();
        assert_file_bytes(&first_path, b"first after\n");
        assert_file_bytes(&second_path, b"second after\n");
        assert_no_pending_transition(&paths, "research");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn transition_recovery_at_each_rename() {
        for interruption in 0..=2 {
            let (dir, paths) = fixture(&format!("each-{interruption}"));
            let files = [
                (
                    "wiki/projects/first.md",
                    &b"first before\n"[..],
                    &b"first after\n"[..],
                ),
                (
                    "wiki/projects/second.md",
                    &b"second before\n"[..],
                    &b"second after\n"[..],
                ),
            ];
            for (relative, before, _target) in files {
                std::fs::write(paths.workspaces_dir.join("research").join(relative), before)
                    .unwrap();
            }
            write_pending_transition(
                &paths,
                "research",
                PendingTransition {
                    operation_id: "txn_each_rename".into(),
                    kind: "supersede".into(),
                    workspace: "research".into(),
                    targets: vec![
                        pending_target(files[0].0, files[0].1, files[0].2),
                        pending_target(files[1].0, files[1].1, files[1].2),
                    ],
                },
            )
            .unwrap();
            for file in files.iter().take(interruption) {
                std::fs::write(paths.workspaces_dir.join("research").join(file.0), file.2).unwrap();
            }
            recover_pending_transition(&paths, "research").unwrap();
            for (relative, _before, target) in files {
                assert_file_bytes(
                    &paths.workspaces_dir.join("research").join(relative),
                    target,
                );
            }
            assert_no_pending_transition(&paths, "research");
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    #[test]
    fn transition_recovery_idempotent() {
        let (dir, paths) = fixture("idempotent");
        let path = paths.workspaces_dir.join("research/wiki/projects/claim.md");
        std::fs::write(&path, b"before\n").unwrap();
        write_pending_transition(
            &paths,
            "research",
            PendingTransition {
                operation_id: "txn_idempotent".into(),
                kind: "supersede".into(),
                workspace: "research".into(),
                targets: vec![pending_target(
                    "wiki/projects/claim.md",
                    b"before\n",
                    b"target\n",
                )],
            },
        )
        .unwrap();
        recover_pending_transition(&paths, "research").unwrap();
        recover_pending_transition(&paths, "research").unwrap();
        assert_file_bytes(&path, b"target\n");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn transition_preimage_mismatch() {
        let (dir, paths) = fixture("mismatch");
        let first_path = paths.workspaces_dir.join("research/wiki/projects/first.md");
        let second_path = paths
            .workspaces_dir
            .join("research/wiki/projects/second.md");
        std::fs::write(&first_path, b"first before\n").unwrap();
        std::fs::write(&second_path, b"unexpected\n").unwrap();
        write_pending_transition(
            &paths,
            "research",
            PendingTransition {
                operation_id: "txn_mismatch".into(),
                kind: "supersede".into(),
                workspace: "research".into(),
                targets: vec![
                    pending_target(
                        "wiki/projects/first.md",
                        b"first before\n",
                        b"first after\n",
                    ),
                    pending_target(
                        "wiki/projects/second.md",
                        b"second before\n",
                        b"second after\n",
                    ),
                ],
            },
        )
        .unwrap();
        let err = recover_pending_transition(&paths, "research")
            .unwrap_err()
            .to_string();
        assert!(err.contains("preimage mismatch"), "{err}");
        assert_file_bytes(&first_path, b"first before\n");
        assert_file_bytes(&second_path, b"unexpected\n");
        assert!(read_pending_transition(&paths, "research").is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn transition_journal_rejects_unsafe_or_malformed_targets() {
        let (dir, paths) = fixture("malformed");
        let base = PendingTransition {
            operation_id: "txn_invalid".into(),
            kind: "supersede".into(),
            workspace: "research".into(),
            targets: vec![pending_target(
                "wiki/projects/claim.md",
                b"before\n",
                b"target\n",
            )],
        };
        struct Case {
            name: &'static str,
            mutate: Box<dyn Fn(&mut PendingTransition)>,
        }
        let cases = vec![
            Case {
                name: "path escape",
                mutate: Box::new(|pending: &mut PendingTransition| {
                    pending.targets[0].path = "../outside".into();
                }),
            },
            Case {
                name: "duplicate target",
                mutate: Box::new(|pending: &mut PendingTransition| {
                    let duplicate = pending.targets[0].clone();
                    pending.targets.push(duplicate);
                }),
            },
            Case {
                name: "target bytes hash mismatch",
                mutate: Box::new(|pending: &mut PendingTransition| {
                    pending.targets[0].target_sha256 = transition_sha256(b"other\n");
                }),
            },
        ];
        for case in cases {
            let mut candidate = base.clone();
            (case.mutate)(&mut candidate);
            assert!(
                write_pending_transition(&paths, "research", candidate).is_err(),
                "{}",
                case.name
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_transition_bytes_atomic_errors() {
        let tmp = std::env::temp_dir().join(format!("zbrain-tbytes-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let success_path = tmp.join("success.md");
        write_transition_bytes_atomic(&success_path, b"hello\n").unwrap();
        assert_eq!(std::fs::read(&success_path).unwrap(), b"hello\n");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&success_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );

        // CreateTemp failure: parent is a file, not a directory.
        let blocker = tmp.join("blocker");
        std::fs::write(&blocker, b"x").unwrap();
        assert!(write_transition_bytes_atomic(&blocker.join("target.md"), b"content").is_err());
        // Rename failure: target is an existing directory.
        let dir_target = tmp.join("dirTarget");
        std::fs::create_dir(&dir_target).unwrap();
        assert!(write_transition_bytes_atomic(&dir_target, b"content").is_err());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn check_pending_transition_coverage() {
        let (dir, paths) = fixture("check");
        assert!(check_pending_transition(&paths, "research").is_ok());
        write_pending_transition(
            &paths,
            "research",
            PendingTransition {
                operation_id: "txn_check".into(),
                kind: "supersede".into(),
                workspace: "research".into(),
                targets: vec![pending_target(
                    "wiki/projects/check.md",
                    b"before\n",
                    b"after\n",
                )],
            },
        )
        .unwrap();
        std::fs::create_dir_all(paths.workspaces_dir.join("research/wiki/projects")).unwrap();
        std::fs::write(
            paths.workspaces_dir.join("research/wiki/projects/check.md"),
            b"before\n",
        )
        .unwrap();
        let err = check_pending_transition(&paths, "research")
            .unwrap_err()
            .to_string();
        assert!(err.contains("pending transition"), "{err}");
        let journal_path = pending_transition_path(&paths, "research").unwrap();
        std::fs::write(&journal_path, b"not json").unwrap();
        let err = check_pending_transition(&paths, "research")
            .unwrap_err()
            .to_string();
        assert!(err.contains("invalid"), "{err}");
        assert!(check_pending_transition(&paths, "../outside").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_pending_transition_coverage() {
        let valid = PendingTransition {
            operation_id: "txn_valid".into(),
            kind: "approve".into(),
            workspace: "research".into(),
            targets: vec![pending_target(
                "wiki/projects/valid.md",
                b"before\n",
                b"after\n",
            )],
        };
        validate_pending_transition("research", &valid).unwrap();

        let mut invalid = valid.clone();
        invalid.workspace = "other".into();
        assert!(validate_pending_transition("research", &invalid).is_err());

        let mut invalid = valid.clone();
        invalid.operation_id = String::new();
        assert!(validate_pending_transition("research", &invalid).is_err());

        let mut invalid = valid;
        invalid.kind = "unknown".into();
        assert!(validate_pending_transition("research", &invalid).is_err());
    }

    #[test]
    fn transition_coverage_extras() {
        assert!(!is_transition_sha256("sha256:zzzz"));
        assert!(!is_transition_sha256(&format!("sha256:{}", "a".repeat(63))));
        assert_eq!(transition_sha256(b"test").len(), "sha256:".len() + 64);
        let id = new_pending_transition_id().unwrap();
        assert!(id.starts_with("txn_"), "{id}");

        let (dir, paths) = fixture("symlink-journal");
        let workspace_root = crate::boundary::validate_workspace(&paths, "research").unwrap();
        let zbrain_dir = workspace_root.join(".zbrain");
        let _ = std::fs::remove_dir_all(&zbrain_dir);
        let outside = dir.join("outside-control");
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, &zbrain_dir).unwrap();
        assert!(pending_transition_path(&paths, "research").is_err());
        std::fs::remove_file(&zbrain_dir).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
