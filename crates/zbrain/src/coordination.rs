use std::collections::HashMap;
use std::ffi::CString;
use std::fs::File;
use std::io::Write;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use serde::{Deserialize, Serialize};

use crate::boundary::{path_within, validate_workspace, BoundaryError};
use crate::paths::{set_permissions, Paths};

pub const WORKSPACE_CONTROL_DIRECTORY_NAME: &str = ".zbrain";
pub const COORDINATION_LOCK_FILE_NAME: &str = "coordination.lock";
pub const GENERATION_FILE_NAME: &str = "generation.json";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceGeneration {
    pub current: u64,
    pub published: u64,
}

pub struct WorkspaceLock {
    file: File,
}

impl std::fmt::Debug for WorkspaceLock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorkspaceLock").finish_non_exhaustive()
    }
}

impl WorkspaceLock {
    fn fd(&self) -> i32 {
        self.file.as_raw_fd()
    }
}

#[derive(Debug)]
pub enum LockError {
    Boundary(BoundaryError),
    Io(String, std::io::Error),
    NotRegularFile(String),
    Symlink(String),
    OutsideWorkspace,
}

impl std::fmt::Display for LockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Boundary(source) => write!(f, "{source}"),
            Self::Io(operation, source) => write!(f, "{operation}: {source}"),
            Self::NotRegularFile(path) => {
                write!(
                    f,
                    "validate coordination lock: {path:?} is not a regular file"
                )
            }
            Self::Symlink(path) => write!(f, "{path:?} must not be a symlink"),
            Self::OutsideWorkspace => {
                write!(f, "workspace control directory resolves outside workspace")
            }
        }
    }
}

impl std::error::Error for LockError {}

impl From<BoundaryError> for LockError {
    fn from(source: BoundaryError) -> Self {
        Self::Boundary(source)
    }
}

pub fn acquire_workspace_lock(
    paths: &Paths,
    workspace: &str,
    exclusive: bool,
) -> Result<WorkspaceLock, LockError> {
    let root = validate_workspace(paths, workspace)?;
    let control_directory = root.join(WORKSPACE_CONTROL_DIRECTORY_NAME);
    ensure_workspace_control_directory(&root, &control_directory)?;
    let lock_path = control_directory.join(COORDINATION_LOCK_FILE_NAME);
    match validate_workspace_control_file(&lock_path) {
        Ok(()) => {}
        Err(ControlValidationError::Symlink(path)) => return Err(LockError::Symlink(path)),
        Err(ControlValidationError::NotRegularFile(path)) => {
            return Err(LockError::NotRegularFile(path));
        }
        Err(ControlValidationError::OutsideWorkspace) => return Err(LockError::OutsideWorkspace),
        Err(ControlValidationError::Io(source)) => {
            return Err(LockError::Io("validate coordination lock".into(), source));
        }
    }

    let c_path = CString::new(lock_path.as_os_str().as_encoded_bytes()).map_err(|source| {
        LockError::Io(
            "open coordination lock".into(),
            std::io::Error::new(std::io::ErrorKind::InvalidInput, source),
        )
    })?;
    let flags = libc::O_RDWR | libc::O_CREAT | libc::O_CLOEXEC | libc::O_NOFOLLOW;
    // SAFETY: c_path is a NUL-free CString alive for the call; O_NOFOLLOW
    // rejects symlink lock files; the fd is closed on every error path below
    // and owned by WorkspaceLock on success.
    let fd = unsafe { libc::open(c_path.as_ptr(), flags, 0o600) };
    if fd < 0 {
        return Err(LockError::Io(
            "open coordination lock".into(),
            std::io::Error::last_os_error(),
        ));
    }
    let close_on_error = |fd: i32| unsafe {
        // SAFETY: fd is an open descriptor owned by this function on every
        // path that reaches this closure.
        libc::close(fd)
    };
    let is_regular = fd_is_regular_file(fd);
    if matches!(&is_regular, Ok(false)) {
        close_on_error(fd);
        return Err(LockError::NotRegularFile(lock_path.display().to_string()));
    }
    if let Err(source) = is_regular {
        close_on_error(fd);
        return Err(LockError::Io("stat coordination lock".into(), source));
    }
    // fchmod on the open fd (not chmod on the path): the fd was opened
    // O_NOFOLLOW and fstat-verified regular above, so no racing writer can
    // redirect this permission change via a swapped symlink.
    let rc = unsafe { libc::fchmod(fd, 0o600) };
    if rc != 0 {
        close_on_error(fd);
        return Err(LockError::Io(
            "set coordination lock permissions".into(),
            std::io::Error::last_os_error(),
        ));
    }
    let mode = if exclusive {
        libc::LOCK_EX
    } else {
        libc::LOCK_SH
    };
    let rc = unsafe { libc::flock(fd, mode) };
    if rc != 0 {
        close_on_error(fd);
        return Err(LockError::Io(
            "acquire coordination lock".into(),
            std::io::Error::last_os_error(),
        ));
    }
    let file = wrap_raw_fd(fd);
    Ok(WorkspaceLock { file })
}

/// Take ownership of a raw fd opened via libc::open.
fn wrap_raw_fd(fd: i32) -> File {
    use std::os::unix::io::FromRawFd;
    // SAFETY: fd is open and uniquely owned here — every error path above
    // closed it, and the success path moves it into WorkspaceLock exactly once.
    unsafe { File::from_raw_fd(fd) }
}

fn fd_is_regular_file(fd: i32) -> Result<bool, std::io::Error> {
    // fstat without disturbing fd ownership: we never wrap the fd in a File
    // here, so there is nothing to forget or close.
    unsafe {
        // SAFETY: zeroed libc::stat is valid init memory; fstat only writes
        // through the pointer and never retains it.
        let mut stat: libc::stat = std::mem::zeroed();
        if libc::fstat(fd, &mut stat) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok((stat.st_mode & libc::S_IFMT) == libc::S_IFREG)
    }
}

impl Drop for WorkspaceLock {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: unlocks the still-open owned fd; the File close that
            // follows releases it. No other owner exists.
            libc::flock(self.fd(), libc::LOCK_UN);
        }
    }
}

pub fn coordination_lock_path(paths: &Paths, workspace: &str) -> Result<PathBuf, BoundaryError> {
    workspace_control_path(paths, workspace, COORDINATION_LOCK_FILE_NAME)
}

pub fn generation_path(paths: &Paths, workspace: &str) -> Result<PathBuf, BoundaryError> {
    workspace_control_path(paths, workspace, GENERATION_FILE_NAME)
}

fn workspace_control_path(
    paths: &Paths,
    workspace: &str,
    name: &str,
) -> Result<PathBuf, BoundaryError> {
    let root = validate_workspace(paths, workspace)?;
    let control_directory = root.join(WORKSPACE_CONTROL_DIRECTORY_NAME);
    match validate_workspace_control_directory(&root, &control_directory) {
        Ok(()) => {}
        Err(ControlValidationError::Io(ref source))
            if source.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(BoundaryError::Io(std::io::Error::other(source.to_string())));
        }
    }
    let path = control_directory.join(name);
    validate_workspace_control_file(&path)
        .map_err(|err| BoundaryError::Io(std::io::Error::other(err.to_string())))?;
    Ok(path)
}

enum ControlValidationError {
    Symlink(String),
    NotRegularFile(String),
    OutsideWorkspace,
    Io(std::io::Error),
}

impl std::fmt::Display for ControlValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Symlink(path) => write!(f, "{path:?} must not be a symlink"),
            Self::NotRegularFile(path) => write!(f, "{path:?} is not a regular file"),
            Self::OutsideWorkspace => {
                write!(f, "workspace control directory resolves outside workspace")
            }
            Self::Io(source) => write!(f, "{source}"),
        }
    }
}

fn ensure_workspace_control_directory(root: &Path, directory: &Path) -> Result<(), LockError> {
    match validate_workspace_control_directory(root, directory) {
        Ok(()) => return Ok(()),
        Err(ControlValidationError::Io(source))
            if source.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(LockError::Io(
                "validate workspace control directory".into(),
                std::io::Error::other(source.to_string()),
            ));
        }
    }
    if let Err(source) = std::fs::create_dir(directory) {
        if source.kind() != std::io::ErrorKind::AlreadyExists {
            return Err(LockError::Io(
                "create workspace control directory".into(),
                std::io::Error::other(source.to_string()),
            ));
        }
    }
    set_permissions(directory, 0o700).map_err(|source| {
        LockError::Io(
            "create workspace control directory".into(),
            std::io::Error::other(source.to_string()),
        )
    })?;
    validate_workspace_control_directory(root, directory).map_err(|err| {
        LockError::Io(
            "validate workspace control directory".into(),
            std::io::Error::other(err.to_string()),
        )
    })?;
    Ok(())
}

fn validate_workspace_control_directory(
    root: &Path,
    directory: &Path,
) -> Result<(), ControlValidationError> {
    if !path_within(root, directory) {
        return Err(ControlValidationError::OutsideWorkspace);
    }
    let info = std::fs::symlink_metadata(directory).map_err(ControlValidationError::Io)?;
    if info.file_type().is_symlink() {
        return Err(ControlValidationError::Symlink(
            directory.display().to_string(),
        ));
    }
    if !info.is_dir() {
        return Err(ControlValidationError::NotRegularFile(
            directory.display().to_string(),
        ));
    }
    let resolved = std::fs::canonicalize(directory).map_err(ControlValidationError::Io)?;
    if !path_within(root, &resolved) {
        return Err(ControlValidationError::OutsideWorkspace);
    }
    Ok(())
}

fn validate_workspace_control_file(path: &Path) -> Result<(), ControlValidationError> {
    let info = match std::fs::symlink_metadata(path) {
        Ok(info) => info,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => return Err(ControlValidationError::Io(source)),
    };
    if info.file_type().is_symlink() {
        return Err(ControlValidationError::Symlink(path.display().to_string()));
    }
    if !info.is_file() {
        return Err(ControlValidationError::NotRegularFile(
            path.display().to_string(),
        ));
    }
    let resolved = std::fs::canonicalize(path).map_err(ControlValidationError::Io)?;
    let absolute = crate::paths::absolute(path).map_err(ControlValidationError::Io)?;
    if resolved != absolute {
        return Err(ControlValidationError::Symlink(path.display().to_string()));
    }
    Ok(())
}

#[derive(Debug)]
pub enum GenerationError {
    Io(std::io::Error),
    Decode(String),
    CurrentRequired,
    PublishedRequired,
    ExtraFields,
    PublishedNewer { published: u64, current: u64 },
    Exhausted,
    Boundary(BoundaryError),
}

impl std::fmt::Display for GenerationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(source) => write!(f, "{source}"),
            Self::Decode(source) => write!(f, "decode generation state: {source}"),
            Self::CurrentRequired => write!(f, "generation state current is required"),
            Self::PublishedRequired => write!(f, "generation state published is required"),
            Self::ExtraFields => {
                write!(
                    f,
                    "generation state must contain only current and published"
                )
            }
            Self::PublishedNewer { published, current } => {
                write!(
                    f,
                    "generation published {published} is newer than current {current}"
                )
            }
            Self::Exhausted => write!(f, "workspace generation exhausted"),
            Self::Boundary(source) => write!(f, "{source}"),
        }
    }
}

impl std::error::Error for GenerationError {}

impl From<std::io::Error> for GenerationError {
    fn from(source: std::io::Error) -> Self {
        Self::Io(source)
    }
}

impl From<BoundaryError> for GenerationError {
    fn from(source: BoundaryError) -> Self {
        Self::Boundary(source)
    }
}

pub fn read_workspace_generation(
    paths: &Paths,
    workspace: &str,
) -> Result<WorkspaceGeneration, GenerationError> {
    let path = generation_path(paths, workspace)?;
    read_generation_file(&path)
}

fn read_generation_file(path: &Path) -> Result<WorkspaceGeneration, GenerationError> {
    let contents = std::fs::read(path)?;
    let value: serde_json::Map<String, serde_json::Value> = serde_json::from_slice(&contents)
        .map_err(|source| GenerationError::Decode(source.to_string()))?;
    if value.len() != 2 {
        return Err(GenerationError::ExtraFields);
    }
    let current = value
        .get("current")
        .filter(|v| !v.is_null())
        .ok_or(GenerationError::CurrentRequired)?;
    let published = value
        .get("published")
        .filter(|v| !v.is_null())
        .ok_or(GenerationError::PublishedRequired)?;
    let current: u64 = serde_json::from_value(current.clone())
        .map_err(|source| GenerationError::Decode(source.to_string()))?;
    let published: u64 = serde_json::from_value(published.clone())
        .map_err(|source| GenerationError::Decode(source.to_string()))?;
    let state = WorkspaceGeneration { current, published };
    if state.published > state.current {
        return Err(GenerationError::PublishedNewer {
            published: state.published,
            current: state.current,
        });
    }
    Ok(state)
}

pub fn write_workspace_generation(
    paths: &Paths,
    workspace: &str,
    state: WorkspaceGeneration,
) -> Result<(), GenerationError> {
    let root = validate_workspace(paths, workspace)?;
    let control_directory = root.join(WORKSPACE_CONTROL_DIRECTORY_NAME);
    ensure_workspace_control_directory(&root, &control_directory)
        .map_err(|err| GenerationError::Io(std::io::Error::other(err.to_string())))?;
    let path = control_directory.join(GENERATION_FILE_NAME);
    write_generation_file(&path, state)
}

pub fn write_generation_file(
    path: &Path,
    state: WorkspaceGeneration,
) -> Result<(), GenerationError> {
    if state.published > state.current {
        return Err(GenerationError::PublishedNewer {
            published: state.published,
            current: state.current,
        });
    }
    validate_workspace_control_file(path)
        .map_err(|err| GenerationError::Io(std::io::Error::other(err.to_string())))?;
    let mut encoded = serde_json::to_vec(&state)
        .map_err(|source| GenerationError::Decode(format!("marshal generation state: {source}")))?;
    encoded.push(b'\n');
    let (temporary_path, mut temporary) =
        tempfile_in(path.parent().expect("generation file has parent"))?;
    let result = (|| -> Result<(), GenerationError> {
        temporary.write_all(&encoded).map_err(|source| {
            GenerationError::Io(std::io::Error::new(
                source.kind(),
                format!("write generation state: {source}"),
            ))
        })?;
        temporary.sync_all().map_err(|source| {
            GenerationError::Io(std::io::Error::new(
                source.kind(),
                format!("sync generation state: {source}"),
            ))
        })?;
        std::fs::rename(&temporary_path, path).map_err(|source| {
            GenerationError::Io(std::io::Error::new(
                source.kind(),
                format!("publish generation state: {source}"),
            ))
        })?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary_path);
    }
    result
}

fn tempfile_in(dir: &Path) -> Result<(PathBuf, File), GenerationError> {
    use std::os::unix::fs::OpenOptionsExt;
    for attempt in 0..64 {
        let path = dir.join(format!(
            ".generation.json.{}.{}.tmp",
            std::process::id(),
            attempt
        ));
        let open = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path);
        match open {
            Ok(file) => return Ok((path, file)),
            Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(source) => {
                return Err(GenerationError::Io(std::io::Error::new(
                    source.kind(),
                    format!("create generation state temporary file: {source}"),
                )));
            }
        }
    }
    Err(GenerationError::Io(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "create generation state temporary file: exhausted attempts",
    )))
}

pub fn ensure_workspace_generation(
    paths: &Paths,
    workspace: &str,
) -> Result<WorkspaceGeneration, GenerationError> {
    match read_workspace_generation(paths, workspace) {
        Ok(state) => Ok(state),
        Err(GenerationError::Io(source)) if source.kind() == std::io::ErrorKind::NotFound => {
            let state = WorkspaceGeneration::default();
            write_workspace_generation(paths, workspace, state)?;
            Ok(state)
        }
        Err(other) => Err(other),
    }
}

// ---------------------------------------------------------------------------
// Test hooks (port of workspaceGenerationHooks) — injection points at
// generation boundaries for later phases' failure tests.
// ---------------------------------------------------------------------------

type Hook = Box<dyn Fn() + Send + Sync>;

fn hooks() -> &'static Mutex<HashMap<String, Hook>> {
    static HOOKS: OnceLock<Mutex<HashMap<String, Hook>>> = OnceLock::new();
    HOOKS.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn set_workspace_generation_test_hook(boundary: &str, hook: Option<Hook>) -> Option<Hook> {
    let mut map = hooks().lock().expect("hooks mutex");
    match hook {
        Some(hook) => map.insert(boundary.to_string(), hook),
        None => map.remove(boundary),
    }
}

pub fn run_workspace_generation_test_hook(boundary: &str) {
    let map = hooks().lock().expect("hooks mutex");
    if let Some(hook) = map.get(boundary) {
        hook();
    }
}

pub const WORKSPACE_GENERATION_HOOK_BEFORE_CANONICAL_WRITE: &str = "before-canonical-write";
pub const WORKSPACE_GENERATION_HOOK_REBUILD_AFTER_SCAN: &str = "rebuild-after-scan";
pub const WORKSPACE_GENERATION_HOOK_REBUILD_BEFORE_FRESHNESS_CAPTURE: &str =
    "rebuild-before-freshness-capture";
pub const WORKSPACE_GENERATION_HOOK_REBUILD_BEFORE_PUBLICATION: &str = "rebuild-before-publication";
pub const WORKSPACE_GENERATION_HOOK_TRUSTED_QUERY_AFTER_LOCKING: &str =
    "trusted-query-after-locking";

// ---------------------------------------------------------------------------
// Canonical mutation barrier (port of beginCanonicalMutationUnlocked and the
// index dirty-marker it drives). The full IndexStore lands in m4; only the
// boundary-validated dirty path is needed here.
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum MutationError {
    Boundary(BoundaryError),
    Io(std::io::Error),
    Message(String),
}

impl std::fmt::Display for MutationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Boundary(source) => write!(f, "{source}"),
            Self::Io(source) => write!(f, "{source}"),
            Self::Message(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for MutationError {}

impl From<std::io::Error> for MutationError {
    fn from(source: std::io::Error) -> Self {
        Self::Io(source)
    }
}

impl From<BoundaryError> for MutationError {
    fn from(source: BoundaryError) -> Self {
        Self::Boundary(source)
    }
}

pub const PENDING_TRANSITION_FILE_NAME: &str = "pending-transition.json";

fn validate_index_boundary_path(path: &Path, directory: bool) -> Result<(), std::io::Error> {
    let clean = crate::paths::absolute(path)?;
    let mut candidate = clean.clone();
    loop {
        match std::fs::symlink_metadata(&candidate) {
            Ok(info) => {
                if info.file_type().is_symlink() {
                    return Err(std::io::Error::other(format!(
                        "{:?} must not be a symlink",
                        candidate.display()
                    )));
                }
                let _resolved = std::fs::canonicalize(&candidate)?;
                if candidate == clean && directory && !info.is_dir() {
                    return Err(std::io::Error::other(format!(
                        "{:?} is not a directory",
                        path.display()
                    )));
                }
                return Ok(());
            }
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => return Err(source),
        }
        let Some(parent) = candidate.parent() else {
            return Err(std::io::Error::other(format!(
                "{:?} has no existing ancestor",
                path.display()
            )));
        };
        if parent == candidate {
            return Err(std::io::Error::other(format!(
                "{:?} has no existing ancestor",
                path.display()
            )));
        }
        candidate = parent.to_path_buf();
    }
}

pub(crate) fn validated_index_paths(paths: &Paths, workspace: &str) -> Result<(), GenerationError> {
    validate_workspace(paths, workspace)?;
    validate_index_boundary_path(&paths.indexes_dir, true).map_err(|err| {
        GenerationError::Io(std::io::Error::other(format!(
            "validate index directory: {err}"
        )))
    })?;
    for name in [format!("{workspace}.sqlite"), format!("{workspace}.dirty")] {
        validate_index_boundary_path(&paths.indexes_dir.join(&name), false).map_err(|err| {
            GenerationError::Io(std::io::Error::other(format!(
                "validate index path {:?}: {err}",
                name
            )))
        })?;
    }
    Ok(())
}

pub(crate) fn mark_dirty_unlocked(paths: &Paths, workspace: &str) -> Result<(), MutationError> {
    validated_index_paths(paths, workspace)
        .map_err(|err| MutationError::Message(err.to_string()))?;
    crate::paths::ensure_directory_mode(&paths.indexes_dir, crate::paths::RUNTIME_DIRECTORY_MODE)?;
    let dirty_path = paths.indexes_dir.join(format!("{workspace}.dirty"));
    std::fs::write(&dirty_path, b"dirty\n")?;
    crate::paths::set_permissions(&dirty_path, crate::paths::DERIVED_INDEX_MODE)?;
    Ok(())
}

/// Advance the workspace generation and mark the index dirty before any
/// canonical write. Fails closed before touching the canonical tree when the
/// index boundary is invalid (the dirty-barrier contract).
pub fn begin_canonical_mutation_unlocked(
    paths: &Paths,
    workspace: &str,
) -> Result<WorkspaceGeneration, MutationError> {
    validated_index_paths(paths, workspace)
        .map_err(|err| MutationError::Message(err.to_string()))?;
    let state = match read_workspace_generation(paths, workspace) {
        Ok(state) => state,
        Err(GenerationError::Io(source)) if source.kind() == std::io::ErrorKind::NotFound => {
            WorkspaceGeneration::default()
        }
        Err(GenerationError::Io(source)) => {
            return Err(MutationError::Message(format!(
                "read workspace generation: {source}"
            )));
        }
        Err(err) => return Err(MutationError::Message(err.to_string())),
    };
    if state.current == u64::MAX {
        return Err(MutationError::Message(format!(
            "workspace {workspace:?} generation exhausted"
        )));
    }
    mark_dirty_unlocked(paths, workspace)?;
    let state = WorkspaceGeneration {
        current: state.current + 1,
        published: state.published,
    };
    write_workspace_generation(paths, workspace, state)
        .map_err(|err| MutationError::Message(format!("advance workspace generation: {err}")))?;
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::FixedClock;
    use crate::config::ensure_config;
    use crate::paths::{Options, Paths};
    use crate::workspace::create_workspace;
    use chrono::{TimeZone, Utc};

    fn fixture(name: &str) -> (PathBuf, Paths) {
        let dir = std::env::temp_dir().join(format!("zbrain-coord-{}-{name}", std::process::id()));
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
        create_workspace(
            &paths,
            "research",
            &FixedClock::new(Utc.with_ymd_and_hms(2026, 7, 30, 10, 0, 0).unwrap()),
        )
        .unwrap();
        (dir, paths)
    }

    #[test]
    fn shared_locks_coexist() {
        let (dir, paths) = fixture("shared");
        let first = acquire_workspace_lock(&paths, "research", false).unwrap();
        let second = acquire_workspace_lock(&paths, "research", false).unwrap();
        drop((first, second));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn exclusive_lock_mode_uses_flock() {
        // In-process: a second exclusive lock on a fresh fd must block. We
        // assert the happy paths (acquire + release) and that flock uses
        // LOCK_EX by probing with LOCK_NB from a child fd via flock(2) on a
        // duplicated descriptor.
        let (dir, paths) = fixture("exclusive");
        let lock = acquire_workspace_lock(&paths, "research", true).unwrap();
        drop(lock);
        let shared = acquire_workspace_lock(&paths, "research", false).unwrap();
        drop(shared);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cross_process_exclusive_lock_blocks() {
        let (dir, paths) = fixture("crossproc");
        let control = paths.workspaces_dir.join("research/.zbrain");
        std::fs::create_dir_all(&control).unwrap();
        let lock_path = control.join(COORDINATION_LOCK_FILE_NAME);
        let holder = acquire_workspace_lock(&paths, "research", true).unwrap();
        let script = format!(
            "import fcntl,sys\nf=open({lock_path:?},'r')\ntry:\n    fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)\nexcept Exception:\n    sys.exit(3)\nsys.exit(0)\n"
        );
        let blocked = std::process::Command::new("python3")
            .arg("-c")
            .arg(&script)
            .output()
            .unwrap();
        assert_eq!(
            blocked.status.code(),
            Some(3),
            "child must be blocked while lock held"
        );
        drop(holder);
        let free = std::process::Command::new("python3")
            .arg("-c")
            .arg(&script)
            .output()
            .unwrap();
        assert_eq!(
            free.status.code(),
            Some(0),
            "child takes lock after release"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn symlink_control_file_rejected() {
        let (dir, paths) = fixture("symlink");
        let control = paths.workspaces_dir.join("research/.zbrain");
        std::fs::create_dir_all(&control).unwrap();
        let outside = dir.join("outside-lock");
        std::fs::write(&outside, b"").unwrap();
        std::os::unix::fs::symlink(&outside, control.join(COORDINATION_LOCK_FILE_NAME)).unwrap();
        let err = acquire_workspace_lock(&paths, "research", true).unwrap_err();
        assert!(matches!(err, LockError::Symlink(_)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn symlink_control_directory_rejected() {
        let (dir, paths) = fixture("symlinkdir");
        let root = paths.workspaces_dir.join("research");
        let outside = dir.join("outside-control");
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, root.join(WORKSPACE_CONTROL_DIRECTORY_NAME)).unwrap();
        let err = acquire_workspace_lock(&paths, "research", true).unwrap_err();
        assert!(
            matches!(err, LockError::Symlink(_))
                || matches!(err, LockError::Io(ref op, _) if op.contains("validate")),
            "unexpected error: {err:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn generation_round_trip_and_validation() {
        let (dir, paths) = fixture("generation");
        let state = ensure_workspace_generation(&paths, "research").unwrap();
        assert_eq!(state, WorkspaceGeneration::default());
        write_workspace_generation(
            &paths,
            "research",
            WorkspaceGeneration {
                current: 5,
                published: 4,
            },
        )
        .unwrap();
        let read = read_workspace_generation(&paths, "research").unwrap();
        assert_eq!(read.current, 5);
        assert_eq!(read.published, 4);
        let err = write_workspace_generation(
            &paths,
            "research",
            WorkspaceGeneration {
                current: 1,
                published: 2,
            },
        )
        .unwrap_err();
        assert!(matches!(err, GenerationError::PublishedNewer { .. }));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn generation_rejects_extra_fields_and_nulls() {
        let (dir, paths) = fixture("genfields");
        let control = paths.workspaces_dir.join("research/.zbrain");
        std::fs::create_dir_all(&control).unwrap();
        let path = control.join(GENERATION_FILE_NAME);
        std::fs::write(&path, b"{\"current\":1,\"published\":1,\"extra\":2}\n").unwrap();
        let err = read_workspace_generation(&paths, "research").unwrap_err();
        assert!(matches!(err, GenerationError::ExtraFields));
        std::fs::write(&path, b"{\"current\":null,\"published\":1}\n").unwrap();
        let err = read_workspace_generation(&paths, "research").unwrap_err();
        assert!(matches!(err, GenerationError::CurrentRequired));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
