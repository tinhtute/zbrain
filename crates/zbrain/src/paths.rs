use std::os::unix::fs::DirBuilderExt as _;
use std::path::{Component, Path, PathBuf};

pub const RUNTIME_DIRECTORY_MODE: u32 = 0o700;
pub const RUNTIME_METADATA_MODE: u32 = 0o600;
pub const EVIDENCE_DIRECTORY_MODE: u32 = 0o700;
pub const EVIDENCE_FILE_MODE: u32 = 0o400;
pub const DERIVED_INDEX_MODE: u32 = 0o600;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    pub cwd: PathBuf,
    pub home_dir: PathBuf,
    pub runtime_dir: PathBuf,
    /// Owner approval key directory (ADR 0002). Never under `runtime_dir`;
    /// `signing::KeyStore` refuses that placement, symlinks, and loose modes.
    pub key_dir: PathBuf,
    pub config_file: PathBuf,
    pub workspaces_dir: PathBuf,
    pub indexes_dir: PathBuf,
}

#[derive(Debug, Clone, Default)]
pub struct Options {
    pub cwd: Option<PathBuf>,
    pub home_dir: Option<PathBuf>,
    pub runtime_dir: Option<PathBuf>,
}

impl Paths {
    pub fn resolve(options: Options) -> Result<Self, PathsError> {
        let cwd = match options.cwd {
            Some(path) => absolute(&path)?,
            None => std::env::current_dir().map_err(|source| PathsError::Cwd { source })?,
        };
        let home = match options.home_dir {
            Some(path) => absolute(&path)?,
            None => std::env::var("HOME")
                .map(PathBuf::from)
                .map_err(|_| PathsError::HomeMissing)?,
        };
        let home = absolute(&home)?;
        let runtime_dir = match options
            .runtime_dir
            .clone()
            .or_else(|| std::env::var("ZBRAIN_HOME").ok().map(PathBuf::from))
        {
            Some(path) => absolute(&path)?,
            None => home.join(".zbrain"),
        };
        let runtime_dir = absolute(&runtime_dir)?;
        let key_dir = resolve_key_dir(&home)?;

        Ok(Self {
            key_dir,
            config_file: runtime_dir.join("config.yml"),
            workspaces_dir: runtime_dir.join("workspaces"),
            indexes_dir: runtime_dir.join("indexes"),
            cwd,
            home_dir: home,
            runtime_dir,
        })
    }
}

/// `$XDG_CONFIG_HOME/zbrain-keys`, falling back to `~/.config/zbrain-keys`.
/// The same path is used on macOS and Linux (ADR 0002); there is no override
/// beyond `XDG_CONFIG_HOME`, and no fallback inside the runtime root.
fn resolve_key_dir(home: &Path) -> Result<PathBuf, PathsError> {
    if let Some(config_home) = std::env::var_os("XDG_CONFIG_HOME") {
        let config_home = PathBuf::from(config_home);
        if !config_home.as_os_str().is_empty() {
            return Ok(absolute(&config_home)?.join("zbrain-keys"));
        }
    }
    Ok(home.join(".config").join("zbrain-keys"))
}

#[derive(Debug)]
pub enum PathsError {
    Cwd {
        source: std::io::Error,
    },
    HomeMissing,
    Absolute {
        path: PathBuf,
        source: std::io::Error,
    },
    Io(std::io::Error),
}

impl std::fmt::Display for PathsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cwd { source } => write!(f, "resolve cwd: {source}"),
            Self::HomeMissing => write!(f, "home directory is not set"),
            Self::Absolute { path, source } => {
                write!(f, "resolve absolute path {:?}: {source}", path)
            }
            Self::Io(source) => write!(f, "{source}"),
        }
    }
}

impl std::error::Error for PathsError {}

impl From<std::io::Error> for PathsError {
    fn from(source: std::io::Error) -> Self {
        Self::Io(source)
    }
}

pub fn absolute(path: &Path) -> Result<PathBuf, std::io::Error> {
    if path.is_absolute() {
        Ok(normalize(path))
    } else {
        let cwd = std::env::current_dir()?;
        Ok(normalize(&cwd.join(path)))
    }
}

/// Resolve `path` against `base` without consulting the filesystem, for
/// tests and call sites that need deterministic anchors.
pub fn absolute_under(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        normalize(path)
    } else {
        normalize(&base.join(path))
    }
}

fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

pub fn ensure_directory_mode(path: &Path, mode: u32) -> Result<(), std::io::Error> {
    // Port of Go's os.MkdirAll(path, mode) semantics: permission bits apply to
    // every directory created along the chain, not just the leaf.
    let mut missing = Vec::new();
    let mut probe = path;
    loop {
        match std::fs::symlink_metadata(probe) {
            Ok(_) => break,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                missing.push(probe.to_path_buf());
                match probe.parent() {
                    Some(parent) => probe = parent,
                    None => break,
                }
            }
            Err(source) => return Err(source),
        }
    }
    for dir in missing.iter().rev() {
        std::fs::create_dir(dir)?;
        set_permissions(dir, mode)?;
    }
    set_permissions(path, mode)
}

pub fn ensure_file_mode(path: &Path, mode: u32) -> Result<(), std::io::Error> {
    set_permissions(path, mode)
}

/// os.MkdirAll semantics: create missing directories with `mode` (umask
/// applies, and `mode` reaches every level created), never chmod paths that
/// already exist.
pub(crate) fn mkdir_all(path: &Path, mode: u32) -> Result<(), std::io::Error> {
    match std::fs::metadata(path) {
        Ok(meta) if meta.is_dir() => return Ok(()),
        Ok(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("{} is not a directory", path.display()),
            ))
        }
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => return Err(source),
    }
    if let Some(parent) = path.parent() {
        mkdir_all(parent, mode)?;
    }
    std::fs::DirBuilder::new().mode(mode).create(path)
}

pub(crate) fn set_permissions(path: &Path, mode: u32) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

pub(crate) fn write_file(path: &Path, contents: &[u8], mode: u32) -> Result<(), std::io::Error> {
    std::fs::write(path, contents)?;
    set_permissions(path, mode)
}

pub fn is_safe_workspace_name(name: &str) -> bool {
    if name.is_empty()
        || name
            != Path::new(name)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("")
    {
        return false;
    }
    name.chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

pub(crate) fn ensure_parent_mode(path: &Path, mode: u32) -> Result<(), std::io::Error> {
    if let Some(parent) = path.parent() {
        ensure_directory_mode(parent, mode)?;
    }
    Ok(())
}

/// Convenience helper mirroring the Go evidenceTestPaths shape.
pub fn resolved_under(home: &Path, runtime_dir: &Path) -> Result<Paths, PathsError> {
    Paths::resolve(Options {
        cwd: Some(home.to_path_buf()),
        home_dir: Some(home.to_path_buf()),
        runtime_dir: Some(runtime_dir.to_path_buf()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root() -> PathBuf {
        static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "zbrain-paths-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn resolve_uses_explicit_options() {
        let root = temp_root();
        let paths = Paths::resolve(Options {
            cwd: Some(root.clone()),
            home_dir: Some(root.clone()),
            runtime_dir: Some(root.join(".zbrain")),
        })
        .unwrap();
        assert_eq!(paths.runtime_dir, root.join(".zbrain"));
        assert_eq!(paths.config_file, root.join(".zbrain/config.yml"));
        assert_eq!(paths.workspaces_dir, root.join(".zbrain/workspaces"));
        assert_eq!(paths.indexes_dir, root.join(".zbrain/indexes"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn resolve_defaults_to_home_dot_zbrain() {
        let root = temp_root();
        let paths = Paths::resolve(Options {
            cwd: Some(root.clone()),
            home_dir: Some(root.clone()),
            runtime_dir: None,
        })
        .unwrap();
        assert_eq!(paths.runtime_dir, root.join(".zbrain"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn safe_workspace_names() {
        for name in ["research", "a1", "w-1"] {
            assert!(is_safe_workspace_name(name), "{name} should be safe");
        }
        for name in [
            "",
            "Research",
            "a_b",
            "../outside",
            "a/b",
            "sp ace",
            ".hidden",
        ] {
            assert!(!is_safe_workspace_name(name), "{name:?} should be unsafe");
        }
    }

    #[test]
    fn ensure_directory_mode_sets_mode_bits() {
        use std::os::unix::fs::PermissionsExt;
        let root = temp_root();
        let dir = root.join("mode-dir");
        ensure_directory_mode(&dir, RUNTIME_DIRECTORY_MODE).unwrap();
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
        let _ = std::fs::remove_dir_all(&root);
    }
}
