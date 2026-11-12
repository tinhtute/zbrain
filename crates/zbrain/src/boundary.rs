use std::path::{Component, Path, PathBuf};

use crate::paths::{is_safe_workspace_name, Paths};

#[derive(Debug)]
pub enum BoundaryError {
    UnsafeName,
    WorkspaceMissing(String),
    WorkspaceSymlink(String),
    WorkspaceNotDirectory(String),
    Stat {
        name: String,
        source: std::io::Error,
    },
    Resolve {
        name: String,
        source: std::io::Error,
    },
    OutsideRoot(String),
    WorkspacesRoot {
        source: std::io::Error,
    },
    RootSymlink(String),
    RootNotDirectory(String),
    EmptyPath,
    UnsafePath(String),
    TargetOutsideWorkspace {
        relative: String,
        workspace: String,
    },
    NotRegularFile(String),
    NoWorkspaceAncestor,
    Io(std::io::Error),
}

impl std::fmt::Display for BoundaryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsafeName => write!(
                f,
                "workspace name must use lowercase letters, numbers, or hyphens only"
            ),
            Self::WorkspaceMissing(name) => write!(f, "workspace {name:?} does not exist"),
            Self::WorkspaceSymlink(name) => write!(f, "workspace {name:?} must not be a symlink"),
            Self::WorkspaceNotDirectory(name) => write!(f, "workspace {name:?} is not a directory"),
            Self::Stat { name, source } => write!(f, "stat workspace {name:?}: {source}"),
            Self::Resolve { name, source } => write!(f, "resolve workspace {name:?}: {source}"),
            Self::OutsideRoot(name) => {
                write!(f, "workspace {name:?} resolves outside the workspaces root")
            }
            Self::WorkspacesRoot { source } => write!(f, "validate workspaces root: {source}"),
            Self::RootSymlink(path) => write!(f, "{path:?} must not be a symlink"),
            Self::RootNotDirectory(path) => write!(f, "{path:?} is not a directory"),
            Self::EmptyPath => write!(f, "workspace path must not be empty"),
            Self::UnsafePath(path) => write!(f, "workspace path {path:?} is not safe"),
            Self::TargetOutsideWorkspace {
                relative,
                workspace,
            } => {
                write!(
                    f,
                    "workspace path {relative:?} is outside workspace {workspace:?}"
                )
            }
            Self::NotRegularFile(path) => write!(f, "{path:?} is not a regular file"),
            Self::NoWorkspaceAncestor => write!(f, "path has no existing workspace ancestor"),
            Self::Io(source) => write!(f, "{source}"),
        }
    }
}

impl std::error::Error for BoundaryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Stat { source, .. }
            | Self::Resolve { source, .. }
            | Self::WorkspacesRoot { source }
            | Self::Io(source) => Some(source),
            _ => None,
        }
    }
}

impl From<std::io::Error> for BoundaryError {
    fn from(source: std::io::Error) -> Self {
        Self::Io(source)
    }
}

/// ValidateWorkspace returns the canonical root of an existing workspace.
/// Workspace names are never cleaned or normalized before validation.
pub fn validate_workspace(paths: &Paths, name: &str) -> Result<PathBuf, BoundaryError> {
    if !is_safe_workspace_name(name) {
        return Err(BoundaryError::UnsafeName);
    }
    let workspaces_root =
        canonical_existing_directory(&paths.workspaces_dir).map_err(|err| match err {
            BoundaryError::RootSymlink(p) => BoundaryError::RootSymlink(p),
            BoundaryError::RootNotDirectory(p) => BoundaryError::RootNotDirectory(p),
            BoundaryError::Io(source) => BoundaryError::WorkspacesRoot { source },
            other => other,
        })?;

    let root = workspaces_root.join(name);
    let info = match std::fs::symlink_metadata(&root) {
        Ok(info) => info,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            return Err(BoundaryError::WorkspaceMissing(name.to_string()));
        }
        Err(source) => {
            return Err(BoundaryError::Stat {
                name: name.to_string(),
                source,
            });
        }
    };
    if info.file_type().is_symlink() {
        return Err(BoundaryError::WorkspaceSymlink(name.to_string()));
    }
    if !info.is_dir() {
        return Err(BoundaryError::WorkspaceNotDirectory(name.to_string()));
    }

    let resolved_root = std::fs::canonicalize(&root).map_err(|source| BoundaryError::Resolve {
        name: name.to_string(),
        source,
    })?;
    if !path_within(&workspaces_root, &resolved_root) {
        return Err(BoundaryError::OutsideRoot(name.to_string()));
    }
    Ok(resolved_root)
}

/// ResolveWorkspacePath returns a canonical path inside an existing workspace.
/// Existing path components are resolved so symlink escapes are rejected while
/// non-existent final components remain valid targets for callers that write.
pub fn resolve_workspace_path(
    paths: &Paths,
    workspace: &str,
    relative: &str,
) -> Result<PathBuf, BoundaryError> {
    let root = validate_workspace(paths, workspace)?;
    let clean = safe_relative_path(relative)?;
    let target = root.join(&clean);
    if !path_within(&root, &target) {
        return Err(BoundaryError::TargetOutsideWorkspace {
            relative: relative.to_string(),
            workspace: workspace.to_string(),
        });
    }
    validate_existing_path(&root, &target).map_err(|err| match err {
        BoundaryError::UnsafePath(p) => BoundaryError::UnsafePath(p),
        other => BoundaryError::Io(std::io::Error::other(format!(
            "workspace path {relative:?}: {other}"
        ))),
    })?;
    Ok(target)
}

pub fn canonical_existing_directory(path: &Path) -> Result<PathBuf, BoundaryError> {
    let info = std::fs::symlink_metadata(path).map_err(BoundaryError::Io)?;
    if info.file_type().is_symlink() {
        return Err(BoundaryError::RootSymlink(path.display().to_string()));
    }
    if !info.is_dir() {
        return Err(BoundaryError::RootNotDirectory(path.display().to_string()));
    }
    let resolved = std::fs::canonicalize(path).map_err(BoundaryError::Io)?;
    Ok(crate::paths::absolute(&resolved)?)
}

pub fn safe_relative_path(path: &str) -> Result<PathBuf, BoundaryError> {
    if path.is_empty() {
        return Err(BoundaryError::EmptyPath);
    }
    let native = Path::new(path);
    let clean = normalize(native);
    let unsafe_path = || BoundaryError::UnsafePath(path.to_string());
    if native.is_absolute()
        || clean != native
        || clean == Path::new(".")
        || clean == Path::new("..")
        || clean.starts_with("../")
    {
        return Err(unsafe_path());
    }
    if clean.components().any(|c| {
        matches!(
            c,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        return Err(unsafe_path());
    }
    Ok(clean)
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

fn validate_existing_path(root: &Path, target: &Path) -> Result<(), BoundaryError> {
    let mut candidate = target.to_path_buf();
    loop {
        match std::fs::symlink_metadata(&candidate) {
            Ok(_) => {
                let resolved = std::fs::canonicalize(&candidate).map_err(|source| {
                    BoundaryError::Io(std::io::Error::other(format!(
                        "resolve existing path: {source}"
                    )))
                })?;
                let resolved = crate::paths::absolute(&resolved).map_err(BoundaryError::Io)?;
                if !path_within(root, &resolved) {
                    return Err(BoundaryError::TargetOutsideWorkspace {
                        relative: candidate.display().to_string(),
                        workspace: root.display().to_string(),
                    });
                }
                return Ok(());
            }
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => return Err(BoundaryError::Io(source)),
        }
        let Some(parent) = candidate.parent() else {
            return Err(BoundaryError::NoWorkspaceAncestor);
        };
        if parent == candidate {
            return Err(BoundaryError::NoWorkspaceAncestor);
        }
        candidate = parent.to_path_buf();
    }
}

pub fn path_within(root: &Path, target: &Path) -> bool {
    match target.strip_prefix(root) {
        Ok(rel) => !rel.as_os_str().is_empty() || target == root,
        Err(_) => false,
    }
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
        let dir =
            std::env::temp_dir().join(format!("zbrain-boundary-{}-{name}", std::process::id()));
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
    fn validate_returns_resolved_root() {
        let (dir, paths) = fixture("resolved");
        let root = validate_workspace(&paths, "research").unwrap();
        assert_eq!(
            root,
            std::fs::canonicalize(paths.workspaces_dir.join("research")).unwrap()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_rejects_missing_unsafe_and_symlink() {
        let (dir, paths) = fixture("missing_symlink");
        assert!(matches!(
            validate_workspace(&paths, "missing"),
            Err(BoundaryError::WorkspaceMissing(_))
        ));
        assert!(matches!(
            validate_workspace(&paths, "../outside"),
            Err(BoundaryError::UnsafeName)
        ));
        std::os::unix::fs::symlink(std::env::temp_dir(), paths.workspaces_dir.join("linked"))
            .unwrap();
        assert!(matches!(
            validate_workspace(&paths, "linked"),
            Err(BoundaryError::WorkspaceSymlink(_))
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_rejects_unsafe_relative_paths() {
        let (dir, paths) = fixture("unsafe_rel");
        for relative in ["", "../escape", "/abs", "a/../b"] {
            assert!(
                resolve_workspace_path(&paths, "research", relative).is_err(),
                "{relative:?} should be rejected"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_rejects_symlink_escape() {
        let (dir, paths) = fixture("symlink_escape");
        let outside = dir.join("outside-secret");
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, paths.workspaces_dir.join("research/escape")).unwrap();
        let err = resolve_workspace_path(&paths, "research", "escape/inner").unwrap_err();
        assert!(!err.to_string().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_accepts_nonexistent_final_component() {
        let (dir, paths) = fixture("nonexistent_final");
        let target = resolve_workspace_path(&paths, "research", "wiki/axioms/new.md").unwrap();
        assert_eq!(
            target,
            std::fs::canonicalize(paths.workspaces_dir.join("research"))
                .unwrap()
                .join("wiki/axioms/new.md")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
