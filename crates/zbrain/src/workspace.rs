use std::path::PathBuf;

use crate::clock::Clock;
use crate::config::{read_config, write_config};
use crate::paths::{
    ensure_directory_mode, is_safe_workspace_name, write_file, Paths, RUNTIME_DIRECTORY_MODE,
    RUNTIME_METADATA_MODE,
};

pub const WIKI_TIERS: [&str; 4] = ["axioms", "mental-models", "projects", "decisions"];

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct WorkspaceCurrent {
    #[serde(rename = "project_root")]
    pub project_root: PathBuf,
    pub workspace: String,
    pub secondary_workspaces: Vec<String>,
}

#[derive(Debug)]
pub enum WorkspaceError {
    UnsafeName,
    AlreadyExists(String),
    Io(std::io::Error),
    Config(crate::config::ConfigError),
    Boundary(crate::boundary::BoundaryError),
    NoDefaultWorkspace,
}

impl std::fmt::Display for WorkspaceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsafeName => write!(
                f,
                "workspace name must use lowercase letters, numbers, or hyphens only"
            ),
            Self::AlreadyExists(name) => write!(f, "workspace {name:?} already exists"),
            Self::Io(source) => write!(f, "{source}"),
            Self::Config(source) => write!(f, "{source}"),
            Self::Boundary(source) => write!(f, "{source}"),
            Self::NoDefaultWorkspace => write!(
                f,
                "no default workspace configured; run `zbrain workspace create <name>` first"
            ),
        }
    }
}

impl std::error::Error for WorkspaceError {}

impl From<std::io::Error> for WorkspaceError {
    fn from(source: std::io::Error) -> Self {
        Self::Io(source)
    }
}

impl From<crate::config::ConfigError> for WorkspaceError {
    fn from(source: crate::config::ConfigError) -> Self {
        Self::Config(source)
    }
}

impl From<crate::boundary::BoundaryError> for WorkspaceError {
    fn from(source: crate::boundary::BoundaryError) -> Self {
        Self::Boundary(source)
    }
}

pub fn create_workspace(
    paths: &Paths,
    name: &str,
    clock: &impl Clock,
) -> Result<(), WorkspaceError> {
    if !is_safe_workspace_name(name) {
        return Err(WorkspaceError::UnsafeName);
    }

    let root = paths.workspaces_dir.join(name);
    match std::fs::metadata(&root) {
        Ok(_) => return Err(WorkspaceError::AlreadyExists(name.to_string())),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => return Err(source.into()),
    }
    ensure_directory_mode(&paths.workspaces_dir, RUNTIME_DIRECTORY_MODE)?;
    ensure_directory_mode(&root, RUNTIME_DIRECTORY_MODE)?;
    for tier in WIKI_TIERS {
        ensure_directory_mode(&root.join("wiki").join(tier), RUNTIME_DIRECTORY_MODE)?;
    }
    for dir in [
        "agents",
        "evidence/sources",
        "evidence/analysis",
        "evidence/qa",
        "evidence/applied",
        "evidence/archive",
    ] {
        ensure_directory_mode(&root.join(dir), RUNTIME_DIRECTORY_MODE)?;
    }

    let readme = format!(
        "# {name}\n\nCreated: {}\n",
        crate::clock::rfc3339(clock.now())
    );
    write_file(
        &root.join("workspace.md"),
        readme.as_bytes(),
        RUNTIME_METADATA_MODE,
    )?;
    write_file(
        &root.join("evidence/_index.md"),
        b"# Evidence Index\n",
        RUNTIME_METADATA_MODE,
    )?;

    let mut config = read_config(&paths.config_file)?;
    if config.default_workspace.is_empty() {
        config.default_workspace = name.to_string();
        write_config(&paths.config_file, &config)?;
    }
    Ok(())
}

pub fn resolve_current_workspace(paths: &Paths) -> Result<WorkspaceCurrent, WorkspaceError> {
    let config = read_config(&paths.config_file)?;
    let workspace = if config.default_workspace.is_empty() {
        return Err(WorkspaceError::NoDefaultWorkspace);
    } else {
        config.default_workspace.clone()
    };
    crate::boundary::validate_workspace(paths, &workspace)?;
    Ok(WorkspaceCurrent {
        project_root: paths.cwd.clone(),
        workspace,
        secondary_workspaces: Vec::new(),
    })
}

pub fn marshal_current(current: &WorkspaceCurrent) -> Result<Vec<u8>, serde_json::Error> {
    let mut out = serde_json::to_vec_pretty(current)?;
    out.push(b'\n');
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::{rfc3339, FixedClock};
    use crate::paths::{Options, Paths, EVIDENCE_FILE_MODE, RUNTIME_METADATA_MODE};
    use chrono::{TimeZone, Utc};
    use std::os::unix::fs::PermissionsExt;

    fn fixture(name: &str) -> (PathBuf, Paths, FixedClock) {
        let dir = std::env::temp_dir().join(format!("zbrain-ws-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut paths = Paths::resolve(Options {
            cwd: Some(dir.clone()),
            home_dir: Some(dir.clone()),
            runtime_dir: Some(dir.join(".zbrain")),
        })
        .unwrap();
        paths.key_dir = crate::signing::test_key_dir();
        let clock = FixedClock::new(Utc.with_ymd_and_hms(2026, 7, 30, 10, 0, 0).unwrap());
        (dir, paths, clock)
    }

    #[test]
    fn create_builds_full_tree_with_modes() {
        let (dir, paths, clock) = fixture("tree");
        create_workspace(&paths, "research", &clock).unwrap();
        let root = paths.workspaces_dir.join("research");
        for tier in WIKI_TIERS {
            assert!(root.join("wiki").join(tier).is_dir(), "tier {tier} missing");
        }
        for sub in [
            "agents",
            "evidence/sources",
            "evidence/analysis",
            "evidence/qa",
            "evidence/applied",
            "evidence/archive",
        ] {
            assert!(root.join(sub).is_dir(), "{sub} missing");
        }
        let readme = std::fs::read_to_string(root.join("workspace.md")).unwrap();
        assert_eq!(
            readme,
            format!("# research\n\nCreated: {}\n", rfc3339(clock.now()))
        );
        assert_eq!(
            std::fs::read(root.join("evidence/_index.md")).unwrap(),
            b"# Evidence Index\n"
        );
        let mode = std::fs::metadata(root.join("workspace.md"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, RUNTIME_METADATA_MODE);
        let dir_mode = std::fs::metadata(root.join("wiki/axioms"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(dir_mode & 0o777, 0o700);
        let evidence_dir = root.join("evidence/sources");
        std::fs::write(evidence_dir.join("probe"), b"x").unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        let _ = EVIDENCE_FILE_MODE;
    }

    #[test]
    fn duplicate_create_rejected() {
        let (dir, paths, clock) = fixture("dup");
        create_workspace(&paths, "research", &clock).unwrap();
        let err = create_workspace(&paths, "research", &clock).unwrap_err();
        assert!(matches!(err, WorkspaceError::AlreadyExists(_)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unsafe_name_rejected() {
        let (dir, paths, clock) = fixture("unsafe");
        for name in ["../outside", "Bad", "a b", ""] {
            let err = create_workspace(&paths, name, &clock).unwrap_err();
            assert!(matches!(err, WorkspaceError::UnsafeName), "{name:?}");
        }
        assert!(!paths.workspaces_dir.join("outside").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn first_workspace_becomes_default() {
        let (dir, paths, clock) = fixture("default");
        crate::config::ensure_config(&paths.config_file).unwrap();
        create_workspace(&paths, "first", &clock).unwrap();
        create_workspace(&paths, "second", &clock).unwrap();
        let config = crate::config::read_config(&paths.config_file).unwrap();
        assert_eq!(config.default_workspace, "first");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_current_validates_and_fails_closed() {
        let (dir, paths, clock) = fixture("current");
        assert!(matches!(
            resolve_current_workspace(&paths),
            Err(WorkspaceError::NoDefaultWorkspace)
        ));
        create_workspace(&paths, "research", &clock).unwrap();
        let current = resolve_current_workspace(&paths).unwrap();
        assert_eq!(current.workspace, "research");
        assert_eq!(current.project_root, paths.cwd);
        assert!(current.secondary_workspaces.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
