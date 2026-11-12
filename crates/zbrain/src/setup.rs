use serde::Serialize;

use crate::assets::{extract_bundled_assets, AssetsError};
use crate::config::{ensure_config, ConfigError};
use crate::paths::{mkdir_all, Paths};

pub const SETUP_SCHEMA_VERSION: u32 = 1;
pub const SETUP_DIRECTORY_MODE: u32 = 0o755;

#[derive(Debug, Serialize)]
pub struct SetupSummary {
    pub schema_version: u32,
    pub config_created: bool,
    pub assets_copied: usize,
    pub assets_skipped: usize,
}

#[derive(Debug)]
pub enum SetupError {
    Io(std::io::Error),
    Config(ConfigError),
    Assets(AssetsError),
}

impl std::fmt::Display for SetupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(source) => write!(f, "{source}"),
            Self::Config(source) => write!(f, "{source}"),
            Self::Assets(source) => write!(f, "{source}"),
        }
    }
}

impl std::error::Error for SetupError {}

pub fn run_setup(paths: &Paths) -> Result<SetupSummary, SetupError> {
    mkdir_all(&paths.runtime_dir, SETUP_DIRECTORY_MODE).map_err(SetupError::Io)?;
    let config_created = ensure_config(&paths.config_file).map_err(SetupError::Config)?;
    let extracted = extract_bundled_assets(paths).map_err(SetupError::Assets)?;
    Ok(SetupSummary {
        schema_version: SETUP_SCHEMA_VERSION,
        config_created,
        assets_copied: extracted.copied.len(),
        assets_skipped: extracted.skipped.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_runtime() -> (std::path::PathBuf, Paths) {
        static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!(
            "zbrain-setup-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let mut paths = Paths::resolve(crate::paths::Options {
            cwd: Some(root.clone()),
            home_dir: Some(root.clone()),
            runtime_dir: Some(root.join(".zbrain")),
        })
        .unwrap();
        paths.key_dir = crate::signing::test_key_dir();
        (root, paths)
    }

    #[test]
    fn run_setup_extracts_assets_and_creates_config() {
        let (root, paths) = temp_runtime();
        let summary = run_setup(&paths).unwrap();
        assert_eq!(summary.schema_version, SETUP_SCHEMA_VERSION);
        assert!(summary.config_created);
        assert_eq!(summary.assets_copied, 21);
        assert_eq!(summary.assets_skipped, 1);
        assert!(paths.runtime_dir.join("README.md").is_file());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn run_setup_is_idempotent() {
        let (root, paths) = temp_runtime();
        let first = run_setup(&paths).unwrap();
        let second = run_setup(&paths).unwrap();
        assert!(first.config_created);
        assert!(!second.config_created);
        assert_eq!(second.assets_copied, first.assets_copied);
        assert_eq!(second.assets_skipped, first.assets_skipped);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn run_setup_mode_bits() {
        use std::os::unix::fs::PermissionsExt;
        let (root, paths) = temp_runtime();
        run_setup(&paths).unwrap();
        let runtime_mode = std::fs::metadata(&paths.runtime_dir)
            .unwrap()
            .permissions()
            .mode();
        // EnsureConfig runs ensureDirectoryMode(0700) over the runtime dir
        // even though run_setup created it with 0755 first.
        assert_eq!(runtime_mode & 0o777, 0o700);
        let config_mode = std::fs::metadata(&paths.config_file)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(config_mode & 0o777, 0o600);
        let _ = std::fs::remove_dir_all(&root);
    }
}
