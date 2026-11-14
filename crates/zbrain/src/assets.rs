use std::fs::DirBuilder;
use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::Path;

use include_dir::{include_dir, Dir, DirEntry};

use crate::paths::Paths;

// include_dir embeds the whole assets/ tree (also assets/view and embed.go),
// so extraction re-applies the go:embed patterns from assets/embed.go before
// copying; this keeps the extracted set identical to the Go binary.
pub static BUNDLED_ASSETS: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/../../assets");

const EMBED_PREFIXES: [&str; 4] = ["agents/", "engine/", "skills/", "templates/"];

pub const EXTRACTION_FILE_MODE: u32 = 0o644;
pub const EXTRACTION_DIRECTORY_MODE: u32 = 0o755;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ExtractionResult {
    pub copied: Vec<String>,
    pub skipped: Vec<String>,
}

#[derive(Debug)]
pub enum AssetsError {
    Io(std::io::Error),
}

impl std::fmt::Display for AssetsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(source) => write!(f, "{source}"),
        }
    }
}

impl std::error::Error for AssetsError {}

pub fn extract_bundled_assets(paths: &Paths) -> Result<ExtractionResult, AssetsError> {
    let mut files = Vec::new();
    collect_files(&BUNDLED_ASSETS, &mut files);
    files.retain(|path| is_embedded(path));
    files.sort();

    let mut result = ExtractionResult::default();
    for path in files {
        if path.ends_with(".go") {
            continue;
        }
        if path.starts_with("workspaces/") {
            result.skipped.push(path.to_string());
            continue;
        }
        let destination = paths.runtime_dir.join(path);
        if let Some(parent) = destination.parent() {
            mkdir_all(parent, EXTRACTION_DIRECTORY_MODE).map_err(AssetsError::Io)?;
        }
        write_asset(&destination, path)?;
        result.copied.push(path.to_string());
    }
    Ok(result)
}

fn write_asset(destination: &Path, asset_path: &str) -> Result<(), AssetsError> {
    let contents = BUNDLED_ASSETS
        .get_file(asset_path)
        .map(|file| file.contents())
        .ok_or_else(|| {
            AssetsError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("embedded asset {asset_path:?} not found"),
            ))
        })?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(EXTRACTION_FILE_MODE)
        .open(destination)
        .map_err(AssetsError::Io)?;
    file.write_all(contents).map_err(AssetsError::Io)
}

fn mkdir_all(path: &Path, mode: u32) -> Result<(), std::io::Error> {
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
    DirBuilder::new().mode(mode).create(path)
}

fn collect_files<'a>(dir: &'a Dir<'a>, out: &mut Vec<&'a str>) {
    for entry in dir.entries() {
        match entry {
            DirEntry::Dir(nested) => collect_files(nested, out),
            DirEntry::File(file) => out.push(file.path().to_str().expect("utf8 asset path")),
        }
    }
}

/// Files matched by the go:embed pattern in assets/embed.go.
pub fn embedded_asset_paths() -> Vec<&'static str> {
    let mut files = Vec::new();
    collect_files(&BUNDLED_ASSETS, &mut files);
    files.retain(|path| is_embedded(path));
    files.sort();
    files
}

fn is_embedded(path: &str) -> bool {
    if path == "README.md" || path == "workspaces/.gitkeep" {
        return true;
    }
    for prefix in EMBED_PREFIXES {
        if let Some(rest) = path.strip_prefix(prefix) {
            // go:embed skips dot/underscore entries while recursing.
            return rest
                .split('/')
                .all(|component| !component.starts_with('.') && !component.starts_with('_'));
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_runtime() -> (std::path::PathBuf, Paths) {
        static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!(
            "zbrain-assets-{}-{}",
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
    fn extract_copies_runtime_assets() {
        let (root, paths) = temp_runtime();
        let result = extract_bundled_assets(&paths).unwrap();
        assert!(!result.copied.is_empty());
        assert!(paths.runtime_dir.join("README.md").is_file());
        assert!(paths.runtime_dir.join("templates/workspace.md").is_file());
        assert!(
            !paths.runtime_dir.join("workspaces/research").exists(),
            "workspace seed assets must not create active workspaces"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn embedded_asset_layout() {
        let (root, paths) = temp_runtime();
        let result = extract_bundled_assets(&paths).unwrap();

        let mut copied = result.copied.clone();
        copied.sort();
        let mut skipped = result.skipped.clone();
        skipped.sort();

        let mut expected_copied: Vec<&str> = documented_embedded_asset_paths()
            .into_iter()
            .filter(|path| !path.starts_with("workspaces/"))
            .collect();
        let expected_skipped: Vec<&str> = documented_embedded_asset_paths()
            .into_iter()
            .filter(|path| path.starts_with("workspaces/"))
            .collect();
        expected_copied.sort();
        assert_eq!(copied, expected_copied);
        assert_eq!(skipped, expected_skipped);

        for root_name in ["README.md", "agents", "engine", "skills", "templates"] {
            assert!(
                paths.runtime_dir.join(root_name).exists(),
                "missing extracted runtime path {root_name:?}"
            );
        }
        assert!(
            !paths.runtime_dir.join("assets").exists(),
            "setup must not create a nested assets directory"
        );
        assert!(
            !paths.runtime_dir.join("workspaces").exists(),
            "workspace seed assets must not create active workspaces"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn embedded_asset_parity() {
        let mut actual = embedded_asset_paths();
        let mut expected = documented_embedded_asset_paths();
        actual.dedup();
        expected.sort();
        assert_eq!(actual, expected);
    }

    #[test]
    fn extract_twice_produces_identical_results() {
        let (root, paths) = temp_runtime();
        let first = extract_bundled_assets(&paths).unwrap();
        let second = extract_bundled_assets(&paths).unwrap();
        assert_eq!(first, second);
        let readme = std::fs::read(paths.runtime_dir.join("README.md")).unwrap();
        let bundled = BUNDLED_ASSETS
            .get_file("README.md")
            .unwrap()
            .contents()
            .to_vec();
        assert_eq!(readme, bundled);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn extraction_mode_bits() {
        let (root, paths) = temp_runtime();
        extract_bundled_assets(&paths).unwrap();
        use std::os::unix::fs::PermissionsExt;
        let dir_mode = std::fs::metadata(paths.runtime_dir.join("agents"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(dir_mode & 0o700, 0o700);
        let file_mode = std::fs::metadata(paths.runtime_dir.join("README.md"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(file_mode & 0o600, 0o600);
        let _ = std::fs::remove_dir_all(&root);
    }

    fn documented_embedded_asset_paths() -> Vec<&'static str> {
        vec![
            "README.md",
            "agents/wiki-planner.md",
            "agents/wiki-qmd-selector.md",
            "engine/claude-rules.md",
            "engine/codex-rules.md",
            "engine/constraints.md",
            "engine/evidence-rules.md",
            "engine/retrieval-rules.md",
            "engine/system-prompt.md",
            "skills/zbrain-ask/SKILL.md",
            "skills/zbrain-ingest/SKILL.md",
            "skills/zbrain-ingest/references/pipeline.md",
            "skills/zbrain-learn/SKILL.md",
            "skills/zbrain-research/SKILL.md",
            "templates/axiom.md",
            "templates/evidence-index.md",
            "templates/evidence-manifest.yaml",
            "templates/evidence-source.yaml",
            "templates/mental-model.md",
            "templates/project.md",
            "templates/workspace.md",
            "workspaces/.gitkeep",
        ]
    }
}
