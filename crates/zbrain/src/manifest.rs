//! manifest.rs — port of internal/runtime/manifest.go: the trust-input
//! manifest hashing every canonical file that can affect trust.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};

use crate::boundary::{path_within, validate_workspace, BoundaryError};
use crate::paths::Paths;
use crate::workspace::WIKI_TIERS;

pub const TRUST_INPUT_KIND_CLAIM: &str = "claim";
pub const TRUST_INPUT_KIND_EVIDENCE_METADATA: &str = "evidence_metadata";
pub const TRUST_INPUT_KIND_EVIDENCE_RAW: &str = "evidence_raw";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustInput {
    pub path: String,
    pub kind: String,
    pub byte_length: i64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustInputManifest {
    pub entries: Vec<TrustInput>,
    pub digest: String,
}

#[derive(Debug)]
pub enum ManifestError {
    Boundary(BoundaryError),
    Io(std::io::Error),
    Message(String),
}

impl std::fmt::Display for ManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Boundary(source) => write!(f, "{source}"),
            Self::Io(source) => write!(f, "{source}"),
            Self::Message(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for ManifestError {}

impl From<std::io::Error> for ManifestError {
    fn from(source: std::io::Error) -> Self {
        Self::Io(source)
    }
}

impl From<BoundaryError> for ManifestError {
    fn from(source: BoundaryError) -> Self {
        Self::Boundary(source)
    }
}

/// BuildTrustInputManifest hashes the canonical files that can affect trust.
pub fn build_trust_input_manifest(
    paths: &Paths,
    workspace: &str,
) -> Result<TrustInputManifest, ManifestError> {
    let root = validate_workspace(paths, workspace)?;

    struct ManifestInput {
        path: PathBuf,
        relative: String,
        kind: &'static str,
    }
    let mut inputs: Vec<ManifestInput> = Vec::new();
    let mut add = |path: &Path, kind: &'static str| -> Result<(), ManifestError> {
        let absolute = crate::paths::absolute(path)?;
        if !path_within(&root, &absolute) {
            return Err(ManifestError::Message(format!(
                "trust input path {:?} is outside workspace",
                path.display()
            )));
        }
        let relative = absolute
            .strip_prefix(&root)
            .map_err(|err| ManifestError::Io(std::io::Error::other(err)))?
            .to_string_lossy()
            .to_string();
        inputs.push(ManifestInput {
            path: absolute,
            relative,
            kind,
        });
        Ok(())
    };

    for tier in WIKI_TIERS {
        let tier_root = root.join("wiki").join(tier);
        validate_trust_input_directory(&root, &tier_root)
            .map_err(|err| ManifestError::Message(format!("validate wiki tier {tier:?}: {err}")))?;
        walk_trust_input_claims(&tier_root, &mut |path, kind| add(path, kind))?;
    }

    let sources_root = root.join("evidence").join("sources");
    walk_trust_input_evidence(&root, &sources_root, &mut |path, kind| add(path, kind))?;

    let mut entries: Vec<TrustInput> = Vec::with_capacity(inputs.len());
    for input in &inputs {
        let (byte_length, digest) = hash_trust_input_file(&input.path).map_err(|err| {
            ManifestError::Message(format!("hash trust input {:?}: {err}", input.relative))
        })?;
        entries.push(TrustInput {
            path: input.relative.clone(),
            kind: input.kind.to_string(),
            byte_length,
            sha256: digest,
        });
    }
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(TrustInputManifest {
        digest: trust_input_manifest_digest(&entries),
        entries,
    })
}

fn walk_trust_input_claims(
    root: &Path,
    add: &mut dyn FnMut(&Path, &'static str) -> Result<(), ManifestError>,
) -> Result<(), ManifestError> {
    let mut children: Vec<PathBuf> = std::fs::read_dir(root)?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .collect();
    children.sort();
    for path in children {
        let info = std::fs::symlink_metadata(&path)?;
        if info.file_type().is_symlink() {
            return Err(ManifestError::Message(format!(
                "trust input {:?} must not be a symlink",
                path.display()
            )));
        }
        if info.is_dir() {
            if path.extension().is_some_and(|ext| ext == "md") {
                return Err(ManifestError::Message(format!(
                    "trust input {:?} is not a regular file",
                    path.display()
                )));
            }
            walk_trust_input_claims(&path, add)?;
            continue;
        }
        if !path.extension().is_some_and(|ext| ext == "md") {
            continue;
        }
        if !info.is_file() {
            return Err(ManifestError::Message(format!(
                "trust input {:?} is not a regular file",
                path.display()
            )));
        }
        add(&path, TRUST_INPUT_KIND_CLAIM)?;
    }
    Ok(())
}

fn walk_trust_input_evidence(
    workspace_root: &Path,
    root: &Path,
    add: &mut dyn FnMut(&Path, &'static str) -> Result<(), ManifestError>,
) -> Result<(), ManifestError> {
    validate_trust_input_directory(workspace_root, root)
        .map_err(|err| ManifestError::Message(format!("validate evidence sources: {err}")))?;
    let mut children: Vec<PathBuf> = std::fs::read_dir(root)?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .collect();
    children.sort();
    for path in children {
        let entry_name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let info = std::fs::symlink_metadata(&path)?;
        if info.file_type().is_symlink() {
            return Err(ManifestError::Message(format!(
                "evidence source {:?} must not be a symlink",
                entry_name
            )));
        }
        if !info.is_dir() {
            continue;
        }
        validate_trust_input_directory(workspace_root, &path)?;
        for (name, kind) in [
            ("source.yaml", TRUST_INPUT_KIND_EVIDENCE_METADATA),
            ("raw", TRUST_INPUT_KIND_EVIDENCE_RAW),
        ] {
            let input_path = path.join(name);
            let info = match std::fs::symlink_metadata(&input_path) {
                Ok(info) => info,
                Err(source) if source.kind() == std::io::ErrorKind::NotFound => continue,
                Err(source) => return Err(source.into()),
            };
            if info.file_type().is_symlink() || !info.is_file() {
                return Err(ManifestError::Message(format!(
                    "trust input {:?} is not a regular file",
                    input_path.display()
                )));
            }
            add(&input_path, kind)?;
        }
    }
    Ok(())
}

fn validate_trust_input_directory(workspace_root: &Path, path: &Path) -> Result<(), ManifestError> {
    let info = std::fs::symlink_metadata(path)?;
    if info.file_type().is_symlink() {
        return Err(ManifestError::Message(format!(
            "{:?} must not be a symlink",
            path.display()
        )));
    }
    if !info.is_dir() {
        return Err(ManifestError::Message(format!(
            "{:?} is not a directory",
            path.display()
        )));
    }
    let absolute = crate::paths::absolute(path)?;
    let resolved = std::fs::canonicalize(path)?;
    let resolved = crate::paths::absolute(&resolved)?;
    if !path_within(workspace_root, &resolved) {
        return Err(ManifestError::Message(
            "resolved path escapes workspace".into(),
        ));
    }
    if resolved != absolute {
        return Err(ManifestError::Message(format!(
            "{:?} contains a symlink",
            path.display()
        )));
    }
    Ok(())
}

fn hash_trust_input_file(path: &Path) -> Result<(i64, String), std::io::Error> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut hash = Sha256::new();
    let mut byte_length: i64 = 0;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
        byte_length += read as i64;
    }
    let digest = hash.finalize();
    Ok((
        byte_length,
        digest.iter().map(|b| format!("{b:02x}")).collect(),
    ))
}

pub(crate) fn trust_input_manifest_digest(entries: &[TrustInput]) -> String {
    // Go json.Marshal of []TrustInput — compact, field order path, kind,
    // byte_length, sha256. serde_json emits the identical byte stream for
    // these ASCII-safe values.
    let encoded = serde_json::to_vec(entries).unwrap_or_default();
    let mut hash = Sha256::new();
    hash.update(&encoded);
    hash.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::FixedClock;
    use crate::config::ensure_config;
    use crate::paths::Options;
    use chrono::{TimeZone, Utc};
    use std::path::PathBuf;

    fn fixture(name: &str) -> (PathBuf, Paths) {
        let dir =
            std::env::temp_dir().join(format!("zbrain-manifest-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut paths = Paths::resolve(Options {
            cwd: Some(dir.join("project")),
            home_dir: Some(dir.clone()),
            runtime_dir: Some(dir.join(".zbrain")),
        })
        .unwrap();
        paths.key_dir = crate::signing::test_key_dir();
        ensure_config(&paths.config_file).unwrap();
        crate::workspace::create_workspace(
            &paths,
            "research",
            &FixedClock::new(Utc.with_ymd_and_hms(2026, 8, 4, 0, 0, 0).unwrap()),
        )
        .unwrap();
        (dir, paths)
    }

    fn write_manifest_file(root: &Path, relative: &str, contents: &[u8]) {
        let path = root.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, contents).unwrap();
    }

    fn expected_entry(relative: &str, contents: &[u8], kind: &str) -> TrustInput {
        let mut hash = Sha256::new();
        hash.update(contents);
        TrustInput {
            path: relative.to_string(),
            kind: kind.to_string(),
            byte_length: contents.len() as i64,
            sha256: hash.finalize().iter().map(|b| format!("{b:02x}")).collect(),
        }
    }

    #[test]
    fn manifest_evidence_inputs() {
        let (dir, paths) = fixture("inputs");
        let root = paths.workspaces_dir.join("research");
        let files: Vec<(&str, &[u8], &str)> = vec![
            ("wiki/axioms/axiom.md", b"axiom\n", TRUST_INPUT_KIND_CLAIM),
            (
                "wiki/mental-models/model.md",
                b"model\n",
                TRUST_INPUT_KIND_CLAIM,
            ),
            (
                "wiki/projects/nested/project.md",
                b"project\n",
                TRUST_INPUT_KIND_CLAIM,
            ),
            (
                "wiki/decisions/decision.md",
                b"decision\n",
                TRUST_INPUT_KIND_CLAIM,
            ),
            (
                "evidence/sources/evd_test/source.yaml",
                b"id: evd_test\n",
                TRUST_INPUT_KIND_EVIDENCE_METADATA,
            ),
            (
                "evidence/sources/evd_test/raw",
                &[0x00, 0x01, 0x02],
                TRUST_INPUT_KIND_EVIDENCE_RAW,
            ),
        ];
        for (relative, contents, _) in &files {
            write_manifest_file(&root, relative, contents);
        }
        for relative in [
            "wiki/projects/derived.json",
            "wiki/projects/readme.txt",
            "workspace.md",
            "evidence/_index.md",
            "evidence/analysis/derived.md",
            "evidence/qa/report.md",
            "evidence/applied/applied.md",
            "evidence/archive/archived.md",
            "evidence/sources/evd_test/notes.md",
        ] {
            write_manifest_file(&root, relative, b"excluded\n");
        }

        let manifest = build_trust_input_manifest(&paths, "research").unwrap();
        assert!(!manifest.digest.is_empty());
        assert_eq!(manifest.entries.len(), files.len());

        let mut want: Vec<TrustInput> = files
            .iter()
            .map(|(relative, contents, kind)| expected_entry(relative, contents, kind))
            .collect();
        want.sort_by(|left, right| left.path.cmp(&right.path));
        assert_eq!(manifest.entries, want);

        let repeated = build_trust_input_manifest(&paths, "research").unwrap();
        assert_eq!(manifest, repeated);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn manifest_detects_change_and_add_remove() {
        let (dir, paths) = fixture("change");
        let root = paths.workspaces_dir.join("research");
        let claim_path = root.join("wiki/projects/claim.md");
        std::fs::write(&claim_path, b"one\n").unwrap();

        let before = build_trust_input_manifest(&paths, "research").unwrap();
        std::fs::write(&claim_path, b"two\n").unwrap();
        let after_replacement = build_trust_input_manifest(&paths, "research").unwrap();
        let before_entry = before
            .entries
            .iter()
            .find(|e| e.path == "wiki/projects/claim.md")
            .unwrap();
        let replacement_entry = after_replacement
            .entries
            .iter()
            .find(|e| e.path == "wiki/projects/claim.md")
            .unwrap();
        assert_eq!(before_entry.byte_length, replacement_entry.byte_length);
        assert_ne!(before_entry.sha256, replacement_entry.sha256);
        assert_ne!(before.digest, after_replacement.digest);

        write_manifest_file(&root, "wiki/projects/added.md", b"added\n");
        let after_add = build_trust_input_manifest(&paths, "research").unwrap();
        assert_eq!(after_add.entries.len(), after_replacement.entries.len() + 1);
        assert_ne!(after_add.digest, after_replacement.digest);
        std::fs::remove_file(root.join("wiki/projects/added.md")).unwrap();
        let after_remove = build_trust_input_manifest(&paths, "research").unwrap();
        assert_eq!(after_remove, after_replacement);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn trust_input_manifest_rejects_unsafe_missing_and_covered_boundary_inputs() {
        let (dir, paths) = fixture("boundary");
        for workspace in ["../outside", "missing"] {
            assert!(
                build_trust_input_manifest(&paths, workspace).is_err(),
                "{workspace}"
            );
        }
        std::os::unix::fs::symlink(std::env::temp_dir(), paths.workspaces_dir.join("linked"))
            .unwrap();
        assert!(build_trust_input_manifest(&paths, "linked").is_err());
        let _ = std::fs::remove_dir_all(&dir);

        // symlinked-claim
        let (dir, paths) = fixture("symlinked-claim");
        let root = paths.workspaces_dir.join("research");
        let outside_claim = dir.join("outside-claim.md");
        std::fs::write(&outside_claim, b"outside\n").unwrap();
        let claim_path = root.join("wiki/projects/linked.md");
        std::os::unix::fs::symlink(&outside_claim, &claim_path).unwrap();
        assert!(build_trust_input_manifest(&paths, "research").is_err());
        let _ = std::fs::remove_dir_all(&dir);

        // non-regular-claim
        let (dir, paths) = fixture("non-regular-claim");
        let claim_path = paths
            .workspaces_dir
            .join("research/wiki/projects/directory.md");
        std::fs::create_dir(&claim_path).unwrap();
        assert!(build_trust_input_manifest(&paths, "research").is_err());
        let _ = std::fs::remove_dir_all(&dir);

        // symlinked-evidence-raw
        let (dir, paths) = fixture("symlinked-evidence-raw");
        let source_root = paths
            .workspaces_dir
            .join("research/evidence/sources/evd_test");
        std::fs::create_dir_all(&source_root).unwrap();
        let outside_raw = dir.join("outside.raw");
        std::fs::write(&outside_raw, b"outside\n").unwrap();
        std::os::unix::fs::symlink(&outside_raw, source_root.join("raw")).unwrap();
        assert!(build_trust_input_manifest(&paths, "research").is_err());
        let _ = std::fs::remove_dir_all(&dir);

        // non-regular-evidence-metadata
        let (dir, paths) = fixture("non-regular-evidence-metadata");
        let source_root = paths
            .workspaces_dir
            .join("research/evidence/sources/evd_test");
        std::fs::create_dir_all(&source_root).unwrap();
        std::fs::create_dir(source_root.join("source.yaml")).unwrap();
        assert!(build_trust_input_manifest(&paths, "research").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn manifest_deterministic() {
        let (dir, paths) = fixture("deterministic");
        crate::workspace::create_workspace(
            &paths,
            "other",
            &FixedClock::new(Utc.with_ymd_and_hms(2026, 8, 4, 0, 0, 0).unwrap()),
        )
        .unwrap();
        let files: Vec<(&str, &[u8])> = vec![
            ("wiki/projects/z.md", b"z\n"),
            ("wiki/axioms/a.md", b"a\n"),
            ("evidence/sources/evd_test/source.yaml", b"id: evd_test\n"),
            ("evidence/sources/evd_test/raw", &[0x01, 0x02]),
        ];
        let first_root = paths.workspaces_dir.join("research");
        let second_root = paths.workspaces_dir.join("other");
        for (relative, contents) in &files {
            write_manifest_file(&first_root, relative, contents);
        }
        for (relative, contents) in files.iter().rev() {
            write_manifest_file(&second_root, relative, contents);
        }

        let first = build_trust_input_manifest(&paths, "research").unwrap();
        let second = build_trust_input_manifest(&paths, "other").unwrap();
        assert_eq!(first.entries, second.entries);
        assert_eq!(first.digest, second.digest);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
