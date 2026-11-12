//! signing.rs — owner approval signatures (ADR 0002).
//!
//! An approved claim is trusted only when it carries an Ed25519 signature over
//! its approval message, made with the owner key file. The key lives outside
//! the runtime root (`$XDG_CONFIG_HOME/zbrain-keys`, falling back to
//! `~/.config/zbrain-keys`), directory `0700`, files `0600`. A symlinked key
//! directory or file, a path inside `ZBRAIN_HOME`, or a looser mode fails
//! closed: the anchor is as protected as the private key.
//!
//! The signed message binds the claim id, the verification digest, and the
//! `verified.at`/`verified.by` fields, because the digest blanks `verified.*`
//! and would otherwise leave the approval provenance forgeable.

use std::io::Write as _;
use std::os::unix::fs::{
    DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
};
use std::path::{Path, PathBuf};

use base64::Engine as _;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest as ShaDigest, Sha256};

use crate::claims::Claim;
use crate::paths::{absolute, Paths};
use crate::yaml::{self, Yaml};

pub const APPROVAL_ALGORITHM: &str = "ed25519";
pub const APPROVAL_SIGNING_DOMAIN: &str = "zbrain.approval/v1";
pub const KEY_DIR_NAME: &str = "zbrain-keys";
pub const PRIVATE_KEY_FILE: &str = "approval.ed25519";
pub const PUBLIC_KEY_FILE: &str = "approval.pub";
pub const KEY_STATE_FILE: &str = "approval.keys.yaml";
pub const KEY_STATE_SCHEMA: &str = "zbrain.approval-keys/v1";
pub const KEY_ID_LEN: usize = 16;

const KEY_DIRECTORY_MODE: u32 = 0o700;
const KEY_FILE_MODE: u32 = 0o600;
const SIGNATURE_LEN: usize = 64;
const SECRET_LEN: usize = 32;

const BASE64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyError(String);

impl KeyError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for KeyError {}

/// One key recorded in `approval.keys.yaml`.
#[derive(Debug, Clone)]
pub struct AnchorKey {
    pub key_id: String,
    pub public_key: VerifyingKey,
    pub state: String,
    pub retired_at: String,
    pub revoked_at: String,
}

/// The loaded anchor: the key directory plus every recorded key. Verification
/// never needs the private key; signing does.
#[derive(Debug, Clone)]
pub struct KeyStore {
    dir: PathBuf,
    keys: Vec<AnchorKey>,
}

#[derive(Debug, Clone)]
pub struct KeyInit {
    pub key_id: String,
    pub dir: PathBuf,
    pub private_key: PathBuf,
    pub public_key: PathBuf,
    pub keys_file: PathBuf,
}

pub fn is_approval_key_id(value: &str) -> bool {
    value.len() == KEY_ID_LEN
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub fn is_approval_signature(value: &str) -> bool {
    BASE64
        .decode(value)
        .map(|bytes| bytes.len() == SIGNATURE_LEN)
        .unwrap_or(false)
}

pub fn key_id_for(public_key: &VerifyingKey) -> String {
    let digest = Sha256::digest(public_key.to_bytes());
    digest[..KEY_ID_LEN / 2]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The byte-exact approval message: domain, claim id, verification digest,
/// approval time, approver, and key id, one per line after the domain.
pub fn approval_message(claim: &Claim, key_id: &str) -> Vec<u8> {
    let mut message = String::from(APPROVAL_SIGNING_DOMAIN);
    for field in [
        claim.id.as_str(),
        claim.verified_digest.as_str(),
        claim.verified_at.as_str(),
        claim.verified_by.as_str(),
        key_id,
    ] {
        message.push('\n');
        message.push_str(field);
    }
    message.into_bytes()
}

impl KeyStore {
    /// Load and validate the anchor. Fails closed on a symlinked key directory
    /// or file, a directory inside the runtime root, or a looser mode.
    pub fn open(paths: &Paths) -> Result<Self, KeyError> {
        let dir = paths.key_dir.clone();
        check_placement(&dir, &paths.runtime_dir)?;
        check_directory(&dir)?;
        let state = read_checked_file(&dir.join(KEY_STATE_FILE))?;
        let keys = parse_key_state(&state)?;
        let public = read_checked_file(&dir.join(PUBLIC_KEY_FILE))?;
        let public_key = decode_public_key(&public)?;
        // A key set with no active key (all retired or revoked) still verifies
        // older claims; only signing needs an active key.
        if let Some(active) = keys.iter().find(|key| key.state == "active") {
            if active.public_key != public_key {
                return Err(KeyError::new(format!(
                    "{} does not match the active key {} in {}",
                    dir.join(PUBLIC_KEY_FILE).display(),
                    active.key_id,
                    dir.join(KEY_STATE_FILE).display()
                )));
            }
        }
        let private = dir.join(PRIVATE_KEY_FILE);
        if private.exists() {
            check_file(&private)?;
        }
        Ok(Self { dir, keys })
    }

    /// Create the owner key, or converge a half-written one. Refuses when a
    /// private key already exists: rotation is a separate ceremony.
    pub fn init(paths: &Paths, now: DateTime<Utc>) -> Result<KeyInit, KeyError> {
        let dir = paths.key_dir.clone();
        check_placement(&dir, &paths.runtime_dir)?;
        if dir.exists() {
            check_directory(&dir)?;
        } else {
            create_key_directory(&dir)?;
        }
        let private_path = dir.join(PRIVATE_KEY_FILE);
        if private_path.exists() {
            return Err(KeyError::new(format!(
                "approval key already exists at {}; rotation is a separate ceremony",
                private_path.display()
            )));
        }
        let signing_key = SigningKey::generate(&mut rand_core::OsRng);
        let public_key = signing_key.verifying_key();
        let key_id = key_id_for(&public_key);
        let created_at = crate::clock::rfc3339(now);
        let public_path = write_key_file(
            &dir,
            PUBLIC_KEY_FILE,
            format!("{}\n", BASE64.encode(public_key.to_bytes())).as_bytes(),
        )?;
        let keys_file = write_key_file(
            &dir,
            KEY_STATE_FILE,
            &key_state_yaml(&key_id, &public_key, &created_at),
        )?;
        // The private key lands last: a crash before this rename leaves no
        // private key, so the next `init` regenerates and converges.
        let private_key = write_key_file(
            &dir,
            PRIVATE_KEY_FILE,
            format!("{}\n", BASE64.encode(signing_key.to_bytes())).as_bytes(),
        )?;
        Ok(KeyInit {
            key_id,
            dir,
            private_key,
            public_key: public_path,
            keys_file,
        })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn keys(&self) -> &[AnchorKey] {
        &self.keys
    }

    /// The active key id and its private key, checked against the anchor.
    pub fn active_signing_key(&self) -> Result<(String, SigningKey), KeyError> {
        let active = self
            .keys
            .iter()
            .find(|key| key.state == "active")
            .ok_or_else(|| KeyError::new("key state has no active key"))?;
        let bytes = read_checked_file(&self.dir.join(PRIVATE_KEY_FILE))?;
        let seed = decode_fixed::<SECRET_LEN>(&bytes, "private key")?;
        let signing_key = SigningKey::from_bytes(&seed);
        if key_id_for(&signing_key.verifying_key()) != active.key_id {
            return Err(KeyError::new(
                "approval private key does not match the active public key",
            ));
        }
        Ok((active.key_id.clone(), signing_key))
    }
}

/// Sign the claim's current verified block with the active owner key.
pub fn sign_claim(claim: &mut Claim, store: &KeyStore) -> Result<(), KeyError> {
    if claim.verified_at.is_empty()
        || claim.verified_by.is_empty()
        || claim.verified_digest.is_empty()
    {
        return Err(KeyError::new(
            "claim has no verified block to sign; compute the digest first",
        ));
    }
    let (key_id, signing_key) = store.active_signing_key()?;
    let message = approval_message(claim, &key_id);
    let signature = signing_key.sign(&message);
    claim.verified_alg = APPROVAL_ALGORITHM.to_string();
    claim.verified_key_id = key_id;
    claim.verified_sig = BASE64.encode(signature.to_bytes());
    Ok(())
}

/// Verify the claim's recorded signature against the anchor.
pub fn verify_claim_signature(claim: &Claim, store: &KeyStore) -> Result<(), KeyError> {
    if claim.verified_alg.is_empty()
        && claim.verified_key_id.is_empty()
        && claim.verified_sig.is_empty()
    {
        return Err(KeyError::new(format!(
            "claim {} is unsigned; run `zbrain claim resign`",
            claim.id
        )));
    }
    if claim.verified_alg != APPROVAL_ALGORITHM {
        return Err(KeyError::new(format!(
            "claim {} verified.alg must be {APPROVAL_ALGORITHM:?}",
            claim.id
        )));
    }
    if !is_approval_key_id(&claim.verified_key_id) {
        return Err(KeyError::new(format!(
            "claim {} verified.key_id is not a 16-hex key id",
            claim.id
        )));
    }
    let key = store
        .keys
        .iter()
        .find(|key| key.key_id == claim.verified_key_id)
        .ok_or_else(|| {
            KeyError::new(format!(
                "claim {} is signed by unknown key {}",
                claim.id, claim.verified_key_id
            ))
        })?;
    key_allows_at(key, &claim.verified_at)?;
    let signature = decode_signature(&claim.verified_sig)?;
    let message = approval_message(claim, &key.key_id);
    key.public_key
        .verify_strict(&message, &signature)
        .map_err(|_| {
            KeyError::new(format!(
                "claim {} approval signature does not verify",
                claim.id
            ))
        })
}

/// Verify one claim against the anchor at `paths.key_dir`.
pub fn verify_claim_signature_at(paths: &Paths, claim: &Claim) -> Result<(), KeyError> {
    let store = KeyStore::open(paths)?;
    verify_claim_signature(claim, &store)
}

fn key_allows_at(key: &AnchorKey, verified_at: &str) -> Result<(), KeyError> {
    let signed_at = crate::clock::parse_rfc3339(verified_at)
        .map_err(|_| KeyError::new(format!("claim verified.at {verified_at:?} is not RFC3339")))?;
    let boundary = match key.state.as_str() {
        "active" => return Ok(()),
        "retired" => &key.retired_at,
        "revoked" => &key.revoked_at,
        other => {
            return Err(KeyError::new(format!(
                "key {} state {other:?} is not supported",
                key.key_id
            )))
        }
    };
    if boundary.is_empty() {
        return Err(KeyError::new(format!(
            "key {} is {} without a boundary time",
            key.key_id, key.state
        )));
    }
    let boundary = crate::clock::parse_rfc3339(boundary).map_err(|_| {
        KeyError::new(format!(
            "key {} {} time is not RFC3339",
            key.key_id, key.state
        ))
    })?;
    if signed_at < boundary {
        return Ok(());
    }
    Err(KeyError::new(format!(
        "claim was signed at {verified_at} but key {} is {} since {boundary}",
        key.key_id,
        key.state,
        boundary = boundary.to_rfc3339()
    )))
}

fn decode_signature(value: &str) -> Result<Signature, KeyError> {
    let bytes = BASE64
        .decode(value.trim())
        .map_err(|err| KeyError::new(format!("verified.sig is not base64: {err}")))?;
    let bytes: [u8; SIGNATURE_LEN] = bytes
        .try_into()
        .map_err(|_| KeyError::new("verified.sig must decode to exactly 64 bytes".to_string()))?;
    Ok(Signature::from_bytes(&bytes))
}

fn decode_public_key(bytes: &[u8]) -> Result<VerifyingKey, KeyError> {
    let decoded = BASE64
        .decode(bytes.trim_ascii())
        .map_err(|err| KeyError::new(format!("{PUBLIC_KEY_FILE} is not base64: {err}")))?;
    let decoded: [u8; SECRET_LEN] = decoded
        .try_into()
        .map_err(|_| KeyError::new(format!("{PUBLIC_KEY_FILE} must decode to 32 bytes")))?;
    VerifyingKey::from_bytes(&decoded)
        .map_err(|err| KeyError::new(format!("{PUBLIC_KEY_FILE} is not a valid key: {err}")))
}

fn decode_fixed<const N: usize>(bytes: &[u8], label: &str) -> Result<[u8; N], KeyError> {
    let decoded = BASE64
        .decode(bytes.trim_ascii())
        .map_err(|err| KeyError::new(format!("{label} is not base64: {err}")))?;
    decoded
        .try_into()
        .map_err(|_| KeyError::new(format!("{label} must decode to {N} bytes")))
}

fn parse_key_state(bytes: &[u8]) -> Result<Vec<AnchorKey>, KeyError> {
    let map = yaml::de::document(bytes)
        .map_err(|err| KeyError::new(format!("{KEY_STATE_FILE} is invalid: {err}")))?;
    let schema = yaml::de::string(&map, "schema")
        .map_err(|err| KeyError::new(format!("{KEY_STATE_FILE}: {err}")))?;
    if schema != KEY_STATE_SCHEMA {
        return Err(KeyError::new(format!(
            "{KEY_STATE_FILE} schema must be {KEY_STATE_SCHEMA:?}"
        )));
    }
    let entries = yaml::de::mapping_list(&map, "keys")
        .map_err(|err| KeyError::new(format!("{KEY_STATE_FILE}: {err}")))?;
    if entries.is_empty() {
        return Err(KeyError::new(format!("{KEY_STATE_FILE} records no keys")));
    }
    let mut keys = Vec::with_capacity(entries.len());
    for entry in &entries {
        let field = |name: &str| {
            yaml::de::string(entry, name)
                .map_err(|err| KeyError::new(format!("{KEY_STATE_FILE}: {err}")))
        };
        let key_id = field("key_id")?;
        if !is_approval_key_id(&key_id) {
            return Err(KeyError::new(format!(
                "{KEY_STATE_FILE} key_id {key_id:?} is not 16 lowercase hex characters"
            )));
        }
        let alg = field("alg")?;
        if alg != APPROVAL_ALGORITHM {
            return Err(KeyError::new(format!(
                "{KEY_STATE_FILE} key {key_id} alg must be {APPROVAL_ALGORITHM:?}"
            )));
        }
        let public = field("public_key")?;
        let public_key = decode_public_key(public.as_bytes())?;
        if key_id_for(&public_key) != key_id {
            return Err(KeyError::new(format!(
                "{KEY_STATE_FILE} key {key_id} public key does not hash to its id"
            )));
        }
        keys.push(AnchorKey {
            key_id,
            public_key,
            state: field("state")?,
            retired_at: field("retired_at")?,
            revoked_at: field("revoked_at")?,
        });
    }
    Ok(keys)
}

fn key_state_yaml(key_id: &str, public_key: &VerifyingKey, created_at: &str) -> Vec<u8> {
    yaml::emit(&Yaml::map(vec![
        ("schema", Yaml::scalar(KEY_STATE_SCHEMA)),
        (
            "keys",
            Yaml::seq(vec![Yaml::map(vec![
                ("key_id", Yaml::scalar(key_id)),
                ("alg", Yaml::scalar(APPROVAL_ALGORITHM)),
                (
                    "public_key",
                    Yaml::scalar(&BASE64.encode(public_key.to_bytes())),
                ),
                ("state", Yaml::scalar("active")),
                ("created_at", Yaml::scalar(created_at)),
            ])]),
        ),
    ]))
}

fn check_placement(dir: &Path, runtime_dir: &Path) -> Result<(), KeyError> {
    let dir_abs = absolute(dir)
        .map_err(|err| KeyError::new(format!("resolve key directory {}: {err}", dir.display())))?;
    let runtime_abs = absolute(runtime_dir).map_err(|err| {
        KeyError::new(format!(
            "resolve runtime directory {}: {err}",
            runtime_dir.display()
        ))
    })?;
    if dir_abs.starts_with(&runtime_abs) {
        return Err(KeyError::new(format!(
            "approval key directory {} is inside the runtime root {}",
            dir_abs.display(),
            runtime_abs.display()
        )));
    }
    let dir_real = canonical_existing_prefix(&dir_abs);
    let runtime_real = canonical_existing_prefix(&runtime_abs);
    if dir_real.starts_with(&runtime_real) {
        return Err(KeyError::new(format!(
            "approval key directory {} resolves inside the runtime root {}",
            dir_real.display(),
            runtime_real.display()
        )));
    }
    Ok(())
}

/// Canonicalize the longest existing prefix so a symlinked ancestor cannot
/// hide a path inside the runtime root.
fn canonical_existing_prefix(path: &Path) -> PathBuf {
    let mut suffix: Vec<std::ffi::OsString> = Vec::new();
    let mut current = path.to_path_buf();
    loop {
        if let Ok(mut resolved) = std::fs::canonicalize(&current) {
            for part in suffix.iter().rev() {
                resolved.push(part);
            }
            return resolved;
        }
        match (current.parent(), current.file_name()) {
            (Some(parent), Some(name)) if !parent.as_os_str().is_empty() => {
                suffix.push(name.to_os_string());
                current = parent.to_path_buf();
            }
            _ => return path.to_path_buf(),
        }
    }
}

fn check_directory(dir: &Path) -> Result<(), KeyError> {
    let metadata = std::fs::symlink_metadata(dir).map_err(|err| {
        KeyError::new(format!(
            "approval key directory {} is unavailable: {err}; run `zbrain key init`",
            dir.display()
        ))
    })?;
    if metadata.file_type().is_symlink() {
        return Err(KeyError::new(format!(
            "approval key directory {} is a symlink",
            dir.display()
        )));
    }
    if !metadata.is_dir() {
        return Err(KeyError::new(format!(
            "approval key path {} is not a directory",
            dir.display()
        )));
    }
    check_mode(dir, metadata.mode(), KEY_DIRECTORY_MODE, "directory")
}

fn check_file(path: &Path) -> Result<(), KeyError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|err| KeyError::new(format!("{} is unavailable: {err}", path.display())))?;
    if metadata.file_type().is_symlink() {
        return Err(KeyError::new(format!("{} is a symlink", path.display())));
    }
    if !metadata.is_file() {
        return Err(KeyError::new(format!("{} is not a file", path.display())));
    }
    check_mode(path, metadata.mode(), KEY_FILE_MODE, "file")
}

fn check_mode(path: &Path, mode: u32, expected: u32, kind: &str) -> Result<(), KeyError> {
    let actual = mode & 0o777;
    if actual & !expected != 0 {
        return Err(KeyError::new(format!(
            "approval key {kind} {} has mode {actual:o}; expected {expected:o} or stricter",
            path.display()
        )));
    }
    Ok(())
}

fn read_checked_file(path: &Path) -> Result<Vec<u8>, KeyError> {
    check_file(path)?;
    std::fs::read(path).map_err(|err| KeyError::new(format!("read {}: {err}", path.display())))
}

fn create_key_directory(dir: &Path) -> Result<(), KeyError> {
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|err| KeyError::new(format!("create {}: {err}", parent.display())))?;
    }
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(KEY_DIRECTORY_MODE)
        .create(dir)
        .map_err(|err| KeyError::new(format!("create {}: {err}", dir.display())))?;
    // `recursive(true)` keeps an existing parent's mode; the key directory
    // itself is created by this call, so set the mode explicitly.
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(KEY_DIRECTORY_MODE))
        .map_err(|err| KeyError::new(format!("set mode on {}: {err}", dir.display())))
}

fn write_key_file(dir: &Path, name: &str, contents: &[u8]) -> Result<PathBuf, KeyError> {
    let temporary = dir.join(format!(".{name}.tmp"));
    let final_path = dir.join(name);
    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(KEY_FILE_MODE)
            .open(&temporary)
            .map_err(|err| KeyError::new(format!("create {}: {err}", temporary.display())))?;
        std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(KEY_FILE_MODE))
            .map_err(|err| KeyError::new(format!("set mode on {}: {err}", temporary.display())))?;
        file.write_all(contents)
            .map_err(|err| KeyError::new(format!("write {}: {err}", temporary.display())))?;
        file.sync_all()
            .map_err(|err| KeyError::new(format!("sync {}: {err}", temporary.display())))?;
    }
    std::fs::rename(&temporary, &final_path).map_err(|err| {
        KeyError::new(format!(
            "rename {} to {}: {err}",
            temporary.display(),
            final_path.display()
        ))
    })?;
    Ok(final_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claims::{
        claim_verification_digest, parse_claim_markdown, render_claim_markdown, Claim,
        ClaimTransition, CLAIM_BASIS_OWNER, CLAIM_STATUS_APPROVED, CLAIM_TRANSITION_APPROVE,
        OKF_CLAIM_TYPE,
    };
    use crate::paths::Options;
    use chrono::TimeZone;

    const CLAIM_ID: &str = "clm_00000000000000000000000000000001";

    struct Fixture {
        dir: PathBuf,
        paths: Paths,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn fixture(name: &str) -> Fixture {
        let dir =
            std::env::temp_dir().join(format!("zbrain-signing-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut paths = Paths::resolve(Options {
            cwd: Some(dir.join("project")),
            home_dir: Some(dir.clone()),
            runtime_dir: Some(dir.join(".zbrain")),
        })
        .unwrap();
        paths.key_dir = dir.join("xdg/zbrain-keys");
        Fixture { dir, paths }
    }

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 11, 12, 10, 0, 0).unwrap()
    }

    fn approved_claim() -> Claim {
        let mut claim = Claim {
            claim_type: OKF_CLAIM_TYPE.into(),
            id: CLAIM_ID.into(),
            tier: "projects".into(),
            status: CLAIM_STATUS_APPROVED.into(),
            title: "Approved fact".into(),
            basis: CLAIM_BASIS_OWNER.into(),
            created_at: "2026-11-12T09:00:00Z".into(),
            created_by: "owner".into(),
            verified_at: "2026-11-12T10:00:00Z".into(),
            verified_by: "owner".into(),
            transitions: vec![ClaimTransition {
                kind: CLAIM_TRANSITION_APPROVE.into(),
                at: "2026-11-12T10:00:00Z".into(),
                by: "owner".into(),
                ..ClaimTransition::default()
            }],
            body: "the fact\n".into(),
            ..Claim::default()
        };
        claim.verified_digest = claim_verification_digest(&claim).unwrap();
        claim
    }

    fn signing_key_from_disk(paths: &Paths) -> SigningKey {
        let bytes = std::fs::read(paths.key_dir.join(PRIVATE_KEY_FILE)).unwrap();
        SigningKey::from_bytes(&decode_fixed::<SECRET_LEN>(&bytes, "private key").unwrap())
    }

    fn sign_with(claim: &mut Claim, signing_key: &SigningKey, key_id: &str) {
        let message = approval_message(claim, key_id);
        claim.verified_alg = APPROVAL_ALGORITHM.into();
        claim.verified_key_id = key_id.into();
        claim.verified_sig = BASE64.encode(signing_key.sign(&message).to_bytes());
    }

    fn mode_of(path: &Path) -> u32 {
        std::fs::symlink_metadata(path).unwrap().mode() & 0o777
    }

    fn rewrite_key_state(paths: &Paths, key_id: &str, state: &str, boundary: &str) {
        let public = std::fs::read_to_string(paths.key_dir.join(PUBLIC_KEY_FILE)).unwrap();
        let body = format!(
            "schema: {KEY_STATE_SCHEMA}\nkeys:\n  - key_id: {key_id}\n    alg: {APPROVAL_ALGORITHM}\n    public_key: {}\n    state: {state}\n    created_at: 2026-11-12T09:00:00Z\n    {state}_at: {boundary}\n",
            public.trim()
        );
        let path = paths.key_dir.join(KEY_STATE_FILE);
        std::fs::write(&path, body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn approval_message_is_byte_exact() {
        let claim = approved_claim();
        let message = approval_message(&claim, "a1b2c3d4e5f60718");
        let expected = format!(
            "zbrain.approval/v1\n{CLAIM_ID}\n{}\n2026-11-12T10:00:00Z\nowner\na1b2c3d4e5f60718",
            claim.verified_digest
        );
        assert_eq!(String::from_utf8(message).unwrap(), expected);
    }

    #[test]
    fn signing_does_not_change_the_verification_digest() {
        let fx = fixture("digest");
        let mut claim = approved_claim();
        let before = claim_verification_digest(&claim).unwrap();
        let legacy = render_claim_markdown(&claim).unwrap();
        KeyStore::init(&fx.paths, now()).unwrap();
        let store = KeyStore::open(&fx.paths).unwrap();
        sign_claim(&mut claim, &store).unwrap();
        assert_eq!(claim_verification_digest(&claim).unwrap(), before);
        assert_eq!(claim.verified_digest, before);
        assert_eq!(store.keys()[0].key_id, claim.verified_key_id);
        assert_eq!(
            store.keys()[0].key_id,
            KeyStore::open(&fx.paths).unwrap().keys()[0].key_id
        );
        assert!(!String::from_utf8_lossy(&legacy).contains("alg:"));
        let signed = render_claim_markdown(&claim).unwrap();
        let text = String::from_utf8_lossy(&signed);
        assert!(text.contains("alg: ed25519"), "{text}");
        assert!(text.contains("key_id: "), "{text}");
        assert!(text.contains("sig: "), "{text}");
    }

    #[test]
    fn signed_claim_round_trips_render_and_parse() {
        let fx = fixture("roundtrip");
        KeyStore::init(&fx.paths, now()).unwrap();
        let store = KeyStore::open(&fx.paths).unwrap();
        let mut claim = approved_claim();
        sign_claim(&mut claim, &store).unwrap();
        let rendered = render_claim_markdown(&claim).unwrap();
        let parsed =
            parse_claim_markdown("projects", &format!("projects/{CLAIM_ID}.md"), &rendered)
                .unwrap();
        assert_eq!(parsed.verified_alg, APPROVAL_ALGORITHM);
        assert_eq!(parsed.verified_key_id, claim.verified_key_id);
        assert_eq!(parsed.verified_sig, claim.verified_sig);
        assert_eq!(parsed.verified_digest, claim.verified_digest);
        verify_claim_signature(&parsed, &store).unwrap();
    }

    #[test]
    fn key_init_creates_a_tight_private_anchor() {
        let fx = fixture("init");
        let report = KeyStore::init(&fx.paths, now()).unwrap();
        assert_eq!(mode_of(&fx.paths.key_dir), 0o700);
        for path in [&report.private_key, &report.public_key, &report.keys_file] {
            assert_eq!(mode_of(path), 0o600, "{}", path.display());
        }
        assert!(is_approval_key_id(&report.key_id));
        let store = KeyStore::open(&fx.paths).unwrap();
        assert_eq!(store.keys().len(), 1);
        assert_eq!(store.keys()[0].state, "active");
        assert_eq!(store.keys()[0].key_id, report.key_id);
    }

    #[test]
    fn key_init_refuses_to_clobber_an_existing_key() {
        let fx = fixture("clobber");
        let first = KeyStore::init(&fx.paths, now()).unwrap();
        let error = KeyStore::init(&fx.paths, now()).unwrap_err();
        assert!(error.to_string().contains("already exists"), "{error}");
        let store = KeyStore::open(&fx.paths).unwrap();
        assert_eq!(store.keys()[0].key_id, first.key_id);
    }

    #[test]
    fn key_dir_inside_the_runtime_root_is_refused() {
        let fx = fixture("inside");
        let mut paths = fx.paths.clone();
        paths.key_dir = paths.runtime_dir.join("zbrain-keys");
        let error = KeyStore::init(&paths, now()).unwrap_err();
        assert!(
            error.to_string().contains("inside the runtime root"),
            "{error}"
        );
        assert!(!paths.key_dir.exists());
    }

    #[test]
    fn symlinked_key_file_is_refused() {
        let fx = fixture("symlink");
        KeyStore::init(&fx.paths, now()).unwrap();
        let public = fx.paths.key_dir.join(PUBLIC_KEY_FILE);
        let target = fx.dir.join("elsewhere.pub");
        std::fs::rename(&public, &target).unwrap();
        std::os::unix::fs::symlink(&target, &public).unwrap();
        let error = KeyStore::open(&fx.paths).unwrap_err();
        assert!(error.to_string().contains("symlink"), "{error}");
    }

    #[test]
    fn loose_key_file_mode_is_refused() {
        let fx = fixture("loose");
        KeyStore::init(&fx.paths, now()).unwrap();
        let public = fx.paths.key_dir.join(PUBLIC_KEY_FILE);
        std::fs::set_permissions(&public, std::fs::Permissions::from_mode(0o644)).unwrap();
        let error = KeyStore::open(&fx.paths).unwrap_err();
        assert!(error.to_string().contains("mode 644"), "{error}");
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let fx = fixture("tamper");
        KeyStore::init(&fx.paths, now()).unwrap();
        let store = KeyStore::open(&fx.paths).unwrap();
        let mut claim = approved_claim();
        sign_claim(&mut claim, &store).unwrap();
        let mut bytes = BASE64.decode(&claim.verified_sig).unwrap();
        bytes[0] ^= 0xff;
        claim.verified_sig = BASE64.encode(bytes);
        let error = verify_claim_signature(&claim, &store).unwrap_err();
        assert!(error.to_string().contains("does not verify"), "{error}");
    }

    #[test]
    fn a_claim_signed_by_another_key_is_rejected() {
        let fx = fixture("otherkey");
        KeyStore::init(&fx.paths, now()).unwrap();
        let store = KeyStore::open(&fx.paths).unwrap();
        let mut claim = approved_claim();
        let other = SigningKey::generate(&mut rand_core::OsRng);
        let other_id = key_id_for(&other.verifying_key());
        sign_with(&mut claim, &other, &other_id);
        let error = verify_claim_signature(&claim, &store).unwrap_err();
        assert!(error.to_string().contains("unknown key"), "{error}");
    }

    #[test]
    fn unsigned_claim_is_rejected_with_the_resign_hint() {
        let fx = fixture("unsigned");
        KeyStore::init(&fx.paths, now()).unwrap();
        let store = KeyStore::open(&fx.paths).unwrap();
        let claim = approved_claim();
        let error = verify_claim_signature(&claim, &store).unwrap_err();
        assert!(error.to_string().contains("unsigned"), "{error}");
        assert!(error.to_string().contains("zbrain claim resign"), "{error}");
    }

    #[test]
    fn retired_key_verifies_only_approvals_before_retirement() {
        let fx = fixture("retired");
        let report = KeyStore::init(&fx.paths, now()).unwrap();
        rewrite_key_state(&fx.paths, &report.key_id, "retired", "2026-11-12T11:00:00Z");
        let store = KeyStore::open(&fx.paths).unwrap();
        let mut claim = approved_claim();
        sign_with(
            &mut claim,
            &signing_key_from_disk(&fx.paths),
            &report.key_id,
        );
        verify_claim_signature(&claim, &store).unwrap();

        claim.verified_at = "2026-11-12T12:00:00Z".into();
        let error = verify_claim_signature(&claim, &store).unwrap_err();
        assert!(error.to_string().contains("retired"), "{error}");
    }

    #[test]
    fn revoked_key_rejects_approvals_after_revocation() {
        let fx = fixture("revoked");
        let report = KeyStore::init(&fx.paths, now()).unwrap();
        rewrite_key_state(&fx.paths, &report.key_id, "revoked", "2026-11-12T11:00:00Z");
        let store = KeyStore::open(&fx.paths).unwrap();
        let mut claim = approved_claim();
        sign_with(
            &mut claim,
            &signing_key_from_disk(&fx.paths),
            &report.key_id,
        );
        verify_claim_signature(&claim, &store).unwrap();

        claim.verified_at = "2026-11-12T11:00:00Z".into();
        let error = verify_claim_signature(&claim, &store).unwrap_err();
        assert!(error.to_string().contains("revoked"), "{error}");
    }

    #[test]
    fn public_key_file_must_match_the_active_entry() {
        let fx = fixture("pubmismatch");
        KeyStore::init(&fx.paths, now()).unwrap();
        let other = SigningKey::generate(&mut rand_core::OsRng);
        let public = fx.paths.key_dir.join(PUBLIC_KEY_FILE);
        std::fs::write(
            &public,
            format!("{}\n", BASE64.encode(other.verifying_key().to_bytes())),
        )
        .unwrap();
        std::fs::set_permissions(&public, std::fs::Permissions::from_mode(0o600)).unwrap();
        let error = KeyStore::open(&fx.paths).unwrap_err();
        assert!(error.to_string().contains("does not match"), "{error}");
    }
}
