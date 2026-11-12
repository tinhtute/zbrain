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
    pub created_at: String,
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

/// A planned key recovery: the new key exists only in memory until the owner
/// types its id and `commit` writes it. ADR 0002 "Key rotation and loss".
#[derive(Debug)]
pub struct KeyRecovery {
    dir: PathBuf,
    key_id: String,
    signing_key: SigningKey,
    previous: Vec<AnchorKey>,
    now: DateTime<Utc>,
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
        open_key_dir(&paths.key_dir, &paths.runtime_dir)
    }

    /// Create the owner key, or converge a half-written one. Refuses when the
    /// anchor is committed: rotation is a separate ceremony, and a lost
    /// private key needs the explicit `recover` ceremony.
    pub fn init(paths: &Paths, now: DateTime<Utc>) -> Result<KeyInit, KeyError> {
        init_key_dir(&paths.key_dir, &paths.runtime_dir, now)
    }

    /// Plan a recovery for a lost private key. Existing claims still verify
    /// against the retired public keys; nothing is written until `commit`.
    ///
    /// A private key the anchor does not record is a recovery that crashed
    /// after writing it: the rerun adopts that key instead of generating
    /// another one, so `commit` converges on the same key id.
    pub fn recover(paths: &Paths, now: DateTime<Utc>) -> Result<KeyRecovery, KeyError> {
        let dir = paths.key_dir.clone();
        check_placement(&dir, &paths.runtime_dir)?;
        check_directory(&dir)?;
        let state_path = dir.join(KEY_STATE_FILE);
        if !state_path.exists() {
            return Err(KeyError::new(format!(
                "no approval key anchor at {}; run `zbrain key init`",
                dir.display()
            )));
        }
        let previous = parse_key_state(&read_checked_file(&state_path)?)?;
        let private_path = dir.join(PRIVATE_KEY_FILE);
        let signing_key = if private_path.exists() {
            let signing_key = signing_key_from_file(&private_path)?;
            let key_id = key_id_for(&signing_key.verifying_key());
            if previous.iter().any(|key| key.key_id == key_id) {
                return Err(KeyError::new(format!(
                    "the approval private key at {} matches key {key_id} in the anchor; \
                     recovery is only for a lost or half-committed key",
                    private_path.display()
                )));
            }
            signing_key
        } else {
            SigningKey::generate(&mut rand_core::OsRng)
        };
        let key_id = key_id_for(&signing_key.verifying_key());
        Ok(KeyRecovery {
            dir,
            key_id,
            signing_key,
            previous,
            now,
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
        let signing_key = signing_key_from_file(&self.dir.join(PRIVATE_KEY_FILE))?;
        if key_id_for(&signing_key.verifying_key()) != active.key_id {
            return Err(KeyError::new(
                "approval private key does not match the active public key",
            ));
        }
        Ok((active.key_id.clone(), signing_key))
    }
}

impl KeyRecovery {
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Keys this recovery retires. Their claims keep verifying: a retired key
    /// is trusted for approvals before its retirement instant. A key that is
    /// already retired or revoked keeps its state and is not listed.
    pub fn retired_key_ids(&self) -> Vec<String> {
        self.previous
            .iter()
            .filter(|key| !matches!(key.state.as_str(), "retired" | "revoked"))
            .map(|key| key.key_id.clone())
            .collect()
    }

    /// Write the new key as active and retire every previous key at `now`.
    /// A revoked key stays revoked and an already-retired key keeps its
    /// original boundary: recovery is the loss path, not the compromise path,
    /// and it must not widen a retired key's validity window.
    ///
    /// The three writes are ordered private key, public key, state file. A
    /// crash between them leaves a private key the anchor does not record, so
    /// the next `recover` adopts it and `commit` completes the same key id;
    /// the surfaces stay fail-closed until then.
    pub fn commit(self) -> Result<KeyInit, KeyError> {
        let private_key = self.write_private_key()?;
        let public_path = self.write_public_key()?;
        let keys_file = self.write_state()?;
        Ok(KeyInit {
            key_id: self.key_id,
            dir: self.dir,
            private_key,
            public_key: public_path,
            keys_file,
        })
    }

    fn write_private_key(&self) -> Result<PathBuf, KeyError> {
        write_key_file(
            &self.dir,
            PRIVATE_KEY_FILE,
            format!("{}\n", BASE64.encode(self.signing_key.to_bytes())).as_bytes(),
        )
    }

    fn write_public_key(&self) -> Result<PathBuf, KeyError> {
        let public_key = self.signing_key.verifying_key();
        write_key_file(
            &self.dir,
            PUBLIC_KEY_FILE,
            format!("{}\n", BASE64.encode(public_key.to_bytes())).as_bytes(),
        )
    }

    /// The state file is the commit marker: until this rename lands the anchor
    /// still names the previous active key.
    fn write_state(&self) -> Result<PathBuf, KeyError> {
        let public_key = self.signing_key.verifying_key();
        let created_at = crate::clock::rfc3339(self.now);
        let mut entries: Vec<AnchorKey> = self
            .previous
            .iter()
            .map(|key| match key.state.as_str() {
                "retired" | "revoked" => key.clone(),
                _ => AnchorKey {
                    state: "retired".to_string(),
                    retired_at: created_at.clone(),
                    ..key.clone()
                },
            })
            .collect();
        entries.push(AnchorKey {
            key_id: self.key_id.clone(),
            public_key,
            state: "active".to_string(),
            created_at,
            retired_at: String::new(),
            revoked_at: String::new(),
        });
        write_key_file(&self.dir, KEY_STATE_FILE, &key_state_yaml(&entries))
    }
}

fn signing_key_from_file(path: &Path) -> Result<SigningKey, KeyError> {
    let bytes = read_checked_file(path)?;
    let seed = decode_fixed::<SECRET_LEN>(&bytes, "private key")?;
    Ok(SigningKey::from_bytes(&seed))
}

fn open_key_dir(dir: &Path, runtime_dir: &Path) -> Result<KeyStore, KeyError> {
    let dir = dir.to_path_buf();
    check_placement(&dir, runtime_dir)?;
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
    Ok(KeyStore { dir, keys })
}

fn init_key_dir(dir: &Path, runtime_dir: &Path, now: DateTime<Utc>) -> Result<KeyInit, KeyError> {
    let dir = dir.to_path_buf();
    check_placement(&dir, runtime_dir)?;
    if dir.exists() {
        check_directory(&dir)?;
    } else {
        create_key_directory(&dir)?;
    }
    let private_path = dir.join(PRIVATE_KEY_FILE);
    let state_path = dir.join(KEY_STATE_FILE);
    // The state file is the commit marker: once it exists the anchor is
    // committed, so a missing private key is real loss, not a crashed init.
    if state_path.exists() {
        let keys = parse_key_state(&read_checked_file(&state_path)?)?;
        if private_path.exists() {
            let key_id = key_id_for(&signing_key_from_file(&private_path)?.verifying_key());
            if keys.iter().any(|key| key.key_id == key_id) {
                return Err(KeyError::new(format!(
                    "approval key already exists at {}; rotation is a separate ceremony",
                    private_path.display()
                )));
            }
            return Err(KeyError::new(format!(
                "the approval private key at {} is key {key_id}, which the anchor at {} \
                 does not record: a recovery was interrupted. Run `zbrain key init --recover` \
                 to finish it",
                private_path.display(),
                state_path.display()
            )));
        }
        let ids: Vec<&str> = keys.iter().map(|key| key.key_id.as_str()).collect();
        return Err(KeyError::new(format!(
            "the approval key anchor at {} records key(s) {} but the private key is gone. \
             Existing claims still verify. To recover, run `zbrain key init --recover` \
             and type the new key id",
            dir.display(),
            ids.join(", ")
        )));
    }
    let signing_key = SigningKey::generate(&mut rand_core::OsRng);
    let public_key = signing_key.verifying_key();
    let key_id = key_id_for(&public_key);
    let created_at = crate::clock::rfc3339(now);
    let private_key = write_key_file(
        &dir,
        PRIVATE_KEY_FILE,
        format!("{}\n", BASE64.encode(signing_key.to_bytes())).as_bytes(),
    )?;
    let public_path = write_key_file(
        &dir,
        PUBLIC_KEY_FILE,
        format!("{}\n", BASE64.encode(public_key.to_bytes())).as_bytes(),
    )?;
    // The state file lands last: a crash before this rename leaves no
    // committed anchor, so the next `init` regenerates and converges.
    let keys_file = write_key_file(
        &dir,
        KEY_STATE_FILE,
        &key_state_yaml(&[AnchorKey {
            key_id: key_id.clone(),
            public_key,
            state: "active".to_string(),
            created_at,
            retired_at: String::new(),
            revoked_at: String::new(),
        }]),
    )?;
    Ok(KeyInit {
        key_id,
        dir,
        private_key,
        public_key: public_path,
        keys_file,
    })
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
        // A revoked key is compromised: no claim it signed is trusted, at any
        // time. ADR 0002 "Key rotation and loss": every claim signed by a
        // revoked key becomes unsigned until re-signed after owner review.
        "revoked" => {
            return Err(KeyError::new(format!(
                "claim is signed by revoked key {}; re-sign it after owner review",
                key.key_id
            )))
        }
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
            created_at: field("created_at")?,
            retired_at: field("retired_at")?,
            revoked_at: field("revoked_at")?,
        });
    }
    Ok(keys)
}

fn key_state_yaml(keys: &[AnchorKey]) -> Vec<u8> {
    let entries = keys
        .iter()
        .map(|key| {
            let mut fields = vec![
                ("key_id", Yaml::scalar(&key.key_id)),
                ("alg", Yaml::scalar(APPROVAL_ALGORITHM)),
                (
                    "public_key",
                    Yaml::scalar(&BASE64.encode(key.public_key.to_bytes())),
                ),
                ("state", Yaml::scalar(&key.state)),
                ("created_at", Yaml::scalar(&key.created_at)),
            ];
            if !key.retired_at.is_empty() {
                fields.push(("retired_at", Yaml::scalar(&key.retired_at)));
            }
            if !key.revoked_at.is_empty() {
                fields.push(("revoked_at", Yaml::scalar(&key.revoked_at)));
            }
            Yaml::map(fields)
        })
        .collect();
    yaml::emit(&Yaml::map(vec![
        ("schema", Yaml::scalar(KEY_STATE_SCHEMA)),
        ("keys", Yaml::seq(entries)),
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

/// Process-wide throwaway key for unit tests. Fixtures point `Paths.key_dir`
/// at it; it never touches the real `~/.config`.
#[cfg(test)]
pub(crate) fn test_key_dir() -> PathBuf {
    static DIR: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    DIR.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("zbrain-test-keys-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        init_key_dir(&dir, &dir.join("runtime"), Utc::now()).expect("init test approval key");
        dir
    })
    .clone()
}

#[cfg(test)]
pub(crate) fn test_key_store() -> KeyStore {
    static STORE: std::sync::OnceLock<KeyStore> = std::sync::OnceLock::new();
    STORE
        .get_or_init(|| {
            let dir = test_key_dir();
            open_key_dir(&dir, &dir.join("runtime")).expect("open test approval key")
        })
        .clone()
}

/// Sign an approved claim built by a test with the process-wide test key.
#[cfg(test)]
pub(crate) fn sign_test_claim(claim: &mut Claim) {
    let store = test_key_store();
    if claim.verified_digest.is_empty() {
        claim.verified_digest = crate::claims::claim_verification_digest(claim)
            .expect("test claim verification digest");
    }
    sign_claim(claim, &store).expect("sign test claim");
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
    fn symlinked_key_directory_is_refused() {
        let fx = fixture("symlink-dir");
        let real = fx.dir.join("elsewhere/zbrain-keys");
        KeyStore::init(
            &Paths {
                key_dir: real.clone(),
                ..fx.paths.clone()
            },
            now(),
        )
        .unwrap();
        std::fs::create_dir_all(fx.dir.join("xdg")).unwrap();
        std::os::unix::fs::symlink(&real, &fx.paths.key_dir).unwrap();
        let error = KeyStore::open(&fx.paths).unwrap_err();
        assert!(error.to_string().contains("is a symlink"), "{error}");
    }

    #[test]
    fn loose_key_directory_mode_is_refused() {
        let fx = fixture("loose-dir");
        KeyStore::init(&fx.paths, now()).unwrap();
        std::fs::set_permissions(&fx.paths.key_dir, std::fs::Permissions::from_mode(0o755))
            .unwrap();
        let error = KeyStore::open(&fx.paths).unwrap_err();
        assert!(error.to_string().contains("mode 755"), "{error}");
    }

    #[test]
    fn symlinked_ancestor_inside_the_runtime_root_is_refused() {
        let fx = fixture("symlink-ancestor");
        let mut paths = fx.paths.clone();
        // The literal path is outside the runtime root; a symlinked ancestor
        // resolves it inside. Only canonicalization catches this.
        std::fs::create_dir_all(&paths.runtime_dir).unwrap();
        std::fs::create_dir_all(fx.dir.join("xdg")).unwrap();
        std::os::unix::fs::symlink(&paths.runtime_dir, fx.dir.join("xdg/link")).unwrap();
        paths.key_dir = fx.dir.join("xdg/link/zbrain-keys");
        let error = KeyStore::init(&paths, now()).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("resolves inside the runtime root"),
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
    fn revoked_key_rejects_every_claim_it_signed() {
        let fx = fixture("revoked");
        let report = KeyStore::init(&fx.paths, now()).unwrap();
        let mut claim = approved_claim();
        sign_with(
            &mut claim,
            &signing_key_from_disk(&fx.paths),
            &report.key_id,
        );
        rewrite_key_state(&fx.paths, &report.key_id, "revoked", "2026-11-12T11:00:00Z");
        let store = KeyStore::open(&fx.paths).unwrap();

        // Signed before the revocation instant: still untrusted, because a
        // compromised key can backdate. ADR 0002 "Compromise".
        claim.verified_at = "2026-11-12T10:00:00Z".into();
        let error = verify_claim_signature(&claim, &store).unwrap_err();
        assert!(error.to_string().contains("revoked"), "{error}");

        claim.verified_at = "2026-11-12T11:00:00Z".into();
        let error = verify_claim_signature(&claim, &store).unwrap_err();
        assert!(error.to_string().contains("revoked"), "{error}");
    }

    #[test]
    fn key_init_refuses_to_replace_a_lost_private_key() {
        let fx = fixture("lost-key");
        let report = KeyStore::init(&fx.paths, now()).unwrap();
        std::fs::remove_file(fx.paths.key_dir.join(PRIVATE_KEY_FILE)).unwrap();

        let error = KeyStore::init(&fx.paths, now()).unwrap_err();
        let text = error.to_string();
        assert!(text.contains("--recover"), "{text}");
        assert!(text.contains(&report.key_id), "{text}");
        // The anchor is untouched: existing claims still verify.
        assert!(KeyStore::open(&fx.paths).is_ok());
    }

    #[test]
    fn recovery_retires_the_old_key_so_old_claims_still_verify() {
        let fx = fixture("recover");
        let report = KeyStore::init(&fx.paths, now()).unwrap();
        let mut claim = approved_claim();
        sign_with(
            &mut claim,
            &signing_key_from_disk(&fx.paths),
            &report.key_id,
        );
        std::fs::remove_file(fx.paths.key_dir.join(PRIVATE_KEY_FILE)).unwrap();

        // Recover an hour later: the retirement boundary must not be the
        // instant the old claim was signed.
        let later = now() + chrono::Duration::hours(1);
        let recovery = KeyStore::recover(&fx.paths, later).unwrap();
        let new_key_id = recovery.key_id().to_string();
        assert_ne!(new_key_id, report.key_id);
        assert_eq!(recovery.retired_key_ids(), vec![report.key_id.clone()]);
        let committed = recovery.commit().expect("commit writes the new anchor");
        assert_eq!(committed.key_id, new_key_id);

        let store = KeyStore::open(&fx.paths).unwrap();
        verify_claim_signature(&claim, &store).expect("retired key keeps old claims valid");
        let (active_id, _) = store.active_signing_key().unwrap();
        assert_eq!(active_id, new_key_id);
        assert_eq!(store.keys().len(), 2);
    }

    #[test]
    fn recovery_refuses_when_the_private_key_is_present() {
        let fx = fixture("recover-present");
        KeyStore::init(&fx.paths, now()).unwrap();
        let error = KeyStore::recover(&fx.paths, now()).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("recovery is only for a lost or half-committed key"),
            "{error}"
        );
    }

    #[test]
    fn recovery_converges_after_a_crash_between_writes() {
        for crash_after in ["private", "public"] {
            let fx = fixture(&format!("crash-{crash_after}"));
            let report = KeyStore::init(&fx.paths, now()).unwrap();
            let mut claim = approved_claim();
            sign_with(
                &mut claim,
                &signing_key_from_disk(&fx.paths),
                &report.key_id,
            );
            std::fs::remove_file(fx.paths.key_dir.join(PRIVATE_KEY_FILE)).unwrap();

            let later = now() + chrono::Duration::hours(1);
            let recovery = KeyStore::recover(&fx.paths, later).unwrap();
            let new_key_id = recovery.key_id().to_string();
            // Stop commit after the named step: that is the on-disk state a
            // crash at that point leaves.
            recovery.write_private_key().unwrap();
            if crash_after == "public" {
                recovery.write_public_key().unwrap();
            }
            drop(recovery);

            // Fail closed until the rerun completes.
            if crash_after == "private" {
                let store = KeyStore::open(&fx.paths).expect("the old anchor still loads");
                assert!(
                    store.active_signing_key().is_err(),
                    "a half-written private key must not sign"
                );
            } else {
                assert!(
                    KeyStore::open(&fx.paths).is_err(),
                    "a half-written public key must not load"
                );
            }

            // `init` names the recovery command instead of demanding a hand
            // deletion.
            let error = KeyStore::init(&fx.paths, later).unwrap_err();
            assert!(error.to_string().contains("--recover"), "{error}");

            // The rerun adopts the private key on disk and converges on the
            // same key id.
            let rerun = KeyStore::recover(&fx.paths, later).unwrap();
            assert_eq!(rerun.key_id(), new_key_id);
            rerun.commit().unwrap();
            let store = KeyStore::open(&fx.paths).unwrap();
            verify_claim_signature(&claim, &store).expect("the retired key keeps the old claim");
            assert_eq!(store.active_signing_key().unwrap().0, new_key_id);
        }
    }

    #[test]
    fn recovery_keeps_an_already_retired_key_boundary() {
        let fx = fixture("retired-boundary");
        let report = KeyStore::init(&fx.paths, now()).unwrap();
        let boundary = "2026-11-12T10:30:00Z";
        rewrite_key_state(&fx.paths, &report.key_id, "retired", boundary);
        std::fs::remove_file(fx.paths.key_dir.join(PRIVATE_KEY_FILE)).unwrap();

        let later = now() + chrono::Duration::hours(1);
        let recovery = KeyStore::recover(&fx.paths, later).unwrap();
        assert!(
            recovery.retired_key_ids().is_empty(),
            "an already retired key is not retired again"
        );
        recovery.commit().unwrap();

        let store = KeyStore::open(&fx.paths).unwrap();
        let old = store
            .keys()
            .iter()
            .find(|key| key.key_id == report.key_id)
            .expect("the old key stays in the anchor");
        assert_eq!(old.state, "retired");
        assert_eq!(
            old.retired_at, boundary,
            "recovery must not move an existing retirement boundary"
        );
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
