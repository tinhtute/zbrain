//! claims.rs — port of internal/runtime/claim.go and claim_store.go (m2
//! surface: parse/render/validate/digests/contradictions, WriteDraft, Read,
//! ScanWorkspace/ScanWorkspaceTrusted, write-once canonical Markdown).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use crate::yaml::de::{self, Error as YamlParseError};
use sha2::{Digest as ShaDigest, Sha256};
use yaml_rust2::Yaml as YamlValue;

use crate::boundary::{
    resolve_workspace_path, safe_relative_path, validate_workspace, BoundaryError,
};
use crate::coordination::{
    begin_canonical_mutation_unlocked, run_workspace_generation_test_hook, MutationError,
    WORKSPACE_GENERATION_HOOK_BEFORE_CANONICAL_WRITE,
};
use crate::evidence::{validate_claim_evidence, EvidenceValidator};
use crate::paths::{
    ensure_directory_mode, ensure_file_mode, Paths, RUNTIME_DIRECTORY_MODE, RUNTIME_METADATA_MODE,
};
use crate::trust::TrustValidator;
use crate::workspace::WIKI_TIERS;
use crate::yaml::{self, Yaml, YamlStyle};

pub const CLAIM_SCHEMA_VERSION: &str = "zbrain.claim/v1";
pub const OKF_CLAIM_TYPE: &str = "zbrain.claim";
pub const ZBRAIN_TRUSTED_MEMORY_PROFILE: &str = "zbrain.trusted-memory/v1";

pub const CLAIM_STATUS_DRAFT: &str = "draft";
pub const CLAIM_STATUS_APPROVED: &str = "approved";
pub const CLAIM_STATUS_SUPERSEDED: &str = "superseded";
pub const CLAIM_STATUS_REVOKED: &str = "revoked";

pub const CLAIM_BASIS_OWNER: &str = "owner";
pub const CLAIM_BASIS_EVIDENCE: &str = "evidence";
pub const CLAIM_BASIS_DERIVED: &str = "derived";

pub const CONTRADICTION_NEGATION: &str = "negation";
pub const CONTRADICTION_VALUE_SWAP: &str = "value_swap";
pub const CONTRADICTION_STATUS_CHANGE: &str = "status_change";

pub const CLAIM_TRANSITION_APPROVE: &str = "approve";
pub const CLAIM_TRANSITION_SUPERSEDE: &str = "supersede";
pub const CLAIM_TRANSITION_REVOKE: &str = "revoke";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Claim {
    pub schema: String,
    pub claim_type: String,
    pub id: String,
    pub tier: String,
    pub path: String,
    pub status: String,
    pub title: String,
    pub description: String,
    pub resource: String,
    pub basis: String,
    pub created_at: String,
    pub created_by: String,
    pub verified_at: String,
    pub verified_by: String,
    pub verified_digest: String,
    /// Approval signature (ADR 0002): `ed25519`, the key id, and the base64
    /// signature over the approval message. Empty on legacy unsigned claims.
    pub verified_alg: String,
    pub verified_key_id: String,
    pub verified_sig: String,
    pub stale_after: String,
    pub sources: Vec<ClaimSource>,
    pub evidence_ids: Vec<String>,
    pub supporting_claim_ids: Vec<String>,
    pub supersedes: Vec<String>,
    pub conflicts_with: Vec<String>,
    pub contradicts: Vec<Contradiction>,
    pub tags: Vec<String>,
    pub transitions: Vec<ClaimTransition>,
    pub body: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClaimSource {
    pub id: String,
    pub resource: String,
    pub title: String,
    pub digest: String,
    pub spans: Vec<EvidenceSpan>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EvidenceSpan {
    pub evidence_id: String,
    pub start_line: i64,
    pub end_line: i64,
    pub digest: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Contradiction {
    pub claim_id: String,
    pub heuristic: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClaimTransition {
    pub kind: String,
    pub at: String,
    pub by: String,
    pub reason: String,
    pub related_claim_ids: Vec<String>,
    pub prior_verification_digest: String,
    pub authorization: Option<ClaimTransitionAuthorization>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClaimTransitionAuthorization {
    pub challenge_id: String,
    pub method: String,
    pub mcp_client: String,
}

#[derive(Debug)]
pub enum ClaimError {
    Boundary(BoundaryError),
    Io(std::io::Error),
    NotFound,
    Message(String),
}

impl std::fmt::Display for ClaimError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Boundary(source) => write!(f, "{source}"),
            Self::Io(source) => write!(f, "{source}"),
            Self::NotFound => write!(f, "claim not found"),
            Self::Message(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for ClaimError {}

impl From<std::io::Error> for ClaimError {
    fn from(source: std::io::Error) -> Self {
        Self::Io(source)
    }
}

impl From<BoundaryError> for ClaimError {
    fn from(source: BoundaryError) -> Self {
        Self::Boundary(source)
    }
}

impl From<MutationError> for ClaimError {
    fn from(source: MutationError) -> Self {
        Self::Message(source.to_string())
    }
}

impl From<YamlParseError> for ClaimError {
    fn from(source: YamlParseError) -> Self {
        Self::Message(source.to_string())
    }
}

pub fn message(err: impl std::fmt::Display) -> ClaimError {
    ClaimError::Message(err.to_string())
}

impl ClaimError {
    pub fn is_not_found(&self) -> bool {
        match self {
            Self::NotFound => true,
            Self::Io(source) => source.kind() == std::io::ErrorKind::NotFound,
            _ => false,
        }
    }
}

pub fn is_claim_id(value: &str) -> bool {
    has_id_prefix(value, "clm_")
}

pub fn is_evidence_id(value: &str) -> bool {
    has_id_prefix(value, "evd_")
}

pub fn is_challenge_id(value: &str) -> bool {
    has_id_prefix(value, "chg_")
}

fn has_id_prefix(value: &str, prefix: &str) -> bool {
    let Some(rest) = value.strip_prefix(prefix) else {
        return false;
    };
    rest.len() == 32
        && rest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn new_claim_id() -> Result<String, std::io::Error> {
    Ok("clm_".to_string() + &random_hex(16)?)
}

pub fn new_evidence_id() -> Result<String, std::io::Error> {
    Ok("evd_".to_string() + &random_hex(16)?)
}

pub(crate) fn random_hex(bytes: usize) -> Result<String, std::io::Error> {
    use std::io::Read;
    let mut buf = vec![0u8; bytes];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut buf)?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

fn sha256_hex(contents: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(contents);
    hex_lower(&hash.finalize())
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------------
// Frontmatter parsing (pure-Rust yaml_rust2 over closed schemas — output
// style is irrelevant on this side).
// ---------------------------------------------------------------------------

#[derive(Default)]
struct ProbeFrontmatter {
    schema: String,
    claim_type: String,
}

#[derive(Default, Clone)]
struct ClaimSourceYaml {
    id: String,
    resource: String,
    title: String,
    digest: String,
    spans: Vec<EvidenceSpanYaml>,
}

#[derive(Default, Clone)]
struct EvidenceSpanYaml {
    evidence_id: String,
    start_line: i64,
    end_line: i64,
    digest: String,
}

#[derive(Default, Clone)]
struct ContradictionYaml {
    claim_id: String,
    heuristic: String,
}

#[derive(Default, Clone)]
struct ClaimTransitionYaml {
    kind: String,
    at: String,
    by: String,
    reason: String,
    related_claim_ids: Vec<String>,
    prior_verification_digest: String,
    authorization: Option<ClaimTransitionAuthorizationYaml>,
}

#[derive(Default, Clone)]
struct ClaimTransitionAuthorizationYaml {
    challenge_id: String,
    method: String,
    mcp_client: String,
}

#[derive(Default)]
struct GeneratedYaml {
    at: String,
    by: String,
}

#[derive(Default)]
struct VerifiedYaml {
    at: String,
    by: String,
    digest: String,
    alg: String,
    key_id: String,
    sig: String,
}

#[derive(Default)]
struct ZbrainProfileYaml {
    profile: String,
    id: String,
    tier: String,
    basis: String,
    evidence_ids: Vec<String>,
    supporting_claim_ids: Vec<String>,
    supersedes: Vec<String>,
    conflicts_with: Vec<String>,
    contradicts: Vec<ContradictionYaml>,
    transitions: Vec<ClaimTransitionYaml>,
}

#[derive(Default)]
struct OkfFrontmatterYaml {
    claim_type: String,
    title: String,
    description: String,
    resource: String,
    tags: Vec<String>,
    sources: Vec<ClaimSourceYaml>,
    generated: Option<GeneratedYaml>,
    verified: Option<VerifiedYaml>,
    status: String,
    stale_after: String,
    zbrain: ZbrainProfileYaml,
}

#[derive(Default)]
struct LegacyFrontmatterYaml {
    schema: String,
    id: String,
    status: String,
    title: String,
    description: String,
    resource: String,
    basis: String,
    created_at: String,
    created_by: String,
    verified: Option<VerifiedYaml>,
    stale_after: String,
    sources: Vec<ClaimSourceYaml>,
    evidence_ids: Vec<String>,
    supporting_claim_ids: Vec<String>,
    supersedes: Vec<String>,
    conflicts_with: Vec<String>,
    tags: Vec<String>,
    transitions: Vec<ClaimTransitionYaml>,
}

type YamlMap = BTreeMap<String, YamlValue>;

fn parse_frontmatter_map(frontmatter: &[u8]) -> Result<YamlMap, ClaimError> {
    de::document(frontmatter).map_err(|err| ClaimError::Message(err.to_string()))
}

impl ProbeFrontmatter {
    fn from_map(map: &YamlMap) -> Result<Self, YamlParseError> {
        Ok(Self {
            schema: de::string(map, "schema")?,
            claim_type: de::string(map, "type")?,
        })
    }
}

impl ClaimSourceYaml {
    fn from_map(map: &YamlMap) -> Result<Self, YamlParseError> {
        Ok(Self {
            id: de::string(map, "id")?,
            resource: de::string(map, "resource")?,
            title: de::string(map, "title")?,
            digest: de::string(map, "digest")?,
            spans: de::mapping_list(map, "spans")?
                .iter()
                .map(EvidenceSpanYaml::from_map)
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

impl EvidenceSpanYaml {
    fn from_map(map: &YamlMap) -> Result<Self, YamlParseError> {
        Ok(Self {
            evidence_id: de::string(map, "evidence_id")?,
            start_line: de::integer(map, "start_line")?,
            end_line: de::integer(map, "end_line")?,
            digest: de::string(map, "digest")?,
        })
    }
}

impl ContradictionYaml {
    fn from_map(map: &YamlMap) -> Result<Self, YamlParseError> {
        Ok(Self {
            claim_id: de::string(map, "claim_id")?,
            heuristic: de::string(map, "heuristic")?,
        })
    }
}

impl ClaimTransitionAuthorizationYaml {
    fn from_map(map: &YamlMap) -> Result<Self, YamlParseError> {
        Ok(Self {
            challenge_id: de::string(map, "challenge_id")?,
            method: de::string(map, "method")?,
            mcp_client: de::string(map, "mcp_client")?,
        })
    }
}

impl ClaimTransitionYaml {
    fn from_map(map: &YamlMap) -> Result<Self, YamlParseError> {
        Ok(Self {
            kind: de::string(map, "kind")?,
            at: de::string(map, "at")?,
            by: de::string(map, "by")?,
            reason: de::string(map, "reason")?,
            related_claim_ids: de::string_list(map, "related_claim_ids")?,
            prior_verification_digest: de::string(map, "prior_verification_digest")?,
            authorization: match de::mapping(map, "authorization")? {
                None => None,
                Some(nested) => Some(ClaimTransitionAuthorizationYaml::from_map(&nested)?),
            },
        })
    }
}

impl GeneratedYaml {
    fn from_map(map: &YamlMap) -> Result<Self, YamlParseError> {
        Ok(Self {
            at: de::string(map, "at")?,
            by: de::string(map, "by")?,
        })
    }
}

impl VerifiedYaml {
    fn from_map(map: &YamlMap) -> Result<Self, YamlParseError> {
        Ok(Self {
            at: de::string(map, "at")?,
            by: de::string(map, "by")?,
            digest: de::string(map, "digest")?,
            alg: de::string(map, "alg")?,
            key_id: de::string(map, "key_id")?,
            sig: de::string(map, "sig")?,
        })
    }
}

impl ZbrainProfileYaml {
    fn from_map(map: &YamlMap) -> Result<Self, YamlParseError> {
        Ok(Self {
            profile: de::string(map, "profile")?,
            id: de::string(map, "id")?,
            tier: de::string(map, "tier")?,
            basis: de::string(map, "basis")?,
            evidence_ids: de::string_list(map, "evidence_ids")?,
            supporting_claim_ids: de::string_list(map, "supporting_claim_ids")?,
            supersedes: de::string_list(map, "supersedes")?,
            conflicts_with: de::string_list(map, "conflicts_with")?,
            contradicts: de::mapping_list(map, "contradicts")?
                .iter()
                .map(ContradictionYaml::from_map)
                .collect::<Result<Vec<_>, _>>()?,
            transitions: de::mapping_list(map, "transitions")?
                .iter()
                .map(ClaimTransitionYaml::from_map)
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

impl OkfFrontmatterYaml {
    fn from_map(map: &YamlMap) -> Result<Self, YamlParseError> {
        Ok(Self {
            claim_type: de::string(map, "type")?,
            title: de::string(map, "title")?,
            description: de::string(map, "description")?,
            resource: de::string(map, "resource")?,
            tags: de::string_list(map, "tags")?,
            sources: de::mapping_list(map, "sources")?
                .iter()
                .map(ClaimSourceYaml::from_map)
                .collect::<Result<Vec<_>, _>>()?,
            generated: match de::mapping(map, "generated")? {
                None => None,
                Some(nested) => Some(GeneratedYaml::from_map(&nested)?),
            },
            verified: match de::mapping(map, "verified")? {
                None => None,
                Some(nested) => Some(VerifiedYaml::from_map(&nested)?),
            },
            status: de::string(map, "status")?,
            stale_after: de::string(map, "stale_after")?,
            zbrain: match de::mapping(map, "zbrain")? {
                None => ZbrainProfileYaml::default(),
                Some(nested) => ZbrainProfileYaml::from_map(&nested)?,
            },
        })
    }
}

impl LegacyFrontmatterYaml {
    fn from_map(map: &YamlMap) -> Result<Self, YamlParseError> {
        Ok(Self {
            schema: de::string(map, "schema")?,
            id: de::string(map, "id")?,
            status: de::string(map, "status")?,
            title: de::string(map, "title")?,
            description: de::string(map, "description")?,
            resource: de::string(map, "resource")?,
            basis: de::string(map, "basis")?,
            created_at: de::string(map, "created_at")?,
            created_by: de::string(map, "created_by")?,
            verified: match de::mapping(map, "verified")? {
                None => None,
                Some(nested) => Some(VerifiedYaml::from_map(&nested)?),
            },
            stale_after: de::string(map, "stale_after")?,
            sources: de::mapping_list(map, "sources")?
                .iter()
                .map(ClaimSourceYaml::from_map)
                .collect::<Result<Vec<_>, _>>()?,
            evidence_ids: de::string_list(map, "evidence_ids")?,
            supporting_claim_ids: de::string_list(map, "supporting_claim_ids")?,
            supersedes: de::string_list(map, "supersedes")?,
            conflicts_with: de::string_list(map, "conflicts_with")?,
            tags: de::string_list(map, "tags")?,
            transitions: de::mapping_list(map, "transitions")?
                .iter()
                .map(ClaimTransitionYaml::from_map)
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

fn source_from_yaml(source: ClaimSourceYaml) -> ClaimSource {
    ClaimSource {
        id: source.id,
        resource: source.resource,
        title: source.title,
        digest: source.digest,
        spans: source
            .spans
            .into_iter()
            .map(|span| EvidenceSpan {
                evidence_id: span.evidence_id,
                start_line: span.start_line,
                end_line: span.end_line,
                digest: span.digest,
            })
            .collect(),
    }
}

fn transitions_from_yaml(transitions: Vec<ClaimTransitionYaml>) -> Vec<ClaimTransition> {
    transitions
        .into_iter()
        .map(|transition| ClaimTransition {
            kind: transition.kind,
            at: transition.at,
            by: transition.by,
            reason: transition.reason,
            related_claim_ids: transition.related_claim_ids,
            prior_verification_digest: transition.prior_verification_digest,
            authorization: transition.authorization.map(|authorization| {
                ClaimTransitionAuthorization {
                    challenge_id: authorization.challenge_id,
                    method: authorization.method,
                    mcp_client: authorization.mcp_client,
                }
            }),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Parse / render.
// ---------------------------------------------------------------------------

pub fn parse_claim_markdown(
    tier: &str,
    rel_path: &str,
    contents: &[u8],
) -> Result<Claim, ClaimError> {
    let (frontmatter, body) = split_markdown_frontmatter(contents)?;
    let path_tier = rel_path.split('/').next().unwrap_or("");
    let tier = if tier.is_empty() { path_tier } else { tier };
    if !path_tier.is_empty() && path_tier != "." && path_tier != tier {
        return Err(message(format!(
            "claim path tier {path_tier:?} does not match expected tier {tier:?}"
        )));
    }

    let probe = ProbeFrontmatter::from_map(&parse_frontmatter_map(frontmatter)?)?;
    let claim = if probe.schema == CLAIM_SCHEMA_VERSION {
        parse_legacy_claim_frontmatter(frontmatter, tier, rel_path, body)?
    } else if probe.claim_type == OKF_CLAIM_TYPE {
        parse_okf_claim_frontmatter(frontmatter, tier, rel_path, body)?
    } else {
        return Err(message(format!(
            "claim type must be {OKF_CLAIM_TYPE:?} or legacy schema {CLAIM_SCHEMA_VERSION:?}"
        )));
    };
    validate_claim_path_id(rel_path, &claim.id)?;
    Ok(claim)
}

pub fn split_markdown_frontmatter(contents: &[u8]) -> Result<(&[u8], &[u8]), ClaimError> {
    if !contents.starts_with(b"---\n") {
        return Err(message("claim frontmatter is required"));
    }
    let rest = &contents[4..];
    let closing = rest
        .windows(5)
        .position(|window| window == b"\n---\n")
        .ok_or_else(|| message("claim frontmatter closing marker is required"))?;
    let frontmatter = &rest[..closing];
    let body = &rest[closing + 5..];
    Ok((frontmatter, body))
}

fn parse_legacy_claim_frontmatter(
    frontmatter: &[u8],
    tier: &str,
    rel_path: &str,
    body: &[u8],
) -> Result<Claim, ClaimError> {
    let metadata = LegacyFrontmatterYaml::from_map(&parse_frontmatter_map(frontmatter)?)?;
    let (verified_at, verified_by, verified_digest, verified_alg, verified_key_id, verified_sig) =
        metadata
            .verified
            .map(|verified| {
                (
                    verified.at,
                    verified.by,
                    verified.digest,
                    verified.alg,
                    verified.key_id,
                    verified.sig,
                )
            })
            .unwrap_or_default();
    let claim = Claim {
        schema: metadata.schema,
        claim_type: OKF_CLAIM_TYPE.to_string(),
        id: metadata.id,
        tier: tier.to_string(),
        path: rel_path.to_string(),
        status: metadata.status,
        title: metadata.title,
        description: metadata.description,
        resource: metadata.resource,
        basis: metadata.basis,
        created_at: metadata.created_at,
        created_by: metadata.created_by,
        verified_at,
        verified_by,
        verified_digest,
        verified_alg,
        verified_key_id,
        verified_sig,
        stale_after: metadata.stale_after,
        sources: metadata.sources.into_iter().map(source_from_yaml).collect(),
        evidence_ids: metadata.evidence_ids,
        supporting_claim_ids: metadata.supporting_claim_ids,
        supersedes: metadata.supersedes,
        conflicts_with: metadata.conflicts_with,
        contradicts: Vec::new(),
        tags: metadata.tags,
        transitions: transitions_from_yaml(metadata.transitions),
        body: String::from_utf8_lossy(body).to_string(),
    };
    if let Err(err) = validate_claim(&claim) {
        let digest_error = err.to_string().contains("claim verified.digest");
        if claim.status != CLAIM_STATUS_APPROVED || !digest_error {
            return Err(err);
        }
        let unsigned = Claim {
            verified_at: String::new(),
            verified_by: String::new(),
            verified_digest: String::new(),
            verified_alg: String::new(),
            verified_key_id: String::new(),
            verified_sig: String::new(),
            ..claim.clone()
        };
        if validate_claim(&unsigned).is_err() {
            return Err(err);
        }
    }
    Ok(claim)
}

fn parse_okf_claim_frontmatter(
    frontmatter: &[u8],
    tier: &str,
    rel_path: &str,
    body: &[u8],
) -> Result<Claim, ClaimError> {
    let metadata = OkfFrontmatterYaml::from_map(&parse_frontmatter_map(frontmatter)?)?;
    let mut claim = Claim {
        claim_type: metadata.claim_type,
        id: metadata.zbrain.id,
        tier: metadata.zbrain.tier,
        path: rel_path.to_string(),
        status: metadata.status,
        title: metadata.title,
        description: metadata.description,
        resource: metadata.resource,
        basis: metadata.zbrain.basis,
        stale_after: metadata.stale_after,
        sources: metadata.sources.into_iter().map(source_from_yaml).collect(),
        evidence_ids: metadata.zbrain.evidence_ids,
        supporting_claim_ids: metadata.zbrain.supporting_claim_ids,
        supersedes: metadata.zbrain.supersedes,
        conflicts_with: metadata.zbrain.conflicts_with,
        contradicts: metadata
            .zbrain
            .contradicts
            .into_iter()
            .map(|contradiction| Contradiction {
                claim_id: contradiction.claim_id,
                heuristic: contradiction.heuristic,
            })
            .collect(),
        tags: metadata.tags,
        transitions: transitions_from_yaml(metadata.zbrain.transitions),
        body: String::from_utf8_lossy(body).to_string(),
        ..Claim::default()
    };
    if claim.tier.is_empty() {
        claim.tier = tier.to_string();
    }
    if let Some(generated) = metadata.generated {
        claim.created_at = generated.at;
        claim.created_by = generated.by;
    }
    if let Some(verified) = metadata.verified {
        claim.verified_at = verified.at;
        claim.verified_by = verified.by;
        claim.verified_digest = verified.digest;
        claim.verified_alg = verified.alg;
        claim.verified_key_id = verified.key_id;
        claim.verified_sig = verified.sig;
    }
    if metadata.zbrain.profile != ZBRAIN_TRUSTED_MEMORY_PROFILE {
        return Err(message(format!(
            "zbrain profile must be {ZBRAIN_TRUSTED_MEMORY_PROFILE:?}"
        )));
    }
    if claim.tier != tier {
        return Err(message(format!(
            "claim zbrain tier {:?} does not match path tier {tier:?}",
            claim.tier
        )));
    }
    validate_claim(&claim)?;
    Ok(claim)
}

fn validate_claim_path_id(rel_path: &str, id: &str) -> Result<(), ClaimError> {
    let base = rel_path.rsplit('/').next().unwrap_or(rel_path);
    let base = base.strip_suffix(".md").unwrap_or(base);
    if is_claim_id(base) && base != id {
        return Err(message(format!(
            "claim path id {base:?} does not match frontmatter id {id:?}"
        )));
    }
    Ok(())
}

/// RenderClaimMarkdown: canonical frontmatter + body; digest premise of the
/// whole migration (must stay byte-identical to the Go oracle).
pub fn render_claim_markdown(claim: &Claim) -> Result<Vec<u8>, ClaimError> {
    validate_claim(claim)?;

    let mut zbrain_entries: Vec<(&str, Yaml)> = vec![
        ("profile", Yaml::scalar(ZBRAIN_TRUSTED_MEMORY_PROFILE)),
        ("id", Yaml::scalar(&claim.id)),
        ("tier", Yaml::scalar(&claim.tier)),
        ("basis", Yaml::scalar(&claim.basis)),
    ];
    if !claim.evidence_ids.is_empty() {
        zbrain_entries.push(("evidence_ids", Yaml::string_list(&claim.evidence_ids)));
    }
    if !claim.supporting_claim_ids.is_empty() {
        zbrain_entries.push((
            "supporting_claim_ids",
            Yaml::string_list(&claim.supporting_claim_ids),
        ));
    }
    if !claim.supersedes.is_empty() {
        zbrain_entries.push(("supersedes", Yaml::string_list(&claim.supersedes)));
    }
    if !claim.conflicts_with.is_empty() {
        zbrain_entries.push(("conflicts_with", Yaml::string_list(&claim.conflicts_with)));
    }
    if !claim.contradicts.is_empty() {
        zbrain_entries.push((
            "contradicts",
            Yaml::seq(
                claim
                    .contradicts
                    .iter()
                    .map(|contradiction| {
                        Yaml::map(vec![
                            ("claim_id", Yaml::scalar(&contradiction.claim_id)),
                            ("heuristic", Yaml::scalar(&contradiction.heuristic)),
                        ])
                    })
                    .collect(),
            ),
        ));
    }
    if !claim.transitions.is_empty() {
        zbrain_entries.push(("transitions", transitions_to_yaml(&claim.transitions)));
    }

    let mut metadata: Vec<(&str, Yaml)> = vec![
        ("type", Yaml::scalar(OKF_CLAIM_TYPE)),
        ("title", Yaml::scalar(&claim.title)),
    ];
    if !claim.description.is_empty() {
        metadata.push(("description", Yaml::scalar(&claim.description)));
    }
    if !claim.resource.is_empty() {
        metadata.push(("resource", Yaml::scalar(&claim.resource)));
    }
    if !claim.tags.is_empty() {
        metadata.push(("tags", Yaml::string_list(&claim.tags)));
    }
    if !claim.sources.is_empty() {
        metadata.push(("sources", sources_to_yaml(&claim.sources)));
    }
    if !claim.created_at.is_empty() || !claim.created_by.is_empty() {
        metadata.push((
            "generated",
            Yaml::map(vec![
                ("at", Yaml::scalar(&claim.created_at)),
                ("by", Yaml::scalar(&claim.created_by)),
            ]),
        ));
    }
    if !claim.verified_at.is_empty()
        || !claim.verified_by.is_empty()
        || !claim.verified_digest.is_empty()
        || !claim.verified_alg.is_empty()
        || !claim.verified_key_id.is_empty()
        || !claim.verified_sig.is_empty()
    {
        let mut verified: Vec<(&str, Yaml)> = vec![
            ("at", Yaml::scalar(&claim.verified_at)),
            ("by", Yaml::scalar(&claim.verified_by)),
            ("digest", Yaml::scalar(&claim.verified_digest)),
        ];
        // Legacy claims render byte-identically: the signature keys appear
        // only once a claim is signed, so their digests keep verifying.
        if !claim.verified_alg.is_empty() {
            verified.push(("alg", Yaml::scalar(&claim.verified_alg)));
        }
        if !claim.verified_key_id.is_empty() {
            verified.push(("key_id", Yaml::scalar(&claim.verified_key_id)));
        }
        if !claim.verified_sig.is_empty() {
            verified.push(("sig", Yaml::scalar(&claim.verified_sig)));
        }
        metadata.push(("verified", Yaml::map(verified)));
    }
    metadata.push(("status", Yaml::scalar(&claim.status)));
    if !claim.stale_after.is_empty() {
        metadata.push(("stale_after", Yaml::scalar(&claim.stale_after)));
    }
    metadata.push(("zbrain", Yaml::map(zbrain_entries)));

    Ok(yaml::emit_markdown_document(
        &Yaml::map(metadata),
        &claim.body,
    ))
}

fn sources_to_yaml(sources: &[ClaimSource]) -> Yaml {
    Yaml::seq(
        sources
            .iter()
            .map(|source| {
                let mut entries: Vec<(&str, Yaml)> = vec![
                    ("id", Yaml::scalar(&source.id)),
                    ("resource", Yaml::scalar(&source.resource)),
                ];
                if !source.title.is_empty() {
                    entries.push(("title", Yaml::scalar(&source.title)));
                }
                entries.push(("digest", Yaml::scalar(&source.digest)));
                if !source.spans.is_empty() {
                    entries.push((
                        "spans",
                        Yaml::seq(
                            source
                                .spans
                                .iter()
                                .map(|span| {
                                    Yaml::map(vec![
                                        ("evidence_id", Yaml::scalar(&span.evidence_id)),
                                        ("start_line", yaml_int(span.start_line)),
                                        ("end_line", yaml_int(span.end_line)),
                                        ("digest", Yaml::scalar(&span.digest)),
                                    ])
                                })
                                .collect(),
                        ),
                    ));
                }
                Yaml::map(entries)
            })
            .collect(),
    )
}

fn transitions_to_yaml(transitions: &[ClaimTransition]) -> Yaml {
    Yaml::seq(
        transitions
            .iter()
            .map(|transition| {
                let mut entries: Vec<(&str, Yaml)> = vec![
                    ("kind", Yaml::scalar(&transition.kind)),
                    ("at", Yaml::scalar(&transition.at)),
                    ("by", Yaml::scalar(&transition.by)),
                ];
                if !transition.reason.is_empty() {
                    entries.push(("reason", Yaml::scalar(&transition.reason)));
                }
                if !transition.related_claim_ids.is_empty() {
                    entries.push((
                        "related_claim_ids",
                        Yaml::string_list(&transition.related_claim_ids),
                    ));
                }
                if !transition.prior_verification_digest.is_empty() {
                    entries.push((
                        "prior_verification_digest",
                        Yaml::scalar(&transition.prior_verification_digest),
                    ));
                }
                if let Some(authorization) = &transition.authorization {
                    let mut authorization_entries: Vec<(&str, Yaml)> =
                        vec![("challenge_id", Yaml::scalar(&authorization.challenge_id))];
                    if !authorization.method.is_empty() {
                        authorization_entries.push(("method", Yaml::scalar(&authorization.method)));
                    }
                    if !authorization.mcp_client.is_empty() {
                        authorization_entries
                            .push(("mcp_client", Yaml::scalar(&authorization.mcp_client)));
                    }
                    entries.push(("authorization", Yaml::map(authorization_entries)));
                }
                Yaml::map(entries)
            })
            .collect(),
    )
}

fn yaml_int(value: i64) -> Yaml {
    Yaml::Scalar {
        value: value.to_string(),
        style: YamlStyle::Plain,
    }
}

// ---------------------------------------------------------------------------
// Validation.
// ---------------------------------------------------------------------------

pub fn validate_claim(claim: &Claim) -> Result<(), ClaimError> {
    if !claim.schema.is_empty() && claim.schema != CLAIM_SCHEMA_VERSION {
        return Err(message(format!(
            "claim schema must be {CLAIM_SCHEMA_VERSION:?} when present"
        )));
    }
    if !claim.claim_type.is_empty() && claim.claim_type != OKF_CLAIM_TYPE {
        return Err(message(format!("claim type must be {OKF_CLAIM_TYPE:?}")));
    }
    if !is_claim_id(&claim.id) {
        return Err(message("claim id must match clm_<32 lowercase hex chars>"));
    }
    if !is_known_wiki_tier(&claim.tier) {
        return Err(message(format!(
            "claim tier {:?} is not supported",
            claim.tier
        )));
    }
    if !is_known_claim_status(&claim.status) {
        return Err(message(format!(
            "claim status {:?} is not supported",
            claim.status
        )));
    }
    if claim.title.trim().is_empty() {
        return Err(message("claim title is required"));
    }
    if !is_known_claim_basis(&claim.basis) {
        return Err(message(format!(
            "claim basis {:?} is not supported",
            claim.basis
        )));
    }
    for source in &claim.sources {
        for span in &source.spans {
            if !is_evidence_id(&span.evidence_id)
                || span.start_line < 1
                || span.end_line < span.start_line
            {
                return Err(message(
                    "claim evidence span has invalid evidence or line range",
                ));
            }
            if !span.digest.starts_with("sha256:span-v1:") {
                return Err(message(
                    "claim evidence span digest must use sha256:span-v1:<hex>",
                ));
            }
        }
    }
    if crate::clock::parse_rfc3339(&claim.created_at).is_err() {
        return Err(message("claim generated.at must be RFC3339"));
    }
    if claim.created_by.trim().is_empty() {
        return Err(message("claim generated.by is required"));
    }
    if !claim.verified_at.is_empty()
        || !claim.verified_by.is_empty()
        || !claim.verified_digest.is_empty()
    {
        if crate::clock::parse_rfc3339(&claim.verified_at).is_err() {
            return Err(message("claim verified.at must be RFC3339"));
        }
        if claim.verified_by.trim().is_empty() {
            return Err(message("claim verified.by is required"));
        }
        if claim.verified_by.chars().any(char::is_control) {
            return Err(message(
                "claim verified.by must not contain control characters",
            ));
        }
        if !claim.verified_digest.starts_with("sha256:") {
            return Err(message("claim verified.digest must use sha256:<hex>"));
        }
    }
    let signed = !claim.verified_alg.is_empty()
        || !claim.verified_key_id.is_empty()
        || !claim.verified_sig.is_empty();
    if signed {
        if claim.verified_at.is_empty()
            || claim.verified_by.is_empty()
            || claim.verified_digest.is_empty()
        {
            return Err(message(
                "claim verified signature requires verified.at, by, and digest",
            ));
        }
        if claim.verified_alg != crate::signing::APPROVAL_ALGORITHM {
            return Err(message("claim verified.alg must be \"ed25519\""));
        }
        if !crate::signing::is_approval_key_id(&claim.verified_key_id) {
            return Err(message(
                "claim verified.key_id must be 16 lowercase hex characters",
            ));
        }
        if !crate::signing::is_approval_signature(&claim.verified_sig) {
            return Err(message("claim verified.sig must be base64 of 64 bytes"));
        }
    }
    if !claim.stale_after.is_empty() && crate::clock::parse_rfc3339(&claim.stale_after).is_err() {
        return Err(message("claim stale_after must be RFC3339"));
    }
    for id in &claim.evidence_ids {
        if !is_evidence_id(id) {
            return Err(message(format!(
                "evidence id {id:?} must match evd_<32 lowercase hex chars>"
            )));
        }
    }
    for source in &claim.sources {
        if !source.id.is_empty() && !is_evidence_id(&source.id) {
            return Err(message(format!(
                "source id {:?} must match evd_<32 lowercase hex chars>",
                source.id
            )));
        }
        if !source.digest.is_empty() && !source.digest.starts_with("sha256:") {
            return Err(message("source digest must use sha256:<hex>"));
        }
    }
    for ids in [
        &claim.supporting_claim_ids,
        &claim.supersedes,
        &claim.conflicts_with,
    ] {
        for id in ids {
            if !is_claim_id(id) {
                return Err(message(format!(
                    "related claim id {id:?} must match clm_<32 lowercase hex chars>"
                )));
            }
        }
    }
    for contradiction in &claim.contradicts {
        if !is_claim_id(&contradiction.claim_id) {
            return Err(message(format!(
                "contradiction claim id {:?} must match clm_<32 lowercase hex chars>",
                contradiction.claim_id
            )));
        }
        if !matches!(
            contradiction.heuristic.as_str(),
            CONTRADICTION_NEGATION | CONTRADICTION_VALUE_SWAP | CONTRADICTION_STATUS_CHANGE
        ) {
            return Err(message(format!(
                "contradiction heuristic {:?} is not supported",
                contradiction.heuristic
            )));
        }
    }
    validate_claim_transitions(&claim.transitions)
}

pub fn validate_claim_transitions(transitions: &[ClaimTransition]) -> Result<(), ClaimError> {
    for (index, transition) in transitions.iter().enumerate() {
        validate_claim_transition(transition)
            .map_err(|err| message(format!("claim transition {index}: {err}")))?;
    }
    Ok(())
}

pub fn validate_claim_transition(transition: &ClaimTransition) -> Result<(), ClaimError> {
    if !matches!(
        transition.kind.as_str(),
        CLAIM_TRANSITION_APPROVE | CLAIM_TRANSITION_SUPERSEDE | CLAIM_TRANSITION_REVOKE
    ) {
        return Err(message(format!(
            "claim transition kind {:?} is not supported",
            transition.kind
        )));
    }
    if crate::clock::parse_rfc3339(&transition.at).is_err() {
        return Err(message("claim transition at must be RFC3339"));
    }
    if transition.by.trim().is_empty() {
        return Err(message("claim transition by is required"));
    }
    if !transition.prior_verification_digest.is_empty()
        && !transition.prior_verification_digest.starts_with("sha256:")
    {
        return Err(message(
            "claim transition prior_verification_digest must use sha256:<hex>",
        ));
    }
    validate_claim_transition_authorization(transition.authorization.as_ref())?;
    let mut seen = HashSet::new();
    for id in &transition.related_claim_ids {
        if !is_claim_id(id) {
            return Err(message(format!(
                "claim transition related claim id {id:?} must match clm_<32 lowercase hex chars>"
            )));
        }
        if !seen.insert(id) {
            return Err(message(format!(
                "claim transition related claim id {id:?} is duplicated"
            )));
        }
    }
    Ok(())
}

pub fn validate_claim_transition_authorization(
    authorization: Option<&ClaimTransitionAuthorization>,
) -> Result<(), ClaimError> {
    let Some(authorization) = authorization else {
        return Ok(());
    };
    if !is_challenge_id(&authorization.challenge_id) {
        return Err(message(
            "claim transition authorization challenge id must match chg_<32 lowercase hex chars>",
        ));
    }
    if authorization.method.trim().is_empty() {
        return Err(message("claim transition authorization method is required"));
    }
    if authorization.mcp_client.trim().is_empty() {
        return Err(message(
            "claim transition authorization MCP client is required",
        ));
    }
    Ok(())
}

pub fn validate_claim_approval(claim: &Claim) -> Result<(), ClaimError> {
    validate_claim(claim)?;
    match claim.basis.as_str() {
        CLAIM_BASIS_OWNER => Ok(()),
        CLAIM_BASIS_EVIDENCE => {
            if claim.evidence_ids.is_empty() {
                return Err(message(
                    "evidence-based claims require at least one evidence id before approval",
                ));
            }
            Ok(())
        }
        CLAIM_BASIS_DERIVED => {
            if claim.supporting_claim_ids.is_empty() && claim.evidence_ids.is_empty() {
                return Err(message(
                    "derived claims require supporting claim or evidence ids before approval",
                ));
            }
            Ok(())
        }
        other => Err(message(format!("claim basis {other:?} is not supported"))),
    }
}

// ---------------------------------------------------------------------------
// Digests.
// ---------------------------------------------------------------------------

/// Digest of the current canonical serialization, hashed immediately before
/// preparing a challenge and compared again before applying one.
pub fn claim_canonical_digest(claim: &Claim) -> Result<String, ClaimError> {
    let rendered = render_claim_markdown(claim)?;
    Ok(format!("sha256:{}", sha256_hex(&rendered)))
}

pub fn claim_verification_digest(claim: &Claim) -> Result<String, ClaimError> {
    let unsigned = Claim {
        verified_at: String::new(),
        verified_by: String::new(),
        verified_digest: String::new(),
        verified_alg: String::new(),
        verified_key_id: String::new(),
        verified_sig: String::new(),
        ..claim.clone()
    };
    let rendered = render_claim_markdown(&unsigned)?;
    Ok(format!("sha256:{}", sha256_hex(&rendered)))
}

pub fn verify_claim_digest(claim: &Claim) -> Result<(), ClaimError> {
    if claim.status != CLAIM_STATUS_APPROVED {
        return Ok(());
    }
    if claim.verified_digest.trim().is_empty() {
        return Err(message("approved claim is missing verification digest"));
    }
    let digest = claim_verification_digest(claim)
        .map_err(|err| message(format!("compute verification digest: {err}")))?;
    if digest != claim.verified_digest {
        return Err(message("verification digest mismatch"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Contradiction heuristics (advisory, deterministic, rule-based).
// ---------------------------------------------------------------------------

pub fn detect_contradictions(draft: &Claim, approved_claims: &[Claim]) -> Vec<Contradiction> {
    let mut contradictions = Vec::new();
    let mut seen = HashSet::new();
    for approved in approved_claims {
        if approved.id == draft.id {
            continue;
        }
        let mut heuristics = HashSet::new();
        for (draft_text, approved_text) in [
            (draft.title.as_str(), approved.title.as_str()),
            (draft.body.as_str(), approved.body.as_str()),
        ] {
            if let Some(heuristic) = classify_contradiction(draft_text, approved_text) {
                heuristics.insert(heuristic);
            }
        }
        for heuristic in [
            CONTRADICTION_STATUS_CHANGE,
            CONTRADICTION_NEGATION,
            CONTRADICTION_VALUE_SWAP,
        ] {
            if !heuristics.contains(heuristic)
                || !seen.insert(format!("{}/{}", approved.id, heuristic))
            {
                continue;
            }
            contradictions.push(Contradiction {
                claim_id: approved.id.clone(),
                heuristic: heuristic.to_string(),
            });
        }
    }
    contradictions
}

fn classify_contradiction(draft_text: &str, approved_text: &str) -> Option<&'static str> {
    if detect_status_change(draft_text, approved_text) {
        return Some(CONTRADICTION_STATUS_CHANGE);
    }
    if detect_negation_flip(draft_text, approved_text) {
        return Some(CONTRADICTION_NEGATION);
    }
    if detect_value_swap(draft_text, approved_text) {
        return Some(CONTRADICTION_VALUE_SWAP);
    }
    None
}

fn negator(token: &str) -> bool {
    matches!(
        token,
        "not"
            | "no"
            | "never"
            | "cannot"
            | "cant"
            | "dont"
            | "doesnt"
            | "isnt"
            | "arent"
            | "wont"
            | "without"
    )
}

fn predicate(token: &str) -> bool {
    matches!(
        token,
        "is" | "are" | "uses" | "requires" | "supports" | "has" | "equals" | "defaults"
    )
}

fn status_word(token: &str) -> bool {
    matches!(
        token,
        "deprecated"
            | "obsolete"
            | "active"
            | "current"
            | "recommended"
            | "rejected"
            | "approved"
            | "stable"
            | "experimental"
            | "required"
            | "optional"
            | "enabled"
            | "disabled"
    )
}

fn auxiliary(token: &str) -> bool {
    matches!(
        token,
        "do" | "does"
            | "did"
            | "can"
            | "will"
            | "would"
            | "may"
            | "might"
            | "with"
            | "without"
            | "also"
            | "even"
            | "still"
    )
}

fn contradiction_tokens(text: &str) -> Vec<String> {
    text.to_lowercase()
        .split(|c: char| !(c.is_alphabetic() || c.is_numeric()))
        .filter(|token| !token.is_empty())
        .map(str::to_string)
        .collect()
}

fn equal_token_slices(left: &[String], right: &[String]) -> bool {
    left == right
}

/// Collapse a trailing plural "s" so "supports" and "support" compare equal.
fn stem_contradiction_token(token: &str) -> String {
    if token.len() > 3 && token.ends_with('s') && !token.ends_with("ss") {
        token[..token.len() - 1].to_string()
    } else {
        token.to_string()
    }
}

fn normalize_contradiction_core(tokens: &[String]) -> (Vec<String>, bool) {
    let mut negated = false;
    let mut core = Vec::with_capacity(tokens.len());
    for token in tokens {
        if negator(token) {
            negated = true;
            continue;
        }
        if auxiliary(token) {
            continue;
        }
        core.push(stem_contradiction_token(token));
    }
    if core.is_empty() {
        return (Vec::new(), negated);
    }
    (core, negated)
}

fn detect_negation_flip(draft_text: &str, approved_text: &str) -> bool {
    let draft_tokens = contradiction_tokens(draft_text);
    let approved_tokens = contradiction_tokens(approved_text);
    if draft_tokens.is_empty() || approved_tokens.is_empty() {
        return false;
    }
    let (draft_core, draft_negated) = normalize_contradiction_core(&draft_tokens);
    let (approved_core, approved_negated) = normalize_contradiction_core(&approved_tokens);
    if draft_negated == approved_negated {
        return false;
    }
    if draft_core.is_empty() || approved_core.is_empty() {
        return false;
    }
    equal_token_slices(&draft_core, &approved_core)
}

#[derive(Debug, PartialEq)]
struct ContradictionClause {
    subject: Vec<String>,
    verb: String,
    object: Vec<String>,
}

fn split_contradiction_clause(text: &str) -> Option<ContradictionClause> {
    let tokens = contradiction_tokens(text);
    for (index, token) in tokens.iter().enumerate() {
        if !predicate(token) {
            continue;
        }
        let subject = &tokens[..index];
        let object = &tokens[index + 1..];
        if subject.is_empty() || object.is_empty() || negator(&object[0]) {
            return None;
        }
        return Some(ContradictionClause {
            subject: subject.to_vec(),
            verb: token.clone(),
            object: object.to_vec(),
        });
    }
    None
}

fn detect_value_swap(draft_text: &str, approved_text: &str) -> bool {
    let (Some(draft_clause), Some(approved_clause)) = (
        split_contradiction_clause(draft_text),
        split_contradiction_clause(approved_text),
    ) else {
        return false;
    };
    if draft_clause.verb != approved_clause.verb {
        return false;
    }
    if !equal_token_slices(&draft_clause.subject, &approved_clause.subject) {
        return false;
    }
    !equal_token_slices(&draft_clause.object, &approved_clause.object)
}

fn detect_status_change(draft_text: &str, approved_text: &str) -> bool {
    let (Some(draft_clause), Some(approved_clause)) = (
        split_contradiction_clause(draft_text),
        split_contradiction_clause(approved_text),
    ) else {
        return false;
    };
    if draft_clause.object.len() != 1 || approved_clause.object.len() != 1 {
        return false;
    }
    let draft_status = &draft_clause.object[0];
    let approved_status = &approved_clause.object[0];
    if !status_word(draft_status) || !status_word(approved_status) {
        return false;
    }
    equal_token_slices(&draft_clause.subject, &approved_clause.subject)
        && draft_status != approved_status
}

// ---------------------------------------------------------------------------
// Claim store.
// ---------------------------------------------------------------------------

pub struct ClaimStore {
    pub paths: Paths,
    /// Injected clock for deterministic lifecycle timestamps; defaults to the
    /// system clock.
    pub now: Option<std::sync::Arc<dyn crate::clock::Clock>>,
}

#[derive(Debug)]
pub struct InvalidClaim {
    pub path: String,
    pub error: String,
}

#[derive(Debug, Default)]
pub struct ClaimScan {
    pub claims: Vec<Claim>,
    pub legacy_unindexed: Vec<String>,
    pub invalid: Vec<InvalidClaim>,
}

pub fn is_known_wiki_tier(tier: &str) -> bool {
    WIKI_TIERS.contains(&tier)
}

pub fn is_known_claim_status(status: &str) -> bool {
    matches!(
        status,
        CLAIM_STATUS_DRAFT | CLAIM_STATUS_APPROVED | CLAIM_STATUS_SUPERSEDED | CLAIM_STATUS_REVOKED
    )
}

pub fn is_known_claim_basis(basis: &str) -> bool {
    matches!(
        basis,
        CLAIM_BASIS_OWNER | CLAIM_BASIS_EVIDENCE | CLAIM_BASIS_DERIVED
    )
}

fn is_zbrain_claim_document(contents: &[u8]) -> bool {
    let Ok((frontmatter, _)) = split_markdown_frontmatter(contents) else {
        return false;
    };
    let Ok(map) = parse_frontmatter_map(frontmatter) else {
        return false;
    };
    let Ok(probe) = ProbeFrontmatter::from_map(&map) else {
        return false;
    };
    probe.schema == CLAIM_SCHEMA_VERSION || probe.claim_type == OKF_CLAIM_TYPE
}

impl ClaimStore {
    pub fn new(paths: Paths) -> Self {
        Self { paths, now: None }
    }

    pub fn with_clock(paths: Paths, now: std::sync::Arc<dyn crate::clock::Clock>) -> Self {
        Self {
            paths,
            now: Some(now),
        }
    }

    pub(crate) fn now(&self) -> chrono::DateTime<chrono::Utc> {
        match &self.now {
            Some(clock) => clock.now(),
            None => chrono::Utc::now(),
        }
    }

    pub fn write_draft(&self, workspace: &str, claim: Claim) -> Result<Claim, ClaimError> {
        let _lock = crate::coordination::acquire_workspace_lock(&self.paths, workspace, true)
            .map_err(message)?;
        crate::transition::recover_pending_transition_for_mutation_unlocked(&self.paths, workspace)
            .map_err(|err| message(err.to_string()))?;
        self.write_draft_unlocked(workspace, claim)
    }

    pub(crate) fn write_draft_unlocked(
        &self,
        workspace: &str,
        mut claim: Claim,
    ) -> Result<Claim, ClaimError> {
        let requested_path = claim.path.clone();
        claim.schema = String::new();
        claim.claim_type = OKF_CLAIM_TYPE.to_string();
        claim.status = CLAIM_STATUS_DRAFT.to_string();
        claim.path = String::new();
        claim.tier = claim.tier.trim().to_string();
        claim.verified_at = String::new();
        claim.verified_by = String::new();
        claim.verified_digest = String::new();
        claim.sources = Vec::new();
        validate_claim(&claim)?;

        let approved_claims = self.approved_claims_for_contradictions(workspace)?;
        claim.contradicts = detect_contradictions(&claim, &approved_claims);
        let mut path = self.claim_path(workspace, &claim)?;
        let matches = self.read_canonical_claims_by_id(workspace, &claim.id)?;
        if matches.len() > 1 {
            return Err(duplicate_canonical_claim_error(&claim.id, &matches));
        }
        let existing = if !requested_path.is_empty() {
            match self.read_claim_path(workspace, &requested_path) {
                Ok(existing_claim) => {
                    if matches.len() == 1 && existing_claim.path != matches[0].path {
                        return Err(message(format!(
                            "claim {} already exists at canonical path {:?}; requested path {:?} would duplicate its identity",
                            claim.id, matches[0].path, requested_path
                        )));
                    }
                    Some(existing_claim)
                }
                Err(err) if err.is_not_found() => {
                    if matches.len() == 1 {
                        return Err(message(format!(
                            "claim {} already exists at canonical path {:?}; requested path {:?} would duplicate its identity",
                            claim.id, matches[0].path, requested_path
                        )));
                    }
                    None
                }
                Err(err) => return Err(err),
            }
        } else {
            matches.first().cloned()
        };

        if let Some(existing) = existing {
            if existing.status != CLAIM_STATUS_DRAFT {
                return Err(message(format!(
                    "claim {} is {} and cannot be overwritten in place",
                    claim.id, existing.status
                )));
            }
            claim.path = existing.path.clone();
            path = self.claim_file_path(workspace, &claim)?;
        }

        begin_canonical_mutation_unlocked(&self.paths, workspace)?;
        run_workspace_generation_test_hook(WORKSPACE_GENERATION_HOOK_BEFORE_CANONICAL_WRITE);
        write_claim_atomic(&path, &claim)?;
        claim.path = claim_rel_path(&claim);
        Ok(claim)
    }

    fn approved_claims_for_contradictions(
        &self,
        workspace: &str,
    ) -> Result<Vec<Claim>, ClaimError> {
        let wiki_root = resolve_workspace_path(&self.paths, workspace, "wiki")?;
        match std::fs::symlink_metadata(&wiki_root) {
            Ok(_) => {}
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(source) => return Err(source.into()),
        }
        let scan = self.scan_workspace(workspace)?;
        Ok(scan
            .claims
            .into_iter()
            .filter(|claim| claim.status == CLAIM_STATUS_APPROVED)
            .collect())
    }

    pub fn read(&self, workspace: &str, id: &str) -> Result<Claim, ClaimError> {
        if !is_claim_id(id) {
            return Err(message("claim id must match clm_<32 lowercase hex chars>"));
        }
        let matches = self.read_canonical_claims_by_id(workspace, id)?;
        match matches.len() {
            0 => Err(ClaimError::NotFound),
            1 => Ok(matches.into_iter().next().expect("one match")),
            _ => Err(duplicate_canonical_claim_error(id, &matches)),
        }
    }

    pub fn read_canonical_claims_by_id(
        &self,
        workspace: &str,
        id: &str,
    ) -> Result<Vec<Claim>, ClaimError> {
        if !is_claim_id(id) {
            return Err(message("claim id must match clm_<32 lowercase hex chars>"));
        }
        let workspace_root = validate_workspace(&self.paths, workspace)?;
        let wiki_root = resolve_workspace_path(&self.paths, workspace, "wiki")?;
        let mut matches = match self.read_flat_claims(workspace, id) {
            Ok(matches) => matches,
            Err(err) if err.is_not_found() => Vec::new(),
            Err(err) => return Err(err),
        };
        if !wiki_has_nested_directories(&wiki_root)? {
            matches.sort_by(|left, right| left.path.cmp(&right.path));
            return Ok(matches);
        }
        matches.clear();
        for (path, _name) in walk_markdown_files(&wiki_root)? {
            let workspace_rel = path
                .strip_prefix(&workspace_root)
                .map_err(message)?
                .to_string_lossy()
                .to_string();
            let safe_path = resolve_workspace_path(&self.paths, workspace, &workspace_rel)?;
            let raw = std::fs::read(&safe_path)?;
            if !is_zbrain_claim_document(&raw) {
                continue;
            }
            let rel = path
                .strip_prefix(&wiki_root)
                .map_err(message)?
                .to_string_lossy()
                .to_string();
            let tier = rel.split('/').next().unwrap_or("").to_string();
            let claim = parse_claim_markdown(&tier, &rel, &raw)?;
            if claim.id != id {
                continue;
            }
            matches.push(claim);
        }
        matches.sort_by(|left, right| left.path.cmp(&right.path));
        Ok(matches)
    }

    fn read_flat_claims(&self, workspace: &str, id: &str) -> Result<Vec<Claim>, ClaimError> {
        if !is_claim_id(id) {
            return Err(message("claim id must match clm_<32 lowercase hex chars>"));
        }
        validate_workspace(&self.paths, workspace)?;
        let mut matches = Vec::new();
        for tier in WIKI_TIERS {
            let relative = format!("wiki/{tier}/{id}.md");
            let path = resolve_workspace_path(&self.paths, workspace, &relative)?;
            let contents = match std::fs::read(&path) {
                Ok(contents) => contents,
                Err(source) if source.kind() == std::io::ErrorKind::NotFound => continue,
                Err(source) => return Err(source.into()),
            };
            let rel = format!("{tier}/{id}.md");
            matches.push(parse_claim_markdown(tier, &rel, &contents)?);
        }
        if matches.is_empty() {
            return Err(ClaimError::NotFound);
        }
        Ok(matches)
    }

    fn read_claim_path(&self, workspace: &str, relative: &str) -> Result<Claim, ClaimError> {
        safe_relative_path(relative)?;
        let parts: Vec<&str> = relative.split('/').collect();
        if parts.len() < 2 || !is_known_wiki_tier(parts[0]) || !relative.ends_with(".md") {
            return Err(message(format!("claim path {relative:?} is not safe")));
        }
        let path = resolve_workspace_path(&self.paths, workspace, &format!("wiki/{relative}"))?;
        let contents = std::fs::read(&path).map_err(ClaimError::Io)?;
        parse_claim_markdown(parts[0], relative, &contents)
    }

    pub fn scan_workspace(&self, workspace: &str) -> Result<ClaimScan, ClaimError> {
        self.scan_workspace_inner(workspace, true)
    }

    /// Verified read of every claim in a workspace: the digest, evidence
    /// closure, and support closure rules the index rebuild applies to
    /// approved claims. A claim that fails them is reported in
    /// [`ClaimScan::invalid`] and never appears in [`ClaimScan::claims`].
    pub fn scan_workspace_trusted(&self, workspace: &str) -> Result<ClaimScan, ClaimError> {
        let mut scan = self.scan_workspace_inner(workspace, false)?;
        let (trusted, invalid) = self.validate_trusted_claims(workspace, &scan.claims)?;
        scan.claims = trusted;
        scan.invalid.extend(invalid);
        scan.invalid.sort_by(|left, right| {
            left.path
                .cmp(&right.path)
                .then_with(|| left.error.cmp(&right.error))
        });
        Ok(scan)
    }

    /// The trust rule for indexed claims: an approved claim must carry a
    /// matching verification digest, a verified evidence closure, and a
    /// verified support closure. Non-approved claims pass through unchanged
    /// (drafts are promotion candidates, not trusted material). The index
    /// rebuild, `status`, `memory_status`, and the viewer all use this one
    /// implementation.
    pub(crate) fn validate_trusted_claims(
        &self,
        workspace: &str,
        claims: &[Claim],
    ) -> Result<(Vec<Claim>, Vec<InvalidClaim>), ClaimError> {
        let mut trust_validator = TrustValidator::from_store(self, workspace)?;
        let mut evidence_validator = EvidenceValidator::new(self.paths.clone(), workspace)
            .map_err(|err| message(err.to_string()))?;
        // Load the owner anchor once per call; a missing or invalid key set
        // makes every approved claim untrusted (fail closed), and the error
        // names the fix.
        let anchor = if claims
            .iter()
            .any(|claim| claim.status == CLAIM_STATUS_APPROVED)
        {
            Some(crate::signing::KeyStore::open(&self.paths))
        } else {
            None
        };
        let mut valid_claims = Vec::with_capacity(claims.len());
        let mut invalid_claims: Vec<InvalidClaim> = Vec::new();
        for claim in claims {
            if claim.status != CLAIM_STATUS_APPROVED {
                valid_claims.push(claim.clone());
                continue;
            }
            let signature = match &anchor {
                Some(Ok(store)) => crate::signing::verify_claim_signature(claim, store),
                Some(Err(err)) => Err(err.clone()),
                None => Ok(()),
            }
            .map_err(|err| message(format!("approval signature: {err}")));
            let result = verify_claim_digest(claim)
                .and_then(|()| signature)
                .and_then(|()| validate_claim_evidence(&mut evidence_validator, claim))
                .and_then(|()| {
                    trust_validator
                        .validate_claim_with_support(claim, &mut |support: &Claim| {
                            validate_claim_evidence(&mut evidence_validator, support)
                                .map_err(|err| err.to_string())
                        })
                        .map_err(|err| message(err.to_string()))
                });
            match result {
                Ok(()) => valid_claims.push(claim.clone()),
                Err(err) => invalid_claims.push(InvalidClaim {
                    path: claim.path.clone(),
                    error: err.to_string(),
                }),
            }
        }
        invalid_claims.sort_by(|left, right| {
            left.path
                .cmp(&right.path)
                .then_with(|| left.error.cmp(&right.error))
        });
        Ok((valid_claims, invalid_claims))
    }

    /// Verified single-claim read: [`ClaimStore::read`] plus the trust rule
    /// for approved claims. Repair and owner-ceremony paths keep using `read`
    /// so an owner can still revoke or migrate a tampered claim.
    pub fn read_trusted(&self, workspace: &str, id: &str) -> Result<Claim, ClaimError> {
        let claim = self.read(workspace, id)?;
        if claim.status != CLAIM_STATUS_APPROVED {
            return Ok(claim);
        }
        let (trusted, invalid) =
            self.validate_trusted_claims(workspace, std::slice::from_ref(&claim))?;
        match trusted.into_iter().next() {
            Some(trusted) => Ok(trusted),
            None => Err(message(format!(
                "claim {} is not trusted: {}",
                claim.id,
                invalid
                    .first()
                    .map(|entry| entry.error.as_str())
                    .unwrap_or("unknown reason")
            ))),
        }
    }

    /// Approved claims whose signature does not verify against the anchor.
    /// `doctor` uses this to name the batch re-sign command; a missing anchor
    /// is reported separately, so this returns only signature failures.
    pub fn unsigned_approved_claims(&self, workspace: &str) -> Result<Vec<String>, ClaimError> {
        let store = match crate::signing::KeyStore::open(&self.paths) {
            Ok(store) => store,
            Err(_) => return Ok(Vec::new()),
        };
        let scan = self.scan_workspace_inner(workspace, false)?;
        let mut ids: Vec<String> = scan
            .claims
            .iter()
            .filter(|claim| claim.status == CLAIM_STATUS_APPROVED)
            .filter(|claim| crate::signing::verify_claim_signature(claim, &store).is_err())
            .map(|claim| claim.id.clone())
            .collect();
        ids.sort();
        Ok(ids)
    }

    pub(crate) fn scan_workspace_inner(
        &self,
        workspace: &str,
        verify_digests: bool,
    ) -> Result<ClaimScan, ClaimError> {
        let workspace_root = validate_workspace(&self.paths, workspace)?;
        let wiki_root = resolve_workspace_path(&self.paths, workspace, "wiki")?;
        match std::fs::metadata(&wiki_root) {
            Ok(_) => {}
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                return Err(message(format!("workspace {workspace:?} does not exist")));
            }
            Err(source) => return Err(source.into()),
        }

        let mut scan = ClaimScan::default();
        let mut parsed: Vec<(Claim, String)> = Vec::new();
        let mut claims_by_id: HashMap<String, Vec<(Claim, String)>> = HashMap::new();
        let mut invalid_by_path: HashMap<String, Vec<String>> = HashMap::new();

        for (path, _name) in walk_markdown_files(&wiki_root)? {
            let rel = path
                .strip_prefix(&wiki_root)
                .map_err(message)?
                .to_string_lossy()
                .to_string();
            let workspace_rel = path
                .strip_prefix(&workspace_root)
                .map_err(message)?
                .to_string_lossy()
                .to_string();
            let safe_path = resolve_workspace_path(&self.paths, workspace, &workspace_rel)?;
            let contents = std::fs::read(&safe_path)?;
            if !is_zbrain_claim_document(&contents) {
                scan.legacy_unindexed.push(rel);
                continue;
            }
            let tier = rel.split('/').next().unwrap_or("").to_string();
            let claim = match parse_claim_markdown(&tier, &rel, &contents) {
                Ok(claim) => claim,
                Err(err) => {
                    invalid_by_path
                        .entry(rel.clone())
                        .or_default()
                        .push(err.to_string());
                    continue;
                }
            };
            claims_by_id
                .entry(claim.id.clone())
                .or_default()
                .push((claim.clone(), rel.clone()));
            if verify_digests {
                if let Err(err) = verify_claim_digest(&claim) {
                    invalid_by_path
                        .entry(rel.clone())
                        .or_default()
                        .push(err.to_string());
                }
            }
            parsed.push((claim, rel));
        }

        let mut duplicate_ids: Vec<String> = claims_by_id
            .iter()
            .filter(|(_, claims)| claims.len() > 1)
            .map(|(id, _)| id.clone())
            .collect();
        duplicate_ids.sort();
        for id in duplicate_ids {
            let claims = &claims_by_id[&id];
            let mut paths: Vec<String> = claims.iter().map(|(_, path)| path.clone()).collect();
            paths.sort();
            let reason = format!(
                "duplicate canonical claim ID {id:?} found at paths: {}",
                paths.join(", ")
            );
            for (_, path) in claims {
                invalid_by_path
                    .entry(path.clone())
                    .or_default()
                    .push(reason.clone());
            }
        }

        parsed.sort_by(|left, right| left.1.cmp(&right.1));
        for (claim, path) in &parsed {
            if invalid_by_path
                .get(path)
                .is_some_and(|reasons| !reasons.is_empty())
            {
                continue;
            }
            scan.claims.push(claim.clone());
        }
        let mut invalid_paths: Vec<String> = invalid_by_path.keys().cloned().collect();
        invalid_paths.sort();
        for path in invalid_paths {
            let mut reasons = invalid_by_path[&path].clone();
            reasons.sort();
            scan.invalid.push(InvalidClaim {
                path,
                error: reasons.join("; "),
            });
        }
        scan.legacy_unindexed.sort();
        Ok(scan)
    }

    pub(crate) fn claim_path(&self, workspace: &str, claim: &Claim) -> Result<PathBuf, ClaimError> {
        let relative = format!(
            "wiki/{}/{id_file}.md",
            claim.tier,
            id_file = format!("{}.md", claim.id).replace(".md", "")
        );
        resolve_workspace_path(&self.paths, workspace, &relative).map_err(ClaimError::Boundary)
    }

    pub(crate) fn claim_file_path(
        &self,
        workspace: &str,
        claim: &Claim,
    ) -> Result<PathBuf, ClaimError> {
        if !claim.path.is_empty() {
            if !claim.path.ends_with(".md") {
                return Err(message(format!("claim path {:?} is not safe", claim.path)));
            }
            return resolve_workspace_path(&self.paths, workspace, &format!("wiki/{}", claim.path))
                .map_err(ClaimError::Boundary);
        }
        self.claim_path(workspace, claim)
    }
}

fn duplicate_canonical_claim_error(id: &str, claims: &[Claim]) -> ClaimError {
    let mut paths: Vec<String> = claims.iter().map(|claim| claim.path.clone()).collect();
    paths.sort();
    duplicate_canonical_claim_paths_error(id, &paths)
}

fn duplicate_canonical_claim_paths_error(id: &str, paths: &[String]) -> ClaimError {
    message(format!(
        "duplicate canonical claim ID {id:?} found at paths: {}",
        paths.join(", ")
    ))
}

fn wiki_has_nested_directories(wiki_root: &Path) -> Result<bool, ClaimError> {
    for tier in WIKI_TIERS {
        let tier_root = wiki_root.join(tier);
        let info = match std::fs::symlink_metadata(&tier_root) {
            Ok(info) => info,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => continue,
            Err(source) => return Err(source.into()),
        };
        if info.file_type().is_symlink() || !info.is_dir() {
            return Ok(true);
        }
        let has_nested = std::fs::read_dir(&tier_root)?
            .filter_map(|entry| entry.ok())
            .any(|entry| entry.file_type().map(|t| t.is_dir()).unwrap_or(false));
        if has_nested {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Lexically ordered walk of all .md files under `root` (Go filepath.WalkDir
/// order: entries sorted, directories recursed when reached).
fn walk_markdown_files(root: &Path) -> Result<Vec<(PathBuf, String)>, ClaimError> {
    let mut files = Vec::new();
    visit_markdown(root, root, &mut files)?;
    Ok(files)
}

fn visit_markdown(
    root: &Path,
    current: &Path,
    files: &mut Vec<(PathBuf, String)>,
) -> Result<(), ClaimError> {
    let mut children: Vec<PathBuf> = std::fs::read_dir(current)?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .collect();
    children.sort();
    for child in children {
        let info = std::fs::symlink_metadata(&child)?;
        if info.is_dir() {
            visit_markdown(root, &child, files)?;
            continue;
        }
        if child.extension().is_some_and(|ext| ext == "md") {
            let rel = child
                .strip_prefix(root)
                .map_err(message)?
                .to_string_lossy()
                .to_string();
            files.push((child.clone(), rel));
        }
    }
    Ok(())
}

pub fn append_unique_claim_id(mut ids: Vec<String>, id: &str) -> Vec<String> {
    if !ids.iter().any(|existing| existing == id) {
        ids.push(id.to_string());
    }
    ids
}

pub fn claim_rel_path(claim: &Claim) -> String {
    if !claim.path.is_empty() {
        return claim.path.clone();
    }
    format!("{}/{id}.md", claim.tier, id = claim.id)
}

/// Atomic canonical write: temp file at 0600 in the target directory, rename,
/// then re-assert the mode on the final path.
pub fn write_claim_atomic(path: &Path, claim: &Claim) -> Result<(), ClaimError> {
    let contents = render_claim_markdown(claim)?;
    if let Some(dir) = path.parent() {
        ensure_directory_mode(dir, RUNTIME_DIRECTORY_MODE)?;
    }
    let dir = path.parent().expect("claim path has parent");
    let file_name = path
        .file_name()
        .expect("claim path has file name")
        .to_string_lossy()
        .to_string();
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
                file.write_all(&contents)?;
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
        return Err(message("create claim temporary file: exhausted attempts"));
    };
    let result = (|| -> Result<(), ClaimError> {
        std::fs::rename(&temporary_path, path)?;
        ensure_file_mode(path, RUNTIME_METADATA_MODE)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary_path);
    }
    result
}

// ---------------------------------------------------------------------------
// Tests (port of claim_test.go and the m2-reachable claim_store_test.go set).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::{parse_rfc3339, rfc3339, FixedClock};
    use crate::config::ensure_config;
    use crate::paths::Options;
    use chrono::{TimeZone, Utc};
    use std::os::unix::fs::PermissionsExt;

    fn fixture(name: &str) -> (PathBuf, Paths, FixedClock) {
        let dir = std::env::temp_dir().join(format!("zbrain-claims-{}-{name}", std::process::id()));
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
        (dir, paths, clock)
    }

    fn valid_owner_claim() -> Claim {
        Claim {
            claim_type: OKF_CLAIM_TYPE.to_string(),
            id: "clm_0123456789abcdef0123456789abcdef".to_string(),
            tier: "projects".to_string(),
            status: CLAIM_STATUS_DRAFT.to_string(),
            title: "Owner preference".to_string(),
            basis: CLAIM_BASIS_OWNER.to_string(),
            created_at: "2026-07-30T09:00:00Z".to_string(),
            created_by: "owner".to_string(),
            body: "Body\n".to_string(),
            ..Claim::default()
        }
    }

    fn valid_store_claim(id: &str, basis: &str) -> Claim {
        Claim {
            claim_type: OKF_CLAIM_TYPE.to_string(),
            id: id.to_string(),
            tier: "projects".to_string(),
            status: CLAIM_STATUS_DRAFT.to_string(),
            title: "Store claim".to_string(),
            basis: basis.to_string(),
            created_at: "2026-07-30T09:00:00Z".to_string(),
            created_by: "owner".to_string(),
            body: "Store body\n".to_string(),
            ..Claim::default()
        }
    }

    fn sha256_file(path: &Path) -> String {
        sha256_hex(&std::fs::read(path).unwrap())
    }

    // -- claim_test.go ------------------------------------------------------

    #[test]
    fn claim_id_format() {
        let id = new_claim_id().unwrap();
        assert!(is_claim_id(&id), "{id}");
    }

    #[test]
    fn claim_round_trip_preserves_body_and_metadata() {
        let claim = Claim {
            description: "Trusted ask returns scoped context.".into(),
            resource: "https://example.com/trusted-ask".into(),
            basis: CLAIM_BASIS_EVIDENCE.into(),
            stale_after: "2027-07-30T09:00:00Z".into(),
            evidence_ids: vec!["evd_0123456789abcdef0123456789abcdef".into()],
            supporting_claim_ids: vec!["clm_11111111111111111111111111111111".into()],
            supersedes: vec!["clm_22222222222222222222222222222222".into()],
            conflicts_with: vec!["clm_33333333333333333333333333333333".into()],
            tags: vec!["memory".into(), "trust".into()],
            body: "# Body\n\nKeep this exact markdown body.\n\n```go\nfmt.Println(\"unchanged\")\n```\n".into(),
            ..valid_owner_claim()
        };

        let rendered = render_claim_markdown(&claim).unwrap();
        let rendered = String::from_utf8(rendered).unwrap();
        assert!(
            rendered.contains("type: zbrain.claim")
                && rendered.contains("profile: zbrain.trusted-memory/v1"),
            "rendered claim is not an OKF zbrain concept:\n{rendered}"
        );
        assert!(!rendered.contains("schema: zbrain.claim/v1"));

        let parsed =
            parse_claim_markdown("projects", "projects/trusted-ask.md", rendered.as_bytes())
                .unwrap();
        assert_eq!(parsed.body, claim.body);
        assert_eq!(parsed.id, claim.id);
        assert_eq!(parsed.title, claim.title);
        assert_eq!(parsed.status, claim.status);
        assert_eq!(parsed.basis, claim.basis);
        assert_eq!(parsed.created_at, claim.created_at);
        assert_eq!(parsed.description, claim.description);
        assert_eq!(parsed.resource, claim.resource);
        assert_eq!(parsed.stale_after, claim.stale_after);
        assert_eq!(parsed.tags.join(","), "memory,trust");

        let rendered_again = String::from_utf8(render_claim_markdown(&parsed).unwrap()).unwrap();
        assert_eq!(rendered_again, rendered);
    }

    #[test]
    fn evidence_span_round_trip_and_validation() {
        let mut claim = valid_owner_claim();
        let evidence_id = "evd_0123456789abcdef0123456789abcdef";
        claim.evidence_ids = vec![evidence_id.to_string()];
        claim.sources = vec![ClaimSource {
            id: evidence_id.to_string(),
            resource: "evidence://snapshot".into(),
            title: String::new(),
            digest: format!("sha256:evidence-v1:{}", "a".repeat(64)),
            spans: vec![EvidenceSpan {
                evidence_id: evidence_id.to_string(),
                start_line: 2,
                end_line: 3,
                digest: format!("sha256:span-v1:{}", "b".repeat(64)),
            }],
        }];
        let rendered = render_claim_markdown(&claim).unwrap();
        let parsed =
            parse_claim_markdown("projects", &format!("projects/{}.md", claim.id), &rendered)
                .unwrap();
        assert_eq!(parsed.sources.len(), 1);
        assert_eq!(parsed.sources[0].spans.len(), 1);
        assert_eq!(parsed.sources[0].spans[0].start_line, 2);
        claim.sources[0].spans[0].start_line = 0;
        assert!(validate_claim(&claim).is_err());
    }

    #[test]
    fn claim_verification_digest_round_trip() {
        for body in ["Approved owner body\n", "# Approved\n\nBody\n"] {
            let mut claim = valid_owner_claim();
            claim.status = CLAIM_STATUS_APPROVED.into();
            claim.body = body.into();
            claim.verified_at = "2026-07-30T10:00:00Z".into();
            claim.verified_by = "owner".into();

            let digest = claim_verification_digest(&claim).unwrap();
            claim.verified_digest = digest.clone();

            let rendered = render_claim_markdown(&claim).unwrap();
            let parsed =
                parse_claim_markdown("projects", &format!("projects/{}.md", claim.id), &rendered)
                    .unwrap();
            let got = claim_verification_digest(&parsed).unwrap();
            assert_eq!(got, parsed.verified_digest);
        }
    }

    #[test]
    fn claim_transition_round_trip() {
        let mut claim = valid_owner_claim();
        claim.transitions = vec![
            ClaimTransition {
                kind: CLAIM_TRANSITION_APPROVE.into(),
                at: "2026-07-30T10:00:00Z".into(),
                by: "owner".into(),
                ..ClaimTransition::default()
            },
            ClaimTransition {
                kind: CLAIM_TRANSITION_SUPERSEDE.into(),
                at: "2026-07-30T11:00:00Z".into(),
                by: "owner".into(),
                reason: "corrected scope".into(),
                related_claim_ids: vec!["clm_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into()],
                prior_verification_digest: format!("sha256:{}", "a".repeat(64)),
                ..ClaimTransition::default()
            },
            ClaimTransition {
                kind: CLAIM_TRANSITION_REVOKE.into(),
                at: "2026-07-30T12:00:00Z".into(),
                by: "owner".into(),
                reason: "withdrawn".into(),
                ..ClaimTransition::default()
            },
        ];

        let rendered = String::from_utf8(render_claim_markdown(&claim).unwrap()).unwrap();
        assert!(
            rendered.contains("transitions:") && rendered.contains("prior_verification_digest:")
        );
        let parsed =
            parse_claim_markdown("projects", "projects/claim.md", rendered.as_bytes()).unwrap();
        assert_eq!(parsed.transitions.len(), 3);
        assert_eq!(parsed.transitions[1].kind, CLAIM_TRANSITION_SUPERSEDE);
        assert_eq!(parsed.transitions[1].reason, "corrected scope");
        assert_eq!(
            parsed.transitions[1].related_claim_ids[0],
            "clm_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        );
        assert_eq!(
            parsed.transitions[1].prior_verification_digest,
            format!("sha256:{}", "a".repeat(64))
        );

        let rendered_again = String::from_utf8(render_claim_markdown(&parsed).unwrap()).unwrap();
        assert_eq!(rendered_again, rendered);
    }

    #[test]
    fn claim_verification_digest_includes_transition_history() {
        let mut claim = valid_owner_claim();
        claim.status = CLAIM_STATUS_APPROVED.into();
        let without = claim_verification_digest(&claim).unwrap();

        claim.transitions = vec![ClaimTransition {
            kind: CLAIM_TRANSITION_APPROVE.into(),
            at: "2026-07-30T10:00:00Z".into(),
            by: "owner".into(),
            ..ClaimTransition::default()
        }];
        let with = claim_verification_digest(&claim).unwrap();
        assert_ne!(with, without);

        claim.verified_at = "2026-07-30T10:01:00Z".into();
        claim.verified_by = "different-owner".into();
        claim.verified_digest = format!("sha256:{}", "b".repeat(64));
        let with_attestation = claim_verification_digest(&claim).unwrap();
        assert_eq!(with_attestation, with);
    }

    #[test]
    fn legacy_approved_claim_without_transitions() {
        let mut claim = valid_owner_claim();
        claim.status = CLAIM_STATUS_APPROVED.into();
        claim.verified_at = "2026-07-30T10:00:00Z".into();
        claim.verified_by = "owner".into();
        let digest = claim_verification_digest(&claim).unwrap();
        claim.verified_digest = digest;

        let rendered = String::from_utf8(render_claim_markdown(&claim).unwrap()).unwrap();
        assert!(!rendered.contains("transitions:"));
        let parsed = parse_claim_markdown(
            "projects",
            &format!("projects/{}.md", claim.id),
            rendered.as_bytes(),
        )
        .unwrap();
        assert!(parsed.transitions.is_empty());
        verify_claim_digest(&parsed).unwrap();
    }

    #[test]
    fn claim_transition_validation() {
        let base = ClaimTransition {
            kind: CLAIM_TRANSITION_APPROVE.into(),
            at: "2026-07-30T10:00:00Z".into(),
            by: "owner".into(),
            ..ClaimTransition::default()
        };
        type TransitionCase = (&'static str, Box<dyn Fn(&mut ClaimTransition)>);
        let mutations: Vec<TransitionCase> = vec![
            (
                "unknown kind",
                Box::new(|t: &mut ClaimTransition| t.kind = "publish".into()),
            ),
            (
                "invalid time",
                Box::new(|t: &mut ClaimTransition| t.at = "not-a-time".into()),
            ),
            (
                "empty actor",
                Box::new(|t: &mut ClaimTransition| t.by = "  ".into()),
            ),
            (
                "unsafe related id",
                Box::new(|t: &mut ClaimTransition| t.related_claim_ids = vec!["../outside".into()]),
            ),
        ];
        for (name, mutate) in mutations {
            let mut candidate = base.clone();
            mutate(&mut candidate);
            assert!(validate_claim_transition(&candidate).is_err(), "{name}");
        }
    }

    #[test]
    fn verify_claim_digest_cases() {
        let mut claim = valid_owner_claim();
        claim.status = CLAIM_STATUS_APPROVED.into();
        claim.verified_at = "2026-07-30T10:00:00Z".into();
        claim.verified_by = "owner".into();
        let digest = claim_verification_digest(&claim).unwrap();
        claim.verified_digest = digest;

        type DigestCase = (&'static str, Box<dyn Fn(&mut Claim)>, &'static str);
        let cases: Vec<DigestCase> = vec![
            (
                "tampered body",
                Box::new(|c: &mut Claim| c.body = "Tampered body\n".into()),
                "verification digest mismatch",
            ),
            (
                "tampered title",
                Box::new(|c: &mut Claim| c.title = "Tampered title".into()),
                "verification digest mismatch",
            ),
            (
                "missing digest",
                Box::new(|c: &mut Claim| c.verified_digest = String::new()),
                "missing verification digest",
            ),
            (
                "draft is skipped",
                Box::new(|c: &mut Claim| {
                    c.status = CLAIM_STATUS_DRAFT.into();
                    c.verified_digest = String::new();
                }),
                "",
            ),
            (
                "superseded is skipped",
                Box::new(|c: &mut Claim| {
                    c.status = CLAIM_STATUS_SUPERSEDED.into();
                    c.verified_digest = String::new();
                }),
                "",
            ),
            (
                "revoked is skipped",
                Box::new(|c: &mut Claim| {
                    c.status = CLAIM_STATUS_REVOKED.into();
                    c.verified_digest = String::new();
                }),
                "",
            ),
        ];
        for (name, mutate, want_error) in cases {
            let mut candidate = claim.clone();
            mutate(&mut candidate);
            let result = verify_claim_digest(&candidate);
            if want_error.is_empty() {
                assert!(result.is_ok(), "{name}: {result:?}");
            } else {
                let err = result.unwrap_err().to_string();
                assert!(err.contains(want_error), "{name}: {err}");
            }
        }
    }

    #[test]
    fn claim_parses_legacy_schema() {
        let contents = b"---\nschema: zbrain.claim/v1\nid: clm_0123456789abcdef0123456789abcdef\nstatus: draft\ntitle: Legacy\nbasis: owner\ncreated_at: 2026-07-30T09:00:00Z\ncreated_by: owner\ntags: [legacy]\n---\n\nBody\n";
        let claim = parse_claim_markdown(
            "projects",
            "projects/clm_0123456789abcdef0123456789abcdef.md",
            contents,
        )
        .unwrap();
        assert_eq!(claim.schema, CLAIM_SCHEMA_VERSION);
        assert_eq!(claim.claim_type, OKF_CLAIM_TYPE);
        assert_eq!(claim.id, "clm_0123456789abcdef0123456789abcdef");
    }

    #[test]
    fn claim_validation_rejects_tier_mismatch() {
        let contents = b"---\ntype: zbrain.claim\ntitle: Tier mismatch\nstatus: draft\ngenerated:\n  at: 2026-07-30T09:00:00Z\n  by: owner\nzbrain:\n  profile: zbrain.trusted-memory/v1\n  id: clm_0123456789abcdef0123456789abcdef\n  tier: decisions\n  basis: owner\n---\n\nBody\n";
        let err =
            parse_claim_markdown("projects", "decisions/tier-mismatch.md", contents).unwrap_err();
        assert!(err.to_string().contains("tier"), "{err}");
    }

    #[test]
    fn claim_validation_rejects_filename_id_mismatch() {
        let contents = b"---\ntype: zbrain.claim\ntitle: ID mismatch\nstatus: draft\ngenerated:\n  at: 2026-07-30T09:00:00Z\n  by: owner\nzbrain:\n  profile: zbrain.trusted-memory/v1\n  id: clm_0123456789abcdef0123456789abcdef\n  tier: projects\n  basis: owner\n---\n\nBody\n";
        let err = parse_claim_markdown(
            "projects",
            "projects/clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.md",
            contents,
        )
        .unwrap_err();
        assert!(err.to_string().contains("path id"), "{err}");
    }

    #[test]
    fn claim_validation_rejects_invalid_relations() {
        let mut claim = valid_owner_claim();
        claim.conflicts_with = vec!["not-a-claim-id".into()];
        assert!(validate_claim(&claim).is_err());
    }

    #[test]
    fn claim_validation_rejects_unsupported_status_and_basis() {
        let mut claim = valid_owner_claim();
        claim.status = "published".into();
        assert!(validate_claim(&claim).is_err());
        let mut claim = valid_owner_claim();
        claim.basis = "rumor".into();
        assert!(validate_claim(&claim).is_err());
    }

    #[test]
    fn claim_approval_guards_by_basis() {
        let mut owner = valid_owner_claim();
        owner.basis = CLAIM_BASIS_OWNER.into();
        validate_claim_approval(&owner).unwrap();

        let mut evidence = valid_owner_claim();
        evidence.basis = CLAIM_BASIS_EVIDENCE.into();
        assert!(validate_claim_approval(&evidence).is_err());
        evidence.evidence_ids = vec!["evd_0123456789abcdef0123456789abcdef".into()];
        validate_claim_approval(&evidence).unwrap();

        let mut derived = valid_owner_claim();
        derived.basis = CLAIM_BASIS_DERIVED.into();
        assert!(validate_claim_approval(&derived).is_err());
        derived.supporting_claim_ids = vec!["clm_11111111111111111111111111111111".into()];
        validate_claim_approval(&derived).unwrap();
    }

    #[test]
    fn claim_validation_rejects_bad_created_at() {
        let mut claim = valid_owner_claim();
        claim.created_at = "Mon, 30 Jul 2026 09:00:00 UTC".into();
        assert!(validate_claim(&claim).is_err());
    }

    #[test]
    fn fixture_claims_round_trip_byte_identically() {
        let fixtures = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        for name in ["claim-minimal.md", "claim-full.md", "claim-tricky.md"] {
            let contents = std::fs::read(fixtures.join(name)).unwrap();
            let parsed =
                parse_claim_markdown("projects", &format!("projects/{name}"), &contents).unwrap();
            let rendered = render_claim_markdown(&parsed).unwrap();
            assert_eq!(
                rendered, contents,
                "fixture {name} did not round-trip byte-identically"
            );
        }
    }

    #[test]
    fn fixture_legacy_claim_parses() {
        let path = std::env::current_dir()
            .unwrap()
            .join("tests/fixtures/claim-legacy.md");
        let contents = std::fs::read(path).unwrap();
        let parsed = parse_claim_markdown(
            "projects",
            "projects/clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.md",
            &contents,
        )
        .unwrap();
        assert_eq!(parsed.schema, CLAIM_SCHEMA_VERSION);
        assert_eq!(parsed.id, "clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert_eq!(parsed.tags, vec!["legacy"]);
        assert_eq!(parsed.body, "\nBody\n");
    }

    #[test]
    fn detect_contradictions_heuristics() {
        let approved = |title: &str, body: &str| {
            let mut claim = valid_owner_claim();
            claim.id = "clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into();
            claim.title = title.into();
            claim.body = body.into();
            claim
        };
        struct Case {
            name: &'static str,
            draft_title: &'static str,
            title: &'static str,
            want: Option<&'static str>,
        }
        let cases = vec![
            Case {
                name: "negation flip on title",
                draft_title: "zbrain runs without network calls",
                title: "zbrain runs with network calls",
                want: Some(CONTRADICTION_NEGATION),
            },
            Case {
                name: "value swap on title",
                draft_title: "zbrain uses SQLite for indexes",
                title: "zbrain uses BoltDB for indexes",
                want: Some(CONTRADICTION_VALUE_SWAP),
            },
            Case {
                name: "status change on title",
                draft_title: "Node runtime is deprecated",
                title: "Node runtime is recommended",
                want: Some(CONTRADICTION_STATUS_CHANGE),
            },
            Case {
                name: "unrelated claims do not contradict",
                draft_title: "zbrain indexes live in SQLite",
                title: "Owner preference",
                want: None,
            },
            Case {
                name: "same polarity does not contradict",
                draft_title: "zbrain runs with network calls",
                title: "zbrain runs with network calls",
                want: None,
            },
            Case {
                name: "different subjects do not value swap",
                draft_title: "viewer binds loopback only",
                title: "gateway binds loopback only",
                want: None,
            },
        ];
        for case in cases {
            let mut draft = approved("draft placeholder", "Body\n");
            draft.id = "clm_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into();
            draft.title = case.draft_title.into();
            let got = detect_contradictions(&draft, &[approved(case.title, "Body\n")]);
            match case.want {
                None => assert!(got.is_empty(), "{}: {got:?}", case.name),
                Some(heuristic) => {
                    assert_eq!(got.len(), 1, "{}", case.name);
                    assert_eq!(got[0].claim_id, "clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
                    assert_eq!(got[0].heuristic, heuristic, "{}", case.name);
                }
            }
        }
    }

    #[test]
    fn detect_contradictions_deduplicates_and_skips_self() {
        let mut approved = valid_owner_claim();
        approved.id = "clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into();
        approved.title = "zbrain uses SQLite for indexes".into();
        let mut draft = valid_owner_claim();
        draft.id = approved.id.clone();
        draft.title = "zbrain uses BoltDB for indexes".into();
        assert!(detect_contradictions(&draft, &[approved.clone()]).is_empty());
        draft.id = "clm_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into();
        let got = detect_contradictions(&draft, &[approved.clone(), approved]);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].claim_id, "clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert_eq!(got[0].heuristic, CONTRADICTION_VALUE_SWAP);
    }

    #[test]
    fn contradicts_frontmatter_round_trip_and_validation() {
        let mut claim = valid_owner_claim();
        claim.contradicts = vec![
            Contradiction {
                claim_id: "clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                heuristic: CONTRADICTION_NEGATION.into(),
            },
            Contradiction {
                claim_id: "clm_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
                heuristic: CONTRADICTION_VALUE_SWAP.into(),
            },
        ];
        let rendered = String::from_utf8(render_claim_markdown(&claim).unwrap()).unwrap();
        assert!(rendered.contains("contradicts:") && rendered.contains("heuristic: negation"));
        let parsed = parse_claim_markdown(
            "projects",
            &format!("projects/{}.md", claim.id),
            rendered.as_bytes(),
        )
        .unwrap();
        assert_eq!(parsed.contradicts, claim.contradicts);
        let rendered_again = String::from_utf8(render_claim_markdown(&parsed).unwrap()).unwrap();
        assert_eq!(rendered_again, rendered);

        let digest = claim_verification_digest(&claim).unwrap();
        claim.verified_digest = digest;
        verify_claim_digest(&claim).unwrap();

        let mut invalid = valid_owner_claim();
        invalid.contradicts = vec![Contradiction {
            claim_id: "not-a-claim-id".into(),
            heuristic: CONTRADICTION_NEGATION.into(),
        }];
        assert!(validate_claim(&invalid).is_err());
        let mut invalid_heuristic = valid_owner_claim();
        invalid_heuristic.contradicts = vec![Contradiction {
            claim_id: "clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            heuristic: "vibes".into(),
        }];
        assert!(validate_claim(&invalid_heuristic).is_err());
    }

    // -- claim_store_test.go (m2-reachable subset) ---------------------------

    #[test]
    fn claim_store_does_not_mutate_legacy_markdown() {
        let (dir, paths, _clock) = fixture("legacy");
        let legacy_path = paths
            .workspaces_dir
            .join("research/wiki/projects/legacy.md");
        let legacy = b"# Legacy note\n\nNo claim schema here.\n";
        std::fs::create_dir_all(legacy_path.parent().unwrap()).unwrap();
        std::fs::write(&legacy_path, legacy).unwrap();
        let before = sha256_file(&legacy_path);

        let store = ClaimStore::new(paths.clone());
        let scan = store.scan_workspace("research").unwrap();
        assert!(scan.claims.is_empty());
        assert_eq!(scan.legacy_unindexed, vec!["projects/legacy.md"]);
        assert_eq!(sha256_file(&legacy_path), before);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn claim_store_scan_reports_invalid_claim_without_mutation() {
        let (dir, paths, _clock) = fixture("invalid");
        let claim_path = paths.workspaces_dir.join("research/wiki/projects/bad.md");
        let contents = b"---\nschema: zbrain.claim/v1\nid: bad\nstatus: draft\ntitle: Bad\nbasis: owner\ncreated_at: 2026-07-30T09:00:00Z\ncreated_by: owner\n---\n\nBad\n";
        std::fs::write(&claim_path, contents).unwrap();
        let before = sha256_file(&claim_path);

        let store = ClaimStore::new(paths.clone());
        let scan = store.scan_workspace("research").unwrap();
        assert_eq!(scan.invalid.len(), 1);
        assert_eq!(scan.invalid[0].path, "projects/bad.md");
        assert_eq!(sha256_file(&claim_path), before);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn finalize_approved_claim(claim: &Claim) -> Claim {
        let mut approved = claim.clone();
        approved.status = CLAIM_STATUS_APPROVED.into();
        approved.verified_at = "2026-07-30T09:00:00Z".into();
        approved.verified_by = "owner".into();
        approved.verified_digest = String::new();
        approved.verified_digest = claim_verification_digest(&approved).unwrap();
        crate::signing::sign_test_claim(&mut approved);
        approved
    }

    fn write_canonical_claim(paths: &Paths, claim: &Claim) {
        let path = paths
            .workspaces_dir
            .join("research/wiki")
            .join(&claim.tier)
            .join(format!("{}.md", claim.id));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        write_claim_atomic(&path, claim).unwrap();
    }

    #[test]
    fn claim_store_scan_rejects_tampered_approved_claim() {
        let (dir, paths, _clock) = fixture("tampered");
        let claim = valid_store_claim("clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", CLAIM_BASIS_OWNER);
        write_canonical_claim(&paths, &finalize_approved_claim(&claim));

        let store = ClaimStore::new(paths.clone());
        let claim_path = paths
            .workspaces_dir
            .join("research/wiki/projects/clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.md");
        let contents = String::from_utf8(std::fs::read(&claim_path).unwrap()).unwrap();
        std::fs::write(&claim_path, contents.replace("Store body", "Tampered body")).unwrap();

        let scan = store.scan_workspace("research").unwrap();
        assert!(scan.claims.is_empty());
        assert_eq!(scan.invalid.len(), 1);
        assert_eq!(
            scan.invalid[0].path,
            "projects/clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.md"
        );
        assert!(
            scan.invalid[0]
                .error
                .contains("verification digest mismatch"),
            "{:?}",
            scan.invalid
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn claim_store_rejects_approved_in_place_overwrite() {
        let (dir, paths, _clock) = fixture("overwrite");
        let claim = valid_store_claim("clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", CLAIM_BASIS_OWNER);
        write_canonical_claim(&paths, &finalize_approved_claim(&claim));

        let store = ClaimStore::new(paths.clone());
        let mut mutated = claim.clone();
        mutated.body = "Mutated body\n".into();
        assert!(store.write_draft("research", mutated).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn claim_store_scan_rejects_duplicate_canonical_claim_ids() {
        let (dir, paths, _clock) = fixture("dupscan");
        let id = "clm_44444444444444444444444444444444";
        let mut flat = valid_store_claim(id, CLAIM_BASIS_OWNER);
        flat.title = "Flat duplicate marker".into();
        flat.body = "flat duplicate marker\n".into();
        write_canonical_claim(&paths, &flat);

        let nested_path = "projects/topics/security/clm_44444444444444444444444444444444.md";
        let mut nested = flat.clone();
        nested.title = "Nested duplicate marker".into();
        nested.body = "nested duplicate marker\n".into();
        nested.path = nested_path.into();
        let write_path = paths.workspaces_dir.join("research/wiki").join(nested_path);
        std::fs::create_dir_all(write_path.parent().unwrap()).unwrap();
        write_claim_atomic(&write_path, &nested).unwrap();

        let flat_path = format!("projects/{id}.md");
        let before_flat = sha256_file(&paths.workspaces_dir.join("research/wiki").join(&flat_path));
        let before_nested = sha256_file(&write_path);
        let store = ClaimStore::new(paths.clone());
        let scan = store.scan_workspace("research").unwrap();
        assert!(scan.claims.is_empty());
        assert_eq!(scan.invalid.len(), 2);
        let want_paths = [flat_path.clone(), nested_path.to_string()];
        for (index, invalid) in scan.invalid.iter().enumerate() {
            assert_eq!(invalid.path, want_paths[index]);
            for path in &want_paths {
                assert!(invalid.error.contains(path), "{}", invalid.error);
            }
            assert!(invalid.error.contains(id));
            assert!(invalid.error.contains("duplicate canonical claim ID"));
        }
        assert_eq!(
            sha256_file(&paths.workspaces_dir.join("research/wiki").join(&flat_path)),
            before_flat
        );
        assert_eq!(sha256_file(&write_path), before_nested);

        let trust_scan = store.scan_workspace("research").unwrap();
        assert!(trust_scan.claims.is_empty());
        assert_eq!(trust_scan.invalid.len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn claim_store_alias_filename_duplicate_canonical_id() {
        let (dir, paths, _clock) = fixture("aliasdup");
        let store = ClaimStore::new(paths.clone());
        let id = "clm_aaaaaaaabbbbbbbbccccccccdddddddd";
        let flat = valid_store_claim(id, CLAIM_BASIS_OWNER);
        write_canonical_claim(&paths, &flat);

        let alias_path = "projects/topics/security/alias.md";
        let mut alias = flat.clone();
        alias.path = alias_path.into();
        alias.title = "Alias duplicate".into();
        alias.body = "alias duplicate\n".into();
        let alias_absolute = paths.workspaces_dir.join("research/wiki").join(alias_path);
        std::fs::create_dir_all(alias_absolute.parent().unwrap()).unwrap();
        write_claim_atomic(&alias_absolute, &alias).unwrap();

        let flat_path = format!("projects/{id}.md");
        let flat_absolute = paths.workspaces_dir.join("research/wiki").join(&flat_path);
        let before_flat = sha256_file(&flat_absolute);
        let before_alias = sha256_file(&alias_absolute);

        match store.read("research", id) {
            Err(err) => {
                let err = err.to_string();
                assert!(err.contains("duplicate canonical claim ID"), "{err}");
                assert!(err.contains(id) && err.contains(&flat_path) && err.contains(alias_path));
            }
            Ok(_) => panic!("Read() error = nil, want duplicate-ID rejection"),
        }
        alias.body = "mutated alias duplicate\n".into();
        match store.write_draft("research", alias) {
            Err(err) => {
                let err = err.to_string();
                assert!(err.contains("duplicate canonical claim ID"), "{err}");
                assert!(err.contains(&flat_path) && err.contains(alias_path));
            }
            Ok(_) => panic!("WriteDraft(alias) error = nil, want duplicate-ID rejection"),
        }

        let scan = store.scan_workspace("research").unwrap();
        assert!(scan.claims.is_empty());
        assert_eq!(scan.invalid.len(), 2);
        for invalid in &scan.invalid {
            assert!(invalid.error.contains(id));
            assert!(invalid.error.contains(&flat_path) && invalid.error.contains(alias_path));
        }
        assert_eq!(sha256_file(&flat_absolute), before_flat);
        assert_eq!(sha256_file(&alias_absolute), before_alias);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn claim_store_workspace_isolation_and_symlink_boundary() {
        let (dir, paths, clock) = fixture("isolation");
        crate::workspace::create_workspace(&paths, "personal", &clock).unwrap();
        let store = ClaimStore::new(paths.clone());
        let claim = valid_store_claim("clm_cccccccccccccccccccccccccccccccc", CLAIM_BASIS_OWNER);
        store.write_draft("research", claim.clone()).unwrap();
        assert!(store.read("personal", &claim.id).is_err());

        let outside = dir.join("outside-claim.md");
        std::fs::write(&outside, b"outside\n").unwrap();
        let escape_path = paths
            .workspaces_dir
            .join("research/wiki/axioms")
            .join(format!("{}.md", claim.id));
        std::os::unix::fs::symlink(&outside, &escape_path).unwrap();
        assert!(store.read("research", &claim.id).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn claim_store_dirty_barrier_leaves_canonical_tree_unchanged() {
        let (dir, paths, _clock) = fixture("dirtybarrier");
        let mut dirty_paths = paths.clone();
        dirty_paths.indexes_dir = dir.join("indexes-blocker");
        std::fs::write(&dirty_paths.indexes_dir, b"not a directory").unwrap();
        let store = ClaimStore::new(dirty_paths.clone());
        let claim = valid_store_claim("clm_dddddddddddddddddddddddddddddddd", CLAIM_BASIS_OWNER);
        let projects_dir = paths.workspaces_dir.join("research/wiki/projects");
        let before = std::fs::read_dir(&projects_dir).unwrap().count();
        assert!(store.write_draft("research", claim).is_err());
        let after = std::fs::read_dir(&projects_dir).unwrap().count();
        assert_eq!(after, before);
        assert!(!dirty_paths.indexes_dir.join("research.dirty").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn claim_store_draft_records_contradiction_metadata() {
        let (dir, paths, _clock) = fixture("contradict");
        let store = ClaimStore::new(paths.clone());

        let mut approved =
            valid_store_claim("clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", CLAIM_BASIS_OWNER);
        approved.title = "zbrain uses SQLite for indexes".into();
        write_canonical_claim(&paths, &finalize_approved_claim(&approved));

        let mut conflicting =
            valid_store_claim("clm_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", CLAIM_BASIS_OWNER);
        conflicting.title = "zbrain uses BoltDB for indexes".into();
        let created = store.write_draft("research", conflicting).unwrap();
        assert_eq!(created.contradicts.len(), 1);
        assert_eq!(created.contradicts[0].claim_id, approved.id);
        assert_eq!(created.contradicts[0].heuristic, CONTRADICTION_VALUE_SWAP);

        let stored = store
            .read("research", "clm_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
            .unwrap();
        assert_eq!(stored.contradicts.len(), 1);
        assert_eq!(stored.contradicts[0].heuristic, CONTRADICTION_VALUE_SWAP);
        assert_eq!(stored.status, CLAIM_STATUS_DRAFT);

        let approved_after = store
            .read("research", "clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .unwrap();
        assert_eq!(approved_after.status, CLAIM_STATUS_APPROVED);
        assert!(approved_after.contradicts.is_empty());

        let mut clean =
            valid_store_claim("clm_cccccccccccccccccccccccccccccccc", CLAIM_BASIS_OWNER);
        clean.title = "Viewer binds loopback only".into();
        let created_clean = store.write_draft("research", clean).unwrap();
        assert!(created_clean.contradicts.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn claim_store_write_draft_rejects_duplicate_identity_across_paths() {
        let (dir, paths, _clock) = fixture("dupidentity");
        let store = ClaimStore::new(paths.clone());
        let claim = valid_store_claim("clm_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", CLAIM_BASIS_OWNER);
        store.write_draft("research", claim.clone()).unwrap();
        let mut requested = claim.clone();
        requested.body = "Different body\n".into();
        requested.path = "projects/other-name.md".into();
        let err = store
            .write_draft("research", requested)
            .unwrap_err()
            .to_string();
        assert!(err.contains("already exists at canonical path"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn claim_store_permissions() {
        let (dir, paths, _clock) = fixture("permissions");
        let store = ClaimStore::new(paths.clone());
        let claim = valid_store_claim("clm_33333333333333333333333333333333", CLAIM_BASIS_OWNER);
        store.write_draft("research", claim).unwrap();
        let claim_path = paths
            .workspaces_dir
            .join("research/wiki/projects/clm_33333333333333333333333333333333.md");
        let mode = std::fs::metadata(&claim_path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, RUNTIME_METADATA_MODE);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rfc3339_clock_round_trip_matches_go() {
        let at = parse_rfc3339("2026-07-30T09:00:00Z").unwrap();
        assert_eq!(rfc3339(at), "2026-07-30T09:00:00Z");
    }
}
