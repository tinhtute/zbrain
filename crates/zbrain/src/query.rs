//! query.rs — port of internal/runtime/query.go: fail-closed trusted query
//! (ask), canonical index binding, contradiction surfacing, temporal recall,
//! and hybrid (RRF) retrieval over the loopback embedding sidecar.

use std::collections::{BTreeSet, HashMap, HashSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::boundary::{resolve_workspace_path, safe_relative_path, validate_workspace};
use crate::claims::{
    claim_verification_digest, parse_claim_markdown, verify_claim_digest, Claim, ClaimSource,
    ClaimStore, Contradiction,
};
use crate::coordination::{
    acquire_workspace_lock, run_workspace_generation_test_hook,
    WORKSPACE_GENERATION_HOOK_TRUSTED_QUERY_AFTER_LOCKING,
};
use crate::embedder::{embedding_text, shares_meaningful_token, EmbeddingStore};
use crate::evidence::{validate_claim_evidence, EvidenceValidator};
use crate::index::{IndexError, IndexStore, IndexedClaim, SearchOptions};
use crate::manifest::TrustInputManifest;
use crate::paths::Paths;
use crate::trust::TrustValidator;
use crate::workspace::resolve_current_workspace;

pub const QUERY_STATUS_READY: &str = "ready";
pub const QUERY_STATUS_GAP: &str = "gap";
pub const QUERY_STATUS_BLOCKED: &str = "blocked";
pub const CLAIM_STATUS_CONFLICT: &str = "conflict";

pub const SCHEMA_VERSION: i64 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryScopes {
    pub primary: String,
    pub includes: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct TrustedQueryOptions {
    pub workspace: String,
    pub includes: Vec<String>,
    pub query: String,
    pub limit: i64,
    /// Embedding enables hybrid retrieval: lexical search merged with vector
    /// search when the workspace has an embedding sidecar. When the database
    /// is missing, behavior is identical to pure lexical search.
    pub embedding: bool,
    pub after: String,
    pub before: String,
    pub as_of: String,
}

// ---------------------------------------------------------------------------
// JSON mirror of Go's TrustedQueryResponse (nil slices marshal as null; empty
// non-nil slices as []).
// ---------------------------------------------------------------------------

/// Go encoding/json float64 formatting: integral values print without a
/// fraction and always in decimal notation (never exponent form for the
/// magnitudes we emit), which ryu-based f64 serialization does not reproduce
/// for small magnitudes (e.g. -3e-6 vs Go's -0.000003).
pub fn go_json_f64<S: serde::Serializer>(value: &f64, serializer: S) -> Result<S::Ok, S::Error> {
    let text = if value.fract() == 0.0 && value.abs() < 1e15 {
        format!("{}", *value as i64)
    } else {
        format!("{value}")
    };
    serde_json::value::RawValue::from_string(text)
        .map_err(serde::ser::Error::custom)?
        .serialize(serializer)
}

#[derive(Debug, Clone, Serialize)]
pub struct QueryClaim {
    pub workspace: String,
    pub id: String,
    pub path: String,
    pub tier: String,
    #[serde(rename = "type")]
    pub claim_type: String,
    pub status: String,
    pub title: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub description: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub stale_after: String,
    #[serde(serialize_with = "go_json_f64")]
    pub score: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sources: Option<Vec<QueryClaimSource>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contradicts: Option<Vec<QueryContradiction>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryClaimSource {
    pub id: String,
    pub resource: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub title: String,
    pub digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spans: Option<Vec<QueryEvidenceSpan>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryEvidenceSpan {
    pub evidence_id: String,
    pub start_line: i64,
    pub end_line: i64,
    pub digest: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct QueryContradiction {
    pub claim_id: String,
    pub heuristic: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct QueryConflict {
    pub workspace: String,
    pub claim_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct QueryGap {
    pub workspace: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct QueryIndexMetadata {
    pub workspace: String,
    pub fresh: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct TrustedQueryResponse {
    pub schema_version: i64,
    pub status: String,
    pub query: String,
    pub scopes: QueryScopesJson,
    pub claims: Option<Vec<QueryClaim>>,
    pub conflicts: Vec<QueryConflict>,
    pub gaps: Option<Vec<QueryGap>>,
    pub promotion_candidates: Option<Vec<QueryClaim>>,
    pub index: Vec<QueryIndexMetadata>,
}

#[derive(Debug, Clone, Serialize)]
pub struct QueryScopesJson {
    pub primary: String,
    // Go initializes Includes as a non-nil empty slice, so it marshals as [].
    pub includes: Vec<String>,
}

pub fn resolve_query_scopes(
    paths: &Paths,
    workspace: &str,
    includes: &[String],
) -> Result<QueryScopes, IndexError> {
    let mut primary = workspace.to_string();
    if primary.is_empty() {
        let current = resolve_current_workspace(paths)?;
        primary = current.workspace;
    }
    validate_workspace(paths, &primary)?;
    let mut seen = std::collections::HashSet::new();
    seen.insert(primary.clone());
    let mut resolved_includes: Vec<String> = Vec::new();
    for include in includes {
        if seen.contains(include) {
            continue;
        }
        validate_workspace(paths, include)?;
        seen.insert(include.clone());
        resolved_includes.push(include.clone());
    }
    Ok(QueryScopes {
        primary,
        includes: resolved_includes,
    })
}

pub fn trusted_query(
    paths: &Paths,
    options: TrustedQueryOptions,
) -> Result<TrustedQueryResponse, IndexError> {
    let temporal = parse_temporal_options(&options)?;
    let scopes = resolve_query_scopes(paths, &options.workspace, &options.includes)?;
    let mut limit = options.limit;
    if limit <= 0 {
        limit = 10;
    }
    let mut response = TrustedQueryResponse {
        schema_version: SCHEMA_VERSION,
        status: QUERY_STATUS_READY.into(),
        query: options.query.clone(),
        scopes: QueryScopesJson {
            primary: scopes.primary.clone(),
            includes: scopes.includes.clone(),
        },
        claims: None,
        conflicts: Vec::new(),
        gaps: None,
        promotion_candidates: None,
        index: Vec::new(),
    };
    let idx = IndexStore::new(paths.clone());
    let mut workspaces = vec![scopes.primary.clone()];
    workspaces.extend(scopes.includes.iter().cloned());
    let mut lock_workspaces = workspaces.clone();
    lock_workspaces.sort();
    let mut locks = Vec::with_capacity(lock_workspaces.len());
    for workspace in &lock_workspaces {
        locks.push(acquire_workspace_lock(paths, workspace, false)?);
    }
    run_workspace_generation_test_hook(WORKSPACE_GENERATION_HOOK_TRUSTED_QUERY_AFTER_LOCKING);
    let mut manifests: HashMap<String, TrustInputManifest> =
        HashMap::with_capacity(workspaces.len());
    for workspace in &workspaces {
        let manifest = idx.check_fresh_unlocked_output(workspace)?;
        manifests.insert(workspace.clone(), manifest);
        response.index.push(QueryIndexMetadata {
            workspace: workspace.clone(),
            fresh: true,
        });
    }
    let trusted_statuses: Vec<String> = if temporal.as_of.is_some() {
        vec![
            crate::claims::CLAIM_STATUS_APPROVED.into(),
            crate::claims::CLAIM_STATUS_SUPERSEDED.into(),
            crate::claims::CLAIM_STATUS_REVOKED.into(),
        ]
    } else {
        vec![crate::claims::CLAIM_STATUS_APPROVED.into()]
    };
    for workspace in &workspaces {
        let manifest = manifests
            .get(workspace)
            .cloned()
            .expect("manifest captured for workspace");
        let approved = idx.search_unlocked_internal(
            workspace,
            SearchOptions {
                query: options.query.clone(),
                statuses: trusted_statuses.clone(),
                limit,
            },
            false,
            true,
        )?;
        let mut approved = approved;
        if options.embedding {
            approved =
                merge_vector_results(paths, &idx, workspace, approved, &options.query, limit)?;
        }
        for claim in approved {
            let Some(canonical) = trusted_claim_at(paths, workspace, &manifest, &claim, &temporal)?
            else {
                continue;
            };
            let mut query_claim = to_query_claim(workspace, &claim);
            query_claim.sources = if canonical.sources.is_empty() {
                None
            } else {
                Some(query_sources(&canonical.sources))
            };
            query_claim.contradicts = if canonical.contradicts.is_empty() {
                None
            } else {
                Some(query_contradictions(&canonical.contradicts))
            };
            if temporal.as_of.is_some()
                && (canonical.status == crate::claims::CLAIM_STATUS_SUPERSEDED
                    || canonical.status == crate::claims::CLAIM_STATUS_REVOKED)
            {
                query_claim.status = crate::claims::CLAIM_STATUS_APPROVED.into();
            }
            response
                .claims
                .get_or_insert_with(Vec::new)
                .push(query_claim);
        }
        let drafts = idx.search_unlocked_internal(
            workspace,
            SearchOptions {
                query: options.query.clone(),
                statuses: vec![crate::claims::CLAIM_STATUS_DRAFT.into()],
                limit,
            },
            false,
            false,
        )?;
        for claim in drafts {
            validate_indexed_claim_binding_internal(
                paths,
                workspace,
                &claim,
                Some(&manifest),
                false,
            )?;
            let canonical = ClaimStore::new(paths.clone()).read(workspace, &claim.id)?;
            if !match_temporal_claim(&canonical, &temporal) {
                continue;
            }
            let mut query_claim = to_query_claim(workspace, &claim);
            query_claim.sources = if canonical.sources.is_empty() {
                None
            } else {
                Some(query_sources(&canonical.sources))
            };
            query_claim.contradicts = if canonical.contradicts.is_empty() {
                None
            } else {
                Some(query_contradictions(&canonical.contradicts))
            };
            if !canonical.contradicts.is_empty() {
                query_claim.status = CLAIM_STATUS_CONFLICT.into();
            }
            response
                .promotion_candidates
                .get_or_insert_with(Vec::new)
                .push(query_claim);
        }
    }
    if let Some(claims) = response.claims.as_mut() {
        sort_query_claims(claims);
    }
    if let Some(candidates) = response.promotion_candidates.as_mut() {
        sort_query_claims(candidates);
    }
    let conflicts = find_query_conflicts(
        paths,
        &idx,
        &manifests,
        &trusted_statuses,
        response.claims.as_deref().unwrap_or(&[]),
        &temporal,
    )?;
    let blocked = !conflicts.is_empty();
    response.conflicts = conflicts;
    if blocked {
        response.status = QUERY_STATUS_BLOCKED.into();
        return Ok(response);
    }
    if response
        .claims
        .as_ref()
        .is_none_or(|claims| claims.is_empty())
    {
        response.status = QUERY_STATUS_GAP.into();
        response.gaps = Some(vec![QueryGap {
            workspace: scopes.primary.clone(),
            reason: "no approved claims matched the query in resolved scopes".into(),
        }]);
        return Ok(response);
    }
    Ok(response)
}

fn query_sources(sources: &[ClaimSource]) -> Vec<QueryClaimSource> {
    sources
        .iter()
        .map(|source| QueryClaimSource {
            id: source.id.clone(),
            resource: source.resource.clone(),
            title: source.title.clone(),
            digest: source.digest.clone(),
            spans: if source.spans.is_empty() {
                None
            } else {
                Some(
                    source
                        .spans
                        .iter()
                        .map(|span| QueryEvidenceSpan {
                            evidence_id: span.evidence_id.clone(),
                            start_line: span.start_line,
                            end_line: span.end_line,
                            digest: span.digest.clone(),
                        })
                        .collect(),
                )
            },
        })
        .collect()
}

fn query_contradictions(contradictions: &[Contradiction]) -> Vec<QueryContradiction> {
    contradictions
        .iter()
        .map(|contradiction| QueryContradiction {
            claim_id: contradiction.claim_id.clone(),
            heuristic: contradiction.heuristic.clone(),
        })
        .collect()
}

/// mergeVectorResults performs hybrid retrieval: it searches the embedding
/// sidecar for vector matches and merges them with the lexical results. The
/// original approved slice is returned unchanged when the sidecar is missing,
/// has no vectors, or holds no vector that shares a meaningful token with the
/// query.
///
/// A vector only counts as evidence when it shares a significant token with the
/// query. loopback-v1 scores unrelated text above zero by hash collision and
/// stopword overlap, so ranking alone would let a miss answer "ready"; the
/// token gate is what keeps readiness fail-closed.
fn merge_vector_results(
    paths: &Paths,
    idx: &IndexStore,
    workspace: &str,
    approved: Vec<IndexedClaim>,
    query: &str,
    limit: i64,
) -> Result<Vec<IndexedClaim>, IndexError> {
    let emb_store = EmbeddingStore::new(paths.clone());
    let Some(vec_ids) = emb_store
        .search_vectors(workspace, query, limit)
        .map_err(|err| IndexError::Message(format!("vector search: {err}")))?
    else {
        return Ok(approved);
    };
    let vec_claims = idx
        .claims_by_ids_unlocked(workspace, &vec_ids)
        .map_err(|err| IndexError::Message(format!("vector claim lookup: {err}")))?;
    if vec_claims.is_empty() {
        return Ok(approved);
    }
    // Reorder the looked-up claims to match the vector similarity rank order.
    let by_id: HashMap<String, IndexedClaim> = vec_claims
        .into_iter()
        .map(|claim| (claim.id.clone(), claim))
        .collect();
    let ordered: Vec<IndexedClaim> = vec_ids
        .iter()
        .filter_map(|id| by_id.get(id).cloned())
        .filter(|claim| {
            shares_meaningful_token(
                query,
                &embedding_text(
                    &claim.title,
                    &claim.description,
                    &claim.indexed_tags,
                    &claim.indexed_body,
                ),
            )
        })
        .collect();
    if ordered.is_empty() {
        return Ok(approved);
    }
    Ok(interleave_claims(approved, ordered, limit))
}

/// interleaveClaims merges two rank-ordered claim lists using Reciprocal Rank
/// Fusion (RRF) with k=60, deduplicating by claim ID and truncating to limit.
/// Scores are reassigned to combined rank positions (0,1,2,…) so a later
/// ascending score sort preserves the RRF order.
pub(crate) fn interleave_claims(
    lexical: Vec<IndexedClaim>,
    vector: Vec<IndexedClaim>,
    limit: i64,
) -> Vec<IndexedClaim> {
    const RRF_K: i64 = 60;
    let mut lex_rank: HashMap<String, i64> = HashMap::with_capacity(lexical.len());
    for (index, claim) in lexical.iter().enumerate() {
        lex_rank.entry(claim.id.clone()).or_insert(index as i64 + 1);
    }
    let mut vec_rank: HashMap<String, i64> = HashMap::with_capacity(vector.len());
    for (index, claim) in vector.iter().enumerate() {
        vec_rank.entry(claim.id.clone()).or_insert(index as i64 + 1);
    }
    let mut claims_by_id: HashMap<String, IndexedClaim> = HashMap::new();
    for claim in lexical {
        claims_by_id.entry(claim.id.clone()).or_insert(claim);
    }
    for claim in vector {
        claims_by_id.entry(claim.id.clone()).or_insert(claim);
    }
    let mut entries: Vec<(IndexedClaim, f64)> = claims_by_id
        .into_values()
        .map(|claim| {
            let mut rrf = 0.0f64;
            if let Some(rank) = lex_rank.get(&claim.id) {
                rrf += 1.0 / (RRF_K + rank) as f64;
            }
            if let Some(rank) = vec_rank.get(&claim.id) {
                rrf += 1.0 / (RRF_K + rank) as f64;
            }
            (claim, rrf)
        })
        .collect();
    entries.sort_by(|(left_claim, left_rrf), (right_claim, right_rrf)| {
        // Deterministic tie-break: smaller lexical rank first, then vector
        // rank, then ID (Go compares presence explicitly).
        let lex_order = match (lex_rank.get(&left_claim.id), lex_rank.get(&right_claim.id)) {
            (Some(li), Some(lj)) => li.cmp(lj),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => std::cmp::Ordering::Equal,
        };
        let vec_order = match (vec_rank.get(&left_claim.id), vec_rank.get(&right_claim.id)) {
            (Some(vi), Some(vj)) => vi.cmp(vj),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => std::cmp::Ordering::Equal,
        };
        right_rrf
            .partial_cmp(left_rrf)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| lex_order)
            .then_with(|| vec_order)
            .then_with(|| left_claim.id.cmp(&right_claim.id))
    });
    let limit = if limit <= 0 { 10 } else { limit };
    entries.truncate(limit as usize);
    entries
        .into_iter()
        .enumerate()
        .map(|(index, (mut claim, _))| {
            claim.score = index as f64;
            claim
        })
        .collect()
}

pub fn validate_indexed_claim_binding(
    paths: &Paths,
    workspace: &str,
    indexed: &IndexedClaim,
    manifest: Option<&TrustInputManifest>,
) -> Result<(), IndexError> {
    validate_indexed_claim_binding_internal(paths, workspace, indexed, manifest, true)
}

fn validate_indexed_claim_binding_internal(
    paths: &Paths,
    workspace: &str,
    indexed: &IndexedClaim,
    manifest: Option<&TrustInputManifest>,
    check_canonical_set: bool,
) -> Result<(), IndexError> {
    let canonical_relative = format!("wiki/{}", indexed.path.replace('\\', "/"));
    let canonical_path =
        resolve_workspace_path(paths, workspace, &canonical_relative).map_err(|err| {
            IndexError::Message(format!("load canonical claim {:?}: {err}", indexed.id))
        })?;
    let contents = std::fs::read(&canonical_path).map_err(|err| {
        IndexError::Message(format!("read canonical claim {:?}: {err}", indexed.id))
    })?;
    let canonical =
        parse_claim_markdown(&indexed.tier, &indexed.path, &contents).map_err(|err| {
            IndexError::Message(format!("parse canonical claim {:?}: {err}", indexed.id))
        })?;
    let mut evidence_validator: Option<EvidenceValidator> = None;
    let mut trust_validator: Option<TrustValidator> = None;
    if let Some(manifest) = manifest {
        let canonical_paths = canonical_claim_paths_from_manifest(manifest, &indexed.id);
        if canonical_paths.len() > 1 {
            return Err(duplicate_canonical_claim_paths_error(
                &indexed.id,
                &canonical_paths,
            ));
        }
        if check_canonical_set {
            let canonical_claims = ClaimStore::new(paths.clone())
                .read_canonical_claims_by_id(workspace, &indexed.id)
                .map_err(|err| {
                    IndexError::Message(format!("load canonical claim set {:?}: {err}", indexed.id))
                })?;
            if canonical_claims.len() > 1 {
                return Err(duplicate_canonical_claim_error(
                    &indexed.id,
                    &canonical_claims,
                ));
            }
        }
    } else {
        let canonical_claims = ClaimStore::new(paths.clone())
            .read_canonical_claims_by_id(workspace, &indexed.id)
            .map_err(|err| {
                IndexError::Message(format!("load canonical claim set {:?}: {err}", indexed.id))
            })?;
        if canonical_claims.len() > 1 {
            return Err(duplicate_canonical_claim_error(
                &indexed.id,
                &canonical_claims,
            ));
        }
    }
    if let Some(manifest) = manifest {
        if !trust_input_manifest_contains_claim(manifest, &canonical_relative) {
            return Err(IndexError::Message(format!(
                "indexed claim {:?} is not present in published trust manifest; run zbrain reindex",
                indexed.id
            )));
        }
    }

    let fields: [(&str, &str, &str); 11] = [
        ("id", &canonical.id, &indexed.id),
        ("path", &canonical.path, &indexed.path),
        ("tier", &canonical.tier, &indexed.tier),
        ("type", &canonical.claim_type, &indexed.claim_type),
        ("status", &canonical.status, &indexed.status),
        ("title", &canonical.title, &indexed.title),
        ("description", &canonical.description, &indexed.description),
        ("stale_after", &canonical.stale_after, &indexed.stale_after),
        ("tags", &canonical.tags.join(" "), &indexed.indexed_tags),
        ("body", &canonical.body, &indexed.indexed_body),
        (
            "verification_digest",
            &canonical.verified_digest,
            &indexed.verification_digest,
        ),
    ];
    for (name, canonical_value, indexed_value) in fields {
        if canonical_value != indexed_value {
            return Err(IndexError::Message(format!(
                "indexed claim {:?} {name} does not match canonical claim",
                indexed.id
            )));
        }
    }
    if canonical.status != crate::claims::CLAIM_STATUS_APPROVED {
        return Ok(());
    }
    verify_claim_digest(&canonical).map_err(|err| {
        IndexError::Message(format!(
            "approved claim {:?} verification failed: {err}",
            indexed.id
        ))
    })?;
    crate::signing::verify_claim_signature_at(paths, &canonical).map_err(|err| {
        IndexError::Message(format!(
            "approved claim {:?} approval signature failed: {err}",
            indexed.id
        ))
    })?;
    if canonical.evidence_ids.is_empty() && canonical.supporting_claim_ids.is_empty() {
        return Ok(());
    }
    if evidence_validator.is_none() {
        evidence_validator = Some(EvidenceValidator::new(paths.clone(), workspace).map_err(
            |err| {
                IndexError::Message(format!(
                    "approved claim {:?} evidence validator is unavailable: {err}",
                    indexed.id
                ))
            },
        )?);
    }
    if !canonical.supporting_claim_ids.is_empty() && trust_validator.is_none() {
        let validator = TrustValidator::from_store(&ClaimStore::new(paths.clone()), workspace)
            .map_err(|err| {
                IndexError::Message(format!(
                    "approved claim {:?} trust validator is unavailable: {err}",
                    indexed.id
                ))
            })?;
        trust_validator = Some(validator);
    }
    if !canonical.evidence_ids.is_empty() {
        let Some(evidence_validator) = evidence_validator.as_mut() else {
            return Err(IndexError::Message(format!(
                "approved claim {:?} evidence validator is unavailable",
                indexed.id
            )));
        };
        validate_claim_evidence(evidence_validator, &canonical).map_err(|err| {
            IndexError::Message(format!(
                "approved claim {:?} evidence validation failed: {err}",
                indexed.id
            ))
        })?;
    }
    if !canonical.supporting_claim_ids.is_empty() {
        let Some(trust_validator) = trust_validator.as_mut() else {
            return Err(IndexError::Message(format!(
                "approved claim {:?} trust validator is unavailable",
                indexed.id
            )));
        };
        // validateSupporting = validateClaimEvidence over the shared evidence
        // validator instance (memoized inside the trust validator).
        let evidence_validator = evidence_validator.as_mut().ok_or_else(|| {
            IndexError::Message(format!(
                "approved claim {:?} evidence validator is unavailable",
                indexed.id
            ))
        })?;
        trust_validator
            .validate_claim_with_support(&canonical, &mut |claim: &Claim| {
                validate_claim_evidence(evidence_validator, claim).map_err(|err| err.to_string())
            })
            .map_err(|err| {
                IndexError::Message(format!(
                    "approved claim {:?} supporting-claim validation failed: {err}",
                    indexed.id
                ))
            })?;
    }
    Ok(())
}

/// Verifies a superseded or revoked claim as it stood when it was approved.
///
/// The lifecycle appends the terminal supersede/revoke transition after the
/// approval digest was recorded, so the recorded digest covers the claim
/// without that transition. Rebuild the approved view, recompute the digest,
/// run the same evidence-closure check the approved path uses, and verify the
/// supporting-claim closure at the as-of instant. Callers fail closed (drop
/// the row) when this returns an error.
fn verify_historical_claim(
    paths: &Paths,
    workspace: &str,
    canonical: &Claim,
    as_of: DateTime<Utc>,
) -> Result<(), String> {
    verify_claim_trust_at(paths, workspace, canonical, as_of)?;
    let mut visiting = HashSet::new();
    visiting.insert(canonical.id.clone());
    let mut verified = HashSet::new();
    verify_support_closure(
        paths,
        workspace,
        canonical,
        as_of,
        &mut visiting,
        &mut verified,
    )
}

/// Verifies one claim as trusted at `as_of`: it was active then, its digest
/// covers the approved content, and its evidence closure verifies.
fn verify_claim_trust_at(
    paths: &Paths,
    workspace: &str,
    claim: &Claim,
    as_of: DateTime<Utc>,
) -> Result<(), String> {
    let filter = TemporalFilter {
        after: None,
        before: None,
        as_of: Some(as_of),
    };
    if !match_temporal_claim(claim, &filter) {
        return Err(format!("claim {:?} was not active at as_of", claim.id));
    }
    if claim.verified_digest.trim().is_empty() {
        return Err(format!(
            "claim {:?} is missing its verification digest",
            claim.id
        ));
    }
    let mut approved = claim.clone();
    if claim.status != crate::claims::CLAIM_STATUS_APPROVED {
        let Some(terminal) = claim.transitions.last() else {
            return Err(format!(
                "claim {:?} is missing its lifecycle transition",
                claim.id
            ));
        };
        if terminal.kind != crate::claims::CLAIM_TRANSITION_SUPERSEDE
            && terminal.kind != crate::claims::CLAIM_TRANSITION_REVOKE
        {
            return Err(format!(
                "claim {:?} terminal transition {:?} is not supersede or revoke",
                claim.id, terminal.kind
            ));
        }
        if terminal.prior_verification_digest != claim.verified_digest {
            return Err(format!(
                "claim {:?} terminal transition does not bind the digest",
                claim.id
            ));
        }
        approved.status = crate::claims::CLAIM_STATUS_APPROVED.to_string();
        approved.transitions.pop();
    }
    let digest = claim_verification_digest(&approved)
        .map_err(|err| format!("compute verification digest for {:?}: {err}", claim.id))?;
    if digest != claim.verified_digest {
        return Err(format!("claim {:?} verification digest mismatch", claim.id));
    }
    crate::signing::verify_claim_signature_at(paths, claim)
        .map_err(|err| format!("claim {:?} approval signature: {err}", claim.id))?;
    if !approved.evidence_ids.is_empty() {
        let mut evidence_validator =
            EvidenceValidator::new(paths.clone(), workspace).map_err(|err| {
                format!(
                    "evidence validator for {:?} is unavailable: {err}",
                    claim.id
                )
            })?;
        validate_claim_evidence(&mut evidence_validator, &approved)
            .map_err(|err| format!("evidence validation for {:?} failed: {err}", claim.id))?;
    }
    Ok(())
}

/// Walks the supporting-claim closure at the as-of instant: every support must
/// have been trusted then, with a verifiable digest and evidence closure.
fn verify_support_closure(
    paths: &Paths,
    workspace: &str,
    claim: &Claim,
    as_of: DateTime<Utc>,
    visiting: &mut HashSet<String>,
    verified: &mut HashSet<String>,
) -> Result<(), String> {
    let mut seen = HashSet::new();
    for id in &claim.supporting_claim_ids {
        if !seen.insert(id.clone()) {
            return Err(format!(
                "claim {:?} has duplicate supporting claim {id:?}",
                claim.id
            ));
        }
        if verified.contains(id) {
            continue;
        }
        if !visiting.insert(id.clone()) {
            return Err(format!("supporting claim cycle at {id:?}"));
        }
        let support = ClaimStore::new(paths.clone())
            .read(workspace, id)
            .map_err(|err| format!("load supporting claim {id:?}: {err}"))?;
        verify_claim_trust_at(paths, workspace, &support, as_of)?;
        verify_support_closure(paths, workspace, &support, as_of, visiting, verified)?;
        visiting.remove(id);
        verified.insert(id.clone());
    }
    Ok(())
}

fn duplicate_canonical_claim_paths_error(id: &str, paths: &[String]) -> IndexError {
    let mut paths = paths.to_vec();
    paths.sort();
    IndexError::Message(format!(
        "duplicate canonical claim ID {id:?} found at paths: {}",
        paths.join(", ")
    ))
}

fn duplicate_canonical_claim_error(id: &str, claims: &[Claim]) -> IndexError {
    let mut paths: Vec<String> = claims.iter().map(|claim| claim.path.clone()).collect();
    paths.sort();
    duplicate_canonical_claim_paths_error(id, &paths)
}

fn canonical_claim_paths_from_manifest(manifest: &TrustInputManifest, id: &str) -> Vec<String> {
    let suffix = format!("/{id}.md");
    let mut paths: Vec<String> = manifest
        .entries
        .iter()
        .filter(|entry| {
            entry.kind == crate::manifest::TRUST_INPUT_KIND_CLAIM
                && entry.path.starts_with("wiki/")
                && entry.path.ends_with(&suffix)
        })
        .map(|entry| entry.path.trim_start_matches("wiki/").to_string())
        .collect();
    paths.sort();
    paths
}

fn trust_input_manifest_contains_claim(manifest: &TrustInputManifest, path: &str) -> bool {
    match manifest
        .entries
        .binary_search_by(|entry| entry.path.as_str().cmp(path))
    {
        Ok(index) => {
            manifest.entries[index].path == path
                && manifest.entries[index].kind == crate::manifest::TRUST_INPUT_KIND_CLAIM
        }
        Err(_) => false,
    }
}

fn to_query_claim(workspace: &str, claim: &IndexedClaim) -> QueryClaim {
    QueryClaim {
        workspace: workspace.to_string(),
        id: claim.id.clone(),
        path: claim.path.clone(),
        tier: claim.tier.clone(),
        claim_type: claim.claim_type.clone(),
        status: claim.status.clone(),
        title: claim.title.clone(),
        description: claim.description.clone(),
        stale_after: claim.stale_after.clone(),
        score: claim.score,
        sources: None,
        contradicts: None,
    }
}

pub(crate) fn sort_query_claims(claims: &mut [QueryClaim]) {
    claims.sort_by(|left, right| {
        left.score
            .partial_cmp(&right.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| left.workspace.cmp(&right.workspace))
            .then_with(|| left.path.cmp(&right.path))
    });
}

/// Loads the canonical claim behind an indexed row and applies the trusted
/// query's per-claim rule: the row must bind to the published manifest, the
/// canonical claim must verify through the approved read path, and it must be
/// trusted at the query instant. Returns `None` when the row is not trusted
/// now. The returned page and the declared conflict targets share this rule,
/// so an unverified or unsigned target can neither block nor unblock.
fn trusted_claim_at(
    paths: &Paths,
    workspace: &str,
    manifest: &TrustInputManifest,
    indexed: &IndexedClaim,
    temporal: &TemporalFilter,
) -> Result<Option<Claim>, IndexError> {
    validate_indexed_claim_binding_internal(paths, workspace, indexed, Some(manifest), false)?;
    let canonical = ClaimStore::new(paths.clone()).read(workspace, &indexed.id)?;
    if !match_temporal_claim(&canonical, temporal) {
        return Ok(None);
    }
    if let Some(as_of) = temporal.as_of {
        let terminal = canonical.status == crate::claims::CLAIM_STATUS_SUPERSEDED
            || canonical.status == crate::claims::CLAIM_STATUS_REVOKED;
        if terminal && verify_historical_claim(paths, workspace, &canonical, as_of).is_err() {
            return Ok(None);
        }
    }
    Ok(Some(canonical))
}

fn record_conflict(
    conflicts: &mut Vec<QueryConflict>,
    seen: &mut HashSet<String>,
    workspace: &str,
    left: &str,
    right: &str,
) {
    let mut ids = vec![left.to_string(), right.to_string()];
    ids.sort();
    let key = format!("{workspace}:{}:{}", ids[0], ids[1]);
    if !seen.insert(key) {
        return;
    }
    conflicts.push(QueryConflict {
        workspace: workspace.to_string(),
        claim_ids: ids,
    });
}

/// Collects the declared conflicts of every returned claim. A target inside
/// the returned page is already trusted by the main loop; a target outside it
/// is looked up by id in the same workspace and must pass the same trust rule
/// before it blocks. Conflicts are declared one-way in the claim format, so
/// only the returned claim's declarations are checked.
fn find_query_conflicts(
    paths: &Paths,
    idx: &IndexStore,
    manifests: &HashMap<String, TrustInputManifest>,
    trusted_statuses: &[String],
    claims: &[QueryClaim],
    temporal: &TemporalFilter,
) -> Result<Vec<QueryConflict>, IndexError> {
    let mut by_workspace: HashMap<String, HashSet<String>> = HashMap::new();
    for claim in claims {
        by_workspace
            .entry(claim.workspace.clone())
            .or_default()
            .insert(claim.id.clone());
    }
    let mut conflicts: Vec<QueryConflict> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut outside: HashMap<String, BTreeSet<String>> = HashMap::new();
    let mut pairs: Vec<(String, String, String)> = Vec::new();
    for query_claim in claims {
        let claim = read_claim_by_path(paths, &query_claim.workspace, &query_claim.path)?;
        if claim.id != query_claim.id {
            return Err(IndexError::Message(format!(
                "query claim {:?} canonical path {:?} contains claim {:?}",
                query_claim.id, query_claim.path, claim.id
            )));
        }
        for other in &claim.conflicts_with {
            let in_page = by_workspace
                .get(&query_claim.workspace)
                .is_some_and(|scope| scope.contains(other));
            if in_page {
                record_conflict(
                    &mut conflicts,
                    &mut seen,
                    &query_claim.workspace,
                    &query_claim.id,
                    other,
                );
                continue;
            }
            outside
                .entry(query_claim.workspace.clone())
                .or_default()
                .insert(other.clone());
            pairs.push((
                query_claim.workspace.clone(),
                query_claim.id.clone(),
                other.clone(),
            ));
        }
    }
    if outside.is_empty() {
        return Ok(conflicts);
    }
    let mut trusted: HashSet<(String, String)> = HashSet::new();
    for (workspace, ids) in outside {
        let Some(manifest) = manifests.get(&workspace) else {
            return Err(IndexError::Message(format!(
                "workspace {workspace:?} has no published trust manifest"
            )));
        };
        let ids: Vec<String> = ids.into_iter().collect();
        let rows = idx.claims_by_ids_with_statuses_unlocked(&workspace, &ids, trusted_statuses)?;
        for row in rows {
            if trusted_claim_at(paths, &workspace, manifest, &row, temporal)?.is_some() {
                trusted.insert((workspace.clone(), row.id));
            }
        }
    }
    for (workspace, declaring, target) in pairs {
        if trusted.contains(&(workspace.clone(), target.clone())) {
            record_conflict(&mut conflicts, &mut seen, &workspace, &declaring, &target);
        }
    }
    Ok(conflicts)
}

// Go ClaimStore.readClaimPath — local re-implementation to keep the claims
// module surface untouched.
fn read_claim_by_path(paths: &Paths, workspace: &str, relative: &str) -> Result<Claim, IndexError> {
    safe_relative_path(relative)?;
    let parts: Vec<&str> = relative.split('/').collect();
    if parts.len() < 2 || !crate::claims::is_known_wiki_tier(parts[0]) || !relative.ends_with(".md")
    {
        return Err(IndexError::Message(format!(
            "claim path {relative:?} is not safe"
        )));
    }
    let path = resolve_workspace_path(paths, workspace, &format!("wiki/{relative}"))?;
    let contents = std::fs::read(&path)?;
    parse_claim_markdown(parts[0], relative, &contents)
        .map_err(|err| IndexError::Message(err.to_string()))
}

#[derive(Debug, Clone, Copy, Default)]
struct TemporalFilter {
    after: Option<DateTime<Utc>>,
    before: Option<DateTime<Utc>>,
    as_of: Option<DateTime<Utc>>,
}

fn parse_rfc3339(value: &str) -> Result<DateTime<Utc>, IndexError> {
    DateTime::parse_from_rfc3339(value)
        .map(|parsed| parsed.with_timezone(&Utc))
        .map_err(|err| IndexError::Message(err.to_string()))
}

/// RFC3339 parse with Go `time.Parse(time.RFC3339, ...)`-shaped error
/// messages (`parsing time "x" as "2006-01-02T15:04:05Z07:00": cannot parse
/// ... as "2006"`, `month out of range`, `extra text: ...`), so user-facing
/// error text matches the Go oracle byte-for-byte.
fn parse_rfc3339_go(value: &str) -> Result<DateTime<Utc>, String> {
    const LAYOUT: &str = "2006-01-02T15:04:05Z07:00";

    struct Cursor<'a> {
        value: &'a str,
        pos: usize,
    }

    impl Cursor<'_> {
        fn fail(&self, element: &str) -> String {
            format!(
                "parsing time {:?} as {:?}: cannot parse {:?} as {:?}",
                self.value,
                LAYOUT,
                &self.value[self.pos..],
                element
            )
        }

        fn digits(&mut self, count: usize, element: &str) -> Result<u32, String> {
            let slice = self
                .value
                .get(self.pos..self.pos + count)
                .ok_or_else(|| self.fail(element))?;
            if !slice.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(self.fail(element));
            }
            self.pos += count;
            slice.parse().map_err(|_| self.fail(element))
        }

        fn literal(&mut self, expected: &str) -> Result<(), String> {
            if self.value[self.pos..].starts_with(expected) {
                self.pos += expected.len();
                Ok(())
            } else {
                Err(self.fail(expected))
            }
        }
    }

    let mut cursor = Cursor { value, pos: 0 };
    let year = cursor.digits(4, "2006")?;
    cursor.literal("-")?;
    let month = cursor.digits(2, "01")?;
    cursor.literal("-")?;
    let day = cursor.digits(2, "02")?;
    cursor.literal("T")?;
    let hour = cursor.digits(2, "15")?;
    cursor.literal(":")?;
    let minute = cursor.digits(2, "04")?;
    cursor.literal(":")?;
    let second = cursor.digits(2, "05")?;
    if matches!(value.as_bytes().get(cursor.pos), Some(b'.') | Some(b',')) {
        let mut end = cursor.pos + 1;
        while matches!(value.as_bytes().get(end), Some(byte) if byte.is_ascii_digit()) {
            end += 1;
        }
        cursor.pos = end;
    }
    let offset_seconds: i32 = match value.as_bytes().get(cursor.pos) {
        Some(b'Z') => {
            cursor.pos += 1;
            0
        }
        Some(sign @ (b'+' | b'-')) => {
            let sign_multiplier: i32 = if *sign == b'+' { 1 } else { -1 };
            cursor.pos += 1;
            let offset_hour = cursor.digits(2, "15")?;
            cursor.literal(":")?;
            let offset_minute = cursor.digits(2, "04")?;
            if offset_hour > 23 {
                return Err(format!(
                    "parsing time {value:?}: time zone offset hour out of range"
                ));
            }
            sign_multiplier * (offset_hour as i32 * 3600 + offset_minute as i32 * 60)
        }
        _ => return Err(cursor.fail("Z07:00")),
    };
    if cursor.pos != value.len() {
        return Err(format!(
            "parsing time {value:?}: extra text: {:?}",
            &value[cursor.pos..]
        ));
    }
    if !(1..=12).contains(&month) {
        return Err(format!("parsing time {value:?}: month out of range"));
    }
    let days_in_month: u32 = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ => {
            let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
            if leap {
                29
            } else {
                28
            }
        }
    };
    if !(1..=days_in_month).contains(&day) {
        return Err(format!("parsing time {value:?}: day out of range"));
    }
    if hour > 23 {
        return Err(format!("parsing time {value:?}: hour out of range"));
    }
    if minute > 59 {
        return Err(format!("parsing time {value:?}: minute out of range"));
    }
    if second > 59 {
        return Err(format!("parsing time {value:?}: second out of range"));
    }
    let offset =
        chrono::FixedOffset::east_opt(offset_seconds).ok_or_else(|| cursor.fail("Z07:00"))?;
    let parsed = match chrono::TimeZone::with_ymd_and_hms(
        &offset,
        year as i32,
        month,
        day,
        hour,
        minute,
        second,
    ) {
        chrono::LocalResult::Single(parsed) => parsed,
        _ => return Err(format!("parsing time {value:?}: day out of range")),
    };
    // Fractional seconds carry no semantic weight for the filters that
    // consume this value; the sub-second part is discarded.
    Ok(parsed.with_timezone(&Utc))
}

fn parse_temporal_options(options: &TrustedQueryOptions) -> Result<TemporalFilter, IndexError> {
    let mut filter = TemporalFilter::default();
    if !options.after.is_empty() {
        filter.after = Some(parse_rfc3339_go(&options.after).map_err(|err| {
            IndexError::Message(format!(
                "invalid after timestamp {:?}: {err}",
                options.after
            ))
        })?);
    }
    if !options.before.is_empty() {
        filter.before = Some(parse_rfc3339_go(&options.before).map_err(|err| {
            IndexError::Message(format!(
                "invalid before timestamp {:?}: {err}",
                options.before
            ))
        })?);
    }
    if !options.as_of.is_empty() {
        filter.as_of = Some(parse_rfc3339_go(&options.as_of).map_err(|err| {
            IndexError::Message(format!(
                "invalid as_of timestamp {:?}: {err}",
                options.as_of
            ))
        })?);
    }
    if let (Some(after), Some(before)) = (filter.after, filter.before) {
        if after > before {
            return Err(IndexError::Message(format!(
                "after timestamp {:?} is after before timestamp {:?}",
                options.after, options.before
            )));
        }
    }
    Ok(filter)
}

fn match_temporal_claim(canonical: &Claim, filter: &TemporalFilter) -> bool {
    if filter.after.is_none() && filter.before.is_none() && filter.as_of.is_none() {
        return true;
    }
    let mut claim_time_str = canonical.verified_at.clone();
    if claim_time_str.is_empty() {
        claim_time_str = canonical.created_at.clone();
    }
    if claim_time_str.is_empty() {
        return false;
    }
    let Ok(claim_time) = parse_rfc3339(&claim_time_str) else {
        return false;
    };

    if let Some(as_of) = filter.as_of {
        if claim_time > as_of {
            return false;
        }
        if !canonical.stale_after.is_empty() {
            let Ok(stale_time) = parse_rfc3339(&canonical.stale_after) else {
                return false;
            };
            if stale_time <= as_of {
                return false;
            }
        }
        if canonical.status == crate::claims::CLAIM_STATUS_SUPERSEDED
            || canonical.status == crate::claims::CLAIM_STATUS_REVOKED
        {
            let mut was_active_at_as_of = false;
            for trans in &canonical.transitions {
                if trans.kind == crate::claims::CLAIM_TRANSITION_SUPERSEDE
                    || trans.kind == crate::claims::CLAIM_TRANSITION_REVOKE
                {
                    let Ok(trans_time) = parse_rfc3339(&trans.at) else {
                        return false;
                    };
                    if trans_time > as_of {
                        was_active_at_as_of = true;
                    } else {
                        return false;
                    }
                }
            }
            if !was_active_at_as_of {
                return false;
            }
        }
    }

    if let Some(after) = filter.after {
        if claim_time < after {
            return false;
        }
    }
    if let Some(before) = filter.before {
        if claim_time > before {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claims::{
        claim_verification_digest, render_claim_markdown, write_claim_atomic, ClaimTransition,
        CLAIM_BASIS_DERIVED, CLAIM_BASIS_EVIDENCE, CLAIM_BASIS_OWNER, CLAIM_STATUS_APPROVED,
        CLAIM_STATUS_DRAFT, CLAIM_TRANSITION_APPROVE, CLAIM_TRANSITION_SUPERSEDE,
        CONTRADICTION_VALUE_SWAP, OKF_CLAIM_TYPE,
    };
    use crate::clock::{rfc3339, FixedClock};
    use crate::embedder::RebuildOptions;
    use crate::index::test_support::{add_store_evidence, sha256_hex};
    use crate::manifest::build_trust_input_manifest;
    use crate::paths::Options;
    use crate::transition::{PendingTransition, PendingTransitionTarget};
    use chrono::TimeZone;
    use std::path::PathBuf;
    use std::sync::Arc;

    fn fixed_query_now() -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 30, 10, 0, 0).unwrap()
    }

    fn query_test_paths(name: &str) -> (PathBuf, Paths) {
        let dir = std::env::temp_dir().join(format!("zbrain-query-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut paths = Paths::resolve(Options {
            cwd: Some(dir.join("project")),
            home_dir: Some(dir.clone()),
            runtime_dir: Some(dir.join(".zbrain")),
        })
        .unwrap();
        paths.key_dir = crate::signing::test_key_dir();
        crate::config::ensure_config(&paths.config_file).unwrap();
        crate::workspace::create_workspace(&paths, "research", &FixedClock::new(fixed_query_now()))
            .unwrap();
        (dir, paths)
    }

    fn query_claim(id: &str, title: &str, basis: &str) -> Claim {
        Claim {
            claim_type: OKF_CLAIM_TYPE.into(),
            id: id.into(),
            tier: "projects".into(),
            status: CLAIM_STATUS_DRAFT.into(),
            title: title.into(),
            basis: basis.into(),
            created_at: rfc3339(fixed_query_now()),
            created_by: "owner".into(),
            tags: vec!["memory".into()],
            body: "query body\n".into(),
            ..Claim::default()
        }
    }

    fn query_claim_store(paths: &Paths) -> ClaimStore {
        ClaimStore::with_clock(paths.clone(), Arc::new(FixedClock::new(fixed_query_now())))
    }

    fn store(paths: &Paths) -> IndexStore {
        IndexStore::new(paths.clone())
    }

    fn search_opts(query: &str, statuses: Vec<&str>, limit: i64) -> SearchOptions {
        SearchOptions {
            query: query.into(),
            statuses: statuses.into_iter().map(str::to_string).collect(),
            limit,
        }
    }

    fn finalize_approved_store_claim(claim: Claim) -> Claim {
        let mut claim = claim;
        claim.status = CLAIM_STATUS_APPROVED.into();
        claim.verified_at = rfc3339(fixed_query_now());
        claim.verified_by = "owner".into();
        claim.verified_digest = String::new();
        claim.verified_digest = claim_verification_digest(&claim).unwrap();
        crate::signing::sign_test_claim(&mut claim);
        claim
    }

    fn forge_trust_freshness_rows(paths: &Paths, workspace: &str) {
        use crate::index::{file_change_token, read_trust_directories, read_trust_input_mtimes};
        use std::os::unix::fs::MetadataExt as _;
        let root = validate_workspace(paths, workspace).unwrap();
        let db_path = store(paths).database_path(workspace).unwrap();
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        let mtimes = read_trust_input_mtimes(&conn).unwrap();
        for path in mtimes.keys() {
            let info = std::fs::symlink_metadata(root.join(path)).unwrap();
            conn.execute(
                "update trust_input_mtimes set modified_at = ?, change_token = ? where path = ?",
                rusqlite::params![
                    info.mtime() * 1_000_000_000 + info.mtime_nsec() as i64,
                    file_change_token(&info),
                    path
                ],
            )
            .unwrap();
        }
        let directories = read_trust_directories(&conn).unwrap();
        for directory in &directories {
            let info = std::fs::symlink_metadata(root.join(&directory.path)).unwrap();
            conn.execute(
                "update trust_directories set modified_at = ?, change_token = ? where path = ?",
                rusqlite::params![
                    info.mtime() * 1_000_000_000 + info.mtime_nsec() as i64,
                    file_change_token(&info),
                    directory.path
                ],
            )
            .unwrap();
        }
    }

    fn binding_probe_claim(id: &str, score: f64) -> QueryClaim {
        QueryClaim {
            workspace: String::new(),
            id: id.to_string(),
            path: String::new(),
            tier: String::new(),
            claim_type: String::new(),
            status: String::new(),
            title: String::new(),
            description: String::new(),
            stale_after: String::new(),
            score,
            sources: None,
            contradicts: None,
        }
    }

    fn claim_ids(response: &TrustedQueryResponse) -> Vec<String> {
        response
            .claims
            .iter()
            .flatten()
            .map(|claim| claim.id.clone())
            .collect()
    }

    #[test]
    fn resolve_scopes_uses_current_and_explicit_includes() {
        let (_dir, paths) = query_test_paths("scopes-current");
        crate::workspace::create_workspace(&paths, "personal", &FixedClock::new(fixed_query_now()))
            .unwrap();
        let scopes = resolve_query_scopes(
            &paths,
            "",
            &["personal".to_string(), "personal".to_string()],
        )
        .unwrap();
        assert_eq!(scopes.primary, "research");
        assert_eq!(scopes.includes, vec!["personal".to_string()]);
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn resolve_query_scopes_rejects_unsafe_missing_and_symlink_scopes() {
        let (_dir, paths) = query_test_paths("scopes-unsafe");
        crate::workspace::create_workspace(&paths, "personal", &FixedClock::new(fixed_query_now()))
            .unwrap();

        for (workspace, includes) in [
            ("../outside", vec![]),
            ("missing", vec![]),
            ("", vec!["".to_string()]),
            ("", vec!["../outside".to_string()]),
            ("", vec!["missing".to_string()]),
        ] {
            assert!(
                resolve_query_scopes(&paths, workspace, &includes).is_err(),
                "workspace={workspace:?} includes={includes:?}"
            );
        }

        std::os::unix::fs::symlink(std::env::temp_dir(), paths.workspaces_dir.join("linked"))
            .unwrap();
        assert!(resolve_query_scopes(&paths, "linked", &[]).is_err());
        assert!(resolve_query_scopes(&paths, "", &["linked".to_string()]).is_err());

        assert!(trusted_query(
            &paths,
            TrustedQueryOptions {
                includes: vec!["missing".into()],
                query: "anything".into(),
                limit: 10,
                ..TrustedQueryOptions::default()
            },
        )
        .is_err());
        assert!(
            paths.indexes_dir.symlink_metadata().is_err(),
            "invalid query scope created indexes directory"
        );
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn trusted_query_fails_closed_when_index_is_stale() {
        let (_dir, paths) = query_test_paths("stale");
        let claim_store = query_claim_store(&paths);
        let mut claim = query_claim(
            "clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "Stale Query Claim",
            CLAIM_BASIS_OWNER,
        );
        claim.body = "stale query body\n".into();
        claim_store.write_draft("research", claim.clone()).unwrap();
        claim_store.approve("research", &claim.id).unwrap();
        store(&paths).rebuild("research").unwrap();
        let claim_path = paths
            .workspaces_dir
            .join("research/wiki/projects")
            .join(format!("{}.md", claim.id));
        let contents = String::from_utf8(std::fs::read(&claim_path).unwrap()).unwrap();
        let contents = contents.replacen("stale query body", "changed stale query body", 1);
        std::fs::write(&claim_path, contents).unwrap();
        let err = trusted_query(
            &paths,
            TrustedQueryOptions {
                query: "stale query".into(),
                limit: 10,
                ..TrustedQueryOptions::default()
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("stale"), "{err}");
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn trusted_query_blocks_pending_transition() {
        let (_dir, paths) = query_test_paths("pending-transition");
        let claim_store = query_claim_store(&paths);
        let claim = query_claim(
            "clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "Pending Query Claim",
            CLAIM_BASIS_OWNER,
        );
        claim_store.write_draft("research", claim.clone()).unwrap();
        claim_store.approve("research", &claim.id).unwrap();
        store(&paths).rebuild("research").unwrap();
        let claim_path = paths
            .workspaces_dir
            .join("research/wiki/projects")
            .join(format!("{}.md", claim.id));
        let before = std::fs::read(&claim_path).unwrap();
        let mut target = before.clone();
        target.extend_from_slice(b"pending\n");
        crate::transition::write_pending_transition(
            &paths,
            "research",
            PendingTransition {
                operation_id: "txn_query".into(),
                kind: CLAIM_TRANSITION_SUPERSEDE.into(),
                workspace: "research".into(),
                targets: vec![PendingTransitionTarget {
                    path: format!("wiki/projects/{}.md", claim.id),
                    preimage_sha256: crate::transition::transition_sha256(&before),
                    target_sha256: crate::transition::transition_sha256(&target),
                    target_bytes: target.clone(),
                }],
            },
        )
        .unwrap();
        let err = trusted_query(
            &paths,
            TrustedQueryOptions {
                query: "pending query".into(),
                limit: 10,
                ..TrustedQueryOptions::default()
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("pending transition"), "{err}");
        assert_eq!(std::fs::read(&claim_path).unwrap(), before);
        assert!(crate::transition::read_pending_transition(&paths, "research").is_ok());
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn trusted_query_fails_closed_when_index_is_rejected() {
        let (_dir, paths) = query_test_paths("rejected");
        let legacy_path = paths
            .workspaces_dir
            .join("research/wiki/projects/legacy.md");
        std::fs::write(&legacy_path, b"legacy rejected input\n").unwrap();
        store(&paths).rebuild("research").unwrap();
        let err = trusted_query(
            &paths,
            TrustedQueryOptions {
                query: "anything".into(),
                limit: 10,
                ..TrustedQueryOptions::default()
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("rejected"), "{err}");
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn unrelated_valid_claim_rejected() {
        let (_dir, paths) = query_test_paths("unrelated-valid");
        let claim_store = query_claim_store(&paths);
        let mut claim = query_claim(
            "clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "Valid Unrelated Claim",
            CLAIM_BASIS_OWNER,
        );
        claim.body = "valid unrelated trusted token\n".into();
        claim_store.write_draft("research", claim.clone()).unwrap();
        claim_store.approve("research", &claim.id).unwrap();
        let legacy_path = paths
            .workspaces_dir
            .join("research/wiki/projects/unrelated-legacy.md");
        std::fs::write(&legacy_path, b"unrelated invalid token\n").unwrap();
        store(&paths).rebuild("research").unwrap();
        let err = trusted_query(
            &paths,
            TrustedQueryOptions {
                query: "valid unrelated".into(),
                limit: 10,
                ..TrustedQueryOptions::default()
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("rejected"), "{err}");
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn dependency_invalidation() {
        for mode in ["revoked", "superseded", "missing"] {
            let (_dir, paths) = query_test_paths(&format!("dependency-{mode}"));
            let claim_store = query_claim_store(&paths);
            let base = query_claim(
                "clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "Base Support",
                CLAIM_BASIS_OWNER,
            );
            let mut middle = query_claim(
                "clm_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "Middle Support",
                CLAIM_BASIS_DERIVED,
            );
            middle.supporting_claim_ids = vec![base.id.clone()];
            let mut dependent = query_claim(
                "clm_cccccccccccccccccccccccccccccccc",
                "Deep Dependent",
                CLAIM_BASIS_DERIVED,
            );
            dependent.supporting_claim_ids = vec![middle.id.clone()];
            dependent.body = "deep dependent trusted token\n".into();
            let mut unrelated = query_claim(
                "clm_dddddddddddddddddddddddddddddddd",
                "Unrelated Trusted",
                CLAIM_BASIS_OWNER,
            );
            unrelated.body = "unrelated trusted token\n".into();
            for claim in [&base, &middle, &dependent, &unrelated] {
                claim_store.write_draft("research", claim.clone()).unwrap();
                claim_store.approve("research", &claim.id).unwrap();
            }
            let initial_summary = store(&paths).rebuild("research").unwrap();
            assert_eq!(
                initial_summary.rebuild_state,
                crate::index::REBUILD_STATUS_CLEAN
            );
            let initial = trusted_query(
                &paths,
                TrustedQueryOptions {
                    query: "deep dependent trusted".into(),
                    limit: 10,
                    ..TrustedQueryOptions::default()
                },
            )
            .unwrap();
            assert_eq!(initial.status, QUERY_STATUS_READY);
            let claims = initial.claims.as_ref().unwrap();
            assert_eq!(claims.len(), 1);
            assert_eq!(claims[0].id, dependent.id);

            let dependent_path = paths
                .workspaces_dir
                .join("research/wiki/projects")
                .join(format!("{}.md", dependent.id));
            let middle_path = paths
                .workspaces_dir
                .join("research/wiki/projects")
                .join(format!("{}.md", middle.id));
            let dependent_before = sha256_hex(&dependent_path);
            let middle_before = sha256_hex(&middle_path);
            let base_path = paths
                .workspaces_dir
                .join("research/wiki/projects")
                .join(format!("{}.md", base.id));
            match mode {
                "revoked" => {
                    claim_store
                        .revoke("research", &base.id, "support withdrawn")
                        .unwrap();
                }
                "superseded" => {
                    let replacement = query_claim(
                        "clm_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                        "Replacement Support",
                        CLAIM_BASIS_OWNER,
                    );
                    claim_store
                        .write_superseding_draft("research", &base.id, replacement)
                        .unwrap();
                    claim_store
                        .approve("research", "clm_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
                        .unwrap();
                }
                _ => {
                    let backup_path = base_path.with_extension("md.bak");
                    std::fs::rename(&base_path, &backup_path).unwrap();
                }
            }

            let summary = store(&paths).rebuild("research").unwrap();
            assert_eq!(
                (
                    summary.rebuild_state.as_str(),
                    summary.invalid,
                    summary.invalid_count
                ),
                (crate::index::REBUILD_STATUS_REJECTED, 2, 2),
                "mode={mode}"
            );
            assert_eq!(summary.invalid_claims.len(), 2);
            assert_eq!(
                summary.invalid_claims[0].path,
                format!("projects/{}.md", middle.id)
            );
            assert_eq!(
                summary.invalid_claims[1].path,
                format!("projects/{}.md", dependent.id)
            );
            for invalid in &summary.invalid_claims {
                assert!(
                    invalid.error.contains(&base.id),
                    "mode={mode}: {}",
                    invalid.error
                );
                assert!(
                    invalid.error.contains(mode),
                    "mode={mode}: {}",
                    invalid.error
                );
            }
            let err = trusted_query(
                &paths,
                TrustedQueryOptions {
                    query: "unrelated trusted".into(),
                    limit: 10,
                    ..TrustedQueryOptions::default()
                },
            )
            .unwrap_err();
            assert!(err.to_string().contains("rejected"), "{err}");
            assert_eq!(sha256_hex(&middle_path), middle_before);
            assert_eq!(sha256_hex(&dependent_path), dependent_before);
            let _ = std::fs::remove_dir_all(&_dir);
        }
    }

    #[test]
    fn evidence_invalidation_and_repair() {
        for mode in ["tampered", "missing"] {
            let (_dir, paths) = query_test_paths(&format!("evidence-{mode}"));
            let evidence = add_store_evidence(&paths, "evidence repair bytes");
            let claim_store = query_claim_store(&paths);
            let mut claim = query_claim(
                "clm_ffffffffffffffffffffffffffffffff",
                "Evidence Repair",
                CLAIM_BASIS_EVIDENCE,
            );
            claim.evidence_ids = vec![evidence.id.clone()];
            claim.body = "evidence repair trusted token\n".into();
            claim_store.write_draft("research", claim.clone()).unwrap();
            claim_store.approve("research", &claim.id).unwrap();
            let initial_summary = store(&paths).rebuild("research").unwrap();
            assert_eq!(
                initial_summary.rebuild_state,
                crate::index::REBUILD_STATUS_CLEAN
            );
            let initial = trusted_query(
                &paths,
                TrustedQueryOptions {
                    query: "evidence repair trusted".into(),
                    limit: 10,
                    ..TrustedQueryOptions::default()
                },
            )
            .unwrap();
            assert_eq!(initial.status, QUERY_STATUS_READY);
            assert_eq!(initial.claims.as_ref().unwrap()[0].id, claim.id);

            let claim_path = paths
                .workspaces_dir
                .join("research/wiki/projects")
                .join(format!("{}.md", claim.id));
            let claim_before = sha256_hex(&claim_path);
            let raw_path = paths
                .workspaces_dir
                .join("research/evidence/sources")
                .join(&evidence.id)
                .join("raw");
            let original_raw = std::fs::read(&raw_path).unwrap();
            let backup_path = raw_path.with_extension("raw.bak");
            if mode == "tampered" {
                use std::os::unix::fs::PermissionsExt;
                let mut permissions = std::fs::metadata(&raw_path).unwrap().permissions();
                permissions.set_mode(0o644);
                std::fs::set_permissions(&raw_path, permissions).unwrap();
                std::fs::write(&raw_path, "x".repeat(original_raw.len())).unwrap();
            } else {
                std::fs::rename(&raw_path, &backup_path).unwrap();
            }

            let summary = store(&paths).rebuild("research").unwrap();
            assert_eq!(
                (
                    summary.rebuild_state.as_str(),
                    summary.invalid,
                    summary.invalid_count
                ),
                (crate::index::REBUILD_STATUS_REJECTED, 1, 1)
            );
            assert!(summary.invalid_claims[0].error.contains(&evidence.id));
            assert!(summary.invalid_claims[0].error.contains("raw"));
            let err = trusted_query(
                &paths,
                TrustedQueryOptions {
                    query: "evidence repair trusted".into(),
                    limit: 10,
                    ..TrustedQueryOptions::default()
                },
            )
            .unwrap_err();
            assert!(err.to_string().contains("rejected"), "{err}");

            if mode == "missing" {
                std::fs::rename(&backup_path, &raw_path).unwrap();
            } else {
                std::fs::write(&raw_path, &original_raw).unwrap();
            }
            let repaired = store(&paths).rebuild("research").unwrap();
            assert_eq!(
                (
                    repaired.rebuild_state.as_str(),
                    repaired.approved,
                    repaired.invalid_count
                ),
                (crate::index::REBUILD_STATUS_CLEAN, 1, 0)
            );
            let response = trusted_query(
                &paths,
                TrustedQueryOptions {
                    query: "evidence repair trusted".into(),
                    limit: 10,
                    ..TrustedQueryOptions::default()
                },
            )
            .unwrap();
            assert_eq!(response.status, QUERY_STATUS_READY);
            assert_eq!(response.claims.as_ref().unwrap()[0].id, claim.id);
            assert_eq!(sha256_hex(&claim_path), claim_before);
            let _ = std::fs::remove_dir_all(&_dir);
        }
    }

    #[test]
    fn trusted_query_fails_closed_when_freshness_rows_forged() {
        let (_dir, paths) = query_test_paths("forged-freshness");
        let evidence = add_store_evidence(&paths, "original trusted evidence");
        let claim_store = query_claim_store(&paths);
        let mut claim = query_claim(
            "clm_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "Forged Freshness Evidence",
            CLAIM_BASIS_EVIDENCE,
        );
        claim.evidence_ids = vec![evidence.id.clone()];
        claim.body = "forged freshness trusted token\n".into();
        claim_store.write_draft("research", claim).unwrap();
        claim_store
            .approve("research", "clm_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
            .unwrap();
        store(&paths).rebuild("research").unwrap();

        let raw_path = paths
            .workspaces_dir
            .join("research/evidence/sources")
            .join(&evidence.id)
            .join("raw");
        let original = std::fs::read(&raw_path).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = std::fs::metadata(&raw_path).unwrap().permissions();
            permissions.set_mode(0o644);
            std::fs::set_permissions(&raw_path, permissions).unwrap();
        }
        std::fs::write(&raw_path, "x".repeat(original.len())).unwrap();

        forge_trust_freshness_rows(&paths, "research");

        store(&paths).check_fresh("research").unwrap();
        let err = trusted_query(
            &paths,
            TrustedQueryOptions {
                query: "forged freshness trusted".into(),
                limit: 10,
                ..TrustedQueryOptions::default()
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains(&evidence.id), "{err}");
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn trusted_query_rejects_approved_claim_outside_published_manifest() {
        let (_dir, paths) = query_test_paths("outside-manifest");
        let claim_store = query_claim_store(&paths);
        let mut published = query_claim(
            "clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "Published Claim",
            CLAIM_BASIS_OWNER,
        );
        published.body = "published manifest trusted token\n".into();
        claim_store.write_draft("research", published).unwrap();
        claim_store
            .approve("research", "clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .unwrap();
        store(&paths).rebuild("research").unwrap();

        let mut injected = query_claim(
            "clm_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "Injected Claim",
            CLAIM_BASIS_OWNER,
        );
        injected.path = format!("projects/{}.md", injected.id);
        injected.status = CLAIM_STATUS_APPROVED.into();
        injected.verified_at = rfc3339(fixed_query_now());
        injected.verified_by = "owner".into();
        injected.transitions = vec![ClaimTransition {
            kind: CLAIM_TRANSITION_APPROVE.into(),
            at: injected.verified_at.clone(),
            by: injected.verified_by.clone(),
            ..ClaimTransition::default()
        }];
        injected.body = "injected manifest trusted token\n".into();
        injected.verified_digest = claim_verification_digest(&injected).unwrap();
        let contents = render_claim_markdown(&injected).unwrap();
        let injected_path = paths
            .workspaces_dir
            .join("research/wiki")
            .join(&injected.path);
        std::fs::write(&injected_path, contents).unwrap();

        let db_path = index_database_path(&store(&paths), "research");
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute(
            "insert into claims(id, path, tier, type, status, title, description, stale_after, tags, body, verification_digest) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rusqlite::params![
                injected.id,
                injected.path,
                injected.tier,
                OKF_CLAIM_TYPE,
                injected.status,
                injected.title,
                injected.description,
                injected.stale_after,
                injected.tags.join(" "),
                injected.body,
                injected.verified_digest,
            ],
        )
        .unwrap();
        drop(conn);

        forge_trust_freshness_rows(&paths, "research");

        store(&paths).check_fresh("research").unwrap();
        let err = trusted_query(
            &paths,
            TrustedQueryOptions {
                query: "injected manifest trusted".into(),
                limit: 10,
                ..TrustedQueryOptions::default()
            },
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("published trust manifest"),
            "{err}"
        );
        let _ = std::fs::remove_dir_all(&_dir);
    }

    fn index_database_path(idx: &crate::index::IndexStore, workspace: &str) -> PathBuf {
        idx.database_path(workspace).unwrap()
    }

    #[test]
    fn trusted_query_fails_closed_when_index_is_dirty() {
        let (_dir, paths) = query_test_paths("dirty");
        store(&paths).rebuild("research").unwrap();
        store(&paths).mark_dirty("research").unwrap();
        let err = trusted_query(
            &paths,
            TrustedQueryOptions {
                query: "anything".into(),
                limit: 10,
                ..TrustedQueryOptions::default()
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("dirty"), "{err}");
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn trusted_query_fails_closed_when_index_is_missing() {
        let (_dir, paths) = query_test_paths("missing-index");
        let err = trusted_query(
            &paths,
            TrustedQueryOptions {
                query: "anything".into(),
                limit: 10,
                ..TrustedQueryOptions::default()
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("does not exist"), "{err}");
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn trusted_query_returns_approved_claims_and_promotion_candidates_separately() {
        let (_dir, paths) = query_test_paths("separate");
        let claim_store = query_claim_store(&paths);
        let mut approved = query_claim(
            "clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "Approved Retrieval",
            CLAIM_BASIS_OWNER,
        );
        approved.body = "local durable memory answer\n".into();
        claim_store
            .write_draft("research", approved.clone())
            .unwrap();
        claim_store.approve("research", &approved.id).unwrap();
        let mut draft = query_claim(
            "clm_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "Draft Retrieval",
            CLAIM_BASIS_OWNER,
        );
        draft.body = "local durable memory draft candidate\n".into();
        claim_store.write_draft("research", draft.clone()).unwrap();
        store(&paths).rebuild("research").unwrap();

        let response = trusted_query(
            &paths,
            TrustedQueryOptions {
                query: "local durable".into(),
                limit: 10,
                ..TrustedQueryOptions::default()
            },
        )
        .unwrap();
        assert_eq!(response.status, QUERY_STATUS_READY);
        let claims = response.claims.as_ref().unwrap();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].id, approved.id);
        assert_eq!(claims[0].claim_type, OKF_CLAIM_TYPE);
        let candidates = response.promotion_candidates.as_ref().unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].id, draft.id);
        assert_eq!(claims[0].status, CLAIM_STATUS_APPROVED);
        assert_eq!(candidates[0].status, CLAIM_STATUS_DRAFT);
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn canonical_index_binding_rejects_duplicate_canonical_claim_id() {
        let (_dir, paths) = query_test_paths("binding-duplicate");
        let claim_store = query_claim_store(&paths);
        let id = "clm_88888888888888888888888888888888";
        let mut flat = query_claim(id, "Flat duplicate query marker", CLAIM_BASIS_OWNER);
        flat.body = "duplicate binding query marker\n".into();
        claim_store.write_draft("research", flat).unwrap();
        claim_store.approve("research", id).unwrap();
        store(&paths).rebuild("research").unwrap();
        let indexed = store(&paths)
            .search(
                "research",
                search_opts("duplicate binding", vec![CLAIM_STATUS_APPROVED], 10),
            )
            .unwrap();
        assert_eq!(indexed.len(), 1);
        assert_eq!(indexed[0].id, id);
        let nested_path = "projects/topics/security/alias.md";
        let mut nested = query_claim(id, "Nested duplicate query marker", CLAIM_BASIS_OWNER);
        nested.body = "nested duplicate query marker\n".into();
        nested.path = nested_path.into();
        let nested = finalize_approved_store_claim(nested);
        let nested_absolute_path = paths.workspaces_dir.join("research/wiki").join(nested_path);
        write_claim_atomic(&nested_absolute_path, &nested).unwrap();
        let manifest = build_trust_input_manifest(&paths, "research").unwrap();

        let err = validate_indexed_claim_binding(&paths, "research", &indexed[0], Some(&manifest))
            .unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("duplicate canonical claim ID"),
            "{message}"
        );
        assert!(message.contains(id), "{message}");
        assert!(message.contains(nested_path), "{message}");
        assert!(trusted_query(
            &paths,
            TrustedQueryOptions {
                query: "duplicate binding".into(),
                limit: 10,
                ..TrustedQueryOptions::default()
            },
        )
        .is_err());
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn canonical_index_binding_rejects_approved_owner_digest_mismatch() {
        let (_dir, paths) = query_test_paths("binding-owner-digest");
        let claim_store = query_claim_store(&paths);
        let mut claim = query_claim(
            "clm_99999999999999999999999999999999",
            "Owner digest binding",
            CLAIM_BASIS_OWNER,
        );
        claim.body = "owner digest binding marker\n".into();
        claim_store.write_draft("research", claim.clone()).unwrap();
        claim_store.approve("research", &claim.id).unwrap();
        store(&paths).rebuild("research").unwrap();
        let indexed = store(&paths)
            .search(
                "research",
                search_opts("owner digest", vec![CLAIM_STATUS_APPROVED], 10),
            )
            .unwrap();
        assert_eq!(indexed.len(), 1);
        assert_eq!(indexed[0].id, claim.id);

        let claim_path = format!("projects/{}.md", claim.id);
        let mut canonical = read_claim_by_path(&paths, "research", &claim_path).unwrap();
        canonical.basis = CLAIM_BASIS_DERIVED.into();
        let canonical_path = paths.workspaces_dir.join("research/wiki").join(&claim_path);
        write_claim_atomic(&canonical_path, &canonical).unwrap();
        let manifest = build_trust_input_manifest(&paths, "research").unwrap();

        let err = validate_indexed_claim_binding(&paths, "research", &indexed[0], Some(&manifest))
            .unwrap_err();
        let message = err.to_string();
        assert!(message.contains("verification failed"), "{message}");
        assert!(
            message.contains("verification digest mismatch"),
            "{message}"
        );
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn canonical_index_binding() {
        struct BindingCase {
            name: &'static str,
            approved: bool,
            query: &'static str,
            mutation: &'static str,
        }
        let cases = [
            BindingCase {
                name: "body",
                approved: true,
                query: "sqlite-only body",
                mutation: "body",
            },
            BindingCase {
                name: "status",
                approved: false,
                query: "canonical binding body",
                mutation: "status",
            },
            BindingCase {
                name: "path",
                approved: true,
                query: "canonical binding body",
                mutation: "path",
            },
            BindingCase {
                name: "digest",
                approved: true,
                query: "canonical binding body",
                mutation: "digest",
            },
            BindingCase {
                name: "missing canonical target",
                approved: true,
                query: "canonical binding body",
                mutation: "id",
            },
        ];
        for case in cases {
            let (_dir, paths) =
                query_test_paths(&format!("binding-{}", case.name.replace(' ', "-")));
            let claim_store = query_claim_store(&paths);
            let mut claim = query_claim(
                "clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "Canonical Binding",
                CLAIM_BASIS_OWNER,
            );
            claim.body = "canonical binding body marker\n".into();
            claim_store.write_draft("research", claim.clone()).unwrap();
            if case.approved {
                claim_store.approve("research", &claim.id).unwrap();
            }
            store(&paths).rebuild("research").unwrap();
            let claim_path = paths
                .workspaces_dir
                .join("research/wiki/projects")
                .join(format!("{}.md", claim.id));
            let before = sha256_hex(&claim_path);
            let db_path = index_database_path(&store(&paths), "research");
            let conn = rusqlite::Connection::open(&db_path).unwrap();
            match case.mutation {
                "body" => conn
                    .execute(
                        "update claims set body = ? where id = ?",
                        rusqlite::params!["sqlite-only body marker\n", claim.id],
                    )
                    .unwrap(),
                "status" => conn
                    .execute(
                        "update claims set status = ? where id = ?",
                        rusqlite::params![CLAIM_STATUS_APPROVED, claim.id],
                    )
                    .unwrap(),
                "path" => conn
                    .execute(
                        "update claims set path = ? where id = ?",
                        rusqlite::params!["projects/forged.md", claim.id],
                    )
                    .unwrap(),
                "digest" => conn
                    .execute(
                        "update claims set verification_digest = ? where id = ?",
                        rusqlite::params![format!("sha256:{}", "0".repeat(64)), claim.id],
                    )
                    .unwrap(),
                _ => conn
                    .execute(
                        "update claims set id = ? where id = ?",
                        rusqlite::params!["clm_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", claim.id],
                    )
                    .unwrap(),
            };
            drop(conn);

            let result = trusted_query(
                &paths,
                TrustedQueryOptions {
                    query: case.query.into(),
                    limit: 10,
                    ..TrustedQueryOptions::default()
                },
            );
            assert!(
                result.is_err(),
                "{}: want fail-closed error, got {:?}",
                case.name,
                result.ok().map(|r| r.status)
            );
            assert_eq!(sha256_hex(&claim_path), before, "{}", case.name);
            let _ = std::fs::remove_dir_all(&_dir);
        }
    }

    #[test]
    fn trusted_query_reports_gap_when_no_approved_claims_match() {
        let (_dir, paths) = query_test_paths("gap");
        store(&paths).rebuild("research").unwrap();
        let response = trusted_query(
            &paths,
            TrustedQueryOptions {
                query: "missing context".into(),
                limit: 10,
                ..TrustedQueryOptions::default()
            },
        )
        .unwrap();
        assert_eq!(response.status, QUERY_STATUS_GAP);
        assert_eq!(response.gaps.as_ref().unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn trusted_query_blocks_explicit_conflict() {
        let (_dir, paths) = query_test_paths("blocked");
        let claim_store = query_claim_store(&paths);
        let mut first = query_claim(
            "clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "Conflict A",
            CLAIM_BASIS_OWNER,
        );
        first.body = "conflict token shared memory\n".into();
        let mut second = query_claim(
            "clm_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "Conflict B",
            CLAIM_BASIS_OWNER,
        );
        second.body = "conflict token shared memory\n".into();
        second.conflicts_with = vec![first.id.clone()];
        claim_store.write_draft("research", first).unwrap();
        claim_store
            .approve("research", "clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .unwrap();
        claim_store.write_draft("research", second).unwrap();
        claim_store
            .approve("research", "clm_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
            .unwrap();
        store(&paths).rebuild("research").unwrap();
        let response = trusted_query(
            &paths,
            TrustedQueryOptions {
                query: "conflict shared".into(),
                limit: 10,
                ..TrustedQueryOptions::default()
            },
        )
        .unwrap();
        assert_eq!(response.status, QUERY_STATUS_BLOCKED);
        assert_eq!(response.conflicts.len(), 1);
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn trusted_query_does_not_use_omitted_workspace() {
        let (_dir, paths) = query_test_paths("omitted-workspace");
        crate::workspace::create_workspace(&paths, "personal", &FixedClock::new(fixed_query_now()))
            .unwrap();
        let claim_store = query_claim_store(&paths);
        let mut personal_claim = query_claim(
            "clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "Personal Only",
            CLAIM_BASIS_OWNER,
        );
        personal_claim.body = "private omitted token\n".into();
        claim_store.write_draft("personal", personal_claim).unwrap();
        claim_store
            .approve("personal", "clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .unwrap();
        store(&paths).rebuild("research").unwrap();
        store(&paths).rebuild("personal").unwrap();
        let without_include = trusted_query(
            &paths,
            TrustedQueryOptions {
                query: "private omitted".into(),
                limit: 10,
                ..TrustedQueryOptions::default()
            },
        )
        .unwrap();
        assert_eq!(without_include.status, QUERY_STATUS_GAP);
        let with_include = trusted_query(
            &paths,
            TrustedQueryOptions {
                query: "private omitted".into(),
                includes: vec!["personal".into()],
                limit: 10,
                ..TrustedQueryOptions::default()
            },
        )
        .unwrap();
        assert_eq!(with_include.status, QUERY_STATUS_READY);
        let claims = with_include.claims.as_ref().unwrap();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].workspace, "personal");
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn trusted_query_surfaces_contradiction_draft_as_conflict_candidate() {
        let (_dir, paths) = query_test_paths("contradiction");
        let claim_store = query_claim_store(&paths);

        let mut approved = query_claim(
            "clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "zbrain uses SQLite for indexes",
            CLAIM_BASIS_OWNER,
        );
        approved.body = "zbrain database storage uses SQLite indexes\n".into();
        claim_store
            .write_draft("research", approved.clone())
            .unwrap();
        claim_store.approve("research", &approved.id).unwrap();

        let mut conflicting_draft = query_claim(
            "clm_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "zbrain uses BoltDB for indexes",
            CLAIM_BASIS_OWNER,
        );
        conflicting_draft.body = "zbrain database storage uses BoltDB indexes\n".into();
        claim_store
            .write_draft("research", conflicting_draft.clone())
            .unwrap();

        let mut clean_draft = query_claim(
            "clm_cccccccccccccccccccccccccccccccc",
            "Viewer binds loopback only",
            CLAIM_BASIS_OWNER,
        );
        clean_draft.body = "zbrain loopback viewer tool\n".into();
        claim_store
            .write_draft("research", clean_draft.clone())
            .unwrap();

        store(&paths).rebuild("research").unwrap();

        let response = trusted_query(
            &paths,
            TrustedQueryOptions {
                query: "database storage indexes".into(),
                limit: 10,
                ..TrustedQueryOptions::default()
            },
        )
        .unwrap();
        assert_eq!(response.status, QUERY_STATUS_READY);
        let claims = response.claims.as_ref().unwrap();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].id, approved.id);
        assert_eq!(claims[0].status, CLAIM_STATUS_APPROVED);
        let candidates = response.promotion_candidates.as_ref().unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].id, conflicting_draft.id);
        assert_eq!(candidates[0].status, CLAIM_STATUS_CONFLICT);
        let contradicts = candidates[0].contradicts.as_ref().unwrap();
        assert_eq!(contradicts.len(), 1);
        assert_eq!(contradicts[0].claim_id, approved.id);
        assert_eq!(contradicts[0].heuristic, CONTRADICTION_VALUE_SWAP);

        let gap_response = trusted_query(
            &paths,
            TrustedQueryOptions {
                query: "loopback viewer".into(),
                limit: 10,
                ..TrustedQueryOptions::default()
            },
        )
        .unwrap();
        assert_eq!(gap_response.status, QUERY_STATUS_GAP);
        let candidates = gap_response.promotion_candidates.as_ref().unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].id, clean_draft.id);
        assert_eq!(candidates[0].status, CLAIM_STATUS_DRAFT);
        assert!(candidates[0]
            .contradicts
            .as_ref()
            .is_none_or(|c| c.is_empty()));
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn trusted_query_temporal_options_validation() {
        let (_dir, paths) = query_test_paths("temporal-validation");
        let cases = [
            ("invalid after", TrustedQueryOptions { query: "test".into(), after: "not-a-date".into(), ..Default::default() }, "invalid after timestamp".to_string()),
            ("invalid before", TrustedQueryOptions { query: "test".into(), before: "2026/08/01".into(), ..Default::default() }, "invalid before timestamp".to_string()),
            ("invalid as_of", TrustedQueryOptions { query: "test".into(), as_of: "yesterday".into(), ..Default::default() }, "invalid as_of timestamp".to_string()),
            (
                "after is after before",
                TrustedQueryOptions {
                    query: "test".into(),
                    after: "2026-08-20T00:00:00Z".into(),
                    before: "2026-08-10T00:00:00Z".into(),
                    ..Default::default()
                },
                "after timestamp \"2026-08-20T00:00:00Z\" is after before timestamp \"2026-08-10T00:00:00Z\"".to_string(),
            ),
        ];
        for (name, options, want_error) in cases {
            let err = trusted_query(&paths, options).unwrap_err();
            assert!(
                err.to_string().contains(&want_error),
                "{name}: {err} want {want_error}"
            );
        }
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn trusted_query_temporal_after_before_range() {
        let (_dir, paths) = query_test_paths("temporal-range");
        let approve_with_time = |paths: &Paths, id: &str, at: chrono::DateTime<Utc>| {
            let store = ClaimStore::with_clock(paths.clone(), Arc::new(FixedClock::new(at)));
            store.approve("research", id).unwrap();
        };

        let mut claim_a = query_claim(
            "clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "Claim Early",
            CLAIM_BASIS_OWNER,
        );
        claim_a.body = "temporal corpus alpha marker\n".into();
        query_claim_store(&paths)
            .write_draft("research", claim_a.clone())
            .unwrap();
        approve_with_time(
            &paths,
            &claim_a.id,
            Utc.with_ymd_and_hms(2026, 8, 1, 10, 0, 0).unwrap(),
        );

        let mut claim_b = query_claim(
            "clm_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "Claim Mid",
            CLAIM_BASIS_OWNER,
        );
        claim_b.body = "temporal corpus beta marker\n".into();
        query_claim_store(&paths)
            .write_draft("research", claim_b.clone())
            .unwrap();
        approve_with_time(
            &paths,
            &claim_b.id,
            Utc.with_ymd_and_hms(2026, 8, 15, 10, 0, 0).unwrap(),
        );

        let mut claim_c = query_claim(
            "clm_cccccccccccccccccccccccccccccccc",
            "Claim Late",
            CLAIM_BASIS_OWNER,
        );
        claim_c.body = "temporal corpus gamma marker\n".into();
        query_claim_store(&paths)
            .write_draft("research", claim_c.clone())
            .unwrap();
        approve_with_time(
            &paths,
            &claim_c.id,
            Utc.with_ymd_and_hms(2026, 8, 28, 10, 0, 0).unwrap(),
        );

        store(&paths).rebuild("research").unwrap();

        let all = trusted_query(
            &paths,
            TrustedQueryOptions {
                query: "temporal corpus".into(),
                limit: 10,
                ..TrustedQueryOptions::default()
            },
        )
        .unwrap();
        assert_eq!(all.claims.as_ref().unwrap().len(), 3);

        let after = trusted_query(
            &paths,
            TrustedQueryOptions {
                query: "temporal corpus".into(),
                after: "2026-08-10T00:00:00Z".into(),
                limit: 10,
                ..TrustedQueryOptions::default()
            },
        )
        .unwrap();
        let claims = after.claims.as_ref().unwrap();
        assert_eq!(claims.len(), 2);
        assert_eq!(claims[0].id, claim_b.id);
        assert_eq!(claims[1].id, claim_c.id);

        let before = trusted_query(
            &paths,
            TrustedQueryOptions {
                query: "temporal corpus".into(),
                before: "2026-08-10T00:00:00Z".into(),
                limit: 10,
                ..TrustedQueryOptions::default()
            },
        )
        .unwrap();
        let claims = before.claims.as_ref().unwrap();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].id, claim_a.id);

        let range = trusted_query(
            &paths,
            TrustedQueryOptions {
                query: "temporal corpus".into(),
                after: "2026-08-10T00:00:00Z".into(),
                before: "2026-08-20T00:00:00Z".into(),
                limit: 10,
                ..TrustedQueryOptions::default()
            },
        )
        .unwrap();
        let claims = range.claims.as_ref().unwrap();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].id, claim_b.id);
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn trusted_query_temporal_as_of_historical_and_staleness() {
        let (_dir, paths) = query_test_paths("temporal-as-of");
        let approve_with_time = |paths: &Paths, id: &str, at: chrono::DateTime<Utc>| {
            let store = ClaimStore::with_clock(paths.clone(), Arc::new(FixedClock::new(at)));
            store.approve("research", id).unwrap();
        };

        let mut claim1 = query_claim(
            "clm_11111111111111111111111111111111",
            "Stale Lifecycle Claim",
            CLAIM_BASIS_OWNER,
        );
        claim1.stale_after = "2026-08-10T00:00:00Z".into();
        claim1.body = "point in time historical memory\n".into();
        query_claim_store(&paths)
            .write_draft("research", claim1.clone())
            .unwrap();
        approve_with_time(
            &paths,
            &claim1.id,
            Utc.with_ymd_and_hms(2026, 8, 1, 10, 0, 0).unwrap(),
        );

        let mut claim2 = query_claim(
            "clm_22222222222222222222222222222222",
            "Superseded Claim",
            CLAIM_BASIS_OWNER,
        );
        claim2.body = "point in time historical memory\n".into();
        query_claim_store(&paths)
            .write_draft("research", claim2.clone())
            .unwrap();
        approve_with_time(
            &paths,
            &claim2.id,
            Utc.with_ymd_and_hms(2026, 8, 5, 10, 0, 0).unwrap(),
        );

        let mut claim3 = query_claim(
            "clm_33333333333333333333333333333333",
            "Replacement Claim",
            CLAIM_BASIS_OWNER,
        );
        claim3.body = "point in time historical memory\n".into();
        let supersede_store = ClaimStore::with_clock(
            paths.clone(),
            Arc::new(FixedClock::new(
                Utc.with_ymd_and_hms(2026, 8, 20, 10, 0, 0).unwrap(),
            )),
        );
        supersede_store
            .write_superseding_draft("research", &claim2.id, claim3.clone())
            .unwrap();
        approve_with_time(
            &paths,
            &claim3.id,
            Utc.with_ymd_and_hms(2026, 8, 20, 10, 0, 0).unwrap(),
        );
        store(&paths).rebuild("research").unwrap();

        let early = trusted_query(
            &paths,
            TrustedQueryOptions {
                query: "historical memory".into(),
                as_of: "2026-08-03T00:00:00Z".into(),
                limit: 10,
                ..TrustedQueryOptions::default()
            },
        )
        .unwrap();
        let claims = early.claims.as_ref().unwrap();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].id, claim1.id);
        assert_eq!(claims[0].status, CLAIM_STATUS_APPROVED);

        let mid = trusted_query(
            &paths,
            TrustedQueryOptions {
                query: "historical memory".into(),
                as_of: "2026-08-15T00:00:00Z".into(),
                limit: 10,
                ..TrustedQueryOptions::default()
            },
        )
        .unwrap();
        let claims = mid.claims.as_ref().unwrap();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].id, claim2.id);
        assert_eq!(claims[0].status, CLAIM_STATUS_APPROVED);

        let late = trusted_query(
            &paths,
            TrustedQueryOptions {
                query: "historical memory".into(),
                as_of: "2026-08-25T00:00:00Z".into(),
                limit: 10,
                ..TrustedQueryOptions::default()
            },
        )
        .unwrap();
        let claims = late.claims.as_ref().unwrap();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].id, claim3.id);
        assert_eq!(claims[0].status, CLAIM_STATUS_APPROVED);
        let _ = std::fs::remove_dir_all(&_dir);
    }

    // -- hybrid_test.go port ------------------------------------------------

    #[test]
    fn hybrid_retrieval() {
        let lexical_only_id = "clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let vector_only_id = "clm_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

        // no embedding database uses pure lexical
        {
            let (dir_holder, paths) = query_test_paths("hybrid-no-embed");
            let claim_store = query_claim_store(&paths);
            let mut lexical_only = query_claim(
                lexical_only_id,
                "Quantum Entanglement Observer",
                CLAIM_BASIS_OWNER,
            );
            lexical_only.body = "quantum entanglement observer discovery\n".into();
            let mut vector_only =
                query_claim(vector_only_id, "Entangled Observer", CLAIM_BASIS_OWNER);
            vector_only.body = "entanglement observer phenomena\n".into();
            for claim in [lexical_only, vector_only] {
                claim_store.write_draft("research", claim.clone()).unwrap();
                claim_store.approve("research", &claim.id).unwrap();
            }
            crate::embedder::rebuild_with_options(
                &paths,
                "research",
                RebuildOptions { embedding: false },
            )
            .unwrap();

            let with_option = trusted_query(
                &paths,
                TrustedQueryOptions {
                    query: "quantum entanglement observer".into(),
                    limit: 10,
                    embedding: true,
                    ..TrustedQueryOptions::default()
                },
            )
            .unwrap();
            let without_option = trusted_query(
                &paths,
                TrustedQueryOptions {
                    query: "quantum entanglement observer".into(),
                    limit: 10,
                    ..TrustedQueryOptions::default()
                },
            )
            .unwrap();
            assert_eq!(with_option.status, QUERY_STATUS_READY);
            assert_eq!(without_option.status, QUERY_STATUS_READY);
            assert_eq!(claim_ids(&with_option), vec![lexical_only_id.to_string()]);
            assert_eq!(
                claim_ids(&without_option),
                vec![lexical_only_id.to_string()]
            );
            let _ = std::fs::remove_dir_all(&dir_holder);
        }

        // empty embedding sidecar uses pure lexical
        {
            let (dir_holder, paths) = query_test_paths("hybrid-empty-sidecar");
            let claim_store = query_claim_store(&paths);
            let mut lexical_only = query_claim(
                lexical_only_id,
                "Quantum Entanglement Observer",
                CLAIM_BASIS_OWNER,
            );
            lexical_only.body = "quantum entanglement observer discovery\n".into();
            let mut vector_only =
                query_claim(vector_only_id, "Entangled Observer", CLAIM_BASIS_OWNER);
            vector_only.body = "entanglement observer phenomena\n".into();
            for claim in [lexical_only, vector_only] {
                claim_store.write_draft("research", claim.clone()).unwrap();
                claim_store.approve("research", &claim.id).unwrap();
            }
            crate::embedder::rebuild_with_options(
                &paths,
                "research",
                RebuildOptions { embedding: false },
            )
            .unwrap();
            let embedding_path =
                crate::embedder::EmbeddingStore::new(paths.clone()).database_path("research");
            let conn = rusqlite::Connection::open(&embedding_path).unwrap();
            conn.execute_batch(
                "create table embeddings (\n\tclaim_id text not null primary key,\n\tvector blob not null,\n\tdimension integer not null\n)",
            )
            .unwrap();
            drop(conn);

            let response = trusted_query(
                &paths,
                TrustedQueryOptions {
                    query: "quantum entanglement observer".into(),
                    limit: 10,
                    embedding: true,
                    ..TrustedQueryOptions::default()
                },
            )
            .unwrap();
            assert_eq!(claim_ids(&response), vec![lexical_only_id.to_string()]);
            let _ = std::fs::remove_dir_all(&dir_holder);
        }

        // embeddings merge lexical and vector matches without duplicates
        {
            let (dir_holder, paths) = query_test_paths("hybrid-merge");
            let claim_store = query_claim_store(&paths);
            let mut lexical_only = query_claim(
                lexical_only_id,
                "Quantum Entanglement Observer",
                CLAIM_BASIS_OWNER,
            );
            lexical_only.body = "quantum entanglement observer discovery\n".into();
            let mut vector_only =
                query_claim(vector_only_id, "Entangled Observer", CLAIM_BASIS_OWNER);
            vector_only.body = "entanglement observer phenomena\n".into();
            for claim in [lexical_only, vector_only] {
                claim_store.write_draft("research", claim.clone()).unwrap();
                claim_store.approve("research", &claim.id).unwrap();
            }
            crate::embedder::rebuild_with_options(
                &paths,
                "research",
                RebuildOptions { embedding: true },
            )
            .unwrap();

            let response = trusted_query(
                &paths,
                TrustedQueryOptions {
                    query: "quantum entanglement observer".into(),
                    limit: 10,
                    embedding: true,
                    ..TrustedQueryOptions::default()
                },
            )
            .unwrap();
            assert_eq!(response.status, QUERY_STATUS_READY);
            let ids = claim_ids(&response);
            assert!(ids.len() >= 2, "want at least 2 hybrid matches: {ids:?}");
            let mut seen = std::collections::HashSet::new();
            for id in &ids {
                assert!(
                    seen.insert(id.clone()),
                    "duplicate claim ID {id} in hybrid results"
                );
            }
            assert_eq!(ids[0], lexical_only_id, "lexical match must be first");
            let _ = std::fs::remove_dir_all(&dir_holder);
        }

        // embeddings without option keep lexical only
        {
            let (dir_holder, paths) = query_test_paths("hybrid-no-option");
            let claim_store = query_claim_store(&paths);
            let mut lexical_only = query_claim(
                lexical_only_id,
                "Quantum Entanglement Observer",
                CLAIM_BASIS_OWNER,
            );
            lexical_only.body = "quantum entanglement observer discovery\n".into();
            let mut vector_only =
                query_claim(vector_only_id, "Entangled Observer", CLAIM_BASIS_OWNER);
            vector_only.body = "entanglement observer phenomena\n".into();
            for claim in [lexical_only, vector_only] {
                claim_store.write_draft("research", claim.clone()).unwrap();
                claim_store.approve("research", &claim.id).unwrap();
            }
            crate::embedder::rebuild_with_options(
                &paths,
                "research",
                RebuildOptions { embedding: true },
            )
            .unwrap();

            let response = trusted_query(
                &paths,
                TrustedQueryOptions {
                    query: "quantum entanglement observer".into(),
                    limit: 10,
                    ..TrustedQueryOptions::default()
                },
            )
            .unwrap();
            assert_eq!(claim_ids(&response), vec![lexical_only_id.to_string()]);
            let _ = std::fs::remove_dir_all(&dir_holder);
        }

        // stale index fails closed on hybrid path
        {
            let (dir_holder, paths) = query_test_paths("hybrid-stale");
            let claim_store = query_claim_store(&paths);
            let mut lexical_only = query_claim(
                lexical_only_id,
                "Quantum Entanglement Observer",
                CLAIM_BASIS_OWNER,
            );
            lexical_only.body = "quantum entanglement observer discovery\n".into();
            let mut vector_only =
                query_claim(vector_only_id, "Entangled Observer", CLAIM_BASIS_OWNER);
            vector_only.body = "entanglement observer phenomena\n".into();
            for claim in [lexical_only.clone(), vector_only] {
                claim_store.write_draft("research", claim.clone()).unwrap();
                claim_store.approve("research", &claim.id).unwrap();
            }
            crate::embedder::rebuild_with_options(
                &paths,
                "research",
                RebuildOptions { embedding: true },
            )
            .unwrap();

            let claim_path = paths
                .workspaces_dir
                .join("research/wiki/projects")
                .join(format!("{lexical_only_id}.md"));
            let contents = String::from_utf8(std::fs::read(&claim_path).unwrap()).unwrap();
            let contents = contents.replacen(
                "quantum entanglement observer discovery",
                "changed quantum entanglement observer discovery",
                1,
            );
            std::fs::write(&claim_path, contents).unwrap();

            let err = trusted_query(
                &paths,
                TrustedQueryOptions {
                    query: "quantum entanglement observer".into(),
                    limit: 10,
                    embedding: true,
                    ..TrustedQueryOptions::default()
                },
            )
            .unwrap_err();
            assert!(err.to_string().contains("stale"), "{err}");
            let _ = std::fs::remove_dir_all(&dir_holder);
        }
    }

    #[test]
    fn interleave_claims_deduplicates_by_id() {
        let lexical = vec![
            IndexedClaim {
                id: "clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                score: 1.0,
                ..Default::default()
            },
            IndexedClaim {
                id: "clm_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
                score: 2.0,
                ..Default::default()
            },
        ];
        let vector = vec![
            IndexedClaim {
                id: "clm_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
                score: 1.0,
                ..Default::default()
            },
            IndexedClaim {
                id: "clm_cccccccccccccccccccccccccccccccc".into(),
                score: 2.0,
                ..Default::default()
            },
        ];

        let merged = interleave_claims(lexical, vector, 10);
        let mut seen = std::collections::HashSet::new();
        for claim in &merged {
            assert!(
                seen.insert(claim.id.clone()),
                "duplicate claim ID {}",
                claim.id
            );
        }
        let want = vec![
            "clm_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "clm_cccccccccccccccccccccccccccccccc",
        ];
        let ids: Vec<&str> = merged.iter().map(|claim| claim.id.as_str()).collect();
        assert_eq!(ids, want);
        for index in 1..merged.len() {
            assert!(merged[index].score > merged[index - 1].score);
        }
        assert_eq!(merged[0].score, 0.0);
        assert_eq!(merged[1].score, 1.0);
        assert_eq!(merged[2].score, 2.0);
    }

    #[test]
    fn interleave_rrf() {
        let lexical = vec![
            IndexedClaim {
                id: "clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                score: 9.0,
                ..Default::default()
            },
            IndexedClaim {
                id: "clm_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
                score: 9.0,
                ..Default::default()
            },
        ];
        let vector = vec![
            IndexedClaim {
                id: "clm_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
                score: 9.0,
                ..Default::default()
            },
            IndexedClaim {
                id: "clm_cccccccccccccccccccccccccccccccc".into(),
                score: 9.0,
                ..Default::default()
            },
        ];
        let merged = interleave_claims(lexical.clone(), vector.clone(), 10);
        assert_eq!(merged.len(), 3);
        let want = vec![
            "clm_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "clm_cccccccccccccccccccccccccccccccc",
        ];
        let ids: Vec<&str> = merged.iter().map(|claim| claim.id.as_str()).collect();
        assert_eq!(ids, want);
        assert_eq!(merged[0].id, "clm_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        for (index, claim) in merged.iter().enumerate() {
            assert_eq!(claim.score, index as f64);
        }
        let mut shuffled = vec![
            binding_probe_claim(&merged[2].id, merged[2].score),
            binding_probe_claim(&merged[0].id, merged[0].score),
            binding_probe_claim(&merged[1].id, merged[1].score),
        ];
        sort_query_claims(&mut shuffled);
        let shuffled_ids: Vec<&str> = shuffled.iter().map(|claim| claim.id.as_str()).collect();
        assert_eq!(shuffled_ids, want);

        let truncated = interleave_claims(lexical, vector, 2);
        assert_eq!(truncated.len(), 2);
        assert_eq!(truncated[0].id, want[0]);
        assert_eq!(truncated[1].id, want[1]);
    }

    #[test]
    fn hybrid_retrieval_respects_workspace_isolation() {
        let (_dir, paths) = query_test_paths("hybrid-isolation");
        crate::workspace::create_workspace(&paths, "personal", &FixedClock::new(fixed_query_now()))
            .unwrap();
        let claim_store = query_claim_store(&paths);
        let mut research_claim = query_claim(
            "clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "Research Memory",
            CLAIM_BASIS_OWNER,
        );
        research_claim.body = "research-only context marker\n".into();
        let mut personal_claim = query_claim(
            "clm_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "Personal Memory",
            CLAIM_BASIS_OWNER,
        );
        personal_claim.body = "workspace-private hybrid marker\n".into();
        for (workspace, claim) in [
            ("research", research_claim.clone()),
            ("personal", personal_claim.clone()),
        ] {
            claim_store.write_draft(workspace, claim.clone()).unwrap();
            claim_store.approve(workspace, &claim.id).unwrap();
        }
        for workspace in ["research", "personal"] {
            crate::embedder::rebuild_with_options(
                &paths,
                workspace,
                RebuildOptions { embedding: true },
            )
            .unwrap();
        }

        let without_include = trusted_query(
            &paths,
            TrustedQueryOptions {
                workspace: "research".into(),
                query: "workspace-private hybrid marker".into(),
                limit: 10,
                embedding: true,
                ..TrustedQueryOptions::default()
            },
        )
        .unwrap();
        assert_eq!(without_include.scopes.primary, "research");
        assert!(without_include.scopes.includes.is_empty());
        for claim in without_include.claims.iter().flatten() {
            assert_eq!(claim.workspace, "research");
            assert_ne!(claim.id, personal_claim.id);
        }

        let with_include = trusted_query(
            &paths,
            TrustedQueryOptions {
                workspace: "research".into(),
                includes: vec!["personal".into()],
                query: "workspace-private hybrid marker".into(),
                limit: 10,
                embedding: true,
                ..TrustedQueryOptions::default()
            },
        )
        .unwrap();
        let mut found_personal = false;
        for claim in with_include.claims.iter().flatten() {
            if claim.workspace == "personal" && claim.id == personal_claim.id {
                found_personal = true;
            }
            assert!(
                claim.workspace == "research" || claim.workspace == "personal",
                "claim outside resolved scopes: {:?}",
                claim
            );
        }
        assert!(
            found_personal,
            "withInclude claims = {:?}",
            with_include.claims
        );
        let _ = std::fs::remove_dir_all(&_dir);
    }

    /// The verification digest blanks `verified.*`, so a flipped signature
    /// keeps the digest intact. Only the signature check in the canonical
    /// binding rejects it, and the query must fail closed rather than serve
    /// the claim.
    #[test]
    fn canonical_index_binding_rejects_a_bad_signature() {
        let (_dir, paths) = query_test_paths("binding-bad-signature");
        let claim_store = query_claim_store(&paths);
        let id = "clm_99999999999999999999999999999999";
        let mut claim = query_claim(id, "Signed binding marker", CLAIM_BASIS_OWNER);
        claim.body = "signed binding query marker\n".into();
        claim_store.write_draft("research", claim).unwrap();
        claim_store.approve("research", id).unwrap();
        store(&paths).rebuild("research").unwrap();
        let indexed = store(&paths)
            .search(
                "research",
                search_opts("signed binding", vec![CLAIM_STATUS_APPROVED], 10),
            )
            .unwrap();
        assert_eq!(indexed.len(), 1);

        let path = paths
            .workspaces_dir
            .join("research/wiki/projects")
            .join(format!("{id}.md"));
        let contents = std::fs::read_to_string(&path).unwrap();
        let marker = "    sig: ";
        let start = contents
            .find(marker)
            .expect("approved claim carries a signature")
            + marker.len();
        let end = start + contents[start..].find('\n').unwrap();
        let mut signature: Vec<u8> = contents[start..end].bytes().collect();
        signature[0] = if signature[0] == b'A' { b'B' } else { b'A' };
        std::fs::write(
            &path,
            format!(
                "{}{}{}",
                &contents[..start],
                String::from_utf8(signature).unwrap(),
                &contents[end..]
            ),
        )
        .unwrap();
        let manifest = build_trust_input_manifest(&paths, "research").unwrap();

        let err = validate_indexed_claim_binding(&paths, "research", &indexed[0], Some(&manifest))
            .unwrap_err();
        let message = err.to_string();
        assert!(message.contains("approval signature"), "{message}");
        assert!(message.contains(id), "{message}");
        assert!(trusted_query(
            &paths,
            TrustedQueryOptions {
                query: "signed binding".into(),
                limit: 10,
                ..TrustedQueryOptions::default()
            },
        )
        .is_err());
        let _ = std::fs::remove_dir_all(&_dir);
    }
}
