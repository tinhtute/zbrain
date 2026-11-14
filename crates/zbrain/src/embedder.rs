//! embedder.rs — port of internal/runtime/embedder.go: the local-only
//! deterministic loopback token embedder and the SQLite embedding sidecar.
//! Pure in-process computation; never contacts a network service.

use std::collections::HashSet;
use std::path::PathBuf;

use rusqlite::Connection;
use sha2::{Digest as _, Sha256};

use crate::index::{create_temp_file, EmbeddingSummary, IndexError, IndexStore};
use crate::paths::{set_permissions, Paths, DERIVED_INDEX_MODE};

pub const LOOPBACK_MODEL: &str = "zbrain/loopback-v1";
pub const DEFAULT_EMBEDDING_DIMENSION: usize = 384;

pub struct LoopbackEmbedder {
    pub dimension: usize,
}

impl Default for LoopbackEmbedder {
    fn default() -> Self {
        Self::new()
    }
}

impl LoopbackEmbedder {
    pub fn new() -> Self {
        Self {
            dimension: DEFAULT_EMBEDDING_DIMENSION,
        }
    }

    /// Embed produces deterministic vectors for each input text. Each vector
    /// has Dimension components and is L2-normalized.
    pub fn embed(&self, texts: &[&str]) -> Vec<Vec<f32>> {
        texts.iter().map(|text| self.embed_one(text)).collect()
    }

    fn embed_one(&self, text: &str) -> Vec<f32> {
        let mut vec = vec![0.0f32; self.dimension];
        for token in loopback_tokens(text) {
            let hash = Sha256::digest(token.as_bytes());
            let idx =
                u32::from_le_bytes([hash[0], hash[1], hash[2], hash[3]]) as usize % self.dimension;
            vec[idx] += 1.0;
            let idx2 =
                u32::from_le_bytes([hash[4], hash[5], hash[6], hash[7]]) as usize % self.dimension;
            vec[idx2] += 0.5;
        }
        let mut norm: f64 = vec.iter().map(|v| (*v as f64) * (*v as f64)).sum();
        if norm > 0.0 {
            norm = norm.sqrt();
            for value in &mut vec {
                *value = (*value as f64 / norm) as f32;
            }
        }
        vec
    }
}

/// embedding_text is the exact text a claim's vector is built from. The
/// readiness gate in query.rs compares a query against the same composition,
/// so both callers must keep using this one function.
pub(crate) fn embedding_text(title: &str, description: &str, tags: &str, body: &str) -> String {
    format!("{title} {description} {tags} {body}")
}

/// Function words carry no retrieval evidence: a vector that overlaps the query
/// only on "the" or "is" is not related to it.
const STOPWORDS: &[&str] = &[
    "and", "are", "but", "can", "could", "did", "does", "for", "from", "had", "has", "have", "her",
    "here", "him", "his", "how", "its", "not", "our", "out", "she", "should", "than", "that",
    "the", "their", "them", "then", "there", "these", "they", "this", "those", "too", "was",
    "were", "what", "when", "where", "which", "who", "why", "will", "with", "would", "you", "your",
];

fn is_significant_token(token: &str) -> bool {
    token.len() > 2 && !STOPWORDS.contains(&token)
}

/// shares_meaningful_token reports whether query and text share at least one
/// token that carries retrieval evidence, using the embedder's own tokenizer.
///
/// This is the collision-free form of "the vector is related": loopback-v1 is a
/// hashed bag-of-words, so its cosine cannot separate a genuinely shared token
/// (median 0.12) from a hash collision on unrelated text (up to 0.28). The gate
/// is therefore decided on tokens, not on the score.
pub(crate) fn shares_meaningful_token(query: &str, text: &str) -> bool {
    let text_tokens: HashSet<String> = loopback_tokens(text)
        .into_iter()
        .filter(|token| is_significant_token(token))
        .collect();
    if text_tokens.is_empty() {
        return false;
    }
    loopback_tokens(query)
        .into_iter()
        .any(|token| is_significant_token(&token) && text_tokens.contains(&token))
}

// loopbackTokens: lowercased tokens split on ASCII non-alphanumerics, deduped
// in first-appearance order (kept independent from the search tokenizer).
pub(crate) fn loopback_tokens(text: &str) -> Vec<String> {
    let lower = text.to_lowercase();
    let mut dedup: HashSet<String> = HashSet::new();
    let mut tokens = Vec::new();
    let mut current = String::new();
    for ch in lower.chars() {
        if ch.is_ascii_lowercase() || ch.is_ascii_digit() {
            current.push(ch);
        } else if !current.is_empty() {
            if dedup.insert(current.clone()) {
                tokens.push(std::mem::take(&mut current));
            } else {
                current.clear();
            }
        }
    }
    if !current.is_empty() && dedup.insert(current.clone()) {
        tokens.push(current);
    }
    tokens
}

pub struct EmbeddingStore {
    pub paths: Paths,
}

pub struct EmbeddingRecord {
    pub claim_id: String,
    pub dimension: usize,
    pub vector: Vec<f32>,
}

impl EmbeddingStore {
    pub fn new(paths: Paths) -> Self {
        Self { paths }
    }

    pub fn database_path(&self, workspace: &str) -> PathBuf {
        self.paths
            .indexes_dir
            .join(format!("{workspace}.embeddings.sqlite"))
    }

    /// Close removes the embedding database for a workspace.
    pub fn close(&self, workspace: &str) -> Result<(), IndexError> {
        let path = self.database_path(workspace);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(source.into()),
        }
    }

    /// StoreVectors writes embedding vectors for the given claims, replacing
    /// any existing embeddings atomically via rename.
    pub fn store_vectors(
        &self,
        workspace: &str,
        records: &[EmbeddingRecord],
    ) -> Result<(), IndexError> {
        if records.is_empty() {
            return self.close(workspace);
        }
        ensure_directory_mode(&self.paths)?;
        let tmp_path = create_temp_file(
            &self.paths.indexes_dir,
            &format!("{workspace}.embeddings.sqlite."),
        )?;
        let result = (|| -> Result<(), IndexError> {
            let conn = Connection::open(&tmp_path)?;
            conn.execute_batch(
                "create table embeddings (
\tclaim_id text not null primary key,
\tvector blob not null,
\tdimension integer not null
)",
            )
            .map_err(|err| IndexError::Message(format!("create embeddings table: {err}")))?;
            let tx = conn.unchecked_transaction()?;
            for record in records {
                let mut bytes = Vec::with_capacity(4 * record.vector.len());
                for value in &record.vector {
                    bytes.extend_from_slice(&value.to_le_bytes());
                }
                tx.execute(
                    "insert into embeddings(claim_id, vector, dimension) values (?, ?, ?)",
                    rusqlite::params![record.claim_id, bytes, record.dimension as i64],
                )
                .map_err(|err| {
                    IndexError::Message(format!("store embedding for {:?}: {err}", record.claim_id))
                })?;
            }
            tx.commit()?;
            drop(conn);
            set_permissions(&tmp_path, DERIVED_INDEX_MODE)?;
            std::fs::rename(&tmp_path, self.database_path(workspace))?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp_path);
        }
        result
    }

    /// SearchVectors returns the top-k most similar claim IDs for the query.
    /// Returns None when no embedding database exists or it has no vectors
    /// (caller falls back to lexical).
    pub fn search_vectors(
        &self,
        workspace: &str,
        query: &str,
        limit: i64,
    ) -> Result<Option<Vec<String>>, IndexError> {
        let path = self.database_path(workspace);
        if let Err(source) = std::fs::symlink_metadata(&path) {
            if source.kind() == std::io::ErrorKind::NotFound {
                return Ok(None);
            }
            return Err(source.into());
        }
        let limit = if limit <= 0 { 10 } else { limit };
        let conn = Connection::open(&path)?;
        let mut statement = conn.prepare("select claim_id, vector, dimension from embeddings")?;
        let mut rows = statement.query([])?;
        struct StoredVector {
            claim_id: String,
            vector: Vec<f32>,
        }
        let mut stored: Vec<StoredVector> = Vec::new();
        while let Some(row) = rows.next()? {
            let claim_id: String = row.get(0)?;
            let blob: Vec<u8> = row.get(1)?;
            let dim: i64 = row.get(2)?;
            if blob.len() != 4 * dim as usize {
                return Err(IndexError::Message(format!(
                    "embedding vector byte length mismatch for {claim_id:?}: {} bytes, want {}",
                    blob.len(),
                    4 * dim
                )));
            }
            let vector: Vec<f32> = (0..dim as usize)
                .map(|i| {
                    f32::from_le_bytes([
                        blob[4 * i],
                        blob[4 * i + 1],
                        blob[4 * i + 2],
                        blob[4 * i + 3],
                    ])
                })
                .collect();
            stored.push(StoredVector { claim_id, vector });
        }
        if stored.is_empty() {
            return Ok(None);
        }
        let embedder = LoopbackEmbedder::new();
        let query_vec = &embedder.embed(&[query])[0];
        let mut scored: Vec<(String, f64)> = Vec::with_capacity(stored.len());
        for vector in &stored {
            if vector.vector.len() != query_vec.len() {
                return Err(IndexError::Message(format!(
                    "embedding dimension mismatch for {:?}: {}, want {}",
                    vector.claim_id,
                    vector.vector.len(),
                    query_vec.len()
                )));
            }
            let dot: f64 = query_vec
                .iter()
                .zip(vector.vector.iter())
                .map(|(q, v)| (*q as f64) * (*v as f64))
                .sum();
            scored.push((vector.claim_id.clone(), dot));
        }
        scored.sort_by(|left, right| {
            right
                .1
                .partial_cmp(&left.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| left.0.cmp(&right.0))
        });
        scored.truncate(limit as usize);
        Ok(Some(scored.into_iter().map(|(id, _)| id).collect()))
    }

    /// Count returns the number of stored embeddings for a workspace.
    pub fn count(&self, workspace: &str) -> Result<i64, IndexError> {
        let path = self.database_path(workspace);
        if let Err(source) = std::fs::symlink_metadata(&path) {
            if source.kind() == std::io::ErrorKind::NotFound {
                return Ok(0);
            }
            return Err(source.into());
        }
        let conn = Connection::open(&path)?;
        let count: i64 = conn.query_row("select count(*) from embeddings", [], |row| row.get(0))?;
        Ok(count)
    }

    /// Summary reports the optional embedding sidecar coverage without making
    /// it a prerequisite for lexical retrieval or workspace status.
    pub fn summary(&self, workspace: &str, eligible: i64) -> EmbeddingSummary {
        let mut summary = EmbeddingSummary {
            strategy: "lexical".into(),
            degraded: "embeddings not configured".into(),
            ..EmbeddingSummary::default()
        };
        let count = match self.count(workspace) {
            Ok(count) => count,
            Err(_) => {
                summary.degraded = "embedding sidecar unavailable".into();
                return summary;
            }
        };
        if count == 0 {
            return summary;
        }
        summary.strategy = "loopback".into();
        summary.model = LOOPBACK_MODEL.into();
        summary.indexed = count;
        summary.eligible = eligible;
        summary.degraded = String::new();
        summary
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct RebuildOptions {
    pub embedding: bool,
}

/// RebuildWithOptions rebuilds the index with optional loopback embedding.
pub fn rebuild_with_options(
    paths: &Paths,
    workspace: &str,
    opts: RebuildOptions,
) -> Result<crate::index::IndexSummary, IndexError> {
    let store = IndexStore::new(paths.clone());
    let mut summary = store.rebuild(workspace)?;
    if !opts.embedding {
        // A non-embedding rebuild must not leave stale vectors behind; the
        // derived index changed and old embeddings no longer correspond to it.
        EmbeddingStore::new(paths.clone())
            .close(workspace)
            .map_err(|err| IndexError::Message(format!("clear stale embeddings: {err}")))?;
        return Ok(summary);
    }
    embed_indexed_claims(&store, paths, workspace, &mut summary)
}

fn embed_indexed_claims(
    _store: &IndexStore,
    paths: &Paths,
    workspace: &str,
    summary: &mut crate::index::IndexSummary,
) -> Result<crate::index::IndexSummary, IndexError> {
    let store = IndexStore::new(paths.clone());
    let database_path = store.database_path(workspace)?;
    let conn = Connection::open(&database_path)?;
    let mut statement =
        conn.prepare("select id, title, description, tags, body from claims where status = ?")?;
    let mut rows = statement.query(rusqlite::params![crate::claims::CLAIM_STATUS_APPROVED])?;
    struct ClaimText {
        id: String,
        text: String,
    }
    let mut claims: Vec<ClaimText> = Vec::new();
    while let Some(row) = rows.next()? {
        let id: String = row.get(0)?;
        let title: String = row.get(1)?;
        let description: String = row.get(2)?;
        let tags: String = row.get(3)?;
        let body: String = row.get(4)?;
        claims.push(ClaimText {
            id,
            text: embedding_text(&title, &description, &tags, &body),
        });
    }
    if claims.is_empty() {
        EmbeddingStore::new(paths.clone()).close(workspace)?;
        summary.embedding.indexed = 0;
        summary.embedding.eligible = 0;
        summary.embedding.strategy = "loopback".into();
        summary.embedding.model = LOOPBACK_MODEL.into();
        summary.embedding.degraded = String::new();
        return Ok(summary.clone());
    }
    let texts: Vec<&str> = claims.iter().map(|claim| claim.text.as_str()).collect();
    let embedder = LoopbackEmbedder::new();
    let vectors = embedder.embed(&texts);
    let records: Vec<EmbeddingRecord> = claims
        .iter()
        .zip(vectors.iter())
        .map(|(claim, vector)| EmbeddingRecord {
            claim_id: claim.id.clone(),
            dimension: embedder.dimension,
            vector: vector.clone(),
        })
        .collect();
    EmbeddingStore::new(paths.clone())
        .store_vectors(workspace, &records)
        .map_err(|err| IndexError::Message(format!("store embeddings: {err}")))?;
    summary.embedding.indexed = records.len() as i64;
    summary.embedding.eligible = records.len() as i64;
    summary.embedding.strategy = "loopback".into();
    summary.embedding.model = LOOPBACK_MODEL.into();
    summary.embedding.degraded = String::new();
    Ok(summary.clone())
}

fn ensure_directory_mode(paths: &Paths) -> Result<(), IndexError> {
    crate::paths::ensure_directory_mode(&paths.indexes_dir, crate::paths::RUNTIME_DIRECTORY_MODE)
        .map_err(IndexError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claims::{Claim, ClaimStore, OKF_CLAIM_TYPE};
    use crate::clock::FixedClock;
    use crate::index::test_support::*;

    #[test]
    fn loopback_embedder_deterministic() {
        let embedder = LoopbackEmbedder::new();
        let vectors = embedder.embed(&["trusted local memory retrieval"]);
        assert_eq!(vectors.len(), 1);
        assert_eq!(vectors[0].len(), embedder.dimension);
        let again = embedder.embed(&["trusted local memory retrieval"]);
        assert_eq!(vectors[0], again[0], "Embed is not deterministic");
    }

    #[test]
    fn loopback_embedder_distinct_inputs() {
        let embedder = LoopbackEmbedder::new();
        let first = embedder.embed(&["trusted local memory retrieval"]);
        let second = embedder.embed(&["quantum entanglement probability"]);
        assert_ne!(first[0], second[0]);
    }

    #[test]
    fn shares_meaningful_token_rejects_unrelated_text() {
        // Audit repro 13: the query shares nothing with the only claim.
        assert!(!shares_meaningful_token(
            "quantum chromodynamics lattice",
            "Deploy window  the deploy window is tuesday"
        ));
        // A paraphrase has no shared token: loopback-v1 cannot express it.
        assert!(!shares_meaningful_token(
            "when can we ship to prod",
            "Deploy window  the deploy window is tuesday"
        ));
    }

    #[test]
    fn shares_meaningful_token_rejects_stopwords_and_short_tokens() {
        // Only "is"/"the" overlap: a function word is not evidence.
        assert!(!shares_meaningful_token(
            "what is the capital of peru",
            "Deploy window  the deploy window is tuesday"
        ));
        // Tokens of two characters or fewer are ignored as well.
        assert!(!shares_meaningful_token("ai", "ai safety policy"));
        // A stopword-only claim text has nothing to match on.
        assert!(!shares_meaningful_token("the is of", "the is of"));
    }

    #[test]
    fn shares_meaningful_token_keeps_partial_overlap() {
        assert!(shares_meaningful_token(
            "quantum entanglement observer",
            "Entangled Observer  entanglement observer phenomena"
        ));
        assert!(shares_meaningful_token(
            "quantum entanglement observer",
            "Quantum Entanglement Observer  quantum entanglement observer discovery"
        ));
    }

    #[test]
    fn loopback_embedder_normalized() {
        let embedder = LoopbackEmbedder::new();
        let vectors = embedder.embed(&["local-first trusted memory", "", "x"]);
        for (index, vector) in vectors.iter().enumerate() {
            let sum_squares: f64 = vector.iter().map(|c| (*c as f64) * (*c as f64)).sum();
            assert!(
                (sum_squares - 1.0).abs() <= 1e-4 || sum_squares == 0.0,
                "vector {index} not L2-normalized: sum of squares = {sum_squares}"
            );
        }
    }

    #[test]
    fn loopback_embedder_search_vectors() {
        let (_dir, paths) = index_test_paths("embedder-search");
        let store = EmbeddingStore::new(paths.clone());
        let embedder = LoopbackEmbedder::new();
        let vectors = embedder.embed(&["quantum entanglement observer", "weather report"]);
        let records = vec![
            EmbeddingRecord {
                claim_id: "clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                dimension: 384,
                vector: vectors[0].clone(),
            },
            EmbeddingRecord {
                claim_id: "clm_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
                dimension: 384,
                vector: vectors[1].clone(),
            },
        ];
        store.store_vectors("research", &records).unwrap();

        let ids = store
            .search_vectors("research", "quantum entanglement observer", 10)
            .unwrap();
        let ids = ids.expect("vectors present");
        assert!(!ids.is_empty());
        assert_eq!(ids[0], records[0].claim_id);

        // Missing database falls back to None.
        assert!(store
            .search_vectors("missing", "quantum", 10)
            .unwrap()
            .is_none());

        // Empty store falls back to None.
        store.close("research").unwrap();
        assert!(store
            .search_vectors("research", "quantum", 10)
            .unwrap()
            .is_none());
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn loopback_embedder_store_round_trip() {
        let (_dir, paths) = index_test_paths("embedder-roundtrip");
        let store = EmbeddingStore::new(paths.clone());
        let records = vec![
            EmbeddingRecord {
                claim_id: "clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                dimension: 2,
                vector: vec![0.6, 0.8],
            },
            EmbeddingRecord {
                claim_id: "clm_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
                dimension: 2,
                vector: vec![1.0, 0.0],
            },
        ];
        store.store_vectors("research", &records).unwrap();
        assert_eq!(store.count("research").unwrap(), 2);
        store.close("research").unwrap();
        assert_eq!(store.count("research").unwrap(), 0);
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn loopback_embedder_store_empty_clears() {
        let (_dir, paths) = index_test_paths("embedder-empty");
        let store = EmbeddingStore::new(paths.clone());
        store
            .store_vectors(
                "research",
                &[EmbeddingRecord {
                    claim_id: "clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                    dimension: 2,
                    vector: vec![0.6, 0.8],
                }],
            )
            .unwrap();
        store.store_vectors("research", &[]).unwrap();
        assert_eq!(store.count("research").unwrap(), 0);
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn loopback_embedder_rebuild_stores_vectors() {
        let (_dir, paths) = index_test_paths("embedder-rebuild");
        let claim_store = ClaimStore::with_clock(
            paths.clone(),
            std::sync::Arc::new(FixedClock::new(fixed_index_now())),
        );
        let claim = index_claim(
            "clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "Loopback Embedding Memory",
            crate::claims::CLAIM_BASIS_OWNER,
        );
        claim_store.write_draft("research", claim).unwrap();
        claim_store
            .approve("research", "clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .unwrap();
        let store = EmbeddingStore::new(paths.clone());

        // Rebuild without --embed must not produce embeddings.
        let summary =
            rebuild_with_options(&paths, "research", RebuildOptions { embedding: false }).unwrap();
        assert_eq!(summary.embedding.indexed, 0);
        assert_eq!(store.count("research").unwrap(), 0);
        let status = store.summary("research", 1);
        assert_eq!(status.strategy, "lexical");
        assert_eq!(status.indexed, 0);
        assert_eq!(status.eligible, 0);
        assert!(!status.degraded.is_empty());

        // Rebuild with --embed stores vectors for approved claims.
        let summary =
            rebuild_with_options(&paths, "research", RebuildOptions { embedding: true }).unwrap();
        assert_eq!(summary.embedding.strategy, "loopback");
        assert_eq!(summary.embedding.indexed, 1);
        assert_eq!(summary.embedding.eligible, 1);
        assert_eq!(store.count("research").unwrap(), 1);
        let status = store.summary("research", 1);
        assert_eq!(status.strategy, "loopback");
        assert_eq!(status.model, "zbrain/loopback-v1");
        assert_eq!(status.indexed, 1);
        assert_eq!(status.eligible, 1);
        assert!(status.degraded.is_empty());

        // Rebuild without --embed clears previously stored embeddings.
        rebuild_with_options(&paths, "research", RebuildOptions { embedding: false }).unwrap();
        assert_eq!(store.count("research").unwrap(), 0);
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn loopback_embedder_rebuild_preserves_schema() {
        let (_dir, paths) = index_test_paths("embedder-schema");
        let claim_store = ClaimStore::with_clock(
            paths.clone(),
            std::sync::Arc::new(FixedClock::new(fixed_index_now())),
        );
        let claim = index_claim(
            "clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "Loopback Schema Memory",
            crate::claims::CLAIM_BASIS_OWNER,
        );
        claim_store.write_draft("research", claim).unwrap();
        claim_store
            .approve("research", "clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .unwrap();
        rebuild_with_options(&paths, "research", RebuildOptions { embedding: true }).unwrap();
        let store = IndexStore::new(paths.clone());
        store.check_fresh("research").unwrap();
        let database_path = store.database_path("research").unwrap();
        let conn = Connection::open(&database_path).unwrap();
        let version: i64 = conn
            .query_row("pragma user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, crate::index_state::INDEX_SCHEMA_VERSION);
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn loopback_tokens_exact() {
        assert_eq!(
            loopback_tokens("Hello, World! hello 123"),
            vec!["hello".to_string(), "world".to_string(), "123".to_string()]
        );
        assert!(loopback_tokens(":::").is_empty());
        let _ = Claim::default();
        let _ = OKF_CLAIM_TYPE;
    }
}
