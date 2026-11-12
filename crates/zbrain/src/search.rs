//! search.rs — port of internal/runtime/search.go: the legacy workspace-wide
//! markdown search used outside the FTS index (wiki/ only, token scoring).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::index::{split_alnum, IndexError};
use crate::paths::Paths;

#[derive(Debug, Clone, Serialize)]
pub struct SearchResult {
    pub path: String,
    pub tier: String,
    pub title: String,
    pub snippet: String,
    pub score: i64,
}

#[derive(Debug, Clone, Default)]
struct ParsedMarkdownNote {
    path: String,
    tier: String,
    title: String,
    headings: String,
    tags: String,
    body_text: String,
}

pub fn search_workspace(
    paths: &Paths,
    workspace: &str,
    query: &str,
    limit: i64,
) -> Result<Vec<SearchResult>, IndexError> {
    let limit = if limit <= 0 { 10 } else { limit };
    let tokens = query_tokens(query);
    if tokens.is_empty() {
        return Err(IndexError::Message("query is required".into()));
    }

    let wiki_root = paths.workspaces_dir.join(workspace).join("wiki");
    if let Err(source) = std::fs::symlink_metadata(&wiki_root) {
        if source.kind() == std::io::ErrorKind::NotFound {
            return Err(IndexError::Message(format!(
                "workspace {workspace:?} does not exist"
            )));
        }
        return Err(IndexError::Io(source));
    }

    let mut results: Vec<SearchResult> = Vec::new();
    let mut files: Vec<PathBuf> = Vec::new();
    collect_markdown_files(&wiki_root, &mut files)?;
    for path in files {
        let note = parse_markdown_note(&wiki_root, &path)?;
        let score = score_note(&note, &tokens);
        if score == 0 {
            continue;
        }
        results.push(SearchResult {
            path: note.path.clone(),
            tier: note.tier.clone(),
            title: note.title.clone(),
            snippet: make_snippet(&note.body_text, &note.headings, &tokens),
            score,
        });
    }

    results.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| left.path.cmp(&right.path))
    });
    results.truncate(limit as usize);
    Ok(results)
}

fn collect_markdown_files(root: &Path, files: &mut Vec<PathBuf>) -> Result<(), IndexError> {
    let mut children: Vec<PathBuf> = std::fs::read_dir(root)?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .collect();
    children.sort();
    for child in children {
        let info = std::fs::symlink_metadata(&child)?;
        if info.is_dir() {
            collect_markdown_files(&child, files)?;
            continue;
        }
        if child.extension().is_some_and(|ext| ext == "md") {
            files.push(child);
        }
    }
    Ok(())
}

fn parse_markdown_note(wiki_root: &Path, path: &Path) -> Result<ParsedMarkdownNote, IndexError> {
    let contents = std::fs::read(path)?;
    let rel = path
        .strip_prefix(wiki_root)
        .map_err(|err| IndexError::Io(std::io::Error::other(err)))?
        .to_string_lossy()
        .replace('\\', "/");
    let tier = rel.split('/').next().unwrap_or("").to_string();

    let text = String::from_utf8_lossy(&contents).into_owned();
    let (metadata, markdown) = split_frontmatter(&text);
    let (headings, body) = markdown_fields(markdown);
    let mut title = metadata.get("title").cloned().unwrap_or_default();
    if title.is_empty() {
        if let Some(first) = headings.first() {
            title = first.clone();
        }
    }
    if title.is_empty() {
        title = path
            .file_stem()
            .map(|stem| stem.to_string_lossy().to_string())
            .unwrap_or_default();
    }

    Ok(ParsedMarkdownNote {
        path: rel,
        tier,
        title,
        headings: headings.join(" "),
        tags: metadata.get("tags").cloned().unwrap_or_default(),
        body_text: body,
    })
}

fn split_frontmatter(contents: &str) -> (HashMap<String, String>, &str) {
    let mut metadata = HashMap::new();
    let Some(rest) = contents.strip_prefix("---\n") else {
        return (metadata, contents);
    };
    let Some(closing) = rest.find("\n---\n") else {
        return (metadata, contents);
    };
    let frontmatter = &rest[..closing];
    let body = &rest[closing + 5..];
    for line in frontmatter.split('\n') {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim().to_lowercase();
        let value = value.trim().trim_matches(|c| c == '"' || c == '\'');
        let value = value
            .strip_suffix(']')
            .unwrap_or(value)
            .strip_prefix('[')
            .unwrap_or(value);
        let value = value.replace(',', " ");
        metadata.insert(key, value.split_whitespace().collect::<Vec<_>>().join(" "));
    }
    (metadata, body)
}

fn markdown_fields(markdown: &str) -> (Vec<String>, String) {
    let mut headings: Vec<String> = Vec::new();
    let mut body_lines: Vec<String> = Vec::new();
    let mut in_fence = false;
    for line in markdown.split('\n') {
        let trimmed = line.trim();
        if trimmed.starts_with("```") || trimmed.starts_with("~~~") {
            in_fence = !in_fence;
            continue;
        }
        if in_fence {
            continue;
        }
        if trimmed.starts_with('#') {
            let heading = trimmed.trim_start_matches('#').trim().to_string();
            if !heading.is_empty() {
                headings.push(clean_markdown_text(&heading));
            }
            continue;
        }
        let cleaned = clean_markdown_text(trimmed);
        if !cleaned.is_empty() {
            body_lines.push(cleaned);
        }
    }
    (headings, body_lines.join(" "))
}

// Hand-rolled equivalent of Go's `\[([^\]]+)\]\([^)]+\)` -> "$1" replacement.
fn replace_markdown_links(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'[' {
            if let Some(close) = input[i + 1..].find(']') {
                let text = &input[i + 1..i + 1 + close];
                if !text.is_empty() && input[i + 1 + close..].starts_with("](") {
                    if let Some(paren) = input[i + close + 3..].find(')') {
                        if paren > 0 {
                            out.push_str(text);
                            i = i + close + 3 + paren + 1;
                            continue;
                        }
                    }
                }
            }
        }
        let ch = input[i..].chars().next().unwrap_or('\u{fffd}');
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn clean_markdown_text(input: &str) -> String {
    let replaced = replace_markdown_links(input);
    let trimmed = replaced.trim_start_matches(|c: char| {
        matches!(c, '>' | '-' | '*' | '_' | '+' | '.' | ' ' | ')' | '0'..='9')
    });
    let stripped: String = trimmed
        .chars()
        .filter(|c| !matches!(c, '`' | '*' | '_' | '#'))
        .collect();
    stripped.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn query_tokens(query: &str) -> Vec<String> {
    let mut tokens: Vec<String> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for field in split_alnum(&query.to_lowercase()) {
        if field.is_empty() || !seen.insert(field.clone()) {
            continue;
        }
        tokens.push(field);
    }
    tokens
}

fn score_note(note: &ParsedMarkdownNote, tokens: &[String]) -> i64 {
    let title = note.title.to_lowercase();
    let headings = note.headings.to_lowercase();
    let tags = note.tags.to_lowercase();
    let body = note.body_text.to_lowercase();
    let mut score: i64 = 0;
    for token in tokens {
        let token_score = title.matches(token.as_str()).count() as i64 * 5
            + headings.matches(token.as_str()).count() as i64 * 3
            + tags.matches(token.as_str()).count() as i64 * 2
            + body.matches(token.as_str()).count() as i64;
        if token_score == 0 {
            return 0;
        }
        score += token_score;
    }
    score
}

fn make_snippet(body: &str, headings: &str, tokens: &[String]) -> String {
    let text: String = if body.is_empty() {
        headings.to_string()
    } else {
        body.to_string()
    };
    let lower = text.to_lowercase();
    let mut start: usize = 0;
    for token in tokens {
        if let Some(index) = lower.find(token.as_str()) {
            start = index.saturating_sub(40);
            break;
        }
    }
    let mut end = start + 160;
    if end > text.len() {
        end = text.len();
    }
    // Go slices bytes and tolerates split runes; floor to char boundaries.
    while start > 0 && !text.is_char_boundary(start) {
        start -= 1;
    }
    while end < text.len() && !text.is_char_boundary(end) {
        end += 1;
    }
    let mut snippet = text[start..end].trim().to_string();
    if start > 0 {
        snippet = format!("…{snippet}");
    }
    if end < text.len() {
        snippet.push('…');
    }
    snippet
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claims::CLAIM_STATUS_APPROVED;
    use crate::clock::FixedClock;
    use crate::config::ensure_config;
    use crate::index::{fts5_query, IndexStore, SearchOptions};
    use crate::paths::Options;
    use chrono::{TimeZone, Utc};

    fn search_test_paths(name: &str) -> (PathBuf, Paths) {
        let dir = std::env::temp_dir().join(format!("zbrain-search-{}-{name}", std::process::id()));
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
        crate::workspace::create_workspace(
            &paths,
            "research",
            &FixedClock::new(Utc.with_ymd_and_hms(2026, 7, 30, 10, 0, 0).unwrap()),
        )
        .unwrap();
        (dir, paths)
    }

    #[test]
    fn search_workspace_parses_markdown_fields() {
        let (_dir, paths) = search_test_paths("markdown");
        let note_path = paths
            .workspaces_dir
            .join("research/wiki/mental-models/retrieval.md");
        let contents = "---\ntitle: Markdown Retrieval\ntags: [go, search]\n---\n\n# Query Pipeline\n\nUse [SQLite FTS5](https://sqlite.org) for local-first memory search.\n\n```go\n// noisy code should not become body text\nsecretSearchIdentifier\n```\n";
        std::fs::write(&note_path, contents).unwrap();

        let results = search_workspace(&paths, "research", "local memory", 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].title, "Markdown Retrieval");
        assert_eq!(results[0].tier, "mental-models");
        assert_eq!(results[0].path, "mental-models/retrieval.md");
        assert!(!results[0].snippet.is_empty());
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn search_workspace_supports_unicode_query_tokens() {
        let (_dir, paths) = search_test_paths("unicode");
        let note_path = paths
            .workspaces_dir
            .join("research/wiki/projects/tieng-viet.md");
        std::fs::write(
            &note_path,
            "# Ghi nhớ tiếng Việt\n\nAgent cần tìm kiếm tri thức nội bộ.",
        )
        .unwrap();
        let results = search_workspace(&paths, "research", "tìm kiếm", 10).unwrap();
        assert_eq!(results.len(), 1);
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn search_workspace_searches_only_wiki() {
        let (_dir, paths) = search_test_paths("wiki-only");
        let evidence_path = paths
            .workspaces_dir
            .join("research/evidence/sources/raw.md");
        std::fs::write(&evidence_path, "poison-token should never be retrieved").unwrap();
        let results = search_workspace(&paths, "research", "poison-token", 10).unwrap();
        assert_eq!(results.len(), 0);
        let _ = std::fs::remove_dir_all(&_dir);
    }

    #[test]
    fn fts5_query_cases() {
        let cases: Vec<(&str, &str, &str)> = vec![
            ("and default", "hello world", "\"hello\" \"world\""),
            ("phrase keep", "\"foo bar\"", "\"foo bar\""),
            ("wildcard keep", "foo*", "foo*"),
            ("wildcard case lower", "Foo*", "foo*"),
            ("phrase not split", "\"exact phrase\"", "\"exact phrase\""),
            (
                "mixed phrase wildcard",
                "hello \"exact phrase\" foo*",
                "\"hello\" \"exact phrase\" foo*",
            ),
            ("near reject upper", "foo NEAR bar", ""),
            ("near reject lower", "foo near bar", ""),
            (
                "near inside phrase allowed",
                "\"foo NEAR bar\"",
                "\"foo near bar\"",
            ),
            ("dedup", "hello hello", "\"hello\""),
            ("single token", "hello", "\"hello\""),
            ("empty", "   ", ""),
            ("prefix with hyphen wildcard", "foo-bar*", "\"foo\" bar*"),
        ];
        for (name, query, want) in cases {
            let got = fts5_query(query);
            assert_eq!(got, want, "fts5Query({query:?}) [{name}]");
        }
    }

    #[test]
    fn fts5_query_rejects_near_in_search() {
        let (_dir, paths) = search_test_paths("near");
        let idx = IndexStore::new(paths.clone());
        idx.rebuild("research").unwrap();
        // NEAR should be rejected as query is required.
        assert!(idx
            .search(
                "research",
                SearchOptions {
                    query: "foo NEAR bar".into(),
                    statuses: vec![CLAIM_STATUS_APPROVED.into()],
                    limit: 10,
                },
            )
            .is_err());
        // Phrase should succeed (no error, even if no results).
        assert!(idx
            .search(
                "research",
                SearchOptions {
                    query: "\"hello world\"".into(),
                    statuses: vec![CLAIM_STATUS_APPROVED.into()],
                    limit: 10,
                },
            )
            .is_ok());
        // Wildcard should succeed.
        assert!(idx
            .search(
                "research",
                SearchOptions {
                    query: "hell*".into(),
                    statuses: vec![CLAIM_STATUS_APPROVED.into()],
                    limit: 10,
                },
            )
            .is_ok());
        let _ = std::fs::remove_dir_all(&_dir);
    }
}
