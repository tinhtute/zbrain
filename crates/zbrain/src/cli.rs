//! cli.rs — port of internal/cli/cli.go: manual arg parsing, dispatch,
//! JSON/text output, and exit-code semantics for every command.
//!
//! The parser is intentionally manual (no clap): Go parses flags by hand and
//! the surface discipline (unknown-flag errors, `--flag value` shape, help
//! gating) is part of the user-visible contract.

use std::collections::HashMap;
use std::io::{Read, Write};

use serde::Serialize;

use crate::approval::{approval_show, run_grant, run_grant_batch};
use crate::claims::{self, Claim, ClaimStore};
use crate::clock::{rfc3339, Clock, SystemClock};
use crate::embedder::{rebuild_with_options, RebuildOptions};
use crate::evidence::EvidenceStore;
use crate::index::{approved_catalog, IndexStore, IndexSummary};
use crate::lifecycle::ClaimMutationOptions;
use crate::paths::Paths;
use crate::query::{trusted_query, TrustedQueryOptions};
use crate::setup::run_setup;
use crate::term::{ApprovalPrompt, StdinPrompt};
use crate::workspace::{create_workspace, marshal_current, resolve_current_workspace};

pub const VERSION: &str = "0.4.0";

/// CLI failure modes mirror Go's `commandExitError`: usage problems exit 2,
/// unknown commands/subcommands and runtime failures exit 1.
#[derive(Debug)]
pub enum CliError {
    Usage(String),
    Failure(String),
}

impl CliError {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Usage(_) => 2,
            Self::Failure(_) => 1,
        }
    }

    pub fn message(&self) -> &str {
        match self {
            Self::Usage(message) | Self::Failure(message) => message,
        }
    }

    fn usage(message: impl std::fmt::Display) -> Self {
        Self::Usage(message.to_string())
    }

    fn failure(message: impl std::fmt::Display) -> Self {
        Self::Failure(message.to_string())
    }
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message())
    }
}

impl std::error::Error for CliError {}

/// Source of owner confirmation lines for the grant walk. The binary always
/// uses [`PromptSource::Stdin`] (TTY-gated like the Go oracle); tests inject
/// [`PromptSource::Scripted`] lines, or [`PromptSource::Live`] when the answer
/// depends on what the command just printed (key recovery).
#[derive(Default)]
pub enum PromptSource {
    #[default]
    Stdin,
    Scripted(Vec<String>),
    Live(Box<dyn FnMut() -> String>),
}

impl std::fmt::Debug for PromptSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stdin => formatter.write_str("Stdin"),
            Self::Scripted(lines) => formatter.debug_tuple("Scripted").field(lines).finish(),
            Self::Live(_) => formatter.write_str("Live"),
        }
    }
}

struct LivePrompt {
    answer: Box<dyn FnMut() -> String>,
}

impl ApprovalPrompt for LivePrompt {
    fn read_confirmation(&mut self) -> std::io::Result<String> {
        Ok((self.answer)())
    }
}

struct VecPrompt {
    lines: std::collections::VecDeque<String>,
}

impl ApprovalPrompt for VecPrompt {
    fn read_confirmation(&mut self) -> std::io::Result<String> {
        self.lines
            .pop_front()
            .ok_or_else(|| std::io::Error::other("approval grant requires the confirmation input"))
    }
}

pub struct App {
    pub stdout: Box<dyn std::io::Write>,
    pub stderr: Box<dyn std::io::Write>,
    pub stdin: Box<dyn std::io::Read>,
    pub paths: Paths,
    pub prompt: PromptSource,
    pub clock: std::sync::Arc<dyn Clock>,
}

#[derive(Clone)]
struct ArcClock(std::sync::Arc<dyn Clock>);

impl Clock for ArcClock {
    fn now(&self) -> chrono::DateTime<chrono::Utc> {
        self.0.now()
    }
}

impl App {
    pub fn run(&mut self, args: &[String]) -> Result<(), CliError> {
        if args.is_empty() {
            self.print_help();
            return Ok(());
        }
        match args[0].as_str() {
            "--help" | "-h" | "help" => {
                if args.len() != 1 {
                    return Err(CliError::usage("usage: zbrain --help"));
                }
                self.print_help();
                Ok(())
            }
            "--version" | "version" => {
                if help_requested(&args[1..]) {
                    self.print_version_help();
                    return Ok(());
                }
                if args.len() > 1 {
                    if args[1].starts_with('-') {
                        return Err(unknown_flag(&args[1]));
                    }
                    return Err(CliError::usage("version accepts no arguments"));
                }
                let _ = writeln!(self.stdout, "{VERSION}");
                Ok(())
            }
            "setup" => self.run_setup(&args[1..]),
            "workspace" => self.run_workspace(&args[1..]),
            "evidence" => self.run_evidence(&args[1..]),
            "claim" => self.run_claim(&args[1..]),
            "migrate" => self.run_migrate(&args[1..]),
            "reindex" => self.run_reindex(&args[1..]),
            "ask" => self.run_ask(&args[1..]),
            "status" => self.run_status(&args[1..]),
            "doctor" => self.run_doctor(&args[1..]),
            "mcp" => self.run_mcp(&args[1..]),
            "view" => self.run_view(&args[1..]),
            "approval" => self.run_approval(&args[1..]),
            "key" => self.run_key(&args[1..]),
            other => {
                if other.starts_with('-') {
                    return Err(unknown_flag(other));
                }
                Err(CliError::failure(format!("unknown command: {other}")))
            }
        }
    }

    fn run_status(&mut self, args: &[String]) -> Result<(), CliError> {
        if help_requested(args) {
            let _ = writeln!(self.stdout, "Usage: zbrain status [--workspace <name>]");
            return Ok(());
        }
        let parsed = parse_flags(args, &["workspace"])?;
        if !parsed.rest.is_empty() {
            return Err(CliError::usage("usage: zbrain status [--workspace <name>]"));
        }
        let workspace = self.resolve_workspace(parsed.single("workspace"))?;
        let idx = IndexStore::new(self.paths.clone());
        let mut summary = IndexSummary {
            workspace: workspace.clone(),
            ..IndexSummary::default()
        };
        match ClaimStore::new(self.paths.clone()).scan_workspace_trusted(&workspace) {
            Ok(scan) => {
                summary.approved = scan.claims.len() as i64;
                summary.invalid = scan.invalid.len() as i64;
                summary.invalid_count = scan.invalid.len() as i64;
                summary.invalid_claims = scan.invalid.iter().map(Into::into).collect();
                summary.catalog = Some(approved_catalog(&scan.claims));
            }
            Err(_) => {
                summary.catalog = None;
            }
        }
        summary.embedding = crate::embedder::EmbeddingStore::new(self.paths.clone())
            .summary(&workspace, summary.approved);
        if let Err(err) = idx.check_fresh(&workspace) {
            summary.rebuild_state = crate::index::REBUILD_STATUS_REJECTED.to_string();
            if summary.invalid == 0 {
                summary.invalid_claims = vec![crate::index::InvalidClaimSerde {
                    path: String::new(),
                    error: err.to_string(),
                }];
            }
        }
        #[derive(Serialize)]
        struct StatusOutput {
            schema_version: u32,
            #[serde(flatten)]
            summary: IndexSummary,
        }
        write_json(
            &mut self.stdout,
            &StatusOutput {
                schema_version: 2,
                summary,
            },
        )
    }

    fn run_doctor(&mut self, args: &[String]) -> Result<(), CliError> {
        if help_requested(args) {
            let _ = writeln!(
                self.stdout,
                "Usage: zbrain doctor [--workspace <name>] [--probe-embedder]"
            );
            return Ok(());
        }
        let mut probe = false;
        let mut filtered: Vec<String> = Vec::with_capacity(args.len());
        for arg in args {
            if arg == "--probe-embedder" {
                probe = true;
                continue;
            }
            filtered.push(arg.clone());
        }
        let parsed = parse_flags(&filtered, &["workspace"])?;
        if !parsed.rest.is_empty() {
            return Err(CliError::usage(
                "usage: zbrain doctor [--workspace <name>] [--probe-embedder]",
            ));
        }
        let workspace = self.resolve_workspace(parsed.single("workspace"))?;
        let mut findings: Vec<String> = Vec::new();
        let mut freshness_failed = false;
        if let Err(err) = IndexStore::new(self.paths.clone()).check_fresh(&workspace) {
            findings.push(err.to_string());
            freshness_failed = true;
        }
        let structural = crate::lint::structural_findings(&self.paths, &workspace)
            .map_err(|err| CliError::failure(err.to_string()))?;
        findings.extend(structural.iter().cloned());
        match EvidenceStore::new(self.paths.clone()).check_drift(&workspace) {
            Err(err) => findings.push(format!("evidence drift check error: {err}")),
            Ok(report) => {
                for finding in &report.findings {
                    if finding.status == crate::evidence::EvidenceDriftStatus::Unchanged {
                        continue;
                    }
                    findings.push(format!(
                        "evidence {} drift: {}; {}",
                        finding.id,
                        drift_status_str(finding.status),
                        finding.recovery_action
                    ));
                }
            }
        }
        match crate::signing::KeyStore::open(&self.paths) {
            Err(err) => findings.push(format!("approval signing key unavailable: {err}")),
            Ok(_) => {
                let unsigned = ClaimStore::new(self.paths.clone())
                    .unsigned_approved_claims(&workspace)
                    .map_err(|err| CliError::failure(err.to_string()))?;
                if !unsigned.is_empty() {
                    findings.push(format!(
                        "{} approved claims are unsigned; run `zbrain claim resign --workspace {}`",
                        unsigned.len(),
                        workspace
                    ));
                }
            }
        }
        if probe {
            let emb_store = crate::embedder::EmbeddingStore::new(self.paths.clone());
            match emb_store.count(&workspace) {
                Err(err) => findings.push(format!("embedder probe error: {err}")),
                Ok(0) => findings.push(
                    "embedder probe unavailable: no embeddings found; run zbrain reindex --embed"
                        .to_string(),
                ),
                Ok(_) => {}
            }
        }
        let status = if findings.is_empty() {
            "healthy"
        } else {
            "degraded"
        };
        let mut next_action = "zbrain reindex";
        if !freshness_failed && !structural.is_empty() {
            next_action = "review structural findings";
        }
        #[derive(Serialize)]
        struct DoctorOutput<'a> {
            schema_version: u32,
            workspace: &'a str,
            status: &'a str,
            findings: &'a [String],
            next_action: &'a str,
        }
        write_json(
            &mut self.stdout,
            &DoctorOutput {
                schema_version: 2,
                workspace: &workspace,
                status,
                findings: &findings,
                next_action,
            },
        )?;
        if !findings.is_empty() {
            return Err(CliError::usage("doctor found domain findings"));
        }
        Ok(())
    }

    fn run_mcp(&mut self, args: &[String]) -> Result<(), CliError> {
        if args.is_empty() {
            return Err(CliError::usage("mcp requires a subcommand: serve"));
        }
        if help_requested(args) {
            self.print_mcp_help();
            return Ok(());
        }
        if args[0].starts_with('-') {
            return Err(unknown_flag(&args[0]));
        }
        if args[0] != "serve" {
            return Err(CliError::usage("mcp requires subcommand: serve"));
        }
        if help_requested(&args[1..]) {
            self.print_mcp_serve_help();
            return Ok(());
        }
        let parsed = parse_flags(&args[1..], NO_FLAGS)?;
        if !parsed.rest.is_empty() {
            return Err(CliError::usage("usage: zbrain mcp serve"));
        }
        let stderr = crate::mcp::SafeStderr::new(Box::new(StderrWriter));
        crate::mcp::serve(crate::mcp::McpOptions {
            version: VERSION.to_string(),
            stderr,
            paths: Some(self.paths.clone()),
            clock: Some(Box::new(ArcClock(self.clock.clone())) as Box<dyn Clock>),
        })
        .map_err(|err| CliError::failure(err.to_string()))
    }

    fn run_view(&mut self, args: &[String]) -> Result<(), CliError> {
        if help_requested(args) {
            self.print_view_help();
            return Ok(());
        }
        let parsed = parse_flags(args, NO_FLAGS)?;
        if !parsed.rest.is_empty() {
            return Err(CliError::usage("usage: zbrain view"));
        }
        let mut server = crate::view::Server::new(self.paths.clone());
        let url = server
            .listen()
            .map_err(|err| CliError::failure(err.to_string()))?;
        let _ = writeln!(self.stdout, "viewer: {url}");
        let _ = self.stdout.flush();
        server
            .serve()
            .map_err(|err| CliError::failure(err.to_string()))
    }

    fn run_approval(&mut self, args: &[String]) -> Result<(), CliError> {
        if args.is_empty() {
            return Err(CliError::usage(
                "approval requires a subcommand: show or grant",
            ));
        }
        if help_requested(args) {
            self.print_approval_help();
            return Ok(());
        }
        if args[0].starts_with('-') {
            return Err(unknown_flag(&args[0]));
        }
        match args[0].as_str() {
            "show" => self.run_approval_show(&args[1..]),
            "grant" => self.run_approval_grant(&args[1..]),
            other => Err(CliError::failure(format!(
                "unknown approval subcommand: {other}"
            ))),
        }
    }

    fn run_approval_show(&mut self, args: &[String]) -> Result<(), CliError> {
        if help_requested(args) {
            self.print_approval_show_help();
            return Ok(());
        }
        let parsed = parse_flags(args, NO_FLAGS)?;
        if parsed.rest.len() != 1 {
            return Err(CliError::usage(
                "usage: zbrain approval show <challenge-id>",
            ));
        }
        let (challenge, workspace) = self.find_challenge(&parsed.rest[0])?;
        write_json(&mut self.stdout, &approval_show(&challenge, &workspace))
    }

    fn run_approval_grant(&mut self, args: &[String]) -> Result<(), CliError> {
        if help_requested(args) {
            self.print_approval_grant_help();
            return Ok(());
        }
        let parsed = parse_flags(args, NO_FLAGS)?;
        if parsed.rest.len() != 1 {
            return Err(CliError::usage(
                "usage: zbrain approval grant <challenge-id>",
            ));
        }
        let (challenge, workspace) = self.find_challenge(&parsed.rest[0])?;
        let store =
            crate::approval::ChallengeStore::with_clock(self.paths.clone(), self.clock.clone());
        if !challenge.items.is_empty() {
            let mut prompt = self.make_prompt()?;
            let output = run_grant_batch(
                &store,
                &challenge,
                &workspace,
                &mut self.stderr,
                &mut *prompt,
            )
            .map_err(|err| CliError::failure(err.to_string()))?;
            return write_json(&mut self.stdout, &output);
        }
        let mut prompt = self.make_prompt()?;
        let output = run_grant(
            &store,
            &challenge,
            &workspace,
            &mut self.stderr,
            &mut *prompt,
        )
        .map_err(|err| CliError::failure(err.to_string()))?;
        write_json(&mut self.stdout, &output)
    }

    fn make_prompt(&mut self) -> Result<Box<dyn ApprovalPrompt>, CliError> {
        match std::mem::replace(&mut self.prompt, PromptSource::Stdin) {
            PromptSource::Stdin => {
                self.prompt = PromptSource::Stdin;
                StdinPrompt::new()
                    .map(|prompt| Box::new(prompt) as Box<dyn ApprovalPrompt>)
                    .map_err(|err| CliError::failure(err.to_string()))
            }
            PromptSource::Scripted(lines) => Ok(Box::new(VecPrompt {
                lines: lines.into_iter().collect(),
            })),
            PromptSource::Live(answer) => Ok(Box::new(LivePrompt { answer })),
        }
    }

    fn find_challenge(
        &self,
        challenge_id: &str,
    ) -> Result<(crate::approval::Challenge, String), CliError> {
        let store =
            crate::approval::ChallengeStore::with_clock(self.paths.clone(), self.clock.clone());
        if let Ok(current) = resolve_current_workspace(&self.paths) {
            if let Ok(challenge) = store.read(&current.workspace, challenge_id) {
                return Ok((challenge, current.workspace));
            }
        }
        store
            .find_challenge(challenge_id)
            .map_err(|err| CliError::failure(err.to_string()))
    }

    fn run_setup(&mut self, args: &[String]) -> Result<(), CliError> {
        if help_requested(args) {
            self.print_setup_help();
            return Ok(());
        }
        let parsed = parse_flags(args, NO_FLAGS)?;
        if !parsed.rest.is_empty() {
            return Err(CliError::usage("setup accepts no arguments"));
        }
        let summary = run_setup(&self.paths).map_err(|err| CliError::failure(err.to_string()))?;
        let _ = writeln!(
            self.stdout,
            "zbrain setup complete\nruntime: {}\nconfig_created: {}\nassets_copied: {}\nassets_skipped: {}",
            self.paths.runtime_dir.display(),
            summary.config_created,
            summary.assets_copied,
            summary.assets_skipped
        );
        Ok(())
    }

    fn run_ask(&mut self, args: &[String]) -> Result<(), CliError> {
        if help_requested(args) {
            self.print_ask_help();
            return Ok(());
        }
        let mut embed = false;
        let mut filtered: Vec<String> = Vec::with_capacity(args.len());
        for arg in args {
            if arg == "--embed" {
                embed = true;
                continue;
            }
            filtered.push(arg.clone());
        }
        let parsed = parse_ask_flags(&filtered)?;
        if parsed.rest.is_empty() {
            return Err(CliError::usage("usage: zbrain ask [--workspace <name>] [--include <name>]... [--embed] [--after <time>] [--before <time>] [--as-of <time>] <query>"));
        }
        let response = trusted_query(
            &self.paths,
            TrustedQueryOptions {
                workspace: parsed.workspace,
                includes: parsed.includes,
                query: parsed.rest.join(" "),
                limit: 10,
                embedding: embed,
                after: parsed.after,
                before: parsed.before,
                as_of: parsed.as_of,
            },
        )
        .map_err(|err| CliError::failure(err.to_string()))?;
        write_json(&mut self.stdout, &response)
    }

    fn run_reindex(&mut self, args: &[String]) -> Result<(), CliError> {
        if help_requested(args) {
            self.print_reindex_help();
            return Ok(());
        }
        let mut embed = false;
        let mut filtered: Vec<String> = Vec::with_capacity(args.len());
        for arg in args {
            if arg == "--embed" {
                embed = true;
                continue;
            }
            filtered.push(arg.clone());
        }
        let parsed = parse_flags(&filtered, &["workspace"])?;
        if !parsed.rest.is_empty() {
            return Err(CliError::usage(
                "usage: zbrain reindex [--workspace <name>] [--embed]",
            ));
        }
        let workspace = self.resolve_workspace(parsed.single("workspace"))?;
        let summary =
            rebuild_with_options(&self.paths, &workspace, RebuildOptions { embedding: embed })
                .map_err(|err| CliError::failure(err.to_string()))?;
        #[derive(Serialize)]
        struct ReindexOutput {
            schema_version: u32,
            #[serde(flatten)]
            summary: IndexSummary,
        }
        write_json(
            &mut self.stdout,
            &ReindexOutput {
                schema_version: 1,
                summary,
            },
        )
    }

    fn run_evidence(&mut self, args: &[String]) -> Result<(), CliError> {
        if args.is_empty() {
            return Err(CliError::usage(
                "evidence requires a subcommand: add or check",
            ));
        }
        if help_requested(args) {
            self.print_evidence_help();
            return Ok(());
        }
        if args[0].starts_with('-') {
            return Err(unknown_flag(&args[0]));
        }
        match args[0].as_str() {
            "add" => self.run_evidence_add(&args[1..]),
            "check" => self.run_evidence_check(&args[1..]),
            _ => Err(CliError::usage(
                "evidence requires a subcommand: add or check",
            )),
        }
    }

    fn run_evidence_add(&mut self, args: &[String]) -> Result<(), CliError> {
        if help_requested(args) {
            self.print_evidence_add_help();
            return Ok(());
        }
        let parsed = parse_flags(args, &["file", "origin", "media-type", "workspace"])?;
        if !parsed.rest.is_empty() {
            return Err(CliError::usage("usage: zbrain evidence add --file <path> --origin <uri-or-path> [--media-type <type>] [--workspace <name>]"));
        }
        let file = parsed.single("file");
        let origin = parsed.single("origin");
        if file.is_empty() || origin.is_empty() {
            return Err(CliError::usage("evidence add requires --file and --origin"));
        }
        let workspace = self.resolve_workspace(parsed.single("workspace"))?;
        let evidence = EvidenceStore::new(self.paths.clone())
            .add_file(
                &workspace,
                std::path::Path::new(&file),
                &origin,
                parsed.single("media-type").as_str(),
                &self.clock,
            )
            .map_err(|err| CliError::failure(err.to_string()))?;
        #[derive(Serialize)]
        struct EvidenceAddOutput<'a> {
            schema_version: u32,
            workspace: &'a str,
            id: &'a str,
            origin: &'a str,
            captured_at: &'a str,
            media_type: &'a str,
            byte_length: i64,
            sha256: &'a str,
            deduped: bool,
        }
        write_json(
            &mut self.stdout,
            &EvidenceAddOutput {
                schema_version: 1,
                workspace: &workspace,
                id: &evidence.id,
                origin: &evidence.origin,
                captured_at: &evidence.captured_at,
                media_type: &evidence.media_type,
                byte_length: evidence.byte_length,
                sha256: &evidence.sha256,
                deduped: evidence.deduped,
            },
        )
    }

    fn run_evidence_check(&mut self, args: &[String]) -> Result<(), CliError> {
        if help_requested(args) {
            self.print_evidence_check_help();
            return Ok(());
        }
        let parsed = parse_flags(args, &["workspace"])?;
        if !parsed.rest.is_empty() {
            return Err(CliError::usage(
                "usage: zbrain evidence check [--workspace <name>]",
            ));
        }
        let workspace = self.resolve_workspace(parsed.single("workspace"))?;
        let report = EvidenceStore::new(self.paths.clone())
            .check_drift(&workspace)
            .map_err(|err| CliError::failure(err.to_string()))?;
        #[derive(Serialize)]
        struct EvidenceCheckOutput<'a> {
            schema_version: u32,
            workspace: &'a str,
            findings: &'a [crate::evidence::EvidenceDriftFinding],
        }
        write_json(
            &mut self.stdout,
            &EvidenceCheckOutput {
                schema_version: 1,
                workspace: &workspace,
                findings: &report.findings,
            },
        )
    }

    fn run_claim(&mut self, args: &[String]) -> Result<(), CliError> {
        if args.is_empty() {
            return Err(CliError::usage(
                "claim requires a subcommand: draft, approve, resign, supersede, or revoke",
            ));
        }
        if help_requested(args) {
            self.print_claim_help();
            return Ok(());
        }
        if args[0].starts_with('-') {
            return Err(unknown_flag(&args[0]));
        }
        match args[0].as_str() {
            "draft" => self.run_claim_draft(&args[1..]),
            "approve" => self.run_claim_approve(&args[1..]),
            "resign" => self.run_claim_resign(&args[1..]),
            "supersede" => self.run_claim_supersede(&args[1..]),
            "revoke" => self.run_claim_revoke(&args[1..]),
            other => Err(CliError::failure(format!(
                "unknown claim subcommand: {other}"
            ))),
        }
    }

    fn run_claim_draft(&mut self, args: &[String]) -> Result<(), CliError> {
        if help_requested(args) {
            self.print_claim_draft_help();
            return Ok(());
        }
        let parsed = parse_flags(
            args,
            &[
                "tier",
                "title",
                "basis",
                "evidence",
                "support",
                "conflicts-with",
                "workspace",
            ],
        )?;
        if !parsed.rest.is_empty() {
            return Err(CliError::usage("usage: zbrain claim draft --tier <tier> --title <title> --basis <owner|evidence|derived> [--evidence <id>]... [--support <id>]... [--conflicts-with <id>]... [--workspace <name>]"));
        }
        let workspace = self.resolve_workspace(parsed.single("workspace"))?;
        let mut body = String::new();
        self.stdin
            .read_to_string(&mut body)
            .map_err(|err| CliError::failure(err.to_string()))?;
        let id = claims::new_claim_id().map_err(|err| CliError::failure(err.to_string()))?;
        let claim = Claim {
            claim_type: claims::OKF_CLAIM_TYPE.to_string(),
            id,
            tier: parsed.single("tier"),
            status: claims::CLAIM_STATUS_DRAFT.to_string(),
            title: parsed.single("title"),
            basis: parsed.single("basis"),
            created_at: rfc3339(self.clock.now()),
            created_by: "owner".to_string(),
            evidence_ids: parsed.all("evidence"),
            supporting_claim_ids: parsed.all("support"),
            conflicts_with: parsed.all("conflicts-with"),
            body,
            ..Claim::default()
        };
        IndexStore::new(self.paths.clone())
            .mark_dirty(&workspace)
            .map_err(|err| CliError::failure(err.to_string()))?;
        let created = ClaimStore::new(self.paths.clone())
            .write_draft(&workspace, claim)
            .map_err(|err| CliError::failure(err.to_string()))?;
        self.write_claim_mutation(&workspace, &created)
    }

    fn run_claim_approve(&mut self, args: &[String]) -> Result<(), CliError> {
        if help_requested(args) {
            self.print_claim_approve_help();
            return Ok(());
        }
        let parsed = parse_flags(args, &["workspace"])?;
        if parsed.rest.len() != 1 {
            return Err(CliError::usage(
                "usage: zbrain claim approve <id> [--workspace <name>]",
            ));
        }
        let workspace = self.resolve_workspace(parsed.single("workspace"))?;
        // The owner ceremony is the only approval path: refuse a piped caller
        // before reading the claim, so a script learns nothing and mutates
        // nothing.
        let mut prompt = self.make_prompt()?;
        // Fail before a challenge is prepared when the owner key is missing or
        // invalid: nothing is mutated and no token is issued.
        crate::signing::KeyStore::open(&self.paths)
            .map_err(|err| CliError::failure(format!("approval signing key unavailable: {err}")))?;
        let store = ClaimStore::with_clock(self.paths.clone(), self.clock.clone());
        let prepare = store
            .approve_challenge_prepare(&workspace, &parsed.rest[0])
            .map_err(|err| CliError::failure(err.to_string()))?;
        let prepared = store
            .prepare_challenge(&workspace, prepare)
            .map_err(|err| CliError::failure(err.to_string()))?;
        let challenges =
            crate::approval::ChallengeStore::with_clock(self.paths.clone(), self.clock.clone());
        let granted = run_grant(
            &challenges,
            &prepared.challenge,
            &workspace,
            &mut self.stderr,
            &mut *prompt,
        )
        .map_err(|err| CliError::failure(err.to_string()))?;
        let token = granted.token;
        IndexStore::new(self.paths.clone())
            .mark_dirty(&workspace)
            .map_err(|err| CliError::failure(err.to_string()))?;
        let claim = store
            .apply_challenge(
                &workspace,
                &prepared.challenge.id,
                &token,
                ClaimMutationOptions::default(),
            )
            .map_err(|err| CliError::failure(err.to_string()))?;
        self.write_claim_mutation(&workspace, &claim)
    }

    /// Batch owner ceremony: re-sign every approved claim with the active
    /// owner key. Lists id, title, approval time, and digest, honors
    /// `--exclude`, and binds the ordered (id, digest) list with the same
    /// action digest the approval ceremony uses.
    fn run_claim_resign(&mut self, args: &[String]) -> Result<(), CliError> {
        if help_requested(args) {
            self.print_claim_resign_help();
            return Ok(());
        }
        let parsed = parse_flags(args, &["workspace", "exclude"])?;
        if !parsed.rest.is_empty() {
            return Err(CliError::usage(
                "usage: zbrain claim resign [--workspace <name>] [--exclude <id>]...",
            ));
        }
        let workspace = self.resolve_workspace(parsed.single("workspace"))?;
        let excludes = parsed.all("exclude");
        let mut prompt = self.make_prompt()?;
        let store = ClaimStore::with_clock(self.paths.clone(), self.clock.clone());
        let candidates = store
            .resign_candidates(&workspace)
            .map_err(|err| CliError::failure(err.to_string()))?;
        #[derive(Serialize)]
        struct ResignOutput {
            schema_version: u32,
            workspace: String,
            #[serde(flatten)]
            report: crate::lifecycle::ResignReport,
        }
        if candidates.is_empty() {
            return write_json(
                &mut self.stdout,
                &ResignOutput {
                    schema_version: 1,
                    workspace,
                    report: crate::lifecycle::ResignReport::default(),
                },
            );
        }
        let to_sign: Vec<&crate::lifecycle::ResignCandidate> = candidates
            .iter()
            .filter(|candidate| !excludes.contains(&candidate.id))
            .collect();
        if to_sign.is_empty() {
            return Err(CliError::failure(
                "every approved claim is excluded; nothing to sign",
            ));
        }
        for candidate in &candidates {
            let marker = if excludes.contains(&candidate.id) {
                "excluded"
            } else {
                "sign"
            };
            let _ = writeln!(
                self.stderr,
                "{marker} {} {} approved {} {}",
                candidate.id, candidate.title, candidate.verified_at, candidate.digest
            );
        }
        let items: Vec<crate::approval::ChallengeItem> = to_sign
            .iter()
            .map(|candidate| crate::approval::ChallengeItem {
                claim_id: candidate.id.clone(),
                canonical_draft_digest: candidate.digest.clone(),
            })
            .collect();
        // The confirmed (id, digest) pairs are the whole mandate: a claim
        // written or changed while the prompt waits is skipped, not signed.
        let targets: Vec<crate::lifecycle::ResignTarget> = to_sign
            .iter()
            .map(|candidate| crate::lifecycle::ResignTarget {
                id: candidate.id.clone(),
                digest: candidate.digest.clone(),
            })
            .collect();
        let action_digest =
            crate::approval::compute_challenge_action_digest(&crate::approval::ChallengePrepare {
                workspace: workspace.clone(),
                operation: "resign".to_string(),
                items,
                ..crate::approval::ChallengePrepare::default()
            });
        let _ = writeln!(self.stderr, "action digest: {action_digest}");
        let _ = write!(
            self.stderr,
            "confirm the last 16 hex characters of the action digest: "
        );
        let _ = self.stderr.flush();
        let confirm = prompt
            .read_confirmation()
            .map_err(|err| CliError::failure(err.to_string()))?;
        if confirm.trim() != crate::approval::action_digest_suffix(&action_digest) {
            return Err(CliError::failure(
                "claim resign denied: digest suffix mismatch",
            ));
        }
        let _ = writeln!(self.stderr);
        let report = store
            .resign_approved(&workspace, &targets, &excludes)
            .map_err(|err| CliError::failure(err.to_string()))?;
        IndexStore::new(self.paths.clone())
            .mark_dirty(&workspace)
            .map_err(|err| CliError::failure(err.to_string()))?;
        write_json(
            &mut self.stdout,
            &ResignOutput {
                schema_version: 1,
                workspace,
                report,
            },
        )
    }

    fn run_key(&mut self, args: &[String]) -> Result<(), CliError> {
        if args.is_empty() {
            return Err(CliError::usage("key requires a subcommand: init"));
        }
        if help_requested(args) {
            self.print_key_help();
            return Ok(());
        }
        if args[0].starts_with('-') {
            return Err(unknown_flag(&args[0]));
        }
        match args[0].as_str() {
            "init" => self.run_key_init(&args[1..]),
            other => Err(CliError::failure(format!(
                "unknown key subcommand: {other}"
            ))),
        }
    }

    fn run_key_init(&mut self, args: &[String]) -> Result<(), CliError> {
        if help_requested(args) {
            self.print_key_init_help();
            return Ok(());
        }
        let recover = args.iter().any(|arg| arg == "--recover");
        let rest: Vec<String> = args
            .iter()
            .filter(|arg| arg.as_str() != "--recover")
            .cloned()
            .collect();
        let parsed = parse_flags(&rest, NO_FLAGS)?;
        if !parsed.rest.is_empty() {
            return Err(CliError::usage("usage: zbrain key init [--recover]"));
        }
        if recover {
            return self.run_key_recover();
        }
        let report = crate::signing::KeyStore::init(&self.paths, self.clock.now())
            .map_err(|err| CliError::failure(err.to_string()))?;
        self.write_key_init(&report, None)
    }

    /// Recovery after private-key loss (ADR 0002): the new key is generated
    /// but not written until the owner types its id. Existing claims keep
    /// verifying against the retired public keys.
    fn run_key_recover(&mut self) -> Result<(), CliError> {
        let mut prompt = self.make_prompt()?;
        let recovery = crate::signing::KeyStore::recover(&self.paths, self.clock.now())
            .map_err(|err| CliError::failure(err.to_string()))?;
        let retired = recovery.retired_key_ids();
        let _ = writeln!(
            self.stderr,
            "recovering the approval key: the private key is gone"
        );
        if !retired.is_empty() {
            let _ = writeln!(
                self.stderr,
                "existing claims keep verifying under retired key(s): {}",
                retired.join(", ")
            );
        }
        let _ = writeln!(self.stderr, "new key id: {}", recovery.key_id());
        let _ = write!(self.stderr, "type the new key id to confirm: ");
        let _ = self.stderr.flush();
        let typed = prompt
            .read_confirmation()
            .map_err(|err| CliError::failure(err.to_string()))?;
        if typed.trim() != recovery.key_id() {
            return Err(CliError::failure(
                "key recovery denied: new key id mismatch",
            ));
        }
        let _ = writeln!(self.stderr);
        let report = recovery
            .commit()
            .map_err(|err| CliError::failure(err.to_string()))?;
        self.write_key_init(&report, Some(retired))
    }

    fn write_key_init(
        &mut self,
        report: &crate::signing::KeyInit,
        retired: Option<Vec<String>>,
    ) -> Result<(), CliError> {
        #[derive(Serialize)]
        struct KeyInitOutput {
            schema_version: u32,
            key_id: String,
            dir: String,
            private_key: String,
            public_key: String,
            keys_file: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            recovered: Option<bool>,
            #[serde(skip_serializing_if = "Option::is_none")]
            retired_key_ids: Option<Vec<String>>,
        }
        let recovered = retired.is_some();
        write_json(
            &mut self.stdout,
            &KeyInitOutput {
                schema_version: 1,
                key_id: report.key_id.clone(),
                dir: report.dir.display().to_string(),
                private_key: report.private_key.display().to_string(),
                public_key: report.public_key.display().to_string(),
                keys_file: report.keys_file.display().to_string(),
                recovered: recovered.then_some(true),
                retired_key_ids: retired,
            },
        )
    }

    fn run_claim_supersede(&mut self, args: &[String]) -> Result<(), CliError> {
        if help_requested(args) {
            self.print_claim_supersede_help();
            return Ok(());
        }
        let parsed = parse_flags(
            args,
            &[
                "tier",
                "title",
                "basis",
                "evidence",
                "support",
                "conflicts-with",
                "workspace",
            ],
        )?;
        if parsed.rest.len() != 1 {
            return Err(CliError::usage("usage: zbrain claim supersede <id> --tier <tier> --title <title> --basis <owner|evidence|derived> [--evidence <id>]... [--support <id>]... [--conflicts-with <id>]... [--workspace <name>]"));
        }
        let workspace = self.resolve_workspace(parsed.single("workspace"))?;
        let mut body = String::new();
        self.stdin
            .read_to_string(&mut body)
            .map_err(|err| CliError::failure(err.to_string()))?;
        let id = claims::new_claim_id().map_err(|err| CliError::failure(err.to_string()))?;
        let replacement = Claim {
            claim_type: claims::OKF_CLAIM_TYPE.to_string(),
            id,
            tier: parsed.single("tier"),
            status: claims::CLAIM_STATUS_DRAFT.to_string(),
            title: parsed.single("title"),
            basis: parsed.single("basis"),
            created_at: rfc3339(self.clock.now()),
            created_by: "owner".to_string(),
            evidence_ids: parsed.all("evidence"),
            supporting_claim_ids: parsed.all("support"),
            conflicts_with: parsed.all("conflicts-with"),
            body,
            ..Claim::default()
        };
        IndexStore::new(self.paths.clone())
            .mark_dirty(&workspace)
            .map_err(|err| CliError::failure(err.to_string()))?;
        let claim = ClaimStore::new(self.paths.clone())
            .write_superseding_draft(&workspace, &parsed.rest[0], replacement)
            .map_err(|err| CliError::failure(err.to_string()))?;
        self.write_claim_mutation(&workspace, &claim)
    }

    fn run_claim_revoke(&mut self, args: &[String]) -> Result<(), CliError> {
        if help_requested(args) {
            self.print_claim_revoke_help();
            return Ok(());
        }
        let parsed = parse_flags(args, &["reason", "workspace"])?;
        if parsed.rest.len() != 1 || parsed.single("reason").is_empty() {
            return Err(CliError::usage(
                "usage: zbrain claim revoke <id> --reason <text> [--workspace <name>]",
            ));
        }
        let reason = parsed.single("reason");
        let workspace = self.resolve_workspace(parsed.single("workspace"))?;
        IndexStore::new(self.paths.clone())
            .mark_dirty(&workspace)
            .map_err(|err| CliError::failure(err.to_string()))?;
        let claim = ClaimStore::new(self.paths.clone())
            .revoke(&workspace, &parsed.rest[0], &reason)
            .map_err(|err| CliError::failure(err.to_string()))?;
        self.write_claim_mutation(&workspace, &claim)
    }

    fn run_migrate(&mut self, args: &[String]) -> Result<(), CliError> {
        if args.is_empty() {
            return Err(CliError::usage("migrate requires subcommand: okf"));
        }
        if help_requested(args) {
            self.print_migrate_help();
            return Ok(());
        }
        if args[0].starts_with('-') {
            return Err(unknown_flag(&args[0]));
        }
        if args[0] != "okf" {
            return Err(CliError::usage("migrate requires subcommand: okf"));
        }
        if help_requested(&args[1..]) {
            self.print_migrate_okf_help();
            return Ok(());
        }
        let parsed = parse_flags(&args[1..], &["workspace"])?;
        if !parsed.rest.is_empty() {
            return Err(CliError::usage(
                "usage: zbrain migrate okf [--workspace <name>]",
            ));
        }
        let workspace = self.resolve_workspace(parsed.single("workspace"))?;
        let summary = ClaimStore::new(self.paths.clone())
            .migrate_okf(&workspace)
            .map_err(|err| CliError::failure(err.to_string()))?;
        let mut index_fresh = true;
        let mut index_fresh_error = String::new();
        if let Err(err) = IndexStore::new(self.paths.clone()).check_fresh(&workspace) {
            index_fresh = false;
            index_fresh_error = err.to_string();
        }
        #[derive(Serialize)]
        struct MigrateOutput {
            schema_version: u32,
            index_fresh: bool,
            #[serde(skip_serializing_if = "String::is_empty")]
            index_fresh_error: String,
            #[serde(flatten)]
            summary: crate::lifecycle::ClaimMigrationSummary,
        }
        write_json(
            &mut self.stdout,
            &MigrateOutput {
                schema_version: 1,
                index_fresh,
                index_fresh_error,
                summary,
            },
        )
    }

    fn write_claim_mutation(&mut self, workspace: &str, claim: &Claim) -> Result<(), CliError> {
        #[derive(Serialize)]
        struct ClaimMutationOutput<'a> {
            schema_version: u32,
            workspace: &'a str,
            id: &'a str,
            status: &'a str,
            path: &'a str,
            index_fresh: bool,
        }
        write_json(
            &mut self.stdout,
            &ClaimMutationOutput {
                schema_version: 1,
                workspace,
                id: &claim.id,
                status: &claim.status,
                path: &claim.path,
                index_fresh: false,
            },
        )
    }

    fn run_workspace(&mut self, args: &[String]) -> Result<(), CliError> {
        if args.is_empty() {
            return Err(CliError::usage(
                "workspace requires a subcommand: create or current",
            ));
        }
        if help_requested(args) {
            self.print_workspace_help();
            return Ok(());
        }
        if args[0].starts_with('-') {
            return Err(unknown_flag(&args[0]));
        }
        match args[0].as_str() {
            "create" => {
                if help_requested(&args[1..]) {
                    self.print_workspace_create_help();
                    return Ok(());
                }
                let parsed = parse_flags(&args[1..], NO_FLAGS)?;
                if parsed.rest.len() != 1 {
                    return Err(CliError::usage("usage: zbrain workspace create <name>"));
                }
                create_workspace(&self.paths, &parsed.rest[0], &self.clock)
                    .map_err(|err| CliError::failure(err.to_string()))?;
                let _ = writeln!(self.stdout, "workspace created: {}", parsed.rest[0]);
                Ok(())
            }
            "current" => {
                if help_requested(&args[1..]) {
                    self.print_workspace_current_help();
                    return Ok(());
                }
                let parsed = parse_flags(&args[1..], NO_FLAGS)?;
                if !parsed.rest.is_empty() {
                    return Err(CliError::usage("workspace current accepts no arguments"));
                }
                let current = resolve_current_workspace(&self.paths)
                    .map_err(|err| CliError::failure(err.to_string()))?;
                let encoded =
                    marshal_current(&current).map_err(|err| CliError::failure(err.to_string()))?;
                self.stdout
                    .write_all(&encoded)
                    .map_err(|err| CliError::failure(err.to_string()))?;
                Ok(())
            }
            other => Err(CliError::failure(format!(
                "unknown workspace subcommand: {other}"
            ))),
        }
    }

    fn resolve_workspace(&self, workspace: String) -> Result<String, CliError> {
        let mut name = workspace;
        if name.is_empty() {
            let current = resolve_current_workspace(&self.paths)
                .map_err(|err| CliError::failure(err.to_string()))?;
            name = current.workspace;
        }
        crate::boundary::validate_workspace(&self.paths, &name)
            .map_err(|err| CliError::failure(err.to_string()))?;
        Ok(name)
    }
}

struct StderrWriter;

impl std::io::Write for StderrWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        std::io::stderr().write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        std::io::stderr().flush()
    }
}

fn write_json(writer: &mut Box<dyn Write>, value: &impl Serialize) -> Result<(), CliError> {
    let mut encoded =
        serde_json::to_string_pretty(value).map_err(|err| CliError::failure(err.to_string()))?;
    encoded.push('\n');
    writer
        .write_all(encoded.as_bytes())
        .map_err(|err| CliError::failure(err.to_string()))
}

#[derive(Debug, Default)]
struct ParsedFlags {
    values: HashMap<String, Vec<String>>,
    rest: Vec<String>,
}

impl ParsedFlags {
    fn single(&self, name: &str) -> String {
        self.values
            .get(name)
            .and_then(|values| values.last().cloned())
            .unwrap_or_default()
    }

    fn all(&self, name: &str) -> Vec<String> {
        self.values.get(name).cloned().unwrap_or_default()
    }
}

fn parse_flags(args: &[String], allowed: &[&str]) -> Result<ParsedFlags, CliError> {
    let mut flags = ParsedFlags::default();
    let mut rest = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if let Some(name) = arg.strip_prefix("--") {
            if !allowed.contains(&name) {
                return Err(unknown_flag(arg));
            }
            if index + 1 >= args.len() || args[index + 1].starts_with("--") {
                return Err(CliError::usage(format!("flag {arg} requires a value")));
            }
            flags
                .values
                .entry(name.to_string())
                .or_default()
                .push(args[index + 1].clone());
            index += 2;
            continue;
        }
        if arg.starts_with('-') {
            return Err(unknown_flag(arg));
        }
        rest.push(arg.clone());
        index += 1;
    }
    flags.rest = rest;
    Ok(flags)
}

struct ParsedAskFlags {
    workspace: String,
    includes: Vec<String>,
    after: String,
    before: String,
    as_of: String,
    rest: Vec<String>,
}

fn parse_ask_flags(args: &[String]) -> Result<ParsedAskFlags, CliError> {
    let parsed = parse_flags(args, &["workspace", "include", "after", "before", "as-of"])?;
    Ok(ParsedAskFlags {
        workspace: parsed.single("workspace"),
        includes: parsed.all("include"),
        after: parsed.single("after"),
        before: parsed.single("before"),
        as_of: parsed.single("as-of"),
        rest: parsed.rest,
    })
}

fn unknown_flag(arg: &str) -> CliError {
    CliError::usage(format!("unknown flag: {arg}"))
}

const NO_FLAGS: &[&str] = &[];

fn help_requested(args: &[String]) -> bool {
    args.len() == 1 && (args[0] == "--help" || args[0] == "-h" || args[0] == "help")
}

pub fn new_app(paths: Paths) -> App {
    App {
        stdout: Box::new(std::io::stdout()),
        stderr: Box::new(std::io::stderr()),
        stdin: Box::new(std::io::stdin()),
        paths,
        prompt: PromptSource::Stdin,
        clock: std::sync::Arc::new(SystemClock),
    }
}

fn drift_status_str(status: crate::evidence::EvidenceDriftStatus) -> &'static str {
    match status {
        crate::evidence::EvidenceDriftStatus::Unchanged => "unchanged",
        crate::evidence::EvidenceDriftStatus::Changed => "changed",
        crate::evidence::EvidenceDriftStatus::Missing => "missing",
        crate::evidence::EvidenceDriftStatus::Uncheckable => "uncheckable",
    }
}

impl App {
    fn print_help(&mut self) {
        let _ = write!(
            self.stdout,
            "zbrain - Rust-native OKF trusted memory CLI\n\
             \n\
             Usage:\n\
             \x20 zbrain <command> [arguments]\n\
             \x20 zbrain <command> --help\n\
             \n\
             Commands:\n\
             \x20 setup\n\
             \x20 workspace create <name>\n\
             \x20 workspace current\n\
             \x20 evidence add --file <path> --origin <uri-or-path> [--media-type <type>] [--workspace <name>]\n\
             \x20 evidence check [--workspace <name>]\n\
             \x20 claim draft --tier <tier> --title <title> --basis <owner|evidence|derived> [--evidence <id>]... [--support <id>]... [--conflicts-with <id>]... [--workspace <name>]\n\
             \x20 claim approve <id> [--workspace <name>]\n\
             \x20 claim resign [--workspace <name>] [--exclude <id>]...\n\
             \x20 claim supersede <id> --tier <tier> --title <title> --basis <owner|evidence|derived> [--evidence <id>]... [--support <id>]... [--conflicts-with <id>]... [--workspace <name>]\n\
             \x20 claim revoke <id> --reason <text> [--workspace <name>]\n\
             \x20 migrate okf [--workspace <name>]\n\
             \x20 reindex [--workspace <name>] [--embed]\n\
             \x20 ask [--workspace <name>] [--include <name>]... [--embed] <query>\n\
             \x20 status [--workspace <name>]\n\
             \x20 doctor [--workspace <name>] [--probe-embedder]\n\
             \x20 mcp serve\n\
             \x20 view\n\
             \x20 approval show <challenge-id>\n\
             \x20 approval grant <challenge-id>\n\
             \x20 key init\n\
             \x20 version\n\
             \n\
             Use `zbrain <command> --help` for command-specific help.\n"
        );
    }

    fn print_setup_help(&mut self) {
        let _ = write!(
            self.stdout,
            "Usage: zbrain setup\n\nPrepare the runtime directory and extract embedded assets.\n"
        );
    }

    fn print_version_help(&mut self) {
        let _ = write!(
            self.stdout,
            "Usage: zbrain version\n\nPrint the CLI version.\n"
        );
    }

    fn print_workspace_help(&mut self) {
        let _ = write!(
            self.stdout,
            "Usage:\n  zbrain workspace create <name>\n  zbrain workspace current\n\nManage the active workspace.\n"
        );
    }

    fn print_workspace_create_help(&mut self) {
        let _ = write!(
            self.stdout,
            "Usage: zbrain workspace create <name>\n\nCreate a workspace using a lowercase name, digits, or hyphens.\n"
        );
    }

    fn print_workspace_current_help(&mut self) {
        let _ = write!(
            self.stdout,
            "Usage: zbrain workspace current\n\nPrint the active workspace as JSON.\n"
        );
    }

    fn print_evidence_help(&mut self) {
        let _ = write!(
            self.stdout,
            "Usage:\n  zbrain evidence add --file <path> --origin <uri-or-path> [--media-type <type>] [--workspace <name>]\n  zbrain evidence check [--workspace <name>]\n\nSnapshot local files as immutable evidence and check origin drift.\n"
        );
    }

    fn print_evidence_check_help(&mut self) {
        let _ = write!(
            self.stdout,
            "Usage: zbrain evidence check [--workspace <name>]\n\nRe-hash each evidence snapshot origin and report drift as JSON.\n\nOptions:\n  --workspace <name>       Target workspace; defaults to the current workspace\n"
        );
    }

    fn print_evidence_add_help(&mut self) {
        let _ = write!(
            self.stdout,
            "Usage: zbrain evidence add --file <path> --origin <uri-or-path> [--media-type <type>] [--workspace <name>]\n\nOptions:\n  --file <path>             Local source file to snapshot\n  --origin <uri-or-path>    Origin recorded in evidence metadata\n  --media-type <type>      Optional media type\n  --workspace <name>       Target workspace; defaults to the current workspace\n"
        );
    }

    fn print_claim_help(&mut self) {
        let _ = write!(
            self.stdout,
            "Usage:\n  zbrain claim draft --tier <tier> --title <title> --basis <owner|evidence|derived> [--evidence <id>]... [--support <id>]... [--conflicts-with <id>]... [--workspace <name>]\n  zbrain claim approve <id> [--workspace <name>]\n  zbrain claim resign [--workspace <name>] [--exclude <id>]...\n  zbrain claim supersede <id> --tier <tier> --title <title> --basis <owner|evidence|derived> [--evidence <id>]... [--support <id>]... [--conflicts-with <id>]... [--workspace <name>]\n  zbrain claim revoke <id> --reason <text> [--workspace <name>]\n\nManage the four-state OKF claim lifecycle.\n"
        );
    }

    fn print_claim_draft_help(&mut self) {
        let _ = write!(
            self.stdout,
            "Usage: zbrain claim draft --tier <tier> --title <title> --basis <owner|evidence|derived> [options]\n\nOptions:\n  --tier <tier>             Claim tier\n  --title <title>           Claim title\n  --basis <basis>           owner, evidence, or derived\n  --evidence <id>           Evidence ID; repeat for multiple IDs\n  --support <id>            Supporting claim ID; repeat for multiple IDs\n  --conflicts-with <id>     Conflicting claim ID; repeat for multiple IDs\n  --workspace <name>       Target workspace; defaults to the current workspace\n\nThe claim body is read from stdin.\n"
        );
    }

    fn print_claim_approve_help(&mut self) {
        let _ = write!(
            self.stdout,
            "Usage: zbrain claim approve <id> [--workspace <name>]\n\nPromote a valid draft claim through the owner ceremony: confirm the last 16\nhex characters of the action digest in an interactive TTY.\n"
        );
    }

    fn print_claim_resign_help(&mut self) {
        let _ = write!(
            self.stdout,
            "Usage: zbrain claim resign [--workspace <name>] [--exclude <id>]...\n\nRe-sign every approved claim with the active owner key in one TTY ceremony.\nThe command lists each claim's id, title, approval time, and digest, prints\nthe batch action digest, and asks for its last 16 hex characters. Claims\nnamed with --exclude stay unsigned and untrusted. Re-running is a no-op for\nclaims already signed by the active key.\n"
        );
    }

    fn print_key_help(&mut self) {
        let _ = write!(
            self.stdout,
            "Usage:\n  zbrain key init\n\nManage the owner approval key (ADR 0002).\n"
        );
    }

    fn print_key_init_help(&mut self) {
        let _ = write!(
            self.stdout,
            "Usage: zbrain key init [--recover]\n\nCreate the owner approval key at $XDG_CONFIG_HOME/zbrain-keys\n(fallback ~/.config/zbrain-keys): directory 0700, files 0600. Refuses a\nsymlinked key path, a path inside ZBRAIN_HOME, looser modes, and an existing\nkey (rotation is a separate ceremony).\n\n--recover  After private-key loss: generate a new key, print its key id, and\n           write it only when the owner types that id. Previous keys are\n           retired, so existing claims keep verifying.\n"
        );
    }

    fn print_claim_supersede_help(&mut self) {
        let _ = write!(
            self.stdout,
            "Usage: zbrain claim supersede <id> --tier <tier> --title <title> --basis <owner|evidence|derived> [options]\n\nOptions:\n  --tier <tier>             Replacement claim tier\n  --title <title>           Replacement claim title\n  --basis <basis>           owner, evidence, or derived\n  --evidence <id>           Evidence ID; repeat for multiple IDs\n  --support <id>            Supporting claim ID; repeat for multiple IDs\n  --conflicts-with <id>     Conflicting claim ID; repeat for multiple IDs\n  --workspace <name>       Target workspace; defaults to the current workspace\n\nThe replacement claim body is read from stdin.\n"
        );
    }

    fn print_claim_revoke_help(&mut self) {
        let _ = write!(
            self.stdout,
            "Usage: zbrain claim revoke <id> --reason <text> [--workspace <name>]\n\nRevoke a claim with an operator-provided reason.\n"
        );
    }

    fn print_migrate_help(&mut self) {
        let _ = write!(
            self.stdout,
            "Usage: zbrain migrate okf [--workspace <name>]\n\nConvert legacy zbrain claim files to OKF concepts.\n"
        );
    }

    fn print_migrate_okf_help(&mut self) {
        self.print_migrate_help();
    }

    fn print_reindex_help(&mut self) {
        let _ = write!(
            self.stdout,
            "Usage: zbrain reindex [--workspace <name>] [--embed]\n\nRebuild the disposable workspace index.\n\nOptions:\n  --embed        Also compute and store loopback embedding vectors\n"
        );
    }

    fn print_view_help(&mut self) {
        let _ = write!(
            self.stdout,
            "Usage: zbrain view\n\nServe the embedded read-only viewer over loopback (127.0.0.1).\n\nThe viewer binds loopback only, sends strict CSP and nosniff headers,\nhas no CORS, and returns 405 for every method other than GET and HEAD.\n"
        );
    }

    fn print_approval_help(&mut self) {
        let _ = write!(
            self.stdout,
            "Usage:\n  zbrain approval show <challenge-id>\n  zbrain approval grant <challenge-id>\n\nRun the local owner-pinned approval ceremony for a lifecycle challenge.\n"
        );
    }

    fn print_approval_show_help(&mut self) {
        let _ = write!(
            self.stdout,
            "Usage: zbrain approval show <challenge-id>\n\nPrint the challenge action summary as JSON. A batch challenge lists every\nbound item with its canonical draft digest.\n"
        );
    }

    fn print_approval_grant_help(&mut self) {
        let _ = write!(
            self.stdout,
            "Usage: zbrain approval grant <challenge-id>\n\nConfirm the last 16 hex characters of the action digest in an interactive\nTTY, then verify and print the one-time token as JSON for later apply.\nA batch challenge walks every bound item in order; each item must be\nconfirmed by its digest suffix or skipped with the literal input \"skip\",\nand one token is issued for the whole batch when at least one item is\ngranted.\n"
        );
    }

    fn print_ask_help(&mut self) {
        let _ = write!(
            self.stdout,
            "Usage: zbrain ask [--workspace <name>] [--include <name>]... [--embed] [--after <time>] [--before <time>] [--as-of <time>] <query>\n\nReturn trusted context JSON without calling an LLM.\n\nOptions:\n  --workspace <name>       Primary workspace; defaults to the current workspace\n  --include <name>         Explicit read-only secondary workspace; repeatable\n  --embed                  Also use local embedding vectors; defaults to lexical-only\n  --after <rfc3339>        Filter claims verified/created at or after timestamp\n  --before <rfc3339>       Filter claims verified/created at or before timestamp\n  --as-of <rfc3339>        Reconstruct active state at point in time\n"
        );
    }

    fn print_mcp_help(&mut self) {
        let _ = write!(
            self.stdout,
            "Usage: zbrain mcp serve\n\nServe the trusted-agent MCP gateway over stdio.\n"
        );
    }

    fn print_mcp_serve_help(&mut self) {
        let _ = write!(
            self.stdout,
            "Usage: zbrain mcp serve\n\nRun the MCP stdio gateway. stdout is protocol-only; diagnostics go to stderr.\n"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval::{
        ChallengeItem, ChallengePrepare, ChallengeStore, CHALLENGE_OPERATION_APPROVE,
    };
    use crate::claims::{CLAIM_BASIS_OWNER, CLAIM_STATUS_APPROVED, OKF_CLAIM_TYPE};
    use crate::paths::Options;
    use chrono::{TimeZone, Utc};
    use std::cell::RefCell;
    use std::io::Cursor;
    use std::path::PathBuf;
    use std::rc::Rc;

    #[derive(Clone, Default)]
    struct SharedOut(Rc<RefCell<Vec<u8>>>);

    impl Write for SharedOut {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.borrow_mut().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct Fixture {
        _dir: PathBuf,
        out: SharedOut,
        err: SharedOut,
    }

    fn fixture() -> (App, Fixture) {
        static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "zbrain-cli-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut paths = Paths::resolve(Options {
            cwd: Some(dir.join("project")),
            home_dir: Some(dir.clone()),
            runtime_dir: Some(dir.join(".zbrain")),
        })
        .unwrap();
        paths.key_dir = crate::signing::test_key_dir();
        let out = SharedOut::default();
        let err = SharedOut::default();
        let app = App {
            stdout: Box::new(out.clone()),
            stderr: Box::new(err.clone()),
            stdin: Box::new(Cursor::new(Vec::new())),
            paths,
            prompt: PromptSource::Scripted(Vec::new()),
            clock: std::sync::Arc::new(crate::clock::FixedClock::new(
                Utc.with_ymd_and_hms(2026, 7, 29, 0, 0, 0).unwrap(),
            )),
        };
        (
            app,
            Fixture {
                _dir: dir,
                out,
                err,
            },
        )
    }

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    fn stdout_text(fix: &Fixture) -> String {
        String::from_utf8(fix.out.0.borrow().clone()).unwrap()
    }

    fn run(app: &mut App, fix: &Fixture, argv: &[&str]) -> Result<(), CliError> {
        fix.out.0.borrow_mut().clear();
        fix.err.0.borrow_mut().clear();
        app.run(&args(argv))
    }

    fn run_ok(app: &mut App, fix: &Fixture, argv: &[&str]) -> String {
        run(app, fix, argv).unwrap_or_else(|err| panic!("run({argv:?}) error = {err}"));
        stdout_text(fix)
    }

    fn setup_research(app: &mut App, fix: &Fixture) {
        run_ok(app, fix, &["setup"]);
        run_ok(app, fix, &["workspace", "create", "research"]);
    }

    fn draft_id(app: &mut App, fix: &Fixture, title: &str, body: &str) -> String {
        app.stdin = Box::new(Cursor::new(body.as_bytes().to_vec()));
        let out = run_ok(
            app,
            fix,
            &[
                "claim", "draft", "--tier", "projects", "--title", title, "--basis", "owner",
            ],
        );
        let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
        parsed["id"].as_str().unwrap().to_string()
    }

    /// Answers the owner ceremony with the digest suffix the CLI will ask for.
    fn approve_via_cli(app: &mut App, fix: &Fixture, id: &str) -> String {
        let store = ClaimStore::with_clock(app.paths.clone(), app.clock.clone());
        let prepare = store.approve_challenge_prepare("research", id).unwrap();
        let suffix = crate::approval::action_digest_suffix(
            &crate::approval::compute_challenge_action_digest(&prepare),
        )
        .to_string();
        app.prompt = PromptSource::Scripted(vec![suffix]);
        run_ok(app, fix, &["claim", "approve", id])
    }

    #[test]
    fn setup_prints_text_summary() {
        let (mut app, fix) = fixture();
        let out = run_ok(&mut app, &fix, &["setup"]);
        assert!(out.contains("zbrain setup complete"), "{out}");
        assert!(out.contains("config_created: true"), "{out}");
        assert!(out.contains("assets_copied: 21"), "{out}");
    }

    #[test]
    fn root_help_lists_commands() {
        let (mut app, fix) = fixture();
        let out = run_ok(&mut app, &fix, &["--help"]);
        for want in [
            "zbrain - Rust-native OKF trusted memory CLI",
            "claim draft --tier <tier>",
            "approval grant <challenge-id>",
            "Use `zbrain <command> --help` for command-specific help.",
        ] {
            assert!(out.contains(want), "help missing {want:?}:\n{out}");
        }
    }

    #[test]
    fn workspace_create_current_round_trip() {
        let (mut app, fix) = fixture();
        setup_research(&mut app, &fix);
        let out = run_ok(&mut app, &fix, &["workspace", "current"]);
        let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed["workspace"], "research");
        assert_eq!(parsed["secondary_workspaces"], serde_json::json!([]));
    }

    #[test]
    fn evidence_add_and_lifecycle_json() {
        let (mut app, fix) = fixture();
        setup_research(&mut app, &fix);
        let source = fix._dir.join("source.txt");
        std::fs::write(&source, b"source bytes").unwrap();
        let out = run_ok(
            &mut app,
            &fix,
            &[
                "evidence",
                "add",
                "--file",
                source.to_str().unwrap(),
                "--origin",
                "file://source.txt",
                "--media-type",
                "text/plain",
            ],
        );
        let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed["schema_version"], 1);
        assert!(parsed["id"].as_str().unwrap().starts_with("evd_"));
        assert_eq!(parsed["deduped"], false);

        let id = draft_id(&mut app, &fix, "CLI Claim", "Claim body\n");
        let out = approve_via_cli(&mut app, &fix, &id);
        let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed["status"], "approved");
        assert_eq!(parsed["index_fresh"], false);
    }

    #[test]
    fn claim_transitions_round_trip() {
        let (mut app, fix) = fixture();
        setup_research(&mut app, &fix);
        let id = draft_id(&mut app, &fix, "Original", "Original body\n");
        approve_via_cli(&mut app, &fix, &id);
        app.prompt = PromptSource::Scripted(Vec::new());
        let err = run(&mut app, &fix, &["claim", "approve", &id]).unwrap_err();
        assert!(
            err.to_string()
                .contains("only draft claims can be approved"),
            "{err}"
        );

        app.stdin = Box::new(Cursor::new(b"Replacement body\n".to_vec()));
        let out = run_ok(
            &mut app,
            &fix,
            &[
                "claim",
                "supersede",
                &id,
                "--tier",
                "projects",
                "--title",
                "Replacement",
                "--basis",
                "owner",
            ],
        );
        let replacement: String = serde_json::from_str::<serde_json::Value>(&out).unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();
        approve_via_cli(&mut app, &fix, &replacement);
        run_ok(
            &mut app,
            &fix,
            &["claim", "revoke", &replacement, "--reason", "withdrawn"],
        );

        let store = ClaimStore::new(app.paths.clone());
        assert_eq!(store.read("research", &id).unwrap().status, "superseded");
        assert_eq!(
            store.read("research", &replacement).unwrap().status,
            "revoked"
        );
    }

    #[test]
    fn claim_approve_refuses_wrong_digest() {
        let (mut app, fix) = fixture();
        setup_research(&mut app, &fix);
        let id = draft_id(&mut app, &fix, "Wrong Digest", "wrong digest body\n");
        app.prompt = PromptSource::Scripted(vec!["0000000000000000".to_string()]);
        let err = run(&mut app, &fix, &["claim", "approve", &id]).unwrap_err();
        assert!(err.to_string().contains("digest suffix mismatch"), "{err}");
        let store = ClaimStore::new(app.paths.clone());
        assert_eq!(store.read("research", &id).unwrap().status, "draft");
    }

    #[test]
    fn reindex_and_ask_ready() {
        let (mut app, fix) = fixture();
        setup_research(&mut app, &fix);
        let id = draft_id(&mut app, &fix, "Trusted Ask", "local trusted answer\n");
        approve_via_cli(&mut app, &fix, &id);
        let out = run_ok(&mut app, &fix, &["reindex"]);
        let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed["schema_version"], 1);
        assert_eq!(parsed["rebuild_state"], "clean");
        let out = run_ok(&mut app, &fix, &["ask", "local", "trusted"]);
        let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed["status"], "ready");
        assert_eq!(parsed["claims"][0]["id"], serde_json::json!(id));
    }

    #[test]
    fn ask_gap_is_success() {
        let (mut app, fix) = fixture();
        setup_research(&mut app, &fix);
        run_ok(&mut app, &fix, &["reindex"]);
        let out = run_ok(&mut app, &fix, &["ask", "missing", "claim"]);
        let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed["status"], "gap");
    }

    #[test]
    fn doctor_healthy_then_dirty() {
        let (mut app, fix) = fixture();
        setup_research(&mut app, &fix);
        run_ok(&mut app, &fix, &["reindex"]);
        let out = run_ok(&mut app, &fix, &["doctor"]);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&out).unwrap()["status"],
            "healthy"
        );
        draft_id(&mut app, &fix, "Dirty Probe", "dirty body\n");
        let err = run(&mut app, &fix, &["doctor"]).unwrap_err();
        assert_eq!(err.exit_code(), 2);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&stdout_text(&fix)).unwrap()["status"],
            "degraded"
        );
    }

    #[test]
    fn approval_single_ceremony_through_cli() {
        let (mut app, fix) = fixture();
        setup_research(&mut app, &fix);
        let id = draft_id(&mut app, &fix, "Ceremony Claim", "Ceremony claim\n");

        let store = ClaimStore::with_clock(app.paths.clone(), app.clock.clone());
        let prepared = store
            .prepare_challenge(
                "research",
                ChallengePrepare {
                    workspace: "research".to_string(),
                    operation: CHALLENGE_OPERATION_APPROVE.to_string(),
                    claim_id: id.clone(),
                    ..ChallengePrepare::default()
                },
            )
            .unwrap();

        let out = run_ok(
            &mut app,
            &fix,
            &["approval", "show", &prepared.challenge.id],
        );
        let shown: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(
            shown["challenge_id"],
            serde_json::json!(prepared.challenge.id)
        );
        assert_eq!(shown["operation"], "approve");

        let suffix =
            crate::approval::action_digest_suffix(&prepared.challenge.action_digest).to_string();
        app.prompt = PromptSource::Scripted(vec![suffix]);
        let out = run_ok(
            &mut app,
            &fix,
            &["approval", "grant", &prepared.challenge.id],
        );
        let granted: serde_json::Value = serde_json::from_str(&out).unwrap();
        let token = granted["token"].as_str().unwrap().to_string();
        assert!(!token.is_empty());

        let approved = store
            .apply_challenge(
                "research",
                &prepared.challenge.id,
                &token,
                Default::default(),
            )
            .unwrap();
        assert_eq!(approved.status, CLAIM_STATUS_APPROVED);

        app.prompt = PromptSource::Scripted(vec!["0000000000000000".to_string()]);
        let challenge_store = ChallengeStore::with_clock(app.paths.clone(), app.clock.clone());
        let second = challenge_store
            .prepare(
                "research",
                ChallengePrepare {
                    workspace: "research".to_string(),
                    operation: CHALLENGE_OPERATION_APPROVE.to_string(),
                    claim_id: id.clone(),
                    ..ChallengePrepare::default()
                },
            )
            .unwrap();
        let err = run(&mut app, &fix, &["approval", "grant", &second.challenge.id]).unwrap_err();
        assert!(err.to_string().contains("suffix"), "{err}");
    }

    #[test]
    fn approval_grant_requires_tty_without_script() {
        let (mut app, fix) = fixture();
        setup_research(&mut app, &fix);
        app.prompt = PromptSource::Stdin;
        let err = run(
            &mut app,
            &fix,
            &["approval", "grant", "chg_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
        )
        .unwrap_err();
        // Either the challenge is missing or stdin is not a TTY; a piped test
        // process must never reach an interactive read.
        assert!(
            err.to_string().contains("TTY") || err.to_string().contains("not found"),
            "{err}"
        );
    }

    #[test]
    fn approval_batch_partial_and_skip_all_through_cli() {
        let (mut app, fix) = fixture();
        setup_research(&mut app, &fix);
        let ids = [
            draft_id(&mut app, &fix, "Batch One", "one body\n"),
            draft_id(&mut app, &fix, "Batch Two", "two body\n"),
            draft_id(&mut app, &fix, "Batch Three", "three body\n"),
        ];
        let store = ClaimStore::new(app.paths.clone());
        let prepared = store
            .prepare_batch_challenge(
                "research",
                ids.iter()
                    .map(|id| ChallengeItem {
                        claim_id: id.clone(),
                        ..ChallengeItem::default()
                    })
                    .collect(),
            )
            .unwrap();
        let suffix_of = |claim_id: &str| {
            store
                .canonical_digest("research", claim_id)
                .map(|(_, digest)| crate::approval::action_digest_suffix(&digest).to_string())
                .unwrap()
        };
        app.prompt = PromptSource::Scripted(vec![
            suffix_of(&ids[0]),
            "skip".to_string(),
            suffix_of(&ids[2]),
        ]);
        let out = run_ok(
            &mut app,
            &fix,
            &["approval", "grant", &prepared.challenge.id],
        );
        let granted: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert!(!granted["token"].as_str().unwrap().is_empty());
        assert_eq!(granted["granted_items"].as_array().unwrap().len(), 2);
        assert_eq!(granted["skipped_items"].as_array().unwrap().len(), 1);

        let skip_ids = [
            draft_id(&mut app, &fix, "Batch Four", "four body\n"),
            draft_id(&mut app, &fix, "Batch Five", "five body\n"),
        ];
        let skip_prepared = store
            .prepare_batch_challenge(
                "research",
                skip_ids
                    .iter()
                    .map(|id| ChallengeItem {
                        claim_id: id.clone(),
                        ..ChallengeItem::default()
                    })
                    .collect(),
            )
            .unwrap();
        app.prompt = PromptSource::Scripted(vec!["skip".to_string(), "skip".to_string()]);
        let out = run_ok(
            &mut app,
            &fix,
            &["approval", "grant", &skip_prepared.challenge.id],
        );
        let skipped: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert!(skipped.get("token").is_none() || skipped["token"].is_null());
        assert_eq!(skipped["skipped_items"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn exit_codes_match_oracle() {
        // Each case runs on a fresh app: claim mutations mark the index dirty
        // before failing, so state must not leak between cases (mirrors Go's
        // per-case testApp).
        let fresh = || {
            let (mut app, fix) = fixture();
            setup_research(&mut app, &fix);
            run_ok(&mut app, &fix, &["reindex"]);
            (app, fix)
        };
        let code = |result: Result<(), CliError>| match result {
            Ok(()) => 0,
            Err(err) => err.exit_code(),
        };
        let (mut app, fix) = fresh();
        assert_eq!(code(run(&mut app, &fix, &["--help"])), 0);
        let (mut app, fix) = fresh();
        assert_eq!(code(run(&mut app, &fix, &["bogus"])), 1);
        let (mut app, fix) = fresh();
        assert_eq!(code(run(&mut app, &fix, &["--bogus"])), 2);
        let (mut app, fix) = fresh();
        assert_eq!(code(run(&mut app, &fix, &["claim", "bogus"])), 1);
        let (mut app, fix) = fresh();
        assert_eq!(code(run(&mut app, &fix, &["ask"])), 2);
        let (mut app, fix) = fresh();
        assert_eq!(code(run(&mut app, &fix, &["mcp"])), 2);
        let (mut app, fix) = fresh();
        assert_eq!(
            code(run(
                &mut app,
                &fix,
                &["claim", "approve", "clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
            )),
            1
        );
        let (mut app, fix) = fresh();
        assert_eq!(code(run(&mut app, &fix, &["ask", "missing"])), 0);
    }

    #[test]
    fn status_emits_catalog_without_leak() {
        let (mut app, fix) = fixture();
        setup_research(&mut app, &fix);
        let id = draft_id(&mut app, &fix, "Approved Catalog", "catalog body\n");
        approve_via_cli(&mut app, &fix, &id);
        draft_id(&mut app, &fix, "Draft Catalog", "draft body\n");
        run_ok(&mut app, &fix, &["reindex"]);
        let out = run_ok(&mut app, &fix, &["status"]);
        let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed["schema_version"], 2);
        assert_eq!(parsed["catalog"].as_array().unwrap().len(), 1);
        assert_eq!(parsed["catalog"][0]["id"], serde_json::json!(id));
    }

    #[test]
    fn claim_type_constant_matches_oracle() {
        assert_eq!(OKF_CLAIM_TYPE, "zbrain.claim");
        assert_eq!(CLAIM_BASIS_OWNER, "owner");
    }

    #[test]
    fn challenge_store_grant_persists_without_cli() {
        let (mut app, fix) = fixture();
        setup_research(&mut app, &fix);
        let id = draft_id(&mut app, &fix, "Direct Grant", "direct body\n");
        let store = ClaimStore::new(app.paths.clone());
        let prepared = store
            .prepare_challenge(
                "research",
                ChallengePrepare {
                    workspace: "research".to_string(),
                    operation: CHALLENGE_OPERATION_APPROVE.to_string(),
                    claim_id: id,
                    ..ChallengePrepare::default()
                },
            )
            .unwrap();
        let challenge_store = ChallengeStore::with_clock(app.paths.clone(), app.clock.clone());
        let granted = challenge_store
            .grant("research", &prepared.challenge.id)
            .unwrap();
        assert!(!granted.token.is_empty());
    }
}
