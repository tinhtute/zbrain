//! view.rs — port of internal/view/server.go: the loopback read-only viewer
//! served by `zbrain view`.
//!
//! std-only HTTP/1.1 over [`std::net::TcpListener`] (one thread per
//! connection): 127.0.0.1 bind with an ephemeral port, GET/HEAD only, strict
//! CSP + nosniff on every response, no CORS headers, 405 for anything else.
//! Page rendering mirrors assets/view/index.html with html/template text
//! escaping; the /api JSON shapes mirror Go's encoding/json output.

use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use include_dir::{include_dir, Dir};

use crate::claims::ClaimStore;
use crate::evidence::EvidenceStore;
use crate::paths::Paths;
use crate::workspace::resolve_current_workspace;

pub static VIEW_ASSETS: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/../../assets/view");

pub const SECURITY_POLICY: &str = "default-src 'self'; script-src 'none'; object-src 'none'";

pub struct Server {
    paths: Paths,
    listener: Option<TcpListener>,
    port: u16,
    url: String,
    stop: Arc<AtomicBool>,
}

impl Server {
    pub fn new(paths: Paths) -> Self {
        Self {
            paths,
            listener: None,
            port: 0,
            url: String::new(),
            stop: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Binds loopback on an ephemeral port and records the bound address.
    /// Must be called before [`Server::serve`]. Returns the viewer URL.
    pub fn listen(&mut self) -> std::io::Result<String> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr: SocketAddr = listener.local_addr()?;
        self.port = addr.port();
        self.url = format!("http://127.0.0.1:{}", self.port);
        self.listener = Some(listener);
        Ok(self.url.clone())
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn stop_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.stop)
    }

    /// Serves the embedded viewer on the bound listener until
    /// [`Server::close`] is called. Blocks the calling thread.
    pub fn serve(&self) -> std::io::Result<()> {
        let listener = self
            .listener
            .as_ref()
            .ok_or_else(|| std::io::Error::other("view: Serve called before Listen"))?;
        listener.set_nonblocking(true)?;
        loop {
            if self.stop.load(Ordering::SeqCst) {
                return Ok(());
            }
            match listener.accept() {
                Ok((stream, _)) => {
                    let paths = self.paths.clone();
                    std::thread::spawn(move || {
                        let _ = handle_connection(stream, &paths);
                    });
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(err) => return Err(err),
            }
        }
    }

    /// Stops the server; the [`Server::serve`] loop exits promptly.
    pub fn close(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

fn handle_connection(mut stream: TcpStream, paths: &Paths) -> std::io::Result<()> {
    // Accepted streams inherit the listener's non-blocking mode; the handler
    // below is written as blocking I/O, so restore blocking mode first.
    // Without this, a read racing the client's write returns WouldBlock and
    // drops the connection unread — a load-dependent flake.
    stream.set_nonblocking(false)?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > 65536 {
            break;
        }
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let response = route_request(&buf, paths);
    stream.write_all(&response)?;
    stream.flush()?;
    Ok(())
}

fn route_request(raw: &[u8], paths: &Paths) -> Vec<u8> {
    let text = String::from_utf8_lossy(raw);
    let mut lines = text.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    if method != "GET" && method != "HEAD" {
        return http_response(
            405,
            "Method Not Allowed",
            "text/plain; charset=utf-8",
            b"",
            method,
        );
    }
    let head_only = method == "HEAD";
    let path = target.split('?').next().unwrap_or("/");
    let path = percent_decode(path);
    match path.as_str() {
        "/" => {
            let body = render_page(paths).unwrap_or_else(|_| b"viewer: page unavailable".to_vec());
            http_response(
                200,
                "OK",
                "text/html; charset=utf-8",
                &body,
                head_flag(head_only),
            )
        }
        "/style.css" => {
            static_response("style.css", "text/css; charset=utf-8", head_flag(head_only))
        }
        "/app.js" => static_response(
            "app.js",
            "text/javascript; charset=utf-8",
            head_flag(head_only),
        ),
        "/api/workspace" => {
            let (status, body) = match resolve_current_workspace(paths) {
                Err(err) => (500, json_error(&err.to_string())),
                Ok(current) => (
                    200,
                    format!("{{\"workspace\":{}}}\n", json_string(&current.workspace)).into_bytes(),
                ),
            };
            let reason = if status == 200 {
                "OK"
            } else {
                "Internal Server Error"
            };
            http_response(
                status,
                reason,
                "application/json; charset=utf-8",
                &body,
                head_flag(head_only),
            )
        }
        "/api/claims" => {
            let (status, body) = match approved_claims_json(paths) {
                Err(err) => (500, json_error(&err.to_string())),
                Ok(body) => (200, body),
            };
            let reason = if status == 200 {
                "OK"
            } else {
                "Internal Server Error"
            };
            http_response(
                status,
                reason,
                "application/json; charset=utf-8",
                &body,
                head_flag(head_only),
            )
        }
        _ => {
            if let Some(id) = path.strip_prefix("/api/claim/") {
                if id.is_empty() || id.contains('/') {
                    return http_response(
                        404,
                        "Not Found",
                        "application/json; charset=utf-8",
                        &json_error("claim not found"),
                        head_flag(head_only),
                    );
                }
                let (status, body) = match claim_json(paths, id) {
                    Err(ClaimApiError::NotFound) => (404, json_error("claim not found")),
                    Err(ClaimApiError::Server(message)) => (500, json_error(&message)),
                    Ok(body) => (200, body),
                };
                let reason = if status == 200 {
                    "OK"
                } else {
                    status_reason(status)
                };
                return http_response(
                    status,
                    reason,
                    "application/json; charset=utf-8",
                    &body,
                    head_flag(head_only),
                );
            }
            if let Some(id) = path.strip_prefix("/api/evidence/") {
                if id.is_empty() || id.contains('/') {
                    return http_response(
                        404,
                        "Not Found",
                        "application/json; charset=utf-8",
                        &json_error("evidence not found"),
                        head_flag(head_only),
                    );
                }
                let (status, body) = match evidence_json(paths, id) {
                    Err(ClaimApiError::NotFound) => (404, json_error("evidence not found")),
                    Err(ClaimApiError::Server(message)) => (500, json_error(&message)),
                    Ok(body) => (200, body),
                };
                let reason = if status == 200 {
                    "OK"
                } else {
                    status_reason(status)
                };
                return http_response(
                    status,
                    reason,
                    "application/json; charset=utf-8",
                    &body,
                    head_flag(head_only),
                );
            }
            http_response(
                404,
                "Not Found",
                "text/plain; charset=utf-8",
                b"404 page not found\n",
                head_flag(head_only),
            )
        }
    }
}

fn head_flag(head_only: bool) -> &'static str {
    if head_only {
        "HEAD"
    } else {
        "GET"
    }
}

fn status_reason(status: u16) -> &'static str {
    match status {
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "OK",
    }
}

fn http_response(
    status: u16,
    reason: &str,
    content_type: &str,
    body: &[u8],
    method: &str,
) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Security-Policy: {SECURITY_POLICY}\r\nContent-Type: {content_type}\r\nX-Content-Type-Options: nosniff\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    if method != "HEAD" {
        out.extend_from_slice(body);
    }
    out
}

fn json_error(message: &str) -> Vec<u8> {
    format!("{{\"error\":{}}}\n", json_string(message)).into_bytes()
}

fn static_response(name: &str, content_type: &str, method: &str) -> Vec<u8> {
    match VIEW_ASSETS.get_file(name) {
        None => http_response(
            404,
            "Not Found",
            "text/plain; charset=utf-8",
            b"404 page not found\n",
            method,
        ),
        Some(file) => http_response(200, "OK", content_type, file.contents(), method),
    }
}

enum ClaimApiError {
    NotFound,
    Server(String),
}

/// Go-compatible HTML text escaping (html.EscapeString): & < > " ' only.
pub fn escape_html(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&#34;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Minimal JSON string quoting matching encoding/json for the characters we
/// emit, including Go's HTML escaping (`<`, `>`, `&`) and U+2028/2029.
fn json_string(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 2);
    out.push('"');
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            ch if (ch as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", ch as u32)),
            _ => out.push(ch),
        }
    }
    out.push('"');
    out
}

struct ClaimView {
    id: String,
    tier: String,
    status: String,
    title: String,
    body: String,
    evidence: Vec<EvidenceView>,
}

struct EvidenceView {
    id: String,
    origin: String,
    media_type: String,
    content: String,
}

fn collect_views(paths: &Paths) -> Result<(String, Vec<ClaimView>), String> {
    let current = resolve_current_workspace(paths).map_err(|err| err.to_string())?;
    let scan = ClaimStore::new(paths.clone())
        .scan_workspace_trusted(&current.workspace)
        .map_err(|err| err.to_string())?;
    let evidence_store = EvidenceStore::new(paths.clone());
    let mut views = Vec::new();
    for claim in &scan.claims {
        if claim.status != crate::claims::CLAIM_STATUS_APPROVED {
            continue;
        }
        let mut view = ClaimView {
            id: claim.id.clone(),
            tier: claim.tier.clone(),
            status: claim.status.clone(),
            title: claim.title.clone(),
            body: claim.body.clone(),
            evidence: Vec::new(),
        };
        for id in &claim.evidence_ids {
            let Ok(evidence) = evidence_store.read(&current.workspace, id) else {
                continue;
            };
            let Ok(raw) = evidence_store.read_raw(&current.workspace, id) else {
                continue;
            };
            view.evidence.push(EvidenceView {
                id: evidence.id,
                origin: evidence.origin,
                media_type: evidence.media_type,
                content: String::from_utf8_lossy(&raw).into_owned(),
            });
        }
        views.push(view);
    }
    Ok((current.workspace, views))
}

/// Server-rendered viewer page. Literal structure mirrors
/// assets/view/index.html; every user-controlled value is HTML-escaped.
pub fn render_page(paths: &Paths) -> Result<Vec<u8>, String> {
    let (workspace, claims) = collect_views(paths).unwrap_or_default();
    let mut out = String::new();
    out.push_str(
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"UTF-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n<title>zbrain viewer</title>\n<link rel=\"stylesheet\" href=\"/style.css\">\n</head>\n<body>\n<main id=\"app\">\n<h1>zbrain</h1>\n<p class=\"status\">trusted memory viewer",
    );
    if !workspace.is_empty() {
        out.push_str(" · workspace: ");
        out.push_str(&escape_html(&workspace));
    }
    out.push_str("</p>\n<section id=\"claims\">\n<h2>Approved claims</h2>\n");
    if claims.is_empty() {
        out.push_str("\n<p class=\"status\">No approved claims.</p>\n");
    } else {
        out.push_str("\n<ul class=\"claims\">\n");
        for claim in &claims {
            out.push_str("\n<li class=\"claim\" id=\"");
            out.push_str(&escape_html(&claim.id));
            out.push_str("\">\n<h3 class=\"claim-title\">");
            out.push_str(&escape_html(&claim.title));
            out.push_str("</h3>\n<p class=\"claim-meta\">");
            out.push_str(&escape_html(&claim.id));
            out.push_str(" · ");
            out.push_str(&escape_html(&claim.tier));
            out.push_str(" · ");
            out.push_str(&escape_html(&claim.status));
            out.push_str("</p>\n<div class=\"claim-body\">");
            out.push_str(&escape_html(&claim.body));
            out.push_str("</div>\n");
            if !claim.evidence.is_empty() {
                out.push_str("\n<div class=\"evidence-list\">\n<h4>Evidence</h4>\n");
                for evidence in &claim.evidence {
                    out.push_str("\n<div class=\"evidence\">\n<p class=\"evidence-meta\">");
                    out.push_str(&escape_html(&evidence.id));
                    out.push_str(" · ");
                    out.push_str(&escape_html(&evidence.origin));
                    out.push_str(" · ");
                    out.push_str(&escape_html(&evidence.media_type));
                    out.push_str("</p>\n<pre class=\"evidence-content\">");
                    out.push_str(&escape_html(&evidence.content));
                    out.push_str("</pre>\n</div>\n");
                }
                out.push_str("\n</div>\n");
            }
            out.push_str("\n</li>\n");
        }
        out.push_str("\n</ul>\n");
    }
    out.push_str("\n</section>\n</main>\n</body>\n</html>\n");
    Ok(out.into_bytes())
}

fn approved_claims_json(paths: &Paths) -> Result<Vec<u8>, String> {
    let current = resolve_current_workspace(paths).map_err(|err| err.to_string())?;
    let scan = ClaimStore::new(paths.clone())
        .scan_workspace_trusted(&current.workspace)
        .map_err(|err| err.to_string())?;
    let mut out = String::from("[");
    let mut first = true;
    for claim in &scan.claims {
        if claim.status != crate::claims::CLAIM_STATUS_APPROVED {
            continue;
        }
        if !first {
            out.push(',');
        }
        first = false;
        out.push_str(&claim_go_json(claim));
    }
    out.push_str("]\n");
    Ok(out.into_bytes())
}

fn claim_json(paths: &Paths, id: &str) -> Result<Vec<u8>, ClaimApiError> {
    let current =
        resolve_current_workspace(paths).map_err(|err| ClaimApiError::Server(err.to_string()))?;
    let claim = ClaimStore::new(paths.clone())
        .read_trusted(&current.workspace, id)
        .map_err(|_| ClaimApiError::NotFound)?;
    Ok(format!("{}\n", claim_go_json(&claim)).into_bytes())
}

fn evidence_json(paths: &Paths, id: &str) -> Result<Vec<u8>, ClaimApiError> {
    let current =
        resolve_current_workspace(paths).map_err(|err| ClaimApiError::Server(err.to_string()))?;
    let store = EvidenceStore::new(paths.clone());
    let evidence = store
        .read(&current.workspace, id)
        .map_err(|_| ClaimApiError::NotFound)?;
    let raw = store
        .read_raw(&current.workspace, id)
        .map_err(|err| ClaimApiError::Server(err.to_string()))?;
    let body = format!(
        "{{\"evidence\":{},\"content\":{}}}\n",
        evidence_go_json(&evidence),
        json_string(&String::from_utf8_lossy(&raw))
    );
    Ok(body.into_bytes())
}

/// encoding/json shape of runtime.Claim (no field tags: capitalized keys in
/// declaration order; slices without omitempty render null when empty).
fn claim_go_json(claim: &crate::claims::Claim) -> String {
    let mut out = String::from("{");
    out.push_str(&format!("\"Schema\":{},", json_string(&claim.schema)));
    out.push_str(&format!("\"Type\":{},", json_string(&claim.claim_type)));
    out.push_str(&format!("\"ID\":{},", json_string(&claim.id)));
    out.push_str(&format!("\"Tier\":{},", json_string(&claim.tier)));
    out.push_str(&format!("\"Path\":{},", json_string(&claim.path)));
    out.push_str(&format!("\"Status\":{},", json_string(&claim.status)));
    out.push_str(&format!("\"Title\":{},", json_string(&claim.title)));
    out.push_str(&format!(
        "\"Description\":{},",
        json_string(&claim.description)
    ));
    out.push_str(&format!("\"Resource\":{},", json_string(&claim.resource)));
    out.push_str(&format!("\"Basis\":{},", json_string(&claim.basis)));
    out.push_str(&format!(
        "\"CreatedAt\":{},",
        json_string(&claim.created_at)
    ));
    out.push_str(&format!(
        "\"CreatedBy\":{},",
        json_string(&claim.created_by)
    ));
    out.push_str(&format!(
        "\"VerifiedAt\":{},",
        json_string(&claim.verified_at)
    ));
    out.push_str(&format!(
        "\"VerifiedBy\":{},",
        json_string(&claim.verified_by)
    ));
    out.push_str(&format!(
        "\"VerifiedDigest\":{},",
        json_string(&claim.verified_digest)
    ));
    out.push_str(&format!(
        "\"StaleAfter\":{},",
        json_string(&claim.stale_after)
    ));
    out.push_str(&format!(
        "\"Sources\":{},",
        claim_sources_go_json(&claim.sources)
    ));
    out.push_str(&format!(
        "\"EvidenceIDs\":{},",
        str_list_go_json(&claim.evidence_ids)
    ));
    out.push_str(&format!(
        "\"SupportingClaimIDs\":{},",
        str_list_go_json(&claim.supporting_claim_ids)
    ));
    out.push_str(&format!(
        "\"Supersedes\":{},",
        str_list_go_json(&claim.supersedes)
    ));
    out.push_str(&format!(
        "\"ConflictsWith\":{},",
        str_list_go_json(&claim.conflicts_with)
    ));
    out.push_str(&format!(
        "\"Contradicts\":{},",
        contradicts_go_json(&claim.contradicts)
    ));
    out.push_str(&format!("\"Tags\":{},", str_list_go_json(&claim.tags)));
    out.push_str(&format!(
        "\"Transitions\":{},",
        transitions_go_json(&claim.transitions)
    ));
    out.push_str(&format!("\"Body\":{}", json_string(&claim.body)));
    out.push('}');
    out
}

fn str_list_go_json(values: &[String]) -> String {
    if values.is_empty() {
        return "null".to_string();
    }
    let mut out = String::from("[");
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str(&json_string(value));
    }
    out.push(']');
    out
}

fn claim_sources_go_json(sources: &[crate::claims::ClaimSource]) -> String {
    if sources.is_empty() {
        return "null".to_string();
    }
    let mut out = String::from("[");
    for (index, source) in sources.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str(&format!(
            "{{\"id\":{},\"resource\":{}",
            json_string(&source.id),
            json_string(&source.resource)
        ));
        if !source.title.is_empty() {
            out.push_str(&format!(",\"title\":{}", json_string(&source.title)));
        }
        out.push_str(&format!(",\"digest\":{}", json_string(&source.digest)));
        if !source.spans.is_empty() {
            out.push_str("\"spans\":[");
            for (span_index, span) in source.spans.iter().enumerate() {
                if span_index > 0 {
                    out.push(',');
                }
                out.push_str(&format!(
                    "{{\"evidence_id\":{},\"start_line\":{},\"end_line\":{},\"digest\":{}}}",
                    json_string(&span.evidence_id),
                    span.start_line,
                    span.end_line,
                    json_string(&span.digest)
                ));
            }
            out.push(']');
        }
        out.push('}');
    }
    out.push(']');
    out
}

fn contradicts_go_json(values: &[crate::claims::Contradiction]) -> String {
    if values.is_empty() {
        return "null".to_string();
    }
    let mut out = String::from("[");
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str(&format!(
            "{{\"claim_id\":{},\"heuristic\":{}}}",
            json_string(&value.claim_id),
            json_string(&value.heuristic)
        ));
    }
    out.push(']');
    out
}

fn transitions_go_json(values: &[crate::claims::ClaimTransition]) -> String {
    if values.is_empty() {
        return "null".to_string();
    }
    let mut out = String::from("[");
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str(&format!(
            "{{\"kind\":{},\"at\":{},\"by\":{}",
            json_string(&value.kind),
            json_string(&value.at),
            json_string(&value.by)
        ));
        if !value.reason.is_empty() {
            out.push_str(&format!(",\"reason\":{}", json_string(&value.reason)));
        }
        if !value.related_claim_ids.is_empty() {
            out.push_str(&format!(
                ",\"related_claim_ids\":{}",
                str_list_go_json(&value.related_claim_ids)
            ));
        }
        if !value.prior_verification_digest.is_empty() {
            out.push_str(&format!(
                ",\"prior_verification_digest\":{}",
                json_string(&value.prior_verification_digest)
            ));
        }
        if let Some(authorization) = &value.authorization {
            out.push_str(",\"authorization\":{");
            let mut auth_first = true;
            if !authorization.challenge_id.is_empty() {
                out.push_str(&format!(
                    "\"challenge_id\":{}",
                    json_string(&authorization.challenge_id)
                ));
                auth_first = false;
            }
            if !authorization.method.is_empty() {
                if !auth_first {
                    out.push(',');
                }
                out.push_str(&format!(
                    "\"method\":{}",
                    json_string(&authorization.method)
                ));
                auth_first = false;
            }
            if !authorization.mcp_client.is_empty() {
                if !auth_first {
                    out.push(',');
                }
                out.push_str(&format!(
                    "\"mcp_client\":{}",
                    json_string(&authorization.mcp_client)
                ));
            }
            out.push('}');
        }
        out.push('}');
    }
    out.push(']');
    out
}

/// encoding/json shape of runtime.Evidence: the struct carries explicit
/// lowercase tags (unlike Claim), served as `{"evidence":..., "content":...}`.
fn evidence_go_json(evidence: &crate::evidence::Evidence) -> String {
    format!(
        "{{\"id\":{},\"origin\":{},\"captured_at\":{},\"media_type\":{},\"byte_length\":{},\"sha256\":{},\"deduped\":{}}}",
        json_string(&evidence.id),
        json_string(&evidence.origin),
        json_string(&evidence.captured_at),
        json_string(&evidence.media_type),
        evidence.byte_length,
        json_string(&evidence.sha256),
        evidence.deduped
    )
}

fn percent_decode(input: &str) -> String {
    let mut out = Vec::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && bytes[index + 1].is_ascii_hexdigit()
            && bytes[index + 2].is_ascii_hexdigit()
        {
            let hex = &input[index + 1..index + 3];
            if let Ok(byte) = u8::from_str_radix(hex, 16) {
                out.push(byte);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[allow(dead_code)]
fn view_asset_names() -> Vec<&'static str> {
    let mut names = Vec::new();
    for entry in VIEW_ASSETS.entries() {
        use include_dir::DirEntry;
        if let DirEntry::File(file) = entry {
            if let Some(name) = file.path().to_str() {
                names.push(name);
            }
        }
    }
    names.sort();
    names
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claims::{
        Claim, CLAIM_BASIS_EVIDENCE, CLAIM_BASIS_OWNER, CLAIM_STATUS_DRAFT, OKF_CLAIM_TYPE,
    };
    use crate::clock::FixedClock;
    use crate::config::ensure_config;
    use crate::evidence::EvidenceStore;
    use crate::paths::Options;
    use chrono::{TimeZone, Utc};
    use std::net::TcpStream;
    use std::time::Duration;

    struct HttpResponse {
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }

    impl HttpResponse {
        fn header(&self, name: &str) -> Option<&str> {
            self.headers
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.as_str())
        }
    }

    fn request(port: u16, method: &str, path: &str) -> HttpResponse {
        request_with_host(port, method, path, Some(&format!("127.0.0.1:{port}")))
    }

    fn request_with_host(port: u16, method: &str, path: &str, host: Option<&str>) -> HttpResponse {
        // Readiness probe: the serve thread may not have reached accept()
        // yet under parallel-test load. Bound sockets queue the handshake,
        // but retrying connect removes all startup timing from the test.
        let mut stream = None;
        for _ in 0..200 {
            match TcpStream::connect(("127.0.0.1", port)) {
                Ok(connected) => {
                    stream = Some(connected);
                    break;
                }
                Err(_) => std::thread::sleep(Duration::from_millis(10)),
            }
        }
        let mut stream = stream.expect("viewer test server did not become ready");
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        let host_line = host.map(|h| format!("Host: {h}\r\n")).unwrap_or_default();
        let text = format!("{method} {path} HTTP/1.1\r\n{host_line}Connection: close\r\n\r\n");
        stream.write_all(text.as_bytes()).unwrap();
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).unwrap();
        let split = raw
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map(|pos| pos + 4)
            .unwrap_or(raw.len());
        let head = String::from_utf8_lossy(&raw[..split]).into_owned();
        let mut lines = head.split("\r\n");
        let status_line = lines.next().unwrap_or("");
        let status: u16 = status_line
            .split_whitespace()
            .nth(1)
            .unwrap_or("0")
            .parse()
            .unwrap_or(0);
        let mut headers = Vec::new();
        for line in lines {
            if line.is_empty() {
                continue;
            }
            if let Some((key, value)) = line.split_once(':') {
                headers.push((key.trim().to_string(), value.trim().to_string()));
            }
        }
        HttpResponse {
            status,
            headers,
            body: raw[split..].to_vec(),
        }
    }

    fn test_paths(name: &str) -> (std::path::PathBuf, Paths) {
        static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "zbrain-view-{}-{}-{name}",
            std::process::id(),
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
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
        (dir, paths)
    }

    // A simpler harness: drive routing + rendering without sockets for unit
    // coverage, and use one socket smoke test for the accept loop.
    #[test]
    fn loopback_binds_ephemeral_port() {
        let (_dir, paths) = test_paths("bind");
        let mut server = Server::new(paths);
        let url = server.listen().unwrap();
        assert!(url.starts_with("http://127.0.0.1:"));
        assert!(server.port() > 0);
    }

    #[test]
    fn root_serves_page_with_strict_headers() {
        let (_dir, paths) = test_paths("root");
        let body = render_page(&paths).unwrap();
        let text = String::from_utf8(body).unwrap();
        assert!(text.contains("zbrain"));
        let response = route_request(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", &paths);
        let text = String::from_utf8(response).unwrap();
        assert!(text.starts_with("HTTP/1.1 200 OK"));
        assert!(text.contains(
            "Content-Security-Policy: default-src 'self'; script-src 'none'; object-src 'none'"
        ));
        assert!(text.contains("X-Content-Type-Options: nosniff"));
        assert!(!text.to_lowercase().contains("access-control-"));
    }

    #[test]
    fn rejects_mutation_methods() {
        let (_dir, paths) = test_paths("methods");
        for method in [
            "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "CONNECT", "BREW",
        ] {
            let raw = format!("{method} / HTTP/1.1\r\nHost: x\r\n\r\n");
            let response = route_request(raw.as_bytes(), &paths);
            let text = String::from_utf8(response).unwrap();
            assert!(text.starts_with("HTTP/1.1 405"), "{method}: {text}");
            assert!(text.contains("Content-Security-Policy:"), "{method}");
        }
    }

    #[test]
    fn unknown_paths_are_404() {
        let (_dir, paths) = test_paths("404");
        for path in ["/missing.html", "/index.html", "/embed.go"] {
            let raw = format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n");
            let response = route_request(raw.as_bytes(), &paths);
            assert!(
                String::from_utf8(response)
                    .unwrap()
                    .starts_with("HTTP/1.1 404"),
                "{path}"
            );
        }
    }

    #[test]
    fn static_assets_served() {
        let (_dir, paths) = test_paths("static");
        for (path, content_type) in [
            ("/style.css", "text/css; charset=utf-8"),
            ("/app.js", "text/javascript; charset=utf-8"),
        ] {
            let raw = format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n");
            let response = route_request(raw.as_bytes(), &paths);
            let text = String::from_utf8(response).unwrap();
            assert!(text.starts_with("HTTP/1.1 200"), "{path}: {text}");
            assert!(
                text.contains(&format!("Content-Type: {content_type}")),
                "{path}"
            );
        }
    }

    #[test]
    fn page_escapes_claim_and_evidence() {
        let (_dir, paths) = test_paths("escape");
        let now = FixedClock::new(Utc.with_ymd_and_hms(2026, 7, 30, 9, 0, 0).unwrap());
        crate::workspace::create_workspace(&paths, "research", &now).unwrap();
        let source = _dir.join("source.html");
        let raw_html = "<h1>Evidence header</h1>\n<p>raw <b>bold</b> text</p>";
        std::fs::write(&source, raw_html).unwrap();
        let evidence = EvidenceStore::new(paths.clone())
            .add_file("research", &source, "file://source.html", "text/html", &now)
            .unwrap();
        let store = ClaimStore::with_clock(paths.clone(), std::sync::Arc::new(now));
        store
            .write_draft(
                "research",
                Claim {
                    claim_type: OKF_CLAIM_TYPE.to_string(),
                    id: "clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
                    tier: "projects".to_string(),
                    status: CLAIM_STATUS_DRAFT.to_string(),
                    title: "Escaping claim".to_string(),
                    basis: CLAIM_BASIS_EVIDENCE.to_string(),
                    created_at: "2026-07-30T09:00:00Z".to_string(),
                    created_by: "owner".to_string(),
                    evidence_ids: vec![evidence.id],
                    body: "Safe text <script>alert('xss')</script>\n<img src=x onerror=alert(1)>"
                        .to_string(),
                    ..Claim::default()
                },
            )
            .unwrap();
        store
            .approve("research", "clm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .unwrap();

        let page = String::from_utf8(render_page(&paths).unwrap()).unwrap();
        assert!(
            page.contains("Safe text &lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;"),
            "{page}"
        );
        assert!(!page.contains("<script>alert('xss')</script>"));
        assert!(
            page.contains("&lt;h1&gt;Evidence header&lt;/h1&gt;"),
            "{page}"
        );
        assert!(!page.contains("<h1>Evidence header</h1>"));
    }

    #[test]
    fn api_endpoints_return_json() {
        let (_dir, paths) = test_paths("api");
        let now = FixedClock::new(Utc.with_ymd_and_hms(2026, 7, 30, 9, 0, 0).unwrap());
        crate::workspace::create_workspace(&paths, "research", &now).unwrap();
        let store = ClaimStore::with_clock(paths.clone(), std::sync::Arc::new(now));
        store
            .write_draft(
                "research",
                Claim {
                    claim_type: OKF_CLAIM_TYPE.to_string(),
                    id: "clm_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
                    tier: "projects".to_string(),
                    status: CLAIM_STATUS_DRAFT.to_string(),
                    title: "API Claim".to_string(),
                    basis: CLAIM_BASIS_OWNER.to_string(),
                    created_at: "2026-07-30T09:00:00Z".to_string(),
                    created_by: "owner".to_string(),
                    body: "api body\n".to_string(),
                    ..Claim::default()
                },
            )
            .unwrap();
        store
            .approve("research", "clm_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
            .unwrap();

        for path in [
            "/api/workspace",
            "/api/claims",
            "/api/claim/clm_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ] {
            let raw = format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n");
            let response = route_request(raw.as_bytes(), &paths);
            let text = String::from_utf8(response).unwrap();
            assert!(text.starts_with("HTTP/1.1 200"), "{path}: {text}");
            let body = text.split("\r\n\r\n").nth(1).unwrap_or("");
            assert!(
                serde_json::from_str::<serde_json::Value>(body).is_ok(),
                "{path}: {body}"
            );
        }
        let raw = "GET /api/workspace HTTP/1.1\r\nHost: x\r\n\r\n";
        let response = String::from_utf8(route_request(raw.as_bytes(), &paths)).unwrap();
        let body = response.split("\r\n\r\n").nth(1).unwrap_or("");
        let parsed: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(parsed["workspace"], "research");
    }

    #[test]
    fn head_returns_headers_without_body() {
        let (_dir, paths) = test_paths("head");
        let raw = "HEAD / HTTP/1.1\r\nHost: x\r\n\r\n";
        let response = route_request(raw.as_bytes(), &paths);
        let text = String::from_utf8(response).unwrap();
        assert!(text.starts_with("HTTP/1.1 200"), "{text}");
        let body = text.split("\r\n\r\n").nth(1).unwrap_or("MISSING");
        assert_eq!(body, "");
    }

    #[test]
    fn socket_smoke_serves_until_close() {
        let (_dir, paths) = test_paths("socket");
        let mut server = Server::new(paths);
        let url = server.listen().unwrap();
        let port: u16 = url.rsplit(':').next().unwrap().parse().unwrap();
        // The test runner has no TTY; assert loopback explicitly.
        let socket: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        assert!(socket.ip().is_loopback());
        let stop = server.stop_handle();
        let serving = std::thread::spawn(move || {
            let _ = server.serve();
        });
        let response = request(port, "GET", "/");
        assert_eq!(response.status, 200);
        assert_eq!(
            response.header("Content-Security-Policy"),
            Some("default-src 'self'; script-src 'none'; object-src 'none'")
        );
        assert_eq!(response.header("X-Content-Type-Options"), Some("nosniff"));
        assert!(response.header("Access-Control-Allow-Origin").is_none());
        assert!(String::from_utf8(response.body).unwrap().contains("zbrain"));
        let head = request(port, "HEAD", "/");
        assert_eq!(head.status, 200);
        assert!(head.body.is_empty());
        let post = request(port, "POST", "/");
        assert_eq!(post.status, 405);
        stop.store(true, Ordering::SeqCst);
        serving.join().unwrap();
    }

    #[test]
    fn host_header_must_be_loopback_with_bound_port() {
        let (_dir, paths) = test_paths("host");
        let mut server = Server::new(paths);
        let url = server.listen().unwrap();
        let port: u16 = url.rsplit(':').next().unwrap().parse().unwrap();
        let other = if port == 65535 { port - 1 } else { port + 1 };
        let stop = server.stop_handle();
        let serving = std::thread::spawn(move || {
            let _ = server.serve();
        });
        for path in ["/", "/api/workspace", "/api/claims"] {
            for bad in [
                "attacker.example".to_string(),
                format!("attacker.example:{port}"),
                format!("127.0.0.1:{other}"),
                "127.0.0.1".to_string(),
                format!("[::1]:{port}"),
                format!("localhost.evil:{port}"),
            ] {
                let response = request_with_host(port, "GET", path, Some(&bad));
                assert_eq!(response.status, 421, "{path} Host: {bad}");
                assert_eq!(response.header("X-Content-Type-Options"), Some("nosniff"));
                assert!(response.header("Content-Security-Policy").is_some());
                assert!(response.header("Access-Control-Allow-Origin").is_none());
                let body = String::from_utf8(response.body).unwrap();
                assert!(!body.contains("zbrain"), "{path} leaked body: {body}");
            }
            let missing = request_with_host(port, "GET", path, None);
            assert_eq!(missing.status, 400, "{path} without Host");
        }
        for good in [
            format!("127.0.0.1:{port}"),
            format!("localhost:{port}"),
            format!("LOCALHOST:{port}"),
        ] {
            for path in ["/", "/api/workspace"] {
                let response = request_with_host(port, "GET", path, Some(&good));
                assert_eq!(response.status, 200, "{path} Host: {good}");
            }
        }
        stop.store(true, Ordering::SeqCst);
        serving.join().unwrap();
    }

    #[test]
    fn escape_html_matches_go_oracle() {
        assert_eq!(escape_html("&<>\"'"), "&amp;&lt;&gt;&#34;&#39;");
        assert_eq!(escape_html("plain · text"), "plain · text");
    }
}
