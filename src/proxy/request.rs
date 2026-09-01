//! Shared request lifecycle helpers.
//!
//! The proxy handles requests across three transport paths (H1, H2-to-H1,
//! H2-to-H2) that each have different I/O but share identical bookkeeping:
//! span recording, Prometheus metrics, and exchange logging. This module
//! extracts that common logic.

use super::logging;
use super::prom::ProxyMetrics;
use std::path::PathBuf;
use std::time::Instant;
use tracing::{debug, info, warn, Span};

/// Completed request metadata for recording spans, metrics, and logs.
///
/// Each transport path populates this after its I/O completes, then calls
/// the methods to record the outcome. This eliminates the copy-pasted
/// bookkeeping blocks that were previously duplicated across all three paths.
pub struct RequestOutcome<'a> {
    pub host: &'a str,
    pub method: &'a str,
    pub path: &'a str,
    pub status_code: u16,
    pub action: &'static str, // "allow" or "deny"
    pub rule_index: usize,
    pub request_bytes: usize,
    pub response_bytes: usize,
    pub start: Instant,
    // For logging
    pub client_addr: &'a str,
    pub request_headers: &'a [u8],
    pub request_body: &'a [u8],
    pub response_headers: &'a [u8],
    pub response_body: &'a [u8],
}

impl RequestOutcome<'_> {
    /// Record policy decision and timing into the current tracing span.
    pub fn record_span(&self, span: &Span) {
        let _ = span.record("http.response.status_code", self.status_code as i64);
        let _ = span.record("alice.policy.action", self.action);
        let _ = span.record("alice.policy.rule_index", self.rule_index as i64);
        let _ = span.record("alice.duration_ms", self.start.elapsed().as_millis() as i64);
    }

    /// Increment Prometheus counters for this request.
    pub fn record_metrics(&self, metrics: &ProxyMetrics) {
        let status_str = self.status_code.to_string();
        metrics
            .requests_total
            .with_label_values(&[self.host, self.method, &status_str, self.action])
            .inc();
        metrics
            .request_bytes_total
            .with_label_values(&[self.host])
            .inc_by(self.request_bytes as u64);
        metrics
            .response_bytes_total
            .with_label_values(&[self.host])
            .inc_by(self.response_bytes as u64);
    }

    /// Emit a per-request summary event with bytes-in / bytes-out / duration.
    ///
    /// Diagnostic for streaming hangs: a long-duration request with
    /// `bytes_in >> bytes_out` (or vice versa) indicates the proxy is
    /// the bottleneck. Balanced bytes with long duration means we're
    /// faithfully relaying an upstream stall.
    ///
    /// Non-2xx responses (4xx/5xx) are surfaced at `warn!` with a body
    /// excerpt so an operator watching the journal during a wedge can
    /// see whether `/v1/messages` is returning 401 / 429 / 5xx / empty
    /// without packet capture. 2xx/3xx stays at `debug!` to avoid
    /// flooding the journal during normal traffic. Callers must
    /// populate `response_body` with at least a leading excerpt for
    /// non-2xx, even when full-exchange logging (`log_dir`) is off —
    /// otherwise the operator only sees the status code.
    pub fn record_summary(&self) {
        if (400..600).contains(&self.status_code) {
            let excerpt = response_excerpt(self.response_body);
            tracing::warn!(
                target: "alice::proxy::request",
                host = %self.host,
                method = %self.method,
                path = %self.path,
                status = self.status_code,
                request_bytes = self.request_bytes,
                response_bytes = self.response_bytes,
                duration_ms = self.start.elapsed().as_millis() as u64,
                response_body_excerpt = %excerpt,
                "request.summary.non_2xx"
            );
        } else {
            debug!(
                target: "alice::proxy::request",
                host = %self.host,
                method = %self.method,
                path = %self.path,
                status = self.status_code,
                request_bytes = self.request_bytes,
                response_bytes = self.response_bytes,
                duration_ms = self.start.elapsed().as_millis() as u64,
                "request.summary"
            );
        }
    }

    /// Write the exchange to the log directory, if configured.
    pub async fn log_exchange(&self, log_dir: &Option<PathBuf>) {
        if let Some(ref dir) = log_dir {
            let url = format!("https://{}{}", self.host, self.path);
            if let Err(e) = logging::log_exchange(
                dir,
                self.client_addr,
                self.method,
                &url,
                self.request_headers,
                self.request_body,
                self.status_code,
                self.response_headers,
                self.response_body,
                self.start,
            )
            .await
            {
                warn!(error = %e, "failed to log HTTP exchange");
            }
        }
    }

    /// Record a denied request: span fields, info log, and deny metric.
    ///
    /// The caller is still responsible for sending the transport-specific
    /// rejection (H1 `403 Forbidden` response or H2 403 response frame).
    pub fn record_deny(&self, span: &Span, metrics: &ProxyMetrics, protocol_tag: &str) {
        self.record_span(span);
        info!(
            host = %self.host,
            path = %self.path,
            rule = self.rule_index,
            "denied{}", if protocol_tag.is_empty() { String::new() } else { format!(" ({})", protocol_tag) },
        );
        metrics
            .requests_total
            .with_label_values(&[self.host, self.method, "403", "deny"])
            .inc();
    }
}

/// Cap on how many bytes of a non-2xx response body we keep around for
/// diagnostic logging. Anthropic's error responses are JSON ~200-500
/// bytes; 1KiB is comfortably larger than typical and small enough that
/// always-capturing it on the proxy hot path is harmless. Anything past
/// the cap is dropped.
pub const NON_2XX_EXCERPT_CAP: usize = 1024;

/// Render a short, journal-friendly excerpt of a response body for
/// inclusion in the non-2xx summary log. UTF-8 lossy (binary error
/// pages render as ASCII garble rather than truncating mid-codepoint).
/// Newlines collapse to spaces so the line stays single-row in
/// journalctl. Empty input → `<empty>`.
fn response_excerpt(body: &[u8]) -> String {
    if body.is_empty() {
        return "<empty>".to_string();
    }
    let take = body.len().min(NON_2XX_EXCERPT_CAP);
    let s = String::from_utf8_lossy(&body[..take]);
    let mut out = s.replace(['\n', '\r'], " ");
    if body.len() > NON_2XX_EXCERPT_CAP {
        out.push('…');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn excerpt_empty_input_renders_marker() {
        assert_eq!(response_excerpt(b""), "<empty>");
    }

    #[test]
    fn excerpt_collapses_newlines_to_spaces() {
        let body = b"{\n  \"error\": \"rate_limit\"\n}\n";
        let out = response_excerpt(body);
        assert!(!out.contains('\n'));
        assert!(out.contains("rate_limit"));
    }

    #[test]
    fn excerpt_truncates_with_marker_past_cap() {
        let body = vec![b'A'; NON_2XX_EXCERPT_CAP * 2];
        let out = response_excerpt(&body);
        assert!(out.ends_with('…'));
        // Output is the cap's worth of A's plus the ellipsis.
        assert_eq!(
            out.chars().filter(|&c| c == 'A').count(),
            NON_2XX_EXCERPT_CAP
        );
    }

    #[test]
    fn excerpt_keeps_short_bodies_intact() {
        let body = b"forbidden";
        let out = response_excerpt(body);
        assert_eq!(out, "forbidden");
    }
}
