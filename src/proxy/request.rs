//! Shared request lifecycle helpers.
//!
//! The proxy handles requests across three transport paths (H1, H2-to-H1,
//! H2-to-H2) that each have different I/O but share identical bookkeeping:
//! span recording, Prometheus metrics, exchange logging, and LLM request
//! transforms. This module extracts that common logic.

use super::llm;
use super::logging;
use super::prom::ProxyMetrics;
use super::transform::{LlmRequestContext, TransformPipeline, TransformResult};
use std::path::PathBuf;
use std::time::Instant;
use tracing::{info, warn, Span};

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
        span.record("http.response.status_code", self.status_code as i64);
        span.record("alice.policy.action", self.action);
        span.record("alice.policy.rule_index", self.rule_index as i64);
        span.record("alice.duration_ms", self.start.elapsed().as_millis() as i64);
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

/// Run the LLM transform pipeline on a request body, if applicable.
///
/// Returns `None` if transforms don't apply (wrong path, empty body, no
/// pipeline, or unparseable JSON). Returns `Some(TransformResult)` if the
/// pipeline was executed; the caller inspects `Continue` vs `Block`.
///
/// On `Continue`, `body` is mutated in place with the transformed content.
pub fn apply_transforms(
    pipeline: &TransformPipeline,
    host: &str,
    path: &str,
    body: &mut Vec<u8>,
) -> Option<TransformResult> {
    if pipeline.is_empty() || !llm::is_messages_endpoint(path) || body.is_empty() {
        return None;
    }

    let parsed: serde_json::Value = serde_json::from_slice(body).ok()?;
    let mut ctx = LlmRequestContext {
        host: host.to_string(),
        path: path.to_string(),
        body: parsed,
    };

    let result = pipeline.process(&mut ctx);
    if matches!(result, TransformResult::Continue) {
        if let Ok(modified) = serde_json::to_vec(&ctx.body) {
            *body = modified;
        }
    }
    Some(result)
}
