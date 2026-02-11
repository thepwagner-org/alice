//! LLM API response parsing for metrics extraction.
//!
//! Parses SSE streaming responses from the Anthropic Messages API
//! to extract token usage, model information, and tool call details.
//! Designed for incremental processing — chunks are fed as they arrive
//! from upstream, with zero latency impact on the proxied stream.

use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;

/// Maximum length for tool argument values (truncated with "..." suffix)
const MAX_ARG_VALUE_LEN: usize = 256;

/// A tool call extracted from an LLM response
#[derive(Debug, Clone, Serialize)]
pub struct ToolCall {
    /// Tool name (e.g., "Bash", "Read", "Edit")
    pub name: String,
    /// Tool arguments as JSON (with large values truncated)
    pub arguments: serde_json::Value,
}

/// Extracted metrics from an LLM API response
#[derive(Debug, Default, Clone, Serialize)]
pub struct LlmMetrics {
    /// Model name (e.g., "claude-opus-4-6")
    pub model: Option<String>,
    /// Input/prompt token count
    pub input_tokens: Option<u64>,
    /// Output/completion token count
    pub output_tokens: Option<u64>,
    /// Cache read tokens
    pub cache_read_tokens: Option<u64>,
    /// Tool calls with names and truncated arguments
    pub tool_calls: Vec<ToolCall>,
    /// Host that served this response
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Request path
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

/// Thread-safe store of LLM completion metrics, queryable via the metrics endpoint.
pub type LlmMetricsStore = Arc<Mutex<Vec<LlmMetrics>>>;

/// In-progress tool call being accumulated from streaming events
#[derive(Debug, Default)]
struct PendingToolCall {
    name: String,
    /// Accumulated partial JSON for the arguments
    input_json: String,
}

/// Check if a request path is the messages endpoint (not count_tokens).
pub fn is_messages_endpoint(path: &str) -> bool {
    let path = path.split('?').next().unwrap_or(path);
    path.starts_with("/v1/messages") && !path.contains("count_tokens")
}

/// Check if response headers indicate an SSE stream (raw header string).
pub fn is_sse_response(headers_str: &str) -> bool {
    headers_str.lines().any(|line| {
        let lower = line.to_lowercase();
        lower.starts_with("content-type:") && lower.contains("text/event-stream")
    })
}

/// Check if an HTTP `HeaderMap` indicates an SSE stream.
pub fn is_sse_header_map(headers: &http::HeaderMap) -> bool {
    headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.contains("text/event-stream"))
        .unwrap_or(false)
}

/// Accumulator for parsing SSE streaming responses.
///
/// Processes SSE events incrementally as they arrive, accumulating metrics
/// until the stream completes.
#[derive(Debug, Default)]
pub struct StreamingMetricsAccumulator {
    metrics: LlmMetrics,
    /// Buffer for incomplete SSE lines spanning chunk boundaries
    line_buffer: String,
    /// In-progress tool calls indexed by content block index
    pending_tools: HashMap<u64, PendingToolCall>,
}

impl StreamingMetricsAccumulator {
    /// Create a new accumulator.
    pub fn new() -> Self {
        Self::default()
    }

    /// Process a chunk of SSE data, extracting metrics from complete events.
    pub fn process_chunk(&mut self, chunk: &[u8]) {
        let chunk_str = match std::str::from_utf8(chunk) {
            Ok(s) => s,
            Err(_) => return,
        };

        self.line_buffer.push_str(chunk_str);

        while let Some(newline_pos) = self.line_buffer.find('\n') {
            let line = self.line_buffer[..newline_pos]
                .trim_end_matches('\r')
                .to_string();
            self.line_buffer = self.line_buffer[newline_pos + 1..].to_string();

            self.process_line(&line);
        }
    }

    /// Process a single SSE line.
    fn process_line(&mut self, line: &str) {
        // Skip empty lines and event type lines
        if line.is_empty() || line.starts_with("event:") {
            return;
        }

        if let Some(data) = line.strip_prefix("data: ") {
            if data == "[DONE]" {
                return;
            }

            if let Ok(json) = serde_json::from_str::<serde_json::Value>(data) {
                self.process_event(&json);
            }
        }
    }

    /// Process a parsed SSE event.
    fn process_event(&mut self, json: &serde_json::Value) {
        let event_type = json.get("type").and_then(|v| v.as_str());

        match event_type {
            Some("message_start") => {
                if let Some(message) = json.get("message") {
                    if let Some(model) = message.get("model").and_then(|v| v.as_str()) {
                        self.metrics.model = Some(model.to_string());
                    }
                    if let Some(usage) = message.get("usage") {
                        if let Some(input) = usage.get("input_tokens").and_then(|v| v.as_u64()) {
                            self.metrics.input_tokens = Some(input);
                        }
                        if let Some(cache) = usage
                            .get("cache_read_input_tokens")
                            .and_then(|v| v.as_u64())
                        {
                            self.metrics.cache_read_tokens = Some(cache);
                        }
                    }
                }
            }
            Some("content_block_start") => {
                if let (Some(index), Some(content_block)) = (
                    json.get("index").and_then(|v| v.as_u64()),
                    json.get("content_block"),
                ) {
                    if content_block.get("type").and_then(|v| v.as_str()) == Some("tool_use") {
                        if let Some(name) = content_block.get("name").and_then(|v| v.as_str()) {
                            self.pending_tools.insert(
                                index,
                                PendingToolCall {
                                    name: name.to_string(),
                                    input_json: String::new(),
                                },
                            );
                        }
                    }
                }
            }
            Some("content_block_delta") => {
                if let (Some(index), Some(delta)) = (
                    json.get("index").and_then(|v| v.as_u64()),
                    json.get("delta"),
                ) {
                    if delta.get("type").and_then(|v| v.as_str()) == Some("input_json_delta") {
                        if let Some(partial) = delta.get("partial_json").and_then(|v| v.as_str()) {
                            if let Some(pending) = self.pending_tools.get_mut(&index) {
                                pending.input_json.push_str(partial);
                            }
                        }
                    }
                }
            }
            Some("content_block_stop") => {
                if let Some(index) = json.get("index").and_then(|v| v.as_u64()) {
                    if let Some(pending) = self.pending_tools.remove(&index) {
                        let arguments = if pending.input_json.is_empty() {
                            serde_json::Value::Object(serde_json::Map::new())
                        } else {
                            match serde_json::from_str::<serde_json::Value>(&pending.input_json) {
                                Ok(mut val) => {
                                    truncate_json_values(&mut val, MAX_ARG_VALUE_LEN);
                                    val
                                }
                                Err(_) => {
                                    let truncated =
                                        truncate_string(&pending.input_json, MAX_ARG_VALUE_LEN);
                                    serde_json::Value::String(truncated)
                                }
                            }
                        };

                        self.metrics.tool_calls.push(ToolCall {
                            name: pending.name,
                            arguments,
                        });
                    }
                }
            }
            Some("message_delta") => {
                if let Some(usage) = json.get("usage") {
                    if let Some(output) = usage.get("output_tokens").and_then(|v| v.as_u64()) {
                        self.metrics.output_tokens = Some(output);
                    }
                }
            }
            _ => {} // ping, text_delta, thinking_delta, signature_delta, message_stop
        }
    }

    /// Finalize and return accumulated metrics.
    pub fn finalize(self) -> LlmMetrics {
        self.metrics
    }

    /// Emit metrics as a tracing event, and push to store if provided.
    pub fn emit(self, host: &str, path: &str, store: Option<&LlmMetricsStore>) {
        let mut metrics = self.finalize();
        metrics.host = Some(host.to_string());
        metrics.path = Some(path.to_string());

        let model = metrics.model.as_deref().unwrap_or("unknown");
        let input_tokens = metrics.input_tokens.unwrap_or(0);
        let output_tokens = metrics.output_tokens.unwrap_or(0);
        let cache_read_tokens = metrics.cache_read_tokens.unwrap_or(0);
        let tool_calls_json = serde_json::to_string(&metrics.tool_calls).unwrap_or_default();

        info!(
            target: "alice::llm",
            model = %model,
            input_tokens = input_tokens,
            output_tokens = output_tokens,
            cache_read_tokens = cache_read_tokens,
            tool_calls = %tool_calls_json,
            tool_count = metrics.tool_calls.len(),
            host = %host,
            path = %path,
            "llm.completion"
        );

        if let Some(store) = store {
            // Use try_lock to avoid blocking the proxy path; drop if contended
            if let Ok(mut vec) = store.try_lock() {
                vec.push(metrics);
            }
        }
    }
}

/// Truncate a string to max_len bytes, adding "..." if truncated.
fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        let mut end = max_len.saturating_sub(3);
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}...", &s[..end])
    }
}

/// Recursively truncate string values in a JSON value.
fn truncate_json_values(value: &mut serde_json::Value, max_len: usize) {
    match value {
        serde_json::Value::String(s) => {
            if s.len() > max_len {
                *s = truncate_string(s, max_len);
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                truncate_json_values(item, max_len);
            }
        }
        serde_json::Value::Object(map) => {
            for (_, v) in map.iter_mut() {
                truncate_json_values(v, max_len);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Text-only SSE response (haiku model, topic classification)
    const SSE_TEXT_ONLY: &str = concat!(
        "event: message_start\n",
        "data: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-haiku-4-5-20251001\",",
        "\"id\":\"msg_01JRyBAYDgNaozQXrghxWu9G\",\"type\":\"message\",\"role\":\"assistant\",",
        "\"content\":[],\"stop_reason\":null,\"stop_sequence\":null,",
        "\"usage\":{\"input_tokens\":291,\"cache_creation_input_tokens\":0,",
        "\"cache_read_input_tokens\":0,\"output_tokens\":1}}}\n\n",
        "event: content_block_start\n",
        "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
        "event: ping\n",
        "data: {\"type\": \"ping\"}\n\n",
        "event: content_block_delta\n",
        "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hello world\"}}\n\n",
        "event: content_block_stop\n",
        "data: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
        "event: message_delta\n",
        "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},",
        "\"usage\":{\"input_tokens\":291,\"output_tokens\":14}}\n\n",
        "event: message_stop\n",
        "data: {\"type\":\"message_stop\"}\n\n",
    );

    // Single tool call response (Bash: cargo fmt --check)
    const SSE_SINGLE_TOOL: &str = concat!(
        "event: message_start\n",
        "data: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-opus-4-6\",",
        "\"id\":\"msg_013DqEcVD4B1bL3DYtyNAD7L\",\"type\":\"message\",\"role\":\"assistant\",",
        "\"content\":[],\"stop_reason\":null,\"stop_sequence\":null,",
        "\"usage\":{\"input_tokens\":3,\"cache_creation_input_tokens\":60,",
        "\"cache_read_input_tokens\":21612,\"output_tokens\":1}}}\n\n",
        "event: content_block_start\n",
        "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":",
        "{\"type\":\"tool_use\",\"id\":\"toolu_01XGoNan4g2EDv5xp63jCmXB\",\"name\":\"Bash\",\"input\":{}}}\n\n",
        "event: ping\n",
        "data: {\"type\": \"ping\"}\n\n",
        "event: content_block_delta\n",
        "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"\"}}\n\n",
        "event: content_block_delta\n",
        "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"command\\\": \"}}\n\n",
        "event: content_block_delta\n",
        "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"\\\"cargo fmt --check\"}}\n\n",
        "event: content_block_delta\n",
        "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\" 2>&1\\\"\"}}\n\n",
        "event: content_block_delta\n",
        "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\", \\\"description\\\": \\\"Check formatting\\\"}\"}}\n\n",
        "event: content_block_stop\n",
        "data: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
        "event: message_delta\n",
        "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"},",
        "\"usage\":{\"input_tokens\":3,\"output_tokens\":78}}\n\n",
        "event: message_stop\n",
        "data: {\"type\":\"message_stop\"}\n\n",
    );

    // Thinking + text + 2 tool calls
    const SSE_THINKING_MULTI_TOOL: &str = concat!(
        "event: message_start\n",
        "data: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-opus-4-6\",",
        "\"id\":\"msg_015Jg2D86iFGemdXGSJVHy6Q\",\"type\":\"message\",\"role\":\"assistant\",",
        "\"content\":[],\"stop_reason\":null,\"stop_sequence\":null,",
        "\"usage\":{\"input_tokens\":3,\"cache_creation_input_tokens\":41,",
        "\"cache_read_input_tokens\":20425,\"output_tokens\":1}}}\n\n",
        // text block (index 0)
        "event: content_block_start\n",
        "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
        "event: content_block_delta\n",
        "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Thinking...\"}}\n\n",
        "event: content_block_stop\n",
        "data: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
        // thinking block (index 1)
        "event: content_block_start\n",
        "data: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"thinking\",\"thinking\":\"\",\"signature\":\"\"}}\n\n",
        "event: content_block_delta\n",
        "data: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"Let me run the checks.\"}}\n\n",
        "event: content_block_stop\n",
        "data: {\"type\":\"content_block_stop\",\"index\":1}\n\n",
        // text block (index 2)
        "event: content_block_start\n",
        "data: {\"type\":\"content_block_start\",\"index\":2,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
        "event: content_block_delta\n",
        "data: {\"type\":\"content_block_delta\",\"index\":2,\"delta\":{\"type\":\"text_delta\",\"text\":\"Let me run the checks.\"}}\n\n",
        "event: content_block_stop\n",
        "data: {\"type\":\"content_block_stop\",\"index\":2}\n\n",
        // tool_use block (index 3) - Bash cargo fmt
        "event: content_block_start\n",
        "data: {\"type\":\"content_block_start\",\"index\":3,\"content_block\":",
        "{\"type\":\"tool_use\",\"id\":\"toolu_01DeUho1xnqCoprvr5hStFCA\",\"name\":\"Bash\",\"input\":{}}}\n\n",
        "event: content_block_delta\n",
        "data: {\"type\":\"content_block_delta\",\"index\":3,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"command\\\": \"}}\n\n",
        "event: content_block_delta\n",
        "data: {\"type\":\"content_block_delta\",\"index\":3,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"\\\"cargo fmt --check 2>&1\\\"\"}}\n\n",
        "event: content_block_delta\n",
        "data: {\"type\":\"content_block_delta\",\"index\":3,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\", \\\"description\\\": \\\"Check formatting\\\"}\"}}\n\n",
        "event: content_block_stop\n",
        "data: {\"type\":\"content_block_stop\",\"index\":3}\n\n",
        // tool_use block (index 4) - Bash cargo clippy
        "event: content_block_start\n",
        "data: {\"type\":\"content_block_start\",\"index\":4,\"content_block\":",
        "{\"type\":\"tool_use\",\"id\":\"toolu_01MTVp8N8dPVwK62BmrEqVR1\",\"name\":\"Bash\",\"input\":{}}}\n\n",
        "event: content_block_delta\n",
        "data: {\"type\":\"content_block_delta\",\"index\":4,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"command\\\": \\\"cargo clippy 2>&1\\\"\"}}\n\n",
        "event: content_block_delta\n",
        "data: {\"type\":\"content_block_delta\",\"index\":4,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\", \\\"description\\\": \\\"Run clippy lints\\\"}\"}}\n\n",
        "event: content_block_stop\n",
        "data: {\"type\":\"content_block_stop\",\"index\":4}\n\n",
        // message_delta with final usage
        "event: message_delta\n",
        "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"},",
        "\"usage\":{\"input_tokens\":3,\"output_tokens\":245}}\n\n",
        "event: message_stop\n",
        "data: {\"type\":\"message_stop\"}\n\n",
    );

    #[test]
    fn test_text_only_response() {
        let mut acc = StreamingMetricsAccumulator::new();
        acc.process_chunk(SSE_TEXT_ONLY.as_bytes());
        let metrics = acc.finalize();

        assert_eq!(metrics.model.as_deref(), Some("claude-haiku-4-5-20251001"));
        assert_eq!(metrics.input_tokens, Some(291));
        assert_eq!(metrics.output_tokens, Some(14));
        assert_eq!(metrics.cache_read_tokens, Some(0));
        assert!(metrics.tool_calls.is_empty());
    }

    #[test]
    fn test_single_tool_call() {
        let mut acc = StreamingMetricsAccumulator::new();
        acc.process_chunk(SSE_SINGLE_TOOL.as_bytes());
        let metrics = acc.finalize();

        assert_eq!(metrics.model.as_deref(), Some("claude-opus-4-6"));
        assert_eq!(metrics.input_tokens, Some(3));
        assert_eq!(metrics.output_tokens, Some(78));
        assert_eq!(metrics.cache_read_tokens, Some(21612));
        assert_eq!(metrics.tool_calls.len(), 1);
        assert_eq!(metrics.tool_calls[0].name, "Bash");
        assert_eq!(
            metrics.tool_calls[0].arguments["command"],
            "cargo fmt --check 2>&1"
        );
        assert_eq!(
            metrics.tool_calls[0].arguments["description"],
            "Check formatting"
        );
    }

    #[test]
    fn test_thinking_multi_tool() {
        let mut acc = StreamingMetricsAccumulator::new();
        acc.process_chunk(SSE_THINKING_MULTI_TOOL.as_bytes());
        let metrics = acc.finalize();

        assert_eq!(metrics.model.as_deref(), Some("claude-opus-4-6"));
        assert_eq!(metrics.input_tokens, Some(3));
        assert_eq!(metrics.output_tokens, Some(245));
        assert_eq!(metrics.cache_read_tokens, Some(20425));

        // Should have 2 tool calls (thinking and text blocks ignored)
        assert_eq!(metrics.tool_calls.len(), 2);

        assert_eq!(metrics.tool_calls[0].name, "Bash");
        assert_eq!(
            metrics.tool_calls[0].arguments["command"],
            "cargo fmt --check 2>&1"
        );

        assert_eq!(metrics.tool_calls[1].name, "Bash");
        assert_eq!(
            metrics.tool_calls[1].arguments["command"],
            "cargo clippy 2>&1"
        );
    }

    #[test]
    fn test_chunked_delivery() {
        // Feed the SSE data in small arbitrary chunks to test line buffering
        let mut acc = StreamingMetricsAccumulator::new();
        let data = SSE_SINGLE_TOOL.as_bytes();

        // Feed 17 bytes at a time (prime number to avoid alignment)
        for chunk in data.chunks(17) {
            acc.process_chunk(chunk);
        }

        let metrics = acc.finalize();
        assert_eq!(metrics.model.as_deref(), Some("claude-opus-4-6"));
        assert_eq!(metrics.tool_calls.len(), 1);
        assert_eq!(metrics.tool_calls[0].name, "Bash");
        assert_eq!(
            metrics.tool_calls[0].arguments["command"],
            "cargo fmt --check 2>&1"
        );
    }

    #[test]
    fn test_is_messages_endpoint() {
        assert!(is_messages_endpoint("/v1/messages"));
        assert!(is_messages_endpoint("/v1/messages?beta=true"));
        assert!(!is_messages_endpoint("/v1/messages/count_tokens"));
        assert!(!is_messages_endpoint("/v1/messages/count_tokens?beta=true"));
        assert!(!is_messages_endpoint("/api/hello"));
    }

    #[test]
    fn test_is_sse_response() {
        assert!(is_sse_response(
            "Content-Type: text/event-stream; charset=utf-8\r\n"
        ));
        assert!(is_sse_response("content-type: text/event-stream\r\n"));
        assert!(!is_sse_response("Content-Type: application/json\r\n"));
    }

    #[test]
    fn test_truncate_json_values() {
        let long_string = "x".repeat(300);
        let mut val = serde_json::json!({
            "short": "hello",
            "long": long_string,
            "nested": {"also_long": long_string.clone()}
        });
        truncate_json_values(&mut val, 256);

        assert_eq!(val["short"], "hello");
        assert!(val["long"].as_str().unwrap().len() <= 256);
        assert!(val["long"].as_str().unwrap().ends_with("..."));
        assert!(val["nested"]["also_long"].as_str().unwrap().len() <= 256);
    }
}
