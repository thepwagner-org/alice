//! Request/response logging for development and debugging.
//!
//! When `log_dir` is configured, writes one JSON file per HTTP exchange
//! containing full request and response details including headers and bodies.
//!
//! WARNING: Logs contain sensitive data (auth tokens, request bodies).
//! Only enable for development/debugging. Ensure log_dir is gitignored.

use anyhow::Result;
use base64::prelude::*;
use serde::Serialize;
use std::collections::HashMap;
use std::path::Path;
use std::time::Instant;
use tokio::fs;
use tracing::debug;

/// Maximum body size to log (1MB). Larger bodies are truncated.
const MAX_BODY_SIZE: usize = 1024 * 1024;

/// Logged HTTP request
#[derive(Debug, Serialize)]
pub struct RequestLog {
    pub method: String,
    pub url: String,
    pub headers: HashMap<String, String>,
    pub body: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_encoding: Option<String>,
    pub body_truncated: bool,
    pub body_size: usize,
}

/// Logged HTTP response
#[derive(Debug, Serialize)]
pub struct ResponseLog {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_encoding: Option<String>,
    pub body_truncated: bool,
    pub body_size: usize,
}

/// Full HTTP exchange log
#[derive(Debug, Serialize)]
pub struct ExchangeLog {
    pub timestamp: String,
    pub duration_ms: u64,
    pub client_addr: String,
    pub request: RequestLog,
    pub response: ResponseLog,
}

/// Encode body for JSON logging.
/// Returns (encoded_body, encoding_type, was_truncated).
fn encode_body(body: &[u8]) -> (String, Option<String>, bool) {
    let truncated = body.len() > MAX_BODY_SIZE;
    let body_slice = if truncated {
        &body[..MAX_BODY_SIZE]
    } else {
        body
    };

    // Try UTF-8 first
    match std::str::from_utf8(body_slice) {
        Ok(s) => (s.to_string(), None, truncated),
        Err(_) => {
            // Binary data - base64 encode
            (
                BASE64_STANDARD.encode(body_slice),
                Some("base64".to_string()),
                truncated,
            )
        }
    }
}

/// Parse raw HTTP headers into a HashMap.
/// Handles both "Header: Value" format and skips malformed lines.
pub fn parse_headers_to_map(headers: &[u8]) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let headers_str = String::from_utf8_lossy(headers);

    for line in headers_str.lines() {
        // Skip request/status line and empty lines
        if line.starts_with("HTTP/")
            || line.starts_with("GET ")
            || line.starts_with("POST ")
            || line.starts_with("PUT ")
            || line.starts_with("DELETE ")
            || line.starts_with("PATCH ")
            || line.starts_with("HEAD ")
            || line.starts_with("OPTIONS ")
            || line.is_empty()
        {
            continue;
        }

        if let Some((name, value)) = line.split_once(':') {
            map.insert(name.trim().to_lowercase(), value.trim().to_string());
        }
    }

    map
}

/// Sanitize a path for use in filenames.
/// Replaces path separators and special characters with underscores.
fn sanitize_path(path: &str) -> String {
    path.trim_start_matches('/')
        .replace(['/', '?', '&', '=', ' '], "_")
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-' || *c == '.')
        .take(100) // Limit length
        .collect()
}

/// Log an HTTP exchange to a JSON file.
#[allow(clippy::too_many_arguments)]
pub async fn log_exchange(
    log_dir: &Path,
    client_addr: &str,
    method: &str,
    url: &str,
    request_headers: &[u8],
    request_body: &[u8],
    response_status: u16,
    response_headers: &[u8],
    response_body: &[u8],
    start_time: Instant,
) -> Result<()> {
    let duration_ms = start_time.elapsed().as_millis() as u64;
    let timestamp = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true);

    // Parse URL for filename
    let host = url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("unknown")
        .split(':')
        .next()
        .unwrap_or("unknown");

    let path = url
        .find('/')
        .and_then(|i| url[i..].find('/').map(|j| &url[i + j..]))
        .unwrap_or("/");

    let sanitized_path = sanitize_path(path);
    let filename = format!(
        "{}_{}_{}_{}.json",
        timestamp.replace([':', '.'], "-"),
        method,
        host,
        if sanitized_path.is_empty() {
            "root"
        } else {
            &sanitized_path
        }
    );

    // Encode bodies
    let (req_body, req_encoding, req_truncated) = encode_body(request_body);
    let (res_body, res_encoding, res_truncated) = encode_body(response_body);

    let exchange = ExchangeLog {
        timestamp,
        duration_ms,
        client_addr: client_addr.to_string(),
        request: RequestLog {
            method: method.to_string(),
            url: url.to_string(),
            headers: parse_headers_to_map(request_headers),
            body: req_body,
            body_encoding: req_encoding,
            body_truncated: req_truncated,
            body_size: request_body.len(),
        },
        response: ResponseLog {
            status: response_status,
            headers: parse_headers_to_map(response_headers),
            body: res_body,
            body_encoding: res_encoding,
            body_truncated: res_truncated,
            body_size: response_body.len(),
        },
    };

    let json = serde_json::to_string_pretty(&exchange)?;
    let file_path = log_dir.join(&filename);

    fs::write(&file_path, json).await?;
    debug!(path = %file_path.display(), "logged HTTP exchange");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_body_utf8() {
        let body = b"Hello, world!";
        let (encoded, encoding, truncated) = encode_body(body);
        assert_eq!(encoded, "Hello, world!");
        assert!(encoding.is_none());
        assert!(!truncated);
    }

    #[test]
    fn test_encode_body_binary() {
        let body = &[0xFF, 0xFE, 0x00, 0x01];
        let (encoded, encoding, truncated) = encode_body(body);
        assert_eq!(encoded, BASE64_STANDARD.encode(body));
        assert_eq!(encoding, Some("base64".to_string()));
        assert!(!truncated);
    }

    #[test]
    fn test_sanitize_path() {
        assert_eq!(sanitize_path("/v1/messages"), "v1_messages");
        assert_eq!(sanitize_path("/api?foo=bar&baz=1"), "api_foo_bar_baz_1");
        assert_eq!(sanitize_path(""), "");
    }

    #[test]
    fn test_parse_headers_to_map() {
        let headers =
            b"GET /path HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n";
        let map = parse_headers_to_map(headers);
        assert_eq!(map.get("host"), Some(&"example.com".to_string()));
        assert_eq!(
            map.get("content-type"),
            Some(&"application/json".to_string())
        );
        assert!(!map.contains_key("get")); // Request line should be skipped
    }
}
