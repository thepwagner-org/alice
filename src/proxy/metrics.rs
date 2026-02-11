//! Plain HTTP metrics server for observability.
//!
//! Serves:
//! - `/llm/completions` — LLM completion metrics as JSON
//! - `/metrics` — Prometheus text exposition format
//!
//! Runs on a separate port from the proxy, no TLS required.

use super::llm::LlmMetricsStore;
use super::prom::ProxyMetrics;
use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{debug, warn};

/// Spawn the metrics HTTP server on the given address.
///
/// Returns a `JoinHandle` for the server task.
pub async fn spawn(
    listen: &str,
    store: LlmMetricsStore,
    prom: ProxyMetrics,
) -> Result<tokio::task::JoinHandle<()>> {
    let listener = TcpListener::bind(listen).await?;
    let addr = listener.local_addr()?;
    debug!(addr = %addr, "metrics server listening");

    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _addr)) = listener.accept().await else {
                continue;
            };

            let store = store.clone();
            let prom = prom.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let n = match stream.read(&mut buf).await {
                    Ok(n) if n > 0 => n,
                    _ => return,
                };

                let request = String::from_utf8_lossy(&buf[..n]);

                // Parse the request line
                let first_line = request.lines().next().unwrap_or("");
                let path = first_line.split_whitespace().nth(1).unwrap_or("/");

                let (status, content_type, body) = match path {
                    "/llm/completions" => {
                        let metrics = store.lock().await;
                        let json = serde_json::to_string(&*metrics).unwrap_or("[]".to_string());
                        ("200 OK", "application/json", json)
                    }
                    "/metrics" => {
                        let body = prom.render();
                        ("200 OK", "text/plain; version=0.0.4; charset=utf-8", body)
                    }
                    _ => ("404 Not Found", "text/plain", "Not Found\n".to_string()),
                };

                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );

                if let Err(e) = stream.write_all(response.as_bytes()).await {
                    warn!(error = %e, "metrics server write error");
                }
            });
        }
    });

    Ok(handle)
}
