use super::CollectorState;
use crate::proxy::collector::allowlist;
use crate::proxy::collector::signal::OtlpSignal;
use anyhow::Result;
use opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest;
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, warn};

pub async fn spawn(
    listen: &str,
    state: Arc<CollectorState>,
) -> Result<(std::net::SocketAddr, tokio::task::JoinHandle<()>)> {
    let listener = TcpListener::bind(listen).await?;
    let addr = listener.local_addr()?;
    debug!(addr = %addr, "collector HTTP listener started");

    let handle = tokio::spawn(async move {
        loop {
            let Ok((stream, _peer)) = listener.accept().await else {
                continue;
            };
            let state = Arc::clone(&state);
            drop(tokio::spawn(handle_connection(stream, state)));
        }
    });

    Ok((addr, handle))
}

async fn handle_connection(mut stream: TcpStream, state: Arc<CollectorState>) {
    let Some((path, body)) = read_request(&mut stream).await else {
        return;
    };

    let status: u16 = match path.as_str() {
        "/v1/traces" => handle_export::<ExportTraceServiceRequest>(body, &state),
        "/v1/metrics" => handle_export::<ExportMetricsServiceRequest>(body, &state),
        _ => 404,
    };

    let response = match status {
        200 => "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string(),
        400 => {
            "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
        }
        _ => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string(),
    };

    if let Err(e) = stream.write_all(response.as_bytes()).await {
        debug!(error = %e, "collector: failed to write response");
    }
}

/// Decode, filter and forward one export request. Identical for every signal
/// type; `T` supplies the proto type, the metric label and the queue payload.
fn handle_export<T: OtlpSignal>(body: Vec<u8>, state: &CollectorState) -> u16 {
    match T::decode(body.as_slice()) {
        Ok(mut req) => {
            let fr = allowlist::filter(&mut req, &state.rules);
            state.forward_filtered(req, &fr, "otlp_http");
            200
        }
        Err(e) => {
            warn!(
                error = %e,
                signal = T::LABEL,
                "collector: failed to decode OTLP export request"
            );
            state
                .metrics
                .collector_received_total
                .with_label_values(&[T::LABEL, "decode_error"])
                .inc();
            400
        }
    }
}

/// Read an HTTP/1.1 request, returning (path, body) or None on error.
async fn read_request(stream: &mut TcpStream) -> Option<(String, Vec<u8>)> {
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];

    // Read until we find the end of headers (\r\n\r\n).
    loop {
        let n = stream.read(&mut tmp).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);

        if let Some(header_end) = find_header_end(&buf) {
            let headers_str = std::str::from_utf8(&buf[..header_end]).ok()?;
            let path = extract_path(headers_str)?.to_string();
            let content_length = extract_content_length(headers_str).unwrap_or(0);

            let body_start = header_end + 4;
            let mut body = buf[body_start..].to_vec();

            if body.len() < content_length {
                let remaining = content_length - body.len();
                let old_len = body.len();
                body.resize(old_len + remaining, 0);
                if stream.read_exact(&mut body[old_len..]).await.is_err() {
                    return None;
                }
            } else {
                body.truncate(content_length);
            }

            return Some((path, body));
        }

        if buf.len() > 65536 {
            return None;
        }
    }
}

fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4).position(|w| w == b"\r\n\r\n")
}

fn extract_path(headers: &str) -> Option<&str> {
    let first_line = headers.lines().next()?;
    let mut parts = first_line.splitn(3, ' ');
    let _method = parts.next()?;
    parts.next()
}

fn extract_content_length(headers: &str) -> Option<usize> {
    for line in headers.lines() {
        let lower = line.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("content-length:") {
            return rest.trim().parse().ok();
        }
    }
    None
}
