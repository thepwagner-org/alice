//! Inbound reverse proxy for forwarding host requests into a sandboxed job.
//!
//! Alice already sits in the host namespace with a veth pair into the job's
//! network namespace. This module adds a second listener that accepts plain
//! HTTP requests from the host and forwards them to a backend service running
//! inside the sandbox (e.g., opencode at 10.0.0.2:PORT).
//!
//! Traffic flow:
//! ```text
//! nj-web → alice reverse proxy (127.0.0.1:NNNNN) → backend (10.0.0.2:PORT via veth)
//! ```
//!
//! Supports HTTP/1.1 request proxying and WebSocket upgrade passthrough.
//! Uses raw TCP forwarding for WebSocket to avoid hyper upgrade complexity.

use anyhow::Result;
use std::net::SocketAddr;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, info_span, Instrument};

/// Configuration for the reverse proxy listener.
#[derive(Debug, Clone)]
pub struct ReverseProxyConfig {
    /// Address to listen on (e.g., "127.0.0.1:0" for ephemeral port)
    pub listen: String,
    /// Backend address to forward to (e.g., "10.0.0.2:3337")
    pub backend: String,
}

/// Spawn the reverse proxy server.
///
/// Returns the bound address (useful when listen port is 0) and a JoinHandle.
pub async fn spawn(
    config: ReverseProxyConfig,
) -> Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let listener = TcpListener::bind(&config.listen).await?;
    let bound_addr = listener.local_addr()?;

    info!(
        listen = %bound_addr,
        backend = %config.backend,
        "reverse proxy listening"
    );

    let backend = config.backend.clone();

    let handle = tokio::spawn(async move {
        loop {
            let Ok((stream, addr)) = listener.accept().await else {
                continue;
            };

            let backend = backend.clone();
            let span = info_span!("reverse", %addr);
            tokio::spawn(
                async move {
                    if let Err(e) = handle_connection(stream, &backend).await {
                        let msg = e.to_string();
                        if msg.contains("Connection reset")
                            || msg.contains("broken pipe")
                            || msg.contains("connection was not properly closed")
                        {
                            debug!(error = %e, "reverse proxy client disconnected");
                        } else {
                            error!(error = %e, "reverse proxy connection error");
                        }
                    }
                }
                .instrument(span),
            );
        }
    });

    Ok((bound_addr, handle))
}

/// Handle a single inbound connection.
///
/// Reads the HTTP request line and headers, forwards them to the backend,
/// then either:
/// - For WebSocket upgrades: splices the two TCP streams bidirectionally
/// - For normal requests: forwards request body, then response, then loops
///   for keep-alive
async fn handle_connection(client: TcpStream, backend: &str) -> Result<()> {
    let mut client = BufReader::new(client);

    // Read the first request line
    let mut request_line = String::new();
    client.read_line(&mut request_line).await?;
    if request_line.is_empty() {
        return Ok(());
    }

    // Read headers
    let mut headers = Vec::new();
    let mut is_upgrade = false;
    let mut content_length: Option<usize> = None;
    loop {
        let mut line = String::new();
        client.read_line(&mut line).await?;
        if line == "\r\n" || line == "\n" {
            break;
        }
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("upgrade:") && lower.contains("websocket") {
            is_upgrade = true;
        }
        if lower.starts_with("content-length:") {
            content_length = lower.split(':').nth(1).and_then(|v| v.trim().parse().ok());
        }
        headers.push(line);
    }

    // Connect to backend
    let mut upstream = TcpStream::connect(backend).await?;

    // Forward request line + headers to backend
    upstream.write_all(request_line.as_bytes()).await?;
    for header in &headers {
        upstream.write_all(header.as_bytes()).await?;
    }
    upstream.write_all(b"\r\n").await?;

    if is_upgrade {
        // WebSocket upgrade: forward any remaining buffered data, then splice
        let buffered = client.buffer().to_vec();
        if !buffered.is_empty() {
            upstream.write_all(&buffered).await?;
        }
        let mut client = client.into_inner();

        // Read backend response (the 101 Switching Protocols)
        let mut response_buf = Vec::with_capacity(4096);
        loop {
            let mut byte = [0u8; 1];
            let n = upstream.read(&mut byte).await?;
            if n == 0 {
                anyhow::bail!("backend closed during websocket upgrade");
            }
            response_buf.push(byte[0]);
            if response_buf.ends_with(b"\r\n\r\n") {
                break;
            }
            if response_buf.len() > 8192 {
                anyhow::bail!("backend upgrade response headers too large");
            }
        }

        // Forward 101 response to client
        client.write_all(&response_buf).await?;
        client.flush().await?;

        debug!("websocket upgrade complete, splicing streams");

        // Bidirectional splice
        let (mut client_read, mut client_write) = tokio::io::split(client);
        let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream);

        tokio::select! {
            r = tokio::io::copy(&mut client_read, &mut upstream_write) => {
                if let Err(e) = r {
                    debug!(error = %e, "websocket client->backend copy ended");
                }
            }
            r = tokio::io::copy(&mut upstream_read, &mut client_write) => {
                if let Err(e) = r {
                    debug!(error = %e, "websocket backend->client copy ended");
                }
            }
        }

        debug!("websocket connection closed");
    } else {
        // Regular HTTP: forward request body, then forward response
        // Forward request body if present
        if let Some(len) = content_length {
            let mut remaining = len;
            let buffered = client.buffer().to_vec();
            let from_buffer = buffered.len().min(remaining);
            if from_buffer > 0 {
                upstream.write_all(&buffered[..from_buffer]).await?;
                remaining -= from_buffer;
                client.consume(from_buffer);
            }
            if remaining > 0 {
                let mut buf = vec![0u8; 8192];
                while remaining > 0 {
                    let to_read = buf.len().min(remaining);
                    let n = client.read(&mut buf[..to_read]).await?;
                    if n == 0 {
                        break;
                    }
                    upstream.write_all(&buf[..n]).await?;
                    remaining -= n;
                }
            }
        }

        // Read and forward backend response
        let mut upstream_reader = BufReader::new(upstream);

        // Response line
        let mut response_line = String::new();
        upstream_reader.read_line(&mut response_line).await?;
        client.get_mut().write_all(response_line.as_bytes()).await?;

        // Response headers
        let mut resp_content_length: Option<usize> = None;
        let mut is_chunked = false;
        loop {
            let mut line = String::new();
            upstream_reader.read_line(&mut line).await?;
            let lower = line.to_ascii_lowercase();
            if lower.starts_with("content-length:") {
                resp_content_length = lower.split(':').nth(1).and_then(|v| v.trim().parse().ok());
            }
            if lower.starts_with("transfer-encoding:") && lower.contains("chunked") {
                is_chunked = true;
            }
            client.get_mut().write_all(line.as_bytes()).await?;
            if line == "\r\n" || line == "\n" {
                break;
            }
        }

        // Response body
        if let Some(len) = resp_content_length {
            let mut remaining = len;
            let mut buf = vec![0u8; 8192];
            while remaining > 0 {
                let to_read = buf.len().min(remaining);
                let n = upstream_reader.read(&mut buf[..to_read]).await?;
                if n == 0 {
                    break;
                }
                client.get_mut().write_all(&buf[..n]).await?;
                remaining -= n;
            }
        } else if is_chunked {
            // Forward chunked encoding until 0\r\n\r\n
            loop {
                // Read chunk size line
                let mut size_line = String::new();
                upstream_reader.read_line(&mut size_line).await?;
                client.get_mut().write_all(size_line.as_bytes()).await?;

                let size = usize::from_str_radix(size_line.trim(), 16).unwrap_or(0);
                if size == 0 {
                    // Terminal chunk — read trailing \r\n
                    let mut trailer = String::new();
                    upstream_reader.read_line(&mut trailer).await?;
                    client.get_mut().write_all(trailer.as_bytes()).await?;
                    break;
                }

                // Forward chunk data + trailing \r\n
                let mut remaining = size + 2; // +2 for \r\n after chunk data
                let mut buf = vec![0u8; 8192];
                while remaining > 0 {
                    let to_read = buf.len().min(remaining);
                    let n = upstream_reader.read(&mut buf[..to_read]).await?;
                    if n == 0 {
                        break;
                    }
                    client.get_mut().write_all(&buf[..n]).await?;
                    remaining -= n;
                }
            }
        } else {
            // No Content-Length and not chunked: stream until the backend closes.
            // This handles SSE (text/event-stream) and other unbounded responses.
            // Flush after each read so events reach the client immediately.
            let mut buf = vec![0u8; 8192];
            loop {
                let n = upstream_reader.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                client.get_mut().write_all(&buf[..n]).await?;
                client.get_mut().flush().await?;
            }
        }

        client.get_mut().flush().await?;
    }

    Ok(())
}
