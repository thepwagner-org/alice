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
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, info_span, warn, Instrument};

/// Configuration for the reverse proxy listener.
#[derive(Debug, Clone)]
pub struct ReverseProxyConfig {
    /// Address to listen on (e.g., "127.0.0.1:0" for ephemeral port)
    pub listen: String,
    /// Backend address to forward to (e.g., "10.0.0.2:3337")
    pub backend: String,
    /// Splice idle timeout: tear the bidirectional copy down after this
    /// long with no data flowing in either direction. Mirrors the
    /// outbound proxy's default of 300s.
    pub idle_timeout: Duration,
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
    let idle_timeout = config.idle_timeout;

    let handle = tokio::spawn(async move {
        loop {
            let Ok((stream, addr)) = listener.accept().await else {
                continue;
            };

            let backend = backend.clone();
            let span = info_span!("reverse", %addr);
            drop(tokio::spawn(
                async move {
                    if let Err(e) = handle_connection(stream, &backend, idle_timeout).await {
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
            ));
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
async fn handle_connection(client: TcpStream, backend: &str, idle_timeout: Duration) -> Result<()> {
    let mut client = BufReader::new(client);

    // Read the first request line
    let mut request_line = String::new();
    let _ = client.read_line(&mut request_line).await?;
    if request_line.is_empty() {
        return Ok(());
    }

    // Read headers
    let mut headers = Vec::new();
    let mut is_upgrade = false;
    let mut content_length: Option<usize> = None;
    loop {
        let mut line = String::new();
        let _ = client.read_line(&mut line).await?;
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
        // Forward request body (Content-Length only — chunked request
        // bodies are unsupported), then splice both directions raw.
        // copy_bidirectional propagates half-close: when upstream FINs,
        // the downstream write half is shut down so the client sees EOF
        // promptly, regardless of HTTP body framing.
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

        // Drain anything left in the BufReader (e.g. pipelined bytes
        // beyond the request body) into upstream before switching to a
        // raw bidirectional copy on the underlying TcpStream.
        let leftover = client.buffer().to_vec();
        if !leftover.is_empty() {
            upstream.write_all(&leftover).await?;
            let n = leftover.len();
            client.consume(n);
        }

        let client_inner = client.into_inner();
        // TCP_NODELAY: don't let Nagle delay short streaming events
        // (NDJSON lines, SSE data: events) on either half of the splice.
        let _ = client_inner.set_nodelay(true);
        let _ = upstream.set_nodelay(true);

        match copy_bidirectional_idle(client_inner, upstream, idle_timeout).await {
            Ok(SpliceOutcome::Completed { c2u, u2c }) => {
                debug!(
                    client_to_upstream = c2u,
                    upstream_to_client = u2c,
                    "reverse proxy splice complete"
                );
            }
            Ok(SpliceOutcome::IdleTimeout) => {
                warn!(
                    backend = %backend,
                    idle_secs = idle_timeout.as_secs(),
                    "reverse proxy idle_timeout reached, terminating splice"
                );
            }
            Err(e) => {
                debug!(error = %e, "reverse proxy splice ended with error");
            }
        }
    }

    Ok(())
}

/// Outcome of an idle-bounded bidirectional splice.
enum SpliceOutcome {
    /// Both directions reached EOF; carries the byte counts.
    Completed { c2u: u64, u2c: u64 },
    /// No bytes flowed in either direction within the idle window, so the
    /// splice was torn down. Dropping the futures closes both sockets,
    /// propagating EOF/RST to each peer.
    IdleTimeout,
}

/// Copy one direction of the splice, mirroring `tokio::io::copy`'s
/// half-close behaviour: on read EOF, shut down the peer's write half so
/// it observes EOF promptly. Bumps `activity` on every chunk so the idle
/// watchdog can tell a stalled splice from a slow-but-progressing one.
async fn copy_half(
    mut reader: ReadHalf<TcpStream>,
    mut writer: WriteHalf<TcpStream>,
    activity: &AtomicU64,
) -> std::io::Result<u64> {
    let mut buf = vec![0u8; 8192];
    let mut total = 0u64;
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            writer.shutdown().await?;
            return Ok(total);
        }
        writer.write_all(&buf[..n]).await?;
        total += n as u64;
        let _ = activity.fetch_add(1, Ordering::Relaxed);
    }
}

/// Bidirectional copy with an idle deadline. Behaves like
/// `tokio::io::copy_bidirectional` (waits for both directions, propagates
/// half-close) but tears the connection down if no byte flows in either
/// direction within `idle_timeout`. The deadline resets on every chunk,
/// so healthy long-lived streams are never cut short.
async fn copy_bidirectional_idle(
    client: TcpStream,
    upstream: TcpStream,
    idle_timeout: Duration,
) -> std::io::Result<SpliceOutcome> {
    let activity = AtomicU64::new(0);
    let (client_read, client_write) = tokio::io::split(client);
    let (upstream_read, upstream_write) = tokio::io::split(upstream);

    let both = async {
        let (c2u, u2c) = tokio::join!(
            copy_half(client_read, upstream_write, &activity),
            copy_half(upstream_read, client_write, &activity),
        );
        Ok::<(u64, u64), std::io::Error>((c2u?, u2c?))
    };
    tokio::pin!(both);

    let mut last_seen = 0u64;
    loop {
        tokio::select! {
            res = &mut both => {
                let (c2u, u2c) = res?;
                return Ok(SpliceOutcome::Completed { c2u, u2c });
            }
            _ = tokio::time::sleep(idle_timeout) => {
                let seen = activity.load(Ordering::Relaxed);
                if seen == last_seen {
                    return Ok(SpliceOutcome::IdleTimeout);
                }
                last_seen = seen;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    /// Backend that accepts one connection, reads up to the request
    /// blank line, writes `body` after a `HTTP/1.1 200 OK\r\n\r\n`
    /// status (no Content-Length, no Transfer-Encoding — unbounded),
    /// then closes. Returns the bound address.
    async fn unbounded_backend(body: &'static [u8]) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            // Drain the request headers.
            let mut buf = [0u8; 4096];
            let mut total = Vec::new();
            loop {
                let n = stream.read(&mut buf).await.unwrap();
                if n == 0 {
                    return;
                }
                total.extend_from_slice(&buf[..n]);
                if total.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
            stream.write_all(body).await.unwrap();
            stream.flush().await.unwrap();
            // Drop the stream → FIN downstream of the reverse proxy.
        }));
        addr
    }

    /// Regression test for the FIN-propagation bug: when the upstream
    /// closes its end of an unbounded response, the downstream client
    /// must observe EOF promptly, not after the kernel's TCP retransmit
    /// timeout (~127s). Pre-fix, this test would hang for ~2 minutes;
    /// post-fix, it completes in milliseconds.
    #[tokio::test]
    async fn upstream_fin_propagates_to_downstream_eof() {
        let backend_addr = unbounded_backend(b"hello world").await;
        let (proxy_addr, _handle) = spawn(ReverseProxyConfig {
            listen: "127.0.0.1:0".to_string(),
            backend: backend_addr.to_string(),
            idle_timeout: Duration::from_secs(300),
        })
        .await
        .unwrap();

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();

        // Read until EOF, with a generous timeout that's still well
        // below the kernel's TCP retransmit timer.
        let mut response = Vec::new();
        let result =
            tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut response)).await;

        let bytes_read = result
            .expect("downstream EOF should arrive promptly")
            .unwrap();
        assert!(bytes_read > 0, "expected some response bytes, got 0");
        assert!(
            response.windows(11).any(|w| w == b"hello world"),
            "response body 'hello world' not found in {:?}",
            String::from_utf8_lossy(&response)
        );
    }

    /// Same fingerprint with an empty body: backend sends only headers
    /// then FINs. Downstream must still see EOF.
    #[tokio::test]
    async fn upstream_empty_body_then_fin_propagates() {
        let backend_addr = unbounded_backend(b"").await;
        let (proxy_addr, _handle) = spawn(ReverseProxyConfig {
            listen: "127.0.0.1:0".to_string(),
            backend: backend_addr.to_string(),
            idle_timeout: Duration::from_secs(300),
        })
        .await
        .unwrap();

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();

        let mut response = Vec::new();
        let result =
            tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut response)).await;

        let bytes_read = result
            .expect("downstream EOF should arrive promptly")
            .unwrap();
        assert!(
            response.starts_with(b"HTTP/1.1 200 OK"),
            "expected response status, got {} bytes: {:?}",
            bytes_read,
            String::from_utf8_lossy(&response)
        );
    }

    /// Backend that accepts one connection, drains the request headers,
    /// then goes silent and holds the socket open — never responding.
    /// Models the silent-wedge incident the idle timeout defends against.
    async fn silent_backend() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            // Read until the peer goes away (the proxy tearing the splice
            // down), holding the connection open in the meantime.
            let mut buf = [0u8; 4096];
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        }));
        addr
    }

    /// The idle-timeout backstop: when neither side sends a byte within
    /// the window, the splice is torn down, surfacing as a prompt EOF on
    /// the client read rather than hanging indefinitely.
    #[tokio::test]
    async fn idle_timeout_tears_down_splice() {
        let backend_addr = silent_backend().await;
        let (proxy_addr, _handle) = spawn(ReverseProxyConfig {
            listen: "127.0.0.1:0".to_string(),
            backend: backend_addr.to_string(),
            idle_timeout: Duration::from_millis(300),
        })
        .await
        .unwrap();

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();

        // No data flows in either direction. The splice must be torn down
        // after the idle window — well within this timeout.
        let mut response = Vec::new();
        let result =
            tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut response)).await;

        let bytes_read = result
            .expect("idle timeout should tear down the splice promptly")
            .unwrap();
        assert_eq!(
            bytes_read,
            0,
            "expected no data before idle teardown, got {:?}",
            String::from_utf8_lossy(&response)
        );
    }
}
