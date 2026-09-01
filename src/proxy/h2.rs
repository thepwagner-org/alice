//! HTTP/2 proxy handler with request inspection for path-based policy.

use crate::config::Action;
use crate::proxy::request::{self, RequestOutcome};
use crate::proxy::ProxyState;
use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use h2::server::SendResponse;
use h2::RecvStream;
use http::{HeaderMap, Request};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;
use tracing::{debug, info, info_span, Instrument, Span};

/// Proxy HTTP/2 traffic between client and upstream with policy enforcement.
///
/// Both client and upstream connections have already completed TLS handshake
/// with HTTP/2 negotiated via ALPN.
pub async fn proxy_h2<C, U>(
    client_tls: C,
    upstream_tls: U,
    host: String,
    state: Arc<ProxyState>,
    resolved_ips: Option<Arc<Vec<IpAddr>>>,
    client_addr: String,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Use large flow control windows for proxy workloads. The HTTP/2 spec
    // default (65535 bytes) is shared across ALL concurrent streams on a
    // connection. Cargo can open 100+ simultaneous index fetches on a single
    // H2 connection — with real network RTT, the bandwidth-delay product
    // quickly exceeds a small connection window and streams stall waiting
    // for WINDOW_UPDATE frames, triggering curl's "less than 10 bytes/sec"
    // timeout. 16 MiB gives ~160 KB per stream at 100 concurrent streams,
    // enough to sustain transfer even with 50-100ms RTT to CDN edges.
    const CONNECTION_WINDOW: u32 = 16 * 1024 * 1024; // 16 MiB
    const STREAM_WINDOW: u32 = 2 * 1024 * 1024; // 2 MiB

    // Perform HTTP/2 handshakes with tuned windows.
    // Cap max_concurrent_streams on the server side so we don't accept more
    // streams from the client than a typical CDN upstream will serve at once.
    let mut client_conn = h2::server::Builder::new()
        .initial_window_size(STREAM_WINDOW)
        .initial_connection_window_size(CONNECTION_WINDOW)
        .max_concurrent_streams(200)
        .handshake(client_tls)
        .await
        .context("HTTP/2 server handshake failed")?;

    let (upstream_send, upstream_conn) = h2::client::Builder::new()
        .initial_window_size(STREAM_WINDOW)
        .initial_connection_window_size(CONNECTION_WINDOW)
        .handshake(upstream_tls)
        .await
        .context("HTTP/2 client handshake failed")?;

    // Spawn task to drive the upstream connection
    let upstream_handle = tokio::spawn(async move {
        if let Err(e) = upstream_conn.await {
            debug!(error = %e, "upstream HTTP/2 connection ended");
        }
    });

    // Track spawned stream handlers so we can wait for them to finish
    let mut stream_tasks = tokio::task::JoinSet::new();

    // Process incoming streams from client
    while let Some(result) = client_conn.accept().await {
        let (request, respond) = result.context("failed to accept client stream")?;

        let host = host.clone();
        let state = Arc::clone(&state);
        let upstream_send = upstream_send.clone();
        let resolved_ips = resolved_ips.clone();
        let client_addr = client_addr.clone();

        let _ = stream_tasks.spawn(
            async move {
                if let Err(e) = handle_stream(
                    request,
                    respond,
                    upstream_send,
                    host,
                    state,
                    resolved_ips,
                    client_addr,
                )
                .await
                {
                    debug!(error = %e, "stream handling error");
                }
            }
            .instrument(Span::current()),
        );
    }

    // Client stopped sending new streams. Wait for in-flight handlers to
    // finish (they may still be forwarding response data) before tearing
    // down the upstream connection that they depend on.
    drop(upstream_send); // release our clone so upstream closes when tasks finish
    while stream_tasks.join_next().await.is_some() {}
    upstream_handle.abort();
    Ok(())
}

/// Proxy HTTP/2 client to HTTP/1.1 upstream with protocol translation.
///
/// Client speaks HTTP/2 but upstream only supports HTTP/1.1.
/// We accept H2 streams from client, convert to H1.1 requests, and translate responses back.
pub async fn proxy_h2_to_h1<C, U>(
    client_tls: C,
    upstream_tls: U,
    host: String,
    state: Arc<ProxyState>,
    resolved_ips: Option<Arc<Vec<IpAddr>>>,
    client_addr: String,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Use larger flow control windows (see proxy_h2 for rationale)
    const STREAM_WINDOW: u32 = 2 * 1024 * 1024;
    const CONNECTION_WINDOW: u32 = 16 * 1024 * 1024;

    // Perform HTTP/2 handshake with client
    let mut client_conn = h2::server::Builder::new()
        .initial_window_size(STREAM_WINDOW)
        .initial_connection_window_size(CONNECTION_WINDOW)
        .max_concurrent_streams(200)
        .handshake(client_tls)
        .await
        .context("HTTP/2 server handshake failed")?;

    // Wrap upstream in mutex for serialized H1.1 access (H1.1 doesn't multiplex)
    let upstream = Arc::new(Mutex::new(upstream_tls));

    // Process incoming streams from client
    while let Some(result) = client_conn.accept().await {
        let (request, respond) = result.context("failed to accept client stream")?;

        let host = host.clone();
        let state = Arc::clone(&state);
        let upstream = Arc::clone(&upstream);
        let resolved_ips = resolved_ips.clone();
        let client_addr = client_addr.clone();

        drop(tokio::spawn(
            async move {
                if let Err(e) = handle_stream_to_h1(
                    request,
                    respond,
                    upstream,
                    host,
                    state,
                    resolved_ips,
                    client_addr,
                )
                .await
                {
                    debug!(error = %e, "stream handling error (h2->h1)");
                }
            }
            .instrument(Span::current()),
        ));
    }

    Ok(())
}

/// Handle a single HTTP/2 stream, translating to HTTP/1.1 for upstream.
async fn handle_stream_to_h1<U>(
    request: Request<RecvStream>,
    mut respond: SendResponse<Bytes>,
    upstream: Arc<Mutex<U>>,
    host: String,
    state: Arc<ProxyState>,
    resolved_ips: Option<Arc<Vec<IpAddr>>>,
    client_addr: String,
) -> Result<()>
where
    U: AsyncRead + AsyncWrite + Unpin,
{
    let request_start = Instant::now();

    // Extract request info
    let path = request
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/")
        .to_string();
    let method = request.method().clone();

    // Create request span with HTTP semantic conventions
    let request_span = info_span!(
        "request",
        http.request.method = %method,
        url.full = %format!("https://{}{}", host, path),
        server.address = %host,
        network.protocol.name = "h2-to-h1",
        http.response.status_code = tracing::field::Empty,
        alice.policy.action = tracing::field::Empty,
        alice.policy.rule_index = tracing::field::Empty,
        alice.duration_ms = tracing::field::Empty,
    );
    let _request_guard = request_span.enter();

    // Evaluate policy (with resolved IPs for CIDR rules if available)
    let decision =
        state
            .policy
            .evaluate(&host, &path, resolved_ips.as_deref().map(|v| v.as_slice()));

    if decision.action == Action::Deny {
        let deny = RequestOutcome {
            host: &host,
            method: method.as_str(),
            path: &path,
            status_code: 403,
            action: "deny",
            rule_index: decision.rule_index,
            request_bytes: 0,
            response_bytes: 0,
            start: request_start,
            client_addr: &client_addr,
            request_headers: &[],
            request_body: &[],
            response_headers: &[],
            response_body: &[],
        };
        deny.record_deny(&request_span, &state.metrics, "h2->h1");
        let mut deny_response = http::Response::new(());
        *deny_response.status_mut() = http::StatusCode::FORBIDDEN;
        let _ = respond.send_response(deny_response, true);
        return Ok(());
    }

    let _ = request_span.record("alice.policy.action", "allow");
    let _ = request_span.record("alice.policy.rule_index", decision.rule_index as i64);
    info!(
        host = %host,
        path = %path,
        method = %method,
        rule = decision.rule_index,
        "allowed (h2->h1)"
    );

    let (mut parts, mut body) = request.into_parts();

    // Capture request headers for logging (before credential injection)
    let request_headers_raw = format_h2_headers_for_log(&parts.headers);

    // Inject credentials if needed
    inject_credentials_h2(&mut parts.headers, &host, &state);

    // Collect request body (for simplicity, buffer it)
    let mut body_bytes = Vec::new();
    while let Some(chunk) = body.data().await {
        let data = chunk.context("error reading client body")?;
        body.flow_control()
            .release_capacity(data.len())
            .context("failed to release client flow control")?;
        body_bytes.extend_from_slice(&data);
    }

    // GCP JWT re-signing: intercept token exchange POST bodies
    if state.gcp_credentials.is_gcp_token_request(&host, &path) {
        if let Some(new_body) = state.gcp_credentials.resign_token_request(&body_bytes) {
            body_bytes = new_body;
        }
    }

    // Build HTTP/1.1 request
    let mut request_text = format!("{} {} HTTP/1.1\r\n", parts.method, &path);
    request_text.push_str(&format!("Host: {}\r\n", host));

    // Build the connection-token denylist. These headers are forbidden in
    // HTTP/2, but we filter defensively so a malformed h2 peer can't smuggle
    // framing directives across the h2->h1 downgrade.
    let connection_tokens: Vec<String> = parts
        .headers
        .get_all("connection")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(',').map(|t| t.trim().to_ascii_lowercase()))
        .filter(|t| !t.is_empty())
        .collect();

    // Copy headers, skipping pseudo-headers (which start with ':') and
    // hop-by-hop / framing headers. alice owns framing on the h1 side, so
    // Connection, Transfer-Encoding, Keep-Alive, Proxy-*, anything named in
    // Connection, and Content-Length are all dropped here.
    for (name, value) in parts.headers.iter() {
        let name_str = name.as_str();
        if name_str.starts_with(':') {
            continue;
        }
        let lower = name_str.to_ascii_lowercase();
        if lower == "content-length"
            || crate::proxy::http::is_hop_by_hop(&lower)
            || connection_tokens.contains(&lower)
        {
            continue;
        }
        request_text.push_str(&format!(
            "{}: {}\r\n",
            name_str,
            value.to_str().unwrap_or("")
        ));
    }

    // alice is authoritative on length: emit a single Content-Length matching
    // the body we actually forward.
    if !body_bytes.is_empty() {
        request_text.push_str(&format!("Content-Length: {}\r\n", body_bytes.len()));
    }

    request_text.push_str("\r\n");

    // Acquire exclusive access to upstream (H1.1 is not multiplexed)
    let mut upstream_guard = upstream.lock().await;

    // Send request
    upstream_guard
        .write_all(request_text.as_bytes())
        .await
        .context("failed to write H1.1 request")?;
    if !body_bytes.is_empty() {
        upstream_guard
            .write_all(&body_bytes)
            .await
            .context("failed to write H1.1 body")?;
    }
    upstream_guard.flush().await?;

    // Read HTTP/1.1 response
    let mut reader = BufReader::new(&mut *upstream_guard);

    // Read status line
    let mut status_line = String::new();
    let _ = reader
        .read_line(&mut status_line)
        .await
        .context("failed to read H1.1 status line")?;

    let status_parts: Vec<&str> = status_line.splitn(3, ' ').collect();
    if status_parts.len() < 2 {
        return Err(anyhow!("invalid H1.1 status line: {}", status_line));
    }
    let status_code: u16 = status_parts[1].parse().context("invalid status code")?;

    // Read headers
    let mut response_headers = Vec::new();
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    let mut server_wants_close = false;

    loop {
        let mut line = String::new();
        let _ = reader.read_line(&mut line).await?;
        if line == "\r\n" || line == "\n" {
            break;
        }
        let line = line.trim_end();
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().to_lowercase();
            let value = value.trim();
            if name == "content-length" {
                content_length = value.parse().ok();
            } else if name == "transfer-encoding" && value.to_lowercase().contains("chunked") {
                chunked = true;
            } else if name == "connection" && value.to_lowercase().contains("close") {
                server_wants_close = true;
            }
            response_headers.push((name, value.to_string()));
        }
    }

    // Format response headers for logging (independent of the body).
    let response_headers_raw = {
        let mut buf = Vec::new();
        for (name, value) in &response_headers {
            buf.extend_from_slice(name.as_bytes());
            buf.extend_from_slice(b": ");
            buf.extend_from_slice(value.as_bytes());
            buf.extend_from_slice(b"\r\n");
        }
        buf.extend_from_slice(b"\r\n");
        buf
    };

    // A 1xx/204/304 response carries no body regardless of framing headers; we
    // must not try to read one (it would block until the connection closes).
    let status_has_body =
        !(status_code == 204 || status_code == 304 || (100..200).contains(&status_code));

    // Decide how the body is framed on the h1 side.
    let framing = if chunked {
        H1Framing::Chunked
    } else if let Some(len) = content_length {
        H1Framing::Length(len as u64)
    } else if server_wants_close && status_has_body {
        // No Content-Length and not chunked: body runs until the upstream
        // closes the connection (RFC 7230 §3.3.3). Previously this case
        // dropped the body entirely.
        H1Framing::UntilClose
    } else {
        H1Framing::Length(0)
    };

    let (response_body, response_body_len) = if decision.redact_tokens {
        // Token redaction needs the whole JSON body, so buffer it.
        let response_body =
            read_h1_body_buffered(&mut reader, framing, state.limits.max_body_bytes).await?;

        // Release upstream lock before the (CPU-bound) redaction + send.
        drop(reader);
        drop(upstream_guard);

        let response_body = if let Some(redacted_body) = state
            .credentials
            .redact_oauth_response(&host, &response_body)
        {
            redacted_body
        } else {
            response_body
        };

        let h2_response =
            build_h2_response(status_code, &response_headers, Some(response_body.len()))?;

        let end_stream = response_body.is_empty();
        let mut send_body = respond
            .send_response(h2_response, end_stream)
            .context("failed to send H2 response")?;
        if !end_stream {
            send_body
                .send_data(Bytes::from(response_body.clone()), true)
                .context("failed to send H2 response body")?;
        }

        let len = response_body.len();
        (response_body, len)
    } else {
        // Stream the body through to the client as it arrives, so SSE events
        // (and any other streamed/chunked response) are forwarded incrementally
        // instead of being buffered until the upstream finishes.
        let h2_response = build_h2_response(status_code, &response_headers, None)?;

        let no_body = matches!(framing, H1Framing::Length(0));
        let mut send_body = respond
            .send_response(h2_response, no_body)
            .context("failed to send H2 response")?;

        if no_body {
            drop(reader);
            drop(upstream_guard);
            (Vec::new(), 0)
        } else {
            // Capture the full body only when logging; otherwise keep just a
            // small leading excerpt for non-2xx errors (for the journal).
            let capture_cap = if state.log_dir.is_some() {
                state.limits.max_body_bytes as usize
            } else if (400..600).contains(&status_code) {
                request::NON_2XX_EXCERPT_CAP
            } else {
                0
            };

            let (captured, total) = stream_h1_body_to_h2(
                &mut reader,
                &mut send_body,
                framing,
                state.limits.max_body_bytes,
                capture_cap,
            )
            .await?;

            drop(reader);
            drop(upstream_guard);

            send_body
                .send_data(Bytes::new(), true)
                .context("failed to end client body")?;

            (captured, total)
        }
    };

    // Record span, metrics, and log the exchange
    let outcome = RequestOutcome {
        host: &host,
        method: method.as_str(),
        path: &path,
        status_code,
        action: "allow",
        rule_index: decision.rule_index,
        request_bytes: request_text.len() + body_bytes.len(),
        response_bytes: response_headers_raw.len() + response_body_len,
        start: request_start,
        client_addr: &client_addr,
        request_headers: &request_headers_raw,
        request_body: &body_bytes,
        response_headers: &response_headers_raw,
        response_body: &response_body,
    };
    outcome.record_span(&request_span);
    outcome.record_metrics(&state.metrics);
    outcome.record_summary();
    outcome.log_exchange(&state.log_dir).await;

    Ok(())
}

/// How an HTTP/1.1 response body is framed on the wire.
#[derive(Debug, Clone, Copy)]
enum H1Framing {
    /// `Transfer-Encoding: chunked`.
    Chunked,
    /// Fixed-length body (`Content-Length`); 0 means no body.
    Length(u64),
    /// Neither Content-Length nor chunked: body runs until the connection
    /// closes (RFC 7230 §3.3.3).
    UntilClose,
}

/// Build the HTTP/2 response (status + headers) to send to the client from the
/// parsed HTTP/1.1 response headers. Hop-by-hop headers (including
/// `Transfer-Encoding`, which has no meaning in h2) are stripped. When
/// `content_length_override` is `Some`, an existing `Content-Length` header is
/// rewritten to that value (used after token redaction changes the body size).
fn build_h2_response(
    status_code: u16,
    response_headers: &[(String, String)],
    content_length_override: Option<usize>,
) -> Result<http::Response<()>> {
    let mut builder = http::Response::builder().status(status_code);
    for (name, value) in response_headers {
        if matches!(
            name.as_str(),
            "connection" | "keep-alive" | "transfer-encoding" | "upgrade"
        ) {
            continue;
        }
        if name == "content-length" {
            if let Some(len) = content_length_override {
                builder = builder.header("content-length", len.to_string());
                continue;
            }
        }
        builder = builder.header(name.as_str(), value.as_str());
    }
    builder.body(()).context("failed to build H2 response")
}

/// Read an entire HTTP/1.1 response body into memory according to `framing`,
/// bounded by `max_bytes`. Used for the buffering paths (token redaction).
async fn read_h1_body_buffered<R: AsyncBufReadExt + Unpin>(
    reader: &mut R,
    framing: H1Framing,
    max_bytes: u64,
) -> Result<Vec<u8>> {
    match framing {
        H1Framing::Length(0) => Ok(Vec::new()),
        H1Framing::Chunked => read_chunked_body(reader, max_bytes).await,
        H1Framing::Length(len) => {
            // Reject a forged Content-Length before allocating the claimed size.
            if len > max_bytes {
                return Err(anyhow!(
                    "response body length {} exceeds maximum of {} bytes",
                    len,
                    max_bytes
                ));
            }
            let mut buf = vec![0u8; len as usize];
            let _ = reader.read_exact(&mut buf).await?;
            Ok(buf)
        }
        H1Framing::UntilClose => {
            let mut buf = Vec::new();
            let mut tmp = vec![0u8; 65536];
            loop {
                let n = reader.read(&mut tmp).await?;
                if n == 0 {
                    break;
                }
                if buf.len() as u64 + n as u64 > max_bytes {
                    return Err(anyhow!(
                        "response body exceeds maximum of {} bytes",
                        max_bytes
                    ));
                }
                buf.extend_from_slice(&tmp[..n]);
            }
            Ok(buf)
        }
    }
}

/// Stream an HTTP/1.1 response body into an HTTP/2 send stream, forwarding each
/// piece as it is read so streamed responses (SSE) reach the client
/// incrementally. Returns `(captured, total_bytes)`, where `captured` holds at
/// most `capture_cap` leading bytes for logging (the full body is forwarded
/// regardless). The terminal empty/end-stream frame is sent by the caller.
async fn stream_h1_body_to_h2<R: AsyncBufReadExt + Unpin>(
    reader: &mut R,
    send_body: &mut h2::SendStream<Bytes>,
    framing: H1Framing,
    max_bytes: u64,
    capture_cap: usize,
) -> Result<(Vec<u8>, usize)> {
    let mut captured = Vec::new();
    let mut total: usize = 0;

    // Forward one slice to the client and retain a capped prefix for logging.
    // A local `fn` (not a closure) so it doesn't borrow `captured` for the whole
    // function — that would block returning it at the end.
    fn emit(
        data: &[u8],
        captured: &mut Vec<u8>,
        capture_cap: usize,
        send_body: &mut h2::SendStream<Bytes>,
    ) -> Result<()> {
        if captured.len() < capture_cap {
            let take = (capture_cap - captured.len()).min(data.len());
            captured.extend_from_slice(&data[..take]);
        }
        send_body
            .send_data(Bytes::copy_from_slice(data), false)
            .context("failed to send body chunk to client")
    }

    match framing {
        H1Framing::Length(0) => {}
        H1Framing::Length(len) => {
            let mut remaining = len;
            let mut buf = vec![0u8; 65536];
            while remaining > 0 {
                let to_read = std::cmp::min(remaining as usize, buf.len());
                let n = reader.read(&mut buf[..to_read]).await?;
                if n == 0 {
                    return Err(anyhow!("unexpected EOF reading body"));
                }
                total += n;
                emit(&buf[..n], &mut captured, capture_cap, send_body)?;
                remaining -= n as u64;
            }
        }
        H1Framing::UntilClose => {
            let mut buf = vec![0u8; 65536];
            loop {
                let n = reader.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                total += n;
                emit(&buf[..n], &mut captured, capture_cap, send_body)?;
            }
        }
        H1Framing::Chunked => loop {
            let mut size_line = String::new();
            let _ = reader.read_line(&mut size_line).await?;
            let size_str = size_line.trim();
            let size_hex = size_str.split(';').next().unwrap_or(size_str);
            let chunk_size = usize::from_str_radix(size_hex, 16).context("invalid chunk size")?;

            if chunk_size == 0 {
                // Terminal chunk: consume trailing CRLF / trailers.
                loop {
                    let mut trailer = String::new();
                    let _ = reader.read_line(&mut trailer).await?;
                    if trailer == "\r\n" || trailer == "\n" {
                        break;
                    }
                }
                break;
            }

            // Bound a single chunk's claimed size so a forged header can't drive
            // a huge per-chunk read buffer.
            if chunk_size as u64 > max_bytes {
                return Err(anyhow!(
                    "chunk size {} exceeds maximum of {} bytes",
                    chunk_size,
                    max_bytes
                ));
            }

            let mut remaining = chunk_size;
            let mut buf = vec![0u8; 65536];
            while remaining > 0 {
                let to_read = std::cmp::min(remaining, buf.len());
                let n = reader.read(&mut buf[..to_read]).await?;
                if n == 0 {
                    return Err(anyhow!("unexpected EOF in chunk"));
                }
                total += n;
                emit(&buf[..n], &mut captured, capture_cap, send_body)?;
                remaining -= n;
            }

            let mut crlf = [0u8; 2];
            let _ = reader.read_exact(&mut crlf).await?;
        },
    }

    Ok((captured, total))
}

/// Read a chunked HTTP/1.1 body, bounding total accumulation at `max_bytes`
/// so a forged chunk size can't drive an unbounded allocation.
async fn read_chunked_body<R: AsyncBufReadExt + Unpin>(
    reader: &mut R,
    max_bytes: u64,
) -> Result<Vec<u8>> {
    let mut body = Vec::new();

    loop {
        let mut size_line = String::new();
        let _ = reader.read_line(&mut size_line).await?;
        let size_str = size_line.trim();
        // A chunk-size line may carry chunk extensions after a ';' (RFC 7230
        // §4.1.1); strip them before parsing the hex size rather than letting
        // them corrupt the parse.
        let size_hex = size_str.split(';').next().unwrap_or(size_str);
        let chunk_size = usize::from_str_radix(size_hex, 16).context("invalid chunk size")?;

        if body.len() as u64 + chunk_size as u64 > max_bytes {
            return Err(anyhow!(
                "chunked body exceeds maximum of {} bytes",
                max_bytes
            ));
        }

        if chunk_size == 0 {
            // Read trailing CRLF
            let mut trailing = String::new();
            let _ = reader.read_line(&mut trailing).await?;
            break;
        }

        let mut chunk = vec![0u8; chunk_size];
        let _ = reader.read_exact(&mut chunk).await?;
        body.extend_from_slice(&chunk);

        // Read chunk-ending CRLF
        let mut crlf = [0u8; 2];
        let _ = reader.read_exact(&mut crlf).await?;
    }

    Ok(body)
}

/// Handle a single HTTP/2 stream: extract path, evaluate policy, proxy or reject.
async fn handle_stream(
    request: Request<RecvStream>,
    mut respond: SendResponse<Bytes>,
    upstream_send: h2::client::SendRequest<Bytes>,
    host: String,
    state: Arc<ProxyState>,
    resolved_ips: Option<Arc<Vec<IpAddr>>>,
    client_addr: String,
) -> Result<()> {
    let request_start = Instant::now();

    // Extract path (including query string) from request URI
    let path = request
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/")
        .to_string();
    let method = request.method().clone();

    // Create request span with HTTP semantic conventions
    let request_span = info_span!(
        "request",
        http.request.method = %method,
        url.full = %format!("https://{}{}", host, path),
        server.address = %host,
        network.protocol.name = "h2",
        http.response.status_code = tracing::field::Empty,
        alice.policy.action = tracing::field::Empty,
        alice.policy.rule_index = tracing::field::Empty,
        alice.duration_ms = tracing::field::Empty,
    );
    let _request_guard = request_span.enter();

    // Evaluate policy (with resolved IPs for CIDR rules if available)
    let decision =
        state
            .policy
            .evaluate(&host, &path, resolved_ips.as_deref().map(|v| v.as_slice()));

    if decision.action == Action::Deny {
        let deny = RequestOutcome {
            host: &host,
            method: method.as_str(),
            path: &path,
            status_code: 403,
            action: "deny",
            rule_index: decision.rule_index,
            request_bytes: 0,
            response_bytes: 0,
            start: request_start,
            client_addr: &client_addr,
            request_headers: &[],
            request_body: &[],
            response_headers: &[],
            response_body: &[],
        };
        deny.record_deny(&request_span, &state.metrics, "h2");
        let mut deny_response = http::Response::new(());
        *deny_response.status_mut() = http::StatusCode::FORBIDDEN;
        let _ = respond.send_response(deny_response, true);
        return Ok(());
    }

    let _ = request_span.record("alice.policy.action", "allow");
    let _ = request_span.record("alice.policy.rule_index", decision.rule_index as i64);
    info!(
        host = %host,
        path = %path,
        method = %method,
        rule = decision.rule_index,
        "allowed (h2)"
    );

    // Split request into parts
    let (mut parts, mut body) = request.into_parts();

    // Capture request headers for logging (before credential injection)
    let request_headers_raw = format_h2_headers_for_log(&parts.headers);

    // Inject credentials if needed
    inject_credentials_h2(&mut parts.headers, &host, &state);

    // Buffer the request body only when GCP token re-signing needs to rewrite
    // it; otherwise stream it straight through.
    let needs_gcp_resign = state.gcp_credentials.is_gcp_token_request(&host, &path);

    // Only capture body bytes into memory when logging is enabled
    let needs_body_capture = state.log_dir.is_some();

    // Build the request to send upstream (without body)
    let upstream_request = http::Request::from_parts(parts, ());

    let body_is_end = body.is_end_stream();

    // Ready the upstream connection for a new request
    let mut upstream_send = upstream_send
        .ready()
        .await
        .context("upstream not ready for request")?;

    // Send request and body to upstream, returning (response_future, captured_body, body_len)
    let (upstream_response, request_body_buf, request_body_len) =
        if needs_gcp_resign && !body_is_end {
            // Buffer the entire body, re-sign GCP JWT, then send
            let mut buf = Vec::new();
            while let Some(chunk) = body.data().await {
                let data = chunk.context("error reading client body")?;
                if buf.len() as u64 + data.len() as u64 > state.limits.max_body_bytes {
                    return Err(anyhow!(
                        "request body exceeds maximum of {} bytes",
                        state.limits.max_body_bytes
                    ));
                }
                buf.extend_from_slice(&data);
                body.flow_control()
                    .release_capacity(data.len())
                    .context("failed to release client flow control")?;
            }

            if let Some(new_body) = state.gcp_credentials.resign_token_request(&buf) {
                buf = new_body;
            }

            // Send headers, then the (possibly rewritten) body as a single data frame
            let end_stream = buf.is_empty();
            let (response_fut, mut send_body) = upstream_send
                .send_request(upstream_request, end_stream)
                .context("failed to send request to upstream")?;

            if !buf.is_empty() {
                send_body
                    .send_data(Bytes::from(buf.clone()), true)
                    .context("failed to send body to upstream")?;
            }

            let len = buf.len();
            (
                response_fut
                    .await
                    .context("failed to receive upstream response")?,
                buf,
                len,
            )
        } else {
            // Stream body through without buffering
            let (response_fut, mut send_body) = upstream_send
                .send_request(upstream_request, body_is_end)
                .context("failed to send request to upstream")?;

            let mut body_buf = Vec::new();
            let mut body_len: usize = 0;
            if !body_is_end {
                while let Some(chunk) = body.data().await {
                    let data = chunk.context("error reading client body")?;
                    body_len += data.len();
                    if needs_body_capture {
                        if body_buf.len() as u64 + data.len() as u64 > state.limits.max_body_bytes {
                            return Err(anyhow!(
                                "request body exceeds maximum of {} bytes",
                                state.limits.max_body_bytes
                            ));
                        }
                        body_buf.extend_from_slice(&data);
                    }
                    body.flow_control()
                        .release_capacity(data.len())
                        .context("failed to release client flow control")?;
                    send_body
                        .send_data(data, false)
                        .context("failed to send body to upstream")?;
                }
                if let Some(trailers) = body
                    .trailers()
                    .await
                    .context("error reading client trailers")?
                {
                    send_body
                        .send_trailers(trailers)
                        .context("failed to send trailers to upstream")?;
                } else {
                    send_body
                        .send_data(Bytes::new(), true)
                        .context("failed to end upstream body")?;
                }
            }

            (
                response_fut
                    .await
                    .context("failed to receive upstream response")?,
                body_buf,
                body_len,
            )
        };

    let (response_parts, mut upstream_body) = upstream_response.into_parts();
    let response_status = response_parts.status.as_u16();

    // Capture response headers for logging
    let response_headers_raw = format_h2_headers_for_log(&response_parts.headers);

    // Build response to send to client
    let mut client_response = http::Response::from_parts(response_parts, ());

    let upstream_body_is_end = upstream_body.is_end_stream();

    // Handle response body - buffer for redaction, stream otherwise
    let (response_body_buf, response_body_len) = if decision.redact_tokens {
        // Token redaction requires buffering the entire body to modify JSON
        let mut response_body_buf = Vec::new();
        if !upstream_body_is_end {
            while let Some(chunk) = upstream_body.data().await {
                let data = chunk.context("error reading upstream body")?;
                if response_body_buf.len() as u64 + data.len() as u64 > state.limits.max_body_bytes
                {
                    return Err(anyhow!(
                        "response body exceeds maximum of {} bytes",
                        state.limits.max_body_bytes
                    ));
                }
                response_body_buf.extend_from_slice(&data);
                upstream_body
                    .flow_control()
                    .release_capacity(data.len())
                    .context("failed to release upstream flow control")?;
            }
        }

        // Redact OAuth tokens
        let response_body_buf = if let Some(redacted_body) = state
            .credentials
            .redact_oauth_response(&host, &response_body_buf)
        {
            redacted_body
        } else {
            response_body_buf
        };

        // Update content-length to match (possibly redacted) body
        if client_response.headers().contains_key("content-length") {
            // ASCII digits are always a valid HeaderValue.
            #[allow(clippy::expect_used)]
            let len_value = http::HeaderValue::from_str(&response_body_buf.len().to_string())
                .expect("usize as decimal is valid header value");
            let _ = client_response
                .headers_mut()
                .insert(http::header::CONTENT_LENGTH, len_value);
        }

        // Send buffered response
        let end_stream = response_body_buf.is_empty() && upstream_body_is_end;
        let mut client_send_body = respond
            .send_response(client_response, end_stream)
            .context("failed to send response to client")?;

        if !response_body_buf.is_empty() {
            client_send_body
                .send_data(Bytes::from(response_body_buf.clone()), true)
                .context("failed to send body to client")?;
        } else if !end_stream {
            client_send_body
                .send_data(Bytes::new(), true)
                .context("failed to end client body")?;
        }

        let len = response_body_buf.len();
        (response_body_buf, len)
    } else {
        // Stream response through without buffering (for SSE, large responses, etc.)
        // Send response headers immediately
        let mut client_send_body = respond
            .send_response(client_response, upstream_body_is_end)
            .context("failed to send response to client")?;

        // Stream body chunks, only capturing for logging when log_dir is set
        // — except for non-2xx responses, where we always keep a small leading
        // excerpt so `record_summary` can surface the error body in the journal.
        let needs_excerpt = (400..600).contains(&response_status);
        let mut response_body_buf = Vec::new();
        let mut response_body_len: usize = 0;
        if !upstream_body_is_end {
            while let Some(chunk) = upstream_body.data().await {
                let data = chunk.context("error reading upstream body")?;
                response_body_len += data.len();
                if needs_body_capture {
                    response_body_buf.extend_from_slice(&data);
                } else if needs_excerpt && response_body_buf.len() < request::NON_2XX_EXCERPT_CAP {
                    let take =
                        (request::NON_2XX_EXCERPT_CAP - response_body_buf.len()).min(data.len());
                    response_body_buf.extend_from_slice(&data[..take]);
                }
                // Release flow control capacity
                upstream_body
                    .flow_control()
                    .release_capacity(data.len())
                    .context("failed to release upstream flow control")?;
                // Forward to client immediately
                client_send_body
                    .send_data(data, false)
                    .context("failed to send body chunk to client")?;
            }
            // Check for trailers
            if let Some(trailers) = upstream_body
                .trailers()
                .await
                .context("error reading upstream trailers")?
            {
                client_send_body
                    .send_trailers(trailers)
                    .context("failed to send trailers to client")?;
            } else {
                // No trailers, just end the stream
                client_send_body
                    .send_data(Bytes::new(), true)
                    .context("failed to end client body")?;
            }
        }

        (response_body_buf, response_body_len)
    };

    // Record span, metrics, and log the exchange
    let outcome = RequestOutcome {
        host: &host,
        method: method.as_str(),
        path: &path,
        status_code: response_status,
        action: "allow",
        rule_index: decision.rule_index,
        request_bytes: request_headers_raw.len() + request_body_len,
        response_bytes: response_headers_raw.len() + response_body_len,
        start: request_start,
        client_addr: &client_addr,
        request_headers: &request_headers_raw,
        request_body: &request_body_buf,
        response_headers: &response_headers_raw,
        response_body: &response_body_buf,
    };
    outcome.record_span(&request_span);
    outcome.record_metrics(&state.metrics);
    outcome.record_summary();
    outcome.log_exchange(&state.log_dir).await;

    Ok(())
}

/// Format HTTP/2 headers into a format suitable for logging.
/// Returns headers as raw bytes similar to HTTP/1.1 format.
fn format_h2_headers_for_log(headers: &HeaderMap) -> Vec<u8> {
    let mut buf = Vec::new();
    for (name, value) in headers.iter() {
        buf.extend_from_slice(name.as_str().as_bytes());
        buf.extend_from_slice(b": ");
        buf.extend_from_slice(value.as_bytes());
        buf.extend_from_slice(b"\r\n");
    }
    buf.extend_from_slice(b"\r\n");
    buf
}

/// Inject credentials into HTTP/2 request headers.
fn inject_credentials_h2(headers: &mut HeaderMap, host: &str, state: &ProxyState) {
    // Collect replacements first to avoid borrowing issues
    let replacements: Vec<_> = headers
        .iter()
        .filter_map(|(name, value)| {
            state
                .credentials
                .replace(host, name, value)
                .map(|replacement| (name.clone(), replacement))
        })
        .collect();

    // Apply replacements
    for (name, replacement) in replacements {
        info!(host = %host, header = %name, "injecting credential (h2)");
        state
            .metrics
            .credential_injections_total
            .with_label_values(&[replacement.credential_name.as_str(), host])
            .inc();
        let _ = headers.insert(name, replacement.value);
    }
}
