use crate::config::Action;
use crate::proxy::request::RequestOutcome;
use crate::proxy::tls::{self, NegotiatedProtocol};
use crate::proxy::{h2 as h2_proxy, ProxyState};
use anyhow::{anyhow, Context, Result};
use http::{HeaderName, HeaderValue};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tracing::{debug, info, info_span, warn};

/// Handle an incoming proxy connection
pub async fn handle_connection(stream: TcpStream, state: Arc<ProxyState>) -> Result<()> {
    // Capture client address early for logging
    let client_addr = stream
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    // Read the initial HTTP request (should be CONNECT for HTTPS)
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    let _ = reader.read_line(&mut request_line).await?;

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 3 {
        return Err(anyhow!("invalid request line"));
    }

    let method = parts[0];
    let uri = parts[1];
    let _version = parts[2];

    if method != "CONNECT" {
        // For non-CONNECT, return 501 with helpful message
        let response = "HTTP/1.1 501 Not Implemented\r\n\
            Content-Type: text/plain\r\n\
            Content-Length: 53\r\n\
            \r\n\
            Alice only proxies HTTPS. Use https:// URLs instead.\n";
        let mut stream = reader.into_inner();
        stream.write_all(response.as_bytes()).await?;
        return Ok(());
    }

    // Parse host:port from CONNECT uri
    let (host, port) = parse_host_port(uri)?;

    // Read remaining headers
    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        let _ = reader.read_line(&mut line).await?;
        if line == "\r\n" || line == "\n" {
            break;
        }
        headers.push(line);
    }

    // Check proxy authentication if configured
    if let Some((expected_user, expected_pass)) = &state.proxy_auth {
        let auth_valid = headers.iter().any(|h| {
            if let Some(creds) = h
                .strip_prefix("Proxy-Authorization: Basic ")
                .or_else(|| h.strip_prefix("proxy-authorization: Basic "))
            {
                check_basic_auth(creds.trim(), expected_user, expected_pass)
            } else {
                false
            }
        });

        if !auth_valid {
            let response =
                "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"alice\"\r\n\r\n";
            let mut stream = reader.into_inner();
            stream.write_all(response.as_bytes()).await?;
            return Ok(());
        }
    }

    // Resolve DNS if we have CIDR rules (needed for policy evaluation)
    // Also cache the resolved IPs to avoid double resolution
    let resolved_ips: Option<Arc<Vec<IpAddr>>> = if state.policy.has_cidr_rules() {
        match state.dns.resolve(&host).await {
            Ok(ips) => {
                if ips.is_empty() {
                    warn!(host = %host, "DNS resolution returned no addresses");
                    let response = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
                    let mut stream = reader.into_inner();
                    stream.write_all(response.as_bytes()).await?;
                    return Ok(());
                }
                // Check for DNS blackhole (0.0.0.0 or ::) - reject early
                if crate::proxy::dns::DnsResolver::has_suspicious_addr(&ips) {
                    debug!(host = %host, "DNS blackhole detected, rejecting");
                    let response = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
                    let mut stream = reader.into_inner();
                    stream.write_all(response.as_bytes()).await?;
                    return Ok(());
                }
                Some(ips)
            }
            Err(e) => {
                warn!(host = %host, error = %e, "DNS resolution failed");
                let response = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
                let mut stream = reader.into_inner();
                stream.write_all(response.as_bytes()).await?;
                return Ok(());
            }
        }
    } else {
        None
    };

    // Evaluate policy at CONNECT time (host only, with resolved IPs for CIDR rules)
    let decision = state
        .policy
        .evaluate_host(&host, resolved_ips.as_deref().map(|v| v.as_slice()));

    // If definitely denied and no path check needed, reject now
    if decision.action == Action::Deny && !decision.needs_path_check {
        info!(host = %host, rule = decision.rule_index, "denied at CONNECT");
        let response = "HTTP/1.1 403 Forbidden\r\n\r\n";
        let mut stream = reader.into_inner();
        stream.write_all(response.as_bytes()).await?;
        stream.flush().await?;
        return Ok(());
    }

    // Send 200 Connection Established
    let mut stream = reader.into_inner();
    stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    stream.flush().await?;

    // Perform TLS MITM
    let (client_tls, client_proto) = tls::accept_client_tls(stream, &state.ca, &host).await?;

    // Connect to upstream - use resolved IP if available to avoid double resolution
    let upstream_tcp = if let Some(ref ips) = resolved_ips {
        // Try the resolved addresses in order: a host with both A and AAAA records
        // may only be listening on one family, and resolver ordering is not stable
        // across versions.
        //
        // Only addresses that reach this same verdict on their own are eligible.
        // `evaluate_host` matches a CIDR rule when *any* resolved IP falls in it,
        // so re-checking each address individually keeps a rebinding answer from
        // smuggling an unvetted IP in as a fallback.
        let candidates: Vec<SocketAddr> = ips
            .iter()
            .filter(|ip| {
                let per_ip = state.policy.evaluate_host(&host, Some(&[**ip]));
                per_ip.action == decision.action && per_ip.rule_index == decision.rule_index
            })
            .map(|ip| SocketAddr::new(*ip, port))
            .collect();

        let mut stream = None;
        let mut last_err = None;
        for addr in &candidates {
            match TcpStream::connect(addr).await {
                Ok(s) => {
                    stream = Some(s);
                    break;
                }
                Err(e) => {
                    debug!(host = %host, %addr, error = %e, "upstream connect failed, trying next address");
                    last_err = Some(e);
                }
            }
        }

        match (stream, last_err) {
            (Some(s), _) => s,
            (None, Some(e)) => {
                return Err(anyhow::Error::new(e)
                    .context(format!("failed to connect to {} ({:?})", host, candidates)))
            }
            (None, None) => {
                return Err(anyhow!(
                    "no policy-approved addresses to connect to for {}",
                    host
                ))
            }
        }
    } else {
        // No CIDR rules - let the OS resolve
        let upstream_addr = format!("{}:{}", host, port);
        TcpStream::connect(&upstream_addr)
            .await
            .with_context(|| format!("failed to connect to {}", upstream_addr))?
    };

    let (upstream_tls, upstream_proto) = tls::connect_upstream_tls(
        upstream_tcp,
        &host,
        state.upstream_ca.as_deref(),
        client_proto,
    )
    .await?;

    debug!(
        host = %host,
        client_proto = ?client_proto,
        upstream_proto = ?upstream_proto,
        "TLS handshakes complete"
    );

    // Route based on negotiated protocols
    match (client_proto, upstream_proto) {
        (NegotiatedProtocol::H2, NegotiatedProtocol::H2) => {
            // Both sides support HTTP/2, use HTTP/2 proxy with request inspection
            h2_proxy::proxy_h2(
                client_tls,
                upstream_tls,
                host,
                state,
                resolved_ips,
                client_addr,
            )
            .await
        }
        (NegotiatedProtocol::H2, NegotiatedProtocol::Http1) => {
            // Client speaks H2 but upstream only supports H1.1 - translate
            debug!(host = %host, "protocol mismatch: translating H2 client to H1.1 upstream");
            h2_proxy::proxy_h2_to_h1(
                client_tls,
                upstream_tls,
                host,
                state,
                resolved_ips,
                client_addr,
            )
            .await
        }
        _ => {
            // Both sides speak HTTP/1.1 (upstream ALPN is constrained to match client)
            let (client_read, client_write) = tokio::io::split(client_tls);
            let (upstream_read, upstream_write) = tokio::io::split(upstream_tls);

            // Need inspection if path checking required, credentials need to be injected,
            // token redaction is configured, or logging is enabled.
            let needs_inspection = decision.needs_path_check
                || decision.requires_redact_inspection
                || state.credentials.has_credentials_for_host(&host)
                || state.log_dir.is_some();

            if needs_inspection {
                // Use HTTP/1.1 parsing to inspect requests
                proxy_with_inspection(
                    client_read,
                    client_write,
                    upstream_read,
                    upstream_write,
                    host,
                    state,
                    resolved_ips,
                    client_addr,
                )
                .await
            } else {
                // No path inspection or credential injection needed, just copy bytes
                info!(host = %host, rule = decision.rule_index, "allowed");
                proxy_bidirectional(client_read, client_write, upstream_read, upstream_write).await
            }
        }
    }
}

/// Simple bidirectional proxy (no inspection)
async fn proxy_bidirectional<CR, CW, UR, UW>(
    mut client_read: CR,
    mut client_write: CW,
    mut upstream_read: UR,
    mut upstream_write: UW,
) -> Result<()>
where
    CR: AsyncReadExt + Unpin,
    CW: AsyncWriteExt + Unpin,
    UR: AsyncReadExt + Unpin,
    UW: AsyncWriteExt + Unpin,
{
    let client_to_upstream = async {
        let mut buf = vec![0u8; 65536];
        loop {
            let n = client_read.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            upstream_write.write_all(&buf[..n]).await?;
        }
        upstream_write.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    };

    let upstream_to_client = async {
        let mut buf = vec![0u8; 65536];
        loop {
            let n = upstream_read.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            client_write.write_all(&buf[..n]).await?;
        }
        client_write.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    };

    // First-done-wins: once one direction EOFs we drop the other half so its
    // socket closes. With try_join the proxy waits for both peers to close,
    // which under TLS MITM can be never — leaving FDs in CLOSE-WAIT.
    tokio::select! {
        res = client_to_upstream => res?,
        res = upstream_to_client => res?,
    }
    Ok(())
}

enum IdleAction {
    ClientReady,
    ClientClosed,
    UpstreamClosed,
    UpstreamUnsolicited,
    IdleTimeout,
}

/// Proxy with HTTP request inspection for path-based policy.
/// Inspects EVERY request on the connection, not just the first.
#[allow(clippy::too_many_arguments)]
async fn proxy_with_inspection<CR, CW, UR, UW>(
    client_read: CR,
    client_write: CW,
    upstream_read: UR,
    upstream_write: UW,
    host: String,
    state: Arc<ProxyState>,
    resolved_ips: Option<Arc<Vec<IpAddr>>>,
    client_addr: String,
) -> Result<()>
where
    CR: AsyncReadExt + Unpin,
    CW: AsyncWriteExt + Unpin,
    UR: AsyncReadExt + Unpin,
    UW: AsyncWriteExt + Unpin,
{
    let mut client_reader = BufReader::new(client_read);
    let mut client_write = client_write;
    let mut upstream_reader = BufReader::new(upstream_read);
    let mut upstream_write = upstream_write;
    let idle_timeout = state.idle_timeout;

    // Process requests in a loop (HTTP/1.1 keep-alive).
    //
    // We watch the upstream during idle so we notice when it half-closes (e.g.
    // CDN keep-alive timeout); otherwise the upstream FD lingers in CLOSE-WAIT
    // until idle_timeout, leaking FDs under parallel load. fill_buf is cancel-
    // safe and non-consuming, so it's safe to race against; read_http_headers
    // is not, so we only call it after the race resolves to ClientReady.
    loop {
        let action = tokio::select! {
            biased;
            res = client_reader.fill_buf() => match res {
                Ok([]) => IdleAction::ClientClosed,
                Ok(_) => IdleAction::ClientReady,
                Err(_) => IdleAction::ClientClosed,
            },
            res = upstream_reader.fill_buf() => match res {
                Ok([]) => IdleAction::UpstreamClosed,
                Ok(_) => IdleAction::UpstreamUnsolicited,
                Err(_) => IdleAction::UpstreamClosed,
            },
            _ = tokio::time::sleep(idle_timeout) => IdleAction::IdleTimeout,
        };

        match action {
            IdleAction::ClientClosed => break,
            IdleAction::IdleTimeout => {
                debug!("connection idle timeout");
                break;
            }
            IdleAction::UpstreamClosed => {
                debug!("upstream closed during keep-alive idle");
                break;
            }
            IdleAction::UpstreamUnsolicited => {
                debug!("unsolicited upstream data during idle, closing keep-alive");
                break;
            }
            IdleAction::ClientReady => {}
        }

        let request_start = Instant::now();

        // Client has data buffered; safe to read full request headers.
        let request_headers = match read_http_headers(
            &mut client_reader,
            state.limits.max_header_bytes,
            state.limits.max_header_count,
        )
        .await
        {
            Ok(headers) => headers,
            Err(_) => break,
        };

        if request_headers.is_empty() {
            // Client closed connection gracefully
            break;
        }

        // Parse the request line
        let request_str = String::from_utf8_lossy(&request_headers);
        let first_line = request_str.lines().next().unwrap_or("");
        let parts: Vec<&str> = first_line.split_whitespace().collect();

        if parts.len() < 2 {
            debug!("invalid HTTP request line");
            break;
        }

        // Make method and path owned to avoid borrow conflicts with credential injection
        let method = parts[0].to_string();
        let path = parts[1].to_string();

        // Create request span with HTTP semantic conventions
        let request_span = info_span!(
            "request",
            http.request.method = %method,
            url.full = %format!("https://{}{}", host, path),
            server.address = %host,
            http.response.status_code = tracing::field::Empty,
            alice.policy.action = tracing::field::Empty,
            alice.policy.rule_index = tracing::field::Empty,
            alice.duration_ms = tracing::field::Empty,
        );
        let _request_guard = request_span.enter();

        // Parse headers for body handling and connection state. alice is the
        // authority on framing: reject ambiguous combinations (Content-Length
        // + Transfer-Encoding, or duplicate/conflicting Content-Length) rather
        // than forward them and open a request-smuggling desync window.
        let (content_length, is_chunked) = match classify_request_framing(&request_str) {
            RequestFraming::Length(n) => (Some(n), false),
            RequestFraming::Chunked => (None, true),
            RequestFraming::Invalid => {
                warn!(
                    host = %host,
                    path = %path,
                    "rejecting request with ambiguous framing (request-smuggling vector)"
                );
                // We cannot safely locate the body boundary, so we must close
                // the connection rather than try to resync.
                let response =
                    "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                client_write.write_all(response.as_bytes()).await?;
                client_write.flush().await?;
                break;
            }
        };
        let client_wants_close = wants_connection_close(&request_str);

        // Evaluate policy (with resolved IPs for CIDR rules if available)
        let decision =
            state
                .policy
                .evaluate(&host, &path, resolved_ips.as_deref().map(|v| v.as_slice()));

        if decision.action == Action::Deny {
            let deny = RequestOutcome {
                host: &host,
                method: &method,
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
            deny.record_deny(&request_span, &state.metrics, "");

            // Drain the request body if present (so connection stays in sync)
            if let Some(len) = content_length {
                drain_body_fixed(&mut client_reader, len).await?;
            } else if is_chunked {
                drain_body_chunked(&mut client_reader).await?;
            }

            // Send 403 to client
            let response = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
            client_write.write_all(response.as_bytes()).await?;
            client_write.flush().await?;

            if client_wants_close {
                break;
            }
            continue;
        }

        // Record span fields for allowed request (status will be updated after response)
        let _ = request_span.record("alice.policy.action", "allow");
        let _ = request_span.record("alice.policy.rule_index", decision.rule_index as i64);
        info!(host = %host, path = %path, method = %method, rule = decision.rule_index, "allowed");

        // Inject credentials if needed
        let request_headers = if state.credentials.has_credentials_for_host(&host) {
            inject_credentials_h1(&request_headers, &host, &state)?
        } else {
            request_headers
        };

        // Always buffer request body (needed for logging and credential inspection)
        let request_body = if let Some(len) = content_length {
            read_body_fixed(&mut client_reader, len, state.limits.max_body_bytes).await?
        } else if is_chunked {
            read_body_chunked(&mut client_reader, state.limits.max_body_bytes).await?
        } else {
            Vec::new()
        };

        // GCP JWT re-signing: intercept token exchange POST bodies
        let (request_headers, request_body) =
            if state.gcp_credentials.is_gcp_token_request(&host, &path) {
                if let Some(new_body) = state.gcp_credentials.resign_token_request(&request_body) {
                    if new_body.len() != request_body.len() {
                        (
                            rewrite_content_length(&request_headers, new_body.len()),
                            new_body,
                        )
                    } else {
                        (request_headers, new_body)
                    }
                } else {
                    (request_headers, request_body)
                }
            } else {
                (request_headers, request_body)
            };

        // Strip hop-by-hop headers (Connection, Transfer-Encoding, Keep-Alive,
        // Proxy-*, plus anything named in Connection) and emit a single
        // Content-Length matching the body alice actually forwards. This makes
        // alice the sole framing authority and closes the smuggling window.
        let request_headers = sanitize_request_headers(&request_headers, request_body.len());

        // Forward request headers to upstream
        upstream_write.write_all(&request_headers).await?;

        // Forward request body
        upstream_write.write_all(&request_body).await?;
        upstream_write.flush().await?;

        // Read response headers from upstream
        let response_headers = read_http_headers(
            &mut upstream_reader,
            state.limits.max_header_bytes,
            state.limits.max_header_count,
        )
        .await?;
        if response_headers.is_empty() {
            return Err(anyhow!("upstream closed connection unexpectedly"));
        }

        // Parse response for body handling
        let response_str = String::from_utf8_lossy(&response_headers);
        let resp_content_length = parse_content_length(&response_str);
        let resp_is_chunked = is_chunked_encoding(&response_str);
        let server_wants_close = wants_connection_close(&response_str);

        // Parse response status for logging
        let response_status = parse_response_status(&response_str);

        // Handle response body - buffer for redaction or GCP token interception, stream otherwise
        let needs_body_buffer =
            decision.redact_tokens || state.gcp_credentials.is_gcp_token_request(&host, &path);
        let (response_headers, response_body, response_body_bytes) = if needs_body_buffer {
            // Token redaction requires buffering the entire body to modify JSON
            let response_body = if let Some(len) = resp_content_length {
                read_body_fixed(&mut upstream_reader, len, state.limits.max_body_bytes).await?
            } else if resp_is_chunked {
                read_body_chunked(&mut upstream_reader, state.limits.max_body_bytes).await?
            } else {
                Vec::new()
            };

            // Decompress gzip if needed for JSON parsing
            let decompressed = decompress_gzip_if_needed(
                &response_headers,
                &response_body,
                state.limits.max_decompressed_bytes,
            );
            let body_for_redaction = decompressed.as_deref().unwrap_or(&response_body);

            // Redact OAuth tokens
            let (headers, body) = if let Some(redacted_body) = state
                .credentials
                .redact_oauth_response(&host, body_for_redaction)
            {
                // Body was modified and is now decompressed JSON - strip content-encoding
                // and rewrite content-length
                let new_headers = rewrite_response_for_buffered_body(
                    &response_headers,
                    redacted_body.len(),
                    decompressed.is_some(),
                );
                (new_headers, redacted_body)
            } else if resp_is_chunked {
                // Even if we didn't redact, we dechunked the body so headers must be fixed
                let new_headers = rewrite_content_length(&response_headers, response_body.len());
                (new_headers, response_body)
            } else {
                (response_headers.clone(), response_body)
            };

            // Forward buffered response
            client_write.write_all(&headers).await?;
            client_write.write_all(&body).await?;
            client_write.flush().await?;

            let body_len = body.len();
            (headers, body, body_len)
        } else {
            // Stream response through without buffering (for SSE, large responses, etc.)
            // Forward headers immediately
            client_write.write_all(&response_headers).await?;
            client_write.flush().await?;

            // Only accumulate the body in memory when something will read
            // it back — i.e. when we're going to write it to the log dir,
            // or when this is a non-2xx response and `record_summary` needs
            // an excerpt for the journal. Skipping otherwise avoids holding
            // an entire `cargo install` crate (multi-MB) in memory per
            // connection.
            let capture = state.log_dir.is_some() || (400..600).contains(&response_status);

            let (response_body, response_body_bytes) = if let Some(len) = resp_content_length {
                let (body, n) = stream_body_fixed(
                    &mut upstream_reader,
                    &mut client_write,
                    len,
                    capture,
                    state.limits.max_body_bytes,
                )
                .await?;
                (body, n as usize)
            } else if resp_is_chunked {
                stream_body_chunked(&mut upstream_reader, &mut client_write, capture).await?
            } else {
                (Vec::new(), 0)
            };

            (response_headers.clone(), response_body, response_body_bytes)
        };

        // Record span, metrics, and log the exchange
        let outcome = RequestOutcome {
            host: &host,
            method: &method,
            path: &path,
            status_code: response_status,
            action: "allow",
            rule_index: decision.rule_index,
            request_bytes: request_headers.len() + request_body.len(),
            response_bytes: response_headers.len() + response_body_bytes,
            start: request_start,
            client_addr: &client_addr,
            request_headers: &request_headers,
            request_body: &request_body,
            response_headers: &response_headers,
            response_body: &response_body,
        };
        outcome.record_span(&request_span);
        outcome.record_metrics(&state.metrics);
        outcome.record_summary();
        outcome.log_exchange(&state.log_dir).await;

        // Check if either side wants to close
        if client_wants_close || server_wants_close {
            break;
        }
    }

    Ok(())
}

/// Read HTTP headers (up to and including the blank line).
/// Returns the raw bytes including the final \r\n\r\n.
///
/// Bounded by `max_bytes` (total header block size) and `max_count` (number of
/// header lines) so a slow-loris-style stream of headers — or a single
/// unterminated line — can't grow the buffer without limit. Each line is read
/// through a `take` adapter so one giant line can't exhaust memory before the
/// size check runs.
async fn read_http_headers<R: AsyncBufReadExt + Unpin>(
    reader: &mut R,
    max_bytes: usize,
    max_count: usize,
) -> Result<Vec<u8>> {
    let mut headers = Vec::new();
    let mut count = 0usize;

    loop {
        if headers.len() >= max_bytes {
            return Err(anyhow!(
                "header block exceeds maximum size of {} bytes",
                max_bytes
            ));
        }
        if count > max_count {
            return Err(anyhow!(
                "header block exceeds maximum count of {} lines",
                max_count
            ));
        }

        // Bound the per-line read so an unterminated line can't grow without
        // limit before the size check above fires on the next iteration.
        let budget = (max_bytes - headers.len()) as u64 + 1;
        let mut line = String::new();
        let n = (&mut *reader).take(budget).read_line(&mut line).await?;
        if n == 0 {
            // EOF before headers complete
            return Ok(headers);
        }

        headers.extend_from_slice(line.as_bytes());

        // Empty line (just \r\n) marks end of headers
        if line == "\r\n" || line == "\n" {
            break;
        }

        count += 1;
    }

    Ok(headers)
}

/// Parse Content-Length header value
fn parse_content_length(headers: &str) -> Option<u64> {
    for line in headers.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("content-length:") {
            if let Some(value) = line.split_once(':').map(|(_, v)| v.trim()) {
                return value.parse().ok();
            }
        }
    }
    None
}

/// Check if Transfer-Encoding: chunked
fn is_chunked_encoding(headers: &str) -> bool {
    for line in headers.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("transfer-encoding:") && lower.contains("chunked") {
            return true;
        }
    }
    false
}

/// Check if Connection: close
fn wants_connection_close(headers: &str) -> bool {
    for line in headers.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("connection:") && lower.contains("close") {
            return true;
        }
    }
    false
}

/// How alice should frame the body of an incoming request, after rejecting
/// ambiguous combinations that enable request smuggling / desync.
#[derive(Debug, PartialEq, Eq)]
enum RequestFraming {
    /// Fixed-length body (0 = no body).
    Length(u64),
    /// Chunked transfer-encoding.
    Chunked,
    /// Ambiguous or conflicting framing — reject with 400 and close.
    Invalid,
}

/// Classify request body framing, rejecting smuggling vectors:
/// - `Content-Length` together with `Transfer-Encoding` (classic CL.TE/TE.CL desync)
/// - more than one `Content-Length` header (duplicate / conflicting)
/// - a `Content-Length` value that doesn't parse as a single integer
///   (e.g. `Content-Length: 5, 6`)
/// - a `Transfer-Encoding` that isn't `chunked` (we can only reframe chunked)
fn classify_request_framing(headers: &str) -> RequestFraming {
    let mut content_lengths: Vec<u64> = Vec::new();
    let mut content_length_invalid = false;
    let mut has_transfer_encoding = false;
    let mut is_chunked = false;

    // Skip the request line; only header lines carry framing.
    for line in headers.lines().skip(1) {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        if name == "content-length" {
            match value.parse::<u64>() {
                Ok(v) => content_lengths.push(v),
                Err(_) => content_length_invalid = true,
            }
        } else if name == "transfer-encoding" {
            has_transfer_encoding = true;
            if value.to_ascii_lowercase().contains("chunked") {
                is_chunked = true;
            }
        }
    }

    if content_length_invalid {
        return RequestFraming::Invalid;
    }
    // Duplicate Content-Length headers (whether or not the values agree) are a
    // smuggling vector; reject rather than guess which one upstream honors.
    if content_lengths.len() > 1 {
        return RequestFraming::Invalid;
    }
    // Content-Length and Transfer-Encoding together is the classic desync.
    if has_transfer_encoding && !content_lengths.is_empty() {
        return RequestFraming::Invalid;
    }

    if has_transfer_encoding {
        if is_chunked {
            RequestFraming::Chunked
        } else {
            // A transfer-coding we can't dechunk and reframe.
            RequestFraming::Invalid
        }
    } else {
        RequestFraming::Length(content_lengths.first().copied().unwrap_or(0))
    }
}

/// True for hop-by-hop headers that a proxy must not forward end-to-end.
/// Covers the named set plus the `Proxy-*` family; callers also drop anything
/// listed in the request's own `Connection` header.
pub(crate) fn is_hop_by_hop(name_lower: &str) -> bool {
    matches!(
        name_lower,
        "connection" | "keep-alive" | "transfer-encoding" | "te" | "trailer" | "upgrade"
    ) || name_lower.starts_with("proxy-")
}

/// Strip hop-by-hop headers and rewrite framing so alice is the sole authority
/// on the request it forwards. Removes Connection, Keep-Alive, Transfer-Encoding,
/// TE, Trailer, Upgrade, Proxy-*, any header named in the Connection field, and
/// all Content-Length headers, then sets a single Content-Length matching the
/// body alice will actually send (omitted when there is no body).
fn sanitize_request_headers(headers: &[u8], body_len: usize) -> Vec<u8> {
    let headers_str = String::from_utf8_lossy(headers);

    // Build the connection-token denylist first: every token named in a
    // `Connection` header is itself hop-by-hop for this message.
    let mut connection_tokens: Vec<String> = Vec::new();
    for line in headers_str.lines().skip(1) {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("connection") {
                for tok in value.split(',') {
                    let tok = tok.trim().to_ascii_lowercase();
                    if !tok.is_empty() {
                        connection_tokens.push(tok);
                    }
                }
            }
        }
    }

    let mut result = Vec::new();

    // Request line is forwarded unchanged.
    let request_line = headers_str.lines().next().unwrap_or("");
    result.extend_from_slice(request_line.as_bytes());
    result.extend_from_slice(b"\r\n");

    for line in headers_str.lines().skip(1) {
        if line.is_empty() {
            break;
        }
        let Some((name, _)) = line.split_once(':') else {
            // Drop malformed header lines rather than forward them verbatim.
            continue;
        };
        let lower = name.trim().to_ascii_lowercase();
        if lower == "content-length" || is_hop_by_hop(&lower) || connection_tokens.contains(&lower)
        {
            continue;
        }
        result.extend_from_slice(line.as_bytes());
        result.extend_from_slice(b"\r\n");
    }

    if body_len > 0 {
        result.extend_from_slice(b"Content-Length: ");
        result.extend_from_slice(body_len.to_string().as_bytes());
        result.extend_from_slice(b"\r\n");
    }

    result.extend_from_slice(b"\r\n");
    result
}

/// Drain (discard) a fixed-length body
async fn drain_body_fixed<R: AsyncReadExt + Unpin>(reader: &mut R, length: u64) -> Result<()> {
    let mut remaining = length;
    let mut buf = [0u8; 8192];

    while remaining > 0 {
        let to_read = std::cmp::min(remaining as usize, buf.len());
        let n = reader.read(&mut buf[..to_read]).await?;
        if n == 0 {
            return Err(anyhow!("unexpected EOF draining body"));
        }
        remaining -= n as u64;
    }

    Ok(())
}

/// Drain (discard) a chunked body
async fn drain_body_chunked<R: AsyncBufReadExt + Unpin>(reader: &mut R) -> Result<()> {
    loop {
        let mut size_line = String::new();
        let _ = reader.read_line(&mut size_line).await?;

        let size_str = size_line.trim();
        let size_hex = size_str.split(';').next().unwrap_or(size_str);
        let chunk_size = usize::from_str_radix(size_hex, 16)
            .with_context(|| format!("invalid chunk size: {}", size_line.trim()))?;

        if chunk_size == 0 {
            // Read trailing CRLF
            loop {
                let mut trailer_line = String::new();
                let _ = reader.read_line(&mut trailer_line).await?;
                if trailer_line == "\r\n" || trailer_line == "\n" {
                    break;
                }
            }
            break;
        }

        // Drain chunk data
        let mut remaining = chunk_size;
        let mut buf = [0u8; 8192];
        while remaining > 0 {
            let to_read = std::cmp::min(remaining, buf.len());
            let n = reader.read(&mut buf[..to_read]).await?;
            if n == 0 {
                return Err(anyhow!("unexpected EOF draining chunk"));
            }
            remaining -= n;
        }

        // Drain CRLF
        let mut crlf = [0u8; 2];
        let _ = reader.read_exact(&mut crlf).await?;
    }

    Ok(())
}

/// Read a fixed-length body into a buffer (for logging).
///
/// A claimed `length` above `max_bytes` is rejected up front so a forged
/// `Content-Length` can't trigger a huge eager allocation.
async fn read_body_fixed<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    length: u64,
    max_bytes: u64,
) -> Result<Vec<u8>> {
    if length > max_bytes {
        return Err(anyhow!(
            "body length {} exceeds maximum of {} bytes",
            length,
            max_bytes
        ));
    }
    let mut body = Vec::with_capacity(length as usize);
    let mut remaining = length;
    let mut buf = [0u8; 8192];

    while remaining > 0 {
        let to_read = std::cmp::min(remaining as usize, buf.len());
        let n = reader.read(&mut buf[..to_read]).await?;
        if n == 0 {
            return Err(anyhow!("unexpected EOF reading body"));
        }
        body.extend_from_slice(&buf[..n]);
        remaining -= n as u64;
    }

    Ok(body)
}

/// Read a chunked body into a buffer (for logging).
/// Returns the decoded body content (without chunk framing).
///
/// Accumulation is capped at `max_bytes` so a chunked stream can't grow the
/// buffer without limit.
async fn read_body_chunked<R: AsyncBufReadExt + Unpin>(
    reader: &mut R,
    max_bytes: u64,
) -> Result<Vec<u8>> {
    let mut body = Vec::new();

    loop {
        // Read chunk size line
        let mut size_line = String::new();
        let _ = reader.read_line(&mut size_line).await?;

        let size_str = size_line.trim();
        let size_hex = size_str.split(';').next().unwrap_or(size_str);
        let chunk_size = usize::from_str_radix(size_hex, 16)
            .with_context(|| format!("invalid chunk size: {}", size_line.trim()))?;

        if body.len() as u64 + chunk_size as u64 > max_bytes {
            return Err(anyhow!(
                "chunked body exceeds maximum of {} bytes",
                max_bytes
            ));
        }

        if chunk_size == 0 {
            // Terminal chunk - read trailing headers/CRLF
            loop {
                let mut trailer_line = String::new();
                let _ = reader.read_line(&mut trailer_line).await?;
                if trailer_line == "\r\n" || trailer_line == "\n" {
                    break;
                }
            }
            break;
        }

        // Read chunk data
        let mut remaining = chunk_size;
        let mut buf = [0u8; 8192];
        while remaining > 0 {
            let to_read = std::cmp::min(remaining, buf.len());
            let n = reader.read(&mut buf[..to_read]).await?;
            if n == 0 {
                return Err(anyhow!("unexpected EOF in chunk"));
            }
            body.extend_from_slice(&buf[..n]);
            remaining -= n;
        }

        // Read chunk-ending CRLF
        let mut crlf = [0u8; 2];
        let _ = reader.read_exact(&mut crlf).await?;
    }

    Ok(body)
}

/// Stream a fixed-length body from reader to writer.
/// Returns `(captured_body, bytes_streamed)`. When `capture` is false the
/// returned Vec is empty and no per-chunk allocation happens — important
/// for large downloads (e.g. cargo crates) when no log_dir is configured.
async fn stream_body_fixed<R, W>(
    reader: &mut R,
    writer: &mut W,
    length: u64,
    capture: bool,
    max_capture_bytes: u64,
) -> Result<(Vec<u8>, u64)>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    // Cap the capture pre-allocation at `max_capture_bytes` so a forged
    // `Content-Length` can't trigger a huge eager allocation. The body is
    // still streamed through in full regardless of the claimed length.
    let mut body = if capture {
        Vec::with_capacity(std::cmp::min(length, max_capture_bytes) as usize)
    } else {
        Vec::new()
    };
    let mut remaining = length;
    let mut buf = vec![0u8; 65536];

    while remaining > 0 {
        let to_read = std::cmp::min(remaining as usize, buf.len());
        let n = reader.read(&mut buf[..to_read]).await?;
        if n == 0 {
            return Err(anyhow!("unexpected EOF reading body"));
        }
        if capture {
            body.extend_from_slice(&buf[..n]);
        }
        writer.write_all(&buf[..n]).await?;
        remaining -= n as u64;
    }

    Ok((body, length))
}

/// Stream a chunked body from reader to writer, flushing after each chunk.
/// Returns `(captured_decoded_body, decoded_bytes)`. The Vec is empty if
/// `capture` is false.
async fn stream_body_chunked<R, W>(
    reader: &mut R,
    writer: &mut W,
    capture: bool,
) -> Result<(Vec<u8>, usize)>
where
    R: AsyncBufReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    let mut body = Vec::new();
    let mut total: usize = 0;

    loop {
        let mut size_line = String::new();
        let _ = reader.read_line(&mut size_line).await?;

        let size_str = size_line.trim();
        let size_hex = size_str.split(';').next().unwrap_or(size_str);
        let chunk_size = usize::from_str_radix(size_hex, 16)
            .with_context(|| format!("invalid chunk size: {}", size_line.trim()))?;

        writer.write_all(size_line.as_bytes()).await?;

        if chunk_size == 0 {
            loop {
                let mut trailer_line = String::new();
                let _ = reader.read_line(&mut trailer_line).await?;
                writer.write_all(trailer_line.as_bytes()).await?;
                if trailer_line == "\r\n" || trailer_line == "\n" {
                    break;
                }
            }
            writer.flush().await?;
            break;
        }

        let mut remaining = chunk_size;
        let mut buf = vec![0u8; 65536];
        while remaining > 0 {
            let to_read = std::cmp::min(remaining, buf.len());
            let n = reader.read(&mut buf[..to_read]).await?;
            if n == 0 {
                return Err(anyhow!("unexpected EOF in chunk"));
            }
            if capture {
                body.extend_from_slice(&buf[..n]);
            }
            writer.write_all(&buf[..n]).await?;
            remaining -= n;
            total += n;
        }

        let mut crlf = [0u8; 2];
        let _ = reader.read_exact(&mut crlf).await?;
        writer.write_all(&crlf).await?;

        // Flush after each chunk so SSE events reach the client immediately.
        writer.flush().await?;
    }

    Ok((body, total))
}

/// Parse HTTP response status code from response headers
fn parse_response_status(headers: &str) -> u16 {
    // First line should be "HTTP/1.1 200 OK" or similar
    if let Some(first_line) = headers.lines().next() {
        let parts: Vec<&str> = first_line.split_whitespace().collect();
        if parts.len() >= 2 {
            if let Ok(status) = parts[1].parse::<u16>() {
                return status;
            }
        }
    }
    0 // Unknown status
}

/// Rewrite the Content-Length header in an HTTP response.
/// Used when token redaction changes the body size.
fn rewrite_content_length(headers: &[u8], new_length: usize) -> Vec<u8> {
    let headers_str = String::from_utf8_lossy(headers);
    let mut result = Vec::new();

    for line in headers_str.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("content-length:") {
            // Replace with new length
            result.extend_from_slice(b"Content-Length: ");
            result.extend_from_slice(new_length.to_string().as_bytes());
            result.extend_from_slice(b"\r\n");
        } else if lower.starts_with("transfer-encoding:") && lower.contains("chunked") {
            // Remove chunked encoding since we're sending a fixed-length body
            // Add Content-Length instead
            result.extend_from_slice(b"Content-Length: ");
            result.extend_from_slice(new_length.to_string().as_bytes());
            result.extend_from_slice(b"\r\n");
        } else {
            result.extend_from_slice(line.as_bytes());
            result.extend_from_slice(b"\r\n");
        }
    }

    result
}

/// Check if a response is gzip-encoded and decompress if so.
/// Returns `Some(decompressed)` if the response was gzip and decompression succeeded,
/// or `None` if the response is not gzip or decompression failed.
fn decompress_gzip_if_needed(headers: &[u8], body: &[u8], max_bytes: u64) -> Option<Vec<u8>> {
    let headers_str = String::from_utf8_lossy(headers);
    let is_gzip = headers_str
        .lines()
        .any(|l| l.to_lowercase().starts_with("content-encoding:") && l.contains("gzip"));

    if !is_gzip || body.is_empty() {
        return None;
    }

    use flate2::read::GzDecoder;
    use std::io::Read;

    // Bound the decompressed output at `max_bytes` to defuse decompression
    // bombs: read at most one byte past the cap, then reject if we hit it.
    let decoder = GzDecoder::new(body);
    let mut decompressed = Vec::new();
    match decoder.take(max_bytes + 1).read_to_end(&mut decompressed) {
        Ok(_) if decompressed.len() as u64 > max_bytes => {
            tracing::warn!(
                max = max_bytes,
                "gzip response exceeds decompression limit, skipping redaction"
            );
            None
        }
        Ok(_) => {
            tracing::debug!(
                original_len = body.len(),
                decompressed_len = decompressed.len(),
                "decompressed gzip response for token redaction"
            );
            Some(decompressed)
        }
        Err(e) => {
            tracing::warn!(error = %e, "failed to decompress gzip response");
            None
        }
    }
}

/// Rewrite response headers for a buffered body that may have been decompressed.
/// Replaces Content-Length, removes Transfer-Encoding: chunked, and optionally
/// removes Content-Encoding: gzip if the body was decompressed.
fn rewrite_response_for_buffered_body(
    headers: &[u8],
    new_length: usize,
    strip_content_encoding: bool,
) -> Vec<u8> {
    let headers_str = String::from_utf8_lossy(headers);
    let mut result = Vec::new();
    let mut has_content_length = false;

    for line in headers_str.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("content-length:") {
            result.extend_from_slice(b"Content-Length: ");
            result.extend_from_slice(new_length.to_string().as_bytes());
            result.extend_from_slice(b"\r\n");
            has_content_length = true;
        } else if lower.starts_with("transfer-encoding:") && lower.contains("chunked") {
            // Replace chunked with Content-Length
            result.extend_from_slice(b"Content-Length: ");
            result.extend_from_slice(new_length.to_string().as_bytes());
            result.extend_from_slice(b"\r\n");
            has_content_length = true;
        } else if strip_content_encoding && lower.starts_with("content-encoding:") {
            // Drop content-encoding since we decompressed
            continue;
        } else {
            result.extend_from_slice(line.as_bytes());
            result.extend_from_slice(b"\r\n");
        }
    }

    // If there was no Content-Length or Transfer-Encoding header, add one
    if !has_content_length && new_length > 0 {
        // Insert before the final \r\n (end of headers)
        let insert_pos = result.len().saturating_sub(2);
        let trailer = result.split_off(insert_pos);
        result.extend_from_slice(b"Content-Length: ");
        result.extend_from_slice(new_length.to_string().as_bytes());
        result.extend_from_slice(b"\r\n");
        result.extend_from_slice(&trailer);
    }

    result
}

/// Inject credentials into an HTTP/1.1 request buffer.
fn inject_credentials_h1(request_buf: &[u8], host: &str, state: &ProxyState) -> Result<Vec<u8>> {
    let request_str = String::from_utf8_lossy(request_buf);
    let lines: Vec<&str> = request_str.lines().collect();

    if lines.is_empty() {
        return Ok(request_buf.to_vec());
    }

    let mut result = Vec::new();

    // Write the request line unchanged
    result.extend_from_slice(lines[0].as_bytes());
    result.extend_from_slice(b"\r\n");

    // Process headers
    for line in &lines[1..] {
        if line.is_empty() {
            // End of headers
            break;
        }

        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim();
            let value = value.trim();

            // Try to parse and check for credential replacement
            if let (Ok(header_name), Ok(header_value)) =
                (name.parse::<HeaderName>(), HeaderValue::from_str(value))
            {
                if let Some(replacement) =
                    state.credentials.replace(host, &header_name, &header_value)
                {
                    info!(host = %host, header = %name, "injecting credential");
                    state
                        .metrics
                        .credential_injections_total
                        .with_label_values(&[replacement.credential_name.as_str(), host])
                        .inc();
                    result.extend_from_slice(name.as_bytes());
                    result.extend_from_slice(b": ");
                    result.extend_from_slice(replacement.value.as_bytes());
                    result.extend_from_slice(b"\r\n");
                    continue;
                }
            }
        }

        // No replacement, write original line
        result.extend_from_slice(line.as_bytes());
        result.extend_from_slice(b"\r\n");
    }

    // End headers
    result.extend_from_slice(b"\r\n");

    // Copy any body that was included in the buffer
    if let Some(pos) = request_buf.windows(4).position(|w| w == b"\r\n\r\n") {
        let body_start = pos + 4;
        if body_start < request_buf.len() {
            result.extend_from_slice(&request_buf[body_start..]);
        }
    }

    Ok(result)
}

fn parse_host_port(uri: &str) -> Result<(String, u16)> {
    if let Some((host, port_str)) = uri.rsplit_once(':') {
        // Surface a malformed authority rather than silently defaulting, which
        // would mask a bad CONNECT target (e.g. "host:notaport").
        let port = port_str
            .parse()
            .with_context(|| format!("invalid port in authority: {uri}"))?;
        Ok((host.to_string(), port))
    } else {
        Ok((uri.to_string(), 443))
    }
}

fn check_basic_auth(encoded: &str, expected_user: &str, expected_pass: &str) -> bool {
    use base64::prelude::*;
    use subtle::ConstantTimeEq;

    let Ok(decoded) = BASE64_STANDARD.decode(encoded) else {
        return false;
    };
    // Compare the decoded `user:pass` bytes (not the base64 text) against the
    // expected credential in constant time, so a wrong guess can't be refined
    // byte-by-byte from response timing. The length difference is allowed to
    // short-circuit — only the credential's length, not its contents, leaks.
    let expected = format!("{expected_user}:{expected_pass}");
    decoded.ct_eq(expected.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use tokio::io::BufReader;

    #[tokio::test]
    async fn test_read_http_headers_complete() {
        let data = b"GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let mut reader = BufReader::new(Cursor::new(data.to_vec()));

        let headers = read_http_headers(&mut reader, 65536, 200).await.unwrap();
        let headers_str = String::from_utf8_lossy(&headers);

        assert!(headers_str.contains("GET /path HTTP/1.1"));
        assert!(headers_str.contains("Host: example.com"));
        assert!(headers_str.ends_with("\r\n\r\n"));
    }

    #[tokio::test]
    async fn test_read_http_headers_eof() {
        // Simulate client disconnect (EOF before complete headers)
        let data = b"GET /path HTTP/1.1\r\n";
        let mut reader = BufReader::new(Cursor::new(data.to_vec()));

        let headers = read_http_headers(&mut reader, 65536, 200).await.unwrap();
        // Should return partial data on EOF
        assert!(!headers.is_empty());
    }

    #[tokio::test]
    async fn test_read_http_headers_size_cap() {
        // A header block larger than the cap is rejected rather than buffered.
        let mut data = b"GET / HTTP/1.1\r\n".to_vec();
        for i in 0..1000 {
            data.extend_from_slice(format!("X-Pad-{i}: aaaaaaaaaaaaaaaaaaaa\r\n").as_bytes());
        }
        data.extend_from_slice(b"\r\n");
        let mut reader = BufReader::new(Cursor::new(data));

        let err = read_http_headers(&mut reader, 1024, 200).await.unwrap_err();
        assert!(err.to_string().contains("maximum size"));
    }

    #[tokio::test]
    async fn test_read_http_headers_count_cap() {
        // Many small header lines trip the count cap before the size cap.
        let mut data = b"GET / HTTP/1.1\r\n".to_vec();
        for i in 0..100 {
            data.extend_from_slice(format!("X-{i}: y\r\n").as_bytes());
        }
        data.extend_from_slice(b"\r\n");
        let mut reader = BufReader::new(Cursor::new(data));

        let err = read_http_headers(&mut reader, 1 << 20, 10)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("maximum count"));
    }

    #[tokio::test]
    async fn test_read_body_fixed_rejects_oversized() {
        // A claimed Content-Length above the cap is rejected up front — no
        // eager allocation of the claimed size.
        let mut reader = BufReader::new(Cursor::new(Vec::new()));
        let err = read_body_fixed(&mut reader, 10_000_000_000, 1024)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("exceeds maximum"));
    }

    #[tokio::test]
    async fn test_read_body_fixed_within_cap() {
        let data = b"hello world".to_vec();
        let len = data.len() as u64;
        let mut reader = BufReader::new(Cursor::new(data));
        let body = read_body_fixed(&mut reader, len, 1024).await.unwrap();
        assert_eq!(body, b"hello world");
    }

    #[tokio::test]
    async fn test_read_body_chunked_rejects_oversized() {
        // Two 8-byte chunks exceed a 10-byte cap.
        let data = b"8\r\nAAAAAAAA\r\n8\r\nBBBBBBBB\r\n0\r\n\r\n".to_vec();
        let mut reader = BufReader::new(Cursor::new(data));
        let err = read_body_chunked(&mut reader, 10).await.unwrap_err();
        assert!(err.to_string().contains("exceeds maximum"));
    }

    #[test]
    fn test_decompress_gzip_rejects_bomb() {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;

        // 1 MiB of zeros compresses tiny but decompresses past a small cap.
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&vec![0u8; 1024 * 1024]).unwrap();
        let compressed = encoder.finish().unwrap();

        let headers = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n";
        // Cap below the decompressed size -> rejected (returns None).
        assert!(decompress_gzip_if_needed(headers, &compressed, 4096).is_none());
        // Cap above the decompressed size -> decompresses fine.
        let out = decompress_gzip_if_needed(headers, &compressed, 8 * 1024 * 1024).unwrap();
        assert_eq!(out.len(), 1024 * 1024);
    }

    #[test]
    fn test_parse_content_length() {
        assert_eq!(parse_content_length("Content-Length: 123\r\n"), Some(123));
        assert_eq!(parse_content_length("content-length: 456\r\n"), Some(456));
        assert_eq!(parse_content_length("Host: example.com\r\n"), None);
    }

    #[test]
    fn test_is_chunked_encoding() {
        assert!(is_chunked_encoding("Transfer-Encoding: chunked\r\n"));
        assert!(is_chunked_encoding("transfer-encoding: chunked\r\n"));
        assert!(!is_chunked_encoding("Content-Length: 123\r\n"));
    }

    #[test]
    fn test_check_basic_auth() {
        // "alice:secret123" base64 encoded
        assert!(check_basic_auth(
            "YWxpY2U6c2VjcmV0MTIz",
            "alice",
            "secret123"
        ));
        // Wrong password
        assert!(!check_basic_auth("YWxpY2U6c2VjcmV0MTIz", "alice", "wrong"));
        // Wrong user
        assert!(!check_basic_auth(
            "YWxpY2U6c2VjcmV0MTIz",
            "bob",
            "secret123"
        ));
        // Correct prefix but truncated password (length differs)
        assert!(!check_basic_auth(
            "YWxpY2U6c2VjcmV0MTIz",
            "alice",
            "secret12"
        ));
        // Malformed base64
        assert!(!check_basic_auth("invalid-base64!!!", "alice", "secret"));
        // Password containing a colon: the full decoded `user:pass` must match,
        // so the split is on the credential as a whole, not the first colon.
        // "alice:sec:ret" base64 encoded
        assert!(check_basic_auth("YWxpY2U6c2VjOnJldA==", "alice", "sec:ret"));
    }

    #[test]
    fn test_classify_request_framing_simple() {
        assert_eq!(
            classify_request_framing("POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\n"),
            RequestFraming::Length(5)
        );
        assert_eq!(
            classify_request_framing("GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
            RequestFraming::Length(0)
        );
        assert_eq!(
            classify_request_framing("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"),
            RequestFraming::Chunked
        );
    }

    #[test]
    fn test_classify_request_framing_rejects_cl_and_te() {
        // The classic CL.TE / TE.CL smuggling vector.
        let headers = "POST / HTTP/1.1\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert_eq!(classify_request_framing(headers), RequestFraming::Invalid);
    }

    #[test]
    fn test_classify_request_framing_rejects_duplicate_cl() {
        // Conflicting duplicate Content-Length.
        let conflicting = "POST / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n";
        assert_eq!(
            classify_request_framing(conflicting),
            RequestFraming::Invalid
        );
        // Even identical duplicates are rejected — a well-formed client sends one.
        let identical = "POST / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n";
        assert_eq!(classify_request_framing(identical), RequestFraming::Invalid);
    }

    #[test]
    fn test_classify_request_framing_rejects_bad_cl() {
        // A comma-listed / unparseable Content-Length value.
        let headers = "POST / HTTP/1.1\r\nContent-Length: 5, 6\r\n\r\n";
        assert_eq!(classify_request_framing(headers), RequestFraming::Invalid);
        // A non-chunked transfer-coding we can't reframe.
        let te = "POST / HTTP/1.1\r\nTransfer-Encoding: gzip\r\n\r\n";
        assert_eq!(classify_request_framing(te), RequestFraming::Invalid);
    }

    #[test]
    fn test_is_hop_by_hop() {
        for h in [
            "connection",
            "keep-alive",
            "transfer-encoding",
            "te",
            "trailer",
            "upgrade",
            "proxy-authorization",
            "proxy-connection",
        ] {
            assert!(is_hop_by_hop(h), "{h} should be hop-by-hop");
        }
        assert!(!is_hop_by_hop("content-type"));
        assert!(!is_hop_by_hop("authorization"));
        assert!(!is_hop_by_hop("host"));
    }

    #[test]
    fn test_sanitize_request_headers_strips_hop_by_hop() {
        let headers = b"POST /x HTTP/1.1\r\n\
            Host: example.com\r\n\
            Connection: keep-alive, x-custom\r\n\
            Keep-Alive: timeout=5\r\n\
            Transfer-Encoding: chunked\r\n\
            Proxy-Authorization: Basic abc\r\n\
            X-Custom: secret\r\n\
            Content-Length: 999\r\n\
            Content-Type: application/json\r\n\
            \r\n";
        let out = sanitize_request_headers(headers, 11);
        let out = String::from_utf8(out).unwrap();

        // Request line and end-to-end headers survive.
        assert!(out.starts_with("POST /x HTTP/1.1\r\n"));
        assert!(out.contains("Host: example.com\r\n"));
        assert!(out.contains("Content-Type: application/json\r\n"));

        // Hop-by-hop headers are gone.
        assert!(!out.to_lowercase().contains("connection:"));
        assert!(!out.to_lowercase().contains("keep-alive:"));
        assert!(!out.to_lowercase().contains("transfer-encoding:"));
        assert!(!out.to_lowercase().contains("proxy-authorization:"));
        // The header named in Connection is also dropped.
        assert!(!out.contains("X-Custom: secret"));

        // alice sets a single Content-Length matching the forwarded body.
        assert_eq!(out.matches("Content-Length:").count(), 1);
        assert!(out.contains("Content-Length: 11\r\n"));
        assert!(out.ends_with("\r\n\r\n"));
    }

    #[test]
    fn test_sanitize_request_headers_no_body_omits_content_length() {
        let headers = b"GET / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n";
        let out = String::from_utf8(sanitize_request_headers(headers, 0)).unwrap();
        assert!(!out.to_lowercase().contains("content-length:"));
        assert!(out.contains("Host: example.com\r\n"));
    }

    #[test]
    fn test_parse_host_port() {
        // With explicit port
        assert_eq!(
            parse_host_port("example.com:8443").unwrap(),
            ("example.com".to_string(), 8443)
        );
        // Without port - defaults to 443
        assert_eq!(
            parse_host_port("example.com").unwrap(),
            ("example.com".to_string(), 443)
        );
        // Standard HTTPS port
        assert_eq!(
            parse_host_port("api.github.com:443").unwrap(),
            ("api.github.com".to_string(), 443)
        );
        // Malformed port is surfaced as an error, not silently defaulted
        assert!(parse_host_port("example.com:notaport").is_err());
    }
}
