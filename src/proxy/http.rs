use crate::config::Action;
use crate::proxy::llm;
use crate::proxy::request::{self, RequestOutcome};
use crate::proxy::tls::{self, NegotiatedProtocol};
use crate::proxy::transform::TransformResult;
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
    reader.read_line(&mut request_line).await?;

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
        reader.read_line(&mut line).await?;
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
        // Use first resolved IP (CIDR rules already checked it's allowed)
        let ip = ips.first().ok_or_else(|| anyhow!("no resolved IPs"))?;
        let addr = SocketAddr::new(*ip, port);
        TcpStream::connect(addr)
            .await
            .with_context(|| format!("failed to connect to {} ({})", host, addr))?
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
            // token redaction is configured, logging enabled, or transforms are configured
            let needs_inspection = decision.needs_path_check
                || decision.has_redact_paths
                || state.credentials.has_credentials_for_host(&host)
                || state.log_dir.is_some()
                || !state.transform_pipeline.is_empty();

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
        let mut buf = vec![0u8; 8192];
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
        let mut buf = vec![0u8; 8192];
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

    tokio::try_join!(client_to_upstream, upstream_to_client)?;
    Ok(())
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

    // Process requests in a loop (HTTP/1.1 keep-alive)
    loop {
        let request_start = Instant::now();

        // Read request headers from client with idle timeout
        let request_headers =
            match tokio::time::timeout(idle_timeout, read_http_headers(&mut client_reader)).await {
                Ok(Ok(headers)) => headers,
                Ok(Err(_)) => {
                    // Client disconnected or sent invalid data - connection done
                    break;
                }
                Err(_) => {
                    // Idle timeout - close connection
                    debug!("connection idle timeout");
                    break;
                }
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

        // Parse headers for body handling and connection state
        let content_length = parse_content_length(&request_str);
        let is_chunked = is_chunked_encoding(&request_str);
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
        request_span.record("alice.policy.action", "allow");
        request_span.record("alice.policy.rule_index", decision.rule_index as i64);
        info!(host = %host, path = %path, method = %method, rule = decision.rule_index, "allowed");

        // Inject credentials if needed
        let request_headers = if state.credentials.has_credentials_for_host(&host) {
            inject_credentials_h1(&request_headers, &host, &state)?
        } else {
            request_headers
        };

        // Always buffer request body (needed for logging and credential inspection)
        let request_body = if let Some(len) = content_length {
            read_body_fixed(&mut client_reader, len).await?
        } else if is_chunked {
            read_body_chunked(&mut client_reader).await?
        } else {
            Vec::new()
        };

        // Run transform pipeline on /v1/messages requests
        let (request_headers, request_body) = {
            let mut body = request_body;
            let original_len = body.len();
            match request::apply_transforms(&state.transform_pipeline, &host, &path, &mut body) {
                Some(TransformResult::Block { status, message }) => {
                    let response = format!(
                        "HTTP/1.1 {} Blocked\r\nContent-Length: {}\r\n\r\n{}",
                        status,
                        message.len(),
                        message
                    );
                    client_write.write_all(response.as_bytes()).await?;
                    client_write.flush().await?;
                    if client_wants_close {
                        break;
                    }
                    continue;
                }
                Some(TransformResult::Continue) if body.len() != original_len => {
                    (rewrite_content_length(&request_headers, body.len()), body)
                }
                _ => (request_headers, body),
            }
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

        // Forward request headers to upstream
        upstream_write.write_all(&request_headers).await?;

        // Forward request body
        upstream_write.write_all(&request_body).await?;
        upstream_write.flush().await?;

        // Read response headers from upstream
        let response_headers = read_http_headers(&mut upstream_reader).await?;
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
        let (response_headers, response_body) = if needs_body_buffer {
            // Token redaction requires buffering the entire body to modify JSON
            let response_body = if let Some(len) = resp_content_length {
                read_body_fixed(&mut upstream_reader, len).await?
            } else if resp_is_chunked {
                read_body_chunked(&mut upstream_reader).await?
            } else {
                Vec::new()
            };

            // Decompress gzip if needed for JSON parsing
            let decompressed = decompress_gzip_if_needed(&response_headers, &response_body);
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

            (headers, body)
        } else {
            // Stream response through without buffering (for SSE, large responses, etc.)
            // Forward headers immediately
            client_write.write_all(&response_headers).await?;
            client_write.flush().await?;

            // Create LLM metrics accumulator for /v1/messages SSE responses
            let is_llm_sse = llm::is_messages_endpoint(&path)
                && llm::is_sse_response(&String::from_utf8_lossy(&response_headers));
            let mut llm_acc = llm::StreamingMetricsAccumulator::new();

            // Stream body, capturing for logging if enabled
            let mut observer_fn = |chunk: &[u8]| llm_acc.process_chunk(chunk);
            let response_body = if let Some(len) = resp_content_length {
                stream_body_fixed(&mut upstream_reader, &mut client_write, len).await?
            } else if resp_is_chunked {
                stream_body_chunked(
                    &mut upstream_reader,
                    &mut client_write,
                    if is_llm_sse {
                        Some(&mut observer_fn as &mut (dyn FnMut(&[u8]) + Send))
                    } else {
                        None
                    },
                )
                .await?
            } else {
                Vec::new()
            };

            // Emit LLM metrics if we were tracking this stream
            if is_llm_sse {
                llm_acc.emit(&host, &path, Some(&state.llm_metrics));
            }

            (response_headers.clone(), response_body)
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
            response_bytes: response_headers.len() + response_body.len(),
            start: request_start,
            client_addr: &client_addr,
            request_headers: &request_headers,
            request_body: &request_body,
            response_headers: &response_headers,
            response_body: &response_body,
        };
        outcome.record_span(&request_span);
        outcome.record_metrics(&state.metrics);
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
async fn read_http_headers<R: AsyncBufReadExt + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    let mut headers = Vec::new();

    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            // EOF before headers complete
            return Ok(headers);
        }

        headers.extend_from_slice(line.as_bytes());

        // Empty line (just \r\n) marks end of headers
        if line == "\r\n" || line == "\n" {
            break;
        }
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
        reader.read_line(&mut size_line).await?;

        let size_str = size_line.trim();
        let size_hex = size_str.split(';').next().unwrap_or(size_str);
        let chunk_size = usize::from_str_radix(size_hex, 16)
            .with_context(|| format!("invalid chunk size: {}", size_line.trim()))?;

        if chunk_size == 0 {
            // Read trailing CRLF
            loop {
                let mut trailer_line = String::new();
                reader.read_line(&mut trailer_line).await?;
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
        reader.read_exact(&mut crlf).await?;
    }

    Ok(())
}

/// Read a fixed-length body into a buffer (for logging)
async fn read_body_fixed<R: AsyncReadExt + Unpin>(reader: &mut R, length: u64) -> Result<Vec<u8>> {
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

/// Read a chunked body into a buffer (for logging)
/// Returns the decoded body content (without chunk framing)
async fn read_body_chunked<R: AsyncBufReadExt + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    let mut body = Vec::new();

    loop {
        // Read chunk size line
        let mut size_line = String::new();
        reader.read_line(&mut size_line).await?;

        let size_str = size_line.trim();
        let size_hex = size_str.split(';').next().unwrap_or(size_str);
        let chunk_size = usize::from_str_radix(size_hex, 16)
            .with_context(|| format!("invalid chunk size: {}", size_line.trim()))?;

        if chunk_size == 0 {
            // Terminal chunk - read trailing headers/CRLF
            loop {
                let mut trailer_line = String::new();
                reader.read_line(&mut trailer_line).await?;
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
        reader.read_exact(&mut crlf).await?;
    }

    Ok(body)
}

/// Stream a fixed-length body from reader to writer, flushing after each chunk.
/// Returns the captured body for logging.
async fn stream_body_fixed<R, W>(reader: &mut R, writer: &mut W, length: u64) -> Result<Vec<u8>>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    let mut body = Vec::with_capacity(length as usize);
    let mut remaining = length;
    let mut buf = [0u8; 8192];

    while remaining > 0 {
        let to_read = std::cmp::min(remaining as usize, buf.len());
        let n = reader.read(&mut buf[..to_read]).await?;
        if n == 0 {
            return Err(anyhow!("unexpected EOF reading body"));
        }
        // Capture for logging
        body.extend_from_slice(&buf[..n]);
        // Forward to client immediately
        writer.write_all(&buf[..n]).await?;
        writer.flush().await?;
        remaining -= n as u64;
    }

    Ok(body)
}

/// Stream a chunked body from reader to writer, flushing after each chunk.
/// Returns the captured decoded body content (without chunk framing).
/// If `observer` is provided, each decoded chunk is also fed to it (for incremental SSE parsing).
#[allow(clippy::type_complexity)]
async fn stream_body_chunked<R, W>(
    reader: &mut R,
    writer: &mut W,
    mut observer: Option<&mut (dyn FnMut(&[u8]) + Send)>,
) -> Result<Vec<u8>>
where
    R: AsyncBufReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    let mut body = Vec::new();

    loop {
        // Read chunk size line
        let mut size_line = String::new();
        reader.read_line(&mut size_line).await?;

        let size_str = size_line.trim();
        let size_hex = size_str.split(';').next().unwrap_or(size_str);
        let chunk_size = usize::from_str_radix(size_hex, 16)
            .with_context(|| format!("invalid chunk size: {}", size_line.trim()))?;

        // Forward chunk size line to client
        writer.write_all(size_line.as_bytes()).await?;

        if chunk_size == 0 {
            // Terminal chunk - read and forward trailing headers/CRLF
            loop {
                let mut trailer_line = String::new();
                reader.read_line(&mut trailer_line).await?;
                writer.write_all(trailer_line.as_bytes()).await?;
                if trailer_line == "\r\n" || trailer_line == "\n" {
                    break;
                }
            }
            writer.flush().await?;
            break;
        }

        // Read and forward chunk data
        let mut remaining = chunk_size;
        let mut buf = [0u8; 8192];
        while remaining > 0 {
            let to_read = std::cmp::min(remaining, buf.len());
            let n = reader.read(&mut buf[..to_read]).await?;
            if n == 0 {
                return Err(anyhow!("unexpected EOF in chunk"));
            }
            // Capture decoded body for logging
            body.extend_from_slice(&buf[..n]);
            // Feed to observer (e.g., LLM metrics accumulator)
            if let Some(ref mut obs) = observer {
                obs(&buf[..n]);
            }
            // Forward to client
            writer.write_all(&buf[..n]).await?;
            remaining -= n;
        }

        // Read and forward chunk-ending CRLF
        let mut crlf = [0u8; 2];
        reader.read_exact(&mut crlf).await?;
        writer.write_all(&crlf).await?;

        // Flush after each chunk to ensure SSE events reach client immediately
        writer.flush().await?;
    }

    Ok(body)
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
fn decompress_gzip_if_needed(headers: &[u8], body: &[u8]) -> Option<Vec<u8>> {
    let headers_str = String::from_utf8_lossy(headers);
    let is_gzip = headers_str
        .lines()
        .any(|l| l.to_lowercase().starts_with("content-encoding:") && l.contains("gzip"));

    if !is_gzip || body.is_empty() {
        return None;
    }

    use flate2::read::GzDecoder;
    use std::io::Read;

    let mut decoder = GzDecoder::new(body);
    let mut decompressed = Vec::new();
    match decoder.read_to_end(&mut decompressed) {
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
        let port = port_str.parse().unwrap_or(443);
        Ok((host.to_string(), port))
    } else {
        Ok((uri.to_string(), 443))
    }
}

fn check_basic_auth(encoded: &str, expected_user: &str, expected_pass: &str) -> bool {
    use base64::prelude::*;
    if let Ok(decoded) = BASE64_STANDARD.decode(encoded) {
        if let Ok(creds) = String::from_utf8(decoded) {
            if let Some((user, pass)) = creds.split_once(':') {
                return user == expected_user && pass == expected_pass;
            }
        }
    }
    false
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

        let headers = read_http_headers(&mut reader).await.unwrap();
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

        let headers = read_http_headers(&mut reader).await.unwrap();
        // Should return partial data on EOF
        assert!(!headers.is_empty());
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
        assert!(!check_basic_auth("YWxpY2U6c2VjcmV0MTIz", "alice", "wrong"));
        assert!(!check_basic_auth("invalid-base64!!!", "alice", "secret"));
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
    }
}
