//! HTTP/2 proxy handler with request inspection for path-based policy.

use crate::config::Action;
use crate::proxy::llm;
use crate::proxy::request::{self, RequestOutcome};
use crate::proxy::transform::TransformResult;
use crate::proxy::ProxyState;
use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use h2::server::SendResponse;
use h2::{Reason, RecvStream};
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
    // Perform HTTP/2 handshakes
    let mut client_conn = h2::server::handshake(client_tls)
        .await
        .context("HTTP/2 server handshake failed")?;

    let (upstream_send, upstream_conn) = h2::client::handshake(upstream_tls)
        .await
        .context("HTTP/2 client handshake failed")?;

    // Spawn task to drive the upstream connection
    let upstream_handle = tokio::spawn(async move {
        if let Err(e) = upstream_conn.await {
            debug!(error = %e, "upstream HTTP/2 connection ended");
        }
    });

    // Process incoming streams from client
    while let Some(result) = client_conn.accept().await {
        let (request, respond) = result.context("failed to accept client stream")?;

        let host = host.clone();
        let state = Arc::clone(&state);
        let upstream_send = upstream_send.clone();
        let resolved_ips = resolved_ips.clone();
        let client_addr = client_addr.clone();

        tokio::spawn(
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

    // Client connection closed, clean up
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
    // Perform HTTP/2 handshake with client
    let mut client_conn = h2::server::handshake(client_tls)
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

        tokio::spawn(
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
        );
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
        respond.send_reset(Reason::REFUSED_STREAM);
        return Ok(());
    }

    request_span.record("alice.policy.action", "allow");
    request_span.record("alice.policy.rule_index", decision.rule_index as i64);
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

    // Run transform pipeline on /v1/messages requests
    if let Some(TransformResult::Block { .. }) =
        request::apply_transforms(&state.transform_pipeline, &host, &path, &mut body_bytes)
    {
        respond.send_reset(Reason::REFUSED_STREAM);
        return Ok(());
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

    // Copy headers (skip pseudo-headers which start with :)
    for (name, value) in parts.headers.iter() {
        let name_str = name.as_str();
        if !name_str.starts_with(':') {
            request_text.push_str(&format!(
                "{}: {}\r\n",
                name_str,
                value.to_str().unwrap_or("")
            ));
        }
    }

    // Add Content-Length if we have a body
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
    reader
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

    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await?;
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
            }
            response_headers.push((name, value.to_string()));
        }
    }

    // Read response body
    let response_body = if chunked {
        read_chunked_body(&mut reader).await?
    } else if let Some(len) = content_length {
        let mut buf = vec![0u8; len];
        reader.read_exact(&mut buf).await?;
        buf
    } else {
        // No body or connection: close semantics
        Vec::new()
    };

    // Release upstream lock
    drop(reader);
    drop(upstream_guard);

    // Redact OAuth tokens if this path is configured for redaction
    let response_body = if decision.redact_tokens {
        if let Some(redacted_body) = state
            .credentials
            .redact_oauth_response(&host, &response_body)
        {
            redacted_body
        } else {
            response_body
        }
    } else {
        response_body
    };

    // Build H2 response
    let mut response_builder = http::Response::builder().status(status_code);
    for (name, value) in &response_headers {
        // Skip hop-by-hop headers
        if !matches!(
            name.as_str(),
            "connection" | "keep-alive" | "transfer-encoding" | "upgrade"
        ) {
            response_builder = response_builder.header(name.as_str(), value.as_str());
        }
    }
    let h2_response = response_builder
        .body(())
        .context("failed to build H2 response")?;

    // Format response headers for logging
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

    // Send response to client
    let end_stream = response_body.is_empty();
    let mut send_body = respond
        .send_response(h2_response, end_stream)
        .context("failed to send H2 response")?;

    if !end_stream {
        send_body
            .send_data(Bytes::from(response_body.clone()), true)
            .context("failed to send H2 response body")?;
    }

    // Record span, metrics, and log the exchange
    let outcome = RequestOutcome {
        host: &host,
        method: method.as_str(),
        path: &path,
        status_code,
        action: "allow",
        rule_index: decision.rule_index,
        request_bytes: request_text.len() + body_bytes.len(),
        response_bytes: response_headers_raw.len() + response_body.len(),
        start: request_start,
        client_addr: &client_addr,
        request_headers: &request_headers_raw,
        request_body: &body_bytes,
        response_headers: &response_headers_raw,
        response_body: &response_body,
    };
    outcome.record_span(&request_span);
    outcome.record_metrics(&state.metrics);
    outcome.log_exchange(&state.log_dir).await;

    Ok(())
}

/// Read a chunked HTTP/1.1 body
async fn read_chunked_body<R: AsyncBufReadExt + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    let mut body = Vec::new();

    loop {
        let mut size_line = String::new();
        reader.read_line(&mut size_line).await?;
        let size_str = size_line.trim();
        let chunk_size = usize::from_str_radix(size_str, 16).context("invalid chunk size")?;

        if chunk_size == 0 {
            // Read trailing CRLF
            let mut trailing = String::new();
            reader.read_line(&mut trailing).await?;
            break;
        }

        let mut chunk = vec![0u8; chunk_size];
        reader.read_exact(&mut chunk).await?;
        body.extend_from_slice(&chunk);

        // Read chunk-ending CRLF
        let mut crlf = [0u8; 2];
        reader.read_exact(&mut crlf).await?;
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
        respond.send_reset(Reason::REFUSED_STREAM);
        return Ok(());
    }

    request_span.record("alice.policy.action", "allow");
    request_span.record("alice.policy.rule_index", decision.rule_index as i64);
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

    // Check if we need to buffer the request body for transform pipeline or GCP re-signing
    let needs_gcp_resign = state.gcp_credentials.is_gcp_token_request(&host, &path);
    let needs_body_transform = (!state.transform_pipeline.is_empty()
        && llm::is_messages_endpoint(&path)
        && !body.is_end_stream())
        || needs_gcp_resign;

    // Build the request to send upstream (without body)
    let upstream_request = http::Request::from_parts(parts, ());

    let body_is_end = body.is_end_stream();

    // Ready the upstream connection for a new request
    let mut upstream_send = upstream_send
        .ready()
        .await
        .context("upstream not ready for request")?;

    // Send request and body to upstream, returning (response_future, captured_body)
    let (upstream_response, request_body_buf) = if needs_body_transform {
        // Buffer the entire body, run transforms, then send
        let mut buf = Vec::new();
        while let Some(chunk) = body.data().await {
            let data = chunk.context("error reading client body")?;
            buf.extend_from_slice(&data);
            body.flow_control()
                .release_capacity(data.len())
                .context("failed to release client flow control")?;
        }

        // Run transform pipeline
        if let Some(TransformResult::Block { .. }) =
            request::apply_transforms(&state.transform_pipeline, &host, &path, &mut buf)
        {
            respond.send_reset(Reason::REFUSED_STREAM);
            return Ok(());
        }

        // GCP JWT re-signing: intercept token exchange POST bodies
        if needs_gcp_resign {
            if let Some(new_body) = state.gcp_credentials.resign_token_request(&buf) {
                buf = new_body;
            }
        }

        // Send headers, then the modified body as a single data frame
        let end_stream = buf.is_empty();
        let (response_fut, mut send_body) = upstream_send
            .send_request(upstream_request, end_stream)
            .context("failed to send request to upstream")?;

        if !buf.is_empty() {
            send_body
                .send_data(Bytes::from(buf.clone()), true)
                .context("failed to send modified body to upstream")?;
        }

        (
            response_fut
                .await
                .context("failed to receive upstream response")?,
            buf,
        )
    } else {
        // Stream body through without buffering
        let (response_fut, mut send_body) = upstream_send
            .send_request(upstream_request, body_is_end)
            .context("failed to send request to upstream")?;

        let mut body_buf = Vec::new();
        if !body_is_end {
            while let Some(chunk) = body.data().await {
                let data = chunk.context("error reading client body")?;
                body_buf.extend_from_slice(&data);
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
        )
    };

    let (response_parts, mut upstream_body) = upstream_response.into_parts();
    let response_status = response_parts.status.as_u16();

    // Capture response headers for logging
    let response_headers_raw = format_h2_headers_for_log(&response_parts.headers);

    // Check if this is an LLM SSE stream before consuming response_parts
    let is_llm_sse =
        llm::is_messages_endpoint(&path) && llm::is_sse_header_map(&response_parts.headers);

    // Build response to send to client
    let client_response = http::Response::from_parts(response_parts, ());

    let upstream_body_is_end = upstream_body.is_end_stream();

    // Handle response body - buffer for redaction, stream otherwise
    let response_body_buf = if decision.redact_tokens {
        // Token redaction requires buffering the entire body to modify JSON
        let mut response_body_buf = Vec::new();
        if !upstream_body_is_end {
            while let Some(chunk) = upstream_body.data().await {
                let data = chunk.context("error reading upstream body")?;
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

        response_body_buf
    } else {
        // Stream response through without buffering (for SSE, large responses, etc.)
        // Send response headers immediately
        let mut client_send_body = respond
            .send_response(client_response, upstream_body_is_end)
            .context("failed to send response to client")?;

        // Create LLM metrics accumulator if this is a streaming messages response
        let mut llm_acc = if is_llm_sse {
            Some(llm::StreamingMetricsAccumulator::new())
        } else {
            None
        };

        // Stream body chunks, capturing for logging
        let mut response_body_buf = Vec::new();
        if !upstream_body_is_end {
            while let Some(chunk) = upstream_body.data().await {
                let data = chunk.context("error reading upstream body")?;
                // Capture for logging
                response_body_buf.extend_from_slice(&data);
                // Feed to LLM metrics accumulator
                if let Some(ref mut acc) = llm_acc {
                    acc.process_chunk(&data);
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

        // Emit LLM metrics after stream completes
        if let Some(acc) = llm_acc {
            acc.emit(&host, &path, Some(&state.llm_metrics));
        }

        response_body_buf
    };

    // Record span, metrics, and log the exchange
    let outcome = RequestOutcome {
        host: &host,
        method: method.as_str(),
        path: &path,
        status_code: response_status,
        action: "allow",
        rule_index: decision.rule_index,
        request_bytes: request_headers_raw.len() + request_body_buf.len(),
        response_bytes: response_headers_raw.len() + response_body_buf.len(),
        start: request_start,
        client_addr: &client_addr,
        request_headers: &request_headers_raw,
        request_body: &request_body_buf,
        response_headers: &response_headers_raw,
        response_body: &response_body_buf,
    };
    outcome.record_span(&request_span);
    outcome.record_metrics(&state.metrics);
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
            .with_label_values(&[&replacement.credential_name, host])
            .inc();
        headers.insert(name, replacement.value);
    }
}
