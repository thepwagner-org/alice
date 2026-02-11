//! Shared test infrastructure for integration tests and benchmarks.

use std::net::SocketAddr;
use std::sync::{Arc, Once};
use std::time::Duration;

use axum::{
    body::Body,
    extract::Path,
    http::{Request, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use rcgen::{
    CertificateParams, DnType, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tempfile::TempDir;
use tokio::net::TcpListener;

// Install the rustls ring crypto provider once for all tests.
static INIT_CRYPTO: Once = Once::new();

pub fn init_crypto_provider() {
    INIT_CRYPTO.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

// ============================================================================
// Certificate Generation
// ============================================================================

/// Generate a self-signed certificate for the mock HTTPS server.
/// Includes SANs for localhost and common test hostnames.
pub fn generate_server_cert(host: &str) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let key = KeyPair::generate().expect("generate keypair");

    let mut params = CertificateParams::default();
    params.distinguished_name.push(DnType::CommonName, host);
    params.subject_alt_names = vec![
        SanType::DnsName(host.try_into().unwrap()),
        SanType::DnsName("localhost".try_into().unwrap()),
        // Test hostnames for CIDR/DNS tests
        SanType::DnsName("allowed-internal.test".try_into().unwrap()),
        SanType::DnsName("evil.test".try_into().unwrap()),
        SanType::DnsName("rebind.test".try_into().unwrap()),
        SanType::DnsName("internal-10.test".try_into().unwrap()),
        SanType::DnsName("internal-172.test".try_into().unwrap()),
        SanType::DnsName("internal-192.test".try_into().unwrap()),
    ];
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

    let cert = params.self_signed(&key).expect("self-signed cert");
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));

    (cert_der, key_der)
}

// ============================================================================
// Mock HTTPS Server
// ============================================================================

/// Spawn a mock HTTPS server on the given port, returns the server's self-signed cert (PEM)
pub async fn spawn_https_server(port: u16) -> (String, tokio::task::JoinHandle<()>) {
    spawn_https_server_with_app(port, default_router(), true).await
}

/// Spawn a mock HTTPS server with a custom router
pub async fn spawn_https_server_with_app(
    port: u16,
    app: Router,
    enable_h2: bool,
) -> (String, tokio::task::JoinHandle<()>) {
    init_crypto_provider();
    let addr = SocketAddr::from(([127, 0, 0, 1], port));

    let (cert_der, key_der) = generate_server_cert("localhost");

    let mut tls_config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("protocol versions")
    .with_no_client_auth()
    .with_single_cert(vec![cert_der.clone()], key_der)
    .expect("tls config");

    if enable_h2 {
        tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    } else {
        tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    }

    let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));
    let cert_pem = pem::encode(&pem::Pem::new("CERTIFICATE", cert_der.as_ref()));

    let listener = TcpListener::bind(addr).await.expect("bind listener");
    let handle = tokio::spawn(async move {
        loop {
            let Ok((stream, _addr)) = listener.accept().await else {
                continue;
            };

            let tls_acceptor = tls_acceptor.clone();
            let app = app.clone();

            tokio::spawn(async move {
                let Ok(tls_stream) = tls_acceptor.accept(stream).await else {
                    return;
                };

                let io = hyper_util::rt::TokioIo::new(tls_stream);
                let service =
                    hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
                        let app = app.clone();
                        async move {
                            use tower::ServiceExt;
                            let (parts, body) = req.into_parts();
                            let body = Body::new(body);
                            let req = Request::from_parts(parts, body);
                            app.oneshot(req).await
                        }
                    });

                let builder = hyper_util::server::conn::auto::Builder::new(
                    hyper_util::rt::TokioExecutor::new(),
                );

                if enable_h2 {
                    let _ = builder.serve_connection(io, service).await;
                } else {
                    let _ = builder.http1_only().serve_connection(io, service).await;
                }
            });
        }
    });

    // Wait for server to be ready
    tokio::time::sleep(Duration::from_millis(50)).await;

    (cert_pem, handle)
}

fn default_router() -> Router {
    Router::new()
        .route("/get", get(handle_get))
        .route("/post", post(handle_post))
        .route("/status/{code}", get(handle_status))
        .route("/headers", get(handle_headers))
        .route("/oauth/token", post(handle_oauth_token))
        .route("/sse", get(handle_sse))
}

/// Handler for GET /get
async fn handle_get() -> impl IntoResponse {
    (StatusCode::OK, "GET response")
}

/// Handler for POST /post
async fn handle_post() -> impl IntoResponse {
    (StatusCode::OK, "POST response")
}

/// Handler for GET /status/{code}
async fn handle_status(Path(code): Path<u16>) -> impl IntoResponse {
    StatusCode::from_u16(code).unwrap_or(StatusCode::BAD_REQUEST)
}

/// Handler for GET /headers
async fn handle_headers(req: Request<Body>) -> impl IntoResponse {
    let headers: Vec<String> = req
        .headers()
        .iter()
        .map(|(k, v)| format!("{}: {}", k, v.to_str().unwrap_or("?")))
        .collect();
    (StatusCode::OK, headers.join("\n"))
}

/// Handler for POST /oauth/token - returns a mock OAuth token response
async fn handle_oauth_token() -> impl IntoResponse {
    let response = serde_json::json!({
        "access_token": "real_access_token_abc123",
        "refresh_token": "real_refresh_token_xyz789",
        "id_token": "real_id_token_jwt.payload.signature",
        "token_type": "Bearer",
        "expires_in": 3600
    });
    (
        StatusCode::OK,
        [("content-type", "application/json")],
        response.to_string(),
    )
}

/// Handler for GET /sse - sends Server-Sent Events with delays between them
async fn handle_sse() -> impl IntoResponse {
    use axum::body::Body;
    use tokio::sync::mpsc;
    use tokio_stream::wrappers::ReceiverStream;

    let (tx, rx) = mpsc::channel::<Result<String, std::io::Error>>(10);

    tokio::spawn(async move {
        for i in 1..=5 {
            let event = format!("data: event {}\n\n", i);
            if tx.send(Ok(event)).await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    });

    let stream = ReceiverStream::new(rx);
    let body = Body::from_stream(stream);

    (
        StatusCode::OK,
        [
            ("content-type", "text/event-stream"),
            ("cache-control", "no-cache"),
        ],
        body,
    )
}

// ============================================================================
// Proxy Configuration
// ============================================================================

/// Configuration for spawning the proxy.
///
/// Use struct update syntax with `Default` for concise test setup:
/// ```ignore
/// ProxyConfig {
///     listen_port: port,
///     rules: vec![RuleSpec::host("allow", "localhost")],
///     upstream_ca_pem: Some(cert),
///     ..Default::default()
/// }
/// ```
pub struct ProxyConfig {
    pub listen_port: u16,
    pub rules: Vec<RuleSpec>,
    pub auth: Option<(String, String)>,
    pub upstream_ca_pem: Option<String>,
    /// Raw TOML snippets for [[credentials]] sections
    pub credentials_toml: Vec<String>,
    /// DNS host overrides (like /etc/hosts)
    pub dns_hosts: Vec<(&'static str, &'static str)>,
    /// Optional metrics endpoint port (plain HTTP)
    pub metrics_port: Option<u16>,
    /// Raw TOML snippets for [[transforms]] sections
    pub transforms_toml: Vec<String>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen_port: 0,
            rules: Vec::new(),
            auth: None,
            upstream_ca_pem: None,
            credentials_toml: Vec::new(),
            dns_hosts: Vec::new(),
            metrics_port: None,
            transforms_toml: Vec::new(),
        }
    }
}

pub struct RuleSpec {
    pub action: &'static str,
    pub host: Option<&'static str>,
    pub cidr: Option<&'static str>,
    pub path: Option<&'static str>,
    pub redact_paths: Vec<&'static str>,
}

impl RuleSpec {
    /// Create a host-based rule
    pub fn host(action: &'static str, host: &'static str) -> Self {
        Self {
            action,
            host: Some(host),
            cidr: None,
            path: None,
            redact_paths: Vec::new(),
        }
    }

    /// Create a host-based rule with token redaction paths
    pub fn host_with_redact(
        action: &'static str,
        host: &'static str,
        redact_paths: Vec<&'static str>,
    ) -> Self {
        Self {
            action,
            host: Some(host),
            cidr: None,
            path: None,
            redact_paths,
        }
    }
}

// ============================================================================
// Proxy Spawning
// ============================================================================

/// Spawn the alice proxy with the given configuration
pub async fn spawn_proxy(config: ProxyConfig, temp_dir: &TempDir) -> tokio::task::JoinHandle<()> {
    let ca_cert_path = temp_dir.path().join("ca.pem");
    let upstream_ca_path = temp_dir.path().join("upstream-ca.pem");
    let config_path = temp_dir.path().join("config.toml");

    // Write upstream CA if provided
    if let Some(upstream_ca_pem) = &config.upstream_ca_pem {
        std::fs::write(&upstream_ca_path, upstream_ca_pem).expect("write upstream CA");
    }

    // Build TOML config
    let mut toml = format!(
        r#"[proxy]
listen = "127.0.0.1:{}"
"#,
        config.listen_port
    );

    if let Some((user, _pass)) = &config.auth {
        toml.push_str(&format!(
            r#"username = "{}"
password_env = "ALICE_TEST_PASSWORD"
"#,
            user
        ));
    }

    if config.upstream_ca_pem.is_some() {
        toml.push_str(&format!(
            "upstream_ca = \"{}\"\n",
            upstream_ca_path.display()
        ));
    }

    toml.push_str(&format!(
        r#"
[ca]
cert_path = "{}"
validity_hours = 1
host_cert_validity_hours = 1
"#,
        ca_cert_path.display()
    ));

    for rule in &config.rules {
        toml.push_str("\n[[rules]]\n");
        toml.push_str(&format!("action = \"{}\"\n", rule.action));
        if let Some(host) = rule.host {
            toml.push_str(&format!("host = \"{}\"\n", host));
        }
        if let Some(cidr) = rule.cidr {
            toml.push_str(&format!("cidr = \"{}\"\n", cidr));
        }
        if let Some(path) = rule.path {
            toml.push_str(&format!("path = \"{}\"\n", path));
        }
        if !rule.redact_paths.is_empty() {
            let paths: Vec<String> = rule
                .redact_paths
                .iter()
                .map(|p| format!("\"{}\"", p))
                .collect();
            toml.push_str(&format!("redact_paths = [{}]\n", paths.join(", ")));
        }
    }

    // Append raw credentials TOML
    for cred_toml in &config.credentials_toml {
        toml.push_str(cred_toml);
    }

    // Write DNS host overrides if any
    if !config.dns_hosts.is_empty() {
        toml.push_str("\n[dns.hosts]\n");
        for (host, ip) in &config.dns_hosts {
            toml.push_str(&format!("\"{}\" = [\"{}\"]\n", host, ip));
        }
    }

    // Write observability config if metrics port is set
    if let Some(port) = config.metrics_port {
        toml.push_str(&format!(
            "\n[observability]\nmetrics_listen = \"127.0.0.1:{}\"\n",
            port
        ));
    }

    // Append raw transforms TOML
    for transform_toml in &config.transforms_toml {
        toml.push_str(transform_toml);
    }

    std::fs::write(&config_path, &toml).expect("write config");

    // Set password env var if auth configured
    if let Some((_user, pass)) = &config.auth {
        std::env::set_var("ALICE_TEST_PASSWORD", pass);
    }

    let handle = tokio::spawn(async move {
        let status = tokio::process::Command::new(env!("CARGO_BIN_EXE_alice"))
            .arg("-c")
            .arg(&config_path)
            .kill_on_drop(true)
            .status()
            .await;
        // Proxy ran until killed
        let _ = status;
    });

    // Wait for proxy to start and write CA cert
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        if ca_cert_path.exists() {
            // Also wait a bit more for the listener to be ready
            tokio::time::sleep(Duration::from_millis(50)).await;
            break;
        }
    }

    handle
}

// ============================================================================
// LLM Mock Server Fixtures
// ============================================================================

/// SSE fixture: text-only response (claude-haiku-4-5-20251001)
pub const LLM_SSE_TEXT_ONLY: &str = concat!(
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

/// SSE fixture: single tool call (Bash: cargo fmt --check)
pub const LLM_SSE_SINGLE_TOOL: &str = concat!(
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

/// Build an Axum router with a `/v1/messages` endpoint that echoes the request body.
/// Used for testing system prompt injection — the test can inspect the body the proxy forwarded.
pub fn echo_router() -> Router {
    use axum::body::Body;
    use axum::response::IntoResponse;
    use axum::routing::{get, post};
    use http_body_util::BodyExt;

    Router::new()
        .route("/get", get(|| async { "GET response" }))
        .route(
            "/v1/messages",
            post(|req: axum::http::Request<Body>| async move {
                let body_bytes = req.into_body().collect().await.unwrap().to_bytes();
                (
                    axum::http::StatusCode::OK,
                    [("content-type", "application/json")],
                    body_bytes,
                )
                    .into_response()
            }),
        )
}

/// Build an Axum router that includes a mock `/v1/messages` endpoint serving SSE.
///
/// The SSE data is delivered in small chunks with delays to simulate real streaming.
pub fn llm_router(sse_fixture: &'static str) -> Router {
    use axum::body::Body;
    use axum::response::IntoResponse;
    use axum::routing::{get, post};
    use tokio::sync::mpsc;
    use tokio_stream::wrappers::ReceiverStream;

    Router::new()
        .route("/get", get(|| async { "GET response" }))
        .route(
            "/headers",
            get(|req: axum::http::Request<axum::body::Body>| async move {
                let headers: Vec<String> = req
                    .headers()
                    .iter()
                    .map(|(k, v)| format!("{}: {}", k, v.to_str().unwrap_or("?")))
                    .collect();
                headers.join("\n")
            }),
        )
        .route(
            "/v1/messages",
            post(move || async move {
                let (tx, rx) = mpsc::channel::<Result<String, std::io::Error>>(32);

                tokio::spawn(async move {
                    // Split SSE fixture into lines and send them in small groups
                    // with delays to simulate real streaming behavior
                    let mut buf = String::new();
                    for line in sse_fixture.lines() {
                        buf.push_str(line);
                        buf.push('\n');

                        // Send after each blank line (end of SSE event)
                        if line.is_empty() {
                            if tx.send(Ok(buf.clone())).await.is_err() {
                                break;
                            }
                            buf.clear();
                            // Small delay between events
                            tokio::time::sleep(Duration::from_millis(5)).await;
                        }
                    }
                    // Send any remaining data
                    if !buf.is_empty() {
                        let _ = tx.send(Ok(buf)).await;
                    }
                });

                let stream = ReceiverStream::new(rx);
                let body = Body::from_stream(stream);
                (
                    axum::http::StatusCode::OK,
                    [
                        ("content-type", "text/event-stream"),
                        ("cache-control", "no-cache"),
                    ],
                    body,
                )
                    .into_response()
            }),
        )
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Find an available port for testing
pub async fn find_available_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);
    port
}
