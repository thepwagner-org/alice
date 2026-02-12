//! Integration tests for Alice HTTPS proxy

mod common;

use common::{
    echo_router, find_available_port, llm_router, spawn_https_server, spawn_https_server_with_app,
    spawn_proxy, ProxyConfig, RuleSpec, LLM_SSE_SINGLE_TOOL, LLM_SSE_TEXT_ONLY,
};

use axum::http::StatusCode;
use reqwest::Proxy;
use std::time::{Duration, Instant};
use tokio::time::timeout;

// ============================================================================
// Test-specific Helpers (not shared with performance tests)
// ============================================================================

/// Spawn a mock HTTPS server that only supports HTTP/1.1 (no ALPN h2)
async fn spawn_https_server_h1_only(port: u16) -> (String, tokio::task::JoinHandle<()>) {
    spawn_https_server_with_app(port, default_router(), false).await
}

fn default_router() -> axum::Router {
    use axum::body::Body;
    use axum::extract::Path;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use axum::routing::{get, post};
    use tokio::sync::mpsc;
    use tokio_stream::wrappers::ReceiverStream;
    axum::Router::new()
        .route("/get", get(|| async { "GET response" }))
        .route("/post", post(|| async { "POST response" }))
        .route(
            "/status/{code}",
            get(|Path(code): Path<u16>| async move {
                StatusCode::from_u16(code).unwrap_or(StatusCode::BAD_REQUEST)
            }),
        )
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
            "/sse",
            get(|| async {
                let (tx, rx) = mpsc::channel::<Result<String, std::io::Error>>(10);
                tokio::spawn(async move {
                    for i in 1..=5 {
                        let event = format!("data: event {}\n\n", i);
                        if tx.send(Ok(event)).await.is_err() {
                            break;
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
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
                    .into_response()
            }),
        )
}

/// Build a reqwest client configured to use the proxy
fn client_with_proxy(
    proxy_port: u16,
    proxy_ca_cert: &std::path::Path,
    auth: Option<(&str, &str)>,
) -> reqwest::Client {
    let proxy_ca = std::fs::read_to_string(proxy_ca_cert).expect("read proxy CA");
    let proxy_ca_cert =
        reqwest::Certificate::from_pem(proxy_ca.as_bytes()).expect("parse proxy CA");

    let proxy_url = format!("http://127.0.0.1:{}", proxy_port);
    let mut proxy = Proxy::https(&proxy_url).expect("proxy");
    if let Some((user, pass)) = auth {
        proxy = proxy.basic_auth(user, pass);
    }

    reqwest::Client::builder()
        .proxy(proxy)
        .add_root_certificate(proxy_ca_cert)
        .build()
        .expect("build client")
}

/// Build a reqwest client that forces HTTP/1.1 (no HTTP/2)
fn client_with_proxy_h1_only(proxy_port: u16, proxy_ca_cert: &std::path::Path) -> reqwest::Client {
    let proxy_ca = std::fs::read_to_string(proxy_ca_cert).expect("read proxy CA");
    let proxy_ca_cert =
        reqwest::Certificate::from_pem(proxy_ca.as_bytes()).expect("parse proxy CA");

    let proxy_url = format!("http://127.0.0.1:{}", proxy_port);
    let proxy = Proxy::https(&proxy_url).expect("proxy");

    reqwest::Client::builder()
        .proxy(proxy)
        .add_root_certificate(proxy_ca_cert)
        .http1_only()
        .build()
        .expect("build client")
}

/// Build an HTTP/2 capable client
fn client_with_proxy_h2(
    proxy_port: u16,
    proxy_ca_cert: &std::path::Path,
    upstream_ca_pem: Option<&str>,
) -> reqwest::Client {
    let proxy_ca = std::fs::read_to_string(proxy_ca_cert).expect("read proxy CA");
    let proxy_ca_cert =
        reqwest::Certificate::from_pem(proxy_ca.as_bytes()).expect("parse proxy CA");

    let proxy_url = format!("http://127.0.0.1:{}", proxy_port);
    let proxy = Proxy::https(&proxy_url).expect("proxy");

    let mut builder = reqwest::Client::builder()
        .proxy(proxy)
        .add_root_certificate(proxy_ca_cert)
        .use_rustls_tls()
        .http2_adaptive_window(true);

    if let Some(ca_pem) = upstream_ca_pem {
        let upstream_cert =
            reqwest::Certificate::from_pem(ca_pem.as_bytes()).expect("parse upstream cert");
        builder = builder.add_root_certificate(upstream_cert);
    }

    builder.build().expect("build client")
}

/// Create a host-based rule with path
fn rule_host_path(action: &'static str, host: &'static str, path: &'static str) -> RuleSpec {
    RuleSpec {
        action,
        host: Some(host),
        cidr: None,
        path: Some(path),
        redact_paths: Vec::new(),
    }
}

/// Create a CIDR-based rule
fn rule_cidr(action: &'static str, cidr: &'static str) -> RuleSpec {
    RuleSpec {
        action,
        host: None,
        cidr: Some(cidr),
        path: None,
        redact_paths: Vec::new(),
    }
}

/// Generate TOML for a credential with env source
fn credential_env(
    name: &str,
    host: &str,
    header: &str,
    match_value: &str,
    format: &str,
    env_var: &str,
) -> String {
    format!(
        r#"
[[credentials]]
name = "{name}"
host = "{host}"
header = "{header}"
match = "{match_value}"
format = "{format}"
env = "{env_var}"
"#
    )
}

/// Generate TOML for a credential with file source
fn credential_file(
    name: &str,
    host: &str,
    header: &str,
    match_value: &str,
    format: &str,
    file_path: &std::path::Path,
) -> String {
    format!(
        r#"
[[credentials]]
name = "{name}"
host = "{host}"
header = "{header}"
match = "{match_value}"
format = "{format}"
file = "{}"
"#,
        file_path.display()
    )
}

/// Generate TOML for a basic-auth credential with env source
fn credential_basic_env(
    name: &str,
    host: &str,
    username: &str,
    match_value: &str,
    env_var: &str,
) -> String {
    format!(
        r#"
[[credentials]]
name = "{name}"
host = "{host}"
scheme = "basic"
username = "{username}"
match = "{match_value}"
env = "{env_var}"
"#
    )
}

// ============================================================================
// HTTP/1.1 Tests
// ============================================================================

#[tokio::test]
async fn test_basic_proxy_flow() {
    let upstream_port = find_available_port().await;
    let proxy_port = find_available_port().await;
    let temp_dir = tempfile::tempdir().expect("temp dir");

    // Start upstream HTTPS server
    let (upstream_cert, _upstream_handle) = spawn_https_server(upstream_port).await;

    // Start proxy allowing localhost
    let _proxy_handle = spawn_proxy(
        ProxyConfig {
            listen_port: proxy_port,
            rules: vec![RuleSpec::host("allow", "localhost")],
            upstream_ca_pem: Some(upstream_cert.clone()),
            ..Default::default()
        },
        &temp_dir,
    )
    .await;

    // Build client - only needs to trust proxy's CA (not upstream cert)
    let client = client_with_proxy(proxy_port, &temp_dir.path().join("ca.pem"), None);

    // Make request through proxy
    let url = format!("https://localhost:{}/get", upstream_port);
    let result = timeout(Duration::from_secs(5), client.get(&url).send()).await;

    let response = result.expect("timeout").expect("request");
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await.expect("body");
    assert_eq!(body, "GET response");
}

#[tokio::test]
async fn test_host_denied() {
    let upstream_port = find_available_port().await;
    let proxy_port = find_available_port().await;
    let temp_dir = tempfile::tempdir().expect("temp dir");

    // Start upstream HTTPS server
    let (upstream_cert, _upstream_handle) = spawn_https_server(upstream_port).await;

    // Start proxy denying localhost
    let _proxy_handle = spawn_proxy(
        ProxyConfig {
            listen_port: proxy_port,
            rules: vec![RuleSpec::host("deny", "localhost")],
            upstream_ca_pem: Some(upstream_cert.clone()),
            ..Default::default()
        },
        &temp_dir,
    )
    .await;

    // Build client - only needs to trust proxy's CA (not upstream cert)
    let client = client_with_proxy(proxy_port, &temp_dir.path().join("ca.pem"), None);

    // Make request through proxy - should be denied
    let url = format!("https://localhost:{}/get", upstream_port);
    let result = timeout(Duration::from_secs(5), client.get(&url).send()).await;

    // The proxy returns 403 at CONNECT time, which manifests as a connection error
    assert!(result.expect("timeout").is_err());
}

#[tokio::test]
async fn test_path_allowed() {
    let upstream_port = find_available_port().await;
    let proxy_port = find_available_port().await;
    let temp_dir = tempfile::tempdir().expect("temp dir");

    // Start upstream HTTPS server
    let (upstream_cert, _upstream_handle) = spawn_https_server(upstream_port).await;

    // Start proxy allowing only /get path
    let _proxy_handle = spawn_proxy(
        ProxyConfig {
            listen_port: proxy_port,
            rules: vec![rule_host_path("allow", "localhost", "/get")],
            upstream_ca_pem: Some(upstream_cert.clone()),
            ..Default::default()
        },
        &temp_dir,
    )
    .await;

    // Build client - only needs to trust proxy's CA (not upstream cert)
    let client = client_with_proxy(proxy_port, &temp_dir.path().join("ca.pem"), None);

    // Request to allowed path should succeed
    let url = format!("https://localhost:{}/get", upstream_port);
    let result = timeout(Duration::from_secs(5), client.get(&url).send()).await;

    let response = result.expect("timeout").expect("request");
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_path_denied() {
    let upstream_port = find_available_port().await;
    let proxy_port = find_available_port().await;
    let temp_dir = tempfile::tempdir().expect("temp dir");

    // Start upstream HTTPS server
    let (upstream_cert, _upstream_handle) = spawn_https_server(upstream_port).await;

    // Start proxy allowing only /get path
    let _proxy_handle = spawn_proxy(
        ProxyConfig {
            listen_port: proxy_port,
            rules: vec![rule_host_path("allow", "localhost", "/get")],
            upstream_ca_pem: Some(upstream_cert.clone()),
            ..Default::default()
        },
        &temp_dir,
    )
    .await;

    // Build client - only needs to trust proxy's CA (not upstream cert)
    let client = client_with_proxy(proxy_port, &temp_dir.path().join("ca.pem"), None);

    // Request to different path should be denied with 403
    let url = format!("https://localhost:{}/post", upstream_port);
    let result = timeout(Duration::from_secs(5), client.post(&url).send()).await;

    let response = result.expect("timeout").expect("request");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_proxy_auth_required() {
    let upstream_port = find_available_port().await;
    let proxy_port = find_available_port().await;
    let temp_dir = tempfile::tempdir().expect("temp dir");

    // Start upstream HTTPS server
    let (upstream_cert, _upstream_handle) = spawn_https_server(upstream_port).await;

    // Start proxy with auth required
    let _proxy_handle = spawn_proxy(
        ProxyConfig {
            listen_port: proxy_port,
            rules: vec![RuleSpec::host("allow", "localhost")],
            auth: Some(("alice".to_string(), "secret123".to_string())),
            upstream_ca_pem: Some(upstream_cert.clone()),
            ..Default::default()
        },
        &temp_dir,
    )
    .await;

    // Build client WITHOUT auth
    let client = client_with_proxy(proxy_port, &temp_dir.path().join("ca.pem"), None);

    // Request should fail (407 at CONNECT = connection error)
    let url = format!("https://localhost:{}/get", upstream_port);
    let result = timeout(Duration::from_secs(5), client.get(&url).send()).await;

    assert!(result.expect("timeout").is_err());
}

#[tokio::test]
async fn test_proxy_auth_success() {
    let upstream_port = find_available_port().await;
    let proxy_port = find_available_port().await;
    let temp_dir = tempfile::tempdir().expect("temp dir");

    // Start upstream HTTPS server
    let (upstream_cert, _upstream_handle) = spawn_https_server(upstream_port).await;

    // Start proxy with auth required
    let _proxy_handle = spawn_proxy(
        ProxyConfig {
            listen_port: proxy_port,
            rules: vec![RuleSpec::host("allow", "localhost")],
            auth: Some(("alice".to_string(), "secret123".to_string())),
            upstream_ca_pem: Some(upstream_cert.clone()),
            ..Default::default()
        },
        &temp_dir,
    )
    .await;

    // Build client WITH correct auth
    let client = client_with_proxy(
        proxy_port,
        &temp_dir.path().join("ca.pem"),
        Some(("alice", "secret123")),
    );

    // Request should succeed
    let url = format!("https://localhost:{}/get", upstream_port);
    let result = timeout(Duration::from_secs(5), client.get(&url).send()).await;

    let response = result.expect("timeout").expect("request");
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_proxy_auth_wrong_password() {
    let upstream_port = find_available_port().await;
    let proxy_port = find_available_port().await;
    let temp_dir = tempfile::tempdir().expect("temp dir");

    // Start upstream HTTPS server
    let (upstream_cert, _upstream_handle) = spawn_https_server(upstream_port).await;

    // Start proxy with auth required
    let _proxy_handle = spawn_proxy(
        ProxyConfig {
            listen_port: proxy_port,
            rules: vec![RuleSpec::host("allow", "localhost")],
            auth: Some(("alice".to_string(), "secret123".to_string())),
            upstream_ca_pem: Some(upstream_cert.clone()),
            ..Default::default()
        },
        &temp_dir,
    )
    .await;

    // Build client WITH wrong password
    let client = client_with_proxy(
        proxy_port,
        &temp_dir.path().join("ca.pem"),
        Some(("alice", "wrongpassword")),
    );

    // Request should fail (407 at CONNECT = connection error)
    let url = format!("https://localhost:{}/get", upstream_port);
    let result = timeout(Duration::from_secs(5), client.get(&url).send()).await;

    assert!(
        result.expect("timeout").is_err(),
        "Connection with wrong password should be rejected"
    );
}

#[tokio::test]
async fn test_non_connect_rejected() {
    let proxy_port = find_available_port().await;
    let temp_dir = tempfile::tempdir().expect("temp dir");

    // Start proxy
    let _proxy_handle = spawn_proxy(
        ProxyConfig {
            listen_port: proxy_port,
            rules: vec![RuleSpec::host("allow", "*")],
            auth: None,
            upstream_ca_pem: None,
            ..Default::default()
        },
        &temp_dir,
    )
    .await;

    // Make a plain HTTP request (not CONNECT) directly to proxy
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", proxy_port))
        .await
        .expect("connect");

    // Send a plain GET request (not CONNECT)
    stream
        .write_all(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .expect("write");

    let mut response = vec![0u8; 1024];
    let n = stream.read(&mut response).await.expect("read");
    let response_str = String::from_utf8_lossy(&response[..n]);

    // Should get 501 Not Implemented
    assert!(
        response_str.contains("501"),
        "Expected 501, got: {}",
        response_str
    );
}

// ============================================================================
// HTTP/2 Tests
// ============================================================================

#[tokio::test]
async fn test_http2_path_policy() {
    // This test verifies HTTP/2 path-based policy enforcement.
    // The proxy inspects individual HTTP/2 streams for path-based policy.
    let upstream_port = find_available_port().await;
    let proxy_port = find_available_port().await;
    let temp_dir = tempfile::tempdir().expect("temp dir");

    // Start upstream HTTPS server
    let (upstream_cert, _upstream_handle) = spawn_https_server(upstream_port).await;

    // Start proxy with path-based rule (this is what needs HTTP/2 inspection)
    let _proxy_handle = spawn_proxy(
        ProxyConfig {
            listen_port: proxy_port,
            rules: vec![rule_host_path("allow", "localhost", "/get")],
            upstream_ca_pem: Some(upstream_cert.clone()),
            ..Default::default()
        },
        &temp_dir,
    )
    .await;

    // Build HTTP/2-capable client
    let client = client_with_proxy_h2(
        proxy_port,
        &temp_dir.path().join("ca.pem"),
        Some(&upstream_cert),
    );

    // Make request through proxy - this should work with HTTP/2 path inspection
    let url = format!("https://localhost:{}/get", upstream_port);
    let result = timeout(Duration::from_secs(5), client.get(&url).send()).await;

    let response = result.expect("timeout").expect("request");
    assert_eq!(response.status(), StatusCode::OK);
    // Verify we actually got HTTP/2
    assert_eq!(response.version(), reqwest::Version::HTTP_2);
}

#[tokio::test]
async fn test_http2_to_http1_translation() {
    // This test verifies that the proxy can translate HTTP/2 client requests
    // to HTTP/1.1 when the upstream server doesn't support HTTP/2.
    let upstream_port = find_available_port().await;
    let proxy_port = find_available_port().await;
    let temp_dir = tempfile::tempdir().expect("temp dir");

    // Start upstream HTTPS server that ONLY supports HTTP/1.1
    let (upstream_cert, _upstream_handle) = spawn_https_server_h1_only(upstream_port).await;

    // Start proxy with path-based rule
    let _proxy_handle = spawn_proxy(
        ProxyConfig {
            listen_port: proxy_port,
            rules: vec![rule_host_path("allow", "localhost", "/get")],
            upstream_ca_pem: Some(upstream_cert.clone()),
            ..Default::default()
        },
        &temp_dir,
    )
    .await;

    // Build HTTP/2 client - it will negotiate H2 with proxy, but proxy will speak H1.1 to upstream
    let client = client_with_proxy_h2(proxy_port, &temp_dir.path().join("ca.pem"), None);

    // Make request through proxy - proxy should translate H2 to H1.1
    let url = format!("https://localhost:{}/get", upstream_port);
    let result = timeout(Duration::from_secs(5), client.get(&url).send()).await;

    let response = result.expect("timeout").expect("request");
    assert_eq!(response.status(), StatusCode::OK);
    // Client sees HTTP/2 (between client and proxy)
    assert_eq!(response.version(), reqwest::Version::HTTP_2);
    let body = response.text().await.expect("body");
    assert_eq!(body, "GET response");
}

// ============================================================================
// Credential Injection Tests
// ============================================================================

#[tokio::test]
async fn test_credential_injection() {
    // This test verifies that the proxy replaces dummy tokens with real secrets
    let upstream_port = find_available_port().await;
    let proxy_port = find_available_port().await;
    let temp_dir = tempfile::tempdir().expect("temp dir");

    // Set the real secret in environment
    std::env::set_var("TEST_REAL_SECRET", "actual-secret-value");

    // Start upstream HTTPS server
    let (upstream_cert, _upstream_handle) = spawn_https_server(upstream_port).await;

    // Start proxy with credential injection configured
    let _proxy_handle = spawn_proxy(
        ProxyConfig {
            listen_port: proxy_port,
            rules: vec![RuleSpec::host("allow", "localhost")],
            auth: None,
            upstream_ca_pem: Some(upstream_cert.clone()),
            credentials_toml: vec![credential_env(
                "test-cred",
                "localhost",
                "Authorization",
                "Bearer DUMMY_TOKEN",
                "Bearer {value}",
                "TEST_REAL_SECRET",
            )],
            dns_hosts: vec![],
            ..Default::default()
        },
        &temp_dir,
    )
    .await;

    // Build client
    let client = client_with_proxy(proxy_port, &temp_dir.path().join("ca.pem"), None);

    // Make request with the dummy token - should be replaced
    let url = format!("https://localhost:{}/headers", upstream_port);
    let result = timeout(
        Duration::from_secs(5),
        client
            .get(&url)
            .header("Authorization", "Bearer DUMMY_TOKEN")
            .send(),
    )
    .await;

    let response = result.expect("timeout").expect("request");
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await.expect("body");

    // The /headers endpoint echoes back the headers it received
    // The proxy should have replaced DUMMY_TOKEN with actual-secret-value
    assert!(
        body.contains("actual-secret-value"),
        "Expected credential injection, got: {}",
        body
    );
    assert!(
        !body.contains("DUMMY_TOKEN"),
        "Dummy token should have been replaced, got: {}",
        body
    );

    std::env::remove_var("TEST_REAL_SECRET");
}

#[tokio::test]
async fn test_credential_no_replacement_when_no_match() {
    // This test verifies that credentials are NOT replaced when the header doesn't match
    let upstream_port = find_available_port().await;
    let proxy_port = find_available_port().await;
    let temp_dir = tempfile::tempdir().expect("temp dir");

    // Set the real secret in environment
    std::env::set_var("TEST_REAL_SECRET_2", "should-not-see-this");

    // Start upstream HTTPS server
    let (upstream_cert, _upstream_handle) = spawn_https_server(upstream_port).await;

    // Start proxy with credential injection configured
    let _proxy_handle = spawn_proxy(
        ProxyConfig {
            listen_port: proxy_port,
            rules: vec![RuleSpec::host("allow", "localhost")],
            auth: None,
            upstream_ca_pem: Some(upstream_cert.clone()),
            credentials_toml: vec![credential_env(
                "test-cred",
                "localhost",
                "Authorization",
                "Bearer DUMMY_TOKEN",
                "Bearer {value}",
                "TEST_REAL_SECRET_2",
            )],
            dns_hosts: vec![],
            ..Default::default()
        },
        &temp_dir,
    )
    .await;

    // Build client
    let client = client_with_proxy(proxy_port, &temp_dir.path().join("ca.pem"), None);

    // Make request with a DIFFERENT token - should NOT be replaced
    let url = format!("https://localhost:{}/headers", upstream_port);
    let result = timeout(
        Duration::from_secs(5),
        client
            .get(&url)
            .header("Authorization", "Bearer SOME_OTHER_TOKEN")
            .send(),
    )
    .await;

    let response = result.expect("timeout").expect("request");
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await.expect("body");

    // The header should pass through unchanged
    assert!(
        body.contains("SOME_OTHER_TOKEN"),
        "Original token should pass through, got: {}",
        body
    );
    assert!(
        !body.contains("should-not-see-this"),
        "Secret should NOT be injected when token doesn't match, got: {}",
        body
    );

    std::env::remove_var("TEST_REAL_SECRET_2");
}

#[tokio::test]
async fn test_credential_no_header() {
    // This test verifies that requests without the credential header pass through normally
    let upstream_port = find_available_port().await;
    let proxy_port = find_available_port().await;
    let temp_dir = tempfile::tempdir().expect("temp dir");

    // Set the real secret in environment
    std::env::set_var("TEST_REAL_SECRET_3", "secret-value");

    // Start upstream HTTPS server
    let (upstream_cert, _upstream_handle) = spawn_https_server(upstream_port).await;

    // Start proxy with credential injection configured
    let _proxy_handle = spawn_proxy(
        ProxyConfig {
            listen_port: proxy_port,
            rules: vec![RuleSpec::host("allow", "localhost")],
            auth: None,
            upstream_ca_pem: Some(upstream_cert.clone()),
            credentials_toml: vec![credential_env(
                "test-cred",
                "localhost",
                "Authorization",
                "Bearer DUMMY_TOKEN",
                "Bearer {value}",
                "TEST_REAL_SECRET_3",
            )],
            dns_hosts: vec![],
            ..Default::default()
        },
        &temp_dir,
    )
    .await;

    // Build client
    let client = client_with_proxy(proxy_port, &temp_dir.path().join("ca.pem"), None);

    // Make request WITHOUT any Authorization header
    let url = format!("https://localhost:{}/headers", upstream_port);
    let result = timeout(Duration::from_secs(5), client.get(&url).send()).await;

    let response = result.expect("timeout").expect("request");
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await.expect("body");

    // Request should succeed, and secret should NOT appear (no header to replace)
    assert!(
        !body.contains("secret-value"),
        "Secret should NOT be injected when header is absent, got: {}",
        body
    );

    std::env::remove_var("TEST_REAL_SECRET_3");
}

#[tokio::test]
async fn test_credential_host_mismatch() {
    // This test verifies that credentials scoped to one host don't apply to others
    let upstream_port = find_available_port().await;
    let proxy_port = find_available_port().await;
    let temp_dir = tempfile::tempdir().expect("temp dir");

    // Set the real secret in environment
    std::env::set_var("TEST_REAL_SECRET_4", "host-scoped-secret");

    // Start upstream HTTPS server
    let (upstream_cert, _upstream_handle) = spawn_https_server(upstream_port).await;

    // Start proxy with credential injection configured for a DIFFERENT host
    let _proxy_handle = spawn_proxy(
        ProxyConfig {
            listen_port: proxy_port,
            rules: vec![RuleSpec::host("allow", "localhost")],
            auth: None,
            upstream_ca_pem: Some(upstream_cert.clone()),
            credentials_toml: vec![credential_env(
                "test-cred",
                "api.github.com", // Different host than we'll request
                "Authorization",
                "Bearer DUMMY_TOKEN",
                "Bearer {value}",
                "TEST_REAL_SECRET_4",
            )],
            dns_hosts: vec![],
            ..Default::default()
        },
        &temp_dir,
    )
    .await;

    // Build client
    let client = client_with_proxy(proxy_port, &temp_dir.path().join("ca.pem"), None);

    // Make request to localhost (not api.github.com) with the dummy token
    let url = format!("https://localhost:{}/headers", upstream_port);
    let result = timeout(
        Duration::from_secs(5),
        client
            .get(&url)
            .header("Authorization", "Bearer DUMMY_TOKEN")
            .send(),
    )
    .await;

    let response = result.expect("timeout").expect("request");
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await.expect("body");

    // Token should pass through unchanged (host doesn't match credential scope)
    assert!(
        body.contains("DUMMY_TOKEN"),
        "Dummy token should pass through when host doesn't match, got: {}",
        body
    );
    assert!(
        !body.contains("host-scoped-secret"),
        "Secret should NOT be injected for wrong host, got: {}",
        body
    );

    std::env::remove_var("TEST_REAL_SECRET_4");
}

#[tokio::test]
async fn test_credential_partial_token_no_match() {
    // This test verifies that partial/similar tokens don't trigger replacement
    // (we require exact match, not substring/prefix match)
    let upstream_port = find_available_port().await;
    let proxy_port = find_available_port().await;
    let temp_dir = tempfile::tempdir().expect("temp dir");

    // Set the real secret in environment
    std::env::set_var("TEST_REAL_SECRET_5", "exact-match-secret");

    // Start upstream HTTPS server
    let (upstream_cert, _upstream_handle) = spawn_https_server(upstream_port).await;

    // Start proxy with credential injection configured
    let _proxy_handle = spawn_proxy(
        ProxyConfig {
            listen_port: proxy_port,
            rules: vec![RuleSpec::host("allow", "localhost")],
            auth: None,
            upstream_ca_pem: Some(upstream_cert.clone()),
            credentials_toml: vec![credential_env(
                "test-cred",
                "localhost",
                "Authorization",
                "Bearer DUMMY_TOKEN",
                "Bearer {value}",
                "TEST_REAL_SECRET_5",
            )],
            dns_hosts: vec![],
            ..Default::default()
        },
        &temp_dir,
    )
    .await;

    // Build client
    let client = client_with_proxy(proxy_port, &temp_dir.path().join("ca.pem"), None);

    // Make request with a SIMILAR but not exact token
    let url = format!("https://localhost:{}/headers", upstream_port);
    let result = timeout(
        Duration::from_secs(5),
        client
            .get(&url)
            .header("Authorization", "Bearer DUMMY_TOKEN_V2") // Similar but not exact
            .send(),
    )
    .await;

    let response = result.expect("timeout").expect("request");
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await.expect("body");

    // Token should pass through unchanged (partial match shouldn't trigger replacement)
    assert!(
        body.contains("DUMMY_TOKEN_V2"),
        "Similar token should pass through unchanged, got: {}",
        body
    );
    assert!(
        !body.contains("exact-match-secret"),
        "Secret should NOT be injected for partial match, got: {}",
        body
    );

    std::env::remove_var("TEST_REAL_SECRET_5");
}

#[tokio::test]
async fn test_credential_injection_from_file() {
    // This test verifies that credentials can be loaded from files (not just env vars)
    let upstream_port = find_available_port().await;
    let proxy_port = find_available_port().await;
    let temp_dir = tempfile::tempdir().expect("temp dir");

    // Create a file containing the secret (with trailing whitespace to test trimming)
    let secret_file = temp_dir.path().join("secret.txt");
    std::fs::write(&secret_file, "  file-based-secret-value  \n").expect("write secret file");

    // Start upstream HTTPS server
    let (upstream_cert, _upstream_handle) = spawn_https_server(upstream_port).await;

    // Start proxy with file-based credential injection
    let _proxy_handle = spawn_proxy(
        ProxyConfig {
            listen_port: proxy_port,
            rules: vec![RuleSpec::host("allow", "localhost")],
            auth: None,
            upstream_ca_pem: Some(upstream_cert.clone()),
            credentials_toml: vec![credential_file(
                "file-cred",
                "localhost",
                "X-Api-Key",
                "DUMMY_API_KEY",
                "{value}",
                &secret_file,
            )],
            dns_hosts: vec![],
            ..Default::default()
        },
        &temp_dir,
    )
    .await;

    // Build client
    let client = client_with_proxy(proxy_port, &temp_dir.path().join("ca.pem"), None);

    // Make request with the dummy token - should be replaced with file content
    let url = format!("https://localhost:{}/headers", upstream_port);
    let result = timeout(
        Duration::from_secs(5),
        client.get(&url).header("X-Api-Key", "DUMMY_API_KEY").send(),
    )
    .await;

    let response = result.expect("timeout").expect("request");
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await.expect("body");

    // The /headers endpoint echoes back the headers it received
    // The proxy should have replaced DUMMY_API_KEY with file-based-secret-value (trimmed)
    assert!(
        body.contains("file-based-secret-value"),
        "Expected file-based credential injection, got: {}",
        body
    );
    assert!(
        !body.contains("DUMMY_API_KEY"),
        "Dummy token should have been replaced, got: {}",
        body
    );
}

// ============================================================================
// Basic Auth Credential Injection Tests
// ============================================================================

#[tokio::test]
async fn test_credential_injection_basic_auth() {
    use base64::prelude::*;

    // This test verifies that basic-auth credentials are base64-decoded, matched, and re-encoded
    let upstream_port = find_available_port().await;
    let proxy_port = find_available_port().await;
    let temp_dir = tempfile::tempdir().expect("temp dir");

    // Set the real secret in environment
    std::env::set_var("TEST_BASIC_AUTH_SECRET", "real-registry-token");

    // Start upstream HTTPS server
    let (upstream_cert, _upstream_handle) = spawn_https_server(upstream_port).await;

    // Start proxy with basic-auth credential injection
    let _proxy_handle = spawn_proxy(
        ProxyConfig {
            listen_port: proxy_port,
            rules: vec![RuleSpec::host("allow", "localhost")],
            auth: None,
            upstream_ca_pem: Some(upstream_cert.clone()),
            credentials_toml: vec![credential_basic_env(
                "basic-cred",
                "localhost",
                "token",
                "DUMMY_REGISTRY_TOKEN",
                "TEST_BASIC_AUTH_SECRET",
            )],
            dns_hosts: vec![],
            ..Default::default()
        },
        &temp_dir,
    )
    .await;

    // Build client
    let client = client_with_proxy(proxy_port, &temp_dir.path().join("ca.pem"), None);

    // Client sends: Authorization: Basic base64("token:DUMMY_REGISTRY_TOKEN")
    // This is what Bundler/pip would send with a dummy password configured
    let dummy_b64 = BASE64_STANDARD.encode(b"token:DUMMY_REGISTRY_TOKEN");
    let dummy_header = format!("Basic {}", dummy_b64);

    let url = format!("https://localhost:{}/headers", upstream_port);
    let result = timeout(
        Duration::from_secs(5),
        client
            .get(&url)
            .header("Authorization", &dummy_header)
            .send(),
    )
    .await;

    let response = result.expect("timeout").expect("request");
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await.expect("body");

    // The upstream should see: Basic base64("token:real-registry-token")
    let expected_b64 = BASE64_STANDARD.encode(b"token:real-registry-token");
    assert!(
        body.contains(&expected_b64),
        "Expected base64-encoded real credential, got: {}",
        body
    );
    // The dummy token should NOT appear (neither in base64 nor plaintext)
    assert!(
        !body.contains(&dummy_b64),
        "Dummy base64 should have been replaced, got: {}",
        body
    );
    assert!(
        !body.contains("DUMMY_REGISTRY_TOKEN"),
        "Dummy token should not appear in plaintext, got: {}",
        body
    );

    std::env::remove_var("TEST_BASIC_AUTH_SECRET");
}

#[tokio::test]
async fn test_credential_injection_basic_auth_no_match() {
    use base64::prelude::*;

    // This test verifies that basic-auth credentials are NOT replaced when the password doesn't match
    let upstream_port = find_available_port().await;
    let proxy_port = find_available_port().await;
    let temp_dir = tempfile::tempdir().expect("temp dir");

    std::env::set_var("TEST_BASIC_AUTH_NO_MATCH", "should-not-see-this");

    let (upstream_cert, _upstream_handle) = spawn_https_server(upstream_port).await;

    let _proxy_handle = spawn_proxy(
        ProxyConfig {
            listen_port: proxy_port,
            rules: vec![RuleSpec::host("allow", "localhost")],
            auth: None,
            upstream_ca_pem: Some(upstream_cert.clone()),
            credentials_toml: vec![credential_basic_env(
                "basic-cred",
                "localhost",
                "token",
                "DUMMY_REGISTRY_TOKEN",
                "TEST_BASIC_AUTH_NO_MATCH",
            )],
            dns_hosts: vec![],
            ..Default::default()
        },
        &temp_dir,
    )
    .await;

    let client = client_with_proxy(proxy_port, &temp_dir.path().join("ca.pem"), None);

    // Client sends a DIFFERENT password — should NOT be replaced
    let other_b64 = BASE64_STANDARD.encode(b"token:SOME_OTHER_TOKEN");
    let other_header = format!("Basic {}", other_b64);

    let url = format!("https://localhost:{}/headers", upstream_port);
    let result = timeout(
        Duration::from_secs(5),
        client
            .get(&url)
            .header("Authorization", &other_header)
            .send(),
    )
    .await;

    let response = result.expect("timeout").expect("request");
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await.expect("body");

    // The original header should pass through unchanged
    assert!(
        body.contains(&other_b64),
        "Original token should pass through, got: {}",
        body
    );
    assert!(
        !body.contains("should-not-see-this"),
        "Secret should NOT be injected when password doesn't match, got: {}",
        body
    );

    std::env::remove_var("TEST_BASIC_AUTH_NO_MATCH");
}

// ============================================================================
// HTTP/1.1 Persistent Connection Policy Tests
// ============================================================================

#[tokio::test]
async fn test_h1_persistent_connection_policy_bypass() {
    // This test demonstrates a security vulnerability:
    // With HTTP/1.1 keep-alive connections, only the FIRST request on a connection
    // is policy-checked. Subsequent requests on the same connection bypass policy.
    //
    // Attack scenario:
    // 1. Policy allows only /get
    // 2. Attacker makes request to /get (allowed, connection established)
    // 3. On same connection, attacker makes request to /post (should be denied)
    // 4. BUG: The second request is NOT checked and goes through!

    let upstream_port = find_available_port().await;
    let proxy_port = find_available_port().await;
    let temp_dir = tempfile::tempdir().expect("temp dir");

    // Start upstream HTTPS server (HTTP/1.1 only to ensure no H2 multiplexing)
    let (upstream_cert, _upstream_handle) = spawn_https_server_h1_only(upstream_port).await;

    // Start proxy allowing ONLY /get path
    let _proxy_handle = spawn_proxy(
        ProxyConfig {
            listen_port: proxy_port,
            rules: vec![rule_host_path("allow", "localhost", "/get")],
            upstream_ca_pem: Some(upstream_cert.clone()),
            ..Default::default()
        },
        &temp_dir,
    )
    .await;

    // Build HTTP/1.1-only client (forces keep-alive connection reuse)
    let client = client_with_proxy_h1_only(proxy_port, &temp_dir.path().join("ca.pem"));

    // First request: GET /get - should succeed (path is allowed)
    let url_get = format!("https://localhost:{}/get", upstream_port);
    let result = timeout(Duration::from_secs(5), client.get(&url_get).send()).await;
    let response = result.expect("timeout").expect("first request");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "First request to /get should succeed"
    );

    // Second request on SAME connection: POST /post - should be DENIED (path not allowed)
    // This uses the same keep-alive connection as the first request.
    let url_post = format!("https://localhost:{}/post", upstream_port);
    let result = timeout(Duration::from_secs(5), client.post(&url_post).send()).await;
    let response = result.expect("timeout").expect("second request");

    // EXPECTED: 403 Forbidden (policy denies /post)
    // ACTUAL BUG: 200 OK (policy bypass via keep-alive)
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "Second request to /post should be DENIED - policy bypass vulnerability!"
    );
}

#[tokio::test]
async fn test_h1_multiple_requests_all_checked() {
    // Verify that ALL requests on a persistent HTTP/1.1 connection are policy-checked,
    // not just the first one. This tests the fix for the policy bypass vulnerability.

    let upstream_port = find_available_port().await;
    let proxy_port = find_available_port().await;
    let temp_dir = tempfile::tempdir().expect("temp dir");

    // Start upstream HTTPS server (HTTP/1.1 only)
    let (upstream_cert, _upstream_handle) = spawn_https_server_h1_only(upstream_port).await;

    // Start proxy allowing both /get and /headers, but NOT /post
    let _proxy_handle = spawn_proxy(
        ProxyConfig {
            listen_port: proxy_port,
            rules: vec![
                rule_host_path("allow", "localhost", "/get"),
                rule_host_path("allow", "localhost", "/headers"),
                // /post is NOT allowed (default deny)
            ],
            upstream_ca_pem: Some(upstream_cert.clone()),
            ..Default::default()
        },
        &temp_dir,
    )
    .await;

    // Build HTTP/1.1-only client
    let client = client_with_proxy_h1_only(proxy_port, &temp_dir.path().join("ca.pem"));

    // Make a request through the proxy
    let url = format!("https://localhost:{}/get", upstream_port);
    let result = timeout(Duration::from_secs(5), client.get(&url).send()).await;
    let response = result.expect("timeout").expect("request 1");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "Request 1 to /get should succeed"
    );

    // Request 2: GET /headers - should succeed
    let url = format!("https://localhost:{}/headers", upstream_port);
    let result = timeout(Duration::from_secs(5), client.get(&url).send()).await;
    let response = result.expect("timeout").expect("request 2");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "Request 2 to /headers should succeed"
    );

    // Request 3: POST /post - should be DENIED
    let url = format!("https://localhost:{}/post", upstream_port);
    let result = timeout(Duration::from_secs(5), client.post(&url).send()).await;
    let response = result.expect("timeout").expect("request 3");
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "Request 3 to /post should be denied"
    );

    // Request 4: GET /get again - should still succeed
    let url = format!("https://localhost:{}/get", upstream_port);
    let result = timeout(Duration::from_secs(5), client.get(&url).send()).await;
    let response = result.expect("timeout").expect("request 4");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "Request 4 to /get should succeed"
    );
}

// ============================================================================
// DNS Rebinding Protection Tests
// ============================================================================
//
// These tests use dns.hosts overrides to simulate DNS rebinding attacks
// without requiring external network access.

/// Test that CIDR deny rules block connections to metadata endpoint IP.
///
/// Simulates DNS rebinding: "evil.test" resolves to 169.254.169.254 (AWS metadata).
/// CIDR rule should block the connection.
#[tokio::test]
async fn test_cidr_denies_metadata_endpoint() {
    let proxy_port = find_available_port().await;
    let temp_dir = tempfile::tempdir().expect("temp dir");

    // Start proxy with CIDR deny for metadata endpoint + dns override
    let _proxy_handle = spawn_proxy(
        ProxyConfig {
            listen_port: proxy_port,
            rules: vec![rule_cidr("deny", "169.254.169.254/32")],
            auth: None,
            upstream_ca_pem: None,
            credentials_toml: vec![],
            dns_hosts: vec![("evil.test", "169.254.169.254")],
            ..Default::default()
        },
        &temp_dir,
    )
    .await;

    let client = client_with_proxy(proxy_port, &temp_dir.path().join("ca.pem"), None);

    // evil.test resolves to 169.254.169.254 via dns.hosts override
    let result = timeout(
        Duration::from_secs(5),
        client.get("https://evil.test/").send(),
    )
    .await;

    // Should fail - proxy rejects due to CIDR rule
    assert!(
        result.expect("timeout").is_err(),
        "Connection to metadata endpoint should be denied by CIDR rule"
    );
}

/// Test that CIDR deny rules block RFC1918 private addresses.
#[tokio::test]
async fn test_cidr_denies_rfc1918() {
    let proxy_port = find_available_port().await;
    let temp_dir = tempfile::tempdir().expect("temp dir");

    // Start proxy with CIDR deny rules for RFC1918 ranges + dns overrides
    let _proxy_handle = spawn_proxy(
        ProxyConfig {
            listen_port: proxy_port,
            rules: vec![
                rule_cidr("deny", "10.0.0.0/8"),
                rule_cidr("deny", "172.16.0.0/12"),
                rule_cidr("deny", "192.168.0.0/16"),
            ],
            auth: None,
            upstream_ca_pem: None,
            credentials_toml: vec![],
            dns_hosts: vec![
                ("internal-10.test", "10.1.2.3"),
                ("internal-172.test", "172.31.0.1"),
                ("internal-192.test", "192.168.1.1"),
            ],
            ..Default::default()
        },
        &temp_dir,
    )
    .await;

    let client = client_with_proxy(proxy_port, &temp_dir.path().join("ca.pem"), None);

    // Test each RFC1918 range
    for host in ["internal-10.test", "internal-172.test", "internal-192.test"] {
        let result = timeout(
            Duration::from_secs(5),
            client.get(format!("https://{}/", host)).send(),
        )
        .await;

        assert!(
            result.expect("timeout").is_err(),
            "Connection to {} should be denied by CIDR rule",
            host
        );
    }
}

/// Test that CIDR rules work together with host-based rules.
///
/// Scenario: Allow specific host, but deny if it resolves to private IP.
#[tokio::test]
async fn test_cidr_and_host_rules_combined() {
    let upstream_port = find_available_port().await;
    let proxy_port = find_available_port().await;
    let temp_dir = tempfile::tempdir().expect("temp dir");

    // Start upstream server
    let (upstream_cert, _upstream_handle) = spawn_https_server(upstream_port).await;

    // Start proxy: allow specific host, but deny private IPs
    // Order matters: CIDR deny should be checked AFTER DNS resolution
    let _proxy_handle = spawn_proxy(
        ProxyConfig {
            listen_port: proxy_port,
            rules: vec![
                // First deny private IPs (checked after DNS resolution)
                rule_cidr("deny", "10.0.0.0/8"),
                // Then allow the host (but it resolves to 10.x.x.x)
                RuleSpec::host("allow", "rebind.test"),
                // Also allow localhost for comparison
                RuleSpec::host("allow", "localhost"),
            ],
            auth: None,
            upstream_ca_pem: Some(upstream_cert.clone()),
            credentials_toml: vec![],
            // rebind.test points to private IP (simulated attack)
            dns_hosts: vec![("rebind.test", "10.0.0.1")],
            ..Default::default()
        },
        &temp_dir,
    )
    .await;

    let client = client_with_proxy(proxy_port, &temp_dir.path().join("ca.pem"), None);

    // rebind.test is "allowed" by host rule but resolves to 10.0.0.1
    // CIDR rule should block it
    let result = timeout(
        Duration::from_secs(5),
        client.get("https://rebind.test/").send(),
    )
    .await;

    assert!(
        result.expect("timeout").is_err(),
        "Connection to rebind.test (10.0.0.1) should be denied by CIDR rule"
    );

    // Meanwhile, localhost should work fine
    let url = format!("https://localhost:{}/get", upstream_port);
    let result = timeout(Duration::from_secs(5), client.get(&url).send()).await;
    let response = result.expect("timeout").expect("localhost request");
    assert_eq!(response.status(), StatusCode::OK);
}

/// Test that CIDR allow rules can permit specific internal services.
#[tokio::test]
async fn test_cidr_allows_specific_internal() {
    let upstream_port = find_available_port().await;
    let proxy_port = find_available_port().await;
    let temp_dir = tempfile::tempdir().expect("temp dir");

    let (upstream_cert, _upstream_handle) = spawn_https_server(upstream_port).await;

    // Proxy config: deny all private IPs EXCEPT specific allowed ones
    // Map "allowed-internal.test" to 127.0.0.1 so we can actually connect
    let _proxy_handle = spawn_proxy(
        ProxyConfig {
            listen_port: proxy_port,
            rules: vec![
                // Allow specific internal service
                rule_cidr("allow", "127.0.0.1/32"),
                // Deny all other private ranges
                rule_cidr("deny", "10.0.0.0/8"),
                rule_cidr("deny", "172.16.0.0/12"),
                rule_cidr("deny", "192.168.0.0/16"),
            ],
            auth: None,
            upstream_ca_pem: Some(upstream_cert.clone()),
            credentials_toml: vec![],
            // Map test host to loopback (our test server)
            dns_hosts: vec![("allowed-internal.test", "127.0.0.1")],
            ..Default::default()
        },
        &temp_dir,
    )
    .await;

    let client = client_with_proxy(proxy_port, &temp_dir.path().join("ca.pem"), None);

    // allowed-internal.test -> 127.0.0.1 should work (CIDR allow)
    let url = format!("https://allowed-internal.test:{}/get", upstream_port);
    let result = timeout(Duration::from_secs(5), client.get(&url).send()).await;
    let response = result.expect("timeout").expect("allowed internal request");
    assert_eq!(response.status(), StatusCode::OK);
}

// ============================================================================
// OAuth Token Redaction Tests
// ============================================================================

#[tokio::test]
async fn test_oauth_token_redaction() {
    // This test verifies that OAuth tokens in responses are redacted and replaced
    // with dummy tokens that the proxy can later swap back to real tokens.
    let upstream_port = find_available_port().await;
    let proxy_port = find_available_port().await;
    let temp_dir = tempfile::tempdir().expect("temp dir");

    // Start upstream HTTPS server (has /oauth/token endpoint)
    let (upstream_cert, _upstream_handle) = spawn_https_server(upstream_port).await;

    // Start proxy with token redaction enabled for /oauth/token path
    let _proxy_handle = spawn_proxy(
        ProxyConfig {
            listen_port: proxy_port,
            rules: vec![RuleSpec::host_with_redact(
                "allow",
                "localhost",
                vec!["/oauth/token"],
            )],
            upstream_ca_pem: Some(upstream_cert.clone()),
            ..Default::default()
        },
        &temp_dir,
    )
    .await;

    // Build client
    let client = client_with_proxy(proxy_port, &temp_dir.path().join("ca.pem"), None);

    // Make request to /oauth/token - response should have redacted tokens
    let url = format!("https://localhost:{}/oauth/token", upstream_port);
    let result = timeout(Duration::from_secs(5), client.post(&url).send()).await;

    let response = result.expect("timeout").expect("request");
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await.expect("body");

    // Parse the response as JSON
    let json: serde_json::Value = serde_json::from_str(&body).expect("parse JSON response");

    // Verify tokens are redacted (format is ALICE_{TYPE}_{id}, not the real tokens)
    let access_token = json["access_token"].as_str().expect("access_token field");
    let refresh_token = json["refresh_token"].as_str().expect("refresh_token field");
    let id_token = json["id_token"].as_str().expect("id_token field");

    assert!(
        access_token.starts_with("ALICE_ACCESS_"),
        "access_token should be redacted, got: {}",
        access_token
    );
    assert!(
        !access_token.contains("real_access_token"),
        "access_token should NOT contain real token, got: {}",
        access_token
    );

    assert!(
        refresh_token.starts_with("ALICE_REFRESH_"),
        "refresh_token should be redacted, got: {}",
        refresh_token
    );
    assert!(
        !refresh_token.contains("real_refresh_token"),
        "refresh_token should NOT contain real token, got: {}",
        refresh_token
    );

    assert!(
        id_token.starts_with("ALICE_ID_"),
        "id_token should be redacted, got: {}",
        id_token
    );
    assert!(
        !id_token.contains("real_id_token"),
        "id_token should NOT contain real token, got: {}",
        id_token
    );

    // Non-token fields should be unchanged
    assert_eq!(json["token_type"], "Bearer");
    assert_eq!(json["expires_in"], 3600);
}

#[tokio::test]
async fn test_oauth_token_no_redaction_when_not_configured() {
    // This test verifies that OAuth tokens are NOT redacted when redact_paths is empty
    let upstream_port = find_available_port().await;
    let proxy_port = find_available_port().await;
    let temp_dir = tempfile::tempdir().expect("temp dir");

    // Start upstream HTTPS server
    let (upstream_cert, _upstream_handle) = spawn_https_server(upstream_port).await;

    // Start proxy WITHOUT token redaction
    let _proxy_handle = spawn_proxy(
        ProxyConfig {
            listen_port: proxy_port,
            rules: vec![RuleSpec::host("allow", "localhost")],
            upstream_ca_pem: Some(upstream_cert.clone()),
            ..Default::default()
        },
        &temp_dir,
    )
    .await;

    // Build client
    let client = client_with_proxy(proxy_port, &temp_dir.path().join("ca.pem"), None);

    // Make request to /oauth/token - tokens should NOT be redacted
    let url = format!("https://localhost:{}/oauth/token", upstream_port);
    let result = timeout(Duration::from_secs(5), client.post(&url).send()).await;

    let response = result.expect("timeout").expect("request");
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await.expect("body");

    // Parse the response as JSON
    let json: serde_json::Value = serde_json::from_str(&body).expect("parse JSON response");

    // Verify tokens are NOT redacted (should be real_xxx_token)
    let access_token = json["access_token"].as_str().expect("access_token field");
    assert!(
        access_token.contains("real_access_token"),
        "access_token should NOT be redacted when not configured, got: {}",
        access_token
    );
}

#[tokio::test]
async fn test_oauth_token_replacement_on_request() {
    // This test verifies that dummy tokens in outbound requests are replaced
    // with real tokens that were previously redacted.
    let upstream_port = find_available_port().await;
    let proxy_port = find_available_port().await;
    let temp_dir = tempfile::tempdir().expect("temp dir");

    // Start upstream HTTPS server
    let (upstream_cert, _upstream_handle) = spawn_https_server(upstream_port).await;

    // Start proxy with token redaction enabled
    let _proxy_handle = spawn_proxy(
        ProxyConfig {
            listen_port: proxy_port,
            rules: vec![RuleSpec::host_with_redact(
                "allow",
                "localhost",
                vec!["/oauth/token"],
            )],
            upstream_ca_pem: Some(upstream_cert.clone()),
            ..Default::default()
        },
        &temp_dir,
    )
    .await;

    // Build client
    let client = client_with_proxy(proxy_port, &temp_dir.path().join("ca.pem"), None);

    // Step 1: Get OAuth tokens (they will be redacted in response)
    let url = format!("https://localhost:{}/oauth/token", upstream_port);
    let result = timeout(Duration::from_secs(5), client.post(&url).send()).await;
    let response = result.expect("timeout").expect("token request");
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await.expect("body");

    let json: serde_json::Value = serde_json::from_str(&body).expect("parse JSON");
    let dummy_access_token = json["access_token"].as_str().expect("access_token");

    // Verify we got a dummy token (format is ALICE_ACCESS_{id})
    assert!(
        dummy_access_token.starts_with("ALICE_ACCESS_"),
        "Should have received a dummy token, got: {}",
        dummy_access_token
    );

    // Step 2: Use the dummy token in an Authorization header - it should be replaced
    // with the real token before being sent to the upstream server
    let url = format!("https://localhost:{}/headers", upstream_port);
    let result = timeout(
        Duration::from_secs(5),
        client
            .get(&url)
            .header("Authorization", format!("Bearer {}", dummy_access_token))
            .send(),
    )
    .await;

    let response = result.expect("timeout").expect("headers request");
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await.expect("body");

    // The /headers endpoint echoes back what it received
    // The proxy should have replaced the dummy token with the real one
    assert!(
        body.contains("real_access_token_abc123"),
        "Dummy token should have been replaced with real token, got: {}",
        body
    );
    assert!(
        !body.contains("ALICE_ACCESS_"),
        "Dummy token should NOT appear in upstream request, got: {}",
        body
    );
}

// ============================================================================
// SSE Streaming Tests
// ============================================================================

#[tokio::test]
async fn test_sse_streaming_h1() {
    // Test that SSE events are delivered incrementally through the proxy,
    // not buffered until the stream ends. This is critical for Claude Code
    // which uses SSE for streaming API responses.
    let upstream_port = find_available_port().await;
    let proxy_port = find_available_port().await;
    let temp_dir = tempfile::tempdir().expect("temp dir");

    // Start upstream HTTPS server (H1 only to test H1 inspection path)
    let (upstream_cert, _upstream_handle) = spawn_https_server_h1_only(upstream_port).await;

    // Start proxy allowing localhost
    let _proxy_handle = spawn_proxy(
        ProxyConfig {
            listen_port: proxy_port,
            rules: vec![RuleSpec::host("allow", "localhost")],
            upstream_ca_pem: Some(upstream_cert.clone()),
            ..Default::default()
        },
        &temp_dir,
    )
    .await;

    // Build HTTP/1.1-only client
    let client = client_with_proxy_h1_only(proxy_port, &temp_dir.path().join("ca.pem"));

    // Make request to SSE endpoint
    let url = format!("https://localhost:{}/sse", upstream_port);
    let result = timeout(Duration::from_secs(10), client.get(&url).send()).await;

    let response = result.expect("timeout").expect("request");
    assert_eq!(response.status(), StatusCode::OK);

    // Read all SSE events, tracking when each arrives
    let mut events = Vec::new();
    let mut event_times = Vec::new();
    let start = Instant::now();
    let mut stream = response.bytes_stream();
    use futures_util::StreamExt;

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.expect("chunk");
        let text = String::from_utf8_lossy(&chunk);
        event_times.push(start.elapsed());
        // Parse SSE events from chunk
        for line in text.lines() {
            if let Some(data) = line.strip_prefix("data: ") {
                events.push(data.to_string());
            }
        }
    }

    // We should have received all 5 events
    assert_eq!(events.len(), 5, "Expected 5 SSE events, got: {:?}", events);

    // Critical check: events should arrive incrementally, not all at once.
    // The server sends events 50ms apart, so if we received them all at once
    // (buffered), total time would be ~250ms but all event_times would cluster.
    // If streamed properly, events should be spread over ~200ms.
    //
    // Check that the time span from first to last chunk is at least 100ms
    // (conservative - server sends over 200ms total)
    if event_times.len() >= 2 {
        let first = event_times.first().unwrap();
        let last = event_times.last().unwrap();
        let span = *last - *first;
        assert!(
            span >= Duration::from_millis(100),
            "SSE events should arrive incrementally, not all at once. \
             Time span from first to last chunk: {:?} (expected >= 100ms). \
             This means the proxy is buffering the entire response. \
             Event times: {:?}",
            span,
            event_times,
        );
    }
}

#[tokio::test]
async fn test_sse_streaming_h1_with_inspection() {
    // Test SSE streaming through the H1 inspection path.
    // This is triggered by having a path-based rule, which forces the proxy
    // to parse every HTTP request on the connection (not just bidirectional copy).
    // This is the code path that Claude Code hits because it has redact_paths.
    let upstream_port = find_available_port().await;
    let proxy_port = find_available_port().await;
    let temp_dir = tempfile::tempdir().expect("temp dir");

    // Start upstream HTTPS server (H1 only)
    let (upstream_cert, _upstream_handle) = spawn_https_server_h1_only(upstream_port).await;

    // Use a path rule to force the inspection path
    let _proxy_handle = spawn_proxy(
        ProxyConfig {
            listen_port: proxy_port,
            rules: vec![
                rule_host_path("allow", "localhost", "/sse"),
                rule_host_path("allow", "localhost", "/get"),
            ],
            upstream_ca_pem: Some(upstream_cert.clone()),
            ..Default::default()
        },
        &temp_dir,
    )
    .await;

    // Build HTTP/1.1-only client
    let client = client_with_proxy_h1_only(proxy_port, &temp_dir.path().join("ca.pem"));

    // Make request to SSE endpoint
    let url = format!("https://localhost:{}/sse", upstream_port);
    let result = timeout(Duration::from_secs(10), client.get(&url).send()).await;

    let response = result.expect("timeout").expect("request");
    assert_eq!(response.status(), StatusCode::OK);

    // Read all SSE events, tracking when each arrives
    let mut events = Vec::new();
    let mut event_times = Vec::new();
    let start = Instant::now();
    let mut stream = response.bytes_stream();
    use futures_util::StreamExt;

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.expect("chunk");
        let text = String::from_utf8_lossy(&chunk);
        event_times.push(start.elapsed());
        for line in text.lines() {
            if let Some(data) = line.strip_prefix("data: ") {
                events.push(data.to_string());
            }
        }
    }

    // We should have received all 5 events
    assert_eq!(events.len(), 5, "Expected 5 SSE events, got: {:?}", events);

    // Check incremental delivery
    if event_times.len() >= 2 {
        let first = event_times.first().unwrap();
        let last = event_times.last().unwrap();
        let span = *last - *first;
        assert!(
            span >= Duration::from_millis(100),
            "SSE events through H1 inspection path should arrive incrementally. \
             Time span from first to last chunk: {:?} (expected >= 100ms). \
             This means the proxy is buffering the entire response in proxy_with_inspection(). \
             Event times: {:?}",
            span,
            event_times,
        );
    }
}

#[tokio::test]
async fn test_sse_streaming_h2() {
    // Test SSE streaming through the H2-to-H2 proxy path
    let upstream_port = find_available_port().await;
    let proxy_port = find_available_port().await;
    let temp_dir = tempfile::tempdir().expect("temp dir");

    // Start upstream HTTPS server (with H2 support)
    let (upstream_cert, _upstream_handle) = spawn_https_server(upstream_port).await;

    // Start proxy allowing localhost
    let _proxy_handle = spawn_proxy(
        ProxyConfig {
            listen_port: proxy_port,
            rules: vec![RuleSpec::host("allow", "localhost")],
            upstream_ca_pem: Some(upstream_cert.clone()),
            ..Default::default()
        },
        &temp_dir,
    )
    .await;

    // Build H2-capable client
    let client = client_with_proxy_h2(
        proxy_port,
        &temp_dir.path().join("ca.pem"),
        Some(&upstream_cert),
    );

    // Make request to SSE endpoint
    let url = format!("https://localhost:{}/sse", upstream_port);
    let result = timeout(Duration::from_secs(10), client.get(&url).send()).await;

    let response = result.expect("timeout").expect("request");
    assert_eq!(response.status(), StatusCode::OK);

    // Read all SSE events, tracking when each arrives
    let mut events = Vec::new();
    let mut event_times = Vec::new();
    let start = Instant::now();
    let mut stream = response.bytes_stream();
    use futures_util::StreamExt;

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.expect("chunk");
        let text = String::from_utf8_lossy(&chunk);
        event_times.push(start.elapsed());
        for line in text.lines() {
            if let Some(data) = line.strip_prefix("data: ") {
                events.push(data.to_string());
            }
        }
    }

    // We should have received all 5 events
    assert_eq!(events.len(), 5, "Expected 5 SSE events, got: {:?}", events);

    // Same incremental delivery check
    if event_times.len() >= 2 {
        let first = event_times.first().unwrap();
        let last = event_times.last().unwrap();
        let span = *last - *first;
        assert!(
            span >= Duration::from_millis(100),
            "SSE events should arrive incrementally over H2, not all at once. \
             Time span from first to last chunk: {:?} (expected >= 100ms). \
             Event times: {:?}",
            span,
            event_times,
        );
    }
}

// ============================================================================
// LLM Metrics Parsing Tests
// ============================================================================
//
// These tests verify that the proxy correctly parses streaming SSE responses
// from the Anthropic Messages API and emits structured `llm.completion`
// tracing events with model, token counts, and tool call details.

#[tokio::test]
async fn test_llm_metrics_h1_single_tool() {
    // Test that LLM metrics are extracted from a streaming /v1/messages response
    // through the HTTP/1.1 inspection path (proxy_with_inspection).
    let upstream_port = find_available_port().await;
    let proxy_port = find_available_port().await;
    let metrics_port = find_available_port().await;
    let temp_dir = tempfile::tempdir().expect("temp dir");

    // Start upstream mock with /v1/messages serving single-tool SSE fixture
    let (upstream_cert, _upstream_handle) =
        spawn_https_server_with_app(upstream_port, llm_router(LLM_SSE_SINGLE_TOOL), false).await;

    // Start proxy with path-based rule (forces inspection path) and metrics endpoint
    let _proxy = spawn_proxy(
        ProxyConfig {
            listen_port: proxy_port,
            rules: vec![rule_host_path("allow", "localhost", "/v1/messages")],
            auth: None,
            upstream_ca_pem: Some(upstream_cert.clone()),
            credentials_toml: vec![],
            metrics_port: Some(metrics_port),
            ..Default::default()
        },
        &temp_dir,
    )
    .await;

    // Build HTTP/1.1-only client
    let client = client_with_proxy_h1_only(proxy_port, &temp_dir.path().join("ca.pem"));

    // POST to /v1/messages — this triggers LLM metrics parsing
    let url = format!("https://localhost:{}/v1/messages", upstream_port);
    let result = timeout(Duration::from_secs(10), client.post(&url).send()).await;

    let response = result.expect("timeout").expect("request");
    assert_eq!(response.status(), StatusCode::OK);

    // Consume the entire response body so the stream completes
    let _body = response.bytes().await.expect("body");

    // Small delay to let the proxy push metrics to the store
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Query the metrics endpoint
    let metrics_client = reqwest::Client::new();
    let metrics_url = format!("http://127.0.0.1:{}/llm/completions", metrics_port);
    let metrics_resp = metrics_client
        .get(&metrics_url)
        .send()
        .await
        .expect("metrics request");
    let body = metrics_resp.text().await.expect("metrics body");
    let completions: Vec<serde_json::Value> =
        serde_json::from_str(&body).expect("parse metrics JSON");

    assert_eq!(
        completions.len(),
        1,
        "Expected exactly 1 LLM completion metric, got {}",
        completions.len(),
    );

    let m = &completions[0];
    assert_eq!(m["model"], "claude-opus-4-6");
    assert_eq!(m["input_tokens"], 3);
    assert_eq!(m["output_tokens"], 78);
    assert_eq!(m["cache_read_tokens"], 21612);

    let tool_calls = m["tool_calls"].as_array().expect("tool_calls is array");
    assert_eq!(tool_calls.len(), 1);
    assert_eq!(tool_calls[0]["name"], "Bash");
    assert_eq!(
        tool_calls[0]["arguments"]["command"],
        "cargo fmt --check 2>&1"
    );
    assert_eq!(
        tool_calls[0]["arguments"]["description"],
        "Check formatting"
    );
}

#[tokio::test]
async fn test_llm_metrics_h1_text_only() {
    // Test text-only response (no tool calls) — verify token counts and empty tool_calls
    let upstream_port = find_available_port().await;
    let proxy_port = find_available_port().await;
    let metrics_port = find_available_port().await;
    let temp_dir = tempfile::tempdir().expect("temp dir");

    let (upstream_cert, _upstream_handle) =
        spawn_https_server_with_app(upstream_port, llm_router(LLM_SSE_TEXT_ONLY), false).await;

    let _proxy = spawn_proxy(
        ProxyConfig {
            listen_port: proxy_port,
            rules: vec![rule_host_path("allow", "localhost", "/v1/messages")],
            auth: None,
            upstream_ca_pem: Some(upstream_cert.clone()),
            credentials_toml: vec![],
            metrics_port: Some(metrics_port),
            ..Default::default()
        },
        &temp_dir,
    )
    .await;

    let client = client_with_proxy_h1_only(proxy_port, &temp_dir.path().join("ca.pem"));

    let url = format!("https://localhost:{}/v1/messages", upstream_port);
    let result = timeout(Duration::from_secs(10), client.post(&url).send()).await;
    let response = result.expect("timeout").expect("request");
    assert_eq!(response.status(), StatusCode::OK);
    let _body = response.bytes().await.expect("body");

    tokio::time::sleep(Duration::from_millis(100)).await;

    let metrics_client = reqwest::Client::new();
    let metrics_url = format!("http://127.0.0.1:{}/llm/completions", metrics_port);
    let metrics_resp = metrics_client
        .get(&metrics_url)
        .send()
        .await
        .expect("metrics request");
    let body = metrics_resp.text().await.expect("metrics body");
    let completions: Vec<serde_json::Value> =
        serde_json::from_str(&body).expect("parse metrics JSON");

    assert_eq!(
        completions.len(),
        1,
        "Expected exactly 1 LLM completion metric, got {}",
        completions.len(),
    );

    let m = &completions[0];
    assert_eq!(m["model"], "claude-haiku-4-5-20251001");
    assert_eq!(m["input_tokens"], 291);
    assert_eq!(m["output_tokens"], 14);
    assert_eq!(m["cache_read_tokens"], 0);

    let tool_calls = m["tool_calls"].as_array().expect("tool_calls is array");
    assert!(tool_calls.is_empty());
}

#[tokio::test]
async fn test_llm_metrics_h2() {
    // Test LLM metrics through the HTTP/2 proxy path (handle_stream in h2.rs).
    let upstream_port = find_available_port().await;
    let proxy_port = find_available_port().await;
    let metrics_port = find_available_port().await;
    let temp_dir = tempfile::tempdir().expect("temp dir");

    // Start upstream mock with H2 enabled
    let (upstream_cert, _upstream_handle) =
        spawn_https_server_with_app(upstream_port, llm_router(LLM_SSE_SINGLE_TOOL), true).await;

    let _proxy = spawn_proxy(
        ProxyConfig {
            listen_port: proxy_port,
            rules: vec![rule_host_path("allow", "localhost", "/v1/messages")],
            auth: None,
            upstream_ca_pem: Some(upstream_cert.clone()),
            credentials_toml: vec![],
            metrics_port: Some(metrics_port),
            ..Default::default()
        },
        &temp_dir,
    )
    .await;

    // Build H2 client
    let client = client_with_proxy_h2(
        proxy_port,
        &temp_dir.path().join("ca.pem"),
        Some(&upstream_cert),
    );

    let url = format!("https://localhost:{}/v1/messages", upstream_port);
    let result = timeout(Duration::from_secs(10), client.post(&url).send()).await;
    let response = result.expect("timeout").expect("request");
    assert_eq!(response.status(), StatusCode::OK);
    // Verify we actually got HTTP/2
    assert_eq!(response.version(), reqwest::Version::HTTP_2);
    let _body = response.bytes().await.expect("body");

    tokio::time::sleep(Duration::from_millis(100)).await;

    let metrics_client = reqwest::Client::new();
    let metrics_url = format!("http://127.0.0.1:{}/llm/completions", metrics_port);
    let metrics_resp = metrics_client
        .get(&metrics_url)
        .send()
        .await
        .expect("metrics request");
    let body = metrics_resp.text().await.expect("metrics body");
    let completions: Vec<serde_json::Value> =
        serde_json::from_str(&body).expect("parse metrics JSON");

    assert_eq!(
        completions.len(),
        1,
        "Expected exactly 1 LLM completion metric via H2, got {}",
        completions.len(),
    );

    let m = &completions[0];
    assert_eq!(m["model"], "claude-opus-4-6");
    assert_eq!(m["input_tokens"], 3);
    assert_eq!(m["output_tokens"], 78);
    assert_eq!(m["cache_read_tokens"], 21612);

    let tool_calls = m["tool_calls"].as_array().expect("tool_calls is array");
    assert_eq!(tool_calls.len(), 1);
    assert_eq!(tool_calls[0]["name"], "Bash");
}

// ============================================================================
// System Prompt Injection Tests
// ============================================================================

#[tokio::test]
async fn test_system_prompt_injection_h1() {
    // Test that the proxy appends a suffix to the system prompt in /v1/messages requests.
    // Uses an echo endpoint that returns the request body so we can inspect the modification.
    let upstream_port = find_available_port().await;
    let proxy_port = find_available_port().await;
    let temp_dir = tempfile::tempdir().expect("temp dir");

    let (upstream_cert, _upstream_handle) =
        spawn_https_server_with_app(upstream_port, echo_router(), false).await;

    let _proxy = spawn_proxy(
        ProxyConfig {
            listen_port: proxy_port,
            rules: vec![rule_host_path("allow", "localhost", "/v1/messages")],
            upstream_ca_pem: Some(upstream_cert.clone()),
            transforms_toml: vec![
                "\n[[transforms]]\ntype = \"system_prompt\"\nsuffix = \"Always mention John Cena.\"\n".to_string(),
            ],
            ..Default::default()
        },
        &temp_dir,
    )
    .await;

    let client = client_with_proxy_h1_only(proxy_port, &temp_dir.path().join("ca.pem"));

    // Send a /v1/messages request with a string system prompt
    let url = format!("https://localhost:{}/v1/messages", upstream_port);
    let body = serde_json::json!({
        "model": "claude-opus-4-6",
        "system": "You are a helpful assistant.",
        "messages": [{"role": "user", "content": "Hello"}]
    });

    let result = timeout(
        Duration::from_secs(10),
        client
            .post(&url)
            .header("content-type", "application/json")
            .body(serde_json::to_string(&body).unwrap())
            .send(),
    )
    .await;

    let response = result.expect("timeout").expect("request");
    assert_eq!(response.status(), StatusCode::OK);

    // The echo endpoint returns the body the proxy forwarded to upstream
    let echoed: serde_json::Value =
        serde_json::from_str(&response.text().await.expect("body")).expect("parse echoed JSON");

    assert_eq!(
        echoed["system"],
        "You are a helpful assistant.\n\nAlways mention John Cena."
    );
    // Other fields should be preserved
    assert_eq!(echoed["model"], "claude-opus-4-6");
    assert!(echoed["messages"].is_array());
}

#[tokio::test]
async fn test_system_prompt_injection_absent_system() {
    // When the request has no "system" field, the proxy should add one.
    let upstream_port = find_available_port().await;
    let proxy_port = find_available_port().await;
    let temp_dir = tempfile::tempdir().expect("temp dir");

    let (upstream_cert, _upstream_handle) =
        spawn_https_server_with_app(upstream_port, echo_router(), false).await;

    let _proxy = spawn_proxy(
        ProxyConfig {
            listen_port: proxy_port,
            rules: vec![rule_host_path("allow", "localhost", "/v1/messages")],
            upstream_ca_pem: Some(upstream_cert.clone()),
            transforms_toml: vec![
                "\n[[transforms]]\ntype = \"system_prompt\"\nsuffix = \"Always mention John Cena.\"\n".to_string(),
            ],
            ..Default::default()
        },
        &temp_dir,
    )
    .await;

    let client = client_with_proxy_h1_only(proxy_port, &temp_dir.path().join("ca.pem"));

    // Send without a system field
    let url = format!("https://localhost:{}/v1/messages", upstream_port);
    let body = serde_json::json!({
        "model": "claude-opus-4-6",
        "messages": [{"role": "user", "content": "Hello"}]
    });

    let result = timeout(
        Duration::from_secs(10),
        client
            .post(&url)
            .header("content-type", "application/json")
            .body(serde_json::to_string(&body).unwrap())
            .send(),
    )
    .await;

    let response = result.expect("timeout").expect("request");
    assert_eq!(response.status(), StatusCode::OK);

    let echoed: serde_json::Value =
        serde_json::from_str(&response.text().await.expect("body")).expect("parse echoed JSON");

    assert_eq!(echoed["system"], "Always mention John Cena.");
}

#[tokio::test]
async fn test_system_prompt_injection_non_messages_unmodified() {
    // Non-/v1/messages paths should NOT have their body modified.
    let upstream_port = find_available_port().await;
    let proxy_port = find_available_port().await;
    let temp_dir = tempfile::tempdir().expect("temp dir");

    let (upstream_cert, _upstream_handle) = spawn_https_server(upstream_port).await;

    let _proxy = spawn_proxy(
        ProxyConfig {
            listen_port: proxy_port,
            rules: vec![RuleSpec::host("allow", "localhost")],
            upstream_ca_pem: Some(upstream_cert.clone()),
            transforms_toml: vec![
                "\n[[transforms]]\ntype = \"system_prompt\"\nsuffix = \"Always mention John Cena.\"\n".to_string(),
            ],
            ..Default::default()
        },
        &temp_dir,
    )
    .await;

    let client = client_with_proxy_h1_only(proxy_port, &temp_dir.path().join("ca.pem"));

    // A simple GET request should work fine and not be affected
    let url = format!("https://localhost:{}/get", upstream_port);
    let result = timeout(Duration::from_secs(5), client.get(&url).send()).await;
    let response = result.expect("timeout").expect("request");
    assert_eq!(response.status(), StatusCode::OK);
}

// ============================================================================
// Prometheus Metrics Tests
// ============================================================================

/// Helper: fetch /metrics from the metrics server and return the body as a string.
async fn fetch_prometheus_metrics(metrics_port: u16) -> String {
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{}/metrics", metrics_port);
    let resp = client.get(&url).send().await.expect("metrics request");
    assert_eq!(resp.status(), StatusCode::OK);
    resp.text().await.expect("metrics body")
}

/// Helper: extract the value of a Prometheus counter line matching the given labels.
///
/// Looks for a line like:
///   alice_requests_total{host="localhost",method="GET",status_code="200",action="allow"} 2
///
/// Returns the counter value, or None if no matching line is found.
fn extract_counter(metrics: &str, name: &str, labels: &[(&str, &str)]) -> Option<f64> {
    for line in metrics.lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        // Match metric name
        if !line.starts_with(name) {
            continue;
        }
        // Check all labels are present
        let all_match = labels
            .iter()
            .all(|(k, v)| line.contains(&format!("{}=\"{}\"", k, v)));
        if all_match {
            // Value is the last whitespace-separated token
            if let Some(val_str) = line.split_whitespace().last() {
                return val_str.parse::<f64>().ok();
            }
        }
    }
    None
}

#[tokio::test]
async fn test_prometheus_request_metrics() {
    // Verifies that alice_requests_total, alice_request_bytes_total, and
    // alice_response_bytes_total are incremented for allowed and denied requests.
    let upstream_port = find_available_port().await;
    let proxy_port = find_available_port().await;
    let metrics_port = find_available_port().await;
    let temp_dir = tempfile::tempdir().expect("temp dir");

    let (upstream_cert, _upstream_handle) = spawn_https_server(upstream_port).await;

    // Only allow /get, deny everything else by default
    let _proxy = spawn_proxy(
        ProxyConfig {
            listen_port: proxy_port,
            rules: vec![rule_host_path("allow", "localhost", "/get")],
            upstream_ca_pem: Some(upstream_cert.clone()),
            metrics_port: Some(metrics_port),
            ..Default::default()
        },
        &temp_dir,
    )
    .await;

    let client = client_with_proxy_h1_only(proxy_port, &temp_dir.path().join("ca.pem"));

    // Make 2 allowed GET requests
    for _ in 0..2 {
        let url = format!("https://localhost:{}/get", upstream_port);
        let resp = timeout(Duration::from_secs(5), client.get(&url).send())
            .await
            .expect("timeout")
            .expect("request");
        assert_eq!(resp.status(), StatusCode::OK);
        let _ = resp.bytes().await;
    }

    // Make 1 denied request (path /post is not allowed)
    let url = format!("https://localhost:{}/post", upstream_port);
    let resp = timeout(Duration::from_secs(5), client.post(&url).send())
        .await
        .expect("timeout")
        .expect("request");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let _ = resp.bytes().await;

    // Give the proxy a moment to flush metrics
    tokio::time::sleep(Duration::from_millis(100)).await;

    let metrics = fetch_prometheus_metrics(metrics_port).await;

    // Verify allowed request counter
    let allowed = extract_counter(
        &metrics,
        "alice_requests_total",
        &[
            ("host", "localhost"),
            ("method", "GET"),
            ("status_code", "200"),
            ("action", "allow"),
        ],
    );
    assert_eq!(
        allowed,
        Some(2.0),
        "Expected 2 allowed GET requests.\nFull /metrics:\n{}",
        metrics,
    );

    // Verify denied request counter
    let denied = extract_counter(
        &metrics,
        "alice_requests_total",
        &[
            ("host", "localhost"),
            ("method", "POST"),
            ("status_code", "403"),
            ("action", "deny"),
        ],
    );
    assert_eq!(
        denied,
        Some(1.0),
        "Expected 1 denied POST request.\nFull /metrics:\n{}",
        metrics,
    );

    // Verify request bytes counter exists and is positive
    let req_bytes = extract_counter(
        &metrics,
        "alice_request_bytes_total",
        &[("host", "localhost")],
    );
    assert!(
        req_bytes.unwrap_or(0.0) > 0.0,
        "Expected positive request bytes.\nFull /metrics:\n{}",
        metrics,
    );

    // Verify response bytes counter exists and is positive
    let resp_bytes = extract_counter(
        &metrics,
        "alice_response_bytes_total",
        &[("host", "localhost")],
    );
    assert!(
        resp_bytes.unwrap_or(0.0) > 0.0,
        "Expected positive response bytes.\nFull /metrics:\n{}",
        metrics,
    );
}

#[tokio::test]
async fn test_prometheus_credential_metrics() {
    // Verifies that alice_credential_injections_total is incremented when
    // credentials are injected.
    let upstream_port = find_available_port().await;
    let proxy_port = find_available_port().await;
    let metrics_port = find_available_port().await;
    let temp_dir = tempfile::tempdir().expect("temp dir");

    std::env::set_var("TEST_PROM_CRED_SECRET", "real-secret");

    let (upstream_cert, _upstream_handle) = spawn_https_server(upstream_port).await;

    let _proxy = spawn_proxy(
        ProxyConfig {
            listen_port: proxy_port,
            rules: vec![RuleSpec::host("allow", "localhost")],
            upstream_ca_pem: Some(upstream_cert.clone()),
            credentials_toml: vec![credential_env(
                "my-api-key",
                "localhost",
                "Authorization",
                "Bearer DUMMY_TOKEN",
                "Bearer {value}",
                "TEST_PROM_CRED_SECRET",
            )],
            metrics_port: Some(metrics_port),
            ..Default::default()
        },
        &temp_dir,
    )
    .await;

    let client = client_with_proxy(proxy_port, &temp_dir.path().join("ca.pem"), None);

    // Make 3 requests with the dummy token — each should trigger credential injection
    for _ in 0..3 {
        let url = format!("https://localhost:{}/headers", upstream_port);
        let resp = timeout(
            Duration::from_secs(5),
            client
                .get(&url)
                .header("Authorization", "Bearer DUMMY_TOKEN")
                .send(),
        )
        .await
        .expect("timeout")
        .expect("request");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.text().await.expect("body");
        assert!(
            body.contains("real-secret"),
            "Credential should have been injected",
        );
    }

    tokio::time::sleep(Duration::from_millis(100)).await;

    let metrics = fetch_prometheus_metrics(metrics_port).await;

    let injections = extract_counter(
        &metrics,
        "alice_credential_injections_total",
        &[("credential_name", "my-api-key"), ("host", "localhost")],
    );
    assert_eq!(
        injections,
        Some(3.0),
        "Expected 3 credential injections.\nFull /metrics:\n{}",
        metrics,
    );

    // Also verify request counter was incremented
    let requests = extract_counter(
        &metrics,
        "alice_requests_total",
        &[
            ("host", "localhost"),
            ("method", "GET"),
            ("action", "allow"),
        ],
    );
    assert_eq!(
        requests,
        Some(3.0),
        "Expected 3 allowed GET requests.\nFull /metrics:\n{}",
        metrics,
    );

    std::env::remove_var("TEST_PROM_CRED_SECRET");
}
