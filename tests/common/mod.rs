//! Shared test infrastructure for integration tests and benchmarks.
#![allow(dead_code)]
// Tests print progress, panic on failure (unwrap/expect), and discard handles.
#![allow(
    clippy::print_stdout,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    unused_results
)]

use std::collections::HashSet;
use std::sync::{Arc, Mutex, Once};
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
use tokio::net::{TcpListener, TcpStream};

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

/// Spawn a mock HTTPS server on an OS-assigned port.
/// Returns (port, cert_pem, handle).
pub async fn spawn_https_server() -> (u16, String, tokio::task::JoinHandle<()>) {
    spawn_https_server_with_app(default_router(), true).await
}

/// Spawn a mock HTTPS server with a custom router on an OS-assigned port.
/// Binds to port 0 to avoid TOCTOU races when tests run in parallel.
/// Returns (port, cert_pem, handle).
pub async fn spawn_https_server_with_app(
    app: Router,
    enable_h2: bool,
) -> (u16, String, tokio::task::JoinHandle<()>) {
    init_crypto_provider();

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

    // Bind to port 0 — the OS assigns an available port atomically,
    // eliminating the TOCTOU race in find_available_port().
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();
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

    (port, cert_pem, handle)
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
#[derive(Default)]
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
    /// Override the default idle timeout (seconds). None = use alice's default.
    pub idle_timeout_secs: Option<u64>,
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

    if let Some(secs) = config.idle_timeout_secs {
        toml.push_str(&format!("idle_timeout_secs = {}\n", secs));
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

    // Wait for the proxy to be reachable.
    //
    // Waiting on the CA cert alone was not enough: the proxy writes it before
    // it binds, so a bind that lost a port race still left the file behind.
    // The test then ran against a proxy that was not listening and failed
    // later with an opaque client-side connect error. Probing the port
    // reports the real problem here instead.
    let addr = format!("127.0.0.1:{}", config.listen_port);
    let mut listening = false;
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        if ca_cert_path.exists() && TcpStream::connect(&addr).await.is_ok() {
            listening = true;
            break;
        }
    }
    assert!(
        listening,
        "proxy never listened on {} (CA cert present: {}) -- \
         it most likely failed to bind the port",
        addr,
        ca_cert_path.exists()
    );

    handle
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Ports already handed out by `find_available_port` in this process.
///
/// Binding port 0 and dropping the listener frees the port again, so two
/// concurrent callers can be handed the same number before either has bound
/// it for real. The integration suite runs ~30 tests in one process, which
/// made that collision routine. Remembering what we issued removes it.
static ISSUED_PORTS: Mutex<Option<HashSet<u16>>> = Mutex::new(None);

/// Find an available port for testing.
///
/// Still a hint rather than a reservation -- a separate process can take the
/// port between this call and the bind -- so callers must verify the server they
/// start is actually reachable. `spawn_proxy` does.
pub async fn find_available_port() -> u16 {
    for _ in 0..100 {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("local addr").port();
        drop(listener);

        let mut issued = ISSUED_PORTS.lock().expect("issued ports");
        if issued.get_or_insert_with(HashSet::new).insert(port) {
            return port;
        }
    }
    panic!("could not find an unused port after 100 attempts");
}

// ============================================================================
// Performance Test Helpers
// ============================================================================

/// Statistics from multiple timing samples
pub struct Stats {
    pub samples: Vec<Duration>,
}

impl Stats {
    pub fn new() -> Self {
        Self { samples: vec![] }
    }

    pub fn add(&mut self, d: Duration) {
        self.samples.push(d);
    }

    pub fn p50(&self) -> Duration {
        let mut sorted = self.samples.clone();
        sorted.sort();
        sorted[sorted.len() / 2]
    }

    pub fn p99(&self) -> Duration {
        let mut sorted = self.samples.clone();
        sorted.sort();
        let idx = (sorted.len() as f64 * 0.99) as usize;
        sorted[idx.min(sorted.len() - 1)]
    }

    pub fn min(&self) -> Duration {
        *self.samples.iter().min().unwrap()
    }

    pub fn max(&self) -> Duration {
        *self.samples.iter().max().unwrap()
    }

    pub fn mean(&self) -> Duration {
        let total: Duration = self.samples.iter().sum();
        total / self.samples.len() as u32
    }
}

pub fn format_duration(d: Duration) -> String {
    let micros = d.as_micros();
    if micros < 1000 {
        format!("{}us", micros)
    } else if micros < 1_000_000 {
        format!("{:.2}ms", micros as f64 / 1000.0)
    } else {
        format!("{:.2}s", micros as f64 / 1_000_000.0)
    }
}

pub fn format_throughput(bytes: usize, duration: Duration) -> String {
    let mb = bytes as f64 / (1024.0 * 1024.0);
    let secs = duration.as_secs_f64();
    let mbps = mb / secs;
    format!("{:.1} MB/s", mbps)
}

pub fn format_overhead(direct: Duration, proxy: Duration) -> String {
    if proxy >= direct {
        let delta = proxy - direct;
        let pct = if direct.is_zero() {
            0.0
        } else {
            (delta.as_secs_f64() / direct.as_secs_f64()) * 100.0
        };
        format!("+{} (+{:.0}%)", format_duration(delta), pct)
    } else {
        let delta = direct - proxy;
        let pct = if direct.is_zero() {
            0.0
        } else {
            (delta.as_secs_f64() / direct.as_secs_f64()) * 100.0
        };
        format!("-{} (-{:.0}%)", format_duration(delta), pct)
    }
}

pub fn print_stats(name: &str, stats: &Stats) {
    println!(
        "  {:<30} p50={:<10} p99={:<10} min={:<10} max={:<10}",
        name,
        format_duration(stats.p50()),
        format_duration(stats.p99()),
        format_duration(stats.min()),
        format_duration(stats.max()),
    );
}

pub fn print_throughput_comparison(label: &str, size: usize, direct: &Stats, proxy: &Stats) {
    println!("  {}:", label);
    println!(
        "    {:<10} {}  (p50={}, p99={})",
        "direct",
        format_throughput(size, direct.mean()),
        format_duration(direct.p50()),
        format_duration(direct.p99()),
    );
    println!(
        "    {:<10} {}  (p50={}, p99={})",
        "proxy",
        format_throughput(size, proxy.mean()),
        format_duration(proxy.p50()),
        format_duration(proxy.p99()),
    );
    println!(
        "    {:<10} {}",
        "overhead",
        format_overhead(direct.p50(), proxy.p50()),
    );
}

/// Measure throughput: warm up once, then time N iterations of GET + full body read.
pub async fn measure_throughput(
    client: &reqwest::Client,
    url: &str,
    expected_size: usize,
    iterations: usize,
) -> Stats {
    // Warm up
    let _ = client.get(url).send().await.unwrap().bytes().await;

    let mut stats = Stats::new();
    for _ in 0..iterations {
        let start = std::time::Instant::now();
        let resp = tokio::time::timeout(Duration::from_secs(30), client.get(url).send())
            .await
            .expect("timeout")
            .expect("request");
        let bytes = resp.bytes().await.expect("read body");
        let elapsed = start.elapsed();
        assert_eq!(bytes.len(), expected_size);
        stats.add(elapsed);
    }
    stats
}

/// Spawn the proxy with a perf-test policy and return the proxy CA cert.
pub async fn spawn_perf_proxy(
    proxy_port: u16,
    rules: Vec<RuleSpec>,
    upstream_cert_pem: Option<&str>,
    temp_dir: &tempfile::TempDir,
) -> (reqwest::Certificate, tokio::task::JoinHandle<()>) {
    let proxy_handle = spawn_proxy(
        ProxyConfig {
            listen_port: proxy_port,
            rules,
            upstream_ca_pem: upstream_cert_pem.map(|s| s.to_string()),
            ..Default::default()
        },
        temp_dir,
    )
    .await;

    let proxy_ca = std::fs::read_to_string(temp_dir.path().join("ca.pem")).expect("read CA");
    let proxy_ca_cert = reqwest::Certificate::from_pem(proxy_ca.as_bytes()).expect("parse CA");

    (proxy_ca_cert, proxy_handle)
}
