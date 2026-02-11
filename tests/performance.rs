//! Performance tests for Alice HTTPS proxy
//!
//! Run with: cargo test --test performance -- --nocapture
//!
//! These tests measure and report timing for key operations:
//! - Certificate issuance (cold and warm cache)
//! - Connection establishment time
//! - Throughput for batch and chunked transfers

mod common;

use common::{
    find_available_port, init_crypto_provider, spawn_https_server, spawn_https_server_with_app,
    spawn_proxy, ProxyConfig, RuleSpec,
};

use axum::{
    body::Body,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use reqwest::Proxy;
use std::time::{Duration, Instant};
use tokio::time::timeout;

// ============================================================================
// Helpers
// ============================================================================

/// Statistics from multiple timing samples
struct Stats {
    samples: Vec<Duration>,
}

impl Stats {
    fn new() -> Self {
        Self { samples: vec![] }
    }

    fn add(&mut self, d: Duration) {
        self.samples.push(d);
    }

    fn p50(&self) -> Duration {
        let mut sorted = self.samples.clone();
        sorted.sort();
        sorted[sorted.len() / 2]
    }

    fn p99(&self) -> Duration {
        let mut sorted = self.samples.clone();
        sorted.sort();
        let idx = (sorted.len() as f64 * 0.99) as usize;
        sorted[idx.min(sorted.len() - 1)]
    }

    fn min(&self) -> Duration {
        *self.samples.iter().min().unwrap()
    }

    fn max(&self) -> Duration {
        *self.samples.iter().max().unwrap()
    }

    fn mean(&self) -> Duration {
        let total: Duration = self.samples.iter().sum();
        total / self.samples.len() as u32
    }
}

fn format_duration(d: Duration) -> String {
    let micros = d.as_micros();
    if micros < 1000 {
        format!("{}us", micros)
    } else if micros < 1_000_000 {
        format!("{:.2}ms", micros as f64 / 1000.0)
    } else {
        format!("{:.2}s", micros as f64 / 1_000_000.0)
    }
}

fn format_throughput(bytes: usize, duration: Duration) -> String {
    let mb = bytes as f64 / (1024.0 * 1024.0);
    let secs = duration.as_secs_f64();
    let mbps = mb / secs;
    format!("{:.1} MB/s", mbps)
}

fn print_stats(name: &str, stats: &Stats) {
    println!(
        "  {:<30} p50={:<10} p99={:<10} min={:<10} max={:<10}",
        name,
        format_duration(stats.p50()),
        format_duration(stats.p99()),
        format_duration(stats.min()),
        format_duration(stats.max()),
    );
}

// ============================================================================
// Certificate Issuance Benchmarks
// ============================================================================

// Note: Cold cache cert generation benchmarks require direct access to the
// CertificateAuthority which isn't exposed. The warm cache test below measures
// the full connection path with cached certificates, which is the common case.

/// Benchmark certificate lookup (warm cache - same host)
#[tokio::test]
async fn perf_cert_issuance_warm() {
    init_crypto_provider();

    let upstream_port = find_available_port().await;
    let proxy_port = find_available_port().await;
    let temp_dir = tempfile::tempdir().expect("temp dir");

    let (upstream_cert, _handle) = spawn_https_server(upstream_port).await;

    let _proxy = spawn_proxy(
        ProxyConfig {
            listen_port: proxy_port,
            rules: vec![RuleSpec::host("allow", "localhost")],
            auth: None,
            upstream_ca_pem: Some(upstream_cert.clone()),
            credentials_toml: vec![],
            dns_hosts: vec![],
            ..Default::default()
        },
        &temp_dir,
    )
    .await;

    let proxy_ca = std::fs::read_to_string(temp_dir.path().join("ca.pem")).expect("read CA");
    let proxy_ca_cert = reqwest::Certificate::from_pem(proxy_ca.as_bytes()).expect("parse CA");

    let mut stats = Stats::new();
    let iterations = 20;

    println!("\n=== Certificate Issuance (Warm Cache) ===");
    println!("  Measuring time with cached certificate...\n");

    // Warm up - first request generates the cert
    let proxy = Proxy::https(format!("http://127.0.0.1:{}", proxy_port)).expect("proxy");
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .add_root_certificate(proxy_ca_cert.clone())
        .build()
        .expect("client");

    let url = format!("https://localhost:{}/get", upstream_port);
    let _ = client.get(&url).send().await;

    // Now measure with warm cache (but fresh TCP connections)
    for _ in 0..iterations {
        // Fresh client = fresh TCP connection, but cert is cached
        let proxy = Proxy::https(format!("http://127.0.0.1:{}", proxy_port)).expect("proxy");
        let client = reqwest::Client::builder()
            .proxy(proxy)
            .add_root_certificate(proxy_ca_cert.clone())
            .build()
            .expect("client");

        let start = Instant::now();
        let result = timeout(Duration::from_secs(10), client.get(&url).send()).await;
        let elapsed = start.elapsed();

        assert!(result.is_ok());
        stats.add(elapsed);
    }

    print_stats("cert_warm (full connection)", &stats);
    println!();
}

// ============================================================================
// Connection Time Benchmarks
// ============================================================================

/// Benchmark full connection establishment (CONNECT + TLS + first byte)
#[tokio::test]
async fn perf_connection_time() {
    init_crypto_provider();

    let upstream_port = find_available_port().await;
    let proxy_port = find_available_port().await;
    let temp_dir = tempfile::tempdir().expect("temp dir");

    let (upstream_cert, _handle) = spawn_https_server(upstream_port).await;

    let _proxy = spawn_proxy(
        ProxyConfig {
            listen_port: proxy_port,
            rules: vec![RuleSpec::host("allow", "localhost")],
            auth: None,
            upstream_ca_pem: Some(upstream_cert.clone()),
            credentials_toml: vec![],
            dns_hosts: vec![],
            ..Default::default()
        },
        &temp_dir,
    )
    .await;

    let proxy_ca = std::fs::read_to_string(temp_dir.path().join("ca.pem")).expect("read CA");
    let proxy_ca_cert = reqwest::Certificate::from_pem(proxy_ca.as_bytes()).expect("parse CA");

    // Warm up cert cache
    let proxy = Proxy::https(format!("http://127.0.0.1:{}", proxy_port)).expect("proxy");
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .add_root_certificate(proxy_ca_cert.clone())
        .build()
        .expect("client");
    let url = format!("https://localhost:{}/get", upstream_port);
    let _ = client.get(&url).send().await;

    let mut stats = Stats::new();
    let iterations = 20;

    println!("\n=== Connection Time ===");
    println!("  Measuring CONNECT + dual TLS handshake + first response byte...\n");

    for _ in 0..iterations {
        // Fresh client for each iteration
        let proxy = Proxy::https(format!("http://127.0.0.1:{}", proxy_port)).expect("proxy");
        let client = reqwest::Client::builder()
            .proxy(proxy)
            .add_root_certificate(proxy_ca_cert.clone())
            .build()
            .expect("client");

        let start = Instant::now();
        let resp = timeout(Duration::from_secs(10), client.get(&url).send())
            .await
            .expect("timeout")
            .expect("request");
        // Read first byte
        let _ = resp.text().await;
        let elapsed = start.elapsed();

        stats.add(elapsed);
    }

    print_stats("connection_time", &stats);
    println!();
}

// ============================================================================
// Throughput Benchmarks
// ============================================================================

/// Create a router that serves large responses
fn throughput_router(size: usize) -> Router {
    Router::new()
        .route("/batch", get(move || async move { batch_response(size) }))
        .route(
            "/chunked",
            get(move || async move { chunked_response(size) }),
        )
}

fn batch_response(size: usize) -> Response {
    let data = vec![b'x'; size];
    Response::builder()
        .status(StatusCode::OK)
        .header("content-length", size.to_string())
        .body(Body::from(data))
        .unwrap()
}

fn chunked_response(size: usize) -> impl IntoResponse {
    // Create chunked response by not setting content-length
    let data = vec![b'x'; size];
    Response::builder()
        .status(StatusCode::OK)
        // No content-length = chunked encoding
        .body(Body::from(data))
        .unwrap()
}

/// Benchmark throughput with Content-Length (batch transfer)
#[tokio::test]
async fn perf_throughput_batch() {
    init_crypto_provider();

    let sizes = [(100 * 1024, "100 KB"), (1024 * 1024, "1 MB")];

    println!("\n=== Throughput (Batch / Content-Length) ===");
    println!("  Measuring download speed through proxy...\n");

    for (size, label) in sizes {
        let upstream_port = find_available_port().await;
        let proxy_port = find_available_port().await;
        let temp_dir = tempfile::tempdir().expect("temp dir");

        let (upstream_cert, _handle) =
            spawn_https_server_with_app(upstream_port, throughput_router(size), true).await;

        let _proxy = spawn_proxy(
            ProxyConfig {
                listen_port: proxy_port,
                rules: vec![RuleSpec::host("allow", "localhost")],
                auth: None,
                upstream_ca_pem: Some(upstream_cert.clone()),
                credentials_toml: vec![],
                dns_hosts: vec![],
                ..Default::default()
            },
            &temp_dir,
        )
        .await;

        let proxy_ca = std::fs::read_to_string(temp_dir.path().join("ca.pem")).expect("read CA");
        let proxy_ca_cert = reqwest::Certificate::from_pem(proxy_ca.as_bytes()).expect("parse CA");

        let proxy = Proxy::https(format!("http://127.0.0.1:{}", proxy_port)).expect("proxy");
        let client = reqwest::Client::builder()
            .proxy(proxy)
            .add_root_certificate(proxy_ca_cert)
            .build()
            .expect("client");

        let url = format!("https://localhost:{}/batch", upstream_port);

        // Warm up
        let _ = client.get(&url).send().await.unwrap().bytes().await;

        let mut stats = Stats::new();
        let iterations = 5;

        for _ in 0..iterations {
            let start = Instant::now();
            let resp = timeout(Duration::from_secs(30), client.get(&url).send())
                .await
                .expect("timeout")
                .expect("request");
            let bytes = resp.bytes().await.expect("read body");
            let elapsed = start.elapsed();

            assert_eq!(bytes.len(), size);
            stats.add(elapsed);
        }

        println!(
            "  {:<10} {}  (p50={}, p99={})",
            label,
            format_throughput(size, stats.mean()),
            format_duration(stats.p50()),
            format_duration(stats.p99()),
        );
    }
    println!();
}

/// Benchmark throughput with chunked transfer encoding
#[tokio::test]
async fn perf_throughput_chunked() {
    init_crypto_provider();

    let sizes = [(100 * 1024, "100 KB"), (1024 * 1024, "1 MB")];

    println!("\n=== Throughput (Chunked Transfer) ===");
    println!("  Measuring download speed with chunked encoding...\n");

    for (size, label) in sizes {
        let upstream_port = find_available_port().await;
        let proxy_port = find_available_port().await;
        let temp_dir = tempfile::tempdir().expect("temp dir");

        let (upstream_cert, _handle) =
            spawn_https_server_with_app(upstream_port, throughput_router(size), true).await;

        let _proxy = spawn_proxy(
            ProxyConfig {
                listen_port: proxy_port,
                rules: vec![RuleSpec::host("allow", "localhost")],
                auth: None,
                upstream_ca_pem: Some(upstream_cert.clone()),
                credentials_toml: vec![],
                dns_hosts: vec![],
                ..Default::default()
            },
            &temp_dir,
        )
        .await;

        let proxy_ca = std::fs::read_to_string(temp_dir.path().join("ca.pem")).expect("read CA");
        let proxy_ca_cert = reqwest::Certificate::from_pem(proxy_ca.as_bytes()).expect("parse CA");

        let proxy = Proxy::https(format!("http://127.0.0.1:{}", proxy_port)).expect("proxy");
        let client = reqwest::Client::builder()
            .proxy(proxy)
            .add_root_certificate(proxy_ca_cert)
            .build()
            .expect("client");

        let url = format!("https://localhost:{}/chunked", upstream_port);

        // Warm up
        let _ = client.get(&url).send().await.unwrap().bytes().await;

        let mut stats = Stats::new();
        let iterations = 5;

        for _ in 0..iterations {
            let start = Instant::now();
            let resp = timeout(Duration::from_secs(30), client.get(&url).send())
                .await
                .expect("timeout")
                .expect("request");
            let bytes = resp.bytes().await.expect("read body");
            let elapsed = start.elapsed();

            assert_eq!(bytes.len(), size);
            stats.add(elapsed);
        }

        println!(
            "  {:<10} {}  (p50={}, p99={})",
            label,
            format_throughput(size, stats.mean()),
            format_duration(stats.p50()),
            format_duration(stats.p99()),
        );
    }
    println!();
}

/// Benchmark HTTP/2 throughput
#[tokio::test]
async fn perf_throughput_h2() {
    init_crypto_provider();

    let size = 1024 * 1024; // 1 MB

    println!("\n=== Throughput (HTTP/2) ===");
    println!("  Measuring download speed with HTTP/2...\n");

    let upstream_port = find_available_port().await;
    let proxy_port = find_available_port().await;
    let temp_dir = tempfile::tempdir().expect("temp dir");

    let (upstream_cert, _handle) =
        spawn_https_server_with_app(upstream_port, throughput_router(size), true).await;

    let _proxy = spawn_proxy(
        ProxyConfig {
            listen_port: proxy_port,
            rules: vec![RuleSpec::host("allow", "localhost")],
            auth: None,
            upstream_ca_pem: Some(upstream_cert.clone()),
            credentials_toml: vec![],
            dns_hosts: vec![],
            ..Default::default()
        },
        &temp_dir,
    )
    .await;

    let proxy_ca = std::fs::read_to_string(temp_dir.path().join("ca.pem")).expect("read CA");
    let proxy_ca_cert = reqwest::Certificate::from_pem(proxy_ca.as_bytes()).expect("parse CA");

    // HTTP/2 client
    let proxy = Proxy::https(format!("http://127.0.0.1:{}", proxy_port)).expect("proxy");
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .add_root_certificate(proxy_ca_cert)
        .use_rustls_tls()
        .http2_adaptive_window(true)
        .build()
        .expect("client");

    let url = format!("https://localhost:{}/batch", upstream_port);

    // Warm up
    let _ = client.get(&url).send().await.unwrap().bytes().await;

    let mut stats = Stats::new();
    let iterations = 5;

    for _ in 0..iterations {
        let start = Instant::now();
        let resp = timeout(Duration::from_secs(30), client.get(&url).send())
            .await
            .expect("timeout")
            .expect("request");

        assert_eq!(resp.version(), reqwest::Version::HTTP_2);

        let bytes = resp.bytes().await.expect("read body");
        let elapsed = start.elapsed();

        assert_eq!(bytes.len(), size);
        stats.add(elapsed);
    }

    println!(
        "  {:<10} {}  (p50={}, p99={})",
        "1 MB",
        format_throughput(size, stats.mean()),
        format_duration(stats.p50()),
        format_duration(stats.p99()),
    );
    println!();
}

// ============================================================================
// Summary Test
// ============================================================================

/// Run all performance measurements and print a summary
#[tokio::test]
async fn perf_summary() {
    println!("\n");
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║              ALICE PROXY PERFORMANCE SUMMARY                 ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();
    println!("Run individual tests for detailed output:");
    println!("  cargo test --test performance perf_cert -- --nocapture");
    println!("  cargo test --test performance perf_connection -- --nocapture");
    println!("  cargo test --test performance perf_throughput -- --nocapture");
    println!();
}
