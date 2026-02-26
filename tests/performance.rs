//! Performance tests for Alice HTTPS proxy
//!
//! These tests are ignored by default (they spawn real proxy instances and
//! measure timing, which is unreliable in CI sandboxes).
//!
//! Run with: cargo test --test performance -- --ignored --nocapture
//!
//! Connection and throughput tests compare direct vs proxy paths to quantify
//! overhead. H2 concurrent stream tests are stress/correctness checks.

mod common;

use common::{
    find_available_port, format_duration, format_overhead, format_throughput, init_crypto_provider,
    measure_throughput, print_stats, print_throughput_comparison, spawn_https_server,
    spawn_https_server_with_app, spawn_perf_proxy, spawn_proxy, ProxyConfig, RuleSpec, Stats,
};

use axum::{
    body::Body,
    extract::Path,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use reqwest::Proxy;
use std::time::{Duration, Instant};
use tokio::time::timeout;

// ============================================================================
// Certificate Issuance Benchmarks
// ============================================================================

// Note: Cold cache cert generation benchmarks require direct access to the
// CertificateAuthority which isn't exposed. The warm cache test below measures
// the full connection path with cached certificates, which is the common case.

/// Benchmark certificate lookup (warm cache - same host)
#[tokio::test]
#[ignore]
async fn perf_cert_issuance_warm() {
    init_crypto_provider();

    let proxy_port = find_available_port().await;
    let temp_dir = tempfile::tempdir().expect("temp dir");

    let (upstream_port, upstream_cert_pem, _handle) = spawn_https_server().await;
    let (proxy_ca_cert, _proxy) = spawn_perf_proxy(
        proxy_port,
        vec![RuleSpec::host("allow", "localhost")],
        Some(&upstream_cert_pem),
        &temp_dir,
    )
    .await;

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

/// Benchmark connection establishment: direct (TLS + first byte) vs proxy (CONNECT + dual TLS)
#[tokio::test]
#[ignore]
async fn perf_connection_time() {
    init_crypto_provider();

    let proxy_port = find_available_port().await;
    let temp_dir = tempfile::tempdir().expect("temp dir");

    let (upstream_port, upstream_cert_pem, _handle) = spawn_https_server().await;
    let url = format!("https://localhost:{}/get", upstream_port);
    let iterations = 20;

    println!("\n=== Connection Time ===\n");

    // --- Direct: TLS handshake + first response byte ---
    let upstream_cert =
        reqwest::Certificate::from_pem(upstream_cert_pem.as_bytes()).expect("parse cert");

    // Warm up
    let client = reqwest::Client::builder()
        .add_root_certificate(upstream_cert.clone())
        .build()
        .expect("client");
    let _ = client.get(&url).send().await;

    let mut direct_stats = Stats::new();
    for _ in 0..iterations {
        let client = reqwest::Client::builder()
            .add_root_certificate(upstream_cert.clone())
            .build()
            .expect("client");

        let start = Instant::now();
        let resp = timeout(Duration::from_secs(10), client.get(&url).send())
            .await
            .expect("timeout")
            .expect("request");
        let _ = resp.text().await;
        let elapsed = start.elapsed();

        direct_stats.add(elapsed);
    }

    // --- Proxy: CONNECT + dual TLS + first byte ---
    let (proxy_ca_cert, _proxy) = spawn_perf_proxy(
        proxy_port,
        vec![RuleSpec::host("allow", "localhost")],
        Some(&upstream_cert_pem),
        &temp_dir,
    )
    .await;

    // Warm up cert cache
    let proxy = Proxy::https(format!("http://127.0.0.1:{}", proxy_port)).expect("proxy");
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .add_root_certificate(proxy_ca_cert.clone())
        .build()
        .expect("client");
    let _ = client.get(&url).send().await;

    let mut proxy_stats = Stats::new();
    for _ in 0..iterations {
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
        let _ = resp.text().await;
        let elapsed = start.elapsed();

        proxy_stats.add(elapsed);
    }

    print_stats("direct (TLS + first byte)", &direct_stats);
    print_stats("proxy  (CONNECT + dual TLS)", &proxy_stats);
    println!(
        "  {:<30} {}",
        "overhead (p50)",
        format_overhead(direct_stats.p50(), proxy_stats.p50()),
    );
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

/// Benchmark throughput with Content-Length (batch transfer), direct vs proxy
#[tokio::test]
#[ignore]
async fn perf_throughput_batch() {
    init_crypto_provider();

    let sizes = [(100 * 1024, "100 KB"), (1024 * 1024, "1 MB")];

    println!("\n=== Throughput (Batch / Content-Length) ===\n");

    for (size, label) in sizes {
        let proxy_port = find_available_port().await;
        let temp_dir = tempfile::tempdir().expect("temp dir");

        let (upstream_port, upstream_cert_pem, _handle) =
            spawn_https_server_with_app(throughput_router(size), true).await;
        let url = format!("https://localhost:{}/batch", upstream_port);

        // Direct
        let upstream_cert =
            reqwest::Certificate::from_pem(upstream_cert_pem.as_bytes()).expect("parse cert");
        let direct_client = reqwest::Client::builder()
            .add_root_certificate(upstream_cert)
            .build()
            .expect("client");
        let direct_stats = measure_throughput(&direct_client, &url, size, 5).await;

        // Proxy
        let (proxy_ca_cert, _proxy) = spawn_perf_proxy(
            proxy_port,
            vec![RuleSpec::host("allow", "localhost")],
            Some(&upstream_cert_pem),
            &temp_dir,
        )
        .await;
        let proxy = Proxy::https(format!("http://127.0.0.1:{}", proxy_port)).expect("proxy");
        let proxy_client = reqwest::Client::builder()
            .proxy(proxy)
            .add_root_certificate(proxy_ca_cert)
            .build()
            .expect("client");
        let proxy_stats = measure_throughput(&proxy_client, &url, size, 5).await;

        print_throughput_comparison(label, size, &direct_stats, &proxy_stats);
    }
    println!();
}

/// Benchmark throughput with chunked transfer encoding, direct vs proxy
#[tokio::test]
#[ignore]
async fn perf_throughput_chunked() {
    init_crypto_provider();

    let sizes = [(100 * 1024, "100 KB"), (1024 * 1024, "1 MB")];

    println!("\n=== Throughput (Chunked Transfer) ===\n");

    for (size, label) in sizes {
        let proxy_port = find_available_port().await;
        let temp_dir = tempfile::tempdir().expect("temp dir");

        let (upstream_port, upstream_cert_pem, _handle) =
            spawn_https_server_with_app(throughput_router(size), true).await;
        let url = format!("https://localhost:{}/chunked", upstream_port);

        // Direct
        let upstream_cert =
            reqwest::Certificate::from_pem(upstream_cert_pem.as_bytes()).expect("parse cert");
        let direct_client = reqwest::Client::builder()
            .add_root_certificate(upstream_cert)
            .build()
            .expect("client");
        let direct_stats = measure_throughput(&direct_client, &url, size, 5).await;

        // Proxy
        let (proxy_ca_cert, _proxy) = spawn_perf_proxy(
            proxy_port,
            vec![RuleSpec::host("allow", "localhost")],
            Some(&upstream_cert_pem),
            &temp_dir,
        )
        .await;
        let proxy = Proxy::https(format!("http://127.0.0.1:{}", proxy_port)).expect("proxy");
        let proxy_client = reqwest::Client::builder()
            .proxy(proxy)
            .add_root_certificate(proxy_ca_cert)
            .build()
            .expect("client");
        let proxy_stats = measure_throughput(&proxy_client, &url, size, 5).await;

        print_throughput_comparison(label, size, &direct_stats, &proxy_stats);
    }
    println!();
}

/// Benchmark HTTP/2 throughput, direct vs proxy
#[tokio::test]
#[ignore]
async fn perf_throughput_h2() {
    init_crypto_provider();

    let size = 1024 * 1024; // 1 MB

    println!("\n=== Throughput (HTTP/2) ===\n");

    let proxy_port = find_available_port().await;
    let temp_dir = tempfile::tempdir().expect("temp dir");

    let (upstream_port, upstream_cert_pem, _handle) =
        spawn_https_server_with_app(throughput_router(size), true).await;
    let url = format!("https://localhost:{}/batch", upstream_port);

    // Direct H2 client
    let upstream_cert =
        reqwest::Certificate::from_pem(upstream_cert_pem.as_bytes()).expect("parse cert");
    let direct_client = reqwest::Client::builder()
        .add_root_certificate(upstream_cert)
        .use_rustls_tls()
        .http2_adaptive_window(true)
        .build()
        .expect("client");

    // Verify H2 negotiation
    let resp = direct_client.get(&url).send().await.expect("request");
    assert_eq!(resp.version(), reqwest::Version::HTTP_2);
    let _ = resp.bytes().await;

    let direct_stats = measure_throughput(&direct_client, &url, size, 5).await;

    // Proxy H2 client
    let (proxy_ca_cert, _proxy) = spawn_perf_proxy(
        proxy_port,
        vec![RuleSpec::host("allow", "localhost")],
        Some(&upstream_cert_pem),
        &temp_dir,
    )
    .await;
    let proxy = Proxy::https(format!("http://127.0.0.1:{}", proxy_port)).expect("proxy");
    let proxy_client = reqwest::Client::builder()
        .proxy(proxy)
        .add_root_certificate(proxy_ca_cert)
        .use_rustls_tls()
        .http2_adaptive_window(true)
        .build()
        .expect("client");

    // Verify H2 through proxy
    let resp = proxy_client.get(&url).send().await.expect("request");
    assert_eq!(resp.version(), reqwest::Version::HTTP_2);
    let _ = resp.bytes().await;

    let proxy_stats = measure_throughput(&proxy_client, &url, size, 5).await;

    print_throughput_comparison("1 MB", size, &direct_stats, &proxy_stats);
    println!();
}

// ============================================================================
// H2 Concurrent Stream Stress Tests
// ============================================================================

/// Simulate cargo sparse index: many small concurrent H2 requests on one connection.
///
/// This reproduces the failure mode where `cargo fetch` opens 100+ concurrent
/// H2 streams through the proxy, exhausting the connection-level flow control
/// window and triggering curl's "less than 10 bytes/sec" timeout.
///
/// Run with: cargo test --test performance perf_h2_concurrent -- --nocapture
#[tokio::test]
#[ignore]
async fn perf_h2_concurrent_streams() {
    init_crypto_provider();

    // Simulate crate index: 150 small files (2-8 KB) with 20ms CDN latency
    let num_streams: usize = 150;
    let response_delay = Duration::from_millis(20);

    println!("\n=== H2 Concurrent Streams (cargo sparse index simulation) ===");
    println!(
        "  {} concurrent streams, {}ms simulated CDN latency\n",
        num_streams,
        response_delay.as_millis()
    );

    let proxy_port = find_available_port().await;
    let temp_dir = tempfile::tempdir().expect("temp dir");

    // Upstream serves small payloads with artificial delay
    let index_router = Router::new().route(
        "/index/*rest",
        get(move |Path(path): Path<String>| async move {
            // Simulate CDN latency
            tokio::time::sleep(response_delay).await;

            // Vary payload size 2-8 KB based on path hash
            let size = 2048 + (path.len() * 137 % 6144);
            let data = vec![b'x'; size];

            Response::builder()
                .status(StatusCode::OK)
                .header("content-length", size.to_string())
                .body(Body::from(data))
                .unwrap()
        }),
    );

    let (upstream_port, upstream_cert, _handle) =
        spawn_https_server_with_app(index_router, true).await;

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

    // Single H2 client = single H2 connection (reqwest multiplexes streams)
    let proxy = Proxy::https(format!("http://127.0.0.1:{}", proxy_port)).expect("proxy");
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .add_root_certificate(proxy_ca_cert)
        .use_rustls_tls()
        .pool_max_idle_per_host(1) // force single connection
        .build()
        .expect("client");

    // Warm up: establish H2 connection and cache the cert
    let warmup_url = format!("https://localhost:{}/index/warmup", upstream_port);
    let _ = client.get(&warmup_url).send().await.unwrap().bytes().await;

    // Fire all streams concurrently
    let mut join_set = tokio::task::JoinSet::new();
    let wall_start = Instant::now();

    for i in 0..num_streams {
        let client = client.clone();
        let url = format!(
            "https://localhost:{}/index/{}/{}",
            upstream_port,
            &["ab", "cd", "ef", "gh", "ij", "kl", "mn"][i % 7],
            format!("crate-{}", i)
        );

        join_set.spawn(async move {
            let start = Instant::now();
            let result = timeout(Duration::from_secs(30), async {
                let resp = client.get(&url).send().await?;
                let bytes = resp.bytes().await?;
                Ok::<usize, reqwest::Error>(bytes.len())
            })
            .await;
            let elapsed = start.elapsed();

            match result {
                Ok(Ok(size)) => (i, elapsed, Some(size), None),
                Ok(Err(e)) => (i, elapsed, None, Some(format!("request error: {}", e))),
                Err(_) => (i, elapsed, None, Some("timeout (30s)".to_string())),
            }
        });
    }

    // Collect results
    let mut stats = Stats::new();
    let mut failures: Vec<(usize, String)> = Vec::new();
    let mut total_bytes: usize = 0;

    while let Some(result) = join_set.join_next().await {
        let (i, elapsed, size, error) = result.expect("task panicked");
        if let Some(err) = error {
            failures.push((i, err));
        } else {
            stats.add(elapsed);
            total_bytes += size.unwrap_or(0);
        }
    }

    let wall_time = wall_start.elapsed();

    // Report
    println!("  completed:  {}/{}", stats.samples.len(), num_streams);
    println!("  failures:   {}", failures.len());
    if !failures.is_empty() {
        for (i, err) in &failures[..failures.len().min(5)] {
            println!("    stream {}: {}", i, err);
        }
        if failures.len() > 5 {
            println!("    ... and {} more", failures.len() - 5);
        }
    }
    println!();

    if !stats.samples.is_empty() {
        print_stats("per-stream latency", &stats);
        println!(
            "  {:<30} {}",
            "wall clock (all streams)",
            format_duration(wall_time)
        );
        println!(
            "  {:<30} {}",
            "aggregate throughput",
            format_throughput(total_bytes, wall_time)
        );

        // Show latency distribution
        let mut sorted = stats.samples.clone();
        sorted.sort();
        println!();
        println!("  latency distribution:");
        for pct in [50, 75, 90, 95, 99, 100] {
            let idx = ((sorted.len() as f64 * pct as f64 / 100.0) as usize).min(sorted.len() - 1);
            println!("    p{:<3}  {}", pct, format_duration(sorted[idx]));
        }
    }
    println!();

    // Fail the test if any streams timed out or errored
    assert!(
        failures.is_empty(),
        "{} of {} streams failed -- H2 flow control starvation likely",
        failures.len(),
        num_streams,
    );

    // Warn if p99 is suspiciously high (> 5x the simulated delay)
    if !stats.samples.is_empty() {
        let p99 = stats.p99();
        let threshold = response_delay * 5;
        if p99 > threshold {
            println!(
                "  WARNING: p99 ({}) > 5x simulated delay ({}) -- possible flow control starvation",
                format_duration(p99),
                format_duration(threshold),
            );
        }
    }
}

/// Same as above but with higher latency to stress flow control harder.
/// Simulates a slow CDN edge (100ms per response).
#[tokio::test]
#[ignore]
async fn perf_h2_concurrent_streams_slow_cdn() {
    init_crypto_provider();

    let num_streams: usize = 150;
    let response_delay = Duration::from_millis(100);

    println!("\n=== H2 Concurrent Streams (slow CDN - 100ms delay) ===");
    println!(
        "  {} concurrent streams, {}ms simulated CDN latency\n",
        num_streams,
        response_delay.as_millis()
    );

    let proxy_port = find_available_port().await;
    let temp_dir = tempfile::tempdir().expect("temp dir");

    let index_router = Router::new().route(
        "/index/*rest",
        get(move |Path(path): Path<String>| async move {
            tokio::time::sleep(response_delay).await;

            let size = 2048 + (path.len() * 137 % 6144);
            let data = vec![b'x'; size];

            Response::builder()
                .status(StatusCode::OK)
                .header("content-length", size.to_string())
                .body(Body::from(data))
                .unwrap()
        }),
    );

    let (upstream_port, upstream_cert, _handle) =
        spawn_https_server_with_app(index_router, true).await;

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
        .use_rustls_tls()
        .pool_max_idle_per_host(1)
        .build()
        .expect("client");

    let warmup_url = format!("https://localhost:{}/index/warmup", upstream_port);
    let _ = client.get(&warmup_url).send().await.unwrap().bytes().await;

    let mut join_set = tokio::task::JoinSet::new();
    let wall_start = Instant::now();

    for i in 0..num_streams {
        let client = client.clone();
        let url = format!(
            "https://localhost:{}/index/{}/{}",
            upstream_port,
            &["ab", "cd", "ef", "gh", "ij", "kl", "mn"][i % 7],
            format!("crate-{}", i)
        );

        join_set.spawn(async move {
            let start = Instant::now();
            let result = timeout(Duration::from_secs(30), async {
                let resp = client.get(&url).send().await?;
                let bytes = resp.bytes().await?;
                Ok::<usize, reqwest::Error>(bytes.len())
            })
            .await;
            let elapsed = start.elapsed();

            match result {
                Ok(Ok(size)) => (i, elapsed, Some(size), None),
                Ok(Err(e)) => (i, elapsed, None, Some(format!("request error: {}", e))),
                Err(_) => (i, elapsed, None, Some("timeout (30s)".to_string())),
            }
        });
    }

    let mut stats = Stats::new();
    let mut failures: Vec<(usize, String)> = Vec::new();
    let mut total_bytes: usize = 0;

    while let Some(result) = join_set.join_next().await {
        let (i, elapsed, size, error) = result.expect("task panicked");
        if let Some(err) = error {
            failures.push((i, err));
        } else {
            stats.add(elapsed);
            total_bytes += size.unwrap_or(0);
        }
    }

    let wall_time = wall_start.elapsed();

    println!("  completed:  {}/{}", stats.samples.len(), num_streams);
    println!("  failures:   {}", failures.len());
    if !failures.is_empty() {
        for (i, err) in &failures[..failures.len().min(5)] {
            println!("    stream {}: {}", i, err);
        }
        if failures.len() > 5 {
            println!("    ... and {} more", failures.len() - 5);
        }
    }
    println!();

    if !stats.samples.is_empty() {
        print_stats("per-stream latency", &stats);
        println!(
            "  {:<30} {}",
            "wall clock (all streams)",
            format_duration(wall_time)
        );
        println!(
            "  {:<30} {}",
            "aggregate throughput",
            format_throughput(total_bytes, wall_time)
        );

        let mut sorted = stats.samples.clone();
        sorted.sort();
        println!();
        println!("  latency distribution:");
        for pct in [50, 75, 90, 95, 99, 100] {
            let idx = ((sorted.len() as f64 * pct as f64 / 100.0) as usize).min(sorted.len() - 1);
            println!("    p{:<3}  {}", pct, format_duration(sorted[idx]));
        }
    }
    println!();

    assert!(
        failures.is_empty(),
        "{} of {} streams failed -- H2 flow control starvation under latency",
        failures.len(),
        num_streams,
    );
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
    println!("  cargo test --test performance perf_cert -- --ignored --nocapture");
    println!("  cargo test --test performance perf_connection -- --ignored --nocapture");
    println!("  cargo test --test performance perf_throughput -- --ignored --nocapture");
    println!("  cargo test --test performance perf_h2_concurrent -- --ignored --nocapture");
    println!();
}
