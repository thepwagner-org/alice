//! Remote performance tests against Cloudflare's speed test CDN.
//!
//! These tests require internet access and are not run by default.
//! Run with: cargo test --test cloudflare -- --ignored --nocapture
//!
//! Cloudflare rate-limits the __down endpoint. The 429 response includes a
//! `Retry-After` header (often 30-50 minutes). Tests respect this header,
//! sleep between requests, and skip tiers that get throttled.
//!
//! Total bandwidth budget: ~50 MB per run (kept low to avoid long cooldowns).

mod common;

use common::{
    find_available_port, format_duration, format_overhead, format_throughput, init_crypto_provider,
    print_stats, spawn_perf_proxy, RuleSpec, Stats,
};

use reqwest::Proxy;
use std::time::{Duration, Instant};
use tokio::time::{sleep, timeout};

const CF_HOST: &str = "speed.cloudflare.com";

/// Delay between individual requests.
const REQUEST_DELAY: Duration = Duration::from_secs(1);

fn cf_url(bytes: usize) -> String {
    format!("https://{}/__down?bytes={}", CF_HOST, bytes)
}

/// Check whether we're rate-limited. If the response is a 429, parse the
/// `Retry-After` header and print when the limit resets.
fn check_rate_limit(resp: &reqwest::Response) -> bool {
    if resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
        if let Some(retry) = resp.headers().get("retry-after") {
            if let Ok(secs) = retry.to_str().unwrap_or("?").parse::<u64>() {
                println!(
                    "    rate-limited (retry after {}m {}s)",
                    secs / 60,
                    secs % 60
                );
            } else {
                println!("    rate-limited (retry-after: {:?})", retry);
            }
        } else {
            println!("    rate-limited");
        }
        return true;
    }
    false
}

/// Measure throughput against a remote endpoint. Returns None if rate-limited.
async fn measure_remote(
    client: &reqwest::Client,
    url: &str,
    expected_size: usize,
    iterations: usize,
) -> Option<Stats> {
    // Warm up (also checks for rate-limit before we start timing)
    let resp = client.get(url).send().await.ok()?;
    if check_rate_limit(&resp) {
        return None;
    }
    let bytes = resp.bytes().await.ok()?;
    if bytes.len() != expected_size {
        return None;
    }
    sleep(REQUEST_DELAY).await;

    let mut stats = Stats::new();
    for _ in 0..iterations {
        let start = Instant::now();
        let resp = timeout(Duration::from_secs(60), client.get(url).send())
            .await
            .ok()?
            .ok()?;
        if check_rate_limit(&resp) {
            // Return partial results if we got at least some samples
            return if stats.samples.is_empty() {
                None
            } else {
                Some(stats)
            };
        }
        let bytes = resp.bytes().await.ok()?;
        if bytes.len() != expected_size {
            return if stats.samples.is_empty() {
                None
            } else {
                Some(stats)
            };
        }
        stats.add(start.elapsed());
        sleep(REQUEST_DELAY).await;
    }
    Some(stats)
}

fn print_comparison(label: &str, size: usize, direct: &Stats, proxy: &Stats) {
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

// ============================================================================
// Connection Time
// ============================================================================

/// Benchmark connection time to Cloudflare: direct TLS vs proxy CONNECT + dual TLS.
#[tokio::test]
#[ignore]
async fn cf_connection_time() {
    init_crypto_provider();

    let proxy_port = find_available_port().await;
    let temp_dir = tempfile::tempdir().expect("temp dir");
    let url = cf_url(1); // 1 byte -- measure connection, not transfer
    let iterations = 10;

    println!("\n=== Connection Time (Cloudflare CDN) ===\n");

    // --- Direct ---
    let mut direct_stats = Stats::new();
    for _ in 0..iterations {
        let client = reqwest::Client::builder().build().expect("client");

        let start = Instant::now();
        let resp = timeout(Duration::from_secs(10), client.get(&url).send())
            .await
            .expect("timeout")
            .expect("request");
        let _ = resp.bytes().await;
        direct_stats.add(start.elapsed());
    }

    // --- Proxy ---
    let (proxy_ca_cert, _proxy) = spawn_perf_proxy(
        proxy_port,
        vec![RuleSpec::host("allow", CF_HOST)],
        None,
        &temp_dir,
    )
    .await;

    // Warm up: establish connection, cache cert
    let proxy = Proxy::https(format!("http://127.0.0.1:{}", proxy_port)).expect("proxy");
    let warmup_client = reqwest::Client::builder()
        .proxy(proxy)
        .add_root_certificate(proxy_ca_cert.clone())
        .build()
        .expect("client");
    let _ = warmup_client.get(&url).send().await;

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
        let _ = resp.bytes().await;
        proxy_stats.add(start.elapsed());
    }

    print_stats("direct (TLS to CF edge)", &direct_stats);
    print_stats("proxy  (CONNECT + dual TLS)", &proxy_stats);
    println!(
        "  {:<30} {}",
        "overhead (p50)",
        format_overhead(direct_stats.p50(), proxy_stats.p50()),
    );
    println!();
}

// ============================================================================
// Throughput
// ============================================================================

/// Benchmark download throughput from Cloudflare CDN: direct vs proxy.
///
/// Two tiers: 1 MB (fits in initial TCP window) and 25 MB (enough for TCP
/// to ramp up). 3 iterations each side = ~52 MB total bandwidth.
/// Gracefully skips tiers that get rate-limited.
#[tokio::test]
#[ignore]
async fn cf_throughput() {
    init_crypto_provider();

    let proxy_port = find_available_port().await;
    let temp_dir = tempfile::tempdir().expect("temp dir");

    // ~52 MB total: (1 warmup + 3 iters) * 2 sides * (1 + 25) MB
    let sizes: &[(usize, &str)] = &[(1024 * 1024, "1 MB"), (25 * 1024 * 1024, "25 MB")];

    println!("\n=== Throughput (Cloudflare CDN) ===\n");

    // Direct client (system/bundled roots)
    let direct_client = reqwest::Client::builder().build().expect("client");

    // Proxy client
    let (proxy_ca_cert, _proxy) = spawn_perf_proxy(
        proxy_port,
        vec![RuleSpec::host("allow", CF_HOST)],
        None,
        &temp_dir,
    )
    .await;
    let proxy = Proxy::https(format!("http://127.0.0.1:{}", proxy_port)).expect("proxy");
    let proxy_client = reqwest::Client::builder()
        .proxy(proxy)
        .add_root_certificate(proxy_ca_cert)
        .build()
        .expect("client");

    let mut any_completed = false;
    for &(size, label) in sizes {
        let url = cf_url(size);

        let direct_stats = measure_remote(&direct_client, &url, size, 3).await;
        let proxy_stats = measure_remote(&proxy_client, &url, size, 3).await;

        match (direct_stats, proxy_stats) {
            (Some(d), Some(p)) => {
                print_comparison(label, size, &d, &p);
                any_completed = true;
            }
            _ => {
                println!("  {}: skipped (rate-limited)", label);
            }
        }
    }
    println!();

    assert!(
        any_completed,
        "all tiers were rate-limited -- wait for Retry-After and retry"
    );
}
