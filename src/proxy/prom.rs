//! Prometheus metrics for the proxy.
//!
//! Exposes request counts, byte totals, credential injections, and connection
//! gauges via a `ProxyMetrics` struct backed by a `prometheus::Registry`.

use prometheus::{self, Encoder, IntCounterVec, IntGauge, Opts, Registry, TextEncoder};

/// All Prometheus metrics for the proxy.
///
/// Cheap to clone (all inner types are `Arc`-based).
#[derive(Clone)]
pub struct ProxyMetrics {
    registry: Registry,

    /// Total requests proxied, by host/method/status_code/action.
    pub requests_total: IntCounterVec,

    /// Total bytes sent upstream (request headers + body), by host.
    pub request_bytes_total: IntCounterVec,

    /// Total bytes received from upstream (response headers + body), by host.
    pub response_bytes_total: IntCounterVec,

    /// Credential injections performed, by credential name and host.
    pub credential_injections_total: IntCounterVec,

    /// Currently active proxy connections.
    pub connections_active: IntGauge,
}

impl ProxyMetrics {
    /// Create and register all metrics.
    pub fn new() -> Self {
        let registry = Registry::new();

        let requests_total = IntCounterVec::new(
            Opts::new("alice_requests_total", "Total proxied requests"),
            &["host", "method", "status_code", "action"],
        )
        .expect("metric can be created");
        registry
            .register(Box::new(requests_total.clone()))
            .expect("metric can be registered");

        let request_bytes_total = IntCounterVec::new(
            Opts::new(
                "alice_request_bytes_total",
                "Total bytes sent upstream (request headers + body)",
            ),
            &["host"],
        )
        .expect("metric can be created");
        registry
            .register(Box::new(request_bytes_total.clone()))
            .expect("metric can be registered");

        let response_bytes_total = IntCounterVec::new(
            Opts::new(
                "alice_response_bytes_total",
                "Total bytes received from upstream (response headers + body)",
            ),
            &["host"],
        )
        .expect("metric can be created");
        registry
            .register(Box::new(response_bytes_total.clone()))
            .expect("metric can be registered");

        let credential_injections_total = IntCounterVec::new(
            Opts::new(
                "alice_credential_injections_total",
                "Total credential injections performed",
            ),
            &["credential_name", "host"],
        )
        .expect("metric can be created");
        registry
            .register(Box::new(credential_injections_total.clone()))
            .expect("metric can be registered");

        let connections_active = IntGauge::with_opts(Opts::new(
            "alice_connections_active",
            "Currently active proxy connections",
        ))
        .expect("metric can be created");
        registry
            .register(Box::new(connections_active.clone()))
            .expect("metric can be registered");

        Self {
            registry,
            requests_total,
            request_bytes_total,
            response_bytes_total,
            credential_injections_total,
            connections_active,
        }
    }

    /// Render all metrics in Prometheus text exposition format.
    pub fn render(&self) -> String {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buf = Vec::new();
        encoder
            .encode(&metric_families, &mut buf)
            .expect("encoding metrics");
        String::from_utf8(buf).expect("metrics are valid UTF-8")
    }
}

/// RAII guard that decrements the active connection gauge on drop.
pub struct ConnectionGuard {
    gauge: IntGauge,
}

impl ConnectionGuard {
    pub fn new(metrics: &ProxyMetrics) -> Self {
        metrics.connections_active.inc();
        Self {
            gauge: metrics.connections_active.clone(),
        }
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.gauge.dec();
    }
}
