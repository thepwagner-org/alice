pub mod allowlist;
pub mod forwarder;
pub mod otlp_http;
pub mod signal;
pub mod statsd;

use crate::config::{CollectorConfig, CollectorRule, ObservabilityConfig};
use crate::proxy::prom::ProxyMetrics;
use allowlist::{CompiledCollectorRule, FilterResult};
use anyhow::{anyhow, Context, Result};
use forwarder::{Forwarder, SendResult};
use globset::Glob;
use signal::OtlpSignal;
use std::sync::Arc;
use tracing::warn;

pub struct CollectorState {
    pub rules: Vec<CompiledCollectorRule>,
    pub forwarder: Arc<Forwarder>,
    pub metrics: ProxyMetrics,
}

impl CollectorState {
    /// Queue an already-filtered request for the upstream collector and count
    /// what happened to it. `source` names the receiver for log context.
    pub fn forward_filtered<T: OtlpSignal>(&self, req: T, fr: &FilterResult, source: &str) {
        let count = |outcome: &str, n: u64| {
            self.metrics
                .collector_received_total
                .with_label_values(&[T::LABEL, outcome])
                .inc_by(n);
        };

        if fr.forwarded > 0 {
            match self.forwarder.try_forward(req.into_payload()) {
                SendResult::Queued => count("forwarded", fr.forwarded),
                SendResult::Dropped => {
                    count("dropped", fr.forwarded);
                    warn!(
                        count = fr.forwarded,
                        signal = T::LABEL,
                        source,
                        "collector dropped telemetry: channel full"
                    );
                }
            }
        }
        if fr.denied > 0 {
            count("denied", fr.denied);
        }
    }
}

/// Spawn the collector HTTP listener and gRPC forwarder.
///
/// Returns the bound address and a join handle for the accept loop.
pub async fn spawn(
    config: &CollectorConfig,
    obs: &ObservabilityConfig,
    metrics: ProxyMetrics,
) -> Result<(std::net::SocketAddr, tokio::task::JoinHandle<()>)> {
    let forward_ep = config
        .forward_endpoint
        .as_deref()
        .or(obs.otlp_endpoint.as_deref())
        .ok_or_else(|| {
            anyhow!(
                "observability.collector requires forward_endpoint \
                 or observability.otlp_endpoint to be set"
            )
        })?;

    let rules = compile_rules(&config.rules)?;
    let forwarder = Forwarder::spawn(forward_ep, metrics.clone())?;

    let state = Arc::new(CollectorState {
        rules,
        forwarder: Arc::new(forwarder),
        metrics,
    });

    if let Some(ref statsd_addr) = config.statsd_listen {
        let (sd_addr, _sd_handle) = statsd::spawn(statsd_addr, Arc::clone(&state)).await?;
        tracing::info!(addr = %sd_addr, "statsd UDP listener started");
    }

    otlp_http::spawn(&config.otlp_http_listen, state).await
}

fn compile_rules(rules: &[CollectorRule]) -> Result<Vec<CompiledCollectorRule>> {
    rules
        .iter()
        .enumerate()
        .map(|(i, rule)| {
            let glob = Glob::new(&rule.name).with_context(|| {
                format!("invalid name glob in collector rule {}: {}", i, rule.name)
            })?;
            Ok(CompiledCollectorRule {
                action: rule.action,
                name_matcher: glob.compile_matcher(),
                signal: rule.signal,
            })
        })
        .collect()
}
