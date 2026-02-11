use crate::config::Config;
use crate::credentials::CredentialStore;
use anyhow::Result;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::{debug, error, info, info_span, warn, Instrument};

#[cfg(unix)]
use tokio::signal::unix::{signal, SignalKind};

mod certs;
mod dns;
pub mod gcp;
mod h2;
mod http;
pub mod llm;
pub mod logging;
pub mod metrics;
mod policy;
pub mod prom;
mod request;
mod tls;
pub mod transform;

use certs::CertificateAuthority;
use dns::DnsResolver;
use gcp::GcpCredentialStore;
use policy::PolicyEngine;
use prom::ProxyMetrics;
use transform::TransformPipeline;

/// Shared state for all proxy connections
pub struct ProxyState {
    pub policy: PolicyEngine,
    pub ca: CertificateAuthority,
    #[allow(dead_code)] // Will be used for DNS-based policy in future
    pub dns: DnsResolver,
    pub proxy_auth: Option<(String, String)>,
    pub upstream_ca: Option<PathBuf>,
    pub credentials: CredentialStore,
    /// GCP service account credentials for proxy-side JWT re-signing
    pub gcp_credentials: GcpCredentialStore,
    pub idle_timeout: Duration,
    /// Directory for request/response logs (development only)
    pub log_dir: Option<PathBuf>,
    /// Accumulated LLM completion metrics (queryable via metrics endpoint)
    pub llm_metrics: llm::LlmMetricsStore,
    /// Prometheus metrics (request counts, bytes, connections, credentials)
    pub metrics: ProxyMetrics,
    /// Transform pipeline for LLM API request modification
    pub transform_pipeline: TransformPipeline,
}

pub async fn run(config: Config) -> Result<()> {
    // Initialize CA and write cert for clients
    let ca =
        CertificateAuthority::new(config.ca.validity_hours, config.ca.host_cert_validity_hours)?;
    ca.write_ca_cert(&config.ca.cert_path)?;
    info!(path = %config.ca.cert_path.display(), "wrote CA certificate");

    // Initialize policy engine
    let policy = PolicyEngine::new(&config.rules)?;
    debug!(rules = config.rules.len(), "loaded policy rules");

    // Initialize DNS resolver with host overrides
    let dns_overrides = config
        .dns
        .hosts
        .iter()
        .filter_map(|(host, addrs)| {
            let parsed: Result<Vec<std::net::IpAddr>, _> =
                addrs.iter().map(|s| s.parse()).collect();
            match parsed {
                Ok(ips) => Some((host.clone(), ips)),
                Err(e) => {
                    tracing::warn!(host = %host, error = %e, "invalid IP in dns.hosts, skipping");
                    None
                }
            }
        })
        .collect();
    let dns = DnsResolver::new(
        config.dns.cache_ttl_secs,
        config.dns.cache_max_entries,
        dns_overrides,
    )
    .await?;

    // Load proxy auth credentials if configured
    let proxy_auth = match (&config.proxy.username, &config.proxy.password_env) {
        (Some(username), Some(password_env)) => {
            let password = std::env::var(password_env).ok();
            password.map(|p| (username.clone(), p))
        }
        _ => None,
    };

    // Load credential store for header injection
    let credentials = CredentialStore::load(&config.credentials)?;

    // Load GCP credentials (service accounts + user accounts)
    let gcp_credentials =
        if config.gcp_credentials.is_empty() && config.gcp_user_credentials.is_empty() {
            GcpCredentialStore::empty()
        } else {
            GcpCredentialStore::load(&config.gcp_credentials, &config.gcp_user_credentials)?
        };

    let idle_timeout = Duration::from_secs(config.proxy.idle_timeout_secs);

    // Create log directory if configured
    let log_dir = if let Some(ref dir) = config.proxy.log_dir {
        std::fs::create_dir_all(dir)?;
        info!(path = %dir.display(), "request/response logging enabled");
        Some(dir.clone())
    } else {
        None
    };

    let llm_metrics = llm::LlmMetricsStore::default();

    // Build transform pipeline from config
    let transform_pipeline = transform::build_pipeline(&config.transforms);

    // Initialize Prometheus metrics
    let proxy_metrics = ProxyMetrics::new();

    let state = Arc::new(ProxyState {
        policy,
        ca,
        dns,
        proxy_auth,
        upstream_ca: config.proxy.upstream_ca,
        credentials,
        gcp_credentials,
        idle_timeout,
        log_dir,
        llm_metrics: llm_metrics.clone(),
        metrics: proxy_metrics.clone(),
        transform_pipeline,
    });

    // Spawn metrics server if configured
    if let Some(ref obs) = config.observability {
        if let Some(ref listen) = obs.metrics_listen {
            let _metrics_handle = metrics::spawn(listen, llm_metrics, proxy_metrics).await?;
            info!(addr = %listen, "metrics server started");
        }
    }

    // Connection limit semaphore
    let connection_limit = Arc::new(Semaphore::new(config.proxy.max_connections));
    debug!(
        max_connections = config.proxy.max_connections,
        idle_timeout_secs = config.proxy.idle_timeout_secs,
        "connection limits configured"
    );

    // Bind listener
    let listener = TcpListener::bind(&config.proxy.listen).await?;
    debug!(addr = %config.proxy.listen, "listening for connections");

    // Server lifecycle span
    let server_span = info_span!(
        "server",
        service.name = "alice",
        server.address = %config.proxy.listen,
    );
    let _server_guard = server_span.enter();

    // Setup graceful shutdown
    #[cfg(unix)]
    let mut sigterm = signal(SignalKind::terminate())?;
    let shutdown = async {
        #[cfg(unix)]
        {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    info!("received SIGINT, shutting down");
                }
                _ = sigterm.recv() => {
                    info!("received SIGTERM, shutting down");
                }
            }
        }
        #[cfg(not(unix))]
        {
            tokio::signal::ctrl_c().await.ok();
            info!("received shutdown signal");
        }
    };
    tokio::pin!(shutdown);

    // Accept connections with graceful shutdown
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                info!("server shutting down gracefully");
                // Small delay to allow in-flight spans to be batched and sent
                tokio::time::sleep(Duration::from_millis(500)).await;
                break;
            }
            result = listener.accept() => {
                match result {
                    Ok((stream, addr)) => {
                        // Acquire connection permit (blocks if at limit)
                        let permit = match connection_limit.clone().try_acquire_owned() {
                            Ok(permit) => permit,
                            Err(_) => {
                                // At connection limit - try to acquire with brief wait
                                warn!(addr = %addr, "connection limit reached, waiting");
                                match tokio::time::timeout(
                                    Duration::from_secs(5),
                                    connection_limit.clone().acquire_owned(),
                                )
                                .await
                                {
                                    Ok(Ok(permit)) => permit,
                                    _ => {
                                        warn!(addr = %addr, "connection rejected: limit exceeded");
                                        drop(stream);
                                        continue;
                                    }
                                }
                            }
                        };

                        let state = Arc::clone(&state);
                        let span = info_span!("conn", %addr);
                        tokio::spawn(
                            async move {
                                // Permit is held for duration of connection
                                let _permit = permit;
                                // Track active connections in Prometheus
                                let _conn_guard = prom::ConnectionGuard::new(&state.metrics);
                                if let Err(e) = http::handle_connection(stream, state).await {
                                    let msg = e.to_string();
                                    if msg.contains("close_notify")
                                        || msg.contains("Connection reset")
                                    {
                                        debug!(error = %e, "connection closed by peer");
                                    } else {
                                        error!(error = %e, "connection error");
                                    }
                                }
                            }
                            .instrument(span),
                        );
                    }
                    Err(e) => {
                        error!(error = %e, "accept error");
                    }
                }
            }
        }
    }

    Ok(())
}
