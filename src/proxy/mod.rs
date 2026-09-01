use crate::config::Config;
use crate::credentials::CredentialStore;
use anyhow::Result;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::{debug, error, info, info_span, warn, Instrument};
use tracing_opentelemetry::OpenTelemetrySpanExt;

#[cfg(unix)]
use tokio::signal::unix::{signal, SignalKind};

mod certs;
pub mod collector;
mod dns;
pub mod gcp;
mod h2;
mod http;
pub mod logging;
pub mod metrics;
mod policy;
pub mod prom;
mod request;
pub mod reverse;
mod tls;

use certs::CertificateAuthority;
use dns::DnsResolver;
use gcp::GcpCredentialStore;
use policy::PolicyEngine;
use prom::ProxyMetrics;

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
    /// Request-size limits (defense-in-depth against memory-exhaustion DoS)
    pub limits: crate::config::Limits,
    /// Directory for request/response logs (development only)
    pub log_dir: Option<PathBuf>,
    /// Prometheus metrics (request counts, bytes, connections, credentials)
    pub metrics: ProxyMetrics,
}

pub async fn run(config: Config, parent_context: Option<opentelemetry::Context>) -> Result<()> {
    // Initialize CA and write cert for clients
    let ca =
        CertificateAuthority::new(config.ca.validity_hours, config.ca.host_cert_validity_hours)?;
    ca.write_ca_cert(&config.ca.cert_path)?;
    info!(path = %config.ca.cert_path.display(), "wrote CA certificate");

    // Initialize policy engine
    let policy = PolicyEngine::new(&config.rules)?;
    debug!(rules = config.rules.len(), "loaded policy rules");

    // Pre-generate certs for exact (non-glob) hosts from rules and credentials,
    // plus any explicitly configured warm_hosts.
    let warm_hosts: Vec<String> = {
        let hosts: std::collections::HashSet<String> = config
            .ca
            .warm_hosts
            .iter()
            .cloned()
            .chain(
                config
                    .rules
                    .iter()
                    .filter_map(|r| r.host.as_ref())
                    .chain(config.credentials.iter().map(|c| &c.host))
                    .filter(|h| {
                        !h.contains('*') && !h.contains('?') && !h.contains('[') && !h.contains('{')
                    })
                    .cloned(),
            )
            .collect();
        // warm_hosts from config are always included, even if they look like globs
        // (the user knows what they want)
        hosts.into_iter().collect()
    };
    if !warm_hosts.is_empty() {
        let warmed = ca.warm_certs(&warm_hosts).await;
        info!(
            count = warmed,
            total = warm_hosts.len(),
            "pre-generated certificates for known hosts"
        );
    }

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
    // Prime any sanctum-backed credentials with an initial token fetch
    // and spawn their background refresh tasks. Failure here aborts startup
    // so we don't serve traffic with an unpopulated credential.
    credentials.start_sanctum_refresh().await?;

    // Load GCP credentials (service accounts + user accounts)
    let gcp_credentials =
        if config.gcp_credentials.is_empty() && config.gcp_user_credentials.is_empty() {
            GcpCredentialStore::empty()
        } else {
            GcpCredentialStore::load(&config.gcp_credentials, &config.gcp_user_credentials)?
        };

    let idle_timeout = Duration::from_secs(config.proxy.idle_timeout_secs);
    let limits = config.proxy.limits();

    // Create log directory if configured
    let log_dir = if let Some(ref dir) = config.proxy.log_dir {
        std::fs::create_dir_all(dir)?;
        info!(path = %dir.display(), "request/response logging enabled");
        Some(dir.clone())
    } else {
        None
    };

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
        limits,
        log_dir,
        metrics: proxy_metrics.clone(),
    });

    // Spawn observability services if configured
    if let Some(ref obs) = config.observability {
        if let Some(ref listen) = obs.metrics_listen {
            let (metrics_addr, _metrics_handle) =
                metrics::spawn(listen, proxy_metrics.clone()).await?;
            info!(addr = %metrics_addr, "metrics server started");
        }
        if let Some(ref col_config) = obs.collector {
            let (col_addr, _col_handle) =
                collector::spawn(col_config, obs, proxy_metrics.clone()).await?;
            info!(addr = %col_addr, "collector started");
        }
    }

    // Spawn reverse proxy if configured
    if let Some(ref rp_config) = config.reverse_proxy {
        let rp = reverse::ReverseProxyConfig {
            listen: rp_config.listen.clone(),
            backend: rp_config.backend.clone(),
            idle_timeout: Duration::from_secs(rp_config.idle_timeout_secs),
        };
        let (bound_addr, _rp_handle) = reverse::spawn(rp).await?;
        info!(addr = %bound_addr, backend = %rp_config.backend, "reverse proxy started");
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
    let listen_addr = listener.local_addr()?;
    info!(addr = %listen_addr, "listening for connections");

    // Forward-proxy connection heartbeat. Tracks the unix-seconds
    // timestamp of the last accepted connection on the main listener
    // (workload → alice → upstream). A stalled workload can go silent
    // mid-task, between one upstream response and its next request —
    // alice sees zero connections for that whole window. Without a
    // heartbeat, "no inbound for N seconds" is only visible by
    // *absence* of log lines, which is hard to grep for and easy to
    // confuse with "alice itself stopped logging." The background task
    // below makes the gap a single emitted INFO line.
    //
    // Initialised to startup time so the first stretch with zero
    // accepts (cold sandbox before the workload starts) doesn't read
    // as an instant stall. The heartbeat only fires once silence
    // crosses ACCEPT_HEARTBEAT_SECS, so a quiet startup is silent.
    let last_accept_unix = Arc::new(AtomicU64::new(now_unix_secs()));
    drop(tokio::spawn(spawn_accept_heartbeat(Arc::clone(
        &last_accept_unix,
    ))));

    // Server lifecycle span — covers the entire accept loop.
    // Uses .instrument() so the span is properly entered/exited around each
    // async poll, making it "current" for child spans on any worker thread.
    //
    // We attach the parent OTel context to thread-local BEFORE creating the
    // span. The OTel layer reads Context::current() in on_new_span to assign
    // the trace_id. set_parent() alone updates the *exported* span but
    // children inherit the trace_id assigned at creation time — causing a
    // trace split where server lives in trace B but conn/request end up in
    // an orphaned trace A.
    //
    // SAFETY: No .await between attach() and drop() — the guard never
    // crosses a yield point, so the thread-local context is scoped to this
    // thread for the duration of the synchronous info_span!() call.
    let _parent_guard = parent_context.as_ref().map(|cx| cx.clone().attach());
    let server_span = info_span!(
        "server",
        service.name = "alice",
        service.version = crate::telemetry::version(),
        server.address = %config.proxy.listen,
    );
    drop(_parent_guard);

    // Also call set_parent so that server_span.context() returns the right
    // parent info for any code that inspects it directly.
    if let Some(cx) = parent_context {
        match server_span.set_parent(cx) {
            Ok(()) => {
                use opentelemetry::trace::TraceContextExt;
                let otel_cx = server_span.context();
                let sc = otel_cx.span().span_context().clone();
                info!(
                    trace_id = %sc.trace_id(),
                    span_id = %sc.span_id(),
                    "linked server span to parent trace context"
                );
            }
            Err(e) => warn!(error = %e, "failed to set parent trace context on server span"),
        }
    }

    // The accept loop is instrumented with server_span so that:
    // 1. The OTel layer initialises the span's trace/span IDs on first enter
    // 2. conn spans created inside automatically inherit server as parent
    // 3. Thread-local context is correct regardless of tokio worker thread
    async move {
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
                            // Stamp accept time before any blocking
                            // semaphore acquire — heartbeat tracks
                            // "kernel handed us a connection," not
                            // "we made it past the connection limit."
                            // The two only diverge under a wedged limit
                            // exhaustion, which is its own log line below.
                            last_accept_unix.store(now_unix_secs(), Ordering::Relaxed);
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
                            drop(tokio::spawn(
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
                            ));
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
    .instrument(server_span)
    .await
}

/// Threshold (seconds since the last accept) at which the heartbeat
/// task starts emitting `proxy.idle` log lines. Tuned to land *before*
/// the ~120s idle kill a sandbox supervisor typically applies, so the
/// gap shows up in alice's logs while the stall is still live, not
/// only in post-mortems.
const ACCEPT_HEARTBEAT_SECS: u64 = 30;

/// Re-emit cadence once silent. Past the threshold, log every
/// `ACCEPT_HEARTBEAT_EVERY` seconds so a long wedge produces multiple
/// timestamped lines for grep-friendly "when did the gap start /
/// end" diagnosis.
const ACCEPT_HEARTBEAT_EVERY: u64 = 30;

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Periodic INFO line when the forward proxy hasn't accepted a
/// connection for a while. Distinguishes "alice is idle (nothing's
/// happening)" from "alice is wedged (we're listening but no one's
/// calling)" without having to grep for the *absence* of `request.summary`.
async fn spawn_accept_heartbeat(last_accept_unix: Arc<AtomicU64>) {
    // Wake at half the emit cadence: catches threshold crossings
    // promptly without paying for sub-second precision we don't need.
    let mut tick = tokio::time::interval(Duration::from_secs(ACCEPT_HEARTBEAT_EVERY / 2));
    let _ = tick.tick().await; // consume immediate first tick
    let mut last_log_unix: u64 = 0;
    loop {
        let _ = tick.tick().await;
        let now = now_unix_secs();
        let last = last_accept_unix.load(Ordering::Relaxed);
        let silent = now.saturating_sub(last);
        if silent < ACCEPT_HEARTBEAT_SECS {
            // Reset the rate-limiter so the next stretch of silence
            // gets its first heartbeat immediately at threshold rather
            // than waiting for the cadence to lap.
            last_log_unix = 0;
            continue;
        }
        let due = last_log_unix == 0 || now.saturating_sub(last_log_unix) >= ACCEPT_HEARTBEAT_EVERY;
        if !due {
            continue;
        }
        last_log_unix = now;
        info!(
            silent_for_secs = silent,
            last_accept_unix = last,
            "proxy.idle no inbound forward-proxy connection"
        );
    }
}
