//! OpenTelemetry telemetry initialization.
//!
//! Adapted from nix-jail's telemetry setup. Provides optional OTLP export
//! with graceful shutdown via TracingGuard.

use opentelemetry::trace::TracerProvider as _;
use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Guard that ensures OpenTelemetry spans are flushed on shutdown.
/// Drop this guard when the application exits to ensure all traces are exported.
pub struct TracingGuard {
    provider: Option<SdkTracerProvider>,
}

impl std::fmt::Debug for TracingGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TracingGuard")
            .field("provider", &self.provider.is_some())
            .finish()
    }
}

impl Drop for TracingGuard {
    fn drop(&mut self) {
        if let Some(provider) = self.provider.take() {
            // Force flush any pending spans before shutdown
            eprintln!("[telemetry] flushing spans...");
            if let Err(e) = provider.force_flush() {
                eprintln!("[telemetry] flush error: {e}");
            }
            eprintln!("[telemetry] shutting down...");
            if let Err(e) = provider.shutdown() {
                eprintln!("[telemetry] shutdown error: {e}");
            }
            eprintln!("[telemetry] done");
        }
    }
}

/// Initialize tracing with optional OpenTelemetry OTLP export.
///
/// # Arguments
/// * `service_name` - Service name for OpenTelemetry (e.g., "alice")
/// * `default_filter` - Default filter level (e.g., "info", "alice=debug")
/// * `json` - If true, output logs as JSON
/// * `otlp_endpoint` - Optional OTLP endpoint for distributed tracing (e.g., "http://localhost:4317")
///
/// # Returns
/// A guard that must be kept alive for the duration of the program.
/// Dropping the guard will flush pending traces.
pub fn init_tracing(
    service_name: &str,
    default_filter: &str,
    json: bool,
    otlp_endpoint: Option<&str>,
) -> TracingGuard {
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter));

    // Use provided endpoint or fall back to environment variable
    let otlp_endpoint: Option<String> = otlp_endpoint
        .map(String::from)
        .or_else(|| std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok());

    // Try to initialize OpenTelemetry if endpoint is configured
    let (provider, otel_init_error) = if let Some(endpoint) = &otlp_endpoint {
        match init_otlp_tracer(service_name, endpoint) {
            Ok(p) => (Some(p), None),
            Err(e) => (None, Some(e.to_string())),
        }
    } else {
        (None, None)
    };

    // Build the subscriber with optional OTel layer
    if json {
        let fmt_layer = fmt::layer().json();
        let otel_layer = provider.as_ref().map(|p| {
            tracing_opentelemetry::layer().with_tracer(p.tracer(service_name.to_string()))
        });

        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt_layer)
            .with(otel_layer)
            .init();
    } else {
        let fmt_layer = fmt::layer();
        let otel_layer = provider.as_ref().map(|p| {
            tracing_opentelemetry::layer().with_tracer(p.tracer(service_name.to_string()))
        });

        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt_layer)
            .with(otel_layer)
            .init();
    }

    // Log OTel status now that tracing is initialized
    if let Some(error) = otel_init_error {
        tracing::warn!(error = %error, "failed to initialize opentelemetry, using console only");
    } else if let Some(endpoint) = otlp_endpoint {
        if provider.is_some() {
            tracing::info!(endpoint = %endpoint, "opentelemetry export enabled");
        }
    }

    TracingGuard { provider }
}

fn init_otlp_tracer(
    service_name: &str,
    endpoint: &str,
) -> Result<SdkTracerProvider, Box<dyn std::error::Error + Send + Sync>> {
    use opentelemetry_otlp::WithExportConfig;
    use opentelemetry_sdk::Resource;

    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .build()?;

    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(
            Resource::builder_empty()
                .with_service_name(service_name.to_string())
                .build(),
        )
        .build();

    Ok(provider)
}
