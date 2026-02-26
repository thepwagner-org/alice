//! OpenTelemetry telemetry initialization.
//!
//! Adapted from nix-jail's telemetry setup. Provides optional OTLP export
//! with graceful shutdown via TracingGuard.

use opentelemetry::propagation::TextMapPropagator;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::SdkTracerProvider;
use std::collections::HashMap;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

const SERVICE_NAME: &str = "alice";

/// Application version from version.toml (embedded at compile time).
pub fn version() -> &'static str {
    include_str!("../version.toml")
        .trim()
        .strip_prefix("version = \"")
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or("unknown")
}

/// Guard that ensures OpenTelemetry spans are flushed on shutdown.
/// Drop this guard when the application exits to ensure all traces are exported.
pub struct TracingGuard {
    provider: Option<SdkTracerProvider>,
    parent_context: Option<opentelemetry::Context>,
}

impl TracingGuard {
    /// Returns the parent trace context extracted from TRACEPARENT env var, if any.
    ///
    /// The caller should `cx.clone().attach()` *synchronously* before creating
    /// the root span so the OTel layer assigns the correct trace_id in
    /// `on_new_span`. Then call `set_parent(cx)` on the span as well.
    ///
    /// Do NOT hold the `ContextGuard` from `attach()` across `.await` points —
    /// tokio can move the task to a different worker thread where
    /// `Context::current()` would be empty.
    pub fn parent_context(&self) -> Option<&opentelemetry::Context> {
        self.parent_context.as_ref()
    }
}

impl std::fmt::Debug for TracingGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TracingGuard")
            .field("provider", &self.provider.is_some())
            .field("parent_context", &self.parent_context.is_some())
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
/// * `json` - If true, output logs as JSON
/// * `otlp_endpoint` - Optional OTLP endpoint for distributed tracing (e.g., "http://localhost:4317")
///
/// # Returns
/// A guard that must be kept alive for the duration of the program.
/// Dropping the guard will flush pending traces.
pub fn init_tracing(json: bool, otlp_endpoint: Option<&str>) -> TracingGuard {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    // Use provided endpoint or fall back to environment variable
    let otlp_endpoint: Option<String> = otlp_endpoint
        .map(String::from)
        .or_else(|| std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok());

    // Try to initialize OpenTelemetry if endpoint is configured
    let (provider, otel_init_error) = if let Some(endpoint) = &otlp_endpoint {
        match init_otlp_tracer(endpoint) {
            Ok(p) => (Some(p), None),
            Err(e) => (None, Some(e.to_string())),
        }
    } else {
        (None, None)
    };

    // Build the subscriber with optional OTel layer
    if json {
        let fmt_layer = fmt::layer().json().with_writer(std::io::stderr);
        let otel_layer = provider.as_ref().map(|p| {
            tracing_opentelemetry::layer().with_tracer(p.tracer(SERVICE_NAME.to_string()))
        });

        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt_layer)
            .with(otel_layer)
            .init();
    } else {
        let fmt_layer = fmt::layer().with_writer(std::io::stderr);
        let otel_layer = provider.as_ref().map(|p| {
            tracing_opentelemetry::layer().with_tracer(p.tracer(SERVICE_NAME.to_string()))
        });

        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt_layer)
            .with(otel_layer)
            .init();
    }

    // Extract parent trace context from environment variables (W3C Trace Context).
    // This allows alice's spans to link to the nix-jail job's trace when spawned
    // with TRACEPARENT/TRACESTATE env vars.
    let parent_context = extract_parent_context_from_env();

    // Log OTel status now that tracing is initialized
    if let Some(error) = otel_init_error {
        tracing::warn!(error = %error, "failed to initialize opentelemetry, using console only");
    } else if let Some(endpoint) = otlp_endpoint {
        if provider.is_some() {
            tracing::info!(endpoint = %endpoint, "opentelemetry export enabled");
        }
    }
    if parent_context.is_some() {
        tracing::info!("extracted parent trace context from TRACEPARENT env var");
    }

    TracingGuard {
        provider,
        parent_context,
    }
}

/// Extract parent trace context from TRACEPARENT/TRACESTATE environment variables.
///
/// This implements W3C Trace Context propagation for child processes.
/// Returns the extracted [`opentelemetry::Context`] which the caller should
/// pass to [`tracing_opentelemetry::OpenTelemetrySpanExt::set_parent()`] on
/// the root span. We do NOT use thread-local `cx.attach()` because `.await`
/// points in async code can move execution to a different tokio worker thread.
fn extract_parent_context_from_env() -> Option<opentelemetry::Context> {
    let traceparent = std::env::var("TRACEPARENT").ok()?;

    // Log raw value at info for diagnosing trace linkage issues
    tracing::info!(traceparent = %traceparent, "found TRACEPARENT env var");

    // Build a carrier from environment variables
    let mut carrier: HashMap<String, String> = HashMap::new();
    let _ = carrier.insert("traceparent".to_string(), traceparent);
    if let Ok(tracestate) = std::env::var("TRACESTATE") {
        tracing::debug!(tracestate = %tracestate, "found TRACESTATE env var");
        let _ = carrier.insert("tracestate".to_string(), tracestate);
    }

    // Extract the context using W3C Trace Context propagator
    let propagator = TraceContextPropagator::new();
    let cx = propagator.extract(&carrier);

    // Verify the extracted context actually contains a valid remote span
    use opentelemetry::trace::TraceContextExt;
    let span_context = cx.span().span_context().clone();
    if span_context.is_valid() {
        tracing::info!(
            trace_id = %span_context.trace_id(),
            parent_span_id = %span_context.span_id(),
            "extracted valid parent span context"
        );
        Some(cx)
    } else {
        tracing::warn!("TRACEPARENT env var present but extracted context is invalid");
        None
    }
}

fn init_otlp_tracer(
    endpoint: &str,
) -> Result<SdkTracerProvider, Box<dyn std::error::Error + Send + Sync>> {
    use opentelemetry::KeyValue;
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
                .with_service_name(SERVICE_NAME.to_string())
                .with_attribute(KeyValue::new("service.version", version().to_string()))
                .build(),
        )
        .build();

    Ok(provider)
}
