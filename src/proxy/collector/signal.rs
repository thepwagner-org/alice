//! Signal-type abstraction over the OTLP export requests.
//!
//! Traces and metrics travel identical paths through the collector: decode,
//! allowlist-filter by item name, forward, count. Everything that differs
//! between them lives behind this trait so the paths themselves are written
//! once. Adding logs as a third signal means adding one impl here.

use crate::config::Signal;
use crate::proxy::collector::forwarder::ForwardPayload;
use opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest;
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;

pub trait OtlpSignal: prost::Message + Default {
    /// Which allowlist rules apply to this signal.
    const SIGNAL: Signal;
    /// Value of the `signal` label on collector metrics, and of the `signal`
    /// field on collector log events.
    const LABEL: &'static str;

    /// Wrap the request for the forwarder queue.
    fn into_payload(self) -> ForwardPayload;

    /// Retain the items (spans, data points, ...) `keep` accepts by name,
    /// pruning scopes and resources left empty.
    fn retain_items(&mut self, keep: &mut dyn FnMut(&str) -> bool);
}

impl OtlpSignal for ExportTraceServiceRequest {
    const SIGNAL: Signal = Signal::Traces;
    const LABEL: &'static str = "traces";

    fn into_payload(self) -> ForwardPayload {
        ForwardPayload::Traces(self)
    }

    fn retain_items(&mut self, keep: &mut dyn FnMut(&str) -> bool) {
        retain_nested(
            &mut self.resource_spans,
            |rs| &mut rs.scope_spans,
            |ss| &mut ss.spans,
            |span| span.name.as_str(),
            keep,
        );
    }
}

impl OtlpSignal for ExportMetricsServiceRequest {
    const SIGNAL: Signal = Signal::Metrics;
    const LABEL: &'static str = "metrics";

    fn into_payload(self) -> ForwardPayload {
        ForwardPayload::Metrics(self)
    }

    fn retain_items(&mut self, keep: &mut dyn FnMut(&str) -> bool) {
        retain_nested(
            &mut self.resource_metrics,
            |rm| &mut rm.scope_metrics,
            |sm| &mut sm.metrics,
            |metric| metric.name.as_str(),
            keep,
        );
    }
}

/// Filter the resource -> scope -> item tree, dropping scopes and resources
/// that end up empty.
fn retain_nested<R, S, I>(
    resources: &mut Vec<R>,
    scopes: fn(&mut R) -> &mut Vec<S>,
    items: fn(&mut S) -> &mut Vec<I>,
    name: fn(&I) -> &str,
    keep: &mut dyn FnMut(&str) -> bool,
) {
    resources.retain_mut(|resource| {
        scopes(resource).retain_mut(|scope| {
            items(scope).retain(|item| keep(name(item)));
            !items(scope).is_empty()
        });
        !scopes(resource).is_empty()
    });
}
