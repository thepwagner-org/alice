use crate::config::{Action, Signal};
use crate::proxy::collector::signal::OtlpSignal;
use globset::GlobMatcher;

pub struct CompiledCollectorRule {
    pub action: Action,
    pub name_matcher: GlobMatcher,
    pub signal: Option<Signal>,
}

pub struct FilterResult {
    pub forwarded: u64,
    pub denied: u64,
}

/// Drop the items whose names the rules deny, pruning scopes and resources
/// left empty. Works the same for every signal type.
pub fn filter<T: OtlpSignal>(req: &mut T, rules: &[CompiledCollectorRule]) -> FilterResult {
    let mut forwarded = 0u64;
    let mut denied = 0u64;

    req.retain_items(&mut |name| {
        let allowed = eval_rules(name, T::SIGNAL, rules) == Action::Allow;
        if allowed {
            forwarded += 1;
        } else {
            denied += 1;
        }
        allowed
    });

    FilterResult { forwarded, denied }
}

fn eval_rules(name: &str, signal: Signal, rules: &[CompiledCollectorRule]) -> Action {
    for rule in rules {
        if let Some(s) = rule.signal {
            if s != signal {
                continue;
            }
        }
        if rule.name_matcher.is_match(name) {
            return rule.action;
        }
    }
    Action::Deny
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::config::Action;
    use globset::Glob;
    use opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest;
    use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
    use opentelemetry_proto::tonic::metrics::v1::{Metric, ResourceMetrics, ScopeMetrics};
    use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span};

    fn rule(action: Action, pattern: &str, signal: Option<Signal>) -> CompiledCollectorRule {
        CompiledCollectorRule {
            action,
            name_matcher: Glob::new(pattern).unwrap().compile_matcher(),
            signal,
        }
    }

    fn span(name: &str) -> Span {
        Span {
            name: name.to_string(),
            ..Default::default()
        }
    }

    fn metric(name: &str) -> Metric {
        Metric {
            name: name.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn test_filter_traces_allow_one_deny_one() {
        let rules = vec![rule(Action::Allow, "allowed.*", None)];

        let mut req = ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans {
                scope_spans: vec![ScopeSpans {
                    spans: vec![span("allowed.handler"), span("denied.handler")],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        };

        let result = filter(&mut req, &rules);
        assert_eq!(result.forwarded, 1);
        assert_eq!(result.denied, 1);
        assert_eq!(req.resource_spans[0].scope_spans[0].spans.len(), 1);
        assert_eq!(
            req.resource_spans[0].scope_spans[0].spans[0].name,
            "allowed.handler"
        );
    }

    #[test]
    fn test_filter_traces_prunes_empty_scopes_and_resources() {
        let rules = vec![rule(Action::Allow, "allowed.*", None)];

        let mut req = ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans {
                scope_spans: vec![
                    ScopeSpans {
                        spans: vec![span("denied.a")],
                        ..Default::default()
                    },
                    ScopeSpans {
                        spans: vec![span("allowed.b")],
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }],
        };

        let result = filter(&mut req, &rules);
        assert_eq!(result.forwarded, 1);
        assert_eq!(result.denied, 1);
        assert_eq!(req.resource_spans[0].scope_spans.len(), 1);
        assert_eq!(
            req.resource_spans[0].scope_spans[0].spans[0].name,
            "allowed.b"
        );
    }

    #[test]
    fn test_filter_traces_default_deny() {
        let rules = vec![];

        let mut req = ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans {
                scope_spans: vec![ScopeSpans {
                    spans: vec![span("anything")],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        };

        let result = filter(&mut req, &rules);
        assert_eq!(result.forwarded, 0);
        assert_eq!(result.denied, 1);
        assert!(req.resource_spans.is_empty());
    }

    #[test]
    fn test_filter_traces_signal_filter() {
        let rules = vec![
            rule(Action::Allow, "*", Some(Signal::Metrics)), // only metrics
        ];

        let mut req = ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans {
                scope_spans: vec![ScopeSpans {
                    spans: vec![span("any.span")],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        };

        let result = filter(&mut req, &rules);
        // Signal is Metrics, rule doesn't apply to Traces → default deny
        assert_eq!(result.forwarded, 0);
        assert_eq!(result.denied, 1);
    }

    #[test]
    fn test_filter_metrics_allow_deny() {
        let rules = vec![rule(Action::Allow, "myapp_*", None)];

        let mut req = ExportMetricsServiceRequest {
            resource_metrics: vec![ResourceMetrics {
                scope_metrics: vec![ScopeMetrics {
                    metrics: vec![metric("myapp_requests"), metric("other_metric")],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        };

        let result = filter(&mut req, &rules);
        assert_eq!(result.forwarded, 1);
        assert_eq!(result.denied, 1);
        assert_eq!(
            req.resource_metrics[0].scope_metrics[0].metrics[0].name,
            "myapp_requests"
        );
    }

    #[test]
    fn test_filter_metrics_prunes_empty_scopes() {
        let rules = vec![rule(Action::Allow, "keep.*", None)];

        let mut req = ExportMetricsServiceRequest {
            resource_metrics: vec![ResourceMetrics {
                scope_metrics: vec![
                    ScopeMetrics {
                        metrics: vec![metric("drop.a"), metric("drop.b")],
                        ..Default::default()
                    },
                    ScopeMetrics {
                        metrics: vec![metric("keep.c")],
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }],
        };

        let result = filter(&mut req, &rules);
        assert_eq!(result.forwarded, 1);
        assert_eq!(result.denied, 2);
        assert_eq!(req.resource_metrics[0].scope_metrics.len(), 1);
        assert_eq!(
            req.resource_metrics[0].scope_metrics[0].metrics[0].name,
            "keep.c"
        );
    }
}
