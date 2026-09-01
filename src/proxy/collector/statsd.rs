use super::CollectorState;
use crate::proxy::collector::allowlist;
use anyhow::{anyhow, Result};
use opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest;
use opentelemetry_proto::tonic::common::v1::{any_value, AnyValue, KeyValue};
use opentelemetry_proto::tonic::metrics::v1::{
    metric, number_data_point, AggregationTemporality, Gauge, Histogram, HistogramDataPoint,
    Metric, NumberDataPoint, ResourceMetrics, ScopeMetrics, Sum,
};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::time::{interval_at, Duration, Instant, MissedTickBehavior};
use tracing::{debug, warn};

const FLUSH_INTERVAL: Duration = Duration::from_secs(1);
const FLUSH_BATCH_SIZE: usize = 256;

pub async fn spawn(
    listen: &str,
    state: Arc<CollectorState>,
) -> Result<(std::net::SocketAddr, tokio::task::JoinHandle<()>)> {
    let socket = UdpSocket::bind(listen).await?;
    let addr = socket.local_addr()?;
    debug!(addr = %addr, "statsd UDP listener started");
    let handle = tokio::spawn(run(socket, state));
    Ok((addr, handle))
}

async fn run(socket: UdpSocket, state: Arc<CollectorState>) {
    let mut buf = vec![0u8; 65536];
    let mut pending: Vec<Metric> = Vec::new();

    let mut flush_ticker = interval_at(Instant::now() + FLUSH_INTERVAL, FLUSH_INTERVAL);
    flush_ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = flush_ticker.tick() => {
                if !pending.is_empty() {
                    flush(&mut pending, &state);
                }
            }
            result = socket.recv_from(&mut buf) => {
                match result {
                    Ok((n, _addr)) => {
                        let data = &buf[..n];
                        for raw in data.split(|&b| b == b'\n') {
                            let Ok(line) = std::str::from_utf8(raw) else { continue };
                            let line = line.trim();
                            if line.is_empty() {
                                continue;
                            }
                            match parse_packet(line) {
                                Ok(pkt) => {
                                    pending.push(packet_to_metric(pkt));
                                    if pending.len() >= FLUSH_BATCH_SIZE {
                                        flush(&mut pending, &state);
                                    }
                                }
                                Err(e) => {
                                    debug!(error = %e, line = line, "statsd: ignoring malformed line");
                                }
                            }
                        }
                    }
                    Err(e) => warn!(error = %e, "statsd: recv_from error"),
                }
            }
        }
    }
}

fn flush(pending: &mut Vec<Metric>, state: &CollectorState) {
    let mut req = ExportMetricsServiceRequest {
        resource_metrics: vec![ResourceMetrics {
            scope_metrics: vec![ScopeMetrics {
                metrics: std::mem::take(pending),
                ..Default::default()
            }],
            ..Default::default()
        }],
    };

    let fr = allowlist::filter(&mut req, &state.rules);
    state.forward_filtered(req, &fr, "statsd");
}

#[derive(Debug, PartialEq)]
struct StatsdPacket {
    name: String,
    value: f64,
    kind: MetricKind,
    sample_rate: f64,
    tags: Vec<(String, String)>,
}

#[derive(Debug, PartialEq)]
enum MetricKind {
    Counter,
    Gauge,
    Timing,
    Histogram,
}

/// Parse a single StatsD line: `name:value|type[|@rate][|#tag1:v1,tag2:v2]`
fn parse_packet(line: &str) -> Result<StatsdPacket> {
    let (name, rest) = line.split_once(':').ok_or_else(|| anyhow!("missing ':'"))?;
    if name.is_empty() {
        return Err(anyhow!("empty name"));
    }

    let mut parts = rest.split('|');

    let value_str = parts.next().ok_or_else(|| anyhow!("missing value"))?;
    let value: f64 = value_str
        .parse()
        .map_err(|_| anyhow!("invalid value: {value_str}"))?;

    let type_str = parts.next().ok_or_else(|| anyhow!("missing type"))?;
    let kind = match type_str {
        "c" => MetricKind::Counter,
        "g" => MetricKind::Gauge,
        "ms" => MetricKind::Timing,
        "h" => MetricKind::Histogram,
        other => return Err(anyhow!("unknown metric type: {other}")),
    };

    let mut sample_rate = 1.0f64;
    let mut tags = Vec::new();

    for part in parts {
        if let Some(rate_str) = part.strip_prefix('@') {
            sample_rate = rate_str
                .parse()
                .map_err(|_| anyhow!("invalid sample rate: {rate_str}"))?;
        } else if let Some(tag_str) = part.strip_prefix('#') {
            for tag in tag_str.split(',') {
                let (k, v) = tag.split_once(':').unwrap_or((tag, ""));
                tags.push((k.to_string(), v.to_string()));
            }
        }
    }

    Ok(StatsdPacket {
        name: name.to_string(),
        value,
        kind,
        sample_rate,
        tags,
    })
}

fn now_unix_nano() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

fn tags_to_attributes(tags: Vec<(String, String)>) -> Vec<KeyValue> {
    tags.into_iter()
        .map(|(k, v)| KeyValue {
            key: k,
            value: Some(AnyValue {
                value: Some(any_value::Value::StringValue(v)),
            }),
            // `key_strindex` is a profiles-only string-table reference and MUST
            // stay unset (0) whenever `key` carries the name inline.
            ..Default::default()
        })
        .collect()
}

fn packet_to_metric(packet: StatsdPacket) -> Metric {
    let now = now_unix_nano();
    let attrs = tags_to_attributes(packet.tags);

    match packet.kind {
        MetricKind::Counter => {
            let adjusted = packet.value / packet.sample_rate;
            Metric {
                name: packet.name,
                data: Some(metric::Data::Sum(Sum {
                    data_points: vec![NumberDataPoint {
                        attributes: attrs,
                        time_unix_nano: now,
                        value: Some(number_data_point::Value::AsDouble(adjusted)),
                        ..Default::default()
                    }],
                    aggregation_temporality: AggregationTemporality::Delta as i32,
                    is_monotonic: true,
                })),
                ..Default::default()
            }
        }
        MetricKind::Gauge => Metric {
            name: packet.name,
            data: Some(metric::Data::Gauge(Gauge {
                data_points: vec![NumberDataPoint {
                    attributes: attrs,
                    time_unix_nano: now,
                    value: Some(number_data_point::Value::AsDouble(packet.value)),
                    ..Default::default()
                }],
            })),
            ..Default::default()
        },
        MetricKind::Timing | MetricKind::Histogram => Metric {
            name: packet.name,
            data: Some(metric::Data::Histogram(Histogram {
                data_points: vec![HistogramDataPoint {
                    attributes: attrs,
                    time_unix_nano: now,
                    count: 1,
                    sum: Some(packet.value),
                    // Single +inf bucket — no client-side bucketing;
                    // the downstream collector re-aggregates.
                    bucket_counts: vec![1],
                    explicit_bounds: vec![],
                    ..Default::default()
                }],
                aggregation_temporality: AggregationTemporality::Delta as i32,
            })),
            ..Default::default()
        },
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        unused_results
    )]

    use super::*;
    use opentelemetry_proto::tonic::common::v1::any_value;
    use opentelemetry_proto::tonic::metrics::v1::{
        metric, number_data_point, AggregationTemporality,
    };

    // ── parser table tests ────────────────────────────────────────────────────

    #[test]
    fn parse_counter_basic() {
        let p = parse_packet("requests:5|c").unwrap();
        assert_eq!(p.name, "requests");
        assert_eq!(p.value, 5.0);
        assert_eq!(p.kind, MetricKind::Counter);
        assert_eq!(p.sample_rate, 1.0);
        assert!(p.tags.is_empty());
    }

    #[test]
    fn parse_gauge() {
        let p = parse_packet("memory:1024|g").unwrap();
        assert_eq!(p.name, "memory");
        assert_eq!(p.value, 1024.0);
        assert_eq!(p.kind, MetricKind::Gauge);
    }

    #[test]
    fn parse_timing() {
        let p = parse_packet("latency:42.5|ms").unwrap();
        assert_eq!(p.kind, MetricKind::Timing);
        assert_eq!(p.value, 42.5);
    }

    #[test]
    fn parse_histogram() {
        let p = parse_packet("size:100|h").unwrap();
        assert_eq!(p.kind, MetricKind::Histogram);
        assert_eq!(p.value, 100.0);
    }

    #[test]
    fn parse_counter_with_sample_rate() {
        let p = parse_packet("hits:1|c|@0.5").unwrap();
        assert_eq!(p.sample_rate, 0.5);
    }

    #[test]
    fn parse_with_tags() {
        let p = parse_packet("requests:1|c|#env:prod,region:us-west").unwrap();
        assert_eq!(
            p.tags,
            vec![
                ("env".to_string(), "prod".to_string()),
                ("region".to_string(), "us-west".to_string()),
            ]
        );
    }

    #[test]
    fn parse_with_sample_rate_and_tags() {
        let p = parse_packet("events:3|c|@0.1|#host:myhost").unwrap();
        assert_eq!(p.value, 3.0);
        assert_eq!(p.sample_rate, 0.1);
        assert_eq!(p.tags[0], ("host".to_string(), "myhost".to_string()));
    }

    #[test]
    fn parse_malformed_no_colon() {
        assert!(parse_packet("badline").is_err());
    }

    #[test]
    fn parse_malformed_no_type() {
        assert!(parse_packet("name:5").is_err());
    }

    #[test]
    fn parse_malformed_bad_value() {
        assert!(parse_packet("name:abc|c").is_err());
    }

    #[test]
    fn parse_malformed_unknown_type() {
        assert!(parse_packet("name:1|x").is_err());
    }

    #[test]
    fn parse_empty_name() {
        assert!(parse_packet(":1|c").is_err());
    }

    // ── conversion tests ──────────────────────────────────────────────────────

    #[test]
    fn counter_becomes_sum() {
        let m = packet_to_metric(StatsdPacket {
            name: "req".to_string(),
            value: 5.0,
            kind: MetricKind::Counter,
            sample_rate: 1.0,
            tags: vec![],
        });
        assert_eq!(m.name, "req");
        let Some(metric::Data::Sum(sum)) = m.data else {
            panic!("expected Sum")
        };
        assert!(sum.is_monotonic);
        assert_eq!(
            sum.aggregation_temporality,
            AggregationTemporality::Delta as i32
        );
        let Some(number_data_point::Value::AsDouble(v)) = sum.data_points[0].value else {
            panic!("expected double value")
        };
        assert_eq!(v, 5.0);
    }

    #[test]
    fn counter_sample_rate_scaling() {
        let m = packet_to_metric(StatsdPacket {
            name: "req".to_string(),
            value: 1.0,
            kind: MetricKind::Counter,
            sample_rate: 0.5,
            tags: vec![],
        });
        let Some(metric::Data::Sum(sum)) = m.data else {
            panic!("expected Sum")
        };
        let Some(number_data_point::Value::AsDouble(v)) = sum.data_points[0].value else {
            panic!()
        };
        assert_eq!(v, 2.0); // 1.0 / 0.5
    }

    #[test]
    fn gauge_becomes_gauge() {
        let m = packet_to_metric(StatsdPacket {
            name: "mem".to_string(),
            value: 1024.0,
            kind: MetricKind::Gauge,
            sample_rate: 1.0,
            tags: vec![],
        });
        assert!(matches!(m.data, Some(metric::Data::Gauge(_))));
    }

    #[test]
    fn timing_becomes_histogram() {
        let m = packet_to_metric(StatsdPacket {
            name: "latency".to_string(),
            value: 42.0,
            kind: MetricKind::Timing,
            sample_rate: 1.0,
            tags: vec![],
        });
        let Some(metric::Data::Histogram(h)) = m.data else {
            panic!("expected Histogram")
        };
        assert_eq!(h.data_points[0].count, 1);
        assert_eq!(h.data_points[0].sum, Some(42.0));
        assert_eq!(
            h.aggregation_temporality,
            AggregationTemporality::Delta as i32
        );
    }

    #[test]
    fn histogram_kind_becomes_histogram() {
        let m = packet_to_metric(StatsdPacket {
            name: "size".to_string(),
            value: 100.0,
            kind: MetricKind::Histogram,
            sample_rate: 1.0,
            tags: vec![],
        });
        assert!(matches!(m.data, Some(metric::Data::Histogram(_))));
    }

    #[test]
    fn tags_become_attributes() {
        let m = packet_to_metric(StatsdPacket {
            name: "req".to_string(),
            value: 1.0,
            kind: MetricKind::Counter,
            sample_rate: 1.0,
            tags: vec![("env".to_string(), "prod".to_string())],
        });
        let Some(metric::Data::Sum(sum)) = m.data else {
            panic!()
        };
        let attrs = &sum.data_points[0].attributes;
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0].key, "env");
        let Some(ref av) = attrs[0].value else {
            panic!()
        };
        let Some(any_value::Value::StringValue(ref v)) = av.value else {
            panic!()
        };
        assert_eq!(v, "prod");
    }
}
