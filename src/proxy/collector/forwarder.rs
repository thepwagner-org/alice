use crate::proxy::prom::ProxyMetrics;
use anyhow::{anyhow, Result};
use opentelemetry_proto::tonic::collector::metrics::v1::{
    metrics_service_client::MetricsServiceClient, ExportMetricsServiceRequest,
};
use opentelemetry_proto::tonic::collector::trace::v1::{
    trace_service_client::TraceServiceClient, ExportTraceServiceRequest,
};
use tokio::sync::mpsc;
use tracing::warn;

const CHANNEL_CAPACITY: usize = 128;

pub enum ForwardPayload {
    Traces(ExportTraceServiceRequest),
    Metrics(ExportMetricsServiceRequest),
}

pub enum SendResult {
    Queued,
    Dropped,
}

pub struct Forwarder {
    tx: mpsc::Sender<ForwardPayload>,
}

impl Forwarder {
    pub fn spawn(endpoint: &str, prom: ProxyMetrics) -> Result<Self> {
        let ep = tonic::transport::Endpoint::from_shared(endpoint.to_string())
            .map_err(|e| anyhow!("invalid forward_endpoint: {e}"))?;
        let channel = ep.connect_lazy();

        let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
        drop(tokio::spawn(forwarder_task(rx, channel, prom)));

        Ok(Self { tx })
    }

    pub fn try_forward(&self, payload: ForwardPayload) -> SendResult {
        match self.tx.try_send(payload) {
            Ok(()) => SendResult::Queued,
            Err(_) => SendResult::Dropped,
        }
    }
}

async fn forwarder_task(
    mut rx: mpsc::Receiver<ForwardPayload>,
    channel: tonic::transport::Channel,
    prom: ProxyMetrics,
) {
    let mut trace_client = TraceServiceClient::new(channel.clone());
    let mut metrics_client = MetricsServiceClient::new(channel);

    while let Some(payload) = rx.recv().await {
        match payload {
            ForwardPayload::Traces(req) => {
                if let Err(e) = trace_client.export(req).await {
                    warn!(error = %e, "failed to forward traces to upstream");
                    prom.collector_forward_errors_total
                        .with_label_values(&["traces"])
                        .inc();
                }
            }
            ForwardPayload::Metrics(req) => {
                if let Err(e) = metrics_client.export(req).await {
                    warn!(error = %e, "failed to forward metrics to upstream");
                    prom.collector_forward_errors_total
                        .with_label_values(&["metrics"])
                        .inc();
                }
            }
        }
    }
}
