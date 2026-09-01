//! Integration tests for alice's StatsD UDP collector.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    unused_results,
    clippy::print_stdout
)]

use opentelemetry_proto::tonic::collector::metrics::v1::{
    metrics_service_server::{MetricsService, MetricsServiceServer},
    ExportMetricsServiceRequest, ExportMetricsServiceResponse,
};
use std::time::Duration;
use tempfile::TempDir;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use tokio_stream::wrappers::TcpListenerStream;

// ── Fake gRPC MetricsService ────────────────────────────────────────────────

struct FakeMetricsService {
    tx: Mutex<mpsc::Sender<ExportMetricsServiceRequest>>,
}

#[tonic::async_trait]
impl MetricsService for FakeMetricsService {
    async fn export(
        &self,
        request: tonic::Request<ExportMetricsServiceRequest>,
    ) -> Result<tonic::Response<ExportMetricsServiceResponse>, tonic::Status> {
        let _ = self.tx.lock().await.send(request.into_inner()).await;
        Ok(tonic::Response::new(ExportMetricsServiceResponse {
            partial_success: None,
        }))
    }
}

async fn spawn_fake_metrics_server(
    port: u16,
) -> (
    mpsc::Receiver<ExportMetricsServiceRequest>,
    tokio::task::JoinHandle<()>,
) {
    let (tx, rx) = mpsc::channel::<ExportMetricsServiceRequest>(16);
    let svc = MetricsServiceServer::new(FakeMetricsService { tx: Mutex::new(tx) });

    let listener = TcpListener::bind(format!("127.0.0.1:{port}"))
        .await
        .expect("bind fake gRPC metrics server");

    let handle = tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    (rx, handle)
}

// ── Alice subprocess helpers ────────────────────────────────────────────────

async fn spawn_alice_statsd(
    proxy_port: u16,
    otlp_http_port: u16,
    statsd_port: u16,
    metrics_port: u16,
    grpc_endpoint: &str,
    allowed_name: &str,
    temp_dir: &TempDir,
) -> tokio::task::JoinHandle<()> {
    let ca_cert_path = temp_dir.path().join("ca.pem");
    let config_path = temp_dir.path().join("config.toml");

    let config = format!(
        r#"[proxy]
listen = "127.0.0.1:{proxy_port}"

[ca]
cert_path = "{ca_path}"
validity_hours = 1
host_cert_validity_hours = 1

[observability]
metrics_listen = "127.0.0.1:{metrics_port}"

[observability.collector]
otlp_http_listen = "127.0.0.1:{otlp_http_port}"
statsd_listen = "127.0.0.1:{statsd_port}"
forward_endpoint = "{grpc_endpoint}"

[[observability.collector.rules]]
action = "allow"
name = "{allowed_name}"
"#,
        proxy_port = proxy_port,
        ca_path = ca_cert_path.display(),
        metrics_port = metrics_port,
        otlp_http_port = otlp_http_port,
        statsd_port = statsd_port,
        grpc_endpoint = grpc_endpoint,
        allowed_name = allowed_name,
    );

    std::fs::write(&config_path, &config).expect("write config");

    let handle = tokio::spawn(async move {
        let _ = tokio::process::Command::new(env!("CARGO_BIN_EXE_alice"))
            .arg("-c")
            .arg(&config_path)
            .kill_on_drop(true)
            .status()
            .await;
    });

    // Wait for CA cert (alice startup signal).
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        if ca_cert_path.exists() {
            break;
        }
    }

    // Wait for OTLP/HTTP TCP port to be reachable (confirms alice is fully up).
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(30)).await;
        if tokio::net::TcpStream::connect(format!("127.0.0.1:{otlp_http_port}"))
            .await
            .is_ok()
        {
            break;
        }
    }

    handle
}

async fn find_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = l.local_addr().expect("local_addr").port();
    drop(l);
    port
}

async fn find_udp_port() -> u16 {
    let s = UdpSocket::bind("127.0.0.1:0").await.expect("bind UDP");
    let port = s.local_addr().expect("local_addr").port();
    drop(s);
    port
}

async fn get_metrics(port: u16) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("connect to metrics");

    let header =
        format!("GET /metrics HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(header.as_bytes())
        .await
        .expect("write request");

    let mut resp = Vec::new();
    stream.read_to_end(&mut resp).await.expect("read response");

    let resp_str = String::from_utf8_lossy(&resp);
    if let Some(pos) = resp_str.find("\r\n\r\n") {
        resp_str[pos + 4..].to_string()
    } else {
        resp_str.to_string()
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_statsd_allow_deny_and_forward() {
    let proxy_port = find_port().await;
    let otlp_http_port = find_port().await;
    let metrics_port = find_port().await;
    let grpc_port = find_port().await;
    let statsd_port = find_udp_port().await;

    let (mut grpc_rx, _grpc_handle) = spawn_fake_metrics_server(grpc_port).await;

    let temp_dir = TempDir::new().expect("tempdir");
    let _alice = spawn_alice_statsd(
        proxy_port,
        otlp_http_port,
        statsd_port,
        metrics_port,
        &format!("http://127.0.0.1:{grpc_port}"),
        "allowed_metric",
        &temp_dir,
    )
    .await;

    // Send two metrics in a single UDP packet: one allowed, one denied.
    let sender = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind sender socket");
    sender
        .send_to(
            b"allowed_metric:5|c\ndenied_metric:1|c",
            format!("127.0.0.1:{statsd_port}"),
        )
        .await
        .expect("send statsd packet");

    // Alice flushes every ~1s; wait up to 5s for the forwarded gRPC call.
    let received = tokio::time::timeout(Duration::from_secs(5), grpc_rx.recv())
        .await
        .expect("timeout waiting for gRPC export")
        .expect("channel closed");

    // Only the allowed metric should have been forwarded.
    let names: Vec<&str> = received
        .resource_metrics
        .iter()
        .flat_map(|rm| &rm.scope_metrics)
        .flat_map(|sm| &sm.metrics)
        .map(|m| m.name.as_str())
        .collect();
    assert_eq!(names, vec!["allowed_metric"], "wrong metrics forwarded");

    // Prometheus counters: forwarded=1, denied=1.
    let metrics_body = get_metrics(metrics_port).await;
    assert!(
        metrics_body
            .contains("alice_collector_received_total{result=\"forwarded\",signal=\"metrics\"} 1"),
        "expected forwarded=1 in:\n{metrics_body}"
    );
    assert!(
        metrics_body
            .contains("alice_collector_received_total{result=\"denied\",signal=\"metrics\"} 1"),
        "expected denied=1 in:\n{metrics_body}"
    );
}
