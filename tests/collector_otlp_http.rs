//! Integration tests for alice's OTLP/HTTP collector.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    unused_results,
    clippy::print_stdout
)]

use opentelemetry_proto::tonic::collector::trace::v1::{
    trace_service_server::{TraceService, TraceServiceServer},
    ExportTraceServiceRequest, ExportTraceServiceResponse,
};
use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span};
use prost::Message;
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use tokio_stream::wrappers::TcpListenerStream;

// ── Fake gRPC TraceService ──────────────────────────────────────────────────

struct FakeTraceService {
    tx: Mutex<mpsc::Sender<ExportTraceServiceRequest>>,
}

#[tonic::async_trait]
impl TraceService for FakeTraceService {
    async fn export(
        &self,
        request: tonic::Request<ExportTraceServiceRequest>,
    ) -> Result<tonic::Response<ExportTraceServiceResponse>, tonic::Status> {
        let _ = self.tx.lock().await.send(request.into_inner()).await;
        Ok(tonic::Response::new(ExportTraceServiceResponse {
            partial_success: None,
        }))
    }
}

/// Spawn a fake tonic gRPC TraceService server. Returns a channel that
/// receives every ExportTraceServiceRequest alice sends.
async fn spawn_fake_trace_server(
    port: u16,
) -> (
    mpsc::Receiver<ExportTraceServiceRequest>,
    tokio::task::JoinHandle<()>,
) {
    let (tx, rx) = mpsc::channel::<ExportTraceServiceRequest>(16);
    let svc = TraceServiceServer::new(FakeTraceService { tx: Mutex::new(tx) });

    let listener = TcpListener::bind(format!("127.0.0.1:{port}"))
        .await
        .expect("bind fake gRPC server");

    let handle = tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await;
    });

    // Give the server a moment to be ready.
    tokio::time::sleep(Duration::from_millis(50)).await;

    (rx, handle)
}

// ── Alice subprocess helpers ────────────────────────────────────────────────

async fn spawn_alice_collector(
    proxy_port: u16,
    collector_port: u16,
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
otlp_http_listen = "127.0.0.1:{collector_port}"
forward_endpoint = "{grpc_endpoint}"

[[observability.collector.rules]]
action = "allow"
name = "{allowed_name}"
"#,
        proxy_port = proxy_port,
        ca_path = ca_cert_path.display(),
        metrics_port = metrics_port,
        grpc_endpoint = grpc_endpoint,
        collector_port = collector_port,
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

    // Wait until the collector HTTP port accepts connections.
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(30)).await;
        if tokio::net::TcpStream::connect(format!("127.0.0.1:{collector_port}"))
            .await
            .is_ok()
        {
            break;
        }
    }

    handle
}

/// Encode and POST a protobuf body to alice's OTLP/HTTP collector.
/// Returns the HTTP status code.
async fn post_proto(port: u16, path: &str, body: Vec<u8>) -> u16 {
    let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("connect to collector");

    let header = format!(
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/x-protobuf\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(header.as_bytes())
        .await
        .expect("write header");
    stream.write_all(&body).await.expect("write body");

    let mut resp = Vec::new();
    stream.read_to_end(&mut resp).await.expect("read response");

    let resp_str = String::from_utf8_lossy(&resp);
    resp_str
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

/// GET alice's /metrics endpoint and return the body.
async fn get_metrics(port: u16) -> String {
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

    // Return everything after the blank line (the body).
    let resp_str = String::from_utf8_lossy(&resp);
    if let Some(pos) = resp_str.find("\r\n\r\n") {
        resp_str[pos + 4..].to_string()
    } else {
        resp_str.to_string()
    }
}

/// Build a serialised ExportTraceServiceRequest with two spans.
fn build_trace_request(allowed: &str, denied: &str) -> Vec<u8> {
    let req = ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            scope_spans: vec![ScopeSpans {
                spans: vec![
                    Span {
                        name: allowed.to_string(),
                        ..Default::default()
                    },
                    Span {
                        name: denied.to_string(),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }],
            ..Default::default()
        }],
    };
    req.encode_to_vec()
}

/// Grab an available TCP port (TOCTOU-safe enough for tests).
async fn find_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = l.local_addr().expect("local_addr").port();
    drop(l);
    port
}

// ── Test ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_collector_allow_deny_and_forward() {
    let proxy_port = find_port().await;
    let collector_port = find_port().await;
    let metrics_port = find_port().await;
    let grpc_port = find_port().await;

    let (mut grpc_rx, _grpc_handle) = spawn_fake_trace_server(grpc_port).await;

    let temp_dir = TempDir::new().expect("tempdir");
    let _alice = spawn_alice_collector(
        proxy_port,
        collector_port,
        metrics_port,
        &format!("http://127.0.0.1:{grpc_port}"),
        "allowed-span",
        &temp_dir,
    )
    .await;

    // POST a request with one allowed and one denied span.
    let body = build_trace_request("allowed-span", "denied-span");
    let status = post_proto(collector_port, "/v1/traces", body).await;
    assert_eq!(status, 200, "expected 200 from collector");

    // The forwarder is async; give it a moment to complete the gRPC call.
    let received = tokio::time::timeout(Duration::from_secs(5), grpc_rx.recv())
        .await
        .expect("timeout waiting for gRPC")
        .expect("channel closed");

    // Only the allowed span should have been forwarded.
    let spans: Vec<&str> = received
        .resource_spans
        .iter()
        .flat_map(|rs| &rs.scope_spans)
        .flat_map(|ss| &ss.spans)
        .map(|s| s.name.as_str())
        .collect();
    assert_eq!(spans, vec!["allowed-span"], "wrong spans forwarded");

    // Check Prometheus metrics.
    let metrics_body = get_metrics(metrics_port).await;

    // forwarded = 1 (the allowed span was queued)
    assert!(
        metrics_body
            .contains("alice_collector_received_total{result=\"forwarded\",signal=\"traces\"} 1"),
        "expected forwarded=1 in:\n{metrics_body}"
    );
    // denied = 1 (the denied span was filtered out)
    assert!(
        metrics_body
            .contains("alice_collector_received_total{result=\"denied\",signal=\"traces\"} 1"),
        "expected denied=1 in:\n{metrics_body}"
    );
}

#[tokio::test]
async fn test_collector_decode_error() {
    let proxy_port = find_port().await;
    let collector_port = find_port().await;
    let metrics_port = find_port().await;
    let grpc_port = find_port().await;

    let (_grpc_rx, _grpc_handle) = spawn_fake_trace_server(grpc_port).await;

    let temp_dir = TempDir::new().expect("tempdir");
    let _alice = spawn_alice_collector(
        proxy_port,
        collector_port,
        metrics_port,
        &format!("http://127.0.0.1:{grpc_port}"),
        "*",
        &temp_dir,
    )
    .await;

    // POST garbage bytes — not a valid protobuf.
    let status = post_proto(collector_port, "/v1/traces", vec![0xFF, 0xFE, 0x00]).await;
    assert_eq!(status, 400, "expected 400 Bad Request on decode error");

    let metrics_body = get_metrics(metrics_port).await;
    assert!(
        metrics_body.contains(
            "alice_collector_received_total{result=\"decode_error\",signal=\"traces\"} 1"
        ),
        "expected decode_error=1 in:\n{metrics_body}"
    );
}

#[tokio::test]
async fn test_collector_unknown_path_returns_404() {
    let proxy_port = find_port().await;
    let collector_port = find_port().await;
    let metrics_port = find_port().await;
    let grpc_port = find_port().await;

    let (_grpc_rx, _grpc_handle) = spawn_fake_trace_server(grpc_port).await;

    let temp_dir = TempDir::new().expect("tempdir");
    let _alice = spawn_alice_collector(
        proxy_port,
        collector_port,
        metrics_port,
        &format!("http://127.0.0.1:{grpc_port}"),
        "*",
        &temp_dir,
    )
    .await;

    let status = post_proto(collector_port, "/v1/logs", vec![]).await;
    assert_eq!(status, 404, "expected 404 for unknown path");
}
