use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use tracing::info;

mod config;
mod credentials;
mod proxy;
mod telemetry;

#[derive(Parser, Debug)]
#[command(name = "alice", about = "A sanitizing HTTPS proxy")]
struct Args {
    /// Path to config file
    #[arg(short, long)]
    config: PathBuf,

    /// Output logs as JSON (default: human-readable)
    #[arg(long)]
    json: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Load config first so we can get telemetry settings
    let config = config::load(&args.config)?;

    // Initialize tracing with optional OTLP export
    let otlp_endpoint = config
        .observability
        .as_ref()
        .and_then(|o| o.otlp_endpoint.as_deref());
    let _tracing_guard = telemetry::init_tracing("alice", "info", args.json, otlp_endpoint);

    info!(listen = %config.proxy.listen, "starting alice proxy");

    // Run proxy with graceful shutdown
    proxy::run(config).await
}
