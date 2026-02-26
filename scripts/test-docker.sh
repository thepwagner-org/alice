#!/bin/bash
#
# Cargo build environment in Docker
#
# Builds and runs Alice on the host, then drops you into a Rust container
# with the source copied in and proxy env vars configured. All network
# traffic (cargo fetch, etc.) goes through Alice.
#
# Usage:
#   ./scripts/test-docker.sh                                  # Default config
#   ./scripts/test-docker.sh examples/policies/httpbin.toml   # Custom config
#
set -euo pipefail

CONFIG="${1:-examples/credentials.toml}"
PROXY_PORT=3128
ALICE_PID=""
IMAGE_NAME="alice-build"

# Extract cert_path from config, fallback to default
CA_CERT=$(grep -E '^\s*cert_path\s*=' "$CONFIG" | sed 's/.*=\s*"\(.*\)"/\1/' || echo "/tmp/alice-ca.pem")
if [[ -z "$CA_CERT" ]]; then
    CA_CERT="/tmp/alice-ca.pem"
fi

cleanup() {
    if [[ -n "$ALICE_PID" ]]; then
        echo "Stopping Alice (pid $ALICE_PID)..."
        kill "$ALICE_PID" 2>/dev/null || true
        wait "$ALICE_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# Build the Docker image first (before proxy is running, so it can pull layers)
echo "==> Building build environment image..."
docker build -q -t "$IMAGE_NAME" -f - . <<'DOCKERFILE'
FROM rust:latest
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /usr/src/alice
COPY . .
DOCKERFILE

echo "==> Building Alice..."
cargo build --release

echo "==> Starting Alice with config: $CONFIG"
rm -f "$CA_CERT"
RUST_LOG=info REAL_TOKEN="${REAL_TOKEN:-hunter2}" cargo run --release --quiet -- -c "$CONFIG" &
ALICE_PID=$!

echo "==> Waiting for CA certificate at $CA_CERT..."
timeout=30
while [[ ! -f "$CA_CERT" ]]; do
    sleep 0.1
    timeout=$((timeout - 1))
    if [[ $timeout -le 0 ]]; then
        echo "Error: Timed out waiting for CA certificate"
        exit 1
    fi
done
echo "    CA certificate ready"

echo "==> Waiting for proxy to be ready on port $PROXY_PORT..."
timeout=30
while ! nc -z 127.0.0.1 "$PROXY_PORT" 2>/dev/null; do
    sleep 0.1
    timeout=$((timeout - 1))
    if [[ $timeout -le 0 ]]; then
        echo "Error: Timed out waiting for proxy"
        exit 1
    fi
done
echo "    Proxy ready"

PROXY_HOST="host.docker.internal"

echo "==> Launching build environment..."
echo ""
echo "    cargo build            # Debug build"
echo "    cargo build --release  # Release build"
echo "    cargo test             # Run tests"
echo "    cargo clippy           # Lint"
echo ""
echo "    All traffic goes through Alice at $PROXY_HOST:$PROXY_PORT"
echo "    Type 'exit' to stop"
echo ""

docker run -it --rm \
    --add-host=host.docker.internal:host-gateway \
    -v "$CA_CERT:/usr/local/share/ca-certificates/alice-ca.crt:ro" \
    -e "http_proxy=http://$PROXY_HOST:$PROXY_PORT" \
    -e "HTTP_PROXY=http://$PROXY_HOST:$PROXY_PORT" \
    -e "https_proxy=http://$PROXY_HOST:$PROXY_PORT" \
    -e "HTTPS_PROXY=http://$PROXY_HOST:$PROXY_PORT" \
    "$IMAGE_NAME" \
    sh -c 'update-ca-certificates >/dev/null 2>&1 && exec bash'
