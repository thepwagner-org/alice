#!/bin/bash
#
# Integration testing with Docker
#
# Builds and runs Alice on the host, then drops you into an Alpine container
# with curl and the CA cert pre-trusted. The proxy is auto-configured.
#
# Usage:
#   ./scripts/test-docker.sh                           # Default credentials.toml
#   ./scripts/test-docker.sh examples/policies/httpbin.toml  # Custom config
#
set -euo pipefail

CONFIG="${1:-examples/credentials.toml}"
PROXY_PORT=3128
ALICE_PID=""
IMAGE_NAME="alice-test-client"

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

# Build test image first (before proxy is running, so apk can reach the internet)
echo "==> Building test container image..."
docker build -q -t "$IMAGE_NAME" - <<'DOCKERFILE'
FROM google/cloud-sdk:alpine
RUN apk add --no-cache curl ca-certificates jq openssl
COPY <<'SCRIPT' /usr/local/bin/test.sh
#!/bin/sh
set -e

pass() { printf "\033[32mPASS\033[0m %s\n" "$1"; }
fail() { printf "\033[31mFAIL\033[0m %s\n" "$1"; }

# Test 1: GCP auth (if dummy key is available)
if [ -f "/tmp/gcp-dummy-sa.json" ]; then
    echo "=== Test 1: GCP service account activation ==="
    PROJECT=$(jq -r .project_id /tmp/gcp-dummy-sa.json)
    SA_EMAIL=$(jq -r .client_email /tmp/gcp-dummy-sa.json)
    if gcloud auth activate-service-account --key-file=/tmp/gcp-dummy-sa.json 2>&1; then
        pass "activated $SA_EMAIL"
    else
        fail "service account activation"
    fi
    echo ""

    echo "=== Test 2: GCP API call (projects.get) ==="
    if gcloud projects describe "$PROJECT" --format='value(projectId)' 2>/dev/null; then
        pass "projects.describe $PROJECT"
    else
        fail "projects.describe (SA may lack resourcemanager.projects.get permission)"
    fi
    echo ""

    # Test 2b: Verify Alice rejects a JWT signed with a different private key
    # (same SA metadata, wrong RSA key — must not be re-signed)
    if [ -f "/tmp/gcp-bad-dummy-sa.json" ]; then
        echo "=== Test 2b: Reject SA key with wrong private key ==="
        BAD_EMAIL=$(jq -r .client_email /tmp/gcp-bad-dummy-sa.json)
        gcloud auth activate-service-account "$BAD_EMAIL" --key-file=/tmp/gcp-bad-dummy-sa.json 2>/dev/null
        # Try an API call — Alice should reject the JWT (signature mismatch)
        if gcloud projects describe "$PROJECT" --account="$BAD_EMAIL" --format='value(projectId)' 2>/dev/null; then
            fail "bad key was accepted (Alice should have rejected it)"
        else
            pass "bad key rejected (JWT signature verification failed)"
        fi
        # Switch back to the good SA
        gcloud config set account "$SA_EMAIL" 2>/dev/null
        echo ""
    fi
else
    echo "=== Skipping GCP tests (no dummy key at /tmp/gcp-dummy-sa.json) ==="
    echo ""
fi

# Test 3: GCP user credential (if dummy gcloud config is available)
if [ -f "/root/.config/gcloud/credentials.db" ]; then
    echo "=== Test 3: GCP user credential (refresh token) ==="
    # gcloud should already be configured via the mounted config dir
    ACCOUNT=$(gcloud config get-value account 2>/dev/null)
    if [ -n "$ACCOUNT" ]; then
        pass "active account: $ACCOUNT"
        if gcloud projects list --limit=1 --format='value(projectId)' 2>/dev/null; then
            pass "projects.list with user credential"
        else
            fail "projects.list with user credential"
        fi
    else
        fail "no active account in dummy config"
    fi
    echo ""
else
    echo "=== Skipping GCP user credential tests (no dummy gcloud config) ==="
    echo ""
fi

# Test 4: Blocked request
echo "=== Test 4: Blocked request (google.com) ==="
STATUS=$(curl -s -o /dev/null -w "%{http_code}" https://google.com 2>/dev/null || true)
if [ "$STATUS" = "403" ]; then
    pass "google.com blocked (HTTP $STATUS)"
else
    fail "expected 403, got $STATUS"
fi
echo ""

echo "Done!"
SCRIPT
RUN chmod +x /usr/local/bin/test.sh
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

# Verify Alice is listening
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

# host.docker.internal works on macOS natively and on Linux with --add-host
PROXY_HOST="host.docker.internal"

# Check for GCP dummy key (written by Alice at startup if gcp_credentials configured)
GCP_DUMMY_KEY="/tmp/alice-gcp-dummy.json"
GCP_BAD_KEY="/tmp/alice-gcp-bad-dummy.json"
GCP_MOUNT_ARGS=""
GCP_ENV_ARGS=""
if [[ -f "$GCP_DUMMY_KEY" ]]; then
    GCP_MOUNT_ARGS="-v $GCP_DUMMY_KEY:/tmp/gcp-dummy-sa.json:ro"
    GCP_ENV_ARGS="-e GOOGLE_APPLICATION_CREDENTIALS=/tmp/gcp-dummy-sa.json"
    echo "    GCP dummy key found at $GCP_DUMMY_KEY (mounted as /tmp/gcp-dummy-sa.json)"

    # Generate a "bad" dummy key: same SA metadata but a different RSA private key.
    # This tests that Alice verifies the JWT signature, not just the issuer claim.
    BAD_RSA_KEY=$(openssl genrsa 2048 2>/dev/null)
    jq --arg key "$BAD_RSA_KEY" '.private_key = $key | .private_key_id = "bad-key-wrong-signer"' \
        "$GCP_DUMMY_KEY" > "$GCP_BAD_KEY"
    GCP_MOUNT_ARGS="$GCP_MOUNT_ARGS -v $GCP_BAD_KEY:/tmp/gcp-bad-dummy-sa.json:ro"
    echo "    Bad dummy key generated at $GCP_BAD_KEY (wrong private key, same metadata)"
fi

# Check for GCP user credentials (dummy gcloud config dir written by Alice)
GCP_DUMMY_CONFIG="/tmp/alice-gcloud"
if [[ -d "$GCP_DUMMY_CONFIG" ]]; then
    GCP_MOUNT_ARGS="$GCP_MOUNT_ARGS -v $GCP_DUMMY_CONFIG:/root/.config/gcloud"
    echo "    GCP dummy config found at $GCP_DUMMY_CONFIG (mounted as /root/.config/gcloud)"
fi

echo "==> Launching test container..."
echo "    Proxy: http://$PROXY_HOST:$PROXY_PORT"
echo ""
echo "    Run 'test.sh' for quick tests, or try manually:"
echo "      gcloud projects describe <project>     # GCP API (if key configured)"
echo "      curl https://google.com                # Blocked"
echo ""
echo "    Type 'exit' to stop"
echo ""

docker run -it --rm \
    --add-host=host.docker.internal:host-gateway \
    -v "$CA_CERT:/usr/local/share/ca-certificates/alice-ca.crt:ro" \
    $GCP_MOUNT_ARGS \
    -e "http_proxy=http://$PROXY_HOST:$PROXY_PORT" \
    -e "HTTP_PROXY=http://$PROXY_HOST:$PROXY_PORT" \
    -e "https_proxy=http://$PROXY_HOST:$PROXY_PORT" \
    -e "HTTPS_PROXY=http://$PROXY_HOST:$PROXY_PORT" \
    $GCP_ENV_ARGS \
    "$IMAGE_NAME" \
    sh -c 'update-ca-certificates >/dev/null 2>&1 && gcloud config set core/custom_ca_certs_file /usr/local/share/ca-certificates/alice-ca.crt 2>/dev/null; exec sh'
