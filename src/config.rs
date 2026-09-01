use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
pub struct Config {
    pub proxy: ProxyConfig,
    pub ca: CaConfig,
    #[serde(default)]
    pub dns: DnsConfig,
    #[serde(default)]
    pub rules: Vec<Rule>,
    #[serde(default)]
    pub credentials: Vec<Credential>,
    /// GCP service account credentials (proxy-side JWT signing)
    #[serde(default)]
    pub gcp_credentials: Vec<GcpCredential>,
    /// GCP user credentials (refresh token swap)
    #[serde(default)]
    pub gcp_user_credentials: Vec<GcpUserCredential>,
    /// Optional observability configuration
    pub observability: Option<ObservabilityConfig>,
    /// Optional reverse proxy configuration for inbound traffic to sandbox.
    pub reverse_proxy: Option<ReverseProxyConfig>,
}

/// Reverse proxy configuration for forwarding host requests into the sandbox.
///
/// When configured, alice spawns a second listener that accepts plain HTTP
/// from the host and forwards to a backend service in the job's network
/// namespace (via the veth pair).
#[derive(Debug, Deserialize)]
pub struct ReverseProxyConfig {
    /// Address to listen on (e.g., "127.0.0.1:0" for ephemeral port)
    pub listen: String,
    /// Backend address to forward to (e.g., "10.0.0.2:3337")
    pub backend: String,
    /// Splice idle timeout in seconds (default: 300). The bidirectional
    /// copy is torn down after this long with no data in either
    /// direction — a backstop against silent wedges where both peers
    /// stay alive but neither sends.
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_secs: u64,
}

/// Observability configuration for metrics and distributed tracing
#[derive(Debug, Deserialize)]
pub struct ObservabilityConfig {
    /// Plain HTTP endpoint for metrics (e.g., "127.0.0.1:9090")
    /// Serves /metrics in Prometheus text exposition format.
    pub metrics_listen: Option<String>,
    /// OTLP endpoint for distributed tracing (e.g., "http://tempo.example.com:4317")
    /// If not set, falls back to OTEL_EXPORTER_OTLP_ENDPOINT env var
    pub otlp_endpoint: Option<String>,
    /// Optional workload-side OTLP/HTTP collector (telemetry egress)
    pub collector: Option<CollectorConfig>,
}

/// Signal type for collector allowlist rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Signal {
    Traces,
    Metrics,
}

/// A single allowlist rule for the telemetry collector.
#[derive(Debug, Clone, Deserialize)]
pub struct CollectorRule {
    pub action: Action,
    /// Glob pattern matched against span or metric name.
    pub name: String,
    /// Optional signal filter; if omitted the rule applies to both traces and metrics.
    pub signal: Option<Signal>,
}

/// Workload-side OTLP/HTTP collector that receives telemetry, applies a
/// name-glob allowlist, and forwards surviving signals to the host collector.
#[derive(Debug, Deserialize)]
pub struct CollectorConfig {
    /// Address to listen on for OTLP/HTTP (e.g., "127.0.0.1:4318").
    /// Defaults to ephemeral port assignment.
    #[serde(default = "default_collector_listen")]
    pub otlp_http_listen: String,
    /// UDP address to listen on for StatsD (e.g., "127.0.0.1:8125").
    /// If absent, the StatsD listener is not started.
    pub statsd_listen: Option<String>,
    /// gRPC endpoint to forward surviving signals to.
    /// If absent, falls back to `observability.otlp_endpoint`.
    pub forward_endpoint: Option<String>,
    /// Allowlist rules (first-match-wins, default-deny).
    #[serde(default)]
    pub rules: Vec<CollectorRule>,
}

fn default_collector_listen() -> String {
    "127.0.0.1:0".to_string()
}

#[derive(Debug, Deserialize)]
pub struct ProxyConfig {
    pub listen: String,
    pub username: Option<String>,
    /// Environment variable containing the proxy password
    pub password_env: Option<String>,
    /// Additional CA certificates to trust for upstream connections (PEM file)
    pub upstream_ca: Option<PathBuf>,
    /// Maximum concurrent connections (default: 1000)
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    /// Connection idle timeout in seconds (default: 300)
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_secs: u64,
    /// Maximum total bytes for an HTTP/1.1 header block (default: 65536).
    /// Bounds slow-loris-style header growth.
    #[serde(default = "default_max_header_bytes")]
    pub max_header_bytes: usize,
    /// Maximum number of header lines in an HTTP/1.1 header block (default: 200).
    #[serde(default = "default_max_header_count")]
    pub max_header_count: usize,
    /// Maximum bytes for a fully-buffered request/response body (default: 104857600 = 100 MiB).
    /// A claimed Content-Length above this is rejected rather than eagerly allocated.
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: u64,
    /// Maximum bytes produced by gzip decompression (default: 104857600 = 100 MiB).
    /// Guards against decompression bombs during token redaction.
    #[serde(default = "default_max_decompressed_bytes")]
    pub max_decompressed_bytes: u64,
    /// Directory for request/response logs (development only)
    /// When set, all requests are logged with full headers and bodies
    pub log_dir: Option<PathBuf>,
}

impl ProxyConfig {
    /// Resolve the configured request-size limits into a compact, copyable struct
    /// for the hot path.
    pub fn limits(&self) -> Limits {
        Limits {
            max_header_bytes: self.max_header_bytes,
            max_header_count: self.max_header_count,
            max_body_bytes: self.max_body_bytes,
            max_decompressed_bytes: self.max_decompressed_bytes,
        }
    }
}

/// Resolved request-size limits (defense-in-depth against memory-exhaustion DoS).
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_header_bytes: usize,
    pub max_header_count: usize,
    pub max_body_bytes: u64,
    pub max_decompressed_bytes: u64,
}

fn default_max_connections() -> usize {
    1000
}

fn default_idle_timeout() -> u64 {
    300
}

fn default_max_header_bytes() -> usize {
    64 * 1024
}

fn default_max_header_count() -> usize {
    200
}

fn default_max_body_bytes() -> u64 {
    100 * 1024 * 1024
}

fn default_max_decompressed_bytes() -> u64 {
    100 * 1024 * 1024
}

#[derive(Debug, Deserialize)]
pub struct CaConfig {
    /// Path where CA certificate will be written (for clients to trust)
    pub cert_path: PathBuf,
    /// CA certificate validity in hours (default: 6)
    #[serde(default = "default_ca_validity")]
    pub validity_hours: u32,
    /// Per-host certificate validity in hours (default: 2)
    #[serde(default = "default_host_cert_validity")]
    pub host_cert_validity_hours: u32,
    /// Hosts to pre-generate certificates for at startup.
    /// Exact hosts from rules and credentials are warmed automatically;
    /// use this for hosts behind glob or CIDR rules.
    #[serde(default)]
    pub warm_hosts: Vec<String>,
}

fn default_ca_validity() -> u32 {
    6
}

fn default_host_cert_validity() -> u32 {
    2
}

#[derive(Debug, Deserialize)]
pub struct DnsConfig {
    /// DNS cache TTL in seconds (default: 300)
    #[serde(default = "default_dns_ttl")]
    pub cache_ttl_secs: u64,
    /// Maximum DNS cache entries (default: 1000)
    #[serde(default = "default_dns_max_entries")]
    pub cache_max_entries: u64,
    /// Static hostname overrides (like /etc/hosts)
    /// Maps hostnames to IP addresses, bypassing DNS resolution
    #[serde(default)]
    pub hosts: std::collections::HashMap<String, Vec<String>>,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            cache_ttl_secs: default_dns_ttl(),
            cache_max_entries: default_dns_max_entries(),
            hosts: std::collections::HashMap::new(),
        }
    }
}

fn default_dns_ttl() -> u64 {
    300
}

fn default_dns_max_entries() -> u64 {
    1000
}

#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    pub action: Action,
    /// Host glob pattern (e.g., "*.github.com", "api.example.com")
    /// Mutually exclusive with `cidr`.
    pub host: Option<String>,
    /// Optional path glob pattern (e.g., "/v1/*"). Only valid with `host`.
    pub path: Option<String>,
    /// CIDR block to match against resolved IP addresses (e.g., "169.254.169.254/32", "10.0.0.0/8")
    /// Mutually exclusive with `host`. Used to block dangerous IP ranges regardless of hostname.
    pub cidr: Option<String>,
    /// Path patterns where OAuth tokens in responses should be redacted.
    /// Only valid with `host` and `action = "allow"`.
    /// Tokens are replaced with dummy values and cached for transparent replacement on outbound requests.
    #[serde(default)]
    pub redact_paths: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Deny,
}

/// Authentication scheme for credential injection.
#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum CredentialScheme {
    /// Custom header matching (default, backward-compatible behavior).
    /// Requires `header`, `match`, and optionally `format`.
    #[default]
    Custom,
    /// HTTP Basic authentication.
    /// Alice decodes the base64 `Authorization: Basic <b64>` header,
    /// matches `username:match`, and re-encodes with the real secret.
    Basic,
}

/// Credential from main config (env or file source).
/// NOTE: `value` field is NOT allowed here - only in SOPS-encrypted files.
#[derive(Debug, Clone, Deserialize)]
pub struct Credential {
    pub name: String,
    /// Host glob pattern (e.g., "api.github.com", "*.example.com")
    pub host: String,
    /// Authentication scheme (default: "custom" for backward compatibility)
    #[serde(default)]
    pub scheme: CredentialScheme,
    /// HTTP header name to inject (e.g., "Authorization")
    /// Required for `scheme = "custom"`. Must not be set for `scheme = "basic"`.
    pub header: Option<String>,
    /// Dummy token value to match (replacement only happens if header equals this)
    /// For `scheme = "custom"`: full header value (e.g., "Bearer DUMMY_TOKEN")
    /// For `scheme = "basic"`: the dummy password portion only
    #[serde(rename = "match")]
    pub match_value: String,
    /// Format string for the real value (e.g., "Bearer {value}")
    /// Only used with `scheme = "custom"` (defaults to "{value}" if omitted).
    /// Must not be set for `scheme = "basic"`.
    pub format: Option<String>,
    /// Username for HTTP Basic auth. Required when `scheme = "basic"`.
    pub username: Option<String>,
    /// Environment variable containing the real secret
    pub env: Option<String>,
    /// File path containing the real secret
    pub file: Option<PathBuf>,
    /// Path to a sanctum broker's Unix domain socket.
    /// alice connects to this gRPC socket on `refresh_interval_secs`
    /// and uses the returned `access_token` as the secret value (formatted
    /// via `format`, just like `env`/`file`).
    pub sanctum_path: Option<PathBuf>,
    /// Credential slot name within the broker's vault (e.g. "claude0").
    /// Required when `sanctum_path` is set.
    pub sanctum_name: Option<String>,
    /// Refresh interval in seconds for `sanctum_path` (default: 60).
    /// Only valid when `sanctum_path` is set.
    pub refresh_interval_secs: Option<u64>,
}

/// GCP service account credential configuration.
///
/// Alice holds the real SA key, generates a dummy key for Bob,
/// and re-signs JWT assertions before they reach Google's token endpoint.
#[derive(Debug, Clone, Deserialize)]
pub struct GcpCredential {
    pub name: String,
    /// Path to the real GCP service account JSON key file
    pub key_file: PathBuf,
    /// Path where Alice writes the dummy SA key file for Bob
    pub dummy_key_path: PathBuf,
    /// OAuth scope (default: "https://www.googleapis.com/auth/cloud-platform")
    /// Enforced at re-sign time: Alice overwrites the `scope` claim of Bob's
    /// JWT assertion with this value, so Bob cannot mint a token broader than
    /// what is configured here.
    #[serde(default = "default_gcp_scope")]
    pub scope: String,
}

/// GCP user credential configuration (refresh token flow).
///
/// Alice reads gcloud's credentials.db and application_default_credentials.json,
/// generates dummy versions for Bob, and swaps refresh tokens at the token endpoint.
#[derive(Debug, Clone, Deserialize)]
pub struct GcpUserCredential {
    pub name: String,
    /// Path to the real gcloud config directory (e.g., ~/.config/gcloud)
    pub gcloud_config_dir: PathBuf,
    /// Path where Alice writes the dummy gcloud config for Bob
    pub dummy_config_dir: PathBuf,
}

fn default_gcp_scope() -> String {
    "https://www.googleapis.com/auth/cloud-platform".to_string()
}

impl Config {
    /// Validate invariants that serde cannot express on its own.
    ///
    /// Fails fast at load time so misconfigurations surface at startup
    /// rather than as runtime surprises.
    fn validate(&self) -> Result<()> {
        // Both validities feed `not_after = now + hours * 3600`, and the
        // host-cert cache TTL is `host_cert_validity_hours * 3600 - 300`.
        // A zero validity yields an instantly-expired cert and underflows
        // the TTL subtraction (u64 wraparound to a near-infinite TTL).
        if self.ca.validity_hours == 0 {
            bail!("ca.validity_hours must be greater than 0");
        }
        if self.ca.host_cert_validity_hours == 0 {
            bail!("ca.host_cert_validity_hours must be greater than 0");
        }

        Ok(())
    }
}

pub fn load(path: &Path) -> Result<Config> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read config file: {}", path.display()))?;

    let config: Config = toml::from_str(&content).with_context(|| "failed to parse config file")?;
    config.validate()?;

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_config() {
        let toml = r#"
[proxy]
listen = "127.0.0.1:3128"
username = "bob"
password_env = "ALICE_PASSWORD"

[ca]
cert_path = "/tmp/alice-ca.pem"

[[rules]]
action = "allow"
host = "*.httpbin.org"
path = "/get"

[[rules]]
action = "allow"
host = "api.github.com"

[[rules]]
action = "deny"
host = "*"
"#;

        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.proxy.listen, "127.0.0.1:3128");
        assert_eq!(config.rules.len(), 3);
        assert_eq!(config.rules[0].host, Some("*.httpbin.org".to_string()));
        assert_eq!(config.rules[0].path, Some("/get".to_string()));
        assert_eq!(config.rules[0].cidr, None);
        // warm_hosts defaults to empty when omitted
        assert!(config.ca.warm_hosts.is_empty());
    }

    #[test]
    fn test_limits_defaults() {
        let toml = r#"
[proxy]
listen = "127.0.0.1:3128"

[ca]
cert_path = "/tmp/alice-ca.pem"
"#;

        let config: Config = toml::from_str(toml).unwrap();
        let limits = config.proxy.limits();
        assert_eq!(limits.max_header_bytes, 64 * 1024);
        assert_eq!(limits.max_header_count, 200);
        assert_eq!(limits.max_body_bytes, 100 * 1024 * 1024);
        assert_eq!(limits.max_decompressed_bytes, 100 * 1024 * 1024);
    }

    #[test]
    fn test_limits_override() {
        let toml = r#"
[proxy]
listen = "127.0.0.1:3128"
max_header_bytes = 8192
max_header_count = 50
max_body_bytes = 1048576
max_decompressed_bytes = 2097152

[ca]
cert_path = "/tmp/alice-ca.pem"
"#;

        let config: Config = toml::from_str(toml).unwrap();
        let limits = config.proxy.limits();
        assert_eq!(limits.max_header_bytes, 8192);
        assert_eq!(limits.max_header_count, 50);
        assert_eq!(limits.max_body_bytes, 1048576);
        assert_eq!(limits.max_decompressed_bytes, 2097152);
    }

    #[test]
    fn test_parse_reverse_proxy() {
        let toml = r#"
[proxy]
listen = "127.0.0.1:3128"

[ca]
cert_path = "/tmp/alice-ca.pem"

[reverse_proxy]
listen = "127.0.0.1:0"
backend = "10.0.0.2:3337"
"#;

        let config: Config = toml::from_str(toml).unwrap();
        let rp = config.reverse_proxy.unwrap();
        assert_eq!(rp.listen, "127.0.0.1:0");
        assert_eq!(rp.backend, "10.0.0.2:3337");
        assert_eq!(rp.idle_timeout_secs, 300);
    }

    #[test]
    fn test_parse_no_reverse_proxy() {
        let toml = r#"
[proxy]
listen = "127.0.0.1:3128"

[ca]
cert_path = "/tmp/alice-ca.pem"
"#;

        let config: Config = toml::from_str(toml).unwrap();
        assert!(config.reverse_proxy.is_none());
    }

    #[test]
    fn test_parse_collector_config() {
        let toml = r#"
[proxy]
listen = "127.0.0.1:3128"

[ca]
cert_path = "/tmp/alice-ca.pem"

[observability]
otlp_endpoint = "http://otel.example.com:4317"

[observability.collector]
otlp_http_listen = "127.0.0.1:4318"
forward_endpoint = "http://otel.example.com:4317"

[[observability.collector.rules]]
action = "allow"
name = "myapp.*"
signal = "traces"

[[observability.collector.rules]]
action = "allow"
name = "myapp_*"
"#;

        let config: Config = toml::from_str(toml).unwrap();
        let obs = config.observability.unwrap();
        let col = obs.collector.unwrap();
        assert_eq!(col.otlp_http_listen, "127.0.0.1:4318");
        assert_eq!(col.rules.len(), 2);
        assert_eq!(col.rules[0].name, "myapp.*");
        assert_eq!(col.rules[0].signal, Some(Signal::Traces));
        assert_eq!(col.rules[1].signal, None);
        assert!(col.statsd_listen.is_none());
    }

    #[test]
    fn test_parse_collector_statsd_listen() {
        let toml = r#"
[proxy]
listen = "127.0.0.1:3128"

[ca]
cert_path = "/tmp/alice-ca.pem"

[observability.collector]
statsd_listen = "127.0.0.1:8125"
forward_endpoint = "http://otel.example.com:4317"
"#;

        let config: Config = toml::from_str(toml).unwrap();
        let col = config.observability.unwrap().collector.unwrap();
        assert_eq!(col.statsd_listen, Some("127.0.0.1:8125".to_string()));
        assert!(col.rules.is_empty());
    }

    #[test]
    fn test_validate_rejects_zero_host_cert_validity() {
        let toml = r#"
[proxy]
listen = "127.0.0.1:3128"

[ca]
cert_path = "/tmp/alice-ca.pem"
host_cert_validity_hours = 0
"#;

        let config: Config = toml::from_str(toml).unwrap();
        let err = config.validate().unwrap_err().to_string();
        assert!(
            err.contains("host_cert_validity_hours"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_validate_rejects_zero_ca_validity() {
        let toml = r#"
[proxy]
listen = "127.0.0.1:3128"

[ca]
cert_path = "/tmp/alice-ca.pem"
validity_hours = 0
"#;

        let config: Config = toml::from_str(toml).unwrap();
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("validity_hours"), "unexpected error: {err}");
    }

    #[test]
    fn test_validate_accepts_default_validity() {
        let toml = r#"
[proxy]
listen = "127.0.0.1:3128"

[ca]
cert_path = "/tmp/alice-ca.pem"
"#;

        let config: Config = toml::from_str(toml).unwrap();
        assert!(config.validate().is_ok());
        // defaults are non-zero
        assert_eq!(config.ca.validity_hours, 6);
        assert_eq!(config.ca.host_cert_validity_hours, 2);
    }

    #[test]
    fn test_parse_warm_hosts() {
        let toml = r#"
[proxy]
listen = "127.0.0.1:3128"

[ca]
cert_path = "/tmp/alice-ca.pem"
warm_hosts = ["api.github.com", "index.crates.io"]

[[rules]]
action = "allow"
host = "*.github.com"
"#;

        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(
            config.ca.warm_hosts,
            vec!["api.github.com", "index.crates.io"]
        );
    }
}
