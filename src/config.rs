use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

use crate::proxy::transform::TransformConfig;

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
    /// Ordered list of request transforms for LLM API endpoints.
    #[serde(default)]
    pub transforms: Vec<TransformConfig>,
}

/// Observability configuration for metrics and distributed tracing
#[derive(Debug, Deserialize)]
pub struct ObservabilityConfig {
    /// Plain HTTP endpoint for metrics (e.g., "127.0.0.1:9090")
    /// Serves /llm/completions (JSON)
    pub metrics_listen: Option<String>,
    /// OTLP endpoint for distributed tracing (e.g., "http://tempo.example.com:4317")
    /// If not set, falls back to OTEL_EXPORTER_OTLP_ENDPOINT env var
    pub otlp_endpoint: Option<String>,
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
    /// Directory for request/response logs (development only)
    /// When set, all requests are logged with full headers and bodies
    pub log_dir: Option<PathBuf>,
}

fn default_max_connections() -> usize {
    1000
}

fn default_idle_timeout() -> u64 {
    300
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
#[derive(Debug, Clone, Deserialize, Default, PartialEq)]
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
    /// Reserved for future use when Alice constructs JWTs from scratch.
    #[serde(default = "default_gcp_scope")]
    #[allow(dead_code)]
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

pub fn load(path: &Path) -> Result<Config> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read config file: {}", path.display()))?;

    let config: Config = toml::from_str(&content).with_context(|| "failed to parse config file")?;

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
    }
}
