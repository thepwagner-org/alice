//! Credential store for injecting secrets into outbound requests.
//!
//! Credentials are loaded from:
//! - Environment variables (`env = "VAR_NAME"`)
//! - Files (`file = "/path/to/secret"`)
//! - Intercepted OAuth responses (dynamic, at runtime)
//!
//! For SOPS-encrypted secrets, use `sops exec-env` to decrypt and pass as env vars:
//!   sops exec-env secrets.yaml -- alice -c config.toml

// Lock unwraps panic only on poisoning (another thread panicked while holding it),
// at which point propagating the panic is the correct response.
#![allow(clippy::unwrap_used)]

use crate::config::{Credential, CredentialScheme};
use crate::sanctum_proto::sanctum_client::SanctumClient;
use crate::sanctum_proto::GetAccessTokenRequest;
use anyhow::{bail, Context, Result};
use base64::prelude::*;
use globset::{Glob, GlobMatcher};
use http::{HeaderName, HeaderValue};
use hyper_util::rt::TokioIo;
use secrecy::{ExposeSecret, SecretString};
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;
use tracing::{debug, info, warn};

/// Result of a successful credential replacement.
pub struct Replacement {
    /// The real header value to inject.
    pub value: HeaderValue,
    /// Name of the credential that matched (for metrics/logging).
    pub credential_name: String,
}

/// Host matching strategy for credentials.
enum HostMatch {
    /// Glob pattern (for static config credentials)
    Glob(GlobMatcher),
    /// Exact match (for dynamic intercepted credentials)
    Exact(String),
}

impl HostMatch {
    fn matches(&self, host: &str) -> bool {
        match self {
            HostMatch::Glob(matcher) => matcher.is_match(host),
            HostMatch::Exact(expected) => expected == host,
        }
    }
}

/// A resolved credential ready for injection.
struct ResolvedCredential {
    name: String,
    host_match: HostMatch,
    header: HeaderName,
    /// Dummy token to match against (only replace if header equals this)
    match_value: HeaderValue,
    /// Pre-formatted real value to inject. Wrapped in Arc<RwLock<>> so a
    /// sanctum refresh task can update it in place without disturbing
    /// the outer credentials list.
    real_value: Arc<RwLock<SecretString>>,
}

impl std::fmt::Debug for ResolvedCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedCredential")
            .field("name", &self.name)
            .field("header", &self.header)
            .field("match_value", &self.match_value)
            .field("real_value", &"[REDACTED]")
            .finish()
    }
}

/// Dynamic credentials captured from intercepted OAuth responses.
///
/// Bounded by keying on `(host_identity, token_type)`: a refreshed token for
/// the same host and token type overwrites the prior entry rather than
/// appending, so a long-lived proxy doesn't accumulate stale credentials.
#[derive(Default)]
struct DynamicStore {
    /// Keyed by the dummy match value so `replace` is an O(1) lookup on the
    /// hot request path rather than a linear scan over every token ever seen.
    by_dummy: HashMap<HeaderValue, ResolvedCredential>,
    /// Maps `(host_identity, token_type)` to the dummy currently representing
    /// it, so a refresh can evict the prior dummy from `by_dummy`. This is
    /// what keeps the store bounded to the number of distinct host/token
    /// pairs in flight.
    current: HashMap<(String, String), HeaderValue>,
}

/// Store for all loaded credentials.
///
/// Thread-safe to support dynamic credential insertion from intercepted responses.
pub struct CredentialStore {
    /// Static credentials from config. Fixed at load time and small, so the
    /// linear scan in `replace` / `has_credentials_for_host` is bounded by the
    /// config size.
    static_creds: Vec<ResolvedCredential>,
    /// Dynamic credentials captured at runtime; bounded and indexed for O(1)
    /// lookup (see `DynamicStore`).
    dynamic: RwLock<DynamicStore>,
    /// Counter for generating unique dummy token names
    token_counter: AtomicU64,
    /// Sanctum refresh tasks queued at load time, drained by
    /// `start_sanctum_refresh`. Each task owns the Arc<RwLock>
    /// of a credential's `real_value` and updates it on a timer.
    pending_sanctum_tasks: Mutex<Vec<SanctumTask>>,
}

impl CredentialStore {
    /// Load credentials from config.
    pub fn load(credentials: &[Credential]) -> Result<Self> {
        let mut resolved = Vec::new();
        let mut sanctum_tasks = Vec::new();

        for cred in credentials {
            let (rc, maybe_task) = resolve_credential(cred)?;
            resolved.push(rc);
            if let Some(task) = maybe_task {
                sanctum_tasks.push(task);
            }
        }

        debug!(
            count = resolved.len(),
            sanctum = sanctum_tasks.len(),
            "loaded credentials"
        );

        Ok(Self {
            static_creds: resolved,
            dynamic: RwLock::new(DynamicStore::default()),
            token_counter: AtomicU64::new(1),
            pending_sanctum_tasks: Mutex::new(sanctum_tasks),
        })
    }

    /// Perform an initial fetch for any sanctum credentials and spawn
    /// background refresh tasks. Must be called once after `load`, before
    /// serving traffic, so the stored `real_value` is populated. Subsequent
    /// calls are no-ops.
    pub async fn start_sanctum_refresh(&self) -> Result<()> {
        let tasks = {
            let mut pending = self.pending_sanctum_tasks.lock().unwrap();
            std::mem::take(&mut *pending)
        };

        if tasks.is_empty() {
            return Ok(());
        }

        for task in tasks {
            task.start().await?;
        }
        Ok(())
    }

    /// Check if a header should be replaced.
    ///
    /// Returns `Some(Replacement)` if:
    /// 1. The host matches a credential's host pattern
    /// 2. The header name matches the credential's header
    /// 3. The current header value exactly equals the credential's match_value
    pub fn replace(
        &self,
        host: &str,
        header: &HeaderName,
        current_value: &HeaderValue,
    ) -> Option<Replacement> {
        // Static credentials match by glob host pattern, so they require a
        // scan — but the set is fixed at load and small.
        for cred in &self.static_creds {
            if let Some(replacement) = try_replace(cred, host, header, current_value) {
                return Some(replacement);
            }
        }
        // Dynamic credentials are keyed by the dummy value, so this is an O(1)
        // lookup rather than a scan over every token ever captured.
        let dynamic = self.dynamic.read().unwrap();
        if let Some(cred) = dynamic.by_dummy.get(current_value) {
            if let Some(replacement) = try_replace(cred, host, header, current_value) {
                return Some(replacement);
            }
        }
        None
    }

    /// Check if any credentials are configured for a given host.
    pub fn has_credentials_for_host(&self, host: &str) -> bool {
        if self
            .static_creds
            .iter()
            .any(|cred| cred.host_match.matches(host))
        {
            return true;
        }
        // Dynamic set is bounded to distinct host/token pairs, so this scan is
        // not linear in the number of historical credentials.
        let dynamic = self.dynamic.read().unwrap();
        dynamic
            .by_dummy
            .values()
            .any(|cred| cred.host_match.matches(host))
    }

    /// Returns true if no credentials are loaded.
    #[allow(dead_code)] // May be useful for future features
    pub fn is_empty(&self) -> bool {
        self.static_creds.is_empty() && self.dynamic.read().unwrap().by_dummy.is_empty()
    }

    /// Insert a dynamic credential from an intercepted OAuth response.
    ///
    /// Generates a dummy token and stores the mapping so that subsequent
    /// requests with the dummy token are replaced with the real one.
    ///
    /// `host_pattern` controls which hosts the credential matches:
    /// - `None` -> exact match on the originating host
    /// - `Some("*.googleapis.com")` -> glob match (for GCP tokens used across services)
    ///
    /// Returns the dummy token value (without Bearer/token prefix).
    fn insert_dynamic(
        &self,
        host: &str,
        token_type: &str,
        real_token: &str,
        host_pattern: Option<&str>,
    ) -> String {
        let id = self.token_counter.fetch_add(1, Ordering::Relaxed);
        let dummy = format!("ALICE_{}_{}", token_type.to_uppercase(), id);
        let dummy_with_bearer = format!("Bearer {}", dummy);
        let real_with_bearer = format!("Bearer {}", real_token);

        let host_match = if let Some(pattern) = host_pattern {
            match Glob::new(pattern) {
                Ok(glob) => HostMatch::Glob(glob.compile_matcher()),
                Err(e) => {
                    warn!(error = %e, pattern = %pattern, "invalid host glob for dynamic credential, falling back to exact match");
                    HostMatch::Exact(host.to_string())
                }
            }
        } else {
            HostMatch::Exact(host.to_string())
        };

        // The host identity (glob pattern if present, else the exact host)
        // plus the token type form the eviction key: a refresh for the same
        // pair overwrites the prior dummy instead of appending.
        let host_identity = host_pattern.unwrap_or(host).to_string();
        let match_value = HeaderValue::from_str(&dummy_with_bearer).unwrap();

        let cred = ResolvedCredential {
            name: format!("dynamic-{}-{}", token_type, id),
            host_match,
            header: HeaderName::from_static("authorization"),
            match_value: match_value.clone(),
            real_value: Arc::new(RwLock::new(SecretString::new(real_with_bearer.into()))),
        };

        debug!(
            host = %host_identity,
            token_type = %token_type,
            dummy = %dummy,
            "captured token from response"
        );

        let key = (host_identity, token_type.to_string());
        let mut dynamic = self.dynamic.write().unwrap();
        // Evict the prior dummy for this host/token pair so the store stays
        // bounded; the stale dummy would never be presented again anyway.
        let previous = dynamic.current.insert(key, match_value.clone());
        if let Some(old_dummy) = previous {
            let _ = dynamic.by_dummy.remove(&old_dummy);
        }
        let _ = dynamic.by_dummy.insert(match_value, cred);

        dummy
    }

    /// Parse an OAuth JSON response and redact token fields.
    ///
    /// Looks for these standard OAuth2 fields:
    /// - `access_token`
    /// - `refresh_token`
    /// - `id_token`
    ///
    /// For each token found:
    /// 1. Generates a dummy token
    /// 2. Stores the real<->dummy mapping
    /// 3. Replaces the value in the response
    ///
    /// Returns `Some(modified_body)` if any tokens were redacted,
    /// or `None` if the body couldn't be parsed or had no tokens.
    pub fn redact_oauth_response(&self, host: &str, body: &[u8]) -> Option<Vec<u8>> {
        // Try to parse as JSON
        let mut json: Value = match serde_json::from_slice(body) {
            Ok(v) => v,
            Err(e) => {
                debug!(error = %e, "response body is not valid JSON, skipping token redaction");
                return None;
            }
        };

        let obj = json.as_object_mut()?;

        let mut redacted_any = false;

        // For GCP token endpoint, dynamic credentials must match *.googleapis.com
        // since the token is obtained from oauth2.googleapis.com but used on
        // storage.googleapis.com, compute.googleapis.com, etc.
        let host_pattern = if host == crate::proxy::gcp::GCP_TOKEN_HOST {
            Some("*.googleapis.com")
        } else {
            None
        };

        // Redact access_token
        if let Some(Value::String(token)) = obj.get("access_token") {
            let dummy = self.insert_dynamic(host, "access", token, host_pattern);
            let _ = obj.insert("access_token".to_string(), Value::String(dummy));
            redacted_any = true;
        }

        // Redact refresh_token
        if let Some(Value::String(token)) = obj.get("refresh_token") {
            let dummy = self.insert_dynamic(host, "refresh", token, host_pattern);
            let _ = obj.insert("refresh_token".to_string(), Value::String(dummy));
            redacted_any = true;
        }

        // Redact id_token (OpenID Connect)
        if let Some(Value::String(token)) = obj.get("id_token") {
            let dummy = self.insert_dynamic(host, "id", token, host_pattern);
            let _ = obj.insert("id_token".to_string(), Value::String(dummy));
            redacted_any = true;
        }

        if redacted_any {
            // Serialize back to JSON
            match serde_json::to_vec(&json) {
                Ok(new_body) => Some(new_body),
                Err(e) => {
                    warn!(error = %e, "failed to serialize redacted JSON");
                    None
                }
            }
        } else {
            debug!("no token fields found in response");
            None
        }
    }
}

/// Build a `Replacement` if `cred` matches the request's host, header, and
/// current (dummy) value. Shared by the static-scan and dynamic-lookup paths.
fn try_replace(
    cred: &ResolvedCredential,
    host: &str,
    header: &HeaderName,
    current_value: &HeaderValue,
) -> Option<Replacement> {
    if cred.host_match.matches(host) && cred.header == *header && cred.match_value == *current_value
    {
        let secret = cred.real_value.read().unwrap();
        if let Ok(value) = HeaderValue::from_str(secret.expose_secret()) {
            return Some(Replacement {
                value,
                credential_name: cred.name.clone(),
            });
        }
    }
    None
}

/// Resolve a credential from the main config file (env, file, or sanctum
/// source). For sanctum credentials, returns a placeholder
/// `ResolvedCredential` plus a `SanctumTask` that the caller must start.
fn resolve_credential(cred: &Credential) -> Result<(ResolvedCredential, Option<SanctumTask>)> {
    // Validate: exactly one of env, file, or sanctum_path must be specified
    let source_count = [
        cred.env.is_some(),
        cred.file.is_some(),
        cred.sanctum_path.is_some(),
    ]
    .iter()
    .filter(|b| **b)
    .count();
    if source_count == 0 {
        bail!(
            "credential '{}': must specify one of 'env', 'file', or 'sanctum_path'",
            cred.name
        );
    }
    if source_count > 1 {
        bail!(
            "credential '{}': must specify only one of 'env', 'file', or 'sanctum_path'",
            cred.name
        );
    }
    if cred.refresh_interval_secs.is_some() && cred.sanctum_path.is_none() {
        bail!(
            "credential '{}': 'refresh_interval_secs' is only valid with 'sanctum_path'",
            cred.name
        );
    }
    if cred.sanctum_name.is_some() && cred.sanctum_path.is_none() {
        bail!(
            "credential '{}': 'sanctum_name' is only valid with 'sanctum_path'",
            cred.name
        );
    }

    // Compile the host matcher (shared by all schemes)
    let host_glob = Glob::new(&cred.host).with_context(|| {
        format!(
            "credential '{}': invalid host pattern '{}'",
            cred.name, cred.host
        )
    })?;

    // For env/file we resolve the secret now; for sanctum we use an
    // empty placeholder and let the refresh task fill it on first fetch.
    let (header, match_value, real_value, sanctum_task) = if let Some(socket) = &cred.sanctum_path {
        // sanctum only supports custom-scheme header injection (Bearer
        // tokens). Basic auth via a refresher doesn't have a real use case.
        if cred.scheme != CredentialScheme::Custom {
            bail!(
                "credential '{}': scheme = 'basic' is not supported with 'sanctum_path'",
                cred.name
            );
        }
        let (header, match_value, format_str) = sanctum_header_and_format(cred)?;
        let interval = cred.refresh_interval_secs.unwrap_or(60);
        if interval == 0 {
            bail!(
                "credential '{}': 'refresh_interval_secs' must be positive",
                cred.name
            );
        }
        let slot_name = cred.sanctum_name.clone().ok_or_else(|| {
            anyhow::anyhow!(
                "credential '{}': 'sanctum_name' is required with 'sanctum_path'",
                cred.name
            )
        })?;
        let real_value = Arc::new(RwLock::new(SecretString::new(String::new().into())));
        let task = SanctumTask {
            name: cred.name.clone(),
            socket: socket.clone(),
            slot_name,
            interval: Duration::from_secs(interval),
            format: format_str,
            real_value: Arc::clone(&real_value),
        };
        (header, match_value, real_value, Some(task))
    } else {
        let secret_value = if let Some(env_var) = &cred.env {
            std::env::var(env_var).with_context(|| {
                format!(
                    "credential '{}': environment variable '{}' not set",
                    cred.name, env_var
                )
            })?
        } else if let Some(file_path) = &cred.file {
            std::fs::read_to_string(file_path)
                .with_context(|| {
                    format!(
                        "credential '{}': failed to read file '{}'",
                        cred.name,
                        file_path.display()
                    )
                })?
                .trim()
                .to_string()
        } else {
            unreachable!("source_count guarantees one source is set")
        };

        let (header, match_value, real_value) = match cred.scheme {
            CredentialScheme::Custom => resolve_custom_credential(cred, &secret_value)?,
            CredentialScheme::Basic => resolve_basic_credential(cred, &secret_value)?,
        };
        let real_value = Arc::new(RwLock::new(SecretString::new(real_value.into())));
        (header, match_value, real_value, None)
    };

    let header_display = header.as_str();
    info!(
        name = %cred.name,
        host = %cred.host,
        header = %header_display,
        scheme = ?cred.scheme,
        sanctum = cred.sanctum_path.is_some(),
        "loaded credential"
    );

    Ok((
        ResolvedCredential {
            name: cred.name.clone(),
            host_match: HostMatch::Glob(host_glob.compile_matcher()),
            header,
            match_value,
            real_value,
        },
        sanctum_task,
    ))
}

/// Validate header-related fields for a sanctum credential and return
/// `(header, match_value, format_string)`. The format string is retained so
/// the refresh task can re-render the header when the access_token changes.
fn sanctum_header_and_format(cred: &Credential) -> Result<(HeaderName, HeaderValue, String)> {
    if cred.username.is_some() {
        bail!(
            "credential '{}': 'username' cannot be set with 'sanctum_path'",
            cred.name
        );
    }

    let header_str = cred.header.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "credential '{}': 'header' is required with 'sanctum_path'",
            cred.name
        )
    })?;
    let header = header_str.parse::<HeaderName>().with_context(|| {
        format!(
            "credential '{}': invalid header name '{}'",
            cred.name, header_str
        )
    })?;
    let match_value = HeaderValue::from_str(&cred.match_value).with_context(|| {
        format!(
            "credential '{}': invalid match value '{}'",
            cred.name, cred.match_value
        )
    })?;
    let format_str = cred.format.as_deref().unwrap_or("{value}").to_string();
    Ok((header, match_value, format_str))
}

/// Resolve a custom-scheme credential (backward-compatible path).
fn resolve_custom_credential(
    cred: &Credential,
    secret_value: &str,
) -> Result<(HeaderName, HeaderValue, String)> {
    // Validate: username must not be set for custom scheme
    if cred.username.is_some() {
        bail!(
            "credential '{}': 'username' cannot be set when scheme = 'custom'",
            cred.name
        );
    }

    // header is required for custom scheme
    let header_str = cred.header.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "credential '{}': 'header' is required when scheme = 'custom'",
            cred.name
        )
    })?;

    let header = header_str.parse::<HeaderName>().with_context(|| {
        format!(
            "credential '{}': invalid header name '{}'",
            cred.name, header_str
        )
    })?;

    let match_value = HeaderValue::from_str(&cred.match_value).with_context(|| {
        format!(
            "credential '{}': invalid match value '{}'",
            cred.name, cred.match_value
        )
    })?;

    // Format the value (default to "{value}" if not specified)
    let format_str = cred.format.as_deref().unwrap_or("{value}");
    let formatted = format_str.replace("{value}", secret_value);

    Ok((header, match_value, formatted))
}

/// Resolve a basic-scheme credential (HTTP Basic auth with base64 encoding).
fn resolve_basic_credential(
    cred: &Credential,
    secret_value: &str,
) -> Result<(HeaderName, HeaderValue, String)> {
    // Validate: header must not be set for basic scheme (it's always Authorization)
    if cred.header.is_some() {
        bail!(
            "credential '{}': 'header' cannot be set when scheme = 'basic' (it is always 'Authorization')",
            cred.name
        );
    }

    // Validate: format must not be set for basic scheme
    if cred.format.is_some() {
        bail!(
            "credential '{}': 'format' cannot be set when scheme = 'basic'",
            cred.name
        );
    }

    // Validate: username is required for basic scheme
    let username = cred.username.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "credential '{}': 'username' is required when scheme = 'basic'",
            cred.name
        )
    })?;

    // Build the match value: Basic base64("username:match_value")
    let dummy_pair = format!("{}:{}", username, cred.match_value);
    let dummy_b64 = BASE64_STANDARD.encode(dummy_pair.as_bytes());
    let match_str = format!("Basic {}", dummy_b64);

    let match_value = HeaderValue::from_str(&match_str).with_context(|| {
        format!(
            "credential '{}': failed to construct Basic auth match value",
            cred.name
        )
    })?;

    // Build the real value: Basic base64("username:secret")
    let real_pair = format!("{}:{}", username, secret_value);
    let real_b64 = BASE64_STANDARD.encode(real_pair.as_bytes());
    let real_value = format!("Basic {}", real_b64);

    let header = HeaderName::from_static("authorization");

    Ok((header, match_value, real_value))
}

/// Background refresher for a sanctum credential. Owns a shared handle
/// to the credential's `real_value`; periodically calls
/// `Sanctum.GetAccessToken` over gRPC (UDS), formats the returned token via
/// `format`, and writes the result into the shared slot. Refresh failures
/// log and keep the prior value.
struct SanctumTask {
    name: String,
    /// Path to the sanctum Unix domain socket (e.g. `/run/sanctum/sanctum.sock`).
    socket: PathBuf,
    /// Vault slot name on the broker (passed in `GetAccessTokenRequest.name`).
    slot_name: String,
    interval: Duration,
    format: String,
    real_value: Arc<RwLock<SecretString>>,
}

impl std::fmt::Debug for SanctumTask {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SanctumTask")
            .field("name", &self.name)
            .field("socket", &self.socket)
            .field("slot_name", &self.slot_name)
            .field("interval", &self.interval)
            .finish()
    }
}

impl SanctumTask {
    /// Connect over UDS, perform the initial fetch (failing loudly so the
    /// proxy doesn't start against a missing or empty broker), then spawn a
    /// background tick that re-fetches every `interval`.
    async fn start(self) -> Result<()> {
        let mut client = sanctum_connect(&self.socket).await.with_context(|| {
            format!(
                "sanctum credential '{}': connect {}",
                self.name,
                self.socket.display()
            )
        })?;
        let token = fetch_token(&mut client, &self.slot_name)
            .await
            .with_context(|| {
                format!(
                    "sanctum credential '{}': initial GetAccessToken(name={}) on {}",
                    self.name,
                    self.slot_name,
                    self.socket.display()
                )
            })?;
        let formatted = self.format.replace("{value}", &token);
        {
            let mut slot = self.real_value.write().unwrap();
            *slot = SecretString::new(formatted.into());
        }
        info!(
            name = %self.name,
            slot = %self.slot_name,
            socket = %self.socket.display(),
            interval_secs = self.interval.as_secs(),
            "sanctum credential primed; refresh loop spawned",
        );

        let _refresh = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(self.interval);
            // First tick fires immediately; the initial fetch above already
            // populated the slot, so consume it.
            let _first = ticker.tick().await;
            loop {
                let _next = ticker.tick().await;
                match fetch_token(&mut client, &self.slot_name).await {
                    Ok(token) => {
                        let formatted = self.format.replace("{value}", &token);
                        let mut slot = self.real_value.write().unwrap();
                        *slot = SecretString::new(formatted.into());
                        debug!(name = %self.name, slot = %self.slot_name, "sanctum token refreshed");
                    }
                    Err(e) => {
                        warn!(
                            name = %self.name,
                            slot = %self.slot_name,
                            socket = %self.socket.display(),
                            error = %e,
                            "sanctum refresh failed; keeping prior token",
                        );
                    }
                }
            }
        });
        Ok(())
    }
}

/// Open a tonic gRPC channel to a sanctum Unix domain socket. The URI is a
/// dummy — the connector swallows it and dials the path instead.
async fn sanctum_connect(socket: &std::path::Path) -> Result<SanctumClient<Channel>> {
    let socket = socket.to_path_buf();
    let endpoint: Endpoint =
        Endpoint::try_from("http://[::]:50051").context("static sanctum URI is valid")?;
    let channel = endpoint
        .connect_with_connector(service_fn(move |_: Uri| {
            let s = socket.clone();
            async move {
                let stream = UnixStream::connect(&s).await?;
                Ok::<_, std::io::Error>(TokioIo::new(stream))
            }
        }))
        .await
        .context("sanctum UDS connect")?;
    Ok(SanctumClient::new(channel))
}

async fn fetch_token(client: &mut SanctumClient<Channel>, slot_name: &str) -> Result<String> {
    let resp = client
        .get_access_token(GetAccessTokenRequest {
            name: slot_name.to_string(),
        })
        .await
        .context("GetAccessToken RPC")?;
    let token = resp.into_inner().access_token;
    if token.is_empty() {
        bail!("sanctum returned empty access_token");
    }
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to build a custom-scheme credential for tests.
    fn custom_cred(
        name: &str,
        host: &str,
        header: &str,
        match_value: &str,
        format: &str,
        env: Option<&str>,
        file: Option<std::path::PathBuf>,
    ) -> Credential {
        Credential {
            name: name.to_string(),
            host: host.to_string(),
            scheme: CredentialScheme::Custom,
            header: Some(header.to_string()),
            match_value: match_value.to_string(),
            format: Some(format.to_string()),
            username: None,
            env: env.map(|s| s.to_string()),
            file,
            sanctum_path: None,
            sanctum_name: None,
            refresh_interval_secs: None,
        }
    }

    /// Helper to build a basic-scheme credential for tests.
    fn basic_cred(
        name: &str,
        host: &str,
        username: &str,
        match_value: &str,
        env: Option<&str>,
        file: Option<std::path::PathBuf>,
    ) -> Credential {
        Credential {
            name: name.to_string(),
            host: host.to_string(),
            scheme: CredentialScheme::Basic,
            header: None,
            match_value: match_value.to_string(),
            format: None,
            username: Some(username.to_string()),
            env: env.map(|s| s.to_string()),
            file,
            sanctum_path: None,
            sanctum_name: None,
            refresh_interval_secs: None,
        }
    }

    /// Read a `ResolvedCredential`'s real_value as a String (test convenience;
    /// the live code accesses it via the lock inside `replace`).
    fn real_value(rc: &ResolvedCredential) -> String {
        rc.real_value.read().unwrap().expose_secret().to_string()
    }

    // ========================================================================
    // Custom scheme tests (existing behavior)
    // ========================================================================

    #[test]
    fn test_resolve_credential_from_env() {
        std::env::set_var("TEST_CRED_SECRET", "my-secret-value");

        let cred = custom_cred(
            "test",
            "api.example.com",
            "Authorization",
            "Bearer DUMMY",
            "Bearer {value}",
            Some("TEST_CRED_SECRET"),
            None,
        );

        let (resolved, task) = resolve_credential(&cred).unwrap();
        assert!(task.is_none());
        assert_eq!(resolved.name, "test");
        assert_eq!(resolved.header, "authorization");
        assert_eq!(real_value(&resolved), "Bearer my-secret-value");

        std::env::remove_var("TEST_CRED_SECRET");
    }

    #[test]
    fn test_resolve_credential_missing_env() {
        let cred = custom_cred(
            "test",
            "api.example.com",
            "Authorization",
            "Bearer DUMMY",
            "Bearer {value}",
            Some("NONEXISTENT_VAR_12345"),
            None,
        );

        let result = resolve_credential(&cred);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("environment variable"));
    }

    #[test]
    fn test_resolve_credential_both_sources_error() {
        let cred = Credential {
            name: "test".to_string(),
            host: "api.example.com".to_string(),
            scheme: CredentialScheme::Custom,
            header: Some("Authorization".to_string()),
            match_value: "Bearer DUMMY".to_string(),
            format: Some("{value}".to_string()),
            username: None,
            env: Some("VAR".to_string()),
            file: Some("/path".into()),
            sanctum_path: None,
            sanctum_name: None,
            refresh_interval_secs: None,
        };

        let result = resolve_credential(&cred);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("must specify only one of"));
    }

    #[test]
    fn test_resolve_credential_no_source_error() {
        let cred = custom_cred(
            "test",
            "api.example.com",
            "Authorization",
            "Bearer DUMMY",
            "{value}",
            None,
            None,
        );

        let result = resolve_credential(&cred);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("must specify one of"));
    }

    #[test]
    fn test_credential_store_replace() {
        std::env::set_var("TEST_REPLACE_SECRET", "real-token");

        let cred = custom_cred(
            "test",
            "*.example.com",
            "Authorization",
            "Bearer DUMMY_TOKEN",
            "Bearer {value}",
            Some("TEST_REPLACE_SECRET"),
            None,
        );

        let store = CredentialStore::load(&[cred]).unwrap();

        // Should replace when host, header, and value all match
        let header = HeaderName::from_static("authorization");
        let dummy_value = HeaderValue::from_static("Bearer DUMMY_TOKEN");
        let result = store.replace("api.example.com", &header, &dummy_value);
        assert!(result.is_some());
        let r = result.unwrap();
        assert_eq!(r.value, "Bearer real-token");
        assert_eq!(r.credential_name, "test");

        // Should NOT replace when value doesn't match
        let other_value = HeaderValue::from_static("Bearer OTHER_TOKEN");
        let result = store.replace("api.example.com", &header, &other_value);
        assert!(result.is_none());

        // Should NOT replace when host doesn't match
        let result = store.replace("other.com", &header, &dummy_value);
        assert!(result.is_none());

        // Should NOT replace when header doesn't match
        let other_header = HeaderName::from_static("x-api-key");
        let result = store.replace("api.example.com", &other_header, &dummy_value);
        assert!(result.is_none());

        std::env::remove_var("TEST_REPLACE_SECRET");
    }

    #[test]
    fn test_has_credentials_for_host() {
        std::env::set_var("TEST_HAS_CRED", "value");

        let cred = custom_cred(
            "test",
            "*.github.com",
            "Authorization",
            "token DUMMY",
            "token {value}",
            Some("TEST_HAS_CRED"),
            None,
        );

        let store = CredentialStore::load(&[cred]).unwrap();

        assert!(store.has_credentials_for_host("api.github.com"));
        assert!(store.has_credentials_for_host("raw.github.com"));
        assert!(!store.has_credentials_for_host("github.com")); // * doesn't match empty
        assert!(!store.has_credentials_for_host("example.com"));

        std::env::remove_var("TEST_HAS_CRED");
    }

    #[test]
    fn test_dynamic_credential_overwrites_and_bounds_store() {
        let store = CredentialStore::load(&[]).unwrap();
        let header = HeaderName::from_static("authorization");

        // Simulate repeated OAuth responses for the same host/token type.
        let mut last_dummy = String::new();
        for _ in 0..10 {
            last_dummy = store.insert_dynamic("api.example.com", "access", "real-token", None);
        }

        // The store must not grow without bound: one entry per (host, type).
        {
            let dynamic = store.dynamic.read().unwrap();
            assert_eq!(dynamic.by_dummy.len(), 1, "store grew past one entry");
            assert_eq!(dynamic.current.len(), 1);
        }

        // The latest dummy resolves to the real token.
        let latest = HeaderValue::from_str(&format!("Bearer {}", last_dummy)).unwrap();
        let result = store.replace("api.example.com", &header, &latest);
        assert_eq!(result.unwrap().value, "Bearer real-token");

        // An earlier, evicted dummy no longer resolves.
        let stale = HeaderValue::from_static("Bearer ALICE_ACCESS_1");
        assert_ne!(latest, stale, "test expects the first dummy to differ");
        assert!(store.replace("api.example.com", &header, &stale).is_none());

        // A distinct token type for the same host adds a second bounded entry.
        let _ = store.insert_dynamic("api.example.com", "refresh", "refresh-token", None);
        {
            let dynamic = store.dynamic.read().unwrap();
            assert_eq!(dynamic.by_dummy.len(), 2);
        }

        assert!(store.has_credentials_for_host("api.example.com"));
        assert!(!store.has_credentials_for_host("other.example.org"));
    }

    #[test]
    fn test_resolve_credential_from_file() {
        use std::io::Write;

        // Create a temp file with the secret
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmp, "  file-secret-value  ").unwrap(); // with whitespace to test trimming

        let cred = custom_cred(
            "file-test",
            "api.example.com",
            "X-Api-Key",
            "DUMMY_KEY",
            "{value}",
            None,
            Some(tmp.path().to_path_buf()),
        );

        let (resolved, task) = resolve_credential(&cred).unwrap();
        assert!(task.is_none());
        assert_eq!(resolved.name, "file-test");
        assert_eq!(resolved.header, "x-api-key");
        // Value should be trimmed
        assert_eq!(real_value(&resolved), "file-secret-value");
    }

    #[test]
    fn test_resolve_credential_missing_file() {
        let cred = custom_cred(
            "test",
            "api.example.com",
            "Authorization",
            "Bearer DUMMY",
            "Bearer {value}",
            None,
            Some("/nonexistent/path/to/secret/file".into()),
        );

        let result = resolve_credential(&cred);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("failed to read file"));
    }

    #[test]
    fn test_custom_scheme_default_format() {
        // When format is omitted, it defaults to "{value}"
        std::env::set_var("TEST_DEFAULT_FMT", "raw-secret");

        let cred = Credential {
            name: "test".to_string(),
            host: "api.example.com".to_string(),
            scheme: CredentialScheme::Custom,
            header: Some("X-Api-Key".to_string()),
            match_value: "DUMMY".to_string(),
            format: None, // omitted
            username: None,
            env: Some("TEST_DEFAULT_FMT".to_string()),
            file: None,
            sanctum_path: None,
            sanctum_name: None,
            refresh_interval_secs: None,
        };

        let (resolved, _task) = resolve_credential(&cred).unwrap();
        assert_eq!(real_value(&resolved), "raw-secret");

        std::env::remove_var("TEST_DEFAULT_FMT");
    }

    #[test]
    fn test_custom_scheme_rejects_username() {
        std::env::set_var("TEST_CUSTOM_USER", "secret");

        let cred = Credential {
            name: "test".to_string(),
            host: "api.example.com".to_string(),
            scheme: CredentialScheme::Custom,
            header: Some("Authorization".to_string()),
            match_value: "Bearer DUMMY".to_string(),
            format: Some("Bearer {value}".to_string()),
            username: Some("alice".to_string()), // not allowed for custom
            env: Some("TEST_CUSTOM_USER".to_string()),
            file: None,
            sanctum_path: None,
            sanctum_name: None,
            refresh_interval_secs: None,
        };

        let result = resolve_credential(&cred);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("'username' cannot be set when scheme = 'custom'"));

        std::env::remove_var("TEST_CUSTOM_USER");
    }

    // ========================================================================
    // Basic scheme tests
    // ========================================================================

    #[test]
    fn test_resolve_basic_credential_from_env() {
        std::env::set_var("TEST_BASIC_SECRET", "real-password");

        let cred = basic_cred(
            "basic-test",
            "pkgs.example.com",
            "token",
            "DUMMY_PASSWORD",
            Some("TEST_BASIC_SECRET"),
            None,
        );

        let (resolved, task) = resolve_credential(&cred).unwrap();
        assert!(task.is_none());
        assert_eq!(resolved.name, "basic-test");
        assert_eq!(resolved.header, "authorization");

        // match_value should be: Basic base64("token:DUMMY_PASSWORD")
        let expected_match = format!("Basic {}", BASE64_STANDARD.encode(b"token:DUMMY_PASSWORD"));
        assert_eq!(resolved.match_value, expected_match.as_str());

        // real_value should be: Basic base64("token:real-password")
        let expected_real = format!("Basic {}", BASE64_STANDARD.encode(b"token:real-password"));
        assert_eq!(real_value(&resolved), expected_real);

        std::env::remove_var("TEST_BASIC_SECRET");
    }

    #[test]
    fn test_resolve_basic_credential_from_file() {
        use std::io::Write;

        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmp, "  file-password  ").unwrap(); // with whitespace

        let cred = basic_cred(
            "basic-file",
            "pkgs.example.com",
            "deploy",
            "DUMMY_TOKEN",
            None,
            Some(tmp.path().to_path_buf()),
        );

        let (resolved, _task) = resolve_credential(&cred).unwrap();
        assert_eq!(resolved.header, "authorization");

        // real_value should use trimmed password
        let expected_real = format!("Basic {}", BASE64_STANDARD.encode(b"deploy:file-password"));
        assert_eq!(real_value(&resolved), expected_real);
    }

    #[test]
    fn test_resolve_basic_credential_missing_username() {
        std::env::set_var("TEST_BASIC_NO_USER", "secret");

        let cred = Credential {
            name: "test".to_string(),
            host: "pkgs.example.com".to_string(),
            scheme: CredentialScheme::Basic,
            header: None,
            match_value: "DUMMY".to_string(),
            format: None,
            username: None, // missing!
            env: Some("TEST_BASIC_NO_USER".to_string()),
            file: None,
            sanctum_path: None,
            sanctum_name: None,
            refresh_interval_secs: None,
        };

        let result = resolve_credential(&cred);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("'username' is required when scheme = 'basic'"));

        std::env::remove_var("TEST_BASIC_NO_USER");
    }

    #[test]
    fn test_resolve_basic_rejects_header_field() {
        std::env::set_var("TEST_BASIC_HDR", "secret");

        let cred = Credential {
            name: "test".to_string(),
            host: "pkgs.example.com".to_string(),
            scheme: CredentialScheme::Basic,
            header: Some("Authorization".to_string()), // not allowed for basic
            match_value: "DUMMY".to_string(),
            format: None,
            username: Some("token".to_string()),
            env: Some("TEST_BASIC_HDR".to_string()),
            file: None,
            sanctum_path: None,
            sanctum_name: None,
            refresh_interval_secs: None,
        };

        let result = resolve_credential(&cred);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("'header' cannot be set when scheme = 'basic'"));

        std::env::remove_var("TEST_BASIC_HDR");
    }

    #[test]
    fn test_resolve_basic_rejects_format_field() {
        std::env::set_var("TEST_BASIC_FMT", "secret");

        let cred = Credential {
            name: "test".to_string(),
            host: "pkgs.example.com".to_string(),
            scheme: CredentialScheme::Basic,
            header: None,
            match_value: "DUMMY".to_string(),
            format: Some("Basic {value}".to_string()), // not allowed for basic
            username: Some("token".to_string()),
            env: Some("TEST_BASIC_FMT".to_string()),
            file: None,
            sanctum_path: None,
            sanctum_name: None,
            refresh_interval_secs: None,
        };

        let result = resolve_credential(&cred);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("'format' cannot be set when scheme = 'basic'"));

        std::env::remove_var("TEST_BASIC_FMT");
    }

    #[test]
    fn test_credential_store_replace_basic() {
        std::env::set_var("TEST_BASIC_REPLACE", "real-secret");

        let cred = basic_cred(
            "basic-replace",
            "*.example.com",
            "token",
            "DUMMY_PW",
            Some("TEST_BASIC_REPLACE"),
            None,
        );

        let store = CredentialStore::load(&[cred]).unwrap();

        let header = HeaderName::from_static("authorization");

        // The client sends: Basic base64("token:DUMMY_PW")
        let dummy_b64 = BASE64_STANDARD.encode(b"token:DUMMY_PW");
        let dummy_value = HeaderValue::from_str(&format!("Basic {}", dummy_b64)).unwrap();

        let result = store.replace("pkgs.example.com", &header, &dummy_value);
        assert!(result.is_some());
        let r = result.unwrap();

        // Should be replaced with: Basic base64("token:real-secret")
        let expected_b64 = BASE64_STANDARD.encode(b"token:real-secret");
        let expected = format!("Basic {}", expected_b64);
        assert_eq!(r.value, expected.as_str());
        assert_eq!(r.credential_name, "basic-replace");

        // Should NOT match a different password
        let other_b64 = BASE64_STANDARD.encode(b"token:OTHER_PW");
        let other_value = HeaderValue::from_str(&format!("Basic {}", other_b64)).unwrap();
        let result = store.replace("pkgs.example.com", &header, &other_value);
        assert!(result.is_none());

        // Should NOT match a different username
        let wrong_user_b64 = BASE64_STANDARD.encode(b"admin:DUMMY_PW");
        let wrong_user_value = HeaderValue::from_str(&format!("Basic {}", wrong_user_b64)).unwrap();
        let result = store.replace("pkgs.example.com", &header, &wrong_user_value);
        assert!(result.is_none());

        // Should NOT match a Bearer token with the same password
        let bearer_value = HeaderValue::from_str("Bearer DUMMY_PW").unwrap();
        let result = store.replace("pkgs.example.com", &header, &bearer_value);
        assert!(result.is_none());

        std::env::remove_var("TEST_BASIC_REPLACE");
    }

    #[test]
    fn test_credential_store_mixed_schemes() {
        // Test that custom and basic credentials can coexist
        std::env::set_var("TEST_MIX_BEARER", "real-bearer-token");
        std::env::set_var("TEST_MIX_BASIC", "real-basic-password");

        let bearer_cred = custom_cred(
            "bearer",
            "api.example.com",
            "Authorization",
            "Bearer DUMMY_BEARER",
            "Bearer {value}",
            Some("TEST_MIX_BEARER"),
            None,
        );

        let basic_cred = basic_cred(
            "basic",
            "api.example.com",
            "token",
            "DUMMY_BASIC",
            Some("TEST_MIX_BASIC"),
            None,
        );

        let store = CredentialStore::load(&[bearer_cred, basic_cred]).unwrap();
        let header = HeaderName::from_static("authorization");

        // Bearer credential should match
        let bearer_value = HeaderValue::from_static("Bearer DUMMY_BEARER");
        let result = store.replace("api.example.com", &header, &bearer_value);
        assert!(result.is_some());
        assert_eq!(result.unwrap().value, "Bearer real-bearer-token");

        // Basic credential should match
        let basic_b64 = BASE64_STANDARD.encode(b"token:DUMMY_BASIC");
        let basic_value = HeaderValue::from_str(&format!("Basic {}", basic_b64)).unwrap();
        let result = store.replace("api.example.com", &header, &basic_value);
        assert!(result.is_some());
        let expected_b64 = BASE64_STANDARD.encode(b"token:real-basic-password");
        assert_eq!(
            result.unwrap().value,
            format!("Basic {}", expected_b64).as_str()
        );

        std::env::remove_var("TEST_MIX_BEARER");
        std::env::remove_var("TEST_MIX_BASIC");
    }

    // ========================================================================
    // Sanctum source tests
    // ========================================================================

    /// Helper to build a sanctum credential for tests.
    fn sanctum_cred(
        name: &str,
        host: &str,
        socket: &std::path::Path,
        refresh_secs: Option<u64>,
    ) -> Credential {
        Credential {
            name: name.to_string(),
            host: host.to_string(),
            scheme: CredentialScheme::Custom,
            header: Some("Authorization".to_string()),
            match_value: "Bearer sk-ant-oat01-AAAA".to_string(),
            format: Some("Bearer {value}".to_string()),
            username: None,
            env: None,
            file: None,
            sanctum_path: Some(socket.to_path_buf()),
            sanctum_name: Some("default".to_string()),
            refresh_interval_secs: refresh_secs,
        }
    }

    #[test]
    fn test_sanctum_resolve_returns_pending_task() {
        let cred = sanctum_cred(
            "anthropic",
            "api.anthropic.com",
            std::path::Path::new("/run/sanctum/sanctum.sock"),
            Some(60),
        );
        let (resolved, task) = resolve_credential(&cred).unwrap();
        assert_eq!(resolved.name, "anthropic");
        assert_eq!(resolved.header, "authorization");
        assert_eq!(resolved.match_value, "Bearer sk-ant-oat01-AAAA");
        // Real value starts empty; refresh task fills it.
        assert_eq!(real_value(&resolved), "");
        let task = task.unwrap();
        assert_eq!(task.name, "anthropic");
        assert_eq!(
            task.socket,
            std::path::Path::new("/run/sanctum/sanctum.sock")
        );
        assert_eq!(task.interval, Duration::from_secs(60));
        assert_eq!(task.format, "Bearer {value}");
    }

    #[test]
    fn test_sanctum_default_refresh_interval() {
        let cred = sanctum_cred(
            "anthropic",
            "api.anthropic.com",
            std::path::Path::new("/run/sanctum/sanctum.sock"),
            None, // omitted — defaults to 60s
        );
        let (_resolved, task) = resolve_credential(&cred).unwrap();
        assert_eq!(task.unwrap().interval, Duration::from_secs(60));
    }

    #[test]
    fn test_sanctum_rejects_zero_interval() {
        let cred = sanctum_cred(
            "anthropic",
            "api.anthropic.com",
            std::path::Path::new("/run/sanctum/sanctum.sock"),
            Some(0),
        );
        let err = resolve_credential(&cred).unwrap_err().to_string();
        assert!(err.contains("must be positive"));
    }

    #[test]
    fn test_sanctum_conflicts_with_env() {
        let mut cred = sanctum_cred(
            "anthropic",
            "api.anthropic.com",
            std::path::Path::new("/run/sanctum/sanctum.sock"),
            None,
        );
        cred.env = Some("ANTHROPIC_TOKEN".to_string());
        let err = resolve_credential(&cred).unwrap_err().to_string();
        assert!(err.contains("must specify only one of"));
    }

    #[test]
    fn test_sanctum_conflicts_with_file() {
        let mut cred = sanctum_cred(
            "anthropic",
            "api.anthropic.com",
            std::path::Path::new("/run/sanctum/sanctum.sock"),
            None,
        );
        cred.file = Some("/tmp/secret".into());
        let err = resolve_credential(&cred).unwrap_err().to_string();
        assert!(err.contains("must specify only one of"));
    }

    #[test]
    fn test_refresh_interval_requires_sanctum() {
        let mut cred = custom_cred(
            "test",
            "api.example.com",
            "Authorization",
            "Bearer DUMMY",
            "Bearer {value}",
            Some("UNSET_VAR_XYZ"),
            None,
        );
        cred.refresh_interval_secs = Some(60);
        let err = resolve_credential(&cred).unwrap_err().to_string();
        assert!(err.contains("'refresh_interval_secs' is only valid"));
    }

    #[test]
    fn test_sanctum_rejects_basic_scheme() {
        let mut cred = sanctum_cred(
            "anthropic",
            "api.anthropic.com",
            std::path::Path::new("/run/sanctum/sanctum.sock"),
            None,
        );
        cred.scheme = CredentialScheme::Basic;
        cred.header = None;
        cred.username = Some("token".to_string());
        cred.format = None;
        let err = resolve_credential(&cred).unwrap_err().to_string();
        assert!(err.contains("scheme = 'basic' is not supported"));
    }

    #[test]
    fn test_sanctum_requires_header() {
        let mut cred = sanctum_cred(
            "anthropic",
            "api.anthropic.com",
            std::path::Path::new("/run/sanctum/sanctum.sock"),
            None,
        );
        cred.header = None;
        let err = resolve_credential(&cred).unwrap_err().to_string();
        assert!(err.contains("'header' is required"));
    }

    /// End-to-end test: spin up a tonic server on a UDS that mimics sanctum,
    /// load a credential pointing at it, run `start_sanctum_refresh`,
    /// and assert that `replace()` injects the freshly fetched token.
    #[tokio::test]
    async fn test_sanctum_end_to_end() {
        use crate::sanctum_proto::sanctum_server::{Sanctum, SanctumServer};
        use crate::sanctum_proto::{
            AccessToken, ForceRefreshRequest, GetAccessTokenRequest, ImportCredentialRequest,
            ImportCredentialResponse,
        };
        use tokio::net::UnixListener;
        use tokio_stream::wrappers::UnixListenerStream;
        use tonic::transport::Server;
        use tonic::{Request, Response, Status};

        struct MockSanctum;
        #[tonic::async_trait]
        impl Sanctum for MockSanctum {
            async fn get_access_token(
                &self,
                req: Request<GetAccessTokenRequest>,
            ) -> Result<Response<AccessToken>, Status> {
                assert_eq!(req.into_inner().name, "default");
                Ok(Response::new(AccessToken {
                    access_token: "sk-ant-oat01-REAL".to_string(),
                    expires_at: None,
                }))
            }
            async fn force_refresh(
                &self,
                _: Request<ForceRefreshRequest>,
            ) -> Result<Response<AccessToken>, Status> {
                Err(Status::unimplemented("mock"))
            }
            async fn import_credential(
                &self,
                _: Request<ImportCredentialRequest>,
            ) -> Result<Response<ImportCredentialResponse>, Status> {
                Err(Status::unimplemented("mock"))
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("sanctum.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let incoming = UnixListenerStream::new(listener);
        let _server = tokio::spawn(async move {
            Server::builder()
                .add_service(SanctumServer::new(MockSanctum))
                .serve_with_incoming(incoming)
                .await
                .unwrap();
        });

        let cred = sanctum_cred("anthropic", "api.anthropic.com", &socket_path, Some(60));
        let store = CredentialStore::load(&[cred]).unwrap();
        store.start_sanctum_refresh().await.unwrap();

        let header = HeaderName::from_static("authorization");
        let dummy = HeaderValue::from_static("Bearer sk-ant-oat01-AAAA");
        let result = store.replace("api.anthropic.com", &header, &dummy);
        let r = result.expect("replacement should fire");
        assert_eq!(r.value, "Bearer sk-ant-oat01-REAL");
        assert_eq!(r.credential_name, "anthropic");
    }

    #[tokio::test]
    async fn test_sanctum_initial_fetch_failure_aborts() {
        // Point at a path with nothing bound; first GetAccessToken must fail loud.
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("nope.sock");

        let cred = sanctum_cred("anthropic", "api.anthropic.com", &socket_path, Some(60));
        let store = CredentialStore::load(&[cred]).unwrap();
        let err = store.start_sanctum_refresh().await.unwrap_err();
        let msg = format!("{:#}", err);
        assert!(msg.contains("sanctum credential 'anthropic'"));
    }
}
