//! Credential store for injecting secrets into outbound requests.
//!
//! Credentials are loaded from:
//! - Environment variables (`env = "VAR_NAME"`)
//! - Files (`file = "/path/to/secret"`)
//! - Intercepted OAuth responses (dynamic, at runtime)
//!
//! For SOPS-encrypted secrets, use `sops exec-env` to decrypt and pass as env vars:
//!   sops exec-env secrets.yaml -- alice -c config.toml

use crate::config::{Credential, CredentialScheme};
use anyhow::{bail, Context, Result};
use base64::prelude::*;
use globset::{Glob, GlobMatcher};
use http::{HeaderName, HeaderValue};
use secrecy::{ExposeSecret, SecretString};
use serde_json::Value;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
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
    /// Pre-formatted real value to inject
    real_value: SecretString,
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

/// Store for all loaded credentials.
///
/// Thread-safe to support dynamic credential insertion from intercepted responses.
pub struct CredentialStore {
    credentials: RwLock<Vec<ResolvedCredential>>,
    /// Counter for generating unique dummy token names
    token_counter: AtomicU64,
}

impl CredentialStore {
    /// Load credentials from config.
    pub fn load(credentials: &[Credential]) -> Result<Self> {
        let mut resolved = Vec::new();

        for cred in credentials {
            resolved.push(resolve_credential(cred)?);
        }

        debug!(count = resolved.len(), "loaded credentials");

        Ok(Self {
            credentials: RwLock::new(resolved),
            token_counter: AtomicU64::new(1),
        })
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
        let credentials = self.credentials.read().unwrap();
        for cred in credentials.iter() {
            if cred.host_match.matches(host)
                && cred.header == *header
                && cred.match_value == *current_value
            {
                // Convert secret to HeaderValue
                if let Ok(value) = HeaderValue::from_str(cred.real_value.expose_secret()) {
                    return Some(Replacement {
                        value,
                        credential_name: cred.name.clone(),
                    });
                }
            }
        }
        None
    }

    /// Check if any credentials are configured for a given host.
    pub fn has_credentials_for_host(&self, host: &str) -> bool {
        let credentials = self.credentials.read().unwrap();
        credentials.iter().any(|cred| cred.host_match.matches(host))
    }

    /// Returns true if no credentials are loaded.
    #[allow(dead_code)] // May be useful for future features
    pub fn is_empty(&self) -> bool {
        let credentials = self.credentials.read().unwrap();
        credentials.is_empty()
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

        let match_desc = host_pattern.unwrap_or(host);

        let cred = ResolvedCredential {
            name: format!("dynamic-{}-{}", token_type, id),
            host_match,
            header: HeaderName::from_static("authorization"),
            match_value: HeaderValue::from_str(&dummy_with_bearer).unwrap(),
            real_value: SecretString::new(real_with_bearer.into()),
        };

        debug!(
            host = %match_desc,
            token_type = %token_type,
            dummy = %dummy,
            "captured token from response"
        );

        let mut credentials = self.credentials.write().unwrap();
        credentials.push(cred);

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
            obj.insert("access_token".to_string(), Value::String(dummy));
            redacted_any = true;
        }

        // Redact refresh_token
        if let Some(Value::String(token)) = obj.get("refresh_token") {
            let dummy = self.insert_dynamic(host, "refresh", token, host_pattern);
            obj.insert("refresh_token".to_string(), Value::String(dummy));
            redacted_any = true;
        }

        // Redact id_token (OpenID Connect)
        if let Some(Value::String(token)) = obj.get("id_token") {
            let dummy = self.insert_dynamic(host, "id", token, host_pattern);
            obj.insert("id_token".to_string(), Value::String(dummy));
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

/// Resolve a credential from the main config file (env or file source).
fn resolve_credential(cred: &Credential) -> Result<ResolvedCredential> {
    // Validate: exactly one of env or file must be specified
    match (&cred.env, &cred.file) {
        (Some(_), Some(_)) => bail!(
            "credential '{}': cannot specify both 'env' and 'file'",
            cred.name
        ),
        (None, None) => bail!(
            "credential '{}': must specify either 'env' or 'file'",
            cred.name
        ),
        _ => {}
    }

    // Load the secret value
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
        unreachable!()
    };

    // Compile the host matcher (shared by both schemes)
    let host_glob = Glob::new(&cred.host).with_context(|| {
        format!(
            "credential '{}': invalid host pattern '{}'",
            cred.name, cred.host
        )
    })?;

    // Branch on scheme
    let (header, match_value, real_value) = match cred.scheme {
        CredentialScheme::Custom => resolve_custom_credential(cred, &secret_value)?,
        CredentialScheme::Basic => resolve_basic_credential(cred, &secret_value)?,
    };

    let header_display = header.as_str();
    info!(
        name = %cred.name,
        host = %cred.host,
        header = %header_display,
        scheme = ?cred.scheme,
        "loaded credential"
    );

    Ok(ResolvedCredential {
        name: cred.name.clone(),
        host_match: HostMatch::Glob(host_glob.compile_matcher()),
        header,
        match_value,
        real_value: SecretString::new(real_value.into()),
    })
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
        }
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

        let resolved = resolve_credential(&cred).unwrap();
        assert_eq!(resolved.name, "test");
        assert_eq!(resolved.header, "authorization");
        assert_eq!(
            resolved.real_value.expose_secret(),
            "Bearer my-secret-value"
        );

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
        };

        let result = resolve_credential(&cred);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("cannot specify both"));
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
            .contains("must specify either"));
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

        let resolved = resolve_credential(&cred).unwrap();
        assert_eq!(resolved.name, "file-test");
        assert_eq!(resolved.header, "x-api-key");
        // Value should be trimmed
        assert_eq!(resolved.real_value.expose_secret(), "file-secret-value");
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
        };

        let resolved = resolve_credential(&cred).unwrap();
        assert_eq!(resolved.real_value.expose_secret(), "raw-secret");

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

        let resolved = resolve_credential(&cred).unwrap();
        assert_eq!(resolved.name, "basic-test");
        assert_eq!(resolved.header, "authorization");

        // match_value should be: Basic base64("token:DUMMY_PASSWORD")
        let expected_match = format!("Basic {}", BASE64_STANDARD.encode(b"token:DUMMY_PASSWORD"));
        assert_eq!(resolved.match_value, expected_match.as_str());

        // real_value should be: Basic base64("token:real-password")
        let expected_real = format!("Basic {}", BASE64_STANDARD.encode(b"token:real-password"));
        assert_eq!(resolved.real_value.expose_secret(), &expected_real);

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

        let resolved = resolve_credential(&cred).unwrap();
        assert_eq!(resolved.header, "authorization");

        // real_value should use trimmed password
        let expected_real = format!("Basic {}", BASE64_STANDARD.encode(b"deploy:file-password"));
        assert_eq!(resolved.real_value.expose_secret(), &expected_real);
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
}
