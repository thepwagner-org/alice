//! Credential store for injecting secrets into outbound requests.
//!
//! Credentials are loaded from:
//! - Environment variables (`env = "VAR_NAME"`)
//! - Files (`file = "/path/to/secret"`)
//! - Intercepted OAuth responses (dynamic, at runtime)
//!
//! For SOPS-encrypted secrets, use `sops exec-env` to decrypt and pass as env vars:
//!   sops exec-env secrets.yaml -- alice -c config.toml

use crate::config::Credential;
use anyhow::{bail, Context, Result};
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

    // Format the value
    let formatted = cred.format.replace("{value}", &secret_value);

    // Compile the host matcher
    let host_glob = Glob::new(&cred.host).with_context(|| {
        format!(
            "credential '{}': invalid host pattern '{}'",
            cred.name, cred.host
        )
    })?;

    // Parse header name
    let header = cred.header.parse::<HeaderName>().with_context(|| {
        format!(
            "credential '{}': invalid header name '{}'",
            cred.name, cred.header
        )
    })?;

    // Parse match value
    let match_value = HeaderValue::from_str(&cred.match_value).with_context(|| {
        format!(
            "credential '{}': invalid match value '{}'",
            cred.name, cred.match_value
        )
    })?;

    info!(
        name = %cred.name,
        host = %cred.host,
        header = %cred.header,
        "loaded credential"
    );

    Ok(ResolvedCredential {
        name: cred.name.clone(),
        host_match: HostMatch::Glob(host_glob.compile_matcher()),
        header,
        match_value,
        real_value: SecretString::new(formatted.into()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_credential_from_env() {
        std::env::set_var("TEST_CRED_SECRET", "my-secret-value");

        let cred = Credential {
            name: "test".to_string(),
            host: "api.example.com".to_string(),
            header: "Authorization".to_string(),
            match_value: "Bearer DUMMY".to_string(),
            format: "Bearer {value}".to_string(),
            env: Some("TEST_CRED_SECRET".to_string()),
            file: None,
        };

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
        let cred = Credential {
            name: "test".to_string(),
            host: "api.example.com".to_string(),
            header: "Authorization".to_string(),
            match_value: "Bearer DUMMY".to_string(),
            format: "Bearer {value}".to_string(),
            env: Some("NONEXISTENT_VAR_12345".to_string()),
            file: None,
        };

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
            header: "Authorization".to_string(),
            match_value: "Bearer DUMMY".to_string(),
            format: "{value}".to_string(),
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
        let cred = Credential {
            name: "test".to_string(),
            host: "api.example.com".to_string(),
            header: "Authorization".to_string(),
            match_value: "Bearer DUMMY".to_string(),
            format: "{value}".to_string(),
            env: None,
            file: None,
        };

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

        let cred = Credential {
            name: "test".to_string(),
            host: "*.example.com".to_string(),
            header: "Authorization".to_string(),
            match_value: "Bearer DUMMY_TOKEN".to_string(),
            format: "Bearer {value}".to_string(),
            env: Some("TEST_REPLACE_SECRET".to_string()),
            file: None,
        };

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

        let cred = Credential {
            name: "test".to_string(),
            host: "*.github.com".to_string(),
            header: "Authorization".to_string(),
            match_value: "token DUMMY".to_string(),
            format: "token {value}".to_string(),
            env: Some("TEST_HAS_CRED".to_string()),
            file: None,
        };

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

        let cred = Credential {
            name: "file-test".to_string(),
            host: "api.example.com".to_string(),
            header: "X-Api-Key".to_string(),
            match_value: "DUMMY_KEY".to_string(),
            format: "{value}".to_string(),
            env: None,
            file: Some(tmp.path().to_path_buf()),
        };

        let resolved = resolve_credential(&cred).unwrap();
        assert_eq!(resolved.name, "file-test");
        assert_eq!(resolved.header, "x-api-key");
        // Value should be trimmed
        assert_eq!(resolved.real_value.expose_secret(), "file-secret-value");
    }

    #[test]
    fn test_resolve_credential_missing_file() {
        let cred = Credential {
            name: "test".to_string(),
            host: "api.example.com".to_string(),
            header: "Authorization".to_string(),
            match_value: "Bearer DUMMY".to_string(),
            format: "Bearer {value}".to_string(),
            env: None,
            file: Some("/nonexistent/path/to/secret/file".into()),
        };

        let result = resolve_credential(&cred);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("failed to read file"));
    }
}
