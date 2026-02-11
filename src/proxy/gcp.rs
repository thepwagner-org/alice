//! GCP service account credential injection via proxy-side JWT re-signing.
//!
//! Flow:
//! 1. Alice loads a real GCP service account key file at startup.
//! 2. Alice generates a dummy SA key file (same metadata, throwaway RSA key)
//!    and writes it where Bob can access it.
//! 3. Bob configures `GOOGLE_APPLICATION_CREDENTIALS=/path/to/dummy-sa.json`.
//! 4. When Bob's client library POSTs a JWT assertion to oauth2.googleapis.com/token,
//!    Alice intercepts the request body, verifies the JWT was signed with the
//!    known dummy key, re-signs it with the real SA key, and forwards it.
//! 5. The response (containing an access token) is handled by existing OAuth
//!    redaction in CredentialStore.

use anyhow::{bail, Context, Result};
use jsonwebtoken::{
    decode, encode, Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation,
};
use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey};
use rsa::pkcs8::LineEnding;
use rsa::RsaPrivateKey;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::config::{GcpCredential, GcpUserCredential};

/// Google's OAuth2 token endpoint host.
pub const GCP_TOKEN_HOST: &str = "oauth2.googleapis.com";

/// The grant type for JWT bearer assertions (RFC 7523).
const JWT_BEARER_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

/// GCP service account JSON key file structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ServiceAccountKey {
    #[serde(rename = "type")]
    key_type: String,
    project_id: String,
    private_key_id: String,
    private_key: String,
    client_email: String,
    client_id: String,
    auth_uri: String,
    token_uri: String,
    auth_provider_x509_cert_url: String,
    client_x509_cert_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    universe_domain: Option<String>,
}

/// JWT claims for GCP service account assertion.
#[derive(Debug, Serialize, Deserialize)]
struct GcpJwtClaims {
    iss: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    aud: String,
    iat: i64,
    exp: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    sub: Option<String>,
}

/// A loaded GCP service account ready for JWT re-signing.
pub struct GcpServiceAccount {
    /// Name identifier (from config)
    pub name: String,
    /// The client_email from the real SA key (used to identify matching JWTs)
    pub client_email: String,
    /// Encoding key derived from the real SA private key
    real_encoding_key: EncodingKey,
    /// The private_key_id from the real SA key (set in JWT header `kid`)
    real_private_key_id: String,
    /// Decoding key derived from the dummy private key (for verifying Bob's signature)
    dummy_decoding_key: DecodingKey,
    /// Path where the dummy key was written
    pub dummy_key_path: String,
}

impl std::fmt::Debug for GcpServiceAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GcpServiceAccount")
            .field("name", &self.name)
            .field("client_email", &self.client_email)
            .field("dummy_key_path", &self.dummy_key_path)
            .finish()
    }
}

impl GcpServiceAccount {
    /// Load a real SA key, generate a dummy key, and write the dummy file.
    pub fn load(config: &GcpCredential) -> Result<Self> {
        // Read and parse the real SA key file
        let real_key_json = std::fs::read_to_string(&config.key_file).with_context(|| {
            format!(
                "gcp credential '{}': failed to read key file '{}'",
                config.name,
                config.key_file.display()
            )
        })?;

        let real_key: ServiceAccountKey =
            serde_json::from_str(&real_key_json).with_context(|| {
                format!(
                    "gcp credential '{}': failed to parse key file as service account JSON",
                    config.name
                )
            })?;

        if real_key.key_type != "service_account" {
            bail!(
                "gcp credential '{}': expected type 'service_account', got '{}'",
                config.name,
                real_key.key_type
            );
        }

        // Parse the real private key (PKCS#8 PEM format from Google)
        let real_encoding_key = EncodingKey::from_rsa_pem(real_key.private_key.as_bytes())
            .with_context(|| {
                format!(
                    "gcp credential '{}': failed to parse private key from key file",
                    config.name
                )
            })?;

        // Generate a dummy RSA keypair for Bob
        let mut rng = rand::thread_rng();
        let dummy_private_key = RsaPrivateKey::new(&mut rng, 2048).with_context(|| {
            format!(
                "gcp credential '{}': failed to generate dummy RSA key",
                config.name
            )
        })?;

        // Extract the dummy public key for signature verification
        let dummy_public_key = dummy_private_key.to_public_key();
        let dummy_public_pem =
            dummy_public_key
                .to_pkcs1_pem(LineEnding::LF)
                .with_context(|| {
                    format!(
                        "gcp credential '{}': failed to encode dummy public key",
                        config.name
                    )
                })?;

        let dummy_decoding_key = DecodingKey::from_rsa_pem(dummy_public_pem.as_bytes())
            .with_context(|| {
                format!(
                    "gcp credential '{}': failed to create decoding key from dummy public key",
                    config.name
                )
            })?;

        // Build the dummy SA JSON key file (same metadata, different private key)
        //
        // Google's SA key files use PKCS#1 format ("BEGIN RSA PRIVATE KEY")
        // not PKCS#8 ("BEGIN PRIVATE KEY"), so convert for compatibility.
        let dummy_pkcs1_pem = dummy_private_key
            .to_pkcs1_pem(LineEnding::LF)
            .with_context(|| {
                format!(
                    "gcp credential '{}': failed to encode dummy key as PKCS#1",
                    config.name
                )
            })?;

        let dummy_key = ServiceAccountKey {
            key_type: "service_account".to_string(),
            project_id: real_key.project_id.clone(),
            private_key_id: format!("alice-dummy-{}", config.name),
            private_key: dummy_pkcs1_pem.to_string(),
            client_email: real_key.client_email.clone(),
            client_id: real_key.client_id.clone(),
            auth_uri: real_key.auth_uri.clone(),
            token_uri: real_key.token_uri.clone(),
            auth_provider_x509_cert_url: real_key.auth_provider_x509_cert_url.clone(),
            client_x509_cert_url: real_key.client_x509_cert_url.clone(),
            universe_domain: real_key.universe_domain.clone(),
        }; // trufflehog:ignore (generated dummy key struct, not a real credential)

        // Write the dummy key file
        let dummy_json = serde_json::to_string_pretty(&dummy_key).with_context(|| {
            format!(
                "gcp credential '{}': failed to serialize dummy key",
                config.name
            )
        })?;

        // Ensure parent directory exists
        if let Some(parent) = config.dummy_key_path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!(
                    "gcp credential '{}': failed to create directory for dummy key at '{}'",
                    config.name,
                    parent.display()
                )
            })?;
        }

        std::fs::write(&config.dummy_key_path, &dummy_json).with_context(|| {
            format!(
                "gcp credential '{}': failed to write dummy key to '{}'",
                config.name,
                config.dummy_key_path.display()
            )
        })?;

        info!(
            name = %config.name,
            client_email = %real_key.client_email,
            dummy_key_path = %config.dummy_key_path.display(),
            "loaded GCP service account credential, wrote dummy key"
        );

        Ok(Self {
            name: config.name.clone(),
            client_email: real_key.client_email,
            real_encoding_key,
            real_private_key_id: real_key.private_key_id,
            dummy_decoding_key,
            dummy_key_path: config.dummy_key_path.display().to_string(),
        })
    }

    /// Attempt to re-sign a JWT assertion in a token exchange POST body.
    ///
    /// The body is `application/x-www-form-urlencoded` with:
    ///   grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=<JWT>
    ///
    /// Returns `Some(new_body)` if the JWT was successfully verified (against the
    /// dummy key) and re-signed (with the real key). Returns `None` if the body
    /// doesn't match or isn't a JWT bearer assertion for this service account.
    pub fn resign_token_request(&self, body: &[u8]) -> Option<Vec<u8>> {
        let body_str = std::str::from_utf8(body).ok()?;

        // Parse form-urlencoded body
        let params: Vec<(String, String)> = url::form_urlencoded::parse(body_str.as_bytes())
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();

        // Check grant_type
        let grant_type = params.iter().find(|(k, _)| k == "grant_type")?;
        if grant_type.1 != JWT_BEARER_GRANT_TYPE {
            return None;
        }

        // Extract the JWT assertion
        let assertion = params.iter().find(|(k, _)| k == "assertion")?;
        let jwt = &assertion.1;

        // Decode the JWT header to check algorithm, and decode claims
        // First, peek at the claims to check if this JWT is for our service account
        let claims = self.verify_and_decode_jwt(jwt)?;

        // Check that the issuer matches our service account
        if claims.iss != self.client_email {
            debug!(
                iss = %claims.iss,
                expected = %self.client_email,
                "JWT issuer doesn't match, skipping"
            );
            return None;
        }

        // Re-sign the JWT with the real private key
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.real_private_key_id.clone());

        let new_jwt = match encode(&header, &claims, &self.real_encoding_key) {
            Ok(jwt) => jwt,
            Err(e) => {
                warn!(error = %e, name = %self.name, "failed to re-sign JWT with real key");
                return None;
            }
        };

        info!(
            name = %self.name,
            client_email = %self.client_email,
            "re-signed GCP JWT assertion"
        );

        // Rebuild the form-urlencoded body with the new assertion
        let new_body: String = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", JWT_BEARER_GRANT_TYPE)
            .append_pair("assertion", &new_jwt)
            .finish();

        Some(new_body.into_bytes())
    }

    /// Verify a JWT was signed with the dummy key and decode its claims.
    ///
    /// Returns `None` if verification fails (wrong key, expired, malformed, etc).
    fn verify_and_decode_jwt(&self, jwt: &str) -> Option<GcpJwtClaims> {
        let mut validation = Validation::new(Algorithm::RS256);
        // Google's token endpoint is the audience for SA key assertions
        validation.set_audience(&["https://oauth2.googleapis.com/token"]);
        // Allow some clock skew
        validation.leeway = 60;
        // Don't validate `sub` as a required claim
        validation.set_required_spec_claims(&["iss", "aud", "exp", "iat"]);

        match decode::<GcpJwtClaims>(jwt, &self.dummy_decoding_key, &validation) {
            Ok(TokenData { claims, .. }) => {
                debug!(
                    iss = %claims.iss,
                    aud = %claims.aud,
                    "verified JWT signature against dummy key"
                );
                Some(claims)
            }
            Err(e) => {
                warn!(
                    error = %e,
                    name = %self.name,
                    "JWT signature verification failed against dummy key — \
                     rejecting (Bob must use the dummy key Alice provided)"
                );
                None
            }
        }
    }
}

// ---------------------------------------------------------------------------
// GCP user credentials (refresh token flow)
// ---------------------------------------------------------------------------

/// The grant type for OAuth2 refresh tokens.
const REFRESH_TOKEN_GRANT_TYPE: &str = "refresh_token";

/// JSON structure stored in gcloud's credentials.db `value` blob.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct GcloudCredentialBlob {
    #[serde(rename = "type")]
    cred_type: String,
    client_id: String,
    client_secret: String,
    refresh_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_uri: Option<String>,
    /// Preserve any extra fields we don't explicitly handle.
    #[serde(flatten)]
    extra: serde_json::Map<String, serde_json::Value>,
}

/// JSON structure of application_default_credentials.json.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ApplicationDefaultCredentials {
    #[serde(rename = "type")]
    cred_type: String,
    client_id: String,
    client_secret: String,
    refresh_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    quota_project_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    universe_domain: Option<String>,
    /// Preserve any extra fields.
    #[serde(flatten)]
    extra: serde_json::Map<String, serde_json::Value>,
}

/// A single mapping from dummy refresh token to real refresh token.
struct RefreshTokenMapping {
    /// The dummy refresh token Bob will send.
    dummy_refresh_token: String,
    /// The real refresh token to substitute.
    real_refresh_token: String,
    /// The real client_id (must also match in the POST body).
    client_id: String,
    /// The real client_secret to substitute.
    real_client_secret: String,
    /// The dummy client_secret Bob will send.
    dummy_client_secret: String,
    /// Account email (for logging).
    account_id: String,
}

/// A loaded GCP user credential ready for refresh token swapping.
pub struct GcpUserAccount {
    /// Name identifier (from config).
    pub name: String,
    /// All refresh token mappings (credentials.db accounts + ADC).
    mappings: Vec<RefreshTokenMapping>,
}

impl std::fmt::Debug for GcpUserAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GcpUserAccount")
            .field("name", &self.name)
            .field("mapping_count", &self.mappings.len())
            .finish()
    }
}

impl GcpUserAccount {
    /// Load user credentials from a gcloud config directory.
    ///
    /// Reads credentials.db and application_default_credentials.json,
    /// generates dummy versions, and writes them to the dummy config directory.
    ///
    /// Returns `None` if no credentials were found (warning logged, not fatal).
    pub fn load(config: &GcpUserCredential) -> Result<Option<Self>> {
        let real_dir = &config.gcloud_config_dir;
        let dummy_dir = &config.dummy_config_dir;

        // Create the dummy directory structure
        std::fs::create_dir_all(dummy_dir).with_context(|| {
            format!(
                "gcp user credential '{}': failed to create dummy config dir '{}'",
                config.name,
                dummy_dir.display()
            )
        })?;

        let mut mappings = Vec::new();
        let mut default_account: Option<String> = None;

        // --- Read credentials.db ---
        let credentials_db_path = real_dir.join("credentials.db");
        if credentials_db_path.exists() {
            let rows = Self::read_credentials_db(&credentials_db_path, &config.name)?;

            if rows.is_empty() {
                debug!(
                    name = %config.name,
                    path = %credentials_db_path.display(),
                    "credentials.db exists but contains no user credentials"
                );
            }

            // Pick the first account as default (gcloud CLI convention)
            if let Some(first) = rows.first() {
                default_account = Some(first.0.clone());
            }

            // Generate dummy tokens and write dummy credentials.db
            let dummy_db_path = dummy_dir.join("credentials.db");
            let mut dummy_rows = Vec::new();

            for (i, (account_id, blob)) in rows.into_iter().enumerate() {
                let dummy_refresh = format!("ALICE_USER_REFRESH_{}", i + 1);
                let dummy_secret = format!("ALICE_CLIENT_SECRET_{}", i + 1);

                let mut dummy_blob = blob.clone();
                dummy_blob.refresh_token = dummy_refresh.clone();
                dummy_blob.client_secret = dummy_secret.clone();

                dummy_rows.push((account_id.clone(), dummy_blob));

                mappings.push(RefreshTokenMapping {
                    dummy_refresh_token: dummy_refresh,
                    real_refresh_token: blob.refresh_token.clone(),
                    client_id: blob.client_id.clone(),
                    real_client_secret: blob.client_secret.clone(),
                    dummy_client_secret: dummy_secret,
                    account_id: account_id.clone(),
                });

                info!(
                    name = %config.name,
                    account = %account_id,
                    client_id = %blob.client_id,
                    "loaded gcloud user credential from credentials.db"
                );
            }

            Self::write_credentials_db(&dummy_db_path, &dummy_rows, &config.name)?;

            // Write empty access_tokens.db (gcloud expects it to exist)
            let dummy_access_db_path = dummy_dir.join("access_tokens.db");
            Self::write_empty_access_tokens_db(&dummy_access_db_path, &config.name)?;
        } else {
            debug!(
                name = %config.name,
                path = %credentials_db_path.display(),
                "credentials.db not found, skipping"
            );
        }

        // --- Read application_default_credentials.json ---
        let adc_path = real_dir.join("application_default_credentials.json");
        if adc_path.exists() {
            let adc_json = std::fs::read_to_string(&adc_path).with_context(|| {
                format!(
                    "gcp user credential '{}': failed to read '{}'",
                    config.name,
                    adc_path.display()
                )
            })?;

            let adc: ApplicationDefaultCredentials =
                serde_json::from_str(&adc_json).with_context(|| {
                    format!(
                        "gcp user credential '{}': failed to parse '{}'",
                        config.name,
                        adc_path.display()
                    )
                })?;

            let dummy_refresh = format!("ALICE_ADC_REFRESH_{}", mappings.len() + 1);
            let dummy_secret = format!("ALICE_ADC_SECRET_{}", mappings.len() + 1);

            mappings.push(RefreshTokenMapping {
                dummy_refresh_token: dummy_refresh.clone(),
                real_refresh_token: adc.refresh_token.clone(),
                client_id: adc.client_id.clone(),
                real_client_secret: adc.client_secret.clone(),
                dummy_client_secret: dummy_secret.clone(),
                account_id: "ADC".to_string(),
            });

            // Write dummy ADC
            let mut dummy_adc = adc;
            dummy_adc.refresh_token = dummy_refresh;
            dummy_adc.client_secret = dummy_secret;

            let dummy_adc_path = dummy_dir.join("application_default_credentials.json");
            let dummy_adc_json = serde_json::to_string_pretty(&dummy_adc).with_context(|| {
                format!(
                    "gcp user credential '{}': failed to serialize dummy ADC",
                    config.name
                )
            })?;
            std::fs::write(&dummy_adc_path, &dummy_adc_json).with_context(|| {
                format!(
                    "gcp user credential '{}': failed to write dummy ADC to '{}'",
                    config.name,
                    dummy_adc_path.display()
                )
            })?;

            info!(
                name = %config.name,
                "loaded application_default_credentials.json"
            );
        }

        // --- Write dummy properties file ---
        // gcloud CLI reads this for the active account and project.
        if let Some(ref account) = default_account {
            Self::write_properties_file(dummy_dir, account, &config.name)?;
        }

        if mappings.is_empty() {
            debug!(
                name = %config.name,
                path = %real_dir.display(),
                "no user credentials found, skipping"
            );
            return Ok(None);
        }

        info!(
            name = %config.name,
            mappings = mappings.len(),
            dummy_dir = %dummy_dir.display(),
            "loaded GCP user credentials"
        );

        Ok(Some(Self {
            name: config.name.clone(),
            mappings,
        }))
    }

    /// Read all accounts from gcloud's credentials.db.
    fn read_credentials_db(
        path: &std::path::Path,
        config_name: &str,
    ) -> Result<Vec<(String, GcloudCredentialBlob)>> {
        let conn =
            rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                .with_context(|| {
                    format!(
                        "gcp user credential '{}': failed to open credentials.db at '{}'",
                        config_name,
                        path.display()
                    )
                })?;

        let mut stmt = conn
            .prepare("SELECT account_id, value FROM credentials")
            .with_context(|| {
                format!(
                    "gcp user credential '{}': credentials.db has unexpected schema",
                    config_name
                )
            })?;

        let rows = stmt
            .query_map([], |row| {
                let account_id: String = row.get(0)?;
                let value: String = row.get(1)?;
                Ok((account_id, value))
            })
            .with_context(|| {
                format!(
                    "gcp user credential '{}': failed to query credentials.db",
                    config_name
                )
            })?;

        let mut results = Vec::new();
        for row in rows {
            let (account_id, value_json) = row.with_context(|| {
                format!(
                    "gcp user credential '{}': failed to read row from credentials.db",
                    config_name
                )
            })?;

            match serde_json::from_str::<GcloudCredentialBlob>(&value_json) {
                Ok(blob) => {
                    if blob.cred_type == "authorized_user" {
                        results.push((account_id, blob));
                    } else {
                        debug!(
                            name = %config_name,
                            account = %account_id,
                            cred_type = %blob.cred_type,
                            "skipping non-user credential in credentials.db"
                        );
                    }
                }
                Err(e) => {
                    warn!(
                        name = %config_name,
                        account = %account_id,
                        error = %e,
                        "failed to parse credential blob, skipping"
                    );
                }
            }
        }

        Ok(results)
    }

    /// Write a dummy credentials.db with the given rows.
    fn write_credentials_db(
        path: &std::path::Path,
        rows: &[(String, GcloudCredentialBlob)],
        config_name: &str,
    ) -> Result<()> {
        // Remove existing file if present (SQLite won't overwrite cleanly)
        if path.exists() {
            std::fs::remove_file(path).ok();
        }

        let conn = rusqlite::Connection::open(path).with_context(|| {
            format!(
                "gcp user credential '{}': failed to create dummy credentials.db at '{}'",
                config_name,
                path.display()
            )
        })?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS credentials (account_id TEXT PRIMARY KEY, value BLOB);",
        )
        .with_context(|| {
            format!(
                "gcp user credential '{}': failed to create credentials table",
                config_name
            )
        })?;

        for (account_id, blob) in rows {
            let value_json = serde_json::to_string(blob).with_context(|| {
                format!(
                    "gcp user credential '{}': failed to serialize credential for '{}'",
                    config_name, account_id
                )
            })?;

            conn.execute(
                "INSERT OR REPLACE INTO credentials (account_id, value) VALUES (?1, ?2)",
                rusqlite::params![account_id, value_json],
            )
            .with_context(|| {
                format!(
                    "gcp user credential '{}': failed to insert credential for '{}'",
                    config_name, account_id
                )
            })?;
        }

        debug!(
            name = %config_name,
            path = %path.display(),
            rows = rows.len(),
            "wrote dummy credentials.db"
        );

        Ok(())
    }

    /// Write an empty access_tokens.db (gcloud expects it).
    fn write_empty_access_tokens_db(path: &std::path::Path, config_name: &str) -> Result<()> {
        if path.exists() {
            std::fs::remove_file(path).ok();
        }

        let conn = rusqlite::Connection::open(path).with_context(|| {
            format!(
                "gcp user credential '{}': failed to create dummy access_tokens.db at '{}'",
                config_name,
                path.display()
            )
        })?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS access_tokens \
             (account_id TEXT PRIMARY KEY, access_token TEXT, \
              token_expiry TIMESTAMP, rapt_token TEXT, id_token TEXT);",
        )
        .with_context(|| {
            format!(
                "gcp user credential '{}': failed to create access_tokens table",
                config_name
            )
        })?;

        Ok(())
    }

    /// Write a minimal gcloud properties file so gcloud knows the active account.
    fn write_properties_file(
        dummy_dir: &std::path::Path,
        account: &str,
        config_name: &str,
    ) -> Result<()> {
        let properties_dir = dummy_dir.join("properties");

        // properties is a file, not a directory
        let content = format!("[core]\naccount = {}\n", account);

        std::fs::write(&properties_dir, &content).with_context(|| {
            format!(
                "gcp user credential '{}': failed to write properties file at '{}'",
                config_name,
                properties_dir.display()
            )
        })?;

        Ok(())
    }

    /// Try to swap a dummy refresh token in a token exchange POST body.
    ///
    /// The body is `application/x-www-form-urlencoded` with:
    ///   grant_type=refresh_token&client_id=...&client_secret=...&refresh_token=...
    ///
    /// Returns `Some(new_body)` if the refresh token was matched and swapped.
    pub fn swap_refresh_token(&self, body: &[u8]) -> Option<Vec<u8>> {
        let body_str = std::str::from_utf8(body).ok()?;

        let params: Vec<(String, String)> = url::form_urlencoded::parse(body_str.as_bytes())
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();

        // Check grant_type
        let grant_type = params.iter().find(|(k, _)| k == "grant_type")?;
        if grant_type.1 != REFRESH_TOKEN_GRANT_TYPE {
            return None;
        }

        // Extract refresh_token and client_id from the request
        let refresh_token = params.iter().find(|(k, _)| k == "refresh_token")?;
        let client_id_param = params.iter().find(|(k, _)| k == "client_id");

        // Find matching mapping
        for mapping in &self.mappings {
            if refresh_token.1 != mapping.dummy_refresh_token {
                continue;
            }

            // Verify client_id matches if present in the request
            if let Some(cid) = client_id_param {
                if cid.1 != mapping.client_id {
                    debug!(
                        expected_client_id = %mapping.client_id,
                        got_client_id = %cid.1,
                        "refresh token matched but client_id doesn't match, skipping"
                    );
                    continue;
                }
            }

            info!(
                name = %self.name,
                account = %mapping.account_id,
                "swapping dummy refresh token with real one"
            );

            // Rebuild the form body with real credentials
            let mut serializer = url::form_urlencoded::Serializer::new(String::new());
            for (k, v) in &params {
                match k.as_str() {
                    "refresh_token" => {
                        serializer.append_pair("refresh_token", &mapping.real_refresh_token);
                    }
                    "client_secret" if v == &mapping.dummy_client_secret => {
                        serializer.append_pair("client_secret", &mapping.real_client_secret);
                    }
                    _ => {
                        serializer.append_pair(k, v);
                    }
                }
            }

            return Some(serializer.finish().into_bytes());
        }

        None
    }
}

/// Collection of GCP service accounts and user accounts for the proxy.
pub struct GcpCredentialStore {
    accounts: Vec<GcpServiceAccount>,
    user_accounts: Vec<GcpUserAccount>,
}

impl GcpCredentialStore {
    /// Load all GCP credentials from config (both service accounts and user accounts).
    pub fn load(sa_configs: &[GcpCredential], user_configs: &[GcpUserCredential]) -> Result<Self> {
        let mut accounts = Vec::new();
        for config in sa_configs {
            accounts.push(GcpServiceAccount::load(config)?);
        }
        if !accounts.is_empty() {
            info!(
                count = accounts.len(),
                "loaded GCP service account credentials"
            );
        }

        let mut user_accounts = Vec::new();
        for config in user_configs {
            if let Some(account) = GcpUserAccount::load(config)? {
                user_accounts.push(account);
            }
        }
        if !user_accounts.is_empty() {
            info!(count = user_accounts.len(), "loaded GCP user credentials");
        }

        Ok(Self {
            accounts,
            user_accounts,
        })
    }

    /// Create an empty store (no GCP credentials configured).
    pub fn empty() -> Self {
        Self {
            accounts: Vec::new(),
            user_accounts: Vec::new(),
        }
    }

    /// Returns true if any GCP credentials are configured.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.accounts.is_empty() && self.user_accounts.is_empty()
    }

    /// Try to re-sign a JWT assertion or swap a refresh token in a token exchange POST body.
    ///
    /// First tries SA JWT re-signing, then user refresh token swapping.
    /// Returns `Some(new_body)` on the first match, or `None` if nothing matched.
    pub fn resign_token_request(&self, body: &[u8]) -> Option<Vec<u8>> {
        // Try service account JWT re-signing first
        for account in &self.accounts {
            if let Some(new_body) = account.resign_token_request(body) {
                return Some(new_body);
            }
        }
        // Try user account refresh token swapping
        for user_account in &self.user_accounts {
            if let Some(new_body) = user_account.swap_refresh_token(body) {
                return Some(new_body);
            }
        }
        None
    }

    /// Check if a request to the given host and path might be a GCP token exchange.
    ///
    /// This is a cheap pre-check to avoid parsing every POST body.
    pub fn is_gcp_token_request(&self, host: &str, path: &str) -> bool {
        let has_any = !self.accounts.is_empty() || !self.user_accounts.is_empty();
        has_any && host == GCP_TOKEN_HOST && path == "/token"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    /// Generate a test SA key file.
    fn write_test_sa_key(tmp: &mut NamedTempFile) -> RsaPrivateKey {
        let mut rng = rand::thread_rng();
        let key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let pem = key.to_pkcs1_pem(LineEnding::LF).unwrap();

        let sa_json = serde_json::json!({
            "type": "service_account",
            "project_id": "test-project",
            "private_key_id": "real-key-id-123",
            "private_key": pem.to_string(),
            "client_email": "test@test-project.iam.gserviceaccount.com",
            "client_id": "123456789",
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
            "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/test%40test-project.iam.gserviceaccount.com"
        });

        write!(tmp, "{}", serde_json::to_string_pretty(&sa_json).unwrap()).unwrap();
        key
    }

    #[test]
    fn test_load_and_generate_dummy_key() {
        let mut real_key_file = NamedTempFile::new().unwrap();
        write_test_sa_key(&mut real_key_file);

        let dummy_key_path = tempfile::NamedTempFile::new().unwrap();

        let config = GcpCredential {
            name: "test-gcp".to_string(),
            key_file: real_key_file.path().to_path_buf(),
            dummy_key_path: dummy_key_path.path().to_path_buf(),
            scope: "https://www.googleapis.com/auth/cloud-platform".to_string(),
        };

        let sa = GcpServiceAccount::load(&config).unwrap();
        assert_eq!(sa.client_email, "test@test-project.iam.gserviceaccount.com");

        // Verify the dummy key file was written and is valid JSON
        let dummy_json = std::fs::read_to_string(dummy_key_path.path()).unwrap();
        let dummy_key: ServiceAccountKey = serde_json::from_str(&dummy_json).unwrap();
        assert_eq!(dummy_key.key_type, "service_account");
        assert_eq!(
            dummy_key.client_email,
            "test@test-project.iam.gserviceaccount.com"
        );
        assert_eq!(dummy_key.private_key_id, "alice-dummy-test-gcp");
        // Dummy key should be different from the real key
        assert!(dummy_key.private_key.contains("BEGIN RSA PRIVATE KEY"));
    }

    #[test]
    fn test_resign_jwt_assertion() {
        let mut real_key_file = NamedTempFile::new().unwrap();
        write_test_sa_key(&mut real_key_file);

        let dummy_key_path = tempfile::NamedTempFile::new().unwrap();

        let config = GcpCredential {
            name: "test-gcp".to_string(),
            key_file: real_key_file.path().to_path_buf(),
            dummy_key_path: dummy_key_path.path().to_path_buf(),
            scope: "https://www.googleapis.com/auth/cloud-platform".to_string(),
        };

        let sa = GcpServiceAccount::load(&config).unwrap();

        // Read the dummy key file and sign a JWT with it (simulating what Bob's gcloud does)
        let dummy_json = std::fs::read_to_string(dummy_key_path.path()).unwrap();
        let dummy_key: ServiceAccountKey = serde_json::from_str(&dummy_json).unwrap();

        let dummy_encoding_key =
            EncodingKey::from_rsa_pem(dummy_key.private_key.as_bytes()).unwrap();

        let claims = GcpJwtClaims {
            iss: "test@test-project.iam.gserviceaccount.com".to_string(),
            scope: Some("https://www.googleapis.com/auth/cloud-platform".to_string()),
            aud: "https://oauth2.googleapis.com/token".to_string(),
            iat: chrono::Utc::now().timestamp(),
            exp: chrono::Utc::now().timestamp() + 3600,
            sub: None,
        };

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("alice-dummy-test-gcp".to_string());

        let bob_jwt = encode(&header, &claims, &dummy_encoding_key).unwrap();

        // Build the form body like gcloud would
        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", JWT_BEARER_GRANT_TYPE)
            .append_pair("assertion", &bob_jwt)
            .finish();

        // Alice should re-sign it
        let result = sa.resign_token_request(body.as_bytes());
        assert!(result.is_some(), "should have re-signed the JWT");

        let new_body = String::from_utf8(result.unwrap()).unwrap();
        // Should still be form-urlencoded with the same grant_type
        assert!(new_body.contains("grant_type="));
        assert!(new_body.contains("assertion="));
        // The assertion should be different (re-signed with real key)
        assert!(!new_body.contains(&bob_jwt));
    }

    #[test]
    fn test_reject_jwt_signed_with_wrong_key() {
        let mut real_key_file = NamedTempFile::new().unwrap();
        write_test_sa_key(&mut real_key_file);

        let dummy_key_path = tempfile::NamedTempFile::new().unwrap();

        let config = GcpCredential {
            name: "test-gcp".to_string(),
            key_file: real_key_file.path().to_path_buf(),
            dummy_key_path: dummy_key_path.path().to_path_buf(),
            scope: "https://www.googleapis.com/auth/cloud-platform".to_string(),
        };

        let sa = GcpServiceAccount::load(&config).unwrap();

        // Sign a JWT with a completely different key (an attacker's key)
        let mut rng = rand::thread_rng();
        let attacker_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let attacker_pem = attacker_key.to_pkcs1_pem(LineEnding::LF).unwrap();
        let attacker_encoding_key = EncodingKey::from_rsa_pem(attacker_pem.as_bytes()).unwrap();

        let claims = GcpJwtClaims {
            iss: "test@test-project.iam.gserviceaccount.com".to_string(),
            scope: Some("https://www.googleapis.com/auth/cloud-platform".to_string()),
            aud: "https://oauth2.googleapis.com/token".to_string(),
            iat: chrono::Utc::now().timestamp(),
            exp: chrono::Utc::now().timestamp() + 3600,
            sub: None,
        };

        let header = Header::new(Algorithm::RS256);
        let attacker_jwt = encode(&header, &claims, &attacker_encoding_key).unwrap();

        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", JWT_BEARER_GRANT_TYPE)
            .append_pair("assertion", &attacker_jwt)
            .finish();

        // Alice should reject it — signature doesn't match the dummy key
        let result = sa.resign_token_request(body.as_bytes());
        assert!(
            result.is_none(),
            "should have rejected JWT signed with wrong key"
        );
    }

    #[test]
    fn test_ignore_non_jwt_bearer_grant() {
        let mut real_key_file = NamedTempFile::new().unwrap();
        write_test_sa_key(&mut real_key_file);

        let dummy_key_path = tempfile::NamedTempFile::new().unwrap();

        let config = GcpCredential {
            name: "test-gcp".to_string(),
            key_file: real_key_file.path().to_path_buf(),
            dummy_key_path: dummy_key_path.path().to_path_buf(),
            scope: "https://www.googleapis.com/auth/cloud-platform".to_string(),
        };

        let sa = GcpServiceAccount::load(&config).unwrap();

        // A refresh_token grant (not a JWT bearer assertion)
        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "refresh_token")
            .append_pair("refresh_token", "1//0eXYZ...")
            .append_pair("client_id", "764086051850-6qr4p6gpi6hn...")
            .append_pair("client_secret", "d-FL95Q19q7MQmFp...")
            .finish();

        let result = sa.resign_token_request(body.as_bytes());
        assert!(result.is_none(), "should ignore non-JWT-bearer grant types");
    }

    #[test]
    fn test_gcp_credential_store() {
        let mut real_key_file = NamedTempFile::new().unwrap();
        write_test_sa_key(&mut real_key_file);

        let dummy_key_path = tempfile::NamedTempFile::new().unwrap();

        let configs = vec![GcpCredential {
            name: "test-gcp".to_string(),
            key_file: real_key_file.path().to_path_buf(),
            dummy_key_path: dummy_key_path.path().to_path_buf(),
            scope: "https://www.googleapis.com/auth/cloud-platform".to_string(),
        }];

        let store = GcpCredentialStore::load(&configs, &[]).unwrap();
        assert!(!store.is_empty());
        assert!(store.is_gcp_token_request("oauth2.googleapis.com", "/token"));
        assert!(!store.is_gcp_token_request("other.com", "/token"));
        assert!(!store.is_gcp_token_request("oauth2.googleapis.com", "/other"));
    }

    #[test]
    fn test_empty_store() {
        let store = GcpCredentialStore::empty();
        assert!(store.is_empty());
        assert!(!store.is_gcp_token_request("oauth2.googleapis.com", "/token"));
    }

    // --- User credential tests ---

    /// Create a test gcloud config directory with a credentials.db.
    fn write_test_credentials_db(dir: &std::path::Path, accounts: &[(&str, &str, &str, &str)]) {
        let db_path = dir.join("credentials.db");
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS credentials (account_id TEXT PRIMARY KEY, value BLOB);",
        )
        .unwrap();

        for (account_id, client_id, client_secret, refresh_token) in accounts {
            let blob = serde_json::json!({
                "type": "authorized_user",
                "client_id": client_id,
                "client_secret": client_secret,
                "refresh_token": refresh_token,
                "token_uri": "https://oauth2.googleapis.com/token"
            });
            conn.execute(
                "INSERT INTO credentials (account_id, value) VALUES (?1, ?2)",
                rusqlite::params![account_id, blob.to_string()],
            )
            .unwrap();
        }
    }

    #[test]
    fn test_load_user_credentials_from_db() {
        let real_dir = tempfile::tempdir().unwrap();
        let dummy_dir = tempfile::tempdir().unwrap();

        write_test_credentials_db(
            real_dir.path(),
            &[(
                "user@example.com",
                "32555940559.apps.googleusercontent.com",
                "real-client-secret",
                "1//0eRealRefreshToken",
            )],
        );

        let config = GcpUserCredential {
            name: "test-user".to_string(),
            gcloud_config_dir: real_dir.path().to_path_buf(),
            dummy_config_dir: dummy_dir.path().to_path_buf(),
        };

        let user = GcpUserAccount::load(&config)
            .unwrap()
            .expect("should find credentials");
        assert_eq!(user.name, "test-user");
        assert_eq!(user.mappings.len(), 1);

        // Verify dummy credentials.db was written
        let dummy_db = dummy_dir.path().join("credentials.db");
        assert!(dummy_db.exists());

        // Read back the dummy db and verify the refresh token is replaced
        let conn = rusqlite::Connection::open(&dummy_db).unwrap();
        let dummy_value: String = conn
            .query_row(
                "SELECT value FROM credentials WHERE account_id = ?1",
                ["user@example.com"],
                |row| row.get(0),
            )
            .unwrap();
        let dummy_blob: serde_json::Value = serde_json::from_str(&dummy_value).unwrap();
        assert_eq!(dummy_blob["refresh_token"], "ALICE_USER_REFRESH_1");
        assert_eq!(dummy_blob["client_secret"], "ALICE_CLIENT_SECRET_1");
        // client_id should be preserved
        assert_eq!(
            dummy_blob["client_id"],
            "32555940559.apps.googleusercontent.com"
        );

        // Verify properties file was written
        let props = std::fs::read_to_string(dummy_dir.path().join("properties")).unwrap();
        assert!(props.contains("user@example.com"));
    }

    #[test]
    fn test_swap_refresh_token() {
        let real_dir = tempfile::tempdir().unwrap();
        let dummy_dir = tempfile::tempdir().unwrap();

        write_test_credentials_db(
            real_dir.path(),
            &[(
                "user@example.com",
                "32555940559.apps.googleusercontent.com",
                "real-secret",
                "1//0eRealRefresh",
            )],
        );

        let config = GcpUserCredential {
            name: "test-user".to_string(),
            gcloud_config_dir: real_dir.path().to_path_buf(),
            dummy_config_dir: dummy_dir.path().to_path_buf(),
        };

        let user = GcpUserAccount::load(&config).unwrap().unwrap();

        // Build a refresh token request like gcloud would, using the dummy token
        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "refresh_token")
            .append_pair("client_id", "32555940559.apps.googleusercontent.com")
            .append_pair("client_secret", "ALICE_CLIENT_SECRET_1")
            .append_pair("refresh_token", "ALICE_USER_REFRESH_1")
            .finish();

        let result = user.swap_refresh_token(body.as_bytes());
        assert!(result.is_some(), "should have swapped the refresh token");

        let new_body = String::from_utf8(result.unwrap()).unwrap();
        let params: Vec<(String, String)> = url::form_urlencoded::parse(new_body.as_bytes())
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();

        // Verify real credentials were substituted
        let refresh = params.iter().find(|(k, _)| k == "refresh_token").unwrap();
        assert_eq!(refresh.1, "1//0eRealRefresh");

        let secret = params.iter().find(|(k, _)| k == "client_secret").unwrap();
        assert_eq!(secret.1, "real-secret");

        // client_id should be unchanged
        let cid = params.iter().find(|(k, _)| k == "client_id").unwrap();
        assert_eq!(cid.1, "32555940559.apps.googleusercontent.com");
    }

    #[test]
    fn test_swap_ignores_wrong_refresh_token() {
        let real_dir = tempfile::tempdir().unwrap();
        let dummy_dir = tempfile::tempdir().unwrap();

        write_test_credentials_db(
            real_dir.path(),
            &[(
                "user@example.com",
                "32555940559.apps.googleusercontent.com",
                "real-secret",
                "1//0eRealRefresh",
            )],
        );

        let config = GcpUserCredential {
            name: "test-user".to_string(),
            gcloud_config_dir: real_dir.path().to_path_buf(),
            dummy_config_dir: dummy_dir.path().to_path_buf(),
        };

        let user = GcpUserAccount::load(&config).unwrap().unwrap();

        // Use a wrong refresh token
        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "refresh_token")
            .append_pair("client_id", "32555940559.apps.googleusercontent.com")
            .append_pair("client_secret", "some-secret")
            .append_pair("refresh_token", "WRONG_TOKEN")
            .finish();

        let result = user.swap_refresh_token(body.as_bytes());
        assert!(result.is_none(), "should not swap unknown refresh token");
    }

    #[test]
    fn test_swap_ignores_jwt_bearer_grant() {
        let real_dir = tempfile::tempdir().unwrap();
        let dummy_dir = tempfile::tempdir().unwrap();

        write_test_credentials_db(
            real_dir.path(),
            &[(
                "user@example.com",
                "32555940559.apps.googleusercontent.com",
                "real-secret",
                "1//0eRealRefresh",
            )],
        );

        let config = GcpUserCredential {
            name: "test-user".to_string(),
            gcloud_config_dir: real_dir.path().to_path_buf(),
            dummy_config_dir: dummy_dir.path().to_path_buf(),
        };

        let user = GcpUserAccount::load(&config).unwrap().unwrap();

        // JWT bearer grant (handled by SA flow, not user flow)
        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", JWT_BEARER_GRANT_TYPE)
            .append_pair("assertion", "eyJhbGciOiJSUzI1NiJ9.xxx.yyy")
            .finish();

        let result = user.swap_refresh_token(body.as_bytes());
        assert!(result.is_none(), "should ignore JWT bearer grants");
    }

    #[test]
    fn test_load_user_credentials_with_adc() {
        let real_dir = tempfile::tempdir().unwrap();
        let dummy_dir = tempfile::tempdir().unwrap();

        // Write ADC file (no credentials.db needed for this test)
        let adc = serde_json::json!({
            "type": "authorized_user",
            "client_id": "764086051850-6qr4p6gpi6hn506pt8ejuq83di341hur.apps.googleusercontent.com", // trufflehog:ignore (Google's public gcloud CLI OAuth client ID)
            "client_secret": "d-FL95Q19q7MQmFpd7hHD0Ty",
            "refresh_token": "1//0eADCRealRefresh",
            "quota_project_id": "my-project"
        });
        std::fs::write(
            real_dir.path().join("application_default_credentials.json"),
            serde_json::to_string_pretty(&adc).unwrap(),
        )
        .unwrap();

        let config = GcpUserCredential {
            name: "test-adc".to_string(),
            gcloud_config_dir: real_dir.path().to_path_buf(),
            dummy_config_dir: dummy_dir.path().to_path_buf(),
        };

        let user = GcpUserAccount::load(&config).unwrap().unwrap();
        assert_eq!(user.mappings.len(), 1);
        assert_eq!(user.mappings[0].account_id, "ADC");

        // Verify dummy ADC was written
        let dummy_adc_path = dummy_dir
            .path()
            .join("application_default_credentials.json");
        assert!(dummy_adc_path.exists());

        let dummy_adc_json = std::fs::read_to_string(&dummy_adc_path).unwrap();
        let dummy_adc: serde_json::Value = serde_json::from_str(&dummy_adc_json).unwrap();
        assert!(dummy_adc["refresh_token"]
            .as_str()
            .unwrap()
            .starts_with("ALICE_ADC_REFRESH_"));
        assert!(dummy_adc["client_secret"]
            .as_str()
            .unwrap()
            .starts_with("ALICE_ADC_SECRET_"));
        // quota_project_id should be preserved
        assert_eq!(dummy_adc["quota_project_id"], "my-project");
    }

    #[test]
    fn test_store_with_user_credentials() {
        let real_dir = tempfile::tempdir().unwrap();
        let dummy_dir = tempfile::tempdir().unwrap();

        write_test_credentials_db(
            real_dir.path(),
            &[(
                "user@example.com",
                "32555940559.apps.googleusercontent.com",
                "real-secret",
                "1//0eRealRefresh",
            )],
        );

        let user_configs = vec![GcpUserCredential {
            name: "test-user".to_string(),
            gcloud_config_dir: real_dir.path().to_path_buf(),
            dummy_config_dir: dummy_dir.path().to_path_buf(),
        }];

        // No SA credentials, only user credentials
        let store = GcpCredentialStore::load(&[], &user_configs).unwrap();
        assert!(!store.is_empty());
        assert!(store.is_gcp_token_request("oauth2.googleapis.com", "/token"));

        // Should swap refresh tokens via the store
        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "refresh_token")
            .append_pair("client_id", "32555940559.apps.googleusercontent.com")
            .append_pair("client_secret", "ALICE_CLIENT_SECRET_1")
            .append_pair("refresh_token", "ALICE_USER_REFRESH_1")
            .finish();

        let result = store.resign_token_request(body.as_bytes());
        assert!(result.is_some(), "store should swap refresh token");
    }
}
