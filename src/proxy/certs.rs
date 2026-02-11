use anyhow::{Context, Result};
use moka::future::Cache;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;

/// Generated certificate and key pair for a host (stores raw bytes for Clone)
#[derive(Clone)]
pub struct HostCert {
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
}

impl HostCert {
    pub fn cert(&self) -> CertificateDer<'static> {
        CertificateDer::from(self.cert_der.clone())
    }

    pub fn key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key_der.clone()))
    }
}

/// Certificate authority for generating per-host certificates
pub struct CertificateAuthority {
    ca_cert: rcgen::Certificate,
    #[allow(dead_code)] // Accessible via ca_cert_der() for future use
    ca_cert_der: CertificateDer<'static>,
    ca_key: KeyPair,
    host_cert_validity_hours: u32,
    cache: Cache<String, Arc<HostCert>>,
}

impl CertificateAuthority {
    pub fn new(ca_validity_hours: u32, host_cert_validity_hours: u32) -> Result<Self> {
        let ca_key = KeyPair::generate()?;

        let mut ca_params = CertificateParams::default();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Alice Proxy CA");
        ca_params
            .distinguished_name
            .push(DnType::OrganizationName, "Alice");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

        let now = OffsetDateTime::now_utc();
        ca_params.not_before = now;
        ca_params.not_after = now + Duration::from_secs(ca_validity_hours as u64 * 3600);

        let ca_cert = ca_params.self_signed(&ca_key)?;
        let ca_cert_der = CertificateDer::from(ca_cert.der().to_vec());

        let cache_ttl = Duration::from_secs((host_cert_validity_hours as u64 * 3600) - 300);
        let cache = Cache::builder()
            .max_capacity(1000)
            .time_to_live(cache_ttl)
            .build();

        Ok(Self {
            ca_cert,
            ca_cert_der,
            ca_key,
            host_cert_validity_hours,
            cache,
        })
    }

    pub fn write_ca_cert(&self, path: &Path) -> Result<()> {
        let pem = self.ca_cert.pem();
        std::fs::write(path, pem)
            .with_context(|| format!("failed to write CA certificate to {}", path.display()))?;
        Ok(())
    }

    #[allow(dead_code)] // Will be used for client cert distribution
    pub fn ca_cert_der(&self) -> &CertificateDer<'static> {
        &self.ca_cert_der
    }

    pub async fn get_or_create_cert(&self, host: &str) -> Result<Arc<HostCert>> {
        if let Some(cert) = self.cache.get(host).await {
            return Ok(cert);
        }

        let cert = self.generate_host_cert(host)?;
        let cert = Arc::new(cert);
        self.cache.insert(host.to_string(), Arc::clone(&cert)).await;
        Ok(cert)
    }

    fn generate_host_cert(&self, host: &str) -> Result<HostCert> {
        let key = KeyPair::generate()?;

        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, host);
        params.subject_alt_names = vec![SanType::DnsName(host.try_into()?)];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

        let now = OffsetDateTime::now_utc();
        params.not_before = now;
        params.not_after = now + Duration::from_secs(self.host_cert_validity_hours as u64 * 3600);

        let cert = params.signed_by(&key, &self.ca_cert, &self.ca_key)?;

        Ok(HostCert {
            cert_der: cert.der().to_vec(),
            key_der: key.serialize_der(),
        })
    }
}
