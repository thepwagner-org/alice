use crate::proxy::certs::{CertificateAuthority, HostCert};
use anyhow::{Context, Result};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::debug;

/// ALPN protocols we support, in order of preference
const ALPN_PROTOCOLS: &[&[u8]] = &[b"h2", b"http/1.1"];

/// ALPN for HTTP/1.1 only (used when client negotiated HTTP/1.1,
/// to avoid protocol mismatch with upstream)
const ALPN_HTTP1_ONLY: &[&[u8]] = &[b"http/1.1"];

/// Negotiated protocol after TLS handshake
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NegotiatedProtocol {
    H2,
    Http1,
}

/// Get the crypto provider (ring)
fn crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Create a TLS server config for MITM with the given host certificate
pub fn server_config_for_host(cert: &HostCert) -> Result<ServerConfig> {
    let mut config = ServerConfig::builder_with_provider(crypto_provider())
        .with_safe_default_protocol_versions()
        .context("failed to set protocol versions")?
        .with_no_client_auth()
        .with_single_cert(vec![cert.cert()], cert.key())
        .context("failed to create server config")?;

    config.alpn_protocols = ALPN_PROTOCOLS.iter().map(|p| p.to_vec()).collect();

    Ok(config)
}

/// Create a TLS client config for connecting to upstream servers.
/// When the client negotiated HTTP/1.1, we only offer HTTP/1.1 to upstream
/// to avoid a protocol mismatch (sending H1.1 bytes over an h2 connection).
pub fn client_config(
    additional_ca: Option<&Path>,
    client_proto: NegotiatedProtocol,
) -> Result<ClientConfig> {
    let mut root_store = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    // Load additional CA certificates if provided
    if let Some(ca_path) = additional_ca {
        let pem_data = std::fs::read(ca_path)
            .with_context(|| format!("failed to read {}", ca_path.display()))?;
        let mut cursor = std::io::Cursor::new(&pem_data);
        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cursor)
            .filter_map(|r| r.ok())
            .collect();
        for cert in certs {
            root_store
                .add(cert)
                .context("failed to add upstream CA certificate")?;
        }
    }

    let mut config = ClientConfig::builder_with_provider(crypto_provider())
        .with_safe_default_protocol_versions()
        .context("failed to set protocol versions")?
        .with_root_certificates(root_store)
        .with_no_client_auth();

    // Match upstream ALPN to client's negotiated protocol to prevent mismatch.
    // If client chose HTTP/1.1, only offer HTTP/1.1 to upstream so we don't
    // end up trying to send H1.1 bytes over an h2 connection.
    config.alpn_protocols = match client_proto {
        NegotiatedProtocol::H2 => ALPN_PROTOCOLS,
        NegotiatedProtocol::Http1 => ALPN_HTTP1_ONLY,
    }
    .iter()
    .map(|p| p.to_vec())
    .collect();

    Ok(config)
}

/// Perform TLS handshake with client using forged certificate.
/// Returns the TLS stream and the negotiated protocol.
pub async fn accept_client_tls<S>(
    stream: S,
    ca: &CertificateAuthority,
    host: &str,
) -> Result<(tokio_rustls::server::TlsStream<S>, NegotiatedProtocol)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let cert = ca.get_or_create_cert(host).await?;
    let config = server_config_for_host(&cert)?;
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let tls_stream = acceptor
        .accept(stream)
        .await
        .context("TLS handshake with client failed")?;

    let alpn = tls_stream.get_ref().1.alpn_protocol();
    debug!(alpn = ?alpn, "client ALPN negotiated");
    let protocol = match alpn {
        Some(b"h2") => NegotiatedProtocol::H2,
        _ => NegotiatedProtocol::Http1,
    };

    Ok((tls_stream, protocol))
}

/// Connect to upstream server with TLS.
/// Returns the TLS stream and the negotiated protocol.
/// `client_proto` is used to constrain ALPN: if the client negotiated HTTP/1.1,
/// we only offer HTTP/1.1 to upstream to prevent protocol mismatch.
pub async fn connect_upstream_tls(
    stream: TcpStream,
    host: &str,
    upstream_ca: Option<&Path>,
    client_proto: NegotiatedProtocol,
) -> Result<(
    tokio_rustls::client::TlsStream<TcpStream>,
    NegotiatedProtocol,
)> {
    let config = client_config(upstream_ca, client_proto)?;
    let connector = TlsConnector::from(Arc::new(config));

    let server_name = ServerName::try_from(host.to_string())
        .map_err(|_| anyhow::anyhow!("invalid server name: {}", host))?;

    let tls_stream = connector
        .connect(server_name, stream)
        .await
        .context("TLS handshake with upstream failed")?;

    let alpn = tls_stream.get_ref().1.alpn_protocol();
    debug!(alpn = ?alpn, "upstream ALPN negotiated");
    let protocol = match alpn {
        Some(b"h2") => NegotiatedProtocol::H2,
        _ => NegotiatedProtocol::Http1,
    };

    Ok((tls_stream, protocol))
}
