//! TLS StreamLayer implementation

use async_trait::async_trait;
use std::sync::Arc;
use std::fs::File;
use std::io::BufReader;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::rustls::{self, pki_types::ServerName, ClientConfig, RootCertStore, ServerConfig};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::{TlsConnector, TlsAcceptor};

use crate::common::{Result, Stream};
use crate::error::Error;

use super::StreamLayer;

/// TLS configuration
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// Server name for SNI
    pub server_name: Option<String>,
    /// Allow insecure certificates
    pub allow_insecure: bool,
    /// ALPN protocols
    pub alpn: Vec<String>,
    /// Certificate file path (for server)
    pub certificate_file: Option<String>,
    /// Private key file path (for server)
    pub key_file: Option<String>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            server_name: None,
            allow_insecure: false,
            alpn: vec![],
            certificate_file: None,
            key_file: None,
        }
    }
}

/// TLS wrapper for encrypting streams
pub struct TlsWrapper {
    config: TlsConfig,
    connector: TlsConnector,
    acceptor: Option<TlsAcceptor>,
}

impl TlsWrapper {
    pub fn new(config: TlsConfig) -> Self {
        let connector = Self::build_connector(&config);
        let acceptor = Self::build_acceptor(&config);
        Self { config, connector, acceptor }
    }

    fn build_connector(config: &TlsConfig) -> TlsConnector {
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let mut tls_config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        if !config.alpn.is_empty() {
            tls_config.alpn_protocols = config
                .alpn
                .iter()
                .map(|s| s.as_bytes().to_vec())
                .collect();
        }

        if config.allow_insecure {
            tls_config
                .dangerous()
                .set_certificate_verifier(Arc::new(InsecureVerifier));
        }

        TlsConnector::from(Arc::new(tls_config))
    }

    fn build_acceptor(config: &TlsConfig) -> Option<TlsAcceptor> {
        let cert_file = config.certificate_file.as_ref()?;
        let key_file = config.key_file.as_ref()?;

        let certs = Self::load_certs(cert_file).ok()?;
        let key = Self::load_private_key(key_file).ok()?;

        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .ok()?;

        Some(TlsAcceptor::from(Arc::new(server_config)))
    }

    fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
        let file = File::open(path)
            .map_err(|e| Error::Config(format!("Failed to open certificate file {}: {}", path, e)))?;
        let mut reader = BufReader::new(file);
        let certs = rustls_pemfile::certs(&mut reader)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Config(format!("Failed to parse certificates: {}", e)))?;
        Ok(certs)
    }

    fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>> {
        let file = File::open(path)
            .map_err(|e| Error::Config(format!("Failed to open key file {}: {}", path, e)))?;
        let mut reader = BufReader::new(file);
        
        let keys = rustls_pemfile::read_all(&mut reader)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Config(format!("Failed to parse private key: {}", e)))?;
        
        for item in keys {
            match item {
                rustls_pemfile::Item::Pkcs8Key(key) => return Ok(PrivateKeyDer::Pkcs8(key)),
                rustls_pemfile::Item::Pkcs1Key(key) => return Ok(PrivateKeyDer::Pkcs1(key)),
                rustls_pemfile::Item::Sec1Key(key) => return Ok(PrivateKeyDer::Sec1(key)),
                _ => continue,
            }
        }
        
        Err(Error::Config("No valid private key found in file".into()))
    }
}

#[async_trait]
impl StreamLayer for TlsWrapper {
    async fn wrap_client(&self, stream: Stream) -> Result<Stream> {
        let server_name = self
            .config
            .server_name
            .as_ref()
            .ok_or_else(|| Error::Config("TLS server name required".into()))?;

        let domain = ServerName::try_from(server_name.clone())
            .map_err(|_| Error::Config(format!("Invalid server name: {}", server_name)))?;

        let tls_stream = self.connector.connect(domain, BoxedStreamWrapper(stream)).await?;
        Ok(Box::new(tls_stream))
    }

    async fn wrap_server(&self, stream: Stream) -> Result<Stream> {
        let acceptor = self.acceptor.as_ref()
            .ok_or_else(|| Error::Config("TLS server requires certificate_file and key_file".into()))?;
        
        let tls_stream = acceptor.accept(BoxedStreamWrapper(stream)).await?;
        Ok(Box::new(tls_stream))
    }
}

/// Wrapper to make boxed Stream work with tokio-rustls
struct BoxedStreamWrapper(Stream);

impl AsyncRead for BoxedStreamWrapper {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for BoxedStreamWrapper {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut *self.0).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.0).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.0).poll_shutdown(cx)
    }
}

/// Insecure certificate verifier for testing
#[derive(Debug)]
struct InsecureVerifier;

impl rustls::client::danger::ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}
