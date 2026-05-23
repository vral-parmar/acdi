#![forbid(unsafe_code)]

//! Async TLS handshake probe using rustls.
//!
//! Connects to a host:port, captures the negotiated protocol version,
//! cipher suite, and peer certificate chain for crypto-asset extraction.

use std::sync::Arc;

use anyhow::{Context, Result};
use rustls::{ClientConfig, ClientConnection, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use tokio_rustls::TlsConnector;

/// Summary of a completed TLS handshake.
#[derive(Debug, Clone)]
pub struct TlsHandshakeResult {
    pub host: String,
    pub port: u16,
    pub tls_version: String,
    pub cipher_suite: String,
    /// DER-encoded peer certificates (leaf first).
    pub peer_certs: Vec<Vec<u8>>,
    /// True if PQC hybrid was detected (set by pqc module).
    pub pqc_hybrid: bool,
    pub error: Option<String>,
}

impl TlsHandshakeResult {
    fn failed(host: String, port: u16, err: String) -> Self {
        TlsHandshakeResult {
            host,
            port,
            tls_version: String::new(),
            cipher_suite: String::new(),
            peer_certs: vec![],
            pqc_hybrid: false,
            error: Some(err),
        }
    }
}

fn build_client_config() -> Result<Arc<ClientConfig>> {
    // rustls 0.23 requires an explicit CryptoProvider. Install ring if none is set yet.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Ok(Arc::new(config))
}

/// Probe a single TLS endpoint. Never panics — errors are returned in the result struct.
pub async fn probe(
    host: &str,
    port: u16,
    timeout_secs: u64,
) -> TlsHandshakeResult {
    match probe_inner(host, port, timeout_secs).await {
        Ok(r) => r,
        Err(e) => TlsHandshakeResult::failed(host.to_string(), port, e.to_string()),
    }
}

async fn probe_inner(
    host: &str,
    port: u16,
    timeout_secs: u64,
) -> Result<TlsHandshakeResult> {
    let config = build_client_config().context("building TLS config")?;
    let connector = TlsConnector::from(config);

    let addr = format!("{host}:{port}");
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
        .context("invalid server name")?;

    let tcp = timeout(Duration::from_secs(timeout_secs), TcpStream::connect(&addr))
        .await
        .with_context(|| format!("TCP connect to {addr} timed out"))?
        .with_context(|| format!("TCP connect to {addr} failed"))?;

    let mut tls = timeout(
        Duration::from_secs(timeout_secs),
        connector.connect(server_name, tcp),
    )
    .await
    .with_context(|| format!("TLS handshake to {addr} timed out"))?
    .with_context(|| format!("TLS handshake to {addr} failed"))?;

    // Send minimal HTTP/1.1 request to flush the handshake and get cert chain.
    let request = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    let _ = tls.write_all(request.as_bytes()).await;

    // Read a small response — we only care about the handshake metadata.
    let mut buf = [0u8; 256];
    let _ = timeout(Duration::from_secs(2), tls.read(&mut buf)).await;

    let (_, conn) = tls.get_ref();
    let tls_version = negotiated_version(conn);
    let cipher_suite = negotiated_cipher(conn);
    let peer_certs = peer_certificates(conn);

    Ok(TlsHandshakeResult {
        host: host.to_string(),
        port,
        tls_version,
        cipher_suite,
        peer_certs,
        pqc_hybrid: false,
        error: None,
    })
}

fn negotiated_version(conn: &ClientConnection) -> String {
    conn.protocol_version()
        .map(|v| format!("{v:?}"))
        .unwrap_or_else(|| "unknown".to_string())
}

fn negotiated_cipher(conn: &ClientConnection) -> String {
    conn.negotiated_cipher_suite()
        .map(|cs| format!("{:?}", cs.suite()))
        .unwrap_or_else(|| "unknown".to_string())
}

fn peer_certificates(conn: &ClientConnection) -> Vec<Vec<u8>> {
    conn.peer_certificates()
        .map(|certs| certs.iter().map(|c| c.as_ref().to_vec()).collect())
        .unwrap_or_default()
}

/// Parse a `host:port` string. Port defaults to 443 if omitted.
pub fn parse_target(target: &str) -> Result<(String, u16)> {
    if let Some((host, port_str)) = target.rsplit_once(':') {
        let port: u16 = port_str
            .parse()
            .with_context(|| format!("invalid port in '{target}'"))?;
        Ok((host.to_string(), port))
    } else {
        Ok((target.to_string(), 443))
    }
}
