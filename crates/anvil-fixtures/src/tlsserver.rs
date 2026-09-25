//! Server-side TLS configuration for fixtures.

use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::Arc;

#[derive(Clone, Debug)]
pub enum ClientAuth {
    None,
    /// Request a client certificate; accept connections without one.
    Optional {
        ca_pem: String,
    },
    /// Require a client certificate chaining to `ca_pem`.
    Required {
        ca_pem: String,
    },
}

#[derive(Clone, Debug)]
pub struct TlsServerOptions {
    pub cert_chain_pem: String,
    pub key_pem: String,
    pub client_auth: ClientAuth,
    pub alpn: Vec<String>,
    pub tls13_only: bool,
    pub tls12_only: bool,
}

impl TlsServerOptions {
    pub fn new(cert_chain_pem: impl Into<String>, key_pem: impl Into<String>) -> Self {
        TlsServerOptions {
            cert_chain_pem: cert_chain_pem.into(),
            key_pem: key_pem.into(),
            client_auth: ClientAuth::None,
            alpn: vec!["h2".into(), "http/1.1".into()],
            tls13_only: false,
            tls12_only: false,
        }
    }
}

pub fn certs(pem: &str) -> Vec<CertificateDer<'static>> {
    rustls_pemfile::certs(&mut pem.as_bytes())
        .filter_map(Result::ok)
        .collect()
}

pub fn key(pem: &str) -> PrivateKeyDer<'static> {
    rustls_pemfile::private_key(&mut pem.as_bytes())
        .ok()
        .flatten()
        .expect("fixture private key")
}

pub fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

pub fn server_config(opts: &TlsServerOptions) -> anyhow::Result<Arc<ServerConfig>> {
    let versions: &[&'static rustls::SupportedProtocolVersion] = if opts.tls13_only {
        &[&rustls::version::TLS13]
    } else if opts.tls12_only {
        &[&rustls::version::TLS12]
    } else {
        &[&rustls::version::TLS13, &rustls::version::TLS12]
    };
    let builder =
        ServerConfig::builder_with_provider(provider()).with_protocol_versions(versions)?;
    let builder = match &opts.client_auth {
        ClientAuth::None => builder.with_no_client_auth(),
        ClientAuth::Optional { ca_pem } | ClientAuth::Required { ca_pem } => {
            let mut roots = RootCertStore::empty();
            for c in certs(ca_pem) {
                roots.add(c)?;
            }
            let b = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider());
            let v = if matches!(opts.client_auth, ClientAuth::Optional { .. }) {
                b.allow_unauthenticated().build()?
            } else {
                b.build()?
            };
            builder.with_client_cert_verifier(v)
        }
    };
    let mut cfg = builder.with_single_cert(certs(&opts.cert_chain_pem), key(&opts.key_pem))?;
    cfg.alpn_protocols = opts.alpn.iter().map(|s| s.as_bytes().to_vec()).collect();
    Ok(Arc::new(cfg))
}

/// Common name of the first presented client certificate, if any.
pub fn client_cn(conn: &rustls::ServerConnection) -> Option<String> {
    let certs = conn.peer_certificates()?;
    let first = certs.first()?;
    // Minimal CN extraction without a full X.509 parser: look for the CN OID
    // (2.5.4.3 = 55 04 03) followed by a UTF8String/PrintableString.
    let der = first.as_ref();
    let mut last = None;
    for i in 0..der.len().saturating_sub(5) {
        if der[i] == 0x55 && der[i + 1] == 0x04 && der[i + 2] == 0x03 {
            let len = der[i + 4] as usize;
            if i + 5 + len <= der.len() {
                last = String::from_utf8(der[i + 5..i + 5 + len].to_vec()).ok();
            }
        }
    }
    last
}
