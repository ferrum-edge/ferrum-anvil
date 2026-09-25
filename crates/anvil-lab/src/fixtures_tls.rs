//! Fixtures for the `tls` gateway profile (port block 19300–19399, see
//! docs/audit/gateway-lab-config.md §3) and the per-run gateway PKI.

use anvil_auth::dpop;
use anvil_domain::auth::{JwtAlgorithm, JwtClaims};
use anvil_fixtures::gateway_pki::GatewayPki;
use anvil_fixtures::http::{self, Fixture};
use anvil_fixtures::idp::{self, IdpFixture};
use anvil_fixtures::pki::Pem;
use anvil_fixtures::raw::{self, RawFixture, RawMode};
use anvil_fixtures::streams::{self, StreamFixture, TcpMode, UdpMode};
use anvil_fixtures::{ClientAuth, TlsServerOptions};
use anyhow::Result;
use base64::Engine as _;
use sha2::Digest;
use std::path::PathBuf;

pub const ISSUER: &str = "https://idp.anvil-lab.invalid";
pub const AUDIENCE: &str = "anvil-lab-api";
const ISSUER_KID: &str = "lab-tls-es256-1";

/// Every field is held so its server keeps running for the whole lab run.
#[allow(dead_code)]
pub struct TlsFixtures {
    pub pki: GatewayPki,
    /// Absolute directory the gateway reads its certificates from.
    pub certs_dir: PathBuf,
    /// 19301: backend-good, the positive control.
    pub trusted: Fixture,
    /// 19302: self-signed.
    pub untrusted: Fixture,
    /// 19303: valid chain, wrong name.
    pub wrong_name: Fixture,
    /// 19304: TLS 1.3, requires a client certificate from backend-client-ca.
    pub mtls13: Fixture,
    /// 19305: TLS 1.2, requires a client certificate from backend-client-ca.
    pub mtls12: Fixture,
    /// 19306: accepts TCP, never answers the ClientHello.
    pub stall: RawFixture,
    /// 19307: plaintext HTTP (the gateway speaks TLS to it).
    pub plain: Fixture,
    /// 19308: TLS server (the gateway speaks plaintext to it).
    pub tls_for_plain: Fixture,
    /// 19309: plaintext echo behind the frontend routes.
    pub echo: Fixture,
    /// 19310: UDP echo behind the DTLS listener.
    pub udp_echo: StreamFixture,
    /// 19311: TCP echo behind the TCP+TLS listener.
    pub tcp_echo: StreamFixture,
    /// 19312: backend-ca chain and right name, but expired.
    pub expired: Fixture,
    /// 19313: JWKS of the lab issuer for certificate-bound tokens (AUTH-026).
    pub idp: IdpFixture,
    /// The issuer's ES256 signing key (PKCS#8 PEM), per run.
    pub issuer_key: String,
}

fn backend_tls(leaf: &Pem, chain_ca: Option<&Pem>) -> TlsServerOptions {
    let chain = match chain_ca {
        Some(ca) => leaf.chain_with(ca),
        None => leaf.cert.clone(),
    };
    let mut o = TlsServerOptions::new(chain, leaf.key.clone());
    // HTTP/1.1 only, so the gateway's startup capability probe keeps every
    // route on the reqwest HTTP/1 pool (the audited dispatch path).
    o.alpn = vec!["http/1.1".into()];
    o
}

impl TlsFixtures {
    pub async fn start(certs_dir: PathBuf) -> Result<Self> {
        let pki = GatewayPki::generate();
        pki.write_to(&certs_dir)?;
        let ca = &pki.backend_ca;
        let mut mtls13 = backend_tls(&pki.backend_good, Some(ca));
        mtls13.client_auth = ClientAuth::Required { ca_pem: pki.backend_client_ca.cert.clone() };
        mtls13.tls13_only = true;
        let mut mtls12 = backend_tls(&pki.backend_good, Some(ca));
        mtls12.client_auth = ClientAuth::Required { ca_pem: pki.backend_client_ca.cert.clone() };
        mtls12.tls12_only = true;
        let issuer_key = dpop::generate_key_pem()?;
        let (x, y) = dpop::public_jwk(&issuer_key)?;
        let jwks =
            serde_json::json!({"keys": [{"kty": "EC", "crv": "P-256", "x": x, "y": y, "kid": ISSUER_KID, "alg": "ES256", "use": "sig"}]});
        Ok(TlsFixtures {
            idp: idp::serve("127.0.0.1:19313", jwks, "unused-client", "unused-secret").await?,
            issuer_key,
            trusted: http::serve("127.0.0.1:19301", Some(backend_tls(&pki.backend_good, Some(ca)))).await?,
            untrusted: http::serve("127.0.0.1:19302", Some(backend_tls(&pki.backend_untrusted, None))).await?,
            wrong_name: http::serve("127.0.0.1:19303", Some(backend_tls(&pki.backend_wrongname, Some(ca)))).await?,
            mtls13: http::serve("127.0.0.1:19304", Some(mtls13)).await?,
            mtls12: http::serve("127.0.0.1:19305", Some(mtls12)).await?,
            stall: raw::serve("127.0.0.1:19306", RawMode::AcceptStall, None).await?,
            plain: http::serve("127.0.0.1:19307", None).await?,
            tls_for_plain: http::serve("127.0.0.1:19308", Some(backend_tls(&pki.backend_good, Some(ca)))).await?,
            echo: http::serve("127.0.0.1:19309", None).await?,
            udp_echo: streams::udp("127.0.0.1:19310", UdpMode::Echo).await?,
            tcp_echo: streams::tcp("127.0.0.1:19311", TcpMode::Echo, None).await?,
            expired: http::serve("127.0.0.1:19312", Some(backend_tls(&pki.backend_expired, Some(ca)))).await?,
            pki,
            certs_dir,
        })
    }
}

/// RFC 8705 `x5t#S256`: base64url(SHA-256(DER certificate)), no padding.
pub fn x5t_s256(cert_pem: &str) -> String {
    let b64: String = cert_pem.lines().filter(|l| !l.starts_with("-----")).collect();
    let der = base64::engine::general_purpose::STANDARD.decode(b64).expect("lab certificate PEM");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(&der))
}

impl TlsFixtures {
    /// An issuer access token bound (cnf.x5t#S256) to `cert_pem` — the lab
    /// plays the identity provider; Anvil only presents the token.
    pub fn bound_token(&self, cert_pem: &str) -> String {
        let claims = JwtClaims {
            iss: Some(ISSUER.into()),
            sub: Some("tls-client-good".into()),
            aud: Some(AUDIENCE.into()),
            expires_in_secs: Some(300),
            not_before_offset_secs: None,
            extra_json: String::new(),
        };
        let extra = serde_json::json!({"cnf": {"x5t#S256": x5t_s256(cert_pem)}});
        anvil_auth::jwt::sign(JwtAlgorithm::ES256, &self.issuer_key, &claims, &extra, Some(ISSUER_KID), chrono::Utc::now())
            .expect("lab token")
    }
}
