//! Fixtures and per-run credentials for the `auth` gateway profile (port
//! block 19100–19199, docs/audit/gateway-lab-config.md §3).
//!
//! Every credential is generated fresh per run and rendered into the
//! gateway's run directory; nothing here is a real secret. The lab plays the
//! identity provider: it owns the ES256 issuer key, serves its JWKS from the
//! IdP fixture and mints issuer tokens the way a real IdP would. Anvil itself
//! never mints issuer tokens — scenarios hand them to it as bearer/DPoP
//! access tokens, exactly as a user would paste one.

use crate::fixtures_auth_soap::SoapSigning;
use anvil_auth::dpop;
use anvil_domain::auth::{JwtAlgorithm, JwtClaims};
use anvil_fixtures::gateway_idp::{self as idp, IdpFixture};
use anvil_fixtures::http::{self, Fixture};
use anvil_fixtures::ldap::{self, LdapFixture};
use anyhow::Result;
use base64::Engine as _;
use hmac::{KeyInit, Mac};

pub const ISSUER: &str = "https://idp.anvil-lab.invalid";
pub const AUDIENCE: &str = "anvil-lab-api";
pub const ISSUER_KID: &str = "lab-es256-1";
/// A signing key the IdP never published (rotation / unknown-kid stimulus).
pub const ROTATED_KID: &str = "lab-es256-unpublished";
pub const OAUTH_CLIENT_ID: &str = "anvil-lab-client";

fn random_hex(bytes: usize) -> String {
    let mut b = vec![0u8; bytes];
    rand::fill(&mut b[..]);
    hex::encode(b)
}

/// Per-run credentials rendered into `auth.yaml` (see its token list).
pub struct LabSecrets {
    pub alice_key: String,
    pub bob_key: String,
    pub alice_jwt_secret: String,
    pub alice_hmac_secret: String,
    pub alice_password: String,
    pub alice_ldap_password: String,
    /// `FERRUM_BASIC_AUTH_HMAC_SECRET` for the gateway process.
    pub basic_hmac_secret: String,
    pub oauth_client_secret: String,
    /// WS-Security UsernameToken password (inline in the soap_ws_security config).
    pub soap_alice_password: String,
    /// oidc_relying_party session sealing secret.
    pub oidc_session_secret: String,
    /// alice's password on the lab IdP's login page (the "browser" user).
    pub oidc_alice_password: String,
}

impl LabSecrets {
    fn generate() -> Self {
        LabSecrets {
            alice_key: format!("alice-{}", random_hex(12)),
            bob_key: format!("bob-{}", random_hex(12)),
            alice_jwt_secret: random_hex(24),
            alice_hmac_secret: random_hex(24),
            alice_password: format!("pw-{}", random_hex(8)),
            alice_ldap_password: format!("ldap-{}", random_hex(8)),
            basic_hmac_secret: random_hex(32),
            oauth_client_secret: random_hex(16),
            soap_alice_password: format!("soap-{}", random_hex(8)),
            oidc_session_secret: random_hex(32),
            oidc_alice_password: format!("idp-{}", random_hex(8)),
        }
    }

    /// `hmac_sha256:<hex>` basic-auth credential hash (types.rs:9009-9031).
    pub fn alice_basic_hash(&self) -> String {
        let mut m = hmac::Hmac::<sha2::Sha256>::new_from_slice(self.basic_hmac_secret.as_bytes()).expect("hmac key");
        m.update(self.alice_password.as_bytes());
        format!("hmac_sha256:{}", hex::encode(m.finalize().into_bytes()))
    }

    /// `{{TOKEN}}` values for auth.yaml.
    pub fn template_vars(&self) -> Vec<(&'static str, String)> {
        vec![
            ("ALICE_API_KEY", self.alice_key.clone()),
            ("BOB_API_KEY", self.bob_key.clone()),
            ("ALICE_JWT_SECRET", self.alice_jwt_secret.clone()),
            ("ALICE_HMAC_SECRET", self.alice_hmac_secret.clone()),
            ("BASIC_AUTH_ALICE_HASH", self.alice_basic_hash()),
            ("SOAP_ALICE_PASSWORD", self.soap_alice_password.clone()),
            ("OIDC_SESSION_SECRET", self.oidc_session_secret.clone()),
        ]
    }
}

/// Every field is held so its server keeps running for the whole lab run.
#[allow(dead_code)]
pub struct AuthFixtures {
    pub secrets: LabSecrets,
    /// 19101: echo backend (reflects request headers).
    pub echo: Fixture,
    /// 19102: identity provider (JWKS, introspection, token endpoint).
    pub idp: IdpFixture,
    /// 19103: second JWKS host, switched off mid-run (AUTH-X03).
    pub idp_outage: IdpFixture,
    /// 19106: LDAP directory.
    pub ldap: LdapFixture,
    /// The IdP's published ES256 signing key (PKCS#8 PEM).
    pub issuer_key: String,
    /// A signing key whose kid the IdP never published.
    pub rotated_key: String,
    /// Anvil's DPoP proof key, and a second, unrelated one.
    pub dpop_key: String,
    pub other_dpop_key: String,
    /// Directory of the per-run SOAP signer / SAML IdP certificates
    /// (`{{LAB_SOAP}}`).
    pub soap_dir: std::path::PathBuf,
    /// The lab's XML signer and SAML identity provider.
    pub soap: SoapSigning,
}

impl AuthFixtures {
    pub async fn start(soap_dir: std::path::PathBuf) -> Result<Self> {
        let secrets = LabSecrets::generate();
        let soap = SoapSigning::setup(&soap_dir).map_err(|e| anyhow::anyhow!("SOAP lab signer setup: {e}"))?;
        let issuer_key = dpop::generate_key_pem()?;
        let rotated_key = dpop::generate_key_pem()?;
        let (x, y) = dpop::public_jwk(&issuer_key)?;
        let jwks =
            serde_json::json!({"keys": [{"kty": "EC", "crv": "P-256", "x": x, "y": y, "kid": ISSUER_KID, "alg": "ES256", "use": "sig"}]});
        let idp = idp::serve("127.0.0.1:19102", jwks.clone(), OAUTH_CLIENT_ID, &secrets.oauth_client_secret).await?;
        let idp_outage = idp::serve("127.0.0.1:19103", jwks, OAUTH_CLIENT_ID, &secrets.oauth_client_secret).await?;
        // Tokens issued to the client-credentials client introspect as alice.
        *idp.state.issued_claims.lock() = serde_json::json!({"username": "alice", "sub": "alice", "iss": ISSUER, "aud": AUDIENCE});
        let ldap = ldap::serve("127.0.0.1:19106", &[("alice", &secrets.alice_ldap_password)]).await?;
        // OIDC provider role for the oidc_relying_party route (AUTH-017): the
        // lab signs ID tokens with the published issuer key.
        let minter_key = issuer_key.clone();
        idp.enable_oidc(
            ISSUER,
            &[("alice", &secrets.oidc_alice_password)],
            std::sync::Arc::new(move |claims: serde_json::Value| {
                anvil_auth::jwt::sign(
                    JwtAlgorithm::ES256,
                    &minter_key,
                    &JwtClaims::default(),
                    &claims,
                    Some(ISSUER_KID),
                    chrono::Utc::now(),
                )
                .unwrap_or_default()
            }),
        );
        Ok(AuthFixtures {
            echo: http::serve("127.0.0.1:19101", None).await?,
            idp,
            idp_outage,
            ldap,
            issuer_key,
            rotated_key,
            dpop_key: dpop::generate_key_pem()?,
            other_dpop_key: dpop::generate_key_pem()?,
            secrets,
            soap_dir,
            soap,
        })
    }

    /// An ES256 issuer token (the IdP's job, done by the lab).
    pub fn issuer_token(&self, key: &str, kid: &str, iss: &str, aud: &str, lifetime_secs: i64, extra: serde_json::Value) -> String {
        let claims = JwtClaims {
            iss: Some(iss.into()),
            sub: Some("alice".into()),
            aud: Some(aud.into()),
            expires_in_secs: Some(lifetime_secs),
            not_before_offset_secs: None,
            extra_json: String::new(),
        };
        anvil_auth::jwt::sign(JwtAlgorithm::ES256, key, &claims, &extra, Some(kid), chrono::Utc::now()).expect("lab issuer token")
    }

    /// An otherwise valid access token whose `iss` claim is the given JSON
    /// value (e.g. an array containing the trusted issuer).
    pub fn issuer_token_with_iss(&self, iss: serde_json::Value) -> String {
        let claims = JwtClaims {
            iss: None,
            sub: Some("alice".into()),
            aud: Some(AUDIENCE.into()),
            expires_in_secs: Some(300),
            not_before_offset_secs: None,
            extra_json: String::new(),
        };
        anvil_auth::jwt::sign(
            JwtAlgorithm::ES256,
            &self.issuer_key,
            &claims,
            &serde_json::json!({ "iss": iss }),
            Some(ISSUER_KID),
            chrono::Utc::now(),
        )
        .expect("lab issuer token")
    }

    /// A valid access token from the published key.
    pub fn good_token(&self) -> String {
        self.issuer_token(&self.issuer_key, ISSUER_KID, ISSUER, AUDIENCE, 300, serde_json::Value::Null)
    }

    /// An access token bound (cnf.jkt) to `proof_key`.
    pub fn dpop_bound_token(&self, proof_key: &str) -> String {
        let (x, y) = dpop::public_jwk(proof_key).expect("proof key");
        let jkt = dpop::thumbprint(&x, &y);
        self.issuer_token(&self.issuer_key, ISSUER_KID, ISSUER, AUDIENCE, 300, serde_json::json!({"cnf": {"jkt": jkt}}))
    }

    /// An HS256 token for the jwt_auth route (the consumer's own secret).
    pub fn hs256(&self, secret: &str, lifetime_secs: i64, nbf_offset: Option<i64>, extra: serde_json::Value) -> String {
        let claims = JwtClaims {
            iss: None,
            sub: Some("alice".into()),
            aud: None,
            expires_in_secs: Some(lifetime_secs),
            not_before_offset_secs: nbf_offset,
            extra_json: String::new(),
        };
        anvil_auth::jwt::sign(JwtAlgorithm::HS256, secret, &claims, &extra, None, chrono::Utc::now()).expect("lab hs256 token")
    }
}

/// An unsigned (`alg: none`) token: the algorithm-confusion stimulus.
pub fn alg_none_token(claims: serde_json::Value) -> String {
    let b64 = |v: &serde_json::Value| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(v).unwrap_or_default());
    format!("{}.{}.", b64(&serde_json::json!({"alg": "none", "typ": "JWT"})), b64(&claims))
}
