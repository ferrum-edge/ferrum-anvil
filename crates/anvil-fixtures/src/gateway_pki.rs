//! Ephemeral PKI for the real-gateway TLS lab (`lab/gateway/tls.*`), named
//! after the plan in docs/audit/gateway-lab-config.md §3. Generated fresh for
//! every lab run, written only under the run directory, never committed and
//! never added to any OS trust store. CA private keys are never written out.
//!
//! The three identities stay separate (build plan §8.1):
//! * `client-ca` issues identities Anvil presents to the gateway frontend;
//! * `frontend-ca` issues the gateway's own server certificate;
//! * `backend-ca` / `backend-client-ca` concern only the gateway-to-backend leg.

use crate::pki::Pem;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SanType,
};
use std::path::Path;
use time::{Duration, OffsetDateTime};

/// Every certificate the tls/auth gateway profiles use.
#[derive(Clone, Debug)]
pub struct GatewayPki {
    /// Root that issued the gateway's frontend (HTTPS/TCP+TLS/DTLS) certificate.
    pub frontend_ca: Pem,
    /// Gateway frontend certificate: SAN `localhost`, `127.0.0.1` (ECDSA P-256, as DTLS requires).
    pub gateway_server: Pem,
    /// Same names, validity already over (for the startup-refusal check).
    pub gateway_server_expired: Pem,
    /// Same names, validity starts in the future.
    pub gateway_server_future: Pem,
    /// Root the gateway trusts for client certificates.
    pub client_ca: Pem,
    /// `CN=anvil-lab-client-good`, mapped to a consumer where mtls_auth is used.
    pub client_good: Pem,
    /// `CN=anvil-lab-client-unmapped`: valid chain, but no consumer maps to it.
    pub client_unmapped: Pem,
    /// A root nobody in the lab trusts.
    pub rogue_ca: Pem,
    /// Client identity issued by the rogue root.
    pub client_rogue: Pem,
    /// Root the gateway trusts for backend server certificates.
    pub backend_ca: Pem,
    /// SAN `localhost`, `127.0.0.1`.
    pub backend_good: Pem,
    /// Valid chain, SAN `wrong-name.anvil-lab.invalid` only.
    pub backend_wrongname: Pem,
    /// Chains to `backend_ca`, names match, validity already over.
    pub backend_expired: Pem,
    /// Self-signed, not issued by `backend_ca`.
    pub backend_untrusted: Pem,
    /// Root the mTLS backends trust for the gateway's backend client identity.
    pub backend_client_ca: Pem,
    /// The gateway's backend client identity (identity #3 in the plan).
    pub gateway_backend_client: Pem,
}

fn dn(cn: &str) -> DistinguishedName {
    let mut d = DistinguishedName::new();
    d.push(DnType::OrganizationName, "Ferrum Anvil Gateway Lab");
    d.push(DnType::CommonName, cn);
    d
}

struct Ca {
    issuer: CertifiedIssuer<'static, KeyPair>,
    cert_pem: String,
}

fn make_ca(cn: &str) -> Ca {
    let mut p = CertificateParams::new(Vec::<String>::new()).expect("params");
    p.distinguished_name = dn(cn);
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];
    p.not_before = OffsetDateTime::now_utc() - Duration::days(2);
    p.not_after = OffsetDateTime::now_utc() + Duration::days(365);
    let key = KeyPair::generate().expect("key");
    let issuer = CertifiedIssuer::self_signed(p, key).expect("ca");
    let cert_pem = issuer.pem();
    Ca { issuer, cert_pem }
}

fn params(cn: &str, sans: &[&str], window: (OffsetDateTime, OffsetDateTime), client: bool) -> CertificateParams {
    let mut p = CertificateParams::new(Vec::<String>::new()).expect("params");
    p.distinguished_name = dn(cn);
    p.subject_alt_names = sans
        .iter()
        .map(|s| match s.parse::<std::net::IpAddr>() {
            Ok(ip) => SanType::IpAddress(ip),
            Err(_) => SanType::DnsName(s.to_string().try_into().expect("dns name")),
        })
        .collect();
    p.is_ca = IsCa::ExplicitNoCa;
    p.key_usages = vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyEncipherment];
    p.extended_key_usages = if client { vec![ExtendedKeyUsagePurpose::ClientAuth] } else { vec![ExtendedKeyUsagePurpose::ServerAuth] };
    p.not_before = window.0;
    p.not_after = window.1;
    p
}

fn leaf(cn: &str, sans: &[&str], issuer: &Issuer<'_, KeyPair>, window: (OffsetDateTime, OffsetDateTime), client: bool) -> Pem {
    let key = KeyPair::generate().expect("key");
    let cert = params(cn, sans, window, client).signed_by(&key, issuer).expect("sign");
    Pem { cert: cert.pem(), key: key.serialize_pem() }
}

const LOCAL_NAMES: &[&str] = &["localhost", "127.0.0.1"];

impl GatewayPki {
    pub fn generate() -> Self {
        let now = OffsetDateTime::now_utc();
        let valid = (now - Duration::days(1), now + Duration::days(30));
        let expired = (now - Duration::days(30), now - Duration::days(1));
        let future = (now + Duration::days(30), now + Duration::days(60));
        let frontend = make_ca("Anvil Gateway Lab Frontend CA");
        let client = make_ca("Anvil Gateway Lab Client CA");
        let rogue = make_ca("Anvil Gateway Lab Rogue CA");
        let backend = make_ca("Anvil Gateway Lab Backend CA");
        let backend_client = make_ca("Anvil Gateway Lab Backend Client CA");
        let untrusted_key = KeyPair::generate().expect("key");
        let untrusted =
            params("anvil-lab-backend-self-signed", LOCAL_NAMES, valid, false).self_signed(&untrusted_key).expect("self-signed");
        GatewayPki {
            gateway_server: leaf("anvil-lab-gateway", LOCAL_NAMES, &frontend.issuer, valid, false),
            gateway_server_expired: leaf("anvil-lab-gateway-expired", LOCAL_NAMES, &frontend.issuer, expired, false),
            gateway_server_future: leaf("anvil-lab-gateway-future", LOCAL_NAMES, &frontend.issuer, future, false),
            client_good: leaf("anvil-lab-client-good", &["anvil-lab-client-good"], &client.issuer, valid, true),
            client_unmapped: leaf("anvil-lab-client-unmapped", &["anvil-lab-client-unmapped"], &client.issuer, valid, true),
            client_rogue: leaf("anvil-lab-client-rogue", &["anvil-lab-client-rogue"], &rogue.issuer, valid, true),
            backend_good: leaf("anvil-lab-backend", LOCAL_NAMES, &backend.issuer, valid, false),
            backend_wrongname: leaf("wrong-name.anvil-lab.invalid", &["wrong-name.anvil-lab.invalid"], &backend.issuer, valid, false),
            backend_expired: leaf("anvil-lab-backend-expired", LOCAL_NAMES, &backend.issuer, expired, false),
            backend_untrusted: Pem { cert: untrusted.pem(), key: untrusted_key.serialize_pem() },
            gateway_backend_client: leaf("anvil-lab-gateway-backend-client", &["anvil-lab-gateway"], &backend_client.issuer, valid, true),
            frontend_ca: Pem { cert: frontend.cert_pem, key: String::new() },
            client_ca: Pem { cert: client.cert_pem, key: String::new() },
            rogue_ca: Pem { cert: rogue.cert_pem, key: String::new() },
            backend_ca: Pem { cert: backend.cert_pem, key: String::new() },
            backend_client_ca: Pem { cert: backend_client.cert_pem, key: String::new() },
        }
    }

    /// Write `<name>.pem` (+ `<name>.key`, mode 0600, for leaves) into `dir`.
    /// CA private keys are not written.
    pub fn write_to(&self, dir: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(dir)?;
        let leaves: [(&str, &Pem); 11] = [
            ("gateway-server", &self.gateway_server),
            ("gateway-server-expired", &self.gateway_server_expired),
            ("gateway-server-future", &self.gateway_server_future),
            ("client-good", &self.client_good),
            ("client-unmapped", &self.client_unmapped),
            ("client-rogue", &self.client_rogue),
            ("backend-good", &self.backend_good),
            ("backend-wrongname", &self.backend_wrongname),
            ("backend-expired", &self.backend_expired),
            ("backend-untrusted", &self.backend_untrusted),
            ("gateway-backend-client", &self.gateway_backend_client),
        ];
        for (name, pem) in leaves {
            std::fs::write(dir.join(format!("{name}.pem")), &pem.cert)?;
            let kp = dir.join(format!("{name}.key"));
            std::fs::write(&kp, &pem.key)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&kp, std::fs::Permissions::from_mode(0o600))?;
            }
        }
        let roots: [(&str, &Pem); 5] = [
            ("frontend-ca", &self.frontend_ca),
            ("client-ca", &self.client_ca),
            ("rogue-ca", &self.rogue_ca),
            ("backend-ca", &self.backend_ca),
            ("backend-client-ca", &self.backend_client_ca),
        ];
        for (name, pem) in roots {
            std::fs::write(dir.join(format!("{name}.pem")), &pem.cert)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_leaves_and_roots_without_ca_keys() {
        let dir = std::env::temp_dir().join(format!("anvil-gw-pki-{}", std::process::id()));
        let pki = GatewayPki::generate();
        pki.write_to(&dir).unwrap();
        for f in ["gateway-server.pem", "gateway-server.key", "client-good.key", "frontend-ca.pem", "backend-client-ca.pem"] {
            assert!(dir.join(f).exists(), "{f}");
        }
        assert!(!dir.join("frontend-ca.key").exists(), "CA private keys are never written");
        assert!(pki.gateway_server.key.contains("PRIVATE KEY"));
        std::fs::remove_dir_all(&dir).ok();
    }
}
