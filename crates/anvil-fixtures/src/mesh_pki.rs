//! Ephemeral SPIFFE PKI for the lab's mesh-mode gateway instance (the
//! admission profile's egress gateway, UP-018). Generated fresh per run,
//! written only under the run directory, never committed and never added to
//! any OS trust store. The CA private key is never written out.
//!
//! * `ca`: the lab mesh trust domain root (`cluster.local`).
//! * `egress`: the egress gateway's X.509-SVID
//!   (`spiffe://cluster.local/ns/ferrum/sa/anvil-lab-egress`). It also carries
//!   `DNS:localhost` / `IP:127.0.0.1` so Anvil can verify the listener with
//!   ordinary hostname verification instead of a verification bypass.
//! * `client`: the SVID Anvil presents on the mTLS egress listener
//!   (`spiffe://cluster.local/ns/ferrum/sa/anvil-lab-client`).
//! * `backend_ca` / `backend`: an unrelated root and `localhost` server
//!   certificate for a TLS backend behind the egress gateway.
//!
//! Mesh client fixtures (the `mesh` lab profile and the SPIFFE/HBONE tests):
//!
//! * `svc`, `ztunnel`: server SVIDs that carry **only** a SPIFFE URI SAN (no
//!   DNS name), so only SPIFFE verification can authenticate them.
//! * `other`: a valid SVID for a different workload of the same trust domain
//!   (wrong expected ID).
//! * `two_uris`: a leaf with two URI SANs (not a valid X.509-SVID).
//! * `no_uri`: a mesh-CA leaf with a DNS SAN only (not an X.509-SVID).
//! * `partner_same_ca`: a mesh-CA leaf whose SPIFFE ID is in another trust
//!   domain (`partner.example`): valid chain, untrusted trust domain.
//! * `foreign_ca` / `foreign_client` / `foreign_server`: an unrelated root for
//!   trust domain `partner.example` and SVIDs issued by it.

use crate::pki::Pem;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};
use std::path::Path;
use time::{Duration, OffsetDateTime};

pub const TRUST_DOMAIN: &str = "cluster.local";
pub const NAMESPACE: &str = "ferrum";
pub const EGRESS_SPIFFE_ID: &str = "spiffe://cluster.local/ns/ferrum/sa/anvil-lab-egress";
pub const CLIENT_SPIFFE_ID: &str = "spiffe://cluster.local/ns/ferrum/sa/anvil-lab-client";
pub const SVC_SPIFFE_ID: &str = "spiffe://cluster.local/ns/ferrum/sa/anvil-lab-svc";
pub const ZTUNNEL_SPIFFE_ID: &str = "spiffe://cluster.local/ns/ferrum/sa/anvil-lab-ztunnel";
pub const OTHER_SPIFFE_ID: &str = "spiffe://cluster.local/ns/ferrum/sa/anvil-lab-other";
pub const PARTNER_TRUST_DOMAIN: &str = "partner.example";
pub const PARTNER_CLIENT_SPIFFE_ID: &str = "spiffe://partner.example/ns/ferrum/sa/anvil-lab-client";
pub const PARTNER_SVC_SPIFFE_ID: &str = "spiffe://partner.example/ns/ferrum/sa/anvil-lab-svc";

#[derive(Clone, Debug)]
pub struct MeshPki {
    pub ca: Pem,
    pub egress: Pem,
    pub client: Pem,
    pub backend_ca: Pem,
    pub backend: Pem,
    pub svc: Pem,
    pub ztunnel: Pem,
    pub other: Pem,
    pub two_uris: Pem,
    pub no_uri: Pem,
    pub partner_same_ca: Pem,
    pub foreign_ca: Pem,
    pub foreign_client: Pem,
    pub foreign_server: Pem,
}

fn dn(cn: &str) -> DistinguishedName {
    let mut d = DistinguishedName::new();
    d.push(DnType::OrganizationName, "Ferrum Anvil Mesh Lab");
    d.push(DnType::CommonName, cn);
    d
}

fn make_ca(cn: &str) -> (CertifiedIssuer<'static, KeyPair>, String) {
    let mut p = CertificateParams::new(Vec::<String>::new()).expect("params");
    p.distinguished_name = dn(cn);
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];
    p.not_before = OffsetDateTime::now_utc() - Duration::days(1);
    p.not_after = OffsetDateTime::now_utc() + Duration::days(30);
    let issuer = CertifiedIssuer::self_signed(p, KeyPair::generate().expect("key")).expect("ca");
    let pem = issuer.pem();
    (issuer, pem)
}

fn leaf(cn: &str, spiffe_id: Option<&str>, local_names: bool, issuer: &CertifiedIssuer<'static, KeyPair>) -> Pem {
    leaf_uris(cn, spiffe_id.into_iter().collect::<Vec<_>>().as_slice(), local_names, issuer)
}

fn leaf_uris(cn: &str, uris: &[&str], local_names: bool, issuer: &CertifiedIssuer<'static, KeyPair>) -> Pem {
    let mut p = CertificateParams::new(Vec::<String>::new()).expect("params");
    p.distinguished_name = dn(cn);
    for id in uris {
        p.subject_alt_names.push(SanType::URI((*id).try_into().expect("uri")));
    }
    if local_names {
        p.subject_alt_names.push(SanType::DnsName("localhost".try_into().expect("dns")));
        p.subject_alt_names.push(SanType::IpAddress(std::net::IpAddr::from([127, 0, 0, 1])));
    }
    p.is_ca = IsCa::ExplicitNoCa;
    p.key_usages = vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyAgreement];
    p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth, ExtendedKeyUsagePurpose::ClientAuth];
    p.not_before = OffsetDateTime::now_utc() - Duration::hours(1);
    p.not_after = OffsetDateTime::now_utc() + Duration::days(7);
    let key = KeyPair::generate().expect("key");
    let cert = p.signed_by(&key, issuer).expect("sign");
    Pem { cert: cert.pem(), key: key.serialize_pem() }
}

impl MeshPki {
    pub fn generate() -> Self {
        let (ca, ca_pem) = make_ca("Anvil Mesh Lab Root");
        let (backend_ca, backend_ca_pem) = make_ca("Anvil Mesh Lab Backend Root");
        let (foreign_ca, foreign_ca_pem) = make_ca("Anvil Mesh Lab Partner Root");
        MeshPki {
            egress: leaf("anvil-lab-egress", Some(EGRESS_SPIFFE_ID), true, &ca),
            client: leaf("anvil-lab-client", Some(CLIENT_SPIFFE_ID), false, &ca),
            backend: leaf("anvil-lab-mesh-backend", None, true, &backend_ca),
            svc: leaf("anvil-lab-svc", Some(SVC_SPIFFE_ID), false, &ca),
            ztunnel: leaf("anvil-lab-ztunnel", Some(ZTUNNEL_SPIFFE_ID), false, &ca),
            other: leaf("anvil-lab-other", Some(OTHER_SPIFFE_ID), false, &ca),
            two_uris: leaf_uris("anvil-lab-two-uris", &[SVC_SPIFFE_ID, "https://anvil.test/svc"], false, &ca),
            no_uri: leaf("anvil-lab-dns-only", None, true, &ca),
            partner_same_ca: leaf("anvil-lab-partner-svc", Some(PARTNER_SVC_SPIFFE_ID), false, &ca),
            foreign_client: leaf("anvil-lab-partner-client", Some(PARTNER_CLIENT_SPIFFE_ID), false, &foreign_ca),
            foreign_server: leaf("anvil-lab-partner-svc", Some(PARTNER_SVC_SPIFFE_ID), false, &foreign_ca),
            ca: Pem { cert: ca_pem, key: String::new() },
            backend_ca: Pem { cert: backend_ca_pem, key: String::new() },
            foreign_ca: Pem { cert: foreign_ca_pem, key: String::new() },
        }
    }

    /// Write `ca.pem`, `backend-ca.pem` and `<leaf>.pem` / `<leaf>.key`
    /// (mode 0600) into `dir`. CA private keys are never written.
    pub fn write_to(&self, dir: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(dir)?;
        for (name, pem) in [
            ("egress", &self.egress),
            ("client", &self.client),
            ("backend", &self.backend),
            ("svc", &self.svc),
            ("ztunnel", &self.ztunnel),
            ("other", &self.other),
            ("foreign-client", &self.foreign_client),
        ] {
            std::fs::write(dir.join(format!("{name}.pem")), &pem.cert)?;
            let kp = dir.join(format!("{name}.key"));
            std::fs::write(&kp, &pem.key)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&kp, std::fs::Permissions::from_mode(0o600))?;
            }
        }
        std::fs::write(dir.join("ca.pem"), &self.ca.cert)?;
        std::fs::write(dir.join("backend-ca.pem"), &self.backend_ca.cert)?;
        std::fs::write(dir.join("foreign-ca.pem"), &self.foreign_ca.cert)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn svids_carry_one_spiffe_uri_and_ca_keys_stay_in_memory() {
        let dir = std::env::temp_dir().join(format!("anvil-mesh-pki-{}", std::process::id()));
        let pki = MeshPki::generate();
        pki.write_to(&dir).unwrap();
        for f in ["ca.pem", "egress.pem", "egress.key", "client.pem", "client.key", "backend.pem", "backend-ca.pem"] {
            assert!(dir.join(f).exists(), "{f}");
        }
        assert!(!dir.join("ca.key").exists(), "CA private keys are never written");
        assert!(pki.egress.key.starts_with("-----BEGIN PRIVATE KEY-----"), "PKCS#8 as the gateway requires");
        std::fs::remove_dir_all(&dir).ok();
    }
}
