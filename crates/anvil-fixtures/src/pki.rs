//! Ephemeral lab PKI. Every run generates fresh keys; nothing here is ever
//! installed into an OS trust store.

use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType,
};
use std::path::Path;
use time::{Duration, OffsetDateTime};

#[derive(Clone, Debug)]
pub struct Pem {
    pub cert: String,
    pub key: String,
}

impl Pem {
    pub fn chain_with(&self, ca: &Pem) -> String {
        format!("{}{}", self.cert, ca.cert)
    }
}

/// Complete set of lab certificates.
#[derive(Clone, Debug)]
pub struct LabPki {
    /// Trusted lab root for server certificates.
    pub ca: Pem,
    /// A different root that clients do NOT trust.
    pub rogue_ca: Pem,
    /// localhost / 127.0.0.1 / ::1 / *.anvil.test, valid, signed by `ca`.
    pub server: Pem,
    pub server_expired: Pem,
    pub server_not_yet_valid: Pem,
    /// Valid chain but SAN = wrong.anvil.invalid only.
    pub server_wrong_name: Pem,
    /// Signed by `rogue_ca`.
    pub server_untrusted: Pem,
    /// Root that servers trust for client authentication.
    pub client_ca: Pem,
    /// Client identity signed by `client_ca` (CN=anvil-client-a).
    pub client_a: Pem,
    /// Second client identity signed by `client_ca` (CN=anvil-client-b).
    pub client_b: Pem,
    /// Client identity signed by `rogue_ca` (not accepted by servers).
    pub client_rogue: Pem,
}

fn dn(cn: &str) -> DistinguishedName {
    let mut d = DistinguishedName::new();
    d.push(DnType::OrganizationName, "Ferrum Anvil Lab");
    d.push(DnType::CommonName, cn);
    d
}

fn ca_params(cn: &str) -> CertificateParams {
    let mut p = CertificateParams::new(Vec::<String>::new()).expect("params");
    p.distinguished_name = dn(cn);
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    p.not_before = OffsetDateTime::now_utc() - Duration::days(1);
    p.not_after = OffsetDateTime::now_utc() + Duration::days(365);
    p
}

struct Ca {
    issuer: CertifiedIssuer<'static, KeyPair>,
    pem: Pem,
}

fn make_ca(cn: &str) -> Ca {
    let key = KeyPair::generate().expect("key");
    let key_pem = key.serialize_pem();
    let issuer = CertifiedIssuer::self_signed(ca_params(cn), key).expect("ca");
    let pem = Pem {
        cert: issuer.pem(),
        key: key_pem,
    };
    Ca { issuer, pem }
}

fn leaf(
    cn: &str,
    sans: &[&str],
    issuer: &Issuer<'_, KeyPair>,
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
    client: bool,
) -> Pem {
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
    p.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    p.extended_key_usages = if client {
        vec![ExtendedKeyUsagePurpose::ClientAuth]
    } else {
        vec![ExtendedKeyUsagePurpose::ServerAuth]
    };
    p.not_before = not_before;
    p.not_after = not_after;
    let key = KeyPair::generate().expect("key");
    let cert = p.signed_by(&key, issuer).expect("sign");
    Pem {
        cert: cert.pem(),
        key: key.serialize_pem(),
    }
}

pub const SERVER_NAMES: &[&str] = &[
    "localhost",
    "127.0.0.1",
    "::1",
    "*.anvil.test",
    "gateway.anvil.test",
    "backend.anvil.test",
];

impl LabPki {
    pub fn generate() -> Self {
        let now = OffsetDateTime::now_utc();
        let ca = make_ca("Anvil Lab Root CA");
        let rogue = make_ca("Anvil Lab Untrusted Root");
        let client_ca = make_ca("Anvil Lab Client CA");
        let valid_from = now - Duration::days(1);
        let valid_to = now + Duration::days(90);
        LabPki {
            server: leaf(
                "anvil-lab-server",
                SERVER_NAMES,
                &ca.issuer,
                valid_from,
                valid_to,
                false,
            ),
            server_expired: leaf(
                "anvil-lab-expired",
                SERVER_NAMES,
                &ca.issuer,
                now - Duration::days(30),
                now - Duration::days(1),
                false,
            ),
            server_not_yet_valid: leaf(
                "anvil-lab-future",
                SERVER_NAMES,
                &ca.issuer,
                now + Duration::days(30),
                now + Duration::days(60),
                false,
            ),
            server_wrong_name: leaf(
                "wrong.anvil.invalid",
                &["wrong.anvil.invalid"],
                &ca.issuer,
                valid_from,
                valid_to,
                false,
            ),
            server_untrusted: leaf(
                "anvil-lab-untrusted",
                SERVER_NAMES,
                &rogue.issuer,
                valid_from,
                valid_to,
                false,
            ),
            client_a: leaf(
                "anvil-client-a",
                &["anvil-client-a"],
                &client_ca.issuer,
                valid_from,
                valid_to,
                true,
            ),
            client_b: leaf(
                "anvil-client-b",
                &["anvil-client-b"],
                &client_ca.issuer,
                valid_from,
                valid_to,
                true,
            ),
            client_rogue: leaf(
                "anvil-client-rogue",
                &["anvil-client-rogue"],
                &rogue.issuer,
                valid_from,
                valid_to,
                true,
            ),
            ca: ca.pem,
            rogue_ca: rogue.pem,
            client_ca: client_ca.pem,
        }
    }

    /// Write every PEM to `dir` (`<name>.crt` / `<name>.key`) for the gateway lab.
    pub fn write_to(&self, dir: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(dir)?;
        let items: [(&str, &Pem); 11] = [
            ("ca", &self.ca),
            ("rogue-ca", &self.rogue_ca),
            ("server", &self.server),
            ("server-expired", &self.server_expired),
            ("server-not-yet-valid", &self.server_not_yet_valid),
            ("server-wrong-name", &self.server_wrong_name),
            ("server-untrusted", &self.server_untrusted),
            ("client-ca", &self.client_ca),
            ("client-a", &self.client_a),
            ("client-b", &self.client_b),
            ("client-rogue", &self.client_rogue),
        ];
        for (name, pem) in items {
            std::fs::write(dir.join(format!("{name}.crt")), &pem.cert)?;
            let kp = dir.join(format!("{name}.key"));
            std::fs::write(&kp, &pem.key)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&kp, std::fs::Permissions::from_mode(0o600))?;
            }
        }
        std::fs::write(
            dir.join("server-chain.crt"),
            self.server.chain_with(&self.ca),
        )?;
        Ok(())
    }
}
