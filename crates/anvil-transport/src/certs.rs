//! Certificate parsing for evidence (public data only; keys are never exposed).

use anvil_domain::execution::CertificateSummary;
use rustls_pki_types::CertificateDer;
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn fingerprint(der: &[u8]) -> String {
    let h = Sha256::digest(der);
    h.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":")
}

/// [`summarize`] for raw DER bytes.
pub fn summarize_der(der: &[u8]) -> CertificateSummary {
    summarize(&CertificateDer::from(der))
}

pub fn summarize(der: &CertificateDer<'_>) -> CertificateSummary {
    match X509Certificate::from_der(der.as_ref()) {
        Ok((_, cert)) => {
            let mut sans = Vec::new();
            if let Ok(Some(ext)) = cert.subject_alternative_name() {
                for gn in &ext.value.general_names {
                    match gn {
                        GeneralName::DNSName(d) => sans.push(format!("DNS:{d}")),
                        GeneralName::IPAddress(ip) => {
                            let s = match ip.len() {
                                4 => std::net::Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]).to_string(),
                                16 => {
                                    let mut a = [0u8; 16];
                                    a.copy_from_slice(ip);
                                    std::net::Ipv6Addr::from(a).to_string()
                                }
                                _ => hex::encode(ip),
                            };
                            sans.push(format!("IP:{s}"));
                        }
                        GeneralName::URI(u) => sans.push(format!("URI:{u}")),
                        GeneralName::RFC822Name(e) => sans.push(format!("email:{e}")),
                        _ => {}
                    }
                }
            }
            let is_ca = cert.basic_constraints().ok().flatten().map(|bc| bc.value.ca).unwrap_or(false);
            let key_algorithm = match cert.public_key().parsed() {
                Ok(x509_parser::public_key::PublicKey::RSA(r)) => format!("RSA-{}", r.key_size()),
                Ok(x509_parser::public_key::PublicKey::EC(ec)) => format!("EC-{}", ec.key_size()),
                Ok(_) => cert.public_key().algorithm.algorithm.to_id_string(),
                Err(_) => "unknown".into(),
            };
            CertificateSummary {
                subject: cert.subject().to_string(),
                issuer: cert.issuer().to_string(),
                subject_alt_names: sans,
                not_before: cert.validity().not_before.to_datetime().to_string(),
                not_after: cert.validity().not_after.to_datetime().to_string(),
                serial_hex: cert.raw_serial_as_string(),
                sha256_fingerprint: fingerprint(der.as_ref()),
                is_ca,
                key_algorithm,
            }
        }
        Err(e) => CertificateSummary {
            subject: format!("<unparseable certificate: {e}>"),
            issuer: String::new(),
            subject_alt_names: vec![],
            not_before: String::new(),
            not_after: String::new(),
            serial_hex: String::new(),
            sha256_fingerprint: fingerprint(der.as_ref()),
            is_ca: false,
            key_algorithm: "unknown".into(),
        },
    }
}
