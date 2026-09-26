//! SPIFFE ID grammar and X.509-SVID shape checks (SPIFFE-ID and X509-SVID
//! specifications).
//!
//! * A SPIFFE ID is `spiffe://<trust-domain>[/<path>]`: lowercase trust
//!   domain of `[a-z0-9.-_]`, path segments of `[a-zA-Z0-9.-_]`, no empty,
//!   `.` or `..` segment, no trailing `/`, no port, userinfo, query or
//!   fragment, at most 2048 bytes.
//! * An X.509-SVID leaf carries **exactly one** URI SAN (the SPIFFE ID), is
//!   not a CA, sets `digitalSignature` and neither `keyCertSign` nor
//!   `cRLSign`. DNS SANs may be present but are never used for identity.
//!
//! Only the leaf's public data is inspected; nothing here trusts the ID
//! before the chain has been verified by the caller.

use x509_parser::prelude::*;

pub const MAX_ID_LEN: usize = 2048;
pub const MAX_TRUST_DOMAIN_LEN: usize = 255;

/// A syntactically valid SPIFFE ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpiffeId {
    pub trust_domain: String,
    /// Path including the leading `/`, or empty.
    pub path: String,
}

impl SpiffeId {
    pub fn as_uri(&self) -> String {
        format!("spiffe://{}{}", self.trust_domain, self.path)
    }
}

impl std::fmt::Display for SpiffeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "spiffe://{}{}", self.trust_domain, self.path)
    }
}

fn trust_domain_char(c: char) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '-' | '_')
}

fn path_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')
}

/// Validate a bare trust domain name (`cluster.local`).
pub fn validate_trust_domain(td: &str) -> Result<(), String> {
    if td.is_empty() {
        return Err("the trust domain is empty".into());
    }
    if td.len() > MAX_TRUST_DOMAIN_LEN {
        return Err(format!("the trust domain is longer than {MAX_TRUST_DOMAIN_LEN} bytes"));
    }
    if let Some(c) = td.chars().find(|c| !trust_domain_char(*c)) {
        return Err(format!(
            "the trust domain contains '{c}'; only lowercase letters, digits, '.', '-' and '_' are allowed (no port or user info)"
        ));
    }
    Ok(())
}

/// Parse a trust domain given either bare (`cluster.local`) or as a SPIFFE ID
/// with no path (`spiffe://cluster.local`).
pub fn parse_trust_domain(s: &str) -> Result<String, String> {
    let s = s.trim();
    let td = if s.starts_with("spiffe://") {
        let id = parse_id(s)?;
        if !id.path.is_empty() {
            return Err(format!("'{s}' is a workload SPIFFE ID, not a trust domain; use '{}'", id.trust_domain));
        }
        id.trust_domain
    } else {
        s.to_string()
    };
    validate_trust_domain(&td)?;
    Ok(td)
}

/// Parse and validate a SPIFFE ID.
pub fn parse_id(s: &str) -> Result<SpiffeId, String> {
    if s.len() > MAX_ID_LEN {
        return Err(format!("a SPIFFE ID is at most {MAX_ID_LEN} bytes"));
    }
    let Some(rest) = s.strip_prefix("spiffe://") else {
        return Err(format!("'{s}' is not a SPIFFE ID (it must start with spiffe://)"));
    };
    if rest.contains(['?', '#']) {
        return Err("a SPIFFE ID has no query or fragment".into());
    }
    let (td, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    validate_trust_domain(td).map_err(|e| format!("'{s}': {e}"))?;
    if !path.is_empty() {
        for seg in path[1..].split('/') {
            if seg.is_empty() {
                return Err(format!("'{s}': the path has an empty segment or a trailing '/'"));
            }
            if seg == "." || seg == ".." {
                return Err(format!("'{s}': the path may not contain '.' or '..' segments"));
            }
            if let Some(c) = seg.chars().find(|c| !path_char(*c)) {
                return Err(format!("'{s}': the path contains '{c}'; only letters, digits, '.', '-' and '_' are allowed"));
            }
        }
    }
    Ok(SpiffeId { trust_domain: td.to_string(), path: path.to_string() })
}

/// Why a leaf is not a valid X.509-SVID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SvidProblem {
    Unparseable(String),
    NoUriSan,
    SeveralUriSans(usize),
    NotSpiffe(String),
    IsCa,
    KeyUsage(String),
}

impl SvidProblem {
    pub fn describe(&self) -> String {
        match self {
            SvidProblem::Unparseable(e) => format!("the certificate could not be parsed ({e})"),
            SvidProblem::NoUriSan => "the certificate carries no URI SAN, so it is not an X.509-SVID".into(),
            SvidProblem::SeveralUriSans(n) => {
                format!("the certificate carries {n} URI SANs; an X.509-SVID carries exactly one, so it is invalid")
            }
            SvidProblem::NotSpiffe(e) => format!("the certificate's URI SAN is not a valid SPIFFE ID: {e}"),
            SvidProblem::IsCa => "the certificate is a CA certificate; an X.509-SVID leaf must not be a CA".into(),
            SvidProblem::KeyUsage(e) => format!("the certificate's key usage is not valid for an X.509-SVID leaf: {e}"),
        }
    }
}

/// Every URI SAN of a certificate, in order.
pub fn uri_sans(der: &[u8]) -> Result<Vec<String>, String> {
    let (_, cert) = X509Certificate::from_der(der).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    if let Ok(Some(ext)) = cert.subject_alternative_name() {
        for gn in &ext.value.general_names {
            if let GeneralName::URI(u) = gn {
                out.push(u.to_string());
            }
        }
    }
    Ok(out)
}

/// The leaf's SPIFFE ID when it carries exactly one URI SAN that is a valid
/// SPIFFE ID (evidence for any TLS server; not a verification).
pub fn peer_spiffe_id(der: &[u8]) -> Option<String> {
    let sans = uri_sans(der).ok()?;
    match sans.as_slice() {
        [one] => parse_id(one).ok().map(|id| id.as_uri()),
        _ => None,
    }
}

/// Check the X.509-SVID leaf shape and return its SPIFFE ID.
pub fn svid_id(der: &[u8]) -> Result<SpiffeId, SvidProblem> {
    let (_, cert) = X509Certificate::from_der(der).map_err(|e| SvidProblem::Unparseable(e.to_string()))?;
    let mut uris = Vec::new();
    if let Ok(Some(ext)) = cert.subject_alternative_name() {
        for gn in &ext.value.general_names {
            if let GeneralName::URI(u) = gn {
                uris.push(u.to_string());
            }
        }
    }
    let uri = match uris.as_slice() {
        [] => return Err(SvidProblem::NoUriSan),
        [one] => one.clone(),
        many => return Err(SvidProblem::SeveralUriSans(many.len())),
    };
    let id = parse_id(&uri).map_err(SvidProblem::NotSpiffe)?;
    if cert.basic_constraints().ok().flatten().map(|bc| bc.value.ca).unwrap_or(false) {
        return Err(SvidProblem::IsCa);
    }
    match cert.key_usage() {
        Ok(Some(ku)) => {
            let ku = ku.value;
            if !ku.digital_signature() {
                return Err(SvidProblem::KeyUsage("digitalSignature is not set".into()));
            }
            if ku.key_cert_sign() || ku.crl_sign() {
                return Err(SvidProblem::KeyUsage("keyCertSign or cRLSign is set".into()));
            }
        }
        Ok(None) => return Err(SvidProblem::KeyUsage("the keyUsage extension is missing (digitalSignature is required)".into())),
        Err(e) => return Err(SvidProblem::KeyUsage(e.to_string())),
    }
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spiffe_id_grammar() {
        let id = parse_id("spiffe://cluster.local/ns/ferrum/sa/svc").unwrap();
        assert_eq!(id.trust_domain, "cluster.local");
        assert_eq!(id.path, "/ns/ferrum/sa/svc");
        assert!(parse_id("spiffe://cluster.local").unwrap().path.is_empty());
        for bad in [
            "https://cluster.local/ns/a",
            "spiffe://",
            "spiffe://Cluster.local/ns/a",
            "spiffe://cluster.local:8443/ns/a",
            "spiffe://user@cluster.local/ns/a",
            "spiffe://cluster.local/ns//a",
            "spiffe://cluster.local/ns/a/",
            "spiffe://cluster.local/ns/../a",
            "spiffe://cluster.local/ns/a?x=1",
            "spiffe://cluster.local/ns/a#f",
            "spiffe://cluster.local/ns/a b",
        ] {
            assert!(parse_id(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn trust_domain_forms() {
        assert_eq!(parse_trust_domain("cluster.local").unwrap(), "cluster.local");
        assert_eq!(parse_trust_domain("spiffe://cluster.local").unwrap(), "cluster.local");
        assert!(parse_trust_domain("spiffe://cluster.local/ns/a").is_err());
        assert!(parse_trust_domain("Cluster.Local").is_err());
        assert!(parse_trust_domain("").is_err());
    }
}
