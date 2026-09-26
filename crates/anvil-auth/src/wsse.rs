//! SOAP WS-Security UsernameToken (PasswordText / PasswordDigest) with an
//! optional wsu:Timestamp, and verbatim embedding of a user-supplied SAML
//! assertion (Anvil never mints assertions).
//!
//! The header is inserted into the existing envelope by byte position (found
//! with a DTD-free XML parser), so the rest of the user's envelope bytes are
//! preserved exactly. X.509 XML signatures are not produced: they require an
//! audited XML-DSig/C14N implementation, which is recorded as unavailable.

use crate::AuthError;
use anvil_domain::auth::WssePasswordType;
use base64::Engine;
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use sha1::{Digest, Sha1};

const WSSE_NS: &str = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
const WSU_NS: &str = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
const PW_TEXT: &str = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText";
const PW_DIGEST: &str = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest";
const B64_ENC: &str = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary";

/// PasswordDigest = Base64(SHA-1(nonce_bytes || created || password)).
pub fn password_digest(nonce: &[u8], created: &str, password: &str) -> String {
    let mut h = Sha1::new();
    h.update(nonce);
    h.update(created.as_bytes());
    h.update(password.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(h.finalize())
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&apos;")
}

pub fn security_header(
    username: &str,
    password: &str,
    ptype: WssePasswordType,
    ttl: Option<u32>,
    saml: Option<&str>,
    now: DateTime<Utc>,
    nonce: &[u8],
) -> String {
    let created = now.to_rfc3339_opts(SecondsFormat::Secs, true);
    let mut s = format!(r#"<wsse:Security xmlns:wsse="{WSSE_NS}" xmlns:wsu="{WSU_NS}">"#);
    if let Some(t) = ttl {
        let expires = (now + Duration::seconds(t as i64)).to_rfc3339_opts(SecondsFormat::Secs, true);
        s.push_str(&format!(
            r#"<wsu:Timestamp wsu:Id="TS-1"><wsu:Created>{created}</wsu:Created><wsu:Expires>{expires}</wsu:Expires></wsu:Timestamp>"#
        ));
    }
    let nonce_b64 = base64::engine::general_purpose::STANDARD.encode(nonce);
    let (ptype_uri, pw) = match ptype {
        WssePasswordType::PasswordText => (PW_TEXT, xml_escape(password)),
        WssePasswordType::PasswordDigest => (PW_DIGEST, password_digest(nonce, &created, password)),
    };
    s.push_str(&format!(
        r#"<wsse:UsernameToken wsu:Id="UT-1"><wsse:Username>{}</wsse:Username><wsse:Password Type="{ptype_uri}">{pw}</wsse:Password><wsse:Nonce EncodingType="{B64_ENC}">{nonce_b64}</wsse:Nonce><wsu:Created>{created}</wsu:Created></wsse:UsernameToken>"#,
        xml_escape(username)
    ));
    if let Some(a) = saml {
        s.push_str(a.trim());
    }
    s.push_str("</wsse:Security>");
    s
}

/// Insert a fresh Security header into the SOAP envelope.
pub fn insert_security(
    body: &[u8],
    username: &str,
    password: &str,
    ptype: WssePasswordType,
    ttl: Option<u32>,
    saml: Option<&str>,
    now: DateTime<Utc>,
) -> Result<Vec<u8>, AuthError> {
    let mut nonce = [0u8; 16];
    rand::fill(&mut nonce);
    let header_xml = security_header(username, password, ptype, ttl, saml, now, &nonce);
    let text = std::str::from_utf8(body).map_err(|_| AuthError::Invalid("SOAP envelope is not UTF-8".into()))?;
    let opts = roxmltree::ParsingOptions { allow_dtd: false, ..Default::default() };
    let doc = roxmltree::Document::parse_with_options(text, opts)
        .map_err(|e| AuthError::Invalid(format!("SOAP envelope is not well-formed XML: {e}")))?;
    let env = doc.root_element();
    if env.tag_name().name() != "Envelope" {
        return Err(AuthError::Invalid("WS-Security requires a SOAP Envelope body".into()));
    }
    if env.descendants().any(|n| n.is_element() && n.tag_name().name() == "Security") {
        return Err(AuthError::Invalid(
            "the envelope already contains a wsse:Security header; remove it or disable WS-Security auth".into(),
        ));
    }
    let env_ns = env.tag_name().namespace().unwrap_or("");
    let prefix = env.lookup_prefix(env_ns).unwrap_or("");
    let qual = |local: &str| if prefix.is_empty() { local.to_string() } else { format!("{prefix}:{local}") };
    let mut out = String::with_capacity(text.len() + header_xml.len() + 64);
    if let Some(header) = env.children().find(|n| n.is_element() && n.tag_name().name() == "Header") {
        // Insert right after the Header start tag.
        let range = header.range();
        let start_tag_end = text[range.start..range.end]
            .find('>')
            .map(|i| range.start + i + 1)
            .ok_or_else(|| AuthError::Invalid("malformed Header".into()))?;
        if text[range.start..start_tag_end].ends_with("/>") {
            out.push_str(&text[..range.start]);
            out.push_str(&format!("<{}>{header_xml}</{}>", qual("Header"), qual("Header")));
            out.push_str(&text[range.end..]);
        } else {
            out.push_str(&text[..start_tag_end]);
            out.push_str(&header_xml);
            out.push_str(&text[start_tag_end..]);
        }
    } else {
        let body_el = env
            .children()
            .find(|n| n.is_element() && n.tag_name().name() == "Body")
            .ok_or_else(|| AuthError::Invalid("SOAP envelope has no Body".into()))?;
        let at = body_el.range().start;
        out.push_str(&text[..at]);
        out.push_str(&format!("<{}>{header_xml}</{}>", qual("Header"), qual("Header")));
        out.push_str(&text[at..]);
    }
    Ok(out.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audited_digest_vectors() {
        let nonce = hex::decode("746573742d6e6f6e63652d3132333435").unwrap();
        assert_eq!(password_digest(&nonce, "2026-01-01T00:00:00.000Z", "secret123"), "lbfI40Phe5aULmg1VUCQQo+Of+4=");
        assert_eq!(password_digest(&nonce, "2026-01-01T00:00:00Z", "secret123"), "Vwk1Tx9Lm4QOBwZQ9VxrVM4/irM=");
    }

    #[test]
    fn inserts_header_preserving_body_bytes() {
        let env = br#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><m:Ping xmlns:m="urn:x">1</m:Ping></soap:Body></soap:Envelope>"#;
        let out = insert_security(env, "alice", "secret123", WssePasswordType::PasswordDigest, Some(300), None, Utc::now()).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("<soap:Header><wsse:Security"));
        assert!(s.contains(r#"<soap:Body><m:Ping xmlns:m="urn:x">1</m:Ping></soap:Body>"#));
        assert!(!s.contains("secret123"), "digest mode never sends the password");
        roxmltree::Document::parse(&s).unwrap();
    }

    #[test]
    fn rejects_dtd_bearing_envelopes() {
        let env = br#"<!DOCTYPE x [<!ENTITY a "b">]><Envelope><Body/></Envelope>"#;
        assert!(insert_security(env, "a", "b", WssePasswordType::PasswordText, None, None, Utc::now()).is_err());
    }
}
