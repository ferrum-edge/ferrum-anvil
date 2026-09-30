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
use anvil_xml_limits::{XmlLimits, check_xml_limits};
use base64::Engine;
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use sha1::{Digest, Sha1};

const WSSE_NS: &str = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
const WSU_NS: &str = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
const PW_TEXT: &str = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText";
const PW_DIGEST: &str = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest";
const B64_ENC: &str = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary";
/// XML nodes one envelope may have, as a request body lint allows.
const MAX_ENVELOPE_NODES: u32 = 1_000_000;
/// What an envelope may contain before it is parsed (it can come from an
/// imported collection). The parser compares each attribute with every
/// earlier one on its element, names and full namespace URIs; for each
/// element that declares a namespace it copies the n in scope, checking each
/// against those already copied (about n²/2 prefix comparisons); and it looks
/// every element and prefixed attribute name up among the namespaces in
/// scope. As for a request body lint: names, prefixes and URIs as long as a
/// WSDL import allows, about 2^20 attribute comparisons, 2^23 prefix
/// comparisons while copying scopes, 2^19 copied namespace references, and
/// 129 comparisons per name looked up.
const ENVELOPE_XML_LIMITS: XmlLimits = XmlLimits {
    attributes_per_element: 256,
    attribute_pairs: 1 << 20,
    attribute_name_bytes: 1_024,
    xmlns_declarations: 4_096,
    xmlns_prefix_bytes: 256,
    xmlns_uri_bytes: 2_048,
    in_scope_namespaces: 128,
    namespace_scope_work: 1 << 24,
};

/// PasswordDigest = Base64(SHA-1(nonce_bytes || created || password)).
pub fn password_digest(nonce: &[u8], created: &str, password: &str) -> String {
    let mut h = Sha1::new();
    h.update(nonce);
    h.update(created.as_bytes());
    h.update(password.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(h.finalize())
}

pub(crate) fn xml_escape(s: &str) -> String {
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

/// A Security header inserted for one send.
pub struct Inserted {
    /// The envelope with the header.
    pub body: Vec<u8>,
    /// The per-send parts of the UsernameToken that authenticate on their
    /// own: a PasswordDigest (with its Nonce) can be replayed against a
    /// service that keeps no nonce cache or Timestamp limit, so both are
    /// secrets of the request. Empty for PasswordText, whose password is the
    /// secret. The `Created` time is not secret.
    pub token_secrets: Vec<String>,
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
    insert_security_token(body, username, password, ptype, ttl, saml, now).map(|i| i.body)
}

/// [`insert_security`], with the parts of the UsernameToken that must be
/// redacted wherever the request is recorded.
pub fn insert_security_token(
    body: &[u8],
    username: &str,
    password: &str,
    ptype: WssePasswordType,
    ttl: Option<u32>,
    saml: Option<&str>,
    now: DateTime<Utc>,
) -> Result<Inserted, AuthError> {
    let mut nonce = [0u8; 16];
    rand::fill(&mut nonce);
    let header_xml = security_header(username, password, ptype, ttl, saml, now, &nonce);
    let token_secrets = match ptype {
        WssePasswordType::PasswordText => vec![],
        WssePasswordType::PasswordDigest => {
            let created = now.to_rfc3339_opts(SecondsFormat::Secs, true);
            vec![password_digest(&nonce, &created, password), base64::engine::general_purpose::STANDARD.encode(nonce)]
        }
    };
    let text = std::str::from_utf8(body).map_err(|_| AuthError::Invalid("SOAP envelope is not UTF-8".into()))?;
    // Counted in one pass before the parser does work that grows with the
    // square of the namespace declarations or of an element's attributes.
    // The scan stops at a DOCTYPE, which the parser then refuses.
    check_xml_limits(text, &ENVELOPE_XML_LIMITS)
        .map_err(|e| AuthError::Invalid(format!("SOAP envelope is too complex to parse safely: {e}")))?;
    let opts = roxmltree::ParsingOptions { allow_dtd: false, nodes_limit: MAX_ENVELOPE_NODES, ..Default::default() };
    let doc = roxmltree::Document::parse_with_options(text, opts).map_err(|e| match e {
        roxmltree::Error::NodesLimitReached => {
            AuthError::Invalid(format!("SOAP envelope is too complex to parse safely: more than {MAX_ENVELOPE_NODES} nodes"))
        }
        e => AuthError::Invalid(format!("SOAP envelope is not well-formed XML: {e}")),
    })?;
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
    Ok(Inserted { body: out.into_bytes(), token_secrets })
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

    /// The digest and nonce registered for redaction are the ones the header carries.
    #[test]
    fn a_password_digest_token_reports_its_digest_and_nonce_as_secrets() {
        let env = br#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body/></soap:Envelope>"#;
        let i = insert_security_token(env, "alice", "secret123", WssePasswordType::PasswordDigest, Some(300), None, Utc::now()).unwrap();
        let s = String::from_utf8(i.body).unwrap();
        let [digest, nonce] = i.token_secrets.as_slice() else {
            panic!("{} token secrets, not the digest and the nonce", i.token_secrets.len())
        };
        assert!(s.contains(&format!("#PasswordDigest\">{digest}</wsse:Password>")), "the digest is not the one sent");
        assert!(s.contains(&format!("#Base64Binary\">{nonce}</wsse:Nonce>")), "the nonce is not the one sent");
        let text = insert_security_token(env, "alice", "secret123", WssePasswordType::PasswordText, None, None, Utc::now()).unwrap();
        assert!(text.token_secrets.is_empty(), "a PasswordText token has no secret but its password");
    }

    #[test]
    fn rejects_dtd_bearing_envelopes() {
        let env = br#"<!DOCTYPE x [<!ENTITY a "b">]><Envelope><Body/></Envelope>"#;
        assert!(insert_security(env, "a", "b", WssePasswordType::PasswordText, None, None, Utc::now()).is_err());
    }

    const SOAP_NS: &str = "http://schemas.xmlsoap.org/soap/envelope/";

    /// An envelope binding `m` to a URI of `uri_bytes`, with `body` in its Body.
    fn envelope(uri_bytes: usize, body: &str) -> String {
        let uri = "u".repeat(uri_bytes);
        format!(r#"<soap:Envelope xmlns:soap="{SOAP_NS}" xmlns:m="{uri}"><soap:Body>{body}</soap:Body></soap:Envelope>"#)
    }

    /// `depth` nested elements that each declare a namespace.
    fn nested_namespaces(depth: usize) -> String {
        let mut s = String::new();
        for i in 0..depth {
            s.push_str(&format!("<e xmlns:p{i}=\"urn:n{i}\">"));
        }
        s.push_str(&"</e>".repeat(depth));
        s
    }

    /// `elements` elements with `attributes` attributes each in the `m` namespace.
    fn wide_elements(elements: usize, attributes: usize) -> String {
        let mut s = String::new();
        for _ in 0..elements {
            s.push_str("<m:c");
            for i in 0..attributes {
                s.push_str(&format!(" m:a{i}=\"\""));
            }
            s.push_str("/>");
        }
        s
    }

    fn insert(env: &str) -> Result<Vec<u8>, AuthError> {
        insert_security(env.as_bytes(), "alice", "secret123", WssePasswordType::PasswordText, Some(300), None, Utc::now())
    }

    /// GHSA-mvjp-hhjj-mh63: an envelope whose namespace or attribute work
    /// grows with the square of its size is refused before it is parsed.
    #[test]
    fn refuses_envelopes_too_complex_to_parse() {
        let started = std::time::Instant::now();
        let envelopes = [
            (envelope(16, &nested_namespaces(5_000)), "more than 128 namespace declarations in scope of one element"),
            (envelope(16, &r#"<m:i xmlns:m="urn:m">v</m:i>"#.repeat(5_000)), "more than 4096 namespace declarations (xmlns)"),
            (envelope(2_000, &wide_elements(1, 300)), "more than 256 attributes on one element"),
            // Each element is within the per-element bound; together they are not.
            (envelope(2_000, &wide_elements(60, 200)), "attribute pairs"),
            (envelope(3_000, ""), "a namespace URI longer than 2048 bytes"),
        ];
        for (env, why) in &envelopes {
            let e = insert(env).expect_err(why).to_string();
            assert!(e.starts_with("SOAP envelope is too complex to parse safely: "), "{e}");
            assert!(e.contains(why), "{e}");
        }
        assert!(started.elapsed() < std::time::Duration::from_secs(10), "took {:?}", started.elapsed());
    }

    #[test]
    fn inserts_into_envelopes_within_the_limits() {
        let envelopes =
            [envelope(16, "<m:Ping>1</m:Ping>"), envelope(2_000, &wide_elements(20, 200)), envelope(16, &nested_namespaces(126))];
        for env in &envelopes {
            let out = String::from_utf8(insert(env).unwrap()).unwrap();
            assert!(out.contains("<soap:Header><wsse:Security"), "{}", &out[..200]);
            assert!(out.ends_with("</soap:Body></soap:Envelope>"));
        }
    }

    /// The most namespace work the limits allow inside an envelope that
    /// declares two: the deepest chain of the longest prefixes, siblings until
    /// the scope budget is spent, and names the parser finds last in scope.
    #[test]
    fn inserts_into_an_envelope_at_the_namespace_limits_promptly() {
        let env = envelope(16, &anvil_xml_limits::test_support::namespace_worst_case(&ENVELOPE_XML_LIMITS, 2, 10_000));
        let started = std::time::Instant::now();
        let out = String::from_utf8(insert(&env).unwrap()).unwrap();
        assert!(out.contains("<soap:Header><wsse:Security"));
        assert!(started.elapsed() < std::time::Duration::from_secs(5), "took {:?}", started.elapsed());
    }
}
