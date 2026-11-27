//! SOAP WS-Security header: UsernameToken (PasswordText / PasswordDigest),
//! an optional wsu:Timestamp, verbatim embedding of a user-supplied SAML
//! assertion (Anvil never mints assertions), and an optional X.509 XML
//! signature (XML-DSig) over the Body, the Timestamp and the UsernameToken.
//!
//! The header is inserted into the existing envelope by byte position (found
//! with a DTD-free XML parser), so the rest of the user's envelope bytes are
//! preserved exactly; a signed Body only gains its `wsu:Id` (and the `wsu`
//! declaration it needs) in its start tag. A signature follows the WS-Security
//! X.509 Token Profile: the certificate is a `wsse:BinarySecurityToken`
//! (X509v3) referenced from `ds:KeyInfo` by a `wsse:SecurityTokenReference`;
//! `ds:SignedInfo` and every Reference use Exclusive XML Canonicalization
//! ([`crate::c14n`]) and SHA-256 digests; the signature is RSA-SHA256 or
//! ECDSA-P256-SHA256 ([`crate::xmldsig`]).
use crate::AuthError;
use crate::c14n;
use crate::xmldsig::{self, SigningIdentity};
use anvil_domain::auth::WssePasswordType;
use anvil_domain::{SecondsFormat, TimeDelta, Timestamp};
use anvil_xml_limits::{XmlLimits, check_xml_limits};
use base64::Engine;
use sha1::{Digest, Sha1};

const WSSE_NS: &str = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
const WSU_NS: &str = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
const PW_TEXT: &str = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText";
const PW_DIGEST: &str = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest";
const B64_ENC: &str = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary";
/// The X.509 Token Profile's single-certificate token type.
pub const X509V3: &str = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3";
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

/// The text as the generated Security header writes it: the five XML
/// predefined entities, nothing else. The engine's redactor registers this
/// form of every secret, so a value written here is recognised.
pub fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&apos;")
}

pub fn security_header(
    username: &str,
    password: &str,
    ptype: WssePasswordType,
    ttl: Option<u32>,
    saml: Option<&str>,
    now: Timestamp,
    nonce: &[u8],
) -> String {
    let created = now.to_rfc3339_opts(SecondsFormat::Secs, true);
    let mut s = format!(r#"<wsse:Security xmlns:wsse="{WSSE_NS}" xmlns:wsu="{WSU_NS}">"#);
    if let Some(t) = ttl {
        let expires = (now + TimeDelta::seconds(t as i64)).to_rfc3339_opts(SecondsFormat::Secs, true);
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
    /// What was signed, when the header carries an X.509 signature.
    pub signed: Option<Signed>,
}

/// Shows sizes and the signature facts only: the body and the token secrets
/// can hold credentials.
impl std::fmt::Debug for Inserted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Inserted")
            .field("body_bytes", &self.body.len())
            .field("token_secrets", &self.token_secrets.len())
            .field("signed", &self.signed)
            .finish()
    }
}

/// Non-secret facts about an X.509 signature, for evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signed {
    /// `RSA-SHA256` or `ECDSA-P256-SHA256`.
    pub algorithm: &'static str,
    /// The `wsu:Id` of each signed element, in document order.
    pub references: Vec<String>,
    /// Hex SHA-256 of the certificate sent in the BinarySecurityToken.
    pub certificate_sha256: String,
}

/// What one Security header holds.
pub struct HeaderSpec<'a> {
    /// Username, password and password type; `None` sends no UsernameToken.
    pub username_token: Option<(&'a str, &'a str, WssePasswordType)>,
    /// Add a `wsu:Timestamp` with this lifetime in seconds.
    pub timestamp_ttl_secs: Option<u32>,
    /// A signed SAML assertion to embed verbatim.
    pub saml: Option<&'a str>,
    /// Sign the Body, the Timestamp and the UsernameToken.
    pub signature: Option<SignatureSpec<'a>>,
}

/// The X.509 signature to add.
pub struct SignatureSpec<'a> {
    pub identity: &'a SigningIdentity,
    /// InclusiveNamespaces PrefixList for every Reference's exclusive
    /// canonicalization (`""` is the default namespace). Usually empty.
    pub inclusive_prefixes: &'a [String],
}

/// Byte offset just past the `>` closing the start tag at the start of
/// `tag`, skipping `>` characters inside single- or double-quoted attribute
/// values (a literal `>` is legal there). `None` when no unquoted `>` exists.
fn start_tag_end(tag: &str) -> Option<usize> {
    let bytes = tag.as_bytes();
    let mut quote: Option<u8> = None;
    for (i, &b) in bytes.iter().enumerate() {
        match quote {
            Some(q) if b == q => quote = None,
            Some(_) => {}
            None if b == b'"' || b == b'\'' => quote = Some(b),
            None if b == b'>' => return Some(i + 1),
            None => {}
        }
    }
    None
}

/// Insert a fresh Security header into the SOAP envelope.
pub fn insert_security(
    body: &[u8],
    username: &str,
    password: &str,
    ptype: WssePasswordType,
    ttl: Option<u32>,
    saml: Option<&str>,
    now: Timestamp,
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
    now: Timestamp,
) -> Result<Inserted, AuthError> {
    let spec = HeaderSpec { username_token: Some((username, password, ptype)), timestamp_ttl_secs: ttl, saml, signature: None };
    insert(body, &spec, now)
}

/// Parse an envelope (or a rewrite of one) within the XML limits. `what`
/// starts each refusal (`SOAP envelope`, `WS-Security envelope`).
fn parse_bounded<'t>(text: &'t str, what: &str, malformed: &str) -> Result<roxmltree::Document<'t>, AuthError> {
    // Counted in one pass before the parser does work that grows with the
    // square of the namespace declarations or of an element's attributes.
    // The scan stops at a DOCTYPE, which the parser then refuses.
    check_xml_limits(text, &ENVELOPE_XML_LIMITS).map_err(|e| AuthError::Invalid(format!("{what} is too complex to parse safely: {e}")))?;
    let opts = roxmltree::ParsingOptions { allow_dtd: false, nodes_limit: MAX_ENVELOPE_NODES, ..Default::default() };
    roxmltree::Document::parse_with_options(text, opts).map_err(|e| match e {
        roxmltree::Error::NodesLimitReached => {
            AuthError::Invalid(format!("{what} is too complex to parse safely: more than {MAX_ENVELOPE_NODES} nodes"))
        }
        e => AuthError::Invalid(format!("{malformed}: {e}")),
    })
}

/// An element id no envelope already uses: `prefix-` and 16 random hex digits.
fn fresh_id(prefix: &str) -> String {
    let b: [u8; 8] = rand::random();
    format!("{prefix}-{}", hex::encode(b))
}

/// The one element whose `wsu:Id` is `id`.
fn by_wsu_id<'a, 'i>(doc: &'a roxmltree::Document<'i>, id: &str) -> Result<roxmltree::Node<'a, 'i>, AuthError> {
    let mut found = doc.descendants().filter(|n| n.is_element() && n.attribute((WSU_NS, "Id")) == Some(id));
    let node = found.next().ok_or_else(|| AuthError::Invalid(format!("no element has the wsu:Id '{id}' to sign")))?;
    if found.next().is_some() {
        return Err(AuthError::Invalid(format!(
            "several elements of the envelope have the wsu:Id '{id}'; a signed id must be unique (XML signature wrapping)"
        )));
    }
    Ok(node)
}

/// The canonicalizer the signer uses: the one place to change to swap in
/// another implementation of [`c14n::Canonicalizer`].
fn canonicalizer() -> &'static dyn c14n::Canonicalizer {
    &c14n::Native
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Insert a fresh Security header, as `spec` describes, into the SOAP
/// envelope.
pub fn insert(body: &[u8], spec: &HeaderSpec<'_>, now: Timestamp) -> Result<Inserted, AuthError> {
    if spec.username_token.is_none() && spec.timestamp_ttl_secs.is_none() && spec.saml.is_none() && spec.signature.is_none() {
        return Err(AuthError::Invalid(
            "the WS-Security header would be empty: add a UsernameToken, a Timestamp, a SAML assertion or an X.509 signature".into(),
        ));
    }
    let signing = spec.signature.as_ref();
    // Unsigned headers keep their fixed ids; signed ones get fresh ids that
    // cannot collide with ids already in the envelope.
    let (ts_id, ut_id) = if signing.is_some() { (fresh_id("TS"), fresh_id("UT")) } else { ("TS-1".to_string(), "UT-1".to_string()) };
    let created = now.to_rfc3339_opts(SecondsFormat::Secs, true);
    // Fresh per send from the thread-local CSPRNG (OS-seeded ChaCha).
    let nonce: [u8; 16] = rand::random();

    // The Security header up to (not including) its end tag.
    let mut security = format!(r#"<wsse:Security xmlns:wsse="{WSSE_NS}" xmlns:wsu="{WSU_NS}">"#);
    if let Some(t) = spec.timestamp_ttl_secs {
        let expires = (now + TimeDelta::seconds(t as i64)).to_rfc3339_opts(SecondsFormat::Secs, true);
        security.push_str(&format!(
            r#"<wsu:Timestamp wsu:Id="{ts_id}"><wsu:Created>{created}</wsu:Created><wsu:Expires>{expires}</wsu:Expires></wsu:Timestamp>"#
        ));
    }
    let mut token_secrets = Vec::new();
    if let Some((username, password, ptype)) = spec.username_token {
        let nonce_b64 = b64(&nonce);
        let (ptype_uri, pw) = match ptype {
            WssePasswordType::PasswordText => (PW_TEXT, xml_escape(password)),
            WssePasswordType::PasswordDigest => {
                let digest = password_digest(&nonce, &created, password);
                token_secrets = vec![digest.clone(), nonce_b64.clone()];
                (PW_DIGEST, digest)
            }
        };
        security.push_str(&format!(
            r#"<wsse:UsernameToken wsu:Id="{ut_id}"><wsse:Username>{}</wsse:Username><wsse:Password Type="{ptype_uri}">{pw}</wsse:Password><wsse:Nonce EncodingType="{B64_ENC}">{nonce_b64}</wsse:Nonce><wsu:Created>{created}</wsu:Created></wsse:UsernameToken>"#,
            xml_escape(username)
        ));
    }
    if let Some(a) = spec.saml {
        security.push_str(a.trim());
    }
    let token_id = fresh_id("X509");
    if let Some(sig) = signing {
        security.push_str(&format!(
            r#"<wsse:BinarySecurityToken EncodingType="{B64_ENC}" ValueType="{X509V3}" wsu:Id="{token_id}">{}</wsse:BinarySecurityToken>"#,
            b64(sig.identity.certificate_der())
        ));
    }
    const SECURITY_END: &str = "</wsse:Security>";

    let text = std::str::from_utf8(body).map_err(|_| AuthError::Invalid("SOAP envelope is not UTF-8".into()))?;
    let doc = parse_bounded(text, "SOAP envelope", "SOAP envelope is not well-formed XML")?;
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
    let body_el = env.children().find(|n| n.is_element() && n.tag_name().name() == "Body");

    // Where the header goes: `at..replace_end` of the original text becomes
    // `open` + header + `close`.
    let (at, replace_end, open, close) = if let Some(header) = env.children().find(|n| n.is_element() && n.tag_name().name() == "Header") {
        // Insert right after the Header start tag. The tag may carry quoted
        // attribute values containing a literal `>`, so the boundary scan
        // must be quote-aware rather than taking the first `>`.
        let range = header.range();
        let start_tag_end = start_tag_end(&text[range.start..range.end])
            .map(|i| range.start + i)
            .ok_or_else(|| AuthError::Invalid("malformed Header".into()))?;
        if text[range.start..start_tag_end].ends_with("/>") {
            (range.start, range.end, format!("<{}>", qual("Header")), format!("</{}>", qual("Header")))
        } else {
            (start_tag_end, start_tag_end, String::new(), String::new())
        }
    } else {
        let b = body_el.ok_or_else(|| AuthError::Invalid("SOAP envelope has no Body".into()))?;
        let at = b.range().start;
        (at, at, format!("<{}>", qual("Header")), format!("</{}>", qual("Header")))
    };

    // A signed Body needs a wsu:Id: its own, or one added to its start tag
    // (with a `wsu` binding when none is in scope there).
    let mut body_id = None;
    let mut body_splice: Option<(usize, String)> = None;
    if signing.is_some() {
        let b = body_el.ok_or_else(|| AuthError::Invalid("SOAP envelope has no Body to sign".into()))?;
        if let Some(id) = b.attribute((WSU_NS, "Id")) {
            body_id = Some(id.to_string());
        } else {
            let id = fresh_id("Body");
            let (p, declare) = ["wsu", "wsu1", "anvilwsu"]
                .into_iter()
                .find_map(|p| match b.lookup_namespace_uri(Some(p)) {
                    Some(u) if u == WSU_NS => Some((p, false)),
                    None => Some((p, true)),
                    Some(_) => None,
                })
                .ok_or_else(|| AuthError::Invalid("the SOAP Body binds every candidate prefix for wsu:Id to another namespace".into()))?;
            let range = b.range();
            let end = start_tag_end(&text[range.start..range.end])
                .map(|i| range.start + i)
                .ok_or_else(|| AuthError::Invalid("malformed Body".into()))?;
            let pos = if text[..end].ends_with("/>") { end - 2 } else { end - 1 };
            let decl = if declare { format!(r#" xmlns:{p}="{WSU_NS}""#) } else { String::new() };
            body_splice = Some((pos, format!(r#"{decl} {p}:Id="{id}""#)));
            body_id = Some(id);
        }
    }

    // Splice the header (and the Body id) in, back to front so earlier
    // offsets stay valid.
    let mut out = String::with_capacity(text.len() + security.len() + 4096);
    out.push_str(text);
    let header_text = format!("{open}{security}{SECURITY_END}{close}");
    let mut header_pos = at;
    match &body_splice {
        Some((pos, s)) if *pos > at => {
            out.insert_str(*pos, s);
            out.replace_range(at..replace_end, &header_text);
        }
        Some((pos, s)) => {
            out.replace_range(at..replace_end, &header_text);
            out.insert_str(*pos, s);
            header_pos += s.len();
        }
        None => out.replace_range(at..replace_end, &header_text),
    }
    drop(doc);

    let mut signed = None;
    if let Some(sig) = signing {
        let signature_at = header_pos + open.len() + security.len();
        let doc = parse_bounded(&out, "WS-Security envelope", "rewritten SOAP envelope is not well-formed XML")?;
        let opts = c14n::Options { with_comments: false, inclusive_prefixes: sig.inclusive_prefixes.to_vec() };
        let mut ids = Vec::new();
        if spec.timestamp_ttl_secs.is_some() {
            ids.push(ts_id.clone());
        }
        if spec.username_token.is_some() {
            ids.push(ut_id.clone());
        }
        ids.push(body_id.clone().unwrap_or_default());
        let transform = if sig.inclusive_prefixes.is_empty() {
            format!(r#"<ds:Transform Algorithm="{}"/>"#, c14n::EXC_C14N)
        } else {
            format!(
                r#"<ds:Transform Algorithm="{0}"><ec:InclusiveNamespaces xmlns:ec="{0}" PrefixList="{1}"/></ds:Transform>"#,
                c14n::EXC_C14N,
                xml_escape(&c14n::format_prefix_list(sig.inclusive_prefixes))
            )
        };
        // Each signed id must name exactly one element (XML signature
        // wrapping), checked here whichever canonicalizer is used.
        let mut starts = Vec::new();
        for id in &ids {
            starts.push(by_wsu_id(&doc, id)?.range().start);
        }
        drop(doc);
        let targets: Vec<c14n::Target> = starts.iter().map(|&at| c14n::Target::ElementAt(at)).collect();
        let canonical = canonicalizer().canonicalize(&out, &targets, &opts).map_err(|e| AuthError::Invalid(e.to_string()))?;
        let mut references = String::new();
        for (id, canonical) in ids.iter().zip(&canonical) {
            let digest = b64(sha2::Sha256::digest(canonical.as_bytes()).as_ref());
            references.push_str(&format!(
                r##"<ds:Reference URI="#{}"><ds:Transforms>{transform}</ds:Transforms><ds:DigestMethod Algorithm="{}"/><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference>"##,
                xml_escape(id),
                xmldsig::DIGEST_SHA256
            ));
        }
        let signature_open = format!(r#"<ds:Signature xmlns:ds="{}">"#, xmldsig::DS_NS);
        let signed_info = format!(
            r#"<ds:SignedInfo><ds:CanonicalizationMethod Algorithm="{}"/><ds:SignatureMethod Algorithm="{}"/>{references}</ds:SignedInfo>"#,
            c14n::EXC_C14N,
            sig.identity.algorithm().uri()
        );
        let head = format!("{signature_open}{signed_info}<ds:SignatureValue>");
        let tail = format!(
            r##"</ds:SignatureValue><ds:KeyInfo><wsse:SecurityTokenReference><wsse:Reference URI="#{token_id}" ValueType="{X509V3}"/></wsse:SecurityTokenReference></ds:KeyInfo></ds:Signature>"##
        );
        out.insert_str(signature_at, &format!("{head}{tail}"));
        // SignedInfo is canonicalized where it stands, with the namespaces
        // it inherits from the envelope.
        parse_bounded(&out, "WS-Security envelope", "rewritten SOAP envelope is not well-formed XML")?;
        let signed_info_at = c14n::Target::ElementAt(signature_at + signature_open.len());
        let canonical_signed_info = canonicalizer()
            .canonicalize(&out, &[signed_info_at], &c14n::Options::default())
            .map_err(|e| AuthError::Invalid(e.to_string()))?
            .pop()
            .ok_or_else(|| AuthError::Invalid("the generated ds:SignedInfo could not be canonicalized".into()))?;
        let value = sig.identity.sign(canonical_signed_info.as_bytes())?;
        out.insert_str(signature_at + head.len(), &b64(&value));
        signed = Some(Signed {
            algorithm: sig.identity.algorithm().label(),
            references: ids,
            certificate_sha256: sig.identity.certificate_sha256(),
        });
    }

    // The splice is textual; never return a rewrite that no longer parses.
    // The rewrite holds content the scan above never saw (a configured SAML
    // assertion, and the Security header's declarations in the envelope's
    // scope), so it is bounded the same way before this parse.
    parse_bounded(&out, "WS-Security envelope", "rewritten SOAP envelope is not well-formed XML")?;
    Ok(Inserted { body: out.into_bytes(), token_secrets, signed })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A password made per run: only the audited vectors depend on its value.
    fn password() -> String {
        let bytes: [u8; 12] = rand::random();
        hex::encode(bytes)
    }

    #[test]
    fn audited_digest_vectors() {
        let nonce = hex::decode("746573742d6e6f6e63652d3132333435").unwrap();
        assert_eq!(password_digest(&nonce, "2026-01-01T00:00:00.000Z", "secret123"), "lbfI40Phe5aULmg1VUCQQo+Of+4=");
        assert_eq!(password_digest(&nonce, "2026-01-01T00:00:00Z", "secret123"), "Vwk1Tx9Lm4QOBwZQ9VxrVM4/irM=");
    }

    #[test]
    fn inserts_into_header_with_quoted_greater_than_attribute() {
        // A literal `>` inside a quoted Header attribute value is legal XML
        // and must not be mistaken for the start-tag boundary.
        for note in [r#"x:note="a>b""#, "x:note='a>b'"] {
            let env = format!(
                r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:x="urn:x"><soap:Header {note}></soap:Header><soap:Body><m:Ping xmlns:m="urn:x">1</m:Ping></soap:Body></soap:Envelope>"#
            );
            let out =
                insert_security(env.as_bytes(), "alice", &password(), WssePasswordType::PasswordDigest, Some(300), None, Timestamp::now())
                    .unwrap();
            let s = String::from_utf8(out).unwrap();
            let doc = roxmltree::Document::parse(&s).unwrap();
            let header =
                doc.descendants().find(|n| n.is_element() && n.tag_name().name() == "Header").expect("Header survives the rewrite");
            assert!(
                header.children().any(|n| n.is_element() && n.tag_name().name() == "Security"),
                "Security is a child of Header in: {s}"
            );
        }
    }

    #[test]
    fn inserts_header_preserving_body_bytes() {
        let env = br#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><m:Ping xmlns:m="urn:x">1</m:Ping></soap:Body></soap:Envelope>"#;
        let pw = password();
        let out = insert_security(env, "alice", &pw, WssePasswordType::PasswordDigest, Some(300), None, Timestamp::now()).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("<soap:Header><wsse:Security"));
        assert!(s.contains(r#"<soap:Body><m:Ping xmlns:m="urn:x">1</m:Ping></soap:Body>"#));
        assert!(!s.contains(&pw), "digest mode never sends the password");
        roxmltree::Document::parse(&s).unwrap();
    }

    /// The digest and nonce registered for redaction are the ones the header carries.
    #[test]
    fn a_password_digest_token_reports_its_digest_and_nonce_as_secrets() {
        let env = br#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body/></soap:Envelope>"#;
        let i =
            insert_security_token(env, "alice", &password(), WssePasswordType::PasswordDigest, Some(300), None, Timestamp::now()).unwrap();
        let s = String::from_utf8(i.body).unwrap();
        let [digest, nonce] = i.token_secrets.as_slice() else {
            panic!("{} token secrets, not the digest and the nonce", i.token_secrets.len())
        };
        assert!(s.contains(&format!("#PasswordDigest\">{digest}</wsse:Password>")), "the digest is not the one sent");
        assert!(s.contains(&format!("#Base64Binary\">{nonce}</wsse:Nonce>")), "the nonce is not the one sent");
        let text = insert_security_token(env, "alice", &password(), WssePasswordType::PasswordText, None, None, Timestamp::now()).unwrap();
        assert!(text.token_secrets.is_empty(), "a PasswordText token has no secret but its password");
    }

    #[test]
    fn rejects_dtd_bearing_envelopes() {
        let env = br#"<!DOCTYPE x [<!ENTITY a "b">]><Envelope><Body/></Envelope>"#;
        assert!(insert_security(env, "a", &password(), WssePasswordType::PasswordText, None, None, Timestamp::now()).is_err());
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
        insert_security(env.as_bytes(), "alice", &password(), WssePasswordType::PasswordText, Some(300), None, Timestamp::now())
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

    fn insert_with_saml(env: &str, saml: &str) -> Result<Vec<u8>, AuthError> {
        insert_security(env.as_bytes(), "alice", &password(), WssePasswordType::PasswordText, Some(300), Some(saml), Timestamp::now())
    }

    /// The rewritten envelope is bounded before it is parsed again: a SAML
    /// assertion the original scan never saw cannot add unbounded attribute
    /// or namespace work (#384), while an ordinary assertion is embedded.
    #[test]
    fn refuses_a_saml_assertion_that_makes_the_envelope_too_complex() {
        let started = std::time::Instant::now();
        let env = envelope(16, "<m:Ping>1</m:Ping>");
        let attrs: String = (0..300).map(|i| format!(" a{i}=\"\"")).collect();
        let assertions = [
            (format!(r#"<saml:Assertion xmlns:saml="urn:s"{attrs}>x</saml:Assertion>"#), "more than 256 attributes on one element"),
            (
                format!(r#"<saml:Assertion xmlns:saml="urn:s">{}</saml:Assertion>"#, nested_namespaces(200)),
                "more than 128 namespace declarations in scope of one element",
            ),
        ];
        for (saml, why) in &assertions {
            let e = insert_with_saml(&env, saml).expect_err(why).to_string();
            assert!(e.starts_with("WS-Security envelope is too complex to parse safely: "), "{e}");
            assert!(e.contains(why), "{e}");
        }
        assert!(started.elapsed() < std::time::Duration::from_secs(10), "took {:?}", started.elapsed());

        // Controls: an ordinary assertion and none at all are both inserted.
        let saml = r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="a1">ok</saml:Assertion>"#;
        let out = String::from_utf8(insert_with_saml(&env, saml).unwrap()).unwrap();
        roxmltree::Document::parse(&out).unwrap();
        assert!(out.contains(saml), "{out}");
        assert!(insert(&env).is_ok());
        // A malformed assertion is still refused as malformed, not embedded.
        let e = insert_with_saml(&env, "<saml:Assertion xmlns:saml=\"urn:s\">").unwrap_err().to_string();
        assert!(e.starts_with("rewritten SOAP envelope is not well-formed XML"), "{e}");
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
