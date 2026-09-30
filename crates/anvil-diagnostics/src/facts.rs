//! Evidence normalization: turns an execution's raw observations into the
//! typed facts rules consume. Response bodies are parsed only for structure
//! (bounded, no DTDs, no external resolution) and are always untrusted data.
//!
//! Text a finding quotes from a response (a JSON `error`, a GraphQL or SOAP
//! fault message, a tunnel refusal body, a body signature) is an
//! [`excerpt`]: redacted with the caller's exact-value redactor before it is
//! cut, so a secret the response echoes across the cut is replaced whole
//! instead of leaving its prefix in the finding.

use anvil_domain::execution::*;
use anvil_domain::outcome::ProtocolStatus;
use anvil_domain::request::Protocol;
use anvil_xml_limits::{XmlLimits, check_xml_limits};

/// Whether the destination is an explicitly trusted Ferrum gateway.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum FerrumTrust {
    #[default]
    NotConfigured,
    Trusted {
        profile_name: String,
        compatibility_id: String,
        /// The client leg to the gateway was TLS with verification enabled
        /// and passing. Plain-HTTP (lab) trust caps confidence at `likely`.
        channel_authenticated: bool,
    },
}

/// Exact-value secret scrubber for evidence excerpts (the engine passes its
/// record redactor). `None`: excerpts are cut as received.
pub type Redact<'a> = Option<&'a dyn Fn(&str) -> String>;

/// How far past an excerpt's cut the redactor looks: a secret (in any form
/// the redactor knows) that starts before the cut and is at most this long
/// is recognized whole before the excerpt is cut.
pub const EXCERPT_LOOKAHEAD_BYTES: usize = 64 * 1024;

/// Inputs for one diagnosis. The engine assembles this from the shared
/// native execution; the UI/CLI never feed it anything else.
pub struct DiagnosticInput<'a> {
    pub protocol: Protocol,
    pub method: &'a str,
    /// Local preparation failure (no attempts were made).
    pub preparation_failure: Option<&'a TransportFailure>,
    pub attempts: &'a [AttemptObservation],
    pub response: Option<&'a ResponseRecord>,
    /// Captured response bytes after content decoding when available.
    pub body: &'a [u8],
    pub stream: Option<&'a StreamTranscript>,
    pub protocol_status: &'a ProtocolStatus,
    pub trust: &'a FerrumTrust,
    pub tls_verification_enabled: bool,
    pub credentials_stripped_on_redirect: bool,
    /// An automatic H3 → TCP fallback was used.
    pub protocol_fallback_from: Option<String>,
    /// SPIFFE Workload API calls, SVIDs and JWT-SVID checks of this execution.
    pub workload: Option<&'a anvil_domain::workload::WorkloadApiEvidence>,
    /// Redacts every excerpt a finding quotes before it is cut ([`excerpt`]).
    /// The record redacts findings again afterwards, but by then a secret
    /// that crossed a cut has lost its tail and no longer matches.
    pub redact: Redact<'a>,
}

/// Structural facts about a response body (bounded parsing).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BodyFacts {
    /// Top-level JSON `error` string, if the body is a JSON object with one.
    pub json_error: Option<String>,
    /// Canonical JSON text of the body (when valid JSON, ≤ 64 KiB).
    pub json_canonical: Option<serde_json::Value>,
    pub soap_fault: Option<SoapFault>,
    pub graphql: Option<GraphQlResult>,
    pub is_html: bool,
    /// Why a SOAP envelope (an XML body whose root element is `Envelope`)
    /// was not inspected for a fault: it is over the pre-parse limits
    /// (`SOAP_FAULT_XML_LIMITS`) or the node limit. A fault in it would go
    /// unseen, so the application outcome is not evaluated.
    pub xml_not_inspected: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoapFault {
    pub code: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphQlResult {
    pub error_count: usize,
    pub has_data: bool,
    pub first_message: String,
}

const MAX_PARSE: usize = 256 * 1024;
/// XML nodes parsed to find a SOAP fault.
const SOAP_FAULT_MAX_NODES: u32 = 50_000;
/// What an XML response body may contain before it is parsed for a SOAP
/// fault (every XML response up to [`MAX_PARSE`] bytes whose root is an
/// `Envelope` is). The parser compares each attribute with every earlier one
/// on its element, names and full namespace URIs; for each element that
/// declares a namespace it copies the n in scope, checking each against those
/// already copied (about n²/2 prefix comparisons); and it looks every element
/// and prefixed attribute name up among the namespaces in scope. With these
/// bounds that stays under 2^18 attribute comparisons of at most 768 bytes,
/// 2^21 prefix comparisons of at most 64 bytes while copying scopes,
/// 1024 · 128 = 2^17 copied namespace references, and 129 comparisons per
/// name looked up.
const SOAP_FAULT_XML_LIMITS: XmlLimits = XmlLimits {
    attributes_per_element: 256,
    attribute_pairs: 1 << 18,
    attribute_name_bytes: 256,
    xmlns_declarations: 1_024,
    xmlns_prefix_bytes: 64,
    xmlns_uri_bytes: 512,
    in_scope_namespaces: 128,
    namespace_scope_work: 1 << 22,
};

fn floor_char_boundary(s: &str, i: usize) -> usize {
    let mut end = i.min(s.len());
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    end
}

/// At most `max_chars` characters of `s`, redacted before the cut.
///
/// `s` is redacted up to [`EXCERPT_LOOKAHEAD_BYTES`] past the cut, then cut:
/// a secret that crosses the cut is replaced whole, and the excerpt ends
/// with the redaction marker where that secret starts. Nothing from past
/// the cut is shown. Without a redactor, `s` is only cut.
pub fn excerpt(redact: Redact<'_>, s: &str, max_chars: usize) -> String {
    let cut = s.char_indices().nth(max_chars).map_or(s.len(), |(i, _)| i);
    match redact {
        Some(r) => redact_then_cut(r, &s[..floor_char_boundary(s, cut.saturating_add(EXCERPT_LOOKAHEAD_BYTES))], cut),
        None => s[..cut].to_string(),
    }
}

/// `window` redacted, then cut at byte `cut` (a char boundary of `window`),
/// as the transport's session previews are: redacting either side of the
/// cut alone finds the same secrets as redacting the whole window unless a
/// secret crosses the cut, and then the part before it is kept.
fn redact_then_cut(redact: &dyn Fn(&str) -> String, window: &str, cut: usize) -> String {
    if cut >= window.len() {
        return redact(window);
    }
    let whole = redact(window);
    if whole == window {
        return window[..cut].to_string();
    }
    let head = redact(&window[..cut]);
    let tail = redact(&window[cut..]);
    if whole.len() == head.len() + tail.len() && whole.starts_with(&head) && whole.ends_with(&tail) {
        return head;
    }
    let same = whole.bytes().zip(head.bytes()).take_while(|(a, b)| a == b).count();
    let mut out = head[..floor_char_boundary(&head, same)].to_string();
    out.push_str(anvil_domain::secret::REDACTED);
    out
}

pub fn body_facts(content_type: Option<&str>, body: &[u8]) -> BodyFacts {
    body_facts_redacted(content_type, body, None)
}

/// [`body_facts`] with the quoted texts (JSON `error`, GraphQL and SOAP fault
/// messages) as redacted [`excerpt`]s. The parsed JSON used for signature
/// matching is kept as received.
pub fn body_facts_redacted(content_type: Option<&str>, body: &[u8], redact: Redact<'_>) -> BodyFacts {
    let mut f = BodyFacts::default();
    if body.is_empty() || body.len() > MAX_PARSE {
        return f;
    }
    let ct = content_type.unwrap_or("").to_ascii_lowercase();
    f.is_html = ct.contains("text/html");
    let trimmed = trim_ascii(body);
    if trimmed.first() == Some(&b'{') || trimmed.first() == Some(&b'[') {
        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(trimmed) {
            if let Some(obj) = v.as_object() {
                if let Some(e) = obj.get("error").and_then(|e| e.as_str()) {
                    f.json_error = Some(excerpt(redact, e, 300));
                }
                if let Some(errs) = obj.get("errors").and_then(|e| e.as_array())
                    && !errs.is_empty()
                    && errs.iter().all(|e| e.get("message").is_some())
                {
                    f.graphql = Some(GraphQlResult {
                        error_count: errs.len(),
                        has_data: obj.get("data").map(|d| !d.is_null()).unwrap_or(false),
                        first_message: excerpt(redact, errs[0].get("message").and_then(|m| m.as_str()).unwrap_or(""), 300),
                    });
                }
            }
            f.json_canonical = Some(v);
        }
    } else if (trimmed.first() == Some(&b'<')) && (ct.contains("xml") || ct.is_empty() || ct.contains("soap")) {
        match soap_fault(trimmed, redact) {
            Ok(fault) => f.soap_fault = fault,
            Err(why) => f.xml_not_inspected = Some(why),
        }
    }
    f
}

fn trim_ascii(b: &[u8]) -> &[u8] {
    let start = b.iter().position(|c| !c.is_ascii_whitespace()).unwrap_or(b.len());
    let end = b.iter().rposition(|c| !c.is_ascii_whitespace()).map(|i| i + 1).unwrap_or(start);
    &b[start..end.max(start)]
}

/// SOAP 1.1/1.2 fault detection. DTDs are refused, so no entity expansion
/// or external resolution can occur. Only a document whose root element is
/// an `Envelope` can carry a fault; any other body is not parsed. `Err` says
/// why an envelope was not inspected: it is over the pre-parse limits or
/// has more than `SOAP_FAULT_MAX_NODES` nodes. An envelope that is not
/// well-formed has no fault.
fn soap_fault(xml: &[u8], redact: Redact<'_>) -> Result<Option<SoapFault>, String> {
    let Ok(text) = std::str::from_utf8(xml) else { return Ok(None) };
    if !root_is_envelope(text) {
        return Ok(None);
    }
    // Counted in one pass before the parser does work that grows with the
    // square of the namespace declarations or of an element's attributes.
    // The scan stops at a DOCTYPE, which the parser then refuses.
    check_xml_limits(text, &SOAP_FAULT_XML_LIMITS).map_err(|e| e.to_string())?;
    let opts = roxmltree::ParsingOptions { allow_dtd: false, nodes_limit: SOAP_FAULT_MAX_NODES, ..Default::default() };
    match roxmltree::Document::parse_with_options(text, opts) {
        Ok(doc) => Ok(fault_in(&doc, redact)),
        Err(roxmltree::Error::NodesLimitReached) => Err(format!("more than {SOAP_FAULT_MAX_NODES} nodes")),
        Err(_) => Ok(None),
    }
}

/// Whether the first element of `text`, after the XML declaration, comments
/// and processing instructions, is named `Envelope` (with any prefix). A
/// DOCTYPE first is not: the parser refuses it.
fn root_is_envelope(text: &str) -> bool {
    let mut rest = text.trim_start();
    loop {
        let skipped = if let Some(r) = rest.strip_prefix("<?") {
            r.find("?>").map(|e| &r[e + 2..])
        } else if let Some(r) = rest.strip_prefix("<!--") {
            r.find("-->").map(|e| &r[e + 3..])
        } else {
            break;
        };
        match skipped {
            Some(r) => rest = r.trim_start(),
            None => return false,
        }
    }
    let Some(tag) = rest.strip_prefix('<') else { return false };
    let name = &tag[..tag.find(|c: char| c.is_ascii_whitespace() || c == '>' || c == '/').unwrap_or(tag.len())];
    name.rsplit(':').next() == Some("Envelope")
}

fn fault_in(doc: &roxmltree::Document<'_>, redact: Redact<'_>) -> Option<SoapFault> {
    let root = doc.root_element();
    if root.tag_name().name() != "Envelope" {
        return None;
    }
    let body = root.children().find(|n| n.is_element() && n.tag_name().name() == "Body")?;
    let fault = body.children().find(|n| n.is_element() && n.tag_name().name() == "Fault")?;
    let child_text = |names: &[&str]| -> String {
        for d in fault.descendants() {
            if d.is_element() && names.contains(&d.tag_name().name()) {
                let t: String = d.descendants().filter(|x| x.is_text()).map(|x| x.text().unwrap_or("")).collect::<String>();
                let t = t.trim().to_string();
                if !t.is_empty() {
                    return excerpt(redact, &t, 300);
                }
            }
        }
        String::new()
    };
    Some(SoapFault { code: child_text(&["faultcode", "Value"]), reason: child_text(&["faultstring", "Text"]) })
}

/// Case-insensitive header values from a response.
pub fn header_values<'a>(resp: &'a ResponseRecord, name: &str) -> Vec<&'a str> {
    resp.header_values(name)
}

pub fn is_idempotent(method: &str) -> bool {
    matches!(method.to_ascii_uppercase().as_str(), "GET" | "HEAD" | "OPTIONS" | "TRACE" | "PUT" | "DELETE")
}

#[cfg(test)]
mod tests {
    use super::*;
    use anvil_domain::secret::REDACTED;

    const SECRET: &str = "echoed-secret-9x2q";

    fn scrub(s: &str) -> String {
        s.replace(SECRET, REDACTED)
    }

    #[test]
    fn excerpts_are_redacted_before_they_are_cut() {
        let redact: Redact<'_> = Some(&scrub);
        // The cut (20 characters) falls after the secret's first 4 characters, then after all but its last.
        for keep in [4, SECRET.len() - 1] {
            let pad = "p".repeat(20 - keep);
            assert_eq!(excerpt(redact, &format!("{pad}{SECRET} and more"), 20), format!("{pad}{REDACTED}"), "keep {keep}");
        }
        // Positive controls: a secret wholly before the cut, wholly after it, no secret, a short text.
        assert_eq!(excerpt(redact, &format!("{SECRET} and more text after it"), 30), format!("{REDACTED} and more te"));
        assert_eq!(excerpt(redact, &format!("{} {SECRET}", "a".repeat(30)), 20), "a".repeat(20));
        assert_eq!(excerpt(redact, &"é".repeat(25), 20), "é".repeat(20), "the cut counts characters");
        assert_eq!(excerpt(redact, "short", 20), "short");
        // Without a redactor the text is only cut.
        assert_eq!(excerpt(None, &format!("{}{SECRET}", "p".repeat(16)), 20), format!("{}{}", "p".repeat(16), &SECRET[..4]));
    }

    #[test]
    fn quoted_body_texts_keep_no_prefix_of_a_secret_crossing_their_cut() {
        // The texts are cut at 300 characters, 4 characters into the secret.
        let redact: Redact<'_> = Some(&scrub);
        let pad = "e".repeat(296);
        let cut = format!("{pad}{REDACTED}");
        let json = format!(r#"{{"error":"{pad}{SECRET}","errors":[{{"message":"{pad}{SECRET}"}}]}}"#);
        let f = body_facts_redacted(Some("application/json"), json.as_bytes(), redact);
        assert_eq!(f.json_error.as_deref(), Some(cut.as_str()));
        assert_eq!(f.graphql.as_ref().map(|g| g.first_message.as_str()), Some(cut.as_str()));
        assert!(f.json_canonical.is_some(), "the parsed body is kept for signature matching");
        let fault = format!("<faultcode>Server</faultcode><faultstring>{pad}{SECRET}</faultstring>");
        let xml = format!("<Envelope><Body><Fault>{fault}</Fault></Body></Envelope>");
        let f = body_facts_redacted(Some("text/xml"), xml.as_bytes(), redact);
        assert_eq!(f.soap_fault, Some(SoapFault { code: "Server".into(), reason: cut }));
        // Cut first, the secret's prefix is left where no exact-value redaction can match it.
        let f = body_facts(Some("application/json"), json.as_bytes());
        assert!(f.json_error.is_some_and(|e| e.ends_with(&SECRET[..4])));
    }

    #[test]
    fn soap_fault_detected_without_dtd() {
        let x = br#"<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><soap:Fault><faultcode>soap:Server</faultcode><faultstring>boom</faultstring></soap:Fault></soap:Body></soap:Envelope>"#;
        let f = body_facts(Some("text/xml"), x);
        assert_eq!(f.soap_fault, Some(SoapFault { code: "soap:Server".into(), reason: "boom".into() }));
    }

    #[test]
    fn xml_entity_bomb_is_not_expanded() {
        let x = br#"<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;">]><Envelope><Body><Fault><faultstring>&lol2;</faultstring></Fault></Body></Envelope>"#;
        let f = body_facts(Some("text/xml"), x);
        assert!(f.soap_fault.is_none(), "DTD-bearing documents are refused, not expanded");
    }

    #[test]
    fn graphql_errors_with_partial_data() {
        let b = br#"{"data":{"user":{"id":"1"}},"errors":[{"message":"denied","path":["user","email"]}]}"#;
        let f = body_facts(Some("application/json"), b);
        let g = f.graphql.unwrap();
        assert_eq!(g.error_count, 1);
        assert!(g.has_data);
    }

    /// GHSA-mvjp-hhjj-mh63: an envelope with the most namespace work the
    /// limits allow (the deepest chain of the longest prefixes, then siblings
    /// until the scope budget is spent, then lookups that scan the whole
    /// scope) is inspected, promptly.
    #[test]
    fn an_envelope_at_the_namespace_limits_is_inspected_promptly() {
        let worst = anvil_xml_limits::test_support::namespace_worst_case(&SOAP_FAULT_XML_LIMITS, 0, 2_000);
        let xml = format!("<Envelope><Body><Fault><faultcode>Server</faultcode></Fault>{worst}</Body></Envelope>");
        assert!(xml.len() <= MAX_PARSE, "{} bytes", xml.len());
        let started = std::time::Instant::now();
        let f = body_facts(Some("text/xml"), xml.as_bytes());
        assert_eq!(f.xml_not_inspected, None);
        assert_eq!(f.soap_fault.map(|x| x.code).as_deref(), Some("Server"));
        assert!(started.elapsed() < std::time::Duration::from_secs(5), "took {:?}", started.elapsed());
    }
}
