//! Evidence normalization: turns an execution's raw observations into the
//! typed facts rules consume. Response bodies are parsed only for structure
//! (bounded, no DTDs, no external resolution) and are always untrusted data.

use anvil_domain::execution::*;
use anvil_domain::outcome::ProtocolStatus;
use anvil_domain::request::Protocol;

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

pub fn body_facts(content_type: Option<&str>, body: &[u8]) -> BodyFacts {
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
                    f.json_error = Some(e.chars().take(300).collect());
                }
                if let Some(errs) = obj.get("errors").and_then(|e| e.as_array())
                    && !errs.is_empty()
                    && errs.iter().all(|e| e.get("message").is_some())
                {
                    f.graphql = Some(GraphQlResult {
                        error_count: errs.len(),
                        has_data: obj.get("data").map(|d| !d.is_null()).unwrap_or(false),
                        first_message: errs[0].get("message").and_then(|m| m.as_str()).unwrap_or("").chars().take(300).collect(),
                    });
                }
            }
            f.json_canonical = Some(v);
        }
    } else if (trimmed.first() == Some(&b'<')) && (ct.contains("xml") || ct.is_empty() || ct.contains("soap")) {
        f.soap_fault = soap_fault(trimmed);
    }
    f
}

fn trim_ascii(b: &[u8]) -> &[u8] {
    let start = b.iter().position(|c| !c.is_ascii_whitespace()).unwrap_or(b.len());
    let end = b.iter().rposition(|c| !c.is_ascii_whitespace()).map(|i| i + 1).unwrap_or(start);
    &b[start..end.max(start)]
}

/// SOAP 1.1/1.2 fault detection. roxmltree rejects DTDs by default, so no
/// entity expansion or external resolution can occur.
fn soap_fault(xml: &[u8]) -> Option<SoapFault> {
    let text = std::str::from_utf8(xml).ok()?;
    let opts = roxmltree::ParsingOptions { allow_dtd: false, nodes_limit: 50_000, ..Default::default() };
    let doc = roxmltree::Document::parse_with_options(text, opts).ok()?;
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
                    return t.chars().take(300).collect();
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
}
