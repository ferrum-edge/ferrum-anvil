//! Bounded JSON/XML syntax lint with line/column messages. XML linting never
//! processes DTDs, external entities or remote schemas.

use anvil_xml_limits::{XmlLimits, check_xml_limits};
use serde::Serialize;

pub const MAX_LINT_BYTES: usize = 4 * 1024 * 1024;
/// XML nodes one lint parses.
const MAX_LINT_XML_NODES: u32 = 1_000_000;
/// What an XML body may contain before it is parsed (the body can come from
/// an imported collection, and lint runs on the UI's command thread). The
/// parser compares each attribute with every earlier one on its element,
/// names and full namespace URIs; for each element that declares a namespace
/// it copies the n in scope, checking each against those already copied
/// (about n²/2 prefix comparisons); and it looks every element and prefixed
/// attribute name up among the namespaces in scope. Names, prefixes and URIs
/// may be as long as a WSDL import allows, so an imported envelope lints.
/// The bounds keep a body to about 2^20 attribute comparisons of at most
/// 3 KiB, 2^23 prefix comparisons of at most 256 bytes while copying scopes,
/// 4096 · 128 = 2^19 copied namespace references, and 129 comparisons per
/// name looked up.
const LINT_XML_LIMITS: XmlLimits = XmlLimits {
    attributes_per_element: 256,
    attribute_pairs: 1 << 20,
    attribute_name_bytes: 1_024,
    xmlns_declarations: 4_096,
    xmlns_prefix_bytes: 256,
    xmlns_uri_bytes: 2_048,
    in_scope_namespaces: 128,
    namespace_scope_work: 1 << 24,
};

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct LintIssue {
    pub line: usize,
    pub column: usize,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum LintResult {
    Valid,
    Invalid {
        issues: Vec<LintIssue>,
    },
    /// Too large to lint within the bound; not an error.
    Skipped {
        reason: String,
    },
    /// Not parsed: the body is over the pre-parse limits (XML whose parse
    /// would cost more than its size). Treated as a lint error when sending.
    Refused {
        reason: String,
    },
}

pub fn json(text: &str) -> LintResult {
    if text.len() > MAX_LINT_BYTES {
        return LintResult::Skipped { reason: format!("body larger than {MAX_LINT_BYTES} bytes") };
    }
    if text.trim().is_empty() {
        return LintResult::Invalid { issues: vec![LintIssue { line: 1, column: 1, message: "empty JSON body".into() }] };
    }
    match serde_json::from_str::<serde::de::IgnoredAny>(text) {
        Ok(_) => LintResult::Valid,
        Err(e) => LintResult::Invalid { issues: vec![LintIssue { line: e.line(), column: e.column(), message: e.to_string() }] },
    }
}

pub fn xml(text: &str) -> LintResult {
    if text.len() > MAX_LINT_BYTES {
        return LintResult::Skipped { reason: format!("body larger than {MAX_LINT_BYTES} bytes") };
    }
    // Counted in one pass before the parser does work that grows with the
    // square of the namespace declarations or of an element's attributes.
    if let Err(e) = check_xml_limits(text, &LINT_XML_LIMITS) {
        return LintResult::Refused { reason: format!("too complex to lint safely: {e}") };
    }
    // `allow_dtd: false` makes the parser reject real DTDs with `DtdDetected`
    // while accepting declaration-like text inside comments and CDATA, where
    // `<!DOCTYPE`/`<!ENTITY` are literal characters rather than markup. The
    // pre-parse scan above relies on it: it stops at a DOCTYPE.
    let opts = roxmltree::ParsingOptions { allow_dtd: false, nodes_limit: MAX_LINT_XML_NODES, ..Default::default() };
    match roxmltree::Document::parse_with_options(text, opts) {
        Ok(_) => LintResult::Valid,
        // A real DTD is refused without entity expansion or external fetches.
        Err(roxmltree::Error::DtdDetected) => LintResult::Invalid {
            issues: vec![LintIssue {
                line: 1,
                column: 1,
                message: "DTDs and entity declarations are not processed; the document is linted as untrusted and rejected".into(),
            }],
        },
        Err(e) => {
            let p = e.pos();
            LintResult::Invalid { issues: vec![LintIssue { line: p.row as usize, column: p.col as usize, message: e.to_string() }] }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_errors_have_positions() {
        match json("{\n  \"a\": 1,\n  \"b\": }") {
            LintResult::Invalid { issues } => assert_eq!(issues[0].line, 3),
            o => panic!("{o:?}"),
        }
        assert_eq!(json(r#"{"a":[1,2]}"#), LintResult::Valid);
    }

    #[test]
    fn data_013_xml_entities_are_refused_not_expanded() {
        let bomb = r#"<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;">]><r>&b;</r>"#;
        assert!(matches!(xml(bomb), LintResult::Invalid { .. }));
        let xxe = r#"<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>"#;
        assert!(matches!(xml(xxe), LintResult::Invalid { .. }));
        assert_eq!(xml("<a><b/></a>"), LintResult::Valid);
    }

    #[test]
    fn xml_accepts_declaration_like_text_inside_cdata_and_comments() {
        // CDATA is character data: `<!DOCTYPE` and `<!ENTITY` there are literal text.
        assert_eq!(xml(r#"<document><![CDATA[<!DOCTYPE html><html><body>Report</body></html>]]></document>"#), LintResult::Valid);
        // Comments are ignored by the parser: a documented example is not a declaration.
        assert_eq!(
            xml(r#"<document><!-- documentation example: <!ENTITY example 'value'> --><value>ok</value></document>"#),
            LintResult::Valid
        );
    }

    #[test]
    fn xml_still_refuses_declarations_that_are_actual_markup() {
        // A comment before the real DTD must not mask it.
        let hidden = xml(r#"<!-- see <!DOCTYPE fake> --><!DOCTYPE r [<!ENTITY a "b">]><r>&a;</r>"#);
        assert!(
            matches!(hidden, LintResult::Invalid { .. }),
            "an actual DTD is refused even when declaration-like text precedes it in a comment"
        );
        // A bare entity declaration in element content is not markup either.
        assert!(matches!(xml(r#"<r><!ENTITY x "y"></r>"#), LintResult::Invalid { .. }));
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

    /// `elements` children of one root, each with `attributes` attributes in
    /// one namespace whose URI is `uri_bytes` long.
    fn wide_elements(elements: usize, attributes: usize, uri_bytes: usize) -> String {
        let mut s = format!("<r xmlns:p=\"{}\">", "u".repeat(uri_bytes));
        for _ in 0..elements {
            s.push_str("<c");
            for i in 0..attributes {
                s.push_str(&format!(" p:a{i}=\"\""));
            }
            s.push_str("/>");
        }
        s.push_str("</r>");
        s
    }

    fn refused(r: &LintResult, why: &str) -> bool {
        matches!(r, LintResult::Refused { reason } if reason.starts_with("too complex to lint safely: ") && reason.contains(why))
    }

    /// `n` sibling elements that each declare the same prefix again.
    fn redeclared(n: usize) -> String {
        format!("<r>{}</r>", r#"<i xmlns:m="urn:m">v</i>"#.repeat(n))
    }

    /// GHSA-mvjp-hhjj-mh63: documents whose namespace or attribute work grows
    /// faster than their size are refused before they are parsed.
    #[test]
    fn xml_too_complex_to_parse_is_refused() {
        let started = std::time::Instant::now();
        for (doc, why) in [
            (nested_namespaces(5_000), "more than 128 namespace declarations in scope of one element"),
            (redeclared(5_000), "more than 4096 namespace declarations (xmlns)"),
            (wide_elements(1, 300, 16), "more than 256 attributes on one element"),
            // Each element is within the per-element bound; together they are not.
            (wide_elements(60, 200, 2_000), "attribute pairs"),
            (wide_elements(1, 2, 3_000), "a namespace URI longer than 2048 bytes"),
        ] {
            let r = xml(&doc);
            assert!(refused(&r, why), "{why}: {r:?}");
        }
        // One more sibling than the scope work budget allows.
        let worst = anvil_xml_limits::test_support::namespace_worst_case(&LINT_XML_LIMITS, 0, 0);
        let over = format!("<r>{}</r>", worst.replacen("</c>", "<s xmlns:extra=\"urn:x\"/></c>", 1));
        let r = xml(&over);
        assert!(refused(&r, "namespace scopes costing more than 16777216"), "{r:?}");
        assert!(started.elapsed() < std::time::Duration::from_secs(10), "took {:?}", started.elapsed());
    }

    /// The most namespace work the limits allow: the deepest chain of the
    /// longest prefixes, siblings until the scope budget is spent, and names
    /// that the parser finds last in the scope. Lint runs on the UI's command
    /// thread, so this must stay quick.
    #[test]
    fn xml_at_the_namespace_limits_lints_promptly() {
        let doc = format!("<r>{}</r>", anvil_xml_limits::test_support::namespace_worst_case(&LINT_XML_LIMITS, 0, 10_000));
        assert!(doc.len() <= MAX_LINT_BYTES, "{} bytes", doc.len());
        let started = std::time::Instant::now();
        assert_eq!(xml(&doc), LintResult::Valid);
        assert!(started.elapsed() < std::time::Duration::from_secs(5), "took {:?}", started.elapsed());
    }

    #[test]
    fn xml_within_the_limits_still_lints() {
        let envelope = r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:m="urn:x"><soap:Body><m:Ping a="1" b="2">1</m:Ping></soap:Body></soap:Envelope>"#;
        assert_eq!(xml(envelope), LintResult::Valid);
        assert_eq!(xml(&nested_namespaces(128)), LintResult::Valid);
        assert_eq!(xml(&redeclared(4_000)), LintResult::Valid);
        assert_eq!(xml(&wide_elements(20, 200, 2_000)), LintResult::Valid);
        // The scan passes malformed text on to the parser, which reports it.
        assert!(matches!(xml("<r a=\"1\"><c></r>"), LintResult::Invalid { .. }));
    }
}
