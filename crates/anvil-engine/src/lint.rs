//! Bounded JSON/XML syntax lint with line/column messages. XML linting never
//! processes DTDs, external entities or remote schemas.

use anvil_xml_limits::{XmlLimits, check_xml_limits};
use serde::Serialize;

pub const MAX_LINT_BYTES: usize = 4 * 1024 * 1024;
/// XML nodes one lint parses.
const MAX_LINT_XML_NODES: u32 = 1_000_000;
/// What an XML body may contain before it is parsed (the body can come from
/// an imported collection). The parser copies the namespaces in scope for
/// every element that declares one and compares each attribute with every
/// earlier one on its element, names and full namespace URIs, so both are
/// bounded before it runs. Names, prefixes and URIs are allowed as long as a
/// WSDL import allows them, so an imported envelope lints; the bounds keep a
/// body to about 2^20 comparisons of at most 3 KiB and (4096/2)^2 = 2^22
/// copied namespace references (8 MiB).
const LINT_XML_LIMITS: XmlLimits = XmlLimits {
    attributes_per_element: 256,
    attribute_pairs: 1 << 20,
    attribute_name_bytes: 1_024,
    xmlns_declarations: 4_096,
    xmlns_prefix_bytes: 256,
    xmlns_uri_bytes: 2_048,
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
        let message = format!("XML too complex to lint safely ({e}); the body was not parsed");
        return LintResult::Invalid { issues: vec![LintIssue { line: 1, column: 1, message }] };
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

    fn too_complex(r: &LintResult) -> bool {
        matches!(r, LintResult::Invalid { issues } if issues[0].message.starts_with("XML too complex to lint safely"))
    }

    /// GHSA-mvjp-hhjj-mh63: documents whose namespace or attribute work grows
    /// with the square of their size are a lint finding, found before parsing.
    #[test]
    fn xml_too_complex_to_parse_is_a_lint_finding() {
        let started = std::time::Instant::now();
        let r = xml(&nested_namespaces(5_000));
        assert!(too_complex(&r), "{r:?}");
        assert!(format!("{r:?}").contains("more than 4096 namespace declarations"), "{r:?}");
        let r = xml(&wide_elements(1, 300, 16));
        assert!(too_complex(&r) && format!("{r:?}").contains("more than 256 attributes on one element"), "{r:?}");
        // Each element is within the per-element bound; together they are not.
        let r = xml(&wide_elements(60, 200, 2_000));
        assert!(too_complex(&r) && format!("{r:?}").contains("attribute pairs"), "{r:?}");
        let r = xml(&wide_elements(1, 2, 3_000));
        assert!(too_complex(&r) && format!("{r:?}").contains("namespace URI longer than 2048 bytes"), "{r:?}");
        assert!(started.elapsed() < std::time::Duration::from_secs(10), "took {:?}", started.elapsed());
    }

    #[test]
    fn xml_within_the_limits_still_lints() {
        let envelope = r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:m="urn:x"><soap:Body><m:Ping a="1" b="2">1</m:Ping></soap:Body></soap:Envelope>"#;
        assert_eq!(xml(envelope), LintResult::Valid);
        assert_eq!(xml(&nested_namespaces(1_000)), LintResult::Valid);
        assert_eq!(xml(&wide_elements(20, 200, 2_000)), LintResult::Valid);
        // The scan passes malformed text on to the parser, which reports it.
        assert!(matches!(xml("<r a=\"1\"><c></r>"), LintResult::Invalid { issues } if !issues[0].message.contains("too complex")));
    }
}
