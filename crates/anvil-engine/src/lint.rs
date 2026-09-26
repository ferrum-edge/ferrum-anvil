//! Bounded JSON/XML syntax lint with line/column messages. XML linting never
//! processes DTDs, external entities or remote schemas.

use serde::Serialize;

pub const MAX_LINT_BYTES: usize = 4 * 1024 * 1024;

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
    // `allow_dtd: false` makes the parser reject real DTDs with `DtdDetected`
    // while accepting declaration-like text inside comments and CDATA, where
    // `<!DOCTYPE`/`<!ENTITY` are literal characters rather than markup.
    let opts = roxmltree::ParsingOptions { allow_dtd: false, nodes_limit: 1_000_000, ..Default::default() };
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
}
