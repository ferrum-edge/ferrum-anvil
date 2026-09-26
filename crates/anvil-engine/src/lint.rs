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
    if text.contains("<!DOCTYPE") || text.contains("<!ENTITY") {
        // Refuse to process DTDs at all (no entity expansion, no external fetch).
        let (line, column) = position(text, text.find("<!").unwrap_or(0));
        return LintResult::Invalid {
            issues: vec![LintIssue {
                line,
                column,
                message: "DTDs and entity declarations are not processed; the document is linted as untrusted and rejected".into(),
            }],
        };
    }
    let opts = roxmltree::ParsingOptions { allow_dtd: false, nodes_limit: 1_000_000, ..Default::default() };
    match roxmltree::Document::parse_with_options(text, opts) {
        Ok(_) => LintResult::Valid,
        Err(e) => {
            let p = e.pos();
            LintResult::Invalid { issues: vec![LintIssue { line: p.row as usize, column: p.col as usize, message: e.to_string() }] }
        }
    }
}

fn position(text: &str, byte: usize) -> (usize, usize) {
    let before = &text[..byte.min(text.len())];
    let line = before.matches('\n').count() + 1;
    let col = before.rsplit('\n').next().map(|l| l.chars().count() + 1).unwrap_or(1);
    (line, col)
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
}
