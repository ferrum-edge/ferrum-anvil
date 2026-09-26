//! The XPath subset used by assertions and extractions is parsed strictly:
//! a path it cannot represent is an evaluation error, never a step that
//! silently selects other nodes (which could pass an assertion or copy the
//! wrong value into a later request).

use anvil_domain::assertions::{Assertion, AssertionKind, AssertionResult, Comparison, Extraction, ExtractionSource};
use anvil_domain::outcome::{ProtocolStatus, TransportState};
use anvil_engine::assertions::{Observed, evaluate, extract, xpath};
use anvil_engine::redact::Redactor;

const ONE_ITEM: &[u8] = br#"<root><item id="present">first</item></root>"#;

fn observe(body: &[u8], a: &[Assertion]) -> Vec<AssertionResult> {
    let status = ProtocolStatus::None;
    let o = Observed {
        response: None,
        body,
        body_unavailable: None,
        latency_ms: None,
        protocol_status: &status,
        stream: None,
        findings: &[],
        transport: TransportState::Completed,
    };
    evaluate(a, &o, &Redactor::new(vec![], vec![]))
}

fn xpath_assertion(path: &str, comparison: Comparison) -> Assertion {
    Assertion { enabled: true, label: String::new(), kind: AssertionKind::XPath { path: path.into(), comparison, value: String::new() } }
}

fn xpath_extraction(path: &str) -> Extraction {
    Extraction { variable: "id".into(), source: ExtractionSource::XPath { path: path.into() }, sensitive: false }
}

#[test]
fn unsupported_or_malformed_predicates_are_errors() {
    for path in [
        "/root/item[@id='missing']",
        "/root/item[@id='present']",
        "/root/item[1",
        "/root/item1]",
        "/root/item[0]",
        "/root/item[00]",
        "/root/item[+1]",
        "/root/item[-1]",
        "/root/item[]",
        "/root/item[last()]",
        "/root/item[1][1]",
        "/root/item[1]x",
        "/root/item[99999999999999999999999999]",
    ] {
        let r = xpath(ONE_ITEM, path);
        assert!(r.is_err(), "{path} must not evaluate, got {r:?}");
    }
}

#[test]
fn syntax_outside_the_subset_is_an_error() {
    for path in [
        "root/item",
        "",
        "/",
        "//",
        "/root/",
        "/root//",
        "/root///item",
        "/root/..",
        "/root/.",
        "/root/node()",
        "/root/item/@*",
        "/root/item/@",
        "/root/item/@id/text()",
        "/root/item/text()/x",
        "/@id",
        "/text()",
        "/root/item | /root",
        "/root/p:*",
        "/root/a:b:c",
        "/root/1item",
        "/child::root",
    ] {
        let r = xpath(ONE_ITEM, path);
        assert!(r.is_err(), "{path:?} must not evaluate, got {r:?}");
    }
}

#[test]
fn the_path_is_validated_before_the_body() {
    let e = xpath(b"not xml", "/root/item[@id='x']").unwrap_err();
    assert!(e.contains("not supported"), "{e}");
}

#[test]
fn positions_select_the_nth_matching_child_of_each_parent() {
    let xml = br#"<root><a><item>a1</item></a><b><item>b1</item><item id="x">b2</item></b></root>"#;
    assert_eq!(xpath(xml, "//item[1]").unwrap().as_deref(), Some("a1"));
    assert_eq!(xpath(xml, "//item[2]").unwrap().as_deref(), Some("b2"));
    assert_eq!(xpath(xml, "//item[3]").unwrap(), None);
    assert_eq!(xpath(xml, "/root/b/item[ 2 ]").unwrap().as_deref(), Some("b2"));
    assert_eq!(xpath(xml, "/root/b/item[3]").unwrap(), None);
    assert_eq!(xpath(xml, "/root/*[2]/item").unwrap().as_deref(), Some("b1"));
    assert_eq!(xpath(xml, "//@id").unwrap().as_deref(), Some("x"));
    assert_eq!(xpath(xml, "/root//item[2]/@id").unwrap().as_deref(), Some("x"));
    assert_eq!(xpath(ONE_ITEM, "/root/item[2]").unwrap(), None);
    assert_eq!(xpath(ONE_ITEM, "/root/item[1]").unwrap().as_deref(), Some("first"));
}

#[test]
fn text_selects_text_node_children() {
    let xml = br#"<r>x<b>y</b>z</r>"#;
    assert_eq!(xpath(xml, "/r").unwrap().as_deref(), Some("xyz"));
    assert_eq!(xpath(xml, "/r/text()").unwrap().as_deref(), Some("x"));
    assert_eq!(xpath(xml, "/r/b/text()").unwrap().as_deref(), Some("y"));
    assert_eq!(xpath(xml, "/r//text()").unwrap().as_deref(), Some("x"));
    assert_eq!(xpath(br#"<r><b>y</b></r>"#, "/r/text()").unwrap(), None);
}

#[test]
fn namespace_prefixes_are_ignored() {
    let xml = br#"<s:Envelope xmlns:s="urn:x"><s:Body><v s:kind="k">one</v></s:Body></s:Envelope>"#;
    assert_eq!(xpath(xml, "/Envelope/Body/v").unwrap().as_deref(), Some("one"));
    assert_eq!(xpath(xml, "/s:Envelope/s:Body/v").unwrap().as_deref(), Some("one"));
    assert_eq!(xpath(xml, "/other:Envelope/Body/v/@s:kind").unwrap().as_deref(), Some("k"));
    assert_eq!(xpath(xml, "//v/@kind").unwrap().as_deref(), Some("k"));
}

#[test]
fn assertions_on_an_unsupported_path_cannot_pass() {
    for path in ["/root/item[@id='missing']", "/root/item[1", "/root/item[0]"] {
        let results = observe(ONE_ITEM, &[xpath_assertion(path, Comparison::Exists), xpath_assertion(path, Comparison::NotExists)]);
        assert_eq!(results.len(), 2);
        for r in &results {
            assert!(!r.passed, "{path}: {}", r.message);
            assert!(r.message.starts_with("could not evaluate: "), "{path}: {}", r.message);
            assert_eq!(r.actual, None);
        }
    }
    let supported = observe(ONE_ITEM, &[xpath_assertion("/root/item[1]", Comparison::Exists)]);
    assert!(supported[0].passed, "{}", supported[0].message);
    let absent = observe(ONE_ITEM, &[xpath_assertion("/root/item[2]", Comparison::NotExists)]);
    assert!(absent[0].passed, "{}", absent[0].message);
}

#[test]
fn extractions_on_an_unsupported_path_fail() {
    let paths = ["/root/item[@id='missing']", "/root/item[1", "/root/item[0]", "/root/item[1]"];
    let extractions: Vec<Extraction> = paths.into_iter().map(xpath_extraction).collect();
    let out = extract(&extractions, None, ONE_ITEM, None);
    assert_eq!(out.len(), 4);
    for r in &out[..3] {
        assert!(r.is_err(), "{r:?}");
    }
    assert_eq!(out[3], Ok(("id".to_string(), "first".to_string(), false)));
}
