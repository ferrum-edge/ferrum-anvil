//! The XPath subset used by assertions and extractions is parsed strictly:
//! a path it cannot represent is an evaluation error, never a step that
//! silently selects other nodes (which could pass an assertion or copy the
//! wrong value into a later request).

use anvil_domain::assertions::{Assertion, AssertionKind, AssertionResult, Comparison, Extraction, ExtractionSource};
use anvil_domain::outcome::{ProtocolStatus, TransportState};
use anvil_engine::assertions::{Observed, evaluate, extract, xpath};
use anvil_engine::redact::Redactor;
use std::time::{Duration, Instant};

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
        // Whitespace between path parts.
        "/root / item",
        "/root/ item",
        "/root /item",
        "/root/item [1]",
        "/root/@ id",
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
    // The first text node in document order, not the first child of the outer element.
    assert_eq!(xpath(br#"<r><b>y</b>z</r>"#, "//text()").unwrap().as_deref(), Some("y"));
    assert_eq!(xpath(br#"<r><b>y</b>z</r>"#, "/r//text()").unwrap().as_deref(), Some("y"));
}

#[test]
fn a_descendant_step_excludes_its_context_element() {
    let xml = br#"<b id="outer">o<b id="inner">i</b></b>"#;
    assert_eq!(xpath(xml, "/b//b").unwrap().as_deref(), Some("i"));
    assert_eq!(xpath(xml, "/b//b/@id").unwrap().as_deref(), Some("inner"));
    assert_eq!(xpath(xml, "/b//b[2]").unwrap(), None, "positions count children of one parent");
}

#[test]
fn names_may_use_unicode_letters() {
    let xml = "<données><é n=\"1\">un</é><é>deux</é></données>".as_bytes();
    assert_eq!(xpath(xml, "/données/é[1]").unwrap().as_deref(), Some("un"));
    assert_eq!(xpath(xml, "/données/é[2]").unwrap().as_deref(), Some("deux"));
    assert_eq!(xpath(xml, "//é/@n").unwrap().as_deref(), Some("1"));
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

#[test]
fn extraction_errors_name_the_variable() {
    let out = extract(&[xpath_extraction("/root/item[0]")], None, ONE_ITEM, None);
    let e = out[0].as_ref().unwrap_err();
    assert!(e.starts_with("extraction for 'id': XPath positions start at 1"), "{e}");
    let out = extract(&[xpath_extraction("/root/item")], None, b"not xml", None);
    let e = out[0].as_ref().unwrap_err();
    assert!(e.starts_with("extraction for 'id': body is not XML"), "{e}");
}

/// `depth` nested elements that each declare a namespace.
fn nested_namespaces(depth: usize) -> Vec<u8> {
    let mut s = String::new();
    for i in 0..depth {
        s.push_str(&format!("<e xmlns:p{i}=\"urn:n{i}\">"));
    }
    s.push_str(&"</e>".repeat(depth));
    s.into_bytes()
}

/// `elements` children of one root, each with `attributes` attributes in one
/// namespace whose URI is `uri_bytes` long.
fn wide_elements(elements: usize, attributes: usize, uri_bytes: usize) -> Vec<u8> {
    let mut s = format!("<r xmlns:p=\"{}\">", "u".repeat(uri_bytes));
    for _ in 0..elements {
        s.push_str("<c");
        for i in 0..attributes {
            s.push_str(&format!(" p:a{i}=\"\""));
        }
        s.push_str("/>");
    }
    s.push_str("</r>");
    s.into_bytes()
}

/// GHSA-mvjp-hhjj-mh63: a response body whose namespace or attribute work
/// grows with the square of its size is not parsed; assertions on it fail
/// and extractions from it fail, promptly.
#[test]
fn xml_too_complex_to_evaluate_fails_assertions_and_extractions() {
    let started = Instant::now();
    let bodies = [
        (nested_namespaces(20_000), "more than 128 namespace declarations in scope of one element"),
        (format!("<r>{}</r>", r#"<i xmlns:m="urn:m">v</i>"#.repeat(9_000)).into_bytes(), "more than 8192 namespace declarations (xmlns)"),
        (wide_elements(1, 300, 16), "more than 256 attributes on one element"),
        // Each element is within the per-element bound; together they are not.
        (wide_elements(200, 250, 500), "attribute pairs"),
        (wide_elements(1, 2, 600), "a namespace URI longer than 512 bytes"),
    ];
    for (body, why) in &bodies {
        for comparison in [Comparison::Exists, Comparison::NotExists] {
            let r = &observe(body, &[xpath_assertion("//c/@a0", comparison)])[0];
            assert!(!r.passed, "{why}: {}", r.message);
            assert!(r.message.starts_with("could not evaluate: XML too complex to evaluate safely ("), "{}", r.message);
            assert!(r.message.contains(why), "{}", r.message);
            assert_eq!(r.actual, None);
        }
        let out = extract(&[xpath_extraction("//c/@a0")], None, body, None);
        let e = out[0].as_ref().unwrap_err();
        assert!(e.starts_with("extraction for 'id': XML too complex to evaluate safely"), "{e}");
    }
    assert!(started.elapsed() < Duration::from_secs(10), "took {:?}", started.elapsed());
}

#[test]
fn xml_within_the_limits_is_evaluated() {
    let wide = wide_elements(20, 250, 500);
    let r = &observe(&wide, &[xpath_assertion("//c/@a249", Comparison::Exists)])[0];
    assert!(r.passed, "{}", r.message);
    assert_eq!(xpath(&nested_namespaces(128), "//e/@missing").unwrap(), None);
    // A service may declare the same prefix again on every element.
    let redeclared = format!("<r>{}</r>", r#"<m:i xmlns:m="urn:m">v</m:i>"#.repeat(5_000));
    assert_eq!(xpath(redeclared.as_bytes(), "/r/i[5000]").unwrap().as_deref(), Some("v"));
    let envelope = br#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><m:R xmlns:m="urn:m" m:id="7">ok</m:R></soap:Body></soap:Envelope>"#;
    assert_eq!(xpath(envelope, "/Envelope/Body/R").unwrap().as_deref(), Some("ok"));
    assert_eq!(xpath(envelope, "//R/@id").unwrap().as_deref(), Some("7"));
}
