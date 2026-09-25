mod common;

use anvil_domain::request::{Body, SoapVersion};
use anvil_import::{Dialect, ImportError, ImportOptions, SampleMode, detect, import};
use common::*;

const WSDL: &str = "wsdl/stockquote.wsdl";

fn soap(r: &anvil_import::ImportResult, key: &str) -> (SoapVersion, String, Option<String>) {
    match &req(r, key).spec.body {
        Body::Soap { version, envelope, action } => (*version, envelope.clone(), action.clone()),
        other => panic!("expected SOAP body, got {other:?}"),
    }
}

fn parse(envelope: &str) -> roxmltree::Document<'_> {
    roxmltree::Document::parse(envelope).unwrap_or_else(|e| panic!("envelope is not well-formed ({e}):\n{envelope}"))
}

#[test]
fn detects_wsdl_versions() {
    assert_eq!(detect(&fixture(WSDL)).dialect, Dialect::Wsdl11);
    let w20 = br#"<?xml version="1.0"?><description xmlns="http://www.w3.org/ns/wsdl" targetNamespace="urn:x"/>"#;
    assert_eq!(detect(w20).dialect, Dialect::Wsdl20);
    assert!(matches!(import(w20, &opts()), Err(ImportError::UnsupportedDialect { dialect: Dialect::Wsdl20, .. })));
}

#[test]
fn two_bindings_produce_soap11_and_soap12_requests() {
    let r = run(WSDL, &opts());
    assert_eq!(r.workspace.name, "StockQuote");
    assert_eq!(r.workspace.description, "Stock quotes over SOAP 1.1 and 1.2.");
    let (v11, env11, action11) = soap(&r, "StockQuoteService/StockQuoteSoap/GetQuote");
    assert_eq!(v11, SoapVersion::Soap11);
    assert_eq!(action11.as_deref(), Some("urn:example:stockquote/GetQuote"));
    let doc = parse(&env11);
    assert_eq!(doc.root_element().tag_name().namespace(), Some("http://schemas.xmlsoap.org/soap/envelope/"));
    let (v12, env12, _) = soap(&r, "StockQuoteService/StockQuoteSoap12/GetQuote");
    assert_eq!(v12, SoapVersion::Soap12);
    assert_eq!(parse(&env12).root_element().tag_name().namespace(), Some("http://www.w3.org/2003/05/soap-envelope"));
    // Empty soapAction on SOAP 1.2 → no action parameter.
    assert_eq!(soap(&r, "StockQuoteService/StockQuoteSoap12/PlaceOrder").2, None);
    // Endpoints become environment variables; URL references them.
    assert_eq!(req(&r, "StockQuoteService/StockQuoteSoap/GetQuote").spec.url, "{{StockQuoteSoap_url}}");
    let env = &r.environments[0];
    assert!(env.variables.iter().any(|v| v.name == "StockQuoteSoap12_url"));
    assert!(!env.variables.iter().any(|v| v.name == "StockQuoteHttp_url"), "unsupported bindings get no endpoint");
    // Folder layout: service → port (version).
    let port = r.folders.iter().find(|f| f.name == "StockQuoteSoap12 (SOAP 1.2)").unwrap();
    let svc = r.folders.iter().find(|f| f.name == "StockQuoteService").unwrap();
    assert_eq!(port.parent_id, Some(svc.meta.id));
    assert_eq!(req(&r, "StockQuoteService/StockQuoteSoap/GetQuote").description, "Latest quote for a symbol.");
}

#[test]
fn envelopes_follow_the_inline_xsd() {
    let r = run(WSDL, &opts());
    let (_, env, _) = soap(&r, "StockQuoteService/StockQuoteSoap/GetQuote");
    let doc = parse(&env);
    let ns = "urn:example:stockquote";
    // Header block from soap:header; credential element left blank.
    let header = doc.descendants().find(|n| n.has_tag_name((ns, "AuthHeader"))).expect("header block");
    let pw = header.children().find(|n| n.has_tag_name((ns, "password"))).unwrap();
    assert_eq!(pw.text(), None);
    assert!(has(&r, "credential_left_blank"));
    // Qualified body element with required child; optional omitted.
    let get = doc.descendants().find(|n| n.has_tag_name((ns, "GetQuote"))).unwrap();
    assert!(get.children().any(|n| n.has_tag_name((ns, "symbol"))));
    assert!(!get.children().any(|n| n.has_tag_name((ns, "asOf"))));

    let (_, env, _) = soap(&r, "StockQuoteService/StockQuoteSoap/PlaceOrder");
    let doc = parse(&env);
    let order = doc.descendants().find(|n| n.has_tag_name((ns, "PlaceOrder"))).unwrap();
    let text = |local: &str| order.children().find(|n| n.has_tag_name((ns, local))).and_then(|n| n.text()).map(str::to_string);
    assert_eq!(text("side").as_deref(), Some("BUY"), "first enumeration");
    let qty: i64 = text("quantity").unwrap().parse().unwrap();
    assert!((1..=500).contains(&qty), "facets honored: {qty}");
    let stock = order.children().find(|n| n.has_tag_name((ns, "stock"))).expect("first choice branch");
    assert_eq!(stock.attribute("currency"), Some("USD"), "fixed attribute");
    assert!(has(&r, "xsd_choice_first"));
    assert!(has_at(&r, "xsd_any", "element[@name='PlaceOrder']"));

    // rpc style: wrapper in soap:body namespace, unqualified part accessors.
    let (_, env, action) = soap(&r, "binding/LegacyRpc/GetPrice");
    assert_eq!(action.as_deref(), Some("GetPrice"));
    let doc = parse(&env);
    let wrapper = doc.descendants().find(|n| n.has_tag_name(("urn:example:legacy", "GetPrice"))).unwrap();
    assert!(wrapper.children().any(|n| n.has_tag_name("symbol") && n.tag_name().namespace().is_none()));
    assert!(has(&r, "binding_without_service"));
    assert!(r.report.required_variables.iter().any(|v| v.name == "LegacyRpc_url"));
}

#[test]
fn optional_content_extension_and_recursion() {
    let r = run(WSDL, &ImportOptions { include_optional: true, ..opts() });
    let (_, env, _) = soap(&r, "StockQuoteService/StockQuoteSoap/PlaceOrder");
    assert!(env.contains("<!--Optional:-->"));
    let doc = parse(&env);
    let ns = "urn:example:stockquote";
    assert!(doc.descendants().any(|n| n.has_tag_name((ns, "note"))));
    // Recursive Basket type is cut and reported.
    assert!(doc.descendants().any(|n| n.has_tag_name((ns, "basket"))));
    assert!(has(&r, "recursive_schema"));
    assert!(env.contains("clientRef="), "optional attribute included");
}

#[test]
fn blank_envelopes_have_no_invented_values() {
    let r = run(WSDL, &ImportOptions { mode: SampleMode::Blank, ..opts() });
    let (_, env, _) = soap(&r, "StockQuoteService/StockQuoteSoap/PlaceOrder");
    let doc = parse(&env);
    let ns = "urn:example:stockquote";
    for local in ["side", "quantity", "symbol"] {
        let n = doc.descendants().find(|n| n.has_tag_name((ns, local))).unwrap();
        assert_eq!(n.text(), None, "{local} should be blank");
    }
    // Fixed values are structural, so they stay.
    assert!(env.contains("currency=\"USD\""));
}

#[test]
fn unsupported_bindings_and_external_schemas_are_reported() {
    let r = run(WSDL, &opts());
    assert!(has_at(&r, "wsdl_binding_unsupported", "binding[@name='StockQuoteHttp']"));
    assert_eq!(r.report.counts.skipped_operations, 1);
    let ext = &r.report.external_refs;
    assert_eq!(ext.len(), 1);
    assert_eq!(ext[0].reference, "https://schemas.example.com/common.xsd");
    assert!(ext[0].requires_approval);
}

#[test]
fn xml_entities_and_dtds_are_refused() {
    // XXE: external entity pointing at a local secret.
    let xxe = br#"<?xml version="1.0"?>
<!DOCTYPE definitions [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<definitions xmlns="http://schemas.xmlsoap.org/wsdl/" targetNamespace="urn:x"><documentation>&xxe;</documentation></definitions>"#;
    assert!(matches!(import(xxe, &opts()), Err(ImportError::UnsafeXml { .. })));
    // Billion laughs.
    let lol = br#"<?xml version="1.0"?>
<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]>
<definitions xmlns="http://schemas.xmlsoap.org/wsdl/">&lol2;</definitions>"#;
    assert!(matches!(import(lol, &opts()), Err(ImportError::UnsafeXml { .. })));
    // Undeclared entity without a DTD is a syntax error, never a fetch.
    let undeclared = br#"<definitions xmlns="http://schemas.xmlsoap.org/wsdl/">&secret;</definitions>"#;
    assert!(matches!(import(undeclared, &opts()), Err(ImportError::Syntax { .. })));
}

#[test]
fn wsdl_imports_are_listed_not_fetched() {
    let doc = br#"<?xml version="1.0"?>
<definitions xmlns="http://schemas.xmlsoap.org/wsdl/" targetNamespace="urn:x" name="Imp">
  <import namespace="urn:y" location="http://10.0.0.5/internal.wsdl"/>
</definitions>"#;
    let r = import(doc, &opts()).unwrap();
    assert_eq!(r.report.external_refs[0].reference, "http://10.0.0.5/internal.wsdl");
    assert!(r.requests.is_empty());
}

#[test]
fn node_limit_applies_to_xml() {
    assert!(matches!(import(&fixture(WSDL), &ImportOptions { max_nodes: 20, ..opts() }), Err(ImportError::LimitExceeded { .. })));
}

#[test]
fn deterministic() {
    assert_eq!(run(WSDL, &opts()), run(WSDL, &opts()));
}
