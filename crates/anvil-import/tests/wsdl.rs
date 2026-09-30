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

/// A one-operation document/literal WSDL (`S/P/Op`) whose request element is
/// `tns:Req`; `{schema}` is replaced with more inline schema and `{parts}`
/// with the input message's parts.
const WSDL_TEMPLATE: &str = r#"<?xml version="1.0"?>
<definitions xmlns="http://schemas.xmlsoap.org/wsdl/" xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
    xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:tns="urn:g" targetNamespace="urn:g" name="G">
  <types>
    <xsd:schema targetNamespace="urn:g" elementFormDefault="qualified">{schema}</xsd:schema>
  </types>
  <message name="In">{parts}</message>
  <portType name="PT"><operation name="Op"><input message="tns:In"/></operation></portType>
  <binding name="B" type="tns:PT">
    <soap:binding style="document" transport="http://schemas.xmlsoap.org/soap/http"/>
    <operation name="Op"><soap:operation soapAction="urn:g#Op"/><input><soap:body use="literal"/></input></operation>
  </binding>
  <service name="S"><port name="P" binding="tns:B"><soap:address location="https://example.com/soap"/></port></service>
</definitions>"#;

fn op_envelope(schema: &str) -> (anvil_import::ImportResult, String) {
    op_envelope_with(schema, r#"<part name="body" element="tns:Req"/>"#)
}

fn op_envelope_with(schema: &str, parts: &str) -> (anvil_import::ImportResult, String) {
    let doc = WSDL_TEMPLATE.replace("{schema}", schema).replace("{parts}", parts);
    let r = import(doc.as_bytes(), &opts()).unwrap();
    let (_, env, _) = soap(&r, "S/P/Op");
    (r, env)
}

fn count(env: &str, local: &str) -> usize {
    parse(env).descendants().filter(|n| n.has_tag_name(("urn:g", local))).count()
}

/// `Ids` and `Items` reference themselves where `{refs}` is.
const RECURSIVE_GROUPS: &str = r#"
<xsd:attributeGroup name="Ids">
  <xsd:attribute name="id" type="xsd:string" use="required"/>
  {attr_refs}
</xsd:attributeGroup>
<xsd:group name="Items">
  <xsd:sequence>
    <xsd:element name="item" type="xsd:string"/>
    {group_refs}
  </xsd:sequence>
</xsd:group>
<xsd:element name="Req">
  <xsd:complexType>
    <xsd:group ref="tns:Items"/>
    <xsd:attributeGroup ref="tns:Ids"/>
  </xsd:complexType>
</xsd:element>"#;

#[test]
fn self_referencing_groups_stop_at_the_first_repetition() {
    // One self-reference each (two would branch at every level; the fan-out
    // test below covers branching within a bound).
    let schema = RECURSIVE_GROUPS
        .replace("{attr_refs}", r#"<xsd:attributeGroup ref="tns:Ids"/>"#)
        .replace("{group_refs}", r#"<xsd:group ref="tns:Items"/>"#);
    let (r, env) = op_envelope(&schema);
    assert!(has(&r, "recursive_schema"));
    assert_eq!(env.matches(" id=\"").count(), 1, "{env}");
    assert_eq!(count(&env, "item"), 1, "{env}");
}

/// Groups `X0`..`X15` each reference the next one twice (2^16 leaves, within
/// the nesting limit, without a shared budget); `X16` holds the leaf.
fn fan_out(attributes: bool) -> String {
    let (kind, leaf) = if attributes {
        ("attributeGroup", r#"<xsd:attribute name="leaf" type="xsd:string" use="required"/>"#)
    } else {
        ("group", r#"<xsd:sequence><xsd:element name="leaf" type="xsd:string"/></xsd:sequence>"#)
    };
    let mut schema = String::new();
    for i in 0..16 {
        let next = format!(r#"<xsd:{kind} ref="tns:X{}"/>"#, i + 1);
        let body = if attributes { format!("{next}{next}") } else { format!("<xsd:sequence>{next}{next}</xsd:sequence>") };
        schema.push_str(&format!(r#"<xsd:{kind} name="X{i}">{body}</xsd:{kind}>"#));
    }
    schema.push_str(&format!(r#"<xsd:{kind} name="X16">{leaf}</xsd:{kind}>"#));
    schema.push_str(&format!(r#"<xsd:element name="Req"><xsd:complexType><xsd:{kind} ref="tns:X0"/></xsd:complexType></xsd:element>"#));
    schema
}

#[test]
fn branching_acyclic_groups_hit_the_shared_budget() {
    for attributes in [false, true] {
        let (r, env) = op_envelope(&fan_out(attributes));
        assert!(has(&r, "sample_size_limit"), "attributes: {attributes}");
        assert!(!has(&r, "recursive_schema"), "acyclic groups are not recursive");
        assert!(env.len() < 4 * 1024 * 1024, "envelope is {} bytes", env.len());
        if attributes {
            // Every path reaches the same attribute: it is written once, so
            // the envelope stays well-formed.
            parse(&env);
            assert_eq!(env.matches(" leaf=\"").count(), 1, "{env}");
        } else {
            let leaves = count(&env, "leaf");
            assert!(leaves > 0 && leaves < 20_000, "{leaves} leaves");
        }
    }
}

#[test]
fn branching_extension_bases_hit_the_shared_budget() {
    // Each type extends the next one twice (2^16 bases without a budget).
    let mut schema = String::new();
    for i in 0..16 {
        let ext = format!(r#"<xsd:complexContent><xsd:extension base="tns:T{}"/></xsd:complexContent>"#, i + 1);
        schema.push_str(&format!(r#"<xsd:complexType name="T{i}">{ext}{ext}</xsd:complexType>"#));
    }
    schema.push_str(concat!(
        r#"<xsd:complexType name="T16"><xsd:sequence><xsd:element name="leaf" type="xsd:string"/></xsd:sequence>"#,
        r#"<xsd:attribute name="mark" type="xsd:string" use="required"/></xsd:complexType>"#,
        r#"<xsd:element name="Req" type="tns:T0"/>"#,
    ));
    let (r, env) = op_envelope(&schema);
    assert!(has(&r, "sample_size_limit"));
    assert!(env.len() < 4 * 1024 * 1024, "envelope is {} bytes", env.len());
    let leaves = count(&env, "leaf");
    assert!(leaves > 0 && leaves < 20_000, "{leaves} leaves");
    assert_eq!(env.matches(" mark=\"").count(), 1, "{env}");
}

#[test]
fn message_parts_are_charged_like_elements() {
    let schema = concat!(
        r#"<xsd:simpleType name="S"><xsd:restriction base="xsd:string">"#,
        r#"<xsd:minLength value="4096"/></xsd:restriction></xsd:simpleType>"#,
    );
    let parts: String = (0..100_000).map(|i| format!(r#"<part name="p{i}" type="tns:S"/>"#)).collect();
    let (r, env) = op_envelope_with(schema, &parts);
    assert!(has(&r, "sample_size_limit"));
    assert!(env.len() < 9 * 1024 * 1024, "envelope is {} bytes", env.len());
    parse(&env);
    // Parts whose element is missing are charged too.
    let parts: String = (0..100_000).map(|i| format!(r#"<part name="p{i}" element="tns:Missing{i}"/>"#)).collect();
    let (r, env) = op_envelope_with(schema, &parts);
    assert!(has(&r, "sample_size_limit"));
    assert!(env.len() < 4 * 1024 * 1024, "envelope is {} bytes", env.len());
}

/// `{ops}` operations of one binding share the message `In`, whose element
/// repeats `Big` (a fixed value of `{big}`) 200 times.
const MANY_OPERATIONS: &str = r#"<?xml version="1.0"?>
<definitions xmlns="http://schemas.xmlsoap.org/wsdl/" xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
    xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:tns="urn:g" targetNamespace="urn:g" name="G">
  <types>
    <xsd:schema targetNamespace="urn:g">
      <xsd:element name="Big" type="xsd:string" fixed="{big}"/>
      <xsd:element name="Req"><xsd:complexType><xsd:sequence>{refs}</xsd:sequence></xsd:complexType></xsd:element>
    </xsd:schema>
  </types>
  <message name="In"><part name="body" element="tns:Req"/></message>
  <portType name="PT">{ops}</portType>
  <binding name="B" type="tns:PT">
    <soap:binding style="document" transport="http://schemas.xmlsoap.org/soap/http"/>
    {bops}
  </binding>
  <service name="S"><port name="P" binding="tns:B"><soap:address location="https://example.com/soap"/></port></service>
</definitions>"#;

#[test]
fn the_import_wide_envelope_budget_is_shared_by_operations() {
    // Ten operations, each asking for about 20 MB; with a 1 MiB input limit
    // the whole import may generate 4 MiB.
    let ops: String = (0..10).map(|i| format!(r#"<operation name="Op{i}"><input message="tns:In"/></operation>"#)).collect();
    let body = r#"<input><soap:body use="literal"/></input>"#;
    let bops: String = (0..10).map(|i| format!(r#"<operation name="Op{i}">{body}</operation>"#)).collect();
    let doc = MANY_OPERATIONS
        .replace("{big}", &"v".repeat(100 * 1024))
        .replace("{refs}", &r#"<xsd:element ref="tns:Big"/>"#.repeat(200))
        .replace("{ops}", &ops)
        .replace("{bops}", &bops);
    let r = import(doc.as_bytes(), &ImportOptions { max_bytes: 1024 * 1024, ..opts() }).unwrap();
    let envelopes: Vec<String> = (0..10).map(|i| soap(&r, &format!("S/P/Op{i}")).1).collect();
    let total: usize = envelopes.iter().map(String::len).sum();
    assert!(total < 5 * 1024 * 1024, "the envelopes hold {total} bytes");
    assert!(has(&r, "sample_size_limit"));
    for env in &envelopes {
        parse(env);
    }
}

const REUSED_GROUPS: &str = r#"
<xsd:attributeGroup name="Common"><xsd:attribute name="lang" type="xsd:string" use="required"/></xsd:attributeGroup>
<xsd:attributeGroup name="Both"><xsd:attributeGroup ref="tns:Common"/></xsd:attributeGroup>
<xsd:group name="Pair">
  <xsd:sequence><xsd:element name="a" type="xsd:string"/><xsd:element name="b" type="xsd:int"/></xsd:sequence>
</xsd:group>
<xsd:complexType name="Row"><xsd:group ref="tns:Pair"/><xsd:attributeGroup ref="tns:Both"/></xsd:complexType>
<xsd:element name="Req">
  <xsd:complexType>
    <xsd:sequence>
      <xsd:element name="first" type="tns:Row"/>
      <xsd:element name="second" type="tns:Row"/>
      <xsd:group ref="tns:Pair"/>
    </xsd:sequence>
  </xsd:complexType>
</xsd:element>"#;

#[test]
fn reused_groups_still_expand_at_every_use() {
    let (r, env) = op_envelope(REUSED_GROUPS);
    assert!(!has(&r, "recursive_schema"));
    assert!(!has(&r, "sample_size_limit"));
    parse(&env);
    assert_eq!(count(&env, "a"), 3, "{env}");
    assert_eq!(count(&env, "b"), 3, "{env}");
    assert_eq!(env.matches(" lang=\"").count(), 2, "{env}");
}
