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
            assert!((1..20_000).contains(&leaves), "{leaves} leaves");
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
    assert!((1..20_000).contains(&leaves), "{leaves} leaves");
    assert_eq!(env.matches(" mark=\"").count(), 1, "{env}");
}

#[test]
fn message_parts_are_charged_like_elements() {
    let schema = concat!(
        r#"<xsd:simpleType name="S"><xsd:restriction base="xsd:string">"#,
        r#"<xsd:minLength value="4096"/></xsd:restriction></xsd:simpleType>"#,
    );
    let parts = (0..100_000).map(|i| format!(r#"<part name="p{i}" type="tns:S"/>"#)).collect::<Vec<_>>().concat();
    let (r, env) = op_envelope_with(schema, &parts);
    assert!(has(&r, "sample_size_limit"));
    assert!(env.len() < 9 * 1024 * 1024, "envelope is {} bytes", env.len());
    parse(&env);
    // Parts whose element is missing are charged too.
    let parts = (0..100_000).map(|i| format!(r#"<part name="p{i}" element="tns:Missing{i}"/>"#)).collect::<Vec<_>>().concat();
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
    let ops = (0..10).map(|i| format!(r#"<operation name="Op{i}"><input message="tns:In"/></operation>"#)).collect::<Vec<_>>().concat();
    let body = r#"<input><soap:body use="literal"/></input>"#;
    let bops = (0..10).map(|i| format!(r#"<operation name="Op{i}">{body}</operation>"#)).collect::<Vec<_>>().concat();
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

#[test]
fn generated_envelope_bytes_are_capped() {
    let big = "v".repeat(100 * 1024);
    let refs = r#"<xsd:element ref="tns:Big"/>"#.repeat(200);
    let mut schema = format!(r#"<xsd:element name="Big" type="xsd:string" fixed="{big}"/>"#);
    schema.push_str(&format!(
        r#"<xsd:element name="Req"><xsd:complexType><xsd:sequence>{refs}</xsd:sequence></xsd:complexType></xsd:element>"#
    ));
    let (r, env) = op_envelope(&schema);
    assert!(has(&r, "sample_size_limit"));
    assert!(env.len() < 9 * 1024 * 1024, "envelope is {} bytes", env.len());
    // What was generated before the limit is kept and stays well-formed.
    let copies = count(&env, "Big");
    assert!((1..200).contains(&copies), "{copies} copies");
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

#[test]
fn elements_with_too_many_namespaces_in_scope_are_refused() {
    let doc = |n: usize| {
        let decls = (0..n).map(|i| format!(r#" xmlns:p{i}="urn:p{i}""#)).collect::<Vec<_>>().concat();
        format!(r#"<definitions xmlns="http://schemas.xmlsoap.org/wsdl/" targetNamespace="urn:x"{decls}/>"#)
    };
    match import(doc(300).as_bytes(), &opts()) {
        Err(ImportError::LimitExceeded { limit, .. }) => assert_eq!(limit, 256),
        other => panic!("expected the namespace limit, got {:?}", other.map(|r| r.requests.len())),
    }
    assert!(import(doc(200).as_bytes(), &opts()).is_ok());
}

/// One binding that every port in `{ports}` (of service `{service}`) uses;
/// `{pad}` stands for padding before what an import looks up in the
/// binding, its operation, the operation's input and the portType operation.
const SHARED_BINDING: &str = r#"<?xml version="1.0"?>
<definitions xmlns="http://schemas.xmlsoap.org/wsdl/" xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
    xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:tns="urn:w" targetNamespace="urn:w" name="W">
  <types><xsd:schema targetNamespace="urn:w"><xsd:element name="Req" type="xsd:string"/></xsd:schema></types>
  <message name="In"><part name="body" element="tns:Req"/></message>
  <portType name="PT"><operation name="Op">{pad}<input message="tns:In"/></operation></portType>
  <binding name="B" type="tns:PT">
    {pad}<soap:binding style="document" transport="http://schemas.xmlsoap.org/soap/http"/>
    <operation name="Op">{pad}<soap:operation soapAction="urn:w/Op"/><input>{pad}<soap:body use="literal"/></input></operation>
  </binding>
  <service name="{service}">{ports}</service>
</definitions>"#;

fn shared_binding(service: &str, ports: usize, pad: usize) -> String {
    let port = |i: usize| format!(r#"<port name="P{i}" binding="tns:B"><soap:address location="https://example.com/{i}"/></port>"#);
    let ports: String = (0..ports).map(port).collect();
    SHARED_BINDING.replace("{pad}", &"<ext/>".repeat(pad)).replace("{ports}", &ports).replace("{service}", service)
}

#[test]
fn ports_sharing_a_binding_read_it_once() {
    // 2000 ports use a binding padded with 100k elements in four places:
    // looking its children up again for every port and operation took about
    // 1.6e9 steps. The indexes read each list once.
    let r = import(shared_binding("S", 2_000, 100_000).as_bytes(), &opts()).unwrap();
    assert_eq!(r.requests.len(), 2_000);
    for key in ["S/P0/Op", "S/P1999/Op"] {
        let (version, env, action) = soap(&r, key);
        assert_eq!(version, SoapVersion::Soap11);
        assert_eq!(action.as_deref(), Some("urn:w/Op"));
        assert!(parse(&env).descendants().any(|n| n.has_tag_name(("urn:w", "Req"))), "{env}");
    }
    // Once no operation fits, the remaining ports are counted without a
    // folder of their own (each port made one before).
    let r = import(shared_binding("S", 2_000, 0).as_bytes(), &ImportOptions { max_operations: 10, ..opts() }).unwrap();
    assert_eq!(r.requests.len(), 10);
    assert_eq!(r.folders.len(), 11, "one service folder and one per imported port");
    assert_eq!(r.report.counts.operations_found, 2_000);
    assert_eq!(r.report.counts.skipped_operations, 1_990);
}

#[test]
fn names_copied_into_every_port_are_charged() {
    // A 200 KB service name is part of every port's folder and request key:
    // 2000 ports copied it 4000 times. The copies are charged to the text
    // budget (4 MiB for a 1 MiB input limit), so the import stops early.
    let doc = shared_binding(&"s".repeat(200 * 1024), 2_000, 0);
    let r = import(doc.as_bytes(), &ImportOptions { max_bytes: 1024 * 1024, ..opts() }).unwrap();
    assert!(has(&r, "text_size_limit"));
    assert!((1..20).contains(&r.requests.len()), "{} requests", r.requests.len());
    assert_eq!(r.report.counts.operations_found, 2_000);
}

#[test]
fn attributes_per_element_are_counted_before_parsing() {
    let doc = |attrs: usize, wrap: (&str, &str)| {
        let attrs: String = (0..attrs).map(|i| format!(r#" a{i}="{i}""#)).collect();
        let el = format!("{}<x{attrs}/>{}", wrap.0, wrap.1);
        format!(r#"<definitions xmlns="http://schemas.xmlsoap.org/wsdl/" targetNamespace="urn:x">{el}</definitions>"#)
    };
    assert!(import(doc(256, ("", "")).as_bytes(), &opts()).is_ok());
    // Markup inside comments and CDATA sections is not counted.
    assert!(import(doc(5_000, ("<!--", "-->")).as_bytes(), &opts()).is_ok());
    assert!(import(doc(5_000, ("<documentation><![CDATA[", "]]></documentation>")).as_bytes(), &opts()).is_ok());
    // The parser compares each attribute with every earlier one: 1M
    // attributes on one element are refused before it runs.
    for n in [257, 1_000_000] {
        match import(doc(n, ("", "")).as_bytes(), &opts()) {
            Err(ImportError::LimitExceeded { what, limit }) => {
                assert_eq!(limit, 256);
                assert!(what.contains("attributes"), "{what}");
            }
            other => panic!("expected the attribute limit, got {:?}", other.map(|r| r.requests.len())),
        }
    }
}

#[test]
fn namespace_declarations_are_counted_before_parsing() {
    // The parser copies the root's 200 namespaces for every child that
    // declares one of its own, before any element is checked.
    let doc = |kids: usize| {
        let decls: String = (0..200).map(|i| format!(r#" xmlns:p{i}="urn:p{i}""#)).collect();
        let kids = r#"<x xmlns:q="urn:q"/>"#.repeat(kids);
        format!(r#"<definitions xmlns="http://schemas.xmlsoap.org/wsdl/" targetNamespace="urn:x"{decls}>{kids}</definitions>"#)
    };
    // 1 + 200 + 823 = 1024 declarations are parsed; one more is refused
    // before parsing, and so is a million.
    assert!(import(doc(823).as_bytes(), &opts()).is_ok());
    for kids in [824, 1_000_000] {
        match import(doc(kids).as_bytes(), &opts()) {
            Err(ImportError::LimitExceeded { what, limit }) => {
                assert_eq!(limit, 1024);
                assert!(what.contains("xmlns"), "{what}");
            }
            other => panic!("expected the declaration limit, got {:?}", other.map(|r| r.requests.len())),
        }
    }
}

#[test]
fn namespace_uris_and_attribute_pairs_are_bounded_before_parsing() {
    let refused = |doc: &str, word: &str, want: usize| match import(doc.as_bytes(), &opts()) {
        Err(ImportError::LimitExceeded { what, limit }) => {
            assert_eq!(limit, want);
            assert!(what.contains(word), "{what}");
        }
        other => panic!("expected the {word} limit, got {:?}", other.map(|r| r.requests.len())),
    };
    // The parser compares the full namespace URI of every pair of prefixed
    // attributes: one 64 KiB URI shared by 256 of them was about 2 GB per element.
    let uri = format!("urn:{}", "u".repeat(64 * 1024));
    let attrs: String = (0..250).map(|i| format!(r#" p:a{i}="{i}""#)).collect();
    let doc = format!(r#"<definitions xmlns="http://schemas.xmlsoap.org/wsdl/" xmlns:p="{uri}"><x{attrs}/></definitions>"#);
    refused(&doc, "URI", 2_048);
    // 100 attributes on each of 4000 elements: about 2e7 pairs, over 2^24.
    let attrs: String = (0..100).map(|i| format!(r#" a{i}="{i}""#)).collect();
    let kids = format!("<x{attrs}/>").repeat(4_000);
    let doc = format!(r#"<definitions xmlns="http://schemas.xmlsoap.org/wsdl/">{kids}</definitions>"#);
    refused(&doc, "pairs", 1 << 24);
}
