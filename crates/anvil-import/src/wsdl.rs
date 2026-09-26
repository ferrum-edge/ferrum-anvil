//! WSDL 1.1 → SOAP 1.1/1.2 requests with blank/sample envelopes.
//!
//! XML is parsed with `roxmltree` with DTDs refused (DATA-013); nothing is
//! ever fetched: `wsdl:import`, `xsd:import`/`include`/`redefine` with a
//! `schemaLocation` are reported as external references. Envelopes are
//! generated from the inline XSD subset documented in `docs/import.md`
//! (sequence/all/choice, element/ref, named and anonymous complex and simple
//! types, extension, enumerations, occurrence, attributes); anything else is
//! reported with its element path.

use crate::builder::Builder;
use crate::report::ImportReport;
use crate::util::{SplitMix64, fnv1a64, is_credential_name, sanitize_var};
use crate::{ImportError, SampleMode};
use anvil_domain::Id;
use anvil_domain::auth::AuthConfig;
use anvil_domain::request::{Body, RequestSpec, SoapVersion};
use anvil_domain::workspace::Variable;
use base64::Engine as _;
use roxmltree::{Document, Node, ParsingOptions};
use std::collections::HashMap;

const WSDL_NS: &str = "http://schemas.xmlsoap.org/wsdl/";
const SOAP11_BIND: &str = "http://schemas.xmlsoap.org/wsdl/soap/";
const SOAP12_BIND: &str = "http://schemas.xmlsoap.org/wsdl/soap12/";
const HTTP_BIND: &str = "http://schemas.xmlsoap.org/wsdl/http/";
const XSD_NS: &str = "http://www.w3.org/2001/XMLSchema";
const SOAP11_ENV: &str = "http://schemas.xmlsoap.org/soap/envelope/";
const SOAP12_ENV: &str = "http://www.w3.org/2003/05/soap-envelope";
const SOAP_ENC: &str = "http://schemas.xmlsoap.org/soap/encoding/";
const MAX_DEPTH: usize = 40;

type QName = (String, String);

fn is(n: &Node, ns: &str, local: &str) -> bool {
    n.is_element() && n.tag_name().name() == local && n.tag_name().namespace() == Some(ns)
}

fn children<'a, 'i>(n: Node<'a, 'i>, ns: &'a str) -> impl Iterator<Item = Node<'a, 'i>> + 'a {
    n.children().filter(move |c| c.is_element() && c.tag_name().namespace() == Some(ns))
}

fn child<'a, 'i>(n: Node<'a, 'i>, ns: &'a str, local: &str) -> Option<Node<'a, 'i>> {
    n.children().find(|c| is(c, ns, local))
}

/// Resolve a QName attribute value in the scope of `n`.
fn qname(n: Node, value: &str) -> QName {
    let (prefix, local) = match value.split_once(':') {
        Some((p, l)) => (Some(p), l),
        None => (None, value),
    };
    let ns = n.lookup_namespace_uri(prefix).unwrap_or("").to_string();
    (ns, local.to_string())
}

/// Element path used as the report location (`/definitions/binding[@name='X']/…`).
fn path(n: Node) -> String {
    let mut parts: Vec<String> = n
        .ancestors()
        .filter(|a| a.is_element())
        .map(|a| match a.attribute("name") {
            Some(name) => format!("{}[@name='{name}']", a.tag_name().name()),
            None => a.tag_name().name().to_string(),
        })
        .collect();
    parts.reverse();
    format!("/{}", parts.join("/"))
}

fn doc_text(n: Node) -> String {
    child(n, WSDL_NS, "documentation").and_then(|d| d.text()).map(|t| t.trim().to_string()).unwrap_or_default()
}

pub(crate) fn import(text: &str, b: &mut Builder) -> Result<(), ImportError> {
    let limit = u32::try_from(b.opts.max_nodes).unwrap_or(u32::MAX);
    let opts = ParsingOptions { allow_dtd: false, nodes_limit: limit, ..ParsingOptions::default() };
    let doc = Document::parse_with_options(text, opts).map_err(|e| match e {
        roxmltree::Error::DtdDetected => {
            ImportError::UnsafeXml { message: "document type definitions (DTDs/entity declarations) are refused in WSDL imports".into() }
        }
        roxmltree::Error::NodesLimitReached => ImportError::LimitExceeded { what: "XML nodes".into(), limit: b.opts.max_nodes },
        other => {
            let pos = other.pos();
            ImportError::Syntax {
                syntax: "XML".into(),
                message: other.to_string(),
                line: Some(pos.row as usize),
                column: Some(pos.col as usize),
            }
        }
    })?;
    if text.contains("<!DOCTYPE") {
        b.report.warn("doctype_ignored", "/", "the DOCTYPE declaration is ignored; external DTDs are never loaded");
    }
    let root = doc.root_element();
    if !is(&root, WSDL_NS, "definitions") {
        return Err(ImportError::Invalid {
            dialect: crate::Dialect::Wsdl11,
            pointer: "/".into(),
            message: format!("root element is <{}>, not wsdl:definitions", root.tag_name().name()),
        });
    }
    let tns = root.attribute("targetNamespace").unwrap_or("").to_string();
    let title = root
        .attribute("name")
        .map(str::to_string)
        .or_else(|| child(root, WSDL_NS, "service").and_then(|s| s.attribute("name")).map(str::to_string));
    if let Some(t) = &title {
        b.title = Some(t.clone());
        b.workspace.name = t.clone();
    }
    b.workspace.description = doc_text(root);
    b.workspace.auth = AuthConfig::None;

    for imp in children(root, WSDL_NS).filter(|c| c.tag_name().name() == "import") {
        let loc = imp.attribute("location").unwrap_or("(no location)");
        b.report.external_ref(loc, &path(imp));
    }

    let schemas = SchemaSet::new(root, &mut b.report);
    let by_name = |local: &str| -> HashMap<String, Node> {
        children(root, WSDL_NS)
            .filter(|c| c.tag_name().name() == local)
            .filter_map(|c| c.attribute("name").map(|n| (n.to_string(), c)))
            .collect()
    };
    let messages = by_name("message");
    let port_types = by_name("portType");
    let bindings = by_name("binding");

    let mut endpoint_vars: Vec<Variable> = vec![];
    let mut used_bindings: Vec<String> = vec![];
    let ctx = WsdlCtx { messages: &messages, port_types: &port_types, schemas: &schemas, tns: &tns };

    for service in children(root, WSDL_NS).filter(|c| c.tag_name().name() == "service") {
        let sname = service.attribute("name").unwrap_or("Service").to_string();
        let sfolder = b.folder(None, &format!("service:{sname}"), &sname);
        if let Some(f) = b.folder_mut(sfolder) {
            f.description = doc_text(service);
        }
        for port in children(service, WSDL_NS).filter(|c| c.tag_name().name() == "port") {
            let pname = port.attribute("name").unwrap_or("Port").to_string();
            let Some(bref) = port.attribute("binding") else {
                b.report.warn("port_without_binding", &path(port), "port has no binding; skipped");
                continue;
            };
            let (_, blocal) = qname(port, bref);
            let Some(binding) = bindings.get(&blocal).copied() else {
                b.report.warn("unresolved_binding", &path(port), format!("binding '{bref}' is not defined in this document"));
                continue;
            };
            used_bindings.push(blocal.clone());
            let is_soap = child(binding, SOAP11_BIND, "binding").is_some() || child(binding, SOAP12_BIND, "binding").is_some();
            let address = port
                .children()
                .find(|c| c.is_element() && c.tag_name().name() == "address")
                .and_then(|a| a.attribute("location"))
                .map(str::to_string);
            let var = sanitize_var(&format!("{pname}_url"));
            match &address {
                _ if !is_soap => {}
                Some(a) => {
                    if !a.contains("://") {
                        b.report.warn("relative_endpoint", &path(port), format!("endpoint address '{a}' is not an absolute URL"));
                    }
                    endpoint_vars.push(Variable::plain(&var, a));
                }
                None => b.report.require_var(&var, false, "the port has no soap:address location", &path(port)),
            }
            import_binding(b, &ctx, binding, Some(sfolder), &format!("{sname}/{pname}"), &pname, &var);
        }
    }
    // Bindings no service exposes: still importable, endpoint unknown
    // (document order, for deterministic output).
    let binding_order: Vec<(String, Node)> = children(root, WSDL_NS)
        .filter(|c| c.tag_name().name() == "binding")
        .filter_map(|c| c.attribute("name").map(|n| (n.to_string(), c)))
        .collect();
    for (bname, binding) in &binding_order {
        if used_bindings.contains(bname) {
            continue;
        }
        let var = sanitize_var(&format!("{bname}_url"));
        b.report.require_var(&var, false, "binding is not exposed by any service port; set its endpoint URL", &path(*binding));
        b.report.warn(
            "binding_without_service",
            &path(*binding),
            format!("binding '{bname}' has no service port; its endpoint is the variable {{{{{var}}}}}"),
        );
        import_binding(b, &ctx, *binding, None, &format!("binding/{bname}"), bname, &var);
    }
    if !endpoint_vars.is_empty() {
        let id = b.add_environment("wsdl:endpoints", "WSDL endpoints", endpoint_vars);
        b.workspace.active_environment_id = Some(id);
    }
    Ok(())
}

struct WsdlCtx<'r, 'a, 'i> {
    messages: &'r HashMap<String, Node<'a, 'i>>,
    port_types: &'r HashMap<String, Node<'a, 'i>>,
    schemas: &'r SchemaSet<'a, 'i>,
    tns: &'r str,
}

fn import_binding(b: &mut Builder, ctx: &WsdlCtx, binding: Node, parent: Option<Id>, key_prefix: &str, label: &str, url_var: &str) {
    let bpath = path(binding);
    let (version, soap_binding) = if let Some(sb) = child(binding, SOAP11_BIND, "binding") {
        (SoapVersion::Soap11, sb)
    } else if let Some(sb) = child(binding, SOAP12_BIND, "binding") {
        (SoapVersion::Soap12, sb)
    } else {
        let what = if child(binding, HTTP_BIND, "binding").is_some() { "HTTP GET/POST binding" } else { "non-SOAP binding" };
        let n = children(binding, WSDL_NS).filter(|c| c.tag_name().name() == "operation").count();
        for _ in 0..n {
            b.report.counts.operations_found += 1;
            b.skipped();
        }
        b.report.unsupported(
            "wsdl_binding_unsupported",
            &bpath,
            format!("{what} is not supported; only SOAP 1.1/1.2 bindings are imported"),
        );
        return;
    };
    let transport = soap_binding.attribute("transport").unwrap_or("");
    if !transport.is_empty() && transport != "http://schemas.xmlsoap.org/soap/http" {
        b.report.unsupported("soap_transport", &bpath, format!("SOAP transport '{transport}' is not supported; HTTP is assumed"));
    }
    let default_style = soap_binding.attribute("style").unwrap_or("document").to_string();
    let vlabel = if version == SoapVersion::Soap11 { "SOAP 1.1" } else { "SOAP 1.2" };
    let folder = b.folder(parent, &format!("port:{key_prefix}"), &format!("{label} ({vlabel})"));
    let port_type = binding.attribute("type").map(|t| qname(binding, t).1).and_then(|n| ctx.port_types.get(&n).copied());
    if port_type.is_none() {
        b.report.warn(
            "unresolved_port_type",
            &bpath,
            "the binding's portType is not defined in this document; envelopes have empty bodies",
        );
    }
    let bind_ns = if version == SoapVersion::Soap11 { SOAP11_BIND } else { SOAP12_BIND };
    for bop in children(binding, WSDL_NS).filter(|c| c.tag_name().name() == "operation") {
        let oname = bop.attribute("name").unwrap_or("").to_string();
        let opath = path(bop);
        if !b.admit(&opath) {
            continue;
        }
        let pt_op = port_type.and_then(|pt| {
            children(pt, WSDL_NS).find(|o| o.tag_name().name() == "operation" && o.attribute("name") == Some(oname.as_str()))
        });
        let Some(pt_op) = pt_op else {
            if port_type.is_some() {
                b.report.warn("unresolved_operation", &opath, format!("operation '{oname}' is not declared in the portType"));
            }
            b.skipped();
            continue;
        };
        let input = child(pt_op, WSDL_NS, "input");
        let Some(input) = input else {
            b.report.unsupported(
                "wsdl_notification_operation",
                &opath,
                "notification / solicit-response operations (no input) are server-initiated and not imported",
            );
            b.skipped();
            continue;
        };
        let soap_op = child(bop, bind_ns, "operation");
        let action = soap_op.and_then(|o| o.attribute("soapAction")).map(str::to_string);
        let style = soap_op.and_then(|o| o.attribute("style")).map(str::to_string).unwrap_or_else(|| default_style.clone());
        let bin = child(bop, WSDL_NS, "input");
        let body_el = bin.and_then(|i| child(i, bind_ns, "body"));
        let use_ = body_el.and_then(|e| e.attribute("use")).unwrap_or("literal");
        if use_ == "encoded" {
            b.report.unsupported(
                "soap_encoded",
                &opath,
                "use=\"encoded\" (SOAP encoding) is not supported; the envelope is generated as literal XML without xsi:type annotations",
            );
        }
        let rpc_ns = body_el.and_then(|e| e.attribute("namespace")).unwrap_or(ctx.tns).to_string();
        let parts_filter: Option<Vec<String>> =
            body_el.and_then(|e| e.attribute("parts")).map(|p| p.split_whitespace().map(str::to_string).collect());

        let key = format!("{key_prefix}/{oname}");
        let seed = b.opts.seed ^ fnv1a64(&key);
        let envelope = {
            let mut g = XsdGen::new(ctx.schemas, &mut b.report, b.opts.mode, b.opts.include_optional, seed, b.opts.max_sample_nodes);
            let mut body_xml = String::new();
            let msg = input.attribute("message").map(|m| qname(input, m).1).and_then(|m| ctx.messages.get(&m).copied());
            match msg {
                Some(msg) => {
                    let parts: Vec<Node> = children(msg, WSDL_NS)
                        .filter(|p| p.tag_name().name() == "part")
                        .filter(|p| parts_filter.as_ref().is_none_or(|f| f.iter().any(|x| Some(x.as_str()) == p.attribute("name"))))
                        .collect();
                    if style == "rpc" {
                        let pfx = g.out.prefix_for(&rpc_ns);
                        body_xml.push_str(&format!("    <{pfx}:{oname}>\n"));
                        for p in &parts {
                            g.part(*p, true, 3, &mut body_xml);
                        }
                        body_xml.push_str(&format!("    </{pfx}:{oname}>\n"));
                    } else {
                        for p in &parts {
                            g.part(*p, false, 2, &mut body_xml);
                        }
                    }
                }
                None => g.report.warn("unresolved_message", &opath, "the input message is not defined in this document; empty body"),
            }
            let mut header_xml = String::new();
            for h in bin.into_iter().flat_map(|i| i.children()).filter(|c| is(c, bind_ns, "header")) {
                let hmsg = h.attribute("message").map(|m| qname(h, m).1).and_then(|m| ctx.messages.get(&m).copied());
                let hpart = h.attribute("part");
                match hmsg.and_then(|m| children(m, WSDL_NS).find(|p| p.tag_name().name() == "part" && p.attribute("name") == hpart)) {
                    Some(p) => g.part(p, false, 2, &mut header_xml),
                    None => g.report.warn("unresolved_header", &path(h), "SOAP header part is not defined in this document"),
                }
            }
            g.out.envelope(version, &header_xml, &body_xml)
        };
        let action = match (version, action) {
            (SoapVersion::Soap12, Some(a)) if a.is_empty() => None,
            (_, a) => a,
        };
        let mut spec = RequestSpec::http("POST", &format!("{{{{{url_var}}}}}"));
        spec.body = Body::Soap { version, envelope, action };
        let req = b.add_request(Some(folder), &oname, &key, spec, &opath);
        req.description = doc_text(pt_op);
        req.tags = vec![vlabel.to_string()];
    }
}

// ----------------------------------------------------------------------
// XSD subset
// ----------------------------------------------------------------------

struct SchemaSet<'a, 'i> {
    elements: HashMap<QName, Node<'a, 'i>>,
    types: HashMap<QName, Node<'a, 'i>>,
    groups: HashMap<QName, Node<'a, 'i>>,
    attr_groups: HashMap<QName, Node<'a, 'i>>,
    attributes: HashMap<QName, Node<'a, 'i>>,
}

impl<'a, 'i> SchemaSet<'a, 'i> {
    fn new(root: Node<'a, 'i>, report: &mut ImportReport) -> Self {
        let mut s = SchemaSet {
            elements: HashMap::new(),
            types: HashMap::new(),
            groups: HashMap::new(),
            attr_groups: HashMap::new(),
            attributes: HashMap::new(),
        };
        let Some(types) = child(root, WSDL_NS, "types") else { return s };
        let schemas: Vec<Node> = types.children().filter(|c| is(c, XSD_NS, "schema")).collect();
        let inline_ns: Vec<&str> = schemas.iter().map(|x| x.attribute("targetNamespace").unwrap_or("")).collect();
        for schema in &schemas {
            let tns = schema.attribute("targetNamespace").unwrap_or("").to_string();
            for c in schema.children().filter(|c| c.is_element() && c.tag_name().namespace() == Some(XSD_NS)) {
                let name = c.attribute("name").map(str::to_string);
                let key = |n: String| (tns.clone(), n);
                match (c.tag_name().name(), name) {
                    ("element", Some(n)) => {
                        s.elements.insert(key(n), c);
                    }
                    ("complexType" | "simpleType", Some(n)) => {
                        s.types.insert(key(n), c);
                    }
                    ("group", Some(n)) => {
                        s.groups.insert(key(n), c);
                    }
                    ("attributeGroup", Some(n)) => {
                        s.attr_groups.insert(key(n), c);
                    }
                    ("attribute", Some(n)) => {
                        s.attributes.insert(key(n), c);
                    }
                    ("import", _) => {
                        let ns = c.attribute("namespace").unwrap_or("");
                        if let Some(loc) = c.attribute("schemaLocation")
                            && !inline_ns.contains(&ns)
                        {
                            report.external_ref(loc, &path(c));
                        } else if !inline_ns.contains(&ns) && ns != SOAP_ENC && ns != XSD_NS && !ns.is_empty() {
                            report.warn(
                                "unresolved_schema_import",
                                &path(c),
                                format!("namespace '{ns}' is imported without an inline schema; its types cannot be generated"),
                            );
                        }
                    }
                    ("include" | "redefine" | "override", _) => {
                        if let Some(loc) = c.attribute("schemaLocation") {
                            report.external_ref(loc, &path(c));
                        }
                    }
                    ("annotation" | "notation", _) => {}
                    (other, _) => report.unsupported("xsd_construct", &path(c), format!("top-level xsd:{other} is not supported")),
                }
            }
        }
        s
    }

    fn lookup<'m>(map: &'m HashMap<QName, Node<'a, 'i>>, q: &QName) -> Option<Node<'a, 'i>> {
        if let Some(n) = map.get(q) {
            return Some(*n);
        }
        // Lenient fallback for sloppy prefix declarations: unique local name.
        let mut it = map.iter().filter(|(k, _)| k.1 == q.1);
        match (it.next(), it.next()) {
            (Some((_, n)), None) => Some(*n),
            _ => None,
        }
    }
}

fn schema_of<'a, 'i>(n: Node<'a, 'i>) -> Option<Node<'a, 'i>> {
    n.ancestors().find(|a| is(a, XSD_NS, "schema"))
}

/// Envelope writer with namespace-prefix management.
struct XmlOut {
    decls: Vec<(String, String)>,
}

impl XmlOut {
    fn prefix_for(&mut self, ns: &str) -> String {
        if let Some((_, p)) = self.decls.iter().find(|(n, _)| n == ns) {
            return p.clone();
        }
        let p = format!("ns{}", self.decls.len() + 1);
        self.decls.push((ns.to_string(), p.clone()));
        p
    }

    fn envelope(&self, version: SoapVersion, header: &str, body: &str) -> String {
        let env_ns = if version == SoapVersion::Soap11 { SOAP11_ENV } else { SOAP12_ENV };
        let mut decl = format!(" xmlns:soapenv=\"{env_ns}\"");
        for (ns, p) in &self.decls {
            decl.push_str(&format!(" xmlns:{p}=\"{}\"", esc(ns, true)));
        }
        let header = if header.is_empty() {
            "  <soapenv:Header/>\n".to_string()
        } else {
            format!("  <soapenv:Header>\n{header}  </soapenv:Header>\n")
        };
        format!("<soapenv:Envelope{decl}>\n{header}  <soapenv:Body>\n{body}  </soapenv:Body>\n</soapenv:Envelope>\n")
    }
}

fn esc(s: &str, attr: bool) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' if attr => o.push_str("&quot;"),
            c => o.push(c),
        }
    }
    o
}

#[derive(Default)]
struct Content {
    attrs: String,
    children: String,
    text: Option<String>,
}

#[derive(Default, Clone, Copy)]
struct Facets {
    min: Option<f64>,
    max: Option<f64>,
    min_len: Option<usize>,
    max_len: Option<usize>,
}

struct XsdGen<'r, 'a, 'i> {
    set: &'r SchemaSet<'a, 'i>,
    report: &'r mut ImportReport,
    mode: SampleMode,
    include_optional: bool,
    rng: SplitMix64,
    type_stack: Vec<QName>,
    nodes: usize,
    max_nodes: usize,
    out: XmlOut,
}

impl<'r, 'a, 'i> XsdGen<'r, 'a, 'i> {
    fn new(
        set: &'r SchemaSet<'a, 'i>,
        report: &'r mut ImportReport,
        mode: SampleMode,
        include_optional: bool,
        seed: u64,
        max_nodes: usize,
    ) -> Self {
        XsdGen {
            set,
            report,
            mode,
            include_optional,
            rng: SplitMix64::new(seed),
            type_stack: vec![],
            nodes: 0,
            max_nodes,
            out: XmlOut { decls: vec![] },
        }
    }

    fn charge(&mut self, n: Node) -> bool {
        if self.nodes >= self.max_nodes {
            self.report.warn(
                "sample_size_limit",
                &path(n),
                format!("envelope reached {} generated nodes (max_sample_nodes); the rest was omitted", self.max_nodes),
            );
            return false;
        }
        self.nodes += 1;
        true
    }

    /// A message part: `element=` (document) or `type=` (rpc, or document
    /// with a type — WS-I disallows the latter).
    fn part(&mut self, p: Node<'a, 'i>, rpc: bool, indent: usize, out: &mut String) {
        let pname = p.attribute("name").unwrap_or("part");
        if let Some(e) = p.attribute("element") {
            let q = qname(p, e);
            match SchemaSet::lookup(&self.set.elements, &q) {
                Some(decl) => self.element(decl, indent, 0, out, true),
                None => {
                    self.report.warn(
                        "unresolved_element",
                        &path(p),
                        format!("element '{e}' is not defined in an inline schema; an empty element is used"),
                    );
                    let pfx = self.out.prefix_for(&q.0);
                    out.push_str(&format!("{}<{pfx}:{}/>\n", "  ".repeat(indent), q.1));
                }
            }
            return;
        }
        if let Some(t) = p.attribute("type") {
            if !rpc {
                self.report.warn(
                    "document_part_type",
                    &path(p),
                    "document-style part uses type= instead of element=; the part name is used as the element name",
                );
            }
            let q = qname(p, t);
            let c = self.typed_content(&q, p, pname, 0);
            write_element(out, indent, pname, &c);
        }
    }

    fn element(&mut self, decl: Node<'a, 'i>, indent: usize, depth: usize, out: &mut String, top: bool) {
        if depth > MAX_DEPTH {
            self.report.warn("schema_depth_limit", &path(decl), format!("XSD nesting deeper than {MAX_DEPTH} levels was not expanded"));
            return;
        }
        if !self.charge(decl) {
            return;
        }
        let min: u64 = decl.attribute("minOccurs").and_then(|v| v.parse().ok()).unwrap_or(1);
        let max = decl.attribute("maxOccurs").unwrap_or("1");
        if min == 0 && !self.include_optional && !top {
            return;
        }
        // `ref=` uses the referenced global element's name and content.
        let (target, global) = match decl.attribute("ref") {
            Some(r) => {
                let q = qname(decl, r);
                match SchemaSet::lookup(&self.set.elements, &q) {
                    Some(g) => (g, true),
                    None => {
                        self.report.warn(
                            "unresolved_element",
                            &path(decl),
                            format!("element ref '{r}' is not defined in an inline schema"),
                        );
                        return;
                    }
                }
            }
            None => (decl, decl.parent().is_some_and(|p| is(&p, XSD_NS, "schema"))),
        };
        if target.attribute("abstract") == Some("true") {
            self.report.unsupported("xsd_abstract_element", &path(target), "abstract elements / substitution groups are not resolved");
        }
        let name = target.attribute("name").unwrap_or("element");
        let schema = schema_of(target);
        let tns = schema.and_then(|s| s.attribute("targetNamespace")).unwrap_or("");
        let qualified = global
            || target.attribute("form") == Some("qualified")
            || (target.attribute("form").is_none() && schema.and_then(|s| s.attribute("elementFormDefault")) == Some("qualified"));
        let qn = if qualified && !tns.is_empty() { format!("{}:{name}", self.out.prefix_for(tns)) } else { name.to_string() };
        let reps = min.clamp(1, 3);
        let pad = "  ".repeat(indent);
        if min == 0 {
            out.push_str(&format!("{pad}<!--Optional:-->\n"));
        }
        if max == "unbounded" || max.parse::<u64>().is_ok_and(|m| m > 1) {
            out.push_str(&format!("{pad}<!--{min} or more repetitions (max {max}):-->\n"));
        }
        for _ in 0..reps {
            let content = self.element_content(target, name, depth);
            write_element(out, indent, &qn, &content);
        }
    }

    fn element_content(&mut self, el: Node<'a, 'i>, name: &str, depth: usize) -> Content {
        if let Some(f) = el.attribute("fixed") {
            return Content { text: Some(esc(f, false)), ..Default::default() };
        }
        if self.mode == SampleMode::Sample
            && let Some(d) = el.attribute("default")
        {
            return Content { text: Some(esc(d, false)), ..Default::default() };
        }
        if let Some(t) = el.attribute("type") {
            let q = qname(el, t);
            return self.typed_content(&q, el, name, depth);
        }
        if let Some(ct) = child(el, XSD_NS, "complexType") {
            return self.complex(ct, depth + 1);
        }
        if let Some(st) = child(el, XSD_NS, "simpleType") {
            let v = self.simple_type(st, name, Facets::default(), depth + 1);
            return Content { text: Some(esc(&v, false)), ..Default::default() };
        }
        // No type: xsd:anyType.
        Content::default()
    }

    fn typed_content(&mut self, q: &QName, at: Node<'a, 'i>, name: &str, depth: usize) -> Content {
        if q.0 == XSD_NS {
            let v = self.builtin(&q.1, name, Facets::default(), at);
            return Content { text: Some(esc(&v, false)), ..Default::default() };
        }
        if q.0 == SOAP_ENC {
            self.report.unsupported("soap_encoded_type", &path(at), format!("SOAP-encoding type soapenc:{} is not supported", q.1));
            return Content::default();
        }
        let Some(t) = SchemaSet::lookup(&self.set.types, q) else {
            self.report.warn("unresolved_type", &path(at), format!("type '{}' is not defined in an inline schema; left empty", q.1));
            return Content::default();
        };
        if self.type_stack.contains(q) {
            self.report.warn("recursive_schema", &path(t), format!("recursive type '{}': expansion stops at the first repetition", q.1));
            return Content::default();
        }
        self.type_stack.push(q.clone());
        let c = if t.tag_name().name() == "complexType" {
            self.complex(t, depth + 1)
        } else {
            let v = self.simple_type(t, name, Facets::default(), depth + 1);
            Content { text: Some(esc(&v, false)), ..Default::default() }
        };
        self.type_stack.pop();
        c
    }

    fn complex(&mut self, ct: Node<'a, 'i>, depth: usize) -> Content {
        let mut c = Content::default();
        if ct.attribute("mixed") == Some("true") {
            self.report.warn("xsd_mixed", &path(ct), "mixed content: only the element structure is generated");
        }
        self.complex_into(ct, depth, &mut c);
        c
    }

    fn complex_into(&mut self, ct: Node<'a, 'i>, depth: usize, c: &mut Content) {
        if depth > MAX_DEPTH {
            return;
        }
        for k in ct.children().filter(|k| k.is_element() && k.tag_name().namespace() == Some(XSD_NS)) {
            match k.tag_name().name() {
                "sequence" | "all" | "choice" | "group" => self.particle(k, depth + 1, c),
                "attribute" => self.attribute(k, c),
                "attributeGroup" => self.attribute_group(k, c, depth),
                "anyAttribute" | "annotation" => {}
                "complexContent" => {
                    for d in k.children().filter(|d| d.is_element() && d.tag_name().namespace() == Some(XSD_NS)) {
                        match d.tag_name().name() {
                            "extension" => {
                                if let Some(base) = d.attribute("base") {
                                    self.base_content(&qname(d, base), d, depth, c);
                                }
                                self.complex_into(d, depth + 1, c);
                            }
                            "restriction" => {
                                let base = d.attribute("base").map(|b| qname(d, b));
                                if base.as_ref().is_some_and(|b| b.0 == SOAP_ENC) {
                                    self.report.unsupported(
                                        "soap_encoded_array",
                                        &path(d),
                                        "SOAP-encoded arrays (soapenc:Array) are not supported",
                                    );
                                    continue;
                                }
                                self.complex_into(d, depth + 1, c);
                            }
                            "annotation" => {}
                            other => self.report.unsupported(
                                "xsd_construct",
                                &path(d),
                                format!("xsd:{other} in complexContent is not supported"),
                            ),
                        }
                    }
                }
                "simpleContent" => {
                    for d in k.children().filter(|d| d.is_element() && d.tag_name().namespace() == Some(XSD_NS)) {
                        match d.tag_name().name() {
                            "extension" | "restriction" => {
                                let facets = facets(d);
                                if let Some(base) = d.attribute("base") {
                                    let q = qname(d, base);
                                    let v = self.simple_by_name(&q, d, "value", facets, depth);
                                    c.text = Some(esc(&v, false));
                                }
                                for a in d.children().filter(|a| a.is_element() && a.tag_name().namespace() == Some(XSD_NS)) {
                                    match a.tag_name().name() {
                                        "attribute" => self.attribute(a, c),
                                        "attributeGroup" => self.attribute_group(a, c, depth),
                                        _ => {}
                                    }
                                }
                            }
                            "annotation" => {}
                            other => {
                                self.report.unsupported("xsd_construct", &path(d), format!("xsd:{other} in simpleContent is not supported"))
                            }
                        }
                    }
                }
                other => self.report.unsupported("xsd_construct", &path(k), format!("xsd:{other} in a complexType is not supported")),
            }
        }
    }

    /// Content of an extension's base type (attributes + particles).
    fn base_content(&mut self, q: &QName, at: Node<'a, 'i>, depth: usize, c: &mut Content) {
        if q.0 == XSD_NS {
            if q.1 != "anyType" {
                let v = self.builtin(&q.1, "value", Facets::default(), at);
                c.text = Some(esc(&v, false));
            }
            return;
        }
        let Some(t) = SchemaSet::lookup(&self.set.types, q) else {
            self.report.warn("unresolved_type", &path(at), format!("base type '{}' is not defined in an inline schema", q.1));
            return;
        };
        if self.type_stack.contains(q) {
            self.report.warn("recursive_schema", &path(t), format!("recursive type '{}': expansion stops at the first repetition", q.1));
            return;
        }
        self.type_stack.push(q.clone());
        if t.tag_name().name() == "complexType" {
            self.complex_into(t, depth + 1, c);
        } else {
            let v = self.simple_type(t, "value", Facets::default(), depth + 1);
            c.text = Some(esc(&v, false));
        }
        self.type_stack.pop();
    }

    fn particle(&mut self, p: Node<'a, 'i>, depth: usize, c: &mut Content) {
        if depth > MAX_DEPTH {
            self.report.warn("schema_depth_limit", &path(p), format!("XSD nesting deeper than {MAX_DEPTH} levels was not expanded"));
            return;
        }
        if p.attribute("minOccurs") == Some("0") && !self.include_optional {
            return;
        }
        match p.tag_name().name() {
            "group" => {
                let Some(r) = p.attribute("ref") else { return self.particle_children(p, depth, c) };
                let q = qname(p, r);
                match SchemaSet::lookup(&self.set.groups, &q) {
                    Some(g) => {
                        for k in g.children().filter(|k| k.is_element() && k.tag_name().namespace() == Some(XSD_NS)) {
                            if matches!(k.tag_name().name(), "sequence" | "all" | "choice") {
                                self.particle(k, depth + 1, c);
                            }
                        }
                    }
                    None => self.report.warn("unresolved_group", &path(p), format!("group '{r}' is not defined in an inline schema")),
                }
            }
            "choice" => {
                let branches: Vec<Node> = p
                    .children()
                    .filter(|k| k.is_element() && k.tag_name().namespace() == Some(XSD_NS) && k.tag_name().name() != "annotation")
                    .collect();
                if branches.len() > 1 {
                    self.report.warn(
                        "xsd_choice_first",
                        &path(p),
                        format!("xsd:choice has {} branches; the first one is generated", branches.len()),
                    );
                }
                if let Some(first) = branches.first() {
                    self.particle_item(*first, depth + 1, c);
                }
            }
            _ => self.particle_children(p, depth, c),
        }
    }

    fn particle_children(&mut self, p: Node<'a, 'i>, depth: usize, c: &mut Content) {
        for k in p.children().filter(|k| k.is_element() && k.tag_name().namespace() == Some(XSD_NS)) {
            self.particle_item(k, depth + 1, c);
        }
    }

    fn particle_item(&mut self, k: Node<'a, 'i>, depth: usize, c: &mut Content) {
        let indent = 0;
        match k.tag_name().name() {
            "element" => {
                let mut s = String::new();
                self.element(k, indent, depth, &mut s, false);
                c.children.push_str(&s);
            }
            "sequence" | "all" | "choice" | "group" => self.particle(k, depth, c),
            "any" => {
                self.report.unsupported("xsd_any", &path(k), "xsd:any wildcard content is not generated; add the element(s) yourself");
                c.children.push_str("<!--xsd:any content-->\n");
            }
            "annotation" => {}
            other => self.report.unsupported("xsd_construct", &path(k), format!("xsd:{other} in a content model is not supported")),
        }
    }

    fn attribute(&mut self, a: Node<'a, 'i>, c: &mut Content) {
        let decl = match a.attribute("ref") {
            Some(r) => match SchemaSet::lookup(&self.set.attributes, &qname(a, r)) {
                Some(g) => g,
                None => {
                    self.report.warn("unresolved_attribute", &path(a), format!("attribute ref '{r}' is not defined in an inline schema"));
                    return;
                }
            },
            None => a,
        };
        let usage = a.attribute("use").unwrap_or("optional");
        if usage == "prohibited" || (usage != "required" && !self.include_optional) {
            return;
        }
        let name = decl.attribute("name").unwrap_or("attr");
        let value = if let Some(f) = decl.attribute("fixed").or(a.attribute("fixed")) {
            f.to_string()
        } else if self.mode == SampleMode::Sample
            && let Some(d) = decl.attribute("default").or(a.attribute("default"))
        {
            d.to_string()
        } else if let Some(t) = decl.attribute("type") {
            self.simple_by_name(&qname(decl, t), decl, name, Facets::default(), 0)
        } else if let Some(st) = child(decl, XSD_NS, "simpleType") {
            self.simple_type(st, name, Facets::default(), 0)
        } else {
            String::new()
        };
        let schema = schema_of(decl);
        let qualified = a.attribute("ref").is_some()
            || decl.attribute("form") == Some("qualified")
            || (decl.attribute("form").is_none() && schema.and_then(|s| s.attribute("attributeFormDefault")) == Some("qualified"));
        let tns = schema.and_then(|s| s.attribute("targetNamespace")).unwrap_or("");
        let an = if qualified && !tns.is_empty() { format!("{}:{name}", self.out.prefix_for(tns)) } else { name.to_string() };
        c.attrs.push_str(&format!(" {an}=\"{}\"", esc(&value, true)));
    }

    fn attribute_group(&mut self, g: Node<'a, 'i>, c: &mut Content, depth: usize) {
        if depth > MAX_DEPTH {
            return;
        }
        let Some(r) = g.attribute("ref") else { return };
        match SchemaSet::lookup(&self.set.attr_groups, &qname(g, r)) {
            Some(def) => {
                for a in def.children().filter(|a| a.is_element() && a.tag_name().namespace() == Some(XSD_NS)) {
                    match a.tag_name().name() {
                        "attribute" => self.attribute(a, c),
                        "attributeGroup" => self.attribute_group(a, c, depth + 1),
                        _ => {}
                    }
                }
            }
            None => {
                self.report.warn("unresolved_attribute_group", &path(g), format!("attributeGroup '{r}' is not defined in an inline schema"))
            }
        }
    }

    fn simple_by_name(&mut self, q: &QName, at: Node<'a, 'i>, name: &str, f: Facets, depth: usize) -> String {
        if q.0 == XSD_NS {
            return self.builtin(&q.1, name, f, at);
        }
        match SchemaSet::lookup(&self.set.types, q) {
            Some(t) if t.tag_name().name() == "simpleType" && depth < MAX_DEPTH => self.simple_type(t, name, f, depth + 1),
            Some(_) => String::new(),
            None => {
                self.report.warn("unresolved_type", &path(at), format!("simple type '{}' is not defined in an inline schema", q.1));
                String::new()
            }
        }
    }

    fn simple_type(&mut self, st: Node<'a, 'i>, name: &str, outer: Facets, depth: usize) -> String {
        if depth > MAX_DEPTH {
            return String::new();
        }
        for k in st.children().filter(|k| k.is_element() && k.tag_name().namespace() == Some(XSD_NS)) {
            match k.tag_name().name() {
                "restriction" => {
                    let enums: Vec<&str> =
                        k.children().filter(|e| is(e, XSD_NS, "enumeration")).filter_map(|e| e.attribute("value")).collect();
                    if let Some(first) = enums.first() {
                        return if self.mode == SampleMode::Sample { first.to_string() } else { String::new() };
                    }
                    if let Some(p) = k.children().find(|e| is(e, XSD_NS, "pattern")) {
                        self.report.warn(
                            "pattern_not_enforced",
                            &path(p),
                            format!("the sample is not guaranteed to match pattern `{}`", p.attribute("value").unwrap_or("")),
                        );
                    }
                    let mut f = facets(k);
                    f.min = f.min.or(outer.min);
                    f.max = f.max.or(outer.max);
                    f.min_len = f.min_len.or(outer.min_len);
                    f.max_len = f.max_len.or(outer.max_len);
                    if let Some(base) = k.attribute("base") {
                        return self.simple_by_name(&qname(k, base), k, name, f, depth);
                    }
                    if let Some(inner) = child(k, XSD_NS, "simpleType") {
                        return self.simple_type(inner, name, f, depth + 1);
                    }
                    return String::new();
                }
                "list" => {
                    if let Some(t) = k.attribute("itemType") {
                        return self.simple_by_name(&qname(k, t), k, name, Facets::default(), depth);
                    }
                    if let Some(inner) = child(k, XSD_NS, "simpleType") {
                        return self.simple_type(inner, name, Facets::default(), depth + 1);
                    }
                    return String::new();
                }
                "union" => {
                    self.report.warn("xsd_union_first", &path(k), "xsd:union: the first member type is generated");
                    if let Some(first) = k.attribute("memberTypes").and_then(|m| m.split_whitespace().next()) {
                        return self.simple_by_name(&qname(k, first), k, name, Facets::default(), depth);
                    }
                    if let Some(inner) = child(k, XSD_NS, "simpleType") {
                        return self.simple_type(inner, name, Facets::default(), depth + 1);
                    }
                    return String::new();
                }
                _ => {}
            }
        }
        String::new()
    }

    fn builtin(&mut self, t: &str, name: &str, f: Facets, at: Node) -> String {
        if self.mode == SampleMode::Blank {
            return String::new();
        }
        if is_credential_name(name) {
            self.report.warn(
                "credential_left_blank",
                &path(at),
                format!("credential-like value '{name}' is never generated; left empty for you to supply"),
            );
            return String::new();
        }
        let r = &mut self.rng;
        let int_range = |lo: i128, hi: i128, f: Facets, r: &mut SplitMix64| -> String {
            let lo = f.min.map(|m| m.ceil() as i128).unwrap_or(lo).max(lo);
            let hi = f.max.map(|m| m.floor() as i128).unwrap_or(hi).min(hi);
            if lo > hi { lo.to_string() } else { r.range_i128(lo, hi).to_string() }
        };
        match t {
            "boolean" => (if r.bool() { "true" } else { "false" }).into(),
            "int" | "integer" | "long" | "short" => int_range(1, 1000, f, r),
            "byte" => int_range(1, 100, f, r),
            "nonNegativeInteger" | "unsignedInt" | "unsignedLong" | "unsignedShort" => int_range(0, 1000, f, r),
            "unsignedByte" => int_range(0, 255, f, r),
            "positiveInteger" => int_range(1, 1000, f, r),
            "negativeInteger" => int_range(-1000, -1, f, r),
            "nonPositiveInteger" => int_range(-1000, 0, f, r),
            "decimal" | "float" | "double" => {
                let lo = f.min.unwrap_or(1.0);
                let hi = f.max.unwrap_or(lo + 1000.0);
                let v = if lo > hi { lo } else { ((lo + r.unit_f64() * (hi - lo)) * 100.0).round() / 100.0 };
                format!("{v}")
            }
            "dateTime" => {
                let secs = r.range_i128(1_577_836_800, 1_893_455_999) as i64;
                chrono::DateTime::from_timestamp(secs, 0).map(|d| d.format("%Y-%m-%dT%H:%M:%SZ").to_string()).unwrap_or_default()
            }
            "date" => {
                let secs = r.range_i128(1_577_836_800, 1_893_455_999) as i64;
                chrono::DateTime::from_timestamp(secs, 0).map(|d| d.format("%Y-%m-%d").to_string()).unwrap_or_default()
            }
            "time" => format!("{:02}:{:02}:00", r.range_i128(0, 23), r.range_i128(0, 59)),
            "duration" => format!("P{}D", r.range_i128(1, 30)),
            "gYear" => r.range_i128(2020, 2030).to_string(),
            "gYearMonth" => format!("{}-{:02}", r.range_i128(2020, 2030), r.range_i128(1, 12)),
            "gMonth" => format!("--{:02}", r.range_i128(1, 12)),
            "gDay" => format!("---{:02}", r.range_i128(1, 28)),
            "gMonthDay" => format!("--{:02}-{:02}", r.range_i128(1, 12), r.range_i128(1, 28)),
            "base64Binary" => base64::engine::general_purpose::STANDARD.encode(r.next_u64().to_be_bytes()),
            "hexBinary" => r.hex(16).to_uppercase(),
            "anyURI" => format!("https://example.com/resource/{}", r.range_i128(1, 9999)),
            "language" => "en".into(),
            "QName" => "value".into(),
            "anyType" | "anySimpleType" => String::new(),
            "string" | "normalizedString" | "token" | "Name" | "NCName" | "NMTOKEN" | "NMTOKENS" | "ID" | "IDREF" | "IDREFS" | "ENTITY" => {
                let stem: String = name.chars().filter(|c| c.is_ascii_alphanumeric()).take(24).collect();
                let stem = if stem.is_empty() { "value".to_string() } else { stem };
                let mut s = format!("{stem}-{}", r.hex(4));
                if let Some(m) = f.min_len
                    && s.len() < m
                {
                    s.push_str(&"x".repeat(m.min(4096) - s.len().min(m.min(4096))));
                }
                if let Some(m) = f.max_len
                    && s.len() > m
                {
                    s.truncate(m);
                }
                s
            }
            other => {
                self.report.warn("unknown_xsd_type", &path(at), format!("built-in type xsd:{other} has no sample generator; left empty"));
                String::new()
            }
        }
    }
}

fn facets(restriction: Node) -> Facets {
    let num = |local: &str| {
        restriction.children().find(|e| is(e, XSD_NS, local)).and_then(|e| e.attribute("value")).and_then(|v| v.parse::<f64>().ok())
    };
    let len = |local: &str| {
        restriction.children().find(|e| is(e, XSD_NS, local)).and_then(|e| e.attribute("value")).and_then(|v| v.parse::<usize>().ok())
    };
    Facets {
        min: num("minInclusive").or_else(|| num("minExclusive").map(|v| v + 1.0)),
        max: num("maxInclusive").or_else(|| num("maxExclusive").map(|v| v - 1.0)),
        min_len: len("minLength").or_else(|| len("length")),
        max_len: len("maxLength").or_else(|| len("length")),
    }
}

/// Write `<qn attrs>text|children</qn>` with indentation of child lines.
fn write_element(out: &mut String, indent: usize, qn: &str, c: &Content) {
    let pad = "  ".repeat(indent);
    match (&c.text, c.children.is_empty()) {
        (None, true) => out.push_str(&format!("{pad}<{qn}{}></{qn}>\n", c.attrs)),
        (Some(t), true) => out.push_str(&format!("{pad}<{qn}{}>{t}</{qn}>\n", c.attrs)),
        (t, false) => {
            out.push_str(&format!("{pad}<{qn}{}>{}\n", c.attrs, t.clone().unwrap_or_default()));
            for line in c.children.lines() {
                out.push_str(&format!("{pad}  {line}\n"));
            }
            out.push_str(&format!("{pad}</{qn}>\n"));
        }
    }
}
