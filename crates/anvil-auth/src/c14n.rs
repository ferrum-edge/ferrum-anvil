//! Exclusive XML Canonicalization 1.0 (`http://www.w3.org/2001/10/xml-exc-c14n#`,
//! with or without comments) of an element subtree, or of a whole document,
//! parsed by roxmltree.
//!
//! This is what the WS-Security signer digests and signs, so the output must
//! be byte-identical to every other conforming implementation. It is checked
//! against the W3C Canonical XML and Exclusive XML Canonicalization examples
//! (`tests/c14n_vectors.rs`) and, on CI, against libxml2 (`xmllint
//! --exc-c14n` and lxml's exclusive C14N, with InclusiveNamespaces prefix
//! lists) on a corpus of SOAP envelopes, and the signatures built on it are
//! verified by xmlsec1 and by Ferrum Edge's own canonicalizer
//! (`tests/xmldsig_interop.rs`, the `xmldsig-interop` workflow and Lab
//! scenario AUTH-030).
//!
//! The subset canonicalized is always a complete subtree (or the document),
//! which is the only node-set a WS-Security `#id` Reference with the
//! exclusive-c14n transform selects. Rules applied (Canonical XML 1.0 §2,
//! Exclusive XML Canonicalization 1.0 §3):
//!
//! - The input is already parsed: character and predefined entity references
//!   are expanded, CDATA sections are text, line ends are normalized to `\n`
//!   and attribute values are normalized (roxmltree does all of this as the
//!   XML specification requires). A DTD is never applied: callers parse with
//!   DTDs refused, and attribute defaults never exist.
//! - Empty elements are written as start/end tag pairs; element and attribute
//!   names keep the prefixes written in the source.
//! - A namespace declaration is written on an element only when the element
//!   visibly utilizes its prefix (the element's own prefix, or a prefixed
//!   attribute's), or the prefix is in the InclusiveNamespaces PrefixList,
//!   and the nearest output ancestor did not already render the same binding.
//!   `xmlns=""` is written when an unprefixed element in no namespace sits
//!   below an output ancestor that rendered a non-empty default namespace.
//!   The `xml` prefix is never declared, and `xml:*` attributes are not
//!   inherited from ancestors outside the subset (exclusive canonicalization).
//! - Namespace declarations are sorted by prefix (the default first), then
//!   attributes by namespace URI (none first) and local name.
//! - Text escapes `&`, `<`, `>` and CR; attribute values escape `&`, `<`, `"`,
//!   TAB, LF and CR.
//! - Comments are written only in the with-comments variant; processing
//!   instructions always. At document level, nodes before the document
//!   element are followed by a line feed and nodes after it are preceded by
//!   one; the XML declaration and the DTD are never written.
//!
//! Traversal is iterative, so element depth never grows the call stack.

use roxmltree::{Node, NodeType};

/// The XML namespace, bound to `xml` by definition and never declared.
const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";
/// The exclusive canonicalization algorithm without comments.
pub const EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
/// The exclusive canonicalization algorithm with comments.
pub const EXC_C14N_WITH_COMMENTS: &str = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";
/// Most prefixes an InclusiveNamespaces PrefixList may name.
pub const MAX_INCLUSIVE_PREFIXES: usize = 64;

/// How to canonicalize.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Options {
    /// Keep comments (`xml-exc-c14n#WithComments`).
    pub with_comments: bool,
    /// The InclusiveNamespaces PrefixList: prefixes treated as by inclusive
    /// Canonical XML (declared wherever they are in scope and not already
    /// rendered). The default namespace is `""` (written `#default`).
    pub inclusive_prefixes: Vec<String>,
}

impl Options {
    /// Options for a parsed InclusiveNamespaces `PrefixList` attribute value.
    pub fn with_prefix_list(prefix_list: &str, with_comments: bool) -> Result<Self, String> {
        Ok(Options { with_comments, inclusive_prefixes: parse_prefix_list(prefix_list)? })
    }
}

/// Parse an InclusiveNamespaces `PrefixList` (whitespace-separated NCNames,
/// `#default` for the default namespace) into prefixes (`""` for the
/// default), without duplicates.
pub fn parse_prefix_list(list: &str) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    for token in list.split_whitespace() {
        let prefix = if token == "#default" {
            ""
        } else if is_ncname(token) && token != "xmlns" {
            token
        } else {
            return Err(format!("'{token}' is not a namespace prefix (an NCName or #default)"));
        };
        if !out.iter().any(|p| p == prefix) {
            out.push(prefix.to_string());
        }
        if out.len() > MAX_INCLUSIVE_PREFIXES {
            return Err(format!("an InclusiveNamespaces PrefixList may name at most {MAX_INCLUSIVE_PREFIXES} prefixes"));
        }
    }
    Ok(out)
}

/// The PrefixList attribute value for `prefixes` (`""` written `#default`).
pub fn format_prefix_list(prefixes: &[String]) -> String {
    prefixes.iter().map(|p| if p.is_empty() { "#default" } else { p.as_str() }).collect::<Vec<_>>().join(" ")
}

/// An XML Namespaces NCName: a Name without colons.
fn is_ncname(s: &str) -> bool {
    let mut chars = s.chars();
    let Some(first) = chars.next() else { return false };
    let start = |c: char| {
        c == '_'
            || c.is_ascii_alphabetic()
            || matches!(c, '\u{C0}'..='\u{D6}' | '\u{D8}'..='\u{F6}' | '\u{F8}'..='\u{2FF}' | '\u{370}'..='\u{37D}' | '\u{37F}'..='\u{1FFF}' | '\u{200C}'..='\u{200D}' | '\u{2070}'..='\u{218F}' | '\u{2C00}'..='\u{2FEF}' | '\u{3001}'..='\u{D7FF}' | '\u{F900}'..='\u{FDCF}' | '\u{FDF0}'..='\u{FFFD}' | '\u{10000}'..='\u{EFFFF}')
    };
    start(first)
        && chars.all(|c| {
            start(c)
                || c == '-'
                || c == '.'
                || c.is_ascii_digit()
                || matches!(c, '\u{B7}' | '\u{300}'..='\u{36F}' | '\u{203F}'..='\u{2040}')
        })
}

/// What to canonicalize in a document given as text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// The element whose start tag begins at this byte offset.
    ElementAt(usize),
    /// The whole document.
    Document,
}

/// The canonicalizer behind the WS-Security signer, as one small interface
/// over document text, so another implementation (a binding to an audited
/// library such as libxml2) can replace [`Native`] without touching the
/// signer. Callers bound and validate the document first (XML limits, no
/// DTD) and check that every signed id names exactly one element; an
/// implementation canonicalizes, nothing more.
pub trait Canonicalizer: Send + Sync {
    /// The canonical form of each target of `xml`, in order.
    fn canonicalize(&self, xml: &str, targets: &[Target], opts: &Options) -> Result<Vec<String>, C14nError>;
}

/// Anvil's own implementation ([`canonicalize`] over roxmltree).
#[derive(Debug, Clone, Copy, Default)]
pub struct Native;

impl Canonicalizer for Native {
    fn canonicalize(&self, xml: &str, targets: &[Target], opts: &Options) -> Result<Vec<String>, C14nError> {
        let parse = roxmltree::ParsingOptions { allow_dtd: false, ..Default::default() };
        let doc = roxmltree::Document::parse_with_options(xml, parse)
            .map_err(|e| C14nError(format!("the document is not well-formed XML: {e}")))?;
        targets
            .iter()
            .map(|t| match *t {
                Target::Document => canonicalize(doc.root(), opts),
                Target::ElementAt(at) => {
                    let node = doc
                        .descendants()
                        .find(|n| n.is_element() && n.range().start == at)
                        .ok_or_else(|| C14nError(format!("no element starts at byte {at}")))?;
                    canonicalize(node, opts)
                }
            })
            .collect()
    }
}

/// Why a subtree could not be canonicalized.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("exclusive canonicalization: {0}")]
pub struct C14nError(String);

/// Canonicalize the subtree rooted at `node` (an element), or the whole
/// document when `node` is the document root.
pub fn canonicalize(node: Node<'_, '_>, opts: &Options) -> Result<String, C14nError> {
    let mut w = Writer { input: node.document().input_text(), opts, out: String::new(), rendered: Vec::new(), frames: Vec::new() };
    match node.node_type() {
        NodeType::Element => w.subtree(node)?,
        NodeType::Root => {
            let mut after_root = false;
            for child in node.children() {
                match child.node_type() {
                    NodeType::Element => {
                        w.subtree(child)?;
                        after_root = true;
                    }
                    NodeType::Comment if !opts.with_comments => {}
                    NodeType::Comment | NodeType::PI => {
                        if after_root {
                            w.out.push('\n');
                        }
                        w.leaf(child);
                        if !after_root {
                            w.out.push('\n');
                        }
                    }
                    // Whitespace outside the document element is not content.
                    NodeType::Text | NodeType::Root => {}
                }
            }
        }
        _ => return Err(C14nError("only an element or a whole document can be canonicalized".into())),
    }
    Ok(w.out)
}

struct Writer<'a, 'o> {
    input: &'a str,
    opts: &'o Options,
    out: String,
    /// Namespace bindings rendered by output ancestors, innermost last.
    rendered: Vec<(String, String)>,
    /// `rendered.len()` before each open element.
    frames: Vec<usize>,
}

impl Writer<'_, '_> {
    /// Write the subtree rooted at `root` (an element) without recursion.
    fn subtree(&mut self, root: Node<'_, '_>) -> Result<(), C14nError> {
        let mut node = root;
        self.enter(node)?;
        'walk: loop {
            if node.is_element()
                && let Some(child) = node.first_child()
            {
                node = child;
                self.enter(node)?;
                continue;
            }
            loop {
                self.leave(node);
                if node == root {
                    break 'walk;
                }
                if let Some(next) = node.next_sibling() {
                    node = next;
                    self.enter(node)?;
                    continue 'walk;
                }
                node = node.parent().ok_or_else(|| C14nError("a node left its subtree".into()))?;
            }
        }
        Ok(())
    }

    fn enter(&mut self, node: Node<'_, '_>) -> Result<(), C14nError> {
        if node.is_element() {
            return self.start_tag(node);
        }
        self.leaf(node);
        Ok(())
    }

    fn leave(&mut self, node: Node<'_, '_>) {
        if node.is_element() {
            self.out.push_str("</");
            self.out.push_str(element_qname(self.input, node));
            self.out.push('>');
            if let Some(len) = self.frames.pop() {
                self.rendered.truncate(len);
            }
        }
    }

    /// Text, a comment or a processing instruction.
    fn leaf(&mut self, node: Node<'_, '_>) {
        match node.node_type() {
            NodeType::Text => escape_text(node.text().unwrap_or_default(), &mut self.out),
            NodeType::Comment if self.opts.with_comments => {
                self.out.push_str("<!--");
                self.out.push_str(node.text().unwrap_or_default());
                self.out.push_str("-->");
            }
            NodeType::PI => {
                if let Some(pi) = node.pi() {
                    self.out.push_str("<?");
                    self.out.push_str(pi.target);
                    if let Some(value) = pi.value.filter(|v| !v.is_empty()) {
                        self.out.push(' ');
                        self.out.push_str(value);
                    }
                    self.out.push_str("?>");
                }
            }
            _ => {}
        }
    }

    /// The binding of `prefix` rendered by the nearest output ancestor.
    fn in_effect(&self, prefix: &str) -> Option<&str> {
        self.rendered.iter().rev().find(|(p, _)| p == prefix).map(|(_, u)| u.as_str())
    }

    fn start_tag(&mut self, e: Node<'_, '_>) -> Result<(), C14nError> {
        let qname = element_qname(self.input, e);
        let element_prefix = qname.split_once(':').map_or("", |(p, _)| p);
        // Prefixes the element visibly utilizes, then the inclusive ones.
        let mut prefixes: Vec<&str> = vec![element_prefix];
        let mut attrs: Vec<(&str, &str, &str, &str)> = Vec::new(); // (ns uri, local, qname, value)
        for a in e.attributes() {
            let aq = self.input.get(a.range_qname()).unwrap_or_default();
            if aq.is_empty() {
                return Err(C14nError("an attribute name could not be read from the source".into()));
            }
            if let Some((p, _)) = aq.split_once(':') {
                prefixes.push(p);
            }
            attrs.push((a.namespace().unwrap_or(""), a.name(), aq, a.value()));
        }
        prefixes.extend(self.opts.inclusive_prefixes.iter().map(String::as_str));
        let mut decls: Vec<(String, String)> = Vec::new();
        for prefix in prefixes {
            if prefix == "xml" || decls.iter().any(|(p, _)| p == prefix) {
                continue;
            }
            if prefix.is_empty() {
                let uri = e.default_namespace().unwrap_or("");
                let effective = self.in_effect("").unwrap_or("");
                if uri != effective {
                    decls.push((String::new(), uri.to_string()));
                }
            } else {
                // An inclusive prefix may be out of scope; a used one never is.
                let Some(uri) = e.lookup_namespace_uri(Some(prefix)) else { continue };
                if uri.is_empty() || uri == XML_NS {
                    return Err(C14nError(format!("the prefix '{prefix}' has no usable namespace binding")));
                }
                if self.in_effect(prefix) != Some(uri) {
                    decls.push((prefix.to_string(), uri.to_string()));
                }
            }
        }
        // Prefixes are unique among the declarations, and expanded names
        // among an element's attributes, so whole-tuple order is the order
        // by prefix, and by (namespace URI, local name).
        decls.sort();
        attrs.sort();

        self.frames.push(self.rendered.len());
        self.out.push('<');
        self.out.push_str(qname);
        for (prefix, uri) in decls {
            self.out.push_str(if prefix.is_empty() { " xmlns" } else { " xmlns:" });
            self.out.push_str(&prefix);
            self.out.push_str("=\"");
            escape_attr(&uri, &mut self.out);
            self.out.push('"');
            self.rendered.push((prefix, uri));
        }
        for (_, _, aq, value) in attrs {
            self.out.push(' ');
            self.out.push_str(aq);
            self.out.push_str("=\"");
            escape_attr(value, &mut self.out);
            self.out.push('"');
        }
        self.out.push('>');
        Ok(())
    }
}

/// The element's qualified name as written in the source start tag.
fn element_qname<'i>(input: &'i str, e: Node<'_, '_>) -> &'i str {
    let tag = input.get(e.range().start + 1..).unwrap_or_default();
    let end = tag.find(|c: char| c.is_ascii_whitespace() || c == '/' || c == '>').unwrap_or(tag.len());
    &tag[..end]
}

fn escape_text(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#xD;"),
            c => out.push(c),
        }
    }
}

fn escape_attr(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '"' => out.push_str("&quot;"),
            '\t' => out.push_str("&#x9;"),
            '\n' => out.push_str("&#xA;"),
            '\r' => out.push_str("&#xD;"),
            c => out.push(c),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c14n_root(xml: &str, opts: &Options) -> String {
        let doc = roxmltree::Document::parse(xml).unwrap();
        canonicalize(doc.root_element(), opts).unwrap()
    }

    #[test]
    fn prefix_lists_parse_and_format() {
        assert_eq!(parse_prefix_list("  wsse  #default soap wsse ").unwrap(), vec!["wsse", "", "soap"]);
        assert_eq!(format_prefix_list(&parse_prefix_list("#default a").unwrap()), "#default a");
        for bad in ["a:b", "xmlns", "#foo", "1a", "-x"] {
            assert!(parse_prefix_list(bad).is_err(), "{bad}");
        }
        let many: String = (0..=MAX_INCLUSIVE_PREFIXES).map(|i| format!("p{i} ")).collect();
        assert!(parse_prefix_list(&many).is_err());
    }

    #[test]
    fn redundant_declarations_are_dropped_and_needed_ones_moved_down() {
        let xml = r#"<a:r xmlns:a="urn:a" xmlns:b="urn:b" xmlns:unused="urn:u"><b:c a:x="1"><a:d xmlns:a="urn:a"/></b:c></a:r>"#;
        assert_eq!(c14n_root(xml, &Options::default()), r#"<a:r xmlns:a="urn:a"><b:c xmlns:b="urn:b" a:x="1"><a:d></a:d></b:c></a:r>"#);
    }

    #[test]
    fn default_namespace_undeclaration_is_written_only_when_needed() {
        let xml = r#"<r xmlns="urn:d"><e xmlns=""><f/></e><g xmlns="urn:d"/></r>"#;
        assert_eq!(c14n_root(xml, &Options::default()), r#"<r xmlns="urn:d"><e xmlns=""><f></f></e><g></g></r>"#);
        // At the apex nothing was rendered: no xmlns="" is needed.
        let doc = roxmltree::Document::parse(xml).unwrap();
        let e = doc.descendants().find(|n| n.has_tag_name("e")).unwrap();
        assert_eq!(canonicalize(e, &Options::default()).unwrap(), "<e><f></f></e>");
    }

    #[test]
    fn attributes_sort_by_namespace_uri_then_local_name() {
        let xml = r#"<e xmlns:z="urn:a" xmlns:a="urn:z" a:k="1" z:k="2" b="3" a="4" xml:lang="en"/>"#;
        assert_eq!(
            c14n_root(xml, &Options::default()),
            r#"<e xmlns:a="urn:z" xmlns:z="urn:a" a="4" b="3" xml:lang="en" z:k="2" a:k="1"></e>"#
        );
    }

    #[test]
    fn exclusive_canonicalization_does_not_inherit_xml_attributes() {
        let xml = r#"<r xml:lang="fr" xml:space="preserve"><e a="1"/></r>"#;
        let doc = roxmltree::Document::parse(xml).unwrap();
        let e = doc.descendants().find(|n| n.has_tag_name("e")).unwrap();
        assert_eq!(canonicalize(e, &Options::default()).unwrap(), r#"<e a="1"></e>"#);
    }

    #[test]
    fn deep_nesting_does_not_recurse() {
        let depth = 20_000;
        let xml = format!("{}{}", "<e>".repeat(depth), "</e>".repeat(depth));
        let doc = roxmltree::Document::parse_with_options(&xml, roxmltree::ParsingOptions { nodes_limit: u32::MAX, ..Default::default() })
            .unwrap();
        let out = canonicalize(doc.root_element(), &Options::default()).unwrap();
        assert_eq!(out.len(), depth * 7);
    }

    #[test]
    fn the_native_canonicalizer_canonicalizes_targets_by_offset() {
        let xml = r#"<a:r xmlns:a="urn:a"><a:e x="1"/><f/></a:r>"#;
        let at = xml.find("<a:e").unwrap();
        let out = Native.canonicalize(xml, &[Target::ElementAt(at), Target::Document], &Options::default()).unwrap();
        assert_eq!(out, [r#"<a:e xmlns:a="urn:a" x="1"></a:e>"#, r#"<a:r xmlns:a="urn:a"><a:e x="1"></a:e><f></f></a:r>"#]);
        assert!(Native.canonicalize(xml, &[Target::ElementAt(1)], &Options::default()).is_err());
        assert!(Native.canonicalize("<!DOCTYPE r []><r/>", &[Target::Document], &Options::default()).is_err());
    }

    #[test]
    fn text_and_attribute_escaping() {
        let xml = "<e a='&lt;&amp;&quot;&gt;&#9;&#10;&#13;'>&lt;&amp;&gt;&#13;\"'<![CDATA[<&>]]></e>";
        assert_eq!(c14n_root(xml, &Options::default()), "<e a=\"&lt;&amp;&quot;>&#x9;&#xA;&#xD;\">&lt;&amp;&gt;&#xD;\"'&lt;&amp;&gt;</e>");
    }
}
