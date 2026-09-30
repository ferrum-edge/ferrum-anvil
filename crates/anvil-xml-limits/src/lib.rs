//! A linear pre-parse scan of XML text for the work `roxmltree` does before
//! any of its own limits apply: it compares every attribute with each earlier
//! one on the same element (their names and full namespace URIs), and copies
//! the namespaces in scope for every element that declares one. Its node
//! limit counts neither attributes nor namespace declarations.
//!
//! The scan counts the attributes of each start tag, the attribute pairs of
//! the whole document and its `xmlns` declarations, and bounds the length of
//! attribute names, namespace prefixes and namespace URIs. It follows the
//! open elements to bound the namespaces in scope of each element and the
//! work of resolving them (see [`XmlLimits::namespace_scope_work`]). It skips
//! comments, CDATA sections, processing instructions and quoted attribute
//! values. It depends on nothing, and its only allocation is a stack with one
//! entry per open element that declares a namespace (at most
//! [`XmlLimits::in_scope_namespaces`] entries). Every crate that parses XML
//! runs it first, each with the limits its input calls for: WSDL imports,
//! request body lint, XPath assertions and extractions, SOAP fault detection
//! in response diagnostics, and WS-Security header insertion.
//!
//! It is not a parser: where the text stops making sense (malformed markup,
//! a DOCTYPE) the scan ends without an error and the parser reports the
//! problem. In particular it stops at a DOCTYPE, so it relies on the caller
//! parsing with DTDs refused (`roxmltree::ParsingOptions { allow_dtd: false }`):
//! entity declarations could otherwise expand into markup the scan never saw.
//! Every caller in Anvil parses that way. Pair it with a
//! `ParsingOptions::nodes_limit`, which bounds what the scan does not count.

/// What the scan bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XmlLimits {
    /// Attributes on one start tag (namespace declarations included).
    pub attributes_per_element: usize,
    /// Attribute pairs the parser compares, summed over every element
    /// (n·(n−1)/2 for an element with n attributes).
    pub attribute_pairs: usize,
    /// Bytes in one attribute name (prefix included).
    pub attribute_name_bytes: usize,
    /// `xmlns` / `xmlns:prefix` declarations in the document.
    pub xmlns_declarations: usize,
    /// Bytes in one declared namespace prefix.
    pub xmlns_prefix_bytes: usize,
    /// Bytes in one declared namespace URI (as written).
    pub xmlns_uri_bytes: usize,
    /// Namespace declarations in scope of one element: its own and those of
    /// its open ancestors (a prefix declared again counts again, so this is
    /// an upper bound on the namespaces in scope). The parser looks every
    /// prefixed element and attribute name up among them one by one.
    pub in_scope_namespaces: usize,
    /// Work of resolving namespace scopes: the square of the declarations in
    /// scope, summed over the elements that declare a namespace. For each such
    /// element the parser copies the parent's namespaces and checks each
    /// against those already copied (about n²/2 prefix comparisons for n in
    /// scope), so a nested chain of n declarations costs about n³/6 and this
    /// budget bounds it. Siblings that declare the same prefix again each
    /// cost only the square of their own small scope.
    pub namespace_scope_work: usize,
}

/// A limit the scan found exceeded, with that limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XmlLimitExceeded {
    AttributesPerElement(usize),
    AttributePairs(usize),
    AttributeNameBytes(usize),
    NamespaceDeclarations(usize),
    NamespacePrefixBytes(usize),
    NamespaceUriBytes(usize),
    InScopeNamespaces(usize),
    NamespaceScopeWork(usize),
}

impl std::fmt::Display for XmlLimitExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::AttributesPerElement(l) => write!(f, "more than {l} attributes on one element"),
            Self::AttributePairs(l) => write!(f, "more than {l} attribute pairs on the elements of the document"),
            Self::AttributeNameBytes(l) => write!(f, "an attribute name longer than {l} bytes"),
            Self::NamespaceDeclarations(l) => write!(f, "more than {l} namespace declarations (xmlns)"),
            Self::NamespacePrefixBytes(l) => write!(f, "a namespace prefix longer than {l} bytes"),
            Self::NamespaceUriBytes(l) => write!(f, "a namespace URI longer than {l} bytes"),
            Self::InScopeNamespaces(l) => write!(f, "more than {l} namespace declarations in scope of one element"),
            Self::NamespaceScopeWork(l) => {
                write!(f, "namespace scopes costing more than {l} to resolve (declarations in scope, squared, per declaring element)")
            }
        }
    }
}

impl std::error::Error for XmlLimitExceeded {}

/// Check `text` against `limits` in one pass, before it is parsed.
pub fn check_xml_limits(text: &str, limits: &XmlLimits) -> Result<(), XmlLimitExceeded> {
    let mut scan = Scan { b: text.as_bytes(), limits: *limits, xmlns: 0, pairs: 0, depth: 0, scopes: Vec::new(), in_scope: 0, work: 0 };
    let mut i = 0;
    while let Some(at) = scan.find_byte(i, b'<') {
        let rest = &scan.b[at..];
        let next = if rest.starts_with(b"<!--") {
            scan.find(at + 4, b"-->").map(|e| e + 3)
        } else if rest.starts_with(b"<![CDATA[") {
            scan.find(at + 9, b"]]>").map(|e| e + 3)
        } else if rest.starts_with(b"<?") {
            scan.find(at + 2, b"?>").map(|e| e + 2)
        } else if rest.starts_with(b"<!") {
            // A DOCTYPE (the parser refuses it) or malformed markup.
            None
        } else if rest.starts_with(b"</") {
            scan.end_tag();
            scan.find_byte(at + 2, b'>').map(|e| e + 1)
        } else {
            scan.start_tag(at + 1)?
        };
        match next {
            Some(n) => i = n,
            None => return Ok(()),
        }
    }
    Ok(())
}

struct Scan<'t> {
    b: &'t [u8],
    limits: XmlLimits,
    xmlns: usize,
    pairs: usize,
    /// Open elements.
    depth: usize,
    /// (depth, declarations) of each open element that declares a namespace.
    scopes: Vec<(usize, usize)>,
    /// Declarations of the open elements.
    in_scope: usize,
    /// Namespace scope work so far.
    work: usize,
}

fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | b'\r')
}

impl Scan<'_> {
    fn find_byte(&self, from: usize, c: u8) -> Option<usize> {
        self.b.get(from..)?.iter().position(|&x| x == c).map(|p| from + p)
    }

    fn find(&self, from: usize, pat: &[u8]) -> Option<usize> {
        self.b.get(from..)?.windows(pat.len()).position(|w| w == pat).map(|p| from + p)
    }

    fn skip_space(&self, mut i: usize) -> usize {
        while self.b.get(i).is_some_and(|&c| is_space(c)) {
            i += 1;
        }
        i
    }

    /// An end tag closes the innermost open element and its declarations.
    /// Text whose end tags do not match its start tags is refused by the
    /// parser where they stop matching.
    fn end_tag(&mut self) {
        self.depth = self.depth.saturating_sub(1);
        if let Some(&(depth, declared)) = self.scopes.last()
            && depth == self.depth
        {
            self.scopes.pop();
            self.in_scope -= declared;
        }
    }

    /// The start tag ending at `>` declared `declared` namespaces.
    fn close_start_tag(&mut self, declared: usize, empty: bool) -> Result<(), XmlLimitExceeded> {
        let l = self.limits;
        if declared > 0 {
            let n = self.in_scope + declared;
            if n > l.in_scope_namespaces {
                return Err(XmlLimitExceeded::InScopeNamespaces(l.in_scope_namespaces));
            }
            self.work = self.work.saturating_add(n.saturating_mul(n));
            if self.work > l.namespace_scope_work {
                return Err(XmlLimitExceeded::NamespaceScopeWork(l.namespace_scope_work));
            }
            if !empty {
                self.scopes.push((self.depth, declared));
                self.in_scope = n;
            }
        }
        if !empty {
            self.depth += 1;
        }
        Ok(())
    }

    /// Check the attributes of the start tag whose name begins at `i`;
    /// `Ok(Some(end))` is just past its `>`, `Ok(None)` ends the scan.
    fn start_tag(&mut self, mut i: usize) -> Result<Option<usize>, XmlLimitExceeded> {
        let b = self.b;
        let l = self.limits;
        while b.get(i).is_some_and(|&c| !is_space(c) && c != b'>' && c != b'/') {
            i += 1;
        }
        let mut attributes = 0usize;
        let mut declared = 0usize;
        let mut empty = false;
        loop {
            i = self.skip_space(i);
            match b.get(i) {
                None => return Ok(None),
                Some(b'>') => {
                    self.close_start_tag(declared, empty)?;
                    return Ok(Some(i + 1));
                }
                Some(b'/') => {
                    empty = true;
                    i += 1;
                    continue;
                }
                Some(_) => empty = false,
            }
            let name = i;
            while b.get(i).is_some_and(|&c| !is_space(c) && !matches!(c, b'=' | b'>' | b'/')) {
                i += 1;
            }
            let name = &b[name..i];
            i = self.skip_space(i);
            if b.get(i) != Some(&b'=') {
                return Ok(None);
            }
            i = self.skip_space(i + 1);
            let quote = match b.get(i) {
                Some(&q @ (b'"' | b'\'')) => q,
                _ => return Ok(None),
            };
            let Some(end) = self.find_byte(i + 1, quote) else { return Ok(None) };
            let value = end - (i + 1);
            i = end + 1;
            // This attribute is compared with each earlier one on the element.
            self.pairs = self.pairs.saturating_add(attributes);
            attributes += 1;
            if attributes > l.attributes_per_element {
                return Err(XmlLimitExceeded::AttributesPerElement(l.attributes_per_element));
            }
            if self.pairs > l.attribute_pairs {
                return Err(XmlLimitExceeded::AttributePairs(l.attribute_pairs));
            }
            if name.len() > l.attribute_name_bytes {
                return Err(XmlLimitExceeded::AttributeNameBytes(l.attribute_name_bytes));
            }
            let prefix = match name.strip_prefix(b"xmlns") {
                Some([]) => Some(0),
                Some([b':', p @ ..]) => Some(p.len()),
                _ => None,
            };
            if let Some(prefix) = prefix {
                declared += 1;
                self.xmlns += 1;
                if self.xmlns > l.xmlns_declarations {
                    return Err(XmlLimitExceeded::NamespaceDeclarations(l.xmlns_declarations));
                }
                if prefix > l.xmlns_prefix_bytes {
                    return Err(XmlLimitExceeded::NamespacePrefixBytes(l.xmlns_prefix_bytes));
                }
                if value > l.xmlns_uri_bytes {
                    return Err(XmlLimitExceeded::NamespaceUriBytes(l.xmlns_uri_bytes));
                }
            }
        }
    }
}

/// Documents for the call sites' regression tests (feature `test-support`).
#[cfg(any(test, feature = "test-support"))]
pub mod test_support {
    use super::XmlLimits;

    /// Elements with the most namespace work `limits` allow, to be placed
    /// inside a root that declares `outer` namespaces: a chain of nested
    /// elements that each declare one more prefix, as deep as the in-scope
    /// bound allows, then siblings inside it that each declare one until the
    /// scope work budget or the declaration count is spent, then `lookups`
    /// elements named with the outermost prefix, which the parser finds last
    /// in the innermost scope. The prefixes are as long as the limits allow
    /// and differ only in their last bytes, so each comparison reads them
    /// whole.
    pub fn namespace_worst_case(limits: &XmlLimits, outer: usize, lookups: usize) -> String {
        let len = limits.xmlns_prefix_bytes.min(limits.attribute_name_bytes.saturating_sub(6));
        assert!(len >= 8, "prefixes of at least 8 bytes");
        let prefix = |i: usize| format!("p{}{i:06}", "q".repeat(len - 7));
        let mut work = outer * outer;
        let mut declared = outer;
        let mut s = String::new();
        let mut depth = 0;
        while outer + depth + 2 <= limits.in_scope_namespaces
            && declared < limits.xmlns_declarations
            && work + (outer + depth + 1).pow(2) <= limits.namespace_scope_work
        {
            depth += 1;
            work += (outer + depth).pow(2);
            declared += 1;
            s.push_str(&format!("<c xmlns:{}=\"urn:a\">", prefix(depth)));
        }
        let n = outer + depth + 1;
        let mut sibling = depth;
        while declared < limits.xmlns_declarations && work + n * n <= limits.namespace_scope_work {
            sibling += 1;
            work += n * n;
            declared += 1;
            s.push_str(&format!("<s xmlns:{}=\"urn:a\"/>", prefix(sibling)));
        }
        if depth > 0 {
            s.push_str(&format!("<{}:e/>", prefix(1)).repeat(lookups));
        }
        s.push_str(&"</c>".repeat(depth));
        s
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::namespace_worst_case;
    use super::*;

    const WIDE: XmlLimits = XmlLimits {
        attributes_per_element: 10,
        attribute_pairs: 1_000,
        attribute_name_bytes: 64,
        xmlns_declarations: 10,
        xmlns_prefix_bytes: 16,
        xmlns_uri_bytes: 64,
        in_scope_namespaces: 10,
        namespace_scope_work: 1_000,
    };

    fn attrs(n: usize) -> String {
        (0..n).map(|i| format!(" a{i}=\"{i}\"")).collect()
    }

    fn with(f: impl FnOnce(&mut XmlLimits)) -> XmlLimits {
        let mut l = WIDE;
        f(&mut l);
        l
    }

    #[test]
    fn counts_attributes_per_start_tag() {
        let four = with(|l| l.attributes_per_element = 4);
        let ok = format!("<r{}><c{}/></r>", attrs(4), attrs(4));
        assert_eq!(check_xml_limits(&ok, &four), Ok(()));
        let over = format!("<r><c{}/></r>", attrs(5));
        assert_eq!(check_xml_limits(&over, &four), Err(XmlLimitExceeded::AttributesPerElement(4)));
        // Single quotes, spaces around `=`, and `>` or `/` inside values.
        let odd = "<r a = 'x>y' b=\"/>\" c='\"'  d=\"'\"/>";
        assert_eq!(check_xml_limits(odd, &four), Ok(()));
        let three = with(|l| l.attributes_per_element = 3);
        assert_eq!(check_xml_limits(odd, &three), Err(XmlLimitExceeded::AttributesPerElement(3)));
    }

    #[test]
    fn sums_attribute_pairs_over_the_document() {
        // Four attributes make 6 pairs; three such elements make 18.
        let doc = format!("<r><a{a}/><b{a}/><c{a}/></r>", a = attrs(4));
        assert_eq!(check_xml_limits(&doc, &with(|l| l.attribute_pairs = 18)), Ok(()));
        assert_eq!(check_xml_limits(&doc, &with(|l| l.attribute_pairs = 17)), Err(XmlLimitExceeded::AttributePairs(17)));
    }

    #[test]
    fn bounds_names_prefixes_and_uris() {
        let long = "x".repeat(65);
        let name = format!("<r {long}=\"1\"/>");
        assert_eq!(check_xml_limits(&name, &WIDE), Err(XmlLimitExceeded::AttributeNameBytes(64)));
        let prefix = format!("<r xmlns:{}=\"urn:a\"/>", "p".repeat(17));
        assert_eq!(check_xml_limits(&prefix, &WIDE), Err(XmlLimitExceeded::NamespacePrefixBytes(16)));
        let uri = format!("<r xmlns=\"{long}\"/>");
        assert_eq!(check_xml_limits(&uri, &WIDE), Err(XmlLimitExceeded::NamespaceUriBytes(64)));
        // Other attributes may have long values.
        assert_eq!(check_xml_limits(&format!("<r a=\"{long}\"/>"), &WIDE), Ok(()));
    }

    #[test]
    fn skips_comments_cdata_instructions_and_values() {
        let hidden =
            format!("<?xml version=\"1.0\"?><!-- <x{a}/> --><r v=\"<x{a}/>\"><![CDATA[<x{a}/>]]><?pi <x{a}/> ?></r>", a = attrs(9));
        assert_eq!(check_xml_limits(&hidden, &with(|l| l.attributes_per_element = 2)), Ok(()));
    }

    #[test]
    fn counts_namespace_declarations_in_the_document() {
        let doc = "<r xmlns=\"urn:a\" xmlns:b=\"urn:b\"><c xmlns:d=\"urn:d\" xmlnsx=\"no\"/></r>";
        assert_eq!(check_xml_limits(doc, &with(|l| l.xmlns_declarations = 3)), Ok(()));
        assert_eq!(check_xml_limits(doc, &with(|l| l.xmlns_declarations = 2)), Err(XmlLimitExceeded::NamespaceDeclarations(2)));
    }

    #[test]
    fn unfollowable_text_ends_the_scan() {
        // The parser reports these; the scan stops without an error.
        let many = attrs(9);
        let two = with(|l| l.attributes_per_element = 2);
        for doc in
            [format!("<r a{many}"), format!("<r a><c{many}/></r>"), format!("<!DOCTYPE r><r{many}/>"), format!("<!-- open <r{many}/>")]
        {
            assert_eq!(check_xml_limits(&doc, &two), Ok(()), "{doc}");
        }
    }

    #[test]
    fn exceeded_limits_read_as_the_limit_they_name() {
        assert_eq!(XmlLimitExceeded::NamespaceDeclarations(4).to_string(), "more than 4 namespace declarations (xmlns)");
        assert_eq!(XmlLimitExceeded::AttributesPerElement(256).to_string(), "more than 256 attributes on one element");
        assert_eq!(XmlLimitExceeded::NamespaceUriBytes(512).to_string(), "a namespace URI longer than 512 bytes");
    }

    fn decl(i: usize) -> String {
        format!(" xmlns:p{i}=\"urn:p{i}\"")
    }

    #[test]
    fn bounds_the_namespaces_in_scope_of_each_element() {
        let three = with(|l| l.in_scope_namespaces = 3);
        // Two on the root and one on the child are in scope of the child.
        let ok = format!("<r{}{}><c{}/></r>", decl(0), decl(1), decl(2));
        assert_eq!(check_xml_limits(&ok, &three), Ok(()));
        let over = format!("<r{}{}><c{}><d{}/></c></r>", decl(0), decl(1), decl(2), decl(3));
        assert_eq!(check_xml_limits(&over, &three), Err(XmlLimitExceeded::InScopeNamespaces(3)));
        // Declarations go out of scope with their element, whether it ends
        // with an end tag or is empty.
        let closed = format!("<r{}><a{}{}></a><b{}/><c{}{}/></r>", decl(0), decl(1), decl(2), decl(3), decl(4), decl(5));
        assert_eq!(check_xml_limits(&closed, &three), Ok(()));
        // A prefix declared again counts again.
        let again = "<r xmlns:p=\"urn:a\"><c xmlns:p=\"urn:b\"><d xmlns:p=\"urn:c\"><e xmlns:p=\"urn:d\"/></d></c></r>";
        assert_eq!(check_xml_limits(again, &three), Err(XmlLimitExceeded::InScopeNamespaces(3)));
        // End tags inside comments, CDATA and values close nothing.
        let hidden = format!("<r{}><!-- </r> --><![CDATA[</r>]]><a v=\"</r>\"{}><b{}/></a></r>", decl(0), decl(1), decl(2));
        assert_eq!(check_xml_limits(&hidden, &three), Ok(()));
        assert_eq!(check_xml_limits(&hidden, &with(|l| l.in_scope_namespaces = 2)), Err(XmlLimitExceeded::InScopeNamespaces(2)));
    }

    #[test]
    fn charges_the_square_of_the_scope_of_each_declaring_element() {
        // A chain of 1, 2 and 3 in scope costs 1 + 4 + 9.
        let chain = format!("<r{}><c{}><d{}/></c></r>", decl(0), decl(1), decl(2));
        assert_eq!(check_xml_limits(&chain, &with(|l| l.namespace_scope_work = 14)), Ok(()));
        assert_eq!(check_xml_limits(&chain, &with(|l| l.namespace_scope_work = 13)), Err(XmlLimitExceeded::NamespaceScopeWork(13)));
        // Elements that declare nothing cost nothing.
        let plain = format!("<r{}>{}</r>", decl(0), "<c><d/></c>".repeat(100));
        assert_eq!(check_xml_limits(&plain, &with(|l| l.namespace_scope_work = 1)), Ok(()));
    }

    #[test]
    fn siblings_that_declare_the_same_prefix_again_stay_cheap() {
        // Ten in scope on the root; each of 10,000 children adds one: 100 + 10,000 * 121.
        let decls: String = (0..10).map(decl).collect();
        let doc = format!("<r{decls}>{}</r>", "<i xmlns:m=\"urn:m\">v</i>".repeat(10_000));
        let l = XmlLimits { xmlns_declarations: 20_000, in_scope_namespaces: 11, namespace_scope_work: 100 + 10_000 * 121, ..WIDE };
        assert_eq!(check_xml_limits(&doc, &l), Ok(()));
        let tight = XmlLimits { namespace_scope_work: 100 + 10_000 * 121 - 1, ..l };
        assert_eq!(check_xml_limits(&doc, &tight), Err(XmlLimitExceeded::NamespaceScopeWork(tight.namespace_scope_work)));
    }

    #[test]
    fn the_worst_case_document_is_at_the_limits() {
        for (in_scope, work, declarations) in [(10, 1_000, 100), (128, 1 << 24, 4_096), (256, 1 << 26, 1_024), (128, 1 << 22, 1_024)] {
            let l = XmlLimits {
                attributes_per_element: 256,
                attribute_pairs: 1 << 20,
                attribute_name_bytes: 1_024,
                xmlns_declarations: declarations,
                xmlns_prefix_bytes: 64,
                xmlns_uri_bytes: 512,
                in_scope_namespaces: in_scope,
                namespace_scope_work: work,
            };
            for outer in [0, 2] {
                let decls: String = (0..outer).map(decl).collect();
                let doc = format!("<r{decls}>{}</r>", namespace_worst_case(&l, outer, 10));
                assert_eq!(check_xml_limits(&doc, &l), Ok(()), "{l:?} outer {outer}");
                // Each bound it is at is exact: one less refuses the document.
                let fewer = [XmlLimits { in_scope_namespaces: in_scope - 1, ..l }, XmlLimits { namespace_scope_work: work / 2, ..l }];
                for tighter in fewer {
                    assert!(check_xml_limits(&doc, &tighter).is_err(), "{tighter:?} outer {outer}");
                }
            }
        }
    }
}
