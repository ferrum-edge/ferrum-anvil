//! A linear pre-parse scan of XML text for the work `roxmltree` does before
//! any of its own limits apply: it compares every attribute with each earlier
//! one on the same element (their names and full namespace URIs), and copies
//! the namespaces in scope for every element that declares one. Its node
//! limit counts neither attributes nor namespace declarations.
//!
//! The scan counts the attributes of each start tag, the attribute pairs of
//! the whole document and its `xmlns` declarations, and bounds the length of
//! attribute names, namespace prefixes and namespace URIs. It skips comments,
//! CDATA sections, processing instructions and quoted attribute values. It
//! uses nothing from this crate, so it can be shared as is.
//!
//! It is not a parser: where the text stops making sense (malformed markup,
//! a DOCTYPE) the scan ends without an error and the parser reports the
//! problem. In particular it stops at a DOCTYPE, so it relies on the caller
//! parsing with DTDs refused (`roxmltree::ParsingOptions { allow_dtd: false }`):
//! entity declarations could otherwise expand into markup the scan never saw.

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
}

/// Check `text` against `limits` in one pass, before it is parsed.
pub fn check_xml_limits(text: &str, limits: &XmlLimits) -> Result<(), XmlLimitExceeded> {
    let mut scan = Scan { b: text.as_bytes(), limits: *limits, xmlns: 0, pairs: 0 };
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

    /// Check the attributes of the start tag whose name begins at `i`;
    /// `Ok(Some(end))` is just past its `>`, `Ok(None)` ends the scan.
    fn start_tag(&mut self, mut i: usize) -> Result<Option<usize>, XmlLimitExceeded> {
        let b = self.b;
        let l = self.limits;
        while b.get(i).is_some_and(|&c| !is_space(c) && c != b'>' && c != b'/') {
            i += 1;
        }
        let mut attributes = 0usize;
        loop {
            i = self.skip_space(i);
            match b.get(i) {
                None => return Ok(None),
                Some(b'>') => return Ok(Some(i + 1)),
                Some(b'/') => {
                    i += 1;
                    continue;
                }
                Some(_) => {}
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

#[cfg(test)]
mod tests {
    use super::*;

    const WIDE: XmlLimits = XmlLimits {
        attributes_per_element: 10,
        attribute_pairs: 1_000,
        attribute_name_bytes: 64,
        xmlns_declarations: 10,
        xmlns_prefix_bytes: 16,
        xmlns_uri_bytes: 64,
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
        let hidden = format!(
            "<?xml version=\"1.0\"?><!-- <x{a}/> --><r v=\"<x{a}/>\"><![CDATA[<x{a}/>]]><?pi <x{a}/> ?></r>",
            a = attrs(9)
        );
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
        for doc in [
            format!("<r a{many}"),
            format!("<r a><c{many}/></r>"),
            format!("<!DOCTYPE r><r{many}/>"),
            format!("<!-- open <r{many}/>"),
        ] {
            assert_eq!(check_xml_limits(&doc, &two), Ok(()), "{doc}");
        }
    }
}
