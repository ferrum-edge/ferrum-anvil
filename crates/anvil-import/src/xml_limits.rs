//! A linear pre-parse scan of XML text for the work `roxmltree` does before
//! any of its own limits apply: it compares every attribute with each earlier
//! one on the same element, and copies the namespaces in scope for every
//! element that declares one. Its node limit counts neither attributes nor
//! namespace declarations.
//!
//! The scan counts the attributes of each start tag and the `xmlns`
//! declarations of the whole document, skipping comments, CDATA sections,
//! processing instructions and quoted attribute values. It uses nothing from
//! this crate, so it can be shared as is.
//!
//! It is not a parser: where the text stops making sense (malformed markup, a
//! DOCTYPE) the scan ends without an error and the parser reports the problem.

/// A limit the scan found exceeded, with that limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XmlLimitExceeded {
    /// A start tag has more attributes than this (namespace declarations included).
    AttributesPerElement(usize),
    /// The document has more `xmlns` / `xmlns:prefix` declarations than this.
    NamespaceDeclarations(usize),
}

/// Check `text` against both limits in one pass, before it is parsed.
pub fn check_xml_limits(text: &str, max_attributes: usize, max_xmlns: usize) -> Result<(), XmlLimitExceeded> {
    let mut scan = Scan { b: text.as_bytes(), max_attributes, max_xmlns, xmlns: 0 };
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
    max_attributes: usize,
    max_xmlns: usize,
    xmlns: usize,
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

    /// Count the attributes of the start tag whose name begins at `i`;
    /// `Ok(Some(end))` is just past its `>`, `Ok(None)` ends the scan.
    fn start_tag(&mut self, mut i: usize) -> Result<Option<usize>, XmlLimitExceeded> {
        let b = self.b;
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
            i = end + 1;
            attributes += 1;
            if attributes > self.max_attributes {
                return Err(XmlLimitExceeded::AttributesPerElement(self.max_attributes));
            }
            if name == b"xmlns" || name.starts_with(b"xmlns:") {
                self.xmlns += 1;
                if self.xmlns > self.max_xmlns {
                    return Err(XmlLimitExceeded::NamespaceDeclarations(self.max_xmlns));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attrs(n: usize) -> String {
        (0..n).map(|i| format!(" a{i}=\"{i}\"")).collect()
    }

    #[test]
    fn counts_attributes_per_start_tag() {
        let ok = format!("<r{}><c{}/></r>", attrs(4), attrs(4));
        assert_eq!(check_xml_limits(&ok, 4, 10), Ok(()));
        let over = format!("<r><c{}/></r>", attrs(5));
        assert_eq!(check_xml_limits(&over, 4, 10), Err(XmlLimitExceeded::AttributesPerElement(4)));
        // Single quotes, spaces around `=`, and `>` or `/` inside values.
        let odd = "<r a = 'x>y' b=\"/>\" c='\"'  d=\"'\"/>";
        assert_eq!(check_xml_limits(odd, 4, 10), Ok(()));
        assert_eq!(check_xml_limits(odd, 3, 10), Err(XmlLimitExceeded::AttributesPerElement(3)));
    }

    #[test]
    fn skips_comments_cdata_instructions_and_values() {
        let hidden = format!(
            "<?xml version=\"1.0\"?><!-- <x{a}/> --><r v=\"<x{a}/>\"><![CDATA[<x{a}/>]]><?pi <x{a}/> ?></r>",
            a = attrs(9)
        );
        assert_eq!(check_xml_limits(&hidden, 2, 10), Ok(()));
    }

    #[test]
    fn counts_namespace_declarations_in_the_document() {
        let doc = "<r xmlns=\"urn:a\" xmlns:b=\"urn:b\"><c xmlns:d=\"urn:d\" xmlnsx=\"no\"/></r>";
        assert_eq!(check_xml_limits(doc, 8, 3), Ok(()));
        assert_eq!(check_xml_limits(doc, 8, 2), Err(XmlLimitExceeded::NamespaceDeclarations(2)));
    }

    #[test]
    fn unfollowable_text_ends_the_scan() {
        // The parser reports these; the scan stops without an error.
        let many = attrs(9);
        for doc in [
            format!("<r a{many}"),
            format!("<r a><c{many}/></r>"),
            format!("<!DOCTYPE r><r{many}/>"),
            format!("<!-- open <r{many}/>"),
        ] {
            assert_eq!(check_xml_limits(&doc, 2, 10), Ok(()), "{doc}");
        }
    }
}
