//! A minimal writer for JMeter test plans (`.jmx`, JMeter's XStream format)
//! and the encoding of text into JMeter property strings.
//!
//! Two layers of escaping apply to every user value:
//!
//! 1. **JMeter's function syntax.** JMeter compiles every string property of
//!    a test element (`FunctionParser.compileString`). A property that holds
//!    a function or variable reference (`${…}`) is compiled as a whole, and
//!    then a backslash escapes the next `$`, `,` or `\`. A property without
//!    one is used verbatim. [`Text::to_jmeter`] therefore writes literal text
//!    unchanged when the value holds no expression and no `${`, and otherwise
//!    doubles every literal `\` and writes every literal `$` as
//!    `${__char(36)}`, which also guarantees the property is compiled (so the
//!    escapes apply) even when the only `${` was literal text.
//! 2. **XML.** The writer escapes `&`, `<`, `>` (and `"` in attributes) and
//!    writes CR, and in attributes also LF and TAB, as character references
//!    so they survive XML end-of-line and attribute normalization. A
//!    character XML 1.0 cannot carry (most C0 controls, U+FFFE, U+FFFF) is
//!    refused, never dropped.

use std::fmt::Write as _;

/// One piece of a JMeter property value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Piece {
    /// Literal text, sent byte for byte.
    Lit(String),
    /// A JMeter expression in JMeter syntax (`${name}`, `${__UUID()}`).
    Expr(String),
}

/// A property value: literal text and JMeter expressions.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Text(pub Vec<Piece>);

impl Text {
    pub fn lit(s: impl Into<String>) -> Self {
        Text(vec![Piece::Lit(s.into())])
    }

    pub fn expr(s: impl Into<String>) -> Self {
        Text(vec![Piece::Expr(s.into())])
    }

    pub fn push_lit(&mut self, s: &str) {
        if s.is_empty() {
            return;
        }
        match self.0.last_mut() {
            Some(Piece::Lit(l)) => l.push_str(s),
            _ => self.0.push(Piece::Lit(s.to_string())),
        }
    }

    pub fn push_expr(&mut self, s: impl Into<String>) {
        self.0.push(Piece::Expr(s.into()));
    }

    pub fn append(&mut self, other: Text) {
        for p in other.0 {
            match p {
                Piece::Lit(l) => self.push_lit(&l),
                Piece::Expr(e) => self.push_expr(e),
            }
        }
    }

    pub fn has_expr(&self) -> bool {
        self.0.iter().any(|p| matches!(p, Piece::Expr(_)))
    }

    /// The literal text when the value holds no expression.
    pub fn as_literal(&self) -> Option<String> {
        let mut out = String::new();
        for p in &self.0 {
            match p {
                Piece::Lit(l) => out.push_str(l),
                Piece::Expr(_) => return None,
            }
        }
        Some(out)
    }

    /// The JMeter property string (see the module documentation).
    pub fn to_jmeter(&self) -> String {
        let compiled = self.has_expr() || self.0.iter().any(|p| matches!(p, Piece::Lit(l) if l.contains("${")));
        let mut out = String::new();
        for p in &self.0 {
            match p {
                Piece::Expr(e) => out.push_str(e),
                Piece::Lit(l) if !compiled => out.push_str(l),
                Piece::Lit(l) => {
                    for c in l.chars() {
                        match c {
                            '\\' => out.push_str("\\\\"),
                            '$' => out.push_str("${__char(36)}"),
                            c => out.push(c),
                        }
                    }
                }
            }
        }
        out
    }
}

/// A character XML 1.0 cannot carry, if any.
pub fn invalid_xml_char(s: &str) -> Option<char> {
    s.chars().find(|&c| {
        let u = c as u32;
        !(u == 0x9 || u == 0xA || u == 0xD || (0x20..=0xD7FF).contains(&u) || (0xE000..=0xFFFD).contains(&u) || u >= 0x10000)
    })
}

fn esc_text(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#13;"),
            c => out.push(c),
        }
    }
}

fn esc_attr(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\r' => out.push_str("&#13;"),
            '\n' => out.push_str("&#10;"),
            '\t' => out.push_str("&#9;"),
            c => out.push(c),
        }
    }
}

/// A test element property.
#[derive(Debug, Clone)]
pub enum Prop {
    Str(&'static str, String),
    Bool(&'static str, bool),
    Int(&'static str, i64),
    Long(&'static str, i64),
    /// A nested element (`elementProp`): name, element type, extra
    /// attributes (guiclass, testclass, testname) and its properties.
    Element {
        name: String,
        element_type: &'static str,
        attrs: Vec<(&'static str, String)>,
        props: Vec<Prop>,
    },
    /// A collection (`collectionProp`) of nested properties.
    Collection(&'static str, Vec<Prop>),
    /// A string property with a name chosen at run time (the entries of a
    /// Response Assertion's test strings).
    NamedStr(String, String),
}

impl Prop {
    pub fn s(name: &'static str, v: impl Into<String>) -> Self {
        Prop::Str(name, v.into())
    }

    /// A string property holding user content.
    pub fn t(name: &'static str, v: &Text) -> Self {
        Prop::Str(name, v.to_jmeter())
    }
}

/// A test element and its children (the `hashTree` that follows it).
#[derive(Debug, Clone)]
pub struct Node {
    pub tag: &'static str,
    pub guiclass: &'static str,
    pub testclass: &'static str,
    pub testname: String,
    pub props: Vec<Prop>,
    pub children: Vec<Node>,
}

impl Node {
    pub fn new(tag: &'static str, guiclass: &'static str, testname: impl Into<String>, props: Vec<Prop>) -> Self {
        Node { tag, guiclass, testclass: tag, testname: testname.into(), props, children: vec![] }
    }

    pub fn with_children(mut self, children: Vec<Node>) -> Self {
        self.children = children;
        self
    }
}

/// Every string in a tree that XML cannot carry, for a refusal.
pub fn check_tree(n: &Node) -> Result<(), char> {
    fn props(p: &[Prop]) -> Result<(), char> {
        for p in p {
            match p {
                Prop::Str(_, v) => check(v)?,
                Prop::NamedStr(k, v) => {
                    check(k)?;
                    check(v)?
                }
                Prop::Element { name, attrs, props: inner, .. } => {
                    check(name)?;
                    for (_, v) in attrs {
                        check(v)?;
                    }
                    props(inner)?
                }
                Prop::Collection(_, inner) => props(inner)?,
                Prop::Bool(..) | Prop::Int(..) | Prop::Long(..) => {}
            }
        }
        Ok(())
    }
    fn check(s: &str) -> Result<(), char> {
        invalid_xml_char(s).map_or(Ok(()), Err)
    }
    check(&n.testname)?;
    props(&n.props)?;
    for c in &n.children {
        check_tree(c)?;
    }
    Ok(())
}

fn indent(out: &mut String, depth: usize) {
    for _ in 0..depth {
        out.push_str("  ");
    }
}

fn write_props(out: &mut String, props: &[Prop], depth: usize) {
    for p in props {
        indent(out, depth);
        match p {
            Prop::Str(name, v) => write_str_prop(out, name, v),
            Prop::NamedStr(name, v) => write_str_prop(out, name, v),
            Prop::Bool(name, v) => {
                let _ = write!(out, "<boolProp name=\"{name}\">{v}</boolProp>");
            }
            Prop::Int(name, v) => {
                let _ = write!(out, "<intProp name=\"{name}\">{v}</intProp>");
            }
            Prop::Long(name, v) => {
                let _ = write!(out, "<longProp name=\"{name}\">{v}</longProp>");
            }
            Prop::Element { name, element_type, attrs, props } => {
                out.push_str("<elementProp name=\"");
                esc_attr(name, out);
                let _ = write!(out, "\" elementType=\"{element_type}\"");
                for (k, v) in attrs {
                    let _ = write!(out, " {k}=\"");
                    esc_attr(v, out);
                    out.push('"');
                }
                if props.is_empty() {
                    out.push_str("/>");
                } else {
                    out.push_str(">\n");
                    write_props(out, props, depth + 1);
                    indent(out, depth);
                    out.push_str("</elementProp>");
                }
            }
            Prop::Collection(name, items) => {
                if items.is_empty() {
                    let _ = write!(out, "<collectionProp name=\"{name}\"/>");
                } else {
                    let _ = writeln!(out, "<collectionProp name=\"{name}\">");
                    write_props(out, items, depth + 1);
                    indent(out, depth);
                    out.push_str("</collectionProp>");
                }
            }
        }
        out.push('\n');
    }
}

fn write_str_prop(out: &mut String, name: &str, v: &str) {
    out.push_str("<stringProp name=\"");
    esc_attr(name, out);
    if v.is_empty() {
        out.push_str("\"></stringProp>");
    } else {
        out.push_str("\">");
        esc_text(v, out);
        out.push_str("</stringProp>");
    }
}

fn write_node(out: &mut String, n: &Node, depth: usize) {
    indent(out, depth);
    let _ = write!(out, "<{} guiclass=\"{}\" testclass=\"{}\" testname=\"", n.tag, n.guiclass, n.testclass);
    esc_attr(&n.testname, out);
    out.push_str("\" enabled=\"true\"");
    if n.props.is_empty() {
        out.push_str("/>\n");
    } else {
        out.push_str(">\n");
        write_props(out, &n.props, depth + 1);
        indent(out, depth);
        let _ = writeln!(out, "</{}>", n.tag);
    }
    indent(out, depth);
    if n.children.is_empty() {
        out.push_str("<hashTree/>\n");
    } else {
        out.push_str("<hashTree>\n");
        for c in &n.children {
            write_node(out, c, depth + 1);
        }
        indent(out, depth);
        out.push_str("</hashTree>\n");
    }
}

/// The complete `.jmx` document for a test plan node (the root element).
pub fn document(plan: &Node, jmeter_version: &str, comment: &str) -> String {
    let mut out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str("<!-- ");
    // `--` may not appear inside an XML comment.
    out.push_str(&comment.replace("--", "- -"));
    out.push_str(" -->\n");
    let _ = writeln!(out, "<jmeterTestPlan version=\"1.2\" properties=\"5.0\" jmeter=\"{jmeter_version}\">");
    out.push_str("  <hashTree>\n");
    write_node(&mut out, plan, 2);
    out.push_str("  </hashTree>\n</jmeterTestPlan>\n");
    out
}

/// Escape a literal for a Perl 5 regular expression (JMeter's default ORO
/// engine, and Java's): every ASCII character that is not a letter or a
/// digit gets a backslash, which makes it literal in both dialects.
pub fn regex_literal(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    for c in s.chars() {
        if c.is_ascii() && !c.is_ascii_alphanumeric() {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// A header name as a case-insensitive Perl 5 pattern, without relying on
/// inline modifiers: letters become `[xX]` classes.
pub fn regex_header_name(name: &str) -> String {
    let mut out = String::new();
    for c in name.chars() {
        if c.is_ascii_alphabetic() {
            let _ = write!(out, "[{}{}]", c.to_ascii_lowercase(), c.to_ascii_uppercase());
        } else {
            out.push_str(&regex_literal(&c.to_string()));
        }
    }
    out
}

/// Escape a value for a Java `.properties` file read with
/// `Properties.load(InputStream)` (ISO-8859-1): backslash escapes for the
/// separators and whitespace, `\uXXXX` for everything outside printable ASCII.
pub fn properties_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for (i, c) in s.chars().enumerate() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{c}' => out.push_str("\\f"),
            '=' | ':' | '#' | '!' => {
                out.push('\\');
                out.push(c);
            }
            ' ' if i == 0 => out.push_str("\\ "),
            c if (' '..='~').contains(&c) => out.push(c),
            c => {
                let mut buf = [0u16; 2];
                for unit in c.encode_utf16(&mut buf) {
                    let _ = write!(out, "\\u{unit:04X}");
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_text_without_expressions_is_verbatim() {
        assert_eq!(Text::lit(r#"{"a":"b\\c","d":"$5"}"#).to_jmeter(), r#"{"a":"b\\c","d":"$5"}"#);
    }

    #[test]
    fn text_with_expressions_escapes_backslashes_and_dollars() {
        let mut t = Text::lit(r"a\b$");
        t.push_expr("${anvil_ds_0}");
        t.push_lit(r"\,c");
        assert_eq!(t.to_jmeter(), r"a\\b${__char(36)}${anvil_ds_0}\\,c");
    }

    #[test]
    fn a_literal_dollar_brace_is_never_a_jmeter_reference() {
        // Without an expression of its own, the literal `${` still forces
        // compilation through `__char`, so the escapes are applied.
        assert_eq!(Text::lit(r"x ${HOME} \y").to_jmeter(), r"x ${__char(36)}{HOME} \\y");
    }

    #[test]
    fn xml_escaping_keeps_carriage_returns_and_refuses_controls() {
        let mut s = String::new();
        esc_text("a&b<c>\r\n", &mut s);
        assert_eq!(s, "a&amp;b&lt;c&gt;&#13;\n");
        assert_eq!(invalid_xml_char("ok\t\r\n"), None);
        assert_eq!(invalid_xml_char("bad\u{1}"), Some('\u{1}'));
        assert_eq!(invalid_xml_char("bad\u{FFFE}"), Some('\u{FFFE}'));
    }

    #[test]
    fn properties_values_round_trip_through_java_escapes() {
        assert_eq!(properties_value(" a=b:c#d!e\\f\né"), "\\ a\\=b\\:c\\#d\\!e\\\\f\\n\\u00E9");
        assert_eq!(properties_value("😀"), "\\uD83D\\uDE00");
    }

    #[test]
    fn header_name_patterns_are_case_insensitive_without_modifiers() {
        assert_eq!(regex_header_name("X-Id"), "[xX]\\-[iI][dD]");
        assert_eq!(regex_literal("a.b*c"), "a\\.b\\*c");
    }

    #[test]
    fn document_shape() {
        let plan = Node::new("TestPlan", "TestPlanGui", "P", vec![Prop::Bool("TestPlan.functional_mode", false)]);
        let doc = document(&plan, "5.6.3", "made -- here");
        assert!(doc.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!-- made - - here -->"));
        let parsed = roxmltree::Document::parse(&doc).unwrap();
        let root = parsed.root_element();
        assert_eq!(root.tag_name().name(), "jmeterTestPlan");
        let tree = root.first_element_child().unwrap();
        assert_eq!(tree.tag_name().name(), "hashTree");
        let names: Vec<_> = tree.children().filter(|c| c.is_element()).map(|c| c.tag_name().name()).collect();
        assert_eq!(names, ["TestPlan", "hashTree"]);
    }
}
