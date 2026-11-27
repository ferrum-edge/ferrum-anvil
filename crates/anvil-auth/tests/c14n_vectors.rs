//! Exclusive XML Canonicalization against the W3C examples.
//!
//! - Canonical XML 1.0 (W3C Recommendation, 15 March 2001), §3 examples. For
//!   documents with no namespace declarations, exclusive and inclusive
//!   canonical forms are identical, so the published canonical forms are the
//!   exclusive ones. Example 3.1 (PIs, comments and the outside of the
//!   document element, with and without comments), 3.2 (whitespace in
//!   content) and 3.6 (UTF-8 encoding) are used as published. Example 3.4
//!   (character modifications and references) is used without its DTD: the
//!   DTD declares `normNames` NMTOKENS and `normId` ID, which Anvil never
//!   applies (it refuses DTDs), so those two attributes keep the CDATA
//!   normalization; the other lines are as published.
//! - Exclusive XML Canonicalization 1.0 (W3C Recommendation, 18 July 2002),
//!   §2.2: the `n1:elem2` subtree of both example documents has the same
//!   exclusive canonical form, the property the algorithm exists for.
//! - InclusiveNamespaces PrefixList (§3) and the default-namespace rules.
//!
//! CI also compares Anvil's output with libxml2's on these inputs and on a
//! corpus of SOAP envelopes (`tests/xmldsig_interop.rs`).

use anvil_auth::c14n::{Options, canonicalize};

fn parse_dtd(xml: &str) -> roxmltree::Document<'_> {
    roxmltree::Document::parse_with_options(xml, roxmltree::ParsingOptions { allow_dtd: true, ..Default::default() }).unwrap()
}

fn doc_c14n(xml: &str, with_comments: bool) -> String {
    let doc = parse_dtd(xml);
    canonicalize(doc.root(), &Options { with_comments, inclusive_prefixes: vec![] }).unwrap()
}

/// The subtree of the first element named `name` in `xml`.
fn subtree_c14n(xml: &str, name: &str, opts: &Options) -> String {
    let doc = roxmltree::Document::parse(xml).unwrap();
    let node = doc.descendants().find(|n| n.is_element() && n.tag_name().name() == name).unwrap();
    canonicalize(node, opts).unwrap()
}

pub const C14N_3_1: &str = r#"<?xml version="1.0"?>

<?xml-stylesheet   href="doc.xsl"
   type="text/xsl"   ?>

<!DOCTYPE doc SYSTEM "doc.dtd">

<doc>Hello, world!<!-- Comment 1 --></doc>

<?pi-without-data     ?>

<!-- Comment 2 -->

<!-- Comment 3 -->
"#;

#[test]
fn w3c_c14n_example_3_1_pis_comments_and_outside_of_document_element() {
    assert_eq!(
        doc_c14n(C14N_3_1, false),
        "<?xml-stylesheet href=\"doc.xsl\"\n   type=\"text/xsl\"   ?>\n<doc>Hello, world!</doc>\n<?pi-without-data?>"
    );
    assert_eq!(
        doc_c14n(C14N_3_1, true),
        "<?xml-stylesheet href=\"doc.xsl\"\n   type=\"text/xsl\"   ?>\n<doc>Hello, world!<!-- Comment 1 --></doc>\n<?pi-without-data?>\n<!-- Comment 2 -->\n<!-- Comment 3 -->"
    );
}

pub const C14N_3_2: &str = "<doc>
   <clean>   </clean>
   <dirty>   A   B   </dirty>
   <mixed>
      A
      <clean>   </clean>
      B
      <dirty>   A   B   </dirty>
      C
   </mixed>
</doc>";

#[test]
fn w3c_c14n_example_3_2_whitespace_in_document_content() {
    assert_eq!(doc_c14n(C14N_3_2, false), C14N_3_2);
}

pub const C14N_3_4_WITHOUT_DTD: &str = r#"<doc>
   <text>First line&#x0d;&#10;Second line</text>
   <value>&#x32;</value>
   <compute><![CDATA[value>"0" && value<"10" ?"valid":"error"]]></compute>
   <compute expr='value>"0" &amp;&amp; value&lt;"10" ?"valid":"error"'>valid</compute>
   <norm attr=' &apos;   &#x20;&#13;&#xa;&#9;   &apos; '/>
   <normNames attr='   A   &#x20;&#13;&#xa;&#9;   B   '/>
   <normId id=' &apos;   &#x20;&#13;&#xa;&#9;   &apos; '/>
</doc>"#;

#[test]
fn w3c_c14n_example_3_4_character_modifications_and_references() {
    let expected = "<doc>
   <text>First line&#xD;
Second line</text>
   <value>2</value>
   <compute>value&gt;\"0\" &amp;&amp; value&lt;\"10\" ?\"valid\":\"error\"</compute>
   <compute expr=\"value>&quot;0&quot; &amp;&amp; value&lt;&quot;10&quot; ?&quot;valid&quot;:&quot;error&quot;\">valid</compute>
   <norm attr=\" '    &#xD;&#xA;&#x9;   ' \"></norm>
   <normNames attr=\"   A    &#xD;&#xA;&#x9;   B   \"></normNames>
   <normId id=\" '    &#xD;&#xA;&#x9;   ' \"></normId>
</doc>";
    assert_eq!(doc_c14n(C14N_3_4_WITHOUT_DTD, false), expected);
}

pub const C14N_3_6: &str = "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n<doc>&#169;</doc>";

#[test]
fn w3c_c14n_example_3_6_utf8_encoding() {
    assert_eq!(doc_c14n(C14N_3_6, false).as_bytes(), b"<doc>\xC2\xA9</doc>");
}

pub const EXC_2_2_FIRST: &str = r#"<n0:local xmlns:n0="foo:bar" xmlns:n3="ftp://example.org">
   <n1:elem2 xmlns:n1="http://example.net" xml:lang="en">
       <n3:stuff xmlns:n3="ftp://example.org"/>
   </n1:elem2>
</n0:local>"#;

pub const EXC_2_2_SECOND: &str = r#"<n2:pdu xmlns:n1="http://example.com"
           xmlns:n2="http://foo.example"
           xml:lang="fr"
           xml:space="retain">
   <n1:elem2 xmlns:n1="http://example.net" xml:lang="en">
       <n3:stuff xmlns:n3="ftp://example.org"/>
   </n1:elem2>
</n2:pdu>"#;

const EXC_2_2_ELEM2: &str = "<n1:elem2 xmlns:n1=\"http://example.net\" xml:lang=\"en\">
       <n3:stuff xmlns:n3=\"ftp://example.org\"></n3:stuff>
   </n1:elem2>";

#[test]
fn w3c_exc_c14n_section_2_2_subtrees_canonicalize_alike_in_both_contexts() {
    let opts = Options::default();
    assert_eq!(subtree_c14n(EXC_2_2_FIRST, "elem2", &opts), EXC_2_2_ELEM2);
    assert_eq!(subtree_c14n(EXC_2_2_SECOND, "elem2", &opts), EXC_2_2_ELEM2);
}

#[test]
fn w3c_exc_c14n_with_comments_keeps_comments_inside_the_subtree() {
    let xml = r#"<r xmlns:a="urn:a"><a:e><!-- kept --><?pi data?>t</a:e></r>"#;
    let with = Options { with_comments: true, inclusive_prefixes: vec![] };
    assert_eq!(subtree_c14n(xml, "e", &with), r#"<a:e xmlns:a="urn:a"><!-- kept --><?pi data?>t</a:e>"#);
    assert_eq!(subtree_c14n(xml, "e", &Options::default()), r#"<a:e xmlns:a="urn:a"><?pi data?>t</a:e>"#);
}

#[test]
fn inclusive_namespaces_prefix_list_renders_listed_prefixes_in_scope() {
    // n2 is in scope but unused inside elem2: only the PrefixList renders it.
    let opts = Options::with_prefix_list("n2 n0", false).unwrap();
    assert_eq!(
        subtree_c14n(EXC_2_2_SECOND, "elem2", &opts),
        "<n1:elem2 xmlns:n1=\"http://example.net\" xmlns:n2=\"http://foo.example\" xml:lang=\"en\">
       <n3:stuff xmlns:n3=\"ftp://example.org\"></n3:stuff>
   </n1:elem2>"
    );
    // Rendered once, at the apex; a descendant does not repeat it.
    let xml = r#"<r xmlns:q="urn:q" xmlns="urn:d"><e><f q:x="1"/></e></r>"#;
    assert_eq!(
        subtree_c14n(xml, "e", &Options::with_prefix_list("q", false).unwrap()),
        r#"<e xmlns="urn:d" xmlns:q="urn:q"><f q:x="1"></f></e>"#
    );
    // #default renders the default namespace on a prefixed apex.
    let xml = r#"<r xmlns="urn:d" xmlns:p="urn:p"><p:e><p:f/></p:e></r>"#;
    assert_eq!(subtree_c14n(xml, "e", &Options::default()), r#"<p:e xmlns:p="urn:p"><p:f></p:f></p:e>"#);
    assert_eq!(
        subtree_c14n(xml, "e", &Options::with_prefix_list("#default", false).unwrap()),
        r#"<p:e xmlns="urn:d" xmlns:p="urn:p"><p:f></p:f></p:e>"#
    );
}

#[test]
fn soap_body_canonicalizes_with_the_namespaces_it_uses() {
    let xml = r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsu="urn:wsu" xmlns:unused="urn:u"><soap:Header/><soap:Body wsu:Id="B"><m:Ping xmlns:m="urn:m"  a = 'x'>1</m:Ping></soap:Body></soap:Envelope>"#;
    assert_eq!(
        subtree_c14n(xml, "Body", &Options::default()),
        r#"<soap:Body xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsu="urn:wsu" wsu:Id="B"><m:Ping xmlns:m="urn:m" a="x">1</m:Ping></soap:Body>"#
    );
}
