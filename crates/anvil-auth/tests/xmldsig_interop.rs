//! Differential tests against independent XML implementations, run by the
//! `xmldsig-interop` workflow (`cargo test -p anvil-auth --test
//! xmldsig_interop -- --ignored`) on a runner with libxml2-utils (`xmllint`),
//! python3-lxml, xmlsec1 and OpenSSL installed. They are ignored elsewhere:
//! a missing tool fails them, it never passes them.
//!
//! - Anvil's exclusive canonicalization equals libxml2's: whole documents
//!   against `xmllint --exc-c14n` (which keeps comments), and element subtrees
//!   with and without comments and with InclusiveNamespaces prefix lists
//!   against lxml's exclusive C14N (libxml2's `xmlC14NExecute`).
//! - Envelopes Anvil signs (RSA-SHA256 with 2048- and 3072-bit keys in
//!   PKCS#8 and PKCS#1 form, ECDSA-P256-SHA256 with PKCS#8 and SEC1 keys;
//!   SOAP 1.1 and 1.2; with and without UsernameToken, Timestamp and a
//!   PrefixList) verify with `xmlsec1 --verify`, and fail once the Body or
//!   the Timestamp is altered.
//! - An OpenSSL-made 1024-bit RSA key and certificate are refused.

use anvil_auth::c14n::{self, Options};
use anvil_auth::wsse::{self, HeaderSpec, SignatureSpec};
use anvil_auth::xmldsig::SigningIdentity;
use anvil_domain::Timestamp;
use anvil_domain::auth::{WssePasswordType, XmlSignatureAlgorithm};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

const SOAP11: &str = "http://schemas.xmlsoap.org/soap/envelope/";
const SOAP12: &str = "http://www.w3.org/2003/05/soap-envelope";
const WSSE_NS: &str = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
const WSU_NS: &str = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";

fn scratch() -> PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    let d = std::env::temp_dir().join(format!("anvil-xmldsig-{}-{}", std::process::id(), N.fetch_add(1, Ordering::Relaxed)));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn run(cmd: &mut Command) -> (bool, String, String) {
    let out = cmd.output().unwrap_or_else(|e| panic!("{cmd:?} could not run (is the tool installed?): {e}"));
    (out.status.success(), String::from_utf8_lossy(&out.stdout).into_owned(), String::from_utf8_lossy(&out.stderr).into_owned())
}

/// Documents for the canonicalization comparison: the W3C examples that
/// need no DTD, and SOAP shapes with the features canonicalization must get
/// right (namespace placement and undeclaration, attribute order and
/// escaping, character references, CDATA, comments, PIs, whitespace,
/// non-ASCII text, QName content that only a PrefixList keeps bound).
fn corpus() -> Vec<String> {
    let mut v = vec![
        "<?xml-stylesheet   href=\"doc.xsl\"\n   type=\"text/xsl\"   ?>\n\n<doc>Hello, world!<!-- Comment 1 --></doc>\n\n<?pi-without-data     ?>\n\n<!-- Comment 2 -->\n\n<!-- Comment 3 -->\n".to_string(),
        "<doc>\n   <clean>   </clean>\n   <dirty>   A   B   </dirty>\n   <mixed>\n      A\n      <clean>   </clean>\n      B\n      <dirty>   A   B   </dirty>\n      C\n   </mixed>\n</doc>".to_string(),
        r#"<doc>
   <text>First line&#x0d;&#10;Second line</text>
   <value>&#x32;</value>
   <compute><![CDATA[value>"0" && value<"10" ?"valid":"error"]]></compute>
   <compute expr='value>"0" &amp;&amp; value&lt;"10" ?"valid":"error"'>valid</compute>
   <norm attr=' &apos;   &#x20;&#13;&#xa;&#9;   &apos; '/>
   <normNames attr='   A   &#x20;&#13;&#xa;&#9;   B   '/>
</doc>"#
            .to_string(),
        "<doc>&#169; caf\u{e9} \u{65e5}\u{672c} &#x1F600;</doc>".to_string(),
        r#"<n0:local xmlns:n0="foo:bar" xmlns:n3="ftp://example.org">
   <n1:elem2 xmlns:n1="http://example.net" xml:lang="en">
       <n3:stuff xmlns:n3="ftp://example.org"/>
   </n1:elem2>
</n0:local>"#
            .to_string(),
        r#"<n2:pdu xmlns:n1="http://example.com"
           xmlns:n2="http://foo.example"
           xml:lang="fr"
           xml:space="retain">
   <n1:elem2 xmlns:n1="http://example.net" xml:lang="en">
       <n3:stuff xmlns:n3="ftp://example.org"/>
   </n1:elem2>
</n2:pdu>"#
            .to_string(),
        r#"<r xmlns="urn:d" xmlns:p="urn:p"><e xmlns=""><f/><p:g xmlns="urn:d2"><h/></p:g></e><p:i p:a="1" b="2" xmlns:z="urn:a" z:c="3"/></r>"#.to_string(),
    ];
    for ns in [SOAP11, SOAP12] {
        v.push(format!(
            r#"<soap:Envelope xmlns:soap="{ns}" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:t="urn:types" xmlns:unused="urn:unused">
  <soap:Header><a:To xmlns:a="http://www.w3.org/2005/08/addressing" soap:mustUnderstand="1">https://svc.example/ws</a:To></soap:Header>
  <soap:Body>
    <m:Order xmlns:m="urn:anvil:orders" xmlns="urn:anvil:default" id='42' note="a &amp; b &lt; c &gt; d &quot;q&quot;">
      <line qty="2" xsi:type="t:Line"><![CDATA[<raw> & stuff]]></line>
      <!-- keep or drop -->
      <?audit level="1"?>
      <empty/>
      <plain xmlns="">text&#13;with CR and tab&#9;here</plain>
    </m:Order>
  </soap:Body>
</soap:Envelope>"#
        ));
        v.push(format!(r#"<env:Envelope xmlns:env="{ns}"><env:Body xmlns:wsu="{WSU_NS}" wsu:Id="b1"><Ping xmlns="urn:ping" xml:lang="en">1</Ping></env:Body></env:Envelope>"#));
    }
    v
}

#[test]
#[ignore = "needs xmllint (libxml2-utils); run by the xmldsig-interop workflow"]
fn whole_documents_match_xmllint_exc_c14n() {
    let dir = scratch();
    for (i, xml) in corpus().iter().enumerate() {
        let f = dir.join(format!("doc-{i}.xml"));
        std::fs::write(&f, xml).unwrap();
        let (ok, stdout, stderr) = run(Command::new("xmllint").arg("--exc-c14n").arg(&f));
        assert!(ok, "xmllint failed on document {i}: {stderr}");
        let doc = roxmltree::Document::parse(xml).unwrap();
        let ours = c14n::canonicalize(doc.root(), &Options { with_comments: true, inclusive_prefixes: vec![] }).unwrap();
        assert_eq!(ours, stdout, "document {i} differs from xmllint --exc-c14n");
    }
}

/// lxml does not pass `#default` through to libxml2 (observed on CI: with
/// `#default` listed, lxml's output equals the output with no PrefixList,
/// apparently because lxml keeps only prefixes found in the document's
/// string dictionary). That case is checked by xmlsec1 instead:
/// `signed_envelopes_verify_with_xmlsec1_and_tampering_fails` signs with the
/// PrefixList `#default`, which libxml2 must canonicalize as Anvil does.
const LXML_C14N: &str = r#"
import sys
from lxml import etree
path, index, comments, prefixes = sys.argv[1], int(sys.argv[2]), sys.argv[3] == "1", sys.argv[4].split()
doc = etree.parse(path, etree.XMLParser(resolve_entities=False, strip_cdata=False))
el = [e for e in doc.getroot().iter() if isinstance(e.tag, str)][index]
sys.stdout.buffer.write(etree.tostring(el, method="c14n", exclusive=True, with_comments=comments, inclusive_ns_prefixes=prefixes or None))
"#;

fn lxml(script: &Path, file: &Path, index: usize, comments: bool, prefixes: &str) -> String {
    let (ok, stdout, stderr) = run(Command::new("python3")
        .arg("-I")
        .arg(script)
        .arg(file)
        .arg(index.to_string())
        .arg(if comments { "1" } else { "0" })
        .arg(prefixes));
    assert!(ok, "lxml failed: {stderr}");
    stdout
}

#[test]
#[ignore = "needs python3-lxml; run by the xmldsig-interop workflow"]
fn element_subtrees_match_lxml_exclusive_c14n_with_prefix_lists() {
    let dir = scratch();
    let script = dir.join("c14n.py");
    std::fs::write(&script, LXML_C14N).unwrap();
    let mut compared = 0;
    for (i, xml) in corpus().iter().enumerate() {
        let f = dir.join(format!("doc-{i}.xml"));
        std::fs::write(&f, xml).unwrap();
        let doc = roxmltree::Document::parse(xml).unwrap();
        for (index, el) in doc.descendants().filter(|n| n.is_element()).enumerate() {
            for comments in [false, true] {
                for list in ["", "t xsi", "n2 n0", "soap p z", "p"] {
                    let opts = Options::with_prefix_list(list, comments).unwrap();
                    let ours = c14n::canonicalize(el, &opts).unwrap();
                    let theirs = lxml(&script, &f, index, comments, list);
                    assert_eq!(
                        ours,
                        theirs,
                        "document {i}, element {index} <{}>, comments {comments}, PrefixList {list:?}",
                        el.tag_name().name()
                    );
                    compared += 1;
                }
            }
        }
    }
    eprintln!("{compared} subtree canonicalizations equal lxml's");
}

/// An OpenSSL key (`kind`: rsa2048, rsa3072, rsa1024, ec) in `form`
/// (pkcs8 or traditional) with a self-signed certificate: (cert, key) PEM.
fn openssl_identity(dir: &Path, name: &str, kind: &str, traditional: bool) -> (String, String) {
    let key = dir.join(format!("{name}.key"));
    let cert = dir.join(format!("{name}.pem"));
    let mut genpkey = Command::new("openssl");
    genpkey.arg("genpkey");
    match kind {
        "ec" => genpkey.args(["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"]),
        rsa => genpkey.args(["-algorithm", "RSA", "-pkeyopt"]).arg(format!("rsa_keygen_bits:{}", rsa.trim_start_matches("rsa"))),
    };
    let (ok, _, e) = run(genpkey.arg("-out").arg(&key));
    assert!(ok, "openssl genpkey: {e}");
    let (ok, _, e) = run(Command::new("openssl")
        .args(["req", "-x509", "-sha256", "-days", "2", "-subj"])
        .arg(format!("/CN=anvil-{name}"))
        .arg("-key")
        .arg(&key)
        .arg("-out")
        .arg(&cert));
    assert!(ok, "openssl req: {e}");
    let key_pem = if traditional {
        let (ok, out, e) = run(Command::new("openssl").args(["pkey", "-traditional", "-in"]).arg(&key));
        assert!(ok, "openssl pkey: {e}");
        out
    } else {
        std::fs::read_to_string(&key).unwrap()
    };
    (std::fs::read_to_string(&cert).unwrap(), key_pem)
}

/// Whether this xmlsec1 has (and so needs) `--lax-key-search` to use a key
/// given on the command line when KeyInfo holds only a token reference.
fn xmlsec_lax() -> bool {
    let (_, out, err) = run(Command::new("xmlsec1").arg("--help-verify"));
    let (_, version, _) = run(Command::new("xmlsec1").arg("--version"));
    format!("{out}{err}").contains("--lax-key-search") || version.split_whitespace().nth(1).is_some_and(|v| !v.starts_with("1.2"))
}

fn xmlsec_verify(dir: &Path, cert_pem: &str, envelope: &str, soap_ns: &str) -> (bool, String) {
    static N: AtomicU64 = AtomicU64::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let cert = dir.join(format!("verify-{n}.pem"));
    let file = dir.join(format!("verify-{n}.xml"));
    std::fs::write(&cert, cert_pem).unwrap();
    std::fs::write(&file, envelope).unwrap();
    let mut cmd = Command::new("xmlsec1");
    cmd.arg("--verify");
    if xmlsec_lax() {
        cmd.arg("--lax-key-search");
    }
    cmd.arg("--pubkey-cert-pem").arg(&cert);
    for node in [format!("{soap_ns}:Body"), format!("{WSU_NS}:Timestamp"), format!("{WSSE_NS}:UsernameToken")] {
        cmd.arg("--id-attr:Id").arg(node);
    }
    let (ok, out, err) = run(cmd.arg(&file));
    (ok, format!("{out}{err}"))
}

#[test]
#[ignore = "needs xmlsec1 and openssl; run by the xmldsig-interop workflow"]
fn signed_envelopes_verify_with_xmlsec1_and_tampering_fails() {
    let dir = scratch();
    let (_, version, _) = run(Command::new("xmlsec1").arg("--version"));
    eprintln!("xmlsec1: {}", version.trim());
    let identities = [
        ("rsa2048-pkcs8", openssl_identity(&dir, "rsa2048-pkcs8", "rsa2048", false)),
        ("rsa2048-pkcs1", openssl_identity(&dir, "rsa2048-pkcs1", "rsa2048", true)),
        ("rsa3072-pkcs8", openssl_identity(&dir, "rsa3072-pkcs8", "rsa3072", false)),
        ("ec-pkcs8", openssl_identity(&dir, "ec-pkcs8", "ec", false)),
        ("ec-sec1", openssl_identity(&dir, "ec-sec1", "ec", true)),
    ];
    let mut verified = 0;
    // Made per run: xmlsec1 checks the signature, never the password.
    let password = hex::encode(rand::random::<[u8; 12]>());
    for (name, (cert, key)) in &identities {
        let identity = SigningIdentity::from_pem(cert, key, XmlSignatureAlgorithm::Auto).unwrap_or_else(|e| panic!("{name}: {e}"));
        for envelope in corpus().into_iter().filter(|x| x.contains(":Envelope")) {
            let soap_ns = if envelope.contains(SOAP12) { SOAP12 } else { SOAP11 };
            for (username, ttl, prefixes) in
                [(true, Some(300), vec![]), (false, Some(60), vec!["t".to_string()]), (false, None, vec![String::new()])]
            {
                let spec = HeaderSpec {
                    username_token: username.then_some(("alice", password.as_str(), WssePasswordType::PasswordDigest)),
                    timestamp_ttl_secs: ttl,
                    saml: None,
                    signature: Some(SignatureSpec { identity: &identity, inclusive_prefixes: &prefixes }),
                };
                let signed = String::from_utf8(wsse::insert(envelope.as_bytes(), &spec, Timestamp::now()).unwrap().body).unwrap();
                let (ok, log) = xmlsec_verify(&dir, cert, &signed, soap_ns);
                assert!(ok, "{name}: xmlsec1 refused Anvil's signature:\n{log}\n{signed}");
                verified += 1;
                // Altered after signing: xmlsec1 must refuse.
                // One more space at the start of the Body's content.
                let body_at = signed.find(":Body").unwrap();
                let content_at = body_at + signed[body_at..].find('>').unwrap() + 1;
                let tampered = format!("{} {}", &signed[..content_at], &signed[content_at..]);
                let (ok, _) = xmlsec_verify(&dir, cert, &tampered, soap_ns);
                assert!(!ok, "{name}: xmlsec1 accepted an envelope whose Body changed after signing");
                if ttl.is_some() {
                    let late = signed.replacen("<wsu:Expires>2", "<wsu:Expires>3", 1);
                    let (ok, _) = xmlsec_verify(&dir, cert, &late, soap_ns);
                    assert!(!ok, "{name}: xmlsec1 accepted an envelope whose Timestamp changed after signing");
                }
            }
        }
    }
    eprintln!("{verified} signed envelopes verified by xmlsec1");
}

#[test]
#[ignore = "needs openssl; run by the xmldsig-interop workflow"]
fn openssl_1024_bit_rsa_keys_are_refused() {
    let dir = scratch();
    let (cert, key) = openssl_identity(&dir, "rsa1024", "rsa1024", false);
    let e = SigningIdentity::from_pem(&cert, &key, XmlSignatureAlgorithm::Auto).unwrap_err().to_string();
    assert!(e.contains("2048"), "{e}");
}
