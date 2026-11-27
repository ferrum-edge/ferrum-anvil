//! WS-Security X.509 XML signatures: structure, digests and signature value
//! checked by a verifier written here from the specifications (XML-DSig core
//! validation over Anvil's exclusive canonicalization, the public key taken
//! from the certificate in the BinarySecurityToken), and the refusals.
//!
//! These tests prove the signer is self-consistent and refuses what it must.
//! Independent implementations verify the same envelopes on CI: xmlsec1 and
//! libxml2 (`tests/xmldsig_interop.rs`, the `xmldsig-interop` workflow) and
//! Ferrum Edge's `soap_ws_security` plugin (Lab scenario AUTH-030).
//!
//! The RSA keys are the throwaway fixtures described in `rsa_jwt.rs`; the
//! certificates and the P-256 key are made per run.

use anvil_auth::c14n::{self, Options};
use anvil_auth::wsse::{self, HeaderSpec, SignatureSpec};
use anvil_auth::xmldsig::{DIGEST_SHA256, DS_NS, ECDSA_SHA256, RSA_SHA256, SigningIdentity};
use anvil_auth::{ResolvedAuth, SignableRequest, WsseSigning};
use anvil_domain::Timestamp;
use anvil_domain::auth::{WssePasswordType, XmlSignatureAlgorithm};
use base64::Engine as _;
use sha2::Digest as _;
use zeroize::Zeroizing;

const RSA_2048_PKCS8: &str = include_str!("fixtures/rsa-test-2048.pkcs8.pem");
const RSA_2048_PKCS1: &str = include_str!("fixtures/rsa-test-2048.pkcs1.pem");
const RSA_1024_PKCS8: &str = include_str!("fixtures/rsa-test-1024.pkcs8.pem");
const WSSE_NS: &str = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
const WSU_NS: &str = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
const ENVELOPE: &str = r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><m:Order xmlns:m="urn:anvil:test" id="7">  <m:Item qty='2'>widget &amp; co</m:Item><!-- a comment --></m:Order></soap:Body></soap:Envelope>"#;

/// A self-signed certificate (PEM) for `key_pem`.
fn certificate(key_pem: &str, cn: &str) -> String {
    let key = rcgen::KeyPair::from_pem(key_pem).expect("rcgen reads the key");
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.distinguished_name.push(rcgen::DnType::CommonName, cn);
    params.self_signed(&key).unwrap().pem()
}

/// A fresh P-256 key (PKCS#8 PEM) and its self-signed certificate.
fn ec_identity() -> (String, String) {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let pem = key.serialize_pem();
    let cert = certificate(&pem, "anvil-test-ec");
    (cert, pem)
}

fn rsa_identity() -> (String, String) {
    (certificate(RSA_2048_PKCS8, "anvil-test-rsa"), RSA_2048_PKCS8.to_string())
}

/// A password made per run (the signature tests never depend on its value).
fn run_password() -> String {
    hex::encode(rand::random::<[u8; 12]>())
}

fn sign(envelope: &str, identity: &SigningIdentity, username: bool, ttl: Option<u32>, prefixes: &[String]) -> wsse::Inserted {
    sign_with(envelope, identity, username, ttl, prefixes, &run_password())
}

fn sign_with(
    envelope: &str,
    identity: &SigningIdentity,
    username: bool,
    ttl: Option<u32>,
    prefixes: &[String],
    password: &str,
) -> wsse::Inserted {
    let spec = HeaderSpec {
        username_token: username.then_some(("alice", password, WssePasswordType::PasswordDigest)),
        timestamp_ttl_secs: ttl,
        saml: None,
        signature: Some(SignatureSpec { identity, inclusive_prefixes: prefixes }),
    };
    wsse::insert(envelope.as_bytes(), &spec, Timestamp::now()).expect("signed")
}

fn child<'a, 'i>(n: roxmltree::Node<'a, 'i>, ns: &str, name: &str) -> roxmltree::Node<'a, 'i> {
    n.children().find(|c| c.has_tag_name((ns, name))).unwrap_or_else(|| panic!("no {name} under {:?}", n.tag_name()))
}

/// XML-DSig core validation of the envelope's WS-Security signature, as a
/// receiver performs it. Returns the signed elements' local names.
fn verify(envelope: &str) -> Result<Vec<String>, String> {
    let doc = roxmltree::Document::parse(envelope).map_err(|e| e.to_string())?;
    let security = doc.descendants().find(|n| n.has_tag_name((WSSE_NS, "Security"))).ok_or("no Security")?;
    let signature = child(security, DS_NS, "Signature");
    let signed_info = child(signature, DS_NS, "SignedInfo");
    assert_eq!(child(signed_info, DS_NS, "CanonicalizationMethod").attribute("Algorithm"), Some(c14n::EXC_C14N));
    let method = child(signed_info, DS_NS, "SignatureMethod").attribute("Algorithm").unwrap().to_string();
    // KeyInfo -> SecurityTokenReference -> BinarySecurityToken.
    let reference = child(child(child(signature, DS_NS, "KeyInfo"), WSSE_NS, "SecurityTokenReference"), WSSE_NS, "Reference");
    assert_eq!(reference.attribute("ValueType"), Some(wsse::X509V3));
    let token_id = reference.attribute("URI").unwrap().strip_prefix('#').unwrap();
    let token = doc.descendants().find(|n| n.attribute((WSU_NS, "Id")) == Some(token_id)).ok_or("token not found")?;
    assert!(token.has_tag_name((WSSE_NS, "BinarySecurityToken")));
    assert_eq!(token.attribute("ValueType"), Some(wsse::X509V3));
    let cert_der = base64::engine::general_purpose::STANDARD.decode(token.text().unwrap()).unwrap();
    let mut signed = Vec::new();
    for r in signed_info.children().filter(|n| n.has_tag_name((DS_NS, "Reference"))) {
        let id = r.attribute("URI").unwrap().strip_prefix('#').unwrap();
        let mut targets = doc.descendants().filter(|n| n.attribute((WSU_NS, "Id")) == Some(id));
        let target = targets.next().ok_or("reference target missing")?;
        assert!(targets.next().is_none(), "duplicate id {id}");
        let transforms: Vec<_> = child(r, DS_NS, "Transforms").children().filter(|n| n.is_element()).collect();
        assert_eq!(transforms.len(), 1);
        assert_eq!(transforms[0].attribute("Algorithm"), Some(c14n::EXC_C14N));
        let opts = match transforms[0].first_element_child() {
            Some(inc) => Options::with_prefix_list(inc.attribute("PrefixList").unwrap(), false).unwrap(),
            None => Options::default(),
        };
        assert_eq!(child(r, DS_NS, "DigestMethod").attribute("Algorithm"), Some(DIGEST_SHA256));
        let digest = sha2::Sha256::digest(c14n::canonicalize(target, &opts).unwrap().as_bytes());
        let expected = base64::engine::general_purpose::STANDARD.decode(child(r, DS_NS, "DigestValue").text().unwrap()).unwrap();
        if digest[..] != expected[..] {
            return Err(format!("digest mismatch for {}", target.tag_name().name()));
        }
        signed.push(target.tag_name().name().to_string());
    }
    let value = base64::engine::general_purpose::STANDARD.decode(child(signature, DS_NS, "SignatureValue").text().unwrap()).unwrap();
    let canonical = c14n::canonicalize(signed_info, &Options::default()).unwrap();
    let (_, cert) = x509_parser::parse_x509_certificate(&cert_der).unwrap();
    let spki = cert.public_key().subject_public_key.data.to_vec();
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED, RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};
    let ok = match method.as_str() {
        RSA_SHA256 => UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, &spki).verify(canonical.as_bytes(), &value).is_ok(),
        ECDSA_SHA256 => UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &spki).verify(canonical.as_bytes(), &value).is_ok(),
        other => return Err(format!("unexpected SignatureMethod {other}")),
    };
    if !ok {
        return Err("SignatureValue does not verify".into());
    }
    Ok(signed)
}

#[test]
fn rsa_and_ecdsa_signatures_cover_body_timestamp_and_username_token() {
    let (rsa_cert, rsa_key) = rsa_identity();
    let (ec_cert, ec_key) = ec_identity();
    for (cert, key, method) in
        [(&rsa_cert, rsa_key.as_str(), RSA_SHA256), (&rsa_cert, RSA_2048_PKCS1, RSA_SHA256), (&ec_cert, ec_key.as_str(), ECDSA_SHA256)]
    {
        let identity = SigningIdentity::from_pem(cert, key, XmlSignatureAlgorithm::Auto).unwrap();
        assert_eq!(identity.algorithm().uri(), method);
        let password = run_password();
        let inserted = sign_with(ENVELOPE, &identity, true, Some(300), &[], &password);
        let out = String::from_utf8(inserted.body).unwrap();
        assert_eq!(verify(&out).unwrap(), ["Timestamp", "UsernameToken", "Body"], "{out}");
        let signed = inserted.signed.unwrap();
        assert_eq!(signed.references.len(), 3);
        assert_eq!(signed.certificate_sha256, identity.certificate_sha256());
        // The Body's content is untouched; only its start tag gains the id.
        assert!(out.contains(
            r#"<m:Order xmlns:m="urn:anvil:test" id="7">  <m:Item qty='2'>widget &amp; co</m:Item><!-- a comment --></m:Order></soap:Body>"#
        ));
        let body_id = &signed.references[2];
        assert!(out.contains(&format!(r#"<soap:Body xmlns:wsu="{WSU_NS}" wsu:Id="{body_id}">"#)), "{out}");
        assert!(!out.contains("PRIVATE KEY") && !out.contains(&password));
    }
}

#[test]
fn a_tampered_body_or_timestamp_fails_verification() {
    let (cert, key) = rsa_identity();
    let identity = SigningIdentity::from_pem(&cert, &key, XmlSignatureAlgorithm::Auto).unwrap();
    let out = String::from_utf8(sign(ENVELOPE, &identity, false, Some(60), &[]).body).unwrap();
    assert_eq!(verify(&out).unwrap(), ["Timestamp", "Body"]);
    assert_eq!(verify(&out.replace("widget", "gadget")).unwrap_err(), "digest mismatch for Body");
    let expires = out.find("<wsu:Expires>").unwrap() + "<wsu:Expires>".len();
    let mut late = out.clone();
    late.replace_range(expires..expires + 4, "2999");
    assert_eq!(verify(&late).unwrap_err(), "digest mismatch for Timestamp");
    // A different key's signature over the same SignedInfo does not verify.
    let (_, other_key) = ec_identity();
    let (ec_cert, _) = ec_identity();
    assert!(SigningIdentity::from_pem(&ec_cert, &other_key, XmlSignatureAlgorithm::Auto).is_err());
}

#[test]
fn inclusive_namespaces_and_an_existing_body_id_are_honoured() {
    let (cert, key) = ec_identity();
    let identity = SigningIdentity::from_pem(&cert, &key, XmlSignatureAlgorithm::EcdsaP256Sha256).unwrap();
    let env = format!(
        r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsu="{WSU_NS}" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:t="urn:types"><s:Header><a:To xmlns:a="urn:addr">x</a:To></s:Header><s:Body wsu:Id="my-body"><v xsi:type="t:Kind">1</v></s:Body></s:Envelope>"#
    );
    let prefixes = vec!["t".to_string(), String::new()];
    let inserted = sign(&env, &identity, false, None, &prefixes);
    let out = String::from_utf8(inserted.body).unwrap();
    assert_eq!(inserted.signed.unwrap().references, ["my-body"]);
    assert!(out.contains(r#"PrefixList="t #default""#), "{out}");
    assert!(out.contains(r#"<s:Body wsu:Id="my-body">"#), "an existing wsu:Id is reused: {out}");
    assert_eq!(verify(&out).unwrap(), ["Body"]);
}

#[test]
fn a_body_whose_scope_binds_wsu_elsewhere_gets_another_prefix() {
    let (cert, key) = rsa_identity();
    let identity = SigningIdentity::from_pem(&cert, &key, XmlSignatureAlgorithm::RsaSha256).unwrap();
    let env = r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsu="urn:not-wsu"><soap:Header/><soap:Body/></soap:Envelope>"#;
    let out = String::from_utf8(sign(env, &identity, true, Some(30), &[]).body).unwrap();
    assert!(out.contains(&format!(r#"<soap:Body xmlns:wsu1="{WSU_NS}" wsu1:Id="Body-"#)), "{out}");
    assert_eq!(verify(&out).unwrap(), ["Timestamp", "UsernameToken", "Body"]);
}

#[test]
fn weak_mismatched_and_unsupported_keys_are_refused_without_quoting_them() {
    let (rsa_cert, _) = rsa_identity();
    let (ec_cert, ec_key) = ec_identity();
    let refusal = |cert: &str, key: &str, alg: XmlSignatureAlgorithm| SigningIdentity::from_pem(cert, key, alg).unwrap_err().to_string();
    let weak = refusal(&rsa_cert, RSA_1024_PKCS8, XmlSignatureAlgorithm::Auto);
    assert!(weak.contains("shorter than 2048 bits"), "{weak}");
    let mismatched = refusal(&rsa_cert, &ec_key, XmlSignatureAlgorithm::Auto);
    assert!(mismatched.contains("does not belong") || mismatched.contains("not a usable RSA"), "{mismatched}");
    let wrong_alg = refusal(&ec_cert, &ec_key, XmlSignatureAlgorithm::RsaSha256);
    assert!(wrong_alg.contains("ECDSA-P256-SHA256"), "{wrong_alg}");
    let encrypted = refusal(
        &ec_cert,
        "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n",
        XmlSignatureAlgorithm::Auto,
    );
    assert!(encrypted.contains("encrypted"), "{encrypted}");
    let key_in_chain = refusal(&format!("{ec_cert}{ec_key}"), &ec_key, XmlSignatureAlgorithm::Auto);
    assert!(key_in_chain.contains("certificates only"), "{key_in_chain}");
    for e in [weak, mismatched, wrong_alg, encrypted, key_in_chain] {
        assert!(!e.contains("MII") && !e.contains("BEGIN"), "a refusal quotes key material: {e}");
    }
    let debug = format!("{:?}", SigningIdentity::from_pem(&ec_cert, &ec_key, XmlSignatureAlgorithm::Auto).unwrap());
    assert!(debug.contains("redacted") && !debug.contains("MII"), "{debug}");
}

#[test]
fn an_empty_header_is_refused_and_an_existing_security_header_too() {
    let spec = HeaderSpec { username_token: None, timestamp_ttl_secs: None, saml: None, signature: None };
    let e = wsse::insert(ENVELOPE.as_bytes(), &spec, Timestamp::now()).unwrap_err().to_string();
    assert!(e.contains("would be empty"), "{e}");
    // Timestamp-only headers are allowed.
    let spec = HeaderSpec { username_token: None, timestamp_ttl_secs: Some(10), saml: None, signature: None };
    let out = String::from_utf8(wsse::insert(ENVELOPE.as_bytes(), &spec, Timestamp::now()).unwrap().body).unwrap();
    assert!(out.contains("<wsu:Timestamp") && !out.contains("UsernameToken"));
}

#[test]
fn apply_registers_the_key_as_a_secret_and_records_signature_facts() {
    let (cert, key) = ec_identity();
    let auth = ResolvedAuth::Wsse {
        username_token: false,
        username: String::new(),
        password: Zeroizing::new(String::new()),
        password_type: WssePasswordType::PasswordText,
        timestamp_ttl_secs: Some(120),
        saml_assertion: None,
        signature: Some(WsseSigning {
            cert_chain_pem: cert,
            private_key_pem: Zeroizing::new(key.clone()),
            algorithm: XmlSignatureAlgorithm::Auto,
            inclusive_prefixes: vec![],
            source_secrets: vec![Zeroizing::new("tok-SENSITIVE-p12-password".into())],
        }),
    };
    assert_eq!(auth.label(), "ws-security(X.509 signature)");
    let req = SignableRequest {
        method: "POST".into(),
        scheme: "https".into(),
        authority: "soap.example.test".into(),
        raw_path: "/ws".into(),
        raw_query: String::new(),
        headers: vec![],
        body: ENVELOPE.as_bytes().to_vec(),
    };
    let applied = anvil_auth::apply(&auth, &req, Timestamp::now()).unwrap();
    assert!(applied.secrets.contains(&key));
    assert!(applied.secrets.iter().any(|s| s == "tok-SENSITIVE-p12-password"));
    let fact = |k: &str| applied.facts.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
    assert_eq!(fact("wsse.signature.algorithm").as_deref(), Some("ECDSA-P256-SHA256"));
    assert_eq!(fact("wsse.signature.references").unwrap().split(' ').count(), 2);
    let body = String::from_utf8(applied.body.unwrap()).unwrap();
    assert_eq!(verify(&body).unwrap(), ["Timestamp", "Body"]);
    // Two sends sign fresh ids and timestamps.
    let again = String::from_utf8(anvil_auth::apply(&auth, &req, Timestamp::now()).unwrap().body.unwrap()).unwrap();
    assert_ne!(body, again);
}
