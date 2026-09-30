//! The effective-request preview shows the body the send path sends when an
//! auth profile rewrites it: a WS-Security UsernameToken request previews its
//! `wsse:Security` header block, with the password and any SAML assertion
//! redacted, and the size the fixture received.

use anvil_domain::Id;
use anvil_domain::auth::{AuthConfig, WsseConfig, WssePasswordType};
use anvil_domain::request::{Body, RequestSpec, SoapVersion};
use anvil_domain::secret::{REDACTED, SecretRef, SensitiveValue};
use anvil_engine::context::MemorySecrets;
use anvil_engine::{Engine, ExecutionContext};
use anvil_fixtures::http as fx;
use anvil_transport::recorder::EventCtx;
use std::collections::HashMap;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

const USERNAME: &str = "preview-client";
const PASSWORD: &str = "audit-only-wsse-password-4m8c";
const ENVELOPE: &str = r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body/></soap:Envelope>"#;

fn init() {
    anvil_transport::init();
    anvil_fixtures::init();
}

/// `body` up to its `wsse:Nonce` and from the end of its `wsse:UsernameToken`:
/// the parts that do not vary per send.
fn fixed_parts(body: &str) -> (&str, &str) {
    let nonce = body.find("<wsse:Nonce").unwrap_or_else(|| panic!("no wsse:Nonce in {body}"));
    let end = body.find("</wsse:UsernameToken>").unwrap_or_else(|| panic!("no wsse:UsernameToken in {body}"));
    (&body[..nonce], &body[end..])
}

#[tokio::test]
async fn preview_shows_the_ws_security_body_as_sent_with_the_password_redacted() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let mut s = RequestSpec::http("POST", &f.url("/echo"));
    s.body = Body::Soap { version: SoapVersion::Soap11, envelope: ENVELOPE.into(), action: None };
    s.auth = AuthConfig::Wsse {
        config: WsseConfig {
            username: USERNAME.into(),
            password: SensitiveValue::template(PASSWORD),
            password_type: WssePasswordType::PasswordText,
            timestamp_ttl_secs: None,
            saml_assertion: None,
        },
    };
    let c = ExecutionContext::standalone(s);

    let p = e.preview(&c).unwrap();
    assert!(!p.inferred.iter().any(|i| i.starts_with("the request would not be sent")), "{:?}", p.inferred);
    assert!(p.body_preview.contains("<soap:Header><wsse:Security"), "the preview has no Security block: {}", p.body_preview);
    assert!(p.body_preview.contains(&format!("<wsse:Username>{USERNAME}</wsse:Username>")), "{}", p.body_preview);
    assert!(p.body_preview.contains(&format!("#PasswordText\">{REDACTED}</wsse:Password>")), "{}", p.body_preview);
    let json = serde_json::to_string(&p).unwrap();
    assert!(!json.contains(PASSWORD), "the preview holds the password: {json}");

    let o = e.execute(&c, EventCtx::none(), CancellationToken::new()).await;
    assert_eq!(o.record.response.as_ref().map(|r| r.status), Some(200), "{:?}", o.record.attempts.last().and_then(|a| a.failure.as_ref()));
    let echo: serde_json::Value = serde_json::from_slice(&o.body).expect("the echo body is JSON");
    let received = echo["body"].as_str().expect("the fixture received a text body");
    assert!(received.contains("<soap:Header><wsse:Security"), "the fixture received no Security block: {received}");
    assert!(received.contains(PASSWORD), "the fixture received no password: {received}");
    assert_eq!(echo["body_len"].as_u64(), Some(p.body_bytes), "the preview's body size differs from the one sent");
    assert_eq!(received.len() as u64, p.body_bytes);
    // The same body apart from the redacted password and the per-send nonce
    // and creation time.
    let sent = received.replace(PASSWORD, REDACTED);
    assert_eq!(fixed_parts(&p.body_preview), fixed_parts(&sent));
}

/// A SAML assertion with a marker that appears nowhere else in the request.
const ASSERTION: &str = r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="audit-only-saml-7d2k"/>"#;
const ASSERTION_MARKER: &str = "audit-only-saml-7d2k";
const SOAP_DATA: &str = r#"<m:Ping xmlns:m="urn:x">visible-soap-data</m:Ping>"#;

#[tokio::test]
async fn preview_redacts_a_vault_backed_saml_assertion_and_keeps_the_soap_data() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let vault = SecretRef { id: Id::new(), label: "saml assertion".into() };
    let mut s = RequestSpec::http("POST", &f.url("/echo"));
    let envelope = ENVELOPE.replace("<soap:Body/>", &format!("<soap:Body>{SOAP_DATA}</soap:Body>"));
    s.body = Body::Soap { version: SoapVersion::Soap11, envelope, action: None };
    s.auth = AuthConfig::Wsse {
        config: WsseConfig {
            username: USERNAME.into(),
            password: SensitiveValue::template(PASSWORD),
            password_type: WssePasswordType::PasswordDigest,
            timestamp_ttl_secs: None,
            saml_assertion: Some(SensitiveValue::Secret { secret: vault.clone() }),
        },
    };
    let mut c = ExecutionContext::standalone(s);
    // Stored as pasted, with surrounding whitespace; embedded trimmed.
    c.secrets = Arc::new(MemorySecrets(HashMap::from([(vault.id, Zeroizing::new(format!("\n  {ASSERTION}\n")))])));

    let p = e.preview(&c).unwrap();
    let json = serde_json::to_string(&p).unwrap();
    assert!(!json.contains(ASSERTION_MARKER), "the preview holds the SAML assertion");
    assert!(!p.inferred.iter().any(|i| i.starts_with("the request would not be sent")), "{:?}", p.inferred);
    assert!(p.body_preview.contains("<soap:Header><wsse:Security"), "the preview has no Security block: {}", p.body_preview);
    assert!(p.body_preview.contains(&format!("{REDACTED}</wsse:Security>")), "the assertion is not redacted in place: {}", p.body_preview);
    assert!(p.body_preview.contains(&format!("<wsse:Username>{USERNAME}</wsse:Username>")), "{}", p.body_preview);
    assert!(p.body_preview.contains(SOAP_DATA), "the SOAP data is not shown: {}", p.body_preview);

    // The assertion is sent, and the fixture's echo of it is redacted in the record.
    let o = e.execute(&c, EventCtx::none(), CancellationToken::new()).await;
    assert_eq!(o.record.response.as_ref().map(|r| r.status), Some(200), "{:?}", o.record.attempts.last().and_then(|a| a.failure.as_ref()));
    let echo: serde_json::Value = serde_json::from_slice(&o.body).expect("the echo body is JSON");
    let received = echo["body"].as_str().expect("the fixture received a text body");
    assert!(received.contains(ASSERTION), "the fixture did not receive the SAML assertion");
    assert!(received.contains(SOAP_DATA), "the fixture did not receive the SOAP data");
    assert_eq!(received.len() as u64, p.body_bytes, "the preview's body size differs from the one sent");
    let record = serde_json::to_string(&o.record).unwrap();
    assert!(!record.contains(ASSERTION_MARKER), "the stored record holds the SAML assertion");
}
