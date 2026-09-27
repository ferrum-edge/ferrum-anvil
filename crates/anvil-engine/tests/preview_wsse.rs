//! The effective-request preview shows the body the send path sends when an
//! auth profile rewrites it: a WS-Security UsernameToken request previews its
//! `wsse:Security` header block, with the password redacted, and the size the
//! fixture received.

use anvil_domain::auth::{AuthConfig, WsseConfig, WssePasswordType};
use anvil_domain::request::{Body, RequestSpec, SoapVersion};
use anvil_domain::secret::{REDACTED, SensitiveValue};
use anvil_engine::{Engine, ExecutionContext};
use anvil_fixtures::http as fx;
use anvil_transport::recorder::EventCtx;
use tokio_util::sync::CancellationToken;

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
