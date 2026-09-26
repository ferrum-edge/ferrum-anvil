//! Redaction of URLs, headers and text in execution evidence: encoded forms
//! of a secret are compared after percent-decoding and replaced whole, and
//! request fields marked sensitive are redacted by name and by value.

use anvil_domain::secret::REDACTED;
use anvil_engine::redact::Redactor;
use anvil_engine::vars::Resolver;

const SECRET: &str = "AUDIT/secret+with=reserved";

fn redactor() -> Redactor {
    Redactor::new(vec![SECRET.into(), "open sesame 42".into()], vec![])
}

/// True when `secret` can be read from `text` directly or after undoing up
/// to three layers of percent-encoding (with `+` read either way).
fn reveals(text: &str, secret: &str) -> bool {
    let mut layers = vec![text.to_string()];
    for _ in 0..3 {
        if layers.iter().any(|l| l.contains(secret)) {
            return true;
        }
        layers = layers
            .iter()
            .flat_map(|l| {
                [
                    percent_encoding::percent_decode_str(l).decode_utf8_lossy().into_owned(),
                    percent_encoding::percent_decode_str(&l.replace('+', " ")).decode_utf8_lossy().into_owned(),
                ]
            })
            .collect();
    }
    layers.iter().any(|l| l.contains(secret))
}

#[test]
fn every_valid_encoding_of_a_secret_query_value_is_replaced_whole() {
    let r = redactor();
    for q in [
        // Anvil's own component encoding.
        "AUDIT%2Fsecret%2Bwith%3Dreserved",
        // Lower-case hex.
        "AUDIT%2fsecret%2bwith%3dreserved",
        // Mixed case.
        "AUDIT%2fsecret%2Bwith%3Dreserved",
        // An unreserved character encoded as well.
        "%41UDIT%2Fsecret%2Bwith%3Dreserved",
        // Only some reserved characters encoded.
        "AUDIT/secret%2Bwith%3Dreserved",
        // Encoded twice.
        "AUDIT%252Fsecret%252Bwith%253Dreserved",
        // Form encoding of a value with spaces, and a mix of `+` and `%20`.
        "open+sesame+42",
        "open%20sesame+42",
    ] {
        let out = r.url(&format!("https://h/p?q={q}&page=2"));
        assert_eq!(out, format!("https://h/p?q={REDACTED}&page=2"), "{q}");
    }
}

#[test]
fn a_secret_inside_a_longer_encoded_value_is_not_recoverable() {
    let r = redactor();
    for q in ["prefix-AUDIT%2Fsecret%2Bwith%3Dreserved-suffix", "prefix-AUDIT%2fsecret%2Bwith%3dreserved-suffix"] {
        let out = r.url(&format!("https://h/p?q={q}&page=2"));
        assert!(!reveals(&out, SECRET), "{q} → {out}");
        assert!(out.ends_with("&page=2"), "{out}");
    }
}

#[test]
fn raw_secrets_are_redacted_even_where_they_split_the_query() {
    let r = Redactor::new(vec!["raw&secret=value".into()], vec![]);
    let out = r.url("https://h/p?token=raw&secret=value&page=2");
    assert!(!out.contains("raw&secret=value") && !out.contains("secret=value"), "{out}");
    assert!(out.ends_with("&page=2"), "{out}");
}

#[test]
fn encoded_secrets_in_path_query_names_and_fragment_are_replaced() {
    let r = redactor();
    let mixed = "AUDIT%2fsecret%2Bwith%3Dreserved";
    assert_eq!(r.url(&format!("https://h/users/{mixed}/items")), format!("https://h/users/{REDACTED}/items"));
    let named = r.url(&format!("https://h/p?{mixed}=1&page=2"));
    assert!(named.starts_with(&format!("https://h/p?{REDACTED}=")) && named.ends_with("&page=2"), "{named}");
    assert_eq!(r.url(&format!("https://h/p?{mixed}&page=2")), format!("https://h/p?{REDACTED}&page=2"));
    assert_eq!(r.url(&format!("https://h/p?page=2#{mixed}")), format!("https://h/p?page=2#{REDACTED}"));
}

#[test]
fn urls_without_secrets_are_unchanged() {
    let r = redactor();
    for u in ["https://h/a%20b/c?x=1+2&y=%2F&z#frag", "https://h/", "/relative/path?x=%41", "https://h:8443/p?open=sesame"] {
        assert_eq!(r.url(u), u);
    }
}

#[test]
fn canonical_encodings_are_scrubbed_from_text_and_url_headers() {
    let r = redactor();
    let sample = ["GET /x?q=AUDIT%2Fsecret%2Bwith%3Dreserved failed", "form q=open+sesame+42", "lower AUDIT%2fsecret%2bwith%3dreserved"];
    let text = r.text(&sample.join("; "));
    assert!(!text.contains("AUDIT") && !text.contains("sesame"), "{text}");
    let location = r.header("Location", "https://idp/cb?code=AUDIT%2fsecret%2Bwith%3Dreserved&state=s1");
    assert_eq!(location, format!("https://idp/cb?code={REDACTED}&state=s1"));
}

#[test]
fn fields_marked_sensitive_are_redacted_by_name_and_by_value() {
    let res = Resolver::new(vec![], None);
    res.mark_sensitive("X-Custom", "FLAGGED-LITERAL-4c1d");
    res.mark_sensitive("pin", "913");
    let r = Redactor::for_execution(&res, &["customer_ssn".to_string()]);
    assert_eq!(r.header("x-custom", "FLAGGED-LITERAL-4c1d"), REDACTED);
    assert_eq!(r.header("X-Custom", "anything"), REDACTED, "the name alone is enough");
    assert_eq!(r.url("https://h/?pin=913&page=2"), format!("https://h/?pin={REDACTED}&page=2"), "short values by name");
    assert_eq!(r.text("echo FLAGGED-LITERAL-4c1d"), format!("echo {REDACTED}"));
    assert_eq!(r.url("https://h/?customer_ssn=1"), format!("https://h/?customer_ssn={REDACTED}"), "configured names still apply");
}

#[test]
fn a_secret_split_across_path_segments_by_a_raw_slash_is_not_recoverable() {
    let r = redactor();
    // Encoded apart from the `/`: neither segment holds the whole value.
    for u in ["https://h/users/AUDIT/secret%2Bwith%3Dreserved/items?page=2", "https://h/users/AUDIT/secret%2bwith=reserved"] {
        let out = r.url(u);
        assert_eq!(out, format!("https://h/{REDACTED}"), "{u}");
        assert!(!reveals(&out, SECRET), "{u} → {out}");
    }
    let relative = r.url("/users/AUDIT/secret%2Bwith%3Dreserved");
    assert_eq!(relative, REDACTED);
}

#[test]
fn a_secret_split_across_query_parts_by_a_raw_ampersand_is_not_recoverable() {
    let secret = "raw&secret=value";
    let r = Redactor::new(vec![secret.into()], vec![]);
    for u in ["https://h:8443/p?q=raw&secret%3Dvalue&page=2", "https://h:8443/p?q=raw&secret%3dvalue#top"] {
        let out = r.url(u);
        assert_eq!(out, format!("https://h:8443/{REDACTED}"), "{u}");
        assert!(!reveals(&out, secret), "{u} → {out}");
    }
}

#[test]
fn fragment_parameters_are_redacted_by_name_and_by_value() {
    let r = redactor();
    let out = r.url("https://app/cb#access_token=eyJ.fragment.tok&state=s1&expires_in=3600");
    assert_eq!(out, format!("https://app/cb#access_token={REDACTED}&state=s1&expires_in=3600"));
    let out = r.url("https://app/cb#code=AUDIT%2fsecret%2Bwith%3Dreserved&state=s1");
    assert_eq!(out, format!("https://app/cb#code={REDACTED}&state=s1"));
    assert_eq!(r.url("https://app/docs#section-2"), "https://app/docs#section-2", "plain fragments stay readable");
}

#[test]
fn link_and_refresh_headers_are_redacted_as_urls() {
    let r = redactor();
    let link = r.header(
        "Link",
        r#"<https://h/p?page=2&access_token=eyJ.link.tok>; rel="next", <https://h/u/AUDIT%2fsecret%2Bwith%3Dreserved>; rel="prev""#,
    );
    assert_eq!(link, format!(r#"<https://h/p?page=2&access_token={REDACTED}>; rel="next", <https://h/u/{REDACTED}>; rel="prev""#));
    let refresh = r.header("Refresh", "5; url=https://h/cb?code=AUDIT%2fsecret%2Bwith%3Dreserved&state=s1");
    assert_eq!(refresh, format!("5; url=https://h/cb?code={REDACTED}&state=s1"));
    let quoted = r.header("Refresh", "0; URL='https://h/cb?token=eyJ.refresh.tok'");
    assert_eq!(quoted, format!("0; URL='https://h/cb?token={REDACTED}'"));
    assert_eq!(r.header("Refresh", "30"), "30");
}

#[test]
fn json_escaped_secrets_are_scrubbed_from_text() {
    let secret = r#"quote"and\back-9e2f"#;
    let r = Redactor::new(vec![secret.into()], vec![]);
    let rendered = serde_json::to_string(secret).unwrap();
    assert_eq!(r.text(&format!("{rendered} is not of type \"integer\"")), format!("\"{REDACTED}\" is not of type \"integer\""));
    assert_eq!(r.text(&format!("raw {secret}")), format!("raw {REDACTED}"));
}
