//! Target parsing keeps an explicitly written port for raw TCP/UDP/TLS/DTLS
//! schemes, even when it equals the default of the special scheme used to
//! parse the authority, and still rejects raw targets with no port at all.

use anvil_domain::execution::{FailureKind, Phase};
use anvil_engine::prepare::{Target, parse_target};

const RAW_SCHEMES: &[&str] = &["tcp", "udp", "tls", "dtls"];

fn parse(raw: &str, allowed: &[&str]) -> Target {
    let mut inferred = Vec::new();
    match parse_target(raw, allowed, &mut inferred) {
        Ok(t) => t,
        Err(e) => panic!("{raw} should parse: {e:?}"),
    }
}

#[test]
fn raw_schemes_keep_explicit_port_80_and_443() {
    for scheme in RAW_SCHEMES {
        for port in [80u16, 443] {
            for (authority, host) in [
                (format!("127.0.0.1:{port}"), "127.0.0.1"),
                (format!("gateway.example.test:{port}"), "gateway.example.test"),
                (format!("[::1]:{port}"), "::1"),
            ] {
                let raw = format!("{scheme}://{authority}");
                let t = parse(&raw, &[scheme]);
                assert_eq!(t.scheme, *scheme, "{raw}");
                assert_eq!(t.host, host, "{raw}");
                assert_eq!(t.port, port, "{raw}");
                assert_eq!(t.authority, authority, "{raw}");
            }
        }
    }
}

#[test]
fn raw_schemes_keep_non_default_ports() {
    for scheme in RAW_SCHEMES {
        for port in [8080u16, 8443] {
            let raw = format!("{scheme}://127.0.0.1:{port}");
            let t = parse(&raw, &[scheme]);
            assert_eq!(t.port, port, "{raw}");
            assert_eq!(t.authority, format!("127.0.0.1:{port}"), "{raw}");
        }
    }
}

#[test]
fn raw_schemes_still_reject_an_omitted_port() {
    for scheme in RAW_SCHEMES {
        for authority in ["127.0.0.1", "gateway.example.test", "[::1]", "127.0.0.1:"] {
            let raw = format!("{scheme}://{authority}");
            let mut inferred = Vec::new();
            let err = match parse_target(&raw, &[scheme], &mut inferred) {
                Ok(t) => panic!("{raw} must be rejected without a port, got {t:?}"),
                Err(e) => e,
            };
            assert_eq!(err.phase, Phase::Prepare, "{raw}");
            assert_eq!(err.kind, FailureKind::InvalidUrl, "{raw}");
            assert!(err.message.contains("explicit port"), "{raw}: {}", err.message);
        }
    }
}

#[test]
fn http_and_https_default_ports_are_unchanged() {
    let cases: &[(&str, u16, &str)] = &[
        ("http://127.0.0.1", 80, "127.0.0.1"),
        ("http://127.0.0.1:80", 80, "127.0.0.1"),
        ("http://127.0.0.1:443", 443, "127.0.0.1:443"),
        ("https://gateway.example.test", 443, "gateway.example.test"),
        ("https://gateway.example.test:443", 443, "gateway.example.test"),
        ("https://gateway.example.test:80", 80, "gateway.example.test:80"),
        ("https://[::1]:443", 443, "[::1]"),
        ("http://[::1]:8080", 8080, "[::1]:8080"),
    ];
    for (raw, port, authority) in cases {
        let t = parse(raw, &["http", "https"]);
        assert_eq!(t.port, *port, "{raw}");
        assert_eq!(t.authority, *authority, "{raw}");
    }
}
