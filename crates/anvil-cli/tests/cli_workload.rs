//! `anvil workload probe` end to end: the real binary against the SPIFFE
//! Workload API fixture on a Unix socket. Nothing secret is printed.
#![cfg(unix)]

use anvil_fixtures::workload_api::{self as wl, Mode};
use std::process::Output;

async fn anvil(args: &[&str], env_socket: Option<&str>) -> Output {
    let mut c = tokio::process::Command::new(env!("CARGO_BIN_EXE_anvil"));
    c.args(args).env_remove("SPIFFE_ENDPOINT_SOCKET");
    if let Some(s) = env_socket {
        c.env("SPIFFE_ENDPOINT_SOCKET", s);
    }
    c.output().await.unwrap()
}

#[tokio::test]
async fn probe_reports_what_the_workload_api_issues_without_secrets() {
    anvil_fixtures::init();
    let path = std::env::temp_dir().join(format!("anvil-cli-wl-{}.sock", std::process::id()));
    let f = wl::serve(&path).await.unwrap();
    // The endpoint from SPIFFE_ENDPOINT_SOCKET, a JWT-SVID for one audience.
    let out = anvil(&["workload", "probe", "--audience", "spiffe://anvil.test/api", "--json"], Some(&f.uri())).await;
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let text = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["endpoint"], f.uri());
    assert_eq!(v["endpoint_source"], "environment");
    assert_eq!(v["x509_svids"][0]["spiffe_id"], wl::WORKLOAD_ID);
    assert_eq!(v["jwt_bundles"][0]["trust_domain"], "anvil.test");
    assert_eq!(v["jwt_bundles"][0]["key_ids"][0], f.kid);
    assert_eq!(v["jwt_svid"]["subject"], wl::WORKLOAD_ID);
    assert!(v["jwt_svid"]["checks"].as_array().unwrap().iter().all(|c| c["result"] == "passed"), "{text}");
    assert!(!text.contains("PRIVATE KEY") && !text.contains("eyJ"), "no key or token is printed");

    // Refused: exit status 2, the status and this process's uid in the text.
    f.set_mode(Mode::Deny);
    let out = anvil(&["workload", "probe", "--endpoint", &f.uri()], None).await;
    assert_eq!(out.status.code(), Some(2));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("PERMISSION_DENIED") && text.contains("uid"), "{text}");

    // No endpoint at all: nothing is dialed.
    let out = anvil(&["workload", "probe"], None).await;
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stdout).contains("SPIFFE_ENDPOINT_SOCKET"));
}
