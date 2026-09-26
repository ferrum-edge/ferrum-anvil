//! SPIFFE Workload API client against the independent fixture server
//! (`anvil_fixtures::workload_api`) over a real Unix domain socket.
#![cfg(unix)]

use anvil_domain::workload::WorkloadEndpointSource;
use anvil_fixtures::GroundTruth;
use anvil_fixtures::workload_api::{self as fx, Mode};
use anvil_transport::workload_api::{CallError, Endpoint, EndpointAddress, WorkloadClient, resolve_endpoint_with};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

fn sock_path(tag: &str) -> PathBuf {
    static N: AtomicU32 = AtomicU32::new(0);
    std::env::temp_dir().join(format!("anvil-wl-{}-{}-{tag}.sock", std::process::id(), N.fetch_add(1, Ordering::Relaxed)))
}

fn client(uri: &str) -> WorkloadClient {
    let endpoint = resolve_endpoint_with(uri, None).unwrap();
    WorkloadClient::new(endpoint, Duration::from_secs(3))
}

fn calls(f: &fx::Fixture) -> Vec<(String, bool, Vec<String>, String)> {
    f.log
        .entries()
        .into_iter()
        .filter_map(|e| match e.event {
            GroundTruth::WorkloadApiCall { rpc, metadata, audiences, answer, .. } => Some((rpc, metadata, audiences, answer)),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn fetch_x509_svid_converts_the_chain_key_and_bundle_and_rotates_on_refetch() {
    anvil_transport::init();
    let f = fx::serve(&sock_path("x509")).await.unwrap();
    let c = client(&f.uri());
    let first = c.fetch_x509_svids().await.result.unwrap();
    assert_eq!(first.svids.len(), 1);
    let s = &first.svids[0];
    assert_eq!(s.spiffe_id, fx::WORKLOAD_ID);
    assert!(s.cert_chain_pem.starts_with("-----BEGIN CERTIFICATE-----"));
    assert!(s.private_key_pem.starts_with("-----BEGIN PRIVATE KEY-----"), "PKCS#8 as the Workload API sends it");
    assert_eq!(s.bundle_pem.len(), 1);
    assert_eq!(s.bundle_pem[0].trim(), f.ca_pem.trim(), "the SVID's trust-domain bundle");
    assert!(s.not_after > s.not_before);
    // The Debug rendering never shows the key.
    assert!(!format!("{s:?}").contains("PRIVATE KEY"));
    // Every call carried the mandatory metadata; a re-fetch mints a new SVID.
    let second = c.fetch_x509_svids().await.result.unwrap();
    assert_ne!(second.svids[0].leaf_der, s.leaf_der, "a fresh SVID (rotation) on every FetchX509SVID");
    assert_eq!(f.issued_x509(), 2);
    assert!(calls(&f).iter().all(|(rpc, md, _, answer)| rpc == "FetchX509SVID" && *md && answer == "OK"));
}

#[tokio::test]
async fn several_identities_keep_their_order_and_federated_bundles_are_listed() {
    anvil_transport::init();
    let f = fx::serve(&sock_path("multi")).await.unwrap();
    f.set_identities(&[fx::WORKLOAD_ID, fx::SECOND_ID]);
    let other = anvil_fixtures::mesh_pki::MeshPki::generate();
    f.add_federated_bundle("partner.example", &other.foreign_ca.cert);
    let got = client(&f.uri()).fetch_x509_svids().await.result.unwrap();
    assert_eq!(got.svids.iter().map(|s| s.spiffe_id.as_str()).collect::<Vec<_>>(), vec![fx::WORKLOAD_ID, fx::SECOND_ID]);
    assert_eq!(got.federated_trust_domains, vec!["partner.example".to_string()]);
}

#[tokio::test]
async fn refusals_are_typed_statuses_and_empty_answers_are_no_identity() {
    anvil_transport::init();
    let f = fx::serve(&sock_path("deny")).await.unwrap();
    let c = client(&f.uri());
    f.set_mode(Mode::Deny);
    match c.fetch_x509_svids().await.result {
        Err(CallError::Status { code: 7, message }) => assert_eq!(message, "workload attestation failed"),
        other => panic!("expected PERMISSION_DENIED, got {other:?}"),
    }
    match c.fetch_jwt_svid(&["aud".into()], None).await.result {
        Err(CallError::Status { code: 7, .. }) => {}
        other => panic!("expected PERMISSION_DENIED, got {other:?}"),
    }
    f.set_mode(Mode::NoIdentity);
    assert!(matches!(c.fetch_x509_svids().await.result, Err(CallError::NoIdentity(_))));
    assert!(matches!(c.fetch_jwt_svid(&["aud".into()], None).await.result, Err(CallError::NoIdentity(_))));
    f.set_mode(Mode::JwtUnimplemented);
    assert!(matches!(c.fetch_jwt_svid(&["aud".into()], None).await.result, Err(CallError::Status { code: 12, .. })));
    assert!(matches!(c.fetch_jwt_bundles().await.result, Err(CallError::Status { code: 12, .. })));
    assert!(c.fetch_x509_svids().await.result.is_ok(), "X.509 still served");
}

#[tokio::test]
async fn jwt_svid_for_the_requested_audiences_verifies_against_the_bundle() {
    anvil_transport::init();
    let f = fx::serve(&sock_path("jwt")).await.unwrap();
    f.set_identities(&[fx::WORKLOAD_ID, fx::SECOND_ID]);
    let c = client(&f.uri());
    let aud = vec!["spiffe://anvil.test/gw".to_string(), "api".to_string()];
    let t = c.fetch_jwt_svid(&aud, None).await.result.unwrap();
    assert_eq!(t.spiffe_id, fx::WORKLOAD_ID);
    assert!(!format!("{t:?}").contains(t.token.as_str()), "the Debug rendering never shows the token");
    let claims = anvil_auth::jwt_svid::decode(&t.token).unwrap().claims;
    assert_eq!(claims["aud"], serde_json::json!(aud));
    let bundles = c.fetch_jwt_bundles().await.result.unwrap();
    assert_eq!(bundles.keys().collect::<Vec<_>>(), vec!["anvil.test"], "spiffe:// keys normalized to the trust domain");
    assert_eq!(anvil_auth::jwt_svid::verify_signature(&t.token, &bundles["anvil.test"]).unwrap(), f.kid);
    // Selecting a held identity; an unheld one is refused by the server.
    let second = c.fetch_jwt_svid(&aud, Some(fx::SECOND_ID)).await.result.unwrap();
    assert_eq!(second.spiffe_id, fx::SECOND_ID);
    assert!(matches!(
        c.fetch_jwt_svid(&aud, Some("spiffe://anvil.test/ns/lab/sa/nobody")).await.result,
        Err(CallError::Status { code: 7, .. })
    ));
    let log = calls(&f);
    assert!(log.iter().any(|(rpc, md, a, _)| rpc == "FetchJWTSVID" && *md && *a == aud), "{log:?}");
}

#[tokio::test]
async fn missing_socket_hang_and_non_grpc_peers_fail_typed() {
    anvil_transport::init();
    // No socket at all.
    let missing = sock_path("missing");
    match client(&format!("unix://{}", missing.display())).fetch_x509_svids().await.result {
        Err(CallError::Unavailable { detail, io_error_kind }) => {
            assert!(detail.contains("no Workload API socket exists"), "{detail}");
            assert_eq!(io_error_kind.as_deref(), Some("NotFound"));
        }
        other => panic!("{other:?}"),
    }
    // An endpoint that accepts and never answers: the deadline, typed.
    let f = fx::serve(&sock_path("hang")).await.unwrap();
    f.set_mode(Mode::Hang);
    let endpoint = resolve_endpoint_with(&f.uri(), None).unwrap();
    let started = std::time::Instant::now();
    let r = WorkloadClient::new(endpoint, Duration::from_millis(400)).fetch_x509_svids().await.result;
    assert!(matches!(r, Err(CallError::Timeout { deadline_ms: 400 })), "{r:?}");
    assert!(started.elapsed() < Duration::from_secs(3));
    // A Unix socket that is not an HTTP/2 gRPC server.
    let raw = sock_path("raw");
    let l = tokio::net::UnixListener::bind(&raw).unwrap();
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            drop(s);
        }
    });
    let r = client(&format!("unix://{}", raw.display())).fetch_x509_svids().await.result;
    assert!(matches!(r, Err(CallError::Unavailable { .. })), "{r:?}");
    let _ = std::fs::remove_file(&raw);
}

#[tokio::test]
async fn a_socket_this_user_may_not_open_is_permission_denied() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    anvil_transport::init();
    let path = sock_path("perm");
    let f = fx::serve(&path).await.unwrap();
    if std::fs::metadata(&path).unwrap().uid() == 0 {
        return; // root ignores the socket's mode
    }
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
    let r = client(&f.uri()).fetch_x509_svids().await.result;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    match r {
        Err(CallError::Unavailable { detail, io_error_kind }) => {
            assert!(detail.contains("permission denied"), "{detail}");
            assert_eq!(io_error_kind.as_deref(), Some("PermissionDenied"));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn the_environment_names_the_endpoint_when_the_profile_does_not() {
    let e: Endpoint = resolve_endpoint_with("", Some("unix:///run/spire/sockets/agent.sock".into())).unwrap();
    assert_eq!(e.source, WorkloadEndpointSource::Environment);
    assert_eq!(e.address, EndpointAddress::Unix("/run/spire/sockets/agent.sock".into()));
}
