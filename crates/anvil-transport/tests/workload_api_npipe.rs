//! SPIFFE Workload API over a Windows named pipe (`npipe:<name>`, SPIRE's
//! transport on Windows) against the fixture's named-pipe server. Windows only.
#![cfg(windows)]

use anvil_fixtures::workload_api as fx;
use anvil_transport::workload_api::{EndpointAddress, EndpointError, WorkloadClient, resolve_endpoint_with};
use std::time::Duration;

#[tokio::test]
async fn named_pipe_endpoints_fetch_svids_on_windows() {
    anvil_transport::init();
    let name = format!("anvil-wl-test-{}", std::process::id());
    let f = fx::serve_named_pipe(&name).await.unwrap();
    let endpoint = resolve_endpoint_with(&f.uri(), None).unwrap();
    assert_eq!(endpoint.address, EndpointAddress::NamedPipe(format!(r"\\.\pipe\{name}")));
    let c = WorkloadClient::new(endpoint, Duration::from_secs(5));
    let x = c.fetch_x509_svids().await.result.unwrap();
    assert_eq!(x.svids[0].spiffe_id, fx::WORKLOAD_ID);
    assert!(x.svids[0].private_key_pem.starts_with("-----BEGIN PRIVATE KEY-----"));
    let t = c.fetch_jwt_svid(&["spiffe://anvil.test/api".to_string()], None).await.result.unwrap();
    assert_eq!(t.spiffe_id, fx::WORKLOAD_ID);
    // Unix domain socket endpoints are refused on Windows, before any dial.
    assert!(matches!(resolve_endpoint_with("unix:///run/spire/sockets/agent.sock", None), Err(EndpointError::Unsupported(_))));
}
