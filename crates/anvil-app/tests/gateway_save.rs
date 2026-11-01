//! `App::save_gateway_unless_covered` (what `anvil send --save-trust` uses):
//! a profile is saved only when no saved profile covers its host on every
//! port, and concurrent saves for one host leave exactly one profile.

use anvil_app::App;
use anvil_app::profiles::ProfileManager;
use anvil_app::workspace::GatewaySave;
use anvil_domain::Id;
use anvil_domain::integration::{IntegrationKind, IntegrationProfile};
use anvil_domain::tls::HostBinding;
use anvil_storage::KdfParams;
use std::sync::{Arc, Barrier};

fn new_app(root: &std::path::Path) -> App {
    let pm = ProfileManager::new(root);
    let (s, dek, _recovery) = pm.create_passphrase("gateways", "correct horse battery", KdfParams::testing()).unwrap();
    let h = anvil_storage::vault::read_header(&s.dir).unwrap();
    App::open(s.dir, h, dek).unwrap()
}

fn gateway(ws: Id, host: &str, port: Option<u16>) -> IntegrationProfile {
    let now = chrono::Utc::now();
    IntegrationProfile {
        id: Id::new(),
        workspace_id: ws,
        name: format!("Ferrum gateway {host}"),
        kind: IntegrationKind::FerrumGateway {
            hosts: vec![HostBinding { host: host.into(), port }],
            compatibility_id: anvil_diagnostics::ferrum::DEFAULT_COMPATIBILITY_ID.into(),
            require_verified_tls: false,
            detail: None,
            console_url: None,
        },
        created_at: now,
        updated_at: now,
    }
}

#[test]
fn a_covered_host_saves_nothing() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let ws = app.create_workspace("W").unwrap().meta.id;
    let wildcard = app.save_integration(gateway(ws, "*.Example.com", None)).unwrap();
    let ported = app.save_integration(gateway(ws, "other.example.org", Some(8443))).unwrap();

    // Covered as the engine matches hosts: a wildcard, case ignored.
    match app.save_gateway_unless_covered(gateway(ws, "gw.example.com", None), "gw.example.com").unwrap() {
        GatewaySave::Covered(c) => assert_eq!(c.id, wildcard.id),
        GatewaySave::Saved(p) => panic!("saved {p:?} next to a covering profile"),
    }
    // A profile bound to one port does not cover the host on every port.
    match app.save_gateway_unless_covered(gateway(ws, "other.example.org", None), "other.example.org").unwrap() {
        GatewaySave::Saved(p) => assert_ne!(p.id, ported.id),
        GatewaySave::Covered(c) => panic!("{c:?} is bound to port 8443 only"),
    }
    assert_eq!(app.integrations(&ws).unwrap().len(), 3);
}

#[test]
fn concurrent_saves_for_one_host_leave_one_profile() {
    const SAVERS: usize = 8;
    let root = tempfile::tempdir().unwrap();
    let app = Arc::new(new_app(root.path()));
    let ws = app.create_workspace("W").unwrap().meta.id;
    let start = Arc::new(Barrier::new(SAVERS));
    let savers: Vec<_> = (0..SAVERS)
        .map(|_| {
            let (app, start) = (app.clone(), start.clone());
            std::thread::spawn(move || {
                start.wait();
                matches!(
                    app.save_gateway_unless_covered(gateway(ws, "gw.example.com", None), "gw.example.com").unwrap(),
                    GatewaySave::Saved(_)
                )
            })
        })
        .collect();
    let saved = savers.into_iter().map(|t| t.join().unwrap()).filter(|s| *s).count();
    assert_eq!(saved, 1);
    assert_eq!(app.integrations(&ws).unwrap().len(), 1);
}
