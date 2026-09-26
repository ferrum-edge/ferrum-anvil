//! The vault lock drops the TLS/QUIC session tickets 0-RTT early data needs,
//! like pooled connections and OAuth tokens: after unlocking, the next request
//! starts from a full handshake. Real sockets, the real application services.

use anvil_app::App;
use anvil_app::exec::SendOptions;
use anvil_app::profiles::{ProfileManager, Unlock};
use anvil_domain::Id;
use anvil_domain::execution::EarlyDataNotUsed;
use anvil_domain::request::RequestSpec;
use anvil_domain::settings::{EarlyDataPolicy, HttpVersionPolicy, SettingsOverrides};
use anvil_domain::tls::{TlsMinVersion, TlsProfile};
use anvil_fixtures::early_data::{self, EarlyMode};
use anvil_fixtures::{LabPki, TlsServerOptions};
use anvil_storage::KdfParams;
use anvil_transport::recorder::EventCtx;
use tokio_util::sync::CancellationToken;

const PASS: &str = "early-lock-passphrase";

/// A GET over forced HTTP/3 with early data on and connection reuse off.
async fn send(app: &App, ws: &Id, url: &str) -> anvil_engine::ExecutionOutput {
    let opts = SendOptions {
        run_override: Some(SettingsOverrides {
            http_version: Some(HttpVersionPolicy::Http3Only),
            keepalive: Some(false),
            early_data: Some(EarlyDataPolicy { enabled: true, extra_methods: vec![] }),
            ..Default::default()
        }),
        ..Default::default()
    };
    app.send(None, ws, Some(RequestSpec::http("GET", url)), opts, EventCtx::none(), CancellationToken::new()).await.unwrap()
}

#[tokio::test]
async fn the_vault_lock_drops_every_session_ticket() {
    anvil_fixtures::init();
    let pki = LabPki::generate();
    let fx = early_data::serve_h3(
        "127.0.0.1:0",
        TlsServerOptions::new(pki.server.chain_with(&pki.ca), pki.server.key.clone()),
        EarlyMode::Accept,
    )
    .await
    .unwrap();
    let root = tempfile::tempdir().unwrap();
    let pm = ProfileManager::new(root.path());
    let (s, dek, _) = pm.create_passphrase("early", PASS, KdfParams::testing()).unwrap();
    let h = anvil_storage::vault::read_header(&s.dir).unwrap();
    let app = App::open(s.dir.clone(), h, dek).unwrap();
    let mut ws = app.create_workspace("Edge").unwrap();
    let tls = app
        .save_tls_profile(TlsProfile {
            id: Id::new(),
            workspace_id: ws.meta.id,
            name: "lab".into(),
            verify: true,
            use_system_roots: false,
            extra_roots_pem: vec![pki.ca.cert.clone()],
            client_identity: None,
            bindings: vec![],
            min_version: TlsMinVersion::Tls12,
            server_name_override: None,
            server_spiffe: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        })
        .unwrap();
    ws.settings.tls_profile_id = Some(tls.id);
    app.save_workspace(ws.clone()).unwrap();
    let url = fx.url("/echo");

    send(&app, &ws.meta.id, &url).await;
    assert!(app.engine.session_tickets_held() >= 1, "the first request stored tickets");
    let o = send(&app, &ws.meta.id, &url).await;
    assert_eq!(o.record.attempts[0].early_data.as_ref().map(|e| e.accepted), Some(Some(true)), "a ticket makes the second request 0-RTT");

    app.lock();
    assert_eq!(app.engine.session_tickets_held(), 0, "the lock dropped every ticket");
    let (_, dek) = ProfileManager::unlock(&s.dir, Unlock::Passphrase(PASS)).unwrap();
    app.unlock(dek).unwrap();
    let o = send(&app, &ws.meta.id, &url).await;
    let ed = o.record.attempts[0].early_data.clone().expect("evidence");
    assert_eq!(ed.not_used, Some(EarlyDataNotUsed::NoTicket), "after the lock the next request starts from a full handshake");
    assert!(!ed.resumption_attempted);
    assert_eq!(fx.requests().iter().map(|r| r.0).collect::<Vec<_>>(), vec![false, true, false]);
}
