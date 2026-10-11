//! Store work of the async paths runs off the async runtime: a send whose
//! context waits for another caller's store transaction can be canceled
//! meanwhile, and the vault secrets a context names are looked up when it is
//! built, so the engine reads no store while it executes.

use anvil_app::exec::SendOptions;
use anvil_app::profiles::ProfileManager;
use anvil_app::{App, AppError};
use anvil_domain::Id;
use anvil_domain::auth::AuthConfig;
use anvil_domain::request::RequestSpec;
use anvil_domain::secret::{SecretRef, SensitiveValue};
use anvil_domain::settings::ProxySelection;
use anvil_domain::tls::{ProxyKind, ProxyProfile};
use anvil_storage::KdfParams;
use anvil_transport::recorder::EventCtx;
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

fn open_app(name: &str) -> (tempfile::TempDir, App) {
    let root = tempfile::tempdir().unwrap();
    let pm = ProfileManager::new(root.path());
    let (s, dek, _recovery) = pm.create_passphrase(name, "correct horse battery", KdfParams::testing()).unwrap();
    let h = anvil_storage::vault::read_header(&s.dir).unwrap();
    let app = App::open(s.dir.clone(), h, dek).unwrap();
    (root, app)
}

fn bearer(secret: &SecretRef) -> RequestSpec {
    let mut spec = RequestSpec::http("GET", "http://127.0.0.1:9/");
    spec.auth = AuthConfig::Bearer { token: SensitiveValue::Secret { secret: secret.clone() }, prefix: "Bearer".into() };
    spec
}

/// An HTTP proxy profile whose password is `password`.
fn proxy(app: &App, ws: &Id, password: &SecretRef) -> Id {
    let now = chrono::Utc::now();
    let p = ProxyProfile {
        id: Id::new(),
        workspace_id: *ws,
        name: password.label.clone(),
        kind: ProxyKind::Http,
        address: "proxy.example.invalid:3128".into(),
        username: Some("user".into()),
        password: Some(SensitiveValue::Secret { secret: password.clone() }),
        no_proxy: String::new(),
        tls_profile_id: None,
        hbone: None,
        created_at: now,
        updated_at: now,
    };
    app.save_proxy_profile(p).unwrap().id
}

#[tokio::test]
async fn a_send_waiting_on_another_callers_transaction_is_canceled_at_once() {
    let (_root, app) = open_app("cancel");
    let ws = app.create_workspace("w").unwrap();
    // Another caller's transaction holds the store until it is released.
    let (held_tx, held_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let store = Arc::clone(&app.store);
    let holder = thread::spawn(move || {
        store.atomically(|_| {
            held_tx.send(()).unwrap();
            // Bounded, so a send that never returns fails the test rather than hangs it.
            let _ = release_rx.recv_timeout(Duration::from_secs(10));
            Ok(())
        })
    });
    held_rx.recv().unwrap();

    let cancel = CancellationToken::new();
    let opts = SendOptions { record_history: true, ..Default::default() };
    let spec = RequestSpec::http("GET", "http://127.0.0.1:9/");
    let send = app.send(None, &ws.meta.id, Some(spec), opts, EventCtx::none(), cancel.clone());
    tokio::pin!(send);
    // Polled once: the send now waits for its context, which waits for the
    // store. The test's own thread is not held.
    tokio::select! {
        biased;
        _ = &mut send => panic!("the send finished while the store was held"),
        () = std::future::ready(()) => {}
    }
    cancel.cancel();
    assert!(matches!(send.await, Err(AppError::Canceled)));

    // The transaction was still open when the send returned.
    let _ = release_tx.send(());
    holder.join().unwrap().unwrap();
    assert!(app.store.list_history(None, None, 10).unwrap().is_empty(), "nothing was recorded");
}

#[test]
fn a_context_looks_up_its_workspace_secrets_when_built_and_fails_them_closed_once_locked() {
    let (_root, app) = open_app("secrets");
    let ws = app.create_workspace("mine").unwrap();
    let other = app.create_workspace("other").unwrap();
    let mine = app.set_secret(&ws.meta.id, "token", "mine-value").unwrap();
    let foreign = app.set_secret(&other.meta.id, "token", "other-value").unwrap();

    // Another workspace's secret does not resolve, as before.
    let ctx = app.build_context(None, &ws.meta.id, Some(bearer(&foreign)), &SendOptions::default()).unwrap();
    let refused = ctx.secrets.resolve(&foreign).unwrap_err();
    assert!(refused.contains("not in this workspace's vault"), "{refused}");

    let ctx = app.build_context(None, &ws.meta.id, Some(bearer(&mine)), &SendOptions::default()).unwrap();
    assert_eq!(ctx.secrets.resolve(&mine).unwrap().as_str(), "mine-value");
    // A protected edit stales even the prefetched snapshot.
    app.store.delete_secret(&mine.id).unwrap();
    assert!(ctx.secrets.resolve(&mine).unwrap_err().contains("configuration changed"));
    assert!(!app.is_locked());
    // Once the profile locks, the context's secrets fail closed.
    app.lock();
    assert_eq!(ctx.secrets.resolve(&mine).unwrap_err(), "Anvil is locked");
}

#[test]
fn a_context_looks_up_only_the_secrets_of_the_profiles_its_settings_select() {
    let (_root, app) = open_app("selected");
    let ws = app.create_workspace("w").unwrap();
    let used = app.set_secret(&ws.meta.id, "used", "used-value").unwrap();
    let unused = app.set_secret(&ws.meta.id, "unused", "unused-value").unwrap();
    let selected = proxy(&app, &ws.meta.id, &used);
    proxy(&app, &ws.meta.id, &unused);
    let mut spec = RequestSpec::http("GET", "http://127.0.0.1:9/");
    spec.settings.proxy_profile_id = Some(ProxySelection::Profile { id: selected });
    let ctx = app.build_context(None, &ws.meta.id, Some(spec), &SendOptions::default()).unwrap();
    // Only the selected proxy's password was looked up when the context was
    // built; the other profile's is looked up if it is used, and is gone by then.
    assert_eq!(ctx.secrets.resolve(&used).unwrap().as_str(), "used-value");
    app.store.delete_secret(&used.id).unwrap();
    app.store.delete_secret(&unused.id).unwrap();
    assert!(ctx.secrets.resolve(&used).unwrap_err().contains("configuration changed"));
    assert!(ctx.secrets.resolve(&unused).is_err());
}
