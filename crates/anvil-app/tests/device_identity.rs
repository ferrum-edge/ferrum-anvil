//! A bundle import or full-backup restore seals, on this device only, every
//! workspace it writes into from this device's workload identity: its
//! requests are refused a JWT-SVID from the Workload API or a token file, and
//! a TLS profile (their own or their proxy's) presenting an X.509-SVID from
//! the Workload API, whatever the conflict policy, until the user allows it
//! here. A JWT-SVID from a vault or variable value still works, only an
//! import or a restore creates a seal, and the seal never leaves the device.

use anvil_app::exec::SendOptions;
use anvil_app::port::ImportApproval;
use anvil_app::profiles::ProfileManager;
use anvil_app::{App, AppError};
use anvil_domain::Id;
use anvil_domain::auth::AuthConfig;
use anvil_domain::request::RequestSpec;
use anvil_domain::secret::SensitiveValue;
use anvil_domain::settings::ProxySelection;
use anvil_domain::tls::{ClientIdentity, ProxyKind, ProxyProfile, TlsProfile};
use anvil_domain::workload::{JwtSvidConfig, JwtSvidSource};
use anvil_portability::ExportMode;
use anvil_portability::plan::ConflictPolicy;
use anvil_storage::{KdfParams, kind};
use std::path::Path;

const URL: &str = "https://api.example.invalid/svid";
const BACKUP_PASS: &str = "backup passphrase 1";

/// Requests that would present this device's JWT-SVID (see [`auths`]).
const DEVICE: &[&str] = &["workload api", "token file", "multi"];

fn new_app(root: &Path, name: &str) -> App {
    let pm = ProfileManager::new(root);
    let (s, dek, _recovery) = pm.create_passphrase(name, "correct horse battery", KdfParams::testing()).unwrap();
    let h = anvil_storage::vault::read_header(&s.dir).unwrap();
    App::open(s.dir, h, dek).unwrap()
}

/// The error of a refused call (an `ExecutionContext` is not `Debug`).
fn refused<T>(r: Result<T, AppError>, label: &str) -> String {
    match r {
        Ok(_) => panic!("{label}: expected a refusal"),
        Err(e) => e.to_string(),
    }
}

/// Approval to write `file` into the stored workspaces `ws`.
fn approve(file: &[u8], ws: Vec<Id>) -> ImportApproval {
    let _ = file;
    ImportApproval { existing_workspaces: ws }
}

fn jwt_svid(source: JwtSvidSource) -> AuthConfig {
    let config = JwtSvidConfig {
        source,
        audiences: vec!["spiffe://example.org/api".into()],
        endpoint: String::new(),
        spiffe_id: None,
        verify_with_bundles: false,
        send_despite_failed_checks: false,
        header_name: "Authorization".into(),
        prefix: "Bearer".into(),
    };
    AuthConfig::JwtSvid { config }
}

fn auths() -> Vec<(&'static str, AuthConfig)> {
    let file = JwtSvidSource::File { path: "/var/run/secrets/tokens/jwt_svid.token".into() };
    let value = JwtSvidSource::Value { token: SensitiveValue::Template { value: "{{jwt_svid}}".into() } };
    vec![
        ("workload api", jwt_svid(JwtSvidSource::WorkloadApi)),
        ("token file", jwt_svid(file)),
        ("multi", AuthConfig::Multi { profiles: vec![AuthConfig::None, jwt_svid(JwtSvidSource::WorkloadApi)] }),
        ("value", jwt_svid(value)),
        ("none", AuthConfig::None),
    ]
}

/// A workspace with one request for each of [`auths`].
fn source_workspace(app: &App) -> Id {
    let ws = app.create_workspace("W").unwrap();
    for (name, auth) in auths() {
        let mut spec = RequestSpec::http("GET", URL);
        spec.auth = auth;
        app.create_request(&ws.meta.id, None, name, spec).unwrap();
    }
    ws.meta.id
}

fn workload_api_draft() -> RequestSpec {
    let mut spec = RequestSpec::http("GET", URL);
    spec.auth = jwt_svid(JwtSvidSource::WorkloadApi);
    spec
}

/// Every request of `ws` that would present this device's JWT-SVID, and a
/// draft that would, is refused with how to allow it; the others build.
fn assert_sealed(app: &App, ws: &Id) {
    assert!(app.device_identity_sealed(ws).unwrap());
    let requests = app.requests(ws).unwrap();
    assert_eq!(requests.len(), auths().len());
    for r in &requests {
        let built = app.build_context(Some(r.meta.id), ws, None, &SendOptions::default());
        if DEVICE.contains(&r.name.as_str()) {
            let err = refused(built, &r.name);
            assert!(err.contains("a bundle import or backup restore wrote into"), "{}: {err}", r.name);
            assert!(err.contains(&format!("anvil workspace allow-device-identity {ws}")), "{}: {err}", r.name);
        } else {
            built.unwrap_or_else(|e| panic!("{}: {e}", r.name));
        }
    }
    let err = refused(app.build_context(None, ws, Some(workload_api_draft()), &SendOptions::default()), "draft");
    assert!(err.contains("a bundle import or backup restore wrote into"), "draft: {err}");
}

/// Every request of `ws`, and a draft, builds.
fn assert_open(app: &App, ws: &Id) {
    assert!(!app.device_identity_sealed(ws).unwrap());
    for r in app.requests(ws).unwrap() {
        app.build_context(Some(r.meta.id), ws, None, &SendOptions::default()).unwrap_or_else(|e| panic!("{}: {e}", r.name));
    }
    app.build_context(None, ws, Some(workload_api_draft()), &SendOptions::default()).unwrap_or_else(|e| panic!("draft: {e}"));
}

#[test]
fn a_bundle_import_seals_the_workspace_it_writes_until_the_user_allows_it() {
    let root = tempfile::tempdir().unwrap();
    let a = new_app(root.path(), "source");
    let ws = source_workspace(&a);
    assert_open(&a, &ws);
    let (bytes, _) = a.export(Some(&ws), ExportMode::ShareSafely, None, false).unwrap();

    let policies = [("merge", ConflictPolicy::Merge), ("replace", ConflictPolicy::Replace), ("duplicate", ConflictPolicy::Duplicate)];
    for (label, policy) in policies {
        let b = new_app(root.path(), label);
        // The preview and the report say so.
        let preview = b.import_preview(&bytes, None, policy).unwrap();
        assert!(preview.warnings.iter().any(|w| w.contains("allow-device-identity")), "{label}: {:?}", preview.warnings);
        let report = b.import(&bytes, None, policy).unwrap();
        assert!(report.warnings.iter().any(|w| w.contains("allow-device-identity")), "{label}: {:?}", report.warnings);
        let imported: Id = report.workspace_ids[0].parse().unwrap();
        assert_eq!(imported == ws, policy != ConflictPolicy::Duplicate, "{label}");
        assert_sealed(&b, &imported);

        // The user's choice on this device lifts it, once.
        assert!(b.allow_device_identity(&imported).unwrap(), "{label}");
        assert_open(&b, &imported);
        assert!(!b.allow_device_identity(&imported).unwrap(), "{label}");
    }
}

#[test]
fn an_import_seals_each_existing_workspace_it_writes_into_and_nothing_else() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path(), "own");
    let ws = source_workspace(&app);
    let (bytes, _) = app.export(Some(&ws), ExportMode::ShareSafely, None, false).unwrap();

    // A copy next to the source: only the copy is sealed.
    let report = app.import(&bytes, None, ConflictPolicy::Duplicate).unwrap();
    let copy: Id = report.workspace_ids[0].parse().unwrap();
    assert_ne!(copy, ws);
    assert_sealed(&app, &copy);
    assert_open(&app, &ws);

    // A refused import seals nothing.
    for policy in [ConflictPolicy::Merge, ConflictPolicy::Replace] {
        assert!(app.import(&bytes, None, policy).is_err());
        assert_open(&app, &ws);
    }

    // Written into with approval, even from its own export, it is sealed.
    for policy in [ConflictPolicy::Merge, ConflictPolicy::Replace] {
        app.import_approved(&bytes, None, policy, &approve(&bytes, vec![ws])).unwrap();
        assert_sealed(&app, &ws);
        assert!(app.allow_device_identity(&ws).unwrap());
        assert_open(&app, &ws);
    }
    assert_sealed(&app, &copy);
}

#[test]
fn a_seal_stays_on_this_device_and_goes_with_its_workspace() {
    let root = tempfile::tempdir().unwrap();
    let a = new_app(root.path(), "a");
    let ws = source_workspace(&a);
    let (bytes, _) = a.export(Some(&ws), ExportMode::ShareSafely, None, false).unwrap();
    let b = new_app(root.path(), "b");
    b.import(&bytes, None, ConflictPolicy::Merge).unwrap();
    assert_sealed(&b, &ws);

    // A full backup does not carry it.
    assert!(b.backup_contents().unwrap().objects.iter().all(|o| o.kind != kind::DEVICE_IDENTITY_SEAL));

    // Deleting the workspace deletes its seal; only a stored workspace is allowed.
    b.delete_workspace(&ws).unwrap();
    assert!(!b.device_identity_sealed(&ws).unwrap());
    assert!(matches!(b.allow_device_identity(&ws), Err(AppError::NotFound(_))));

    // Imported again, it is sealed again. Locked, nothing is read or lifted.
    b.import(&bytes, None, ConflictPolicy::Merge).unwrap();
    assert_sealed(&b, &ws);
    b.lock();
    assert!(matches!(b.device_identity_sealed(&ws), Err(AppError::Locked)));
    assert!(matches!(b.allow_device_identity(&ws), Err(AppError::Locked)));
}

#[test]
fn a_backup_restore_seals_every_workspace_it_writes_until_the_user_allows_it() {
    let root = tempfile::tempdir().unwrap();
    let a = new_app(root.path(), "old device");
    let ws = source_workspace(&a);
    let other = a.create_workspace("Other").unwrap().meta.id;
    let (backup, _) = a.export_backup_with(BACKUP_PASS, KdfParams::testing()).unwrap();
    // Taking a backup seals nothing where it was taken.
    assert_open(&a, &ws);

    // Restored on a new device, every workspace is sealed; the preview and
    // the report say so.
    let b = new_app(root.path(), "new device");
    let preview = b.restore_preview(&backup, Some(BACKUP_PASS), ConflictPolicy::Merge).unwrap();
    assert!(preview.warnings.iter().any(|w| w.contains("allow-device-identity")), "{:?}", preview.warnings);
    assert!(!b.device_identity_sealed(&ws).unwrap());
    let report = b.restore(&backup, Some(BACKUP_PASS), ConflictPolicy::Merge).unwrap();
    assert!(report.warnings.iter().any(|w| w.contains("allow-device-identity")), "{:?}", report.warnings);
    assert_sealed(&b, &ws);
    assert!(b.device_identity_sealed(&other).unwrap());
    // Restoring your own backup on a new device means lifting the seals.
    assert!(b.allow_device_identity(&ws).unwrap());
    assert!(b.allow_device_identity(&other).unwrap());
    assert_open(&b, &ws);

    // A refused restore seals nothing.
    assert!(b.restore(&backup, Some(BACKUP_PASS), ConflictPolicy::Replace).is_err());
    assert_open(&b, &ws);
    assert!(!b.device_identity_sealed(&other).unwrap());

    // Restored again over the workspaces it claims, with approval, they are
    // sealed again.
    for policy in [ConflictPolicy::Merge, ConflictPolicy::Replace] {
        b.restore_approved(&backup, Some(BACKUP_PASS), policy, &approve(&backup, vec![ws, other])).unwrap();
        assert_sealed(&b, &ws);
        assert!(b.device_identity_sealed(&other).unwrap());
        assert!(b.allow_device_identity(&ws).unwrap());
        assert!(b.allow_device_identity(&other).unwrap());
        assert_open(&b, &ws);
    }
}

fn tls_profile(app: &App, ws: &Id, name: &str, client_identity: Option<ClientIdentity>) -> Id {
    let now = chrono::Utc::now();
    let p = TlsProfile {
        id: Id::new(),
        workspace_id: *ws,
        name: name.into(),
        verify: true,
        use_system_roots: true,
        extra_roots_pem: vec![],
        client_identity,
        bindings: vec![],
        min_version: Default::default(),
        server_name_override: None,
        server_spiffe: None,
        created_at: now,
        updated_at: now,
    };
    app.save_tls_profile(p).unwrap().id
}

/// An HBONE proxy whose own connection uses TLS profile `tls`.
fn proxy_profile(app: &App, ws: &Id, tls: Id) -> Id {
    let now = chrono::Utc::now();
    let p = ProxyProfile {
        id: Id::new(),
        workspace_id: *ws,
        name: "mesh".into(),
        kind: ProxyKind::Hbone,
        address: "mesh.example.invalid:15008".into(),
        username: None,
        password: None,
        no_proxy: String::new(),
        tls_profile_id: Some(tls),
        hbone: None,
        created_at: now,
        updated_at: now,
    };
    app.save_proxy_profile(p).unwrap().id
}

/// A draft that selects TLS profile `tls` and proxy profile `proxy`.
fn with_profiles(tls: Option<Id>, proxy: Option<Id>) -> RequestSpec {
    let mut spec = RequestSpec::http("GET", URL);
    spec.settings.tls_profile_id = tls;
    spec.settings.proxy_profile_id = proxy.map(|id| ProxySelection::Profile { id });
    spec
}

#[test]
fn a_sealed_workspace_refuses_tls_profiles_that_present_this_devices_x509_svid() {
    let root = tempfile::tempdir().unwrap();
    let a = new_app(root.path(), "source");
    let ws = source_workspace(&a);
    let (bytes, _) = a.export(Some(&ws), ExportMode::ShareSafely, None, false).unwrap();
    let b = new_app(root.path(), "target");
    b.import(&bytes, None, ConflictPolicy::Merge).unwrap();
    assert!(b.device_identity_sealed(&ws).unwrap());

    let svid = ClientIdentity::WorkloadApi { endpoint: String::new(), spiffe_id: None, trust_bundle: false };
    let x509 = tls_profile(&b, &ws, "svid", Some(svid));
    let plain = tls_profile(&b, &ws, "plain", None);
    let (svid_proxy, plain_proxy) = (proxy_profile(&b, &ws, x509), proxy_profile(&b, &ws, plain));
    // (label, draft, whether it would present this device's X.509-SVID)
    let cases = [
        ("own profile", with_profiles(Some(x509), None), true),
        ("proxy's profile", with_profiles(None, Some(svid_proxy)), true),
        ("proxy's profile only", with_profiles(Some(plain), Some(svid_proxy)), true),
        ("no svid", with_profiles(Some(plain), Some(plain_proxy)), false),
        ("no profile", with_profiles(None, None), false),
    ];
    let build = |spec: &RequestSpec| b.build_context(None, &ws, Some(spec.clone()), &SendOptions::default());
    for (label, spec, device) in &cases {
        if *device {
            let err = refused(build(spec), label);
            assert!(err.contains("a bundle import or backup restore wrote into") && err.contains("X.509-SVID"), "{label}: {err}");
            assert!(err.contains(&format!("anvil workspace allow-device-identity {ws}")), "{label}: {err}");
        } else {
            build(spec).unwrap_or_else(|e| panic!("{label}: {e}"));
        }
    }
    // Selected for the whole workspace, it is refused to every request.
    let mut w = b.workspace(&ws).unwrap();
    w.settings.tls_profile_id = Some(x509);
    b.save_workspace(w).unwrap();
    refused(build(&with_profiles(None, None)), "workspace profile");

    // Allowed on this device, every one builds.
    assert!(b.allow_device_identity(&ws).unwrap());
    for (label, spec, _) in &cases {
        build(spec).unwrap_or_else(|e| panic!("{label}: {e}"));
    }
}
