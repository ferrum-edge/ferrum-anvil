//! Desktop file access goes only through grants recorded when the user picks
//! a file in a native dialog: a path, a made-up token, a grant for another
//! purpose, an expired or revoked grant, or a file swapped after it was
//! chosen never reaches the disk.

use anvil_app::App;
use anvil_app::file_grants::{Access, FileGrants, FilePurpose, GrantError, MAX_GRANTS};
use anvil_app::profiles::ProfileManager;
use anvil_domain::Id;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[cfg(unix)]
mod fifo;
#[cfg(unix)]
use fifo::{mkfifo, within_seconds};

fn file(dir: &Path, name: &str, contents: &[u8]) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, contents).unwrap();
    p
}

fn canonical_pem(pem: &str) -> Vec<u8> {
    let mut canonical = String::new();
    for line in pem.lines() {
        canonical.push_str(line.trim().trim_start_matches('\u{feff}'));
        canonical.push('\n');
    }
    canonical.into_bytes()
}

fn partial_files(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".partial"))
        .collect()
}

fn vault(root: &Path) -> (App, Id) {
    let profiles = ProfileManager::new(root);
    let (profile, key, _) = profiles.create_passphrase("PEM", "test passphrase", anvil_storage::KdfParams::testing()).unwrap();
    let header = anvil_storage::vault::read_header(&profile.dir).unwrap();
    let app = App::open(profile.dir, header, key).unwrap();
    let workspace = app.create_workspace("keys").unwrap().meta.id;
    (app, workspace)
}

#[test]
fn private_key_grants_never_return_bytes_and_cannot_change_purpose() {
    let root = tempfile::tempdir().unwrap();
    let (app, workspace) = vault(root.path());
    let key = anvil_fixtures::LabPki::generate().client_a.key;
    let path = file(root.path(), "key.pem", key.as_bytes());
    let grants = FileGrants::default();
    for purpose in [
        FilePurpose::PemCertificate,
        FilePurpose::Pkcs12File,
        FilePurpose::Attachment,
        FilePurpose::BundleImport,
        FilePurpose::SpecSource,
        FilePurpose::Dataset,
        FilePurpose::Ruleset,
    ] {
        let grant = grants.grant_private_key(&app, &path).unwrap();
        assert_eq!(grants.read(&grant.token, purpose).unwrap_err(), GrantError::WrongPurpose);
        assert!(grants.import_private_key(&app, &grant.token, &workspace, "key").is_err());
    }
    let grant = grants.grant_private_key(&app, &path).unwrap();
    assert_eq!(grants.read(&grant.token, FilePurpose::PemPrivateKey).unwrap_err(), GrantError::WrongPurpose,);
    assert!(app.store.list_secret_ids(Some(&workspace)).unwrap().is_empty());
}

#[test]
fn a_private_key_is_ingested_once_as_a_reference_and_still_prepares_tls() {
    let root = tempfile::tempdir().unwrap();
    let (app, workspace) = vault(root.path());
    let pki = anvil_fixtures::LabPki::generate();
    let path = file(root.path(), "key.pem", pki.client_a.key.as_bytes());
    let grants = FileGrants::default();
    let grant = grants.grant_private_key(&app, &path).unwrap();
    let secret = grants.import_private_key(&app, &grant.token, &workspace, "key").unwrap();
    let returned = serde_json::to_value(&secret).unwrap();
    assert_eq!(returned, serde_json::json!({ "id": secret.id, "label": "key" }));
    assert!(!returned.to_string().contains("PRIVATE KEY"));
    assert!(grants.is_empty());
    assert!(grants.import_private_key(&app, &grant.token, &workspace, "again").is_err());
    assert_eq!(grants.read(&grant.token, FilePurpose::PemCertificate).unwrap_err(), GrantError::Unknown,);
    let (_, stored) = app.store.get_workspace_secret(&secret.id, &workspace).unwrap().unwrap();
    assert_eq!(&*stored, &pki.client_a.key);
    let settings = anvil_transport::tls::TlsSettings {
        verify: true,
        extra_roots_pem: vec![pki.ca.cert],
        client_identity: Some(anvil_transport::tls::ClientIdentityMaterial {
            cert_chain_pem: pki.client_a.chain_with(&pki.client_ca),
            private_key_pem: stored,
        }),
        ..Default::default()
    };
    assert!(anvil_transport::tls::prepare(&settings).is_ok());
}

#[test]
fn concurrent_private_key_ingestion_spends_the_grant_atomically() {
    use std::sync::{Arc, Barrier};
    let root = tempfile::tempdir().unwrap();
    let (app, workspace) = vault(root.path());
    let app = Arc::new(app);
    let path = file(root.path(), "key.pem", b"vault-only canary");
    let grants = Arc::new(FileGrants::default());
    let grant = grants.grant_private_key(&app, &path).unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let workers: Vec<_> = (0..2)
        .map(|_| {
            let (app, grants, barrier) = (app.clone(), grants.clone(), barrier.clone());
            let token = grant.token.clone();
            std::thread::spawn(move || {
                barrier.wait();
                grants.import_private_key(&app, &token, &workspace, "key")
            })
        })
        .collect();
    let successes = workers.into_iter().map(|worker| worker.join().unwrap()).filter(Result::is_ok).count();
    assert_eq!(successes, 1);
    assert_eq!(app.store.list_secret_ids(Some(&workspace)).unwrap().len(), 1);
    assert!(grants.is_empty());
}

#[test]
fn failed_private_key_ingestion_cannot_be_replayed() {
    let root = tempfile::tempdir().unwrap();
    let (app, workspace) = vault(root.path());
    let grants = FileGrants::default();
    for contents in [vec![0xff], vec![b'x'; 1024 * 1024 + 1]] {
        let path = file(root.path(), "key.pem", &contents);
        let grant = grants.grant_private_key(&app, &path).unwrap();
        assert!(grants.import_private_key(&app, &grant.token, &workspace, "key").is_err());
        assert!(grants.is_empty());
        assert!(grants.import_private_key(&app, &grant.token, &workspace, "again").is_err());
    }
    let path = file(root.path(), "key.pem", b"vault-only canary");
    let grant = grants.grant_private_key(&app, &path).unwrap();
    assert!(grants.import_private_key(&app, &grant.token, &Id::new(), "missing").is_err());
    assert!(grants.is_empty());
    let grant = grants.grant_private_key(&app, &path).unwrap();
    let swap = file(root.path(), "swap", b"different file");
    std::fs::rename(swap, &path).unwrap();
    assert!(grants.import_private_key(&app, &grant.token, &workspace, "changed").is_err());
    assert!(grants.is_empty());
    assert!(app.store.list_secret_ids(Some(&workspace)).unwrap().is_empty());
}

#[test]
fn private_key_grants_keep_expiry_lock_and_dialog_generation_controls() {
    let root = tempfile::tempdir().unwrap();
    let (app, workspace) = vault(root.path());
    let path = file(root.path(), "key.pem", b"vault-only canary");
    let expired = FileGrants::new(Duration::ZERO);
    let grant = expired.grant_private_key(&app, &path).unwrap();
    assert!(expired.import_private_key(&app, &grant.token, &workspace, "expired").is_err());
    let grants = FileGrants::default();
    let generation = grants.generation();
    let grant = grants.grant_private_key(&app, &path).unwrap();
    grants.revoke_all();
    assert!(grants.import_private_key(&app, &grant.token, &workspace, "revoked").is_err());
    assert_eq!(grants.grant_private_key_at(&app, &path, generation).unwrap_err(), GrantError::Revoked,);
    assert!(grants.is_empty());
    assert!(app.store.list_secret_ids(Some(&workspace)).unwrap().is_empty());
}

#[test]
fn private_key_grants_require_the_issuing_vault_even_before_revocation() {
    let root = tempfile::tempdir().unwrap();
    let (a, a_workspace) = vault(root.path());
    let (b, b_workspace) = vault(root.path());
    let path = file(root.path(), "key.pem", b"vault-only canary");
    let grants = FileGrants::default();
    assert_eq!(grants.grant_read(FilePurpose::PemPrivateKey, &path).unwrap_err(), GrantError::WrongPurpose,);
    assert_eq!(grants.grant_read_at(FilePurpose::PemPrivateKey, &path, grants.generation()).unwrap_err(), GrantError::WrongPurpose,);
    let grant = grants.grant_private_key(&a, &path).unwrap();
    assert!(grants.import_private_key(&b, &grant.token, &b_workspace, "wrong").is_err());
    assert!(grants.is_empty(), "a wrong-vault claim is also spent");
    assert!(grants.import_private_key(&a, &grant.token, &a_workspace, "replay").is_err());
    assert!(a.store.list_secret_ids(None).unwrap().is_empty());
    assert!(b.store.list_secret_ids(None).unwrap().is_empty());
}

#[test]
fn a_claim_read_before_revocation_cannot_write_after_the_vault_reopens() {
    let root = tempfile::tempdir().unwrap();
    let (app, workspace) = vault(root.path());
    let path = file(root.path(), "key.pem", b"vault-only canary");
    let grants = FileGrants::default();
    let grant = grants.grant_private_key(&app, &path).unwrap();
    let claim = grants.claim_private_key(&app, &grant.token).unwrap();
    assert!(grants.is_empty());
    grants.revoke_all();
    app.lock();
    let (_, key) = ProfileManager::unlock(&app.dir, anvil_app::profiles::Unlock::Passphrase("test passphrase")).unwrap();
    app.unlock(key).unwrap();
    assert!(matches!(claim.store(&workspace, "abandoned", || true), Err(anvil_app::AppError::Locked),));
    assert!(app.store.list_secret_ids(None).unwrap().is_empty());
    assert!(grants.import_private_key(&app, &grant.token, &workspace, "replay").is_err());
}

#[test]
fn certificate_reads_refuse_private_keys_mixed_pem_and_relabelled_keys() {
    let root = tempfile::tempdir().unwrap();
    let pki = anvil_fixtures::LabPki::generate();
    let grants = FileGrants::default();
    let relabelled = pki.client_a.key.replace("PRIVATE KEY", "CERTIFICATE");
    let mut refused = vec![
        pki.client_a.key.clone(),
        format!("{}{}", pki.ca.cert, pki.client_a.key),
        format!("{}{}", pki.client_a.key, pki.ca.cert),
        relabelled,
        "-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n".into(),
        format!("{}-----BEGIN CERTIFICATE-----\n", pki.ca.cert),
    ];
    for label in ["RSA PRIVATE KEY", "EC PRIVATE KEY", "ENCRYPTED PRIVATE KEY", "OPENSSH PRIVATE KEY"] {
        refused.push(format!("{}-----BEGIN {label}-----\ncanary\n-----END {label}-----\n", pki.ca.cert,));
    }
    for contents in refused {
        let path = file(root.path(), "cert.pem", contents.as_bytes());
        let grant = grants.grant_read(FilePurpose::PemCertificate, &path).unwrap();
        let error = grants.read(&grant.token, FilePurpose::PemCertificate).unwrap_err();
        assert!(matches!(error, GrantError::Invalid(_)));
        assert!(!error.to_string().contains("canary"));
        assert!(!error.to_string().contains(&pki.client_a.key));
    }
}

#[test]
fn certificate_chains_are_readable_but_comments_and_vault_disposition_are_not() {
    let root = tempfile::tempdir().unwrap();
    let (app, workspace) = vault(root.path());
    let pki = anvil_fixtures::LabPki::generate();
    let chain = pki.client_a.chain_with(&pki.client_ca);
    let contents = format!("comment canary\n{chain}\ntrailing canary\n").replace('\n', "\r\n");
    let path = file(root.path(), "cert.pem", contents.as_bytes());
    assert_eq!(std::fs::read(&path).unwrap(), contents.as_bytes());
    let grants = FileGrants::default();
    let grant = grants.grant_read(FilePurpose::PemCertificate, &path).unwrap();
    let expected = canonical_pem(&chain);
    for _ in 0..2 {
        let returned = grants.read(&grant.token, FilePurpose::PemCertificate).unwrap();
        assert_eq!(returned.bytes, expected);
    }
    assert!(grants.import_private_key(&app, &grant.token, &workspace, "confused").is_err());
    assert!(grants.is_empty());
    assert!(app.store.list_secret_ids(Some(&workspace)).unwrap().is_empty());
}

#[test]
fn a_read_grant_reads_the_chosen_file_and_can_be_reused() {
    let dir = tempfile::tempdir().unwrap();
    let pem = anvil_fixtures::LabPki::generate().ca.cert;
    let path = file(dir.path(), "cert.pem", pem.as_bytes());
    let expected = canonical_pem(&pem);
    let grants = FileGrants::default();
    let g = grants.grant_read(FilePurpose::PemCertificate, &path).unwrap();
    assert_eq!(g.file_name, "cert.pem");
    // Opaque: the token does not carry the path or the name.
    assert!(!g.token.contains("cert"), "{}", g.token);
    assert!(!g.token.contains(&*dir.path().to_string_lossy()), "{}", g.token);
    // Preview then apply read the same selection.
    for _ in 0..2 {
        let f = grants.read(&g.token, FilePurpose::PemCertificate).unwrap();
        assert_eq!(f.bytes, expected);
        assert_eq!(f.file_name, "cert.pem");
    }
    let again = grants.grant_read(FilePurpose::PemCertificate, &path).unwrap();
    assert_ne!(again.token, g.token, "every selection gets a fresh token");
}

#[test]
fn a_path_or_a_made_up_token_is_never_read() {
    let dir = tempfile::tempdir().unwrap();
    let path = file(dir.path(), "secret.txt", b"not for the webview");
    let grants = FileGrants::default();
    // A real grant exists for another file; it must not help.
    let other = file(dir.path(), "chosen.txt", b"chosen");
    grants.grant_read(FilePurpose::PemCertificate, &other).unwrap();
    let canonical = std::fs::canonicalize(&path).unwrap();
    for token in [
        path.to_string_lossy().into_owned(),
        canonical.to_string_lossy().into_owned(),
        "secret.txt".to_string(),
        format!("fg-{}", "0".repeat(32)),
        String::new(),
    ] {
        for purpose in [FilePurpose::PemCertificate, FilePurpose::Pkcs12File, FilePurpose::Attachment, FilePurpose::BundleImport] {
            assert_eq!(grants.read(&token, purpose).unwrap_err(), GrantError::Unknown, "{token}");
        }
    }
}

#[test]
fn a_path_or_a_made_up_token_is_never_written() {
    let dir = tempfile::tempdir().unwrap();
    let existing = file(dir.path(), "keep.txt", b"original");
    let fresh = dir.path().join("new.anvil");
    let grants = FileGrants::default();
    for target in [&existing, &fresh] {
        let token = target.to_string_lossy().into_owned();
        for purpose in
            [FilePurpose::BundleExport, FilePurpose::LoadReportExport, FilePurpose::RunReportExport, FilePurpose::LintReportExport]
        {
            assert_eq!(grants.write(&token, purpose, b"bundle").unwrap_err(), GrantError::Unknown);
        }
    }
    assert_eq!(std::fs::read(&existing).unwrap(), b"original");
    assert!(!fresh.exists());
    assert!(partial_files(dir.path()).is_empty());
}

#[test]
fn a_grant_serves_only_the_purpose_it_was_chosen_for() {
    let dir = tempfile::tempdir().unwrap();
    let path = file(dir.path(), "key.pem", b"private");
    let grants = FileGrants::default();
    let g = grants.grant_read(FilePurpose::Pkcs12File, &path).unwrap();
    assert_eq!(grants.read(&g.token, FilePurpose::PemCertificate).unwrap_err(), GrantError::WrongPurpose,);
    // Misuse revokes the grant.
    assert_eq!(grants.read(&g.token, FilePurpose::Pkcs12File).unwrap_err(), GrantError::Unknown);

    // A read grant never becomes a write destination.
    let g = grants.grant_read(FilePurpose::Attachment, &path).unwrap();
    assert_eq!(grants.write(&g.token, FilePurpose::BundleExport, b"overwrite").unwrap_err(), GrantError::WrongPurpose);
    assert_eq!(grants.write(&g.token, FilePurpose::Attachment, b"overwrite").unwrap_err(), GrantError::WrongPurpose);
    assert_eq!(std::fs::read(&path).unwrap(), b"private");

    // A write grant never reads its destination back.
    let g = grants.grant_write(FilePurpose::BundleExport, &path).unwrap();
    assert_eq!(grants.read(&g.token, FilePurpose::BundleImport).unwrap_err(), GrantError::WrongPurpose);
    assert_eq!(grants.read(&g.token, FilePurpose::BundleExport).unwrap_err(), GrantError::WrongPurpose);

    // One export kind's destination is not another's.
    let g = grants.grant_write(FilePurpose::RunReportExport, &path).unwrap();
    assert_eq!(grants.write(&g.token, FilePurpose::BundleExport, b"x").unwrap_err(), GrantError::WrongPurpose);
    assert_eq!(std::fs::read(&path).unwrap(), b"private");
}

#[test]
fn grants_are_issued_only_for_the_matching_dialog_kind_and_absolute_files() {
    let dir = tempfile::tempdir().unwrap();
    let path = file(dir.path(), "a.json", b"{}");
    let grants = FileGrants::default();
    assert_eq!(grants.grant_read(FilePurpose::BundleExport, &path).unwrap_err(), GrantError::WrongPurpose);
    assert_eq!(grants.grant_write(FilePurpose::BundleImport, &path).unwrap_err(), GrantError::WrongPurpose);
    assert!(matches!(grants.grant_read(FilePurpose::Dataset, Path::new("a.json")), Err(GrantError::Invalid(_))));
    assert!(matches!(grants.grant_write(FilePurpose::BundleExport, Path::new("out.anvil")), Err(GrantError::Invalid(_))));
    assert!(matches!(grants.grant_read(FilePurpose::Dataset, dir.path()), Err(GrantError::Invalid(_))));
    assert!(matches!(grants.grant_write(FilePurpose::BundleExport, dir.path()), Err(GrantError::Invalid(_))));
    assert!(grants.is_empty());
}

#[test]
fn reads_are_bounded_per_purpose() {
    let dir = tempfile::tempdir().unwrap();
    let path = file(dir.path(), "big.pem", &vec![b'a'; 1024 * 1024 + 1]);
    let grants = FileGrants::default();
    let g = grants.grant_read(FilePurpose::PemCertificate, &path).unwrap();
    assert_eq!(grants.read(&g.token, FilePurpose::PemCertificate).unwrap_err(), GrantError::TooLarge("1 MiB".into()),);
    let g = grants.grant_read(FilePurpose::Attachment, &path).unwrap();
    assert_eq!(grants.read(&g.token, FilePurpose::Attachment).unwrap().bytes.len(), 1024 * 1024 + 1);
}

#[test]
fn a_write_replaces_the_chosen_destination_and_spends_the_grant() {
    let dir = tempfile::tempdir().unwrap();
    let dest = file(dir.path(), "backup.anvil", b"old");
    let grants = FileGrants::default();
    let g = grants.grant_write(FilePurpose::BundleExport, &dest).unwrap();
    assert_eq!(g.file_name, "backup.anvil");
    assert_eq!(grants.write(&g.token, FilePurpose::BundleExport, b"new bundle").unwrap(), 10);
    assert_eq!(std::fs::read(&dest).unwrap(), b"new bundle");
    assert!(partial_files(dir.path()).is_empty());
    assert_eq!(grants.write(&g.token, FilePurpose::BundleExport, b"again").unwrap_err(), GrantError::Unknown);
    assert_eq!(std::fs::read(&dest).unwrap(), b"new bundle");

    // A destination that does not exist yet is created.
    let fresh = dir.path().join("report.html");
    let g = grants.grant_write(FilePurpose::LoadReportExport, &fresh).unwrap();
    grants.write(&g.token, FilePurpose::LoadReportExport, b"<html>").unwrap();
    assert_eq!(std::fs::read(&fresh).unwrap(), b"<html>");
}

#[test]
fn a_failed_write_keeps_the_grant_for_a_retry() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("run.xml");
    let grants = FileGrants::default();
    let g = grants.grant_write(FilePurpose::RunReportExport, &dest).unwrap();
    std::fs::create_dir(&dest).unwrap();
    assert!(matches!(grants.write(&g.token, FilePurpose::RunReportExport, b"<junit/>"), Err(GrantError::Invalid(_))));
    assert!(dest.is_dir());
    std::fs::remove_dir(&dest).unwrap();
    grants.write(&g.token, FilePurpose::RunReportExport, b"<junit/>").unwrap();
    assert_eq!(std::fs::read(&dest).unwrap(), b"<junit/>");
    assert!(partial_files(dir.path()).is_empty());
}

#[test]
fn lock_revokes_every_grant() {
    let dir = tempfile::tempdir().unwrap();
    let src = file(dir.path(), "spec.yaml", b"openapi: 3.1.0");
    let dest = dir.path().join("out.anvil");
    let grants = FileGrants::default();
    let r = grants.grant_read(FilePurpose::SpecSource, &src).unwrap();
    let w = grants.grant_write(FilePurpose::BundleExport, &dest).unwrap();
    assert_eq!(grants.len(), 2);
    grants.revoke_all();
    assert!(grants.is_empty());
    assert_eq!(grants.read(&r.token, FilePurpose::SpecSource).unwrap_err(), GrantError::Unknown);
    assert_eq!(grants.write(&w.token, FilePurpose::BundleExport, b"x").unwrap_err(), GrantError::Unknown);
    assert!(!dest.exists());
}

#[test]
fn grants_expire() {
    let dir = tempfile::tempdir().unwrap();
    let src = file(dir.path(), "data.csv", b"a\n1\n");
    let grants = FileGrants::new(Duration::ZERO);
    let g = grants.grant_read(FilePurpose::Dataset, &src).unwrap();
    assert_eq!(grants.read(&g.token, FilePurpose::Dataset).unwrap_err(), GrantError::Unknown);
}

#[test]
fn outstanding_grants_are_bounded() {
    let dir = tempfile::tempdir().unwrap();
    let src = file(dir.path(), "a.bin", b"x");
    let grants = FileGrants::default();
    let tokens: Vec<String> = (0..=MAX_GRANTS).map(|_| grants.grant_read(FilePurpose::Attachment, &src).unwrap().token).collect();
    assert_eq!(grants.len(), MAX_GRANTS);
    assert_eq!(grants.read(&tokens[0], FilePurpose::Attachment).unwrap_err(), GrantError::Unknown);
    assert_eq!(grants.read(&tokens[MAX_GRANTS], FilePurpose::Attachment).unwrap().bytes, b"x");
}

#[test]
fn a_file_replaced_after_it_was_chosen_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = file(dir.path(), "cert.pem", b"chosen");
    let grants = FileGrants::default();
    let g = grants.grant_read(FilePurpose::PemCertificate, &path).unwrap();
    // Created before the original goes away, so it cannot reuse its inode
    // (Unix) or file index (Windows).
    let swap = file(dir.path(), "swap", b"substituted");
    std::fs::rename(swap, &path).unwrap();
    assert_eq!(grants.read(&g.token, FilePurpose::PemCertificate).unwrap_err(), GrantError::Changed,);
}

#[test]
fn a_lock_while_the_dialog_is_open_grants_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let pem = anvil_fixtures::LabPki::generate().ca.cert;
    let src = file(dir.path(), "a.pem", pem.as_bytes());
    let expected = canonical_pem(&pem);
    let dest = dir.path().join("out.anvil");
    let grants = FileGrants::default();
    let before = grants.generation();
    grants.revoke_all();
    assert_ne!(grants.generation(), before);
    assert_eq!(grants.grant_read_at(FilePurpose::PemCertificate, &src, before).unwrap_err(), GrantError::Revoked,);
    assert_eq!(grants.grant_write_at(FilePurpose::BundleExport, &dest, before).unwrap_err(), GrantError::Revoked);
    assert!(grants.is_empty());
    // A choice started after the lock is granted.
    let now = grants.generation();
    let g = grants.grant_read_at(FilePurpose::PemCertificate, &src, now).unwrap();
    let returned = grants.read(&g.token, FilePurpose::PemCertificate).unwrap();
    assert_eq!(returned.bytes, expected);
    assert!(!dest.exists());
}

#[test]
fn a_token_file_choice_is_never_a_session_grant() {
    let dir = tempfile::tempdir().unwrap();
    let path = file(dir.path(), "jwt_svid.token", b"token");
    let grants = FileGrants::default();
    assert_eq!(FilePurpose::JwtSvidFile.access(), Access::Bind);
    assert_eq!(grants.grant_read(FilePurpose::JwtSvidFile, &path).unwrap_err(), GrantError::WrongPurpose);
    assert_eq!(grants.grant_write(FilePurpose::JwtSvidFile, &path).unwrap_err(), GrantError::WrongPurpose);
    assert!(grants.is_empty());
    let g = grants.grant_read(FilePurpose::PemCertificate, &path).unwrap();
    assert_eq!(grants.read(&g.token, FilePurpose::JwtSvidFile).unwrap_err(), GrantError::WrongPurpose);
}

#[test]
fn a_linked_file_choice_is_never_a_session_grant() {
    let dir = tempfile::tempdir().unwrap();
    let path = file(dir.path(), "payload.bin", b"payload");
    let grants = FileGrants::default();
    assert_eq!(FilePurpose::LinkedFile.access(), Access::Bind);
    assert_eq!(FilePurpose::LinkedFile.max_read_bytes(), 0);
    assert_eq!(grants.grant_read(FilePurpose::LinkedFile, &path).unwrap_err(), GrantError::WrongPurpose);
    assert_eq!(grants.grant_write(FilePurpose::LinkedFile, &path).unwrap_err(), GrantError::WrongPurpose);
    assert!(grants.is_empty());
    let g = grants.grant_read(FilePurpose::Attachment, &path).unwrap();
    assert_eq!(grants.read(&g.token, FilePurpose::LinkedFile).unwrap_err(), GrantError::WrongPurpose);
}

#[test]
fn a_failed_write_that_is_kept_stays_within_the_bound() {
    let dir = tempfile::tempdir().unwrap();
    let src = file(dir.path(), "a.bin", b"x");
    let dest = dir.path().join("out.anvil");
    let grants = FileGrants::default();
    let w = grants.grant_write(FilePurpose::BundleExport, &dest).unwrap();
    for _ in 1..MAX_GRANTS {
        grants.grant_read(FilePurpose::Attachment, &src).unwrap();
    }
    std::fs::create_dir(&dest).unwrap();
    assert!(grants.write(&w.token, FilePurpose::BundleExport, b"bundle").is_err());
    assert_eq!(grants.len(), MAX_GRANTS);
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn a_file_swapped_for_a_link_after_it_was_chosen_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = file(dir.path(), "cert.pem", b"chosen");
        let secret = file(dir.path(), "secret", b"elsewhere");
        let grants = FileGrants::default();
        let g = grants.grant_read(FilePurpose::PemCertificate, &path).unwrap();
        std::fs::remove_file(&path).unwrap();
        symlink(secret, &path).unwrap();
        assert_eq!(grants.read(&g.token, FilePurpose::PemCertificate).unwrap_err(), GrantError::Changed,);
    }

    #[test]
    fn a_folder_swapped_for_a_link_after_the_choice_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let chosen = root.path().join("chosen");
        let elsewhere = root.path().join("elsewhere");
        std::fs::create_dir(&chosen).unwrap();
        std::fs::create_dir(&elsewhere).unwrap();
        let src = file(&chosen, "spec.json", b"{}");
        file(&elsewhere, "spec.json", b"{\"other\":true}");
        let dest = chosen.join("out.anvil");
        let grants = FileGrants::default();
        let r = grants.grant_read(FilePurpose::SpecSource, &src).unwrap();
        let w = grants.grant_write(FilePurpose::BundleExport, &dest).unwrap();
        std::fs::rename(&chosen, root.path().join("moved")).unwrap();
        symlink(&elsewhere, &chosen).unwrap();
        assert_eq!(grants.read(&r.token, FilePurpose::SpecSource).unwrap_err(), GrantError::Changed);
        assert_eq!(grants.write(&w.token, FilePurpose::BundleExport, b"bundle").unwrap_err(), GrantError::Changed);
        assert!(!elsewhere.join("out.anvil").exists());
        assert!(partial_files(&elsewhere).is_empty());
    }

    #[test]
    fn a_write_replaces_a_link_at_the_destination_instead_of_following_it() {
        let dir = tempfile::tempdir().unwrap();
        let victim = file(dir.path(), "victim", b"untouched");
        let dest = dir.path().join("report.json");
        symlink(&victim, &dest).unwrap();
        let grants = FileGrants::default();
        let g = grants.grant_write(FilePurpose::LoadReportExport, &dest).unwrap();
        grants.write(&g.token, FilePurpose::LoadReportExport, b"{\"report\":1}").unwrap();
        assert_eq!(std::fs::read(&victim).unwrap(), b"untouched");
        assert!(!std::fs::symlink_metadata(&dest).unwrap().file_type().is_symlink());
        assert_eq!(std::fs::read(&dest).unwrap(), b"{\"report\":1}");
    }

    #[test]
    fn an_exported_bundle_is_readable_only_by_its_owner() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let dest = file(dir.path(), "backup.anvil", b"old");
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o644)).unwrap();
        let grants = FileGrants::default();
        let g = grants.grant_write(FilePurpose::BundleExport, &dest).unwrap();
        grants.write(&g.token, FilePurpose::BundleExport, b"bundle").unwrap();
        assert_eq!(std::fs::metadata(&dest).unwrap().permissions().mode() & 0o777, 0o600);
    }
}

#[cfg(unix)]
#[test]
fn a_fifo_is_never_granted_or_read_and_never_blocks() {
    let dir = tempfile::tempdir().unwrap();
    let grants = std::sync::Arc::new(FileGrants::default());
    // Choosing a FIFO (with no writer, so a blocking open would wait for one)
    // grants nothing.
    let fifo = dir.path().join("pipe");
    mkfifo(&fifo);
    let chosen = within_seconds({
        let grants = grants.clone();
        move || grants.grant_read(FilePurpose::Dataset, &fifo)
    });
    assert_eq!(chosen.unwrap_err(), GrantError::Invalid("not a regular file".into()));
    assert!(grants.is_empty());

    // A chosen file swapped for a FIFO under the same name is refused.
    let path = file(dir.path(), "rows.csv", b"id\n1\n");
    let g = grants.grant_read(FilePurpose::Dataset, &path).unwrap();
    std::fs::remove_file(&path).unwrap();
    mkfifo(&path);
    let read = within_seconds(move || grants.read(&g.token, FilePurpose::Dataset).map(|f| f.bytes));
    assert_eq!(read.unwrap_err(), GrantError::Changed);
}
