//! Desktop file access goes only through grants recorded when the user picks
//! a file in a native dialog: a path, a made-up token, a grant for another
//! purpose, an expired or revoked grant, or a file swapped after it was
//! chosen never reaches the disk.

use anvil_app::file_grants::{FileGrants, FilePurpose, GrantError, MAX_GRANTS};
use std::path::{Path, PathBuf};
use std::time::Duration;

fn file(dir: &Path, name: &str, contents: &[u8]) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, contents).unwrap();
    p
}

fn partial_files(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".partial"))
        .collect()
}

#[test]
fn a_read_grant_reads_the_chosen_file_and_can_be_reused() {
    let dir = tempfile::tempdir().unwrap();
    let path = file(dir.path(), "cert.pem", b"-----BEGIN CERTIFICATE-----");
    let grants = FileGrants::default();
    let g = grants.grant_read(FilePurpose::PemFile, &path).unwrap();
    assert_eq!(g.file_name, "cert.pem");
    // Opaque: the token does not carry the path or the name.
    assert!(!g.token.contains("cert"), "{}", g.token);
    assert!(!g.token.contains(&*dir.path().to_string_lossy()), "{}", g.token);
    // Preview then apply read the same selection.
    for _ in 0..2 {
        let f = grants.read(&g.token, FilePurpose::PemFile).unwrap();
        assert_eq!(f.bytes, b"-----BEGIN CERTIFICATE-----");
        assert_eq!(f.file_name, "cert.pem");
    }
    let again = grants.grant_read(FilePurpose::PemFile, &path).unwrap();
    assert_ne!(again.token, g.token, "every selection gets a fresh token");
}

#[test]
fn a_path_or_a_made_up_token_is_never_read() {
    let dir = tempfile::tempdir().unwrap();
    let path = file(dir.path(), "secret.txt", b"not for the webview");
    let grants = FileGrants::default();
    // A real grant exists for another file; it must not help.
    let other = file(dir.path(), "chosen.txt", b"chosen");
    grants.grant_read(FilePurpose::PemFile, &other).unwrap();
    let canonical = std::fs::canonicalize(&path).unwrap();
    for token in [
        path.to_string_lossy().into_owned(),
        canonical.to_string_lossy().into_owned(),
        "secret.txt".to_string(),
        format!("fg-{}", "0".repeat(32)),
        String::new(),
    ] {
        for purpose in [FilePurpose::PemFile, FilePurpose::Pkcs12File, FilePurpose::Attachment, FilePurpose::BundleImport] {
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
        for purpose in [FilePurpose::BundleExport, FilePurpose::LoadReportExport, FilePurpose::RunReportExport] {
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
    assert_eq!(grants.read(&g.token, FilePurpose::PemFile).unwrap_err(), GrantError::WrongPurpose);
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
    let g = grants.grant_read(FilePurpose::PemFile, &path).unwrap();
    assert_eq!(grants.read(&g.token, FilePurpose::PemFile).unwrap_err(), GrantError::TooLarge("1 MiB".into()));
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

#[cfg(unix)]
mod unix {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn a_file_replaced_after_it_was_chosen_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = file(dir.path(), "cert.pem", b"chosen");
        let grants = FileGrants::default();
        let g = grants.grant_read(FilePurpose::PemFile, &path).unwrap();
        // Created before the original goes away, so it cannot reuse its inode.
        let swap = file(dir.path(), "swap", b"substituted");
        std::fs::rename(swap, &path).unwrap();
        assert_eq!(grants.read(&g.token, FilePurpose::PemFile).unwrap_err(), GrantError::Changed);
    }

    #[test]
    fn a_file_swapped_for_a_link_after_it_was_chosen_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = file(dir.path(), "cert.pem", b"chosen");
        let secret = file(dir.path(), "secret", b"elsewhere");
        let grants = FileGrants::default();
        let g = grants.grant_read(FilePurpose::PemFile, &path).unwrap();
        std::fs::remove_file(&path).unwrap();
        symlink(secret, &path).unwrap();
        assert_eq!(grants.read(&g.token, FilePurpose::PemFile).unwrap_err(), GrantError::Changed);
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
}
