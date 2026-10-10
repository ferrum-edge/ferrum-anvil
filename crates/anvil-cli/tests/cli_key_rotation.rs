//! Real CLI rotation input, confirmation and offline recovery for linked policy.
use anvil_app::App;
use anvil_app::profiles::{ProfileManager, Unlock};
use anvil_domain::workspace::LinkedIdentity;
use anvil_storage::{KdfParams, crypto, vault};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Output, Stdio};

const OLD: &str = "old cli rotation password";
const NEW: &str = "new cli rotation password";
fn spawn(root: &std::path::Path, flags: &[&str]) -> Child {
    Command::new(env!("CARGO_BIN_EXE_anvil"))
        .arg("--data-dir")
        .arg(root)
        .arg("--profile")
        .arg("rotation")
        .args(flags)
        .env_remove("ANVIL_PASSPHRASE")
        .env_remove("ANVIL_PROFILE")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}
fn cli(root: &std::path::Path, flags: &[&str], input: &str) -> Output {
    let mut child = spawn(root, flags);
    child.stdin.take().unwrap().write_all(input.as_bytes()).unwrap();
    child.wait_with_output().unwrap()
}
fn fixture() -> (tempfile::TempDir, std::path::PathBuf, vault::ProfileHeader, String) {
    let root = tempfile::tempdir().unwrap();
    // This fixture is an authentic historical profile, before canonical
    // policy enrollment. New product profiles ignore legacy sidecar bindings.
    let dir = root.path().join("profiles").join("legacy");
    let created = vault::create_passphrase_profile(&dir, "rotation", OLD, KdfParams::testing()).unwrap();
    let h = created.header;
    let old = created.dek;
    let rk = created.recovery_key.unwrap();
    let app = App::open(dir.clone(), h.clone(), old.clone()).unwrap();
    app.create_workspace("kept").unwrap();
    drop(app);
    // A valid persisted legacy binding fixture. No provider proof is forged:
    // the CLI must use the explicitly supplied local recovery credential.
    let linked = LinkedIdentity {
        provider: "mock".into(),
        subject: "test".into(),
        email: None,
        linked_at: chrono::Utc::now(),
        require_fresh_login: true,
    };
    let sealed =
        crypto::seal(&old, format!("anvil-identity-binding-v1/{}", h.profile_id).as_bytes(), &serde_json::to_vec(&linked).unwrap());
    let hex: String = sealed.iter().map(|b| format!("{b:02x}")).collect();
    let binding = serde_json::json!({"format":"anvil-identity-binding", "version":1,"provider":linked.provider,
        "subject":linked.subject,"linked_at":linked.linked_at,"require_fresh_login":true,"sealed":hex});
    std::fs::write(dir.join("identity.json"), serde_json::to_vec(&binding).unwrap()).unwrap();
    (root, dir, h, rk.to_string())
}
const FLAGS: &[&str] = &["profile", "rotate-key", "--confirm-rotation", "--new-passphrase-stdin", "--recovery-key-stdin"];
fn delivered_key(child: &mut Child, old_recovery: &str) -> (BufReader<std::process::ChildStdout>, String) {
    child.stdin.as_mut().unwrap().write_all(format!("{old_recovery}\n{NEW}\n").as_bytes()).unwrap();
    let mut out = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    out.read_line(&mut line).unwrap();
    let recovery = line.split(": ").nth(1).expect("replacement delivered before commit").trim().to_string();
    line.clear();
    out.read_line(&mut line).unwrap();
    assert!(line.contains("Rotation has not committed"));
    (out, recovery)
}
#[test]
fn explicit_recovery_input_rotates_a_fresh_login_profile_offline_and_retains_policy() {
    let (root, dir, h, rk) = fixture();
    let refused = cli(
        root.path(),
        &["--passphrase-stdin", "profile", "rotate-key", "--confirm-rotation", "--new-passphrase-stdin"],
        &format!("{OLD}\n{NEW}\n"),
    );
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("POLICY_ENROLLMENT_REQUIRED"));
    let missing_confirmation = cli(root.path(), &["profile", "rotate-key", "--new-passphrase-stdin", "--recovery-key-stdin"], "");
    assert!(!missing_confirmation.status.success());
    assert_eq!(vault::read_header(&dir).unwrap().key_check, h.key_check);
    let mut child = spawn(root.path(), FLAGS);
    let (reader, recovery) = delivered_key(&mut child, &rk);
    child.stdout = Some(reader.into_inner());
    child.stdin.take().unwrap().write_all(format!("{recovery}\n").as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(ProfileManager::unlock(&dir, Unlock::Passphrase(NEW)).is_err());
    assert!(ProfileManager::unlock_requirements(&dir).unwrap().fresh_login_required);
    let now = vault::read_header(&dir).unwrap();
    assert!(vault::unlock_with_recovery(&now, &rk).is_err());
    let (now, new_key) = ProfileManager::unlock(&dir, Unlock::RecoveryKey(&recovery)).unwrap();
    let reopened = App::open(dir, now, new_key).unwrap();
    assert_eq!(reopened.workspaces().unwrap()[0].name, "kept");
}

#[test]
fn failed_delivery_or_acknowledgment_keeps_old_linked_offline_recovery() {
    for failure in ["output", "eof", "mismatch", "killed"] {
        let (root, dir, h, rk) = fixture();
        let mut child = spawn(root.path(), FLAGS);
        if failure == "output" {
            drop(child.stdout.take());
            child.stdin.take().unwrap().write_all(format!("{rk}\n{NEW}\n").as_bytes()).unwrap();
        } else {
            let (reader, _) = delivered_key(&mut child, &rk);
            child.stdout = Some(reader.into_inner());
            assert_eq!(vault::read_header(&dir).unwrap().key_check, h.key_check);
            if failure == "killed" {
                child.kill().unwrap();
            } else if failure == "mismatch" {
                child.stdin.as_mut().unwrap().write_all(b"not the saved key\n").unwrap();
            }
            drop(child.stdin.take());
        }
        let out = child.wait_with_output().unwrap();
        assert!(!out.status.success(), "{failure}");
        assert_eq!(vault::read_header(&dir).unwrap().key_check, h.key_check, "{failure}");
        let (header, key) = ProfileManager::unlock(&dir, Unlock::RecoveryKey(&rk)).unwrap();
        assert_eq!(App::open(dir, header, key).unwrap().workspaces().unwrap()[0].name, "kept");
    }
}

#[test]
fn post_commit_output_loss_retains_acknowledged_linked_offline_recovery() {
    let (root, dir, h, rk) = fixture();
    let mut child = spawn(root.path(), FLAGS);
    let (reader, recovery) = delivered_key(&mut child, &rk);
    assert_eq!(vault::read_header(&dir).unwrap().key_check, h.key_check);
    // The replacement was delivered and saved before confirmation. Close
    // output before commit so the success report fails deterministically.
    drop(reader);
    child.stdin.take().unwrap().write_all(format!("{recovery}\n").as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(!out.status.success());
    assert_ne!(vault::read_header(&dir).unwrap().key_check, h.key_check);
    assert!(ProfileManager::unlock(&dir, Unlock::RecoveryKey(&rk)).is_err());
    assert!(ProfileManager::unlock(&dir, Unlock::Passphrase(NEW)).is_err());
    let (header, key) = ProfileManager::unlock(&dir, Unlock::RecoveryKey(&recovery)).unwrap();
    assert_eq!(App::open(dir, header, key).unwrap().workspaces().unwrap()[0].name, "kept");
}

#[test]
fn explicit_legacy_enrollment_requires_saved_recovery_confirmation_before_commit() {
    const ENROLL: &[&str] =
        &["--passphrase-stdin", "profile", "enroll-policy", "--confirm-replace-unknown-policy", "--new-passphrase-stdin"];
    for outcome in ["eof", "mismatch", "saved", "output_lost_after_ack"] {
        let (root, dir, h, old_recovery) = fixture();
        std::fs::remove_file(dir.join("identity.json")).unwrap();
        assert!(ProfileManager::unlock(&dir, Unlock::Passphrase(OLD)).is_err());
        let mut child = spawn(root.path(), ENROLL);
        child.stdin.as_mut().unwrap().write_all(format!("{OLD}\n{NEW}\n").as_bytes()).unwrap();
        let mut reader = BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let recovery = line.split(": ").nth(1).unwrap().trim().to_string();
        line.clear();
        reader.read_line(&mut line).unwrap();
        assert!(line.contains("Enrollment has not committed"));
        assert_eq!(vault::read_header(&dir).unwrap().key_check, h.key_check);
        if outcome != "output_lost_after_ack" {
            child.stdout = Some(reader.into_inner());
        } else {
            drop(reader);
        }
        if outcome != "eof" {
            let ack = if outcome == "mismatch" { "incorrect saved record" } else { &recovery };
            child.stdin.as_mut().unwrap().write_all(format!("{ack}\n").as_bytes()).unwrap();
        }
        drop(child.stdin.take());
        let out = child.wait_with_output().unwrap();
        assert_eq!(out.status.success(), outcome == "saved", "{outcome}: {}", String::from_utf8_lossy(&out.stderr));
        if matches!(outcome, "eof" | "mismatch") {
            assert_eq!(vault::read_header(&dir).unwrap().key_check, h.key_check);
            assert!(ProfileManager::unlock(&dir, Unlock::RecoveryKey(&old_recovery)).is_ok());
        } else {
            assert_ne!(vault::read_header(&dir).unwrap().key_check, h.key_check);
            assert!(ProfileManager::unlock(&dir, Unlock::RecoveryKey(&old_recovery)).is_err());
            assert!(!ProfileManager::unlock_requirements(&dir).unwrap().fresh_login_required);
            let (header, key) = ProfileManager::unlock(&dir, Unlock::RecoveryKey(&recovery)).unwrap();
            assert_eq!(App::open(dir, header, key).unwrap().workspaces().unwrap()[0].name, "kept");
        }
    }
}
