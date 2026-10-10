//! Real CLI rotation input, confirmation and offline recovery for linked policy.
use anvil_app::App;
use anvil_app::profiles::{ProfileManager, Unlock};
use anvil_domain::workspace::LinkedIdentity;
use anvil_storage::{KdfParams, crypto, vault};
use std::io::Write;
use std::process::{Command, Output, Stdio};

const OLD: &str = "old cli rotation password";
const NEW: &str = "new cli rotation password";
fn cli(root: &std::path::Path, flags: &[&str], input: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_anvil"))
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
        .unwrap();
    child.stdin.take().unwrap().write_all(input.as_bytes()).unwrap();
    child.wait_with_output().unwrap()
}
#[test]
fn explicit_recovery_input_rotates_a_fresh_login_profile_offline_and_retains_policy() {
    let root = tempfile::tempdir().unwrap();
    let (s, old, rk) = ProfileManager::new(root.path()).create_passphrase("rotation", OLD, KdfParams::testing()).unwrap();
    let h = vault::read_header(&s.dir).unwrap();
    let app = App::open(s.dir.clone(), h.clone(), old.clone()).unwrap();
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
    std::fs::write(s.dir.join("identity.json"), serde_json::to_vec(&binding).unwrap()).unwrap();
    let refused = cli(
        root.path(),
        &["--passphrase-stdin", "profile", "rotate-key", "--confirm-rotation", "--new-passphrase-stdin"],
        &format!("{OLD}\n{NEW}\n"),
    );
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("fresh"));
    let missing_confirmation = cli(root.path(), &["profile", "rotate-key", "--new-passphrase-stdin", "--recovery-key-stdin"], "");
    assert!(!missing_confirmation.status.success());
    assert_eq!(vault::read_header(&s.dir).unwrap().key_check, h.key_check);
    let out = cli(
        root.path(),
        &["profile", "rotate-key", "--confirm-rotation", "--new-passphrase-stdin", "--recovery-key-stdin"],
        &format!("{}\n{NEW}\n", rk.as_str()),
    );
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stdout).contains("NEW RECOVERY KEY"));
    assert!(ProfileManager::unlock(&s.dir, Unlock::Passphrase(NEW)).is_err());
    assert!(ProfileManager::unlock_requirements(&s.dir).unwrap().fresh_login_required);
    let now = vault::read_header(&s.dir).unwrap();
    assert!(vault::unlock_with_recovery(&now, &rk).is_err());
    let new_key = vault::unlock_with_passphrase(&now, NEW).unwrap();
    let reopened = App::open(s.dir, now, new_key).unwrap();
    assert_eq!(reopened.workspaces().unwrap()[0].name, "kept");
}
