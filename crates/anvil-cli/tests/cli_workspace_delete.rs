//! `anvil workspace delete`: the real binary and a real profile on disk. It
//! names the workspace by its id or a unique exact name, never by a guess,
//! and deletes nothing without `--confirm-delete`.

use anvil_app::App;
use anvil_app::profiles::{ProfileManager, Unlock};
use anvil_domain::request::RequestSpec;
use anvil_storage::KdfParams;
use std::path::Path;
use std::process::{Command, Output};

const PASS: &str = "cli-workspace-delete-passphrase-1";

/// A profile with workspaces `Keep` and `Gone` (with a request in each), and
/// two workspaces both named `Twin`.
fn setup(root: &Path) {
    let pm = ProfileManager::new(root);
    let (s, dek, _) = pm.create_passphrase("ci", PASS, KdfParams::testing()).unwrap();
    let h = anvil_storage::vault::read_header(&s.dir).unwrap();
    let app = App::open(s.dir, h, dek).unwrap();
    for name in ["Keep", "Gone", "Twin", "Twin"] {
        let ws = app.create_workspace(name).unwrap();
        app.create_request(&ws.meta.id, None, "req", RequestSpec::http("GET", "https://api.example.invalid/")).unwrap();
    }
}

fn open(root: &Path) -> App {
    let s = ProfileManager::new(root).list().into_iter().next().unwrap();
    let (h, key) = ProfileManager::unlock(&s.dir, Unlock::Passphrase(PASS)).unwrap();
    App::open(s.dir, h, key).unwrap()
}

fn anvil(data: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_anvil"))
        .arg("--data-dir")
        .arg(data)
        .args(args)
        .env("ANVIL_PASSPHRASE", PASS)
        .env_remove("ANVIL_EXPORT_PASSPHRASE")
        .env_remove("ANVIL_PROFILE")
        .env_remove("ANVIL_DATA_DIR")
        .output()
        .unwrap()
}

fn text(o: &Output) -> String {
    format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr))
}

fn names(data: &Path) -> Vec<String> {
    let mut names: Vec<String> = open(data).workspaces().unwrap().into_iter().map(|w| w.name).collect();
    names.sort();
    names
}

#[test]
fn a_workspace_is_deleted_only_when_named_exactly_and_confirmed() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    setup(&data);
    let all = ["Gone", "Keep", "Twin", "Twin"];

    // Without the confirmation nothing is deleted.
    let o = anvil(&data, &["workspace", "delete", "Gone"]);
    assert_ne!(o.status.code(), Some(0), "{}", text(&o));
    assert!(text(&o).contains("--confirm-delete"), "{}", text(&o));
    assert_eq!(names(&data), all);

    // A name that is not exact, or that two workspaces share, is refused.
    for (name, says) in [("gone", "no workspace has the id or the exact name"), ("Twin", "2 workspaces are named")] {
        let o = anvil(&data, &["workspace", "delete", name, "--confirm-delete"]);
        assert_ne!(o.status.code(), Some(0), "{name}: {}", text(&o));
        assert!(text(&o).contains(says), "{name}: {}", text(&o));
    }
    assert_eq!(names(&data), all);

    // By its exact name, confirmed: the workspace and its requests are gone.
    let gone = open(&data).workspaces().unwrap().into_iter().find(|w| w.name == "Gone").unwrap().meta.id;
    let o = anvil(&data, &["workspace", "delete", "Gone", "--confirm-delete"]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    assert!(text(&o).contains("deleted workspace 'Gone'"), "{}", text(&o));
    assert_eq!(names(&data), ["Keep", "Twin", "Twin"]);
    let app = open(&data);
    assert!(app.requests(&gone).unwrap_or_default().is_empty());

    // By id, one of two workspaces that share a name.
    let twin = app.workspaces().unwrap().into_iter().find(|w| w.name == "Twin").unwrap().meta.id.to_string();
    drop(app);
    let o = anvil(&data, &["workspace", "delete", &twin, "--confirm-delete"]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    assert_eq!(names(&data), ["Keep", "Twin"]);
}
