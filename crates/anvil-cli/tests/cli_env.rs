//! `anvil env` end to end: the real binary, a real profile on disk and a real
//! fixture server. An imported spec's `fill in {{bearer}}` is supplied from
//! the command line, kept in the vault and never printed; the environment
//! an import brought is listed, chosen and checked by name.

use anvil_app::App;
use anvil_app::profiles::{ProfileManager, Unlock};
use anvil_domain::secret::SensitiveValue;
use anvil_storage::KdfParams;
use std::path::Path;
use std::process::{Output, Stdio};
use tokio::io::AsyncWriteExt;

const PASS: &str = "cli-env-passphrase-1";
const TOKEN: &str = "cli-env-TOKEN-7319";

async fn anvil_with_stdin(data: &Path, args: &[&str], stdin: Option<&str>, env: &[(&str, &str)]) -> Output {
    let mut c = tokio::process::Command::new(env!("CARGO_BIN_EXE_anvil"));
    c.arg("--data-dir")
        .arg(data)
        .args(args)
        .env("ANVIL_PASSPHRASE", PASS)
        .env_remove("ANVIL_PROFILE")
        .env_remove("ANVIL_DATA_DIR")
        .envs(env.iter().copied())
        .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = c.spawn().unwrap();
    if let Some(s) = stdin {
        let mut i = child.stdin.take().unwrap();
        i.write_all(s.as_bytes()).await.unwrap();
    }
    child.wait_with_output().await.unwrap()
}

async fn anvil(data: &Path, args: &[&str]) -> Output {
    anvil_with_stdin(data, args, None, &[]).await
}

fn text(o: &Output) -> String {
    format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr))
}

fn open(root: &Path) -> App {
    let s = ProfileManager::new(root).list().into_iter().next().unwrap();
    let (h, key) = ProfileManager::unlock(&s.dir, Unlock::Passphrase(PASS)).unwrap();
    App::open(s.dir, h, key).unwrap()
}

fn spec(base: &str) -> String {
    format!(
        r#"openapi: 3.0.3
info: {{title: Echo API, version: "1"}}
servers:
  - {{url: "{base}", description: local}}
  - {{url: "https://staging.example.invalid", description: staging}}
security: [{{bearer: []}}]
components:
  securitySchemes:
    bearer: {{type: http, scheme: bearer}}
paths:
  /echo:
    get: {{operationId: echo, responses: {{"200": {{description: ok}}}}}}
"#
    )
}

fn authorization(f: &anvil_fixtures::http::Fixture) -> Option<String> {
    f.log.last_request_headers()?.into_iter().find(|(n, _)| n == "authorization").map(|(_, v)| v)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_imported_bearer_is_filled_in_from_the_command_line() {
    anvil_fixtures::init();
    let f = anvil_fixtures::http::serve("127.0.0.1:0", None).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    ProfileManager::new(&data).create_passphrase("ci", PASS, KdfParams::testing()).unwrap();
    let file = dir.path().join("openapi.yaml");
    std::fs::write(&file, spec(&f.url(""))).unwrap();
    let file = file.to_str().unwrap();

    // The import says what to fill in, and how.
    let o = anvil(&data, &["import-spec", "--new-workspace", "--file", file]).await;
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    let out = text(&o);
    assert!(out.contains("into workspace 'Echo API 1'"), "{out}");
    assert!(out.contains("environments: 'local', 'staging' ('local' is active)"), "{out}");
    assert!(out.contains("anvil env set 'Echo API 1' bearer --secret --value-stdin"), "{out}");
    let ws = "Echo API 1";

    // Not sent until it is.
    let o = anvil(&data, &["send", "echo", "--workspace", ws]).await;
    assert_eq!(o.status.code(), Some(1), "{}", text(&o));
    assert_eq!(authorization(&f), None);

    // A secret on the command line is refused, with nothing written.
    let o = anvil(&data, &["env", "set", ws, "bearer", "--secret", TOKEN]).await;
    assert_eq!(o.status.code(), Some(3), "{}", text(&o));
    assert!(text(&o).contains("--value-stdin"), "{}", text(&o));
    assert!(open(&data).environments(&open(&data).find_workspace(ws).unwrap().meta.id).unwrap().iter().all(|e| e.variables.len() == 1));

    // From stdin, after the passphrase line: kept in the vault, never printed.
    let o = anvil_with_stdin(
        &data,
        &["--passphrase-stdin", "env", "set", ws, "bearer", "--secret", "--value-stdin"],
        Some(&format!("{PASS}\n{TOKEN}\n")),
        &[("ANVIL_PASSPHRASE", "")],
    )
    .await;
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    assert!(text(&o).contains("set bearer (secret, kept in the vault) in environment 'local'"), "{}", text(&o));
    {
        let app = open(&data);
        let w = app.find_workspace(ws).unwrap();
        let local = app.environments(&w.meta.id).unwrap().into_iter().find(|e| e.name == "local").unwrap();
        let v = local.variables.iter().find(|v| v.name == "bearer").unwrap();
        assert!(v.secret, "{v:?}");
        let SensitiveValue::Secret { secret } = &v.value else { panic!("not in the vault: {v:?}") };
        assert_eq!(app.store.get_workspace_secret(&secret.id, &w.meta.id).unwrap().unwrap().1.as_str(), TOKEN);
    }
    let o = anvil(&data, &["env", "show", ws]).await;
    assert!(text(&o).contains("bearer = ‹secret, in the vault›") && !text(&o).contains(TOKEN), "{}", text(&o));

    // Now it is sent with the token, which stays out of the output.
    let o = anvil(&data, &["send", "echo", "--workspace", ws, "--json"]).await;
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    assert_eq!(authorization(&f).as_deref(), Some(format!("Bearer {TOKEN}").as_str()));
    assert!(!text(&o).contains(TOKEN), "the send printed the token");
    let o = anvil(&data, &["run", ws, "--folder", "/", "-q"]).await;
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));

    // Once secret, always secret: an argument is refused even without --secret.
    let o = anvil(&data, &["env", "set", ws, "bearer", "plain"]).await;
    assert_eq!(o.status.code(), Some(3), "{}", text(&o));
    let o =
        anvil_with_stdin(&data, &["env", "set", ws, "bearer", "--value-env", "CLI_ENV_TOKEN"], None, &[("CLI_ENV_TOKEN", "rotated")]).await;
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    assert!(text(&o).contains("(secret, kept in the vault)"), "{}", text(&o));
    anvil(&data, &["send", "echo", "--workspace", ws]).await;
    assert_eq!(authorization(&f).as_deref(), Some("Bearer rotated"));

    // A wrong environment name lists the ones there are; `use` switches.
    let o = anvil(&data, &["send", "echo", "--workspace", ws, "--env", "stage"]).await;
    assert_eq!(o.status.code(), Some(3), "{}", text(&o));
    assert!(text(&o).contains("it has: 'local', 'staging'"), "{}", text(&o));
    let o = anvil(&data, &["env", "use", ws, "STAGING"]).await;
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    let o = anvil(&data, &["env", "list", ws]).await;
    let listing = text(&o);
    assert!(listing.lines().any(|l| l.starts_with("* ") && l.contains("staging")), "{listing}");
    let o = anvil(&data, &["env", "use", ws, "--none"]).await;
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    let o = anvil(&data, &["env", "set", ws, "x", "1"]).await;
    assert_eq!(o.status.code(), Some(3), "{}", text(&o));
    assert!(text(&o).contains("no active environment"), "{}", text(&o));

    // Unset.
    let o = anvil(&data, &["env", "unset", ws, "bearer", "--env", "local"]).await;
    assert!(text(&o).contains("removed bearer"), "{}", text(&o));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_import_into_an_existing_workspace_names_its_environment() {
    anvil_fixtures::init();
    let f = anvil_fixtures::http::serve("127.0.0.1:0", None).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    ProfileManager::new(&data).create_passphrase("ci", PASS, KdfParams::testing()).unwrap();
    let file = dir.path().join("openapi.yaml");
    std::fs::write(&file, spec(&f.url(""))).unwrap();
    let file = file.to_str().unwrap();
    assert_eq!(anvil(&data, &["workspace", "create", "Shop"]).await.status.code(), Some(0));

    // The import root's environments are not active in the workspace: the
    // hint names one.
    let o = anvil(&data, &["import-spec", "Shop", "--file", file]).await;
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    let out = text(&o);
    assert!(out.contains("(not active here: pick one with --env"), "{out}");
    assert!(out.contains("anvil env set Shop bearer --env local --secret --value-stdin"), "{out}");
    let o = anvil(&data, &["env", "list", "Shop"]).await;
    assert!(text(&o).contains("(imported with 'Echo API')"), "{}", text(&o));

    let o =
        anvil_with_stdin(&data, &["env", "set", "Shop", "bearer", "--env", "local", "--secret", "--value-stdin"], Some(TOKEN), &[]).await;
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    let o = anvil(&data, &["send", "Echo API/echo", "--workspace", "Shop", "--env", "local"]).await;
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    assert_eq!(authorization(&f).as_deref(), Some(format!("Bearer {TOKEN}").as_str()));

    // A second import of the same spec brings a second 'local': the name no
    // longer picks one, and the hint names the new one by id.
    let o = anvil(&data, &["import-spec", "Shop", "--file", file]).await;
    let out = text(&o);
    let hint = out.lines().find(|l| l.contains("anvil env set")).unwrap();
    assert!(!hint.contains("--env local"), "{out}");
    let o = anvil(&data, &["send", "Echo API/echo", "--workspace", "Shop", "--env", "local"]).await;
    assert_eq!(o.status.code(), Some(3), "{}", text(&o));
    assert!(text(&o).contains("2 environments of workspace 'Shop' are named 'local'"), "{}", text(&o));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn names_are_never_guessed_and_hints_stay_runnable() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    ProfileManager::new(&data).create_passphrase("ci", PASS, KdfParams::testing()).unwrap();

    // create: printed id, --use, a duplicate refused.
    assert_eq!(anvil(&data, &["workspace", "create", "Solo"]).await.status.code(), Some(0));
    let o = anvil(&data, &["env", "create", "Solo", "dev", "--use"]).await;
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    let id = String::from_utf8_lossy(&o.stdout).trim().to_string();
    let o = anvil(&data, &["env", "list", "solo"]).await;
    assert!(text(&o).lines().any(|l| l.starts_with(&format!("* {id}  dev"))), "{}", text(&o));
    let o = anvil(&data, &["env", "create", "Solo", "DEV"]).await;
    assert_eq!(o.status.code(), Some(3), "{}", text(&o));
    assert!(text(&o).contains("already has an environment named 'DEV'"), "{}", text(&o));
    let o = anvil(&data, &["env", "set", "Solo", "host", "example.com"]).await;
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    let o = anvil(&data, &["env", "set", "Solo", "token", "--secret", "--value-env", "CLI_ENV_UNSET_VARIABLE"]).await;
    assert_eq!(o.status.code(), Some(3), "{}", text(&o));
    assert!(text(&o).contains("'CLI_ENV_UNSET_VARIABLE' is not set"), "{}", text(&o));

    // Two workspaces of one name: the env commands refuse the name.
    for _ in 0..2 {
        assert_eq!(anvil(&data, &["workspace", "create", "Twin"]).await.status.code(), Some(0));
    }
    let o = anvil_with_stdin(&data, &["env", "set", "twin", "token", "--secret", "--value-stdin"], Some(TOKEN), &[]).await;
    assert_eq!(o.status.code(), Some(3), "{}", text(&o));
    assert!(text(&o).contains("2 workspaces are named 'twin'"), "{}", text(&o));

    // A server description that reads as an option is named by id.
    let file = dir.path().join("openapi.yaml");
    std::fs::write(&file, spec("http://127.0.0.1:9").replace("description: local", "description: \"-local\"")).unwrap();
    let o = anvil(&data, &["import-spec", "Solo", "--file", file.to_str().unwrap()]).await;
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    let out = text(&o);
    let hint = out.lines().find(|l| l.contains("anvil env set")).unwrap_or_else(|| panic!("{out}"));
    assert!(!hint.contains("--env -local") && !hint.contains("--env '-local'"), "{out}");
    let args: Vec<&str> = hint.split_whitespace().skip(1).collect();
    let o = anvil_with_stdin(&data, &args, Some(TOKEN), &[]).await;
    assert_eq!(o.status.code(), Some(0), "{hint}: {}", text(&o));
}
