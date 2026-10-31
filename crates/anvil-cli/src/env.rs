//! `anvil env`: list, inspect and edit a workspace's environments, so the
//! variables an import asks for (`fill in {{token}}`) can be supplied from
//! the command line. Secret values never come from the command line itself
//! and are never printed.

use anvil_app::App;
use anvil_domain::Id;
use anvil_domain::secret::SensitiveValue;
use anvil_domain::workspace::{Environment, Workspace};
use anyhow::{Result, anyhow, bail};
use clap::Subcommand;
use std::io::Read;

/// The most `--value-stdin` reads.
const MAX_VALUE_BYTES: u64 = 1024 * 1024;

#[derive(Subcommand)]
pub enum EnvCmd {
    /// List the workspace's environments: `*` marks the active one, and an
    /// environment an imported collection brought names that collection.
    List {
        /// Workspace (id or name).
        workspace: String,
    },
    /// Print an environment's variables (default: the active one). Secret
    /// values are never printed.
    Show {
        /// Workspace (id or name).
        workspace: String,
        /// Environment (id or name).
        env: Option<String>,
    },
    /// Create an empty environment.
    Create {
        /// Workspace (id or name).
        workspace: String,
        name: String,
        /// Also make it the active environment.
        #[arg(long = "use")]
        make_active: bool,
    },
    /// Make an environment the active one: `send` and `run` use it when no
    /// `--env` is given.
    Use {
        /// Workspace (id or name).
        workspace: String,
        /// Environment (id or name).
        #[arg(required_unless_present = "none")]
        env: Option<String>,
        /// Make no environment active.
        #[arg(long, conflicts_with = "env")]
        none: bool,
    },
    /// Set a variable in an environment (default: the active one). Give the
    /// value as an argument, or with --value-stdin or --value-env. A secret
    /// is kept in the profile's encrypted vault and must not be an argument.
    /// A variable that is secret stays secret.
    Set {
        /// Workspace (id or name).
        workspace: String,
        /// Variable name, as used in `{{name}}`.
        name: String,
        /// The value (not for secrets: use --value-stdin or --value-env).
        #[arg(conflicts_with_all = ["value_stdin", "value_env"], required_unless_present_any = ["value_stdin", "value_env"])]
        value: Option<String>,
        /// Environment (id or name). Default: the active environment.
        #[arg(long)]
        env: Option<String>,
        /// Keep the value in the vault, masked and redacted from history,
        /// reports and safe-share exports.
        #[arg(long)]
        secret: bool,
        /// Read the value from stdin (all of it, less one trailing newline;
        /// after the passphrase line with --passphrase-stdin).
        #[arg(long, conflicts_with = "value_env")]
        value_stdin: bool,
        /// Read the value from this process environment variable.
        #[arg(long, value_name = "VAR")]
        value_env: Option<String>,
    },
    /// Remove a variable from an environment (default: the active one).
    Unset {
        /// Workspace (id or name).
        workspace: String,
        name: String,
        /// Environment (id or name). Default: the active environment.
        #[arg(long)]
        env: Option<String>,
    },
}

/// `envs` by name, case ignored.
pub fn sorted(mut envs: Vec<Environment>) -> Vec<Environment> {
    envs.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()).then(a.meta.id.to_string().cmp(&b.meta.id.to_string())));
    envs
}

/// The environment of `ws` that `name` names: its id, or its name with case
/// ignored when no other environment has it. A miss lists the names there are.
pub fn find_environment(app: &App, ws: &Workspace, name: &str) -> Result<Environment> {
    let all = sorted(app.environments(&ws.meta.id)?);
    if let Some(e) = all.iter().find(|e| e.meta.id.to_string() == name) {
        return Ok(e.clone());
    }
    let mut named: Vec<Environment> = all.iter().filter(|e| e.name.eq_ignore_ascii_case(name)).cloned().collect();
    match named.len() {
        1 => Ok(named.remove(0)),
        0 if all.is_empty() => {
            bail!("environment '{name}' not found: workspace '{}' has no environments (`anvil env create` adds one)", ws.name)
        }
        0 => bail!(
            "environment '{name}' not found in workspace '{}'; it has: {} (`anvil env list` shows them)",
            ws.name,
            all.iter().map(|e| format!("'{}'", e.name)).collect::<Vec<_>>().join(", ")
        ),
        n => bail!(
            "{n} environments of workspace '{}' are named '{name}'; name the one you mean by its id: {}",
            ws.name,
            named.iter().map(|e| e.meta.id.to_string()).collect::<Vec<_>>().join(", ")
        ),
    }
}

/// [`find_environment`]'s id, or `None` when no name is given.
pub fn environment_id(app: &App, ws: &Workspace, name: Option<&str>) -> Result<Option<Id>> {
    name.map(|n| find_environment(app, ws, n).map(|e| e.meta.id)).transpose()
}

/// `name`, or else the workspace's active environment.
fn target(app: &App, ws: &Workspace, name: Option<&str>) -> Result<Environment> {
    if let Some(n) = name {
        return find_environment(app, ws, n);
    }
    let all = app.environments(&ws.meta.id)?;
    if all.is_empty() {
        bail!("workspace '{}' has no environments (`anvil env create` adds one)", ws.name);
    }
    let active = ws.active_environment_id.and_then(|id| all.into_iter().find(|e| e.meta.id == id));
    active.ok_or_else(|| anyhow!("workspace '{}' has no active environment; name one with --env (`anvil env list` shows them)", ws.name))
}

/// The imported collections (their root folders' names) that brought each
/// environment of `ws`.
fn import_owners(app: &App, ws: &Id) -> Result<Vec<(Id, String)>> {
    Ok(app
        .folders(ws)?
        .into_iter()
        .filter(|f| f.import_root)
        .flat_map(|f| f.import_environment_ids.iter().map(|e| (*e, f.name.clone())).collect::<Vec<_>>())
        .collect())
}

/// The value `set` stores: the argument, stdin or a process environment variable.
fn read_value(value: Option<&str>, value_stdin: bool, value_env: Option<&str>, secret: bool) -> Result<String> {
    if let Some(v) = value {
        if secret {
            bail!(
                "a secret value given as an argument is kept in shell history and visible to other processes; pass it with --value-stdin or --value-env"
            );
        }
        return Ok(v.to_string());
    }
    if let Some(var) = value_env {
        return std::env::var(var).map_err(|_| anyhow!("the environment variable '{var}' is not set (or is not valid UTF-8)"));
    }
    debug_assert!(value_stdin);
    let mut bytes = Vec::new();
    std::io::stdin().lock().take(MAX_VALUE_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_VALUE_BYTES {
        bail!("the value on stdin is larger than 1 MiB");
    }
    let mut s = String::from_utf8(bytes).map_err(|_| anyhow!("the value on stdin is not valid UTF-8"))?;
    if s.ends_with('\n') {
        s.pop();
        if s.ends_with('\r') {
            s.pop();
        }
    }
    Ok(s)
}

fn shown(v: &anvil_domain::workspace::Variable) -> String {
    let value = match &v.value {
        SensitiveValue::Secret { .. } => "‹secret, in the vault›".to_string(),
        SensitiveValue::Template { .. } if v.secret => "‹secret›".to_string(),
        SensitiveValue::Template { value } => value.clone(),
    };
    format!("{}{} = {value}", v.name, if v.enabled { "" } else { " (disabled)" })
}

pub fn env_cmd(app: &App, cmd: &EnvCmd) -> Result<i32> {
    match cmd {
        EnvCmd::List { workspace } => {
            let ws = app.find_workspace(workspace)?;
            let envs = sorted(app.environments(&ws.meta.id)?);
            if envs.is_empty() {
                println!("workspace '{}' has no environments (`anvil env create` adds one)", ws.name);
                return Ok(0);
            }
            let owners = import_owners(app, &ws.meta.id)?;
            for e in &envs {
                let active = if ws.active_environment_id == Some(e.meta.id) { "*" } else { " " };
                let from: Vec<&str> = owners.iter().filter(|(id, _)| *id == e.meta.id).map(|(_, n)| n.as_str()).collect();
                let from = if from.is_empty() { String::new() } else { format!("  (imported with '{}')", from.join("', '")) };
                println!("{active} {}  {}  {} variable(s){from}", e.meta.id, e.name, e.variables.len());
            }
        }
        EnvCmd::Show { workspace, env } => {
            let ws = app.find_workspace(workspace)?;
            let e = target(app, &ws, env.as_deref())?;
            let active = if ws.active_environment_id == Some(e.meta.id) { " (active)" } else { "" };
            println!("environment '{}'{active} of workspace '{}'", e.name, ws.name);
            if e.variables.is_empty() {
                println!("  no variables");
            }
            for v in &e.variables {
                println!("  {}", shown(v));
            }
        }
        EnvCmd::Create { workspace, name, make_active } => {
            let ws = app.find_workspace(workspace)?;
            if name.trim().is_empty() {
                bail!("give the environment a name");
            }
            if app.environments(&ws.meta.id)?.iter().any(|e| e.name.eq_ignore_ascii_case(name)) {
                bail!("workspace '{}' already has an environment named '{name}'", ws.name);
            }
            let e = app.create_environment(&ws.meta.id, name, vec![])?;
            if *make_active {
                app.set_active_environment(&ws.meta.id, Some(&e.meta.id))?;
            }
            println!("{}", e.meta.id);
        }
        EnvCmd::Use { workspace, env, none } => {
            let ws = app.find_workspace(workspace)?;
            if *none {
                app.set_active_environment(&ws.meta.id, None)?;
                println!("workspace '{}' has no active environment now", ws.name);
                return Ok(0);
            }
            let name = env.as_deref().ok_or_else(|| anyhow!("name an environment or pass --none"))?;
            let e = find_environment(app, &ws, name)?;
            app.set_active_environment(&ws.meta.id, Some(&e.meta.id))?;
            println!("'{}' is now the active environment of workspace '{}'", e.name, ws.name);
        }
        EnvCmd::Set { workspace, name, value, env, secret, value_stdin, value_env } => {
            let ws = app.find_workspace(workspace)?;
            let e = target(app, &ws, env.as_deref())?;
            let already_secret = e.variables.iter().any(|v| v.name == *name && v.secret);
            let v = read_value(value.as_deref(), *value_stdin, value_env.as_deref(), *secret || already_secret)?;
            let saved = app.set_environment_variable(&e.meta.id, name, &v, *secret)?;
            let how = if saved.variables.iter().any(|x| x.name == *name && x.secret) { " (secret, kept in the vault)" } else { "" };
            println!("set {name}{how} in environment '{}' of workspace '{}'", saved.name, ws.name);
        }
        EnvCmd::Unset { workspace, name, env } => {
            let ws = app.find_workspace(workspace)?;
            let e = target(app, &ws, env.as_deref())?;
            let (saved, removed) = app.unset_environment_variable(&e.meta.id, name)?;
            if removed {
                println!("removed {name} from environment '{}' of workspace '{}'", saved.name, ws.name);
            } else {
                println!("environment '{}' of workspace '{}' has no variable {name}", saved.name, ws.name);
            }
        }
    }
    Ok(0)
}
