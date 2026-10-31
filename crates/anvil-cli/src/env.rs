//! `anvil env`: list, inspect and edit a workspace's environments, so the
//! variables an import asks for (`fill in {{token}}`) can be supplied from
//! the command line. Secret values never come from the command line itself
//! and are never printed. Names and values from storage (an import may have
//! written them) are printed through `terminal_safe`.

use anvil_app::App;
use anvil_contract::terminal_safe as t;
use anvil_domain::Id;
use anvil_domain::secret::SensitiveValue;
use anvil_domain::workspace::{Environment, Variable, Workspace};
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
        /// Workspace (id, or a name no other workspace has).
        workspace: String,
    },
    /// Print an environment's variables (default: the active one). Secret
    /// values are never printed.
    Show {
        /// Workspace (id, or a name no other workspace has).
        workspace: String,
        /// Environment (id or name).
        env: Option<String>,
    },
    /// Create an empty environment.
    Create {
        /// Workspace (id, or a name no other workspace has).
        workspace: String,
        name: String,
        /// Also make it the active environment.
        #[arg(long = "use")]
        make_active: bool,
    },
    /// Make an environment the active one: `send` and `run` use it when no
    /// `--env` is given.
    Use {
        /// Workspace (id, or a name no other workspace has).
        workspace: String,
        /// Environment (id or name).
        #[arg(required_unless_present = "none")]
        env: Option<String>,
        /// Make no environment active.
        #[arg(long, conflicts_with = "env")]
        none: bool,
    },
    /// Set a variable in an environment (default: the active one). Give the
    /// value as an argument, or with --value-stdin or --value-env. The
    /// variable is enabled, and other variables of the same name in the
    /// environment are removed. A secret is kept in the profile's encrypted
    /// vault and must not be an argument; a variable that is secret stays
    /// secret, and the vault entry it held is deleted unless something else
    /// references it.
    Set {
        /// Workspace (id, or a name no other workspace has).
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
        /// Read the value from stdin: all of it, less one trailing newline.
        /// With --passphrase-stdin on a passphrase profile, the value
        /// follows the passphrase line.
        #[arg(long, conflicts_with = "value_env")]
        value_stdin: bool,
        /// Read the value from this process environment variable.
        #[arg(long, value_name = "VAR")]
        value_env: Option<String>,
    },
    /// Remove a variable from an environment (default: the active one), and
    /// the vault entry it held unless something else references it.
    Unset {
        /// Workspace (id, or a name no other workspace has).
        workspace: String,
        name: String,
        /// Environment (id or name). Default: the active environment.
        #[arg(long)]
        env: Option<String>,
    },
}

/// `envs` by name, case ignored, then id: the order they are listed in.
pub fn sorted(mut envs: Vec<Environment>) -> Vec<Environment> {
    envs.sort_by_cached_key(|e| (e.name.to_lowercase(), e.meta.id.to_string()));
    envs
}

fn quoted_names(envs: Vec<Environment>) -> String {
    sorted(envs).iter().map(|e| format!("'{}'", t(&e.name))).collect::<Vec<_>>().join(", ")
}

/// The environment of `ws` that `name` names: its id, or its name with case
/// ignored when no other environment has it. A miss lists the names there are.
pub fn find_environment(app: &App, ws: &Workspace, name: &str) -> Result<Environment> {
    let mut all = app.environments(&ws.meta.id)?;
    if let Some(i) = all.iter().position(|e| e.meta.id.to_string() == name) {
        return Ok(all.swap_remove(i));
    }
    let named: Vec<&Environment> = all.iter().filter(|e| e.name.eq_ignore_ascii_case(name)).collect();
    match named.len() {
        1 => Ok(named[0].clone()),
        0 if all.is_empty() => {
            bail!("environment '{}' not found: workspace '{}' has no environments (`anvil env create` adds one)", t(name), t(&ws.name))
        }
        0 => bail!(
            "environment '{}' not found in workspace '{}'; it has: {} (`anvil env list` shows them)",
            t(name),
            t(&ws.name),
            quoted_names(all)
        ),
        n => bail!(
            "{n} environments of workspace '{}' are named '{}'; name the one you mean by its id: {}",
            t(&ws.name),
            t(name),
            named.iter().map(|e| e.meta.id.to_string()).collect::<Vec<_>>().join(", ")
        ),
    }
}

/// [`find_environment`]'s id, or `None` when no name is given.
pub fn environment_id(app: &App, ws: &Workspace, name: Option<&str>) -> Result<Option<Id>> {
    name.map(|n| find_environment(app, ws, n).map(|e| e.meta.id)).transpose()
}

/// The workspace `id_or_name` names: its id, or its name with case ignored
/// when no other workspace has it. A secret is never written on a guess.
fn find_workspace(app: &App, id_or_name: &str) -> Result<Workspace> {
    let mut all = app.workspaces()?;
    if let Some(i) = all.iter().position(|w| w.meta.id.to_string() == id_or_name) {
        return Ok(all.swap_remove(i));
    }
    let mut named: Vec<Workspace> = all.into_iter().filter(|w| w.name.eq_ignore_ascii_case(id_or_name)).collect();
    match named.len() {
        1 => Ok(named.remove(0)),
        0 => bail!("workspace '{}' not found (`anvil workspace list` shows them)", t(id_or_name)),
        n => bail!(
            "{n} workspaces are named '{}'; name the one you mean by its id: {}",
            t(id_or_name),
            named.iter().map(|w| w.meta.id.to_string()).collect::<Vec<_>>().join(", ")
        ),
    }
}

/// `name`, or else the workspace's active environment.
fn target(app: &App, ws: &Workspace, name: Option<&str>) -> Result<Environment> {
    if let Some(n) = name {
        return find_environment(app, ws, n);
    }
    let all = app.environments(&ws.meta.id)?;
    if all.is_empty() {
        bail!("workspace '{}' has no environments (`anvil env create` adds one)", t(&ws.name));
    }
    let active = ws.active_environment_id.and_then(|id| all.into_iter().find(|e| e.meta.id == id));
    active
        .ok_or_else(|| anyhow!("workspace '{}' has no active environment; name one with --env (`anvil env list` shows them)", t(&ws.name)))
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
        return std::env::var(var).map_err(|_| anyhow!("the environment variable '{}' is not set (or is not valid UTF-8)", t(var)));
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

fn shown(v: &Variable) -> String {
    let value = match &v.value {
        SensitiveValue::Secret { .. } => "‹secret, in the vault›".to_string(),
        SensitiveValue::Template { .. } if v.secret => "‹secret›".to_string(),
        SensitiveValue::Template { value } => t(value),
    };
    format!("{}{} = {value}", t(&v.name), if v.enabled { "" } else { " (disabled)" })
}

pub fn env_cmd(app: &App, cmd: &EnvCmd) -> Result<i32> {
    match cmd {
        EnvCmd::List { workspace } => {
            let ws = find_workspace(app, workspace)?;
            let envs = sorted(app.environments(&ws.meta.id)?);
            if envs.is_empty() {
                println!("workspace '{}' has no environments (`anvil env create` adds one)", t(&ws.name));
                return Ok(0);
            }
            let owners = import_owners(app, &ws.meta.id)?;
            for e in &envs {
                let active = if ws.active_environment_id == Some(e.meta.id) { "*" } else { " " };
                let from: Vec<String> = owners.iter().filter(|(id, _)| *id == e.meta.id).map(|(_, n)| t(n)).collect();
                let from = if from.is_empty() { String::new() } else { format!("  (imported with '{}')", from.join("', '")) };
                println!("{active} {}  {}  {} variable(s){from}", e.meta.id, t(&e.name), e.variables.len());
            }
        }
        EnvCmd::Show { workspace, env } => {
            let ws = find_workspace(app, workspace)?;
            let e = target(app, &ws, env.as_deref())?;
            let active = if ws.active_environment_id == Some(e.meta.id) { " (active)" } else { "" };
            println!("environment '{}'{active} of workspace '{}'", t(&e.name), t(&ws.name));
            if e.variables.is_empty() {
                println!("  no variables");
            }
            for v in &e.variables {
                println!("  {}", shown(v));
            }
        }
        EnvCmd::Create { workspace, name, make_active } => {
            let ws = find_workspace(app, workspace)?;
            let e = app.create_named_environment(&ws.meta.id, name, *make_active)?;
            println!("{}", e.meta.id);
        }
        EnvCmd::Use { workspace, env, none } => {
            let ws = find_workspace(app, workspace)?;
            if *none {
                app.set_active_environment(&ws.meta.id, None)?;
                println!("workspace '{}' has no active environment now", t(&ws.name));
                return Ok(0);
            }
            let name = env.as_deref().ok_or_else(|| anyhow!("name an environment or pass --none"))?;
            let e = find_environment(app, &ws, name)?;
            app.set_active_environment(&ws.meta.id, Some(&e.meta.id))?;
            println!("'{}' is now the active environment of workspace '{}'", t(&e.name), t(&ws.name));
        }
        EnvCmd::Set { workspace, name, value, env, secret, value_stdin, value_env } => {
            let ws = find_workspace(app, workspace)?;
            let e = target(app, &ws, env.as_deref())?;
            // The same rule as the store's: secret if any variable of the name is.
            let already_secret = e.variables.iter().any(|v| v.name == *name && v.is_secret());
            let v = read_value(value.as_deref(), *value_stdin, value_env.as_deref(), *secret || already_secret)?;
            let saved = app.set_environment_variable(&e.meta.id, name, &v, *secret)?;
            let how = if saved.variables.iter().any(|x| x.name == *name && x.is_secret()) { " (secret, kept in the vault)" } else { "" };
            println!("set {}{how} in environment '{}' of workspace '{}'", t(name), t(&saved.name), t(&ws.name));
        }
        EnvCmd::Unset { workspace, name, env } => {
            let ws = find_workspace(app, workspace)?;
            let e = target(app, &ws, env.as_deref())?;
            let (saved, removed) = app.unset_environment_variable(&e.meta.id, name)?;
            if removed {
                println!("removed {} from environment '{}' of workspace '{}'", t(name), t(&saved.name), t(&ws.name));
            } else {
                println!("environment '{}' of workspace '{}' has no variable {}", t(&saved.name), t(&ws.name), t(name));
            }
        }
    }
    Ok(0)
}
