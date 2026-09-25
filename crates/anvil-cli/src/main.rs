//! `anvil` — headless Ferrum Anvil.
//!
//! Uses exactly the same application services and engine as the desktop app.
//! Exit codes: 0 success · 1 transport/application failure · 2 assertion
//! failure · 3 local/usage error.
//!
//! Unlocking a passphrase profile: `--passphrase-stdin` (preferred) or the
//! `ANVIL_PASSPHRASE` environment variable (visible to other processes of the
//! same user; use only in isolated CI). Keychain profiles unlock automatically.

use anvil_app::App;
use anvil_app::exec::SendOptions;
use anvil_app::profiles::{ProfileManager, Unlock};
use anvil_domain::diagnostics::{Confidence, Severity};
use anvil_domain::integration::{IntegrationKind, IntegrationProfile};
use anvil_domain::outcome::{ApplicationState, AssertionState, TransportState};
use anvil_domain::request::{Body, KeyValue, RequestSpec};
use anvil_domain::tls::HostBinding;
use anvil_portability::ExportMode;
use anvil_portability::plan::ConflictPolicy;
use anvil_storage::KdfParams;
use anvil_transport::recorder::EventCtx;
use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand, ValueEnum};
use std::io::Read;
use std::path::PathBuf;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(name = "anvil", version, about = "Ferrum Anvil — put your APIs to the test (headless)")]
struct Cli {
    /// Data directory (defaults to the platform application-data directory).
    #[arg(long, env = "ANVIL_DATA_DIR", global = true)]
    data_dir: Option<PathBuf>,
    /// Profile name or id (defaults to the only/first profile).
    #[arg(long, env = "ANVIL_PROFILE", global = true)]
    profile: Option<String>,
    /// Read the profile passphrase from stdin (first line).
    #[arg(long, global = true)]
    passphrase_stdin: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Manage local profiles.
    Profile {
        #[command(subcommand)]
        cmd: ProfileCmd,
    },
    /// Manage workspaces.
    Workspace {
        #[command(subcommand)]
        cmd: WorkspaceCmd,
    },
    /// Save a request into a workspace.
    Add(AddArgs),
    /// Send a saved request or an ad-hoc URL and print the diagnosis.
    Send(SendArgs),
    /// List recent history.
    History {
        #[arg(long)]
        workspace: Option<String>,
        #[arg(short = 'n', default_value_t = 20)]
        limit: usize,
    },
    /// Export a workspace (or everything) to a bundle.
    Export {
        #[arg(long)]
        workspace: Option<String>,
        #[arg(long, value_enum, default_value_t = Mode::Share)]
        mode: Mode,
        #[arg(long)]
        out: PathBuf,
        /// Only print what would be included/excluded.
        #[arg(long)]
        preview: bool,
    },
    /// Import a bundle (previewed first; `--dry-run` stops after the preview).
    Import {
        file: PathBuf,
        #[arg(long, value_enum, default_value_t = Policy::Merge)]
        policy: Policy,
        #[arg(long)]
        dry_run: bool,
    },
    /// Decode a JWT locally (never verifies it).
    Jwt { token: String },
    /// Write the JSON Schemas of the data contracts.
    Schema {
        #[arg(long, default_value = "contracts/schemas")]
        out: PathBuf,
    },
    /// Environment self-check (data dir, trust store, keychain).
    Doctor,
}

#[derive(Subcommand)]
enum ProfileCmd {
    List,
    Create {
        name: String,
        /// Store the data key in the OS credential store instead of a passphrase.
        #[arg(long)]
        keychain: bool,
    },
}

#[derive(Subcommand)]
enum WorkspaceCmd {
    List,
    Create { name: String },
    Tree { workspace: String },
}

#[derive(clap::Args)]
struct AddArgs {
    workspace: String,
    name: String,
    #[arg(long, default_value = "GET")]
    method: String,
    #[arg(long)]
    url: String,
    /// Folder path like `Orders/Refunds` (created if missing).
    #[arg(long)]
    folder: Option<String>,
    #[arg(short = 'H', long = "header")]
    headers: Vec<String>,
    #[arg(long)]
    json: Option<String>,
}

#[derive(clap::Args)]
struct SendArgs {
    /// Saved request (id, name or Folder/Path/Name). Omit to send `--url`.
    request: Option<String>,
    #[arg(long)]
    workspace: Option<String>,
    #[arg(long)]
    url: Option<String>,
    #[arg(long, short = 'X', default_value = "GET")]
    method: String,
    #[arg(short = 'H', long = "header")]
    headers: Vec<String>,
    #[arg(long)]
    data: Option<String>,
    #[arg(long)]
    env: Option<String>,
    /// Treat this host as a trusted Ferrum gateway for this send (lab use; plain HTTP caps confidence).
    #[arg(long)]
    trust_ferrum: Option<String>,
    /// Print the full execution record as JSON.
    #[arg(long)]
    json: bool,
    #[arg(long)]
    no_history: bool,
    /// Send even if the body fails syntax lint.
    #[arg(long)]
    send_anyway: bool,
}

#[derive(Copy, Clone, ValueEnum)]
enum Mode {
    Share,
    Encrypted,
    Backup,
}

#[derive(Copy, Clone, ValueEnum)]
enum Policy {
    Merge,
    Replace,
    Duplicate,
}

fn passphrase(from_stdin: bool, env: &str) -> Result<Option<Zeroizing<String>>> {
    if from_stdin {
        let mut s = String::new();
        std::io::stdin().read_line(&mut s)?;
        return Ok(Some(Zeroizing::new(s.trim_end_matches(['\r', '\n']).to_string())));
    }
    Ok(std::env::var(env).ok().map(Zeroizing::new))
}

fn open_app(cli: &Cli) -> Result<App> {
    let root = cli.data_dir.clone().unwrap_or_else(anvil_storage::default_data_dir);
    let pm = ProfileManager::new(&root);
    let summary = match &cli.profile {
        Some(p) => pm.find(p)?,
        None => pm.list().into_iter().next().ok_or_else(|| anyhow!("no profile exists; run `anvil profile create <name>`"))?,
    };
    let (header, key) = match summary.protection {
        anvil_domain::workspace::ProtectionMode::OsKeychain => ProfileManager::unlock(&summary.dir, Unlock::Keychain)?,
        anvil_domain::workspace::ProtectionMode::Passphrase => {
            let p = passphrase(cli.passphrase_stdin, "ANVIL_PASSPHRASE")?
                .ok_or_else(|| anyhow!("profile '{}' is locked: pass --passphrase-stdin or set ANVIL_PASSPHRASE", summary.display_name))?;
            ProfileManager::unlock(&summary.dir, Unlock::Passphrase(&p))?
        }
    };
    Ok(App::open(summary.dir, header, key)?)
}

fn kv(h: &str) -> Result<KeyValue> {
    let (n, v) = h.split_once(':').ok_or_else(|| anyhow!("header '{h}' must be 'Name: value'"))?;
    Ok(KeyValue::new(n.trim(), v.trim_start()))
}

fn print_outcome(out: &anvil_engine::ExecutionOutput, json: bool) {
    let r = &out.record;
    if json {
        println!("{}", serde_json::to_string_pretty(r).unwrap_or_default());
        return;
    }
    println!("{} {}", r.prepared.method, r.prepared.url);
    println!("  {}", r.outcome.summary);
    println!(
        "  transport={:?} application={:?} assertions={:?} dispatch={:?}",
        r.outcome.transport, r.outcome.application, r.outcome.assertions, r.outcome.dispatch
    );
    if let Some(a) = r.attempts.last() {
        let phases: Vec<String> = a
            .phases
            .iter()
            .map(|p| match p.duration_us() {
                Some(d) => format!("{:?} {:.1}ms", p.phase, d as f64 / 1000.0),
                None => format!("{:?} {:?}", p.phase, p.status),
            })
            .collect();
        println!("  phases: {}", phases.join(" · "));
    }
    for w in &r.outcome.warnings {
        println!("  ! {}", w.message);
    }
    for f in &r.findings {
        let conf = match f.confidence {
            Confidence::Confirmed => "confirmed",
            Confidence::Likely => "likely",
            Confidence::Unknown => "unknown",
            Confidence::ConflictingEvidence => "conflicting evidence",
        };
        let mark = match f.severity {
            Severity::Error => "✗",
            Severity::Warning => "!",
            Severity::Info => "i",
        };
        println!("\n  {mark} {} [{conf}; {:?}]", f.title, f.scope);
        println!("    {}", f.explanation);
        for d in f.does_not_prove.iter().take(3) {
            println!("    does not prove: {d}");
        }
        for rem in f.remediation.iter().take(3) {
            println!("    next ({:?}): {}", rem.owner, rem.text);
        }
    }
    for a in &r.assertion_results {
        println!("  {} {} — {}", if a.passed { "✓" } else { "✗" }, a.label, a.message);
    }
}

#[tokio::main]
async fn main() {
    anvil_transport::init();
    let cli = Cli::parse();
    let code = match run(cli).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e:#}");
            3
        }
    };
    std::process::exit(code);
}

async fn run(cli: Cli) -> Result<i32> {
    match &cli.cmd {
        Cmd::Profile { cmd } => {
            let root = cli.data_dir.clone().unwrap_or_else(anvil_storage::default_data_dir);
            let pm = ProfileManager::new(&root);
            match cmd {
                ProfileCmd::List => {
                    for p in pm.list() {
                        println!("{}  {:?}  {}  {}", p.profile_id, p.protection, p.display_name, p.dir.display());
                    }
                }
                ProfileCmd::Create { name, keychain } => {
                    if *keychain {
                        let (s, _) = pm.create_keychain(name)?;
                        println!("created keychain-protected profile {} ({})", s.display_name, s.profile_id);
                    } else {
                        let p = passphrase(cli.passphrase_stdin, "ANVIL_PASSPHRASE")?
                            .ok_or_else(|| anyhow!("provide the new passphrase with --passphrase-stdin or ANVIL_PASSPHRASE"))?;
                        let (s, _, recovery) = pm.create_passphrase(name, &p, KdfParams::interactive())?;
                        println!("created passphrase-protected profile {} ({})", s.display_name, s.profile_id);
                        println!("RECOVERY KEY (shown once; store it offline): {}", recovery.as_str());
                    }
                }
            }
            Ok(0)
        }
        Cmd::Schema { out } => {
            std::fs::create_dir_all(out)?;
            for (name, schema) in anvil_domain::schema::all() {
                let mut bytes = serde_json::to_vec_pretty(&schema)?;
                bytes.push(b'\n');
                std::fs::write(out.join(format!("{name}.schema.json")), bytes)?;
            }
            println!("wrote {} schemas to {}", anvil_domain::schema::all().len(), out.display());
            Ok(0)
        }
        Cmd::Jwt { token } => {
            let i = anvil_auth::jwt::inspect(token, chrono::Utc::now(), 0).map_err(|e| anyhow!(e.to_string()))?;
            println!("{}", serde_json::to_string_pretty(&i)?);
            Ok(0)
        }
        Cmd::Doctor => {
            let root = cli.data_dir.clone().unwrap_or_else(anvil_storage::default_data_dir);
            println!("data dir: {}", root.display());
            let (n, errs) = anvil_transport::tls::system_root_status();
            println!(
                "system trust store: {n} roots loaded{}",
                if errs.is_empty() { String::new() } else { format!(" ({} load errors)", errs.len()) }
            );
            println!("profiles: {}", ProfileManager::new(&root).list().len());
            println!("engine: {} · catalog: {}", anvil_transport::ADAPTER_VERSION, anvil_diagnostics_version());
            Ok(0)
        }
        _ => run_with_app(&cli).await,
    }
}

fn anvil_diagnostics_version() -> String {
    anvil_diagnostics::catalog_version()
}

async fn run_with_app(cli: &Cli) -> Result<i32> {
    let app = open_app(cli)?;
    match &cli.cmd {
        Cmd::Workspace { cmd } => match cmd {
            WorkspaceCmd::List => {
                for w in app.workspaces()? {
                    println!("{}  {}", w.meta.id, w.name);
                }
                Ok(0)
            }
            WorkspaceCmd::Create { name } => {
                let w = app.create_workspace(name)?;
                println!("{}", w.meta.id);
                Ok(0)
            }
            WorkspaceCmd::Tree { workspace } => {
                let w = app.find_workspace(workspace)?;
                fn print(nodes: &[anvil_app::workspace::TreeNode], depth: usize) {
                    for n in nodes {
                        match n.kind {
                            "folder" => println!("{}▸ {}", "  ".repeat(depth), n.name),
                            _ => println!(
                                "{}{} {}  {}",
                                "  ".repeat(depth),
                                n.method.clone().unwrap_or_default(),
                                n.name,
                                n.url.clone().unwrap_or_default()
                            ),
                        }
                        print(&n.children, depth + 1);
                    }
                }
                print(&app.tree(&w.meta.id)?, 0);
                Ok(0)
            }
        },
        Cmd::Add(a) => {
            let w = app.find_workspace(&a.workspace)?;
            let mut parent = None;
            if let Some(path) = &a.folder {
                for seg in path.split('/').filter(|s| !s.is_empty()) {
                    let existing = app.folders(&w.meta.id)?.into_iter().find(|f| f.parent_id == parent && f.name == seg);
                    parent = Some(match existing {
                        Some(f) => f.meta.id,
                        None => app.create_folder(&w.meta.id, parent, seg)?.meta.id,
                    });
                }
            }
            let mut spec = RequestSpec::http(&a.method, &a.url);
            for h in &a.headers {
                spec.headers.push(kv(h)?);
            }
            if let Some(j) = &a.json {
                spec.body = Body::Json { text: j.clone() };
            }
            let r = app.create_request(&w.meta.id, parent, &a.name, spec)?;
            println!("{}", r.meta.id);
            Ok(0)
        }
        Cmd::Send(s) => {
            let ws = match &s.workspace {
                Some(w) => app.find_workspace(w)?,
                None => match app.workspaces()?.into_iter().next() {
                    Some(w) => w,
                    None => app.create_workspace("Default")?,
                },
            };
            let env = match &s.env {
                Some(e) => Some(
                    app.environments(&ws.meta.id)?
                        .into_iter()
                        .find(|x| x.name.eq_ignore_ascii_case(e))
                        .ok_or_else(|| anyhow!("environment '{e}' not found"))?
                        .meta
                        .id,
                ),
                None => None,
            };
            if let Some(host) = &s.trust_ferrum
                && !app
                    .integrations(&ws.meta.id)?
                    .iter()
                    .any(|i| matches!(&i.kind, IntegrationKind::FerrumGateway { hosts, .. } if hosts.iter().any(|h| h.host == *host)))
            {
                let now = chrono::Utc::now();
                app.save_integration(IntegrationProfile {
                    id: anvil_domain::Id::new(),
                    workspace_id: ws.meta.id,
                    name: format!("Ferrum gateway {host}"),
                    kind: IntegrationKind::FerrumGateway {
                        hosts: vec![HostBinding { host: host.clone(), port: None }],
                        compatibility_id: "ferrum-edge-0.9.5".into(),
                        require_verified_tls: false,
                        detail: None,
                        console_url: None,
                    },
                    created_at: now,
                    updated_at: now,
                })?;
            }
            let (rid, draft) = match (&s.request, &s.url) {
                (Some(r), _) => (Some(app.find_request(&ws.meta.id, r)?.meta.id), None),
                (None, Some(u)) => {
                    let mut spec = RequestSpec::http(&s.method, u);
                    for h in &s.headers {
                        spec.headers.push(kv(h)?);
                    }
                    if let Some(d) = &s.data {
                        spec.body = Body::Raw { text: d.clone(), content_type: None };
                    }
                    (None, Some(spec))
                }
                (None, None) => bail!("give a saved request or --url"),
            };
            let cancel = CancellationToken::new();
            let c2 = cancel.clone();
            tokio::spawn(async move {
                if tokio::signal::ctrl_c().await.is_ok() {
                    c2.cancel();
                }
            });
            let out = app
                .send(
                    rid,
                    &ws.meta.id,
                    draft,
                    SendOptions { environment: env, record_history: !s.no_history, send_anyway: s.send_anyway, ..Default::default() },
                    EventCtx::none(),
                    cancel,
                )
                .await
                .context("send")?;
            print_outcome(&out, s.json);
            let o = &out.record.outcome;
            Ok(if o.assertions == AssertionState::Fail {
                2
            } else if o.transport != TransportState::Completed || o.application == ApplicationState::Failure {
                1
            } else {
                0
            })
        }
        Cmd::History { workspace, limit } => {
            let ws = match workspace {
                Some(w) => Some(app.find_workspace(w)?.meta.id),
                None => None,
            };
            for h in app.store.list_history(ws.as_ref(), None, *limit)? {
                if let Some((rec, _)) = app.store.get_history::<anvil_domain::execution::ExecutionRecord>(&h.id)? {
                    println!("{}  {}  {}", rec.started_at.format("%Y-%m-%d %H:%M:%S"), rec.prepared.url, rec.outcome.summary);
                }
            }
            Ok(0)
        }
        Cmd::Export { workspace, mode, out, preview } => {
            let ws = match workspace {
                Some(w) => Some(app.find_workspace(w)?.meta.id),
                None => None,
            };
            let m = match mode {
                Mode::Share => ExportMode::ShareSafely,
                Mode::Encrypted => ExportMode::EncryptedTransfer,
                Mode::Backup => ExportMode::FullBackup,
            };
            if *preview {
                let p = app.export_preview(ws.as_ref(), m, false)?;
                println!("{}", serde_json::to_string_pretty(&p)?);
                return Ok(0);
            }
            let pass = if matches!(m, ExportMode::ShareSafely) { None } else { std::env::var("ANVIL_EXPORT_PASSPHRASE").ok() };
            if !matches!(m, ExportMode::ShareSafely) && pass.is_none() {
                bail!("encrypted exports need ANVIL_EXPORT_PASSPHRASE (the recipient needs it to restore)");
            }
            let (bytes, p) = app.export(ws.as_ref(), m, pass.as_deref(), false)?;
            std::fs::write(out, &bytes)?;
            println!(
                "wrote {} ({} bytes): {} objects, {} secrets, {} excluded",
                out.display(),
                bytes.len(),
                p.manifest.counts.values().sum::<usize>(),
                p.secrets_included,
                p.manifest.excluded.len()
            );
            for w in &p.manifest.content_warnings {
                println!("  ! {} {}", w.pointer, w.reason);
            }
            Ok(0)
        }
        Cmd::Import { file, policy, dry_run } => {
            let bytes = std::fs::read(file)?;
            let pass = std::env::var("ANVIL_EXPORT_PASSPHRASE").ok();
            let pol = match policy {
                Policy::Merge => ConflictPolicy::Merge,
                Policy::Replace => ConflictPolicy::Replace,
                Policy::Duplicate => ConflictPolicy::Duplicate,
            };
            let rep = if *dry_run { app.import_preview(&bytes, pass.as_deref(), pol)? } else { app.import(&bytes, pass.as_deref(), pol)? };
            println!("{}", serde_json::to_string_pretty(&rep)?);
            Ok(0)
        }
        _ => unreachable!(),
    }
}

#[allow(dead_code)]
fn read_all_stdin() -> Result<String> {
    let mut s = String::new();
    std::io::stdin().read_to_string(&mut s)?;
    Ok(s)
}
