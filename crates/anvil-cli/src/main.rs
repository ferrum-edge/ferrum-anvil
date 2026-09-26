//! `anvil` — headless Ferrum Anvil.
//!
//! Uses exactly the same application services and engine as the desktop app.
//! Exit codes: 0 success · 1 transport/application failure · 2 assertion
//! failure · 3 local/usage error.
//!
//! `anvil run` maps a collection run onto the same codes: 2 when any step
//! failed an assertion (and assertions count as failures), otherwise 1 when
//! any step failed or could not be sent, or the run was canceled/aborted;
//! 3 when the run could not start (untrusted scenario, invalid scenario or
//! dataset, locked profile, usage error).
//!
//! Unlocking a passphrase profile: `--passphrase-stdin` (preferred) or the
//! `ANVIL_PASSPHRASE` environment variable (visible to other processes of the
//! same user; use only in isolated CI). Keychain profiles unlock automatically.

mod collection;
mod specs_load;

use anvil_app::exec::SendOptions;
use anvil_app::port::ImportApproval;
use anvil_app::profiles::{ProfileManager, Unlock};
use anvil_app::{App, AppError};
use anvil_domain::diagnostics::{Confidence, Severity};
use anvil_domain::integration::{IntegrationKind, IntegrationProfile};
use anvil_domain::outcome::{
    ApplicationState, AssertionState, ProtocolStatus, TransportState, WsExtensions, WsNegotiation, WsViolationKind,
};
use anvil_domain::request::{Body, KeyValue, RequestSpec};
use anvil_domain::tls::HostBinding;
use anvil_portability::plan::ConflictPolicy;
use anvil_portability::{BundleError, ExportMode};
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
    /// Run a scenario or every request of a folder (collection runner).
    Run(RunArgs),
    /// Import an API spec or collection (OpenAPI, WSDL, Postman, Insomnia, cURL, HAR).
    ImportSpec(specs_load::ImportSpecArgs),
    /// Load plans, runs (in a worker process) and reports.
    Load {
        #[command(subcommand)]
        cmd: specs_load::LoadCmd,
    },
    /// Manage collection-runner scenarios.
    Scenario {
        #[command(subcommand)]
        cmd: ScenarioCmd,
    },
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
        /// Write into this workspace stored here (repeatable). Merge and
        /// Replace refuse a bundle or full backup that claims a stored
        /// workspace unless it is named here; `--dry-run` lists them under
        /// `plan.existing_workspaces`. Only for files you trust.
        #[arg(long = "into-existing", value_name = "WORKSPACE_ID")]
        into_existing: Vec<String>,
        /// The `bundle_sha256` of the dry run you reviewed: the import is
        /// refused unless the file still has it. Without it,
        /// `--into-existing` approves the file as this command reads it.
        #[arg(long = "bundle-sha256", value_name = "SHA256")]
        bundle_sha256: Option<String>,
    },
    /// Decode a JWT locally (never verifies it).
    Jwt { token: String },
    /// SPIFFE Workload API: what the endpoint issues to this process.
    Workload {
        #[command(subcommand)]
        cmd: WorkloadCmd,
    },
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
enum WorkloadCmd {
    /// Fetch the X.509-SVIDs and JWT bundles (and, with --audience, a
    /// JWT-SVID checked against them) and print what was issued. Keys and
    /// tokens are never printed or kept.
    Probe {
        /// `unix:///path/to/socket` (Windows: `npipe:name`). Default: $SPIFFE_ENDPOINT_SOCKET.
        #[arg(long, default_value = "")]
        endpoint: String,
        /// Also request a JWT-SVID for this audience and check it locally.
        #[arg(long)]
        audience: Option<String>,
        /// Deadline per call, in milliseconds.
        #[arg(long, default_value_t = 5000)]
        timeout_ms: u64,
        /// Print the probe as JSON.
        #[arg(long)]
        json: bool,
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
    /// HTTP version policy for this send (overrides the saved settings).
    #[arg(long, value_enum)]
    http_version: Option<HttpVersionArg>,
    /// Do not reuse a pooled connection for this send.
    #[arg(long)]
    no_keepalive: bool,
    /// Send an eligible request (GET, HEAD, OPTIONS, plus --early-data-method)
    /// as TLS 1.3 / QUIC 0-RTT early data when a session ticket allows it.
    /// Tickets live in memory only, so a single `send` process starts without
    /// one: its record shows the full handshake and the tickets it received.
    #[arg(long)]
    early_data: bool,
    /// With --early-data: an idempotent method (PUT, DELETE, TRACE) that may
    /// also be sent as early data. Repeatable. Other methods are refused.
    #[arg(long = "early-data-method", requires = "early_data")]
    early_data_methods: Vec<String>,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum HttpVersionArg {
    Auto,
    Http1,
    Http2,
    H2c,
    Http3,
    Http3Fallback,
}

impl HttpVersionArg {
    fn policy(self) -> anvil_domain::settings::HttpVersionPolicy {
        use anvil_domain::settings::HttpVersionPolicy as P;
        match self {
            HttpVersionArg::Auto => P::Auto,
            HttpVersionArg::Http1 => P::Http1Only,
            HttpVersionArg::Http2 => P::Http2Only,
            HttpVersionArg::H2c => P::H2c,
            HttpVersionArg::Http3 => P::Http3Only,
            HttpVersionArg::Http3Fallback => P::Http3WithFallback,
        }
    }
}

/// The run-layer settings a `send` asks for on the command line, if any.
fn send_override(s: &SendArgs) -> Option<anvil_domain::settings::SettingsOverrides> {
    if s.http_version.is_none() && !s.no_keepalive && !s.early_data {
        return None;
    }
    Some(anvil_domain::settings::SettingsOverrides {
        http_version: s.http_version.map(HttpVersionArg::policy),
        keepalive: s.no_keepalive.then_some(false),
        early_data: s
            .early_data
            .then(|| anvil_domain::settings::EarlyDataPolicy { enabled: true, extra_methods: s.early_data_methods.clone() }),
        ..Default::default()
    })
}

#[derive(clap::Args)]
struct RunArgs {
    /// Workspace (id or name).
    workspace: String,
    /// Scenario to run (id or name).
    #[arg(long, conflicts_with = "folder", required_unless_present = "folder")]
    scenario: Option<String>,
    /// Folder to run, like `Orders/Refunds` (`/` = every request of the workspace).
    #[arg(long)]
    folder: Option<String>,
    /// Environment name (defaults to the workspace's active environment).
    #[arg(long)]
    env: Option<String>,
    /// CSV or JSON (array of objects) dataset file; replaces the scenario's dataset.
    #[arg(long)]
    dataset: Option<PathBuf>,
    /// Dataset format (inferred from the file extension when omitted).
    #[arg(long, value_enum)]
    dataset_format: Option<DsFormat>,
    /// Dataset column whose values are secrets (repeatable).
    #[arg(long = "sensitive-column")]
    sensitive_columns: Vec<String>,
    /// Iterations (default: the scenario's, else one per dataset row, else 1).
    #[arg(long)]
    iterations: Option<u32>,
    /// Stop each iteration at its first failed step (overrides the scenario).
    #[arg(long, conflicts_with = "continue_on_failure")]
    stop_on_failure: bool,
    /// Run every step even after a failure (overrides the scenario).
    #[arg(long)]
    continue_on_failure: bool,
    /// Dimensions that make a step fail (comma-separated). Default: all three.
    #[arg(long, value_enum, value_delimiter = ',')]
    fail_on: Vec<Dimension>,
    /// Run an untrusted (imported) scenario once, after you reviewed it.
    #[arg(long)]
    allow_untrusted: bool,
    /// Do not record the executed steps in history.
    #[arg(long)]
    no_history: bool,
    /// Write the JSON report here.
    #[arg(long)]
    json: Option<PathBuf>,
    /// Write a JUnit XML report here.
    #[arg(long)]
    junit: Option<PathBuf>,
    /// Write a standalone offline HTML summary here.
    #[arg(long)]
    html: Option<PathBuf>,
    /// No live progress on stderr.
    #[arg(long, short)]
    quiet: bool,
}

#[derive(Subcommand)]
enum ScenarioCmd {
    /// Create a scenario from saved requests, in order.
    Create {
        workspace: String,
        name: String,
        /// Saved request (id, name or Folder/Path/Name); repeat in run order.
        #[arg(long = "step", required = true)]
        steps: Vec<String>,
        /// Iterations (default: one per dataset row, else 1).
        #[arg(long)]
        iterations: Option<u32>,
        #[arg(long)]
        stop_on_failure: bool,
        /// Think time before every step after the first.
        #[arg(long, default_value_t = 0)]
        delay_ms: u64,
        /// Attach a CSV / JSON dataset file (stored in the workspace).
        #[arg(long)]
        dataset: Option<PathBuf>,
        #[arg(long, value_enum)]
        dataset_format: Option<DsFormat>,
        #[arg(long = "sensitive-column")]
        sensitive_columns: Vec<String>,
    },
    List {
        workspace: String,
    },
    Show {
        workspace: String,
        scenario: String,
    },
    /// Mark a reviewed scenario as trusted so it can run (imported scenarios
    /// start untrusted).
    Trust {
        workspace: String,
        scenario: String,
    },
}

#[derive(Copy, Clone, ValueEnum)]
enum DsFormat {
    Csv,
    Json,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum Dimension {
    Transport,
    Application,
    Assertions,
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

/// WebSocket extension negotiation and compression evidence, one fact per line.
fn ws_extension_lines(e: &WsExtensions) -> Vec<String> {
    let state = match e.negotiation {
        WsNegotiation::NotOffered => "not offered",
        WsNegotiation::NotNegotiated => "offered, not negotiated (the session is uncompressed)",
        WsNegotiation::Negotiated => "negotiated",
        WsNegotiation::Rejected => "the server's answer was refused (handshake failed)",
    };
    let mut out = vec![format!("permessage-deflate: {state}")];
    if let Some(o) = &e.offered {
        out.push(format!("  offered:  {o}"));
    }
    out.push(format!("  answered: {}", e.answered.as_deref().unwrap_or("no extension")));
    if let Some(p) = &e.problem {
        out.push(format!("  refused because {p}"));
    }
    if let Some(t) = &e.traffic {
        for (dir, x) in [("sent", t.sent), ("received", t.received)] {
            out.push(format!(
                "  {dir}: {} message(s), {} compressed, {} payload bytes, {} bytes on the wire",
                x.messages, x.compressed_messages, x.payload_bytes, x.wire_bytes
            ));
        }
    }
    if let Some(v) = &e.violation {
        out.push(format!(
            "  ended by {}",
            match v.kind {
                WsViolationKind::CompressedWithoutNegotiation => "a compressed message the peer never negotiated",
                WsViolationKind::Undecodable => "a compressed message from the peer that could not be decompressed",
                WsViolationKind::TooLargeAfterDecompression => "Anvil's message limit, reached while decompressing",
            }
        ));
    }
    out
}

/// One line of 0-RTT evidence for the terminal.
fn early_data_line(e: &anvil_domain::execution::EarlyDataObservation) -> String {
    use anvil_domain::execution::EarlyDataTransport;
    let mut parts = vec![match e.transport {
        EarlyDataTransport::Quic => "QUIC".to_string(),
        EarlyDataTransport::Tls => "TLS/TCP".to_string(),
    }];
    if e.resumption_attempted {
        parts.push(match e.resumption_accepted {
            Some(true) => "session resumed".into(),
            Some(false) => "resumption declined".into(),
            None => "resumption offered".into(),
        });
    }
    if e.offered {
        parts.push(format!(
            "{} bytes offered as early data, {}",
            e.bytes,
            match e.accepted {
                Some(true) => "accepted",
                Some(false) if e.resent_after_handshake => "rejected and re-sent after the handshake",
                Some(false) => "rejected",
                None => "outcome unknown",
            }
        ));
    }
    if let Some(r) = e.not_used {
        parts.push(format!("not used: {r:?}"));
    }
    parts.push(format!("{} ticket(s) received", e.tickets_received));
    parts.join(", ")
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
    if let ProtocolStatus::WebSocket { extensions: Some(e), .. } = &r.outcome.protocol_status {
        for line in ws_extension_lines(e) {
            println!("  {line}");
        }
    }
    for a in &r.attempts {
        if let Some(e) = &a.early_data {
            println!("  early data (attempt {}): {}", a.index, early_data_line(e));
        }
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

/// Stack for the thread that drives the top-level future. Windows gives the
/// main thread only 1 MiB (Linux and macOS: 8 MiB), less than the deepest
/// engine and runner futures need.
const MAIN_STACK: usize = 16 << 20;
/// Stack for runtime worker threads (Tokio's default is 2 MiB).
const WORKER_STACK: usize = 8 << 20;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread().thread_stack_size(WORKER_STACK).enable_all().build().expect("tokio runtime")
}

fn main() {
    let main = std::thread::Builder::new().name("anvil".into()).stack_size(MAIN_STACK).spawn(real_main).expect("start the main thread");
    // `real_main` always exits the process; getting here means it panicked.
    let _ = main.join();
    std::process::exit(101);
}

fn real_main() {
    // `anvil` re-launches itself as the load worker (job on stdin). Exit
    // directly: dropping the runtime would wait on the blocking stdin reader.
    if std::env::args_os().nth(1).is_some_and(|a| a == specs_load::LOAD_WORKER_FLAG) {
        anvil_transport::init();
        // A named binding: a temporary runtime would be dropped at the end of
        // the statement — before `exit` — and wait on the stdin reader forever.
        let rt = runtime();
        let code = rt.block_on(anvil_load::worker::run_stdio());
        std::process::exit(code);
    }
    let code = runtime().block_on(cli_main());
    std::process::exit(code);
}

async fn cli_main() -> i32 {
    anvil_transport::init();
    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(e) => {
            // --help / --version print to stdout and succeed; usage errors
            // are local errors (3), not assertion failures (clap's default 2).
            let code = if e.use_stderr() { 3 } else { 0 };
            let _ = e.print();
            return code;
        }
    };
    match run(cli).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e:#}");
            3
        }
    }
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
        Cmd::Workload { cmd: WorkloadCmd::Probe { endpoint, audience, timeout_ms, json } } => {
            let p = anvil_engine::workload::probe(endpoint, audience.as_deref(), std::time::Duration::from_millis(*timeout_ms)).await;
            if *json {
                println!("{}", serde_json::to_string_pretty(&p)?);
            } else {
                print_probe(&p);
            }
            let ok = p.endpoint_error.is_none()
                && p.calls.iter().all(|c| c.result == anvil_domain::workload::WorkloadCallResult::Ok)
                && p.jwt_svid.as_ref().is_none_or(|j| j.failed_checks().next().is_none());
            Ok(if ok { 0 } else { 2 })
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

fn print_probe(p: &anvil_engine::workload::WorkloadProbe) {
    use anvil_domain::workload::WorkloadCallResult as R;
    println!("endpoint: {}{}", p.endpoint, p.endpoint_source.map(|s| format!(" ({s:?})")).unwrap_or_default());
    if let Some(e) = &p.endpoint_error {
        println!("  not dialed: {e}");
        return;
    }
    for c in &p.calls {
        let res = match &c.result {
            R::Ok => "OK".to_string(),
            R::Unavailable { detail, .. } => format!("unavailable: {detail}"),
            R::Timeout { deadline_ms } => format!("no answer within {deadline_ms} ms"),
            R::Status { code_name, message, .. } => format!("{code_name} {message:?}"),
            R::NoIdentity { detail } => format!("no identity: {detail}"),
            R::Malformed { detail } => format!("malformed answer: {detail}"),
        };
        let uid = c.caller_uid.map(|u| format!(" (this process: uid {u})")).unwrap_or_default();
        println!("  {:<16} {res}{uid}", c.rpc.method());
    }
    for s in &p.x509_svids {
        println!(
            "  X.509-SVID  {}  expires {}  chain {}  bundle {} CA",
            s.spiffe_id,
            s.not_after.to_rfc3339(),
            s.chain_length,
            s.bundle_certificates
        );
    }
    for b in &p.jwt_bundles {
        println!("  JWT bundle  {}  keys {}", b.trust_domain, b.key_ids.join(", "));
    }
    if !p.federated_trust_domains.is_empty() {
        println!("  federated   {}", p.federated_trust_domains.join(", "));
    }
    if let Some(j) = &p.jwt_svid {
        println!(
            "  JWT-SVID    sub {} aud {:?} alg {} (token not shown)",
            j.subject.as_deref().unwrap_or("?"),
            j.audiences,
            j.algorithm.as_deref().unwrap_or("?")
        );
        for c in &j.checks {
            println!("    {:<10} {:?}: {}", format!("{:?}", c.check).to_lowercase(), c.result, c.detail);
        }
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
                        compatibility_id: anvil_diagnostics::ferrum::DEFAULT_COMPATIBILITY_ID.into(),
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
                    SendOptions {
                        environment: env,
                        record_history: !s.no_history,
                        send_anyway: s.send_anyway,
                        run_override: send_override(s),
                        ..Default::default()
                    },
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
        Cmd::Run(a) => collection::run_collection(&app, a).await,
        Cmd::ImportSpec(a) => specs_load::import_spec(&app, a),
        Cmd::Load { cmd } => specs_load::load_cmd(&app, cmd).await,
        Cmd::Scenario { cmd } => collection::scenario_cmd(&app, cmd),
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
            if matches!(m, ExportMode::FullBackup) {
                if ws.is_some() {
                    bail!("a full backup covers every workspace; drop --workspace or choose another --mode");
                }
                if *preview {
                    println!("{}", serde_json::to_string_pretty(&app.backup_preview()?)?);
                    return Ok(0);
                }
                let Some(pass) = export_passphrase().map(Zeroizing::new) else {
                    bail!("encrypted exports need ANVIL_EXPORT_PASSPHRASE (the recipient needs it to restore)");
                };
                let (bytes, p) = app.export_backup(&pass)?;
                std::fs::write(out, &bytes)?;
                println!(
                    "wrote {} ({} bytes, encrypted): {} items, {} secrets, {} excluded",
                    out.display(),
                    bytes.len(),
                    p.manifest.counts.values().sum::<usize>(),
                    p.secrets_included,
                    p.manifest.excluded.len()
                );
                return Ok(0);
            }
            if *preview {
                let p = app.export_preview(ws.as_ref(), m, false)?;
                println!("{}", serde_json::to_string_pretty(&p)?);
                return Ok(0);
            }
            let pass = if matches!(m, ExportMode::ShareSafely) { None } else { export_passphrase() };
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
        Cmd::Import { file, policy, dry_run, into_existing, bundle_sha256 } => {
            let bytes = std::fs::read(file)?;
            let pass = export_passphrase();
            let pol = match policy {
                Policy::Merge => ConflictPolicy::Merge,
                Policy::Replace => ConflictPolicy::Replace,
                Policy::Duplicate => ConflictPolicy::Duplicate,
            };
            let mut approval = ImportApproval::default();
            for w in into_existing {
                approval.existing_workspaces.push(w.parse().with_context(|| format!("invalid workspace id '{w}'"))?);
            }
            // Workspaces named here are approved for the file this command
            // read, unless `--bundle-sha256` names the file a dry run showed.
            if !approval.existing_workspaces.is_empty() || bundle_sha256.is_some() {
                approval.bundle_sha256 = Some(bundle_sha256.clone().unwrap_or_else(|| anvil_app::port::file_sha256(&bytes)));
            }
            // A full backup is restored; anything else is imported as a bundle.
            let rep = match (anvil_app::backup::is_backup(&bytes), *dry_run) {
                (true, true) => app.restore_preview(&bytes, pass.as_deref(), pol),
                (true, false) => app.restore_approved(&bytes, pass.as_deref(), pol, &approval),
                (false, true) => app.import_preview(&bytes, pass.as_deref(), pol),
                (false, false) => app.import_approved(&bytes, pass.as_deref(), pol, &approval),
            };
            let rep = rep.map_err(|e| match e {
                AppError::Bundle(BundleError::NotEncrypted) => anyhow!(
                    "this bundle is not encrypted; unset ANVIL_EXPORT_PASSPHRASE (or leave it empty) to import it; nothing was imported"
                ),
                e => e.into(),
            })?;
            println!("{}", serde_json::to_string_pretty(&rep)?);
            Ok(0)
        }
        _ => unreachable!(),
    }
}

/// The export passphrase from `ANVIL_EXPORT_PASSPHRASE`. An empty value is
/// no passphrase: a bundle without a vault refuses any passphrase.
fn export_passphrase() -> Option<String> {
    std::env::var("ANVIL_EXPORT_PASSPHRASE").ok().filter(|p| !p.is_empty())
}

#[allow(dead_code)]
fn read_all_stdin() -> Result<String> {
    let mut s = String::new();
    std::io::stdin().read_to_string(&mut s)?;
    Ok(s)
}
