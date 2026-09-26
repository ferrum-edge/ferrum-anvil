//! Manages a real Ferrum Edge release binary for the lab.

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use tokio::process::{Child, Command};

pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().expect("repo root")
}

pub fn asset_name() -> &'static str {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => "ferrum-edge-macos-aarch64",
        ("macos", "x86_64") => "ferrum-edge-macos-x86_64",
        ("linux", "aarch64") => "ferrum-edge-linux-aarch64",
        ("linux", "x86_64") => "ferrum-edge-linux-x86_64",
        ("windows", "x86_64") => "ferrum-edge-windows-x86_64.exe",
        _ => "unsupported-platform",
    }
}

#[derive(Clone, Debug)]
pub struct Lock {
    pub release: String,
    pub source_sha: String,
    pub sha256: String,
    /// The lock file this was read from (relative to the repository root).
    pub file: String,
}

impl Lock {
    /// The Anvil compatibility id (and diagnostics catalog) of this release,
    /// e.g. `v0.9.7` -> `ferrum-edge-0.9.7`.
    pub fn compatibility_id(&self) -> String {
        compatibility_id_for(&self.release)
    }
}

pub fn compatibility_id_for(release: &str) -> String {
    format!("ferrum-edge-{}", release.trim().trim_start_matches('v'))
}

/// The default pin: the lab runs this release unless another is selected.
pub const DEFAULT_LOCK: &str = "lab/gateway/RELEASE.lock";
/// Every supported release has `<dir>/<release>.lock`.
pub const RELEASES_DIR: &str = "lab/gateway/releases";

static SELECTED_RELEASE: OnceLock<Option<String>> = OnceLock::new();

/// Select the gateway release for this process (`--release`), falling back to
/// `$ANVIL_LAB_RELEASE`, then to the default pin. Call before anything reads
/// the lock; later calls are ignored.
pub fn select_release(release: Option<String>) {
    let _ = SELECTED_RELEASE.set(normalize_release(release.or_else(|| std::env::var("ANVIL_LAB_RELEASE").ok())));
}

fn normalize_release(r: Option<String>) -> Option<String> {
    r.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).map(|s| if s.starts_with('v') { s } else { format!("v{s}") })
}

fn selected_release() -> Option<String> {
    SELECTED_RELEASE.get_or_init(|| normalize_release(std::env::var("ANVIL_LAB_RELEASE").ok())).clone()
}

/// Releases with a lock under `lab/gateway/releases/`, sorted.
pub fn available_releases() -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(repo_root().join(RELEASES_DIR))
        .map(|d| d.flatten().filter_map(|e| e.file_name().to_str().and_then(|n| n.strip_suffix(".lock")).map(String::from)).collect())
        .unwrap_or_default();
    v.sort();
    v
}

fn parse_lock(text: &str, file: &str) -> Result<Lock> {
    let mut release = String::new();
    let mut source_sha = String::new();
    let mut sha256 = String::new();
    for line in text.lines().filter(|l| !l.starts_with('#')) {
        let mut p = line.split_whitespace();
        match (p.next(), p.next()) {
            (Some("release"), Some(v)) => release = v.into(),
            (Some("source_sha"), Some(v)) => source_sha = v.into(),
            (Some(n), Some(v)) if n == asset_name() => sha256 = v.into(),
            _ => {}
        }
    }
    if release.is_empty() {
        bail!("{file} names no release");
    }
    if sha256.is_empty() {
        bail!("no pinned checksum for {} in {file}", asset_name());
    }
    Ok(Lock { release, source_sha, sha256, file: file.into() })
}

/// Read the lock of the selected release (`lab/gateway/releases/<release>.lock`)
/// or, when none is selected, the default pin `lab/gateway/RELEASE.lock`.
pub fn read_lock() -> Result<Lock> {
    let root = repo_root();
    let Some(release) = selected_release() else {
        return parse_lock(
            &std::fs::read_to_string(root.join(DEFAULT_LOCK)).with_context(|| format!("reading {DEFAULT_LOCK}"))?,
            DEFAULT_LOCK,
        );
    };
    if !release.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')) {
        bail!("invalid release name {release:?}");
    }
    let file = format!("{RELEASES_DIR}/{release}.lock");
    let text = std::fs::read_to_string(root.join(&file))
        .with_context(|| format!("no lock for Ferrum Edge {release} ({file}); supported releases: {}", available_releases().join(", ")))?;
    let lock = parse_lock(&text, &file)?;
    if lock.release != release {
        bail!("{file} pins {} instead of {release}", lock.release);
    }
    Ok(lock)
}

/// The lock of this process's release, read once.
pub fn current_lock() -> &'static Lock {
    static L: OnceLock<Lock> = OnceLock::new();
    L.get_or_init(|| read_lock().unwrap_or_else(|e| panic!("reading the lab gateway lock: {e:#}")))
}

/// Compatibility id of the release under test; every lab profile declares it
/// in its trusted Ferrum integration profile, so diagnoses use that
/// release's catalog.
pub fn compatibility_id() -> String {
    current_lock().compatibility_id()
}

/// `Ferrum Edge 0.9.7`-style name of the release under test, for skip reasons.
pub fn release_label() -> String {
    format!("Ferrum Edge {}", current_lock().release.trim_start_matches('v'))
}

/// Fill `{release}` in a skip reason with the release under test. Reasons
/// using it state facts checked in the source of every supported release.
pub fn release_text(s: &str) -> String {
    s.replace("{release}", &release_label())
}

/// Candidate paths for the release's binary, in lookup order:
/// `$ANVIL_LAB_FERRUM_BIN`, `lab/bin/<release>/<asset>`,
/// `../lab-bin/<release>/<asset>`, then the legacy unversioned
/// `lab/bin/<asset>` and `../lab-bin/<asset>`.
fn candidates(lock: &Lock) -> Vec<(PathBuf, bool)> {
    let root = repo_root();
    let explicit = std::env::var("ANVIL_LAB_FERRUM_BIN").ok().filter(|s| !s.is_empty()).map(|p| (PathBuf::from(p), true));
    explicit
        .into_iter()
        .chain([
            (root.join("lab/bin").join(&lock.release).join(asset_name()), true),
            (root.join("../lab-bin").join(&lock.release).join(asset_name()), true),
            // Legacy locations hold whichever release was fetched last: a
            // binary of another release there is skipped, never run.
            (root.join("lab/bin").join(asset_name()), false),
            (root.join("../lab-bin").join(asset_name()), false),
        ])
        .collect()
}

/// Locate and verify the selected release's gateway binary. A binary is only
/// ever returned when its sha256 equals the lock's pin.
pub fn binary() -> Result<(PathBuf, Lock)> {
    let lock = read_lock()?;
    let mut skipped = Vec::new();
    for (c, must_match) in candidates(&lock) {
        if c.exists() {
            let bytes = std::fs::read(&c)?;
            let got = hex::encode(Sha256::digest(&bytes));
            if got == lock.sha256 {
                return Ok((c, lock));
            }
            if must_match {
                bail!(
                    "{} has sha256 {got}, but {} pins {} for Ferrum Edge {} — refusing to run an unverified gateway",
                    c.display(),
                    lock.file,
                    lock.sha256,
                    lock.release
                );
            }
            skipped.push(format!("{} (another release: sha256 {got})", c.display()));
        }
    }
    let note = if skipped.is_empty() { String::new() } else { format!("; skipped {}", skipped.join(", ")) };
    bail!(
        "Ferrum Edge {} binary not found; run lab/scripts/fetch-gateway.sh {} (it verifies the pinned sha256){note}",
        lock.release,
        lock.release
    )
}

pub struct Gateway {
    pub child: Child,
    pub profile: String,
    pub admin: String,
    pub log_path: PathBuf,
    #[allow(dead_code)] // kept for debugging output paths
    pub run_dir: PathBuf,
}

/// Render `{{TOKENS}}` in a profile file.
pub fn render(text: &str, vars: &[(&str, String)]) -> String {
    let mut out = text.to_string();
    for (k, v) in vars {
        out = out.replace(&format!("{{{{{k}}}}}"), v);
    }
    out
}

/// When a started instance counts as up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Readiness {
    /// Admin `/health` reports `ready:true` (file mode, CP, a DP that has a snapshot).
    Ready,
    /// Admin `/live` answers: the process serves traffic but may never become
    /// ready (a data plane whose control plane is unreachable).
    Live,
}

/// One gateway process. `Gateway::start` is the file-mode shorthand; CP/DP
/// profiles run several instances with their own run directories.
pub struct Instance<'a> {
    /// Run directory name under `lab/.run/`.
    pub name: &'a str,
    /// `file`, `cp` or `dp`.
    pub mode: &'a str,
    pub conf: &'a str,
    /// Resource file (`-c`); file mode only.
    pub yaml: Option<&'a str>,
    pub vars: &'a [(&'a str, String)],
    pub admin_port: u16,
    /// Extra environment; a key here replaces the generated default.
    pub env: &'a [(&'a str, String)],
    pub readiness: Readiness,
    /// Append to an existing operator log (a restarted instance) instead of truncating it.
    pub append_log: bool,
}

impl Gateway {
    pub async fn start(
        profile: &str,
        conf_name: &str,
        yaml_name: &str,
        vars: &[(&str, String)],
        admin_port: u16,
        extra_env: &[(&str, String)],
    ) -> Result<Gateway> {
        Self::launch(Instance {
            name: profile,
            mode: "file",
            conf: conf_name,
            yaml: Some(yaml_name),
            vars,
            admin_port,
            env: extra_env,
            readiness: Readiness::Ready,
            append_log: false,
        })
        .await
    }

    pub async fn launch(i: Instance<'_>) -> Result<Gateway> {
        let (bin, _lock) = binary()?;
        let root = repo_root();
        let profile = i.name;
        let run_dir = root.join("lab/.run").join(profile);
        std::fs::create_dir_all(&run_dir)?;
        let conf =
            render(&std::fs::read_to_string(root.join("lab/gateway").join(i.conf)).with_context(|| format!("reading {}", i.conf))?, i.vars);
        let yaml = match i.yaml {
            Some(y) => {
                Some(render(&std::fs::read_to_string(root.join("lab/gateway").join(y)).with_context(|| format!("reading {y}"))?, i.vars))
            }
            None => None,
        };
        if conf.contains("{{") || yaml.as_deref().is_some_and(|y| y.contains("{{")) {
            bail!("unrendered template tokens remain in profile {profile}");
        }
        let conf_path = run_dir.join(i.conf);
        std::fs::write(&conf_path, conf)?;
        let yaml_path = match (i.yaml, yaml) {
            (Some(name), Some(text)) => {
                let p = run_dir.join(name);
                std::fs::write(&p, text)?;
                Some(p)
            }
            _ => None,
        };
        let defaults = [
            ("PATH", std::env::var("PATH").unwrap_or_default()),
            ("HOME", run_dir.display().to_string()),
            ("FERRUM_ADMIN_JWT_SECRET", random_secret()),
            ("FERRUM_METRICS_BEARER_TOKEN", random_secret()),
        ];
        let mut env: Vec<(String, String)> =
            defaults.into_iter().filter(|(k, _)| !i.env.iter().any(|(e, _)| e == k)).map(|(k, v)| (k.to_string(), v)).collect();
        for (k, v) in i.env {
            env.push((k.to_string(), v.clone()));
        }
        let args = |verb: &str| {
            let mut a: Vec<std::ffi::OsString> = vec![verb.into(), "-m".into(), i.mode.into(), "-s".into(), conf_path.clone().into()];
            if let Some(y) = &yaml_path {
                a.push("-c".into());
                a.push(y.clone().into());
            }
            a
        };
        // Validate first (fails fast on schema drift).
        let out = Command::new(&bin)
            .args(args("validate"))
            .env_clear()
            .envs(env.iter().map(|(a, b)| (a.as_str(), b.as_str())))
            .current_dir(&run_dir)
            .output()
            .await?;
        if !out.status.success() {
            bail!(
                "ferrum-edge validate failed for profile {profile}:\n{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
        }
        let log_path = run_dir.join("gateway.log");
        let log = if i.append_log {
            std::fs::OpenOptions::new().create(true).append(true).open(&log_path)?
        } else {
            std::fs::File::create(&log_path)?
        };
        let child = Command::new(&bin)
            .args(args("run"))
            .env_clear()
            .envs(env.iter().map(|(a, b)| (a.as_str(), b.as_str())))
            .current_dir(&run_dir)
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log))
            .kill_on_drop(true)
            .spawn()
            .context("starting ferrum-edge")?;
        let gw = Gateway { child, profile: profile.into(), admin: format!("127.0.0.1:{}", i.admin_port), log_path, run_dir };
        let probe = match i.readiness {
            Readiness::Ready => ("/health", "\"ready\":true"),
            Readiness::Live => ("/live", "\"status\":\"ok\""),
        };
        gw.wait_ready(Duration::from_secs(30), probe).await?;
        Ok(gw)
    }

    async fn wait_ready(&self, max: Duration, (path, needle): (&str, &str)) -> Result<()> {
        let start = Instant::now();
        loop {
            if let Ok(body) = http_get(&self.admin, path).await
                && body.contains(needle)
            {
                return Ok(());
            }
            if start.elapsed() > max {
                let tail = std::fs::read_to_string(&self.log_path).unwrap_or_default();
                let tail: String = tail.lines().rev().take(30).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join("\n");
                bail!("gateway profile {} did not become ready within {:?}; log tail:\n{tail}", self.profile, max);
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    /// Operator-side ground truth: gateway stdout transaction lines.
    pub fn log_lines(&self) -> Vec<String> {
        std::fs::read_to_string(&self.log_path).unwrap_or_default().lines().map(|s| s.to_string()).collect()
    }

    /// Hard stop (SIGKILL): the process disappears without a graceful drain,
    /// like a crash.
    pub async fn kill(mut self) {
        let _ = self.child.kill().await;
    }

    pub async fn stop(mut self) {
        #[cfg(unix)]
        if let Some(pid) = self.child.id() {
            unsafe_kill(pid);
        }
        let _ = tokio::time::timeout(Duration::from_secs(5), self.child.wait()).await;
        let _ = self.child.kill().await;
    }
}

#[cfg(unix)]
fn unsafe_kill(pid: u32) {
    // SIGTERM via the kill(1) utility to avoid an unsafe libc call.
    let _ = std::process::Command::new("kill").arg("-TERM").arg(pid.to_string()).status();
}

pub fn random_secret() -> String {
    let mut b = [0u8; 32];
    rand::fill(&mut b);
    hex::encode(b)
}

/// Minimal HTTP/1.1 GET over loopback for readiness polling.
pub async fn http_get(addr: &str, path: &str) -> Result<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = tokio::time::timeout(Duration::from_secs(2), tokio::net::TcpStream::connect(addr)).await??;
    s.write_all(format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n").as_bytes()).await?;
    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), s.read_to_end(&mut buf)).await??;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lock_at(file: &str) -> Lock {
        parse_lock(&std::fs::read_to_string(repo_root().join(file)).unwrap(), file).unwrap()
    }

    /// The default pin is one of the supported releases, with identical pins.
    #[test]
    fn default_pin_is_a_supported_release_with_the_same_pins() {
        let text = std::fs::read_to_string(repo_root().join(DEFAULT_LOCK)).unwrap();
        let body = |t: &str| t.lines().filter(|l| !l.starts_with('#') && !l.trim().is_empty()).map(String::from).collect::<Vec<_>>();
        let default = lock_at(DEFAULT_LOCK);
        let file = format!("{RELEASES_DIR}/{}.lock", default.release);
        let copy = std::fs::read_to_string(repo_root().join(&file)).unwrap_or_else(|_| panic!("{file} missing"));
        assert_eq!(body(&text), body(&copy), "{DEFAULT_LOCK} and {file} disagree");
    }

    /// Every supported release has a well-formed lock and an embedded
    /// diagnostics catalog, so the lab's trusted profile never falls back.
    #[test]
    fn every_supported_release_has_a_lock_and_a_catalog() {
        let releases = available_releases();
        assert!(releases.len() >= 2, "{releases:?}");
        for r in releases {
            let l = lock_at(&format!("{RELEASES_DIR}/{r}.lock"));
            assert_eq!(l.release, r);
            assert_eq!(l.source_sha.len(), 40, "{r}: source sha");
            assert_eq!(l.sha256.len(), 64, "{r}: {} checksum", asset_name());
            let id = l.compatibility_id();
            let cat = anvil_diagnostics::ferrum::catalog_for(&id).unwrap_or_else(|| panic!("no diagnostics catalog for {id}"));
            assert_eq!(cat.source_sha, l.source_sha, "{r}: catalog audited at another commit than the lab runs");
        }
    }

    #[test]
    fn release_names_normalize_and_map_to_compatibility_ids() {
        assert_eq!(normalize_release(Some(" 0.9.5 ".into())), Some("v0.9.5".into()));
        assert_eq!(normalize_release(Some("v0.9.7".into())), Some("v0.9.7".into()));
        assert_eq!(normalize_release(Some("".into())), None);
        assert_eq!(compatibility_id_for("v0.9.7"), "ferrum-edge-0.9.7");
    }
}
