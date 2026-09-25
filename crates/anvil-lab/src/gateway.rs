//! Manages a real Ferrum Edge release binary for the lab.

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::Stdio;
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

pub struct Lock {
    pub release: String,
    pub source_sha: String,
    pub sha256: String,
}

pub fn read_lock() -> Result<Lock> {
    let text = std::fs::read_to_string(repo_root().join("lab/gateway/RELEASE.lock"))?;
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
    if sha256.is_empty() {
        bail!("no pinned checksum for {} in lab/gateway/RELEASE.lock", asset_name());
    }
    Ok(Lock { release, source_sha, sha256 })
}

/// Locate and verify the pinned gateway binary.
/// Search order: $ANVIL_LAB_FERRUM_BIN, lab/bin/<asset>, ../lab-bin/<asset>.
pub fn binary() -> Result<(PathBuf, Lock)> {
    let lock = read_lock()?;
    let root = repo_root();
    let candidates: Vec<PathBuf> = std::env::var("ANVIL_LAB_FERRUM_BIN")
        .ok()
        .map(PathBuf::from)
        .into_iter()
        .chain([root.join("lab/bin").join(asset_name()), root.join("../lab-bin").join(asset_name())])
        .collect();
    for c in candidates {
        if c.exists() {
            let bytes = std::fs::read(&c)?;
            let got = hex::encode(Sha256::digest(&bytes));
            if got != lock.sha256 {
                bail!("{} has sha256 {got}, but RELEASE.lock pins {} — refusing to run an unverified gateway", c.display(), lock.sha256);
            }
            return Ok((c, lock));
        }
    }
    bail!("Ferrum Edge {} binary not found; run lab/scripts/fetch-gateway.sh (it verifies the pinned sha256)", lock.release)
}

pub struct Gateway {
    pub child: Child,
    pub profile: String,
    pub admin: String,
    pub log_path: PathBuf,
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

impl Gateway {
    pub async fn start(
        profile: &str,
        conf_name: &str,
        yaml_name: &str,
        vars: &[(&str, String)],
        admin_port: u16,
        extra_env: &[(&str, String)],
    ) -> Result<Gateway> {
        let (bin, _lock) = binary()?;
        let root = repo_root();
        let run_dir = root.join("lab/.run").join(profile);
        std::fs::create_dir_all(&run_dir)?;
        let conf = render(
            &std::fs::read_to_string(root.join("lab/gateway").join(conf_name)).with_context(|| format!("reading {conf_name}"))?,
            vars,
        );
        let yaml = render(
            &std::fs::read_to_string(root.join("lab/gateway").join(yaml_name)).with_context(|| format!("reading {yaml_name}"))?,
            vars,
        );
        if conf.contains("{{") || yaml.contains("{{") {
            bail!("unrendered template tokens remain in profile {profile}");
        }
        let conf_path = run_dir.join(conf_name);
        let yaml_path = run_dir.join(yaml_name);
        std::fs::write(&conf_path, conf)?;
        std::fs::write(&yaml_path, yaml)?;
        let mut env: Vec<(String, String)> = vec![
            ("PATH".into(), std::env::var("PATH").unwrap_or_default()),
            ("HOME".into(), run_dir.display().to_string()),
            ("FERRUM_ADMIN_JWT_SECRET".into(), random_secret()),
            ("FERRUM_METRICS_BEARER_TOKEN".into(), random_secret()),
        ];
        for (k, v) in extra_env {
            env.push((k.to_string(), v.clone()));
        }
        // Validate first (fails fast on schema drift).
        let out = Command::new(&bin)
            .args(["validate", "-m", "file", "-s"])
            .arg(&conf_path)
            .arg("-c")
            .arg(&yaml_path)
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
        let log = std::fs::File::create(&log_path)?;
        let child = Command::new(&bin)
            .args(["run", "-m", "file", "-s"])
            .arg(&conf_path)
            .arg("-c")
            .arg(&yaml_path)
            .env_clear()
            .envs(env.iter().map(|(a, b)| (a.as_str(), b.as_str())))
            .current_dir(&run_dir)
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log))
            .kill_on_drop(true)
            .spawn()
            .context("starting ferrum-edge")?;
        let gw = Gateway { child, profile: profile.into(), admin: format!("127.0.0.1:{admin_port}"), log_path, run_dir };
        gw.wait_ready(Duration::from_secs(30)).await?;
        Ok(gw)
    }

    async fn wait_ready(&self, max: Duration) -> Result<()> {
        let start = Instant::now();
        loop {
            if let Ok(body) = http_get(&self.admin, "/health").await
                && body.contains("\"ready\":true")
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

fn random_secret() -> String {
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
