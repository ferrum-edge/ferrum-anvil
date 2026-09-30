//! Update check and in-app upgrade.
//!
//! Checking is opt-in: at launch only while `AppSettings::check_for_updates`
//! is on (off by default), otherwise only when the user clicks "Check now".
//! A check asks the GitHub Releases API for the latest published Anvil
//! release; the request carries nothing about the user but Anvil's version
//! (in the User-Agent) and their IP address.
//!
//! Installing runs the Tauri updater: it downloads the release's updater
//! artifact and verifies its minisign signature against the public key
//! compiled into this build (`plugins.updater.pubkey`) before it replaces
//! anything. A build without that key cannot verify an update, so it links
//! to the release page instead.

use crate::commands::{R, blocking, e};
use parking_lot::Mutex;
use semver::Version;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tauri::{AppHandle, Emitter};
use tauri_plugin_updater::UpdaterExt;

const LATEST_RELEASE_API: &str = "https://api.github.com/repos/ferrum-edge/ferrum-anvil/releases/latest";
const RELEASES_PAGE: &str = "https://github.com/ferrum-edge/ferrum-anvil/releases";
const TAG_PREFIX: &str = "anvil-v";
const CHECK_TIMEOUT: Duration = Duration::from_secs(15);
/// The whole download of an update, body included.
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// A release description larger than this is not read.
const MAX_RESPONSE: usize = 1 << 20;
/// Release notes are cut to this many characters.
const MAX_NOTES: usize = 4000;
/// Download progress is reported at most once per this many bytes.
const PROGRESS_STEP: u64 = 256 * 1024;

/// How this build installs an update.
#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InstallMode {
    /// Download, verify the signature and install in the app.
    InApp,
    /// This build carries no updater key: the user downloads the release.
    ReleasePage,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct AvailableUpdate {
    pub version: String,
    pub name: String,
    /// Plain text (the release description, cut to `MAX_NOTES`).
    pub notes: String,
    pub published_at: Option<String>,
    pub url: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct UpdateCheck {
    pub current: String,
    /// The latest published release when it is newer than this build.
    pub update: Option<AvailableUpdate>,
    pub install: InstallMode,
    /// Installing quits Anvil (the Windows installer replaces the running app).
    pub install_quits: bool,
}

#[derive(Deserialize)]
struct GithubRelease {
    tag_name: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    published_at: Option<String>,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
}

#[derive(Serialize, Clone)]
struct UpdateProgress {
    downloaded: u64,
    total: Option<u64>,
}

/// Whether the launch check ran in this process.
static LAUNCH_CHECKED: AtomicBool = AtomicBool::new(false);
/// The result of the last check, so a lock and unlock still shows it.
static LAST: Mutex<Option<UpdateCheck>> = Mutex::new(None);
static INSTALLING: AtomicBool = AtomicBool::new(false);

/// The check when Anvil opens: once per launch and only while the setting is
/// on. Later calls (after a lock and unlock) return the last result. `None`
/// when no check is wanted.
#[tauri::command]
pub async fn update_check_on_launch(handle: AppHandle) -> R<Option<UpdateCheck>> {
    let enabled = blocking(&handle, |st| st.app()?.settings().map(|s| s.check_for_updates).map_err(e)).await?;
    if !enabled {
        return Ok(None);
    }
    if LAUNCH_CHECKED.swap(true, Ordering::SeqCst) {
        return Ok(LAST.lock().clone());
    }
    check(&handle).await.map(Some)
}

/// A check the user asked for.
#[tauri::command]
pub async fn update_check(handle: AppHandle) -> R<UpdateCheck> {
    check(&handle).await
}

async fn check(handle: &AppHandle) -> R<UpdateCheck> {
    let current = handle.package_info().version.clone();
    let update = evaluate(&current, latest_release().await?);
    let result = UpdateCheck { current: current.to_string(), update, install: install_mode(handle), install_quits: cfg!(windows) };
    *LAST.lock() = Some(result.clone());
    Ok(result)
}

/// Download, verify and install `version`, reporting `update-progress`
/// events. Anvil runs the old version until it restarts (`update_restart`);
/// on Windows the installer quits Anvil itself.
#[tauri::command]
pub async fn update_install(handle: AppHandle, version: String) -> R<()> {
    if install_mode(&handle) != InstallMode::InApp {
        return Err("This build cannot verify updates. Download the release from its page.".into());
    }
    let wanted = Version::parse(&version).map_err(|_| format!("invalid version '{version}'"))?;
    if INSTALLING.swap(true, Ordering::SeqCst) {
        return Err("An update is already being installed.".into());
    }
    struct Done;
    impl Drop for Done {
        fn drop(&mut self) {
            INSTALLING.store(false, Ordering::SeqCst);
        }
    }
    let _done = Done;
    // `_done` clears INSTALLING on every return below, errors and timeouts included.
    let updater = handle.updater_builder().timeout(CHECK_TIMEOUT).build().map_err(|x| format!("The updater is not available: {x}"))?;
    let mut update = updater.check().await.map_err(|x| format!("Could not read the update manifest: {x}"))?.ok_or_else(|| {
        format!(
            "The update manifest does not offer a version newer than {} yet (it may not be published). Try again later or download the release from its page.",
            handle.package_info().version
        )
    })?;
    update.timeout = Some(DOWNLOAD_TIMEOUT);
    if Version::parse(&update.version).ok() != Some(wanted) {
        return Err(format!("The release offered changed to {} since the check. Check again.", update.version));
    }
    let (mut downloaded, mut reported) = (0u64, 0u64);
    let events = handle.clone();
    update
        .download_and_install(
            move |chunk, total| {
                downloaded += chunk as u64;
                if downloaded - reported >= PROGRESS_STEP || Some(downloaded) == total {
                    reported = downloaded;
                    let _ = events.emit("update-progress", UpdateProgress { downloaded, total });
                }
            },
            || {},
        )
        .await
        .map_err(|x| format!("The update was not installed: {x}"))?;
    Ok(())
}

/// Restart into the installed update.
#[tauri::command]
pub fn update_restart(handle: AppHandle) {
    handle.request_restart();
}

/// Open the release page of `version` in the browser.
#[tauri::command]
pub fn update_open_release_page(version: String) -> R<()> {
    let version = Version::parse(&version).map_err(|_| format!("invalid version '{version}'"))?;
    tauri_plugin_opener::open_url(release_page(&version), None::<&str>).map_err(|x| x.to_string())
}

fn release_page(version: &Version) -> String {
    format!("{RELEASES_PAGE}/tag/{TAG_PREFIX}{version}")
}

/// In-app install needs the updater public key (empty, the default until the
/// owner configures one, verifies nothing) and a bundle the release signs an
/// update for: releases carry none for `.deb`/`.rpm` installs, and an
/// unbundled binary has nothing to replace.
fn install_mode(handle: &AppHandle) -> InstallMode {
    use tauri::utils::config::BundleType;
    let key = handle.config().plugins.0.get("updater").and_then(|u| u.get("pubkey")).and_then(|k| k.as_str()).unwrap_or("");
    let signed_bundle =
        matches!(tauri::utils::platform::bundle_type(), Some(BundleType::App | BundleType::AppImage | BundleType::Msi | BundleType::Nsis));
    if key.trim().is_empty() || !signed_bundle { InstallMode::ReleasePage } else { InstallMode::InApp }
}

/// The latest published release, `None` before the first one.
async fn latest_release() -> R<Option<GithubRelease>> {
    let client = reqwest::Client::builder()
        .user_agent(concat!("FerrumAnvil/", env!("CARGO_PKG_VERSION")))
        .timeout(CHECK_TIMEOUT)
        .build()
        .map_err(|x| format!("Could not start the update check: {x}"))?;
    let mut resp = client
        .get(LATEST_RELEASE_API)
        .header(reqwest::header::ACCEPT, "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .send()
        .await
        .map_err(|x| format!("Could not reach GitHub: {}", x.without_url()))?;
    match resp.status().as_u16() {
        200..=299 => {}
        404 => return Ok(None),
        403 | 429 => return Err("GitHub's limit for update checks from this network was reached. Try again later.".into()),
        s => return Err(format!("GitHub answered the update check with HTTP {s}.")),
    }
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|x| format!("Could not read GitHub's answer: {}", x.without_url()))? {
        if body.len() + chunk.len() > MAX_RESPONSE {
            return Err("GitHub's answer to the update check is too large.".into());
        }
        body.extend_from_slice(&chunk);
    }
    parse_release(&body).map(Some)
}

fn parse_release(body: &[u8]) -> R<GithubRelease> {
    serde_json::from_slice(body).map_err(|x| format!("Unexpected answer from GitHub: {x}"))
}

/// The update `release` offers over `current`: a stable Anvil release
/// (`anvil-vX.Y.Z`) newer than this build.
fn evaluate(current: &Version, release: Option<GithubRelease>) -> Option<AvailableUpdate> {
    let r = release.filter(|r| !r.draft && !r.prerelease)?;
    let version = r.tag_name.strip_prefix(TAG_PREFIX).and_then(|v| Version::parse(v).ok())?;
    if !version.pre.is_empty() || version <= *current {
        return None;
    }
    Some(AvailableUpdate {
        url: release_page(&version),
        name: r.name.map(|n| n.trim().to_string()).filter(|n| !n.is_empty()).unwrap_or_else(|| format!("Ferrum Anvil {version}")),
        notes: cut(r.body.unwrap_or_default().trim(), MAX_NOTES),
        published_at: r.published_at,
        version: version.to_string(),
    })
}

fn cut(s: &str, max: usize) -> String {
    match s.char_indices().nth(max) {
        Some((i, _)) => format!("{}…", s[..i].trim_end()),
        None => s.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn release(tag: &str) -> GithubRelease {
        parse_release(format!(r#"{{"tag_name":"{tag}","name":"","body":"Fixes.\r\n","published_at":"2026-10-01T00:00:00Z","draft":false,"prerelease":false,"html_url":"https://example.com"}}"#).as_bytes())
            .unwrap()
    }

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap()
    }

    #[test]
    fn a_newer_stable_release_is_offered() {
        let u = evaluate(&v("0.1.0"), Some(release("anvil-v0.2.0"))).unwrap();
        assert_eq!(u.version, "0.2.0");
        assert_eq!(u.name, "Ferrum Anvil 0.2.0");
        assert_eq!(u.notes, "Fixes.");
        // The page is built from the checked tag, never taken from the answer.
        assert_eq!(u.url, "https://github.com/ferrum-edge/ferrum-anvil/releases/tag/anvil-v0.2.0");
        assert_eq!(u.published_at.as_deref(), Some("2026-10-01T00:00:00Z"));
    }

    #[test]
    fn same_older_foreign_and_prerelease_tags_are_not_offered() {
        let current = v("0.2.0");
        for tag in ["anvil-v0.2.0", "anvil-v0.1.9", "anvil-v0.3.0-rc.1", "v0.3.0", "ferrum-v0.3.0", "anvil-vnext", "anvil-v0.3"] {
            assert_eq!(evaluate(&current, Some(release(tag))), None, "{tag}");
        }
        assert_eq!(evaluate(&current, None), None);
        let mut pre = release("anvil-v0.3.0");
        pre.prerelease = true;
        assert_eq!(evaluate(&current, Some(pre)), None);
        let mut draft = release("anvil-v0.3.0");
        draft.draft = true;
        assert_eq!(evaluate(&current, Some(draft)), None);
    }

    #[test]
    fn a_prerelease_build_is_offered_its_final_release() {
        assert!(evaluate(&v("0.3.0-rc.1"), Some(release("anvil-v0.3.0"))).is_some());
    }

    #[test]
    fn long_notes_are_cut_on_a_character_boundary() {
        assert_eq!(cut("ééééé", 3), "ééé…");
        assert_eq!(cut("abc", 3), "abc");
        let mut r = release("anvil-v9.0.0");
        r.body = Some("ü".repeat(MAX_NOTES + 10));
        assert_eq!(evaluate(&v("0.1.0"), Some(r)).unwrap().notes.chars().count(), MAX_NOTES + 1);
    }

    /// The shipped updater config loads as the plugin reads it at startup, requires a signed
    /// version and carries no key (a release build gets the owner's key from the workflow).
    #[test]
    fn the_shipped_updater_config_requires_a_signed_version_and_has_no_key() {
        let conf: serde_json::Value = serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        let updater: tauri_plugin_updater::Config = serde_json::from_value(conf["plugins"]["updater"].clone()).unwrap();
        assert!(updater.require_signed_version);
        assert!(!updater.allow_downgrades);
        assert_eq!(updater.pubkey, "");
        let endpoints: Vec<String> = updater.endpoints.iter().map(|u| u.to_string()).collect();
        assert_eq!(endpoints, ["https://github.com/ferrum-edge/ferrum-anvil/releases/latest/download/latest.json"]);
    }

    #[test]
    fn a_minimal_answer_parses_and_garbage_does_not() {
        assert!(parse_release(br#"{"tag_name":"anvil-v1.0.0"}"#).is_ok());
        assert!(parse_release(b"<html>").is_err());
    }
}
