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
/// Only this many characters of the Markdown description are converted.
const MAX_MARKDOWN: usize = 4 * MAX_NOTES;
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
    /// Plain text (the release description's Markdown as text, cut to `MAX_NOTES`).
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
        notes: cut(&plain_notes(&cut(r.body.unwrap_or_default().trim(), MAX_MARKDOWN)), MAX_NOTES),
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

/// GitHub release descriptions are Markdown; the dialog shows text and never
/// renders markup. This turns the common syntax into readable text: callout
/// markers become a label ("Warning: …"), quote and heading markers, emphasis
/// and code backticks go, bullets become "•", fenced code keeps its lines and
/// links read "text (url)". Anything else (HTML included) stays as written.
fn plain_notes(md: &str) -> String {
    let md = strip_comments(md);
    let mut out: Vec<String> = Vec::new();
    let mut fence: Option<String> = None;
    let mut callout: Option<&str> = None;
    for line in md.lines() {
        let line = line.trim_end();
        if let Some(f) = &fence {
            if line.trim_start().starts_with(f.as_str()) {
                fence = None;
            } else {
                out.push(line.to_string());
            }
            continue;
        }
        let (indent, mut rest) = line.split_at(line.len() - line.trim_start().len());
        if rest.starts_with("```") || rest.starts_with("~~~") {
            let c = rest.chars().next().unwrap_or('`');
            fence = Some(rest.chars().take_while(|&x| x == c).collect());
            continue;
        }
        let mut quoted = false;
        while let Some(r) = rest.strip_prefix('>') {
            rest = r.trim_start();
            quoted = true;
        }
        if quoted && let Some(label) = callout_label(rest) {
            callout = Some(label);
            continue;
        }
        let mut text = if is_rule(rest) {
            continue;
        } else if let Some(h) = heading(rest) {
            plain_inline(h)
        } else if let Some(item) = ["- ", "* ", "+ "].iter().find_map(|b| rest.strip_prefix(b)) {
            format!("{indent}• {}", plain_inline(item))
        } else {
            format!("{indent}{}", plain_inline(rest))
        };
        if let Some(label) = callout.take() {
            text = if text.trim().is_empty() { format!("{label}:") } else { format!("{label}: {}", text.trim_start()) };
        }
        if !text.trim().is_empty() || out.last().is_some_and(|l| !l.is_empty()) {
            out.push(if text.trim().is_empty() { String::new() } else { text });
        }
    }
    if let Some(label) = callout {
        out.push(format!("{label}:"));
    }
    out.join("\n").trim().to_string()
}

/// `<!-- … -->`, which GitHub does not show either.
fn strip_comments(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find("<!--") {
        out.push_str(&rest[..i]);
        match rest[i + 4..].find("-->") {
            Some(j) => rest = &rest[i + 4 + j + 3..],
            None => rest = "",
        }
    }
    out.push_str(rest);
    out
}

/// The label of a GitHub callout marker line (`> [!WARNING]`).
fn callout_label(s: &str) -> Option<&'static str> {
    let kind = s.trim().strip_prefix("[!")?.strip_suffix(']')?;
    ["Note", "Tip", "Important", "Warning", "Caution"].into_iter().find(|l| l.eq_ignore_ascii_case(kind))
}

/// A thematic break (`---`, `***`, `___`) or a setext underline (`===`).
fn is_rule(s: &str) -> bool {
    let t: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    t.len() >= 3 && ['-', '*', '_', '='].iter().any(|&c| t.chars().all(|x| x == c))
}

/// The text of an ATX heading (`## Fixes ##`).
fn heading(s: &str) -> Option<&str> {
    let hashes = s.chars().take_while(|&c| c == '#').count();
    let rest = &s[hashes..];
    if !(1..=6).contains(&hashes) || !(rest.is_empty() || rest.starts_with([' ', '\t'])) {
        return None;
    }
    let rest = rest.trim();
    Some(match rest.trim_end_matches('#') {
        t if t.is_empty() || t.ends_with([' ', '\t']) => t.trim_end(),
        _ => rest,
    })
}

/// One line of Markdown text without its inline syntax.
fn plain_inline(s: &str) -> String {
    let c: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    // Emphasis closers to leave out, and what replaces the `](url)` of a link.
    let mut skip = vec![false; c.len()];
    let mut link_ends: std::collections::HashMap<usize, (usize, String)> = Default::default();
    let mut i = 0;
    while i < c.len() {
        if skip[i] {
            i += 1;
            continue;
        }
        if let Some((resume, suffix)) = link_ends.remove(&i) {
            out.push_str(&suffix);
            i = resume;
            continue;
        }
        let ch = c[i];
        // An image reads as its alt text.
        if ch == '!'
            && c.get(i + 1) == Some(&'[')
            && let Some((text_end, _, resume)) = link(&c, i + 1)
        {
            link_ends.insert(text_end, (resume, String::new()));
            i += 2;
            continue;
        }
        let n = c[i..].iter().take_while(|&&x| x == ch).count();
        match ch {
            '\\' if c.get(i + 1).is_some_and(|x| x.is_ascii_punctuation()) => {
                out.push(c[i + 1]);
                i += 2;
            }
            '`' => match find_run(&c, i + n, '`', n, |_| true) {
                Some(j) => {
                    let code: String = c[i + n..j].iter().collect();
                    let code = match code.strip_prefix(' ').and_then(|x| x.strip_suffix(' ')) {
                        Some(inner) if !inner.trim().is_empty() => inner.to_string(),
                        _ => code,
                    };
                    out.push_str(&code);
                    i = j + n;
                }
                None => {
                    out.extend(&c[i..i + n]);
                    i += n;
                }
            },
            '[' => match link(&c, i) {
                Some((text_end, url, resume)) => {
                    let text: String = c[i + 1..text_end].iter().collect();
                    if text.trim().is_empty() || text == url {
                        out.push_str(&url);
                        i = resume;
                    } else {
                        link_ends.insert(text_end, (resume, format!(" ({url})")));
                        i += 1;
                    }
                }
                None => {
                    out.push('[');
                    i += 1;
                }
            },
            '<' => match autolink(&c, i) {
                Some((url, resume)) => {
                    out.push_str(&url);
                    i = resume;
                }
                None => {
                    out.push('<');
                    i += 1;
                }
            },
            '*' | '_' | '~' if (ch != '~' && n <= 3) || (ch == '~' && n == 2) => {
                let word = |x: Option<&char>| x.is_some_and(|x| x.is_alphanumeric());
                let opens =
                    c.get(i + n).is_some_and(|x| !x.is_whitespace()) && (ch != '_' || !word(i.checked_sub(1).and_then(|p| c.get(p))));
                let closer = opens
                    .then(|| find_run(&c, i + n + 1, ch, n, |j| !c[j - 1].is_whitespace() && (ch != '_' || !word(c.get(j + n)))))
                    .flatten();
                match closer {
                    Some(j) => skip[j..j + n].iter_mut().for_each(|x| *x = true),
                    None => out.extend(&c[i..i + n]),
                }
                i += n;
            }
            _ => {
                out.extend(&c[i..i + n]);
                i += n;
            }
        }
    }
    out
}

/// The start of the next run of exactly `n` `ch` from `from` that `ok` accepts
/// (outside code, a backslash-escaped `ch` is no delimiter).
fn find_run(c: &[char], from: usize, ch: char, n: usize, ok: impl Fn(usize) -> bool) -> Option<usize> {
    let mut j = from;
    while j < c.len() {
        if ch != '`' && c[j] == '\\' {
            j += 2;
            continue;
        }
        let len = c[j..].iter().take_while(|&&x| x == ch).count();
        if len == n && ok(j) {
            return Some(j);
        }
        j += len.max(1);
    }
    None
}

/// `[text](url "title")` at `open`: the index of `]`, the URL and the index after `)`.
fn link(c: &[char], open: usize) -> Option<(usize, String, usize)> {
    let mut depth = 0usize;
    let mut k = open + 1;
    let text_end = loop {
        match c.get(k)? {
            '\\' => k += 1,
            '[' => depth += 1,
            ']' if depth == 0 => break k,
            ']' => depth -= 1,
            _ => {}
        }
        k += 1;
    };
    if c.get(text_end + 1) != Some(&'(') {
        return None;
    }
    let mut depth = 0usize;
    let mut k = text_end + 2;
    let close = loop {
        match c.get(k)? {
            '(' => depth += 1,
            ')' if depth == 0 => break k,
            ')' => depth -= 1,
            _ => {}
        }
        k += 1;
    };
    let dest: String = c[text_end + 2..close].iter().collect();
    let url = dest.split_whitespace().next()?.trim_start_matches('<').trim_end_matches('>').to_string();
    (!url.is_empty()).then_some((text_end, url, close + 1))
}

/// `<https://…>` at `open`: the URL and the index after `>`.
fn autolink(c: &[char], open: usize) -> Option<(String, usize)> {
    let close = open + 1 + c[open + 1..].iter().position(|&x| x == '>' || x == '<' || x.is_whitespace())?;
    let url: String = c[open + 1..close].iter().collect();
    (c[close] == '>' && ["https://", "http://", "mailto:"].iter().any(|p| url.starts_with(p))).then_some((url, close + 1))
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
    fn markdown_notes_read_as_plain_text() {
        let md = "<!-- generated -->\r\n## What's new ##\r\n\r\n> [!WARNING]\r\n> **Unsigned preview.** Verify with `SHA256SUMS`; updates *are* signed.\r\n\r\n\r\n\
                  Built by [run 42](https://github.com/x/actions/runs/42 \"CI\"). See <https://example.com/a_b>.\r\n\
                  ---\r\n\
                  - __Settings → Updates__ keeps `check_for_updates`\r\n  * nested ~~old~~ item\r\n+ ![logo](https://x/l.png) [https://x.io](https://x.io)\r\n\
                  ```sh\r\n**not** emphasis\r\n```\r\n2 * 3 * 4, snake_case_name, *.json, \\*literal\\*, [not a link], C#";
        assert_eq!(
            plain_notes(md),
            "What's new\n\n\
             Warning: Unsigned preview. Verify with SHA256SUMS; updates are signed.\n\n\
             Built by run 42 (https://github.com/x/actions/runs/42). See https://example.com/a_b.\n\
             • Settings → Updates keeps check_for_updates\n  • nested old item\n• logo https://x.io\n\
             **not** emphasis\n\
             2 * 3 * 4, snake_case_name, *.json, *literal*, [not a link], C#"
        );
    }

    #[test]
    fn markdown_edge_cases_stay_readable() {
        assert_eq!(plain_notes("> [!note]\n> Keep it."), "Note: Keep it.");
        assert_eq!(plain_notes("> [!TIP]"), "Tip:");
        assert_eq!(plain_notes("> quoted\n> > twice"), "quoted\ntwice");
        assert_eq!(plain_notes("# C#\n###### six\n####### seven"), "C#\nsix\n####### seven");
        assert_eq!(plain_notes("***both*** and **a *b* c**"), "both and a b c");
        assert_eq!(plain_notes("``a ` b`` and ` x `"), "a ` b and x");
        assert_eq!(plain_notes("[a [b] c](u_(1) \"t\") [x]() [open"), "a [b] c (u_(1)) [x]() [open");
        assert_eq!(plain_notes("<b>kept</b> <not a link>"), "<b>kept</b> <not a link>");
        assert_eq!(plain_notes("unclosed <!-- comment"), "unclosed");
        assert_eq!(plain_notes("```\nno end\n  indented"), "no end\n  indented");
    }

    #[test]
    fn the_offered_update_carries_plain_notes() {
        let mut r = release("anvil-v9.0.0");
        r.body = Some("> [!WARNING]\n> **Careful.** See [docs](https://d).\n\n- one\n- two".into());
        assert_eq!(evaluate(&v("0.1.0"), Some(r)).unwrap().notes, "Warning: Careful. See docs (https://d).\n\n• one\n• two");
        // A huge description is cut before it is converted.
        let mut r = release("anvil-v9.0.0");
        r.body = Some("*a ".repeat(MAX_RESPONSE / 3));
        assert_eq!(evaluate(&v("0.1.0"), Some(r)).unwrap().notes.chars().count(), MAX_NOTES + 1);
    }

    #[test]
    fn a_minimal_answer_parses_and_garbage_does_not() {
        assert!(parse_release(br#"{"tag_name":"anvil-v1.0.0"}"#).is_ok());
        assert!(parse_release(b"<html>").is_err());
    }
}
