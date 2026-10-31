//! REL-003, signed update integrity: an update whose signature is wrong or
//! whose artifact was altered after signing is refused before anything is
//! installed, and leaves the installed app and the profile unchanged.
//!
//! Every case drives the path `update_install` takes, through the pinned
//! `tauri-plugin-updater`: `build_updater` and `install_offered` (manifest
//! check, download, minisign verification, install). The app runs on Tauri's
//! mock runtime with the updater plugin registered as `run` registers it and
//! configured from the shipped `tauri.conf.json` (`requireSignedVersion`
//! included). Only three settings differ: the public key is a minisign key
//! generated for the test, the endpoint is a loopback HTTP server that serves
//! the manifest (`latest.json` in the static `platforms` format releases
//! publish) and the artifact, and plain HTTP is allowed for that endpoint.
//!
//! The plugin installs into a sandbox instead of over the test binary: an app
//! bundle on macOS (the `.app` the plugin replaces from a `.app.tar.gz`) and
//! an AppImage on Linux (replaced from an `.AppImage.tar.gz`). A real profile
//! vault, made by the profile manager, sits next to it. The valid control
//! installs and the snapshot sees it; a refusal must leave every file and
//! folder of the install and the profile with the same SHA-256, size, mode,
//! inode and modification time, and leave no updater staging folder behind.
//!
//! Windows is not covered: its install step starts the installer and exits
//! the process, and CI does not run this crate's tests there.

use super::{build_updater, install_offered};
use crate::state::DesktopState;
use crate::state::tests::{TempRoot, create};
use aws_lc_rs::digest::{SHA256, digest};
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use blake2::{Blake2b512, Digest as _};
use parking_lot::Mutex;
use semver::Version;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tauri::test::{MockRuntime, mock_builder, mock_context, noop_assets};
use tauri_plugin_updater::UpdaterExt;

/// The updater stages in the system temp folder, which `Outcome` watches: one
/// case at a time.
static SERIAL: Mutex<()> = Mutex::new(());

const OFFERED: &str = "0.2.0";
const MANIFEST: &str = "/latest.json";
const ARTIFACT: &str = "/anvil-update.tar.gz";
const INSTALLED_EXE: &[u8] = b"ferrum-anvil installed build\n";
const UPDATE_EXE: &[u8] = b"ferrum-anvil 0.2.0 signed update\n";
const TAMPERED_EXE: &[u8] = b"ferrum-anvil 0.2.0 tampered build\n";

/// What the plugin replaces (relative to the install folder) and the
/// executable the updater is pointed at, as the plugin derives one from the other.
#[cfg(target_os = "macos")]
const BUNDLE: &str = "Ferrum Anvil.app";
#[cfg(target_os = "macos")]
const EXE: &str = "Ferrum Anvil.app/Contents/MacOS/ferrum-anvil";
#[cfg(target_os = "linux")]
const BUNDLE: &str = "Ferrum Anvil.AppImage";
#[cfg(target_os = "linux")]
const EXE: &str = "Ferrum Anvil.AppImage";

/// The files of an installed app (or of an update artifact) whose executable is `exe`.
fn bundle_files(exe: &[u8]) -> Vec<(&'static str, Vec<u8>, u32)> {
    let mut files = vec![(EXE, exe.to_vec(), 0o755)];
    if cfg!(target_os = "macos") {
        files.push(("Ferrum Anvil.app/Contents/Info.plist", b"<plist><dict/></plist>\n".to_vec(), 0o644));
    }
    files
}

/// An updater artifact as the bundler makes one: the bundle in a `.tar.gz`.
fn artifact(exe: &[u8]) -> Vec<u8> {
    let mut tar = tar::Builder::new(flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default()));
    for (path, bytes, mode) in bundle_files(exe) {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(bytes.len() as u64);
        header.set_mode(mode);
        header.set_mtime(1_790_000_000);
        tar.append_data(&mut header, path, bytes.as_slice()).unwrap();
    }
    tar.into_inner().unwrap().finish().unwrap()
}

/// A minisign key pair generated for the test, as `tauri signer generate` makes one.
struct Key {
    pair: Ed25519KeyPair,
    id: [u8; 8],
}

impl Key {
    fn generate() -> Self {
        let mut id = [0u8; 8];
        aws_lc_rs::rand::fill(&mut id).unwrap();
        Key { pair: Ed25519KeyPair::generate().unwrap(), id }
    }

    /// `plugins.updater.pubkey`: the minisign public key file, base64-encoded.
    fn pubkey(&self) -> String {
        let mut bin = b"Ed".to_vec();
        bin.extend(self.id);
        bin.extend(self.pair.public_key().as_ref());
        B64.encode(format!("untrusted comment: minisign public key: {:016X}\n{}\n", u64::from_le_bytes(self.id), B64.encode(bin)))
    }

    /// The signature `tauri signer sign` makes for the artifact of `version`.
    fn sign(&self, data: &[u8], version: &str) -> Sig {
        Sig::new(&self.pair, self.id, data, format!("timestamp:1790000000\tfile:anvil-update.tar.gz\tversion:{version}"))
    }
}

/// A prehashed (`ED`) minisign signature.
struct Sig {
    key_id: [u8; 8],
    signature: [u8; 64],
    trusted_comment: String,
    global: [u8; 64],
}

impl Sig {
    fn new(pair: &Ed25519KeyPair, key_id: [u8; 8], data: &[u8], trusted_comment: String) -> Self {
        let signature: [u8; 64] = pair.sign(&Blake2b512::digest(data)[..]).as_ref().try_into().unwrap();
        let mut global = signature.to_vec();
        global.extend(trusted_comment.as_bytes());
        let global = pair.sign(&global).as_ref().try_into().unwrap();
        Sig { key_id, signature, trusted_comment, global }
    }

    /// The manifest's `signature`: the `.sig` file, base64-encoded.
    fn manifest_value(&self) -> String {
        let mut line = b"ED".to_vec();
        line.extend(self.key_id);
        line.extend(self.signature);
        B64.encode(format!(
            "untrusted comment: signature from tauri secret key\n{}\ntrusted comment: {}\n{}\n",
            B64.encode(line),
            self.trusted_comment,
            B64.encode(self.global)
        ))
    }
}

/// A loopback HTTP server for the manifest and the artifact.
struct Server {
    addr: SocketAddr,
    routes: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Server {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (routes, requests, stop) =
            (Arc::new(Mutex::new(BTreeMap::new())), Arc::new(Mutex::new(Vec::new())), Arc::new(AtomicBool::new(false)));
        let (r, q, s) = (routes.clone(), requests.clone(), stop.clone());
        let thread = std::thread::spawn(move || {
            for conn in listener.incoming() {
                if s.load(Ordering::SeqCst) {
                    break;
                }
                if let Ok(conn) = conn {
                    respond(conn, &r, &q);
                }
            }
        });
        Server { addr, routes, requests, stop, thread: Some(thread) }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }

    fn serve(&self, path: &str, body: Vec<u8>) {
        self.routes.lock().insert(path.to_string(), body);
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn respond(mut conn: TcpStream, routes: &Mutex<BTreeMap<String, Vec<u8>>>, requests: &Mutex<Vec<String>>) {
    let _ = conn.set_read_timeout(Some(Duration::from_secs(10)));
    let Ok(read) = conn.try_clone() else { return };
    let mut reader = BufReader::new(read);
    let mut request = String::new();
    if reader.read_line(&mut request).is_err() {
        return;
    }
    let mut header = String::new();
    while matches!(reader.read_line(&mut header), Ok(n) if n > 0) && !header.trim_end().is_empty() {
        header.clear();
    }
    let path = request.split_whitespace().nth(1).unwrap_or_default().to_string();
    let body = routes.lock().get(&path).cloned();
    requests.lock().push(path);
    let (status, body) = match body {
        Some(b) => ("200 OK", b),
        None => ("404 Not Found", Vec::new()),
    };
    let head = format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
    let _ = conn.write_all(head.as_bytes()).and_then(|()| conn.write_all(&body));
}

/// What a file or folder is, down to its bytes and identity.
#[derive(Debug, PartialEq, Eq)]
enum Node {
    Dir { mode: u32, ino: u64, mtime: (i64, i64) },
    File { sha256: Vec<u8>, len: u64, mode: u32, ino: u64, mtime: (i64, i64) },
    Link(PathBuf),
}

type Snapshot = BTreeMap<PathBuf, Node>;

/// Every file and folder under `root`, by relative path.
fn snapshot(root: &Path) -> Snapshot {
    fn walk(root: &Path, path: &Path, out: &mut Snapshot) {
        let meta = std::fs::symlink_metadata(path).unwrap();
        let mtime = (meta.mtime(), meta.mtime_nsec());
        let node = if meta.file_type().is_symlink() {
            Node::Link(std::fs::read_link(path).unwrap())
        } else if meta.is_dir() {
            for entry in std::fs::read_dir(path).unwrap() {
                walk(root, &entry.unwrap().path(), out);
            }
            Node::Dir { mode: meta.mode(), ino: meta.ino(), mtime }
        } else {
            let sha256 = digest(&SHA256, &std::fs::read(path).unwrap()).as_ref().to_vec();
            Node::File { sha256, len: meta.len(), mode: meta.mode(), ino: meta.ino(), mtime }
        };
        out.insert(path.strip_prefix(root).unwrap().to_path_buf(), node);
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

/// The updater's staging folders (`tauri_updated_app…`, `tauri_current_app…`)
/// in the system temp folder.
fn updater_staging() -> BTreeSet<String> {
    std::fs::read_dir(std::env::temp_dir())
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
        .filter(|n| n.starts_with("tauri_"))
        .collect()
}

/// The app with the updater plugin as `run` registers it, configured from
/// the shipped `tauri.conf.json` but for the key and the endpoint.
fn app(pubkey: &str, endpoint: &str) -> tauri::App<MockRuntime> {
    let conf: serde_json::Value = serde_json::from_str(include_str!("../../tauri.conf.json")).unwrap();
    let mut updater = conf["plugins"]["updater"].clone();
    assert_eq!(updater["requireSignedVersion"].as_bool(), Some(true), "the shipped updater config requires a signed version");
    updater["pubkey"] = pubkey.into();
    updater["endpoints"] = serde_json::json!([endpoint]);
    // The loopback endpoint is plain HTTP; TLS is not what this test is about.
    updater["dangerousInsecureTransportProtocol"] = true.into();
    let mut context = mock_context::<MockRuntime, _>(noop_assets());
    context.config_mut().plugins.0.insert("updater".into(), updater);
    context.package_info_mut().version = Version::parse(conf["version"].as_str().unwrap()).unwrap();
    mock_builder().plugin(tauri_plugin_updater::Builder::new().build()).build(context).unwrap()
}

/// What is served for the offered version.
struct Offer {
    artifact: Vec<u8>,
    signature: String,
}

struct Outcome {
    result: Result<(), String>,
    /// Bytes the plugin downloaded before it decided.
    downloaded: u64,
    requests: Vec<String>,
    install: (Snapshot, Snapshot),
    profile: (Snapshot, Snapshot),
    staging: (BTreeSet<String>, BTreeSet<String>),
    exe_after: Vec<u8>,
}

/// Offer an update (made with the trusted key) through the real updater path
/// and record what it changed.
fn offer_update(make: impl FnOnce(&Key) -> Offer) -> Outcome {
    let _serial = SERIAL.lock();
    let key = Key::generate();
    let root = TempRoot::new();
    let install = root.0.join("install");
    for (path, bytes, mode) in bundle_files(INSTALLED_EXE) {
        let path = install.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    }
    let data = root.0.join("data");
    {
        let st = DesktopState::new(data.clone());
        let (profile, dir) = create(&st, "REL-003");
        drop(profile);
        assert!(dir.starts_with(&data));
    }

    let server = Server::start();
    let offer = make(&key);
    let target = tauri_plugin_updater::target().unwrap();
    let manifest = serde_json::json!({
        "version": OFFERED,
        "notes": "REL-003",
        "pub_date": "2026-10-31T00:00:00Z",
        "platforms": { target: { "signature": offer.signature, "url": server.url(ARTIFACT) } },
    });
    server.serve(MANIFEST, serde_json::to_vec(&manifest).unwrap());
    server.serve(ARTIFACT, offer.artifact);
    let app = app(&key.pubkey(), &server.url(MANIFEST));
    let current = app.package_info().version.clone();
    let updater = build_updater(app.updater_builder().executable_path(install.join(EXE)).no_proxy()).unwrap();

    let before = (snapshot(&install), snapshot(&data), updater_staging());
    let mut downloaded = 0u64;
    let result = tauri::async_runtime::block_on(install_offered(&updater, &Version::parse(OFFERED).unwrap(), &current, |chunk, _| {
        downloaded += chunk as u64;
    }));
    let after = (snapshot(&install), snapshot(&data), updater_staging());

    Outcome {
        result,
        downloaded,
        requests: server.requests.lock().clone(),
        install: (before.0, after.0),
        profile: (before.1, after.1),
        staging: (before.2, after.2),
        exe_after: std::fs::read(install.join(EXE)).unwrap(),
    }
}

/// Refused at verification, after the whole artifact was downloaded, with
/// nothing changed.
fn assert_refused(case: &str, o: &Outcome, artifact_len: usize, why: &str) {
    assert_eq!(o.result, Err(format!("The update was not installed: {why}")), "{case}");
    // The plugin had the whole artifact: the refusal is the signature check
    // on its bytes, not a network or manifest failure.
    assert_eq!(o.requests, [MANIFEST, ARTIFACT], "{case}");
    assert_eq!(o.downloaded, artifact_len as u64, "{case}");
    assert_eq!(o.install.1, o.install.0, "{case}: the installed app changed");
    assert_eq!(o.exe_after, INSTALLED_EXE, "{case}");
    assert_eq!(o.profile.1, o.profile.0, "{case}: the profile changed");
    assert_eq!(o.staging.1, o.staging.0, "{case}: the updater staged an install");
}

/// (a) Control: an update signed by the configured key for the version it is
/// offered as verifies and installs, and the snapshot sees the install.
#[test]
fn rel_003_a_validly_signed_update_verifies_and_installs() {
    let artifact = artifact(UPDATE_EXE);
    let len = artifact.len();
    let o = offer_update(|key| Offer { signature: key.sign(&artifact, OFFERED).manifest_value(), artifact });
    assert_eq!(o.result, Ok(()));
    assert_eq!(o.requests, [MANIFEST, ARTIFACT]);
    assert_eq!(o.downloaded, len as u64);
    assert_eq!(o.exe_after, UPDATE_EXE);
    assert_ne!(o.install.1, o.install.0);
    assert!(matches!(o.install.1.get(Path::new(BUNDLE)), Some(Node::Dir { .. } | Node::File { .. })));
    // Installing touches neither the profile nor leaves staging behind.
    assert_eq!(o.profile.1, o.profile.0);
    assert_eq!(o.staging.1, o.staging.0);
}

/// (b) A signature that is not the configured key's is refused before install.
#[test]
fn rel_003_an_update_with_a_wrong_or_invalid_signature_is_refused_without_changes() {
    let artifact = artifact(UPDATE_EXE);
    let len = artifact.len();
    type MakeSig = fn(&Key, &[u8]) -> String;
    let cases: [(&str, MakeSig, &str); 5] = [
        (
            "signed by another key",
            |_, data| Key::generate().sign(data, OFFERED).manifest_value(),
            "The signature was created with a different key than the one provided",
        ),
        (
            "signed by another key under the configured key id",
            |key, data| {
                let other = Key::generate();
                Sig::new(&other.pair, key.id, data, format!("timestamp:1790000000\tfile:anvil-update.tar.gz\tversion:{OFFERED}"))
                    .manifest_value()
            },
            "The signature verification failed",
        ),
        (
            "configured key's signature with a flipped bit",
            |key, data| {
                let mut sig = key.sign(data, OFFERED);
                sig.signature[17] ^= 0x01;
                sig.manifest_value()
            },
            "The signature verification failed",
        ),
        (
            "configured key's signature with an edited trusted comment",
            |key, data| {
                let mut sig = key.sign(data, OFFERED);
                sig.trusted_comment = sig.trusted_comment.replace("file:anvil-update", "file:other-update");
                sig.manifest_value()
            },
            "The signature verification failed",
        ),
        ("not a minisign signature", |_, _| B64.encode("untrusted comment: none\nnot a signature\n"), "Invalid encoding in minisign data"),
    ];
    for (case, make, why) in cases {
        let artifact = artifact.clone();
        let o = offer_update(|key| Offer { signature: make(key, &artifact), artifact });
        assert_refused(case, &o, len, why);
    }
}

/// (c) An artifact altered after it was signed is refused before install,
/// even when the altered artifact is itself a well-formed update.
#[test]
fn rel_003_an_update_altered_after_signing_is_refused_without_changes() {
    let signed = artifact(UPDATE_EXE);
    type Alter = fn(Vec<u8>) -> Vec<u8>;
    let cases: [(&str, Alter); 3] = [
        ("replaced by a rebuilt artifact with another executable", |_| artifact(TAMPERED_EXE)),
        ("one bit flipped", |mut a| {
            let i = a.len() / 2;
            a[i] ^= 0x01;
            a
        }),
        ("bytes appended", |mut a| {
            a.extend_from_slice(b"\0tampered");
            a
        }),
    ];
    for (case, alter) in cases {
        let served = alter(signed.clone());
        assert_ne!(served, signed, "{case}");
        let len = served.len();
        let o = offer_update(|key| Offer { signature: key.sign(&signed, OFFERED).manifest_value(), artifact: served });
        assert_refused(case, &o, len, "The signature verification failed");
    }
}
