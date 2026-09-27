//! `anvil load create --rate` and `--vus` end to end: the real binary and a
//! real profile on disk. The saved plan holds the target for `--duration`
//! from the start instead of ramping up from 0. Nothing is sent.

use anvil_app::App;
use anvil_app::profiles::{ProfileManager, Unlock};
use anvil_domain::Id;
use anvil_domain::load::{Stage, Workload};
use anvil_domain::request::RequestSpec;
use anvil_load::schedule;
use anvil_storage::KdfParams;
use std::path::Path;
use std::process::{Command, Output};

const PASS: &str = "cli-load-plan-passphrase-1";

/// A profile whose workspace `Audit` holds the request `Ping`. Returns the
/// id of `Audit`.
fn setup(root: &Path) -> Id {
    let pm = ProfileManager::new(root);
    let (s, dek, _) = pm.create_passphrase("ci", PASS, KdfParams::testing()).unwrap();
    let h = anvil_storage::vault::read_header(&s.dir).unwrap();
    let app = App::open(s.dir, h, dek).unwrap();
    let ws = app.create_workspace("Audit").unwrap();
    app.create_request(&ws.meta.id, None, "Ping", RequestSpec::http("GET", "https://ping.example.invalid/")).unwrap();
    ws.meta.id
}

fn anvil(data: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_anvil"))
        .arg("--data-dir")
        .arg(data)
        .args(args)
        .env("ANVIL_PASSPHRASE", PASS)
        .env_remove("ANVIL_PROFILE")
        .env_remove("ANVIL_DATA_DIR")
        .output()
        .unwrap()
}

fn text(o: &Output) -> String {
    format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr))
}

/// The workload of the plan `name` saved in `ws`, read back through App.
fn workload(root: &Path, ws: &Id, name: &str) -> Workload {
    let s = ProfileManager::new(root).list().into_iter().next().unwrap();
    let (h, key) = ProfileManager::unlock(&s.dir, Unlock::Passphrase(PASS)).unwrap();
    let app = App::open(s.dir, h, key).unwrap();
    app.load_plans(ws).unwrap().into_iter().find(|p| p.name == name).unwrap().workload
}

fn assert_held(stages: &[Stage], target: u64, duration: u64) {
    let n = target as f64;
    let d = duration as f64;
    assert_eq!(schedule::total_secs(stages), Some(duration), "{stages:?}");
    assert_eq!(schedule::target_at(stages, 0.0), n, "held from the start: {stages:?}");
    assert_eq!(schedule::target_at(stages, d / 2.0), n, "held at the midpoint: {stages:?}");
    assert_eq!(schedule::vus_at(stages, 0.0), target, "{stages:?}");
}

#[test]
fn rate_and_vus_hold_the_target_for_the_duration() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path();
    let ws = setup(data);

    let o = anvil(data, &["load", "create", "Audit", "Rate", "--request", "Ping", "--rate", "100", "--duration", "20"]);
    assert!(o.status.success(), "{}", text(&o));
    match workload(data, &ws, "Rate") {
        Workload::OpenArrivalRate { stages, .. } => {
            assert_held(&stages, 100, 20);
            assert_eq!(schedule::planned_arrivals(&stages), 2_000.0, "{stages:?}");
            assert_eq!(schedule::Arrivals::new(&stages).count(), 2_000, "{stages:?}");
        }
        w => panic!("--rate makes an open workload: {w:?}"),
    }

    let o = anvil(data, &["load", "create", "Audit", "Users", "--request", "Ping", "--vus", "100", "--duration", "20"]);
    assert!(o.status.success(), "{}", text(&o));
    match workload(data, &ws, "Users") {
        Workload::ClosedVirtualUsers { stages, .. } => {
            assert_held(&stages, 100, 20);
            // The same stages as an open workload would plan N·D arrivals.
            assert_eq!(schedule::planned_arrivals(&stages), 2_000.0, "{stages:?}");
        }
        w => panic!("--vus makes a closed workload: {w:?}"),
    }
}
