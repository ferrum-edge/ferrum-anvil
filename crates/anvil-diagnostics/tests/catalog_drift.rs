//! Diagnostic catalog drift (release gate, plan §16): every finding code a
//! rule can emit has user-facing wording in
//! `catalog/diagnostics/findings.en.json`, and every catalog entry is still
//! emitted by some rule — so wording never silently falls back to
//! "No wording is available for this finding code" and stale entries do not
//! accumulate.
//!
//! Codes are extracted from the rule sources (anvil-diagnostics and the
//! engine's adapter findings) using the construction patterns those files use:
//!
//! * `Draft::new("code", …)`
//! * helper closures declared as `let name = |code: &str, …|` and called as `name("code", …)`
//! * `let code = match … { … => "code", … }`
//! * `format!("ferrum.token.{t}")`, expanded over the public token vocabulary
//!   of every embedded Ferrum compatibility catalog (one per supported release).
//!
//! It also checks that every Ferrum catalog on disk is embedded and internally
//! consistent.
//!
//! A `Draft::new` whose statement supplies its own `catalog_text` (adapter
//! observations worded at the call site) is exempt from needing a catalog
//! entry. If a rule starts building codes some other way, extend the patterns
//! here — the minimum-count assertion keeps the scanner from silently
//! matching nothing.

use anvil_diagnostics::{ferrum, render};
use anvil_domain::diagnostics::Owner;
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const CODE: &str = r#""([a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+)""#;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<_> = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("reading {}: {e}", dir.display())).flatten().collect();
    entries.sort_by_key(|e| e.path());
    for e in entries {
        let p = e.path();
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

#[derive(Debug, Default)]
struct Emitted {
    /// code -> source files that emit it
    worded_by_catalog: BTreeMap<String, BTreeSet<String>>,
    /// codes whose call site supplies `catalog_text`
    self_worded: BTreeMap<String, BTreeSet<String>>,
    /// `format!("ferrum.token.{..}")` seen
    ferrum_token_format: bool,
}

fn matching_brace(s: &str, open: usize) -> usize {
    let mut depth = 0usize;
    for (i, ch) in s[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return open + i;
                }
            }
            _ => {}
        }
    }
    panic!("unbalanced braces after offset {open}");
}

fn scan(files: &[PathBuf]) -> Emitted {
    let draft_new = Regex::new(&format!(r"Draft::new\(\s*{CODE}")).unwrap();
    let closure = Regex::new(r"let\s+(\w+)\s*=\s*\|code:\s*&str").unwrap();
    let code_match = Regex::new(r"let\s+code\s*=\s*match\b").unwrap();
    let arm = Regex::new(&format!(r"=>\s*{CODE}")).unwrap();
    let mut out = Emitted::default();
    let root = repo_root();
    for f in files {
        let src = std::fs::read_to_string(f).unwrap();
        let name = f.strip_prefix(&root).unwrap_or(f).display().to_string();
        let mut add = |code: &str, self_worded: bool| {
            let map = if self_worded { &mut out.self_worded } else { &mut out.worded_by_catalog };
            map.entry(code.to_string()).or_default().insert(name.clone());
        };
        for m in draft_new.captures_iter(&src) {
            let whole = m.get(0).unwrap();
            let next = src[whole.end()..].find("Draft::new(").map(|i| whole.end() + i).unwrap_or(src.len());
            let self_worded = src[whole.end()..next].contains("catalog_text = Some(");
            add(&m[1], self_worded);
        }
        for c in closure.captures_iter(&src) {
            let call = Regex::new(&format!(r"\b{}\(\s*{CODE}", regex::escape(&c[1]))).unwrap();
            for m in call.captures_iter(&src) {
                add(&m[1], false);
            }
        }
        for c in code_match.find_iter(&src) {
            let open = c.end() + src[c.end()..].find('{').expect("match body");
            let close = matching_brace(&src, open);
            for m in arm.captures_iter(&src[open..close]) {
                add(&m[1], false);
            }
        }
        if src.contains(r#"format!("ferrum.token.{"#) {
            out.ferrum_token_format = true;
        }
    }
    out
}

fn sources() -> Vec<PathBuf> {
    let root = repo_root();
    let mut files = Vec::new();
    rust_files(&root.join("crates/anvil-diagnostics/src"), &mut files);
    rust_files(&root.join("crates/anvil-engine/src"), &mut files);
    files
}

#[test]
fn every_emitted_code_has_catalog_wording_and_no_entry_is_stale() {
    let catalog = render::catalog();
    let emitted = scan(&sources());

    // Guard against the scanner silently matching nothing after a refactor.
    assert!(
        emitted.worded_by_catalog.len() >= 100,
        "only {} finding codes extracted from rule sources — update the extraction patterns in this test",
        emitted.worded_by_catalog.len()
    );
    assert!(emitted.ferrum_token_format, "the ferrum.token.<token> construction was not found; update this test");

    let mut expected: BTreeMap<String, String> =
        emitted.worded_by_catalog.iter().map(|(c, f)| (c.clone(), f.iter().cloned().collect::<Vec<_>>().join(", "))).collect();
    // Every embedded Ferrum release's vocabulary needs wording, not only the default's.
    for cat in ferrum::catalogs() {
        for t in &cat.tokens {
            expected.insert(
                format!("ferrum.token.{t}"),
                format!("rules/ferrum_rules.rs (public token vocabulary of {})", cat.compatibility_id),
            );
        }
    }

    let missing: Vec<String> =
        expected.iter().filter(|(c, _)| !catalog.findings.contains_key(*c)).map(|(c, f)| format!("{c}  (emitted in {f})")).collect();
    assert!(missing.is_empty(), "finding codes without wording in catalog/diagnostics/findings.en.json:\n  {}", missing.join("\n  "));

    let stale: Vec<&String> =
        catalog.findings.keys().filter(|c| !expected.contains_key(*c) && !emitted.self_worded.contains_key(*c)).collect();
    assert!(stale.is_empty(), "catalog entries no rule emits (stale wording or an unrecognised construction pattern): {stale:?}");
}

/// Every Ferrum compatibility catalog on disk is embedded (and vice versa), and
/// each one is internally consistent: its own compatibility id and source
/// commit on every citation, no dangling sibling / fixture / removal ids, and
/// only its own public tokens in markers and release notes.
#[test]
fn ferrum_catalogs_are_embedded_and_internally_consistent() {
    let dir = repo_root().join("catalog/ferrum");
    let on_disk: BTreeSet<String> = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .filter(|e| e.path().join("outcomes.json").exists())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    let embedded: BTreeSet<String> = ferrum::compatibility_ids().map(String::from).collect();
    assert_eq!(on_disk, embedded, "every catalog/ferrum/<id>/outcomes.json must be embedded in anvil_diagnostics::ferrum");
    assert!(embedded.contains(ferrum::DEFAULT_COMPATIBILITY_ID));

    let ident = Regex::new(r"^[a-z][a-z0-9_]*$").unwrap();
    let mut previous: Option<BTreeSet<String>> = None;
    for id in ferrum::compatibility_ids() {
        let raw: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(dir.join(id).join("outcomes.json")).unwrap()).unwrap();
        let mut problems = Vec::new();
        assert_eq!(raw["compatibility_id"], id);
        let sha = raw["gateway"]["source_sha"].as_str().expect("gateway.source_sha");
        assert_eq!(sha.len(), 40, "{id}: full source sha");
        let tag = raw["gateway"]["release_tag"].as_str().expect("gateway.release_tag");
        assert_eq!(format!("ferrum-edge-{}", tag.trim_start_matches('v')), id);
        let tokens: BTreeSet<&str> = raw["public_tokens"].as_array().unwrap().iter().filter_map(|t| t.as_str()).collect();
        let outcomes = raw["outcomes"].as_array().expect("outcomes");
        let mut ids = BTreeSet::new();
        for o in outcomes {
            let oid = o["id"].as_str().unwrap_or("<no id>").to_string();
            if !ids.insert(oid.clone()) {
                problems.push(format!("duplicate outcome {oid}"));
            }
            for field in ["family", "condition", "minimum_truthful_diagnosis", "owner", "evidence_visibility"] {
                if o[field].as_str().is_none_or(|s| s.trim().is_empty()) {
                    problems.push(format!("{oid}: empty {field}"));
                }
            }
            let sources = o["source"].as_array().map(Vec::as_slice).unwrap_or_default();
            if sources.is_empty() {
                problems.push(format!("{oid}: no source citation"));
            }
            for s in sources {
                if s["sha"].as_str() != Some(&sha[..7]) {
                    problems.push(format!("{oid}: source {} cites sha {} instead of {}", s["path"], s["sha"], &sha[..7]));
                }
                if s["line"].as_u64().is_none_or(|l| l == 0) || s["path"].as_str().is_none_or(str::is_empty) {
                    problems.push(format!("{oid}: malformed source {s}"));
                }
            }
            if let Some(t) = o["public_signal"]["x_gateway_error"].as_str() {
                for part in t.split('|').map(str::trim).filter(|p| ident.is_match(p)) {
                    if !tokens.contains(part) {
                        problems.push(format!("{oid}: x_gateway_error {part:?} is not one of this release's public tokens"));
                    }
                }
            }
        }
        for o in outcomes {
            for s in o["shared_signal_with"].as_array().map(Vec::as_slice).unwrap_or_default() {
                if !s.as_str().is_some_and(|s| ids.contains(s)) {
                    problems.push(format!("{}: shared_signal_with names unknown outcome {s}", o["id"]));
                }
            }
        }
        for (case, list) in raw["fixture_index"].as_object().unwrap() {
            for x in list.as_array().unwrap() {
                if !x.as_str().is_some_and(|x| ids.contains(x)) {
                    problems.push(format!("fixture_index[{case}] names unknown outcome {x}"));
                }
            }
        }
        for t in raw["marker_semantics"]["tokens"].as_object().map(|m| m.keys().collect::<Vec<_>>()).unwrap_or_default() {
            if !tokens.contains(t.as_str()) {
                problems.push(format!("marker_semantics names unknown token {t}"));
            }
        }
        for r in raw["removed_outcomes"].as_array().map(Vec::as_slice).unwrap_or_default() {
            let rid = r["id"].as_str().unwrap_or_default();
            if ids.contains(rid) {
                problems.push(format!("removed outcome {rid} is still listed"));
            }
            if previous.as_ref().is_some_and(|p| !p.contains(rid)) {
                problems.push(format!("removed outcome {rid} does not exist in the previous release's catalog"));
            }
            if r["reason"].as_str().is_none_or(|s| s.trim().is_empty()) {
                problems.push(format!("removed outcome {rid} has no reason"));
            }
        }
        if raw["drift"].as_array().is_none_or(Vec::is_empty) {
            problems.push("no drift / reconciliation section".into());
        }
        assert!(problems.is_empty(), "{id} catalog problems:\n  {}", problems.join("\n  "));
        previous = Some(ids);
    }
}

/// The desktop profile dialog offers exactly the embedded catalogs, newest
/// (the default for new profiles) first.
#[test]
fn desktop_profile_dialog_offers_the_embedded_catalogs() {
    let src = std::fs::read_to_string(repo_root().join("apps/desktop/src/Dialogs.tsx")).unwrap();
    let start = src.find("export const FERRUM_COMPATIBILITY").expect("FERRUM_COMPATIBILITY list in Dialogs.tsx");
    let list = &src[start..start + src[start..].find("] as const").expect("end of list")];
    let offered: Vec<String> = Regex::new(r#"id: "([^"]+)""#).unwrap().captures_iter(list).map(|c| c[1].to_string()).collect();
    let mut embedded: Vec<String> = ferrum::compatibility_ids().map(String::from).collect();
    embedded.reverse();
    assert_eq!(offered, embedded, "Dialogs.tsx FERRUM_COMPATIBILITY must list every embedded catalog, newest first");
    assert_eq!(offered.first().map(String::as_str), Some(ferrum::DEFAULT_COMPATIBILITY_ID));
}

#[test]
fn self_worded_codes_are_the_known_adapter_observations() {
    // Call sites that word their own finding bypass the catalog; keep that set
    // explicit so a rule does not drift out of the catalog unnoticed.
    let emitted = scan(&sources());
    let self_worded: BTreeSet<&str> =
        emitted.self_worded.keys().map(String::as_str).filter(|c| !render::catalog().findings.contains_key(*c)).collect();
    let allowed: BTreeSet<&str> = ["grpc.reflection_unavailable", "udp.icmp_port_unreachable", "udp.repeated_payloads"].into();
    assert_eq!(
        self_worded, allowed,
        "self-worded finding codes changed; move new wording into catalog/diagnostics/findings.en.json or update this list with a reason"
    );
}

#[test]
fn catalog_entries_are_well_formed() {
    let catalog = render::catalog();
    assert_eq!(catalog.locale, "en");
    assert!(!catalog.version.trim().is_empty());
    // Codes whose call sites always supply title/explanation (e.g.
    // `ferrum.outcome`, worded from the Ferrum compatibility catalog) may leave
    // those two fields empty here; everything else needs both.
    let emitted = scan(&sources());
    let worded_at_call_site = |code: &str| emitted.self_worded.contains_key(code) && !emitted.worded_by_catalog.contains_key(code);
    let placeholder = Regex::new(r"\{([^{}]*)\}").unwrap();
    let ident = Regex::new(r"^[a-z][a-z0-9_]*$").unwrap();
    let mut problems = Vec::new();
    for (code, t) in &catalog.findings {
        if t.title.trim().is_empty() || (t.explanation.trim().is_empty() && !worded_at_call_site(code)) {
            problems.push(format!("{code}: empty title or explanation"));
        }
        let texts = std::iter::once(&t.title)
            .chain(std::iter::once(&t.explanation))
            .chain(&t.alternatives)
            .chain(&t.does_not_prove)
            .chain(&t.confirm_with)
            .chain(t.remediation.iter().map(|r| &r.text));
        for text in texts {
            for p in placeholder.captures_iter(text) {
                if !ident.is_match(&p[1]) {
                    problems.push(format!("{code}: malformed placeholder {{{}}} in {text:?}", &p[1]));
                }
            }
        }
        for r in &t.remediation {
            // render::owner() silently maps unknown strings to Owner::Unknown;
            // require the catalog to use the contract's spelling.
            if serde_json::from_value::<Owner>(serde_json::Value::String(r.owner.clone())).is_err() {
                problems.push(format!("{code}: remediation owner {:?} is not a contract Owner value", r.owner));
            }
        }
    }
    assert!(problems.is_empty(), "catalog problems:\n  {}", problems.join("\n  "));
}
