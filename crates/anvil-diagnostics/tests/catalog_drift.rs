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
//! * `format!("ferrum.token.{t}")`, expanded over the Ferrum compatibility
//!   catalog's public token vocabulary.
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
    for t in &ferrum::catalog().tokens {
        expected.insert(format!("ferrum.token.{t}"), "rules/ferrum_rules.rs (public token vocabulary)".into());
    }

    let missing: Vec<String> =
        expected.iter().filter(|(c, _)| !catalog.findings.contains_key(*c)).map(|(c, f)| format!("{c}  (emitted in {f})")).collect();
    assert!(missing.is_empty(), "finding codes without wording in catalog/diagnostics/findings.en.json:\n  {}", missing.join("\n  "));

    let stale: Vec<&String> =
        catalog.findings.keys().filter(|c| !expected.contains_key(*c) && !emitted.self_worded.contains_key(*c)).collect();
    assert!(stale.is_empty(), "catalog entries no rule emits (stale wording or an unrecognised construction pattern): {stale:?}");
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
