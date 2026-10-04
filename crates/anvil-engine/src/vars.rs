//! Variable resolution.
//!
//! Precedence (later wins): app defaults → workspace base → selected
//! environment → folders (root → leaf) → iteration dataset → run-local
//! extracted values. `{{name}}` references resolve recursively with cycle
//! detection and bounded expansion. Unresolved names fail validation; they
//! are never silently replaced with an empty string. Dynamic helpers:
//! `{{$uuid}}`, `{{$timestamp}}`, `{{$timestampMs}}`, `{{$isoTimestamp}}`,
//! `{{$randomInt}}`, `{{$randomInt 1 10}}`, `{{$counter}}`,
//! `{{$randomFrom a|b|c}}`.

use crate::context::SecretResolver;
use anvil_domain::execution::{FailureKind, Phase, TransportFailure};
use parking_lot::Mutex;
use rand::{RngExt, SeedableRng};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use zeroize::Zeroizing;

const MAX_DEPTH: usize = 16;
const MAX_OUTPUT: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct VarEntry {
    pub name: String,
    pub value: String,
    pub secret: bool,
}

#[derive(Debug, Clone)]
pub struct VarLayer {
    /// Scope label shown in errors and the Effective request inspector.
    pub label: String,
    pub vars: Vec<VarEntry>,
}

pub struct Resolver {
    layers: Vec<VarLayer>,
    secrets: Option<Arc<dyn SecretResolver>>,
    variable_values: Mutex<HashMap<(usize, usize), Zeroizing<String>>>,
    value_transform: Option<fn(&str) -> String>,
    pub(crate) oauth_endpoint: Mutex<Option<(String, String)>>,
    counter: AtomicU64,
    secret_substitutions: AtomicU64,
    rng: Mutex<rand::rngs::StdRng>,
    /// Secret values substituted so far (for exact-value redaction).
    pub used_secrets: Mutex<Vec<String>>,
    /// What secrets substituted into a hex- or base64-encoded session payload
    /// decode to, as text and as hex (for exact-value redaction; see
    /// `redact::note_decoded_secrets`).
    pub decoded_secrets: Mutex<Vec<String>>,
    /// Names (and winning scope) of variables used.
    pub used: Mutex<Vec<(String, String)>>,
    /// Names of request fields (headers, query parameters, form fields) the
    /// user marked sensitive, for name-based redaction.
    pub sensitive_names: Mutex<Vec<String>>,
}

impl Resolver {
    pub fn new(layers: Vec<VarLayer>, seed: Option<u64>) -> Self {
        let rng = match seed {
            Some(s) => rand::rngs::StdRng::seed_from_u64(s),
            None => rand::make_rng(),
        };
        Resolver {
            layers,
            secrets: None,
            variable_values: Mutex::new(HashMap::new()),
            value_transform: None,
            oauth_endpoint: Mutex::new(None),
            counter: AtomicU64::new(0),
            secret_substitutions: AtomicU64::new(0),
            rng: Mutex::new(rng),
            used_secrets: Mutex::new(vec![]),
            decoded_secrets: Mutex::new(vec![]),
            used: Mutex::new(vec![]),
            sensitive_names: Mutex::new(vec![]),
        }
    }

    /// Resolve deferred vault variables on use or during complete-scope preparation.
    pub fn with_secrets(mut self, secrets: Arc<dyn SecretResolver>) -> Self {
        self.secrets = Some(secrets);
        self
    }

    /// Preflight masks dynamic helpers, including helpers inside vault values.
    pub fn with_value_transform(mut self, transform: fn(&str) -> String) -> Self {
        self.value_transform = Some(transform);
        self
    }

    /// Record a request field the user marked sensitive: its resolved value
    /// joins the exact-value secrets and its name the redacted names.
    pub fn mark_sensitive(&self, name: &str, value: &str) {
        if !value.is_empty() {
            self.used_secrets.lock().push(value.to_string());
        }
        let mut names = self.sensitive_names.lock();
        if !name.is_empty() && !names.iter().any(|n| n.eq_ignore_ascii_case(name)) {
            names.push(name.to_string());
        }
    }

    pub fn with_counter_start(self, n: u64) -> Self {
        self.counter.store(n, Ordering::Relaxed);
        self
    }

    fn lookup(&self, name: &str) -> Option<(&VarEntry, &str, usize, usize)> {
        for (layer_index, layer) in self.layers.iter().enumerate().rev() {
            if let Some((variable_index, v)) = layer.vars.iter().enumerate().rev().find(|(_, v)| v.name == name) {
                return Some((v, &layer.label, layer_index, variable_index));
            }
        }
        None
    }

    pub fn scopes_searched(&self) -> Vec<String> {
        self.layers.iter().map(|l| l.label.clone()).collect()
    }

    /// Number of secret variable substitutions performed so far.
    pub(crate) fn secret_substitutions(&self) -> u64 {
        self.secret_substitutions.load(Ordering::Relaxed)
    }

    /// Resolve all `{{…}}` references in `input`. `field` names the request
    /// field for error messages (e.g. `headers[2].value`).
    pub fn resolve(&self, input: &str, field: &str) -> Result<String, TransportFailure> {
        let mut stack = Vec::new();
        self.resolve_inner(input, field, &mut stack, 0)
    }

    fn resolve_inner(&self, input: &str, field: &str, stack: &mut Vec<String>, depth: usize) -> Result<String, TransportFailure> {
        if !input.contains("{{") {
            return Ok(input.to_string());
        }
        if depth > MAX_DEPTH {
            return Err(TransportFailure::new(
                Phase::Prepare,
                FailureKind::VariableCycle,
                format!("variable expansion in {field} exceeded {MAX_DEPTH} levels ({})", stack.join(" → ")),
            )
            .with_field(field));
        }
        let mut out = String::with_capacity(input.len());
        let mut rest = input;
        while let Some(open) = rest.find("{{") {
            out.push_str(&rest[..open]);
            let after = &rest[open + 2..];
            let Some(close) = after.find("}}") else {
                // Unterminated braces are literal text.
                out.push_str(&rest[open..]);
                rest = "";
                break;
            };
            let expr = after[..close].trim();
            rest = &after[close + 2..];
            if let Some(dynamic) = expr.strip_prefix('$') {
                out.push_str(&self.dynamic(dynamic, field)?);
            } else {
                if expr.is_empty() {
                    return Err(TransportFailure::new(
                        Phase::Prepare,
                        FailureKind::UnresolvedVariable,
                        format!("empty variable reference {{{{}}}} in {field}."),
                    )
                    .with_field(field));
                }
                if stack.iter().any(|s| s == expr) {
                    let mut path = stack.clone();
                    path.push(expr.to_string());
                    return Err(TransportFailure::new(
                        Phase::Prepare,
                        FailureKind::VariableCycle,
                        format!("variables reference each other in a cycle: {}", path.join(" → ")),
                    )
                    .with_field(field));
                }
                let Some((entry, scope, layer_index, variable_index)) = self.lookup(expr) else {
                    return Err(TransportFailure::new(
                        Phase::Prepare,
                        FailureKind::UnresolvedVariable,
                        format!(
                            "variable '{expr}' used in {field} is not defined in any active scope ({}).",
                            self.scopes_searched().join(", ")
                        ),
                    )
                    .with_field(field));
                };
                self.used.lock().push((expr.to_string(), scope.to_string()));
                stack.push(expr.to_string());
                let raw = self.variable_value(layer_index, variable_index)?;
                let value = self.resolve_inner(&raw, field, stack, depth + 1).map_err(|mut failure| {
                    if entry.secret {
                        failure.message = "could not resolve a secret variable; check the vault and active variables".into();
                    }
                    failure
                })?;
                stack.pop();
                if entry.secret && !value.is_empty() {
                    self.secret_substitutions.fetch_add(1, Ordering::Relaxed);
                    self.used_secrets.lock().push(value.clone());
                }
                out.push_str(&value);
            }
            if out.len() > MAX_OUTPUT {
                return Err(TransportFailure::new(
                    Phase::Prepare,
                    FailureKind::VariableCycle,
                    format!("variable expansion in {field} exceeded {MAX_OUTPUT} bytes"),
                )
                .with_field(field));
            }
        }
        out.push_str(rest);
        Ok(out)
    }

    /// The frozen, unexpanded value used when preparing the original layers.
    /// Caller must validate the OAuth endpoint before materializing credentials.
    pub fn variable_value(&self, layer: usize, variable: usize) -> Result<String, TransportFailure> {
        let entry = &self.layers[layer].vars[variable];
        let value = match self.secrets.as_ref().and_then(|s| s.variable_secret(layer, variable)) {
            Some(reference) => {
                let mut values = self.variable_values.lock();
                if let Some(value) = values.get(&(layer, variable)) {
                    value.to_string()
                } else {
                    let value = self.secrets.as_ref().unwrap().resolve(&reference).map_err(|_| {
                        TransportFailure::new(
                            Phase::Prepare,
                            FailureKind::AuthPreparationFailed,
                            "could not resolve a secret variable; check the vault and active variables",
                        )
                        .with_field("variables")
                    })?;
                    let raw = value.to_string();
                    values.insert((layer, variable), value);
                    raw
                }
            }
            None => entry.value.clone(),
        };
        Ok(match self.value_transform {
            Some(transform) => transform(&value),
            None => value,
        })
    }

    /// Freeze every enabled vault variable after OAuth validation, including
    /// unused and shadowed entries. Do not expand their data or dynamic helpers.
    pub(crate) fn materialize_variables(&self) -> Result<(), TransportFailure> {
        if let Some(secrets) = &self.secrets {
            for (layer_index, layer) in self.layers.iter().enumerate() {
                for variable_index in 0..layer.vars.len() {
                    if secrets.variable_secret(layer_index, variable_index).is_some() {
                        self.variable_value(layer_index, variable_index)?;
                    }
                }
            }
        }
        Ok(())
    }

    fn dynamic(&self, expr: &str, field: &str) -> Result<String, TransportFailure> {
        let mut parts = expr.split_whitespace();
        let name = parts.next().unwrap_or("");
        let args: Vec<&str> = parts.collect();
        let now = chrono::Utc::now();
        Ok(match name {
            "uuid" | "randomUUID" | "guid" => uuid::Uuid::new_v4().to_string(),
            "timestamp" => now.timestamp().to_string(),
            "timestampMs" => now.timestamp_millis().to_string(),
            "isoTimestamp" => now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "counter" => (self.counter.fetch_add(1, Ordering::Relaxed) + 1).to_string(),
            "randomInt" => {
                let (lo, hi) = match args.as_slice() {
                    [a, b] => (a.parse::<i64>().unwrap_or(0), b.parse::<i64>().unwrap_or(1000)),
                    _ => (0, 1000),
                };
                if hi < lo {
                    return Err(TransportFailure::new(
                        Phase::Prepare,
                        FailureKind::UnresolvedVariable,
                        format!("$randomInt range {lo}..{hi} is empty in {field}"),
                    )
                    .with_field(field));
                }
                self.rng.lock().random_range(lo..=hi).to_string()
            }
            "randomFrom" => {
                let joined = args.join(" ");
                let choices: Vec<&str> = joined.split('|').filter(|s| !s.is_empty()).take(1000).collect();
                if choices.is_empty() {
                    return Err(TransportFailure::new(
                        Phase::Prepare,
                        FailureKind::UnresolvedVariable,
                        format!("$randomFrom needs choices a|b|c in {field}"),
                    )
                    .with_field(field));
                }
                let i = self.rng.lock().random_range(0..choices.len());
                choices[i].to_string()
            }
            other => {
                return Err(TransportFailure::new(
                    Phase::Prepare,
                    FailureKind::UnresolvedVariable,
                    format!("unknown dynamic variable '${other}' in {field}"),
                )
                .with_field(field));
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layer(label: &str, vars: &[(&str, &str, bool)]) -> VarLayer {
        VarLayer {
            label: label.into(),
            vars: vars.iter().map(|(n, v, s)| VarEntry { name: n.to_string(), value: v.to_string(), secret: *s }).collect(),
        }
    }

    #[test]
    fn precedence_later_layers_win() {
        let r = Resolver::new(
            vec![layer("workspace", &[("host", "ws.example", false)]), layer("environment:dev", &[("host", "dev.example", false)])],
            None,
        );
        assert_eq!(r.resolve("https://{{host}}/x", "url").unwrap(), "https://dev.example/x");
    }

    #[test]
    fn local_002_unresolved_is_an_error_with_scopes() {
        let r = Resolver::new(vec![layer("workspace", &[])], None);
        let e = r.resolve("Bearer {{token}}", "headers[0].value").unwrap_err();
        assert_eq!(e.kind, FailureKind::UnresolvedVariable);
        assert!(e.message.contains("token") && e.message.contains("workspace"));
        assert_eq!(e.field.as_deref(), Some("headers[0].value"));
    }

    #[test]
    fn local_003_cycle_detected_with_path() {
        let r = Resolver::new(vec![layer("env", &[("a", "{{b}}", false), ("b", "x{{a}}", false)])], None);
        let e = r.resolve("{{a}}", "url").unwrap_err();
        assert_eq!(e.kind, FailureKind::VariableCycle);
        assert!(e.message.contains("a → b → a"), "{}", e.message);
    }

    #[test]
    fn secrets_are_tracked_for_redaction() {
        let r = Resolver::new(vec![layer("env", &[("key", "s3cr3t-value", true), ("k2", "{{key}}", false)])], None);
        assert_eq!(r.resolve("x={{k2}}", "q").unwrap(), "x=s3cr3t-value");
        assert!(r.used_secrets.lock().contains(&"s3cr3t-value".to_string()));
    }

    #[test]
    fn secret_substitutions_are_counted_independently_of_redaction_values() {
        let r = Resolver::new(vec![layer("env", &[("key", "s3cr3t-value", true)])], None);
        assert_eq!(r.resolve("{{key}}", "headers[0].value").unwrap(), "s3cr3t-value");
        assert_eq!(r.resolve("{{key}}", "body").unwrap(), "s3cr3t-value");
        r.used_secrets.lock().dedup();
        assert_eq!(r.used_secrets.lock().len(), 1);
        assert_eq!(r.secret_substitutions(), 2);
    }

    #[test]
    fn seeded_dynamic_values_are_reproducible() {
        let a = Resolver::new(vec![], Some(42));
        let b = Resolver::new(vec![], Some(42));
        assert_eq!(a.resolve("{{$randomInt 1 1000000}}", "x").unwrap(), b.resolve("{{$randomInt 1 1000000}}", "x").unwrap());
        assert_eq!(a.resolve("{{$counter}}-{{$counter}}", "x").unwrap(), "1-2");
    }
}
