//! Insomnia v4 JSON exports and v5 YAML collection/environment files.
//!
//! Request groups become folders; the base environment becomes workspace
//! variables and sub-environments become environments (nested data is
//! flattened to dotted names). Nunjucks `{{ _.var }}` references become
//! Anvil `{{var}}`; `{% uuid %}` / `{% now %}` tags map to dynamic
//! variables; other template tags are reported and left in place. Scripts
//! and unit tests are retained in the report, never executed.

use crate::builder::Builder;
use crate::common::{body_from_text, credential, dedupe_content_type, env_var, header_content_type, maybe_redact, parse_form};
use crate::util::{is_credential_name, ptr, sanitize_var, scalar_text, str_of};
use crate::{Dialect, ImportError};
use anvil_domain::Id;
use anvil_domain::auth::{AuthConfig, KeyLocation, OAuth2Config, OAuthClientAuth, OAuthGrant};
use anvil_domain::request::{Body, KeyValue, MultipartContent, MultipartPart, RequestSpec};
use anvil_domain::secret::SensitiveValue;
use anvil_domain::settings::SettingsOverrides;
use anvil_domain::workspace::Variable;
use serde_json::{Map, Value};
use std::collections::HashMap;

const MAX_DEPTH: usize = 64;

/// Convert Insomnia/Nunjucks templating to Anvil `{{var}}` syntax.
pub(crate) fn template(b: &mut Builder, s: &str, at: &str) -> String {
    if !s.contains("{{") && !s.contains("{%") {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    loop {
        let next_var = rest.find("{{");
        let next_tag = rest.find("{%");
        let (i, is_tag) = match (next_var, next_tag) {
            (Some(v), Some(t)) if t < v => (t, true),
            (Some(v), _) => (v, false),
            (None, Some(t)) => (t, true),
            (None, None) => break,
        };
        out.push_str(&rest[..i]);
        let after = &rest[i + 2..];
        let close = if is_tag { "%}" } else { "}}" };
        let Some(end) = after.find(close) else {
            out.push_str(&rest[i..]);
            rest = "";
            break;
        };
        let inner = after[..end].trim();
        rest = &after[end + 2..];
        if is_tag {
            let mut words = inner.split_whitespace();
            let tag = words.next().unwrap_or("");
            let arg = words.next().unwrap_or("").trim_matches(|c| c == '\'' || c == '"');
            let mapped = match (tag, arg) {
                ("uuid", _) => Some("{{$uuid}}"),
                ("now", "millis" | "ms") => Some("{{$timestampMs}}"),
                ("now", "unix" | "seconds" | "s") => Some("{{$timestamp}}"),
                ("now", _) => Some("{{$isoTimestamp}}"),
                _ => None,
            };
            match mapped {
                Some(m) => out.push_str(m),
                None => {
                    b.report.unsupported(
                        "template_tag",
                        at,
                        format!("Insomnia template tag `{{% {tag} … %}}` has no Anvil equivalent; replace it before sending"),
                    );
                    out.push_str(&format!("{{%{}%}}", &after[..end]));
                }
            }
        } else {
            let expr = inner.strip_prefix("_.").unwrap_or(inner);
            if expr.contains('|') || expr.contains('(') || expr.contains(' ') {
                b.report.unsupported(
                    "template_expression",
                    at,
                    format!("Nunjucks expression `{{{{ {inner} }}}}` is not supported; left as written"),
                );
                out.push_str(&format!("{{{{{}}}}}", &after[..end]));
            } else {
                let expr = expr.strip_prefix("_['").and_then(|e| e.strip_suffix("']")).unwrap_or(expr);
                out.push_str(&format!("{{{{{expr}}}}}"));
            }
        }
    }
    out.push_str(rest);
    out
}

fn sort_key(v: &Value) -> f64 {
    v.get("metaSortKey").or_else(|| v.pointer("/meta/sortKey")).and_then(Value::as_f64).unwrap_or(0.0)
}

/// Flatten nested environment data (`{api: {host: x}}` → `api.host`).
fn flatten(prefix: &str, v: &Value, out: &mut Vec<(String, String)>, depth: usize) {
    match v {
        Value::Object(m) if depth < 16 => {
            for (k, x) in m {
                let name = if prefix.is_empty() { k.clone() } else { format!("{prefix}.{k}") };
                flatten(&name, x, out, depth + 1);
            }
        }
        Value::Array(_) | Value::Object(_) => out.push((prefix.to_string(), v.to_string())),
        other => out.push((prefix.to_string(), scalar_text(other))),
    }
}

fn env_vars(b: &mut Builder, data: Option<&Value>, at: &str) -> Vec<Variable> {
    let mut flat = vec![];
    if let Some(d) = data {
        flatten("", d, &mut flat, 0);
    }
    let mut out = vec![];
    for (k, v) in flat {
        let p = ptr(at, &k);
        let v = template(b, &v, &p);
        if let Some(var) = env_var(b, &k, &v, is_credential_name(&k), true, &p) {
            out.push(var);
        }
    }
    out
}

// ---------------------------------------------------------------- v4 ----

pub(crate) fn import_v4(root: &Value, b: &mut Builder) -> Result<(), ImportError> {
    let Some(resources) = root.get("resources").and_then(Value::as_array) else {
        return Err(ImportError::Invalid {
            dialect: Dialect::InsomniaV4,
            pointer: "/resources".into(),
            message: "missing `resources` array".into(),
        });
    };
    let mut by_parent: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, r) in resources.iter().enumerate() {
        by_parent.entry(str_of(r, "parentId").unwrap_or("").to_string()).or_default().push(i);
    }
    b.workspace.auth = AuthConfig::None;
    let workspaces: Vec<usize> = (0..resources.len()).filter(|i| str_of(&resources[*i], "_type") == Some("workspace")).collect();
    let mut handled = vec![false; resources.len()];
    let multi = workspaces.len() > 1;
    if multi {
        b.report.warn(
            "multiple_workspaces",
            "/resources",
            format!("the export contains {} workspaces; each becomes a top-level folder", workspaces.len()),
        );
    }
    for &w in &workspaces {
        handled[w] = true;
        let ws = &resources[w];
        let wid = str_of(ws, "_id").unwrap_or("").to_string();
        let name = str_of(ws, "name").unwrap_or("Insomnia workspace").to_string();
        let parent = if multi {
            Some(b.folder(None, &format!("insomnia:{wid}"), &name))
        } else {
            b.title = Some(name.clone());
            b.workspace.name = name.clone();
            b.workspace.description = str_of(ws, "description").unwrap_or("").to_string();
            None
        };
        // Environments: base (child of the workspace) and sub-environments.
        let envs: Vec<usize> =
            by_parent.get(&wid).into_iter().flatten().copied().filter(|i| str_of(&resources[*i], "_type") == Some("environment")).collect();
        for (n, &e) in envs.iter().enumerate() {
            handled[e] = true;
            let base = &resources[e];
            let bp = format!("/resources/{e}/data");
            let vars = env_vars(b, base.get("data"), &bp);
            if n == 0 && !multi {
                b.workspace.variables = vars;
            } else {
                b.report.warn(
                    "extra_base_environment",
                    &format!("/resources/{e}"),
                    "additional base environment imported as an environment",
                );
                b.add_environment(
                    &format!("insomnia:{}", str_of(base, "_id").unwrap_or("")),
                    str_of(base, "name").unwrap_or("Environment"),
                    vars,
                );
            }
            let bid = str_of(base, "_id").unwrap_or("").to_string();
            let mut subs: Vec<usize> = by_parent.get(&bid).into_iter().flatten().copied().collect();
            subs.sort_by(|a, c| sort_key(&resources[*a]).total_cmp(&sort_key(&resources[*c])));
            for s in subs {
                handled[s] = true;
                let sub = &resources[s];
                let sp = format!("/resources/{s}/data");
                let vars = env_vars(b, sub.get("data"), &sp);
                let id = b.add_environment(
                    &format!("insomnia:{}", str_of(sub, "_id").unwrap_or("")),
                    str_of(sub, "name").unwrap_or("Environment"),
                    vars,
                );
                if b.workspace.active_environment_id.is_none() {
                    b.workspace.active_environment_id = Some(id);
                }
                if sub.get("isPrivate").and_then(Value::as_bool) == Some(true) {
                    b.report.warn(
                        "private_environment",
                        &format!("/resources/{s}"),
                        "private environment imported; review it before sharing the workspace",
                    );
                }
            }
        }
        walk_v4(b, resources, &by_parent, &wid, parent, &mut handled, 0);
    }
    for (i, r) in resources.iter().enumerate() {
        if handled[i] {
            continue;
        }
        let ty = str_of(r, "_type").unwrap_or("unknown");
        let p = format!("/resources/{i}");
        match ty {
            "unit_test" => {
                let owner = str_of(r, "name").unwrap_or("unit test");
                if let Some(code) = str_of(r, "code") {
                    b.report.script(&p, owner, "unit_test", "text/javascript", code.to_string());
                }
            }
            "unit_test_suite" => {}
            "cookie_jar" => b.report.unsupported("cookie_jar", &p, "cookie jars are not imported (they may contain session credentials)"),
            "api_spec" => b.report.unsupported(
                "embedded_spec",
                &p,
                "embedded API spec is not imported here; import the spec file with the OpenAPI importer",
            ),
            "grpc_request" | "websocket_request" | "websocket_payload" | "proto_file" | "proto_directory" => {
                if ty.ends_with("_request") {
                    b.report.counts.operations_found += 1;
                    b.skipped();
                }
                b.report.unsupported("insomnia_resource", &p, format!("Insomnia '{ty}' resources are not imported yet"))
            }
            "request" | "request_group" | "environment" => {
                b.report.warn("orphan_resource", &p, format!("{ty} is not reachable from a workspace; skipped"));
                if ty == "request" {
                    b.report.counts.operations_found += 1;
                    b.skipped();
                }
            }
            other => b.report.unsupported("insomnia_resource", &p, format!("Insomnia '{other}' resources are not imported")),
        }
    }
    Ok(())
}

fn walk_v4(
    b: &mut Builder,
    res: &[Value],
    by_parent: &HashMap<String, Vec<usize>>,
    pid: &str,
    folder: Option<Id>,
    handled: &mut [bool],
    depth: usize,
) {
    if depth > MAX_DEPTH {
        b.report.warn(
            "folder_depth_limit",
            "/resources",
            format!("request groups nested deeper than {MAX_DEPTH} levels were not imported"),
        );
        return;
    }
    let mut kids: Vec<usize> = by_parent.get(pid).into_iter().flatten().copied().collect();
    kids.sort_by(|a, c| sort_key(&res[*a]).total_cmp(&sort_key(&res[*c])).then(a.cmp(c)));
    for i in kids {
        let r = &res[i];
        let at = format!("/resources/{i}");
        match str_of(r, "_type") {
            Some("request_group") => {
                handled[i] = true;
                let id = str_of(r, "_id").unwrap_or("").to_string();
                let name = str_of(r, "name").unwrap_or("Folder").to_string();
                let fid =
                    group(b, r, &at, folder, &id, &name, r.get("environment"), r.get("preRequestScript"), r.get("afterResponseScript"));
                walk_v4(b, res, by_parent, &id, Some(fid), handled, depth + 1);
            }
            Some("request") => {
                handled[i] = true;
                if !b.admit(&at) {
                    continue;
                }
                let key = format!("insomnia:{}", str_of(r, "_id").unwrap_or(&at));
                let settings = v4_settings(b, r, &at);
                let scripts = [("prerequest", r.get("preRequestScript")), ("after_response", r.get("afterResponseScript"))];
                request(b, r, &at, folder, &key, settings, &scripts);
            }
            _ => {}
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn group(
    b: &mut Builder,
    r: &Value,
    at: &str,
    parent: Option<Id>,
    id: &str,
    name: &str,
    env: Option<&Value>,
    pre: Option<&Value>,
    post: Option<&Value>,
) -> Id {
    let fid = b.folder(parent, &format!("insomnia:{id}"), name);
    let vars = env_vars(b, env, &ptr(at, "environment"));
    let auth = r.get("authentication").map(|a| auth(b, a, &ptr(at, "authentication"), name));
    for (ev, s) in [("prerequest", pre), ("after_response", post)] {
        if let Some(src) = s.and_then(Value::as_str).filter(|s| !s.trim().is_empty()) {
            b.report.script(at, name, ev, "text/javascript", src.to_string());
        }
    }
    if r.get("headers").and_then(Value::as_array).is_some_and(|h| !h.is_empty()) {
        b.report.unsupported("folder_headers", &ptr(at, "headers"), "folder-level headers are not supported; add them to the requests");
    }
    let desc = str_of(r, "description").or_else(|| r.pointer("/meta/description").and_then(Value::as_str)).unwrap_or("").to_string();
    if let Some(f) = b.folder_mut(fid) {
        f.variables = vars;
        f.description = desc;
        if let Some(a) = auth {
            f.auth = a;
        }
    }
    fid
}

fn v4_settings(b: &mut Builder, r: &Value, at: &str) -> SettingsOverrides {
    let mut s = SettingsOverrides::default();
    match str_of(r, "settingFollowRedirects") {
        Some("on") => s.redirects = Some(anvil_domain::settings::RedirectPolicy { follow: true, ..Default::default() }),
        Some("off") => s.redirects = Some(anvil_domain::settings::RedirectPolicy { follow: false, ..Default::default() }),
        _ => {}
    }
    if r.get("settingSendCookies").and_then(Value::as_bool) == Some(false) {
        s.cookies = Some(false);
    }
    if r.get("settingEncodeUrl").and_then(Value::as_bool) == Some(false) {
        b.report.unsupported("encode_url_off", at, "disabling URL encoding is not supported; Anvil percent-encodes query values");
    }
    if r.get("settingDisableRenderRequestBody").and_then(Value::as_bool) == Some(true) {
        b.report.unsupported("render_body_off", at, "Anvil always resolves {{variables}} in bodies; the body is interpolated when sent");
    }
    s
}

// ---------------------------------------------------------------- v5 ----

pub(crate) fn import_v5(root: &Value, b: &mut Builder) -> Result<(), ImportError> {
    let ty = str_of(root, "type").unwrap_or("");
    let name = str_of(root, "name").unwrap_or("Insomnia collection").to_string();
    b.title = Some(name.clone());
    b.workspace.name = name;
    b.workspace.auth = AuthConfig::None;
    if let Some(d) = root.pointer("/meta/description").and_then(Value::as_str) {
        b.workspace.description = d.to_string();
    }
    if !ty.starts_with("collection.") && !ty.starts_with("environment.") && !ty.starts_with("spec.") {
        return Err(ImportError::UnsupportedDialect {
            dialect: Dialect::InsomniaV5,
            message: format!("Insomnia document type '{ty}' is not supported"),
        });
    }
    if root.get("spec").is_some() {
        b.report.unsupported(
            "embedded_spec",
            "/spec",
            "embedded API spec is not imported here; import the spec file with the OpenAPI importer",
        );
    }
    if root.get("cookieJar").is_some() {
        b.report.unsupported("cookie_jar", "/cookieJar", "cookie jars are not imported (they may contain session credentials)");
    }
    if let Some(envs) = root.get("environments") {
        let base_vars = env_vars(b, envs.get("data"), "/environments/data");
        b.workspace.variables = base_vars;
        for (i, sub) in envs.get("subEnvironments").and_then(Value::as_array).into_iter().flatten().enumerate() {
            let p = format!("/environments/subEnvironments/{i}");
            let vars = env_vars(b, sub.get("data"), &ptr(&p, "data"));
            let key = sub.pointer("/meta/id").and_then(Value::as_str).map(str::to_string).unwrap_or(p.clone());
            let id = b.add_environment(&format!("insomnia:{key}"), str_of(sub, "name").unwrap_or("Environment"), vars);
            if b.workspace.active_environment_id.is_none() {
                b.workspace.active_environment_id = Some(id);
            }
            if sub.get("isPrivate").and_then(Value::as_bool) == Some(true) {
                b.report.warn("private_environment", &p, "private environment imported; review it before sharing the workspace");
            }
        }
    }
    if let Some(items) = root.get("collection").and_then(Value::as_array) {
        walk_v5(b, items, "/collection", None, 0);
    }
    Ok(())
}

fn walk_v5(b: &mut Builder, items: &[Value], base: &str, folder: Option<Id>, depth: usize) {
    if depth > MAX_DEPTH {
        b.report.warn("folder_depth_limit", base, format!("folders nested deeper than {MAX_DEPTH} levels were not imported"));
        return;
    }
    let mut order: Vec<usize> = (0..items.len()).collect();
    order.sort_by(|a, c| sort_key(&items[*a]).total_cmp(&sort_key(&items[*c])).then(a.cmp(c)));
    for i in order {
        let it = &items[i];
        let at = format!("{base}/{i}");
        let id = it.pointer("/meta/id").and_then(Value::as_str).unwrap_or("").to_string();
        let name = str_of(it, "name").unwrap_or("").to_string();
        if let Some(children) = it.get("children").and_then(Value::as_array) {
            let key = if id.is_empty() { at.clone() } else { id.clone() };
            let pre = it.pointer("/scripts/preRequest");
            let post = it.pointer("/scripts/afterResponse");
            let fid = group(b, it, &at, folder, &key, if name.is_empty() { "Folder" } else { &name }, it.get("environment"), pre, post);
            walk_v5(b, children, &ptr(&at, "children"), Some(fid), depth + 1);
        } else if it.get("url").is_some() || it.get("method").is_some() {
            if id.starts_with("greq_") || id.starts_with("ws-req_") {
                b.report.counts.operations_found += 1;
                b.skipped();
                b.report.unsupported("insomnia_resource", &at, "gRPC/WebSocket requests are not imported yet");
                continue;
            }
            if !b.admit(&at) {
                continue;
            }
            let key = format!("insomnia:{}", if id.is_empty() { at.clone() } else { id });
            let settings = v5_settings(b, it.get("settings"), &ptr(&at, "settings"));
            let scripts = [("prerequest", it.pointer("/scripts/preRequest")), ("after_response", it.pointer("/scripts/afterResponse"))];
            request(b, it, &at, folder, &key, settings, &scripts);
        } else {
            b.report.warn("empty_item", &at, "collection item is neither a folder nor a request; skipped");
        }
    }
}

fn v5_settings(b: &mut Builder, s: Option<&Value>, at: &str) -> SettingsOverrides {
    let mut out = SettingsOverrides::default();
    let Some(s) = s else { return out };
    match str_of(s, "followRedirects") {
        Some("on") => out.redirects = Some(anvil_domain::settings::RedirectPolicy { follow: true, ..Default::default() }),
        Some("off") => out.redirects = Some(anvil_domain::settings::RedirectPolicy { follow: false, ..Default::default() }),
        _ => {}
    }
    if s.pointer("/cookies/send").and_then(Value::as_bool) == Some(false) {
        out.cookies = Some(false);
    }
    if s.get("encodeUrl").and_then(Value::as_bool) == Some(false) {
        b.report.unsupported("encode_url_off", at, "disabling URL encoding is not supported; Anvil percent-encodes query values");
    }
    if s.get("renderRequestBody").and_then(Value::as_bool) == Some(false) {
        b.report.unsupported("render_body_off", at, "Anvil always resolves {{variables}} in bodies; the body is interpolated when sent");
    }
    out
}

// ------------------------------------------------------------ shared ----

fn kv_list(b: &mut Builder, v: Option<&Value>, at: &str, what: &str) -> Vec<KeyValue> {
    let mut out = vec![];
    for (i, h) in v.and_then(Value::as_array).into_iter().flatten().enumerate() {
        let p = format!("{at}/{i}");
        let name = template(b, str_of(h, "name").unwrap_or(""), &p);
        if name.is_empty() {
            continue;
        }
        let raw = template(b, &h.get("value").map(scalar_text).unwrap_or_default(), &p);
        let (value, sensitive) = maybe_redact(b, &name, &raw, &p, what);
        out.push(KeyValue {
            name,
            value,
            enabled: h.get("disabled").and_then(Value::as_bool) != Some(true),
            description: str_of(h, "description").unwrap_or("").to_string(),
            sensitive,
        });
    }
    out
}

fn request(
    b: &mut Builder,
    r: &Value,
    at: &str,
    folder: Option<Id>,
    key: &str,
    settings: SettingsOverrides,
    scripts: &[(&str, Option<&Value>)],
) {
    let name = str_of(r, "name").unwrap_or("").to_string();
    let method = str_of(r, "method").unwrap_or("GET").to_ascii_uppercase();
    let raw_url = template(b, str_of(r, "url").unwrap_or(""), &ptr(at, "url"));
    let url = path_params(b, &raw_url, r.get("pathParameters"), &ptr(at, "pathParameters"));
    let mut spec = RequestSpec::http(&method, &url);
    spec.params = kv_list(b, r.get("parameters"), &ptr(at, "parameters"), "query");
    spec.headers = kv_list(b, r.get("headers"), &ptr(at, "headers"), "header");
    let ct = header_content_type(&spec.headers);
    spec.body = body(b, r.get("body"), &ptr(at, "body"), ct.as_deref());
    dedupe_content_type(&mut spec.headers, &spec.body);
    spec.auth = match r.get("authentication") {
        Some(a) => auth(b, a, &ptr(at, "authentication"), &name),
        None => AuthConfig::Inherit,
    };
    spec.settings = settings;
    for (ev, s) in scripts {
        if let Some(src) = s.and_then(Value::as_str).filter(|s| !s.trim().is_empty()) {
            b.report.script(at, &name, ev, "text/javascript", src.to_string());
        }
    }
    let desc = str_of(r, "description").or_else(|| r.pointer("/meta/description").and_then(Value::as_str)).unwrap_or("").to_string();
    let req = b.add_request(folder, &name, key, spec, at);
    req.description = desc;
}

fn path_params(b: &mut Builder, url: &str, params: Option<&Value>, at: &str) -> String {
    let Some(list) = params.and_then(Value::as_array).filter(|l| !l.is_empty()) else { return url.to_string() };
    let mut out = url.to_string();
    for p in list {
        let Some(name) = str_of(p, "name") else { continue };
        let val = p.get("value").map(scalar_text).unwrap_or_default();
        let rep = if val.is_empty() {
            let v = sanitize_var(name);
            b.report.require_var(&v, false, "Insomnia path parameter without a value", at);
            format!("{{{{{v}}}}}")
        } else {
            template(b, &val, at)
        };
        out = out.replace(&format!(":{name}"), &rep);
    }
    out
}

fn body(b: &mut Builder, v: Option<&Value>, at: &str, header_ct: Option<&str>) -> Body {
    let Some(v) = v.filter(|v| v.as_object().is_some_and(|m| !m.is_empty())) else { return Body::None };
    let mime = str_of(v, "mimeType").map(str::to_string).or_else(|| header_ct.map(str::to_string));
    let essence = mime.as_deref().map(crate::util::media_essence).unwrap_or_default();
    let text = template(b, str_of(v, "text").unwrap_or(""), &ptr(at, "text"));
    match essence.as_str() {
        "application/x-www-form-urlencoded" => match v.get("params") {
            Some(_) => Body::FormUrlEncoded { fields: kv_list(b, v.get("params"), &ptr(at, "params"), "form field") },
            None => parse_form(&text).map(|fields| Body::FormUrlEncoded { fields }).unwrap_or(Body::Raw { text, content_type: mime }),
        },
        "multipart/form-data" => {
            let mut parts = vec![];
            for (i, p) in v.get("params").and_then(Value::as_array).into_iter().flatten().enumerate() {
                let pp = format!("{}/{i}", ptr(at, "params"));
                let name = template(b, str_of(p, "name").unwrap_or(""), &pp);
                if str_of(p, "type") == Some("file") {
                    b.report.warn(
                        "file_part_requires_attachment",
                        &pp,
                        "file content is not part of the export: attach the file before sending (imported disabled)",
                    );
                    if let Some(f) = str_of(p, "fileName").filter(|f| !f.is_empty()) {
                        b.report.external_ref(f, &pp);
                    }
                    parts.push(MultipartPart {
                        name,
                        enabled: false,
                        content: MultipartContent::Text { value: String::new() },
                        content_type: None,
                    });
                    continue;
                }
                let raw = template(b, &p.get("value").map(scalar_text).unwrap_or_default(), &pp);
                let (value, _) = maybe_redact(b, &name, &raw, &pp, "form field");
                parts.push(MultipartPart {
                    name,
                    enabled: p.get("disabled").and_then(Value::as_bool) != Some(true),
                    content: MultipartContent::Text { value },
                    content_type: None,
                });
            }
            Body::Multipart { parts }
        }
        "application/graphql" => {
            let parsed: Map<String, Value> =
                serde_json::from_str::<Value>(&text).ok().and_then(|v| v.as_object().cloned()).unwrap_or_default();
            let query = parsed.get("query").and_then(Value::as_str).unwrap_or(&text).to_string();
            let variables = match parsed.get("variables") {
                Some(Value::Null) | None => String::new(),
                Some(Value::String(s)) => s.clone(),
                Some(o) => o.to_string(),
            };
            let operation_name = parsed.get("operationName").and_then(Value::as_str).map(str::to_string);
            Body::GraphQl { query, variables, operation_name }
        }
        _ if str_of(v, "fileName").is_some_and(|f| !f.is_empty()) => {
            let f = str_of(v, "fileName").unwrap_or("");
            b.report.external_ref(f, at);
            b.report.warn(
                "binary_body_requires_attachment",
                at,
                "binary file body is not part of the export: attach the file before sending",
            );
            Body::None
        }
        "" if text.is_empty() => Body::None,
        _ => body_from_text(mime.as_deref(), text).0,
    }
}

fn auth(b: &mut Builder, a: &Value, at: &str, owner: &str) -> AuthConfig {
    let Some(m) = a.as_object() else { return AuthConfig::Inherit };
    if m.is_empty() {
        return AuthConfig::Inherit;
    }
    if a.get("disabled").and_then(Value::as_bool) == Some(true) {
        return AuthConfig::None;
    }
    let ty = str_of(a, "type").unwrap_or("none");
    let v = sanitize_var(if owner.is_empty() { "insomnia" } else { owner });
    let get = |b: &mut Builder, k: &str| template(b, &a.get(k).map(scalar_text).unwrap_or_default(), &ptr(at, k));
    match ty {
        "none" => AuthConfig::None,
        "inherit" => AuthConfig::Inherit,
        "basic" => {
            let username = get(b, "username");
            let pw = get(b, "password");
            AuthConfig::Basic {
                username,
                password: credential(b, &pw, &format!("{v}_password"), &ptr(at, "password"), "Basic auth password"),
            }
        }
        "bearer" => {
            let t = get(b, "token");
            let prefix = str_of(a, "prefix").filter(|p| !p.is_empty()).unwrap_or("Bearer").to_string();
            AuthConfig::Bearer { token: credential(b, &t, &format!("{v}_token"), &ptr(at, "token"), "bearer token"), prefix }
        }
        "apikey" => {
            let name = get(b, "key");
            let val = get(b, "value");
            let location = match str_of(a, "addTo") {
                Some("queryParams") => KeyLocation::Query,
                Some("cookie") => KeyLocation::Cookie,
                _ => KeyLocation::Header,
            };
            AuthConfig::ApiKey { name, value: credential(b, &val, &format!("{v}_api_key"), &ptr(at, "value"), "API key"), location }
        }
        "oauth2" => {
            let grant = match str_of(a, "grantType") {
                Some("client_credentials") => Some(OAuthGrant::ClientCredentials),
                Some("authorization_code") => {
                    if a.get("usePkce").and_then(Value::as_bool) != Some(true) {
                        b.report.warn(
                            "oauth2_pkce_upgrade",
                            at,
                            "authorization-code grant is imported as authorization code with PKCE (S256)",
                        );
                    }
                    Some(OAuthGrant::AuthorizationCodePkce)
                }
                Some("refresh_token") => Some(OAuthGrant::RefreshToken),
                _ => None,
            };
            for k in ["accessToken", "refreshToken", "identityToken"] {
                if a.get(k).and_then(Value::as_str).is_some_and(|s| !s.trim().is_empty()) {
                    b.report.redacted(&ptr(at, k), format!("cached OAuth 2 {k}"), "(dropped)");
                }
            }
            let Some(grant) = grant else {
                b.report.unsupported(
                    "oauth2_grant_unsupported",
                    at,
                    format!(
                        "OAuth 2 grant '{}' is not supported; imported as a bearer-token placeholder",
                        str_of(a, "grantType").unwrap_or("")
                    ),
                );
                return AuthConfig::Bearer { token: credential(b, "", &format!("{v}_token"), at, "bearer token"), prefix: "Bearer".into() };
            };
            let secret_raw = get(b, "clientSecret");
            let client_secret = if grant == OAuthGrant::ClientCredentials || !secret_raw.is_empty() {
                credential(b, &secret_raw, &format!("{v}_client_secret"), &ptr(at, "clientSecret"), "OAuth 2 client secret")
            } else {
                SensitiveValue::default()
            };
            AuthConfig::OAuth2 {
                config: OAuth2Config {
                    grant,
                    token_url: get(b, "accessTokenUrl"),
                    authorization_url: get(b, "authorizationUrl"),
                    client_id: get(b, "clientId"),
                    client_secret,
                    scope: get(b, "scope"),
                    audience: get(b, "audience"),
                    client_auth: if a.get("credentialsInBody").and_then(Value::as_bool) == Some(true) {
                        OAuthClientAuth::RequestBody
                    } else {
                        OAuthClientAuth::BasicHeader
                    },
                    token_cache_id: None,
                    refresh_skew_secs: 30,
                },
            }
        }
        other => {
            b.report.unsupported(
                "auth_unsupported",
                at,
                format!("Insomnia auth type '{other}' is not supported; the request is imported without credentials (auth: none)"),
            );
            AuthConfig::None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ImportOptions;

    #[test]
    fn templates() {
        let o = ImportOptions::default();
        let mut b = Builder::new(&o, "x");
        assert_eq!(template(&mut b, "{{ _.baseUrl }}/a/{{ id }}", "/"), "{{baseUrl}}/a/{{id}}");
        assert_eq!(template(&mut b, "{% uuid 'v4' %}-{% now 'millis' %}", "/"), "{{$uuid}}-{{$timestampMs}}");
        assert_eq!(template(&mut b, "{% response 'body', 'req_1', '$.id' %}", "/t"), "{% response 'body', 'req_1', '$.id' %}");
        assert!(b.report.has_code("template_tag"));
    }
}
