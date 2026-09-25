//! Postman collection v2.0/v2.1 and environment/globals exports.
//!
//! Scripts (`event` pre-request/test) are retained verbatim in the report as
//! disabled/untrusted and never executed. Auth helpers become Anvil auth
//! configs whose secrets are `{{placeholders}}` (literal credentials are
//! redacted unless `include_credentials`). File references (form-data
//! files, binary bodies) are reported, never read.

use crate::builder::Builder;
use crate::common::{
    body_from_text, check_dynamic_vars, credential, dedupe_content_type, env_var, header_content_type, maybe_redact, split_query,
};
use crate::util::{is_credential_name, ptr, sanitize_var, scalar_text, str_of};
use crate::{Dialect, ImportError};
use anvil_domain::Id;
use anvil_domain::auth::{AuthConfig, KeyLocation, OAuth2Config, OAuthClientAuth, OAuthGrant};
use anvil_domain::request::{Body, KeyValue, MultipartContent, MultipartPart, RequestSpec};
use anvil_domain::secret::SensitiveValue;
use anvil_domain::settings::SettingsOverrides;
use anvil_domain::workspace::Variable;
use serde_json::Value;

const MAX_FOLDER_DEPTH: usize = 64;

fn description(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Object(o)) => o.get("content").and_then(Value::as_str).unwrap_or("").to_string(),
        _ => String::new(),
    }
}

pub(crate) fn import_collection(root: &Value, dialect: Dialect, b: &mut Builder) -> Result<(), ImportError> {
    let info = root.get("info").cloned().unwrap_or(Value::Null);
    let name = str_of(&info, "name").unwrap_or("Postman collection").to_string();
    b.title = Some(name.clone());
    b.workspace.name = name.clone();
    b.workspace.description = description(info.get("description"));
    if dialect == Dialect::PostmanV20 {
        b.report.warn(
            "postman_v20",
            "/info/schema",
            "Postman collection v2.0: imported with the v2.1 mapping (auth parameters accept both shapes)",
        );
    }
    b.workspace.variables = variables(b, root.get("variable"), "/variable");
    b.workspace.auth = match root.get("auth") {
        Some(a) => auth(b, a, "/auth", &name),
        None => AuthConfig::None,
    };
    events(b, root.get("event"), "/event", &name);
    if let Some(items) = root.get("item").and_then(Value::as_array) {
        walk_items(b, items, "/item", None, 0);
    } else {
        return Err(ImportError::Invalid { dialect, pointer: "/item".into(), message: "collection has no `item` array".into() });
    }
    Ok(())
}

fn walk_items(b: &mut Builder, items: &[Value], base: &str, parent: Option<Id>, depth: usize) {
    for (i, it) in items.iter().enumerate() {
        let at = format!("{base}/{i}");
        let name = str_of(it, "name").unwrap_or("").to_string();
        if let Some(children) = it.get("item").and_then(Value::as_array) {
            if depth >= MAX_FOLDER_DEPTH {
                b.report.warn("folder_depth_limit", &at, format!("folders nested deeper than {MAX_FOLDER_DEPTH} levels were not imported"));
                continue;
            }
            let key = format!("pm:{at}");
            let fid = b.folder(parent, &key, if name.is_empty() { "Folder" } else { &name });
            let vars = variables(b, it.get("variable"), &ptr(&at, "variable"));
            let fauth = it.get("auth").map(|a| auth(b, a, &ptr(&at, "auth"), &name));
            if let Some(f) = b.folder_mut(fid) {
                f.description = description(it.get("description"));
                f.variables = vars;
                if let Some(a) = fauth {
                    f.auth = a;
                }
            }
            events(b, it.get("event"), &ptr(&at, "event"), &name);
            walk_items(b, children, &ptr(&at, "item"), Some(fid), depth + 1);
        } else if it.get("request").is_some() {
            if !b.admit(&at) {
                continue;
            }
            request(b, it, &at, parent, &name);
        } else {
            b.report.warn("empty_item", &at, "item has neither `request` nor `item`; skipped");
        }
    }
}

fn request(b: &mut Builder, it: &Value, at: &str, folder: Option<Id>, name: &str) {
    let rptr = ptr(at, "request");
    let req = &it["request"];
    let (method, url_v, header_v, body_v, auth_v, desc) = match req {
        Value::String(u) => ("GET".to_string(), Value::String(u.clone()), None, None, None, String::new()),
        _ => (
            str_of(req, "method").unwrap_or("GET").to_ascii_uppercase(),
            req.get("url").cloned().unwrap_or(Value::String(String::new())),
            req.get("header"),
            req.get("body"),
            req.get("auth"),
            description(req.get("description")),
        ),
    };
    let (url, params) = url(b, &url_v, &ptr(&rptr, "url"));
    let mut spec = RequestSpec::http(&method, &url);
    spec.params = params;
    spec.headers = headers(b, header_v, &ptr(&rptr, "header"));
    let ct = header_content_type(&spec.headers);
    spec.body = match body_v {
        Some(bv) => body(b, bv, &ptr(&rptr, "body"), ct.as_deref()),
        None => Body::None,
    };
    dedupe_content_type(&mut spec.headers, &spec.body);
    spec.auth = match auth_v {
        Some(a) => auth(b, a, &ptr(&rptr, "auth"), name),
        None => AuthConfig::Inherit,
    };
    for k in ["proxy", "certificate"] {
        if req.get(k).is_some() {
            b.report.unsupported(
                "request_setting",
                &ptr(&rptr, k),
                format!("per-request `{k}` settings are not imported; use a proxy/TLS profile"),
            );
        }
    }
    spec.settings = behavior(b, it.get("protocolProfileBehavior"), &ptr(at, "protocolProfileBehavior"));
    events(b, it.get("event"), &ptr(at, "event"), name);
    if let Some(r) = it.get("response").and_then(Value::as_array).filter(|r| !r.is_empty()) {
        b.report.unsupported("saved_responses", &ptr(at, "response"), format!("{} saved example response(s) are not imported", r.len()));
    }
    let key = str_of(it, "id").map(|id| format!("postman:{id}")).unwrap_or_else(|| format!("postman:{at}"));
    let r = b.add_request(folder, name, &key, spec, at);
    r.description = desc;
}

/// `protocolProfileBehavior` → settings. TLS-verification bypass is never
/// applied (DATA-008).
fn behavior(b: &mut Builder, v: Option<&Value>, at: &str) -> SettingsOverrides {
    let mut s = SettingsOverrides::default();
    let Some(m) = v.and_then(Value::as_object) else { return s };
    for (k, val) in m {
        let p = ptr(at, k);
        match (k.as_str(), val) {
            ("strictSSL", Value::Bool(false)) => b.report.inactive(
                &p,
                "tls.verify",
                "false",
                "TLS certificate verification bypass is never imported as an active setting; use an explicit TLS profile if you really need it",
            ),
            ("strictSSL", _) => {}
            ("followRedirects", Value::Bool(f)) => {
                let mut r = s.redirects.unwrap_or_default();
                r.follow = *f;
                s.redirects = Some(r);
            }
            ("maxRedirects", Value::Number(n)) => {
                let mut r = s.redirects.unwrap_or_default();
                r.max = n.as_u64().unwrap_or(10).min(255) as u8;
                s.redirects = Some(r);
            }
            ("followAuthorizationHeader", Value::Bool(true)) => b.report.inactive(
                &p,
                "redirects.forward_credentials_cross_origin",
                "true",
                "forwarding credentials across redirects is never imported as an active setting",
            ),
            ("disableCookies", Value::Bool(d)) => s.cookies = Some(!*d),
            ("disableBodyPruning" | "followOriginalHttpMethod" | "followAuthorizationHeader", _) => {}
            (other, _) => b.report.unsupported("request_setting", &p, format!("Postman setting `{other}` is not imported")),
        }
    }
    s
}

fn events(b: &mut Builder, v: Option<&Value>, at: &str, owner: &str) {
    let Some(list) = v.and_then(Value::as_array) else { return };
    for (i, e) in list.iter().enumerate() {
        let p = format!("{at}/{i}");
        let listen = str_of(e, "listen").unwrap_or("event");
        let script = e.get("script").cloned().unwrap_or(Value::Null);
        let src = match script.get("exec") {
            Some(Value::Array(lines)) => lines.iter().map(scalar_text).collect::<Vec<_>>().join("\n"),
            Some(Value::String(s)) => s.clone(),
            _ => String::new(),
        };
        if let Some(external) = str_of(&script, "src") {
            b.report.external_ref(external, &ptr(&p, "script"));
        }
        if src.trim().is_empty() {
            continue;
        }
        let lang = str_of(&script, "type").unwrap_or("text/javascript");
        b.report.script(&p, owner, listen, lang, src);
    }
}

/// Collection/folder variables. Credential-like literals follow the
/// credential policy: without `include_credentials` they are dropped and
/// listed as required variables (so `{{name}}` references fail validation
/// until the user supplies them).
fn variables(b: &mut Builder, v: Option<&Value>, at: &str) -> Vec<Variable> {
    let Some(list) = v.and_then(Value::as_array) else { return vec![] };
    let mut out = vec![];
    for (i, var) in list.iter().enumerate() {
        let p = format!("{at}/{i}");
        let Some(key) = str_of(var, "key").or_else(|| str_of(var, "id")) else { continue };
        let value = var.get("value").map(scalar_text).unwrap_or_default();
        let secret = str_of(var, "type") == Some("secret") || is_credential_name(key);
        if let Some(v) = env_var(b, key, &value, secret, var.get("disabled").and_then(Value::as_bool) != Some(true), &p) {
            out.push(Variable { description: description(var.get("description")), ..v });
        }
    }
    out
}

fn headers(b: &mut Builder, v: Option<&Value>, at: &str) -> Vec<KeyValue> {
    let mut out = vec![];
    match v {
        Some(Value::Array(list)) => {
            for (i, h) in list.iter().enumerate() {
                let p = format!("{at}/{i}");
                let name = str_of(h, "key").unwrap_or("").to_string();
                if name.is_empty() {
                    continue;
                }
                let raw = h.get("value").map(scalar_text).unwrap_or_default();
                check_dynamic_vars(b, &raw, &p);
                let (value, sensitive) = maybe_redact(b, &name, &raw, &p, "header");
                out.push(KeyValue {
                    name,
                    value,
                    enabled: h.get("disabled").and_then(Value::as_bool) != Some(true),
                    description: description(h.get("description")),
                    sensitive,
                });
            }
        }
        Some(Value::String(s)) => {
            for (i, line) in s.lines().enumerate() {
                let Some((k, val)) = line.split_once(':') else { continue };
                let p = format!("{at}#line{i}");
                let (value, sensitive) = maybe_redact(b, k.trim(), val.trim(), &p, "header");
                out.push(KeyValue { name: k.trim().into(), value, enabled: true, description: String::new(), sensitive });
            }
        }
        _ => {}
    }
    out
}

/// URL: `raw` wins; otherwise rebuilt from parts. Query parameters come from
/// the `query` array (keeping disabled entries) or the raw query string.
/// Path variables (`:id`) are substituted from `url.variable` or become
/// `{{id}}` placeholders.
fn url(b: &mut Builder, v: &Value, at: &str) -> (String, Vec<KeyValue>) {
    let (raw, query_list, path_vars) = match v {
        Value::String(s) => (s.clone(), None, None),
        Value::Object(_) => {
            let raw = str_of(v, "raw").map(str::to_string).unwrap_or_else(|| rebuild_url(v));
            (raw, v.get("query").and_then(Value::as_array).cloned(), v.get("variable").and_then(Value::as_array).cloned())
        }
        _ => (String::new(), None, None),
    };
    check_dynamic_vars(b, &raw, &ptr(at, "raw"));
    let (base, raw_pairs) = split_query(&raw);
    let base = if raw_pairs.is_empty() && query_list.is_some() { base.split('?').next().unwrap_or("").to_string() } else { base };
    let mut params = vec![];
    match query_list {
        Some(list) => {
            for (i, q) in list.iter().enumerate() {
                let p = format!("{}/{i}", ptr(at, "query"));
                let Some(k) = str_of(q, "key") else { continue };
                let raw_v = q.get("value").map(scalar_text).unwrap_or_default();
                let (value, sensitive) = maybe_redact(b, k, &raw_v, &p, "query");
                params.push(KeyValue {
                    name: k.to_string(),
                    value,
                    enabled: q.get("disabled").and_then(Value::as_bool) != Some(true),
                    description: description(q.get("description")),
                    sensitive,
                });
            }
        }
        None => {
            for (i, (k, v)) in raw_pairs.into_iter().enumerate() {
                let p = format!("{}#query{i}", ptr(at, "raw"));
                let (value, sensitive) = maybe_redact(b, &k, &v, &p, "query");
                params.push(KeyValue { name: k, value, enabled: true, description: String::new(), sensitive });
            }
        }
    }
    let url = substitute_path_vars(b, &base, path_vars.as_deref().unwrap_or(&[]), &ptr(at, "variable"));
    (url, params)
}

fn rebuild_url(v: &Value) -> String {
    let join = |x: Option<&Value>, sep: &str| -> String {
        match x {
            Some(Value::Array(a)) => a
                .iter()
                .map(|s| s.as_str().map(str::to_string).unwrap_or_else(|| str_of(s, "value").unwrap_or("").to_string()))
                .collect::<Vec<_>>()
                .join(sep),
            Some(Value::String(s)) => s.clone(),
            _ => String::new(),
        }
    };
    let mut out = String::new();
    if let Some(p) = str_of(v, "protocol") {
        out.push_str(&format!("{p}://"));
    }
    out.push_str(&join(v.get("host"), "."));
    if let Some(port) = v.get("port").map(scalar_text).filter(|s| !s.is_empty()) {
        out.push_str(&format!(":{port}"));
    }
    let path = join(v.get("path"), "/");
    if !path.is_empty() {
        out.push('/');
        out.push_str(path.trim_start_matches('/'));
    }
    out
}

fn substitute_path_vars(b: &mut Builder, url: &str, vars: &[Value], at: &str) -> String {
    let path_start = match url.find("://") {
        Some(i) => url[i + 3..].find('/').map(|j| i + 3 + j),
        None => url.find('/'),
    };
    let Some(start) = path_start else { return url.to_string() };
    let (head, path) = url.split_at(start);
    let segs: Vec<String> = path
        .split('/')
        .map(|seg| {
            let Some(name) = seg.strip_prefix(':').filter(|n| !n.is_empty()) else { return seg.to_string() };
            let val =
                vars.iter().find(|v| str_of(v, "key") == Some(name)).and_then(|v| v.get("value")).map(scalar_text).unwrap_or_default();
            if val.is_empty() {
                let var = sanitize_var(name);
                b.report.require_var(&var, false, "Postman path variable without a value", at);
                format!("{{{{{var}}}}}")
            } else {
                val
            }
        })
        .collect();
    format!("{head}{}", segs.join("/"))
}

fn body(b: &mut Builder, v: &Value, at: &str, header_ct: Option<&str>) -> Body {
    if v.get("disabled").and_then(Value::as_bool) == Some(true) {
        b.report.unsupported("disabled_body", at, "the body was disabled in Postman; it is not imported");
        return Body::None;
    }
    match str_of(v, "mode").unwrap_or("") {
        "raw" => {
            let text = v.get("raw").map(scalar_text).unwrap_or_default();
            check_dynamic_vars(b, &text, &ptr(at, "raw"));
            let lang = v.pointer("/options/raw/language").and_then(Value::as_str).unwrap_or("text");
            let mime = header_ct.map(str::to_string).or_else(|| {
                Some(
                    match lang {
                        "json" => "application/json",
                        "xml" => "application/xml",
                        "html" => "text/html",
                        "javascript" => "application/javascript",
                        _ => "text/plain",
                    }
                    .to_string(),
                )
            });
            let (body, _) = body_from_text(mime.as_deref(), text);
            body
        }
        "urlencoded" => {
            let mut fields = vec![];
            for (i, f) in v.get("urlencoded").and_then(Value::as_array).into_iter().flatten().enumerate() {
                let p = format!("{}/{i}", ptr(at, "urlencoded"));
                let k = str_of(f, "key").unwrap_or("").to_string();
                let raw = f.get("value").map(scalar_text).unwrap_or_default();
                let (value, sensitive) = maybe_redact(b, &k, &raw, &p, "form field");
                fields.push(KeyValue {
                    name: k,
                    value,
                    enabled: f.get("disabled").and_then(Value::as_bool) != Some(true),
                    description: description(f.get("description")),
                    sensitive,
                });
            }
            Body::FormUrlEncoded { fields }
        }
        "formdata" => {
            let mut parts = vec![];
            for (i, f) in v.get("formdata").and_then(Value::as_array).into_iter().flatten().enumerate() {
                let p = format!("{}/{i}", ptr(at, "formdata"));
                let k = str_of(f, "key").unwrap_or("").to_string();
                let enabled = f.get("disabled").and_then(Value::as_bool) != Some(true);
                let content_type = str_of(f, "contentType").map(str::to_string);
                if str_of(f, "type") == Some("file") {
                    file_refs(b, f.get("src"), &p);
                    parts.push(MultipartPart {
                        name: k,
                        enabled: false,
                        content: MultipartContent::Text { value: String::new() },
                        content_type,
                    });
                    continue;
                }
                let raw = f.get("value").map(scalar_text).unwrap_or_default();
                let (value, _) = maybe_redact(b, &k, &raw, &p, "form field");
                parts.push(MultipartPart { name: k, enabled, content: MultipartContent::Text { value }, content_type });
            }
            Body::Multipart { parts }
        }
        "file" => {
            file_refs(b, v.pointer("/file/src"), &ptr(at, "file"));
            Body::None
        }
        "graphql" => {
            let g = v.get("graphql").cloned().unwrap_or(Value::Null);
            let query = str_of(&g, "query").unwrap_or("").to_string();
            let variables = match g.get("variables") {
                Some(Value::String(s)) => s.clone(),
                Some(Value::Null) | None => String::new(),
                Some(other) => other.to_string(),
            };
            Body::GraphQl { query, variables, operation_name: None }
        }
        "" => Body::None,
        other => {
            b.report.unsupported("body_mode", at, format!("Postman body mode '{other}' is not supported"));
            Body::None
        }
    }
}

fn file_refs(b: &mut Builder, src: Option<&Value>, at: &str) {
    let paths: Vec<String> = match src {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).map(str::to_string).collect(),
        _ => vec![],
    };
    b.report.warn(
        "file_part_requires_attachment",
        at,
        "file content is not part of the collection: attach the file before sending (imported disabled)",
    );
    for p in paths {
        b.report.external_ref(&p, at);
    }
}

/// Read an auth parameter in either the v2.1 array form
/// (`[{key, value}]`) or the v2.0 object form (`{key: value}`).
fn param(a: &Value, ty: &str, key: &str) -> Option<String> {
    match a.get(ty)? {
        Value::Array(list) => list.iter().find(|p| str_of(p, "key") == Some(key)).and_then(|p| p.get("value")).map(scalar_text),
        Value::Object(m) => m.get(key).map(scalar_text),
        _ => None,
    }
}

fn auth(b: &mut Builder, a: &Value, at: &str, owner: &str) -> AuthConfig {
    let ty = str_of(a, "type").unwrap_or("noauth");
    let v = sanitize_var(owner);
    let p = |k: &str| param(a, ty, k).unwrap_or_default();
    let fp = |k: &str| ptr(&ptr(at, ty), k);
    match ty {
        "noauth" => AuthConfig::None,
        "inherit" => AuthConfig::Inherit,
        "basic" => {
            let username = p("username");
            let password = credential(b, &p("password"), &format!("{v}_password"), &fp("password"), "Basic auth password");
            AuthConfig::Basic { username, password }
        }
        "bearer" => AuthConfig::Bearer {
            token: credential(b, &p("token"), &format!("{v}_token"), &fp("token"), "bearer token"),
            prefix: "Bearer".into(),
        },
        "apikey" => {
            let name = param(a, ty, "key").unwrap_or_else(|| "X-API-Key".into());
            let location = match p("in").as_str() {
                "query" => KeyLocation::Query,
                _ => KeyLocation::Header,
            };
            AuthConfig::ApiKey { name, value: credential(b, &p("value"), &format!("{v}_api_key"), &fp("value"), "API key"), location }
        }
        "oauth2" => {
            let access = p("accessToken");
            if crate::util::has_literal_secret(&access) {
                b.report.redacted(&fp("accessToken"), "cached OAuth 2 access token", "(dropped)");
            }
            let grant = match p("grant_type").as_str() {
                "client_credentials" => Some(OAuthGrant::ClientCredentials),
                "authorization_code_with_pkce" => Some(OAuthGrant::AuthorizationCodePkce),
                "authorization_code" | "" => {
                    b.report.warn("oauth2_pkce_upgrade", at, "authorization-code grant is imported as authorization code with PKCE (S256)");
                    Some(OAuthGrant::AuthorizationCodePkce)
                }
                _ => None,
            };
            let Some(grant) = grant else {
                b.report.unsupported(
                    "oauth2_grant_unsupported",
                    at,
                    format!("OAuth 2 grant '{}' is not supported; imported as a bearer-token placeholder", p("grant_type")),
                );
                return AuthConfig::Bearer { token: credential(b, "", &format!("{v}_token"), at, "bearer token"), prefix: "Bearer".into() };
            };
            let client_secret = if grant == OAuthGrant::ClientCredentials || !p("clientSecret").is_empty() {
                credential(b, &p("clientSecret"), &format!("{v}_client_secret"), &fp("clientSecret"), "OAuth 2 client secret")
            } else {
                SensitiveValue::default()
            };
            AuthConfig::OAuth2 {
                config: OAuth2Config {
                    grant,
                    token_url: p("accessTokenUrl"),
                    authorization_url: p("authUrl"),
                    client_id: p("clientId"),
                    client_secret,
                    scope: p("scope"),
                    audience: p("audience"),
                    client_auth: if p("client_authentication") == "body" {
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
                format!("Postman auth type '{other}' is not supported; the request is imported without credentials (auth: none)"),
            );
            AuthConfig::None
        }
    }
}

pub(crate) fn import_environment(root: &Value, b: &mut Builder) -> Result<(), ImportError> {
    let name = str_of(root, "name").unwrap_or("Postman environment").to_string();
    let globals = str_of(root, "_postman_variable_scope") == Some("globals");
    b.title = Some(name.clone());
    b.workspace.name = name.clone();
    let mut vars = vec![];
    for (i, v) in root.get("values").and_then(Value::as_array).into_iter().flatten().enumerate() {
        let p = format!("/values/{i}");
        let Some(key) = str_of(v, "key") else { continue };
        let value = v.get("value").map(scalar_text).unwrap_or_default();
        let secret = str_of(v, "type") == Some("secret") || is_credential_name(key);
        let enabled = v.get("enabled").and_then(Value::as_bool) != Some(false);
        if let Some(var) = env_var(b, key, &value, secret, enabled, &p) {
            vars.push(var);
        }
    }
    if globals {
        b.workspace.variables = vars;
    } else {
        let id = b.add_environment("postman:env", &name, vars);
        b.workspace.active_environment_id = Some(id);
    }
    Ok(())
}
