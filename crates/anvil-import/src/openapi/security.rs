//! Security requirements → auth *placeholders*.
//!
//! Credentials are never invented: every secret is a `{{variable}}`
//! reference named after the security scheme and listed in
//! [`crate::ImportReport::required_variables`]. The variables are not
//! defined by the import, so a request fails validation (unresolved
//! variable) until the user supplies them.

use super::Ctx;
use crate::builder::Builder;
use crate::util::{ptr, sanitize_var, str_of};
use anvil_domain::auth::{AuthConfig, KeyLocation, OAuth2Config, OAuthClientAuth, OAuthGrant};
use anvil_domain::secret::SensitiveValue;
use serde_json::Value;

fn var(b: &mut Builder, name: &str, secret: bool, reason: &str, at: &str) -> String {
    b.report.require_var(name, secret, reason, at);
    format!("{{{{{name}}}}}")
}

/// Locate a security scheme by requirement key. OpenAPI 3.2 also allows a
/// URI reference; internal `#/…` references are resolved, anything else is
/// reported as external.
fn find_scheme<'a>(ctx: &Ctx<'a>, b: &mut Builder, key: &str, at: &str) -> Option<(&'a Value, String)> {
    let base = if ctx.dialect == crate::Dialect::Swagger20 { "/securityDefinitions" } else { "/components/securitySchemes" };
    let p = ptr(base, key);
    if let Some(s) = ctx.root.pointer(&p) {
        return ctx.refs.resolve(s, &p, &mut b.report);
    }
    if ctx.dialect == crate::Dialect::OpenApi32 && (key.contains('#') || key.contains(':')) {
        if let Some(frag) = key.strip_prefix('#')
            && frag.starts_with('/')
        {
            let decoded = percent_encoding::percent_decode_str(frag).decode_utf8_lossy().into_owned();
            if let Some(s) = ctx.root.pointer(&decoded) {
                return ctx.refs.resolve(s, &decoded, &mut b.report);
            }
            b.report.warn("undefined_security_scheme", at, format!("security requirement '{key}' does not point to a scheme"));
            return None;
        }
        b.report.external_ref(key, at);
        return None;
    }
    b.report.warn("undefined_security_scheme", at, format!("security requirement names '{key}', which is not defined"));
    None
}

/// Map one scheme to an auth config, or `None` (reported) when unsupported.
fn scheme_auth(ctx: &Ctx, b: &mut Builder, key: &str, scheme: &Value, sptr: &str, scopes: &[String]) -> Option<AuthConfig> {
    let v = sanitize_var(key);
    if scheme.get("deprecated").and_then(Value::as_bool) == Some(true) {
        b.report.warn("deprecated_security_scheme", sptr, format!("security scheme '{key}' is marked deprecated"));
    }
    let ty = str_of(scheme, "type").unwrap_or("");
    match ty {
        "apiKey" => {
            let name = str_of(scheme, "name").unwrap_or(key).to_string();
            let location = match str_of(scheme, "in") {
                Some("query") => KeyLocation::Query,
                Some("cookie") => KeyLocation::Cookie,
                _ => KeyLocation::Header,
            };
            let value = var(b, &v, true, &format!("API key for security scheme '{key}'"), sptr);
            Some(AuthConfig::ApiKey { name, value: SensitiveValue::template(value), location })
        }
        "basic" => Some(basic(b, &v, key, sptr)),
        "http" => match str_of(scheme, "scheme").map(str::to_ascii_lowercase).as_deref() {
            Some("basic") => Some(basic(b, &v, key, sptr)),
            Some("bearer") => Some(bearer(b, &v, key, sptr)),
            Some(other) => {
                b.report.unsupported(
                    "unsupported_http_auth",
                    sptr,
                    format!("HTTP authentication scheme '{other}' (security scheme '{key}') is not supported; requests using it carry no credentials"),
                );
                None
            }
            None => {
                b.report.warn("invalid_security_scheme", sptr, format!("http security scheme '{key}' has no `scheme`"));
                None
            }
        },
        "oauth2" => Some(oauth2(ctx, b, &v, key, scheme, sptr, scopes)),
        "openIdConnect" => {
            if let Some(u) = str_of(scheme, "openIdConnectUrl") {
                b.report.external_ref(u, &ptr(sptr, "openIdConnectUrl"));
            }
            b.report.unsupported(
                "openid_connect_discovery",
                sptr,
                format!("OpenID Connect discovery for '{key}' is not fetched during import; imported as a bearer-token placeholder"),
            );
            Some(bearer(b, &v, key, sptr))
        }
        "mutualTLS" => {
            b.report.unsupported(
                "mutual_tls_scheme",
                sptr,
                format!("security scheme '{key}' requires a client certificate: select a TLS profile with a client identity (not an auth setting)"),
            );
            None
        }
        other => {
            b.report.unsupported("unknown_security_scheme", sptr, format!("security scheme type '{other}' is not supported"));
            None
        }
    }
}

fn basic(b: &mut Builder, v: &str, key: &str, at: &str) -> AuthConfig {
    let username = var(b, &format!("{v}_username"), false, &format!("Basic auth user for security scheme '{key}'"), at);
    let password = var(b, &format!("{v}_password"), true, &format!("Basic auth password for security scheme '{key}'"), at);
    AuthConfig::Basic { username, password: SensitiveValue::template(password) }
}

fn bearer(b: &mut Builder, v: &str, key: &str, at: &str) -> AuthConfig {
    let token = var(b, v, true, &format!("bearer token for security scheme '{key}'"), at);
    AuthConfig::Bearer { token: SensitiveValue::template(token), prefix: "Bearer".into() }
}

fn oauth2(ctx: &Ctx, b: &mut Builder, v: &str, key: &str, scheme: &Value, sptr: &str, scopes: &[String]) -> AuthConfig {
    if let Some(u) = str_of(scheme, "oauth2MetadataUrl") {
        b.report.external_ref(u, &ptr(sptr, "oauth2MetadataUrl"));
    }
    // Normalize Swagger 2.0 `flow` and OpenAPI 3 `flows`.
    let mut flows: Vec<(&str, &Value, String)> = vec![];
    if ctx.dialect == crate::Dialect::Swagger20 {
        let f = match str_of(scheme, "flow") {
            Some("application") => "clientCredentials",
            Some("accessCode") => "authorizationCode",
            Some("implicit") => "implicit",
            Some("password") => "password",
            _ => "",
        };
        flows.push((f, scheme, sptr.to_string()));
    } else if let Some(m) = scheme.get("flows").and_then(Value::as_object) {
        for (name, f) in m {
            let n: &str = match name.as_str() {
                "clientCredentials" => "clientCredentials",
                "authorizationCode" => "authorizationCode",
                "implicit" => "implicit",
                "password" => "password",
                "deviceAuthorization" => "deviceAuthorization",
                _ => "",
            };
            flows.push((n, f, ptr(&ptr(sptr, "flows"), name)));
        }
    }
    let pick = flows.iter().find(|f| f.0 == "clientCredentials").or_else(|| flows.iter().find(|f| f.0 == "authorizationCode"));
    if flows.len() > 1 {
        b.report.warn(
            "oauth2_flow_choice",
            sptr,
            format!(
                "security scheme '{key}' offers flows [{}]; {}",
                flows.iter().map(|f| f.0).collect::<Vec<_>>().join(", "),
                pick.map(|p| format!("'{}' was imported", p.0)).unwrap_or_else(|| "none is supported".into())
            ),
        );
    }
    let Some((flow, f, fptr)) = pick else {
        let names = flows.iter().map(|f| f.0).filter(|n| !n.is_empty()).collect::<Vec<_>>().join(", ");
        b.report.unsupported(
            "oauth2_flow_unsupported",
            sptr,
            format!("OAuth 2 flow(s) [{names}] of '{key}' are not supported; imported as a bearer-token placeholder"),
        );
        return bearer(b, v, key, sptr);
    };
    let grant = if *flow == "clientCredentials" { OAuthGrant::ClientCredentials } else { OAuthGrant::AuthorizationCodePkce };
    let token_url = str_of(f, "tokenUrl").unwrap_or("").to_string();
    if token_url.is_empty() {
        b.report.warn("oauth2_missing_token_url", fptr, format!("OAuth 2 flow of '{key}' has no tokenUrl"));
    }
    let client_id = var(b, &format!("{v}_client_id"), false, &format!("OAuth 2 client id for '{key}'"), sptr);
    let client_secret = if grant == OAuthGrant::ClientCredentials {
        SensitiveValue::template(var(b, &format!("{v}_client_secret"), true, &format!("OAuth 2 client secret for '{key}'"), sptr))
    } else {
        SensitiveValue::default()
    };
    AuthConfig::OAuth2 {
        config: OAuth2Config {
            grant,
            token_url,
            authorization_url: str_of(f, "authorizationUrl").unwrap_or("").to_string(),
            client_id,
            client_secret,
            scope: scopes.join(" "),
            audience: String::new(),
            client_auth: OAuthClientAuth::BasicHeader,
            token_cache_id: None,
            refresh_skew_secs: 30,
        },
    }
}

/// Map a security requirement list (alternatives of conjunctions).
/// `[]` and `[{}]` mean "no authentication". The first alternative whose
/// schemes are all supported is used; others are reported.
pub(crate) fn requirement_auth(ctx: &Ctx, b: &mut Builder, req: &Value, at: &str) -> AuthConfig {
    let Some(alts) = req.as_array() else {
        b.report.warn("invalid_security", at, "`security` must be an array of requirement objects");
        return AuthConfig::None;
    };
    if alts.is_empty() {
        return AuthConfig::None;
    }
    let mut mapped: Vec<(usize, Option<AuthConfig>, bool)> = vec![];
    for (i, alt) in alts.iter().enumerate() {
        let aptr = format!("{at}/{i}");
        let Some(m) = alt.as_object() else { continue };
        if m.is_empty() {
            mapped.push((i, Some(AuthConfig::None), true));
            if i == 0 {
                break;
            }
            continue;
        }
        let mut profiles = vec![];
        let mut complete = true;
        for (key, scopes) in m {
            let scopes: Vec<String> =
                scopes.as_array().map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect()).unwrap_or_default();
            match find_scheme(ctx, b, key, &ptr(&aptr, key)) {
                Some((scheme, sptr)) => match scheme_auth(ctx, b, key, scheme, &sptr, &scopes) {
                    Some(a) => profiles.push(a),
                    None => complete = false,
                },
                None => complete = false,
            }
        }
        let auth = match profiles.len() {
            0 => None,
            1 => profiles.pop(),
            _ => Some(AuthConfig::Multi { profiles }),
        };
        mapped.push((i, auth, complete));
        if complete {
            break;
        }
    }
    let chosen = mapped.iter().find(|m| m.2).or_else(|| mapped.iter().find(|m| m.1.is_some())).cloned();
    if alts.len() > 1
        && let Some((i, _, _)) = &chosen
    {
        b.report.warn(
            "security_alternatives",
            at,
            format!("{} alternative security requirements; alternative #{i} was applied, the others are not represented", alts.len()),
        );
    }
    match chosen {
        Some((_, Some(a), _)) => a,
        _ => AuthConfig::None,
    }
}
