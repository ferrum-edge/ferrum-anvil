//! Request preparation: interpolation, URL/target construction, header
//! validation, body serialization, content-type inference and lint. Runs
//! entirely locally; any failure here means nothing was sent.

use crate::context::AttachmentResolver;
use crate::lint::{self, LintResult};
use crate::vars::Resolver;
use anvil_domain::execution::{FailureKind, Phase, TransportFailure};
use anvil_domain::request::{Body, LintSendPolicy, MultipartContent, RequestSpec, SoapVersion};
use anvil_domain::settings::EffectiveSettings;
use bytes::Bytes;

#[derive(Debug, Clone)]
pub struct Target {
    pub scheme: String,
    /// Host for DNS/SNI (no brackets for IPv6).
    pub host: String,
    pub port: u16,
    /// Default Host/`:authority` value.
    pub authority: String,
    /// Raw path (starts with `/`).
    pub path: String,
    /// Raw query without `?` (may be empty).
    pub query: String,
}

impl Target {
    pub fn request_target(&self) -> String {
        if self.query.is_empty() { self.path.clone() } else { format!("{}?{}", self.path, self.query) }
    }

    pub fn url(&self) -> String {
        format!("{}://{}{}", self.scheme, self.authority, self.request_target())
    }

    pub fn origin(&self) -> (String, String, u16) {
        (self.scheme.clone(), self.host.to_ascii_lowercase(), self.port)
    }
}

/// The first explicit Host wins over the URL authority. Auth-written
/// headers replace all configured headers of the same name before this.
pub fn request_authority(headers: &[(String, String)], target: &Target) -> String {
    headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("host"))
        .map(|(_, value)| value.clone())
        .unwrap_or_else(|| target.authority.clone())
}

/// Resolve only the inputs that can change a forward proxy's authority.
/// The caller supplies its per-run-aware template resolver: `None` means
/// an input varies or cannot be resolved. Generated credentials used as
/// Host also remain unproven. No signing or token acquisition occurs here.
pub fn preflight_authority(
    ctx: &crate::ExecutionContext,
    target: &Target,
    resolve: impl Fn(&str, &str) -> Option<String>,
) -> Option<String> {
    use anvil_domain::auth::{AuthConfig, KeyLocation};

    fn auth_host(
        auth: &AuthConfig,
        ctx: &crate::ExecutionContext,
        resolve: &impl Fn(&str, &str) -> Option<String>,
        headers: &mut Vec<(String, String)>,
    ) -> Option<()> {
        match auth {
            AuthConfig::ApiKey { name, value, location: KeyLocation::Header } => {
                let name = resolve(name, "auth.name")?;
                if name.eq_ignore_ascii_case("host") {
                    let (raw, _) = crate::context::resolve_sensitive(value, ctx.secrets.as_ref()).ok()?;
                    let value = resolve(&raw, "auth.value")?;
                    headers.retain(|(name, _)| !name.eq_ignore_ascii_case("host"));
                    headers.push((name, value));
                }
            }
            AuthConfig::Jwt { header_name, .. } if header_name.eq_ignore_ascii_case("host") => {
                return None;
            }
            AuthConfig::JwtSvid { config } if config.header_name.trim().eq_ignore_ascii_case("host") => {
                return None;
            }
            AuthConfig::Multi { profiles } => {
                for profile in profiles {
                    auth_host(profile, ctx, resolve, headers)?;
                }
            }
            _ => {}
        }
        Some(())
    }

    let mut headers = Vec::new();
    let metadata = ctx.spec.grpc.as_ref().filter(|_| ctx.spec.protocol == anvil_domain::request::Protocol::Grpc);
    let inputs = ctx.spec.headers.iter().chain(metadata.into_iter().flat_map(|g| &g.metadata));
    for header in inputs.filter(|header| header.enabled) {
        let name = resolve(header.name.trim(), "headers.name")?;
        if name.eq_ignore_ascii_case("host") {
            headers.push((name, resolve(&header.value, "headers.value")?));
        }
    }
    let (_, auth) = ctx.effective_auth();
    auth_host(&auth, ctx, &resolve, &mut headers)?;
    Some(request_authority(&headers, target))
}

#[derive(Debug, Clone)]
pub struct PreparedHttp {
    pub method: String,
    pub target: Target,
    pub headers: Vec<(String, String)>,
    /// Lowercased names of the configured headers marked sensitive. They are
    /// credentials of the request's own origin, like `Authorization`.
    pub sensitive_headers: Vec<String>,
    pub body: Bytes,
    /// Whether the body holds a secret: resolving it substituted a secret
    /// variable, or it has a form field the user marked sensitive (whatever
    /// its value, literal or not). Decided structurally, before encoding: a
    /// form-urlencoded or re-serialized GraphQL body holds the secret in a
    /// form a byte scan does not find.
    pub body_uses_secret: bool,
    pub content_type: Option<String>,
    pub inferred: Vec<String>,
    pub lint_bypassed: Option<String>,
}

fn local(kind: FailureKind, msg: impl Into<String>, field: &str) -> TransportFailure {
    TransportFailure::new(Phase::Prepare, kind, msg).with_field(field)
}

/// Characters that are not valid unencoded in a request-target.
fn encode_target_part(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            ' ' | '"' | '<' | '>' | '\\' | '^' | '`' | '{' | '|' | '}' => out.push_str(&format!("%{:02X}", ch as u32)),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => out.push_str(&format!("%{:02X}", c as u32)),
            c if !c.is_ascii() => {
                let mut buf = [0u8; 4];
                for b in c.encode_utf8(&mut buf).bytes() {
                    out.push_str(&format!("%{b:02X}"));
                }
            }
            c => out.push(c),
        }
    }
    out
}

/// The one query encoder, shared with multi-auth so an HMAC profile signs
/// the query parameters an earlier profile added exactly as they are sent.
pub use anvil_auth::encode_query_component as encode_component;

/// Parse a resolved URL into a target without normalizing the path.
pub fn parse_target(raw: &str, allowed_schemes: &[&str], inferred: &mut Vec<String>) -> Result<Target, TransportFailure> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(local(FailureKind::InvalidUrl, "the URL is empty", "url"));
    }
    let with_scheme = if raw.contains("://") {
        raw.to_string()
    } else {
        inferred.push(format!("no scheme given; using {}://", allowed_schemes[0]));
        format!("{}://{raw}", allowed_schemes[0])
    };
    let (scheme, rest) = with_scheme.split_once("://").ok_or_else(|| local(FailureKind::InvalidUrl, "the URL has no scheme", "url"))?;
    let scheme = scheme.to_ascii_lowercase();
    if !allowed_schemes.contains(&scheme.as_str()) {
        return Err(local(
            FailureKind::UnsupportedScheme,
            format!("scheme '{scheme}' is not supported for this protocol (expected {})", allowed_schemes.join(" or ")),
            "url",
        ));
    }
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    if authority.is_empty() {
        return Err(local(FailureKind::InvalidUrl, "the URL has no host", "url"));
    }
    if authority.contains('@') {
        return Err(local(
            FailureKind::InvalidUrl,
            "credentials embedded in the URL are not sent; use an auth profile (Basic) so they are stored and redacted as secrets",
            "url",
        ));
    }
    let parse_scheme = match scheme.as_str() {
        "ws" | "grpc" | "tcp" | "udp" => "http",
        "wss" | "grpcs" | "tls" | "dtls" => "https",
        s => s,
    };
    let u = url::Url::parse(&format!("{parse_scheme}://{authority}/"))
        .map_err(|e| local(FailureKind::InvalidUrl, format!("invalid host or port in '{authority}': {e}"), "url"))?;
    let host = match u.host() {
        Some(url::Host::Domain(d)) => d.to_string(),
        Some(url::Host::Ipv4(ip)) => ip.to_string(),
        Some(url::Host::Ipv6(ip)) => ip.to_string(),
        None => return Err(local(FailureKind::InvalidUrl, "the URL has no host", "url")),
    };
    let default_port = match scheme.as_str() {
        "http" | "ws" | "grpc" => Some(80),
        "https" | "wss" | "grpcs" => Some(443),
        _ => None,
    };
    // `url` drops a port equal to the parse scheme's default, so an explicit `:80`/`:443` on a raw
    // scheme (which has no implicit default) reads back as `None`. Re-parse under the other special
    // scheme, whose default differs, to recover the port that was actually written.
    let explicit_port = match u.port() {
        Some(p) => Some(p),
        None if default_port.is_none() => {
            let alt_scheme = if parse_scheme == "https" { "http" } else { "https" };
            url::Url::parse(&format!("{alt_scheme}://{authority}/")).ok().and_then(|alt| alt.port())
        }
        None => None,
    };
    let port = match explicit_port.or(default_port) {
        Some(p) => p,
        None => return Err(local(FailureKind::InvalidUrl, format!("{scheme}:// URLs need an explicit port"), "url")),
    };
    let host_for_authority = if host.contains(':') { format!("[{host}]") } else { host.clone() };
    let authority = if Some(port) == default_port { host_for_authority } else { format!("{host_for_authority}:{port}") };
    let tail = &rest[end..];
    let tail = tail.split('#').next().unwrap_or("");
    let (path, query) = match tail.split_once('?') {
        Some((p, q)) => (p, q),
        None => (tail, ""),
    };
    let path = if path.is_empty() { "/".to_string() } else { encode_target_part(path) };
    Ok(Target { scheme, host, port, authority, path, query: encode_target_part(query) })
}

/// Why an explicit `Host` value is not `uri-host [":" port]` (RFC 9110
/// §7.2, RFC 3986 §3.2.2): a host name or IPv4 address, or an IPv6 address
/// in brackets, each with an optional port. `None` when it is one. The
/// value is the authority the request names, and its signature covers; it
/// changes a cleartext HTTP forward proxy's absolute-form destination;
/// otherwise it never changes where the connection goes.
pub(crate) fn host_problem(v: &str) -> Option<String> {
    if v.is_empty() {
        return Some("it is empty".into());
    }
    if v.chars().any(char::is_whitespace) {
        return Some("it contains whitespace".into());
    }
    for (c, part) in [('@', "userinfo"), ('/', "a path"), ('?', "a query"), ('#', "a fragment")] {
        if v.contains(c) {
            return Some(format!("it contains {part} ('{c}')"));
        }
    }
    let (host, port) = match v.strip_prefix('[') {
        Some(rest) => {
            let Some((literal, after)) = rest.split_once(']') else { return Some("the IPv6 address has no closing ']'".into()) };
            if literal.parse::<std::net::Ipv6Addr>().is_err() {
                return Some("the address in brackets is not an IPv6 address".into());
            }
            match after.strip_prefix(':') {
                Some(port) => (None, Some(port)),
                None if after.is_empty() => (None, None),
                None => return Some("only a port may follow the IPv6 address".into()),
            }
        }
        None if v.matches(':').count() > 1 => {
            return Some(match v.parse::<std::net::Ipv6Addr>() {
                Ok(_) => "an IPv6 address must be in brackets ([...])".into(),
                Err(_) => "it has more than one ':' (a single ':' separates the host from the port)".into(),
            });
        }
        None => match v.split_once(':') {
            Some((host, port)) => (Some(host), Some(port)),
            None => (Some(v), None),
        },
    };
    if host.is_some_and(|h| h.is_empty()) {
        return Some("it has no host".into());
    }
    if host.is_some_and(|h| !is_reg_name(h)) {
        return Some("the host is not a host name or an IPv4 address".into());
    }
    if port.is_some_and(|p| !p.bytes().all(|b| b.is_ascii_digit()) || p.parse::<u16>().is_err()) {
        return Some("the port is not a number from 0 to 65535".into());
    }
    None
}

/// An RFC 3986 `reg-name` (which covers an IPv4 address): unreserved and
/// sub-delim characters and percent-encoded octets.
fn is_reg_name(h: &str) -> bool {
    let mut bytes = h.bytes();
    while let Some(b) = bytes.next() {
        let ok = match b {
            b'%' => bytes.next().is_some_and(|x| x.is_ascii_hexdigit()) && bytes.next().is_some_and(|x| x.is_ascii_hexdigit()),
            b => b.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=".contains(&b),
        };
        if !ok {
            return false;
        }
    }
    true
}

fn has_header(h: &[(String, String)], name: &str) -> bool {
    h.iter().any(|(n, _)| n.eq_ignore_ascii_case(name))
}

pub fn prepare_http(
    spec: &RequestSpec,
    r: &Resolver,
    attachments: &dyn AttachmentResolver,
    settings: &EffectiveSettings,
    send_anyway: bool,
    allowed_schemes: &[&str],
) -> Result<PreparedHttp, TransportFailure> {
    prepare_http_with_redaction_names(spec, r, attachments, settings, &[], send_anyway, allowed_schemes)
}

/// Prepare an HTTP request using configured credential names to identify
/// credential-bearing form fields for cross-origin redirect handling.
pub(crate) fn prepare_http_with_redaction_names(
    spec: &RequestSpec,
    r: &Resolver,
    attachments: &dyn AttachmentResolver,
    settings: &EffectiveSettings,
    redaction_names: &[String],
    send_anyway: bool,
    allowed_schemes: &[&str],
) -> Result<PreparedHttp, TransportFailure> {
    let mut inferred = Vec::new();
    let method = r.resolve(spec.method.trim(), "method")?.to_ascii_uppercase();
    if method.is_empty() || !method.bytes().all(|b| b.is_ascii_alphabetic() || b == b'-' || b == b'_') {
        return Err(local(FailureKind::InvalidHeader, format!("'{method}' is not a valid HTTP method token"), "method"));
    }
    let url = r.resolve(&spec.url, "url")?;
    let mut target = parse_target(&url, allowed_schemes, &mut inferred)?;
    let mut extra_query = Vec::new();
    for (i, p) in spec.params.iter().enumerate().filter(|(_, p)| p.enabled) {
        let k = r.resolve(&p.name, &format!("params[{i}].name"))?;
        let v = r.resolve(&p.value, &format!("params[{i}].value"))?;
        if p.sensitive {
            r.mark_sensitive(&k, &v);
        }
        extra_query.push(format!("{}={}", encode_component(&k), encode_component(&v)));
    }
    if !extra_query.is_empty() {
        let joined = extra_query.join("&");
        target.query = if target.query.is_empty() { joined } else { format!("{}&{joined}", target.query) };
    }

    let mut headers: Vec<(String, String)> = Vec::new();
    let mut sensitive_headers: Vec<String> = Vec::new();
    for (i, h) in spec.headers.iter().enumerate().filter(|(_, h)| h.enabled) {
        let n = r.resolve(h.name.trim(), &format!("headers[{i}].name"))?;
        let v = r.resolve(&h.value, &format!("headers[{i}].value"))?;
        if h.sensitive {
            r.mark_sensitive(&n, &v);
        }
        if http::HeaderName::from_bytes(n.as_bytes()).is_err() {
            return Err(local(FailureKind::InvalidHeader, format!("'{n}' is not a valid header name"), &format!("headers[{i}].name")));
        }
        if n.starts_with(':') {
            return Err(local(
                FailureKind::InvalidHeader,
                "HTTP/2 pseudo-headers are set by the protocol, not as ordinary headers",
                &format!("headers[{i}].name"),
            ));
        }
        if http::HeaderValue::from_str(&v).is_err() {
            return Err(local(
                FailureKind::InvalidHeader,
                format!("the value of '{n}' contains characters not allowed in a header"),
                &format!("headers[{i}].value"),
            ));
        }
        // Sent as the Host (HTTP/1.1) or :authority (HTTP/2, HTTP/3) of
        // every HTTP-based protocol, and signed as such.
        if n.eq_ignore_ascii_case("host")
            && let Some(why) = host_problem(&v)
        {
            return Err(local(
                FailureKind::InvalidHeader,
                format!(
                    "the Host header must be a host with an optional port (a host name, an IPv4 address or an IPv6 address in brackets, then optionally :port), and {why}; the request was not sent"
                ),
                &format!("headers[{i}].value"),
            ));
        }
        if h.sensitive {
            sensitive_headers.push(n.to_ascii_lowercase());
        }
        headers.push((n, v));
    }

    // ---- body ----
    let secret_substitutions_before_body = r.secret_substitutions();
    let mut sensitive_body_field = false;
    let (body, inferred_ct, lint_target): (Vec<u8>, Option<String>, Option<(&str, String)>) = match &spec.body {
        Body::None => (vec![], None, None),
        Body::Raw { text, content_type } => {
            let t = r.resolve(text, "body")?;
            (t.into_bytes(), Some(content_type.clone().unwrap_or_else(|| "text/plain; charset=utf-8".into())), None)
        }
        Body::Json { text } => {
            let t = r.resolve(text, "body")?;
            (t.clone().into_bytes(), Some("application/json".into()), Some(("json", t)))
        }
        Body::Xml { text } => {
            let t = r.resolve(text, "body")?;
            (t.clone().into_bytes(), Some("application/xml".into()), Some(("xml", t)))
        }
        Body::FormUrlEncoded { fields } => {
            let mut parts = Vec::new();
            for (i, f) in fields.iter().enumerate().filter(|(_, f)| f.enabled) {
                let k = r.resolve(&f.name, &format!("body.fields[{i}].name"))?;
                let v = r.resolve(&f.value, &format!("body.fields[{i}].value"))?;
                if f.sensitive {
                    r.mark_sensitive(&k, &v);
                }
                if f.sensitive || crate::redact::is_credential_name(&k, redaction_names) {
                    sensitive_body_field = true;
                }
                parts.push(format!(
                    "{}={}",
                    url::form_urlencoded::byte_serialize(k.as_bytes()).collect::<String>(),
                    url::form_urlencoded::byte_serialize(v.as_bytes()).collect::<String>()
                ));
            }
            (parts.join("&").into_bytes(), Some("application/x-www-form-urlencoded".into()), None)
        }
        Body::Multipart { parts } => {
            let mut b = [0u8; 12];
            rand::fill(&mut b);
            let boundary = format!("----AnvilFormBoundary{}", hex::encode(b));
            let mut out: Vec<u8> = Vec::new();
            for (i, p) in parts.iter().enumerate().filter(|(_, p)| p.enabled) {
                let resolved_name = r.resolve(&p.name, &format!("body.parts[{i}].name"))?;
                let name = resolved_name.replace('"', "%22");
                out.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
                match &p.content {
                    MultipartContent::Text { value } => {
                        let v = r.resolve(value, &format!("body.parts[{i}].value"))?;
                        // Multipart parts carry no sensitive flag; a credential-like name alone
                        // keeps the body off cross-origin redirects.
                        if crate::redact::is_credential_name(&resolved_name, redaction_names) {
                            sensitive_body_field = true;
                        }
                        out.extend_from_slice(format!("Content-Disposition: form-data; name=\"{name}\"\r\n").as_bytes());
                        if let Some(ct) = &p.content_type {
                            out.extend_from_slice(format!("Content-Type: {ct}\r\n").as_bytes());
                        }
                        out.extend_from_slice(b"\r\n");
                        out.extend_from_slice(v.as_bytes());
                    }
                    MultipartContent::File { attachment, file_name } => {
                        let data = attachments
                            .load(attachment)
                            .map_err(|e| local(FailureKind::MissingAttachment, e, &format!("body.parts[{i}].file")))?;
                        let fname = file_name.clone().unwrap_or_else(|| match attachment {
                            anvil_domain::request::AttachmentRef::Stored { file_name, .. } => file_name.clone(),
                            anvil_domain::request::AttachmentRef::LinkedFile { path } => std::path::Path::new(path)
                                .file_name()
                                .map(|f| f.to_string_lossy().into_owned())
                                .unwrap_or_else(|| "file".into()),
                        });
                        out.extend_from_slice(
                            format!("Content-Disposition: form-data; name=\"{name}\"; filename=\"{}\"\r\n", fname.replace('"', "%22"))
                                .as_bytes(),
                        );
                        out.extend_from_slice(
                            format!(
                                "Content-Type: {}\r\n\r\n",
                                p.content_type.clone().unwrap_or_else(|| "application/octet-stream".into())
                            )
                            .as_bytes(),
                        );
                        out.extend_from_slice(&data);
                    }
                }
                out.extend_from_slice(b"\r\n");
            }
            out.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
            (out, Some(format!("multipart/form-data; boundary={boundary}")), None)
        }
        Body::Binary { attachment, content_type } => {
            let data = attachments.load(attachment).map_err(|e| local(FailureKind::MissingAttachment, e, "body.attachment"))?;
            (data.to_vec(), Some(content_type.clone().unwrap_or_else(|| "application/octet-stream".into())), None)
        }
        Body::GraphQl { query, variables, operation_name } => {
            let q = r.resolve(query, "body.query")?;
            let vars_text = r.resolve(variables, "body.variables")?;
            let vars = if vars_text.trim().is_empty() {
                serde_json::Value::Null
            } else {
                match serde_json::from_str::<serde_json::Value>(&vars_text) {
                    Ok(v) if v.is_object() => v,
                    Ok(_) => {
                        return Err(local(FailureKind::BodySerialization, "GraphQL variables must be a JSON object", "body.variables"));
                    }
                    Err(e) => {
                        if !send_anyway {
                            return Err(local(
                                FailureKind::LintBlocked,
                                format!("GraphQL variables are not valid JSON (line {}, column {}): {e}", e.line(), e.column()),
                                "body.variables",
                            ));
                        }
                        serde_json::Value::Null
                    }
                }
            };
            let mut obj = serde_json::Map::new();
            obj.insert("query".into(), q.into());
            if !vars.is_null() {
                obj.insert("variables".into(), vars);
            }
            if let Some(op) = operation_name {
                obj.insert("operationName".into(), r.resolve(op, "body.operation_name")?.into());
            }
            (serde_json::to_vec(&serde_json::Value::Object(obj)).unwrap_or_default(), Some("application/json".into()), None)
        }
        Body::Soap { version, envelope, action } => {
            let t = r.resolve(envelope, "body")?;
            let action = match action {
                Some(a) => Some(r.resolve(a, "body.action")?),
                None => None,
            };
            let ct = match version {
                SoapVersion::Soap11 => {
                    if let Some(a) = &action
                        && !has_header(&headers, "SOAPAction")
                    {
                        headers.push(("SOAPAction".into(), format!("\"{a}\"")));
                        inferred.push("SOAPAction header from the SOAP 1.1 action".into());
                    }
                    "text/xml; charset=utf-8".to_string()
                }
                SoapVersion::Soap12 => match &action {
                    Some(a) => format!("application/soap+xml; charset=utf-8; action=\"{a}\""),
                    None => "application/soap+xml; charset=utf-8".to_string(),
                },
            };
            (t.clone().into_bytes(), Some(ct), Some(("xml", t)))
        }
    };
    let body_uses_secret = sensitive_body_field || r.secret_substitutions() > secret_substitutions_before_body;

    // ---- lint ----
    let mut lint_bypassed = None;
    if let Some((kind, text)) = lint_target
        && spec.lint_policy != LintSendPolicy::Off
    {
        let res = if kind == "json" { lint::json(&text) } else { lint::xml(&text) };
        let finding = match res {
            LintResult::Invalid { issues } => {
                let i = &issues[0];
                Some(format!("{} body is not well-formed at line {}, column {}: {}", kind.to_uppercase(), i.line, i.column, i.message))
            }
            // Not parsed at all, so there is no position to report.
            LintResult::Refused { reason } => Some(format!("{} body was not linted: {reason}", kind.to_uppercase())),
            LintResult::Valid | LintResult::Skipped { .. } => None,
        };
        if let Some(msg) = finding {
            if spec.lint_policy == LintSendPolicy::Block && !send_anyway {
                return Err(local(FailureKind::LintBlocked, msg, "body"));
            }
            lint_bypassed = Some(msg);
        }
    }

    if body.len() as u64 > settings.limits.max_request_body_bytes {
        return Err(local(
            FailureKind::RequestTooLargeLocal,
            format!("request body is {} bytes, above the local limit of {} bytes", body.len(), settings.limits.max_request_body_bytes),
            "body",
        ));
    }

    let mut content_type = headers.iter().find(|(n, _)| n.eq_ignore_ascii_case("content-type")).map(|(_, v)| v.clone());
    if let Some(ct) = inferred_ct {
        if content_type.is_some() {
            if content_type.as_deref() != Some(ct.as_str()) {
                inferred.push(format!("kept explicit Content-Type (the body type suggests '{ct}')"));
            }
        } else if settings.infer_content_type && !body.is_empty() {
            headers.push(("Content-Type".into(), ct.clone()));
            inferred.push(format!("Content-Type: {ct} (inferred from the body type)"));
            content_type = Some(ct);
        }
    }
    if !has_header(&headers, "user-agent") {
        headers.push(("User-Agent".into(), format!("Ferrum-Anvil/{}", env!("CARGO_PKG_VERSION"))));
        inferred.push("User-Agent added".into());
    }
    if !has_header(&headers, "accept") {
        headers.push(("Accept".into(), "*/*".into()));
    }
    if settings.decompress && !has_header(&headers, "accept-encoding") {
        headers.push(("Accept-Encoding".into(), "gzip, deflate, br, zstd".into()));
        inferred.push("Accept-Encoding: gzip, deflate, br, zstd (automatic decompression is on)".into());
    }
    Ok(PreparedHttp {
        method,
        target,
        headers,
        sensitive_headers,
        body: Bytes::from(body),
        body_uses_secret,
        content_type,
        inferred,
        lint_bypassed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_preserves_raw_path_and_encodes_only_invalid_chars() {
        let mut inf = vec![];
        let t = parse_target("https://API.Example.com:8443/a/../b/%2F c?x=1&y=é#frag", &["https", "http"], &mut inf).unwrap();
        assert_eq!(t.host, "api.example.com");
        assert_eq!(t.authority, "api.example.com:8443");
        assert_eq!(t.path, "/a/../b/%2F%20c", "dot segments and existing escapes are preserved");
        assert_eq!(t.query, "x=1&y=%C3%A9");
    }

    #[test]
    fn local_001_malformed_urls_fail_locally() {
        let mut inf = vec![];
        for bad in ["", "https://", "ftp://x/", "https://user:pw@h/", "https://exa mple.com/"] {
            let e = parse_target(bad, &["https", "http"], &mut inf).unwrap_err();
            assert!(matches!(e.kind, FailureKind::InvalidUrl | FailureKind::UnsupportedScheme), "{bad}: {:?}", e);
            assert_eq!(e.phase, Phase::Prepare);
        }
    }

    /// The load preflight accepts a per-run port after a fixed loopback host
    /// (`anvil-app` `per_run_origin`) only because a value there can change
    /// the port or make the URL invalid, never the host: an `@` anywhere in
    /// the authority is refused, the host ends at the first `:`, and the port
    /// must be ASCII digits in range. Pinned for every scheme a load request
    /// is sent with, and for a URL whose scheme is inferred.
    #[test]
    fn a_value_after_a_fixed_hosts_port_colon_never_changes_the_host() {
        let schemes = ["http", "https", "ws", "wss", "grpc", "grpcs", "tcp", "tls", "udp", "dtls"];
        let values = [
            "80@evil.example",
            "80\\@evil.example",
            "80#@evil.example",
            "80/../@evil.example",
            "80%40evil.example",
            "\u{ff18}\u{ff10}",
            "80:81",
            "80\tevil",
            "//evil.example",
            "80.evil.example",
            "80\\evil.example",
            "",
        ];
        for scheme in schemes {
            for (host, parsed) in [("127.0.0.1", "127.0.0.1"), ("[::1]", "::1"), ("localhost", "localhost")] {
                for value in values {
                    let url = format!("{scheme}://{host}:{value}/x");
                    if let Ok(t) = parse_target(&url, &[scheme], &mut vec![]) {
                        assert_eq!(t.host, parsed, "{url}");
                    }
                }
            }
        }
        for value in values {
            let url = format!("localhost:{value}/x");
            if let Ok(t) = parse_target(&url, &["https", "http"], &mut vec![]) {
                assert_eq!(t.host, "localhost", "{url}");
            }
        }

        // The two rejections the preflight relies on, explicitly.
        for scheme in schemes {
            for value in ["80@evil.example", "80\\@evil.example", "@evil.example"] {
                let url = format!("{scheme}://127.0.0.1:{value}/x");
                assert!(parse_target(&url, &[scheme], &mut vec![]).is_err(), "{url}");
            }
            for port in ["65536", "99999", "-1", "80x", "\u{ff18}\u{ff10}", "80:81", "80.evil.example", "80%40evil.example"] {
                let url = format!("{scheme}://127.0.0.1:{port}/x");
                assert!(parse_target(&url, &[scheme], &mut vec![]).is_err(), "{url}");
            }
        }
    }

    fn prepared(spec: &RequestSpec) -> PreparedHttp {
        let vars = vec![
            crate::vars::VarEntry { name: "password".into(), value: "tok-SENSITIVE-p@ss w/rd+=".into(), secret: true, literal: false },
            crate::vars::VarEntry { name: "password_ref".into(), value: "{{password}}".into(), secret: false, literal: false },
            crate::vars::VarEntry {
                name: "credentials".into(),
                value: r#"{ "user": "alice", "password": "tok-SENSITIVE-gql-9z8y7x" }"#.into(),
                secret: true,
                literal: false,
            },
            crate::vars::VarEntry { name: "user".into(), value: "alice".into(), secret: false, literal: false },
        ];
        let r = Resolver::new(vec![crate::vars::VarLayer { label: "environment:test".into(), vars }], Some(1));
        let attachments = crate::context::MemoryAttachments::default();
        prepare_http(spec, &r, &attachments, &EffectiveSettings::default(), false, &["https"]).unwrap()
    }

    fn holds(body: &[u8], s: &str) -> bool {
        body.windows(s.len()).any(|w| w == s.as_bytes())
    }

    #[test]
    fn body_uses_secret_is_decided_before_the_body_is_encoded() {
        use anvil_domain::request::KeyValue;
        let mut spec = RequestSpec::http("POST", "https://api.example.com/login");
        spec.body = Body::FormUrlEncoded { fields: vec![KeyValue::new("user", "{{user}}"), KeyValue::new("password", "{{password}}")] };
        let form = prepared(&spec);
        assert!(form.body_uses_secret);
        assert!(!holds(&form.body, "tok-SENSITIVE-p@ss w/rd+="), "the encoded form does not hold the secret byte for byte");

        spec.body = Body::GraphQl {
            query: "mutation Login($input: LoginInput!) { login(input: $input) { ok } }".into(),
            variables: r#"{"input": {{credentials}}}"#.into(),
            operation_name: None,
        };
        let graphql = prepared(&spec);
        assert!(graphql.body_uses_secret);
        let secret = r#"{ "user": "alice", "password": "tok-SENSITIVE-gql-9z8y7x" }"#;
        assert!(!holds(&graphql.body, secret), "the re-serialized variables do not hold the secret byte for byte");

        // A secret used outside the body does not mark the body.
        spec.headers.push(KeyValue::new("Authorization", "Basic {{password}}"));
        spec.body = Body::FormUrlEncoded { fields: vec![KeyValue::new("user", "{{user}}")] };
        assert!(!prepared(&spec).body_uses_secret);

        // Reusing a secret already resolved in a header still marks the body.
        spec.body = Body::FormUrlEncoded { fields: vec![KeyValue::new("password", "{{password}}")] };
        assert!(prepared(&spec).body_uses_secret);

        // Indirect expansion resolves the secret variable in the body.
        spec.body = Body::Raw { text: "{{password_ref}}".into(), content_type: None };
        assert!(prepared(&spec).body_uses_secret);

        // Multipart text parts are resolved before their bytes are assembled.
        spec.body = Body::Multipart {
            parts: vec![anvil_domain::request::MultipartPart {
                name: "password".into(),
                enabled: true,
                content: MultipartContent::Text { value: "{{password}}".into() },
                content_type: None,
            }],
        };
        assert!(prepared(&spec).body_uses_secret);
    }

    /// A form field marked sensitive holds a secret whether its value is a
    /// secret variable or a literal; once form-encoded, a literal's bytes are
    /// not in the body as such.
    #[test]
    fn a_sensitive_form_field_marks_the_body_whatever_its_value() {
        use anvil_domain::request::KeyValue;
        let literal = "tok-SENSITIVE-lit p@ss+w/rd";
        let mut spec = RequestSpec::http("POST", "https://api.example.com/login");
        let password = KeyValue { sensitive: true, ..KeyValue::new("password", literal) };
        spec.body = Body::FormUrlEncoded { fields: vec![KeyValue::new("user", "alice"), password.clone()] };
        let form = prepared(&spec);
        assert!(form.body_uses_secret, "a sensitive literal form field marks the body");
        assert!(!holds(&form.body, literal), "the encoded form does not hold the literal byte for byte");

        // A short sensitive value, below the byte scan's minimum, still marks it.
        let pin = KeyValue { sensitive: true, ..KeyValue::new("pin", "123") };
        spec.body = Body::FormUrlEncoded { fields: vec![pin] };
        assert!(prepared(&spec).body_uses_secret);

        // Credential-named literal fields are sensitive even when the user
        // did not mark them explicitly.
        spec.body = Body::FormUrlEncoded { fields: vec![KeyValue::new("user", "alice"), KeyValue::new("password", literal)] };
        assert!(prepared(&spec).body_uses_secret);

        let vars = Resolver::new(vec![], Some(1));
        let attachments = crate::context::MemoryAttachments::default();
        let custom_name = prepare_http_with_redaction_names(
            &RequestSpec {
                body: Body::FormUrlEncoded { fields: vec![KeyValue::new("access_code", "1234")] },
                ..RequestSpec::http("POST", "https://api.example.com/login")
            },
            &vars,
            &attachments,
            &EffectiveSettings::default(),
            &["access_code".into()],
            false,
            &["https"],
        )
        .unwrap();
        assert!(custom_name.body_uses_secret, "configured credential names mark literal fields");

        // A disabled sensitive field is not sent, so it does not either.
        let disabled = KeyValue { enabled: false, ..password };
        spec.body = Body::FormUrlEncoded { fields: vec![KeyValue::new("user", "alice"), disabled] };
        assert!(!prepared(&spec).body_uses_secret);
    }

    #[test]
    fn credential_name_fields_do_not_register_literal_values_as_secrets() {
        use anvil_domain::request::KeyValue;
        let value = "John Smith";
        let spec = RequestSpec {
            body: Body::FormUrlEncoded { fields: vec![KeyValue::new("author", value)] },
            ..RequestSpec::http("POST", "https://api.example.com/submit")
        };
        let resolver = Resolver::new(vec![], Some(1));
        let attachments = crate::context::MemoryAttachments::default();
        let request = prepare_http(&spec, &resolver, &attachments, &EffectiveSettings::default(), false, &["https"]).unwrap();

        assert!(resolver.used_secrets.lock().is_empty(), "a heuristic name does not register its value as a secret");
        let redactor = crate::redact::Redactor::for_execution(&resolver, &[]);
        let preview = redactor.text(&String::from_utf8_lossy(&request.body));
        let decoded_value = url::form_urlencoded::parse(preview.as_bytes()).find(|(name, _)| name == "author").map(|(_, value)| value);
        assert_eq!(decoded_value.as_deref(), Some(value), "the preview still shows the author value");
    }

    #[test]
    fn a_multipart_credential_named_text_part_marks_the_body() {
        let spec = RequestSpec {
            body: Body::Multipart {
                parts: vec![anvil_domain::request::MultipartPart {
                    name: "password".into(),
                    enabled: true,
                    content: MultipartContent::Text { value: "literal-password".into() },
                    content_type: None,
                }],
            },
            ..RequestSpec::http("POST", "https://api.example.com/login")
        };
        assert!(prepared(&spec).body_uses_secret);
    }

    #[test]
    fn an_explicit_host_is_uri_host_with_an_optional_port() {
        for ok in ["api.example.test", "A.test:8443", "192.0.2.10", "192.0.2.10:8080", "[2001:db8::1]", "[::1]:443", "a%2Db.test"] {
            assert_eq!(host_problem(ok), None, "{ok}");
        }
        for (bad, why) in [
            ("", "empty"),
            ("a.test/admin", "a path"),
            ("user@a.test", "userinfo"),
            ("user:pw@a.test", "userinfo"),
            ("a.test?x=1", "a query"),
            ("a.test#top", "a fragment"),
            ("a.test extra", "whitespace"),
            ("a.test\t", "whitespace"),
            ("2001:db8::1", "brackets"),
            ("a.test:80:90", "more than one ':'"),
            ("a.test::80", "more than one ':'"),
            ("[2001:db8::1", "closing"),
            ("[a.test]", "not an IPv6 address"),
            ("[::1]x", "only a port"),
            (":443", "no host"),
            ("a.test:", "port"),
            ("a.test:+80", "port"),
            ("a.test:65536", "port"),
            ("a\\b.test", "not a host name"),
            ("a%zz.test", "not a host name"),
        ] {
            let problem = host_problem(bad).unwrap_or_else(|| panic!("{bad:?} was accepted"));
            assert!(problem.contains(why), "{bad:?}: {problem}");
        }
    }

    #[test]
    fn ipv6_literal() {
        let mut inf = vec![];
        let t = parse_target("http://[::1]:8080/x", &["http"], &mut inf).unwrap();
        assert_eq!(t.host, "::1");
        assert_eq!(t.authority, "[::1]:8080");
    }

    #[test]
    fn default_preparation_lints_declaration_like_xml_as_text_not_a_dtd() {
        let r = Resolver::new(vec![crate::vars::VarLayer { label: "environment:test".into(), vars: Vec::new() }], Some(1));
        let attachments = crate::context::MemoryAttachments::default();

        let cdata = r#"<document><![CDATA[<!DOCTYPE html><html><body>Report</body></html>]]></document>"#;
        let mut spec = RequestSpec::http("POST", "https://api.example.com/");
        spec.body = Body::Xml { text: cdata.into() };
        let form = prepare_http(&spec, &r, &attachments, &EffectiveSettings::default(), false, &["https"]).unwrap();
        assert_eq!(&form.body[..], cdata.as_bytes());

        let comment = r#"<document><!-- documentation example: <!ENTITY example 'value'> --><value>ok</value></document>"#;
        spec.body = Body::Xml { text: comment.into() };
        prepare_http(&spec, &r, &attachments, &EffectiveSettings::default(), false, &["https"]).unwrap();

        spec.body = Body::Xml { text: r#"<!DOCTYPE r [<!ENTITY a "b">]><r>&a;</r>"#.into() };
        let err = prepare_http(&spec, &r, &attachments, &EffectiveSettings::default(), false, &["https"]).unwrap_err();
        assert_eq!(err.kind, FailureKind::LintBlocked);
        assert_eq!(err.phase, Phase::Prepare);
    }
}
