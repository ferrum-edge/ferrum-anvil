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

#[derive(Debug, Clone)]
pub struct PreparedHttp {
    pub method: String,
    pub target: Target,
    pub headers: Vec<(String, String)>,
    /// Lowercased names of the configured headers marked sensitive. They are
    /// credentials of the request's own origin, like `Authorization`.
    pub sensitive_headers: Vec<String>,
    pub body: Bytes,
    /// Whether resolving the body substituted a secret variable. Decided
    /// structurally, before encoding: a form-urlencoded or re-serialized
    /// GraphQL body holds the secret in a form a byte scan does not find.
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

const QUERY_COMPONENT: &percent_encoding::AsciiSet =
    &percent_encoding::NON_ALPHANUMERIC.remove(b'-').remove(b'_').remove(b'.').remove(b'~');

pub fn encode_component(s: &str) -> String {
    percent_encoding::utf8_percent_encode(s, QUERY_COMPONENT).to_string()
}

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
        if h.sensitive {
            sensitive_headers.push(n.to_ascii_lowercase());
        }
        headers.push((n, v));
    }

    // ---- body ----
    let secrets_before_body = r.used_secrets.lock().len();
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
                let name = r.resolve(&p.name, &format!("body.parts[{i}].name"))?.replace('"', "%22");
                out.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
                match &p.content {
                    MultipartContent::Text { value } => {
                        let v = r.resolve(value, &format!("body.parts[{i}].value"))?;
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
    let body_uses_secret = r.used_secrets.lock().len() > secrets_before_body;

    // ---- lint ----
    let mut lint_bypassed = None;
    if let Some((kind, text)) = lint_target
        && spec.lint_policy != LintSendPolicy::Off
    {
        let res = if kind == "json" { lint::json(&text) } else { lint::xml(&text) };
        if let LintResult::Invalid { issues } = res {
            let i = &issues[0];
            let msg = format!("{} body is not well-formed at line {}, column {}: {}", kind.to_uppercase(), i.line, i.column, i.message);
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

    fn prepared(spec: &RequestSpec) -> PreparedHttp {
        let vars = vec![
            crate::vars::VarEntry { name: "password".into(), value: "tok-SENSITIVE-p@ss w/rd+=".into(), secret: true },
            crate::vars::VarEntry {
                name: "credentials".into(),
                value: r#"{ "user": "alice", "password": "tok-SENSITIVE-gql-9z8y7x" }"#.into(),
                secret: true,
            },
            crate::vars::VarEntry { name: "user".into(), value: "alice".into(), secret: false },
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
    }

    #[test]
    fn ipv6_literal() {
        let mut inf = vec![];
        let t = parse_target("http://[::1]:8080/x", &["http"], &mut inf).unwrap();
        assert_eq!(t.host, "::1");
        assert_eq!(t.authority, "[::1]:8080");
    }
}
