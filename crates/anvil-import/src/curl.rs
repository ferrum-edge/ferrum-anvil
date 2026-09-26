//! cURL command lines (bash/zsh quoting).
//!
//! Supported: `-X`, `-H`, `-d`/`--data`/`--data-ascii`/`--data-raw`/
//! `--data-binary`/`--data-urlencode`/`--json`, `-F`/`--form`/
//! `--form-string`, `-G`, `-u`, `-A`, `-e`, `-b`, `-I`, `-L`,
//! `--max-redirs`, `--compressed`, `--oauth2-bearer`, HTTP-version flags,
//! `--connect-timeout`, `-m`, `--url`. `-k`/`--insecure` is reported and
//! never applied (imports never weaken TLS). File references (`@file`,
//! `-T`, `<file`) are reported, never read. Shell `$VAR` references become
//! `{{VAR}}` placeholders.

use crate::builder::Builder;
use crate::common::{body_from_text, credential, dedupe_content_type, maybe_redact, parse_form, split_query};
use crate::util::is_json_media;
use crate::{Dialect, ImportError};
use anvil_domain::auth::AuthConfig;
use anvil_domain::request::{Body, KeyValue, MultipartContent, MultipartPart, RequestSpec, SoapVersion};
use anvil_domain::settings::{HttpVersionPolicy, RedirectPolicy, SettingsOverrides, TimeoutOverrides};

const MAX_ARGS: usize = 10_000;

/// A shell word plus whether it contained an unexpanded `$VAR` reference.
#[derive(Debug, Clone, PartialEq)]
struct Word {
    text: String,
    vars: Vec<String>,
}

/// Tokenize one command line with POSIX shell quoting rules: single quotes,
/// double quotes (with `\` escapes), `$'…'` ANSI-C strings, backslash
/// escapes and line continuations. Parsing stops at the first unquoted
/// control operator (`|`, `;`, `&`, `>`, `<`) — the rest is returned.
fn tokenize(input: &str) -> Result<(Vec<Word>, Option<String>), String> {
    let chars: Vec<char> = input.chars().collect();
    let mut words = vec![];
    let mut cur = String::new();
    let mut vars = vec![];
    let mut in_word = false;
    let mut i = 0;
    let push = |cur: &mut String, vars: &mut Vec<String>, in_word: &mut bool, words: &mut Vec<Word>| {
        if *in_word {
            words.push(Word { text: std::mem::take(cur), vars: std::mem::take(vars) });
            *in_word = false;
        }
    };
    while i < chars.len() {
        let c = chars[i];
        match c {
            '\\' if i + 1 < chars.len() && (chars[i + 1] == '\n' || (chars[i + 1] == '\r' && chars.get(i + 2) == Some(&'\n'))) => {
                i += if chars[i + 1] == '\r' { 3 } else { 2 };
            }
            '\\' if i + 1 < chars.len() => {
                cur.push(chars[i + 1]);
                in_word = true;
                i += 2;
            }
            ' ' | '\t' | '\n' | '\r' => {
                push(&mut cur, &mut vars, &mut in_word, &mut words);
                i += 1;
            }
            '#' if !in_word => {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
            }
            '\'' => {
                in_word = true;
                i += 1;
                let start = i;
                while i < chars.len() && chars[i] != '\'' {
                    i += 1;
                }
                if i >= chars.len() {
                    return Err("unterminated single quote".into());
                }
                cur.extend(&chars[start..i]);
                i += 1;
            }
            '$' if chars.get(i + 1) == Some(&'\'') => {
                in_word = true;
                i += 2;
                loop {
                    let Some(&ch) = chars.get(i) else { return Err("unterminated $'…' string".into()) };
                    i += 1;
                    match ch {
                        '\'' => break,
                        '\\' => {
                            let Some(&e) = chars.get(i) else { return Err("unterminated $'…' string".into()) };
                            i += 1;
                            match e {
                                'n' => cur.push('\n'),
                                't' => cur.push('\t'),
                                'r' => cur.push('\r'),
                                '0' => cur.push('\0'),
                                'e' | 'E' => cur.push('\u{1b}'),
                                'x' => {
                                    let hex: String = chars[i..].iter().take(2).take_while(|c| c.is_ascii_hexdigit()).collect();
                                    i += hex.len();
                                    if let Some(ch) = u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32) {
                                        cur.push(ch);
                                    }
                                }
                                'u' | 'U' => {
                                    let max = if e == 'u' { 4 } else { 8 };
                                    let hex: String = chars[i..].iter().take(max).take_while(|c| c.is_ascii_hexdigit()).collect();
                                    i += hex.len();
                                    if let Some(ch) = u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32) {
                                        cur.push(ch);
                                    }
                                }
                                other => cur.push(other),
                            }
                        }
                        other => cur.push(other),
                    }
                }
            }
            '"' => {
                in_word = true;
                i += 1;
                loop {
                    let Some(&ch) = chars.get(i) else { return Err("unterminated double quote".into()) };
                    i += 1;
                    match ch {
                        '"' => break,
                        '\\' => match chars.get(i) {
                            Some(&e @ ('$' | '`' | '"' | '\\')) => {
                                cur.push(e);
                                i += 1;
                            }
                            Some('\n') => i += 1,
                            _ => cur.push('\\'),
                        },
                        '$' => i = read_var(&chars, i, &mut cur, &mut vars),
                        other => cur.push(other),
                    }
                }
            }
            '$' => {
                in_word = true;
                i = read_var(&chars, i + 1, &mut cur, &mut vars);
            }
            '|' | ';' | '&' | '>' | '<' => {
                push(&mut cur, &mut vars, &mut in_word, &mut words);
                let rest: String = chars[i..].iter().collect();
                return Ok((words, Some(rest)));
            }
            other => {
                cur.push(other);
                in_word = true;
                i += 1;
            }
        }
        if words.len() > MAX_ARGS {
            return Err(format!("more than {MAX_ARGS} arguments"));
        }
    }
    push(&mut cur, &mut vars, &mut in_word, &mut words);
    Ok((words, None))
}

/// `$NAME` / `${NAME}` after the `$` at `i`: emit a `{{NAME}}` placeholder.
fn read_var(chars: &[char], mut i: usize, cur: &mut String, vars: &mut Vec<String>) -> usize {
    let braced = chars.get(i) == Some(&'{');
    if braced {
        i += 1;
    }
    let start = i;
    while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
        i += 1;
    }
    let name: String = chars[start..i].iter().collect();
    if braced {
        // Skip modifiers such as ${VAR:-default} up to the closing brace.
        while i < chars.len() && chars[i] != '}' {
            i += 1;
        }
        i += 1;
    }
    if name.is_empty() {
        cur.push('$');
    } else {
        cur.push_str(&format!("{{{{{name}}}}}"));
        vars.push(name);
    }
    i
}

enum Data {
    Text(String),
    UrlEncode(String),
}

pub(crate) fn import(text: &str, b: &mut Builder) -> Result<(), ImportError> {
    let t = text.trim_start();
    let t = t.strip_prefix("$ ").unwrap_or(t);
    let (words, rest) = tokenize(t).map_err(|m| ImportError::Syntax { syntax: "shell".into(), message: m, line: None, column: None })?;
    if let Some(r) = rest {
        let r = r.trim();
        if !r.is_empty() {
            b.report.unsupported(
                "shell_pipeline",
                "/args",
                format!("only the first command is imported; ignored: {}", crate::util::clip(r, 80)),
            );
        }
    }
    if words.is_empty() || !(words[0].text == "curl" || words[0].text.ends_with("/curl") || words[0].text == "curl.exe") {
        return Err(ImportError::Invalid {
            dialect: Dialect::Curl,
            pointer: "/args/0".into(),
            message: "the command does not start with curl".into(),
        });
    }
    b.workspace.name = "cURL import".into();
    b.workspace.auth = AuthConfig::None;
    for w in &words {
        for v in &w.vars {
            b.report.require_var(v, crate::util::is_credential_name(v), "shell variable in the cURL command", "/args");
        }
    }

    let mut method: Option<String> = None;
    let mut urls: Vec<(String, String)> = vec![];
    let mut headers: Vec<KeyValue> = vec![];
    let mut data: Vec<Data> = vec![];
    let mut form: Vec<MultipartPart> = vec![];
    let mut get = false;
    let mut head = false;
    let mut json = false;
    let mut auth = AuthConfig::Inherit;
    let mut settings = SettingsOverrides::default();
    let mut follow = false;
    let mut max_redirs: Option<u8> = None;

    let args = expand_clusters(words.iter().map(|w| w.text.clone()).collect());
    let mut i = 1;
    while i < args.len() {
        let at = format!("/args/{}", args[i].1);
        let a = args[i].0.clone();
        let opt = a.clone();
        let value = |i: &mut usize| -> Option<String> {
            *i += 1;
            args.get(*i).map(|x| x.0.clone())
        };
        match opt.as_str() {
            "-X" | "--request" => method = value(&mut i).map(|m| m.to_ascii_uppercase()),
            "-H" | "--header" => {
                if let Some(h) = value(&mut i) {
                    if let Some(file) = h.strip_prefix('@') {
                        b.report.external_ref(file, &at);
                        b.report.unsupported("curl_header_file", &at, "headers read from a file are not imported");
                    } else if let Some((k, v)) = h.split_once(':') {
                        let k = k.trim().to_string();
                        let v = v.trim().to_string();
                        if v.is_empty() {
                            b.report.warn("curl_header_removal", &at, format!("`-H \"{k}:\"` removes a default curl header; not represented"));
                        } else {
                            let (value, sensitive) = maybe_redact(b, &k, &v, &at, "header");
                            headers.push(KeyValue { name: k, value, enabled: true, description: String::new(), sensitive });
                        }
                    } else if let Some(k) = h.strip_suffix(';') {
                        headers.push(KeyValue::new(k.trim(), ""));
                    }
                }
            }
            "-d" | "--data" | "--data-ascii" | "--data-binary" => {
                if let Some(d) = value(&mut i) {
                    if let Some(file) = d.strip_prefix('@') {
                        b.report.external_ref(file, &at);
                        b.report.unsupported("curl_data_file", &at, "request data read from a file is not imported; paste the content into the body");
                    } else {
                        // cURL strips CR/LF only from data it reads from a
                        // file; a literal argument is sent byte for byte.
                        data.push(Data::Text(d));
                    }
                }
            }
            "--data-raw" => {
                if let Some(d) = value(&mut i) {
                    data.push(Data::Text(d));
                }
            }
            "--json" => {
                json = true;
                if let Some(d) = value(&mut i) {
                    if let Some(file) = d.strip_prefix('@') {
                        b.report.external_ref(file, &at);
                        b.report.unsupported("curl_data_file", &at, "request data read from a file is not imported");
                    } else {
                        data.push(Data::Text(d));
                    }
                }
            }
            "--data-urlencode" => {
                if let Some(d) = value(&mut i) {
                    if d.contains('@') && d.split_once('@').is_some_and(|(n, _)| !n.contains('=')) {
                        b.report.external_ref(d.split_once('@').map(|x| x.1).unwrap_or(""), &at);
                        b.report.unsupported("curl_data_file", &at, "URL-encoded data read from a file is not imported");
                    } else {
                        data.push(Data::UrlEncode(d));
                    }
                }
            }
            "-F" | "--form" | "--form-string" => {
                if let Some(f) = value(&mut i) {
                    let Some((name, val)) = f.split_once('=') else {
                        b.report.warn("curl_form", &at, format!("form field '{f}' has no '='; skipped"));
                        i += 1;
                        continue;
                    };
                    if opt == "--form-string" {
                        // Everything after the first '=' is the literal value:
                        // no `@`/`<` file reads and no `;type=` metadata.
                        let (value, _) = maybe_redact(b, name, val, &at, "form field");
                        form.push(MultipartPart {
                            name: name.into(),
                            enabled: true,
                            content: MultipartContent::Text { value },
                            content_type: None,
                        });
                        i += 1;
                        continue;
                    }
                    let mut parts = val.split(';');
                    let content = parts.next().unwrap_or("").to_string();
                    let ctype = parts.find_map(|p| p.trim().strip_prefix("type=").map(str::to_string));
                    if content.starts_with('@') || content.starts_with('<') {
                        b.report.external_ref(&content[1..], &at);
                        b.report.warn("file_part_requires_attachment", &at, format!("form part '{name}' reads a file: attach it before sending (imported disabled)"));
                        form.push(MultipartPart { name: name.into(), enabled: false, content: MultipartContent::Text { value: String::new() }, content_type: ctype });
                    } else {
                        let (value, _) = maybe_redact(b, name, &content, &at, "form field");
                        form.push(MultipartPart { name: name.into(), enabled: true, content: MultipartContent::Text { value }, content_type: ctype });
                    }
                }
            }
            "-G" | "--get" => get = true,
            "-I" | "--head" => head = true,
            "-u" | "--user" => {
                if let Some(u) = value(&mut i) {
                    let (user, pass) = match u.split_once(':') {
                        Some((a, p)) => (a.to_string(), p.to_string()),
                        None => (u.clone(), String::new()),
                    };
                    let pw = credential(b, &pass, "password", &at, "Basic auth password");
                    auth = AuthConfig::Basic { username: user, password: pw };
                }
            }
            "--oauth2-bearer" => {
                if let Some(t) = value(&mut i) {
                    auth = AuthConfig::Bearer { token: credential(b, &t, "token", &at, "bearer token"), prefix: "Bearer".into() };
                }
            }
            "--digest" | "--ntlm" | "--negotiate" | "--anyauth" | "--aws-sigv4" => {
                if opt == "--aws-sigv4" {
                    value(&mut i);
                }
                b.report.unsupported("curl_auth_scheme", &at, format!("`{opt}` authentication is not supported; imported without it"));
            }
            "--basic" => {}
            "-A" | "--user-agent" => {
                if let Some(v) = value(&mut i) {
                    headers.push(KeyValue::new("User-Agent", v));
                }
            }
            "-e" | "--referer" => {
                if let Some(v) = value(&mut i) {
                    headers.push(KeyValue::new("Referer", v));
                }
            }
            "-b" | "--cookie" => {
                if let Some(v) = value(&mut i) {
                    if v.contains('=') {
                        let (value, sensitive) = maybe_redact(b, "Cookie", &v, &at, "header");
                        headers.push(KeyValue { name: "Cookie".into(), value, enabled: true, description: String::new(), sensitive });
                    } else {
                        b.report.external_ref(&v, &at);
                        b.report.unsupported("curl_cookie_file", &at, "cookies read from a cookie jar file are not imported");
                    }
                }
            }
            "-k" | "--insecure" | "--proxy-insecure" => b.report.inactive(
                &at,
                "tls.verify",
                "false",
                "TLS certificate verification bypass is never imported as an active setting; use an explicit TLS profile if you really need it",
            ),
            "-L" | "--location" => follow = true,
            "--location-trusted" => {
                follow = true;
                b.report.inactive(
                    &at,
                    "redirects.forward_credentials_cross_origin",
                    "true",
                    "forwarding credentials to other hosts on redirect is never imported as an active setting",
                );
            }
            "--max-redirs" => max_redirs = value(&mut i).and_then(|v| v.parse::<i64>().ok()).map(|v| v.clamp(0, 255) as u8),
            "--compressed" => settings.decompress = Some(true),
            "--http1.0" | "--http1.1" => settings.http_version = Some(HttpVersionPolicy::Http1Only),
            "--http2" => settings.http_version = Some(HttpVersionPolicy::Auto),
            "--http2-prior-knowledge" => settings.http_version = Some(HttpVersionPolicy::H2c),
            "--http3" => settings.http_version = Some(HttpVersionPolicy::Http3WithFallback),
            "--http3-only" => settings.http_version = Some(HttpVersionPolicy::Http3Only),
            "--connect-timeout" => {
                if let Some(ms) = value(&mut i).and_then(|v| v.parse::<f64>().ok()).map(|s| (s * 1000.0) as u64) {
                    settings.timeouts.get_or_insert_with(TimeoutOverrides::default).connect_ms = Some(Some(ms));
                }
            }
            "-m" | "--max-time" => {
                if let Some(ms) = value(&mut i).and_then(|v| v.parse::<f64>().ok()).map(|s| (s * 1000.0) as u64) {
                    settings.timeouts.get_or_insert_with(TimeoutOverrides::default).total_ms = Some(Some(ms));
                }
            }
            "--url" => {
                if let Some(u) = value(&mut i) {
                    urls.push((u, at.clone()));
                }
            }
            "-T" | "--upload-file" => {
                if let Some(f) = value(&mut i) {
                    b.report.external_ref(&f, &at);
                    b.report.unsupported("curl_upload_file", &at, "file uploads (-T) are not imported; attach the file as a binary body");
                    method.get_or_insert_with(|| "PUT".into());
                }
            }
            "-x" | "--proxy" | "--cacert" | "--capath" | "-E" | "--cert" | "--key" | "--cert-type" | "--key-type" | "--pass" | "--resolve"
            | "--connect-to" | "--interface" | "--dns-servers" | "--proxy-user" | "-U" => {
                let v = value(&mut i).unwrap_or_default();
                let shown = if matches!(opt.as_str(), "--pass" | "--proxy-user" | "-U") { "(redacted)".to_string() } else { v.clone() };
                if matches!(opt.as_str(), "--cacert" | "--capath" | "-E" | "--cert" | "--key") {
                    b.report.external_ref(v.split(':').next().unwrap_or(&v), &at);
                }
                b.report.unsupported("curl_connection_option", &at, format!("`{opt} {shown}` is not imported; configure a proxy/TLS profile or DNS override instead"));
            }
            // Output/progress/verbosity flags do not change the request.
            "-s" | "--silent" | "-S" | "--show-error" | "-v" | "--verbose" | "-i" | "--include" | "-f" | "--fail" | "--fail-with-body" | "-#"
            | "--progress-bar" | "-N" | "--no-buffer" | "--globoff" | "-g" | "-O" | "--remote-name" | "-J" | "--remote-header-name" | "-n"
            | "--netrc" | "--path-as-is" | "-q" => {}
            "-o" | "--output" | "-w" | "--write-out" | "-D" | "--dump-header" | "--retry" | "--retry-delay" | "--trace" | "--trace-ascii"
            | "-c" | "--cookie-jar" | "-r" | "--range" | "-z" | "--time-cond" | "-C" | "--continue-at" | "--limit-rate" => {
                value(&mut i);
                if matches!(opt.as_str(), "--retry" | "-r" | "--range" | "-z" | "--time-cond" | "-C" | "--continue-at" | "--limit-rate") {
                    b.report.unsupported("curl_option", &at, format!("`{opt}` is not imported"));
                }
            }
            s if s.starts_with('-') && s.len() > 1 => {
                b.report.unsupported("curl_option", &at, format!("unknown or unsupported curl option `{s}`; ignored"));
            }
            _ => urls.push((a.clone(), at.clone())),
        }
        i += 1;
    }
    finish(b, Parsed { method, urls, headers, data, form, get, head, json, auth, settings, follow, max_redirs })
}

/// Long options that consume the next argument.
const LONG_WITH_VALUE: &[&str] = &[
    "--request",
    "--header",
    "--data",
    "--data-ascii",
    "--data-binary",
    "--data-raw",
    "--data-urlencode",
    "--json",
    "--form",
    "--form-string",
    "--user",
    "--user-agent",
    "--referer",
    "--cookie",
    "--max-redirs",
    "--connect-timeout",
    "--max-time",
    "--url",
    "--upload-file",
    "--proxy",
    "--cacert",
    "--capath",
    "--cert",
    "--key",
    "--cert-type",
    "--key-type",
    "--pass",
    "--resolve",
    "--connect-to",
    "--interface",
    "--dns-servers",
    "--proxy-user",
    "--output",
    "--write-out",
    "--dump-header",
    "--retry",
    "--retry-delay",
    "--trace",
    "--trace-ascii",
    "--cookie-jar",
    "--range",
    "--time-cond",
    "--continue-at",
    "--limit-rate",
    "--oauth2-bearer",
    "--aws-sigv4",
];

/// Expand short-option clusters (`-sSL`, `-XPOST`, `-H'x: y'`) into
/// separate arguments, keeping each argument's original index for report
/// locations. Values of value-taking options are never re-interpreted.
fn expand_clusters(args: Vec<String>) -> Vec<(String, usize)> {
    let mut out = vec![];
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if i == 0 || !a.starts_with('-') || a == "-" {
            out.push((a.clone(), i));
        } else if a.starts_with("--") {
            out.push((a.clone(), i));
            if LONG_WITH_VALUE.contains(&a.as_str()) && i + 1 < args.len() {
                out.push((args[i + 1].clone(), i + 1));
                i += 1;
            }
        } else {
            let chars: Vec<char> = a[1..].chars().collect();
            for (j, c) in chars.iter().enumerate() {
                let f = format!("-{c}");
                if takes_value(&f) {
                    out.push((f, i));
                    let rest: String = chars[j + 1..].iter().collect();
                    if !rest.is_empty() {
                        out.push((rest, i));
                    } else if i + 1 < args.len() {
                        out.push((args[i + 1].clone(), i + 1));
                        i += 1;
                    }
                    break;
                }
                out.push((f, i));
            }
        }
        i += 1;
    }
    out
}

fn takes_value(flag: &str) -> bool {
    matches!(
        flag,
        "-X" | "-H"
            | "-d"
            | "-F"
            | "-u"
            | "-A"
            | "-e"
            | "-b"
            | "-m"
            | "-o"
            | "-w"
            | "-T"
            | "-x"
            | "-E"
            | "-D"
            | "-r"
            | "-z"
            | "-C"
            | "-U"
            | "-c"
    )
}

struct Parsed {
    method: Option<String>,
    urls: Vec<(String, String)>,
    headers: Vec<KeyValue>,
    data: Vec<Data>,
    form: Vec<MultipartPart>,
    get: bool,
    head: bool,
    json: bool,
    auth: AuthConfig,
    settings: SettingsOverrides,
    follow: bool,
    max_redirs: Option<u8>,
}

fn finish(b: &mut Builder, p: Parsed) -> Result<(), ImportError> {
    let Parsed { method, urls, mut headers, data, form, get, head, json, auth, mut settings, follow, max_redirs } = p;
    let Some((raw_url, url_at)) = urls.first().cloned() else {
        return Err(ImportError::Invalid { dialect: Dialect::Curl, pointer: "/args".into(), message: "no URL in the cURL command".into() });
    };
    for (u, at) in urls.iter().skip(1) {
        b.report.unsupported("curl_multiple_urls", at, format!("only the first URL is imported; '{u}' ignored"));
    }
    if !b.admit(&url_at) {
        return Ok(());
    }
    if follow || max_redirs.is_some() {
        settings.redirects = Some(RedirectPolicy { follow, max: max_redirs.unwrap_or(50), forward_credentials_cross_origin: false });
    }
    let mut url = if raw_url.contains("://") || raw_url.starts_with("{{") { raw_url.clone() } else { format!("http://{raw_url}") };
    if raw_url != url {
        b.report.warn("curl_default_scheme", &url_at, "no scheme in the URL; curl defaults to http://");
    }
    // Credentials embedded in the URL are moved to Basic auth.
    let mut auth = auth;
    if let Some((scheme, rest)) = url.split_once("://")
        && let Some(at_pos) = rest.find('@').filter(|p| rest[..*p].find('/').is_none())
    {
        let userinfo = rest[..at_pos].to_string();
        let (user, pass) =
            userinfo.split_once(':').map(|(u, p)| (u.to_string(), p.to_string())).unwrap_or((userinfo.clone(), String::new()));
        let pw = credential(b, &crate::common::query_decode(&pass), "password", &url_at, "password in the URL");
        auth = AuthConfig::Basic { username: crate::common::query_decode(&user), password: pw };
        url = format!("{scheme}://{}", &rest[at_pos + 1..]);
    }
    let (base, pairs) = split_query(&url);
    let mut params: Vec<KeyValue> = pairs
        .into_iter()
        .enumerate()
        .map(|(n, (k, v))| {
            let (value, sensitive) = maybe_redact(b, &k, &v, &format!("{url_at}#query{n}"), "query");
            KeyValue { name: k, value, enabled: true, description: String::new(), sensitive }
        })
        .collect();

    let has_ct = headers.iter().any(|h| h.name.eq_ignore_ascii_case("content-type"));
    if json {
        if !has_ct {
            headers.push(KeyValue::new("Content-Type", "application/json"));
        }
        if !headers.iter().any(|h| h.name.eq_ignore_ascii_case("accept")) {
            headers.push(KeyValue::new("Accept", "application/json"));
        }
    }
    let ct = crate::common::header_content_type(&headers);
    let mut body = Body::None;
    if !form.is_empty() {
        body = Body::Multipart { parts: form };
        if !data.is_empty() {
            b.report.warn("curl_data_and_form", "/args", "both -d and -F were given (curl refuses this); the form is imported");
        }
    } else if !data.is_empty() {
        let all_encoded = data.iter().all(|d| matches!(d, Data::UrlEncode(_)));
        let joined = data
            .iter()
            .map(|d| match d {
                Data::Text(t) => t.clone(),
                Data::UrlEncode(e) => urlencode_arg(e),
            })
            .collect::<Vec<_>>()
            .join(if json { "" } else { "&" });
        if get {
            for (k, v) in parse_form(&joined)
                .map(|f| f.into_iter().map(|kv| (kv.name, kv.value)).collect::<Vec<_>>())
                .unwrap_or_else(|| vec![(joined.clone(), String::new())])
            {
                let (value, sensitive) = maybe_redact(b, &k, &v, "/args", "query");
                params.push(KeyValue { name: k, value, enabled: true, description: String::new(), sensitive });
            }
        } else {
            let mime = ct.clone().unwrap_or_else(|| "application/x-www-form-urlencoded".into());
            let is_form = crate::util::media_essence(&mime) == "application/x-www-form-urlencoded";
            if is_form && ct.is_none() && !all_encoded && joined.trim_start().starts_with(['{', '[']) {
                b.report.warn(
                    "curl_json_as_form",
                    "/args",
                    "the data looks like JSON but curl sends it as application/x-www-form-urlencoded (no Content-Type header); imported as-is",
                );
                body = Body::Raw { text: joined, content_type: Some(mime) };
            } else if crate::util::media_essence(&mime) == "application/soap+xml" {
                // SOAP 1.2 carries the action as a media-type parameter.
                let params = crate::util::media_params(&mime);
                let action = params.iter().find(|(n, _)| n == "action").map(|(_, v)| v.clone()).filter(|a| !a.is_empty());
                // The engine derives `application/soap+xml; charset=utf-8[; action="…"]`
                // from the body. Drop the header only when that is exactly what
                // was given; otherwise it stays and takes precedence when sending.
                let derivable = params.iter().any(|(n, v)| n == "charset" && v.eq_ignore_ascii_case("utf-8"))
                    && params.iter().filter(|(n, _)| n == "action").count() <= 1
                    && params.iter().all(|(n, v)| match n.as_str() {
                        "charset" => v.eq_ignore_ascii_case("utf-8"),
                        "action" => !v.is_empty() && !v.contains(['"', '\\']),
                        _ => false,
                    });
                if derivable {
                    headers.retain(|h| !h.name.eq_ignore_ascii_case("content-type"));
                }
                body = Body::Soap { version: SoapVersion::Soap12, envelope: joined, action };
            } else if let Some(action) =
                headers.iter().find(|h| h.name.eq_ignore_ascii_case("SOAPAction")).map(|h| h.value.trim_matches('"').to_string())
                && crate::util::is_xml_media(&mime)
            {
                // The engine derives `text/xml; charset=utf-8` for SOAP 1.1.
                // Preserve any explicit type with different parameters so its
                // charset and other media-type details reach the request.
                let is_derivable = |content_type: &str| {
                    let params = crate::util::media_params(content_type);
                    crate::util::media_essence(content_type) == "text/xml"
                        && params.len() == 1
                        && params[0].0 == "charset"
                        && params[0].1.eq_ignore_ascii_case("utf-8")
                };
                let derivable = headers
                    .iter()
                    .filter(|h| h.enabled && h.name.eq_ignore_ascii_case("content-type"))
                    .all(|h| is_derivable(&h.value));
                headers.retain(|h| {
                    !h.name.eq_ignore_ascii_case("SOAPAction") && !(derivable && h.name.eq_ignore_ascii_case("content-type"))
                });
                body = Body::Soap { version: SoapVersion::Soap11, envelope: joined, action: Some(action) };
            } else {
                let (mut bd, _) = body_from_text(Some(&mime), joined);
                if let Body::FormUrlEncoded { fields } = &mut bd {
                    for (n, f) in fields.iter_mut().enumerate() {
                        let (value, sensitive) = maybe_redact(b, &f.name, &f.value, &format!("/args#data{n}"), "form field");
                        f.value = value;
                        f.sensitive = sensitive;
                    }
                }
                if let Body::Json { text } = &mut bd
                    && let Ok(mut v) = serde_json::from_str::<serde_json::Value>(text)
                {
                    let before = b.report.redactions.len();
                    crate::common::scrub_json(b, &mut v, "/args#json");
                    if b.report.redactions.len() > before {
                        *text = serde_json::to_string_pretty(&v).unwrap_or_default();
                    }
                }
                body = bd;
            }
        }
    }
    dedupe_content_type(&mut headers, &body);
    if json && is_json_media(ct.as_deref().unwrap_or("")) {
        headers.retain(|h| !(h.name.eq_ignore_ascii_case("content-type") && h.value == "application/json"));
    }
    let method = method.unwrap_or_else(|| {
        if head {
            "HEAD".into()
        } else if matches!(body, Body::None) || get {
            "GET".into()
        } else {
            "POST".into()
        }
    });
    let mut spec = RequestSpec::http(&method, &base);
    spec.params = params;
    spec.headers = headers;
    spec.body = body;
    spec.auth = auth;
    spec.settings = settings;
    let host = base.split("://").nth(1).and_then(|r| r.split(['/', '?']).next()).unwrap_or(&base).to_string();
    let path = base.split("://").nth(1).and_then(|r| r.find('/').map(|p| &r[p..])).unwrap_or("/");
    b.title = Some(format!("{method} {host}"));
    let name = format!("{method} {path}");
    b.add_request(None, &name, &format!("curl:{method} {base}"), spec, &url_at);
    Ok(())
}

/// `--data-urlencode` forms: `content`, `=content`, `name=content`.
fn urlencode_arg(e: &str) -> String {
    let enc = |s: &str| url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>();
    match e.split_once('=') {
        Some(("", content)) => enc(content),
        Some((name, content)) => format!("{name}={}", enc(content)),
        None => enc(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(s: &str) -> Vec<String> {
        tokenize(s).unwrap().0.into_iter().map(|w| w.text).collect()
    }

    #[test]
    fn quoting() {
        assert_eq!(words(r#"curl 'a b' "c \"d\" $HOME" e\ f"#), vec!["curl", "a b", "c \"d\" {{HOME}}", "e f"]);
        assert_eq!(words("curl $'x\\ty\\u00e9' \\\n  -v"), vec!["curl", "x\ty\u{e9}", "-v"]);
        assert_eq!(words("curl x # comment\n"), vec!["curl", "x"]);
        let (w, rest) = tokenize("curl x | jq .").unwrap();
        assert_eq!(w.len(), 2);
        assert_eq!(rest.as_deref(), Some("| jq ."));
        assert!(tokenize("curl 'unterminated").is_err());
    }
}
