//! Preflight locality must describe the destination execution really sends.
//! Recording proxies never relay traffic; all execution stays on loopback.

use anvil_app::App;
use anvil_app::profiles::ProfileManager;
use anvil_domain::Id;
use anvil_domain::auth::{AuthConfig, KeyLocation, OAuth2Config, OAuthClientAuth, OAuthGrant};
use anvil_domain::execution::{DispatchState, FailureKind};
use anvil_domain::load::{ConnectionMode, LoadPlan, Workload};
use anvil_domain::request::{KeyValue, Protocol, RequestSpec};
use anvil_domain::secret::{SecretRef, SensitiveValue};
use anvil_domain::settings::{DnsOverride, ProxySelection};
use anvil_domain::tls::{ProxyKind, ProxyProfile};
use anvil_domain::workspace::{DatasetFormat, Variable};
use anvil_engine::context::SecretResolver;
use anvil_engine::vars::{VarEntry, VarLayer};
use anvil_engine::{Engine, ExecutionContext, ExecutionOutput};
use anvil_storage::KdfParams;
use anvil_transport::recorder::EventCtx;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

fn new_app(root: &std::path::Path) -> App {
    let manager = ProfileManager::new(root);
    let (profile, key, _) = manager.create_passphrase("test", "correct horse battery", KdfParams::testing()).unwrap();
    let header = anvil_storage::vault::read_header(&profile.dir).unwrap();
    App::open(profile.dir, header, key).unwrap()
}

fn plan(app: &App, workspace: Id, spec: RequestSpec) -> LoadPlan {
    let request = app.create_request(&workspace, None, "preflight", spec).unwrap();
    app.save_load_plan(LoadPlan {
        id: Id::new(),
        workspace_id: workspace,
        name: "preflight".into(),
        workload: Workload::Iterations { iterations: 1, concurrency: 1 },
        chain: vec![request.meta.id],
        mix: vec![],
        dataset_id: None,
        environment_id: None,
        connection_mode: ConnectionMode::Fresh,
        warmup_secs: 0,
        abort: None,
        seed: 1,
        trusted: true,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    })
    .unwrap()
}

fn context(app: &App, plan: &LoadPlan) -> ExecutionContext {
    app.load_job(plan).unwrap().requests.remove(&plan.chain[0]).unwrap()
}

fn warns(app: &App, plan: &LoadPlan) -> bool {
    app.load_preflight(plan).unwrap().warnings.iter().any(|warning| warning.contains("Traffic leaves this machine"))
}

fn pin(app: &App, workspace: Id, host: &str, addresses: &[&str]) {
    let mut ws = app.workspace(&workspace).unwrap();
    ws.settings.dns_overrides.retain(|entry| entry.host != host);
    ws.settings
        .dns_overrides
        .push(DnsOverride { host: host.into(), addresses: addresses.iter().map(|address| (*address).into()).collect() });
    app.save_workspace(ws).unwrap();
}

#[test]
fn localhost_preflight_uses_fixed_addresses_before_system_locality() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let ws = app.create_workspace("Fixed localhost address").unwrap().meta.id;
    let p = plan(&app, ws, RequestSpec::http("GET", "http://api.localhost:8080/"));

    pin(&app, ws, "api.localhost", &["198.51.100.7"]);
    assert!(warns(&app, &p), "a fixed non-loopback answer remains remote");
    pin(&app, ws, "api.localhost", &["127.0.0.1"]);
    assert!(!warns(&app, &p), "a fixed loopback answer remains local");
}

fn proxy(app: &App, workspace: Id, kind: ProxyKind, address: &str, no_proxy: &str) -> ProxyProfile {
    app.save_proxy_profile(ProxyProfile {
        id: Id::new(),
        workspace_id: workspace,
        name: "recording proxy".into(),
        kind,
        address: address.into(),
        username: None,
        password: None,
        no_proxy: no_proxy.into(),
        tls_profile_id: None,
        hbone: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    })
    .unwrap()
}

fn routed(mut spec: RequestSpec, proxy: &ProxyProfile) -> RequestSpec {
    spec.settings.proxy_profile_id = Some(ProxySelection::Profile { id: proxy.id });
    spec
}

fn oauth(url: &str) -> AuthConfig {
    AuthConfig::OAuth2 {
        config: OAuth2Config {
            grant: OAuthGrant::ClientCredentials,
            token_url: url.into(),
            authorization_url: String::new(),
            client_id: "client".into(),
            client_secret: SensitiveValue::template("fixture-secret"),
            scope: String::new(),
            audience: String::new(),
            client_auth: OAuthClientAuth::RequestBody,
            token_cache_id: None,
            refresh_skew_secs: 30,
        },
    }
}

fn vault_variable(name: &str, secret: &SecretRef) -> Variable {
    Variable {
        name: name.into(),
        value: SensitiveValue::Secret { secret: secret.clone() },
        secret: true,
        enabled: true,
        description: String::new(),
    }
}

struct CountedSecrets {
    inner: Arc<dyn SecretResolver>,
    reads: Arc<Mutex<Vec<Id>>>,
}

impl SecretResolver for CountedSecrets {
    fn resolve(&self, reference: &SecretRef) -> Result<Zeroizing<String>, String> {
        self.reads.lock().unwrap().push(reference.id);
        self.inner.resolve(reference)
    }

    fn variable_secret(&self, layer: usize, variable: usize) -> Option<SecretRef> {
        self.inner.variable_secret(layer, variable)
    }
}

struct ReplaceIssuerAfterRead {
    inner: Arc<dyn SecretResolver>,
    store: Arc<anvil_storage::Store>,
    workspace: Id,
    issuer: SecretRef,
}

impl SecretResolver for ReplaceIssuerAfterRead {
    fn resolve(&self, reference: &SecretRef) -> Result<Zeroizing<String>, String> {
        let value = self.inner.resolve(reference)?;
        if reference.id == self.issuer.id {
            self.store
                .put_secret(&self.issuer.id, Some(&self.workspace), &self.issuer.label, "http://changed-issuer-canary.test/token")
                .map_err(|error| error.to_string())?;
        }
        Ok(value)
    }

    fn variable_secret(&self, layer: usize, variable: usize) -> Option<SecretRef> {
        self.inner.variable_secret(layer, variable)
    }
}

fn row(ctx: &mut ExecutionContext, name: &str, value: &str) {
    ctx.var_layers.push(VarLayer {
        label: "dataset".into(),
        vars: vec![VarEntry { name: name.into(), value: value.into(), secret: false, literal: false }],
    });
}

async fn send(ctx: &ExecutionContext) -> ExecutionOutput {
    tokio::time::timeout(Duration::from_secs(5), Engine::new().execute(ctx, EventCtx::none(), CancellationToken::new()))
        .await
        .expect("loopback execution completes")
}

struct Recorder {
    address: SocketAddr,
    requests: Arc<Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Recorder {
    async fn start(socks: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = requests.clone();
        let task = tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let recorded = recorded.clone();
                tokio::spawn(async move {
                    if socks {
                        record_socks(socket, recorded).await;
                    } else {
                        record_http(socket, recorded).await;
                    }
                });
            }
        });
        Self { address, requests, task }
    }

    fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.address)
    }
}

impl Drop for Recorder {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn record_http(mut socket: TcpStream, requests: Arc<Mutex<Vec<String>>>) {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() > 16 * 1024 || socket.read_exact(&mut byte).await.is_err() {
            return;
        }
        head.push(byte[0]);
    }
    let text = String::from_utf8(head).unwrap();
    let line = text.lines().next().unwrap().to_string();
    let length = text.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("content-length").then(|| value.trim().parse::<usize>().unwrap())
    });
    if let Some(length) = length {
        socket.read_exact(&mut vec![0; length]).await.unwrap();
    }
    requests.lock().unwrap().push(line.clone());
    let (status, body) = if line.starts_with("CONNECT ") {
        ("403 Forbidden", "")
    } else {
        ("200 OK", r#"{"access_token":"fixture-token","token_type":"Bearer","expires_in":3600}"#)
    };
    let response = format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len(),);
    socket.write_all(response.as_bytes()).await.unwrap();
}

async fn record_socks(mut socket: TcpStream, requests: Arc<Mutex<Vec<String>>>) {
    let mut greeting = [0; 3];
    socket.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [5, 1, 0]);
    socket.write_all(&[5, 0]).await.unwrap();
    let mut head = [0; 4];
    socket.read_exact(&mut head).await.unwrap();
    assert_eq!(head, [5, 1, 0, 3], "target must remain a proxy-resolved name");
    let length = socket.read_u8().await.unwrap();
    let mut host = vec![0; length as usize];
    socket.read_exact(&mut host).await.unwrap();
    let port = socket.read_u16().await.unwrap();
    requests.lock().unwrap().push(format!("{}:{port}", String::from_utf8(host).unwrap()));
    socket.write_all(&[5, 2, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
}

#[tokio::test]
async fn nested_oauth_conflicts_are_refused_before_any_issuer_is_contacted() {
    anvil_transport::init();
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let ws = app.create_workspace("OAuth conflicts").unwrap().meta.id;
    let first = Recorder::start(false).await;
    let second = Recorder::start(false).await;
    let dataset = app.create_dataset(&ws, "issuer", DatasetFormat::Csv, b"issuer\n127.0.0.1\n", vec![]).unwrap();
    let mut spec = RequestSpec::http("GET", &first.url("/api"));
    spec.auth = AuthConfig::Multi {
        profiles: vec![
            oauth(&first.url("/token")),
            AuthConfig::Multi {
                profiles: vec![AuthConfig::None, oauth(&format!("http://{{{{issuer}}}}:{}/token", second.address.port()))],
            },
        ],
    };
    let mut p = plan(&app, ws, spec);
    p.dataset_id = Some(dataset.meta.id);
    let error = app.load_preflight(&p).unwrap_err().to_string();
    assert!(error.contains("one OAuth 2 profile"), "{error}");
    let mut ctx = context(&app, &p);
    row(&mut ctx, "issuer", "127.0.0.1");
    let output = send(&ctx).await;
    let failure = output.record.attempts.last().unwrap().failure.as_ref().unwrap();
    assert_eq!(failure.kind, FailureKind::AuthPreparationFailed);
    assert_eq!(output.record.outcome.dispatch, DispatchState::NotDispatched);
    assert!(first.requests().is_empty());
    assert!(second.requests().is_empty());
    let interactive_error =
        anvil_engine::oauth_http::interactive_oauth(&ctx).err().expect("interactive sign-in also refuses the conflicting profiles");
    assert!(interactive_error.message.contains("one OAuth 2 profile"));

    // Even identical OAuth profiles conflict on Authorization.
    let mut duplicate = RequestSpec::http("GET", &first.url("/api"));
    duplicate.auth = AuthConfig::Multi { profiles: vec![oauth(&first.url("/token")), oauth(&first.url("/token"))] };
    let p = plan(&app, ws, duplicate);
    assert!(app.load_preflight(&p).is_err());
    assert_eq!(send(&context(&app, &p)).await.record.outcome.dispatch, DispatchState::NotDispatched,);
    assert!(first.requests().is_empty());

    // A nested single OAuth plus a separate API key keeps its valid behavior.
    let mut valid = RequestSpec::http("GET", &first.url("/api"));
    valid.auth = AuthConfig::Multi {
        profiles: vec![
            AuthConfig::ApiKey { name: "X-API-Key".into(), value: SensitiveValue::template("fixture-key"), location: KeyLocation::Header },
            AuthConfig::Multi { profiles: vec![oauth(&first.url("/token"))] },
        ],
    };
    let p = plan(&app, ws, valid);
    assert!(!warns(&app, &p));
    assert_eq!(send(&context(&app, &p)).await.record.response.unwrap().status, 200);
    assert_eq!(first.requests(), ["POST /token HTTP/1.1", "GET /api HTTP/1.1"]);
    assert!(second.requests().is_empty());
}

#[tokio::test]
async fn proxy_resolved_names_ignore_client_pins_including_oauth_and_no_proxy() {
    anvil_transport::init();
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let ws = app.create_workspace("Proxy names").unwrap().meta.id;
    pin(&app, ws, "api.example.test", &["127.0.0.1"]);
    pin(&app, ws, "issuer.example.test", &["127.0.0.1"]);
    let api = Recorder::start(false).await;
    for (kind, scheme) in [(ProxyKind::Http, "http"), (ProxyKind::Http, "https"), (ProxyKind::Socks5, "http")] {
        let recorder = Recorder::start(kind == ProxyKind::Socks5).await;
        let profile = proxy(&app, ws, kind, &recorder.address.to_string(), "");
        let url = format!("{scheme}://api.example.test:{}/api", api.address.port());
        let p = plan(&app, ws, routed(RequestSpec::http("GET", &url), &profile));
        assert!(warns(&app, &p), "{kind:?} {scheme}");
        let _ = send(&context(&app, &p)).await;
        let expected = match (kind, scheme) {
            (ProxyKind::Socks5, _) => format!("api.example.test:{}", api.address.port()),
            (_, "https") => format!("CONNECT api.example.test:{} HTTP/1.1", api.address.port()),
            _ => format!("GET {url} HTTP/1.1"),
        };
        assert_eq!(recorder.requests(), [expected]);

        // Only the token request uses the proxy; the literal API target bypasses it.
        let profile = proxy(&app, ws, kind, &recorder.address.to_string(), "127.0.0.1");
        let token_url = format!("{scheme}://issuer.example.test:{}/token", api.address.port());
        let mut spec = routed(RequestSpec::http("GET", &api.url("/api")), &profile);
        spec.auth = oauth(&token_url);
        let p = plan(&app, ws, spec.clone());
        let before = recorder.requests().len();
        let api_before = api.requests().len();
        if scheme == "http" {
            assert!(app.load_preflight(&p).unwrap_err().to_string().contains("HTTPS or literal-loopback HTTP"));
            let o = send(&context(&app, &p)).await;
            assert_eq!(o.record.outcome.dispatch, DispatchState::NotDispatched);
            assert_eq!(recorder.requests().len(), before, "ineligible token URL never reaches the proxy");
            assert_eq!(api.requests().len(), api_before);
        } else {
            assert!(warns(&app, &p));
            let _ = send(&context(&app, &p)).await;
            assert!(recorder.requests().last().unwrap().contains("issuer.example.test"));
        }

        // Port-free NO_PROXY makes the same fixed pin authoritative on the client.
        let bypass = proxy(&app, ws, kind, &recorder.address.to_string(), "127.0.0.1,api.example.test,issuer.example.test");
        // A literal-loopback HTTP issuer is eligible and bypasses the proxy.
        spec = routed(RequestSpec::http("GET", &api.url("/api")), &bypass);
        spec.auth = oauth(&api.url("/token"));
        let p = plan(&app, ws, spec);
        assert!(!warns(&app, &p));
        let before = recorder.requests().len();
        assert_eq!(send(&context(&app, &p)).await.record.response.unwrap().status, 200);
        assert_eq!(recorder.requests().len(), before);
        let direct =
            plan(&app, ws, routed(RequestSpec::http("GET", &format!("http://api.example.test:{}/api", api.address.port())), &bypass));
        assert!(!warns(&app, &direct));
        assert_eq!(send(&context(&app, &direct)).await.record.response.unwrap().status, 200);
        assert_eq!(recorder.requests().len(), before);
    }
}

#[tokio::test]
async fn oauth_preflight_rejects_cleartext_names_before_credentials_or_dispatch() {
    anvil_transport::init();
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let ws = app.create_workspace("Issuer eligibility").unwrap().meta.id;
    let credential = app.set_secret(&ws, "OAuth credential", "{{vault-canary}}").unwrap();
    let api = Recorder::start(false).await;
    let recorder = Recorder::start(false).await;
    let profile = proxy(&app, ws, ProxyKind::Http, &recorder.address.to_string(), "");
    for host in ["localhost", "issuer.example.test", "[::ffff:192.168.1.1]"] {
        pin(&app, ws, host, &["127.0.0.1"]);
        for proxied in [false, true] {
            let mut spec = RequestSpec::http("GET", &api.url("/api"));
            spec.auth = oauth(&format!("http://{host}:{}/token?hidden=endpoint-material", api.address.port()));
            if let AuthConfig::OAuth2 { config } = &mut spec.auth {
                config.client_id = "{{missing_client_id}}".into();
                config.client_secret = SensitiveValue::Secret { secret: credential.clone() };
            }
            if proxied {
                spec = routed(spec, &profile);
            }
            let p = plan(&app, ws, spec);
            let error = app.load_preflight(&p).unwrap_err().to_string();
            assert!(error.contains("HTTPS or literal-loopback HTTP"));
            assert!(!error.contains("endpoint-material"));
            assert!(!error.contains("missing_client"));
            assert!(!error.contains("vault-canary"));
            let o = send(&context(&app, &p)).await;
            assert_eq!(o.record.outcome.dispatch, DispatchState::NotDispatched);
            assert_eq!(o.record.attempts.last().unwrap().failure.as_ref().unwrap().kind, FailureKind::AuthPreparationFailed);
            assert!(!serde_json::to_string(&o.record).unwrap().contains("vault-canary"));
            assert!(api.requests().is_empty());
            assert!(recorder.requests().is_empty());
        }
    }
}

#[tokio::test]
async fn literal_loopback_cleartext_issuers_through_a_proxy_are_refused_before_credentials_or_traffic() {
    anvil_transport::init();
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let ws = app.create_workspace("Proxied loopback issuer").unwrap().meta.id;
    let credential = app.set_secret(&ws, "OAuth credential", "vault-canary").unwrap();
    let api = Recorder::start(false).await;
    let recorder = Recorder::start(false).await;
    // NO_PROXY entries for another host or port do not bypass the issuer.
    for no_proxy in ["", "issuer.example.test", "127.0.0.1:1,[::1]:1"] {
        let profile = proxy(&app, ws, ProxyKind::Http, &recorder.address.to_string(), no_proxy);
        for endpoint in [api.url("/token"), format!("http://[::1]:{}/token", api.address.port())] {
            let mut spec = routed(RequestSpec::http("GET", &api.url("/api")), &profile);
            spec.auth = oauth(&endpoint);
            if let AuthConfig::OAuth2 { config } = &mut spec.auth {
                config.client_secret = SensitiveValue::Secret { secret: credential.clone() };
            }
            let p = plan(&app, ws, spec);
            let error = app.load_preflight(&p).unwrap_err().to_string();
            assert!(error.contains("direct connection"), "{error}");
            assert!(!error.contains("vault-canary"));
            let o = send(&context(&app, &p)).await;
            assert_eq!(o.record.outcome.dispatch, DispatchState::NotDispatched);
            let failure = o.record.attempts.last().unwrap().failure.clone().unwrap();
            assert_eq!(failure.kind, FailureKind::AuthPreparationFailed);
            assert!(failure.message.contains("direct connection"), "{}", failure.message);
            assert!(!serde_json::to_string(&o.record).unwrap().contains("vault-canary"));
        }
    }
    assert!(api.requests().is_empty());
    assert!(recorder.requests().is_empty(), "the proxy received nothing");
    // A NO_PROXY bypass keeps the cleartext token request on this machine.
    let bypass = proxy(&app, ws, ProxyKind::Http, &recorder.address.to_string(), "127.0.0.1");
    let mut spec = routed(RequestSpec::http("GET", &api.url("/api")), &bypass);
    spec.auth = oauth(&api.url("/token"));
    let p = plan(&app, ws, spec);
    assert!(!warns(&app, &p));
    assert_eq!(send(&context(&app, &p)).await.record.response.unwrap().status, 200);
    assert!(recorder.requests().is_empty());
}

#[test]
fn oauth_vault_prefetch_requires_a_fixed_validated_endpoint_for_every_grant_and_scope() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let mut ws = app.create_workspace("Credential ordering").unwrap();
    ws.variables.push(anvil_domain::workspace::Variable::plain("issuer", "http://127.0.0.1:8080/token"));
    app.save_workspace(ws.clone()).unwrap();
    for grant in [OAuthGrant::ClientCredentials, OAuthGrant::RefreshToken, OAuthGrant::AuthorizationCodePkce] {
        for (endpoint, prefetched) in [
            ("http://127.0.0.1:8080/token", true),
            ("https://issuer.example.test/token", true),
            ("http://issuer.example.test/token", false),
            ("http://[::ffff:192.168.1.1]/token", false),
            ("{{issuer}}", false),
        ] {
            for inherited in [false, true] {
                let secret = app.set_secret(&ws.meta.id, "OAuth credential", "original-vault-value").unwrap();
                let mut auth = oauth(endpoint);
                if let AuthConfig::OAuth2 { config } = &mut auth {
                    config.grant = grant;
                    config.authorization_url = "http://127.0.0.1:8080/authorize".into();
                    config.client_secret = SensitiveValue::Secret { secret: secret.clone() };
                }
                // Exercise both the spec's duplicate reference and inherited,
                // nested effective auth. Neither may bypass the prefetch gate.
                let nested = AuthConfig::Multi { profiles: vec![AuthConfig::Multi { profiles: vec![auth] }] };
                let mut spec = RequestSpec::http("GET", "http://127.0.0.1:8080/api");
                spec.auth = if inherited {
                    ws.auth = nested;
                    app.save_workspace(ws.clone()).unwrap();
                    AuthConfig::Inherit
                } else {
                    nested
                };
                let p = plan(&app, ws.meta.id, spec);
                let ctx = context(&app, &p);
                // A genuinely prefetched vault value survives deletion from
                // storage. A deferred reference must consult the real vault.
                app.store.delete_secret(&secret.id).unwrap();
                let resolved = ctx.secrets.resolve(&secret);
                if prefetched {
                    assert_eq!(resolved.unwrap().as_str(), "original-vault-value");
                } else {
                    assert!(resolved.is_err(), "unvalidated credential was prefetched: {endpoint}");
                }
            }
        }
    }
    // A literal-loopback cleartext issuer is ineligible through a proxy.
    let profile = proxy(&app, ws.meta.id, ProxyKind::Http, "127.0.0.1:3128", "");
    let secret = app.set_secret(&ws.meta.id, "OAuth credential", "original-vault-value").unwrap();
    let mut spec = routed(RequestSpec::http("GET", "http://127.0.0.1:8080/api"), &profile);
    spec.auth = oauth("http://127.0.0.1:8080/token");
    if let AuthConfig::OAuth2 { config } = &mut spec.auth {
        config.client_secret = SensitiveValue::Secret { secret: secret.clone() };
    }
    let ctx = context(&app, &plan(&app, ws.meta.id, spec));
    app.store.delete_secret(&secret.id).unwrap();
    assert!(ctx.secrets.resolve(&secret).is_err(), "a proxied cleartext credential was prefetched");
}

#[tokio::test]
async fn templated_eligible_oauth_endpoint_still_acquires_a_vault_backed_credential() {
    anvil_transport::init();
    anvil_fixtures::init();
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let mut ws = app.create_workspace("Deferred eligible issuer").unwrap();
    let api = anvil_fixtures::http::serve("127.0.0.1:0", None).await.unwrap();
    ws.variables.push(anvil_domain::workspace::Variable::plain("issuer", &api.url("/oauth/token")));
    app.save_workspace(ws.clone()).unwrap();
    let secret = app.set_secret(&ws.meta.id, "OAuth credential", "anvil-secret").unwrap();
    let mut spec = RequestSpec::http("GET", &api.url("/echo"));
    spec.auth = oauth("{{issuer}}");
    if let AuthConfig::OAuth2 { config } = &mut spec.auth {
        config.client_id = "anvil-client".into();
        config.client_auth = OAuthClientAuth::BasicHeader;
        config.client_secret = SensitiveValue::Secret { secret };
    }
    let p = plan(&app, ws.meta.id, spec);
    assert!(!warns(&app, &p));
    let output = send(&context(&app, &p)).await;
    assert_eq!(output.record.response.unwrap().status, 200);
    assert_eq!(*api.state.oauth_token_requests.lock(), 1);
    assert_eq!(api.log.requests(), [("POST".into(), "/oauth/token".into()), ("GET".into(), "/echo".into())]);
}

#[test]
fn oauth_endpoint_expansion_errors_do_not_expose_vault_derived_variable_names() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let mut ws = app.create_workspace("Endpoint errors").unwrap();
    let secret = app.set_secret(&ws.meta.id, "Issuer URL", "{{vault-canary}}").unwrap();
    ws.variables.push(anvil_domain::workspace::Variable {
        name: "issuer".into(),
        value: SensitiveValue::Secret { secret },
        secret: true,
        enabled: true,
        description: String::new(),
    });
    app.save_workspace(ws.clone()).unwrap();
    let mut spec = RequestSpec::http("GET", "http://127.0.0.1:8080/api");
    spec.auth = oauth("{{issuer}}");
    let p = plan(&app, ws.meta.id, spec);
    let error = app.load_preflight(&p).unwrap_err().to_string();
    assert_eq!(error, "could not resolve OAuth token URL; check the vault and active variables");
    assert!(!error.contains("vault-canary"));
}

#[tokio::test]
async fn app_and_worker_producer_check_ineligible_issuers_before_nested_vault_variables_and_aliases() {
    anvil_transport::init();
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let mut ws = app.create_workspace("Credential variables").unwrap();
    let expected = "the OAuth token endpoint requires HTTPS or literal-loopback HTTP";
    for grant in [OAuthGrant::ClientCredentials, OAuthGrant::RefreshToken, OAuthGrant::AuthorizationCodePkce] {
        for endpoint_source in ["literal", "template", "vault"] {
            for missing in [false, true] {
                let credential = app.set_secret(&ws.meta.id, "credential-label-canary", "{{credential-value-canary}}").unwrap();
                let endpoint = "http://issuer.example.test/token";
                let issuer = app.set_secret(&ws.meta.id, "issuer", endpoint).unwrap();
                ws.variables = vec![
                    vault_variable("oauth_secret", &credential),
                    Variable::plain("nested_credential", "{{oauth_secret}}"),
                    Variable::plain("credential_cycle", "{{credential_cycle}}"),
                    Variable::plain("issuer", "{{issuer_value}}"),
                    if endpoint_source == "vault" {
                        vault_variable("issuer_value", &issuer)
                    } else {
                        Variable::plain("issuer_value", endpoint)
                    },
                ];
                app.save_workspace(ws.clone()).unwrap();
                if missing {
                    app.store.delete_secret(&credential.id).unwrap();
                }
                let mut spec = RequestSpec::http("GET", "http://127.0.0.1:8080/api");
                // HTTP preparation and an earlier mixed-auth profile must not
                // materialize aliases of the credential before the OAuth gate.
                spec.headers.push(KeyValue::new("X-Credential", "{{nested_credential}}"));
                let mut auth = oauth(if endpoint_source == "literal" { endpoint } else { "{{issuer}}" });
                if let AuthConfig::OAuth2 { config } = &mut auth {
                    config.grant = grant;
                    config.client_id = "{{missing-client-canary}}".into();
                    config.client_secret = SensitiveValue::template("{{nested_credential}}{{credential_cycle}}");
                    config.authorization_url = "http://127.0.0.1:8080/authorize".into();
                }
                spec.auth = AuthConfig::Multi {
                    profiles: vec![
                        AuthConfig::ApiKey {
                            name: "X-API-Key".into(),
                            value: SensitiveValue::Secret { secret: credential.clone() },
                            location: KeyLocation::Header,
                        },
                        auth,
                    ],
                };
                let p = plan(&app, ws.meta.id, spec);
                let mut job = app.load_job(&p).expect("context defers unvalidated credential variables");
                let ctx = job.requests.get_mut(&p.chain[0]).unwrap();
                assert!(ctx.secrets.variable_secret(0, 0).is_some(), "the credential reference is retained");
                // Deletion exposes any eager prefetch, including a duplicate
                // direct reference through the spec or mixed effective auth.
                app.store.delete_secret(&credential.id).unwrap();
                assert!(ctx.secrets.resolve(&credential).is_err(), "credential was prefetched before eligibility");
                let reads = Arc::new(Mutex::new(Vec::new()));
                ctx.secrets = Arc::new(CountedSecrets { inner: ctx.secrets.clone(), reads: reads.clone() });
                let output = send(ctx).await;
                assert_eq!(output.record.outcome.dispatch, DispatchState::NotDispatched);
                assert_eq!(output.record.attempts[0].failure.as_ref().unwrap().message, expected);
                assert!(!serde_json::to_string(&output.record).unwrap().contains("canary"));
                let error = anvil_load::WorkerJob::from_load_job(&p, &job, anvil_load::RunOptions::default()).unwrap_err();
                assert_eq!(error.to_string(), format!("invalid load plan: {expected}"));
                assert!(!error.to_string().contains("canary"), "no wire job or credential-bearing error is produced");
                assert!(!reads.lock().unwrap().contains(&credential.id), "neither production sink read the credential");
                assert_eq!(app.load_preflight(&p).unwrap_err().to_string(), expected);
                assert_eq!(app.worker_job(&p, true).unwrap_err().to_string(), format!("invalid load plan: {expected}"));
                assert_eq!(
                    app.oauth_token_status(Some(p.chain[0]), &ws.meta.id, None, &anvil_app::exec::SendOptions::default())
                        .unwrap_err()
                        .to_string(),
                    expected,
                );
            }
        }
    }
}

#[tokio::test]
async fn app_worker_round_trip_preserves_eligible_vault_issuers_and_credential_variables() {
    anvil_transport::init();
    anvil_fixtures::init();
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let mut ws = app.create_workspace("Eligible credential variables").unwrap();
    for https in [false, true] {
        let pki = anvil_fixtures::LabPki::generate();
        let tls = https.then(|| anvil_fixtures::TlsServerOptions::new(pki.server.chain_with(&pki.ca), pki.server.key.clone()));
        let api = anvil_fixtures::http::serve("127.0.0.1:0", tls).await.unwrap();
        let endpoint = if https { api.url_host("api.anvil.test", "/oauth/token") } else { api.url("/oauth/token") };
        let trust = app
            .save_tls_profile(anvil_domain::tls::TlsProfile {
                id: Id::new(),
                workspace_id: ws.meta.id,
                name: "issuer trust".into(),
                verify: true,
                use_system_roots: false,
                extra_roots_pem: vec![pki.ca.cert.clone()],
                client_identity: None,
                bindings: vec![],
                min_version: anvil_domain::tls::TlsMinVersion::Tls12,
                server_name_override: None,
                server_spiffe: None,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            })
            .unwrap();
        for variable_credential in [false, true] {
            let credential = app.set_secret(&ws.meta.id, "client secret", "anvil-secret").unwrap();
            let issuer = app.set_secret(&ws.meta.id, "issuer URL", &endpoint).unwrap();
            ws.variables = vec![
                vault_variable("issuer_value", &issuer),
                Variable::plain("issuer", "{{issuer_value}}"),
                vault_variable("oauth_secret", &credential),
                Variable::plain("nested_credential", "{{oauth_secret}}"),
            ];
            ws.settings.tls_profile_id = Some(trust.id);
            ws.settings.dns_overrides = vec![DnsOverride { host: "api.anvil.test".into(), addresses: vec!["127.0.0.1".into()] }];
            app.save_workspace(ws.clone()).unwrap();
            let mut spec = RequestSpec::http("GET", &api.url("/echo"));
            spec.auth = oauth("{{issuer}}");
            if let AuthConfig::OAuth2 { config } = &mut spec.auth {
                config.client_id = "anvil-client".into();
                config.client_auth = OAuthClientAuth::BasicHeader;
                config.client_secret = if variable_credential {
                    SensitiveValue::template("{{nested_credential}}")
                } else {
                    SensitiveValue::Secret { secret: credential.clone() }
                };
            }
            let p = plan(&app, ws.meta.id, spec);
            let preflight = app.load_preflight(&p).unwrap();
            assert_eq!(preflight.destinations.len(), 2);
            assert_eq!(send(&context(&app, &p)).await.record.response.unwrap().status, 200);
            let wire = app.worker_job(&p, true).unwrap();
            let json = serde_json::to_string(&wire).unwrap();
            let wire: anvil_load::WorkerJob = serde_json::from_str(&json).unwrap();
            assert!(!format!("{wire:?}").contains("anvil-secret"));
            app.store.delete_secret(&credential.id).unwrap();
            app.store.delete_secret(&issuer.id).unwrap();
            let (plan, job, options) = wire.into_load_job().unwrap();
            let report = tokio::time::timeout(
                Duration::from_secs(10),
                anvil_load::LoadRun::prepare(plan, job, options).unwrap().execute(CancellationToken::new(), None),
            )
            .await
            .expect("worker acquisition completes against the loopback fixture");
            assert_eq!(report.counts.completed, 1);
            assert_eq!(report.counts.transport_failures, 0);
            assert_eq!(report.counts.application_failures, 0);
        }
        // Per-run paths and literal-loopback ports remain supported, even
        // when their templates are reached through a vault-backed issuer.
        let credential = app.set_secret(&ws.meta.id, "dataset client secret", "anvil-secret").unwrap();
        let scheme = if https { "https" } else { "http" };
        let issuer = app
            .set_secret(&ws.meta.id, "dataset issuer", &format!("{scheme}://127.0.0.1:{{{{port}}}}/oauth/token?row={{{{row}}}}"))
            .unwrap();
        ws.variables = vec![vault_variable("issuer", &issuer), vault_variable("oauth_secret", &credential)];
        app.save_workspace(ws.clone()).unwrap();
        let dataset = app
            .create_dataset(
                &ws.meta.id,
                "issuer path",
                DatasetFormat::Csv,
                format!("port,row\n{},one\n", api.addr.port()).as_bytes(),
                vec![],
            )
            .unwrap();
        let mut spec = RequestSpec::http("GET", &api.url("/echo"));
        spec.auth = oauth("{{issuer}}");
        if let AuthConfig::OAuth2 { config } = &mut spec.auth {
            config.client_id = "anvil-client".into();
            config.client_auth = OAuthClientAuth::BasicHeader;
            config.client_secret = SensitiveValue::template("{{oauth_secret}}");
        }
        let mut p = plan(&app, ws.meta.id, spec);
        p.dataset_id = Some(dataset.meta.id);
        assert!(app.load_preflight(&p).is_ok());
        let wire = app.worker_job(&p, true).unwrap();
        let (plan, job, options) = wire.into_load_job().unwrap();
        let report = tokio::time::timeout(
            Duration::from_secs(10),
            anvil_load::LoadRun::prepare(plan, job, options).unwrap().execute(CancellationToken::new(), None),
        )
        .await
        .expect("dataset issuer acquisition completes");
        assert_eq!(report.counts.completed, 1);
        assert_eq!(report.counts.transport_failures, 0);
        assert_eq!(*api.state.oauth_token_requests.lock(), 5);
        api.shutdown();
    }
}

#[test]
fn worker_producer_masks_helpers_inside_vault_issuers_and_sanitizes_missing_credentials() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let mut ws = app.create_workspace("Producer eligibility").unwrap();
    let credential = app.set_secret(&ws.meta.id, "credential-label-canary", "credential-value-canary").unwrap();
    for issuer_value in
        ["{{$randomFrom http://127.0.0.1/token|http://issuer.example.test/token}}", "{{missing-issuer-canary}}", "{{issuer}}"]
    {
        let issuer = app.set_secret(&ws.meta.id, "issuer", issuer_value).unwrap();
        ws.variables = vec![vault_variable("issuer", &issuer), vault_variable("oauth_secret", &credential)];
        app.save_workspace(ws.clone()).unwrap();
        let mut spec = RequestSpec::http("GET", "http://127.0.0.1:8080/api");
        spec.auth = oauth("{{issuer}}");
        if let AuthConfig::OAuth2 { config } = &mut spec.auth {
            config.client_secret = SensitiveValue::Secret { secret: credential.clone() };
        }
        let p = plan(&app, ws.meta.id, spec);
        let mut job = app.load_job(&p).unwrap();
        let ctx = job.requests.get_mut(&p.chain[0]).unwrap();
        let reads = Arc::new(Mutex::new(Vec::new()));
        ctx.secrets = Arc::new(CountedSecrets { inner: ctx.secrets.clone(), reads: reads.clone() });
        let error = anvil_load::WorkerJob::from_load_job(&p, &job, anvil_load::RunOptions::default()).unwrap_err().to_string();
        assert!(!error.contains("canary"));
        let message = error.strip_prefix("invalid load plan: ").unwrap();
        assert!(message.contains("per-run values") || message == "could not resolve auth.token_url; check the vault and active variables");
        assert!(!reads.lock().unwrap().contains(&credential.id));
    }
    app.store.delete_secret(&credential.id).unwrap();
    for direct in [false, true] {
        ws.variables = vec![Variable::plain("issuer", "https://issuer.example.test/token"), vault_variable("oauth_secret", &credential)];
        app.save_workspace(ws.clone()).unwrap();
        let mut spec = RequestSpec::http("GET", "http://127.0.0.1:8080/api");
        spec.auth = oauth("{{issuer}}");
        if let AuthConfig::OAuth2 { config } = &mut spec.auth {
            config.client_secret =
                if direct { SensitiveValue::Secret { secret: credential.clone() } } else { SensitiveValue::template("{{oauth_secret}}") };
        }
        let p = plan(&app, ws.meta.id, spec);
        assert!(app.load_preflight(&p).is_ok(), "preflight validates eligibility without consuming credentials");
        let error = app.worker_job(&p, true).unwrap_err().to_string();
        assert_eq!(
            error,
            if direct {
                "invalid load plan: could not resolve a load credential; check the vault and active variables"
            } else {
                "invalid load plan: could not resolve a load variable; check the vault and active variables"
            },
        );
        assert!(!error.contains("canary"));
    }
}

#[test]
fn ordinary_vault_variables_keep_their_snapshot_and_layer_errors_do_not_quote_names_or_labels() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let mut ws = app.create_workspace("Ordinary variables").unwrap();
    let secret = app.set_secret(&ws.meta.id, "ordinary vault value", "echo").unwrap();
    let missing = SecretRef { id: Id::new(), label: "missing-label-canary".into() };
    let mut disabled = vault_variable("disabled-name-canary", &missing);
    disabled.enabled = false;
    ws.variables = vec![vault_variable("path", &secret), disabled];
    app.save_workspace(ws.clone()).unwrap();
    let p = plan(&app, ws.meta.id, RequestSpec::http("GET", "http://127.0.0.1:8080/{{path}}"));
    let job = app.load_job(&p).unwrap();
    app.store.delete_secret(&secret.id).unwrap();
    let wire = anvil_load::WorkerJob::from_load_job(&p, &job, anvil_load::RunOptions::default()).unwrap();
    assert_eq!(wire.requests[0].var_layers[0].vars[0].value.expose(), "echo");
    assert!(wire.requests[0].var_layers[0].vars[0].secret);
    assert_eq!(wire.requests[0].var_layers[0].vars.len(), 1);
    ws.variables = vec![vault_variable("missing-name-canary", &missing)];
    app.save_workspace(ws).unwrap();
    let error = app.load_job(&p).err().unwrap().to_string();
    assert!(error.contains("could not resolve a secret variable"));
    assert!(!error.contains("canary"));
}

#[test]
fn worker_serializes_the_issuer_snapshot_that_passed_eligibility_even_if_the_vault_changes() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let mut ws = app.create_workspace("Issuer snapshot").unwrap();
    let issuer = app.set_secret(&ws.meta.id, "issuer", "https://issuer.example.test/token").unwrap();
    let credential = app.set_secret(&ws.meta.id, "client secret", "eligible-credential-canary").unwrap();
    ws.variables = vec![vault_variable("issuer", &issuer), vault_variable("oauth_secret", &credential)];
    app.save_workspace(ws.clone()).unwrap();
    let mut spec = RequestSpec::http("GET", "http://127.0.0.1:8080/api");
    spec.auth = oauth("{{issuer}}");
    if let AuthConfig::OAuth2 { config } = &mut spec.auth {
        config.client_secret = SensitiveValue::template("{{oauth_secret}}");
    }
    let p = plan(&app, ws.meta.id, spec);
    let mut job = app.load_job(&p).unwrap();
    let ctx = job.requests.get_mut(&p.chain[0]).unwrap();
    ctx.secrets = Arc::new(ReplaceIssuerAfterRead {
        inner: ctx.secrets.clone(),
        store: app.store.clone(),
        workspace: ws.meta.id,
        issuer: issuer.clone(),
    });
    let wire = anvil_load::WorkerJob::from_load_job(&p, &job, anvil_load::RunOptions::default()).unwrap();
    assert_eq!(wire.requests[0].var_layers[0].vars[0].value.expose(), "https://issuer.example.test/token");
    assert!(!serde_json::to_string(&wire).unwrap().contains("changed-issuer-canary"));
    assert_eq!(
        app.worker_job(&p, true).unwrap_err().to_string(),
        "invalid load plan: the OAuth token endpoint requires HTTPS or literal-loopback HTTP",
    );
}

#[test]
fn oauth_preflight_uses_the_common_canonical_literal_policy_and_keeps_consent() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let ws = app.create_workspace("Canonical issuers").unwrap().meta.id;
    for endpoint in [
        "http://127.0.0.1:8080/token",
        "http://127.1:8080/token",
        "http://[::1]:8080/token",
        "http://[::ffff:127.0.0.1]:8080/token",
        "https://issuer.example.test/token",
    ] {
        let mut spec = RequestSpec::http("GET", "http://127.0.0.1:8080/api");
        spec.auth = oauth(endpoint);
        let p = plan(&app, ws, spec);
        let preflight = app.load_preflight(&p).unwrap();
        assert_eq!(preflight.destinations.len(), 2);
        assert!(preflight.destinations[1].starts_with("OAuth token URL "));
        assert_eq!(warns(&app, &p), endpoint.starts_with("https"));
    }
}

#[tokio::test]
async fn effective_host_controls_forward_proxy_consent_and_wire_authority() {
    anvil_transport::init();
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let ws = app.create_workspace("Host authority").unwrap().meta.id;
    let recorder = Recorder::start(false).await;
    let profile = proxy(&app, ws, ProxyKind::Http, &recorder.address.to_string(), "");
    let environment = app
        .create_environment(&ws, "fixed Host", vec![anvil_domain::workspace::Variable::plain("fixed_host", "remote.example.test")])
        .unwrap();
    let dataset = app.create_dataset(&ws, "hosts", DatasetFormat::Csv, b"host,header\nremote.example.test,Host\n", vec![]).unwrap();
    for (name, value, auth) in [
        ("Host", "remote.example.test", false),
        ("Host", "{{fixed_host}}", false),
        ("hOsT", "{{host}}", false),
        ("{{header}}", "remote.example.test", false),
        ("Host", "remote.example.test", true),
        ("Host", "{{host}}", true),
        ("{{header}}", "remote.example.test", true),
    ] {
        let mut spec = routed(RequestSpec::http("GET", "http://127.0.0.1:8080/api"), &profile);
        if auth {
            spec.headers.push(KeyValue::new("Host", "127.0.0.1:8080"));
            spec.auth = AuthConfig::Multi {
                profiles: vec![AuthConfig::Multi {
                    profiles: vec![AuthConfig::ApiKey {
                        name: name.into(),
                        value: SensitiveValue::template(value),
                        location: KeyLocation::Header,
                    }],
                }],
            };
        } else {
            spec.headers.push(KeyValue::new(name, value));
        }
        let mut p = plan(&app, ws, spec);
        p.dataset_id = Some(dataset.meta.id);
        p.environment_id = Some(environment.meta.id);
        assert!(warns(&app, &p), "{name} {value} auth={auth}");
        let preflight = app.load_preflight(&p).unwrap();
        assert!(preflight.destinations[0].contains("Host authority"));
        assert!(!preflight.destinations[0].contains("remote.example.test"), "Host values stay private",);
        let mut ctx = context(&app, &p);
        row(&mut ctx, "host", "remote.example.test");
        row(&mut ctx, "header", "Host");
        assert_eq!(send(&ctx).await.record.response.unwrap().status, 200);
        assert_eq!(recorder.requests().last().unwrap(), "GET http://remote.example.test/api HTTP/1.1",);
    }

    // First configured Host wins; auth replaces it. Client overrides cannot
    // make a proxy-resolved Host local, nor may URL shorthand canonicalize it.
    for (first, second, auth, warning) in [
        ("127.0.0.1:8080", "remote.example.test", None, false),
        ("remote.example.test", "127.0.0.1:8080", None, true),
        ("remote.example.test", "remote.example.test", Some("127.0.0.1:8080"), false),
        ("127.0.0.1:8080", "127.0.0.1:8080", Some("127.1:8080"), true),
    ] {
        let mut spec = routed(RequestSpec::http("GET", "http://127.0.0.1:8080/api"), &profile);
        spec.headers = vec![KeyValue::new("Host", first), KeyValue::new("Host", second)];
        if let Some(value) = auth {
            spec.auth = AuthConfig::ApiKey { name: "Host".into(), value: SensitiveValue::template(value), location: KeyLocation::Header };
        }
        pin(&app, ws, "remote.example.test", &["127.0.0.1"]);
        pin(&app, ws, "127.1", &["127.0.0.1"]);
        let p = plan(&app, ws, spec);
        assert_eq!(warns(&app, &p), warning, "{first} {second} {auth:?}");
    }

    // A direct connection routes by its URL, so ordinary per-run Host remains valid.
    let bypass = proxy(&app, ws, ProxyKind::Http, &recorder.address.to_string(), "127.0.0.1");
    let mut spec = routed(RequestSpec::http("GET", "http://127.0.0.1:8080/api"), &bypass);
    spec.headers.push(KeyValue::new("Host", "{{host}}"));
    let mut p = plan(&app, ws, spec);
    p.dataset_id = Some(dataset.meta.id);
    assert!(!warns(&app, &p));
}

#[tokio::test]
async fn cleartext_forward_proxy_receives_the_authority_preflight_checks() {
    use anvil_domain::settings::HttpVersionPolicy;
    use anvil_fixtures::GroundTruth;
    anvil_transport::init();
    anvil_fixtures::init();
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let ws = app.create_workspace("HTTP proxy versions").unwrap().meta.id;
    // This HTTP/1.1 and h2c peer records requests and never forwards them.
    let recorder = anvil_fixtures::http::serve("127.0.0.1:0", None).await.unwrap();
    let profile = proxy(&app, ws, ProxyKind::Http, &recorder.addr.to_string(), "");
    let environment =
        app.create_environment(&ws, "fixed", vec![anvil_domain::workspace::Variable::plain("fixed_host", "remote.example.test")]).unwrap();
    let dataset = app.create_dataset(&ws, "hosts", DatasetFormat::Csv, b"host,header\nremote.example.test,Host\n", vec![]).unwrap();
    // The proxy receives names unchanged, despite client overrides.
    pin(&app, ws, "remote.example.test", &["127.0.0.1"]);
    for version in [HttpVersionPolicy::Auto, HttpVersionPolicy::Http1Only, HttpVersionPolicy::H2c, HttpVersionPolicy::Http3WithFallback] {
        for (name, value, auth, warning, expected) in [
            ("Host", "remote.example.test", false, true, "remote.example.test"),
            ("Host", "{{fixed_host}}", false, true, "remote.example.test"),
            ("hOsT", "{{host}}", false, true, "remote.example.test"),
            ("{{header}}", "remote.example.test", false, true, "remote.example.test"),
            ("Host", "remote.example.test", true, true, "remote.example.test"),
            ("Host", "{{host}}", true, true, "remote.example.test"),
            ("{{header}}", "remote.example.test", true, true, "remote.example.test"),
            ("Host", "127.0.0.1:8080", false, false, "127.0.0.1:8080"),
            ("Host", "127.0.0.1:8080", true, false, "127.0.0.1:8080"),
        ] {
            let mut spec = routed(RequestSpec::http("GET", "http://127.0.0.1:8080/echo"), &profile);
            spec.settings.http_version = Some(version);
            if auth {
                let initial = if warning { "127.0.0.1:8080" } else { "remote.example.test" };
                spec.headers.push(KeyValue::new("Host", initial));
                spec.auth = AuthConfig::ApiKey { name: name.into(), value: SensitiveValue::template(value), location: KeyLocation::Header };
            } else {
                spec.headers.push(KeyValue::new(name, value));
            }
            let mut p = plan(&app, ws, spec);
            p.dataset_id = Some(dataset.meta.id);
            p.environment_id = Some(environment.meta.id);
            assert_eq!(warns(&app, &p), warning, "{version:?} {name} {value} auth={auth}");
            let preflight = app.load_preflight(&p).unwrap();
            assert!(!preflight.destinations[0].contains("remote.example.test"), "Host values stay private");
            let mut ctx = context(&app, &p);
            row(&mut ctx, "host", "remote.example.test");
            row(&mut ctx, "header", "Host");
            let before = recorder.log.entries().len();
            let response = send(&ctx).await.record.response.unwrap();
            assert_eq!(response.status, 200);
            let protocol = if version == HttpVersionPolicy::H2c { "HTTP/2" } else { "HTTP/1.1" };
            assert_eq!(response.http_version, protocol);
            let authority = recorder.log.entries().into_iter().skip(before).rev().find_map(|entry| match entry.event {
                GroundTruth::AuthorityReceived { path, authority } if path == "/echo" => Some(authority),
                _ => None,
            });
            assert_eq!(authority.as_deref(), Some(expected), "{version:?}: proxy-received authority");
            assert!(
                !recorder
                    .log
                    .entries()
                    .iter()
                    .any(|entry| { matches!(&entry.event, GroundTruth::RequestReceived { method, .. } if method == "CONNECT") })
            );
        }
    }

    let direct = anvil_fixtures::http::serve("127.0.0.1:0", None).await.unwrap();
    let bypass = proxy(&app, ws, ProxyKind::Http, &recorder.addr.to_string(), "127.0.0.1");
    let mut spec = routed(RequestSpec::http("GET", &direct.url("/echo")), &bypass);
    spec.settings.http_version = Some(HttpVersionPolicy::H2c);
    spec.headers.push(KeyValue::new("Host", "{{host}}"));
    let mut p = plan(&app, ws, spec);
    p.dataset_id = Some(dataset.meta.id);
    assert!(!warns(&app, &p), "NO_PROXY routes by the URL, independently of Host");
    let before = recorder.log.entries().len();
    let mut ctx = context(&app, &p);
    row(&mut ctx, "host", "remote.example.test");
    assert_eq!(send(&ctx).await.record.response.unwrap().status, 200);
    assert_eq!(recorder.log.entries().len(), before);
    assert!(
        direct.log.entries().iter().any(|entry| {
            matches!(&entry.event, GroundTruth::AuthorityReceived { authority, .. } if authority == "remote.example.test")
        })
    );
}

#[tokio::test]
async fn cleartext_session_proxies_connect_to_the_url_target_instead_of_host() {
    use anvil_domain::request::{GrpcMode, GrpcSchemaSource, GrpcSpec, GrpcWire};
    use anvil_domain::settings::HttpVersionPolicy;
    anvil_transport::init();
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let ws = app.create_workspace("Session proxy routing").unwrap().meta.id;
    let recorder = Recorder::start(false).await;
    let profile = proxy(&app, ws, ProxyKind::Http, &recorder.address.to_string(), "");
    let proto = app.put_attachment("echo.proto", anvil_fixtures::grpc::ECHO_PROTO.as_bytes(), None).unwrap();
    for (protocol, wire, version) in [
        (Protocol::Sse, GrpcWire::Grpc, HttpVersionPolicy::Http1Only),
        (Protocol::Sse, GrpcWire::Grpc, HttpVersionPolicy::H2c),
        (Protocol::WebSocket, GrpcWire::Grpc, HttpVersionPolicy::Auto),
        (Protocol::Grpc, GrpcWire::Grpc, HttpVersionPolicy::Auto),
        (Protocol::Grpc, GrpcWire::GrpcWeb, HttpVersionPolicy::Http1Only),
        (Protocol::Grpc, GrpcWire::GrpcWeb, HttpVersionPolicy::H2c),
        (Protocol::Grpc, GrpcWire::GrpcWebText, HttpVersionPolicy::Http1Only),
        (Protocol::Grpc, GrpcWire::GrpcWebText, HttpVersionPolicy::H2c),
    ] {
        let scheme = if protocol == Protocol::WebSocket { "ws" } else { "http" };
        let mut spec = routed(RequestSpec::http("GET", &format!("{scheme}://127.0.0.1:8080/")), &profile);
        spec.protocol = protocol;
        spec.settings.http_version = Some(version);
        spec.headers.push(KeyValue::new("Host", "remote.example.test"));
        if protocol == Protocol::Grpc {
            spec.grpc = Some(GrpcSpec {
                service: "anvil.lab.v1.Echo".into(),
                method: "Unary".into(),
                mode: GrpcMode::Unary,
                schema: GrpcSchemaSource::ProtoFiles { files: vec![proto.clone()] },
                messages: vec!["{}".into()],
                metadata: vec![],
                deadline_ms: None,
                plaintext: false,
                wire,
            });
        }
        let p = plan(&app, ws, spec);
        assert!(!warns(&app, &p), "{protocol:?} {wire:?} {version:?}: CONNECT fixes the target");
        let before = recorder.requests().len();
        let output = send(&context(&app, &p)).await;
        assert_eq!(recorder.requests().len(), before + 1, "{protocol:?} {wire:?} {version:?}");
        assert_eq!(recorder.requests().last().unwrap(), "CONNECT 127.0.0.1:8080 HTTP/1.1");
        assert!(output.record.attempts.last().unwrap().failure.is_some(), "recording proxy refuses the tunnel");
    }
}

#[tokio::test]
async fn masque_locality_checks_the_template_and_records_the_actual_connect_udp_path() {
    use anvil_domain::request::{MASQUE_DEFAULT_TEMPLATE, MasqueSpec, PayloadEncoding, StreamPayload, UdpSpec};
    use anvil_domain::tls::TlsProfile;
    use anvil_fixtures::h3server::{self, H3Options};
    use anvil_fixtures::{GroundTruth, LabPki, TlsServerOptions};
    anvil_transport::init();
    anvil_fixtures::init();
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let ws = app.create_workspace("MASQUE routing templates").unwrap().meta.id;
    let pki = LabPki::generate();
    // Record CONNECT-UDP, then refuse before resolving or relaying any target.
    let recorder = h3server::serve_with(
        "127.0.0.1:0",
        TlsServerOptions::new(pki.server.chain_with(&pki.ca), pki.server.key.clone()),
        H3Options { connect_udp: false, ..Default::default() },
    )
    .await
    .unwrap();
    let tls = app
        .save_tls_profile(TlsProfile {
            id: Id::new(),
            workspace_id: ws,
            name: "MASQUE fixture".into(),
            verify: true,
            use_system_roots: false,
            extra_roots_pem: vec![pki.ca.cert.clone()],
            client_identity: None,
            bindings: vec![],
            min_version: Default::default(),
            server_name_override: None,
            server_spiffe: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        })
        .unwrap();
    let environment = app
        .create_environment(&ws, "canonical", vec![anvil_domain::workspace::Variable::plain("canonical", MASQUE_DEFAULT_TEMPLATE)])
        .unwrap();
    let dataset =
        app.create_dataset(&ws, "route", DatasetFormat::Csv, b"relay_host,template\nremote.example.test,unused\n", vec![]).unwrap();
    let custom = "/.well-known/masque/udp/remote.example.test/{target_port}/?original={target_host}";
    let varying = "/.well-known/masque/udp/{{relay_host}}/{target_port}/?original={target_host}";
    let canonical_path = "/.well-known/masque/udp/127.0.0.1/9/";
    let custom_path = "/.well-known/masque/udp/remote.example.test/9/?original=127.0.0.1";
    for dtls in [false, true] {
        for (template, dataset_driven, warning, expected) in [
            (MASQUE_DEFAULT_TEMPLATE, false, false, canonical_path),
            ("{{canonical}}", false, false, canonical_path),
            (custom, false, true, custom_path),
            (varying, true, true, custom_path),
            ("{{template}}", true, true, canonical_path),
            (
                "/.well-known/masque/udp/{target_host}/{target_port}/?local=true",
                false,
                true,
                "/.well-known/masque/udp/127.0.0.1/9/?local=true",
            ),
        ] {
            let scheme = if dtls { "dtls" } else { "udp" };
            let mut spec = RequestSpec::http("GET", &format!("{scheme}://127.0.0.1:9/"));
            spec.protocol = Protocol::Udp;
            spec.settings.tls_profile_id = Some(tls.id);
            spec.udp = Some(UdpSpec {
                dtls,
                datagrams: vec![StreamPayload { data: "never relayed".into(), encoding: PayloadEncoding::Text }],
                response_window_ms: 100,
                max_datagrams: 1,
                masque: Some(MasqueSpec { proxy_url: recorder.url(""), uri_template: template.into(), datagrams: Default::default() }),
                proxy_protocol: None,
            });
            let mut p = plan(&app, ws, spec);
            p.environment_id = Some(environment.meta.id);
            p.dataset_id = dataset_driven.then_some(dataset.meta.id);
            assert_eq!(warns(&app, &p), warning, "dtls={dtls} {template}");
            let preflight = app.load_preflight(&p).unwrap();
            assert_eq!(preflight.destinations[0].contains("MASQUE routing template is unproven"), warning);
            assert!(!preflight.destinations[0].contains("remote.example.test"), "template values stay private");
            let before = recorder.log.entries().len();
            let mut ctx = context(&app, &p);
            if dataset_driven {
                row(&mut ctx, "relay_host", "remote.example.test");
                row(&mut ctx, "template", MASQUE_DEFAULT_TEMPLATE);
            }
            let output = send(&ctx).await;
            let requests: Vec<_> = recorder
                .log
                .entries()
                .into_iter()
                .skip(before)
                .filter_map(|entry| match entry.event {
                    GroundTruth::RequestReceived { method, path, .. } => Some((method, path)),
                    _ => None,
                })
                .collect();
            assert_eq!(requests, vec![("CONNECT".into(), expected.into())], "actual CONNECT-UDP path");
            assert!(output.record.findings.iter().any(|finding| finding.code == "masque.proxy_refused"));
            assert!(!recorder.log.entries().iter().any(|entry| matches!(entry.event, GroundTruth::DatagramRelayed { .. })));
        }
    }
}

#[test]
fn escaped_raw_hosts_and_shorthand_proxy_names_use_execution_parsers() {
    use anvil_domain::request::{MASQUE_DEFAULT_TEMPLATE, MasqueSpec, PayloadEncoding, StreamPayload, UdpSpec};
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let ws = app.create_workspace("Parser parity").unwrap().meta.id;
    for (protocol, scheme) in [
        (Protocol::Tcp, "tcp"),
        (Protocol::Tcp, "tls"),
        (Protocol::Udp, "udp"),
        (Protocol::Udp, "dtls"),
        (Protocol::WebSocket, "ws"),
        (Protocol::WebSocket, "wss"),
    ] {
        pin(&app, ws, "%6cocalhost", &["127.0.0.1"]);
        pin(&app, ws, "localhost", &["198.51.100.7"]);
        let mut spec = RequestSpec::http("GET", &format!("{scheme}://%6cocalhost:8080/"));
        spec.protocol = protocol;
        if protocol == Protocol::Udp {
            spec.udp = Some(UdpSpec {
                dtls: scheme == "dtls",
                datagrams: vec![StreamPayload { data: "x".into(), encoding: PayloadEncoding::Text }],
                response_window_ms: 100,
                max_datagrams: 1,
                masque: None,
                proxy_protocol: None,
            });
        }
        let p = plan(&app, ws, spec);
        assert!(warns(&app, &p), "{scheme}");
        assert!(app.load_preflight(&p).unwrap().destinations[0].contains("localhost:8080"));
        pin(&app, ws, "%6cocalhost", &["198.51.100.7"]);
        pin(&app, ws, "localhost", &["127.0.0.1"]);
        assert!(!warns(&app, &p), "{scheme}: use normalized execution host's override");
    }
    let profile = proxy(&app, ws, ProxyKind::Http, "127.1:3128", "");
    let p = plan(&app, ws, routed(RequestSpec::http("GET", "http://127.0.0.1:8080/"), &profile));
    pin(&app, ws, "127.1", &["198.51.100.7"]);
    assert!(warns(&app, &p));
    pin(&app, ws, "127.1", &["127.0.0.1"]);
    assert!(!warns(&app, &p), "proxy names keep the connector's spelling");

    // HTTPS CONNECT and MASQUE also resolve the destination at the proxy.
    pin(&app, ws, "api.example.test", &["127.0.0.1"]);
    let https = proxy(&app, ws, ProxyKind::Https, "127.0.0.1:3128", "");
    let p = plan(&app, ws, routed(RequestSpec::http("GET", "http://api.example.test:8080/"), &https));
    assert!(warns(&app, &p));
    let mut udp = RequestSpec::http("GET", "udp://api.example.test:8080/");
    udp.protocol = Protocol::Udp;
    udp.udp = Some(UdpSpec {
        dtls: false,
        datagrams: vec![StreamPayload { data: "x".into(), encoding: PayloadEncoding::Text }],
        response_window_ms: 100,
        max_datagrams: 1,
        masque: Some(MasqueSpec {
            proxy_url: "https://127.0.0.1:4433".into(),
            uri_template: MASQUE_DEFAULT_TEMPLATE.into(),
            datagrams: Default::default(),
        }),
        proxy_protocol: None,
    });
    let p = plan(&app, ws, udp.clone());
    assert!(warns(&app, &p));
    udp.url = "udp://127.0.0.1:8080/".into();
    assert!(!warns(&app, &plan(&app, ws, udp)));
}

#[tokio::test]
async fn hbone_receives_unpinned_target_and_oauth_names_despite_client_overrides() {
    use anvil_domain::tls::{ClientIdentity, ServerSpiffeIdentity, TlsProfile};
    use anvil_fixtures::hbone::{self, HboneOptions};
    use anvil_fixtures::mesh_pki::{MeshPki, ZTUNNEL_SPIFFE_ID};
    anvil_transport::init();
    anvil_fixtures::init();
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let ws = app.create_workspace("HBONE names").unwrap().meta.id;
    let pki = MeshPki::generate();
    let endpoint = hbone::serve(
        "127.0.0.1:0",
        HboneOptions {
            server_cert_chain_pem: pki.ztunnel.chain_with(&pki.ca),
            server_key_pem: pki.ztunnel.key.clone(),
            client_auth: anvil_fixtures::ClientAuth::Required { ca_pem: pki.ca.cert.clone() },
            alpn: vec!["h2".into()],
            allowed: vec![],
            unavailable: vec![],
            udp_faults: vec![],
        },
    )
    .await
    .unwrap();
    let tls = app
        .save_tls_profile(TlsProfile {
            id: Id::new(),
            workspace_id: ws,
            name: "mesh".into(),
            verify: true,
            use_system_roots: false,
            extra_roots_pem: vec![pki.ca.cert.clone()],
            client_identity: Some(ClientIdentity::Pem {
                cert_chain_pem: pki.client.chain_with(&pki.ca),
                private_key_pem: SensitiveValue::template(pki.client.key.clone()),
            }),
            bindings: vec![],
            min_version: Default::default(),
            server_name_override: None,
            server_spiffe: Some(ServerSpiffeIdentity { expected_server_spiffe_id: Some(ZTUNNEL_SPIFFE_ID.into()), trust_domain: None }),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        })
        .unwrap();
    let mut profile = proxy(&app, ws, ProxyKind::Hbone, &endpoint.address(), "127.0.0.1");
    profile.tls_profile_id = Some(tls.id);
    profile = app.save_proxy_profile(profile).unwrap();
    pin(&app, ws, "api.example.test", &["127.0.0.1"]);
    pin(&app, ws, "issuer.example.test", &["127.0.0.1"]);
    let api = Recorder::start(false).await;
    let target = plan(&app, ws, routed(RequestSpec::http("GET", "http://api.example.test:8080/api"), &profile));
    assert!(warns(&app, &target));
    let _ = send(&context(&app, &target)).await;
    assert_eq!(endpoint.connects().last().unwrap().authority, "api.example.test:8080");

    let mut spec = routed(RequestSpec::http("GET", &api.url("/api")), &profile);
    spec.auth = oauth("https://issuer.example.test:8080/token");
    let token = plan(&app, ws, spec.clone());
    assert!(warns(&app, &token));
    let _ = send(&context(&app, &token)).await;
    assert_eq!(endpoint.connects().last().unwrap().authority, "issuer.example.test:8080");
    assert!(api.requests().is_empty());

    profile.no_proxy = "127.0.0.1,api.example.test,issuer.example.test".into();
    profile = app.save_proxy_profile(profile).unwrap();
    spec = routed(RequestSpec::http("GET", &api.url("/api")), &profile);
    spec.auth = oauth(&api.url("/token"));
    let bypass = plan(&app, ws, spec);
    assert!(!warns(&app, &bypass));
    let before = endpoint.connects().len();
    assert_eq!(send(&context(&app, &bypass)).await.record.response.unwrap().status, 200);
    assert_eq!(endpoint.connects().len(), before);
}

#[tokio::test]
async fn preflight_never_queries_a_silent_resolver_or_waits_for_dns_deadlines() {
    use anvil_domain::settings::{ResolverMode, TimeoutOverrides};
    use tokio::net::UdpSocket;
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let ws = app.create_workspace("Silent DNS").unwrap().meta.id;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut workspace = app.workspace(&ws).unwrap();
    workspace.settings.resolver = Some(ResolverMode::Custom { nameservers: vec![socket.local_addr().unwrap().to_string()] });
    workspace.settings.timeouts = Some(TimeoutOverrides { dns_ms: Some(Some(5_000)), ..Default::default() });
    app.save_workspace(workspace).unwrap();
    let p = plan(&app, ws, RequestSpec::http("GET", "http://changing.example.test:8080/api"));
    let started = std::time::Instant::now();
    assert!(warns(&app, &p));
    assert!(started.elapsed() < Duration::from_secs(1), "no DNS wait in synchronous preflight");
    let error = socket.try_recv_from(&mut [0; 4096]).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock, "preflight sends no DNS query");

    // System DNS also remains unproven, without starting a blocking OS lookup.
    let mut workspace = app.workspace(&ws).unwrap();
    workspace.settings.resolver = Some(ResolverMode::System);
    workspace.settings.timeouts.as_mut().unwrap().dns_ms = Some(None);
    app.save_workspace(workspace).unwrap();
    assert!(warns(&app, &p));
}

#[tokio::test]
async fn changing_dns_answers_never_establish_preflight_locality() {
    use anvil_domain::settings::{IpPreference, ResolverMode};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use tokio::net::UdpSocket;
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let ws = app.create_workspace("DNS rebinding").unwrap().meta.id;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server = socket.local_addr().unwrap();
    let remote = Arc::new(AtomicBool::new(false));
    let queries = Arc::new(AtomicUsize::new(0));
    let (answer_remote, received) = (remote.clone(), queries.clone());
    let task = tokio::spawn(async move {
        let mut packet = [0; 4096];
        while let Ok((length, peer)) = socket.recv_from(&mut packet).await {
            received.fetch_add(1, Ordering::SeqCst);
            let query = &packet[..length];
            let mut end = 12;
            while query[end] != 0 {
                end += query[end] as usize + 1;
            }
            let kind = u16::from_be_bytes([query[end + 1], query[end + 2]]);
            end += 5;
            let mut response = query[..end].to_vec();
            response[2..4].copy_from_slice(&[0x81, 0x80]);
            response[6..12].fill(0);
            if kind == 1 {
                response[7] = 1;
                response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4]);
                let ip = if answer_remote.load(Ordering::SeqCst) { [198, 51, 100, 7] } else { [127, 0, 0, 1] };
                response.extend_from_slice(&ip);
            }
            socket.send_to(&response, peer).await.unwrap();
        }
    });
    let mut workspace = app.workspace(&ws).unwrap();
    workspace.settings.resolver = Some(ResolverMode::Custom { nameservers: vec![server.to_string()] });
    workspace.settings.ip_preference = Some(IpPreference::Ipv4Only);
    app.save_workspace(workspace).unwrap();
    let p = plan(&app, ws, RequestSpec::http("GET", "http://changing.example.test:8080/api"));
    assert!(warns(&app, &p));
    assert_eq!(queries.load(Ordering::SeqCst), 0);
    let ctx = context(&app, &p);
    let settings = anvil_engine::settings::resolve(&ctx.settings_layers);
    let dns = anvil_transport::dns::DnsConfig {
        resolver: settings.resolver,
        overrides: settings.dns_overrides,
        ip_preference: settings.ip_preference,
    };
    for (changes, expected) in [(false, "127.0.0.1:8080"), (true, "198.51.100.7:8080")] {
        remote.store(changes, Ordering::SeqCst);
        let answer = anvil_transport::dns::resolve("changing.example.test", 8080, &dns, Some(Duration::from_secs(2))).await.unwrap();
        assert_eq!(answer.addrs, [expected.parse::<SocketAddr>().unwrap()]);
        let before = queries.load(Ordering::SeqCst);
        assert!(warns(&app, &p));
        assert_eq!(queries.load(Ordering::SeqCst), before, "preflight does not take a disposable answer",);
    }
    pin(&app, ws, "changing.example.test", &["127.0.0.1"]);
    assert!(!warns(&app, &p), "a fixed override skips the changing resolver at send too");
    task.abort();
}

#[test]
fn fixed_resolution_uses_literal_precedence_ip_filtering_and_browser_authorization_rules() {
    use anvil_domain::settings::IpPreference;
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let ws = app.create_workspace("Fixed addresses").unwrap().meta.id;
    let p = plan(&app, ws, RequestSpec::http("GET", "http://localhost:8080/api"));
    for addresses in [vec![], vec!["not-an-ip"], vec!["127.0.0.1", "198.51.100.7"]] {
        pin(&app, ws, "localhost", &addresses);
        assert!(warns(&app, &p), "{addresses:?}");
    }
    pin(&app, ws, "localhost", &["127.0.0.1", "2001:db8::1"]);
    let mut workspace = app.workspace(&ws).unwrap();
    workspace.settings.ip_preference = Some(IpPreference::Ipv4Only);
    app.save_workspace(workspace).unwrap();
    assert!(!warns(&app, &p), "only the retained IPv4 address can be dialed");
    pin(&app, ws, "localhost", &["::1"]);
    assert!(warns(&app, &p), "an empty filtered answer is unproven");
    pin(&app, ws, "127.0.0.1", &["198.51.100.7"]);
    let literal = plan(&app, ws, RequestSpec::http("GET", "http://127.0.0.1:8080/api"));
    assert!(!warns(&app, &literal), "literal DNS always wins over an override");

    pin(&app, ws, "issuer.example.test", &["127.0.0.1"]);
    let mut spec = RequestSpec::http("GET", "http://127.0.0.1:8080/api");
    spec.auth = oauth("http://127.0.0.1:8080/token");
    if let AuthConfig::OAuth2 { config } = &mut spec.auth {
        config.grant = OAuthGrant::AuthorizationCodePkce;
        config.authorization_url = "http://issuer.example.test:8080/authorize".into();
    }
    let browser = plan(&app, ws, spec);
    assert!(warns(&app, &browser), "client overrides cannot pin an external browser's DNS");
}
