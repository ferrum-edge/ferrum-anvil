//! Token-endpoint HTTP for OAuth acquisition, using the same instrumented
//! transport and the workspace's trust settings (never a separate client).

use crate::Engine;
use crate::context::ExecutionContext;
use crate::prepare;
use anvil_auth::oauth::{BoxFut, TokenHttp};
use anvil_domain::execution::AttemptReason;
use anvil_domain::settings::{EffectiveSettings, HttpVersionPolicy};
use anvil_transport::dns::DnsConfig;
use anvil_transport::http::HttpPlan;
use anvil_transport::recorder::EventCtx;
use base64::Engine as _;
use bytes::Bytes;
use tokio_util::sync::CancellationToken;

pub struct EngineTokenHttp<'a> {
    pub engine: &'a Engine,
    pub ctx: &'a ExecutionContext,
    pub settings: &'a EffectiveSettings,
}

impl TokenHttp for EngineTokenHttp<'_> {
    fn post_form<'b>(
        &'b self,
        url: &'b str,
        form: Vec<(String, String)>,
        basic: Option<(String, String)>,
    ) -> BoxFut<'b, Result<(u16, Vec<u8>), String>> {
        Box::pin(async move {
            let mut inferred = vec![];
            let t = prepare::parse_target(url, &["https", "http"], &mut inferred).map_err(|e| e.message)?;
            let body: String = url::form_urlencoded::Serializer::new(String::new()).extend_pairs(form.iter()).finish();
            let mut headers = vec![
                (http::header::CONTENT_TYPE, http::HeaderValue::from_static("application/x-www-form-urlencoded")),
                (http::header::ACCEPT, http::HeaderValue::from_static("application/json")),
            ];
            if let Some((u, p)) = basic {
                let enc = |s: &str| url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>();
                let token = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", enc(&u), enc(&p)));
                headers.push((
                    http::header::AUTHORIZATION,
                    http::HeaderValue::from_str(&format!("Basic {token}")).map_err(|e| e.to_string())?,
                ));
            }
            let tls = if t.scheme == "https" {
                let mut inf = vec![];
                Some(crate::http_exec::tls_for(self.engine, self.ctx, self.settings, &t, &mut inf).map_err(|e| e.message)?.0)
            } else {
                None
            };
            let plan = HttpPlan {
                method: http::Method::POST,
                https: t.scheme == "https",
                host: t.host.clone(),
                port: t.port,
                authority: t.authority.clone(),
                request_target: t.request_target(),
                headers,
                body: Bytes::from(body),
                version: HttpVersionPolicy::Auto,
                timeouts: self.settings.timeouts,
                limits: self.settings.limits,
                keepalive: true,
                dns: DnsConfig {
                    resolver: self.settings.resolver.clone(),
                    overrides: self.settings.dns_overrides.clone(),
                    ip_preference: self.settings.ip_preference,
                },
                proxy: None,
                tls,
                isolation: format!("{}|oauth", self.ctx.isolation),
                display_url: url.to_string(),
            };
            let mut outs = self.engine.http.execute(&plan, 0, AttemptReason::Initial, &EventCtx::none(), &CancellationToken::new()).await;
            let out = outs.pop().ok_or("no attempt")?;
            match (out.response, out.observation.failure) {
                (Some(r), None) => Ok((r.status, out.body.to_vec())),
                (_, Some(f)) => Err(format!("token endpoint {}: {:?} — {}", t.authority, f.kind, f.message)),
                (None, None) => Err("token endpoint returned no response".into()),
            }
        })
    }
}
