//! HTTP/3 execution policy: forced H3 never falls back silently; automatic
//! mode records the failed H3 attempt and the TCP fallback as separate attempts.

use crate::Engine;
use anvil_domain::execution::AttemptReason;
use anvil_domain::settings::HttpVersionPolicy;
use anvil_transport::http::{AttemptOutput, HttpPlan};
use anvil_transport::recorder::EventCtx;
use tokio_util::sync::CancellationToken;

pub async fn execute(
    engine: &Engine,
    plan: &HttpPlan,
    policy: HttpVersionPolicy,
    index: u32,
    reason: AttemptReason,
    events: &EventCtx,
    cancel: &CancellationToken,
) -> Vec<AttemptOutput> {
    let h3 = engine.h3.execute(plan, index, reason, events, cancel).await;
    let failed_without_response = h3.response.is_none() && h3.observation.failure.is_some();
    let canceled = cancel.is_cancelled();
    if policy == HttpVersionPolicy::Http3WithFallback && failed_without_response && !canceled {
        let mut tcp_plan = plan.clone();
        tcp_plan.version = HttpVersionPolicy::Auto;
        let mut outs = vec![h3];
        let fb = engine.http.execute(&tcp_plan, index + 1, AttemptReason::ProtocolFallback { from: "h3".into() }, events, cancel).await;
        outs.extend(fb);
        return outs;
    }
    vec![h3]
}
