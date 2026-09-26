//! Replay safety: per-attempt dispatch state and the whole-request summary.
//! A failure that *may* have reached the peer is never presented as safe to
//! replay for non-idempotent operations.

use super::Ctx;
use crate::Draft;
use crate::facts::is_idempotent;
use anvil_domain::diagnostics::{Confidence, EvidenceSource as E, Owner, Severity, SourceScope};
use anvil_domain::execution::{BodyCompleteness, DispatchState};

pub fn rules(ctx: &Ctx<'_>, out: &mut Vec<Draft>) {
    let attempts = ctx.input.attempts;
    let Some(last) = attempts.last() else { return };
    let method = ctx.input.method.to_ascii_uppercase();
    let idempotent = is_idempotent(&method);
    let failed = last.failure.is_some();
    let incomplete = ctx.input.response.map(|r| r.body.completeness == BodyCompleteness::Incomplete).unwrap_or(false);

    if failed && (last.dispatch == DispatchState::MayHaveBeenSent || (incomplete && last.dispatch == DispatchState::Sent)) {
        let severity = if idempotent { Severity::Info } else { Severity::Warning };
        out.push(
            Draft::new(
                "request.processing_uncertain",
                "dispatch.safety",
                Confidence::Confirmed,
                SourceScope::Unknown,
                Owner::Caller,
                severity,
            )
            .ev_at(E::NativeTransport, "dispatch", format!("{:?}", last.dispatch), last.index)
            .ev_at(
                E::NativeTransport,
                "request.bytes_written",
                last.bytes.connection_bytes_written.map(|b| b.to_string()).unwrap_or_default(),
                last.index,
            )
            .var("method", method.clone())
            .var(
                "replay_advice",
                if idempotent {
                    "Repeating this idempotent request is normally safe.".to_string()
                } else {
                    format!("Do not automatically repeat this {method}; check whether the operation took effect first.")
                },
            ),
        );
    }

    if attempts.len() > 1 {
        let earlier_maybe =
            attempts[..attempts.len() - 1].iter().any(|a| matches!(a.dispatch, DispatchState::MayHaveBeenSent | DispatchState::Sent));
        if earlier_maybe && last.dispatch == DispatchState::NotDispatched && failed && !idempotent {
            out.push(
                Draft::new(
                    "request.earlier_attempt_may_have_processed",
                    "dispatch.safety",
                    Confidence::Confirmed,
                    SourceScope::Unknown,
                    Owner::Caller,
                    Severity::Warning,
                )
                .ev(E::NativeTransport, "attempts", attempts.len().to_string())
                .ev(
                    E::NativeTransport,
                    "attempt_dispatch",
                    attempts.iter().map(|a| format!("#{}:{:?}", a.index, a.dispatch)).collect::<Vec<_>>().join(", "),
                )
                .var("method", method.clone())
                .var("attempts", attempts.len().to_string()),
            );
        }
    }
}
