//! Local credential checks that need no network (decode is not verification).

use anvil_auth::ResolvedAuth;
use anvil_diagnostics::Draft;
use anvil_domain::diagnostics::{Confidence, EvidenceSource, Owner, Severity, SourceScope};

fn check_token(token: &str, out: &mut Vec<Draft>) {
    if token.split('.').count() != 3 {
        return;
    }
    let Ok(i) = anvil_auth::jwt::inspect(token, chrono::Utc::now(), 0) else { return };
    let exp = i.claims.get("exp").and_then(|v| v.as_i64());
    let nbf = i.claims.get("nbf").and_then(|v| v.as_i64());
    match i.time_status {
        anvil_auth::jwt::TimeStatus::Expired => out.push(
            Draft::new(
                "auth.token_expired_locally",
                "local.credentials",
                Confidence::Likely,
                SourceScope::LocalClient,
                Owner::Caller,
                Severity::Warning,
            )
            .ev(EvidenceSource::LocalValidation, "jwt.exp", exp.map(|e| e.to_string()).unwrap_or_default())
            .var("when", exp.and_then(|e| chrono::DateTime::from_timestamp(e, 0)).map(|d| d.to_rfc3339()).unwrap_or_default()),
        ),
        anvil_auth::jwt::TimeStatus::NotYetValid => out.push(
            Draft::new(
                "auth.token_not_yet_valid_locally",
                "local.credentials",
                Confidence::Likely,
                SourceScope::LocalClient,
                Owner::Caller,
                Severity::Warning,
            )
            .ev(EvidenceSource::LocalValidation, "jwt.nbf", nbf.map(|e| e.to_string()).unwrap_or_default())
            .var("when", nbf.and_then(|e| chrono::DateTime::from_timestamp(e, 0)).map(|d| d.to_rfc3339()).unwrap_or_default()),
        ),
        _ => {}
    }
}

/// AUTH-004/005: flag bearer JWTs that are expired / not yet valid by the local clock.
pub fn bearer_expiry(auth: &ResolvedAuth, out: &mut Vec<Draft>) {
    match auth {
        ResolvedAuth::Bearer { token, .. } => check_token(token, out),
        ResolvedAuth::OAuth2 { access_token, .. } => check_token(access_token, out),
        ResolvedAuth::Dpop { access_token, .. } => check_token(access_token, out),
        ResolvedAuth::Multi(v) => v.iter().for_each(|a| bearer_expiry(a, out)),
        _ => {}
    }
}
