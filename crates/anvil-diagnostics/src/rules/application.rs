use super::Ctx;
use crate::{Draft, warn};
use anvil_domain::diagnostics::{Confidence, EvidenceSource as E, Owner, Severity, SourceScope};
use anvil_domain::outcome::{OutcomeWarning, WarningCode};

pub fn rules(ctx: &Ctx<'_>, out: &mut Vec<Draft>, warnings: &mut Vec<OutcomeWarning>) {
    let Some(r) = ctx.input.response else { return };
    let idx = ctx.attempt_index();
    if let Some(f) = &ctx.body.soap_fault {
        out.push(
            Draft::new("app.soap_fault", "app.body", Confidence::Confirmed, SourceScope::Unknown, Owner::ApiOwner, Severity::Error)
                .ev_at(E::BodyContent, "soap.faultcode", f.code.clone(), idx)
                .ev_at(E::BodyContent, "soap.faultstring", f.reason.clone(), idx)
                .ev_at(E::HttpStatus, "status", r.status.to_string(), idx)
                .var("status", r.status.to_string())
                .var("fault_code", f.code.clone())
                .var("fault_reason", f.reason.clone()),
        );
    }
    if let Some(g) = &ctx.body.graphql {
        out.push(
            Draft::new("app.graphql_errors", "app.body", Confidence::Confirmed, SourceScope::Unknown, Owner::ApiOwner, Severity::Error)
                .ev_at(E::BodyContent, "graphql.error_count", g.error_count.to_string(), idx)
                .ev_at(E::BodyContent, "graphql.first_message", g.first_message.clone(), idx)
                .ev_at(E::BodyContent, "graphql.partial_data", g.has_data.to_string(), idx)
                .var("status", r.status.to_string())
                .var("count", g.error_count.to_string())
                .var("first", g.first_message.clone())
                .var(
                    "partial",
                    if g.has_data {
                        "Partial data was also returned and is preserved.".into()
                    } else {
                        "No data was returned.".to_string()
                    },
                ),
        );
    }
    if ctx.body.is_html {
        warn(
            warnings,
            WarningCode::ResponseIsUntrustedContent,
            "The response contains HTML. Anvil shows it as inert text; scripts and links in it have no access to the app.",
        );
    }
    if ctx.input.credentials_stripped_on_redirect {
        warn(
            warnings,
            WarningCode::CredentialsStrippedOnRedirect,
            "A redirect crossed to a different origin; Authorization, cookies and the client certificate were not forwarded.",
        );
    }
}
