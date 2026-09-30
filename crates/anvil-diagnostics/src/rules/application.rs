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
    if let Some(why) = &ctx.body.xml_not_inspected {
        warn(
            warnings,
            WarningCode::PartialVisibility,
            format!("The SOAP envelope is too complex to inspect safely ({why}); the application outcome was not evaluated."),
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
    // Its wording says the transport succeeded: a 4xx or 5xx carrying a
    // JSON-RPC error is explained by the status findings (and the catalog).
    if let Some(e) = ctx.body.jsonrpc_error.as_ref().filter(|_| (200..300).contains(&r.status)) {
        // The code alone does not say whose the fault is (invalid params are
        // the caller's, an internal error the server's).
        let (scope, owner) = (SourceScope::Unknown, Owner::Unknown);
        let mut d = Draft::new("app.jsonrpc_error", "app.body", Confidence::Confirmed, scope, owner, Severity::Error)
            .ev_at(E::BodyContent, "jsonrpc.error.code", e.code.to_string(), idx)
            .ev_at(E::BodyContent, "jsonrpc.error.message", e.message.clone(), idx)
            .ev_at(E::HttpStatus, "status", r.status.to_string(), idx)
            .var("status", r.status.to_string())
            .var("code", e.code.to_string())
            .var("message", if e.message.is_empty() { "(no message)".to_string() } else { e.message.clone() })
            .var("meaning", jsonrpc_code_meaning(e.code).to_string());
        if let Some(g) = &e.gateway {
            d = d.ev_at(E::BodyContent, "jsonrpc.error.data.gateway", g.clone(), idx);
        }
        out.push(d);
    }
    if let Some(t) = &ctx.body.mcp_tool_error {
        // The tool ran and reported its own failure.
        let (scope, owner) = (SourceScope::UpstreamApplication, Owner::ApiOwner);
        out.push(
            Draft::new("app.mcp_tool_error", "app.body", Confidence::Confirmed, scope, owner, Severity::Error)
                .ev_at(E::BodyContent, "mcp.result.isError", "true", idx)
                .ev_at(E::BodyContent, "mcp.result.content.text", t.text.clone(), idx)
                .var("status", r.status.to_string())
                .var("text", if t.text.is_empty() { "(no text content)".to_string() } else { t.text.clone() }),
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

/// What a JSON-RPC 2.0 error code means by itself (JSON-RPC 2.0 §5.1). The
/// application-defined range carries no meaning without the server's own
/// documentation.
fn jsonrpc_code_meaning(code: i64) -> &'static str {
    match code {
        -32700 => "the server could not parse the request as JSON (parse error)",
        -32600 => "the request is not a valid JSON-RPC request (invalid request)",
        -32601 => "the method does not exist or is not available (method not found)",
        -32602 => "the method's parameters are invalid (invalid params)",
        -32603 => "the server failed internally (internal error)",
        -32099..=-32000 => "a server-defined error; its meaning is the server's own",
        _ => "an application-defined error; its meaning is the server's own",
    }
}
