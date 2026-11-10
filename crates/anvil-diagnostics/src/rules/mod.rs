//! Rule families. Each rule reads typed facts and emits drafts; wording is
//! applied later from the findings catalog.

mod application;
mod auth_session;
mod dispatch;
mod early_data;
mod ferrum_detail;
mod ferrum_rules;
mod http_status;
mod mesh;
mod network;
mod protocols;
mod proxy_header;
mod tls;
mod transport;
mod workload;

use crate::Draft;
use crate::facts::{BodyFacts, DiagnosticInput};
use anvil_domain::execution::{AttemptObservation, TransportFailure};
use anvil_domain::outcome::OutcomeWarning;

pub struct Ctx<'a> {
    pub input: &'a DiagnosticInput<'a>,
    pub body: &'a BodyFacts,
}

impl<'a> Ctx<'a> {
    pub fn final_attempt(&self) -> Option<&'a AttemptObservation> {
        self.input.attempts.last()
    }

    /// The failure that ended the execution: a preparation failure, or the
    /// final attempt's transport failure.
    pub fn final_failure(&self) -> Option<&'a TransportFailure> {
        self.input.preparation_failure.or_else(|| self.final_attempt().and_then(|a| a.failure.as_ref()))
    }

    pub fn attempt_index(&self) -> u32 {
        self.final_attempt().map(|a| a.index).unwrap_or(0)
    }

    /// At most `max_chars` of a text the finding quotes, redacted before
    /// it is cut ([`crate::facts::excerpt`]).
    pub fn excerpt(&self, s: &str, max_chars: usize) -> String {
        crate::facts::excerpt(self.input.redact, s, max_chars)
    }

    pub fn target_host(&self) -> String {
        self.final_attempt().and_then(|a| url_host(&a.url)).unwrap_or_else(|| "the destination".to_string())
    }
}

fn url_host(u: &str) -> Option<String> {
    let rest = u.split("://").nth(1)?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let authority = authority.rsplit('@').next()?;
    Some(authority.to_string())
}

/// Whether the execution stopped at an interactive login step (AUTH-017).
pub fn stopped_at_login(ctx: &Ctx<'_>) -> bool {
    auth_session::login_redirect(ctx).is_some()
}

pub fn run_all(ctx: &Ctx<'_>, drafts: &mut Vec<Draft>, warnings: &mut Vec<OutcomeWarning>) {
    network::local(ctx, drafts);
    network::dns_connect_proxy(ctx, drafts);
    tls::rules(ctx, drafts, warnings);
    mesh::rules(ctx, drafts, warnings);
    transport::rules(ctx, drafts, warnings);
    dispatch::rules(ctx, drafts);
    http_status::rules(ctx, drafts);
    ferrum_rules::rules(ctx, drafts, warnings);
    ferrum_detail::rules(ctx, drafts);
    application::rules(ctx, drafts, warnings);
    protocols::rules(ctx, drafts, warnings);
    early_data::rules(ctx, drafts);
    proxy_header::rules(ctx, drafts);
    auth_session::rules(ctx, drafts);
    workload::rules(ctx, drafts);
    proxy_header::annotate(ctx, drafts);
}
