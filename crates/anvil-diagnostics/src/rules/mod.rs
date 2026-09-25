//! Rule families. Each rule reads typed facts and emits drafts; wording is
//! applied later from the findings catalog.

mod application;
mod dispatch;
mod ferrum_rules;
mod http_status;
mod network;
mod protocols;
mod tls;
mod transport;

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

/// Metadata for every rule (id, version, fixtures) — used by docs and by the
/// catalog consistency tests.
pub struct RuleMeta {
    pub id: &'static str,
    pub version: u32,
    pub summary: &'static str,
    pub fixtures: &'static [&'static str],
}

pub const RULES: &[RuleMeta] = &[
    RuleMeta {
        id: "local.preparation",
        version: 1,
        summary: "Local validation/preparation failures before any network activity",
        fixtures: &["LOCAL-001", "LOCAL-002", "LOCAL-003", "LOCAL-004", "LOCAL-005", "LOCAL-006", "TLS-007"],
    },
    RuleMeta { id: "network.dns", version: 1, summary: "Client-leg name resolution outcomes", fixtures: &["LOCAL-007", "LOCAL-008"] },
    RuleMeta { id: "network.connect", version: 1, summary: "Client-leg TCP connect outcomes", fixtures: &["LOCAL-009", "LOCAL-010"] },
    RuleMeta { id: "network.proxy", version: 1, summary: "Forward proxy setup outcomes", fixtures: &["LOCAL-006", "TLS-017"] },
    RuleMeta {
        id: "tls.verification",
        version: 1,
        summary: "Peer certificate verification failures on the client leg",
        fixtures: &["TLS-001", "TLS-002", "TLS-003", "TLS-004", "TLS-013"],
    },
    RuleMeta {
        id: "tls.handshake",
        version: 1,
        summary: "TLS handshake rejections, alerts, stalls and protocol mismatches",
        fixtures: &["TLS-005", "TLS-006", "TLS-009", "TLS-010", "TLS-011", "TLS-012"],
    },
    RuleMeta { id: "tls.bypass", version: 1, summary: "Scoped verification bypass warning", fixtures: &["TLS-015", "TLS-016"] },
    RuleMeta {
        id: "transport.exchange",
        version: 1,
        summary: "Request write / response header wait outcomes",
        fixtures: &["LOCAL-011", "PROTO-003", "PROTO-004", "PROTO-005"],
    },
    RuleMeta {
        id: "transport.body",
        version: 1,
        summary: "Response completeness after headers",
        fixtures: &["UP-011", "UP-012", "UP-013", "TRUST-007", "LOCAL-012"],
    },
    RuleMeta {
        id: "dispatch.safety",
        version: 1,
        summary: "Per-attempt and whole-request processing uncertainty",
        fixtures: &["LOCAL-011", "UP-012", "UP-020", "TRUST-008"],
    },
    RuleMeta {
        id: "http.status",
        version: 1,
        summary: "Generic HTTP status meaning without origin inference",
        fixtures: &["GW-006", "GW-007", "GW-016", "GW-017", "TRUST-006", "AUTH-003"],
    },
    RuleMeta {
        id: "ferrum.marker",
        version: 1,
        summary: "Ferrum public markers: trust, tokens, conflicts, unknown tokens, degraded routing",
        fixtures: &[
            "TRUST-001",
            "TRUST-002",
            "TRUST-003",
            "TRUST-004",
            "TRUST-005",
            "GW-018",
            "UP-001",
            "UP-009",
            "GW-001",
            "GW-002",
            "GW-004",
            "GW-005",
        ],
    },
    RuleMeta {
        id: "ferrum.catalog",
        version: 1,
        summary: "Signature matching against the source-audited Ferrum outcome inventory",
        fixtures: &["UP-001", "UP-002", "UP-014", "UP-015", "GW-006", "GW-007", "GW-008", "GW-009", "GW-010"],
    },
    RuleMeta {
        id: "app.body",
        version: 1,
        summary: "Application failures inside transport-successful responses (SOAP, GraphQL)",
        fixtures: &["PROTO-023", "PROTO-024"],
    },
    RuleMeta {
        id: "protocol.grpc",
        version: 1,
        summary: "gRPC terminal status semantics",
        fixtures: &["PROTO-014", "PROTO-015", "PROTO-016", "PROTO-017"],
    },
    RuleMeta {
        id: "protocol.websocket",
        version: 1,
        summary: "WebSocket handshake and close semantics",
        fixtures: &["PROTO-009", "PROTO-010", "PROTO-011", "PROTO-012", "PROTO-013"],
    },
    RuleMeta {
        id: "protocol.streams",
        version: 1,
        summary: "SSE / TCP / UDP session semantics",
        fixtures: &["PROTO-018", "PROTO-019", "PROTO-020", "PROTO-021", "PROTO-022"],
    },
    RuleMeta {
        id: "protocol.http3",
        version: 1,
        summary: "HTTP/3 forced mode and fallback reporting",
        fixtures: &["PROTO-006", "PROTO-007", "PROTO-008"],
    },
];

pub fn run_all(ctx: &Ctx<'_>, drafts: &mut Vec<Draft>, warnings: &mut Vec<OutcomeWarning>) {
    network::local(ctx, drafts);
    network::dns_connect_proxy(ctx, drafts);
    tls::rules(ctx, drafts, warnings);
    transport::rules(ctx, drafts, warnings);
    dispatch::rules(ctx, drafts);
    http_status::rules(ctx, drafts);
    ferrum_rules::rules(ctx, drafts, warnings);
    application::rules(ctx, drafts, warnings);
    protocols::rules(ctx, drafts, warnings);
}
