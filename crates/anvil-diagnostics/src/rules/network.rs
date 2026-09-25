use super::Ctx;
use crate::Draft;
use anvil_domain::diagnostics::{Confidence, EvidenceSource as E, Owner, Severity, SourceScope};
use anvil_domain::execution::{FailureKind as K, Phase};

/// Local preparation failures: nothing left the machine, so no remote party
/// can be blamed.
pub fn local(ctx: &Ctx<'_>, out: &mut Vec<Draft>) {
    let Some(f) = ctx.final_failure() else { return };
    if !f.kind.is_local_preparation() {
        return;
    }
    let code = match f.kind {
        K::InvalidUrl | K::UnsupportedScheme => "local.invalid_url",
        K::UnresolvedVariable => "local.unresolved_variable",
        K::VariableCycle => "local.variable_cycle",
        K::MissingAttachment => "local.missing_attachment",
        K::ClientIdentityInvalid => "local.client_identity_invalid",
        K::ClientIdentityKeyMismatch => "local.client_identity_key_mismatch",
        K::TlsProfileInvalid => "local.tls_profile_invalid",
        K::ProxyConfigInvalid => "local.proxy_config_invalid",
        K::LintBlocked => "local.lint_blocked",
        K::UnsupportedCombination => "local.unsupported_combination",
        K::AuthPreparationFailed => "local.auth_preparation_failed",
        K::VaultLocked => "local.vault_locked",
        K::RequestTooLargeLocal => "local.request_too_large",
        _ => "local.validation_failed",
    };
    out.push(
        Draft::new(code, "local.preparation", Confidence::Confirmed, SourceScope::LocalClient, Owner::Caller, Severity::Error)
            .ev(E::LocalValidation, "failure.kind", format!("{:?}", f.kind))
            .ev(E::LocalValidation, "failure.field", f.field.clone().unwrap_or_default())
            .var("message", f.message.clone())
            .var("field", f.field.clone().unwrap_or_else(|| "the request".into())),
    );
}

pub fn dns_connect_proxy(ctx: &Ctx<'_>, out: &mut Vec<Draft>) {
    let Some(a) = ctx.final_attempt() else { return };
    let Some(f) = a.failure.as_ref() else { return };
    let host = ctx.target_host();
    let deadline = f.deadline_ms.map(|d| d.to_string()).unwrap_or_else(|| "the configured".into());
    let base = |code: &str, rule: &'static str, conf: Confidence, scope: SourceScope, owner: Owner| {
        Draft::new(code, rule, conf, scope, owner, Severity::Error)
            .ev_at(E::NativeTransport, "failure.kind", format!("{:?}", f.kind), a.index)
            .ev_at(E::NativeTransport, "failure.phase", format!("{:?}", f.phase), a.index)
            .var("host", host.clone())
            .var("deadline_ms", deadline.clone())
            .var("message", f.message.clone())
    };
    let proxied = a.connection.as_ref().and_then(|c| c.via_proxy.clone());
    let d = match f.kind {
        K::DnsNoSuchHost => {
            Some(base("client.dns.no_such_host", "network.dns", Confidence::Confirmed, SourceScope::ClientToPeer, Owner::Caller))
        }
        K::DnsNoRecords => {
            Some(base("client.dns.no_records", "network.dns", Confidence::Confirmed, SourceScope::ClientToPeer, Owner::Caller))
        }
        K::DnsTimeout => {
            Some(base("client.dns.timeout", "network.dns", Confidence::Confirmed, SourceScope::ClientToPeer, Owner::NetworkAdministrator))
        }
        K::DnsServerFailure => Some(base(
            "client.dns.server_failure",
            "network.dns",
            Confidence::Confirmed,
            SourceScope::ClientToPeer,
            Owner::NetworkAdministrator,
        )),
        K::DnsOther => Some(base("client.dns.other", "network.dns", Confidence::Unknown, SourceScope::ClientToPeer, Owner::Unknown)),
        K::ConnectRefused => {
            Some(base("client.connect.refused", "network.connect", Confidence::Confirmed, SourceScope::ClientToPeer, Owner::Unknown))
        }
        K::ConnectTimeout => Some(base(
            "client.connect.timeout",
            "network.connect",
            Confidence::Confirmed,
            SourceScope::ClientToPeer,
            Owner::NetworkAdministrator,
        )),
        K::NetworkUnreachable | K::HostUnreachable => Some(base(
            "client.connect.unreachable",
            "network.connect",
            Confidence::Confirmed,
            SourceScope::ClientToPeer,
            Owner::NetworkAdministrator,
        )),
        K::ConnectReset => {
            Some(base("client.connect.reset", "network.connect", Confidence::Confirmed, SourceScope::ClientToPeer, Owner::Unknown))
        }
        K::AddressUnavailable => Some(base(
            "client.connect.address_unavailable",
            "network.connect",
            Confidence::Confirmed,
            SourceScope::LocalClient,
            Owner::Caller,
        )),
        K::ConnectOther => {
            Some(base("client.connect.other", "network.connect", Confidence::Unknown, SourceScope::ClientToPeer, Owner::Unknown))
        }
        K::ProxyConnectFailed => Some(
            base("proxy.connect_failed", "network.proxy", Confidence::Confirmed, SourceScope::ForwardProxy, Owner::NetworkAdministrator)
                .var("proxy", proxied.clone().unwrap_or_else(|| "the configured proxy".into())),
        ),
        K::ProxyAuthRequired => Some(
            base("proxy.auth_required", "network.proxy", Confidence::Confirmed, SourceScope::ForwardProxy, Owner::Caller)
                .var("proxy", proxied.clone().unwrap_or_else(|| "the configured proxy".into())),
        ),
        K::ProxyTunnelRejected => Some(
            base("proxy.tunnel_rejected", "network.proxy", Confidence::Confirmed, SourceScope::ForwardProxy, Owner::NetworkAdministrator)
                .var("proxy", proxied.clone().unwrap_or_else(|| "the configured proxy".into()))
                .var("status", f.status.map(|s| s.to_string()).unwrap_or_else(|| "an error".into())),
        ),
        K::ProxyProtocolError => Some(
            base("proxy.protocol_error", "network.proxy", Confidence::Confirmed, SourceScope::ForwardProxy, Owner::NetworkAdministrator)
                .var("proxy", proxied.clone().unwrap_or_else(|| "the configured proxy".into())),
        ),
        _ => None,
    };
    if let Some(mut d) = d {
        if f.phase == Phase::Dns
            && let Some(c) = &a.connection
            && let Some(src) = &c.resolution_source
        {
            d = d.ev_at(E::NativeTransport, "dns.source", src.clone(), a.index);
        }
        if let Some(c) = &a.connection {
            for ca in &c.connect_attempts {
                d = d.ev_at(
                    E::NativeTransport,
                    "connect.attempt",
                    format!("{} → {}", ca.address, ca.failure.map(|k| format!("{k:?}")).unwrap_or_else(|| "connected".into())),
                    a.index,
                );
            }
        }
        out.push(d);
    }
}
