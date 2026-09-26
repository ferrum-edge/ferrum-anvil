//! The admission profile's second gateway instance: Ferrum Edge (0.9.5 / 0.9.7) in
//! **mesh mode** (egress-gateway topology, localized file config), used for
//! UP-018. In 0.9.5 and 0.9.7 the per-destination physical-connection ceiling
//! (DestinationRule `connectionPool.tcp.maxConnections`) exists only as a
//! mesh-projected `Upstream.port_overrides[].max_connections`; file mode
//! rejects that field, so the live ceiling needs this instance.
//!
//! Anvil drives the egress gateway's SVID-mTLS listener (127.0.0.1:18589)
//! with an ordinary verified TLS client identity (the lab client SVID) and
//! the destination ServiceEntry host in `Host`. Everything binds loopback
//! inside the admission port block; the PKI is generated per run.

use crate::fixtures_policy::Target;
use crate::gateway::{self, Gateway, Instance, Readiness};
use anvil_domain::integration::{IntegrationKind, IntegrationProfile};
use anvil_domain::request::RequestSpec;
use anvil_domain::secret::SensitiveValue;
use anvil_domain::settings::{DnsOverride, SettingsOverrides, TimeoutOverrides};
use anvil_domain::tls::{ClientIdentity, HostBinding, TlsMinVersion, TlsProfile};
use anvil_engine::ExecutionContext;
use anvil_fixtures::http1_only::{self, Http1Fixture};
use anvil_fixtures::mesh_pki::MeshPki;
use anyhow::Result;
use std::path::PathBuf;

/// Egress mTLS listener (FERRUM_MESH_EGRESS_LISTEN_ADDR in admission-mesh.conf).
pub const EGRESS_PORT: u16 = 18589;
pub const MESH_ADMIN_PORT: u16 = 18592;
/// The capped destination's lane: `Host: localhost:18589` selects the
/// ServiceEntry `localhost:19503` (reqwest HTTP/1.1 dispatch).
pub const H1_LANE: Target = Target {
    base: "https://localhost:18589",
    port: EGRESS_PORT,
    profile_name: "lab admission mesh gateway",
    isolation: "lab-admission-mesh",
};
/// Operator id of the materialized egress proxy (0.9.5 and 0.9.7 escape `-` in the
/// ServiceEntry name as `_dash_`).
pub const H1_PROXY_ID: &str = "mesh-egress-ferrum-anvil_dash_lab_dash_h1_dash_capped-localhost-19503";

pub struct MeshInstance {
    pub gateway: Gateway,
    pub pki: MeshPki,
    /// 19503: strictly HTTP/1.1 backend behind the capped destination
    /// (ground truth: what reached it). It must refuse the gateway's startup
    /// h2c capability probe, or the probe's pooled connection would itself
    /// occupy the single permitted slot (live-checked).
    pub backend: Http1Fixture,
}

fn run_dir() -> PathBuf {
    gateway::repo_root().join("lab/.run/admission-mesh")
}

/// Start the capped backend, then the mesh-mode egress gateway (its startup
/// capability probe classifies the backend before any scenario runs).
pub async fn start() -> Result<MeshInstance> {
    let pki = MeshPki::generate();
    let pki_dir = run_dir().join("pki");
    pki.write_to(&pki_dir)?;
    let backend = http1_only::serve("127.0.0.1:19503").await?;
    let vars = [("MESH_PKI", pki_dir.display().to_string()), ("LAB_RUN", run_dir().display().to_string())];
    let gateway = Gateway::launch(Instance {
        name: "admission-mesh",
        mode: "mesh",
        conf: "admission-mesh.conf",
        yaml: Some("admission-mesh.json"),
        vars: &vars,
        admin_port: MESH_ADMIN_PORT,
        env: &[],
        readiness: Readiness::Ready,
        append_log: false,
    })
    .await?;
    Ok(MeshInstance { gateway, pki, backend })
}

/// A request to the egress listener for `lane`, presenting the lab client
/// SVID and verifying the listener against the lab mesh root (no bypass).
pub fn request(mesh: &MeshInstance, lane: &Target, trusted: bool, path: &str) -> ExecutionContext {
    let mut c = ExecutionContext::standalone(RequestSpec::http("GET", &format!("{}{path}", lane.base)));
    c.isolation = lane.isolation.into();
    let profile = TlsProfile {
        id: anvil_domain::Id::new(),
        workspace_id: anvil_domain::Id::new(),
        name: "lab mesh client SVID".into(),
        verify: true,
        use_system_roots: false,
        extra_roots_pem: vec![mesh.pki.ca.cert.clone()],
        client_identity: Some(ClientIdentity::Pem {
            cert_chain_pem: mesh.pki.client.chain_with(&mesh.pki.ca),
            private_key_pem: SensitiveValue::template(mesh.pki.client.key.clone()),
        }),
        bindings: vec![],
        min_version: TlsMinVersion::Tls12,
        server_name_override: None,
        server_spiffe: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    let o = SettingsOverrides {
        tls_profile_id: Some(profile.id),
        // The listener binds 127.0.0.1 only; keep `localhost` off ::1.
        dns_overrides: vec![DnsOverride { host: "localhost".into(), addresses: vec!["127.0.0.1".into()] }],
        timeouts: Some(TimeoutOverrides { total_ms: Some(Some(20_000)), ..Default::default() }),
        ..Default::default()
    };
    c.tls_profiles.push(profile);
    c.settings_layers.push(("run".into(), o));
    if trusted {
        c.integrations.push(IntegrationProfile {
            id: anvil_domain::Id::new(),
            workspace_id: anvil_domain::Id::new(),
            name: lane.profile_name.into(),
            kind: IntegrationKind::FerrumGateway {
                hosts: vec![
                    HostBinding { host: "localhost".into(), port: Some(EGRESS_PORT) },
                    HostBinding { host: "127.0.0.1".into(), port: Some(EGRESS_PORT) },
                ],
                compatibility_id: crate::gateway::compatibility_id(),
                require_verified_tls: false,
                detail: None,
                console_url: None,
            },
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        });
    }
    c
}
