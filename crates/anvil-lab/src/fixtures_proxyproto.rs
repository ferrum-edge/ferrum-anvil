//! Fixtures for the `proxyproto` profile (ports 19901–19923, see
//! lab/gateway/proxyproto{,-auth,-v6}.yaml).
//!
//! The TCP backends require a PROXY v2 header themselves: the gateway's
//! `backend_proxy_protocol: v2` re-advertises the client identity it resolved
//! from Anvil's header, so the backend records what the gateway concluded.
//! The UDP backends are plain echoes that record every payload byte, so a
//! backend that received envelope bytes would show them.

use anvil_fixtures::LabPki;
use anvil_fixtures::proxy_protocol::{self as pp, ProxyFixture};
use anyhow::Result;
use std::path::{Path, PathBuf};

/// Every field is held so its server keeps running for the whole lab run.
#[allow(dead_code)]
pub struct ProxyProtoFixtures {
    pub pki: LabPki,
    pub certs_dir: PathBuf,
    /// Backend of `pp-tcp` (18901).
    pub tcp_backend: ProxyFixture,
    /// Backend of `pp-tcp-tls` (18902).
    pub tls_backend: ProxyFixture,
    /// Backend of `pp-udp` (18903).
    pub udp_backend: ProxyFixture,
    /// Backend of `pp-dtls` (18904).
    pub dtls_backend: ProxyFixture,
    /// Backend of `pp-udp-auth` (18911).
    pub udp_auth_backend: ProxyFixture,
    /// Backend of `pp-dtls-auth` (18912).
    pub dtls_auth_backend: ProxyFixture,
    /// Backends of the untrusted-peer instance (`pp-v6-tcp`, `pp-v6-udp`): must stay silent.
    pub v6_tcp_backend: ProxyFixture,
    pub v6_udp_backend: ProxyFixture,
}

impl ProxyProtoFixtures {
    /// `certs_dir` receives the per-run PKI rendered into `{{LAB_CERTS}}`.
    pub async fn start(certs_dir: &Path) -> Result<Self> {
        let pki = LabPki::generate();
        pki.write_to(certs_dir)?;
        let gateway = vec!["127.0.0.1".parse()?];
        Ok(ProxyProtoFixtures {
            tcp_backend: pp::tcp_echo("127.0.0.1:19901", gateway.clone(), None).await?,
            tls_backend: pp::tcp_echo("127.0.0.1:19902", gateway, None).await?,
            udp_backend: pp::udp_plain_echo("127.0.0.1:19903").await?,
            dtls_backend: pp::udp_plain_echo("127.0.0.1:19904").await?,
            udp_auth_backend: pp::udp_plain_echo("127.0.0.1:19913").await?,
            dtls_auth_backend: pp::udp_plain_echo("127.0.0.1:19914").await?,
            v6_tcp_backend: pp::tcp_echo("127.0.0.1:19921", vec!["127.0.0.1".parse()?], None).await?,
            v6_udp_backend: pp::udp_plain_echo("127.0.0.1:19923").await?,
            certs_dir: certs_dir.to_path_buf(),
            pki,
        })
    }

    pub fn clear_logs(&self) {
        for f in [
            &self.tcp_backend,
            &self.tls_backend,
            &self.udp_backend,
            &self.dtls_backend,
            &self.udp_auth_backend,
            &self.dtls_auth_backend,
            &self.v6_tcp_backend,
            &self.v6_udp_backend,
        ] {
            f.log.clear();
        }
    }
}
