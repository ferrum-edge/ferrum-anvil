//! Fixtures for the `streams` profile (ports 19400–19499, see
//! docs/audit/gateway-lab-config.md §3 and lab/gateway/streams.yaml).
//! Ports 19409 (gRPC backend down) and 19410 (TCP backend refused) are
//! deliberately left unbound.

use anvil_fixtures::http::{self, Fixture};
use anvil_fixtures::lab_streams::{self, SlowFixture, TcpRelay};
use anvil_fixtures::streams::{self, StreamFixture, TcpMode, UdpMode};
use anvil_fixtures::{LabPki, TlsServerOptions};
use anyhow::Result;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// How long the slow gRPC backend holds its response headers (longer than
/// the 1 s `backend_read_timeout_ms` of the `proto016-grpc-slow` route).
pub const GRPC_SLOW_DELAY: Duration = Duration::from_secs(4);

/// Every field is held so its server keeps running for the whole lab run.
#[allow(dead_code)]
pub struct StreamsFixtures {
    pub pki: LabPki,
    pub certs_dir: PathBuf,
    pub ws: Fixture,
    pub grpc: Fixture,
    pub echo: Fixture,
    pub tcp_halfclose: StreamFixture,
    pub udp_echo: StreamFixture,
    pub udp_silent: StreamFixture,
    pub udp_lossy: StreamFixture,
    pub tcp_echo: StreamFixture,
    pub tcps_echo: StreamFixture,
    pub grpc_slow: SlowFixture,
    pub sse: Fixture,
    pub tcps_untrusted: StreamFixture,
    pub sse_abort: SlowFixture,
    /// HTTPS backend offering ALPN h2 (lab CA): the gateway's direct HTTP/2 upstream leg.
    pub h2_tls: Fixture,
    /// TCP-only path to the gateway's HTTPS port: nothing answers QUIC on
    /// 19420/udp, which models a network that blocks UDP.
    pub udp_blocked_path: TcpRelay,
}

fn tls(chain: String, key: String) -> TlsServerOptions {
    let mut o = TlsServerOptions::new(chain, key);
    o.alpn = vec![];
    o
}

impl StreamsFixtures {
    /// `certs_dir` receives the per-run PKI rendered into `{{LAB_CERTS}}`.
    pub async fn start(certs_dir: &Path) -> Result<Self> {
        let pki = LabPki::generate();
        pki.write_to(certs_dir)?;
        let https: std::net::SocketAddr = "127.0.0.1:18443".parse()?;
        Ok(StreamsFixtures {
            ws: http::serve("127.0.0.1:19401", None).await?,
            grpc: http::serve("127.0.0.1:19402", None).await?,
            echo: http::serve("127.0.0.1:19403", None).await?,
            tcp_halfclose: streams::tcp("127.0.0.1:19404", TcpMode::ReplyAfterHalfClose, None).await?,
            udp_echo: streams::udp("127.0.0.1:19405", UdpMode::Echo).await?,
            udp_silent: streams::udp("127.0.0.1:19406", UdpMode::Silent).await?,
            udp_lossy: streams::udp("127.0.0.1:19407", UdpMode::DropEveryOther).await?,
            tcp_echo: streams::tcp("127.0.0.1:19408", TcpMode::Echo, None).await?,
            tcps_echo: streams::tcp("127.0.0.1:19411", TcpMode::Echo, Some(tls(pki.server.chain_with(&pki.ca), pki.server.key.clone())))
                .await?,
            grpc_slow: lab_streams::delayed_grpc("127.0.0.1:19412", GRPC_SLOW_DELAY).await?,
            sse: http::serve("127.0.0.1:19413", None).await?,
            tcps_untrusted: streams::tcp(
                "127.0.0.1:19414",
                TcpMode::Echo,
                Some(tls(pki.server_untrusted.chain_with(&pki.rogue_ca), pki.server_untrusted.key.clone())),
            )
            .await?,
            sse_abort: lab_streams::sse_abort("127.0.0.1:19416").await?,
            h2_tls: http::serve("127.0.0.1:19417", Some(TlsServerOptions::new(pki.server.chain_with(&pki.ca), pki.server.key.clone())))
                .await?,
            udp_blocked_path: lab_streams::relay("127.0.0.1:19420", https).await?,
            certs_dir: certs_dir.to_path_buf(),
            pki,
        })
    }

    /// Forget traffic the gateway sent on its own (capability probes).
    pub fn clear_logs(&self) {
        for l in [
            &self.ws.log,
            &self.grpc.log,
            &self.echo.log,
            &self.tcp_halfclose.log,
            &self.udp_echo.log,
            &self.udp_silent.log,
            &self.udp_lossy.log,
            &self.tcp_echo.log,
            &self.tcps_echo.log,
            &self.grpc_slow.log,
            &self.sse.log,
            &self.tcps_untrusted.log,
            &self.sse_abort.log,
            &self.h2_tls.log,
            &self.udp_blocked_path.log,
        ] {
            l.clear();
        }
    }
}
