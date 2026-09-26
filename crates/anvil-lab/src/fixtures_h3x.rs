//! Fixtures for the `h3x` profile (ports 19800–19899, lab/gateway/h3x.yaml):
//! SSE backends behind the gateway's HTTP/3 listener, UDP targets behind its
//! CONNECT-UDP route, and a TCP-only path to the QUIC port (UDP blocked).

use anvil_fixtures::LabPki;
use anvil_fixtures::http::{self, Fixture};
use anvil_fixtures::lab_streams::{self, SlowFixture, TcpRelay};
use anvil_fixtures::streams::{self, StreamFixture, UdpMode};
use anyhow::Result;
use std::path::{Path, PathBuf};

/// Every field is held so its server keeps running for the whole lab run.
#[allow(dead_code)]
pub struct H3xFixtures {
    pub pki: LabPki,
    pub certs_dir: PathBuf,
    /// HTTP/1.1 echo: the positive control's backend.
    pub echo: Fixture,
    /// `/sse?count=&interval=` event streams.
    pub sse: Fixture,
    /// Events, then an aborted body.
    pub sse_abort: SlowFixture,
    /// Events 1–2 then an abort; with `Last-Event-ID`, one more event and a clean end.
    pub sse_flaky: SlowFixture,
    /// Admitted CONNECT-UDP destination that echoes.
    pub udp_echo: StreamFixture,
    /// Admitted CONNECT-UDP destination that never answers.
    pub udp_silent: StreamFixture,
    /// A live echo that is NOT a MASQUE destination of the route.
    pub udp_unlisted: StreamFixture,
    /// TCP-only path to the gateway's HTTPS port: nothing answers QUIC on
    /// 19820/udp, which models a network that blocks UDP.
    pub udp_blocked_path: TcpRelay,
}

impl H3xFixtures {
    /// `certs_dir` receives the per-run PKI rendered into `{{LAB_CERTS}}`.
    pub async fn start(certs_dir: &Path) -> Result<Self> {
        let pki = LabPki::generate();
        pki.write_to(certs_dir)?;
        let https: std::net::SocketAddr = "127.0.0.1:18843".parse()?;
        Ok(H3xFixtures {
            echo: http::serve("127.0.0.1:19803", None).await?,
            sse: http::serve("127.0.0.1:19813", None).await?,
            sse_abort: lab_streams::sse_abort("127.0.0.1:19816").await?,
            sse_flaky: lab_streams::sse_flaky("127.0.0.1:19817").await?,
            udp_echo: streams::udp("127.0.0.1:19805", UdpMode::Echo).await?,
            udp_silent: streams::udp("127.0.0.1:19806", UdpMode::Silent).await?,
            udp_unlisted: streams::udp("127.0.0.1:19807", UdpMode::Echo).await?,
            udp_blocked_path: lab_streams::relay("127.0.0.1:19820", https).await?,
            certs_dir: certs_dir.to_path_buf(),
            pki,
        })
    }

    /// Forget traffic the gateways sent on their own (capability probes).
    pub fn clear_logs(&self) {
        for l in [
            &self.echo.log,
            &self.sse.log,
            &self.sse_abort.log,
            &self.sse_flaky.log,
            &self.udp_echo.log,
            &self.udp_silent.log,
            &self.udp_unlisted.log,
            &self.udp_blocked_path.log,
        ] {
            l.clear();
        }
    }
}
