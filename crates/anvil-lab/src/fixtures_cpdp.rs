//! Fixtures for the `cpdp` profile (ports 19700–19799, see
//! docs/audit/gateway-lab-config.md §3 and lab/gateway/cpdp-*.conf).

use anvil_fixtures::http::{self, Fixture};
use anvil_fixtures::lab_streams::{self, TcpRelay};
use anyhow::Result;

/// The control plane's gRPC listener (cpdp-cp.conf).
pub const CP_GRPC: &str = "127.0.0.1:18795";

/// Every field is held so its server keeps running for the whole lab run.
pub struct CpdpFixtures {
    /// Backend of the CP-delivered route `/cpdp/echo` (and the tick routes).
    pub echo: Fixture,
    /// The data plane reaches its control plane only through this relay
    /// (cpdp-dp.conf `FERRUM_DP_CP_GRPC_URLS`), so a cut is a real network
    /// partition while the control plane keeps running.
    pub cp_path: TcpRelay,
}

impl CpdpFixtures {
    pub async fn start() -> Result<Self> {
        Ok(CpdpFixtures {
            echo: http::serve("127.0.0.1:19701", None).await?,
            cp_path: lab_streams::relay("127.0.0.1:19795", CP_GRPC.parse()?).await?,
        })
    }
}
