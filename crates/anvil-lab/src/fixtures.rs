//! Fixture sets per lab profile (ports from docs/audit/gateway-lab-config.md).

use anvil_fixtures::dns::{self, DnsFixture, DnsMode};
use anvil_fixtures::http::{self, Fixture};
use anvil_fixtures::raw::{self, RawFixture, RawMode};
use anyhow::Result;

pub struct CoreFixtures {
    pub ok: Fixture,
    pub upload_stall: RawFixture,
    pub header_stall: RawFixture,
    pub body_stall: RawFixture,
    pub reset: RawFixture,
    pub short_body: RawFixture,
    pub oversize: Fixture,
    pub post_dispatch: RawFixture,
    pub breaker: Fixture,
    pub app403: Fixture,
    pub app500: Fixture,
    pub degraded: Fixture,
    pub dns: DnsFixture,
}

impl CoreFixtures {
    pub async fn start() -> Result<Self> {
        Ok(CoreFixtures {
            ok: http::serve("127.0.0.1:19001", None).await?,
            upload_stall: raw::serve("127.0.0.1:19009", RawMode::ReadThenStall, None).await?,
            header_stall: raw::serve("127.0.0.1:19010", RawMode::ReadThenStall, None).await?,
            body_stall: raw::serve("127.0.0.1:19011", RawMode::HeadersThenStall { sent: 16 }, None).await?,
            reset: raw::serve("127.0.0.1:19012", RawMode::ResetMidBody { sent: 2048 }, None).await?,
            short_body: raw::serve("127.0.0.1:19013", RawMode::ShortBody { declared: 1000, sent: 100 }, None).await?,
            oversize: http::serve("127.0.0.1:19014", None).await?,
            post_dispatch: raw::serve("127.0.0.1:19020", RawMode::ResetAfterRequest, None).await?,
            breaker: http::serve("127.0.0.1:19021", None).await?,
            app403: http::serve("127.0.0.1:19022", None).await?,
            app500: http::serve("127.0.0.1:19023", None).await?,
            degraded: http::serve("127.0.0.1:19024", None).await?,
            dns: dns::serve("127.0.0.1:19053", DnsMode::NxDomain).await?,
        })
    }
}
