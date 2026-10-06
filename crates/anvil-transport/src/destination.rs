//! Per-execution redirect authority. Resolution is consumed once and pinned
//! into the connector configuration and pool key, never checked then discarded.

use crate::dns;
use crate::http::HttpPlan;
use crate::recorder::Recorder;
use anvil_domain::execution::{FailureKind, Phase, PhaseStatus, TransportFailure};
use anvil_domain::settings::DnsOverride;
use parking_lot::Mutex;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Zone {
    Public,
    Private,
    Shared,
    LinkLocal,
    Loopback,
    /// 198.18.0.0/15: the benchmarking range fake-IP TUN proxies answer
    /// every name with. Never public.
    Benchmark,
}

impl Zone {
    fn bit(self) -> u8 {
        1 << self as u8
    }
}

const PUBLIC: u8 = 1 << Zone::Public as u8;

#[derive(Clone, Copy, Default)]
enum Origin {
    #[default]
    Unresolved,
    /// The zones of the original answer, and whether any hop so far could
    /// reach a public address. After a public hop, only public hops follow.
    Resolved {
        zones: u8,
        public_hop: bool,
    },
    OpaqueProxy,
}

/// One original destination's authority, shared by all of its attempts, TCP
/// fallback and redirects. The original grants the zones of its whole
/// resolved answer; a redirect stays within them or is wholly public.
#[derive(Default)]
pub struct DestinationPolicy {
    origin: Mutex<Origin>,
}

fn refused(message: &str) -> TransportFailure {
    TransportFailure::new(Phase::Connect, FailureKind::UnsupportedCombination, message).with_field("settings.redirects")
}

fn zone(ip: IpAddr) -> Option<Zone> {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            if ip.is_loopback() {
                Some(Zone::Loopback)
            } else if ip.is_link_local() {
                Some(Zone::LinkLocal)
            } else if ip.is_private() {
                Some(Zone::Private)
            } else if a == 100 && (64..=127).contains(&b) {
                Some(Zone::Shared)
            } else if a == 198 && (b == 18 || b == 19) {
                Some(Zone::Benchmark)
            } else if a == 0
                || a >= 224
                || (a == 192 && b == 0 && (c == 0 || c == 2))
                || (a == 192 && b == 88 && c == 99)
                || (a == 198 && b == 51 && c == 100)
                || (a == 203 && b == 0 && c == 113)
            {
                None
            } else {
                Some(Zone::Public)
            }
        }
        IpAddr::V6(ip) => {
            if let Some(mapped) = ip.to_ipv4_mapped() {
                return zone(IpAddr::V4(mapped));
            }
            let s = ip.segments();
            // Well-known NAT64 prefix (64:ff9b::/96): the embedded IPv4.
            if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
                let [.., a, b, c, d] = ip.octets();
                return zone(IpAddr::V4(Ipv4Addr::new(a, b, c, d)));
            }
            if ip.is_loopback() {
                Some(Zone::Loopback)
            } else if s[0] & 0xffc0 == 0xfe80 {
                Some(Zone::LinkLocal)
            } else if s[0] & 0xfe00 == 0xfc00 {
                Some(Zone::Private)
            } else if s[0] & 0xe000 == 0x2000
                && s[0] != 0x2002
                && !(s[0] == 0x2001 && (s[1] < 0x0200 || s[1] == 0x0db8))
                && !(s[0] == 0x3fff && s[1] < 0x1000)
                && !((s[4] == 0 || s[4] == 0x0200) && s[5] == 0x5efe)
            {
                Some(Zone::Public)
            } else {
                // Unspecified, multicast, site-local, IPv4-compatible,
                // translation/transition and reserved ranges fail closed.
                None
            }
        }
    }
}

impl DestinationPolicy {
    fn validate(&self, addrs: &[SocketAddr], redirected: bool) -> Result<(), TransportFailure> {
        let mut zones = 0;
        for addr in addrs {
            zones |= zone(addr.ip()).ok_or_else(|| refused("the destination resolves to an address that is not permitted unicast"))?.bit();
        }
        if zones == 0 {
            return Err(refused("the destination has no permitted unicast address"));
        }
        let mut origin = self.origin.lock();
        match *origin {
            // The original grants exactly the zones of its resolved answer.
            Origin::Unresolved if !redirected => *origin = Origin::Resolved { zones, public_hop: zones & PUBLIC != 0 },
            // A retry or fallback of the original stays in its zones or public ones.
            Origin::Resolved { zones: allowed, public_hop } if !redirected && zones & !(allowed | PUBLIC) == 0 => {
                *origin = Origin::Resolved { zones: allowed, public_hop: public_hop || zones & PUBLIC != 0 };
            }
            Origin::Resolved { zones: allowed, public_hop } if redirected => {
                if zones == PUBLIC {
                    *origin = Origin::Resolved { zones: allowed, public_hop: true };
                } else if zones & PUBLIC != 0 {
                    return Err(refused("the redirect resolves to mixed public and non-public network zones"));
                } else if public_hop {
                    return Err(refused("the redirect would return to a non-public network zone after a public hop"));
                } else if zones & !allowed != 0 {
                    return Err(refused("the redirect would leave the original destination's approved network zones"));
                }
            }
            _ => {
                return Err(refused("the redirect or retry would leave the original destination's approved network zones"));
            }
        }
        Ok(())
    }

    /// Resolve and pin before pool checkout, request dispatch or any dial.
    /// Called for every attempt, including the transport's unsent resend.
    pub(crate) async fn pin(
        &self,
        plan: &HttpPlan,
        redirected: bool,
        rec: &mut Recorder,
        deadline: Option<Instant>,
        cancel: &CancellationToken,
    ) -> Result<HttpPlan, TransportFailure> {
        if cancel.is_cancelled() {
            return Err(TransportFailure::new(Phase::Dns, FailureKind::Canceled, "canceled before destination resolution"));
        }
        if deadline.is_some_and(|d| Instant::now() >= d) {
            return Err(TransportFailure::new(
                Phase::Dns,
                FailureKind::TotalTimeout,
                "total deadline elapsed before destination resolution",
            )
            .with_deadline(plan.timeouts.total_ms));
        }
        if plan.proxy.is_some() {
            if redirected {
                return Err(refused("proxy redirects are unsupported: the resolved destination cannot be verified"));
            }
            // Preserve explicit original proxy requests. Even a later direct
            // NO_PROXY hop has no verified original zone to inherit.
            if let Some(ip) = dns::parse_literal(&plan.host)
                && zone(ip).is_none()
            {
                return Err(refused("the original destination is not a permitted unicast address"));
            }
            if crate::http::forward_proxy_routes_authority(plan.https, plan.proxy.as_ref().map(|p| p.kind)) {
                let authority = plan
                    .headers
                    .iter()
                    .find(|(n, _)| n == http::header::HOST)
                    .and_then(|(_, v)| v.to_str().ok())
                    .unwrap_or(&plan.authority);
                if let Some(host) = crate::http::authority_host(authority)
                    && let Some(ip) = dns::parse_literal(&host)
                    && zone(ip).is_none()
                {
                    return Err(refused("the proxy request authority is not a permitted unicast address"));
                }
            }
            *self.origin.lock() = Origin::OpaqueProxy;
            return Ok(plan.clone());
        }
        if redirected && matches!(*self.origin.lock(), Origin::OpaqueProxy | Origin::Unresolved) {
            return Err(refused("the original destination's resolved network zone is unavailable"));
        }
        let idx = rec.start(Phase::Dns);
        let remaining = deadline.map(|d| d.saturating_duration_since(Instant::now()));
        let resolution = tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(TransportFailure::new(
                Phase::Dns,
                FailureKind::Canceled,
                "canceled during destination resolution",
            )),
            _ = async {
                match remaining {
                    Some(d) => tokio::time::sleep(d).await,
                    None => std::future::pending().await,
                }
            } => Err(TransportFailure::new(
                Phase::Dns,
                FailureKind::TotalTimeout,
                "total deadline elapsed during destination resolution",
            )
            .with_deadline(plan.timeouts.total_ms)),
            r = dns::resolve(
                &plan.host,
                plan.port,
                &plan.dns,
                plan.timeouts.dns_ms.map(Duration::from_millis),
            ) => r,
        }?;
        self.validate(&resolution.addrs, redirected)?;
        rec.finish_with(
            idx,
            PhaseStatus::Completed,
            format!("validated {} destination; addresses pinned for dial and pool", resolution.source),
        );
        let mut pinned = plan.clone();
        // Literals already bind their address. DNS overrides bind the exact
        // answer for names, including CNAME/multi-record/Happy Eyeballs paths.
        if dns::parse_literal(&plan.host).is_none() {
            pinned.dns.overrides.retain(|o| !o.host.eq_ignore_ascii_case(&plan.host));
            pinned
                .dns
                .overrides
                .push(DnsOverride { host: plan.host.clone(), addresses: resolution.addrs.iter().map(|a| a.ip().to_string()).collect() });
        }
        Ok(pinned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connector::ProxyPlan;
    use crate::dns::DnsConfig;
    use crate::http::{EarlyDataIntent, HttpTransport};
    use crate::recorder::EventCtx;
    use anvil_domain::execution::{AttemptReason, DispatchState};
    use anvil_domain::settings::{HttpVersionPolicy, Limits, ResolverMode, Timeouts};
    use anvil_domain::tls::ProxyKind;
    use bytes::Bytes;
    use std::sync::Arc;

    fn addresses(values: &[&str]) -> Vec<SocketAddr> {
        values.iter().map(|v| SocketAddr::new(v.parse().unwrap(), 80)).collect()
    }

    fn public_origin() -> DestinationPolicy {
        let policy = DestinationPolicy::default();
        policy.validate(&addresses(&["8.8.8.8"]), false).unwrap();
        policy
    }

    fn plan(host: &str, port: u16) -> HttpPlan {
        HttpPlan {
            method: http::Method::POST,
            https: false,
            host: host.into(),
            port,
            authority: format!("{host}:{port}"),
            request_target: "/echo".into(),
            headers: vec![],
            body: Bytes::from_static(b"body-must-not-be-forwarded"),
            version: HttpVersionPolicy::Http1Only,
            timeouts: Timeouts::default(),
            limits: Limits::default(),
            keepalive: true,
            dns: DnsConfig::default(),
            proxy: None,
            tls: None,
            isolation: "destination-tests".into(),
            display_url: format!("http://{host}:{port}/echo"),
            proxy_header: None,
            proxy_header_withheld: None,
            early_data: EarlyDataIntent::Off,
            fence: None,
        }
    }

    #[test]
    fn public_authority_cannot_enter_any_privileged_or_invalid_zone() {
        let policy = public_origin();
        for ip in [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "224.0.0.1",
            "0.0.0.0",
            "240.0.0.1",
            "192.0.2.1",
            "198.18.0.1",
            "::1",
            "::",
            "fc00::1",
            "fe80::1",
            "ff02::1",
            "fec0::1",
            "::127.0.0.1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "64:ff9b::7f00:1",
            "2002:7f00:1::",
            "2001::1",
            "2001:db8::1",
            "3fff::1",
            "2001:4860::5efe:7f00:1",
        ] {
            assert!(policy.validate(&addresses(&[ip]), true).is_err(), "{ip}");
        }
        assert!(policy.validate(&addresses(&["1.1.1.1", "2606:4700::1111"]), true).is_ok());
        assert!(policy.validate(&addresses(&["::ffff:1.1.1.1"]), true).is_ok());
    }

    #[test]
    fn original_private_targets_keep_only_their_zones_and_public_authority() {
        for first in ["127.0.0.1", "10.0.0.1", "100.64.0.1", "169.254.1.1", "::1", "fc00::1"] {
            let policy = DestinationPolicy::default();
            policy.validate(&addresses(&[first]), false).unwrap();
            assert!(policy.validate(&addresses(&[first]), true).is_ok());
            assert!(policy.validate(&addresses(&["8.8.8.8"]), true).is_ok());
            let other = if zone(first.parse().unwrap()) == Some(Zone::Loopback) { "10.0.0.1" } else { "127.0.0.1" };
            assert!(policy.validate(&addresses(&[other]), true).is_err());
            assert!(policy.validate(&addresses(&[other]), false).is_err(), "retries inherit authority",);
        }
        let policy = DestinationPolicy::default();
        assert!(policy.validate(&addresses(&["224.0.0.1"]), false).is_err());
        assert!(policy.validate(&addresses(&["10.0.0.1", "224.0.0.1"]), false).is_err(), "every address must be permitted");
        // A mixed public answer is pinned as is, but its chain is public from the start.
        let policy = DestinationPolicy::default();
        policy.validate(&addresses(&["8.8.8.8", "127.0.0.1"]), false).unwrap();
        assert!(policy.validate(&addresses(&["127.0.0.1", "8.8.8.8"]), false).is_ok(), "a retry keeps the answer");
        assert!(policy.validate(&addresses(&["8.8.8.8", "127.0.0.1"]), true).is_err(), "a redirect cannot mix zones");
        assert!(policy.validate(&addresses(&["127.0.0.1"]), true).is_err());
        assert!(policy.validate(&addresses(&["8.8.4.4"]), true).is_ok());
    }

    #[test]
    fn mixed_zone_nat64_and_fake_ip_originals_are_authorized_and_bound_redirects() {
        assert_eq!(zone("64:ff9b::808:808".parse().unwrap()), Some(Zone::Public));
        assert_eq!(zone("64:ff9b::a00:1".parse().unwrap()), Some(Zone::Private));
        assert_eq!(zone("64:ff9b::7f00:1".parse().unwrap()), Some(Zone::Loopback));
        assert_eq!(zone("64:ff9b:1::808:808".parse().unwrap()), None, "only the well-known prefix embeds IPv4");
        let answers: [&[&str]; 5] = [
            // Tailscale MagicDNS: a CGNAT IPv4 and a ULA IPv6 address.
            &["100.101.102.103", "fd7a:115c:a1e0::1"],
            // mDNS `.local`: a private IPv4 and a link-local IPv6 address.
            &["192.168.1.20", "fe80::1"],
            // DNS64/NAT64: an IPv4-only public host behind the well-known prefix.
            &["64:ff9b::808:808"],
            &["64:ff9b::a00:1", "10.0.0.1"],
            // Fake-IP TUN proxies answer every name from 198.18.0.0/15.
            &["198.18.0.7"],
        ];
        for answer in answers {
            let policy = DestinationPolicy::default();
            policy.validate(&addresses(answer), false).unwrap();
            assert!(policy.validate(&addresses(answer), false).is_ok(), "{answer:?}: retries keep the answer");
            assert!(policy.validate(&addresses(answer), true).is_ok(), "{answer:?}: same-host redirects keep working");
            assert!(policy.validate(&addresses(&["127.0.0.1"]), true).is_err(), "{answer:?}: no new zone");
            assert!(policy.validate(&addresses(&["198.51.100.1"]), true).is_err(), "{answer:?}: invalid ranges stay refused");
        }
        let policy = DestinationPolicy::default();
        policy.validate(&addresses(&["100.101.102.103", "fd7a:115c:a1e0::1"]), false).unwrap();
        assert!(policy.validate(&addresses(&["fd7a:115c:a1e0::2"]), true).is_ok(), "a redirect within the zones");
        assert!(policy.validate(&addresses(&["192.168.1.1", "100.64.0.1"]), true).is_ok());
        assert!(policy.validate(&addresses(&["169.254.169.254"]), true).is_err(), "a zone the original lacked");
    }

    #[test]
    fn a_public_hop_taints_the_chain_for_every_non_public_zone() {
        for first in ["127.0.0.1", "10.0.0.1", "100.64.0.1", "169.254.1.1", "198.18.0.1", "fd00::1"] {
            let policy = DestinationPolicy::default();
            policy.validate(&addresses(&[first]), false).unwrap();
            policy.validate(&addresses(&["8.8.8.8"]), true).unwrap();
            assert!(policy.validate(&addresses(&[first]), true).is_err(), "{first}: no bounce back after a public hop");
            assert!(policy.validate(&addresses(&["1.1.1.1"]), true).is_ok(), "{first}: public hops continue");
        }
    }

    #[tokio::test]
    async fn overrides_mapped_addresses_and_cached_connections_cannot_bypass_public_policy() {
        crate::init();
        let fixture = anvil_fixtures::http::serve("127.0.0.1:0", None).await.unwrap();
        let transport = HttpTransport::new();
        let mut p = plan("sink.test", fixture.addr.port());
        p.dns.overrides.push(DnsOverride { host: p.host.clone(), addresses: vec!["127.0.0.1".into()] });
        let cancel = CancellationToken::new();
        let initial = transport.execute(&p, 0, AttemptReason::Initial, &EventCtx::none(), &cancel).await;
        assert!(initial[0].observation.failure.is_none());
        assert_eq!(fixture.log.count_requests(), 1);
        for values in [vec!["127.0.0.1"], vec!["::ffff:127.0.0.1"], vec!["8.8.8.8", "127.0.0.1"]] {
            p.dns.overrides[0].addresses = values.into_iter().map(str::to_string).collect();
            let result = transport
                .execute_attempt_guarded(
                    &p,
                    1,
                    AttemptReason::Redirect { status: 307 },
                    &EventCtx::none(),
                    &cancel,
                    Some((&public_origin(), true)),
                )
                .await;
            let obs = &result.outputs[0].observation;
            assert_eq!(obs.dispatch, DispatchState::NotDispatched);
            assert_eq!(obs.failure.as_ref().unwrap().kind, FailureKind::UnsupportedCombination);
            assert!(obs.connection.is_none(), "refused before pool checkout or dial");
            assert_eq!(obs.bytes.connection_bytes_written, None);
        }
        assert_eq!(fixture.log.count_requests(), 1, "no body reached the cached private socket");
        fixture.shutdown();
    }

    /// Real custom DNS responses; mutable answers model a resolver changing
    /// after origin approval. No real public endpoint or internet is contacted.
    async fn dns_server(answers: Arc<Mutex<Vec<Ipv4Addr>>>) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
                if n < 17 {
                    continue;
                }
                let mut end = 12;
                while end < n && buf[end] != 0 {
                    end += 1 + buf[end] as usize;
                }
                end += 5;
                if end > n {
                    continue;
                }
                let ips = if buf[end - 4..end - 2] == [0, 1] { answers.lock().clone() } else { vec![] };
                let mut reply = buf[..end].to_vec();
                reply[2..4].copy_from_slice(&[0x81, 0x80]);
                let cname = b"\x04sink\x04test\x00";
                let count = if ips.is_empty() { 0 } else { ips.len() + 1 };
                reply[6..8].copy_from_slice(&(count as u16).to_be_bytes());
                reply[8..12].fill(0);
                if !ips.is_empty() {
                    // CNAME plus terminal A records in the same actual answer.
                    reply.extend_from_slice(&[0xc0, 0x0c, 0, 5, 0, 1, 0, 0, 0, 0]);
                    reply.extend_from_slice(&(cname.len() as u16).to_be_bytes());
                    reply.extend_from_slice(cname);
                }
                for ip in ips {
                    reply.extend_from_slice(cname);
                    reply.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 0, 0, 4]);
                    reply.extend_from_slice(&ip.octets());
                }
                let _ = socket.send_to(&reply, peer).await;
            }
        });
        (address, task)
    }

    #[tokio::test]
    async fn changing_real_dns_is_checked_and_the_validated_answer_is_the_dial_answer() {
        crate::init();
        let fixture = anvil_fixtures::http::serve("127.0.0.1:0", None).await.unwrap();
        let answers = Arc::new(Mutex::new(vec!["8.8.8.8".parse().unwrap()]));
        let (dns_addr, task) = dns_server(answers.clone()).await;
        let mut p = plan("changing.test", fixture.addr.port());
        p.dns.resolver = ResolverMode::Custom { nameservers: vec![dns_addr.to_string()] };
        let policy = DestinationPolicy::default();
        let mut rec = Recorder::new(0, EventCtx::none());
        let cancel = CancellationToken::new();
        let pinned = policy.pin(&p, false, &mut rec, None, &cancel).await.unwrap();
        *answers.lock() = vec!["127.0.0.1".parse().unwrap()];
        let fixed = dns::resolve(&p.host, p.port, &pinned.dns, None).await.unwrap();
        assert_eq!(fixed.addrs, vec![SocketAddr::new("8.8.8.8".parse().unwrap(), p.port)],);
        let transport = HttpTransport::new();
        let result = transport
            .execute_attempt_guarded(&p, 1, AttemptReason::Redirect { status: 308 }, &EventCtx::none(), &cancel, Some((&policy, true)))
            .await;
        assert_eq!(result.outputs[0].observation.dispatch, DispatchState::NotDispatched);
        assert!(result.outputs[0].observation.failure.as_ref().unwrap().message.contains("zone"));
        assert!(result.outputs[0].observation.connection.is_none());
        assert_eq!(fixture.log.count_requests(), 0);
        // A fresh intentional loopback origin and its same-zone redirect work
        // through this same resolver and actual dial, and the connection is reused.
        let local = DestinationPolicy::default();
        for i in 0..2 {
            let r =
                transport.execute_attempt_guarded(&p, i, AttemptReason::Initial, &EventCtx::none(), &cancel, Some((&local, i > 0))).await;
            let obs = &r.outputs[0].observation;
            assert!(obs.failure.is_none(), "{:?}", obs.failure);
            assert_eq!(obs.connection.as_ref().unwrap().reused, i > 0);
        }
        assert_eq!(fixture.log.count_requests(), 2);
        task.abort();
        fixture.shutdown();
    }

    #[tokio::test]
    async fn a_mixed_zone_answer_is_dialed_and_its_rotations_reuse_the_connection() {
        crate::init();
        let fixture = anvil_fixtures::http::serve("127.0.0.1:0", None).await.unwrap();
        let transport = HttpTransport::new();
        let mut p = plan("tailnet.test", fixture.addr.port());
        let cancel = CancellationToken::new();
        // One answer set in the rotated orders a round-robin resolver returns;
        // the reachable loopback address is first, so the dial reaches the fixture.
        let rotations = [["127.0.0.1", "100.64.0.1", "fd7a:115c:a1e0::1"], ["127.0.0.1", "fd7a:115c:a1e0::1", "100.64.0.1"]];
        for (i, answer) in rotations.into_iter().enumerate() {
            p.dns.overrides = vec![DnsOverride { host: p.host.clone(), addresses: answer.into_iter().map(str::to_string).collect() }];
            let policy = DestinationPolicy::default();
            let r =
                transport.execute_attempt_guarded(&p, 0, AttemptReason::Initial, &EventCtx::none(), &cancel, Some((&policy, false))).await;
            let obs = &r.outputs[0].observation;
            assert!(obs.failure.is_none(), "{:?}", obs.failure);
            assert_eq!(obs.connection.as_ref().unwrap().reused, i > 0, "the same address set keeps its pooled connection");
        }
        assert_eq!(fixture.log.count_requests(), 2);
        fixture.shutdown();
    }

    #[tokio::test]
    async fn a_redirect_through_a_public_hop_cannot_return_to_loopback() {
        crate::init();
        let fixture = anvil_fixtures::http::serve("127.0.0.1:0", None).await.unwrap();
        let transport = HttpTransport::new();
        let p = plan("127.0.0.1", fixture.addr.port());
        let cancel = CancellationToken::new();
        let policy = DestinationPolicy::default();
        let r = transport.execute_attempt_guarded(&p, 0, AttemptReason::Initial, &EventCtx::none(), &cancel, Some((&policy, false))).await;
        assert!(r.outputs[0].observation.failure.is_none());
        // The loopback origin redirects to a public host (validated only; nothing
        // public is contacted), which redirects back to the loopback listener.
        policy.validate(&addresses(&["93.184.216.34"]), true).unwrap();
        let r = transport
            .execute_attempt_guarded(&p, 2, AttemptReason::Redirect { status: 302 }, &EventCtx::none(), &cancel, Some((&policy, true)))
            .await;
        let obs = &r.outputs[0].observation;
        assert_eq!(obs.dispatch, DispatchState::NotDispatched);
        assert!(obs.failure.as_ref().unwrap().message.contains("after a public hop"));
        assert!(obs.connection.is_none(), "refused before pool checkout or dial");
        assert_eq!(fixture.log.count_requests(), 1);
        fixture.shutdown();
    }

    #[tokio::test]
    async fn every_remote_dns_proxy_mode_refuses_redirects_before_proxy_traffic() {
        for kind in [ProxyKind::Http, ProxyKind::Https, ProxyKind::Socks5, ProxyKind::Hbone] {
            let mut p = plan("sink.test", 80);
            p.proxy = Some(ProxyPlan {
                kind,
                host: "127.0.0.1".into(),
                port: 9,
                credentials: None,
                tls: None,
                label: "test-proxy".into(),
                connect_headers: vec![],
            });
            let policy = public_origin();
            let transport = HttpTransport::new();
            let r = transport
                .execute_attempt_guarded(
                    &p,
                    1,
                    AttemptReason::Redirect { status: 307 },
                    &EventCtx::none(),
                    &CancellationToken::new(),
                    Some((&policy, true)),
                )
                .await;
            assert!(r.outputs[0].observation.connection.is_none());
            assert!(r.outputs[0].observation.failure.as_ref().unwrap().message.contains("proxy"));
        }
    }

    #[tokio::test]
    async fn quic_and_cancellation_deadlines_cannot_bypass_destination_validation() {
        let policy = public_origin();
        let mut p = plan("127.0.0.1", 9);
        p.https = true;
        let cancel = CancellationToken::new();
        let h3 = crate::h3::H3Transport::new();
        let r = h3
            .execute_attempt_guarded(&p, 1, AttemptReason::Redirect { status: 307 }, &EventCtx::none(), &cancel, Some((&policy, true)))
            .await;
        assert!(r.outputs[0].observation.connection.is_none());
        assert_eq!(r.outputs[0].observation.dispatch, DispatchState::NotDispatched);
        assert_eq!(r.outputs[0].observation.failure.as_ref().unwrap().kind, FailureKind::UnsupportedCombination,);
        let mut rec = Recorder::new(0, EventCtx::none());
        let error = policy.pin(&p, true, &mut rec, Some(Instant::now()), &cancel).await.err().unwrap();
        assert_eq!(error.kind, FailureKind::TotalTimeout);
        cancel.cancel();
        let error = policy.pin(&p, true, &mut rec, None, &cancel).await.err().unwrap();
        assert_eq!(error.kind, FailureKind::Canceled);
        assert!(rec.phases.is_empty(), "no resolver or dial started");
    }
}
