//! Client-leg name resolution with typed outcomes.
//!
//! * `System` uses the OS resolver (`getaddrinfo`) on a blocking thread. The
//!   OS call cannot be interrupted; on timeout Anvil stops waiting and records
//!   `dns_timeout` while the OS call finishes in the background.
//! * `Custom` queries configured DNS servers directly (hickory), which yields
//!   precise NXDOMAIN / NODATA / SERVFAIL / timeout distinctions.
//! * Overrides and IP literals skip resolution and are recorded as such.

use anvil_domain::execution::{FailureKind, Phase, TransportFailure};
use anvil_domain::settings::{DnsOverride, IpPreference, ResolverMode};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Resolution {
    pub addrs: Vec<SocketAddr>,
    /// `literal`, `override`, `system`, `custom_resolver`.
    pub source: &'static str,
}

#[derive(Debug, Clone, Default)]
pub struct DnsConfig {
    pub resolver: ResolverMode,
    pub overrides: Vec<DnsOverride>,
    pub ip_preference: IpPreference,
}

pub fn parse_literal(host: &str) -> Option<IpAddr> {
    let h = host.trim_start_matches('[').trim_end_matches(']');
    h.parse::<IpAddr>().ok()
}

/// Order/filter addresses per the IP preference (stable within a family).
pub fn apply_preference(mut addrs: Vec<SocketAddr>, pref: IpPreference) -> Vec<SocketAddr> {
    match pref {
        IpPreference::System => addrs,
        IpPreference::Ipv4Only => addrs.into_iter().filter(|a| a.is_ipv4()).collect(),
        IpPreference::Ipv6Only => addrs.into_iter().filter(|a| a.is_ipv6()).collect(),
        IpPreference::PreferIpv4 => {
            addrs.sort_by_key(|a| if a.is_ipv4() { 0 } else { 1 });
            addrs
        }
        IpPreference::PreferIpv6 => {
            addrs.sort_by_key(|a| if a.is_ipv6() { 0 } else { 1 });
            addrs
        }
    }
}

/// The pool-key form of a DNS configuration. Each override's addresses are
/// sorted and deduplicated, so a stable answer set that a round-robin resolver
/// returns in rotated order keeps reusing its connections. Dialing still uses
/// the configured order.
pub(crate) fn pool_key(cfg: &DnsConfig) -> String {
    let mut overrides = Vec::new();
    for o in &cfg.overrides {
        let mut addresses: Vec<&str> = o.addresses.iter().map(String::as_str).collect();
        addresses.sort_unstable();
        addresses.dedup();
        overrides.push((o.host.as_str(), addresses));
    }
    format!("{:?}{:?}{:?}", cfg.resolver, overrides, cfg.ip_preference)
}

/// Fixed addresses used by the connector without contacting a resolver.
/// `None` means send-time DNS can change the addresses; a preflight must not
/// treat a one-time lookup as proof of locality.
pub fn fixed_resolution(host: &str, port: u16, cfg: &DnsConfig) -> Option<Result<Resolution, TransportFailure>> {
    if let Some(ip) = parse_literal(host) {
        return Some(Ok(Resolution { addrs: vec![SocketAddr::new(ip, port)], source: "literal" }));
    }
    if let Some(ov) = cfg.overrides.iter().find(|o| o.host.eq_ignore_ascii_case(host)) {
        let mut addrs = Vec::new();
        for a in &ov.addresses {
            match parse_literal(a) {
                Some(ip) => addrs.push(SocketAddr::new(ip, port)),
                None => {
                    return Some(Err(TransportFailure::new(
                        Phase::Prepare,
                        FailureKind::InvalidUrl,
                        format!("DNS override for {host} contains a non-IP address: {a}"),
                    )
                    .with_field("settings.dns_overrides")));
                }
            }
        }
        let addrs = apply_preference(addrs, cfg.ip_preference);
        return Some(Ok(Resolution { addrs, source: "override" }));
    }
    None
}

pub async fn resolve(host: &str, port: u16, cfg: &DnsConfig, timeout: Option<Duration>) -> Result<Resolution, TransportFailure> {
    if let Some(fixed) = fixed_resolution(host, port, cfg) {
        return fixed;
    }

    let fut = async {
        match &cfg.resolver {
            ResolverMode::System => resolve_system(host, port).await,
            ResolverMode::Custom { nameservers } => resolve_custom(host, port, nameservers, timeout).await,
        }
    };
    let res = match timeout {
        Some(t) => match tokio::time::timeout(t, fut).await {
            Ok(r) => r,
            Err(_) => Err(TransportFailure::new(
                Phase::Dns,
                FailureKind::DnsTimeout,
                format!("name resolution for {host} did not complete within {} ms", t.as_millis()),
            )
            .with_deadline(Some(t.as_millis() as u64))),
        },
        None => fut.await,
    }?;
    let addrs = apply_preference(res.addrs, cfg.ip_preference);
    if addrs.is_empty() {
        return Err(TransportFailure::new(
            Phase::Dns,
            FailureKind::DnsNoRecords,
            format!("{host} resolved, but no addresses match the IP preference {:?}", cfg.ip_preference),
        ));
    }
    Ok(Resolution { addrs, source: res.source })
}

async fn resolve_system(host: &str, port: u16) -> Result<Resolution, TransportFailure> {
    let h = host.to_string();
    let joined = tokio::task::spawn_blocking(move || {
        let hints = dns_lookup::AddrInfoHints { socktype: dns_lookup::SockType::Stream.into(), ..Default::default() };
        dns_lookup::getaddrinfo(Some(&h), None, Some(hints)).map(|it| {
            let mut v: Vec<IpAddr> = Vec::new();
            for ai in it.flatten() {
                let ip = ai.sockaddr.ip();
                if !v.contains(&ip) {
                    v.push(ip);
                }
            }
            v
        })
    })
    .await;
    match joined {
        Ok(Ok(ips)) => system_answer(host, port, ips),
        Ok(Err(e)) => {
            use dns_lookup::LookupErrorKind as L;
            let kind = match e.kind() {
                // getaddrinfo reports both NXDOMAIN and NODATA as EAI_NONAME on
                // several platforms; the system resolver cannot separate them.
                L::NoName => FailureKind::DnsNoSuchHost,
                L::NoData => FailureKind::DnsNoRecords,
                L::Again => FailureKind::DnsServerFailure,
                L::Fail => FailureKind::DnsServerFailure,
                _ => FailureKind::DnsOther,
            };
            let io: std::io::Error = e.into();
            let mut f = TransportFailure::new(Phase::Dns, kind, format!("system resolver could not resolve {host}: {io}"));
            f.io_error_kind = Some(format!("{:?}", io.kind()));
            Err(f)
        }
        Err(join) => Err(TransportFailure::new(Phase::Dns, FailureKind::Internal, format!("resolver task failed: {join}"))),
    }
}

fn system_answer(host: &str, port: u16, ips: Vec<IpAddr>) -> Result<Resolution, TransportFailure> {
    let ips = if is_localhost_name(host) { loopback_addresses(host, ips)? } else { ips };
    if ips.is_empty() {
        Err(TransportFailure::new(Phase::Dns, FailureKind::DnsNoRecords, format!("{host} has no address records")))
    } else {
        Ok(Resolution { addrs: ips.into_iter().map(|ip| SocketAddr::new(ip, port)).collect(), source: "system" })
    }
}

pub fn is_localhost_name(host: &str) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let host = host.strip_suffix('.').unwrap_or(host);
    host.eq_ignore_ascii_case("localhost")
        || host.rsplit_once('.').is_some_and(|(rest, tld)| !rest.is_empty() && tld.eq_ignore_ascii_case("localhost"))
}

fn loopback_addresses(host: &str, ips: Vec<IpAddr>) -> Result<Vec<IpAddr>, TransportFailure> {
    let loopback: Vec<IpAddr> = ips.into_iter().filter(|ip| is_loopback(*ip)).collect();
    if loopback.is_empty() {
        return Err(TransportFailure::new(
            Phase::Dns,
            FailureKind::DnsNoRecords,
            format!("system resolver returned records for {host}, but none were loopback; use a DNS override for non-loopback targets"),
        ));
    }
    Ok(loopback)
}

pub fn is_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_loopback(),
        IpAddr::V6(ip) => ip.is_loopback() || ip.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback()),
    }
}

async fn resolve_custom(host: &str, port: u16, nameservers: &[String], timeout: Option<Duration>) -> Result<Resolution, TransportFailure> {
    use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolverConfig, ResolverOpts};
    use hickory_resolver::net::runtime::TokioRuntimeProvider;
    let mut config = ResolverConfig::default();
    for ns in nameservers {
        let sa: SocketAddr = match ns.parse::<SocketAddr>() {
            Ok(s) => s,
            Err(_) => match ns.parse::<IpAddr>() {
                Ok(ip) => SocketAddr::new(ip, 53),
                Err(_) => {
                    return Err(TransportFailure::new(
                        Phase::Prepare,
                        FailureKind::InvalidUrl,
                        format!("custom nameserver '{ns}' is not ip or ip:port"),
                    )
                    .with_field("settings.resolver.nameservers"));
                }
            },
        };
        let mut udp = ConnectionConfig::udp();
        udp.port = sa.port();
        let mut tcp = ConnectionConfig::tcp();
        tcp.port = sa.port();
        config.add_name_server(NameServerConfig::new(sa.ip(), true, vec![udp, tcp]));
    }
    let mut opts = ResolverOpts::default();
    if let Some(t) = timeout {
        opts.timeout = t;
    }
    opts.attempts = 1;
    opts.cache_size = 0;
    let resolver = hickory_resolver::Resolver::builder_with_config(config, TokioRuntimeProvider::default())
        .with_options(opts)
        .build()
        .map_err(|e| TransportFailure::new(Phase::Dns, FailureKind::DnsOther, format!("resolver setup failed: {e}")))?;
    let fqdn = if host.ends_with('.') { host.to_string() } else { format!("{host}.") };
    match resolver.lookup_ip(fqdn.as_str()).await {
        Ok(lookup) => {
            let addrs: Vec<SocketAddr> = lookup.iter().map(|ip| SocketAddr::new(ip, port)).collect();
            if addrs.is_empty() {
                Err(TransportFailure::new(Phase::Dns, FailureKind::DnsNoRecords, format!("{host} has no A/AAAA records")))
            } else {
                Ok(Resolution { addrs, source: "custom_resolver" })
            }
        }
        Err(e) => {
            use hickory_resolver::net::NetError;
            let kind = if e.is_nx_domain() {
                FailureKind::DnsNoSuchHost
            } else if e.is_no_records_found() {
                FailureKind::DnsNoRecords
            } else {
                match &e {
                    NetError::Timeout => FailureKind::DnsTimeout,
                    NetError::Dns(_) => FailureKind::DnsServerFailure,
                    _ => FailureKind::DnsOther,
                }
            };
            Err(TransportFailure::new(Phase::Dns, kind, format!("DNS query for {host} failed: {e}")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{is_localhost_name, is_loopback, system_answer};
    use std::net::{IpAddr, SocketAddr};

    #[test]
    fn localhost_name_matching_handles_case_and_root_dot_without_partial_matches() {
        for host in ["localhost", "LOCALHOST", "api.localhost", "API.LOCALHOST", "api.localhost."] {
            assert!(is_localhost_name(host), "expected {host} to be a localhost name");
        }

        for host in ["notlocalhost", "localhost.example.com", ".localhost", "localhost.."] {
            assert!(!is_localhost_name(host), "expected {host} not to be a localhost name");
        }
    }

    #[test]
    fn localhost_system_answers_keep_only_loopback_addresses() {
        let answer = system_answer(
            "API.LOCALHOST.",
            8080,
            vec!["192.0.2.10".parse().unwrap(), "127.0.0.1".parse().unwrap(), "::1".parse().unwrap()],
        )
        .unwrap();

        assert_eq!(answer.addrs, vec![SocketAddr::new("127.0.0.1".parse().unwrap(), 8080), SocketAddr::new("::1".parse().unwrap(), 8080),]);
    }

    #[test]
    fn localhost_system_answers_without_loopback_are_rejected() {
        let error = system_answer("api.localhost", 8080, vec!["192.0.2.10".parse().unwrap()]).unwrap_err();

        assert!(error.message.contains("records for api.localhost, but none were loopback"));
        assert!(error.message.contains("use a DNS override"));
    }

    #[test]
    fn non_localhost_system_answers_keep_public_addresses() {
        let answer = system_answer("example.com", 443, vec!["192.0.2.10".parse().unwrap()]).unwrap();

        assert_eq!(answer.addrs, vec![SocketAddr::new("192.0.2.10".parse().unwrap(), 443)]);
    }

    #[test]
    fn loopback_classification_includes_ipv4_mapped_ipv6_only_for_loopback() {
        assert!(is_loopback("::ffff:127.0.0.1".parse::<IpAddr>().unwrap()));
        assert!(!is_loopback("0.0.0.0".parse().unwrap()));
        assert!(!is_loopback("::".parse().unwrap()));
    }
}
