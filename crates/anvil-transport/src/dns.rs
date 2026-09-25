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

fn parse_literal(host: &str) -> Option<IpAddr> {
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

pub async fn resolve(
    host: &str,
    port: u16,
    cfg: &DnsConfig,
    timeout: Option<Duration>,
) -> Result<Resolution, TransportFailure> {
    if let Some(ip) = parse_literal(host) {
        return Ok(Resolution {
            addrs: vec![SocketAddr::new(ip, port)],
            source: "literal",
        });
    }
    if let Some(ov) = cfg
        .overrides
        .iter()
        .find(|o| o.host.eq_ignore_ascii_case(host))
    {
        let mut addrs = Vec::new();
        for a in &ov.addresses {
            match parse_literal(a) {
                Some(ip) => addrs.push(SocketAddr::new(ip, port)),
                None => {
                    return Err(TransportFailure::new(
                        Phase::Prepare,
                        FailureKind::InvalidUrl,
                        format!("DNS override for {host} contains a non-IP address: {a}"),
                    )
                    .with_field("settings.dns_overrides"));
                }
            }
        }
        let addrs = apply_preference(addrs, cfg.ip_preference);
        return Ok(Resolution {
            addrs,
            source: "override",
        });
    }

    let fut = async {
        match &cfg.resolver {
            ResolverMode::System => resolve_system(host, port).await,
            ResolverMode::Custom { nameservers } => {
                resolve_custom(host, port, nameservers, timeout).await
            }
        }
    };
    let res = match timeout {
        Some(t) => match tokio::time::timeout(t, fut).await {
            Ok(r) => r,
            Err(_) => Err(TransportFailure::new(
                Phase::Dns,
                FailureKind::DnsTimeout,
                format!(
                    "name resolution for {host} did not complete within {} ms",
                    t.as_millis()
                ),
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
            format!(
                "{host} resolved, but no addresses match the IP preference {:?}",
                cfg.ip_preference
            ),
        ));
    }
    Ok(Resolution {
        addrs,
        source: res.source,
    })
}

async fn resolve_system(host: &str, port: u16) -> Result<Resolution, TransportFailure> {
    let h = host.to_string();
    let joined = tokio::task::spawn_blocking(move || {
        let hints = dns_lookup::AddrInfoHints {
            socktype: dns_lookup::SockType::Stream.into(),
            ..Default::default()
        };
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
        Ok(Ok(ips)) => {
            if ips.is_empty() {
                Err(TransportFailure::new(
                    Phase::Dns,
                    FailureKind::DnsNoRecords,
                    format!("{host} has no address records"),
                ))
            } else {
                Ok(Resolution {
                    addrs: ips
                        .into_iter()
                        .map(|ip| SocketAddr::new(ip, port))
                        .collect(),
                    source: "system",
                })
            }
        }
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
            let mut f = TransportFailure::new(
                Phase::Dns,
                kind,
                format!("system resolver could not resolve {host}: {io}"),
            );
            f.io_error_kind = Some(format!("{:?}", io.kind()));
            Err(f)
        }
        Err(join) => Err(TransportFailure::new(
            Phase::Dns,
            FailureKind::Internal,
            format!("resolver task failed: {join}"),
        )),
    }
}

async fn resolve_custom(
    host: &str,
    port: u16,
    nameservers: &[String],
    timeout: Option<Duration>,
) -> Result<Resolution, TransportFailure> {
    use hickory_resolver::config::{
        ConnectionConfig, NameServerConfig, ResolverConfig, ResolverOpts,
    };
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
    let resolver =
        hickory_resolver::Resolver::builder_with_config(config, TokioRuntimeProvider::default())
            .with_options(opts)
            .build()
            .map_err(|e| {
                TransportFailure::new(
                    Phase::Dns,
                    FailureKind::DnsOther,
                    format!("resolver setup failed: {e}"),
                )
            })?;
    let fqdn = if host.ends_with('.') {
        host.to_string()
    } else {
        format!("{host}.")
    };
    match resolver.lookup_ip(fqdn.as_str()).await {
        Ok(lookup) => {
            let addrs: Vec<SocketAddr> =
                lookup.iter().map(|ip| SocketAddr::new(ip, port)).collect();
            if addrs.is_empty() {
                Err(TransportFailure::new(
                    Phase::Dns,
                    FailureKind::DnsNoRecords,
                    format!("{host} has no A/AAAA records"),
                ))
            } else {
                Ok(Resolution {
                    addrs,
                    source: "custom_resolver",
                })
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
            Err(TransportFailure::new(
                Phase::Dns,
                kind,
                format!("DNS query for {host} failed: {e}"),
            ))
        }
    }
}
