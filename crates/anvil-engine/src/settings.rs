//! Deterministic settings resolution with per-field provenance:
//! app defaults → workspace → ancestor folders → request → run override.

use anvil_domain::settings::*;

fn src(sources: &mut Vec<SettingSource>, field: &str, layer: &str) {
    sources.retain(|s| s.field != field);
    sources.push(SettingSource { field: field.into(), layer: layer.into() });
}

pub fn resolve(layers: &[(String, SettingsOverrides)]) -> EffectiveSettings {
    let mut e = EffectiveSettings::default();
    let mut sources = Vec::new();
    for (label, o) in layers {
        if let Some(v) = o.http_version {
            e.http_version = v;
            src(&mut sources, "http_version", label);
        }
        if let Some(t) = &o.timeouts {
            macro_rules! t {
                ($f:ident) => {
                    if let Some(v) = t.$f {
                        e.timeouts.$f = v;
                        src(&mut sources, concat!("timeouts.", stringify!($f)), label);
                    }
                };
            }
            t!(dns_ms);
            t!(connect_ms);
            t!(tls_handshake_ms);
            t!(request_write_ms);
            t!(response_headers_ms);
            t!(body_idle_ms);
            t!(total_ms);
        }
        if let Some(v) = o.redirects {
            e.redirects = v;
            src(&mut sources, "redirects", label);
        }
        if let Some(v) = o.retries {
            e.retries = v;
            src(&mut sources, "retries", label);
        }
        if let Some(v) = o.ip_preference {
            e.ip_preference = v;
            src(&mut sources, "ip_preference", label);
        }
        if let Some(v) = &o.resolver {
            e.resolver = v.clone();
            src(&mut sources, "resolver", label);
        }
        if !o.dns_overrides.is_empty() {
            // Overrides accumulate; a later layer's entry for the same host wins.
            for d in &o.dns_overrides {
                e.dns_overrides.retain(|x| !x.host.eq_ignore_ascii_case(&d.host));
                e.dns_overrides.push(d.clone());
            }
            src(&mut sources, "dns_overrides", label);
        }
        if let Some(p) = o.proxy_profile_id {
            e.proxy_profile_id = match p {
                ProxySelection::None => None,
                ProxySelection::Profile { id } => Some(id),
            };
            src(&mut sources, "proxy", label);
        }
        if let Some(v) = o.tls_profile_id {
            e.tls_profile_id = Some(v);
            src(&mut sources, "tls_profile", label);
        }
        if let Some(v) = o.limits {
            e.limits = v;
            src(&mut sources, "limits", label);
        }
        if let Some(v) = o.decompress {
            e.decompress = v;
            src(&mut sources, "decompress", label);
        }
        if let Some(v) = o.cookies {
            e.cookies = v;
            src(&mut sources, "cookies", label);
        }
        if let Some(v) = o.keepalive {
            e.keepalive = v;
            src(&mut sources, "keepalive", label);
        }
        if let Some(v) = o.infer_content_type {
            e.infer_content_type = v;
            src(&mut sources, "infer_content_type", label);
        }
        if let Some(v) = o.integration_profile_id {
            e.integration_profile_id = Some(v);
            src(&mut sources, "integration_profile", label);
        }
    }
    e.sources = sources;
    e
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn later_layers_override_with_provenance() {
        let ws = SettingsOverrides { http_version: Some(HttpVersionPolicy::Http1Only), ..Default::default() };
        let folder = SettingsOverrides {
            timeouts: Some(TimeoutOverrides { connect_ms: Some(Some(123)), ..Default::default() }),
            ..Default::default()
        };
        let req = SettingsOverrides { http_version: Some(HttpVersionPolicy::Http2Only), ..Default::default() };
        let e = resolve(&[("workspace".into(), ws), ("folder:api".into(), folder), ("request".into(), req)]);
        assert_eq!(e.http_version, HttpVersionPolicy::Http2Only);
        assert_eq!(e.timeouts.connect_ms, Some(123));
        assert_eq!(e.timeouts.dns_ms, Timeouts::default().dns_ms);
        let src = |f: &str| e.sources.iter().find(|s| s.field == f).map(|s| s.layer.clone());
        assert_eq!(src("http_version").as_deref(), Some("request"));
        assert_eq!(src("timeouts.connect_ms").as_deref(), Some("folder:api"));
    }
}
