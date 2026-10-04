//! Finite response state. Matching and expiry remain cookie_store's RFC 6265 rules.
//! A flat collection avoids unaccounted empty domain/path maps and LRU tombstones.

use cookie_store::Cookie;
use std::collections::BTreeMap;

pub(crate) const MAX_SET_COOKIE_BYTES: usize = 4096;
const MAX_ITEM_BYTES: usize = 8192;
const MAX_SITE_COUNT: usize = 180;
const MAX_SITE_BYTES: usize = 128 * 1024;
const MAX_JAR_COUNT: usize = 3000;
const MAX_JAR_BYTES: usize = 2 * 1024 * 1024;
pub(crate) const MAX_COOKIE_HEADER_BYTES: usize = 8192;

struct Entry {
    cookie: Cookie<'static>,
    site: String,
    bytes: usize,
    used: u64,
    created: u64,
}

#[derive(Default)]
pub(crate) struct BoundedJar {
    entries: Vec<Entry>,
    clock: u64,
}

impl BoundedJar {
    pub(crate) fn purge_expired(&mut self) {
        self.entries.retain(|e| !e.cookie.is_expired());
    }

    fn tick(&mut self) -> u64 {
        if self.clock == u64::MAX {
            // Rebase only ordering metadata, preserving ties and creation order.
            let mut stamps: Vec<u64> = self
                .entries
                .iter()
                .flat_map(|e| [e.used, e.created])
                .collect();
            stamps.sort_unstable();
            stamps.dedup();
            for e in &mut self.entries {
                e.used = stamps.binary_search(&e.used).unwrap() as u64;
                e.created = stamps.binary_search(&e.created).unwrap() as u64;
            }
            self.clock = stamps.len() as u64;
        }
        self.clock += 1;
        self.clock
    }

    pub(crate) fn insert(&mut self, cookie: Cookie<'static>, wire_bytes: usize) {
        self.purge_expired();
        let Some(domain) = cookie.domain.as_cow() else {
            return;
        };
        let site = site_key(&domain);
        // raw_cookie retains its serialized backing string, while the parsed
        // domain/path and site are owned separately. Charge fixed metadata too.
        let bytes = wire_bytes
            + domain.len()
            + cookie.path.as_ref().len()
            + site.len()
            + std::mem::size_of::<Entry>();
        if bytes > MAX_ITEM_BYTES {
            return;
        }
        let used = self.tick();
        let old = self.entries.iter().position(|e| {
            e.cookie.domain.as_cow().as_deref() == Some(domain.as_ref())
                && e.cookie.path.as_ref() == cookie.path.as_ref()
                && e.cookie.name() == cookie.name()
        });
        let created = old.map(|i| self.entries.remove(i).created);
        // An expired replacement removes the same tuple immediately; never keep
        // the expired object as cookie_store::insert would until a later sweep.
        if cookie.is_expired() {
            return;
        }
        loop {
            let (count, total) = self.site_usage(&site);
            if count < MAX_SITE_COUNT && total + bytes <= MAX_SITE_BYTES {
                break;
            }
            self.evict(&site);
        }
        while self.entries.len() >= MAX_JAR_COUNT || self.bytes() + bytes > MAX_JAR_BYTES {
            // Fair accounting: reclaim from the largest retained site, then
            // its LRU entry. Deterministic lexical tie-breaking prevents a peer
            // from winning through hash iteration or many domain/path keys.
            let mut sites: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
            for e in &self.entries {
                let usage = sites.entry(&e.site).or_default();
                usage.0 += e.bytes;
                usage.1 += 1;
            }
            let largest = sites
                .into_iter()
                .max_by_key(|(s, usage)| (*usage, *s))
                .unwrap()
                .0
                .to_string();
            self.evict(&largest);
        }
        self.entries.push(Entry {
            cookie,
            site,
            bytes,
            used,
            created: created.unwrap_or(used),
        });
    }

    fn bytes(&self) -> usize {
        self.entries.iter().map(|e| e.bytes).sum()
    }

    fn site_usage(&self, site: &str) -> (usize, usize) {
        self.entries
            .iter()
            .filter(|e| e.site == site)
            .fold((0, 0), |(n, b), e| (n + 1, b + e.bytes))
    }

    fn evict(&mut self, site: &str) {
        let i = self.entries
            .iter()
            .enumerate()
            .filter(|(_, e)| e.site == site)
            .min_by_key(|(_, e)| (e.used, e.created, e.cookie.name()))
            .map(|(i, _)| i)
            .unwrap();
        self.entries.remove(i);
    }

    pub(crate) fn header(&mut self, url: &url::Url) -> Option<String> {
        self.purge_expired();
        let mut indices: Vec<usize> = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, e)| e.cookie.matches(url))
            .map(|(i, _)| i)
            .collect();
        indices.sort_by_key(|i| {
            let e = &self.entries[*i];
            (std::cmp::Reverse(e.cookie.path.as_ref().len()), e.created, *i)
        });
        // Count before reserving or serializing any pair. Skip whole cookies;
        // never truncate a value into a different credential.
        let mut selected = Vec::new();
        let mut bytes = 0;
        for i in indices {
            let e = &self.entries[i];
            let pair = e.cookie.name().len() + 1 + e.cookie.value().len();
            let added = pair + if selected.is_empty() { 0 } else { 2 };
            if bytes + added <= MAX_COOKIE_HEADER_BYTES {
                selected.push(i);
                bytes += added;
            }
        }
        if selected.is_empty() {
            return None;
        }
        let used = self.tick();
        let mut header = String::with_capacity(bytes);
        for i in selected {
            let e = &mut self.entries[i];
            if !header.is_empty() {
                header.push_str("; ");
            }
            header.push_str(e.cookie.name());
            header.push('=');
            header.push_str(e.cookie.value());
            e.used = used;
        }
        Some(header)
    }
}

fn site_key(domain: &str) -> String {
    let domain = domain.trim_end_matches('.');
    if psl::suffix(domain.as_bytes()).is_some_and(|s| s.is_known()) {
        psl::domain_str(domain).unwrap_or(domain).to_string()
    } else {
        domain.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put(jar: &mut BoundedJar, host: &str, value: &str) {
        let url = url::Url::parse(&format!("https://{host}/")).unwrap();
        if let Some(cookie) = crate::scoped_cookie(value, &url) {
            jar.insert(cookie, value.len());
        }
    }

    fn invariants(jar: &BoundedJar) {
        assert!(jar.entries.len() <= MAX_JAR_COUNT);
        assert!(jar.bytes() <= MAX_JAR_BYTES);
        for e in &jar.entries {
            assert!(!e.cookie.is_expired());
            assert!(e.bytes <= MAX_ITEM_BYTES);
            let (n, b) = jar.site_usage(&e.site);
            assert!(n <= MAX_SITE_COUNT && b <= MAX_SITE_BYTES);
        }
    }

    #[test]
    fn site_count_lru_and_same_tuple_replacement_are_exact() {
        let mut jar = BoundedJar::default();
        for i in 0..MAX_SITE_COUNT {
            put(&mut jar, "a.example.com", &format!("c{i}=v; Path=/p{i}"));
        }
        let url = url::Url::parse("https://a.example.com/p0").unwrap();
        assert_eq!(jar.header(&url).as_deref(), Some("c0=v"));
        put(&mut jar, "b.example.com", "fresh=v; Domain=example.com");
        assert!(jar.entries.iter().any(|e| e.cookie.name() == "c0"));
        assert!(!jar.entries.iter().any(|e| e.cookie.name() == "c1"));
        let before = jar.bytes();
        put(&mut jar, "a.example.com", "c0=longer; Path=/p0");
        assert_eq!(jar.entries.len(), MAX_SITE_COUNT);
        assert_eq!(jar.bytes(), before + 5, "replacement charges only the new size");
        assert_eq!(
            jar.header(&url).as_deref(),
            Some("c0=longer; fresh=v"),
        );
        put(&mut jar, "a.example.com", "c0=deleted; Path=/p0; Max-Age=0");
        assert_eq!(jar.entries.len(), MAX_SITE_COUNT - 1);
        invariants(&jar);
    }

    #[test]
    fn implicit_and_explicit_path_and_host_only_domain_replace_the_same_tuple() {
        let mut jar = BoundedJar::default();
        put(&mut jar, "example.com", "a=initial");
        let created = jar.entries[0].created;
        put(&mut jar, "example.com", "a=replaced; Path=/; Domain=example.com");
        assert_eq!(jar.entries.len(), 1);
        assert_eq!(jar.entries[0].created, created);
        let url = url::Url::parse("https://example.com/").unwrap();
        assert_eq!(jar.header(&url).as_deref(), Some("a=replaced"));
        put(&mut jar, "example.com", "a=gone; Path=/; Max-Age=0");
        assert!(jar.entries.is_empty());
    }

    #[test]
    fn serialized_bytes_charge_paths_domains_and_expired_entries_are_removed() {
        let mut jar = BoundedJar::default();
        let value = "v".repeat(2000);
        for i in 0..100 {
            put(&mut jar, "example.com", &format!("c{i:03}={value}; Path=/p{i:03}"));
        }
        let expected = MAX_SITE_BYTES / jar.entries[0].bytes;
        assert_eq!(jar.entries.len(), expected);
        assert_eq!(jar.bytes(), expected * jar.entries[0].bytes);
        assert_eq!(jar.entries[0].cookie.name(), format!("c{:03}", 100 - expected));
        let e = &jar.entries[0];
        assert!(e.bytes > e.cookie.name().len() + e.cookie.value().len() + 1);
        let before = jar.bytes();
        let removed = e.bytes;
        jar.entries[0].cookie.expire();
        let n = jar.entries.len();
        jar.header(&url::Url::parse("https://example.com/").unwrap());
        assert_eq!(jar.entries.len(), n - 1);
        assert_eq!(jar.bytes(), before - removed);
        invariants(&jar);
    }

    #[test]
    fn isolation_count_is_bounded_across_many_domain_path_keys() {
        let mut jar = BoundedJar::default();
        for i in 0..MAX_JAR_COUNT + 20 {
            put(&mut jar, &format!("h{i}.test"), "a=b");
        }
        assert_eq!(jar.entries.len(), MAX_JAR_COUNT);
        invariants(&jar);
    }

    #[test]
    fn isolation_bytes_evict_from_the_largest_site_before_small_sites() {
        let mut jar = BoundedJar::default();
        put(&mut jar, "small.test", "keep=1");
        let value = "v".repeat(3000);
        for site in 0..40 {
            for i in 0..20 {
                put(&mut jar, &format!("site{site}.test"), &format!("c{i}={value}"));
            }
        }
        assert!(jar.entries.len() < 801);
        assert!(jar.entries.iter().any(|e| e.cookie.name() == "keep"));
        invariants(&jar);
    }

    #[test]
    fn private_psl_and_unknown_suffix_sites_are_isolated() {
        assert_eq!(site_key("a.example.co.uk"), "example.co.uk");
        assert_eq!(site_key("a.tenant.github.io"), "tenant.github.io");
        assert_ne!(site_key("a.github.io"), site_key("b.github.io"));
        assert_eq!(site_key("a.internal"), "a.internal");
        let mut jar = BoundedJar::default();
        put(&mut jar, "a.internal", "no=1; Domain=internal");
        put(&mut jar, "sub.a.internal", "no=1; Domain=a.internal");
        put(&mut jar, "a.internal", "yes=1; Domain=a.internal");
        assert_eq!(jar.entries.len(), 1);
        assert_eq!(
            jar.header(&url::Url::parse("https://sub.a.internal/").unwrap()),
            None,
        );
    }

    #[test]
    fn giant_values_and_inherited_metadata_are_rejected_before_retention() {
        let mut jar = BoundedJar::default();
        put(
            &mut jar,
            "example.com",
            &format!("huge={}", "v".repeat(MAX_SET_COOKIE_BYTES)),
        );
        assert!(jar.entries.is_empty());
        let url = url::Url::parse(&format!(
            "https://example.com/{}/end",
            "p".repeat(5000),
        )).unwrap();
        assert!(crate::scoped_cookie("a=b", &url).is_none());
        let url = url::Url::parse("https://example.com/").unwrap();
        let cookie = crate::scoped_cookie("a=b", &url).unwrap();
        jar.insert(cookie, MAX_ITEM_BYTES);
        assert!(jar.entries.is_empty());
    }

    #[test]
    fn output_is_capped_at_equality_and_preserves_path_then_creation_order() {
        let mut jar = BoundedJar::default();
        // Pair sizes 4090 + 4090 + 8, plus two separators, equal 8192.
        put(&mut jar, "example.com", &format!("a={}", "v".repeat(4088)));
        put(&mut jar, "example.com", &format!("b={}", "v".repeat(4088)));
        put(&mut jar, "example.com", "c=123456");
        put(&mut jar, "example.com", "d=overflow");
        let url = url::Url::parse("https://example.com/").unwrap();
        let header = jar.header(&url).unwrap();
        assert_eq!(header.len(), MAX_COOKIE_HEADER_BYTES);
        assert!(header.ends_with("; c=123456"));
        assert!(!header.contains("d=overflow"));
        put(&mut jar, "example.com", "path=first; Path=/deep");
        let url = url::Url::parse("https://example.com/deep/child").unwrap();
        assert!(jar.header(&url).unwrap().starts_with("path=first; a="));
        invariants(&jar);
    }
}
