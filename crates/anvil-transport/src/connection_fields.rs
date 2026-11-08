//! Connection-specific fields, which an HTTP/2 or HTTP/3 request must not
//! carry (RFC 9113 §8.2.2, RFC 9114 §4.2): a peer treats a message with one
//! as malformed. hyper's HTTP/2 client removes them silently; HTTP/3 has no
//! such layer underneath, so every HTTP/2 and HTTP/3 request builder here,
//! and the engine's effective-request preview, apply this one rule:
//!
//! - `Connection`, `Keep-Alive`, `Proxy-Connection`, `Transfer-Encoding` and
//!   `Upgrade` are left out;
//! - so is every field a `Connection` value nominates;
//! - and `TE`, unless its value is `trailers`.

use http::{HeaderName, HeaderValue};

/// The fields left out by name alone (lowercase).
pub const CONNECTION_SPECIFIC: &[&str] = &["connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade"];

/// Which fields of one request are connection-specific: built from all of
/// its fields, since a `Connection` value nominates others.
#[derive(Debug, Default, Clone)]
pub struct ConnectionSpecific {
    /// The names `Connection` values nominate (lowercase, trimmed).
    nominated: Vec<String>,
}

impl ConnectionSpecific {
    /// The rule for a request whose fields are `fields` (name, value).
    pub fn of<'a>(fields: impl IntoIterator<Item = (&'a str, &'a str)>) -> Self {
        let nominated = fields
            .into_iter()
            .filter(|(n, _)| n.trim().eq_ignore_ascii_case("connection"))
            .flat_map(|(_, v)| v.split(','))
            .map(|t| t.trim().to_ascii_lowercase())
            .filter(|t| !t.is_empty())
            .collect();
        ConnectionSpecific { nominated }
    }

    /// [`Self::of`] for typed fields. A value that is not text nominates
    /// nothing.
    pub fn of_fields<'a>(fields: impl IntoIterator<Item = (&'a HeaderName, &'a HeaderValue)>) -> Self {
        Self::of(fields.into_iter().filter_map(|(n, v)| v.to_str().ok().map(|v| (n.as_str(), v))))
    }

    /// Whether `name: value` is left out of an HTTP/2 or HTTP/3 request.
    pub fn drops(&self, name: &str, value: &str) -> bool {
        let name = name.trim();
        if CONNECTION_SPECIFIC.iter().any(|c| name.eq_ignore_ascii_case(c)) {
            return true;
        }
        if name.eq_ignore_ascii_case("te") && !value.trim().eq_ignore_ascii_case("trailers") {
            return true;
        }
        self.nominated.iter().any(|n| name.eq_ignore_ascii_case(n))
    }

    /// [`Self::drops`] for a typed field. A `TE` value that is not text is
    /// not `trailers`.
    pub fn drops_field(&self, name: &HeaderName, value: &HeaderValue) -> bool {
        self.drops(name.as_str(), value.to_str().unwrap_or(""))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kept(fields: &[(&str, &str)]) -> Vec<String> {
        let rule = ConnectionSpecific::of(fields.iter().copied());
        fields.iter().filter(|(n, v)| !rule.drops(n, v)).map(|(n, v)| format!("{n}: {v}")).collect()
    }

    #[test]
    fn connection_specific_fields_are_left_out() {
        let fields = [
            ("Connection", "keep-alive, X-Foo"),
            ("Keep-Alive", "timeout=5"),
            ("Proxy-Connection", "keep-alive"),
            ("Transfer-Encoding", "chunked"),
            ("Upgrade", "h2c"),
            ("x-foo", "nominated"),
            ("TE", "gzip"),
            ("Accept", "application/json"),
            ("X-Bar", "kept"),
        ];
        assert_eq!(kept(&fields), ["Accept: application/json", "X-Bar: kept"]);
    }

    #[test]
    fn te_trailers_is_kept() {
        assert_eq!(kept(&[("TE", "trailers")]), ["TE: trailers"]);
        assert_eq!(kept(&[("te", " Trailers ")]), ["te:  Trailers "]);
        assert!(kept(&[("te", "trailers, gzip")]).is_empty());
        assert!(kept(&[("te", "")]).is_empty());
    }

    #[test]
    fn typed_fields_follow_the_same_rule() {
        let fields = [
            (HeaderName::from_static("connection"), HeaderValue::from_static("x-hop")),
            (HeaderName::from_static("x-hop"), HeaderValue::from_static("1")),
            (HeaderName::from_static("te"), HeaderValue::from_bytes(b"\xfftrailers").unwrap()),
            (HeaderName::from_static("te"), HeaderValue::from_static("trailers")),
            (HeaderName::from_static("x-end"), HeaderValue::from_static("1")),
        ];
        let rule = ConnectionSpecific::of_fields(fields.iter().map(|(n, v)| (n, v)));
        let kept: Vec<_> = fields.iter().filter(|(n, v)| !rule.drops_field(n, v)).map(|(n, _)| n.as_str()).collect();
        assert_eq!(kept, ["te", "x-end"]);
    }
}
