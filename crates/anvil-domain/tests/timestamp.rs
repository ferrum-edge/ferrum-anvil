//! `Timestamp` keeps the wire format of the `chrono::DateTime<Utc>` it
//! replaced (#576): stored profiles, bundles, reports and the published JSON
//! Schemas all carry it, so every expected string below is what chrono wrote
//! or accepted.

use anvil_domain::{SecondsFormat, TimeDelta, Timestamp};
use schemars::{JsonSchema, SchemaGenerator};
use serde_json::{Value, json};

/// 2026-01-02T03:04:05Z.
const SECS: i64 = 1_767_323_045;

fn at(nanos: u32) -> Timestamp {
    Timestamp::from_unix(SECS, nanos).unwrap()
}

fn wire(t: Timestamp) -> String {
    serde_json::to_string(&t).unwrap()
}

fn parse(s: &str) -> Timestamp {
    let via_str: Timestamp = s.parse().unwrap_or_else(|e| panic!("{s:?}: {e}"));
    let via_serde: Timestamp = serde_json::from_value(Value::String(s.into())).unwrap();
    assert_eq!(via_str, via_serde, "{s:?}");
    via_str
}

#[test]
fn serializes_with_z_and_the_shortest_exact_fraction() {
    for (nanos, expected) in [
        (0, r#""2026-01-02T03:04:05Z""#),
        (120_000_000, r#""2026-01-02T03:04:05.120Z""#),
        (123_000_000, r#""2026-01-02T03:04:05.123Z""#),
        (500_000, r#""2026-01-02T03:04:05.000500Z""#),
        (123_456_000, r#""2026-01-02T03:04:05.123456Z""#),
        (1_000, r#""2026-01-02T03:04:05.000001Z""#),
        (123_456_789, r#""2026-01-02T03:04:05.123456789Z""#),
        (1, r#""2026-01-02T03:04:05.000000001Z""#),
    ] {
        assert_eq!(wire(at(nanos)), expected, "{nanos} ns");
        assert_eq!(serde_json::from_str::<Timestamp>(expected).unwrap(), at(nanos), "{expected} reads back");
    }
}

#[test]
fn serializes_the_edges_of_the_range() {
    assert_eq!(wire(Timestamp::UNIX_EPOCH), r#""1970-01-01T00:00:00Z""#);
    assert_eq!(wire(Timestamp::default()), r#""1970-01-01T00:00:00Z""#);
    let before_epoch = Timestamp::from_unix_millis(-1).unwrap();
    assert_eq!(wire(before_epoch), r#""1969-12-31T23:59:59.999Z""#);
    assert_eq!((before_epoch.unix_seconds(), before_epoch.unix_millis()), (-1, -1));
    assert_eq!(wire(Timestamp::MAX), r#""9999-12-31T23:59:59.999999999Z""#);
    assert_eq!(wire(Timestamp::MIN), r#""-9999-01-01T00:00:00Z""#);
    assert_eq!(parse("-9999-01-01T00:00:00Z"), Timestamp::MIN);
}

#[test]
fn reads_any_offset_and_normalises_to_utc() {
    let expected = at(0);
    for s in [
        "2026-01-02T03:04:05Z",
        "2026-01-02T03:04:05z",
        "2026-01-02T05:04:05+02:00",
        "2026-01-01T22:34:05-04:30",
        "2026-01-02T03:04:05+00:00",
        "2026-01-02T03:04:05-00:00",
        // chrono's relaxed reading, which serde used.
        "2026-01-02t03:04:05Z",
        "2026-01-02 03:04:05Z",
        "2026-01-02T05:04:05+0200",
        "2026-01-02T01:04:05\u{2212}02:00",
        "2026-01-02T03:04:05 UTC",
        "2026-01-02T03:04:05utc",
        "2026-1-2T3:4:5Z",
        " 2026-01-02T03:04:05Z ",
        // chrono's Display form.
        "2026-01-02 03:04:05 UTC",
    ] {
        assert_eq!(parse(s), expected, "{s:?}");
    }
    assert_eq!(wire(parse("2026-01-02T05:04:05.5+02:00")), r#""2026-01-02T03:04:05.500Z""#);
    // Digits past nanoseconds are dropped, not rounded.
    assert_eq!(wire(parse("2026-01-02T03:04:05.1234567891Z")), r#""2026-01-02T03:04:05.123456789Z""#);
    // An offset can move the date.
    assert_eq!(wire(parse("2026-01-01T23:30:00-05:00")), r#""2026-01-02T04:30:00Z""#);
}

#[test]
fn a_leap_second_reads_as_the_last_nanosecond_of_its_minute() {
    assert_eq!(wire(parse("2016-12-31T23:59:60Z")), r#""2016-12-31T23:59:59.999999999Z""#);
    assert_eq!(wire(Timestamp::parse_rfc3339("2016-12-31T23:59:60.5Z").unwrap()), r#""2016-12-31T23:59:59.999999999Z""#);
}

#[test]
fn refuses_what_chrono_refused() {
    for s in [
        "",
        "yesterday",
        "2026-01-02",
        "2026-01-02T03:04:05",
        "2026-01-02T03:04Z",
        "2026-13-02T03:04:05Z",
        "2026-02-29T03:04:05Z",
        "2026-01-02T24:00:00Z",
        "2026-01-02T03:60:05Z",
        "2026-01-02T03:04:61Z",
        "2026-01-02T03:04:05+24:00",
        "2026-01-02T03:04:05+02:60",
        "2026-01-02T03:04:05+02",
        "2026-01-02T03:04:05.Z",
        "2026-01-02T03:04:05Z trailing",
        "2026-01-02X03:04:05Z",
        "10000-01-01T00:00:00Z",
    ] {
        assert!(s.parse::<Timestamp>().is_err(), "{s:?} must not parse");
        assert!(serde_json::from_value::<Timestamp>(Value::String(s.into())).is_err(), "{s:?} must not deserialize");
    }
    assert!(serde_json::from_value::<Timestamp>(json!(1_767_323_045)).is_err(), "a number is not a timestamp");
    assert_eq!("2026-01-02T03:04:05".parse::<Timestamp>().unwrap_err().to_string(), "premature end of input");
    assert_eq!("2026-13-02T03:04:05Z".parse::<Timestamp>().unwrap_err().to_string(), "input is out of range");
}

#[test]
fn years_beyond_9999_are_out_of_range() {
    // chrono read these (it serialized years past 9999 with a sign); `time`
    // stops at 9999. Nothing Anvil wrote is that far out.
    assert!("+10000-01-01T00:00:00Z".parse::<Timestamp>().is_err());
    assert!("9999-12-31T23:00:00-05:00".parse::<Timestamp>().is_err());
    assert_eq!(parse("9999-12-31T23:59:59.999999999Z"), Timestamp::MAX);
}

#[test]
fn strict_rfc3339_is_chronos_parse_from_rfc3339() {
    for (s, expected) in [
        ("2026-01-02T03:04:05Z", at(0)),
        ("2026-01-02t03:04:05.12z", at(120_000_000)),
        ("2026-01-02 03:04:05Z", at(0)),
        ("2026-01-02T05:04:05+02:00", at(0)),
        ("2026-01-02T01:04:05\u{2212}02:00", at(0)),
    ] {
        assert_eq!(Timestamp::parse_rfc3339(s), Ok(expected), "{s:?}");
    }
    for s in [
        "2026-1-02T03:04:05Z",
        "2026-01-02T05:04:05+0200",
        "2026-01-02T03:04:05 UTC",
        "2026-01-02T03:04:05UTC",
        " 2026-01-02T03:04:05Z",
        "2026-01-02T03:04:05Z ",
        "2026-01-02  03:04:05Z",
        "2026-01-02T03:04:05",
        "+2026-01-02T03:04:05Z",
    ] {
        assert!(Timestamp::parse_rfc3339(s).is_err(), "{s:?} is not strict RFC 3339");
    }
}

#[test]
fn rfc3339_text_matches_chrono() {
    let t = at(120_000_000);
    assert_eq!(t.to_rfc3339(), "2026-01-02T03:04:05.120+00:00");
    assert_eq!(at(0).to_rfc3339(), "2026-01-02T03:04:05+00:00");
    assert_eq!(t.to_rfc3339_opts(SecondsFormat::Secs, true), "2026-01-02T03:04:05Z");
    assert_eq!(t.to_rfc3339_opts(SecondsFormat::Millis, true), "2026-01-02T03:04:05.120Z");
    assert_eq!(t.to_rfc3339_opts(SecondsFormat::Micros, false), "2026-01-02T03:04:05.120000+00:00");
    assert_eq!(t.to_rfc3339_opts(SecondsFormat::Nanos, true), "2026-01-02T03:04:05.120000000Z");
    assert_eq!(t.to_rfc3339_opts(SecondsFormat::AutoSi, true), "2026-01-02T03:04:05.120Z");
    assert_eq!(at(999_999_999).to_rfc3339_opts(SecondsFormat::Millis, true), "2026-01-02T03:04:05.999Z", "truncated");
    assert_eq!(format!("{t:?}"), "2026-01-02T03:04:05.120Z");
    assert_eq!(t.to_string(), "2026-01-02 03:04:05.120 UTC");
    assert_eq!(at(0).to_string(), "2026-01-02 03:04:05 UTC");
}

#[test]
fn strftime_equivalents() {
    let t = at(120_000_000);
    assert_eq!(t.format_date(), "2026-01-02");
    assert_eq!(t.format_date_time(), "2026-01-02 03:04:05");
    assert_eq!(t.format_iso_seconds(), "2026-01-02T03:04:05");
    assert_eq!(t.format_time(), "03:04:05");
    assert_eq!(t.format_basic(), "20260102T030405Z");
    assert_eq!(t.format_basic_millis(), "20260102T030405120Z");
}

#[test]
fn unix_time_and_arithmetic() {
    let t = at(120_456_789);
    assert_eq!(t.unix_seconds(), SECS);
    assert_eq!(t.unix_millis(), SECS * 1_000 + 120);
    assert_eq!(t.unix_micros(), SECS * 1_000_000 + 120_456);
    assert_eq!(t.subsec_nanos(), 120_456_789);
    assert_eq!(Timestamp::from_unix_millis(t.unix_millis()), Some(at(120_000_000)));
    assert_eq!(Timestamp::from_unix_seconds(SECS), Some(at(0)));
    assert_eq!(Timestamp::from_ymd_hms(2026, 1, 2, 3, 4, 5), Some(at(0)));
    assert_eq!(Timestamp::from_ymd_hms(2026, 2, 29, 0, 0, 0), None);
    assert_eq!(Timestamp::from_unix(SECS, 1_000_000_000), None);
    assert_eq!(Timestamp::from_unix_seconds(i64::MAX), None);

    let later = t + TimeDelta::seconds(55);
    assert_eq!(later.unix_seconds(), SECS + 55);
    assert_eq!(later - t, TimeDelta::seconds(55));
    assert_eq!(t - later, -TimeDelta::seconds(55));
    assert_eq!(later - TimeDelta::seconds(55), t);
    let mut moved = t;
    moved += TimeDelta::days(1);
    moved -= TimeDelta::hours(24);
    assert_eq!(moved, t);
    assert_eq!(t + std::time::Duration::from_millis(1500), t + TimeDelta::milliseconds(1500));
    assert_eq!(Timestamp::MAX.checked_add(TimeDelta::seconds(1)), None);
    assert_eq!(Timestamp::MIN.checked_sub(TimeDelta::seconds(1)), None);
    assert_eq!(t.checked_add(TimeDelta::seconds(1)), Some(t + TimeDelta::seconds(1)));
    assert!(t < later);
}

#[test]
fn json_schema_is_what_schemars_chrono04_emitted() {
    assert!(Timestamp::inline_schema());
    let mut generator = SchemaGenerator::default();
    assert_eq!(generator.subschema_for::<Timestamp>().as_value(), &json!({"type": "string", "format": "date-time"}));
    assert_eq!(generator.subschema_for::<Option<Timestamp>>().as_value(), &json!({"type": ["string", "null"], "format": "date-time"}));
    assert!(generator.definitions().is_empty(), "inline, never a $ref");
}

/// The published schemas (generated with chrono04 before #576 and checked
/// for drift in CI) hold exactly the two shapes above for every timestamp.
#[test]
fn published_schemas_hold_only_those_shapes() {
    fn walk(v: &Value, found: &mut Vec<Value>) {
        match v {
            Value::Object(o) => {
                if o.get("format") == Some(&json!("date-time")) {
                    let mut shape = o.clone();
                    shape.remove("description");
                    found.push(Value::Object(shape));
                }
                o.values().for_each(|x| walk(x, found));
            }
            Value::Array(a) => a.iter().for_each(|x| walk(x, found)),
            _ => {}
        }
    }
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../contracts/schemas");
    let mut found = Vec::new();
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "json") {
            walk(&serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap(), &mut found);
        }
    }
    assert!(!found.is_empty());
    let mut generator = SchemaGenerator::default();
    let plain = generator.subschema_for::<Timestamp>().to_value();
    let optional = generator.subschema_for::<Option<Timestamp>>().to_value();
    for shape in found {
        assert!(shape == plain || shape == optional, "unexpected date-time schema {shape}");
    }
}
