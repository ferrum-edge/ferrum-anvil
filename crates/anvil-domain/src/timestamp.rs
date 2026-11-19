//! [`Timestamp`]: the one UTC instant type in every Anvil contract.
//!
//! It wraps [`time::UtcDateTime`] and keeps the wire format the workspace
//! had with `chrono::DateTime<Utc>`, byte for byte, because stored profiles,
//! exported bundles, reports and the published JSON Schemas all carry it:
//!
//! * **Serialize** writes RFC 3339 in UTC with a `Z` suffix and the shortest
//!   exact fraction from {none, 3, 6, 9} digits (chrono's `AutoSi`), for
//!   example `2026-01-02T03:04:05Z`, `…05.120Z`, `…05.000001Z`.
//! * **Deserialize** (and [`FromStr`]) accept what chrono's `DateTime<Utc>`
//!   accepted: its relaxed RFC 3339 reading, with any `±hh:mm` offset (or `Z`
//!   or `UTC`), normalised to UTC. The only inputs chrono took that this type
//!   refuses are years outside -9999..=9999 (outside `time`'s range); a leap
//!   second (`:60`) is read as the last nanosecond of that minute.
//! * **JsonSchema** is the inline `{"type":"string","format":"date-time"}`
//!   that schemars' `chrono04` feature emitted for `DateTime<Tz>`.
//! * **Debug** is the serialized form and **Display** is chrono's
//!   `2026-01-02 03:04:05 UTC`, so log lines and messages do not change.
//!
//! Formatting is written from the integer fields: no runtime format strings
//! and nothing fallible on the hot path.

use std::borrow::Cow;
use std::fmt::{self, Write as _};
use std::ops::{Add, AddAssign, Sub, SubAssign};
use std::str::FromStr;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use time::{Date, Month, Time, UtcDateTime};

/// Signed span between two [`Timestamp`]s, and the amount added to or taken
/// from one (`TimeDelta::seconds(30)`, `TimeDelta::days(1)`, ...).
pub use time::SignedDuration as TimeDelta;

const NANOS_PER_SEC: u32 = 1_000_000_000;

/// A UTC instant with nanosecond precision (years -9999..=9999).
///
/// See the [module documentation](self) for the wire format.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(UtcDateTime);

/// Fraction digits for [`Timestamp::to_rfc3339_opts`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecondsFormat {
    /// No fraction.
    Secs,
    /// Always three digits.
    Millis,
    /// Always six digits.
    Micros,
    /// Always nine digits.
    Nanos,
    /// None when zero, otherwise the shortest exact one of 3, 6 or 9 digits.
    AutoSi,
}

impl Timestamp {
    /// 1970-01-01T00:00:00Z.
    pub const UNIX_EPOCH: Self = Self(UtcDateTime::UNIX_EPOCH);
    /// The earliest representable instant, -9999-01-01T00:00:00Z.
    pub const MIN: Self = Self(UtcDateTime::MIN);
    /// The latest representable instant, 9999-12-31T23:59:59.999999999Z.
    pub const MAX: Self = Self(UtcDateTime::MAX);

    /// The current time from the system clock.
    pub fn now() -> Self {
        Self(UtcDateTime::now())
    }

    /// `secs` seconds and `nanos` nanoseconds after the Unix epoch; `None` when
    /// out of range or `nanos` is not below one second.
    pub fn from_unix(secs: i64, nanos: u32) -> Option<Self> {
        if nanos >= NANOS_PER_SEC {
            return None;
        }
        UtcDateTime::from_unix_timestamp(secs).ok()?.replace_nanosecond(nanos).ok().map(Self)
    }

    /// Whole Unix seconds; `None` when out of range.
    pub fn from_unix_seconds(secs: i64) -> Option<Self> {
        Self::from_unix(secs, 0)
    }

    /// Unix milliseconds; `None` when out of range.
    pub fn from_unix_millis(millis: i64) -> Option<Self> {
        UtcDateTime::from_unix_timestamp_nanos(i128::from(millis) * 1_000_000).ok().map(Self)
    }

    /// A calendar date and time of day in UTC; `None` when any field is out of
    /// range.
    pub fn from_ymd_hms(year: i32, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> Option<Self> {
        let date = Date::from_calendar_date(year, Month::try_from(month).ok()?, day).ok()?;
        let time = Time::from_hms(hour, minute, second).ok()?;
        Some(Self(UtcDateTime::new(date, time)))
    }

    /// Whole seconds since the Unix epoch, rounded toward negative infinity.
    pub fn unix_seconds(self) -> i64 {
        self.0.unix_timestamp()
    }

    /// Milliseconds since the Unix epoch, rounded toward negative infinity.
    pub fn unix_millis(self) -> i64 {
        self.unix_seconds() * 1_000 + i64::from(self.0.nanosecond() / 1_000_000)
    }

    /// Microseconds since the Unix epoch, rounded toward negative infinity.
    pub fn unix_micros(self) -> i64 {
        self.unix_seconds() * 1_000_000 + i64::from(self.0.nanosecond() / 1_000)
    }

    /// Nanoseconds within the second, `0..1_000_000_000`.
    pub fn subsec_nanos(self) -> u32 {
        self.0.nanosecond()
    }

    /// `self + delta`, or `None` when the result is out of range.
    pub fn checked_add(self, delta: TimeDelta) -> Option<Self> {
        self.0.checked_add(delta).map(Self)
    }

    /// `self - delta`, or `None` when the result is out of range.
    pub fn checked_sub(self, delta: TimeDelta) -> Option<Self> {
        self.0.checked_sub(delta).map(Self)
    }

    /// Strict RFC 3339 (section 5.6): exactly `YYYY-MM-DD`, `T` (either case)
    /// or one space, `hh:mm:ss`, an optional fraction, then `Z` or `±hh:mm`.
    /// The offset is applied and the result is in UTC. This is the reading of
    /// chrono's `DateTime::parse_from_rfc3339`; [`FromStr`] (and serde) are
    /// more lenient.
    pub fn parse_rfc3339(s: &str) -> Result<Self, ParseError> {
        parse::strict(s)
    }

    /// RFC 3339 with an explicit `+00:00` offset and an [`SecondsFormat::AutoSi`]
    /// fraction (chrono's `to_rfc3339`).
    pub fn to_rfc3339(self) -> String {
        self.to_rfc3339_opts(SecondsFormat::AutoSi, false)
    }

    /// RFC 3339 with the given fraction, ending in `Z` when `use_z` is set and
    /// in `+00:00` otherwise (chrono's `to_rfc3339_opts`).
    pub fn to_rfc3339_opts(self, secform: SecondsFormat, use_z: bool) -> String {
        let mut out = String::with_capacity(35);
        // Writing to a String cannot fail.
        let _ = self.write_rfc3339(&mut out, secform, use_z);
        out
    }

    /// `YYYY-MM-DD` (strftime `%Y-%m-%d`).
    pub fn format_date(self) -> String {
        let mut out = String::with_capacity(10);
        let _ = self.write_date(&mut out, "-");
        out
    }

    /// `YYYY-MM-DD hh:mm:ss`, no fraction or zone (strftime `%Y-%m-%d %H:%M:%S`).
    pub fn format_date_time(self) -> String {
        let mut out = String::with_capacity(19);
        let _ = self.write_date(&mut out, "-");
        out.push(' ');
        let _ = self.write_time(&mut out, ":");
        out
    }

    /// `YYYY-MM-DDThh:mm:ss`, no fraction or zone (strftime `%Y-%m-%dT%H:%M:%S`).
    pub fn format_iso_seconds(self) -> String {
        let mut out = String::with_capacity(19);
        let _ = self.write_date(&mut out, "-");
        out.push('T');
        let _ = self.write_time(&mut out, ":");
        out
    }

    /// `hh:mm:ss`, no fraction or zone (strftime `%H:%M:%S`).
    pub fn format_time(self) -> String {
        let mut out = String::with_capacity(8);
        let _ = self.write_time(&mut out, ":");
        out
    }

    /// Basic ISO 8601 `YYYYMMDDThhmmssZ` for file names (strftime
    /// `%Y%m%dT%H%M%SZ`).
    pub fn format_basic(self) -> String {
        let mut out = String::with_capacity(16);
        let _ = self.write_date(&mut out, "");
        out.push('T');
        let _ = self.write_time(&mut out, "");
        out.push('Z');
        out
    }

    /// Basic ISO 8601 with milliseconds and no decimal point,
    /// `YYYYMMDDThhmmssfffZ` (strftime `%Y%m%dT%H%M%S%3fZ`).
    pub fn format_basic_millis(self) -> String {
        let mut out = String::with_capacity(19);
        let _ = self.write_date(&mut out, "");
        out.push('T');
        let _ = self.write_time(&mut out, "");
        let _ = write!(out, "{:03}Z", self.0.nanosecond() / 1_000_000);
        out
    }

    fn write_date(self, w: &mut impl fmt::Write, sep: &str) -> fmt::Result {
        let year = self.0.year();
        if (0..=9999).contains(&year) {
            write!(w, "{year:04}")?;
        } else {
            // ISO 8601 requires the explicit sign for out-of-range years.
            write!(w, "{year:+05}")?;
        }
        write!(w, "{sep}{:02}{sep}{:02}", u8::from(self.0.month()), self.0.day())
    }

    fn write_time(self, w: &mut impl fmt::Write, sep: &str) -> fmt::Result {
        write!(w, "{:02}{sep}{:02}{sep}{:02}", self.0.hour(), self.0.minute(), self.0.second())
    }

    fn write_fraction(self, w: &mut impl fmt::Write, secform: SecondsFormat) -> fmt::Result {
        let nano = self.0.nanosecond();
        match secform {
            SecondsFormat::Secs => Ok(()),
            SecondsFormat::Millis => write!(w, ".{:03}", nano / 1_000_000),
            SecondsFormat::Micros => write!(w, ".{:06}", nano / 1_000),
            SecondsFormat::Nanos => write!(w, ".{nano:09}"),
            SecondsFormat::AutoSi if nano == 0 => Ok(()),
            SecondsFormat::AutoSi if nano.is_multiple_of(1_000_000) => write!(w, ".{:03}", nano / 1_000_000),
            SecondsFormat::AutoSi if nano.is_multiple_of(1_000) => write!(w, ".{:06}", nano / 1_000),
            SecondsFormat::AutoSi => write!(w, ".{nano:09}"),
        }
    }

    fn write_rfc3339(self, w: &mut impl fmt::Write, secform: SecondsFormat, use_z: bool) -> fmt::Result {
        self.write_date(w, "-")?;
        w.write_char('T')?;
        self.write_time(w, ":")?;
        self.write_fraction(w, secform)?;
        w.write_str(if use_z { "Z" } else { "+00:00" })
    }
}

impl Default for Timestamp {
    /// The Unix epoch, as `chrono::DateTime<Utc>::default()` was.
    fn default() -> Self {
        Self::UNIX_EPOCH
    }
}

impl From<std::time::SystemTime> for Timestamp {
    /// Panics when the time is outside years -9999..=9999.
    fn from(t: std::time::SystemTime) -> Self {
        Self(UtcDateTime::from(t))
    }
}

impl From<Timestamp> for std::time::SystemTime {
    fn from(t: Timestamp) -> Self {
        std::time::SystemTime::from(t.0)
    }
}

impl fmt::Debug for Timestamp {
    /// The serialized form, `2026-01-02T03:04:05.120Z`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.write_rfc3339(f, SecondsFormat::AutoSi, true)
    }
}

impl fmt::Display for Timestamp {
    /// `2026-01-02 03:04:05.120 UTC`, as chrono displayed `DateTime<Utc>`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.write_date(f, "-")?;
        f.write_char(' ')?;
        self.write_time(f, ":")?;
        self.write_fraction(f, SecondsFormat::AutoSi)?;
        f.write_str(" UTC")
    }
}

impl FromStr for Timestamp {
    type Err = ParseError;

    /// Relaxed RFC 3339 with any offset, normalised to UTC: the input chrono's
    /// `DateTime<Utc>` accepted from a string and from serde.
    fn from_str(s: &str) -> Result<Self, ParseError> {
        parse::relaxed(s)
    }
}

impl Add<TimeDelta> for Timestamp {
    type Output = Self;

    /// Panics when the result is out of range; see [`Timestamp::checked_add`].
    fn add(self, rhs: TimeDelta) -> Self {
        Self(self.0 + rhs)
    }
}

impl Sub<TimeDelta> for Timestamp {
    type Output = Self;

    /// Panics when the result is out of range; see [`Timestamp::checked_sub`].
    fn sub(self, rhs: TimeDelta) -> Self {
        Self(self.0 - rhs)
    }
}

impl AddAssign<TimeDelta> for Timestamp {
    fn add_assign(&mut self, rhs: TimeDelta) {
        *self = *self + rhs;
    }
}

impl SubAssign<TimeDelta> for Timestamp {
    fn sub_assign(&mut self, rhs: TimeDelta) {
        *self = *self - rhs;
    }
}

impl Add<std::time::Duration> for Timestamp {
    type Output = Self;

    fn add(self, rhs: std::time::Duration) -> Self {
        Self(self.0 + rhs)
    }
}

impl Sub<std::time::Duration> for Timestamp {
    type Output = Self;

    fn sub(self, rhs: std::time::Duration) -> Self {
        Self(self.0 - rhs)
    }
}

impl Sub for Timestamp {
    type Output = TimeDelta;

    /// The signed span from `rhs` to `self`.
    fn sub(self, rhs: Self) -> TimeDelta {
        self.0 - rhs.0
    }
}

/// [`fmt::Display`] adapter so serialization streams without a temporary
/// `String`, as chrono's did (`collect_str`).
struct Rfc3339(Timestamp);

impl fmt::Display for Rfc3339 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.write_rfc3339(f, SecondsFormat::AutoSi, true)
    }
}

impl Serialize for Timestamp {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&Rfc3339(*self))
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;

        impl de::Visitor<'_> for Visitor {
            type Value = Timestamp;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an RFC 3339 formatted date and time string")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Timestamp, E> {
                value.parse().map_err(E::custom)
            }
        }

        deserializer.deserialize_str(Visitor)
    }
}

impl JsonSchema for Timestamp {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> Cow<'static, str> {
        "DateTime".into()
    }

    fn schema_id() -> Cow<'static, str> {
        "anvil_domain::Timestamp".into()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "format": "date-time"
        })
    }
}

/// Why a string is not a timestamp. The messages are chrono's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseError(ParseErrorKind);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParseErrorKind {
    OutOfRange,
    Invalid,
    TooShort,
    TooLong,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self.0 {
            ParseErrorKind::OutOfRange => "input is out of range",
            ParseErrorKind::Invalid => "input contains invalid characters",
            ParseErrorKind::TooShort => "premature end of input",
            ParseErrorKind::TooLong => "trailing input",
        })
    }
}

impl std::error::Error for ParseError {}

/// Ports of chrono 0.4's `parse_rfc3339` (strict) and `parse_rfc3339_relaxed`
/// (behind `FromStr` and serde), so every stored value chrono read still
/// reads, and nothing it refused is newly accepted.
mod parse {
    use super::{NANOS_PER_SEC, ParseError, ParseErrorKind, TimeDelta, Timestamp};
    use time::{Date, Month, Time, UtcDateTime};

    type Result<T> = std::result::Result<T, ParseError>;

    const OUT_OF_RANGE: ParseError = ParseError(ParseErrorKind::OutOfRange);
    const INVALID: ParseError = ParseError(ParseErrorKind::Invalid);
    const TOO_SHORT: ParseError = ParseError(ParseErrorKind::TooShort);
    const TOO_LONG: ParseError = ParseError(ParseErrorKind::TooLong);

    /// Validated fields before the offset is applied.
    struct Fields {
        year: i64,
        month: i64,
        day: i64,
        hour: i64,
        minute: i64,
        /// 0..=60; 60 is a leap second.
        second: i64,
        nanosecond: u32,
        /// Seconds east of UTC.
        offset: i32,
    }

    impl Fields {
        fn to_timestamp(&self) -> Result<Timestamp> {
            let year = i32::try_from(self.year).map_err(|_| OUT_OF_RANGE)?;
            let month = u8::try_from(self.month).ok().and_then(|m| Month::try_from(m).ok()).ok_or(OUT_OF_RANGE)?;
            let day = u8::try_from(self.day).map_err(|_| OUT_OF_RANGE)?;
            let date = Date::from_calendar_date(year, month, day).map_err(|_| OUT_OF_RANGE)?;
            // `time` has no leap seconds: `:60` becomes the last nanosecond of
            // the minute, the closest instant it can hold.
            let (second, nanosecond) = match self.second {
                60 => (59, NANOS_PER_SEC - 1),
                s => (u8::try_from(s).map_err(|_| OUT_OF_RANGE)?, self.nanosecond),
            };
            let hour = u8::try_from(self.hour).map_err(|_| OUT_OF_RANGE)?;
            let minute = u8::try_from(self.minute).map_err(|_| OUT_OF_RANGE)?;
            let time = Time::from_hms_nano(hour, minute, second, nanosecond).map_err(|_| OUT_OF_RANGE)?;
            // RFC 3339 offsets run from -23:59 to +23:59.
            if self.offset.unsigned_abs() >= 86_400 {
                return Err(OUT_OF_RANGE);
            }
            let local = UtcDateTime::new(date, time);
            local.checked_sub(TimeDelta::seconds(i64::from(self.offset))).map(Timestamp).ok_or(OUT_OF_RANGE)
        }
    }

    /// chrono `scan::number`: `min..=max` ASCII digits.
    fn number(s: &str, min: usize, max: usize) -> Result<(&str, i64)> {
        let bytes = s.as_bytes();
        if bytes.len() < min {
            return Err(TOO_SHORT);
        }
        let mut n = 0i64;
        for (i, &c) in bytes.iter().take(max).enumerate() {
            if !c.is_ascii_digit() {
                return if i < min { Err(INVALID) } else { Ok((&s[i..], n)) };
            }
            n = n.checked_mul(10).and_then(|n| n.checked_add(i64::from(c - b'0'))).ok_or(OUT_OF_RANGE)?;
        }
        Ok((&s[max.min(bytes.len())..], n))
    }

    /// chrono `scan::nanosecond`: one to nine digits scaled to nanoseconds;
    /// further digits are skipped.
    fn nanosecond(s: &str) -> Result<(&str, u32)> {
        const SCALE: [u32; 10] = [0, 100_000_000, 10_000_000, 1_000_000, 100_000, 10_000, 1_000, 100, 10, 1];
        let original = s.len();
        let (s, v) = number(s, 1, 9)?;
        let consumed = original - s.len();
        let v = u32::try_from(v).map_err(|_| OUT_OF_RANGE)?.checked_mul(SCALE[consumed]).ok_or(OUT_OF_RANGE)?;
        Ok((s.trim_start_matches(|c: char| c.is_ascii_digit()), v))
    }

    /// chrono `scan::timezone_offset` with `allow_zulu` and the U+2212 minus
    /// sign: `Z`, or a sign, two hour digits, `separator`, two minute digits.
    fn timezone_offset(mut s: &str, separator: fn(&str) -> Result<&str>) -> Result<(&str, i32)> {
        if let Some(b'Z' | b'z') = s.as_bytes().first() {
            return Ok((&s[1..], 0));
        }
        let negative = match s.chars().next() {
            Some('+') => false,
            Some('-') => true,
            Some('\u{2212}') => true,
            Some(_) => return Err(INVALID),
            None => return Err(TOO_SHORT),
        };
        s = &s[s.chars().next().map_or(0, char::len_utf8)..];
        let two_digits = |s: &str| -> Result<(u8, u8)> {
            match s.as_bytes() {
                [a, b, ..] => Ok((*a, *b)),
                _ => Err(TOO_SHORT),
            }
        };
        let hours = match two_digits(s)? {
            (h1 @ b'0'..=b'9', h2 @ b'0'..=b'9') => i32::from((h1 - b'0') * 10 + (h2 - b'0')),
            _ => return Err(INVALID),
        };
        s = separator(&s[2..])?;
        let minutes = match two_digits(s)? {
            (m1 @ b'0'..=b'5', m2 @ b'0'..=b'9') => i32::from((m1 - b'0') * 10 + (m2 - b'0')),
            (b'6'..=b'9', b'0'..=b'9') => return Err(OUT_OF_RANGE),
            _ => return Err(INVALID),
        };
        let seconds = hours * 3600 + minutes * 60;
        Ok((&s[2..], if negative { -seconds } else { seconds }))
    }

    const MINUS: &[u8] = b"-";
    const COLON: &[u8] = b":";
    const DATE_TIME_SEPARATOR: &[u8] = b"tT ";

    /// chrono `scan::char(s, b':')`: exactly one colon.
    fn colon(s: &str) -> Result<&str> {
        match s.as_bytes().first() {
            Some(b':') => Ok(&s[1..]),
            Some(_) => Err(INVALID),
            None => Err(TOO_SHORT),
        }
    }

    /// chrono `scan::colon_or_space`: any run of colons and whitespace.
    fn colon_or_space(s: &str) -> Result<&str> {
        Ok(s.trim_start_matches(|c: char| c == ':' || c.is_whitespace()))
    }

    /// chrono `parse_rfc3339`.
    pub(super) fn strict(s: &str) -> Result<Timestamp> {
        let bytes = s.as_bytes();
        if bytes.len() < 19 {
            return Err(TOO_SHORT);
        }
        let digit = |i: usize| -> Result<i64> {
            let b = bytes[i];
            if b.is_ascii_digit() { Ok(i64::from(b - b'0')) } else { Err(INVALID) }
        };
        let literal = |i: usize, allowed: &'static [u8]| if allowed.contains(&bytes[i]) { Ok(()) } else { Err(INVALID) };
        let year = digit(0)? * 1000 + digit(1)? * 100 + digit(2)? * 10 + digit(3)?;
        literal(4, MINUS)?;
        let month = digit(5)? * 10 + digit(6)?;
        literal(7, MINUS)?;
        let day = digit(8)? * 10 + digit(9)?;
        literal(10, DATE_TIME_SEPARATOR)?;
        let hour = digit(11)? * 10 + digit(12)?;
        literal(13, COLON)?;
        let minute = digit(14)? * 10 + digit(15)?;
        literal(16, COLON)?;
        let second = digit(17)? * 10 + digit(18)?;
        if hour > 23 || minute > 59 || second > 60 {
            return Err(OUT_OF_RANGE);
        }
        // The first 19 bytes are ASCII, so these slices are on char boundaries.
        let (rest, nanos) = if bytes[19..].first() == Some(&b'.') { nanosecond(&s[20..])? } else { (&s[19..], 0) };
        let (rest, offset) = timezone_offset(rest, colon)?;
        if !rest.is_empty() {
            return Err(TOO_LONG);
        }
        Fields { year, month, day, hour, minute, second, nanosecond: nanos, offset }.to_timestamp()
    }

    /// chrono numeric item: leading whitespace, then up to `width` digits, or
    /// with `signed` an explicit sign and any number of digits.
    fn numeric(s: &str, width: usize, signed: bool) -> Result<(&str, i64)> {
        let s = s.trim_start();
        if signed {
            if let Some(rest) = s.strip_prefix('-') {
                let (rest, v) = number(rest, 1, usize::MAX)?;
                return Ok((rest, 0i64.checked_sub(v).ok_or(OUT_OF_RANGE)?));
            }
            if let Some(rest) = s.strip_prefix('+') {
                return number(rest, 1, usize::MAX);
            }
        }
        number(s, 1, width)
    }

    /// chrono `Item::Space("")` then `Item::Literal`.
    fn spaced_literal<'a>(s: &'a str, lit: &str) -> Result<&'a str> {
        let s = s.trim_start();
        if s.len() < lit.len() {
            return Err(TOO_SHORT);
        }
        s.strip_prefix(lit).ok_or(INVALID)
    }

    fn in_range(v: i64, lo: i64, hi: i64) -> Result<i64> {
        if (lo..=hi).contains(&v) { Ok(v) } else { Err(OUT_OF_RANGE) }
    }

    /// chrono `parse_rfc3339_relaxed` plus the trailing-input check of
    /// `FromStr for DateTime<FixedOffset>`: unpadded fields, signed years,
    /// spaces between components, `T`, `t` or a space between date and time,
    /// and `Z`, `UTC` (any case) or `±hh[:]mm` as the offset.
    pub(super) fn relaxed(s: &str) -> Result<Timestamp> {
        let (s, year) = numeric(s, 4, true)?;
        i32::try_from(year).map_err(|_| OUT_OF_RANGE)?;
        let s = spaced_literal(s, "-")?;
        let (s, month) = numeric(s, 2, false)?;
        let month = in_range(month, 1, 12)?;
        let s = spaced_literal(s, "-")?;
        let (s, day) = numeric(s, 2, false)?;
        let day = in_range(day, 1, 31)?;
        let s = match s.as_bytes().first() {
            Some(b't' | b'T' | b' ') => &s[1..],
            Some(_) => return Err(INVALID),
            None => return Err(TOO_SHORT),
        };
        let (s, hour) = numeric(s, 2, false)?;
        let hour = in_range(hour, 0, 23)?;
        let s = spaced_literal(s, ":")?;
        let (s, minute) = numeric(s, 2, false)?;
        let minute = in_range(minute, 0, 59)?;
        let s = spaced_literal(s, ":")?;
        let (s, second) = numeric(s, 2, false)?;
        let second = in_range(second, 0, 60)?;
        let (s, nanos) = match s.strip_prefix('.') {
            Some(rest) => nanosecond(rest)?,
            None => (s, 0),
        };
        let s = s.trim_start();
        let (s, offset) =
            if s.len() >= 3 && s.as_bytes()[..3].eq_ignore_ascii_case(b"UTC") { (&s[3..], 0) } else { timezone_offset(s, colon_or_space)? };
        if !s.trim_start().is_empty() {
            return Err(TOO_LONG);
        }
        Fields { year, month, day, hour, minute, second, nanosecond: nanos, offset }.to_timestamp()
    }
}
