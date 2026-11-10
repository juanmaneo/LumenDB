//! Durations and instants as a person writes them, for the command line:
//! `90s`, `1h`, `2024-05-01`, `2024-05-01T12:30:00.5+02:00`, `now-1h`.
//! They all end up as integer nanoseconds, UTC, since 1970-01-01. Months and
//! years are not units: their length varies, and a window of "one month" would
//! not be a fixed number of nanoseconds.

use std::time::{SystemTime, UNIX_EPOCH};

const SECOND: i64 = 1_000_000_000;

/// Units of a duration, longest suffix first (`ms` before `s`).
const UNITS: [(&str, i64); 8] = [
    ("ns", 1),
    ("us", 1_000),
    ("ms", 1_000_000),
    ("s", SECOND),
    ("m", 60 * SECOND),
    ("h", 3_600 * SECOND),
    ("d", 86_400 * SECOND),
    ("w", 7 * 86_400 * SECOND),
];

/// The wall clock, in ns since the epoch.
pub fn now_ns() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_nanos()).unwrap_or(i64::MAX))
}

/// `<digits><unit>` with the unit one of `ns us ms s m h d w`, or digits
/// alone for ns. `None` for anything else, a sign, and an overflow.
pub fn parse_duration(s: &str) -> Option<i64> {
    let (digits, unit) = UNITS
        .iter()
        .find_map(|&(name, ns)| s.strip_suffix(name).map(|d| (d, ns)))
        .unwrap_or((s, 1));
    if !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse::<i64>().ok()?.checked_mul(unit)
}

/// An instant: an integer (ns since the epoch, possibly negative), `now`,
/// `now-DURATION` or `now+DURATION` (relative to `now`), or an RFC 3339
/// date, `YYYY-MM-DD[Thh:mm:ss[.f]][Z|+hh:mm|-hh:mm]` (a space also
/// separates the date from the time; no offset means UTC).
pub fn parse_time(s: &str, now: i64) -> Option<i64> {
    if let Ok(ns) = s.parse() {
        return Some(ns);
    }
    match s.strip_prefix("now") {
        Some("") => Some(now),
        Some(rest) => {
            let ns = parse_duration(rest.get(1..)?)?;
            match rest.as_bytes()[0] {
                b'-' => now.checked_sub(ns),
                b'+' => now.checked_add(ns),
                _ => None,
            }
        }
        None => parse_rfc3339(s),
    }
}

/// Exactly `n` ASCII digits at the start of `s`, and what follows them.
fn digits(s: &str, n: usize) -> Option<(i64, &str)> {
    let head = s.get(..n)?;
    let value = head
        .bytes()
        .try_fold(0, |acc, b| b.is_ascii_digit().then(|| acc * 10 + i64::from(b - b'0')))?;
    Some((value, &s[n..]))
}

fn parse_rfc3339(s: &str) -> Option<i64> {
    let (year, s) = digits(s, 4)?;
    let (month, s) = digits(s.strip_prefix('-')?, 2)?;
    let (day, s) = digits(s.strip_prefix('-')?, 2)?;
    if !(1..=12).contains(&month) | (day < 1) | (day > days_in_month(year, month)) {
        return None;
    }
    let mut seconds = days_from_civil(year, month, day) * 86_400;
    let mut nanos = 0;
    let mut zone = s;
    if let Some(t) = s.strip_prefix(['T', ' ']) {
        let (hour, t) = digits(t, 2)?;
        let (minute, t) = digits(t.strip_prefix(':')?, 2)?;
        let (second, t) = digits(t.strip_prefix(':')?, 2)?;
        if (hour > 23) | (minute > 59) | (second > 59) {
            return None;
        }
        seconds += hour * 3_600 + minute * 60 + second;
        zone = t;
        if let Some(t) = t.strip_prefix('.') {
            let n = t.bytes().take_while(u8::is_ascii_digit).count();
            if !(1..=9).contains(&n) {
                return None;
            }
            let fraction = t.bytes().take(n).fold(0, |acc, b| acc * 10 + i64::from(b - b'0'));
            nanos = fraction * 10_i64.pow(9 - n as u32);
            zone = &t[n..];
        }
    }
    seconds -= parse_zone(zone)?;
    i64::try_from(i128::from(seconds) * i128::from(SECOND) + i128::from(nanos)).ok()
}

/// The offset of a zone from UTC, in seconds: `Z`, nothing, `+hh:mm`, `-hh:mm`.
fn parse_zone(z: &str) -> Option<i64> {
    if matches!(z, "" | "Z" | "z") {
        return Some(0);
    }
    let sign = match z.as_bytes()[0] {
        b'+' => 1,
        b'-' => -1,
        _ => return None,
    };
    let (hour, t) = digits(&z[1..], 2)?;
    let (minute, t) = digits(t.strip_prefix(':')?, 2)?;
    if (hour > 23) | (minute > 59) | !t.is_empty() {
        return None;
    }
    Some(sign * (hour * 3_600 + minute * 60))
}

fn days_in_month(year: i64, month: i64) -> i64 {
    let leap = (year % 4 == 0) & ((year % 100 != 0) | (year % 400 == 0));
    match month {
        2 => 28 + i64::from(leap),
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days from 1970-01-01 to a valid date (Howard Hinnant's algorithm).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = year - i64::from(month <= 2);
    let era = y.div_euclid(400);
    let year_of_era = y - era * 400;
    let day_of_year = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        for (s, ns) in [
            ("0", 0),
            ("7", 7),
            ("7ns", 7),
            ("3us", 3_000),
            ("5ms", 5_000_000),
            ("10s", 10 * SECOND),
            ("2m", 120 * SECOND),
            ("1h", 3_600 * SECOND),
            ("1d", 86_400 * SECOND),
            ("2w", 14 * 86_400 * SECOND),
        ] {
            assert_eq!(parse_duration(s), Some(ns), "{s}");
        }
        for s in [
            "",
            "s",
            "h",
            "1x",
            "1 h",
            "-5s",
            "+5s",
            "1.5s",
            "1M",
            "1y",
            "1hh",
            "99999999999999999999",
            "9223372036854775807w",
        ] {
            assert_eq!(parse_duration(s), None, "{s}");
        }
    }

    #[test]
    fn instants() {
        let now = 1_700_000_000 * SECOND;
        for (s, want) in [
            ("0", 0),
            ("-5", -5),
            ("1700000000000000000", now),
            ("now", now),
            ("now-1h", now - 3_600 * SECOND),
            ("now+30s", now + 30 * SECOND),
            ("1970-01-01", 0),
            ("1970-01-01T00:00:01Z", SECOND),
            ("2023-11-14T22:13:20Z", now),
            ("2023-11-14 22:13:20", now),
            ("2023-11-14T22:13:20z", now),
            ("2023-11-14T22:13:20.5Z", now + SECOND / 2),
            ("2023-11-14T22:13:20.000000001", now + 1),
            ("2023-11-15T00:13:20+02:00", now),
            ("2023-11-14T20:43:20-01:30", now),
            ("1969-12-31T23:59:59Z", -SECOND),
            ("2024-02-29", 1_709_164_800 * SECOND),
            ("2000-02-29", 951_782_400 * SECOND),
            ("2262-04-11T23:47:16.854775807Z", i64::MAX),
        ] {
            assert_eq!(parse_time(s, now), Some(want), "{s}");
        }
    }

    #[test]
    fn invalid_instants() {
        let now = 0;
        for s in [
            "",
            "soon",
            "now-",
            "now+",
            "now*1h",
            "now-x",
            "now1h",
            "now-é",
            "nowé",
            "9223372036854775808",
            "2023-13-01",
            "2023-00-01",
            "2023-04-31",
            "2023-02-29",
            "1900-02-29",
            "2023-01-00",
            "2023-1-01",
            "2023/01/01",
            "2023-01-01x",
            "2023-01-01T24:00:00Z",
            "2023-01-01T00:60:00Z",
            "2023-01-01T00:00:60Z",
            "2023-01-01T00:00:00.Z",
            "2023-01-01T00:00:00.1234567890Z",
            "2023-01-01T00:00:00+24:00",
            "2023-01-01T00:00:00+00:60",
            "2023-01-01T00:00:00+0000",
            "2023-01-01T00:00:00+00:00x",
            "2023-01-01T00:00:00*00:00",
            "2023-01-01T00:00:00Zx",
            "+2023-01-01",
            "٢٠٢٣-01-01",
            "2262-04-11T23:47:16.854775808Z",
            "9999-12-31",
            "0000-01-01",
        ] {
            assert_eq!(parse_time(s, now), None, "{s}");
        }
        assert_eq!(parse_time("now-1h", i64::MIN), None);
        assert_eq!(parse_time("now+1h", i64::MAX), None);
        // Every truncation of a valid instant is invalid, or a valid shorter one.
        let full = "2023-11-14T22:13:20.123456789+02:00";
        let valid: Vec<usize> = (0..full.len())
            .filter(|&n| parse_time(&full[..n], now).is_some())
            .collect();
        // The first four are plain integers; then a date, a time, and 1 to 9 fraction digits.
        let want: Vec<usize> = [1, 2, 3, 4, 10, 19].into_iter().chain(21..=29).collect();
        assert_eq!(valid, want);
    }

    #[test]
    fn the_wall_clock_is_after_2023() {
        assert!(now_ns() > 1_700_000_000 * SECOND);
    }
}
