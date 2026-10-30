//! InfluxDB line protocol:
//!
//! ```text
//! measurement[,tag=value...] field=value[,field=value...] [timestamp_ns]
//! ```
//!
//! Field values: `1.5` / `1` (float, the default), `-3i` (integer), `7u`
//! (unsigned), `t`/`true`/`F`/`false`... (boolean), `"text"` (string).
//! A backslash makes the next character literal (`\,` `\=` `\ ` `\"` `\\`),
//! and `\n` stands for a newline so a point always fits on one line. Blank
//! lines and `#` comments are skipped. Quotes are only meaningful in string
//! field values.

use crate::error::{Error, Result};
use std::collections::BTreeMap;
use std::fmt;
use std::fmt::Write as _;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FieldType {
    Float = 0,
    Int = 1,
    UInt = 2,
    Bool = 3,
    Str = 4,
}

impl FieldType {
    pub fn from_u8(b: u8) -> Option<FieldType> {
        match b {
            0 => Some(FieldType::Float),
            1 => Some(FieldType::Int),
            2 => Some(FieldType::UInt),
            3 => Some(FieldType::Bool),
            4 => Some(FieldType::Str),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum FieldValue {
    Float(f64),
    Int(i64),
    UInt(u64),
    Bool(bool),
    Str(String),
}

impl FieldValue {
    pub fn field_type(&self) -> FieldType {
        match self {
            FieldValue::Float(_) => FieldType::Float,
            FieldValue::Int(_) => FieldType::Int,
            FieldValue::UInt(_) => FieldType::UInt,
            FieldValue::Bool(_) => FieldType::Bool,
            FieldValue::Str(_) => FieldType::Str,
        }
    }

    /// Numeric value as `f64` (`None` for booleans and strings).
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            FieldValue::Float(v) => Some(*v),
            FieldValue::Int(v) => Some(*v as f64),
            FieldValue::UInt(v) => Some(*v as f64),
            FieldValue::Bool(_) | FieldValue::Str(_) => None,
        }
    }

    /// Whether the value can be written (floats must be finite).
    pub fn is_valid(&self) -> bool {
        match self {
            FieldValue::Float(v) => v.is_finite(),
            _ => true,
        }
    }
}

impl fmt::Display for FieldValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FieldValue::Float(v) => write!(f, "{v}"),
            FieldValue::Int(v) => write!(f, "{v}i"),
            FieldValue::UInt(v) => write!(f, "{v}u"),
            FieldValue::Bool(v) => write!(f, "{v}"),
            FieldValue::Str(s) => write!(f, "\"{}\"", escape(s, STR_SPECIALS)),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Point {
    pub measurement: String,
    pub tags: BTreeMap<String, String>,
    pub fields: BTreeMap<String, FieldValue>,
    /// Nanoseconds since the Unix epoch; `None` means "now" at write time.
    pub timestamp: Option<i64>,
}

impl Point {
    pub fn new(measurement: impl Into<String>) -> Self {
        Point {
            measurement: measurement.into(),
            tags: BTreeMap::new(),
            fields: BTreeMap::new(),
            timestamp: None,
        }
    }

    pub fn tag(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.tags.insert(k.into(), v.into());
        self
    }

    pub fn field(mut self, k: impl Into<String>, v: FieldValue) -> Self {
        self.fields.insert(k.into(), v);
        self
    }

    pub fn at(mut self, ts: i64) -> Self {
        self.timestamp = Some(ts);
        self
    }

    /// Checks what the parser would enforce: non-empty measurement, at least
    /// one field, non-empty tag keys/values and field keys, finite floats.
    pub fn validate(&self) -> std::result::Result<(), String> {
        let bad_tag = self.tags.iter().any(|(k, v)| k.is_empty() | v.is_empty());
        let bad_field = self.fields.iter().any(|(k, v)| k.is_empty() | !v.is_valid());
        if self.measurement.is_empty() | self.fields.is_empty() | bad_tag | bad_field {
            return Err(format!("invalid point {self:?}"));
        }
        Ok(())
    }
}

pub const MEASUREMENT_SPECIALS: &[char] = &[',', ' ', '\\', '\n'];
pub const KEY_SPECIALS: &[char] = &[',', '=', ' ', '"', '\\', '\n'];
const STR_SPECIALS: &[char] = &['"', '\\', '\n'];

/// Backslash-escapes every char of `specials` (newline becomes `\n`).
pub fn escape(s: &str, specials: &[char]) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if specials.contains(&c) {
            out.push('\\');
        }
        out.push(if c == '\n' { 'n' } else { c });
    }
    out
}

/// Inverse of [`escape`]: `\x` becomes `x` (`\n` a newline); a lone
/// trailing backslash is kept.
pub fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        let lit = match c {
            '\\' => chars.next().unwrap_or('\\'),
            _ => {
                out.push(c);
                continue;
            }
        };
        out.push(if lit == 'n' { '\n' } else { lit });
    }
    out
}

/// Splits at unescaped `delim` (outside double quotes when `quotes`).
/// Returns the pieces and whether every quote was closed.
fn split(s: &str, delim: char, quotes: bool) -> (Vec<&str>, bool) {
    let mut out = Vec::new();
    let (mut start, mut esc, mut in_quotes) = (0, false, false);
    for (i, c) in s.char_indices() {
        match c {
            _ if esc => esc = false,
            '\\' => esc = true,
            '"' if quotes => in_quotes = !in_quotes,
            _ if (c == delim) & !in_quotes => {
                out.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&s[start..]);
    (out, !in_quotes)
}

/// `key=value` split at the first unescaped `=`: unescaped key, raw value.
fn split_pair(s: &str) -> std::result::Result<(String, &str), String> {
    let (pieces, _) = split(s, '=', false);
    let key = unescape(pieces[0]);
    let value = s.get(pieces[0].len() + 1..).unwrap_or("");
    if key.is_empty() | (pieces.len() < 2) {
        return Err(format!("expected key=value, got {s:?}"));
    }
    Ok((key, value))
}

fn parse_value(raw: &str) -> std::result::Result<FieldValue, String> {
    let bad = || format!("invalid field value {raw:?}");
    if let Some(body) = raw.strip_prefix('"') {
        return body
            .strip_suffix('"')
            .map(|s| FieldValue::Str(unescape(s)))
            .ok_or_else(bad);
    }
    Ok(match raw {
        "t" | "T" | "true" | "True" | "TRUE" => FieldValue::Bool(true),
        "f" | "F" | "false" | "False" | "FALSE" => FieldValue::Bool(false),
        _ if raw.ends_with('i') => FieldValue::Int(raw[..raw.len() - 1].parse().map_err(|_| bad())?),
        _ if raw.ends_with('u') => FieldValue::UInt(raw[..raw.len() - 1].parse().map_err(|_| bad())?),
        _ => {
            let v: f64 = raw.parse().map_err(|_| bad())?;
            if !v.is_finite() {
                return Err(bad());
            }
            FieldValue::Float(v)
        }
    })
}

/// Parses one line (no newline).
pub fn parse_line(line: &str) -> std::result::Result<Point, String> {
    let line = line.trim_start();
    let (head, _) = split(line, ' ', false);
    let key = head[0];
    let rest = line[key.len()..].strip_prefix(' ').ok_or("missing fields")?;
    let (sections, closed) = split(rest, ' ', true);
    let (fields, ts) = match (sections.as_slice(), closed) {
        ([f], true) => (*f, None),
        ([f, t], true) => (*f, Some(*t)),
        _ => return Err(format!("expected `measurement[,tags] fields [timestamp]`: {line:?}")),
    };
    let (key_parts, _) = split(key, ',', false);
    let mut point = Point::new(unescape(key_parts[0]));
    if point.measurement.is_empty() {
        return Err("empty measurement".into());
    }
    for t in &key_parts[1..] {
        let (k, v) = split_pair(t)?;
        let v = unescape(v);
        if v.is_empty() | point.tags.insert(k.clone(), v).is_some() {
            return Err(format!("empty or duplicate tag {k:?}"));
        }
    }
    let (field_parts, _) = split(fields, ',', true);
    for f in field_parts {
        let (k, raw) = split_pair(f)?;
        let v = parse_value(raw)?;
        if point.fields.insert(k.clone(), v).is_some() {
            return Err(format!("duplicate field {k:?}"));
        }
    }
    point.timestamp = ts
        .map(|t| t.parse::<i64>().map_err(|_| format!("invalid timestamp {t:?}")))
        .transpose()?;
    Ok(point)
}

/// Parses a whole payload; errors carry the 1-based line number.
pub fn parse(input: &str) -> Result<Vec<Point>> {
    input
        .lines()
        .enumerate()
        .filter(|(_, l)| {
            let l = l.trim_start();
            !l.is_empty() & !l.starts_with('#')
        })
        .map(|(i, l)| parse_line(l).map_err(|msg| Error::Parse { line: i + 1, msg }))
        .collect()
}

/// Formats `p` as one line (without newline); `parse_line` inverts it.
pub fn to_line(p: &Point) -> String {
    let mut s = String::new();
    write_line(&mut s, p, p.timestamp);
    s
}

/// Appends `p` to `out` as one line with timestamp `ts` (no newline).
pub fn write_line(out: &mut String, p: &Point, ts: Option<i64>) {
    out.push_str(&escape(&p.measurement, MEASUREMENT_SPECIALS));
    for (k, v) in &p.tags {
        let _ = write!(out, ",{}={}", escape(k, KEY_SPECIALS), escape(v, KEY_SPECIALS));
    }
    for (i, (k, v)) in p.fields.iter().enumerate() {
        let sep = if i == 0 { ' ' } else { ',' };
        let _ = write!(out, "{sep}{}={v}", escape(k, KEY_SPECIALS));
    }
    if let Some(ts) = ts {
        let _ = write!(out, " {ts}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_line() {
        let p = parse_line("cpu,host=a,region=eu usage=0.5,count=3i,big=7u,up=t,name=\"x y\" 1700").unwrap();
        assert_eq!(p.measurement, "cpu");
        assert_eq!(p.tags["host"], "a");
        assert_eq!(p.tags["region"], "eu");
        assert_eq!(p.fields["usage"], FieldValue::Float(0.5));
        assert_eq!(p.fields["count"], FieldValue::Int(3));
        assert_eq!(p.fields["big"], FieldValue::UInt(7));
        assert_eq!(p.fields["up"], FieldValue::Bool(true));
        assert_eq!(p.fields["name"], FieldValue::Str("x y".into()));
        assert_eq!(p.timestamp, Some(1700));
        let q = parse_line("  m f=1").unwrap();
        assert_eq!((q.timestamp, q.fields["f"].clone()), (None, FieldValue::Float(1.0)));
    }

    #[test]
    fn booleans_and_escapes() {
        for (s, b) in [
            ("t", true),
            ("T", true),
            ("true", true),
            ("True", true),
            ("TRUE", true),
            ("f", false),
            ("F", false),
            ("false", false),
            ("False", false),
            ("FALSE", false),
        ] {
            assert_eq!(
                parse_line(&format!("m v={s}")).unwrap().fields["v"],
                FieldValue::Bool(b)
            );
        }
        let p = parse_line(r#"my\ m,t\,k=v\=1\ 2 f\ k="a \"q\" \\ b,c",g=-2i"#).unwrap();
        assert_eq!(p.measurement, "my m");
        assert_eq!(p.tags["t,k"], "v=1 2");
        assert_eq!(p.fields["f k"], FieldValue::Str(r#"a "q" \ b,c"#.into()));
        assert_eq!(p.fields["g"], FieldValue::Int(-2));
        assert_eq!(unescape("a\\"), "a\\");
        assert_eq!(unescape("a\\nb"), "a\nb");
    }

    #[test]
    fn rejects_malformed_lines() {
        for bad in [
            "m",
            "m ",
            ",t=v f=1",
            "m,t f=1",
            "m,t= f=1",
            "m,=v f=1",
            "m,t=a,t=b f=1",
            "m f",
            "m =1",
            "m f=1,f=2",
            "m f=1 2 3",
            "m f=\"open",
            "m f=\"a\"b",
            "m f=\"",
            "m f=1x",
            "m f=xi",
            "m f=-1u",
            "m f=inf",
            "m f=1 abc",
        ] {
            assert!(parse_line(bad).is_err(), "{bad:?} should fail");
        }
    }

    #[test]
    fn payload_with_comments_and_line_numbers() {
        let pts = parse("# header\n\ncpu v=1 1\r\ncpu v=2 2\n").unwrap();
        assert_eq!(pts.len(), 2);
        let err = parse("cpu v=1\ncpu oops\n").unwrap_err().to_string();
        assert_eq!(err, "line 2: expected key=value, got \"oops\"");
    }

    #[test]
    fn roundtrip_through_to_line() {
        let p = Point::new("a b,c\nd")
            .tag("k=1", "v 2,\\")
            .tag("z", "\n")
            .field("q\"k", FieldValue::Int(0))
            .field("f", FieldValue::Float(-0.25))
            .field("i", FieldValue::Int(i64::MIN))
            .field("u", FieldValue::UInt(u64::MAX))
            .field("b", FieldValue::Bool(false))
            .field("s", FieldValue::Str("say \"hi\"\n\\".into()))
            .at(-5);
        let line = to_line(&p);
        assert!(!line.contains('\n'));
        assert_eq!(parse_line(&line).unwrap(), p);
        let no_ts = Point::new("m").field("x", FieldValue::Float(1e300));
        assert_eq!(parse_line(&to_line(&no_ts)).unwrap(), no_ts);
    }

    #[test]
    fn types_and_validation() {
        let all = [
            FieldValue::Float(1.0),
            FieldValue::Int(-1),
            FieldValue::UInt(1),
            FieldValue::Bool(true),
            FieldValue::Str("s".into()),
        ];
        for (i, v) in all.iter().enumerate() {
            assert_eq!(FieldType::from_u8(i as u8), Some(v.field_type()));
            assert!(v.is_valid());
        }
        assert_eq!(FieldType::from_u8(5), None);
        assert_eq!(
            all.iter().map(|v| v.as_f64()).collect::<Vec<_>>(),
            vec![Some(1.0), Some(-1.0), Some(1.0), None, None]
        );
        assert!(!FieldValue::Float(f64::NAN).is_valid());
        let ok = Point::new("m").tag("t", "v").field("f", FieldValue::Int(1));
        assert!(ok.validate().is_ok());
        assert!(Point::new("m").validate().is_err());
        assert!(Point::new("").field("f", FieldValue::Int(1)).validate().is_err());
        assert!(ok.clone().tag("e", "").validate().is_err());
        assert!(ok.clone().field("", FieldValue::Int(1)).validate().is_err());
        assert!(ok.field("n", FieldValue::Float(f64::INFINITY)).validate().is_err());
    }
}
