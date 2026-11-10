//! The plain kind of line protocol, straight into columns.
//!
//! Most of what is written is lines of series that have been seen, with the
//! same fields, in the same order, as every line before: `cpu,host=a usage=1.5,
//! idle=3i 1700000000000000000`. For those there is no need to make a point
//! of a line, with a `String` for the measurement, a tree for the tags and
//! another for the fields. The text of a series (`cpu,host=a`) is looked up
//! as it is, and says which columns the fields of the line go to, so the
//! values are parsed straight into the vectors of those columns.
//!
//! Only lines without a backslash or a quote are plain. A line of a series
//! that is not known, a field that is not where the last line had it, a value
//! that is not of the type of its column, a string: the whole payload is then
//! left to [`crate::lineproto`], which does everything and says what is wrong
//! with it. What this makes is what that makes (and the tests say so).

use crate::batch::{Batch, ColumnPoints};
use crate::chunk::Column;
use crate::lineproto::FieldType;
use std::collections::HashMap;
use std::str::FromStr;

/// The most series that are remembered.
pub(crate) const MAX_SERIES: usize = 1 << 20;

/// The fields of the lines of a series, in order, and where they go.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Fields(pub Vec<(Box<str>, u64, FieldType)>);

/// The series that plain lines can be made of, by the text of the line up to
/// the first space: measurement and tags, as written.
pub(crate) type Cache = HashMap<Box<str>, Fields>;

/// What a line is made of, if it is plain: the text of the series, the text
/// of the fields, and the timestamp, if there is one. `None` for what is not
/// a plain line (which includes a line that should be left out, and a
/// payload with one: this is about lines to write).
fn split(line: &str) -> Option<(&str, &str, Option<&str>)> {
    let bytes = line.as_bytes();
    let special = |b: &u8| matches!(b, b' ' | b'\\' | b'"' | b'\r');
    let first = bytes.iter().position(special).filter(|&i| bytes[i] == b' ')?;
    let rest = &line[first + 1..];
    let bytes = rest.as_bytes();
    match bytes.iter().position(special) {
        None => Some((&line[..first], rest, None)),
        Some(i) if bytes[i] == b' ' => {
            let time = &rest[i + 1..];
            // Nothing special after the timestamp, which is a number.
            let plain = time.bytes().all(|b| b.is_ascii_digit() | (b == b'-'));
            plain.then_some((&line[..first], &rest[..i], Some(time)))
        }
        Some(_) => None,
    }
}

/// The float that starts `bytes`, if it is of the plain form (an optional
/// minus, digits, a dot and digits, at most 15 of them altogether), and how
/// many bytes it is. A number that has at most 15 digits is exact as a
/// double, and so is the power of ten that it is divided by (up to 10^22):
/// the quotient is the double that is nearest to the number, which is what
/// parsing makes.
fn float_prefix(bytes: &[u8]) -> Option<(f64, usize)> {
    const POWERS: [f64; 16] = [
        1e0, 1e1, 1e2, 1e3, 1e4, 1e5, 1e6, 1e7, 1e8, 1e9, 1e10, 1e11, 1e12, 1e13, 1e14, 1e15,
    ];
    let negative = bytes.first() == Some(&b'-');
    let start = usize::from(negative);
    let (mut mantissa, mut digits, mut dot) = (0u64, 0usize, None::<usize>);
    let mut end = start;
    for &b in &bytes[start..] {
        match b {
            b'0'..=b'9' => mantissa = mantissa.wrapping_mul(10).wrapping_add(u64::from(b - b'0')),
            b'.' if dot.is_none() => dot = Some(end),
            _ => break,
        }
        end += 1;
        digits += usize::from(b != b'.');
    }
    // Digits on both sides of a dot, or no dot, and not too many.
    let after_dot = dot.map_or(0, |at| end - at - 1);
    let whole = (digits > after_dot) | (dot.is_none() & (digits > 0));
    if !whole | (digits > 15) | (dot.is_some() & (after_dot == 0)) {
        return None;
    }
    let value = mantissa as f64 / POWERS[after_dot];
    Some((if negative { -value } else { value }, end))
}

/// The value of `text` as a float, as `str::parse` makes it, if that is
/// finite (what a line can have): the plain forms are made without it.
pub(crate) fn parse_float(text: &str) -> Option<f64> {
    match float_prefix(text.as_bytes()) {
        Some((value, used)) if used == text.len() => Some(value),
        _ => text.parse::<f64>().ok().filter(|v| v.is_finite()),
    }
}

/// An integer of at most 18 digits (so that it fits), with a minus if the
/// type has it, at the start of `bytes`: its value, and how many bytes it is.
fn int_prefix(bytes: &[u8], signed: bool) -> Option<(i64, usize)> {
    let negative = signed & (bytes.first() == Some(&b'-'));
    let start = usize::from(negative);
    let digits = bytes[start..].iter().take_while(|b| b.is_ascii_digit()).count();
    if !(1..=18).contains(&digits) {
        return None;
    }
    let end = start + digits;
    let value = bytes[start..end]
        .iter()
        .fold(0i64, |v, &b| v * 10 + i64::from(b - b'0'));
    Some((if negative { -value } else { value }, end))
}

/// Whether `bytes` goes on with the end of a value, or of the line.
fn ends_value(bytes: &[u8], at: usize) -> bool {
    matches!(bytes.get(at), None | Some(b',' | b' '))
}

/// The length of the value that starts `bytes`.
fn value_len(bytes: &[u8]) -> usize {
    bytes
        .iter()
        .position(|b| matches!(b, b',' | b' '))
        .unwrap_or(bytes.len())
}

fn parse_bool(text: &str) -> Option<bool> {
    match text {
        "t" | "T" | "true" | "True" | "TRUE" => Some(true),
        "f" | "F" | "false" | "False" | "FALSE" => Some(false),
        _ => None,
    }
}

/// The integer that starts `text` and ends with `suffix`, as `T` (which
/// `i64` turns into without loss), and the length of both: the quick form
/// when there are at most 18 digits, else what `str::parse` makes.
fn suffixed<T: FromStr + From<i64>>(text: &str, suffix: u8, signed: bool) -> Option<(T, usize)> {
    let bytes = text.as_bytes();
    let (value, used) = match int_prefix(bytes, signed) {
        Some((v, used)) => (T::from(v), used),
        None => {
            let digits = value_len(bytes).checked_sub(1)?;
            (text[..digits].parse().ok()?, digits)
        }
    };
    (bytes.get(used) == Some(&suffix) && ends_value(bytes, used + 1)).then_some((value, used + 1))
}

/// The unsigned integer that starts `text` and ends with `u`, and the length
/// of both.
fn unsigned(text: &str) -> Option<(u64, usize)> {
    let bytes = text.as_bytes();
    let (value, used) = match int_prefix(bytes, false) {
        Some((v, used)) => (v as u64, used),
        None => {
            let digits = value_len(bytes).checked_sub(1)?;
            (text[..digits].parse().ok()?, digits)
        }
    };
    (bytes.get(used) == Some(&b'u') && ends_value(bytes, used + 1)).then_some((value, used + 1))
}

/// Adds the value that starts `bytes` to `column` as a point at `ts`, if it
/// is of the type of the column and a plain one; returns the length of the
/// value. What is not made with the quick forms is left to `str::parse`, which
/// does what the line protocol parser does.
fn push(column: &mut ColumnPoints, ts: i64, text: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    let len = match &mut column.values {
        Column::Float(v) => {
            let (value, len) = match float_prefix(bytes).filter(|&(_, used)| ends_value(bytes, used)) {
                Some(found) => found,
                None => {
                    let len = value_len(bytes);
                    (parse_float(&text[..len])?, len)
                }
            };
            v.push(value);
            len
        }
        Column::Int(v) => {
            let (value, len) = suffixed::<i64>(text, b'i', true)?;
            v.push(value);
            len
        }
        Column::UInt(v) => {
            let (value, len) = unsigned(text)?;
            v.push(value);
            len
        }
        Column::Bool(v) => {
            let len = value_len(bytes);
            v.push(parse_bool(&text[..len])?);
            len
        }
        Column::Str(_) => return None,
    };
    column.ts.push(ts);
    Some(len)
}

/// The points of the plain lines of `text`, by column, and how many lines
/// there are: if all the lines are plain, of series that are in `cache`, with
/// the fields in the order that it says, and values of the types it says. A
/// line that has no timestamp gets `now`. `None` if there is a line that is
/// not like that.
pub(crate) fn parse(text: &str, cache: &Cache, now: i64) -> Option<(Batch, usize)> {
    let mut batch = Batch::default();
    let mut lines = 0;
    // A column gets about as many points as there are lines for a series.
    let per_series = text.bytes().filter(|&b| b == b'\n').count() / cache.len().max(1);
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        // The text of a series that is in the cache has no backslash, no
        // quote and no space in it; so there is nothing to look for in it.
        let (series, rest) = line.split_once(' ')?;
        let Fields(slots) = cache.get(series)?;
        let (fields, ts) = match rest.split_once(' ') {
            Some((fields, time)) if time.bytes().all(|b| b.is_ascii_digit() | (b == b'-')) => {
                (fields, time.parse::<i64>().ok()?)
            }
            Some(_) => return None,
            None => (rest, now),
        };
        let mut rest = fields;
        for (i, (name, col, ty)) in slots.iter().enumerate() {
            rest = rest.strip_prefix(&**name)?.strip_prefix('=')?;
            let column = batch
                .entry(*col)
                .or_insert_with(|| ColumnPoints::with_capacity(*ty, per_series + 1));
            // (A value ends at a comma or a space, so the cut is at a character.)
            rest = &rest[push(column, ts, rest)?..];
            rest = match (rest.as_bytes().first(), i + 1 == slots.len()) {
                (Some(b','), false) => &rest[1..],
                (None, true) => rest,
                _ => return None,
            };
        }
        lines += 1;
    }
    Some((batch, lines))
}

/// `text` in pieces of about `size` bytes that are made of whole lines.
pub(crate) fn segments(text: &str, size: usize) -> Vec<&str> {
    let mut pieces = Vec::new();
    let mut rest = text;
    while rest.len() > size {
        let Some(end) = rest.as_bytes()[size..].iter().position(|&b| b == b'\n') else {
            break;
        };
        let (piece, tail) = rest.split_at(size + end + 1);
        pieces.push(piece);
        rest = tail;
    }
    if !(rest.is_empty() & !pieces.is_empty()) {
        pieces.push(rest);
    }
    pieces
}

/// What `line`, if plain, says about its series: its text, and the names of
/// its fields in the order they are in.
pub(crate) fn plain_fields(line: &str) -> Option<(&str, Vec<&str>)> {
    let (series, fields, _) = split(line)?;
    let names = fields
        .split(',')
        .map(|f| f.split_once('=').map(|(name, _)| name))
        .collect::<Option<Vec<_>>>()?;
    Some((series, names))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_line_is_cut_in_three_if_it_is_plain() {
        assert_eq!(split("cpu,h=a v=1 5"), Some(("cpu,h=a", "v=1", Some("5"))));
        assert_eq!(split("cpu v=1,w=2"), Some(("cpu", "v=1,w=2", None)));
        assert_eq!(split("cpu v=1 -5"), Some(("cpu", "v=1", Some("-5"))));
        for not_plain in [
            "",
            "cpu",
            " cpu v=1",
            "cpu\\ x v=1",
            "cpu,h=\"a\" v=1",
            "cpu v=\"a b\"",
            "cpu v=1 5 6",
            "cpu v=1 5x",
            "cpu v=1 \\5",
            "cpu v=1\rx",
            "cpu v=1 5\rx",
            "cpu  v=1",
        ] {
            assert_eq!(split(not_plain), None, "{not_plain:?}");
        }
    }

    #[test]
    fn floats_are_what_str_parse_makes() {
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut texts: Vec<String> = [
            "0",
            "-0",
            "0.0",
            "1",
            "1.",
            ".5",
            "-.5",
            "+1.5",
            "1e3",
            "1E-3",
            "1.5e300",
            "123456789012345",
            "1234567890123456",
            "0.000000000000001",
            "0.0000000000000001",
            "99999999999999.9",
            "-",
            "",
            ".",
            "-.",
            "1.2.3",
            "1,5",
            "abc",
            "inf",
            "-inf",
            "nan",
            "NaN",
            "1e999",
            "-1e999",
            "1e-999",
            "0x10",
            "1 ",
            " 1",
            "１",
        ]
        .map(String::from)
        .to_vec();
        for _ in 0..20_000 {
            let digits = next() % 19;
            let mantissa: String = (0..digits).map(|_| char::from(b'0' + (next() % 10) as u8)).collect();
            let dot = next() as usize % (mantissa.len() + 1);
            let sign = ["", "-", "+"][next() as usize % 3];
            texts.push(format!("{sign}{}.{}", &mantissa[..dot], &mantissa[dot..]));
            texts.push(format!("{sign}{mantissa}"));
        }
        for text in &texts {
            let want = text.parse::<f64>().ok().filter(|v| v.is_finite());
            let got = parse_float(text);
            assert_eq!(got.map(f64::to_bits), want.map(f64::to_bits), "{text:?}");
        }
    }

    fn cache() -> Cache {
        let fields =
            |names: &[(&str, u64, FieldType)]| Fields(names.iter().map(|&(n, c, t)| (n.into(), c, t)).collect());
        let mut cache = Cache::new();
        cache.insert(
            "cpu,host=a".into(),
            fields(&[
                ("usage", 0, FieldType::Float),
                ("cores", 1, FieldType::Int),
                ("up", 2, FieldType::Bool),
            ]),
        );
        cache.insert("m".into(), fields(&[("n", 3, FieldType::UInt)]));
        cache.insert("s".into(), fields(&[("text", 4, FieldType::Str)]));
        cache
    }

    #[test]
    fn plain_lines_of_known_series_go_into_columns() {
        let text = "cpu,host=a usage=1.5,cores=4i,up=t 10\n\nm n=7u\ncpu,host=a usage=-2,cores=-1i,up=FALSE 20\n";
        let (batch, lines) = parse(text, &cache(), 99).unwrap();
        assert_eq!(lines, 3);
        assert_eq!(batch[&0].ts, vec![10, 20]);
        assert_eq!(batch[&0].values, Column::Float(vec![1.5, -2.0]));
        assert_eq!(batch[&1].values, Column::Int(vec![4, -1]));
        assert_eq!(batch[&2].values, Column::Bool(vec![true, false]));
        // No timestamp: the time that is given.
        assert_eq!(
            (batch[&3].ts.clone(), batch[&3].values.clone()),
            (vec![99], Column::UInt(vec![7]))
        );
        assert_eq!(batch.len(), 4);
    }

    #[test]
    fn anything_else_is_left_to_the_slow_way() {
        let known = "cpu,host=a usage=1.5,cores=4i,up=t 10";
        assert!(parse(known, &cache(), 0).is_some());
        // No line at all is nothing to write.
        assert_eq!(parse("", &cache(), 0).unwrap().1, 0);
        assert_eq!(parse("\n\n", &cache(), 0).unwrap().1, 0);
        for line in [
            // a series that is not known, in the text as it is
            "cpu,host=b usage=1.5,cores=4i,up=t 10",
            "cpu,host=a,x=y usage=1.5,cores=4i,up=t 10",
            // the fields not where they were: another order, fewer, more, other names
            "cpu,host=a cores=4i,usage=1.5,up=t 10",
            "cpu,host=a usage=1.5,cores=4i 10",
            "cpu,host=a usage=1.5,cores=4i,up=t,extra=1 10",
            "cpu,host=a usage=1.5,cores=4i,upx=t 10",
            "cpu,host=a usage=1.5,cores=4i,up 10",
            "cpu,host=a usage=1.5 cores=4i 10",
            "cpu,host=a usage=1.5,,cores=4i,up=t 10",
            // values of other types than the columns, or no value
            "cpu,host=a usage=1i,cores=4i,up=t 10",
            "cpu,host=a usage=1u,cores=4i,up=t 10",
            "cpu,host=a usage=t,cores=4i,up=t 10",
            "cpu,host=a usage=1.5,cores=4,up=t 10",
            "cpu,host=a usage=1.5,cores=4.5i,up=t 10",
            "cpu,host=a usage=1.5,cores=4u,up=t 10",
            "cpu,host=a usage=1.5,cores=4i,up=yes 10",
            "cpu,host=a usage=nan,cores=4i,up=t 10",
            "cpu,host=a usage=inf,cores=4i,up=t 10",
            "cpu,host=a usage=,cores=4i,up=t 10",
            "m n=-1u",
            "m n=1",
            // a string column, which is never fast
            "s text=a",
            // a timestamp that is not one
            "cpu,host=a usage=1.5,cores=4i,up=t 1.5",
            "cpu,host=a usage=1.5,cores=4i,up=t x",
            "cpu,host=a usage=1.5,cores=4i,up=t 99999999999999999999",
            // not plain
            "cpu\\,host=a usage=1.5,cores=4i,up=t 10",
        ] {
            assert!(parse(line, &cache(), 0).is_none(), "{line:?}");
            // One line like that makes the whole payload slow.
            assert!(parse(&format!("{known}\n{line}"), &cache(), 0).is_none(), "{line:?}");
        }
    }

    /// A value of a column of each type, as `lineproto` and the fast way read it.
    #[test]
    fn values_are_read_as_the_line_protocol_parser_reads_them() {
        use crate::lineproto::{parse_line, FieldValue};
        let mut state = 0x2545_f491_4f6c_dd1d_u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut texts: Vec<String> = [
            "1",
            "-1",
            "0",
            "-0",
            "+1",
            "1.5",
            "-1.5",
            "1e3",
            "1E3",
            "1.5e-3",
            "t",
            "T",
            "true",
            "True",
            "TRUE",
            "f",
            "F",
            "false",
            "False",
            "FALSE",
            "tRuE",
            "yes",
            "1i",
            "-1i",
            "+1i",
            "0i",
            "-0i",
            "1u",
            "0u",
            "-1u",
            "+1u",
            "9223372036854775807i",
            "9223372036854775808i",
            "-9223372036854775808i",
            "-9223372036854775809i",
            "18446744073709551615u",
            "18446744073709551616u",
            "999999999999999999i",
            "9999999999999999999i",
            "1ii",
            "i",
            "u",
            "-i",
            "1.5i",
            "1.i",
            ".5i",
            "1e3i",
            "1.",
            ".5",
            "-.5",
            ".",
            "-",
            "",
            "nan",
            "inf",
            "-inf",
            "1e999",
            "0x1",
            "1_0",
            "1,5",
            "000000000000000000001i",
            "00000000000000000001.5",
            "123456789012345.5",
            "0.1234567890123456",
        ]
        .map(String::from)
        .to_vec();
        for _ in 0..3000 {
            let digits = 1 + next() % 20;
            let n: String = (0..digits).map(|_| char::from(b'0' + (next() % 10) as u8)).collect();
            let sign = ["", "-", "+"][next() as usize % 3];
            texts.push(format!("{sign}{n}"));
            texts.push(format!("{sign}{n}i"));
            texts.push(format!("{sign}{n}u"));
            let dot = next() as usize % (n.len() + 1);
            texts.push(format!("{sign}{}.{}", &n[..dot], &n[dot..]));
        }
        let types = [FieldType::Float, FieldType::Int, FieldType::UInt, FieldType::Bool];
        for text in &texts {
            // What the slow way makes of `m v=<text> 5`, and of the text without a timestamp.
            let slow = parse_line(&format!("m v={text} 5")).ok().map(|p| p.fields["v"].clone());
            for ty in types {
                let mut cache = Cache::new();
                cache.insert("m".into(), Fields(vec![("v".into(), 0, ty)]));
                for line in [format!("m v={text} 5"), format!("m v={text}")] {
                    let fast = parse(&line, &cache, 5).and_then(|(batch, _)| {
                        assert_eq!(batch[&0].ts, vec![5], "{line:?}");
                        (batch[&0].len() == 1).then(|| batch[&0].values.get(0))
                    });
                    let want = slow.clone().filter(|v| v.field_type() == ty);
                    match (&fast, &want) {
                        (Some(FieldValue::Float(a)), Some(FieldValue::Float(b))) => {
                            assert_eq!(a.to_bits(), b.to_bits(), "{line:?}")
                        }
                        // (What has no quick form is left to `str::parse`, so nothing is left out.)
                        _ => assert_eq!(fast, want, "{line:?} {ty:?}"),
                    }
                }
            }
        }
    }

    #[test]
    fn text_is_cut_into_pieces_of_whole_lines() {
        let text = "aaaa\nbb\ncccccc\nd\n\nééé\nlast";
        for size in [0, 1, 4, 5, 6, 9, 14, 100] {
            let pieces = segments(text, size);
            assert_eq!(pieces.concat(), text, "{size}");
            assert!(pieces[..pieces.len() - 1].iter().all(|p| p.ends_with('\n')), "{size}");
        }
        assert_eq!(segments(text, 5), ["aaaa\nbb\n", "cccccc\n", "d\n\nééé\n", "last"][..]);
        assert_eq!(segments("", 5), [""]);
        // The cut is not made inside a character.
        assert_eq!(segments("é\né\n", 1), ["é\n", "é\n"]);
        assert_eq!(segments("no newline at all", 3), ["no newline at all"]);
    }

    #[test]
    fn the_names_of_the_fields_of_a_plain_line() {
        assert_eq!(plain_fields("cpu,h=a x=1,y=2 5"), Some(("cpu,h=a", vec!["x", "y"])));
        assert_eq!(plain_fields("cpu x=1"), Some(("cpu", vec!["x"])));
        assert_eq!(plain_fields("cpu x"), None);
        assert_eq!(plain_fields("cpu x=1,y"), None);
        assert_eq!(plain_fields("cpu \"x\"=1"), None);
    }
}
