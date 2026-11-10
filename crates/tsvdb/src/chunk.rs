//! Immutable columnar chunk: the timestamps and values of one column (series
//! × field) inside one partition, compressed in the spirit of Gorilla
//! (Pelkonen et al., VLDB 2015) without any external codec:
//!
//! - timestamps: first value, then zigzag varint *delta-of-deltas* (regular
//!   sampling costs one byte per point);
//! - floats: XOR with the previous value, storing only the meaningful bits
//!   with a reusable leading/trailing-zero window (bit-packed);
//! - integers / unsigned: zigzag varint deltas;
//! - booleans: one bit each; strings: length-prefixed.
//!
//! Layout: `type u8 | n varint | t0 zigzag | n dod varints | values`.
//! Decoding is bounds-checked: corrupt input yields an error, never a panic.

use crate::agg::Slice;
use crate::error::{Error, Result};
use crate::lineproto::{FieldType, FieldValue};
use flashkv::codec::Decoder;
use flashkv::varint::{put_len_prefixed, put_uvarint64};

#[derive(Clone, Debug, PartialEq)]
pub enum Column {
    Float(Vec<f64>),
    Int(Vec<i64>),
    UInt(Vec<u64>),
    Bool(Vec<bool>),
    Str(Vec<String>),
}

impl Column {
    pub fn new(ty: FieldType) -> Column {
        match ty {
            FieldType::Float => Column::Float(Vec::new()),
            FieldType::Int => Column::Int(Vec::new()),
            FieldType::UInt => Column::UInt(Vec::new()),
            FieldType::Bool => Column::Bool(Vec::new()),
            FieldType::Str => Column::Str(Vec::new()),
        }
    }

    pub fn field_type(&self) -> FieldType {
        match self {
            Column::Float(_) => FieldType::Float,
            Column::Int(_) => FieldType::Int,
            Column::UInt(_) => FieldType::UInt,
            Column::Bool(_) => FieldType::Bool,
            Column::Str(_) => FieldType::Str,
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Column::Float(v) => v.len(),
            Column::Int(v) => v.len(),
            Column::UInt(v) => v.len(),
            Column::Bool(v) => v.len(),
            Column::Str(v) => v.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Appends `v`, which must have the column's type.
    pub fn push(&mut self, v: FieldValue) -> Result<()> {
        match (self, v) {
            (Column::Float(c), FieldValue::Float(x)) => c.push(x),
            (Column::Int(c), FieldValue::Int(x)) => c.push(x),
            (Column::UInt(c), FieldValue::UInt(x)) => c.push(x),
            (Column::Bool(c), FieldValue::Bool(x)) => c.push(x),
            (Column::Str(c), FieldValue::Str(x)) => c.push(x),
            (c, v) => {
                return Err(Error::Schema(format!(
                    "{:?} value in a {:?} column",
                    v.field_type(),
                    c.field_type()
                )))
            }
        }
        Ok(())
    }

    /// Value at `i` (panics if out of bounds, like slice indexing).
    pub fn get(&self, i: usize) -> FieldValue {
        match self {
            Column::Float(v) => FieldValue::Float(v[i]),
            Column::Int(v) => FieldValue::Int(v[i]),
            Column::UInt(v) => FieldValue::UInt(v[i]),
            Column::Bool(v) => FieldValue::Bool(v[i]),
            Column::Str(v) => FieldValue::Str(v[i].clone()),
        }
    }
}

/// Sorts by timestamp (stable) and keeps the *last* value written for each
/// timestamp, which is InfluxDB's overwrite semantics.
pub fn normalize(mut points: Vec<(i64, FieldValue)>) -> Vec<(i64, FieldValue)> {
    points.sort_by_key(|p| p.0);
    let mut out: Vec<(i64, FieldValue)> = Vec::with_capacity(points.len());
    for p in points {
        match out.last_mut() {
            Some(last) if last.0 == p.0 => *last = p,
            _ => out.push(p),
        }
    }
    out
}

/// A number of one of the three numeric types, as a column of it holds them.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Num {
    Float(f64),
    Int(i64),
    UInt(u64),
}

impl Num {
    pub fn value(self) -> FieldValue {
        match self {
            Num::Float(x) => FieldValue::Float(x),
            Num::Int(x) => FieldValue::Int(x),
            Num::UInt(x) => FieldValue::UInt(x),
        }
    }

    /// The type (1, 2 or 3, as stored) and the bits.
    fn parts(self) -> (u8, u64) {
        match self {
            Num::Float(x) => (1, x.to_bits()),
            Num::Int(x) => (2, x as u64),
            Num::UInt(x) => (3, x),
        }
    }

    fn from_parts(tag: u8, bits: u64) -> Option<Num> {
        match tag {
            1 => Some(Num::Float(f64::from_bits(bits))),
            2 => Some(Num::Int(bits as i64)),
            3 => Some(Num::UInt(bits)),
            _ => None,
        }
    }
}

/// What a column of numbers says about a chunk of it.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Numbers {
    /// The sum of the values as floats (compensated, see [`crate::agg::add`]).
    pub sum: f64,
    pub min: f64,
    pub max: f64,
    /// The values of the earliest and of the latest point.
    pub first: Num,
    pub last: Num,
}

/// What is known of a chunk without decoding it. It is stored under a key of
/// its own, next to the chunk's, so that a query can find out from a few
/// small entries which chunks it has to read, and answer from these alone
/// for a chunk that lies inside one window of its aggregate.
#[derive(Clone, Debug, PartialEq)]
pub struct ChunkStats {
    pub count: u64,
    /// The earliest and the latest timestamp.
    pub min_ts: i64,
    pub max_ts: i64,
    /// For a column of numbers.
    pub numbers: Option<Numbers>,
}

impl ChunkStats {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_uvarint64(&mut out, self.count);
        put_uvarint64(&mut out, zigzag(self.min_ts));
        put_uvarint64(&mut out, zigzag(self.max_ts));
        match self.numbers {
            None => out.push(0),
            Some(n) => {
                let (tag, first) = n.first.parts();
                out.push(tag);
                for bits in [
                    n.sum.to_bits(),
                    n.min.to_bits(),
                    n.max.to_bits(),
                    first,
                    n.last.parts().1,
                ] {
                    out.extend_from_slice(&bits.to_le_bytes());
                }
            }
        }
        out
    }

    pub fn decode(buf: &[u8]) -> Result<ChunkStats> {
        let mut d = Decoder::new(buf);
        let count = d.varint();
        let (min_ts, max_ts) = (unzigzag(d.varint()), unzigzag(d.varint()));
        let tag = d.u8();
        let numbers = (tag != 0).then(|| {
            let mut next = || d.u64();
            let (sum, min, max) = (next(), next(), next());
            let (first, last) = (Num::from_parts(tag, next()), Num::from_parts(tag, next()));
            first.zip(last).map(|(first, last)| Numbers {
                sum: f64::from_bits(sum),
                min: f64::from_bits(min),
                max: f64::from_bits(max),
                first,
                last,
            })
        });
        d.finish("chunk statistics")?;
        if !d.is_done() | (count == 0) {
            return Err(Error::Corrupt("chunk statistics".into()));
        }
        match numbers {
            None => Ok(ChunkStats {
                count,
                min_ts,
                max_ts,
                numbers: None,
            }),
            Some(None) => Err(Error::Corrupt("chunk statistics: number type".into())),
            Some(n) => Ok(ChunkStats {
                count,
                min_ts,
                max_ts,
                numbers: n,
            }),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Chunk {
    ts: Vec<i64>,
    col: Column,
}

fn zigzag(v: i64) -> u64 {
    ((v << 1) ^ (v >> 63)) as u64
}

fn unzigzag(v: u64) -> i64 {
    ((v >> 1) as i64) ^ -((v & 1) as i64)
}

/// Writes bits, most significant first, through a 64-bit accumulator.
#[derive(Default)]
struct BitWriter {
    buf: Vec<u8>,
    /// The bits not yet in `buf`, in the low `filled` bits.
    acc: u64,
    filled: u32,
}

impl BitWriter {
    /// Appends the low `n` bits of `v` (`n` is at most 64).
    fn put(&mut self, v: u64, n: u32) {
        let v = v & u64::MAX.checked_shr(64 - n).unwrap_or(0);
        // The accumulator is never full: `filled` is below 64.
        let room = 64 - self.filled;
        if n < room {
            self.acc = self.acc.checked_shl(n).unwrap_or(0) | v;
            self.filled += n;
        } else {
            // `v` fills the accumulator, which goes to the buffer, and what
            // is left of `v` starts the next one.
            let rest = n - room;
            let word = self.acc.checked_shl(room).unwrap_or(0) | (v >> rest);
            self.buf.extend_from_slice(&word.to_be_bytes());
            self.acc = v & (1u64 << rest).wrapping_sub(1);
            self.filled = rest;
        }
    }

    /// The bytes, the last one padded with zero bits.
    fn finish(mut self) -> Vec<u8> {
        let bytes = self.filled.div_ceil(8) as usize;
        let last = self.acc.checked_shl(64 - self.filled).unwrap_or(0);
        self.buf.extend_from_slice(&last.to_be_bytes()[..bytes]);
        self.buf
    }
}

struct BitReader<'a> {
    buf: &'a [u8],
    pos: usize,
    bad: bool,
}

impl<'a> BitReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        BitReader {
            buf,
            pos: 0,
            bad: false,
        }
    }

    /// The 8 bytes from byte `i` on (zeros past the end), as a number.
    fn word(&self, i: usize) -> u64 {
        match self.buf.get(i..i + 8) {
            Some(w) => u64::from_be_bytes(w.try_into().expect("8 bytes")),
            None => {
                let mut w = [0u8; 8];
                let rest = self.buf.get(i..).unwrap_or_default();
                w[..rest.len()].copy_from_slice(rest);
                u64::from_be_bytes(w)
            }
        }
    }

    /// Next `n` bits (sticky failure: 0 once the input is exhausted).
    fn get(&mut self, n: u32) -> u64 {
        if self.bad | (self.pos + n as usize > self.buf.len() * 8) {
            self.bad = true;
            return 0;
        }
        if n > 56 {
            // A word holds at most 57 bits from any bit position.
            let high = self.get(n - 32);
            return (high << 32) | self.get(32);
        }
        let v = (self.word(self.pos / 8) << (self.pos % 8))
            .checked_shr(64 - n)
            .unwrap_or(0);
        self.pos += n as usize;
        v
    }
}

fn encode_floats(vals: &[f64]) -> Vec<u8> {
    let mut w = BitWriter::default();
    let (mut prev, mut lead, mut trail) = (0u64, u32::MAX, 0u32);
    for v in vals {
        let bits = v.to_bits();
        let x = bits ^ prev;
        prev = bits;
        if x == 0 {
            w.put(0, 1);
            continue;
        }
        w.put(1, 1);
        let (l, t) = (x.leading_zeros().min(31), x.trailing_zeros());
        if (l >= lead) & (t >= trail) {
            w.put(0, 1);
            w.put(x >> trail, 64 - lead - trail);
        } else {
            let len = 64 - l - t;
            w.put(1, 1);
            w.put(u64::from(l), 5);
            w.put(u64::from(len - 1), 6);
            w.put(x >> t, len);
            (lead, trail) = (l, t);
        }
    }
    w.finish()
}

fn decode_floats(buf: &[u8], n: usize) -> (Vec<f64>, bool) {
    let mut r = BitReader::new(buf);
    let (mut prev, mut lead, mut trail) = (0u64, 0u32, 0u32);
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        if r.get(1) == 1 {
            if r.get(1) == 1 {
                lead = r.get(5) as u32;
                let len = r.get(6) as u32 + 1;
                trail = 64u32.saturating_sub(lead + len);
            }
            prev ^= r.get(64 - lead - trail) << trail;
        }
        out.push(f64::from_bits(prev));
    }
    (out, !r.bad)
}

fn put_deltas(out: &mut Vec<u8>, vals: impl Iterator<Item = i64>) {
    let mut prev = 0i64;
    for v in vals {
        put_uvarint64(out, zigzag(v.wrapping_sub(prev)));
        prev = v;
    }
}

fn get_deltas(d: &mut Decoder, n: usize) -> Vec<i64> {
    let mut prev = 0i64;
    (0..n)
        .map(|_| {
            prev = prev.wrapping_add(unzigzag(d.varint()));
            prev
        })
        .collect()
}

impl Chunk {
    /// Builds a chunk of type `ty` from points in any order (see [`normalize`]).
    pub fn from_points(ty: FieldType, points: Vec<(i64, FieldValue)>) -> Result<Chunk> {
        let points = normalize(points);
        let mut col = Column::new(ty);
        let mut ts = Vec::with_capacity(points.len());
        for (t, v) in points {
            col.push(v)?;
            ts.push(t);
        }
        Ok(Chunk { ts, col })
    }

    pub fn len(&self) -> usize {
        self.ts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ts.is_empty()
    }

    pub fn field_type(&self) -> FieldType {
        self.col.field_type()
    }

    /// Sorted, unique timestamps.
    pub fn timestamps(&self) -> &[i64] {
        &self.ts
    }

    pub fn column(&self) -> &Column {
        &self.col
    }

    /// What a query can know of the chunk without decoding it; `None` for
    /// an empty chunk.
    pub fn stats(&self) -> Option<ChunkStats> {
        let (&min_ts, &max_ts) = self.ts.first().zip(self.ts.last())?;
        Some(ChunkStats {
            count: self.ts.len() as u64,
            min_ts,
            max_ts,
            numbers: Slice::of(&self.col).map(|s| s.numbers()),
        })
    }

    pub fn points(&self) -> Vec<(i64, FieldValue)> {
        self.ts.iter().enumerate().map(|(i, &t)| (t, self.col.get(i))).collect()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![self.field_type() as u8];
        put_uvarint64(&mut out, self.ts.len() as u64);
        let t0 = self.ts.first().copied().unwrap_or(0);
        put_uvarint64(&mut out, zigzag(t0));
        let (mut prev, mut prev_delta) = (t0, 0i64);
        for &t in &self.ts {
            let delta = t.wrapping_sub(prev);
            put_uvarint64(&mut out, zigzag(delta.wrapping_sub(prev_delta)));
            (prev, prev_delta) = (t, delta);
        }
        match &self.col {
            Column::Float(v) => put_len_prefixed(&mut out, &encode_floats(v)),
            Column::Int(v) => put_deltas(&mut out, v.iter().copied()),
            Column::UInt(v) => put_deltas(&mut out, v.iter().map(|&x| x as i64)),
            Column::Bool(v) => {
                let mut w = BitWriter::default();
                v.iter().for_each(|&b| w.put(u64::from(b), 1));
                put_len_prefixed(&mut out, &w.finish());
            }
            Column::Str(v) => v.iter().for_each(|s| put_len_prefixed(&mut out, s.as_bytes())),
        }
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Chunk> {
        let mut d = Decoder::new(buf);
        let ty = FieldType::from_u8(d.u8()).ok_or_else(|| Error::Corrupt("chunk type".into()))?;
        // Every timestamp takes at least one byte: a corrupt count cannot
        // make us allocate or loop beyond the input size.
        let n = d.varint().min(d.remaining() as u64) as usize;
        let t0 = unzigzag(d.varint());
        let (mut prev, mut prev_delta) = (t0, 0i64);
        let ts: Vec<i64> = (0..n)
            .map(|_| {
                prev_delta = prev_delta.wrapping_add(unzigzag(d.varint()));
                prev = prev.wrapping_add(prev_delta);
                prev
            })
            .collect();
        let (col, bits_ok) = match ty {
            FieldType::Float => {
                let (v, ok) = decode_floats(d.lp(), n);
                (Column::Float(v), ok)
            }
            FieldType::Int => (Column::Int(get_deltas(&mut d, n)), true),
            FieldType::UInt => (
                Column::UInt(get_deltas(&mut d, n).into_iter().map(|x| x as u64).collect()),
                true,
            ),
            FieldType::Bool => {
                let mut r = BitReader::new(d.lp());
                let v = (0..n).map(|_| r.get(1) == 1).collect();
                (Column::Bool(v), !r.bad)
            }
            FieldType::Str => (
                Column::Str((0..n).map(|_| String::from_utf8_lossy(d.lp()).into_owned()).collect()),
                true,
            ),
        };
        d.finish("chunk")?;
        if !bits_ok | !d.is_done() {
            return Err(Error::Corrupt("chunk bit stream or trailing bytes".into()));
        }
        Ok(Chunk { ts, col })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn samples() -> Vec<Vec<FieldValue>> {
        let floats = [
            0.0,
            0.0,
            1.5,
            1.5,
            1.25,
            -3.0e10,
            f64::MIN_POSITIVE,
            1.0,
            1.0000001,
            42.0,
        ];
        vec![
            floats.iter().map(|&f| FieldValue::Float(f)).collect(),
            [0, -1, i64::MAX, i64::MIN, 5, 5].map(FieldValue::Int).to_vec(),
            [0, u64::MAX, 3, 3].map(FieldValue::UInt).to_vec(),
            [true, false, false, true, true, true, false, true, true]
                .map(FieldValue::Bool)
                .to_vec(),
            ["", "a", "héllo", "a"].map(|s| FieldValue::Str(s.into())).to_vec(),
        ]
    }

    #[test]
    fn roundtrip_every_type() {
        for values in samples() {
            let ty = values[0].field_type();
            // Irregular timestamps, including negative and huge jumps.
            let ts = [-7, 0, 10, 20, 30, 1_000_000_007, i64::MAX - 1, i64::MAX, 40, 50];
            let pts: Vec<(i64, FieldValue)> = ts.iter().copied().zip(values).collect();
            let chunk = Chunk::from_points(ty, pts.clone()).unwrap();
            assert_eq!(chunk.field_type(), ty);
            assert_eq!(chunk.column().field_type(), ty);
            assert_eq!(chunk.points(), normalize(pts));
            let bytes = chunk.encode();
            assert_eq!(Chunk::decode(&bytes).unwrap(), chunk);
            assert!(!chunk.is_empty() && !chunk.column().is_empty());
            assert!(chunk.timestamps().windows(2).all(|w| w[0] < w[1]));
        }
    }

    #[test]
    fn regular_series_compress_well() {
        let pts: Vec<(i64, FieldValue)> = (0..1000)
            .map(|i| {
                (
                    1_700_000_000_000_000_000 + i * 10_000_000_000,
                    FieldValue::Float(20.0 + (i % 4) as f64 * 0.5),
                )
            })
            .collect();
        let bytes = Chunk::from_points(FieldType::Float, pts).unwrap().encode();
        assert!(bytes.len() < 1000 * 3);
    }

    #[test]
    fn empty_chunk_and_normalize() {
        for ty in [
            FieldType::Float,
            FieldType::Int,
            FieldType::UInt,
            FieldType::Bool,
            FieldType::Str,
        ] {
            let c = Chunk::from_points(ty, Vec::new()).unwrap();
            assert!(c.is_empty() && c.column().is_empty());
            assert_eq!((c.len(), c.column().len()), (0, 0));
            assert_eq!(Chunk::decode(&c.encode()).unwrap(), c);
        }
        let n = normalize(vec![
            (2, FieldValue::Int(1)),
            (1, FieldValue::Int(2)),
            (2, FieldValue::Int(3)),
        ]);
        assert_eq!(n, vec![(1, FieldValue::Int(2)), (2, FieldValue::Int(3))]);
    }

    #[test]
    fn type_mismatch_is_rejected() {
        let mut c = Column::new(FieldType::Int);
        assert!(c.push(FieldValue::Float(1.0)).is_err());
        assert!(Chunk::from_points(FieldType::Str, vec![(1, FieldValue::Bool(true))]).is_err());
    }

    #[test]
    fn corrupt_input_is_an_error() {
        assert!(Chunk::decode(&[]).is_err());
        assert!(Chunk::decode(&[9, 0, 0]).is_err());
        for values in samples() {
            let ty = values[0].field_type();
            let pts: Vec<(i64, FieldValue)> = (0..).zip(values).collect();
            let bytes = Chunk::from_points(ty, pts).unwrap().encode();
            for cut in 0..bytes.len() {
                assert!(Chunk::decode(&bytes[..cut]).is_err(), "{ty:?} cut at {cut}");
            }
            let mut extra = bytes.clone();
            extra.push(0);
            assert!(Chunk::decode(&extra).is_err());
        }
        // Valid framing, truncated bit streams.
        let mut floats = vec![FieldType::Float as u8, 2, 0, 0, 2];
        put_len_prefixed(&mut floats, &[0xff]);
        assert!(Chunk::decode(&floats).is_err());
        let mut bools = vec![FieldType::Bool as u8, 9, 0, 0, 2, 2, 2, 2, 2, 2, 2, 2];
        put_len_prefixed(&mut bools, &[0xff]);
        assert!(Chunk::decode(&bools).is_err());
    }

    #[test]
    fn statistics_say_what_the_chunk_holds() {
        let floats = [
            (5, FieldValue::Float(2.0)),
            (1, FieldValue::Float(-1.0)),
            (9, FieldValue::Float(4.5)),
        ];
        let stats = Chunk::from_points(FieldType::Float, floats.to_vec())
            .unwrap()
            .stats()
            .unwrap();
        let numbers = stats.numbers.unwrap();
        assert_eq!((stats.count, stats.min_ts, stats.max_ts), (3, 1, 9));
        assert_eq!((numbers.sum, numbers.min, numbers.max), (5.5, -1.0, 4.5));
        // The values of the earliest and of the latest point, which is not the order of writing.
        assert_eq!((numbers.first, numbers.last), (Num::Float(-1.0), Num::Float(4.5)));
        assert_eq!(numbers.first.value(), FieldValue::Float(-1.0));
        let ints = [(1, FieldValue::Int(i64::MIN)), (2, FieldValue::Int(i64::MAX))];
        let n = Chunk::from_points(FieldType::Int, ints.to_vec())
            .unwrap()
            .stats()
            .unwrap()
            .numbers
            .unwrap();
        assert_eq!((n.first, n.last), (Num::Int(i64::MIN), Num::Int(i64::MAX)));
        assert_eq!((n.min, n.max), (i64::MIN as f64, i64::MAX as f64));
        let uints = [(1, FieldValue::UInt(u64::MAX))];
        let n = Chunk::from_points(FieldType::UInt, uints.to_vec())
            .unwrap()
            .stats()
            .unwrap()
            .numbers
            .unwrap();
        assert_eq!((n.first.value(), n.sum), (FieldValue::UInt(u64::MAX), u64::MAX as f64));
        // Every type, as it is stored, and back; text and booleans have no numbers.
        for values in samples() {
            let ty = values[0].field_type();
            let pts: Vec<(i64, FieldValue)> = (-3..).zip(values).collect();
            let stats = Chunk::from_points(ty, pts).unwrap().stats().unwrap();
            assert_eq!(stats.numbers.is_some(), !matches!(ty, FieldType::Bool | FieldType::Str));
            assert_eq!(ChunkStats::decode(&stats.encode()).unwrap(), stats, "{ty:?}");
        }
        // A chunk with nothing in it has nothing to say.
        assert_eq!(Chunk::from_points(FieldType::Float, Vec::new()).unwrap().stats(), None);
    }

    #[test]
    fn corrupt_statistics_are_an_error() {
        let stats = Chunk::from_points(FieldType::Float, vec![(1, FieldValue::Float(1.0))])
            .unwrap()
            .stats()
            .unwrap();
        let bytes = stats.encode();
        for cut in 0..bytes.len() {
            assert!(ChunkStats::decode(&bytes[..cut]).is_err(), "cut at {cut}");
        }
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(ChunkStats::decode(&extra).is_err());
        // No point; a number type that does not exist.
        assert!(ChunkStats::decode(&[0, 0, 0, 0]).is_err());
        let mut odd = bytes.clone();
        odd[3] = 9;
        assert!(ChunkStats::decode(&odd).is_err());
        assert_eq!(ChunkStats::decode(&bytes).unwrap(), stats);
    }

    #[test]
    fn bit_io() {
        let mut w = BitWriter::default();
        w.put(0b101, 3);
        w.put(u64::MAX, 64);
        let bytes = w.finish();
        let mut r = BitReader::new(&bytes);
        assert_eq!(r.get(3), 0b101);
        assert_eq!(r.get(64), u64::MAX);
        assert_eq!(r.get(8), 0);
        assert!(r.bad);
        assert_eq!(r.get(0), 0, "sticky");
        assert_eq!(unzigzag(zigzag(i64::MIN)), i64::MIN);
        // A corrupt window (lead + len > 64) must not panic.
        let mut w = BitWriter::default();
        w.put(0b11, 2);
        w.put(31, 5);
        w.put(63, 6);
        w.put(0, 33);
        assert!(decode_floats(&w.finish(), 1).1);
    }

    /// The bit I/O against the obvious bit-by-bit version, for every width
    /// and a spread of alignments.
    #[test]
    fn bit_io_matches_the_obvious_version() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for round in 0..200 {
            let fields: Vec<(u64, u32)> = (0..round % 40 + 1).map(|_| (next(), (next() % 65) as u32)).collect();
            let mut w = BitWriter::default();
            let mut bits = Vec::new();
            for &(v, n) in &fields {
                w.put(v, n);
                bits.extend((0..n).rev().map(|i| (v >> i) & 1 == 1));
            }
            let bytes = w.finish();
            let want: Vec<u8> = bits
                .chunks(8)
                .map(|c| c.iter().enumerate().fold(0, |b, (i, &x)| b | (u8::from(x) << (7 - i))))
                .collect();
            assert_eq!(bytes, want, "round {round}");
            let mut r = BitReader::new(&bytes);
            for &(v, n) in &fields {
                let mask = if n == 64 { u64::MAX } else { (1 << n) - 1 };
                assert_eq!(r.get(n), v & mask, "round {round} width {n}");
            }
            assert!(!r.bad);
        }
    }
}
