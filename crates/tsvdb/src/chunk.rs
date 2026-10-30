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

#[derive(Default)]
struct BitWriter {
    buf: Vec<u8>,
    bits: usize,
}

impl BitWriter {
    /// Appends the low `n` bits of `v`, most significant first.
    fn put(&mut self, v: u64, n: u32) {
        for i in (0..n).rev() {
            if self.bits.is_multiple_of(8) {
                self.buf.push(0);
            }
            let bit = ((v >> i) & 1) as u8;
            *self.buf.last_mut().expect("pushed above") |= bit << (7 - self.bits % 8);
            self.bits += 1;
        }
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

    /// Next `n` bits (sticky failure: 0 once the input is exhausted).
    fn get(&mut self, n: u32) -> u64 {
        if self.bad | (self.pos + n as usize > self.buf.len() * 8) {
            self.bad = true;
            return 0;
        }
        let mut v = 0u64;
        for _ in 0..n {
            let byte = self.buf[self.pos / 8];
            v = (v << 1) | u64::from((byte >> (7 - self.pos % 8)) & 1);
            self.pos += 1;
        }
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
    w.buf
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
                put_len_prefixed(&mut out, &w.buf);
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
    fn bit_io() {
        let mut w = BitWriter::default();
        w.put(0b101, 3);
        w.put(u64::MAX, 64);
        let mut r = BitReader::new(&w.buf);
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
        assert!(decode_floats(&w.buf, 1).1);
    }
}
