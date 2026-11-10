//! Points as the columns they go to: the timestamps and the values of a
//! column, as typed vectors, in the order they were written. That is what a
//! write is turned into, what the write buffer holds, and what a record of
//! the write-ahead log is made of; no point has a value of its own that is
//! boxed or tagged.
//!
//! The record of the log: `version u8 | body...`, a body being `columns
//! uvarint | column...` and a column `id uvarint | type u8 | n uvarint | n
//! timestamps (zigzag varints of the differences of the differences) | n
//! values`, a float as its 8 bytes, a signed integer zigzag and an unsigned
//! one as a varint, a boolean as a byte and a string with its length. A
//! write that is parsed in pieces on several threads has a body for each
//! piece, which are put one after the other without being merged.

use crate::chunk::{unzigzag, zigzag, Column};
use crate::error::{Error, Result};
use crate::hash::FastMap;
use crate::lineproto::{FieldType, FieldValue};
use flashkv::codec::Decoder;
use flashkv::varint::{put_len_prefixed, put_uvarint64};
use std::collections::hash_map::Entry;

const VERSION: u8 = 1;

/// The points of one column, in the order they were written (not sorted,
/// and a timestamp can be there more than once: the last one wins).
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ColumnPoints {
    pub ts: Vec<i64>,
    pub values: Column,
}

impl ColumnPoints {
    pub fn new(ty: FieldType) -> ColumnPoints {
        ColumnPoints {
            ts: Vec::new(),
            values: Column::new(ty),
        }
    }

    /// An empty column with room for `n` points.
    pub fn with_capacity(ty: FieldType, n: usize) -> ColumnPoints {
        let mut points = ColumnPoints::new(ty);
        points.reserve(n);
        points
    }

    /// Makes room for `n` more points.
    pub fn reserve(&mut self, n: usize) {
        self.ts.reserve(n);
        self.values.reserve(n);
    }

    pub fn len(&self) -> usize {
        self.ts.len()
    }

    /// Adds a point; the value must have the type of the column.
    pub fn push(&mut self, ts: i64, value: FieldValue) -> Result<()> {
        self.values.push(value)?;
        self.ts.push(ts);
        Ok(())
    }

    /// Adds the points of `later`, which are newer, of the same type.
    pub fn append(&mut self, later: ColumnPoints) -> Result<()> {
        self.values.append(later.values)?;
        self.ts.extend(later.ts);
        Ok(())
    }
}

/// The points of a write, by column.
pub(crate) type Batch = FastMap<u64, ColumnPoints>;

/// The number of points in `batch`.
pub(crate) fn points_in(batch: &Batch) -> usize {
    batch.values().map(ColumnPoints::len).sum()
}

/// The part of a record that is the columns of `batch`.
pub(crate) fn encode_body(batch: &Batch) -> Vec<u8> {
    let mut out = Vec::new();
    let mut columns: Vec<_> = batch.iter().collect();
    columns.sort_unstable_by_key(|c| c.0);
    put_uvarint64(&mut out, columns.len() as u64);
    for (&id, points) in columns {
        put_uvarint64(&mut out, id);
        out.push(points.values.field_type() as u8);
        put_uvarint64(&mut out, points.len() as u64);
        // The timestamps as the differences of the differences, which are
        // zero for a column that is written at a regular pace.
        let (mut previous, mut step) = (0i64, 0i64);
        for &t in &points.ts {
            let delta = t.wrapping_sub(previous);
            put_uvarint64(&mut out, zigzag(delta.wrapping_sub(step)));
            (previous, step) = (t, delta);
        }
        match &points.values {
            Column::Float(v) => v.iter().for_each(|x| out.extend_from_slice(&x.to_le_bytes())),
            Column::Int(v) => v.iter().for_each(|&x| put_uvarint64(&mut out, zigzag(x))),
            Column::UInt(v) => v.iter().for_each(|&x| put_uvarint64(&mut out, x)),
            Column::Bool(v) => out.extend(v.iter().map(|&b| u8::from(b))),
            Column::Str(v) => v.iter().for_each(|s| put_len_prefixed(&mut out, s.as_bytes())),
        }
    }
    out
}

/// The record of the log made of the bodies of the batches of a write, in the
/// order they are to be applied.
pub(crate) fn record(bodies: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + bodies.iter().map(Vec::len).sum::<usize>());
    out.push(VERSION);
    bodies.iter().for_each(|b| out.extend_from_slice(b));
    out
}

/// The record of the log for `batch`.
pub(crate) fn encode(batch: &Batch) -> Vec<u8> {
    record(&[encode_body(batch)])
}

/// The batch that a record of the log holds (all its bodies, one after the
/// other). Bytes that are not a record are an error, never a panic, however
/// they came to be.
pub(crate) fn decode(record: &[u8]) -> Result<Batch> {
    let bad = || Error::Corrupt("record of the log".into());
    let mut d = Decoder::new(record);
    if d.u8() != VERSION {
        return Err(bad());
    }
    let mut batch = Batch::default();
    while !d.is_done() {
        let mut body = Batch::default();
        // Every column takes at least 3 bytes, and every point 2: a count that
        // is more than that is not one.
        let declared = d.varint();
        let columns = declared.min(d.remaining() as u64 / 3);
        if columns != declared {
            return Err(bad());
        }
        for _ in 0..columns {
            let id = d.varint();
            let ty = FieldType::from_u8(d.u8()).ok_or_else(bad)?;
            let declared = d.varint();
            let n = declared.min(d.remaining() as u64 / 2);
            if n != declared {
                return Err(bad());
            }
            let n = n as usize;
            let mut ts = Vec::with_capacity(n);
            let (mut previous, mut step) = (0i64, 0i64);
            for _ in 0..n {
                step = step.wrapping_add(unzigzag(d.varint()));
                previous = previous.wrapping_add(step);
                ts.push(previous);
            }
            let values = match ty {
                FieldType::Float => Column::Float((0..n).map(|_| f64::from_bits(d.u64())).collect()),
                FieldType::Int => Column::Int((0..n).map(|_| unzigzag(d.varint())).collect()),
                FieldType::UInt => Column::UInt((0..n).map(|_| d.varint()).collect()),
                FieldType::Bool => Column::Bool((0..n).map(|_| d.u8() == 1).collect()),
                FieldType::Str => Column::Str((0..n).map(|_| String::from_utf8_lossy(d.lp()).into_owned()).collect()),
            };
            if body.insert(id, ColumnPoints { ts, values }).is_some() {
                return Err(bad());
            }
        }
        for (id, points) in body {
            match batch.entry(id) {
                Entry::Vacant(free) => {
                    free.insert(points);
                }
                Entry::Occupied(mut held) => held.get_mut().append(points).map_err(|_| bad())?,
            }
        }
    }
    d.finish("record of the log")?;
    Ok(batch)
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn sample() -> Batch {
        let mut b = Batch::default();
        let mut add = |id: u64, ty: FieldType, points: Vec<(i64, FieldValue)>| {
            let c = b.entry(id).or_insert_with(|| ColumnPoints::new(ty));
            points.into_iter().for_each(|(t, v)| c.push(t, v).unwrap());
        };
        let f = FieldValue::Float;
        add(
            7,
            FieldType::Float,
            vec![(10, f(1.5)), (5, f(-0.0)), (i64::MIN, f(f64::MAX)), (5, f(2.0))],
        );
        add(
            1,
            FieldType::Int,
            vec![(1, FieldValue::Int(i64::MIN)), (2, FieldValue::Int(i64::MAX))],
        );
        add(
            3,
            FieldType::UInt,
            vec![(0, FieldValue::UInt(u64::MAX)), (9, FieldValue::UInt(0))],
        );
        add(
            4,
            FieldType::Bool,
            vec![(1, FieldValue::Bool(true)), (2, FieldValue::Bool(false))],
        );
        add(
            1000,
            FieldType::Str,
            vec![
                (1, FieldValue::Str("héllo".into())),
                (1, FieldValue::Str(String::new())),
            ],
        );
        b
    }

    #[test]
    fn a_record_holds_what_the_batch_holds() {
        let batch = sample();
        assert_eq!(points_in(&batch), 12);
        let record = encode(&batch);
        assert_eq!(decode(&record).unwrap(), batch);
        // The same batch is always the same bytes, whatever the order in the map.
        assert_eq!(encode(&decode(&record).unwrap()), record);
        let empty = encode(&Batch::default());
        assert_eq!(decode(&empty).unwrap(), Batch::default());
        assert_eq!(points_in(&Batch::default()), 0);
    }

    #[test]
    fn a_record_that_is_not_one_is_an_error() {
        let record = encode(&sample());
        assert!(decode(&[]).is_err());
        assert!(decode(&[VERSION + 1, 0]).is_err());
        // (A record cut after its first byte has no body: a record with nothing in it.)
        for cut in (0..record.len()).filter(|&cut| cut != 1) {
            assert!(decode(&record[..cut]).is_err(), "cut at {cut}");
        }
        assert_eq!(decode(&record[..1]).unwrap(), Batch::default());
        let mut extra = record.clone();
        extra.push(1);
        assert!(decode(&extra).is_err());
        // A type that does not exist; a column twice.
        assert!(decode(&[VERSION, 1, 0, 9, 0]).is_err());
        let twice = [VERSION, 2, 0, FieldType::Bool as u8, 0, 0, FieldType::Bool as u8, 0];
        assert!(decode(&twice).is_err());
        // Counts that are far more than the bytes can hold do not allocate.
        assert!(decode(&[VERSION, 0xff, 0xff, 0xff, 0xff, 0x0f]).is_err());
        let huge = [VERSION, 1, 0, FieldType::Float as u8, 0xff, 0xff, 0xff, 0xff, 0x0f];
        assert!(decode(&huge).is_err());
    }

    #[test]
    fn a_record_of_several_bodies_is_all_of_them_in_order() {
        let (a, b) = (sample(), sample());
        let one = decode(&record(&[encode_body(&a), encode_body(&b)])).unwrap();
        for (id, points) in &a {
            let both = &one[id];
            assert_eq!(both.len(), 2 * points.len());
            let mut want = points.clone();
            want.append(b[id].clone()).unwrap();
            assert_eq!(both, &want);
        }
        // Bodies that do not agree on the type of a column: not a record.
        let mut other = Batch::default();
        other.insert(7, ColumnPoints::new(FieldType::Bool));
        assert!(decode(&record(&[encode_body(&a), encode_body(&other)])).is_err());
    }

    #[test]
    fn points_are_added_and_appended_by_type() {
        let mut a = ColumnPoints::new(FieldType::Int);
        a.push(1, FieldValue::Int(1)).unwrap();
        assert!(a.push(2, FieldValue::Float(1.0)).is_err());
        assert_eq!(a.len(), 1, "a point of the wrong type is not added");
        let mut b = ColumnPoints::new(FieldType::Int);
        b.push(0, FieldValue::Int(0)).unwrap();
        a.append(b).unwrap();
        assert_eq!((a.ts.as_slice(), a.values), (&[1, 0][..], Column::Int(vec![1, 0])));
        let mut a = ColumnPoints::new(FieldType::Int);
        assert!(a.append(ColumnPoints::new(FieldType::Bool)).is_err());
    }
}
