//! Atomic write batches (LevelDB `WriteBatch`).
//!
//! The in-memory representation *is* the WAL encoding, so committing a batch
//! is a single append: `seq: u64le | count: varint | ops...` where each op is
//! `0 | lp(key)` (delete) or `1 | lp(key) | lp(value)` (put).

use crate::codec::Decoder;
use crate::error::{Error, Result};
use crate::varint::{put_len_prefixed, put_uvarint64};

const DEL: u8 = 0;
const PUT: u8 = 1;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WriteBatch {
    rep: Vec<u8>,
    count: u64,
}

/// One decoded operation: `value == None` is a deletion.
pub type Op<'a> = (&'a [u8], Option<&'a [u8]>);

impl WriteBatch {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn put(&mut self, key: &[u8], value: &[u8]) -> &mut Self {
        self.rep.push(PUT);
        put_len_prefixed(&mut self.rep, key);
        put_len_prefixed(&mut self.rep, value);
        self.count += 1;
        self
    }

    pub fn delete(&mut self, key: &[u8]) -> &mut Self {
        self.rep.push(DEL);
        put_len_prefixed(&mut self.rep, key);
        self.count += 1;
        self
    }

    /// Number of operations.
    pub fn len(&self) -> usize {
        self.count as usize
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn clear(&mut self) {
        self.rep.clear();
        self.count = 0;
    }

    /// Encoded size in bytes (what the WAL will store).
    pub fn approximate_size(&self) -> usize {
        self.rep.len() + 18
    }

    /// Operations in insertion order.
    pub fn ops(&self) -> Vec<Op<'_>> {
        decode_ops(&self.rep, self.count).unwrap_or_default()
    }

    pub(crate) fn encode(&self, seq: u64) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.approximate_size());
        out.extend_from_slice(&seq.to_le_bytes());
        put_uvarint64(&mut out, self.count);
        out.extend_from_slice(&self.rep);
        out
    }

    /// Decode a WAL payload into `(first_seq, batch)`, validating every op.
    pub(crate) fn decode(payload: &[u8]) -> Result<(u64, WriteBatch)> {
        let mut d = Decoder::new(payload);
        let seq = d.u64();
        let count = d.varint();
        d.finish("write batch header")?;
        let rep = &payload[payload.len() - d.remaining()..];
        decode_ops(rep, count)?;
        Ok((
            seq,
            WriteBatch {
                rep: rep.to_vec(),
                count,
            },
        ))
    }
}

fn decode_ops(rep: &[u8], count: u64) -> Result<Vec<Op<'_>>> {
    let mut d = Decoder::new(rep);
    let mut out = Vec::with_capacity(count.min(1 << 16) as usize);
    while !d.is_done() {
        let kind = d.u8();
        let key = d.lp();
        let value = (kind == PUT).then(|| d.lp());
        if kind > PUT {
            return Err(Error::corruption(format!("unknown batch op {kind}")));
        }
        out.push((key, value));
    }
    d.finish("write batch")?;
    if out.len() as u64 != count {
        return Err(Error::corruption("write batch count mismatch"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_encode_decode() {
        let mut b = WriteBatch::new();
        assert!(b.is_empty());
        b.put(b"k1", b"v1").delete(b"k2").put(b"", b"");
        assert_eq!(b.len(), 3);
        assert!(b.approximate_size() > 10);
        let ops = b.ops();
        assert_eq!(ops[0], (&b"k1"[..], Some(&b"v1"[..])));
        assert_eq!(ops[1], (&b"k2"[..], None));
        let enc = b.encode(77);
        let (seq, back) = WriteBatch::decode(&enc).unwrap();
        assert_eq!(seq, 77);
        assert_eq!(back, b);
        b.clear();
        assert!(b.is_empty());
        assert!(b.ops().is_empty());
    }

    #[test]
    fn decode_rejects_corruption() {
        assert!(WriteBatch::decode(&[1, 2, 3]).is_err());
        let mut b = WriteBatch::new();
        b.put(b"a", b"b");
        let enc = b.encode(1);
        // count mismatch
        let mut bad = enc.clone();
        bad[8] = 2;
        assert!(WriteBatch::decode(&bad).unwrap_err().to_string().contains("count"));
        // unknown op kind
        let mut bad = enc.clone();
        bad[9] = 7;
        assert!(WriteBatch::decode(&bad).unwrap_err().to_string().contains("unknown"));
        // truncated op
        assert!(WriteBatch::decode(&enc[..enc.len() - 1]).is_err());
    }
}
