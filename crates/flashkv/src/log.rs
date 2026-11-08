//! CRC-framed record log, shared by the WAL and the manifest.
//!
//! Record = `masked_crc32c(len ++ payload): u32le | len: u32le | payload`.
//! A hardware crash can leave a torn tail; [`parse`] returns the longest
//! valid prefix and where it ends, and [`tail`] tells a torn tail (a write
//! that never completed, so was never acknowledged: safe to drop) from
//! corruption (a bit flip or bad sector in data that may have been
//! acknowledged: never silently dropped). This is the storage fault model of
//! TigerBeetle and of protocol-aware recovery (Alagappan et al., FAST '18).

use crate::crc::masked_crc;
use crate::env::WritableFile;
use crate::error::{Error, Result};

pub const HEADER: usize = 8;

/// Append the framing of `payload` to `out`.
pub fn frame(out: &mut Vec<u8>, payload: &[u8]) {
    let len = (payload.len() as u32).to_le_bytes();
    out.extend_from_slice(&masked_crc(&len, payload).to_le_bytes());
    out.extend_from_slice(&len);
    out.extend_from_slice(payload);
}

/// Every intact record of `buf` in order, plus the byte offset where the
/// valid prefix ends (`== buf.len()` when the log is clean).
pub fn parse(buf: &[u8]) -> (Vec<&[u8]>, usize) {
    let mut out = Vec::new();
    let mut pos = 0;
    while buf.len() - pos >= HEADER {
        let crc = u32::from_le_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]);
        let len_bytes = &buf[pos + 4..pos + 8];
        let len = u32::from_le_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]) as usize;
        let body = pos + HEADER;
        if len > buf.len() - body || masked_crc(len_bytes, &buf[body..body + len]) != crc {
            break;
        }
        out.push(&buf[body..body + len]);
        pos = body + len;
    }
    (out, pos)
}

/// What follows the valid prefix of a log, see [`tail`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tail {
    /// Every byte belongs to an intact record.
    Clean,
    /// An incomplete last record, or zero fill: a write cut short by a crash.
    Torn,
    /// A complete record with a bad checksum, or intact records after a bad
    /// one: the data was damaged after it was written.
    Corrupt,
}

/// Classifies the bytes of `buf` after `end`, the valid prefix returned by
/// [`parse`].
///
/// A crash can only tear the last write, and a torn write is a prefix of a
/// record (or zeros where the file system extended the file before the data
/// landed). So a bad record whose declared length fits in the file, or any
/// intact record further on, means corruption. A bit flip in a length field
/// can make a damaged record look incomplete: further records still give it
/// away, and for the last record of the file the checksum is tried with the
/// length of the bytes actually there. Only a flipped length in a last record
/// followed by zero fill still passes for a torn write.
pub fn tail(buf: &[u8], end: usize) -> Tail {
    let rest = &buf[end..];
    if rest.is_empty() {
        return Tail::Clean;
    }
    if rest.iter().all(|&b| b == 0) {
        return Tail::Torn;
    }
    let complete = rest.len() >= HEADER && {
        let crc = u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]);
        let declared = u32::from_le_bytes([rest[4], rest[5], rest[6], rest[7]]) as usize;
        let actual = rest.len() - HEADER;
        declared <= actual || masked_crc(&(actual as u32).to_le_bytes(), &rest[HEADER..]) == crc
    };
    if complete || (1..rest.len()).any(|i| !parse(&rest[i..]).0.is_empty()) {
        Tail::Corrupt
    } else {
        Tail::Torn
    }
}

/// [`parse`] for recovery: a torn tail is dropped, corruption is an error
/// naming `what` and the offset, so acknowledged data is never lost silently.
pub fn parse_checked<'a>(buf: &'a [u8], what: &str) -> Result<Vec<&'a [u8]>> {
    let (records, end) = parse(buf);
    match tail(buf, end) {
        Tail::Corrupt => Err(Error::corruption(format!("{what}: damaged record at offset {end}"))),
        Tail::Clean | Tail::Torn => Ok(records),
    }
}

/// Append-only record writer over a [`WritableFile`].
pub struct LogWriter {
    file: Box<dyn WritableFile>,
    buf: Vec<u8>,
    size: u64,
}

impl LogWriter {
    pub fn new(file: Box<dyn WritableFile>) -> Self {
        LogWriter {
            file,
            buf: Vec::new(),
            size: 0,
        }
    }

    /// Append one record with a single write; `sync` makes it durable.
    pub fn add(&mut self, payload: &[u8], sync: bool) -> Result<()> {
        self.buf.clear();
        frame(&mut self.buf, payload);
        self.file.append(&self.buf)?;
        self.size += self.buf.len() as u64;
        if sync {
            self.file.sync()?;
        }
        Ok(())
    }

    pub fn sync(&mut self) -> Result<()> {
        Ok(self.file.sync()?)
    }

    /// Bytes written so far.
    pub fn size(&self) -> u64 {
        self.size
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::{Env, FaultEnv, OsEnv};
    use std::sync::Arc;

    #[test]
    fn frame_parse_roundtrip_and_torn_tails() {
        let mut buf = Vec::new();
        frame(&mut buf, b"one");
        frame(&mut buf, b"");
        frame(&mut buf, &[9u8; 1000]);
        let (recs, end) = parse(&buf);
        assert_eq!(recs.len(), 3);
        assert_eq!(recs[0], b"one");
        assert!(recs[1].is_empty());
        assert_eq!(end, buf.len());
        // every truncation yields a clean prefix
        for cut in 0..buf.len() {
            let (r, e) = parse(&buf[..cut]);
            assert!(r.len() < 3);
            assert!(e <= cut);
        }
        // flipped payload byte stops parsing at that record
        let mut bad = buf.clone();
        bad[HEADER + 3 + HEADER + HEADER + 10] ^= 1;
        assert_eq!(parse(&bad).0.len(), 2);
        // huge length field
        let mut huge = buf.clone();
        huge[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(parse(&huge), (vec![], 0));
    }

    #[test]
    fn torn_tails_are_told_from_corruption() {
        let mut buf = Vec::new();
        frame(&mut buf, b"one");
        frame(&mut buf, &[7u8; 100]);
        frame(&mut buf, b"three");
        let classify = |b: &[u8]| tail(b, parse(b).1);
        assert_eq!(classify(&buf), Tail::Clean);
        // Every proper prefix is a torn write.
        for cut in 1..buf.len() {
            let t = classify(&buf[..cut]);
            assert!(t == Tail::Clean || t == Tail::Torn, "cut {cut}: {t:?}");
        }
        // Zero fill after the data, even a whole header's worth.
        let mut zeros = buf.clone();
        zeros.extend_from_slice(&[0; 64]);
        assert_eq!(classify(&zeros), Tail::Torn);
        // A flipped bit anywhere, including the last record, is corruption.
        for i in 0..buf.len() {
            for bit in 0..8 {
                let mut bad = buf.clone();
                bad[i] ^= 1 << bit;
                assert_eq!(classify(&bad), Tail::Corrupt, "byte {i} bit {bit}");
            }
        }
        // The one blind spot: the last record's length flipped beyond the end
        // of the file, then zero fill. That looks exactly like a torn write.
        let mut last = buf.clone();
        let n = last.len();
        last[n - 5 - 2] ^= 0x10;
        assert_eq!(classify(&last), Tail::Corrupt);
        last.extend_from_slice(&[0; 16]);
        assert_eq!(classify(&last), Tail::Torn);
        // An earlier record's length: the intact record after it is found.
        let mut first = buf.clone();
        first[6] ^= 0x10;
        assert_eq!(classify(&first), Tail::Corrupt);
        // parse_checked drops torn tails and reports corruption.
        assert_eq!(parse_checked(&zeros, "log").unwrap().len(), 3);
        assert_eq!(
            parse_checked(&first, "log 7").unwrap_err().to_string(),
            "corruption: log 7: damaged record at offset 0"
        );
    }

    #[test]
    fn writer_appends_and_syncs() {
        let d = crate::env::tests::tmpdir("log-writer");
        let p = d.join("log");
        let env = FaultEnv::new(Arc::new(OsEnv));
        let mut w = LogWriter::new(env.create(&p).unwrap());
        w.add(b"a", false).unwrap();
        w.add(b"bb", true).unwrap();
        w.sync().unwrap();
        assert_eq!(w.size(), (HEADER * 2 + 3) as u64);
        let data = std::fs::read(&p).unwrap();
        assert_eq!(parse(&data).0, vec![&b"a"[..], b"bb"]);
        env.fail_after(1);
        assert!(w.add(b"c", true).is_err());
        assert!(w.sync().is_err());
        env.fail_after(0);
        assert!(w.add(b"c", false).is_err());
    }
}
