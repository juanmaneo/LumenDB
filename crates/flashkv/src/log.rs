//! CRC-framed record log, shared by the WAL and the manifest.
//!
//! Record = `masked_crc32c(len ++ payload): u32le | len: u32le | payload`.
//! A hardware crash can leave a torn or garbage tail; [`parse`] returns the
//! longest valid prefix and where it ends, so recovery never trips over it.

use crate::crc::masked_crc;
use crate::env::WritableFile;
use crate::error::Result;

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
