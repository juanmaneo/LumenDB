//! Immutable sorted tables (LevelDB `table` format, simplified).
//!
//! ```text
//! data block*  : entries | type: u8 | masked_crc32c(payload ++ type): u32le
//!   entry      : shared varint | unshared varint | key suffix | seq varint
//!                | kind u8 (0 = tombstone, 1 = value) | [lp(value)]
//! index block  : count varint | (lp(last_key) last_seq off size)*  (varints)
//! filter block : bloom bitmap | k
//! footer (48B) : index_off index_len filter_off filter_len entries magic (u64le)
//! ```
//!
//! Entries are sorted by `(key asc, seq desc)`; keys are prefix-compressed
//! against the previous entry of the block and blocks may be LZ-compressed.
//! Reads use `pread` on an immutable file: every block is length- and
//! CRC-checked so corruption is an `Err`, never a crash.

use crate::bloom;
use crate::codec::Decoder;
use crate::crc::masked_crc;
use crate::env::{RandomAccessFile, WritableFile};
use crate::error::{Error, Result};
use crate::lz;
use crate::merge::Entry;
use crate::varint::{put_len_prefixed, put_uvarint64};
use std::cmp::Reverse;
use std::sync::Arc;

pub const MAGIC: u64 = 0x4c55_4d45_4e44_4231; // "LUMENDB1"
const FOOTER: usize = 48;
const RAW: u8 = 0;
const LZ: u8 = 1;

#[derive(Clone, Copy, Debug)]
pub struct TableOptions {
    pub block_size: usize,
    pub compress: bool,
    pub bloom_bits_per_key: usize,
}

impl Default for TableOptions {
    fn default() -> Self {
        TableOptions {
            block_size: 4096,
            compress: true,
            bloom_bits_per_key: 10,
        }
    }
}

/// Append `type | crc` to a block payload.
pub fn seal(mut payload: Vec<u8>, ty: u8) -> Vec<u8> {
    payload.push(ty);
    let crc = masked_crc(&payload, &[]);
    payload.extend_from_slice(&crc.to_le_bytes());
    payload
}

/// Summary of a finished table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TableInfo {
    pub size: u64,
    pub entries: u64,
    pub smallest: Vec<u8>,
    pub largest: Vec<u8>,
}

pub struct TableBuilder {
    file: Box<dyn WritableFile>,
    opts: TableOptions,
    block: Vec<u8>,
    prev_key: Vec<u8>,
    prev_seq: u64,
    index: Vec<u8>,
    index_count: u64,
    hashes: Vec<u64>,
    offset: u64,
    entries: u64,
    smallest: Vec<u8>,
}

fn shared_prefix(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b).take_while(|(x, y)| x == y).count()
}

impl TableBuilder {
    pub fn new(file: Box<dyn WritableFile>, opts: TableOptions) -> Self {
        TableBuilder {
            file,
            opts,
            block: Vec::with_capacity(opts.block_size * 2),
            prev_key: Vec::new(),
            prev_seq: 0,
            index: Vec::new(),
            index_count: 0,
            hashes: Vec::new(),
            offset: 0,
            entries: 0,
            smallest: Vec::new(),
        }
    }

    /// Add the next entry; callers guarantee `(key asc, seq desc)` order.
    pub fn add(&mut self, e: &Entry) -> Result<()> {
        if self.entries == 0 {
            self.smallest = e.key.clone();
        }
        let shared = if self.block.is_empty() {
            0
        } else {
            shared_prefix(&self.prev_key, &e.key)
        };
        if self.entries == 0 || self.prev_key != e.key {
            self.hashes.push(bloom::hash(&e.key));
        }
        put_uvarint64(&mut self.block, shared as u64);
        put_len_prefixed(&mut self.block, &e.key[shared..]);
        put_uvarint64(&mut self.block, e.seq);
        match &e.value {
            Some(v) => {
                self.block.push(1);
                put_len_prefixed(&mut self.block, v);
            }
            None => self.block.push(0),
        }
        self.prev_key.clear();
        self.prev_key.extend_from_slice(&e.key);
        self.prev_seq = e.seq;
        self.entries += 1;
        if self.block.len() >= self.opts.block_size {
            self.flush_block()?;
        }
        Ok(())
    }

    /// Bytes written plus the pending block (used to split outputs).
    pub fn estimated_size(&self) -> u64 {
        self.offset + self.block.len() as u64
    }

    fn write_raw(&mut self, payload: Vec<u8>, compress: bool) -> Result<(u64, u64)> {
        let (payload, ty) = match compress.then(|| lz::compress(&payload)) {
            Some(c) if c.len() < payload.len() - payload.len() / 8 => (c, LZ),
            _ => (payload, RAW),
        };
        let data = seal(payload, ty);
        self.file.append(&data)?;
        let at = self.offset;
        self.offset += data.len() as u64;
        Ok((at, data.len() as u64))
    }

    fn flush_block(&mut self) -> Result<()> {
        let block = std::mem::take(&mut self.block);
        let (off, size) = self.write_raw(block, self.opts.compress)?;
        put_len_prefixed(&mut self.index, &self.prev_key);
        put_uvarint64(&mut self.index, self.prev_seq);
        put_uvarint64(&mut self.index, off);
        put_uvarint64(&mut self.index, size);
        self.index_count += 1;
        Ok(())
    }

    /// Write index, filter and footer, then fsync the file.
    pub fn finish(mut self) -> Result<TableInfo> {
        if !self.block.is_empty() {
            self.flush_block()?;
        }
        let mut index = Vec::with_capacity(self.index.len() + 10);
        put_uvarint64(&mut index, self.index_count);
        index.extend_from_slice(&self.index);
        let (index_off, index_len) = self.write_raw(index, false)?;
        let filter = bloom::build(&self.hashes, self.opts.bloom_bits_per_key);
        let (filter_off, filter_len) = self.write_raw(filter, false)?;
        let mut footer = Vec::with_capacity(FOOTER);
        for v in [index_off, index_len, filter_off, filter_len, self.entries, MAGIC] {
            footer.extend_from_slice(&v.to_le_bytes());
        }
        self.file.append(&footer)?;
        self.file.sync()?;
        Ok(TableInfo {
            size: self.offset + FOOTER as u64,
            entries: self.entries,
            smallest: self.smallest,
            largest: self.prev_key,
        })
    }
}

struct IndexEntry {
    last_key: Vec<u8>,
    last_seq: u64,
    offset: u64,
    size: u64,
}

/// An open, immutable table. Cheap to share across threads.
pub struct Table {
    file: Arc<dyn RandomAccessFile>,
    index: Vec<IndexEntry>,
    filter: Vec<u8>,
    entries: u64,
}

fn read_block(file: &dyn RandomAccessFile, offset: u64, size: u64) -> Result<Vec<u8>> {
    if size < 5 || offset.saturating_add(size) > file.len() {
        return Err(Error::corruption(format!("block {offset}+{size} out of file bounds")));
    }
    let mut buf = vec![0u8; size as usize];
    file.read_at(&mut buf, offset)?;
    let crc_at = buf.len() - 4;
    let stored = u32::from_le_bytes([buf[crc_at], buf[crc_at + 1], buf[crc_at + 2], buf[crc_at + 3]]);
    if masked_crc(&buf[..crc_at], &[]) != stored {
        return Err(Error::corruption(format!("block checksum mismatch at {offset}")));
    }
    let ty = buf[crc_at - 1];
    buf.truncate(crc_at - 1);
    match ty {
        RAW => Ok(buf),
        LZ => lz::decompress(&buf),
        _ => Err(Error::corruption(format!("unknown block type {ty}"))),
    }
}

/// Decode every entry of a data block.
pub fn decode_block(data: &[u8]) -> Result<Vec<Entry>> {
    let mut d = Decoder::new(data);
    let mut out: Vec<Entry> = Vec::new();
    let mut prev: &[u8] = &[];
    while !d.is_done() {
        let shared = d.varint() as usize;
        let suffix = d.lp();
        let seq = d.varint();
        let kind = d.u8();
        let value = (kind == 1).then(|| d.lp().to_vec());
        if shared > prev.len() || kind > 1 {
            return Err(Error::corruption("bad block entry"));
        }
        let mut key = Vec::with_capacity(shared + suffix.len());
        key.extend_from_slice(&prev[..shared]);
        key.extend_from_slice(suffix);
        out.push(Entry { key, seq, value });
        prev = &out[out.len() - 1].key;
    }
    d.finish("data block")?;
    Ok(out)
}

impl Table {
    pub fn open(file: Arc<dyn RandomAccessFile>) -> Result<Table> {
        let len = file.len();
        if len < FOOTER as u64 {
            return Err(Error::corruption("table shorter than footer"));
        }
        let mut footer = [0u8; FOOTER];
        file.read_at(&mut footer, len - FOOTER as u64)?;
        let mut d = Decoder::new(&footer);
        let (index_off, index_len, filter_off, filter_len, entries, magic) =
            (d.u64(), d.u64(), d.u64(), d.u64(), d.u64(), d.u64());
        if magic != MAGIC {
            return Err(Error::corruption("bad table magic"));
        }
        let raw_index = read_block(file.as_ref(), index_off, index_len)?;
        let filter = read_block(file.as_ref(), filter_off, filter_len)?;
        let mut d = Decoder::new(&raw_index);
        let count = d.varint();
        let mut index = Vec::with_capacity(count.min(1 << 20) as usize);
        for _ in 0..count {
            let last_key = d.lp().to_vec();
            let (last_seq, offset, size) = (d.varint(), d.varint(), d.varint());
            index.push(IndexEntry {
                last_key,
                last_seq,
                offset,
                size,
            });
            if d.is_done() {
                break;
            }
        }
        d.finish("table index")?;
        if index.len() as u64 != count || !d.is_done() {
            return Err(Error::corruption("table index count mismatch"));
        }
        Ok(Table {
            file,
            index,
            filter,
            entries,
        })
    }

    pub fn entries(&self) -> u64 {
        self.entries
    }

    pub fn may_contain(&self, key: &[u8]) -> bool {
        bloom::may_contain(&self.filter, bloom::hash(key))
    }

    fn block(&self, i: usize) -> Result<Vec<Entry>> {
        let ie = &self.index[i];
        decode_block(&read_block(self.file.as_ref(), ie.offset, ie.size)?)
    }

    /// Newest version of `key` with `seq <= snap`.
    pub fn get(&self, key: &[u8], snap: u64) -> Result<Option<(u64, Option<Vec<u8>>)>> {
        if !self.may_contain(key) {
            return Ok(None);
        }
        let target = (key, Reverse(snap));
        let i = self
            .index
            .partition_point(|ie| (ie.last_key.as_slice(), Reverse(ie.last_seq)) < target);
        if i == self.index.len() {
            return Ok(None);
        }
        let block = self.block(i)?;
        let j = block.partition_point(|e| (e.key.as_slice(), Reverse(e.seq)) < target);
        Ok(block
            .into_iter()
            .nth(j)
            .filter(|e| e.key == key)
            .map(|e| (e.seq, e.value)))
    }

    /// Iterate every version with `start <= key < end`.
    pub fn iter(self: &Arc<Self>, start: &[u8], end: Option<&[u8]>) -> TableIter {
        let next_block = self.index.partition_point(|ie| ie.last_key.as_slice() < start);
        TableIter {
            table: self.clone(),
            next_block,
            buf: Vec::new().into_iter(),
            start: start.to_vec(),
            end: end.map(<[u8]>::to_vec),
        }
    }
}

pub struct TableIter {
    table: Arc<Table>,
    next_block: usize,
    buf: std::vec::IntoIter<Entry>,
    start: Vec<u8>,
    end: Option<Vec<u8>>,
}

impl Iterator for TableIter {
    type Item = Result<Entry>;

    fn next(&mut self) -> Option<Result<Entry>> {
        loop {
            if let Some(e) = self.buf.next() {
                if e.key < self.start {
                    continue;
                }
                if self.end.as_ref().is_some_and(|end| e.key >= *end) {
                    self.next_block = usize::MAX;
                    self.buf = Vec::new().into_iter();
                    return None;
                }
                return Some(Ok(e));
            }
            if self.next_block >= self.table.index.len() {
                return None;
            }
            let i = self.next_block;
            self.next_block += 1;
            match self.table.block(i) {
                Ok(b) => self.buf = b.into_iter(),
                Err(e) => {
                    self.next_block = usize::MAX;
                    return Some(Err(e));
                }
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::env::{Env, FaultEnv, OsEnv};
    use crate::merge::tests::e;
    use std::path::Path;

    pub fn build(env: &dyn Env, path: &Path, entries: &[Entry], opts: TableOptions) -> Result<TableInfo> {
        let mut b = TableBuilder::new(env.create(path)?, opts);
        for x in entries {
            b.add(x)?;
        }
        b.finish()
    }

    fn sample(n: usize) -> Vec<Entry> {
        let mut v = Vec::new();
        for i in 0..n {
            let k = format!("key{i:06}");
            v.push(e(
                &k,
                100 + i as u64,
                Some(&format!("value-{i}-{}", "x".repeat(i % 50))),
            ));
            if i % 7 == 0 {
                v.push(e(&k, 50, None));
            }
        }
        v
    }

    fn small_blocks() -> TableOptions {
        TableOptions {
            block_size: 256,
            ..TableOptions::default()
        }
    }

    #[test]
    fn build_open_get_iter() {
        let d = crate::env::tests::tmpdir("sst-basic");
        let p = d.join("t.sst");
        let entries = sample(2000);
        let info = build(&OsEnv, &p, &entries, small_blocks()).unwrap();
        assert_eq!(info.entries, entries.len() as u64);
        assert_eq!(info.smallest, b"key000000");
        assert_eq!(info.largest, b"key001999");
        assert_eq!(info.size, std::fs::metadata(&p).unwrap().len());
        let t = Arc::new(Table::open(OsEnv.open(&p).unwrap()).unwrap());
        assert_eq!(t.entries(), entries.len() as u64);
        assert!(t.index.len() > 10);
        assert_eq!(t.get(b"key000123", u64::MAX).unwrap().unwrap().0, 223);
        assert_eq!(t.get(b"key000007", 60).unwrap(), Some((50, None)));
        assert_eq!(t.get(b"key000007", 10).unwrap(), None);
        assert_eq!(t.get(b"key000008", 10).unwrap(), None);
        assert_eq!(t.get(b"nope", u64::MAX).unwrap(), None);
        assert_eq!(t.get(b"key001999", 0).unwrap(), None);
        // a key that passes the bloom check but sorts after the last block
        let mut past = None;
        for i in 0..100_000 {
            let k = format!("zz{i}");
            if t.may_contain(k.as_bytes()) {
                past = Some(k);
                break;
            }
        }
        assert_eq!(t.get(past.unwrap().as_bytes(), u64::MAX).unwrap(), None);
        let all: Vec<Entry> = t.iter(b"", None).map(|r| r.unwrap()).collect();
        assert_eq!(all, entries);
        let mid: Vec<Entry> = t.iter(b"key000500", Some(b"key000510")).map(|r| r.unwrap()).collect();
        assert_eq!(mid.first().unwrap().key, b"key000500");
        assert_eq!(mid.iter().filter(|x| x.value.is_some()).count(), 10);
        let mut it = t.iter(b"key000500", Some(b"key000501"));
        assert!(it.next().is_some());
        assert!(it.next().is_none());
        assert!(it.next().is_none());
        assert!(t.iter(b"zzz", None).next().is_none());
    }

    #[test]
    fn uncompressed_and_empty_tables() {
        let d = crate::env::tests::tmpdir("sst-raw");
        let p = d.join("raw.sst");
        let opts = TableOptions {
            compress: false,
            ..small_blocks()
        };
        build(&OsEnv, &p, &sample(100), opts).unwrap();
        let t = Arc::new(Table::open(OsEnv.open(&p).unwrap()).unwrap());
        assert_eq!(t.iter(b"", None).count(), 115);
        let p2 = d.join("empty.sst");
        let info = build(&OsEnv, &p2, &[], TableOptions::default()).unwrap();
        assert_eq!(info.entries, 0);
        let t = Arc::new(Table::open(OsEnv.open(&p2).unwrap()).unwrap());
        assert_eq!(t.get(b"a", 1).unwrap(), None);
        assert!(t.iter(b"", None).next().is_none());
    }

    #[test]
    fn corruption_is_detected() {
        let d = crate::env::tests::tmpdir("sst-corrupt");
        let p = d.join("t.sst");
        build(&OsEnv, &p, &sample(300), small_blocks()).unwrap();
        let good = std::fs::read(&p).unwrap();
        let open = |bytes: &[u8]| {
            std::fs::write(&p, bytes).unwrap();
            Table::open(OsEnv.open(&p).unwrap()).map(Arc::new)
        };
        assert!(open(&good[..10]).is_err());
        let mut bad = good.clone();
        let n = bad.len();
        bad[n - 1] ^= 1;
        assert!(open(&bad).err().unwrap().to_string().contains("magic"));
        let mut bad = good.clone();
        bad[n - FOOTER] ^= 1; // index offset
        assert!(open(&bad).is_err());
        let mut bad = good.clone();
        bad[n - FOOTER + 16] = 0xff; // filter offset
        bad[n - FOOTER + 17] = 0xff;
        assert!(open(&bad).is_err());
        // corrupt the first data block: open works, reads fail
        let mut bad = good.clone();
        bad[3] ^= 0xff;
        let t = open(&bad).unwrap();
        assert!(t.get(b"key000000", u64::MAX).is_err());
        let mut it = t.iter(b"", None);
        assert!(it.next().unwrap().is_err());
        assert!(it.next().is_none());
    }

    #[test]
    fn malformed_index_and_blocks() {
        let d = crate::env::tests::tmpdir("sst-index");
        let p = d.join("t.sst");
        // hand-made table with a given index payload
        let make = |index: Vec<u8>| {
            let mut file = seal(index, RAW);
            let ilen = file.len() as u64;
            let filter = seal(vec![0, 0], RAW);
            let flen = filter.len() as u64;
            file.extend_from_slice(&filter);
            for v in [0, ilen, ilen, flen, 0, MAGIC] {
                file.extend_from_slice(&v.to_le_bytes());
            }
            std::fs::write(&p, &file).unwrap();
            Table::open(OsEnv.open(&p).unwrap())
        };
        assert!(make(vec![1]).is_err()); // count 1, truncated entry
        assert!(make(vec![2, 0, 0, 0, 0]).is_err()); // count 2, one entry
        assert!(make(vec![0, 9]).is_err()); // trailing bytes
        assert!(make(vec![1, 0, 0, 0, 0, 7]).is_err()); // trailing after entry
        let t = make(vec![1, 1, b'a', 0, 0, 5]).unwrap(); // block of size 5 at 0
        assert!(t.get(b"a", 9).is_err()); // that "block" is the index: bad crc
                                          // unknown block type and corrupt lz payload with valid crcs
        let f = |block: Vec<u8>| {
            std::fs::write(&p, &block).unwrap();
            read_block(OsEnv.open(&p).unwrap().as_ref(), 0, block.len() as u64)
        };
        assert!(f(seal(vec![1, 2], 9)).unwrap_err().to_string().contains("type"));
        assert!(f(seal(vec![9, 9], LZ)).is_err());
        assert_eq!(f(seal(lz::compress(b"hello"), LZ)).unwrap(), b"hello");
        assert!(f(vec![1, 2]).is_err());
    }

    #[test]
    fn decode_block_rejects_garbage() {
        assert!(decode_block(&[5, 1, b'a', 1, 0]).is_err()); // shared > prev
        assert!(decode_block(&[0, 1, b'a', 1, 9]).is_err()); // bad kind
        assert!(decode_block(&[0, 1]).is_err()); // truncated
        assert_eq!(decode_block(&[]).unwrap(), vec![]);
    }

    #[test]
    fn io_faults_surface() {
        let d = crate::env::tests::tmpdir("sst-faults");
        let p = d.join("t.sst");
        let env = FaultEnv::new(Arc::new(OsEnv));
        let entries = sample(200);
        // fail at every write op of the build in turn
        let mut n = 0;
        loop {
            env.fail_after(n);
            let r = build(&env, &p, &entries, small_blocks());
            env.heal();
            if r.is_ok() {
                break;
            }
            n += 1;
        }
        assert!(n > 5);
        // and at every read op of open + full scan
        let mut n = 0;
        loop {
            env.fail_after(n);
            let r = env
                .open(&p)
                .map_err(Error::from)
                .and_then(Table::open)
                .and_then(|t| Arc::new(t).iter(b"", None).collect::<Result<Vec<_>>>());
            env.heal();
            if r.is_ok() {
                break;
            }
            n += 1;
        }
        assert!(n > 3);
    }
}
