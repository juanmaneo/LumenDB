//! Immutable versions of the table layout and the edits between them.
//!
//! A [`Version`] is an immutable snapshot of which tables live on which
//! level. Readers clone an `Arc<Version>` and never take a lock while they
//! read; flush and compaction build a *new* version and swap the pointer
//! (eguan/ibs style), so they never block or slow the read path. Files of a
//! replaced version stay readable through their open descriptors until the
//! last reader drops it.
//!
//! Level 0 holds flushed memtables (overlapping, newest first); levels 1..N
//! hold sorted runs of non-overlapping tables (LevelDB leveled compaction).

use crate::codec::Decoder;
use crate::error::{Error, Result};
use crate::merge::Source;
use crate::sstable::Table;
use crate::varint::{put_len_prefixed, put_uvarint64};
use std::sync::Arc;

pub const NUM_LEVELS: usize = 7;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileMeta {
    pub number: u64,
    pub size: u64,
    pub entries: u64,
    pub smallest: Vec<u8>,
    pub largest: Vec<u8>,
}

impl FileMeta {
    /// Does `[lo, hi]` intersect this file's key range?
    pub fn overlaps(&self, lo: &[u8], hi: &[u8]) -> bool {
        self.largest.as_slice() >= lo && self.smallest.as_slice() <= hi
    }
}

pub struct TableFile {
    pub meta: FileMeta,
    pub table: Arc<Table>,
}

/// A delta between versions, persisted in the manifest. An edit holding
/// every live file is a full snapshot of the database layout.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VersionEdit {
    pub log_number: Option<u64>,
    pub next_file: Option<u64>,
    pub last_seq: Option<u64>,
    pub deleted: Vec<(usize, u64)>,
    pub added: Vec<(usize, FileMeta)>,
}

const TAG_LOG: u64 = 1;
const TAG_NEXT_FILE: u64 = 2;
const TAG_LAST_SEQ: u64 = 3;
const TAG_DELETE: u64 = 4;
const TAG_ADD: u64 = 5;

impl VersionEdit {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for (tag, v) in [
            (TAG_LOG, self.log_number),
            (TAG_NEXT_FILE, self.next_file),
            (TAG_LAST_SEQ, self.last_seq),
        ] {
            if let Some(v) = v {
                put_uvarint64(&mut out, tag);
                put_uvarint64(&mut out, v);
            }
        }
        for &(level, number) in &self.deleted {
            put_uvarint64(&mut out, TAG_DELETE);
            put_uvarint64(&mut out, level as u64);
            put_uvarint64(&mut out, number);
        }
        for (level, f) in &self.added {
            put_uvarint64(&mut out, TAG_ADD);
            for v in [*level as u64, f.number, f.size, f.entries] {
                put_uvarint64(&mut out, v);
            }
            put_len_prefixed(&mut out, &f.smallest);
            put_len_prefixed(&mut out, &f.largest);
        }
        out
    }

    pub fn decode(buf: &[u8]) -> Result<VersionEdit> {
        let mut d = Decoder::new(buf);
        let mut e = VersionEdit::default();
        while !d.is_done() {
            let tag = d.varint();
            match tag {
                TAG_LOG => e.log_number = Some(d.varint()),
                TAG_NEXT_FILE => e.next_file = Some(d.varint()),
                TAG_LAST_SEQ => e.last_seq = Some(d.varint()),
                TAG_DELETE => e.deleted.push((d.varint() as usize, d.varint())),
                TAG_ADD => {
                    let (level, number, size, entries) = (d.varint() as usize, d.varint(), d.varint(), d.varint());
                    let smallest = d.lp().to_vec();
                    let largest = d.lp().to_vec();
                    e.added.push((
                        level,
                        FileMeta {
                            number,
                            size,
                            entries,
                            smallest,
                            largest,
                        },
                    ));
                }
                _ => return Err(Error::corruption(format!("unknown version edit tag {tag}"))),
            }
        }
        d.finish("version edit")?;
        let bad_level = e.deleted.iter().map(|d| d.0).chain(e.added.iter().map(|a| a.0));
        if bad_level.max().is_some_and(|l| l >= NUM_LEVELS) {
            return Err(Error::corruption("version edit level out of range"));
        }
        Ok(e)
    }

    /// Fold `other` into this edit (used to compact the manifest on replay).
    pub fn absorb(&mut self, other: &VersionEdit) {
        self.log_number = other.log_number.or(self.log_number);
        self.next_file = other.next_file.or(self.next_file);
        self.last_seq = other.last_seq.or(self.last_seq);
        for d in &other.deleted {
            self.added.retain(|(l, f)| (*l, f.number) != *d);
        }
        self.added.extend(other.added.iter().cloned());
    }
}

/// Tunables for compaction picking.
#[derive(Clone, Copy, Debug)]
pub struct LevelOptions {
    /// Compact level 0 once it holds this many tables.
    pub l0_trigger: usize,
    /// Byte budget of level 1; each next level is `multiplier` times larger.
    pub base_bytes: u64,
    pub multiplier: u64,
}

/// A chosen compaction: merge `inputs` (on `level`) with the overlapping
/// `next` files of `level + 1` into new `level + 1` tables.
pub struct Compaction {
    pub level: usize,
    pub inputs: Vec<Arc<TableFile>>,
    pub next: Vec<Arc<TableFile>>,
    /// No older data can exist below the output: tombstones may be dropped.
    pub bottom: bool,
}

#[derive(Clone, Default)]
pub struct Version {
    pub levels: [Vec<Arc<TableFile>>; NUM_LEVELS],
}

pub type Opener<'a> = &'a dyn Fn(&FileMeta) -> Result<Arc<Table>>;

impl Version {
    /// A new version with `edit` applied; added tables are opened via `open`.
    pub fn with_edit(&self, edit: &VersionEdit, open: Opener<'_>) -> Result<Version> {
        let mut v = self.clone();
        for &(level, number) in &edit.deleted {
            v.levels[level].retain(|f| f.meta.number != number);
        }
        for (level, meta) in &edit.added {
            let table = open(meta)?;
            v.levels[*level].push(Arc::new(TableFile {
                meta: meta.clone(),
                table,
            }));
        }
        v.levels[0].sort_by_key(|f| std::cmp::Reverse(f.meta.number));
        for l in &mut v.levels[1..] {
            l.sort_by(|a, b| a.meta.smallest.cmp(&b.meta.smallest));
        }
        Ok(v)
    }

    /// Every live file as a snapshot edit.
    pub fn snapshot_edit(&self) -> VersionEdit {
        let mut e = VersionEdit::default();
        for (level, files) in self.levels.iter().enumerate() {
            e.added.extend(files.iter().map(|f| (level, f.meta.clone())));
        }
        e
    }

    pub fn num_files(&self) -> usize {
        self.levels.iter().map(Vec::len).sum()
    }

    pub fn level_bytes(&self, level: usize) -> u64 {
        self.levels[level].iter().map(|f| f.meta.size).sum()
    }

    /// Newest version of `key` with `seq <= snap` across all tables.
    pub fn get(&self, key: &[u8], snap: u64) -> Result<Option<(u64, Option<Vec<u8>>)>> {
        for f in &self.levels[0] {
            if f.meta.overlaps(key, key) {
                if let Some(hit) = f.table.get(key, snap)? {
                    return Ok(Some(hit));
                }
            }
        }
        for files in &self.levels[1..] {
            let i = files.partition_point(|f| f.meta.largest.as_slice() < key);
            if let Some(f) = files.get(i).filter(|f| f.meta.smallest.as_slice() <= key) {
                if let Some(hit) = f.table.get(key, snap)? {
                    return Ok(Some(hit));
                }
            }
        }
        Ok(None)
    }

    /// Files of `level` intersecting `[lo, hi]`.
    pub fn overlapping(&self, level: usize, lo: &[u8], hi: &[u8]) -> Vec<Arc<TableFile>> {
        self.levels[level]
            .iter()
            .filter(|f| f.meta.overlaps(lo, hi))
            .cloned()
            .collect()
    }

    /// One sorted source per table intersecting `[start, end)`.
    pub fn sources(&self, start: &[u8], end: Option<&[u8]>) -> Vec<Source> {
        self.levels
            .iter()
            .flatten()
            .filter(|f| f.meta.largest.as_slice() >= start && end.is_none_or(|e| f.meta.smallest.as_slice() < e))
            .map(|f| Box::new(f.table.iter(start, end)) as Source)
            .collect()
    }

    /// Pick the most urgent compaction, if any level is over budget.
    /// `cursor[level]` rotates which file of a level is compacted next.
    pub fn pick(&self, opts: &LevelOptions, cursor: &mut [Vec<u8>; NUM_LEVELS]) -> Option<Compaction> {
        let mut best = (1.0f64, usize::MAX);
        let mut budget = opts.base_bytes.max(1);
        for level in 0..NUM_LEVELS - 1 {
            let score = if level == 0 {
                self.levels[0].len() as f64 / opts.l0_trigger.max(1) as f64
            } else {
                let s = self.level_bytes(level) as f64 / budget as f64;
                budget = budget.saturating_mul(opts.multiplier.max(2));
                s
            };
            if score >= best.0 {
                best = (score, level);
            }
        }
        let level = best.1;
        let inputs: Vec<Arc<TableFile>> = match level {
            usize::MAX => return None,
            0 => self.levels[0].clone(),
            _ => {
                let files = &self.levels[level];
                let at = files.iter().position(|f| f.meta.smallest > cursor[level]).unwrap_or(0);
                cursor[level] = files[at].meta.largest.clone();
                vec![files[at].clone()]
            }
        };
        let lo = inputs
            .iter()
            .map(|f| &f.meta.smallest)
            .min()
            .cloned()
            .unwrap_or_default();
        let hi = inputs
            .iter()
            .map(|f| &f.meta.largest)
            .max()
            .cloned()
            .unwrap_or_default();
        let next = self.overlapping(level + 1, &lo, &hi);
        let bottom = (level + 2..NUM_LEVELS).all(|l| self.overlapping(l, &lo, &hi).is_empty());
        Some(Compaction {
            level,
            inputs,
            next,
            bottom,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::{Env, OsEnv};
    use crate::merge::tests::e;
    use crate::merge::Entry;
    use crate::sstable::tests::build;
    use crate::sstable::TableOptions;
    use std::path::PathBuf;

    fn meta(number: u64, lo: &str, hi: &str, size: u64) -> FileMeta {
        FileMeta {
            number,
            size,
            entries: 1,
            smallest: lo.into(),
            largest: hi.into(),
        }
    }

    #[test]
    fn edit_roundtrip_absorb_and_errors() {
        let e1 = VersionEdit {
            log_number: Some(3),
            next_file: Some(9),
            last_seq: Some(100),
            deleted: vec![(1, 4)],
            added: vec![(0, meta(5, "a", "z", 10)), (2, meta(6, "b", "c", 20))],
        };
        assert_eq!(VersionEdit::decode(&e1.encode()).unwrap(), e1);
        assert_eq!(VersionEdit::decode(&[]).unwrap(), VersionEdit::default());
        assert!(VersionEdit::decode(&[99]).unwrap_err().to_string().contains("tag"));
        assert!(VersionEdit::decode(&[TAG_ADD as u8, 1]).is_err());
        assert!(VersionEdit::decode(&[TAG_DELETE as u8, 7, 1])
            .unwrap_err()
            .to_string()
            .contains("level"));
        assert!(VersionEdit::decode(&[TAG_ADD as u8, 9, 1, 1, 1, 0, 0]).is_err());
        let mut acc = VersionEdit::default();
        acc.absorb(&e1);
        acc.absorb(&VersionEdit {
            last_seq: Some(200),
            deleted: vec![(0, 5)],
            ..Default::default()
        });
        assert_eq!(acc.log_number, Some(3));
        assert_eq!(acc.last_seq, Some(200));
        assert_eq!(acc.added.len(), 1);
        assert!(meta(1, "b", "d", 0).overlaps(b"a", b"b"));
        assert!(!meta(1, "b", "d", 0).overlaps(b"e", b"f"));
    }

    struct Fixture {
        dir: PathBuf,
    }

    impl Fixture {
        fn new(name: &str) -> Self {
            Fixture {
                dir: crate::env::tests::tmpdir(name),
            }
        }
        fn file(&self, number: u64, entries: &[Entry]) -> FileMeta {
            let p = self.dir.join(format!("{number}.sst"));
            let info = build(&OsEnv, &p, entries, TableOptions::default()).unwrap();
            FileMeta {
                number,
                size: info.size,
                entries: info.entries,
                smallest: info.smallest,
                largest: info.largest,
            }
        }
        fn open(&self) -> impl Fn(&FileMeta) -> Result<Arc<Table>> + '_ {
            |m| {
                Ok(Arc::new(Table::open(
                    OsEnv.open(&self.dir.join(format!("{}.sst", m.number)))?,
                )?))
            }
        }
    }

    #[test]
    fn layered_lookups_and_sources() {
        let fx = Fixture::new("version-get");
        let l0_old = fx.file(1, &[e("k", 1, Some("old")), e("m", 2, Some("m2"))]);
        let l0_new = fx.file(2, &[e("k", 5, Some("new")), e("x", 6, None)]);
        let l1a = fx.file(3, &[e("a", 0, Some("a0")), e("c", 0, Some("c0"))]);
        let l1b = fx.file(4, &[e("p", 0, Some("p0")), e("x", 0, Some("x0"))]);
        let edit = VersionEdit {
            added: vec![(0, l0_old), (0, l0_new), (1, l1b), (1, l1a)],
            ..Default::default()
        };
        let open = fx.open();
        let v = Version::default().with_edit(&edit, &open).unwrap();
        assert_eq!(v.num_files(), 4);
        assert_eq!(v.levels[0][0].meta.number, 2);
        assert_eq!(v.levels[1][0].meta.number, 3);
        assert!(v.level_bytes(1) > 0);
        assert_eq!(v.get(b"k", 9).unwrap(), Some((5, Some(b"new".to_vec()))));
        assert_eq!(v.get(b"k", 3).unwrap(), Some((1, Some(b"old".to_vec()))));
        assert_eq!(v.get(b"x", 9).unwrap(), Some((6, None)));
        assert_eq!(v.get(b"c", 9).unwrap(), Some((0, Some(b"c0".to_vec()))));
        assert_eq!(v.get(b"b", 9).unwrap(), None); // in a1's range, absent
        assert_eq!(v.get(b"d", 9).unwrap(), None); // between files
        assert_eq!(v.get(b"z", 9).unwrap(), None); // past everything
        assert_eq!(v.sources(b"", None).len(), 4);
        assert_eq!(v.sources(b"n", Some(b"q")).len(), 2);
        assert_eq!(v.overlapping(1, b"b", b"b").len(), 1);
        let snap = v.snapshot_edit();
        assert_eq!(snap.added.len(), 4);
        let v2 = v
            .with_edit(
                &VersionEdit {
                    deleted: vec![(0, 1), (1, 3)],
                    ..Default::default()
                },
                &open,
            )
            .unwrap();
        assert_eq!(v2.num_files(), 2);
        let bad = VersionEdit {
            added: vec![(1, meta(77, "a", "b", 1))],
            ..Default::default()
        };
        assert!(v.with_edit(&bad, &open).is_err());
        std::fs::write(fx.dir.join("78.sst"), b"not a table").unwrap();
        assert!(open(&meta(78, "a", "b", 1)).is_err());
    }

    #[test]
    fn get_propagates_table_errors() {
        let fx = Fixture::new("version-err");
        let m0 = fx.file(1, &[e("k", 1, Some("v"))]);
        let m1 = fx.file(2, &[e("k", 0, Some("v"))]);
        let open = fx.open();
        let v = Version::default()
            .with_edit(
                &VersionEdit {
                    added: vec![(0, m0.clone()), (1, m1.clone())],
                    ..Default::default()
                },
                &open,
            )
            .unwrap();
        // corrupt both files in place: data blocks are read lazily
        for n in [1, 2] {
            let p = fx.dir.join(format!("{n}.sst"));
            let mut b = std::fs::read(&p).unwrap();
            b[0] ^= 0xff;
            std::fs::write(&p, b).unwrap();
        }
        assert!(v.get(b"k", 9).is_err());
        let only_l1 = v
            .with_edit(
                &VersionEdit {
                    deleted: vec![(0, 1)],
                    ..Default::default()
                },
                &open,
            )
            .unwrap();
        assert!(only_l1.get(b"k", 9).is_err());
    }

    #[test]
    fn compaction_picking() {
        let fx = Fixture::new("version-pick");
        let open = fx.open();
        let opts = LevelOptions {
            l0_trigger: 2,
            base_bytes: 1,
            multiplier: 10,
        };
        let mut cursor: [Vec<u8>; NUM_LEVELS] = Default::default();
        assert!(Version::default().pick(&opts, &mut cursor).is_none());
        let a = fx.file(1, &[e("a", 3, Some("1")), e("f", 3, Some("1"))]);
        let b = fx.file(2, &[e("c", 4, Some("1"))]);
        let l1 = fx.file(3, &[e("b", 1, Some("1")), e("d", 1, Some("1"))]);
        let l1far = fx.file(4, &[e("x", 1, Some("1"))]);
        let l3 = fx.file(5, &[e("e", 0, Some("1"))]);
        let edit = VersionEdit {
            added: vec![(0, a), (0, b), (1, l1), (1, l1far), (3, l3)],
            ..Default::default()
        };
        let v = Version::default().with_edit(&edit, &open).unwrap();
        // level 1 (way over its 1-byte budget) outranks level 0 (score 1.0)
        let c = v.pick(&opts, &mut cursor).unwrap();
        assert_eq!(c.level, 1);
        assert_eq!(c.inputs[0].meta.number, 3);
        assert!(c.next.is_empty());
        assert!(c.bottom); // file 5 ("e") on level 3 is outside [b, d]
        let c2 = v.pick(&opts, &mut cursor).unwrap();
        assert_eq!(c2.inputs[0].meta.number, 4); // cursor rotated
        assert!(c2.bottom);
        let c3 = v.pick(&opts, &mut cursor).unwrap();
        assert_eq!(c3.inputs[0].meta.number, 3); // wrapped around

        // only level 0 over budget
        let relaxed = LevelOptions {
            base_bytes: u64::MAX,
            ..opts
        };
        let c = v.pick(&relaxed, &mut cursor).unwrap();
        assert_eq!(c.level, 0);
        assert_eq!(c.inputs.len(), 2);
        assert_eq!(c.next.len(), 1);
        assert!(!c.bottom); // level 3 file "e" lies inside [a, f]
        let lazy = LevelOptions {
            l0_trigger: 10,
            ..relaxed
        };
        assert!(v.pick(&lazy, &mut cursor).is_none());
    }
}
