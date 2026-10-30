//! K-way merge of sorted entry streams, snapshot visibility and the
//! compaction garbage filter.
//!
//! Every source (memtable, immutable memtable, SSTables) yields entries in
//! `(key asc, seq desc)` order; the merge preserves it with a binary heap.

use crate::error::{Error, Result};
use std::cmp::Reverse;
use std::collections::BinaryHeap;

/// One version of a key; `value == None` is a tombstone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub key: Vec<u8>,
    pub seq: u64,
    pub value: Option<Vec<u8>>,
}

/// A sorted stream of entries.
pub type Source = Box<dyn Iterator<Item = Result<Entry>> + Send>;

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct Head {
    key: Vec<u8>,
    seq: Reverse<u64>,
    src: usize,
    value: Option<Vec<u8>>,
}

pub struct Merge {
    sources: Vec<Source>,
    heap: BinaryHeap<Reverse<Head>>,
    err: Option<Error>,
}

impl Merge {
    pub fn new(sources: Vec<Source>) -> Self {
        let mut m = Merge {
            heap: BinaryHeap::with_capacity(sources.len()),
            sources,
            err: None,
        };
        for i in 0..m.sources.len() {
            m.pull(i);
        }
        m
    }

    fn pull(&mut self, src: usize) {
        match self.sources[src].next() {
            Some(Ok(e)) => self.heap.push(Reverse(Head {
                key: e.key,
                seq: Reverse(e.seq),
                src,
                value: e.value,
            })),
            Some(Err(e)) => self.err = Some(e),
            None => {}
        }
    }
}

impl Iterator for Merge {
    type Item = Result<Entry>;

    fn next(&mut self) -> Option<Result<Entry>> {
        if let Some(e) = self.err.take() {
            return Some(Err(e));
        }
        let Reverse(h) = self.heap.pop()?;
        self.pull(h.src);
        Some(Ok(Entry {
            key: h.key,
            seq: h.seq.0,
            value: h.value,
        }))
    }
}

/// User-visible `(key, value)` pairs as of snapshot `snap`: the newest
/// version `<= snap` of each key, tombstones hidden.
pub struct Visible {
    inner: Merge,
    snap: u64,
    last: Option<Vec<u8>>,
}

impl Visible {
    pub fn new(inner: Merge, snap: u64) -> Self {
        Visible {
            inner,
            snap,
            last: None,
        }
    }
}

impl Iterator for Visible {
    type Item = Result<(Vec<u8>, Vec<u8>)>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let e = match self.inner.next()? {
                Ok(e) => e,
                Err(err) => return Some(Err(err)),
            };
            if e.seq > self.snap || self.last.as_deref() == Some(e.key.as_slice()) {
                continue;
            }
            self.last = Some(e.key.clone());
            if let Some(v) = e.value {
                return Some(Ok((e.key, v)));
            }
        }
    }
}

/// LevelDB's compaction drop rule. An entry is garbage when a newer version
/// of the same key is already visible to every live snapshot, or when it is a
/// tombstone visible to every snapshot and no older data can exist below the
/// output level (`drop_tombstones`).
pub struct GcFilter {
    smallest_snapshot: u64,
    drop_tombstones: bool,
    key: Option<Vec<u8>>,
    last_seq: u64,
}

impl GcFilter {
    pub fn new(smallest_snapshot: u64, drop_tombstones: bool) -> Self {
        GcFilter {
            smallest_snapshot,
            drop_tombstones,
            key: None,
            last_seq: u64::MAX,
        }
    }

    /// True if `e` must be written to the compaction output.
    pub fn keep(&mut self, e: &Entry) -> bool {
        if self.key.as_deref() != Some(e.key.as_slice()) {
            self.key = Some(e.key.clone());
            self.last_seq = u64::MAX;
        }
        let shadowed = self.last_seq <= self.smallest_snapshot;
        let dead_tombstone = e.value.is_none() && e.seq <= self.smallest_snapshot && self.drop_tombstones;
        self.last_seq = e.seq;
        !shadowed && !dead_tombstone
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn e(key: &str, seq: u64, value: Option<&str>) -> Entry {
        Entry {
            key: key.as_bytes().to_vec(),
            seq,
            value: value.map(|v| v.as_bytes().to_vec()),
        }
    }

    pub fn src(v: Vec<Entry>) -> Source {
        Box::new(v.into_iter().map(Ok))
    }

    #[test]
    fn merges_in_key_then_seq_order() {
        let m = Merge::new(vec![
            src(vec![e("a", 5, Some("a5")), e("c", 1, Some("c1"))]),
            src(vec![]),
            src(vec![e("a", 7, None), e("b", 2, Some("b2"))]),
        ]);
        let got: Vec<(String, u64)> = m
            .map(|r| r.unwrap())
            .map(|x| (String::from_utf8(x.key).unwrap(), x.seq))
            .collect();
        assert_eq!(
            got,
            vec![("a".into(), 7), ("a".into(), 5), ("b".into(), 2), ("c".into(), 1)]
        );
    }

    #[test]
    fn errors_surface_once() {
        let bad: Source = Box::new(vec![Err(Error::corruption("x"))].into_iter());
        let mut m = Merge::new(vec![bad, src(vec![e("a", 1, Some("1"))])]);
        assert!(m.next().unwrap().is_err());
        assert_eq!(m.next().unwrap().unwrap().key, b"a");
        assert!(m.next().is_none());
        let mut v = Visible::new(
            Merge::new(vec![Box::new(vec![Err(Error::corruption("y"))].into_iter())]),
            9,
        );
        assert!(v.next().unwrap().is_err());
        assert!(v.next().is_none());
    }

    #[test]
    fn visible_respects_snapshot_and_tombstones() {
        let mk = || {
            Merge::new(vec![src(vec![
                e("a", 9, None),
                e("a", 4, Some("a4")),
                e("b", 6, Some("b6")),
                e("b", 3, Some("b3")),
                e("c", 2, None),
            ])])
        };
        let all = |snap| -> Vec<(Vec<u8>, Vec<u8>)> { Visible::new(mk(), snap).map(|r| r.unwrap()).collect() };
        assert_eq!(all(100), vec![(b"b".to_vec(), b"b6".to_vec())]);
        assert_eq!(
            all(5),
            vec![(b"a".to_vec(), b"a4".to_vec()), (b"b".to_vec(), b"b3".to_vec())]
        );
        assert!(all(1).is_empty());
    }

    #[test]
    fn gc_filter_rules() {
        let mut f = GcFilter::new(5, true);
        assert!(f.keep(&e("a", 9, Some("x")))); // newer than snapshot
        assert!(f.keep(&e("a", 4, Some("y")))); // needed by snapshot 5
        assert!(!f.keep(&e("a", 3, Some("z")))); // shadowed by seq 4
        assert!(!f.keep(&e("b", 2, None))); // dead tombstone
        assert!(!f.keep(&e("b", 1, Some("old")))); // under the tombstone
        assert!(f.keep(&e("c", 7, None))); // tombstone newer than snapshot
        let mut keep_tomb = GcFilter::new(5, false);
        assert!(keep_tomb.keep(&e("b", 2, None)));
        assert!(!keep_tomb.keep(&e("b", 1, Some("old"))));
    }
}
