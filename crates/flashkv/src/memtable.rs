//! Multi-version in-memory table.
//!
//! An ordered map keyed by `(user_key, Reverse(seq))`, so all versions of a
//! key are adjacent with the newest first — exactly the SSTable order, which
//! makes flushing a straight sequential write. Readers and the single writer
//! share it through a `RwLock` held only for the duration of one operation.

use crate::batch::WriteBatch;
use crate::merge::Entry;
use parking_lot::RwLock;
use std::cmp::Reverse;
use std::collections::BTreeMap;
use std::ops::Bound;
use std::sync::atomic::{AtomicUsize, Ordering};

type Map = BTreeMap<(Vec<u8>, Reverse<u64>), Option<Vec<u8>>>;

#[derive(Default)]
pub struct Memtable {
    map: RwLock<Map>,
    size: AtomicUsize,
}

impl Memtable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert every op of `batch`, numbering them from `seq`.
    pub fn apply(&self, batch: &WriteBatch, seq: u64) {
        let mut map = self.map.write();
        let mut added = 0;
        for (i, (k, v)) in batch.ops().into_iter().enumerate() {
            added += k.len() + v.map_or(0, <[u8]>::len) + 32;
            map.insert((k.to_vec(), Reverse(seq + i as u64)), v.map(<[u8]>::to_vec));
        }
        self.size.fetch_add(added, Ordering::Relaxed);
    }

    /// Newest version of `key` with `seq <= snap`: `(seq, value)`; a `None`
    /// value is a tombstone.
    pub fn get(&self, key: &[u8], snap: u64) -> Option<(u64, Option<Vec<u8>>)> {
        let map = self.map.read();
        let start = (key.to_vec(), Reverse(snap));
        let ((k, Reverse(seq)), v) = map.range(start..).next()?;
        (k.as_slice() == key).then(|| (*seq, v.clone()))
    }

    /// All versions with `start <= key < end` (`end == None`: unbounded).
    pub fn entries(&self, start: &[u8], end: Option<&[u8]>) -> Vec<Entry> {
        let map = self.map.read();
        let lo = Bound::Included((start.to_vec(), Reverse(u64::MAX)));
        let hi = end.map_or(Bound::Unbounded, |e| Bound::Excluded((e.to_vec(), Reverse(u64::MAX))));
        map.range((lo, hi))
            .map(|((k, Reverse(seq)), v)| Entry {
                key: k.clone(),
                seq: *seq,
                value: v.clone(),
            })
            .collect()
    }

    pub fn approximate_size(&self) -> usize {
        self.size.load(Ordering::Relaxed)
    }

    pub fn len(&self) -> usize {
        self.map.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_and_snapshots() {
        let m = Memtable::new();
        assert!(m.is_empty());
        let mut b = WriteBatch::new();
        b.put(b"a", b"1").put(b"b", b"2");
        m.apply(&b, 1);
        let mut b = WriteBatch::new();
        b.put(b"a", b"3").delete(b"b");
        m.apply(&b, 3);
        assert_eq!(m.len(), 4);
        assert!(m.approximate_size() > 0);
        assert_eq!(m.get(b"a", 10), Some((3, Some(b"3".to_vec()))));
        assert_eq!(m.get(b"a", 2), Some((1, Some(b"1".to_vec()))));
        assert_eq!(m.get(b"a", 0), None);
        assert_eq!(m.get(b"b", 10), Some((4, None)));
        assert_eq!(m.get(b"c", 10), None);
        assert_eq!(m.get(b"0", 10), None);
        let all = m.entries(b"", None);
        assert_eq!(all.len(), 4);
        assert_eq!((all[0].key.as_slice(), all[0].seq), (&b"a"[..], 3));
        let only_a = m.entries(b"a", Some(b"b"));
        assert_eq!(only_a.len(), 2);
        assert!(m.entries(b"c", None).is_empty());
    }
}
