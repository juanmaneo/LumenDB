//! Raft log: entries indexed from 1, virtual sentinel at 0 (term 0).
//!
//! After a snapshot the log starts at a *base* `(base_index, base_term)`, the
//! last entry the snapshot covers: entries up to the base are gone, and the
//! first entry held has index `base_index + 1`. The base plays the part of the
//! sentinel, with `(0, 0)` for a log that was never compacted.
//!
//! Invariants, preserved by every mutating method (`append` is atomic: on
//! `Err` the log is unchanged):
//! - indices are contiguous starting at `base_index + 1`:
//!   `get(i).unwrap().index == i` for every `base_index < i <= last_index()`,
//!   and `last_index() == base_index + len()`;
//! - terms are non-decreasing: `term_at(i) <= term_at(i + 1)`, from the base on;
//! - `term_at(base_index) == Some(base_term)` (sentinel), `term_at(i) == None`
//!   for `i < base_index` (compacted) and for `i > last_index()`.

use crate::error::{Error, LogError, Result};
use crate::{Index, Term};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogEntry {
    pub index: Index,
    pub term: Term,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Log {
    entries: Vec<LogEntry>,
    base_index: Index,
    base_term: Term,
}

impl Log {
    pub fn new() -> Self {
        Log::default()
    }

    /// An empty log that starts after the snapshot `(base_index, base_term)`.
    pub fn with_base(base_index: Index, base_term: Term) -> Self {
        Log {
            entries: Vec::new(),
            base_index,
            base_term,
        }
    }

    /// Index of the last entry the log has dropped (0 if never compacted).
    pub fn base_index(&self) -> Index {
        self.base_index
    }

    /// Term of the entry at [`Log::base_index`].
    pub fn base_term(&self) -> Term {
        self.base_term
    }

    /// Index of the last entry (the base when no entry is held); pure.
    pub fn last_index(&self) -> Index {
        self.base_index + self.entries.len() as Index
    }

    /// Term of the last entry (the base term when no entry is held); pure.
    pub fn last_term(&self) -> Term {
        self.entries.last().map_or(self.base_term, |e| e.term)
    }

    /// Term at `index`: the base term at the base (`Some(0)` for 0 on a log
    /// never compacted), `None` below it and past the end; pure.
    pub fn term_at(&self, index: Index) -> Option<Term> {
        if index == self.base_index {
            Some(self.base_term)
        } else {
            self.get(index).map(|e| e.term)
        }
    }

    /// Like [`Log::term_at`], but past-the-end is a `LogInconsistency` error.
    pub fn term(&self, index: Index) -> Result<Term> {
        self.term_at(index).ok_or(Error::LogInconsistency(LogError::BeyondLast {
            index,
            last: self.last_index(),
        }))
    }

    /// The entries held, in index order (`entries()[i].index == base_index + i + 1`).
    pub fn entries(&self) -> &[LogEntry] {
        &self.entries
    }

    /// The entry at `index`; `None` at or below the base and past the end.
    pub fn get(&self, index: Index) -> Option<&LogEntry> {
        let offset = index.checked_sub(self.base_index + 1)?;
        self.entries.get(offset as usize)
    }

    /// The entries with index in `(from, to]`; `from` must not be below the base.
    pub fn entries_after(&self, from: Index, to: Index) -> Result<Vec<LogEntry>> {
        if from >= to {
            return Ok(Vec::new());
        }
        if (to > self.last_index()) | (from < self.base_index) {
            return Err(Error::LogInconsistency(LogError::InvalidRange {
                from,
                to,
                last: self.last_index(),
            }));
        }
        let (lo, hi) = (from - self.base_index, to - self.base_index);
        Ok(self.entries[lo as usize..hi as usize].to_vec())
    }

    /// Checks, without mutating, that `append(entries)` would succeed: entry
    /// indices are consecutive, the first is in `base_index + 1..=last_index() + 1`,
    /// and terms are non-decreasing from `term_at(first - 1)` through the batch.
    pub fn check_append(&self, entries: &[LogEntry]) -> Result<()> {
        let Some(first) = entries.first() else {
            return Ok(());
        };
        let mut prev_index = first.index.wrapping_sub(1);
        let mut prev_term = self
            .term_at(prev_index)
            .ok_or(Error::LogInconsistency(LogError::NotContiguous {
                index: first.index,
                last: self.last_index(),
            }))?;
        for e in entries {
            if e.index != prev_index.wrapping_add(1) || e.term < prev_term {
                return Err(Error::LogInconsistency(LogError::DoesNotFollow {
                    index: e.index,
                    term: e.term,
                    prev_index,
                    prev_term,
                }));
            }
            prev_index = e.index;
            prev_term = e.term;
        }
        Ok(())
    }

    /// Appends `entries` (Raft AppendEntries semantics), atomically.
    ///
    /// Entries already present with the same term are kept; at the first index
    /// whose term differs, the log is truncated and the rest of the batch is
    /// pushed. Fails (leaving the log untouched) if [`Log::check_append`] does.
    pub fn append(&mut self, entries: &[LogEntry]) -> Result<()> {
        self.check_append(entries)?;
        if let Some(k) = self.first_conflict(entries) {
            self.truncate_after(k - 1);
            let skip = (k - entries[0].index) as usize;
            self.entries.extend_from_slice(&entries[skip..]);
        }
        Ok(())
    }

    /// Index of the first entry of `entries` that is not already in the log
    /// with the same term (`None` when the whole batch is already present).
    /// `append` truncates from there; `> last_index()` means a pure append.
    pub fn first_conflict(&self, entries: &[LogEntry]) -> Option<Index> {
        entries
            .iter()
            .find(|e| self.term_at(e.index) != Some(e.term))
            .map(|e| e.index)
    }

    /// Drops every entry with index `> index`, never past the base (no-op if
    /// `index >= last_index()`).
    pub fn truncate_after(&mut self, index: Index) {
        let keep = index.min(self.last_index()).saturating_sub(self.base_index);
        self.entries.truncate(keep as usize);
    }

    /// Moves the base to the snapshot `(index, term)`, which must be above
    /// the current base. If the log has the entry `index` with term `term`,
    /// the entries after it are kept; otherwise the snapshot replaces the
    /// whole log, which is left empty. Atomic.
    pub fn install_snapshot(&mut self, index: Index, term: Term) -> Result<()> {
        if index <= self.base_index {
            return Err(Error::LogInconsistency(LogError::NotAboveBase {
                index,
                base: self.base_index,
            }));
        }
        let kept = match self.term_at(index) == Some(term) {
            true => self.entries.split_off((index - self.base_index) as usize),
            false => Vec::new(),
        };
        self.entries = kept;
        self.base_index = index;
        self.base_term = term;
        Ok(())
    }

    /// Number of entries held (not counting the compacted ones).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(i: Index, t: Term) -> LogEntry {
        LogEntry {
            index: i,
            term: t,
            data: vec![i as u8],
        }
    }

    /// The documented invariants, for any base.
    fn invariants(l: &Log) -> bool {
        let b = l.base_index();
        l.entries()
            .iter()
            .enumerate()
            .all(|(i, x)| x.index == b + i as Index + 1)
            && l.entries().windows(2).all(|w| w[0].term <= w[1].term)
            && l.entries().first().is_none_or(|x| x.term >= l.base_term())
            && l.term_at(b) == Some(l.base_term())
            && (b == 0 || l.term_at(b - 1).is_none())
            && l.term_at(l.last_index() + 1).is_none()
            && l.last_index() == b + l.len() as Index
    }

    #[test]
    fn empty_and_append() {
        let mut l = Log::new();
        assert_eq!(l.last_index(), 0);
        assert_eq!(l.last_term(), 0);
        assert_eq!(l.term(0).unwrap(), 0);
        assert!(l.term(1).is_err());
        assert!(l.is_empty());
        l.append(&[e(1, 1), e(2, 2)]).unwrap();
        assert_eq!(l.last_index(), 2);
        assert_eq!(l.term(2).unwrap(), 2);
        assert!(l.append(&[e(4, 2)]).is_err());
        assert_eq!(l.entries_after(1, 2).unwrap().len(), 1);
        assert!(l.entries_after(2, 3).is_err());
        assert!(l.entries_after(2, 2).unwrap().is_empty());
    }

    #[test]
    fn conflict_and_truncate() {
        let mut l = Log::new();
        l.append(&[e(1, 1), e(2, 1), e(3, 1)]).unwrap();
        l.append(&[e(3, 2), e(4, 2)]).unwrap();
        assert_eq!(l.term(3).unwrap(), 2);
        l.truncate_after(1);
        assert_eq!(l.last_index(), 1);
        l.truncate_after(9);
        assert_eq!(l.last_index(), 1);
        assert_eq!(l.len(), 1);
        assert!(!l.is_empty());
        assert!(l.get(0).is_none());
        assert_eq!(l.get(1).unwrap().data, vec![1u8]);
        assert_eq!(l.entries(), &[e(1, 1)]);
    }

    #[test]
    fn term_at_sentinel_and_bounds() {
        let mut l = Log::new();
        assert_eq!(l.term_at(0), Some(0));
        assert_eq!(l.term_at(1), None);
        l.append(&[e(1, 3)]).unwrap();
        assert_eq!(l.term_at(1), Some(3));
        assert_eq!(l.term_at(2), None);
        assert_eq!(l.term_at(u64::MAX), None);
    }

    #[test]
    fn append_rejects_and_is_atomic() {
        let mut l = Log::new();
        l.append(&[e(1, 2), e(2, 2)]).unwrap();
        let before = l.clone();
        // index 0, gap, non-consecutive batch, decreasing terms (in batch and vs prefix)
        assert!(l.append(&[e(0, 2)]).is_err());
        assert!(l.append(&[e(4, 2)]).is_err());
        assert!(l.append(&[e(3, 2), e(5, 2)]).is_err());
        assert!(l.append(&[e(3, 3), e(4, 2)]).is_err());
        assert!(l.append(&[e(2, 1)]).is_err());
        assert!(l.append(&[e(3, 2), e(4, 2), e(4, 2)]).is_err());
        assert_eq!(l, before);
        assert!(l.check_append(&[]).is_ok());
        l.append(&[]).unwrap();
        assert_eq!(l, before);
    }

    #[test]
    fn append_keeps_matching_suffix() {
        let mut l = Log::new();
        l.append(&[e(1, 1), e(2, 1), e(3, 1)]).unwrap();
        // stale/duplicate delivery of a prefix must not truncate later entries
        l.append(&[e(1, 1), e(2, 1)]).unwrap();
        assert_eq!(l.last_index(), 3);
        assert_eq!(l.first_conflict(&[e(1, 1), e(2, 1)]), None);
        assert_eq!(l.first_conflict(&[e(3, 1), e(4, 1)]), Some(4));
        assert_eq!(l.first_conflict(&[e(2, 2)]), Some(2));
        // conflict in the middle of the batch truncates from there
        l.append(&[e(2, 1), e(3, 2), e(4, 2)]).unwrap();
        assert_eq!(l.last_index(), 4);
        assert_eq!(l.term_at(3), Some(2));
        for i in 1..=l.last_index() {
            assert_eq!(l.get(i).unwrap().index, i);
            assert!(l.term_at(i - 1) <= l.term_at(i));
        }
    }

    #[test]
    fn snapshots_move_the_base() {
        let mut l = Log::new();
        l.append(&[e(1, 1), e(2, 1), e(3, 2), e(4, 2)]).unwrap();
        // A snapshot the log agrees with keeps the suffix.
        let mut a = l.clone();
        a.install_snapshot(2, 1).unwrap();
        assert_eq!((a.base_index(), a.base_term(), a.last_index(), a.len()), (2, 1, 4, 2));
        assert_eq!(
            (a.term_at(1), a.term_at(2), a.term_at(3), a.last_term()),
            (None, Some(1), Some(2), 2)
        );
        assert!(a.get(2).is_none() && a.get(0).is_none());
        assert_eq!(a.get(3).unwrap().index, 3);
        assert_eq!(a.entries(), &[e(3, 2), e(4, 2)]);
        assert!(invariants(&a));
        // One that disagrees at the base term, or lies beyond the log,
        // replaces the log.
        for (index, term, last_term) in [(2, 9, 9), (7, 2, 2)] {
            let mut b = l.clone();
            b.install_snapshot(index, term).unwrap();
            assert_eq!(
                (b.base_index(), b.last_index(), b.last_term(), b.len()),
                (index, index, last_term, 0)
            );
            assert!(invariants(&b));
        }
        // The base must move forward.
        let before = a.clone();
        for index in [0, 1, 2] {
            let err = a.install_snapshot(index, 1).unwrap_err();
            assert_eq!(err, Error::LogInconsistency(LogError::NotAboveBase { index, base: 2 }));
            assert_eq!(a, before);
        }
        // Reading and appending past a base.
        assert_eq!(a.entries_after(2, 4).unwrap(), vec![e(3, 2), e(4, 2)]);
        assert_eq!(a.entries_after(3, 4).unwrap(), vec![e(4, 2)]);
        assert!(a.entries_after(1, 4).is_err(), "below the base");
        assert!(a.entries_after(2, 5).is_err());
        assert!(a.entries_after(1, 1).unwrap().is_empty());
        a.append(&[e(3, 2), e(4, 2), e(5, 3)]).unwrap();
        assert_eq!(a.last_index(), 5);
        // The base cannot be appended to or conflicted with.
        assert!(a.append(&[e(2, 1)]).is_err());
        assert!(a.append(&[e(1, 1)]).is_err());
        // Truncation stops at the base.
        a.truncate_after(0);
        assert_eq!((a.base_index(), a.last_index()), (2, 2));
        assert_eq!(Log::with_base(5, 3).last_term(), 3);
        assert_eq!(Log::with_base(5, 3).term_at(5), Some(3));
        assert_eq!(Log::with_base(5, 3).last_index(), 5);
    }

    /// Appending to a log with any base keeps the invariants, or fails and
    /// changes nothing: every base up to 2, prefix of up to 2 entries and
    /// batch of up to 3 entries over indices 0..=6 and terms 0..=2.
    #[test]
    fn append_with_a_base_is_exhaustively_safe() {
        let items: Vec<(Index, Term)> = (0..=6).flat_map(|i| (0..=2).map(move |t| (i, t))).collect();
        let mut batches: Vec<Vec<(Index, Term)>> = vec![vec![]];
        for &a in &items {
            batches.push(vec![a]);
            for &b in &items {
                batches.push(vec![a, b]);
                for &c in &items {
                    batches.push(vec![a, b, c]);
                }
            }
        }
        let mut checked = 0;
        for base in 0..=2u64 {
            for base_term in 0..=2 {
                for prefix in [
                    vec![],
                    vec![0],
                    vec![1],
                    vec![2],
                    vec![0, 1],
                    vec![1, 1],
                    vec![1, 2],
                    vec![2, 2],
                ] {
                    let mut log = Log::with_base(base, base_term);
                    let initial: Vec<LogEntry> = prefix.iter().zip(base + 1..).map(|(&t, i)| e(i, t)).collect();
                    if log.append(&initial).is_err() {
                        continue;
                    }
                    for batch in &batches {
                        let batch: Vec<LogEntry> = batch.iter().map(|&(i, t)| e(i, t)).collect();
                        let before = log.clone();
                        let mut after = log.clone();
                        match after.append(&batch) {
                            Err(_) => assert_eq!(after, before),
                            Ok(()) => {
                                assert!(invariants(&after), "{before:?} + {batch:?}");
                                assert!(batch.iter().all(|x| after.term_at(x.index) == Some(x.term)));
                                // Nothing at or below the base is ever touched.
                                assert_eq!((after.base_index(), after.base_term()), (base, base_term));
                            }
                        }
                        checked += 1;
                    }
                }
            }
        }
        assert!(checked > 100_000);
    }
}
