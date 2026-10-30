//! Raft log: entries indexed from 1, virtual sentinel at 0 (term 0).
//!
//! Invariants, preserved by every mutating method (`append` is atomic: on
//! `Err` the log is unchanged):
//! - indices are contiguous starting at 1: `get(i).unwrap().index == i` for
//!   every `1 <= i <= last_index()`, and `last_index() == len()`;
//! - terms are non-decreasing: `term_at(i) <= term_at(i + 1)`;
//! - `term_at(0) == Some(0)` (sentinel) and `term_at(i) == None` iff
//!   `i > last_index()`.

use crate::error::{Error, Result};
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
}

impl Log {
    pub fn new() -> Self {
        Log { entries: Vec::new() }
    }

    /// Index of the last entry (0 when empty); pure.
    pub fn last_index(&self) -> Index {
        self.entries.len() as Index
    }

    /// Term of the last entry (0 when empty); pure.
    pub fn last_term(&self) -> Term {
        self.entries.last().map_or(0, |e| e.term)
    }

    /// Term at `index`: `Some(0)` for the sentinel 0, `None` past the end; pure.
    pub fn term_at(&self, index: Index) -> Option<Term> {
        match index {
            0 => Some(0),
            i => self.get(i).map(|e| e.term),
        }
    }

    /// Like [`Log::term_at`], but past-the-end is a `LogInconsistency` error.
    pub fn term(&self, index: Index) -> Result<Term> {
        self.term_at(index)
            .ok_or_else(|| Error::LogInconsistency(format!("index {} beyond last {}", index, self.last_index())))
    }

    /// All entries, in index order (`entries()[i].index == i + 1`).
    pub fn entries(&self) -> &[LogEntry] {
        &self.entries
    }

    pub fn get(&self, index: Index) -> Option<&LogEntry> {
        if index == 0 {
            None
        } else {
            self.entries.get((index - 1) as usize)
        }
    }

    pub fn entries_after(&self, from: Index, to: Index) -> Result<Vec<LogEntry>> {
        if from >= to {
            return Ok(Vec::new());
        }
        if to > self.last_index() {
            return Err(Error::LogInconsistency(format!(
                "range ({},{}] invalid, last={}",
                from,
                to,
                self.last_index()
            )));
        }
        Ok(self.entries[from as usize..to as usize].to_vec())
    }

    /// Checks, without mutating, that `append(entries)` would succeed: entry
    /// indices are consecutive, the first is in `1..=last_index() + 1`, and
    /// terms are non-decreasing from `term_at(first - 1)` through the batch.
    pub fn check_append(&self, entries: &[LogEntry]) -> Result<()> {
        let Some(first) = entries.first() else {
            return Ok(());
        };
        let mut prev_index = first.index.wrapping_sub(1);
        let mut prev_term = self.term_at(prev_index).ok_or_else(|| {
            Error::LogInconsistency(format!(
                "entry index {} not contiguous (last={})",
                first.index,
                self.last_index()
            ))
        })?;
        for e in entries {
            if e.index != prev_index.wrapping_add(1) || e.term < prev_term {
                return Err(Error::LogInconsistency(format!(
                    "entry ({}, term {}) does not follow ({}, term {})",
                    e.index, e.term, prev_index, prev_term
                )));
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

    /// Drops every entry with index `> index` (no-op if `index >= last_index()`).
    pub fn truncate_after(&mut self, index: Index) {
        self.entries.truncate(index.min(self.last_index()) as usize);
    }

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
}
