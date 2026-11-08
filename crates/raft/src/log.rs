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
//!   for `i < base_index` (compacted) and for `i > last_index()`;
//! - the cluster configuration follows the entries: `voters()` is the list in
//!   the last [`EntryKind::Config`] entry held, or the base's list when there
//!   is none. Truncation, appends and snapshots keep it so, and a config entry
//!   that holds no valid voter list is never accepted.

use crate::error::{Error, LogError, Result};
use crate::{Index, NodeId, Term};

/// What an entry means to the protocol.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EntryKind {
    /// Application data (or, with empty data, a leader's no-op).
    #[default]
    Normal,
    /// The voter set the cluster uses from this entry on, in effect as soon
    /// as it is in the log, committed or not (Raft thesis section 4.1). The
    /// data is the whole set, see [`encode_voters`]. The application has
    /// nothing to apply for it.
    Config,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogEntry {
    pub index: Index,
    pub term: Term,
    pub kind: EntryKind,
    pub data: Vec<u8>,
}

/// A voter set as the data of a config entry: the ids in ascending order, 8
/// bytes each.
pub fn encode_voters(voters: &[NodeId]) -> Vec<u8> {
    voters.iter().flat_map(|v| v.to_le_bytes()).collect()
}

/// The voters in `data`; `None` unless it is [`encode_voters`] of a non-empty,
/// strictly ascending list.
pub fn decode_voters(data: &[u8]) -> Option<Vec<NodeId>> {
    let (chunks, rest) = data.as_chunks::<8>();
    if chunks.is_empty() | !rest.is_empty() {
        return None;
    }
    let ids: Vec<NodeId> = chunks.iter().map(|c| NodeId::from_le_bytes(*c)).collect();
    ids.windows(2).all(|w| w[0] < w[1]).then_some(ids)
}

impl LogEntry {
    /// An application entry.
    pub fn new(index: Index, term: Term, data: Vec<u8>) -> Self {
        LogEntry {
            index,
            term,
            kind: EntryKind::Normal,
            data,
        }
    }

    /// A configuration entry: from here on the voters are `voters`, which
    /// must be non-empty and ascending.
    pub fn config(index: Index, term: Term, voters: &[NodeId]) -> Self {
        LogEntry {
            index,
            term,
            kind: EntryKind::Config,
            data: encode_voters(voters),
        }
    }

    /// The voters of a valid configuration entry.
    pub fn voters(&self) -> Option<Vec<NodeId>> {
        match self.kind {
            EntryKind::Config => decode_voters(&self.data),
            EntryKind::Normal => None,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Log {
    entries: Vec<LogEntry>,
    base_index: Index,
    base_term: Term,
    /// The configuration at the base (empty: none known).
    base_voters: Vec<NodeId>,
    /// The configuration entries held, as `(index, voters)`, ascending.
    configs: Vec<(Index, Vec<NodeId>)>,
}

impl Log {
    pub fn new() -> Self {
        Log::default()
    }

    /// An empty log that starts after the snapshot `(base_index, base_term)`,
    /// whose configuration was `voters` (empty: none known).
    pub fn with_base(base_index: Index, base_term: Term, voters: Vec<NodeId>) -> Self {
        Log {
            base_index,
            base_term,
            base_voters: voters,
            ..Log::default()
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

    /// The configuration in effect at the end of the log: committed or not,
    /// the last configuration entry decides. Empty when the log has none and
    /// its base knows none.
    pub fn voters(&self) -> &[NodeId] {
        self.configs.last().map_or(&self.base_voters, |c| &c.1)
    }

    /// The configuration in effect at `index`, which needs entries up to it:
    /// the last configuration entry at or below it, or the base's.
    pub fn voters_at(&self, index: Index) -> &[NodeId] {
        match self.configs.iter().rfind(|c| c.0 <= index) {
            Some(c) => &c.1,
            None => &self.base_voters,
        }
    }

    /// Index of the entry that set [`Log::voters`], 0 when it is the base's.
    pub fn config_index(&self) -> Index {
        self.configs.last().map_or(0, |c| c.0)
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
    /// terms are non-decreasing from `term_at(first - 1)` through the batch,
    /// and every configuration entry holds a valid voter list.
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
            if e.kind == EntryKind::Config && decode_voters(&e.data).is_none() {
                return Err(Error::LogInconsistency(LogError::BadConfig { index: e.index }));
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
            let added = entries[skip..].iter().filter_map(|e| Some((e.index, e.voters()?)));
            self.configs.extend(added);
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
        self.configs.retain(|c| c.0 <= index);
    }

    /// Moves the base to the snapshot `(index, term)`, whose configuration
    /// was `voters` (empty: none known), and which must be above the current
    /// base. If the log has the entry `index` with term `term`, the entries
    /// after it are kept; otherwise the snapshot replaces the whole log,
    /// which is left empty. Atomic.
    pub fn install_snapshot(&mut self, index: Index, term: Term, voters: Vec<NodeId>) -> Result<()> {
        if index <= self.base_index {
            return Err(Error::LogInconsistency(LogError::NotAboveBase {
                index,
                base: self.base_index,
            }));
        }
        let agrees = self.term_at(index) == Some(term);
        self.entries = match agrees {
            true => self.entries.split_off((index - self.base_index) as usize),
            false => Vec::new(),
        };
        self.configs.retain(|c| agrees & (c.0 > index));
        self.base_index = index;
        self.base_term = term;
        self.base_voters = voters;
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
        LogEntry::new(i, t, vec![i as u8])
    }

    fn c(i: Index, t: Term, voters: &[NodeId]) -> LogEntry {
        LogEntry::config(i, t, voters)
    }

    /// The configuration implied by the entries, the slow way.
    fn recomputed(l: &Log) -> Vec<(Index, Vec<NodeId>)> {
        l.entries()
            .iter()
            .filter_map(|x| Some((x.index, x.voters()?)))
            .collect()
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
            && l.configs == recomputed(l)
            && l.voters() == recomputed(l).last().map_or(&l.base_voters[..], |x| &x.1[..])
            && l.config_index() == recomputed(l).last().map_or(0, |x| x.0)
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
        a.install_snapshot(2, 1, vec![]).unwrap();
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
            b.install_snapshot(index, term, vec![]).unwrap();
            assert_eq!(
                (b.base_index(), b.last_index(), b.last_term(), b.len()),
                (index, index, last_term, 0)
            );
            assert!(invariants(&b));
        }
        // The base must move forward.
        let before = a.clone();
        for index in [0, 1, 2] {
            let err = a.install_snapshot(index, 1, vec![]).unwrap_err();
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
        assert_eq!(Log::with_base(5, 3, vec![]).last_term(), 3);
        assert_eq!(Log::with_base(5, 3, vec![]).term_at(5), Some(3));
        assert_eq!(Log::with_base(5, 3, vec![]).last_index(), 5);
    }

    #[test]
    fn voter_lists_roundtrip_and_reject_garbage() {
        assert_eq!(decode_voters(&encode_voters(&[1, 5, 9])), Some(vec![1, 5, 9]));
        assert_eq!(decode_voters(&encode_voters(&[u64::MAX])), Some(vec![u64::MAX]));
        assert_eq!(decode_voters(&[]), None, "empty");
        assert_eq!(decode_voters(&[1, 0, 0, 0, 0, 0, 0]), None, "not a multiple of 8");
        assert_eq!(decode_voters(&encode_voters(&[2, 2])), None, "duplicate");
        assert_eq!(decode_voters(&encode_voters(&[3, 2])), None, "not ascending");
        assert_eq!(c(4, 1, &[1, 2]).voters(), Some(vec![1, 2]));
        assert_eq!(e(4, 1).voters(), None);
        let bad = LogEntry {
            kind: EntryKind::Config,
            ..e(2, 1)
        };
        assert_eq!(bad.voters(), None);
        let mut l = Log::new();
        let err = l.append(&[e(1, 1), bad]).unwrap_err();
        assert_eq!(err, Error::LogInconsistency(LogError::BadConfig { index: 2 }));
        assert!(l.is_empty(), "atomic");
        assert_eq!(EntryKind::default(), EntryKind::Normal);
    }

    #[test]
    fn the_configuration_follows_the_entries() {
        let mut l = Log::with_base(0, 0, vec![1, 2, 3]);
        assert_eq!((l.voters(), l.config_index()), (&[1, 2, 3][..], 0));
        l.append(&[e(1, 1), c(2, 1, &[1, 2, 3, 4]), e(3, 1), c(4, 2, &[1, 2, 4])])
            .unwrap();
        assert_eq!((l.voters(), l.config_index()), (&[1, 2, 4][..], 4));
        assert_eq!(l.voters_at(1), &[1, 2, 3]);
        assert_eq!(l.voters_at(2), &[1, 2, 3, 4]);
        assert_eq!(l.voters_at(3), &[1, 2, 3, 4]);
        assert_eq!(l.voters_at(9), &[1, 2, 4]);
        assert!(invariants(&l));
        // A conflicting suffix takes its configuration back to the one before.
        l.append(&[e(4, 3)]).unwrap();
        assert_eq!((l.voters(), l.config_index()), (&[1, 2, 3, 4][..], 2));
        // Truncating, appending a replacement.
        l.append(&[c(3, 4, &[2, 3])]).unwrap();
        assert_eq!((l.voters(), l.config_index(), l.last_index()), (&[2, 3][..], 3, 3));
        l.truncate_after(1);
        assert_eq!((l.voters(), l.config_index()), (&[1, 2, 3][..], 0));
        assert!(invariants(&l));
        // A snapshot that keeps the suffix keeps its configuration entries,
        // one that replaces the log drops them; the base's voters are the
        // snapshot's.
        let mut l = Log::with_base(0, 0, vec![1]);
        l.append(&[c(1, 1, &[1, 2]), e(2, 1), c(3, 1, &[1, 2, 3])]).unwrap();
        let mut kept = l.clone();
        kept.install_snapshot(2, 1, vec![1, 2]).unwrap();
        assert_eq!(
            (kept.voters(), kept.config_index(), kept.voters_at(2)),
            (&[1, 2, 3][..], 3, &[1, 2][..])
        );
        assert!(invariants(&kept));
        let mut replaced = l.clone();
        replaced.install_snapshot(2, 9, vec![7, 8]).unwrap();
        assert_eq!((replaced.voters(), replaced.config_index()), (&[7, 8][..], 0));
        assert!(invariants(&replaced));
        let mut all = l.clone();
        all.install_snapshot(3, 1, vec![1, 2, 3]).unwrap();
        assert_eq!((all.voters(), all.config_index()), (&[1, 2, 3][..], 0));
        assert!(invariants(&all));
    }

    /// An entry of either kind, fixed by its index and term.
    fn mixed(i: Index, t: Term) -> LogEntry {
        if (i + t).is_multiple_of(3) {
            c(i, t, &[i + 1, i + 5])
        } else {
            e(i, t)
        }
    }

    /// Appending to a log with any base keeps the invariants, or fails and
    /// changes nothing: every base up to 2, prefix of up to 2 entries and
    /// batch of up to 3 entries over indices 0..=6 and terms 0..=2. Some of
    /// the entries are configuration entries, so the voter bookkeeping is
    /// checked against a recomputation too.
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
                    let mut log = Log::with_base(base, base_term, vec![9]);
                    let initial: Vec<LogEntry> = prefix.iter().zip(base + 1..).map(|(&t, i)| mixed(i, t)).collect();
                    if log.append(&initial).is_err() {
                        continue;
                    }
                    for batch in &batches {
                        let batch: Vec<LogEntry> = batch.iter().map(|&(i, t)| mixed(i, t)).collect();
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
                        let mut cut = after.clone();
                        cut.truncate_after(base + 1);
                        assert!(invariants(&cut));
                        checked += 1;
                    }
                }
            }
        }
        assert!(checked > 100_000);
    }
}
