use crate::{Index, NodeId, Term};
use std::fmt;

/// Why a log operation was rejected.
///
/// Kept structured (formatted only in `Display`) so that error paths do no
/// string formatting: this keeps the kani proof of `Log::append` tractable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogError {
    /// `index` is past the last entry.
    BeyondLast { index: Index, last: Index },
    /// The range `(from, to]` is not inside the log.
    InvalidRange { from: Index, to: Index, last: Index },
    /// A batch starting at `index` would leave a gap (or starts at 0).
    NotContiguous { index: Index, last: Index },
    /// Entry `(index, term)` does not follow `(prev_index, prev_term)`.
    DoesNotFollow {
        index: Index,
        term: Term,
        prev_index: Index,
        prev_term: Term,
    },
    /// Appending would truncate committed entries.
    TruncatesCommitted,
    /// A snapshot at `index` does not move the base `base` forward.
    NotAboveBase { index: Index, base: Index },
}

impl fmt::Display for LogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            LogError::BeyondLast { index, last } => write!(f, "index {index} beyond last {last}"),
            LogError::InvalidRange { from, to, last } => write!(f, "range ({from},{to}] invalid, last={last}"),
            LogError::NotContiguous { index, last } => write!(f, "entry index {index} not contiguous (last={last})"),
            LogError::DoesNotFollow {
                index,
                term,
                prev_index,
                prev_term,
            } => write!(
                f,
                "entry ({index}, term {term}) does not follow ({prev_index}, term {prev_term})"
            ),
            LogError::TruncatesCommitted => write!(f, "append would truncate committed entries"),
            LogError::NotAboveBase { index, base } => write!(f, "snapshot at {index} is not above the base {base}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Durable storage failed (I/O error, corruption); the node must stop.
    Storage(String),
    /// Message from a node that is not a peer of this one.
    UnknownPeer(u64),
    /// Entries that would break the log invariants or a committed prefix.
    LogInconsistency(LogError),
    /// This node is not in its own voter set.
    NotConfigured,
    /// Proposal sent to a non-leader; carries the known leader, if any.
    NotLeader(Option<NodeId>),
    /// A linearizable read needs an entry of the leader's own term to be
    /// committed first; one is on its way, retry shortly.
    NotReady,
    /// A snapshot the node cannot take: the reason.
    BadSnapshot(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Storage(m) => write!(f, "storage: {m}"),
            Error::UnknownPeer(id) => write!(f, "unknown peer {id}"),
            Error::LogInconsistency(m) => write!(f, "log inconsistency: {m}"),
            Error::NotConfigured => write!(f, "node not in peer set"),
            Error::NotLeader(hint) => write!(f, "not leader (leader hint: {hint:?})"),
            Error::NotReady => write!(f, "leader has not committed an entry of its term yet, retry"),
            Error::BadSnapshot(why) => write!(f, "bad snapshot: {why}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Storage(e.to_string())
    }
}

impl From<flashkv::Error> for Error {
    fn from(e: flashkv::Error) -> Self {
        Error::Storage(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn display() {
        assert!(format!("{}", Error::Storage("s".into())).contains('s'));
        assert!(format!("{}", Error::UnknownPeer(7)).contains("7"));
        let e = Error::LogInconsistency(LogError::TruncatesCommitted);
        assert_eq!(
            e.to_string(),
            "log inconsistency: append would truncate committed entries"
        );
        assert!(format!("{}", Error::NotConfigured).contains("not in peer set"));
        assert!(format!("{}", Error::NotLeader(Some(3))).contains("Some(3)"));
        assert!(Error::NotReady.to_string().ends_with("retry"));
        assert_eq!(Error::BadSnapshot("too new").to_string(), "bad snapshot: too new");
    }

    #[test]
    fn log_error_display() {
        let cases = [
            (LogError::BeyondLast { index: 5, last: 3 }, "index 5 beyond last 3"),
            (
                LogError::InvalidRange {
                    from: 1,
                    to: 9,
                    last: 3,
                },
                "range (1,9] invalid, last=3",
            ),
            (
                LogError::NotContiguous { index: 7, last: 3 },
                "entry index 7 not contiguous (last=3)",
            ),
            (
                LogError::DoesNotFollow {
                    index: 4,
                    term: 1,
                    prev_index: 3,
                    prev_term: 2,
                },
                "entry (4, term 1) does not follow (3, term 2)",
            ),
            (LogError::TruncatesCommitted, "append would truncate committed entries"),
            (
                LogError::NotAboveBase { index: 2, base: 5 },
                "snapshot at 2 is not above the base 5",
            ),
        ];
        for (e, want) in cases {
            assert_eq!(e.to_string(), want);
        }
    }

    #[test]
    fn conversions() {
        let e: Error = std::io::Error::other("disk on fire").into();
        assert_eq!(e, Error::Storage("disk on fire".into()));
        let e: Error = flashkv::Error::Corruption("bad".into()).into();
        assert_eq!(e, Error::Storage("corruption: bad".into()));
    }
}
