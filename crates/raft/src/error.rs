use crate::NodeId;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Durable storage failed (I/O error, corruption); the node must stop.
    Storage(String),
    /// Message from a node that is not a peer of this one.
    UnknownPeer(u64),
    /// Entries that would break the log invariants or a committed prefix.
    LogInconsistency(String),
    /// This node is not in its own voter set.
    NotConfigured,
    /// Proposal sent to a non-leader; carries the known leader, if any.
    NotLeader(Option<NodeId>),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Storage(m) => write!(f, "storage: {m}"),
            Error::UnknownPeer(id) => write!(f, "unknown peer {id}"),
            Error::LogInconsistency(m) => write!(f, "log inconsistency: {m}"),
            Error::NotConfigured => write!(f, "node not in peer set"),
            Error::NotLeader(hint) => write!(f, "not leader (leader hint: {hint:?})"),
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
        assert!(format!("{}", Error::LogInconsistency("l".into())).contains('l'));
        assert!(format!("{}", Error::NotConfigured).contains("not in peer set"));
        assert!(format!("{}", Error::NotLeader(Some(3))).contains("Some(3)"));
    }

    #[test]
    fn conversions() {
        let e: Error = std::io::Error::other("disk on fire").into();
        assert_eq!(e, Error::Storage("disk on fire".into()));
        let e: Error = flashkv::Error::Corruption("bad".into()).into();
        assert_eq!(e, Error::Storage("corruption: bad".into()));
    }
}
