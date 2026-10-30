//! Error type shared by every flashkv module.

use std::fmt;
use std::io;

#[derive(Debug)]
pub enum Error {
    /// Underlying I/O failure (disk, permissions, injected fault...).
    Io(io::Error),
    /// Persistent data failed validation (bad CRC, bad framing, bad magic).
    Corruption(String),
    /// Caller supplied an invalid argument.
    InvalidInput(String),
    /// Optimistic transaction lost a read/write race.
    Conflict(String),
    /// A previous write or background flush/compaction failed; the database
    /// refuses further writes until reopened (LevelDB's sticky `bg_error_`).
    Background(String),
}

impl Error {
    pub(crate) fn corruption(msg: impl Into<String>) -> Self {
        Error::Corruption(msg.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "io error: {e}"),
            Error::Corruption(m) => write!(f, "corruption: {m}"),
            Error::InvalidInput(m) => write!(f, "invalid input: {m}"),
            Error::Conflict(m) => write!(f, "transaction conflict: {m}"),
            Error::Background(m) => write!(f, "background error: {m}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error as _;

    #[test]
    fn display_and_source() {
        let io: Error = io::Error::other("disk").into();
        assert_eq!(io.to_string(), "io error: disk");
        assert!(io.source().is_some());
        assert_eq!(Error::corruption("c").to_string(), "corruption: c");
        assert_eq!(Error::InvalidInput("i".into()).to_string(), "invalid input: i");
        assert_eq!(Error::Conflict("k".into()).to_string(), "transaction conflict: k");
        assert_eq!(Error::Background("b".into()).to_string(), "background error: b");
        assert!(Error::Conflict("k".into()).source().is_none());
    }
}
