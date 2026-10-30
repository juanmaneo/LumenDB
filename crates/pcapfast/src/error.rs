//! Error type for capture parsing.

use std::fmt;
use std::io;

#[derive(Debug)]
pub enum Error {
    /// Underlying I/O failure (open, mmap, read).
    Io(io::Error),
    /// The first bytes are neither a pcap nor a pcapng magic.
    BadMagic(u32),
    /// Structurally invalid data at `offset` (torn tails are *not* errors).
    Malformed { offset: u64, what: &'static str },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "io error: {e}"),
            Error::BadMagic(m) => write!(f, "unrecognized capture magic 0x{m:08x} (not pcap/pcapng)"),
            Error::Malformed { offset, what } => write!(f, "malformed capture at byte {offset}: {what}"),
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

/// Test helper: Debug rendering of the error in `r` (panics on `Ok`).
#[cfg(test)]
pub(crate) fn err_kind<T: fmt::Debug>(r: Result<T>) -> String {
    format!("{:?}", r.unwrap_err())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error as _;

    #[test]
    fn display_source_and_from() {
        let io: Error = io::Error::other("boom").into();
        assert!(io.to_string().contains("boom"));
        assert!(io.source().is_some());
        let bad = Error::BadMagic(0xdead_beef);
        assert!(bad.to_string().contains("0xdeadbeef"));
        assert!(bad.source().is_none());
        let m = Error::Malformed { offset: 42, what: "x" };
        assert_eq!(m.to_string(), "malformed capture at byte 42: x");
        assert!(format!("{m:?}").contains("Malformed"));
    }
}
