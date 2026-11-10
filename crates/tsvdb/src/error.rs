//! Error type shared by every tsvdb module.

use std::fmt;

#[derive(Debug)]
pub enum Error {
    /// Malformed line protocol (1-based line number).
    Parse { line: usize, msg: String },
    /// A field was written with a type different from its first write.
    Schema(String),
    /// Stored data failed validation.
    Corrupt(String),
    /// Invalid query.
    Query(String),
    /// Storage engine failure.
    Kv(flashkv::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Parse { line, msg } => write!(f, "line {line}: {msg}"),
            Error::Schema(m) => write!(f, "schema conflict: {m}"),
            Error::Corrupt(m) => write!(f, "corrupt data: {m}"),
            Error::Query(m) => write!(f, "invalid query: {m}"),
            Error::Kv(e) => write!(f, "storage: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Kv(e) => Some(e),
            _ => None,
        }
    }
}

impl From<flashkv::Error> for Error {
    fn from(e: flashkv::Error) -> Self {
        Error::Kv(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Kv(e.into())
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error as _;

    #[test]
    fn display_and_source() {
        let cases = [
            (
                Error::Parse {
                    line: 3,
                    msg: "x".into(),
                },
                "line 3: x",
            ),
            (Error::Schema("s".into()), "schema conflict: s"),
            (Error::Corrupt("c".into()), "corrupt data: c"),
            (Error::Query("q".into()), "invalid query: q"),
        ];
        for (e, want) in cases {
            assert_eq!(e.to_string(), want);
            assert!(e.source().is_none());
        }
        let kv: Error = flashkv::Error::Corruption("bad".into()).into();
        assert_eq!(kv.to_string(), "storage: corruption: bad");
        assert!(kv.source().is_some());
        let io: Error = std::io::Error::other("disk").into();
        assert_eq!(io.to_string(), "storage: io error: disk");
    }
}
