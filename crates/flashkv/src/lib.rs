//! flashkv: a crash-safe, high-performance ordered key-value store.
//!
//! - **LevelDB**: LSM tree — CRC-framed WAL, memtable, immutable SSTables
//!   with bloom filters, leveled compaction, CRC-framed manifest + `CURRENT`.
//! - **LMDB**: readers never block (they hold immutable `Arc` snapshots of the
//!   layout) — but deliberately **no mmap** of database files: tables are read
//!   with `pread`, every block is length- and CRC-checked, so a truncated file
//!   after a hardware crash is an `Err`, never a SIGBUS, and there is no map
//!   size to outgrow (LMDB's `MDB_MAP_FULL` crash).
//! - **FoundationDB**: modular storage layer ([`env::Env`]) with deterministic
//!   fault injection and power-loss simulation ([`env::FaultEnv`], and the
//!   in-memory [`memenv::MemEnv`] with torn writes and bit flips), MVCC
//!   snapshots and optimistic serializable transactions.
//! - **eguan/ibs, eblob, Akumuli**: flush and compaction write brand-new files
//!   on a background thread and publish them with one pointer swap, so they
//!   never block or slow down the read path.
//!
//! Ordering comes from sequence numbers (a logical clock), never wall time.

pub mod batch;
pub mod bloom;
pub mod codec;
pub mod crc;
pub mod db;
pub mod env;
pub mod error;
pub mod log;
pub mod lz;
pub mod manifest;
pub mod memenv;
pub mod memtable;
pub mod merge;
pub mod sstable;
pub mod txn;
pub mod varint;
pub mod version;

pub use batch::WriteBatch;
pub use db::{Db, DbOptions, Snapshot, Stats};
pub use error::{Error, Result};
pub use txn::Transaction;
