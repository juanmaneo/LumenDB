//! tsvdb: columnar time-series database on top of flashkv, inspired by
//! InfluxDB v3 (IOx).
//!
//! - Writes arrive as line protocol ([`lineproto`]), are made durable in a
//!   flashkv-backed write-ahead batch, and land in an in-memory write buffer.
//! - Each measurement + tag set is a series ([`tags`]); each (series, field)
//!   is a typed column.
//! - The buffer is flushed into immutable columnar chunks ([`chunk`]:
//!   delta-of-delta timestamps, Gorilla XOR floats) keyed by hour partition
//!   ([`partition`]).
//! - [`compact`] merges partitions in the background from a snapshot with one
//!   atomic batch, so reads are never blocked, and rolls data up (downsampling).
//! - [`query`] evaluates range scans and sum/count/min/max/mean aggregates,
//!   optionally per time window, and top-N (e.g. the heaviest pcap flows).

pub mod chunk;
pub mod compact;
pub mod db;
pub mod error;
pub mod lineproto;
pub mod partition;
pub mod query;
pub mod tags;
pub mod time;

pub use db::{capture_points, Db, DbOptions, DbStats};
pub use error::{Error, Result};
pub use lineproto::{FieldType, FieldValue, Point};
pub use query::{Agg, Align, Fill, Query, Row};
