//! Deterministic Raft consensus core (majority quorum), SWIM gossip membership,
//! and Lamport logical clocks. Transport-agnostic: callers ship `Message`s /
//! `Gossip` between peers; nodes are driven by `tick()`/`step()` and are fully
//! deterministic, which makes them testable and model-checkable (see `proofs`).
//!
//! Time is purely logical (Lamport clocks) — never the wall clock.

pub mod clock;
pub mod error;
pub mod log;
pub mod message;
pub mod node;
pub mod quorum;
pub mod storage;
pub mod swim;

pub use clock::LamportClock;
pub use error::{Error, Result};
pub use log::{Log, LogEntry};
pub use message::{Message, MsgType};
pub use node::{Config, Node, NodeState, TickOutcome};
pub use quorum::{is_majority, quorum};
pub use storage::{DurableState, FileStorage, MemoryStorage, Storage};
pub use swim::{Gossip, Member, Status, Swim};

pub type NodeId = u64;
pub type Index = u64;
pub type Term = u64;
