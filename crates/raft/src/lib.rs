//! Deterministic Raft consensus core (majority quorum), SWIM gossip membership,
//! and Lamport logical clocks. A [`Node`] is transport-agnostic: callers ship
//! `Message`s / `Gossip` between peers, driving it with `tick()`/`step()`, and
//! it is fully deterministic, which makes it testable and model-checkable (see
//! `proofs` and [`sim`]). [`net`] and [`server`] are one way to run it for
//! real: a TCP transport over the [`wire`] format, and a loop that ticks a node
//! and feeds a [`StateMachine`].
//!
//! The node's time is purely logical (Lamport clocks) — never the wall clock.
//! Only [`Server`] ties a tick to real time.

pub mod auth;
pub mod clock;
pub mod error;
pub mod log;
pub mod message;
pub mod net;
pub mod node;
pub mod quorum;
pub mod server;
pub mod sim;
pub mod storage;
pub mod swim;
pub mod wire;

pub use auth::{AuthStream, Secret};
pub use clock::LamportClock;
pub use error::{Error, LogError, Result};
pub use log::{EntryKind, Log, LogEntry};
pub use message::{Message, MsgType};
pub use net::{NetOptions, NetStats, Transport};
pub use node::{Config, Node, NodeState, ReadState, TickOutcome};
pub use quorum::{is_majority, quorum};
pub use server::{Server, ServerOptions, StateMachine};
pub use storage::{DurableState, FileStorage, MemoryStorage, Snapshot, Storage};
pub use swim::{Gossip, Member, Status, Swim};

pub type NodeId = u64;
pub type Index = u64;
pub type Term = u64;
