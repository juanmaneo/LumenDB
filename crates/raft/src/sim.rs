//! Deterministic cluster simulator in the style of TigerBeetle's VOPR.
//!
//! A seed fixes everything: message drops, duplicates, delays (and so
//! reordering), network partitions, process crashes, power loss with torn
//! writes, bit flips in the Raft log, and I/O errors. Each replica runs
//! [`FileStorage`] over its own [`MemEnv`], so the code under test is the
//! real storage stack, only the disk is simulated. A failing seed replays
//! exactly.
//!
//! After every event the simulator checks Raft's safety properties:
//! - election safety: at most one leader per term;
//! - leader completeness: a new leader of term `T` holds every entry seen
//!   committed in a term below `T`;
//! - state machine safety: no two replicas ever commit or apply different
//!   entries at one index, and entries are applied in index order;
//! - linearizable reads: an answered read, even from a stale leader that was
//!   asked, includes everything committed when it was asked;
//! - snapshots: every replica has a state machine (a hash of the entries it
//!   applied) that it snapshots, compacting its log, and restores from the
//!   snapshot after a restart or when a leader sends one, in chunks of a
//!   few bytes (or whole, depending on the leader) over a network that
//!   drops, repeats and reorders them. No two replicas may ever have
//!   different state at the same index;
//! - membership: an operator keeps changing the cluster through whichever
//!   replica leads (add a learner, promote it, remove a voter, drop a
//!   learner), while replicas crash and partitions come and go. Committed
//!   configurations must differ by exactly one server, and the configuration
//!   a snapshot carries must be the committed one at its index. Election
//!   safety, leader completeness and state machine safety are what catch two
//!   disjoint majorities;
//! - leadership transfer: the operator also asks the leader to hand
//!   leadership to a voter, which then campaigns at once. This changes which
//!   server leads and when, and nothing else, so the properties above are all
//!   there is to check; the run counts the hand-overs that succeed;
//! - log matching (every few ticks): two logs with the same term at an index
//!   are identical up to it, over the part both still have.
//!
//! Then faults stop, every replica restarts and the cluster must converge:
//! one leader, and among the voters of its configuration nobody recovering,
//! identical logs, commit indices and state machines. Corruption hits at
//! most a minority of the smallest voter set at a time, so the cluster can
//! always recover. Safety holds even beyond that; only liveness needs the
//! bound.

use crate::error::Error;
use crate::log::LogEntry;
use crate::message::{Message, MsgType};
use crate::node::{Config, Node, NodeState, ReadState};
use crate::storage::{FileStorage, Snapshot};
use crate::{Index, NodeId, Term};
use flashkv::env::Env;
use flashkv::memenv::MemEnv;
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;

/// Fault rates, in parts per million per opportunity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Faults {
    /// Per message.
    pub drop: u32,
    /// Per message: deliver it twice.
    pub duplicate: u32,
    /// Delivery takes 1 to `max_delay` ticks, so messages get reordered.
    pub max_delay: u64,
    /// Per tick: split the cluster in two for 10 to 100 ticks.
    pub partition: u32,
    /// Per replica and tick: the process dies, then the power goes out.
    pub crash: u32,
    /// Per crash: also flip one bit in a Raft log file.
    pub corrupt: u32,
    /// Per replica and tick: a storage operation soon fails, and the process
    /// crashes on the error.
    pub io_error: u32,
    /// A crashed replica restarts after this many ticks (inclusive range).
    pub downtime: (u64, u64),
    /// Per tick: a client proposes an entry to the leader.
    pub propose: u32,
    /// Per tick: a client asks the leader for a linearizable read.
    pub read: u32,
    /// Per replica and tick: snapshot the state machine and compact the log.
    pub snapshot: u32,
    /// Per tick: the operator asks the leader for a membership change.
    pub membership: u32,
    /// Per tick: the operator asks the leader to hand leadership to a voter.
    pub transfer: u32,
}

impl Default for Faults {
    fn default() -> Self {
        Faults {
            drop: 20_000,
            duplicate: 20_000,
            max_delay: 4,
            partition: 3_000,
            crash: 2_000,
            corrupt: 300_000,
            io_error: 1_000,
            downtime: (5, 60),
            propose: 300_000,
            read: 150_000,
            snapshot: 30_000,
            membership: 25_000,
            transfer: 10_000,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimConfig {
    /// Servers that exist: ids `1..=replicas`. All of them run from the start.
    pub replicas: u64,
    /// How many of them, `1..=voters`, are voters at the start; the others
    /// wait to be added. 0: the seed picks between 3 (or `replicas`, if
    /// fewer) and `replicas`.
    pub voters: u64,
    /// Ticks with faults.
    pub ticks: u64,
    /// Fault-free ticks to converge in afterwards.
    pub heal_ticks: u64,
    pub faults: Faults,
}

impl Default for SimConfig {
    fn default() -> Self {
        SimConfig {
            replicas: 5,
            voters: 0,
            ticks: 2_000,
            heal_ticks: 600,
            faults: Faults::default(),
        }
    }
}

/// What a run went through.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub seed: u64,
    /// Final commit index.
    pub committed: Index,
    /// Distinct (term, leader) pairs seen.
    pub elections: u64,
    pub crashes: u64,
    pub corruptions: u64,
    /// Replicas that came back with a damaged log, then caught up.
    pub recoveries: u64,
    pub io_errors: u64,
    pub partitions: u64,
    pub delivered: u64,
    pub dropped: u64,
    /// Reads answered, each checked against what was committed when asked.
    pub reads_served: u64,
    /// Reads that failed because the leader lost its leadership first.
    pub reads_failed: u64,
    /// Snapshots taken, each compacting a log.
    pub snapshots: u64,
    /// InstallSnapshot messages sent by leaders to followers behind their log.
    pub snapshots_sent: u64,
    /// Snapshots the state machine was restored from: after a restart, or
    /// sent by a leader to a follower that needed compacted entries.
    pub restores: u64,
    /// Membership changes that committed.
    pub reconfigs: u64,
    /// Leadership transfers a leader accepted.
    pub transfers: u64,
    /// Transfers after which the next leader elected was the target.
    pub handovers: u64,
}

impl Report {
    /// Adds the counters of `o`; the seed is left alone.
    pub fn add(&mut self, o: &Report) {
        self.committed += o.committed;
        self.elections += o.elections;
        self.crashes += o.crashes;
        self.corruptions += o.corruptions;
        self.recoveries += o.recoveries;
        self.io_errors += o.io_errors;
        self.partitions += o.partitions;
        self.delivered += o.delivered;
        self.dropped += o.dropped;
        self.reads_served += o.reads_served;
        self.reads_failed += o.reads_failed;
        self.snapshots += o.snapshots;
        self.snapshots_sent += o.snapshots_sent;
        self.restores += o.restores;
        self.reconfigs += o.reconfigs;
        self.transfers += o.transfers;
        self.handovers += o.handovers;
    }

    /// The counters, without the seed.
    pub fn summary(&self) -> String {
        format!(
            "committed {}, elections {}, crashes {}, corruptions {}, recoveries {}, io errors {}, \
             partitions {}, reads {} served / {} failed, snapshots {} taken / {} sent / {} restored, \
             membership changes {}, leadership transfers {} done of {} asked, \
             messages {} delivered / {} dropped",
            self.committed,
            self.elections,
            self.crashes,
            self.corruptions,
            self.recoveries,
            self.io_errors,
            self.partitions,
            self.reads_served,
            self.reads_failed,
            self.snapshots,
            self.snapshots_sent,
            self.restores,
            self.reconfigs,
            self.handovers,
            self.transfers,
            self.delivered,
            self.dropped
        )
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "seed {}: {}", self.seed, self.summary())
    }
}

/// Runs one seed to the end: `Err` describes the first violated property.
pub fn run(seed: u64, cfg: &SimConfig) -> Result<Report, String> {
    let mut sim = Sim::new(seed, cfg.clone());
    let result = (0..cfg.ticks + cfg.heal_ticks)
        .try_for_each(|_| sim.tick())
        .and_then(|()| sim.converged());
    result.map_err(|e| format!("seed {seed}, tick {}: {e}", sim.now))?;
    Ok(sim.report)
}

/// splitmix64.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    /// Uniform in `0..n` (0 when `n == 0`).
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
    fn range(&mut self, (lo, hi): (u64, u64)) -> u64 {
        lo + self.below(hi.saturating_sub(lo) + 1)
    }
    fn chance(&mut self, ppm: u32) -> bool {
        self.below(1_000_000) < ppm as u64
    }
}

/// The state machine of a replica: a hash of every entry applied, in order.
fn fold(digest: u64, e: &LogEntry) -> u64 {
    let mut h = digest ^ e.index.rotate_left(21) ^ e.term.rotate_left(42);
    for &b in &e.data {
        h = (h ^ b as u64).wrapping_mul(0x0100_0000_01b3);
    }
    h.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ (h >> 29)
}

/// The safety oracle: everything any replica ever reported.
#[derive(Default)]
struct Checker {
    leaders: BTreeMap<Term, NodeId>,
    /// Each committed entry, with the lowest term it was seen committed in.
    committed: BTreeMap<Index, (LogEntry, Term)>,
    /// The state machine (digest) after each index, as first seen.
    states: BTreeMap<Index, u64>,
    /// The committed configurations by the index of their entry. Index 0 is
    /// the initial one, when known.
    configs: BTreeMap<Index, Vec<NodeId>>,
}

/// A log as the simulator sees it: where it starts, and its entries.
type LogView = (Index, Vec<LogEntry>);

/// How many servers two voter sets differ by.
fn distance(a: &[NodeId], b: &[NodeId]) -> usize {
    a.iter().filter(|x| !b.contains(x)).count() + b.iter().filter(|x| !a.contains(x)).count()
}

impl Checker {
    /// A checker for a cluster that starts with the voters `initial`.
    fn new(initial: Vec<NodeId>) -> Self {
        Checker {
            configs: BTreeMap::from([(0, initial)]),
            ..Checker::default()
        }
    }

    /// The configuration entry at `index` committed with `voters`. It must
    /// differ from the committed configurations around it by one server.
    fn config(&mut self, index: Index, voters: Vec<NodeId>) -> Result<(), String> {
        let before = self.configs.range(..index).next_back();
        let after = self.configs.range(index + 1..).next();
        for (&other, v) in before.into_iter().chain(after) {
            let by = distance(v, &voters);
            if by != 1 {
                return Err(format!(
                    "configurations {other} and {index} differ by {by} servers, not one"
                ));
            }
        }
        self.configs.insert(index, voters);
        Ok(())
    }

    /// `id` uses the voters `voters` where it is at `index`, with no
    /// configuration entry of its log beyond that: they must be the ones
    /// committed at that index. This covers a snapshot it takes or installs,
    /// and the configuration a node derives from its log. No voters at all
    /// is what a node without configuration, and without a configuration
    /// entry in its log, knows.
    fn config_at(&self, id: NodeId, index: Index, voters: &[NodeId]) -> Result<(), String> {
        match self.configs.range(..=index).next_back() {
            Some((&at, v)) if (v != voters) & !(voters.is_empty() & (at == 0)) => Err(format!(
                "replica {id} uses voters {voters:?} at index {index}, but {v:?} was committed"
            )),
            _ => Ok(()),
        }
    }

    /// `id` leads `term`; returns whether that is news. A new leader must
    /// hold every entry committed in an earlier term.
    fn leader(&mut self, id: NodeId, term: Term, log: &dyn Fn() -> LogView) -> Result<bool, String> {
        match self.leaders.entry(term) {
            Entry::Occupied(o) if *o.get() == id => Ok(false),
            Entry::Occupied(o) => Err(format!("two leaders in term {term}: {} and {id}", o.get())),
            Entry::Vacant(v) => {
                v.insert(id);
                let (base, entries) = log();
                // Entries a snapshot covers are checked through the states.
                for (&i, (e, t)) in self.committed.range(base + 1..) {
                    if (*t < term) & (entries.get((i - base - 1) as usize) != Some(e)) {
                        return Err(format!("leader {id} of term {term} lacks committed entry {i}"));
                    }
                }
                Ok(true)
            }
        }
    }

    /// `id` has state `digest` after applying up to index `n`: every replica
    /// must agree on it.
    fn state(&mut self, id: NodeId, n: Index, digest: u64) -> Result<(), String> {
        match self.states.entry(n) {
            Entry::Vacant(v) => {
                v.insert(digest);
                Ok(())
            }
            Entry::Occupied(o) if *o.get() == digest => Ok(()),
            Entry::Occupied(o) => Err(format!(
                "replica {id} has state {digest:016x} at index {n}, others have {:016x}",
                o.get()
            )),
        }
    }

    /// `id`, in `term`, sees `entries` committed.
    fn commit(&mut self, id: NodeId, term: Term, entries: &[LogEntry]) -> Result<(), String> {
        for e in entries {
            match self.committed.entry(e.index) {
                Entry::Vacant(v) => {
                    v.insert((e.clone(), term));
                    if let Some(voters) = e.voters() {
                        self.config(e.index, voters)?;
                    }
                }
                Entry::Occupied(mut o) if o.get().0 == *e => {
                    let lowest = &mut o.get_mut().1;
                    *lowest = (*lowest).min(term);
                }
                Entry::Occupied(_) => return Err(format!("replica {id} committed a different entry {}", e.index)),
            }
        }
        Ok(())
    }

    /// The highest index seen committed.
    fn top(&self) -> Index {
        self.committed.last_key_value().map_or(0, |(&i, _)| i)
    }

    /// `id` applies `e` as its `n`-th entry.
    fn apply(&self, id: NodeId, n: Index, e: &LogEntry) -> Result<(), String> {
        match (e.index == n) & (self.committed.get(&n).map(|c| &c.0) == Some(e)) {
            true => Ok(()),
            false => Err(format!(
                "replica {id} applied entry {} as its entry {n}, not as committed",
                e.index
            )),
        }
    }
}

/// The entries of `log` after index `floor` (which is at least its base).
fn after(log: &LogView, floor: Index) -> &[LogEntry] {
    &log.1[(floor - log.0) as usize..]
}

/// Log matching over every pair of `logs`, on the part both still have.
fn log_matching(logs: &[LogView]) -> Result<(), String> {
    for (a, x) in logs.iter().enumerate() {
        for y in &logs[a + 1..] {
            let floor = x.0.max(y.0);
            let (xs, ys) = (
                after(x, floor.min(x.0 + x.1.len() as Index)),
                after(y, floor.min(y.0 + y.1.len() as Index)),
            );
            let common = xs.len().min(ys.len());
            let same = (0..common).rev().find(|&i| xs[i].term == ys[i].term);
            if let Some(i) = same.filter(|&i| xs[..=i] != ys[..=i]) {
                return Err(format!(
                    "logs share term {} at index {} but differ up to it",
                    xs[i].term,
                    floor + i as Index + 1
                ));
            }
        }
    }
    Ok(())
}

struct Replica {
    env: MemEnv,
    node: Option<Node>,
    down_until: u64,
    /// Index the state machine is at in this incarnation: entries applied,
    /// or the snapshot it was restored from plus the entries after it.
    applied: Index,
    /// The state machine: a hash of everything applied, see [`fold`].
    digest: u64,
    /// Commit index already reported to the checker in this incarnation.
    seen_commit: Index,
    /// Corrupted and not yet caught up (counts against the minority bound).
    damaged: bool,
}

struct Sim {
    cfg: SimConfig,
    rng: Rng,
    now: u64,
    dir: PathBuf,
    /// The voters the cluster started with, `1..=n`.
    initial: Vec<NodeId>,
    replicas: Vec<Replica>,
    /// In-flight messages by (delivery tick, send order).
    queue: BTreeMap<(u64, u64), Message>,
    sent: u64,
    /// Until when, and which side each replica is on.
    partition: Option<(u64, Vec<bool>)>,
    check: Checker,
    payload: u64,
    /// Reads asked and not yet answered, by (replica, id): the highest index
    /// known to be committed when each was asked.
    reads: BTreeMap<(usize, u64), Index>,
    /// The target of the last transfer a leader accepted, until the next
    /// election.
    transfer: Option<NodeId>,
    report: Report,
}

impl Sim {
    fn new(seed: u64, cfg: SimConfig) -> Self {
        let mut rng = Rng(seed);
        let fewest = cfg.replicas.min(3);
        let count = match cfg.voters {
            0 => rng.range((fewest, cfg.replicas)),
            n => n.min(cfg.replicas),
        };
        let initial: Vec<NodeId> = (1..=count).collect();
        let replicas = (0..cfg.replicas)
            .map(|_| Replica {
                env: MemEnv::new(),
                node: None,
                down_until: 0,
                applied: 0,
                digest: 0,
                seen_commit: 0,
                damaged: false,
            })
            .collect();
        Sim {
            rng,
            now: 0,
            dir: PathBuf::from("/raft"),
            check: Checker::new(initial.clone()),
            initial,
            replicas,
            queue: BTreeMap::new(),
            sent: 0,
            partition: None,
            payload: 0,
            reads: BTreeMap::new(),
            transfer: None,
            report: Report {
                seed,
                ..Report::default()
            },
            cfg,
        }
    }

    fn faulty(&self) -> bool {
        self.now < self.cfg.ticks
    }

    /// One tick of simulated time.
    fn tick(&mut self) -> Result<(), String> {
        if self.now == self.cfg.ticks {
            self.heal();
        }
        if self.faulty() {
            self.inject();
        }
        for i in 0..self.replicas.len() {
            if self.replicas[i].node.is_none() & (self.replicas[i].down_until <= self.now) {
                self.start(i)?;
            }
        }
        for i in 0..self.replicas.len() {
            match self.replicas[i].node.as_ref().map(Node::tick) {
                None => {}
                Some(Ok(out)) => {
                    self.observe(i)?;
                    if let Some(snapshot) = &out.snapshot {
                        self.restore(i, snapshot)?;
                    }
                    let (id, r) = (i as NodeId + 1, &mut self.replicas[i]);
                    for e in &out.committed {
                        r.applied += 1;
                        self.check.apply(id, r.applied, e)?;
                        r.digest = fold(r.digest, e);
                        self.check.state(id, r.applied, r.digest)?;
                    }
                    for read in &out.reads {
                        self.answered(i, read)?;
                    }
                    if self.rng.chance(self.cfg.faults.snapshot) {
                        self.take_snapshot(i)?;
                    }
                    self.send(out.messages);
                }
                Some(Err(e)) => self.failed(i, e)?,
            }
        }
        if (self.now < self.cfg.ticks + self.cfg.heal_ticks / 2) & self.rng.chance(self.cfg.faults.propose) {
            self.propose()?;
        }
        if (self.now < self.cfg.ticks + self.cfg.heal_ticks / 2) & self.rng.chance(self.cfg.faults.read) {
            self.read();
        }
        if (self.now < self.cfg.ticks + self.cfg.heal_ticks / 2) & self.rng.chance(self.cfg.faults.membership) {
            self.reconfigure()?;
        }
        if (self.now < self.cfg.ticks + self.cfg.heal_ticks / 2) & self.rng.chance(self.cfg.faults.transfer) {
            self.hand_over();
        }
        self.deliver()?;
        if self.now.is_multiple_of(16) {
            log_matching(&self.logs())?;
        }
        self.now += 1;
        Ok(())
    }

    fn logs(&self) -> Vec<LogView> {
        self.replicas
            .iter()
            .filter_map(|r| r.node.as_ref().map(|n| (n.snapshot_index(), n.log_snapshot().1)))
            .collect()
    }

    /// Replica `i`'s state machine is replaced by the snapshot's.
    fn restore(&mut self, i: usize, snapshot: &Snapshot) -> Result<(), String> {
        let id = i as NodeId + 1;
        let digest = <[u8; 8]>::try_from(&snapshot.data[..])
            .map(u64::from_le_bytes)
            .map_err(|_| {
                format!(
                    "replica {id} got a snapshot with {} bytes of state",
                    snapshot.data.len()
                )
            })?;
        let r = &mut self.replicas[i];
        (r.applied, r.digest) = (snapshot.index, digest);
        self.check.state(id, snapshot.index, digest)?;
        self.check.config_at(id, snapshot.index, &snapshot.voters)?;
        self.report.restores += 1;
        Ok(())
    }

    /// Replica `i` snapshots its state machine, which drops its log up to there.
    fn take_snapshot(&mut self, i: usize) -> Result<(), String> {
        let r = &self.replicas[i];
        let node = r.node.as_ref().expect("a replica that just ticked is up");
        if r.applied <= node.snapshot_index() {
            return Ok(());
        }
        match node.compact(r.applied, r.digest.to_le_bytes().to_vec()) {
            Ok(()) => {
                self.report.snapshots += 1;
                Ok(())
            }
            Err(e) => self.failed(i, e),
        }
    }

    fn inject(&mut self) {
        let f = self.cfg.faults.clone();
        if self.partition.as_ref().is_some_and(|(until, _)| *until <= self.now) {
            self.partition = None;
        }
        if self.partition.is_none() & self.rng.chance(f.partition) {
            let sides = self.replicas.iter().map(|_| self.rng.next() & 1 == 1).collect();
            self.partition = Some((self.now + self.rng.range((10, 100)), sides));
            self.report.partitions += 1;
        }
        // A server that no live node counts as a voter cannot hold anyone up.
        let voting: Vec<NodeId> = (self.replicas.iter())
            .filter_map(|r| r.node.as_ref())
            .flat_map(Node::voters)
            .collect();
        let bound = (self.fewest_voters() as usize).saturating_sub(1) / 2;
        for i in 0..self.replicas.len() {
            let up = self.replicas[i].node.is_some();
            if up & self.rng.chance(f.crash) {
                let damaged = (self.replicas.iter().enumerate())
                    .filter(|(i, r)| r.damaged & voting.contains(&(*i as NodeId + 1)))
                    .count();
                let corrupt = self.rng.chance(f.corrupt) & (damaged < bound);
                self.crash(i, corrupt);
            } else if up & self.rng.chance(f.io_error) {
                let n = self.rng.below(8);
                self.replicas[i].env.fail_after(n);
            }
        }
    }

    /// Faults stop: partitions heal, disks stop failing, everyone restarts.
    fn heal(&mut self) {
        self.partition = None;
        for r in &mut self.replicas {
            r.env.heal();
            r.down_until = r.down_until.min(self.now);
        }
    }

    /// The smallest voter set the cluster can have: the operator never goes
    /// below 3 voters (or all the servers, if there are fewer), and without
    /// an operator it stays at its initial size.
    fn fewest_voters(&self) -> u64 {
        match self.cfg.faults.membership {
            0 => self.initial.len() as u64,
            _ => self.cfg.replicas.min(3),
        }
    }

    fn start(&mut self, i: usize) -> Result<(), String> {
        let id = i as NodeId + 1;
        let env: Arc<dyn Env> = Arc::new(self.replicas[i].env.clone());
        let storage =
            FileStorage::open_with_env(env, &self.dir).map_err(|e| format!("replica {id} cannot restart: {e}"))?;
        // A cluster may mix replicas with and without pre-vote.
        let base = match id <= self.initial.len() as NodeId {
            true => Config::cluster(id, self.initial.clone()),
            false => Config::joiner(id),
        };
        let seed = self.rng.next();
        let cfg = Config {
            seed,
            pre_vote: self.rng.next() & 1 == 0,
            // The state machine's snapshot is a few bytes: chunks of 3 or 5
            // make it travel in pieces, 0 in one, and replicas differ.
            snapshot_chunk: [0, 3, 5][(seed >> 33) as usize % 3],
            ..base
        };
        let node = Node::new(cfg, storage).expect("a configured node, and FileStorage::load cannot fail");
        let r = &mut self.replicas[i];
        r.damaged = node.recovering();
        r.node = Some(node);
        // The state machine starts empty; a stored snapshot is restored by
        // the node's first tick.
        (r.applied, r.digest, r.seen_commit) = (0, 0, 0);
        Ok(())
    }

    /// The process dies, then the power goes out; optionally a bit of a log
    /// file rots while the replica is down.
    fn crash(&mut self, i: usize, corrupt: bool) {
        let rng = &mut self.rng;
        let r = &mut self.replicas[i];
        r.node = None;
        self.reads.retain(|&(replica, _), _| replica != i);
        r.env.heal();
        r.env.crash(&mut |unsynced| rng.below(unsynced as u64 + 1) as usize);
        if corrupt {
            let logs: Vec<String> = (r.env.list(&self.dir).expect("the directory exists"))
                .into_iter()
                .filter(|n| n.starts_with("raft-"))
                .collect();
            // A replica that ran has a durable log: FileStorage::open syncs it.
            let path = self.dir.join(&logs[rng.below(logs.len() as u64) as usize]);
            let len = r.env.read_all(&path).expect("listed").len() as u64;
            r.env.flip_bit(&path, rng.below(len * 8)).expect("in range");
            r.damaged = true;
            self.report.corruptions += 1;
        }
        r.down_until = self.now + rng.range(self.cfg.faults.downtime);
        self.report.crashes += 1;
    }

    /// A replica returned an error: expected only from an injected I/O fault,
    /// on which the process crashes.
    fn failed(&mut self, i: usize, e: crate::Error) -> Result<(), String> {
        if self.replicas[i].env.injected() == 0 {
            return Err(format!("replica {} failed: {e}", i + 1));
        }
        self.report.io_errors += 1;
        self.crash(i, false);
        Ok(())
    }

    /// Checks what replica `i` did, after any of its steps.
    fn observe(&mut self, i: usize) -> Result<(), String> {
        let r = &mut self.replicas[i];
        let node = r.node.as_ref().expect("observed replicas are up");
        let (id, term, commit) = (node.id(), node.term(), node.commit_index());
        let view = || (node.snapshot_index(), node.log_snapshot().1);
        if (node.role() == NodeState::Leader) && self.check.leader(id, term, &view)? {
            self.report.elections += 1;
            self.report.handovers += u64::from(self.transfer.take() == Some(id));
        }
        if commit > r.seen_commit {
            // Entries a snapshot covers were never in this log to see.
            let log = view();
            let from = r.seen_commit.max(log.0);
            self.check
                .commit(id, term, &log.1[(from - log.0) as usize..(commit - log.0) as usize])?;
            r.seen_commit = commit;
        }
        // With no configuration entry beyond the commit index in its log, the
        // voters a node uses are the ones committed at that index.
        if !node.config_pending() {
            self.check.config_at(id, commit, &node.voters())?;
        }
        if r.damaged & !node.recovering() {
            r.damaged = false;
            self.report.recoveries += 1;
        }
        Ok(())
    }

    /// The replica that leads in the highest term.
    fn newest_leader(&self) -> Option<usize> {
        (self.replicas.iter().enumerate())
            .filter_map(|(i, r)| r.node.as_ref().map(|n| (n, i)))
            .filter(|(n, _)| n.role() == NodeState::Leader)
            .max_by_key(|(n, _)| n.term())
            .map(|(_, i)| i)
    }

    /// The operator asks the leader for one membership change: it adds a
    /// learner, promotes one, removes a voter or drops a learner. A leader
    /// refuses when a change is pending, when a learner has not caught up, or
    /// when it has just lost its leadership; that is normal.
    fn reconfigure(&mut self) -> Result<(), String> {
        let Some(i) = self.newest_leader() else { return Ok(()) };
        let node = self.replicas[i].node.as_ref().expect("a leader is up");
        let (voters, learners) = (node.voters(), node.learners());
        let outside = (1..=self.cfg.replicas).filter(|id| !voters.contains(id) & !learners.contains(id));
        let mut ops: Vec<(Op, NodeId)> = outside.map(|id| (Op::AddLearner, id)).collect();
        ops.extend(
            learners
                .iter()
                .flat_map(|&id| [(Op::AddVoter, id), (Op::RemoveLearner, id)]),
        );
        if voters.len() as u64 > self.fewest_voters() {
            ops.extend(voters.iter().map(|&id| (Op::RemoveVoter, id)));
        }
        if ops.is_empty() {
            return Ok(());
        }
        let (op, id) = ops[self.rng.below(ops.len() as u64) as usize];
        let result = match op {
            Op::AddLearner => node.add_learner(id),
            Op::RemoveLearner => node.remove_learner(id),
            Op::AddVoter => node.add_voter(id).map(|_| ()),
            Op::RemoveVoter => node.remove_voter(id).map(|_| ()),
        };
        match result {
            Err(Error::NotReady | Error::NotLeader(_) | Error::BadConfig(_)) => Ok(()),
            Err(e) => self.failed(i, e),
            Ok(()) => self.observe(i),
        }
    }

    /// The operator asks the leader to hand leadership to another voter. A
    /// leader only refuses for a target that is not a voter or is itself,
    /// which this never asks for, so it takes the request.
    fn hand_over(&mut self) {
        let Some(i) = self.newest_leader() else { return };
        let node = self.replicas[i].node.as_ref().expect("a leader is up");
        let others: Vec<NodeId> = (node.voters().into_iter()).filter(|&v| v != node.id()).collect();
        if others.is_empty() {
            return;
        }
        let target = others[self.rng.below(others.len() as u64) as usize];
        node.transfer_leadership(target).expect("a voter, not itself");
        self.report.transfers += 1;
        self.transfer = Some(target);
    }

    fn propose(&mut self) -> Result<(), String> {
        let Some(i) = self.newest_leader() else { return Ok(()) };
        self.payload += 1;
        let data = self.payload.to_le_bytes().to_vec();
        // A leader that is handing leadership over takes no writes.
        match self.replicas[i].node.as_ref().map(|n| n.propose(data)) {
            Some(Err(e)) if e != Error::NotReady => self.failed(i, e),
            _ => self.observe(i),
        }
    }

    /// A client asks a leader, any leader: a stale one that still believes
    /// it leads must never answer.
    fn read(&mut self) {
        let leaders: Vec<usize> = (0..self.replicas.len())
            .filter(|&i| {
                self.replicas[i]
                    .node
                    .as_ref()
                    .is_some_and(|n| n.role() == NodeState::Leader)
            })
            .collect();
        if leaders.is_empty() {
            return;
        }
        let i = leaders[self.rng.below(leaders.len() as u64) as usize];
        // A leader answers with an id, or with `NotReady` while the empty
        // entry of its term is not committed yet.
        if let Ok(id) = self.replicas[i].node.as_ref().expect("a leader is up").read_index() {
            self.reads.insert((i, id), self.check.top());
        }
    }

    /// Replica `i` answered a read: it must have been asked, an answer must
    /// include everything committed when it was asked (linearizability), and
    /// the replica must have applied up to it.
    fn answered(&mut self, i: usize, read: &ReadState) -> Result<(), String> {
        let id = i + 1;
        let floor = (self.reads.remove(&(i, read.id)))
            .ok_or_else(|| format!("replica {id} answered read {} that it was never asked", read.id))?;
        let Some(index) = read.index else {
            self.report.reads_failed += 1;
            return Ok(());
        };
        if index < floor {
            return Err(format!(
                "stale read: replica {id} served a read at index {index}, but {floor} was committed when it was asked"
            ));
        }
        if self.replicas[i].applied < index {
            return Err(format!(
                "replica {id} served a read at index {index} before applying it"
            ));
        }
        self.report.reads_served += 1;
        Ok(())
    }

    fn send(&mut self, messages: Vec<Message>) {
        let f = &self.cfg.faults;
        for m in messages {
            self.report.snapshots_sent += (m.msg_type == MsgType::InstallSnapshot) as u64;
            let faulty = self.now < self.cfg.ticks;
            if faulty & self.rng.chance(f.drop) {
                self.report.dropped += 1;
                continue;
            }
            let copies = 1 + (faulty & self.rng.chance(f.duplicate)) as usize;
            for _ in 0..copies {
                let at = self.now + self.rng.range((1, f.max_delay));
                self.sent += 1;
                self.queue.insert((at, self.sent), m.clone());
            }
        }
    }

    fn cut(&self, a: NodeId, b: NodeId) -> bool {
        (self.partition.as_ref()).is_some_and(|(_, side)| side[a as usize - 1] != side[b as usize - 1])
    }

    fn deliver(&mut self) -> Result<(), String> {
        while self.queue.first_key_value().is_some_and(|(&(at, _), _)| at <= self.now) {
            let (_, m) = self.queue.pop_first().expect("checked above");
            let to = m.to as usize - 1;
            let res = match (&self.replicas[to].node, self.cut(m.from, m.to)) {
                (Some(node), false) => node.step(m),
                _ => {
                    self.report.dropped += 1;
                    continue;
                }
            };
            self.report.delivered += 1;
            match res {
                Ok(replies) => {
                    self.observe(to)?;
                    self.send(replies);
                }
                Err(e) => self.failed(to, e)?,
            }
        }
        Ok(())
    }

    /// After healing: every replica up, one leader, and the voters of its
    /// configuration caught up, with identical logs (past the newest
    /// snapshot), commit indices and state machines. Servers that are not
    /// voters, such as the removed ones, are not expected to.
    fn converged(&mut self) -> Result<(), String> {
        let up: Vec<&Node> = self.replicas.iter().filter_map(|r| r.node.as_ref()).collect();
        let leaders = up.iter().filter(|n| n.role() == NodeState::Leader).count();
        let leader = up.iter().find(|n| n.role() == NodeState::Leader);
        let voters = leader.map_or_else(Vec::new, |n| n.voters());
        // A leader that is not among its own voters has not stepped down.
        let leads_itself = leader.is_some_and(|n| voters.contains(&n.id()));
        let members: Vec<usize> = (0..self.replicas.len())
            .filter(|&i| voters.contains(&(i as NodeId + 1)))
            .collect();
        let nodes: Vec<&Node> = members.iter().filter_map(|&i| self.replicas[i].node.as_ref()).collect();
        let logs: Vec<LogView> = nodes.iter().map(|n| (n.snapshot_index(), n.log_snapshot().1)).collect();
        let commits: Vec<Index> = nodes.iter().map(|n| n.commit_index()).collect();
        let recovering = nodes.iter().filter(|n| n.recovering()).count();
        let machines: Vec<(Index, u64)> = members
            .iter()
            .map(|&i| (self.replicas[i].applied, self.replicas[i].digest))
            .collect();
        let floor = logs.iter().map(|l| l.0).max().unwrap_or(0);
        let lasts: Vec<Index> = logs.iter().map(|l| l.0 + l.1.len() as Index).collect();
        let ok = (up.len() == self.replicas.len())
            & (leaders == 1)
            & leads_itself
            & (recovering == 0)
            & lasts.windows(2).all(|w| w[0] == w[1])
            & logs.windows(2).all(|w| after(&w[0], floor) == after(&w[1], floor))
            & commits.windows(2).all(|w| w[0] == w[1])
            & machines.windows(2).all(|w| w[0] == w[1]);
        if !ok {
            let each: Vec<String> = (up.iter())
                .map(|n| {
                    let (role, recovering) = (n.role(), n.recovering());
                    format!(
                        "{}: {role:?} term {} voters {:?} commit {} recovering {recovering}",
                        n.id(),
                        n.term(),
                        n.voters(),
                        n.commit_index()
                    )
                })
                .collect();
            return Err(format!(
                "no convergence after healing: {} of {} up, {leaders} leaders, voters {voters:?}, \
                 {recovering} recovering, last indices {lasts:?}, commit indices {commits:?}, \
                 state machines {machines:x?}; replicas: {}",
                up.len(),
                self.replicas.len(),
                each.join("; "),
            ));
        }
        self.report.committed = commits[0];
        self.report.reconfigs = self.check.configs.len() as u64 - 1;
        Ok(())
    }
}

/// What the operator asks of a leader.
#[derive(Clone, Copy)]
enum Op {
    AddLearner,
    AddVoter,
    RemoveVoter,
    RemoveLearner,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quick(replicas: u64) -> SimConfig {
        SimConfig {
            replicas,
            voters: 0,
            ticks: 600,
            heal_ticks: 400,
            faults: Faults {
                crash: 5_000,
                ..Faults::default()
            },
        }
    }

    #[test]
    fn seeds_hold_every_property_under_faults() {
        let mut total = Report::default();
        for seed in 0..12 {
            for replicas in [3, 5] {
                let r = run(seed, &quick(replicas)).unwrap();
                assert!(r.committed > 0, "{r}");
                total.add(&r);
            }
        }
        // The faults really happened.
        assert!(total.crashes > 50, "{total}");
        assert!(total.corruptions > 5, "{total}");
        assert!(total.reads_served > 100, "{total}");
        assert!(total.reads_failed > 0, "{total}");
        assert!(
            total.snapshots > 100 && total.snapshots_sent > 10 && total.restores > 10,
            "{total}"
        );
        assert!(total.recoveries > 0, "{total}");
        assert!(total.io_errors > 0, "{total}");
        assert!(total.partitions > 0, "{total}");
        assert!(total.dropped > 0, "{total}");
    }

    #[test]
    fn runs_replay_exactly() {
        let cfg = quick(3);
        assert_eq!(run(7, &cfg), run(7, &cfg));
        assert_ne!(run(7, &cfg), run(8, &cfg));
        let shown = run(7, &cfg).unwrap().to_string();
        assert!(shown.starts_with("seed 7: committed "), "{shown}");
    }

    #[test]
    fn single_replica_and_no_faults() {
        let cfg = SimConfig {
            replicas: 1,
            voters: 0,
            ticks: 0,
            heal_ticks: 200,
            faults: Faults::default(),
        };
        let r = run(1, &cfg).unwrap();
        assert!(r.committed > 0 && r.crashes == 0);
        assert_eq!(SimConfig::default().replicas, 5);
    }

    #[test]
    fn rng_bounds() {
        let mut r = Rng(1);
        assert_eq!(r.below(0), 0);
        assert!((0..1000).all(|_| (3..=5).contains(&r.range((3, 5)))));
        assert_eq!(r.range((4, 4)), 4);
        assert!(!r.chance(0) & r.chance(1_000_000));
    }

    fn e(index: Index, term: Term) -> LogEntry {
        LogEntry::new(index, term, vec![index as u8, term as u8])
    }

    #[test]
    fn checker_catches_violations() {
        let mut c = Checker::default();
        let empty = || (0, Vec::new());
        assert_eq!(c.leader(1, 1, &empty), Ok(true));
        assert_eq!(c.leader(1, 1, &empty), Ok(false));
        assert!(c.leader(2, 1, &empty).unwrap_err().contains("two leaders in term 1"));
        c.commit(1, 2, &[e(1, 1), e(2, 2)]).unwrap();
        c.commit(2, 1, &[e(1, 1)]).unwrap();
        assert_eq!(c.committed[&1].1, 1, "lowest term kept");
        assert!(c.commit(3, 3, &[e(2, 3)]).unwrap_err().contains("different entry 2"));
        // Entry 2 was seen committed in term 2: a term-2 leader need not have it.
        assert_eq!(c.leader(3, 2, &|| (0, vec![e(1, 1)])), Ok(true));
        let lacking = c.leader(3, 3, &|| (0, vec![e(1, 1)])).unwrap_err();
        assert!(lacking.contains("lacks committed entry 2"), "{lacking}");
        // A leader whose snapshot covers the entries is not asked for them
        // (the states are compared instead), but must have what follows.
        assert_eq!(c.leader(3, 4, &|| (2, vec![])), Ok(true));
        c.commit(1, 1, &[e(3, 1)]).unwrap();
        let lacking = c.leader(3, 5, &|| (2, vec![e(3, 2)])).unwrap_err();
        assert!(lacking.contains("lacks committed entry 3"), "{lacking}");
        assert_eq!(c.leader(3, 6, &|| (2, vec![e(3, 1)])), Ok(true));
        // Committed configurations differ by one server, in either order.
        let mut k = Checker::new(vec![1, 2, 3]);
        k.config(5, vec![1, 2, 3, 4]).unwrap();
        k.config(9, vec![1, 3, 4]).unwrap();
        k.config(7, vec![1, 2, 3, 4, 5]).unwrap_err();
        let two = k.config(3, vec![1, 2, 3, 4, 5]).unwrap_err();
        assert!(
            two.contains("configurations 0 and 3 differ by 2 servers, not one"),
            "{two}"
        );
        assert_eq!(k.configs.len(), 3);
        // ... also when they come with the entries a replica reports.
        let entry = LogEntry::config(12, 1, &[1, 2]);
        let by_three = k.commit(1, 1, &[entry]).unwrap_err();
        assert!(by_three.contains("differ by"), "{by_three}");
        // A node's voters must be those committed at its index; none at all
        // is fine before the first entry, for a node with no configuration.
        let at = |c: &Checker, index, voters: &[NodeId]| c.config_at(1, index, voters);
        assert_eq!(at(&k, 0, &[1, 2, 3]), Ok(()));
        assert_eq!(at(&k, 4, &[]), Ok(()));
        assert_eq!(at(&k, 6, &[1, 2, 3, 4]), Ok(()));
        assert_eq!(at(&k, 20, &[1, 3, 4]), Ok(()));
        let wrong = at(&k, 6, &[1, 2, 3]).unwrap_err();
        assert!(
            wrong.contains("replica 1 uses voters [1, 2, 3] at index 6, but [1, 2, 3, 4] was committed"),
            "{wrong}"
        );
        assert!(at(&k, 6, &[]).is_err());
        // States must agree at every index.
        c.state(1, 5, 0xabc).unwrap();
        c.state(2, 5, 0xabc).unwrap();
        let diverged = c.state(3, 5, 0xdef).unwrap_err();
        assert!(
            diverged.contains("replica 3 has state 0000000000000def at index 5"),
            "{diverged}"
        );
        c.apply(1, 1, &e(1, 1)).unwrap();
        assert!(c.apply(1, 2, &e(1, 1)).is_err());
        assert!(c.apply(1, 2, &e(2, 9)).is_err());
        assert!(c.apply(1, 3, &e(3, 3)).is_err());
    }

    #[test]
    fn log_matching_catches_divergence() {
        let a = vec![e(1, 1), e(2, 1), e(3, 2)];
        let mut b = a.clone();
        b[0].data = b"other".to_vec();
        let whole = |entries: Vec<LogEntry>| (0, entries);
        assert!(log_matching(&[whole(a.clone()), whole(a[..2].to_vec()), whole(vec![e(1, 1), e(2, 3)])]).is_ok());
        assert!(log_matching(&[whole(a.clone()), whole(vec![])]).is_ok());
        assert!(log_matching(&[whole(a.clone()), whole(b.clone())])
            .unwrap_err()
            .contains("term 2 at index 3"));
        // Logs compare on the part both still have: the one that starts
        // later has dropped the divergence below its base...
        assert!(log_matching(&[whole(b.clone()), (1, a[1..].to_vec())]).is_ok());
        assert!(log_matching(&[(2, a[2..].to_vec()), whole(b.clone())]).is_ok());
        // ... but not one above it.
        let mut c = a.clone();
        c[1].data = b"other".to_vec();
        let err = log_matching(&[whole(a.clone()), (1, c[1..].to_vec())]).unwrap_err();
        assert!(err.contains("term 2 at index 3"), "{err}");
        // A log that ends before the other starts has nothing to compare.
        assert!(log_matching(&[whole(vec![e(1, 1)]), (5, vec![e(6, 9)])]).is_ok());
    }

    fn started(cfg: SimConfig) -> Sim {
        let mut sim = Sim::new(3, cfg);
        sim.tick().unwrap();
        sim
    }

    #[test]
    fn a_replica_that_cannot_restart_is_reported() {
        let mut sim = started(quick(3));
        sim.crash(0, false);
        let env = sim.replicas[0].env.clone();
        let state = sim.dir.join("raft.state");
        // One bit in each copy of the state file.
        env.flip_bit(&state, 8 * 10).unwrap();
        env.flip_bit(&state, 8 * 50).unwrap();
        sim.replicas[0].down_until = 0;
        let err = sim.tick().unwrap_err();
        assert!(err.starts_with("replica 1 cannot restart: "), "{err}");
    }

    #[test]
    fn replica_errors_without_an_injected_fault_are_violations() {
        let mut sim = started(quick(3));
        let bad = Message::append_entries(2, 1, 9, 0, 0, vec![e(5, 9)], 0);
        sim.queue.insert((sim.now, 0), bad);
        let err = sim.tick().unwrap_err();
        assert!(err.starts_with("replica 1 failed: "), "{err}");
        // From `tick` and `propose` too.
        let mut sim = started(quick(1));
        let env = sim.replicas[0].env.clone();
        env.fail_after(0);
        sim.replicas[0].env = MemEnv::new();
        // Its first campaign writes the vote.
        let err = (0..100).find_map(|_| sim.tick().err()).unwrap();
        assert!(err.starts_with("replica 1 failed: "), "{err}");
        let mut sim = started(quick(1));
        while sim.replicas[0].node.as_ref().unwrap().role() != NodeState::Leader {
            sim.tick().unwrap();
        }
        let env = sim.replicas[0].env.clone();
        env.fail_after(0);
        sim.replicas[0].env = MemEnv::new();
        assert!(sim.propose().unwrap_err().starts_with("replica 1 failed: "));
        // The same, reached from a tick that proposes.
        let mut sim = started(quick(1));
        while sim.replicas[0].node.as_ref().unwrap().role() != NodeState::Leader {
            sim.tick().unwrap();
        }
        let env = sim.replicas[0].env.clone();
        env.fail_after(0);
        sim.replicas[0].env = MemEnv::new();
        let err = (0..200).find_map(|_| sim.tick().err()).unwrap();
        assert!(err.starts_with("replica 1 failed: "), "{err}");
    }

    /// Breaks each safety property on purpose, as a buggy node would, and
    /// checks that every path that watches a replica reports it.
    #[test]
    fn oracle_violations_stop_the_run() {
        let other = || LogEntry::new(1, 1, b"other".to_vec());
        let first_error = |sim: &mut Sim| (0..200).find_map(|_| sim.tick().err()).unwrap();
        // Two leaders in one term, seen on a tick.
        let mut sim = started(quick(1));
        sim.check.leaders.insert(1, 99);
        assert!(first_error(&mut sim).contains("two leaders in term 1: 99 and 1"));
        // ... and when a proposal is made.
        let mut sim = started(quick(1));
        let term = {
            let node = sim.replicas[0].node.as_ref().unwrap();
            while node.role() != NodeState::Leader {
                node.tick().unwrap();
            }
            node.term()
        };
        sim.check.leaders.insert(term, 99);
        assert!(sim.propose().unwrap_err().contains("two leaders"));
        // A different entry committed at an index, seen on a tick.
        let mut sim = started(quick(1));
        sim.check.committed.insert(1, (other(), 99));
        assert!(first_error(&mut sim).contains("committed a different entry 1"));
        // ... and on a delivery.
        let mut sim = started(quick(3));
        sim.check.committed.insert(1, (other(), 99));
        let m = Message::append_entries(2, 1, 1, 0, 0, vec![e(1, 1)], 1);
        sim.queue.insert((sim.now, 0), m);
        assert!(sim.tick().unwrap_err().contains("committed a different entry 1"));
        // An entry applied out of order.
        let mut sim = started(quick(1));
        sim.replicas[0].applied = 100;
        assert!(first_error(&mut sim).contains("applied entry 1 as its entry 101"));
        // Two logs that agree on a term but not on what came before.
        let mut sim = started(quick(2));
        let a = Message::append_entries(2, 1, 1, 0, 0, vec![e(1, 1)], 0);
        let mut b = Message::append_entries(1, 2, 1, 0, 0, vec![e(1, 1)], 0);
        b.entries[0].data = b"other".to_vec();
        sim.replicas[0].node.as_ref().unwrap().step(a).unwrap();
        sim.replicas[1].node.as_ref().unwrap().step(b).unwrap();
        sim.now = 32;
        assert!(sim
            .tick()
            .unwrap_err()
            .contains("logs share term 1 at index 1 but differ up to it"));
    }

    #[test]
    fn reads_are_checked_against_what_was_committed() {
        let mut sim = started(quick(1));
        let read = |id, index| ReadState { id, index };
        let never = sim.answered(0, &read(9, Some(1))).unwrap_err();
        assert!(never.contains("read 9 that it was never asked"), "{never}");
        // Committed up to 10 when asked: an answer at 3 is stale.
        sim.reads.insert((0, 1), 10);
        let stale = sim.answered(0, &read(1, Some(3))).unwrap_err();
        assert!(
            stale.contains("stale read: replica 1 served a read at index 3, but 10"),
            "{stale}"
        );
        // An answer past what the replica applied is wrong too.
        sim.reads.insert((0, 2), 0);
        let early = sim.answered(0, &read(2, Some(4))).unwrap_err();
        assert!(early.contains("before applying it"), "{early}");
        // Right answers, and a failure that is allowed.
        sim.replicas[0].applied = 4;
        sim.reads.insert((0, 3), 4);
        sim.answered(0, &read(3, Some(4))).unwrap();
        sim.reads.insert((0, 4), 99);
        sim.answered(0, &read(4, None)).unwrap();
        assert_eq!((sim.report.reads_served, sim.report.reads_failed), (1, 1));
        assert!(sim.reads.is_empty());
        // A read the simulator never asked for is released by a tick.
        let mut sim = started(SimConfig {
            faults: Faults {
                propose: 0,
                read: 0,
                ..quick(1).faults
            },
            ..quick(1)
        });
        let node = sim.replicas[0].node.as_ref().unwrap();
        while node.role() != NodeState::Leader {
            node.tick().unwrap();
        }
        assert_eq!(node.read_index(), Err(Error::NotReady));
        node.tick().unwrap();
        node.read_index().unwrap();
        let err = sim.tick().unwrap_err();
        assert!(err.contains("that it was never asked"), "{err}");
    }

    /// A single replica that leads, driven by its node directly so that the
    /// simulator has seen nothing of it, and that the simulator leaves alone.
    fn idle_leader(faults: Faults) -> Sim {
        let sim = started(SimConfig {
            faults: Faults {
                propose: 0,
                read: 0,
                crash: 0,
                io_error: 0,
                ..faults
            },
            ..quick(1)
        });
        let node = sim.replicas[0].node.as_ref().unwrap();
        while node.role() != NodeState::Leader {
            node.tick().unwrap();
        }
        sim
    }

    /// An [`idle_leader`] with one entry committed and handed out by its node.
    fn leader_with_an_unseen_entry(faults: Faults) -> Sim {
        let sim = idle_leader(faults);
        let node = sim.replicas[0].node.as_ref().unwrap();
        node.propose(b"a".to_vec()).unwrap();
        // Its own empty entry, and this one.
        assert_eq!(node.tick().unwrap().committed.len(), 2);
        sim
    }

    #[test]
    fn snapshot_errors_are_violations() {
        let snapshot = |data: &[u8]| Snapshot {
            index: 1,
            term: 1,
            voters: vec![1, 2, 3],
            data: data.to_vec(),
        };
        let mut sim = started(quick(1));
        let err = sim.restore(0, &snapshot(&[1, 2, 3])).unwrap_err();
        assert!(err.contains("replica 1 got a snapshot with 3 bytes of state"), "{err}");
        // ... also when it is a stored snapshot restored by the first tick
        // after a restart.
        let mut sim = leader_with_an_unseen_entry(Faults::default());
        sim.replicas[0]
            .node
            .as_ref()
            .unwrap()
            .compact(1, vec![1, 2, 3])
            .unwrap();
        sim.crash(0, false);
        sim.replicas[0].down_until = 0;
        let err = (0..5).find_map(|_| sim.tick().err()).unwrap();
        assert!(err.contains("3 bytes of state"), "{err}");
        // A replica that cannot store its snapshot fails the run, from
        // `take_snapshot` and from the tick that takes one.
        let faults = Faults {
            snapshot: 1_000_000,
            ..Faults::default()
        };
        let mut sim = leader_with_an_unseen_entry(faults);
        sim.replicas[0].applied = 1;
        sim.replicas[0].env.fail_after(0);
        sim.replicas[0].env = MemEnv::new();
        let err = sim.tick().unwrap_err();
        assert!(err.starts_with("replica 1 failed: "), "{err}");
        // Replicas with different state machines at one index: from the
        // entries a tick applies, and from a snapshot restored.
        let mut sim = idle_leader(Faults::default());
        sim.replicas[0].node.as_ref().unwrap().propose(b"a".to_vec()).unwrap();
        sim.check.states.insert(1, 0xbad);
        let err = sim.tick().unwrap_err();
        assert!(
            err.contains("replica 1 has state") && err.contains("at index 1, others have 0000000000000bad"),
            "{err}"
        );
        let mut sim = started(quick(1));
        sim.check.states.insert(1, 5);
        let err = sim.restore(0, &snapshot(&6u64.to_le_bytes())).unwrap_err();
        assert!(err.contains("others have 0000000000000005"), "{err}");
        // A replica that is already at its snapshot has nothing to take.
        let mut sim = leader_with_an_unseen_entry(Faults::default());
        assert_eq!(sim.take_snapshot(0), Ok(()));
        assert_eq!(sim.report.snapshots, 0);
    }

    #[test]
    fn convergence_failures_are_reported() {
        let mut sim = started(quick(3));
        sim.crash(1, false);
        let err = sim.converged().unwrap_err();
        assert!(err.contains("2 of 3 up, 0 leaders"), "{err}");
        let err = run(
            5,
            &SimConfig {
                heal_ticks: 0,
                ..quick(3)
            },
        )
        .unwrap_err();
        assert!(err.starts_with("seed 5, tick 600: no convergence"), "{err}");
    }

    /// A cluster of 5 servers with 4 voters at the start, and no faults but
    /// the operator's.
    fn operated(membership: u32) -> Sim {
        started(SimConfig {
            replicas: 5,
            voters: 4,
            ticks: 5_000,
            heal_ticks: 100,
            faults: Faults {
                drop: 0,
                duplicate: 0,
                partition: 0,
                crash: 0,
                io_error: 0,
                propose: 0,
                read: 0,
                snapshot: 0,
                membership,
                ..Faults::default()
            },
        })
    }

    #[test]
    fn the_operator_changes_the_cluster_and_the_voters_are_counted() {
        // Some servers wait to be added; the operator can be switched off.
        let cfg = |voters, membership| SimConfig {
            replicas: 5,
            voters,
            ticks: 600,
            heal_ticks: 400,
            faults: Faults {
                membership,
                ..quick(5).faults
            },
        };
        let idle = run(4, &cfg(4, 0)).unwrap();
        assert!(idle.committed > 0 && idle.reconfigs == 0);
        let busy = run(4, &cfg(4, 100_000)).unwrap();
        assert!(busy.reconfigs > 0, "{busy}");
        assert!(busy.to_string().contains("membership changes"), "{busy}");
        let mut sum = Report::default();
        sum.add(&busy);
        sum.add(&busy);
        assert_eq!(sum.reconfigs, 2 * busy.reconfigs);
        // The seed picks how many start as voters when none is asked for.
        let sizes: Vec<usize> = (0..20).map(|seed| Sim::new(seed, cfg(0, 0)).initial.len()).collect();
        assert!(sizes.iter().all(|n| (3..=5).contains(n)) && sizes.iter().any(|&n| n != sizes[0]));
        assert_eq!(
            Sim::new(1, cfg(9, 0)).initial.len(),
            5,
            "no more than there are servers"
        );
    }

    #[test]
    fn leadership_is_handed_over_in_the_simulator() {
        let cfg = |transfer| SimConfig {
            replicas: 5,
            voters: 5,
            ticks: 600,
            heal_ticks: 400,
            faults: Faults {
                drop: 0,
                duplicate: 0,
                partition: 0,
                crash: 0,
                io_error: 0,
                membership: 0,
                transfer,
                ..Faults::default()
            },
        };
        let none = run(2, &cfg(0)).unwrap();
        assert_eq!((none.transfers, none.handovers), (0, 0));
        let r = run(2, &cfg(30_000)).unwrap();
        assert!(r.transfers > 5 && r.handovers > 5 && r.handovers <= r.transfers, "{r}");
        assert!(r.to_string().contains(" leadership transfers "), "{r}");
        let mut sum = Report::default();
        sum.add(&r);
        sum.add(&r);
        assert_eq!((sum.transfers, sum.handovers), (2 * r.transfers, 2 * r.handovers));
        // Nothing to ask while there is no leader, and nobody to hand over to
        // in a cluster of one.
        let mut sim = started(quick(3));
        sim.hand_over();
        assert_eq!(sim.report.transfers, 0);
        let mut sim = idle_leader(Faults::default());
        sim.hand_over();
        assert_eq!(sim.report.transfers, 0);
    }

    #[test]
    fn a_failing_leader_during_a_membership_change_is_a_violation() {
        let mut sim = operated(1_000_000);
        // Wait for a leader that has committed its own empty entry.
        let leader = (0..200)
            .find_map(|_| {
                sim.tick().unwrap();
                sim.newest_leader().filter(|&i| {
                    let n = sim.replicas[i].node.as_ref().unwrap();
                    n.commit_index() > 0
                })
            })
            .unwrap();
        // Its disk fails, without the simulator having injected it.
        sim.replicas[leader].env.fail_after(0);
        sim.replicas[leader].env = MemEnv::new();
        let err = (0..200).find_map(|_| sim.reconfigure().err()).unwrap();
        assert!(err.starts_with(&format!("replica {} failed: ", leader + 1)), "{err}");
        // The same from a tick, in which the operator acts every time.
        let err = (0..200).find_map(|_| sim.tick().err()).unwrap();
        assert!(err.contains(" failed: "), "{err}");
    }

    #[test]
    fn a_node_that_disagrees_about_the_configuration_is_a_violation() {
        // The checker was told the committed configuration is another one.
        let mut sim = started(quick(3));
        sim.check.configs.insert(0, vec![9]);
        let err = sim.observe(0).unwrap_err();
        assert!(
            err.contains("replica 1 uses voters [1, 2, 3] at index 0, but [9] was committed"),
            "{err}"
        );
        // The same for the configuration a snapshot brings.
        let snapshot = Snapshot {
            index: 1,
            term: 1,
            voters: vec![1, 2, 3],
            data: 7u64.to_le_bytes().to_vec(),
        };
        let err = sim.restore(0, &snapshot).unwrap_err();
        assert!(
            err.contains("uses voters [1, 2, 3] at index 1, but [9] was committed"),
            "{err}"
        );
    }
}
