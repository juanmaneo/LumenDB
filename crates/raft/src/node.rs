//! Deterministic Raft node (Ongaro & Ousterhout): leader election, log
//! replication, majority-quorum commit. Driven by `tick()` (logical time) and
//! `step(msg)`; every event advances a Lamport clock and every message
//! carries it, so nothing depends on the wall clock.
//!
//! Durability: term, vote and entries are written to [`Storage`] *before* the
//! in-memory state changes and before any message that depends on them is
//! returned, so a node that crashes and restarts never votes twice in a term
//! nor forgets an entry it acknowledged.
//!
//! Pre-vote (Raft thesis §9.6): a node whose election timer fires first asks
//! its peers whether they would vote for it, without changing its term. Only
//! with a majority of promises does it campaign. A node cut off from the
//! cluster therefore never inflates its term, and does not depose a healthy
//! leader when it comes back. A peer refuses while it hears from a leader, so
//! a node that merely lost contact cannot win either.
//!
//! Protocol-aware recovery: if storage reports the log damaged
//! ([`DurableState::recovering`]), entries this node acknowledged may be gone,
//! and some of them may have been committed with its help. Such a node never
//! grants a vote and never campaigns, so every election quorum still overlaps
//! every commit quorum in an intact node, and an elected leader holds every
//! committed entry. The node leaves this state once an AppendEntries from the
//! leader of its current term has left it with that leader's whole log, and
//! the exit is made durable first. A single-node cluster has no one to copy
//! from, so a damaged single node stays stuck: that is the correct fail-stop.
//!
//! ReadIndex (Raft thesis §6.4): [`Node::read_index`] gives a linearizable
//! read without writing to the log. The leader notes its commit index, then
//! confirms it is still the leader by getting one AppendEntries of a later
//! round acknowledged by a majority. When the state machine has applied up to
//! that index, `tick()` releases the read, which may then be served from local
//! state. A leader cut off from the majority never confirms, so it can never
//! serve a stale read. A new leader has no entry of its own term committed
//! yet, and then `read_index` asks the caller to retry shortly.
//!
//! Snapshots and log compaction: the application owns the state machine, so
//! it decides when to snapshot. [`Node::compact`] takes the serialized state
//! machine as of an applied index, stores it durably and drops the log up to
//! there. A leader whose follower needs entries it has dropped sends the
//! snapshot instead (`InstallSnapshot`, in one message). The follower stores
//! it, and `tick()` hands it to the application as [`TickOutcome::snapshot`]
//! to restore the state machine from, before any entries after it. After a
//! restart the first tick does the same with the stored snapshot.
//!
//! Membership changes (Raft thesis section 4.1, one server at a time): the
//! cluster configuration is a voter set held in [`crate::EntryKind::Config`] log
//! entries. A configuration is in effect as soon as its entry is in the log,
//! committed or not, and a truncated entry takes it back to the one before.
//! The leader changes the voter set by one server per entry
//! ([`Node::add_voter`], [`Node::remove_voter`]), so the old and the new
//! majorities always overlap. It refuses a change while an earlier one is not
//! committed, and before it has committed an entry of its own term: without
//! that, two leaders in different terms could pick different configurations
//! on the same log prefix. A new server first joins as a learner
//! ([`Node::add_learner`]): it gets the log but does not vote or count toward
//! any quorum, and [`Node::add_voter`] waits until it has caught up, so a
//! slow newcomer cannot stall commits. A node that is not a voter never votes
//! and never campaigns, and as long as a node hears from a leader, vote
//! traffic from a server outside the voter set is ignored, so a removed server
//! cannot depose it (with pre-vote on, which is the default, it cannot disturb
//! a cluster that has a leader either way). Without a leader the traffic is
//! answered: a server that has not heard that another was added may need that
//! one to win. Granting a vote needs no membership, only the candidate's own
//! voter set decides whether it counts. A server whose removal is still
//! uncommitted keeps campaigning, see `is_member`. A leader that
//! commits its own removal steps down. Until the cluster has a configuration
//! entry the configured voters apply ([`Config::voters`]); an empty list makes
//! a node that waits to be added ([`Config::joiner`]).
//!
//! A new leader appends an empty entry of its term at once (Raft thesis
//! section 6.4). Entries of earlier terms commit only together with an entry
//! of the leader's own term, so without it they could stay uncommitted, and
//! stale entries on a follower unreplaced, until a client happened to write.
//! Applications must ignore entries with empty data.
//!
//! Committed entries are handed out by `tick()` in index order, exactly once
//! per process lifetime (after a restart they are replayed from just after the
//! snapshot, or from index 1 without one, as the commit index is re-learned).

use crate::clock::LamportClock;
use crate::error::{Error, LogError, Result};
use crate::log::{Log, LogEntry};
use crate::message::{Message, MsgType};
use crate::quorum::{is_majority, quorum};
use crate::storage::{DurableState, Snapshot, Storage};
use crate::{Index, NodeId, Term};
use parking_lot::Mutex;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// Maximum entries shipped in one AppendEntries.
pub const MAX_BATCH: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeState {
    Follower,
    /// Collecting pre-vote promises; the term has not changed yet.
    PreCandidate,
    Candidate,
    Leader,
}

#[derive(Clone, Debug, Default)]
pub struct TickOutcome {
    /// Messages to deliver to peers.
    pub messages: Vec<Message>,
    /// A snapshot to restore the state machine from, before applying
    /// `committed`, which then follows it: set after a restart and when the
    /// leader sent a snapshot. It replaces the state machine's state.
    pub snapshot: Option<Arc<Snapshot>>,
    /// Newly committed entries, to apply to the state machine in order.
    pub committed: Vec<LogEntry>,
    /// Reads that are decided, see [`Node::read_index`].
    pub reads: Vec<ReadState>,
}

/// The end of a [`Node::read_index`] request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadState {
    /// The id `read_index` returned.
    pub id: u64,
    /// `Some(i)`: the leader was confirmed with commit index `i`, and every
    /// entry up to `i` has been handed out by `tick` (`TickOutcome::committed`
    /// of this or an earlier tick). Once the caller has applied them, a read
    /// of the state machine is linearizable. `None`: leadership was lost
    /// before it was confirmed; retry on the current leader.
    pub index: Option<Index>,
}

/// A read waiting for a majority to confirm the leader.
struct PendingRead {
    id: u64,
    index: Index,
    /// Round of the AppendEntries that confirms it (`None`: not yet sent).
    round: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub id: NodeId,
    /// The voters until the log holds a configuration entry (or a snapshot
    /// that knows one). Empty for a node that waits to be added to a cluster.
    pub voters: Vec<NodeId>,
    pub election_timeout_min: u64,
    pub election_timeout_max: u64,
    pub heartbeat_interval: u64,
    pub seed: u64,
    /// Ask for pre-votes before campaigning.
    pub pre_vote: bool,
}

impl Config {
    pub fn single(id: NodeId) -> Self {
        Config {
            id,
            voters: vec![id],
            election_timeout_min: 5,
            election_timeout_max: 10,
            heartbeat_interval: 2,
            seed: 0x1234_5678_9abc_def0,
            pre_vote: true,
        }
    }

    /// A node that is not in any cluster yet: it votes for nobody and never
    /// campaigns, and learns the configuration from the leader that adds it
    /// ([`Node::add_learner`], then [`Node::add_voter`]).
    pub fn joiner(id: NodeId) -> Self {
        Config::cluster(id, Vec::new())
    }

    pub fn cluster(id: NodeId, voters: Vec<NodeId>) -> Self {
        Config {
            id,
            voters,
            election_timeout_min: 10,
            election_timeout_max: 20,
            heartbeat_interval: 3,
            seed: 0x0fed_cba9_8765_4321,
            pre_vote: true,
        }
    }
}

struct Inner {
    role: NodeState,
    term: Term,
    voted_for: Option<NodeId>,
    leader_id: Option<NodeId>,
    log: Log,
    commit_index: Index,
    last_applied: Index,
    election_elapsed: u64,
    election_timeout: u64,
    heartbeat_elapsed: u64,
    votes: BTreeSet<NodeId>,
    pre_votes: BTreeSet<NodeId>,
    next_index: BTreeMap<NodeId, Index>,
    match_index: BTreeMap<NodeId, Index>,
    rng: u64,
    clock: LamportClock,
    recovering: bool,
    next_read_id: u64,
    /// Last read round sent as leader.
    read_round: u64,
    /// The highest read round each peer acknowledged as leader.
    read_acked: BTreeMap<NodeId, u64>,
    reads: Vec<PendingRead>,
    /// Confirmed reads, released by the next tick.
    reads_ready: Vec<(u64, Index)>,
    /// Reads abandoned because this node stopped being leader.
    reads_failed: Vec<u64>,
    /// The snapshot at the log's base, which a leader sends to a follower
    /// that needs entries below it.
    snapshot: Option<Arc<Snapshot>>,
    /// A snapshot the next tick hands to the application.
    install: Option<Arc<Snapshot>>,
    /// Leader only: servers that get the log without being voters, so that
    /// they can catch up before they are added.
    learners: BTreeSet<NodeId>,
}

pub struct Node {
    cfg: Config,
    /// `cfg.voters`, ascending and deduplicated: the voters until the log
    /// knows a configuration.
    initial: Vec<NodeId>,
    storage: Arc<dyn Storage>,
    state: Mutex<Inner>,
}

/// Randomized election timeout in `[min, max]` (xorshift64*, deterministic).
fn random_timeout(cfg: &Config, rng: &mut u64) -> u64 {
    let mut x = *rng;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    *rng = x;
    let r = x.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 32;
    let span = cfg
        .election_timeout_max
        .saturating_sub(cfg.election_timeout_min)
        .saturating_add(1);
    cfg.election_timeout_min.max(1) + r % span
}

impl Node {
    pub fn new(cfg: Config, storage: Arc<dyn Storage>) -> Result<Self> {
        if !cfg.voters.is_empty() && !cfg.voters.contains(&cfg.id) {
            return Err(Error::NotConfigured);
        }
        let DurableState {
            term,
            voted_for,
            log,
            recovering,
            snapshot,
        } = storage.load()?;
        if log.base_index() != snapshot.as_ref().map_or(0, |s| s.index) {
            return Err(Error::Storage("the log does not start after the snapshot".into()));
        }
        let initial: BTreeSet<NodeId> = cfg.voters.iter().copied().collect();
        let mut rng = (cfg.seed ^ cfg.id) | 1;
        let election_timeout = random_timeout(&cfg, &mut rng);
        Ok(Node {
            initial: initial.into_iter().collect(),
            storage,
            state: Mutex::new(Inner {
                role: NodeState::Follower,
                term,
                voted_for,
                leader_id: None,
                commit_index: log.base_index(),
                last_applied: log.base_index(),
                log,
                election_elapsed: 0,
                election_timeout,
                heartbeat_elapsed: 0,
                votes: BTreeSet::new(),
                pre_votes: BTreeSet::new(),
                next_index: BTreeMap::new(),
                match_index: BTreeMap::new(),
                rng,
                clock: LamportClock::new(),
                recovering,
                next_read_id: 0,
                read_round: 0,
                read_acked: BTreeMap::new(),
                reads: Vec::new(),
                reads_ready: Vec::new(),
                reads_failed: Vec::new(),
                install: snapshot.clone(),
                snapshot,
                learners: BTreeSet::new(),
            }),
            cfg,
        })
    }

    pub fn id(&self) -> NodeId {
        self.cfg.id
    }

    pub fn role(&self) -> NodeState {
        self.state.lock().role
    }

    pub fn term(&self) -> Term {
        self.state.lock().term
    }

    /// Last known leader of the current term.
    pub fn leader(&self) -> Option<NodeId> {
        self.state.lock().leader_id
    }

    pub fn commit_index(&self) -> Index {
        self.state.lock().commit_index
    }

    pub fn logical_time(&self) -> u64 {
        self.state.lock().clock.now()
    }

    /// The log was damaged: no voting or campaigning until caught up.
    pub fn recovering(&self) -> bool {
        self.state.lock().recovering
    }

    /// Index of the last entry the snapshot covers (0: no snapshot).
    pub fn snapshot_index(&self) -> Index {
        self.state.lock().log.base_index()
    }

    /// The voters in effect: the last configuration in the log, committed or
    /// not.
    pub fn voters(&self) -> Vec<NodeId> {
        let s = self.state.lock();
        self.voters_of(&s).to_vec()
    }

    /// Whether the log holds a configuration entry that is not committed yet.
    /// A leader starts no other membership change meanwhile.
    pub fn config_pending(&self) -> bool {
        let s = self.state.lock();
        s.log.config_index() > s.commit_index
    }

    /// The servers this leader replicates to without them voting.
    pub fn learners(&self) -> Vec<NodeId> {
        self.state.lock().learners.iter().copied().collect()
    }

    /// The voters in effect, ascending.
    fn voters_of<'a>(&'a self, s: &'a Inner) -> &'a [NodeId] {
        match s.log.voters() {
            [] => &self.initial,
            voters => voters,
        }
    }

    /// The voters in effect at `index`, which the log must still hold.
    fn voters_at<'a>(&'a self, s: &'a Inner, index: Index) -> &'a [NodeId] {
        match s.log.voters_at(index) {
            [] => &self.initial,
            voters => voters,
        }
    }

    fn is_voter(&self, s: &Inner) -> bool {
        self.voters_of(s).binary_search(&self.cfg.id).is_ok()
    }

    /// Whether `id` takes part in elections: it is a voter, or it is a voter
    /// of the committed configuration and an uncommitted change removes it.
    /// The latter matters: the leader that appended the removal may be gone,
    /// with the entry on the removed server (which has the longest log) and
    /// nowhere else, and the voters that remain cannot win without its vote.
    /// Safe, because a candidate counts the votes it needs in its own latest
    /// configuration, which differs from the committed one by one server. A
    /// removal that is committed ends it.
    fn is_member(&self, s: &Inner, id: NodeId) -> bool {
        let pending = s.log.config_index() > s.commit_index;
        let voter = |voters: &[NodeId]| voters.binary_search(&id).is_ok();
        voter(self.voters_of(s)) | (pending & voter(self.voters_at(s, s.commit_index)))
    }

    /// How many of `votes` are voters in the configuration in effect.
    fn counted(&self, s: &Inner, votes: &BTreeSet<NodeId>) -> usize {
        let voters = self.voters_of(s);
        votes.iter().filter(|v| voters.binary_search(v).is_ok()).count()
    }

    /// The voters other than this node.
    fn others(&self, s: &Inner) -> Vec<NodeId> {
        (self.voters_of(s).iter().copied())
            .filter(|&v| v != self.cfg.id)
            .collect()
    }

    /// Current term and the log: the entries after the snapshot.
    pub fn log_snapshot(&self) -> (Term, Vec<LogEntry>) {
        let s = self.state.lock();
        (s.term, s.log.entries().to_vec())
    }

    /// Snapshots the state machine: `data` is its state after applying every
    /// entry up to `index`, which must be above the current snapshot and not
    /// beyond what [`Node::tick`] has handed out. The snapshot is stored
    /// durably, then the log up to `index` is dropped.
    pub fn compact(&self, index: Index, data: Vec<u8>) -> Result<()> {
        let mut s = self.state.lock();
        if index > s.last_applied {
            return Err(Error::BadSnapshot("index is not applied yet"));
        }
        if index <= s.log.base_index() {
            return Err(Error::BadSnapshot("index is not above the snapshot"));
        }
        let term = s.log.term_at(index).expect("applied entries are in the log");
        let voters = self.voters_at(&s, index).to_vec();
        let snapshot = Arc::new(Snapshot {
            index,
            term,
            voters,
            data,
        });
        self.storage.install_snapshot(snapshot.clone())?;
        s.log
            .install_snapshot(index, term, snapshot.voters.clone())
            .expect("checked to be above the base");
        s.snapshot = Some(snapshot);
        s.clock.tick();
        Ok(())
    }

    /// Appends `data` to the leader's log (durably); it commits once a
    /// majority has it. Returns its index.
    pub fn propose(&self, data: Vec<u8>) -> Result<Index> {
        let mut s = self.state.lock();
        if s.role != NodeState::Leader {
            return Err(Error::NotLeader(s.leader_id));
        }
        let entry = LogEntry::new(s.log.last_index() + 1, s.term, data);
        let batch = std::slice::from_ref(&entry);
        self.storage.append_entries(batch)?;
        s.log.append(batch).expect("a leader appends at its own tail");
        s.clock.tick();
        Ok(entry.index)
    }

    /// Starts replicating the log to `id`, which does not vote or count
    /// toward any quorum. Leader only. Once it has caught up,
    /// [`Node::add_voter`] makes it a voter.
    pub fn add_learner(&self, id: NodeId) -> Result<()> {
        let mut s = self.state.lock();
        if s.role != NodeState::Leader {
            return Err(Error::NotLeader(s.leader_id));
        }
        if id == self.cfg.id {
            return Err(Error::BadConfig("this node is the leader"));
        }
        if self.voters_of(&s).contains(&id) {
            return Err(Error::BadConfig("already a voter"));
        }
        s.learners.insert(id);
        self.sync_targets(&mut s);
        Ok(())
    }

    /// Stops replicating to the learner `id`.
    pub fn remove_learner(&self, id: NodeId) -> Result<()> {
        let mut s = self.state.lock();
        if s.role != NodeState::Leader {
            return Err(Error::NotLeader(s.leader_id));
        }
        if !s.learners.remove(&id) {
            return Err(Error::BadConfig("not a learner"));
        }
        self.sync_targets(&mut s);
        Ok(())
    }

    /// Makes the learner `id` a voter: appends the configuration entry and
    /// returns its index. It takes effect on this leader at once and is
    /// committed by a majority of the new voter set. Leader only; refused
    /// unless `id` is a learner that holds everything committed, while the
    /// leader has committed an entry of its term and no other change is
    /// uncommitted.
    pub fn add_voter(&self, id: NodeId) -> Result<Index> {
        let mut s = self.state.lock();
        self.may_change_config(&mut s)?;
        if self.voters_of(&s).contains(&id) {
            return Err(Error::BadConfig("already a voter"));
        }
        if !s.learners.contains(&id) {
            return Err(Error::BadConfig("not a learner, add it as one first"));
        }
        if s.match_index.get(&id).copied().unwrap_or(0) < s.commit_index {
            return Err(Error::BadConfig("the learner has not caught up"));
        }
        let mut voters = self.voters_of(&s).to_vec();
        voters.push(id);
        voters.sort_unstable();
        let index = self.append_config(&mut s, &voters)?;
        s.learners.remove(&id);
        Ok(index)
    }

    /// Removes the voter `id`, itself included: appends the configuration
    /// entry and returns its index. A leader that removes itself steps down
    /// once the entry is committed. Same conditions as [`Node::add_voter`]
    /// (but `id` is a voter, and not the last one).
    pub fn remove_voter(&self, id: NodeId) -> Result<Index> {
        let mut s = self.state.lock();
        self.may_change_config(&mut s)?;
        let voters = self.voters_of(&s);
        if !voters.contains(&id) {
            return Err(Error::BadConfig("not a voter"));
        }
        if voters.len() == 1 {
            return Err(Error::BadConfig("cannot remove the last voter"));
        }
        let voters: Vec<NodeId> = voters.iter().copied().filter(|&v| v != id).collect();
        self.append_config(&mut s, &voters)
    }

    /// The leader may start a membership change: it has committed an entry of
    /// its own term, and the last change is committed.
    fn may_change_config(&self, s: &mut Inner) -> Result<()> {
        if s.role != NodeState::Leader {
            return Err(Error::NotLeader(s.leader_id));
        }
        self.need_current_term_commit(s)?;
        if s.log.config_index() > s.commit_index {
            return Err(Error::BadConfig("the previous change is not committed yet"));
        }
        Ok(())
    }

    /// Appends the configuration entry `voters` to the leader's log.
    fn append_config(&self, s: &mut Inner, voters: &[NodeId]) -> Result<Index> {
        let entry = LogEntry::config(s.log.last_index() + 1, s.term, voters);
        let batch = std::slice::from_ref(&entry);
        self.storage.append_entries(batch)?;
        s.log.append(batch).expect("a leader appends at its own tail");
        s.clock.tick();
        self.sync_targets(s);
        Ok(entry.index)
    }

    /// Leader: replicate to the servers that need the log. Those are the
    /// voters, the learners, and the voters of the committed configuration:
    /// a server removed by an uncommitted change keeps getting entries until
    /// the change commits, as it may be needed to commit it. Progress of the
    /// ones that stay is kept.
    fn sync_targets(&self, s: &mut Inner) {
        let mut wanted: BTreeSet<NodeId> = (self.voters_of(s).iter())
            .chain(self.voters_at(s, s.commit_index))
            .chain(&s.learners)
            .copied()
            .collect();
        wanted.remove(&self.cfg.id);
        s.next_index.retain(|p, _| wanted.contains(p));
        s.match_index.retain(|p, _| wanted.contains(p));
        s.read_acked.retain(|p, _| wanted.contains(p));
        let next = s.log.last_index() + 1;
        for p in wanted {
            s.next_index.entry(p).or_insert(next);
            s.match_index.entry(p).or_insert(0);
            s.read_acked.entry(p).or_insert(0);
        }
    }

    /// Stops being leader without a term change, because the configuration
    /// that excludes this node is committed.
    fn step_down(s: &mut Inner) {
        s.role = NodeState::Follower;
        s.leader_id = None;
        s.election_elapsed = 0;
        s.learners.clear();
        s.next_index.clear();
        s.match_index.clear();
        s.read_acked.clear();
    }

    /// A leader that has no committed entry of its own term does not know its
    /// commit index is current. It appended one when it was elected, so this
    /// only asks the caller to retry until that has committed.
    fn need_current_term_commit(&self, s: &Inner) -> Result<()> {
        match s.log.term_at(s.commit_index) == Some(s.term) {
            true => Ok(()),
            false => Err(Error::NotReady),
        }
    }

    /// Starts a linearizable read and returns its id; the answer arrives in
    /// [`TickOutcome::reads`] (see [`ReadState`]). Ids are unique within one
    /// process lifetime.
    ///
    /// Leader only. `Err(NotReady)` means the leader has no committed entry
    /// of its own term yet, which it needs to know its commit index is
    /// current; the empty entry it appended when elected is on its way, so
    /// retry after a few ticks.
    pub fn read_index(&self) -> Result<u64> {
        let mut s = self.state.lock();
        if s.role != NodeState::Leader {
            return Err(Error::NotLeader(s.leader_id));
        }
        self.need_current_term_commit(&s)?;
        s.next_read_id += 1;
        s.clock.tick();
        let (id, index) = (s.next_read_id, s.commit_index);
        if self.others(&s).is_empty() {
            s.reads_ready.push((id, index));
        } else {
            s.reads.push(PendingRead { id, index, round: None });
        }
        Ok(id)
    }

    /// A node that is no longer leader will never confirm its pending reads.
    fn fail_unconfirmed_reads(s: &mut Inner) {
        if s.role != NodeState::Leader {
            let ids: Vec<u64> = s.reads.drain(..).map(|r| r.id).collect();
            s.reads_failed.extend(ids);
        }
    }

    /// Moves reads whose round a majority has acknowledged to `reads_ready`.
    fn confirm_reads(&self, s: &mut Inner) {
        let voters = self.voters_of(s);
        let n = voters.len();
        let me = usize::from(voters.contains(&self.cfg.id));
        let acked: Vec<u64> = (voters.iter())
            .filter(|&&v| v != self.cfg.id)
            .map(|v| s.read_acked.get(v).copied().unwrap_or(0))
            .collect();
        let confirmed = |r: &PendingRead| {
            let acks = acked.iter().filter(|&&a| Some(a) >= r.round).count();
            r.round.is_some() & is_majority(me + acks, n)
        };
        let (ready, waiting): (Vec<_>, Vec<_>) = std::mem::take(&mut s.reads).into_iter().partition(confirmed);
        s.reads = waiting;
        s.reads_ready.extend(ready.into_iter().map(|r| (r.id, r.index)));
    }

    /// Advances logical time by one tick: heartbeats / replication as leader,
    /// election timeout otherwise. Returns messages and newly committed entries.
    pub fn tick(&self) -> Result<TickOutcome> {
        let mut s = self.state.lock();
        let mut messages = Vec::new();
        Self::fail_unconfirmed_reads(&mut s);
        if s.role == NodeState::Leader {
            s.heartbeat_elapsed += 1;
            // Reads wait for a round that starts after they were asked.
            let reads_due = s.reads.iter().any(|r| r.round.is_none());
            if (s.heartbeat_elapsed >= self.cfg.heartbeat_interval) | reads_due {
                s.heartbeat_elapsed = 0;
                let round = if reads_due {
                    s.read_round += 1;
                    s.read_round
                } else {
                    0
                };
                for r in s.reads.iter_mut().filter(|r| r.round.is_none()) {
                    r.round = Some(round);
                }
                let targets: Vec<NodeId> = s.next_index.keys().copied().collect();
                for p in targets {
                    let mut m = self.replicate(&s, p);
                    m.read_ctx = round;
                    messages.push(Self::send(&mut s, m));
                }
            }
            self.maybe_commit(&mut s);
        } else {
            s.election_elapsed += 1;
            if s.election_elapsed >= s.election_timeout {
                // The leader's lease is over, whether or not this node may
                // campaign: others may need its vote.
                s.leader_id = None;
                if s.recovering | !self.is_member(&s, self.cfg.id) {
                    s.election_elapsed = 0;
                } else {
                    self.start_election(&mut s, &mut messages)?;
                }
            }
        }
        let snapshot = s.install.take();
        let committed = (s.log)
            .entries_after(s.last_applied, s.commit_index)
            .expect("applied entries are in the log");
        s.last_applied = s.commit_index;
        // A confirmed read's index is a commit index from before this tick,
        // and the tick has just handed out everything up to the commit index.
        let mut reads: Vec<ReadState> = (std::mem::take(&mut s.reads_ready).into_iter())
            .map(|(id, index)| ReadState { id, index: Some(index) })
            .collect();
        reads.extend(s.reads_failed.drain(..).map(|id| ReadState { id, index: None }));
        Ok(TickOutcome {
            messages,
            snapshot,
            committed,
            reads,
        })
    }

    /// Handles one message from a peer; returns the replies to send.
    pub fn step(&self, msg: Message) -> Result<Vec<Message>> {
        let mut s = self.state.lock();
        // Only voters take part in elections. A server that was removed, or
        // has not learned yet that it was added, must not move anybody's
        // term. Appends and snapshots come from whoever leads, and replies
        // are matched against the leader's own targets. A message from this
        // node itself is a transport mistake.
        let vote_traffic = matches!(
            msg.msg_type,
            MsgType::RequestVote | MsgType::RequestVoteReply | MsgType::PreVote | MsgType::PreVoteReply
        );
        // While a leader is heard from, vote traffic from a server outside the
        // configuration is ignored (Raft thesis section 4.2.3). Without a
        // leader it is not: a server this node has not heard was added may be
        // the only one that can win.
        let outsider = vote_traffic & s.leader_id.is_some() & !self.is_member(&s, msg.from);
        if outsider | (msg.from == self.cfg.id) {
            return Ok(Vec::new());
        }
        s.clock.observe(msg.lc);
        // Asking for, or promising, a pre-vote is not a term change.
        let pre = match msg.msg_type {
            MsgType::PreVote => true,
            MsgType::PreVoteReply => msg.vote_granted,
            _ => false,
        };
        if (msg.term > s.term) & !pre {
            self.storage.save_vote(msg.term, None)?;
            s.term = msg.term;
            s.voted_for = None;
            s.leader_id = None;
            s.role = NodeState::Follower;
            s.learners.clear();
        }
        let replies: Vec<Message> = if msg.term < s.term {
            self.stale_reply(&s, &msg).into_iter().collect()
        } else {
            match msg.msg_type {
                MsgType::RequestVote => vec![self.on_request_vote(&mut s, &msg)?],
                MsgType::RequestVoteReply => {
                    self.on_vote_reply(&mut s, &msg)?;
                    Vec::new()
                }
                MsgType::AppendEntries => {
                    let mut reply = self.on_append(&mut s, &msg)?;
                    reply.read_ctx = msg.read_ctx;
                    vec![reply]
                }
                MsgType::AppendEntriesReply | MsgType::InstallSnapshotReply => {
                    self.on_append_reply(&mut s, &msg).into_iter().collect()
                }
                MsgType::InstallSnapshot => {
                    let mut reply = self.on_install_snapshot(&mut s, &msg)?;
                    reply.read_ctx = msg.read_ctx;
                    vec![reply]
                }
                MsgType::PreVote => vec![self.on_pre_vote(&s, &msg)],
                MsgType::PreVoteReply => self.on_pre_vote_reply(&mut s, &msg)?,
            }
        };
        Self::fail_unconfirmed_reads(&mut s);
        Ok(replies.into_iter().map(|m| Self::send(&mut s, m)).collect())
    }

    fn send(s: &mut Inner, mut m: Message) -> Message {
        m.lc = s.clock.stamp();
        m
    }

    fn stale_reply(&self, s: &Inner, msg: &Message) -> Option<Message> {
        match msg.msg_type {
            MsgType::RequestVote => Some(Message::request_vote_reply(self.cfg.id, msg.from, s.term, false)),
            MsgType::AppendEntries => Some(Message::append_entries_reply(self.cfg.id, msg.from, s.term, false, 0)),
            MsgType::PreVote => Some(Message::pre_vote_reply(self.cfg.id, msg.from, s.term, false)),
            MsgType::InstallSnapshot => Some(Message::install_snapshot_reply(self.cfg.id, msg.from, s.term, false, 0)),
            MsgType::RequestVoteReply
            | MsgType::AppendEntriesReply
            | MsgType::PreVoteReply
            | MsgType::InstallSnapshotReply => None,
        }
    }

    /// An election timeout: ask for pre-votes, or campaign right away when
    /// pre-vote is off or there is nobody to ask.
    fn start_election(&self, s: &mut Inner, out: &mut Vec<Message>) -> Result<()> {
        let others = self.others(s);
        if !self.cfg.pre_vote | others.is_empty() {
            return self.campaign(s, out);
        }
        s.role = NodeState::PreCandidate;
        s.leader_id = None;
        s.pre_votes.clear();
        s.pre_votes.insert(self.cfg.id);
        s.election_elapsed = 0;
        s.election_timeout = random_timeout(&self.cfg, &mut s.rng);
        let (term, last_index, last_term) = (s.term + 1, s.log.last_index(), s.log.last_term());
        for p in others {
            let m = Message::pre_vote(self.cfg.id, p, term, last_index, last_term);
            out.push(Self::send(s, m));
        }
        Ok(())
    }

    /// Promises a vote for `msg.from` in `msg.term` if it could win one, and
    /// changes nothing: not the term, not the vote, not the election timer.
    /// Refused while a leader is heard from (or this node is the leader), and
    /// when this node is recovering.
    fn on_pre_vote(&self, s: &Inner, msg: &Message) -> Message {
        let up_to_date = (msg.last_log_term, msg.last_log_index) >= (s.log.last_term(), s.log.last_index());
        // A follower forgets its leader when its own election timer fires,
        // so a known leader means one heard from within a timeout.
        let leased = s.leader_id.is_some();
        let granted = (msg.term > s.term) & up_to_date & !leased & !s.recovering;
        let term = if granted { msg.term } else { s.term };
        Message::pre_vote_reply(self.cfg.id, msg.from, term, granted)
    }

    /// Counts a promise; with a majority, starts the real campaign.
    fn on_pre_vote_reply(&self, s: &mut Inner, msg: &Message) -> Result<Vec<Message>> {
        let mut out = Vec::new();
        let current = (s.role == NodeState::PreCandidate) & msg.vote_granted & (msg.term == s.term + 1);
        if current {
            s.pre_votes.insert(msg.from);
            if is_majority(self.counted(s, &s.pre_votes), self.voters_of(s).len()) {
                self.campaign(s, &mut out)?;
            }
        }
        Ok(out)
    }

    fn campaign(&self, s: &mut Inner, out: &mut Vec<Message>) -> Result<()> {
        let term = s.term + 1;
        self.storage.save_vote(term, Some(self.cfg.id))?;
        s.term = term;
        s.voted_for = Some(self.cfg.id);
        s.leader_id = None;
        s.role = NodeState::Candidate;
        s.votes.clear();
        s.votes.insert(self.cfg.id);
        s.pre_votes.clear();
        s.election_elapsed = 0;
        s.election_timeout = random_timeout(&self.cfg, &mut s.rng);
        let (last_index, last_term) = (s.log.last_index(), s.log.last_term());
        for p in self.others(s) {
            let m = Message::request_vote(self.cfg.id, p, term, last_index, last_term);
            out.push(Self::send(s, m));
        }
        self.maybe_win(s)
    }

    /// Becomes leader on a majority of votes, with an empty entry of the new
    /// term appended first (see the module docs).
    fn maybe_win(&self, s: &mut Inner) -> Result<()> {
        if !is_majority(self.counted(s, &s.votes), self.voters_of(s).len()) {
            return Ok(());
        }
        let noop = LogEntry::new(s.log.last_index() + 1, s.term, Vec::new());
        let batch = std::slice::from_ref(&noop);
        self.storage.append_entries(batch)?;
        s.log.append(batch).expect("a leader appends at its own tail");
        s.role = NodeState::Leader;
        s.leader_id = Some(self.cfg.id);
        s.learners.clear();
        s.next_index.clear();
        s.match_index.clear();
        s.read_acked.clear();
        s.read_round = 0;
        self.sync_targets(s);
        // Heartbeat on the very next tick.
        s.heartbeat_elapsed = self.cfg.heartbeat_interval;
        Ok(())
    }

    /// Commits the highest index stored on a majority, if it is from the
    /// current term (Raft §5.4.2: older entries commit only indirectly).
    fn maybe_commit(&self, s: &mut Inner) {
        let mut matched: Vec<Index> = (self.voters_of(s).iter())
            .map(|v| match *v == self.cfg.id {
                true => s.log.last_index(),
                false => s.match_index.get(v).copied().unwrap_or(0),
            })
            .collect();
        matched.sort_unstable();
        let candidate = matched[matched.len() - quorum(matched.len())];
        if candidate > s.commit_index && s.log.term_at(candidate) == Some(s.term) {
            let pending = s.log.config_index() > s.commit_index;
            s.commit_index = candidate;
            // A configuration entry just committed: servers it removed need
            // no more entries, and a leader it removed hands over.
            if pending & (s.log.config_index() <= candidate) {
                if self.is_voter(s) {
                    self.sync_targets(s);
                } else {
                    Self::step_down(s);
                }
            }
        }
    }

    /// What `peer` needs next: entries, or the snapshot when it needs
    /// entries this log no longer has.
    fn replicate(&self, s: &Inner, peer: NodeId) -> Message {
        match &s.snapshot {
            Some(snap) if s.next_index[&peer] <= snap.index => {
                let mut m = Message::install_snapshot(self.cfg.id, peer, s.term, snap.clone(), s.commit_index);
                m.leader_last_index = s.log.last_index();
                m
            }
            _ => self.append_for(s, peer),
        }
    }

    /// AppendEntries for `peer`; its `next_index` must be above the base.
    fn append_for(&self, s: &Inner, peer: NodeId) -> Message {
        let prev = s.next_index[&peer] - 1;
        let prev_term = s.log.term_at(prev).unwrap_or(0);
        let entries = s.log.entries();
        let start = ((prev - s.log.base_index()) as usize).min(entries.len());
        let end = start.saturating_add(MAX_BATCH).min(entries.len());
        let mut m = Message::append_entries(
            self.cfg.id,
            peer,
            s.term,
            prev,
            prev_term,
            entries[start..end].to_vec(),
            s.commit_index,
        );
        m.leader_last_index = s.log.last_index();
        m
    }

    fn on_request_vote(&self, s: &mut Inner, msg: &Message) -> Result<Message> {
        let up_to_date = (msg.last_log_term, msg.last_log_index) >= (s.log.last_term(), s.log.last_index());
        let free = s.voted_for.unwrap_or(msg.from) == msg.from;
        let granted = up_to_date & free & !s.recovering;
        if granted {
            self.storage.save_vote(s.term, Some(msg.from))?;
            s.voted_for = Some(msg.from);
            s.election_elapsed = 0;
        }
        Ok(Message::request_vote_reply(self.cfg.id, msg.from, s.term, granted))
    }

    fn on_vote_reply(&self, s: &mut Inner, msg: &Message) -> Result<()> {
        if (s.role == NodeState::Candidate) & msg.vote_granted {
            s.votes.insert(msg.from);
            self.maybe_win(s)?;
        }
        Ok(())
    }

    fn on_append(&self, s: &mut Inner, msg: &Message) -> Result<Message> {
        s.role = NodeState::Follower;
        s.leader_id = Some(msg.from);
        s.election_elapsed = 0;
        if s.log.term_at(msg.last_log_index) != Some(msg.last_log_term) {
            // Our last index lets the leader skip back quickly.
            let hint = s.log.last_index();
            return Ok(Message::append_entries_reply(
                self.cfg.id,
                msg.from,
                s.term,
                false,
                hint,
            ));
        }
        s.log.check_append(&msg.entries)?;
        if s.log.first_conflict(&msg.entries).unwrap_or(Index::MAX) <= s.commit_index {
            return Err(Error::LogInconsistency(LogError::TruncatesCommitted));
        }
        self.storage.append_entries(&msg.entries)?;
        s.log.append(&msg.entries).expect("validated by check_append");
        let last_new = msg.entries.last().map_or(msg.last_log_index, |e| e.index);
        s.commit_index = s.commit_index.max(msg.commit_index.min(last_new));
        // Our log now matches the leader's up to `last_new`; entries past it
        // may be stale leftovers, so they do not count.
        if s.recovering & (last_new >= msg.leader_last_index) {
            self.storage.mark_repaired()?;
            s.recovering = false;
        }
        Ok(Message::append_entries_reply(
            self.cfg.id,
            msg.from,
            s.term,
            true,
            last_new,
        ))
    }

    /// Takes the leader's snapshot, unless this node already committed
    /// everything it covers. The application gets it on the next tick.
    fn on_install_snapshot(&self, s: &mut Inner, msg: &Message) -> Result<Message> {
        s.role = NodeState::Follower;
        s.leader_id = Some(msg.from);
        s.election_elapsed = 0;
        let Some(snapshot) = msg.snapshot.clone() else {
            return Err(Error::BadSnapshot("InstallSnapshot without a snapshot"));
        };
        let index = snapshot.index;
        let reply = |s: &Inner, matched| Message::install_snapshot_reply(self.cfg.id, msg.from, s.term, true, matched);
        if index <= s.commit_index {
            // Committed entries are the same on every node, so this log
            // matches the leader's up to its commit index.
            return Ok(reply(s, s.commit_index));
        }
        self.storage.install_snapshot(snapshot.clone())?;
        s.log
            .install_snapshot(index, snapshot.term, snapshot.voters.clone())
            .expect("above the commit index, so above the base");
        s.commit_index = index;
        s.last_applied = index;
        s.snapshot = Some(snapshot.clone());
        s.install = Some(snapshot);
        if s.recovering & (index >= msg.leader_last_index) {
            self.storage.mark_repaired()?;
            s.recovering = false;
        }
        Ok(reply(s, index))
    }

    fn on_append_reply(&self, s: &mut Inner, msg: &Message) -> Option<Message> {
        if s.role != NodeState::Leader {
            return None;
        }
        // A reply from a server that is no longer replicated to is old news.
        let current = *s.next_index.get(&msg.from)?;
        // Any reply of this term shows the follower accepted this leader
        // after the round named in `read_ctx` began.
        if msg.read_ctx > 0 {
            let acked = s.read_acked.entry(msg.from).or_insert(0);
            *acked = (*acked).max(msg.read_ctx);
            self.confirm_reads(s);
        }
        let next = if msg.success {
            // Trust the reply even if it is lower than before: a follower
            // that lost entries to storage damage reports what it really has
            // (a reordered older reply only causes a harmless resend).
            s.match_index.insert(msg.from, msg.match_index);
            self.maybe_commit(s);
            msg.match_index + 1
        } else {
            (current - 1).min(msg.match_index.saturating_add(1)).max(1)
        };
        // Committing may have removed this server from the targets, or made
        // this node step down.
        *s.next_index.get_mut(&msg.from)? = next;
        let more = (next <= s.log.last_index()) | !msg.success;
        more.then(|| self.replicate(s, msg.from))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryStorage;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn entry(index: Index, term: Term, data: &[u8]) -> LogEntry {
        LogEntry::new(index, term, data.to_vec())
    }

    /// A cluster member that campaigns right away (no pre-vote phase).
    fn classic(id: NodeId, voters: Vec<NodeId>) -> Config {
        Config {
            pre_vote: false,
            ..Config::cluster(id, voters)
        }
    }

    /// Ticks until `node` starts an election; returns that tick's messages.
    fn campaign(node: &Node) -> Vec<Message> {
        let mut out = node.tick().unwrap();
        while node.role() != NodeState::Candidate {
            out = node.tick().unwrap();
        }
        out.messages
    }

    fn leader_of(node: &Node, ticks: usize) {
        for _ in 0..ticks {
            node.tick().unwrap();
        }
        assert_eq!(node.role(), NodeState::Leader);
    }

    /// Nodes 1..=n; messages to or from a `down` node are dropped.
    struct Net {
        nodes: Vec<Node>,
        applied: Vec<Vec<LogEntry>>,
        reads: Vec<Vec<ReadState>>,
        snapshots: Vec<Vec<Arc<Snapshot>>>,
    }

    impl Net {
        fn new(n: u64) -> Self {
            Self::with_pre_vote(n, true)
        }

        fn with_pre_vote(n: u64, pre_vote: bool) -> Self {
            let voters: Vec<NodeId> = (1..=n).collect();
            let nodes: Vec<Node> = voters
                .iter()
                .map(|&id| {
                    let cfg = Config {
                        pre_vote,
                        ..Config::cluster(id, voters.clone())
                    };
                    Node::new(cfg, MemoryStorage::new()).unwrap()
                })
                .collect();
            Net {
                applied: vec![Vec::new(); nodes.len()],
                reads: vec![Vec::new(); nodes.len()],
                snapshots: vec![Vec::new(); nodes.len()],
                nodes,
            }
        }

        fn node(&self, id: NodeId) -> &Node {
            &self.nodes[(id - 1) as usize]
        }

        fn run(&mut self, ticks: usize, down: &[NodeId]) {
            for _ in 0..ticks {
                let mut q = VecDeque::new();
                for (i, n) in self.nodes.iter().enumerate() {
                    let out = n.tick().unwrap();
                    self.applied[i].extend(out.committed);
                    self.reads[i].extend(out.reads);
                    self.snapshots[i].extend(out.snapshot);
                    q.extend(out.messages);
                }
                while let Some(m) = q.pop_front() {
                    if down.contains(&m.to) | down.contains(&m.from) {
                        continue;
                    }
                    q.extend(self.node(m.to).step(m).unwrap());
                }
            }
        }

        fn leaders(&self, down: &[NodeId]) -> Vec<NodeId> {
            self.nodes
                .iter()
                .filter(|n| (n.role() == NodeState::Leader) & !down.contains(&n.id()))
                .map(|n| n.id())
                .collect()
        }
    }

    #[test]
    fn single_node_elects_and_commits() {
        let node = Node::new(Config::single(1), MemoryStorage::new()).unwrap();
        assert_eq!(
            (node.role(), node.id(), node.term(), node.commit_index()),
            (NodeState::Follower, 1, 0, 0)
        );
        leader_of(&node, 20);
        assert_eq!(node.leader(), Some(1));
        // Its own empty entry came first, and committed by itself.
        assert_eq!(node.commit_index(), 1);
        assert_eq!(node.propose(b"cmd-1".to_vec()).unwrap(), 2);
        let committed = node.tick().unwrap().committed;
        assert_eq!(committed, vec![entry(2, node.term(), b"cmd-1")]);
        assert!(node.tick().unwrap().committed.is_empty(), "applied once");
        assert_eq!(node.commit_index(), 2);
        let (term, entries) = node.log_snapshot();
        assert!(term >= 1 && entries.len() == 2 && entries[0].data.is_empty());
        assert!(node.logical_time() > 0);
    }

    #[test]
    fn configuration_errors() {
        let mut cfg = Config::single(1);
        cfg.voters = vec![2];
        assert_eq!(Node::new(cfg, MemoryStorage::new()).err(), Some(Error::NotConfigured));
        let node = Node::new(Config::cluster(1, vec![1, 2, 3]), MemoryStorage::new()).unwrap();
        assert_eq!(node.propose(b"x".to_vec()), Err(Error::NotLeader(None)));
        // A message from this node itself is a transport mistake.
        for m in [
            Message::request_vote(1, 1, 1, 0, 0),
            Message::pre_vote(1, 1, 1, 0, 0),
            Message::request_vote_reply(1, 1, 1, true),
            Message::pre_vote_reply(1, 1, 1, true),
            Message::append_entries(1, 1, 1, 0, 0, vec![], 0),
        ] {
            assert_eq!(node.step(m), Ok(vec![]));
        }
        assert_eq!((node.term(), node.logical_time()), (0, 0));
        // While a leader is heard from, vote traffic from outside the voter
        // set is ignored without moving the term, but a voter is answered.
        node.step(Message::append_entries(2, 1, 1, 0, 0, vec![], 0)).unwrap();
        for m in [
            Message::request_vote(9, 1, 5, 0, 0),
            Message::pre_vote(9, 1, 5, 0, 0),
            Message::request_vote_reply(9, 1, 5, true),
            Message::pre_vote_reply(9, 1, 5, true),
        ] {
            assert_eq!(node.step(m), Ok(vec![]));
        }
        assert_eq!((node.term(), node.leader()), (1, Some(2)));
        assert!(!node.step(Message::pre_vote(3, 1, 5, 0, 0)).unwrap().is_empty());
        // Once the leader has been silent for a timeout, anybody who asks is
        // answered: the server that asks may be the one that was added.
        while node.leader().is_some() {
            node.tick().unwrap();
        }
        assert!(node.step(Message::request_vote(9, 1, 7, 0, 0)).unwrap()[0].vote_granted);
        assert_eq!(node.term(), 7);
        // An empty voter list is a node that waits to be added.
        let joiner = Node::new(Config::joiner(4), MemoryStorage::new()).unwrap();
        assert!(joiner.voters().is_empty() && joiner.learners().is_empty());
    }

    #[test]
    fn timeout_respects_bounds() {
        let mut cfg = Config::cluster(1, vec![1]);
        let mut rng = 7;
        for _ in 0..100 {
            let t = random_timeout(&cfg, &mut rng);
            assert!((10..=20).contains(&t));
        }
        cfg.election_timeout_min = 0;
        cfg.election_timeout_max = 0;
        assert_eq!(random_timeout(&cfg, &mut rng), 1);
    }

    #[test]
    fn cluster_replicates_survives_leader_loss_and_repairs_logs() {
        let mut net = Net::new(3);
        net.run(60, &[]);
        let leaders = net.leaders(&[]);
        assert_eq!(leaders.len(), 1);
        let old = leaders[0];
        let old_term = net.node(old).term();
        for i in 0..3u8 {
            net.node(old).propose(vec![i]).unwrap();
        }
        net.run(10, &[]);
        for applied in &net.applied {
            assert_eq!(applied.len(), 4, "its empty entry and three proposals");
        }
        // Partition the leader away: the others elect a new one.
        net.run(80, &[old]);
        let new = net.leaders(&[old]);
        assert_eq!(new.len(), 1);
        assert_ne!(new[0], old);
        assert!(net.node(new[0]).term() > old_term);
        assert_eq!(
            net.node(old).role(),
            NodeState::Leader,
            "isolated, still thinks it leads"
        );
        net.node(old).propose(b"lost".to_vec()).unwrap();
        net.node(new[0]).propose(b"kept".to_vec()).unwrap();
        net.run(10, &[old]);
        // Heal: the old leader steps down and its uncommitted entry is replaced.
        net.run(30, &[]);
        assert_eq!(net.node(old).role(), NodeState::Follower);
        assert_eq!(net.node(old).leader(), Some(new[0]));
        let reference = net.node(new[0]).log_snapshot().1;
        // Two empty entries, one per leader, the three proposals and "kept".
        assert_eq!(reference.len(), 6);
        assert_eq!(reference[5].data, b"kept");
        for n in &net.nodes {
            assert_eq!(n.log_snapshot().1, reference);
            assert_eq!(n.commit_index(), 6);
        }
        for applied in &net.applied {
            assert_eq!(applied, &reference);
        }
    }

    #[test]
    fn stale_messages_are_rejected_or_ignored() {
        let node = Node::new(Config::cluster(1, vec![1, 2, 3]), MemoryStorage::new()).unwrap();
        assert!(node.step(Message::request_vote(2, 1, 5, 0, 0)).unwrap()[0].vote_granted);
        assert_eq!(node.term(), 5);
        let r = node.step(Message::request_vote(3, 1, 3, 0, 0)).unwrap();
        assert!(!r[0].vote_granted && r[0].term == 5 && r[0].lc > 0);
        let r = node.step(Message::append_entries(2, 1, 3, 0, 0, vec![], 0)).unwrap();
        assert!(!r[0].success);
        assert!(node
            .step(Message::request_vote_reply(2, 1, 3, true))
            .unwrap()
            .is_empty());
        assert!(node
            .step(Message::append_entries_reply(2, 1, 3, true, 1))
            .unwrap()
            .is_empty());
    }

    #[test]
    fn voting_rules() {
        let storage = MemoryStorage::with_state(DurableState {
            term: 2,
            voted_for: None,
            log: {
                let mut l = Log::new();
                l.append(&[entry(1, 2, b"a"), entry(2, 2, b"b")]).unwrap();
                l
            },
            recovering: false,
            snapshot: None,
        });
        let node = Node::new(Config::cluster(1, vec![1, 2, 3]), storage.clone()).unwrap();
        // Candidate log is behind (older last term / shorter): refused.
        assert!(!node.step(Message::request_vote(2, 1, 2, 5, 1)).unwrap()[0].vote_granted);
        assert!(!node.step(Message::request_vote(2, 1, 2, 1, 2)).unwrap()[0].vote_granted);
        // Up to date: granted, repeatable for the same candidate, not for another.
        assert!(node.step(Message::request_vote(2, 1, 2, 2, 2)).unwrap()[0].vote_granted);
        assert!(node.step(Message::request_vote(2, 1, 2, 2, 2)).unwrap()[0].vote_granted);
        assert!(!node.step(Message::request_vote(3, 1, 2, 9, 9)).unwrap()[0].vote_granted);
        assert_eq!(storage.load().unwrap().voted_for, Some(2));
        // Restart: the durable vote is kept.
        let node = Node::new(Config::cluster(1, vec![1, 2, 3]), storage).unwrap();
        assert!(!node.step(Message::request_vote(3, 1, 2, 9, 9)).unwrap()[0].vote_granted);
    }

    #[test]
    fn candidate_counts_votes() {
        let node = Node::new(classic(1, vec![1, 2, 3, 4, 5]), MemoryStorage::new()).unwrap();
        // Vote replies to a follower are ignored.
        assert!(node
            .step(Message::request_vote_reply(2, 1, 0, true))
            .unwrap()
            .is_empty());
        let msgs = campaign(&node);
        assert_eq!(msgs.len(), 4);
        assert!(msgs.iter().all(|m| m.msg_type == MsgType::RequestVote));
        let t = node.term();
        node.step(Message::request_vote_reply(2, 1, t, false)).unwrap();
        node.step(Message::request_vote_reply(3, 1, t, true)).unwrap();
        assert_eq!(node.role(), NodeState::Candidate);
        node.step(Message::request_vote_reply(4, 1, t, true)).unwrap();
        assert_eq!(node.role(), NodeState::Leader);
        // Appends replies to a non-leader are ignored.
        let f = Node::new(Config::cluster(1, vec![1, 2, 3]), MemoryStorage::new()).unwrap();
        assert!(f
            .step(Message::append_entries_reply(2, 1, 0, true, 1))
            .unwrap()
            .is_empty());
    }

    #[test]
    fn follower_append_rules() {
        let node = Node::new(Config::cluster(2, vec![1, 2, 3]), MemoryStorage::new()).unwrap();
        let ok = node
            .step(Message::append_entries(
                1,
                2,
                1,
                0,
                0,
                vec![entry(1, 1, b"a"), entry(2, 1, b"b")],
                1,
            ))
            .unwrap();
        assert!(ok[0].success && ok[0].match_index == 2);
        assert_eq!((node.commit_index(), node.leader()), (1, Some(1)));
        // Previous entry mismatch: rejected with our last index as a hint.
        let r = node.step(Message::append_entries(1, 2, 1, 5, 1, vec![], 9)).unwrap();
        assert!(!r[0].success && r[0].match_index == 2);
        // Heartbeat advances commit, bounded by what we have.
        node.step(Message::append_entries(1, 2, 1, 1, 1, vec![], 9)).unwrap();
        assert_eq!(node.commit_index(), 1);
        node.step(Message::append_entries(1, 2, 1, 2, 1, vec![], 9)).unwrap();
        assert_eq!(node.commit_index(), 2);
        assert_eq!(node.tick().unwrap().committed.len(), 2);
        // Malformed batch.
        assert!(node
            .step(Message::append_entries(1, 2, 1, 2, 1, vec![entry(4, 1, b"x")], 2))
            .is_err());
        // Overwriting a committed entry is refused.
        assert!(node
            .step(Message::append_entries(1, 2, 2, 1, 1, vec![entry(2, 2, b"z")], 2))
            .is_err());
        assert_eq!(node.log_snapshot().1[1].data, b"b");
    }

    #[test]
    fn leader_backs_off_and_resends() {
        let node = Node::new(classic(1, vec![1, 2, 3]), MemoryStorage::new()).unwrap();
        node.step(Message::append_entries(2, 1, 1, 0, 0, vec![entry(1, 1, b"a")], 0))
            .unwrap();
        campaign(&node);
        let t = node.term();
        node.step(Message::request_vote_reply(2, 1, t, true)).unwrap();
        assert_eq!(node.role(), NodeState::Leader);
        node.propose(b"b".to_vec()).unwrap();
        // The log: "a" from the old leader, the new leader's empty entry, "b".
        // Peer 2 reports a gap: resend from its hint.
        let r = node.step(Message::append_entries_reply(2, 1, t, false, 0)).unwrap();
        assert_eq!((r[0].last_log_index, r[0].entries.len()), (0, 3));
        // Peer 2 caught up fully: nothing more to send, everything commits
        // (entry 1 indirectly, through the current-term entries).
        let r = node.step(Message::append_entries_reply(2, 1, t, true, 3)).unwrap();
        assert!(r.is_empty());
        assert_eq!(node.commit_index(), 3);
        // Peer 3 has only entry 1: the rest is sent right away.
        let r = node.step(Message::append_entries_reply(3, 1, t, true, 1)).unwrap();
        assert_eq!((r[0].last_log_index, r[0].entries.len()), (1, 2));
        assert_eq!(r[0].leader_last_index, 3);
        // Peer 2 lost entries since it acknowledged 3: believe it and resend.
        let r = node.step(Message::append_entries_reply(2, 1, t, true, 0)).unwrap();
        assert_eq!((r[0].last_log_index, r[0].entries.len()), (0, 3));
        assert_eq!(node.commit_index(), 3, "commit never goes back");
    }

    #[test]
    fn old_term_entries_need_a_current_term_entry() {
        let mut log = Log::new();
        log.append(&[entry(1, 1, b"old")]).unwrap();
        let storage = MemoryStorage::with_state(DurableState {
            term: 1,
            voted_for: None,
            log,
            recovering: false,
            snapshot: None,
        });
        let node = Node::new(classic(1, vec![1, 2, 3]), storage).unwrap();
        campaign(&node);
        let t = node.term();
        node.step(Message::request_vote_reply(2, 1, t, true)).unwrap();
        assert_eq!(node.role(), NodeState::Leader);
        // The log is the old entry and the leader's own empty entry. A
        // majority holding the old entry does not commit it...
        node.step(Message::append_entries_reply(2, 1, t, true, 1)).unwrap();
        assert_eq!(node.commit_index(), 0);
        // ... a majority holding an entry of this term commits both.
        node.step(Message::append_entries_reply(2, 1, t, true, 2)).unwrap();
        assert_eq!(node.commit_index(), 2);
    }

    /// Storage whose calls start failing after a budget.
    struct Failing {
        inner: Arc<MemoryStorage>,
        budget: AtomicU64,
    }

    impl Failing {
        fn new(budget: u64) -> Arc<Self> {
            Self::with_state(budget, DurableState::default())
        }
        fn with_state(budget: u64, state: DurableState) -> Arc<Self> {
            Arc::new(Failing {
                inner: MemoryStorage::with_state(state),
                budget: AtomicU64::new(budget),
            })
        }
        fn spend(&self) -> Result<()> {
            let left = self.budget.load(Ordering::SeqCst);
            self.budget.store(left.saturating_sub(1), Ordering::SeqCst);
            (left > 0).then_some(()).ok_or(Error::Storage("disk gone".into()))
        }
    }

    impl Storage for Failing {
        fn load(&self) -> Result<DurableState> {
            self.spend()?;
            self.inner.load()
        }
        fn save_vote(&self, term: Term, voted_for: Option<NodeId>) -> Result<()> {
            self.spend()?;
            self.inner.save_vote(term, voted_for)
        }
        fn append_entries(&self, entries: &[LogEntry]) -> Result<()> {
            self.spend()?;
            self.inner.append_entries(entries)
        }
        fn mark_repaired(&self) -> Result<()> {
            self.spend()?;
            self.inner.mark_repaired()
        }
        fn install_snapshot(&self, snapshot: Arc<Snapshot>) -> Result<()> {
            self.spend()?;
            self.inner.install_snapshot(snapshot)
        }
    }

    #[test]
    fn storage_failures_surface_and_leave_state_unchanged() {
        let cfg = || Config::cluster(1, vec![1, 2, 3]);
        assert!(Node::new(cfg(), Failing::new(0)).is_err());
        // Higher term seen.
        let n = Node::new(cfg(), Failing::new(1)).unwrap();
        assert!(n.step(Message::append_entries(2, 1, 4, 0, 0, vec![], 0)).is_err());
        assert_eq!(n.term(), 0);
        // Granting a vote.
        let n = Node::new(cfg(), Failing::new(1)).unwrap();
        assert!(n.step(Message::request_vote(2, 1, 0, 0, 0)).is_err());
        // Appending as follower.
        let n = Node::new(cfg(), Failing::new(2)).unwrap();
        n.step(Message::append_entries(2, 1, 0, 0, 0, vec![entry(1, 0, b"a")], 0))
            .unwrap();
        assert!(n
            .step(Message::append_entries(2, 1, 0, 1, 0, vec![entry(2, 0, b"b")], 0))
            .is_err());
        assert_eq!(n.log_snapshot().1.len(), 1);
        // Starting an election.
        let n = Node::new(classic(1, vec![1, 2, 3]), Failing::new(1)).unwrap();
        let errs = (0..40).filter(|_| n.tick().is_err()).count();
        assert!(errs > 0);
        assert_eq!((n.term(), n.role()), (0, NodeState::Follower));
        // A pre-vote majority whose campaign cannot save the vote.
        let n = Node::new(cfg(), Failing::new(1)).unwrap();
        pre_campaign(&n);
        assert!(n.step(Message::pre_vote_reply(2, 1, 1, true)).is_err());
        assert_eq!((n.term(), n.role()), (0, NodeState::PreCandidate));
        // The empty entry that makes a node leader: it does not lead without it.
        let n = Node::new(Config::single(1), Failing::new(2)).unwrap();
        let errs = (0..40).filter(|_| n.tick().is_err()).count();
        assert!(errs > 0);
        assert_eq!(n.role(), NodeState::Candidate);
        assert!(n.log_snapshot().1.is_empty());
        // Proposing.
        let n = Node::new(Config::single(1), Failing::new(3)).unwrap();
        leader_of(&n, 20);
        assert!(n.propose(b"x".to_vec()).is_err());
        assert_eq!(n.log_snapshot().1.len(), 1);
        // Winning with a vote that arrives by message.
        let n = Node::new(classic(1, vec![1, 2, 3]), Failing::new(2)).unwrap();
        campaign(&n);
        let t = n.term();
        assert!(n.step(Message::request_vote_reply(2, 1, t, true)).is_err());
        assert_eq!(n.role(), NodeState::Candidate);
        // Leaving the recovering state: the entries are kept, the flag too.
        let damaged = DurableState {
            recovering: true,
            ..DurableState::default()
        };
        let catch_up = || Message::append_entries(2, 1, 0, 0, 0, vec![entry(1, 0, b"a")], 0);
        let n = Node::new(cfg(), Failing::with_state(2, damaged.clone())).unwrap();
        assert!(n.step(catch_up()).is_err());
        assert!(n.recovering());
        assert_eq!(n.log_snapshot().1.len(), 1);
        let n = Node::new(cfg(), Failing::with_state(3, damaged)).unwrap();
        assert!(n.step(catch_up()).unwrap()[0].success);
        assert!(!n.recovering());
    }

    /// A leader of node 1 in a classic cluster of three, term returned: its
    /// own empty entry (index 1, term `t`) and one of "x" (index 2) are
    /// acknowledged by node 2 and committed.
    fn committed_leader() -> (Node, Term) {
        let node = Node::new(classic(1, vec![1, 2, 3]), MemoryStorage::new()).unwrap();
        campaign(&node);
        let t = node.term();
        node.step(Message::request_vote_reply(2, 1, t, true)).unwrap();
        node.propose(b"x".to_vec()).unwrap();
        node.step(Message::append_entries_reply(2, 1, t, true, 2)).unwrap();
        assert_eq!(node.commit_index(), 2);
        (node, t)
    }

    #[test]
    fn read_index_waits_for_a_commit_in_the_term_and_a_majority() {
        let node = Node::new(classic(1, vec![1, 2, 3]), MemoryStorage::new()).unwrap();
        assert_eq!(node.read_index(), Err(Error::NotLeader(None)));
        campaign(&node);
        let t = node.term();
        node.step(Message::request_vote_reply(2, 1, t, true)).unwrap();
        // Nothing of this term is committed yet, not even the leader's own
        // empty entry.
        assert_eq!(node.read_index(), Err(Error::NotReady));
        assert_eq!(node.read_index(), Err(Error::NotReady));
        let log = node.log_snapshot().1;
        assert_eq!((log.len(), log[0].term, log[0].data.len()), (1, t, 0));
        node.step(Message::append_entries_reply(2, 1, t, true, 1)).unwrap();
        assert_eq!(node.commit_index(), 1);
        // Reads asked before a tick share the round that tick starts.
        let a = node.read_index().unwrap();
        let b = node.read_index().unwrap();
        let sent = node.tick().unwrap().messages;
        assert!(sent
            .iter()
            .all(|m| m.msg_type == MsgType::AppendEntries && m.read_ctx == 1));
        assert_eq!(sent.len(), 2);
        // An acknowledgement of an older round does not count, and neither
        // does one without a round.
        let reply = |from, ctx| {
            let mut m = Message::append_entries_reply(from, 1, t, true, 1);
            m.read_ctx = ctx;
            m
        };
        node.step(reply(2, 0)).unwrap();
        assert!(node.tick().unwrap().reads.is_empty());
        // One acknowledgement of round 1 is a majority of three with the leader.
        node.step(reply(3, 1)).unwrap();
        let reads = node.tick().unwrap().reads;
        assert_eq!(
            reads,
            vec![ReadState { id: a, index: Some(1) }, ReadState { id: b, index: Some(1) }]
        );
        assert!(node.tick().unwrap().reads.is_empty(), "released once");
        // A reply to a later round also confirms the reads of earlier ones.
        let c = node.read_index().unwrap();
        node.tick().unwrap();
        let d = node.read_index().unwrap();
        node.tick().unwrap();
        node.step(reply(2, 3)).unwrap();
        let ids: Vec<u64> = node.tick().unwrap().reads.iter().map(|r| r.id).collect();
        assert_eq!(ids, vec![c, d]);
        // The reply is echoed by a follower, and a stale one is ignored.
        let f = Node::new(classic(2, vec![1, 2, 3]), MemoryStorage::new()).unwrap();
        let mut m = Message::append_entries(1, 2, 1, 0, 0, vec![], 0);
        m.read_ctx = 7;
        assert_eq!(f.step(m).unwrap()[0].read_ctx, 7);
        assert!(f.step(reply(1, 5)).unwrap().is_empty());
    }

    #[test]
    fn read_index_fails_when_leadership_is_lost() {
        let (node, t) = committed_leader();
        let id = node.read_index().unwrap();
        // Deposed before a majority confirmed it.
        node.step(Message::request_vote(3, 1, t + 1, 9, 9)).unwrap();
        assert_eq!(node.role(), NodeState::Follower);
        assert_eq!(node.tick().unwrap().reads, vec![ReadState { id, index: None }]);
        assert_eq!(node.read_index(), Err(Error::NotLeader(None)));
        // A confirmed read survives losing leadership: it was confirmed
        // while this node led.
        let (node, t) = committed_leader();
        let id = node.read_index().unwrap();
        node.tick().unwrap();
        let mut m = Message::append_entries_reply(3, 1, t, true, 2);
        m.read_ctx = 1;
        node.step(m).unwrap();
        node.step(Message::request_vote(2, 1, t + 1, 9, 9)).unwrap();
        assert_eq!(node.tick().unwrap().reads, vec![ReadState { id, index: Some(2) }]);
    }

    #[test]
    fn single_node_reads_need_no_round() {
        let node = Node::new(Config::single(1), MemoryStorage::new()).unwrap();
        leader_of(&node, 20);
        assert_eq!(node.commit_index(), 1);
        let id = node.read_index().unwrap();
        let out = node.tick().unwrap();
        assert_eq!(out.reads, vec![ReadState { id, index: Some(1) }]);
        assert!(out.messages.is_empty());
    }

    #[test]
    fn a_cut_off_leader_cannot_serve_reads() {
        let mut net = Net::new(3);
        net.run(60, &[]);
        let old = net.leaders(&[])[0];
        net.node(old).propose(b"x".to_vec()).unwrap();
        net.run(10, &[]);
        // A read through the connected leader completes within a few ticks.
        let id = net.node(old).read_index().unwrap();
        net.run(5, &[]);
        assert_eq!(net.reads[(old - 1) as usize], vec![ReadState { id, index: Some(2) }]);
        // Cut off, it still believes it leads but cannot confirm a read.
        let stale = net.node(old).read_index().unwrap();
        net.run(80, &[old]);
        assert_eq!(net.node(old).role(), NodeState::Leader);
        assert_eq!(net.reads[(old - 1) as usize].len(), 1, "nothing was released");
        let new = net.leaders(&[old])[0];
        assert_ne!(new, old);
        // Once it hears from the new leader, the read fails instead of being
        // answered from a possibly stale state.
        net.run(30, &[]);
        assert_eq!(
            net.reads[(old - 1) as usize].last(),
            Some(&ReadState { id: stale, index: None })
        );
        assert_eq!(net.node(old).role(), NodeState::Follower);
    }

    fn snapshot_of(index: Index, term: Term, voters: &[NodeId], data: &[u8]) -> Snapshot {
        Snapshot {
            index,
            term,
            voters: voters.to_vec(),
            data: data.to_vec(),
        }
    }

    /// An InstallSnapshot message for a cluster of nodes 1, 2 and 3.
    fn install_msg(
        from: NodeId,
        to: NodeId,
        term: Term,
        index: Index,
        snap_term: Term,
        data: &[u8],
        commit: Index,
    ) -> Message {
        let snapshot = Arc::new(snapshot_of(index, snap_term, &[1, 2, 3], data));
        Message::install_snapshot(from, to, term, snapshot, commit)
    }

    #[test]
    fn compaction_drops_the_log_and_a_restart_restores_the_snapshot() {
        let storage = MemoryStorage::new();
        let node = Node::new(Config::single(1), storage.clone()).unwrap();
        leader_of(&node, 20);
        for i in 0..3u8 {
            node.propose(vec![i]).unwrap();
        }
        let t = node.term();
        assert_eq!(node.tick().unwrap().committed.len(), 3);
        let cannot = |index, why| assert_eq!(node.compact(index, vec![]), Err(Error::BadSnapshot(why)));
        cannot(9, "index is not applied yet");
        cannot(0, "index is not above the snapshot");
        node.compact(2, b"state at 2".to_vec()).unwrap();
        assert_eq!(
            (node.snapshot_index(), node.log_snapshot().1),
            (2, vec![entry(3, t, &[1]), entry(4, t, &[2])])
        );
        cannot(2, "index is not above the snapshot");
        cannot(1, "index is not above the snapshot");
        // Taking a snapshot of its own state is not something to restore.
        assert!(node.tick().unwrap().snapshot.is_none());
        assert_eq!(
            storage.load().unwrap().snapshot.as_deref(),
            Some(&snapshot_of(2, t, &[1], b"state at 2"))
        );
        // After a restart the first tick hands out the snapshot, once, and
        // the entries after it follow when the commit index is learned again.
        drop(node);
        let node = Node::new(Config::single(1), storage.clone()).unwrap();
        assert_eq!((node.commit_index(), node.snapshot_index()), (2, 2));
        let out = node.tick().unwrap();
        assert_eq!(out.snapshot.as_deref(), Some(&snapshot_of(2, t, &[1], b"state at 2")));
        assert!(out.committed.is_empty());
        assert!(node.tick().unwrap().snapshot.is_none());
        leader_of(&node, 20);
        assert_eq!(node.propose(b"n".to_vec()).unwrap(), 6, "after its new empty entry");
        let committed: Vec<Index> = node.tick().unwrap().committed.iter().map(|e| e.index).collect();
        // (`leader_of` already handed out 3 to 5)
        assert_eq!(committed, vec![6]);
        // A snapshot that does not match the log is refused at start.
        let bad = MemoryStorage::with_state(DurableState {
            snapshot: Some(Arc::new(snapshot_of(5, 1, &[], b"x"))),
            ..DurableState::default()
        });
        let err = Node::new(Config::single(1), bad).err().unwrap();
        assert_eq!(err, Error::Storage("the log does not start after the snapshot".into()));
    }

    #[test]
    fn leader_sends_the_snapshot_to_a_follower_that_needs_compacted_entries() {
        let (node, t) = committed_leader();
        node.propose(b"y".to_vec()).unwrap();
        node.propose(b"z".to_vec()).unwrap();
        node.step(Message::append_entries_reply(2, 1, t, true, 4)).unwrap();
        assert_eq!(node.tick().unwrap().committed.len(), 4);
        node.compact(4, b"state at 4".to_vec()).unwrap();
        // Peer 3 never got anything: it needs entry 1. Peer 2 is current.
        let ask_read = node.read_index().unwrap();
        let sent = (0..3).flat_map(|_| node.tick().unwrap().messages).collect::<Vec<_>>();
        let to = |peer| sent.iter().find(|m| m.to == peer).unwrap();
        let (snap, append) = (to(3), to(2));
        assert_eq!(snap.msg_type, MsgType::InstallSnapshot);
        assert_eq!((snap.term, snap.last_log_index, snap.last_log_term), (t, 4, t));
        assert_eq!((snap.commit_index, snap.leader_last_index), (4, 4));
        assert_eq!(snap.snapshot.as_ref().unwrap().data, b"state at 4");
        assert_eq!((append.msg_type, append.last_log_index), (MsgType::AppendEntries, 4));
        // The snapshot carries the read round too: its reply confirms the read.
        assert_eq!((snap.read_ctx, append.read_ctx), (1, 1));
        let mut reply = Message::install_snapshot_reply(3, 1, t, true, 4);
        reply.read_ctx = 1;
        assert!(
            node.step(reply.clone()).unwrap().is_empty(),
            "nothing after the snapshot yet"
        );
        assert_eq!(
            node.tick().unwrap().reads,
            vec![ReadState {
                id: ask_read,
                index: Some(4)
            }]
        );
        // With an entry after it, the reply is answered with appends from there.
        node.propose(b"w".to_vec()).unwrap();
        reply.read_ctx = 0;
        let next = node.step(reply).unwrap();
        assert_eq!(next[0].msg_type, MsgType::AppendEntries);
        assert_eq!((next[0].last_log_index, next[0].entries.len()), (4, 1));
        // A follower that rejects an append is sent the snapshot again when
        // it needs compacted entries.
        let r = node.step(Message::append_entries_reply(3, 1, t, false, 0)).unwrap();
        assert_eq!(r[0].msg_type, MsgType::InstallSnapshot);
        // A snapshot message from a stale leader is answered with our term.
        let stale = node.step(install_msg(2, 1, t - 1, 9, 9, b"", 9)).unwrap();
        assert_eq!(
            (stale[0].msg_type, stale[0].success, stale[0].term),
            (MsgType::InstallSnapshotReply, false, t)
        );
        // ... and a reply of a stale term is ignored.
        assert!(node
            .step(Message::install_snapshot_reply(2, 1, t - 1, true, 9))
            .unwrap()
            .is_empty());
    }

    #[test]
    fn follower_installs_a_snapshot_in_each_case() {
        let node_with = |entries: &[LogEntry]| {
            let storage = MemoryStorage::new();
            let node = Node::new(classic(2, vec![1, 2, 3]), storage.clone()).unwrap();
            node.step(Message::append_entries(1, 2, 1, 0, 0, entries.to_vec(), 0))
                .unwrap();
            (node, storage)
        };
        let install = |node: &Node, index, term, leader_last| {
            let mut m = install_msg(1, 2, 1, index, term, b"S", index);
            m.leader_last_index = leader_last;
            let r = node.step(m).unwrap();
            (r[0].msg_type, r[0].success, r[0].match_index)
        };
        let log = |last: Index| (1..=last).map(|i| entry(i, 1, b"e")).collect::<Vec<_>>();
        // The log agrees with the snapshot: the entries after it are kept.
        let (node, storage) = node_with(&log(5));
        assert_eq!(install(&node, 3, 1, 5), (MsgType::InstallSnapshotReply, true, 3));
        assert_eq!((node.commit_index(), node.snapshot_index()), (3, 3));
        assert_eq!(node.log_snapshot().1, vec![entry(4, 1, b"e"), entry(5, 1, b"e")]);
        assert_eq!(
            storage.load().unwrap().snapshot.as_deref(),
            Some(&snapshot_of(3, 1, &[1, 2, 3], b"S"))
        );
        // The application gets it on the next tick, once, with nothing after.
        let out = node.tick().unwrap();
        assert_eq!(out.snapshot.as_deref(), Some(&snapshot_of(3, 1, &[1, 2, 3], b"S")));
        assert!(out.committed.is_empty() && node.tick().unwrap().snapshot.is_none());
        // One it already covers is acknowledged with its commit index.
        for index in [1, 3] {
            assert_eq!(install(&node, index, 1, 5), (MsgType::InstallSnapshotReply, true, 3));
        }
        assert!(node.tick().unwrap().snapshot.is_none());
        // Entries after the snapshot commit as usual.
        node.step(Message::append_entries(1, 2, 1, 5, 1, vec![], 5)).unwrap();
        assert_eq!(node.tick().unwrap().committed.len(), 2);
        // The log disagrees at the snapshot's index, or is shorter: replaced.
        let (node, _) = node_with(&log(3));
        assert_eq!(install(&node, 3, 2, 3), (MsgType::InstallSnapshotReply, true, 3));
        assert!(node.log_snapshot().1.is_empty());
        let (node, _) = node_with(&log(1));
        install(&node, 5, 1, 5);
        assert_eq!((node.snapshot_index(), node.log_snapshot().1.len()), (5, 0));
        // An append after the snapshot continues from it; one that needs
        // compacted entries is told where this log ends.
        let r = node
            .step(Message::append_entries(1, 2, 1, 5, 1, vec![entry(6, 1, b"f")], 6))
            .unwrap();
        assert!(r[0].success && r[0].match_index == 6);
        let r = node.step(Message::append_entries(1, 2, 1, 2, 1, vec![], 6)).unwrap();
        assert!(!r[0].success && r[0].match_index == 6);
    }

    #[test]
    fn a_snapshot_ends_recovery_when_it_covers_the_leaders_log() {
        let damaged_node = || {
            let node = Node::new(Config::cluster(1, vec![1, 2, 3]), damaged(1, &[entry(1, 1, b"a")])).unwrap();
            assert!(node.recovering());
            node
        };
        let install = |node: &Node, leader_last| {
            let mut m = install_msg(2, 1, 1, 4, 1, b"S", 4);
            m.leader_last_index = leader_last;
            node.step(m).unwrap();
        };
        let node = damaged_node();
        install(&node, 9);
        assert!(node.recovering(), "the leader has more");
        let node = damaged_node();
        install(&node, 4);
        assert!(!node.recovering());
    }

    #[test]
    fn snapshot_storage_failures_leave_the_node_unchanged() {
        let cfg = || Config::cluster(2, vec![1, 2, 3]);
        let snapshot = || install_msg(1, 2, 0, 4, 0, b"S", 4);
        let n = Node::new(cfg(), Failing::new(1)).unwrap();
        assert!(n.step(snapshot()).is_err());
        assert_eq!((n.snapshot_index(), n.commit_index()), (0, 0));
        assert!(n.tick().unwrap().snapshot.is_none());
        // The snapshot is in, but leaving recovery failed: it stays recovering.
        let recovering = DurableState {
            recovering: true,
            ..DurableState::default()
        };
        let n = Node::new(cfg(), Failing::with_state(2, recovering)).unwrap();
        let mut m = snapshot();
        m.leader_last_index = 4;
        assert!(n.step(m).is_err());
        assert!(n.recovering());
        assert_eq!(n.snapshot_index(), 4);
        // Compacting.
        // (the budget covers load, the vote, the empty entry and two proposals)
        let n = Node::new(Config::single(1), Failing::new(5)).unwrap();
        leader_of(&n, 20);
        n.propose(b"a".to_vec()).unwrap();
        n.propose(b"b".to_vec()).unwrap();
        n.tick().unwrap();
        assert_eq!(n.compact(1, vec![]), Err(Error::Storage("disk gone".into())));
        assert_eq!(n.snapshot_index(), 0);
    }

    #[test]
    fn a_lagging_follower_catches_up_through_a_snapshot() {
        let mut net = Net::new(3);
        net.run(60, &[]);
        let leader = net.leaders(&[])[0];
        let lag = (1..=3).find(|&i| i != leader).unwrap();
        for i in 0..10u8 {
            net.node(leader).propose(vec![i]).unwrap();
        }
        let before = net.node(lag).commit_index();
        net.run(20, &[lag]);
        let applied = net.applied[(leader - 1) as usize].len() as Index;
        assert!(applied >= 10 && net.node(lag).commit_index() == before);
        // The leader snapshots and drops its log: the entries the follower
        // misses exist only in the snapshot now.
        net.node(leader).compact(applied, b"state".to_vec()).unwrap();
        assert!(net.node(leader).log_snapshot().1.is_empty());
        net.run(30, &[]);
        assert_eq!(net.node(lag).snapshot_index(), applied);
        assert_eq!(net.snapshots[(lag - 1) as usize].len(), 1);
        assert_eq!(net.snapshots[(lag - 1) as usize][0].data, b"state");
        assert_eq!(net.node(lag).commit_index(), applied);
        // It keeps replicating normally from there.
        net.node(leader).propose(b"after".to_vec()).unwrap();
        net.run(20, &[]);
        let want = net.node(leader).log_snapshot().1;
        assert_eq!(want.len(), 1);
        assert_eq!(net.node(lag).log_snapshot().1, want);
        assert_eq!(net.node(lag).commit_index(), applied + 1);
        assert_eq!(net.applied[(lag - 1) as usize].last(), want.last());
    }

    /// Ticks `node` until it asks for pre-votes; returns those messages.
    fn pre_campaign(node: &Node) -> Vec<Message> {
        loop {
            let out = node.tick().unwrap().messages;
            if node.role() == NodeState::PreCandidate {
                return out;
            }
        }
    }

    #[test]
    fn pre_vote_changes_nothing_until_a_majority_promises() {
        let storage = MemoryStorage::new();
        let node = Node::new(Config::cluster(1, vec![1, 2, 3]), storage.clone()).unwrap();
        let asks = pre_campaign(&node);
        assert_eq!(asks.len(), 2);
        assert!(asks.iter().all(|m| m.msg_type == MsgType::PreVote && m.term == 1));
        // Asking changed neither the term nor the vote, in memory or on disk.
        assert_eq!((node.term(), storage.load().unwrap().term), (0, 0));
        assert_eq!(storage.load().unwrap().voted_for, None);
        // Refusals (same term, or an older one) change nothing either.
        assert!(node.step(Message::pre_vote_reply(2, 1, 0, false)).unwrap().is_empty());
        assert_eq!(node.role(), NodeState::PreCandidate);
        // A promise for a term that is not the one asked for is ignored.
        assert!(node.step(Message::pre_vote_reply(2, 1, 7, true)).unwrap().is_empty());
        assert_eq!(node.role(), NodeState::PreCandidate);
        // One promise makes a majority of three: the real campaign starts.
        let votes = node.step(Message::pre_vote_reply(2, 1, 1, true)).unwrap();
        assert_eq!((node.role(), node.term()), (NodeState::Candidate, 1));
        assert_eq!(votes.len(), 2);
        assert!(votes.iter().all(|m| m.msg_type == MsgType::RequestVote && m.term == 1));
        assert_eq!(storage.load().unwrap().voted_for, Some(1));
        // A late promise from the other peer changes nothing.
        assert!(node.step(Message::pre_vote_reply(3, 1, 1, true)).unwrap().is_empty());
        // Promises to a node that is not asking are ignored.
        let follower = Node::new(Config::cluster(1, vec![1, 2, 3]), MemoryStorage::new()).unwrap();
        assert!(follower
            .step(Message::pre_vote_reply(2, 1, 1, true))
            .unwrap()
            .is_empty());
        assert_eq!(follower.role(), NodeState::Follower);
        // Without a majority of promises, a five-node asker keeps asking.
        let five = Node::new(Config::cluster(1, vec![1, 2, 3, 4, 5]), MemoryStorage::new()).unwrap();
        pre_campaign(&five);
        five.step(Message::pre_vote_reply(2, 1, 1, true)).unwrap();
        assert_eq!((five.role(), five.term()), (NodeState::PreCandidate, 0));
        // A refusal from a node in a later term makes the asker catch up.
        five.step(Message::pre_vote_reply(3, 1, 9, false)).unwrap();
        assert_eq!((five.role(), five.term()), (NodeState::Follower, 9));
    }

    #[test]
    fn pre_vote_is_granted_only_to_a_candidate_that_could_win() {
        let mut log = Log::new();
        log.append(&[entry(1, 2, b"a"), entry(2, 2, b"b")]).unwrap();
        let state = |recovering| DurableState {
            term: 2,
            voted_for: Some(3),
            log: log.clone(),
            recovering,
            snapshot: None,
        };
        let node = |recovering| {
            let s = MemoryStorage::with_state(state(recovering));
            (Node::new(Config::cluster(1, vec![1, 2, 3]), s.clone()).unwrap(), s)
        };
        let ask = |n: &Node, term, idx, last_term| {
            let r = n.step(Message::pre_vote(2, 1, term, idx, last_term)).unwrap();
            (r[0].msg_type, r[0].vote_granted, r[0].term)
        };
        let (n, s) = node(false);
        // Promised: next term, log at least as up to date. Nothing changes,
        // not even the vote it already gave in this term.
        assert_eq!(ask(&n, 3, 2, 2), (MsgType::PreVoteReply, true, 3));
        assert_eq!(ask(&n, 3, 5, 3), (MsgType::PreVoteReply, true, 3));
        assert_eq!((n.term(), s.load().unwrap().voted_for), (2, Some(3)));
        // Refused with our own term: log behind, or not a later term.
        assert_eq!(ask(&n, 3, 1, 2), (MsgType::PreVoteReply, false, 2));
        assert_eq!(ask(&n, 3, 9, 1), (MsgType::PreVoteReply, false, 2));
        assert_eq!(ask(&n, 2, 9, 9), (MsgType::PreVoteReply, false, 2));
        assert_eq!(ask(&n, 1, 9, 9), (MsgType::PreVoteReply, false, 2));
        // Refused while a leader is heard from, even with a better log.
        n.step(Message::append_entries(3, 1, 2, 2, 2, vec![], 0)).unwrap();
        assert_eq!(ask(&n, 3, 9, 9), (MsgType::PreVoteReply, false, 2));
        // ... and by a leader itself.
        let leader = Node::new(Config::single(1), MemoryStorage::new()).unwrap();
        leader_of(&leader, 20);
        let l = Node::new(classic(1, vec![1, 2, 3]), MemoryStorage::new()).unwrap();
        campaign(&l);
        let t = l.term();
        l.step(Message::request_vote_reply(2, 1, t, true)).unwrap();
        assert_eq!(l.role(), NodeState::Leader);
        let r = l.step(Message::pre_vote(2, 1, t + 1, 9, 9)).unwrap();
        assert!(!r[0].vote_granted && r[0].term == t);
        // A recovering node never promises.
        let (n, _) = node(true);
        assert_eq!(ask(&n, 3, 9, 9), (MsgType::PreVoteReply, false, 2));
    }

    /// What pre-vote is for: a node cut off from the cluster keeps its term,
    /// so it cannot depose the leader when it comes back.
    #[test]
    fn isolated_node_does_not_disturb_the_cluster_when_it_returns() {
        let run = |pre_vote: bool| {
            let mut net = Net::with_pre_vote(3, pre_vote);
            net.run(60, &[]);
            let leader = net.leaders(&[])[0];
            let (term, loner) = (net.node(leader).term(), (1..=3).find(|&i| i != leader).unwrap());
            net.run(300, &[loner]);
            let isolated_term = net.node(loner).term();
            net.run(60, &[]);
            let after = (net.leaders(&[]), net.node(leader).term());
            (term, isolated_term, after, leader)
        };
        let (term, isolated, (leaders, now), leader) = run(true);
        assert_eq!((isolated, now, leaders), (term, term, vec![leader]), "pre-vote on");
        let (term, isolated, (_, now), _) = run(false);
        assert!(
            isolated > term + 5 && now >= isolated,
            "classic: {term} {isolated} {now}"
        );
    }

    fn damaged(term: Term, entries: &[LogEntry]) -> Arc<MemoryStorage> {
        let mut log = Log::new();
        log.append(entries).unwrap();
        MemoryStorage::with_state(DurableState {
            term,
            voted_for: None,
            log,
            recovering: true,
            snapshot: None,
        })
    }

    #[test]
    fn recovering_node_neither_votes_nor_campaigns() {
        let storage = damaged(2, &[entry(1, 2, b"a")]);
        let node = Node::new(Config::cluster(1, vec![1, 2, 3]), storage.clone()).unwrap();
        assert!(node.recovering());
        for _ in 0..200 {
            assert!(node.tick().unwrap().messages.is_empty());
        }
        assert_eq!((node.role(), node.term()), (NodeState::Follower, 2));
        // Even a candidate far ahead is refused, in this term and the next.
        assert!(!node.step(Message::request_vote(2, 1, 2, 9, 9)).unwrap()[0].vote_granted);
        assert!(!node.step(Message::request_vote(2, 1, 3, 9, 9)).unwrap()[0].vote_granted);
        assert_eq!(storage.load().unwrap().voted_for, None);
    }

    #[test]
    fn recovering_node_rejoins_once_it_has_the_leaders_whole_log() {
        // Our damaged log kept a stale entry 2 the leader does not have.
        let storage = damaged(2, &[entry(1, 2, b"a"), entry(2, 2, b"stale")]);
        let node = Node::new(Config::cluster(1, vec![1, 2, 3]), storage.clone()).unwrap();
        let append = |prev: Index, prev_term: Term, entries: Vec<LogEntry>, leader_last: Index| {
            let mut m = Message::append_entries(2, 1, 3, prev, prev_term, entries, 0);
            m.leader_last_index = leader_last;
            node.step(m).unwrap()
        };
        // Matches up to 1 only: the leftover entry 2 does not count.
        assert!(append(1, 2, vec![], 2)[0].success);
        assert!(node.recovering());
        // A partial batch is not enough either.
        assert!(append(1, 2, vec![entry(2, 3, b"b")], 3)[0].success);
        assert!(node.recovering() && storage.load().unwrap().recovering);
        assert!(append(2, 3, vec![entry(3, 3, b"c")], 3)[0].success);
        assert!(!node.recovering() && !storage.load().unwrap().recovering);
        // Back to normal: votes are granted again.
        let r = node.step(Message::request_vote(3, 1, 4, 3, 3)).unwrap();
        assert!(r[0].vote_granted);
    }

    #[test]
    fn damaged_follower_catches_up_in_a_cluster() {
        let mut net = Net::new(3);
        net.run(60, &[]);
        let leader = net.leaders(&[])[0];
        for i in 0..5u8 {
            net.node(leader).propose(vec![i]).unwrap();
        }
        net.run(10, &[]);
        // A follower restarts having lost all but its first entry; the
        // leader still believes it has all 5.
        let f = (1..=3).find(|&id| id != leader).unwrap();
        let (term, entries) = net.node(f).log_snapshot();
        let voters: Vec<NodeId> = (1..=3).collect();
        net.nodes[(f - 1) as usize] = Node::new(Config::cluster(f, voters), damaged(term, &entries[..1])).unwrap();
        assert!(net.node(f).recovering());
        for i in 5..8u8 {
            net.node(leader).propose(vec![i]).unwrap();
        }
        net.run(20, &[]);
        assert!(!net.node(f).recovering());
        assert_eq!(net.node(f).log_snapshot().1, net.node(leader).log_snapshot().1);
        assert_eq!(net.node(f).commit_index(), 9, "the empty entry, eight proposals");
    }

    impl Net {
        /// Nodes `1..=voters` form the cluster; the `joiners` after them
        /// wait to be added.
        fn joined(voters: u64, joiners: u64) -> Self {
            let mut net = Net::new(voters);
            for id in voters + 1..=voters + joiners {
                net.nodes
                    .push(Node::new(Config::joiner(id), MemoryStorage::new()).unwrap());
                net.applied.push(Vec::new());
                net.reads.push(Vec::new());
                net.snapshots.push(Vec::new());
            }
            net
        }
    }

    fn refused<T>(why: &'static str) -> Result<T> {
        Err(Error::BadConfig(why))
    }

    #[test]
    fn a_server_joins_as_a_learner_and_is_promoted() {
        let mut net = Net::joined(3, 1);
        net.run(60, &[]);
        let leader = net.leaders(&[])[0];
        let follower = (1..=3).find(|&i| i != leader).unwrap();
        // Only the leader changes the cluster.
        let f = net.node(follower);
        let not_leader = || Error::NotLeader(Some(leader));
        assert_eq!(f.add_learner(4), Err(not_leader()));
        assert_eq!(f.remove_learner(4), Err(not_leader()));
        assert_eq!(f.add_voter(4), Err(not_leader()));
        assert_eq!(f.remove_voter(1), Err(not_leader()));
        // What the leader refuses.
        assert_eq!(net.node(leader).add_learner(leader), refused("this node is the leader"));
        assert_eq!(net.node(leader).add_learner(follower), refused("already a voter"));
        assert_eq!(net.node(leader).remove_learner(4), refused("not a learner"));
        assert_eq!(
            net.node(leader).add_voter(4),
            refused("not a learner, add it as one first")
        );
        assert_eq!(net.node(leader).add_voter(follower), refused("already a voter"));
        assert_eq!(net.node(leader).remove_voter(9), refused("not a voter"));
        // A learner gets the log, and does not vote or campaign.
        net.node(leader).add_learner(4).unwrap();
        assert_eq!(net.node(leader).learners(), vec![4]);
        net.run(40, &[]);
        let joiner = net.node(4);
        assert_eq!(joiner.log_snapshot().1, net.node(leader).log_snapshot().1);
        assert_eq!(
            (joiner.role(), joiner.term()),
            (NodeState::Follower, net.node(leader).term())
        );
        assert!(joiner.voters().is_empty());
        assert_eq!(net.node(leader).voters(), vec![1, 2, 3]);
        // It can be dropped again, and picked up again.
        net.node(leader).remove_learner(4).unwrap();
        assert!(net.node(leader).learners().is_empty());
        net.node(leader).add_learner(4).unwrap();
        net.run(40, &[]);
        // Promoted: in effect on the leader at once, committed by a majority
        // of the four, and one change at a time.
        let index = net.node(leader).add_voter(4).unwrap();
        assert_eq!(net.node(leader).voters(), vec![1, 2, 3, 4]);
        assert!(net.node(leader).learners().is_empty() && net.node(leader).config_pending());
        assert_eq!(
            net.node(leader).remove_voter(follower),
            refused("the previous change is not committed yet")
        );
        net.run(40, &[]);
        assert!(!net.node(leader).config_pending());
        for n in &net.nodes {
            assert_eq!(n.voters(), vec![1, 2, 3, 4]);
            assert!(n.commit_index() >= index);
        }
        // The new voter takes part: of the four, the leader and node 4 are
        // not a majority, and with one more of the old ones they are.
        let old: Vec<NodeId> = (1..=3).filter(|&i| i != leader).collect();
        let four = net.node(leader).propose(b"four".to_vec()).unwrap();
        net.run(20, &old);
        assert!(net.node(leader).commit_index() < four);
        net.run(30, &old[..1]);
        assert_eq!(net.node(leader).commit_index(), four);
        assert_eq!(net.node(4).commit_index(), four);
        assert!(net.node(4).log_snapshot().1.last().is_some_and(|e| e.data == b"four"));
    }

    #[test]
    fn a_removed_server_is_replicated_to_until_the_change_commits_and_then_left_alone() {
        let (node, t) = committed_leader();
        // Who the leader sends to within one heartbeat interval.
        let targets = |node: &Node| {
            let mut to: Vec<NodeId> = (0..3)
                .flat_map(|_| node.tick().unwrap().messages)
                .map(|m| m.to)
                .collect();
            to.sort_unstable();
            to.dedup();
            to
        };
        assert_eq!(targets(&node), vec![2, 3]);
        let index = node.remove_voter(3).unwrap();
        assert_eq!((index, node.voters(), node.config_pending()), (3, vec![1, 2], true));
        // Node 3 may be needed to commit it, so it still gets entries.
        assert_eq!(targets(&node), vec![2, 3]);
        // A majority of the new two commits it: node 1 and node 2.
        node.step(Message::append_entries_reply(2, 1, t, true, 3)).unwrap();
        assert_eq!((node.commit_index(), node.config_pending()), (3, false));
        assert_eq!(targets(&node), vec![2]);
        // A late reply from the removed server is old news.
        assert!(node
            .step(Message::append_entries_reply(3, 1, t, true, 3))
            .unwrap()
            .is_empty());
        assert!(node
            .step(Message::append_entries_reply(9, 1, t, false, 0))
            .unwrap()
            .is_empty());
        // Its votes and requests count for nothing, as it is no member now.
        assert_eq!(node.step(Message::request_vote(3, 1, t + 1, 9, 9)), Ok(vec![]));
        assert_eq!(node.term(), t);
    }

    #[test]
    fn a_leader_that_removes_itself_steps_down_when_the_change_commits() {
        let mut net = Net::new(3);
        net.run(60, &[]);
        let old = net.leaders(&[])[0];
        let term = net.node(old).term();
        let l = net.node(old);
        let index = l.remove_voter(old).unwrap();
        assert_eq!(l.role(), NodeState::Leader, "until it commits");
        assert!(!l.voters().contains(&old));
        net.run(1, &[]);
        net.run(60, &[]);
        assert!(net.node(old).commit_index() >= index);
        assert_eq!(net.node(old).role(), NodeState::Follower);
        assert_eq!(net.node(old).leader(), None);
        let new = net.leaders(&[]);
        assert_eq!(new.len(), 1);
        assert_ne!(new[0], old);
        assert!(net.node(new[0]).term() > term);
        // It stays out: it never campaigns, and the others never count it.
        let after = net.node(new[0]).term();
        net.run(300, &[]);
        assert_eq!((net.leaders(&[]), net.node(new[0]).term()), (new, after));
        assert_eq!(net.node(old).role(), NodeState::Follower);
    }

    #[test]
    fn a_server_that_is_being_removed_keeps_its_place_until_the_change_commits() {
        // Node 2 holds an uncommitted entry that removes it, and nothing else
        // knows about that entry: it may still have to lead.
        let node = Node::new(classic(2, vec![1, 2, 3]), MemoryStorage::new()).unwrap();
        let append = |entries: Vec<LogEntry>, commit| {
            node.step(Message::append_entries(1, 2, 1, 0, 0, entries, commit))
                .unwrap();
        };
        append(vec![entry(1, 1, b"a"), LogEntry::config(2, 1, &[1, 3])], 1);
        assert_eq!(node.voters(), vec![1, 3]);
        assert!(node.config_pending());
        // No leader in earshot: it campaigns, though it is not in the voter
        // set it uses, and only the votes of that set count.
        let asks = campaign(&node);
        assert_eq!(asks.iter().map(|m| m.to).collect::<Vec<_>>(), vec![1, 3]);
        let t = node.term();
        node.step(Message::request_vote_reply(1, 2, t, true)).unwrap();
        assert_eq!(
            node.role(),
            NodeState::Candidate,
            "one vote of two: it does not count itself"
        );
        node.step(Message::request_vote_reply(3, 2, t, true)).unwrap();
        assert_eq!(node.role(), NodeState::Leader);
        // It commits its own removal with 1 and 3 together, then hands over.
        node.step(Message::append_entries_reply(1, 2, t, true, 3)).unwrap();
        assert_eq!(node.role(), NodeState::Leader, "the entry needs both of the two");
        node.step(Message::append_entries_reply(3, 2, t, true, 3)).unwrap();
        assert_eq!((node.role(), node.leader()), (NodeState::Follower, None));
    }

    #[test]
    fn votes_from_servers_outside_the_configuration_do_not_count() {
        // The log holds an uncommitted configuration without node 2, which
        // is still a voter of the committed one. Node 1 campaigns with it.
        let mut log = Log::new();
        log.append(&[LogEntry::config(1, 1, &[1, 3, 5])]).unwrap();
        let storage = MemoryStorage::with_state(DurableState {
            term: 1,
            log,
            ..DurableState::default()
        });
        let node = Node::new(classic(1, vec![1, 2, 3]), storage).unwrap();
        let asks = campaign(&node);
        assert_eq!(asks.iter().map(|m| m.to).collect::<Vec<_>>(), vec![3, 5]);
        let t = node.term();
        node.step(Message::request_vote_reply(2, 1, t, true)).unwrap();
        assert_eq!(node.role(), NodeState::Candidate, "node 2 is not a voter of [1, 3, 5]");
        node.step(Message::request_vote_reply(3, 1, t, true)).unwrap();
        assert_eq!(node.role(), NodeState::Leader);
        // Pre-votes are counted the same way.
        let node = Node::new(Config::cluster(1, vec![1, 3, 5]), MemoryStorage::new()).unwrap();
        pre_campaign(&node);
        node.step(Message::pre_vote_reply(9, 1, 1, true)).unwrap();
        assert_eq!(node.role(), NodeState::PreCandidate);
    }

    #[test]
    fn nodes_without_a_place_never_campaign() {
        let joiner = Node::new(Config::joiner(4), MemoryStorage::new()).unwrap();
        for _ in 0..200 {
            assert!(joiner.tick().unwrap().messages.is_empty());
        }
        assert_eq!((joiner.role(), joiner.term()), (NodeState::Follower, 0));
        // A node that the log removed does not either, once that committed.
        let node = Node::new(classic(2, vec![1, 2, 3]), MemoryStorage::new()).unwrap();
        node.step(Message::append_entries(
            1,
            2,
            1,
            0,
            0,
            vec![entry(1, 1, b"a"), LogEntry::config(2, 1, &[1, 3])],
            2,
        ))
        .unwrap();
        assert!(!node.config_pending());
        for _ in 0..200 {
            assert!(node.tick().unwrap().messages.is_empty());
        }
        assert_eq!(node.role(), NodeState::Follower);
        // The configured voters are kept ascending and without duplicates.
        let node = Node::new(Config::cluster(1, vec![3, 1, 2, 2]), MemoryStorage::new()).unwrap();
        assert_eq!(node.voters(), vec![1, 2, 3]);
    }

    #[test]
    fn membership_changes_wait_for_an_entry_of_the_leaders_term() {
        let node = Node::new(classic(1, vec![1, 2, 3]), MemoryStorage::new()).unwrap();
        assert_eq!(node.remove_voter(3), Err(Error::NotLeader(None)));
        campaign(&node);
        let t = node.term();
        node.step(Message::request_vote_reply(2, 1, t, true)).unwrap();
        // Its own empty entry is not committed yet.
        assert_eq!(node.remove_voter(3), Err(Error::NotReady));
        node.add_learner(4).unwrap();
        assert_eq!(node.add_voter(4), Err(Error::NotReady));
        node.step(Message::append_entries_reply(2, 1, t, true, 1)).unwrap();
        // The learner must have everything committed.
        assert_eq!(
            node.add_voter(4),
            Err(Error::BadConfig("the learner has not caught up"))
        );
        node.step(Message::append_entries_reply(4, 1, t, true, 1)).unwrap();
        assert_eq!(node.add_voter(4), Ok(2));
        let pending = Err(Error::BadConfig("the previous change is not committed yet"));
        assert_eq!(node.add_voter(4), pending);
        assert_eq!(node.voters(), vec![1, 2, 3, 4]);
        assert!(node.learners().is_empty());
        // Four voters: the entry commits with three of them.
        node.step(Message::append_entries_reply(2, 1, t, true, 2)).unwrap();
        assert!(node.config_pending());
        node.step(Message::append_entries_reply(4, 1, t, true, 2)).unwrap();
        assert!(!node.config_pending());
        assert_eq!(node.add_voter(4), Err(Error::BadConfig("already a voter")));
        // The last voter is never removed.
        let single = Node::new(Config::single(1), MemoryStorage::new()).unwrap();
        leader_of(&single, 20);
        assert_eq!(
            single.remove_voter(1),
            Err(Error::BadConfig("cannot remove the last voter"))
        );
    }

    #[test]
    fn a_configuration_entry_that_cannot_be_stored_is_not_in_effect() {
        // The budget covers the load, the vote and the leader's empty entry.
        let node = Node::new(classic(1, vec![1, 2, 3]), Failing::new(3)).unwrap();
        campaign(&node);
        let t = node.term();
        node.step(Message::request_vote_reply(2, 1, t, true)).unwrap();
        node.step(Message::append_entries_reply(2, 1, t, true, 1)).unwrap();
        assert_eq!(node.remove_voter(3), Err(Error::Storage("disk gone".into())));
        assert_eq!((node.voters(), node.log_snapshot().1.len()), (vec![1, 2, 3], 1));
        // The same promoting a learner: it stays a learner.
        let node = Node::new(classic(1, vec![1, 2, 3]), Failing::new(3)).unwrap();
        campaign(&node);
        let t = node.term();
        node.step(Message::request_vote_reply(2, 1, t, true)).unwrap();
        node.step(Message::append_entries_reply(2, 1, t, true, 1)).unwrap();
        node.add_learner(4).unwrap();
        node.step(Message::append_entries_reply(4, 1, t, true, 1)).unwrap();
        assert_eq!(node.add_voter(4), Err(Error::Storage("disk gone".into())));
        assert_eq!((node.voters(), node.learners()), (vec![1, 2, 3], vec![4]));
    }

    #[test]
    fn the_configuration_travels_with_snapshots() {
        // A leader of one adds node 2, and snapshots after that.
        let storage = MemoryStorage::new();
        let node = Node::new(Config::single(1), storage.clone()).unwrap();
        leader_of(&node, 20);
        let t = node.term();
        node.add_learner(2).unwrap();
        node.step(Message::append_entries_reply(2, 1, t, true, 1)).unwrap();
        let index = node.add_voter(2).unwrap();
        node.step(Message::append_entries_reply(2, 1, t, true, index)).unwrap();
        assert!(!node.config_pending());
        node.tick().unwrap();
        node.propose(b"after".to_vec()).unwrap();
        node.step(Message::append_entries_reply(2, 1, t, true, index + 1))
            .unwrap();
        node.tick().unwrap();
        node.compact(index + 1, b"state".to_vec()).unwrap();
        let stored = storage.load().unwrap().snapshot.unwrap();
        assert_eq!(stored.voters, vec![1, 2]);
        // The log no longer holds the entry; after a restart the snapshot
        // says who the voters are, not the configured list.
        drop(node);
        let node = Node::new(Config::single(1), storage).unwrap();
        assert_eq!(node.voters(), vec![1, 2]);
        // A follower that installs a snapshot takes its configuration.
        let follower = Node::new(classic(2, vec![1, 2, 3]), MemoryStorage::new()).unwrap();
        let snapshot = Arc::new(snapshot_of(5, 1, &[2, 3, 4], b"S"));
        follower.step(Message::install_snapshot(1, 2, 1, snapshot, 5)).unwrap();
        assert_eq!(follower.voters(), vec![2, 3, 4]);
        // The snapshot message must carry a snapshot, and entries a valid
        // configuration.
        let empty = Message {
            msg_type: MsgType::InstallSnapshot,
            ..Message::request_vote(1, 2, 1, 0, 0)
        };
        assert_eq!(
            follower.step(empty),
            Err(Error::BadSnapshot("InstallSnapshot without a snapshot"))
        );
        let bad = LogEntry {
            kind: crate::EntryKind::Config,
            ..entry(6, 1, b"not voters")
        };
        let err = follower.step(Message::append_entries(1, 2, 1, 5, 1, vec![bad], 0));
        assert_eq!(err, Err(Error::LogInconsistency(LogError::BadConfig { index: 6 })));
    }
}
