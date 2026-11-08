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
//! Committed entries are handed out by `tick()` in index order, exactly once
//! per process lifetime (after a restart they are replayed from index 1 as the
//! commit index is re-learned).

use crate::clock::LamportClock;
use crate::error::{Error, LogError, Result};
use crate::log::{Log, LogEntry};
use crate::message::{Message, MsgType};
use crate::quorum::{is_majority, quorum};
use crate::storage::{DurableState, Storage};
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
    /// Newly committed entries, to apply to the state machine in order.
    pub committed: Vec<LogEntry>,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub id: NodeId,
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
}

pub struct Node {
    cfg: Config,
    /// Voters other than this node, deduplicated.
    peers: Vec<NodeId>,
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
        if !cfg.voters.contains(&cfg.id) {
            return Err(Error::NotConfigured);
        }
        let DurableState {
            term,
            voted_for,
            log,
            recovering,
        } = storage.load()?;
        let peers: BTreeSet<NodeId> = cfg.voters.iter().copied().filter(|&v| v != cfg.id).collect();
        let mut rng = (cfg.seed ^ cfg.id) | 1;
        let election_timeout = random_timeout(&cfg, &mut rng);
        Ok(Node {
            peers: peers.into_iter().collect(),
            storage,
            state: Mutex::new(Inner {
                role: NodeState::Follower,
                term,
                voted_for,
                leader_id: None,
                log,
                commit_index: 0,
                last_applied: 0,
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

    /// Current term and full log.
    pub fn log_snapshot(&self) -> (Term, Vec<LogEntry>) {
        let s = self.state.lock();
        (s.term, s.log.entries().to_vec())
    }

    /// Appends `data` to the leader's log (durably); it commits once a
    /// majority has it. Returns its index.
    pub fn propose(&self, data: Vec<u8>) -> Result<Index> {
        let mut s = self.state.lock();
        if s.role != NodeState::Leader {
            return Err(Error::NotLeader(s.leader_id));
        }
        let entry = LogEntry {
            index: s.log.last_index() + 1,
            term: s.term,
            data,
        };
        let batch = std::slice::from_ref(&entry);
        self.storage.append_entries(batch)?;
        s.log.append(batch).expect("a leader appends at its own tail");
        s.clock.tick();
        Ok(entry.index)
    }

    /// Advances logical time by one tick: heartbeats / replication as leader,
    /// election timeout otherwise. Returns messages and newly committed entries.
    pub fn tick(&self) -> Result<TickOutcome> {
        let mut s = self.state.lock();
        let mut messages = Vec::new();
        if s.role == NodeState::Leader {
            s.heartbeat_elapsed += 1;
            if s.heartbeat_elapsed >= self.cfg.heartbeat_interval {
                s.heartbeat_elapsed = 0;
                for &p in &self.peers {
                    let m = self.append_for(&s, p);
                    messages.push(Self::send(&mut s, m));
                }
            }
            self.maybe_commit(&mut s);
        } else {
            s.election_elapsed += 1;
            if s.election_elapsed >= s.election_timeout {
                if s.recovering {
                    s.election_elapsed = 0;
                } else {
                    self.start_election(&mut s, &mut messages)?;
                }
            }
        }
        let committed = s.log.entries()[s.last_applied as usize..s.commit_index as usize].to_vec();
        s.last_applied = s.commit_index;
        Ok(TickOutcome { messages, committed })
    }

    /// Handles one message from a peer; returns the replies to send.
    pub fn step(&self, msg: Message) -> Result<Vec<Message>> {
        if !self.peers.contains(&msg.from) {
            return Err(Error::UnknownPeer(msg.from));
        }
        let mut s = self.state.lock();
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
        }
        let replies: Vec<Message> = if msg.term < s.term {
            self.stale_reply(&s, &msg).into_iter().collect()
        } else {
            match msg.msg_type {
                MsgType::RequestVote => vec![self.on_request_vote(&mut s, &msg)?],
                MsgType::RequestVoteReply => {
                    self.on_vote_reply(&mut s, &msg);
                    Vec::new()
                }
                MsgType::AppendEntries => vec![self.on_append(&mut s, &msg)?],
                MsgType::AppendEntriesReply => self.on_append_reply(&mut s, &msg).into_iter().collect(),
                MsgType::PreVote => vec![self.on_pre_vote(&s, &msg)],
                MsgType::PreVoteReply => self.on_pre_vote_reply(&mut s, &msg)?,
            }
        };
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
            MsgType::RequestVoteReply | MsgType::AppendEntriesReply | MsgType::PreVoteReply => None,
        }
    }

    /// An election timeout: ask for pre-votes, or campaign right away when
    /// pre-vote is off or there is nobody to ask.
    fn start_election(&self, s: &mut Inner, out: &mut Vec<Message>) -> Result<()> {
        if !self.cfg.pre_vote | self.peers.is_empty() {
            return self.campaign(s, out);
        }
        s.role = NodeState::PreCandidate;
        s.leader_id = None;
        s.pre_votes.clear();
        s.pre_votes.insert(self.cfg.id);
        s.election_elapsed = 0;
        s.election_timeout = random_timeout(&self.cfg, &mut s.rng);
        let (term, last_index, last_term) = (s.term + 1, s.log.last_index(), s.log.last_term());
        for &p in &self.peers {
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
            if is_majority(s.pre_votes.len(), self.peers.len() + 1) {
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
        for &p in &self.peers {
            let m = Message::request_vote(self.cfg.id, p, term, last_index, last_term);
            out.push(Self::send(s, m));
        }
        self.maybe_win(s);
        Ok(())
    }

    fn maybe_win(&self, s: &mut Inner) {
        if is_majority(s.votes.len(), self.peers.len() + 1) {
            s.role = NodeState::Leader;
            s.leader_id = Some(self.cfg.id);
            let next = s.log.last_index() + 1;
            s.next_index = self.peers.iter().map(|&p| (p, next)).collect();
            s.match_index = self.peers.iter().map(|&p| (p, 0)).collect();
            // Heartbeat on the very next tick.
            s.heartbeat_elapsed = self.cfg.heartbeat_interval;
        }
    }

    /// Commits the highest index stored on a majority, if it is from the
    /// current term (Raft §5.4.2: older entries commit only indirectly).
    fn maybe_commit(&self, s: &mut Inner) {
        let mut matched: Vec<Index> = s.match_index.values().copied().collect();
        matched.push(s.log.last_index());
        matched.sort_unstable();
        let candidate = matched[matched.len() - quorum(matched.len())];
        if candidate > s.commit_index && s.log.term_at(candidate) == Some(s.term) {
            s.commit_index = candidate;
        }
    }

    fn append_for(&self, s: &Inner, peer: NodeId) -> Message {
        let prev = s.next_index[&peer] - 1;
        let prev_term = s.log.term_at(prev).unwrap_or(0);
        let entries = s.log.entries();
        let start = (prev as usize).min(entries.len());
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

    fn on_vote_reply(&self, s: &mut Inner, msg: &Message) {
        if (s.role == NodeState::Candidate) & msg.vote_granted {
            s.votes.insert(msg.from);
            self.maybe_win(s);
        }
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

    fn on_append_reply(&self, s: &mut Inner, msg: &Message) -> Option<Message> {
        if s.role != NodeState::Leader {
            return None;
        }
        let next = if msg.success {
            // Trust the reply even if it is lower than before: a follower
            // that lost entries to storage damage reports what it really has
            // (a reordered older reply only causes a harmless resend).
            s.match_index.insert(msg.from, msg.match_index);
            self.maybe_commit(s);
            msg.match_index + 1
        } else {
            (s.next_index[&msg.from] - 1)
                .min(msg.match_index.saturating_add(1))
                .max(1)
        };
        s.next_index.insert(msg.from, next);
        let more = (next <= s.log.last_index()) | !msg.success;
        more.then(|| self.append_for(s, msg.from))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryStorage;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn entry(index: Index, term: Term, data: &[u8]) -> LogEntry {
        LogEntry {
            index,
            term,
            data: data.to_vec(),
        }
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
        assert_eq!(node.propose(b"cmd-1".to_vec()).unwrap(), 1);
        let committed = node.tick().unwrap().committed;
        assert_eq!(committed, vec![entry(1, node.term(), b"cmd-1")]);
        assert!(node.tick().unwrap().committed.is_empty(), "applied once");
        assert_eq!(node.commit_index(), 1);
        let (term, entries) = node.log_snapshot();
        assert!(term >= 1 && entries.len() == 1);
        assert!(node.logical_time() > 0);
    }

    #[test]
    fn configuration_errors() {
        let mut cfg = Config::single(1);
        cfg.voters = vec![2];
        assert_eq!(Node::new(cfg, MemoryStorage::new()).err(), Some(Error::NotConfigured));
        let node = Node::new(Config::cluster(1, vec![1, 2, 3]), MemoryStorage::new()).unwrap();
        assert_eq!(node.propose(b"x".to_vec()), Err(Error::NotLeader(None)));
        assert_eq!(
            node.step(Message::request_vote(9, 1, 1, 0, 0)),
            Err(Error::UnknownPeer(9))
        );
        assert_eq!(
            node.step(Message::request_vote(1, 1, 1, 0, 0)),
            Err(Error::UnknownPeer(1))
        );
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
            assert_eq!(applied.len(), 3);
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
        assert_eq!(reference.len(), 4);
        for n in &net.nodes {
            assert_eq!(n.log_snapshot().1, reference);
            assert_eq!(n.commit_index(), 4);
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
        // Peer 2 reports a gap: resend from its hint.
        let r = node.step(Message::append_entries_reply(2, 1, t, false, 0)).unwrap();
        assert_eq!((r[0].last_log_index, r[0].entries.len()), (0, 2));
        // Peer 2 caught up fully: nothing more to send, both entries commit
        // (entry 1 indirectly, through the current-term entry 2).
        let r = node.step(Message::append_entries_reply(2, 1, t, true, 2)).unwrap();
        assert!(r.is_empty());
        assert_eq!(node.commit_index(), 2);
        // Peer 3 has only entry 1: the rest is sent right away.
        let r = node.step(Message::append_entries_reply(3, 1, t, true, 1)).unwrap();
        assert_eq!((r[0].last_log_index, r[0].entries.len()), (1, 1));
        assert_eq!(r[0].leader_last_index, 2);
        // Peer 2 lost entries since it acknowledged 2: believe it and resend.
        let r = node.step(Message::append_entries_reply(2, 1, t, true, 0)).unwrap();
        assert_eq!((r[0].last_log_index, r[0].entries.len()), (0, 2));
        assert_eq!(node.commit_index(), 2, "commit never goes back");
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
        });
        let node = Node::new(Config::single(1), storage).unwrap();
        leader_of(&node, 20);
        node.tick().unwrap();
        assert_eq!(node.commit_index(), 0);
        node.propose(b"new".to_vec()).unwrap();
        assert_eq!(node.tick().unwrap().committed.len(), 2);
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
        // Proposing.
        let n = Node::new(Config::single(1), Failing::new(2)).unwrap();
        leader_of(&n, 20);
        assert!(n.propose(b"x".to_vec()).is_err());
        assert!(n.log_snapshot().1.is_empty());
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
        assert_eq!(net.node(f).commit_index(), 8);
    }
}
