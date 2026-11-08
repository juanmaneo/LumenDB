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
    next_index: BTreeMap<NodeId, Index>,
    match_index: BTreeMap<NodeId, Index>,
    rng: u64,
    clock: LamportClock,
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
        let DurableState { term, voted_for, log } = storage.load()?;
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
                next_index: BTreeMap::new(),
                match_index: BTreeMap::new(),
                rng,
                clock: LamportClock::new(),
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
                self.campaign(&mut s, &mut messages)?;
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
        if msg.term > s.term {
            self.storage.save_vote(msg.term, None)?;
            s.term = msg.term;
            s.voted_for = None;
            s.leader_id = None;
            s.role = NodeState::Follower;
        }
        let reply = if msg.term < s.term {
            self.stale_reply(&s, &msg)
        } else {
            match msg.msg_type {
                MsgType::RequestVote => Some(self.on_request_vote(&mut s, &msg)?),
                MsgType::RequestVoteReply => {
                    self.on_vote_reply(&mut s, &msg);
                    None
                }
                MsgType::AppendEntries => Some(self.on_append(&mut s, &msg)?),
                MsgType::AppendEntriesReply => self.on_append_reply(&mut s, &msg),
            }
        };
        Ok(reply.into_iter().map(|m| Self::send(&mut s, m)).collect())
    }

    fn send(s: &mut Inner, mut m: Message) -> Message {
        m.lc = s.clock.stamp();
        m
    }

    fn stale_reply(&self, s: &Inner, msg: &Message) -> Option<Message> {
        match msg.msg_type {
            MsgType::RequestVote => Some(Message::request_vote_reply(self.cfg.id, msg.from, s.term, false)),
            MsgType::AppendEntries => Some(Message::append_entries_reply(self.cfg.id, msg.from, s.term, false, 0)),
            MsgType::RequestVoteReply | MsgType::AppendEntriesReply => None,
        }
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
        Message::append_entries(
            self.cfg.id,
            peer,
            s.term,
            prev,
            prev_term,
            entries[start..end].to_vec(),
            s.commit_index,
        )
    }

    fn on_request_vote(&self, s: &mut Inner, msg: &Message) -> Result<Message> {
        let up_to_date = (msg.last_log_term, msg.last_log_index) >= (s.log.last_term(), s.log.last_index());
        let free = s.voted_for.unwrap_or(msg.from) == msg.from;
        let granted = up_to_date & free;
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
            let matched = s.match_index[&msg.from].max(msg.match_index);
            s.match_index.insert(msg.from, matched);
            self.maybe_commit(s);
            matched + 1
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
            let voters: Vec<NodeId> = (1..=n).collect();
            let nodes: Vec<Node> = voters
                .iter()
                .map(|&id| Node::new(Config::cluster(id, voters.clone()), MemoryStorage::new()).unwrap())
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
        let node = Node::new(Config::cluster(1, vec![1, 2, 3, 4, 5]), MemoryStorage::new()).unwrap();
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
        let node = Node::new(Config::cluster(1, vec![1, 2, 3]), MemoryStorage::new()).unwrap();
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
    }

    #[test]
    fn old_term_entries_need_a_current_term_entry() {
        let mut log = Log::new();
        log.append(&[entry(1, 1, b"old")]).unwrap();
        let storage = MemoryStorage::with_state(DurableState {
            term: 1,
            voted_for: None,
            log,
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
            Arc::new(Failing {
                inner: MemoryStorage::new(),
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
        let n = Node::new(cfg(), Failing::new(1)).unwrap();
        let errs = (0..40).filter(|_| n.tick().is_err()).count();
        assert!(errs > 0);
        assert_eq!((n.term(), n.role()), (0, NodeState::Follower));
        // Proposing.
        let n = Node::new(Config::single(1), Failing::new(2)).unwrap();
        leader_of(&n, 20);
        assert!(n.propose(b"x".to_vec()).is_err());
        assert!(n.log_snapshot().1.is_empty());
    }
}
