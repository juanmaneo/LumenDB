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
//! - log matching (every few ticks): two logs with the same term at an index
//!   are identical up to it.
//!
//! Then faults stop, every replica restarts and the cluster must converge:
//! one leader, nobody recovering, identical logs and commit indices.
//! Corruption hits at most a minority of replicas at a time, so the
//! cluster can always recover. Safety holds even beyond that; only liveness
//! needs the bound.

use crate::error::Error;
use crate::log::LogEntry;
use crate::message::Message;
use crate::node::{Config, Node, NodeState, ReadState};
use crate::storage::FileStorage;
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
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimConfig {
    pub replicas: u64,
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
    }

    /// The counters, without the seed.
    pub fn summary(&self) -> String {
        format!(
            "committed {}, elections {}, crashes {}, corruptions {}, recoveries {}, io errors {}, \
             partitions {}, reads {} served / {} failed, messages {} delivered / {} dropped",
            self.committed,
            self.elections,
            self.crashes,
            self.corruptions,
            self.recoveries,
            self.io_errors,
            self.partitions,
            self.reads_served,
            self.reads_failed,
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

/// The safety oracle: everything any replica ever reported.
#[derive(Default)]
struct Checker {
    leaders: BTreeMap<Term, NodeId>,
    /// Each committed entry, with the lowest term it was seen committed in.
    committed: BTreeMap<Index, (LogEntry, Term)>,
}

impl Checker {
    /// `id` leads `term`; returns whether that is news. A new leader must
    /// hold every entry committed in an earlier term.
    fn leader(&mut self, id: NodeId, term: Term, log: &dyn Fn() -> Vec<LogEntry>) -> Result<bool, String> {
        match self.leaders.entry(term) {
            Entry::Occupied(o) if *o.get() == id => Ok(false),
            Entry::Occupied(o) => Err(format!("two leaders in term {term}: {} and {id}", o.get())),
            Entry::Vacant(v) => {
                v.insert(id);
                let log = log();
                for (&i, (e, t)) in &self.committed {
                    if (*t < term) & (log.get(i as usize - 1) != Some(e)) {
                        return Err(format!("leader {id} of term {term} lacks committed entry {i}"));
                    }
                }
                Ok(true)
            }
        }
    }

    /// `id`, in `term`, sees `entries` committed.
    fn commit(&mut self, id: NodeId, term: Term, entries: &[LogEntry]) -> Result<(), String> {
        for e in entries {
            match self.committed.entry(e.index) {
                Entry::Vacant(v) => {
                    v.insert((e.clone(), term));
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

/// Log matching over every pair of `logs`.
fn log_matching(logs: &[Vec<LogEntry>]) -> Result<(), String> {
    for (a, x) in logs.iter().enumerate() {
        for y in &logs[a + 1..] {
            let common = x.len().min(y.len());
            let same = (0..common).rev().find(|&i| x[i].term == y[i].term);
            if let Some(i) = same.filter(|&i| x[..=i] != y[..=i]) {
                return Err(format!(
                    "logs share term {} at index {} but differ up to it",
                    x[i].term,
                    i + 1
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
    /// Entries applied in this incarnation.
    applied: Index,
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
    voters: Vec<NodeId>,
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
    report: Report,
}

impl Sim {
    fn new(seed: u64, cfg: SimConfig) -> Self {
        let voters: Vec<NodeId> = (1..=cfg.replicas).collect();
        let replicas = voters
            .iter()
            .map(|_| Replica {
                env: MemEnv::new(),
                node: None,
                down_until: 0,
                applied: 0,
                seen_commit: 0,
                damaged: false,
            })
            .collect();
        Sim {
            rng: Rng(seed),
            now: 0,
            dir: PathBuf::from("/raft"),
            voters,
            replicas,
            queue: BTreeMap::new(),
            sent: 0,
            partition: None,
            check: Checker::default(),
            payload: 0,
            reads: BTreeMap::new(),
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
                    let r = &mut self.replicas[i];
                    for e in &out.committed {
                        r.applied += 1;
                        self.check.apply(i as NodeId + 1, r.applied, e)?;
                    }
                    for read in &out.reads {
                        self.answered(i, read)?;
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
            self.read()?;
        }
        self.deliver()?;
        if self.now.is_multiple_of(16) {
            log_matching(&self.logs())?;
        }
        self.now += 1;
        Ok(())
    }

    fn logs(&self) -> Vec<Vec<LogEntry>> {
        self.replicas
            .iter()
            .filter_map(|r| r.node.as_ref().map(|n| n.log_snapshot().1))
            .collect()
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
        let bound = (self.replicas.len() - 1) / 2;
        for i in 0..self.replicas.len() {
            let up = self.replicas[i].node.is_some();
            if up & self.rng.chance(f.crash) {
                let damaged = self.replicas.iter().filter(|r| r.damaged).count();
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

    fn start(&mut self, i: usize) -> Result<(), String> {
        let id = i as NodeId + 1;
        let env: Arc<dyn Env> = Arc::new(self.replicas[i].env.clone());
        let storage =
            FileStorage::open_with_env(env, &self.dir).map_err(|e| format!("replica {id} cannot restart: {e}"))?;
        // A cluster may mix replicas with and without pre-vote.
        let cfg = Config {
            seed: self.rng.next(),
            pre_vote: self.rng.next() & 1 == 0,
            ..Config::cluster(id, self.voters.clone())
        };
        let node = Node::new(cfg, storage).expect("a voter, and FileStorage::load cannot fail");
        let r = &mut self.replicas[i];
        r.damaged = node.recovering();
        r.node = Some(node);
        r.applied = 0;
        r.seen_commit = 0;
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
        if (node.role() == NodeState::Leader) && self.check.leader(id, term, &|| node.log_snapshot().1)? {
            self.report.elections += 1;
        }
        if commit > r.seen_commit {
            let log = node.log_snapshot().1;
            self.check
                .commit(id, term, &log[r.seen_commit as usize..commit as usize])?;
            r.seen_commit = commit;
        }
        if r.damaged & !node.recovering() {
            r.damaged = false;
            self.report.recoveries += 1;
        }
        Ok(())
    }

    fn propose(&mut self) -> Result<(), String> {
        let leader = (self.replicas.iter().enumerate())
            .filter_map(|(i, r)| r.node.as_ref().map(|n| (n, i)))
            .filter(|(n, _)| n.role() == NodeState::Leader)
            .max_by_key(|(n, _)| n.term())
            .map(|(_, i)| i);
        let Some(i) = leader else { return Ok(()) };
        self.payload += 1;
        let data = self.payload.to_le_bytes().to_vec();
        match self.replicas[i].node.as_ref().map(|n| n.propose(data)) {
            Some(Err(e)) => self.failed(i, e),
            _ => self.observe(i),
        }
    }

    /// A client asks a leader, any leader: a stale one that still believes
    /// it leads must never answer.
    fn read(&mut self) -> Result<(), String> {
        let leaders: Vec<usize> = (0..self.replicas.len())
            .filter(|&i| {
                self.replicas[i]
                    .node
                    .as_ref()
                    .is_some_and(|n| n.role() == NodeState::Leader)
            })
            .collect();
        if leaders.is_empty() {
            return Ok(());
        }
        let i = leaders[self.rng.below(leaders.len() as u64) as usize];
        let asked = self.replicas[i].node.as_ref().expect("a leader is up").read_index();
        match asked {
            Ok(id) => {
                self.reads.insert((i, id), self.check.top());
                Ok(())
            }
            Err(Error::NotReady) => Ok(()),
            Err(e) => self.failed(i, e),
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

    /// After healing: every replica up and caught up, one leader, identical
    /// logs and commit indices.
    fn converged(&mut self) -> Result<(), String> {
        let nodes: Vec<&Node> = self.replicas.iter().filter_map(|r| r.node.as_ref()).collect();
        let logs = self.logs();
        let leaders = nodes.iter().filter(|n| n.role() == NodeState::Leader).count();
        let commits: Vec<Index> = nodes.iter().map(|n| n.commit_index()).collect();
        let recovering = nodes.iter().filter(|n| n.recovering()).count();
        let ok = (nodes.len() == self.replicas.len())
            & (leaders == 1)
            & (recovering == 0)
            & logs.windows(2).all(|w| w[0] == w[1])
            & commits.windows(2).all(|w| w[0] == w[1]);
        if !ok {
            return Err(format!(
                "no convergence after healing: {} of {} up, {leaders} leaders, {recovering} recovering, \
                 log lengths {:?}, commit indices {commits:?}",
                nodes.len(),
                self.replicas.len(),
                logs.iter().map(Vec::len).collect::<Vec<_>>()
            ));
        }
        self.report.committed = commits[0];
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quick(replicas: u64) -> SimConfig {
        SimConfig {
            replicas,
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
        LogEntry {
            index,
            term,
            data: vec![index as u8, term as u8],
        }
    }

    #[test]
    fn checker_catches_violations() {
        let mut c = Checker::default();
        assert_eq!(c.leader(1, 1, &Vec::new), Ok(true));
        assert_eq!(c.leader(1, 1, &Vec::new), Ok(false));
        assert!(c.leader(2, 1, &Vec::new).unwrap_err().contains("two leaders in term 1"));
        c.commit(1, 2, &[e(1, 1), e(2, 2)]).unwrap();
        c.commit(2, 1, &[e(1, 1)]).unwrap();
        assert_eq!(c.committed[&1].1, 1, "lowest term kept");
        assert!(c.commit(3, 3, &[e(2, 3)]).unwrap_err().contains("different entry 2"));
        // Entry 2 was seen committed in term 2: a term-2 leader need not have it.
        assert_eq!(c.leader(3, 2, &|| vec![e(1, 1)]), Ok(true));
        let lacking = c.leader(3, 3, &|| vec![e(1, 1)]).unwrap_err();
        assert!(lacking.contains("lacks committed entry 2"), "{lacking}");
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
        assert!(log_matching(&[a.clone(), a[..2].to_vec(), vec![e(1, 1), e(2, 3)]]).is_ok());
        assert!(log_matching(&[a.clone(), vec![]]).is_ok());
        assert!(log_matching(&[a, b]).unwrap_err().contains("term 2 at index 3"));
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
        let other = || LogEntry {
            index: 1,
            term: 1,
            data: b"other".to_vec(),
        };
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
        // The replica's own failure to start a read surfaces too.
        let mut sim = started(quick(1));
        while sim.replicas[0].node.as_ref().unwrap().role() != NodeState::Leader {
            sim.replicas[0].node.as_ref().unwrap().tick().unwrap();
        }
        sim.replicas[0].env.fail_after(0);
        sim.replicas[0].env = MemEnv::new();
        let err = sim.read().unwrap_err();
        assert!(err.starts_with("replica 1 failed: "), "{err}");
        // The same from a tick that asks for a read (and never proposes).
        let mut sim = started(SimConfig {
            faults: Faults {
                propose: 0,
                read: 1_000_000,
                ..quick(1).faults
            },
            ..quick(1)
        });
        while sim.replicas[0].node.as_ref().unwrap().role() != NodeState::Leader {
            sim.replicas[0].node.as_ref().unwrap().tick().unwrap();
        }
        sim.replicas[0].env.fail_after(0);
        sim.replicas[0].env = MemEnv::new();
        let err = sim.tick().unwrap_err();
        assert!(err.starts_with("replica 1 failed: "), "{err}");
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
}
