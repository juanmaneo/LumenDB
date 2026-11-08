//! A running Raft node: [`Server`] ticks a [`Node`] on a clock, moves its
//! messages through a [`Transport`], and hands what commits to the
//! application's [`StateMachine`], which it also snapshots to keep the log
//! short.
//!
//! One thread does all of it, in a loop: wait for a message for the rest of
//! the tick, step the node with it and send the replies; when the tick is
//! due, tick the node, send its messages, restore a snapshot it hands over,
//! apply the entries that committed, release the reads that were confirmed,
//! and compact when enough entries have piled up. Committed entries reach the
//! application on ticks, so apply lags a commit by at most one tick.
//!
//! A storage error stops the server (the Raft state on disk can no longer be
//! trusted to match memory); [`Server::failure`] says why, and every call
//! then fails with [`Error::Stopped`]. A message that is merely bad, such as
//! one a peer should not have sent, is dropped.
//!
//! Addresses are static: [`Server::set_peer`] says where each node lives,
//! including nodes not in the cluster yet, which has to be done before the
//! leader adds one and on the node that is added (it must reach the leader).

use crate::error::{Error, Result};
use crate::log::{EntryKind, LogEntry};
use crate::net::{NetOptions, Transport};
use crate::node::Node;
use crate::storage::Snapshot;
use crate::{Index, NodeId};
use parking_lot::{Condvar, Mutex};
use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// The replicated state machine of an application.
pub trait StateMachine: Send + 'static {
    /// Applies a committed entry that carries application data. Entries
    /// arrive in index order, once per run of the process: after a restart
    /// they are replayed from the snapshot, so a state machine that keeps
    /// its state on disk must skip what it has (`entry.index` says).
    fn apply(&mut self, entry: &LogEntry);

    /// Replaces the state with the one in `snapshot`. Called before the
    /// entries after it, at the start of a run when there is a stored
    /// snapshot, and when the leader sends one.
    fn restore(&mut self, snapshot: &Snapshot);

    /// The state after every entry applied so far, serialized.
    fn snapshot(&mut self) -> Vec<u8>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerOptions {
    /// Real time per logical tick: election timeouts and heartbeats are
    /// counted in these.
    pub tick: Duration,
    /// Snapshot once this many entries have been applied since the last
    /// snapshot (0: never).
    pub snapshot_every: u64,
    pub net: NetOptions,
}

impl Default for ServerOptions {
    fn default() -> Self {
        ServerOptions {
            tick: Duration::from_millis(20),
            snapshot_every: 10_000,
            net: NetOptions::default(),
        }
    }
}

/// What the loop publishes for the callers that wait.
#[derive(Default)]
struct State {
    /// The index up to which the state machine has the entries.
    applied: Index,
    /// Ids of the reads somebody waits for, and the outcomes that arrived.
    waiting: BTreeSet<u64>,
    reads: BTreeMap<u64, Option<Index>>,
    /// Why the server stopped, if it stopped by itself.
    failure: Option<String>,
    stopped: bool,
}

struct Inner {
    node: Node,
    transport: Transport,
    app: Mutex<Box<dyn StateMachine>>,
    state: Mutex<State>,
    changed: Condvar,
    stop: AtomicBool,
    opts: ServerOptions,
}

pub struct Server {
    inner: Arc<Inner>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl Server {
    /// Starts the loop. `transport` is shared with nobody else. The
    /// application keeps its own handle on its state, if it reads it.
    pub fn start(node: Node, transport: Transport, app: impl StateMachine, opts: ServerOptions) -> Self {
        let inner = Arc::new(Inner {
            node,
            transport,
            app: Mutex::new(Box::new(app)),
            state: Mutex::new(State::default()),
            changed: Condvar::new(),
            stop: AtomicBool::new(false),
            opts,
        });
        let thread = {
            let inner = inner.clone();
            thread::spawn(move || inner.run())
        };
        Server {
            inner,
            thread: Mutex::new(Some(thread)),
        }
    }

    /// The Raft node: its role, leader, voters, and the membership calls
    /// (`add_learner`, `add_voter`, ...).
    pub fn node(&self) -> &Node {
        &self.inner.node
    }

    /// Where messages for node `id` go; see the module docs.
    pub fn set_peer(&self, id: NodeId, addr: SocketAddr) {
        self.inner.transport.set_peer(id, addr);
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.inner.transport.local_addr()
    }

    pub fn transport(&self) -> &Transport {
        &self.inner.transport
    }

    /// Appends `data` to the log (leader only) and returns its index; once
    /// [`Server::wait_applied`] says it is applied, a majority has it.
    pub fn propose(&self, data: Vec<u8>) -> Result<Index> {
        self.running()?;
        self.inner.node.propose(data)
    }

    /// Waits until the state machine has every entry up to `index`.
    pub fn wait_applied(&self, index: Index, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        let mut st = self.inner.state.lock();
        loop {
            if st.applied >= index {
                return Ok(());
            }
            if st.stopped {
                return Err(Error::Stopped);
            }
            if self.inner.changed.wait_until(&mut st, deadline).timed_out() {
                return Err(Error::Timeout);
            }
        }
    }

    /// A linearizable read barrier ([`Node::read_index`]): leader only.
    /// When it returns, the state machine reflects everything committed
    /// before the call, so reading its state then is linearizable.
    pub fn read_barrier(&self, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        let mut st = self.inner.state.lock();
        if st.stopped {
            return Err(Error::Stopped);
        }
        let id = self.inner.node.read_index()?;
        st.waiting.insert(id);
        loop {
            match st.reads.remove(&id) {
                Some(Some(_)) => return Ok(()),
                Some(None) => return Err(Error::NotLeader(self.inner.node.leader())),
                None => {}
            }
            if st.stopped {
                return Err(Error::Stopped);
            }
            if self.inner.changed.wait_until(&mut st, deadline).timed_out() {
                st.waiting.remove(&id);
                return Err(Error::Timeout);
            }
        }
    }

    /// Why the server stopped by itself, if it did.
    pub fn failure(&self) -> Option<String> {
        self.inner.state.lock().failure.clone()
    }

    /// Stops the loop and the transport. Idempotent; also done on drop.
    pub fn shutdown(&self) {
        self.inner.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.lock().take() {
            let _ = t.join();
        }
        self.inner.transport.shutdown();
        self.inner.state.lock().stopped = true;
        self.inner.changed.notify_all();
    }

    fn running(&self) -> Result<()> {
        match self.inner.state.lock().stopped {
            true => Err(Error::Stopped),
            false => Ok(()),
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl Inner {
    fn run(&self) {
        let mut next_tick = Instant::now() + self.opts.tick;
        while !self.stop.load(Ordering::SeqCst) {
            let wait = next_tick.saturating_duration_since(Instant::now());
            if let Some(msg) = self.transport.recv_timeout(wait) {
                if let Err(e) = self.step(msg) {
                    return self.fail(e);
                }
            }
            if Instant::now() >= next_tick {
                next_tick = Instant::now() + self.opts.tick;
                if let Err(e) = self.tick() {
                    return self.fail(e);
                }
            }
        }
    }

    /// Steps the node with a message from a peer. A storage error is the
    /// server's end; any other error is the message's fault.
    fn step(&self, msg: crate::Message) -> Result<()> {
        match self.node.step(msg) {
            Ok(replies) => replies.iter().for_each(|m| {
                self.transport.send(m);
            }),
            Err(e @ Error::Storage(_)) => return Err(e),
            Err(_) => {}
        }
        Ok(())
    }

    fn tick(&self) -> Result<()> {
        let out = self.node.tick()?;
        for m in &out.messages {
            self.transport.send(m);
        }
        let mut app = self.app.lock();
        let mut applied = None;
        if let Some(snapshot) = &out.snapshot {
            app.restore(snapshot);
            applied = Some(snapshot.index);
        }
        for e in &out.committed {
            if (e.kind == EntryKind::Normal) & !e.data.is_empty() {
                app.apply(e);
            }
            applied = Some(e.index);
        }
        let applied_now = {
            let mut st = self.state.lock();
            st.applied = applied.unwrap_or(st.applied);
            // Only the reads somebody still waits for are kept.
            let State { waiting, reads, .. } = &mut *st;
            reads.extend(
                (out.reads.iter())
                    .filter(|r| waiting.remove(&r.id))
                    .map(|r| (r.id, r.index)),
            );
            st.applied
        };
        self.changed.notify_all();
        let since = applied_now.saturating_sub(self.node.snapshot_index());
        if (self.opts.snapshot_every > 0) & (since >= self.opts.snapshot_every) {
            let data = app.snapshot();
            self.node.compact(applied_now, data)?;
        }
        Ok(())
    }

    /// The loop ends with `e`; waiters are told.
    fn fail(&self, e: Error) {
        let mut st = self.state.lock();
        st.failure = Some(e.to_string());
        st.stopped = true;
        self.changed.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::Config;
    use crate::storage::{DurableState, MemoryStorage, Storage};
    use crate::{Message, NodeState};
    use std::sync::atomic::AtomicU64;

    const LONG: Duration = Duration::from_secs(20);

    #[derive(Default)]
    struct Totals {
        sum: u64,
        applied: Vec<Index>,
        restores: u64,
    }

    /// Sums the numbers proposed to it; the test reads `totals`.
    #[derive(Clone, Default)]
    struct Counter {
        totals: Arc<Mutex<Totals>>,
    }

    impl StateMachine for Counter {
        fn apply(&mut self, e: &LogEntry) {
            let mut t = self.totals.lock();
            t.sum += u64::from_le_bytes(e.data[..8].try_into().unwrap());
            t.applied.push(e.index);
        }
        fn restore(&mut self, s: &Snapshot) {
            let mut t = self.totals.lock();
            t.sum = u64::from_le_bytes(s.data[..8].try_into().unwrap());
            t.restores += 1;
        }
        fn snapshot(&mut self) -> Vec<u8> {
            self.totals.lock().sum.to_le_bytes().to_vec()
        }
    }

    /// A server and the totals its state machine keeps.
    struct Member {
        server: Server,
        counter: Counter,
    }

    impl Member {
        fn with_app<T>(&self, f: impl FnOnce(&Totals) -> T) -> T {
            f(&self.counter.totals.lock())
        }
    }

    impl std::ops::Deref for Member {
        type Target = Server;
        fn deref(&self) -> &Server {
            &self.server
        }
    }

    fn opts(snapshot_every: u64) -> ServerOptions {
        ServerOptions {
            tick: Duration::from_millis(4),
            snapshot_every,
            net: NetOptions {
                retry_after: Duration::from_millis(10),
                ..NetOptions::default()
            },
        }
    }

    fn transport() -> Transport {
        Transport::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap(), opts(0).net).unwrap()
    }

    /// `voters` servers `1..=voters` that know each other, and `joiners`
    /// more that wait to be added; every server knows every address.
    fn cluster(voters: u64, joiners: u64, snapshot_every: u64) -> Vec<Member> {
        let ids: Vec<NodeId> = (1..=voters + joiners).collect();
        let transports: Vec<Transport> = ids.iter().map(|_| transport()).collect();
        let addrs: Vec<SocketAddr> = transports.iter().map(Transport::local_addr).collect();
        let initial: Vec<NodeId> = (1..=voters).collect();
        let servers: Vec<Member> = transports
            .into_iter()
            .zip(&ids)
            .map(|(t, &id)| {
                // Slow elections, so that a busy machine does not cause any.
                let cfg = Config {
                    election_timeout_min: 50,
                    election_timeout_max: 100,
                    ..match id <= voters {
                        true => Config::cluster(id, initial.clone()),
                        false => Config::joiner(id),
                    }
                };
                let node = Node::new(cfg, MemoryStorage::new()).unwrap();
                let counter = Counter::default();
                let server = Server::start(node, t, counter.clone(), opts(snapshot_every));
                Member { server, counter }
            })
            .collect();
        for s in &servers {
            for (&peer, &addr) in ids.iter().zip(&addrs) {
                s.set_peer(peer, addr);
            }
        }
        servers
    }

    fn wait_until<T>(what: &str, mut f: impl FnMut() -> Option<T>) -> T {
        let start = Instant::now();
        loop {
            if let Some(v) = f() {
                return v;
            }
            assert!(start.elapsed() < LONG, "timed out waiting for {what}");
            thread::sleep(Duration::from_millis(2));
        }
    }

    /// The leader of `servers`, once there is exactly one that is up.
    fn find_leader<'a>(servers: &'a [Member], down: &[NodeId]) -> &'a Member {
        wait_until("a single leader", || {
            let up = servers.iter().filter(|s| !down.contains(&s.node().id()));
            let mut leaders = up.filter(|s| s.node().role() == NodeState::Leader);
            let first = leaders.next()?;
            // A stale leader may linger a moment after a change; two is not stable.
            leaders.next().is_none().then_some(first)
        })
    }

    fn number(n: u64) -> Vec<u8> {
        n.to_le_bytes().to_vec()
    }

    #[test]
    fn a_cluster_over_tcp_replicates_and_applies() {
        let servers = cluster(3, 0, 0);
        let leader = find_leader(&servers, &[]);
        let mut last = 0;
        for n in 1..=20 {
            last = leader.propose(number(n)).unwrap();
        }
        for s in &servers {
            s.wait_applied(last, LONG).unwrap();
            assert_eq!(s.with_app(|c| c.sum), 210);
            // Only entries with data reach the application, in order.
            assert_eq!(s.with_app(|c| c.applied.len()), 20);
        }
        // Followers do not take proposals.
        let follower = servers.iter().find(|s| s.node().id() != leader.node().id()).unwrap();
        assert_eq!(
            follower.propose(number(1)),
            Err(Error::NotLeader(Some(leader.node().id())))
        );
        assert!(leader.transport().stats().sent > 0);
        // Waiting for an index that never comes times out.
        assert_eq!(
            leader.wait_applied(last + 100, Duration::from_millis(30)),
            Err(Error::Timeout)
        );
    }

    #[test]
    fn a_read_barrier_makes_local_reads_linearizable() {
        let servers = cluster(3, 0, 0);
        let leader = find_leader(&servers, &[]);
        let index = leader.propose(number(5)).unwrap();
        leader.wait_applied(index, LONG).unwrap();
        // Applied means committed, so the leader's own entries are too.
        leader.read_barrier(LONG).unwrap();
        assert_eq!(leader.with_app(|c| c.sum), 5);
        let follower = servers.iter().find(|s| s.node().id() != leader.node().id()).unwrap();
        let leader_id = leader.node().id();
        assert_eq!(follower.read_barrier(LONG), Err(Error::NotLeader(Some(leader_id))));
        // A barrier nobody can confirm times out, and leaves nothing behind.
        let alone = cluster(3, 0, 0);
        let l = find_leader(&alone, &[]);
        let index = l.propose(number(1)).unwrap();
        l.wait_applied(index, LONG).unwrap();
        for s in alone.iter().filter(|s| s.node().id() != l.node().id()) {
            s.shutdown();
        }
        assert_eq!(l.read_barrier(Duration::from_millis(40)), Err(Error::Timeout));
        assert!(l.inner.state.lock().waiting.is_empty());
        thread::scope(|scope| {
            // Leadership is lost before the barrier is confirmed: the loop
            // reports the read as failed.
            let waiter = scope.spawn(|| l.read_barrier(LONG));
            let id = wait_until("the barrier to wait", || l.inner.state.lock().waiting.first().copied());
            {
                let mut st = l.inner.state.lock();
                st.waiting.remove(&id);
                st.reads.insert(id, None);
            }
            l.inner.changed.notify_all();
            assert_eq!(waiter.join().unwrap(), Err(Error::NotLeader(Some(l.node().id()))));
            // The server stops while a barrier waits.
            let waiter = scope.spawn(|| l.read_barrier(LONG));
            wait_until("the barrier to wait", || {
                (!l.inner.state.lock().waiting.is_empty()).then_some(())
            });
            l.shutdown();
            assert_eq!(waiter.join().unwrap(), Err(Error::Stopped));
        });
    }

    #[test]
    fn the_cluster_survives_losing_its_leader() {
        let servers = cluster(3, 0, 0);
        let old = find_leader(&servers, &[]);
        let first = old.propose(number(1)).unwrap();
        for s in &servers {
            s.wait_applied(first, LONG).unwrap();
        }
        let old_id = old.node().id();
        old.shutdown();
        let new = find_leader(&servers, &[old_id]);
        assert_ne!(new.node().id(), old_id);
        let second = new.propose(number(10)).unwrap();
        new.wait_applied(second, LONG).unwrap();
        assert_eq!(new.with_app(|c| c.sum), 11);
        // The stopped server refuses everything.
        assert_eq!(old.propose(number(1)), Err(Error::Stopped));
        assert_eq!(old.wait_applied(99, Duration::from_millis(10)), Err(Error::Stopped));
        assert_eq!(old.read_barrier(Duration::from_millis(10)), Err(Error::Stopped));
        assert_eq!(old.failure(), None, "it was stopped, it did not fail");
        old.shutdown();
    }

    #[test]
    fn snapshots_compact_the_log_and_bring_a_new_server_up() {
        let servers = cluster(3, 1, 8);
        let leader = find_leader(&servers[..3], &[]);
        let mut last = 0;
        for n in 1..=40 {
            last = leader.propose(number(n)).unwrap();
        }
        leader.wait_applied(last, LONG).unwrap();
        wait_until("a snapshot", || (leader.node().snapshot_index() > 0).then_some(()));
        // The new server joins as a learner, which needs the snapshot, and
        // is promoted once it has caught up.
        let newcomer = &servers[3];
        leader.node().add_learner(4).unwrap();
        newcomer.wait_applied(last, LONG).unwrap();
        assert_eq!(newcomer.with_app(|c| c.sum), 820);
        assert!(
            newcomer.with_app(|c| c.restores) >= 1,
            "it was restored from a snapshot"
        );
        // (Refused while the learner is still catching up.)
        wait_until("promotion", || leader.node().add_voter(4).ok());
        wait_until("the new configuration", || {
            servers
                .iter()
                .all(|s| s.node().voters() == vec![1, 2, 3, 4])
                .then_some(())
        });
        // The enlarged cluster keeps working, with the newcomer in it.
        let more = leader.propose(number(1000)).unwrap();
        for s in &servers {
            s.wait_applied(more, LONG).unwrap();
            assert_eq!(s.with_app(|c| c.sum), 1820);
        }
        // A server that is removed stops being part of it.
        leader.node().remove_voter(4).unwrap();
        wait_until("removal", || (leader.node().voters() == vec![1, 2, 3]).then_some(()));
    }

    /// Storage that fails every write after the first `allowed` ones.
    struct Breaks {
        inner: Arc<MemoryStorage>,
        allowed: AtomicU64,
    }

    impl Breaks {
        fn new(allowed: u64) -> Arc<Self> {
            Arc::new(Breaks {
                inner: MemoryStorage::new(),
                allowed: AtomicU64::new(allowed),
            })
        }
        /// Runs `f` on the storage while writes are allowed.
        fn through<T>(&self, f: impl FnOnce(&MemoryStorage) -> Result<T>) -> Result<T> {
            let left = self.allowed.load(Ordering::SeqCst);
            if left == 0 {
                return Err(Error::Storage("disk gone".into()));
            }
            self.allowed.store(left - 1, Ordering::SeqCst);
            f(&self.inner)
        }
    }

    impl Storage for Breaks {
        fn load(&self) -> Result<DurableState> {
            self.inner.load()
        }
        fn save_vote(&self, term: u64, voted_for: Option<NodeId>) -> Result<()> {
            self.through(|s| s.save_vote(term, voted_for))
        }
        fn append_entries(&self, entries: &[LogEntry]) -> Result<()> {
            self.through(|s| s.append_entries(entries))
        }
        fn mark_repaired(&self) -> Result<()> {
            self.through(|s| s.mark_repaired())
        }
        fn install_snapshot(&self, snapshot: Arc<Snapshot>) -> Result<()> {
            self.through(|s| s.install_snapshot(snapshot))
        }
    }

    #[test]
    fn the_failing_storage_lets_writes_through_until_its_budget_is_spent() {
        let b = Breaks::new(3);
        b.mark_repaired().unwrap();
        b.append_entries(&[]).unwrap();
        b.install_snapshot(Arc::new(Snapshot {
            index: 1,
            term: 1,
            voters: vec![1],
            data: Vec::new(),
        }))
        .unwrap();
        assert_eq!(b.save_vote(1, None), Err(Error::Storage("disk gone".into())));
        assert_eq!(b.load().unwrap().term, 0);
    }

    fn start(cfg: Config, storage: Arc<Breaks>, snapshot_every: u64) -> Member {
        let node = Node::new(cfg, storage).unwrap();
        let counter = Counter::default();
        let server = Server::start(node, transport(), counter.clone(), opts(snapshot_every));
        Member { server, counter }
    }

    fn stopped_by(server: &Member) -> String {
        wait_until("the server to fail", || server.failure())
    }

    #[test]
    fn a_storage_error_stops_the_server_wherever_it_happens() {
        // Starting an election, in a tick.
        let s = start(Config::single(1), Breaks::new(0), 0);
        assert_eq!(stopped_by(&s), "storage: disk gone");
        assert_eq!(s.propose(number(1)), Err(Error::Stopped));
        assert_eq!(s.wait_applied(1, Duration::from_millis(10)), Err(Error::Stopped));
        // Taking a snapshot, in a tick: the vote, the leader's empty entry
        // and one proposal are written, the snapshot is the fourth write.
        let s = start(Config::single(1), Breaks::new(3), 2);
        wait_until("leadership", || (s.node().role() == NodeState::Leader).then_some(()));
        s.propose(number(1)).unwrap();
        assert_eq!(stopped_by(&s), "storage: disk gone");
        assert_eq!(s.node().snapshot_index(), 0);
        // Handling a message, as a follower that never campaigns on its own:
        // a peer asks for a vote in a later term and it cannot be saved.
        let patient = Config {
            election_timeout_min: 1_000_000,
            election_timeout_max: 1_000_000,
            ..Config::cluster(1, vec![1, 2])
        };
        let s = start(patient, Breaks::new(0), 0);
        let peer = transport();
        peer.set_peer(1, s.local_addr());
        wait_until("the server to fail", || {
            peer.send(&Message::request_vote(2, 1, 9, 0, 0));
            s.failure()
        });
        assert_eq!(s.node().term(), 0, "memory kept the old term");
    }

    #[test]
    fn messages_a_peer_should_not_send_are_dropped() {
        let node = Node::new(Config::cluster(1, vec![1, 2]), MemoryStorage::new()).unwrap();
        let counter = Counter::default();
        let s = Server::start(node, transport(), counter.clone(), opts(0));
        let peer = transport();
        peer.set_peer(1, s.local_addr());
        // An InstallSnapshot without a snapshot is an error of the node.
        let bad = Message {
            msg_type: crate::MsgType::InstallSnapshot,
            ..Message::request_vote(2, 1, 1, 0, 0)
        };
        for _ in 0..5 {
            assert!(peer.send(&bad));
        }
        // The server carries on: it hears a leader and takes its entries.
        let append = Message::append_entries(2, 1, 1, 0, 0, vec![LogEntry::new(1, 1, number(7))], 1);
        wait_until("the entry to be applied", || {
            peer.send(&append);
            s.wait_applied(1, Duration::from_millis(20)).ok()
        });
        assert_eq!(counter.totals.lock().sum, 7);
        assert_eq!(s.failure(), None);
    }

    #[test]
    fn shutdown_is_idempotent_and_drop_stops_the_threads() {
        let servers = cluster(1, 0, 0);
        let addr = servers[0].local_addr();
        servers[0].shutdown();
        servers[0].shutdown();
        assert_eq!(servers[0].transport().peers().len(), 0);
        drop(servers);
        // Nobody listens any more.
        wait_until("the port to close", || {
            std::net::TcpStream::connect(addr).is_err().then_some(())
        });
        let o = ServerOptions::default();
        assert!(o.tick > Duration::ZERO && o.snapshot_every > 0);
    }
}
