//! A [`tsvdb`] replicated by Raft.
//!
//! Every node keeps a complete copy of the database. A write is parsed on the
//! leader, given the leader's clock for every point without a timestamp, and
//! appended to the Raft log as line protocol. When it commits, every node
//! applies it to its own database, so all copies hold the same points.
//! `write_lines` returns once the leader has applied the write.
//!
//! **Replay is harmless.** Two writes of one point (same series, field and
//! timestamp) leave the last one, and a replayed log writes the same points
//! in the same order, so applying an entry twice changes no query result.
//! That is why a crash between a database write and the note of how far the
//! log has been applied costs nothing but a little disk: after a restart the
//! node starts again from the last note. The note is `applied`, written after
//! the database acknowledged the write (which is made durable: sync is forced
//! on), every [`NOTE_EVERY`] entries, at every snapshot and at shutdown.
//!
//! **Refused writes are refused everywhere.** The database may reject a write
//! only for a reason that follows from the data, such as a field that already
//! has another type (`Error::Schema`). Every node sees the same history, so
//! every node refuses the same entries; the leader tells the writer
//! ([`Error::Rejected`]). Anything else, such as a failing disk, stops the
//! node: it can no longer follow the log.
//!
//! **Snapshots are dumps.** To compact the Raft log the node dumps the whole
//! database as compressed line protocol ([`tsvdb::Db::dump`]); a node that
//! is too far behind, or new, is restored from it. A snapshot is held in
//! memory and travels in one message, so `snapshot_every` should be large
//! for a large database; 0 never compacts, and the log grows.
//!
//! **Reads.** [`ReplicatedDb::query`] reads this node's copy, which lags the
//! leader by at most the entries not yet applied. [`ReplicatedDb::query_consistent`]
//! is linearizable and served by the leader.

use parking_lot::Mutex;
use raft::{
    Config, FileStorage, Index, LogEntry, Node, NodeId, Server, ServerOptions, Snapshot, StateMachine, Transport,
};
use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tsvdb::{lineproto, Db, DbOptions, Point, Query, Row};

/// The node notes how far it has applied the log every this many entries.
pub const NOTE_EVERY: u64 = 64;

/// How many refusals are kept for the writers that have not asked yet.
const KEPT_REFUSALS: usize = 1024;

#[derive(Debug)]
pub enum Error {
    /// The Raft layer: `NotLeader(hint)`, `Timeout`, `Stopped`, storage...
    Raft(raft::Error),
    /// The database: malformed line protocol, an invalid query, storage.
    Db(tsvdb::Error),
    Io(io::Error),
    /// The write committed, and every node refused it when applying it.
    Rejected(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Raft(e) => write!(f, "raft: {e}"),
            Error::Db(e) => write!(f, "database: {e}"),
            Error::Io(e) => write!(f, "io: {e}"),
            Error::Rejected(why) => write!(f, "write refused: {why}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<raft::Error> for Error {
    fn from(e: raft::Error) -> Self {
        Error::Raft(e)
    }
}

impl From<tsvdb::Error> for Error {
    fn from(e: tsvdb::Error) -> Self {
        Error::Db(e)
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone)]
pub struct ClusterOptions {
    /// The clock, snapshot interval and network options of the Raft server.
    /// `snapshot_every` defaults to 100000 here.
    pub raft: ServerOptions,
    /// Election timeout range, in ticks.
    pub election_timeout: (u64, u64),
    /// Heartbeat interval, in ticks.
    pub heartbeat: u64,
    pub db: DbOptions,
}

impl Default for ClusterOptions {
    fn default() -> Self {
        ClusterOptions {
            raft: ServerOptions {
                snapshot_every: 100_000,
                ..ServerOptions::default()
            },
            election_timeout: (10, 20),
            heartbeat: 3,
            db: DbOptions::default(),
        }
    }
}

/// What this node has done, since it started.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ClusterStats {
    /// The index of the last log entry applied (or covered by a snapshot).
    pub applied_index: Index,
    /// Entries written to the database by this run.
    pub applied_entries: u64,
    /// Entries refused when applied.
    pub refused_entries: u64,
    /// Snapshots the database was restored from by this run.
    pub restores: u64,
}

#[derive(Default)]
struct Counters {
    applied_entries: AtomicU64,
    refused_entries: AtomicU64,
    restores: AtomicU64,
}

/// What the state machine and [`ReplicatedDb`] share.
struct Shared {
    db: Arc<Db>,
    counters: Counters,
    /// Why entries were refused, until the writer asks.
    refused: Mutex<BTreeMap<Index, String>>,
    /// The last entry applied, and the last one noted in `note`.
    progress: Mutex<(Index, Index)>,
    note: PathBuf,
}

/// The note: the index, in one CRC-framed record. A missing or damaged note
/// means 0: replay from the start of the log.
fn read_note(path: &Path) -> Index {
    let Ok(bytes) = fs::read(path) else { return 0 };
    let (records, end) = flashkv::log::parse(&bytes);
    match records.as_slice() {
        [r] if (r.len() == 8) & (end == bytes.len()) => u64::from_le_bytes(r[..8].try_into().expect("8 bytes")),
        _ => 0,
    }
}

impl Shared {
    fn applied(&self) -> Index {
        self.progress.lock().0
    }

    /// Writes the note for the entry applied last.
    fn write_note(&self) -> io::Result<()> {
        let mut progress = self.progress.lock();
        let mut framed = Vec::new();
        flashkv::log::frame(&mut framed, &progress.0.to_le_bytes());
        let tmp = self.note.with_extension("tmp");
        fs::write(&tmp, framed)?;
        fs::rename(&tmp, &self.note)?;
        progress.1 = progress.0;
        Ok(())
    }

    /// The database has everything up to `index`.
    fn advance(&self, index: Index) -> io::Result<()> {
        let due = {
            let mut progress = self.progress.lock();
            progress.0 = index;
            index - progress.1 >= NOTE_EVERY
        };
        match due {
            true => self.write_note(),
            false => Ok(()),
        }
    }

    fn refuse(&self, index: Index, why: String) {
        Counters::bump(&self.counters.refused_entries);
        let mut refused = self.refused.lock();
        refused.insert(index, why);
        while refused.len() > KEPT_REFUSALS {
            refused.pop_first();
        }
    }
}

impl Counters {
    fn bump(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

/// The Raft state machine of a [`ReplicatedDb`].
struct App {
    shared: Arc<Shared>,
}

impl StateMachine for App {
    fn apply(&mut self, entry: &LogEntry) -> std::result::Result<(), String> {
        let shared = &self.shared;
        // Everything up to the note is in the database already.
        if entry.index <= shared.applied() {
            return Ok(());
        }
        match shared.db.write_lines(&String::from_utf8_lossy(&entry.data)) {
            Ok(_) => Counters::bump(&shared.counters.applied_entries),
            // These follow from the data, so every node refuses the entry.
            Err(e @ (tsvdb::Error::Schema(_) | tsvdb::Error::Parse { .. })) => {
                shared.refuse(entry.index, e.to_string());
            }
            Err(e) => return Err(e.to_string()),
        }
        shared.advance(entry.index).map_err(|e| e.to_string())
    }

    fn restore(&mut self, s: &Snapshot) -> std::result::Result<(), String> {
        let shared = &self.shared;
        // A database that has applied the entries behind the snapshot has it.
        if s.index <= shared.applied() {
            return Ok(());
        }
        let text = flashkv::lz::decompress(&s.data).map_err(|e| e.to_string())?;
        let text = String::from_utf8_lossy(&text);
        shared.db.write_lines(&text).map_err(|e| e.to_string())?;
        Counters::bump(&shared.counters.restores);
        shared.progress.lock().0 = s.index;
        shared.write_note().map_err(|e| e.to_string())
    }

    fn snapshot(&mut self) -> std::result::Result<Vec<u8>, String> {
        let shared = &self.shared;
        shared.write_note().map_err(|e| e.to_string())?;
        let text = shared.db.dump().map_err(|e| e.to_string())?;
        Ok(flashkv::lz::compress(text.as_bytes()))
    }
}

fn now_ns() -> i64 {
    let since = SystemTime::now().duration_since(UNIX_EPOCH);
    since.map_or(0, |d| i64::try_from(d.as_nanos()).unwrap_or(i64::MAX))
}

/// A tsvdb node of a Raft cluster; see the module docs.
pub struct ReplicatedDb {
    server: Server,
    shared: Arc<Shared>,
}

impl ReplicatedDb {
    /// Opens (or creates) the node in `dir`, which holds the Raft state in
    /// `raft`, the database in `db` and the note of how far the log was
    /// applied. It listens on `listen`; `peers` are the addresses of the
    /// other nodes, including nodes that are not in the cluster yet (a
    /// leader can only add a node whose address it knows, and a node that is
    /// added must know where the leader is). `voters` are the voters of a new
    /// cluster, the same on every node that starts it; an empty list makes a
    /// node that waits to be added with `server().node().add_learner(id)` and
    /// `add_voter(id)` on the leader. A node that has a log goes by that.
    pub fn open(
        dir: &Path,
        id: NodeId,
        listen: SocketAddr,
        voters: &[NodeId],
        peers: &[(NodeId, SocketAddr)],
        opts: ClusterOptions,
    ) -> Result<Self> {
        let transport = Transport::bind(listen, opts.raft.net.clone())?;
        Self::open_on(dir, id, transport, voters, peers, opts)
    }

    /// Like [`ReplicatedDb::open`], on a transport that is already bound:
    /// its address is where the node listens.
    pub fn open_on(
        dir: &Path,
        id: NodeId,
        transport: Transport,
        voters: &[NodeId],
        peers: &[(NodeId, SocketAddr)],
        opts: ClusterOptions,
    ) -> Result<Self> {
        fs::create_dir_all(dir)?;
        let storage = FileStorage::open(&dir.join("raft"))?;
        // The note may only run behind the data, never ahead of it.
        let mut db_opts = opts.db;
        db_opts.kv.sync = true;
        let db = Arc::new(Db::open(&dir.join("db"), db_opts)?);
        let note = dir.join("applied");
        let base = match voters.is_empty() {
            true => Config::joiner(id),
            false => Config::cluster(id, voters.to_vec()),
        };
        let cfg = Config {
            election_timeout_min: opts.election_timeout.0,
            election_timeout_max: opts.election_timeout.1,
            heartbeat_interval: opts.heartbeat,
            ..base
        };
        let node = Node::new(cfg, storage)?;
        for &(peer, addr) in peers {
            transport.set_peer(peer, addr);
        }
        let applied = read_note(&note);
        let shared = Arc::new(Shared {
            db,
            counters: Counters::default(),
            refused: Mutex::new(BTreeMap::new()),
            progress: Mutex::new((applied, applied)),
            note,
        });
        let app = App { shared: shared.clone() };
        let server = Server::start(node, transport, app, opts.raft);
        Ok(ReplicatedDb { server, shared })
    }

    pub fn id(&self) -> NodeId {
        self.server.node().id()
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.server.local_addr()
    }

    pub fn is_leader(&self) -> bool {
        self.server.node().role() == raft::NodeState::Leader
    }

    /// The Raft server: role, leader, voters, membership changes.
    pub fn server(&self) -> &Server {
        &self.server
    }

    /// This node's database. Writing to it directly makes the copies differ.
    pub fn db(&self) -> &Db {
        &self.shared.db
    }

    pub fn stats(&self) -> ClusterStats {
        let c = &self.shared.counters;
        ClusterStats {
            applied_index: self.shared.applied(),
            applied_entries: c.applied_entries.load(Ordering::Relaxed),
            refused_entries: c.refused_entries.load(Ordering::Relaxed),
            restores: c.restores.load(Ordering::Relaxed),
        }
    }

    /// Writes line protocol through the leader (`Error::Raft(NotLeader(..))`
    /// elsewhere) and waits up to `timeout` for the leader to apply it.
    /// Returns the number of points. Malformed text is refused before it
    /// reaches the log; a write that the database refuses when applying it
    /// is [`Error::Rejected`].
    pub fn write_lines(&self, text: &str, timeout: Duration) -> Result<usize> {
        self.write_points(&lineproto::parse(text)?, timeout)
    }

    /// Like [`ReplicatedDb::write_lines`], for points. A point without a
    /// timestamp gets the leader's time, so that every node stores the same.
    pub fn write_points(&self, points: &[Point], timeout: Duration) -> Result<usize> {
        if points.is_empty() {
            return Ok(0);
        }
        let now = now_ns();
        let mut data = String::new();
        for p in points {
            lineproto::write_line(&mut data, p, Some(p.timestamp.unwrap_or(now)));
            data.push('\n');
        }
        let index = self.server.propose(data.into_bytes())?;
        self.server.wait_applied(index, timeout)?;
        match self.shared.refused.lock().remove(&index) {
            Some(why) => Err(Error::Rejected(why)),
            None => Ok(points.len()),
        }
    }

    /// Runs `q` on this node's copy, which may lag the leader.
    pub fn query(&self, q: &Query) -> Result<Vec<Row>> {
        Ok(self.shared.db.query(q)?)
    }

    /// Runs `q` on the leader after a linearizable read barrier: it sees
    /// every write that was acknowledged before the call.
    pub fn query_consistent(&self, q: &Query, timeout: Duration) -> Result<Vec<Row>> {
        self.server.read_barrier(timeout)?;
        self.query(q)
    }

    /// Stops the node and notes how far it has applied the log. Also done
    /// on drop, which ignores a failure to write the note (it costs a replay).
    pub fn shutdown(&self) -> Result<()> {
        self.server.shutdown();
        Ok(self.shared.write_note()?)
    }
}

impl Drop for ReplicatedDb {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flashkv::env::{FaultEnv, OsEnv};
    use raft::{NetOptions, NodeState};
    use std::net::TcpListener;
    use std::time::Instant;
    use tsvdb::FieldValue;

    const LONG: Duration = Duration::from_secs(20);

    fn tmpdir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("cluster-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    fn free_addr() -> SocketAddr {
        TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap()
    }

    fn any_local() -> SocketAddr {
        "127.0.0.1:0".parse().unwrap()
    }

    /// A transport on `addr`, retried while something else is on it for a
    /// moment (a connection of another test may hold the port).
    fn bind_again(addr: SocketAddr, opts: &ClusterOptions) -> Transport {
        wait_until("the address", || Transport::bind(addr, opts.raft.net.clone()).ok())
    }

    fn fast(snapshot_every: u64) -> ClusterOptions {
        let mut db = DbOptions::default();
        db.kv.background = false;
        ClusterOptions {
            raft: ServerOptions {
                tick: Duration::from_millis(4),
                snapshot_every,
                net: NetOptions {
                    retry_after: Duration::from_millis(10),
                    ..NetOptions::default()
                },
            },
            election_timeout: (50, 100),
            heartbeat: 3,
            db,
        }
    }

    fn wait_until<T>(what: &str, mut f: impl FnMut() -> Option<T>) -> T {
        let start = Instant::now();
        loop {
            if let Some(v) = f() {
                return v;
            }
            assert!(start.elapsed() < LONG, "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    /// Nodes `1..=voters` that start a cluster, and `spare` more that wait
    /// to be added; every node knows every address.
    struct Cluster {
        dir: PathBuf,
        addrs: Vec<(NodeId, SocketAddr)>,
        voters: Vec<NodeId>,
        opts: ClusterOptions,
        nodes: Vec<Option<ReplicatedDb>>,
    }

    impl Cluster {
        fn start(name: &str, voters: u64, spare: u64, opts: ClusterOptions) -> Cluster {
            let ids: Vec<NodeId> = (1..=voters + spare).collect();
            // Bound now and kept, so that no other test can take the ports.
            let transports: Vec<Transport> = (ids.iter())
                .map(|_| Transport::bind(any_local(), opts.raft.net.clone()).unwrap())
                .collect();
            let mut c = Cluster {
                dir: tmpdir(name),
                addrs: ids
                    .iter()
                    .zip(&transports)
                    .map(|(&id, t)| (id, t.local_addr()))
                    .collect(),
                voters: (1..=voters).collect(),
                opts,
                nodes: Vec::new(),
            };
            c.nodes = ids.iter().zip(transports).map(|(&id, t)| Some(c.open(id, t))).collect();
            c
        }

        fn open(&self, id: NodeId, transport: Transport) -> ReplicatedDb {
            let voters = if self.voters.contains(&id) {
                &self.voters[..]
            } else {
                &[]
            };
            let dir = self.dir.join(id.to_string());
            ReplicatedDb::open_on(&dir, id, transport, voters, &self.addrs, self.opts.clone()).unwrap()
        }

        fn node(&self, id: NodeId) -> &ReplicatedDb {
            self.nodes[(id - 1) as usize].as_ref().unwrap()
        }

        fn up(&self) -> impl Iterator<Item = &ReplicatedDb> {
            self.nodes.iter().flatten()
        }

        fn stop(&mut self, id: NodeId) {
            self.nodes[(id - 1) as usize].take().unwrap().shutdown().unwrap();
        }

        fn restart(&mut self, id: NodeId) {
            let transport = bind_again(self.addrs[(id - 1) as usize].1, &self.opts);
            self.nodes[(id - 1) as usize] = Some(self.open(id, transport));
        }

        fn leader(&self) -> &ReplicatedDb {
            wait_until("one leader", || {
                let mut leaders = self.up().filter(|n| n.is_leader());
                let first = leaders.next()?;
                leaders.next().is_none().then_some(first)
            })
        }

        /// Writes through the leader, retrying while the cluster settles.
        fn write(&self, text: &str) -> usize {
            wait_until("a write", || self.leader().write_lines(text, LONG).ok())
        }
    }

    impl Drop for Cluster {
        fn drop(&mut self) {
            self.nodes.clear();
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    fn usage(host: &str) -> Query {
        Query::new("cpu", "usage").filter("host", host)
    }

    /// The rows of `q` on every node that is up, once all have `want` rows.
    fn same_everywhere(c: &Cluster, q: &Query, want: usize) -> Vec<Row> {
        let rows = wait_until("the copies to converge", || {
            let all: Vec<Vec<Row>> = c.up().map(|n| n.query(q).unwrap()).collect();
            all.iter().all(|r| r.len() == want).then_some(all)
        });
        assert!(rows.windows(2).all(|w| w[0] == w[1]), "the copies differ: {rows:?}");
        rows.into_iter().next().unwrap()
    }

    #[test]
    fn writes_go_through_the_leader_and_reach_every_copy() {
        let c = Cluster::start("replicate", 3, 0, fast(0));
        let leader = c.leader();
        assert_eq!(c.write("cpu,host=a usage=1 10\ncpu,host=a usage=2 20\n"), 2);
        let rows = same_everywhere(&c, &usage("a"), 2);
        assert_eq!(rows[0].value, FieldValue::Float(1.0));
        // A follower does not take writes, and says who does.
        let follower = c.up().find(|n| n.id() != leader.id()).unwrap();
        let err = follower.write_lines("cpu,host=a usage=3 30", LONG).unwrap_err();
        let hint = format!("raft: not leader (leader hint: Some({}))", leader.id());
        assert_eq!(err.to_string(), hint);
        // Points without a timestamp get the leader's time, the same everywhere.
        assert_eq!(c.write("cpu,host=b usage=5\ncpu,host=b usage=6\n"), 2);
        let rows = same_everywhere(&c, &usage("b"), 1);
        assert!(rows[0].ts > 1_000_000_000_000_000_000, "{rows:?}");
        // Text that is no line protocol never reaches the log; none is a no-op.
        let before = leader.server().node().commit_index();
        let err = leader.write_lines("not a point", LONG).unwrap_err();
        assert!(err.to_string().starts_with("database: line 1"), "{err}");
        assert_eq!(leader.write_lines("\n\n", LONG).unwrap(), 0);
        assert_eq!(leader.server().node().commit_index(), before);
        // The consistent read is the leader's, and sees the last write at once.
        let q = usage("b");
        assert_eq!(leader.query_consistent(&q, LONG).unwrap().len(), 1);
        let err = follower.query_consistent(&q, LONG).unwrap_err();
        assert_eq!(err.to_string(), hint);
        // Points are written the same way, and a write of none is a no-op.
        let point = Point::new("cpu")
            .tag("host", "p")
            .field("usage", FieldValue::Float(7.0));
        assert_eq!(leader.write_points(&[point.clone(), point.at(5)], LONG).unwrap(), 2);
        assert_eq!(leader.write_points(&[], LONG).unwrap(), 0);
        same_everywhere(&c, &usage("p"), 2);
        // A query that is no query is the caller's error, on any node.
        let err = leader.query(&q.clone().range(5, 5)).unwrap_err();
        assert!(err.to_string().starts_with("database: invalid query"), "{err}");
        assert_eq!(leader.stats().refused_entries, 0);
        assert_eq!(leader.id(), leader.server().node().id());
        assert!(leader.local_addr().port() > 0);
        assert!(leader.db().measurements().contains(&"cpu".to_string()));
    }

    #[test]
    fn a_write_the_database_refuses_is_refused_on_every_node() {
        let c = Cluster::start("refuse", 3, 0, fast(0));
        c.write("cpu,host=a usage=1 10");
        // The field is a float; an integer is parsed fine and refused when
        // applied, on every node alike.
        let leader = c.leader();
        let err = leader.write_lines("cpu,host=a usage=2i 20", LONG).unwrap_err();
        assert!(err.to_string().starts_with("write refused: schema conflict"), "{err}");
        wait_until("every node to refuse it", || {
            c.up().all(|n| n.stats().refused_entries == 1).then_some(())
        });
        assert_eq!(same_everywhere(&c, &usage("a"), 1).len(), 1);
        // Nothing stopped: the next write goes through.
        assert_eq!(c.write("cpu,host=a usage=3 30"), 1);
        same_everywhere(&c, &usage("a"), 2);
        assert!(leader.server().failure().is_none());
    }

    #[test]
    fn a_node_that_is_restarted_catches_up_and_does_not_apply_twice() {
        let mut c = Cluster::start("restart", 3, 0, fast(0));
        c.write("cpu,host=a usage=1 10\ncpu,host=a usage=2 20\n");
        same_everywhere(&c, &usage("a"), 2);
        let victim = c.up().find(|n| !n.is_leader()).unwrap().id();
        let first = c.node(victim).stats();
        assert_eq!(first.applied_entries, 1);
        c.stop(victim);
        c.write("cpu,host=a usage=3 30");
        c.restart(victim);
        same_everywhere(&c, &usage("a"), 3);
        // The note said it had the first entry: only the new one was applied.
        let after = c.node(victim).stats();
        assert_eq!(after.applied_entries, 1, "{after:?}");
        assert!(after.applied_index > first.applied_index);
        // A node that lost its note replays the log, with the same result.
        c.stop(victim);
        fs::remove_file(c.dir.join(victim.to_string()).join("applied")).unwrap();
        c.restart(victim);
        same_everywhere(&c, &usage("a"), 3);
        wait_until("the replay", || {
            (c.node(victim).stats().applied_entries == 2).then_some(())
        });
    }

    #[test]
    fn a_new_node_is_brought_up_from_a_snapshot() {
        let c = Cluster::start("snapshot", 3, 1, fast(3));
        for t in 1..=12 {
            c.write(&format!("cpu,host=a usage={t} {t}\n"));
        }
        let leader = c.leader();
        wait_until("a snapshot", || {
            (leader.server().node().snapshot_index() > 0).then_some(())
        });
        leader.server().node().add_learner(4).unwrap();
        let newcomer = c.node(4);
        wait_until("the newcomer to restore", || {
            (newcomer.stats().restores >= 1).then_some(())
        });
        same_everywhere(&c, &usage("a"), 12);
        wait_until("promotion", || leader.server().node().add_voter(4).ok());
        wait_until("the new configuration", || {
            c.up()
                .all(|n| n.server().node().voters() == vec![1, 2, 3, 4])
                .then_some(())
        });
        // It takes part from now on.
        c.write("cpu,host=a usage=99 99");
        same_everywhere(&c, &usage("a"), 13);
        assert_eq!(newcomer.stats().refused_entries, 0);
    }

    #[test]
    fn the_cluster_survives_losing_its_leader() {
        let mut c = Cluster::start("failover", 3, 0, fast(0));
        c.write("cpu,host=a usage=1 10");
        let old = c.leader().id();
        c.stop(old);
        // The two that remain elect a leader and carry on.
        assert_eq!(c.write("cpu,host=a usage=2 20"), 1);
        same_everywhere(&c, &usage("a"), 2);
        c.restart(old);
        same_everywhere(&c, &usage("a"), 2);
        assert_ne!(c.leader().server().node().role(), NodeState::Follower);
    }

    #[test]
    fn a_database_that_fails_stops_the_node() {
        let dir = tmpdir("failing");
        let fault = Arc::new(FaultEnv::new(Arc::new(OsEnv)));
        let mut opts = fast(0);
        opts.db.kv.env = fault.clone();
        let node = ReplicatedDb::open(&dir, 1, free_addr(), &[1], &[], opts).unwrap();
        wait_until("leadership", || node.is_leader().then_some(()));
        assert_eq!(node.write_lines("cpu,host=a usage=1 10", LONG).unwrap(), 1);
        fault.fail_after(0);
        // The entry commits, but this node cannot write it: it stops.
        let err = node.write_lines("cpu,host=a usage=2 20", LONG).unwrap_err();
        assert_eq!(err.to_string(), "raft: the server has stopped");
        let why = node.server().failure().unwrap();
        assert!(why.starts_with("state machine: storage"), "{why}");
        drop(node);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn opening_reports_what_is_wrong() {
        let dir = tmpdir("open-errors");
        fs::create_dir_all(&dir).unwrap();
        let open = |d: &Path, id, listen: SocketAddr, voters: &[NodeId]| {
            let opened = ReplicatedDb::open(d, id, listen, voters, &[], fast(0));
            opened.err().unwrap().to_string()
        };
        // The directory cannot be created.
        fs::write(dir.join("file"), b"x").unwrap();
        let err = open(&dir.join("file").join("n"), 1, free_addr(), &[1]);
        assert!(err.starts_with("io: "), "{err}");
        // The Raft state, or the database, is not where it should be.
        let node = dir.join("a");
        fs::create_dir_all(&node).unwrap();
        fs::write(node.join("raft"), b"x").unwrap();
        assert!(open(&node, 1, free_addr(), &[1]).starts_with("raft: "));
        let node = dir.join("b");
        fs::create_dir_all(&node).unwrap();
        fs::write(node.join("db"), b"x").unwrap();
        assert!(open(&node, 1, free_addr(), &[1]).starts_with("database: "));
        // This node is not one of the voters.
        let err = open(&dir.join("c"), 9, free_addr(), &[1, 2]);
        assert_eq!(err, "raft: node not in peer set");
        // The address is not this machine's.
        let elsewhere: SocketAddr = "192.0.2.1:0".parse().unwrap();
        assert!(open(&dir.join("d"), 1, elsewhere, &[1]).starts_with("io: "));
        // Errors say what they are.
        for (e, want) in [
            (Error::from(raft::Error::Timeout), "raft: timed out"),
            (Error::from(io::Error::other("full")), "io: full"),
            (Error::Rejected("no".into()), "write refused: no"),
            (
                Error::from(tsvdb::Error::Query("q".into())),
                "database: invalid query: q",
            ),
        ] {
            assert_eq!(e.to_string(), want);
        }
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn shutdown_reports_a_note_it_cannot_write() {
        let dir = tmpdir("note-error");
        let node = ReplicatedDb::open(&dir, 1, free_addr(), &[1], &[], fast(0)).unwrap();
        // The note cannot be written where a directory is in the way...
        fs::create_dir_all(dir.join("applied.tmp")).unwrap();
        let err = node.shutdown().unwrap_err();
        assert!(err.to_string().starts_with("io: "), "{err}");
        // ... nor put in place where a directory that is not empty is.
        fs::remove_dir(dir.join("applied.tmp")).unwrap();
        fs::create_dir_all(dir.join("applied")).unwrap();
        fs::write(dir.join("applied").join("x"), b"x").unwrap();
        let err = node.shutdown().unwrap_err();
        assert!(err.to_string().starts_with("io: "), "{err}");
        drop(node);
        let _ = fs::remove_dir_all(dir);
    }

    /// The state machine alone, on a database in a directory of its own.
    fn app(name: &str, db_opts: DbOptions) -> (App, PathBuf) {
        let dir = tmpdir(name);
        fs::create_dir_all(&dir).unwrap();
        let shared = Shared {
            db: Arc::new(Db::open(&dir.join("db"), db_opts).unwrap()),
            counters: Counters::default(),
            refused: Mutex::new(BTreeMap::new()),
            progress: Mutex::new((0, 0)),
            note: dir.join("applied"),
        };
        (
            App {
                shared: Arc::new(shared),
            },
            dir,
        )
    }

    fn entry(index: Index, text: &str) -> LogEntry {
        LogEntry::new(index, 1, text.as_bytes().to_vec())
    }

    fn quiet() -> DbOptions {
        let mut o = DbOptions::default();
        o.kv.background = false;
        o
    }

    #[test]
    fn the_state_machine_applies_skips_and_refuses() {
        let (mut app, dir) = app("app", quiet());
        let shared = app.shared.clone();
        app.apply(&entry(1, "cpu,host=a usage=1 10\n")).unwrap();
        assert_eq!(
            (
                shared.applied(),
                shared.counters.applied_entries.load(Ordering::Relaxed)
            ),
            (1, 1)
        );
        // What the note covers is skipped, and so is a replay of an entry.
        app.apply(&entry(1, "cpu,host=a usage=7 10\n")).unwrap();
        assert_eq!(shared.db.query(&usage("a")).unwrap()[0].value, FieldValue::Float(1.0));
        // A type conflict and malformed data are refused, and noted as such.
        app.apply(&entry(2, "cpu,host=a usage=2i 20\n")).unwrap();
        app.apply(&entry(3, "garbage")).unwrap();
        assert_eq!(shared.counters.refused_entries.load(Ordering::Relaxed), 2);
        assert!(shared.refused.lock()[&2].contains("schema conflict"));
        assert!(shared.refused.lock()[&3].contains("line 1"));
        assert_eq!(shared.applied(), 3, "a refused entry is applied too");
        // The note follows after NOTE_EVERY entries, and read_note reads it.
        assert_eq!(read_note(&shared.note), 0);
        app.apply(&entry(NOTE_EVERY + 3, "cpu,host=a usage=4 40\n")).unwrap();
        assert_eq!(read_note(&shared.note), NOTE_EVERY + 3);
        // Old refusals are forgotten beyond a limit.
        for i in 0..KEPT_REFUSALS as u64 + 5 {
            shared.refuse(1_000 + i, "x".into());
        }
        let kept = shared.refused.lock();
        assert_eq!(kept.len(), KEPT_REFUSALS);
        assert!(!kept.contains_key(&2) && kept.contains_key(&(1_004 + KEPT_REFUSALS as u64)));
        drop(kept);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn a_storage_error_while_applying_is_the_nodes_end() {
        let fault = Arc::new(FaultEnv::new(Arc::new(OsEnv)));
        let mut opts = quiet();
        opts.kv.env = fault.clone();
        let (mut app, dir) = app("app-fails", opts);
        fault.fail_after(0);
        let err = app.apply(&entry(1, "cpu,host=a usage=1 10\n")).unwrap_err();
        assert!(err.starts_with("storage"), "{err}");
        assert_eq!(app.shared.applied(), 0);
        // So is a note that cannot be written.
        let (mut app, dir2) = app_with_bad_note("note-apply");
        let err = app
            .apply(&entry(NOTE_EVERY + 1, "cpu,host=a usage=1 10\n"))
            .unwrap_err();
        assert!(!err.is_empty());
        for d in [dir, dir2] {
            let _ = fs::remove_dir_all(d);
        }
    }

    /// A state machine whose note is a directory, so it cannot be written.
    fn app_with_bad_note(name: &str) -> (App, PathBuf) {
        let (app, dir) = app(name, quiet());
        fs::create_dir_all(dir.join("applied.tmp")).unwrap();
        (app, dir)
    }

    #[test]
    fn the_state_machine_restores_and_takes_snapshots() {
        let (mut source, dir_a) = app("snap-source", quiet());
        source
            .apply(&entry(1, "cpu,host=a usage=1 10\ncpu,host=b usage=2 10\n"))
            .unwrap();
        source.apply(&entry(2, "cpu,host=a usage=3 20\n")).unwrap();
        let data = source.snapshot().unwrap();
        assert_eq!(read_note(&source.shared.note), 2, "taking a snapshot writes the note");
        let snapshot = Snapshot {
            index: 2,
            term: 1,
            voters: vec![1],
            data,
        };
        let (mut target, dir_b) = app("snap-target", quiet());
        target.restore(&snapshot).unwrap();
        let shared = target.shared.clone();
        assert_eq!(
            (shared.applied(), shared.counters.restores.load(Ordering::Relaxed)),
            (2, 1)
        );
        assert_eq!(read_note(&shared.note), 2);
        for host in ["a", "b"] {
            assert_eq!(
                shared.db.query(&usage(host)).unwrap(),
                source.shared.db.query(&usage(host)).unwrap()
            );
        }
        // One it is past is skipped; damaged data is an error; so is an
        // empty database's snapshot, which restores nothing.
        target.restore(&snapshot).unwrap();
        assert_eq!(shared.counters.restores.load(Ordering::Relaxed), 1);
        let damaged = Snapshot {
            index: 9,
            data: vec![0xff; 12],
            ..snapshot.clone()
        };
        assert!(target.restore(&damaged).is_err());
        let (mut empty, dir_c) = app("snap-empty", quiet());
        let nothing = Snapshot {
            index: 5,
            data: empty.snapshot().unwrap(),
            ..snapshot
        };
        target.restore(&nothing).unwrap();
        assert_eq!(shared.applied(), 5);
        // A snapshot needs the note to be writable, and a database that works.
        let (mut stuck, dir_d) = app_with_bad_note("note-snapshot");
        assert!(stuck.snapshot().is_err());
        let fault = Arc::new(FaultEnv::new(Arc::new(OsEnv)));
        let mut opts = quiet();
        opts.kv.env = fault.clone();
        let (mut broken, dir_e) = app("snap-broken", opts);
        broken.apply(&entry(1, "cpu,host=a usage=1 10\n")).unwrap();
        // A write that fails poisons the database, and then it cannot be read.
        fault.fail_after(0);
        assert!(broken.apply(&entry(2, "cpu,host=a usage=2 20\n")).is_err());
        assert!(broken.snapshot().is_err());
        for d in [dir_a, dir_b, dir_c, dir_d, dir_e] {
            let _ = fs::remove_dir_all(d);
        }
    }

    #[test]
    fn restoring_into_a_database_that_fails_is_an_error() {
        let (mut source, dir_a) = app("restore-source", quiet());
        source.apply(&entry(1, "cpu,host=a usage=1 10\n")).unwrap();
        let snapshot = Snapshot {
            index: 1,
            term: 1,
            voters: vec![1],
            data: source.snapshot().unwrap(),
        };
        let fault = Arc::new(FaultEnv::new(Arc::new(OsEnv)));
        let mut opts = quiet();
        opts.kv.env = fault.clone();
        let (mut target, dir_b) = app("restore-target", opts);
        fault.fail_after(0);
        assert!(target.restore(&snapshot).is_err());
        assert_eq!(target.shared.applied(), 0);
        // A note that cannot be written after the restore fails it too.
        let (mut target, dir_c) = app_with_bad_note("note-restore");
        assert!(target.restore(&snapshot).is_err());
        for d in [dir_a, dir_b, dir_c] {
            let _ = fs::remove_dir_all(d);
        }
    }

    #[test]
    fn notes_are_read_defensively() {
        let dir = tmpdir("notes");
        fs::create_dir_all(&dir).unwrap();
        let note = dir.join("applied");
        assert_eq!(read_note(&note), 0, "no note");
        let write = |bytes: &[u8]| fs::write(&note, bytes).unwrap();
        let mut good = Vec::new();
        flashkv::log::frame(&mut good, &77u64.to_le_bytes());
        write(&good);
        assert_eq!(read_note(&note), 77);
        let mut trailing = good.clone();
        trailing.push(0);
        write(&trailing);
        assert_eq!(read_note(&note), 0, "junk after the record");
        let mut flipped = good.clone();
        flipped[9] ^= 1;
        write(&flipped);
        assert_eq!(read_note(&note), 0, "bad checksum");
        let mut short = Vec::new();
        flashkv::log::frame(&mut short, &[1, 2, 3]);
        write(&short);
        assert_eq!(read_note(&note), 0, "wrong size");
        let mut two = good.clone();
        two.extend(&good);
        write(&two);
        assert_eq!(read_note(&note), 0, "two records");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn options_and_conversions() {
        let o = ClusterOptions::default();
        assert!(o.raft.snapshot_every >= 10_000 && o.election_timeout.0 < o.election_timeout.1);
        assert!(o.heartbeat > 0);
        assert_eq!(ClusterStats::default().applied_index, 0);
        let p = Point::new("m").field("f", FieldValue::Int(1)).at(5);
        assert_eq!(lineproto::to_line(&p), "m f=1i 5");
    }
}
