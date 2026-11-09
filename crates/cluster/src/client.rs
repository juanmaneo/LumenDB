//! How to talk to a node from outside: a line-based text protocol over TCP,
//! the server that answers it for a [`ReplicatedDb`] ([`ClientServer`]), and
//! two clients ([`Client`]: one node; [`ClusterClient`]: a cluster, which
//! finds the leader).
//!
//! One request per line, the reply to each in order, on a connection that
//! stays open:
//!
//! | request | reply |
//! |---|---|
//! | `PING` | `OK PONG` |
//! | `STATUS` | `OK id=1 role=leader term=3 leader=1 voters=1,2,3 learners= commit=9 applied=9 snapshot=0 raft=ADDR` |
//! | `WRITE <bytes>`, a newline, then that many bytes of line protocol | `OK <points>` |
//! | `QUERY <consistent\|local> <measurement> <field> [start=NS] [end=NS] [agg=A] [every=NS] [top=N] [where=<tag>=<value>]...` | `ROWS <n>`, then n lines `series TAB ts TAB value` |
//! | `PEER <id> <addr>` | `OK ok`: where to send messages to node `id` (saved: it is still known after a restart) |
//! | `ADD-LEARNER <id>`, `REMOVE-LEARNER <id>` | `OK added`, `OK removed` |
//! | `ADD-VOTER <id>`, `REMOVE-VOTER <id>` | `OK <index of the configuration entry>` |
//! | `TRANSFER <id>` | `OK transferred`: leadership is handed to voter `id`, which now leads |
//! | `SHUTDOWN` | `OK stopping`, and the node stops |
//!
//! Anything can fail with `ERR <code> <text>`; see [`Code`]. A request that
//! cannot be parsed gets `ERR bad`, and the connection is closed. Names in a
//! query (measurement, field, tags, values) are percent-encoded: everything
//! but ASCII letters, digits and `._-:/,` is `%XX`, so a space or `=` never
//! occurs inside one. In rows, a backslash, tab, newline and carriage return
//! are written `\\`, `\t`, `\n` and `\r`.
//!
//! **Which node.** Writes, consistent queries and membership changes only
//! work on the leader (so does `TRANSFER`): elsewhere the reply is `ERR
//! notleader <id of the leader, or "unknown">`. A [`ClusterClient`] tries the nodes it was given
//! until one is the leader. It retries only when the request cannot have
//! been applied: a node that cannot be reached, `notleader` and `notready`.
//! A write that fails with `timeout` or a lost connection may or may not have
//! been applied, and the client does not guess.
//!
//! **Limits.** A request line is at most [`MAX_HEADER`] bytes and a write
//! at most [`MAX_BODY`] bytes.
//!
//! **Authentication.** With a [`Secret`] ([`ClientServer::start_with`],
//! [`Client::connect_with`], [`ClusterClient::set_secret`]), a connection
//! starts with a handshake that proves both ends know it, and everything
//! after is checked (see [`raft::auth`]). A client that has none, or another,
//! never gets a reply, so it cannot write, read or change the membership: with
//! another secret it is told so, and with none it just times out (or cannot
//! read what it gets). This is the same secret as the nodes use
//! among themselves, and whoever has it is trusted with everything: there are
//! no roles. There is **no encryption**: the requests and rows cross the
//! network as they are. The handshake of a connection that is not
//! authenticated waits as long as the server's `timeout`, and costs a thread
//! until then. Both sides must agree: a server without a secret does not
//! speak the handshake.

use crate::{Error, ReplicatedDb};
use parking_lot::{Condvar, Mutex};
use raft::{AuthStream, NodeId, Secret};
use std::collections::BTreeMap;
use std::fmt::{self, Write as _};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use tsvdb::{Agg, Query};

/// The longest request line, in bytes.
pub const MAX_HEADER: u64 = 64 * 1024;

/// The most line protocol one `WRITE` carries, in bytes.
pub const MAX_BODY: u64 = 64 * 1024 * 1024;

/// What the handshake of a client connection is for: see [`raft::auth`].
const PURPOSE: &str = "client";

/// The longest line a client accepts in a reply (a row).
const MAX_REPLY_LINE: u64 = 1024 * 1024;

/// How long a [`ClusterClient`] waits before it goes through the nodes again.
const RETRY_PAUSE: Duration = Duration::from_millis(20);

const MALFORMED: &str = "unknown or malformed request";

/// A parse failure; the text goes to the client.
type Parse<T> = std::result::Result<T, String>;

fn invalid(msg: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// A membership change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    AddLearner,
    AddVoter,
    RemoveVoter,
    RemoveLearner,
}

impl Change {
    pub const ALL: [Change; 4] = [
        Change::AddLearner,
        Change::AddVoter,
        Change::RemoveVoter,
        Change::RemoveLearner,
    ];

    /// The word that starts the request.
    pub fn verb(self) -> &'static str {
        match self {
            Change::AddLearner => "ADD-LEARNER",
            Change::AddVoter => "ADD-VOTER",
            Change::RemoveVoter => "REMOVE-VOTER",
            Change::RemoveLearner => "REMOVE-LEARNER",
        }
    }

    pub fn parse(verb: &str) -> Parse<Change> {
        Change::ALL
            .into_iter()
            .find(|c| c.verb() == verb)
            .ok_or_else(|| MALFORMED.to_string())
    }
}

/// A request to a node.
#[derive(Clone, Debug, PartialEq)]
pub enum Request {
    Ping,
    Status,
    /// Line protocol, as text.
    Write(String),
    Query {
        /// Linearizable, on the leader; otherwise the node's own copy.
        consistent: bool,
        query: Query,
        /// Keep the `n` rows with the largest values.
        top: Option<u64>,
    },
    /// Messages for this node go to this address.
    Peer(NodeId, SocketAddr),
    Member(Change, NodeId),
    /// Hand leadership to this voter.
    Transfer(NodeId),
    Shutdown,
}

/// Why a request failed; the word after `ERR`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Code {
    /// Not the leader; the text is the leader's id, or `unknown`.
    NotLeader,
    /// The leader has not committed an entry of its own term yet: retry.
    NotReady,
    /// Not done in time. A write may still commit.
    Timeout,
    /// The node is shutting down.
    Stopped,
    /// A membership change or a leadership transfer the leader refuses, or
    /// that the target did not complete: the text says why.
    Refused,
    /// The write committed and the database refused it (for example, a
    /// field that already has another type).
    Rejected,
    /// The request is malformed, or the query is invalid.
    Bad,
    /// Anything else, such as a failing disk.
    Internal,
}

impl Code {
    pub const ALL: [Code; 8] = [
        Code::NotLeader,
        Code::NotReady,
        Code::Timeout,
        Code::Stopped,
        Code::Refused,
        Code::Rejected,
        Code::Bad,
        Code::Internal,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Code::NotLeader => "notleader",
            Code::NotReady => "notready",
            Code::Timeout => "timeout",
            Code::Stopped => "stopped",
            Code::Refused => "refused",
            Code::Rejected => "rejected",
            Code::Bad => "bad",
            Code::Internal => "internal",
        }
    }

    fn parse(name: &str) -> Option<Code> {
        Code::ALL.into_iter().find(|c| c.name() == name)
    }
}

/// A row of a query result: [`tsvdb::Row`] with the value as text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResultRow {
    pub series: String,
    pub ts: i64,
    pub value: String,
}

/// The reply to a request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reply {
    Ok(String),
    Rows(Vec<ResultRow>),
    Err { code: Code, text: String },
}

impl fmt::Display for Reply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Reply::Ok(text) => f.write_str(text),
            Reply::Rows(rows) => write!(f, "{} rows", rows.len()),
            Reply::Err { code, text } => write!(f, "{} {text}", code.name()),
        }
    }
}

/// Everything but ASCII letters, digits and `._-:/,` as `%XX`.
pub fn encode_token(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b.is_ascii_alphanumeric() || b"._-:/,".contains(&b) {
            true => out.push(char::from(b)),
            false => {
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

/// The inverse of [`encode_token`].
pub fn decode_token(s: &str) -> Parse<String> {
    let mut out = Vec::with_capacity(s.len());
    let mut bytes = s.bytes();
    while let Some(b) = bytes.next() {
        if b != b'%' {
            out.push(b);
            continue;
        }
        let mut digit = || bytes.next().and_then(|c| char::from(c).to_digit(16));
        match (digit(), digit()) {
            (Some(hi), Some(lo)) => out.push(u8::try_from(hi * 16 + lo).expect("two hex digits")),
            _ => return Err("bad %-escape".to_string()),
        }
    }
    String::from_utf8(out).map_err(|_| "not UTF-8".to_string())
}

fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c => out.push(c),
        }
    }
    out
}

fn unescape(s: &str) -> Parse<String> {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        out.push(match chars.next() {
            Some('\\') => '\\',
            Some('t') => '\t',
            Some('n') => '\n',
            Some('r') => '\r',
            _ => return Err("bad escape in a row".to_string()),
        });
    }
    Ok(out)
}

fn uint(s: &str) -> Parse<u64> {
    s.parse().map_err(|_| format!("not a number: {s:?}"))
}

fn int(s: &str) -> Parse<i64> {
    s.parse().map_err(|_| format!("not a number: {s:?}"))
}

/// The next line without its newline; `None` at the end of the input. Fails
/// on a line longer than `limit` bytes, one that ends before its newline,
/// and one that is not UTF-8.
fn read_line(r: &mut dyn BufRead, limit: u64) -> io::Result<Option<String>> {
    let mut buf = Vec::new();
    if (&mut *r).take(limit).read_until(b'\n', &mut buf)? == 0 {
        return Ok(None);
    }
    if buf.pop() != Some(b'\n') {
        return Err(invalid("line too long or cut off"));
    }
    String::from_utf8(buf).map(Some).map_err(|_| invalid("not UTF-8"))
}

impl Request {
    /// The bytes to send: the line, and for a write its body.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = match self {
            Request::Ping => "PING".to_string(),
            Request::Status => "STATUS".to_string(),
            Request::Shutdown => "SHUTDOWN".to_string(),
            Request::Write(text) => format!("WRITE {}", text.len()),
            Request::Peer(id, addr) => format!("PEER {id} {addr}"),
            Request::Member(change, id) => format!("{} {id}", change.verb()),
            Request::Transfer(id) => format!("TRANSFER {id}"),
            Request::Query { consistent, query, top } => query_line(*consistent, query, *top),
        };
        out.push('\n');
        if let Request::Write(text) = self {
            out.push_str(text);
        }
        out.into_bytes()
    }
}

fn query_line(consistent: bool, q: &Query, top: Option<u64>) -> String {
    let mode = if consistent { "consistent" } else { "local" };
    let mut s = format!(
        "QUERY {mode} {} {} start={} end={}",
        encode_token(&q.measurement),
        encode_token(&q.field),
        q.start,
        q.end
    );
    if let Some(agg) = q.agg {
        let _ = write!(s, " agg={}", agg.name());
    }
    if let Some(every) = q.every {
        let _ = write!(s, " every={every}");
    }
    if let Some(n) = top {
        let _ = write!(s, " top={n}");
    }
    for (k, v) in &q.filters {
        let _ = write!(s, " where={}={}", encode_token(k), encode_token(v));
    }
    s
}

/// Reads one request; `None` when the peer has closed the connection.
/// A malformed request is an `InvalidData` error (the connection is of no
/// further use: where the next request starts is unknown).
pub fn read_request(r: &mut dyn BufRead) -> io::Result<Option<Request>> {
    let Some(line) = read_line(r, MAX_HEADER)? else {
        return Ok(None);
    };
    if let Some(len) = line.strip_prefix("WRITE ") {
        let len = uint(len).map_err(invalid)?;
        if len > MAX_BODY {
            return Err(invalid("write too large"));
        }
        let mut body = Vec::new();
        (&mut *r).take(len).read_to_end(&mut body)?;
        if body.len() as u64 != len {
            return Err(invalid("write cut short"));
        }
        let text = String::from_utf8(body).map_err(|_| invalid("not UTF-8"))?;
        return Ok(Some(Request::Write(text)));
    }
    parse_request(&line).map(Some).map_err(invalid)
}

fn parse_request(line: &str) -> Parse<Request> {
    let t: Vec<&str> = line.split(' ').collect();
    Ok(match t[..] {
        ["PING"] => Request::Ping,
        ["STATUS"] => Request::Status,
        ["SHUTDOWN"] => Request::Shutdown,
        ["PEER", id, addr] => Request::Peer(uint(id)?, addr.parse().map_err(|_| format!("bad address {addr:?}"))?),
        ["QUERY", mode, measurement, field, ref options @ ..] => parse_query(mode, measurement, field, options)?,
        ["TRANSFER", id] => Request::Transfer(uint(id)?),
        [verb, id] => Request::Member(Change::parse(verb)?, uint(id)?),
        _ => return Err(MALFORMED.to_string()),
    })
}

fn parse_query(mode: &str, measurement: &str, field: &str, options: &[&str]) -> Parse<Request> {
    let consistent = match mode {
        "consistent" => true,
        "local" => false,
        _ => return Err("the query mode is consistent or local".to_string()),
    };
    let mut query = Query::new(decode_token(measurement)?, decode_token(field)?);
    let mut top = None;
    for option in options {
        let (key, value) = option.split_once('=').ok_or("expected key=value")?;
        match key {
            "start" => query.start = int(value)?,
            "end" => query.end = int(value)?,
            "every" => query.every = Some(int(value)?),
            "top" => top = Some(uint(value)?),
            "agg" => query.agg = Some(Agg::parse(value).ok_or("unknown aggregate")?),
            "where" => {
                let (tag, tag_value) = value.split_once('=').ok_or("where= expects tag=value")?;
                query = query.filter(decode_token(tag)?, decode_token(tag_value)?);
            }
            _ => return Err(format!("unknown query option {key:?}")),
        }
    }
    Ok(Request::Query { consistent, query, top })
}

impl Reply {
    /// The bytes to send. Text that has a newline in it is cut into one line.
    pub fn encode(&self) -> Vec<u8> {
        let one_line = |s: &str| s.replace(['\n', '\r'], " ");
        match self {
            Reply::Ok(text) => format!("OK {}\n", one_line(text)),
            Reply::Err { code, text } => format!("ERR {} {}\n", code.name(), one_line(text)),
            Reply::Rows(rows) => {
                let mut s = format!("ROWS {}\n", rows.len());
                for r in rows {
                    let _ = writeln!(s, "{}\t{}\t{}", escape(&r.series), r.ts, escape(&r.value));
                }
                s
            }
        }
        .into_bytes()
    }
}

fn parse_row(line: &str) -> Parse<ResultRow> {
    let f: Vec<&str> = line.split('\t').collect();
    let [series, ts, value] = f[..] else {
        return Err("a row has three fields".to_string());
    };
    Ok(ResultRow {
        series: unescape(series)?,
        ts: int(ts)?,
        value: unescape(value)?,
    })
}

/// Reads one reply (`ERR` included: that is an answer, not a failure).
pub fn read_reply(r: &mut dyn BufRead) -> io::Result<Reply> {
    let line = read_line(r, MAX_REPLY_LINE)?.ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?;
    let (verb, rest) = line.split_once(' ').ok_or_else(|| invalid("reply without a verb"))?;
    match verb {
        "OK" => Ok(Reply::Ok(rest.to_string())),
        "ERR" => {
            let (code, text) = rest.split_once(' ').ok_or_else(|| invalid("ERR without a text"))?;
            let code = Code::parse(code).ok_or_else(|| invalid("unknown error code"))?;
            Ok(Reply::Err {
                code,
                text: text.to_string(),
            })
        }
        "ROWS" => {
            let n = uint(rest).map_err(invalid)?;
            let mut rows = Vec::new();
            for _ in 0..n {
                let row = read_line(r, MAX_REPLY_LINE)?.ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?;
                rows.push(parse_row(&row).map_err(invalid)?);
            }
            Ok(Reply::Rows(rows))
        }
        _ => Err(invalid("unknown reply")),
    }
}

/// The reply for a failure.
fn error_reply(e: &Error) -> Reply {
    let (code, text) = match e {
        Error::Raft(raft::Error::NotLeader(hint)) => (
            Code::NotLeader,
            hint.map_or("unknown".to_string(), |leader| leader.to_string()),
        ),
        Error::Raft(raft::Error::NotReady) => (Code::NotReady, e.to_string()),
        Error::Raft(raft::Error::Timeout) => (Code::Timeout, e.to_string()),
        Error::Raft(raft::Error::Stopped) => (Code::Stopped, e.to_string()),
        Error::Raft(raft::Error::BadConfig(_) | raft::Error::Transfer(_)) => (Code::Refused, e.to_string()),
        Error::Rejected(_) => (Code::Rejected, e.to_string()),
        Error::Db(tsvdb::Error::Parse { .. } | tsvdb::Error::Query(_) | tsvdb::Error::Schema(_)) => {
            (Code::Bad, e.to_string())
        }
        _ => (Code::Internal, e.to_string()),
    };
    Reply::Err { code, text }
}

fn status(db: &ReplicatedDb) -> String {
    let node = db.server().node();
    let list = |ids: Vec<NodeId>| ids.iter().map(NodeId::to_string).collect::<Vec<_>>().join(",");
    let leader = node.leader().map_or("none".to_string(), |l| l.to_string());
    let role = format!("{:?}", node.role()).to_lowercase();
    format!(
        "id={} role={role} term={} leader={leader} voters={} learners={} commit={} applied={} snapshot={} raft={}",
        node.id(),
        node.term(),
        list(node.voters()),
        list(node.learners()),
        node.commit_index(),
        db.stats().applied_index,
        node.snapshot_index(),
        db.local_addr()
    )
}

fn run_query(
    db: &ReplicatedDb,
    consistent: bool,
    query: &Query,
    top: Option<u64>,
    timeout: Duration,
) -> crate::Result<Reply> {
    let rows = if consistent {
        db.query_consistent(query, timeout)
    } else {
        db.query(query)
    }?;
    let rows = match top {
        Some(n) => tsvdb::query::top_n(rows, usize::try_from(n).unwrap_or(usize::MAX)),
        None => rows,
    };
    let rows = rows.iter().map(|r| ResultRow {
        series: r.series.clone(),
        ts: r.ts,
        value: r.value.to_string(),
    });
    Ok(Reply::Rows(rows.collect()))
}

fn change_membership(db: &ReplicatedDb, change: Change, id: NodeId) -> crate::Result<String> {
    let node = db.server().node();
    let done = match change {
        Change::AddLearner => node.add_learner(id).map(|()| "added".to_string()),
        Change::RemoveLearner => node.remove_learner(id).map(|()| "removed".to_string()),
        Change::AddVoter => node.add_voter(id).map(|index| index.to_string()),
        Change::RemoveVoter => node.remove_voter(id).map(|index| index.to_string()),
    };
    Ok(done?)
}

fn transfer(db: &ReplicatedDb, id: NodeId, timeout: Duration) -> crate::Result<String> {
    db.server().transfer_leadership(id, timeout)?;
    Ok("transferred".to_string())
}

/// Does what `req` asks on `db`; waits up to `timeout` for a write to be
/// applied, a read barrier to be reached or a leadership transfer to be done. `SHUTDOWN` only answers: stopping
/// is up to the caller ([`ClientServer`] does it).
pub fn execute(db: &ReplicatedDb, req: &Request, timeout: Duration) -> Reply {
    let done = match req {
        Request::Ping => Ok(Reply::Ok("PONG".to_string())),
        Request::Status => Ok(Reply::Ok(status(db))),
        Request::Shutdown => Ok(Reply::Ok("stopping".to_string())),
        Request::Write(text) => db.write_lines(text, timeout).map(|n| Reply::Ok(n.to_string())),
        Request::Query { consistent, query, top } => run_query(db, *consistent, query, *top, timeout),
        Request::Peer(id, addr) => db.set_peer(*id, *addr).map(|()| Reply::Ok("ok".to_string())),
        Request::Member(change, id) => change_membership(db, *change, *id).map(Reply::Ok),
        Request::Transfer(id) => transfer(db, *id, timeout).map(Reply::Ok),
    };
    done.unwrap_or_else(|e| error_reply(&e))
}

/// What the listener, the connections and the owner of a [`ClientServer`]
/// share.
struct Shared {
    stop: AtomicBool,
    next_conn: AtomicU64,
    conns: Mutex<BTreeMap<u64, TcpStream>>,
    /// Set by `SHUTDOWN` and by [`ClientServer::stop`].
    down: Mutex<bool>,
    down_changed: Condvar,
}

impl Shared {
    fn signal(&self) {
        *self.down.lock() = true;
        self.down_changed.notify_all();
    }
}

/// Answers the client protocol for a [`ReplicatedDb`]: a thread listens, and
/// each connection has a thread of its own.
pub struct ClientServer {
    addr: SocketAddr,
    shared: Arc<Shared>,
    acceptor: Mutex<Option<JoinHandle<()>>>,
    handlers: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

impl ClientServer {
    /// Listens on `listen` (port 0 lets the system pick one: see
    /// [`ClientServer::local_addr`]). A write or a consistent read waits up
    /// to `timeout` for the node.
    pub fn start(db: Arc<ReplicatedDb>, listen: SocketAddr, timeout: Duration) -> io::Result<ClientServer> {
        ClientServer::start_with(db, listen, timeout, None)
    }

    /// [`ClientServer::start`], and with a `secret` a client has to prove it
    /// knows it first, within `timeout`: see the module docs.
    pub fn start_with(
        db: Arc<ReplicatedDb>,
        listen: SocketAddr,
        timeout: Duration,
        secret: Option<Secret>,
    ) -> io::Result<ClientServer> {
        let listener = TcpListener::bind(listen)?;
        // Neither can fail on a socket that has just been bound.
        listener
            .set_nonblocking(true)
            .expect("a new listener can be made non-blocking");
        let addr = listener.local_addr().expect("a bound listener has an address");
        let shared = Arc::new(Shared {
            stop: AtomicBool::new(false),
            next_conn: AtomicU64::new(0),
            conns: Mutex::new(BTreeMap::new()),
            down: Mutex::new(false),
            down_changed: Condvar::new(),
        });
        let handlers = Arc::new(Mutex::new(Vec::new()));
        let acceptor = {
            let (shared, handlers) = (shared.clone(), handlers.clone());
            thread::spawn(move || accept_loop(&listener, &db, &shared, &handlers, timeout, secret))
        };
        Ok(ClientServer {
            addr,
            shared,
            acceptor: Mutex::new(Some(acceptor)),
            handlers,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Blocks until a client sent `SHUTDOWN`, or [`ClientServer::stop`] ran.
    pub fn wait_shutdown(&self) {
        let mut down = self.shared.down.lock();
        self.shared.down_changed.wait_while(&mut down, |down| !*down);
    }

    /// Stops listening, closes every connection and waits for the threads.
    /// Idempotent; also done on drop. It does not stop the node.
    pub fn stop(&self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        // The acceptor first: after it, no connection is registered anymore.
        if let Some(acceptor) = self.acceptor.lock().take() {
            let _ = acceptor.join();
        }
        for conn in self.shared.conns.lock().values() {
            let _ = conn.shutdown(Shutdown::Both);
        }
        let handlers: Vec<JoinHandle<()>> = self.handlers.lock().drain(..).collect();
        for handler in handlers {
            let _ = handler.join();
        }
        self.shared.signal();
    }
}

impl Drop for ClientServer {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Accepts connections until told to stop, a thread for each.
fn accept_loop(
    listener: &TcpListener,
    db: &Arc<ReplicatedDb>,
    shared: &Arc<Shared>,
    handlers: &Mutex<Vec<JoinHandle<()>>>,
    timeout: Duration,
    secret: Option<Secret>,
) {
    while !shared.stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                // Not inheriting the listener's mode is not guaranteed.
                let _ = stream.set_nonblocking(false);
                let _ = stream.set_nodelay(true);
                let id = shared.next_conn.fetch_add(1, Ordering::Relaxed);
                // A connection that cannot be copied just cannot be closed from here.
                shared.conns.lock().extend(stream.try_clone().map(|copy| (id, copy)));
                let (db, shared, secret) = (db.clone(), shared.clone(), secret.clone());
                let handler = thread::spawn(move || {
                    serve_connection(stream, &db, &shared, timeout, secret.as_ref());
                    shared.conns.lock().remove(&id);
                });
                let mut handlers = handlers.lock();
                handlers.retain(|h| !h.is_finished());
                handlers.push(handler);
            }
            // Nothing to accept (or the system is out of descriptors): wait.
            Err(_) => thread::sleep(Duration::from_millis(5)),
        }
    }
}

/// Answers the requests of one connection until it ends, a request is
/// malformed, or one asks the node to stop. With a secret, a client that
/// cannot prove it knows it is dropped without a reply.
fn serve_connection(stream: TcpStream, db: &ReplicatedDb, shared: &Shared, timeout: Duration, secret: Option<&Secret>) {
    let stream = match secret {
        None => AuthStream::plain(stream),
        // (a timeout of zero would mean no timeout at all)
        Some(secret) => match AuthStream::accept(stream, secret, PURPOSE, timeout.max(Duration::from_millis(1))) {
            Ok(stream) => stream,
            Err(_) => return,
        },
    };
    let mut conn = BufReader::new(stream);
    loop {
        let req = match read_request(&mut conn) {
            Ok(Some(req)) => req,
            Ok(None) => return,
            Err(e) => {
                let bad = Reply::Err {
                    code: Code::Bad,
                    text: e.to_string(),
                };
                let _ = conn.get_mut().write_all(&bad.encode());
                return;
            }
        };
        let sent = conn.get_mut().write_all(&execute(db, &req, timeout).encode());
        // The reply is on its way before the owner is told to stop.
        let stop = req == Request::Shutdown;
        if stop {
            shared.signal();
        }
        if stop || sent.is_err() {
            return;
        }
    }
}

/// A connection to one node.
pub struct Client {
    stream: BufReader<AuthStream>,
}

impl Client {
    /// Connects, waiting up to `timeout`; the same time limits every wait for
    /// a reply later.
    pub fn connect(addr: SocketAddr, timeout: Duration) -> io::Result<Client> {
        Client::connect_with(addr, timeout, None)
    }

    /// [`Client::connect`], and with a `secret` the handshake that proves
    /// both ends know it, which also has to finish within `timeout`. The
    /// server must have the same secret.
    pub fn connect_with(addr: SocketAddr, timeout: Duration, secret: Option<&Secret>) -> io::Result<Client> {
        let stream = TcpStream::connect_timeout(&addr, timeout)?;
        // These fail only on a socket that is already gone, which the first
        // call finds out about.
        let _ = stream.set_nodelay(true);
        let _ = stream.set_read_timeout(Some(timeout));
        let _ = stream.set_write_timeout(Some(timeout));
        let stream = match secret {
            None => AuthStream::plain(stream),
            Some(secret) => AuthStream::connect(stream, secret, PURPOSE)?,
        };
        Ok(Client {
            stream: BufReader::new(stream),
        })
    }

    /// Sends `req` and waits for the reply. An error means the outcome is
    /// not known: a write may have been applied.
    pub fn call(&mut self, req: &Request) -> io::Result<Reply> {
        let sent = self.stream.get_mut().write_all(&req.encode());
        sent.and_then(|()| read_reply(&mut self.stream))
    }
}

/// Finds the leader of a cluster among the nodes it knows; see the module
/// docs for what it retries.
pub struct ClusterClient {
    nodes: Vec<SocketAddr>,
    timeout: Duration,
    patience: Duration,
    /// Where the next call starts: the node that answered the last one.
    first: usize,
    secret: Option<Secret>,
}

impl ClusterClient {
    /// `nodes` are client addresses (see [`ClientServer`]). `timeout` limits
    /// one connection attempt and one wait for a reply; `patience` is how
    /// long [`ClusterClient::call`] keeps looking for a leader.
    pub fn new(nodes: Vec<SocketAddr>, timeout: Duration, patience: Duration) -> Self {
        ClusterClient {
            nodes,
            timeout,
            patience,
            first: 0,
            secret: None,
        }
    }

    /// Authenticates to the nodes from now on, which must have the same
    /// secret; `None` goes back to none.
    pub fn set_secret(&mut self, secret: Option<Secret>) {
        self.secret = secret;
    }

    /// Sends `req` to the nodes in turn until one that is the leader (or,
    /// for a request that does not need it, any node) answers. After the
    /// patience is used up, the last answer is returned: `ERR notleader`
    /// if the nodes were up but there was no leader, or the error of the
    /// last attempt to connect.
    pub fn call(&mut self, req: &Request) -> io::Result<Reply> {
        let deadline = Instant::now() + self.patience;
        let mut last = Err(io::Error::from(io::ErrorKind::NotConnected));
        loop {
            for k in 0..self.nodes.len() {
                let i = (self.first + k) % self.nodes.len();
                let mut client = match Client::connect_with(self.nodes[i], self.timeout, self.secret.as_ref()) {
                    Ok(client) => client,
                    Err(e) => {
                        last = Err(e);
                        continue;
                    }
                };
                match client.call(req) {
                    r @ Ok(Reply::Err {
                        code: Code::NotLeader | Code::NotReady,
                        ..
                    }) => last = r,
                    answer => {
                        self.first = i;
                        return answer;
                    }
                }
            }
            if Instant::now() >= deadline {
                return last;
            }
            thread::sleep(RETRY_PAUSE);
        }
    }

    /// Sends `req` to every node, whatever it answers.
    pub fn each(&self, req: &Request) -> Vec<(SocketAddr, io::Result<Reply>)> {
        let ask = |addr| {
            Client::connect_with(addr, self.timeout, self.secret.as_ref()).and_then(|mut client| client.call(req))
        };
        self.nodes.iter().map(|&addr| (addr, ask(addr))).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ClusterOptions;
    use raft::{NetOptions, ServerOptions, Transport};
    use std::path::PathBuf;
    use tsvdb::DbOptions;

    const LONG: Duration = Duration::from_secs(20);

    fn tmpdir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("cluster-client-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    fn any_local() -> SocketAddr {
        "127.0.0.1:0".parse().unwrap()
    }

    /// An address nothing listens on.
    fn dead_addr() -> SocketAddr {
        TcpListener::bind(any_local()).unwrap().local_addr().unwrap()
    }

    fn fast() -> ClusterOptions {
        let mut db = DbOptions::default();
        db.kv.background = false;
        ClusterOptions {
            raft: ServerOptions {
                tick: Duration::from_millis(4),
                snapshot_every: 0,
                net: NetOptions {
                    retry_after: Duration::from_millis(10),
                    ..NetOptions::default()
                },
            },
            election_timeout: (50, 100),
            heartbeat: 3,
            snapshot_chunk: raft::node::SNAPSHOT_CHUNK,
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
            thread::sleep(Duration::from_millis(2));
        }
    }

    fn row(series: &str, ts: i64, value: &str) -> ResultRow {
        ResultRow {
            series: series.to_string(),
            ts,
            value: value.to_string(),
        }
    }

    /// A node and its client port.
    struct Node {
        db: Arc<ReplicatedDb>,
        gate: ClientServer,
        dir: PathBuf,
    }

    impl Node {
        fn addr(&self) -> SocketAddr {
            self.gate.local_addr()
        }

        /// Stops the node, as far as its clients can tell.
        fn kill(&self) {
            self.gate.stop();
            self.db.shutdown().unwrap();
        }
    }

    impl Drop for Node {
        fn drop(&mut self) {
            self.kill();
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn node(db: ReplicatedDb, dir: PathBuf) -> Node {
        node_with(db, dir, None)
    }

    fn node_with(db: ReplicatedDb, dir: PathBuf, secret: Option<&Secret>) -> Node {
        let db = Arc::new(db);
        let gate = ClientServer::start_with(db.clone(), any_local(), LONG, secret.cloned()).unwrap();
        Node { db, gate, dir }
    }

    fn secret() -> Secret {
        Secret::new(b"client-test-secret-0123456789").unwrap()
    }

    fn other_secret() -> Secret {
        Secret::new(b"another-client-secret-012345").unwrap()
    }

    /// Nodes `1..=n`, all voters, that know each other.
    fn start(name: &str, n: u64) -> Vec<Node> {
        start_secure(name, n, None)
    }

    /// [`start`], with the nodes and their clients sharing a secret.
    fn start_secure(name: &str, n: u64, secret: Option<&Secret>) -> Vec<Node> {
        let mut opts = fast();
        opts.raft.net.secret = secret.cloned();
        let ids: Vec<NodeId> = (1..=n).collect();
        // Bound now and kept, so that no other test can take the ports.
        let transports: Vec<Transport> = (ids.iter())
            .map(|_| Transport::bind(any_local(), opts.raft.net.clone()).unwrap())
            .collect();
        let addrs: Vec<(NodeId, SocketAddr)> = ids
            .iter()
            .zip(&transports)
            .map(|(&id, t)| (id, t.local_addr()))
            .collect();
        (ids.iter().zip(transports))
            .map(|(&id, t)| {
                let dir = tmpdir(&format!("{name}-{id}"));
                let db = ReplicatedDb::open_on(&dir, id, t, &ids, &addrs, opts.clone()).unwrap();
                node_with(db, dir, secret)
            })
            .collect()
    }

    /// A node that knows only `peers`.
    fn open_node(name: &str, id: NodeId, voters: &[NodeId], peers: &[(NodeId, SocketAddr)]) -> Node {
        let dir = tmpdir(name);
        let db = ReplicatedDb::open(&dir, id, any_local(), voters, peers, fast()).unwrap();
        node(db, dir)
    }

    fn leader(nodes: &[Node]) -> &Node {
        wait_until("a leader", || nodes.iter().find(|n| n.db.is_leader()))
    }

    fn all_requests() -> Vec<Request> {
        let mut full = Query::new("my meas", "f=1")
            .range(-5, 99)
            .agg(Agg::Mean)
            .filter("host name", "a=b c")
            .filter("dc", "");
        full.every = Some(60);
        let mut all = vec![
            Request::Ping,
            Request::Status,
            Request::Shutdown,
            Request::Write("cpu,host=a usage=1 10\ncpu,host=a usage=2 20\n".to_string()),
            Request::Write(String::new()),
            Request::Write("héllo ✓ 100%".to_string()),
            Request::Peer(7, "127.0.0.1:4000".parse().unwrap()),
            Request::Peer(7, "[::1]:4000".parse().unwrap()),
            Request::Query {
                consistent: true,
                query: Query::new("flows", "bytes"),
                top: None,
            },
            Request::Query {
                consistent: false,
                query: full,
                top: Some(3),
            },
        ];
        all.extend(Change::ALL.map(|change| Request::Member(change, 4)));
        all.push(Request::Transfer(4));
        all
    }

    #[test]
    fn tokens_round_trip_and_bad_escapes_are_refused() {
        for s in [
            "",
            "plain._-:/,",
            "a b",
            "k=v",
            "100%",
            "tab\t",
            "héllo ✓",
            "line\nbreak",
        ] {
            let token = encode_token(s);
            assert!(!token.contains([' ', '=', '\t', '\n']), "{token}");
            assert_eq!(decode_token(&token).unwrap(), s);
        }
        assert_eq!(encode_token("a b=c"), "a%20b%3Dc");
        assert_eq!(decode_token("a%20b%3dc").unwrap(), "a b=c");
        for bad in ["%", "%4", "%zz", "%4z"] {
            assert_eq!(decode_token(bad).unwrap_err(), "bad %-escape", "{bad}");
        }
        assert_eq!(decode_token("%FF").unwrap_err(), "not UTF-8");
    }

    #[test]
    fn requests_round_trip() {
        for req in all_requests() {
            let encoded = req.encode();
            let mut input = &encoded[..];
            assert_eq!(read_request(&mut input).unwrap(), Some(req.clone()), "{req:?}");
            assert!(input.is_empty(), "{req:?} left bytes behind");
        }
        // They follow each other on one connection.
        let stream: Vec<u8> = all_requests().iter().flat_map(Request::encode).collect();
        let mut input = &stream[..];
        for req in all_requests() {
            assert_eq!(read_request(&mut input).unwrap(), Some(req));
        }
        assert_eq!(read_request(&mut input).unwrap(), None);
    }

    #[test]
    fn malformed_requests_are_refused() {
        let cases = [
            ("FROB\n", MALFORMED),
            ("PING x\n", MALFORMED),
            ("STATUS \n", MALFORMED),
            ("WRITE\n", MALFORMED),
            ("QUERY\n", MALFORMED),
            ("QUERY local m\n", MALFORMED),
            ("WRITE x\n", "not a number"),
            ("WRITE 5\nabc", "write cut short"),
            ("PEER x 127.0.0.1:1\n", "not a number"),
            ("PEER 1 nope\n", "bad address"),
            ("ADD-VOTER x\n", "not a number"),
            ("TRANSFER x\n", "not a number"),
            ("TRANSFER\n", MALFORMED),
            ("QUERY now m f\n", "the query mode is consistent or local"),
            ("QUERY local %zz f\n", "bad %-escape"),
            ("QUERY local m %zz\n", "bad %-escape"),
            ("QUERY local m f start\n", "expected key=value"),
            ("QUERY local m f start=x\n", "not a number"),
            ("QUERY local m f end=x\n", "not a number"),
            ("QUERY local m f every=x\n", "not a number"),
            ("QUERY local m f top=x\n", "not a number"),
            ("QUERY local m f agg=median\n", "unknown aggregate"),
            ("QUERY local m f where=abc\n", "where= expects tag=value"),
            ("QUERY local m f where=%zz=v\n", "bad %-escape"),
            ("QUERY local m f where=k=%zz\n", "bad %-escape"),
            ("QUERY local m f bogus=1\n", "unknown query option"),
            ("PING", "line too long or cut off"),
        ];
        for (input, want) in cases {
            let e = read_request(&mut input.as_bytes()).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::InvalidData, "{input:?}");
            assert!(e.to_string().contains(want), "{input:?}: {e}");
        }
        let too_long = format!("{}\n", "a".repeat(usize::try_from(MAX_HEADER).unwrap() + 10));
        let too_big = format!("WRITE {}\n", MAX_BODY + 1);
        for (input, want) in [
            (&too_long[..], "line too long or cut off"),
            (&too_big[..], "write too large"),
        ] {
            let e = read_request(&mut input.as_bytes()).unwrap_err();
            assert!(e.to_string().contains(want), "{e}");
        }
        for input in [&b"\xff\n"[..], &b"WRITE 2\n\xff\xfe"[..]] {
            let e = read_request(&mut &input[..]).unwrap_err();
            assert_eq!(e.to_string(), "not UTF-8");
        }
        assert_eq!(read_request(&mut &b""[..]).unwrap(), None);
    }

    #[test]
    fn replies_round_trip() {
        let mut all = vec![
            Reply::Ok("PONG".to_string()),
            Reply::Ok(String::new()),
            Reply::Rows(Vec::new()),
            Reply::Rows(vec![
                row("cpu,host=a", -5, "1.5"),
                row("a\\b\tc\nd\re", i64::MAX, "\"x\ty\""),
            ]),
            Reply::Err {
                code: Code::Bad,
                text: String::new(),
            },
        ];
        all.extend(Code::ALL.map(|code| Reply::Err {
            code,
            text: format!("{} text", code.name()),
        }));
        let stream: Vec<u8> = all.iter().flat_map(Reply::encode).collect();
        let mut input = &stream[..];
        for reply in &all {
            assert_eq!(&read_reply(&mut input).unwrap(), reply);
        }
        assert!(input.is_empty());
        // Text that has a newline in it stays one line.
        assert_eq!(Reply::Ok("two\nlines\r".to_string()).encode(), b"OK two lines \n");
    }

    #[test]
    fn malformed_replies_are_errors() {
        let cases = [
            ("", "unexpected end of file"),
            ("OK no newline", "line too long or cut off"),
            ("OK\n", "reply without a verb"),
            ("HUH x\n", "unknown reply"),
            ("ERR notleader\n", "ERR without a text"),
            ("ERR what x\n", "unknown error code"),
            ("ROWS x\n", "not a number"),
            ("ROWS 2\na\t1\tb\n", "unexpected end of file"),
            ("ROWS 1\na\tb\n", "a row has three fields"),
            ("ROWS 1\na\\q\t1\tb\n", "bad escape in a row"),
            ("ROWS 1\na\\\t1\tb\n", "bad escape in a row"),
            ("ROWS 1\na\tx\tb\n", "not a number"),
            ("ROWS 1\na\t1\tb\\q\n", "bad escape in a row"),
        ];
        for (input, want) in cases {
            let e = read_reply(&mut input.as_bytes()).unwrap_err();
            assert!(e.to_string().contains(want), "{input:?}: {e}");
        }
    }

    /// A connection that fails when read.
    struct Broken;

    impl Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("broken"))
        }
    }

    #[test]
    fn a_connection_that_fails_is_an_error() {
        // `head` arrives, then the connection breaks.
        let after = |head: &'static [u8]| BufReader::new(head.chain(Broken));
        for (what, e) in [
            ("a request", read_request(&mut after(b"")).unwrap_err()),
            ("a write", read_request(&mut after(b"WRITE 5\n")).unwrap_err()),
            ("a reply", read_reply(&mut after(b"")).unwrap_err()),
            ("the rows", read_reply(&mut after(b"ROWS 1\n")).unwrap_err()),
        ] {
            assert_eq!(e.to_string(), "broken", "{what}");
        }
    }

    #[test]
    fn replies_display_as_text() {
        assert_eq!(Reply::Ok("PONG".to_string()).to_string(), "PONG");
        assert_eq!(Reply::Rows(vec![row("a", 1, "2")]).to_string(), "1 rows");
        let e = Reply::Err {
            code: Code::NotLeader,
            text: "3".to_string(),
        };
        assert_eq!(e.to_string(), "notleader 3");
    }

    #[test]
    fn errors_become_codes() {
        use raft::Error as R;
        let db = |e| Error::Db(e);
        let cases = [
            (Error::Raft(R::NotLeader(Some(3))), Code::NotLeader, Some("3")),
            (Error::Raft(R::NotLeader(None)), Code::NotLeader, Some("unknown")),
            (Error::Raft(R::NotReady), Code::NotReady, None),
            (Error::Raft(R::Timeout), Code::Timeout, None),
            (Error::Raft(R::Stopped), Code::Stopped, None),
            (Error::Raft(R::BadConfig("already a voter")), Code::Refused, None),
            (Error::Raft(R::Transfer("not a voter")), Code::Refused, None),
            (Error::Rejected("nope".to_string()), Code::Rejected, None),
            (
                db(tsvdb::Error::Parse {
                    line: 1,
                    msg: "x".to_string(),
                }),
                Code::Bad,
                None,
            ),
            (db(tsvdb::Error::Query("q".to_string())), Code::Bad, None),
            (db(tsvdb::Error::Schema("s".to_string())), Code::Bad, None),
            (db(tsvdb::Error::Corrupt("c".to_string())), Code::Internal, None),
            (Error::Raft(R::Storage("disk".to_string())), Code::Internal, None),
            (Error::Io(io::Error::other("boom")), Code::Internal, None),
        ];
        for (e, code, text) in cases {
            let text = text.map_or(e.to_string(), String::from);
            assert_eq!(error_reply(&e), Reply::Err { code, text }, "{e}");
        }
        assert!(error_reply(&Error::Raft(raft::Error::BadConfig("why")))
            .to_string()
            .ends_with("membership change refused: why"));
    }

    #[test]
    fn a_node_executes_every_request() {
        let nodes = start("execute", 1);
        let n = leader(&nodes);
        let run = |req: Request| execute(&n.db, &req, LONG);
        assert_eq!(run(Request::Ping), Reply::Ok("PONG".to_string()));
        assert_eq!(run(Request::Shutdown), Reply::Ok("stopping".to_string()));
        assert_eq!(run(Request::Write(String::new())), Reply::Ok("0".to_string()));
        let lines = "cpu,host=a usage=1 10\ncpu,host=a usage=3 20\ncpu,host=b usage=9 10\n";
        assert_eq!(run(Request::Write(lines.to_string())), Reply::Ok("3".to_string()));
        let status = run(Request::Status).to_string();
        assert!(status.starts_with("id=1 role=leader term="), "{status}");
        assert!(status.contains(" leader=1 voters=1 learners= commit="), "{status}");
        assert!(status.contains(" snapshot=0 raft=127.0.0.1:"), "{status}");

        let query = |consistent, q: Query, top| {
            run(Request::Query {
                consistent,
                query: q,
                top,
            })
        };
        let raw = Query::new("cpu", "usage").filter("host", "a");
        for consistent in [false, true] {
            assert_eq!(
                query(consistent, raw.clone(), None),
                Reply::Rows(vec![row("cpu,host=a", 10, "1"), row("cpu,host=a", 20, "3")])
            );
            let sums = Query::new("cpu", "usage").agg(Agg::Sum);
            assert_eq!(
                query(consistent, sums.clone(), None),
                Reply::Rows(vec![row("cpu,host=a", i64::MIN, "4"), row("cpu,host=b", i64::MIN, "9")])
            );
            assert_eq!(
                query(consistent, sums, Some(1)),
                Reply::Rows(vec![row("cpu,host=b", i64::MIN, "9")])
            );
        }

        // Refused: a bad query, text that is not line protocol, and a field
        // that has another type (that one only when the write is applied).
        let bad = query(false, Query::new("cpu", "usage").range(5, 5), None);
        assert!(bad.to_string().starts_with("bad database: invalid query"), "{bad}");
        let bad = run(Request::Write("garbage".to_string()));
        assert!(bad.to_string().starts_with("bad database: line 1"), "{bad}");
        let rejected = run(Request::Write("cpu,host=a usage=1i 30\n".to_string()));
        assert!(
            rejected
                .to_string()
                .starts_with("rejected write refused: schema conflict"),
            "{rejected}"
        );

        let elsewhere: SocketAddr = "127.0.0.1:9".parse().unwrap();
        assert_eq!(run(Request::Peer(9, elsewhere)), Reply::Ok("ok".to_string()));
        assert_eq!(n.db.server().transport().peers().get(&9), Some(&elsewhere));

        // Nobody to hand leadership to in a cluster of one.
        assert_eq!(
            run(Request::Transfer(1)).to_string(),
            "refused raft: leadership transfer failed: the target is this node"
        );
        assert_eq!(
            run(Request::Transfer(2)).to_string(),
            "refused raft: leadership transfer failed: the target is not a voter"
        );
    }

    #[test]
    fn a_node_changes_its_membership_when_asked() {
        let nodes = start("members", 1);
        let n = leader(&nodes);
        let spare = open_node("members-2", 2, &[], &[(1, n.db.local_addr())]);
        let run = |req: Request| execute(&n.db, &req, LONG);
        assert_eq!(
            run(Request::Peer(2, spare.db.local_addr())),
            Reply::Ok("ok".to_string())
        );
        let leader_itself = run(Request::Member(Change::AddLearner, 1)).to_string();
        assert_eq!(
            leader_itself,
            "refused raft: membership change refused: this node is the leader"
        );
        assert_eq!(
            run(Request::Member(Change::AddLearner, 2)),
            Reply::Ok("added".to_string())
        );
        assert!(run(Request::Status).to_string().contains(" learners=2 "));
        // (refused until the learner has caught up, and while a change is pending)
        let change = |change: Change| {
            wait_until("the change to be accepted", || {
                run(Request::Member(change, 2)).to_string().parse::<u64>().ok()
            })
        };
        let added = change(Change::AddVoter);
        wait_until("the new voter to learn its role", || {
            (spare.db.server().node().voters() == [1, 2]).then_some(())
        });
        assert!(run(Request::Status).to_string().contains(" voters=1,2 "));
        let removed = change(Change::RemoveVoter);
        assert!(removed > added);
        assert_eq!(
            run(Request::Member(Change::AddLearner, 2)),
            Reply::Ok("added".to_string())
        );
        assert_eq!(
            run(Request::Member(Change::RemoveLearner, 2)),
            Reply::Ok("removed".to_string())
        );
        let again = run(Request::Member(Change::RemoveLearner, 2)).to_string();
        assert_eq!(again, "refused raft: membership change refused: not a learner");
    }

    #[test]
    fn followers_point_to_the_leader() {
        let nodes = start("redirect", 3);
        let lead = leader(&nodes);
        let lead_id = lead.db.id();
        wait_until("every node to know the leader", || {
            (nodes.iter())
                .all(|n| n.db.server().node().leader() == Some(lead_id))
                .then_some(())
        });
        let follower = nodes.iter().find(|n| n.db.id() != lead_id).unwrap();
        let on = |n: &Node, req: Request| execute(&n.db, &req, LONG);
        let moved = Reply::Err {
            code: Code::NotLeader,
            text: lead_id.to_string(),
        };
        assert_eq!(on(follower, Request::Write("m v=1 5\n".to_string())), moved);
        let q = Query::new("m", "v");
        let consistent = Request::Query {
            consistent: true,
            query: q.clone(),
            top: None,
        };
        assert_eq!(on(follower, consistent.clone()), moved);
        assert_eq!(on(follower, Request::Member(Change::AddLearner, 9)), moved);
        // Reading its own copy works anywhere, once it has the write.
        assert_eq!(
            on(lead, Request::Write("m v=1 5\n".to_string())),
            Reply::Ok("1".to_string())
        );
        assert_eq!(on(lead, consistent), Reply::Rows(vec![row("m", 5, "1")]));
        let local = Request::Query {
            consistent: false,
            query: q,
            top: None,
        };
        wait_until("the follower to apply the write", || {
            (on(follower, local.clone()) == Reply::Rows(vec![row("m", 5, "1")])).then_some(())
        });
    }

    #[test]
    fn the_server_answers_connections() {
        let nodes = start("sockets", 1);
        let n = leader(&nodes);
        let mut client = Client::connect(n.addr(), LONG).unwrap();
        let mut other = Client::connect(n.addr(), LONG).unwrap();
        assert_eq!(client.call(&Request::Ping).unwrap(), Reply::Ok("PONG".to_string()));
        assert_eq!(
            client.call(&Request::Write("m v=1 5\n".to_string())).unwrap(),
            Reply::Ok("1".to_string())
        );
        let q = Request::Query {
            consistent: true,
            query: Query::new("m", "v"),
            top: None,
        };
        assert_eq!(other.call(&q).unwrap(), Reply::Rows(vec![row("m", 5, "1")]));

        // A request that cannot be parsed ends the connection, with a reason.
        for (sent, want) in [
            (&b"FROB\n"[..], "ERR bad unknown or malformed request\n"),
            (&b"WRITE 10\nabc"[..], "ERR bad write cut short\n"),
        ] {
            let mut raw = TcpStream::connect(n.addr()).unwrap();
            raw.write_all(sent).unwrap();
            raw.shutdown(Shutdown::Write).unwrap();
            let mut reply = String::new();
            raw.read_to_string(&mut reply).unwrap();
            assert_eq!(reply, want);
        }

        // Stopping closes the connections that are idle, and is idempotent.
        let mut idle = TcpStream::connect(n.addr()).unwrap();
        n.gate.stop();
        n.gate.stop();
        assert_eq!(idle.read(&mut [0u8; 1]).unwrap_or(0), 0);
        assert!(client.call(&Request::Ping).is_err());
        assert!(other.call(&Request::Ping).is_err());
    }

    #[test]
    fn shutdown_wakes_the_owner() {
        let nodes = start("shutdown", 1);
        let n = leader(&nodes);
        thread::scope(|s| {
            let waiter = s.spawn(|| n.gate.wait_shutdown());
            let mut client = Client::connect(n.addr(), LONG).unwrap();
            assert_eq!(
                client.call(&Request::Shutdown).unwrap(),
                Reply::Ok("stopping".to_string())
            );
            waiter.join().unwrap();
            // The connection ends after SHUTDOWN.
            assert!(client.call(&Request::Ping).is_err());
        });
        // It stays shut down.
        n.gate.wait_shutdown();
    }

    #[test]
    fn start_and_connect_failures_are_errors() {
        let nodes = start("failures", 1);
        let n = leader(&nodes);
        let taken = ClientServer::start(n.db.clone(), n.addr(), LONG).err().unwrap();
        assert_eq!(taken.kind(), io::ErrorKind::AddrInUse);
        let refused = Client::connect(dead_addr(), LONG).err().unwrap();
        assert_eq!(refused.kind(), io::ErrorKind::ConnectionRefused);
        let no_time = Client::connect(n.addr(), Duration::ZERO).err().unwrap();
        assert_eq!(no_time.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn a_cluster_client_finds_the_leader_and_survives_losing_it() {
        let nodes = start("cluster-client", 3);
        let addrs: Vec<SocketAddr> = nodes.iter().map(Node::addr).collect();
        let mut c = ClusterClient::new(addrs, LONG, LONG);
        // (this waits for the election)
        let write = |n: u32| Request::Write(format!("m v={n} {n}\n"));
        assert_eq!(c.call(&write(5)).unwrap(), Reply::Ok("1".to_string()));
        let all = Request::Query {
            consistent: true,
            query: Query::new("m", "v"),
            top: None,
        };
        assert_eq!(c.call(&all).unwrap(), Reply::Rows(vec![row("m", 5, "5")]));

        let statuses: Vec<String> = c
            .each(&Request::Status)
            .into_iter()
            .map(|(_, reply)| reply.unwrap().to_string())
            .collect();
        assert_eq!(statuses.len(), 3);
        assert_eq!(statuses.iter().filter(|s| s.contains(" role=leader ")).count(), 1);

        // Lose the leader: it stays in the list, and refuses connections.
        leader(&nodes).kill();
        assert_eq!(c.call(&write(6)).unwrap(), Reply::Ok("1".to_string()));
        assert_eq!(
            c.call(&all).unwrap(),
            Reply::Rows(vec![row("m", 5, "5"), row("m", 6, "6")])
        );
        let pings = c.each(&Request::Ping);
        assert_eq!(pings.iter().filter(|(_, reply)| reply.is_err()).count(), 1);
        assert_eq!(pings.iter().filter(|(_, reply)| reply.is_ok()).count(), 2);
    }

    #[test]
    fn an_authenticated_cluster_serves_only_those_who_know_the_secret() {
        let s = secret();
        let nodes = start_secure("secure", 3, Some(&s));
        let addrs: Vec<SocketAddr> = nodes.iter().map(Node::addr).collect();
        let mut c = ClusterClient::new(addrs.clone(), LONG, LONG);
        c.set_secret(Some(s.clone()));
        // The nodes elect a leader, and replicate to each other, with the
        // secret on the Raft port too.
        assert_eq!(
            c.call(&Request::Write("m v=5 5\n".to_string())).unwrap(),
            Reply::Ok("1".to_string())
        );
        let local = Request::Query {
            consistent: false,
            query: Query::new("m", "v"),
            top: None,
        };
        let copy = Reply::Rows(vec![row("m", 5, "5")]);
        wait_until("every node to have the write", || {
            let copies = c.each(&local);
            (copies.iter().all(|(_, reply)| reply.as_ref().ok() == Some(&copy))).then_some(())
        });

        // A client has to know it, and gets told when it does not.
        let short = Duration::from_millis(300);
        let wrong = Client::connect_with(addrs[0], short, Some(&other_secret()))
            .err()
            .unwrap();
        assert!(wrong.to_string().contains("same secret"), "{wrong}");
        let mut none = Client::connect(addrs[0], short).unwrap();
        assert!(none.call(&Request::Ping).is_err());
        let mut none = ClusterClient::new(addrs.clone(), short, short);
        assert!(none.call(&Request::Ping).is_err());
        assert!(none.each(&Request::Ping).iter().all(|(_, reply)| reply.is_err()));
        let mut wrong = ClusterClient::new(addrs.clone(), short, short);
        wrong.set_secret(Some(other_secret()));
        let refused = wrong.call(&Request::Write("m v=6 6\n".to_string())).unwrap_err();
        assert!(refused.to_string().contains("same secret"), "{refused}");
        // Bytes that are no handshake end the connection.
        let mut raw = TcpStream::connect(addrs[0]).unwrap();
        raw.set_read_timeout(Some(LONG)).unwrap();
        raw.read_exact(&mut [0u8; 32]).unwrap();
        raw.write_all(&[0xAA; 100]).unwrap();
        assert_eq!(raw.read(&mut [0u8; 1]).unwrap_or(0), 0);
        // Nothing of that got in, and the cluster is as it was.
        assert_eq!(c.call(&local).unwrap(), copy);
        assert_eq!(
            c.each(&Request::Ping).iter().filter(|(_, reply)| reply.is_ok()).count(),
            3
        );
    }

    #[test]
    fn a_client_with_a_secret_gives_up_on_a_server_that_has_none() {
        let nodes = start("plain-server", 1);
        let short = Duration::from_millis(300);
        let e = Client::connect_with(nodes[0].addr(), short, Some(&secret()))
            .err()
            .unwrap();
        assert!(e.to_string().contains("same secret"), "{e}");
        // And the server is as it was.
        let mut client = Client::connect(nodes[0].addr(), LONG).unwrap();
        assert_eq!(client.call(&Request::Ping).unwrap(), Reply::Ok("PONG".to_string()));
    }

    #[test]
    fn a_cluster_client_gives_up_when_there_is_no_leader_or_no_node() {
        // One voter of three, alone: there is nobody to elect it.
        let alone = open_node("alone", 1, &[1, 2, 3], &[]);
        let mut c = ClusterClient::new(vec![alone.addr()], LONG, Duration::from_millis(100));
        assert_eq!(
            c.call(&Request::Write("m v=1 5\n".to_string())).unwrap(),
            Reply::Err {
                code: Code::NotLeader,
                text: "unknown".to_string()
            }
        );
        // A request that any node answers does not need one.
        assert_eq!(c.call(&Request::Ping).unwrap(), Reply::Ok("PONG".to_string()));

        let patience = Duration::from_millis(50);
        let mut c = ClusterClient::new(vec![dead_addr()], LONG, patience);
        assert_eq!(
            c.call(&Request::Ping).unwrap_err().kind(),
            io::ErrorKind::ConnectionRefused
        );
        let mut c = ClusterClient::new(Vec::new(), LONG, patience);
        assert_eq!(c.call(&Request::Ping).unwrap_err().kind(), io::ErrorKind::NotConnected);
    }
}
