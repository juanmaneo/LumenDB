//! A TCP transport for [`Message`]s, on `std::net` only.
//!
//! Raft needs no reliable delivery: it already copes with lost, duplicated
//! and reordered messages, which is what the simulator throws at it. So the
//! transport is deliberately lossy, and never blocks the node:
//!
//! - [`Transport::send`] encodes the message ([`crate::wire`]) and queues it
//!   for the peer's writer thread. A full queue, an unknown peer, a peer that
//!   is down and a failed write all just drop it.
//! - One writer thread per peer owns an outgoing connection, opened on the
//!   first message and again after a failure. After a failed connect it drops
//!   what arrives for [`NetOptions::retry_after`] instead of retrying each
//!   one.
//! - A listener thread accepts connections, one reader thread each. A reader
//!   decodes frames into the inbox, [`Transport::recv_timeout`], and drops
//!   the connection on a bad checksum, an oversized frame or garbage; the
//!   sender simply reconnects.
//!
//! Every drop is counted ([`Transport::stats`]). There is no authentication
//! and no encryption: run it on a trusted network, or wrap it (a VPN, or
//! stunnel). A message says who it is from, and the transport believes it.

use crate::message::Message;
use crate::wire::{decode, encode, read_frame, MAX_FRAME};
use crate::NodeId;
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetOptions {
    /// The largest frame a reader accepts. It must cover the largest message:
    /// a batch of entries, and a chunk of a snapshot (`Config::snapshot_chunk`),
    /// or the whole snapshot where chunking is off.
    pub max_frame: usize,
    /// Messages queued for one peer before new ones are dropped.
    pub outbox: usize,
    pub connect_timeout: Duration,
    /// A write that stalls this long fails the connection.
    pub write_timeout: Duration,
    /// After a failed connect, messages for that peer are dropped this long.
    pub retry_after: Duration,
}

impl Default for NetOptions {
    fn default() -> Self {
        NetOptions {
            max_frame: MAX_FRAME,
            outbox: 1024,
            connect_timeout: Duration::from_millis(500),
            write_timeout: Duration::from_secs(5),
            retry_after: Duration::from_millis(100),
        }
    }
}

/// What the transport did, since it started.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NetStats {
    /// Messages handed to a peer's connection.
    pub sent: u64,
    /// Messages decoded and put in the inbox.
    pub received: u64,
    /// Dropped because the peer's queue was full or the peer is unknown.
    pub dropped_unqueued: u64,
    /// Dropped because the peer could not be reached.
    pub dropped_unreachable: u64,
    /// Failed writes: the message is lost, the connection is closed.
    pub write_errors: u64,
    /// Inbound connections closed for sending bad frames.
    pub bad_frames: u64,
}

#[derive(Default)]
struct Counters {
    sent: AtomicU64,
    received: AtomicU64,
    dropped_unqueued: AtomicU64,
    dropped_unreachable: AtomicU64,
    write_errors: AtomicU64,
    bad_frames: AtomicU64,
}

impl Counters {
    fn bump(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

struct Shared {
    stop: AtomicBool,
    counters: Counters,
    /// Inbound connections by id, so that shutdown can unblock their readers.
    inbound: Mutex<BTreeMap<u64, TcpStream>>,
    next_inbound: AtomicU64,
}

struct Peer {
    addr: SocketAddr,
    queue: SyncSender<Vec<u8>>,
}

pub struct Transport {
    local: SocketAddr,
    opts: NetOptions,
    shared: Arc<Shared>,
    inbox: Mutex<Receiver<Message>>,
    peers: Mutex<BTreeMap<NodeId, Peer>>,
    threads: Mutex<Vec<JoinHandle<()>>>,
}

impl Transport {
    /// Listens on `addr` (use port 0 to let the system pick one, see
    /// [`Transport::local_addr`]).
    pub fn bind(addr: SocketAddr, opts: NetOptions) -> io::Result<Self> {
        let listener = TcpListener::bind(addr)?;
        // Neither can fail on a socket that has just been bound.
        listener
            .set_nonblocking(true)
            .expect("a new listener can be made non-blocking");
        let local = listener.local_addr().expect("a bound listener has an address");
        let shared = Arc::new(Shared {
            stop: AtomicBool::new(false),
            counters: Counters::default(),
            inbound: Mutex::new(BTreeMap::new()),
            next_inbound: AtomicU64::new(0),
        });
        let (inbox_tx, inbox) = mpsc::channel();
        let acceptor = {
            let (shared, max) = (shared.clone(), opts.max_frame);
            thread::spawn(move || accept_loop(listener, shared, inbox_tx, max))
        };
        Ok(Transport {
            local,
            opts,
            shared,
            inbox: Mutex::new(inbox),
            peers: Mutex::new(BTreeMap::new()),
            threads: Mutex::new(vec![acceptor]),
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// Where messages for node `id` go. Setting it again moves the peer; the
    /// messages still queued for the old address are lost.
    pub fn set_peer(&self, id: NodeId, addr: SocketAddr) {
        let (queue, rx) = mpsc::sync_channel(self.opts.outbox);
        let (shared, opts) = (self.shared.clone(), self.opts.clone());
        let writer = thread::spawn(move || write_loop(addr, rx, shared, opts));
        self.threads.lock().push(writer);
        // The old peer's queue is dropped here, which ends its writer.
        self.peers.lock().insert(id, Peer { addr, queue });
    }

    /// Forgets node `id`: nothing is sent to it from now on.
    pub fn remove_peer(&self, id: NodeId) {
        self.peers.lock().remove(&id);
    }

    /// The peers and where they are.
    pub fn peers(&self) -> BTreeMap<NodeId, SocketAddr> {
        self.peers.lock().iter().map(|(&id, p)| (id, p.addr)).collect()
    }

    /// Queues `msg` for `msg.to`; `false` if it was dropped right away
    /// (unknown peer, or its queue is full). `true` is no promise of delivery.
    pub fn send(&self, msg: &Message) -> bool {
        let queued = match self.peers.lock().get(&msg.to) {
            Some(p) => p.queue.try_send(encode(msg)),
            None => Err(TrySendError::Disconnected(Vec::new())),
        };
        if queued.is_err() {
            Counters::bump(&self.shared.counters.dropped_unqueued);
        }
        queued.is_ok()
    }

    /// The next message received, waiting up to `timeout`.
    pub fn recv_timeout(&self, timeout: Duration) -> Option<Message> {
        self.inbox.lock().recv_timeout(timeout).ok()
    }

    pub fn stats(&self) -> NetStats {
        let c = &self.shared.counters;
        let get = |a: &AtomicU64| a.load(Ordering::Relaxed);
        NetStats {
            sent: get(&c.sent),
            received: get(&c.received),
            dropped_unqueued: get(&c.dropped_unqueued),
            dropped_unreachable: get(&c.dropped_unreachable),
            write_errors: get(&c.write_errors),
            bad_frames: get(&c.bad_frames),
        }
    }

    /// Stops the threads and closes every connection. Idempotent; also done
    /// when the transport is dropped.
    pub fn shutdown(&self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        self.peers.lock().clear();
        // The acceptor first: after it, no connection is registered anymore.
        let threads: Vec<JoinHandle<()>> = self.threads.lock().drain(..).collect();
        for t in threads {
            let _ = t.join();
        }
        for conn in self.shared.inbound.lock().values() {
            let _ = conn.shutdown(Shutdown::Both);
        }
    }
}

impl Drop for Transport {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Accepts connections until told to stop, a reader thread for each.
fn accept_loop(listener: TcpListener, shared: Arc<Shared>, inbox: mpsc::Sender<Message>, max: usize) {
    while !shared.stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                // Not inheriting the listener's mode is not guaranteed.
                let _ = stream.set_nonblocking(false);
                let _ = stream.set_nodelay(true);
                let id = shared.next_inbound.fetch_add(1, Ordering::Relaxed);
                // A connection that cannot be copied just cannot be closed from here.
                shared.inbound.lock().extend(stream.try_clone().map(|copy| (id, copy)));
                let (shared, inbox) = (shared.clone(), inbox.clone());
                thread::spawn(move || {
                    read_loop(stream, &inbox, max, &shared.counters);
                    shared.inbound.lock().remove(&id);
                });
            }
            // Nothing to accept (or the system is out of descriptors): wait.
            Err(_) => thread::sleep(Duration::from_millis(5)),
        }
    }
}

/// Decodes frames from `stream` into `inbox` until the stream ends, a frame
/// is bad, or the inbox is gone.
fn read_loop(mut stream: TcpStream, inbox: &mpsc::Sender<Message>, max: usize, counters: &Counters) {
    loop {
        let frame = match read_frame(&mut stream, max) {
            Ok(Some(frame)) => frame,
            Ok(None) => return,
            Err(e) => {
                // A peer that closed or reset the connection is not a bad one.
                let damaged = e.kind() == io::ErrorKind::InvalidData;
                counters.bad_frames.fetch_add(u64::from(damaged), Ordering::Relaxed);
                return;
            }
        };
        let Ok(msg) = decode(&frame) else {
            Counters::bump(&counters.bad_frames);
            return;
        };
        if inbox.send(msg).is_err() {
            return;
        }
        Counters::bump(&counters.received);
    }
}

/// Sends the frames queued for one peer over a connection it keeps open.
fn write_loop(addr: SocketAddr, queue: Receiver<Vec<u8>>, shared: Arc<Shared>, opts: NetOptions) {
    let mut conn: Option<TcpStream> = None;
    let mut retry_at = Instant::now();
    let counters = &shared.counters;
    for frame in queue {
        if shared.stop.load(Ordering::SeqCst) {
            return;
        }
        if conn.is_none() && Instant::now() >= retry_at {
            conn = connect(addr, &opts);
            retry_at = Instant::now() + opts.retry_after * u32::from(conn.is_none());
        }
        let Some(stream) = conn.as_mut() else {
            Counters::bump(&counters.dropped_unreachable);
            continue;
        };
        match stream.write_all(&frame) {
            Ok(()) => Counters::bump(&counters.sent),
            Err(_) => {
                Counters::bump(&counters.write_errors);
                conn = None;
            }
        }
    }
}

fn connect(addr: SocketAddr, opts: &NetOptions) -> Option<TcpStream> {
    let stream = TcpStream::connect_timeout(&addr, opts.connect_timeout).ok()?;
    // These fail only on a socket that is already gone, which the first
    // write finds out about.
    let _ = stream.set_nodelay(true);
    let _ = stream.set_write_timeout(Some(opts.write_timeout));
    Some(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log::LogEntry;
    use std::io::Read;

    const LONG: Duration = Duration::from_secs(10);

    fn local() -> SocketAddr {
        "127.0.0.1:0".parse().unwrap()
    }

    fn transport(opts: NetOptions) -> Transport {
        Transport::bind(local(), opts).unwrap()
    }

    fn fast() -> NetOptions {
        NetOptions {
            retry_after: Duration::from_millis(20),
            ..NetOptions::default()
        }
    }

    /// Polls until `cond` holds.
    fn wait_until(what: &str, cond: impl Fn() -> bool) {
        let start = Instant::now();
        while !cond() {
            assert!(start.elapsed() < LONG, "timed out waiting for {what}");
            thread::sleep(Duration::from_millis(2));
        }
    }

    fn vote(from: NodeId, to: NodeId, term: u64) -> Message {
        Message::request_vote(from, to, term, 7, 3)
    }

    #[test]
    fn two_transports_exchange_messages_in_order() {
        let (a, b) = (transport(fast()), transport(fast()));
        a.set_peer(2, b.local_addr());
        b.set_peer(1, a.local_addr());
        assert_eq!(a.peers(), BTreeMap::from([(2, b.local_addr())]));
        for term in 1..=50 {
            assert!(a.send(&vote(1, 2, term)));
        }
        for term in 1..=50 {
            assert_eq!(b.recv_timeout(LONG), Some(vote(1, 2, term)));
        }
        // Both directions, each over its own connection; big messages too.
        let big = Message::append_entries(2, 1, 1, 0, 0, vec![LogEntry::new(1, 1, vec![7; 3 << 20])], 0);
        assert!(b.send(&big));
        assert_eq!(a.recv_timeout(LONG), Some(big));
        assert_eq!(
            a.recv_timeout(Duration::from_millis(30)),
            None,
            "nothing else is coming"
        );
        wait_until("the counters", || a.stats().sent == 50 && b.stats().received == 50);
        assert_eq!((a.stats().received, b.stats().sent), (1, 1));
        assert_eq!(a.stats().write_errors + b.stats().write_errors, 0);
    }

    #[test]
    fn messages_to_unknown_peers_and_full_queues_are_dropped() {
        let t = transport(fast());
        assert!(!t.send(&vote(1, 9, 1)));
        assert_eq!(t.stats().dropped_unqueued, 1);
        // A peer whose writer never runs, with room for one message.
        let (queue, _held) = mpsc::sync_channel(1);
        t.peers.lock().insert(5, Peer { addr: local(), queue });
        assert!(t.send(&vote(1, 5, 1)));
        assert!(!t.send(&vote(1, 5, 2)));
        assert_eq!(t.stats().dropped_unqueued, 2);
        // A forgotten peer is unknown again.
        t.remove_peer(5);
        assert!(!t.send(&vote(1, 5, 3)));
        assert!(t.peers().is_empty());
    }

    #[test]
    fn a_peer_that_is_down_is_retried_after_a_while() {
        let b = transport(fast());
        let addr = b.local_addr();
        drop(b);
        let a = transport(fast());
        a.set_peer(2, addr);
        assert!(a.send(&vote(1, 2, 1)));
        wait_until("the first drop", || a.stats().dropped_unreachable == 1);
        // Within the retry delay, no new attempt: dropped at once.
        assert!(a.send(&vote(1, 2, 2)));
        wait_until("the second drop", || a.stats().dropped_unreachable == 2);
        // The peer comes back on the same address: delivery resumes.
        let b = Transport::bind(addr, fast()).unwrap();
        let start = Instant::now();
        while b.recv_timeout(Duration::from_millis(20)).is_none() {
            assert!(start.elapsed() < LONG, "never reconnected");
            a.send(&vote(1, 2, 3));
        }
        assert!(a.stats().sent >= 1);
    }

    #[test]
    fn a_peer_that_hangs_up_costs_messages_not_the_connection_attempt() {
        // A listener that accepts, then closes at once.
        let l = TcpListener::bind(local()).unwrap();
        let addr = l.local_addr().unwrap();
        let closer = thread::spawn(move || {
            for s in l.incoming().take(4) {
                drop(s);
            }
        });
        let a = transport(fast());
        a.set_peer(2, addr);
        let big = Message::append_entries(1, 2, 1, 0, 0, vec![LogEntry::new(1, 1, vec![1; 1 << 20])], 0);
        let start = Instant::now();
        while a.stats().write_errors == 0 {
            let stats = a.stats();
            assert!(start.elapsed() < LONG, "no write ever failed: {stats:?}");
            a.send(&big);
            thread::sleep(Duration::from_millis(2));
        }
        drop(a);
        // Free the listener's thread: connect until it has seen four.
        while !closer.is_finished() {
            let _ = TcpStream::connect(addr);
        }
        closer.join().unwrap();
    }

    #[test]
    fn bad_frames_close_the_connection_and_good_ones_still_arrive() {
        let t = transport(NetOptions {
            max_frame: 1 << 16,
            ..fast()
        });
        let good = encode(&vote(3, 1, 4));
        let connect = || TcpStream::connect(t.local_addr()).unwrap();
        let closed_by_peer = |mut s: TcpStream| {
            let mut b = [0u8; 1];
            s.set_read_timeout(Some(LONG)).unwrap();
            s.read(&mut b).unwrap_or(0) == 0
        };
        // A flipped bit.
        let mut flipped = good.clone();
        flipped[12] ^= 1;
        let mut s = connect();
        s.write_all(&flipped).unwrap();
        assert!(closed_by_peer(s));
        // A frame beyond the limit.
        let mut s = connect();
        s.write_all(&[0, 0, 0, 0, 1, 0, 1, 0]).unwrap();
        assert!(closed_by_peer(s));
        // An intact frame around bytes that are no message.
        let mut junk = Vec::new();
        flashkv::log::frame(&mut junk, b"not a message");
        let mut s = connect();
        s.write_all(&junk).unwrap();
        assert!(closed_by_peer(s));
        wait_until("three bad frames", || t.stats().bad_frames == 3);
        // A good message after a bad one arrives, on a new connection.
        let mut s = connect();
        s.write_all(&good).unwrap();
        assert_eq!(t.recv_timeout(LONG), Some(vote(3, 1, 4)));
        // A connection that hangs up half way through a frame is no bad frame.
        let mut s = connect();
        s.write_all(&good[..good.len() - 1]).unwrap();
        drop(s);
        let mut s = connect();
        s.write_all(&good).unwrap();
        s.write_all(&good).unwrap();
        assert!(t.recv_timeout(LONG).is_some() && t.recv_timeout(LONG).is_some());
        assert_eq!(t.stats().bad_frames, 3);
    }

    #[test]
    fn finished_connections_are_forgotten() {
        let t = transport(fast());
        let mut s = TcpStream::connect(t.local_addr()).unwrap();
        s.write_all(&encode(&vote(3, 1, 4))).unwrap();
        assert!(t.recv_timeout(LONG).is_some());
        assert_eq!(t.shared.inbound.lock().len(), 1);
        drop(s);
        wait_until("the connection to be forgotten", || t.shared.inbound.lock().is_empty());
    }

    #[test]
    fn the_reader_stops_when_the_inbox_is_gone() {
        let l = TcpListener::bind(local()).unwrap();
        let mut client = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (server, _) = l.accept().unwrap();
        let (tx, rx) = mpsc::channel();
        drop(rx);
        client.write_all(&encode(&vote(3, 1, 4))).unwrap();
        let counters = Counters::default();
        read_loop(server, &tx, MAX_FRAME, &counters);
        assert_eq!(counters.received.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn peers_can_move_and_shutdown_is_final() {
        let (a, b, c) = (transport(fast()), transport(fast()), transport(fast()));
        a.set_peer(2, b.local_addr());
        assert!(a.send(&vote(1, 2, 1)));
        assert!(b.recv_timeout(LONG).is_some());
        // The same id at another address: c receives from now on.
        a.set_peer(2, c.local_addr());
        assert_eq!(a.peers()[&2], c.local_addr());
        assert!(a.send(&vote(1, 2, 2)));
        assert_eq!(c.recv_timeout(LONG), Some(vote(1, 2, 2)));
        assert_eq!(b.recv_timeout(Duration::from_millis(30)), None);
        // Shutdown can be repeated.
        a.shutdown();
        a.shutdown();
        assert!(!a.send(&vote(1, 2, 3)));
        // Nobody listens on a closed transport.
        let addr = a.local_addr();
        wait_until("the listener to close", || TcpStream::connect(addr).is_err());
        // Dropping does the same, with connections open.
        let s = TcpStream::connect(b.local_addr()).unwrap();
        let mut s2 = s.try_clone().unwrap();
        wait_until("the connection", || !b.shared.inbound.lock().is_empty());
        drop(b);
        let mut byte = [0u8; 1];
        s2.set_read_timeout(Some(LONG)).unwrap();
        assert_eq!(s2.read(&mut byte).unwrap_or(0), 0);
    }

    #[test]
    fn options_have_sane_defaults_and_a_bad_address_is_an_error() {
        let o = NetOptions::default();
        assert_eq!(o.max_frame, MAX_FRAME);
        assert!(o.outbox > 0 && o.retry_after < o.write_timeout);
        // An address that is not this machine's.
        let elsewhere: SocketAddr = "192.0.2.1:0".parse().unwrap();
        assert!(Transport::bind(elsewhere, NetOptions::default()).is_err());
        assert_eq!(NetStats::default().sent, 0);
    }
}
