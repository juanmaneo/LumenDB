//! Durable Raft state: current term, vote and log.
//!
//! [`FileStorage`] goes through flashkv's [`Env`], so the same deterministic
//! fault-injection / power-loss simulation that covers the KV engine covers
//! Raft persistence too. Layout of the storage directory:
//!
//! - `raft.state`: two identical CRC-framed copies of the record
//!   `term | voted flag | voted | log gen | recovering flag | snapshot index |
//!   snapshot term`, replaced atomically (write tmp, sync, rename, sync dir);
//! - `raft-<gen>.log`: CRC-framed batches of entries, each batch is one record
//!   (all or nothing). Appends go to the tail with a single write + sync. It
//!   holds only the entries after the snapshot;
//! - `raft-snap-<index>.snap`: the snapshot of the state machine that covers
//!   every entry up to `index`, one CRC-framed record, named by index so that
//!   a log rewrite never copies it. It is written and synced before the state
//!   file points at it. Any other `.log` or `.snap` file is garbage from an
//!   interrupted rewrite or compaction and is removed at the next open.
//!
//! A batch that truncates the log (Raft conflict resolution), as well as every
//! open, rewrites the whole log into `raft-<gen+1>.log` and only then points
//! `raft.state` at it, so a crash at any point leaves either the old or the new
//! log in effect, never a mix, and a torn tail is dropped at the next open.
//! Everything is durable *before* memory is updated: an `Ok` means the vote or
//! entries survive a power loss, so a node never votes twice in one term.
//!
//! Storage faults follow TigerBeetle's model and protocol-aware recovery
//! (Alagappan et al., FAST '18). A crash can only tear the last write, which
//! was never acknowledged, so a torn log tail is dropped. Anything else, such
//! as a bit flip in an acknowledged batch, may have lost entries this node
//! acknowledged or voted on. Then the intact prefix is kept and the node is
//! marked [`DurableState::recovering`] (durably, in the same atomic state
//! update that installs the repaired log) until it has copied a leader's log;
//! see [`crate::Node`]. The term and vote cannot be re-learned from peers, so
//! the state file holds two copies: either intact copy is used, and when both
//! are intact they must agree. A state file with no intact copy fails the open.
//! The copies guard against silent corruption, not unreadable sectors: both
//! are read in one call. A snapshot file that fails its checksum loses the
//! applied prefix, which only a leader can restore: the node starts from an
//! empty log, marked recovering, and receives the leader's snapshot or log. A
//! missing snapshot or log file fails the open instead.

use crate::error::{Error, Result};
use crate::log::{decode_voters, encode_voters, EntryKind, Log, LogEntry};
use crate::{Index, NodeId, Term};
use flashkv::codec::Decoder;
use flashkv::env::{Env, LockGuard, OsEnv};
use flashkv::log::{frame, parse, tail, LogWriter, Tail};
use flashkv::varint::{put_len_prefixed, put_uvarint64};
use parking_lot::Mutex;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// A snapshot of the state machine: the effect of every entry up to `index`
/// (whose term was `term`). What `data` holds is up to the application. The
/// cluster configuration at `index` is part of it, as the log entries that
/// set it are gone (empty: the log never had a configuration entry, and the
/// node's own configured voters apply).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub index: Index,
    pub term: Term,
    pub voters: Vec<NodeId>,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DurableState {
    pub term: Term,
    pub voted_for: Option<NodeId>,
    /// Entries after the snapshot, if there is one: `log.base_index()` and
    /// `log.base_term()` are the snapshot's index and term.
    pub log: Log,
    /// The log was damaged and may miss entries this node acknowledged: it
    /// must not vote or campaign until it has caught up with a leader.
    pub recovering: bool,
    pub snapshot: Option<Arc<Snapshot>>,
}

/// Persistence used by [`crate::Node`]. Implementations must make every
/// successful call durable and leave the state unchanged on `Err`.
pub trait Storage: Send + Sync {
    fn load(&self) -> Result<DurableState>;
    fn save_vote(&self, term: Term, voted_for: Option<NodeId>) -> Result<()>;
    /// Raft AppendEntries semantics, see [`Log::append`].
    fn append_entries(&self, entries: &[LogEntry]) -> Result<()>;
    /// Clears [`DurableState::recovering`].
    fn mark_repaired(&self) -> Result<()>;
    /// Makes `snapshot` the base of the log, see [`Log::install_snapshot`]:
    /// the entries after it are kept only if the log agrees with it. Fails
    /// unless it is above the current base.
    fn install_snapshot(&self, snapshot: Arc<Snapshot>) -> Result<()>;
}

/// Volatile storage for tests and simulations.
#[derive(Default)]
pub struct MemoryStorage {
    state: Mutex<DurableState>,
}

impl MemoryStorage {
    pub fn new() -> Arc<Self> {
        Arc::new(MemoryStorage::default())
    }

    /// Storage pre-loaded with `state` (e.g. to simulate a restart).
    pub fn with_state(state: DurableState) -> Arc<Self> {
        Arc::new(MemoryStorage {
            state: Mutex::new(state),
        })
    }
}

impl Storage for MemoryStorage {
    fn load(&self) -> Result<DurableState> {
        Ok(self.state.lock().clone())
    }
    fn save_vote(&self, term: Term, voted_for: Option<NodeId>) -> Result<()> {
        let mut s = self.state.lock();
        s.term = term;
        s.voted_for = voted_for;
        Ok(())
    }
    fn append_entries(&self, entries: &[LogEntry]) -> Result<()> {
        self.state.lock().log.append(entries)
    }
    fn mark_repaired(&self) -> Result<()> {
        self.state.lock().recovering = false;
        Ok(())
    }
    fn install_snapshot(&self, snapshot: Arc<Snapshot>) -> Result<()> {
        let mut s = self.state.lock();
        s.log
            .install_snapshot(snapshot.index, snapshot.term, snapshot.voters.clone())?;
        s.snapshot = Some(snapshot);
        Ok(())
    }
}

const STATE_FILE: &str = "raft.state";
const STATE_TMP: &str = "raft.state.tmp";
/// Payload of one state copy: term, voted flag, voted, gen, recovering flag,
/// snapshot index and term.
const STATE_LEN: usize = 8 + 1 + 8 + 8 + 1 + 8 + 8;
const STATE_COPY: usize = flashkv::log::HEADER + STATE_LEN;

fn log_name(gen: u64) -> String {
    format!("raft-{gen:06}.log")
}

const SNAP_PREFIX: &str = "raft-snap-";

fn snap_name(index: Index) -> String {
    format!("{SNAP_PREFIX}{index:020}.snap")
}

fn encode_snapshot(s: &Snapshot) -> Vec<u8> {
    let mut p = Vec::with_capacity(32 + s.data.len());
    p.extend_from_slice(&s.index.to_le_bytes());
    p.extend_from_slice(&s.term.to_le_bytes());
    put_len_prefixed(&mut p, &encode_voters(&s.voters));
    p.extend_from_slice(&s.data);
    let mut out = Vec::with_capacity(p.len() + flashkv::log::HEADER);
    frame(&mut out, &p);
    out
}

/// The snapshot in `buf`, if it is one intact record and is the snapshot
/// `(index, term)` the state file expects.
fn decode_snapshot(buf: &[u8], index: Index, term: Term) -> Option<Snapshot> {
    let (records, end) = parse(buf);
    let [p] = records.as_slice() else {
        return None;
    };
    if end != buf.len() {
        return None;
    }
    let mut d = Decoder::new(p);
    let (i, t) = (d.u64(), d.u64());
    let voters = d.lp();
    let rest = d.remaining();
    let data = d.bytes(rest);
    let voters = match voters.is_empty() {
        true => Some(Vec::new()),
        false => decode_voters(voters),
    };
    if ((i, t) != (index, term)) | d.finish("snapshot").is_err() {
        return None;
    }
    Some(Snapshot {
        index: i,
        term: t,
        voters: voters?,
        data: data.to_vec(),
    })
}

/// Contents of `raft.state`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct StateRecord {
    term: Term,
    voted_for: Option<NodeId>,
    gen: u64,
    recovering: bool,
    /// Index and term of the snapshot (0, 0: none).
    snap_index: Index,
    snap_term: Term,
}

impl StateRecord {
    fn of(state: &DurableState, gen: u64) -> Self {
        StateRecord {
            term: state.term,
            voted_for: state.voted_for,
            gen,
            recovering: state.recovering,
            snap_index: state.log.base_index(),
            snap_term: state.log.base_term(),
        }
    }
}

fn encode_state(r: &StateRecord) -> Vec<u8> {
    let mut p = Vec::with_capacity(STATE_LEN);
    p.extend_from_slice(&r.term.to_le_bytes());
    p.push(r.voted_for.is_some() as u8);
    p.extend_from_slice(&r.voted_for.unwrap_or(0).to_le_bytes());
    p.extend_from_slice(&r.gen.to_le_bytes());
    p.push(r.recovering as u8);
    p.extend_from_slice(&r.snap_index.to_le_bytes());
    p.extend_from_slice(&r.snap_term.to_le_bytes());
    let mut out = Vec::with_capacity(2 * STATE_COPY);
    frame(&mut out, &p);
    frame(&mut out, &p);
    out
}

/// One copy, or `None` if it is damaged.
fn decode_copy(copy: &[u8]) -> Option<StateRecord> {
    match parse(copy).0.as_slice() {
        [p] if p.len() == STATE_LEN => {
            let mut d = Decoder::new(p);
            let term = d.u64();
            let has_vote = d.u8() != 0;
            let voted = d.u64();
            let gen = d.u64();
            let recovering = d.u8() != 0;
            let (snap_index, snap_term) = (d.u64(), d.u64());
            Some(StateRecord {
                term,
                voted_for: has_vote.then_some(voted),
                gen,
                recovering,
                snap_index,
                snap_term,
            })
        }
        _ => None,
    }
}

fn decode_state(buf: &[u8]) -> Result<StateRecord> {
    let corrupt = |why: &str| Err(Error::Storage(format!("corrupt {STATE_FILE}: {why}")));
    if buf.len() != 2 * STATE_COPY {
        return corrupt("wrong size");
    }
    let (a, b) = buf.split_at(STATE_COPY);
    match (decode_copy(a), decode_copy(b)) {
        (Some(x), Some(y)) if x != y => corrupt("copies disagree"),
        (Some(x), _) | (None, Some(x)) => Ok(x),
        (None, None) => corrupt("both copies damaged"),
    }
}

fn encode_batch(entries: &[LogEntry]) -> Vec<u8> {
    let mut p = Vec::new();
    put_uvarint64(&mut p, entries.len() as u64);
    for e in entries {
        p.extend_from_slice(&e.index.to_le_bytes());
        p.extend_from_slice(&e.term.to_le_bytes());
        p.push(e.kind as u8);
        put_len_prefixed(&mut p, &e.data);
    }
    p
}

fn decode_batch(p: &[u8]) -> Result<Vec<LogEntry>> {
    let mut d = Decoder::new(p);
    let n = d.varint();
    // Every entry takes at least 18 bytes: a corrupt count cannot spin.
    let n = n.min(d.remaining() as u64);
    let mut out = Vec::new();
    for _ in 0..n {
        let index = d.u64();
        let term = d.u64();
        let kind = match d.u8() {
            0 => EntryKind::Normal,
            1 => EntryKind::Config,
            _ => return Err(Error::Storage("unknown entry kind".into())),
        };
        let data = d.lp().to_vec();
        out.push(LogEntry {
            index,
            term,
            kind,
            data,
        });
    }
    d.finish("raft log batch")?;
    Ok(out)
}

/// `Ok(None)` when `path` does not exist.
fn read_opt(env: &dyn Env, path: &Path) -> io::Result<Option<Vec<u8>>> {
    match env.read_all(path) {
        Ok(b) => Ok(Some(b)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

struct Inner {
    state: DurableState,
    gen: u64,
    writer: LogWriter,
    /// A tail append failed: the file may end with a partial batch, so the
    /// next append must rewrite the log instead of appending after it.
    dirty: bool,
}

/// Crash-safe file-backed [`Storage`] (see module docs for the format).
pub struct FileStorage {
    env: Arc<dyn Env>,
    dir: PathBuf,
    inner: Mutex<Inner>,
    _lock: LockGuard,
}

impl FileStorage {
    pub fn open(dir: &Path) -> Result<Arc<Self>> {
        Self::open_with_env(Arc::new(OsEnv), dir)
    }

    pub fn open_with_env(env: Arc<dyn Env>, dir: &Path) -> Result<Arc<Self>> {
        env.create_dir_all(dir)?;
        let lock = env.lock(&dir.join("LOCK"))?;
        let rec = match read_opt(&*env, &dir.join(STATE_FILE))? {
            Some(buf) => decode_state(&buf)?,
            None => StateRecord::default(),
        };
        let gen = rec.gen;
        let log_buf = match (read_opt(&*env, &dir.join(log_name(gen)))?, gen) {
            (Some(buf), _) => buf,
            (None, 0) => Vec::new(),
            (None, g) => return Err(Error::Storage(format!("missing {}", log_name(g)))),
        };
        let (records, end) = parse(&log_buf);
        let mut damaged = tail(&log_buf, end) == Tail::Corrupt;
        let snapshot = match (rec.snap_index, read_opt(&*env, &dir.join(snap_name(rec.snap_index)))?) {
            (0, _) => None,
            (i, None) => return Err(Error::Storage(format!("missing {}", snap_name(i)))),
            (i, Some(buf)) => decode_snapshot(&buf, i, rec.snap_term).map(Arc::new),
        };
        // A snapshot that fails its checksum takes the log after it along:
        // those entries cannot follow anything. Start empty, as recovering.
        damaged |= (rec.snap_index != 0) & snapshot.is_none();
        let mut log = snapshot
            .as_ref()
            .map_or_else(Log::new, |s| Log::with_base(s.index, s.term, s.voters.clone()));
        for record in records {
            // An intact checksum around a batch that does not decode or does
            // not follow the log is damage too: keep the prefix before it.
            if decode_batch(record).and_then(|b| log.append(&b)).is_err() {
                damaged = true;
                break;
            }
        }
        let state = DurableState {
            term: rec.term,
            voted_for: rec.voted_for,
            log,
            recovering: rec.recovering | damaged,
            snapshot,
        };
        // Compact into a fresh generation: drops any torn tail, and a damaged
        // log is replaced together with setting the recovering flag.
        let writer = write_log(&*env, dir, &state, gen + 1)?;
        // Every other generation and snapshot is garbage, including ones a
        // crash brought back because their removal was never made durable.
        let current = (log_name(gen + 1), state.snapshot.as_ref().map(|s| snap_name(s.index)));
        for name in env.list(dir)? {
            let old_log = name.starts_with("raft-") & name.ends_with(".log") & (name != current.0);
            let old_snap =
                name.starts_with(SNAP_PREFIX) & name.ends_with(".snap") & (Some(&name) != current.1.as_ref());
            if old_log | old_snap {
                let _ = env.remove(&dir.join(name));
            }
        }
        Ok(Arc::new(FileStorage {
            env,
            dir: dir.to_path_buf(),
            inner: Mutex::new(Inner {
                state,
                gen: gen + 1,
                writer,
                dirty: false,
            }),
            _lock: lock,
        }))
    }

    /// Current log generation (bumped by every full rewrite).
    pub fn generation(&self) -> u64 {
        self.inner.lock().gen
    }
}

/// Writes and syncs the snapshot file. Its directory entry becomes durable
/// with the `sync_dir` of the `write_log` that commits it.
fn write_snapshot(env: &dyn Env, dir: &Path, snapshot: &Snapshot) -> Result<()> {
    let mut f = env.create(&dir.join(snap_name(snapshot.index)))?;
    f.append(&encode_snapshot(snapshot))?;
    f.sync()?;
    Ok(())
}

fn write_state(env: &dyn Env, dir: &Path, rec: &StateRecord) -> Result<()> {
    let tmp = dir.join(STATE_TMP);
    let mut f = env.create(&tmp)?;
    f.append(&encode_state(rec))?;
    f.sync()?;
    env.rename(&tmp, &dir.join(STATE_FILE))?;
    env.sync_dir(dir)?;
    Ok(())
}

/// Writes `state.log` as generation `gen`, makes it durable, then commits it
/// by pointing the state file at it. Returns the writer for later appends.
fn write_log(env: &dyn Env, dir: &Path, state: &DurableState, gen: u64) -> Result<LogWriter> {
    let mut buf = Vec::new();
    frame(&mut buf, &encode_batch(state.log.entries()));
    let mut f = env.create(&dir.join(log_name(gen)))?;
    f.append(&buf)?;
    f.sync()?;
    env.sync_dir(dir)?;
    write_state(env, dir, &StateRecord::of(state, gen))?;
    Ok(LogWriter::new(f))
}

impl Storage for FileStorage {
    fn load(&self) -> Result<DurableState> {
        Ok(self.inner.lock().state.clone())
    }

    fn save_vote(&self, term: Term, voted_for: Option<NodeId>) -> Result<()> {
        let mut g = self.inner.lock();
        let rec = StateRecord {
            term,
            voted_for,
            ..StateRecord::of(&g.state, g.gen)
        };
        write_state(&*self.env, &self.dir, &rec)?;
        g.state.term = term;
        g.state.voted_for = voted_for;
        Ok(())
    }

    fn mark_repaired(&self) -> Result<()> {
        let mut g = self.inner.lock();
        let rec = StateRecord {
            recovering: false,
            ..StateRecord::of(&g.state, g.gen)
        };
        write_state(&*self.env, &self.dir, &rec)?;
        g.state.recovering = false;
        Ok(())
    }

    fn append_entries(&self, entries: &[LogEntry]) -> Result<()> {
        let mut g = self.inner.lock();
        g.state.log.check_append(entries)?;
        let last = g.state.log.last_index();
        match g.state.log.first_conflict(entries) {
            None => Ok(()),
            Some(k) if k > last && !g.dirty => {
                let skip = (k - entries[0].index) as usize;
                let r = g.writer.add(&encode_batch(&entries[skip..]), true);
                g.dirty = r.is_err();
                r?;
                g.state.log.append(entries)
            }
            Some(_) => {
                let mut next = g.state.clone();
                next.log.append(entries).expect("validated by check_append");
                let gen = g.gen + 1;
                let writer = write_log(&*self.env, &self.dir, &next, gen)?;
                let _ = self.env.remove(&self.dir.join(log_name(g.gen)));
                *g = Inner {
                    state: next,
                    gen,
                    writer,
                    dirty: false,
                };
                Ok(())
            }
        }
    }

    fn install_snapshot(&self, snapshot: Arc<Snapshot>) -> Result<()> {
        let mut g = self.inner.lock();
        let mut next = g.state.clone();
        next.log
            .install_snapshot(snapshot.index, snapshot.term, snapshot.voters.clone())?;
        next.snapshot = Some(snapshot.clone());
        // The snapshot is durable before the state file points at it, and the
        // state file switches log and snapshot together. A crash in between
        // leaves the old pair in effect and the new snapshot as garbage.
        write_snapshot(&*self.env, &self.dir, &snapshot)?;
        let gen = g.gen + 1;
        let writer = write_log(&*self.env, &self.dir, &next, gen)?;
        let _ = self.env.remove(&self.dir.join(log_name(g.gen)));
        if let Some(old) = &g.state.snapshot {
            let _ = self.env.remove(&self.dir.join(snap_name(old.index)));
        }
        *g = Inner {
            state: next,
            gen,
            writer,
            dirty: false,
        };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flashkv::env::FaultEnv;
    use std::fs;

    fn e(index: u64, term: u64) -> LogEntry {
        LogEntry::new(index, term, format!("e{index}t{term}").into_bytes())
    }

    fn c(index: u64, term: u64, voters: &[NodeId]) -> LogEntry {
        LogEntry::config(index, term, voters)
    }

    fn tmpdir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("raft-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn memory_storage_roundtrip() {
        let s = MemoryStorage::new();
        s.save_vote(5, Some(3)).unwrap();
        s.append_entries(&[e(1, 5), e(2, 5)]).unwrap();
        assert!(s.append_entries(&[e(9, 5)]).is_err());
        let st = s.load().unwrap();
        assert_eq!((st.term, st.voted_for, st.log.last_index()), (5, Some(3), 2));
        let r = MemoryStorage::with_state(DurableState {
            recovering: true,
            ..st.clone()
        });
        assert!(r.load().unwrap().recovering);
        r.mark_repaired().unwrap();
        assert_eq!(r.load().unwrap(), st);
        // Snapshots replace the log prefix, and must move the base forward.
        let snapshot = Arc::new(Snapshot {
            index: 1,
            term: 5,
            voters: vec![1, 2],
            data: b"x".to_vec(),
        });
        r.install_snapshot(snapshot.clone()).unwrap();
        let after = r.load().unwrap();
        assert_eq!((after.log.base_index(), after.log.last_index()), (1, 2));
        assert_eq!(after.log.voters(), &[1, 2]);
        assert_eq!(after.snapshot, Some(snapshot.clone()));
        assert!(r.install_snapshot(snapshot).is_err());
        assert_eq!(r.load().unwrap(), after);
    }

    #[test]
    fn file_storage_persists_and_compacts() {
        let dir = tmpdir("persist");
        {
            let s = FileStorage::open(&dir).unwrap();
            assert_eq!(s.load().unwrap(), DurableState::default());
            assert_eq!(s.generation(), 1);
            s.save_vote(7, Some(2)).unwrap();
            s.append_entries(&[e(1, 7), e(2, 7)]).unwrap();
            s.append_entries(&[e(2, 7), e(3, 7)]).unwrap(); // overlap: only 3 is written
            s.append_entries(&[e(1, 7)]).unwrap(); // already present: no-op
            s.append_entries(&[]).unwrap();
            assert!(s.append_entries(&[e(5, 7)]).is_err());
            assert!(FileStorage::open(&dir).is_err(), "directory is locked");
        }
        // Torn tail after the last batch is ignored.
        let log = dir.join(log_name(1));
        let mut bytes = fs::read(&log).unwrap();
        bytes.extend_from_slice(&[0xde, 0xad, 0xbe]);
        fs::write(&log, bytes).unwrap();
        let s = FileStorage::open(&dir).unwrap();
        let st = s.load().unwrap();
        assert_eq!((st.term, st.voted_for, st.recovering), (7, Some(2), false));
        assert_eq!(st.log.entries(), &[e(1, 7), e(2, 7), e(3, 7)]);
        assert_eq!(s.generation(), 2);
        assert!(!log.exists(), "old generation removed");
        drop(s);
        // Leftover generations (e.g. resurrected by a crash) are removed too;
        // other files are left alone.
        fs::write(dir.join(log_name(1)), b"stale").unwrap();
        fs::write(dir.join("raft-notes.txt"), b"keep").unwrap();
        fs::write(dir.join("other.log"), b"keep").unwrap();
        let s = FileStorage::open(&dir).unwrap();
        assert_eq!(s.generation(), 3);
        let mut names: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        assert_eq!(
            names,
            ["LOCK", "other.log", "raft-000003.log", "raft-notes.txt", "raft.state"]
        );
        // Conflict rewrites the log into a new generation.
        s.append_entries(&[e(2, 8)]).unwrap();
        assert_eq!(s.generation(), 4);
        drop(s);
        let s = FileStorage::open(&dir).unwrap();
        assert_eq!(s.load().unwrap().log.entries(), &[e(1, 7), e(2, 8)]);
        s.save_vote(9, None).unwrap();
        drop(s);
        let st = FileStorage::open(&dir).unwrap().load().unwrap();
        assert_eq!((st.term, st.voted_for, st.log.last_index()), (9, None, 2));
        fs::remove_dir_all(&dir).unwrap();
    }

    /// Writes `batches` (one log record each) as the current log of `dir`,
    /// whose storage must be closed; returns the log path.
    fn write_current_log(dir: &Path, batches: &[&[u8]]) -> PathBuf {
        let gen = decode_state(&fs::read(dir.join(STATE_FILE)).unwrap()).unwrap().gen;
        let mut buf = Vec::new();
        for b in batches {
            frame(&mut buf, b);
        }
        let path = dir.join(log_name(gen));
        fs::write(&path, &buf).unwrap();
        path
    }

    #[test]
    fn corruption_is_reported_or_marks_recovering() {
        let dir = tmpdir("corrupt");
        FileStorage::open(&dir).unwrap().append_entries(&[e(1, 1)]).unwrap();
        // gen 1 is current; a missing log for gen > 0 is an error.
        fs::rename(dir.join(log_name(1)), dir.join("moved")).unwrap();
        assert!(FileStorage::open(&dir).is_err());
        fs::rename(dir.join("moved"), dir.join(log_name(1))).unwrap();
        // Valid CRC around a malformed batch: the prefix before it is kept.
        let one = encode_batch(&[e(1, 1)]);
        write_current_log(&dir, &[&one, &[1, 0, 0]]);
        let st = FileStorage::open(&dir).unwrap().load().unwrap();
        assert!(st.recovering);
        assert_eq!(st.log.entries(), &[e(1, 1)]);
        // Non-contiguous entries.
        write_current_log(&dir, &[&encode_batch(&[e(2, 1)])]);
        let st = FileStorage::open(&dir).unwrap().load().unwrap();
        assert!(st.recovering && st.log.is_empty());
        // State file without an intact copy.
        fs::write(dir.join(STATE_FILE), b"garbage").unwrap();
        assert!(FileStorage::open(&dir).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    /// The bug this guards against: a bit flip in the log used to drop every
    /// entry from the damaged batch on, silently, so the node could vote for
    /// a candidate missing entries it had acknowledged.
    #[test]
    fn bit_flip_marks_recovering_durably() {
        let dir = tmpdir("bitflip");
        {
            let s = FileStorage::open(&dir).unwrap();
            s.save_vote(3, Some(2)).unwrap();
            s.append_entries(&[e(1, 3)]).unwrap();
            s.append_entries(&[e(2, 3)]).unwrap();
            s.append_entries(&[e(3, 3)]).unwrap();
        }
        let log = dir.join(log_name(1));
        let mut bytes = fs::read(&log).unwrap();
        let second_batch = bytes.len() - 2 * (flashkv::log::HEADER + encode_batch(&[e(3, 3)]).len()) + 12;
        bytes[second_batch] ^= 0x04;
        fs::write(&log, &bytes).unwrap();
        let s = FileStorage::open(&dir).unwrap();
        let st = s.load().unwrap();
        assert_eq!((st.term, st.voted_for, st.recovering), (3, Some(2), true));
        assert_eq!(st.log.entries(), &[e(1, 3)]);
        // Votes, appends and reopening keep the flag: the repaired log on disk
        // is clean now, so only the state file remembers.
        s.save_vote(4, None).unwrap();
        s.append_entries(&[e(2, 4)]).unwrap();
        drop(s);
        let fault = FaultEnv::new(Arc::new(OsEnv));
        let s = FileStorage::open_with_env(Arc::new(fault.clone()), &dir).unwrap();
        let st = s.load().unwrap();
        assert_eq!((st.term, st.voted_for, st.recovering), (4, None, true));
        assert_eq!(st.log.entries(), &[e(1, 3), e(2, 4)]);
        fault.fail_after(0);
        assert!(s.mark_repaired().is_err());
        assert!(s.load().unwrap().recovering, "unchanged on error");
        fault.heal();
        s.mark_repaired().unwrap();
        assert!(!s.load().unwrap().recovering);
        drop(s);
        let st = FileStorage::open(&dir).unwrap().load().unwrap();
        assert_eq!((st.term, st.recovering, st.log.last_index()), (4, false, 2));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn one_damaged_state_copy_is_tolerated() {
        let dir = tmpdir("statecopy");
        FileStorage::open(&dir).unwrap().save_vote(6, Some(1)).unwrap();
        let path = dir.join(STATE_FILE);
        // Each open writes a new generation, so take the current file each time.
        for i in 0..2 * STATE_COPY {
            let mut bad = fs::read(&path).unwrap();
            bad[i] ^= 0x01;
            fs::write(&path, &bad).unwrap();
            let st = FileStorage::open(&dir).unwrap().load().unwrap();
            assert_eq!((st.term, st.voted_for, st.recovering), (6, Some(1), false), "byte {i}");
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn state_codec() {
        let r = StateRecord {
            term: 4,
            voted_for: Some(u64::MAX),
            gen: 3,
            recovering: true,
            snap_index: 9,
            snap_term: 4,
        };
        let s = encode_state(&r);
        assert_eq!(s.len(), 2 * STATE_COPY);
        assert_eq!(decode_state(&s).unwrap(), r);
        let plain = StateRecord {
            term: 1,
            ..StateRecord::default()
        };
        assert_eq!(decode_state(&encode_state(&plain)).unwrap(), plain);
        let err = |b: &[u8]| decode_state(b).unwrap_err().to_string();
        let mut trailing = s.clone();
        trailing.push(0);
        assert!(err(&trailing).contains("wrong size"));
        // Either copy alone is enough; both damaged is an error.
        let (mut first, mut second, mut both) = (s.clone(), s.clone(), s.clone());
        first[10] ^= 1;
        second[STATE_COPY + 10] ^= 1;
        both[10] ^= 1;
        both[STATE_COPY + 10] ^= 1;
        assert_eq!(decode_state(&first).unwrap(), r);
        assert_eq!(decode_state(&second).unwrap(), r);
        assert!(err(&both).contains("both copies damaged"));
        // Two intact copies that differ: refuse to guess.
        let mut mixed = encode_state(&r);
        mixed.truncate(STATE_COPY);
        mixed.extend_from_slice(&encode_state(&plain)[STATE_COPY..]);
        assert!(err(&mixed).contains("copies disagree"));
        // An intact record of the wrong length is a damaged copy.
        let mut short = Vec::new();
        frame(&mut short, &[0; STATE_LEN - 1]);
        short.push(0);
        short.extend_from_slice(&s[STATE_COPY..]);
        assert_eq!(decode_state(&short).unwrap(), r);
        assert_eq!(
            decode_batch(&encode_batch(&[e(1, 1), e(2, 3)])).unwrap(),
            vec![e(1, 1), e(2, 3)]
        );
        assert!(decode_batch(&[0xff]).is_err());
    }

    #[test]
    fn failed_tail_append_forces_rewrite() {
        let dir = tmpdir("dirty");
        let fault = FaultEnv::new(Arc::new(OsEnv));
        let s = FileStorage::open_with_env(Arc::new(fault.clone()), &dir).unwrap();
        s.append_entries(&[e(1, 1)]).unwrap();
        fault.fail_after(1); // the append lands, its sync fails
        assert!(s.append_entries(&[e(2, 1)]).is_err());
        fault.heal();
        let gen = s.generation();
        s.append_entries(&[e(2, 1)]).unwrap();
        assert_eq!(s.generation(), gen + 1);
        s.append_entries(&[e(3, 1)]).unwrap();
        assert_eq!(s.generation(), gen + 1, "back on the fast path");
        drop(s);
        let st = FileStorage::open(&dir).unwrap().load().unwrap();
        assert_eq!(st.log.entries(), &[e(1, 1), e(2, 1), e(3, 1)]);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn read_opt_propagates_other_errors() {
        let dir = tmpdir("readopt");
        fs::create_dir_all(&dir).unwrap();
        assert!(read_opt(&OsEnv, &dir).is_err(), "reading a directory fails");
        assert_eq!(read_opt(&OsEnv, &dir.join("none")).unwrap(), None);
        fs::remove_dir_all(&dir).unwrap();
    }

    /// Runs a workload with the n-th I/O failing, then a power loss; whatever
    /// was acknowledged must be recovered exactly.
    #[test]
    fn fault_injection_then_power_loss_keeps_acknowledged_state() {
        for n in 0.. {
            let dir = tmpdir("faults");
            let fault = FaultEnv::new(Arc::new(OsEnv));
            let env: Arc<dyn Env> = Arc::new(fault.clone());
            fault.fail_after(n);
            let mut acked = DurableState::default();
            let script = |acked: &mut DurableState| -> Result<()> {
                let s = FileStorage::open_with_env(env.clone(), &dir)?;
                s.save_vote(1, Some(1))?;
                (acked.term, acked.voted_for) = (1, Some(1));
                s.append_entries(&[e(1, 1), e(2, 1)])?;
                acked.log.append(&[e(1, 1), e(2, 1)]).unwrap();
                s.append_entries(&[e(3, 1)])?;
                acked.log.append(&[e(3, 1)]).unwrap();
                s.append_entries(&[e(2, 2), c(3, 2, &[1, 2, 3])])?;
                acked.log.append(&[e(2, 2), c(3, 2, &[1, 2, 3])]).unwrap();
                // Compaction: the snapshot and the shortened log switch together.
                let snap = Arc::new(Snapshot {
                    index: 2,
                    term: 2,
                    voters: vec![1, 2],
                    data: b"state at 2".to_vec(),
                });
                s.install_snapshot(snap.clone())?;
                acked.log.install_snapshot(2, 2, vec![1, 2]).unwrap();
                acked.snapshot = Some(snap);
                s.append_entries(&[c(4, 2, &[1, 2, 3, 4])])?;
                acked.log.append(&[c(4, 2, &[1, 2, 3, 4])]).unwrap();
                // A snapshot ahead of the log replaces it, and replaces the
                // previous snapshot file.
                let snap = Arc::new(Snapshot {
                    index: 6,
                    term: 3,
                    voters: vec![1, 2, 3, 4],
                    data: b"state at 6".to_vec(),
                });
                s.install_snapshot(snap.clone())?;
                acked.log.install_snapshot(6, 3, vec![1, 2, 3, 4]).unwrap();
                acked.snapshot = Some(snap);
                s.save_vote(2, None)?;
                (acked.term, acked.voted_for) = (2, None);
                drop(s);
                let s = FileStorage::open_with_env(env.clone(), &dir)?;
                assert_eq!(s.load().unwrap(), *acked);
                Ok(())
            };
            let done = script(&mut acked).is_ok();
            fault.heal();
            fault.crash().unwrap();
            let recovered = FileStorage::open(&dir).unwrap().load().unwrap();
            assert!(!recovered.recovering, "a crash is not corruption, fault at op {n}");
            assert_eq!(recovered.term, acked.term, "fault at op {n}");
            assert_eq!(recovered.voted_for, acked.voted_for, "fault at op {n}");
            assert_eq!(recovered.log, acked.log, "fault at op {n}");
            assert_eq!(recovered.snapshot, acked.snapshot, "fault at op {n}");
            // Whatever the interruption, no file of an older pair is left.
            let mut names = fs::read_dir(&dir).unwrap().count();
            names -= usize::from(dir.join("LOCK").exists());
            assert!(names <= 4, "{names} files, fault at op {n}");
            fs::remove_dir_all(&dir).unwrap();
            if done {
                break;
            }
        }
    }

    fn snap(index: u64, term: u64, data: &[u8]) -> Arc<Snapshot> {
        Arc::new(Snapshot {
            index,
            term,
            voters: vec![1, 2, 3],
            data: data.to_vec(),
        })
    }

    fn dir_names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn snapshots_replace_the_log_prefix_and_survive_reopening() {
        let dir = tmpdir("snapshot");
        let s = FileStorage::open(&dir).unwrap();
        s.append_entries(&[e(1, 1), e(2, 1), e(3, 2), e(4, 2), e(5, 2)])
            .unwrap();
        // A snapshot the log agrees with keeps the entries after it.
        s.install_snapshot(snap(3, 2, b"three")).unwrap();
        let st = s.load().unwrap();
        assert_eq!((st.log.base_index(), st.log.base_term()), (3, 2));
        assert_eq!(st.log.entries(), &[e(4, 2), e(5, 2)]);
        assert_eq!(st.snapshot.as_deref(), Some(&*snap(3, 2, b"three")));
        // Appends continue after it, and so does a conflict rewrite.
        s.append_entries(&[e(6, 2)]).unwrap();
        s.append_entries(&[e(6, 3)]).unwrap();
        assert_eq!(s.load().unwrap().log.entries(), &[e(4, 2), e(5, 2), e(6, 3)]);
        // It must move the base forward, and nothing changes otherwise.
        let before = s.load().unwrap();
        for index in [1, 3] {
            assert!(s.install_snapshot(snap(index, 2, b"old")).is_err());
            assert_eq!(s.load().unwrap(), before);
        }
        assert_eq!(dir_names(&dir).iter().filter(|n| n.contains("snap")).count(), 1);
        drop(s);
        let s = FileStorage::open(&dir).unwrap();
        let st = s.load().unwrap();
        assert_eq!(st, before);
        assert!(!st.recovering);
        // One that disagrees with the log (or is beyond it) replaces it.
        s.install_snapshot(snap(5, 9, b"five")).unwrap();
        let st = s.load().unwrap();
        assert_eq!(
            (st.log.base_index(), st.log.last_index(), st.log.last_term()),
            (5, 5, 9)
        );
        let mut want = vec![
            "LOCK".to_string(),
            snap_name(5),
            log_name(s.generation()),
            STATE_FILE.to_string(),
        ];
        want.sort();
        assert_eq!(dir_names(&dir), want);
        drop(s);
        let st = FileStorage::open(&dir).unwrap().load().unwrap();
        assert_eq!(st.snapshot.as_deref(), Some(&*snap(5, 9, b"five")));
        assert_eq!(st.log.base_index(), 5);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn damaged_snapshots_reset_the_log_and_mark_the_node_recovering() {
        let dir = tmpdir("snapshot-damage");
        let build = || {
            let _ = fs::remove_dir_all(&dir);
            let s = FileStorage::open(&dir).unwrap();
            s.save_vote(4, Some(2)).unwrap();
            s.append_entries(&[e(1, 3), e(2, 3), e(3, 4)]).unwrap();
            s.install_snapshot(snap(2, 3, b"state")).unwrap();
            s.append_entries(&[e(4, 4)]).unwrap();
        };
        let path = dir.join(snap_name(2));
        let reopened = || FileStorage::open(&dir).unwrap().load().unwrap();
        // Bit rot in the snapshot: its data is gone, the log after it cannot
        // follow anything, term and vote stay.
        build();
        let mut bytes = fs::read(&path).unwrap();
        let n = bytes.len();
        bytes[n - 2] ^= 0x10;
        fs::write(&path, &bytes).unwrap();
        let st = reopened();
        assert!(st.recovering && st.snapshot.is_none() && st.log.is_empty());
        assert_eq!((st.log.base_index(), st.term, st.voted_for), (0, 4, Some(2)));
        assert!(!path.exists(), "the damaged file is garbage now");
        assert!(reopened().recovering, "and it stays recovering");
        // The same for trailing bytes, a snapshot of another index or term, and
        // one that is too short.
        for bad in [
            [encode_snapshot(&snap(2, 3, b"state")), vec![0]].concat(),
            encode_snapshot(&snap(2, 4, b"state")),
            encode_snapshot(&snap(1, 3, b"state")),
            {
                let mut b = Vec::new();
                frame(&mut b, &[0; 15]);
                b
            },
        ] {
            build();
            fs::write(&path, &bad).unwrap();
            let st = reopened();
            assert!(st.recovering && st.snapshot.is_none(), "{bad:?}");
        }
        // A missing snapshot file fails the open instead.
        build();
        fs::remove_file(&path).unwrap();
        let err = FileStorage::open(&dir).err().unwrap();
        assert_eq!(err, Error::Storage(format!("missing {}", snap_name(2))));
        // A snapshot file the state never pointed at (a crash before the
        // switch) is removed, and one it points at is not.
        build();
        fs::write(dir.join(snap_name(7)), b"orphan").unwrap();
        let st = reopened();
        assert!(!st.recovering);
        assert_eq!(st.snapshot.as_deref(), Some(&*snap(2, 3, b"state")));
        assert!(!dir.join(snap_name(7)).exists() && path.exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn entry_kinds_and_snapshot_voters_are_validated_on_decoding() {
        let batch = vec![e(1, 1), c(2, 1, &[1, 2]), e(3, 1)];
        assert_eq!(decode_batch(&encode_batch(&batch)).unwrap(), batch);
        let mut p = Vec::new();
        put_uvarint64(&mut p, 1);
        p.extend_from_slice(&1u64.to_le_bytes());
        p.extend_from_slice(&1u64.to_le_bytes());
        p.push(7);
        put_len_prefixed(&mut p, b"x");
        assert_eq!(decode_batch(&p), Err(Error::Storage("unknown entry kind".into())));
        // A snapshot record whose voter list is not one is damaged; an empty
        // list means none was known.
        let record = |voters: &[u8]| {
            let mut p = Vec::new();
            p.extend_from_slice(&2u64.to_le_bytes());
            p.extend_from_slice(&3u64.to_le_bytes());
            put_len_prefixed(&mut p, voters);
            p.extend_from_slice(b"data");
            let mut out = Vec::new();
            frame(&mut out, &p);
            out
        };
        let decoded = |voters: &[u8]| decode_snapshot(&record(voters), 2, 3);
        assert_eq!(decoded(&encode_voters(&[1, 2])).unwrap().voters, vec![1, 2]);
        assert_eq!(decoded(&[]).unwrap().voters, Vec::<NodeId>::new());
        assert_eq!(decoded(&encode_voters(&[1, 2])).unwrap().data, b"data");
        assert_eq!(decoded(&encode_voters(&[2, 1])), None, "not ascending");
        assert_eq!(decoded(&[1, 2, 3]), None, "not a list of ids");
        // The snapshot the state file names is the one that is read.
        assert_eq!(decode_snapshot(&record(&[]), 2, 4), None);
        assert_eq!(decode_snapshot(&record(&[]), 5, 3), None);
    }
}
