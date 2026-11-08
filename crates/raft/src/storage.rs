//! Durable Raft state: current term, vote and log.
//!
//! [`FileStorage`] goes through flashkv's [`Env`], so the same deterministic
//! fault-injection / power-loss simulation that covers the KV engine covers
//! Raft persistence too. Layout of the storage directory:
//!
//! - `raft.state`: two identical CRC-framed copies of the record
//!   `term | voted flag | voted | log gen | recovering flag`, replaced
//!   atomically (write tmp, sync, rename, sync dir);
//! - `raft-<gen>.log`: CRC-framed batches of entries, each batch is one record
//!   (all or nothing). Appends go to the tail with a single write + sync.
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
//! are read in one call.

use crate::error::{Error, Result};
use crate::log::{Log, LogEntry};
use crate::{NodeId, Term};
use flashkv::codec::Decoder;
use flashkv::env::{Env, LockGuard, OsEnv};
use flashkv::log::{frame, parse, tail, LogWriter, Tail};
use flashkv::varint::{put_len_prefixed, put_uvarint64};
use parking_lot::Mutex;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DurableState {
    pub term: Term,
    pub voted_for: Option<NodeId>,
    pub log: Log,
    /// The log was damaged and may miss entries this node acknowledged: it
    /// must not vote or campaign until it has caught up with a leader.
    pub recovering: bool,
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
}

const STATE_FILE: &str = "raft.state";
const STATE_TMP: &str = "raft.state.tmp";
/// Payload of one state copy: term, voted flag, voted, gen, recovering flag.
const STATE_LEN: usize = 8 + 1 + 8 + 8 + 1;
const STATE_COPY: usize = flashkv::log::HEADER + STATE_LEN;

fn log_name(gen: u64) -> String {
    format!("raft-{gen:06}.log")
}

/// Contents of `raft.state`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct StateRecord {
    term: Term,
    voted_for: Option<NodeId>,
    gen: u64,
    recovering: bool,
}

impl StateRecord {
    fn of(state: &DurableState, gen: u64) -> Self {
        StateRecord {
            term: state.term,
            voted_for: state.voted_for,
            gen,
            recovering: state.recovering,
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
            Some(StateRecord {
                term,
                voted_for: has_vote.then_some(voted),
                gen,
                recovering,
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
        put_len_prefixed(&mut p, &e.data);
    }
    p
}

fn decode_batch(p: &[u8]) -> Result<Vec<LogEntry>> {
    let mut d = Decoder::new(p);
    let n = d.varint();
    // Every entry takes at least 17 bytes: a corrupt count cannot spin.
    let n = n.min(d.remaining() as u64);
    let mut out = Vec::new();
    for _ in 0..n {
        let index = d.u64();
        let term = d.u64();
        let data = d.lp().to_vec();
        out.push(LogEntry { index, term, data });
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
        let mut log = Log::new();
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
        };
        // Compact into a fresh generation: drops any torn tail, and a damaged
        // log is replaced together with setting the recovering flag.
        let writer = write_log(&*env, dir, &state, gen + 1)?;
        // Every other generation is garbage, including ones a crash brought
        // back because their removal was never made durable.
        for name in env.list(dir)? {
            if name.starts_with("raft-") & name.ends_with(".log") & (name != log_name(gen + 1)) {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use flashkv::env::FaultEnv;
    use std::fs;

    fn e(index: u64, term: u64) -> LogEntry {
        LogEntry {
            index,
            term,
            data: format!("e{index}t{term}").into_bytes(),
        }
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
                s.append_entries(&[e(2, 2), e(3, 2)])?;
                acked.log.append(&[e(2, 2), e(3, 2)]).unwrap();
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
            fs::remove_dir_all(&dir).unwrap();
            if done {
                break;
            }
        }
    }
}
