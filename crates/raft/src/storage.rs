//! Durable Raft state: current term, vote and log.
//!
//! [`FileStorage`] goes through flashkv's [`Env`], so the same deterministic
//! fault-injection / power-loss simulation that covers the KV engine covers
//! Raft persistence too. Layout of the storage directory:
//!
//! - `raft.state`: one CRC-framed record `term | voted flag | voted | log gen`,
//!   replaced atomically (write tmp, sync, rename, sync dir);
//! - `raft-<gen>.log`: CRC-framed batches of entries, each batch is one record
//!   (all or nothing). Appends go to the tail with a single write + sync.
//!
//! A batch that truncates the log (Raft conflict resolution), as well as every
//! open, rewrites the whole log into `raft-<gen+1>.log` and only then points
//! `raft.state` at it, so a crash at any point leaves either the old or the new
//! log in effect, never a mix, and a torn tail is dropped at the next open.
//! Everything is durable *before* memory is updated: an `Ok` means the vote or
//! entries survive a power loss, so a node never votes twice in one term.

use crate::error::{Error, Result};
use crate::log::{Log, LogEntry};
use crate::{NodeId, Term};
use flashkv::codec::Decoder;
use flashkv::env::{Env, LockGuard, OsEnv};
use flashkv::log::{frame, parse, LogWriter};
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
}

/// Persistence used by [`crate::Node`]. Implementations must make every
/// successful call durable and leave the state unchanged on `Err`.
pub trait Storage: Send + Sync {
    fn load(&self) -> Result<DurableState>;
    fn save_vote(&self, term: Term, voted_for: Option<NodeId>) -> Result<()>;
    /// Raft AppendEntries semantics, see [`Log::append`].
    fn append_entries(&self, entries: &[LogEntry]) -> Result<()>;
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
}

const STATE_FILE: &str = "raft.state";
const STATE_TMP: &str = "raft.state.tmp";

fn log_name(gen: u64) -> String {
    format!("raft-{gen:06}.log")
}

fn encode_state(term: Term, voted_for: Option<NodeId>, gen: u64) -> Vec<u8> {
    let mut p = Vec::with_capacity(25);
    p.extend_from_slice(&term.to_le_bytes());
    p.push(voted_for.is_some() as u8);
    p.extend_from_slice(&voted_for.unwrap_or(0).to_le_bytes());
    p.extend_from_slice(&gen.to_le_bytes());
    let mut out = Vec::with_capacity(p.len() + flashkv::log::HEADER);
    frame(&mut out, &p);
    out
}

fn decode_state(buf: &[u8]) -> Result<(Term, Option<NodeId>, u64)> {
    let (records, end) = parse(buf);
    match (records.as_slice(), end == buf.len()) {
        ([p], true) => {
            let mut d = Decoder::new(p);
            let term = d.u64();
            let has_vote = d.u8() != 0;
            let voted = d.u64();
            let gen = d.u64();
            d.finish("raft state")?;
            Ok((term, has_vote.then_some(voted), gen))
        }
        _ => Err(Error::Storage(format!("corrupt {STATE_FILE}"))),
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
        let (term, voted_for, gen) = match read_opt(&*env, &dir.join(STATE_FILE))? {
            Some(buf) => decode_state(&buf)?,
            None => (0, None, 0),
        };
        let log_buf = match (read_opt(&*env, &dir.join(log_name(gen)))?, gen) {
            (Some(buf), _) => buf,
            (None, 0) => Vec::new(),
            (None, g) => return Err(Error::Storage(format!("missing {}", log_name(g)))),
        };
        let mut log = Log::new();
        for record in parse(&log_buf).0 {
            log.append(&decode_batch(record)?)?;
        }
        let state = DurableState { term, voted_for, log };
        // Compact into a fresh generation: drops any torn tail.
        let writer = write_log(&*env, dir, &state, gen + 1)?;
        let _ = env.remove(&dir.join(log_name(gen)));
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

fn write_state(env: &dyn Env, dir: &Path, term: Term, voted_for: Option<NodeId>, gen: u64) -> Result<()> {
    let tmp = dir.join(STATE_TMP);
    let mut f = env.create(&tmp)?;
    f.append(&encode_state(term, voted_for, gen))?;
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
    write_state(env, dir, state.term, state.voted_for, gen)?;
    Ok(LogWriter::new(f))
}

impl Storage for FileStorage {
    fn load(&self) -> Result<DurableState> {
        Ok(self.inner.lock().state.clone())
    }

    fn save_vote(&self, term: Term, voted_for: Option<NodeId>) -> Result<()> {
        let mut g = self.inner.lock();
        write_state(&*self.env, &self.dir, term, voted_for, g.gen)?;
        g.state.term = term;
        g.state.voted_for = voted_for;
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
        let r = MemoryStorage::with_state(st.clone());
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
        assert_eq!((st.term, st.voted_for), (7, Some(2)));
        assert_eq!(st.log.entries(), &[e(1, 7), e(2, 7), e(3, 7)]);
        assert_eq!(s.generation(), 2);
        assert!(!log.exists(), "old generation removed");
        // Conflict rewrites the log into a new generation.
        s.append_entries(&[e(2, 8)]).unwrap();
        assert_eq!(s.generation(), 3);
        drop(s);
        let s = FileStorage::open(&dir).unwrap();
        assert_eq!(s.load().unwrap().log.entries(), &[e(1, 7), e(2, 8)]);
        s.save_vote(9, None).unwrap();
        drop(s);
        let st = FileStorage::open(&dir).unwrap().load().unwrap();
        assert_eq!((st.term, st.voted_for, st.log.last_index()), (9, None, 2));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn corruption_is_reported() {
        let dir = tmpdir("corrupt");
        FileStorage::open(&dir).unwrap().append_entries(&[e(1, 1)]).unwrap();
        // gen 1 is current; a missing log for gen > 0 is an error.
        fs::rename(dir.join(log_name(1)), dir.join("moved")).unwrap();
        assert!(FileStorage::open(&dir).is_err());
        fs::rename(dir.join("moved"), dir.join(log_name(1))).unwrap();
        // Valid CRC around a malformed batch.
        let mut bad = Vec::new();
        frame(&mut bad, &[1, 0, 0]);
        fs::write(dir.join(log_name(1)), &bad).unwrap();
        assert!(FileStorage::open(&dir).is_err());
        // Non-contiguous entries.
        let mut gap = Vec::new();
        frame(&mut gap, &encode_batch(&[e(2, 1)]));
        fs::write(dir.join(log_name(1)), &gap).unwrap();
        assert!(FileStorage::open(&dir).is_err());
        // Corrupt state file.
        fs::write(dir.join(STATE_FILE), b"garbage").unwrap();
        assert!(FileStorage::open(&dir).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn state_codec() {
        let s = encode_state(4, Some(u64::MAX), 3);
        assert_eq!(decode_state(&s).unwrap(), (4, Some(u64::MAX), 3));
        assert_eq!(decode_state(&encode_state(1, None, 0)).unwrap(), (1, None, 0));
        let mut trailing = s.clone();
        trailing.push(0);
        assert!(decode_state(&trailing).is_err());
        let mut short = Vec::new();
        frame(&mut short, &[1, 2, 3]);
        assert!(decode_state(&short).is_err());
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
