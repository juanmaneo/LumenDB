//! The database: WAL + memtable + leveled SSTables + manifest.
//!
//! Write path (one lock, one append): encode the batch, append it to the WAL
//! (fsync when `sync`), insert into the memtable, publish the sequence number.
//! A full memtable becomes immutable and a fresh WAL is started; the flush to
//! a level-0 table and every compaction run on the background thread.
//!
//! Read path (no lock held while reading): grab `Arc`s of the memtable, the
//! immutable memtable and the current [`Version`], then search them newest to
//! oldest. Flush/compaction publish a new `Version` atomically (eguan/ibs
//! style), so they never block readers and never make them wait for I/O
//! that is not theirs.
//!
//! Crash safety (hardware crash, not just process crash): a write that
//! returned `Ok` with `sync` is in an fsynced WAL whose directory entry is
//! fsynced; tables are fsynced before the manifest edit naming them is
//! fsynced; WALs are deleted only after that edit is durable. Any failure on
//! the write or background path is sticky (`Error::Background`): the engine
//! stops accepting writes instead of risking an inconsistent log.

use crate::batch::WriteBatch;
use crate::env::{Env, LockGuard, OsEnv};
use crate::error::{Error, Result};
use crate::log::{self, LogWriter};
use crate::manifest::{self, file_name, parse_file_name, FileKind, Manifest};
use crate::memtable::Memtable;
use crate::merge::{Entry, GcFilter, Merge, Source, Visible};
use crate::sstable::{Table, TableBuilder, TableOptions};
use crate::txn::Transaction;
use crate::version::{Compaction, FileMeta, LevelOptions, Version, VersionEdit, NUM_LEVELS};
use parking_lot::{Condvar, Mutex};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering::SeqCst};
use std::sync::Arc;
use std::thread::JoinHandle;

#[derive(Clone)]
pub struct DbOptions {
    /// Filesystem layer (swap for [`crate::env::FaultEnv`] in simulations).
    pub env: Arc<dyn Env>,
    pub create_if_missing: bool,
    /// fsync the WAL on every write (survives power loss).
    pub sync: bool,
    /// Memtable size that triggers a flush.
    pub write_buffer_size: usize,
    /// Split compaction outputs at this size.
    pub target_file_size: u64,
    pub table: TableOptions,
    pub levels: LevelOptions,
    /// Start a fresh manifest once the current one exceeds this size.
    pub max_manifest_size: u64,
    /// Flush/compact on a background thread (else inline in the writer).
    pub background: bool,
}

impl Default for DbOptions {
    fn default() -> Self {
        DbOptions {
            env: Arc::new(OsEnv),
            create_if_missing: true,
            sync: true,
            write_buffer_size: 4 << 20,
            target_file_size: 2 << 20,
            table: TableOptions::default(),
            levels: LevelOptions {
                l0_trigger: 4,
                base_bytes: 10 << 20,
                multiplier: 10,
            },
            max_manifest_size: 64 << 20,
            background: true,
        }
    }
}

/// A consistent read view pinned at a sequence number. Compaction keeps
/// every version a live snapshot can see.
pub struct Snapshot {
    seq: u64,
    registry: Arc<Mutex<BTreeMap<u64, usize>>>,
}

impl Snapshot {
    pub fn sequence(&self) -> u64 {
        self.seq
    }
}

impl Drop for Snapshot {
    fn drop(&mut self) {
        let mut r = self.registry.lock();
        let left = r.get_mut(&self.seq).map(|c| {
            *c -= 1;
            *c
        });
        if left == Some(0) {
            r.remove(&self.seq);
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stats {
    pub last_sequence: u64,
    pub memtable_bytes: usize,
    pub files_per_level: Vec<usize>,
    pub bytes_per_level: Vec<u64>,
    pub flushes: u64,
    pub compactions: u64,
    pub trivial_moves: u64,
    pub live_snapshots: usize,
}

struct State {
    mem: Arc<Memtable>,
    /// WALs holding `mem`'s data (oldest first).
    mem_logs: Vec<u64>,
    imm: Option<Arc<Memtable>>,
    imm_logs: Vec<u64>,
    version: Arc<Version>,
}

impl State {
    fn min_log(&self) -> u64 {
        self.imm_logs.iter().chain(&self.mem_logs).copied().min().unwrap_or(0)
    }
}

struct Work {
    manifest: Manifest,
    cursor: [Vec<u8>; NUM_LEVELS],
}

#[derive(Default)]
struct Signal {
    pending: bool,
    shutdown: bool,
}

struct Inner {
    dir: PathBuf,
    env: Arc<dyn Env>,
    opts: DbOptions,
    writer: Mutex<LogWriter>,
    state: Mutex<State>,
    work: Mutex<Work>,
    next_file: AtomicU64,
    last_seq: AtomicU64,
    snapshots: Arc<Mutex<BTreeMap<u64, usize>>>,
    bg_error: Mutex<Option<String>>,
    signal: Mutex<Signal>,
    cv: Condvar,
    flushes: AtomicU64,
    compactions: AtomicU64,
    trivial_moves: AtomicU64,
    _lock: LockGuard,
}

fn open_table(env: &dyn Env, dir: &Path, m: &FileMeta) -> Result<Arc<Table>> {
    let file = env.open(&dir.join(file_name(FileKind::Table, m.number)))?;
    Ok(Arc::new(Table::open(file)?))
}

/// Smallest key strictly greater than every key starting with `prefix`.
pub fn prefix_successor(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut v = prefix.to_vec();
    while let Some(last) = v.pop() {
        if last < 0xff {
            v.push(last + 1);
            return Some(v);
        }
    }
    None
}

impl Inner {
    fn path(&self, kind: FileKind, number: u64) -> PathBuf {
        self.dir.join(file_name(kind, number))
    }

    /// Record a sticky error and hand it back.
    fn fail(&self, e: Error) -> Error {
        self.bg_error.lock().get_or_insert_with(|| e.to_string());
        e
    }

    fn check_bg(&self) -> Result<()> {
        match &*self.bg_error.lock() {
            Some(m) => Err(Error::Background(m.clone())),
            None => Ok(()),
        }
    }

    fn parts(&self) -> (Arc<Memtable>, Option<Arc<Memtable>>, Arc<Version>) {
        let s = self.state.lock();
        (s.mem.clone(), s.imm.clone(), s.version.clone())
    }

    fn smallest_snapshot(&self) -> u64 {
        let last = self.last_seq.load(SeqCst);
        self.snapshots.lock().keys().next().copied().unwrap_or(last)
    }

    /// Newest `(seq, value)` of `key` visible at `snap`.
    fn lookup(&self, key: &[u8], snap: u64) -> Result<Option<(u64, Option<Vec<u8>>)>> {
        let (mem, imm, version) = self.parts();
        if let Some(hit) = mem.get(key, snap) {
            return Ok(Some(hit));
        }
        if let Some(hit) = imm.and_then(|m| m.get(key, snap)) {
            return Ok(Some(hit));
        }
        version.get(key, snap)
    }

    fn write_locked(&self, wal: &mut LogWriter, batch: &WriteBatch) -> Result<()> {
        self.check_bg()?;
        if batch.is_empty() {
            return Ok(());
        }
        let seq = self.last_seq.load(SeqCst) + 1;
        if let Err(e) = wal.add(&batch.encode(seq), self.opts.sync) {
            return Err(self.fail(e));
        }
        let mem = self.state.lock().mem.clone();
        mem.apply(batch, seq);
        self.last_seq.store(seq + batch.len() as u64 - 1, SeqCst);
        if mem.approximate_size() >= self.opts.write_buffer_size {
            // The write itself is durable; a failed rotation only poisons
            // later writes.
            if let Err(e) = self.rotate(wal) {
                self.fail(e);
            }
        }
        Ok(())
    }

    /// Freeze the memtable and switch to a new WAL.
    fn rotate(&self, wal: &mut LogWriter) -> Result<()> {
        if self.state.lock().imm.is_some() {
            self.run_work()?; // write stall: the previous flush is still pending
        }
        let number = self.next_file.fetch_add(1, SeqCst);
        let file = self.env.create(&self.path(FileKind::Log, number))?;
        self.env.sync_dir(&self.dir)?;
        *wal = LogWriter::new(file);
        {
            let mut s = self.state.lock();
            let mem = std::mem::replace(&mut s.mem, Arc::new(Memtable::new()));
            s.imm = Some(mem);
            s.imm_logs = std::mem::replace(&mut s.mem_logs, vec![number]);
        }
        if self.opts.background {
            self.signal.lock().pending = true;
            self.cv.notify_one();
            return Ok(());
        }
        self.run_work()
    }

    /// Flush the immutable memtable, then compact until no level is over
    /// budget. Failures are sticky.
    fn run_work(&self) -> Result<()> {
        self.check_bg()?;
        let mut work = self.work.lock();
        self.do_work(&mut work).map_err(|e| self.fail(e))
    }

    fn do_work(&self, work: &mut Work) -> Result<()> {
        self.flush_imm(work)?;
        loop {
            let version = self.state.lock().version.clone();
            let Some(c) = version.pick(&self.opts.levels, &mut work.cursor) else {
                return Ok(());
            };
            self.compact(work, c)?;
        }
    }

    fn new_table(&self) -> Result<(u64, TableBuilder)> {
        let number = self.next_file.fetch_add(1, SeqCst);
        let file = self.env.create(&self.path(FileKind::Table, number))?;
        Ok((number, TableBuilder::new(file, self.opts.table)))
    }

    fn finish_table(&self, (number, builder): (u64, TableBuilder)) -> Result<FileMeta> {
        let info = builder.finish()?;
        Ok(FileMeta {
            number,
            size: info.size,
            entries: info.entries,
            smallest: info.smallest,
            largest: info.largest,
        })
    }

    /// Write the entries `filter` keeps into new tables, splitting at
    /// `target_file_size` when `split` (never inside one user key).
    fn build_tables(
        &self,
        src: &mut dyn Iterator<Item = Result<Entry>>,
        filter: &mut GcFilter,
        split: bool,
    ) -> Result<Vec<FileMeta>> {
        let mut out = Vec::new();
        let mut cur: Option<(u64, TableBuilder)> = None;
        let mut last_key = Vec::new();
        for r in src {
            let e = r?;
            if !filter.keep(&e) {
                continue;
            }
            let table = match cur.take() {
                Some(t) if split && t.1.estimated_size() >= self.opts.target_file_size && e.key != last_key => {
                    out.push(self.finish_table(t)?);
                    self.new_table()?
                }
                Some(t) => t,
                None => self.new_table()?,
            };
            cur.insert(table).1.add(&e)?;
            last_key = e.key;
        }
        out.extend(cur.map(|t| self.finish_table(t)).transpose()?);
        Ok(out)
    }

    /// Open the new tables, make them and the edit durable, publish.
    fn install(&self, work: &mut Work, mut edit: VersionEdit, flushed_imm: bool) -> Result<()> {
        edit.next_file = Some(self.next_file.load(SeqCst));
        let base = self.state.lock().version.clone();
        let next = base.with_edit(&edit, &|m| open_table(self.env.as_ref(), &self.dir, m))?;
        self.env.sync_dir(&self.dir)?;
        work.manifest.append(&edit)?;
        {
            let mut s = self.state.lock();
            s.version = Arc::new(next);
            if flushed_imm {
                s.imm = None;
            }
        }
        if work.manifest.size() > self.opts.max_manifest_size {
            self.roll_manifest(work)?;
        }
        Ok(())
    }

    /// Replace the manifest by a fresh one holding a single snapshot.
    fn roll_manifest(&self, work: &mut Work) -> Result<()> {
        let number = self.next_file.fetch_add(1, SeqCst);
        let (version, min_log) = {
            let s = self.state.lock();
            (s.version.clone(), s.min_log())
        };
        let snapshot = VersionEdit {
            log_number: Some(min_log),
            next_file: Some(self.next_file.load(SeqCst)),
            last_seq: Some(self.last_seq.load(SeqCst)),
            ..version.snapshot_edit()
        };
        let fresh = Manifest::create(self.env.as_ref(), &self.dir, number, &snapshot)?;
        let old = std::mem::replace(&mut work.manifest, fresh);
        let _ = self.env.remove(&self.path(FileKind::Manifest, old.number()));
        Ok(())
    }

    fn flush_imm(&self, work: &mut Work) -> Result<()> {
        let (imm, imm_logs, log_number) = {
            let s = self.state.lock();
            (s.imm.clone(), s.imm_logs.clone(), s.mem_logs[0])
        };
        let Some(imm) = imm else {
            return Ok(());
        };
        let mut src = imm.entries(&[], None).into_iter().map(Ok);
        let mut filter = GcFilter::new(self.smallest_snapshot(), false);
        let files = self.build_tables(&mut src, &mut filter, false)?;
        let edit = VersionEdit {
            log_number: Some(log_number),
            last_seq: Some(self.last_seq.load(SeqCst)),
            added: files.into_iter().map(|f| (0, f)).collect(),
            ..Default::default()
        };
        self.install(work, edit, true)?;
        for n in imm_logs {
            let _ = self.env.remove(&self.path(FileKind::Log, n));
        }
        self.flushes.fetch_add(1, SeqCst);
        Ok(())
    }

    fn compact(&self, work: &mut Work, c: Compaction) -> Result<()> {
        let out_level = c.level + 1;
        let mut edit = VersionEdit::default();
        edit.deleted.extend(c.inputs.iter().map(|f| (c.level, f.meta.number)));
        edit.deleted.extend(c.next.iter().map(|f| (out_level, f.meta.number)));
        if c.inputs.len() == 1 && c.next.is_empty() {
            edit.added.push((out_level, c.inputs[0].meta.clone()));
            self.trivial_moves.fetch_add(1, SeqCst);
            return self.install(work, edit, false);
        }
        let all: Vec<_> = c.inputs.iter().chain(&c.next).cloned().collect();
        let sources: Vec<Source> = all
            .iter()
            .map(|f| Box::new(f.table.iter(&[], None)) as Source)
            .collect();
        let mut merge = Merge::new(sources);
        let mut filter = GcFilter::new(self.smallest_snapshot(), c.bottom);
        let files = self.build_tables(&mut merge, &mut filter, true)?;
        edit.added.extend(files.into_iter().map(|f| (out_level, f)));
        self.install(work, edit, false)?;
        for f in all {
            let _ = self.env.remove(&self.path(FileKind::Table, f.meta.number));
        }
        self.compactions.fetch_add(1, SeqCst);
        Ok(())
    }
}

fn background_loop(inner: Arc<Inner>) {
    loop {
        {
            let mut s = inner.signal.lock();
            while !s.pending && !s.shutdown {
                inner.cv.wait(&mut s);
            }
            if s.shutdown {
                return;
            }
            s.pending = false;
        }
        let _ = inner.run_work(); // errors are sticky and reported to writers
    }
}

pub struct Db {
    inner: Arc<Inner>,
    bg: Option<JoinHandle<()>>,
}

impl Db {
    /// Open (and recover) the database in `dir`.
    pub fn open(dir: &Path, opts: DbOptions) -> Result<Db> {
        let env = opts.env.clone();
        if opts.create_if_missing {
            env.create_dir_all(dir)?;
        }
        let lock = env.lock(&dir.join("LOCK"))?;
        let state = match manifest::recover(env.as_ref(), dir)? {
            Some((_, state)) => state,
            None if opts.create_if_missing => VersionEdit::default(),
            None => return Err(Error::InvalidInput(format!("no database in {}", dir.display()))),
        };
        let log_number = state.log_number.unwrap_or(0);
        let mut last_seq = state.last_seq.unwrap_or(0);
        let version = Version::default().with_edit(&state, &|m| open_table(env.as_ref(), dir, m))?;
        let names = env.list(dir)?;
        let owned: Vec<(FileKind, u64)> = names.iter().filter_map(|n| parse_file_name(n)).collect();
        let mut next_file = owned
            .iter()
            .map(|f| f.1 + 1)
            .fold(state.next_file.unwrap_or(1), u64::max);
        let mut logs: Vec<u64> = owned
            .iter()
            .filter(|(k, n)| *k == FileKind::Log && *n >= log_number)
            .map(|f| f.1)
            .collect();
        logs.sort_unstable();
        // Replay surviving WALs; a torn tail ends each log's valid prefix,
        // corruption fails the open instead of dropping acknowledged writes.
        let mem = Memtable::new();
        for n in &logs {
            let name = file_name(FileKind::Log, *n);
            let data = env.read_all(&dir.join(&name))?;
            for rec in log::parse_checked(&data, &name)? {
                let (seq, batch) = WriteBatch::decode(rec)?;
                mem.apply(&batch, seq);
                last_seq = last_seq.max((seq + batch.len() as u64).saturating_sub(1));
            }
        }
        let wal_number = next_file;
        let manifest_number = next_file + 1;
        next_file += 2;
        let wal = LogWriter::new(env.create(&dir.join(file_name(FileKind::Log, wal_number)))?);
        logs.push(wal_number);
        let snapshot = VersionEdit {
            log_number: Some(logs[0]),
            next_file: Some(next_file),
            last_seq: Some(last_seq),
            ..version.snapshot_edit()
        };
        let manifest = Manifest::create(env.as_ref(), dir, manifest_number, &snapshot)?;
        // Collect garbage left by crashes and failed operations.
        let live: Vec<u64> = snapshot.added.iter().map(|a| a.1.number).collect();
        for (kind, n) in owned {
            let dead = match kind {
                FileKind::Log => n < logs[0],
                FileKind::Table => !live.contains(&n),
                FileKind::Manifest => n != manifest_number,
                FileKind::Temp => true,
            };
            if dead {
                let _ = env.remove(&dir.join(file_name(kind, n)));
            }
        }
        let inner = Arc::new(Inner {
            dir: dir.to_path_buf(),
            env,
            writer: Mutex::new(wal),
            state: Mutex::new(State {
                mem: Arc::new(mem),
                mem_logs: logs,
                imm: None,
                imm_logs: Vec::new(),
                version: Arc::new(version),
            }),
            work: Mutex::new(Work {
                manifest,
                cursor: Default::default(),
            }),
            next_file: AtomicU64::new(next_file),
            last_seq: AtomicU64::new(last_seq),
            snapshots: Arc::default(),
            bg_error: Mutex::new(None),
            signal: Mutex::new(Signal::default()),
            cv: Condvar::new(),
            flushes: AtomicU64::new(0),
            compactions: AtomicU64::new(0),
            trivial_moves: AtomicU64::new(0),
            _lock: lock,
            opts,
        });
        let bg = inner.opts.background.then(|| {
            let i = inner.clone();
            std::thread::spawn(move || background_loop(i))
        });
        Ok(Db { inner, bg })
    }

    pub fn put(&self, key: &[u8], value: &[u8]) -> Result<()> {
        let mut b = WriteBatch::new();
        b.put(key, value);
        self.write(&b)
    }

    pub fn delete(&self, key: &[u8]) -> Result<()> {
        let mut b = WriteBatch::new();
        b.delete(key);
        self.write(&b)
    }

    /// Apply `batch` atomically.
    pub fn write(&self, batch: &WriteBatch) -> Result<()> {
        let mut wal = self.inner.writer.lock();
        self.inner.write_locked(&mut wal, batch)
    }

    /// Commit `batch` only if none of `reads` changed after `read_seq`
    /// (optimistic concurrency control, FoundationDB-style).
    pub(crate) fn commit(&self, read_seq: u64, reads: &[Vec<u8>], batch: &WriteBatch) -> Result<()> {
        let mut wal = self.inner.writer.lock();
        for k in reads {
            if let Some((seq, _)) = self.inner.lookup(k, u64::MAX)? {
                if seq > read_seq {
                    return Err(Error::Conflict(format!(
                        "key {:?} changed at seq {seq} after read at {read_seq}",
                        String::from_utf8_lossy(k)
                    )));
                }
            }
        }
        self.inner.write_locked(&mut wal, batch)
    }

    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.get_seq(key, self.inner.last_seq.load(SeqCst))
    }

    pub fn get_at(&self, key: &[u8], snapshot: &Snapshot) -> Result<Option<Vec<u8>>> {
        self.get_seq(key, snapshot.seq)
    }

    pub(crate) fn get_seq(&self, key: &[u8], seq: u64) -> Result<Option<Vec<u8>>> {
        Ok(self.inner.lookup(key, seq)?.and_then(|(_, v)| v))
    }

    pub fn snapshot(&self) -> Snapshot {
        let mut r = self.inner.snapshots.lock();
        let seq = self.inner.last_seq.load(SeqCst);
        *r.entry(seq).or_insert(0) += 1;
        Snapshot {
            seq,
            registry: self.inner.snapshots.clone(),
        }
    }

    pub fn begin_transaction(&self) -> Transaction<'_> {
        Transaction::new(self, self.snapshot())
    }

    /// Lazy iterator over live `(key, value)` pairs with `start <= key < end`.
    pub fn iter(&self, start: &[u8], end: Option<&[u8]>) -> Visible {
        self.iter_seq(start, end, self.inner.last_seq.load(SeqCst))
    }

    pub fn iter_at(&self, snapshot: &Snapshot, start: &[u8], end: Option<&[u8]>) -> Visible {
        self.iter_seq(start, end, snapshot.seq)
    }

    fn iter_seq(&self, start: &[u8], end: Option<&[u8]>, seq: u64) -> Visible {
        let (mem, imm, version) = self.inner.parts();
        let mut sources: Vec<Source> = vec![Box::new(mem.entries(start, end).into_iter().map(Ok))];
        if let Some(imm) = imm {
            sources.push(Box::new(imm.entries(start, end).into_iter().map(Ok)));
        }
        sources.extend(version.sources(start, end));
        Visible::new(Merge::new(sources), seq)
    }

    pub fn scan(&self, start: &[u8], end: Option<&[u8]>) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        self.iter(start, end).collect()
    }

    pub fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        self.scan(prefix, prefix_successor(prefix).as_deref())
    }

    /// Flush the memtable and run every pending compaction, synchronously.
    pub fn flush(&self) -> Result<()> {
        {
            let mut wal = self.inner.writer.lock();
            self.inner.check_bg()?;
            if !self.inner.state.lock().mem.is_empty() {
                self.inner.rotate(&mut wal).map_err(|e| self.inner.fail(e))?;
            }
        }
        self.inner.run_work()
    }

    /// fsync the WAL (only useful with `sync == false`).
    pub fn sync(&self) -> Result<()> {
        self.inner.writer.lock().sync()
    }

    pub fn stats(&self) -> Stats {
        let version = self.inner.state.lock().version.clone();
        Stats {
            last_sequence: self.inner.last_seq.load(SeqCst),
            memtable_bytes: self.inner.state.lock().mem.approximate_size(),
            files_per_level: version.levels.iter().map(Vec::len).collect(),
            bytes_per_level: (0..NUM_LEVELS).map(|l| version.level_bytes(l)).collect(),
            flushes: self.inner.flushes.load(SeqCst),
            compactions: self.inner.compactions.load(SeqCst),
            trivial_moves: self.inner.trivial_moves.load(SeqCst),
            live_snapshots: self.inner.snapshots.lock().values().sum(),
        }
    }

    pub fn num_files(&self) -> usize {
        self.inner.state.lock().version.num_files()
    }

    /// The sticky background error, if any.
    pub fn background_error(&self) -> Option<String> {
        self.inner.bg_error.lock().clone()
    }

    /// Sync the WAL, stop the background thread and report any sticky error.
    pub fn close(self) -> Result<()> {
        self.sync()?;
        self.inner.check_bg()
    }
}

impl Drop for Db {
    fn drop(&mut self) {
        self.inner.signal.lock().shutdown = true;
        self.inner.cv.notify_all();
        if let Some(h) = self.bg.take() {
            let _ = h.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::tests::tmpdir;
    use crate::env::FaultEnv;
    use std::time::{Duration, Instant};

    fn small(env: Arc<dyn Env>) -> DbOptions {
        DbOptions {
            env,
            write_buffer_size: 4 << 10,
            target_file_size: 8 << 10,
            table: TableOptions {
                block_size: 512,
                ..TableOptions::default()
            },
            levels: LevelOptions {
                l0_trigger: 2,
                base_bytes: 16 << 10,
                multiplier: 4,
            },
            background: false,
            sync: false,
            ..DbOptions::default()
        }
    }

    fn key(i: u32) -> Vec<u8> {
        format!("key{i:08}").into_bytes()
    }

    fn val(i: u32, round: u32) -> Vec<u8> {
        format!("value-{i}-{round}-{}", "p".repeat((i % 40) as usize)).into_bytes()
    }

    fn fill(db: &Db, n: u32, round: u32) {
        for i in 0..n {
            db.put(&key(i), &val(i, round)).unwrap();
        }
    }

    #[test]
    fn put_get_delete_and_scans() {
        let d = tmpdir("db-basic");
        let db = Db::open(&d, small(Arc::new(OsEnv))).unwrap();
        assert_eq!(db.get(b"missing").unwrap(), None);
        db.put(b"a", b"1").unwrap();
        db.put(b"b", b"2").unwrap();
        db.put(b"ba", b"3").unwrap();
        db.delete(b"a").unwrap();
        db.write(&WriteBatch::new()).unwrap();
        assert_eq!(db.get(b"a").unwrap(), None);
        assert_eq!(db.get(b"b").unwrap(), Some(b"2".to_vec()));
        assert_eq!(db.scan_prefix(b"b").unwrap().len(), 2);
        assert_eq!(db.scan(b"", None).unwrap().len(), 2);
        assert_eq!(db.scan(b"b", Some(b"ba")).unwrap().len(), 1);
        assert_eq!(db.scan_prefix(&[0xff]).unwrap().len(), 0);
        assert_eq!(db.stats().last_sequence, 4);
        db.sync().unwrap();
        db.close().unwrap();
    }

    #[test]
    fn prefix_successor_cases() {
        assert_eq!(prefix_successor(b"ab"), Some(b"ac".to_vec()));
        assert_eq!(prefix_successor(&[1, 0xff]), Some(vec![2]));
        assert_eq!(prefix_successor(&[0xff, 0xff]), None);
        assert_eq!(prefix_successor(b""), None);
    }

    #[test]
    fn flush_compact_and_reopen() {
        let d = tmpdir("db-compact");
        let opts = small(Arc::new(OsEnv));
        let db = Db::open(&d, opts.clone()).unwrap();
        for round in 0..4 {
            fill(&db, 1500, round);
        }
        for i in (0..1500).step_by(3) {
            db.delete(&key(i)).unwrap();
        }
        db.flush().unwrap();
        db.flush().unwrap(); // nothing to do
        let st = db.stats();
        assert!(st.flushes > 5 && st.compactions > 0, "{st:?}");
        assert!(st.files_per_level[1..].iter().sum::<usize>() > 0);
        let check = |db: &Db, extra: usize| {
            for i in 0..1500 {
                let want = (i % 3 != 0).then(|| val(i, 3));
                assert_eq!(db.get(&key(i)).unwrap(), want, "key {i}");
            }
            assert_eq!(db.scan(b"", None).unwrap().len(), 1000 + extra);
        };
        check(&db, 0);
        drop(db);
        let db = Db::open(&d, opts.clone()).unwrap();
        check(&db, 0);
        assert!(db.num_files() > 0);
        db.close().unwrap();
        // not-yet-flushed data comes back from the WAL
        let db = Db::open(&d, opts.clone()).unwrap();
        db.put(b"wal-only", b"x").unwrap();
        db.close().unwrap();
        let db = Db::open(&d, opts).unwrap();
        assert_eq!(db.get(b"wal-only").unwrap(), Some(b"x".to_vec()));
        check(&db, 1);
    }

    #[test]
    fn snapshots_survive_compaction() {
        let d = tmpdir("db-snap");
        let db = Db::open(&d, small(Arc::new(OsEnv))).unwrap();
        fill(&db, 500, 0);
        let s0 = db.snapshot();
        let s0b = db.snapshot();
        assert_eq!(s0.sequence(), 500);
        for round in 1..5 {
            fill(&db, 500, round);
        }
        db.delete(&key(7)).unwrap();
        db.flush().unwrap();
        assert_eq!(db.stats().live_snapshots, 2);
        assert_eq!(db.get_at(&key(7), &s0).unwrap(), Some(val(7, 0)));
        assert_eq!(db.get(&key(7)).unwrap(), None);
        assert_eq!(db.iter_at(&s0, b"", None).count(), 500);
        assert_eq!(db.iter(b"", None).count(), 499);
        drop(s0b);
        drop(s0);
        assert_eq!(db.stats().live_snapshots, 0);
        // compaction may now drop the old versions
        fill(&db, 500, 9);
        db.flush().unwrap();
        assert_eq!(db.get(&key(1)).unwrap(), Some(val(1, 9)));
    }

    #[test]
    fn open_errors_and_lock() {
        let d = tmpdir("db-open");
        let opts = DbOptions {
            create_if_missing: false,
            ..small(Arc::new(OsEnv))
        };
        assert!(Db::open(&d, opts.clone())
            .err()
            .unwrap()
            .to_string()
            .contains("no database"));
        let db = Db::open(&d, small(Arc::new(OsEnv))).unwrap();
        assert!(Db::open(&d, small(Arc::new(OsEnv))).is_err()); // locked
        drop(db);
        Db::open(&d, opts).unwrap();
        // corrupt batch inside a valid WAL record is an error, not data loss
        let db = Db::open(&d, small(Arc::new(OsEnv))).unwrap();
        db.put(b"k", b"v").unwrap();
        drop(db);
        let wal = std::fs::read_dir(&d)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "log"))
            .max()
            .unwrap();
        let acked = std::fs::read(&wal).unwrap();
        let mut bytes = Vec::new();
        log::frame(&mut bytes, &[1, 2, 3]);
        std::fs::write(&wal, bytes).unwrap();
        assert!(Db::open(&d, small(Arc::new(OsEnv))).is_err());
        // a flipped bit in an acknowledged write fails the open instead of
        // silently dropping that write and every later one
        let mut flipped = acked.clone();
        flipped[log::HEADER + 2] ^= 1;
        std::fs::write(&wal, flipped).unwrap();
        let e = Db::open(&d, small(Arc::new(OsEnv))).err().unwrap().to_string();
        assert!(e.contains("damaged record at offset 0"), "{e}");
        // a torn tail after it is still dropped
        let mut torn = acked;
        torn.extend_from_slice(&[9, 9, 9]);
        std::fs::write(&wal, torn).unwrap();
        drop(Db::open(&d, small(Arc::new(OsEnv))).unwrap());
        std::fs::remove_file(&wal).unwrap();
        // stray temp files are collected; a missing table is an error
        std::fs::write(d.join(file_name(FileKind::Temp, 999)), b"").unwrap();
        let db = Db::open(&d, small(Arc::new(OsEnv))).unwrap();
        assert!(!d.join(file_name(FileKind::Temp, 999)).exists());
        db.put(b"k", b"v").unwrap();
        db.flush().unwrap();
        drop(db);
        let sst = std::fs::read_dir(&d)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .find(|p| p.extension().is_some_and(|x| x == "sst"))
            .unwrap();
        std::fs::remove_file(sst).unwrap();
        assert!(Db::open(&d, small(Arc::new(OsEnv))).is_err());
    }

    #[test]
    fn transactions_detect_conflicts() {
        let d = tmpdir("db-txn");
        let db = Db::open(&d, small(Arc::new(OsEnv))).unwrap();
        db.put(b"x", b"0").unwrap();
        let mut t = db.begin_transaction();
        assert_eq!(t.get(b"x").unwrap(), Some(b"0".to_vec()));
        db.put(b"x", b"1").unwrap();
        t.put(b"y", b"1");
        assert!(t.commit().unwrap_err().to_string().contains("conflict"));
        let mut t = db.begin_transaction();
        assert_eq!(t.get(b"nope").unwrap(), None);
        t.put(b"x", b"2");
        t.commit().unwrap();
        assert_eq!(db.get(b"x").unwrap(), Some(b"2".to_vec()));
    }

    #[test]
    fn background_thread_flushes_and_compacts() {
        let d = tmpdir("db-bg");
        let opts = DbOptions {
            background: true,
            ..small(Arc::new(OsEnv))
        };
        let db = Db::open(&d, opts.clone()).unwrap();
        std::thread::sleep(Duration::from_millis(20));
        for round in 0..3 {
            fill(&db, 1000, round);
        }
        db.flush().unwrap();
        assert!(db.stats().compactions > 0);
        for i in 0..1000 {
            assert_eq!(db.get(&key(i)).unwrap(), Some(val(i, 2)));
        }
        db.close().unwrap();
        let db = Db::open(&d, opts).unwrap();
        assert_eq!(db.scan(b"", None).unwrap().len(), 1000);
    }

    #[test]
    fn reads_see_immutable_memtable() {
        let d = tmpdir("db-imm");
        let opts = DbOptions {
            background: true,
            ..small(Arc::new(OsEnv))
        };
        let db = Db::open(&d, opts).unwrap();
        db.put(b"k", b"v").unwrap();
        // freeze the memtable by hand, without letting the flush run
        {
            let _work = db.inner.work.lock();
            let mut wal = db.inner.writer.lock();
            db.inner.rotate(&mut wal).unwrap();
            assert!(db.inner.state.lock().imm.is_some());
            assert_eq!(db.get(b"k").unwrap(), Some(b"v".to_vec()));
            assert_eq!(db.get(b"other").unwrap(), None);
            assert_eq!(db.scan(b"", None).unwrap().len(), 1);
        }
        db.flush().unwrap();
        assert!(db.inner.state.lock().imm.is_none());
    }

    #[test]
    fn write_stall_flushes_pending_memtable() {
        let d = tmpdir("db-stall");
        let db = Db::open(&d, small(Arc::new(OsEnv))).unwrap();
        db.put(b"k", b"v").unwrap();
        // leave an immutable memtable behind as a busy background would
        {
            let mut s = db.inner.state.lock();
            let mem = std::mem::replace(&mut s.mem, Arc::new(Memtable::new()));
            s.imm = Some(mem);
        }
        fill(&db, 200, 0); // overflows the buffer: rotate must flush imm first
        assert!(db.stats().flushes >= 2);
        assert_eq!(db.get(b"k").unwrap(), Some(b"v".to_vec()));
    }

    #[test]
    fn failed_stall_flush_poisons_later_writes() {
        let d = tmpdir("db-stall-fail");
        let env = FaultEnv::new(Arc::new(OsEnv));
        let opts = DbOptions {
            write_buffer_size: 1,
            ..small(Arc::new(env.clone()))
        };
        let db = Db::open(&d, opts).unwrap();
        {
            let mut s = db.inner.state.lock();
            let mem = std::mem::replace(&mut s.mem, Arc::new(Memtable::new()));
            mem.apply(WriteBatch::new().put(b"old", b"x"), 1);
            s.imm = Some(mem);
        }
        env.fail_after(1); // the WAL append succeeds, the stalled flush fails
        db.put(b"k", b"v").unwrap();
        assert!(db.put(b"k2", b"v").is_err());
        assert!(db.inner.run_work().is_err());
    }

    #[test]
    fn manifest_rolls_over() {
        let d = tmpdir("db-manifest-roll");
        let opts = DbOptions {
            max_manifest_size: 1,
            ..small(Arc::new(OsEnv))
        };
        let db = Db::open(&d, opts.clone()).unwrap();
        fill(&db, 1000, 0);
        db.flush().unwrap();
        drop(db);
        let manifests = std::fs::read_dir(&d)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with("MANIFEST"))
            .count();
        assert_eq!(manifests, 1);
        let db = Db::open(&d, opts).unwrap();
        assert_eq!(db.scan(b"", None).unwrap().len(), 1000);
    }

    /// Run a workload against an env that fails at operation `n`; returns
    /// whether the workload completed and the keys acknowledged as written.
    fn faulty_run(d: &Path, env: &FaultEnv, n: u64, max_manifest_size: u64) -> (bool, u32) {
        let opts = DbOptions {
            sync: true,
            max_manifest_size,
            target_file_size: 2 << 10,
            ..small(Arc::new(env.clone()))
        };
        env.fail_after(n);
        let mut acked = 0;
        let ok = (|| -> Result<()> {
            let db = Db::open(d, opts.clone())?;
            for i in 0..100 {
                db.put(&key(i), &val(i, 0))?;
                acked = i + 1;
            }
            drop(db);
            let db = Db::open(d, opts)?; // recovery runs under faults too
            for i in 100..200 {
                db.put(&key(i), &val(i, 0))?;
                acked = i + 1;
            }
            let mut it = db.iter(b"", None);
            it.next().transpose()?;
            db.get(&key(1))?;
            let mut t = db.begin_transaction();
            t.get(&key(5))?;
            t.put(&key(5), &val(5, 0));
            t.commit()?;
            db.flush()?;
            db.close()
        })()
        .is_ok();
        (ok, acked)
    }

    #[test]
    fn fault_injection_then_power_loss_keeps_acknowledged_writes() {
        for max_manifest_size in [u64::MAX, 1] {
            power_loss_sweep(max_manifest_size);
        }
    }

    fn power_loss_sweep(max_manifest_size: u64) {
        let d = tmpdir(&format!("db-faults-{max_manifest_size}"));
        let mut n = 0;
        loop {
            let _ = std::fs::remove_dir_all(&d);
            let env = FaultEnv::new(Arc::new(OsEnv));
            let (ok, acked) = faulty_run(&d, &env, n, max_manifest_size);
            env.heal();
            env.crash().unwrap();
            // after the crash every acknowledged (synced) write is present
            let db = Db::open(&d, small(Arc::new(OsEnv))).unwrap();
            for i in 0..acked {
                assert_eq!(db.get(&key(i)).unwrap(), Some(val(i, 0)), "fault at {n}, key {i}");
            }
            drop(db);
            if ok {
                break;
            }
            n += 1;
        }
        assert!(n > 50, "only {n} fault points");
    }

    #[test]
    fn background_failure_is_sticky() {
        let d = tmpdir("db-bg-fail");
        let env = FaultEnv::new(Arc::new(OsEnv));
        let opts = DbOptions {
            background: true,
            ..small(Arc::new(env.clone()))
        };
        let db = Db::open(&d, opts).unwrap();
        db.put(b"a", b"1").unwrap();
        // writes succeed (WAL), then the flush on the background thread fails
        env.fail_after(3);
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut i = 0;
        while db.background_error().is_none() && Instant::now() < deadline {
            let _ = db.put(&key(i), &val(i, 0));
            i += 1;
        }
        assert!(db.background_error().is_some());
        assert!(db.put(b"b", b"2").unwrap_err().to_string().contains("background"));
        assert!(db.flush().is_err());
        env.heal();
        assert!(db.close().is_err());
    }

    #[test]
    fn flush_reports_rotation_failure() {
        let d = tmpdir("db-flush-fail");
        let env = FaultEnv::new(Arc::new(OsEnv));
        let db = Db::open(&d, small(Arc::new(env.clone()))).unwrap();
        db.put(b"a", b"1").unwrap();
        env.fail_after(0);
        assert!(db.flush().is_err());
        assert!(db.background_error().is_some());
        env.heal();
        assert!(db.sync().is_ok());
    }
}
