//! In-memory [`Env`] for deterministic simulation, in the style of
//! TigerBeetle's VOPR. There is no disk I/O, so thousands of seeded runs take
//! seconds, and every fault is chosen by the caller, typically from a seeded
//! PRNG.
//!
//! A file is an inode: its bytes and how many of them are synced. A directory
//! entry maps a path to an inode, and there are two views of the entries:
//! `live`, what the running process sees, and `durable`, what survives a
//! power loss. `sync` on a file makes its bytes durable, `sync_dir` makes the
//! directory's creates, renames and removes durable. Recreating an existing
//! file truncates it in place, durably: the strict reading of `O_TRUNC`.
//! Directories are durable as soon as they are created.
//!
//! Faults:
//! - [`MemEnv::crash`]: power loss. The live view reverts to the durable one,
//!   and every file keeps its synced bytes plus a prefix of the unsynced ones
//!   whose length the caller picks (a torn write).
//! - [`MemEnv::flip_bit`]: silent corruption (bit rot, a misdirected write).
//! - [`MemEnv::fail_after`]: the n-th operation and every later one fail.
//!
//! Handles of a crashed process must be dropped before it restarts: locks are
//! released by their guards.

use crate::env::{Env, LockGuard, RandomAccessFile, WritableFile};
use parking_lot::Mutex;
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Default)]
struct FileData {
    bytes: Vec<u8>,
    synced: usize,
}

type Inode = Arc<Mutex<FileData>>;

struct Fs {
    live: BTreeMap<PathBuf, Inode>,
    durable: BTreeMap<PathBuf, Inode>,
    dirs: BTreeSet<PathBuf>,
    locks: BTreeSet<PathBuf>,
    ops: u64,
    fail_at: u64,
    injected: u64,
}

impl Fs {
    fn tick(&mut self) -> io::Result<()> {
        let n = self.ops;
        self.ops += 1;
        if n >= self.fail_at {
            self.injected += 1;
            return Err(io::Error::other(format!("injected fault at op {n}")));
        }
        Ok(())
    }

    fn file(&self, path: &Path) -> io::Result<&Inode> {
        self.live.get(path).ok_or_else(|| not_found(path))
    }

    fn dir(&self, dir: &Path) -> io::Result<()> {
        match self.dirs.contains(dir) {
            true => Ok(()),
            false => Err(not_found(dir)),
        }
    }
}

fn not_found(path: &Path) -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, format!("{}: not found", path.display()))
}

fn parent(path: &Path) -> &Path {
    path.parent().unwrap_or(Path::new(""))
}

/// The in-memory file system; clones share it.
#[derive(Clone)]
pub struct MemEnv(Arc<Mutex<Fs>>);

impl Default for MemEnv {
    fn default() -> Self {
        MemEnv(Arc::new(Mutex::new(Fs {
            live: BTreeMap::new(),
            durable: BTreeMap::new(),
            dirs: BTreeSet::new(),
            locks: BTreeSet::new(),
            ops: 0,
            fail_at: u64::MAX,
            injected: 0,
        })))
    }
}

impl MemEnv {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of operations performed so far.
    pub fn ops(&self) -> u64 {
        self.0.lock().ops
    }

    /// Let `n` more operations succeed, then fail every following one.
    pub fn fail_after(&self, n: u64) {
        let mut fs = self.0.lock();
        fs.fail_at = fs.ops.saturating_add(n);
    }

    /// Operations failed by [`MemEnv::fail_after`] since the last heal.
    pub fn injected(&self) -> u64 {
        self.0.lock().injected
    }

    /// Stop injecting faults and reset the injected count.
    pub fn heal(&self) {
        let mut fs = self.0.lock();
        fs.fail_at = u64::MAX;
        fs.injected = 0;
    }

    /// Power loss. Entries that `sync_dir` never made durable are undone, and
    /// each file keeps its synced bytes plus `torn(unsynced)` more (clamped).
    pub fn crash(&self, torn: &mut dyn FnMut(usize) -> usize) {
        let mut fs = self.0.lock();
        fs.live = fs.durable.clone();
        for inode in fs.durable.values() {
            let mut f = inode.lock();
            let unsynced = f.bytes.len() - f.synced;
            let keep = f.synced + torn(unsynced).min(unsynced);
            f.bytes.truncate(keep);
            f.synced = keep;
        }
    }

    /// Flips bit `bit` of `path` (bit 0 is the low bit of byte 0), in place:
    /// both the live and the durable content change.
    pub fn flip_bit(&self, path: &Path, bit: u64) -> io::Result<()> {
        let fs = self.0.lock();
        let mut f = fs.file(path)?.lock();
        let byte = (bit / 8) as usize;
        match f.bytes.get_mut(byte) {
            Some(b) => {
                *b ^= 1 << (bit % 8);
                Ok(())
            }
            None => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{}: bit {bit} is past the end", path.display()),
            )),
        }
    }
}

struct MemWritable {
    fs: Arc<Mutex<Fs>>,
    inode: Inode,
}

impl WritableFile for MemWritable {
    fn append(&mut self, data: &[u8]) -> io::Result<()> {
        self.fs.lock().tick()?;
        self.inode.lock().bytes.extend_from_slice(data);
        Ok(())
    }
    fn sync(&mut self) -> io::Result<()> {
        self.fs.lock().tick()?;
        let mut f = self.inode.lock();
        f.synced = f.bytes.len();
        Ok(())
    }
}

struct MemRandom {
    fs: Arc<Mutex<Fs>>,
    bytes: Vec<u8>,
}

impl RandomAccessFile for MemRandom {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        self.fs.lock().tick()?;
        let start = offset.min(self.bytes.len() as u64) as usize;
        match self.bytes[start..].get(..buf.len()) {
            Some(src) => {
                buf.copy_from_slice(src);
                Ok(())
            }
            None => Err(io::Error::new(io::ErrorKind::UnexpectedEof, "read past the end")),
        }
    }
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }
}

struct MemLock {
    fs: Arc<Mutex<Fs>>,
    path: PathBuf,
}

impl Drop for MemLock {
    fn drop(&mut self) {
        self.fs.lock().locks.remove(&self.path);
    }
}

impl Env for MemEnv {
    fn create(&self, path: &Path) -> io::Result<Box<dyn WritableFile>> {
        let mut fs = self.0.lock();
        fs.tick()?;
        fs.dir(parent(path))?;
        let inode = match fs.live.get(path) {
            Some(inode) => {
                *inode.lock() = FileData::default();
                inode.clone()
            }
            None => {
                let inode = Inode::default();
                fs.live.insert(path.to_path_buf(), inode.clone());
                inode
            }
        };
        Ok(Box::new(MemWritable {
            fs: self.0.clone(),
            inode,
        }))
    }
    fn open(&self, path: &Path) -> io::Result<Arc<dyn RandomAccessFile>> {
        let mut fs = self.0.lock();
        fs.tick()?;
        let bytes = fs.file(path)?.lock().bytes.clone();
        Ok(Arc::new(MemRandom {
            fs: self.0.clone(),
            bytes,
        }))
    }
    fn read_all(&self, path: &Path) -> io::Result<Vec<u8>> {
        let mut fs = self.0.lock();
        fs.tick()?;
        let bytes = fs.file(path)?.lock().bytes.clone();
        Ok(bytes)
    }
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        let mut fs = self.0.lock();
        fs.tick()?;
        fs.dir(parent(to))?;
        let inode = fs.live.remove(from).ok_or_else(|| not_found(from))?;
        fs.live.insert(to.to_path_buf(), inode);
        Ok(())
    }
    fn remove(&self, path: &Path) -> io::Result<()> {
        let mut fs = self.0.lock();
        fs.tick()?;
        fs.live.remove(path).map(drop).ok_or_else(|| not_found(path))
    }
    fn list(&self, dir: &Path) -> io::Result<Vec<String>> {
        let mut fs = self.0.lock();
        fs.tick()?;
        fs.dir(dir)?;
        Ok(fs
            .live
            .keys()
            .filter(|p| parent(p) == dir)
            .map(|p| p.file_name().unwrap_or_default().to_string_lossy().into_owned())
            .collect())
    }
    fn create_dir_all(&self, dir: &Path) -> io::Result<()> {
        let mut fs = self.0.lock();
        fs.tick()?;
        fs.dirs.extend(dir.ancestors().map(Path::to_path_buf));
        Ok(())
    }
    fn sync_dir(&self, dir: &Path) -> io::Result<()> {
        let mut fs = self.0.lock();
        fs.tick()?;
        fs.dir(dir)?;
        let fs = &mut *fs;
        fs.durable.retain(|p, _| parent(p) != dir);
        for (p, inode) in fs.live.iter().filter(|(p, _)| parent(p) == dir) {
            fs.durable.insert(p.clone(), inode.clone());
        }
        Ok(())
    }
    fn lock(&self, path: &Path) -> io::Result<LockGuard> {
        let mut fs = self.0.lock();
        fs.tick()?;
        if !fs.locks.insert(path.to_path_buf()) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                format!("{} is locked", path.display()),
            ));
        }
        Ok(Box::new(MemLock {
            fs: self.0.clone(),
            path: path.to_path_buf(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{Db, DbOptions};

    fn write(env: &MemEnv, path: &Path, data: &[u8], sync: bool) -> Box<dyn WritableFile> {
        let mut w = env.create(path).unwrap();
        w.append(data).unwrap();
        if sync {
            w.sync().unwrap();
        }
        w
    }

    #[test]
    fn files_directories_and_locks() {
        let env = MemEnv::new();
        let d = Path::new("/db");
        assert_eq!(env.create(&d.join("a")).err().unwrap().kind(), io::ErrorKind::NotFound);
        env.create_dir_all(&d.join("sub")).unwrap();
        write(&env, &d.join("a"), b"hello", false);
        assert_eq!(env.read_all(&d.join("a")).unwrap(), b"hello");
        let r = env.open(&d.join("a")).unwrap();
        assert_eq!(r.len(), 5);
        let mut buf = [0u8; 3];
        r.read_at(&mut buf, 1).unwrap();
        assert_eq!(&buf, b"ell");
        assert_eq!(r.read_at(&mut buf, 4).unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
        assert!(r.read_at(&mut buf, 99).is_err());
        // Recreating truncates in place.
        write(&env, &d.join("a"), b"x", false);
        assert_eq!(env.read_all(&d.join("a")).unwrap(), b"x");
        env.rename(&d.join("a"), &d.join("b")).unwrap();
        write(&env, &d.join("sub/c"), b"", false);
        assert_eq!(env.list(d).unwrap(), vec!["b".to_string()]);
        assert_eq!(env.list(&d.join("sub")).unwrap(), vec!["c".to_string()]);
        env.remove(&d.join("b")).unwrap();
        for missing in [d.join("a"), d.join("b")] {
            assert_eq!(env.read_all(&missing).unwrap_err().kind(), io::ErrorKind::NotFound);
            assert!(env.open(&missing).is_err());
            assert!(env.remove(&missing).is_err());
            assert!(env.rename(&missing, &d.join("z")).is_err());
        }
        assert!(env.rename(&d.join("sub/c"), Path::new("/nowhere/c")).is_err());
        assert!(env.list(Path::new("/nowhere")).is_err());
        assert!(env.sync_dir(Path::new("/nowhere")).is_err());
        // A bare file name lives in the empty directory.
        env.create_dir_all(Path::new("rel")).unwrap();
        write(&env, Path::new("top"), b"t", false);
        assert_eq!(env.list(Path::new("")).unwrap(), vec!["top".to_string()]);
        let g = env.lock(&d.join("LOCK")).unwrap();
        assert!(env.lock(&d.join("LOCK")).unwrap_err().to_string().contains("locked"));
        drop(g);
        env.lock(&d.join("LOCK")).unwrap();
    }

    #[test]
    fn crash_keeps_synced_bytes_and_durable_entries() {
        let env = MemEnv::new();
        let d = Path::new("/db");
        env.create_dir_all(d).unwrap();
        let mut w = write(&env, &d.join("durable"), b"synced", true);
        w.append(b"-torn").unwrap();
        write(&env, &d.join("gone"), b"x", true);
        write(&env, &d.join("old"), b"old", true);
        env.sync_dir(d).unwrap();
        // After the dir sync: an unsynced create, a rename over a durable
        // file and a removal, none of them durable.
        write(&env, &d.join("late"), b"late", true);
        write(&env, &d.join("new.tmp"), b"new", true);
        env.rename(&d.join("new.tmp"), &d.join("old")).unwrap();
        env.remove(&d.join("gone")).unwrap();
        let mut asked = Vec::new();
        env.crash(&mut |unsynced| {
            asked.push(unsynced);
            3
        });
        assert_eq!(asked, vec![5, 0, 0]);
        assert_eq!(env.read_all(&d.join("durable")).unwrap(), b"synced-to");
        assert_eq!(env.read_all(&d.join("old")).unwrap(), b"old");
        assert_eq!(env.read_all(&d.join("gone")).unwrap(), b"x");
        assert!(env.read_all(&d.join("late")).is_err());
        // Torn bytes that survived are durable now; asking for more than
        // there is gets clamped.
        env.crash(&mut |_| 100);
        assert_eq!(env.read_all(&d.join("durable")).unwrap(), b"synced-to");
        // A durable rename survives.
        env.rename(&d.join("old"), &d.join("moved")).unwrap();
        env.sync_dir(d).unwrap();
        env.crash(&mut |_| 0);
        assert_eq!(env.read_all(&d.join("moved")).unwrap(), b"old");
        assert!(env.read_all(&d.join("old")).is_err());
    }

    #[test]
    fn bit_flips_and_injected_failures() {
        let env = MemEnv::new();
        let p = Path::new("f");
        env.create_dir_all(Path::new("")).unwrap();
        let mut w = write(&env, p, &[0, 0], true);
        env.flip_bit(p, 9).unwrap();
        assert_eq!(env.read_all(p).unwrap(), [0, 2]);
        assert_eq!(env.flip_bit(p, 16).unwrap_err().kind(), io::ErrorKind::InvalidInput);
        assert!(env.flip_bit(Path::new("missing"), 0).is_err());
        let r = env.open(p).unwrap();
        let ops = env.ops();
        env.fail_after(0);
        assert_eq!(env.ops(), ops);
        let mut b = [0u8; 1];
        assert!(w.append(b"x").is_err());
        assert!(w.sync().is_err());
        assert!(r.read_at(&mut b, 0).is_err());
        assert!(env.create(p).is_err());
        assert!(env.open(p).is_err());
        assert!(env.read_all(p).is_err());
        assert!(env.rename(p, p).is_err());
        assert!(env.remove(p).is_err());
        assert!(env.list(Path::new("")).is_err());
        assert!(env.create_dir_all(Path::new("")).is_err());
        assert!(env.sync_dir(Path::new("")).is_err());
        assert!(env.lock(Path::new("L")).is_err());
        assert_eq!(env.injected(), 12);
        env.heal();
        assert_eq!(env.injected(), 0);
        assert_eq!(env.read_all(p).unwrap(), [0, 2]);
    }

    /// flashkv itself over `MemEnv`: torn writes at a power loss never lose an
    /// acknowledged (synced) write, through flushes and compactions.
    #[test]
    fn db_survives_power_loss_with_torn_writes() {
        let env = MemEnv::new();
        let dir = Path::new("/kv");
        let opts = || DbOptions {
            env: Arc::new(env.clone()),
            write_buffer_size: 2 << 10,
            target_file_size: 4 << 10,
            ..DbOptions::default()
        };
        let mut acked = 0u32;
        for round in 0..8u32 {
            let db = Db::open(dir, opts()).unwrap();
            for i in 0..acked {
                let want = format!("value-{i:05}");
                assert_eq!(
                    db.get(format!("key-{i:05}").as_bytes()).unwrap(),
                    Some(want.into_bytes())
                );
            }
            for _ in 0..150 {
                let (k, v) = (format!("key-{acked:05}"), format!("value-{acked:05}"));
                db.put(k.as_bytes(), v.as_bytes()).unwrap();
                acked += 1;
            }
            drop(db);
            env.crash(&mut |unsynced| unsynced * round as usize / 8);
        }
    }
}
