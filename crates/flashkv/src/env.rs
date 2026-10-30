//! Pluggable filesystem environment (LevelDB's `Env`).
//!
//! Every byte flashkv persists goes through [`Env`], which makes the engine
//! modular (FoundationDB-style: swap the storage layer) and lets tests run a
//! deterministic fault simulation with [`FaultEnv`]:
//!
//! - `fail_after(n)`: the n-th I/O operation and every later one fails, like a
//!   disk that dies mid-flight;
//! - `crash()`: emulates a *hardware* crash / power loss — every file loses
//!   the bytes that were not `sync`ed and files created since the last
//!   directory sync disappear.
//!
//! Files are read with positional reads (`pread`), never mmap: a truncated or
//! corrupt file yields an `Err`, never a SIGBUS, and there is no map size to
//! outgrow (the classic LMDB `MDB_MAP_FULL` failure).

use parking_lot::Mutex;
use std::any::Any;
use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Append-only file (WAL, SSTable under construction, manifest).
pub trait WritableFile: Send {
    fn append(&mut self, data: &[u8]) -> io::Result<()>;
    /// Make every appended byte durable (`fdatasync`).
    fn sync(&mut self) -> io::Result<()>;
}

/// Immutable file read with positional reads.
pub trait RandomAccessFile: Send + Sync {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()>;
    fn len(&self) -> u64;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Opaque guard holding an exclusive lock on a database directory.
pub type LockGuard = Box<dyn Any + Send + Sync>;

pub trait Env: Send + Sync {
    /// Create (or truncate) a file for appending.
    fn create(&self, path: &Path) -> io::Result<Box<dyn WritableFile>>;
    fn open(&self, path: &Path) -> io::Result<Arc<dyn RandomAccessFile>>;
    fn read_all(&self, path: &Path) -> io::Result<Vec<u8>>;
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()>;
    fn remove(&self, path: &Path) -> io::Result<()>;
    /// File names (not paths) inside `dir`.
    fn list(&self, dir: &Path) -> io::Result<Vec<String>>;
    fn create_dir_all(&self, dir: &Path) -> io::Result<()>;
    /// Make directory entries (creates, renames, deletes) durable.
    fn sync_dir(&self, dir: &Path) -> io::Result<()>;
    /// Exclusive advisory lock; held until the guard is dropped.
    fn lock(&self, path: &Path) -> io::Result<LockGuard>;
}

/// The real operating-system filesystem.
#[derive(Clone, Copy, Debug, Default)]
pub struct OsEnv;

struct OsWritable(File);

impl WritableFile for OsWritable {
    fn append(&mut self, data: &[u8]) -> io::Result<()> {
        self.0.write_all(data)
    }
    fn sync(&mut self) -> io::Result<()> {
        self.0.sync_data()
    }
}

struct OsRandom {
    file: File,
    len: u64,
}

impl RandomAccessFile for OsRandom {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        self.file.read_exact_at(buf, offset)
    }
    fn len(&self) -> u64 {
        self.len
    }
}

impl Env for OsEnv {
    fn create(&self, path: &Path) -> io::Result<Box<dyn WritableFile>> {
        let f = OpenOptions::new().write(true).create(true).truncate(true).open(path)?;
        Ok(Box::new(OsWritable(f)))
    }
    fn open(&self, path: &Path) -> io::Result<Arc<dyn RandomAccessFile>> {
        let file = File::open(path)?;
        let len = file.metadata().map_or(0, |m| m.len());
        Ok(Arc::new(OsRandom { file, len }))
    }
    fn read_all(&self, path: &Path) -> io::Result<Vec<u8>> {
        fs::read(path)
    }
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        fs::rename(from, to)
    }
    fn remove(&self, path: &Path) -> io::Result<()> {
        fs::remove_file(path)
    }
    fn list(&self, dir: &Path) -> io::Result<Vec<String>> {
        Ok(fs::read_dir(dir)?
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect())
    }
    fn create_dir_all(&self, dir: &Path) -> io::Result<()> {
        fs::create_dir_all(dir)
    }
    fn sync_dir(&self, dir: &Path) -> io::Result<()> {
        File::open(dir).and_then(|d| d.sync_all())
    }
    fn lock(&self, path: &Path) -> io::Result<LockGuard> {
        let f = OpenOptions::new().write(true).create(true).truncate(false).open(path)?;
        match f.try_lock() {
            Ok(()) => Ok(Box::new(f)),
            Err(e) => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                format!("{} is locked: {e}", path.display()),
            )),
        }
    }
}

#[derive(Default)]
struct FaultState {
    /// Durable length of every file written through this env.
    synced: HashMap<PathBuf, u64>,
    /// Files whose directory entry is not yet durable.
    unsynced_creates: HashSet<PathBuf>,
    /// Renames not yet made durable: destination and its previous content.
    unsynced_renames: Vec<(PathBuf, Option<Vec<u8>>)>,
}

struct FaultShared {
    inner: Arc<dyn Env>,
    ops: AtomicU64,
    fail_at: AtomicU64,
    state: Mutex<FaultState>,
}

impl FaultShared {
    fn tick(&self) -> io::Result<()> {
        let n = self.ops.fetch_add(1, Ordering::SeqCst);
        if n >= self.fail_at.load(Ordering::SeqCst) {
            return Err(io::Error::other(format!("injected fault at op {n}")));
        }
        Ok(())
    }
}

/// Fault-injecting wrapper around another [`Env`] (deterministic simulation).
#[derive(Clone)]
pub struct FaultEnv(Arc<FaultShared>);

impl FaultEnv {
    pub fn new(inner: Arc<dyn Env>) -> Self {
        FaultEnv(Arc::new(FaultShared {
            inner,
            ops: AtomicU64::new(0),
            fail_at: AtomicU64::new(u64::MAX),
            state: Mutex::new(FaultState::default()),
        }))
    }

    /// Number of I/O operations performed so far.
    pub fn ops(&self) -> u64 {
        self.0.ops.load(Ordering::SeqCst)
    }

    /// Let `n` more operations succeed, then fail every following one.
    pub fn fail_after(&self, n: u64) {
        self.0.fail_at.store(self.ops().saturating_add(n), Ordering::SeqCst);
    }

    /// Stop injecting faults.
    pub fn heal(&self) {
        self.0.fail_at.store(u64::MAX, Ordering::SeqCst);
    }

    /// Simulate power loss: undo renames and delete created files that were
    /// never made durable by `sync_dir`, and truncate every file to its last
    /// synced length.
    pub fn crash(&self) -> io::Result<()> {
        let mut guard = self.0.state.lock();
        let st = &mut *guard;
        while let Some((to, prev)) = st.unsynced_renames.pop() {
            st.synced.remove(&to);
            match prev {
                Some(bytes) => fs::write(&to, bytes)?,
                None => {
                    let _ = fs::remove_file(&to);
                }
            }
        }
        for p in st.unsynced_creates.drain() {
            st.synced.remove(&p);
            let _ = fs::remove_file(&p);
        }
        for (p, len) in st.synced.iter() {
            if let Ok(f) = OpenOptions::new().write(true).open(p) {
                f.set_len(*len)?;
            }
        }
        Ok(())
    }
}

struct FaultWritable {
    env: Arc<FaultShared>,
    path: PathBuf,
    file: Box<dyn WritableFile>,
    written: u64,
}

impl WritableFile for FaultWritable {
    fn append(&mut self, data: &[u8]) -> io::Result<()> {
        self.env.tick()?;
        self.file.append(data)?;
        self.written += data.len() as u64;
        Ok(())
    }
    fn sync(&mut self) -> io::Result<()> {
        self.env.tick()?;
        self.file.sync()?;
        self.env.state.lock().synced.insert(self.path.clone(), self.written);
        Ok(())
    }
}

struct FaultRandom {
    env: Arc<FaultShared>,
    file: Arc<dyn RandomAccessFile>,
}

impl RandomAccessFile for FaultRandom {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        self.env.tick()?;
        self.file.read_at(buf, offset)
    }
    fn len(&self) -> u64 {
        self.file.len()
    }
}

impl Env for FaultEnv {
    fn create(&self, path: &Path) -> io::Result<Box<dyn WritableFile>> {
        self.0.tick()?;
        let file = self.0.inner.create(path)?;
        let mut st = self.0.state.lock();
        st.synced.insert(path.to_path_buf(), 0);
        st.unsynced_creates.insert(path.to_path_buf());
        Ok(Box::new(FaultWritable {
            env: self.0.clone(),
            path: path.to_path_buf(),
            file,
            written: 0,
        }))
    }
    fn open(&self, path: &Path) -> io::Result<Arc<dyn RandomAccessFile>> {
        self.0.tick()?;
        let file = self.0.inner.open(path)?;
        Ok(Arc::new(FaultRandom {
            env: self.0.clone(),
            file,
        }))
    }
    fn read_all(&self, path: &Path) -> io::Result<Vec<u8>> {
        self.0.tick()?;
        self.0.inner.read_all(path)
    }
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        self.0.tick()?;
        let prev = fs::read(to).ok();
        self.0.inner.rename(from, to)?;
        let mut st = self.0.state.lock();
        if let Some(len) = st.synced.remove(from) {
            st.synced.insert(to.to_path_buf(), len);
        }
        st.unsynced_creates.remove(from);
        st.unsynced_renames.push((to.to_path_buf(), prev));
        Ok(())
    }
    fn remove(&self, path: &Path) -> io::Result<()> {
        self.0.tick()?;
        self.0.inner.remove(path)?;
        let mut st = self.0.state.lock();
        st.synced.remove(path);
        st.unsynced_creates.remove(path);
        Ok(())
    }
    fn list(&self, dir: &Path) -> io::Result<Vec<String>> {
        self.0.tick()?;
        self.0.inner.list(dir)
    }
    fn create_dir_all(&self, dir: &Path) -> io::Result<()> {
        self.0.tick()?;
        self.0.inner.create_dir_all(dir)
    }
    fn sync_dir(&self, dir: &Path) -> io::Result<()> {
        self.0.tick()?;
        self.0.inner.sync_dir(dir)?;
        let mut st = self.0.state.lock();
        st.unsynced_creates.retain(|p| p.parent() != Some(dir));
        st.unsynced_renames.retain(|(p, _)| p.parent() != Some(dir));
        Ok(())
    }
    fn lock(&self, path: &Path) -> io::Result<LockGuard> {
        self.0.tick()?;
        self.0.inner.lock(path)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Fresh empty directory under the system temp dir.
    pub fn tmpdir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("flashkv-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn os_env_roundtrip() {
        let d = tmpdir("env-os");
        let e = OsEnv;
        let p = d.join("a");
        let mut w = e.create(&p).unwrap();
        w.append(b"hello").unwrap();
        w.sync().unwrap();
        drop(w);
        let r = e.open(&p).unwrap();
        assert_eq!(r.len(), 5);
        assert!(!r.is_empty());
        let mut buf = [0u8; 3];
        r.read_at(&mut buf, 1).unwrap();
        assert_eq!(&buf, b"ell");
        assert!(r.read_at(&mut buf, 4).is_err());
        assert_eq!(e.read_all(&p).unwrap(), b"hello");
        e.rename(&p, &d.join("b")).unwrap();
        assert_eq!(e.list(&d).unwrap(), vec!["b".to_string()]);
        e.sync_dir(&d).unwrap();
        e.remove(&d.join("b")).unwrap();
        e.create_dir_all(&d.join("x/y")).unwrap();
        let g = e.lock(&d.join("LOCK")).unwrap();
        let err = e.lock(&d.join("LOCK")).err().unwrap();
        assert!(err.to_string().contains("locked"));
        drop(g);
        e.lock(&d.join("LOCK")).unwrap();
    }

    #[test]
    fn os_env_errors() {
        let e = OsEnv;
        let missing = Path::new("/nonexistent-flashkv/dir/f");
        assert!(e.create(missing).is_err());
        assert!(e.open(missing).is_err());
        assert!(e.read_all(missing).is_err());
        assert!(e.rename(missing, missing).is_err());
        assert!(e.remove(missing).is_err());
        assert!(e.list(missing).is_err());
        assert!(e.sync_dir(missing).is_err());
        assert!(e.lock(missing).is_err());
        assert!(e.create_dir_all(Path::new("/proc/flashkv-nope")).is_err());
    }

    #[test]
    fn fault_env_counts_fails_and_heals() {
        let d = tmpdir("env-fault");
        let f = FaultEnv::new(Arc::new(OsEnv));
        let p = d.join("a");
        let mut w = f.create(&p).unwrap();
        w.append(b"abc").unwrap();
        w.sync().unwrap();
        let r = f.open(&p).unwrap();
        let mut b = [0u8; 3];
        r.read_at(&mut b, 0).unwrap();
        assert_eq!(r.len(), 3);
        assert_eq!(f.ops(), 5);
        f.fail_after(0);
        assert!(w.append(b"x").is_err());
        assert!(w.sync().is_err());
        assert!(r.read_at(&mut b, 0).is_err());
        assert!(f.create(&p).is_err());
        assert!(f.open(&p).is_err());
        assert!(f.read_all(&p).is_err());
        assert!(f.rename(&p, &p).is_err());
        assert!(f.remove(&p).is_err());
        assert!(f.list(&d).is_err());
        assert!(f.create_dir_all(&d).is_err());
        assert!(f.sync_dir(&d).is_err());
        assert!(f.lock(&d.join("L")).is_err());
        f.heal();
        f.read_all(&p).unwrap();
        f.list(&d).unwrap();
        f.create_dir_all(&d).unwrap();
        f.lock(&d.join("L")).unwrap();
    }

    #[test]
    fn fault_env_inner_errors_propagate() {
        let f = FaultEnv::new(Arc::new(OsEnv));
        let missing = Path::new("/nonexistent-flashkv/f");
        assert!(f.create(missing).is_err());
        assert!(f.open(missing).is_err());
        assert!(f.rename(missing, missing).is_err());
        assert!(f.remove(missing).is_err());
        assert!(f.sync_dir(missing).is_err());
        struct Bad;
        impl WritableFile for Bad {
            fn append(&mut self, _: &[u8]) -> io::Result<()> {
                Err(io::Error::other("a"))
            }
            fn sync(&mut self) -> io::Result<()> {
                Err(io::Error::other("s"))
            }
        }
        let mut w = FaultWritable {
            env: f.0.clone(),
            path: PathBuf::from("x"),
            file: Box::new(Bad),
            written: 0,
        };
        assert!(w.append(b"x").is_err());
        assert!(w.sync().is_err());
    }

    #[test]
    fn crash_drops_unsynced_data_and_files() {
        let d = tmpdir("env-crash");
        let f = FaultEnv::new(Arc::new(OsEnv));
        let durable = d.join("durable");
        let mut w = f.create(&durable).unwrap();
        w.append(b"synced").unwrap();
        w.sync().unwrap();
        w.append(b"-lost").unwrap();
        f.sync_dir(&d).unwrap();
        let ghost = d.join("ghost");
        let mut g = f.create(&ghost).unwrap();
        g.append(b"x").unwrap();
        g.sync().unwrap();
        let moved = d.join("moved");
        let mut m = f.create(&d.join("tmp")).unwrap();
        m.append(b"mm").unwrap();
        m.sync().unwrap();
        f.rename(&d.join("tmp"), &moved).unwrap();
        let gone = d.join("gone");
        f.create(&gone).unwrap();
        f.remove(&gone).unwrap();
        // a tracked file deleted behind the env's back is simply skipped
        let behind = d.join("behind");
        f.create(&behind).unwrap();
        f.sync_dir(&d).unwrap();
        fs::remove_file(&behind).unwrap();
        // `ghost` became durable with the second dir sync; `late` never did
        let late = d.join("late");
        f.create(&late).unwrap();
        // renames that were never made durable are undone
        fs::write(d.join("plain"), b"untracked").unwrap();
        f.rename(&d.join("plain"), &d.join("plain2")).unwrap();
        fs::write(d.join("cur"), b"old").unwrap();
        let mut t = f.create(&d.join("cur.tmp")).unwrap();
        t.append(b"new").unwrap();
        t.sync().unwrap();
        f.rename(&d.join("cur.tmp"), &d.join("cur")).unwrap();
        f.create(&d.join("n.tmp")).unwrap();
        f.rename(&d.join("n.tmp"), &d.join("fresh")).unwrap();
        f.crash().unwrap();
        assert_eq!(fs::read(d.join("cur")).unwrap(), b"old");
        assert!(!d.join("fresh").exists());
        assert_eq!(fs::read(&durable).unwrap(), b"synced");
        assert_eq!(fs::read(&moved).unwrap(), b"mm");
        assert!(ghost.exists());
        assert!(!late.exists());
    }

    #[test]
    fn crash_reports_truncate_errors() {
        let d = tmpdir("env-crash-dir");
        let f = FaultEnv::new(Arc::new(OsEnv));
        // a tracked path that is a directory cannot be opened for writing: skipped
        f.0.state.lock().synced.insert(d.clone(), 0);
        f.crash().unwrap();
        // a character device opens for writing but rejects ftruncate
        let mut st = f.0.state.lock();
        st.synced.clear();
        st.synced.insert(PathBuf::from("/dev/full"), 0);
        drop(st);
        assert!(f.crash().is_err());
        // restoring a renamed-over file can fail too
        f.0.state
            .lock()
            .unsynced_renames
            .push((PathBuf::from("/nonexistent-flashkv/x"), Some(vec![1])));
        assert!(f.crash().is_err());
    }
}
