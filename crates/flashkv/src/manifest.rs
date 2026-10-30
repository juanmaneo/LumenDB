//! Durable layout metadata: `CURRENT` → `MANIFEST-n` → version edits.
//!
//! The manifest is a CRC-framed log of [`VersionEdit`]s whose first record is
//! a full snapshot. `CURRENT` is switched atomically (write temp file, fsync,
//! rename, fsync directory), so after a hardware crash it names either the
//! old or the new manifest, never a half-written one. A torn manifest tail
//! only loses edits whose effects were never acknowledged (the WALs and
//! tables they referenced are still on disk and are recovered or collected).

use crate::env::Env;
use crate::error::{Error, Result};
use crate::log::{self, LogWriter};
use crate::version::VersionEdit;
use std::path::Path;

pub const CURRENT: &str = "CURRENT";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileKind {
    Log,
    Table,
    Manifest,
    Temp,
}

pub fn file_name(kind: FileKind, number: u64) -> String {
    match kind {
        FileKind::Log => format!("{number:06}.log"),
        FileKind::Table => format!("{number:06}.sst"),
        FileKind::Manifest => format!("MANIFEST-{number:06}"),
        FileKind::Temp => format!("{number:06}.tmp"),
    }
}

/// Inverse of [`file_name`]; `None` for files flashkv does not own.
pub fn parse_file_name(name: &str) -> Option<(FileKind, u64)> {
    if let Some(n) = name.strip_prefix("MANIFEST-") {
        return n.parse().ok().map(|n| (FileKind::Manifest, n));
    }
    let (stem, ext) = name.split_once('.')?;
    let kind = match ext {
        "log" => FileKind::Log,
        "sst" => FileKind::Table,
        "tmp" => FileKind::Temp,
        _ => return None,
    };
    stem.parse().ok().map(|n| (kind, n))
}

/// Atomically point `CURRENT` at manifest `number`.
pub fn set_current(env: &dyn Env, dir: &Path, number: u64) -> Result<()> {
    let tmp = dir.join(file_name(FileKind::Temp, number));
    let mut f = env.create(&tmp)?;
    f.append(format!("{}\n", file_name(FileKind::Manifest, number)).as_bytes())?;
    f.sync()?;
    env.rename(&tmp, &dir.join(CURRENT))?;
    Ok(env.sync_dir(dir)?)
}

/// Replay the current manifest: `(manifest_number, folded edit)`, or `None`
/// for a directory without a database.
pub fn recover(env: &dyn Env, dir: &Path) -> Result<Option<(u64, VersionEdit)>> {
    if !env.list(dir)?.iter().any(|n| n == CURRENT) {
        return Ok(None);
    }
    let current = env.read_all(&dir.join(CURRENT))?;
    let name = String::from_utf8_lossy(&current);
    let number = match parse_file_name(name.trim_end()) {
        Some((FileKind::Manifest, n)) if name.ends_with('\n') => n,
        _ => return Err(Error::corruption(format!("bad CURRENT contents {name:?}"))),
    };
    let data = env.read_all(&dir.join(file_name(FileKind::Manifest, number)))?;
    let (records, _) = log::parse(&data);
    if records.is_empty() {
        return Err(Error::corruption("manifest has no snapshot record"));
    }
    let mut state = VersionEdit::default();
    for r in records {
        state.absorb(&VersionEdit::decode(r)?);
    }
    Ok(Some((number, state)))
}

/// Appends edits to the live manifest, each one fsynced before it counts.
pub struct Manifest {
    log: LogWriter,
    number: u64,
}

impl Manifest {
    /// Start manifest `number` with a full snapshot and make it current.
    pub fn create(env: &dyn Env, dir: &Path, number: u64, snapshot: &VersionEdit) -> Result<Manifest> {
        let file = env.create(&dir.join(file_name(FileKind::Manifest, number)))?;
        let mut log = LogWriter::new(file);
        log.add(&snapshot.encode(), true)?;
        set_current(env, dir, number)?;
        Ok(Manifest { log, number })
    }

    pub fn append(&mut self, edit: &VersionEdit) -> Result<()> {
        self.log.add(&edit.encode(), true)
    }

    pub fn number(&self) -> u64 {
        self.number
    }

    pub fn size(&self) -> u64 {
        self.log.size()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::{FaultEnv, OsEnv};
    use std::sync::Arc;

    #[test]
    fn names_roundtrip() {
        for kind in [FileKind::Log, FileKind::Table, FileKind::Manifest, FileKind::Temp] {
            assert_eq!(parse_file_name(&file_name(kind, 42)), Some((kind, 42)));
        }
        for bad in ["LOCK", "CURRENT", "x.log", "1.txt", "MANIFEST-x", "noext"] {
            assert_eq!(parse_file_name(bad), None, "{bad}");
        }
    }

    #[test]
    fn create_append_recover() {
        let d = crate::env::tests::tmpdir("manifest");
        let env = OsEnv;
        assert!(recover(&env, &d).unwrap().is_none());
        let snap = VersionEdit {
            next_file: Some(5),
            ..Default::default()
        };
        let mut m = Manifest::create(&env, &d, 3, &snap).unwrap();
        assert_eq!(m.number(), 3);
        m.append(&VersionEdit {
            last_seq: Some(9),
            ..Default::default()
        })
        .unwrap();
        assert!(m.size() > 0);
        let (n, st) = recover(&env, &d).unwrap().unwrap();
        assert_eq!((n, st.next_file, st.last_seq), (3, Some(5), Some(9)));
        // torn tail is ignored
        let mp = d.join(file_name(FileKind::Manifest, 3));
        let mut bytes = std::fs::read(&mp).unwrap();
        bytes.extend_from_slice(&[1, 2, 3]);
        std::fs::write(&mp, &bytes).unwrap();
        assert!(recover(&env, &d).unwrap().is_some());
        // a record that frames correctly but does not decode
        let mut bytes = std::fs::read(&mp).unwrap();
        bytes.truncate(bytes.len() - 3);
        log::frame(&mut bytes, &[99]);
        std::fs::write(&mp, &bytes).unwrap();
        assert!(recover(&env, &d).is_err());
        // empty manifest
        std::fs::write(&mp, b"").unwrap();
        assert!(recover(&env, &d).unwrap_err().to_string().contains("snapshot"));
        // CURRENT problems
        std::fs::write(d.join(CURRENT), b"MANIFEST-000003").unwrap();
        assert!(recover(&env, &d).is_err());
        std::fs::write(d.join(CURRENT), b"000003.log\n").unwrap();
        assert!(recover(&env, &d).is_err());
        std::fs::write(d.join(CURRENT), b"MANIFEST-000004\n").unwrap();
        assert!(recover(&env, &d).is_err());
    }

    #[test]
    fn io_faults_surface() {
        let d = crate::env::tests::tmpdir("manifest-faults");
        let env = FaultEnv::new(Arc::new(OsEnv));
        let mut n = 0;
        loop {
            env.fail_after(n);
            let r = Manifest::create(&env, &d, 1, &VersionEdit::default()).and_then(|mut m| {
                m.append(&VersionEdit::default())?;
                recover(&env, &d)
            });
            env.heal();
            if r.is_ok() {
                break;
            }
            n += 1;
        }
        assert!(n >= 8);
    }
}
