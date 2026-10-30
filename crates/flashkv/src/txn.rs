//! Optimistic transactions (FoundationDB-style): reads come from a snapshot
//! (plus the transaction's own buffered writes), writes are buffered, and
//! commit atomically checks that nothing read was overwritten since the
//! snapshot before applying the batch — serializable without read locks.

use crate::batch::WriteBatch;
use crate::db::{Db, Snapshot};
use crate::error::Result;
use std::collections::BTreeMap;

pub struct Transaction<'a> {
    db: &'a Db,
    snapshot: Snapshot,
    reads: Vec<Vec<u8>>,
    local: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
    batch: WriteBatch,
}

impl<'a> Transaction<'a> {
    pub(crate) fn new(db: &'a Db, snapshot: Snapshot) -> Self {
        Transaction {
            db,
            snapshot,
            reads: Vec::new(),
            local: BTreeMap::new(),
            batch: WriteBatch::new(),
        }
    }

    /// Read `key` as of the snapshot, seeing this transaction's own writes.
    pub fn get(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        if let Some(v) = self.local.get(key) {
            return Ok(v.clone());
        }
        let v = self.db.get_seq(key, self.snapshot.sequence())?;
        self.reads.push(key.to_vec());
        Ok(v)
    }

    pub fn put(&mut self, key: &[u8], value: &[u8]) -> &mut Self {
        self.local.insert(key.to_vec(), Some(value.to_vec()));
        self.batch.put(key, value);
        self
    }

    pub fn delete(&mut self, key: &[u8]) -> &mut Self {
        self.local.insert(key.to_vec(), None);
        self.batch.delete(key);
        self
    }

    pub fn read_sequence(&self) -> u64 {
        self.snapshot.sequence()
    }

    /// Apply all writes atomically, or fail with `Error::Conflict`.
    pub fn commit(self) -> Result<()> {
        self.db.commit(self.snapshot.sequence(), &self.reads, &self.batch)
    }

    /// Discard the transaction (same as dropping it).
    pub fn rollback(self) {}
}

#[cfg(test)]
mod tests {
    use crate::db::{Db, DbOptions};
    use crate::env::tests::tmpdir;

    #[test]
    fn read_your_writes_conflicts_and_rollback() {
        let d = tmpdir("txn");
        let db = Db::open(&d, DbOptions::default()).unwrap();
        db.put(b"a", b"1").unwrap();
        let mut t = db.begin_transaction();
        assert_eq!(t.read_sequence(), 1);
        assert_eq!(t.get(b"a").unwrap(), Some(b"1".to_vec()));
        t.put(b"b", b"2").delete(b"a");
        assert_eq!(t.get(b"b").unwrap(), Some(b"2".to_vec()));
        assert_eq!(t.get(b"a").unwrap(), None);
        db.put(b"unrelated", b"z").unwrap();
        t.commit().unwrap();
        assert_eq!(db.get(b"a").unwrap(), None);
        assert_eq!(db.get(b"b").unwrap(), Some(b"2".to_vec()));

        let mut t1 = db.begin_transaction();
        t1.get(b"b").unwrap();
        db.put(b"b", b"3").unwrap();
        t1.put(b"c", b"x");
        assert!(t1.commit().unwrap_err().to_string().contains("conflict"));
        assert_eq!(db.get(b"c").unwrap(), None);

        let mut t2 = db.begin_transaction();
        t2.put(b"ghost", b"nope");
        t2.rollback();
        assert_eq!(db.get(b"ghost").unwrap(), None);
        assert_eq!(db.stats().live_snapshots, 0);
    }
}
