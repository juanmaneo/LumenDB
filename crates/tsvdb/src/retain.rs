//! Retention: forgetting data that is older than it needs to be (QuestDB's
//! TTL).
//!
//! Data goes a whole partition at a time, which is cheap: a partition is a
//! range of keys, so dropping it is a run of deletes with no read of the
//! points. [`Db::drop_before`] drops the partitions that end at or before a
//! time, and [`Db::retention_cutoff`] says which time that is for data kept
//! `ttl` long. As in QuestDB, the reference time is the *earlier* of the wall
//! clock and the newest point: a point dated in the future does not make the
//! cutoff run ahead, and a database whose writers have stopped keeps its last
//! `ttl` of data instead of being emptied by the passing of time.
//!
//! The write buffer is flushed first, so that no point that is about to be
//! dropped is left in the write-ahead log to be replayed after a restart.
//! Points written later with old timestamps make their partition again; the
//! next call drops it. A series whose data is all gone stays listed.
//! Dropping and compaction share a lock, so a merge never puts back a chunk
//! that was just dropped.

use crate::db::{data_key, key_parts, stats_key, Db};
use crate::error::{Error, Result};
use crate::query::Query;
use flashkv::WriteBatch;
use std::sync::Arc;

/// Chunks deleted by one batch.
const DROP_BATCH: usize = 4096;

impl Db {
    /// The time before which data is to be dropped to keep `ttl` ns of it
    /// (`measurement`'s, or everyone's): the earlier of `now` and the newest
    /// point, minus `ttl`. `None` when there is no point at all.
    pub fn retention_cutoff(&self, measurement: Option<&str>, ttl: i64, now: i64) -> Result<Option<i64>> {
        if ttl <= 0 {
            return Err(Error::Query("the time to keep data must be positive".into()));
        }
        let measurements = match measurement {
            Some(m) => vec![m.to_string()],
            None => self.measurements(),
        };
        let mut newest: Option<i64> = None;
        for m in &measurements {
            for field in self.fields(m).into_keys() {
                for row in self.query(&Query::new(m, &field).latest())? {
                    newest = newest.max(Some(row.ts));
                }
            }
        }
        Ok(newest.map(|n| n.min(now).saturating_sub(ttl)))
    }

    /// Keeps the last `ttl` ns of the data of `measurement` (of everything
    /// if `None`): [`Db::retention_cutoff`], then [`Db::drop_before`].
    /// Returns the cutoff and the number of chunks dropped, or `None` when
    /// there is no data.
    pub fn retain(&self, measurement: Option<&str>, ttl: i64, now: i64) -> Result<Option<(i64, usize)>> {
        let Some(cutoff) = self.retention_cutoff(measurement, ttl, now)? else {
            return Ok(None);
        };
        Ok(Some((cutoff, self.drop_before(measurement, cutoff)?)))
    }

    /// Drops the partitions of `measurement` (of every measurement if
    /// `None`) that end at or before `cutoff`: every point older than the
    /// start of the partition that holds `cutoff`. Returns the number of
    /// chunks dropped. Not atomic, but it can be repeated: after a failure
    /// some chunks are gone and the others go with the next call.
    pub fn drop_before(&self, measurement: Option<&str>, cutoff: i64) -> Result<usize> {
        let _serial = self.compact_lock.lock();
        self.flush()?;
        let first_kept = self.opts.partition.bucket(cutoff);
        // The keys to delete, column by column, taken as the batches need them.
        let mut keys = self.columns(measurement).into_iter().flat_map(|col| {
            let (lo, hi) = (data_key(col, i64::MIN, 0), data_key(col, first_kept, 0));
            self.kv.iter(&lo, Some(&hi)).map(|item| item.map(|(key, _)| key))
        });
        let mut dropped = 0;
        loop {
            let doomed: Vec<Vec<u8>> = keys.by_ref().take(DROP_BATCH).collect::<flashkv::Result<_>>()?;
            if doomed.is_empty() {
                return Ok(dropped);
            }
            let mut batch = WriteBatch::new();
            doomed.iter().for_each(|key| {
                batch.delete(key);
                batch.delete(&stats_key(key));
            });
            // The store and the statistics that queries have copied change together.
            let mut guard = self.state.lock();
            self.kv.write(&batch)?;
            for (col, bucket, seq) in doomed.iter().filter_map(|key| key_parts(key)) {
                if let Some(catalog) = guard.catalog.get_mut(&col) {
                    Arc::make_mut(catalog).remove(&(bucket, seq));
                }
            }
            drop(guard);
            dropped += doomed.len();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::tests::{cpu, opts, tmpdir};
    use crate::lineproto::{FieldValue, Point};
    use crate::partition::Partitioner;
    use flashkv::env::{Env, FaultEnv, OsEnv};
    use std::path::Path;
    use std::sync::Arc;

    fn open(name: &str, partition: i64) -> (Db, std::path::PathBuf) {
        let dir = tmpdir(name);
        let mut o = opts();
        o.partition = Partitioner::new(partition);
        (Db::open(&dir, o).unwrap(), dir)
    }

    fn times(db: &Db, m: &str, field: &str) -> Vec<i64> {
        db.query(&Query::new(m, field))
            .unwrap()
            .into_iter()
            .map(|r| r.ts)
            .collect()
    }

    fn mem(ts: i64) -> Point {
        Point::new("mem")
            .tag("host", "a")
            .field("free", FieldValue::UInt(1))
            .at(ts)
    }

    #[test]
    fn the_cutoff_is_the_earlier_of_now_and_the_newest_point_minus_the_ttl() {
        let (db, dir) = open("retain-cutoff", 10);
        assert_eq!(db.retention_cutoff(None, 5, 1000).unwrap(), None);
        db.write_points(&[cpu("a", 100, 1.0), cpu("b", 120, 1.0), mem(500)])
            .unwrap();
        // Stored or buffered, the newest of everything counts...
        assert_eq!(db.retention_cutoff(None, 30, 10_000).unwrap(), Some(470));
        db.flush().unwrap();
        assert_eq!(db.retention_cutoff(None, 30, 10_000).unwrap(), Some(470));
        // ...or of one measurement.
        assert_eq!(db.retention_cutoff(Some("cpu"), 30, 10_000).unwrap(), Some(90));
        assert_eq!(db.retention_cutoff(Some("nothing"), 30, 10_000).unwrap(), None);
        // A point dated after now does not move the cutoff past now - ttl.
        assert_eq!(db.retention_cutoff(None, 30, 300).unwrap(), Some(270));
        // The time to keep is a positive time.
        for ttl in [0, -1] {
            assert!(db.retention_cutoff(None, ttl, 1000).is_err());
        }
        assert_eq!(
            db.retention_cutoff(Some("cpu"), i64::MAX, 1000).unwrap(),
            Some(120 - i64::MAX)
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn retain_is_the_cutoff_and_the_drop() {
        let (db, dir) = open("retain-both", 10);
        assert_eq!(db.retain(None, 5, 1000).unwrap(), None);
        db.write_points(&[cpu("a", 5, 1.0), cpu("a", 15, 2.0), cpu("a", 25, 3.0)])
            .unwrap();
        // The newest point is at 25, so 20 is the cutoff: [0, 10) and [10, 20) end before it.
        assert_eq!(db.retain(None, 5, 1000).unwrap(), Some((20, 2)));
        assert_eq!(times(&db, "cpu", "usage"), [25]);
        assert!(db.retain(None, 0, 1000).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn whole_partitions_before_the_cutoff_are_dropped_and_stay_dropped() {
        let (db, dir) = open("retain-drop", 10);
        let mut o = opts();
        o.partition = Partitioner::new(10);
        db.write_points(&[cpu("a", 5, 1.0), cpu("a", 15, 2.0), cpu("b", 19, 3.0), mem(7)])
            .unwrap();
        db.flush().unwrap();
        // Buffered, and in the write-ahead log: dropped as well, and not replayed.
        db.write_points(&[cpu("a", 25, 4.0), cpu("a", 3, 5.0), cpu("a", 31, 6.0)])
            .unwrap();
        // 20 is the start of a partition: [10, 20) ends there and goes. That
        // is two chunks of a's [0, 10), one of a's [10, 20) and one of b's.
        assert_eq!(db.drop_before(Some("cpu"), 20).unwrap(), 4);
        assert_eq!(times(&db, "cpu", "usage"), [25, 31]);
        assert_eq!(times(&db, "mem", "free"), [7], "another measurement is not touched");
        // 29 is inside [20, 30): that partition is kept, whole.
        assert_eq!(db.drop_before(None, 29).unwrap(), 1, "only mem's [0, 10)");
        assert_eq!(db.drop_before(None, 29).unwrap(), 0, "and again");
        assert_eq!(times(&db, "cpu", "usage"), [25, 31]);
        assert!(times(&db, "mem", "free").is_empty());
        assert_eq!(db.drop_before(Some("nothing"), 1000).unwrap(), 0);
        // After a restart, nothing comes back from the log.
        db.close().unwrap();
        let db = Db::open(&dir, o).unwrap();
        assert_eq!(times(&db, "cpu", "usage"), [25, 31]);
        assert!(times(&db, "mem", "free").is_empty());
        // The series is still listed, with no data; the rest of the data is dropped by the next call.
        assert_eq!(db.measurements(), ["cpu", "mem"]);
        assert_eq!(db.drop_before(None, i64::MAX).unwrap(), 2);
        assert!(times(&db, "cpu", "usage").is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn dropping_goes_on_across_batches() {
        let (db, dir) = open("retain-batches", 1);
        let points: Vec<Point> = (0..5_000).map(|ts| cpu("a", ts, 1.0)).collect();
        db.write_points(&points).unwrap();
        db.flush().unwrap();
        assert_eq!(db.drop_before(None, 4_500).unwrap(), 4_500);
        assert_eq!(times(&db, "cpu", "usage"), (4_500..5_000).collect::<Vec<_>>());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn compaction_goes_on_after_a_drop() {
        let mut o = opts();
        o.partition = Partitioner::new(10);
        o.compact_min_chunks = 2;
        let dir = tmpdir("retain-compact");
        let db = Db::open(&dir, o).unwrap();
        for ts in [1, 2, 3] {
            db.write_points(&[cpu("a", ts, 1.0), cpu("a", 20 + ts, 2.0)]).unwrap();
            db.flush().unwrap();
        }
        assert_eq!(db.drop_before(None, 10).unwrap(), 3);
        assert_eq!(db.compact().unwrap(), 1);
        assert_eq!(times(&db, "cpu", "usage"), [21, 22, 23]);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// The n-th I/O fails, then the power goes out: what was acknowledged
    /// and not yet to be dropped is still there, and a finished drop is done.
    #[test]
    fn a_failure_while_dropping_leaves_a_state_the_next_call_finishes() {
        let script = |env: Arc<dyn Env>, dir: &Path, acked: &mut Vec<i64>| -> Result<()> {
            let mut o = opts();
            o.kv.env = env;
            o.kv.sync = true;
            o.partition = Partitioner::new(10);
            let db = Db::open(dir, o)?;
            for ts in [1, 15, 25] {
                db.write_points(&[cpu("a", ts, 1.0)])?;
                acked.push(ts);
            }
            db.flush()?;
            db.kv.flush()?;
            db.write_points(&[cpu("a", 5, 9.0)])?;
            acked.push(5);
            // The newest point is at 25: the cutoff is 20.
            assert_eq!(db.retain(None, 5, i64::MAX)?.map(|r| r.0), Some(20));
            Ok(())
        };
        for n in 0.. {
            let dir = tmpdir("retain-faults");
            let fault = FaultEnv::new(Arc::new(OsEnv));
            fault.fail_after(n);
            let mut acked = Vec::new();
            let done = script(Arc::new(fault.clone()), &dir, &mut acked).is_ok();
            fault.heal();
            fault.crash().unwrap();
            let mut o = opts();
            o.partition = Partitioner::new(10);
            let db = Db::open(&dir, o).unwrap();
            let got = times(&db, "cpu", "usage");
            assert!(got.contains(&25) | !acked.contains(&25), "fault at op {n}: {got:?}");
            if done {
                assert_eq!(got, [25], "fault at op {n}");
            }
            // Whatever the state, a second call finishes the job.
            db.drop_before(None, 20).unwrap();
            assert_eq!(
                times(&db, "cpu", "usage").iter().filter(|&&t| t < 20).count(),
                0,
                "fault at op {n}"
            );
            drop(db);
            std::fs::remove_dir_all(&dir).unwrap();
            if done {
                break;
            }
        }
    }

    #[test]
    fn a_poisoned_database_cannot_drop() {
        let dir = tmpdir("retain-poison");
        let fault = FaultEnv::new(Arc::new(OsEnv));
        let mut o = opts();
        o.kv.env = Arc::new(fault.clone());
        let db = Db::open(&dir, o).unwrap();
        fault.fail_after(0);
        assert!(db.write_points(&[cpu("a", 1, 1.0)]).is_err());
        fault.heal();
        assert!(db.drop_before(None, 10).is_err());
        assert!(db.retention_cutoff(None, 5, 10).is_err());
        assert!(db.retain(None, 5, 10).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }
}
