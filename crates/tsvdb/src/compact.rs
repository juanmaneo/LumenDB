//! Background compaction and downsampling.
//!
//! Every flush adds one chunk per column and partition, so a busy partition
//! accumulates many small chunks. [`Db::compact`] merges them (sorted,
//! deduplicated, last write wins) into one, the eguan/ibs way: it works from
//! a flashkv snapshot without holding the database lock, and publishes with a
//! single atomic batch that deletes the inputs and overwrites the newest
//! input's key. Readers keep using their own snapshots and are never blocked;
//! chunks flushed meanwhile have higher sequence numbers, so they still win.
//!
//! [`Db::rollup`] downsamples: it writes the windowed aggregates of a query as
//! a new measurement (e.g. 1-minute means of 10-second samples).
//! [`Compactor`] runs `compact` periodically on a background thread.

use crate::chunk::Chunk;
use crate::chunk::ChunkStats;
use crate::db::{key_parts, stats_key, Db, PARTITION_PREFIX};
use crate::error::{Error, Result};
use crate::lineproto::Point;
use crate::query::Query;
use flashkv::WriteBatch;
use std::sync::atomic::Ordering;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// A partition of a column that was merged: the keys of the chunks that went,
/// and the key and statistics of the one that is left.
struct Merged {
    removed: Vec<Vec<u8>>,
    key: Vec<u8>,
    stats: ChunkStats,
}

impl Db {
    /// Merges every partition holding at least `compact_min_chunks` chunks
    /// (and at least 2). Returns the number of partitions merged. Only the
    /// small entries with the statistics of all the chunks are read to find
    /// them, and the chunks of the partitions that are merged.
    pub fn compact(&self) -> Result<usize> {
        let _serial = self.compact_lock.lock();
        self.state.lock().healthy()?;
        let snapshot = self.kv.snapshot();
        let mut batch = WriteBatch::new();
        let mut merges = Vec::new();
        let mut group: Vec<Vec<u8>> = Vec::new();
        for item in self.kv.iter_at(&snapshot, b"E", Some(b"F")) {
            let (k, _) = item?;
            if group
                .first()
                .is_some_and(|g| g.get(..PARTITION_PREFIX) != k.get(..PARTITION_PREFIX))
            {
                merges.extend(self.merge_group(&snapshot, std::mem::take(&mut group), &mut batch)?);
            }
            group.push(k);
        }
        merges.extend(self.merge_group(&snapshot, group, &mut batch)?);
        // The store and the statistics that queries have copied change together.
        let mut guard = self.state.lock();
        self.kv.write(&batch)?;
        for m in &merges {
            for (col, bucket, seq) in m.removed.iter().filter_map(|key| key_parts(key)) {
                if let Some(catalog) = guard.catalog.get_mut(&col) {
                    Arc::make_mut(catalog).remove(&(bucket, seq));
                }
            }
            for (col, bucket, seq) in [&m.key].into_iter().filter_map(|key| key_parts(key)) {
                if let Some(catalog) = guard.catalog.get_mut(&col) {
                    Arc::make_mut(catalog).insert((bucket, seq), m.stats.clone());
                }
            }
        }
        self.compactions.fetch_add(merges.len() as u64, Ordering::Relaxed);
        Ok(merges.len())
    }

    /// Puts the merging of the chunks that the statistics `keys` (of one
    /// partition of a column, in the order they were written) are of in
    /// `batch`, if there are enough of them.
    fn merge_group(
        &self,
        snapshot: &flashkv::Snapshot,
        keys: Vec<Vec<u8>>,
        batch: &mut WriteBatch,
    ) -> Result<Option<Merged>> {
        if keys.len() < self.opts.compact_min_chunks.max(2) {
            return Ok(None);
        }
        let data_keys: Vec<Vec<u8>> = keys
            .iter()
            .map(|k| {
                let mut data = k.clone();
                data[0] = b'D';
                data
            })
            .collect();
        let chunks = data_keys
            .iter()
            .map(|k| self.chunk_at(snapshot, k))
            .collect::<Result<Vec<_>>>()?;
        let ty = chunks[0].field_type();
        let points = chunks.iter().flat_map(Chunk::points).collect();
        let merged = Chunk::from_points(ty, points).expect("a column has a single type");
        let (newest, older) = data_keys.split_last().expect("at least two chunks");
        for k in older {
            batch.delete(k);
            batch.delete(&stats_key(k));
        }
        batch.put(newest, &merged.encode());
        let stats = merged.stats().expect("a merged chunk has points");
        batch.put(&stats_key(newest), &stats.encode());
        Ok(Some(Merged {
            removed: older.to_vec(),
            key: newest.clone(),
            stats,
        }))
    }

    /// Writes the aggregated rows of `q` (which needs an aggregate and a
    /// window) as points of measurement `target`, same tags, field
    /// `q.field`. Returns the number of points written.
    pub fn rollup(&self, q: &Query, target: &str) -> Result<usize> {
        if q.agg.is_none() | q.every.is_none() {
            return Err(Error::Query("rollup needs an aggregate and a window".into()));
        }
        let points: Vec<Point> = self
            .query(q)?
            .into_iter()
            .map(|r| Point {
                measurement: target.to_string(),
                tags: (*r.tags).clone(),
                fields: [(q.field.clone(), r.value)].into(),
                timestamp: Some(r.ts),
            })
            .collect();
        self.write_all(&points)
    }
}

/// Periodic background compaction; stops on [`Compactor::stop`] or drop.
pub struct Compactor {
    stop: mpsc::Sender<()>,
    handle: JoinHandle<u64>,
}

impl Compactor {
    /// Compacts now and then every `every` until stopped.
    pub fn start(db: Arc<Db>, every: Duration) -> Compactor {
        let (stop, rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            let mut passes = 0;
            loop {
                let _ = db.compact();
                passes += 1;
                match rx.recv_timeout(every) {
                    Err(RecvTimeoutError::Timeout) => {}
                    _ => return passes,
                }
            }
        });
        Compactor { stop, handle }
    }

    /// Stops the thread; returns how many passes it ran.
    pub fn stop(self) -> u64 {
        let Compactor { stop, handle } = self;
        let _ = stop.send(());
        handle.join().expect("compactor thread panicked")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::tests::{cpu, opts, tmpdir};
    use crate::lineproto::FieldValue;
    use crate::query::Agg;

    #[test]
    fn compaction_merges_and_keeps_answers() {
        let dir = tmpdir("compact");
        let mut o = opts();
        o.compact_min_chunks = 3;
        let db = Db::open(&dir, o).unwrap();
        // Three flushes of the same partition, with an overwrite.
        for (ts, v) in [(1, 1.0), (2, 2.0), (1, 7.0)] {
            db.write_points(&[cpu("a", ts, v), cpu("b", ts, v)]).unwrap();
            db.flush().unwrap();
        }
        // Another partition with a single chunk is left alone.
        db.write_points(&[cpu("a", 10 * crate::partition::HOUR_NS, 3.0)])
            .unwrap();
        db.flush().unwrap();
        let q = Query::new("cpu", "usage").filter("host", "a");
        let before = db.query(&q).unwrap();
        assert_eq!(before[0].value, FieldValue::Float(7.0));
        let reader = db.kv.snapshot();
        assert_eq!(db.compact().unwrap(), 2, "one partition per host");
        assert_eq!(db.stats().compactions, 2);
        assert_eq!(db.query(&q).unwrap(), before);
        assert_eq!(db.compact().unwrap(), 0, "nothing left to merge");
        // A reader's snapshot still sees the pre-compaction chunks.
        let old: Vec<_> = db.kv.iter_at(&reader, b"D", Some(b"E")).collect();
        assert_eq!(old.len(), 7);
        let chunks = db.kv.scan(b"D", Some(b"E")).unwrap();
        assert_eq!(chunks.len(), 3);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn corrupt_chunk_stops_compaction() {
        let dir = tmpdir("compact-corrupt");
        let mut o = opts();
        o.compact_min_chunks = 2;
        let db = Db::open(&dir, o).unwrap();
        // The corrupt group (column 0) is followed by another column's group.
        db.write_points(&[cpu("a", 1, 1.0), cpu("b", 1, 1.0)]).unwrap();
        db.flush().unwrap();
        let junk = |col: u64| {
            let key = crate::db::data_key(col, 0, 999);
            db.kv.put(&key, b"\x09").unwrap();
            let text = ChunkStats {
                count: 1,
                min_ts: 0,
                max_ts: 0,
                numbers: None,
            };
            db.kv.put(&stats_key(&key), &text.encode()).unwrap();
            key
        };
        let key = junk(0);
        assert!(db.compact().is_err());
        // ... and as the last group.
        db.kv.delete(&key).unwrap();
        db.kv.delete(&stats_key(&key)).unwrap();
        junk(1);
        assert!(db.compact().is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn keys_that_are_not_those_of_chunks_stop_compaction_and_not_the_process() {
        let dir = tmpdir("compact-junk");
        let mut o = opts();
        o.compact_min_chunks = 2;
        let db = Db::open(&dir, o).unwrap();
        db.write_points(&[cpu("a", 1, 1.0)]).unwrap();
        db.flush().unwrap();
        // One such key is a group of one; with a second, the merge looks for
        // the chunk and does not find it.
        db.kv.put(b"Eab", b"").unwrap();
        assert_eq!(db.compact().unwrap(), 0);
        db.kv.put(b"Eac", b"").unwrap();
        let e = db.compact().unwrap_err().to_string();
        assert!(e.contains("chunk (it has statistics)"), "{e}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rollup_downsamples() {
        let dir = tmpdir("rollup");
        let db = Db::open(&dir, opts()).unwrap();
        let pts: Vec<Point> = (0..6).map(|i| cpu("a", i * 10, i as f64)).collect();
        db.write_points(&pts).unwrap();
        let q = Query::new("cpu", "usage").range(0, 60).agg(Agg::Mean).every(30);
        assert_eq!(db.rollup(&q, "cpu_30").unwrap(), 2);
        let rows = db.query(&Query::new("cpu_30", "usage")).unwrap();
        assert_eq!(
            rows.iter().map(|r| (r.ts, r.value.clone())).collect::<Vec<_>>(),
            vec![(0, FieldValue::Float(1.0)), (30, FieldValue::Float(4.0))]
        );
        assert_eq!(rows[0].tags["host"], "a");
        assert!(db.rollup(&Query::new("cpu", "usage"), "x").is_err());
        assert!(db.rollup(&Query::new("cpu", "usage").agg(Agg::Sum), "x").is_err());
        let empty_range = Query::new("cpu", "usage").agg(Agg::Sum).every(5).range(9, 9);
        assert!(db.rollup(&empty_range, "x").is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn background_compactor_runs_until_stopped() {
        let dir = tmpdir("compactor");
        let mut o = opts();
        o.compact_min_chunks = 2;
        let db = Arc::new(Db::open(&dir, o).unwrap());
        for ts in 0..2 {
            db.write_points(&[cpu("a", ts, 1.0)]).unwrap();
            db.flush().unwrap();
        }
        let c = Compactor::start(db.clone(), Duration::from_millis(1));
        thread::sleep(Duration::from_millis(50));
        assert!(c.stop() >= 2);
        assert_eq!(db.stats().compactions, 1);
        assert_eq!(db.query(&Query::new("cpu", "usage")).unwrap().len(), 2);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
