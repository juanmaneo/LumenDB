//! The database: every byte lives in flashkv (crash-safe, no mmap).
//!
//! Write path (InfluxDB v3 style WAL + write buffer):
//! 1. points are validated against the schema (a field keeps its first type);
//! 2. one flashkv batch atomically stores the new series / schema / column
//!    entries plus the points as a line-protocol WAL record — when
//!    `write_points` returns `Ok` the points survive a power loss;
//! 3. points join the in-memory write buffer.
//!
//! When the buffer is large enough it is flushed: one batch writes a
//! compressed [`Chunk`] per column and partition and deletes the WAL records
//! it covers. At open the index is rebuilt and pending WAL records replayed.
//!
//! Reads take a flashkv snapshot plus a copy of the matching buffered points
//! under a short lock, then decode chunks without any lock; compaction
//! ([`crate::compact`]) rewrites chunks with atomic batches, so it never blocks
//! nor disturbs readers.
//!
//! Any storage failure poisons the database (like LevelDB's background
//! error): later calls fail until it is reopened, which recovers exactly the
//! acknowledged writes.
//!
//! Key space: `C`+sid+field → column, `D`+col+bucket+seq → chunk,
//! `F`+measurement+field → type, `Mseq` → sequence, `S`+series key → series,
//! `W`+seq → WAL record.

use crate::chunk::{normalize, Chunk};
use crate::error::{Error, Result};
use crate::lineproto::{self, FieldType, FieldValue, Point};
use crate::partition::{encode_bucket, Partitioner};
use crate::query::{self, Query, Row};
use crate::tags::{Series, SeriesIndex};
use crate::time::now_ns;
use flashkv::codec::Decoder;
use flashkv::varint::put_len_prefixed;
use flashkv::WriteBatch;
use parking_lot::Mutex;
use pcapfast::flow::proto_name;
use pcapfast::{FlowKey, FlowStats, FlowTable, ParseStats};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

/// Points per `write_points` call when ingesting captures.
pub const INGEST_BATCH: usize = 50_000;
const META_SEQ: &[u8] = b"Mseq";

#[derive(Clone)]
pub struct DbOptions {
    pub kv: flashkv::DbOptions,
    pub partition: Partitioner,
    /// Buffered points that trigger a flush to chunks.
    pub flush_points: usize,
    /// Chunks of one column/partition that make compaction merge them.
    pub compact_min_chunks: usize,
    /// The most rows a query may make by filling empty windows.
    pub max_fill_rows: usize,
}

impl Default for DbOptions {
    fn default() -> Self {
        DbOptions {
            kv: flashkv::DbOptions::default(),
            partition: Partitioner::hourly(),
            flush_points: 100_000,
            compact_min_chunks: 4,
            max_fill_rows: query::MAX_FILL_ROWS,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DbStats {
    pub series: usize,
    pub columns: usize,
    pub buffered_points: usize,
    pub wal_records: usize,
    pub flushes: u64,
    pub compactions: u64,
}

#[derive(Default)]
pub(crate) struct State {
    index: SeriesIndex,
    /// measurement → field → type.
    schema: HashMap<String, HashMap<String, FieldType>>,
    /// series id → field → column id.
    cols: HashMap<u64, HashMap<String, u64>>,
    col_types: HashMap<u64, FieldType>,
    next_col: u64,
    buffer: HashMap<u64, Vec<(i64, FieldValue)>>,
    buffered: usize,
    /// WAL keys not yet covered by a flush.
    wal: Vec<Vec<u8>>,
    seq: u64,
    poisoned: Option<String>,
    flushes: u64,
}

fn corrupt(what: &str) -> Error {
    Error::Corrupt(format!("bad {what} entry"))
}

fn lossy(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn series_kv_key(key: &str) -> Vec<u8> {
    [b"S", key.as_bytes()].concat()
}

fn field_key(measurement: &str, field: &str) -> Vec<u8> {
    let mut k = vec![b'F'];
    put_len_prefixed(&mut k, measurement.as_bytes());
    k.extend_from_slice(field.as_bytes());
    k
}

fn column_key(sid: u64, field: &str) -> Vec<u8> {
    [&b"C"[..], &sid.to_le_bytes(), field.as_bytes()].concat()
}

pub(crate) fn data_key(col: u64, bucket: i64, seq: u64) -> Vec<u8> {
    [
        &b"D"[..],
        &col.to_be_bytes(),
        &encode_bucket(bucket),
        &seq.to_be_bytes(),
    ]
    .concat()
}

/// Timestamped values of one column.
type Points = Vec<(i64, FieldValue)>;

fn in_range(q: &Query, p: &(i64, FieldValue)) -> bool {
    (p.0 >= q.start) & (p.0 < q.end)
}

/// The newest point in the range of `q` among the chunks of one partition.
fn newest_in_chunks(chunks: &[Vec<u8>], q: &Query) -> Result<Option<(i64, FieldValue)>> {
    let mut points = Vec::new();
    for chunk in chunks {
        points.extend(Chunk::decode(chunk)?.points());
    }
    Ok(normalize(points).into_iter().rev().find(|p| in_range(q, p)))
}

/// Length of the `D`+col+bucket prefix shared by the chunks of a partition.
pub(crate) const PARTITION_PREFIX: usize = 17;

impl State {
    pub(crate) fn healthy(&self) -> Result<()> {
        match &self.poisoned {
            Some(e) => Err(Error::Kv(flashkv::Error::Background(e.clone()))),
            None => Ok(()),
        }
    }

    fn load_field(&mut self, k: &[u8], v: &[u8]) -> Result<()> {
        let mut d = Decoder::new(&k[1..]);
        let m = lossy(d.lp());
        let f = lossy(d.bytes(d.remaining()));
        match (d.finish("field key"), v.first().copied().and_then(FieldType::from_u8)) {
            (Ok(()), Some(ty)) => {
                self.schema.entry(m).or_default().insert(f, ty);
                Ok(())
            }
            _ => Err(corrupt("field")),
        }
    }

    fn load_column(&mut self, k: &[u8], v: &[u8]) -> Result<()> {
        let mut d = Decoder::new(&k[1..]);
        let sid = d.u64();
        let field = lossy(d.bytes(d.remaining()));
        let mut dv = Decoder::new(v);
        let col = dv.u64();
        let ty = FieldType::from_u8(dv.u8());
        match (d.finish("column key").and(dv.finish("column")), ty) {
            (Ok(()), Some(ty)) => {
                self.cols.entry(sid).or_default().insert(field, col);
                self.col_types.insert(col, ty);
                self.next_col = self.next_col.max(col + 1);
                Ok(())
            }
            _ => Err(corrupt("column")),
        }
    }

    /// Resolves series / columns for `points` (registering new ones in
    /// memory and in `batch`) and returns `(column, ts, value)` triples.
    fn stage(&mut self, points: &[Point], now: i64, batch: &mut WriteBatch) -> Vec<(u64, i64, FieldValue)> {
        let mut staged = Vec::new();
        for p in points {
            let ts = p.timestamp.unwrap_or(now);
            let (sid, new) = self.index.insert(&p.measurement, &p.tags);
            if new {
                let s = self.index.series(sid).expect("just inserted");
                batch.put(&series_kv_key(&s.key()), &s.encode());
            }
            let schema = self.schema.entry(p.measurement.clone()).or_default();
            let cols = self.cols.entry(sid).or_default();
            for (f, v) in &p.fields {
                let ty = v.field_type();
                schema.entry(f.clone()).or_insert_with(|| {
                    batch.put(&field_key(&p.measurement, f), &[ty as u8]);
                    ty
                });
                let col = *cols.entry(f.clone()).or_insert_with(|| {
                    let c = self.next_col;
                    self.next_col += 1;
                    self.col_types.insert(c, ty);
                    batch.put(&column_key(sid, f), &[&c.to_le_bytes()[..], &[ty as u8]].concat());
                    c
                });
                staged.push((col, ts, v.clone()));
            }
        }
        staged
    }

    fn apply(&mut self, staged: Vec<(u64, i64, FieldValue)>) {
        self.buffered += staged.len();
        for (col, ts, v) in staged {
            self.buffer.entry(col).or_default().push((ts, v));
        }
    }

    fn replay(&mut self, record: &[u8]) -> Result<()> {
        let points = lineproto::parse(&String::from_utf8_lossy(record))?;
        let staged = self.stage(&points, 0, &mut WriteBatch::new());
        self.apply(staged);
        Ok(())
    }
}

/// Every point well-formed and every field consistent with the schema and
/// with the other points of the batch.
fn check_points(schema: &HashMap<String, HashMap<String, FieldType>>, points: &[Point]) -> Result<()> {
    let mut seen: HashMap<(&str, &str), FieldType> = HashMap::new();
    for p in points {
        p.validate().map_err(Error::Schema)?;
        for (f, v) in &p.fields {
            let ty = v.field_type();
            let known = schema.get(&p.measurement).and_then(|m| m.get(f)).copied();
            let want = *seen.entry((&p.measurement, f)).or_insert(known.unwrap_or(ty));
            if want != ty {
                return Err(Error::Schema(format!(
                    "field {f:?} of {:?} is {want:?}, got {ty:?}",
                    p.measurement
                )));
            }
        }
    }
    Ok(())
}

fn flow_points(flows: &FlowTable) -> Vec<Point> {
    flows.iter().map(|(k, s)| flow_point(k, s)).collect()
}

fn timeline_points(timeline: &BTreeMap<u64, (u64, u64)>) -> Vec<Point> {
    timeline
        .iter()
        .map(|(&ts, &(packets, bytes))| {
            Point::new("traffic")
                .field("packets", FieldValue::UInt(packets))
                .field("bytes", FieldValue::UInt(bytes))
                .at(i64::try_from(ts).unwrap_or(i64::MAX))
        })
        .collect()
}

fn flow_point(k: &FlowKey, s: &FlowStats) -> Point {
    let proto = proto_name(k.proto).map_or_else(|| k.proto.to_string(), str::to_string);
    Point::new("flows")
        .tag("src", k.src.to_string())
        .tag("dst", k.dst.to_string())
        .tag("sport", k.src_port.to_string())
        .tag("dport", k.dst_port.to_string())
        .tag("proto", proto)
        .field("packets", FieldValue::UInt(s.packets))
        .field("bytes", FieldValue::UInt(s.bytes))
        .field(
            "duration_ns",
            FieldValue::UInt(s.last_ts_ns.saturating_sub(s.first_ts_ns)),
        )
        .at(i64::try_from(s.first_ts_ns).unwrap_or(i64::MAX))
}

/// The points [`Db::ingest_capture`] writes: one `flows` point per flow and
/// one `traffic` point per timeline bucket.
pub fn capture_points(stats: &ParseStats) -> Vec<Point> {
    [flow_points(&stats.flows), timeline_points(&stats.timeline)].concat()
}

pub struct Db {
    pub(crate) kv: flashkv::Db,
    pub(crate) opts: DbOptions,
    pub(crate) state: Mutex<State>,
    pub(crate) compact_lock: Mutex<()>,
    pub(crate) compactions: AtomicU64,
}

impl Db {
    pub fn open(dir: &Path, opts: DbOptions) -> Result<Db> {
        let kv = flashkv::Db::open(dir, opts.kv.clone())?;
        let mut entries = kv.scan(b"C", Some(b"D"))?;
        entries.extend(kv.scan(b"F", Some(b"X"))?);
        let mut st = State::default();
        // Key order guarantees series, schema and columns precede the WAL.
        for (k, v) in entries {
            match k[0] {
                b'C' => st.load_column(&k, &v)?,
                b'F' => st.load_field(&k, &v)?,
                b'M' => {
                    let mut d = Decoder::new(&v);
                    st.seq = d.u64();
                    d.finish("sequence")?;
                }
                b'S' => st.index.restore(Series::decode(&v)?),
                b'W' => {
                    st.replay(&v)?;
                    st.wal.push(k);
                }
                _ => {}
            }
        }
        Ok(Db {
            kv,
            opts,
            state: Mutex::new(st),
            compact_lock: Mutex::new(()),
            compactions: AtomicU64::new(0),
        })
    }

    /// Writes `points` durably (see module docs). Points without a timestamp
    /// get the current time. All or nothing.
    pub fn write_points(&self, points: &[Point]) -> Result<()> {
        let mut guard = self.state.lock();
        let st = &mut *guard;
        st.healthy()?;
        check_points(&st.schema, points)?;
        let now = now_ns();
        let mut batch = WriteBatch::new();
        let staged = st.stage(points, now, &mut batch);
        let mut text = String::new();
        for p in points {
            lineproto::write_line(&mut text, p, Some(p.timestamp.unwrap_or(now)));
            text.push('\n');
        }
        st.seq += 1;
        let wal_key = [&b"W"[..], &st.seq.to_be_bytes()].concat();
        batch.put(&wal_key, text.as_bytes());
        batch.put(META_SEQ, &st.seq.to_le_bytes());
        self.commit(st, &batch)?;
        st.wal.push(wal_key);
        st.apply(staged);
        if st.buffered >= self.opts.flush_points {
            // The points are already durable: a failed flush only poisons
            // the database (reported by the next call), the write stands.
            let _ = self.flush_locked(st);
        }
        Ok(())
    }

    /// Parses line protocol and writes it; returns the number of points.
    pub fn write_lines(&self, text: &str) -> Result<usize> {
        let points = lineproto::parse(text)?;
        self.write_points(&points)?;
        Ok(points.len())
    }

    fn commit(&self, st: &mut State, batch: &WriteBatch) -> Result<()> {
        self.kv.write(batch).map_err(|e| {
            st.poisoned = Some(e.to_string());
            Error::Kv(e)
        })
    }

    /// Moves the write buffer into chunks.
    pub fn flush(&self) -> Result<()> {
        let mut guard = self.state.lock();
        guard.healthy()?;
        self.flush_locked(&mut guard)
    }

    fn flush_locked(&self, st: &mut State) -> Result<()> {
        let mut batch = WriteBatch::new();
        for (col, points) in std::mem::take(&mut st.buffer) {
            let ty = st.col_types[&col];
            for (bucket, part) in self.opts.partition.split(points) {
                let chunk = Chunk::from_points(ty, part).expect("buffered values match their column type");
                st.seq += 1;
                batch.put(&data_key(col, bucket, st.seq), &chunk.encode());
            }
        }
        for k in st.wal.drain(..) {
            batch.delete(&k);
        }
        batch.put(META_SEQ, &st.seq.to_le_bytes());
        self.commit(st, &batch)?;
        st.buffered = 0;
        st.flushes += 1;
        Ok(())
    }

    /// Series matching `q` with their points in `[q.start, q.end)`, sorted
    /// and deduplicated (last write wins).
    fn read_series(&self, q: &Query) -> Result<Vec<(Series, Points)>> {
        let (targets, snapshot) = {
            let st = self.state.lock();
            st.healthy()?;
            let targets: Vec<(Series, u64, Points)> = st
                .index
                .lookup(&q.measurement, &q.filters)
                .into_iter()
                .filter_map(|sid| {
                    let col = *st.cols[&sid].get(&q.field)?;
                    let series = st.index.series(sid).expect("indexed").clone();
                    Some((series, col, st.buffer.get(&col).cloned().unwrap_or_default()))
                })
                .collect();
            (targets, self.kv.snapshot())
        };
        let buckets = self.opts.partition.buckets(q.start, q.end);
        let mut out = Vec::with_capacity(targets.len());
        for (series, col, buffered) in targets {
            let lo = data_key(col, *buckets.start(), 0);
            let hi = data_key(col, buckets.end() + 1, 0);
            let points = if q.latest {
                self.newest_point(&snapshot, (&lo, &hi), buffered, q)?
            } else {
                let mut points = Vec::new();
                for item in self.kv.iter_at(&snapshot, &lo, Some(&hi)) {
                    let (_, v) = item?;
                    points.extend(Chunk::decode(&v)?.points());
                }
                points.extend(buffered);
                normalize(points).into_iter().filter(|p| in_range(q, p)).collect()
            };
            out.push((series, points));
        }
        Ok(out)
    }

    /// The newest point of one column in the range of `q`, as a list of at
    /// most one point. It goes through the keys of the column's chunks but
    /// decodes only those of the newest partition (and the one before it, if
    /// the newest holds nothing in range), so a long history costs a key scan
    /// and not a decode of every point.
    fn newest_point(
        &self,
        snapshot: &flashkv::Snapshot,
        (lo, hi): (&[u8], &[u8]),
        buffered: Points,
        q: &Query,
    ) -> Result<Points> {
        // The chunks of the last two partitions, oldest first, by partition.
        let mut parts: Vec<(Vec<u8>, Vec<Vec<u8>>)> = Vec::new();
        for item in self.kv.iter_at(snapshot, lo, Some(hi)) {
            let (k, v) = item?;
            if parts.last().map(|p| &p.0[..]) != Some(&k[..PARTITION_PREFIX]) {
                if parts.len() == 2 {
                    parts.remove(0);
                }
                parts.push((k[..PARTITION_PREFIX].to_vec(), Vec::new()));
            }
            parts.last_mut().expect("a partition was just added").1.push(v);
        }
        let newest = parts
            .iter()
            .rev()
            .find_map(|(_, chunks)| newest_in_chunks(chunks, q).transpose())
            .transpose()?;
        // The buffer is newer than every chunk, so it wins a tie.
        let both = newest.into_iter().chain(buffered).collect();
        Ok(normalize(both)
            .into_iter()
            .rev()
            .find(|p| in_range(q, p))
            .into_iter()
            .collect())
    }

    /// Runs `q`: one row per point (raw) or per series and window (aggregate).
    pub fn query(&self, q: &Query) -> Result<Vec<Row>> {
        q.validate()?;
        let mut rows = Vec::new();
        for (series, points) in self.read_series(q)? {
            let budget = self.opts.max_fill_rows.saturating_sub(rows.len());
            for (ts, value) in query::evaluate_within(&points, q, budget)? {
                rows.push(Row {
                    series: series.key(),
                    tags: series.tags.clone(),
                    ts,
                    value,
                });
            }
        }
        Ok(rows)
    }

    /// Like [`Db::query`] then [`query::top_n`].
    pub fn top(&self, q: &Query, n: usize) -> Result<Vec<Row>> {
        Ok(query::top_n(self.query(q)?, n))
    }

    pub(crate) fn write_all(&self, points: &[Point]) -> Result<usize> {
        for batch in points.chunks(INGEST_BATCH) {
            self.write_points(batch)?;
        }
        Ok(points.len())
    }

    /// One `flows` point per flow (tags src/dst/sport/dport/proto; fields
    /// packets/bytes/duration_ns; timestamp = first packet).
    pub fn ingest_flows(&self, flows: &FlowTable) -> Result<usize> {
        self.write_all(&flow_points(flows))
    }

    /// One `traffic` point (packets/bytes) per timeline bucket.
    pub fn ingest_timeline(&self, timeline: &BTreeMap<u64, (u64, u64)>) -> Result<usize> {
        self.write_all(&timeline_points(timeline))
    }

    /// Flows and timeline of a parsed capture; returns the points written.
    pub fn ingest_capture(&self, stats: &ParseStats) -> Result<usize> {
        self.write_all(&capture_points(stats))
    }

    pub fn measurements(&self) -> Vec<String> {
        self.state.lock().index.measurements()
    }

    /// The fields of `measurement` and their types (empty if unknown).
    pub fn fields(&self, measurement: &str) -> BTreeMap<String, FieldType> {
        let st = self.state.lock();
        let fields = st.schema.get(measurement);
        fields
            .map(|m| m.iter().map(|(k, &t)| (k.clone(), t)).collect())
            .unwrap_or_default()
    }

    /// Every point of the database as line protocol, one line per series
    /// and timestamp, which holds the fields that have a value then. Writing
    /// the text to an empty database gives one with the same data. The whole
    /// database is built in memory.
    pub fn dump(&self) -> Result<String> {
        let mut points: BTreeMap<(String, i64), Point> = BTreeMap::new();
        for m in self.measurements() {
            for f in self.fields(&m).into_keys() {
                for row in self.query(&Query::new(&m, &f))? {
                    let key = (row.series.clone(), row.ts);
                    let point = points.entry(key).or_insert_with(|| {
                        let mut p = Point::new(&m).at(row.ts);
                        p.tags = row.tags.clone();
                        p
                    });
                    point.fields.insert(f.clone(), row.value);
                }
            }
        }
        let mut text = String::new();
        for p in points.values() {
            lineproto::write_line(&mut text, p, p.timestamp);
            text.push('\n');
        }
        Ok(text)
    }

    pub fn tag_values(&self, measurement: &str, key: &str) -> BTreeSet<String> {
        self.state.lock().index.tag_values(measurement, key)
    }

    pub fn stats(&self) -> DbStats {
        let st = self.state.lock();
        DbStats {
            series: st.index.len(),
            columns: st.col_types.len(),
            buffered_points: st.buffered,
            wal_records: st.wal.len(),
            flushes: st.flushes,
            compactions: self.compactions.load(Ordering::Relaxed),
        }
    }

    /// Closes the store; buffered points stay in the WAL and are replayed.
    pub fn close(self) -> Result<()> {
        Ok(self.kv.close()?)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::query::{Agg, Fill};
    use flashkv::env::{Env, FaultEnv, OsEnv};
    use std::path::PathBuf;
    use std::sync::Arc;

    pub(crate) fn tmpdir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("tsvdb-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    pub(crate) fn opts() -> DbOptions {
        let mut o = DbOptions::default();
        o.kv.background = false;
        o.kv.sync = false;
        o.flush_points = 1_000_000;
        o
    }

    pub(crate) fn cpu(host: &str, ts: i64, v: f64) -> Point {
        Point::new("cpu")
            .tag("host", host)
            .field("usage", FieldValue::Float(v))
            .at(ts)
    }

    fn values(db: &Db, q: &Query) -> Vec<(i64, FieldValue)> {
        db.query(q).unwrap().into_iter().map(|r| (r.ts, r.value)).collect()
    }

    #[test]
    fn a_dump_rebuilds_the_same_database() {
        let (a, b) = (tmpdir("dump-a"), tmpdir("dump-b"));
        let db = Db::open(&a, opts()).unwrap();
        db.write_lines(
            "cpu,host=a usage=1.5,cores=4i 10\ncpu,host=a usage=2.5 20\ncpu,host=b\\ x=y usage=9 10\n\
             mem,host=a free=7u,up=true,note=\"hi, \\\"you\\\"\" 10\n",
        )
        .unwrap();
        db.flush().unwrap();
        // Later writes (a rewrite, a new field) live in the buffer.
        db.write_lines("cpu,host=a usage=3.5 20\nmem,host=a free=8u 30\n")
            .unwrap();
        let text = db.dump().unwrap();
        assert_eq!(text.lines().count(), 5, "{text}");
        let fresh = Db::open(&b, opts()).unwrap();
        assert_eq!(fresh.write_lines(&text).unwrap(), 5);
        assert_eq!(fresh.measurements(), db.measurements());
        for m in db.measurements() {
            let fields = db.fields(&m);
            assert_eq!(fresh.fields(&m), fields);
            for f in fields.keys() {
                let q = Query::new(&m, f);
                assert_eq!(fresh.query(&q).unwrap(), db.query(&q).unwrap(), "{m}.{f}");
            }
        }
        assert_eq!(fresh.dump().unwrap(), text, "stable");
        assert_eq!(db.fields("cpu").len(), 2);
        assert!(db.fields("nothing").is_empty());
        assert_eq!(Db::open(&tmpdir("dump-c"), opts()).unwrap().dump().unwrap(), "");
        for d in [a, b, tmpdir("dump-c")] {
            let _ = std::fs::remove_dir_all(d);
        }
    }

    #[test]
    fn fill_applies_to_stored_and_buffered_points() {
        let dir = tmpdir("fill");
        let mut o = opts();
        o.max_fill_rows = 15;
        let db = Db::open(&dir, o).unwrap();
        let s = 1_000_000_000;
        db.write_points(&[cpu("a", s, 1.0), cpu("a", 4 * s, 4.0), cpu("b", 2 * s, 7.0)])
            .unwrap();
        db.flush().unwrap();
        db.write_points(&[cpu("a", 6 * s, 6.0)]).unwrap();
        let q = Query::new("cpu", "usage")
            .filter("host", "a")
            .range(0, 8 * s)
            .agg(Agg::Max)
            .every(s)
            .fill(Fill::Prev);
        let got: Vec<(i64, f64)> = db
            .query(&q)
            .unwrap()
            .into_iter()
            .map(|r| (r.ts / s, r.value.as_f64().unwrap()))
            .collect();
        // Nothing before the first point; the last one is carried to the end.
        let want = [(1, 1.0), (2, 1.0), (3, 1.0), (4, 4.0), (5, 4.0), (6, 6.0), (7, 6.0)];
        assert_eq!(got, want);
        // Each series is filled on its own.
        let both = Query::new("cpu", "usage")
            .range(0, 8 * s)
            .agg(Agg::Max)
            .every(s)
            .fill(Fill::Value(0.0));
        let rows = db.query(&both.clone().range(0, 7 * s)).unwrap();
        assert_eq!(rows.len(), 14);
        assert_eq!(rows.iter().filter(|r| r.series == "cpu,host=b").count(), 7);
        // The budget is for the whole query: 8 rows for the first series leave 7.
        let e = db.query(&both).unwrap_err().to_string();
        assert!(e.contains("filling would make 8 rows, more than the 7 allowed"), "{e}");
        // And a query that fills needs an aggregate and a window.
        assert!(db.query(&Query::new("cpu", "usage").fill(Fill::Prev)).is_err());
    }

    /// The latest point of each series, as the last row of a plain query.
    fn last_of_each_series(db: &Db, q: &Query) -> Vec<Row> {
        let mut last: Vec<Row> = Vec::new();
        for row in db.query(q).unwrap() {
            match last.last_mut() {
                Some(l) if l.series == row.series => *l = row,
                _ => last.push(row),
            }
        }
        last
    }

    #[test]
    fn latest_is_the_last_point_of_each_series() {
        let dir = tmpdir("latest");
        let mut o = opts();
        o.partition = Partitioner::new(10);
        let db = Db::open(&dir, o.clone()).unwrap();
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = move |n: u64| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (state >> 33) % n
        };
        let hosts = ["a", "b", "c"];
        let mut ranges = vec![(i64::MIN, i64::MAX)];
        for round in 0..60 {
            // A few points anywhere in ten partitions: some behind the newest, some a rewrite.
            let points: Vec<Point> = (0..next(6))
                .map(|_| cpu(hosts[next(3) as usize], next(100) as i64, next(1000) as f64))
                .collect();
            db.write_points(&points).unwrap();
            match next(4) {
                0 => db.flush().unwrap(),
                1 if round % 7 == 0 => {
                    db.flush().unwrap();
                    db.compact().unwrap();
                }
                _ => {}
            }
            let start = next(110) as i64 - 5;
            ranges.push((start, start + 1 + next(60) as i64));
            for &(start, end) in &ranges[ranges.len().saturating_sub(3)..] {
                let all = Query::new("cpu", "usage").range(start, end);
                let latest = db.query(&all.clone().latest()).unwrap();
                assert_eq!(
                    latest,
                    last_of_each_series(&db, &all),
                    "round {round}, [{start}, {end})"
                );
            }
        }
        let all = Query::new("cpu", "usage");
        let latest = db.query(&all.clone().latest()).unwrap();
        assert_eq!(latest.len(), 3, "{latest:?}");
        assert_eq!(latest, last_of_each_series(&db, &all));
        // The same from disk and the replayed log after a restart.
        db.close().unwrap();
        let db = Db::open(&dir, o).unwrap();
        assert_eq!(db.query(&all.clone().latest()).unwrap(), latest);
        for &(start, end) in &ranges {
            let all = all.clone().range(start, end);
            assert_eq!(db.query(&all.clone().latest()).unwrap(), last_of_each_series(&db, &all));
        }
        // Nothing in range, no row; and a series that has no such field has none.
        assert!(db.query(&all.clone().range(1000, 2000).latest()).unwrap().is_empty());
        assert!(db.query(&Query::new("cpu", "nope").latest()).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn latest_prefers_the_buffer_on_a_tie_and_looks_back_when_the_newest_partition_is_out_of_range() {
        let dir = tmpdir("latest-tie");
        let mut o = opts();
        o.partition = Partitioner::new(10);
        let db = Db::open(&dir, o).unwrap();
        db.write_points(&[
            cpu("a", 5, 1.0),
            cpu("a", 15, 2.0),
            cpu("a", 25, 3.0),
            cpu("a", 35, 4.0),
        ])
        .unwrap();
        db.flush().unwrap();
        let q = Query::new("cpu", "usage").latest();
        let value = |q: &Query| db.query(q).unwrap()[0].value.clone();
        assert_eq!(value(&q), FieldValue::Float(4.0));
        // The newest partition [30, 40) has a point, but it is past the end;
        // the one before it has the answer.
        assert_eq!(value(&q.clone().range(0, 30)), FieldValue::Float(3.0));
        assert_eq!(db.query(&q.clone().range(0, 30)).unwrap()[0].ts, 25);
        // Neither partition [30, 40) nor the one before it has a point in [36, 39).
        assert_eq!(db.query(&q.clone().range(36, 39)).unwrap().len(), 0);
        // A rewrite in the buffer wins the tie at ts 35; an older point does not win.
        db.write_points(&[cpu("a", 35, 9.0), cpu("a", 1, 7.0)]).unwrap();
        assert_eq!(value(&q), FieldValue::Float(9.0));
        // A newer point in the buffer wins.
        db.write_points(&[cpu("a", 36, 5.5)]).unwrap();
        let row = &db.query(&q).unwrap()[0];
        assert_eq!((row.ts, row.value.clone()), (36, FieldValue::Float(5.5)));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn write_query_flush_reopen() {
        let dir = tmpdir("basic");
        let db = Db::open(&dir, opts()).unwrap();
        db.write_points(&[cpu("a", 10, 1.0), cpu("b", 10, 5.0), cpu("a", 20, 2.0)])
            .unwrap();
        assert_eq!(
            db.write_lines("cpu,host=a usage=3 30\nmem,host=a free=7i 30\n")
                .unwrap(),
            2
        );
        let q = Query::new("cpu", "usage").filter("host", "a");
        let want = vec![
            (10, FieldValue::Float(1.0)),
            (20, FieldValue::Float(2.0)),
            (30, FieldValue::Float(3.0)),
        ];
        assert_eq!(values(&db, &q), want);
        let s = db.stats();
        assert_eq!((s.series, s.columns, s.buffered_points, s.wal_records), (3, 3, 5, 2));
        db.flush().unwrap();
        assert_eq!(values(&db, &q), want, "same answer from chunks");
        // Buffer and chunks mix; a rewrite of ts 20 wins.
        db.write_points(&[cpu("a", 20, 9.0), cpu("a", 40, 4.0)]).unwrap();
        let rows = db.query(&q.clone().range(15, 41)).unwrap();
        assert_eq!(rows[0].series, "cpu,host=a");
        assert_eq!(rows[0].tags["host"], "a");
        assert_eq!(
            rows.iter().map(|r| r.value.clone()).collect::<Vec<_>>(),
            [9.0, 3.0, 4.0].map(FieldValue::Float)
        );
        db.close().unwrap();
        // Reopen: chunks from disk plus the replayed WAL.
        let db = Db::open(&dir, opts()).unwrap();
        assert_eq!(db.stats().wal_records, 1);
        assert_eq!(values(&db, &q).len(), 4);
        assert_eq!(db.measurements(), vec!["cpu", "mem"]);
        assert_eq!(db.tag_values("cpu", "host").len(), 2);
        let mean = db.query(&Query::new("cpu", "usage").agg(Agg::Mean)).unwrap();
        assert_eq!(mean.len(), 2);
        let top = db.top(&Query::new("cpu", "usage").agg(Agg::Max), 1).unwrap();
        assert_eq!(
            (top[0].series.as_str(), top[0].value.clone()),
            ("cpu,host=a", FieldValue::Float(9.0))
        );
        assert!(db.query(&Query::new("cpu", "nope")).unwrap().is_empty());
        assert!(db.query(&Query::new("cpu", "usage").range(1, 1)).is_err());
        assert!(db
            .query(&Query::new("mem", "free").filter("host", "a").agg(Agg::Sum))
            .is_ok());
        assert!(db.query(&Query::new("cpu", "usage").agg(Agg::Sum)).is_ok());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn schema_is_enforced_atomically() {
        let dir = tmpdir("schema");
        let db = Db::open(&dir, opts()).unwrap();
        db.write_points(&[cpu("a", 1, 1.0)]).unwrap();
        let bad_type = Point::new("cpu").tag("host", "a").field("usage", FieldValue::Int(1));
        let err = db.write_points(&[cpu("a", 2, 2.0), bad_type]).unwrap_err();
        assert!(err.to_string().starts_with("schema conflict"), "{err}");
        let mixed = [
            Point::new("new").field("x", FieldValue::Int(1)),
            Point::new("new").field("x", FieldValue::Bool(true)),
        ];
        assert!(db.write_points(&mixed).is_err());
        assert!(db.write_points(&[Point::new("empty")]).is_err());
        assert_eq!(db.stats().buffered_points, 1, "nothing from the failed batches");
        assert!(db.write_lines("bad line").is_err());
        assert!(db.write_lines("cpu,host=a usage=1i 5").is_err());
        db.write_lines("log msg=\"hi\" 1").unwrap();
        assert!(db.query(&Query::new("log", "msg").agg(Agg::Sum)).is_err());
        assert!(db.top(&Query::new("log", "msg").agg(Agg::Sum), 1).is_err());
        // No timestamp: stamped with the current time.
        db.write_points(&[Point::new("now").field("v", FieldValue::Bool(true))])
            .unwrap();
        let r = db.query(&Query::new("now", "v")).unwrap();
        assert!(r[0].ts > 1_600_000_000_000_000_000);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn automatic_flush_and_partitions() {
        let dir = tmpdir("autoflush");
        let mut o = opts();
        o.flush_points = 4;
        o.partition = Partitioner::new(100);
        let db = Db::open(&dir, o).unwrap();
        let pts: Vec<Point> = (0..10).map(|i| cpu("a", i * 50, i as f64)).collect();
        db.write_points(&pts[..3]).unwrap();
        assert_eq!(db.stats().flushes, 0);
        db.write_points(&pts[3..]).unwrap();
        let s = db.stats();
        assert_eq!((s.flushes, s.buffered_points, s.wal_records), (1, 0, 0));
        let q = Query::new("cpu", "usage").range(100, 300);
        assert_eq!(
            values(&db, &q).iter().map(|v| v.0).collect::<Vec<_>>(),
            vec![100, 150, 200, 250]
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn ingests_a_capture() {
        let dir = tmpdir("ingest");
        let db = Db::open(&dir, opts()).unwrap();
        let mut pcap = Vec::new();
        let synth = pcapfast::synth::SynthOptions {
            packets: 500,
            flows: 7,
            ..Default::default()
        };
        pcapfast::synth::generate(&synth, &mut pcap).unwrap();
        let stats = pcapfast::parse_bytes(&pcap, &pcapfast::ParseOptions::default()).unwrap();
        let n = db.ingest_capture(&stats).unwrap();
        assert_eq!(n, stats.flows.len() + stats.timeline.len());
        let points = capture_points(&stats);
        assert_eq!(points.len(), n);
        assert_eq!(
            points.iter().filter(|p| p.measurement == "flows").count(),
            stats.flows.len()
        );
        assert_eq!(db.ingest_timeline(&stats.timeline).unwrap(), stats.timeline.len());
        let top = query::top_flows(&db, i64::MIN, i64::MAX, 3).unwrap();
        assert_eq!(top.len(), 3.min(stats.flows.len()));
        let heaviest = stats.flows.top_n(1)[0].1.bytes as f64;
        assert_eq!(top[0].value, FieldValue::Float(heaviest));
        let total = db.query(&Query::new("traffic", "packets").agg(Agg::Sum)).unwrap();
        assert_eq!(
            total[0].value,
            FieldValue::Float(stats.packets as f64),
            "re-ingest overwrites"
        );
        // Unknown IP protocols are tagged with their number.
        let mut flows = FlowTable::new();
        let key = FlowKey {
            src: "10.0.0.1".parse().unwrap(),
            dst: "10.0.0.2".parse().unwrap(),
            src_port: 0,
            dst_port: 0,
            proto: 99,
        };
        flows.record(key, 5, 60);
        db.ingest_flows(&flows).unwrap();
        assert!(db.tag_values("flows", "proto").contains("99"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn raw_put(dir: &Path, k: &[u8], v: &[u8]) {
        let kv = flashkv::Db::open(dir, opts().kv).unwrap();
        kv.put(k, v).unwrap();
        kv.close().unwrap();
    }

    #[test]
    fn corrupt_entries_fail_open() {
        let dir = tmpdir("corrupt");
        let db = Db::open(&dir, opts()).unwrap();
        db.write_points(&[cpu("a", 1, 1.0)]).unwrap();
        db.close().unwrap();
        raw_put(&dir, b"Gstray", b"ignored");
        assert!(Db::open(&dir, opts()).is_ok());
        let cases: [(&[u8], &[u8]); 7] = [
            (b"F\x05cpu", &[0]),
            (b"F\x03cpuusage", &[9]),
            (b"C\x01", &[0; 9]),
            (b"C\x00\x00\x00\x00\x00\x00\x00\x00f", &[0; 3]),
            (b"Mseq", &[1]),
            (b"S\x00", &[1]),
            (b"W\xff", b"not line protocol"),
        ];
        for (k, v) in cases {
            let dir2 = tmpdir("corrupt2");
            let kv = flashkv::Db::open(&dir2, opts().kv).unwrap();
            kv.put(k, v).unwrap();
            kv.close().unwrap();
            assert!(Db::open(&dir2, opts()).is_err(), "{k:?}");
            std::fs::remove_dir_all(&dir2).unwrap();
        }
        // A corrupt chunk fails the query that reads it.
        raw_put(&dir, &data_key(0, 0, 999), b"\x09");
        let db = Db::open(&dir, opts()).unwrap();
        assert!(db.query(&Query::new("cpu", "usage")).is_err());
        assert!(db.query(&Query::new("cpu", "usage").latest()).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The n-th I/O fails, then the power goes out: every acknowledged point
    /// must be readable after recovery, and nothing else.
    #[test]
    fn fault_injection_then_power_loss_keeps_acknowledged_points() {
        let script = |env: Arc<dyn Env>, dir: &Path, acked: &mut Vec<i64>, q: &Query| -> Result<()> {
            let mut o = opts();
            o.kv.env = env;
            o.kv.sync = true;
            o.flush_points = 3;
            o.compact_min_chunks = 2;
            let db = Db::open(dir, o.clone())?;
            for ts in 0..4 {
                db.write_points(&[cpu("a", ts, ts as f64)])?;
                acked.push(ts);
            }
            db.flush()?;
            db.kv.flush()?;
            db.compact()?;
            db.write_points(&[cpu("a", 9, 9.0)])?;
            acked.push(9);
            db.kv.flush()?;
            drop(db);
            let db = Db::open(dir, o)?;
            let want = if q.latest { 1 } else { acked.len() };
            assert_eq!(db.query(q)?.len(), want);
            Ok(())
        };
        // Reading everything, and reading only the newest point, both from disk.
        let all = Query::new("cpu", "usage");
        for q in [all.clone(), all.clone().latest()] {
            for n in 0.. {
                let dir = tmpdir("faults");
                let fault = FaultEnv::new(Arc::new(OsEnv));
                fault.fail_after(n);
                let mut acked = Vec::new();
                let done = script(Arc::new(fault.clone()), &dir, &mut acked, &q).is_ok();
                fault.heal();
                fault.crash().unwrap();
                let db = Db::open(&dir, opts()).unwrap();
                let got: Vec<i64> = values(&db, &all).into_iter().map(|v| v.0).collect();
                assert_eq!(got, acked, "fault at op {n}");
                drop(db);
                std::fs::remove_dir_all(&dir).unwrap();
                if done {
                    break;
                }
            }
        }
    }

    #[test]
    fn poisoned_db_refuses_work() {
        let dir = tmpdir("poison");
        let fault = FaultEnv::new(Arc::new(OsEnv));
        let mut o = opts();
        o.kv.env = Arc::new(fault.clone());
        let db = Db::open(&dir, o).unwrap();
        fault.fail_after(0);
        assert!(db.write_points(&[cpu("a", 1, 1.0)]).is_err());
        fault.heal();
        assert!(db.write_points(&[cpu("a", 2, 1.0)]).is_err());
        assert!(db.flush().is_err());
        assert!(db.query(&Query::new("cpu", "usage")).is_err());
        assert!(db.compact().is_err());
        let mut flows = FlowTable::new();
        let key = FlowKey {
            src: "10.0.0.1".parse().unwrap(),
            dst: "10.0.0.2".parse().unwrap(),
            src_port: 1,
            dst_port: 2,
            proto: 6,
        };
        flows.record(key, 5, 60);
        assert!(db.ingest_flows(&flows).is_err());
        assert!(query::top_flows(&db, 0, 10, 1).is_err());
        assert!(db.close().is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
