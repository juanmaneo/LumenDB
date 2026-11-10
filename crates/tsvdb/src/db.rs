//! The database: chunks, their statistics and the catalog live in flashkv
//! (crash-safe, no mmap); the write-ahead log is a file of its own.
//!
//! Write path (InfluxDB v3 style WAL + write buffer):
//! 1. points are validated against the schema (a field keeps its first type)
//!    and turned into typed columns (`batch`; plain lines of known
//!    series go straight there, see `fast`);
//! 2. new series / schema / column entries are stored in flashkv, then the
//!    columns are appended to the log as one CRC-framed record (fsynced with
//!    `sync`) — when the write returns `Ok` the points survive a power loss;
//! 3. the columns join the in-memory write buffer.
//!
//! When the buffer is large enough it is flushed: one batch writes a
//! compressed [`Chunk`] and its [`ChunkStats`] per column and partition, and
//! names the new log that writes go to from then on; the old logs are
//! removed. At open the index is rebuilt and the live logs replayed (a torn
//! tail is dropped, damage is an error).
//!
//! Reads take a flashkv snapshot, the statistics of the chunks and a copy of
//! the matching buffered points under a short lock, then work without any
//! lock; compaction ([`crate::compact`]) rewrites chunks with atomic batches,
//! so it never blocks nor disturbs readers.
//!
//! Any storage failure poisons the database (like LevelDB's background
//! error): later calls fail until it is reopened, which recovers exactly the
//! acknowledged writes.
//!
//! Key space: `C`+sid+field → column, `D`+col+bucket+seq → chunk,
//! `E`+col+bucket+seq → statistics of that chunk (see [`ChunkStats`]),
//! `F`+measurement+field → type, `Mseq` → sequence, `S`+series key → series,
//! `V` → format of the database, `Z` → the first live log.

use crate::agg::{self, Aggregator, Slice};
use crate::batch::{self, Batch, ColumnPoints};
use crate::chunk::{normalize, Chunk, ChunkStats};
use crate::error::{Error, Result};
use crate::fast;
use crate::lineproto::{self, FieldType, FieldValue, Point};
use crate::par;
use crate::partition::{decode_bucket, encode_bucket, Partitioner};
use crate::query::{self, Query, Row};
use crate::tags::{series_key, Series, SeriesIndex};
use crate::time::now_ns;
use flashkv::codec::Decoder;
use flashkv::log::{self, LogWriter};
use flashkv::varint::put_len_prefixed;
use flashkv::WriteBatch;
use parking_lot::{Mutex, RwLock};
use pcapfast::flow::proto_name;
use pcapfast::{FlowKey, FlowStats, FlowTable, ParseStats};
use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// The size of the pieces that a large write is parsed in, on several
/// threads: parsing a piece is much more than starting a thread.
const SEGMENT_BYTES: usize = 256 << 10;

/// The most points that wait in memory for [`DbOptions::chunk_points`].
pub const MAX_BUFFERED_POINTS: usize = 8 << 20;

/// Points per `write_points` call when ingesting captures.
pub const INGEST_BATCH: usize = 50_000;
const META_SEQ: &[u8] = b"Mseq";
/// Where the format of the database is: 2 had the statistics of the chunks;
/// 3 has records of the log that are binary, and holds a column at a time.
const FORMAT_KEY: &[u8] = b"V";
/// Where the first log that is to be read is: older ones are of points that
/// are in chunks (it is one of the things a flush stores).
const WAL_KEY: &[u8] = b"Z";
const FORMAT: u8 = 3;

#[derive(Clone)]
pub struct DbOptions {
    pub kv: flashkv::DbOptions,
    pub partition: Partitioner,
    /// Buffered points that trigger a flush to chunks...
    pub flush_points: usize,
    /// ...but not before the columns that have points buffered hold this
    /// many on average (at most [`MAX_BUFFERED_POINTS`] in all), so that the
    /// chunks are not tiny: a flush writes a chunk per column and partition,
    /// and every chunk is something to look at in each query and to merge.
    /// 0 for a flush as soon as `flush_points` are buffered.
    pub chunk_points: usize,
    /// Chunks of one column/partition that make compaction merge them.
    pub compact_min_chunks: usize,
    /// The most rows a query may make by filling empty windows.
    pub max_fill_rows: usize,
    /// The most threads to use for a query (to read the columns of its
    /// series), for parsing a large write, and for building the chunks of a
    /// flush; 0 for as many as there are cores.
    pub threads: usize,
}

impl Default for DbOptions {
    fn default() -> Self {
        // What the store holds is chunks, which are compressed already, and a
        // block that is compressed again is only slower to write: and a flush
        // of the buffer is several megabytes, so a memtable that is larger
        // than the default means the writer waits for the tables less often.
        let kv = flashkv::DbOptions {
            write_buffer_size: 32 << 20,
            table: flashkv::sstable::TableOptions {
                compress: false,
                ..Default::default()
            },
            ..Default::default()
        };
        DbOptions {
            kv,
            partition: Partitioner::hourly(),
            flush_points: 100_000,
            chunk_points: 512,
            compact_min_chunks: 4,
            max_fill_rows: query::MAX_FILL_ROWS,
            threads: 0,
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
    /// Writes of lines that were turned into columns straight away.
    pub fast_writes: u64,
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
    buffer: Batch,
    buffered: usize,
    /// The log that writes go to until the next flush, which is a file of the
    /// directory of the database (not a key of the store: the store would
    /// write them again, in a table, and again when merging tables, to
    /// delete them at the flush).
    wal: Option<LogWriter>,
    /// Which one it is, and the older ones (their points are in the buffer
    /// still) that are left.
    wal_gen: u64,
    wal_older: Vec<u64>,
    wal_records: usize,
    seq: u64,
    poisoned: Option<String>,
    flushes: u64,
    /// The statistics of the chunks of the columns that queries have read,
    /// by column, then (partition, sequence number). Whoever writes or
    /// deletes a chunk does so under the lock of the state, and updates this.
    pub(crate) catalog: HashMap<u64, Arc<Catalog>>,
}

/// The statistics of the chunks of one column, by (partition, sequence number).
pub(crate) type Catalog = BTreeMap<(i64, u64), ChunkStats>;

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

/// The column, partition and sequence number that a `D` or `E` key is of.
pub(crate) fn key_parts(key: &[u8]) -> Option<(u64, i64, u64)> {
    let key: &[u8; 25] = key.try_into().ok()?;
    let word = |at: usize| <[u8; 8]>::try_from(&key[at..at + 8]).expect("8 bytes");
    Some((
        u64::from_be_bytes(word(1)),
        decode_bucket(word(9)),
        u64::from_be_bytes(word(17)),
    ))
}

/// The key of the statistics of the chunk that `data_key` is the key of.
pub(crate) fn stats_key(data_key: &[u8]) -> Vec<u8> {
    let mut key = data_key.to_vec();
    key[0] = b'E';
    key
}

fn wal_name(gen: u64) -> String {
    format!("{gen:016x}.tswal")
}

fn wal_generation(name: &str) -> Option<u64> {
    u64::from_str_radix(name.strip_suffix(".tswal")?, 16).ok()
}

/// Timestamped values of one column.
type Points = Vec<(i64, FieldValue)>;

/// Appends the rows of a series, which share its key and tags.
fn push_rows(rows: &mut Vec<Row>, series: &Series, points: Points) {
    rows.extend(points.into_iter().map(|(ts, value)| Row {
        series: series.key.clone(),
        tags: series.tags.clone(),
        ts,
        value,
    }));
}

/// A chunk that a query may read: what is known of it, and where it is.
struct Piece {
    stats: ChunkStats,
    source: Source,
}

enum Source {
    /// The partition and the sequence number of the chunk, which is of a
    /// column that is known.
    Stored(i64, u64),
    /// The write buffer, as a chunk.
    Buffered(Chunk),
}

/// A column that a query reads, and the points of it that are only buffered.
struct Target {
    series: Arc<Series>,
    col: u64,
    buffered: Option<ColumnPoints>,
    /// The statistics of the stored chunks of the column, at the time of the
    /// query; those of the partitions in the range are the ones to look at.
    stored: Arc<Catalog>,
}

/// The newest point of a chunk in the range of `q`.
fn newest_in(chunk: &Chunk, q: &Query) -> Option<(i64, FieldValue)> {
    let ts = chunk.timestamps();
    // (A chunk that is looked at has a timestamp before the end.)
    let last = ts.partition_point(|&t| t < q.end).wrapping_sub(1);
    ts.get(last)
        .filter(|&&t| t >= q.start)
        .map(|&t| (t, chunk.column().get(last)))
}

fn in_range(q: &Query, p: &(i64, FieldValue)) -> bool {
    (p.0 >= q.start) & (p.0 < q.end)
}

/// Length of the `D`+col+bucket prefix shared by the chunks of a partition.
pub(crate) const PARTITION_PREFIX: usize = 17;

impl State {
    /// The statistics of the chunks of column `col`, read from the store
    /// the first time they are wanted.
    fn stats_of(&mut self, kv: &flashkv::Db, col: u64) -> Result<Arc<Catalog>> {
        match self.catalog.entry(col) {
            Entry::Occupied(known) => Ok(known.get().clone()),
            Entry::Vacant(unknown) => {
                let mut stats = Catalog::new();
                for (key, value) in kv.scan_prefix(&[&b"E"[..], &col.to_be_bytes()].concat())? {
                    let (_, bucket, seq) = key_parts(&key).ok_or_else(|| corrupt("chunk statistics key"))?;
                    stats.insert((bucket, seq), ChunkStats::decode(&value)?);
                }
                Ok(unknown.insert(Arc::new(stats)).clone())
            }
        }
    }

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
    /// memory and in `batch`) and returns the points by column.
    fn stage(&mut self, points: &[Point], now: i64, batch: &mut WriteBatch) -> Batch {
        let mut staged = Batch::default();
        for p in points {
            let ts = p.timestamp.unwrap_or(now);
            let (sid, new) = self.index.insert(&p.measurement, &p.tags);
            if new {
                let s = self.index.series(sid).expect("just inserted");
                batch.put(&series_kv_key(s.key()), &s.encode());
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
                let points = staged.entry(col).or_insert_with(|| ColumnPoints::new(ty));
                points
                    .push(ts, v.clone())
                    .expect("the points of a column are of its type");
            }
        }
        staged
    }

    /// Adds the points of a write to the buffer; their columns are known and
    /// they have the types of the columns. `room` is the number of points
    /// that a column of the buffer is to have room for, when it is made.
    fn apply(&mut self, staged: Batch, room: usize) {
        self.buffered += batch::points_in(&staged);
        for (col, points) in staged {
            match self.buffer.entry(col) {
                std::collections::hash_map::Entry::Occupied(mut held) => {
                    held.get_mut()
                        .append(points)
                        .expect("the points of a column are of its type");
                }
                std::collections::hash_map::Entry::Vacant(free) => {
                    let room = room.max(points.len());
                    let mut buffered = ColumnPoints::with_capacity(points.values.field_type(), room);
                    buffered.append(points).expect("the points of a column are of its type");
                    free.insert(buffered);
                }
            }
        }
    }

    /// Puts a record of the log back in the buffer.
    fn replay(&mut self, record: &[u8]) -> Result<()> {
        let staged = batch::decode(record)?;
        let known = |(col, points): (&u64, &ColumnPoints)| self.col_types.get(col) == Some(&points.values.field_type());
        if !staged.iter().all(known) {
            return Err(Error::Corrupt(
                "record of the log: a column that is not there or not of that type".into(),
            ));
        }
        self.apply(staged, 0);
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
    dir: PathBuf,
    pub(crate) kv: flashkv::Db,
    pub(crate) opts: DbOptions,
    pub(crate) state: Mutex<State>,
    pub(crate) compact_lock: Mutex<()>,
    pub(crate) compactions: AtomicU64,
    /// The series that lines can be turned into columns for without making
    /// points of them (see [`crate::fast`]). Series and columns are never
    /// removed or changed, so what is in here stays true.
    fast: RwLock<fast::Cache>,
    fast_writes: AtomicU64,
}

impl Db {
    pub fn open(dir: &Path, opts: DbOptions) -> Result<Db> {
        let kv = flashkv::Db::open(dir, opts.kv.clone())?;
        let older = || Error::Corrupt("the database was made by an older version, whose format is not read".into());
        match kv.get(FORMAT_KEY)?.as_deref() {
            Some([FORMAT]) => {}
            Some([older_format]) if *older_format < FORMAT => return Err(older()),
            Some(_) => return Err(corrupt("format")),
            None if kv.iter(b"D", Some(b"E")).next().is_some() => return Err(older()),
            None => kv.put(FORMAT_KEY, &[FORMAT])?,
        }
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
                _ => {}
            }
        }
        let env = opts.kv.env.clone();
        let live_from = match kv.get(WAL_KEY)? {
            Some(v) => {
                let mut d = Decoder::new(&v);
                let first = d.u64();
                d.finish("first log")?;
                first
            }
            None => 0,
        };
        let mut gens: Vec<u64> = env.list(dir)?.iter().filter_map(|n| wal_generation(n)).collect();
        gens.sort_unstable();
        // The logs of points that are in chunks, which a crash left, go.
        for gen in gens.iter().filter(|&&g| g < live_from) {
            let _ = env.remove(&dir.join(wal_name(*gen)));
        }
        gens.retain(|&g| g >= live_from);
        for gen in &gens {
            let name = wal_name(*gen);
            let data = env.read_all(&dir.join(&name))?;
            for record in log::parse_checked(&data, &name)? {
                st.replay(record)?;
                st.wal_records += 1;
            }
        }
        // Writes go to a log of their own: no record is added after a torn one.
        st.wal_gen = gens.last().map_or(live_from, |last| last + 1);
        st.wal_older = gens;
        let db = Db {
            dir: dir.to_path_buf(),
            kv,
            opts,
            state: Mutex::default(),
            compact_lock: Mutex::new(()),
            compactions: AtomicU64::new(0),
            fast: RwLock::default(),
            fast_writes: AtomicU64::new(0),
        };
        let wal = db.start_wal(st.wal_gen)?;
        st.wal = Some(wal);
        *db.state.lock() = st;
        Ok(db)
    }

    /// A new log, which is there after a crash.
    fn start_wal(&self, gen: u64) -> flashkv::Result<LogWriter> {
        let env = &self.opts.kv.env;
        let file = env.create(&self.dir.join(wal_name(gen)))?;
        if self.opts.kv.sync {
            env.sync_dir(&self.dir)?;
        }
        Ok(LogWriter::new(file))
    }

    /// Writes `points` durably (see module docs). Points without a timestamp
    /// get the current time. All or nothing.
    pub fn write_points(&self, points: &[Point]) -> Result<()> {
        let mut guard = self.state.lock();
        let st = &mut *guard;
        st.healthy()?;
        check_points(&st.schema, points)?;
        let mut batch = WriteBatch::new();
        let staged = st.stage(points, now_ns(), &mut batch);
        let record = batch::encode(&staged);
        self.write_staged(st, vec![staged], &record, batch)
    }

    /// Makes `staged`, whose series and columns are known and whose points
    /// are of the types of the columns, durable and puts it in the buffer, a
    /// batch after the other.
    /// `batch` has what is to be stored before the record of the log: the new
    /// series, fields and columns.
    fn write_staged(&self, st: &mut State, staged: Vec<Batch>, record: &[u8], batch: WriteBatch) -> Result<()> {
        // What the points are of (series, fields, columns) first, so that no
        // record of the log is of something that is not there after a crash.
        if !batch.is_empty() {
            self.commit(st, &batch)?;
        }
        let logged = st.wal.as_mut().expect("the log is open").add(record, self.opts.kv.sync);
        logged.map_err(|e| self.poison(st, e))?;
        st.wal_records += 1;
        let room = self.opts.chunk_points;
        staged.into_iter().for_each(|batch| st.apply(batch, room));
        let wanted = self.opts.chunk_points.saturating_mul(st.buffer.len());
        if st.buffered >= self.opts.flush_points.max(wanted.min(MAX_BUFFERED_POINTS)) {
            // The points are already durable: a failed flush only poisons
            // the database (reported by the next call), the write stands.
            let _ = self.flush_locked(st);
        }
        Ok(())
    }

    /// Parses line protocol and writes it; returns the number of points. A
    /// large text is parsed in pieces, on several threads.
    pub fn write_lines(&self, text: &str) -> Result<usize> {
        let now = now_ns();
        let parsed = {
            let cache = self.fast.read();
            let pieces = fast::segments(text, SEGMENT_BYTES);
            let parse = |piece: &str| {
                let (staged, lines) = fast::parse(piece, &cache, now)?;
                Some((batch::encode_body(&staged), staged, lines))
            };
            let threads = par::threads_for(self.opts.threads);
            par::map(threads, pieces, parse).into_iter().collect::<Option<Vec<_>>>()
        };
        let lines = parsed.iter().flatten().map(|p| p.2).sum::<usize>();
        if let Some(parsed) = parsed.filter(|_| lines > 0) {
            let (bodies, staged): (Vec<_>, Vec<_>) = parsed.into_iter().map(|(body, staged, _)| (body, staged)).unzip();
            let record = batch::record(&bodies);
            let mut guard = self.state.lock();
            guard.healthy()?;
            self.write_staged(&mut guard, staged, &record, WriteBatch::new())?;
            self.fast_writes.fetch_add(1, Ordering::Relaxed);
            return Ok(lines);
        }
        let points = lineproto::parse(text)?;
        self.write_points(&points)?;
        self.learn(text);
        Ok(points.len())
    }

    /// Remembers the series of the plain lines of `text`, which has just been
    /// written, so that the next lines of them can go the fast way.
    fn learn(&self, text: &str) {
        let st = self.state.lock();
        let mut cache = self.fast.write();
        for line in text.lines() {
            let Some((series, names)) = fast::plain_fields(line) else {
                continue;
            };
            if (cache.len() >= fast::MAX_SERIES) | cache.contains_key(series) {
                continue;
            }
            let Ok(point) = lineproto::parse_line(line) else {
                continue;
            };
            let Some(cols) = st
                .index
                .get(&series_key(&point.measurement, &point.tags))
                .and_then(|sid| st.cols.get(&sid))
            else {
                continue;
            };
            let slots: Vec<(Box<str>, u64, FieldType)> = names
                .iter()
                .filter_map(|name| {
                    let name: Box<str> = (*name).into();
                    cols.get(&*name).map(|&col| (name, col, st.col_types[&col]))
                })
                .collect();
            // Strings are not for the fast way; nor is a name that is twice.
            let distinct = names.iter().collect::<std::collections::HashSet<_>>().len() == names.len();
            let fine = (slots.len() == names.len()) & distinct & slots.iter().all(|f| f.2 != FieldType::Str);
            cache.extend(fine.then(|| (series.into(), fast::Fields(slots))));
        }
    }

    fn commit(&self, st: &mut State, batch: &WriteBatch) -> Result<()> {
        self.kv.write(batch).map_err(|e| self.poison(st, e))
    }

    /// Every later call fails until the database is opened again, which
    /// recovers what was acknowledged.
    fn poison(&self, st: &mut State, e: flashkv::Error) -> Error {
        st.poisoned = Some(e.to_string());
        Error::Kv(e)
    }

    /// Moves the write buffer into chunks.
    pub fn flush(&self) -> Result<()> {
        let mut guard = self.state.lock();
        guard.healthy()?;
        self.flush_locked(&mut guard)
    }

    fn flush_locked(&self, st: &mut State) -> Result<()> {
        let mut batch = WriteBatch::new();
        let mut written = Vec::new();
        let partition = self.opts.partition;
        let columns: Vec<(u64, ColumnPoints)> = std::mem::take(&mut st.buffer).into_iter().collect();
        // The chunks of the columns are made on several threads.
        let build = |(col, points): (u64, ColumnPoints)| {
            let chunk = Chunk::from_columns(points.ts, points.values);
            let runs = partition.runs(chunk.timestamps());
            let parts: Vec<(i64, Chunk)> = match runs.as_slice() {
                [(bucket, _)] => vec![(*bucket, chunk)],
                _ => runs
                    .into_iter()
                    .map(|(b, r)| (b, chunk.slice(r.start, r.end)))
                    .collect(),
            };
            let encoded: Vec<_> = parts
                .into_iter()
                .map(|(bucket, part)| {
                    let stats = part.stats().expect("a part has points");
                    (col, bucket, part.encode(), stats)
                })
                .collect();
            encoded
        };
        let threads = par::threads_for(self.opts.threads);
        for (col, bucket, chunk, stats) in par::map(threads, columns, build).into_iter().flatten() {
            st.seq += 1;
            let key = data_key(col, bucket, st.seq);
            batch.put(&key, &chunk);
            batch.put(&stats_key(&key), &stats.encode());
            written.push((col, (bucket, st.seq), stats));
        }
        // From now on, writes go to a new log: the points of the old ones are
        // in these chunks, and the first log to read is the new one.
        let next = st.wal_gen + 1;
        let wal = self.start_wal(next).map_err(|e| self.poison(st, e))?;
        batch.put(WAL_KEY, &next.to_le_bytes());
        batch.put(META_SEQ, &st.seq.to_le_bytes());
        self.commit(st, &batch)?;
        st.wal = Some(wal);
        let older = std::mem::take(&mut st.wal_older);
        for gen in older.into_iter().chain([st.wal_gen]) {
            let _ = self.opts.kv.env.remove(&self.dir.join(wal_name(gen)));
        }
        st.wal_gen = next;
        st.wal_records = 0;
        for (col, key, stats) in written {
            if let Some(catalog) = st.catalog.get_mut(&col) {
                Arc::make_mut(catalog).insert(key, stats);
            }
        }
        st.buffered = 0;
        st.flushes += 1;
        Ok(())
    }

    /// The columns that `q` reads, with a flashkv snapshot that goes with the
    /// buffered points and the statistics copied here (taken together, under
    /// the lock: whoever changes the chunks does it under the lock too).
    fn targets(&self, q: &Query) -> Result<(Vec<Target>, flashkv::Snapshot)> {
        let mut guard = self.state.lock();
        let st = &mut *guard;
        st.healthy()?;
        let mut targets = Vec::new();
        for sid in st.index.lookup(&q.measurement, &q.filters) {
            let Some(&col) = st.cols[&sid].get(&q.field) else {
                continue;
            };
            let stored = st.stats_of(&self.kv, col)?;
            targets.push(Target {
                series: st.index.series(sid).expect("indexed").clone(),
                col,
                buffered: st.buffer.get(&col).cloned(),
                stored,
            });
        }
        Ok((targets, self.kv.snapshot()))
    }

    /// The chunks of one column that may hold points in the range of `q`,
    /// with their statistics, the buffered points last, as one more chunk.
    fn pieces(&self, target: Target, q: &Query) -> Vec<Piece> {
        let buckets = self.opts.partition.buckets(q.start, q.end);
        let mut pieces: Vec<Piece> = target
            .stored
            .range((*buckets.start(), 0)..=(*buckets.end(), u64::MAX))
            .filter(|(_, stats)| (stats.max_ts >= q.start) & (stats.min_ts < q.end))
            .map(|(&(bucket, seq), stats)| Piece {
                stats: stats.clone(),
                source: Source::Stored(bucket, seq),
            })
            .collect();
        let in_range = |stats: &ChunkStats| (stats.max_ts >= q.start) & (stats.min_ts < q.end);
        if let Some(buffered) = target.buffered {
            let buffered = Chunk::from_columns(buffered.ts, buffered.values);
            if let Some(stats) = buffered.stats().filter(in_range) {
                pieces.push(Piece {
                    stats,
                    source: Source::Buffered(buffered),
                });
            }
        }
        pieces
    }

    fn load(&self, snapshot: &flashkv::Snapshot, col: u64, piece: Piece) -> Result<Chunk> {
        match piece.source {
            Source::Buffered(chunk) => Ok(chunk),
            Source::Stored(bucket, seq) => self.chunk_at(snapshot, &data_key(col, bucket, seq)),
        }
    }

    /// The chunk stored under `key`, which is there if its statistics are.
    pub(crate) fn chunk_at(&self, snapshot: &flashkv::Snapshot, key: &[u8]) -> Result<Chunk> {
        let value = self.kv.get_at(key, snapshot)?;
        Chunk::decode(&value.ok_or_else(|| corrupt("chunk (it has statistics)"))?)
    }

    /// The points of the pieces in the range of `q`, sorted, the last write
    /// of a timestamp winning.
    fn points_of(&self, snapshot: &flashkv::Snapshot, col: u64, pieces: Vec<Piece>, q: &Query) -> Result<Points> {
        let mut points = Vec::new();
        for piece in pieces {
            points.extend(self.load(snapshot, col, piece)?.points());
        }
        Ok(normalize(points).into_iter().filter(|p| in_range(q, p)).collect())
    }

    /// The points of one column in `[q.start, q.end)` that `q` asks for, or
    /// its aggregate windows: the rows, as (timestamp, value).
    ///
    /// When no two chunks have a timestamp in common, nothing has to be
    /// sorted or dropped, and an aggregate or the latest point is made from
    /// the statistics of the chunks that are in the range and in one window,
    /// and from the points of the others only.
    fn evaluate_target(
        &self,
        snapshot: &flashkv::Snapshot,
        target: Target,
        q: &Query,
        budget: usize,
    ) -> Result<Vec<(i64, FieldValue)>> {
        if q.latest {
            return self.newest(snapshot, target, q);
        }
        let col = target.col;
        let mut pieces = self.pieces(target, q);
        // Chunks come in the order they were written, which is time order
        // when the points were written in time order.
        let in_order = pieces.windows(2).all(|w| w[0].stats.max_ts < w[1].stats.min_ts);
        let disjoint = in_order || agg::disjoint(pieces.iter().map(|p| (p.stats.min_ts, p.stats.max_ts)));
        let numeric = pieces.iter().all(|p| p.stats.numbers.is_some());
        if let Some(agg) = q.agg.filter(|_| disjoint & numeric) {
            pieces.sort_by_key(|p| p.stats.min_ts);
            let mut aggregator = Aggregator::new(q, agg);
            for piece in pieces {
                if aggregator.covers(&piece.stats) {
                    aggregator.push_stats(&piece.stats);
                    continue;
                }
                let chunk = self.load(snapshot, col, piece)?;
                let values = Slice::of(chunk.column()).expect("the chunks are of numbers");
                aggregator.push(chunk.timestamps(), values);
            }
            return query::fill_windows(aggregator.finish(), q, budget);
        }
        // The pieces are in the order they were written, which decides who
        // wins a timestamp.
        let points = self.points_of(snapshot, col, pieces, q)?;
        query::evaluate_within(&points, q, budget)
    }

    /// The newest point of a column in the range of `q`, as a list of at most
    /// one point. The chunks of a partition hold only timestamps of it, so
    /// the newest point is in the newest partition that has one in the range,
    /// and nothing older is looked at; and a chunk that lies in the range
    /// has its newest point in its statistics. A chunk of the same partition
    /// that was written later wins a tie, and the buffer wins over all.
    fn newest(&self, snapshot: &flashkv::Snapshot, target: Target, q: &Query) -> Result<Points> {
        let buckets = self.opts.partition.buckets(q.start, q.end);
        let chunks = target.stored.range((*buckets.start(), 0)..=(*buckets.end(), u64::MAX));
        let mut stored: Option<(i64, FieldValue)> = None;
        let mut bucket = None;
        for (&(b, seq), stats) in chunks.rev() {
            if stored.is_some() & (bucket != Some(b)) {
                break;
            }
            bucket = Some(b);
            let inside = (stats.min_ts >= q.start) & (stats.max_ts < q.end);
            let candidate = match stats.numbers.filter(|_| inside) {
                Some(n) => Some((stats.max_ts, n.last.value())),
                None if (stats.max_ts < q.start) | (stats.min_ts >= q.end) => None,
                None => newest_in(&self.chunk_at(snapshot, &data_key(target.col, b, seq))?, q),
            };
            // Later chunks come first: a point of the same timestamp is theirs.
            stored = match (stored, candidate) {
                (Some(old), Some(new)) if new.0 > old.0 => Some(new),
                (None, new) => new,
                (old, _) => old,
            };
        }
        // Of equal timestamps, the point that was written last is the newest.
        let buffered = target.buffered.and_then(|b| {
            let (i, &t) = (b.ts.iter().enumerate())
                .filter(|&(_, &t)| (t >= q.start) & (t < q.end))
                .max_by_key(|&(i, &t)| (t, i))?;
            Some((t, b.values.get(i)))
        });
        let newest = match (stored, buffered) {
            (Some(old), Some(new)) if new.0 < old.0 => Some(old),
            (old, new) => new.or(old),
        };
        Ok(newest.into_iter().collect())
    }

    /// Runs `q`: one row per point (raw) or per series and window (aggregate).
    /// The columns of the series are read on several threads when that pays,
    /// unless there is a fill, whose rows are counted over all the series.
    pub fn query(&self, q: &Query) -> Result<Vec<Row>> {
        q.validate()?;
        let (targets, snapshot) = self.targets(q)?;
        let mut rows = Vec::new();
        let max = self.opts.max_fill_rows;
        let evaluate = |target: Target, budget: usize| {
            let series = target.series.clone();
            self.evaluate_target(&snapshot, target, q, budget)
                .map(|points| (series, points))
        };
        // With a fill, a series has what the others left of the budget; so
        // the series go one at a time.
        if q.fill.is_some() {
            for target in targets {
                let (series, points) = evaluate(target, max.saturating_sub(rows.len()))?;
                push_rows(&mut rows, &series, points);
            }
        } else {
            let threads = par::threads_for(self.opts.threads);
            for outcome in par::map(threads, targets, |t| evaluate(t, max)) {
                let (series, points) = outcome?;
                push_rows(&mut rows, &series, points);
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

    /// The ids of the columns of the series of `measurement`, or of every
    /// series without one.
    pub(crate) fn columns(&self, measurement: Option<&str>) -> Vec<u64> {
        let st = self.state.lock();
        let series = match measurement {
            Some(m) => st.index.lookup(m, &[]),
            None => st.cols.keys().copied().collect(),
        };
        series.iter().flat_map(|sid| st.cols[sid].values().copied()).collect()
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
                    let key = (row.series.to_string(), row.ts);
                    let point = points.entry(key).or_insert_with(|| {
                        let mut p = Point::new(&m).at(row.ts);
                        p.tags = (*row.tags).clone();
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
            wal_records: st.wal_records,
            flushes: st.flushes,
            compactions: self.compactions.load(Ordering::Relaxed),
            fast_writes: self.fast_writes.load(Ordering::Relaxed),
        }
    }

    /// Closes the store; buffered points stay in the WAL and are replayed.
    pub fn close(self) -> Result<()> {
        self.state.lock().wal.as_mut().expect("the log is open").sync()?;
        Ok(self.kv.close()?)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::chunk::{Num, Numbers};
    use crate::query::{Agg, Align, Fill};
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
        o.chunk_points = 0;
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
        assert_eq!(rows.iter().filter(|r| &*r.series == "cpu,host=b").count(), 7);
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
        assert_eq!(&*rows[0].series, "cpu,host=a");
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
            (&*top[0].series, top[0].value.clone()),
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
            (b"Z", &[1]),
        ];
        for (k, v) in cases {
            let dir2 = tmpdir("corrupt2");
            let kv = flashkv::Db::open(&dir2, opts().kv).unwrap();
            kv.put(k, v).unwrap();
            kv.close().unwrap();
            assert!(Db::open(&dir2, opts()).is_err(), "{k:?}");
            std::fs::remove_dir_all(&dir2).unwrap();
        }
        // A corrupt chunk fails the query that reads it: here a chunk of
        // text (so that the statistics are no help) after the only point.
        let key = data_key(0, 0, 999);
        raw_put(&dir, &key, b"\x09");
        let text = ChunkStats {
            count: 1,
            min_ts: 5,
            max_ts: 5,
            numbers: None,
        };
        raw_put(&dir, &stats_key(&key), &text.encode());
        let db = Db::open(&dir, opts()).unwrap();
        assert!(db.query(&Query::new("cpu", "usage")).is_err());
        assert!(db.query(&Query::new("cpu", "usage").latest()).is_err());
        db.close().unwrap();
        // A key of statistics that is not a key of a chunk is as bad.
        raw_put(&dir, &[&b"E"[..], &0u64.to_be_bytes(), b"x"].concat(), b"");
        let db = Db::open(&dir, opts()).unwrap();
        let e = db.query(&Query::new("cpu", "usage")).unwrap_err().to_string();
        assert!(e.contains("bad chunk statistics key entry"), "{e}");
        db.close().unwrap();
        let kv = flashkv::Db::open(&dir, opts().kv).unwrap();
        kv.delete(&[&b"E"[..], &0u64.to_be_bytes(), b"x"].concat()).unwrap();
        kv.close().unwrap();
        // Statistics that are corrupt are as bad.
        raw_put(&dir, &stats_key(&key), b"\x01");
        let db = Db::open(&dir, opts()).unwrap();
        assert!(db.query(&Query::new("cpu", "usage")).is_err());
        db.close().unwrap();
        // Statistics of a chunk that is not there.
        let kv = flashkv::Db::open(&dir, opts().kv).unwrap();
        kv.delete(&key).unwrap();
        kv.put(&stats_key(&key), &text.encode()).unwrap();
        kv.close().unwrap();
        let db = Db::open(&dir, opts()).unwrap();
        let e = db.query(&Query::new("cpu", "usage")).unwrap_err().to_string();
        assert!(e.contains("chunk (it has statistics)"), "{e}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn many_series_are_read_on_many_threads_with_the_same_result() {
        let dir = tmpdir("threads");
        let mut o = opts();
        o.partition = Partitioner::new(100);
        o.threads = 4;
        let db = Db::open(&dir, o.clone()).unwrap();
        for round in 0..6 {
            let points: Vec<Point> = (0..40)
                .flat_map(|h| (0..5).map(move |i| (h, round * 50 + i * 10)))
                .map(|(h, ts)| cpu(&format!("h{h:02}"), ts, (h * 7 + ts) as f64))
                .collect();
            db.write_points(&points).unwrap();
            if round < 4 {
                db.flush().unwrap();
            }
        }
        let queries = [
            Query::new("cpu", "usage"),
            Query::new("cpu", "usage").agg(Agg::Sum),
            Query::new("cpu", "usage").agg(Agg::Max).every(60),
            Query::new("cpu", "usage").range(30, 120).latest(),
        ];
        let threaded: Vec<_> = queries.iter().map(|q| db.query(q).unwrap()).collect();
        assert_eq!(threaded[1].len(), 40);
        assert_eq!(threaded[1][39].tags["host"], "h39");
        db.close().unwrap();
        o.threads = 1;
        let db = Db::open(&dir, o).unwrap();
        let serial: Vec<_> = queries.iter().map(|q| db.query(q).unwrap()).collect();
        assert_eq!(threaded, serial);
        // The first error is the one reported.
        let e = db.query(&Query::new("cpu", "usage").agg(Agg::Sum).every(1).fill(Fill::Prev));
        assert!(e.is_ok());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_flush_waits_for_chunks_of_a_useful_size() {
        let dir = tmpdir("chunk-points");
        let mut o = opts();
        o.flush_points = 1;
        o.chunk_points = 5;
        let db = Db::open(&dir, o).unwrap();
        // Two columns: the flush comes with the fifth point of each.
        for ts in 0..4 {
            db.write_points(&[cpu("a", ts, 1.0), cpu("b", ts, 1.0)]).unwrap();
            assert_eq!(db.stats().flushes, 0, "{ts}");
        }
        db.write_points(&[cpu("a", 4, 1.0), cpu("b", 4, 1.0)]).unwrap();
        assert_eq!(db.stats().flushes, 1);
        assert_eq!(db.stats().buffered_points, 0);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_aggregate_that_needs_a_chunk_that_cannot_be_read_fails() {
        let dir = tmpdir("agg-unreadable");
        let db = Db::open(&dir, opts()).unwrap();
        db.write_points(&[cpu("a", 3, 1.0)]).unwrap();
        db.flush().unwrap();
        // By its statistics, a chunk of numbers from 10 to 20; but it is none.
        let key = data_key(0, 0, 999);
        db.kv.put(&key, b"\x09").unwrap();
        let numbers = Numbers {
            sum: 3.0,
            min: 1.0,
            max: 2.0,
            first: Num::Float(1.0),
            last: Num::Float(2.0),
        };
        let stats = ChunkStats {
            count: 2,
            min_ts: 10,
            max_ts: 20,
            numbers: Some(numbers),
        };
        db.kv.put(&stats_key(&key), &stats.encode()).unwrap();
        // All of it is in the range: the statistics are enough.
        let q = Query::new("cpu", "usage").agg(Agg::Sum);
        assert_eq!(db.query(&q).unwrap()[0].value, FieldValue::Float(4.0));
        // A range that cuts it needs its points.
        assert!(db.query(&q.range(0, 15)).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// What `write_lines` made of the payloads, and what the line protocol
    /// parser and `write_points` make of them, which is the reference.
    #[test]
    fn the_fast_way_makes_what_the_slow_way_makes() {
        let (a, b) = (tmpdir("fast-a"), tmpdir("fast-b"));
        let (fast, slow) = (Db::open(&a, opts()).unwrap(), Db::open(&b, opts()).unwrap());
        let payloads = [
            // Teaches: the series, and the order of the fields. Comments are left out.
            "cpu,host=a usage=1.5,cores=4i,up=t,n=7u 100\ncpu,host=b usage=2.5,cores=8i,up=f,n=9u 100\n#c a=b\n#d a=1\n",
            // The same, the fast way, and an empty line.
            "cpu,host=a usage=2.5,cores=4i,up=f,n=8u 200\ncpu,host=b usage=3.5,cores=8i,up=t,n=10u 200\n\n",
            // Out of order, and a point that is written again.
            "cpu,host=a usage=9.5,cores=1i,up=t,n=1u 100\ncpu,host=a usage=0.5,cores=2i,up=t,n=2u 50\n",
            // A series that is new, and fields in another order.
            "cpu,host=c usage=1,cores=1i,up=t,n=1u 300\ncpu,host=a cores=5i,usage=1.25,n=3u,up=f 400\n",
            // A string, an escape, a space where it should not be.
            "cpu,host=a usage=1,cores=1i,up=t,n=1u,note=\"hi there\" 500\ncpu\\ x,host=a v=1 500\n  cpu,host=b usage=1,cores=1i,up=t,n=1u 500\n",
            // A series with a string, again: nothing fast about it. And the others.
            "cpu,host=a usage=1,cores=1i,up=t,n=1u,note=\"again\" 600\ncpu,host=b usage=4.5,cores=9i,up=f,n=11u 600\n",
            "cpu,host=c usage=2,cores=2i,up=f,n=2u 700\ncpu,host=c usage=-3.25e1,cores=-2i,up=T,n=0u 800\n",
            // Numbers that have to be parsed with care.
            "cpu,host=b usage=0.1,cores=1i,up=t,n=1u 900\ncpu,host=b usage=123456789.123456789,cores=1i,up=t,n=1u 901\ncpu,host=b usage=1e3,cores=1i,up=t,n=1u 902\n",
        ];
        let errors = [
            // The type of a field changes; a value that is nothing; a field twice; no field.
            "cpu,host=a usage=1i,cores=4i,up=t,n=7u 1000\n",
            "cpu,host=a usage=abc,cores=4i,up=t,n=7u 1000\n",
            "cpu,host=a usage=1,usage=2,cores=4i,up=t,n=7u 1000\n",
            "cpu,host=a\n",
        ];
        for (i, text) in payloads.iter().enumerate() {
            let points = lineproto::parse(text).unwrap();
            slow.write_points(&points).unwrap();
            assert_eq!(fast.write_lines(text).unwrap(), points.len(), "{i}");
            assert_eq!(fast.dump().unwrap(), slow.dump().unwrap(), "payload {i}");
        }
        let stats = fast.stats();
        assert!(stats.fast_writes >= 3, "{stats:?}");
        assert_eq!(slow.stats().fast_writes, 0);
        for text in errors {
            let want = lineproto::parse(text)
                .map(|p| slow.write_points(&p))
                .unwrap_or_else(Err);
            let got = fast.write_lines(text).map(|_| ());
            assert_eq!(got.unwrap_err().to_string(), want.unwrap_err().to_string(), "{text:?}");
        }
        assert_eq!(fast.dump().unwrap(), slow.dump().unwrap());
        // The same from the files: the records of the log, and then the chunks.
        fast.close().unwrap();
        let fast = Db::open(&a, opts()).unwrap();
        assert_eq!(fast.dump().unwrap(), slow.dump().unwrap(), "replayed");
        fast.flush().unwrap();
        slow.flush().unwrap();
        assert_eq!(fast.dump().unwrap(), slow.dump().unwrap(), "flushed");
        // Without a timestamp, now.
        let before = now_ns();
        fast.write_lines("cpu,host=a usage=1,cores=1i,up=t,n=1u\n").unwrap();
        let q = Query::new("cpu", "usage").filter("host", "a").latest();
        let ts = fast.query(&q).unwrap()[0].ts;
        assert!((before..=now_ns()).contains(&ts));
        for d in [a, b] {
            std::fs::remove_dir_all(d).unwrap();
        }
    }

    fn logs(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".tswal"))
            .collect();
        names.sort();
        names
    }

    #[test]
    fn the_log_is_a_file_that_is_read_back_and_that_a_flush_replaces() {
        let dir = tmpdir("log-files");
        let db = Db::open(&dir, opts()).unwrap();
        assert_eq!(logs(&dir), ["0000000000000000.tswal"]);
        db.write_points(&[cpu("a", 1, 1.0)]).unwrap();
        db.write_points(&[cpu("a", 2, 2.0)]).unwrap();
        assert_eq!(db.stats().wal_records, 2);
        db.close().unwrap();
        // Read back, and the new writes go to a log of their own.
        let db = Db::open(&dir, opts()).unwrap();
        assert_eq!(db.stats().wal_records, 2);
        assert_eq!(db.stats().buffered_points, 2);
        assert_eq!(logs(&dir), ["0000000000000000.tswal", "0000000000000001.tswal"]);
        db.write_points(&[cpu("a", 3, 3.0)]).unwrap();
        // A flush puts the points in chunks, and the logs of them go.
        db.flush().unwrap();
        assert_eq!(logs(&dir), ["0000000000000002.tswal"]);
        assert_eq!(db.stats().wal_records, 0);
        db.write_points(&[cpu("a", 4, 4.0)]).unwrap();
        db.close().unwrap();
        // A log that a crash left after its points were in chunks is not read, and goes.
        let old = dir.join(wal_name(1));
        let mut record = Vec::new();
        let mut stale = Batch::default();
        stale.insert(0, {
            let mut c = ColumnPoints::new(FieldType::Float);
            c.push(99, FieldValue::Float(99.0)).unwrap();
            c
        });
        log::frame(&mut record, &batch::encode(&stale));
        std::fs::write(&old, &record).unwrap();
        let db = Db::open(&dir, opts()).unwrap();
        assert!(!old.exists());
        let times: Vec<i64> = db
            .query(&Query::new("cpu", "usage"))
            .unwrap()
            .iter()
            .map(|r| r.ts)
            .collect();
        assert_eq!(times, [1, 2, 3, 4]);
        db.close().unwrap();
        // A torn tail (a write that was cut short) is dropped, and the points before it are not.
        let latest = dir.join(logs(&dir).last().unwrap());
        let mut bytes = std::fs::read(&latest).unwrap();
        let whole = bytes.len();
        bytes.extend_from_slice(&[9, 9, 9, 9, 200, 0, 0, 0, 1, 2, 3]);
        std::fs::write(&latest, &bytes).unwrap();
        let db = Db::open(&dir, opts()).unwrap();
        assert_eq!(db.query(&Query::new("cpu", "usage")).unwrap().len(), 4);
        db.close().unwrap();
        // Damage in the middle of a log is not that, and stops the open.
        let latest = dir.join(logs(&dir)[0].clone());
        bytes = std::fs::read(&latest).unwrap();
        bytes.truncate(whole);
        let mut second = Vec::new();
        log::frame(&mut second, &batch::encode(&stale));
        bytes.extend_from_slice(&second);
        let at = bytes.len() / 4;
        bytes[at] ^= 0xff;
        std::fs::write(&latest, &bytes).unwrap();
        assert!(Db::open(&dir, opts()).is_err());
        // A record that is framed well but is not a record.
        let mut framed = Vec::new();
        log::frame(&mut framed, &[7, 7, 7]);
        std::fs::write(&latest, &framed).unwrap();
        let e = Db::open(&dir, opts()).err().unwrap().to_string();
        assert!(e.contains("record of the log"), "{e}");
        // A record of a column that is not there, or of another type, is no better.
        for column in [999, 0] {
            let mut wrong = Batch::default();
            let ty = if column == 0 { FieldType::Int } else { FieldType::Float };
            wrong.insert(column, ColumnPoints::new(ty));
            let mut framed = Vec::new();
            log::frame(&mut framed, &batch::encode(&wrong));
            std::fs::write(&latest, &framed).unwrap();
            let e = Db::open(&dir, opts()).err().unwrap().to_string();
            assert!(e.contains("a column that is not there or not of that type"), "{e}");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn keys_of_chunks_say_what_they_are_of() {
        for (col, bucket, seq) in [(0, 0, 0), (7, -3, 99), (u64::MAX, i64::MIN, u64::MAX), (1, i64::MAX, 1)] {
            let key = data_key(col, bucket, seq);
            assert_eq!(key_parts(&key), Some((col, bucket, seq)));
            assert_eq!(key_parts(&stats_key(&key)), Some((col, bucket, seq)));
            assert_eq!(&stats_key(&key)[1..], &key[1..]);
        }
        assert_eq!(key_parts(b""), None);
        assert_eq!(key_parts(&data_key(1, 2, 3)[1..]), None);
        assert_eq!(key_parts(&[data_key(1, 2, 3), vec![0]].concat()), None);
    }

    /// Every column whose statistics queries have copied: they are what the
    /// store says.
    pub(crate) fn assert_catalog_matches_store(db: &Db) {
        let st = db.state.lock();
        for (col, copied) in &st.catalog {
            let stored: Catalog = db
                .kv
                .scan_prefix(&[&b"E"[..], &col.to_be_bytes()].concat())
                .unwrap()
                .into_iter()
                .map(|(k, v)| {
                    let (_, bucket, seq) = key_parts(&k).unwrap();
                    ((bucket, seq), ChunkStats::decode(&v).unwrap())
                })
                .collect();
            assert_eq!(**copied, stored, "column {col}");
        }
    }

    #[test]
    fn the_statistics_that_queries_copied_follow_every_change() {
        let dir = tmpdir("catalog");
        let mut o = opts();
        o.partition = Partitioner::new(10);
        o.compact_min_chunks = 2;
        let db = Db::open(&dir, o.clone()).unwrap();
        let columns = |db: &Db| db.state.lock().catalog.len();
        let batch = |db: &Db, from: i64| {
            let points: Vec<Point> = (from..from + 30)
                .flat_map(|t| [cpu("a", t, t as f64), cpu("b", t, -(t as f64))])
                .collect();
            db.write_points(&points).unwrap();
            db.flush().unwrap();
        };
        batch(&db, 0);
        assert_eq!(columns(&db), 0, "nothing has been read yet");
        let only_a = Query::new("cpu", "usage").filter("host", "a").agg(Agg::Sum).every(10);
        let before = db.query(&only_a).unwrap();
        assert_eq!(columns(&db), 1, "only the column that was read");
        assert_catalog_matches_store(&db);
        // A flush adds to a column that was read, and not to the others.
        batch(&db, 20);
        assert_eq!(columns(&db), 1);
        assert_catalog_matches_store(&db);
        let all = Query::new("cpu", "usage").agg(Agg::Sum).every(10);
        let rows = db.query(&all).unwrap();
        assert_eq!(columns(&db), 2);
        assert_catalog_matches_store(&db);
        // Merging chunks, then dropping partitions.
        assert!(db.compact().unwrap() > 0);
        assert_catalog_matches_store(&db);
        assert_eq!(db.query(&all).unwrap().len(), rows.len());
        assert_eq!(db.query(&only_a).unwrap().len(), before.len() + 2);
        assert!(db.drop_before(None, 25).unwrap() > 0);
        assert_catalog_matches_store(&db);
        let dropped = db.query(&all).unwrap();
        assert_eq!(dropped.iter().map(|r| r.ts).min(), Some(20));
        // After a restart the copies are made again, from the store.
        db.close().unwrap();
        let db = Db::open(&dir, o).unwrap();
        assert_eq!(columns(&db), 0);
        assert_eq!(db.query(&all).unwrap(), dropped);
        assert_catalog_matches_store(&db);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_format_of_the_database_is_checked() {
        // A new database says which format it is; reopening it is fine.
        let dir = tmpdir("format");
        let db = Db::open(&dir, opts()).unwrap();
        db.write_points(&[cpu("a", 1, 1.0)]).unwrap();
        db.flush().unwrap();
        assert_eq!(db.kv.get(FORMAT_KEY).unwrap(), Some(vec![FORMAT]));
        db.close().unwrap();
        assert!(Db::open(&dir, opts()).is_ok());
        // A newer format is not understood; an older one is refused with a word.
        raw_put(&dir, FORMAT_KEY, &[FORMAT + 1]);
        let e = Db::open(&dir, opts()).err().unwrap().to_string();
        assert!(e.contains("bad format entry"), "{e}");
        raw_put(&dir, FORMAT_KEY, &[FORMAT - 1]);
        let e = Db::open(&dir, opts()).err().unwrap().to_string();
        assert!(e.contains("made by an older version"), "{e}");
        // Chunks without a mark are those of a version that had no statistics.
        let old = tmpdir("format-old");
        raw_put(&old, &data_key(0, 0, 1), b"\x00");
        let e = Db::open(&old, opts()).err().unwrap().to_string();
        assert!(e.contains("made by an older version"), "{e}");
        for d in [dir, old] {
            std::fs::remove_dir_all(d).unwrap();
        }
    }

    /// The values that the points of a column were last written with.
    type Truth = BTreeMap<(String, &'static str), BTreeMap<i64, FieldValue>>;

    fn close(a: &FieldValue, b: &FieldValue) -> bool {
        match (a, b) {
            (FieldValue::Float(x), FieldValue::Float(y)) => (x - y).abs() <= 1e-9 * (1.0 + x.abs()),
            _ => a == b,
        }
    }

    /// Every aggregate, window, alignment, fill and range, from the database
    /// and from the points it was written with.
    fn check_aggregates(db: &Db, truth: &Truth, what: &str) {
        let aggs = [
            Agg::Sum,
            Agg::Count,
            Agg::Min,
            Agg::Max,
            Agg::Mean,
            Agg::First,
            Agg::Last,
        ];
        let ranges = [(i64::MIN, i64::MAX), (13, 777), (100, 200), (5, 1000), (5000, 6000)];
        let windows = [None, Some(10), Some(30), Some(100), Some(250)];
        for field in ["f", "i", "u"] {
            for agg in aggs {
                for every in windows {
                    for align in [Align::Calendar, Align::Start] {
                        for fill in [None, Some(Fill::Prev)] {
                            let skip = every.is_none() & ((align == Align::Start) | fill.is_some());
                            if skip {
                                continue;
                            }
                            for &(start, end) in &ranges {
                                let mut q = Query::new("cpu", field).range(start, end).agg(agg).align(align);
                                q.every = every;
                                q.fill = fill;
                                let got = db.query(&q);
                                let mut want = Vec::new();
                                for ((host, f), points) in truth.iter().filter(|((_, f), _)| *f == field) {
                                    assert_eq!(*f, field);
                                    let points: Vec<_> =
                                        points.range(start..end).map(|(&t, v)| (t, v.clone())).collect();
                                    let rows = query::evaluate_within(&points, &q, query::MAX_FILL_ROWS).unwrap();
                                    want.extend(rows.into_iter().map(|(t, v)| (host.clone(), t, v)));
                                }
                                let label = format!(
                                    "{what}: {field} {agg:?} every {every:?} {align:?} {fill:?} [{start}, {end})"
                                );
                                let mut got: Vec<_> = got
                                    .unwrap()
                                    .into_iter()
                                    .map(|r| (r.tags["host"].clone(), r.ts, r.value))
                                    .collect();
                                got.sort_by(|a, b| (&a.0, a.1).cmp(&(&b.0, b.1)));
                                want.sort_by(|a, b| (&a.0, a.1).cmp(&(&b.0, b.1)));
                                assert_eq!(got.len(), want.len(), "{label}");
                                for (g, w) in got.iter().zip(&want) {
                                    assert!(
                                        (&g.0, g.1) == (&w.0, w.1) && close(&g.2, &w.2),
                                        "{label}: {g:?} != {w:?}"
                                    );
                                }
                            }
                        }
                    }
                }
            }
            // The latest point, too.
            for &(start, end) in &ranges {
                let q = Query::new("cpu", field).range(start, end).latest();
                let mut want: Vec<(String, i64, FieldValue)> = truth
                    .iter()
                    .filter(|((_, f), _)| *f == field)
                    .filter_map(|((host, _), points)| {
                        let (t, v) = points.range(start..end).next_back()?;
                        Some((host.clone(), *t, v.clone()))
                    })
                    .collect();
                let mut got: Vec<_> = db
                    .query(&q)
                    .unwrap()
                    .into_iter()
                    .map(|r| (r.tags["host"].clone(), r.ts, r.value))
                    .collect();
                got.sort_by(|a, b| a.0.cmp(&b.0));
                want.sort_by(|a, b| a.0.cmp(&b.0));
                assert_eq!(got, want, "{what}: latest {field} [{start}, {end})");
            }
        }
    }

    /// Writes a point of `host` with a value of each type that `k` makes.
    fn put(db: &Db, truth: &mut Truth, host: &str, ts: i64, k: u64) {
        let values = [
            ("f", FieldValue::Float(k as f64 * 0.5 - 20.0)),
            ("i", FieldValue::Int(k as i64 - 30)),
            ("u", FieldValue::UInt(k * 3)),
        ];
        let mut p = Point::new("cpu").tag("host", host).at(ts);
        for (f, v) in values {
            p = p.field(f, v.clone());
            truth.entry((host.to_string(), f)).or_default().insert(ts, v);
        }
        db.write_points(&[p]).unwrap();
    }

    #[test]
    fn aggregates_agree_with_the_points_they_are_made_of() {
        let dir = tmpdir("agg-agree");
        let mut o = opts();
        o.partition = Partitioner::new(100);
        o.compact_min_chunks = 2;
        let db = Db::open(&dir, o.clone()).unwrap();
        let mut truth = Truth::new();
        let mut state = 0x2545_f491_4f6c_dd1d_u64;
        let mut next = move |n: u64| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (state >> 33) % n
        };
        // Points as ingestion makes them: in time order, chunk after chunk,
        // the last ones still in the buffer.
        for round in 0..14 {
            for host in ["a", "b"] {
                for i in 0..5 {
                    put(&db, &mut truth, host, round * 70 + i * 12 + next(5) as i64, next(100));
                }
            }
            if round < 12 {
                db.flush().unwrap();
            }
        }
        check_aggregates(&db, &truth, "in order");
        // Points that are rewritten, and new ones between old ones, in a chunk
        // of their own: its range overlaps those of other chunks.
        for ts in [15, 20, 25, 310, 311] {
            put(&db, &mut truth, "a", ts, next(100));
        }
        db.flush().unwrap();
        check_aggregates(&db, &truth, "overlapping");
        // Compaction merges the chunks of a partition, with no overlap left.
        db.compact().unwrap();
        check_aggregates(&db, &truth, "compacted");
        db.close().unwrap();
        let db = Db::open(&dir, o).unwrap();
        check_aggregates(&db, &truth, "reopened");
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
