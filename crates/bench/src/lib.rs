//! `bench`: the LumenDB command line. All logic lives here (the binary is a
//! thin wrapper) and returns the text to print, which keeps it testable.
//!
//! Every storage-backed command accepts `--fail-after N`, which makes the
//! N-th filesystem operation (and all later ones) fail through flashkv's
//! fault-injecting `Env` — a quick way to watch crash handling from a shell.

use cluster::client::Change;
use cluster::{ClientServer, ClusterClient, ClusterOptions, ReplicatedDb, Reply, Request};
use flashkv::env::{FaultEnv, OsEnv};
use flashkv::WriteBatch;
use pcapfast::synth::{self, SynthOptions};
use pcapfast::{parse_bytes, parse_file, Format, ParseOptions};
use raft::{NetOptions, NodeId, Secret, ServerOptions, Transport};
use std::error::Error;
use std::fmt::Write as _;
use std::fs::File;
use std::io::{BufWriter, Write as _};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tsvdb::time::{now_ns, parse_duration, parse_time};
use tsvdb::{query, Agg, Align, Db, DbOptions, Fill, Query};

pub type Res<T> = Result<T, Box<dyn Error>>;

pub const USAGE: &str = "\
usage: bench <command> [args]

commands:
  gen-pcap <out> [--packets N] [--flows N] [--seed N] [--interval-ns N] [--format pcap|pcapng]
      write a synthetic capture
  ingest <capture> --db DIR [--threads N] [--bucket-ns N] [--flush-points N]
      parse a pcap/pcapng file and store its flows (measurement `flows`)
      and traffic timeline (measurement `traffic`) in tsvdb
  write <file.lp> --db DIR
      write InfluxDB line protocol
  query --db DIR [--measurement M] [--field F] [--where tag=value]... [--start TIME]
        [--end TIME] [--agg sum|count|min|max|mean|first|last] [--every DURATION]
        [--align calendar|start] [--fill prev|linear|NUMBER] [--latest 0|1] [--top N]
      query tsvdb (default: raw `flows` bytes). A TIME is an integer (ns since
      1970), `now`, `now-1h` or `now+30s`, or a UTC date: 2024-05-01,
      2024-05-01T12:30:00Z, 2024-05-01T12:30:00.5+02:00. A DURATION is an
      integer (ns) or a number and a unit (ns us ms s m h d w): 90s, 1h, 1d.
      With --every, a window starts at a multiple of the duration since 1970
      (an hour window on the hour, a day window at midnight UTC), whatever
      --start is; --align start makes the first one start at --start. A
      window without points is left out, unless --fill makes a row for it:
      with the value of the window before (prev), a line between the windows
      around it (linear) or a constant. It needs --agg and --every, and
      covers --start to --end if both are given (else the data's range); a
      window the fill has nothing for (prev or linear at an end) stays out.
      --latest 1 gives only the newest point of each series in the range,
      with its own timestamp (no --agg, no --every); with --top N, the N
      series with the largest latest values
  retain --db DIR --keep DURATION [--measurement M]
      keep the last DURATION (1h, 7d, 4w...) of the data of M (default: of
      every measurement) and drop the rest, a whole partition (an hour) at a
      time: the partitions that end before the cutoff, which is DURATION
      before the newest point, or before now if that is earlier (so a
      database nobody writes to any more keeps its last DURATION of data, and
      a point dated in the future moves nothing). A cluster is not reached by
      this: use `client retain`
  kv-bench --db DIR [--ops N] [--value-size N] [--batch N]
      flashkv write / point-read / scan throughput
  parse-bench <capture> [--threads N] [--runs N] [--min-mpps X]
      parse a capture N times (default 5) after one warm-up pass that loads it
      into the page cache. `wall` is the whole parse_file call (open, mmap,
      parse, munmap), `parse` excludes mapping and unmapping. Fails if the
      best wall-clock rate is below X Mpkt/s
  vopr [--seeds N] [--start N] [--replicas N] [--voters N] [--ticks N] [--heal-ticks N]
      deterministic Raft cluster simulation (in the style of TigerBeetle's
      VOPR): per seed, message loss, duplication, reordering, partitions,
      crashes, power loss with torn writes, log bit flips and I/O errors,
      and an operator who adds and removes servers (--voters N: how many of
      the replicas are voters at the start, default: the seed picks), with
      the safety properties checked after every event. A failing seed
      replays exactly with `--start SEED --seeds 1`
  cluster-demo [--nodes N] [--packets N] [--flows N] [--dir DIR] [--timeout-ms N]
      a tsvdb replicated by Raft, in this process: N nodes (default 3) on
      loopback ports ingest a synthetic capture through the leader, and every
      node must end up with the same data; then the leader is stopped, and the
      others elect a new one and carry on. `--dir` keeps the nodes' files
      (default: a temporary directory, removed afterwards); `--timeout-ms` is
      how long to wait for an election, a write to be applied or the nodes to
      catch up (default 10000)
  serve --id N --dir DIR --raft ADDR --client ADDR [--voters 1,2,3] [--peer ID=ADDR]...
        [--snapshot-every N] [--snapshot-chunk BYTES] [--timeout-ms N] [--secret-file FILE]
      run one node of a replicated tsvdb cluster, in this process, until a
      client sends SHUTDOWN. Raft listens on --raft and the client protocol
      on --client (port 0 lets the system pick; the first line printed says
      which). --voters starts a cluster and is the same on every node; a node
      without it waits to be added (client add-learner, then add-voter), and a
      node that has a log goes by that. --peer says where another node's Raft
      listens (more can be told later: client peer). The addresses a node is
      told are saved in DIR/peers, so after a restart it finds the others
      again; only a node that moved has to be told. A snapshot is sent to a
      node that needs one in chunks of at most --snapshot-chunk bytes
      (default 1048576; 0: in one message). Writes and consistent queries
      wait up to --timeout-ms for the node (default 5000). With --secret-file,
      every connection, from another node or from a client, has to prove it
      knows the secret in FILE: at least 16 random bytes, for instance made
      by `head -c 32 /dev/urandom | base64 > FILE`, readable by its owner
      only. All the nodes and clients of a cluster use the same one. It
      authenticates the peer and every byte that follows, but nothing is
      encrypted, and whoever has the secret is trusted with everything
  client --nodes ADDR,ADDR,... <command> [--timeout-ms N] [--patience-ms N] [--secret-file FILE]
      talk to a cluster through the client addresses of its nodes. Commands:
        status                 every node: role, term, leader, voters, log positions
        ping                   every node: PONG, or why not; fails if any node
                               did not answer (a health check)
        write FILE             write line protocol through the leader
        query [query flags]    like `query`, on the leader (linearizable), or
                               on the first node that answers with --local 1
        add-learner ID, add-voter ID, remove-voter ID, remove-learner ID
                               change the membership, through the leader
        transfer ID            hand leadership to voter ID (to take the
                               leader out of service without an election
                               timeout); it returns once ID leads
        retain --keep DURATION [--measurement M]
                               like `retain`, on every node: the leader works
                               out the cutoff and puts it in the log
        peer ID ADDR           tell every node where node ID's Raft listens
        shutdown               stop every node
      The leader is looked for among the nodes for up to --patience-ms
      (default 10000); --timeout-ms (default 10000) limits each connection
      and each wait for a reply. --secret-file is the secret of the cluster
      (see `serve`): nodes that have one answer nothing without it. A write
      that fails with a timeout or a lost connection may or may not have been
      applied

storage options (ingest, write, query, retain, kv-bench):
  --sync 0|1        fsync every write (default 1)
  --background 0|1  flush/compact on a background thread (default 1)
  --fail-after N    inject an I/O error at the N-th filesystem operation
";

const STORAGE_FLAGS: [&str; 4] = ["db", "sync", "background", "fail-after"];

/// The flags that describe a query (`query` and `client query`).
const QUERY_FLAGS: [&str; 11] = [
    "measurement",
    "field",
    "where",
    "start",
    "end",
    "agg",
    "every",
    "align",
    "fill",
    "latest",
    "top",
];

struct Args {
    pos: Vec<String>,
    flags: Vec<(String, String)>,
}

impl Args {
    fn parse(args: &[String]) -> Res<Args> {
        let mut out = Args {
            pos: Vec::new(),
            flags: Vec::new(),
        };
        let mut it = args.iter();
        while let Some(a) = it.next() {
            match a.strip_prefix("--") {
                Some(name) => {
                    let v = it.next().ok_or(format!("--{name} needs a value"))?;
                    out.flags.push((name.to_string(), v.clone()));
                }
                None => out.pos.push(a.clone()),
            }
        }
        Ok(out)
    }

    fn check(&self, allowed: &[&str]) -> Res<()> {
        let allowed: Vec<&str> = allowed.iter().chain(&STORAGE_FLAGS).copied().collect();
        match self.flags.iter().find(|(k, _)| !allowed.contains(&k.as_str())) {
            Some((k, _)) => Err(format!("unknown flag --{k}").into()),
            None => Ok(()),
        }
    }

    /// Last value of `--name`.
    fn get(&self, name: &str) -> Option<&str> {
        self.flags
            .iter()
            .rev()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    fn all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.flags
            .iter()
            .filter(move |(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    fn req(&self, name: &str) -> Res<&str> {
        Ok(self.get(name).ok_or(format!("missing --{name}"))?)
    }

    fn pos(&self, i: usize, what: &str) -> Res<&str> {
        Ok(self.pos.get(i).ok_or(format!("missing {what}"))?)
    }

    fn opt<T: FromStr>(&self, name: &str) -> Res<Option<T>> {
        match self.get(name) {
            None => Ok(None),
            Some(s) => Ok(Some(s.parse().map_err(|_| format!("--{name}: invalid number {s:?}"))?)),
        }
    }

    fn num<T: FromStr>(&self, name: &str, default: T) -> Res<T> {
        Ok(self.opt(name)?.unwrap_or(default))
    }

    /// `--name`, a time (see `parse_time`), if given.
    fn time(&self, name: &str) -> Res<Option<i64>> {
        let parse = |s| parse_time(s, now_ns()).ok_or(format!("--{name}: invalid time {s:?}"));
        Ok(self.get(name).map(parse).transpose()?)
    }

    /// `--name`, a duration (see `parse_duration`), if given.
    fn duration(&self, name: &str) -> Res<Option<i64>> {
        let parse = |s| parse_duration(s).ok_or(format!("--{name}: invalid duration {s:?}"));
        Ok(self.get(name).map(parse).transpose()?)
    }
}

fn kv_options(a: &Args) -> Res<flashkv::DbOptions> {
    let mut o = flashkv::DbOptions {
        sync: a.num::<u64>("sync", 1)? != 0,
        background: a.num::<u64>("background", 1)? != 0,
        ..Default::default()
    };
    if let Some(n) = a.opt::<u64>("fail-after")? {
        let fault = FaultEnv::new(Arc::new(OsEnv));
        fault.fail_after(n);
        o.env = Arc::new(fault);
    }
    Ok(o)
}

fn secs(d: Duration) -> f64 {
    d.as_secs_f64().max(1e-9)
}

fn gen_pcap(a: &Args) -> Res<String> {
    a.check(&["packets", "flows", "seed", "interval-ns", "format"])?;
    let path = a.pos(1, "output file")?;
    let format = match a.get("format").unwrap_or("pcap") {
        "pcap" => Format::Pcap,
        "pcapng" => Format::PcapNg,
        f => return Err(format!("unknown format {f:?}").into()),
    };
    let defaults = SynthOptions::default();
    let o = SynthOptions {
        packets: a.num("packets", 100_000)?,
        flows: u32::try_from(a.num::<u64>("flows", 64)?)?,
        seed: a.num("seed", defaults.seed)?,
        interval_ns: a.num("interval-ns", defaults.interval_ns)?,
        format,
        ..defaults
    };
    let t = Instant::now();
    // `generate` flushes the writer itself.
    let bytes = synth::generate(&o, &mut BufWriter::new(File::create(path)?))?;
    Ok(format!(
        "wrote {} packets ({bytes} bytes, {format:?}) to {path} in {:.1} ms\n",
        o.packets,
        secs(t.elapsed()) * 1e3
    ))
}

/// Validated database location and options (checked before any work).
fn db_options(a: &Args) -> Res<(&str, DbOptions)> {
    let opts = DbOptions {
        kv: kv_options(a)?,
        flush_points: a.num("flush-points", 100_000)?,
        ..Default::default()
    };
    Ok((a.req("db")?, opts))
}

fn open_db((dir, opts): (&str, DbOptions)) -> Res<Db> {
    Ok(Db::open(Path::new(dir), opts)?)
}

fn ingest(a: &Args) -> Res<String> {
    a.check(&["threads", "bucket-ns", "flush-points"])?;
    let path = a.pos(1, "capture file")?;
    let db_opts = db_options(a)?;
    let popts = ParseOptions {
        threads: a.num("threads", 0)?,
        bucket_ns: a.num("bucket-ns", 1_000_000_000)?,
        ..Default::default()
    };
    let stats = parse_file(Path::new(path), &popts)?;
    let p = secs(stats.elapsed);
    let mut out = format!(
        "parsed {} packets, {} bytes, {} flows, {} non-IP ({:?}, {} chunks{}) in {:.1} ms: {:.2} Mpkt/s, {:.2} Gbit/s\n",
        stats.packets,
        stats.bytes,
        stats.flows.len(),
        stats.non_ip,
        stats.format,
        stats.chunks,
        if stats.torn_tail { ", torn tail ignored" } else { "" },
        p * 1e3,
        stats.packets as f64 / p / 1e6,
        stats.bytes as f64 * 8.0 / p / 1e9,
    );
    let db = open_db(db_opts)?;
    let t = Instant::now();
    let points = db.ingest_capture(&stats)?;
    db.flush()?;
    let i = secs(t.elapsed());
    let s = db.stats();
    db.close()?;
    let _ = writeln!(
        out,
        "ingested {points} points ({} series, {} columns) in {:.1} ms: {:.0} points/s",
        s.series,
        s.columns,
        i * 1e3,
        points as f64 / i
    );
    Ok(out)
}

fn write_lp(a: &Args) -> Res<String> {
    a.check(&[])?;
    let path = a.pos(1, "line protocol file")?;
    let db_opts = db_options(a)?;
    let text = std::fs::read_to_string(path)?;
    let db = open_db(db_opts)?;
    let n = db.write_lines(&text)?;
    db.close()?;
    Ok(format!("wrote {n} points\n"))
}

/// The query that the flags of `query` and `client query` describe, and the
/// number of rows to keep (`--top`).
fn query_args(a: &Args) -> Res<(Query, Option<usize>)> {
    let mut q = Query::new(
        a.get("measurement").unwrap_or("flows"),
        a.get("field").unwrap_or("bytes"),
    )
    .range(a.time("start")?.unwrap_or(i64::MIN), a.time("end")?.unwrap_or(i64::MAX));
    for w in a.all("where") {
        let (k, v) = w
            .split_once('=')
            .ok_or(format!("--where expects tag=value, got {w:?}"))?;
        q = q.filter(k, v);
    }
    q.agg = a
        .get("agg")
        .map(|s| Agg::parse(s).ok_or(format!("unknown aggregate {s:?}")))
        .transpose()?;
    q.every = a.duration("every")?;
    q.align = a
        .get("align")
        .map(|s| Align::parse(s).ok_or(format!("unknown alignment {s:?}")))
        .transpose()?
        .unwrap_or(Align::Calendar);
    q.fill = a
        .get("fill")
        .map(|s| Fill::parse(s).ok_or(format!("unknown fill {s:?}")))
        .transpose()?;
    q.latest = a.num::<u64>("latest", 0)? != 0;
    Ok((q, a.opt::<usize>("top")?))
}

fn run_query(a: &Args) -> Res<String> {
    a.check(&QUERY_FLAGS)?;
    let (q, top) = query_args(a)?;
    let db = open_db(db_options(a)?)?;
    let rows = db.query(&q)?;
    let rows = match top {
        Some(n) => query::top_n(rows, n),
        None => rows,
    };
    let mut out = String::new();
    for r in &rows {
        let _ = writeln!(out, "{}\t{}\t{}", r.series, r.ts, r.value);
    }
    let _ = writeln!(out, "{} rows", rows.len());
    Ok(out)
}

/// What `retain` and `client retain` keep: a measurement (all if none), and
/// for how long.
fn retain_args(a: &Args) -> Res<(Option<String>, i64)> {
    let keep = a.duration("keep")?.ok_or("missing --keep")?;
    if keep == 0 {
        return Err("--keep must be more than 0".into());
    }
    Ok((a.get("measurement").map(str::to_string), keep))
}

fn retain(a: &Args) -> Res<String> {
    a.check(&["keep", "measurement"])?;
    let (measurement, keep) = retain_args(a)?;
    let db = open_db(db_options(a)?)?;
    let out = match db.retain(measurement.as_deref(), keep, now_ns())? {
        None => "no data: nothing to drop\n".to_string(),
        Some((cutoff, chunks)) => format!("dropped {chunks} chunks that end before {cutoff} ns since 1970\n"),
    };
    db.close()?;
    Ok(out)
}

fn kv_bench(a: &Args) -> Res<String> {
    a.check(&["ops", "value-size", "batch"])?;
    let ops: u64 = a.num("ops", 100_000)?;
    let value = vec![0xab; a.num("value-size", 100)?];
    let batch = a.num::<u64>("batch", 1_000)?.max(1);
    let kv = flashkv::Db::open(Path::new(a.req("db")?), kv_options(a)?)?;
    let key = |i: u64| format!("key{:016x}", i.wrapping_mul(0x9e37_79b9_7f4a_7c15));
    let t = Instant::now();
    let mut i = 0;
    while i < ops {
        let mut b = WriteBatch::new();
        for j in i..(i + batch).min(ops) {
            b.put(key(j).as_bytes(), &value);
        }
        kv.write(&b)?;
        i += batch;
    }
    let w = secs(t.elapsed());
    kv.flush()?;
    let t = Instant::now();
    let mut found = 0u64;
    for j in 0..ops {
        found += u64::from(kv.get(key(j).as_bytes())?.is_some());
    }
    let r = secs(t.elapsed());
    let t = Instant::now();
    let scanned = kv.scan(b"", None)?.len();
    let s = secs(t.elapsed());
    let files = kv.num_files();
    kv.close()?;
    Ok(format!(
        "write: {ops} keys in {:.1} ms ({:.0} ops/s, {:.1} MB/s)\n\
         read:  {found}/{ops} found in {:.1} ms ({:.0} ops/s)\n\
         scan:  {scanned} entries in {:.1} ms ({:.0} entries/s), {files} table files\n",
        w * 1e3,
        ops as f64 / w,
        (ops as f64 * value.len() as f64) / w / 1e6,
        r * 1e3,
        ops as f64 / r,
        s * 1e3,
        scanned as f64 / s,
    ))
}

fn parse_bench(a: &Args) -> Res<String> {
    a.check(&["threads", "runs", "min-mpps"])?;
    let path = Path::new(a.pos(1, "capture file")?);
    let opts = ParseOptions {
        threads: a.num("threads", 0)?,
        ..Default::default()
    };
    let runs = a.num::<usize>("runs", 5)?.max(1);
    let min_mpps = a.opt::<f64>("min-mpps")?;
    let size = std::fs::metadata(path)?.len() as f64;
    let mut out = String::new();
    let mut packets = 0;
    // (wall, parse) seconds of each timed run.
    let mut times = Vec::with_capacity(runs);
    // Run 0 is the warm-up pass.
    for run in 0..=runs {
        let t = Instant::now();
        let s = parse_file(path, &opts)?;
        let wall = secs(t.elapsed());
        let parse = secs(s.elapsed);
        packets = s.packets;
        let line = match run {
            0 => format!(
                "{}: {:.2} GB, {packets} packets, {:?}, {} chunks",
                path.display(),
                size / 1e9,
                s.format,
                s.chunks
            ),
            _ => {
                times.push((wall, parse));
                format!("run {run}: wall {:.1} ms, parse {:.1} ms", wall * 1e3, parse * 1e3)
            }
        };
        let _ = writeln!(out, "{line}");
    }
    let rate = |t: f64| (packets as f64 / t / 1e6, size / t / 1e9);
    let mut mpps = 0.0;
    for (what, i) in [("wall ", 0), ("parse", 1)] {
        let mut t: Vec<f64> = times.iter().map(|w| [w.0, w.1][i]).collect();
        t.sort_by(f64::total_cmp);
        let (best, median) = (t[0], t[t.len() / 2]);
        let (m, gbs) = rate(best);
        if i == 0 {
            mpps = m;
        }
        let _ = writeln!(
            out,
            "best {what}: {:.1} ms, {m:.2} Mpkt/s, {gbs:.2} GB/s (median {:.1} ms)",
            best * 1e3,
            median * 1e3
        );
    }
    match min_mpps {
        Some(min) if mpps < min => {
            Err(format!("{out}regression: best wall-clock {mpps:.2} Mpkt/s is below --min-mpps {min}").into())
        }
        _ => Ok(out),
    }
}

fn vopr(a: &Args) -> Res<String> {
    a.check(&["seeds", "start", "replicas", "voters", "ticks", "heal-ticks"])?;
    let defaults = raft::sim::SimConfig::default();
    let cfg = raft::sim::SimConfig {
        replicas: a.num("replicas", defaults.replicas)?,
        voters: a.num("voters", defaults.voters)?,
        ticks: a.num("ticks", defaults.ticks)?,
        heal_ticks: a.num("heal-ticks", defaults.heal_ticks)?,
        ..defaults
    };
    if !(1..=64).contains(&cfg.replicas) {
        return Err("--replicas must be between 1 and 64".into());
    }
    let start = a.num::<u64>("start", 0)?;
    let seeds = a.num::<u64>("seeds", 100)?;
    let t = Instant::now();
    let mut failures = Vec::new();
    let mut total = raft::sim::Report::default();
    for seed in start..start.saturating_add(seeds) {
        match raft::sim::run(seed, &cfg) {
            Ok(r) => total.add(&r),
            Err(e) => failures.push(e),
        }
    }
    let mut out = format!(
        "{seeds} seeds from {start}, {} replicas, {} + {} ticks, in {:.1} s\n{}\n",
        cfg.replicas,
        cfg.ticks,
        cfg.heal_ticks,
        secs(t.elapsed()),
        total.summary()
    );
    if failures.is_empty() {
        let _ = writeln!(out, "all safety properties held");
        return Ok(out);
    }
    for f in &failures {
        let _ = writeln!(out, "FAILED {f}");
    }
    let _ = write!(
        out,
        "{} of {seeds} seeds failed; replay one with `bench vopr --start SEED --seeds 1 --replicas {}`",
        failures.len(),
        cfg.replicas
    );
    Err(out.into())
}

/// Polls `f` for up to `limit`.
fn wait_for<T>(limit: Duration, mut f: impl FnMut() -> Option<T>) -> Option<T> {
    let start = Instant::now();
    loop {
        match f() {
            Some(v) => return Some(v),
            None if start.elapsed() >= limit => return None,
            None => std::thread::sleep(Duration::from_millis(2)),
        }
    }
}

/// The only leader among `nodes`, once there is one.
fn sole_leader(nodes: &[ReplicatedDb], limit: Duration) -> Option<&ReplicatedDb> {
    wait_for(limit, || {
        let mut leaders = nodes.iter().filter(|n| n.is_leader());
        let first = leaders.next()?;
        leaders.next().is_none().then_some(first)
    })
}

fn cluster_demo(a: &Args) -> Res<String> {
    a.check(&["nodes", "packets", "flows", "dir", "timeout-ms"])?;
    let n = a.num::<u64>("nodes", 3)?;
    if !(1..=7).contains(&n) {
        return Err("--nodes must be between 1 and 7".into());
    }
    let o = SynthOptions {
        packets: a.num("packets", 20_000)?,
        flows: u32::try_from(a.num::<u64>("flows", 64)?)?,
        ..SynthOptions::default()
    };
    let limit = Duration::from_millis(a.num("timeout-ms", 10_000)?);
    let dir = match a.get("dir") {
        Some(d) => PathBuf::from(d),
        None => std::env::temp_dir().join(format!("lumendb-cluster-demo-{}", std::process::id())),
    };
    let mut capture = Vec::new();
    synth::generate(&o, &mut capture).expect("writing to memory cannot fail");
    let stats = parse_bytes(&capture, &ParseOptions::default()).expect("a synthetic capture parses");
    let points = tsvdb::capture_points(&stats);

    let ids: Vec<NodeId> = (1..=n).collect();
    let loopback: SocketAddr = ([127, 0, 0, 1], 0).into();
    let transports: Vec<Transport> = (ids.iter())
        .map(|_| Transport::bind(loopback, NetOptions::default()).expect("a loopback port"))
        .collect();
    let addrs: Vec<(NodeId, SocketAddr)> = ids
        .iter()
        .zip(&transports)
        .map(|(&id, t)| (id, t.local_addr()))
        .collect();
    let opts = ClusterOptions {
        raft: ServerOptions {
            tick: Duration::from_millis(5),
            snapshot_every: 0,
            ..ServerOptions::default()
        },
        election_timeout: (20, 40),
        ..ClusterOptions::default()
    };
    let nodes = (ids.iter().zip(transports))
        .map(|(&id, t)| ReplicatedDb::open_on(&dir.join(id.to_string()), id, t, &ids, &addrs, opts.clone()))
        .collect::<Result<Vec<_>, _>>();
    let result = nodes.map_err(Box::from).and_then(|nodes| {
        let report = demo_run(&nodes, &points, limit);
        drop(nodes);
        report
    });
    if a.get("dir").is_none() {
        let _ = std::fs::remove_dir_all(&dir);
    }
    let report = result?;
    Ok(format!(
        "{n} nodes on loopback, {} packets in {} flows: {} points to replicate\n{report}",
        stats.packets,
        stats.flows.len(),
        points.len()
    ))
}

/// The demo proper, on nodes that are up; nothing waits longer than `limit`.
fn demo_run(nodes: &[ReplicatedDb], points: &[tsvdb::Point], limit: Duration) -> Res<String> {
    let mut out = String::new();
    let leader = sole_leader(nodes, limit).ok_or("no leader was elected in time")?;
    let _ = writeln!(out, "node {} is the leader", leader.id());
    let t = Instant::now();
    let batches: Vec<&[tsvdb::Point]> = points.chunks(2_000).collect();
    let written: usize = (batches.iter())
        .map(|b| leader.write_points(b, limit).unwrap_or(0))
        .sum();
    let _ = writeln!(
        out,
        "wrote {written} of {} points in {} batches through node {} in {:.0} ms",
        points.len(),
        batches.len(),
        leader.id(),
        secs(t.elapsed()) * 1e3
    );
    let applied = leader.stats().applied_index;
    let caught_up = wait_for(limit, || {
        nodes.iter().all(|n| n.stats().applied_index >= applied).then_some(())
    });
    let _ = writeln!(
        out,
        "every node applied the log up to entry {applied}: {}; same data on all: {}",
        caught_up.is_some(),
        same_data(nodes.iter())
    );
    for node in nodes {
        let top = query::top_flows(node.db(), i64::MIN, i64::MAX, 1);
        let heaviest = top.map(|rows| rows.first().map(|r| (r.series.clone(), r.value.clone())));
        let _ = writeln!(out, "node {}: heaviest flow {heaviest:?}", node.id());
    }
    if nodes.len() < 3 {
        let _ = writeln!(out, "(a failover needs at least 3 nodes)");
        return Ok(out);
    }
    let old = leader.id();
    let _ = leader.shutdown();
    let survivors: Vec<&ReplicatedDb> = nodes.iter().filter(|n| n.id() != old).collect();
    let next = wait_for(limit, || survivors.iter().copied().find(|n| n.is_leader()));
    let _ = writeln!(
        out,
        "stopped node {old}; the new leader is {:?}",
        next.map(ReplicatedDb::id)
    );
    let marker = tsvdb::Point::new("demo").field("failover", tsvdb::FieldValue::UInt(1));
    let written = next.map(|l| l.write_points(&[marker], limit).ok());
    let _ = writeln!(out, "points written after the failover: {written:?}");
    let target = next.map_or(0, |l| l.stats().applied_index);
    let _ = wait_for(limit, || {
        survivors
            .iter()
            .all(|n| n.stats().applied_index >= target)
            .then_some(())
    });
    let _ = writeln!(
        out,
        "the {} survivors hold the same data: {}",
        survivors.len(),
        same_data(survivors.iter().copied())
    );
    Ok(out)
}

/// Whether the databases of `nodes` hold exactly the same points.
fn same_data<'a>(nodes: impl Iterator<Item = &'a ReplicatedDb>) -> bool {
    let dumps: Vec<String> = nodes.map(|n| n.db().dump().unwrap_or_default()).collect();
    dumps.windows(2).all(|w| w[0] == w[1])
}

fn socket_addr(flag: &str, s: &str) -> Res<SocketAddr> {
    Ok(s.parse().map_err(|_| format!("{flag}: bad address {s:?}"))?)
}

fn node_id(flag: &str, s: &str) -> Res<NodeId> {
    Ok(s.parse().map_err(|_| format!("{flag}: invalid node id {s:?}"))?)
}

/// The secret in the file `--secret-file` names, if there is one.
fn secret(a: &Args) -> Res<Option<Secret>> {
    Ok(a.get("secret-file")
        .map(|path| Secret::from_file(Path::new(path)))
        .transpose()?)
}

/// Runs a node until a client stops it; `announce` is given the line that
/// says where it listens, as soon as it does.
fn serve_node(a: &Args, announce: &dyn Fn(String)) -> Res<String> {
    a.check(&[
        "id",
        "dir",
        "raft",
        "client",
        "voters",
        "peer",
        "snapshot-every",
        "snapshot-chunk",
        "timeout-ms",
        "secret-file",
    ])?;
    let id = node_id("--id", a.req("id")?)?;
    let dir = Path::new(a.req("dir")?);
    let raft = socket_addr("--raft", a.req("raft")?)?;
    let client = socket_addr("--client", a.req("client")?)?;
    let voters = match a.get("voters") {
        Some(list) => (list.split(','))
            .map(|v| node_id("--voters", v))
            .collect::<Res<Vec<_>>>()?,
        None => Vec::new(),
    };
    let mut peers = Vec::new();
    for p in a.all("peer") {
        let (peer, addr) = p.split_once('=').ok_or(format!("--peer expects ID=ADDR, got {p:?}"))?;
        peers.push((node_id("--peer", peer)?, socket_addr("--peer", addr)?));
    }
    let defaults = ClusterOptions::default();
    let secret = secret(a)?;
    let mut opts = ClusterOptions {
        raft: ServerOptions {
            snapshot_every: a.num("snapshot-every", defaults.raft.snapshot_every)?,
            ..defaults.raft
        },
        snapshot_chunk: a.num("snapshot-chunk", defaults.snapshot_chunk)?,
        ..defaults
    };
    opts.raft.net.secret = secret.clone();
    let timeout = Duration::from_millis(a.num("timeout-ms", 5_000)?);
    let db = Arc::new(ReplicatedDb::open(dir, id, raft, &voters, &peers, opts)?);
    let server = ClientServer::start_with(db.clone(), client, timeout, secret)?;
    announce(format!(
        "node {id} listening: raft {}, client {}",
        db.local_addr(),
        server.local_addr()
    ));
    server.wait_shutdown();
    // The node first: a request in flight is answered `stopped` at once.
    let _ = db.shutdown();
    server.stop();
    Ok(format!("node {id} stopped\n"))
}

fn serve(a: &Args) -> Res<String> {
    serve_node(a, &|line| {
        println!("{line}");
        // (a closed stdout only means that nobody reads the line)
        let _ = std::io::stdout().flush();
    })
}

/// What a reply says, as the output of `client`.
fn render(reply: Reply) -> Res<String> {
    match reply {
        Reply::Ok(text) => Ok(format!("{text}\n")),
        Reply::Rows(rows) => {
            let mut out = String::new();
            for r in &rows {
                let _ = writeln!(out, "{}\t{}\t{}", r.series, r.ts, r.value);
            }
            let _ = writeln!(out, "{} rows", rows.len());
            Ok(out)
        }
        Reply::Err { code, text } => Err(format!("{} {text}", code.name()).into()),
    }
}

/// Sends `req` to every node and reports each answer. A `strict` command
/// fails when any node did not do it; `status` shows the nodes that are down.
fn each_report(c: &ClusterClient, req: &Request, strict: bool) -> Res<String> {
    let replies = c.each(req);
    let mut out = String::new();
    let mut failed = 0;
    for (addr, reply) in &replies {
        failed += usize::from(!matches!(reply, Ok(Reply::Ok(_))));
        let text = match reply {
            Ok(reply) => reply.to_string(),
            Err(e) => format!("unreachable: {e}"),
        };
        let _ = writeln!(out, "{addr}: {text}");
    }
    match strict && failed > 0 {
        true => Err(format!("{failed} of {} nodes failed:\n{}", replies.len(), out.trim_end()).into()),
        false => Ok(out),
    }
}

fn client(a: &Args) -> Res<String> {
    let own = ["nodes", "timeout-ms", "patience-ms", "secret-file", "local", "keep"];
    a.check(&[&own[..], &QUERY_FLAGS[..]].concat())?;
    let nodes = (a.req("nodes")?.split(','))
        .map(|n| socket_addr("--nodes", n))
        .collect::<Res<Vec<_>>>()?;
    let timeout = Duration::from_millis(a.num("timeout-ms", 10_000)?);
    let patience = Duration::from_millis(a.num("patience-ms", 10_000)?);
    let mut c = ClusterClient::new(nodes, timeout, patience);
    c.set_secret(secret(a)?);
    let command = a.pos(1, "client command")?;
    // The request, and for one that goes to every node: whether it is strict.
    let (req, every) = match command {
        "status" => (Request::Status, Some(false)),
        "ping" => (Request::Ping, Some(true)),
        "shutdown" => (Request::Shutdown, Some(true)),
        "peer" => {
            let id = node_id("peer", a.pos(2, "node id")?)?;
            let addr = socket_addr("peer", a.pos(3, "address")?)?;
            (Request::Peer(id, addr), Some(true))
        }
        "transfer" => (Request::Transfer(node_id("transfer", a.pos(2, "node id")?)?), None),
        "write" => {
            let text = std::fs::read_to_string(a.pos(2, "line protocol file")?)?;
            (Request::Write(text), None)
        }
        "retain" => {
            let (measurement, keep) = retain_args(a)?;
            (Request::Retain { measurement, keep }, None)
        }
        "query" => {
            let (query, top) = query_args(a)?;
            let consistent = a.num::<u64>("local", 0)? == 0;
            let top = top.map(|n| n as u64);
            (Request::Query { consistent, query, top }, None)
        }
        other => match Change::parse(&other.to_uppercase()) {
            Ok(change) => (Request::Member(change, node_id(other, a.pos(2, "node id")?)?), None),
            Err(_) => return Err(format!("unknown client command {other:?}").into()),
        },
    };
    if let Some(strict) = every {
        return each_report(&c, &req, strict);
    }
    let out = render(c.call(&req)?)?;
    Ok(match command {
        "write" => format!("wrote {} points\n", out.trim_end()),
        "retain" => match out.trim_end().parse::<i64>() {
            Ok(cutoff) => format!("dropped what ends before {cutoff} ns since 1970, on every node\n"),
            Err(_) => "no data: nothing to drop\n".to_string(),
        },
        _ => out,
    })
}

/// Runs the command line `args` (without the program name); returns the
/// text to print on success.
pub fn run(args: &[String]) -> Res<String> {
    let a = Args::parse(args)?;
    match a.pos.first().map(String::as_str) {
        None | Some("help") => Ok(USAGE.to_string()),
        Some("gen-pcap") => gen_pcap(&a),
        Some("ingest") => ingest(&a),
        Some("write") => write_lp(&a),
        Some("query") => run_query(&a),
        Some("retain") => retain(&a),
        Some("kv-bench") => kv_bench(&a),
        Some("parse-bench") => parse_bench(&a),
        Some("vopr") => vopr(&a),
        Some("cluster-demo") => cluster_demo(&a),
        Some("serve") => serve(&a),
        Some("client") => client(&a),
        Some(other) => Err(format!("unknown command {other:?}\n\n{USAGE}").into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::path::PathBuf;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("bench-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn cmd(s: &str) -> Res<String> {
        run(&s.split_whitespace().map(String::from).collect::<Vec<_>>())
    }

    fn err(s: &str) -> String {
        cmd(s).unwrap_err().to_string()
    }

    #[test]
    fn usage_and_argument_errors() {
        assert_eq!(cmd("").unwrap(), USAGE);
        assert_eq!(cmd("help").unwrap(), USAGE);
        assert!(err("frobnicate").starts_with("unknown command"));
        assert_eq!(err("query --db"), "--db needs a value");
        assert_eq!(err("query --bogus 1"), "unknown flag --bogus");
        assert_eq!(err("query"), "missing --db");
        assert_eq!(err("ingest --db x"), "missing capture file");
        assert_eq!(err("gen-pcap"), "missing output file");
        assert_eq!(err("gen-pcap f --packets -1"), "--packets: invalid number \"-1\"");
        assert_eq!(err("gen-pcap f --format nope"), "unknown format \"nope\"");
        assert!(err("gen-pcap f --flows 99999999999").contains("too large"));
        assert_eq!(
            err("query --db x --where nope"),
            "--where expects tag=value, got \"nope\""
        );
        assert_eq!(err("query --db x --agg median"), "unknown aggregate \"median\"");
        assert_eq!(err("query --db x --every soon"), "--every: invalid duration \"soon\"");
        assert_eq!(err("query --db x --every -1"), "--every: invalid duration \"-1\"");
        assert_eq!(err("query --db x --align never"), "unknown alignment \"never\"");
        assert_eq!(err("query --db x --fill nan"), "unknown fill \"nan\"");
        assert_eq!(err("query --db x --latest soon"), "--latest: invalid number \"soon\"");
        assert_eq!(err("query --db x --sync maybe"), "--sync: invalid number \"maybe\"");
        assert_eq!(
            err("query --db x --background maybe"),
            "--background: invalid number \"maybe\""
        );
        assert_eq!(err("query --db x --fail-after z"), "--fail-after: invalid number \"z\"");
        assert_eq!(err("query --db x --flush-points z"), "unknown flag --flush-points");
        assert_eq!(
            err("ingest c --db x --flush-points z --threads 1"),
            "--flush-points: invalid number \"z\""
        );
        assert_eq!(err("query --db x --top z"), "--top: invalid number \"z\"");
        for (args, want) in [
            ("gen-pcap f --x 1", "unknown flag --x"),
            ("gen-pcap f --flows z", "--flows: invalid number \"z\""),
            ("gen-pcap f --seed z", "--seed: invalid number \"z\""),
            ("gen-pcap f --interval-ns z", "--interval-ns: invalid number \"z\""),
            ("ingest c --x 1", "unknown flag --x"),
            ("ingest c --db x --threads z", "--threads: invalid number \"z\""),
            ("ingest c --db x --bucket-ns z", "--bucket-ns: invalid number \"z\""),
            ("write f --x 1", "unknown flag --x"),
            ("write f", "missing --db"),
            ("query --db x --start z", "--start: invalid time \"z\""),
            ("query --db x --end 2024-13-01", "--end: invalid time \"2024-13-01\""),
            ("kv-bench --x 1", "unknown flag --x"),
            ("kv-bench --ops z", "--ops: invalid number \"z\""),
            ("kv-bench --value-size z", "--value-size: invalid number \"z\""),
            ("kv-bench --batch z", "--batch: invalid number \"z\""),
            ("kv-bench", "missing --db"),
            ("kv-bench --db x --sync z", "--sync: invalid number \"z\""),
            ("parse-bench", "missing capture file"),
            ("parse-bench c --x 1", "unknown flag --x"),
            ("parse-bench c --threads z", "--threads: invalid number \"z\""),
            ("parse-bench c --runs z", "--runs: invalid number \"z\""),
            ("parse-bench c --min-mpps z", "--min-mpps: invalid number \"z\""),
            ("vopr --x 1", "unknown flag --x"),
            ("vopr --seeds z", "--seeds: invalid number \"z\""),
            ("vopr --start z", "--start: invalid number \"z\""),
            ("vopr --replicas z", "--replicas: invalid number \"z\""),
            ("vopr --voters z", "--voters: invalid number \"z\""),
            ("vopr --ticks z", "--ticks: invalid number \"z\""),
            ("vopr --heal-ticks z", "--heal-ticks: invalid number \"z\""),
            ("vopr --replicas 0", "--replicas must be between 1 and 64"),
            ("vopr --replicas 65", "--replicas must be between 1 and 64"),
        ] {
            assert_eq!(err(args), want, "{args}");
        }
    }

    #[test]
    fn gen_ingest_query_pipeline() {
        let d = tmp("pipeline");
        for format in ["pcap", "pcapng"] {
            let cap = d.join(format!("c.{format}"));
            let db = d.join(format!("db-{format}"));
            let (cap, db) = (cap.display(), db.display());
            let out = cmd(&format!(
                "gen-pcap {cap} --packets 2000 --flows 9 --format {format} --seed 3 --interval-ns 500"
            ))
            .unwrap();
            assert!(out.starts_with("wrote 2000 packets"), "{out}");
            let out = cmd(&format!(
                "ingest {cap} --db {db} --threads 2 --bucket-ns 100000 --sync 0 --flush-points 50"
            ))
            .unwrap();
            assert!(out.contains("parsed 2000 packets") && out.contains("ingested"), "{out}");
            let out = cmd(&format!("query --db {db} --agg sum --top 3")).unwrap();
            assert!(out.ends_with("3 rows\n"), "{out}");
            let out = cmd(&format!("query --db {db} --measurement traffic --field packets --agg sum --start 0 --end 9223372036854775807 --every 3600000000000")).unwrap();
            assert!(out.contains("2000"), "{out}");
            // The same with human units: calendar windows, and anchored at the start.
            for align in ["calendar", "start"] {
                let out = cmd(&format!("query --db {db} --measurement traffic --field packets --agg sum --start 1970-01-01 --end now+1d --every 1d --align {align}")).unwrap();
                assert!(out.contains("2000"), "{align}: {out}");
            }
            // A fill makes a row for every empty day since 1970 too.
            let out = cmd(&format!("query --db {db} --measurement traffic --field packets --agg sum --start 1970-01-01 --end now+1d --every 1d --fill 0")).unwrap();
            let rows = out.lines().count();
            assert!(out.contains("2000") && rows > 20_000, "{rows} rows");
            // The newest point of each series, with its own timestamp; the top 2 of them.
            let out = cmd(&format!("query --db {db} --latest 1")).unwrap();
            assert!(out.lines().count() > 2, "{out}");
            assert!(
                out.lines().all(|l| l.ends_with(" rows") || l.split('\t').count() == 3),
                "{out}"
            );
            let out = cmd(&format!("query --db {db} --latest 1 --top 2")).unwrap();
            assert!(out.ends_with("2 rows\n"), "{out}");
            assert!(cmd(&format!("query --db {db} --latest 1 --agg sum")).is_err());
            let out = cmd(&format!("query --db {db} --where proto=udp --where proto=tcp")).unwrap();
            assert_eq!(out, "0 rows\n");
            assert!(cmd(&format!("query --db {db} --start 5 --end 5")).is_err());
        }
        // Torn tail is reported, not fatal.
        let cap = d.join("c.pcap");
        let bytes = std::fs::read(&cap).unwrap();
        std::fs::write(&cap, &bytes[..bytes.len() - 3]).unwrap();
        let out = cmd(&format!(
            "ingest {} --db {} --background 0",
            cap.display(),
            d.join("torn").display()
        ))
        .unwrap();
        assert!(out.contains("torn tail ignored"), "{out}");
        assert!(cmd(&format!("ingest {} --db x", d.join("missing").display())).is_err());
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn gen_pcap_write_errors() {
        assert!(cmd("gen-pcap /nonexistent-dir/x.pcap --packets 1").is_err());
        // /dev/full accepts the open and fails every write (ENOSPC): a large
        // capture fails while generating, a tiny one at the final flush.
        assert!(cmd("gen-pcap /dev/full --packets 10000").is_err());
        assert!(cmd("gen-pcap /dev/full --packets 1").is_err());
    }

    #[test]
    fn write_line_protocol() {
        let d = tmp("write");
        let lp = d.join("in.lp");
        std::fs::write(&lp, "cpu,host=a usage=1 10\ncpu,host=a usage=3 20\n").unwrap();
        let db = d.join("db");
        let out = cmd(&format!("write {} --db {}", lp.display(), db.display())).unwrap();
        assert_eq!(out, "wrote 2 points\n");
        let out = cmd(&format!(
            "query --db {} --measurement cpu --field usage --where host=a --agg mean",
            db.display()
        ))
        .unwrap();
        assert_eq!(out, format!("cpu,host=a\t{}\t2\n1 rows\n", i64::MIN));
        std::fs::write(&lp, "garbage").unwrap();
        assert!(cmd(&format!("write {} --db {}", lp.display(), db.display())).is_err());
        assert!(cmd(&format!("write {} --db {}", d.join("nope").display(), db.display())).is_err());
        assert!(cmd(&format!("write --db {}", db.display())).is_err());
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn kv_bench_reports_throughput() {
        let d = tmp("kv");
        let out = cmd(&format!(
            "kv-bench --db {} --ops 500 --value-size 32 --batch 64 --sync 0",
            d.join("db").display()
        ))
        .unwrap();
        assert!(out.contains("read:  500/500 found"), "{out}");
        assert!(out.contains("scan:  500 entries"), "{out}");
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn parse_bench_reports_runs_and_gates_on_min_rate() {
        let d = tmp("parse-bench");
        let cap = d.join("c.pcap");
        cmd(&format!("gen-pcap {} --packets 3000", cap.display())).unwrap();
        let out = cmd(&format!(
            "parse-bench {} --runs 3 --threads 2 --min-mpps 0",
            cap.display()
        ))
        .unwrap();
        assert!(out.contains("3000 packets, Pcap"), "{out}");
        assert!(out.contains("run 3: ") && !out.contains("run 4"), "{out}");
        assert!(out.contains("best wall : ") && out.contains("best parse: "), "{out}");
        assert!(out.contains("(median "), "{out}");
        let out = cmd(&format!("parse-bench {} --runs 0", cap.display())).unwrap();
        assert!(out.contains("run 1: ") && !out.contains("run 2"), "{out}");
        let e = err(&format!("parse-bench {} --runs 1 --min-mpps 1e12", cap.display()));
        assert!(
            e.contains("best wall : ") && e.contains("is below --min-mpps 1000000000000"),
            "{e}"
        );
        assert!(cmd(&format!("parse-bench {}", d.join("missing").display())).is_err());
        std::fs::write(&cap, b"not a capture").unwrap();
        assert!(cmd(&format!("parse-bench {}", cap.display())).is_err());
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn the_cluster_demo_replicates_fails_over_and_reports_problems() {
        // Three nodes: replicate, then lose the leader.
        let dir = tmp("demo");
        let kept = dir.join("kept");
        let out = cmd(&format!(
            "cluster-demo --packets 2000 --flows 8 --dir {}",
            kept.display()
        ))
        .unwrap();
        assert!(
            out.starts_with("3 nodes on loopback, 2000 packets in 8 flows: "),
            "{out}"
        );
        assert!(out.contains("is the leader\nwrote "), "{out}");
        assert!(out.contains("batches through node "), "{out}");
        assert!(out.contains("; same data on all: true\n"), "{out}");
        assert!(out.contains("every node applied the log up to entry "), "{out}");
        assert_eq!(out.matches("heaviest flow Ok(Some((").count(), 3, "{out}");
        assert!(out.contains("the new leader is Some("), "{out}");
        assert!(
            out.contains("points written after the failover: Some(Some(1))"),
            "{out}"
        );
        assert!(out.contains("the 2 survivors hold the same data: true\n"), "{out}");
        assert!(kept.join("1").join("raft").exists(), "--dir keeps the files");
        // One node has nobody to fail over to; the files go when no --dir is given.
        let out = cmd("cluster-demo --nodes 1 --packets 200 --flows 2").unwrap();
        assert!(out.starts_with("1 nodes on loopback"), "{out}");
        assert!(out.contains("(a failover needs at least 3 nodes)"), "{out}");
        assert!(!std::env::temp_dir()
            .join(format!("lumendb-cluster-demo-{}", std::process::id()))
            .exists());
        // Problems are reported: arguments, the directory, and no time to elect.
        assert_eq!(err("cluster-demo --nodes 0"), "--nodes must be between 1 and 7");
        assert_eq!(err("cluster-demo --nodes 8"), "--nodes must be between 1 and 7");
        assert_eq!(
            err("cluster-demo --flows 99999999999"),
            "number too large to fit in target type"
        );
        assert!(err("cluster-demo --nodes x").contains("--nodes: invalid number"));
        assert_eq!(err("cluster-demo --x 1"), "unknown flag --x");
        for flag in ["packets", "flows", "timeout-ms"] {
            let message = err(&format!("cluster-demo --{flag} x"));
            assert!(message.contains(&format!("--{flag}: invalid number")), "{message}");
        }
        // (a path below a file cannot be made into a directory)
        let note = kept.join("1").join("applied");
        assert!(note.is_file());
        let blocked = format!("cluster-demo --dir {}", note.join("x").display());
        let message = err(&blocked);
        assert!(message.starts_with("io: "), "{message}");
        assert_eq!(
            err("cluster-demo --timeout-ms 1 --packets 100"),
            "no leader was elected in time"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn vopr_runs_seeds_and_reports_failures() {
        let out = cmd("vopr --seeds 3 --start 10 --replicas 3 --voters 3 --ticks 300 --heal-ticks 300").unwrap();
        assert!(
            out.starts_with("3 seeds from 10, 3 replicas, 300 + 300 ticks, in "),
            "{out}"
        );
        assert!(
            out.contains("\ncommitted ") && out.ends_with("all safety properties held\n"),
            "{out}"
        );
        // Defaults: 100 seeds would be slow in a debug build, so run none.
        let out = cmd("vopr --seeds 0").unwrap();
        assert!(
            out.starts_with("0 seeds from 0, 5 replicas, 2000 + 600 ticks, in "),
            "{out}"
        );
        // No time to elect a leader and nothing to heal in: every seed fails.
        let e = err("vopr --seeds 2 --start 4 --replicas 3 --ticks 5 --heal-ticks 0");
        assert!(e.contains("FAILED seed 4, tick 5: no convergence after healing"), "{e}");
        assert!(e.contains("FAILED seed 5, tick 5: "), "{e}");
        assert!(
            e.ends_with("2 of 2 seeds failed; replay one with `bench vopr --start SEED --seeds 1 --replicas 3`"),
            "{e}"
        );
    }

    fn loopback() -> SocketAddr {
        "127.0.0.1:0".parse().unwrap()
    }

    /// A one-node cluster in this process, once it has elected itself.
    fn one_node(dir: &Path) -> (Arc<ReplicatedDb>, ClientServer) {
        let opts = ClusterOptions::default();
        let db = ReplicatedDb::open(&dir.join("node"), 1, loopback(), &[1], &[], opts).unwrap();
        let db = Arc::new(db);
        let gate = ClientServer::start(db.clone(), loopback(), Duration::from_secs(10)).unwrap();
        assert!(wait_for(Duration::from_secs(20), || db.is_leader().then_some(())).is_some());
        (db, gate)
    }

    #[test]
    fn client_commands_talk_to_a_node() {
        let d = tmp("client");
        let (_db, gate) = one_node(&d);
        let node = gate.local_addr();
        let c = |rest: &str| cmd(&format!("client --nodes {node} {rest}"));
        let lp = d.join("in.lp");
        std::fs::write(
            &lp,
            "cpu,host=a usage=1 10\ncpu,host=a usage=3 20\ncpu,host=b usage=8 10\n",
        )
        .unwrap();
        assert_eq!(c(&format!("write {}", lp.display())).unwrap(), "wrote 3 points\n");
        let status = c("status").unwrap();
        assert!(status.starts_with(&format!("{node}: id=1 role=leader ")), "{status}");
        assert_eq!(c("ping").unwrap(), format!("{node}: PONG\n"));

        let min = i64::MIN;
        let sums = "--measurement cpu --field usage --agg sum";
        let both = format!("cpu,host=a\t{min}\t4\ncpu,host=b\t{min}\t8\n2 rows\n");
        assert_eq!(c(&format!("query {sums}")).unwrap(), both);
        assert_eq!(c(&format!("query {sums} --local 1")).unwrap(), both);
        assert_eq!(
            c(&format!("query {sums} --top 1")).unwrap(),
            format!("cpu,host=b\t{min}\t8\n1 rows\n")
        );
        assert_eq!(
            c("query --measurement cpu --field usage --where host=a --start 15").unwrap(),
            "cpu,host=a\t20\t3\n1 rows\n"
        );
        assert!(c("query --start 5 --end 5")
            .unwrap_err()
            .to_string()
            .starts_with("bad database: invalid query"));

        // Retention: an hour of data kept, on every node.
        assert_eq!(
            c("retain --keep 1h").unwrap(),
            "dropped what ends before -3599999999980 ns since 1970, on every node\n"
        );
        assert_eq!(
            c("retain --keep 1h --measurement nothing").unwrap(),
            "no data: nothing to drop\n"
        );

        // Membership: the leader does it or says why not.
        assert_eq!(c("add-learner 2").unwrap(), "added\n");
        assert_eq!(c("remove-learner 2").unwrap(), "removed\n");
        let refused = "refused raft: membership change refused: ";
        assert_eq!(
            c("remove-learner 2").unwrap_err().to_string(),
            format!("{refused}not a learner")
        );
        assert_eq!(
            c("add-voter 2").unwrap_err().to_string(),
            format!("{refused}not a learner, add it as one first")
        );
        assert_eq!(c("peer 9 127.0.0.1:9").unwrap(), format!("{node}: ok\n"));
        // Leadership: nobody to hand it to in a cluster of one.
        assert_eq!(
            c("transfer 1").unwrap_err().to_string(),
            "refused raft: leadership transfer failed: the target is this node"
        );
        assert_eq!(
            c("transfer 7").unwrap_err().to_string(),
            "refused raft: leadership transfer failed: the target is not a voter"
        );

        for (args, want) in [
            ("--x 1 status", "unknown flag --x"),
            ("frobnicate", "unknown client command \"frobnicate\""),
            ("", "missing client command"),
            ("peer", "missing node id"),
            ("peer x 127.0.0.1:1", "peer: invalid node id \"x\""),
            ("peer 1", "missing address"),
            ("peer 1 nope", "peer: bad address \"nope\""),
            ("write", "missing line protocol file"),
            ("retain", "missing --keep"),
            ("retain --keep soon", "--keep: invalid duration \"soon\""),
            ("retain --keep 0", "--keep must be more than 0"),
            ("add-voter", "missing node id"),
            ("transfer", "missing node id"),
            ("transfer x", "transfer: invalid node id \"x\""),
            ("add-voter x", "add-voter: invalid node id \"x\""),
            ("query --top z", "--top: invalid number \"z\""),
            ("query --local z", "--local: invalid number \"z\""),
            ("status --timeout-ms z", "--timeout-ms: invalid number \"z\""),
            ("status --patience-ms z", "--patience-ms: invalid number \"z\""),
        ] {
            assert_eq!(c(args).unwrap_err().to_string(), want, "{args}");
        }
        assert_eq!(err("client status"), "missing --nodes");
        assert_eq!(err("client --nodes nope status"), "--nodes: bad address \"nope\"");
        assert!(c("write /nonexistent/in.lp")
            .unwrap_err()
            .to_string()
            .contains("No such file"));

        // Nodes that are down: shown by `status`, fatal for `peer`; and
        // nothing to talk to at all is an error.
        let dead = TcpListener::bind(loopback()).unwrap().local_addr().unwrap();
        let mixed = format!("client --nodes {dead},{node} --patience-ms 50");
        let status = cmd(&format!("{mixed} status")).unwrap();
        assert!(status.starts_with(&format!("{dead}: unreachable: ")), "{status}");
        assert!(status.contains(&format!("{node}: id=1 role=leader ")), "{status}");
        let e = err(&format!("{mixed} peer 9 127.0.0.1:9"));
        assert!(e.starts_with("1 of 2 nodes failed:\n"), "{e}");
        assert!(e.contains(&format!("{dead}: unreachable: ")), "{e}");
        assert!(e.contains(&format!("{node}: ok")), "{e}");
        // `ping` is a health check: it fails too, and says which node did not
        // answer and which did.
        let e = err(&format!("{mixed} ping"));
        assert!(e.starts_with("1 of 2 nodes failed:\n"), "{e}");
        assert!(e.contains(&format!("{dead}: unreachable: ")), "{e}");
        assert!(e.contains(&format!("{node}: PONG")), "{e}");
        let e = err(&format!("client --nodes {dead} --patience-ms 50 query"));
        assert!(e.contains("refused"), "{e}");

        assert_eq!(c("shutdown").unwrap(), format!("{node}: stopping\n"));
        gate.wait_shutdown();
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn serve_runs_a_node_until_a_client_stops_it() {
        let d = tmp("serve-run");
        let words: Vec<String> = format!(
            "serve --id 1 --dir {} --raft 127.0.0.1:0 --client 127.0.0.1:0 --voters 1 \
             --peer 2=127.0.0.1:9 --snapshot-every 5 --snapshot-chunk 64 --timeout-ms 3000",
            d.join("n").display()
        )
        .split_whitespace()
        .map(String::from)
        .collect();
        let a = Args::parse(&words).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let stopped = std::thread::scope(|s| {
            let node = s.spawn(|| serve_node(&a, &|line| tx.send(line).unwrap()).ok());
            let line = rx.recv_timeout(Duration::from_secs(20)).unwrap();
            assert!(line.starts_with("node 1 listening: raft 127.0.0.1:"), "{line}");
            let client_addr: SocketAddr = line.split_once(", client ").unwrap().1.parse().unwrap();
            let mut c = cluster::Client::connect(client_addr, Duration::from_secs(10)).unwrap();
            assert_eq!(
                c.call(&Request::Status).unwrap().to_string().matches(" role=").count(),
                1
            );
            assert_eq!(c.call(&Request::Shutdown).unwrap(), Reply::Ok("stopping".to_string()));
            node.join().unwrap()
        });
        assert_eq!(stopped.as_deref(), Some("node 1 stopped\n"));
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn serve_reports_bad_arguments_and_startup_problems() {
        let d = tmp("serve");
        let dir = d.join("n");
        let base = format!(
            "serve --id 1 --dir {} --raft 127.0.0.1:0 --client 127.0.0.1:0",
            dir.display()
        );
        for (args, want) in [
            ("serve", "missing --id".to_string()),
            ("serve --id z", "--id: invalid node id \"z\"".to_string()),
            ("serve --id 1", "missing --dir".to_string()),
            ("serve --id 1 --dir x", "missing --raft".to_string()),
            (
                "serve --id 1 --dir x --raft nope",
                "--raft: bad address \"nope\"".to_string(),
            ),
            (
                "serve --id 1 --dir x --raft 127.0.0.1:0",
                "missing --client".to_string(),
            ),
            (
                "serve --id 1 --dir x --raft 127.0.0.1:0 --client nope",
                "--client: bad address \"nope\"".to_string(),
            ),
        ] {
            assert_eq!(err(args), want, "{args}");
        }
        for (extra, want) in [
            ("--x 1", "unknown flag --x"),
            ("--voters 1,z", "--voters: invalid node id \"z\""),
            ("--peer 2", "--peer expects ID=ADDR, got \"2\""),
            ("--peer z=127.0.0.1:1", "--peer: invalid node id \"z\""),
            ("--peer 2=nope", "--peer: bad address \"nope\""),
            ("--snapshot-every z", "--snapshot-every: invalid number \"z\""),
            ("--snapshot-chunk z", "--snapshot-chunk: invalid number \"z\""),
            ("--timeout-ms z", "--timeout-ms: invalid number \"z\""),
            // a node that is not among the voters it is asked to start
            ("--voters 2,3", "raft: node not in peer set"),
        ] {
            assert_eq!(err(&format!("{base} {extra}")), want, "{extra}");
        }
        // The client port is taken.
        let taken = TcpListener::bind(loopback()).unwrap();
        let e = err(&format!(
            "serve --id 1 --dir {} --raft 127.0.0.1:0 --client {}",
            dir.display(),
            taken.local_addr().unwrap()
        ));
        assert!(e.contains("in use"), "{e}");
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn a_secret_file_is_read_and_checked() {
        let d = tmp("secret-file");
        let (short, good) = (d.join("short"), d.join("good"));
        std::fs::write(&short, "tiny\n").unwrap();
        std::fs::write(&good, "a-secret-for-the-bench-tests\n").unwrap();
        let base = format!(
            "serve --id 1 --dir {} --raft 127.0.0.1:0 --client 127.0.0.1:0",
            d.join("n").display()
        );
        for command in [base.as_str(), "client --nodes 127.0.0.1:1 status"] {
            let e = err(&format!("{command} --secret-file {}", short.display()));
            assert!(e.starts_with(&short.display().to_string()), "{e}");
            assert!(e.contains("at least 16 bytes, this one has 4"), "{e}");
            let e = err(&format!("{command} --secret-file {}", d.join("missing").display()));
            assert!(e.contains("No such file"), "{e}");
        }
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn serve_and_client_share_a_secret() {
        let d = tmp("secret-run");
        let (good, other) = (d.join("good"), d.join("other"));
        std::fs::write(&good, "a-secret-for-the-bench-tests\n").unwrap();
        std::fs::write(&other, "not-the-secret-of-this-cluster").unwrap();
        let words: Vec<String> = format!(
            "serve --id 1 --dir {} --raft 127.0.0.1:0 --client 127.0.0.1:0 --voters 1 --secret-file {}",
            d.join("n").display(),
            good.display()
        )
        .split_whitespace()
        .map(String::from)
        .collect();
        let a = Args::parse(&words).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        // (not a scope: if an assertion below fails, the test must fail, not
        // wait for a node that nobody stops)
        let node = std::thread::spawn(move || serve_node(&a, &|line| tx.send(line).unwrap()).ok());
        let stopped = {
            let line = rx.recv_timeout(Duration::from_secs(20)).unwrap();
            let addr: SocketAddr = line.split_once(", client ").unwrap().1.parse().unwrap();
            let c = |secret: &Path, rest: &str| {
                let flags = "--timeout-ms 400 --patience-ms 100";
                cmd(&format!(
                    "client --nodes {addr} {flags} --secret-file {} {rest}",
                    secret.display()
                ))
            };
            assert_eq!(c(&good, "ping").unwrap(), format!("{addr}: PONG\n"));
            // Another secret: nothing is answered, and the client is told why.
            let e = c(&other, "ping").unwrap_err().to_string();
            assert!(e.starts_with("1 of 1 nodes failed:"), "{e}");
            assert!(e.contains("same secret"), "{e}");
            let status = c(&other, "status").unwrap();
            assert!(status.starts_with(&format!("{addr}: unreachable: ")), "{status}");
            assert!(c(&other, "shutdown").is_err());
            // None at all.
            let e = err(&format!(
                "client --nodes {addr} --timeout-ms 400 --patience-ms 100 ping"
            ));
            assert!(e.starts_with("1 of 1 nodes failed:"), "{e}");
            // (the node may not have elected itself yet)
            assert!(c(&good, "status").unwrap().contains(": id=1 role="));
            assert_eq!(c(&good, "shutdown").unwrap(), format!("{addr}: stopping\n"));
            node.join().unwrap()
        };
        assert_eq!(stopped.as_deref(), Some("node 1 stopped\n"));
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// Sweeps `--fail-after` over a command until it succeeds: every storage
    /// error path surfaces as an error, never a panic.
    fn sweep(name: &str, make: impl Fn(&Path) -> String) {
        let d = tmp(name);
        for n in 0.. {
            let db = d.join(format!("db{n}"));
            let r = cmd(&format!("{} --background 0 --fail-after {n}", make(&db)));
            if r.is_ok() {
                break;
            }
        }
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn retention_from_the_command_line() {
        let d = tmp("retain");
        let (db, lp) = (d.join("db"), d.join("in.lp"));
        let (db, lp) = (db.display(), lp.display());
        // 25 hours apart, and long ago: the cutoff goes by the newest point.
        std::fs::write(
            d.join("in.lp"),
            "cpu,host=a usage=1 1000000000000\ncpu,host=a usage=2 90000000000000\nmem,host=a free=3u 1000000000000\n",
        )
        .unwrap();
        assert_eq!(cmd(&format!("write {lp} --db {db}")).unwrap(), "wrote 3 points\n");
        let rows = |m: &str, f: &str| cmd(&format!("query --db {db} --measurement {m} --field {f}")).unwrap();
        assert_eq!(
            cmd(&format!("retain --db {db} --keep 1h --measurement nothing")).unwrap(),
            "no data: nothing to drop\n"
        );
        let out = cmd(&format!("retain --db {db} --keep 1h --measurement cpu")).unwrap();
        assert_eq!(out, "dropped 1 chunks that end before 86400000000000 ns since 1970\n");
        assert_eq!(rows("cpu", "usage"), "cpu,host=a\t90000000000000\t2\n1 rows\n");
        assert_eq!(rows("mem", "free"), "mem,host=a\t1000000000000\t3u\n1 rows\n");
        // Without a measurement, all of them; and again: nothing is left to drop.
        let out = cmd(&format!("retain --db {db} --keep 1h")).unwrap();
        assert_eq!(out, "dropped 1 chunks that end before 86400000000000 ns since 1970\n");
        assert_eq!(rows("mem", "free"), "0 rows\n");
        let out = cmd(&format!("retain --db {db} --keep 1h")).unwrap();
        assert_eq!(out, "dropped 0 chunks that end before 86400000000000 ns since 1970\n");
        assert_eq!(rows("cpu", "usage"), "cpu,host=a\t90000000000000\t2\n1 rows\n");
        for (args, want) in [
            ("retain --db x", "missing --keep"),
            ("retain --keep 1h", "missing --db"),
            ("retain --db x --keep soon", "--keep: invalid duration \"soon\""),
            ("retain --db x --keep 0", "--keep must be more than 0"),
            ("retain --db x --keep 0s", "--keep must be more than 0"),
            ("retain --db x --keep 1h --every 1m", "unknown flag --every"),
        ] {
            assert_eq!(err(args), want, "{args}");
        }
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn fault_injection_sweeps() {
        let d = tmp("sweep-input");
        let cap = d.join("c.pcap");
        cmd(&format!("gen-pcap {} --packets 300 --flows 5", cap.display())).unwrap();
        let lp = d.join("in.lp");
        std::fs::write(&lp, "m v=1 1\n").unwrap();
        sweep("sweep-ingest", |db| {
            format!("ingest {} --db {} --flush-points 100", cap.display(), db.display())
        });
        sweep("sweep-write", |db| {
            format!("write {} --db {}", lp.display(), db.display())
        });
        sweep("sweep-query", |db| format!("query --db {}", db.display()));
        // Old and new points, so that there is something to drop.
        let old_and_new = d.join("old.lp");
        std::fs::write(&old_and_new, "m v=1 1000000000000\nm v=2 90000000000000\n").unwrap();
        // And chunks on disk, which the cutoff has to read.
        sweep("sweep-retain-chunks", |db| {
            cmd(&format!(
                "ingest {} --db {} --flush-points 100",
                cap.display(),
                db.display()
            ))
            .unwrap();
            format!("retain --db {} --keep 1h", db.display())
        });
        sweep("sweep-retain", |db| {
            cmd(&format!("write {} --db {}", old_and_new.display(), db.display())).unwrap();
            format!("retain --db {} --keep 1h", db.display())
        });
        sweep("sweep-kv", |db| {
            format!("kv-bench --db {} --ops 40 --batch 8", db.display())
        });
        std::fs::remove_dir_all(&d).unwrap();
    }
}
