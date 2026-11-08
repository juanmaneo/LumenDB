//! `bench`: the LumenDB command line. All logic lives here (the binary is a
//! thin wrapper) and returns the text to print, which keeps it testable.
//!
//! Every storage-backed command accepts `--fail-after N`, which makes the
//! N-th filesystem operation (and all later ones) fail through flashkv's
//! fault-injecting `Env` — a quick way to watch crash handling from a shell.

use flashkv::env::{FaultEnv, OsEnv};
use flashkv::WriteBatch;
use pcapfast::synth::{self, SynthOptions};
use pcapfast::{parse_file, Format, ParseOptions};
use std::error::Error;
use std::fmt::Write as _;
use std::fs::File;
use std::io::BufWriter;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tsvdb::{query, Agg, Db, DbOptions, Query};

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
  query --db DIR [--measurement M] [--field F] [--where tag=value]... [--start NS]
        [--end NS] [--agg sum|count|min|max|mean] [--every NS] [--top N]
      query tsvdb (default: raw `flows` bytes)
  kv-bench --db DIR [--ops N] [--value-size N] [--batch N]
      flashkv write / point-read / scan throughput
  parse-bench <capture> [--threads N] [--runs N] [--min-mpps X]
      parse a capture N times (default 5) after one warm-up pass that loads it
      into the page cache. `wall` is the whole parse_file call (open, mmap,
      parse, munmap), `parse` excludes mapping and unmapping. Fails if the
      best wall-clock rate is below X Mpkt/s
  vopr [--seeds N] [--start N] [--replicas N] [--ticks N] [--heal-ticks N]
      deterministic Raft cluster simulation (in the style of TigerBeetle's
      VOPR): per seed, message loss, duplication, reordering, partitions,
      crashes, power loss with torn writes, log bit flips and I/O errors,
      with the safety properties checked after every event. A failing seed
      replays exactly with `--start SEED --seeds 1`

storage options (ingest, write, query, kv-bench):
  --sync 0|1        fsync every write (default 1)
  --background 0|1  flush/compact on a background thread (default 1)
  --fail-after N    inject an I/O error at the N-th filesystem operation
";

const STORAGE_FLAGS: [&str; 4] = ["db", "sync", "background", "fail-after"];

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

fn run_query(a: &Args) -> Res<String> {
    a.check(&["measurement", "field", "where", "start", "end", "agg", "every", "top"])?;
    let mut q = Query::new(
        a.get("measurement").unwrap_or("flows"),
        a.get("field").unwrap_or("bytes"),
    )
    .range(a.num("start", i64::MIN)?, a.num("end", i64::MAX)?);
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
    q.every = a.opt("every")?;
    let top = a.opt::<usize>("top")?;
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
    a.check(&["seeds", "start", "replicas", "ticks", "heal-ticks"])?;
    let defaults = raft::sim::SimConfig::default();
    let cfg = raft::sim::SimConfig {
        replicas: a.num("replicas", defaults.replicas)?,
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
            Ok(r) => {
                total.committed += r.committed;
                total.elections += r.elections;
                total.crashes += r.crashes;
                total.corruptions += r.corruptions;
                total.recoveries += r.recoveries;
                total.io_errors += r.io_errors;
                total.partitions += r.partitions;
                total.delivered += r.delivered;
                total.dropped += r.dropped;
            }
            Err(e) => failures.push(e),
        }
    }
    let mut out = format!(
        "{seeds} seeds from {start}, {} replicas, {} + {} ticks, in {:.1} s\n\
         committed {}, elections {}, crashes {}, log corruptions {}, recoveries {}, io errors {}, \
         partitions {}, messages {} delivered / {} dropped\n",
        cfg.replicas,
        cfg.ticks,
        cfg.heal_ticks,
        secs(t.elapsed()),
        total.committed,
        total.elections,
        total.crashes,
        total.corruptions,
        total.recoveries,
        total.io_errors,
        total.partitions,
        total.delivered,
        total.dropped
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
        Some("kv-bench") => kv_bench(&a),
        Some("parse-bench") => parse_bench(&a),
        Some("vopr") => vopr(&a),
        Some(other) => Err(format!("unknown command {other:?}\n\n{USAGE}").into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        assert_eq!(err("query --db x --every soon"), "--every: invalid number \"soon\"");
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
            ("query --db x --start z", "--start: invalid number \"z\""),
            ("query --db x --end z", "--end: invalid number \"z\""),
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
    fn vopr_runs_seeds_and_reports_failures() {
        let out = cmd("vopr --seeds 3 --start 10 --replicas 3 --ticks 300 --heal-ticks 300").unwrap();
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
        sweep("sweep-kv", |db| {
            format!("kv-bench --db {} --ops 40 --batch 8", db.display())
        });
        std::fs::remove_dir_all(&d).unwrap();
    }
}
