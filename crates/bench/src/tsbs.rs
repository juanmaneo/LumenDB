//! `tsdb-bench` and `gen-cpu`: a workload in the style of TSBS (the Time
//! Series Benchmark Suite) "cpu-only" use case. Every host reports ten CPU
//! gauges every `--interval`, as a random walk that stays between 0 and 100.
//! The generator is deterministic, so `gen-cpu` writes exactly the line
//! protocol that `tsdb-bench` ingests, and another database can be given the
//! same data to compare with.

use crate::{db_options, open_db, secs, Args, Res};
use std::fmt::Write as _;
use std::fs::File;
use std::io::{BufWriter, Write as _};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Instant;
use tsvdb::partition::HOUR_NS;
use tsvdb::{Agg, Db, Query};

/// 2016-01-01T00:00:00Z, where TSBS starts too.
const START_NS: i64 = 1_451_606_400_000_000_000;
const MINUTE_NS: i64 = 60_000_000_000;

pub(crate) const FIELDS: [&str; 10] = [
    "usage_user",
    "usage_system",
    "usage_idle",
    "usage_nice",
    "usage_iowait",
    "usage_irq",
    "usage_softirq",
    "usage_steal",
    "usage_guest",
    "usage_guest_nice",
];

/// The flags that describe the data (`tsdb-bench` and `gen-cpu`).
pub(crate) const DATA_FLAGS: [&str; 4] = ["hosts", "hours", "interval", "seed"];

struct Workload {
    hosts: u64,
    /// Readings per host.
    steps: u64,
    interval: i64,
    seed: u64,
}

impl Workload {
    fn from_args(a: &Args) -> Res<Workload> {
        let hosts = a.num::<u32>("hosts", 100)?;
        let hours = a.num::<u16>("hours", 24)?;
        let interval = a.duration("interval")?.unwrap_or(10_000_000_000);
        if (hosts == 0) | (hours == 0) | (interval <= 0) {
            return Err("--hosts, --hours and --interval must be more than 0".into());
        }
        Ok(Workload {
            hosts: u64::from(hosts),
            steps: (i64::from(hours) * HOUR_NS / interval).max(1) as u64,
            interval,
            seed: a.num("seed", 42)?,
        })
    }

    fn rows(&self) -> u64 {
        self.hosts * self.steps
    }
}

/// Line protocol for the workload, in time order and, at one time, host order.
struct Gen<'a> {
    w: &'a Workload,
    next: u64,
    rng: u64,
    /// The ten gauges of every host.
    walk: Vec<[f64; FIELDS.len()]>,
}

impl<'a> Gen<'a> {
    fn new(w: &'a Workload) -> Gen<'a> {
        Gen {
            w,
            next: 0,
            rng: w.seed | 1,
            walk: vec![[50.0; FIELDS.len()]; w.hosts as usize],
        }
    }

    fn done(&self) -> bool {
        self.next >= self.w.rows()
    }

    /// xorshift64*, as a number in [0, 1).
    fn random(&mut self) -> f64 {
        self.rng ^= self.rng >> 12;
        self.rng ^= self.rng << 25;
        self.rng ^= self.rng >> 27;
        (self.rng.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 11) as f64 / (1u64 << 53) as f64
    }

    /// Appends up to `rows` lines to `out`; returns how many.
    fn batch(&mut self, rows: usize, out: &mut String) -> usize {
        let end = self.w.rows().min(self.next + rows as u64);
        let made = (end - self.next) as usize;
        while self.next < end {
            let (host, step) = (self.next % self.w.hosts, self.next / self.w.hosts);
            let _ = write!(
                out,
                "cpu,datacenter=dc_{},hostname=host_{host},region=region_{} ",
                host % 20,
                host % 5
            );
            for (i, name) in FIELDS.iter().enumerate() {
                let step_by = self.random() * 2.0 - 1.0;
                let gauge = &mut self.walk[host as usize][i];
                *gauge = (*gauge + step_by).clamp(0.0, 100.0);
                let _ = write!(out, "{}{name}={gauge:.4}", if i == 0 { "" } else { "," });
            }
            let _ = writeln!(out, " {}", START_NS + step as i64 * self.w.interval);
            self.next += 1;
        }
        made
    }
}

pub(crate) fn gen_cpu(a: &Args) -> Res<String> {
    a.check(&DATA_FLAGS)?;
    let path = a.pos(1, "output file")?;
    let w = Workload::from_args(a)?;
    let t = Instant::now();
    let mut out = BufWriter::new(File::create(path)?);
    let (mut gen, mut text, mut bytes) = (Gen::new(&w), String::new(), 0);
    while !gen.done() {
        text.clear();
        gen.batch(5000, &mut text);
        out.write_all(text.as_bytes())?;
        bytes += text.len();
    }
    out.flush()?;
    Ok(format!(
        "wrote {} rows ({bytes} bytes) to {path} in {:.1} ms\n",
        w.rows(),
        secs(t.elapsed()) * 1e3
    ))
}

/// A named group of queries that are timed together (TSBS runs one query per
/// reading of all ten gauges, so those groups have ten).
struct Case {
    name: &'static str,
    queries: Vec<Query>,
}

fn cases(w: &Workload) -> Vec<Case> {
    let host = format!("host_{}", w.hosts / 2);
    let hours = |n: i64| (START_NS, START_NS + n * HOUR_NS);
    let one_host = |q: Query| q.filter("hostname", host.clone());
    let per_field =
        |f: &dyn Fn(Query) -> Query| -> Vec<Query> { FIELDS.iter().map(|name| f(Query::new("cpu", *name))).collect() };
    let (from, to) = hours(1);
    let (from12, to12) = hours(12);
    let (from8, to8) = hours(8);
    let max_per_minute = |q: Query| q.agg(Agg::Max).every(MINUTE_NS);
    vec![
        Case {
            name: "single-groupby-1-1-1",
            queries: vec![max_per_minute(one_host(Query::new("cpu", FIELDS[0]))).range(from, to)],
        },
        Case {
            name: "single-groupby-1-1-12",
            queries: vec![max_per_minute(one_host(Query::new("cpu", FIELDS[0]))).range(from12, to12)],
        },
        Case {
            name: "cpu-max-all-1",
            queries: per_field(&|q| one_host(q).range(from8, to8).agg(Agg::Max).every(HOUR_NS)),
        },
        Case {
            name: "double-groupby-1",
            queries: vec![Query::new("cpu", FIELDS[0])
                .range(from12, to12)
                .agg(Agg::Mean)
                .every(HOUR_NS)],
        },
        Case {
            name: "double-groupby-all",
            queries: per_field(&|q| q.range(from12, to12).agg(Agg::Mean).every(HOUR_NS)),
        },
        Case {
            name: "lastpoint",
            queries: per_field(&|q| q.latest()),
        },
        Case {
            name: "sum-everything-1",
            queries: vec![Query::new("cpu", FIELDS[0]).agg(Agg::Sum)],
        },
        Case {
            name: "sum-everything-all",
            queries: per_field(&|q| q.agg(Agg::Sum)),
        },
    ]
}

/// The best and the median of `times` (seconds).
fn best_and_median(mut times: Vec<f64>) -> (f64, f64) {
    times.sort_by(f64::total_cmp);
    (times[0], times[times.len() / 2])
}

/// Runs a case `runs` times: a line with its timings, or the first error.
fn run_case(db: &Db, case: &Case, runs: usize) -> Res<String> {
    (0..runs)
        .map(|_| {
            let t = Instant::now();
            let rows = case
                .queries
                .iter()
                .map(|q| db.query(q).map(|r| r.len()))
                .sum::<tsvdb::Result<usize>>();
            rows.map(|n| (secs(t.elapsed()), n))
        })
        .collect::<tsvdb::Result<Vec<_>>>()
        .map(|runs| {
            let rows = runs[0].1;
            let (best, median) = best_and_median(runs.into_iter().map(|r| r.0).collect());
            format!(
                "  {:<24} best {:>10.3} ms   median {:>10.3} ms   {rows} rows\n",
                case.name,
                best * 1e3,
                median * 1e3
            )
        })
        .map_err(Into::into)
}

/// The size of the files in `dir`.
fn disk_bytes(dir: &str) -> u64 {
    let files = std::fs::read_dir(Path::new(dir)).into_iter().flatten().flatten();
    files.filter_map(|f| f.metadata().ok()).map(|m| m.len()).sum()
}

pub(crate) fn tsdb_bench(a: &Args) -> Res<String> {
    a.check(
        &[
            &DATA_FLAGS[..],
            &["batch", "runs", "flush-points", "ingest", "threads", "only", "writers"],
        ]
        .concat(),
    )?;
    let w = Workload::from_args(a)?;
    let batch = a.num::<usize>("batch", 5000)?.max(1);
    let runs = a.num::<usize>("runs", 5)?;
    let ingest = a.num::<u64>("ingest", 1)? != 0;
    let only = a.get("only").unwrap_or("");
    let writers = a.num::<usize>("writers", 1)?.max(1);
    let (dir, mut opts) = db_options(a)?;
    opts.threads = a.num("threads", 0)?;
    let db = open_db((dir, opts))?;
    let mut gen = Gen::new(&w);
    if !ingest {
        gen.next = w.rows();
    }
    // The text is made first (it is not what is measured), then written by
    // --writers threads, each taking the next batch when it is free, like
    // that many clients of a server.
    let mut batches = Vec::new();
    while !gen.done() {
        let mut text = String::new();
        gen.batch(batch, &mut text);
        batches.push(text);
    }
    let t = Instant::now();
    let next = AtomicUsize::new(0);
    let failed: Mutex<Option<tsvdb::Error>> = Mutex::new(None);
    std::thread::scope(|scope| {
        for _ in 0..writers {
            scope.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                let Some(text) = batches.get(i) else { break };
                if let Err(e) = db.write_lines(text) {
                    *failed.lock().unwrap() = Some(e);
                    break;
                }
            });
        }
    });
    if let Some(e) = failed.into_inner().unwrap() {
        return Err(e.into());
    }
    let write = t.elapsed();
    let t = Instant::now();
    db.flush()?;
    let flush = t.elapsed();
    let (rows, values) = (w.rows(), w.rows() * FIELDS.len() as u64);
    let total = secs(write + flush);
    let stats = db.stats();
    let ingested = format!(
        "ingest: {:.1} ms: {:.0} rows/s, {:.2} M values/s\n\
         \x20 write_lines {:.1} ms on {writers} threads ({} of {} batches the fast way), final flush {:.1} ms; {} flushes, {} series, {} columns\n",
        total * 1e3,
        rows as f64 / total,
        values as f64 / total / 1e6,
        secs(write) * 1e3,
        stats.fast_writes,
        rows.div_ceil(batch as u64),
        secs(flush) * 1e3,
        stats.flushes,
        stats.series,
        stats.columns,
    );
    let out = format!(
        "{} hosts x {} gauges, {} readings each every {} ms: {rows} rows, {values} values, batch {batch}\n\
         {}queries (best of {runs} runs):\n",
        w.hosts,
        FIELDS.len(),
        w.steps,
        w.interval / 1_000_000,
        if ingest {
            ingested
        } else {
            "ingest: skipped\n".to_string()
        },
    );
    let queries = cases(&w)
        .iter()
        .filter(|c| (runs > 0) & c.name.contains(only))
        .map(|c| run_case(&db, c, runs))
        .collect::<Res<String>>();
    db.close()?;
    queries.map(|q| format!("{out}{}\ndisk: {} bytes\n", q.trim_end(), disk_bytes(dir)))
}

#[cfg(test)]
mod tests {
    use crate::run;

    fn cmd(s: &str) -> crate::Res<String> {
        run(&s.split_whitespace().map(String::from).collect::<Vec<_>>())
    }

    #[test]
    fn generator_is_deterministic_and_complete() {
        let d = std::env::temp_dir().join(format!("bench-{}-gen-cpu", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let (a, b) = (d.join("a.lp"), d.join("b.lp"));
        let make = |f: &std::path::Path, seed: u32| {
            cmd(&format!(
                "gen-cpu {} --hosts 3 --hours 1 --interval 10m --seed {seed}",
                f.display()
            ))
            .unwrap()
        };
        assert!(make(&a, 1).starts_with("wrote 18 rows ("));
        make(&b, 1);
        let text = std::fs::read_to_string(&a).unwrap();
        assert_eq!(text, std::fs::read_to_string(&b).unwrap());
        assert_eq!(text.lines().count(), 18);
        let first = text.lines().next().unwrap();
        assert!(first.starts_with("cpu,datacenter=dc_0,hostname=host_0,region=region_0 usage_user="));
        assert!(first.ends_with(" 1451606400000000000"));
        // Time order, then host order; every value in [0, 100].
        assert!(text.lines().nth(3).unwrap().contains("hostname=host_0,"));
        assert!(text.lines().nth(3).unwrap().ends_with(" 1451607000000000000"));
        let points = tsvdb::lineproto::parse(&text).unwrap();
        assert_eq!(points.len(), 18);
        for p in &points {
            assert_eq!(p.fields.len(), 10);
            for v in p.fields.values() {
                assert!((0.0..=100.0).contains(&v.as_f64().unwrap()));
            }
        }
        // Another seed, other values.
        make(&b, 2);
        assert_ne!(text, std::fs::read_to_string(&b).unwrap());
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn bad_arguments() {
        let err = |s: &str| cmd(s).unwrap_err().to_string();
        for (args, want) in [
            ("gen-cpu", "missing output file"),
            ("gen-cpu f --x 1", "unknown flag --x"),
            (
                "gen-cpu f --hosts 0",
                "--hosts, --hours and --interval must be more than 0",
            ),
            (
                "gen-cpu f --hours 0",
                "--hosts, --hours and --interval must be more than 0",
            ),
            (
                "gen-cpu f --interval 0s",
                "--hosts, --hours and --interval must be more than 0",
            ),
            ("gen-cpu f --hosts z", "--hosts: invalid number \"z\""),
            ("gen-cpu f --hours 99999", "--hours: invalid number \"99999\""),
            ("gen-cpu f --interval soon", "--interval: invalid duration \"soon\""),
            ("gen-cpu f --seed z", "--seed: invalid number \"z\""),
            ("tsdb-bench --x 1", "unknown flag --x"),
            ("tsdb-bench", "missing --db"),
            ("tsdb-bench --db x --batch z", "--batch: invalid number \"z\""),
            ("tsdb-bench --db x --runs z", "--runs: invalid number \"z\""),
            ("tsdb-bench --db x --ingest z", "--ingest: invalid number \"z\""),
            ("tsdb-bench --db x --threads z", "--threads: invalid number \"z\""),
            ("tsdb-bench --db x --writers z", "--writers: invalid number \"z\""),
            (
                "tsdb-bench --db x --hosts 0",
                "--hosts, --hours and --interval must be more than 0",
            ),
            (
                "tsdb-bench --db x --flush-points z",
                "--flush-points: invalid number \"z\"",
            ),
        ] {
            assert_eq!(err(args), want, "{args}");
        }
        // Not a place a file can be made.
        assert!(cmd("gen-cpu /nonexistent-dir/x.lp").is_err());
        // A full disk (/dev/full), when a batch is written and when the last bytes are.
        assert!(cmd("gen-cpu /dev/full --hosts 100 --hours 1").is_err());
        assert!(cmd("gen-cpu /dev/full --hosts 1 --hours 1 --interval 1h").is_err());
    }

    #[test]
    fn benchmark_reports_every_case() {
        let d = std::env::temp_dir().join(format!("bench-{}-tsdb-bench", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let out = cmd(&format!(
            "tsdb-bench --db {} --hosts 4 --hours 2 --interval 1m --batch 50 --runs 2 --flush-points 400 --sync 0",
            d.display()
        ))
        .unwrap();
        assert!(
            out.starts_with("4 hosts x 10 gauges, 120 readings each every 60000 ms: 480 rows, 4800 values, batch 50\n")
        );
        for name in [
            "single-groupby-1-1-1 ",
            "single-groupby-1-1-12",
            "cpu-max-all-1",
            "double-groupby-1",
            "double-groupby-all",
            "lastpoint",
            "sum-everything-1",
            "sum-everything-all",
        ] {
            assert!(out.contains(&format!("  {name}")), "{name} in {out}");
        }
        // Per minute for the host over the 120 minutes there are: 60 rows in
        // the first hour; one row per host and hour (two hours); 10 fields.
        assert!(out.contains("   60 rows\n"), "{out}");
        assert!(out.contains("   120 rows\n"), "{out}");
        assert!(out.contains("   40 rows\n"), "{out}");
        assert!(out.contains("   8 rows\n"), "{out}");
        assert!(out.contains("\ndisk: "), "{out}");
        // Queries on what is there: the same rows, and no ingestion.
        let again = cmd(&format!(
            "tsdb-bench --db {} --hosts 4 --hours 2 --interval 1m --runs 1 --ingest 0 --sync 0",
            d.display()
        ))
        .unwrap();
        assert!(
            again.contains("\ningest: skipped\nqueries (best of 1 runs):\n"),
            "{again}"
        );
        assert!(
            again.contains("   120 rows\n") && again.contains("   40 rows\n"),
            "{again}"
        );
        std::fs::remove_dir_all(&d).unwrap();
        // Several writers, and a failure of one of them (a database that is poisoned).
        let out = cmd(&format!(
            "tsdb-bench --db {} --hosts 4 --hours 2 --interval 1m --batch 50 --runs 1 --writers 3 --sync 0",
            d.display()
        ))
        .unwrap();
        assert!(out.contains(" on 3 threads ("), "{out}");
        assert!(out.contains("   120 rows\n"), "{out}");
        std::fs::remove_dir_all(&d).unwrap();
        for n in 0.. {
            let r = cmd(&format!(
                "tsdb-bench --db {}/w{n} --hosts 2 --hours 1 --interval 10m --batch 3 --runs 0 --writers 2 \
                 --flush-points 4 --background 0 --fail-after {n}",
                d.display()
            ));
            if r.is_ok() {
                break;
            }
        }
        std::fs::remove_dir_all(&d).unwrap();
        // One case.
        let one = cmd(&format!(
            "tsdb-bench --db {} --hosts 4 --hours 2 --interval 1m --runs 1 --ingest 0 --sync 0 --only lastpoint",
            d.display()
        ))
        .unwrap();
        assert!(one.contains("  lastpoint") && !one.contains("groupby"), "{one}");
        // No runs, no queries.
        let out = cmd(&format!(
            "tsdb-bench --db {} --hosts 2 --hours 1 --interval 10m --runs 0 --sync 0",
            d.display()
        ))
        .unwrap();
        assert!(out.contains("queries (best of 0 runs):\n\ndisk: "), "{out}");
        assert!(!out.contains("groupby"), "{out}");
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn storage_errors_surface() {
        let d = std::env::temp_dir().join(format!("bench-{}-tsdb-bench-sweep", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        for n in 0.. {
            let r = cmd(&format!(
                "tsdb-bench --db {}/db{n} --hosts 2 --hours 1 --interval 10m --batch 5 --runs 1 \
                 --flush-points 10 --background 0 --fail-after {n}",
                d.display()
            ));
            if r.is_ok() {
                break;
            }
        }
        std::fs::remove_dir_all(&d).unwrap();
    }
}
