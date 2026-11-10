//! The `cargo xtask` pattern (<https://github.com/matklad/cargo-xtask>):
//! project automation written in Rust, run with `cargo xtask <task>` through
//! the alias in `.cargo/config.toml`.
//!
//! - `dev-check`: fails on the first failing step of `cargo fmt --check`, `cargo clippy -D warnings`
//!   and the coverage gate (`cargo llvm-cov --fail-under-lines 100 --fail-under-regions 100`),
//!   which runs every test, so there is no separate `cargo test` before it.
//!   `--no-coverage` replaces the gate with a plain `cargo test --workspace`;
//!   without it a missing cargo-llvm-cov is an error. CI runs it without flags.
//! - `kani`: proves the harnesses of the `proofs` crate (`cargo kani -p proofs`),
//!   with virtual memory capped at [`KANI_MEMORY_KIB`] (`ulimit -v`): a proof
//!   that blows up fails instead of driving the machine into the OOM killer.
//! - `bench`: generates a synthetic capture under `target/bench` and runs
//!   `bench parse-bench` on it in release mode; `--min-mpps` turns it into a
//!   regression gate.
//! - `vopr`: runs `bench vopr` in release mode: the deterministic Raft
//!   cluster simulation over many seeds, with crashes, torn writes, log bit
//!   flips, partitions and message faults, checking the safety properties
//!   after every event.
//!
//! xtask never installs or touches git hooks.
//!
//! The cargo used can be overridden with `XTASK_CARGO` (the tests point it at
//! a fake, so they never recurse into real builds).

use std::path::{Path, PathBuf};
use std::process::Command;

pub const USAGE: &str = "\
usage: cargo xtask <task>

tasks:
  dev-check [--no-coverage]  fmt --check, clippy -D warnings, the tests under a 100% coverage
                             gate (--no-coverage: the tests alone)
  kani                       run the kani proofs (cargo kani -p proofs), memory capped at 8 GiB
  bench [--packets N] [--min-mpps X]
                             generate a synthetic capture (default 4800000 packets, about
                             3.6 GB) in target/bench and benchmark parsing it (release build)
  vopr [--seeds N] [--start N] [--replicas N]
                             simulate Raft clusters under faults for N seeds (default 200,
                             release build); a failing seed prints how to replay it
";

/// Default number of seeds of `cargo xtask vopr`.
pub const VOPR_SEEDS: u64 = 200;

/// Default capture size of `cargo xtask bench`: about 3.6 GB.
pub const BENCH_PACKETS: u64 = 4_800_000;

/// Where `cargo xtask bench` writes its capture, relative to the root.
pub const BENCH_DIR: &str = "target/bench";
pub const BENCH_CAPTURE: &str = "target/bench/capture.pcap";

/// Virtual memory cap for `cargo kani` and everything it spawns (CBMC).
/// Every harness verifies in well under 1 GiB.
pub const KANI_MEMORY_KIB: u64 = 8 * 1024 * 1024;

pub const NO_LLVM_COV: &str = "cargo-llvm-cov is not installed: run `rustup component add llvm-tools-preview && \
cargo install cargo-llvm-cov`, or pass --no-coverage to skip the coverage gate";

pub const NO_KANI: &str = "cargo-kani is not installed: run `cargo install --locked kani-verifier && cargo kani setup`";

/// Where and with which cargo tasks run.
pub struct Ctx {
    pub cargo: String,
    pub root: PathBuf,
}

impl Ctx {
    /// `XTASK_CARGO` (else `CARGO`, else `cargo`), rooted at the workspace.
    ///
    /// The root comes from `CARGO_MANIFEST_DIR` as set by `cargo run` at run
    /// time; the compile-time value is only a fallback, because cargo does not
    /// rebuild when the checkout is moved or renamed, which would leave a
    /// stale, nonexistent path baked into the binary.
    pub fn from_env() -> Ctx {
        let var = |k: &str| std::env::var(k);
        let manifest_dir =
            PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap_or(env!("CARGO_MANIFEST_DIR").into()));
        Ctx {
            cargo: var("XTASK_CARGO")
                .or_else(|_| var("CARGO"))
                .unwrap_or(String::from("cargo")),
            root: manifest_dir.parent().unwrap_or(Path::new(".")).to_path_buf(),
        }
    }

    /// Runs cargo with `args`, under `ulimit -v memory_kib` if given.
    fn cargo(&self, args: &[&str], memory_kib: Option<u64>) -> Result<bool, String> {
        let mut cmd = match memory_kib {
            None => Command::new(&self.cargo),
            Some(kib) => {
                let mut sh = Command::new("sh");
                sh.args(["-c", &format!("ulimit -v {kib} && exec \"$0\" \"$@\""), &self.cargo]);
                sh
            }
        };
        cmd.args(args)
            .current_dir(&self.root)
            .status()
            .map(|s| s.success())
            .map_err(|e| format!("cannot run {} in {}: {e}", self.cargo, self.root.display()))
    }

    /// Runs one step, failing with the command line.
    fn step(&self, args: &[&str]) -> Result<(), String> {
        self.step_limited(args, None)
    }

    /// Like [`Ctx::step`], with virtual memory capped at `memory_kib`.
    fn step_limited(&self, args: &[&str], memory_kib: Option<u64>) -> Result<(), String> {
        let limit = memory_kib.map_or(String::new(), |kib| format!(" (memory limit {kib} KiB)"));
        println!("xtask: cargo {}{limit}", args.join(" "));
        match self.cargo(args, memory_kib)? {
            true => Ok(()),
            false => Err(format!("`cargo {}` failed{limit}", args.join(" "))),
        }
    }

    /// Whether the cargo subcommand `sub` is installed.
    fn has(&self, sub: &str) -> Result<bool, String> {
        self.cargo(&[sub, "--version"], None)
    }
}

pub fn dev_check(ctx: &Ctx, no_coverage: bool) -> Result<String, String> {
    if !no_coverage && !ctx.has("llvm-cov")? {
        return Err(NO_LLVM_COV.into());
    }
    ctx.step(&["fmt", "--all", "--", "--check"])?;
    ctx.step(&["clippy", "--workspace", "--all-targets", "--", "-D", "warnings"])?;
    if no_coverage {
        ctx.step(&["test", "--workspace"])?;
        return Ok("dev-check passed (coverage gate skipped)\n".into());
    }
    // The gate runs every test (and fails on a failing one): a plain run
    // before it would only build and run them a second time. (There are no
    // doctests, which coverage does not run: if one is added, so must a
    // `cargo test --doc` step be.)
    ctx.step(&[
        "llvm-cov",
        "--workspace",
        "--fail-under-lines",
        "100",
        "--fail-under-regions",
        "100",
    ])?;
    Ok("dev-check passed: fmt, clippy, tests, 100% line and region coverage\n".into())
}

pub fn kani(ctx: &Ctx) -> Result<String, String> {
    if !ctx.has("kani")? {
        return Err(NO_KANI.into());
    }
    ctx.step_limited(&["kani", "-p", "proofs"], Some(KANI_MEMORY_KIB))?;
    Ok("kani: all proof harnesses verified\n".into())
}

pub fn bench(ctx: &Ctx, args: &[&str]) -> Result<String, String> {
    let mut packets = BENCH_PACKETS.to_string();
    let mut min_mpps = None;
    let mut it = args.iter();
    while let Some(&flag) = it.next() {
        let value = it.next().ok_or(format!("{flag} needs a value"))?;
        match flag {
            "--packets" if value.parse::<u64>().is_ok() => packets = value.to_string(),
            "--min-mpps" if value.parse::<f64>().is_ok() => min_mpps = Some(*value),
            "--packets" | "--min-mpps" => return Err(format!("{flag}: invalid number {value:?}")),
            _ => return Err(format!("unknown bench flag {flag}\n\n{USAGE}")),
        }
    }
    let dir = ctx.root.join(BENCH_DIR);
    std::fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let run = ["run", "--release", "-q", "-p", "lumen-bench", "--"];
    let gen = ["gen-pcap", BENCH_CAPTURE, "--packets", &packets, "--flows", "5000"];
    ctx.step(&[&run[..], &gen].concat())?;
    let mut parse = vec!["parse-bench", BENCH_CAPTURE, "--runs", "5"];
    parse.extend(min_mpps.iter().flat_map(|m| ["--min-mpps", m]));
    ctx.step(&[&run[..], &parse].concat())?;
    Ok("bench: done\n".into())
}

pub fn vopr(ctx: &Ctx, args: &[&str]) -> Result<String, String> {
    let seeds = VOPR_SEEDS.to_string();
    let mut flags = vec![("--seeds", seeds.as_str()), ("--start", "0")];
    let mut it = args.iter();
    while let Some(&flag) = it.next() {
        let value = it.next().ok_or(format!("{flag} needs a value"))?;
        if value.parse::<u64>().is_err() {
            return Err(format!("{flag}: invalid number {value:?}"));
        }
        match flags.iter_mut().find(|(f, _)| *f == flag) {
            Some(slot) => slot.1 = value,
            None if flag == "--replicas" => flags.push((flag, value)),
            None => return Err(format!("unknown vopr flag {flag}\n\n{USAGE}")),
        }
    }
    let mut cmd = vec!["run", "--release", "-q", "-p", "lumen-bench", "--", "vopr"];
    cmd.extend(flags.iter().flat_map(|&(f, v)| [f, v]));
    ctx.step(&cmd)?;
    Ok("vopr: all safety properties held\n".into())
}

/// Runs `args` (without the program name); returns the text to print.
pub fn run(args: &[String], ctx: &Ctx) -> Result<String, String> {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        [] | ["help"] => Ok(USAGE.into()),
        ["dev-check"] => dev_check(ctx, false),
        ["dev-check", "--no-coverage"] => dev_check(ctx, true),
        ["kani"] => kani(ctx),
        ["bench", rest @ ..] => bench(ctx, rest),
        ["vopr", rest @ ..] => vopr(ctx, rest),
        _ => Err(format!("unknown task {args:?}\n\n{USAGE}")),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::fs::{self, Permissions};
    use std::os::unix::fs::PermissionsExt;

    /// Tests write executable scripts and spawn processes: a fork in one
    /// thread while another holds a script open for writing makes exec fail
    /// with ETXTBSY, so these tests run one at a time.
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    pub(crate) fn serial() -> std::sync::MutexGuard<'static, ()> {
        SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(crate) fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("xtask-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    /// An executable shell script at `dir/name`.
    pub(crate) fn script(dir: &Path, name: &str, body: &str) -> String {
        let p = dir.join(name);
        fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&p, Permissions::from_mode(0o755)).unwrap();
        p.display().to_string()
    }

    /// Fake cargo logging its arguments, failing when they match `fail`
    /// (a shell `case` pattern).
    fn ctx(dir: &Path, fail: &str) -> Ctx {
        let log = dir.join("log");
        let cargo = script(
            dir,
            "cargo",
            &format!("echo \"$*\" >> {}\ncase \"$*\" in {fail}) exit 1;; esac", log.display()),
        );
        Ctx {
            cargo,
            root: dir.to_path_buf(),
        }
    }

    fn log(dir: &Path) -> String {
        fs::read_to_string(dir.join("log")).unwrap_or_default()
    }

    fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }

    #[test]
    fn dev_check_runs_every_step() {
        let _serial = serial();
        let d = tmp("ok");
        let c = ctx(&d, "never");
        let out = run(&args("dev-check"), &c).unwrap();
        assert!(out.contains("100% line and region coverage") && !out.contains("hook"));
        assert_eq!(
            log(&d),
            "llvm-cov --version\nfmt --all -- --check\nclippy --workspace --all-targets -- -D warnings\n\
             llvm-cov --workspace --fail-under-lines 100 --fail-under-regions 100\n"
        );
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn dev_check_stops_at_the_first_failure() {
        let _serial = serial();
        for (fail, want) in [
            ("fmt*", "`cargo fmt --all -- --check` failed"),
            (
                "clippy*",
                "`cargo clippy --workspace --all-targets -- -D warnings` failed",
            ),
            (
                "llvm-cov\\ --workspace*",
                "`cargo llvm-cov --workspace --fail-under-lines 100 --fail-under-regions 100` failed",
            ),
            ("llvm-cov\\ --version", NO_LLVM_COV),
        ] {
            let d = tmp("fail");
            assert_eq!(run(&args("dev-check"), &ctx(&d, fail)).unwrap_err(), want);
            fs::remove_dir_all(&d).unwrap();
        }
    }

    #[test]
    fn no_coverage_skips_the_gate() {
        let _serial = serial();
        let d = tmp("nocov");
        let out = run(&args("dev-check --no-coverage"), &ctx(&d, "llvm-cov*")).unwrap();
        assert!(out.contains("coverage gate skipped"));
        assert!(!log(&d).contains("llvm-cov"));
        assert!(log(&d).ends_with("clippy --workspace --all-targets -- -D warnings\ntest --workspace\n"));
        fs::remove_dir_all(&d).unwrap();
        // Without the gate, the tests are run on their own.
        let d = tmp("nocov-fail");
        let e = run(&args("dev-check --no-coverage"), &ctx(&d, "test*")).unwrap_err();
        assert_eq!(e, "`cargo test --workspace` failed");
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn kani_task() {
        let _serial = serial();
        let d = tmp("kani");
        assert_eq!(
            run(&args("kani"), &ctx(&d, "never")).unwrap(),
            "kani: all proof harnesses verified\n"
        );
        assert_eq!(log(&d), "kani --version\nkani -p proofs\n");
        assert_eq!(run(&args("kani"), &ctx(&d, "kani\\ --version")).unwrap_err(), NO_KANI);
        assert_eq!(
            run(&args("kani"), &ctx(&d, "kani\\ -p*")).unwrap_err(),
            "`cargo kani -p proofs` failed (memory limit 8388608 KiB)"
        );
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn kani_runs_under_the_memory_limit() {
        let _serial = serial();
        let d = tmp("kani-limit");
        let limits = d.join("limits");
        let cargo = script(
            &d,
            "cargo",
            &format!("echo \"$* $(ulimit -v)\" >> {}", limits.display()),
        );
        let c = Ctx { cargo, root: d.clone() };
        run(&args("kani"), &c).unwrap();
        let limits = fs::read_to_string(limits).unwrap();
        let lines: Vec<&str> = limits.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("kani --version "));
        assert_eq!(lines[1], format!("kani -p proofs {KANI_MEMORY_KIB}"));
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn bench_generates_then_parses() {
        let _serial = serial();
        let d = tmp("bench");
        let r = "run --release -q -p lumen-bench --";
        assert_eq!(run(&args("bench"), &ctx(&d, "never")).unwrap(), "bench: done\n");
        assert!(d.join(BENCH_DIR).is_dir());
        assert_eq!(
            log(&d),
            format!(
                "{r} gen-pcap {BENCH_CAPTURE} --packets {BENCH_PACKETS} --flows 5000\n\
                 {r} parse-bench {BENCH_CAPTURE} --runs 5\n"
            )
        );
        fs::remove_dir_all(&d).unwrap();
        let d = tmp("bench-flags");
        run(&args("bench --packets 10 --min-mpps 2.5"), &ctx(&d, "never")).unwrap();
        assert_eq!(
            log(&d),
            format!(
                "{r} gen-pcap {BENCH_CAPTURE} --packets 10 --flows 5000\n\
                 {r} parse-bench {BENCH_CAPTURE} --runs 5 --min-mpps 2.5\n"
            )
        );
        for (fail, want) in [("*gen-pcap*", "gen-pcap"), ("*parse-bench*", "parse-bench")] {
            let e = run(&args("bench"), &ctx(&d, fail)).unwrap_err();
            assert!(e.starts_with("`cargo run") && e.contains(want), "{e}");
        }
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn bench_argument_errors() {
        let _serial = serial();
        let d = tmp("bench-args");
        let c = ctx(&d, "never");
        for (a, want) in [
            ("bench --packets", "--packets needs a value"),
            ("bench --packets x", "--packets: invalid number \"x\""),
            ("bench --min-mpps x", "--min-mpps: invalid number \"x\""),
        ] {
            assert_eq!(run(&args(a), &c).unwrap_err(), want);
        }
        assert!(run(&args("bench --runs 3"), &c)
            .unwrap_err()
            .starts_with("unknown bench flag --runs"));
        assert_eq!(log(&d), "");
        // The root is a file: the capture directory cannot be created.
        let file = d.join("file");
        fs::write(&file, "").unwrap();
        let c = Ctx { root: file, ..c };
        assert!(run(&args("bench"), &c).unwrap_err().starts_with("cannot create"));
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn vopr_runs_the_simulator_in_release_mode() {
        let _serial = serial();
        let d = tmp("vopr");
        let r = "run --release -q -p lumen-bench -- vopr";
        assert_eq!(
            run(&args("vopr"), &ctx(&d, "never")).unwrap(),
            "vopr: all safety properties held\n"
        );
        assert_eq!(log(&d), format!("{r} --seeds {VOPR_SEEDS} --start 0\n"));
        fs::remove_dir_all(&d).unwrap();
        let d = tmp("vopr-flags");
        run(&args("vopr --replicas 3 --start 40 --seeds 7"), &ctx(&d, "never")).unwrap();
        assert_eq!(log(&d), format!("{r} --seeds 7 --start 40 --replicas 3\n"));
        assert_eq!(
            run(&args("vopr"), &ctx(&d, "*vopr*")).unwrap_err(),
            format!("`cargo {r} --seeds {VOPR_SEEDS} --start 0` failed")
        );
        for (a, want) in [
            ("vopr --seeds", "--seeds needs a value"),
            ("vopr --seeds x", "--seeds: invalid number \"x\""),
            ("vopr --replicas -1", "--replicas: invalid number \"-1\""),
        ] {
            assert_eq!(run(&args(a), &ctx(&d, "never")).unwrap_err(), want);
        }
        assert!(run(&args("vopr --ticks 3"), &ctx(&d, "never"))
            .unwrap_err()
            .starts_with("unknown vopr flag --ticks"));
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn missing_cargo() {
        let _serial = serial();
        let d = tmp("missing");
        let c = Ctx {
            cargo: "/nonexistent/cargo".into(),
            ..ctx(&d, "never")
        };
        assert!(run(&args("kani"), &c).unwrap_err().starts_with("cannot run"));
        assert!(run(&args("dev-check"), &c).unwrap_err().starts_with("cannot run"));
        assert!(run(&args("dev-check --no-coverage"), &c)
            .unwrap_err()
            .starts_with("cannot run"));
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn usage_and_unknown_tasks() {
        let _serial = serial();
        let d = tmp("usage");
        let c = ctx(&d, "never");
        assert_eq!(run(&[], &c).unwrap(), USAGE);
        assert_eq!(run(&args("help"), &c).unwrap(), USAGE);
        assert!(run(&args("deploy"), &c).unwrap_err().starts_with("unknown task"));
        assert!(run(&args("install-hook"), &c).unwrap_err().starts_with("unknown task"));
        let real = Ctx::from_env();
        assert!(real.root.join("Cargo.toml").exists());
        fs::remove_dir_all(&d).unwrap();
    }
}
