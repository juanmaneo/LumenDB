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
//! - `release VERSION`: bumps the version of every crate, turns the
//!   `Unreleased` section of `CHANGELOG.md` into the section of VERSION (the
//!   commit subjects since the last release if nobody wrote one: generated
//!   notes are better than none), runs dev-check and a publish dry run, then
//!   commits and tags `vVERSION`.
//! - `publish`: `cargo publish` of every crate of the tagged HEAD, in
//!   dependency order ([`PUBLISH_ORDER`]). A version already on crates.io is
//!   skipped, so after crates.io's limit on new crates it is simply run again.
//!
//! xtask never installs or touches git hooks, and never pushes: `release`
//! and `publish` say what to push.
//!
//! The cargo used can be overridden with `XTASK_CARGO` (the tests point it at
//! a fake, so they never recurse into real builds), and git with `XTASK_GIT`.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

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
  release VERSION            bump every crate to VERSION, release the Unreleased section of
                             CHANGELOG.md (or the commit subjects since the last tag if it
                             is empty), run dev-check and a publish dry run, then commit
                             and tag vVERSION
  publish                    cargo publish every crate of the tagged HEAD, in dependency
                             order; versions already on crates.io are skipped, so it is run
                             again after crates.io's rate limit

Nothing is ever pushed: release and publish print the git push to run.
";

/// The crates published to crates.io, each after the ones it depends on.
pub const PUBLISH_ORDER: [&str; 7] = [
    "lumen-cpu",
    "lumen-flashkv",
    "pcapfast",
    "lumen-raft",
    "tsvdb",
    "lumen-cluster",
    "lumen-bench",
];

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
    pub git: String,
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
            git: var("XTASK_GIT").unwrap_or(String::from("git")),
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

    /// Runs cargo with `args`, showing its standard error as it comes:
    /// whether it succeeded, and that text.
    fn cargo_stderr(&self, args: &[&str]) -> Result<(bool, String), String> {
        let mut child = Command::new(&self.cargo)
            .args(args)
            .current_dir(&self.root)
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("cannot run {} in {}: {e}", self.cargo, self.root.display()))?;
        let mut text = String::new();
        let stderr = BufReader::new(child.stderr.take().expect("stderr is piped"));
        for line in stderr.lines().map_while(Result::ok) {
            eprintln!("{line}");
            text.push_str(&line);
            text.push('\n');
        }
        Ok((child.wait().is_ok_and(|s| s.success()), text))
    }

    /// Runs git with `args` in the root: its standard output.
    fn git(&self, args: &[&str]) -> Result<String, String> {
        let out = Command::new(&self.git)
            .args(args)
            .current_dir(&self.root)
            .output()
            .map_err(|e| format!("cannot run {}: {e}", self.git))?;
        match out.status.success() {
            true => Ok(String::from_utf8_lossy(&out.stdout).into_owned()),
            false => Err(format!(
                "`git {}` failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            )),
        }
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

/// `MAJOR.MINOR.PATCH`, if `v` is one.
fn parse_version(v: &str) -> Option<(u64, u64, u64)> {
    let mut parts = v.split('.').map(|p| p.parse::<u64>().ok());
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(Some(major)), Some(Some(minor)), Some(Some(patch)), None) => Some((major, minor, patch)),
        _ => None,
    }
}

/// The version in `[workspace.package]` of the root manifest.
fn workspace_version(manifest: &str) -> Option<&str> {
    let head = "[workspace.package]";
    let start = manifest.find(head)? + head.len();
    let end = manifest[start..].find("\n[").map_or(manifest.len(), |i| start + i);
    manifest[start..end]
        .lines()
        .find_map(|l| l.strip_prefix("version = \"")?.strip_suffix('"'))
}

/// The root manifest with version `old` replaced by `new`: the version of
/// the workspace, and the version required of each crate of the workspace
/// (the dependencies with a `path` in `crates/`).
fn bump_manifest(manifest: &str, old: &str, new: &str) -> String {
    let (from, to) = (format!("version = \"{old}\""), format!("version = \"{new}\""));
    let bump = |l: &str| match l == from || l.contains("path = \"crates/") {
        true => l.replace(&from, &to),
        false => l.to_string(),
    };
    manifest.lines().map(|l| bump(l) + "\n").collect()
}

/// The changelog with its `Unreleased` section released as `version` on
/// `date` (a new, empty `Unreleased` above it), and that section's notes.
/// An empty section is filled with `generated`.
fn release_changelog(text: &str, version: &str, date: &str, generated: &str) -> Result<(String, String), String> {
    let head = "## [Unreleased]\n";
    let start = text
        .find(head)
        .ok_or("CHANGELOG.md has no \"## [Unreleased]\" section")?
        + head.len();
    let end = text[start..].find("\n## [").map_or(text.len(), |i| start + i + 1);
    let notes = match text[start..end].trim() {
        "" => generated.trim(),
        written => written,
    };
    if notes.is_empty() {
        return Err(
            "nothing to release: the Unreleased section of CHANGELOG.md is empty, and nothing \
                    was committed since the last release"
                .into(),
        );
    }
    let released = format!(
        "{}\n## [{version}] - {date}\n\n{notes}\n\n{}",
        &text[..start],
        &text[end..]
    );
    Ok((released.trim_end().to_string() + "\n", notes.to_string()))
}

/// The UTC date `secs` seconds after 1970, as YYYY-MM-DD (Howard Hinnant's
/// `civil_from_days`).
fn date(secs: u64) -> String {
    let z = secs / 86_400 + 719_468;
    let (era, doe) = (z / 146_097, z % 146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

fn read(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))
}

/// Fails unless the working tree has no changes.
fn clean(ctx: &Ctx) -> Result<(), String> {
    let changes = ctx.git(&["status", "--porcelain"])?;
    changes.is_empty().then_some(()).ok_or(format!(
        "the working tree has changes: commit or stash them first\n{changes}"
    ))
}

pub fn release(ctx: &Ctx, args: &[&str]) -> Result<String, String> {
    let [version] = args else {
        return Err(format!("release needs the new version, like 0.2.0\n\n{USAGE}"));
    };
    let new = parse_version(version).ok_or(format!("invalid version {version:?}: expected MAJOR.MINOR.PATCH"))?;
    clean(ctx)?;
    let tag = format!("v{version}");
    if !ctx.git(&["tag", "--list", &tag])?.trim().is_empty() {
        return Err(format!("tag {tag} already exists"));
    }
    let (manifest_path, changelog_path) = (ctx.root.join("Cargo.toml"), ctx.root.join("CHANGELOG.md"));
    let manifest = read(&manifest_path)?;
    let old = workspace_version(&manifest).ok_or("Cargo.toml has no version in [workspace.package]")?;
    if parse_version(old).is_none_or(|o| o >= new) {
        return Err(format!("{version} does not come after the current version {old}"));
    }
    let changelog = read(&changelog_path)?;
    let since = ctx.git(&["log", "--format=- %s", &format!("v{old}..HEAD")])?;
    let today = date(SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs()));
    let (changelog, notes) = release_changelog(&changelog, version, &today, &since)?;
    let bumped = bump_manifest(&manifest, old, version);
    for (path, text) in [(&manifest_path, &bumped), (&changelog_path, &changelog)] {
        std::fs::write(path, text).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    }
    // (Cargo.lock follows the new version, and what is checked is what is
    // tagged.)
    ctx.step(&["update", "--workspace"])
        .and_then(|()| dev_check(ctx, false))
        .and_then(|_| ctx.step(&["publish", "--workspace", "--dry-run", "--allow-dirty"]))
        .map_err(|e| format!("{e}\n(the new version is left in the working tree: `git checkout -- .` undoes it)"))?;
    ctx.git(&["commit", "-q", "-a", "-m", &format!("Release {version}\n\n{notes}\n")])?;
    // (Verbatim: the default cleanup of a tag message drops the lines that
    // start with `#`, which are the headings of the notes.)
    ctx.git(&[
        "tag",
        "-a",
        "--cleanup=verbatim",
        &tag,
        "-m",
        &format!("LumenDB {version}\n\n{notes}\n"),
    ])?;
    Ok(format!(
        "released {version}: commit and tag {tag} made, nothing pushed\n\
         next: `cargo xtask publish`, then `git push origin HEAD {tag}`\n"
    ))
}

pub fn publish(ctx: &Ctx) -> Result<String, String> {
    let manifest = read(&ctx.root.join("Cargo.toml"))?;
    let version = workspace_version(&manifest).ok_or("Cargo.toml has no version in [workspace.package]")?;
    let tag = format!("v{version}");
    if !ctx.git(&["tag", "--points-at", "HEAD"])?.lines().any(|t| t == tag) {
        return Err(format!(
            "HEAD is not tagged {tag}: make the release with `cargo xtask release VERSION` first"
        ));
    }
    clean(ctx)?;
    let mut done = String::new();
    for name in PUBLISH_ORDER {
        println!("xtask: cargo publish -p {name}");
        let (ok, errors) = ctx.cargo_stderr(&["publish", "-p", name])?;
        if ok {
            done.push_str(&format!("{name} {version}: published\n"));
        } else if errors.contains("already exists") {
            done.push_str(&format!("{name} {version}: already on crates.io\n"));
        } else if errors.contains("status 429") {
            return Err(format!(
                "{done}{name}: crates.io limits how many new crates are published in a row; run \
                 `cargo xtask publish` again in about 10 minutes (what is published is skipped)"
            ));
        } else {
            return Err(format!("{done}`cargo publish -p {name}` failed"));
        }
    }
    Ok(format!(
        "{done}every crate of {tag} is on crates.io; push with `git push origin HEAD {tag}`\n"
    ))
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
        ["release", rest @ ..] => release(ctx, rest),
        ["publish"] => publish(ctx),
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
            git: "git".into(),
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
        let c = Ctx {
            cargo,
            git: "git".into(),
            root: d.clone(),
        };
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

    const MANIFEST: &str = r#"[workspace]
members = []

[workspace.package]
version = "0.1.0"
edition = "2021"

[workspace.dependencies]
cpu = { package = "lumen-cpu", path = "crates/cpu", version = "0.1.0" }
rand = { version = "0.1.0" }
memmap2 = "0.9"
"#;

    /// A changelog with notes written under Unreleased, and one without.
    const WRITTEN: &str =
        "# Changelog\n\n## [Unreleased]\n\n### Added\n\n- A thing.\n\n## [0.1.0] - 2026-11-10\n\nFirst.\n";
    const EMPTY: &str = "# Changelog\n\n## [Unreleased]\n\n## [0.1.0] - 2026-11-10\n\nFirst.\n";

    const DEV_CHECK_LOG: &str = "llvm-cov --version\nfmt --all -- --check\n\
         clippy --workspace --all-targets -- -D warnings\n\
         llvm-cov --workspace --fail-under-lines 100 --fail-under-regions 100\n";

    fn git(repo: &Path, args: &[&str]) -> String {
        let out = Command::new("git").args(args).current_dir(repo).output().unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "git {args:?}: {stderr}");
        String::from_utf8(out.stdout).unwrap()
    }

    /// A git repository `<tmp>/repo` holding MANIFEST and `changelog`, tagged
    /// v0.1.0, with a fake cargo (failing like [`ctx`]) next to it, outside the
    /// working tree.
    fn repo(name: &str, changelog: &str, fail: &str) -> (PathBuf, Ctx) {
        let d = tmp(name);
        let root = d.join("repo");
        fs::create_dir(&root).unwrap();
        git(&root, &["init", "-q"]);
        for (key, value) in [
            ("user.name", "test"),
            ("user.email", "test@example.com"),
            ("commit.gpgSign", "false"),
            ("tag.gpgSign", "false"),
            ("tag.forceSignAnnotated", "false"),
        ] {
            git(&root, &["config", key, value]);
        }
        fs::write(root.join("Cargo.toml"), MANIFEST).unwrap();
        fs::write(root.join("CHANGELOG.md"), changelog).unwrap();
        git(&root, &["add", "."]);
        git(&root, &["commit", "-q", "-m", "First"]);
        git(&root, &["tag", "v0.1.0"]);
        (d.clone(), Ctx { root, ..ctx(&d, fail) })
    }

    /// Commits `file` with `content`, or without the file.
    fn commit(root: &Path, file: &str, content: Option<&str>, subject: &str) {
        match content {
            Some(content) => fs::write(root.join(file), content).unwrap(),
            None => fs::remove_file(root.join(file)).unwrap(),
        }
        git(root, &["add", "-A"]);
        git(root, &["commit", "-q", "--allow-empty", "-m", subject]);
    }

    /// `c` with a git that first runs the shell `prelude`, in the repository,
    /// then is git.
    fn git_with(c: Ctx, prelude: &str) -> Ctx {
        let dir = c.root.parent().unwrap().to_path_buf();
        let git = script(&dir, "fakegit", &format!("{prelude}\nexec git \"$@\""));
        Ctx { git, ..c }
    }

    /// `c` with a git failing with "boom" when its arguments match `fail` (a
    /// shell `case` pattern).
    fn failing_git(c: Ctx, fail: &str) -> Ctx {
        git_with(c, &format!("case \"$*\" in {fail}) echo boom >&2; exit 1;; esac"))
    }

    /// `c` with a cargo that logs its arguments and answers the `case` arms
    /// `rules` (on the arguments) before succeeding.
    fn rules_cargo(c: Ctx, rules: &str) -> Ctx {
        let dir = c.root.parent().unwrap().to_path_buf();
        let body = format!(
            "echo \"$*\" >> {}\ncase \"$*\" in\n{rules}\n*) ;;\nesac",
            dir.join("log").display()
        );
        Ctx {
            cargo: script(&dir, "cargo", &body),
            ..c
        }
    }

    #[test]
    fn versions() {
        assert_eq!(parse_version("0.1.10"), Some((0, 1, 10)));
        for bad in ["", "1", "1.2", "1.2.3.4", "1.2.x", "v1.2.3", "1.2.-3", "1..3"] {
            assert_eq!(parse_version(bad), None, "{bad:?}");
        }
        // Versions compare by number, not by text.
        assert!(parse_version("0.1.10") > parse_version("0.1.9"));

        assert_eq!(workspace_version(MANIFEST), Some("0.1.0"));
        assert_eq!(
            workspace_version("[workspace.package]\nversion = \"2.0.0\"\n"),
            Some("2.0.0")
        );
        // Another section's version is not the workspace's.
        for manifest in [
            "[package]\nversion = \"9.9.9\"\n[workspace.package]\nedition = \"2021\"\n",
            "[workspace.package]\nedition = \"2021\"\n\n[other]\nversion = \"3.0.0\"\n",
            "[workspace]\nmembers = []\n",
            "",
        ] {
            assert_eq!(workspace_version(manifest), None, "{manifest:?}");
        }
    }

    #[test]
    fn bump_changes_the_workspace_and_its_crates_only() {
        let bumped = bump_manifest(MANIFEST, "0.1.0", "0.2.0");
        assert_eq!(
            bumped,
            MANIFEST
                .replace(
                    "[workspace.package]\nversion = \"0.1.0\"",
                    "[workspace.package]\nversion = \"0.2.0\""
                )
                .replace("crates/cpu\", version = \"0.1.0\"", "crates/cpu\", version = \"0.2.0\"")
        );
        // A foreign crate that happens to be at the same version keeps it.
        assert!(bumped.contains("rand = { version = \"0.1.0\" }\nmemmap2 = \"0.9\"\n"));
        assert_eq!(bump_manifest("a = 1", "0.1.0", "0.2.0"), "a = 1\n");
    }

    #[test]
    fn changelog_release() {
        let text = "# Changelog\n\n## [Unreleased]\n\n- new\n\n## [0.1.0] - 2026-11-10\n\nFirst.\n";
        let (out, notes) = release_changelog(text, "0.2.0", "2027-01-02", "- generated").unwrap();
        assert_eq!(notes, "- new");
        assert_eq!(
            out,
            "# Changelog\n\n## [Unreleased]\n\n## [0.2.0] - 2027-01-02\n\n- new\n\n## [0.1.0] - 2026-11-10\n\nFirst.\n"
        );
        // Nothing written: the generated notes are used.
        let (out, notes) = release_changelog(EMPTY, "0.2.0", "2027-01-02", "- gen\n").unwrap();
        assert_eq!(notes, "- gen");
        assert_eq!(
            out,
            "# Changelog\n\n## [Unreleased]\n\n## [0.2.0] - 2027-01-02\n\n- gen\n\n## [0.1.0] - 2026-11-10\n\nFirst.\n"
        );
        // Unreleased is the last section.
        let (out, _) = release_changelog("# C\n\n## [Unreleased]\n\n- new\n", "1.0.0", "2027-01-02", "").unwrap();
        assert_eq!(out, "# C\n\n## [Unreleased]\n\n## [1.0.0] - 2027-01-02\n\n- new\n");
        // Neither written nor generated: nothing to release.
        assert!(release_changelog(EMPTY, "0.2.0", "2027-01-02", " \n")
            .unwrap_err()
            .starts_with("nothing to release"));
        assert!(release_changelog("# Changelog\n", "0.2.0", "2027-01-02", "- x")
            .unwrap_err()
            .contains("no \"## [Unreleased]\" section"));
    }

    #[test]
    fn dates() {
        for (secs, want) in [
            (0, "1970-01-01"),
            (951_782_400, "2000-02-29"),
            (1_700_000_000, "2023-11-14"),
            (1_709_164_800, "2024-02-29"),
            (1_735_689_599, "2024-12-31"),
            (1_735_689_600, "2025-01-01"),
            (4_107_542_400, "2100-03-01"),
        ] {
            assert_eq!(date(secs), want);
        }
    }

    #[test]
    fn release_commits_and_tags() {
        let _serial = serial();
        let (d, c) = repo("rel", WRITTEN, "never");
        let out = run(&args("release 0.1.1"), &c).unwrap();
        assert!(out.starts_with("released 0.1.1") && out.contains("`git push origin HEAD v0.1.1`"));
        // What is checked is what is tagged: the lock file, the checks, the dry run.
        assert_eq!(
            log(&d),
            format!("update --workspace\n{DEV_CHECK_LOG}publish --workspace --dry-run --allow-dirty\n")
        );

        let manifest = fs::read_to_string(c.root.join("Cargo.toml")).unwrap();
        assert_eq!(workspace_version(&manifest), Some("0.1.1"));
        assert!(manifest.contains("crates/cpu\", version = \"0.1.1\" }"));
        assert!(manifest.contains("rand = { version = \"0.1.0\" }"));
        let changelog = fs::read_to_string(c.root.join("CHANGELOG.md")).unwrap();
        let (head, rest) = changelog.split_once("## [0.1.1] - ").unwrap();
        assert_eq!(head, "# Changelog\n\n## [Unreleased]\n\n");
        let (day, rest) = rest.split_at(10);
        assert!(day.starts_with("20") && day.matches('-').count() == 2, "{day}");
        assert_eq!(
            rest,
            "\n\n### Added\n\n- A thing.\n\n## [0.1.0] - 2026-11-10\n\nFirst.\n"
        );

        let r = &c.root;
        assert_eq!(git(r, &["rev-list", "--count", "HEAD"]), "2\n");
        assert_eq!(git(r, &["status", "--porcelain"]), "");
        assert_eq!(
            git(r, &["log", "-1", "--format=%B"]).trim(),
            "Release 0.1.1\n\n### Added\n\n- A thing."
        );
        assert_eq!(git(r, &["tag", "--points-at", "HEAD"]), "v0.1.1\n");
        assert_eq!(git(r, &["cat-file", "-t", "v0.1.1"]), "tag\n");
        assert_eq!(
            git(r, &["tag", "-l", "--format=%(contents)", "v0.1.1"]).trim(),
            "LumenDB 0.1.1\n\n### Added\n\n- A thing."
        );

        // And the tagged commit is what `publish` accepts.
        let out = run(&args("publish"), &c).unwrap();
        assert!(out.contains("every crate of v0.1.1 is on crates.io"), "{out}");
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn release_notes_default_to_the_commit_subjects() {
        let _serial = serial();
        let (d, c) = repo("rel-gen", EMPTY, "never");
        commit(&c.root, "a.txt", Some(""), "Faster CRC");
        commit(&c.root, "b.txt", Some(""), "Fix a leak");
        run(&args("release 0.2.0"), &c).unwrap();
        let changelog = fs::read_to_string(c.root.join("CHANGELOG.md")).unwrap();
        assert!(
            changelog.ends_with("\n\n- Fix a leak\n- Faster CRC\n\n## [0.1.0] - 2026-11-10\n\nFirst.\n"),
            "{changelog}"
        );
        assert!(git(&c.root, &["log", "-1", "--format=%B"]).starts_with("Release 0.2.0\n\n- Fix a leak\n- Faster CRC"));
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn release_refuses_what_it_cannot_do() {
        let _serial = serial();
        let (d, c) = repo("rel-refuse", WRITTEN, "never");
        let usage = "release needs the new version";
        assert!(run(&args("release"), &c).unwrap_err().starts_with(usage));
        assert!(run(&args("release 0.1.1 0.1.2"), &c).unwrap_err().starts_with(usage));
        for bad in ["1.2", "x", "1.2.3.4", "v1.2.3"] {
            let e = run(&args(&format!("release {bad}")), &c).unwrap_err();
            assert_eq!(e, format!("invalid version {bad:?}: expected MAJOR.MINOR.PATCH"));
        }
        // A version that was released.
        assert_eq!(
            run(&args("release 0.1.0"), &c).unwrap_err(),
            "tag v0.1.0 already exists"
        );
        git(&c.root, &["tag", "v0.3.0"]);
        assert_eq!(
            run(&args("release 0.3.0"), &c).unwrap_err(),
            "tag v0.3.0 already exists"
        );
        // One that does not come after the current one.
        assert_eq!(
            run(&args("release 0.0.9"), &c).unwrap_err(),
            "0.0.9 does not come after the current version 0.1.0"
        );
        git(&c.root, &["tag", "-d", "v0.1.0"]);
        assert_eq!(
            run(&args("release 0.1.0"), &c).unwrap_err(),
            "0.1.0 does not come after the current version 0.1.0"
        );
        // Uncommitted changes.
        fs::write(c.root.join("junk"), "").unwrap();
        let e = run(&args("release 0.1.1"), &c).unwrap_err();
        assert!(
            e.starts_with("the working tree has changes") && e.contains("junk"),
            "{e}"
        );
        // Nothing was run or touched.
        assert_eq!(log(&d), "");
        fs::remove_file(c.root.join("junk")).unwrap();
        assert_eq!(git(&c.root, &["status", "--porcelain"]), "");
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn release_needs_a_manifest_and_a_changelog_to_release() {
        let _serial = serial();
        let no_version = MANIFEST.replace("version = \"0.1.0\"\nedition", "edition");
        let bad_version = MANIFEST.replace("version = \"0.1.0\"\nedition", "version = \"x\"\nedition");
        let cases: [(&str, Option<&str>, &str); 6] = [
            ("Cargo.toml", None, "cannot read"),
            (
                "Cargo.toml",
                Some(&no_version),
                "Cargo.toml has no version in [workspace.package]",
            ),
            (
                "Cargo.toml",
                Some(&bad_version),
                "0.2.0 does not come after the current version x",
            ),
            ("CHANGELOG.md", None, "cannot read"),
            (
                "CHANGELOG.md",
                Some("# Changelog\n"),
                "CHANGELOG.md has no \"## [Unreleased]\" section",
            ),
            ("CHANGELOG.md", Some(WRITTEN), ""),
        ];
        for (file, content, want) in cases {
            let (d, c) = repo("rel-files", EMPTY, "never");
            commit(&c.root, file, content, "change");
            match want {
                "" => assert!(run(&args("release 0.2.0"), &c).is_ok()),
                _ => {
                    let e = run(&args("release 0.2.0"), &c).unwrap_err();
                    assert!(e.starts_with(want), "{file}: {e}");
                    // The edits are made only once everything is known to be in order.
                    assert_eq!(git(&c.root, &["status", "--porcelain"]), "");
                }
            }
            fs::remove_dir_all(&d).unwrap();
        }
        // No notes written, and nothing committed since the last release.
        let (d, c) = repo("rel-nothing", EMPTY, "never");
        let e = run(&args("release 0.2.0"), &c).unwrap_err();
        assert!(e.starts_with("nothing to release"), "{e}");
        assert_eq!(git(&c.root, &["status", "--porcelain"]), "");
        assert_eq!(log(&d), "");
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn a_failing_check_leaves_the_edits_uncommitted() {
        let _serial = serial();
        for fail in [
            "update*",
            "fmt*",
            "clippy*",
            "llvm-cov\\ --version",
            "llvm-cov\\ --workspace*",
            "publish*",
        ] {
            let (d, c) = repo("rel-fail", WRITTEN, fail);
            let e = run(&args("release 0.1.1"), &c).unwrap_err();
            assert!(
                e.ends_with("(the new version is left in the working tree: `git checkout -- .` undoes it)"),
                "{e}"
            );
            assert_eq!(git(&c.root, &["tag", "--list", "v0.1.1"]), "");
            assert_eq!(git(&c.root, &["rev-list", "--count", "HEAD"]), "1\n");
            let status = git(&c.root, &["status", "--porcelain"]);
            assert!(
                status.contains("Cargo.toml") && status.contains("CHANGELOG.md"),
                "{status}"
            );
            git(&c.root, &["checkout", "--", "."]);
            assert_eq!(git(&c.root, &["status", "--porcelain"]), "");
            fs::remove_dir_all(&d).unwrap();
        }
    }

    #[test]
    fn release_git_failures() {
        let _serial = serial();
        for (fail, want) in [
            ("status*", "`git status --porcelain` failed: boom"),
            ("tag\\ --list*", "`git tag --list v0.1.1` failed: boom"),
            ("log*", "`git log --format=- %s v0.1.0..HEAD` failed: boom"),
            ("commit*", "`git commit -q -a -m Release 0.1.1"),
            ("tag\\ -a*", "`git tag -a --cleanup=verbatim v0.1.1 -m LumenDB 0.1.1"),
        ] {
            let (d, c) = repo("rel-git", WRITTEN, "never");
            let e = run(&args("release 0.1.1"), &failing_git(c, fail)).unwrap_err();
            assert!(e.starts_with(want) && e.ends_with("failed: boom"), "{e}");
            fs::remove_dir_all(&d).unwrap();
        }
        // The tag failed after the commit: the commit stays, and the tag can be made by hand.
        let (d, c) = repo("rel-git-tag", WRITTEN, "never");
        let c = failing_git(c, "tag\\ -a*");
        run(&args("release 0.1.1"), &c).unwrap_err();
        assert_eq!(git(&c.root, &["rev-list", "--count", "HEAD"]), "2\n");
        fs::remove_dir_all(&d).unwrap();

        let (d, c) = repo("rel-nogit", WRITTEN, "never");
        let c = Ctx {
            git: "/nonexistent/git".into(),
            ..c
        };
        let e = run(&args("release 0.1.1"), &c).unwrap_err();
        assert!(e.starts_with("cannot run /nonexistent/git"), "{e}");
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn release_cannot_write_the_changelog() {
        let _serial = serial();
        let (d, c) = repo("rel-write", WRITTEN, "never");
        // After the changelog was read, a directory takes its place.
        let c = git_with(c, "case \"$1\" in log) rm CHANGELOG.md; mkdir CHANGELOG.md;; esac");
        let e = run(&args("release 0.1.1"), &c).unwrap_err();
        assert!(e.starts_with("cannot write") && e.contains("CHANGELOG.md"), "{e}");
        assert_eq!(log(&d), "");
        fs::remove_dir_all(&d).unwrap();
    }

    /// What `cargo publish` prints for a crate crates.io already has, and for
    /// one too many new crates in a row.
    fn exists(name: &str) -> String {
        format!(
            "publish\\ -p\\ {name}) echo 'error: crate {name}@0.1.0 already exists on crates.io index' >&2; exit 101;;"
        )
    }

    fn limited(name: &str) -> String {
        format!(
            "publish\\ -p\\ {name}) echo 'error: the remote server responded with an error (status 429 Too Many \
Requests): too many new crates' >&2; exit 101;;"
        )
    }

    #[test]
    fn publish_goes_in_dependency_order() {
        let _serial = serial();
        let (d, c) = repo("pub", WRITTEN, "never");
        let out = run(&args("publish"), &c).unwrap();
        let published: String = PUBLISH_ORDER
            .iter()
            .map(|n| format!("{n} 0.1.0: published\n"))
            .collect();
        assert_eq!(
            out,
            format!("{published}every crate of v0.1.0 is on crates.io; push with `git push origin HEAD v0.1.0`\n")
        );
        let calls: String = PUBLISH_ORDER.iter().map(|n| format!("publish -p {n}\n")).collect();
        assert_eq!(log(&d), calls);
        // Dependencies come first: no crate is published before the ones it needs.
        let pos = |n: &str| PUBLISH_ORDER.iter().position(|&p| p == n).unwrap();
        assert!(pos("lumen-cpu") < pos("lumen-flashkv") && pos("lumen-flashkv") < pos("tsvdb"));
        assert!(pos("pcapfast") < pos("tsvdb") && pos("lumen-raft") < pos("lumen-cluster"));
        assert!(pos("tsvdb") < pos("lumen-cluster") && pos("lumen-cluster") < pos("lumen-bench"));
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn publish_skips_what_is_there_and_stops_at_the_rate_limit() {
        let _serial = serial();
        let (d, c) = repo("pub-limit", WRITTEN, "never");
        let rules = [exists("lumen-cpu"), exists("lumen-flashkv"), limited("lumen-raft")].join("\n");
        let e = run(&args("publish"), &rules_cargo(c, &rules)).unwrap_err();
        assert!(
            e.starts_with(
                "lumen-cpu 0.1.0: already on crates.io\nlumen-flashkv 0.1.0: already on crates.io\n\
                 pcapfast 0.1.0: published\nlumen-raft: crates.io limits"
            ),
            "{e}"
        );
        assert!(e.ends_with("`cargo xtask publish` again in about 10 minutes (what is published is skipped)"));
        // It stopped there.
        assert_eq!(log(&d).lines().count(), 4);
        fs::remove_dir_all(&d).unwrap();

        // Run again after the wait: everything is on crates.io.
        let (d, c) = repo("pub-again", WRITTEN, "never");
        let rules: Vec<String> = PUBLISH_ORDER.iter().map(|n| exists(n)).collect();
        let out = run(&args("publish"), &rules_cargo(c, &rules.join("\n"))).unwrap();
        assert_eq!(out.matches(": already on crates.io\n").count(), PUBLISH_ORDER.len());
        assert!(out.ends_with("push with `git push origin HEAD v0.1.0`\n"));
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn publish_stops_at_any_other_failure() {
        let _serial = serial();
        let (d, c) = repo("pub-fail", WRITTEN, "never");
        let rules = "publish\\ -p\\ tsvdb) echo 'error: no good' >&2; exit 101;;";
        let e = run(&args("publish"), &rules_cargo(c, rules)).unwrap_err();
        assert_eq!(
            e,
            "lumen-cpu 0.1.0: published\nlumen-flashkv 0.1.0: published\npcapfast 0.1.0: published\n\
             lumen-raft 0.1.0: published\n`cargo publish -p tsvdb` failed"
        );
        assert_eq!(log(&d).lines().count(), 5);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn publish_needs_the_release_to_be_made() {
        let _serial = serial();
        let (d, c) = repo("pub-refuse", WRITTEN, "never");
        // A commit after the tag, and a tag that is only similar.
        commit(&c.root, "a.txt", Some(""), "later");
        let e = run(&args("publish"), &c).unwrap_err();
        assert!(e.starts_with("HEAD is not tagged v0.1.0: make the release with"), "{e}");
        git(&c.root, &["tag", "v0.1.0-rc1"]);
        assert!(run(&args("publish"), &c)
            .unwrap_err()
            .starts_with("HEAD is not tagged v0.1.0"));
        // Tagged, with changes.
        git(&c.root, &["tag", "-f", "v0.1.0"]);
        fs::write(c.root.join("junk"), "").unwrap();
        let e = run(&args("publish"), &c).unwrap_err();
        assert!(
            e.starts_with("the working tree has changes") && e.contains("junk"),
            "{e}"
        );
        assert_eq!(log(&d), "");
        fs::remove_file(c.root.join("junk")).unwrap();
        run(&args("publish"), &c).unwrap();
        fs::remove_dir_all(&d).unwrap();

        for (content, want) in [
            (None, "cannot read"),
            (
                Some("[workspace]\n"),
                "Cargo.toml has no version in [workspace.package]",
            ),
        ] {
            let (d, c) = repo("pub-manifest", WRITTEN, "never");
            commit(&c.root, "Cargo.toml", content, "change");
            let e = run(&args("publish"), &c).unwrap_err();
            assert!(e.starts_with(want), "{e}");
            fs::remove_dir_all(&d).unwrap();
        }
    }

    #[test]
    fn publish_tool_failures() {
        let _serial = serial();
        for (fail, want) in [
            ("tag\\ --points-at*", "`git tag --points-at HEAD` failed: boom"),
            ("status*", "`git status --porcelain` failed: boom"),
        ] {
            let (d, c) = repo("pub-git", WRITTEN, "never");
            assert_eq!(run(&args("publish"), &failing_git(c, fail)).unwrap_err(), want);
            fs::remove_dir_all(&d).unwrap();
        }
        let (d, c) = repo("pub-missing", WRITTEN, "never");
        let nogit = Ctx {
            git: "/nonexistent/git".into(),
            cargo: c.cargo.clone(),
            root: c.root.clone(),
        };
        let nogit = Ctx {
            root: c.root.clone(),
            ..nogit
        };
        assert!(run(&args("publish"), &nogit)
            .unwrap_err()
            .starts_with("cannot run /nonexistent/git"));
        let nocargo = Ctx {
            cargo: "/nonexistent/cargo".into(),
            ..c
        };
        let e = run(&args("publish"), &nocargo).unwrap_err();
        assert!(e.starts_with("cannot run /nonexistent/cargo"), "{e}");
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
