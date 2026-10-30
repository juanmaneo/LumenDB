//! The `cargo xtask` pattern (<https://github.com/matklad/cargo-xtask>):
//! project automation written in Rust, run with `cargo xtask <task>` through
//! the alias in `.cargo/config.toml`.
//!
//! - `dev-check`: fails on the first failing step of `cargo fmt --check`, `cargo clippy -D warnings`,
//!   `cargo test --workspace` and the coverage gate
//!   (`cargo llvm-cov --fail-under-lines 100 --fail-under-regions 100`).
//!   `--no-coverage` skips the gate; without it a missing cargo-llvm-cov is an
//!   error. CI runs it without flags.
//! - `kani`: proves the harnesses of the `proofs` crate (`cargo kani -p proofs`).
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
  dev-check [--no-coverage]  fmt --check, clippy -D warnings, test, 100% coverage gate
  kani                       run the kani proofs (cargo kani -p proofs)
";

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

    fn cargo(&self, args: &[&str]) -> Result<bool, String> {
        Command::new(&self.cargo)
            .args(args)
            .current_dir(&self.root)
            .status()
            .map(|s| s.success())
            .map_err(|e| format!("cannot run {} in {}: {e}", self.cargo, self.root.display()))
    }

    /// Runs one step, failing with the command line.
    fn step(&self, args: &[&str]) -> Result<(), String> {
        println!("xtask: cargo {}", args.join(" "));
        match self.cargo(args)? {
            true => Ok(()),
            false => Err(format!("`cargo {}` failed", args.join(" "))),
        }
    }

    /// Whether the cargo subcommand `sub` is installed.
    fn has(&self, sub: &str) -> Result<bool, String> {
        self.cargo(&[sub, "--version"])
    }
}

pub fn dev_check(ctx: &Ctx, no_coverage: bool) -> Result<String, String> {
    if !no_coverage && !ctx.has("llvm-cov")? {
        return Err(NO_LLVM_COV.into());
    }
    ctx.step(&["fmt", "--all", "--", "--check"])?;
    ctx.step(&["clippy", "--workspace", "--all-targets", "--", "-D", "warnings"])?;
    ctx.step(&["test", "--workspace"])?;
    if no_coverage {
        return Ok("dev-check passed (coverage gate skipped)\n".into());
    }
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
    ctx.step(&["kani", "-p", "proofs"])?;
    Ok("kani: all proof harnesses verified\n".into())
}

/// Runs `args` (without the program name); returns the text to print.
pub fn run(args: &[String], ctx: &Ctx) -> Result<String, String> {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        [] | ["help"] => Ok(USAGE.into()),
        ["dev-check"] => dev_check(ctx, false),
        ["dev-check", "--no-coverage"] => dev_check(ctx, true),
        ["kani"] => kani(ctx),
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
             test --workspace\nllvm-cov --workspace --fail-under-lines 100 --fail-under-regions 100\n"
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
            ("test*", "`cargo test --workspace` failed"),
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
        assert!(run(&args("kani"), &ctx(&d, "kani\\ -p*")).is_err());
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
