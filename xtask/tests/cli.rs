//! Runs the real `xtask` binary (covers `main.rs`) with a fake cargo, so it
//! never recurses into a real build.

use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Output};

fn xtask(args: &[&str], cargo: Option<&str>) -> Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_xtask"));
    c.args(args).env_remove("XTASK_CARGO");
    if let Some(cargo) = cargo {
        c.env("XTASK_CARGO", cargo);
    }
    c.output().unwrap()
}

/// One test: writing the fake cargo while another test thread forks could
/// make its exec fail with ETXTBSY.
#[test]
fn help_and_failures() {
    let out = xtask(&["help"], None);
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("dev-check"));

    let out = xtask(&["deploy"], None);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).starts_with("xtask: unknown task"));

    let dir = std::env::temp_dir().join(format!("xtask-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let fake = dir.join("cargo");
    std::fs::write(&fake, "#!/bin/sh\nexit 1\n").unwrap();
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
    let out = xtask(&["kani"], Some(fake.to_str().unwrap()));
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("cargo-kani is not installed"));
    std::fs::remove_dir_all(&dir).unwrap();
}
