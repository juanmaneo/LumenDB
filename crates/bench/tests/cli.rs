//! Runs the real `bench` binary end to end (covers `main.rs`).

use std::process::Command;

fn bench(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_bench")).args(args).output().unwrap()
}

#[test]
fn prints_usage_and_succeeds() {
    let out = bench(&[]);
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("usage: bench"));
}

#[test]
fn reports_errors_with_exit_code_2() {
    let out = bench(&["frobnicate"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).starts_with("error: unknown command"));
}

#[test]
fn generates_and_ingests_a_capture() {
    let dir = std::env::temp_dir().join(format!("bench-cli-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let cap = dir.join("c.pcapng");
    let db = dir.join("db");
    let (cap, db) = (cap.to_str().unwrap(), db.to_str().unwrap());
    assert!(bench(&["gen-pcap", cap, "--packets", "1000", "--format", "pcapng"])
        .status
        .success());
    let out = bench(&["ingest", cap, "--db", db, "--sync", "0"]);
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("parsed 1000 packets"));
    let out = bench(&["query", "--db", db, "--agg", "count"]);
    assert!(String::from_utf8_lossy(&out.stdout).contains(" rows"));
    std::fs::remove_dir_all(&dir).unwrap();
}
