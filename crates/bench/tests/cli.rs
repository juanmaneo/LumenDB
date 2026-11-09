//! Runs the real `bench` binary end to end (covers `main.rs`).

use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use std::process::{Child, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

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

/// A `bench serve` process. Killed when dropped, so that a failing test
/// leaves nothing behind.
struct Node {
    id: u64,
    child: Child,
    stdout: BufReader<ChildStdout>,
    raft: String,
    client: String,
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Starts node `id` with the ports picked by the system, and reads where it
/// listens from its first line.
fn spawn(dir: &Path, id: u64, extra: &[&str]) -> Node {
    let data = dir.join(id.to_string());
    let mut child = Command::new(env!("CARGO_BIN_EXE_bench"))
        .args(["serve", "--id", &id.to_string(), "--dir", data.to_str().unwrap()])
        .args([
            "--raft",
            "127.0.0.1:0",
            "--client",
            "127.0.0.1:0",
            "--timeout-ms",
            "5000",
        ])
        .args(extra)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    let prefix = format!("node {id} listening: raft ");
    let rest = line.trim().strip_prefix(&prefix).expect("the startup line");
    let (raft, client) = rest.split_once(", client ").expect("two addresses");
    let (raft, client) = (raft.to_string(), client.to_string());
    Node {
        id,
        child,
        stdout,
        raft,
        client,
    }
}

/// `bench client --nodes NODES REST...`: the output, and whether it succeeded.
fn client(nodes: &str, rest: &[&str]) -> (bool, String) {
    let mut args = vec!["client", "--nodes", nodes];
    args.extend(rest);
    let out = bench(&args);
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    (out.status.success(), text + &String::from_utf8_lossy(&out.stderr))
}

/// Like `client`, for a command that must succeed.
fn client_ok(nodes: &str, rest: &[&str]) -> String {
    let (ok, text) = client(nodes, rest);
    assert!(ok, "bench client {rest:?} failed: {text}");
    text
}

fn addrs(nodes: &[Node]) -> String {
    let all: Vec<&str> = nodes.iter().map(|n| n.client.as_str()).collect();
    all.join(",")
}

/// The id of the node whose `status` line says it is the leader.
fn leader_id(status: &str) -> u64 {
    let line = status.lines().find(|l| l.contains(" role=leader ")).unwrap();
    let id = line.split_whitespace().find_map(|w| w.strip_prefix("id=")).unwrap();
    id.parse().unwrap()
}

fn eventually(what: &str, mut done: impl FnMut() -> bool) {
    let start = Instant::now();
    while !done() {
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "timed out waiting for {what}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn processes_form_a_cluster_that_replicates_fails_over_and_grows() {
    let dir = std::env::temp_dir().join(format!("bench-processes-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let file = |name: &str, text: &str| {
        let path = dir.join(name);
        std::fs::write(&path, text).unwrap();
        path.to_str().unwrap().to_string()
    };
    let first = file("first.lp", "cpu,host=a usage=1 10\ncpu,host=a usage=3 20\n");
    let second = file("second.lp", "cpu,host=a usage=5 30\n");
    let sum = ["query", "--measurement", "cpu", "--field", "usage", "--agg", "sum"];
    let sum_is = |n: u32| format!("cpu,host=a\t{}\t{n}\n1 rows\n", i64::MIN);

    // Three nodes start a cluster. They learn each other's Raft addresses
    // afterwards, so that no port has to be picked before they start.
    let mut nodes: Vec<Node> = (1..=3).map(|id| spawn(&dir, id, &["--voters", "1,2,3"])).collect();
    let all = addrs(&nodes);
    for n in &nodes {
        client_ok(&all, &["peer", &n.id.to_string(), &n.raft]);
    }
    assert_eq!(client_ok(&all, &["write", &first]), "wrote 2 points\n");
    assert_eq!(client_ok(&all, &sum), sum_is(4));
    // Every node ends up with the data.
    for n in &nodes {
        eventually("a node to have the write", || {
            let mut args = sum.to_vec();
            args.extend(["--local", "1"]);
            client(&n.client, &args) == (true, sum_is(4))
        });
    }
    let status = client_ok(&all, &["status"]);
    assert_eq!(status.lines().count(), 3, "{status}");
    assert_eq!(status.matches(" role=leader ").count(), 1, "{status}");
    let pong = client_ok(&all, &["ping"]);
    assert_eq!(pong.matches(": PONG\n").count(), 3, "{pong}");

    // Leadership is handed to another node on request, and the cluster goes
    // on with it.
    let heir = (1..=3).find(|&id| id != leader_id(&status)).unwrap();
    assert_eq!(client_ok(&all, &["transfer", &heir.to_string()]), "transferred\n");
    eventually("the heir to lead alone", || {
        let status = client_ok(&all, &["status"]);
        status.matches(" role=leader ").count() == 1 && leader_id(&status) == heir
    });

    // Kill the leader without any goodbye. The others elect a new one, and
    // the client goes around the node that is gone.
    let leader_id = heir;
    let at = nodes.iter().position(|n| n.id == leader_id).unwrap();
    nodes[at].child.kill().unwrap();
    nodes[at].child.wait().unwrap();
    assert_eq!(client_ok(&all, &["write", &second]), "wrote 1 points\n");
    assert_eq!(client_ok(&all, &sum), sum_is(9));
    let status = client_ok(&all, &["status"]);
    assert_eq!(status.matches("unreachable").count(), 1, "{status}");
    assert_eq!(status.matches(" role=leader ").count(), 1, "{status}");
    // A health check fails while a node is down, and says which.
    let (ok, text) = client(&all, &["ping"]);
    assert!(!ok && text.contains("1 of 3 nodes failed:"), "{text}");
    assert_eq!(
        (text.matches("unreachable").count(), text.matches(": PONG").count()),
        (1, 2)
    );

    // It comes back from its files, on another port. It is not told where
    // the others are (it saved that); the others are told where it is.
    nodes[at] = spawn(&dir, leader_id, &["--voters", "1,2,3"]);
    let all = addrs(&nodes);
    client_ok(&all, &["peer", &leader_id.to_string(), &nodes[at].raft]);
    eventually("the restarted node to catch up", || {
        let mut args = sum.to_vec();
        args.extend(["--local", "1"]);
        client(&nodes[at].client, &args) == (true, sum_is(9))
    });

    // A fourth node joins: first as a learner, a voter once it has caught up.
    let peers: Vec<String> = nodes.iter().map(|n| format!("{}={}", n.id, n.raft)).collect();
    let mut extra = Vec::new();
    for p in &peers {
        extra.extend(["--peer", p.as_str()]);
    }
    nodes.push(spawn(&dir, 4, &extra));
    let all = addrs(&nodes);
    client_ok(&all, &["peer", "4", &nodes[3].raft]);
    assert_eq!(client_ok(&all, &["add-learner", "4"]), "added\n");
    eventually("the learner to be made a voter", || client(&all, &["add-voter", "4"]).0);
    eventually("every node to list four voters", || {
        let status = client_ok(&all, &["status"]);
        status.matches(" voters=1,2,3,4 ").count() == 4
    });
    eventually("the new voter to have the data", || {
        let mut args = sum.to_vec();
        args.extend(["--local", "1"]);
        client(&nodes[3].client, &args) == (true, sum_is(9))
    });

    // Stopping every node ends the processes.
    let stopped = client_ok(&all, &["shutdown"]);
    assert_eq!(stopped.matches(": stopping").count(), 4, "{stopped}");
    for n in &mut nodes {
        assert!(n.child.wait().unwrap().success());
        let mut rest = String::new();
        n.stdout.read_to_string(&mut rest).unwrap();
        assert_eq!(rest, format!("node {} stopped\n", n.id));
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A client that is quick to give up, with this secret file (or none).
fn quick(nodes: &str, secret: Option<&str>, rest: &[&str]) -> (bool, String) {
    let mut args = vec!["--timeout-ms", "300", "--patience-ms", "100"];
    if let Some(file) = secret {
        args.extend(["--secret-file", file]);
    }
    args.extend(rest);
    client(nodes, &args)
}

#[test]
fn processes_with_a_secret_answer_only_those_who_have_it() {
    let dir = std::env::temp_dir().join(format!("bench-secure-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let file = |name: &str, text: &str| {
        let path = dir.join(name);
        std::fs::write(&path, text).unwrap();
        path.to_str().unwrap().to_string()
    };
    let (secret, other) = (
        file("secret", "the-secret-of-this-cluster\n"),
        file("other", "not-this-cluster-s-secret"),
    );
    let lp = file("in.lp", "cpu,host=a usage=1 10\ncpu,host=a usage=3 20\n");
    let sum = ["query", "--measurement", "cpu", "--field", "usage", "--agg", "sum"];
    let sum_is = format!("cpu,host=a\t{}\t4\n1 rows\n", i64::MIN);

    let mut nodes: Vec<Node> = (1..=3)
        .map(|id| spawn(&dir, id, &["--voters", "1,2,3", "--secret-file", &secret]))
        .collect();
    let all = addrs(&nodes);
    let with = |rest: &[&str]| {
        let mut args = vec!["--secret-file", secret.as_str()];
        args.extend(rest);
        client_ok(&all, &args)
    };
    for n in &nodes {
        with(&["peer", &n.id.to_string(), &n.raft]);
    }
    // The nodes elect a leader and replicate to each other over connections
    // that are authenticated, too.
    assert_eq!(with(&["write", &lp]), "wrote 2 points\n");
    let mut args = vec!["--secret-file", secret.as_str()];
    args.extend(sum);
    assert_eq!(client_ok(&all, &args), sum_is);
    args.extend(["--local", "1"]);
    for n in &nodes {
        eventually("a node to have the write", || {
            client(&n.client, &args) == (true, sum_is.clone())
        });
    }
    assert_eq!(with(&["ping"]).matches(": PONG\n").count(), 3);

    // Without the secret, or with another, nothing is answered, and nothing
    // is changed: not even a stop.
    for given in [None, Some(other.as_str())] {
        for rest in [&["ping"][..], &["write", &lp], &["shutdown"]] {
            let (ok, text) = quick(&all, given, rest);
            assert!(!ok, "{rest:?} with {given:?} worked: {text}");
            if given.is_some() {
                assert!(text.contains("same secret"), "{rest:?}: {text}");
            }
        }
        // (`status` says what each node answered, and is not strict)
        let (ok, text) = quick(&all, given, &["status"]);
        assert!(ok && text.matches("unreachable: ").count() == 3, "{text}");
    }
    assert_eq!(with(&["ping"]).matches(": PONG\n").count(), 3);
    let mut args = vec!["--secret-file", secret.as_str()];
    args.extend(sum);
    assert_eq!(client_ok(&all, &args), sum_is);

    // The secret stops them all.
    assert_eq!(with(&["shutdown"]).matches(": stopping").count(), 3);
    for n in &mut nodes {
        assert!(n.child.wait().unwrap().success());
    }
    std::fs::remove_dir_all(&dir).unwrap();
}
