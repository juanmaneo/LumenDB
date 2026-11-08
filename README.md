# LumenDB

[![CI](https://github.com/juanmaneo/LumenDB/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/juanmaneo/LumenDB/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Parse packet captures at "the speed of light" into a crash-safe, columnar
time-series database. LumenDB is written entirely in Rust and depends only on
`memmap2` and `parking_lot`.

| crate | what it is | inspired by |
|---|---|---|
| [`flashkv`](crates/flashkv) | crash-safe ordered key-value store (LSM) | LevelDB, LMDB, FoundationDB, eguan/ibs |
| [`raft`](crates/raft) | Raft consensus, SWIM membership, Lamport clocks | Raft paper, CockroachDB, Serf/dkron |
| [`pcapfast`](crates/pcapfast) | zero-copy multithreaded pcap / pcapng parser | — |
| [`tsvdb`](crates/tsvdb) | columnar TSDB on flashkv | InfluxDB v3 (IOx), Gorilla, Akumuli |
| [`bench`](crates/bench) | command line: generate, ingest, query, benchmark | — |
| [`xtask`](xtask) | `cargo xtask dev-check` / `kani` / `bench` | cargo-xtask |
| [`proofs`](proofs) | kani model-checking harnesses | — |

## Architecture

```text
 pcap / pcapng file                       line protocol
        |                                       |
        | mmap read-only                        |
        v                                       |
 +--------------------------------+             |
 | pcapfast                       |             |
 | record-aligned chunks,         |             |
 | scoped threads                 |             |
 +--------------------------------+             |
        |                                       |
        | flows + traffic timeline              |
        v                                       v
 +-----------------------------------------------------+
 | tsvdb                                               |
 +-----------------------------------------------------+
        |
        | WAL record + series/schema
        | flush: Gorilla chunks per column and hour
        v
 +-----------------------------------------------------+
 | flashkv                                             |<-- compactor thread
 |                                                     |    (snapshot read, atomic batch)
 |                                                     |<-- queries (snapshot)
 +-----------------------------------------------------+
        |
        | pread, CRC-checked
        v
 +-----------------------------------------------------+
 | files: WAL, SSTables, MANIFEST                      |
 +-----------------------------------------------------+
        ^
        | FileStorage on the same Env
        |
 +-----------------------------------------------------+
 | raft: Raft + SWIM + Lamport                         |
 +-----------------------------------------------------+
```

### flashkv: the storage engine

- **LevelDB's design.** Writes go to a CRC32C-framed write-ahead log, then a
  memtable. They are flushed to immutable SSTables (prefix-compressed blocks,
  optional LZ compression, bloom filters, CRC per block) with leveled
  compaction. A `MANIFEST` log plus `CURRENT` is updated by atomic rename.
- **Hardware-crash safety.** With `sync` on (the default), a write returns
  `Ok` only once it is on stable storage. Recovery tells a torn tail from
  corruption, as TigerBeetle does. A torn tail is an incomplete last record
  or zero fill: a write that never completed, so it was never acknowledged.
  It is cut at the last valid record. A complete record with a bad checksum,
  or intact records after a bad one, means acknowledged data was damaged, so
  the open fails instead of silently dropping it. Errors are sticky, like
  LevelDB's `bg_error`: after a failed write, later writes are refused until
  the store is reopened.
- **No mmap of database files.** This avoids LMDB's map-size failure
  (`MDB_MAP_FULL`) and SIGBUS on a truncated file. Tables are read with
  `pread`, and every block is length- and CRC-checked, so corruption becomes
  an `Err`, never a crash.
- **Modular, like FoundationDB.** All I/O goes through the `Env` trait.
  `FaultEnv` injects a failure at the N-th operation and simulates power loss:
  unsynced bytes, files and renames disappear. Tests sweep every fault point
  and check that every acknowledged write survives. The same harness covers
  raft's storage, tsvdb and the CLI. `MemEnv` is an in-memory `Env` for
  simulation: a power loss keeps each file's synced bytes plus a torn prefix
  of the rest, and a bit can be flipped in place.
- **Compaction never slows reads** (eguan/ibs, eblob). Flush and compaction
  write new files on a background thread and publish them with one pointer
  swap. Readers hold immutable snapshots, and live snapshots pin the versions
  they can see. MVCC snapshots support optimistic, serializable transactions.

### raft: distribution primitives

- **Raft** (election, log replication, majority-quorum commit), deterministic
  and transport-agnostic: drive it with `tick()` and `step(msg)`. Term, vote
  and entries are durable before any dependent message leaves, so a node
  never votes twice in a term. `FileStorage` uses flashkv's `Env` and record
  framing: an atomic state file plus a generation-numbered log.
- **Pre-vote** (Raft thesis, section 9.6). A node whose election timer fires
  first asks its peers whether they would vote for it, without changing its
  term or vote. Only with a majority of promises does it campaign. A peer
  refuses while it hears from a leader, and a recovering node never promises.
  So a node cut off from the cluster keeps its term and does not depose a
  healthy leader when it comes back. It is on by default (`Config::pre_vote`),
  and clusters may mix nodes with and without it.
- **ReadIndex** (Raft thesis, section 6.4). `Node::read_index` gives a
  linearizable read without writing to the log. The leader notes its commit
  index and confirms it still leads when a majority acknowledges an
  AppendEntries of a later round, piggybacked on the normal replication
  traffic. `tick()` then releases the read, and the state machine can answer
  it locally. A leader cut off from the majority never confirms, so it never
  serves a stale read, and when it is deposed its pending reads fail. A new
  leader first needs an entry of its own term committed, so a read asked
  before that returns `NotReady`: retry in a few ticks.
- **An empty entry per leader.** A new leader appends an empty entry of its
  term as soon as it is elected (Raft thesis, section 6.4). Entries of
  earlier terms commit only together with an entry of the leader's term, so
  without it they could stay uncommitted until a client happened to write.
  The simulator found this: after a leader change the cluster did not always
  converge. Applications must ignore entries with empty data, and entries of
  kind `Config`.
- **Membership changes** (Raft thesis, section 4.1, one server at a time).
  The voter set is held in configuration entries of the log, in effect as
  soon as the entry is appended and taken back if it is truncated. The
  leader changes it by one server per entry (`add_voter`, `remove_voter`), so
  the old and the new majorities always overlap. It refuses a change while
  another is not committed, and before it has committed an entry of its own
  term (otherwise two leaders could choose different configurations on the
  same prefix). A new server joins first as a learner (`add_learner`): it
  gets the log but neither votes nor counts toward a quorum, and `add_voter`
  waits until it has caught up, so a slow newcomer cannot stall commits.
  A node that is not a voter never campaigns, and while it hears from a
  leader a node ignores vote traffic from servers outside its voter set, so a
  removed server cannot disturb the cluster. A leader that removes itself
  steps down once the change commits. A server whose removal is not
  committed keeps its place in elections: the leader may be gone with the
  entry only on the server it removes, and the rest could not win without it.
  Snapshots carry the configuration, as the entries that set it are gone.
  The application sees committed configuration entries too, and ignores them.
- **Snapshots and log compaction.** The application owns the state machine,
  so it decides when to snapshot: `Node::compact(index, data)` stores the
  serialized state machine as of an applied index, durably, and drops the log
  up to there. A leader whose follower needs entries it has dropped sends
  the snapshot instead (`InstallSnapshot`, in one message, so a transport
  must handle messages as large as a snapshot). The follower stores it, and
  `tick()` hands it over as `TickOutcome::snapshot` to restore the state
  machine from, before any entries after it. After a restart the first tick
  does the same with the stored snapshot. On disk the snapshot is its own
  file, named by index and written and synced before the state file points
  at it, so a log rewrite never copies it and a crash leaves either the old
  or the new pair. A snapshot that fails its checksum loses the applied
  prefix: the node starts from an empty log, marked recovering, and is
  caught up by the leader.
- **Wire format and TCP transport** (`raft::wire`, `raft::net`, `std::net`
  only). A message is one record in flashkv's CRC framing, so a flipped bit,
  a truncated stream and garbage are all detected, and a lying length costs
  nothing: the receiver never allocates more than has arrived. The transport
  is deliberately lossy, as Raft copes with lost, duplicated and reordered
  messages (the simulator proves it): `send` never blocks, one writer thread
  per peer reconnects after failures and drops what it cannot deliver, and a
  reader drops a connection that sends a bad frame. Every drop is counted.
  There is no authentication or encryption; run it on a trusted network or
  behind a tunnel.
- **Server** (`raft::server`). `Server` runs a node on a clock: it steps the
  node with what the transport receives, ticks it, sends its messages, hands
  committed entries, snapshots and confirmed reads to the application's
  `StateMachine`, and compacts the log every `snapshot_every` entries. The
  application proposes (`propose`, `wait_applied`) and gets linearizable
  reads from `read_barrier`. A storage error stops the server for good, as
  the state on disk can no longer be trusted to match memory.
- **Protocol-aware recovery** (TigerBeetle; Alagappan et al., FAST '18). A
  bit flip in the Raft log may have destroyed entries the node acknowledged,
  and so helped commit. The node keeps the intact prefix and is marked
  *recovering*, durably. A recovering node never votes and never campaigns,
  so every election quorum still overlaps every commit quorum in an intact
  node. It rejoins once it holds the current leader's whole log. A damaged
  single-node cluster stays stuck: there is no one to copy from, and
  stopping is safer than guessing. The state file (term, vote) holds two
  checksummed copies; either one is enough, and two intact copies must agree.
- **Deterministic simulation** (TigerBeetle's VOPR). One seed fixes a whole
  run of a 3 to 7 replica cluster, each replica on its own `MemEnv` with the
  real `FileStorage`: message loss, duplication and reordering, partitions,
  crashes, power loss with torn writes, bit flips in the Raft log, and I/O
  errors, while an operator keeps adding and removing servers through
  whichever replica leads. After every event the simulator checks election safety (one leader
  per term), leader completeness, state machine safety (no two replicas
  commit or apply different entries at an index), log matching, and
  linearizable reads (a read, even one sent to a stale leader, must include
  everything committed when it was asked), and snapshots (each replica has a
  state machine, a hash of what it applied, that it snapshots, restores after
  a restart and when a leader sends a snapshot; no two replicas may ever
  differ in state at the same index), and membership (committed
  configurations differ by one server, and the voters a node or a snapshot
  has are the ones committed at its index). Then
  faults stop and the cluster must converge: one leader that is one of its
  own voters, and among the voters nobody recovering, identical logs and
  state machines. Corruption hits a minority of the voters at a time, which is
  what the protocol can survive. A failing seed replays exactly. The check
  is real: with the recovery rule removed, 9 of 300 seeds fail with `leader
  lacks committed entry`, and a leader that confirms reads one acknowledgement
  early fails within the first few seeds with `stale read`; a snapshot that
  never reaches the state machine, or a restart that skips the stored one,
  fails on seed 0 with `applied entry ... not as committed`. For membership,
  allowing several changes at once fails with `leader ... lacks committed
  entry`, a change of two servers fails on seed 0, a log that keeps
  configuration entries it truncated fails within a few dozen seeds, and a leader that never steps down after
  removing itself leaves no convergence. Two guards only unit tests catch:
  the committed-entry-in-term rule for changes (the simulator did not find its
  scenario in 600 seeds), and replicating to a removed server until the
  change commits. `cargo test` runs a fixed set of seeds, and
  `cargo xtask vopr` runs many; `--voters N` fixes how many replicas start
  as voters.
- **SWIM** membership: round-robin probes, indirect `PingReq` probes,
  suspicion, death, incarnation-based refutation, and piggybacked gossip.
- **Lamport clocks** stamp every message. Ordering never depends on wall
  clocks. Lamport clocks are enough here, so there is no HLC: Raft terms and
  log indices already order replicated state, and nothing needs to match
  physical time.

### pcapfast: the parser

The capture is mmapped read-only. It is *input*, so mmap cannot corrupt the
database. pcapfast detects pcap vs pcapng (both byte orders, µs/ns
resolution), cuts the file into record- or block-aligned chunks and parses
them on scoped threads. Headers are read in place, so packets are never
copied. Each thread fills its own flow table and timeline, and the results
are merged. Torn tails are reported, not fatal.

`cargo xtask bench` measures it on a synthetic capture of 4.8 million
packets (3.6 GB) that is already in the page cache. On a 16-thread machine,
the best of 5 runs was:

| what is timed | time | rate |
|---|---|---|
| parsing the mapped file | 134 ms | 36 Mpkt/s, 27 GB/s |
| the whole `parse_file` call | 348 ms | 14 Mpkt/s, 10 GB/s |

The gap is the kernel mapping and unmapping 3.6 GB (about 880,000 pages);
the parse itself scales with threads. Medians are noisier, about 200 ms and
470 ms.

### tsvdb: the time-series database

- **Data model.** InfluxDB line protocol, with escaping and float, integer,
  unsigned, boolean and string fields. Each measurement plus tag set is a
  series, held in an inverted tag index. Each (series, field) pair is a typed
  column, and a field keeps its first type.
- **Write path.** One flashkv batch holds the new series, schema and column
  entries plus a line-protocol WAL record, so an acknowledged write survives
  a power loss. The points then go to an in-memory buffer. A flush turns the
  buffer into immutable **chunks**, one per column and hour partition. Chunks
  use delta-of-delta timestamps, Gorilla XOR floats, zigzag-delta integers
  and bit-packed booleans.
- **Compaction and downsampling.** Compaction merges a partition's chunks
  from a snapshot and publishes the result with one atomic batch, so reads
  are never blocked. `rollup` writes windowed aggregates as a new measurement
  (downsampling).
- **Queries.** Range scans with tag filters, `sum`/`count`/`min`/`max`/`mean`
  per series and optional time window, and top-N (for example the heaviest
  flows of a capture).

## Usage

```sh
cargo build --release
B=target/release/bench

$B gen-pcap /tmp/cap.pcapng --packets 1000000 --flows 5000 --format pcapng
$B ingest /tmp/cap.pcapng --db /tmp/lumendb
$B query --db /tmp/lumendb --agg sum --top 10                       # heaviest flows (bytes)
$B query --db /tmp/lumendb --measurement traffic --field packets \
         --agg sum --every 60000000000                            # packets per minute
$B query --db /tmp/lumendb --where proto=udp --where dport=53 --agg count
echo 'cpu,host=a usage=0.5 1700000000000000000' > /tmp/m.lp
$B write /tmp/m.lp --db /tmp/lumendb
$B kv-bench --db /tmp/kv --ops 1000000 --sync 0                   # flashkv throughput
$B parse-bench /tmp/cap.pcapng --runs 5 --min-mpps 5              # pcapfast throughput
```

Every storage-backed command accepts `--sync 0|1`, `--background 0|1` and
`--fail-after N`. The last one injects an I/O error at the N-th filesystem
operation, so you can watch crash handling from a shell.

As a library:

```rust
use tsvdb::{Agg, Db, DbOptions, Query};

let db = Db::open("data".as_ref(), DbOptions::default())?;
db.write_lines("cpu,host=a usage=0.5 1700000000000000000")?;
let rows = db.query(&Query::new("cpu", "usage").filter("host", "a").agg(Agg::Mean))?;
let stats = pcapfast::parse_file("cap.pcap".as_ref(), &Default::default())?;
db.ingest_capture(&stats)?;
let top = tsvdb::query::top_flows(&db, i64::MIN, i64::MAX, 10)?;
```

## xtask

Project automation uses the [cargo-xtask](https://github.com/matklad/cargo-xtask)
pattern. The alias lives in `.cargo/config.toml`.

| command | does |
|---|---|
| `cargo xtask dev-check` | fails on the first failing step: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, then `cargo llvm-cov --workspace --fail-under-lines 100 --fail-under-regions 100` |
| `cargo xtask dev-check --no-coverage` | the same without the coverage gate (for machines without cargo-llvm-cov) |
| `cargo xtask kani` | `cargo kani -p proofs`, with virtual memory capped at 8 GiB (`ulimit -v`) so a runaway proof fails instead of triggering the OOM killer |
| `cargo xtask vopr [--seeds N] [--start N] [--replicas N]` | in release mode, runs the Raft cluster simulation for `N` seeds (default 200, about 0.1 s each) and checks the safety properties after every event. A failing seed is printed with the command that replays it, for example `bench vopr --start 42 --seeds 1` |
| `cargo xtask bench [--packets N] [--min-mpps X]` | in release mode, writes a synthetic capture (default 4.8 million packets, about 3.6 GB) to `target/bench/capture.pcap`, then runs `bench parse-bench` on it: one warm-up pass and 5 timed runs. With `--min-mpps`, it fails if the best wall-clock rate is below `X` Mpkt/s |


A missing `cargo-llvm-cov` or `cargo-kani` fails with installation
instructions:

```sh
rustup component add llvm-tools-preview && cargo install cargo-llvm-cov
cargo install --locked kani-verifier && cargo kani setup
```

**Coverage policy.** Every line and every region of every file is covered,
including the binaries: integration tests spawn them through
`env!("CARGO_BIN_EXE_<name>")`, and every file has `#[cfg(test)]` tests.

**Proofs.** The kani harnesses in [`proofs`](proofs/src/lib.rs) prove the
following, within the bounds stated in each harness:

- the flashkv varint round-trips every `u64`;
- CRC32C matches its published check values, and CRC masking is a
  bijection;

  A masked CRC is the raw CRC passed through a fixed post-processing step.
  flashkv uses the LevelDB form,
  `mask(c) = c.rotate_right(15).wrapping_add(0xa282_e8a8)`. Other common
  masks:

  | mask | what it is |
  |---|---|
  | `crc(x) ⊕ 0xFFFFFFFF` | complement, as in the IEEE 802.3 FCS |
  | `crc(x) ⊕ k` | XOR with a fixed constant `k`, e.g. zlib |
  | `swap_bytes(crc(x))` | bit or byte reversal |

  Each transform is a bijection on the 32-bit checksum space: XOR with a
  constant is its own inverse, rotation and byte order are permutations,
  and adding a constant modulo 2³² is undone by subtracting it. Therefore
  `masked(a) = masked(b)` ⟺ `crc(a) = crc(b)`. Masking neither creates nor
  hides collisions. It is cosmetic, and every collision and
  burst-error-detection property of CRC-32 carries over unchanged.

  The Ethernet FCS is the canonical example: it is just `crc32(frame)` run
  through complement and byte swap (transmitted most-significant byte
  first). It is not a new checksum and changes nothing about error
  detection. It only makes the wire encoding well-behaved: an all-zeros
  frame no longer maps to an all-zeros checksum.

- any two majority quorums intersect;
- the Lamport clock is monotonic.

The same properties run as unit tests in every build.

raft `Log::append` keeping its invariants and being atomic on error is
checked by exhaustive enumeration in a unit test instead: every log of up to
2 entries and every batch of up to 3 entries, over indices 0..=4 and terms
0..=3. That is a proof for this finite domain. Kani cannot check it: with a
symbolic entry index, CBMC runs out of memory on the log's `Vec` operations,
even for a one-entry log and a one-entry batch.

## CI

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs on
`ubuntu-latest`:

1. `cargo xtask dev-check`: fmt, clippy `-D warnings`, tests and the 100%
   line and region coverage gate.
2. `cargo xtask kani`: the proofs.
3. `cargo build --release --workspace`.

## Authorship

This code was initially written with the help of **Le Chonk**, aka
[Mistral Large 4](https://mistral.ai) from Mistral.ai. Le Chonk is a
large language model, and the entire codebase — crates, tests, proofs and
CI — was generated through conversations with it, then reviewed and edited
by a human (aka https://github.com/juanmaneo).

## License

MIT — see [LICENSE](LICENSE).
