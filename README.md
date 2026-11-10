# LumenDB

[![CI](https://github.com/juanmaneo/LumenDB/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/juanmaneo/LumenDB/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Parse packet captures at "the speed of light" into a crash-safe, columnar
time-series database. LumenDB is written entirely in Rust and depends only on
`memmap2` and `parking_lot`.

The crates are published as the packages in parentheses; in the code they
keep the short names (`use flashkv::Db`, through `package = "lumen-flashkv"`).

| crate | what it is | inspired by |
|---|---|---|
| [`cpu`](crates/cpu) (`lumen-cpu`) | portability layer for special instructions (x86_64, aarch64, portable fallback) | corsix/fast-crc32 |
| [`flashkv`](crates/flashkv) (`lumen-flashkv`) | crash-safe ordered key-value store (LSM) | LevelDB, LMDB, FoundationDB, eguan/ibs |
| [`raft`](crates/raft) (`lumen-raft`) | Raft consensus, SWIM membership, Lamport clocks, shared-secret authentication | Raft paper, CockroachDB, Serf/dkron, TigerBeetle |
| [`pcapfast`](crates/pcapfast) | zero-copy multithreaded pcap / pcapng parser | — |
| [`tsvdb`](crates/tsvdb) | columnar TSDB on flashkv | InfluxDB v3 (IOx), Gorilla, Akumuli, QuestDB |
| [`cluster`](crates/cluster) (`lumen-cluster`) | tsvdb replicated by raft | TigerBeetle, CockroachDB |
| [`bench`](crates/bench) (`lumen-bench`) | command line, binary `bench`: generate, ingest, query, benchmark, run and drive a cluster | — |
| [`xtask`](xtask) | `cargo xtask dev-check` / `kani` / `vopr` / `bench` | cargo-xtask |
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
 | typed columns in memory, CRC-framed log of its own  |---> files: NNNN.tswal
 +-----------------------------------------------------+
        |
        | series/schema; flush: Gorilla chunks per column
        | and hour, and the statistics of each chunk
        v
 +-----------------------------------------------------+
 | flashkv                                             |<-- compactor thread
 |                                                     |    (snapshot read, atomic batch)
 |                                                     |<-- queries (snapshot, statistics,
 |                                                     |    columns read on several threads)
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

### cpu: the portability layer

No other crate touches `std::arch`. Each kind of instruction is a trait
(`Crc32cInstr`, `Clmul`). `x86_64` (SSE4.2, PCLMULQDQ) and `aarch64` (CRC32,
NEON PMULL) implement the traits, and the algorithms are written once over
them. A plain Rust version covers other processors and kani. The best
implementation is picked at the first call.

CRC32C uses the [corsix/fast-crc32](https://github.com/corsix/fast-crc32)
fusion algorithm. `bench crc-bench` on a Ryzen 7 5800U (Zen 3, laptop), with
the block shape chosen by a hyperfine sweep:

| buffer | fused | SSE4.2, one stream | tables |
|---|---|---|---|
| 512 B | 11.2 GB/s | 4.9 GB/s | 0.98 GB/s |
| 4 KiB | 16.0 GB/s | 4.9 GB/s | 0.97 GB/s |
| 1 MiB | 13.7 GB/s | 4.6 GB/s | 0.96 GB/s |

The aarch64 shape is the one corsix measured fastest on Ampere Altra. It has
not been measured on Ampere hardware here: it is tested under QEMU
(Neoverse N1 and N2, `cargo test-aarch64`), and the CI's ARM job prints its
speed on GitHub's runner.

### flashkv: the storage engine

- **LevelDB's design**: a CRC32C-framed WAL, a memtable, and immutable
  SSTables (prefix-compressed blocks, optional LZ, bloom filters, a CRC per
  block) with leveled compaction. `MANIFEST` plus `CURRENT` are updated by
  atomic rename.
- **Hardware-crash safety**: with `sync` on (the default), a write returns
  `Ok` only once it is on stable storage. Recovery cuts a torn tail (a write
  that was never acknowledged), but fails on damaged acknowledged data
  instead of dropping it, as TigerBeetle does. Errors are sticky, like
  LevelDB's `bg_error`.
- **No mmap of database files**: no `MDB_MAP_FULL`, no SIGBUS. Tables are read
  with `pread`, and corruption is an `Err`, never a crash.
- **Fault injection** (FoundationDB): all I/O goes through the `Env` trait.
  `FaultEnv` fails the N-th operation and simulates power loss. Tests sweep
  every fault point and check that every acknowledged write survives, in
  flashkv, raft's storage, tsvdb and the CLI. `MemEnv` adds torn writes and
  bit flips for simulation.
- **Compaction never blocks reads** (eguan/ibs): new files are published with
  one pointer swap, and readers hold immutable snapshots. MVCC snapshots
  support optimistic, serializable transactions.

### raft: distribution primitives

- **Raft**, deterministic and transport-agnostic (`tick()`, `step(msg)`),
  with durable state written before any dependent message is sent.
  `FileStorage` is built on flashkv's `Env`.
- From the Raft thesis: **pre-vote**, **ReadIndex** linearizable reads, an
  empty entry per new leader, **one-server-at-a-time membership changes**
  with learners, **leadership transfer**, and **snapshots** sent in
  resumable chunks.
- **Protocol-aware recovery** (TigerBeetle; Alagappan et al., FAST '18): a
  node whose log was damaged keeps the intact prefix and neither votes nor
  campaigns until it holds the leader's whole log. The state file holds two
  checksummed copies.
- **Deterministic simulation** (TigerBeetle's VOPR): one seed fixes a whole
  run of 3 to 7 replicas with message loss, partitions, crashes, power loss,
  torn writes, bit flips, I/O errors and membership changes. Election safety,
  log matching, state machine safety, linearizable reads, snapshots and
  membership are checked after every event, then the cluster must converge.
  Removing a safety rule makes seeds fail. A failing seed replays exactly.
- **TCP transport and wire format** (`std::net` only): each message is a
  CRC-framed record, and the transport is lossy by design.
- **Shared-secret authentication**: an HMAC-SHA256 challenge-response, then
  an HMAC tag on every record (SHA-256 and HMAC are written in the crate and
  checked against the FIPS 180-4 and RFC 4231 vectors). There is no
  encryption, no roles and no rotation, and the code has had no audit. On a
  hostile network, put a tunnel (WireGuard, stunnel) in front of it.
- **SWIM** membership and **Lamport clocks**. There is no HLC: terms and log
  indices already order replicated state.
- **Not implemented**: automatic leader handoff, step-down on loss of quorum,
  pipelined replication, a checksum chain over the log (the per-record CRCs
  and the simulator's checks cover what it would catch).

### pcapfast: the parser

pcapfast mmaps the capture read-only (it is input, so mmap cannot corrupt
the database) and detects pcap or pcapng (both byte orders, µs or ns). It
parses record-aligned chunks on scoped threads, without copying packets,
and merges per-thread flow tables. A torn tail is reported, not fatal.

`cargo xtask bench`, 4.8 million packets (3.6 GB) in the page cache, 16
threads, best of 5:

| what is timed | time | rate |
|---|---|---|
| parsing the mapped file | 134 ms | 36 Mpkt/s, 27 GB/s |
| the whole `parse_file` call (with mmap/munmap) | 348 ms | 14 Mpkt/s, 10 GB/s |

### tsvdb: the time-series database

- **Data model**: InfluxDB line protocol. A series is a measurement plus a
  tag set, held in an inverted tag index. Each (series, field) pair is a
  typed column.
- **Write path**: new series and schema go to flashkv, then the columns go
  to a CRC-framed WAL of tsvdb's own (fsynced with `sync` on), then to an
  in-memory buffer. A flush writes one immutable chunk per column and hour
  (delta-of-delta timestamps, Gorilla XOR floats, zigzag integers,
  bit-packed booleans), with per-chunk statistics.
- **Fast ingestion**: plain lines of a known series are parsed straight into
  columns, and large writes are parsed on several threads.
- **Compaction, downsampling** (`rollup`) and **retention**
  (`retain --keep 7d`, which drops whole partitions, as QuestDB's TTL does).
- **Queries**: tag filters, `sum`/`count`/`min`/`max`/`mean`/`first`/`last`,
  time windows, top-N, `--fill prev|linear|N`, `--latest`. A chunk that lies
  inside the range and inside one window is answered from its statistics
  without being decoded. Large queries read their columns on several
  threads.

#### Ideas taken from QuestDB

| QuestDB | LumenDB |
|---|---|
| `SAMPLE BY`, calendar-aligned, `ALIGN TO FIRST OBSERVATION` | `--every`, `--align start` |
| `FILL(PREV \| LINEAR \| const)` | `--fill prev\|linear\|NUMBER` |
| `first`, `last`, `nsum` | `first`, `last`; compensated `sum` and `mean` |
| `LATEST ON` | `--latest 1` |
| TTL | `retain --keep`, replicated by the cluster |
| `1h`, `7d`, ISO dates, `now()` | the same on the command line |

Not taken: `ASOF JOIN`, materialized views, `SYMBOL`, `FILL(NULL)`, Parquet,
and the network protocols (ILP, REST, PostgreSQL wire).

#### Measured against QuestDB

A TSBS-like "cpu-only" workload (`bench gen-cpu`: 100 hosts, ten gauges, 10 s
interval, 24 h, 864,000 rows). QuestDB 10.2.0 runs with its default
configuration and gets the same file over ILP/TCP. The machine is a Ryzen 7
5800U with an NVMe SSD (ext4).

| ingestion, rows/s | LumenDB | QuestDB |
|---|---|---|
| 1 writer, no fsync | 598,000 | 262,000 |
| 4 writers, no fsync | 765,000 | 326,000 (8 connections) |
| 4 writers, fsync per 5000 rows | 604,000 | — |

| query, best of 10, ms | LumenDB | QuestDB (`execute`) |
|---|---|---|
| single-groupby-1-1-1 | 0.018 | 2.0 |
| single-groupby-1-1-12 | 0.24 | 5.5 |
| cpu-max-all-1 | 0.030 | 2.6 |
| double-groupby-1 | 0.22 | 9.9 |
| double-groupby-all | 2.4 | 13.1 |
| lastpoint | 0.53 | 1.2 |
| sum-everything-all | 2.9 | 20.7 |

On disk: 75 MB against about 560 MB.

Caveats: LumenDB runs in process, while QuestDB is a server fed by a Python
sender. Hour windows match LumenDB's partitions, so those queries are
answered from statistics. QuestDB does more (SQL, joins, value filters).
This is one workload on one machine. To reproduce:
`bench gen-cpu cpu.lp && bench tsdb-bench --db DIR --sync 0 --runs 10`.

### cluster: a tsvdb replicated by Raft

```text
  client --write_lines--> leader                          every node
                            |                     +--------------------------+
                            | stamp timestamps    | raft log   (FileStorage) |
                            | propose, as text    |    |                     |
                            v                     |    v commit              |
                       Raft log ---replicated---> | tsvdb   (apply, in order)|
                                                  +--------------------------+
```

- Every node keeps a full copy. Writes go through the leader.
  `query_consistent` is linearizable, while `query` reads the local copy.
- Applying an entry twice is harmless, so replay after a crash is safe.
- Retention is an order in the log, so every node drops the same partitions.
- Snapshots are compressed database dumps.
- Membership: add a node as a learner, then promote it to voter once it has
  caught up.
- `bench serve` runs a node, and `bench client` talks to a cluster through a
  line-based TCP protocol documented in `cluster::client`. The client follows
  the leader and retries only what cannot have been applied.

## Usage

```sh
cargo build --release
B=target/release/bench

$B gen-pcap /tmp/cap.pcapng --packets 1000000 --flows 5000 --format pcapng
$B ingest /tmp/cap.pcapng --db /tmp/lumendb
$B query --db /tmp/lumendb --agg sum --top 10                       # heaviest flows (bytes)
$B query --db /tmp/lumendb --measurement traffic --field packets \
         --agg sum --every 1m --fill 0 --start 2024-05-01 --end now   # packets per minute
$B query --db /tmp/lumendb --where proto=udp --where dport=53 --agg count
$B retain --db /tmp/lumendb --keep 7d
echo 'cpu,host=a usage=0.5 1700000000000000000' > /tmp/m.lp
$B write /tmp/m.lp --db /tmp/lumendb
$B kv-bench --db /tmp/kv --ops 1000000 --sync 0                   # flashkv throughput
$B crc-bench                                                      # every CRC32C implementation
$B gen-cpu /tmp/cpu.lp && $B tsdb-bench --db /tmp/tsdb --sync 0   # TSBS-like benchmark
$B parse-bench /tmp/cap.pcapng                                    # pcapfast throughput
$B cluster-demo                                                   # 3 replicated nodes, then a failover
$B vopr --seeds 200                                               # Raft simulation
```

Storage commands accept `--sync 0|1`, `--background 0|1` and
`--fail-after N` (inject an I/O error at the N-th filesystem operation).
`bench help` lists every flag.

A three-node cluster:

```sh
P="--peer 1=127.0.0.1:7001 --peer 2=127.0.0.1:7002 --peer 3=127.0.0.1:7003"
for i in 1 2 3; do
  $B serve --id $i --dir /tmp/n$i --raft 127.0.0.1:700$i --client 127.0.0.1:800$i --voters 1,2,3 $P &
done
c() { $B client --nodes 127.0.0.1:8001,127.0.0.1:8002,127.0.0.1:8003 "$@"; }
c write /tmp/m.lp
c query --measurement cpu --field usage --agg mean
c status
c shutdown
```

Add `--secret-file FILE` to every `serve` and `client` to authenticate
nodes and clients.

As a library:

```rust
use tsvdb::{Agg, Db, DbOptions, Query};

let db = Db::open("data".as_ref(), DbOptions::default())?;
db.write_lines("cpu,host=a usage=0.5 1700000000000000000")?;
let rows = db.query(&Query::new("cpu", "usage").filter("host", "a").agg(Agg::Mean))?;
let stats = pcapfast::parse_file("cap.pcap".as_ref(), &Default::default())?;
db.ingest_capture(&stats)?;
```

## xtask

| command | does |
|---|---|
| `cargo xtask dev-check` | `cargo fmt --check`, `clippy -D warnings`, then every test under `cargo llvm-cov` with a 100% line and region gate |
| `cargo xtask dev-check --no-coverage` | the same with plain `cargo test` |
| `cargo xtask kani` | the proofs, with virtual memory capped at 8 GiB |
| `cargo xtask vopr [--seeds N]` | the Raft simulation in release mode |
| `cargo xtask bench` | writes a 3.6 GB synthetic capture and runs `parse-bench` on it |

Prerequisites: `cargo install cargo-llvm-cov` and
`cargo install --locked kani-verifier && cargo kani setup`.

**Coverage**: every line and region of every file is covered, binaries
included.

**Proofs**: the kani harnesses in [`proofs`](proofs/src/lib.rs) prove, within
the bounds stated in each:

- the flashkv varint round-trips every `u64`;
- CRC32C matches its published check values (the portable version: kani
  cannot model the CPU instructions; unit tests check every hardware version
  against it), and CRC masking is a bijection;

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

raft's `Log::append` invariants are checked by exhaustive enumeration over a
small finite domain instead, because CBMC runs out of memory on them.

## CI

[`.github/workflows/ci.yml`](.github/workflows/ci.yml):

1. `cargo xtask dev-check` (fmt, clippy, tests, 100% coverage);
2. `cargo xtask kani`, with a pinned kani and a cached, retried download;
3. `cargo build --release --workspace`;
4. on `ubuntu-24.04-arm`: clippy, tests and `bench crc-bench`.

## Authorship

This code was initially written with the help of **Le Chonk**, aka
[Mistral Large 4](https://mistral.ai) from Mistral.ai. Le Chonk is a
large language model, and the entire codebase — crates, tests, proofs and
CI — was generated through conversations with it, then reviewed and edited
by a human (aka https://github.com/juanmaneo).

## License

MIT — see [LICENSE](LICENSE).
