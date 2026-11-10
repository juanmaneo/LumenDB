# Changelog

All notable changes to LumenDB are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-11-10

Initial release: a pure-Rust workspace, with no dependency beyond `memmap2`
and `parking_lot`, 100% line and region test coverage, kani proofs of the
core invariants, and fault-injection tests that sweep every fault point.

### Added

- `lumen-cpu`: the portability layer. SSE4.2, PCLMULQDQ and NEON instruction
  traits with a plain-Rust fallback; CRC32C by the corsix/fast-crc32 fusion
  (16 GB/s on one Zen 3 core).
- `lumen-flashkv`: the crash-safe ordered key-value store, an LSM in the
  style of LevelDB: WAL, memtable, SSTables, leveled compaction, MVCC
  snapshots, sticky errors, torn-tail recovery.
- `lumen-raft`: Raft (pre-vote, ReadIndex, single-server membership changes),
  SWIM membership and Lamport clocks, checked by a deterministic VOPR-style
  simulation over hundreds of seeds.
- `pcapfast`: the zero-copy multithreaded pcap / pcapng parser: 36 Mpkt/s on
  16 threads, torn tails reported, not fatal.
- `tsvdb`: the columnar time-series database on flashkv: Gorilla chunks,
  line-protocol writes, `--every` windows, fills, top-N, retention, rollups,
  statistics-only answers for whole chunks. Single-writer ingestion of
  598,000 rows/s against QuestDB's 262,000 on the same machine.
- `lumen-cluster`: a tsvdb replicated by Raft, with a line-based TCP client
  that follows the leader and retries only what cannot have been applied.
- `lumen-bench`: the command line: generate, ingest, query, benchmark.

Known limits: the wire has authentication but no encryption (put a tunnel in
front of it), and the SQL of a server like QuestDB (joins, value filters) is
out of scope.
