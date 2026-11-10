# lumen-cluster

A [tsvdb](https://crates.io/crates/tsvdb) replicated by
[lumen-raft](https://crates.io/crates/lumen-raft), part of
[LumenDB](https://github.com/juanmaneo/LumenDB).

- Every node keeps a full copy. Writes go through the leader's Raft log;
  every node applies them to its own database. Replaying the log is
  harmless, and a write refused for its data is refused on every node.
- Linearizable queries on the leader, local queries anywhere.
- Retention is replicated as an order in the log; snapshots are compressed
  dumps, sent in chunks.
- A TCP client protocol (`ClientServer`, `Client`, `ClusterClient`) with
  optional shared-secret authentication.

The `bench serve` and `bench client` commands of
[lumen-bench](https://crates.io/crates/lumen-bench) run it as processes.

License: MIT.
