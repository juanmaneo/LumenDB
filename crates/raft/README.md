# lumen-raft

The distribution primitives of
[LumenDB](https://github.com/juanmaneo/LumenDB).

- **Raft**: elections, log replication, majority-quorum commit, membership
  changes, snapshots, leadership transfer. The `Node` is deterministic and
  transport-agnostic: drive it with `tick()` and `step(msg)`. Term, vote and
  entries are durable before any message that depends on them leaves.
- **SWIM** membership: probes, indirect probes, suspicion, piggybacked
  gossip.
- **Lamport clocks**: ordering never depends on wall clocks.
- `FileStorage` for durable state (on lumen-flashkv's `Env`), a TCP
  `Transport`, a `Server` loop that feeds a `StateMachine`, optional
  authenticated connections, and a deterministic cluster simulator (`sim`)
  in the style of TigerBeetle's VOPR.

License: MIT.
