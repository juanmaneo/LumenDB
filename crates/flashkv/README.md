# lumen-flashkv

The crash-safe, ordered key-value store of
[LumenDB](https://github.com/juanmaneo/LumenDB): a LevelDB-style LSM tree.

- CRC32C-framed write-ahead log, memtable, SSTables with bloom filters and
  per-block CRCs, leveled compaction, `MANIFEST` + `CURRENT`.
- With `sync` on (the default), a write returns `Ok` only once it is on
  stable storage. Torn tails are cut on recovery, and corruption is an
  `Err`, never a crash: tables are read with `pread`, never mmapped.
- Background flush and compaction, MVCC snapshots, optimistic transactions.
- All I/O goes through the `Env` trait. `FaultEnv` and `MemEnv` inject
  failures and simulate power loss for tests.

```rust
use lumen_flashkv::{Db, DbOptions, WriteBatch};

let db = Db::open("data".as_ref(), DbOptions::default())?;
db.put(b"k1", b"v1")?;
let mut batch = WriteBatch::new();
batch.put(b"k2", b"v2").delete(b"k1");
db.write(&batch)?; // atomic
assert_eq!(db.get(b"k2")?, Some(b"v2".to_vec()));
```

License: MIT.
