# tsvdb

The columnar time-series database of
[LumenDB](https://github.com/juanmaneo/LumenDB), on lumen-flashkv, inspired
by InfluxDB v3.

- Writes in InfluxDB line protocol. Each measurement + tag set is a series;
  each (series, field) a typed column.
- A write is durable when it returns. Flushes turn the buffer into
  compressed chunks per column and hour (delta-of-delta timestamps, Gorilla
  floats), merged in the background without blocking reads.
- Queries: time ranges, tag filters, `sum`/`count`/`min`/`max`/`mean`/
  `first`/`last` per series and time window, fills, latest point, top-N;
  downsampling (`rollup`) and retention.
- Ingests pcapfast captures: flows and a traffic timeline.

```rust
use tsvdb::{Agg, Db, DbOptions, Query};

let db = Db::open("data".as_ref(), DbOptions::default())?;
db.write_lines("cpu,host=a usage=0.5 1700000000000000000")?;
let rows = db.query(&Query::new("cpu", "usage").filter("host", "a").agg(Agg::Mean))?;
```

License: MIT.
