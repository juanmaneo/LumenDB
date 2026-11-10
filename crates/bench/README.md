# lumen-bench

The command line of [LumenDB](https://github.com/juanmaneo/LumenDB). It
installs a binary named `bench`:

```sh
cargo install lumen-bench

bench gen-pcap /tmp/cap.pcapng --packets 1000000 --flows 5000 --format pcapng
bench ingest /tmp/cap.pcapng --db /tmp/lumendb
bench query --db /tmp/lumendb --agg sum --top 10      # heaviest flows
bench tsdb-bench --db /tmp/tsbs                       # TSBS-like workload
bench serve --id 1 --dir /tmp/n1 --raft 127.0.0.1:7001 --client 127.0.0.1:8001 --voters 1
bench client --nodes 127.0.0.1:8001 status
```

`bench` with no arguments lists every command: capture generation and
ingestion, line protocol writes, queries, retention, KV / CRC / parser
benchmarks, a deterministic Raft simulator (`vopr`) and a replicated
cluster (`serve`, `client`).

License: MIT.
