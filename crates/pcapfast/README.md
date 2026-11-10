# pcapfast

The zero-copy, multithreaded pcap / pcapng parser of
[LumenDB](https://github.com/juanmaneo/LumenDB).

- Detects pcap or pcapng (both byte orders, µs or ns timestamps).
- Maps the capture read-only, cuts it into record-aligned chunks and parses
  them on scoped threads; headers are read in place, packets never copied.
- Extracts flows (5-tuple: packets, bytes, first and last seen) and a
  traffic timeline. A torn tail is reported, not fatal.

```rust
let stats = pcapfast::parse_file("capture.pcapng".as_ref(), &Default::default())?;
println!("{} packets, {} bytes", stats.packets, stats.bytes);
```

License: MIT.
