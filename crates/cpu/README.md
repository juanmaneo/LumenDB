# lumen-cpu

The portability layer of [LumenDB](https://github.com/juanmaneo/LumenDB):
everything that needs a particular processor instruction to be fast.

- A trait per kind of instruction (`Crc32cInstr`, `Clmul`), implemented by
  each architecture: x86_64 (SSE4.2 + PCLMULQDQ) and aarch64 (CRC + PMULL).
- Algorithms written once over the traits: CRC32C by Peter Cawley's fusion
  method.
- A portable plain-Rust fallback, used on other processors and by kani.

The fastest implementation the processor supports is picked at the first
call.

```rust
let crc = lumen_cpu::crc32c::extend(0, b"123456789");
assert_eq!(crc, 0xE306_9283);
```

License: MIT.
