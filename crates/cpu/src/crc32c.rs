//! CRC32C (Castagnoli), the checksum of every log record, table block and
//! Raft message. [`extend`] runs the fastest implementation the processor
//! has, picked once at the first call; [`engines`] lists them all.
//!
//! # The fused algorithm
//!
//! One CRC instruction after the other runs at the instruction's latency, 8
//! bytes every 2 or 3 cycles, while the processor could start one every
//! cycle. `fused` keeps it busy (after Peter Cawley's "fusion" CRC32C,
//! <https://github.com/corsix/fast-crc32>). It cuts a block of the data into
//! `S` scalar streams, each run through the CRC instruction by its own chain,
//! followed by a vector region that `V` accumulators fold with carry-less
//! multiplication, on the vector units, at the same time:
//!
//! ```text
//! | stream 0 | stream 1 | ... | stream S-1 | vector region (V accumulators) |
//! ```
//!
//! At the end of the block, the accumulators are folded into one, and each
//! stream's register is moved to the end of the block by one carry-less
//! multiplication, `c·x^(8n) mod P`. The CRC is linear, so the XOR of all
//! of them is the CRC of the block. The constants are powers of x modulo P,
//! computed at compile time (`x_pow`) for each block size, so blocks have a
//! few fixed sizes: as many of 64 steps as fit, then of 8 steps, then at most
//! one each of 4, 2 and 1 steps, then the rest one instruction at a time.
//!
//! The registers are bit-reflected: bit `i` of a 32-bit value is the
//! coefficient of `x^(31-i)`. For two such values zero-extended to 64 bits,
//! the carry-less product is `x^65·a·b` in the 128-bit reflected form, and its
//! low 64 bits read as a 64-bit message are `x·a·b`; the CRC instruction on
//! that word multiplies by `x^32` and reduces modulo P. Hence the shift
//! constant `x^(8n-33)` for `n` bytes, and the fold constants `x^(8d+31)` (low
//! lane) and `x^(8d-33)` (high lane) for an accumulator moved `d` bytes.

use crate::{Clmul, Crc32cInstr};

/// The Castagnoli polynomial, bit-reflected, without its `x^32` term.
pub const POLY: u32 = 0x82f6_3b78;

/// Continue a finalized CRC32C over more data:
/// `extend(extend(0, a), b) == extend(0, a ++ b)`.
pub type Extend = fn(u32, &[u8]) -> u32;

/// One implementation of CRC32C.
#[derive(Clone, Copy, Debug)]
pub struct Engine {
    pub name: &'static str,
    pub extend: Extend,
}

/// Every implementation this processor can run, the fastest first. The last
/// is the portable one.
pub fn engines() -> Vec<Engine> {
    let mut all = Vec::new();
    #[cfg(all(target_arch = "x86_64", not(kani)))]
    crate::x86_64::crc32c_engines(&mut all);
    #[cfg(all(target_arch = "aarch64", not(kani)))]
    crate::aarch64::crc32c_engines(&mut all);
    all.push(Engine {
        name: "portable: slicing-by-8 tables",
        extend: crate::portable::crc32c,
    });
    all
}

/// CRC32C of `data`, continuing the finalized CRC `crc` (0 to start), by the
/// fastest implementation the processor has.
#[cfg(not(kani))]
pub fn extend(crc: u32, data: &[u8]) -> u32 {
    static BEST: std::sync::OnceLock<Extend> = std::sync::OnceLock::new();
    BEST.get_or_init(|| engines()[0].extend)(crc, data)
}

/// [`extend`] for kani proofs: the portable implementation, because kani
/// can model neither the feature detection (CPUID is inline assembly) nor
/// the instructions. The tests check that every implementation is the same
/// function.
#[cfg(kani)]
pub fn extend(crc: u32, data: &[u8]) -> u32 {
    crate::portable::crc32c(crc, data)
}

/// `x·v mod P`.
const fn mul_x(v: u32) -> u32 {
    (v >> 1) ^ (POLY & (v & 1).wrapping_neg())
}

/// `a·b mod P`.
const fn mul_mod(a: u32, b: u32) -> u32 {
    let mut r = 0;
    let mut i = 0;
    while i < 32 {
        r = mul_x(r) ^ (b & ((a >> i) & 1).wrapping_neg());
        i += 1;
    }
    r
}

/// `x^e mod P`.
const fn x_pow(mut e: u64) -> u32 {
    // x^0 and x^1.
    let (mut r, mut sq) = (1 << 31, 1 << 30);
    while e > 0 {
        r = [r, mul_mod(r, sq)][(e & 1) as usize];
        sq = mul_mod(sq, sq);
        e >>= 1;
    }
    r
}

/// The constant that moves a register over `bytes` bytes by one carry-less
/// multiplication: `x^(8·bytes-33) mod P` (`bytes >= 5`).
const fn shift_k(bytes: usize) -> u32 {
    x_pow(8 * bytes as u64 - 33)
}

/// The constants that fold a 128-bit accumulator `bytes` bytes forward, for
/// its low and its high lane.
const fn fold_k(bytes: usize) -> (u64, u64) {
    (x_pow(8 * bytes as u64 + 31) as u64, shift_k(bytes) as u64)
}

/// The shift constant of each of the `S` streams of a block whose streams
/// are `stream` bytes long, followed by a `vector` byte region.
const fn stream_ks<const S: usize>(stream: usize, vector: usize) -> [u32; S] {
    let mut k = [0; S];
    let mut s = 0;
    while s < S {
        k[s] = shift_k((S - 1 - s) * stream + vector);
        s += 1;
    }
    k
}

/// CRC32C of `data` from the finalized `crc`, by the fused algorithm with
/// `V` vector accumulators and `S` scalar streams that take `X` words each
/// per step (`V`, `S` and `X` at least 1).
#[inline(always)]
pub(crate) fn fused<I: Crc32cInstr, M: Clmul, const V: usize, const S: usize, const X: usize>(
    i: I,
    m: M,
    crc: u32,
    data: &[u8],
) -> u32 {
    let (crc, data) = blocks::<I, M, V, S, X, 64>(i, m, !crc, data);
    let (crc, data) = blocks::<I, M, V, S, X, 8>(i, m, crc, data);
    let (crc, data) = blocks::<I, M, V, S, X, 4>(i, m, crc, data);
    let (crc, data) = blocks::<I, M, V, S, X, 2>(i, m, crc, data);
    let (crc, data) = blocks::<I, M, V, S, X, 1>(i, m, crc, data);
    !single(i, crc, data)
}

/// The raw register `crc` over `data`, one instruction after the other.
#[inline(always)]
pub(crate) fn single<I: Crc32cInstr>(i: I, mut crc: u32, data: &[u8]) -> u32 {
    let (words, rest) = data.as_chunks::<8>();
    for w in words {
        crc = i.crc_u64(crc, u64::from_le_bytes(*w));
    }
    for &b in rest {
        crc = i.crc_u8(crc, b);
    }
    crc
}

/// The raw register `crc` over as many blocks of `STEPS` steps as `data`
/// holds, and what is left of it.
#[inline(always)]
fn blocks<I: Crc32cInstr, M: Clmul, const V: usize, const S: usize, const X: usize, const STEPS: usize>(
    i: I,
    m: M,
    mut crc: u32,
    mut data: &[u8],
) -> (u32, &[u8]) {
    let size = (S * 8 * X + V * 16) * STEPS;
    while let Some((head, rest)) = data.split_at_checked(size) {
        crc = block::<I, M, V, S, X, STEPS>(i, m, crc, head);
        data = rest;
    }
    (crc, data)
}

/// The raw register `crc` over one block of `STEPS` steps.
#[inline(always)]
fn block<I: Crc32cInstr, M: Clmul, const V: usize, const S: usize, const X: usize, const STEPS: usize>(
    i: I,
    m: M,
    crc: u32,
    block: &[u8],
) -> u32 {
    let stream = 8 * X * STEPS;
    let (scalar, vector) = block.split_at(S * stream);
    let streams: [&[[[u8; 8]; X]]; S] =
        std::array::from_fn(|s| scalar[s * stream..][..stream].as_chunks().0.as_chunks().0);
    let rows: &[[[u8; 16]; V]] = vector.as_chunks().0.as_chunks().0;
    let (lo, hi) = const { fold_k(16 * V) };
    let k = m.pair(lo, hi);
    let mut acc: [M::V; V] = std::array::from_fn(|j| m.load(&rows[0][j]));
    let mut crcs = [0; S];
    crcs[0] = crc;
    for (step, row) in rows[1..].iter().enumerate() {
        for (a, chunk) in acc.iter_mut().zip(row) {
            *a = m.fold(*a, k, m.load(chunk));
        }
        scalar_step(i, &mut crcs, &streams, step);
    }
    scalar_step(i, &mut crcs, &streams, STEPS - 1);
    // The accumulators, 16 bytes apart, into one at the end of the block.
    let (lo, hi) = const { fold_k(16) };
    let k16 = m.pair(lo, hi);
    let mut x = acc[0];
    for &a in &acc[1..] {
        x = m.fold(x, k16, a);
    }
    // Each stream's register moved to the end of the block, as a 64-bit
    // product that the CRC instruction reduces with the last word.
    let ks: [u32; S] = const { stream_ks::<S>(8 * X * STEPS, 16 * V * STEPS) };
    let mut moved = 0;
    for (&c, k) in crcs.iter().zip(ks) {
        moved ^= m.mul32(c, k);
    }
    let (lo, hi) = m.lanes(x);
    i.crc_u64(i.crc_u64(0, lo), hi ^ moved)
}

/// One step of every scalar stream: `X` words each, interleaved.
#[inline(always)]
fn scalar_step<I: Crc32cInstr, const S: usize, const X: usize>(
    i: I,
    crcs: &mut [u32; S],
    streams: &[&[[[u8; 8]; X]]; S],
    step: usize,
) {
    for x in 0..X {
        for (c, stream) in crcs.iter_mut().zip(streams) {
            *c = i.crc_u64(*c, u64::from_le_bytes(stream[step][x]));
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// An implementation compiled for instructions the caller must check for.
    pub(crate) type Unchecked = unsafe fn(u32, &[u8]) -> u32;

    /// CRC32C one bit at a time, the definition.
    pub(crate) fn bitwise(crc: u32, data: &[u8]) -> u32 {
        let mut crc = !crc;
        for &b in data {
            crc ^= b as u32;
            for _ in 0..8 {
                crc = mul_x(crc);
            }
        }
        !crc
    }

    /// Pseudo-random bytes.
    pub(crate) fn bytes(n: usize) -> Vec<u8> {
        (0..n as u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
            .collect()
    }

    /// The lengths that reach every path of the fused algorithm for every
    /// shape the tests use: every length up to two 8-step blocks of the
    /// largest step (128 bytes), then around several 64-step blocks.
    pub(crate) fn lengths() -> impl Iterator<Item = usize> {
        (0..=2100).chain([
            4095,
            4096,
            4097,
            7167,
            7168,
            7169,
            9000,
            14_336 + 1000 + 112 + 13,
            70_000,
        ])
    }

    /// `f` is CRC32C at every length, offset and starting value.
    pub(crate) fn check(name: &str, f: impl Fn(u32, &[u8]) -> u32) {
        let data = bytes(70_000 + 9);
        for offset in [0, 1, 7] {
            for len in lengths() {
                let part = &data[offset..offset + len];
                for init in [0, 0xdead_beef] {
                    let (got, want) = (f(init, part), bitwise(init, part));
                    assert_eq!(got, want, "{name}: offset {offset}, length {len}, init {init:#x}");
                }
            }
        }
        assert_eq!(f(0, b"123456789"), 0xe306_9283, "{name}");
    }

    #[test]
    fn every_engine_is_crc32c() {
        let all = engines();
        assert_eq!(all.last().map(|e| e.name), Some("portable: slicing-by-8 tables"));
        for e in &all {
            check(e.name, e.extend);
        }
        assert_eq!(extend(0, b"123456789"), 0xe306_9283);
    }

    #[test]
    fn known_vectors() {
        let ascending: Vec<u8> = (0..32).collect();
        for e in engines() {
            let name = e.name;
            assert_eq!((e.extend)(0, b""), 0, "{name}");
            assert_eq!((e.extend)(0, &[0u8; 32]), 0x8a91_36aa, "{name}");
            assert_eq!((e.extend)(0, &[0xffu8; 32]), 0x62a8_ab43, "{name}");
            assert_eq!((e.extend)(0, &ascending), 0x46dd_794e, "{name}");
        }
    }

    /// The constants, computed at run time (they are otherwise only
    /// evaluated by the compiler), against values that are known.
    #[test]
    fn constants() {
        assert_eq!(x_pow(0), 1 << 31);
        assert_eq!(x_pow(31), 1);
        // x^32 is P without its x^32 term.
        assert_eq!(x_pow(32), POLY);
        assert_eq!(mul_mod(x_pow(100), x_pow(23)), x_pow(123));
        // Moving a register over n zero bytes is multiplying it by x^(8n).
        for n in [5, 16, 64, 1000] {
            let reg = 0x1234_5678;
            let by_zeros = !bitwise(!reg, &vec![0; n]);
            assert_eq!(mul_mod(reg, x_pow(8 * n as u64)), by_zeros, "{n}");
        }
        assert_eq!(fold_k(16), (x_pow(159) as u64, x_pow(95) as u64));
        assert_eq!(stream_ks::<2>(10, 20), [shift_k(30), shift_k(20)]);
        assert_eq!(shift_k(5), x_pow(7));
    }
}
