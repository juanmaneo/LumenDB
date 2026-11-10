//! The portability layer. Everything in LumenDB that needs a particular
//! processor instruction to be fast lives in this crate, and no other crate
//! of the workspace touches `std::arch`.
//!
//! The pattern, for each kind of instruction:
//!
//! 1. A **trait** says what the instruction computes, in terms that do not
//!    depend on the architecture: [`Crc32cInstr`] is one step of the CRC32C
//!    register, [`Clmul`] is carry-less multiplication.
//! 2. Each **architecture implements** the traits in its own module
//!    (`x86_64`, `aarch64`), on a token type that only its `detect` makes,
//!    once the processor has said it has the instruction. That is what makes
//!    the trait methods safe to call.
//! 3. The **algorithms** are written once, generic over the traits (see
//!    [`crc32c`]). Each architecture runs them inside a function compiled for
//!    its instructions (`#[target_feature]`), where every trait method inlines
//!    down to the bare instruction.
//! 4. There is always a **portable** implementation in plain Rust
//!    ([`portable`]), for a processor without the instructions, and for kani,
//!    which can model neither the feature detection nor the instructions.
//!
//! The fastest implementation the processor can run is picked at the first
//! call, from what it reports.
//!
//! Adding an architecture means a module that implements the traits and
//! lists its implementations (see `x86_64::crc32c_engines`); adding a kind
//! of instruction means a trait here, an implementation in each architecture
//! module that has one, and a portable fallback.

// Without an architecture module (kani, or another processor), the generic
// algorithms have no caller.
#![cfg_attr(
    any(kani, not(any(target_arch = "x86_64", target_arch = "aarch64"))),
    allow(dead_code)
)]

pub mod crc32c;
pub mod portable;

#[cfg(all(target_arch = "aarch64", not(kani)))]
pub mod aarch64;
#[cfg(all(target_arch = "x86_64", not(kani)))]
pub mod x86_64;

/// The CRC32C instruction: one step of the CRC register for the Castagnoli
/// polynomial, bit-reflected and raw (no inversion before or after), as
/// x86's `crc32` (SSE4.2) and ARMv8's `crc32c*` (FEAT_CRC32) compute it.
pub trait Crc32cInstr: Copy {
    /// The register after one more byte.
    fn crc_u8(self, crc: u32, byte: u8) -> u32;
    /// The register after eight more bytes: `word` read little-endian.
    fn crc_u64(self, crc: u32, word: u64) -> u32;
}

/// Carry-less multiplication (of polynomials over GF(2)) on 128-bit vector
/// registers, as x86's `pclmulqdq` and ARMv8's `pmull` (FEAT_PMULL, NEON)
/// compute it.
pub trait Clmul: Copy {
    /// A 128-bit vector register.
    type V: Copy;
    /// 16 bytes in memory order: byte 0 is the low byte of the low lane.
    fn load(self, bytes: &[u8; 16]) -> Self::V;
    /// The register with 64-bit lanes `lo` and `hi`.
    fn pair(self, lo: u64, hi: u64) -> Self::V;
    /// The two 64-bit lanes, low first.
    fn lanes(self, v: Self::V) -> (u64, u64);
    /// `lo(a)·lo(k) ⊕ hi(a)·hi(k) ⊕ c`: the step that folds a CRC
    /// accumulator `a` forward onto the data `c`, by the constants `k`.
    fn fold(self, a: Self::V, k: Self::V, c: Self::V) -> Self::V;
    /// `a·b` (63 bits at most).
    fn mul32(self, a: u32, b: u32) -> u64;
}
