//! aarch64: ARMv8's `crc32c*` (FEAT_CRC32, mandatory from ARMv8.1) and NEON's
//! `pmull` (FEAT_PMULL), on Ampere Altra (Neoverse N1), AmpereOne, AWS
//! Graviton, Apple M and every other server or desktop ARMv8 core.
//!
//! The fused shape, 3 accumulators and 4 streams of 2 words, is the one
//! Peter Cawley measured fastest on Ampere Altra (`v3s4x2`, about 36 GB/s a
//! core against about 23 GB/s for the three scalar streams alone): a Neoverse
//! N1 issues one `crc32cx` a cycle, and its two vector pipes take `pmull` and
//! `eor` at the same time.

use std::arch::aarch64::{
    __crc32cb, __crc32cd, uint64x2_t, vcombine_u64, vcreate_u64, veorq_u64, vgetq_lane_u64, vld1q_u8, vmull_high_p64,
    vmull_p64, vreinterpretq_p64_u64, vreinterpretq_u64_p128, vreinterpretq_u64_u8,
};

use crate::crc32c::{self, Engine};
use crate::{Clmul, Crc32cInstr};

/// Proof that the processor has the CRC32 instructions.
#[derive(Clone, Copy, Debug)]
pub struct Crc(());

impl Crc {
    pub fn detect() -> Option<Self> {
        std::arch::is_aarch64_feature_detected!("crc").then_some(Crc(()))
    }
}

/// Proof that the processor has the 64-bit polynomial multiplication.
#[derive(Clone, Copy, Debug)]
pub struct Pmull(());

impl Pmull {
    pub fn detect() -> Option<Self> {
        std::arch::is_aarch64_feature_detected!("pmull").then_some(Pmull(()))
    }
}

impl Crc32cInstr for Crc {
    #[inline(always)]
    fn crc_u8(self, crc: u32, byte: u8) -> u32 {
        // SAFETY: a `Crc` exists only once the processor has said it has FEAT_CRC32.
        unsafe { __crc32cb(crc, byte) }
    }

    #[inline(always)]
    fn crc_u64(self, crc: u32, word: u64) -> u32 {
        // SAFETY: as in `crc_u8`.
        unsafe { __crc32cd(crc, word) }
    }
}

impl Clmul for Pmull {
    type V = uint64x2_t;

    #[inline(always)]
    fn load(self, bytes: &[u8; 16]) -> uint64x2_t {
        // SAFETY: the 16 bytes are readable, the load does not need them
        // aligned, and NEON is part of aarch64.
        unsafe { vreinterpretq_u64_u8(vld1q_u8(bytes.as_ptr())) }
    }

    #[inline(always)]
    fn pair(self, lo: u64, hi: u64) -> uint64x2_t {
        // SAFETY: NEON is part of aarch64.
        unsafe { vcombine_u64(vcreate_u64(lo), vcreate_u64(hi)) }
    }

    #[inline(always)]
    fn lanes(self, v: uint64x2_t) -> (u64, u64) {
        // SAFETY: NEON is part of aarch64.
        unsafe { (vgetq_lane_u64::<0>(v), vgetq_lane_u64::<1>(v)) }
    }

    #[inline(always)]
    fn fold(self, a: uint64x2_t, k: uint64x2_t, c: uint64x2_t) -> uint64x2_t {
        // SAFETY: a `Pmull` exists only once the processor has said it has
        // FEAT_PMULL, and NEON is part of aarch64.
        unsafe {
            let lo = vmull_p64(vgetq_lane_u64::<0>(a), vgetq_lane_u64::<0>(k));
            let hi = vmull_high_p64(vreinterpretq_p64_u64(a), vreinterpretq_p64_u64(k));
            veorq_u64(veorq_u64(vreinterpretq_u64_p128(lo), vreinterpretq_u64_p128(hi)), c)
        }
    }

    #[inline(always)]
    fn mul32(self, a: u32, b: u32) -> u64 {
        // SAFETY: as in `fold`.
        unsafe { vmull_p64(u64::from(a), u64::from(b)) as u64 }
    }
}

/// The CRC32C implementations this processor can run, the fastest first.
pub(crate) fn crc32c_engines(out: &mut Vec<Engine>) {
    let (crc, pmull) = (Crc::detect(), Pmull::detect());
    out.extend(crc.and(pmull).map(|_| Engine {
        name: "aarch64: crc32cx + PMULL, fused (4 streams, 3 accumulators)",
        extend: fused,
    }));
    out.extend(crc.map(|_| Engine {
        name: "aarch64: crc32cx, one stream",
        extend: single,
    }));
}

/// The fused algorithm with `V` accumulators and `S` streams of `X` words.
/// (Rust's `aes` target feature is the one that enables `pmull`.)
#[target_feature(enable = "crc,aes")]
fn fused_shape<const V: usize, const S: usize, const X: usize>(crc: u32, data: &[u8]) -> u32 {
    crc32c::fused::<_, _, V, S, X>(Crc(()), Pmull(()), crc, data)
}

fn fused(crc: u32, data: &[u8]) -> u32 {
    // SAFETY: `crc32c_engines` lists this only when the processor has both.
    unsafe { fused_shape::<3, 4, 2>(crc, data) }
}

#[target_feature(enable = "crc")]
fn single_run(crc: u32, data: &[u8]) -> u32 {
    !crc32c::single(Crc(()), !crc, data)
}

fn single(crc: u32, data: &[u8]) -> u32 {
    // SAFETY: `crc32c_engines` lists this only when the processor has FEAT_CRC32.
    unsafe { single_run(crc, data) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crc32c::tests::{check, Unchecked};

    /// Every aarch64 processor the tests run on has both.
    #[test]
    fn both_engines_are_listed() {
        let mut all = Vec::new();
        crc32c_engines(&mut all);
        assert_eq!(all.len(), 2);
    }

    /// The fused algorithm is CRC32C whatever its shape, including a single
    /// accumulator and a single stream.
    #[test]
    fn every_shape_is_crc32c() {
        assert!(Crc::detect().is_some());
        assert!(Pmull::detect().is_some());
        let shapes: [(&str, Unchecked); 5] = [
            ("v3 s4 x2", fused_shape::<3, 4, 2>),
            ("v1 s3 x2", fused_shape::<1, 3, 2>),
            ("v2 s2 x1", fused_shape::<2, 2, 1>),
            ("v4 s1 x3", fused_shape::<4, 1, 3>),
            ("v1 s1 x1", fused_shape::<1, 1, 1>),
        ];
        for (name, f) in shapes {
            // SAFETY: the processor has FEAT_CRC32 and FEAT_PMULL (asserted above).
            check(name, |crc, data| unsafe { f(crc, data) });
        }
    }
}
