//! x86_64: SSE4.2's `crc32` and PCLMULQDQ's `pclmulqdq`, on every Intel
//! processor since Westmere (2010) and every AMD one since Bulldozer (2011).

use std::arch::x86_64::{
    __m128i, _mm_clmulepi64_si128, _mm_crc32_u64, _mm_crc32_u8, _mm_cvtsi128_si64, _mm_cvtsi32_si128, _mm_loadu_si128,
    _mm_set_epi64x, _mm_unpackhi_epi64, _mm_xor_si128,
};

use crate::crc32c::{self, Engine};
use crate::{Clmul, Crc32cInstr};

/// Proof that the processor has SSE4.2.
#[derive(Clone, Copy, Debug)]
pub struct Sse42(());

impl Sse42 {
    pub fn detect() -> Option<Self> {
        std::arch::is_x86_feature_detected!("sse4.2").then_some(Sse42(()))
    }
}

/// Proof that the processor has PCLMULQDQ.
#[derive(Clone, Copy, Debug)]
pub struct Pclmulqdq(());

impl Pclmulqdq {
    pub fn detect() -> Option<Self> {
        std::arch::is_x86_feature_detected!("pclmulqdq").then_some(Pclmulqdq(()))
    }
}

impl Crc32cInstr for Sse42 {
    #[inline(always)]
    fn crc_u8(self, crc: u32, byte: u8) -> u32 {
        // SAFETY: an `Sse42` exists only once the processor has said it has SSE4.2.
        unsafe { _mm_crc32_u8(crc, byte) }
    }

    #[inline(always)]
    fn crc_u64(self, crc: u32, word: u64) -> u32 {
        // SAFETY: as in `crc_u8`. The result is a 32-bit register zero-extended.
        unsafe { _mm_crc32_u64(u64::from(crc), word) as u32 }
    }
}

impl Clmul for Pclmulqdq {
    type V = __m128i;

    #[inline(always)]
    fn load(self, bytes: &[u8; 16]) -> __m128i {
        // SAFETY: the 16 bytes are readable; the load does not need them aligned.
        unsafe { _mm_loadu_si128(bytes.as_ptr().cast()) }
    }

    #[inline(always)]
    fn pair(self, lo: u64, hi: u64) -> __m128i {
        // SAFETY: SSE2 is part of x86_64.
        unsafe { _mm_set_epi64x(hi as i64, lo as i64) }
    }

    #[inline(always)]
    fn lanes(self, v: __m128i) -> (u64, u64) {
        // SAFETY: SSE2 is part of x86_64.
        unsafe {
            (
                _mm_cvtsi128_si64(v) as u64,
                _mm_cvtsi128_si64(_mm_unpackhi_epi64(v, v)) as u64,
            )
        }
    }

    #[inline(always)]
    fn fold(self, a: __m128i, k: __m128i, c: __m128i) -> __m128i {
        // SAFETY: a `Pclmulqdq` exists only once the processor has said it has
        // PCLMULQDQ, and SSE2 is part of x86_64.
        unsafe {
            let (lo, hi) = (_mm_clmulepi64_si128::<0x00>(a, k), _mm_clmulepi64_si128::<0x11>(a, k));
            _mm_xor_si128(_mm_xor_si128(lo, hi), c)
        }
    }

    #[inline(always)]
    fn mul32(self, a: u32, b: u32) -> u64 {
        // SAFETY: as in `fold`.
        unsafe {
            let (a, b) = (_mm_cvtsi32_si128(a as i32), _mm_cvtsi32_si128(b as i32));
            _mm_cvtsi128_si64(_mm_clmulepi64_si128::<0x00>(a, b)) as u64
        }
    }
}

/// The CRC32C implementations this processor can run, the fastest first.
pub(crate) fn crc32c_engines(out: &mut Vec<Engine>) {
    let (sse, clmul) = (Sse42::detect(), Pclmulqdq::detect());
    out.extend(sse.and(clmul).map(|_| Engine {
        name: "x86_64: SSE4.2 crc32 + PCLMULQDQ, fused (3 streams, 2 accumulators)",
        extend: fused,
    }));
    out.extend(sse.map(|_| Engine {
        name: "x86_64: SSE4.2 crc32, one stream",
        extend: single,
    }));
}

/// The fused algorithm with `V` accumulators and `S` streams of `X` words.
#[target_feature(enable = "sse4.2,pclmulqdq")]
fn fused_shape<const V: usize, const S: usize, const X: usize>(crc: u32, data: &[u8]) -> u32 {
    crc32c::fused::<_, _, V, S, X>(Sse42(()), Pclmulqdq(()), crc, data)
}

/// 2 accumulators and 3 streams of 4 words: the fastest shape on a Zen 3
/// (Ryzen 7 5800U), measured with hyperfine over buffers of 256 bytes to
/// 1 MiB, against 1 to 3 accumulators and 3 or 4 streams of 2 to 4 words.
fn fused(crc: u32, data: &[u8]) -> u32 {
    // SAFETY: `crc32c_engines` lists this only when the processor has both.
    unsafe { fused_shape::<2, 3, 4>(crc, data) }
}

#[target_feature(enable = "sse4.2")]
fn single_run(crc: u32, data: &[u8]) -> u32 {
    !crc32c::single(Sse42(()), !crc, data)
}

fn single(crc: u32, data: &[u8]) -> u32 {
    // SAFETY: `crc32c_engines` lists this only when the processor has SSE4.2.
    unsafe { single_run(crc, data) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crc32c::tests::{check, Unchecked};

    /// Every x86_64 processor the tests run on has both.
    #[test]
    fn both_engines_are_listed() {
        let mut all = Vec::new();
        crc32c_engines(&mut all);
        assert_eq!(all.len(), 2);
    }

    /// The fused algorithm is CRC32C whatever its shape, including several
    /// accumulators and a single stream.
    #[test]
    fn every_shape_is_crc32c() {
        assert!(Sse42::detect().is_some());
        assert!(Pclmulqdq::detect().is_some());
        let shapes: [(&str, Unchecked); 5] = [
            ("v2 s3 x4", fused_shape::<2, 3, 4>),
            ("v3 s4 x2", fused_shape::<3, 4, 2>),
            ("v2 s2 x1", fused_shape::<2, 2, 1>),
            ("v4 s1 x3", fused_shape::<4, 1, 3>),
            ("v1 s1 x1", fused_shape::<1, 1, 1>),
        ];
        for (name, f) in shapes {
            // SAFETY: the processor has SSE4.2 and PCLMULQDQ (asserted above).
            check(name, |crc, data| unsafe { f(crc, data) });
        }
    }
}
