//! CRC32C (Castagnoli) with LevelDB-style masking.
//!
//! No external crate. Where the processor has the instruction (SSE4.2 on x86)
//! it does 8 bytes per instruction, a few GB/s a core; anywhere else it is
//! slicing-by-8 over tables computed at compile time (`const fn`), which does
//! several hundred MB/s. Both are checked against a bit by bit version.

use std::sync::OnceLock;

const POLY: u32 = 0x82f6_3b78;

const fn make_tables() -> [[u32; 256]; 8] {
    let mut t = [[0u32; 256]; 8];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { (c >> 1) ^ POLY } else { c >> 1 };
            k += 1;
        }
        t[0][i] = c;
        i += 1;
    }
    let mut s = 1;
    while s < 8 {
        let mut i = 0;
        while i < 256 {
            let prev = t[s - 1][i];
            t[s][i] = (prev >> 8) ^ t[0][(prev & 0xff) as usize];
            i += 1;
        }
        s += 1;
    }
    t
}

static TABLES: [[u32; 256]; 8] = make_tables();

pub fn mask(crc: u32) -> u32 {
    crc.rotate_right(15).wrapping_add(0xa282_e8a8)
}

pub fn unmask(masked: u32) -> u32 {
    masked.wrapping_sub(0xa282_e8a8).rotate_left(15)
}

/// CRC32C of `data`.
pub fn crc32c(data: &[u8]) -> u32 {
    crc32c_extend(0, data)
}

/// Continue a finalized CRC32C `init` over more `data`
/// (`crc32c_extend(crc32c(a), b) == crc32c(a ++ b)`).
pub fn crc32c_extend(init: u32, data: &[u8]) -> u32 {
    static BEST: OnceLock<fn(u32, &[u8]) -> u32> = OnceLock::new();
    BEST.get_or_init(best)(init, data)
}

/// The fastest way there is here.
fn best() -> fn(u32, &[u8]) -> u32 {
    #[cfg(target_arch = "x86_64")]
    return std::arch::is_x86_feature_detected!("sse4.2")
        .then_some(hardware as fn(u32, &[u8]) -> u32)
        .unwrap_or(software);
    #[cfg(not(target_arch = "x86_64"))]
    software
}

/// [`crc32c_extend`] by the instruction of the processor, which must be there
/// (it is for what [`best`] says).
#[cfg(target_arch = "x86_64")]
fn hardware(init: u32, data: &[u8]) -> u32 {
    #[target_feature(enable = "sse4.2")]
    fn run(init: u32, data: &[u8]) -> u32 {
        use std::arch::x86_64::{_mm_crc32_u64, _mm_crc32_u8};
        let (chunks, rest) = data.as_chunks::<8>();
        let mut crc = u64::from(!init);
        for c in chunks {
            crc = _mm_crc32_u64(crc, u64::from_le_bytes(*c));
        }
        let mut crc = crc as u32;
        for &b in rest {
            crc = _mm_crc32_u8(crc, b);
        }
        !crc
    }
    // SAFETY: only reached when the processor has SSE4.2 (see `best`, and the
    // test that calls this checks for it).
    unsafe { run(init, data) }
}

/// [`crc32c_extend`] with tables, for any processor.
fn software(init: u32, data: &[u8]) -> u32 {
    let t = &TABLES;
    let mut crc = !init;
    let (chunks, rest) = data.as_chunks::<8>();
    for c in chunks {
        let lo = crc ^ u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
        crc = t[7][(lo & 0xff) as usize]
            ^ t[6][((lo >> 8) & 0xff) as usize]
            ^ t[5][((lo >> 16) & 0xff) as usize]
            ^ t[4][(lo >> 24) as usize]
            ^ t[3][c[4] as usize]
            ^ t[2][c[5] as usize]
            ^ t[1][c[6] as usize]
            ^ t[0][c[7] as usize];
    }
    for &b in rest {
        crc = (crc >> 8) ^ t[0][((crc ^ b as u32) & 0xff) as usize];
    }
    !crc
}

pub fn masked_crc(header: &[u8], payload: &[u8]) -> u32 {
    mask(crc32c_extend(crc32c(header), payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bitwise(data: &[u8]) -> u32 {
        let mut crc = !0u32;
        for &b in data {
            crc ^= b as u32;
            for _ in 0..8 {
                crc = if crc & 1 != 0 { (crc >> 1) ^ POLY } else { crc >> 1 };
            }
        }
        !crc
    }

    #[test]
    fn tables_match_runtime_construction() {
        // `make_tables` is const-evaluated for TABLES; run it once at runtime
        // to check the const path and the runtime path agree.
        assert_eq!(make_tables(), TABLES);
    }

    #[test]
    fn mask_unmask_roundtrip() {
        for v in [0u32, 1, 0xffff_ffff, 0xdead_beef] {
            assert_eq!(unmask(mask(v)), v);
            assert_ne!(mask(v), 0);
        }
    }

    #[test]
    fn known_crc32c_vectors() {
        assert_eq!(crc32c(b""), 0);
        assert_eq!(crc32c(b"123456789"), 0xe306_9283);
        assert_eq!(crc32c(&[0u8; 32]), 0x8a91_36aa);
        assert_eq!(crc32c(&[0xffu8; 32]), 0x62a8_ab43);
        let inc: Vec<u8> = (0u8..32).collect();
        assert_eq!(crc32c(&inc), 0x46dd_794e);
    }

    #[test]
    fn slicing_matches_bitwise_reference() {
        let data: Vec<u8> = (0..1000u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
            .collect();
        for len in [0, 1, 7, 8, 9, 15, 16, 17, 255, 1000] {
            assert_eq!(crc32c(&data[..len]), bitwise(&data[..len]), "len {len}");
        }
    }

    /// Every way of computing it is the same function, at every length and
    /// alignment, and from any state.
    #[test]
    fn the_ways_agree() {
        let data: Vec<u8> = (0..300u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 11) as u8)
            .collect();
        for offset in 0..9 {
            for len in (0..40).chain([63, 64, 65, 127, 128, 129, 291]) {
                let part = &data[offset..offset + len];
                for init in [0, 1, 0xdead_beef, u32::MAX] {
                    let want = software(init, part);
                    assert_eq!(crc32c_extend(init, part), want, "{offset} {len} {init}");
                    #[cfg(target_arch = "x86_64")]
                    assert_eq!(hardware(init, part), want, "{offset} {len} {init}");
                }
                assert_eq!(software(0, part), bitwise(part));
            }
        }
    }

    #[test]
    fn extend_matches_single_pass() {
        let data = b"the quick brown fox jumps over the lazy dog";
        for split in 0..data.len() {
            assert_eq!(crc32c(data), crc32c_extend(crc32c(&data[..split]), &data[split..]));
        }
    }

    #[test]
    fn masked_crc_combines() {
        let a = masked_crc(b"ab", b"cd");
        assert_eq!(a, masked_crc(b"a", b"bcd"));
        assert_eq!(a, masked_crc(b"abcd", b""));
        assert_ne!(a, 0);
    }
}
