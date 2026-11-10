//! CRC32C (Castagnoli) with LevelDB-style masking.
//!
//! The checksum itself is the `cpu` crate's: the fastest implementation the
//! processor has (SSE4.2 and PCLMULQDQ on x86_64, CRC32 and PMULL on
//! aarch64, tables elsewhere and under kani).

pub fn mask(crc: u32) -> u32 {
    crc.rotate_right(15).wrapping_add(0xa282_e8a8)
}

pub fn unmask(masked: u32) -> u32 {
    masked.wrapping_sub(0xa282_e8a8).rotate_left(15)
}

/// CRC32C of `data`.
pub fn crc32c(data: &[u8]) -> u32 {
    cpu::crc32c::extend(0, data)
}

/// Continue a finalized CRC32C `init` over more `data`
/// (`crc32c_extend(crc32c(a), b) == crc32c(a ++ b)`).
pub fn crc32c_extend(init: u32, data: &[u8]) -> u32 {
    cpu::crc32c::extend(init, data)
}

pub fn masked_crc(header: &[u8], payload: &[u8]) -> u32 {
    mask(crc32c_extend(crc32c(header), payload))
}

#[cfg(test)]
mod tests {
    use super::*;

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
