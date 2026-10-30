//! CRC32C (Castagnoli) with LevelDB-style masking.
//!
//! Pure Rust, no external crate: slicing-by-8 over tables computed at compile
//! time (`const fn`), which processes 8 bytes per step (~several GB/s).

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
