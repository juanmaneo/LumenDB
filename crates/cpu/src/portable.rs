//! Plain Rust, for any processor: what runs where there is no better
//! instruction, and under kani.

use crate::crc32c::POLY;

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

/// CRC32C of `data`, continuing the finalized CRC `init`, by slicing-by-8
/// over tables computed at compile time: 8 bytes a step, several hundred
/// MB/s to about 1.5 GB/s.
pub fn crc32c(init: u32, data: &[u8]) -> u32 {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables_match_runtime_construction() {
        // `make_tables` is const-evaluated for TABLES; run it once at runtime
        // to check the const path and the runtime path agree.
        assert_eq!(make_tables(), TABLES);
    }
}
