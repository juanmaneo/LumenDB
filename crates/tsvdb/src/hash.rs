//! A fast hash for keys that nobody who writes to the database picks: the
//! numbers of columns, which the database hands out one after the other.
//! (Not for text of the writers: that one gets the hash of std, which holds
//! against keys made to collide.)

use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hasher};

#[derive(Default)]
pub(crate) struct Fast(u64);

impl Hasher for Fast {
    fn write(&mut self, bytes: &[u8]) {
        bytes.iter().for_each(|&b| self.write_u64(u64::from(b)));
    }

    fn write_u64(&mut self, i: u64) {
        self.0 = (self.0.rotate_left(5) ^ i).wrapping_mul(0x517c_c1b7_2722_0a95);
    }

    fn finish(&self) -> u64 {
        // The low bits are the ones a table looks at, and a product leaves
        // them as poor as the keys.
        self.0 ^ (self.0 >> 32)
    }
}

pub(crate) type FastMap<K, V> = HashMap<K, V, BuildHasherDefault<Fast>>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_map_of_numbers_keeps_them_apart() {
        let mut m: FastMap<u64, u64> = FastMap::default();
        for k in 0..10_000 {
            m.insert(k, k * 2);
        }
        assert!((0..10_000).all(|k| m[&k] == k * 2));
        // The low bits of the hashes of consecutive numbers are not all alike.
        let low: std::collections::HashSet<u64> = (0..1000u64)
            .map(|k| {
                let mut h = Fast::default();
                h.write_u64(k);
                h.finish() & 0xff
            })
            .collect();
        let distinct = low.len();
        assert!(distinct > 128, "{distinct}");
        // Bytes hash too, for whatever else is a key.
        let mut bytes: FastMap<&[u8], u8> = FastMap::default();
        bytes.insert(b"ab", 1);
        bytes.insert(b"ba", 2);
        assert_eq!((bytes[&b"ab"[..]], bytes[&b"ba"[..]]), (1, 2));
    }
}
