//! Per-table bloom filter (LevelDB `BloomFilterPolicy`): ~1% false positives
//! at 10 bits/key, so point lookups skip almost every table without I/O.
//!
//! Layout: `bitmap | k: u8`. Probes use double hashing `h + i*delta`.

/// 64-bit FNV-1a followed by a murmur3 finalizer for good bit dispersion.
pub fn hash(key: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in key {
        h ^= b as u64;
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h ^= h >> 33;
    h = h.wrapping_mul(0xff51_afd7_ed55_8ccd);
    h ^= h >> 33;
    h
}

/// Build a filter for the given key hashes.
pub fn build(hashes: &[u64], bits_per_key: usize) -> Vec<u8> {
    let k = ((bits_per_key as f64 * 0.69) as u8).clamp(1, 30);
    let bits = (hashes.len() * bits_per_key).max(64);
    let bytes = bits.div_ceil(8);
    let bits = (bytes * 8) as u64;
    let mut out = vec![0u8; bytes + 1];
    for &h in hashes {
        let delta = h.rotate_right(17) | 1;
        let mut x = h;
        for _ in 0..k {
            let bit = x % bits;
            out[(bit / 8) as usize] |= 1 << (bit % 8);
            x = x.wrapping_add(delta);
        }
    }
    out[bytes] = k;
    out
}

/// False means "definitely absent". Malformed filters answer true.
pub fn may_contain(filter: &[u8], h: u64) -> bool {
    let Some((&k, bitmap)) = filter.split_last() else {
        return true;
    };
    if bitmap.is_empty() || k == 0 || k > 30 {
        return true;
    }
    let bits = (bitmap.len() * 8) as u64;
    let delta = h.rotate_right(17) | 1;
    let mut x = h;
    for _ in 0..k {
        let bit = x % bits;
        if bitmap[(bit / 8) as usize] & (1 << (bit % 8)) == 0 {
            return false;
        }
        x = x.wrapping_add(delta);
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_false_negatives_and_few_false_positives() {
        let keys: Vec<Vec<u8>> = (0..10_000u32).map(|i| format!("key{i}").into_bytes()).collect();
        let hashes: Vec<u64> = keys.iter().map(|k| hash(k)).collect();
        let f = build(&hashes, 10);
        assert!(hashes.iter().all(|&h| may_contain(&f, h)));
        let fp = (0..10_000u32)
            .filter(|i| may_contain(&f, hash(format!("other{i}").as_bytes())))
            .count();
        assert!(fp < 300, "false positives: {fp}");
    }

    #[test]
    fn tiny_and_malformed_filters() {
        let f = build(&[], 10);
        assert_eq!(f.len(), 9);
        assert!(!may_contain(&f, hash(b"x")));
        assert!(may_contain(&[], 1));
        assert!(may_contain(&[3], 1));
        assert!(may_contain(&[0xff, 0], 1));
        assert!(may_contain(&[0xff, 31], 1));
        assert_eq!(build(&[1], 1)[8], 1);
        assert_ne!(hash(b"a"), hash(b"b"));
    }
}
