//! Machine-checked properties of LumenDB's core algorithms.
//!
//! Each property is a plain boolean function, so it is unit-tested on
//! samples in every build and *proved* for all inputs (within the stated
//! bounds) by the [kani](https://github.com/model-checking/kani) harnesses in
//! `harnesses`, run with `cargo xtask kani` (`cargo kani -p proofs`):
//!
//! 1. flashkv varint encoding round-trips every `u64`;
//! 2. flashkv CRC32C matches the published check values, and CRC masking is
//!    a bijection (the check values for the `cpu` crate's portable table
//!    version, which it uses under `cfg(kani)`: kani can model neither the
//!    feature detection nor the CRC and carry-less multiply instructions, and
//!    the `cpu` crate's `every_engine_is_crc32c` test checks that every
//!    implementation is the same function);
//! 3. raft `Log::append` keeps the log invariants (contiguous indices,
//!    non-decreasing terms, sentinel), keeps the matching prefix, contains the
//!    batch afterwards, and is atomic on error;
//! 4. any two majority quorums of the same voters intersect;
//! 5. the Lamport clock never goes backwards and `observe` orders receipt
//!    after send.
//!
//! Property 3 is the exception: it is checked by *exhaustive enumeration* of
//! a finite domain (the `log_append_exhaustive` test), which is a proof for
//! that domain. Kani cannot check it: with a symbolic entry index, the
//! truncate-and-extend of the log's `Vec` makes CBMC exhaust memory (over
//! 35 GB) even for a one-entry prefix and a one-entry batch.

use flashkv::crc::{crc32c, mask, unmask};
use flashkv::varint::{decode_uvarint64, put_uvarint64};
use raft::{is_majority, quorum, Index, LamportClock, Log, LogEntry, Term};

/// Property 1: `decode(encode(v)) == (v, len)` with `len <= 10`.
pub fn varint_roundtrip(v: u64) -> bool {
    let mut buf = Vec::with_capacity(10);
    put_uvarint64(&mut buf, v);
    buf.len() <= 10 && decode_uvarint64(&buf).ok() == Some((v, buf.len()))
}

/// Property 2a: CRC32C check values (RFC 3720 §B.4 and the "123456789" check).
pub fn crc32c_known_vectors() -> bool {
    let ascending: Vec<u8> = (0..32).collect();
    crc32c(b"") == 0
        && crc32c(b"123456789") == 0xe306_9283
        && crc32c(&[0u8; 32]) == 0x8a91_36aa
        && crc32c(&[0xffu8; 32]) == 0x62a8_ab43
        && crc32c(&ascending) == 0x46dd_794e
}

/// Property 2b: masking stored CRCs is invertible and never a fixed point.
pub fn crc_mask_roundtrip(c: u32) -> bool {
    unmask(mask(c)) == c && mask(c) != c
}

fn entry(index: Index, term: Term) -> LogEntry {
    LogEntry::new(index, term, Vec::new())
}

/// The documented `Log` invariants.
pub fn log_invariants(log: &Log) -> bool {
    let e = log.entries();
    e.iter().enumerate().all(|(i, x)| x.index == i as Index + 1)
        && e.windows(2).all(|w| w[0].term <= w[1].term)
        && log.term_at(0) == Some(0)
        && log.term_at(log.last_index() + 1).is_none()
        && log.last_index() == e.len() as Index
}

/// Property 3: starting from the log with terms `prefix` (vacuously true if
/// that is not a valid log), appending `batch` either fails and changes
/// nothing, or succeeds, keeps the invariants and the entries before the
/// batch, and contains every batch entry.
pub fn log_append_is_safe(prefix: &[Term], batch: &[(Index, Term)]) -> bool {
    let mut log = Log::new();
    let initial: Vec<LogEntry> = prefix.iter().zip(1..).map(|(&t, i)| entry(i, t)).collect();
    if log.append(&initial).is_err() {
        return true;
    }
    let before = log.clone();
    let batch: Vec<LogEntry> = batch.iter().map(|&(i, t)| entry(i, t)).collect();
    match log.append(&batch) {
        Err(_) => log == before,
        Ok(()) => {
            let keep = batch.first().map_or(before.len(), |e| e.index as usize - 1);
            log_invariants(&log)
                && log.entries()[..keep] == before.entries()[..keep]
                && batch.iter().all(|e| log.term_at(e.index) == Some(e.term))
        }
    }
}

/// Property 4: two vote sets (bitmasks over `n <= 64` voters), each a
/// majority, share a voter; and `is_majority` agrees with `quorum`.
pub fn quorums_intersect(n: u32, a: u64, b: u64) -> bool {
    let n = n.clamp(1, 64);
    let voters = u64::MAX >> (64 - n);
    let (a, b) = (a & voters, b & voters);
    let q = quorum(n as usize);
    let majority = |s: u64| is_majority(s.count_ones() as usize, n as usize);
    let consistent = majority(a) == (a.count_ones() as usize >= q);
    consistent && (!(majority(a) && majority(b)) || a & b != 0)
}

/// Property 5: from time `start`, `tick` and `observe(m)` never decrease
/// the clock, and below saturation they strictly increase past `m`.
pub fn lamport_monotonic(start: u64, m: u64) -> bool {
    let mut c = LamportClock::with_time(start);
    let t1 = c.tick();
    let ticked = t1 >= start && (start == u64::MAX || t1 == start + 1);
    let t2 = c.observe(m);
    let observed = t2 >= t1 && t2 >= m && (t1.max(m) == u64::MAX || t2 > t1.max(m));
    ticked && observed && c.now() == t2
}

/// Kani proof harnesses (only compiled by `cargo kani`).
#[cfg(kani)]
mod harnesses {
    use super::*;

    #[kani::proof]
    #[kani::unwind(12)]
    fn varint_roundtrips() {
        assert!(varint_roundtrip(kani::any()));
    }

    #[kani::proof]
    #[kani::unwind(40)]
    fn crc32c_matches_check_values() {
        assert!(crc32c_known_vectors());
    }

    #[kani::proof]
    fn crc_masking_is_a_bijection() {
        assert!(crc_mask_roundtrip(kani::any()));
    }

    #[kani::proof]
    fn majority_quorums_intersect() {
        let n: u32 = kani::any();
        kani::assume((1..=64).contains(&n));
        assert!(quorums_intersect(n, kani::any(), kani::any()));
    }

    #[kani::proof]
    fn lamport_clock_is_monotonic() {
        assert!(lamport_monotonic(kani::any(), kani::any()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varints() {
        for v in [0, 1, 127, 128, 300, u32::MAX as u64, u64::MAX - 1, u64::MAX] {
            assert!(varint_roundtrip(v), "{v}");
        }
        for s in 0..64 {
            assert!(varint_roundtrip(1 << s));
        }
    }

    #[test]
    fn crc() {
        assert!(crc32c_known_vectors());
        for c in [0, 1, 0xa282_e8a8, 0xdead_beef, u32::MAX] {
            assert!(crc_mask_roundtrip(c));
        }
    }

    /// Every sequence of at most `max_len` elements of `alphabet`.
    fn sequences<T: Copy>(alphabet: &[T], max_len: usize) -> Vec<Vec<T>> {
        let mut all = vec![Vec::new()];
        let mut last = vec![Vec::new()];
        for _ in 0..max_len {
            last = last
                .iter()
                .flat_map(|s| {
                    alphabet.iter().map(move |&x| {
                        let mut s = s.clone();
                        s.push(x);
                        s
                    })
                })
                .collect();
            all.extend(last.iter().cloned());
        }
        all
    }

    #[test]
    fn sequences_enumerates_everything_once() {
        let s = sequences(&[0u8, 1], 2);
        assert_eq!(
            s,
            [vec![], vec![0], vec![1], vec![0, 0], vec![0, 1], vec![1, 0], vec![1, 1]]
        );
    }

    /// Property 3, proved by exhaustive enumeration: every prefix of up to 2
    /// entries and every batch of up to 3 entries over indices 0..=4 and
    /// terms 0..=3 (21 prefixes x 8421 batches).
    #[test]
    fn log_append_exhaustive() {
        let terms: Vec<Term> = (0..=3).collect();
        let singles: Vec<(Index, Term)> = (0..=4).flat_map(|i| terms.iter().map(move |&t| (i, t))).collect();
        let prefixes = sequences(&terms, 2);
        let batches = sequences(&singles, 3);
        assert_eq!((prefixes.len(), batches.len()), (21, 8421));
        for p in &prefixes {
            for b in &batches {
                assert!(log_append_is_safe(p, b), "{p:?} + {b:?}");
            }
        }
    }

    #[test]
    fn invariants_detect_broken_logs() {
        let mut log = Log::new();
        log.append(&[entry(1, 1), entry(2, 2)]).unwrap();
        assert!(log_invariants(&log));
    }

    #[test]
    fn quorums() {
        for n in 1..=10u32 {
            for a in 0..(1u64 << n) {
                for b in [0, a, !a, a >> 1, a.rotate_left(3), u64::MAX] {
                    assert!(quorums_intersect(n, a, b));
                }
            }
        }
        assert!(quorums_intersect(0, u64::MAX, u64::MAX));
        assert!(quorums_intersect(64, u64::MAX, 1 << 63));
        assert!(quorums_intersect(99, 0, 0));
    }

    #[test]
    fn lamport() {
        for s in [0, 1, 1000, u64::MAX - 1, u64::MAX] {
            for m in [0, 1, s, s.saturating_add(5), u64::MAX - 1, u64::MAX] {
                assert!(lamport_monotonic(s, m), "{s} {m}");
            }
        }
    }
}
