//! Majority quorum arithmetic: quorum(n) = n/2 + 1 (Raft / CockroachDB).
//! Any two quorums intersect, which is what makes the committed prefix safe.
//!
//! Invariants (pure, total, no overflow for any `n < usize::MAX`):
//! - `quorum(n) == n / 2 + 1`;
//! - `2 * quorum(n) > n`: any two majorities of the same `n` voters share at
//!   least one voter (`quorum(n) + quorum(n) - n >= 1`);
//! - `quorum(n) <= n` for every `n >= 1`, so a full cluster can always commit;
//! - `is_majority(v, n) <=> v >= quorum(n)`, monotone in `v`.

/// Size of the smallest majority of `n` voters: `n / 2 + 1`.
pub const fn quorum(n: usize) -> usize {
    n / 2 + 1
}

/// Whether `votes` out of `n` voters form a majority (`votes >= quorum(n)`).
pub const fn is_majority(votes: usize, n: usize) -> bool {
    votes >= quorum(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quorum_sizes() {
        assert_eq!(quorum(0), 1);
        assert_eq!(quorum(1), 1);
        assert_eq!(quorum(2), 2);
        assert_eq!(quorum(3), 2);
        assert_eq!(quorum(5), 3);
        assert_eq!(quorum(7), 4);
    }

    #[test]
    fn majority_check() {
        assert!(is_majority(1, 1));
        assert!(!is_majority(1, 2));
        assert!(is_majority(2, 3));
        assert!(!is_majority(2, 5));
    }

    #[test]
    fn quorums_intersect() {
        for n in 1..=15usize {
            assert!(2 * quorum(n) > n);
            assert!(quorum(n) <= n);
            for v in 0..=n {
                assert_eq!(is_majority(v, n), v >= quorum(n));
            }
        }
    }
}
