//! Time partitioning (InfluxDB v3 partitions data by time, one hour by
//! default). Bucket `b` covers `[b * duration, (b + 1) * duration)`, also for
//! negative timestamps (Euclidean division). Buckets are encoded big-endian
//! with the sign bit flipped so that byte order equals time order in flashkv.

use std::ops::{Range, RangeInclusive};

pub const HOUR_NS: i64 = 3_600 * 1_000_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Partitioner {
    duration: i64,
}

impl Default for Partitioner {
    fn default() -> Self {
        Partitioner::hourly()
    }
}

impl Partitioner {
    pub fn hourly() -> Self {
        Partitioner { duration: HOUR_NS }
    }

    /// Partitions of `duration` ns (at least 1).
    pub fn new(duration: i64) -> Self {
        Partitioner {
            duration: duration.max(1),
        }
    }

    pub fn duration(&self) -> i64 {
        self.duration
    }

    pub fn bucket(&self, ts: i64) -> i64 {
        ts.div_euclid(self.duration)
    }

    /// First timestamp of `bucket` (saturating).
    pub fn start(&self, bucket: i64) -> i64 {
        bucket.saturating_mul(self.duration)
    }

    /// Buckets overlapping the non-empty range `[start, end)`.
    pub fn buckets(&self, start: i64, end: i64) -> RangeInclusive<i64> {
        self.bucket(start)..=self.bucket(end.saturating_sub(1).max(start))
    }

    /// The runs of `ts`, which is sorted, that are in one bucket each: the
    /// bucket and the indexes of its points.
    pub fn runs(&self, ts: &[i64]) -> Vec<(i64, Range<usize>)> {
        let mut runs: Vec<(i64, Range<usize>)> = Vec::new();
        for (i, &t) in ts.iter().enumerate() {
            let bucket = self.bucket(t);
            match runs.last_mut() {
                Some((b, run)) if *b == bucket => run.end = i + 1,
                _ => runs.push((bucket, i..i + 1)),
            }
        }
        runs
    }
}

/// Order-preserving encoding of a bucket number.
pub fn encode_bucket(b: i64) -> [u8; 8] {
    ((b as u64) ^ (1 << 63)).to_be_bytes()
}

pub fn decode_bucket(bytes: [u8; 8]) -> i64 {
    (u64::from_be_bytes(bytes) ^ (1 << 63)) as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buckets_and_bounds() {
        let p = Partitioner::default();
        assert_eq!(p.duration(), HOUR_NS);
        assert_eq!(p.bucket(0), 0);
        assert_eq!(p.bucket(HOUR_NS - 1), 0);
        assert_eq!(p.bucket(HOUR_NS), 1);
        assert_eq!(p.bucket(-1), -1);
        assert_eq!(p.start(2), 2 * HOUR_NS);
        assert_eq!(p.start(i64::MAX), i64::MAX);
        assert_eq!(p.buckets(0, HOUR_NS), 0..=0);
        assert_eq!(p.buckets(-1, HOUR_NS + 1), -1..=1);
        assert_eq!(
            p.buckets(i64::MIN, i64::MAX),
            p.bucket(i64::MIN)..=p.bucket(i64::MAX - 1)
        );
        assert_eq!(Partitioner::new(0).duration(), 1);
    }

    #[test]
    fn runs_group_sorted_timestamps_by_bucket() {
        let p = Partitioner::new(10);
        assert_eq!(p.runs(&[]), vec![]);
        assert_eq!(p.runs(&[3]), vec![(0, 0..1)]);
        assert_eq!(
            p.runs(&[-7, -1, 3, 9, 11, 12, 35]),
            vec![(-1, 0..2), (0, 2..4), (1, 4..6), (3, 6..7)]
        );
    }

    #[test]
    fn encoding_preserves_order() {
        let values = [i64::MIN, -5, -1, 0, 1, 7, i64::MAX];
        for w in values.windows(2) {
            assert!(encode_bucket(w[0]) < encode_bucket(w[1]));
        }
        for v in values {
            assert_eq!(decode_bucket(encode_bucket(v)), v);
        }
    }
}
