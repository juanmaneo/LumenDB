//! Aggregation of numeric columns, one window at a time, straight from the
//! decoded chunks: no point is made, and no window collects its values in a
//! `Vec` to be reduced afterwards. A run of values in one window is folded
//! into the window's accumulator with a tight loop over a slice.
//!
//! The chunks have to be sorted and disjoint in time (see [`disjoint`]), which
//! is what ordinary ingestion and compaction make. Anything else (a point
//! written again, or out of order across chunks) goes through
//! [`crate::chunk::normalize`] and [`crate::query::evaluate_within`], which
//! this has to agree with.

use crate::chunk::{ChunkStats, Column, Num, Numbers};
use crate::lineproto::FieldValue;
use crate::query::{Agg, Geometry, Query, Window};

/// The values of a numeric column.
#[derive(Clone, Copy)]
pub(crate) enum Slice<'a> {
    Float(&'a [f64]),
    Int(&'a [i64]),
    UInt(&'a [u64]),
}

impl<'a> Slice<'a> {
    /// `None` for a column of booleans or strings.
    pub(crate) fn of(column: &'a Column) -> Option<Slice<'a>> {
        match column {
            Column::Float(v) => Some(Slice::Float(v)),
            Column::Int(v) => Some(Slice::Int(v)),
            Column::UInt(v) => Some(Slice::UInt(v)),
            Column::Bool(_) | Column::Str(_) => None,
        }
    }

    fn len(&self) -> usize {
        match self {
            Slice::Float(v) => v.len(),
            Slice::Int(v) => v.len(),
            Slice::UInt(v) => v.len(),
        }
    }

    fn range(&self, from: usize, to: usize) -> Slice<'a> {
        match *self {
            Slice::Float(v) => Slice::Float(&v[from..to]),
            Slice::Int(v) => Slice::Int(&v[from..to]),
            Slice::UInt(v) => Slice::UInt(&v[from..to]),
        }
    }

    fn num(&self, i: usize) -> Num {
        match self {
            Slice::Float(v) => Num::Float(v[i]),
            Slice::Int(v) => Num::Int(v[i]),
            Slice::UInt(v) => Num::UInt(v[i]),
        }
    }

    fn value(&self, i: usize) -> FieldValue {
        self.num(i).value()
    }

    /// What the whole slice, which is not empty, says about itself.
    pub(crate) fn numbers(&self) -> Numbers {
        let (mut total, mut error) = (0.0, 0.0);
        let mut sum = |x: f64| add(&mut total, &mut error, x);
        match self {
            Slice::Float(v) => v.iter().for_each(|&x| sum(x)),
            Slice::Int(v) => v.iter().for_each(|&x| sum(x as f64)),
            Slice::UInt(v) => v.iter().for_each(|&x| sum(x as f64)),
        }
        Numbers {
            sum: compensated(total, error),
            min: self.fold(f64::INFINITY, f64::min),
            max: self.fold(f64::NEG_INFINITY, f64::max),
            first: self.num(0),
            last: self.num(self.len() - 1),
        }
    }

    fn fold(&self, init: f64, f: impl Fn(f64, f64) -> f64) -> f64 {
        match self {
            Slice::Float(v) => v.iter().fold(init, |a, &x| f(a, x)),
            Slice::Int(v) => v.iter().fold(init, |a, &x| f(a, x as f64)),
            Slice::UInt(v) => v.iter().fold(init, |a, &x| f(a, x as f64)),
        }
    }
}

/// Neumaier's compensated sum, one value at a time: `total` and the rounding
/// errors `error` that are added back at the end ([`compensated`]).
pub(crate) fn add(total: &mut f64, error: &mut f64, x: f64) {
    let t = *total + x;
    *error += if total.abs() >= x.abs() {
        (*total - t) + x
    } else {
        (x - t) + *total
    };
    *total = t;
}

/// The sum that `total` and `error` stand for. A sum that is infinite or NaN
/// is the plain one.
pub(crate) fn compensated(total: f64, error: f64) -> f64 {
    let sum = total + error;
    if sum.is_nan() {
        total
    } else {
        sum
    }
}

#[derive(Clone)]
struct Acc {
    count: u64,
    total: f64,
    error: f64,
    min: f64,
    max: f64,
    first: Option<FieldValue>,
    last: Option<FieldValue>,
}

impl Acc {
    fn new() -> Acc {
        Acc {
            count: 0,
            total: 0.0,
            error: 0.0,
            min: f64::INFINITY,
            max: f64::NEG_INFINITY,
            first: None,
            last: None,
        }
    }

    /// Folds in the values of a run of points, in time order.
    fn add_run(&mut self, agg: Agg, run: Slice) {
        self.count += run.len() as u64;
        match agg {
            Agg::Count => {}
            Agg::Sum | Agg::Mean => {
                let (mut total, mut error) = (self.total, self.error);
                match run {
                    Slice::Float(v) => v.iter().for_each(|&x| add(&mut total, &mut error, x)),
                    Slice::Int(v) => v.iter().for_each(|&x| add(&mut total, &mut error, x as f64)),
                    Slice::UInt(v) => v.iter().for_each(|&x| add(&mut total, &mut error, x as f64)),
                }
                (self.total, self.error) = (total, error);
            }
            Agg::Min => self.min = run.fold(self.min, f64::min),
            Agg::Max => self.max = run.fold(self.max, f64::max),
            Agg::First => {
                self.first.get_or_insert_with(|| run.value(0));
            }
            Agg::Last => self.last = Some(run.value(run.len() - 1)),
        }
    }

    /// Folds in a chunk of `count` points that `n` describes, which is in
    /// the window and after what is in it.
    fn add_stats(&mut self, agg: Agg, count: u64, n: &Numbers) {
        self.count += count;
        match agg {
            Agg::Count => {}
            Agg::Sum | Agg::Mean => add(&mut self.total, &mut self.error, n.sum),
            Agg::Min => self.min = self.min.min(n.min),
            Agg::Max => self.max = self.max.max(n.max),
            Agg::First => {
                self.first.get_or_insert_with(|| n.first.value());
            }
            Agg::Last => self.last = Some(n.last.value()),
        }
    }

    fn result(self, agg: Agg) -> FieldValue {
        match agg {
            Agg::Count => FieldValue::UInt(self.count),
            Agg::Sum => FieldValue::Float(compensated(self.total, self.error)),
            Agg::Mean => FieldValue::Float(compensated(self.total, self.error) / self.count as f64),
            Agg::Min => FieldValue::Float(self.min),
            Agg::Max => FieldValue::Float(self.max),
            Agg::First => self.first.expect("a window has a point"),
            Agg::Last => self.last.expect("a window has a point"),
        }
    }
}

/// Collects the windows of one series from its points, which arrive in time
/// order, a run at a time, or from the statistics of a chunk, which arrive
/// in the same order.
pub(crate) struct Aggregator {
    agg: Agg,
    geometry: Geometry,
    start: i64,
    end: i64,
    windows: Vec<(i128, Acc)>,
}

impl Aggregator {
    pub(crate) fn new(q: &Query, agg: Agg) -> Aggregator {
        Aggregator {
            agg,
            geometry: Geometry::of(q),
            start: q.start,
            end: q.end,
            windows: Vec::new(),
        }
    }

    /// The accumulator of window `w`, which is the last one or a new one.
    fn window(&mut self, w: i128) -> &mut Acc {
        if self.windows.last().map(|l| l.0) != Some(w) {
            self.windows.push((w, Acc::new()));
        }
        &mut self.windows.last_mut().expect("a window was just added").1
    }

    /// Adds the points `(ts[i], values[i])`. Those outside the range of the
    /// query are skipped; all of them are after the ones added before.
    pub(crate) fn push(&mut self, ts: &[i64], values: Slice) {
        let lo = ts.partition_point(|&t| t < self.start);
        let hi = ts.partition_point(|&t| t < self.end);
        let mut i = lo;
        while i < hi {
            let w = self.geometry.window(ts[i]);
            let next = self.geometry.start(w + 1);
            let j = i + ts[i..hi].partition_point(|&t| i128::from(t) < next);
            let agg = self.agg;
            self.window(w).add_run(agg, values.range(i, j));
            i = j;
        }
    }

    /// Whether the chunk that these statistics are of can be added as a
    /// whole: it is a chunk of numbers, in the range, and in one window.
    pub(crate) fn covers(&self, s: &ChunkStats) -> bool {
        s.numbers.is_some()
            & (s.min_ts >= self.start)
            & (s.max_ts < self.end)
            & (self.geometry.window(s.min_ts) == self.geometry.window(s.max_ts))
    }

    /// Adds the chunk that these statistics are of, which [`covers`] says
    /// they can stand for.
    ///
    /// [`covers`]: Aggregator::covers
    pub(crate) fn push_stats(&mut self, s: &ChunkStats) {
        let numbers = s.numbers.expect("covers checked that there are numbers");
        let agg = self.agg;
        let w = self.geometry.window(s.min_ts);
        self.window(w).add_stats(agg, s.count, &numbers);
    }

    /// The windows with points, in order, with their values.
    pub(crate) fn finish(self) -> Vec<Window> {
        let agg = self.agg;
        self.windows.into_iter().map(|(w, acc)| (w, acc.result(agg))).collect()
    }
}

/// Whether no two of the ranges (earliest and latest timestamp) have a
/// timestamp in common, so that no point is overwritten by another.
pub(crate) fn disjoint(ranges: impl Iterator<Item = (i64, i64)>) -> bool {
    let mut ranges: Vec<(i64, i64)> = ranges.collect();
    ranges.sort_unstable();
    ranges.windows(2).all(|w| w[0].1 < w[1].0)
}
