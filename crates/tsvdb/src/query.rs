//! Queries: a time range over one field of a measurement, filtered by tag
//! equality, optionally aggregated (sum/count/min/max/mean/first/last) per
//! series and per time window (`GROUP BY time(every)`), plus top-N ranking — e.g. the
//! heaviest flows of an ingested capture ([`top_flows`]).

use crate::db::Db;
use crate::error::{Error, Result};
use crate::lineproto::FieldValue;
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Agg {
    Sum,
    Count,
    Min,
    Max,
    Mean,
    /// The value of the earliest point of the window, of any field type.
    First,
    /// The value of the latest point of the window, of any field type.
    Last,
}

impl Agg {
    pub fn parse(s: &str) -> Option<Agg> {
        match s {
            "sum" => Some(Agg::Sum),
            "count" => Some(Agg::Count),
            "min" => Some(Agg::Min),
            "max" => Some(Agg::Max),
            "mean" => Some(Agg::Mean),
            "first" => Some(Agg::First),
            "last" => Some(Agg::Last),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Agg::Sum => "sum",
            Agg::Count => "count",
            Agg::Min => "min",
            Agg::Max => "max",
            Agg::Mean => "mean",
            Agg::First => "first",
            Agg::Last => "last",
        }
    }
}

/// Where the windows of an aggregation (`every`) start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Align {
    /// At multiples of the window, counted from 1970-01-01 UTC: a one-hour
    /// window starts on the hour and a one-day window at midnight, whatever
    /// the range asked for, and two queries (or two rollups) over different
    /// ranges cut time the same way. This is the default.
    Calendar,
    /// At the start of the range (`start`), like InfluxDB's `GROUP BY time()`
    /// with an offset. Without a start, the first window starts at `i64::MIN`.
    Start,
}

impl Align {
    pub fn parse(s: &str) -> Option<Align> {
        match s {
            "calendar" => Some(Align::Calendar),
            "start" => Some(Align::Start),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Align::Calendar => "calendar",
            Align::Start => "start",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Query {
    pub measurement: String,
    pub field: String,
    /// `tag = value` predicates, all of which must hold.
    pub filters: Vec<(String, String)>,
    /// Inclusive start, exclusive end (ns).
    pub start: i64,
    pub end: i64,
    pub agg: Option<Agg>,
    /// Aggregation window (ns); `None` aggregates the whole range.
    pub every: Option<i64>,
    /// Where the windows start.
    pub align: Align,
}

impl Query {
    /// All of time, raw values.
    pub fn new(measurement: impl Into<String>, field: impl Into<String>) -> Self {
        Query {
            measurement: measurement.into(),
            field: field.into(),
            filters: Vec::new(),
            start: i64::MIN,
            end: i64::MAX,
            agg: None,
            every: None,
            align: Align::Calendar,
        }
    }

    pub fn filter(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.filters.push((k.into(), v.into()));
        self
    }

    pub fn range(mut self, start: i64, end: i64) -> Self {
        (self.start, self.end) = (start, end);
        self
    }

    pub fn agg(mut self, agg: Agg) -> Self {
        self.agg = Some(agg);
        self
    }

    pub fn every(mut self, every: i64) -> Self {
        self.every = Some(every);
        self
    }

    pub fn align(mut self, align: Align) -> Self {
        self.align = align;
        self
    }

    pub fn validate(&self) -> Result<()> {
        if (self.start >= self.end) | (self.every.unwrap_or(1) <= 0) {
            return Err(Error::Query(format!(
                "need start < end and a positive window: {self:?}"
            )));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Row {
    /// Canonical series key, e.g. `flows,proto=tcp,...`.
    pub series: String,
    pub tags: BTreeMap<String, String>,
    pub ts: i64,
    pub value: FieldValue,
}

/// Neumaier's compensated sum: the rounding error of each addition is
/// accumulated on the side and added back, so a long series of floats of
/// very different sizes does not lose the small ones (`1e100 + 1 - 1e100` is
/// 1, not 0). A sum that is infinite or NaN is the plain one.
fn sum(values: &[f64]) -> f64 {
    let (mut total, mut error) = (0.0, 0.0);
    for &x in values {
        let t = total + x;
        error += if total.abs() >= x.abs() {
            (total - t) + x
        } else {
            (x - t) + total
        };
        total = t;
    }
    let compensated = total + error;
    if compensated.is_nan() {
        total
    } else {
        compensated
    }
}

fn reduce(agg: Agg, window: &[(i64, FieldValue)]) -> Result<FieldValue> {
    let numeric = || -> Result<Vec<f64>> {
        window
            .iter()
            .map(|(_, v)| {
                v.as_f64()
                    .ok_or_else(|| Error::Query(format!("{} of a non-numeric field", agg.name())))
            })
            .collect()
    };
    Ok(match agg {
        Agg::Count => FieldValue::UInt(window.len() as u64),
        Agg::First => window[0].1.clone(),
        Agg::Last => window[window.len() - 1].1.clone(),
        Agg::Sum => FieldValue::Float(sum(&numeric()?)),
        Agg::Min => FieldValue::Float(numeric()?.into_iter().fold(f64::INFINITY, f64::min)),
        Agg::Max => FieldValue::Float(numeric()?.into_iter().fold(f64::NEG_INFINITY, f64::max)),
        Agg::Mean => {
            let v = numeric()?;
            FieldValue::Float(sum(&v) / v.len() as f64)
        }
    })
}

/// Applies `q`'s aggregation to the sorted points of one series. Raw points
/// are returned as-is; aggregated rows are stamped with their window start.
pub fn evaluate(points: &[(i64, FieldValue)], q: &Query) -> Result<Vec<(i64, FieldValue)>> {
    let Some(agg) = q.agg else {
        return Ok(points.to_vec());
    };
    // Without a window, one window that starts at the start of the range.
    let (origin, width) = match q.every {
        None => (i128::from(q.start), i128::MAX),
        Some(every) if q.align == Align::Start => (i128::from(q.start), i128::from(every)),
        Some(every) => (0, i128::from(every)),
    };
    let window = |ts: i64| (i128::from(ts) - origin).div_euclid(width);
    let stamp = |w: i128| (origin + w * width).clamp(i64::MIN.into(), i64::MAX.into()) as i64;
    points
        .chunk_by(|a, b| window(a.0) == window(b.0))
        .map(|w| Ok((stamp(window(w[0].0)), reduce(agg, w)?)))
        .collect()
}

/// The `n` rows with the largest numeric values, largest first.
pub fn top_n(mut rows: Vec<Row>, n: usize) -> Vec<Row> {
    let key = |r: &Row| r.value.as_f64().unwrap_or(f64::NEG_INFINITY);
    rows.sort_by(|a, b| key(b).total_cmp(&key(a)));
    rows.truncate(n);
    rows
}

/// Heaviest flows by bytes in `[start, end)` of a capture ingested with
/// [`Db::ingest_capture`].
pub fn top_flows(db: &Db, start: i64, end: i64, n: usize) -> Result<Vec<Row>> {
    let q = Query::new("flows", "bytes").range(start, end).agg(Agg::Sum);
    Ok(top_n(db.query(&q)?, n))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pts(v: &[(i64, f64)]) -> Vec<(i64, FieldValue)> {
        v.iter().map(|&(t, x)| (t, FieldValue::Float(x))).collect()
    }

    #[test]
    fn agg_names_roundtrip() {
        for a in [
            Agg::Sum,
            Agg::Count,
            Agg::Min,
            Agg::Max,
            Agg::Mean,
            Agg::First,
            Agg::Last,
        ] {
            assert_eq!(Agg::parse(a.name()), Some(a));
        }
        assert_eq!(Agg::parse("median"), None);
    }

    #[test]
    fn validation() {
        let q = Query::new("m", "f");
        assert!(q.validate().is_ok());
        assert!(q.clone().range(5, 5).validate().is_err());
        assert!(q.clone().every(0).validate().is_err());
        assert!(q.filter("k", "v").every(1).validate().is_ok());
    }

    #[test]
    fn raw_and_whole_range_aggregates() {
        let p = pts(&[(1, 2.0), (2, 4.0), (3, 9.0)]);
        let q = Query::new("m", "f").range(0, 10);
        assert_eq!(evaluate(&p, &q).unwrap(), p);
        let expect = [
            (Agg::Sum, FieldValue::Float(15.0)),
            (Agg::Count, FieldValue::UInt(3)),
            (Agg::Min, FieldValue::Float(2.0)),
            (Agg::Max, FieldValue::Float(9.0)),
            (Agg::Mean, FieldValue::Float(5.0)),
            (Agg::First, FieldValue::Float(2.0)),
            (Agg::Last, FieldValue::Float(9.0)),
        ];
        for (agg, want) in expect {
            assert_eq!(evaluate(&p, &q.clone().agg(agg)).unwrap(), vec![(0, want)]);
        }
        // Whole time range: one window starting at i64::MIN.
        let all = Query::new("m", "f").agg(Agg::Count);
        assert_eq!(evaluate(&p, &all).unwrap(), vec![(i64::MIN, FieldValue::UInt(3))]);
        assert!(evaluate(&[], &all).unwrap().is_empty());
    }

    #[test]
    fn align_names_roundtrip() {
        for a in [Align::Calendar, Align::Start] {
            assert_eq!(Align::parse(a.name()), Some(a));
        }
        assert_eq!(Align::parse("first"), None);
        assert_eq!(Query::new("m", "f").align, Align::Calendar);
        assert_eq!(Query::new("m", "f").align(Align::Start).align, Align::Start);
    }

    #[test]
    fn calendar_windows_ignore_where_the_range_starts() {
        let p = pts(&[(-1, 32.0), (3, 1.0), (4, 2.0), (5, 4.0), (9, 8.0), (10, 16.0)]);
        let q = Query::new("m", "f").range(-3, 20).agg(Agg::Sum).every(5);
        let sums = |q: &Query| -> Vec<(i64, f64)> {
            let in_range: Vec<_> = p
                .iter()
                .filter(|(t, _)| (q.start..q.end).contains(t))
                .cloned()
                .collect();
            let rows = evaluate(&in_range, q).unwrap();
            rows.into_iter().map(|(t, v)| (t, v.as_f64().unwrap())).collect()
        };
        // Windows are [-5, 0), [0, 5), [5, 10), [10, 15) wherever the range starts.
        let calendar = [(-5, 32.0), (0, 3.0), (5, 12.0), (10, 16.0)];
        assert_eq!(sums(&q), calendar);
        assert_eq!(sums(&q.clone().range(3, 20))[..], calendar[1..]);
        assert_eq!(sums(&q.clone().range(i64::MIN, i64::MAX))[..], calendar);
        // Anchored at the start instead: [-3, 2), [2, 7), [7, 12).
        let anchored = [(-3, 32.0), (2, 7.0), (7, 24.0)];
        assert_eq!(sums(&q.clone().align(Align::Start)), anchored);
    }

    #[test]
    fn windows_at_the_ends_of_time() {
        let p = pts(&[(i64::MIN, 1.0), (i64::MAX, 2.0)]);
        let q = Query::new("m", "f").agg(Agg::Count).every(i64::MAX);
        // The first window would start below i64::MIN: its stamp saturates.
        let stamps: Vec<i64> = evaluate(&p, &q).unwrap().into_iter().map(|r| r.0).collect();
        assert_eq!(stamps, vec![i64::MIN, i64::MAX]);
        let stamps: Vec<i64> = evaluate(&p, &q.align(Align::Start))
            .unwrap()
            .into_iter()
            .map(|r| r.0)
            .collect();
        assert_eq!(stamps, vec![i64::MIN, i64::MAX - 1]);
    }

    #[test]
    fn windows() {
        let p = pts(&[(-3, 1.0), (0, 1.0), (4, 2.0), (5, 3.0), (12, 4.0)]);
        let q = Query::new("m", "f").range(-5, 20).agg(Agg::Sum).every(5);
        assert_eq!(
            evaluate(&p, &q).unwrap(),
            vec![
                (-5, FieldValue::Float(1.0)),
                (0, FieldValue::Float(3.0)),
                (5, FieldValue::Float(3.0)),
                (10, FieldValue::Float(4.0)),
            ]
        );
    }

    #[test]
    fn non_numeric_aggregates_fail_except_count_first_and_last() {
        let p = vec![(1, FieldValue::Str("x".into())), (2, FieldValue::Bool(true))];
        let q = Query::new("m", "f");
        for agg in [Agg::Sum, Agg::Min, Agg::Max, Agg::Mean] {
            assert!(evaluate(&p, &q.clone().agg(agg)).is_err());
        }
        assert_eq!(
            evaluate(&p, &q.clone().agg(Agg::Count)).unwrap()[0].1,
            FieldValue::UInt(2)
        );
        assert_eq!(
            evaluate(&p, &q.clone().agg(Agg::First)).unwrap()[0].1,
            FieldValue::Str("x".into())
        );
        assert_eq!(evaluate(&p, &q.agg(Agg::Last)).unwrap()[0].1, FieldValue::Bool(true));
    }

    #[test]
    fn open_high_low_close_per_window() {
        let p = pts(&[(0, 5.0), (1, 9.0), (2, 1.0), (3, 6.0), (10, 7.0), (11, 7.5)]);
        let bars = |agg| -> Vec<f64> {
            let q = Query::new("m", "f").agg(agg).every(10);
            evaluate(&p, &q)
                .unwrap()
                .iter()
                .map(|r| r.1.as_f64().unwrap())
                .collect()
        };
        assert_eq!(bars(Agg::First), [5.0, 7.0]);
        assert_eq!(bars(Agg::Max), [9.0, 7.5]);
        assert_eq!(bars(Agg::Min), [1.0, 7.0]);
        assert_eq!(bars(Agg::Last), [6.0, 7.5]);
    }

    #[test]
    fn sums_are_compensated() {
        // The naive sum of these is 0 (or 1, by order); the exact one is 2.
        let hard = [1e100, 1.0, -1e100, 1.0];
        assert_eq!(hard.iter().sum::<f64>(), 1.0);
        assert_eq!(sum(&hard), 2.0);
        assert_eq!(sum(&[1.0, 1e100, 1.0, -1e100]), 2.0);
        assert_eq!(sum(&[]), 0.0);
        assert_eq!(sum(&[0.1; 10]), 1.0);
        assert_eq!([0.1; 10].iter().sum::<f64>(), 0.9999999999999999);
        // Infinities and NaN are not turned into something else.
        assert_eq!(sum(&[1.0, f64::INFINITY]), f64::INFINITY);
        assert_eq!(sum(&[f64::INFINITY, 1.0]), f64::INFINITY);
        assert_eq!(sum(&[f64::NEG_INFINITY, 1.0]), f64::NEG_INFINITY);
        assert_eq!(sum(&[f64::MAX, f64::MAX]), f64::INFINITY);
        assert!(sum(&[f64::INFINITY, f64::NEG_INFINITY]).is_nan());
        assert!(sum(&[1.0, f64::NAN]).is_nan());
        let mean = pts(&[(1, 1e100), (2, 1.0), (3, -1e100), (4, 1.0)]);
        let q = Query::new("m", "f").agg(Agg::Mean);
        assert_eq!(evaluate(&mean, &q).unwrap()[0].1, FieldValue::Float(0.5));
    }

    #[test]
    fn top_n_orders_by_value() {
        let row = |s: &str, v: FieldValue| Row {
            series: s.into(),
            tags: BTreeMap::new(),
            ts: 0,
            value: v,
        };
        let rows = vec![
            row("a", FieldValue::Float(1.0)),
            row("b", FieldValue::UInt(10)),
            row("c", FieldValue::Str("x".into())),
            row("d", FieldValue::Int(5)),
        ];
        let top: Vec<String> = top_n(rows, 3).into_iter().map(|r| r.series).collect();
        assert_eq!(top, vec!["b", "d", "a"]);
    }
}
