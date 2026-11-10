//! Queries: a time range over one field of a measurement, filtered by tag
//! equality, optionally aggregated (sum/count/min/max/mean/first/last) per
//! series and per time window (`GROUP BY time(every)`), plus top-N ranking — e.g. the
//! heaviest flows of an ingested capture ([`top_flows`]).

use crate::db::Db;
use crate::error::{Error, Result};
use crate::lineproto::FieldValue;
use std::collections::BTreeMap;
use std::ops::Range;

/// The most rows that filling the empty windows of a query may make, unless
/// [`crate::DbOptions::max_fill_rows`] says otherwise: a tiny window over a
/// long range must be an error, not an out-of-memory kill.
pub const MAX_FILL_ROWS: usize = 1 << 20;

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

/// What to put in the windows of a series that have no points (QuestDB's
/// `FILL`). Without a fill, such windows are left out. There is no null in
/// tsvdb: a window that a fill has nothing for is left out too, and a series
/// with no point in the range has no rows.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Fill {
    /// The value of the closest window before. Nothing before the first one.
    Prev,
    /// A straight line, by window start, from the closest window before to
    /// the closest one after. Nothing before the first or after the last.
    Linear,
    /// A constant, of the type of the aggregate's result (rounded for an
    /// integer one). The range of the windows is the range of the query when
    /// it has a start and an end, and the data's otherwise.
    Value(f64),
}

impl Fill {
    /// `prev`, `linear`, or a finite number.
    pub fn parse(s: &str) -> Option<Fill> {
        match s {
            "prev" => Some(Fill::Prev),
            "linear" => Some(Fill::Linear),
            _ => s.parse().ok().filter(|v: &f64| v.is_finite()).map(Fill::Value),
        }
    }

    /// What [`Fill::parse`] reads back.
    pub fn name(self) -> String {
        match self {
            Fill::Prev => "prev".to_string(),
            Fill::Linear => "linear".to_string(),
            Fill::Value(v) => v.to_string(),
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
    /// What to do with windows without points; needs `agg` and `every`.
    pub fill: Option<Fill>,
    /// Only the newest point of each series in the range, with its own
    /// timestamp (QuestDB's `LATEST ON`). No aggregate, no window.
    pub latest: bool,
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
            fill: None,
            latest: false,
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

    pub fn latest(mut self) -> Self {
        self.latest = true;
        self
    }

    pub fn fill(mut self, fill: Fill) -> Self {
        self.fill = Some(fill);
        self
    }

    pub fn validate(&self) -> Result<()> {
        if (self.start >= self.end) | (self.every.unwrap_or(1) <= 0) {
            return Err(Error::Query(format!(
                "need start < end and a positive window: {self:?}"
            )));
        }
        if self.latest & (self.agg.is_some() | self.every.is_some()) {
            return Err(Error::Query("the latest point takes no aggregate and no window".into()));
        }
        if self.fill.is_some() & (self.agg.is_none() | self.every.is_none()) {
            return Err(Error::Query("a fill needs an aggregate and a window".into()));
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

/// A window's number (counted from the origin of the windows) and its value.
type Window = (i128, FieldValue);

fn not_numeric() -> Error {
    Error::Query("a fill with a number or a line needs a numeric result".into())
}

/// A value of the type of `reference` (what an aggregate returned), made
/// from `x`.
fn like(reference: &FieldValue, x: f64) -> Result<FieldValue> {
    match reference {
        FieldValue::Float(_) => Ok(FieldValue::Float(x)),
        FieldValue::Int(_) => Ok(FieldValue::Int(x.round() as i64)),
        FieldValue::UInt(_) => Ok(FieldValue::UInt(x.round() as u64)),
        FieldValue::Bool(_) | FieldValue::Str(_) => Err(not_numeric()),
    }
}

/// The value at window `at`, on the line between two windows.
fn line(before: &Window, after: &Window, at: i128) -> Result<FieldValue> {
    let (x, y) = before.1.as_f64().zip(after.1.as_f64()).ok_or_else(not_numeric)?;
    let t = (at - before.0) as f64 / (after.0 - before.0) as f64;
    like(&before.1, x + (y - x) * t)
}

/// Appends the rows of the empty windows `gap`, which lie between `before`
/// and `after` (either may be missing at an end of the range).
fn fill_gap(
    out: &mut Vec<(i64, FieldValue)>,
    gap: Range<i128>,
    fill: Fill,
    (before, after): (Option<&Window>, Option<&Window>),
    stamp: &dyn Fn(i128) -> i64,
) -> Result<()> {
    for at in gap {
        let value = match (fill, before, after) {
            (Fill::Prev, Some(b), _) => Some(b.1.clone()),
            (Fill::Linear, Some(b), Some(a)) => Some(line(b, a, at)?),
            (Fill::Value(c), ..) => {
                let beside = before.or(after).expect("a gap has a window beside it");
                Some(like(&beside.1, c)?)
            }
            _ => None,
        };
        out.extend(value.map(|v| (stamp(at), v)));
    }
    Ok(())
}

/// Applies `q`'s aggregation to the sorted points of one series. Raw points
/// are returned as-is; aggregated rows are stamped with their window start.
/// A fill makes at most [`MAX_FILL_ROWS`] rows.
pub fn evaluate(points: &[(i64, FieldValue)], q: &Query) -> Result<Vec<(i64, FieldValue)>> {
    evaluate_within(points, q, MAX_FILL_ROWS)
}

/// [`evaluate`], where a fill may make `budget` rows.
pub(crate) fn evaluate_within(
    points: &[(i64, FieldValue)],
    q: &Query,
    budget: usize,
) -> Result<Vec<(i64, FieldValue)>> {
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
    let windows = points
        .chunk_by(|a, b| window(a.0) == window(b.0))
        .map(|w| Ok((window(w[0].0), reduce(agg, w)?)))
        .collect::<Result<Vec<Window>>>()?;
    let Some(fill) = q.fill else {
        return Ok(windows.into_iter().map(|(w, v)| (stamp(w), v)).collect());
    };
    if windows.is_empty() {
        return Ok(Vec::new());
    }
    // Fill from the window of the start of the range to that of its end, or
    // where the data begins and ends if the range is open on that side.
    let first = if q.start == i64::MIN {
        windows[0].0
    } else {
        window(q.start)
    };
    let last = if q.end == i64::MAX {
        windows[windows.len() - 1].0
    } else {
        window(q.end.saturating_sub(1))
    };
    let count = last - first + 1;
    if count > budget as i128 {
        return Err(Error::Query(format!(
            "filling would make {count} rows, more than the {budget} allowed: use a larger window or a narrower range"
        )));
    }
    let mut out = Vec::new();
    let (mut before, mut next) = (None, first);
    for w in &windows {
        fill_gap(&mut out, next..w.0, fill, (before, Some(w)), &stamp)?;
        out.push((stamp(w.0), w.1.clone()));
        (before, next) = (Some(w), w.0 + 1);
    }
    fill_gap(&mut out, next..last + 1, fill, (before, None), &stamp)?;
    Ok(out)
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
    fn fill_names_roundtrip() {
        for f in [
            Fill::Prev,
            Fill::Linear,
            Fill::Value(0.0),
            Fill::Value(-3.5),
            Fill::Value(0.1 + 0.2),
            Fill::Value(1e300),
        ] {
            assert_eq!(Fill::parse(&f.name()), Some(f));
        }
        assert_eq!(Fill::parse("1e3"), Some(Fill::Value(1000.0)));
        assert_eq!(Fill::name(Fill::Value(2.0)), "2");
        for bad in ["", "none", "next", "nan", "inf", "-inf", "1x"] {
            assert_eq!(Fill::parse(bad), None, "{bad}");
        }
        assert_eq!(Query::new("m", "f").fill, None);
        assert_eq!(Query::new("m", "f").fill(Fill::Prev).fill, Some(Fill::Prev));
    }

    #[test]
    fn validation() {
        let q = Query::new("m", "f");
        assert!(q.validate().is_ok());
        assert!(q.clone().range(5, 5).validate().is_err());
        assert!(q.clone().every(0).validate().is_err());
        assert!(q.clone().filter("k", "v").every(1).validate().is_ok());
        // A fill needs an aggregate and a window.
        let filled = q.fill(Fill::Prev);
        assert!(filled.validate().is_err());
        assert!(filled.clone().agg(Agg::Sum).validate().is_err());
        assert!(filled.clone().every(5).validate().is_err());
        assert!(filled.agg(Agg::Sum).every(5).validate().is_ok());
        // The latest point is a point, not an aggregate.
        let latest = Query::new("m", "f").latest();
        assert!(latest.validate().is_ok());
        assert!(latest.clone().agg(Agg::Sum).validate().is_err());
        assert!(latest.every(5).validate().is_err());
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

    /// Rows of `evaluate`, with the values as numbers.
    fn filled(points: &[(i64, f64)], q: &Query) -> Vec<(i64, f64)> {
        let rows = evaluate(&pts(points), q).unwrap();
        rows.into_iter().map(|(t, v)| (t, v.as_f64().unwrap())).collect()
    }

    fn close(got: Vec<(i64, f64)>, want: &[(i64, f64)]) {
        assert_eq!(got.len(), want.len(), "{got:?}");
        for (g, w) in got.iter().zip(want) {
            assert!(g.0 == w.0 && (g.1 - w.1).abs() < 1e-9, "{got:?} != {want:?}");
        }
    }

    #[test]
    fn fill_makes_a_row_for_every_window_that_has_something() {
        // Windows 0, 3, 4 and 7 of ten have points, with sums 1, 4, 6 and 10.
        let p = [(5, 1.0), (35, 4.0), (45, 6.0), (70, 10.0)];
        let q = Query::new("m", "f").range(0, 100).agg(Agg::Sum).every(10);
        close(filled(&p, &q), &[(0, 1.0), (30, 4.0), (40, 6.0), (70, 10.0)]);
        let prev = [
            (0, 1.0),
            (10, 1.0),
            (20, 1.0),
            (30, 4.0),
            (40, 6.0),
            (50, 6.0),
            (60, 6.0),
            (70, 10.0),
        ];
        let prev_to_the_end = [prev.as_slice(), &[(80, 10.0), (90, 10.0)]].concat();
        close(filled(&p, &q.clone().fill(Fill::Prev)), &prev_to_the_end);
        // A line between windows 0 and 3, and between 4 and 7; nothing after window 7.
        let line = [
            (0, 1.0),
            (10, 2.0),
            (20, 3.0),
            (30, 4.0),
            (40, 6.0),
            (50, 22.0 / 3.0),
            (60, 26.0 / 3.0),
            (70, 10.0),
        ];
        close(filled(&p, &q.clone().fill(Fill::Linear)), &line);
        let zeros: Vec<(i64, f64)> = (0..10)
            .map(|w| (w * 10, [1.0, 0.0, 0.0, 4.0, 6.0, 0.0, 0.0, 10.0, 0.0, 0.0][w as usize]))
            .collect();
        close(filled(&p, &q.clone().fill(Fill::Value(0.0))), &zeros);
        // With no start and no end, the data's range: window 0 to window 7.
        let open = Query::new("m", "f").agg(Agg::Sum).every(10);
        close(filled(&p, &open.clone().fill(Fill::Prev)), &prev);
        close(
            filled(&p, &open.clone().fill(Fill::Value(-1.0)))[..3].to_vec(),
            &[(0, 1.0), (10, -1.0), (20, -1.0)],
        );
        assert_eq!(filled(&p, &open.clone().fill(Fill::Value(-1.0))).len(), 8);
        // Only an end: the windows up to the one that holds its last instant (99).
        assert_eq!(
            filled(&p, &open.clone().range(i64::MIN, 100).fill(Fill::Value(0.0))).len(),
            10
        );
        assert_eq!(
            filled(&p, &open.clone().range(i64::MIN, 101).fill(Fill::Value(0.0))).len(),
            11
        );
        // Only a start: from its window to the data's last one. Windows -2 and -1 come first.
        let from = open.clone().range(-20, i64::MAX).fill(Fill::Value(0.0));
        assert_eq!(filled(&p, &from)[..3], [(-20, 0.0), (-10, 0.0), (0, 1.0)]);
        assert_eq!(filled(&p, &from).len(), 10);
        // Leading windows have no previous one and no line to be on.
        let lead = Query::new("m", "f").range(-20, 100).agg(Agg::Sum).every(10);
        close(filled(&p, &lead.clone().fill(Fill::Prev)), &prev_to_the_end);
        assert_eq!(filled(&p, &lead.clone().fill(Fill::Linear)).len(), 8);
        assert_eq!(filled(&p, &lead.clone().fill(Fill::Value(0.0))).len(), 12);
        // Windows anchored at the start of the range.
        let anchored = Query::new("m", "f")
            .range(5, 100)
            .align(Align::Start)
            .agg(Agg::Sum)
            .every(10);
        let rows = filled(&p, &anchored.fill(Fill::Value(0.0)));
        assert_eq!((rows[0], rows[1], rows[2].0, rows.len()), ((5, 1.0), (15, 0.0), 25, 10));
        // No point, no row, whatever the fill.
        assert!(filled(&[], &q.fill(Fill::Value(1.0))).is_empty());
    }

    #[test]
    fn a_fill_has_the_type_of_the_result() {
        let at = |t: i64, v: FieldValue| (t, v);
        let q = Query::new("m", "f").range(0, 40).agg(Agg::First).every(10);
        let ints = [at(5, FieldValue::Int(10)), at(35, FieldValue::Int(20))];
        let values = |q: &Query, p: &[(i64, FieldValue)]| -> Vec<FieldValue> {
            evaluate(p, q).unwrap().into_iter().map(|r| r.1).collect()
        };
        let want = [
            FieldValue::Int(10),
            FieldValue::Int(13),
            FieldValue::Int(17),
            FieldValue::Int(20),
        ];
        assert_eq!(values(&q.clone().fill(Fill::Linear), &ints), want);
        assert_eq!(values(&q.clone().fill(Fill::Value(7.4)), &ints)[1], FieldValue::Int(7));
        assert_eq!(values(&q.clone().fill(Fill::Prev), &ints)[2], FieldValue::Int(10));
        // A count is unsigned; the number is rounded, and not below zero.
        let count = Query::new("m", "f").range(0, 30).agg(Agg::Count).every(10);
        let p = pts(&[(5, 1.0), (25, 1.0)]);
        assert_eq!(
            values(&count.clone().fill(Fill::Value(0.0)), &p)[1],
            FieldValue::UInt(0)
        );
        assert_eq!(
            values(&count.clone().fill(Fill::Value(2.5)), &p)[1],
            FieldValue::UInt(3)
        );
        assert_eq!(values(&count.fill(Fill::Value(-4.0)), &p)[1], FieldValue::UInt(0));
        // Text can be carried forward, but is no number.
        let text = [at(5, FieldValue::Str("a".into())), at(25, FieldValue::Bool(true))];
        let strings = [at(5, FieldValue::Str("a".into())), at(25, FieldValue::Str("b".into()))];
        let q = Query::new("m", "f").range(0, 30).agg(Agg::First).every(10);
        let carried = values(&q.clone().fill(Fill::Prev), &strings);
        assert_eq!(carried[1], FieldValue::Str("a".into()));
        // The error can come from the end of the range, too.
        let lone = [at(5, FieldValue::Str("a".into()))];
        assert!(evaluate(&lone, &q.clone().fill(Fill::Value(1.0))).is_err());
        for fill in [Fill::Linear, Fill::Value(1.0)] {
            for p in [&strings, &text] {
                let e = evaluate(p, &q.clone().fill(fill)).unwrap_err();
                assert!(e.to_string().contains("needs a numeric result"), "{e}");
            }
        }
    }

    #[test]
    fn filling_too_many_windows_is_refused() {
        let p = pts(&[(5, 1.0), (95, 2.0)]);
        let q = Query::new("m", "f")
            .range(0, 100)
            .agg(Agg::Sum)
            .every(10)
            .fill(Fill::Prev);
        assert_eq!(evaluate_within(&p, &q, 10).unwrap().len(), 10);
        let e = evaluate_within(&p, &q, 9).unwrap_err().to_string();
        assert!(e.contains("filling would make 10 rows, more than the 9 allowed"), "{e}");
        // A nanosecond window over decades is the case it is for.
        let huge = Query::new("m", "f").agg(Agg::Sum).every(1).fill(Fill::Prev);
        assert!(evaluate(&pts(&[(0, 1.0), (i64::MAX, 2.0)]), &huge).is_err());
        // Without a fill, the same query is fine.
        assert_eq!(
            evaluate(&pts(&[(0, 1.0), (i64::MAX, 2.0)]), &Query { fill: None, ..huge })
                .unwrap()
                .len(),
            2
        );
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
