//! Queries: a time range over one field of a measurement, filtered by tag
//! equality, optionally aggregated (sum/count/min/max/mean) per series and
//! per time window (`GROUP BY time(every)`), plus top-N ranking — e.g. the
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
}

impl Agg {
    pub fn parse(s: &str) -> Option<Agg> {
        match s {
            "sum" => Some(Agg::Sum),
            "count" => Some(Agg::Count),
            "min" => Some(Agg::Min),
            "max" => Some(Agg::Max),
            "mean" => Some(Agg::Mean),
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
        Agg::Sum => FieldValue::Float(numeric()?.iter().sum()),
        Agg::Min => FieldValue::Float(numeric()?.into_iter().fold(f64::INFINITY, f64::min)),
        Agg::Max => FieldValue::Float(numeric()?.into_iter().fold(f64::NEG_INFINITY, f64::max)),
        Agg::Mean => {
            let v = numeric()?;
            FieldValue::Float(v.iter().sum::<f64>() / v.len() as f64)
        }
    })
}

/// Applies `q`'s aggregation to the sorted points of one series. Raw points
/// are returned as-is; aggregated rows are stamped with their window start.
pub fn evaluate(points: &[(i64, FieldValue)], q: &Query) -> Result<Vec<(i64, FieldValue)>> {
    let Some(agg) = q.agg else {
        return Ok(points.to_vec());
    };
    let width = q.every.map_or(i128::MAX, i128::from);
    let start = i128::from(q.start);
    let window = |ts: i64| (i128::from(ts) - start) / width;
    points
        .chunk_by(|a, b| window(a.0) == window(b.0))
        .map(|w| Ok(((start + window(w[0].0) * width) as i64, reduce(agg, w)?)))
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
        for a in [Agg::Sum, Agg::Count, Agg::Min, Agg::Max, Agg::Mean] {
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
    fn non_numeric_aggregates_fail_except_count() {
        let p = vec![(1, FieldValue::Str("x".into())), (2, FieldValue::Bool(true))];
        let q = Query::new("m", "f");
        for agg in [Agg::Sum, Agg::Min, Agg::Max, Agg::Mean] {
            assert!(evaluate(&p, &q.clone().agg(agg)).is_err());
        }
        assert_eq!(evaluate(&p, &q.agg(Agg::Count)).unwrap()[0].1, FieldValue::UInt(2));
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
