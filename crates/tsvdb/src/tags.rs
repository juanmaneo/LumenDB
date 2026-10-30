//! Series index: measurement + tag set → series id, plus an inverted index
//! (measurement, tag key, tag value) → series ids for tag predicates
//! (InfluxDB's TSI, in memory and rebuilt from flashkv at open).

use crate::error::Result;
use crate::lineproto::{escape, KEY_SPECIALS, MEASUREMENT_SPECIALS};
use flashkv::codec::Decoder;
use flashkv::varint::{put_len_prefixed, put_uvarint64};
use std::collections::{BTreeMap, BTreeSet, HashMap};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Series {
    pub id: u64,
    pub measurement: String,
    pub tags: BTreeMap<String, String>,
}

impl Series {
    /// Canonical series key, e.g. `cpu,host=a,region=eu`.
    pub fn key(&self) -> String {
        series_key(&self.measurement, &self.tags)
    }

    /// Persistent form (the id is stored by the caller, in the key).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.id.to_le_bytes());
        put_len_prefixed(&mut out, self.measurement.as_bytes());
        put_uvarint64(&mut out, self.tags.len() as u64);
        for (k, v) in &self.tags {
            put_len_prefixed(&mut out, k.as_bytes());
            put_len_prefixed(&mut out, v.as_bytes());
        }
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Series> {
        let mut d = Decoder::new(buf);
        let id = d.u64();
        let measurement = String::from_utf8_lossy(d.lp()).into_owned();
        let n = d.varint().min(d.remaining() as u64);
        let mut tags = BTreeMap::new();
        for _ in 0..n {
            let k = String::from_utf8_lossy(d.lp()).into_owned();
            let v = String::from_utf8_lossy(d.lp()).into_owned();
            tags.insert(k, v);
        }
        d.finish("series entry")?;
        Ok(Series { id, measurement, tags })
    }
}

/// Canonical (line-protocol escaped, tags sorted) series key.
pub fn series_key(measurement: &str, tags: &BTreeMap<String, String>) -> String {
    let mut s = escape(measurement, MEASUREMENT_SPECIALS);
    for (k, v) in tags {
        s.push(',');
        s.push_str(&escape(k, KEY_SPECIALS));
        s.push('=');
        s.push_str(&escape(v, KEY_SPECIALS));
    }
    s
}

type Posting = (String, String, String);

#[derive(Default, Debug)]
pub struct SeriesIndex {
    by_key: HashMap<String, u64>,
    series: HashMap<u64, Series>,
    by_measurement: BTreeMap<String, BTreeSet<u64>>,
    postings: HashMap<Posting, BTreeSet<u64>>,
    next_id: u64,
}

impl SeriesIndex {
    pub fn new() -> Self {
        SeriesIndex::default()
    }

    pub fn len(&self) -> usize {
        self.series.len()
    }

    pub fn is_empty(&self) -> bool {
        self.series.is_empty()
    }

    pub fn get(&self, key: &str) -> Option<u64> {
        self.by_key.get(key).copied()
    }

    pub fn series(&self, id: u64) -> Option<&Series> {
        self.series.get(&id)
    }

    /// Id of the series, creating it if needed; `true` when it is new.
    pub fn insert(&mut self, measurement: &str, tags: &BTreeMap<String, String>) -> (u64, bool) {
        match self.get(&series_key(measurement, tags)) {
            Some(id) => (id, false),
            None => {
                let id = self.next_id;
                self.restore(Series {
                    id,
                    measurement: measurement.to_string(),
                    tags: tags.clone(),
                });
                (id, true)
            }
        }
    }

    /// Adds a series with a known id (index rebuild at open).
    pub fn restore(&mut self, s: Series) {
        self.next_id = self.next_id.max(s.id + 1);
        self.by_key.insert(s.key(), s.id);
        self.by_measurement
            .entry(s.measurement.clone())
            .or_default()
            .insert(s.id);
        for (k, v) in &s.tags {
            self.postings
                .entry((s.measurement.clone(), k.clone(), v.clone()))
                .or_default()
                .insert(s.id);
        }
        self.series.insert(s.id, s);
    }

    /// Series of `measurement` matching every `tag = value` filter, by id.
    pub fn lookup(&self, measurement: &str, filters: &[(String, String)]) -> Vec<u64> {
        let mut acc = self.by_measurement.get(measurement).cloned().unwrap_or_default();
        for (k, v) in filters {
            let key = (measurement.to_string(), k.clone(), v.clone());
            acc = self
                .postings
                .get(&key)
                .map_or(BTreeSet::new(), |p| acc.intersection(p).copied().collect());
        }
        acc.into_iter().collect()
    }

    pub fn measurements(&self) -> Vec<String> {
        self.by_measurement.keys().cloned().collect()
    }

    /// Distinct values of tag `key` in `measurement` (SHOW TAG VALUES).
    pub fn tag_values(&self, measurement: &str, key: &str) -> BTreeSet<String> {
        self.lookup(measurement, &[])
            .into_iter()
            .filter_map(|id| self.series[&id].tags.get(key).cloned())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tags(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|&(k, v)| (k.to_string(), v.to_string())).collect()
    }

    fn f(k: &str, v: &str) -> (String, String) {
        (k.to_string(), v.to_string())
    }

    #[test]
    fn insert_and_lookup() {
        let mut idx = SeriesIndex::new();
        assert!(idx.is_empty());
        let (a, new_a) = idx.insert("cpu", &tags(&[("host", "a"), ("dc", "eu")]));
        let (b, _) = idx.insert("cpu", &tags(&[("host", "b"), ("dc", "eu")]));
        let (c, _) = idx.insert("mem", &tags(&[("host", "a")]));
        let (a2, new_a2) = idx.insert("cpu", &tags(&[("dc", "eu"), ("host", "a")]));
        assert!(new_a && !new_a2 && a == a2);
        assert_eq!(idx.len(), 3);
        assert_eq!(idx.lookup("cpu", &[]), vec![a, b]);
        assert_eq!(idx.lookup("cpu", &[f("dc", "eu")]), vec![a, b]);
        assert_eq!(idx.lookup("cpu", &[f("dc", "eu"), f("host", "b")]), vec![b]);
        assert!(idx.lookup("cpu", &[f("host", "zz")]).is_empty());
        assert!(idx.lookup("disk", &[]).is_empty());
        assert_eq!(idx.lookup("mem", &[f("host", "a")]), vec![c]);
        assert_eq!(idx.measurements(), vec!["cpu".to_string(), "mem".to_string()]);
        assert_eq!(
            idx.tag_values("cpu", "host").into_iter().collect::<Vec<_>>(),
            vec!["a", "b"]
        );
        assert!(idx.tag_values("cpu", "nope").is_empty());
        assert_eq!(idx.series(a).unwrap().key(), "cpu,dc=eu,host=a");
        assert_eq!(idx.get("cpu,dc=eu,host=a"), Some(a));
    }

    #[test]
    fn persistence_roundtrip() {
        let s = Series {
            id: 42,
            measurement: "net work".into(),
            tags: tags(&[("k,1", "v=2"), ("z", "")]),
        };
        assert_eq!(s.key(), "net\\ work,k\\,1=v\\=2,z=");
        let back = Series::decode(&s.encode()).unwrap();
        assert_eq!(back, s);
        assert!(Series::decode(&s.encode()[..10]).is_err());
        let mut idx = SeriesIndex::new();
        idx.restore(s);
        assert_eq!(idx.insert("x", &BTreeMap::new()), (43, true));
    }
}
