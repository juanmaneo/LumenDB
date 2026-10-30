//! Flow keys (5-tuple), per-flow statistics and a mergeable flow table keyed
//! with a tiny Fx-style hasher (no SipHash on the per-packet hot path).

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::fmt;
use std::hash::{BuildHasherDefault, Hasher};
use std::net::{IpAddr, SocketAddr};

const FX_K: u64 = 0x517c_c1b7_2722_0a95;

/// Fx-style multiplicative hasher (as used by rustc). Not DoS resistant,
/// which is fine for flow tables built from a capture file.
#[derive(Clone, Copy, Debug, Default)]
pub struct FxHasher {
    hash: u64,
}

impl Hasher for FxHasher {
    fn write(&mut self, bytes: &[u8]) {
        for c in bytes.chunks(8) {
            let mut w = [0u8; 8];
            w[..c.len()].copy_from_slice(c);
            self.hash = (self.hash.rotate_left(5) ^ u64::from_le_bytes(w)).wrapping_mul(FX_K);
        }
    }

    fn finish(&self) -> u64 {
        self.hash
    }
}

pub type FxBuildHasher = BuildHasherDefault<FxHasher>;

/// Human-readable IP protocol name, if well known.
pub fn proto_name(proto: u8) -> Option<&'static str> {
    match proto {
        1 => Some("icmp"),
        6 => Some("tcp"),
        17 => Some("udp"),
        58 => Some("icmp6"),
        132 => Some("sctp"),
        _ => None,
    }
}

/// Unidirectional 5-tuple. Ports are 0 for port-less protocols and for
/// non-first IP fragments.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct FlowKey {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
}

impl fmt::Display for FlowKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match proto_name(self.proto) {
            Some(n) => n.to_string(),
            None => format!("p{}", self.proto),
        };
        let src = SocketAddr::new(self.src, self.src_port);
        let dst = SocketAddr::new(self.dst, self.dst_port);
        write!(f, "{name} {src} -> {dst}")
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FlowStats {
    pub packets: u64,
    /// Sum of on-the-wire (original) lengths.
    pub bytes: u64,
    pub first_ts_ns: u64,
    pub last_ts_ns: u64,
}

impl FlowStats {
    fn absorb(&mut self, o: &FlowStats) {
        self.packets += o.packets;
        self.bytes += o.bytes;
        self.first_ts_ns = self.first_ts_ns.min(o.first_ts_ns);
        self.last_ts_ns = self.last_ts_ns.max(o.last_ts_ns);
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FlowTable {
    map: HashMap<FlowKey, FlowStats, FxBuildHasher>,
}

impl FlowTable {
    pub fn new() -> Self {
        Self::default()
    }

    fn add(&mut self, key: FlowKey, s: FlowStats) {
        match self.map.entry(key) {
            Entry::Occupied(mut e) => e.get_mut().absorb(&s),
            Entry::Vacant(e) => {
                e.insert(s);
            }
        }
    }

    /// Account one packet of `wire_len` bytes seen at `ts_ns`.
    pub fn record(&mut self, key: FlowKey, ts_ns: u64, wire_len: u32) {
        let s = FlowStats {
            packets: 1,
            bytes: u64::from(wire_len),
            first_ts_ns: ts_ns,
            last_ts_ns: ts_ns,
        };
        self.add(key, s);
    }

    /// Fold another table in (per-thread tables are merged this way).
    pub fn merge(&mut self, other: FlowTable) {
        for (k, s) in other.map {
            self.add(k, s);
        }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn get(&self, k: &FlowKey) -> Option<&FlowStats> {
        self.map.get(k)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&FlowKey, &FlowStats)> {
        self.map.iter()
    }

    /// The `n` heaviest flows by bytes (ties broken by key), deterministic.
    pub fn top_n(&self, n: usize) -> Vec<(FlowKey, FlowStats)> {
        let mut v: Vec<_> = self.map.iter().map(|(k, s)| (*k, *s)).collect();
        v.sort_unstable_by(|a, b| b.1.bytes.cmp(&a.1.bytes).then(a.0.cmp(&b.0)));
        v.truncate(n);
        v
    }

    /// All flows sorted by key.
    pub fn into_sorted(self) -> Vec<(FlowKey, FlowStats)> {
        let mut v: Vec<_> = self.map.into_iter().collect();
        v.sort_unstable_by_key(|a| a.0);
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::hash::BuildHasher;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn k(last: u8, proto: u8) -> FlowKey {
        FlowKey {
            src: IpAddr::V4(Ipv4Addr::new(10, 0, 0, last)),
            dst: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            src_port: 1234,
            dst_port: 80,
            proto,
        }
    }

    #[test]
    fn hasher_is_deterministic_and_handles_partial_words() {
        let b = FxBuildHasher::default();
        assert_eq!(b.hash_one(k(1, 6)), b.hash_one(k(1, 6)));
        assert_ne!(b.hash_one(k(1, 6)), b.hash_one(k(2, 6)));
        let mut h = FxHasher::default();
        h.write(&[1, 2, 3, 4, 5, 6, 7, 8, 9]);
        assert_ne!(h.finish(), 0);
    }

    #[test]
    fn display_all_protocols() {
        assert_eq!(k(2, 6).to_string(), "tcp 10.0.0.2:1234 -> 10.0.0.1:80");
        for (p, n) in [(1, "icmp"), (17, "udp"), (58, "icmp6"), (132, "sctp"), (47, "p47")] {
            assert!(k(2, p).to_string().starts_with(n));
        }
        let v6 = FlowKey {
            src: IpAddr::V6(Ipv6Addr::LOCALHOST),
            dst: IpAddr::V6(Ipv6Addr::LOCALHOST),
            src_port: 1,
            dst_port: 2,
            proto: 17,
        };
        assert_eq!(v6.to_string(), "udp [::1]:1 -> [::1]:2");
    }

    #[test]
    fn record_merge_and_ordering() {
        let mut a = FlowTable::new();
        assert!(a.is_empty());
        a.record(k(1, 6), 100, 10);
        a.record(k(1, 6), 50, 20);
        a.record(k(2, 17), 70, 500);
        let mut b = FlowTable::new();
        b.record(k(1, 6), 300, 5);
        b.record(k(3, 6), 1, 35);
        a.merge(b);
        assert_eq!(a.len(), 3);
        let s = a.get(&k(1, 6)).unwrap();
        assert_eq!(
            *s,
            FlowStats {
                packets: 3,
                bytes: 35,
                first_ts_ns: 50,
                last_ts_ns: 300
            }
        );
        assert_eq!(a.iter().count(), 3);
        let top = a.top_n(2);
        assert_eq!(top[0].0, k(2, 17));
        assert_eq!(top[1].0, k(1, 6)); // tie on 35 bytes broken by key order
        let sorted = a.clone().into_sorted();
        assert_eq!(sorted.iter().map(|(k, _)| k.src).collect::<Vec<_>>().len(), 3);
        assert!(sorted.windows(2).all(|w| w[0].0 < w[1].0));
        assert_eq!(a.top_n(10).len(), 3);
    }
}
