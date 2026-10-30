//! Classic libpcap format: zero-copy record walking plus a resynchronisation
//! heuristic ([`find_next_record`]) used to cut a file into record-aligned
//! chunks that threads parse independently.

use crate::error::{Error, Result};

pub const GLOBAL_HEADER_LEN: usize = 24;
pub const RECORD_HEADER_LEN: usize = 16;
pub const MAGIC_MICROS: u32 = 0xa1b2_c3d4;
pub const MAGIC_NANOS: u32 = 0xa1b2_3c4d;
/// Upper bound for a plausible captured length when the file's snaplen is 0.
pub const DEFAULT_SNAPLEN_LIMIT: u32 = 262_144;
/// Number of consecutive plausible records required to accept a resync point.
pub const CHAIN_DEPTH: usize = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PcapHeader {
    pub big_endian: bool,
    pub nanos: bool,
    pub snaplen: u32,
    pub linktype: u32,
}

impl PcapHeader {
    fn u32_at(&self, b: &[u8], at: usize) -> u32 {
        let w = [b[at], b[at + 1], b[at + 2], b[at + 3]];
        if self.big_endian {
            u32::from_be_bytes(w)
        } else {
            u32::from_le_bytes(w)
        }
    }

    fn caplen_limit(&self) -> u32 {
        if self.snaplen == 0 {
            DEFAULT_SNAPLEN_LIMIT
        } else {
            self.snaplen
        }
    }
}

/// Return `(big_endian, nanos)` if `magic` (read little-endian) is a pcap magic.
pub fn classify_magic(magic: u32) -> Option<(bool, bool)> {
    match magic {
        MAGIC_MICROS => Some((false, false)),
        MAGIC_NANOS => Some((false, true)),
        m if m == MAGIC_MICROS.swap_bytes() => Some((true, false)),
        m if m == MAGIC_NANOS.swap_bytes() => Some((true, true)),
        _ => None,
    }
}

/// Parse the 24-byte global header.
pub fn parse_header(buf: &[u8]) -> Result<PcapHeader> {
    let h = buf.get(..GLOBAL_HEADER_LEN).ok_or(Error::Malformed {
        offset: 0,
        what: "pcap global header truncated",
    })?;
    let magic = u32::from_le_bytes([h[0], h[1], h[2], h[3]]);
    let (big_endian, nanos) = classify_magic(magic).ok_or(Error::BadMagic(magic))?;
    let mut hdr = PcapHeader {
        big_endian,
        nanos,
        snaplen: 0,
        linktype: 0,
    };
    hdr.snaplen = hdr.u32_at(h, 16);
    hdr.linktype = hdr.u32_at(h, 20) & 0xffff;
    Ok(hdr)
}

/// One captured packet, borrowing its bytes from the input buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record<'a> {
    pub ts_ns: u64,
    pub orig_len: u32,
    pub data: &'a [u8],
}

/// Outcome of decoding the record header at some offset.
#[derive(Debug, PartialEq, Eq)]
pub enum Next<'a> {
    /// A complete record and the offset of the following one.
    Record(Record<'a>, usize),
    /// Exactly at end of buffer.
    End,
    /// Header or data runs past the end of the buffer (torn tail).
    Torn,
}

/// Decode the record starting at `off`.
pub fn read_record<'a>(buf: &'a [u8], off: usize, hdr: &PcapHeader) -> Next<'a> {
    if off == buf.len() {
        return Next::End;
    }
    let Some(h) = buf.get(off..off + RECORD_HEADER_LEN) else {
        return Next::Torn;
    };
    let sec = u64::from(hdr.u32_at(h, 0));
    let frac = u64::from(hdr.u32_at(h, 4));
    let caplen = hdr.u32_at(h, 8) as usize;
    let orig_len = hdr.u32_at(h, 12);
    let start = off + RECORD_HEADER_LEN;
    match buf.get(start..start + caplen) {
        Some(data) => {
            let ts_ns = sec * 1_000_000_000 + if hdr.nanos { frac } else { frac * 1_000 };
            Next::Record(Record { ts_ns, orig_len, data }, start + caplen)
        }
        None => Next::Torn,
    }
}

fn plausible(buf: &[u8], off: usize, hdr: &PcapHeader) -> Option<usize> {
    let h = buf.get(off..off + RECORD_HEADER_LEN)?;
    let frac = hdr.u32_at(h, 4);
    let caplen = hdr.u32_at(h, 8);
    let orig = hdr.u32_at(h, 12);
    let frac_ok = frac < if hdr.nanos { 1_000_000_000 } else { 1_000_000 };
    let ok = frac_ok && caplen > 0 && caplen <= hdr.caplen_limit() && caplen <= orig;
    ok.then_some(off + RECORD_HEADER_LEN + caplen as usize)
}

/// True if `CHAIN_DEPTH` plausible, complete records start at `off` back to
/// back (a shorter chain is accepted only if it ends exactly at EOF). A
/// false positive is harmless: the reader verifies every chunk boundary and
/// falls back to a sequential parse, so results never depend on it.
pub fn chain_ok(buf: &[u8], mut off: usize, hdr: &PcapHeader) -> bool {
    for i in 0..CHAIN_DEPTH {
        if i > 0 && off == buf.len() {
            return true;
        }
        match plausible(buf, off, hdr) {
            Some(next) if next <= buf.len() => off = next,
            _ => return false,
        }
    }
    true
}

/// Find the first offset `>= from` where a record plausibly starts.
pub fn find_next_record(buf: &[u8], from: usize, hdr: &PcapHeader) -> Option<usize> {
    (from..buf.len()).find(|&off| chain_ok(buf, off, hdr))
}

/// Parse every record starting in `[start, end)`, calling `f(linktype,
/// ts_ns, orig_len, data)`. Returns the offset where parsing stopped and
/// whether it stopped on a torn record.
pub fn parse_range(
    buf: &[u8],
    hdr: &PcapHeader,
    start: usize,
    end: usize,
    f: &mut crate::packet::PacketSink<'_>,
) -> (usize, bool) {
    let mut off = start;
    while off < end {
        match read_record(buf, off, hdr) {
            Next::Record(r, next) => {
                f(hdr.linktype, r.ts_ns, r.orig_len, r.data);
                off = next;
            }
            Next::End => break,
            Next::Torn => return (off, true),
        }
    }
    (off, false)
}

/// Zero-copy iterator over the records of a whole pcap buffer.
pub struct Records<'a> {
    buf: &'a [u8],
    hdr: PcapHeader,
    off: usize,
    torn: bool,
}

impl<'a> Records<'a> {
    pub fn new(buf: &'a [u8]) -> Result<Self> {
        let hdr = parse_header(buf)?;
        Ok(Records {
            buf,
            hdr,
            off: GLOBAL_HEADER_LEN,
            torn: false,
        })
    }

    pub fn header(&self) -> &PcapHeader {
        &self.hdr
    }

    /// True once iteration stopped on an incomplete trailing record.
    pub fn torn(&self) -> bool {
        self.torn
    }

    pub fn offset(&self) -> usize {
        self.off
    }
}

impl<'a> Iterator for Records<'a> {
    type Item = Record<'a>;

    fn next(&mut self) -> Option<Record<'a>> {
        match read_record(self.buf, self.off, &self.hdr) {
            Next::Record(r, next) => {
                self.off = next;
                Some(r)
            }
            Next::End => None,
            Next::Torn => {
                self.torn = true;
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::synth::{write_pcap_header, write_pcap_record};

    fn file(big_endian: bool, nanos: bool, recs: &[(u64, &[u8])]) -> Vec<u8> {
        let mut v = Vec::new();
        write_pcap_header(&mut v, big_endian, nanos, 65535, 1).unwrap();
        for (ts, d) in recs {
            write_pcap_record(&mut v, big_endian, nanos, *ts, d.len() as u32 + 4, d).unwrap();
        }
        v
    }

    #[test]
    fn header_variants() {
        for be in [false, true] {
            for ns in [false, true] {
                let v = file(be, ns, &[]);
                let h = parse_header(&v).unwrap();
                assert_eq!(
                    h,
                    PcapHeader {
                        big_endian: be,
                        nanos: ns,
                        snaplen: 65535,
                        linktype: 1
                    }
                );
            }
        }
        assert!(crate::error::err_kind(parse_header(&[0; 10])).starts_with("Malformed"));
        assert_eq!(crate::error::err_kind(parse_header(&[0x0a; 24])), "BadMagic(168430090)");
        assert_eq!(classify_magic(0), None);
    }

    #[test]
    fn iterate_records_and_torn_tail() {
        for (be, ns) in [(false, false), (true, true), (false, true), (true, false)] {
            let v = file(be, ns, &[(1_500_000_123_000, b"abc"), (2_000_000_000_000, b"defgh")]);
            let mut it = Records::new(&v).unwrap();
            assert_eq!(it.header().linktype, 1);
            let a = it.next().unwrap();
            assert_eq!((a.ts_ns, a.orig_len, a.data), (1_500_000_123_000, 7, &b"abc"[..]));
            assert_eq!(it.next().unwrap().data, b"defgh");
            assert!(it.next().is_none());
            assert!(!it.torn());
            assert_eq!(it.offset(), v.len());
            for cut in [v.len() - 1, v.len() - 6, v.len() - 13] {
                let mut it = Records::new(&v[..cut]).unwrap();
                assert_eq!(it.by_ref().count(), 1);
                assert!(it.torn());
            }
        }
        assert!(Records::new(&[]).is_err());
    }

    #[test]
    fn parse_range_stops_at_end_or_torn() {
        let v = file(false, false, &[(1_000, b"a"), (2_000, b"bb"), (3_000, b"ccc")]);
        let hdr = parse_header(&v).unwrap();
        let mut seen = Vec::new();
        let (stop, torn) = parse_range(&v, &hdr, GLOBAL_HEADER_LEN, 42, &mut |lt, ts, ol, d| {
            seen.push((lt, ts, ol, d.len()));
        });
        assert_eq!((stop, torn), (GLOBAL_HEADER_LEN + 17 + 18, false));
        assert_eq!(seen, vec![(1, 1_000, 5, 1), (1, 2_000, 6, 2)]);
        assert_eq!(
            parse_range(&v, &hdr, GLOBAL_HEADER_LEN, usize::MAX, &mut |_, _, _, _| {}),
            (v.len(), false)
        );
        let cut = &v[..v.len() - 1];
        let (stop, torn) = parse_range(cut, &hdr, GLOBAL_HEADER_LEN, cut.len(), &mut |_, _, _, _| {});
        assert!(torn && stop == GLOBAL_HEADER_LEN + 35);
    }

    #[test]
    fn resync_finds_real_boundaries() {
        let recs: Vec<(u64, Vec<u8>)> = (0..20u64).map(|i| (i * 1_000, vec![0xee; 30 + i as usize])).collect();
        let refs: Vec<(u64, &[u8])> = recs.iter().map(|(t, d)| (*t, d.as_slice())).collect();
        let v = file(false, false, &refs);
        let hdr = parse_header(&v).unwrap();
        let mut starts = vec![GLOBAL_HEADER_LEN];
        for r in &recs[..19] {
            starts.push(starts.last().unwrap() + 16 + r.1.len());
        }
        for from in [GLOBAL_HEADER_LEN, GLOBAL_HEADER_LEN + 1, 100, 400, starts[18] + 1] {
            let found = find_next_record(&v, from, &hdr).unwrap();
            assert_eq!(found, *starts.iter().find(|&&s| s >= from).unwrap());
        }
        assert_eq!(find_next_record(&v, starts[19] + 1, &hdr), None);
        // a torn tail never anchors a chunk boundary
        assert!(!chain_ok(&v[..v.len() - 3], starts[19], &hdr));
        assert!(chain_ok(&v[..starts[19]], starts[18], &hdr));
        // implausible: zero caplen, frac too large, caplen > orig, caplen > snaplen
        let mut z = v.clone();
        z[starts[0] + 8..starts[0] + 12].copy_from_slice(&0u32.to_le_bytes());
        assert!(!chain_ok(&z, starts[0], &hdr));
        let mut f = v.clone();
        f[starts[0] + 4..starts[0] + 8].copy_from_slice(&1_000_000u32.to_le_bytes());
        assert!(!chain_ok(&f, starts[0], &hdr));
        let mut o = v.clone();
        o[starts[0] + 12..starts[0] + 16].copy_from_slice(&1u32.to_le_bytes());
        assert!(!chain_ok(&o, starts[0], &hdr));
        let small = PcapHeader { snaplen: 10, ..hdr };
        assert!(!chain_ok(&v, starts[0], &small));
        let zero = PcapHeader { snaplen: 0, ..hdr };
        assert!(chain_ok(&v, starts[0], &zero));
        let nano = PcapHeader { nanos: true, ..hdr };
        assert!(chain_ok(&f, starts[0], &nano));
    }
}
