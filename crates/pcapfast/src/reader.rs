//! Parallel capture reader: detect pcap vs pcapng, mmap the file read-only,
//! cut it into record-aligned chunks, decode chunks on scoped threads (each
//! with its own [`FlowTable`] and timeline) and merge.
//!
//! Results are always identical to a single-threaded pass: every chunk must
//! stop exactly where the next one starts; if a pcap resync heuristic ever
//! picked a false boundary the whole buffer is re-parsed sequentially.

use crate::error::{Error, Result};
use crate::flow::FlowTable;
use crate::packet::flow_key;
use crate::pcap::{self, PcapHeader, GLOBAL_HEADER_LEN};
use crate::pcapng::{self, NgState, BT_SHB};
use memmap2::Mmap;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Format {
    #[default]
    Pcap,
    PcapNg,
}

impl Format {
    /// Detect the format from the first bytes.
    pub fn detect(buf: &[u8]) -> Result<Format> {
        let m = buf.get(..4).ok_or(Error::Malformed {
            offset: 0,
            what: "capture shorter than its magic",
        })?;
        let magic = u32::from_le_bytes([m[0], m[1], m[2], m[3]]);
        if magic == BT_SHB {
            Ok(Format::PcapNg)
        } else if pcap::classify_magic(magic).is_some() {
            Ok(Format::Pcap)
        } else {
            Err(Error::BadMagic(magic))
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseOptions {
    /// Worker threads; 0 = available parallelism.
    pub threads: usize,
    /// Width of timeline buckets in ns (0 is treated as 1).
    pub bucket_ns: u64,
    /// Minimum chunk size in bytes handed to one thread.
    pub min_chunk: usize,
}

impl Default for ParseOptions {
    fn default() -> Self {
        ParseOptions {
            threads: 0,
            bucket_ns: 1_000_000_000,
            min_chunk: 4 << 20,
        }
    }
}

impl ParseOptions {
    fn effective_threads(&self) -> usize {
        match self.threads {
            0 => std::thread::available_parallelism().map_or(1, |n| n.get()),
            n => n,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ParseStats {
    pub packets: u64,
    /// Sum of original (on-the-wire) lengths.
    pub bytes: u64,
    pub flows: FlowTable,
    /// Bucket start (ns) -> (packets, bytes).
    pub timeline: BTreeMap<u64, (u64, u64)>,
    /// Packets that carried no IP flow (ARP, unknown link types, garbage).
    pub non_ip: u64,
    /// The capture ended with an incomplete record/block (ignored).
    pub torn_tail: bool,
    pub format: Format,
    /// Number of chunks actually parsed in parallel.
    pub chunks: usize,
    pub elapsed: Duration,
}

impl ParseStats {
    fn absorb(&mut self, a: Acc) {
        self.packets += a.packets;
        self.bytes += a.bytes;
        self.non_ip += a.non_ip;
        self.flows.merge(a.flows);
        for (b, (p, by)) in a.timeline {
            let e = self.timeline.entry(b).or_default();
            e.0 += p;
            e.1 += by;
        }
    }
}

/// Per-thread accumulator; the current timeline bucket is cached so the
/// BTreeMap is only touched when time crosses a bucket boundary.
struct Acc {
    bucket_ns: u64,
    packets: u64,
    bytes: u64,
    non_ip: u64,
    flows: FlowTable,
    timeline: BTreeMap<u64, (u64, u64)>,
    cur: Option<(u64, u64, u64)>,
}

impl Acc {
    fn new(bucket_ns: u64) -> Self {
        Acc {
            bucket_ns: bucket_ns.max(1),
            packets: 0,
            bytes: 0,
            non_ip: 0,
            flows: FlowTable::new(),
            timeline: BTreeMap::new(),
            cur: None,
        }
    }

    #[inline]
    fn packet(&mut self, linktype: u32, ts_ns: u64, orig_len: u32, data: &[u8]) {
        self.packets += 1;
        self.bytes += u64::from(orig_len);
        match flow_key(linktype, data) {
            Some(k) => self.flows.record(k, ts_ns, orig_len),
            None => self.non_ip += 1,
        }
        let bucket = ts_ns - ts_ns % self.bucket_ns;
        match &mut self.cur {
            Some((b, p, by)) if *b == bucket => {
                *p += 1;
                *by += u64::from(orig_len);
            }
            cur => {
                if let Some((b, p, by)) = cur.replace((bucket, 1, u64::from(orig_len))) {
                    Self::bump(&mut self.timeline, b, p, by);
                }
            }
        }
    }

    fn bump(t: &mut BTreeMap<u64, (u64, u64)>, b: u64, p: u64, by: u64) {
        let e = t.entry(b).or_default();
        e.0 += p;
        e.1 += by;
    }

    fn finish(mut self) -> Acc {
        if let Some((b, p, by)) = self.cur.take() {
            Self::bump(&mut self.timeline, b, p, by);
        }
        self
    }
}

/// One unit of parallel work: a byte range plus the decoder state at its start.
#[derive(Clone, Debug)]
struct Chunk {
    start: usize,
    end: usize,
    kind: Kind,
}

#[derive(Clone, Debug)]
enum Kind {
    Pcap(PcapHeader),
    Ng(NgState),
}

struct ChunkOut {
    acc: Acc,
    stop: usize,
    torn: bool,
}

fn run_chunk(buf: &[u8], c: &Chunk, bucket_ns: u64) -> Result<ChunkOut> {
    let mut acc = Acc::new(bucket_ns);
    let (stop, torn) = match &c.kind {
        Kind::Pcap(hdr) => pcap::parse_range(buf, hdr, c.start, c.end, &mut |lt, ts, ol, d| acc.packet(lt, ts, ol, d)),
        Kind::Ng(st) => {
            let s = pcapng::parse_range(buf, c.start, c.end, st.clone(), &mut |lt, ts, ol, d| {
                acc.packet(lt, ts, ol, d)
            })?;
            (s.end_offset, s.torn)
        }
    };
    Ok(ChunkOut {
        acc: acc.finish(),
        stop,
        torn,
    })
}

fn plan(buf: &[u8], format: Format, chunk_size: usize) -> Result<Vec<Chunk>> {
    match format {
        Format::Pcap => {
            let hdr = pcap::parse_header(buf)?;
            let mut starts = vec![GLOBAL_HEADER_LEN];
            let mut probe = GLOBAL_HEADER_LEN.saturating_add(chunk_size);
            while probe < buf.len() {
                match pcap::find_next_record(buf, probe, &hdr) {
                    Some(s) => {
                        starts.push(s);
                        probe = s.saturating_add(chunk_size);
                    }
                    None => break,
                }
            }
            starts.push(buf.len());
            Ok(starts
                .windows(2)
                .map(|w| Chunk {
                    start: w[0],
                    end: w[1],
                    kind: Kind::Pcap(hdr),
                })
                .collect())
        }
        Format::PcapNg => {
            let mut cuts = pcapng::scan(buf, chunk_size)?.cuts;
            let ends: Vec<usize> = cuts.iter().skip(1).map(|c| c.0).chain([buf.len()]).collect();
            Ok(cuts
                .drain(..)
                .zip(ends)
                .map(|((start, st), end)| Chunk {
                    start,
                    end,
                    kind: Kind::Ng(st),
                })
                .collect())
        }
    }
}

fn run_parallel(buf: &[u8], chunks: &[Chunk], threads: usize, bucket_ns: u64) -> Vec<Result<ChunkOut>> {
    let next = std::sync::atomic::AtomicUsize::new(0);
    let mut slots: Vec<Option<Result<ChunkOut>>> = chunks.iter().map(|_| None).collect();
    let results = parking_lot::Mutex::new(&mut slots);
    std::thread::scope(|s| {
        for _ in 0..threads.min(chunks.len()) {
            s.spawn(|| loop {
                let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let Some(c) = chunks.get(i) else { break };
                let r = run_chunk(buf, c, bucket_ns);
                results.lock()[i] = Some(r);
            });
        }
    });
    slots.into_iter().flatten().collect()
}

/// Parse an in-memory capture.
pub fn parse_bytes(buf: &[u8], opts: &ParseOptions) -> Result<ParseStats> {
    let t0 = Instant::now();
    let format = Format::detect(buf)?;
    let threads = opts.effective_threads();
    let chunk_size = (buf.len() / threads).max(opts.min_chunk).max(1);
    let mut chunks = plan(buf, format, chunk_size)?;
    loop {
        if let Some(mut stats) = merge(buf, &chunks, threads, opts.bucket_ns)? {
            stats.format = format;
            stats.elapsed = t0.elapsed();
            return Ok(stats);
        }
        // A resync point was inside a record: redo the buffer as one chunk
        // (a single chunk always verifies, so this loops at most once).
        chunks.truncate(1);
        chunks[0].end = buf.len();
    }
}

/// Run chunks in parallel and merge in order. `Ok(None)` if some chunk did
/// not stop exactly where its successor starts.
fn merge(buf: &[u8], chunks: &[Chunk], threads: usize, bucket_ns: u64) -> Result<Option<ParseStats>> {
    let outs = run_parallel(buf, chunks, threads, bucket_ns);
    let mut stats = ParseStats {
        chunks: chunks.len(),
        ..ParseStats::default()
    };
    let mut expect = chunks[0].start;
    for (c, out) in chunks.iter().zip(outs) {
        if c.start != expect {
            return Ok(None);
        }
        let out = out?;
        expect = out.stop;
        stats.torn_tail = out.torn;
        stats.absorb(out.acc);
    }
    Ok(Some(stats))
}

/// mmap `path` read-only (capture files are input, never written) and parse.
pub fn parse_file(path: &Path, opts: &ParseOptions) -> Result<ParseStats> {
    let file = File::open(path)?;
    // SAFETY: the map is read-only and private to this call; if another
    // process truncates the capture concurrently we may fault, which is the
    // documented memmap2 caveat for input files (DB files are never mmapped).
    let map = unsafe { Mmap::map(&file)? };
    #[cfg(unix)]
    let _ = map.advise(memmap2::Advice::Sequential);
    parse_bytes(&map, opts)
}

/// Read everything from `r` and parse on a single thread.
pub fn parse_reader(r: &mut dyn Read, opts: &ParseOptions) -> Result<ParseStats> {
    parse_reader_parallel(
        r,
        &ParseOptions {
            threads: 1,
            ..opts.clone()
        },
    )
}

/// Read everything from `r` and parse in parallel.
pub fn parse_reader_parallel(r: &mut dyn Read, opts: &ParseOptions) -> Result<ParseStats> {
    let mut buf = Vec::new();
    r.read_to_end(&mut buf)?;
    parse_bytes(&buf, opts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::synth::{frame, SynthOptions};
    use crate::synth::{generate, write_ng_epb, write_ng_idb, write_ng_shb, write_pcap_header, write_pcap_record};

    fn synth(format: Format, nanos: bool, be: bool, packets: u64) -> Vec<u8> {
        let o = SynthOptions {
            packets,
            format,
            nanos,
            big_endian: be,
            interval_ns: 7_919_000,
            ..Default::default()
        };
        let mut v = Vec::new();
        generate(&o, &mut v).unwrap();
        v
    }

    fn opts(threads: usize, min_chunk: usize) -> ParseOptions {
        ParseOptions {
            threads,
            min_chunk,
            ..ParseOptions::default()
        }
    }

    fn same(a: &ParseStats, b: &ParseStats) {
        assert_eq!(
            (a.packets, a.bytes, a.non_ip, a.torn_tail, a.format),
            (b.packets, b.bytes, b.non_ip, b.torn_tail, b.format)
        );
        assert_eq!(a.flows, b.flows);
        assert_eq!(a.timeline, b.timeline);
    }

    #[test]
    fn detect_formats() {
        assert_eq!(
            Format::detect(&synth(Format::Pcap, false, true, 0)).unwrap(),
            Format::Pcap
        );
        assert_eq!(
            Format::detect(&synth(Format::PcapNg, false, false, 0)).unwrap(),
            Format::PcapNg
        );
        assert!(crate::error::err_kind(Format::detect(b"ab")).starts_with("Malformed"));
        assert!(crate::error::err_kind(Format::detect(b"GIF89a")).starts_with("BadMagic"));
    }

    #[test]
    fn parallel_equals_sequential_for_all_variants() {
        for format in [Format::Pcap, Format::PcapNg] {
            for (nanos, be) in [(false, false), (true, false), (false, true), (true, true)] {
                let v = synth(format, nanos, be, 3_000);
                let one = parse_bytes(&v, &opts(1, usize::MAX)).unwrap();
                assert_eq!(one.chunks, 1);
                assert_eq!(one.packets, 3_000);
                assert_eq!(one.timeline.values().map(|x| x.0).sum::<u64>(), 3_000);
                assert!(one.non_ip > 0 && one.flows.len() > 10 && !one.torn_tail);
                for (t, mc) in [(4, 1), (8, 4096), (3, 100_000), (0, 1)] {
                    let par = parse_bytes(&v, &opts(t, mc)).unwrap();
                    same(&one, &par);
                    if mc < 100_000 {
                        assert!(par.chunks > 1, "{format:?} t{t} mc{mc}");
                    }
                }
            }
        }
    }

    #[test]
    fn torn_tails_are_flagged_not_errors() {
        for format in [Format::Pcap, Format::PcapNg] {
            let v = synth(format, false, false, 500);
            let full = parse_bytes(&v, &opts(1, usize::MAX)).unwrap();
            let cut = &v[..v.len() - 7];
            let seq = parse_bytes(cut, &opts(1, usize::MAX)).unwrap();
            assert!(seq.torn_tail);
            assert_eq!(seq.packets, full.packets - 1);
            same(&seq, &parse_bytes(cut, &opts(6, 512)).unwrap());
        }
    }

    #[test]
    fn false_resync_point_falls_back_to_sequential() {
        // A big packet whose payload hides three fake-but-plausible records
        // ending exactly where the real next record starts.
        let mut fake = Vec::new();
        for _ in 0..3 {
            write_pcap_record(&mut fake, false, false, 5_000, 40, &[0x11; 20]).unwrap();
        }
        let mut payload = vec![0xff; 600];
        payload.extend_from_slice(&fake);
        let mut v = Vec::new();
        write_pcap_header(&mut v, false, false, 65535, 1).unwrap();
        write_pcap_record(&mut v, false, false, 1_000, payload.len() as u32, &payload).unwrap();
        for i in 0..5u32 {
            let f = frame(i, 30, false);
            write_pcap_record(&mut v, false, false, 2_000, f.len() as u32, &f).unwrap();
        }
        let seq = parse_bytes(&v, &opts(1, usize::MAX)).unwrap();
        assert_eq!(seq.packets, 6);
        let par = parse_bytes(&v, &opts(2, 100)).unwrap();
        assert_eq!(par.chunks, 1);
        same(&seq, &par);
        // trailing garbage: no resync point is found in it, it is a torn tail
        v.extend_from_slice(&[0xff; 1000]);
        let seq = parse_bytes(&v, &opts(1, usize::MAX)).unwrap();
        assert!(seq.torn_tail && seq.packets == 6);
        same(&seq, &parse_bytes(&v, &opts(3, 100)).unwrap());
    }

    #[test]
    fn errors_surface() {
        assert!(crate::error::err_kind(parse_bytes(&[], &opts(1, 1))).starts_with("Malformed"));
        assert!(
            crate::error::err_kind(parse_bytes(&[0xd4, 0xc3, 0xb2, 0xa1, 0], &opts(1, 1))).starts_with("Malformed")
        );
        // the header scan rejects a later section's bad byte-order magic
        let mut ng = Vec::new();
        write_ng_shb(&mut ng, false).unwrap();
        write_ng_shb(&mut ng, false).unwrap();
        let half = ng.len() / 2;
        ng[half + 8] = 0;
        assert!(parse_bytes(&ng, &opts(1, 1)).is_err());
        // scan accepts the EPB, the chunk parser rejects its unknown interface
        let mut epb = Vec::new();
        write_ng_shb(&mut epb, false).unwrap();
        write_ng_idb(&mut epb, false, 1, 0, None).unwrap();
        write_ng_epb(&mut epb, false, 0, 0, 3, b"abc").unwrap();
        write_ng_epb(&mut epb, false, 7, 0, 3, b"abc").unwrap();
        assert!(parse_bytes(&epb, &opts(4, 1)).is_err());
    }

    #[test]
    fn accumulator_buckets_and_zero_width() {
        let mut a = Acc::new(0);
        a.packet(1, 5, 10, &[]);
        a.packet(1, 5, 10, &[]);
        a.packet(1, 3, 1, &[]);
        a.packet(1, 5, 2, &[]);
        let a = a.finish();
        assert_eq!(a.timeline[&5], (3, 22));
        assert_eq!(a.timeline[&3], (1, 1));
        assert_eq!(a.non_ip, 4);
        assert_eq!(Acc::new(10).finish().timeline.len(), 0);
    }

    #[test]
    fn file_and_reader_entry_points() {
        let dir = std::env::temp_dir().join(format!("pcapfast-reader-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("x.pcapng");
        let v = synth(Format::PcapNg, true, false, 1_000);
        std::fs::write(&path, &v).unwrap();
        let f = parse_file(&path, &ParseOptions::default()).unwrap();
        assert_eq!((f.packets, f.format), (1_000, Format::PcapNg));
        assert!(f.elapsed > Duration::ZERO);
        same(&f, &parse_reader(&mut &v[..], &ParseOptions::default()).unwrap());
        same(&f, &parse_reader_parallel(&mut &v[..], &opts(4, 1)).unwrap());
        let empty = dir.join("empty.pcap");
        std::fs::write(&empty, b"").unwrap();
        assert!(crate::error::err_kind(parse_file(&empty, &ParseOptions::default())).starts_with("Malformed"));
        assert!(crate::error::err_kind(parse_file(&dir.join("missing"), &ParseOptions::default())).starts_with("Io"));
        // a directory opens fine but can be neither mapped nor read
        assert!(crate::error::err_kind(parse_file(&dir, &ParseOptions::default())).starts_with("Io"));
        let mut d = File::open(&dir).unwrap();
        assert!(crate::error::err_kind(parse_reader(&mut d, &ParseOptions::default())).starts_with("Io"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
