//! Deterministic synthetic capture generator (pcap / pcapng) plus low-level
//! record/block writers, used by tests, benchmarks and `bench gen-pcap`.

use crate::pcap::{MAGIC_MICROS, MAGIC_NANOS};
use crate::pcapng::{BT_EPB, BT_IDB, BT_SHB, BT_SPB, BYTE_ORDER_MAGIC, OPT_IF_TSRESOL};
use crate::reader::Format;
use std::io::{self, Write};

fn u16b(be: bool, v: u16) -> [u8; 2] {
    if be {
        v.to_be_bytes()
    } else {
        v.to_le_bytes()
    }
}

fn u32b(be: bool, v: u32) -> [u8; 4] {
    if be {
        v.to_be_bytes()
    } else {
        v.to_le_bytes()
    }
}

pub fn write_pcap_header(w: &mut dyn Write, be: bool, nanos: bool, snaplen: u32, linktype: u32) -> io::Result<()> {
    w.write_all(&u32b(be, if nanos { MAGIC_NANOS } else { MAGIC_MICROS }))?;
    w.write_all(&u16b(be, 2))?;
    w.write_all(&u16b(be, 4))?;
    w.write_all(&[0; 8])?;
    w.write_all(&u32b(be, snaplen))?;
    w.write_all(&u32b(be, linktype))
}

pub fn write_pcap_record(
    w: &mut dyn Write,
    be: bool,
    nanos: bool,
    ts_ns: u64,
    orig_len: u32,
    data: &[u8],
) -> io::Result<()> {
    let frac = ts_ns % 1_000_000_000;
    let frac = if nanos { frac } else { frac / 1_000 };
    w.write_all(&u32b(be, (ts_ns / 1_000_000_000) as u32))?;
    w.write_all(&u32b(be, frac as u32))?;
    w.write_all(&u32b(be, data.len() as u32))?;
    w.write_all(&u32b(be, orig_len))?;
    w.write_all(data)
}

/// Write a generic pcapng block; `body` is zero-padded to 4 bytes.
pub fn write_ng_block(w: &mut dyn Write, be: bool, ty: u32, body: &[u8]) -> io::Result<()> {
    let pad = (4 - body.len() % 4) % 4;
    let total = (12 + body.len() + pad) as u32;
    w.write_all(&u32b(be, ty))?;
    w.write_all(&u32b(be, total))?;
    w.write_all(body)?;
    w.write_all(&[0; 3][..pad])?;
    w.write_all(&u32b(be, total))
}

pub fn write_ng_shb(w: &mut dyn Write, be: bool) -> io::Result<()> {
    let mut b = u32b(be, BYTE_ORDER_MAGIC).to_vec();
    b.extend_from_slice(&u16b(be, 1));
    b.extend_from_slice(&u16b(be, 0));
    b.extend_from_slice(&[0xff; 8]); // section length: unknown
    write_ng_block(w, be, BT_SHB, &b)
}

pub fn write_ng_idb(w: &mut dyn Write, be: bool, linktype: u16, snaplen: u32, tsresol: Option<u8>) -> io::Result<()> {
    let mut b = u16b(be, linktype).to_vec();
    b.extend_from_slice(&[0, 0]);
    b.extend_from_slice(&u32b(be, snaplen));
    if let Some(r) = tsresol {
        b.extend_from_slice(&u16b(be, OPT_IF_TSRESOL));
        b.extend_from_slice(&u16b(be, 1));
        b.extend_from_slice(&[r, 0, 0, 0]);
        b.extend_from_slice(&[0; 4]);
    }
    write_ng_block(w, be, BT_IDB, &b)
}

pub fn write_ng_epb(w: &mut dyn Write, be: bool, if_id: u32, ticks: u64, orig_len: u32, data: &[u8]) -> io::Result<()> {
    let mut b = Vec::with_capacity(20 + data.len());
    b.extend_from_slice(&u32b(be, if_id));
    b.extend_from_slice(&u32b(be, (ticks >> 32) as u32));
    b.extend_from_slice(&u32b(be, ticks as u32));
    b.extend_from_slice(&u32b(be, data.len() as u32));
    b.extend_from_slice(&u32b(be, orig_len));
    b.extend_from_slice(data);
    write_ng_block(w, be, BT_EPB, &b)
}

pub fn write_ng_spb(w: &mut dyn Write, be: bool, orig_len: u32, data: &[u8]) -> io::Result<()> {
    let mut b = u32b(be, orig_len).to_vec();
    b.extend_from_slice(data);
    write_ng_block(w, be, BT_SPB, &b)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SynthOptions {
    pub packets: u64,
    /// Number of distinct 5-tuples (0 is treated as 1).
    pub flows: u32,
    pub seed: u64,
    pub start_ns: u64,
    pub interval_ns: u64,
    pub format: Format,
    /// Nanosecond timestamps (pcap ns magic / pcapng if_tsresol=9).
    pub nanos: bool,
    pub big_endian: bool,
}

impl Default for SynthOptions {
    fn default() -> Self {
        SynthOptions {
            packets: 10_000,
            flows: 64,
            seed: 0x5eed,
            start_ns: 1_700_000_000_000_000_000,
            interval_ns: 1_000,
            format: Format::Pcap,
            nanos: false,
            big_endian: false,
        }
    }
}

/// xorshift64* PRNG: tiny, fast, deterministic.
#[derive(Clone, Copy, Debug)]
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(seed | 1)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
}

/// Build the Ethernet frame of packet `n` of flow `flow` with `payload` bytes.
pub fn frame(flow: u32, payload: usize, arp: bool) -> Vec<u8> {
    let mut f = vec![0x02, 0, 0, 0, 0, 1, 0x02, 0, 0, 0, 0, 2];
    if arp {
        f.extend_from_slice(&[0x08, 0x06]);
        f.extend_from_slice(&[0; 28]);
        return f;
    }
    let b = flow.to_be_bytes();
    let (sport, dport) = (
        1024 + (flow % 50_000) as u16,
        [80u16, 443, 53, 8080][(flow % 4) as usize],
    );
    let kind = flow % 16;
    if kind == 12 {
        f.extend_from_slice(&[0x81, 0x00, 0, (flow % 4000) as u8]);
    }
    let proto = match kind {
        13 => 1,
        k if k % 2 == 0 => 6,
        _ => 17,
    };
    let mut l4 = Vec::with_capacity(20 + payload);
    l4.extend_from_slice(&sport.to_be_bytes());
    l4.extend_from_slice(&dport.to_be_bytes());
    l4.resize(if proto == 6 { 20 } else { 8 }, 0);
    l4.resize(l4.len() + payload, 0xab);
    if kind == 10 || kind == 11 {
        f.extend_from_slice(&[0x86, 0xdd, 0x60, 0, 0, 0]);
        f.extend_from_slice(&(l4.len() as u16).to_be_bytes());
        f.extend_from_slice(&[proto, 64]);
        f.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, b[0], b[1], b[2], b[3]]);
        f.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    } else {
        let tot = (20 + l4.len()) as u16;
        f.extend_from_slice(&[0x08, 0x00, 0x45, 0]);
        f.extend_from_slice(&tot.to_be_bytes());
        f.extend_from_slice(&[0, 0, 0x40, 0, 64, proto, 0, 0]);
        f.extend_from_slice(&[10, b[1], b[2], b[3]]);
        f.extend_from_slice(&[192, 168, 0, 1]);
    }
    f.extend_from_slice(&l4);
    f
}

struct Counting<'a> {
    inner: &'a mut dyn Write,
    n: u64,
}

impl Write for Counting<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.n += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Write a deterministic synthetic capture; returns the bytes written.
pub fn generate(opts: &SynthOptions, w: &mut dyn Write) -> io::Result<u64> {
    let mut w = Counting { inner: w, n: 0 };
    let be = opts.big_endian;
    match opts.format {
        Format::Pcap => write_pcap_header(&mut w, be, opts.nanos, 65535, 1)?,
        Format::PcapNg => {
            write_ng_shb(&mut w, be)?;
            write_ng_idb(&mut w, be, 1, 65535, opts.nanos.then_some(9))?;
        }
    }
    let mut rng = Rng::new(opts.seed);
    let flows = u64::from(opts.flows.max(1));
    for i in 0..opts.packets {
        let r = rng.next_u64();
        let ts = opts.start_ns + i * opts.interval_ns;
        let f = frame(
            (r % flows) as u32,
            ((r >> 20) % 1400) as usize,
            (r >> 40).is_multiple_of(50),
        );
        match opts.format {
            Format::Pcap => write_pcap_record(&mut w, be, opts.nanos, ts, f.len() as u32, &f)?,
            Format::PcapNg => {
                let ticks = if opts.nanos { ts } else { ts / 1_000 };
                write_ng_epb(&mut w, be, 0, ticks, f.len() as u32, &f)?;
            }
        }
    }
    w.flush()?;
    Ok(w.n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::flow_key;

    #[test]
    fn frames_decode_to_their_flow() {
        let mut protos = std::collections::BTreeSet::new();
        for flow in 0..32u32 {
            let k = flow_key(1, &frame(flow, 10, false)).unwrap();
            protos.insert((k.proto, k.src.is_ipv6()));
            assert_eq!(k, flow_key(1, &frame(flow, 900, false)).unwrap());
        }
        assert_eq!(protos.len(), 5); // tcp4, udp4, icmp4, tcp6, udp6
        assert_eq!(flow_key(1, &frame(3, 10, true)), None);
    }

    #[test]
    fn generate_is_deterministic_and_counts_bytes() {
        for format in [Format::Pcap, Format::PcapNg] {
            for (nanos, big_endian) in [(false, false), (true, true)] {
                let o = SynthOptions {
                    packets: 200,
                    format,
                    nanos,
                    big_endian,
                    ..SynthOptions::default()
                };
                let mut a = Vec::new();
                let n = generate(&o, &mut a).unwrap();
                assert_eq!(n, a.len() as u64);
                let mut b = Vec::new();
                generate(&o, &mut b).unwrap();
                assert_eq!(a, b);
            }
        }
        let zero = SynthOptions {
            packets: 3,
            flows: 0,
            ..SynthOptions::default()
        };
        assert!(generate(&zero, &mut Vec::new()).unwrap() > 24);
    }

    struct Fail(usize);
    impl Write for Fail {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            if self.0 == 0 {
                return Err(io::Error::other("full"));
            }
            self.0 -= 1;
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            match self.0 {
                0 => Err(io::Error::other("flush")),
                _ => Ok(()),
            }
        }
    }

    #[test]
    fn write_errors_propagate_from_every_step() {
        for format in [Format::Pcap, Format::PcapNg] {
            let o = SynthOptions {
                packets: 2,
                format,
                ..SynthOptions::default()
            };
            let total = {
                let mut v = Vec::new();
                generate(&o, &mut v).unwrap();
                let mut probe = Fail(usize::MAX);
                generate(&o, &mut probe).unwrap();
                usize::MAX - probe.0
            };
            for k in 0..=total {
                assert!(generate(&o, &mut Fail(k)).is_err());
            }
        }
        let mut f = Fail(0);
        assert!(write_ng_idb(&mut f, false, 1, 0, Some(9)).is_err());
        assert!(write_ng_spb(&mut f, false, 1, b"x").is_err());
    }
}
