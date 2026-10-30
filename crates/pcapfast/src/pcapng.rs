//! pcapng: Section Header, Interface Description, Enhanced and Simple Packet
//! blocks (others skipped by length), both byte orders, `if_tsresol`.
//!
//! Parallelism: [`scan`] walks block *headers only* (jumping by
//! `block_total_length`) and records cut points together with the parser
//! state ([`NgState`]: byte order + interface table) valid there, so each
//! chunk can then be decoded independently and zero-copy.

use crate::error::{Error, Result};

pub const BT_SHB: u32 = 0x0a0d_0d0a;
pub const BT_IDB: u32 = 1;
pub const BT_SPB: u32 = 3;
pub const BT_EPB: u32 = 6;
pub const BYTE_ORDER_MAGIC: u32 = 0x1a2b_3c4d;
pub const OPT_IF_TSRESOL: u16 = 9;

/// Timestamp resolution of an interface, as ticks per second.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TsRes {
    units_per_sec: u64,
    /// Nanoseconds per tick when it is an integer (fast path), else 0.
    ns_per_tick: u64,
}

impl TsRes {
    pub const MICROS: TsRes = TsRes {
        units_per_sec: 1_000_000,
        ns_per_tick: 1_000,
    };

    /// Decode an `if_tsresol` option byte (`10^-v`, or `2^-v` if the MSB is set).
    pub fn from_option(v: u8) -> Option<TsRes> {
        let units = if v & 0x80 != 0 {
            1u64.checked_shl(u32::from(v & 0x7f))?
        } else {
            10u64.checked_pow(u32::from(v))?
        };
        let ns_per_tick = if 1_000_000_000 % units == 0 {
            1_000_000_000 / units
        } else {
            0
        };
        Some(TsRes {
            units_per_sec: units,
            ns_per_tick,
        })
    }

    pub fn units_per_sec(&self) -> u64 {
        self.units_per_sec
    }

    pub fn to_ns(&self, ticks: u64) -> u64 {
        if self.ns_per_tick != 0 {
            ticks.wrapping_mul(self.ns_per_tick)
        } else {
            (u128::from(ticks) * 1_000_000_000 / u128::from(self.units_per_sec)) as u64
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Interface {
    pub linktype: u32,
    pub snaplen: u32,
    pub tsres: TsRes,
}

/// Decoder state at a block boundary.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NgState {
    pub big_endian: bool,
    pub interfaces: Vec<Interface>,
}

impl NgState {
    fn u16_at(&self, b: &[u8], at: usize) -> u16 {
        let w = [b[at], b[at + 1]];
        if self.big_endian {
            u16::from_be_bytes(w)
        } else {
            u16::from_le_bytes(w)
        }
    }

    fn u32_at(&self, b: &[u8], at: usize) -> u32 {
        let w = [b[at], b[at + 1], b[at + 2], b[at + 3]];
        if self.big_endian {
            u32::from_be_bytes(w)
        } else {
            u32::from_le_bytes(w)
        }
    }
}

/// Result of parsing a byte range.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NgStats {
    pub blocks: u64,
    /// Offset where parsing stopped (a block boundary, or the torn block).
    pub end_offset: usize,
    /// Parsing stopped on an incomplete trailing block.
    pub torn: bool,
}

fn malformed(offset: usize, what: &'static str) -> Error {
    Error::Malformed {
        offset: offset as u64,
        what,
    }
}

enum Block<'a> {
    Full { ty: u32, body: &'a [u8], next: usize },
    End,
    Torn,
}

/// Locate the block at `off`, updating byte order first if it is an SHB.
fn block_at<'a>(buf: &'a [u8], off: usize, st: &mut NgState) -> Result<Block<'a>> {
    if off == buf.len() {
        return Ok(Block::End);
    }
    let Some(h) = buf.get(off..off + 8) else {
        return Ok(Block::Torn);
    };
    let ty = st.u32_at(h, 0);
    if ty == BT_SHB {
        let Some(bom) = buf.get(off + 8..off + 12) else {
            return Ok(Block::Torn);
        };
        let le = u32::from_le_bytes([bom[0], bom[1], bom[2], bom[3]]);
        st.big_endian = match le {
            BYTE_ORDER_MAGIC => false,
            m if m == BYTE_ORDER_MAGIC.swap_bytes() => true,
            _ => return Err(malformed(off, "bad pcapng byte-order magic")),
        };
    }
    let len = st.u32_at(h, 4) as usize;
    if len < 12 || !len.is_multiple_of(4) {
        return Err(malformed(off, "bad pcapng block length"));
    }
    let Some(block) = buf.get(off..off + len) else {
        return Ok(Block::Torn);
    };
    if st.u32_at(block, len - 4) != len as u32 {
        return Err(malformed(off, "pcapng trailing block length mismatch"));
    }
    Ok(Block::Full {
        ty,
        body: &block[8..len - 4],
        next: off + len,
    })
}

/// Apply a structural block (SHB / IDB) to the state.
fn apply(ty: u32, body: &[u8], off: usize, st: &mut NgState) -> Result<()> {
    match ty {
        BT_SHB => st.interfaces.clear(),
        BT_IDB => {
            if body.len() < 8 {
                return Err(malformed(off, "pcapng IDB too short"));
            }
            let mut iface = Interface {
                linktype: u32::from(st.u16_at(body, 0)),
                snaplen: st.u32_at(body, 4),
                tsres: TsRes::MICROS,
            };
            let mut p = 8;
            while p + 4 <= body.len() {
                let code = st.u16_at(body, p);
                let olen = usize::from(st.u16_at(body, p + 2));
                let val = body
                    .get(p + 4..p + 4 + olen)
                    .ok_or(malformed(off, "pcapng option overflows IDB"))?;
                if code == 0 {
                    break;
                }
                if code == OPT_IF_TSRESOL && olen == 1 {
                    iface.tsres = TsRes::from_option(val[0]).ok_or(malformed(off, "if_tsresol out of range"))?;
                }
                p += 4 + olen.div_ceil(4) * 4;
            }
            st.interfaces.push(iface);
        }
        _ => {}
    }
    Ok(())
}

fn iface(st: &NgState, id: usize, off: usize) -> Result<&Interface> {
    st.interfaces
        .get(id)
        .ok_or(malformed(off, "pcapng packet references unknown interface"))
}

/// Parse all blocks starting in `[start, end)` with initial state `st`,
/// calling `f(linktype, ts_ns, orig_len, data)` per packet.
pub fn parse_range(
    buf: &[u8],
    start: usize,
    end: usize,
    mut st: NgState,
    f: &mut crate::packet::PacketSink<'_>,
) -> Result<NgStats> {
    let mut stats = NgStats {
        end_offset: start,
        ..NgStats::default()
    };
    let mut off = start;
    while off < end {
        let (ty, body, next) = match block_at(buf, off, &mut st)? {
            Block::Full { ty, body, next } => (ty, body, next),
            // `End` cannot happen here (off < end <= len); fold it with Torn.
            Block::Torn | Block::End => {
                stats.torn = true;
                break;
            }
        };
        match ty {
            BT_EPB => {
                if body.len() < 20 {
                    return Err(malformed(off, "pcapng EPB too short"));
                }
                let ifc = iface(&st, st.u32_at(body, 0) as usize, off)?;
                let ticks = (u64::from(st.u32_at(body, 4)) << 32) | u64::from(st.u32_at(body, 8));
                let caplen = st.u32_at(body, 12) as usize;
                let data = body
                    .get(20..20 + caplen)
                    .ok_or(malformed(off, "pcapng EPB caplen overflows block"))?;
                f(ifc.linktype, ifc.tsres.to_ns(ticks), st.u32_at(body, 16), data);
            }
            BT_SPB => {
                if body.len() < 4 {
                    return Err(malformed(off, "pcapng SPB too short"));
                }
                let ifc = iface(&st, 0, off)?;
                let orig = st.u32_at(body, 0);
                let mut cap = (body.len() - 4).min(orig as usize);
                if ifc.snaplen != 0 {
                    cap = cap.min(ifc.snaplen as usize);
                }
                f(ifc.linktype, 0, orig, &body[4..4 + cap]);
            }
            _ => apply(ty, body, off, &mut st)?,
        }
        stats.blocks += 1;
        off = next;
    }
    stats.end_offset = off;
    Ok(stats)
}

/// Header-only scan of the whole buffer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Scan {
    /// Chunk start offsets with the state valid there; the first is `(0, default)`.
    pub cuts: Vec<(usize, NgState)>,
    /// Offset where the scan stopped.
    pub end_offset: usize,
    pub torn: bool,
    /// State after the last complete block.
    pub state: NgState,
}

/// Walk block headers, emitting a cut roughly every `chunk` bytes.
pub fn scan(buf: &[u8], chunk: usize) -> Result<Scan> {
    let chunk = chunk.max(1);
    let mut st = NgState::default();
    let mut out = Scan {
        cuts: vec![(0, st.clone())],
        ..Scan::default()
    };
    let mut off = 0;
    let mut next_cut = chunk;
    loop {
        match block_at(buf, off, &mut st)? {
            Block::Full { ty, body, next } => {
                if off == 0 && ty != BT_SHB {
                    return Err(malformed(0, "pcapng must start with a section header"));
                }
                apply(ty, body, off, &mut st)?;
                off = next;
                if off >= next_cut && off < buf.len() {
                    out.cuts.push((off, st.clone()));
                    next_cut = off.saturating_add(chunk);
                }
            }
            Block::End => break,
            Block::Torn => {
                out.torn = true;
                break;
            }
        }
    }
    out.end_offset = off;
    out.state = st;
    Ok(out)
}

/// State valid at the first block boundary `>= upto` (or at the end).
pub fn prefix_state(buf: &[u8], upto: usize) -> Result<(usize, NgState)> {
    if upto == 0 {
        return Ok((0, NgState::default()));
    }
    let s = scan(buf, upto)?;
    Ok(s.cuts.into_iter().nth(1).unwrap_or((s.end_offset, s.state)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::synth::{write_ng_block, write_ng_epb, write_ng_idb, write_ng_shb, write_ng_spb};

    fn sample(be: bool) -> Vec<u8> {
        let mut v = Vec::new();
        write_ng_shb(&mut v, be).unwrap();
        write_ng_idb(&mut v, be, 1, 0, None).unwrap();
        write_ng_idb(&mut v, be, 101, 128, Some(9)).unwrap();
        write_ng_epb(&mut v, be, 0, 1_500_000, 60, b"hello").unwrap();
        write_ng_block(&mut v, be, 0x0bad, &[1, 2, 3, 4]).unwrap();
        write_ng_epb(&mut v, be, 1, 2_000_000_007, 7, b"abcdefg").unwrap();
        write_ng_spb(&mut v, be, 3, b"xyz").unwrap();
        v
    }

    type Pkt = (u32, u64, u32, Vec<u8>);

    fn sink(_: u32, _: u64, _: u32, _: &[u8]) {}

    fn collect(buf: &[u8]) -> (Vec<Pkt>, NgStats) {
        let mut out = Vec::new();
        let st = parse_range(buf, 0, buf.len(), NgState::default(), &mut |lt, ts, ol, d| {
            out.push((lt, ts, ol, d.to_vec()));
        })
        .unwrap();
        (out, st)
    }

    #[test]
    fn tsres_decoding() {
        assert_eq!(TsRes::from_option(6), Some(TsRes::MICROS));
        assert_eq!(TsRes::from_option(9).unwrap().to_ns(5), 5);
        assert_eq!(TsRes::from_option(3).unwrap().to_ns(5), 5_000_000);
        let p = TsRes::from_option(12).unwrap();
        assert_eq!((p.units_per_sec(), p.to_ns(5_000)), (1_000_000_000_000, 5));
        let b = TsRes::from_option(0x80 | 10).unwrap();
        assert_eq!(b.to_ns(1024), 1_000_000_000);
        assert_eq!(TsRes::from_option(0x80).unwrap().to_ns(2), 2_000_000_000);
        assert_eq!(TsRes::from_option(20), None);
        assert_eq!(TsRes::from_option(0x80 | 64), None);
    }

    #[test]
    fn parses_both_byte_orders() {
        for be in [false, true] {
            let v = sample(be);
            let (pkts, st) = collect(&v);
            assert_eq!(
                st,
                NgStats {
                    blocks: 7,
                    end_offset: v.len(),
                    torn: false
                }
            );
            assert_eq!(pkts[0], (1, 1_500_000_000, 60, b"hello".to_vec()));
            assert_eq!(pkts[1], (101, 2_000_000_007, 7, b"abcdefg".to_vec()));
            assert_eq!(pkts[2], (1, 0, 3, b"xyz".to_vec()));
        }
    }

    #[test]
    fn spb_respects_snaplen_and_new_sections_reset_state() {
        let mut v = Vec::new();
        write_ng_shb(&mut v, false).unwrap();
        write_ng_idb(&mut v, false, 1, 2, None).unwrap();
        write_ng_spb(&mut v, false, 10, b"abcd").unwrap();
        write_ng_shb(&mut v, true).unwrap();
        write_ng_idb(&mut v, true, 113, 0, Some(0x80 | 20)).unwrap();
        write_ng_epb(&mut v, true, 0, 1 << 20, 9, b"q").unwrap();
        let (pkts, _) = collect(&v);
        assert_eq!(pkts[0], (1, 0, 10, b"ab".to_vec()));
        assert_eq!(pkts[1], (113, 1_000_000_000, 9, b"q".to_vec()));
        // the second section forgot interface 1 of the first one
        let mut w = v.clone();
        write_ng_epb(&mut w, true, 1, 0, 1, b"z").unwrap();
        assert!(parse_range(&w, 0, w.len(), NgState::default(), &mut sink).is_err());
    }

    #[test]
    fn torn_tails_stop_cleanly() {
        let v = sample(false);
        let full = collect(&v).1;
        for cut in 1..v.len() {
            let r = parse_range(&v[..cut], 0, cut, NgState::default(), &mut sink);
            let st = r.unwrap();
            assert!(st.end_offset <= cut);
            assert_eq!(st.torn, st.end_offset < cut, "cut {cut}");
            assert!(st.blocks <= full.blocks);
        }
    }

    fn expect_err(v: &[u8], what: &str) {
        let e = parse_range(v, 0, v.len(), NgState::default(), &mut sink).unwrap_err();
        assert!(e.to_string().contains(what), "{e} vs {what}");
    }

    #[test]
    fn malformed_blocks() {
        let mut shb = Vec::new();
        write_ng_shb(&mut shb, false).unwrap();
        let mut bad_bom = shb.clone();
        bad_bom[8] = 0;
        expect_err(&bad_bom, "byte-order");
        let mut bad_len = shb.clone();
        bad_len[4] = 13;
        expect_err(&bad_len, "block length");
        let mut tiny_len = shb.clone();
        tiny_len[4..8].copy_from_slice(&8u32.to_le_bytes());
        expect_err(&tiny_len, "block length");
        let mut bad_trailer = shb.clone();
        let n = bad_trailer.len();
        bad_trailer[n - 4] ^= 0x40;
        expect_err(&bad_trailer, "trailing");
        let with = |ty: u32, body: &[u8]| {
            let mut v = shb.clone();
            write_ng_block(&mut v, false, ty, body).unwrap();
            v
        };
        expect_err(&with(BT_IDB, &[1, 0, 0, 0]), "IDB too short");
        let mut opt_over = vec![1, 0, 0, 0, 0, 0, 0, 0];
        opt_over.extend_from_slice(&[9, 0, 8, 0, 6, 0, 0, 0]);
        expect_err(&with(BT_IDB, &opt_over), "option overflows");
        let mut bad_res = vec![1, 0, 0, 0, 0, 0, 0, 0];
        bad_res.extend_from_slice(&[9, 0, 1, 0, 99, 0, 0, 0]);
        expect_err(&with(BT_IDB, &bad_res), "if_tsresol");
        expect_err(&with(BT_EPB, &[0; 16]), "EPB too short");
        expect_err(&with(BT_EPB, &[0; 20]), "unknown interface");
        expect_err(&with(BT_SPB, &[]), "SPB too short");
        expect_err(&with(BT_SPB, &[0; 4]), "unknown interface");
        let mut epb_over = shb.clone();
        write_ng_idb(&mut epb_over, false, 1, 0, None).unwrap();
        let mut body = vec![0u8; 20];
        body[12] = 200;
        write_ng_block(&mut epb_over, false, BT_EPB, &body).unwrap();
        expect_err(&epb_over, "caplen");
        // IDB options: unknown option skipped, end-of-options honoured, odd tsresol len ignored
        let mut opts = vec![1, 0, 0, 0, 0, 0, 0, 0];
        opts.extend_from_slice(&[2, 0, 3, 0, b'e', b't', b'h', 0]);
        opts.extend_from_slice(&[9, 0, 2, 0, 3, 3, 0, 0]);
        opts.extend_from_slice(&[0, 0, 0, 0]);
        opts.extend_from_slice(&[9, 0, 1, 0, 99, 0, 0, 0]);
        let mut st = NgState::default();
        apply(BT_IDB, &opts, 0, &mut st).unwrap();
        assert_eq!(st.interfaces[0].tsres, TsRes::MICROS);
    }

    #[test]
    fn scan_cuts_carry_state() {
        let v = sample(true);
        let s = scan(&v, 1).unwrap();
        assert_eq!(s.cuts.len(), 7);
        assert_eq!((s.end_offset, s.torn), (v.len(), false));
        // every cut parsed independently yields the same packets as one pass
        let mut pkts = Vec::new();
        for (i, (start, st)) in s.cuts.iter().enumerate() {
            let end = s.cuts.get(i + 1).map_or(v.len(), |c| c.0);
            let r = parse_range(&v, *start, end, st.clone(), &mut |lt, ts, ol, d| {
                pkts.push((lt, ts, ol, d.to_vec()))
            });
            assert_eq!(r.unwrap().end_offset, end);
        }
        assert_eq!(pkts, collect(&v).0);
        assert_eq!(scan(&v, 0).unwrap().cuts.len(), 7);
        assert_eq!(scan(&v, usize::MAX).unwrap().cuts.len(), 1);
        let torn = scan(&v[..v.len() - 2], 1).unwrap();
        assert!(torn.torn);
        let mut not_shb = Vec::new();
        write_ng_block(&mut not_shb, false, BT_IDB, &[0; 8]).unwrap();
        assert!(scan(&not_shb, 1).is_err());
        let mut bad_idb = Vec::new();
        write_ng_shb(&mut bad_idb, false).unwrap();
        write_ng_block(&mut bad_idb, false, BT_IDB, &[0; 4]).unwrap();
        assert!(scan(&bad_idb, 1).is_err());
    }

    #[test]
    fn prefix_state_at_offsets() {
        let v = sample(false);
        let (off, st) = prefix_state(&v, 0).unwrap();
        assert_eq!((off, st), (0, NgState::default()));
        let (off, st) = prefix_state(&v, 40).unwrap();
        assert!(off >= 40);
        assert_eq!(st.interfaces.len(), 1);
        let (off, st) = prefix_state(&v, v.len() + 10).unwrap();
        assert_eq!((off, st.interfaces.len()), (v.len(), 2));
        assert!(prefix_state(&[1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0], 4).is_err());
    }
}
