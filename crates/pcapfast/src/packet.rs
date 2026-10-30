//! Zero-copy L2 -> L4 decoding of a captured frame into a [`FlowKey`].
//! Every access is bounds-checked; garbage yields `None`, never a panic.
//! Frames cut short by the snap length still produce a key (ports 0).

use crate::flow::FlowKey;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Per-packet callback: `(linktype, ts_ns, orig_len, captured_bytes)`.
pub type PacketSink<'a> = dyn FnMut(u32, u64, u32, &[u8]) + 'a;

pub const LINKTYPE_NULL: u32 = 0;
pub const LINKTYPE_ETHERNET: u32 = 1;
pub const LINKTYPE_RAW: u32 = 101;
pub const LINKTYPE_LINUX_SLL: u32 = 113;
pub const LINKTYPE_IPV4: u32 = 228;
pub const LINKTYPE_IPV6: u32 = 229;

pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;
pub const ETHERTYPE_IPV6: u16 = 0x86dd;
pub const ETHERTYPE_VLAN: u16 = 0x8100;
pub const ETHERTYPE_QINQ: u16 = 0x88a8;
pub const ETHERTYPE_VLAN_9100: u16 = 0x9100;

pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;
pub const PROTO_ICMPV6: u8 = 58;
pub const PROTO_SCTP: u8 = 132;

/// Decode the flow key of a frame captured with link type `linktype`.
pub fn flow_key(linktype: u32, frame: &[u8]) -> Option<FlowKey> {
    match linktype {
        LINKTYPE_ETHERNET => ethernet(frame),
        LINKTYPE_RAW | LINKTYPE_IPV4 | LINKTYPE_IPV6 => ip(frame),
        LINKTYPE_LINUX_SLL => l3(be16(frame, 14)?, &frame[16..]),
        LINKTYPE_NULL => ip(frame.get(4..)?),
        _ => None,
    }
}

fn be16(b: &[u8], at: usize) -> Option<u16> {
    let s = b.get(at..at + 2)?;
    Some(u16::from_be_bytes([s[0], s[1]]))
}

fn ethernet(f: &[u8]) -> Option<FlowKey> {
    let mut ty = be16(f, 12)?;
    let mut off = 14;
    while matches!(ty, ETHERTYPE_VLAN | ETHERTYPE_QINQ | ETHERTYPE_VLAN_9100) {
        ty = be16(f, off + 2)?;
        off += 4;
    }
    l3(ty, &f[off..])
}

fn l3(ethertype: u16, p: &[u8]) -> Option<FlowKey> {
    match ethertype {
        ETHERTYPE_IPV4 => ipv4(p),
        ETHERTYPE_IPV6 => ipv6(p),
        _ => None,
    }
}

/// Decode a bare IP packet, dispatching on the version nibble.
pub fn ip(p: &[u8]) -> Option<FlowKey> {
    match p.first()? >> 4 {
        4 => ipv4(p),
        6 => ipv6(p),
        _ => None,
    }
}

/// Decode an IPv4 packet. Only the first fragment carries L4 ports.
pub fn ipv4(p: &[u8]) -> Option<FlowKey> {
    let h = p.get(..20)?;
    let ihl = usize::from(h[0] & 0x0f) * 4;
    if h[0] >> 4 != 4 || ihl < 20 {
        return None;
    }
    let src = IpAddr::V4(Ipv4Addr::new(h[12], h[13], h[14], h[15]));
    let dst = IpAddr::V4(Ipv4Addr::new(h[16], h[17], h[18], h[19]));
    let first_fragment = u16::from_be_bytes([h[6], h[7]]) & 0x1fff == 0;
    let l4 = if first_fragment { p.get(ihl..) } else { None };
    Some(key(src, dst, h[9], l4))
}

fn addr16(b: &[u8]) -> Ipv6Addr {
    let mut a = [0u8; 16];
    a.copy_from_slice(b);
    Ipv6Addr::from(a)
}

/// Decode an IPv6 packet, walking hop-by-hop / routing / fragment /
/// destination-options extension headers.
pub fn ipv6(p: &[u8]) -> Option<FlowKey> {
    let h = p.get(..40)?;
    if h[0] >> 4 != 6 {
        return None;
    }
    let src = IpAddr::V6(addr16(&h[8..24]));
    let dst = IpAddr::V6(addr16(&h[24..40]));
    let mut next = h[6];
    let mut off = 40;
    loop {
        match next {
            0 | 43 | 60 => {
                let e = p.get(off..off + 2)?;
                next = e[0];
                off += (usize::from(e[1]) + 1) * 8;
            }
            44 => {
                let e = p.get(off..off + 8)?;
                next = e[0];
                off += 8;
                if u16::from_be_bytes([e[2], e[3]]) >> 3 != 0 {
                    return Some(key(src, dst, next, None));
                }
            }
            _ => return Some(key(src, dst, next, p.get(off..))),
        }
    }
}

fn key(src: IpAddr, dst: IpAddr, proto: u8, l4: Option<&[u8]>) -> FlowKey {
    let (src_port, dst_port) = match (proto, l4) {
        (PROTO_TCP | PROTO_UDP | PROTO_SCTP, Some(b)) if b.len() >= 4 => {
            (u16::from_be_bytes([b[0], b[1]]), u16::from_be_bytes([b[2], b[3]]))
        }
        _ => (0, 0),
    };
    FlowKey {
        src,
        dst,
        src_port,
        dst_port,
        proto,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PORTS: [u8; 4] = [0x04, 0xd2, 0x00, 0x50]; // 1234 -> 80

    fn v4(proto: u8, frag: u16, l4: &[u8]) -> Vec<u8> {
        let f = frag.to_be_bytes();
        let mut p = vec![
            0x45, 0, 0, 0, 0, 0, f[0], f[1], 64, proto, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
        ];
        p.extend_from_slice(l4);
        p
    }

    fn v6(next: u8, rest: &[u8]) -> Vec<u8> {
        let mut p = vec![0x60, 0, 0, 0, 0, 0, next, 64];
        p.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        p.extend_from_slice(&Ipv6Addr::UNSPECIFIED.octets());
        p.extend_from_slice(rest);
        p
    }

    fn eth(tys: &[u16], payload: &[u8]) -> Vec<u8> {
        let mut f = vec![0u8; 12];
        for (i, t) in tys.iter().enumerate() {
            f.extend_from_slice(&t.to_be_bytes());
            if i + 1 < tys.len() {
                f.extend_from_slice(&[0, 1]); // VLAN TCI
            }
        }
        f.extend_from_slice(payload);
        f
    }

    fn ports(k: Option<FlowKey>) -> (u16, u16, u8) {
        let k = k.unwrap();
        (k.src_port, k.dst_port, k.proto)
    }

    #[test]
    fn ethernet_ipv4_variants() {
        let tcp = eth(&[ETHERTYPE_IPV4], &v4(PROTO_TCP, 0, &PORTS));
        assert_eq!(ports(flow_key(LINKTYPE_ETHERNET, &tcp)), (1234, 80, 6));
        let k = flow_key(LINKTYPE_ETHERNET, &tcp).unwrap();
        assert_eq!(k.src, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(k.dst, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        let udp = eth(&[ETHERTYPE_IPV4], &v4(PROTO_UDP, 0, &PORTS));
        assert_eq!(ports(flow_key(1, &udp)), (1234, 80, 17));
        let sctp = eth(&[ETHERTYPE_IPV4], &v4(PROTO_SCTP, 0, &PORTS));
        assert_eq!(ports(flow_key(1, &sctp)), (1234, 80, 132));
        let icmp = eth(&[ETHERTYPE_IPV4], &v4(PROTO_ICMP, 0, &PORTS));
        assert_eq!(ports(flow_key(1, &icmp)), (0, 0, 1));
        // first fragment (MF set, offset 0) keeps ports, later fragments don't
        let mf = eth(&[ETHERTYPE_IPV4], &v4(PROTO_TCP, 0x2000, &PORTS));
        assert_eq!(ports(flow_key(1, &mf)), (1234, 80, 6));
        let later = eth(&[ETHERTYPE_IPV4], &v4(PROTO_TCP, 0x2010, &PORTS));
        assert_eq!(ports(flow_key(1, &later)), (0, 0, 6));
        // snapped L4 / IHL past the end
        let short = eth(&[ETHERTYPE_IPV4], &v4(PROTO_TCP, 0, &[1, 2]));
        assert_eq!(ports(flow_key(1, &short)), (0, 0, 6));
        let mut long_ihl = v4(PROTO_TCP, 0, &[]);
        long_ihl[0] = 0x4f;
        assert_eq!(ports(ip(&long_ihl)), (0, 0, 6));
        let mut bad_ihl = v4(PROTO_TCP, 0, &PORTS);
        bad_ihl[0] = 0x44;
        assert_eq!(ip(&bad_ihl), None);
        // ethertype says IPv4 but the version nibble disagrees (both ways)
        assert_eq!(flow_key(1, &eth(&[ETHERTYPE_IPV4], &v6(PROTO_UDP, &PORTS))), None);
        assert_eq!(flow_key(1, &eth(&[ETHERTYPE_IPV6], &v4(PROTO_UDP, 0, &[0; 40]))), None);
    }

    #[test]
    fn vlan_stacks_and_non_ip() {
        let p = v4(PROTO_UDP, 0, &PORTS);
        for tags in [
            vec![ETHERTYPE_VLAN, ETHERTYPE_IPV4],
            vec![ETHERTYPE_QINQ, ETHERTYPE_VLAN, ETHERTYPE_IPV4],
            vec![ETHERTYPE_VLAN_9100, ETHERTYPE_IPV4],
        ] {
            assert_eq!(ports(flow_key(1, &eth(&tags, &p))), (1234, 80, 17));
        }
        assert_eq!(flow_key(1, &eth(&[ETHERTYPE_ARP], &[0; 28])), None);
        assert_eq!(flow_key(9999, &p), None);
    }

    #[test]
    fn ipv6_extension_headers() {
        assert_eq!(ports(ip(&v6(PROTO_UDP, &PORTS))), (1234, 80, 17));
        // hop-by-hop(0) -> routing(43, 16 bytes) -> dest-opts(60) -> tcp
        let mut ext = vec![43, 0, 0, 0, 0, 0, 0, 0];
        ext.extend_from_slice(&[60, 1]);
        ext.extend_from_slice(&[0; 14]);
        ext.extend_from_slice(&[PROTO_TCP, 0, 0, 0, 0, 0, 0, 0]);
        ext.extend_from_slice(&PORTS);
        assert_eq!(ports(ip(&v6(0, &ext))), (1234, 80, 6));
        // first fragment: ports visible; later fragment: not
        let mut first = vec![PROTO_UDP, 0, 0, 1, 0, 0, 0, 7];
        first.extend_from_slice(&PORTS);
        assert_eq!(ports(ip(&v6(44, &first))), (1234, 80, 17));
        let mut later = vec![PROTO_UDP, 0, 0, 0x10, 0, 0, 0, 7];
        later.extend_from_slice(&PORTS);
        assert_eq!(ports(ip(&v6(44, &later))), (0, 0, 17));
        assert_eq!(ports(ip(&v6(PROTO_ICMPV6, &[128, 0]))), (0, 0, 58));
        assert_eq!(ip(&[0x00; 40]), None);
    }

    #[test]
    fn other_link_types() {
        let p = v4(PROTO_TCP, 0, &PORTS);
        for lt in [LINKTYPE_RAW, LINKTYPE_IPV4, LINKTYPE_IPV6] {
            assert!(flow_key(lt, &p).is_some());
        }
        let mut sll = vec![0u8; 14];
        sll.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        sll.extend_from_slice(&p);
        assert_eq!(ports(flow_key(LINKTYPE_LINUX_SLL, &sll)), (1234, 80, 6));
        let mut null = vec![2, 0, 0, 0];
        null.extend_from_slice(&v6(PROTO_UDP, &PORTS));
        assert_eq!(ports(flow_key(LINKTYPE_NULL, &null)), (1234, 80, 17));
    }

    #[test]
    fn every_truncation_is_safe() {
        let mut ext = vec![44, 0, 0, 0, 0, 0, 0, 0];
        ext.extend_from_slice(&[PROTO_UDP, 0, 0, 0, 0, 0, 0, 1]);
        ext.extend_from_slice(&PORTS);
        let mut sll = vec![0u8; 14];
        sll.extend_from_slice(&ETHERTYPE_IPV6.to_be_bytes());
        sll.extend_from_slice(&v6(0, &ext));
        let mut null = vec![2, 0, 0, 0];
        null.extend_from_slice(&v4(PROTO_UDP, 0, &PORTS));
        let frames = [
            (
                LINKTYPE_ETHERNET,
                eth(&[ETHERTYPE_QINQ, ETHERTYPE_VLAN, ETHERTYPE_IPV4], &v4(6, 0, &PORTS)),
            ),
            (LINKTYPE_ETHERNET, eth(&[ETHERTYPE_IPV6], &v6(0, &ext))),
            (LINKTYPE_LINUX_SLL, sll),
            (LINKTYPE_NULL, null),
            (LINKTYPE_RAW, v6(0, &ext)),
        ];
        for (lt, f) in &frames {
            assert!(flow_key(*lt, f).is_some());
            for n in 0..f.len() {
                let _ = flow_key(*lt, &f[..n]);
            }
        }
        assert_eq!(ip(&[]), None);
    }
}
