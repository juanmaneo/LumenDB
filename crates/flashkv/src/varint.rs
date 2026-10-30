//! LEB128 varints + length-prefixed strings (LevelDB coding.cc).

use crate::error::{Error, Result};

pub fn put_uvarint64(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

pub fn put_uvarint32(out: &mut Vec<u8>, v: u32) {
    put_uvarint64(out, v as u64);
}

pub const MAX_VARINT64_LEN: usize = 10;

pub fn decode_uvarint64(buf: &[u8]) -> Result<(u64, usize)> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    for (i, &b) in buf.iter().enumerate() {
        if shift >= 64 {
            return Err(Error::corruption("varint64 too long"));
        }
        result |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            return Ok((result, i + 1));
        }
        shift += 7;
    }
    Err(Error::corruption("truncated varint64"))
}

pub fn get_uvarint64(buf: &[u8]) -> Result<u64> {
    let (v, n) = decode_uvarint64(buf)?;
    if n != buf.len() {
        return Err(Error::corruption("trailing bytes after varint64"));
    }
    Ok(v)
}

pub fn put_len_prefixed(out: &mut Vec<u8>, data: &[u8]) {
    put_uvarint32(out, data.len() as u32);
    out.extend_from_slice(data);
}

pub fn get_len_prefixed(buf: &[u8]) -> Result<(Vec<u8>, usize)> {
    let (len, n) = decode_uvarint64(buf)?;
    let len = len as usize;
    if buf.len() < n + len {
        return Err(Error::corruption("truncated length-prefixed string"));
    }
    Ok((buf[n..n + len].to_vec(), n + len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_roundtrip() {
        for v in [0u64, 1, 127, 128, 300, u32::MAX as u64, u64::MAX] {
            let mut buf = Vec::new();
            put_uvarint64(&mut buf, v);
            assert!(buf.len() <= MAX_VARINT64_LEN);
            assert_eq!(decode_uvarint64(&buf).unwrap(), (v, buf.len()));
            assert_eq!(get_uvarint64(&buf).unwrap(), v);
        }
        let mut buf = Vec::new();
        put_uvarint64(&mut buf, 300);
        assert_eq!(buf, vec![0xac, 0x02]);
    }

    #[test]
    fn varint_errors() {
        assert!(decode_uvarint64(&[]).is_err());
        assert!(decode_uvarint64(&[0x80]).is_err());
        let mut buf = vec![0xffu8; 11];
        buf[10] = 0x01;
        assert!(decode_uvarint64(&buf).is_err());
        let mut buf = Vec::new();
        put_uvarint64(&mut buf, 1);
        buf.push(0);
        assert!(get_uvarint64(&buf).is_err());
        assert!(get_uvarint64(&[0x80]).is_err());
        assert!(get_len_prefixed(&[0x80]).is_err());
    }

    #[test]
    fn len_prefixed_roundtrip() {
        let mut buf = Vec::new();
        put_len_prefixed(&mut buf, b"hello");
        put_len_prefixed(&mut buf, b"");
        put_len_prefixed(&mut buf, &[7u8; 1000]);
        let (a, n) = get_len_prefixed(&buf).unwrap();
        assert_eq!(a, b"hello");
        let (b, n2) = get_len_prefixed(&buf[n..]).unwrap();
        assert!(b.is_empty());
        let (c, n3) = get_len_prefixed(&buf[n + n2..]).unwrap();
        assert_eq!(c.len(), 1000);
        assert_eq!(n + n2 + n3, buf.len());
        let mut bad = Vec::new();
        put_uvarint32(&mut bad, 100);
        bad.extend_from_slice(b"short");
        assert!(get_len_prefixed(&bad).is_err());
    }

    #[test]
    fn put_uvarint32_works() {
        let mut buf = Vec::new();
        put_uvarint32(&mut buf, 70000);
        assert_eq!(decode_uvarint64(&buf).unwrap().0, 70000);
    }
}
