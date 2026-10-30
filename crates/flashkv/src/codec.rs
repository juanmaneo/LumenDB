//! Bounds-checked decoding with a *sticky* error flag.
//!
//! Every accessor returns a neutral value (0 / empty slice) once the input is
//! exhausted and remembers the failure; the caller checks [`Decoder::finish`]
//! once at the end. Corrupt input therefore can never panic or read out of
//! bounds, and decoders stay branch-light (one error check per structure).

use crate::error::{Error, Result};
use crate::varint::decode_uvarint64;

pub struct Decoder<'a> {
    buf: &'a [u8],
    pos: usize,
    bad: bool,
}

impl<'a> Decoder<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Decoder {
            buf,
            pos: 0,
            bad: false,
        }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// True when all input was consumed without error.
    pub fn is_done(&self) -> bool {
        self.bad || self.pos == self.buf.len()
    }

    pub fn bytes(&mut self, n: usize) -> &'a [u8] {
        if self.bad || n > self.remaining() {
            self.bad = true;
            return &[];
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        s
    }

    pub fn u8(&mut self) -> u8 {
        self.bytes(1).first().copied().unwrap_or(0)
    }

    pub fn u64(&mut self) -> u64 {
        let s = self.bytes(8);
        let mut a = [0u8; 8];
        a[..s.len()].copy_from_slice(s);
        u64::from_le_bytes(a)
    }

    pub fn varint(&mut self) -> u64 {
        match decode_uvarint64(&self.buf[self.pos..]) {
            Ok((v, n)) if !self.bad => {
                self.pos += n;
                v
            }
            _ => {
                self.bad = true;
                0
            }
        }
    }

    /// Varint length followed by that many bytes.
    pub fn lp(&mut self) -> &'a [u8] {
        let n = self.varint();
        self.bytes(usize::try_from(n).unwrap_or(usize::MAX))
    }

    /// `Ok(())` if nothing failed, else a corruption error naming `what`.
    pub fn finish(&self, what: &str) -> Result<()> {
        if self.bad {
            return Err(Error::corruption(format!("truncated or malformed {what}")));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::varint::{put_len_prefixed, put_uvarint64};

    #[test]
    fn decodes_values_in_order() {
        let mut b = vec![7u8];
        b.extend_from_slice(&42u64.to_le_bytes());
        put_uvarint64(&mut b, 300);
        put_len_prefixed(&mut b, b"key");
        let mut d = Decoder::new(&b);
        assert_eq!(d.u8(), 7);
        assert_eq!(d.u64(), 42);
        assert_eq!(d.varint(), 300);
        assert_eq!(d.lp(), b"key");
        assert!(d.is_done());
        assert_eq!(d.remaining(), 0);
        d.finish("x").unwrap();
    }

    #[test]
    fn errors_are_sticky() {
        let mut d = Decoder::new(&[1, 2]);
        assert_eq!(d.u64(), 0);
        assert!(d.is_done());
        assert_eq!(d.u8(), 0);
        assert_eq!(d.varint(), 0);
        assert!(d.lp().is_empty());
        assert!(d.finish("thing").unwrap_err().to_string().contains("thing"));
        let mut d = Decoder::new(&[0x80]);
        assert_eq!(d.varint(), 0);
        d.finish("v").unwrap_err();
        let mut d = Decoder::new(&[5, 1]);
        assert!(d.lp().is_empty());
        d.finish("lp").unwrap_err();
        let d = Decoder::new(&[1]);
        assert!(!d.is_done());
    }
}
