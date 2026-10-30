//! Tiny LZ77 block compressor (LZ4-flavoured, varint-framed), pure Rust.
//!
//! Stream = sequence of `uvarint(lit_len) literals uvarint(match_len)
//! [uvarint(offset)]`; `match_len == 0` marks the final sequence. Matches are
//! found greedily through a 4-byte hash table, so compression is a single
//! linear pass and decompression is a tight copy loop.

use crate::error::{Error, Result};
use crate::varint::{decode_uvarint64, put_uvarint64};

const MIN_MATCH: usize = 4;
const HASH_BITS: u32 = 14;
const MAX_OFFSET: usize = 1 << 16;

fn hash4(b: &[u8]) -> usize {
    let v = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    (v.wrapping_mul(2_654_435_761) >> (32 - HASH_BITS)) as usize
}

/// Compress `input` into a new buffer.
pub fn compress(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() / 2 + 16);
    let mut table = vec![usize::MAX; 1 << HASH_BITS];
    let mut anchor = 0;
    let mut i = 0;
    while i + MIN_MATCH <= input.len() {
        let h = hash4(&input[i..]);
        let cand = table[h];
        table[h] = i;
        if cand != usize::MAX && i - cand < MAX_OFFSET && input[cand..cand + MIN_MATCH] == input[i..i + MIN_MATCH] {
            let mut len = MIN_MATCH;
            while i + len < input.len() && input[cand + len] == input[i + len] {
                len += 1;
            }
            put_uvarint64(&mut out, (i - anchor) as u64);
            out.extend_from_slice(&input[anchor..i]);
            put_uvarint64(&mut out, len as u64);
            put_uvarint64(&mut out, (i - cand) as u64);
            i += len;
            anchor = i;
        } else {
            i += 1;
        }
    }
    put_uvarint64(&mut out, (input.len() - anchor) as u64);
    out.extend_from_slice(&input[anchor..]);
    put_uvarint64(&mut out, 0);
    out
}

fn read_var(buf: &[u8], pos: &mut usize) -> Result<usize> {
    let (v, n) = decode_uvarint64(&buf[*pos..])?;
    *pos += n;
    Ok(v as usize)
}

/// Decompress a buffer produced by [`compress`]; every length and offset is
/// validated so corrupt input yields `Err`, never a panic.
pub fn decompress(input: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() * 2);
    let mut pos = 0;
    loop {
        let lit = read_var(input, &mut pos)?;
        if lit > input.len() - pos {
            return Err(Error::corruption("lz: literal run past end of input"));
        }
        out.extend_from_slice(&input[pos..pos + lit]);
        pos += lit;
        let mlen = read_var(input, &mut pos)?;
        if mlen == 0 {
            if pos != input.len() {
                return Err(Error::corruption("lz: trailing bytes after final sequence"));
            }
            return Ok(out);
        }
        let off = read_var(input, &mut pos)?;
        if off == 0 || off > out.len() {
            return Err(Error::corruption("lz: match offset out of range"));
        }
        let start = out.len() - off;
        for k in 0..mlen {
            let b = out[start + k];
            out.push(b);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(data: &[u8]) -> usize {
        let c = compress(data);
        assert_eq!(decompress(&c).unwrap(), data);
        c.len()
    }

    #[test]
    fn roundtrips_various_inputs() {
        assert!(roundtrip(b"") <= 2);
        roundtrip(b"abc");
        roundtrip(b"abcdabcdabcdabcdabcd");
        assert!(roundtrip(&vec![b'a'; 10_000]) < 100);
        let noise: Vec<u8> = (0..5000u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 11) as u8)
            .collect();
        roundtrip(&noise);
        let text = "key00001234 value-xxxxxxxx ".repeat(300);
        assert!(roundtrip(text.as_bytes()) < text.len() / 4);
        // matches further than MAX_OFFSET apart are not referenced
        let mut far = b"WXYZ".to_vec();
        far.extend(noise.iter().cycle().take(MAX_OFFSET + 10));
        far.extend_from_slice(b"WXYZ");
        roundtrip(&far);
    }

    #[test]
    fn rejects_corrupt_streams() {
        assert!(decompress(&[]).is_err());
        assert!(decompress(&[5, b'a']).is_err());
        assert!(decompress(&[1, b'a']).is_err());
        assert!(decompress(&[1, b'a', 4]).is_err());
        assert!(decompress(&[1, b'a', 4, 0]).is_err());
        assert!(decompress(&[1, b'a', 4, 2]).is_err());
        assert!(decompress(&[0, 0, 9]).is_err());
        assert_eq!(decompress(&[1, b'a', 4, 1, 0, 0]).unwrap(), b"aaaaa");
    }
}
