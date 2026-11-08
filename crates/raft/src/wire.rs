//! Wire format of [`Message`]: what a transport puts on a stream.
//!
//! A message is one CRC-framed record, the same framing as flashkv's logs
//! (`masked crc32c(len ++ payload): u32le | len: u32le | payload`), so a bit
//! flipped in transit, a truncated stream and garbage are all detected, and
//! the receiver never has to trust a length before the data has arrived. The
//! payload, all integers little-endian:
//!
//! ```text
//! version u8 | type u8 | flags u8 (1: vote granted, 2: success)
//! from, to, term, last log index, last log term, commit index,
//! match index, leader last index, read context, Lamport clock: u64 each
//! entry count (varint), then per entry: index u64, term u64, kind u8, data (len-prefixed)
//! snapshot flag u8, then if 1: index u64, term u64, voters (len-prefixed), data (len-prefixed)
//! ```
//!
//! A snapshot travels in one message, so frames can be as large as a
//! snapshot; [`read_frame`] takes the largest size it accepts.

use crate::error::{Error, Result};
use crate::log::{decode_voters, encode_voters, EntryKind, LogEntry};
use crate::message::{Message, MsgType};
use crate::storage::Snapshot;
use flashkv::codec::Decoder;
use flashkv::crc::masked_crc;
use flashkv::log::{frame, HEADER};
use flashkv::varint::{put_len_prefixed, put_uvarint64};
use std::io::{self, Read};
use std::sync::Arc;

pub const VERSION: u8 = 1;

/// A frame size no sane cluster exceeds: 1 GiB.
pub const MAX_FRAME: usize = 1 << 30;

const VOTE_GRANTED: u8 = 1;
const SUCCESS: u8 = 2;

fn type_code(t: MsgType) -> u8 {
    match t {
        MsgType::RequestVote => 0,
        MsgType::RequestVoteReply => 1,
        MsgType::AppendEntries => 2,
        MsgType::AppendEntriesReply => 3,
        MsgType::PreVote => 4,
        MsgType::PreVoteReply => 5,
        MsgType::InstallSnapshot => 6,
        MsgType::InstallSnapshotReply => 7,
    }
}

fn type_of(code: u8) -> Option<MsgType> {
    Some(match code {
        0 => MsgType::RequestVote,
        1 => MsgType::RequestVoteReply,
        2 => MsgType::AppendEntries,
        3 => MsgType::AppendEntriesReply,
        4 => MsgType::PreVote,
        5 => MsgType::PreVoteReply,
        6 => MsgType::InstallSnapshot,
        7 => MsgType::InstallSnapshotReply,
        _ => return None,
    })
}

/// The framed bytes of `m`, ready to write to a stream.
pub fn encode(m: &Message) -> Vec<u8> {
    let mut p = vec![VERSION, type_code(m.msg_type)];
    p.push((u8::from(m.vote_granted) * VOTE_GRANTED) | (u8::from(m.success) * SUCCESS));
    for v in [
        m.from,
        m.to,
        m.term,
        m.last_log_index,
        m.last_log_term,
        m.commit_index,
        m.match_index,
        m.leader_last_index,
        m.read_ctx,
        m.lc,
    ] {
        p.extend_from_slice(&v.to_le_bytes());
    }
    put_uvarint64(&mut p, m.entries.len() as u64);
    for e in &m.entries {
        p.extend_from_slice(&e.index.to_le_bytes());
        p.extend_from_slice(&e.term.to_le_bytes());
        p.push(e.kind as u8);
        put_len_prefixed(&mut p, &e.data);
    }
    p.push(u8::from(m.snapshot.is_some()));
    if let Some(s) = &m.snapshot {
        p.extend_from_slice(&s.index.to_le_bytes());
        p.extend_from_slice(&s.term.to_le_bytes());
        put_len_prefixed(&mut p, &encode_voters(&s.voters));
        put_len_prefixed(&mut p, &s.data);
    }
    let mut out = Vec::with_capacity(p.len() + HEADER);
    frame(&mut out, &p);
    out
}

/// The message in a frame's `payload`, as [`read_frame`] returns it. Never
/// panics, whatever the bytes.
pub fn decode(payload: &[u8]) -> Result<Message> {
    let bad = Error::BadMessage;
    let mut d = Decoder::new(payload);
    if d.u8() != VERSION {
        return Err(bad("unknown version"));
    }
    let msg_type = type_of(d.u8()).ok_or(bad("unknown message type"))?;
    let flags = d.u8();
    if flags & !(VOTE_GRANTED | SUCCESS) != 0 {
        return Err(bad("unknown flags"));
    }
    let mut fields = [0u64; 10];
    fields.iter_mut().for_each(|f| *f = d.u64());
    let [from, to, term, last_log_index, last_log_term, commit_index, match_index, leader_last_index, read_ctx, lc] =
        fields;
    // Every entry takes at least 18 bytes: a corrupt count cannot spin.
    let count = d.varint().min(d.remaining() as u64);
    let mut entries = Vec::new();
    for _ in 0..count {
        let (index, term) = (d.u64(), d.u64());
        let kind = match d.u8() {
            0 => EntryKind::Normal,
            1 => EntryKind::Config,
            _ => return Err(bad("unknown entry kind")),
        };
        entries.push(LogEntry {
            index,
            term,
            kind,
            data: d.lp().to_vec(),
        });
    }
    let snapshot = match d.u8() {
        0 => None,
        1 => {
            let (index, term) = (d.u64(), d.u64());
            let voters = d.lp();
            let voters = match voters.is_empty() {
                true => Vec::new(),
                false => decode_voters(voters).ok_or(bad("snapshot voters"))?,
            };
            let data = d.lp().to_vec();
            Some(Arc::new(Snapshot {
                index,
                term,
                voters,
                data,
            }))
        }
        _ => return Err(bad("unknown snapshot flag")),
    };
    if d.finish("message").is_err() | (d.remaining() != 0) {
        return Err(bad("truncated or trailing bytes"));
    }
    Ok(Message {
        msg_type,
        from,
        to,
        term,
        last_log_index,
        last_log_term,
        entries,
        commit_index,
        vote_granted: flags & VOTE_GRANTED != 0,
        match_index,
        success: flags & SUCCESS != 0,
        leader_last_index,
        read_ctx,
        snapshot,
        lc,
    })
}

/// Reads one frame from `r` and returns its payload: `Ok(None)` when the
/// stream ends between frames. An `Err` is an I/O error, a stream that ends
/// inside a frame, a frame longer than `max`, or a checksum mismatch; the
/// stream cannot be used after it. A lying length costs nothing: the payload
/// buffer grows only as data arrives.
pub fn read_frame(r: &mut dyn Read, max: usize) -> io::Result<Option<Vec<u8>>> {
    let mut head = [0u8; HEADER];
    let mut got = 0;
    while got < HEADER {
        match r.read(&mut head[got..])? {
            0 if got == 0 => return Ok(None),
            0 => return Err(io::ErrorKind::UnexpectedEof.into()),
            n => got += n,
        }
    }
    let crc = u32::from_le_bytes([head[0], head[1], head[2], head[3]]);
    let len = u32::from_le_bytes([head[4], head[5], head[6], head[7]]) as usize;
    if len > max {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame too large"));
    }
    let mut payload = Vec::new();
    Read::take(r, len as u64).read_to_end(&mut payload)?;
    if payload.len() < len {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    if masked_crc(&head[4..], &payload) != crc {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame checksum mismatch"));
    }
    Ok(Some(payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One message of every type, with every field in use somewhere.
    fn samples() -> Vec<Message> {
        let snapshot = Arc::new(Snapshot {
            index: 9,
            term: 3,
            voters: vec![1, 2, 5],
            data: b"state".to_vec(),
        });
        let mut append = Message::append_entries(
            1,
            2,
            4,
            7,
            3,
            vec![
                LogEntry::new(8, 4, b"payload".to_vec()),
                LogEntry::config(9, 4, &[1, 2, 3]),
                LogEntry::new(10, 4, Vec::new()),
            ],
            8,
        );
        (append.leader_last_index, append.read_ctx, append.lc) = (10, 77, u64::MAX);
        let mut snap = Message::install_snapshot(1, 2, 4, snapshot, 9);
        snap.leader_last_index = 12;
        let mut reply = Message::append_entries_reply(2, 1, 4, true, 10);
        reply.read_ctx = 77;
        let mut empty_voters = Message::install_snapshot(1, 2, 4, Arc::new(Snapshot::default()), 0);
        empty_voters.lc = 5;
        vec![
            Message::request_vote(1, 2, 5, 10, 4),
            Message::request_vote_reply(2, 1, 5, true),
            Message::request_vote_reply(2, 1, 5, false),
            append,
            reply,
            Message::append_entries_reply(2, 1, 4, false, 3),
            Message::pre_vote(1, 2, 6, 10, 4),
            Message::pre_vote_reply(2, 1, 6, true),
            snap,
            Message::install_snapshot_reply(2, 1, 4, true, 9),
            empty_voters,
        ]
    }

    /// The payload of an encoded message.
    fn payload(m: &Message) -> Vec<u8> {
        let framed = encode(m);
        read_frame(&mut &framed[..], MAX_FRAME).unwrap().unwrap()
    }

    #[test]
    fn every_message_roundtrips() {
        for m in samples() {
            assert_eq!(decode(&payload(&m)).unwrap(), m, "{m:?}");
        }
        // Frames follow each other on a stream, which then ends cleanly.
        let mut stream = Vec::new();
        for m in samples() {
            stream.extend(encode(&m));
        }
        let mut r = &stream[..];
        for m in samples() {
            assert_eq!(decode(&read_frame(&mut r, MAX_FRAME).unwrap().unwrap()).unwrap(), m);
        }
        assert_eq!(read_frame(&mut r, MAX_FRAME).unwrap(), None);
    }

    #[test]
    fn any_prefix_of_a_message_is_an_error_not_a_panic() {
        for m in samples() {
            let p = payload(&m);
            let len = p.len();
            for n in 0..len {
                assert!(decode(&p[..n]).is_err(), "{n} of {len} bytes of {m:?}");
            }
            let mut long = p.clone();
            long.push(0);
            assert_eq!(decode(&long), Err(Error::BadMessage("truncated or trailing bytes")));
        }
    }

    #[test]
    fn malformed_payloads_are_named() {
        let good = payload(&samples()[3]);
        let with = |at: usize, v: u8| {
            let mut p = good.clone();
            p[at] = v;
            decode(&p)
        };
        assert_eq!(with(0, 2), Err(Error::BadMessage("unknown version")));
        assert_eq!(with(1, 8), Err(Error::BadMessage("unknown message type")));
        assert_eq!(with(2, 4), Err(Error::BadMessage("unknown flags")));
        // The first entry's kind byte follows the header, the entry count
        // (1 byte) and the entry's index and term.
        let kind = 3 + 10 * 8 + 1 + 16;
        assert_eq!(good[kind], 0);
        assert_eq!(with(kind, 2), Err(Error::BadMessage("unknown entry kind")));
        // The snapshot flag is the last byte of a message without one.
        let last = good.len() - 1;
        assert_eq!(with(last, 2), Err(Error::BadMessage("unknown snapshot flag")));
        // A snapshot with a voter list that is not one.
        let snap = payload(&samples()[8]);
        let voters_at = snap.len() - b"state".len() - 1 - 3 * 8 - 1;
        assert_eq!(snap[voters_at], 24, "length of the voter list");
        let mut p = snap.clone();
        p[voters_at + 1..voters_at + 9].copy_from_slice(&9u64.to_le_bytes());
        assert_eq!(decode(&p), Err(Error::BadMessage("snapshot voters")));
        // A count that promises more entries than there are bytes.
        let mut p = payload(&Message::request_vote(1, 2, 3, 4, 5));
        p[3 + 10 * 8] = 0x7f;
        assert!(decode(&p).is_err());
    }

    #[test]
    fn a_bit_flip_anywhere_in_a_frame_is_detected() {
        for m in samples() {
            let framed = encode(&m);
            for bit in 0..framed.len() * 8 {
                let mut f = framed.clone();
                f[bit / 8] ^= 1 << (bit % 8);
                assert!(read_frame(&mut &f[..], MAX_FRAME).is_err(), "bit {bit} of {m:?}");
            }
        }
    }

    #[test]
    fn frames_are_bounded_and_may_not_be_cut_short() {
        let framed = encode(&samples()[3]);
        let n = framed.len() - HEADER;
        // Too large for the limit: refused before the data is read.
        let err = read_frame(&mut &framed[..], n - 1).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(read_frame(&mut &framed[..], n).unwrap().is_some());
        // An empty stream is a clean end; any cut inside a frame is not.
        assert_eq!(read_frame(&mut &[][..], MAX_FRAME).unwrap(), None);
        for cut in 1..framed.len() {
            let err = read_frame(&mut &framed[..cut], MAX_FRAME).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof, "cut at {cut}");
        }
        // A length that lies (4 GiB, and only a few bytes follow) costs nothing.
        let mut lie = framed.clone();
        lie[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(read_frame(&mut &lie[..], MAX_FRAME).is_err());
        // Reading in small pieces gives the same result.
        struct Dribble<'a>(&'a [u8]);
        impl Read for Dribble<'_> {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                let n = self.0.len().min(buf.len()).min(3);
                buf[..n].copy_from_slice(&self.0[..n]);
                self.0 = &self.0[n..];
                Ok(n)
            }
        }
        let got = read_frame(&mut Dribble(&framed), MAX_FRAME).unwrap().unwrap();
        assert_eq!(decode(&got).unwrap(), samples()[3]);
        // Errors of the stream itself surface.
        struct Broken;
        impl Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("reset"))
            }
        }
        assert_eq!(read_frame(&mut Broken, MAX_FRAME).unwrap_err().to_string(), "reset");
        // ... also in the middle of a frame, after its header.
        struct BreaksAfterHeader(Vec<u8>);
        impl Read for BreaksAfterHeader {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if self.0.is_empty() {
                    return Err(io::Error::other("reset"));
                }
                let n = self.0.len().min(buf.len());
                buf[..n].copy_from_slice(&self.0[..n]);
                self.0.drain(..n);
                Ok(n)
            }
        }
        let torn = BreaksAfterHeader(framed[..HEADER + 2].to_vec());
        assert_eq!(read_frame(&mut { torn }, MAX_FRAME).unwrap_err().to_string(), "reset");
    }

    #[test]
    fn type_codes_roundtrip() {
        for code in 0..8 {
            assert_eq!(type_code(type_of(code).unwrap()), code);
        }
        assert_eq!(type_of(8), None);
    }
}
