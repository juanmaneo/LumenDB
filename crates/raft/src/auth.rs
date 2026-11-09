//! Authenticating TCP connections with a pre-shared secret, on `std` only.
//!
//! LumenDB has no TLS: that would take a dependency. This is what can be done
//! without one, and it is not the same thing. **It authenticates and protects
//! integrity; it does not encrypt.** Whoever can read the network sees the
//! data. Run it over a VPN or stunnel where that matters.
//!
//! What a connection gets from it:
//!
//! - **Both ends prove they know the secret** before anything else is
//!   accepted (a challenge-response with HMAC-SHA256), so a stranger cannot
//!   write, read or change the membership, and cannot pose as a node.
//!   Nonces are fresh for each connection, so a recorded handshake is of no
//!   use later.
//! - **Every byte after it is authenticated.** Each direction has a key of its
//!   own, derived from the secret and both nonces. Data travels in records
//!   `len u32le | payload | tag`, with
//!   `tag = HMAC-SHA256(key, sequence u64le | len u32le | payload)`. A record
//!   that was changed, replayed, reordered or reflected, or is missing from
//!   the middle of the stream, fails its check, and the connection ends.
//!   Cutting a connection short cannot be prevented (anyone on the path can
//!   reset a TCP connection): to the layers above it looks like any other
//!   lost connection.
//! - A *purpose* (`"raft"`, `"client"`) is mixed into every proof and key, so
//!   a handshake for one port is of no use on the other.
//!
//! What it does not do:
//!
//! - **Hide anything.** There is no confidentiality.
//! - **Tell the holders of the secret apart.** Every node and every client
//!   that has it is trusted with everything: a node can pose as any other,
//!   and a client can stop nodes and change the membership. A node's `from`
//!   field is as good as the secret.
//! - **Resist guessing offline.** The proofs are keyed with the secret, so
//!   someone who recorded a handshake can test guesses against it. Use a long
//!   random secret (`head -c 32 /dev/urandom | base64 > secret`), not a
//!   password, and keep the file readable by its owner only.
//! - **Stop a stranger from connecting.** A connection that has not
//!   authenticated costs a thread until the handshake times out.
//!
//! A [`Secret`] is at least [`MIN_SECRET`] bytes. Nonces come from std's
//! hasher keys (the operating system's randomness), a counter and the clock,
//! mixed through SHA-256.

use std::collections::hash_map::RandomState;
use std::fmt;
use std::hash::{BuildHasher, Hasher};
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The shortest secret accepted, in bytes.
pub const MIN_SECRET: usize = 16;

/// The most data one record carries, in bytes.
pub const MAX_RECORD: usize = 64 * 1024;

/// The size of a SHA-256 digest, an HMAC and a record's tag.
pub const TAG: usize = 32;

const NONCE: usize = 32;

// ----------------------------------------------------------------- SHA-256

/// FIPS 180-4: the first 32 bits of the fractional parts of the cube roots of
/// the first 64 primes.
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98,
    0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8,
    0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
    0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2,
];

/// The first 32 bits of the fractional parts of the square roots of the first
/// 8 primes.
const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    for (word, bytes) in w.iter_mut().zip(block.as_chunks::<4>().0) {
        *word = u32::from_be_bytes(*bytes);
    }
    for i in 16..64 {
        let (a, b) = (w[i - 15], w[i - 2]);
        let s0 = a.rotate_right(7) ^ a.rotate_right(18) ^ (a >> 3);
        let s1 = b.rotate_right(17) ^ b.rotate_right(19) ^ (b >> 10);
        w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for (k, wi) in K.iter().zip(w) {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let t1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(*k).wrapping_add(wi);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        (h, g, f, e) = (g, f, e, d.wrapping_add(t1));
        (d, c, b, a) = (c, b, a, t1.wrapping_add(t2));
    }
    for (s, v) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *s = s.wrapping_add(v);
    }
}

/// An incremental SHA-256.
struct Sha256 {
    state: [u32; 8],
    block: [u8; 64],
    /// Bytes in `block`, always below 64 between calls.
    filled: usize,
    /// Bytes hashed so far.
    total: u64,
}

impl Sha256 {
    fn new() -> Sha256 {
        Sha256 {
            state: H0,
            block: [0; 64],
            filled: 0,
            total: 0,
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        self.total = self.total.wrapping_add(data.len() as u64);
        if self.filled > 0 {
            let take = (64 - self.filled).min(data.len());
            self.block[self.filled..self.filled + take].copy_from_slice(&data[..take]);
            self.filled += take;
            data = &data[take..];
            if self.filled < 64 {
                return;
            }
            compress(&mut self.state, &self.block);
            self.filled = 0;
        }
        let (blocks, rest) = data.as_chunks::<64>();
        for block in blocks {
            compress(&mut self.state, block);
        }
        self.block[..rest.len()].copy_from_slice(rest);
        self.filled = rest.len();
    }

    fn finish(mut self) -> [u8; 32] {
        let bits = self.total.wrapping_mul(8);
        // A 1 bit, zeros up to 8 bytes short of a block, then the length.
        let mut pad = [0u8; 64];
        pad[0] = 0x80;
        let zeros = (119 - self.filled) % 64;
        self.update(&pad[..1 + zeros]);
        self.update(&bits.to_be_bytes());
        let mut out = [0u8; 32];
        for (bytes, word) in out.as_chunks_mut::<4>().0.iter_mut().zip(self.state) {
            *bytes = word.to_be_bytes();
        }
        out
    }
}

/// The SHA-256 digest of `data` (FIPS 180-4).
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(data);
    hash.finish()
}

/// HMAC-SHA256 (RFC 2104) of the concatenation of `parts`, so that nothing
/// has to be copied together first.
pub fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut block = [0u8; 64];
    match key.len() > 64 {
        true => block[..32].copy_from_slice(&sha256(key)),
        false => block[..key.len()].copy_from_slice(key),
    }
    let mut inner = Sha256::new();
    inner.update(&block.map(|b| b ^ 0x36));
    for part in parts {
        inner.update(part);
    }
    let mut outer = Sha256::new();
    outer.update(&block.map(|b| b ^ 0x5c));
    outer.update(&inner.finish());
    outer.finish()
}

/// Whether `a` and `b` are equal, in a time that does not depend on where
/// they differ.
fn same(a: &[u8; TAG], b: &[u8; TAG]) -> bool {
    a.iter().zip(b).fold(0u8, |diff, (x, y)| diff | (x ^ y)) == 0
}

// ------------------------------------------------------------------ secret

/// A pre-shared secret. Its `Debug` output does not show it.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(Vec<u8>);

impl Secret {
    /// `bytes` as a secret; at least [`MIN_SECRET`] of them.
    pub fn new(bytes: &[u8]) -> io::Result<Secret> {
        match bytes.len() >= MIN_SECRET {
            true => Ok(Secret(bytes.to_vec())),
            false => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "a secret takes at least {MIN_SECRET} bytes, this one has {}",
                    bytes.len()
                ),
            )),
        }
    }

    /// The contents of a file, without the newline an editor or `echo` puts
    /// at its end.
    pub fn from_file(path: &Path) -> io::Result<Secret> {
        let named = |e: io::Error| io::Error::new(e.kind(), format!("{}: {e}", path.display()));
        let mut bytes = std::fs::read(path).map_err(named)?;
        while bytes.ends_with(b"\n") | bytes.ends_with(b"\r") {
            bytes.pop();
        }
        Secret::new(&bytes).map_err(named)
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(..)")
    }
}

// --------------------------------------------------------------- handshake

/// 32 bytes that nobody can predict.
fn nonce() -> [u8; NONCE] {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut seed = [0u8; 32];
    // Each `RandomState` is keyed from the operating system's randomness.
    for bytes in seed.as_chunks_mut::<8>().0 {
        *bytes = RandomState::new().build_hasher().finish().to_le_bytes();
    }
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    hmac_sha256(
        b"lumendb nonce",
        &[&seed, &count.to_le_bytes(), &now.as_nanos().to_le_bytes()],
    )
}

/// What one side proves, or what one direction is keyed with: the secret,
/// the purpose, a label that says which, and both nonces.
fn derive(secret: &Secret, purpose: &str, label: &str, nonce_s: &[u8; NONCE], nonce_c: &[u8; NONCE]) -> [u8; TAG] {
    let purpose_len = (purpose.len() as u32).to_le_bytes();
    let parts: [&[u8]; 7] = [
        b"lumendb auth v1\0",
        &purpose_len,
        purpose.as_bytes(),
        label.as_bytes(),
        b"\0",
        nonce_s,
        nonce_c,
    ];
    hmac_sha256(&secret.0, &parts)
}

fn denied() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "the other side's proof is wrong")
}

fn handshake_failed(e: io::Error) -> io::Error {
    io::Error::new(
        e.kind(),
        format!("authentication failed ({e}): do both sides use the same secret?"),
    )
}

/// The keys and counters of one connection.
struct Session {
    send_key: [u8; TAG],
    recv_key: [u8; TAG],
    send_seq: u64,
    recv_seq: u64,
}

impl Session {
    fn new(secret: &Secret, purpose: &str, nonce_s: &[u8; NONCE], nonce_c: &[u8; NONCE], server: bool) -> Session {
        let key = |label| derive(secret, purpose, label, nonce_s, nonce_c);
        let (to_server, to_client) = (key("client-to-server key"), key("server-to-client key"));
        let (send_key, recv_key) = match server {
            true => (to_client, to_server),
            false => (to_server, to_client),
        };
        Session {
            send_key,
            recv_key,
            send_seq: 0,
            recv_seq: 0,
        }
    }
}

/// The connecting side. The server speaks first: its nonce, then the client
/// sends its own with a proof, and the server answers with a proof.
fn client_handshake(
    r: &mut dyn Read,
    w: &mut dyn Write,
    secret: &Secret,
    purpose: &str,
    nonce_c: [u8; NONCE],
) -> io::Result<Session> {
    let mut nonce_s = [0u8; NONCE];
    r.read_exact(&mut nonce_s)?;
    let mut hello = [0u8; NONCE + TAG];
    hello[..NONCE].copy_from_slice(&nonce_c);
    hello[NONCE..].copy_from_slice(&derive(secret, purpose, "client proof", &nonce_s, &nonce_c));
    w.write_all(&hello)?;
    let mut theirs = [0u8; TAG];
    r.read_exact(&mut theirs)?;
    if !same(&theirs, &derive(secret, purpose, "server proof", &nonce_s, &nonce_c)) {
        return Err(denied());
    }
    Ok(Session::new(secret, purpose, &nonce_s, &nonce_c, false))
}

/// The accepting side of [`client_handshake`].
fn server_handshake(
    r: &mut dyn Read,
    w: &mut dyn Write,
    secret: &Secret,
    purpose: &str,
    nonce_s: [u8; NONCE],
) -> io::Result<Session> {
    w.write_all(&nonce_s)?;
    let (mut nonce_c, mut theirs) = ([0u8; NONCE], [0u8; TAG]);
    r.read_exact(&mut nonce_c)?;
    r.read_exact(&mut theirs)?;
    if !same(&theirs, &derive(secret, purpose, "client proof", &nonce_s, &nonce_c)) {
        return Err(denied());
    }
    w.write_all(&derive(secret, purpose, "server proof", &nonce_s, &nonce_c))?;
    Ok(Session::new(secret, purpose, &nonce_s, &nonce_c, true))
}

// ----------------------------------------------------------------- records

/// The tag of the record that has the number `seq`.
fn record_tag(key: &[u8; TAG], seq: u64, payload: &[u8]) -> [u8; TAG] {
    let len = (payload.len() as u32).to_le_bytes();
    hmac_sha256(key, &[&seq.to_le_bytes(), &len, payload])
}

/// `len u32le | payload | tag`.
fn seal(key: &[u8; TAG], seq: u64, payload: &[u8]) -> Vec<u8> {
    let mut record = Vec::with_capacity(4 + payload.len() + TAG);
    record.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    record.extend_from_slice(payload);
    record.extend_from_slice(&record_tag(key, seq, payload));
    record
}

fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// Reads and checks the next record into `out`. `Ok(false)`: the stream ended
/// between records. Anything wrong is an error, and ends the stream's use:
/// `InvalidData` for a record that is too large or fails its check,
/// `UnexpectedEof` for one that is cut short.
fn read_record(inner: &mut dyn Duplex, session: &mut Session, out: &mut Vec<u8>) -> io::Result<bool> {
    let mut head = [0u8; 4];
    if inner.read(&mut head[..1])? == 0 {
        return Ok(false);
    }
    inner.read_exact(&mut head[1..])?;
    let len = u32::from_le_bytes(head) as usize;
    if len > MAX_RECORD {
        return Err(invalid("authenticated record too large"));
    }
    out.clear();
    out.resize(len, 0);
    inner.read_exact(out)?;
    let mut tag = [0u8; TAG];
    inner.read_exact(&mut tag)?;
    if !same(&tag, &record_tag(&session.recv_key, session.recv_seq, out)) {
        return Err(invalid("authenticated record fails its check"));
    }
    session.recv_seq += 1;
    Ok(true)
}

/// What an [`AuthStream`] runs over: a `TcpStream`, or a stand-in in tests.
trait Duplex: Read + Write + Send {}

impl<T: Read + Write + Send> Duplex for T {}

/// A connection, authenticated or not (see the module docs). Not
/// authenticated, it passes bytes through; authenticated, it turns each write
/// into records and hands out only data from records that passed their check.
///
/// After any error, drop it: a record cut in two or a stream that is out of
/// step cannot be taken up again.
pub struct AuthStream {
    inner: Box<dyn Duplex>,
    session: Option<Session>,
    /// The record being read, and how much of it was handed out.
    pending: Vec<u8>,
    used: usize,
}

impl AuthStream {
    fn over(inner: Box<dyn Duplex>, session: Option<Session>) -> AuthStream {
        AuthStream {
            inner,
            session,
            pending: Vec::new(),
            used: 0,
        }
    }

    /// `stream`, with no authentication.
    pub fn plain(stream: TcpStream) -> AuthStream {
        AuthStream::over(Box::new(stream), None)
    }

    /// The handshake of the side that connected. It waits for the other side
    /// as long as `stream`'s read timeout allows, and leaves the timeouts
    /// alone. `purpose` must be the same on both sides.
    pub fn connect(stream: TcpStream, secret: &Secret, purpose: &str) -> io::Result<AuthStream> {
        let (mut r, mut w) = (&stream, &stream);
        let session = client_handshake(&mut r, &mut w, secret, purpose, nonce()).map_err(handshake_failed)?;
        Ok(AuthStream::over(Box::new(stream), Some(session)))
    }

    /// The handshake of the side that accepted, which must finish within
    /// `timeout` (not zero). After it, reads wait as long as it takes.
    pub fn accept(stream: TcpStream, secret: &Secret, purpose: &str, timeout: Duration) -> io::Result<AuthStream> {
        // Neither fails on a socket that works.
        let _ = stream.set_read_timeout(Some(timeout));
        let (mut r, mut w) = (&stream, &stream);
        let session = server_handshake(&mut r, &mut w, secret, purpose, nonce()).map_err(handshake_failed);
        let _ = stream.set_read_timeout(None);
        Ok(AuthStream::over(Box::new(stream), Some(session?)))
    }

    /// Whether the other side proved it knows the secret.
    pub fn is_authenticated(&self) -> bool {
        self.session.is_some()
    }
}

impl Read for AuthStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let Some(session) = self.session.as_mut() else {
            return self.inner.read(buf);
        };
        if buf.is_empty() {
            return Ok(0);
        }
        // (an empty record is no end of the stream)
        while self.used == self.pending.len() {
            if !read_record(&mut *self.inner, session, &mut self.pending)? {
                return Ok(0);
            }
            self.used = 0;
        }
        let n = buf.len().min(self.pending.len() - self.used);
        buf[..n].copy_from_slice(&self.pending[self.used..self.used + n]);
        self.used += n;
        Ok(n)
    }
}

impl Write for AuthStream {
    /// Sends at most [`MAX_RECORD`] bytes of `buf` as one record.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let Some(session) = self.session.as_mut() else {
            return self.inner.write(buf);
        };
        let payload = &buf[..buf.len().min(MAX_RECORD)];
        if payload.is_empty() {
            return Ok(0);
        }
        self.inner
            .write_all(&seal(&session.send_key, session.send_seq, payload))?;
        session.send_seq += 1;
        Ok(payload.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    use std::io::Cursor;
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::thread;

    const LONG: Duration = Duration::from_secs(20);

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn pattern(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i * 31 + 7) as u8).collect()
    }

    #[test]
    fn sha256_matches_the_fips_180_vectors() {
        for (input, digest) in [
            (&b""[..], "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            (
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            ),
            (
                b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
            ),
            (
                &vec![b'a'; 1_000_000],
                "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
            ),
        ] {
            let len = input.len();
            assert_eq!(hex(&sha256(input)), digest, "{len} bytes");
        }
    }

    #[test]
    fn sha256_pads_correctly_around_block_boundaries() {
        // Digests of `pattern(n)` from Python's hashlib.
        for (n, digest) in [
            (1, "ca358758f6d27e6cf45272937977a748fd88391db679ceda7dc7bf1f005ee879"),
            (55, "8aa994584139d128848eeebc4e815639ba5ab6e6e39574195a63ac4f14f7c43b"),
            (56, "ad574708f75c044c9b85de64cb568ee7711ff4f36448c6242f053ba8f6cc2b63"),
            (63, "280ed3e8ff1df845b2e7dfe6ac6cee817bef20e783cc65abc41b818b4d2fe076"),
            (64, "c6ab9724ade5b6a7a1edfffb12f3aa9181351355af8fd08c919952ad211339dd"),
            (65, "788367c73c7ddf4c53f65e68cc0d943e6227ab55b0e78ba63ace822b1c6301c0"),
            (119, "3d610547d68216dedf7435a4fb6260353911f6b3fd3f18805ddb8be285d726fe"),
            (120, "1f80156a804cb7862ad113e8200e9d74499723e7c7854d5f48776d3148e09656"),
            (127, "192409cd280e14b743642ad1343fbd3e82d9305de72c078117745a679210cc3d"),
            (128, "cc548ca2dec1f6fe4f58b2e27aa9c7521607df1130d140b55a4dad0665302356"),
            (129, "81e89a7b2911aaa7795f9e3d4910cb47d6cd2b00d83b8399481527261a1a7519"),
            (300, "4ebe2a8bd5ece93fb899b68e8a5fe64464b2058a5ddca6c079bc907930aa3003"),
        ] {
            assert_eq!(hex(&sha256(&pattern(n))), digest, "{n} bytes");
        }
    }

    #[test]
    fn sha256_in_pieces_is_sha256_in_one() {
        let data = pattern(300);
        let whole = sha256(&data);
        for piece in [1, 2, 3, 7, 31, 63, 64, 65, 100, 299, 300, 500] {
            let mut hash = Sha256::new();
            for part in data.chunks(piece) {
                hash.update(part);
            }
            assert_eq!(hash.finish(), whole, "pieces of {piece}");
        }
    }

    #[test]
    fn hmac_matches_the_rfc_4231_vectors() {
        for (key, data, mac) in [
            (
                vec![0x0b; 20],
                b"Hi There".to_vec(),
                "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            ),
            (
                b"Jefe".to_vec(),
                b"what do ya want for nothing?".to_vec(),
                "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
            ),
            (
                vec![0xaa; 20],
                vec![0xdd; 50],
                "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
            ),
            (
                (1..=25).collect(),
                vec![0xcd; 50],
                "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
            ),
            // Keys longer than a block are hashed first.
            (
                vec![0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First".to_vec(),
                "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
            ),
            (
                vec![0xaa; 131],
                b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm."
                    .to_vec(),
                "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
            ),
        ] {
            assert_eq!(hex(&hmac_sha256(&key, &[&data])), mac);
            // However the data is cut into parts.
            let (a, b) = data.split_at(data.len() / 3);
            assert_eq!(hex(&hmac_sha256(&key, &[a, &[], b])), mac);
        }
    }

    #[test]
    fn comparison_sees_every_byte() {
        let a = [7u8; TAG];
        assert!(same(&a, &a));
        for i in 0..TAG {
            let mut b = a;
            b[i] ^= 0x80;
            assert!(!same(&a, &b), "byte {i}");
        }
    }

    fn secret() -> Secret {
        Secret::new(b"0123456789abcdef-test-secret").unwrap()
    }

    fn other_secret() -> Secret {
        Secret::new(b"another-secret-0123456789").unwrap()
    }

    fn tmp(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("raft-auth-{}-{name}", std::process::id()))
    }

    #[test]
    fn secrets_are_long_enough_and_never_shown() {
        let short = Secret::new(b"too short").err().unwrap();
        assert_eq!(short.kind(), io::ErrorKind::InvalidInput);
        assert!(short.to_string().contains("at least 16 bytes, this one has 9"));
        assert!(Secret::new(&[0; MIN_SECRET - 1]).is_err());
        assert!(Secret::new(&[0; MIN_SECRET]).is_ok());
        assert_eq!(format!("{:?}", secret()), "Secret(..)");
    }

    #[test]
    fn a_secret_file_loses_its_trailing_newline() {
        let path = tmp("secret");
        let want = Secret::new(b"a-secret-of-some-length").unwrap();
        for text in [
            &b"a-secret-of-some-length"[..],
            b"a-secret-of-some-length\n",
            b"a-secret-of-some-length\r\n",
            b"a-secret-of-some-length\n\n",
        ] {
            std::fs::write(&path, text).unwrap();
            assert_eq!(Secret::from_file(&path).unwrap(), want, "{text:?}");
        }
        // The text that is left has to be long enough.
        std::fs::write(&path, b"short\n").unwrap();
        let e = Secret::from_file(&path).err().unwrap();
        assert!(e.to_string().starts_with(&path.display().to_string()), "{e}");
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
        std::fs::remove_file(&path).unwrap();
        let e = Secret::from_file(&path).err().unwrap();
        assert_eq!(e.kind(), io::ErrorKind::NotFound);
        assert!(e.to_string().starts_with(&path.display().to_string()), "{e}");
    }

    #[test]
    fn nonces_do_not_repeat() {
        let all: Vec<[u8; NONCE]> = (0..200).map(|_| nonce()).collect();
        for (i, a) in all.iter().enumerate() {
            assert!(!all[..i].contains(a));
        }
    }

    /// A stand-in for a connection: reads from a script, records what is
    /// written, and can be made to fail.
    struct Mem {
        input: Cursor<Vec<u8>>,
        output: Arc<Mutex<Vec<u8>>>,
        fail_reads: bool,
        /// How many writes succeed before they fail.
        writes_left: usize,
    }

    impl Mem {
        fn reading(input: Vec<u8>) -> Mem {
            Mem {
                input: Cursor::new(input),
                output: Arc::default(),
                fail_reads: false,
                writes_left: usize::MAX,
            }
        }
    }

    impl Read for Mem {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.fail_reads {
                return Err(io::Error::other("read failed"));
            }
            self.input.read(buf)
        }
    }

    impl Write for Mem {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.writes_left == 0 {
                return Err(io::Error::other("write failed"));
            }
            self.writes_left -= 1;
            self.output.lock().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// The client's session and the server's, for the same handshake.
    fn sessions() -> (Session, Session) {
        let (nonce_s, nonce_c) = ([1u8; NONCE], [2u8; NONCE]);
        (
            Session::new(&secret(), "test", &nonce_s, &nonce_c, false),
            Session::new(&secret(), "test", &nonce_s, &nonce_c, true),
        )
    }

    /// A client's end of a connection that has `bytes` to read.
    fn client_reading(bytes: Vec<u8>) -> AuthStream {
        AuthStream::over(Box::new(Mem::reading(bytes)), Some(sessions().0))
    }

    fn read_everything(mut s: AuthStream) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        s.read_to_end(&mut out).map(|_| out)
    }

    #[test]
    fn the_two_sides_of_a_session_use_opposite_keys() {
        let (client, server) = sessions();
        assert_eq!(client.send_key, server.recv_key);
        assert_eq!(client.recv_key, server.send_key);
        assert_ne!(client.send_key, client.recv_key);
        // Another purpose or another nonce is another key.
        let other = Session::new(&secret(), "other", &[1; NONCE], &[2; NONCE], false);
        assert_ne!(other.send_key, client.send_key);
        let other = Session::new(&secret(), "test", &[1; NONCE], &[3; NONCE], false);
        assert_ne!(other.send_key, client.send_key);
        let other = Session::new(&other_secret(), "test", &[1; NONCE], &[2; NONCE], false);
        assert_ne!(other.send_key, client.send_key);
    }

    #[test]
    fn records_carry_a_tag_over_their_number_and_length() {
        let key = [9u8; TAG];
        let record = seal(&key, 3, b"hello");
        assert_eq!(&record[..4], &5u32.to_le_bytes());
        assert_eq!(&record[4..9], b"hello");
        let tag = hmac_sha256(&key, &[&3u64.to_le_bytes(), &5u32.to_le_bytes(), b"hello"]);
        assert_eq!(&record[9..], &tag);
        assert_ne!(record, seal(&key, 4, b"hello"));
        assert_ne!(record, seal(&[8u8; TAG], 3, b"hello"));
        assert_eq!(seal(&key, 0, b"").len(), 4 + TAG);
    }

    #[test]
    fn a_session_reads_what_the_other_side_sealed() {
        let (_, server) = sessions();
        let mut bytes = seal(&server.send_key, 0, b"hello ");
        bytes.extend(seal(&server.send_key, 1, b""));
        bytes.extend(seal(&server.send_key, 2, b"world"));
        let mut s = client_reading(bytes.clone());
        // In pieces smaller than a record, and an empty read is no end.
        assert_eq!(s.read(&mut []).unwrap(), 0);
        let mut got = Vec::new();
        let mut one = [0u8; 4];
        loop {
            let n = s.read(&mut one).unwrap();
            if n == 0 {
                break;
            }
            got.extend_from_slice(&one[..n]);
        }
        assert_eq!(got, b"hello world");
        assert_eq!(read_everything(client_reading(bytes)).unwrap(), b"hello world");
        assert!(client_reading(Vec::new()).is_authenticated());
    }

    #[test]
    fn a_record_that_was_changed_is_refused_wherever() {
        let (_, server) = sessions();
        let record = seal(&server.send_key, 0, b"hello world");
        assert_eq!(read_everything(client_reading(record.clone())).unwrap(), b"hello world");
        for i in 0..record.len() {
            for bit in [0x01, 0x80] {
                let mut bad = record.clone();
                bad[i] ^= bit;
                assert!(read_everything(client_reading(bad)).is_err(), "byte {i}, bit {bit:#x}");
            }
        }
    }

    #[test]
    fn a_replayed_dropped_or_reordered_record_is_refused() {
        let (_, server) = sessions();
        let first = seal(&server.send_key, 0, b"one");
        let second = seal(&server.send_key, 1, b"two");
        let third = seal(&server.send_key, 2, b"three");
        let join = |parts: &[&Vec<u8>]| parts.iter().flat_map(|p| p.iter().copied()).collect::<Vec<u8>>();
        assert_eq!(
            read_everything(client_reading(join(&[&first, &second, &third]))).unwrap(),
            b"onetwothree"
        );
        let e = read_everything(client_reading(join(&[&first, &first]))).err().unwrap();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData, "replayed");
        assert!(
            read_everything(client_reading(join(&[&first, &third]))).is_err(),
            "dropped"
        );
        assert!(
            read_everything(client_reading(join(&[&second, &first]))).is_err(),
            "reordered"
        );
        // A record the same side sealed for the other direction.
        let mine = seal(&sessions().0.send_key, 0, b"one");
        assert!(read_everything(client_reading(mine)).is_err(), "reflected");
    }

    #[test]
    fn broken_streams_are_errors_not_ends() {
        let (_, server) = sessions();
        let record = seal(&server.send_key, 0, b"hello world");
        // The stream ends between records: that is an end.
        assert_eq!(read_everything(client_reading(Vec::new())).unwrap(), b"");
        // Cut inside the length, the payload and the tag.
        for cut in [1, 3, 4, 9, record.len() - 1] {
            let e = read_everything(client_reading(record[..cut].to_vec())).err().unwrap();
            assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof, "cut at {cut}");
        }
        // A length beyond the limit costs no memory.
        let huge = (MAX_RECORD as u32 + 1).to_le_bytes().to_vec();
        let e = read_everything(client_reading(huge)).err().unwrap();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        // The largest record is fine.
        let big = pattern(MAX_RECORD);
        let record = seal(&server.send_key, 0, &big);
        assert_eq!(read_everything(client_reading(record)).unwrap(), big);
        // An error of the connection itself.
        let mut mem = Mem::reading(Vec::new());
        mem.fail_reads = true;
        let mut s = AuthStream::over(Box::new(mem), Some(sessions().0));
        assert_eq!(s.read(&mut [0u8; 4]).err().unwrap().to_string(), "read failed");
    }

    #[test]
    fn writes_become_records_of_a_bounded_size() {
        let (client, server) = sessions();
        let mem = Mem::reading(Vec::new());
        let output = mem.output.clone();
        let mut s = AuthStream::over(Box::new(mem), Some(client));
        s.write_all(b"hello").unwrap();
        assert_eq!(s.write(b"").unwrap(), 0);
        s.flush().unwrap();
        let data = pattern(2 * MAX_RECORD + 1);
        assert_eq!(s.write(&data).unwrap(), MAX_RECORD, "one record at most");
        s.write_all(&data[MAX_RECORD..]).unwrap();
        let sent = output.lock().clone();
        let mut want = seal(&server.recv_key, 0, b"hello");
        want.extend(seal(&server.recv_key, 1, &data[..MAX_RECORD]));
        want.extend(seal(&server.recv_key, 2, &data[MAX_RECORD..2 * MAX_RECORD]));
        want.extend(seal(&server.recv_key, 3, &data[2 * MAX_RECORD..]));
        assert_eq!(sent, want);
        // And the other side reads them back as one stream.
        let mut back = AuthStream::over(Box::new(Mem::reading(sent)), Some(sessions().1));
        let mut got = vec![0u8; 5 + data.len()];
        back.read_exact(&mut got).unwrap();
        assert_eq!(&got[..5], b"hello");
        assert_eq!(&got[5..], &data[..]);
    }

    #[test]
    fn a_failed_write_is_an_error_and_sends_no_record_number() {
        let mut mem = Mem::reading(Vec::new());
        mem.writes_left = 0;
        let mut s = AuthStream::over(Box::new(mem), Some(sessions().0));
        assert_eq!(s.write(b"x").err().unwrap().to_string(), "write failed");
        assert_eq!(s.session.as_ref().unwrap().send_seq, 0);
    }

    #[test]
    fn without_a_session_bytes_pass_through() {
        let mut mem = Mem::reading(b"plain bytes".to_vec());
        let output = mem.output.clone();
        mem.writes_left = 1;
        let mut s = AuthStream::over(Box::new(mem), None);
        assert!(!s.is_authenticated());
        let mut got = [0u8; 5];
        assert_eq!(s.read(&mut got).unwrap(), 5);
        assert_eq!(&got, b"plain");
        s.write_all(b"as is").unwrap();
        assert_eq!(&*output.lock(), b"as is");
        assert!(s.write(b"more").is_err());
    }

    /// The client's handshake against a server that sends `input`, and lets
    /// `writes` writes through: the outcome, and what the client sent.
    fn client_script(input: Vec<u8>, writes: usize) -> (io::Result<Session>, Vec<u8>) {
        let mut w = Mem::reading(Vec::new());
        w.writes_left = writes;
        let session = client_handshake(&mut Cursor::new(input), &mut w, &secret(), "test", [2; NONCE]);
        let sent = w.output.lock().clone();
        (session, sent)
    }

    #[test]
    fn the_client_handshake_checks_the_server() {
        let proof = derive(&secret(), "test", "server proof", &[1; NONCE], &[2; NONCE]);
        let mut good = vec![1u8; NONCE];
        good.extend(proof);
        let (session, sent) = client_script(good.clone(), usize::MAX);
        assert_eq!(session.unwrap().send_key, sessions().0.send_key);
        // It said who it is, and proved it knows the secret.
        assert_eq!(&sent[..NONCE], &[2u8; NONCE]);
        assert_eq!(
            &sent[NONCE..],
            &derive(&secret(), "test", "client proof", &[1; NONCE], &[2; NONCE])
        );
        // A proof from another secret, a missing one, a challenge that is cut
        // off, and a write that fails.
        let mut bad = good.clone();
        bad[NONCE] ^= 1;
        assert_eq!(
            client_script(bad, usize::MAX).0.err().unwrap().kind(),
            io::ErrorKind::PermissionDenied
        );
        let e = client_script(good[..NONCE].to_vec(), usize::MAX).0.err().unwrap();
        assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof);
        let e = client_script(good[..10].to_vec(), usize::MAX).0.err().unwrap();
        assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof);
        assert_eq!(client_script(good, 0).0.err().unwrap().to_string(), "write failed");
    }

    /// The server's handshake against a client that sends `hello`, and lets
    /// `writes` writes through: the outcome, and what the server sent.
    fn server_script(hello: Vec<u8>, writes: usize) -> (io::Result<Session>, Vec<u8>) {
        let mut w = Mem::reading(Vec::new());
        w.writes_left = writes;
        let session = server_handshake(&mut Cursor::new(hello), &mut w, &secret(), "test", [1; NONCE]);
        let sent = w.output.lock().clone();
        (session, sent)
    }

    #[test]
    fn the_server_handshake_checks_the_client() {
        let mut hello = vec![2u8; NONCE];
        hello.extend(derive(&secret(), "test", "client proof", &[1; NONCE], &[2; NONCE]));
        let (session, sent) = server_script(hello.clone(), usize::MAX);
        assert_eq!(session.unwrap().send_key, sessions().1.send_key);
        // It sent a challenge, and then its proof.
        assert_eq!(&sent[..NONCE], &[1u8; NONCE]);
        assert_eq!(
            &sent[NONCE..],
            &derive(&secret(), "test", "server proof", &[1; NONCE], &[2; NONCE])
        );
        // A wrong proof, a hello cut short in either part, and writes that fail.
        let mut wrong = hello.clone();
        wrong[NONCE + 5] ^= 4;
        let (session, sent) = server_script(wrong, usize::MAX);
        assert_eq!(session.err().unwrap().kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(sent.len(), NONCE, "no proof for a stranger");
        for cut in [10, NONCE + TAG - 1] {
            let (session, _) = server_script(hello[..cut].to_vec(), usize::MAX);
            assert_eq!(
                session.err().unwrap().kind(),
                io::ErrorKind::UnexpectedEof,
                "cut at {cut}"
            );
        }
        assert_eq!(
            server_script(hello.clone(), 0).0.err().unwrap().to_string(),
            "write failed"
        );
        assert_eq!(server_script(hello, 1).0.err().unwrap().to_string(), "write failed");
    }

    fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        (client, server)
    }

    /// Both ends of a handshake over TCP: (client's result, server's result).
    fn handshake(client: &Secret, server: &Secret) -> (io::Result<AuthStream>, io::Result<AuthStream>) {
        let (c, s) = tcp_pair();
        thread::scope(|scope| {
            let accepted = scope.spawn(|| AuthStream::accept(s, server, "test", LONG));
            let connected = AuthStream::connect(c, client, "test");
            (connected, accepted.join().unwrap())
        })
    }

    #[test]
    fn two_ends_with_the_same_secret_talk_both_ways() {
        let (client, server) = handshake(&secret(), &secret());
        let (mut client, mut server) = (client.unwrap(), server.unwrap());
        assert!(client.is_authenticated() && server.is_authenticated());
        let data = pattern(3 * MAX_RECORD + 11);
        thread::scope(|scope| {
            let echo = scope.spawn(|| {
                let mut got = vec![0u8; data.len()];
                server.read_exact(&mut got).unwrap();
                server.write_all(&got).unwrap();
                server.write_all(b"done").unwrap();
            });
            client.write_all(&data).unwrap();
            let mut back = vec![0u8; data.len() + 4];
            client.read_exact(&mut back).unwrap();
            assert_eq!(&back[..data.len()], &data[..]);
            assert_eq!(&back[data.len()..], b"done");
            echo.join().unwrap();
        });
    }

    #[test]
    fn a_stranger_does_not_get_in_either_way() {
        // Another secret: both sides fail, and say what to check.
        let (client, server) = handshake(&secret(), &other_secret());
        let (client, server) = (client.err().unwrap(), server.err().unwrap());
        assert_eq!(server.kind(), io::ErrorKind::PermissionDenied);
        assert!(
            server.to_string().contains("do both sides use the same secret?"),
            "{server}"
        );
        assert!(client.to_string().contains("authentication failed"), "{client}");

        // Not authenticating at all: the server gets bytes that are no proof,
        // or too few of them, or nothing before its time is up.
        let (mut c, s) = tcp_pair();
        c.write_all(&[7; 100]).unwrap();
        let e = AuthStream::accept(s, &secret(), "test", LONG).err().unwrap();
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
        let (mut c, s) = tcp_pair();
        let e = thread::scope(|scope| {
            let accepted = scope.spawn(|| AuthStream::accept(s, &secret(), "test", LONG));
            // Read the challenge first: closing with it unread would reset the connection.
            c.read_exact(&mut [0u8; NONCE]).unwrap();
            c.write_all(&[7; 10]).unwrap();
            drop(c);
            accepted.join().unwrap().err().unwrap()
        });
        assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof);
        let (_c, s) = tcp_pair();
        let e = AuthStream::accept(s, &secret(), "test", Duration::from_millis(50))
            .err()
            .unwrap();
        assert!(
            [io::ErrorKind::WouldBlock, io::ErrorKind::TimedOut].contains(&e.kind()),
            "{e}"
        );

        // Authenticating, to a server that does not: no challenge comes.
        let (c, _s) = tcp_pair();
        c.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
        let e = AuthStream::connect(c, &secret(), "test").err().unwrap();
        assert!(
            [io::ErrorKind::WouldBlock, io::ErrorKind::TimedOut].contains(&e.kind()),
            "{e}"
        );
    }

    #[test]
    fn a_connection_that_is_idle_after_the_handshake_does_not_time_out() {
        let (c, s) = tcp_pair();
        let (mut client, mut server) = thread::scope(|scope| {
            let accepted = scope.spawn(|| AuthStream::accept(s, &secret(), "test", Duration::from_millis(300)));
            let client = AuthStream::connect(c, &secret(), "test").unwrap();
            (client, accepted.join().unwrap().unwrap())
        });
        thread::sleep(Duration::from_millis(500));
        client.write_all(b"late").unwrap();
        let mut got = [0u8; 4];
        server.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"late");
    }

    #[test]
    fn a_plain_stream_goes_over_tcp_as_it_is() {
        let (c, s) = tcp_pair();
        let (mut c, mut s) = (AuthStream::plain(c), AuthStream::plain(s));
        c.write_all(b"ping").unwrap();
        let mut got = [0u8; 4];
        s.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"ping");
        assert!(!c.is_authenticated());
    }
}
