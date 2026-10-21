//! The hashes HTTP Digest is computed with: MD5, SHA-256 and
//! SHA-512/256, as C's built-in implementations compute them
//! (`lib/md5.c`, `lib/sha256.c`, `lib/curl_sha512_256.c`). Each keeps a
//! fixed state and allocates nothing.

/// A hash, fed in pieces.
pub(crate) trait Hash: Default {
    /// The digest's length in bytes.
    const LEN: usize;
    fn update(&mut self, bytes: &[u8]);
    /// The digest, in its first `LEN` bytes.
    fn finish(self) -> [u8; 32];
}

/// Bytes gathered into blocks of `N`, and how many there were.
#[derive(Clone)]
struct Blocks<const N: usize> {
    block: [u8; N],
    filled: usize,
    total: u128,
}

impl<const N: usize> Default for Blocks<N> {
    fn default() -> Self {
        Blocks {
            block: [0; N],
            filled: 0,
            total: 0,
        }
    }
}

impl<const N: usize> Blocks<N> {
    /// Feed `bytes`, handing each full block to `compress`.
    fn feed(&mut self, mut bytes: &[u8], mut compress: impl FnMut(&[u8; N])) {
        self.total += bytes.len() as u128;
        while !bytes.is_empty() {
            let take = (N - self.filled).min(bytes.len());
            self.block[self.filled..self.filled + take].copy_from_slice(&bytes[..take]);
            self.filled += take;
            bytes = &bytes[take..];
            if self.filled == N {
                compress(&self.block);
                self.filled = 0;
            }
        }
    }

    /// The padding: a one bit, zeros, and the length in bits in its last
    /// `len_bytes`, big- or little-endian.
    fn pad(&mut self, len_bytes: usize, big_endian: bool, mut compress: impl FnMut(&[u8; N])) {
        let bits = self.total.wrapping_mul(8);
        self.block[self.filled] = 0x80;
        self.filled += 1;
        if self.filled > N - len_bytes {
            self.block[self.filled..].fill(0);
            compress(&self.block);
            self.filled = 0;
        }
        self.block[self.filled..N - len_bytes].fill(0);
        let len = &mut self.block[N - len_bytes..];
        if big_endian {
            len.copy_from_slice(&bits.to_be_bytes()[16 - len_bytes..]);
        } else {
            len.copy_from_slice(&bits.to_le_bytes()[..len_bytes]);
        }
        compress(&self.block);
    }
}

const MD5_K: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];
/// Which word each of MD5's steps reads.
const MD5_G: [usize; 64] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 1, 6, 11, 0, 5, 10, 15, 4, 9, 14, 3, 8,
    13, 2, 7, 12, 5, 8, 11, 14, 1, 4, 7, 10, 13, 0, 3, 6, 9, 12, 15, 2, 0, 7, 14, 5, 12, 3, 10, 1,
    8, 15, 6, 13, 4, 11, 2, 9,
];
/// How far each step rotates.
const MD5_S: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9,
    14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15,
    21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

#[derive(Clone)]
pub(crate) struct Md5 {
    state: [u32; 4],
    blocks: Blocks<64>,
}

impl Default for Md5 {
    fn default() -> Self {
        Md5 {
            state: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476],
            blocks: Blocks::default(),
        }
    }
}

fn md5_compress(state: &mut [u32; 4], block: &[u8; 64]) {
    let mut x = [0u32; 16];
    for (i, word) in x.iter_mut().enumerate() {
        *word = u32::from_le_bytes(block[i * 4..i * 4 + 4].try_into().expect("four bytes"));
    }
    let [mut a, mut b, mut c, mut d] = *state;
    for i in 0..64 {
        let f = match i / 16 {
            0 => (b & c) | (!b & d),
            1 => (b & d) | (c & !d),
            2 => b ^ c ^ d,
            _ => c ^ (b | !d),
        };
        let sum = a
            .wrapping_add(f)
            .wrapping_add(MD5_K[i])
            .wrapping_add(x[MD5_G[i]]);
        (a, d, c) = (d, c, b);
        b = b.wrapping_add(sum.rotate_left(MD5_S[i]));
    }
    for (s, v) in state.iter_mut().zip([a, b, c, d]) {
        *s = s.wrapping_add(v);
    }
}

impl Hash for Md5 {
    const LEN: usize = 16;

    fn update(&mut self, bytes: &[u8]) {
        let state = &mut self.state;
        self.blocks.feed(bytes, |block| md5_compress(state, block));
    }

    fn finish(mut self) -> [u8; 32] {
        let state = &mut self.state;
        self.blocks
            .pad(8, false, |block| md5_compress(state, block));
        let mut out = [0; 32];
        for (i, word) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        out
    }
}

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[derive(Clone)]
pub(crate) struct Sha256 {
    state: [u32; 8],
    blocks: Blocks<64>,
}

impl Default for Sha256 {
    fn default() -> Self {
        Sha256 {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            blocks: Blocks::default(),
        }
    }
}

fn sha256_compress(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes(block[i * 4..i * 4 + 4].try_into().expect("four bytes"));
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }
    let mut v = *state;
    for i in 0..64 {
        let [a, b, c, d, e, f, g, h] = v;
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(SHA256_K[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        v = [t1.wrapping_add(t2), a, b, c, d.wrapping_add(t1), e, f, g];
    }
    for (s, x) in state.iter_mut().zip(v) {
        *s = s.wrapping_add(x);
    }
}

impl Hash for Sha256 {
    const LEN: usize = 32;

    fn update(&mut self, bytes: &[u8]) {
        let state = &mut self.state;
        self.blocks
            .feed(bytes, |block| sha256_compress(state, block));
    }

    fn finish(mut self) -> [u8; 32] {
        let state = &mut self.state;
        self.blocks
            .pad(8, true, |block| sha256_compress(state, block));
        let mut out = [0; 32];
        for (i, word) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

const SHA512_K: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

/// SHA-512 with its own initial values, cut to 256 bits (FIPS 180-4,
/// 5.3.6.2).
#[derive(Clone)]
pub(crate) struct Sha512_256 {
    state: [u64; 8],
    blocks: Blocks<128>,
}

impl Default for Sha512_256 {
    fn default() -> Self {
        Sha512_256 {
            state: [
                0x22312194fc2bf72c,
                0x9f555fa3c84c64c2,
                0x2393b86b6f53b151,
                0x963877195940eabd,
                0x96283ee2a88effe3,
                0xbe5e1e2553863992,
                0x2b0199fc2c85b8aa,
                0x0eb72ddc81c52ca2,
            ],
            blocks: Blocks::default(),
        }
    }
}

fn sha512_compress(state: &mut [u64; 8], block: &[u8; 128]) {
    let mut w = [0u64; 80];
    for i in 0..16 {
        w[i] = u64::from_be_bytes(block[i * 8..i * 8 + 8].try_into().expect("eight bytes"));
    }
    for i in 16..80 {
        let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
        let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }
    let mut v = *state;
    for i in 0..80 {
        let [a, b, c, d, e, f, g, h] = v;
        let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
        let ch = (e & f) ^ (!e & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(SHA512_K[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        v = [t1.wrapping_add(t2), a, b, c, d.wrapping_add(t1), e, f, g];
    }
    for (s, x) in state.iter_mut().zip(v) {
        *s = s.wrapping_add(x);
    }
}

impl Hash for Sha512_256 {
    const LEN: usize = 32;

    fn update(&mut self, bytes: &[u8]) {
        let state = &mut self.state;
        self.blocks
            .feed(bytes, |block| sha512_compress(state, block));
    }

    fn finish(mut self) -> [u8; 32] {
        let state = &mut self.state;
        self.blocks
            .pad(16, true, |block| sha512_compress(state, block));
        let mut out = [0; 32];
        for (i, word) in self.state[..4].iter().enumerate() {
            out[i * 8..i * 8 + 8].copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex<H: Hash>(input: &[u8]) -> String {
        let mut h = H::default();
        h.update(input);
        h.finish()[..H::LEN]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// Fed in pieces, as at once.
    fn pieces<H: Hash>(input: &[u8]) -> String {
        let mut h = H::default();
        for chunk in input.chunks(7) {
            h.update(chunk);
        }
        h.finish()[..H::LEN]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// Units 1601, 1610 and 1615, and RFC 1321's, FIPS 180's vectors.
    #[test]
    fn hashes_as_c() {
        assert_eq!(hex::<Md5>(b"1"), "c4ca4238a0b923820dcc509a6f75849b");
        assert_eq!(
            hex::<Md5>(b"hello-you-fool"),
            "88670b6d5d742fada5cdf9b682875f22"
        );
        assert_eq!(hex::<Md5>(b""), "d41d8cd98f00b204e9800998ecf8427e");
        let alnum =
            b"12345678901234567890123456789012345678901234567890123456789012345678901234567890";
        assert_eq!(hex::<Md5>(alnum), "57edf4a22be3c955ac49da2e2107b67a");
        assert_eq!(
            hex::<Sha256>(b"1"),
            "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b"
        );
        assert_eq!(
            hex::<Sha256>(b"hello-you-fool"),
            "cbb16a8ab9cbb935a8cba02e28c02630d1199c1f0217f47c9620f3efe82715ae"
        );
        assert_eq!(
            hex::<Sha256>(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        let cases: [(&[u8], &str); 5] = [
            (
                b"1",
                "18d27566bd1ac66b2332d8c54ad43f7bb22079c906d05f491f3f07a28d5c6990",
            ),
            (
                b"hello-you-fool",
                "af6fb4b0139bee13d1953cb8c7cd5b19f9cdcd21efdfa7425c0713eacc1a3976",
            ),
            (
                b"abc",
                "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23",
            ),
            (
                b"",
                "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a",
            ),
            (
                b"Simple string.",
                "decb3c81654ba0f5f0456b7e61f50df538a4fcb18a95ff59bc0482cf23b23256",
            ),
        ];
        for (input, want) in cases {
            assert_eq!(hex::<Sha512_256>(input), want);
        }
        let seq: Vec<u8> = (1..=255).rev().collect();
        assert_eq!(
            hex::<Sha512_256>(&seq),
            "2231f2a1b489b244f766a0b831edb7738a34dc11c82cf2b58860396b5c067037"
        );
    }

    /// Lengths around a block's padding boundary, fed in pieces.
    #[test]
    fn pads_at_every_length() {
        for len in 0..300 {
            let input: Vec<u8> = (0..len).map(|i| i as u8).collect();
            assert_eq!(hex::<Md5>(&input), pieces::<Md5>(&input));
            assert_eq!(hex::<Sha256>(&input), pieces::<Sha256>(&input));
            assert_eq!(hex::<Sha512_256>(&input), pieces::<Sha512_256>(&input));
        }
    }
}
