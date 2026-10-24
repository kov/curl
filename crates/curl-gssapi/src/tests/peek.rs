//! Reading what the library put inside its first Kerberos token, with the
//! `rc4-hmac` session key the made-up cache gave it (RFC 4757): the
//! checksum of the authenticator (RFC 4121, 4.1.1), where the channel
//! bindings and the flags asked for go.

/// The authenticator's checksum in `token`, a first Kerberos token made
/// with the `rc4-hmac` session key `key`.
pub(super) fn authenticator_checksum(token: &[u8], key: &[u8]) -> Vec<u8> {
    // The mechanism's framing, its OID, then KRB_AP_REQ's token id.
    let (tag, framed) = element(token);
    assert_eq!(tag, 0x60);
    let (tag, oid) = element(framed);
    assert_eq!((tag, oid), (0x06, crate::KRB5_OID));
    let after_oid = rest_after(framed);
    assert_eq!(&after_oid[..2], b"\x01\x00");
    let (tag, ap_req) = element(&after_oid[2..]);
    assert_eq!(tag, 0x6e);
    let ap_req = sequence(ap_req);
    let encrypted = sequence(field(ap_req, 4));
    let (tag, cipher) = element(field(encrypted, 2));
    assert_eq!(tag, 0x04);
    // Key usage 11, the authenticator.
    let plain = rc4_hmac_decrypt(key, 11, cipher);
    let (tag, authenticator) = element(&plain[8..]);
    assert_eq!(tag, 0x62);
    let checksum = sequence(field(sequence(authenticator), 3));
    let (tag, bytes) = element(field(checksum, 1));
    assert_eq!(tag, 0x04);
    bytes.to_vec()
}

/// What the checksum holds for `binding` (`kg_checksum_channel_bindings`):
/// no addresses, the binding as the application's data; 16 zero bytes
/// for none.
pub(super) fn bindings_hash(binding: Option<&[u8]>) -> [u8; 16] {
    let Some(data) = binding else {
        return [0; 16];
    };
    let mut fields = Vec::new();
    // The initiator's and the acceptor's address types and addresses.
    fields.extend_from_slice(&[0; 16]);
    fields.extend_from_slice(&(data.len() as u32).to_le_bytes());
    fields.extend_from_slice(data);
    md5(&fields)
}

/// One DER element at the start of `bytes`: its tag and its content.
fn element(bytes: &[u8]) -> (u8, &[u8]) {
    let (start, len) = header(bytes);
    (bytes[0], &bytes[start..start + len])
}

fn header(bytes: &[u8]) -> (usize, usize) {
    let first = bytes[1] as usize;
    if first < 0x80 {
        return (2, first);
    }
    let n = first & 0x7f;
    let len = bytes[2..2 + n]
        .iter()
        .fold(0, |len, &b| len << 8 | b as usize);
    (2 + n, len)
}

/// What follows the element at the start of `bytes`.
fn rest_after(bytes: &[u8]) -> &[u8] {
    let (start, len) = header(bytes);
    &bytes[start + len..]
}

/// The content of a SEQUENCE.
fn sequence(bytes: &[u8]) -> &[u8] {
    let (tag, content) = element(bytes);
    assert_eq!(tag, 0x30);
    content
}

/// The content of the field tagged `[n]` among a SEQUENCE's `fields`.
fn field(mut fields: &[u8], n: u8) -> &[u8] {
    while !fields.is_empty() {
        let (tag, content) = element(fields);
        if tag == 0xa0 | n {
            return content;
        }
        fields = rest_after(fields);
    }
    panic!("no field [{n}]");
}

/// RFC 4757's decryption, without checking the integrity it carries.
fn rc4_hmac_decrypt(key: &[u8], usage: u32, cipher: &[u8]) -> Vec<u8> {
    let k1 = hmac_md5(key, &usage.to_le_bytes());
    let (checksum, data) = cipher.split_at(16);
    let k3 = hmac_md5(&k1, checksum);
    rc4(&k3, data)
}

fn rc4(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut s: [u8; 256] = core::array::from_fn(|i| i as u8);
    let mut j = 0u8;
    for i in 0..256 {
        j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
        s.swap(i, j as usize);
    }
    let (mut i, mut j) = (0u8, 0u8);
    data.iter()
        .map(|&b| {
            i = i.wrapping_add(1);
            j = j.wrapping_add(s[i as usize]);
            s.swap(i as usize, j as usize);
            b ^ s[s[i as usize].wrapping_add(s[j as usize]) as usize]
        })
        .collect()
}

fn hmac_md5(key: &[u8], message: &[u8]) -> [u8; 16] {
    assert!(key.len() <= 64);
    let mut padded = [0u8; 64];
    padded[..key.len()].copy_from_slice(key);
    let inner: Vec<u8> = padded
        .iter()
        .map(|b| b ^ 0x36)
        .chain(message.iter().copied())
        .collect();
    let outer: Vec<u8> = padded.iter().map(|b| b ^ 0x5c).chain(md5(&inner)).collect();
    md5(&outer)
}

/// MD5 (RFC 1321).
fn md5(message: &[u8]) -> [u8; 16] {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    let k: [u32; 64] =
        core::array::from_fn(|i| ((i as f64 + 1.0).sin().abs() * 4_294_967_296.0) as u32);
    let mut data = message.to_vec();
    data.push(0x80);
    while data.len() % 64 != 56 {
        data.push(0);
    }
    data.extend_from_slice(&((message.len() as u64) * 8).to_le_bytes());
    let mut h: [u32; 4] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];
    for block in data.chunks(64) {
        let m: [u32; 16] = core::array::from_fn(|i| {
            u32::from_le_bytes(block[4 * i..4 * i + 4].try_into().unwrap())
        });
        let [mut a, mut b, mut c, mut d] = h;
        for i in 0..64 {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let f = f.wrapping_add(a).wrapping_add(k[i]).wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(f.rotate_left(S[i]));
        }
        for (h, v) in h.iter_mut().zip([a, b, c, d]) {
            *h = h.wrapping_add(v);
        }
    }
    let mut out = [0; 16];
    for (i, v) in h.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&v.to_le_bytes());
    }
    out
}

#[test]
fn md5_is_rfc_1321_s() {
    assert_eq!(
        md5(b"message digest"),
        *b"\xf9\x6b\x69\x7d\x7c\xb7\x93\x8d\x52\x5a\x2f\x31\xaa\xf1\x61\xd0"
    );
    // RFC 2104's second case.
    assert_eq!(
        hmac_md5(b"Jefe", b"what do ya want for nothing?"),
        *b"\x75\x0c\x78\x3e\x6a\xb0\xb5\x03\xea\xa8\x6e\x31\x0a\x5d\xb7\x38"
    );
}
