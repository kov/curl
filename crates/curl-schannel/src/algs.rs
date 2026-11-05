//! The algorithms a cipher list names for Schannel's older credential
//! (`set_ssl_ciphers`'s `algs`): each `CALG_` name and its number.

/// The most algorithms a list gives (`NUM_CIPHERS`).
pub(crate) const MOST: usize = 47;

const ALGS: &[(&[u8], u32)] = &[
    (b"CALG_MD2", 0x8001),
    (b"CALG_MD4", 0x8002),
    (b"CALG_MD5", 0x8003),
    (b"CALG_SHA", 0x8004),
    (b"CALG_SHA1", 0x8004),
    (b"CALG_MAC", 0x8005),
    (b"CALG_RSA_SIGN", 0x2400),
    (b"CALG_DSS_SIGN", 0x2200),
    (b"CALG_NO_SIGN", 0x2000),
    (b"CALG_RSA_KEYX", 0xa400),
    (b"CALG_DES", 0x6601),
    (b"CALG_3DES_112", 0x6609),
    (b"CALG_3DES", 0x6603),
    (b"CALG_DESX", 0x6604),
    (b"CALG_RC2", 0x6602),
    (b"CALG_RC4", 0x6801),
    (b"CALG_SEAL", 0x6802),
    (b"CALG_DH_SF", 0xaa01),
    (b"CALG_DH_EPHEM", 0xaa02),
    (b"CALG_AGREEDKEY_ANY", 0xaa03),
    (b"CALG_HUGHES_MD5", 0xa003),
    (b"CALG_SKIPJACK", 0x660a),
    (b"CALG_TEK", 0x660b),
    (b"CALG_CYLINK_MEK", 0x660c),
    (b"CALG_SSL3_SHAMD5", 0x8008),
    (b"CALG_SSL3_MASTER", 0x4c01),
    (b"CALG_SCHANNEL_MASTER_HASH", 0x4c02),
    (b"CALG_SCHANNEL_MAC_KEY", 0x4c03),
    (b"CALG_SCHANNEL_ENC_KEY", 0x4c07),
    (b"CALG_PCT1_MASTER", 0x4c04),
    (b"CALG_SSL2_MASTER", 0x4c05),
    (b"CALG_TLS1_MASTER", 0x4c06),
    (b"CALG_RC5", 0x660d),
    (b"CALG_HMAC", 0x8009),
    (b"CALG_TLS1PRF", 0x800a),
    (b"CALG_HASH_REPLACE_OWF", 0x800b),
    (b"CALG_AES_128", 0x660e),
    (b"CALG_AES_192", 0x660f),
    (b"CALG_AES_256", 0x6610),
    (b"CALG_AES", 0x6611),
    (b"CALG_SHA_256", 0x800c),
    (b"CALG_SHA_384", 0x800d),
    (b"CALG_SHA_512", 0x800e),
    (b"CALG_ECDH", 0xaa05),
    (b"CALG_ECMQV", 0xa001),
    (b"CALG_ECDSA", 0x2203),
    (b"CALG_ECDH_EPHEM", 0xae06),
];

/// The algorithm a list's item names, up to its `:` (`get_alg_id_by_name`).
pub(crate) fn named(item: &[u8]) -> Option<u32> {
    let end = item
        .iter()
        .position(|&b| b == b':' || b == 0)
        .unwrap_or(item.len());
    let name = &item[..end];
    ALGS.iter().find(|(n, _)| *n == name).map(|&(_, id)| id)
}

/// The number a list's item starts with, if it starts with digits and is
/// no more than `INT_MAX` (`curlx_str_number`).
pub(crate) fn number(item: &[u8]) -> Option<u32> {
    let digits = item.iter().take_while(|b| b.is_ascii_digit()).count();
    if digits == 0 {
        return None;
    }
    let mut n: u64 = 0;
    for &d in &item[..digits] {
        n = n * 10 + u64::from(d - b'0');
        if n > u64::from(i32::MAX.cast_unsigned()) {
            return None;
        }
    }
    u32::try_from(n).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A name is matched whole, up to its colon; a number is taken up to
    /// `INT_MAX`.
    #[test]
    fn items_are_read_as_c_reads_them() {
        assert_eq!(named(b"CALG_RC4:CALG_AES"), Some(0x6801));
        assert_eq!(named(b"CALG_SHA"), Some(0x8004));
        assert_eq!(named(b"CALG_SH"), None);
        assert_eq!(number(b"26128:x"), Some(26128));
        assert_eq!(number(b"2147483648"), None);
        assert_eq!(number(b"CALG"), None);
    }
}
