#![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

use super::*;
use crate::tls::cache::tests::c_made_session;

/// A session of every field, as C's `Curl_ssl_session_pack` lays it out.
const WHOLE: &[u8] = &[
    1, // version
    4, 0, 3, b'd', b'e', b'r', // ticket
    2, 0x03, 0x04, // version of TLS
    3, 0, 0, 0, 0, 0x65, 0x53, 0xf1, 0x00, // good until
    5, 0, 2, b'h', b'2', // ALPN
    6, 0, 1, 0, 0, // early data
    8, // sectrust
    7, 0, 2, b't', b'p', // QUIC's transport parameters
];

/// The offsets at which `WHOLE` may be cut and still be a session.
const FIELD_ENDS: &[usize] = &[1, 7, 10, 19, 24, 29, 30, 35];

/// What C's build exported goes out again as it came.
#[test]
fn a_session_c_made_packs_to_the_same_bytes() {
    let (_, blob) = c_made_session();
    let s = unpack(&blob).unwrap();
    assert_eq!(s.version, TLS13);
    assert_eq!(s.alpn_name(), Some(&b"http/1.1"[..]));
    assert_eq!(pack(&s).unwrap(), blob);
}

const TLS13: u16 = 0x304;

/// Every field is read, and packed in C's one order whatever the order it
/// came in.
#[test]
fn fields_read_in_any_order_and_pack_in_c_s() {
    let s = unpack(WHOLE).unwrap();
    assert_eq!(s.data, b"der");
    assert_eq!(s.version, TLS13);
    assert_eq!(s.valid_until, 0x6553_f100);
    assert_eq!(s.chosen(), Some(Chosen::H2));
    assert_eq!(s.earlydata_max, 65536);
    assert!(s.sectrust);
    assert_eq!(s.quic_params, b"tp");
    assert_eq!(pack(&s).unwrap(), WHOLE);
    let shuffled = [
        &[1][..],
        &[8],
        &[7, 0, 2, b't', b'p'],
        &[6, 0, 1, 0, 0],
        &[5, 0, 2, b'h', b'2'],
        &[3, 0, 0, 0, 0, 0x65, 0x53, 0xf1, 0x00],
        &[2, 0x03, 0x04],
        &[4, 0, 3, b'd', b'e', b'r'],
    ]
    .concat();
    assert_eq!(pack(&unpack(&shuffled).unwrap()).unwrap(), WHOLE);
}

/// The last of a tag wins, as test 1678's packet asks.
#[test]
fn the_last_of_a_tag_wins() {
    let s = unpack(&[
        1, 4, 0, 1, b'A', 5, 0, 1, b'a', 7, 0, 1, b'Q', 4, 0, 1, b'B', 5, 0, 1, b'b', 7, 0, 1, b'R',
    ])
    .unwrap();
    assert_eq!(s.data, b"B");
    assert_eq!(s.alpn_name(), Some(&b"b"[..]));
    assert_eq!(s.quic_params, b"R");
}

/// An ALPN no build offers is kept, and goes out as it came; to a zero
/// byte in it, where C's string ends; and one of no length is one, not
/// none.
#[test]
fn an_alpn_is_kept_whatever_it_says() {
    let other = [1, 4, 0, 1, b'T', 5, 0, 3, b'f', b'o', b'o'];
    let s = unpack(&other).unwrap();
    assert_eq!((s.chosen(), s.alpn_name()), (None, Some(&b"foo"[..])));
    let packed = pack(&s).unwrap();
    assert!(packed.ends_with(&[5, 0, 3, b'f', b'o', b'o']), "{packed:?}");
    let cut = unpack(&[1, 5, 0, 4, b'h', b'2', 0, b'x']).unwrap();
    assert_eq!(cut.chosen(), Some(Chosen::H2));
    assert!(pack(&cut).unwrap().ends_with(&[5, 0, 2, b'h', b'2']));
    let empty = unpack(&[1, 5, 0, 0]).unwrap();
    assert_eq!(empty.alpn_name(), Some(&b""[..]));
    assert!(pack(&empty).unwrap().ends_with(&[5, 0, 0]));
}

/// A blob of a version alone is a session of nothing, C's as much as ours:
/// no ticket, and packed with an empty one.
#[test]
fn a_blob_may_say_nothing() {
    let s = unpack(&[1]).unwrap();
    assert!(s.data.is_empty());
    assert_eq!(s.alpn_name(), None);
    assert_eq!(
        pack(&s).unwrap(),
        [1, 4, 0, 0, 2, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0]
    );
}

/// Cut anywhere but at the end of a field, a blob cannot be read.
#[test]
fn every_truncation_is_refused() {
    assert_eq!(unpack(&[]).unwrap_err(), ErrorKind::ReadError);
    for at in 1..WHOLE.len() {
        let got = unpack(&WHOLE[..at]);
        if FIELD_ENDS.contains(&at) {
            assert!(got.is_ok(), "cut at {at}");
        } else {
            assert_eq!(got.unwrap_err(), ErrorKind::ReadError, "cut at {at}");
        }
    }
    assert!(unpack(WHOLE).is_ok());
    let (_, blob) = c_made_session();
    // A real session: its ticket first, cut anywhere in it.
    assert_eq!(blob[1], TICKET);
    let ticket = usize::from(u16::from_be_bytes([blob[2], blob[3]]));
    for at in 2..4 + ticket {
        assert_eq!(
            unpack(&blob[..at]).unwrap_err(),
            ErrorKind::ReadError,
            "cut at {at}"
        );
    }
    assert!(unpack(&blob[..4 + ticket]).is_ok());
}

/// Not of this version, with a tag unknown or a length past the end, it
/// cannot be read.
#[test]
fn what_is_not_a_session_is_refused() {
    for bad in [
        &[0][..],
        &[2, 4, 0, 1, b'T'],
        &[1, 0],
        &[1, 9],
        &[1, 0xff],
        &[1, 4, 0xff, 0xff, 0],
        &[1, 5, 0, 2, b'h'],
        &[1, 7, 0, 1],
        b"second sequence",
    ] {
        assert_eq!(unpack(bad).unwrap_err(), ErrorKind::ReadError, "{bad:?}");
    }
}

/// Any byte of a blob, any way changed, is an answer and never a panic; and
/// what reads packs, unless its date or length is one the export refuses.
#[test]
fn a_corrupt_blob_is_only_ever_an_answer() {
    let (_, real) = c_made_session();
    for blob in [WHOLE, &real[..40]] {
        for i in 0..blob.len() {
            for bit in 0..8 {
                let mut bad = blob.to_vec();
                bad[i] ^= 1 << bit;
                if let Ok(s) = unpack(&bad)
                    && s.valid_until >= 0
                {
                    drop(pack(&s));
                }
            }
        }
    }
    // Noise, from a generator with no state to set up.
    let mut x = 0x2545_f491_4f6c_dd1du64;
    let mut noise = [0u8; 300];
    for _ in 0..2000 {
        for b in &mut noise {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *b = x as u8;
        }
        let len = (x % 300) as usize;
        noise[0] = 1;
        if let Ok(s) = unpack(&noise[..len.max(1)])
            && s.valid_until >= 0
        {
            drop(pack(&s));
        }
    }
}

/// A date past what 63 bits hold reads, as C's cast has it, as before 1970.
#[test]
fn a_date_past_63_bits_reads_as_before_1970() {
    let s = unpack(&[1, 3, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]).unwrap();
    assert_eq!(s.valid_until, -1);
}

/// What fits C's buffer packs; a ticket that does not is too large, one
/// past its length field a bad argument, as is early data past 32 bits.
#[test]
fn what_does_not_fit_is_refused_as_c_refuses_it() {
    let sized = |n: usize| TlsTicket::new(vec![b'x'; n], TLS13, None, 0, 1);
    // The rest of the blob is 1+1+2 before and 3+9 after; a zero byte ends it.
    let most = PACKED_MAX - 1 - (4 + 3 + 9);
    assert_eq!(pack(&sized(most)).unwrap().len(), PACKED_MAX - 1);
    assert_eq!(pack(&sized(most + 1)).unwrap_err(), ErrorKind::TooLarge);
    assert_eq!(
        pack(&sized(0x1_0000)).unwrap_err(),
        ErrorKind::BadFunctionArgument
    );
    let mut early = sized(1);
    early.earlydata_max = u32::MAX as usize + 1;
    assert_eq!(pack(&early).unwrap_err(), ErrorKind::BadFunctionArgument);
    early.earlydata_max = u32::MAX as usize;
    assert!(pack(&early).is_ok());
}
