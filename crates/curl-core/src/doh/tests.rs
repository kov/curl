//! C's unit tests 1650, 1655 and 1658, and hostile answers.

use super::*;
use crate::doh::c_tests::{
    UNIT1650_ANSWERS, UNIT1650_FULL, UNIT1650_QUERIES, UNIT1655_NAMES, UNIT1658,
};
use std::fmt::Write;

/// An answer's addresses and time to live, as unit1650 writes them.
fn shown(a: &DohAnswer<'_>) -> String {
    let mut out = String::new();
    for addr in &a.addrs {
        match addr {
            IpAddr::V4(v4) => write!(out, "{v4} ").unwrap(),
            IpAddr::V6(v6) => {
                let [s0, s1, s2, s3, s4, s5, s6, s7] = v6.segments();
                write!(
                    out,
                    "{s0:04x}:{s1:04x}:{s2:04x}:{s3:04x}:{s4:04x}:{s5:04x}:{s6:04x}:{s7:04x} "
                )
                .unwrap();
            }
        }
    }
    // C starts from the largest it can hold.
    write!(out, "({})", a.ttl.unwrap_or(i32::MAX as u32)).unwrap();
    out
}

#[test]
fn unit1650_queries() {
    for &(name, what, want, rc) in UNIT1650_QUERIES {
        let made = encode_query(name, what);
        assert_eq!(made.as_ref().map(|_| ()).map_err(|e| *e), rc, "{name:?}");
        if let (Ok(made), Some(want)) = (&made, want) {
            assert_eq!(&made[..], want, "{name:?}");
        }
    }
}

#[test]
fn unit1650_answers() {
    for (i, &(packet, what, rc, want)) in UNIT1650_ANSWERS.iter().enumerate() {
        let got = decode_answer(packet, what);
        assert_eq!(got.as_ref().map(|_| ()).map_err(|e| *e), rc, "row {i}");
        if let (Ok(got), Some(want)) = (&got, want) {
            assert_eq!(shown(got), want, "row {i}");
        }
    }
}

/// An HTTPS record shorter than three bytes is refused, as unit1650's
/// `httpsrr` case.
#[test]
fn unit1650_https_record_length() {
    let mut packet = vec![
        0x00, 0x00, 0x81, 0x80, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
    ];
    for i in 0..=3usize {
        packet[22] = i as u8;
        let got = decode_answer(&packet[..packet.len() - 3 + i], QueryType::Https);
        if i < 3 {
            assert_eq!(got, Err(DohError::RdataLength));
        } else {
            assert_eq!(got.unwrap().https.len(), 1);
        }
    }
}

/// Every truncation of an answer, from either end, is refused.
#[test]
fn unit1650_truncations() {
    for i in 0..UNIT1650_FULL.len() {
        assert!(
            decode_answer(&UNIT1650_FULL[..i], QueryType::A).is_err(),
            "{i}"
        );
    }
    // C's other end reaches the literal's NUL too, as its size says not.
    for i in 1..=UNIT1650_FULL.len() {
        assert!(
            decode_answer(&UNIT1650_FULL[i..], QueryType::A).is_err(),
            "{i}"
        );
    }
    let whole = decode_answer(UNIT1650_FULL, QueryType::A).unwrap();
    assert_eq!(whole.addrs, [IpAddr::from([127, 0, 0, 1])]);
}

#[test]
fn unit1655_names() {
    for &(name, rc) in UNIT1655_NAMES {
        let made = encode_query(name, QueryType::A);
        assert_eq!(made.as_ref().map(|_| ()).map_err(|e| *e), rc, "{name:?}");
        if let Ok(made) = made {
            assert!(made.len() <= MAX_QUERY);
            assert!(made.len() > name.len());
        }
    }
}

/// A trailing dot adds nothing; each letter one.
#[test]
fn unit1655_lengths() {
    let one = encode_query(b"a.com", QueryType::A).unwrap();
    assert_eq!(one, encode_query(b"a.com.", QueryType::A).unwrap());
    assert_eq!(
        encode_query(b"aa.com", QueryType::A).unwrap().len(),
        one.len() + 1
    );
}

/// A record decoded, as unit1658 writes it, with C's numbers for its
/// failures.
fn account(data: &[u8]) -> String {
    let mut out = String::new();
    let record = match decode_https_record(data) {
        Ok(r) => r,
        Err(e) => {
            let n = match e {
                RecordError::BadParameter => 43,
                RecordError::BadName | RecordError::OutOfMemory => 27,
                RecordError::Weird => 8,
                RecordError::BadAlpn => 61,
            };
            return format!("r:{n}|");
        }
    };
    write!(out, "r:0|p:{}|", record.priority).unwrap();
    write!(out, "{}|", String::from_utf8_lossy(&record.target)).unwrap();
    for a in &record.alpns {
        let id = match a {
            RecordAlpn::H1 => 8,
            RecordAlpn::H2 => 0x10,
            RecordAlpn::H3 => 0x20,
        };
        write!(out, "alpn:{id:x}|").unwrap();
    }
    if record.no_default_alpn {
        out.push_str("no-def-alpn|");
    }
    if let Some(p) = record.port {
        write!(out, "port:{p}|").unwrap();
    }
    for a in &record.ipv4_hints {
        write!(out, "ipv4:{a}|").unwrap();
    }
    if !record.ech.is_empty() {
        out.push_str("ech:");
        for b in &record.ech {
            write!(out, "{b:02x}").unwrap();
        }
        out.push('|');
    }
    for a in &record.ipv6_hints {
        let s = a.segments();
        write!(
            out,
            "ipv6:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}|",
            s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]
        )
        .unwrap();
    }
    out
}

#[test]
fn unit1658_records() {
    for &(name, data, want) in UNIT1658 {
        assert_eq!(account(data), want, "{name}");
    }
}

/// A small generator, so a failure repeats.
fn next(seed: &mut u64) -> u64 {
    *seed ^= *seed << 13;
    *seed ^= *seed >> 7;
    *seed ^= *seed << 17;
    *seed
}

/// No answer, however mangled, panics: whatever came of C's tables, cut and
/// with bytes changed.
#[test]
fn hostile_answers_never_panic() {
    let mut seed = 0x1650_1658_u64;
    let decode_all = |p: &[u8]| {
        for what in [QueryType::A, QueryType::Aaaa, QueryType::Https] {
            if let Ok(a) = decode_answer(p, what) {
                assert!(a.addrs.len() <= MAX_ADDRS);
                assert!(a.https.len() <= MAX_HTTPS);
                assert!(a.ttl.is_none_or(|t| t <= MAX_TTL));
            }
        }
        let _ = decode_https_record(p);
    };
    for &(packet, ..) in UNIT1650_ANSWERS {
        for _ in 0..2000 {
            let mut p = packet.to_vec();
            for _ in 0..1 + next(&mut seed) % 4 {
                let i = next(&mut seed) as usize % p.len().max(1);
                if let Some(b) = p.get_mut(i) {
                    *b = next(&mut seed) as u8;
                }
            }
            p.truncate(next(&mut seed) as usize % (p.len() + 1));
            decode_all(&p);
        }
    }
    for &(_, data, _) in UNIT1658 {
        for _ in 0..2000 {
            let mut p = data.to_vec();
            let i = next(&mut seed) as usize % p.len().max(1);
            if let Some(b) = p.get_mut(i) {
                *b = next(&mut seed) as u8;
            }
            decode_all(&p);
        }
    }
}

/// A question with a record count far beyond what is there ends at the
/// message's end, not after sixty-five thousand reads.
#[test]
fn counts_past_the_message_are_refused() {
    let mut p = vec![0, 0, 1, 0, 0xff, 0xff, 0, 0, 0, 0, 0, 0];
    assert_eq!(decode_answer(&p, QueryType::A), Err(DohError::OutOfRange));
    p[4] = 0;
    p[5] = 0;
    p[6] = 0xff;
    assert_eq!(decode_answer(&p, QueryType::A), Err(DohError::OutOfRange));
    p[6] = 0;
    p[8] = 0xff;
    assert_eq!(decode_answer(&p, QueryType::A), Err(DohError::OutOfRange));
    p[8] = 0;
    p[10] = 0xff;
    assert_eq!(decode_answer(&p, QueryType::A), Err(DohError::OutOfRange));
}

/// A compression pointer is stepped over, so one pointing at itself loops
/// nowhere; a label's reserved prefixes are refused.
#[test]
fn names_are_skipped_not_followed() {
    let mut p = vec![0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    p.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1]);
    assert_eq!(
        decode_answer(&p, QueryType::A),
        Ok(DohAnswer::default()),
        "a pointer to itself"
    );
    for prefix in [0x40, 0x80] {
        p[12] = prefix;
        assert_eq!(decode_answer(&p, QueryType::A), Err(DohError::BadLabel));
    }
}

/// Bytes left after the last section are refused; a record of the wrong
/// type or class too.
#[test]
fn what_an_answer_may_not_be() {
    let ok = UNIT1650_FULL;
    let mut more = ok.to_vec();
    more.push(0);
    assert_eq!(decode_answer(&more, QueryType::A), Err(DohError::Malformed));
    assert_eq!(
        decode_answer(ok, QueryType::Aaaa),
        Err(DohError::UnexpectedType)
    );
    let mut class = ok.to_vec();
    // The answer's class, after its pointer and type.
    class[33 + 4] = 9;
    assert_eq!(
        decode_answer(&class, QueryType::A),
        Err(DohError::UnexpectedClass)
    );
    let mut short = ok.to_vec();
    short[43..45].copy_from_slice(&[0, 3]);
    short.pop();
    assert_eq!(
        decode_answer(&short, QueryType::A),
        Err(DohError::RdataLength)
    );
}

/// More addresses than are kept are ignored, not refused, and the least
/// time to live wins.
#[test]
fn the_addresses_past_the_limit_are_ignored() {
    let mut p = vec![0, 0, 1, 0, 0, 0, 0, 30, 0, 0, 0, 0];
    for i in 0..30u8 {
        p.extend_from_slice(&[0, 0, 1, 0, 1]);
        p.extend_from_slice(&u32::from(1000 - u16::from(i)).to_be_bytes());
        p.extend_from_slice(&[0, 4, 10, 0, 0, i]);
    }
    let a = decode_answer(&p, QueryType::A).unwrap();
    assert_eq!(a.addrs.len(), MAX_ADDRS);
    assert_eq!(a.addrs[23], IpAddr::from([10, 0, 0, 23]));
    assert_eq!(a.ttl, Some(1000 - 29));
}

/// A label is at most 63 bytes on the wire: what would be its length's top
/// bits mean something else.
#[test]
fn a_label_is_at_most_63_bytes() {
    let name = |n: usize| {
        let mut name = vec![b'a'; n];
        name.extend_from_slice(b".test");
        name
    };
    assert!(encode_query(&name(63), QueryType::A).is_ok());
    assert_eq!(
        encode_query(&name(64), QueryType::A),
        Err(DohError::BadLabel)
    );
}

/// A message answering with `n` records of `kind`, each with `data`.
fn answering(kind: u16, data: &[u8], n: u8) -> Vec<u8> {
    let mut m = vec![0, 0, 0x81, 0x80, 0, 1, 0, n, 0, 0, 0, 0];
    m.extend_from_slice(b"\x01a\x00");
    m.extend_from_slice(&kind.to_be_bytes());
    m.extend_from_slice(&[0, 1]);
    for _ in 0..n {
        m.extend_from_slice(&[0xc0, 0x0c]);
        m.extend_from_slice(&kind.to_be_bytes());
        m.extend_from_slice(&[0, 1, 0, 0, 0, 60, 0, u8::try_from(data.len()).unwrap()]);
        m.extend_from_slice(data);
    }
    m
}

#[test]
fn an_answer_keeps_as_many_as_c_does() {
    let m = answering(1, &[1, 2, 3, 4], 25);
    assert_eq!(decode_answer(&m, QueryType::A).unwrap().addrs.len(), 24);
    let m = answering(28, &[1; 16], 25);
    assert_eq!(decode_answer(&m, QueryType::Aaaa).unwrap().addrs.len(), 24);
    let m = answering(65, &[0, 1, 0], 5);
    assert_eq!(decode_answer(&m, QueryType::Https).unwrap().https.len(), 4);
}

#[test]
fn a_query_as_long_as_it_may_be_is_made() {
    // Twelve of header, four of question, two for the first label's length
    // and the root's: labels of 63 and their dots for the rest.
    let fits = MAX_QUERY - 12 - 4 - 2;
    let mut name = Vec::new();
    while name.len() + 64 < fits {
        name.extend_from_slice(&[b'a'; 63]);
        name.push(b'.');
    }
    name.resize(fits, b'b');
    assert_eq!(encode_query(&name, QueryType::A).unwrap().len(), MAX_QUERY);
    name.push(b'b');
    assert_eq!(
        encode_query(&name, QueryType::A),
        Err(DohError::NameTooLong)
    );
}

/// A target of labels of 63, as long as `want` with their dots.
fn target(want: usize) -> Vec<u8> {
    let mut data = vec![0, 1];
    let mut left = want;
    while left > 0 {
        let label = left.min(64) - 1;
        data.push(u8::try_from(label).unwrap());
        data.resize(data.len() + label, b'a');
        left -= label + 1;
    }
    data.push(0);
    data
}

/// C reads a target into a buffer of 253 bytes, its NUL among them: 252
/// with the dots are taken, 253 are not.
#[test]
fn a_record_s_target_is_as_long_as_c_takes() {
    let max = decode_https_record(&target(252)).unwrap();
    assert_eq!(max.target.len(), 252, "its last dot among them");
    assert_eq!(
        decode_https_record(&target(253)).err(),
        Some(RecordError::BadName)
    );
    // A label of 63 is one; one of 64 is not a label.
    let mut data = vec![0, 1, 1, b'a', 63];
    data.resize(data.len() + 63, b'b');
    data.push(0);
    assert!(decode_https_record(&data).is_ok());
    data[4] = 64;
    data.push(b'b');
    assert_eq!(decode_https_record(&data).err(), Some(RecordError::BadName));
}

#[test]
fn a_parameter_said_twice_is_refused() {
    assert_eq!(
        decode_https_record(b"\0\x01\0\0\x02\0\0\0\x02\0\0").err(),
        Some(RecordError::Weird)
    );
}

#[test]
fn a_record_is_printed_as_c_prints_it() {
    let data = b"\0\x01\0\
        \0\0\0\0\
        \0\x01\0\x06\x02h3\x02h2\
        \0\x02\0\0\
        \0\x03\0\x02\x01\xbb\
        \0\x04\0\x08\x01\x02\x03\x04\x05\x06\x07\x08\
        \0\x05\0\x02\xaa\xbb\
        \0\x06\0\x20\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x02";
    let shown = decode_https_record(data).unwrap().print().unwrap();
    assert_eq!(
        String::from_utf8(shown).unwrap(),
        "1 . mandatory-keys(ignored) alpn=h3,h2 port=443 no-default-alpn \
         ipv6hint=::1,::2 ipv4hint=1.2.3.4,5.6.7.8 ech=<2 bytes>"
    );
}
