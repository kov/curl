use super::*;

fn oack(p: &[u8], requested: usize, uploading: bool) -> (Result<Oack, OackRefused>, Vec<String>) {
    let mut said = Vec::new();
    let got = parse_oack(p, requested, uploading, &mut |args| {
        said.push(args.to_string())
    });
    (got, said)
}

/// The block size and the file's size are read, each said; the size is
/// not taken for an upload, and other options are passed over.
#[test]
fn an_oack_is_read() {
    let (got, said) = oack(
        b"blksize\x001024\0tsize\x005000\0timeout\x006\0",
        1024,
        false,
    );
    assert_eq!(
        got,
        Ok(Oack {
            blksize: 1024,
            tsize: Some(5000)
        })
    );
    assert_eq!(
        said,
        [
            "got option=(blksize) value=(1024)",
            "blksize parsed from OACK (1024) requested (1024)",
            "got option=(tsize) value=(5000)",
            "tsize parsed from OACK (5000)",
            "got option=(timeout) value=(6)",
        ]
    );
    let (got, _) = oack(b"TSIZE\x005000\0", 512, true);
    assert_eq!(
        got,
        Ok(Oack {
            blksize: 512,
            tsize: None
        })
    );
    // A size that is no number is passed over.
    let (got, _) = oack(b"tsize\0x\0", 512, false);
    assert_eq!(got.unwrap().tsize, None);
    assert_eq!(oack(b"", 512, false).0.unwrap().blksize, BLKSIZE_DEFAULT);
}

/// An OACK cut short, or with a block size C cannot take, is refused,
/// said as C says it.
#[test]
fn a_bad_oack_is_refused() {
    for (p, want) in [
        (&b"blksize"[..], "Malformed ACK packet, rejecting"),
        (b"blksize\0", "Malformed ACK packet, rejecting"),
        (b"blksize\x001024", "Malformed ACK packet, rejecting"),
        (
            b"blksize\x0070000\0",
            "blksize is larger than max supported (65464)",
        ),
        (
            b"blksize\0x\0",
            "blksize is larger than max supported (65464)",
        ),
        (b"blksize\x000\0", "invalid blocksize value in OACK packet"),
        (
            b"blksize\x007\0",
            "blksize is smaller than min supported (8)",
        ),
        (
            b"blksize\x002048\0",
            "server requested blksize larger than allocated (2048)",
        ),
        (b"tsize\x000z\0", "invalid tsize -:z:- value in OACK packet"),
    ] {
        let (got, _) = oack(p, 1024, false);
        assert_eq!(got.unwrap_err().to_string(), want, "{p:?}");
    }
}

/// The request names the file and the mode, then the options C asks
/// for, each ended by a zero byte.
#[test]
fn the_first_packet_is_made_as_c_makes_it() {
    let mut out = Vec::new();
    first_packet(&mut out, false, b"f.txt", false, 512, None).unwrap();
    assert_eq!(out, b"\0\x01f.txt\0octet\0");
    first_packet(&mut out, true, b"f", true, 512, Some((7, 1024, 3))).unwrap();
    assert_eq!(
        out,
        b"\0\x02f\0netascii\0tsize\x007\0blksize\x001024\0timeout\x003\0"
    );
    // A name that leaves no room for the mode and four bytes.
    let long = [b'a'; 504];
    assert_eq!(
        first_packet(&mut out, false, &long, false, 512, None),
        Err(FirstRefused::NameTooLong)
    );
    let fits = [b'a'; 503];
    first_packet(&mut out, false, &fits, false, 512, None).unwrap();
    // Options past the default block's room.
    let fits = [b'a'; 473];
    first_packet(&mut out, false, &fits, false, 512, Some((0, 512, 1))).unwrap();
    assert_eq!(out.len(), 512);
    // The last, a byte past it.
    let near = [b'a'; 474];
    assert_eq!(
        first_packet(&mut out, false, &near, false, 512, Some((0, 512, 1))),
        Err(FirstRefused::OptionsTooLong)
    );
}

/// The server's codes, and the ends without answer, are C's errors.
#[test]
fn failures_are_c_s_errors() {
    for (code, kind) in [
        (0, ErrorKind::TftpIllegal),
        (1, ErrorKind::TftpNotfound),
        (2, ErrorKind::TftpPerm),
        (3, ErrorKind::RemoteDiskFull),
        (4, ErrorKind::TftpIllegal),
        (5, ErrorKind::TftpUnknownid),
        (6, ErrorKind::RemoteFileExists),
        (7, ErrorKind::TftpNosuchuser),
        (8, ErrorKind::AbortedByCallback),
    ] {
        assert_eq!(Failure::Server(code).kind(), kind, "{code}");
    }
    assert_eq!(Failure::Timeout.kind(), ErrorKind::OperationTimedout);
    assert_eq!(Failure::NoResponse.kind(), ErrorKind::CouldntConnect);
}

/// Block numbers wrap at 16 bits.
#[test]
fn blocks_wrap() {
    assert_eq!(next_block(65535), 0);
    assert_eq!(next_block(7), 8);
    assert_eq!(strnlen(b"ab\0c"), 2);
    assert_eq!(strnlen(b"abc"), 3);
}

/// The block size an application asks for is brought within TFTP's
/// bounds, 0 among them, as C's `value_range` brings it.
#[test]
fn block_sizes_are_clamped() {
    assert_eq!(TftpBlockSize::clamped(0).get(), 8);
    assert_eq!(TftpBlockSize::clamped(400).get(), 400);
    assert_eq!(TftpBlockSize::clamped(1 << 40).get(), 65464);
}

static SAMPLES: &[&[u8]] = &[
    b"blksize\x001024\0tsize\x005000\0",
    b"tsize\x000\0",
    b"timeout\x006\0blksize\x008\0",
];

proptest::proptest! {
    #![proptest_config(crate::untrusted::config(512))]

    /// Whatever an OACK holds, it is read or refused.
    #[test]
    fn any_oack_is_read_or_refused(
        p in crate::untrusted::mutated(SAMPLES),
        requested in 8usize..70000,
        uploading in proptest::bool::ANY,
    ) {
        let (got, _) = oack(&p, requested, uploading);
        if let Ok(o) = got {
            proptest::prop_assert!(o.blksize <= requested.max(BLKSIZE_DEFAULT));
            proptest::prop_assert!(o.blksize >= 8);
        }
    }
}
