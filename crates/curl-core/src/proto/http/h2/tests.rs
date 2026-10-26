use super::*;

/// A `:status` is three digits, the first not 0, as C reads it.
#[test]
fn a_status_is_read_as_c_reads_it() {
    assert_eq!(decode_status(b"200"), Some(200));
    assert_eq!(decode_status(b"101"), Some(101));
    assert_eq!(decode_status(b"999"), Some(999));
    assert_eq!(decode_status(b"099"), None);
    assert_eq!(decode_status(b"20"), None);
    assert_eq!(decode_status(b"2000"), None);
    assert_eq!(decode_status(b"2x0"), None);
}

/// The trailers are held to C's limits exactly (`Curl_dynhds_add`): a
/// mebibyte of names and values, their framing not counted, and 5,000
/// fields; a field that fills what is left is kept, one byte more is not.
#[test]
fn trailers_are_held_to_c_s_limits_at_their_edges() {
    let max = Trailers::MAX_BYTES;
    let mut t = Trailers::default();
    assert_eq!(t.add(b"a", &vec![b'x'; max / 2 - 1]), Ok(()));
    let left = max - max / 2;
    assert_eq!(t.add(b"b", &vec![b'x'; left]), Err(OutOfMemory));
    assert_eq!(t.add(b"b", &vec![b'x'; left - 1]), Ok(()));
    assert_eq!(t.add(b"c", b""), Err(OutOfMemory));

    // A name alone filling the room is kept; one longer than it is not.
    let mut t = Trailers::default();
    assert_eq!(t.add(&vec![b'n'; max + 1], b""), Err(OutOfMemory));
    assert_eq!(t.add(&vec![b'n'; max], b""), Ok(()));

    let mut t = Trailers::default();
    for _ in 0..Trailers::MAX_COUNT {
        assert_eq!(t.add(b"a", b"b"), Ok(()));
    }
    assert_eq!(t.add(b"a", b"b"), Err(OutOfMemory));
}
