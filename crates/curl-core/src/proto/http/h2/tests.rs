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
