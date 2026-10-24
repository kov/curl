//! `--cert`'s argument: a certificate's name and its passphrase after a
//! colon, `\` escaping a colon or itself in the name
//! (`parse_cert_parameter`, tool unit test 1394).

use std::borrow::Cow;

use curl_alloc::TryVec as _;

use super::ParamError;

/// A certificate's name, and the passphrase after it.
type Split<'a> = (Cow<'a, [u8]>, Option<&'a [u8]>);

/// The certificate's name and the passphrase, if one follows a colon.
/// A name with nothing to unescape, or a PKCS#11 URI, is the argument
/// itself.
pub(crate) fn split(arg: &[u8]) -> Result<Split<'_>, ParamError> {
    if arg.is_empty() {
        return Err(ParamError::BlankString);
    }
    if arg.len() >= 7 && arg[..7].eq_ignore_ascii_case(b"pkcs11:")
        || !arg.iter().any(|&b| b == b':' || b == b'\\')
    {
        return Ok((Cow::Borrowed(arg), None));
    }
    let mut name = Vec::new();
    name.try_reserve_exact(arg.len())
        .map_err(|_| ParamError::NoMem)?;
    // Room for the whole argument is reserved: no push fails.
    let mut put = |b: u8| name.try_push(b).expect("reserved");
    let mut i = 0;
    while i < arg.len() {
        match arg[i] {
            b'\\' => {
                i += 1;
                match arg.get(i) {
                    // A trailing backslash is itself.
                    None => put(b'\\'),
                    Some(&c @ (b'\\' | b':')) => {
                        put(c);
                        i += 1;
                    }
                    // Any other is kept, with what it is before.
                    Some(&c) => {
                        put(b'\\');
                        put(c);
                        i += 1;
                    }
                }
            }
            b':' => {
                let rest = &arg[i + 1..];
                let pass = (!rest.is_empty()).then_some(rest);
                return Ok((Cow::Owned(name), pass));
            }
            c => {
                put(c);
                i += 1;
            }
        }
    }
    Ok((Cow::Owned(name), None))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tool unit test 1394's table, its non-Windows rows.
    #[test]
    fn splits_as_unit_1394() {
        for (arg, name, pass) in [
            (&br"foo:bar:baz"[..], &br"foo"[..], Some(&br"bar:baz"[..])),
            (br"foo\:bar:baz", br"foo:bar", Some(br"baz")),
            (br"foo\\:bar:baz", br"foo\", Some(br"bar:baz")),
            (br"foo:bar\:baz", br"foo", Some(br"bar\:baz")),
            (br"foo:bar\\:baz", br"foo", Some(br"bar\\:baz")),
            (br"foo\bar\baz", br"foo\bar\baz", None),
            (br"foo\\bar\\baz", br"foo\bar\baz", None),
            (br"foo\", br"foo\", None),
            (br"foo\\", br"foo\", None),
            (br"foo:bar\", br"foo", Some(br"bar\")),
            (br"foo:bar\\", br"foo", Some(br"bar\\")),
            (br"foo:bar:", br"foo", Some(br"bar:")),
            (br"foo\::bar\:", br"foo:", Some(br"bar\:")),
            (b"pkcs11:foobar", b"pkcs11:foobar", None),
            (b"PKCS11:foobar", b"PKCS11:foobar", None),
            (b"PkCs11:foobar", b"PkCs11:foobar", None),
            // A colon with nothing after gives no passphrase.
            (b"foo:", b"foo", None),
        ] {
            let (got_name, got_pass) = split(arg).unwrap();
            assert_eq!(&*got_name, name, "{}", String::from_utf8_lossy(arg));
            assert_eq!(got_pass, pass, "{}", String::from_utf8_lossy(arg));
        }
        assert_eq!(split(b"").unwrap_err(), ParamError::BlankString);
    }
}
