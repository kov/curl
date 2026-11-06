//! `--cert`'s argument: a certificate's name and its passphrase after a
//! colon, `\` escaping a colon or itself in the name
//! (`parse_cert_parameter`, tool unit test 1394), and on Windows a drive
//! letter's colon kept in the name.

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
            // On Windows, a letter and a colon starting the argument, a
            // separator after, are a drive's: the colon is the name's.
            b':' if cfg!(windows)
                && i == 1
                && arg[0].is_ascii_alphabetic()
                && matches!(arg.get(2), Some(b'\\' | b'/')) =>
            {
                put(b':');
                i += 1;
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
    fn tool1394_splits() {
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

    /// Tool unit test 1394's Windows rows: a letter and a colon before a
    /// separator start a name on a drive, its colon kept.
    #[cfg(windows)]
    #[test]
    fn tool1394_splits_a_drive_letter_on_windows() {
        for (arg, name, pass) in [
            (
                &br"c:\foo:bar:baz"[..],
                &br"c:\foo"[..],
                Some(&br"bar:baz"[..]),
            ),
            (br"c:\foo\:bar:baz", br"c:\foo:bar", Some(br"baz")),
            (br"c:\foo\\:bar:baz", br"c:\foo\", Some(br"bar:baz")),
            (br"c:\foo:bar\:baz", br"c:\foo", Some(br"bar\:baz")),
            (br"c:\foo:bar\\:baz", br"c:\foo", Some(br"bar\\:baz")),
            (br"c:\foo\bar\baz", br"c:\foo\bar\baz", None),
            (br"c:\foo\\bar\\baz", br"c:\foo\bar\baz", None),
            (br"c:\foo\", br"c:\foo\", None),
            (br"c:\foo\\", br"c:\foo\", None),
            (br"c:\foo:bar\", br"c:\foo", Some(br"bar\")),
            (br"c:\foo:bar\\", br"c:\foo", Some(br"bar\\")),
            (br"c:\foo:bar:", br"c:\foo", Some(br"bar:")),
            (br"c:\foo\::bar\:", br"c:\foo:", Some(br"bar\:")),
            // A forward slash after the colon too, as MSYS hands a path.
            (b"C:/work/a.crt:pw", b"C:/work/a.crt", Some(b"pw")),
            // Not a letter, or not first, or no separator after: a
            // separating colon.
            (b"1:/a", b"1", Some(b"/a")),
            (b"xc:/a", b"xc", Some(b"/a")),
            (b"c:a", b"c", Some(b"a")),
        ] {
            let (got_name, got_pass) = split(arg).unwrap();
            assert_eq!(&*got_name, name, "{}", String::from_utf8_lossy(arg));
            assert_eq!(got_pass, pass, "{}", String::from_utf8_lossy(arg));
        }
    }
}
