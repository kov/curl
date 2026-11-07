//! The priority string a session is set to (`gnutls_set_ssl_version_min_max`,
//! `gtls_set_priority`): the versions the transfer allows, as GnuTLS
//! names them after C's own defaults, and the transfer's cipher list,
//! which adds to that or replaces it.

use curl_alloc::TryVec as _;
use curl_core::error::ErrorKind;
use curl_core::options::{TlsMaxVersion, TlsMinVersion};

/// C's defaults (`GNUTLS_CIPHERS`), then `$rest`.
macro_rules! concat_ciphers {
    ($rest:literal) => {
        concat!(
            "NORMAL:%PROFILE_MEDIUM:-ARCFOUR-128:-CTYPE-ALL:+CTYPE-X509",
            $rest
        )
    };
}

/// C's defaults alone.
#[cfg(test)]
const CIPHERS: &str = concat_ciphers!("");

/// The priorities of the versions from `min` to `max`, as C names them,
/// TLS 1.3 the newest when none is set; none for a range C has none for
/// (`GnuTLS: cannot set TLS protocol`).
pub(crate) fn versions(min: TlsMinVersion, max: TlsMaxVersion) -> Option<&'static str> {
    use TlsMaxVersion as Max;
    use TlsMinVersion as Min;
    let min = match min {
        Min::Tls1 | Min::Tls1_0 => 0,
        Min::Tls1_1 => 1,
        Min::Tls1_2 => 2,
        Min::Tls1_3 => 3,
    };
    let max = match max {
        Max::None | Max::Default | Max::Tls1_3 => 3,
        Max::Tls1_0 => 0,
        Max::Tls1_1 => 1,
        Max::Tls1_2 => 2,
    };
    Some(match (min, max) {
        (0, 0) => concat_ciphers!(":-VERS-SSL3.0:-VERS-TLS-ALL:+VERS-TLS1.0"),
        (0, 1) => concat_ciphers!(":-VERS-SSL3.0:-VERS-TLS-ALL:+VERS-TLS1.1:+VERS-TLS1.0"),
        (0, 2) => {
            concat_ciphers!(":-VERS-SSL3.0:-VERS-TLS-ALL:+VERS-TLS1.2:+VERS-TLS1.1:+VERS-TLS1.0")
        }
        (1, 1) => concat_ciphers!(":-VERS-SSL3.0:-VERS-TLS-ALL:+VERS-TLS1.1"),
        (1, 2) => concat_ciphers!(":-VERS-SSL3.0:-VERS-TLS-ALL:+VERS-TLS1.2:+VERS-TLS1.1"),
        (2, 2) => concat_ciphers!(":-VERS-SSL3.0:-VERS-TLS-ALL:+VERS-TLS1.2"),
        (3, 3) => concat_ciphers!(":-VERS-SSL3.0:-VERS-TLS-ALL:+VERS-TLS1.3"),
        (0, 3) => concat_ciphers!(":-VERS-SSL3.0"),
        (1, 3) => {
            concat_ciphers!(":-VERS-SSL3.0:-VERS-TLS-ALL:+VERS-TLS1.3:+VERS-TLS1.2:+VERS-TLS1.1")
        }
        (2, 3) => concat_ciphers!(":-VERS-SSL3.0:-VERS-TLS-ALL:+VERS-TLS1.3:+VERS-TLS1.2"),
        _ => return None,
    })
}

/// The priority string of `base`, the versions', and `ciphers`, the
/// transfer's list (`CURLOPT_SSL_CIPHER_LIST`), as a C string: a list
/// that starts with `+`, `-` or `!` is added to `base`, any other
/// replaces it.
pub(crate) fn string(base: &str, ciphers: Option<&[u8]>) -> Result<Vec<u8>, ErrorKind> {
    let oom = |_: curl_alloc::OutOfMemory| ErrorKind::OutOfMemory;
    let mut out = Vec::new();
    match ciphers {
        Some(c) if matches!(c.first(), Some(b'+' | b'-' | b'!')) => {
            out.try_reserve_exact(base.len() + 1 + c.len() + 1)
                .map_err(|_| ErrorKind::OutOfMemory)?;
            out.try_extend_from_slice(base.as_bytes()).map_err(oom)?;
            out.try_push(b':').map_err(oom)?;
            out.try_extend_from_slice(c).map_err(oom)?;
        }
        Some(c) => out.try_extend_from_slice(c).map_err(oom)?,
        None => out.try_extend_from_slice(base.as_bytes()).map_err(oom)?,
    }
    out.try_push(0).map_err(oom)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use TlsMaxVersion as Max;
    use TlsMinVersion as Min;

    /// Each range C names, as it names it.
    #[test]
    fn each_range_is_named_as_c_names_it() {
        let v = |min, max| versions(min, max).map(|p| p.strip_prefix(CIPHERS).expect("C's"));
        assert_eq!(
            v(Min::Tls1_2, Max::None),
            Some(":-VERS-SSL3.0:-VERS-TLS-ALL:+VERS-TLS1.3:+VERS-TLS1.2")
        );
        assert_eq!(v(Min::Tls1, Max::Default), Some(":-VERS-SSL3.0"));
        assert_eq!(v(Min::Tls1_0, Max::Tls1_3), Some(":-VERS-SSL3.0"));
        assert_eq!(
            v(Min::Tls1_0, Max::Tls1_0),
            Some(":-VERS-SSL3.0:-VERS-TLS-ALL:+VERS-TLS1.0")
        );
        assert_eq!(
            v(Min::Tls1_0, Max::Tls1_1),
            Some(":-VERS-SSL3.0:-VERS-TLS-ALL:+VERS-TLS1.1:+VERS-TLS1.0")
        );
        assert_eq!(
            v(Min::Tls1, Max::Tls1_2),
            Some(":-VERS-SSL3.0:-VERS-TLS-ALL:+VERS-TLS1.2:+VERS-TLS1.1:+VERS-TLS1.0")
        );
        assert_eq!(
            v(Min::Tls1_1, Max::Tls1_1),
            Some(":-VERS-SSL3.0:-VERS-TLS-ALL:+VERS-TLS1.1")
        );
        assert_eq!(
            v(Min::Tls1_1, Max::Tls1_2),
            Some(":-VERS-SSL3.0:-VERS-TLS-ALL:+VERS-TLS1.2:+VERS-TLS1.1")
        );
        assert_eq!(
            v(Min::Tls1_1, Max::None),
            Some(":-VERS-SSL3.0:-VERS-TLS-ALL:+VERS-TLS1.3:+VERS-TLS1.2:+VERS-TLS1.1")
        );
        assert_eq!(
            v(Min::Tls1_2, Max::Tls1_2),
            Some(":-VERS-SSL3.0:-VERS-TLS-ALL:+VERS-TLS1.2")
        );
        assert_eq!(
            v(Min::Tls1_3, Max::Default),
            Some(":-VERS-SSL3.0:-VERS-TLS-ALL:+VERS-TLS1.3")
        );
        assert_eq!(v(Min::Tls1_3, Max::Tls1_2), None);
        assert_eq!(v(Min::Tls1_2, Max::Tls1_1), None);
        assert_eq!(v(Min::Tls1_1, Max::Tls1_0), None);
    }

    /// A list opening with `+`, `-` or `!` adds to the versions' own;
    /// any other replaces it.
    #[test]
    fn a_cipher_list_adds_or_replaces() {
        assert_eq!(string("BASE", None).unwrap(), b"BASE\0");
        assert_eq!(string("BASE", Some(b"+A")).unwrap(), b"BASE:+A\0");
        assert_eq!(string("BASE", Some(b"-B")).unwrap(), b"BASE:-B\0");
        assert_eq!(string("BASE", Some(b"!C")).unwrap(), b"BASE:!C\0");
        assert_eq!(string("BASE", Some(b"NONE:+D")).unwrap(), b"NONE:+D\0");
    }
}
