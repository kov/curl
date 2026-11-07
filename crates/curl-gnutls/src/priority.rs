//! The priority string a session is set to (`gnutls_set_ssl_version_min_max`,
//! `gtls_set_priority`): the versions the transfer allows, as GnuTLS
//! names them after C's own defaults, and the transfer's cipher list,
//! which adds to that or replaces it.

use std::ffi::CStr;

use curl_alloc::TryVec as _;
use curl_core::error::ErrorKind;
use curl_core::options::{TlsMaxVersion, TlsMinVersion};

/// `text`, which ends in its only zero byte, as a C string.
const fn c(text: &'static str) -> &'static CStr {
    match CStr::from_bytes_with_nul(text.as_bytes()) {
        Ok(c) => c,
        Err(_) => panic!("one zero byte, at the end"),
    }
}

/// C's defaults (`GNUTLS_CIPHERS`), then `$rest`, as a C string.
macro_rules! concat_ciphers {
    ($rest:literal) => {
        c(concat!(
            "NORMAL:%PROFILE_MEDIUM:-ARCFOUR-128:-CTYPE-ALL:+CTYPE-X509",
            $rest,
            "\0"
        ))
    };
}

/// C's defaults alone.
#[cfg(test)]
const CIPHERS: &str = "NORMAL:%PROFILE_MEDIUM:-ARCFOUR-128:-CTYPE-ALL:+CTYPE-X509";

/// The priorities of a QUIC session, whatever the transfer's versions
/// (`QUIC_PRIORITY`): TLS 1.3 alone, QUIC's ciphers and groups, and no
/// TLS 1.3 compatibility mode.
pub(crate) const QUIC: &CStr = c(concat!(
    "NORMAL:%PROFILE_MEDIUM:-VERS-ALL:+VERS-TLS1.3:-CIPHER-ALL:+AES-128-GCM:",
    "+AES-256-GCM:+CHACHA20-POLY1305:+AES-128-CCM:-GROUP-ALL:",
    "+GROUP-SECP256R1:+GROUP-X25519:+GROUP-SECP384R1:+GROUP-SECP521R1:",
    "%DISABLE_TLS13_COMPAT_MODE\0"
));

/// The priorities of the versions from `min` to `max`, as C names them,
/// TLS 1.3 the newest when none is set; none for a range C has none for
/// (`GnuTLS: cannot set TLS protocol`).
pub(crate) fn versions(min: TlsMinVersion, max: TlsMaxVersion) -> Option<&'static CStr> {
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

/// The priority string of `base`, the versions' or QUIC's, and
/// `ciphers`, the transfer's list (`CURLOPT_SSL_CIPHER_LIST`), as a C
/// string: a list that starts with `+`, `-` or `!` is added to `base`,
/// any other replaces it. Made in one allocation.
pub(crate) fn string(base: &CStr, ciphers: &[u8]) -> Result<Vec<u8>, ErrorKind> {
    let oom = |_: curl_alloc::OutOfMemory| ErrorKind::OutOfMemory;
    let base = base.to_bytes();
    let adds = matches!(ciphers.first(), Some(b'+' | b'-' | b'!'));
    let len = if adds { base.len() + 1 } else { 0 } + ciphers.len() + 1;
    let mut out = Vec::new();
    out.try_reserve_exact(len)
        .map_err(|_| ErrorKind::OutOfMemory)?;
    if adds {
        out.try_extend_from_slice(base).map_err(oom)?;
        out.try_push(b':').map_err(oom)?;
    }
    out.try_extend_from_slice(ciphers).map_err(oom)?;
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
        let v = |min, max| {
            versions(min, max).map(|p| p.to_str().unwrap().strip_prefix(CIPHERS).expect("C's"))
        };
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
        // Made to its length, so never grown.
        let made = |ciphers: &[u8]| {
            let s = string(c"BASE", ciphers).unwrap();
            assert_eq!(s.capacity(), s.len(), "one allocation");
            s
        };
        assert_eq!(made(b"+A"), b"BASE:+A\0");
        assert_eq!(made(b"-B"), b"BASE:-B\0");
        assert_eq!(made(b"!C"), b"BASE:!C\0");
        assert_eq!(made(b"NONE:+D"), b"NONE:+D\0");
    }
}
