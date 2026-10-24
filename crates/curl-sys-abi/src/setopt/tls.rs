//! The TLS options of `curl_easy_setopt` that say who the client is and
//! how far the peer is checked past its chain (`lib/setopt.c`): the
//! revocation list and the pinned key, the client's certificate and key
//! with their types and password, each taken as C takes it.

use curl_core::options::{Options, TlsOptions};

use super::{Arg, Refused, blob, owned};
use crate::ffi::{self, CURLoption};

/// `option` is one this module sets.
pub(super) fn takes(option: CURLoption) -> bool {
    [
        ffi::CURLOPT_CRLFILE,
        ffi::CURLOPT_PINNEDPUBLICKEY,
        ffi::CURLOPT_SSLCERT,
        ffi::CURLOPT_SSLCERT_BLOB,
        ffi::CURLOPT_SSLCERTTYPE,
        ffi::CURLOPT_SSLKEY,
        ffi::CURLOPT_SSLKEY_BLOB,
        ffi::CURLOPT_SSLKEYTYPE,
        ffi::CURLOPT_KEYPASSWD,
    ]
    .contains(&option)
}

/// Set `option`, one `takes` names, to `arg`.
pub(super) fn apply(options: &mut Options, option: CURLoption, arg: Arg) -> Result<(), Refused> {
    let tls = &mut options.tls.options;
    match (option, arg) {
        (ffi::CURLOPT_CRLFILE, Arg::Ptr(p)) => {
            // SAFETY: the application passes a C string or NULL.
            let value = unsafe { owned(p) }?;
            tls.set(|t| &mut t.crl_file, value)?;
        }
        (ffi::CURLOPT_PINNEDPUBLICKEY, Arg::Ptr(p)) => {
            // SAFETY: as above.
            let value = unsafe { owned(p) }?;
            tls.set(|t| &mut t.pinned_key, value)?;
        }
        (
            ffi::CURLOPT_SSLCERT
            | ffi::CURLOPT_SSLCERTTYPE
            | ffi::CURLOPT_SSLKEY
            | ffi::CURLOPT_SSLKEYTYPE
            | ffi::CURLOPT_KEYPASSWD,
            Arg::Ptr(p),
        ) => {
            // SAFETY: as above.
            let value = unsafe { owned(p) }?;
            tls.set(text_field(option), value)?;
        }
        (ffi::CURLOPT_SSLCERT_BLOB | ffi::CURLOPT_SSLKEY_BLOB, Arg::Ptr(p)) => {
            // SAFETY: the application passes a blob or NULL.
            let value = unsafe { blob(p) }?;
            tls.set(text_field(option), value)?;
        }
        _ => unreachable!("an option `takes` names, of its type"),
    }
    Ok(())
}

/// The field a string or blob option of the client's certificate sets.
fn text_field(option: CURLoption) -> fn(&mut TlsOptions) -> &mut Option<Vec<u8>> {
    match option {
        ffi::CURLOPT_SSLCERT => |t| &mut t.cert,
        ffi::CURLOPT_SSLCERTTYPE => |t| &mut t.cert_type,
        ffi::CURLOPT_SSLKEY => |t| &mut t.key,
        ffi::CURLOPT_SSLKEYTYPE => |t| &mut t.key_type,
        ffi::CURLOPT_KEYPASSWD => |t| &mut t.key_password,
        ffi::CURLOPT_SSLCERT_BLOB => |t| &mut t.cert_blob,
        ffi::CURLOPT_SSLKEY_BLOB => |t| &mut t.key_blob,
        _ => unreachable!("a string option of the client's certificate"),
    }
}
