//! The TLS options of `curl_easy_setopt` that say who the client is and
//! how far the peer is checked past its chain (`lib/setopt.c`): the
//! revocation list and the pinned key, each taken as C takes it.

use curl_core::options::Options;

use super::{Arg, Refused, owned};
use crate::ffi::{self, CURLoption};

/// `option` is one this module sets.
pub(super) fn takes(option: CURLoption) -> bool {
    [ffi::CURLOPT_CRLFILE, ffi::CURLOPT_PINNEDPUBLICKEY].contains(&option)
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
        _ => unreachable!("an option `takes` names, of its type"),
    }
    Ok(())
}
