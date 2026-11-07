//! The suites mbedTLS offers, of the cipher lists the transfer gives
//! (`mbed_set_selected_ciphers`), by the core's table of their names
//! (`lib/vtls/cipher_suite.c`).

use curl_alloc::{OutOfMemory, TryVec as _};
use curl_core::error::ErrorKind;
use curl_core::tls::TlsCx;

use crate::library::Mbedtls;

pub(crate) use curl_core::tls::suites::name;

/// The suites to offer, of those the library has, as the cipher lists
/// before TLS 1.3 (`tls12`) and for it (`tls13`) name them, one at least
/// set (`mbed_set_selected_ciphers`), as the core selects them, ended by
/// 0 as the library takes them. `SslCipher` if none is left.
pub(crate) fn select<G: Mbedtls>(
    lib: &G,
    io: &mut TlsCx<'_>,
    tls12: Option<&[u8]>,
    tls13: Option<&[u8]>,
) -> Result<Vec<i32>, ErrorKind> {
    let is13 = |id: i32| lib.suite_name(id).starts_with(b"TLS1-3");
    // Every suite the library has is numbered within 16 bits; one that is
    // not is no suite a list can name.
    let id = |s: i32| u16::try_from(s).unwrap_or(0);
    let mut selected =
        curl_core::tls::suites::select(io, "mbedTLS", lib.suites(), id, is13, tls12, tls13)?;
    selected
        .try_push(0)
        .map_err(|OutOfMemory| ErrorKind::OutOfMemory)?;
    Ok(selected)
}
