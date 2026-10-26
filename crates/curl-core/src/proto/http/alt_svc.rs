//! The alt-svc cache in a transfer: what a response's `Alt-Svc:` field
//! says kept (`http_header_a`). The cache is consulted as a transfer
//! picks its peer (`multi::state`).

use crate::altsvc::Alpn;
use crate::conn::Peer;
use crate::date::cache_now;
use crate::error::ErrorKind;
use crate::multi::Host;
use crate::multi::state::StepCx;
use crate::trace;

/// Keep what a response's `Alt-Svc:` field, `value` as it follows the
/// name, says of `origin`, if the cache is on and the transfer is over
/// HTTPS (`secured`), or the debug build is told to take it over HTTP
/// (`CURL_ALTSVC_HTTP`): its alternatives are to the origin in `over`,
/// the version the response came in.
pub(crate) fn from_field<H: Host>(
    cx: &mut StepCx<'_, H>,
    origin: &Peer,
    over: Alpn,
    value: &[u8],
    secured: bool,
) -> Result<(), ErrorKind> {
    if cx.easy().alt_svc().is_none() {
        return Ok(());
    }
    #[cfg(feature = "debug-hooks")]
    let secured = secured || curl_os::env::is_set(b"CURL_ALTSVC_HTTP");
    if !secured {
        return Ok(());
    }
    let now = cache_now(cx.unix_time());
    // Taken out while it is parsed, so that what parsing says is traced
    // as it is said: the debug handler may use the handle.
    let on = cx.easy_mut().alt_svc_mut().expect("on, as above");
    let mut alt_svc = std::mem::take(on);
    let origin = (origin.name(), origin.port(), over);
    let parsed = alt_svc.parse(value, origin, now, &mut |args| trace::info(cx, args));
    *cx.easy_mut().alt_svc_mut().expect("on still") = alt_svc;
    parsed.map_err(|_| ErrorKind::OutOfMemory)
}
