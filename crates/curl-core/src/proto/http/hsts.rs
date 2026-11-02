//! The HSTS cache in a transfer: its files and the application's entries
//! read as each transfer starts, an `http` URL to a host in it switched
//! to `https`, and what a response over HTTPS says kept. The cache is the
//! handle's own or its share's; C tells the share's lock functions only of
//! the files read.

use crate::date::cache_now as now;
use crate::error::{ErrorKind, url_error};
use crate::hsts::{HstsEntry, LoadError, PullError, StsError, pull_into};
use crate::multi::Host;
use crate::multi::state::StepCx;
use crate::trace;
use crate::url::{GetOptions, Part, SetOptions, Url};

/// Read the files named and what the application's reader gives into
/// the cache, if it is on (`Curl_hsts_loadfiles`, `Curl_hsts_loadcb`).
pub(crate) fn load<H: Host>(cx: &mut StepCx<'_, H>) -> Result<(), ErrorKind> {
    let now = now(cx.unix_time());
    let easy = cx.easy_mut();
    easy.load_hsts_files(now).map_err(|e| match e {
        LoadError::OutOfMemory => ErrorKind::OutOfMemory,
        LoadError::Read => ErrorKind::ReadError,
        LoadError::TooLarge => ErrorKind::TooLarge,
    })?;
    let Some(reader) = easy.options().http.hsts.read.clone() else {
        return Ok(());
    };
    if !easy.hsts_enabled() {
        return Ok(());
    }
    // Each entry is kept under the share's lock, the application's reader
    // called out of it.
    let mut keep = |entry: HstsEntry<'_>| easy.with_hsts(|h| h.add(entry, now)).unwrap_or(Ok(()));
    pull_into(&*reader, &mut keep).map_err(|e| match e {
        PullError::Aborted => ErrorKind::AbortedByCallback,
        PullError::Invalid => ErrorKind::BadFunctionArgument,
        PullError::OutOfMemory => ErrorKind::OutOfMemory,
    })
}

/// Switch `url` to `https` if it is an `http` one to a host the cache
/// says to reach only over HTTPS, `name` being the host as it is looked
/// up (`hsts_upgrade`). The URL read back is the transfer's from then on;
/// true if switched.
pub(crate) fn upgrade<H: Host>(
    url: &mut Url,
    name: &[u8],
    cx: &mut StepCx<'_, H>,
) -> Result<bool, ErrorKind> {
    let now = now(cx.unix_time());
    let applies = cx.easy_mut().with_hsts(|hsts| hsts.applies(name, now));
    if applies != Some(true) {
        return Ok(false);
    }
    url.set(Part::Scheme, Some(b"https"), SetOptions::NONE)
        .map_err(url_error)?;
    let whole = url.get(Part::Url, GetOptions::NONE).map_err(url_error)?;
    trace::info_with(
        cx,
        &[b"Switched from HTTP to HTTPS due to HSTS => ", &whole],
    );
    Ok(true)
}

/// Keep what a response's `Strict-Transport-Security:` field, `value`,
/// says of `host`, if the cache is on and the transfer is over HTTPS
/// (`secured`), or the debug build is told to take it over HTTP
/// (`CURL_HSTS_HTTP`). A field the cache cannot take is passed over, and
/// said so (`http_header_s`).
pub(crate) fn from_field<H: Host>(
    cx: &mut StepCx<'_, H>,
    host: &[u8],
    value: &[u8],
    secured: bool,
) -> Result<(), ErrorKind> {
    if !cx.easy().hsts_enabled() {
        return Ok(());
    }
    #[cfg(feature = "debug-hooks")]
    let secured = secured || curl_os::env::is_set(b"CURL_HSTS_HTTP");
    if !secured {
        return Ok(());
    }
    let now = now(cx.unix_time());
    let parsed = cx
        .easy_mut()
        .with_hsts(|hsts| hsts.parse(host, value.trim_ascii_start(), now))
        .expect("on, as above");
    match parsed {
        Err(StsError::OutOfMemory) => Err(ErrorKind::OutOfMemory),
        Err(StsError::Illegal) => {
            trace::info(cx, format_args!("Illegal STS header skipped"));
            Ok(())
        }
        Ok(()) => {
            #[cfg(feature = "debug-hooks")]
            {
                let n = cx.easy().read_hsts(crate::hsts::Hsts::len).unwrap_or(0);
                trace::info(cx, format_args!("Parsed STS header fine ({n} entries)"));
            }
            Ok(())
        }
    }
}
