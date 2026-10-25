//! The HSTS cache in a transfer: its files and the application's entries
//! read as each transfer starts, an `http` URL to a host in it switched
//! to `https`, and what a response over HTTPS says kept.

use crate::date::cache_now as now;
use crate::error::{ErrorKind, url_error};
use crate::hsts::{LoadError, PullError, StsError};
use crate::multi::Host;
use crate::multi::state::StepCx;
use crate::trace;
use crate::url::{GetOptions, Part, SetOptions, Url};

/// Read the files named and what the application's reader gives into
/// the cache, if it is on (`Curl_hsts_loadfiles`, `Curl_hsts_loadcb`).
pub(crate) fn load<H: Host>(cx: &mut StepCx<'_, H>) -> Result<(), ErrorKind> {
    let now = now(cx.unix_time());
    let easy = cx.easy_mut();
    let Some(hsts) = easy.hsts_mut() else {
        return Ok(());
    };
    hsts.load_named(now).map_err(|e| match e {
        LoadError::OutOfMemory => ErrorKind::OutOfMemory,
        LoadError::Read => ErrorKind::ReadError,
        LoadError::TooLarge => ErrorKind::TooLarge,
    })?;
    let Some(reader) = easy.options().http.hsts.read.clone() else {
        return Ok(());
    };
    let hsts = easy.hsts_mut().expect("on, as above");
    hsts.pull(&*reader, now).map_err(|e| match e {
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
    let Some(hsts) = cx.easy_mut().hsts_mut() else {
        return Ok(false);
    };
    if !hsts.applies(name, now) {
        return Ok(false);
    }
    url.set(Part::Scheme, Some(b"https"), SetOptions::NONE)
        .map_err(url_error)?;
    let whole = url.get(Part::Url, GetOptions::NONE).map_err(url_error)?;
    let shown = trace::Bytes(&whole);
    trace::info(
        cx,
        format_args!("Switched from HTTP to HTTPS due to HSTS => {shown}"),
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
    if cx.easy().hsts().is_none() {
        return Ok(());
    }
    #[cfg(feature = "debug-hooks")]
    let secured = secured || curl_os::env::is_set(b"CURL_HSTS_HTTP");
    if !secured {
        return Ok(());
    }
    let now = now(cx.unix_time());
    let hsts = cx.easy_mut().hsts_mut().expect("on, as above");
    match hsts.parse(host, value.trim_ascii_start(), now) {
        Err(StsError::OutOfMemory) => Err(ErrorKind::OutOfMemory),
        Err(StsError::Illegal) => {
            trace::info(cx, format_args!("Illegal STS header skipped"));
            Ok(())
        }
        Ok(()) => {
            #[cfg(feature = "debug-hooks")]
            {
                let n = cx.easy().hsts().map_or(0, crate::hsts::Hsts::len);
                trace::info(cx, format_args!("Parsed STS header fine ({n} entries)"));
            }
            Ok(())
        }
    }
}
