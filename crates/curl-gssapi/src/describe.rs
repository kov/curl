//! A status's text, as C lays it out (`Curl_gss_log_error`,
//! `check_gss_err`).

use curl_core::gss::{GssStatus, Style, TooLong};

use crate::sys::{self, Code};

/// The room `Curl_gss_log_error` writes in, its NUL included
/// (`GSS_LOG_BUFFER_LEN`).
const LOG_BUFFER: usize = 1024;

/// The most `check_gss_err`'s buffer holds, its NUL included
/// (`MAX_GSS_LEN`).
const SOCKS_BUFFER: usize = 1024;

pub(crate) fn describe(
    status: &GssStatus,
    style: Style,
    out: &mut dyn FnMut(&[u8]),
) -> Result<(), TooLong> {
    let (major, minor) = status.codes();
    match style {
        Style::Log => {
            let mut buf = [0u8; LOG_BUFFER];
            let mut len = 0;
            if major != sys::GSS_S_FAILURE {
                len = every_message(major, Code::Gss, &mut buf, len);
            }
            len = every_message(minor, Code::Mech, &mut buf, len);
            out(&buf[..len]);
            Ok(())
        }
        Style::Socks => {
            let mut buf = [0u8; SOCKS_BUFFER];
            let mut len = 0;
            for (status, code) in [(major, Code::Gss), (minor, Code::Mech)] {
                // C asks again while the call fails and says no more
                // follows, which it can do for ever; once is what it
                // takes when the call works.
                let mut context = 0;
                let (result, text) = sys::display_status(status, code, &mut context);
                if result == sys::GSS_S_COMPLETE {
                    len = add(&mut buf, len, text.bytes())?;
                }
                if matches!(code, Code::Gss) {
                    len = add(&mut buf, len, b".\n")?;
                }
            }
            out(&buf[..len]);
            Ok(())
        }
    }
}

/// Each of `status`'s messages after `len` in `buf`, followed by `". "`,
/// those that fit (`display_gss_error`): the new length.
fn every_message(status: u32, code: Code, buf: &mut [u8; LOG_BUFFER], mut len: usize) -> usize {
    let mut context = 0;
    loop {
        let (result, text) = sys::display_status(status, code, &mut context);
        let text = text.bytes();
        if result == sys::GSS_S_COMPLETE && !text.is_empty() && LOG_BUFFER > len + text.len() + 3 {
            // `%.*s` stops at a NUL.
            let text = text.split(|&b| b == 0).next().unwrap_or_default();
            buf[len..len + text.len()].copy_from_slice(text);
            len += text.len();
            buf[len..len + 2].copy_from_slice(b". ");
            len += 2;
        }
        if sys::is_error(result) || context == 0 {
            return len;
        }
    }
}

/// `bytes` added after `len` in `buf`, if they fit with the NUL that
/// would follow (`curlx_dyn_addn`): the new length.
fn add(buf: &mut [u8; SOCKS_BUFFER], len: usize, bytes: &[u8]) -> Result<usize, TooLong> {
    if len + bytes.len() + 1 > SOCKS_BUFFER {
        return Err(TooLong);
    }
    buf[len..len + bytes.len()].copy_from_slice(bytes);
    Ok(len + bytes.len())
}
