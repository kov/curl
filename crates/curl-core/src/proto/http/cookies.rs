//! The cookie jar as HTTP uses it: read from its files as a transfer
//! starts (`Curl_cookie_loadfiles`), given what servers set
//! (`http_header_s`), and asked what a request sends (`http_cookies`).
//!
//! The jar is taken out of the handle while it is used, so that what it
//! says can be traced, and put back however that ends.

use std::io::Read as _;

use curl_alloc::{OutOfMemory, TryVec as _};

use crate::cookie::{Jar, Source};
use crate::error::ErrorKind;
use crate::multi::Host;
use crate::multi::state::StepCx;
use crate::options::Lines;
use crate::proto::http1::request::{SameOrigin, UserHeaders};
use crate::trace;

/// The longest `Cookie:` line a request sends (`MAX_COOKIE_HEADER_LEN`).
const MAX_LINE: usize = 8190;

/// Where a request goes, as its cookies see it.
pub(super) struct Site<'a> {
    /// The custom `Host:` header's name, where one is sent, else the
    /// URL's host.
    pub(super) host: &'a [u8],
    /// The URL's path, without its query.
    pub(super) path: &'a [u8],
}

impl Site<'_> {
    /// Whether secure cookies go and may be set: over a secure
    /// connection, or to this host (`Curl_secure_context`).
    fn secure(&self) -> bool {
        self.host.eq_ignore_ascii_case(b"localhost")
            || self.host == b"127.0.0.1"
            || self.host == b"::1"
    }
}

/// The name a custom `Host:` header gives, where one is sent, for the
/// cookies (`req.cookiehost`): without a port, and an IPv6 address out of
/// its brackets. An empty one gives none.
pub(super) fn custom_host(
    headers: &UserHeaders,
    same: Option<SameOrigin>,
) -> Result<Option<Vec<u8>>, OutOfMemory> {
    let Some(value) = same.and_then(|same| headers.host_value(same)) else {
        return Ok(None);
    };
    if value.is_empty() {
        return Ok(None);
    }
    let mut host = Vec::new();
    match value.split_first() {
        Some((b'[', inner)) => {
            // C moves all but the last byte over the bracket, so that
            // without a closing one the last byte is there twice.
            host.try_extend_from_slice(inner)?;
            host.try_push(value[value.len() - 1])?;
            if let Some(at) = host.iter().position(|&b| b == b']') {
                host.truncate(at);
            }
        }
        _ => {
            let end = value.iter().position(|&b| b == b':').unwrap_or(value.len());
            host.try_extend_from_slice(&value[..end])?;
        }
    }
    Ok(Some(host))
}

/// Turn the jar on if the options want it, read the cookie files into it
/// and start it, as each transfer starts (`Curl_cookie_loadfiles`,
/// `Curl_cookie_run`).
pub(crate) fn load<H: Host>(cx: &mut StepCx<'_, H>) -> Result<(), ErrorKind> {
    let easy = cx.easy_mut();
    if easy.options().http.cookies.wanted() && easy.cookies.is_none() {
        easy.cookies = Some(Jar::default());
    }
    let Some(mut jar) = easy.cookies.take() else {
        return Ok(());
    };
    // Out of the options while the trace is reached; put back however
    // reading them ends.
    let files = std::mem::take(&mut cx.easy_mut().options_mut().http.cookies.files);
    let read = read_files(cx, &mut jar, &files);
    if read.is_ok() {
        jar.start();
    }
    let easy = cx.easy_mut();
    easy.options_mut().http.cookies.files = files;
    easy.cookies = Some(jar);
    read
}

fn read_files<H: Host>(
    cx: &mut StepCx<'_, H>,
    jar: &mut Jar,
    files: &Lines,
) -> Result<(), ErrorKind> {
    let new_session = cx.easy().options().http.cookies.new_session;
    for name in files.iter() {
        // An empty name reads nothing, and turns the jar on all the same.
        if name.is_empty() {
            continue;
        }
        let text = match open(name)? {
            Opened::File(mut file) => read_all(&mut file)?,
            Opened::Missing => {
                trace::info_with(
                    cx,
                    &[b"WARNING: failed to open cookie file \"", name, b"\""],
                );
                continue;
            }
            Opened::Directory => {
                trace::info_with(
                    cx,
                    &[
                        b"WARNING: cookie filename points to a directory: \"",
                        name,
                        b"\"",
                    ],
                );
                continue;
            }
        };
        jar.load(&text, new_session, false, None, cx.unix_time())
            .map_err(oom)?;
    }
    Ok(())
}

/// A cookie file, as it was opened.
enum Opened {
    File(std::fs::File),
    Missing,
    Directory,
}

/// Open the cookie file `name`, `-` standard input (`cookie_load`).
fn open(name: &[u8]) -> Result<Opened, ErrorKind> {
    let file = if name == b"-" {
        curl_os::fs::stdin()
    } else {
        let mut path = Vec::new();
        path.try_extend_from_slice(name).map_err(oom)?;
        path.try_push(0).map_err(oom)?;
        match std::ffi::CStr::from_bytes_with_nul(&path) {
            Ok(path) => curl_os::fs::open_read(path),
            Err(_) => Err(std::io::ErrorKind::InvalidInput.into()),
        }
    };
    let Ok(file) = file else {
        return Ok(Opened::Missing);
    };
    if file.metadata().is_ok_and(|m| m.is_dir()) {
        return Ok(Opened::Directory);
    }
    Ok(Opened::File(file))
}

/// The text of the cookie file `name`, none if it is no file or cannot
/// be opened; an empty name reads none.
pub(crate) fn read_file(name: &[u8]) -> Result<Option<Vec<u8>>, ErrorKind> {
    if name.is_empty() {
        return Ok(None);
    }
    match open(name)? {
        Opened::File(mut file) => read_all(&mut file).map(Some),
        Opened::Missing | Opened::Directory => Ok(None),
    }
}

/// The whole of `file`; a read that fails fails the transfer, as C's
/// `Curl_get_line` fails it.
fn read_all(file: &mut std::fs::File) -> Result<Vec<u8>, ErrorKind> {
    let mut text = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match file.read(&mut chunk) {
            Ok(0) => return Ok(text),
            Ok(n) => text.try_extend_from_slice(&chunk[..n]).map_err(oom)?,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(ErrorKind::ReadError),
        }
    }
}

/// Give the jar a cookie a server sets in its `Set-Cookie:` field,
/// `value` being all after the colon. `set` counts those this request has
/// stored.
pub(super) fn set_by_server<H: Host>(
    cx: &mut StepCx<'_, H>,
    value: &[u8],
    site: &Site<'_>,
    set: &mut u8,
) -> Result<(), ErrorKind> {
    let Some(mut jar) = cx.easy_mut().cookies.take() else {
        return Ok(());
    };
    let source = Source::Server {
        host: site.host,
        path: site.path,
        secure: site.secure(),
    };
    let now = cx.unix_time();
    let stored = match jar.set_by(value, source, None, now, set) {
        Ok(said) => {
            if let Some(said) = said {
                said.line(|parts| trace::info_with(cx, parts));
            }
            Ok(())
        }
        Err(OutOfMemory) => Err(ErrorKind::OutOfMemory),
    };
    cx.easy_mut().cookies = Some(jar);
    stored
}

/// What the request's `Cookie:` line says, if it has one (`http_cookies`):
/// the jar's cookies for the site, longest path first, then the
/// application's own if `application`.
pub(super) fn request_value<H: Host>(
    cx: &mut StepCx<'_, H>,
    site: &Site<'_>,
    application: bool,
) -> Result<Option<Vec<u8>>, ErrorKind> {
    let mut value = Vec::new();
    let mut count = 0;
    // The line is full: the application's do not go either.
    let mut full = false;
    if let Some(mut jar) = cx.easy_mut().cookies.take() {
        let made = jar_cookies(cx, &mut jar, site, &mut value, &mut count, &mut full);
        cx.easy_mut().cookies = Some(jar);
        made?;
    }
    if application && !full {
        let send = cx.easy().options().http.cookies.send.as_deref();
        let send = send.expect("asked for only where the application sends some");
        if count > 0 {
            value.try_extend_from_slice(b"; ").map_err(oom)?;
        }
        value.try_extend_from_slice(send).map_err(oom)?;
        count += 1;
    }
    Ok((count > 0).then_some(value))
}

fn jar_cookies<H: Host>(
    cx: &mut StepCx<'_, H>,
    jar: &mut Jar,
    site: &Site<'_>,
    value: &mut Vec<u8>,
    count: &mut usize,
    full: &mut bool,
) -> Result<(), ErrorKind> {
    jar.sweep(cx.unix_time());
    let matching = jar
        .matching(site.host, site.path, site.secure())
        .map_err(oom)?;
    if matching.capped {
        matching.capped_line(|parts| trace::info_with(cx, parts));
    }
    // "Cookie: " counts.
    let mut len = 8;
    for co in &matching.cookies {
        let add = co.name().len() + co.value().len() + 1;
        if len + add >= MAX_LINE {
            trace::info_with(
                cx,
                &[
                    b"Restricted outgoing cookies due to header size, '",
                    co.name(),
                    b"' not sent",
                ],
            );
            *full = true;
            break;
        }
        if *count > 0 {
            value.try_extend_from_slice(b"; ").map_err(oom)?;
            len += 2;
        }
        value.try_extend_from_slice(co.name()).map_err(oom)?;
        value.try_push(b'=').map_err(oom)?;
        value.try_extend_from_slice(co.value()).map_err(oom)?;
        len += add;
        *count += 1;
    }
    Ok(())
}

fn oom(_: OutOfMemory) -> ErrorKind {
    ErrorKind::OutOfMemory
}
