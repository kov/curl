//! The cookie jar as HTTP uses it: read from its files as a transfer
//! starts (`Curl_cookie_loadfiles`), given what servers set
//! (`http_header_s`), and asked what a request sends (`http_cookies`).
//!
//! The jar is the handle's own, or its share's if that keeps the cookies,
//! as C's `data->cookies` is either. A share's is used one operation at a
//! time under its lock, as C locks `CURL_LOCK_DATA_COOKIE` around each, so
//! that handles sharing the jar take turns with it whichever threads run
//! them; what an operation says is traced once the lock is let go.

use std::io::Read as _;

use curl_alloc::{OutOfMemory, TryVec as _};

use crate::cookie::{Jar, Source, Suffixes};
use crate::easy::Easy;
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
    if easy.options().http.cookies.wanted() {
        easy.enable_cookies();
    }
    let on = easy.cookies.is_some();
    // Out of the options while the trace is reached; put back however
    // reading them ends.
    let files = std::mem::take(&mut easy.options_mut().http.cookies.files);
    let mut texts = Vec::new();
    let read = match on && files.iter().next().is_some() {
        true => read_files(cx, &files, &mut texts).map(Some),
        false => Ok(None),
    };
    cx.easy_mut().options_mut().http.cookies.files = files;
    // Those read before one failed are kept, and the jar not started.
    if !texts.is_empty() || matches!(read, Ok(Some(()))) {
        let new_session = cx.easy().options().http.cookies.new_session;
        let now = cx.unix_time();
        let easy = cx.easy_mut();
        let suffixes = easy.public_suffixes().map_err(oom)?;
        let list = suffixes.as_ref().map(Suffixes::list);
        let loaded = jar_section(easy, |jar| {
            texts
                .iter()
                .try_for_each(|text| jar.load(text, new_session, false, list, now))
        });
        loaded.expect("on, checked above").map_err(oom)?;
    }
    read?;
    // Started, a use of the share's cookies whether or not the handle's
    // jar is on.
    let easy = cx.easy_mut();
    if jar_section(easy, Jar::start).is_none() {
        easy.watch_shared_jar();
    }
    Ok(())
}

/// Run `f` on the jar the handle uses, if its jar is on: its share's, if
/// that keeps the cookies, as one use of it, else its own.
fn jar_section<R>(easy: &mut Easy, f: impl FnOnce(&mut Jar) -> R) -> Option<R> {
    easy.cookies.as_ref()?;
    match easy.with_shared_jar(f) {
        Ok(r) => r,
        Err(f) => easy.cookies.as_mut().map(f),
    }
}

/// Read the cookie files `files` names onto `texts`, tracing those that
/// cannot be.
fn read_files<H: Host>(
    cx: &mut StepCx<'_, H>,
    files: &Lines,
    texts: &mut Vec<Vec<u8>>,
) -> Result<(), ErrorKind> {
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
        texts.try_push(text).map_err(oom)?;
    }
    Ok(())
}

/// Trace lines said while the jar was in use, traced once it is not; held
/// only for a verbose transfer.
struct Held {
    verbose: bool,
    lines: Vec<Vec<u8>>,
    /// A line could not be held, for want of memory.
    failed: bool,
}

impl Held {
    fn new<H: Host>(cx: &StepCx<'_, H>) -> Held {
        Held {
            verbose: cx.easy().options().output.verbose,
            lines: Vec::new(),
            failed: false,
        }
    }

    fn hold(&mut self, parts: &[&[u8]]) {
        if !self.verbose || self.failed {
            return;
        }
        let mut line = Vec::new();
        let made = parts
            .iter()
            .try_for_each(|part| line.try_extend_from_slice(part));
        self.failed = made.and_then(|()| self.lines.try_push(line)).is_err();
    }

    /// Trace the lines held.
    fn trace<H: Host>(self, cx: &mut StepCx<'_, H>) -> Result<(), ErrorKind> {
        for line in &self.lines {
            trace::info_with(cx, &[line]);
        }
        match self.failed {
            true => Err(ErrorKind::OutOfMemory),
            false => Ok(()),
        }
    }
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
    if cx.easy().cookies.is_none() {
        return Ok(());
    }
    let suffixes = cx.easy_mut().public_suffixes().map_err(oom)?;
    let list = suffixes.as_ref().map(Suffixes::list);
    let source = Source::Server {
        host: site.host,
        path: site.path,
        secure: site.secure(),
    };
    let now = cx.unix_time();
    let mut held = Held::new(cx);
    let stored = jar_section(cx.easy_mut(), |jar| {
        let said = jar.set_by(value, source, list, now, set)?;
        if let Some(said) = said {
            said.lines(|parts| held.hold(parts));
        }
        Ok(())
    });
    held.trace(cx)?;
    stored.expect("on, checked above").map_err(oom)
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
    let now = cx.unix_time();
    let mut held = Held::new(cx);
    let made = jar_section(cx.easy_mut(), |jar| {
        jar_cookies(jar, site, now, &mut held, &mut value, &mut count, &mut full)
    });
    held.trace(cx)?;
    made.transpose()?;
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

fn jar_cookies(
    jar: &mut Jar,
    site: &Site<'_>,
    now: i64,
    held: &mut Held,
    value: &mut Vec<u8>,
    count: &mut usize,
    full: &mut bool,
) -> Result<(), ErrorKind> {
    jar.sweep(now);
    let matching = jar
        .matching(site.host, site.path, site.secure())
        .map_err(oom)?;
    if matching.capped {
        matching.capped_line(|parts| held.hold(parts));
    }
    // "Cookie: " counts.
    let mut len = 8;
    for co in &matching.cookies {
        let add = co.name().len() + co.value().len() + 1;
        if len + add >= MAX_LINE {
            held.hold(&[
                b"Restricted outgoing cookies due to header size, '",
                co.name(),
                b"' not sent",
            ]);
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
