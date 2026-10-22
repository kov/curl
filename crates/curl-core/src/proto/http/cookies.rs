//! The cookie jar as HTTP uses it: read from its files as a transfer
//! starts (`Curl_cookie_loadfiles`), given what servers set
//! (`http_header_s`), and asked what a request sends (`http_cookies`).
//!
//! The jar is the handle's own, or its share's if that keeps the cookies,
//! as C's `data->cookies` is either. A share's is used one operation at a
//! time under its lock, as C locks `CURL_LOCK_DATA_COOKIE` around each, so
//! that handles sharing the jar take turns with it whichever threads run
//! them; what an operation says is traced once the lock is let go.

use curl_alloc::{OutOfMemory, TryVec as _};

use crate::cookie::{Jar, Source, Suffixes};
use crate::easy::Easy;
use crate::error::ErrorKind;
use crate::multi::Host;
use crate::multi::state::StepCx;
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
    // A file named has turned the jar on.
    let mut texts = Vec::new();
    let named = easy.options().http.cookies.files.iter().next().is_some();
    let read = match named {
        true => read_files(cx, &mut texts).map(Some),
        false => Ok(None),
    };
    // Those read before one failed are kept, and the jar not started.
    if !texts.is_empty() || matches!(read, Ok(Some(()))) {
        let new_session = cx.easy().options().http.cookies.new_session;
        let now = cx.unix_time();
        let easy = cx.easy_mut();
        let suffixes = easy.public_suffixes().map_err(oom)?;
        let list = suffixes.as_ref().map(Suffixes::list);
        let mut set = easy.set_cookies;
        let loaded = jar_section(easy, |jar| {
            texts
                .iter()
                .try_for_each(|text| jar.load(text, new_session, false, list, now, &mut set))
        });
        easy.set_cookies = set;
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

/// Read the cookie files the options name onto `texts`, tracing those
/// that cannot be. They are taken by their place in the list, which stays
/// in the options while a file is traced: the debug handler may add one,
/// and C, walking the list it appends to, reads that one too.
fn read_files<H: Host>(cx: &mut StepCx<'_, H>, texts: &mut Vec<Vec<u8>>) -> Result<(), ErrorKind> {
    let mut at = 0;
    loop {
        let said = {
            let files = &cx.easy().options().http.cookies.files;
            let Some(name) = files.iter().nth(at) else {
                break;
            };
            at += 1;
            // An empty name reads nothing, and turns the jar on all the
            // same.
            if name.is_empty() {
                continue;
            }
            match open(name)? {
                Opened::File(mut file) => {
                    texts.try_push(read_all(&mut file)?).map_err(oom)?;
                    continue;
                }
                Opened::Missing => {
                    trace::line_with(&[b"WARNING: failed to open cookie file \"", name, b"\""])
                }
                Opened::Directory => trace::line_with(&[
                    b"WARNING: cookie filename points to a directory: \"",
                    name,
                    b"\"",
                ]),
            }
        };
        trace::info_line(cx, &said);
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
fn read_all(file: &mut impl std::io::Read) -> Result<Vec<u8>, ErrorKind> {
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
/// `value` being all after the colon, counted with the others stored
/// since the request started.
pub(super) fn set_by_server<H: Host>(
    cx: &mut StepCx<'_, H>,
    value: &[u8],
    site: &Site<'_>,
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
    let mut set = cx.easy().set_cookies;
    let stored = jar_section(cx.easy_mut(), |jar| {
        let said = jar.set_by(value, source, list, now, &mut set)?;
        if let Some(said) = said {
            said.lines(|parts| held.hold(parts));
        }
        Ok(())
    });
    cx.easy_mut().set_cookies = set;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_host_is_secure() {
        for (host, secure) in [
            (&b"localhost"[..], true),
            (b"LocalHost", true),
            (b"127.0.0.1", true),
            (b"::1", true),
            (b"example.com", false),
            (b"127.0.0.2", false),
            (b"::2", false),
            (b"localhost.example", false),
        ] {
            let site = Site { host, path: b"/" };
            assert_eq!(site.secure(), secure, "{}", host.escape_ascii());
        }
    }

    fn held() -> Held {
        Held {
            verbose: true,
            lines: Vec::new(),
            failed: false,
        }
    }

    /// The `Cookie:` value the jar `file` gives a request to example.com,
    /// whether the line is full, and what was said.
    fn cookie_line(file: &[u8]) -> (String, bool, Vec<String>) {
        let mut jar = Jar::default();
        jar.load(file, false, false, None, 0, &mut 0).unwrap();
        let site = Site {
            host: b"example.com",
            path: b"/",
        };
        let mut held = held();
        let (mut value, mut count, mut full) = (Vec::new(), 0, false);
        jar_cookies(
            &mut jar, &site, 0, &mut held, &mut value, &mut count, &mut full,
        )
        .unwrap();
        let said = held
            .lines
            .iter()
            .map(|l| String::from_utf8(l.clone()).unwrap())
            .collect();
        (String::from_utf8(value).unwrap(), full, said)
    }

    fn cookie(name: &str, value_len: usize) -> String {
        format!(
            "example.com\tFALSE\t/\tFALSE\t0\t{name}\t{}\n",
            "v".repeat(value_len)
        )
    }

    #[test]
    fn the_line_holds_8190_bytes_with_its_name() {
        // "Cookie: " and `a=` and the value, short of 8190.
        let (value, full, said) = cookie_line(cookie("a", 8179).as_bytes());
        assert_eq!((value.len(), full, said.len()), (8181, false, 0));
        let (value, full, said) = cookie_line(cookie("a", 8180).as_bytes());
        assert_eq!((value.as_str(), full), ("", true));
        assert_eq!(
            said,
            ["Restricted outgoing cookies due to header size, 'a' not sent"]
        );
    }

    #[test]
    fn each_cookie_after_the_first_counts_its_separator() {
        // Sent longest name first, each fitting with all before it but
        // its own separator: 8 for "Cookie: ", 5 for `ccc=v`, 2 + 103 for
        // `; bb=` and its value, and 1 + 8069 + 1 for `a=` and its value
        // make 8189.
        let three = |a: usize| [cookie("ccc", 1), cookie("bb", 100), cookie("a", a)].concat();
        let (value, full, _) = cookie_line(three(8069).as_bytes());
        assert!(!full);
        assert_eq!(
            value,
            format!("ccc=v; bb={}; a={}", "v".repeat(100), "v".repeat(8069))
        );
        let (value, full, said) = cookie_line(three(8070).as_bytes());
        assert!(full);
        assert_eq!(value, format!("ccc=v; bb={}", "v".repeat(100)));
        assert_eq!(
            said,
            ["Restricted outgoing cookies due to header size, 'a' not sent"]
        );
    }

    #[test]
    fn lines_are_held_only_for_a_verbose_transfer_and_until_one_fails() {
        let mut quiet = Held {
            verbose: false,
            ..held()
        };
        quiet.hold(&[b"a"]);
        assert!(quiet.lines.is_empty());
        // Those after one that could not be held are not held either, so
        // that what is traced is all that was said up to the failure.
        let mut failed = Held {
            failed: true,
            ..held()
        };
        failed.hold(&[b"a"]);
        assert!(failed.lines.is_empty());
        let mut held = held();
        held.hold(&[b"a", b"b"]);
        assert_eq!(held.lines, [b"ab".to_vec()]);
    }

    /// A reader giving `pieces` in turn, then the end.
    struct Pieces(Vec<std::io::Result<Vec<u8>>>);

    impl std::io::Read for Pieces {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.0.is_empty() {
                return Ok(0);
            }
            let piece = self.0.remove(0)?;
            buf[..piece.len()].copy_from_slice(&piece);
            Ok(piece.len())
        }
    }

    #[test]
    fn a_read_is_retried_when_interrupted_and_fails_otherwise() {
        let interrupted = || Err(std::io::ErrorKind::Interrupted.into());
        let mut reader = Pieces(vec![Ok(b"ab".to_vec()), interrupted(), Ok(b"c".to_vec())]);
        assert_eq!(read_all(&mut reader), Ok(b"abc".to_vec()));
        let mut reader = Pieces(vec![
            Ok(b"ab".to_vec()),
            Err(std::io::ErrorKind::Other.into()),
            Ok(b"c".to_vec()),
        ]);
        assert_eq!(read_all(&mut reader), Err(ErrorKind::ReadError));
    }

    #[test]
    fn a_cookie_file_is_read_whole_if_it_is_one() {
        let dir = std::env::temp_dir().join(format!("curl-cookie-read-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("jar");
        let text = "x".repeat(10_000);
        std::fs::write(&file, &text).unwrap();
        let name = |p: &std::path::Path| p.as_os_str().as_encoded_bytes().to_vec();
        assert_eq!(read_file(&name(&file)), Ok(Some(text.into_bytes())));
        assert_eq!(read_file(&name(&dir)), Ok(None));
        assert_eq!(read_file(&name(&dir.join("missing"))), Ok(None));
        assert_eq!(read_file(b""), Ok(None));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
