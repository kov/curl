//! The easy handle: one transfer's configuration, added to a multi to run.

use std::fmt;
use std::io::Write as _;
use std::time::Duration;

use curl_alloc::{OutOfMemory, TryVec as _, try_box};

use crate::coding::Decoders;
use crate::conn::io::SystemNet;
use crate::cookie::{Jar, Suffixes};
use crate::error::{Error, ErrorKind, MultiErrorKind};
use crate::handler::Handler;
use crate::id::ArenaPolicy;
use crate::multi::{AddError, Env, Multi, NoEvents, WaitMode, drive_by_events};
use crate::options::{Lines, Options};
use crate::proto::http::auth::Auth;
use crate::report::TransferReport;
use crate::save::{self, SaveError};
use crate::share::{Kind, Share, ShareLock, watched};
use crate::time::{Clock as _, SystemClock};

/// A transfer's configuration. `Multi::add` takes it by value to run it
/// and `Multi::remove` gives it back; `perform` runs it on its own. The
/// default allocates nothing.
#[derive(Debug, Default)]
pub struct Easy {
    options: Options,
    /// The current or last transfer's.
    report: TransferReport,
    /// The progress meter's titles are out: a handle writes them once.
    pub(crate) meter_titled: bool,
    /// The setting of `Options::resolve` last read into a cache.
    pub(crate) resolve_read: u64,
    /// The last list read had a `*` entry, which answers for any name
    /// (C's `wildcard_resolve`).
    pub(crate) wildcard_resolve: bool,
    /// The multi `perform` runs the handle in, kept with its connections
    /// from one to the next; `Multi::add` drops it.
    pub(crate) private: Option<Private>,
    /// Authenticating with the origin, from one transfer to the next.
    pub(crate) auth: Auth,
    /// The cookie jar, once the options or the application turn it on
    /// (C's `cookies` with `cookie_engine`): kept from one transfer to
    /// the next, and through `reset`. On a share that keeps cookies, the
    /// share's is used in its place, and this one only says the jar is on.
    pub(crate) cookies: Option<Jar>,
    /// Where connections, resolved names and cookies are kept for the
    /// transfers after, if not in the handle's own multi (`CURLOPT_SHARE`,
    /// C's `data->share`): kept through `reset`, not copied with the
    /// handle.
    share: Option<Share>,
    /// Told around each use the transfers make of what the share keeps;
    /// goes with the share.
    pub(crate) share_watch: Option<Handler<dyn ShareLock>>,
    /// The public suffixes cookies are checked against: without them, a
    /// domain needs a dot, as in C built without libpsl.
    suffixes: SuffixList,
    /// The content codings the handle can undo.
    decoders: Decoders,
}

/// Where a handle's public suffixes come from.
#[derive(Debug, Default)]
enum SuffixList {
    #[default]
    None,
    Given(Suffixes),
    /// Made the first time they are wanted.
    Made(fn() -> Result<Suffixes, OutOfMemory>),
}

/// A handle's own multi (C's `multi_easy`).
pub(crate) struct Private(Box<Multi>);

impl fmt::Debug for Private {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Private")
    }
}

/// How long a perform waits for something to happen before looking again.
const POLL: Duration = Duration::from_millis(1000);

impl Easy {
    pub fn new() -> Easy {
        Easy::default()
    }

    pub fn options(&self) -> &Options {
        &self.options
    }

    /// The authentication state, beside the options it reads.
    pub(crate) fn auth_with_options(&mut self) -> (&mut Auth, &Options) {
        (&mut self.auth, &self.options)
    }

    pub fn options_mut(&mut self) -> &mut Options {
        &mut self.options
    }

    /// What the running or last transfer reports (`curl_easy_getinfo`).
    pub fn report(&self) -> &TransferReport {
        &self.report
    }

    /// The method of the running or last request, as
    /// `CURLINFO_EFFECTIVE_METHOD` names it: the application's custom one,
    /// even where a redirect stopped sending it, or the one the request
    /// had.
    pub fn effective_method(&self) -> &[u8] {
        if let Some(custom) = &self.options.http.custom_method {
            return custom;
        }
        self.report.method().name()
    }

    pub(crate) fn report_mut(&mut self) -> &mut TransferReport {
        &mut self.report
    }

    /// A handle with the same options (`curl_easy_duphandle`).
    pub fn try_clone(&self) -> Result<Easy, OutOfMemory> {
        Ok(Easy {
            options: self.options.try_clone()?,
            report: TransferReport::default(),
            meter_titled: false,
            resolve_read: 0,
            wildcard_resolve: false,
            auth: Auth::default(),
            private: None,
            // A jar of its own, empty, if this one's is on.
            cookies: self.cookies.as_ref().map(|_| Jar::default()),
            share: None,
            share_watch: None,
            suffixes: match &self.suffixes {
                SuffixList::Given(given) => SuffixList::Given(given.clone()),
                SuffixList::Made(make) => SuffixList::Made(*make),
                SuffixList::None => SuffixList::None,
            },
            decoders: self.decoders,
        })
    }

    /// Every option back to its default, and the report with them
    /// (`curl_easy_reset`). The private multi and the cookie jar stay.
    pub fn reset(&mut self) {
        self.options = Options::default();
        self.report = self.report.cleared();
        self.meter_titled = false;
        self.resolve_read = 0;
        self.wildcard_resolve = false;
        self.auth = Auth::default();
    }

    /// The share the handle's transfers use.
    pub fn share(&self) -> Option<&Share> {
        self.share.as_ref()
    }

    /// Use `share` for the transfers from now on, or none.
    pub fn set_share(&mut self, share: Option<Share>) {
        self.share = share;
        self.share_watch = None;
    }

    /// Use `share` for the transfers from now on, `watch` told around
    /// each use they make of what it keeps.
    pub fn set_share_watched(&mut self, share: Share, watch: Handler<dyn ShareLock>) {
        self.share = Some(share);
        self.share_watch = Some(watch);
    }

    /// What is told around each use of the share, if anything is.
    pub(crate) fn share_watch(&self) -> Option<&dyn ShareLock> {
        self.share_watch.as_deref()
    }

    /// The content codings the handle's responses can be undone from,
    /// kept through `reset` (those of the libraries C's build has).
    pub fn set_decoders(&mut self, decoders: Decoders) {
        self.decoders = decoders;
    }

    pub(crate) fn decoders(&self) -> Decoders {
        self.decoders
    }

    /// The public suffixes cookies' domains are checked against, kept
    /// through `reset` (libpsl's list, as C's build has it).
    pub fn set_public_suffixes(&mut self, suffixes: Option<Suffixes>) {
        self.suffixes = suffixes.map_or(SuffixList::None, SuffixList::Given);
    }

    /// As `set_public_suffixes`, with a list `make` makes the first time
    /// one is wanted, so that a handle no cookie needs it for costs
    /// nothing: as C loads it in the handle's multi.
    pub fn set_public_suffixes_from(&mut self, make: fn() -> Result<Suffixes, OutOfMemory>) {
        self.suffixes = SuffixList::Made(make);
    }

    /// The public suffixes, made now if they are made when wanted.
    pub(crate) fn public_suffixes(&mut self) -> Result<Option<Suffixes>, OutOfMemory> {
        if let SuffixList::Made(make) = self.suffixes {
            self.suffixes = SuffixList::Given(make()?);
        }
        Ok(match &self.suffixes {
            SuffixList::Given(given) => Some(given.clone()),
            SuffixList::Made(_) => unreachable!("made above"),
            SuffixList::None => None,
        })
    }

    /// Turn the cookie jar on: one of the handle's own, empty, if it has
    /// none (`CURLOPT_COOKIEJAR`).
    pub fn enable_cookies(&mut self) {
        if self.cookies.is_none() {
            self.cookies = Some(Jar::default());
        }
    }

    /// Forget the cookie files and the handle's own jar, with its cookies
    /// (`CURLOPT_COOKIEFILE` NULL). A share's jar is not the handle's to
    /// forget.
    pub fn forget_cookies(&mut self) {
        self.options.http.cookies.files = Lines::default();
        self.cookies = None;
    }

    /// Store a cookie the application gives, a `Set-Cookie:` line or one
    /// in the Netscape format, turning the jar on if it is not
    /// (`CURLOPT_COOKIELIST`). Its domain is not checked against the
    /// public suffixes.
    pub fn add_cookie(&mut self, line: &[u8]) -> Result<(), ErrorKind> {
        let now = SystemClock::new().unix_time();
        // C counts the line against the last request's fields, and drops
        // it silently past their limit; this counts it alone
        // (DIVERGENCE.md).
        let mut set = 0;
        let suffixes = self.public_suffixes().map_err(oom)?;
        let list = suffixes.as_ref().map(Suffixes::list);
        self.with_jar(true, |jar| jar.add_line(line, list, now, &mut set))
            .expect("made if missing")
            .map_err(oom)
    }

    /// Forget every cookie (`CURLOPT_COOKIELIST` `ALL`).
    pub fn clear_cookies(&mut self) -> Result<(), ErrorKind> {
        self.with_jar(false, Jar::clear);
        Ok(())
    }

    /// Forget the cookies that last the session (`CURLOPT_COOKIELIST`
    /// `SESS`).
    pub fn clear_session_cookies(&mut self) -> Result<(), ErrorKind> {
        self.with_jar(false, Jar::clear_session);
        Ok(())
    }

    /// Read the cookie files into the jar again, without checking their
    /// domains against the public suffixes (`CURLOPT_COOKIELIST`
    /// `RELOAD`). A file that cannot be opened is passed over.
    pub fn reload_cookies(&mut self) -> Result<(), ErrorKind> {
        let cookies = &self.options.http.cookies;
        if cookies.files.iter().next().is_none() {
            return Ok(());
        }
        let mut texts = Vec::new();
        // Each file read, even one that is not there, starts the jar.
        for name in cookies.files.iter() {
            let text = crate::proto::http::cookies::read_file(name)?;
            texts.try_push(text.unwrap_or_default()).map_err(oom)?;
        }
        let new_session = cookies.new_session;
        let now = SystemClock::new().unix_time();
        let suffixes = self.public_suffixes().map_err(oom)?;
        let list = suffixes.as_ref().map(Suffixes::list);
        self.with_jar(true, |jar| {
            texts
                .iter()
                .try_for_each(|text| jar.load(text, new_session, true, list, now))
        })
        .expect("made if missing")
        .map_err(oom)
    }

    /// Every cookie the jar holds that has a domain, as a line in the
    /// Netscape format (`CURLINFO_COOKIELIST`), those expired swept out
    /// first.
    pub fn cookie_list(&mut self) -> Result<Vec<Vec<u8>>, ErrorKind> {
        let now = SystemClock::new().unix_time();
        let listed = self.with_jar(false, |jar| -> Result<_, OutOfMemory> {
            let mut lines = Vec::new();
            if jar.len() == 0 {
                return Ok(lines);
            }
            jar.sweep(now);
            for co in jar.listed() {
                let mut line = Vec::new();
                co.netscape(&mut line)?;
                lines.try_push(line)?;
            }
            Ok(lines)
        });
        Ok(listed.transpose().map_err(oom)?.unwrap_or_default())
    }

    /// Run `f` on the jar the handle uses: its share's, if that keeps the
    /// cookies, as one use of it, else its own, made if `make` and it has
    /// none. None if there is no jar.
    fn with_jar<R>(&mut self, make: bool, f: impl FnOnce(&mut Jar) -> R) -> Option<R> {
        let f = match self.with_shared_jar(f) {
            Ok(r) => return r,
            Err(f) => f,
        };
        if make && self.cookies.is_none() {
            self.cookies = Some(Jar::default());
        }
        self.cookies.as_mut().map(f)
    }

    /// Tell the application of a use of the share's jar that makes none
    /// of it, where C locks the jar and finds nothing to do.
    pub(crate) fn watch_shared_jar(&self) {
        if let Some(share) = &self.share {
            watched(self.share_watch(), share, Kind::Cookies, || ());
        }
    }

    /// Run `f` on the share's jar, as one use of it, under its lock and
    /// with the application told around it; `Err(f)` back if the handle
    /// has no share keeping cookies.
    pub(crate) fn with_shared_jar<R, F: FnOnce(&mut Jar) -> R>(
        &self,
        f: F,
    ) -> Result<Option<R>, F> {
        let Some(share) = self.share.as_ref().filter(|s| s.keeps(Kind::Cookies)) else {
            return Err(f);
        };
        let watch = self.share_watch();
        Ok(watched(watch, share, Kind::Cookies, || {
            share.cookies().as_mut().map(f)
        }))
    }

    /// Write the cookie jar to `Cookies::save_to`, `-` standard output
    /// (`Curl_flush_cookies`): the share's, if it keeps the cookies, else
    /// the handle's own. A jar no transfer has started since its files
    /// were read is not written, as they may not all have been. Nothing to
    /// write is no failure.
    pub fn save_cookies(&mut self) -> Result<(), ErrorKind> {
        let Some(to) = &self.options.http.cookies.save_to else {
            self.watch_shared_jar();
            return Ok(());
        };
        let save = |jar: &mut Jar| match jar.running() {
            true => write_jar(jar, to),
            false => Ok(()),
        };
        let written = match self.with_shared_jar(save) {
            Ok(written) => written,
            Err(save) => self.cookies.as_mut().map(save),
        };
        written.unwrap_or(Ok(())).map_err(|e| match e {
            SaveError::OutOfMemory => ErrorKind::OutOfMemory,
            SaveError::Write => ErrorKind::WriteError,
        })
    }

    /// Run the transfer to its end, blocking (`curl_easy_perform`), in the
    /// handle's own multi, made the first time with the system's clock
    /// and network.
    pub fn perform(&mut self) -> Result<(), Error> {
        self.perform_by(Drive::Waits)
    }

    /// Run the transfer to its end as `perform` does, driven through
    /// `socket_action` by what the multi tells its timer and socket
    /// callbacks (the debug build's `curl_easy_perform_ev`).
    #[cfg(feature = "debug-hooks")]
    pub fn perform_ev(&mut self) -> Result<(), Error> {
        self.perform_by(Drive::Events)
    }

    fn perform_by(&mut self, drive: Drive) -> Result<(), Error> {
        let mut multi = match self.private.take() {
            Some(Private(multi)) => multi,
            None => {
                let env = Env {
                    clock: try_box(SystemClock::new()).map_err(oom)?,
                    net: try_box(SystemNet).map_err(oom)?,
                    arena: ArenaPolicy::new(16, 0).expect("a valid policy"),
                    waker: None,
                };
                try_box(Multi::new(env).map_err(oom)?).map_err(oom)?
            }
        };
        let result = self.perform_in(&mut multi, drive);
        self.private = Some(Private(multi));
        result
    }

    /// Run the transfer to its end in `multi`, driven as `drive` says.
    pub(crate) fn perform_in(&mut self, multi: &mut Multi, drive: Drive) -> Result<(), Error> {
        // The easy handle's limit is its multi's (`curl_easy_perform`).
        multi.conn_limits_mut().max_connects = Some(self.options().limits.reuse.max_connects);
        let (result, easy) = run_to_end(multi, std::mem::take(self), drive);
        *self = easy;
        result.map_err(|kind| Error::with_detail(kind, self.report().failure()))
    }
}

/// The jar's cookies, swept of those expired, to the file `to`.
fn write_jar(jar: &mut Jar, to: &[u8]) -> Result<(), SaveError> {
    let mut text = Vec::new();
    jar.file(SystemClock::new().unix_time(), &mut text)?;
    if to == b"-" {
        let mut out = std::io::stdout().lock();
        out.write_all(&text)?;
        out.flush()?;
        return Ok(());
    }
    save::replace(to, &text)
}

fn oom(_: OutOfMemory) -> ErrorKind {
    ErrorKind::OutOfMemory
}

/// How a perform drives its multi.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Drive {
    /// Waiting on the multi's sockets, then running it (`easy_transfer`).
    Waits,
    /// Through `socket_action`, by what it tells its callbacks
    /// (`easy_events`).
    #[cfg_attr(not(feature = "debug-hooks"), expect(dead_code))]
    Events,
}

/// Add `easy` to `multi`, drive it to its end as `drive` says, and take it
/// out again: its result, and the handle.
fn run_to_end(multi: &mut Multi, easy: Easy, drive: Drive) -> (Result<(), ErrorKind>, Easy) {
    let id = match multi.add(easy, (), &mut NoEvents) {
        Ok(id) => id,
        Err(AddError { kind, easy }) => return (Err(multi_error(kind)), easy),
    };
    let result = match drive {
        Drive::Waits => wait_to_end(multi),
        Drive::Events => drive_by_events(multi, id).unwrap_or_else(|e| Err(multi_error(e))),
    };
    let removed = multi.remove(id, &mut NoEvents).expect("added above");
    (result, removed.easy)
}

/// Wait on `multi`'s sockets and run it until its transfer ends
/// (`easy_transfer`).
fn wait_to_end(multi: &mut Multi) -> Result<(), ErrorKind> {
    loop {
        if let Err(e) = multi.wait(&mut [], POLL, WaitMode::Poll) {
            return Err(multi_error(e));
        }
        match multi.perform(&mut NoEvents) {
            Err(e) => return Err(multi_error(e)),
            Ok(0) => {
                if let Some(msg) = multi.info_read() {
                    return msg.result;
                }
            }
            Ok(_) => {}
        }
    }
}

/// A multi's failure as the transfer's: out of memory, or something that
/// should never happen.
fn multi_error(e: MultiErrorKind) -> ErrorKind {
    match e {
        MultiErrorKind::OutOfMemory => ErrorKind::OutOfMemory,
        _ => ErrorKind::BadFunctionArgument,
    }
}

// A handle may move to whichever thread runs its next transfer.
const _: () = {
    const fn sendable<T: Send>() {}
    sendable::<Easy>();
};

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::Mutex;

    use curl_alloc::TryArc;

    use super::*;
    use crate::handler::{DebugHandler, DebugKind, Handler, Write, WriteHandler};
    use crate::multi::TransferCx;
    use crate::options::{Method, Resume, UploadSource};
    use crate::time::{ManualClock, TimeLimit};
    use crate::url::{ParseOptions, Url};
    use crate::version::Protocol;

    /// A directory of its own for a test, removed after it.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Scratch {
            let dir =
                std::env::temp_dir().join(format!("curl-core-easy-{}-{name}", std::process::id()));
            // Left over from a run that did not finish.
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir(&dir).unwrap();
            Scratch(dir)
        }

        fn url(&self, name: &str) -> Vec<u8> {
            format!("file://{}/{name}", self.0.display()).into_bytes()
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[derive(Clone, Default)]
    struct Body(Arc<Mutex<Vec<u8>>>);

    impl WriteHandler for Body {
        fn write(&self, _: &mut TransferCx<'_>, body: &[u8]) -> Write {
            self.0.lock().unwrap().extend_from_slice(body);
            Write::Accepted
        }
    }

    fn easy(url: &[u8]) -> (Easy, Body) {
        let mut e = Easy::new();
        e.options_mut().set_url(Some(url)).unwrap();
        let body = Body::default();
        e.options_mut().callbacks.write = Some(Handler::write(body.clone()).unwrap());
        (e, body)
    }

    /// A file downloads on the handle's own, which keeps its multi for the
    /// next transfer; a failure is the transfer's.
    #[test]
    fn performs_a_file_url_on_its_own() {
        let s = Scratch::new("download");
        std::fs::write(s.0.join("f"), b"hello").unwrap();
        let (mut e, body) = easy(&s.url("f"));
        assert_eq!(e.perform(), Ok(()));
        assert_eq!(*body.0.lock().unwrap(), b"hello");
        assert_eq!(e.report().sizes().download(), 5);
        assert_eq!(e.report().protocol(), Some(Protocol::File));
        assert!(e.private.is_some(), "kept");
        e.options_mut().set_url(Some(&s.url("missing"))).unwrap();
        let err = e.perform().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::FileCouldntReadFile);
        // Known before the file is looked for.
        assert_eq!(e.report().protocol(), Some(Protocol::File));
        e.options_mut().set_url(Some(b"nosuch://x/")).unwrap();
        assert!(e.perform().is_err());
        assert_eq!(e.report().protocol(), None);
        assert!(e.private.is_some(), "kept after a failure");
        e.options_mut().set_url(Some(&s.url("f"))).unwrap();
        assert_eq!(e.perform(), Ok(()));
        assert_eq!(*body.0.lock().unwrap(), b"hellohello");
    }

    /// A handle made on one thread, with its handlers and the multi of
    /// its own its last transfer left, runs its next transfer on another.
    #[test]
    fn a_handle_moves_to_another_thread() {
        let s = Scratch::new("thread");
        std::fs::write(s.0.join("f"), b"hello").unwrap();
        let (mut e, body) = easy(&s.url("f"));
        assert_eq!(e.perform(), Ok(()));
        let e = std::thread::spawn(move || {
            assert_eq!(e.perform(), Ok(()));
            e
        })
        .join()
        .unwrap();
        assert_eq!(*body.0.lock().unwrap(), b"hellohello");
        assert_eq!(e.report().sizes().download(), 5);
    }

    /// What a debug handler was given, in order.
    type Traced = Vec<(DebugKind, Vec<u8>)>;

    #[derive(Clone, Default)]
    struct Lines(Arc<Mutex<Traced>>);

    impl DebugHandler for Lines {
        fn debug(&self, _: &mut TransferCx<'_>, kind: DebugKind, data: &[u8]) {
            self.0.lock().unwrap().push((kind, data.to_vec()));
        }
    }

    /// The reason a transfer fails is the error's detail, in C's words, and
    /// a verbose transfer traces it.
    #[test]
    fn a_failure_says_why() {
        let s = Scratch::new("why");
        let missing = s.url("missing");
        let (mut e, _) = easy(&missing);
        let lines = Lines::default();
        e.options_mut().output.verbose = true;
        e.options_mut().callbacks.debug = Some(Handler::debug(lines.clone()).unwrap());
        let err = e.perform().unwrap_err();
        let path = &missing[b"file://".len()..];
        let why = [&b"Could not open file "[..], path].concat();
        assert_eq!(err.detail(), Some(&why[..]));
        assert_eq!(err.to_string().as_bytes(), why);
        assert_eq!(e.report().failure(), Some(&why[..]));
        let traced = lines.0.lock().unwrap().clone();
        // The debug build says what it is first (`multi_warn_debug`), once
        // for the handle's multi.
        #[cfg(feature = "debug-hooks")]
        let traced = {
            assert_eq!(traced[0], (DebugKind::Text, b"!!! WARNING !!!\n".to_vec()));
            assert_eq!(
                traced[1],
                (
                    DebugKind::Text,
                    b"This is a debug build of libcurl, do not use in production.\n".to_vec()
                )
            );
            traced[2..].to_vec()
        };
        assert_eq!(traced, [(DebugKind::Text, [&why[..], b"\n"].concat())]);
        lines.0.lock().unwrap().clear();
        e.perform().unwrap_err();
        assert_eq!(lines.0.lock().unwrap().len(), 1, "warned once");

        let why = |url: &[u8]| {
            let (mut e, _) = easy(url);
            let err = e.perform().unwrap_err();
            (
                err.kind(),
                String::from_utf8(err.detail().unwrap().to_vec()).unwrap(),
            )
        };
        let mut no_url = Easy::new();
        let err = no_url.perform().unwrap_err();
        assert_eq!(err.detail(), Some(&b"No URL set"[..]));
        assert_eq!(
            why(b"nosuch://x/"),
            (
                ErrorKind::UnsupportedProtocol,
                "Protocol \"nosuch\" not supported".into()
            )
        );
        assert_eq!(
            why(b"FTP://x/"),
            (
                ErrorKind::UnsupportedProtocol,
                "Protocol \"ftp\" is disabled".into()
            )
        );
        let bad = b"file://h st/";
        let parse = ParseOptions {
            guess_scheme: true,
            non_support_scheme: true,
            ..ParseOptions::NONE
        };
        let reason = Url::parse(bad, parse).unwrap_err();
        assert_eq!(
            why(bad),
            (ErrorKind::UrlMalformat, format!("URL rejected: {reason}"))
        );
        // A handler that fails a write is told of in C's words.
        std::fs::write(s.0.join("f"), b"hello").unwrap();
        let mut e = Easy::new();
        e.options_mut().set_url(Some(&s.url("f"))).unwrap();
        e.options_mut().callbacks.write = Some(Handler::write(Refuse).unwrap());
        let err = e.perform().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::WriteError);
        assert_eq!(
            err.detail(),
            Some(&b"client returned ERROR on write of 5 bytes"[..])
        );
    }

    struct Refuse;

    impl WriteHandler for Refuse {
        fn write(&self, _: &mut TransferCx<'_>, _: &[u8]) -> Write {
            Write::Fail
        }
    }

    /// A bare path is a file with `file` as the default protocol (test
    /// 1146).
    #[test]
    fn performs_a_path_with_the_default_protocol() {
        let s = Scratch::new("default");
        std::fs::write(s.0.join("f"), b"hello").unwrap();
        let path = s.0.join("f");
        let (mut e, body) = easy(path.as_os_str().as_encoded_bytes());
        assert_eq!(e.perform().unwrap_err().kind(), ErrorKind::UrlMalformat);
        e.options_mut().set_default_protocol(Some(b"file")).unwrap();
        assert_eq!(e.perform(), Ok(()));
        assert_eq!(*body.0.lock().unwrap(), b"hello");
        let copy = e.try_clone().unwrap();
        assert_eq!(copy.options().default_protocol(), Some(&b"file"[..]));
    }

    /// An upload writes the file; resumed, it appends past the resume
    /// point.
    #[test]
    fn performs_an_upload_and_resumes_it() {
        let s = Scratch::new("upload");
        let (mut e, _) = easy(&s.url("f"));
        e.options_mut().method = Method::Upload;
        let body = |b: &[u8]| UploadSource::Bytes(TryArc::try_new(b.to_vec()).unwrap());
        e.options_mut().upload = body(b"01234");
        assert_eq!(e.perform(), Ok(()));
        assert_eq!(std::fs::read(s.0.join("f")).unwrap(), b"01234");
        e.options_mut().upload = body(b"0123456789");
        e.options_mut().resume = Some(Resume::At(NonZeroU64::new(5).unwrap()));
        assert_eq!(e.perform(), Ok(()));
        assert_eq!(std::fs::read(s.0.join("f")).unwrap(), b"0123456789");
        assert_eq!(e.report().sizes().upload(), 5);
    }

    /// A multi's own failure is the transfer's out of memory, or a bad
    /// argument; the error shows its kind's message.
    #[test]
    fn errors_read_as_their_kinds() {
        assert_eq!(
            multi_error(MultiErrorKind::OutOfMemory),
            ErrorKind::OutOfMemory
        );
        assert_eq!(
            multi_error(MultiErrorKind::BadEasyHandle),
            ErrorKind::BadFunctionArgument
        );
        let e = Error::from(ErrorKind::FileCouldntReadFile);
        assert_eq!(e.to_string(), ErrorKind::FileCouldntReadFile.to_string());
        assert!(!e.to_string().is_empty());
    }

    /// A handle added to a multi leaves its own multi behind.
    #[test]
    fn adding_a_handle_drops_its_own_multi() {
        let s = Scratch::new("add");
        std::fs::write(s.0.join("f"), b"x").unwrap();
        let (mut e, _) = easy(&s.url("f"));
        e.perform().unwrap();
        let clock = ManualClock::new().unwrap();
        let env = Env {
            clock: Box::new(clock.clone()),
            net: Box::new(crate::conn::io::FakeNet::new(clock)),
            arena: ArenaPolicy::new(16, 0).unwrap(),
            waker: None,
        };
        let mut m: Multi = Multi::new(env).unwrap();
        let id = m.add(e, (), &mut NoEvents).unwrap();
        let e = m.remove(id, &mut NoEvents).unwrap().easy;
        assert!(e.private.is_none());
    }

    /// The cookies the application gives are kept beside each other, and
    /// cleared all, those of the session alone, or forgotten with the
    /// files they came from (`CURLOPT_COOKIELIST`, `CURLOPT_COOKIEFILE`).
    #[test]
    fn cookies_are_added_cleared_and_forgotten() {
        let session = b"example.com\tFALSE\t/\tFALSE\t0\ts\t1";
        let lasting = b"example.com\tFALSE\t/\tFALSE\t4102444800\tp\t2";
        let mut e = Easy::new();
        e.add_cookie(session).unwrap();
        e.add_cookie(lasting).unwrap();
        let mut list = e.cookie_list().unwrap();
        list.sort();
        assert_eq!(list, [session.to_vec(), lasting.to_vec()]);
        e.clear_session_cookies().unwrap();
        assert_eq!(e.cookie_list().unwrap(), [lasting.to_vec()]);
        e.clear_cookies().unwrap();
        assert!(e.cookie_list().unwrap().is_empty());
        e.add_cookie(lasting).unwrap();
        e.options_mut()
            .http
            .cookies
            .files
            .push(b"some.jar")
            .unwrap();
        e.forget_cookies();
        assert!(e.cookie_list().unwrap().is_empty());
        assert!(e.options().http.cookies.files.iter().next().is_none());
    }

    /// Every cookie the application gives is kept, past the limit of 50 a
    /// response may set. C counts `Set-Cookie:` lines given here against
    /// that limit until the next request starts, and once it is reached
    /// drops every line given, silently: it keeps 50 of these 61
    /// (DIVERGENCE.md).
    #[test]
    fn the_application_s_cookies_have_no_limit() {
        let mut e = Easy::new();
        for i in 0..60 {
            let line = format!("Set-Cookie: c{i}=v; domain=example.com");
            e.add_cookie(line.as_bytes()).unwrap();
        }
        e.add_cookie(b"example.com\tFALSE\t/\tFALSE\t0\tnetscape\tv")
            .unwrap();
        assert_eq!(e.cookie_list().unwrap().len(), 61);
    }

    /// Driven by events, a transfer runs to its end as when waited on.
    #[cfg(feature = "debug-hooks")]
    #[test]
    fn performs_driven_by_events() {
        let s = Scratch::new("events");
        std::fs::write(s.0.join("f"), b"hello").unwrap();
        let (mut e, body) = easy(&s.url("f"));
        assert_eq!(e.perform_ev(), Ok(()));
        assert_eq!(*body.0.lock().unwrap(), b"hello");
        let (mut e, _) = easy(&s.url("missing"));
        assert!(e.perform_ev().is_err());
    }

    #[test]
    fn clones_options_and_resets_them() {
        let mut easy = Easy::new();
        easy.options_mut().set_url(Some(b"file:///x")).unwrap();
        easy.options_mut().limits.total = TimeLimit::from_millis(5);
        let http = &mut easy.options_mut().http;
        http.user_agent = Some(b"me".to_vec());
        http.referer = Some(b"r".to_vec());
        http.headers = crate::options::UserHeaders::new([&b"X-A: 1"[..]]).unwrap();
        http.fail_on_error = true;
        let copy = easy.try_clone().unwrap();
        assert_eq!(copy.options().url(), Some(&b"file:///x"[..]));
        assert_eq!(copy.options().limits.total, TimeLimit::from_millis(5));
        let http = &copy.options().http;
        assert_eq!(
            (http.user_agent.as_deref(), http.referer.as_deref()),
            (Some(&b"me"[..]), Some(&b"r"[..]))
        );
        assert!(http.headers.lines().eq([&b"X-A: 1"[..]]));
        assert!(http.fail_on_error);
        easy.reset();
        assert_eq!(easy.options().url(), None);
        assert_eq!(easy.options().limits.total, None);
        assert_eq!(copy.options().url(), Some(&b"file:///x"[..]));
    }

    /// Over the system's network: a closed port refuses with C's words,
    /// and a listening one is connected to, both traced as C traces them.
    #[test]
    fn connects_over_loopback() {
        let traced = |url: &str| {
            let (mut e, _) = easy(url.as_bytes());
            let lines = Lines::default();
            e.options_mut().output.verbose = true;
            e.options_mut().callbacks.debug = Some(Handler::debug(lines.clone()).unwrap());
            let result = e.perform().map_err(|err| err.kind());
            let text: Vec<String> = lines
                .0
                .lock()
                .unwrap()
                .iter()
                .map(|(_, l)| String::from_utf8(l.clone()).unwrap())
                .filter(|l| !l.starts_with("!!!") && !l.starts_with("This is a debug build"))
                .collect();
            (result, text)
        };
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = closed.local_addr().unwrap().port();
        drop(closed);
        let (result, text) = traced(&format!("tcp://127.0.0.1:{port}/"));
        assert_eq!(result, Err(ErrorKind::CouldntConnect));
        assert_eq!(text[0], format!("  Trying 127.0.0.1:{port}...\n"));
        let refused = format!("connect to 127.0.0.1 port {port} from 127.0.0.1 port ");
        assert!(text[1].starts_with(&refused), "{text:?}");
        assert!(
            text[1].ends_with(" failed: Connection refused\n"),
            "{text:?}"
        );
        let failed = format!("Failed to connect to 127.0.0.1:{port} after ");
        assert!(text[2].starts_with(&failed), "{text:?}");
        assert!(
            text[2].ends_with(" ms: Could not connect to server\n"),
            "{text:?}"
        );
        assert_eq!(text[3..], ["closing connection #0\n"]);

        let listening = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listening.local_addr().unwrap().port();
        let (result, text) = traced(&format!("tcp://127.0.0.1:{port}/"));
        assert_eq!(result, Ok(()));
        let (accepted, from) = listening.accept().unwrap();
        drop(accepted);
        let established = format!(
            "Established connection to 127.0.0.1 (127.0.0.1 port {port}) from 127.0.0.1 port {} \n",
            from.port()
        );
        assert_eq!(
            text,
            [
                format!("  Trying 127.0.0.1:{port}...\n"),
                established,
                format!("Connection #0 to host 127.0.0.1:{port} left intact\n"),
            ]
        );
    }
}
