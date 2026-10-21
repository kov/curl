//! The easy handle: one transfer's configuration, added to a multi to run.

use std::fmt;
use std::time::Duration;

use curl_alloc::{OutOfMemory, try_box};

use crate::conn::io::SystemNet;
use crate::error::{Error, ErrorKind, MultiErrorKind};
use crate::id::ArenaPolicy;
use crate::multi::{AddError, Env, Multi, NoEvents, WaitMode, drive_by_events};
use crate::options::Options;
use crate::proto::http::auth::HostAuth;
use crate::report::TransferReport;
use crate::share::Lent;
use crate::time::SystemClock;

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
    pub(crate) auth: HostAuth,
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
    pub(crate) fn auth_with_options(&mut self) -> (&mut HostAuth, &Options) {
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
            auth: HostAuth::default(),
            private: None,
        })
    }

    /// Every option back to its default, and the report with them
    /// (`curl_easy_reset`). The private multi stays.
    pub fn reset(&mut self) {
        self.options = Options::default();
        self.report = self.report.cleared();
        self.meter_titled = false;
        self.resolve_read = 0;
        self.wildcard_resolve = false;
        self.auth = HostAuth::default();
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

    /// Run the transfer to its end in `multi`, driven as `drive` says,
    /// with its share's caches in place of the multi's own for the length
    /// of it.
    pub(crate) fn perform_in(&mut self, multi: &mut Multi, drive: Drive) -> Result<(), Error> {
        // The easy handle's limit is its multi's (`curl_easy_perform`).
        multi.conn_limits_mut().max_connects = Some(self.options().limits.reuse.max_connects);
        let share = self.options.share.clone();
        let mut lent = match &share {
            // A perform from a handler of a transfer on the same share.
            Some(share) => Some(
                share
                    .lend()
                    .map_err(|Lent| Error::from(ErrorKind::RecursiveApiCall))?,
            ),
            None => None,
        };
        if let Some(caches) = &mut lent {
            multi.swap_caches(caches);
        }
        let (result, easy) = run_to_end(multi, std::mem::take(self), drive);
        *self = easy;
        if let (Some(share), Some(mut caches)) = (share, lent) {
            multi.swap_caches(&mut caches);
            share.give_back(caches);
        }
        result.map_err(|kind| Error::with_detail(kind, self.report().failure()))
    }
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

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::num::NonZeroU64;
    use std::path::PathBuf;
    use std::rc::Rc;

    use curl_alloc::TryRc;

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
    struct Body(Rc<RefCell<Vec<u8>>>);

    impl WriteHandler for Body {
        fn write(&self, _: &mut TransferCx<'_>, body: &[u8]) -> Write {
            self.0.borrow_mut().extend_from_slice(body);
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
        assert_eq!(*body.0.borrow(), b"hello");
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
        assert_eq!(*body.0.borrow(), b"hellohello");
    }

    /// What a debug handler was given, in order.
    type Traced = Vec<(DebugKind, Vec<u8>)>;

    #[derive(Clone, Default)]
    struct Lines(Rc<RefCell<Traced>>);

    impl DebugHandler for Lines {
        fn debug(&self, _: &mut TransferCx<'_>, kind: DebugKind, data: &[u8]) {
            self.0.borrow_mut().push((kind, data.to_vec()));
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
        let traced = lines.0.borrow().clone();
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
        lines.0.borrow_mut().clear();
        e.perform().unwrap_err();
        assert_eq!(lines.0.borrow().len(), 1, "warned once");

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
        assert_eq!(*body.0.borrow(), b"hello");
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
        let body = |b: &[u8]| UploadSource::Bytes(TryRc::try_new(b.to_vec()).unwrap());
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
                .borrow()
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
