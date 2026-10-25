//! The easy handle: one transfer's configuration, added to a multi to run.

use std::fmt;
use std::io::Write as _;
use std::time::Duration;

use curl_alloc::{OutOfMemory, TryArc, TryVec as _, try_box};

use crate::coding::Decoders;
use crate::components::Components;
use crate::conn::io::{SystemNet, Waker};
use crate::cookie::{Jar, LoadError, Suffixes};
use crate::error::{Error, ErrorKind, MultiErrorKind};
use crate::handler::Handler;
use crate::hsts::Hsts;
use crate::id::ArenaPolicy;
use crate::libraries::{Libraries, SharedLibraries};
use crate::multi::{AddError, Env, Multi, NoEvents, WaitMode, drive_by_events};
use crate::options::{Lines, Options};
use crate::proto::http1::auth::Auth;
use crate::report::TransferReport;
use crate::save;
pub use crate::save::SaveError;
use crate::share::{Kind, Share, ShareLock, watched};
use crate::time::{Clock as _, SystemClock};
use crate::trace;

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
    pub(crate) cookies: Option<Box<Jar>>,
    /// Cookies stored from `Set-Cookie:` lines since the request started
    /// (`req.setcookies`), whoever gave them: a response, a cookie file or
    /// the application. Past `MAX_SET_PER_REQUEST`, no cookie of any kind
    /// is stored until the next request starts.
    pub(crate) set_cookies: u8,
    /// The HSTS cache, once the application turns it on (C's `hsts`):
    /// kept from one transfer to the next, and through `reset`.
    pub(crate) hsts: Option<Box<Hsts>>,
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
    /// What the libraries bound beside the core do for it: the content
    /// codings it undoes, the signatures it makes, the TLS it speaks.
    libraries: SharedLibraries,
    /// Which components trace, read at each line: shared with whoever
    /// gave it, kept through `reset` and by a copy of the handle. Without
    /// one, only the lines of a verbose transfer that belong to no
    /// component are traced.
    components: Option<Components>,
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
        if let Some(custom) = &self.options.http.custom.method {
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
            cookies: match self.cookies {
                Some(_) => Some(try_box(Jar::default())?),
                None => None,
            },
            set_cookies: 0,
            hsts: self
                .hsts
                .as_deref()
                .map(|h| self.hsts_copy(h))
                .transpose()?,
            share: None,
            share_watch: None,
            suffixes: match &self.suffixes {
                SuffixList::Given(given) => SuffixList::Given(given.clone()),
                SuffixList::Made(make) => SuffixList::Made(*make),
                SuffixList::None => SuffixList::None,
            },
            libraries: self.libraries.clone(),
            components: self.components.clone(),
        })
    }

    /// The HSTS cache a copy of the handle starts with
    /// (`curl_easy_duphandle`): its file and the application's reader read
    /// into a new one, as C reads them, then the entries alive here. What
    /// fails to be read is passed over, as in C.
    fn hsts_copy(&self, hsts: &Hsts) -> Result<Box<Hsts>, OutOfMemory> {
        let now = crate::proto::http::hsts::now(SystemClock::new().unix_time());
        let mut copy = try_box(Hsts::default())?;
        let options = &*self.options.http.hsts;
        if let Some(file) = &options.file
            && let Err(crate::hsts::LoadError::OutOfMemory) = copy.load(file, now)
        {
            return Err(OutOfMemory);
        }
        if let Some(reader) = &options.read
            && let Err(crate::hsts::PullError::OutOfMemory) = copy.pull(&**reader, now)
        {
            return Err(OutOfMemory);
        }
        let alive = hsts.alive_copy(now)?;
        copy.merge(alive)?;
        Ok(copy)
    }

    /// Every option back to its default, and the report with them but
    /// for its last socket error (`curl_easy_reset`). The private multi
    /// and the cookie jar stay.
    pub fn reset(&mut self) {
        self.options = Options::default();
        self.report = self.report.reset();
        self.meter_titled = false;
        self.resolve_read = 0;
        self.wildcard_resolve = false;
        self.auth = Auth::default();
        self.set_cookies = 0;
    }

    /// Which components trace, as the application set it.
    pub fn components(&self) -> Option<&Components> {
        self.components.as_ref()
    }

    /// Trace the components `components` turns on, from now on: it is
    /// read at each line, so a change to it shows in a running transfer
    /// (`curl_global_trace`).
    pub fn set_components(&mut self, components: Option<Components>) {
        self.components = components;
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

    /// The libraries the handle's transfers use, kept through `reset`
    /// (those C's build has): the content codings its responses can be
    /// undone from, what signs its requests.
    pub fn set_libraries(&mut self, libraries: SharedLibraries) {
        self.libraries = libraries;
    }

    pub(crate) fn libraries(&self) -> &Libraries {
        &self.libraries
    }

    /// The handle's libraries, held apart from it.
    pub(crate) fn shared_libraries(&self) -> SharedLibraries {
        self.libraries.clone()
    }

    pub(crate) fn decoders(&self) -> Decoders {
        self.libraries.decoders
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

    /// Turn the HSTS cache on, empty, if it is not (`CURLHSTS_ENABLE`).
    pub fn enable_hsts(&mut self) -> Result<(), OutOfMemory> {
        if self.hsts.is_none() {
            self.hsts = Some(try_box(Hsts::default())?);
        }
        Ok(())
    }

    /// Turn the HSTS cache off: its entries and the files named are
    /// forgotten (`CURLOPT_HSTS_CTRL` without `CURLHSTS_ENABLE`).
    pub fn disable_hsts(&mut self) {
        self.hsts = None;
    }

    /// Read the HSTS file `file` into the cache as each transfer starts,
    /// and write the cache to it as the handle goes; the cache is turned
    /// on. Without a file, the files named are forgotten and the cache
    /// turned off (`CURLOPT_HSTS`).
    pub fn add_hsts_file(&mut self, file: Option<&[u8]>) -> Result<(), OutOfMemory> {
        self.enable_hsts()?;
        let Some(file) = file else {
            self.disable_hsts();
            return Ok(());
        };
        let mut copy = Vec::new();
        copy.try_extend_from_slice(file)?;
        let hsts = self.hsts.as_deref_mut().expect("enabled above");
        hsts.read_at_start(file)?;
        self.options.http.hsts.make_mut()?.file = Some(copy);
        Ok(())
    }

    /// Whether the HSTS cache is on.
    pub fn hsts_enabled(&self) -> bool {
        self.hsts.is_some()
    }

    /// Write the HSTS cache, if it is on, to `HstsOptions::file` or else
    /// the file last read, and give it to the application's writer
    /// (`Curl_hsts_save`). A file not written, or a writer that says the
    /// save fails, fails it, after the rest is done.
    pub fn save_hsts(&mut self) -> Result<(), SaveError> {
        let Some(hsts) = self.hsts.as_deref() else {
            return Ok(());
        };
        let options = &*self.options.http.hsts;
        let file = options.file.as_deref().or(hsts.file());
        let mut result = Ok(());
        if let Some(file) = file.filter(|f| !f.is_empty()) {
            result = crate::save::replace(file, &hsts.text()?);
        }
        if let Some(writer) = &options.write {
            // The writer's verdict is the save's, as C's is.
            result = match hsts.push(&**writer) {
                true => Ok(()),
                false => Err(SaveError::Write),
            };
        }
        result
    }

    /// Turn the cookie jar on: one of the handle's own, empty, if it has
    /// none (`CURLOPT_COOKIEJAR`). Making it is what can run out of
    /// memory.
    pub fn enable_cookies(&mut self) -> Result<(), OutOfMemory> {
        if self.cookies.is_none() {
            self.cookies = Some(try_box(Jar::default())?);
        }
        Ok(())
    }

    /// Forget the cookie files and the handle's own jar, with its cookies
    /// (`CURLOPT_COOKIEFILE` NULL). A share's jar is not the handle's to
    /// forget.
    pub fn forget_cookies(&mut self) {
        if let Some(cookies) = self.options.http.cookies.made_mut() {
            cookies.files = Lines::default();
        }
        self.cookies = None;
    }

    /// Store a cookie the application gives, a `Set-Cookie:` line or one
    /// in the Netscape format, turning the jar on if it is not
    /// (`CURLOPT_COOKIELIST`). Its domain is not checked against the
    /// public suffixes.
    ///
    /// `notes` hears each line C would trace of it, its end included: why
    /// it was dropped, or, once a transfer or a reload has started the
    /// jar, that it was added.
    pub fn add_cookie(
        &mut self,
        line: &[u8],
        mut notes: impl FnMut(&[u8]),
    ) -> Result<(), OutOfMemory> {
        let now = SystemClock::new().unix_time();
        // Counted with the last request's, and dropped silently past
        // their limit, as C counts it.
        let mut set = self.set_cookies;
        let suffixes = self.public_suffixes()?;
        let list = suffixes.as_ref().map(Suffixes::list);
        let added = self
            .with_jar(true, |jar| {
                let said = jar.add_line(line, list, now, &mut set)?;
                if let Some(said) = said {
                    said.lines(|parts| notes(trace::line_with(parts).ended().bytes()));
                }
                Ok(())
            })?
            .expect("made if missing");
        self.set_cookies = set;
        added
    }

    /// Forget every cookie (`CURLOPT_COOKIELIST` `ALL`).
    pub fn clear_cookies(&mut self) -> Result<(), OutOfMemory> {
        self.with_jar(false, Jar::clear)?;
        Ok(())
    }

    /// Forget the cookies that last the session (`CURLOPT_COOKIELIST`
    /// `SESS`).
    pub fn clear_session_cookies(&mut self) -> Result<(), OutOfMemory> {
        self.with_jar(false, Jar::clear_session)?;
        Ok(())
    }

    /// Read the cookie files into the jar again, without checking their
    /// domains against the public suffixes (`CURLOPT_COOKIELIST`
    /// `RELOAD`), each in turn, as one use of the jar. A file that cannot
    /// be opened is passed over; one that cannot be read stops the walk.
    ///
    /// `notes` hears each line C would trace, its end included: a file
    /// that cannot be opened, then what each file's lines say, in turn.
    pub fn reload_cookies(&mut self, mut notes: impl FnMut(&[u8])) -> Result<(), LoadError> {
        let cookies = &self.options.http.cookies;
        if cookies.files.iter().next().is_none() {
            return Ok(());
        }
        let files = cookies.files.try_clone()?;
        let new_session = cookies.new_session;
        let now = SystemClock::new().unix_time();
        let suffixes = self.public_suffixes()?;
        let list = suffixes.as_ref().map(Suffixes::list);
        let mut set = self.set_cookies;
        let loaded = self
            .with_jar(true, |jar| {
                for name in files.iter() {
                    // An empty name reads nothing; each other one that
                    // is not there is warned of. Either starts the jar.
                    let text = match name.is_empty() {
                        true => None,
                        false => match crate::proto::http::cookies::read_named(name)? {
                            Ok(text) => Some(text),
                            Err(warning) => {
                                notes(warning.ended().bytes());
                                None
                            }
                        },
                    };
                    let Some(text) = text else {
                        jar.start();
                        continue;
                    };
                    jar.load(&text, new_session, true, list, now, &mut set, |said| {
                        said.lines(|parts| notes(trace::line_with(parts).ended().bytes()));
                    })?;
                }
                Ok(())
            })?
            .expect("made if missing");
        self.set_cookies = set;
        loaded
    }

    /// Every cookie the jar holds that has a domain, as a line in the
    /// Netscape format (`CURLINFO_COOKIELIST`), those expired swept out
    /// first.
    pub fn cookie_list(&mut self) -> Result<Vec<Vec<u8>>, OutOfMemory> {
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
        })?;
        Ok(listed.transpose()?.unwrap_or_default())
    }

    /// Run `f` on the jar the handle uses: its share's, if that keeps the
    /// cookies, as one use of it, else its own, made if `make` and it has
    /// none. None if there is no jar.
    fn with_jar<R>(
        &mut self,
        make: bool,
        f: impl FnOnce(&mut Jar) -> R,
    ) -> Result<Option<R>, OutOfMemory> {
        let f = match self.with_shared_jar(f) {
            Ok(r) => return Ok(r),
            Err(f) => f,
        };
        if make {
            self.enable_cookies()?;
        }
        Ok(self.cookies.as_deref_mut().map(f))
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
    pub fn save_cookies(&mut self) -> Result<(), SaveError> {
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
            Err(save) => self.cookies.as_deref_mut().map(save),
        };
        written.unwrap_or(Ok(()))
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
                // A waker, as every C multi has one (`Curl_wakeup_init`),
                // watched as a perform's multi waits; without the
                // descriptors for it, the multi goes without.
                let waker = match Waker::new() {
                    Ok(w) => Some(TryArc::try_new(w).map_err(oom)?),
                    Err(_) => None,
                };
                let env = Env {
                    clock: try_box(SystemClock::new()).map_err(oom)?,
                    // A multi whose resolver cannot be set up is not made
                    // (`Curl_multi_handle`'s `goto error`).
                    net: try_box(
                        SystemNet::for_multi(crate::conn::threaded::Threads::EASY)
                            .map_err(|_| ErrorKind::OutOfMemory)?,
                    )
                    .map_err(oom)?,
                    arena: ArenaPolicy::new(16, 0).expect("a valid policy"),
                    waker,
                };
                let mut multi = try_box(Multi::new(env).map_err(oom)?).map_err(oom)?;
                // As few TLS peers as C's `multi_easy` keeps.
                multi.keep_tls_sessions_of(crate::tls::SessionCache::PERFORM_PEERS);
                multi
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
        multi.set_quick_exit(self.options().quick_exit);
        // The multi holds its transfers in memory of their own.
        let result = match curl_alloc::try_box_or_back(std::mem::take(self)) {
            Ok(easy) => {
                let (result, easy) = run_to_end(multi, easy, drive);
                *self = *easy;
                result
            }
            Err(easy) => {
                *self = easy;
                Err(ErrorKind::OutOfMemory)
            }
        };
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
fn run_to_end(
    multi: &mut Multi,
    easy: Box<Easy>,
    drive: Drive,
) -> (Result<(), ErrorKind>, Box<Easy>) {
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
        if let Err(e) = multi.wait(&mut [], POLL, WaitMode::Poll, &mut NoEvents) {
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
    /// A perform's own multi has a waker, as every C multi has one, which
    /// its waits count (`multi_wait`'s `fds`).
    #[test]
    fn a_perform_s_multi_has_a_waker() {
        let s = Scratch::new("waker");
        std::fs::write(s.0.join("f"), b"x").unwrap();
        let (mut e, _) = easy(&s.url("f"));
        e.perform().unwrap();
        let Some(Private(multi)) = &e.private else {
            panic!("the multi is kept");
        };
        assert!(multi.waker().is_some());
    }

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
        let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
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
        e.add_cookie(session, |_| {}).unwrap();
        e.add_cookie(lasting, |_| {}).unwrap();
        let mut list = e.cookie_list().unwrap();
        list.sort();
        assert_eq!(list, [session.to_vec(), lasting.to_vec()]);
        e.clear_session_cookies().unwrap();
        assert_eq!(e.cookie_list().unwrap(), [lasting.to_vec()]);
        e.clear_cookies().unwrap();
        assert!(e.cookie_list().unwrap().is_empty());
        e.add_cookie(lasting, |_| {}).unwrap();
        e.options_mut()
            .http
            .cookies
            .make_mut()
            .unwrap()
            .files
            .push(b"some.jar")
            .unwrap();
        e.forget_cookies();
        assert!(e.cookie_list().unwrap().is_empty());
        assert!(e.options().http.cookies.files.iter().next().is_none());
    }

    /// The jar is listed bucket by bucket (`CURLINFO_COOKIELIST`), a domain
    /// past ASCII in C's bucket: the C library on x86_64 lists these three
    /// domains in this order, `bücher.de` last.
    #[test]
    fn cookies_are_listed_in_c_s_order() {
        let line = |domain: &str| format!("{domain}\tFALSE\t/\tFALSE\t0\tn\tv").into_bytes();
        let mut e = Easy::new();
        for domain in ["example.com", "bücher.de", "b.example.org"] {
            e.add_cookie(&line(domain), |_| {}).unwrap();
        }
        let order = if core::ffi::c_char::MIN != 0 {
            ["b.example.org", "example.com", "bücher.de"]
        } else {
            ["b.example.org", "bücher.de", "example.com"]
        };
        assert_eq!(e.cookie_list().unwrap(), order.map(line));
    }

    /// A reload notes each file it cannot open as it reaches it, between
    /// what the files before and after it say; a cookie added notes why
    /// it was dropped, and, once the reload has started the jar, that it
    /// was added (the C build's `CURLOPT_COOKIELIST` trace).
    #[test]
    fn cookie_commands_note_what_c_traces() {
        let dir = std::env::temp_dir().join(format!("curl-reload-notes-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a"), "Set-Cookie: =\n").unwrap();
        std::fs::write(dir.join("b"), "Set-Cookie: b\x01=x; domain=example.com\n").unwrap();
        let name = |p: &str| dir.join(p).to_str().unwrap().to_string();
        let mut notes = Vec::new();
        let mut e = Easy::new();
        let add = |e: &mut Easy, line: &str, notes: &mut Vec<String>| {
            e.add_cookie(line.as_bytes(), |l| {
                notes.push(String::from_utf8(l.to_vec()).unwrap());
            })
            .unwrap();
        };
        add(&mut e, ".a.com\tTRUE\t/\tFALSE\t0\tfirst\tx", &mut notes);
        add(&mut e, "Set-Cookie: =", &mut notes);
        assert_eq!(notes, ["invalid cookie, dropped\n"]);
        notes.clear();
        for file in ["a", "missing", "", "b"] {
            let file = if file.is_empty() {
                String::new()
            } else {
                name(file)
            };
            e.options_mut()
                .http
                .cookies
                .make_mut()
                .unwrap()
                .files
                .push(file.as_bytes())
                .unwrap();
        }
        e.reload_cookies(|l| notes.push(String::from_utf8(l.to_vec()).unwrap()))
            .unwrap();
        add(&mut e, ".b.com\tTRUE\t/\tFALSE\t0\tsecond\ty", &mut notes);
        let missing = name("missing");
        assert_eq!(
            notes,
            [
                "invalid cookie, dropped\n".to_string(),
                format!("WARNING: failed to open cookie file \"{missing}\"\n"),
                "invalid octets in name, cookie dropped\n".to_string(),
                "Added cookie second=\"y\" for domain b.com, path /, expire 0\n".to_string(),
            ]
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The application's `Set-Cookie:` lines count toward the 50 one
    /// request stores, as C counts them (`req.setcookies`): once they are
    /// reached, no line it gives is stored, in either format, and it is
    /// not told. As on the C build: 50 of 60 lines and a Netscape one; 51
    /// of 49, a Netscape one, 5 more and another.
    #[test]
    fn the_application_s_cookies_count_toward_the_limit() {
        let add = |e: &mut Easy, n: usize, prefix: &str| {
            for i in 0..n {
                let line = format!("Set-Cookie: {prefix}{i}=v; domain=example.com");
                e.add_cookie(line.as_bytes(), |_| {}).unwrap();
            }
        };
        let netscape = |e: &mut Easy, name: &str| {
            let line = format!("example.com\tFALSE\t/\tFALSE\t0\t{name}\tv");
            e.add_cookie(line.as_bytes(), |_| {}).unwrap();
        };
        let mut e = Easy::new();
        add(&mut e, 60, "a");
        netscape(&mut e, "n1");
        assert_eq!(e.cookie_list().unwrap().len(), 50);
        let mut e = Easy::new();
        add(&mut e, 49, "a");
        netscape(&mut e, "n1");
        add(&mut e, 5, "b");
        netscape(&mut e, "n2");
        assert_eq!(e.cookie_list().unwrap().len(), 51);
        // A reset starts the count again; a copy starts its own.
        e.reset();
        add(&mut e, 3, "c");
        assert_eq!(e.cookie_list().unwrap().len(), 54);
        let mut copy = e.try_clone().unwrap();
        add(&mut copy, 3, "d");
        assert_eq!(copy.cookie_list().unwrap().len(), 3);
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
        http.custom.make_mut().unwrap().referer = Some(b"r".to_vec());
        http.headers = crate::options::UserHeaders::new([&b"X-A: 1"[..]]).unwrap();
        http.fail_on_error = true;
        let copy = easy.try_clone().unwrap();
        assert_eq!(copy.options().url(), Some(&b"file:///x"[..]));
        assert_eq!(copy.options().limits.total, TimeLimit::from_millis(5));
        let http = &copy.options().http;
        assert_eq!(
            (http.user_agent.as_deref(), http.custom.referer.as_deref()),
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
    /// and the refusal is reported; a listening one is connected to, both
    /// traced as C traces them.
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
            (result, text, e.report().os_errno().map(|n| n.kind()))
        };
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = closed.local_addr().unwrap().port();
        drop(closed);
        let (result, text, why) = traced(&format!("tcp://127.0.0.1:{port}/"));
        assert_eq!(result, Err(ErrorKind::CouldntConnect));
        assert_eq!(why, Some(std::io::ErrorKind::ConnectionRefused));
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
        let (result, text, why) = traced(&format!("tcp://127.0.0.1:{port}/"));
        assert_eq!((result, why), (Ok(()), None));
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
