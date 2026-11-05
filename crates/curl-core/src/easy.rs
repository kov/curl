//! The easy handle: one transfer's configuration, added to a multi to run.

use std::fmt;
use std::io::Write as _;
use std::time::Duration;

use curl_alloc::{OutOfMemory, TryArc, TryVec as _, try_box};

use crate::altsvc::{AltSvc, AltSvcCtrl};
use crate::auth::http::Auth;
use crate::coding::Decoders;
use crate::components::Components;
use crate::conn::ConnId;
use crate::conn::io::{SystemNet, Waker};
use crate::cookie::{Jar, LoadError, NeverAsked, SuffixCheck};
use crate::error::{Error, ErrorKind, MultiErrorKind};
use crate::handler::{Handler, WriteHandler};
use crate::hsts::{Hsts, LoadError as CacheLoadError};
use crate::id::ArenaPolicy;
use crate::libraries::{Libraries, SharedLibraries};
use crate::multi::{AddError, Env, Multi, NoEvents, WaitMode};
use crate::multi::{EventTable, TransferId, drive_by_events_with};
use crate::options::{Lines, Options};
use crate::report::TransferReport;
use crate::save;

pub use crate::save::{CacheFile, SaveError};
use crate::share::{Kind, Share, ShareInUse, ShareLock, watched};
use crate::time::SystemClock;
use crate::trace;

/// A transfer's configuration. `Multi::add` takes it by value to run it
/// and `Multi::remove` gives it back; `perform` runs it on its own. The
/// default allocates nothing.
#[derive(Debug, Default)]
pub struct Easy {
    /// The work of the multi's this handle does, which its lines name
    /// (`state.feat`): none for one of the application's.
    doing: Option<crate::components::Component>,
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
    pub(crate) private: Option<Box<Private>>,
    /// Authenticating with the origin, from one transfer to the next.
    pub(crate) auth: Auth,
    /// The cookie jar it uses, and whether it is on (C's `cookies` with
    /// `cookie_engine`): kept from one transfer to the next, and through
    /// `reset`.
    pub(crate) jar: JarUse,
    /// Cookies stored from `Set-Cookie:` lines since the request started
    /// (`req.setcookies`), whoever gave them: a response, a cookie file or
    /// the application. Past `MAX_SET_PER_REQUEST`, no cookie of any kind
    /// is stored until the next request starts.
    pub(crate) set_cookies: u8,
    /// The credentials the handle's last request set out with, as the
    /// next request's trace says them before it takes its own (C's
    /// `state.creds`, kept until the handle is closed, through `reset`).
    pub(crate) shown_credentials: Option<crate::auth::creds::Shown>,
    /// The connection the handle's transfer had last, in the pool of its
    /// multi or its share: the one its next search tries first, and the
    /// one a transfer that only connected sends and receives on
    /// (`state.last_cpid`). Forgotten as the handle joins a multi or
    /// changes to or from a share that keeps connections; a connection
    /// gone since fails its lookup.
    pub(crate) last_conn: Option<LastConn>,
    /// The HSTS and alt-svc caches, made the first time the application
    /// turns either on: few handles do.
    caches: Option<Box<HostCaches>>,
    /// The HSTS cache it uses (C's `hsts`), kept through `reset`.
    hsts: HstsUse,
    /// Where connections, resolved names and cookies are kept for the
    /// transfers after, if not in the handle's own multi (`CURLOPT_SHARE`,
    /// C's `data->share`): kept through `reset`, not copied with the
    /// handle.
    share: Option<Share>,
    /// Told around each use the transfers make of what the share keeps;
    /// goes with the share.
    pub(crate) share_watch: Option<Handler<dyn ShareLock>>,
    /// What the libraries bound beside the core do for it: the content
    /// codings it undoes, the signatures it makes, the TLS it speaks.
    libraries: SharedLibraries,
    /// Which components trace, read at each line: shared with whoever
    /// gave it, kept through `reset` and by a copy of the handle. Without
    /// one, only the lines of a verbose transfer that belong to no
    /// component are traced.
    components: Option<Components>,
    /// RTSP's sequence numbers and interleaved channels, from one
    /// request and connection to the next: kept through `reset`, not
    /// copied with the handle (C's `state.rtsp_*`). Made the first time
    /// either is set: few handles speak RTSP.
    rtsp: Option<Box<RtspState>>,
    /// What C keeps of the resolves its transfers started and has not let
    /// go of yet (`state.async`): not copied with the handle.
    pub(crate) asyncs: crate::conn::asyncs::Asyncs,
}

/// A handle let go of lets go of its resolves' records, each said
/// (`Curl_close`'s `Curl_resolv_destroy_all`).
impl Drop for Easy {
    fn drop(&mut self) {
        self.asyncs_let_go(TransferId::lone());
    }
}

/// A handle in a multi, as `Multi::easy_mut` gives it out: everything of
/// [`Easy`] that reads, and what may change whatever its transfer is doing.
/// Its share is not among that: whether it may change turns on what the
/// transfer holds, which the multi knows (`Multi::set_share`).
///
/// ```compile_fail,E0599
/// fn change<H: curl_core::multi::Host>(
///     multi: &mut curl_core::multi::Multi<H>,
///     id: curl_core::multi::TransferId,
/// ) {
///     let _ = multi.easy_mut(id).unwrap().set_share(None);
/// }
/// ```
pub struct EasyView<'a> {
    easy: &'a mut Easy,
    /// What its handlers are told it is: its id in its multi, or the
    /// lone handle's.
    id: TransferId,
}

impl std::ops::Deref for EasyView<'_> {
    type Target = Easy;

    fn deref(&self) -> &Easy {
        self.easy
    }
}

/// Each as the method of [`Easy`] it forwards to says.
impl EasyView<'_> {
    pub fn options_mut(&mut self) -> &mut Options {
        self.easy.options_mut()
    }

    pub fn tell_failure(&mut self, why: &[u8]) {
        self.easy.tell_failure(why);
    }

    pub fn forget_url(&mut self) {
        self.easy.forget_url();
    }

    pub fn show_set_url(&mut self) {
        self.easy.show_set_url();
    }

    pub fn reset(&mut self) {
        self.easy.reset_as(self.id);
    }

    pub fn release_resolves(&mut self) {
        self.easy.asyncs_let_go(self.id);
    }

    pub fn rtsp_mut(&mut self) -> Result<&mut RtspState, OutOfMemory> {
        self.easy.rtsp_mut()
    }

    pub fn set_libraries(&mut self, libraries: SharedLibraries) {
        self.easy.set_libraries(libraries);
    }

    pub fn enable_hsts(&mut self, mode: CacheFile) -> Result<(), OutOfMemory> {
        self.easy.enable_hsts(mode)
    }

    pub fn disable_hsts(&mut self) {
        self.easy.disable_hsts();
    }

    pub fn add_hsts_file(&mut self, file: Option<&[u8]>) -> Result<(), OutOfMemory> {
        self.easy.add_hsts_file(file)
    }

    pub fn enable_alt_svc(&mut self, ctrl: AltSvcCtrl) -> Result<(), OutOfMemory> {
        self.easy.enable_alt_svc(ctrl)
    }

    pub fn add_alt_svc_file(&mut self, file: Option<&[u8]>) -> Result<(), CacheLoadError> {
        self.easy.add_alt_svc_file(file)
    }

    pub fn enable_cookies(&mut self) -> Result<(), OutOfMemory> {
        self.easy.enable_cookies()
    }

    pub fn forget_cookies(&mut self) {
        self.easy.forget_cookies();
    }

    pub fn add_cookie(&mut self, line: &[u8], notes: impl FnMut(&[u8])) -> Result<(), OutOfMemory> {
        self.easy.add_cookie(line, notes)
    }

    pub fn clear_cookies(&mut self) -> Result<(), OutOfMemory> {
        self.easy.clear_cookies()
    }

    pub fn clear_session_cookies(&mut self) -> Result<(), OutOfMemory> {
        self.easy.clear_session_cookies()
    }

    pub fn reload_cookies(&mut self, notes: impl FnMut(&[u8])) -> Result<(), LoadError> {
        self.easy.reload_cookies(notes)
    }

    pub fn cookie_list(&mut self) -> Result<Vec<Vec<u8>>, OutOfMemory> {
        self.easy.cookie_list()
    }

    pub fn save_cookies(&mut self) -> Result<(), SaveError> {
        self.easy.save_cookies()
    }
}

/// What RTSP keeps from one request and connection to the next, through
/// `reset` (C's `state.rtsp_next_client_CSeq`, `rtsp_next_server_CSeq`,
/// `rtsp_CSeq_recv` and `rtp_channel_mask`). Its sequence numbers start
/// at 1 as a connection is first made, where none is set.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RtspState {
    pub(crate) next_client_cseq: u32,
    pub(crate) next_server_cseq: u32,
    pub(crate) cseq_recv: u32,
    /// The interleaved channels the `Transport:` headers named, a bit
    /// each.
    pub(crate) channels: [u8; 32],
}

impl RtspState {
    /// The CSeq the next request sends (`CURLINFO_RTSP_CLIENT_CSEQ`).
    pub fn next_client_cseq(&self) -> u32 {
        self.next_client_cseq
    }

    /// The CSeq the server's next request is expected with
    /// (`CURLINFO_RTSP_SERVER_CSEQ`).
    pub fn next_server_cseq(&self) -> u32 {
        self.next_server_cseq
    }

    /// The CSeq last received (`CURLINFO_RTSP_CSEQ_RECV`).
    pub fn cseq_recv(&self) -> u32 {
        self.cseq_recv
    }

    /// `CURLOPT_RTSP_CLIENT_CSEQ`.
    pub fn set_next_client_cseq(&mut self, n: u32) {
        self.next_client_cseq = n;
    }

    /// `CURLOPT_RTSP_SERVER_CSEQ`.
    pub fn set_next_server_cseq(&mut self, n: u32) {
        self.next_server_cseq = n;
    }

    /// Whether `channel` is one a `Transport:` header named.
    pub(crate) fn interleaves(&self, channel: u8) -> bool {
        self.channels[usize::from(channel / 8)] & (1 << (channel % 8)) != 0
    }

    /// `channel` is one to read RTP from.
    pub(crate) fn add_channel(&mut self, channel: u8) {
        self.channels[usize::from(channel / 8)] |= 1 << (channel % 8);
    }
}

/// The connection a handle's transfer had last (`state.last_cpid`).
#[derive(Clone, Copy, Debug)]
pub(crate) struct LastConn {
    pub(crate) id: ConnId,
    /// The handle has sent or received on it itself, which a transfer
    /// that only connected leaves it to (C's `data->conn`, attached again
    /// by `curl_easy_send` and `curl_easy_recv`): the handle's next
    /// perform closes it.
    pub(crate) used: bool,
}

/// The cookie jar a handle uses, and whether it is on (C's `cookies`,
/// the handle's own or its share's, with `cookie_engine`).
#[derive(Debug, Default)]
pub(crate) enum JarUse {
    /// None: the options and the application have not turned one on, and
    /// the handle is on no share keeping cookies.
    #[default]
    Off,
    /// Its own, on no share keeping cookies.
    Own(Box<Jar>),
    /// Its share's, as a handle joining a share that keeps cookies uses
    /// it: `on` as the handle's options or the application turned its jar
    /// on, before or since. Off, the transfers leave it alone but the
    /// application's calls on the jar still reach it, as C points the
    /// handle at the share's jar as it joins whatever its `cookie_engine`.
    Shared { on: bool },
}

impl JarUse {
    /// Whether the jar is on: the transfers send and store cookies.
    pub(crate) fn is_on(&self) -> bool {
        matches!(self, JarUse::Own(_) | JarUse::Shared { on: true })
    }
}

/// The HSTS cache a handle uses (C's `hsts`, the handle's own or its
/// share's, as `CURLOPT_HSTS_CTRL` and `CURLOPT_SHARE` leave it).
#[derive(Debug, Default)]
enum HstsUse {
    /// None: the application has not turned one on, and the handle is on
    /// no share keeping one.
    #[default]
    Off,
    /// Its own, on no share keeping one.
    Own(Box<Hsts>),
    /// Its share's, as a handle joining a share that keeps one uses it,
    /// turned on or not.
    Shared,
    /// On a share keeping one, the handle has let it go
    /// (`CURLOPT_HSTS_CTRL` without `CURLHSTS_ENABLE`): its own, once
    /// turned on again.
    Left(Option<Box<Hsts>>),
}

/// The caches of what servers said of hosts, each once the application
/// turns it on, kept from one transfer to the next and through `reset`.
#[derive(Debug, Default)]
struct HostCaches {
    /// The files read into the cache in use as each transfer starts (C's
    /// `state.hstslist`).
    hsts_files: Vec<Vec<u8>>,
    /// Whether this handle writes the cache's file back.
    hsts_mode: CacheFile,
    /// C's `asi`.
    alt_svc: Option<AltSvc>,
}

/// A handle's own multi (C's `multi_easy`).
pub(crate) struct Private {
    pub(crate) multi: Multi,
    /// What the multi last told the callbacks of a perform driven by
    /// events, which stay set on it until it goes, as C's do: its
    /// cleanup's changes are heard there.
    pub(crate) events: Option<EventTable>,
}

impl fmt::Debug for Private {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Private")
    }
}

impl Drop for Private {
    fn drop(&mut self) {
        if let Some(table) = &mut self.events {
            self.multi.close_connections(table);
        }
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

    /// Report no URL until the next transfer starts, as setting
    /// `CURLOPT_CURLU` frees C's `state.url`: `CURLINFO_EFFECTIVE_URL` is
    /// then empty.
    pub fn forget_url(&mut self) {
        self.report.forget_url();
    }

    /// Report the URL the options give (`CURLOPT_URL`) until the next
    /// transfer starts, as setting it points C's `state.url` at it, or
    /// none if none is set: read back only as getinfo asks.
    pub fn show_set_url(&mut self) {
        if self.options.url().is_some() {
            self.report.show_set_url();
        } else {
            self.report.forget_url();
        }
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

    /// A reason the handle failed, given by an API call rather than a
    /// transfer (`failf`): kept and told to the failure sink if it is the
    /// first since the last transfer's start. With no sink it is kept
    /// nowhere, so the first a sink could hear is the one it hears.
    pub fn tell_failure(&mut self, why: &[u8]) {
        let Some(sink) = self.options.callbacks.failure.clone() else {
            return;
        };
        let first = self.report.unsaid();
        self.report.record_told(why);
        if first {
            sink.write(why);
        }
    }

    /// The work of the multi's this handle does, which its lines name.
    pub(crate) fn doing(&self) -> Option<crate::components::Component> {
        self.doing
    }

    pub(crate) fn report_mut(&mut self) -> &mut TransferReport {
        &mut self.report
    }

    /// A handle for a response the server pushes in answer to one of this
    /// handle's requests (`h2_duphandle`): this one's libraries and share,
    /// its stream's weight, and where its output, its headers, its trace
    /// and its progress go; nothing else.
    pub(crate) fn pushed(&self) -> Easy {
        let mut pushed = Easy::default();
        pushed.libraries = self.libraries.clone();
        pushed.components = self.components.clone();
        // Linked to the share as C links it (`Curl_share_easy_link`): the
        // share's jar and HSTS cache taken up, the jar off.
        pushed.link_share(self.share.clone());
        pushed.share_watch = self.share_watch.clone();
        let (to, from) = (&mut pushed.options, &self.options);
        to.http.stream_weight = from.http.stream_weight;
        to.callbacks.write = from.callbacks.write.clone();
        to.callbacks.header = from.callbacks.header.clone();
        to.callbacks.debug = from.callbacks.debug.clone();
        to.progress = from.progress.clone();
        pushed
    }

    /// A handle for a DoH probe posting `query` to this handle's DoH server,
    /// with `left` to do it in (`doh_probe_run`): this one's libraries and
    /// share, its trace if it traces DoH, and the TLS settings C has probes
    /// inherit; nothing else, not its proxy.
    pub(crate) fn doh_probe(
        &self,
        query: &[u8],
        body: Handler<dyn WriteHandler>,
        left: Option<Duration>,
    ) -> Result<Easy, OutOfMemory> {
        let mut probe = Easy::default();
        probe.doing = Some(crate::components::Component::Doh);
        probe.components = self.components.clone();
        probe.libraries = self.libraries.clone();
        probe.link_share(self.share.clone());
        probe.share_watch = self.share_watch.clone();
        let (to, from) = (&mut probe.options, &self.options);
        let url = from.doh.url.as_deref();
        to.set_url(url)?;
        to.set_default_protocol(Some(b"https"))?;
        *to.dns.make_mut()? = from.dns.try_clone_for_resolve()?;
        to.callbacks.write = Some(body);
        to.upload =
            crate::options::UploadSource::Bytes(TryArc::try_new(crate::options::copy(query)?)?);
        to.method = crate::options::Method::Post;
        to.http.headers =
            crate::options::UserHeaders::new([&b"Content-Type: application/dns-message"[..]])?;
        let maybe_https = !url.is_some_and(|u| {
            u.get(..5)
                .is_some_and(|scheme| scheme.eq_ignore_ascii_case(b"http:"))
        });
        if maybe_https {
            to.http.version = crate::options::HttpVersion::Http2Tls;
            to.http.pipewait = true;
        }
        // HTTP as well only in the debug build, for the tests.
        #[cfg(any(test, feature = "debug-hooks"))]
        let schemes: &[&str] = &["http", "https"];
        #[cfg(not(any(test, feature = "debug-hooks")))]
        let schemes: &[&str] = &["https"];
        to.schemes.make_mut()?.allowed =
            crate::options::Protocols::of(schemes).expect("libcurl knows them");
        to.limits.total = left.and_then(|d| {
            let ms = u64::try_from(d.as_millis()).unwrap_or(u64::MAX);
            crate::time::TimeLimit::from_millis(ms)
        });
        to.callbacks.stderr = from.callbacks.stderr.clone();
        to.callbacks.debug = from.callbacks.debug.clone();
        let traces = self
            .components
            .as_ref()
            .is_some_and(|c| c.traces(crate::components::Component::Doh));
        to.output.verbose = from.output.verbose && traces;
        if maybe_https {
            to.tls.verify_host = from.doh.verify_host;
            to.tls.verify_peer = from.doh.verify_peer;
            to.tls.certinfo = from.tls.certinfo;
            let (t, f) = (to.tls.options.make_mut()?, &*from.tls.options);
            t.verify_status = from.doh.verify_status;
            t.ca_file = f.ca_file.try_clone()?;
            t.ca_path = f.ca_path.try_clone()?;
            t.ca_blob = f.ca_blob.try_clone()?;
            t.crl_file = f
                .crl_file
                .as_deref()
                .map(crate::options::copy)
                .transpose()?;
            t.curves = f.curves.as_deref().map(crate::options::copy).transpose()?;
            t.context = f.context.clone();
            let auto = crate::options::SslOptions::AUTO_CLIENT_CERT.bits();
            t.ssl_options = crate::options::SslOptions::from_bits(f.ssl_options.bits() & !auto);
        }
        Ok(probe)
    }

    /// A handle with the same options (`curl_easy_duphandle`).
    pub fn try_clone(&self) -> Result<Easy, OutOfMemory> {
        self.try_clone_with(&mut |_| Ok(()))
    }

    /// As `try_clone`, `prepare` given the copy's options before the copy
    /// reads anything through them: its HSTS file and reader are read as
    /// it is made, so a handler that should be the copy's is made the
    /// copy's here.
    pub fn try_clone_with(
        &self,
        prepare: &mut dyn FnMut(&mut Options) -> Result<(), OutOfMemory>,
    ) -> Result<Easy, OutOfMemory> {
        let mut copy = Easy {
            doing: None,
            options: self.options.try_clone()?,
            report: TransferReport::default(),
            meter_titled: false,
            resolve_read: 0,
            wildcard_resolve: false,
            auth: Auth::default(),
            private: None,
            // A jar of its own, empty, if this one's is on.
            jar: match self.jar.is_on() {
                true => JarUse::Own(try_box(Jar::default())?),
                false => JarUse::Off,
            },
            set_cookies: 0,
            shown_credentials: None,
            last_conn: None,
            caches: None,
            hsts: HstsUse::Off,
            share: None,
            share_watch: None,
            libraries: self.libraries.clone(),
            components: self.components.clone(),
            rtsp: None,
            asyncs: Default::default(),
        };
        prepare(&mut copy.options)?;
        let now = crate::date::cache_now(SystemClock::new().unix_time());
        if let Some(alive) = self.read_hsts(|hsts| hsts.alive_copy(now)) {
            let hsts = copy.hsts_copy(alive?, now)?;
            copy.hsts = HstsUse::Own(try_box(hsts)?);
            copy.caches_made()?.hsts_mode = self.hsts_mode();
        }
        if let Some(original) = self.alt_svc() {
            // A cache of its own, which reads the file named, as C's copy
            // does; it keeps the original's control, which C's copy
            // loses (DIVERGENCE.md).
            let mut a = original.copy_empty();
            if let Some(file) = &copy.options.http.alt_svc.file {
                let now = crate::date::cache_now(SystemClock::new().unix_time());
                // What fails to be read is passed over, as in C.
                if let Err(CacheLoadError::OutOfMemory) = a.load(file, now) {
                    return Err(OutOfMemory);
                }
            }
            copy.caches_made()?.alt_svc = Some(a);
        }
        Ok(copy)
    }

    /// The HSTS cache this copy of a handle starts with
    /// (`curl_easy_duphandle`): its file and the application's reader read
    /// into a new one, as C reads them, then `alive`, the entries alive in
    /// the original's. What fails to be read is passed over, as in C.
    fn hsts_copy(&self, alive: Hsts, now: i64) -> Result<Hsts, OutOfMemory> {
        let mut copy = Hsts::default();
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
        copy.merge(alive)?;
        Ok(copy)
    }

    /// Every option back to its default, and the report with them but
    /// for its last socket error (`curl_easy_reset`). The private multi
    /// and the cookie jar stay.
    pub fn reset(&mut self) {
        self.reset_as(TransferId::lone());
    }

    /// The same, its handlers told it is `me`.
    fn reset_as(&mut self, me: TransferId) {
        // Said while the handle's settings still trace (`curl_easy_reset`'s
        // `Curl_req_hard_reset`, before `Curl_freeset`).
        self.asyncs_let_go(me);
        self.options = Options::default();
        self.report = self.report.reset();
        self.meter_titled = false;
        self.resolve_read = 0;
        self.wildcard_resolve = false;
        self.auth = Auth::default();
        self.set_cookies = 0;
    }

    /// Let go of what the handle keeps of the resolves its transfers
    /// started, each said as C says it (`Curl_close`'s
    /// `Curl_resolv_destroy_all`). Dropping the handle does it too; one
    /// whose debug handler reaches what holds the handle calls it first,
    /// while that is whole.
    pub fn release_resolves(&mut self) {
        self.asyncs_let_go(TransferId::lone());
    }

    /// Whether it keeps a record of a resolve, which `release_resolves`
    /// or dropping it lets go of.
    pub fn holds_resolves(&self) -> bool {
        self.asyncs.nth_newest(0).is_some()
    }

    /// Each of its resolves' records let go of, the newest first, said as
    /// it goes outside any transfer's step, its handlers told it is `me`
    /// (`Curl_resolv_destroy_all`).
    fn asyncs_let_go(&mut self, me: TransferId) {
        while let Some(id) = self.asyncs.pop_newest() {
            let id = id.get();
            let dns = crate::components::Component::Dns;
            trace::of_lone(self, me, dns, format_args!("[{id}] destroy async"));
        }
    }

    /// What RTSP keeps from one request to the next.
    pub fn rtsp(&self) -> RtspState {
        self.rtsp.as_deref().copied().unwrap_or_default()
    }

    /// The same, to change: made now if not yet.
    pub fn rtsp_mut(&mut self) -> Result<&mut RtspState, curl_alloc::OutOfMemory> {
        if self.rtsp.is_none() {
            self.rtsp = Some(curl_alloc::try_box(RtspState::default())?);
        }
        Ok(self.rtsp.as_deref_mut().expect("made above"))
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

    /// Whether the handle has taken a connection a transfer only made as
    /// its own, by sending or receiving on it (C's `data->conn`, outside a
    /// transfer).
    pub fn holds_connection(&self) -> bool {
        self.last_conn.is_some_and(|l| l.used)
    }

    /// Use `share` for the transfers from now on, or none; refused while
    /// the handle holds a connection it only made (`setopt_share`). A
    /// handle in a multi changes through `Multi::set_share`, which knows
    /// of its running transfer's.
    pub fn set_share(&mut self, share: Option<Share>) -> Result<(), ShareInUse> {
        self.share_may_change()?;
        self.forget_pool(share.as_ref());
        self.relink_jar(share.as_ref());
        self.relink_hsts(share.as_ref());
        self.share = share;
        self.share_watch = None;
        Ok(())
    }

    /// Use `share` for the transfers from now on, `watch` told around
    /// each use they make of what it keeps; refused as [`Easy::set_share`]
    /// is.
    pub fn set_share_watched(
        &mut self,
        share: Share,
        watch: Handler<dyn ShareLock>,
    ) -> Result<(), ShareInUse> {
        self.share_may_change()?;
        self.forget_pool(Some(&share));
        self.relink_jar(Some(&share));
        self.relink_hsts(Some(&share));
        self.share = Some(share);
        self.share_watch = Some(watch);
        Ok(())
    }

    /// Leave the share as the handle is closed, a connection it only made
    /// going with it (`Curl_share_easy_unlink`). Out of a multi no transfer
    /// runs, so nothing refuses it; in one, `Multi::leave_share` does for a
    /// running transfer's connection.
    pub fn leave_share(&mut self) {
        self.forget_pool(None);
        self.relink_jar(None);
        self.relink_hsts(None);
        self.share = None;
        self.share_watch = None;
    }

    /// Join `share`, a handle made here that holds no connection, as
    /// `CURLOPT_SHARE` joins it: what it keeps of cookies and HSTS taken
    /// up as C points the handle at them.
    fn link_share(&mut self, share: Option<Share>) {
        self.set_share(share)
            .expect("a handle just made holds no connection");
    }

    fn share_may_change(&self) -> Result<(), ShareInUse> {
        if self.holds_connection() {
            return Err(ShareInUse);
        }
        Ok(())
    }

    /// The handle as one in a multi is reached, for code taking either.
    pub fn view(&mut self) -> EasyView<'_> {
        self.view_as(TransferId::lone())
    }

    /// The handle as its multi reaches it, as `id`.
    pub(crate) fn view_as(&mut self, id: TransferId) -> EasyView<'_> {
        EasyView { easy: self, id }
    }

    /// Forget the last connection, if the pool it is in changes: leaving
    /// a share that keeps connections, or joining one
    /// (`Curl_share_easy_unlink`, `Curl_share_easy_link`).
    fn forget_pool(&mut self, next: Option<&Share>) {
        let kept = self.shared(Kind::Connections).is_some();
        if kept || next.is_some_and(|s| s.keeps(Kind::Connections)) {
            self.last_conn = None;
            self.report.set_conn(None);
        }
    }

    /// As the share changes to `next`: joining one that keeps cookies, the
    /// handle's own are gone and the share's used in their place, the jar
    /// on or off as it was; leaving one, it has no jar until something
    /// turns one on (`Curl_share_easy_link`, `Curl_share_easy_unlink`).
    fn relink_jar(&mut self, next: Option<&Share>) {
        if next.is_some_and(|s| s.keeps(Kind::Cookies)) {
            self.jar = JarUse::Shared {
                on: self.jar.is_on(),
            };
        } else if let JarUse::Shared { .. } = self.jar {
            self.jar = JarUse::Off;
        }
    }

    /// As the share changes to `next`: joining one that keeps an HSTS
    /// cache, the handle's own is gone and the share's used, turned on or
    /// not; leaving one, the handle has only its own, if it made one after
    /// letting go of the share's (`Curl_share_easy_link`,
    /// `Curl_share_easy_unlink`). The files named stay.
    fn relink_hsts(&mut self, next: Option<&Share>) {
        let own = match std::mem::take(&mut self.hsts) {
            HstsUse::Own(own) | HstsUse::Left(Some(own)) => Some(own),
            HstsUse::Off | HstsUse::Shared | HstsUse::Left(None) => None,
        };
        self.hsts = match (next.is_some_and(|s| s.keeps(Kind::Hsts)), own) {
            (true, _) => HstsUse::Shared,
            (false, Some(own)) => HstsUse::Own(own),
            (false, None) => HstsUse::Off,
        };
    }

    /// The share the handle's `kind` is kept in, if it is kept in one;
    /// else it is the handle's own, or its multi's. The one answer for
    /// every kind, asked at each use: for cookies and the HSTS cache, what
    /// the handle took up as it joined the share, as C points the handle
    /// at the share's then; for the rest, what the share keeps, as C asks
    /// the share's `specifier` at each use. Whether the application is
    /// told of a use is the share's to say ([`watched`]), not this.
    pub(crate) fn shared(&self, kind: Kind) -> Option<&Share> {
        let share = self.share.as_ref()?;
        let kept = match kind {
            Kind::Cookies => matches!(self.jar, JarUse::Shared { .. }),
            Kind::Hsts => matches!(self.hsts, HstsUse::Shared),
            Kind::Connections | Kind::Names | Kind::SslSessions | Kind::Psl => share.keeps(kind),
        };
        kept.then_some(share)
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

    /// What says the build has public suffixes to the jar, for cookies
    /// whose domains are not checked against them.
    fn unasked_suffixes(&self) -> Option<&'static dyn SuffixCheck> {
        self.libraries.psl.map(|_| &NeverAsked as &dyn SuffixCheck)
    }

    /// Turn the HSTS cache on, empty, if it is not, its file written back
    /// as `mode` says (`CURLHSTS_ENABLE`, `CURLHSTS_READONLYFILE`).
    pub fn enable_hsts(&mut self, mode: CacheFile) -> Result<(), OutOfMemory> {
        self.hsts_made()?;
        self.caches_made()?.hsts_mode = mode;
        Ok(())
    }

    /// Make an HSTS cache of the handle's own, empty, if it uses none.
    fn hsts_made(&mut self) -> Result<(), OutOfMemory> {
        match &mut self.hsts {
            HstsUse::Off => self.hsts = HstsUse::Own(try_box(Hsts::default())?),
            HstsUse::Left(own @ None) => *own = Some(try_box(Hsts::default())?),
            HstsUse::Own(_) | HstsUse::Left(Some(_)) | HstsUse::Shared => {}
        }
        Ok(())
    }

    /// Whether the handle is on a share keeping an HSTS cache, using it or
    /// having let it go.
    fn on_hsts_share(&self) -> bool {
        matches!(self.hsts, HstsUse::Shared | HstsUse::Left(_))
    }

    /// Run `f` on the HSTS cache the handle uses, if any: its share's, if
    /// that keeps one, under its lock, else its own. The application is
    /// not told: C locks the cache only around the files it reads
    /// ([`Easy::with_hsts_told`]). Nothing `f` does may call out.
    pub(crate) fn with_hsts<R>(&mut self, f: impl FnOnce(&mut Hsts) -> R) -> Option<R> {
        if let Some(share) = self.shared(Kind::Hsts) {
            return share.hsts().as_mut().map(f);
        }
        match &mut self.hsts {
            HstsUse::Own(own) | HstsUse::Left(Some(own)) => Some(f(own)),
            HstsUse::Off | HstsUse::Shared | HstsUse::Left(None) => None,
        }
    }

    /// As [`Easy::with_hsts`], reading it from a handle not to be changed.
    pub(crate) fn read_hsts<R>(&self, f: impl FnOnce(&Hsts) -> R) -> Option<R> {
        if let Some(share) = self.shared(Kind::Hsts) {
            return share.hsts().as_ref().map(f);
        }
        match &self.hsts {
            HstsUse::Own(own) | HstsUse::Left(Some(own)) => Some(f(own)),
            HstsUse::Off | HstsUse::Shared | HstsUse::Left(None) => None,
        }
    }

    /// As [`Easy::with_hsts`], the application told around it if the share
    /// keeps a cache, even with the handle using its own, as C's lock asks
    /// only what the share keeps (`Curl_hsts_loadfiles`).
    fn with_hsts_told<R>(&mut self, f: impl FnOnce(&mut Hsts) -> R) -> Option<R> {
        let Some(share) = self.share.clone() else {
            return self.with_hsts(f);
        };
        let watch = self.share_watch.clone();
        watched(watch.as_deref(), &share, Kind::Hsts, || self.with_hsts(f))
    }

    /// Read the files named into the cache the handle uses, as one use of
    /// the share's (`Curl_hsts_loadfiles`). Without a cache they stay named
    /// and are not read: C dereferences the cache it does not have
    /// (DIVERGENCE.md).
    pub(crate) fn load_hsts_files(&mut self, now: i64) -> Result<(), crate::hsts::LoadError> {
        let Some(caches) = self.caches.as_deref_mut() else {
            return Ok(());
        };
        if caches.hsts_files.is_empty() {
            return Ok(());
        }
        let files = std::mem::take(&mut caches.hsts_files);
        let loaded = self.with_hsts_told(|hsts| files.iter().try_for_each(|f| hsts.load(f, now)));
        if let Some(caches) = self.caches.as_deref_mut() {
            caches.hsts_files = files;
        }
        loaded.unwrap_or(Ok(()))
    }

    /// How many HSTS files are read as each transfer starts.
    #[cfg(test)]
    pub(crate) fn hsts_files_named(&self) -> usize {
        self.caches.as_deref().map_or(0, |c| c.hsts_files.len())
    }

    /// Whether this handle writes the HSTS cache's file back.
    fn hsts_mode(&self) -> CacheFile {
        self.caches
            .as_deref()
            .map_or_else(CacheFile::default, |c| c.hsts_mode)
    }

    /// The caches, made now if the handle has none.
    fn caches_made(&mut self) -> Result<&mut HostCaches, OutOfMemory> {
        if self.caches.is_none() {
            self.caches = Some(try_box(HostCaches::default())?);
        }
        Ok(self.caches.as_deref_mut().expect("made above"))
    }

    /// The alt-svc cache, if on.
    pub(crate) fn alt_svc(&self) -> Option<&AltSvc> {
        self.caches.as_deref()?.alt_svc.as_ref()
    }

    pub(crate) fn alt_svc_mut(&mut self) -> Option<&mut AltSvc> {
        self.caches.as_deref_mut()?.alt_svc.as_mut()
    }

    /// Turn the HSTS cache off (`CURLOPT_HSTS_CTRL` without
    /// `CURLHSTS_ENABLE`): its entries and the files named are forgotten,
    /// but on a share keeping one the share's is only let go, and the files
    /// stay named.
    pub fn disable_hsts(&mut self) {
        if self.on_hsts_share() {
            self.hsts = HstsUse::Left(None);
            return;
        }
        self.hsts = HstsUse::Off;
        if let Some(caches) = self.caches.as_deref_mut() {
            caches.hsts_files = Vec::new();
            caches.hsts_mode = CacheFile::default();
        }
    }

    /// Read the HSTS file `file` into the cache as each transfer starts,
    /// and write the cache to it as the handle goes; the cache is turned
    /// on. Without a file, the files named are forgotten and the cache
    /// turned off, unless it is a share's (`CURLOPT_HSTS`).
    pub fn add_hsts_file(&mut self, file: Option<&[u8]>) -> Result<(), OutOfMemory> {
        self.hsts_made()?;
        let Some(file) = file else {
            if self.on_hsts_share() {
                if let Some(caches) = self.caches.as_deref_mut() {
                    caches.hsts_files = Vec::new();
                }
            } else {
                self.disable_hsts();
            }
            return Ok(());
        };
        let mut copy = Vec::new();
        copy.try_extend_from_slice(file)?;
        let mut named = Vec::new();
        named.try_extend_from_slice(file)?;
        self.caches_made()?.hsts_files.try_push(named)?;
        self.options.http.hsts.make_mut()?.file = Some(copy);
        Ok(())
    }

    /// Whether the HSTS cache is on.
    pub fn hsts_enabled(&self) -> bool {
        self.read_hsts(|_| ()).is_some()
    }

    /// Write the HSTS cache, if it is on, to `HstsOptions::file` or else
    /// the file last read, and give it to the application's writer
    /// (`Curl_hsts_save`). A file not written, or a writer that says the
    /// save fails, fails it, after the rest is done. What is written is
    /// taken from a share's cache under its lock, and written and given to
    /// the writer, the application's, once that is let go; C does not tell
    /// the lock functions of any of it.
    pub fn save_hsts(&mut self) -> Result<(), SaveError> {
        let options = &*self.options.http.hsts;
        // C never sets the flag it tests, so writes a read-only file back
        // (DIVERGENCE.md).
        let written = self.hsts_mode() == CacheFile::ReadWrite;
        let taken = self.read_hsts(|hsts| -> Result<_, OutOfMemory> {
            let file = options.file.as_deref().or(hsts.file());
            let file = file.filter(|f| written && !f.is_empty());
            let file = file.map(crate::options::copy).transpose()?;
            let text = file.is_some().then(|| hsts.text()).transpose()?;
            let every = options.write.as_ref().map(|_| hsts.alive_copy(i64::MIN));
            Ok((file.zip(text), every.transpose()?))
        });
        let Some(taken) = taken else {
            return Ok(());
        };
        let (to_file, every) = taken?;
        let mut result = Ok(());
        if let Some((file, text)) = to_file {
            result = crate::save::replace(&file, &text);
        }
        if let (Some(writer), Some(every)) = (&options.write, every) {
            // The writer's verdict is the save's, as C's is.
            result = match every.push(&**writer) {
                true => Ok(()),
                false => Err(SaveError::Write),
            };
        }
        result
    }

    /// Turn the alt-svc cache on, empty, if it is not, and have it behave
    /// as `ctrl` says (`CURLOPT_ALTSVC_CTRL`).
    pub fn enable_alt_svc(&mut self, ctrl: AltSvcCtrl) -> Result<(), OutOfMemory> {
        self.alt_svc_made()?.set_ctrl(ctrl);
        Ok(())
    }

    /// The alt-svc cache, made empty now if the handle has none.
    fn alt_svc_made(&mut self) -> Result<&mut AltSvc, OutOfMemory> {
        Ok(self
            .caches_made()?
            .alt_svc
            .get_or_insert_with(AltSvc::default))
    }

    /// Read the alt-svc file `file` into the cache now, and write the
    /// cache to it as the handle goes; the cache is turned on. Without a
    /// file, the cache is still turned on, and written to the file last
    /// read (`CURLOPT_ALTSVC`). A file that cannot be opened adds
    /// nothing; one that cannot be read fails, as C's does.
    pub fn add_alt_svc_file(&mut self, file: Option<&[u8]>) -> Result<(), CacheLoadError> {
        self.alt_svc_made()?;
        let copy = file.map(crate::options::copy).transpose()?;
        self.options.http.alt_svc.make_mut()?.file = copy;
        let Some(file) = file else {
            return Ok(());
        };
        let now = crate::date::cache_now(SystemClock::new().unix_time());
        let alt_svc = self.alt_svc_mut().expect("made above");
        alt_svc.load(file, now)
    }

    /// Whether the alt-svc cache is on.
    pub fn alt_svc_enabled(&self) -> bool {
        self.alt_svc().is_some()
    }

    /// Write the alt-svc cache, if it is on and its file not read-only,
    /// to `AltSvcOptions::file` or else the file last read
    /// (`Curl_altsvc_save`).
    pub fn save_alt_svc(&mut self) -> Result<(), SaveError> {
        let Some(alt_svc) = self.alt_svc() else {
            return Ok(());
        };
        let file = self.options.http.alt_svc.file.as_deref();
        let file = file.or(alt_svc.file());
        match file {
            Some(file) if alt_svc.ctrl().file == CacheFile::ReadWrite && !file.is_empty() => {
                crate::save::replace(file, &alt_svc.text()?)
            }
            _ => Ok(()),
        }
    }

    /// Turn the cookie jar on: one of the handle's own, empty, if it has
    /// none (`CURLOPT_COOKIEJAR`). Making it is what can run out of
    /// memory.
    pub fn enable_cookies(&mut self) -> Result<(), OutOfMemory> {
        match &mut self.jar {
            JarUse::Off => self.jar = JarUse::Own(try_box(Jar::default())?),
            JarUse::Shared { on } => *on = true,
            JarUse::Own(_) => {}
        }
        if let Some(cookies) = self.options.http.cookies.made_mut() {
            cookies.jar_made();
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
        self.jar = match self.jar {
            JarUse::Shared { .. } => JarUse::Shared { on: false },
            JarUse::Off | JarUse::Own(_) => JarUse::Off,
        };
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
        let list = self.unasked_suffixes();
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
        let list = self.unasked_suffixes();
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
        Ok(self.own_jar().map(f))
    }

    /// The handle's own jar, if it has one: none if it is off or the
    /// share's.
    pub(crate) fn own_jar(&mut self) -> Option<&mut Jar> {
        match &mut self.jar {
            JarUse::Own(jar) => Some(jar),
            JarUse::Off | JarUse::Shared { .. } => None,
        }
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
        let Some(share) = self.shared(Kind::Cookies) else {
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
        let Some(to) = self.options.http.cookies.save_to() else {
            self.watch_shared_jar();
            return Ok(());
        };
        let save = |jar: &mut Jar| match jar.running() {
            true => write_jar(jar, to),
            false => Ok(()),
        };
        let written = match self.with_shared_jar(save) {
            Ok(written) => written,
            // The jar alone, the options borrowed for its name.
            Err(save) => match &mut self.jar {
                JarUse::Own(jar) => Some(save(jar)),
                JarUse::Off | JarUse::Shared { .. } => None,
            },
        };
        written.unwrap_or(Ok(()))
    }

    /// Run the transfer to its end, blocking (`curl_easy_perform`), in the
    /// handle's own multi, made the first time with the system's network.
    pub fn perform(&mut self) -> Result<(), Error> {
        self.perform_by(false)
    }

    /// Run the transfer to its end as `perform` does, driven through
    /// `socket_action` by what the multi tells its timer and socket
    /// callbacks (the debug build's `curl_easy_perform_ev`).
    #[cfg(feature = "debug-hooks")]
    pub fn perform_ev(&mut self) -> Result<(), Error> {
        self.perform_by(true)
    }

    /// Run the transfer to its end as `perform` does, for a handle already
    /// in memory of its own, as a multi holds one: the box itself goes into
    /// the handle's multi and comes back, nothing copied or allocated for
    /// it. The handle, and the transfer's result.
    pub fn perform_boxed(self: Box<Self>) -> (Box<Easy>, Result<(), Error>) {
        self.perform_boxed_by(false)
    }

    /// `perform_boxed`, driven through `socket_action` as `perform_ev`
    /// drives it.
    #[cfg(feature = "debug-hooks")]
    pub fn perform_ev_boxed(self: Box<Self>) -> (Box<Easy>, Result<(), Error>) {
        self.perform_boxed_by(true)
    }

    fn perform_by(&mut self, by_events: bool) -> Result<(), Error> {
        // The multi holds its transfers in memory of their own.
        match curl_alloc::try_box_or_back(std::mem::take(self)) {
            Ok(easy) => {
                let (easy, result) = easy.perform_boxed_by(by_events);
                *self = *easy;
                result
            }
            Err(easy) => {
                *self = easy;
                let kind = ErrorKind::OutOfMemory;
                Err(Error::with_detail(kind, self.report().failure()))
            }
        }
    }

    fn perform_boxed_by(mut self: Box<Self>, by_events: bool) -> (Box<Easy>, Result<(), Error>) {
        let mut private = match self.private_multi() {
            Ok(private) => private,
            Err(kind) => return (self, Err(kind.into())),
        };
        let Private { multi, events } = &mut *private;
        let drive = if by_events {
            Drive::Events(events.get_or_insert_with(EventTable::default))
        } else {
            Drive::Waits
        };
        let (mut easy, result) = run_in(multi, self, drive);
        easy.private = Some(private);
        (easy, result)
    }

    /// The multi a perform runs the handle in: the one it kept, or one
    /// made now, the first time.
    fn private_multi(&mut self) -> Result<Box<Private>, ErrorKind> {
        let private = match self.private.take() {
            Some(private) => private,
            None => {
                // Winsock, started while the multi's waker and network are
                // made, until the multi holds a start of its own; a refusal
                // fails the sockets as they open.
                let _winsock = curl_os::net::Winsock::start().ok();
                // A waker, as every C multi has one (`Curl_wakeup_init`),
                // watched as a perform's multi waits; without the
                // descriptors for it, the multi goes without.
                let waker = match Waker::new() {
                    Ok(w) => Some(TryArc::try_new(w).map_err(oom)?),
                    Err(_) => None,
                };
                // A multi whose resolver cannot be set up is not made
                // (`Curl_multi_handle`'s `goto error`).
                let net = try_box(
                    SystemNet::for_multi(crate::conn::threaded::Threads::EASY)
                        .map_err(|_| ErrorKind::OutOfMemory)?,
                )
                .map_err(oom)?;
                let arena = ArenaPolicy::new(16, 0).expect("a valid policy");
                let env = Env::new(net, arena, waker);
                let mut multi = Multi::new(env).map_err(oom)?;
                // As few TLS peers as C's `multi_easy` keeps.
                multi.keep_tls_sessions_of(crate::tls::SessionCache::PERFORM_PEERS);
                multi.make_handle_own();
                try_box(Private {
                    multi,
                    events: None,
                })
                .map_err(oom)?
            }
        };
        Ok(private)
    }

    /// Run the transfer to its end in `multi`, driven as `drive` says: a
    /// test's multi in place of the handle's own.
    #[cfg(test)]
    pub(crate) fn perform_in(&mut self, multi: &mut Multi, drive: Drive) -> Result<(), Error> {
        // The multi holds its transfers in memory of their own.
        match curl_alloc::try_box_or_back(std::mem::take(self)) {
            Ok(easy) => {
                let (easy, result) = run_in(multi, easy, drive);
                *self = *easy;
                result
            }
            Err(easy) => {
                *self = easy;
                let kind = ErrorKind::OutOfMemory;
                Err(Error::with_detail(kind, self.report().failure()))
            }
        }
    }
}

/// Run `easy`'s transfer to its end in `multi`, driven as `drive` says:
/// the handle, and the transfer's result.
fn run_in(multi: &mut Multi, easy: Box<Easy>, drive: Drive) -> (Box<Easy>, Result<(), Error>) {
    // The easy handle's limit is its multi's (`curl_easy_perform`).
    multi.conn_limits_mut().max_connects = Some(easy.options().limits.reuse.max_connects);
    multi.set_quick_exit(easy.options().quick_exit);
    let (result, easy) = run_to_end(multi, easy, drive);
    let result = result.map_err(|kind| Error::with_detail(kind, easy.report().failure()));
    (easy, result)
}

/// The jar's cookies, swept of those expired, to the file `to`.
fn write_jar(jar: &mut Jar, to: &[u8]) -> Result<(), SaveError> {
    let mut text = Vec::new();
    jar.file(SystemClock::new().unix_time(), &mut text)?;
    if to == b"-" {
        // In the mode standard output is in, as C's `fputs` to `stdout`.
        let mode = curl_os::fs::mode(curl_os::fs::Std::Out);
        let mut out = curl_os::text::Writer::new(std::io::stdout().lock(), mode);
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
#[derive(Debug)]
pub(crate) enum Drive<'t> {
    /// Waiting on the multi's sockets, then running it (`easy_transfer`).
    Waits,
    /// Through `socket_action`, by what it tells its callbacks, watching
    /// what the table holds (`easy_events`).
    Events(&'t mut EventTable),
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
        Drive::Events(table) => {
            drive_by_events_with(multi, id, table).unwrap_or_else(|e| Err(multi_error(e)))
        }
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

    /// A pushed transfer's handle takes its parent's libraries, trace
    /// components, share and the share's watch, the very ones and not
    /// copies (`h2_duphandle`).
    #[test]
    fn a_pushed_handle_takes_its_parent_s_libraries_and_share() {
        let mut e = Easy::new();
        e.set_libraries(SharedLibraries::new(crate::libraries::Libraries::NONE).unwrap());
        e.set_components(Some(crate::components::Components::new().unwrap()));
        let share = crate::share::Share::new().unwrap();
        let told = crate::share::Told::new(&share);
        e.set_share_watched(share.clone(), told.handler()).unwrap();
        let pushed = e.pushed();
        assert!(std::ptr::eq(&*pushed.libraries, &*e.libraries));
        let components = pushed.components().expect("the parent's components");
        components.configure(b"multi");
        assert!(
            e.components()
                .unwrap()
                .traces(crate::components::Component::Multi)
        );
        assert!(pushed.share().is_some_and(|s| s.is(&share)));
        assert!(pushed.share_watch().is_some());
    }

    /// A build with a public suffix list takes the application's cookie for
    /// a domain with no dot, which it does not check; one without refuses it
    /// (`parse_cookie_header` under `USE_LIBPSL`).
    #[test]
    fn the_application_s_cookie_is_taken_as_the_build_s_list_says() {
        struct NoList;
        impl crate::psl::SuffixLibrary for NoList {
            fn latest(&self) -> Option<crate::cookie::Suffixes> {
                None
            }
            fn builtin(&self) -> Option<crate::cookie::Suffixes> {
                None
            }
        }
        static LIBRARY: NoList = NoList;
        let line = b"Set-Cookie: a=1; domain=com";
        let mut with = Easy::new();
        let libraries = crate::libraries::Libraries {
            psl: Some(&LIBRARY),
            ..crate::libraries::Libraries::NONE
        };
        with.set_libraries(SharedLibraries::new(libraries).unwrap());
        with.add_cookie(line, |_| {}).unwrap();
        assert_eq!(with.cookie_list().unwrap().len(), 1);
        let mut without = Easy::new();
        without.add_cookie(line, |_| {}).unwrap();
        assert!(without.cookie_list().unwrap().is_empty());
    }

    /// What a failure sink hears.
    #[derive(Clone, Default)]
    struct Heard(Arc<Mutex<Vec<Vec<u8>>>>);

    impl crate::handler::TextSink for Heard {
        fn write(&self, text: &[u8]) {
            self.0.lock().unwrap().push(text.to_vec());
        }
    }

    /// A reason an API call gives is kept and told if it is the first, and
    /// the next is neither (`failf`).
    #[test]
    fn a_call_s_reason_is_told_if_the_first() {
        let heard = Heard::default();
        let mut e = Easy::new();
        e.tell_failure(b"no sink");
        assert_eq!(e.report().failure(), None, "kept nowhere with no sink");
        e.options_mut().callbacks.failure = Some(Handler::text(heard.clone()).unwrap());
        e.tell_failure(b"first");
        e.tell_failure(b"second");
        assert_eq!(*heard.0.lock().unwrap(), [b"first".to_vec()]);
        assert_eq!(e.report().failure(), Some(&b"first"[..]));
    }

    /// A handle holding the connection it took has its share refused,
    /// joined or left, and one it only made does not (`setopt_share`).
    #[test]
    fn a_share_is_refused_while_the_handle_holds_a_connection() {
        let mut e = Easy::new();
        let share = crate::share::Share::new().unwrap();
        let policy = crate::id::ArenaPolicy::new(1, 0).unwrap();
        let mut conns = crate::id::Arena::<u8, crate::conn::ConnSlot>::new(policy).unwrap();
        let id = conns.reserve().unwrap().fill(0);
        e.last_conn = Some(LastConn { id, used: false });
        e.set_share(None).unwrap();
        e.last_conn = Some(LastConn { id, used: true });
        assert_eq!(e.set_share(Some(share.clone())), Err(ShareInUse));
        assert!(e.share().is_none());
        let told = crate::share::Told::new(&share);
        let watched = e.set_share_watched(share.clone(), told.handler());
        assert_eq!(watched, Err(ShareInUse));
    }

    /// Each of the view's methods does on the handle what the handle's own
    /// does, as code holding a handle in a multi reaches it only so.
    #[test]
    fn a_view_changes_the_handle_it_is_of() {
        let dir = Scratch::new("view");
        let session = b"example.com\tFALSE\t/\tFALSE\t0\tsession\t1".to_vec();
        let lasting = b"example.com\tFALSE\t/\tFALSE\t99999999999\tlasting\t2".to_vec();
        let file = dir.0.join("cookies");
        std::fs::write(&file, &lasting).unwrap();
        let file = file.as_os_str().as_encoded_bytes().to_vec();
        let jar = dir.0.join("jar");

        let mut e = Easy::new();
        let mut v = e.view();
        v.options_mut().output.verbose = true;
        assert!(v.options().output.verbose);

        let heard = Heard::default();
        v.options_mut().callbacks.failure = Some(Handler::text(heard.clone()).unwrap());
        v.tell_failure(b"why");
        assert_eq!(*heard.0.lock().unwrap(), [b"why".to_vec()]);

        v.rtsp_mut().unwrap().next_client_cseq = 7;
        assert_eq!(v.rtsp().next_client_cseq, 7);

        let libraries = SharedLibraries::new(crate::libraries::Libraries::NONE).unwrap();
        v.set_libraries(libraries.clone());
        assert!(std::ptr::eq(v.libraries(), &*libraries));

        v.enable_hsts(CacheFile::ReadOnly).unwrap();
        assert!(v.hsts_enabled());
        assert_eq!(v.hsts_mode(), CacheFile::ReadOnly);
        v.disable_hsts();
        assert!(!v.hsts_enabled());
        v.add_hsts_file(Some(b"named")).unwrap();
        assert_eq!(v.hsts_files_named(), 1);

        let versions = crate::altsvc::Versions {
            h1: true,
            h2: false,
            h3: false,
        };
        let ctrl = crate::altsvc::AltSvcCtrl {
            file: CacheFile::ReadOnly,
            versions,
        };
        v.enable_alt_svc(ctrl).unwrap();
        assert!(v.alt_svc_enabled());
        let mut other = Easy::new();
        other.view().add_alt_svc_file(None).unwrap();
        assert!(other.alt_svc_enabled());

        v.enable_cookies().unwrap();
        assert!(v.jar.is_on());
        v.add_cookie(&session, |_| {}).unwrap();
        v.add_cookie(&lasting, |_| {}).unwrap();
        assert_eq!(v.cookie_list().unwrap().len(), 2);
        v.clear_session_cookies().unwrap();
        assert_eq!(v.cookie_list().unwrap(), std::slice::from_ref(&lasting));
        v.clear_cookies().unwrap();
        assert_eq!(v.cookie_list().unwrap(), Vec::<Vec<u8>>::new());

        let cookies = v.options_mut().http.cookies.make_mut().unwrap();
        cookies.files.push(&file).unwrap();
        cookies.set_save_to(Some(jar.as_os_str().as_encoded_bytes().to_vec()));
        v.reload_cookies(|_| {}).unwrap();
        assert_eq!(v.cookie_list().unwrap(), std::slice::from_ref(&lasting));
        v.save_cookies().unwrap();
        assert!(jar.exists(), "written through the view");

        v.forget_cookies();
        assert!(!v.jar.is_on());
        v.reset();
        assert!(!v.options().output.verbose);
    }

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

        /// The URL of `name` in it: on Windows its drive after a slash,
        /// and slashes for its backslashes.
        fn url(&self, name: &str) -> Vec<u8> {
            #[cfg(unix)]
            let dir = self.0.display().to_string();
            #[cfg(windows)]
            let dir = format!("/{}", self.0.display()).replace('\\', "/");
            format!("file://{dir}/{name}").into_bytes()
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

    /// A boxed handle performs in its box, which comes back the same, with
    /// the multi of its own kept for the next transfer and a failure's
    /// detail said, as `perform` does.
    #[test]
    fn performs_a_boxed_handle_in_its_box() {
        let s = Scratch::new("boxed");
        std::fs::write(s.0.join("f"), b"hello").unwrap();
        let (e, body) = easy(&s.url("f"));
        let e = Box::new(e);
        let at: *const Easy = &*e;
        let (mut e, result) = e.perform_boxed();
        assert_eq!(result, Ok(()));
        assert!(std::ptr::eq(at, &*e), "the same box");
        assert_eq!(*body.0.lock().unwrap(), b"hello");
        assert_eq!(e.report().sizes().download(), 5);
        let private: *const Private = &**e.private.as_ref().expect("kept");
        e.options_mut().set_url(Some(&s.url("missing"))).unwrap();
        let (e, result) = e.perform_boxed();
        let err = result.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::FileCouldntReadFile);
        assert!(
            err.detail()
                .is_some_and(|d| d.starts_with(b"Could not open file "))
        );
        assert!(std::ptr::eq(at, &*e), "the same box after a failure");
        let kept: *const Private = &**e.private.as_ref().expect("kept");
        assert!(std::ptr::eq(private, kept), "the same multi");
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
        // The path as the URL has it, on Windows the slash before its
        // drive dropped.
        #[cfg(unix)]
        let path = &missing[b"file://".len()..];
        #[cfg(windows)]
        let path = &missing[b"file:///".len()..];
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
            why(b"LDAP://x/"),
            (
                ErrorKind::UnsupportedProtocol,
                "Protocol \"ldap\" is disabled".into()
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
        // On Windows a drive is no scheme, though a slash follows it
        // (`Curl_is_absolute_url`).
        #[cfg(windows)]
        {
            let slashed = path.display().to_string().replace('\\', "/");
            e.options_mut().set_url(Some(slashed.as_bytes())).unwrap();
            body.0.lock().unwrap().clear();
            assert_eq!(e.perform(), Ok(()));
            assert_eq!(*body.0.lock().unwrap(), b"hello");
        }
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
        e.options_mut().resume = Some(Resume::At(crate::options::ResumeOffset::new(5).unwrap()));
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
        let Some(Private { multi, .. }) = e.private.as_deref() else {
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
        // Boxed, in the same box, its failure still the transfer's.
        let (e, body) = easy(&s.url("f"));
        let e = Box::new(e);
        let at: *const Easy = &*e;
        let (mut e, result) = e.perform_ev_boxed();
        assert_eq!(result, Ok(()));
        assert!(std::ptr::eq(at, &*e), "the same box");
        assert_eq!(*body.0.lock().unwrap(), b"hello");
        e.options_mut().set_url(Some(&s.url("missing"))).unwrap();
        let (e, result) = e.perform_ev_boxed();
        assert_eq!(result.unwrap_err().kind(), ErrorKind::FileCouldntReadFile);
        assert!(std::ptr::eq(at, &*e), "the same box after a failure");
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
        // Port 1, which no unprivileged test can bind: a port picked free
        // and let go can be taken by a test running beside this one.
        let port = 1;
        let (result, text, why) = traced(&format!("tcp://127.0.0.1:{port}/"));
        assert_eq!(result, Err(ErrorKind::CouldntConnect));
        assert_eq!(why, Some(std::io::ErrorKind::ConnectionRefused));
        assert_eq!(text[0], format!("  Trying 127.0.0.1:{port}...\n"));
        // Windows says no local address of a connect refused.
        #[cfg(unix)]
        let refused = format!("connect to 127.0.0.1 port {port} from 127.0.0.1 port ");
        #[cfg(windows)]
        let refused = format!("connect to 127.0.0.1 port {port} from 0.0.0.0 port ");
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
