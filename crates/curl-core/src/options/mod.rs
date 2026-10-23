//! A transfer's options, in typed groups: what `curl_easy_setopt` sets.
//!
//! Only the options the multi reads exist yet; the rest arrive with the
//! code that reads them.

#[cfg(any(test, feature = "test-util"))]
pub mod script;

use curl_alloc::{OutOfMemory, TryArc, TryVec, try_box};

use std::fmt;
use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};
use std::time::Duration;

use crate::handler::{
    DebugHandler, Handler, HeaderHandler, LentBytes, LineSource, ProgressHandler, ReadHandler,
    Rewind, SocketCloser, SocketConfigurer, SocketOpener, TextSink, TrailerHandler, WriteHandler,
};
use crate::mime::MimeSource;
use crate::mime::read::Escape;
use crate::time::TimeLimit;
use crate::url::SharedUrl;

pub use crate::proto::http1::request::{UserHeaders, Version as HttpVersion};

/// Every option of a transfer. The default sets nothing and allocates
/// nothing.
#[derive(Debug, Default)]
pub struct Options {
    url: Option<Vec<u8>>,
    shared_url: Option<SharedUrl>,
    default_protocol: Option<Vec<u8>>,
    /// How the URL is read.
    pub url_rules: UrlRules,
    /// What the request asks for.
    pub method: Method,
    /// Where in the resource the transfer starts.
    pub resume: Option<Resume>,
    /// The part of the resource a download asks for, as given
    /// (`CURLOPT_RANGE`): `X-Y`, `X-` or `-Y`, or for HTTP several of
    /// them. A resume point is asked for in its place.
    pub range: Option<Vec<u8>>,
    /// What a file an upload creates may be opened for.
    pub new_file_mode: FileMode,
    /// The remote file's time is read, where the protocol has to ask for
    /// it (`CURLOPT_FILETIME`): HTTP's `Last-Modified`.
    pub filetime: bool,
    /// The remote file is transferred only if its time meets this.
    pub time_condition: Option<TimeCondition>,
    pub limits: Limits,
    /// The limits on how much a transfer delivers and how fast it goes,
    /// which few transfers set.
    pub flow: Cold<Flow>,
    /// Which of a name's addresses a connection may use
    /// (`CURLOPT_IPRESOLVE`).
    pub ip_version: IpVersion,
    /// The IPv6 scope connections are made in, in place of the URL's
    /// zone (`CURLOPT_ADDRESS_SCOPE`).
    pub address_scope: Option<NonZeroU32>,
    /// What each TCP socket is set to before it connects, and what opens,
    /// sets and closes a transfer's sockets in place of the system; few
    /// transfers change any of it.
    pub sockets: Cold<Sockets>,
    /// The port the first URL is reached on, whatever it says, and any a
    /// relative redirect leads to (`CURLOPT_PORT`).
    pub port: Option<NonZeroU16>,
    /// Addresses given for names ahead of resolving them
    /// (`CURLOPT_RESOLVE`).
    pub resolve: ResolveList,
    /// Peers to connect to in place of the URL's
    /// (`CURLOPT_CONNECT_TO`): `HOST:PORT:CONNECT-TO-HOST:CONNECT-TO-PORT`,
    /// the first that matches the URL's host and port taken, an empty
    /// field matching any and keeping the URL's.
    pub connect_to: Lines,
    pub output: Output,
    pub callbacks: Callbacks,
    pub progress: Progress,
    /// What a transfer sends, if its request has a body.
    pub upload: UploadSource,
    /// How a multipart body is made.
    pub mime: Cold<MimeOptions>,
    /// Who the transfer authenticates as.
    pub login: Cold<Login>,
    pub netrc: Cold<Netrc>,
    pub proxy: Cold<Proxy>,
    pub schemes: Cold<Schemes>,
    pub http: Http,
    pub tls: Tls,
    /// What the test protocol `script:` plays.
    #[cfg(any(test, feature = "test-util"))]
    pub script: Option<script::Script>,
    /// The failures a `file:` transfer meets, for the tests of what it
    /// does then.
    #[cfg(test)]
    pub(crate) file_faults: crate::proto::file::Faults,
    /// A layer each connection the transfer makes puts on its stream once
    /// up, for the tests of what the layers are asked.
    #[cfg(test)]
    pub(crate) layer: Option<fn() -> Box<dyn crate::conn::layer::Layer>>,
}

/// The user, password and token the application gives
/// (`CURLOPT_USERNAME`, `CURLOPT_PASSWORD`, `CURLOPT_USERPWD`,
/// `CURLOPT_XOAUTH2_BEARER`), each as given; none is not the same as
/// empty. They go only to the origin the transfer starts at,
/// unless `Http::unrestricted_auth` says otherwise.
#[derive(Debug)]
pub struct Login {
    pub user: Option<Vec<u8>>,
    pub password: Option<Vec<u8>>,
    /// An OAuth 2.0 token, for Bearer (`CURLOPT_XOAUTH2_BEARER`).
    pub bearer: Option<Vec<u8>>,
}

/// The proxy transfers go through, and which go direct.
#[derive(Debug)]
pub struct Proxy {
    /// The proxy, as a URL whose scheme may name its type
    /// (`CURLOPT_PROXY`): none to look for one in the environment, an
    /// empty one for none at all.
    pub url: Option<Vec<u8>>,
    /// Its type where the URL names none (`CURLOPT_PROXYTYPE`).
    pub kind: ProxyType,
    /// The SOCKS proxy it is reached through, as a URL whose scheme may
    /// name its type, SOCKS4 if none (`CURLOPT_PRE_PROXY`): alone, the
    /// proxy; an empty one for none, which also leaves the environment
    /// unread.
    pub pre_proxy: Option<Vec<u8>>,
    /// Its port where the URL names none (`CURLOPT_PROXYPORT`); none for
    /// its scheme's.
    pub port: Option<NonZeroU16>,
    /// The hosts reached without it, a comma-separated list
    /// (`CURLOPT_NOPROXY`): none to look in the environment.
    pub no_proxy: Option<Vec<u8>>,
    /// Every transfer tunnels through an HTTP proxy, with `CONNECT`
    /// (`CURLOPT_HTTPPROXYTUNNEL`).
    pub tunnel: bool,
    /// The user an HTTP proxy is given where its URL names none
    /// (`CURLOPT_PROXYUSERNAME`).
    pub user: Option<Vec<u8>>,
    /// Its password, likewise (`CURLOPT_PROXYPASSWORD`).
    pub password: Option<Vec<u8>>,
    /// The methods it may be authenticated with (`CURLOPT_PROXYAUTH`).
    pub auth: HttpAuth,
    /// The answer to `CONNECT` is not delivered, though its headers are
    /// kept (`CURLOPT_SUPPRESS_CONNECT_HEADERS`).
    pub suppress_connect_headers: bool,
    /// How a SOCKS5 proxy may authenticate the user
    /// (`CURLOPT_SOCKS5_AUTH`).
    pub socks5_auth: Socks5Auth,
    /// The header lines an HTTP proxy is sent of its own
    /// (`CURLOPT_PROXYHEADER`).
    pub headers: UserHeaders,
    /// The proxy is sent the application's headers for the origin in
    /// their place (`CURLHEADER_UNIFIED` in `CURLOPT_HEADEROPT`).
    pub unified_headers: bool,
    /// A new connection says first where it comes from, in the PROXY
    /// protocol's line (`CURLOPT_HAPROXYPROTOCOL`).
    pub haproxy: bool,
    /// The address it says, as source and destination both, in place of
    /// the connection's (`CURLOPT_HAPROXY_CLIENT_IP`).
    pub haproxy_client_ip: Option<Vec<u8>>,
}

/// The methods a SOCKS5 proxy may authenticate with
/// (`CURLOPT_SOCKS5_AUTH`): a user and password, GSS-API, and whether
/// one of them must be, never none. Both, and none allowed, unless set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Socks5Auth {
    pub basic: bool,
    pub gssapi: bool,
    /// The proxy must authenticate the user (`CURLAUTH_ONLY`).
    pub only: bool,
}

impl Socks5Auth {
    pub const DEFAULT: Socks5Auth = Socks5Auth {
        basic: true,
        gssapi: true,
        only: false,
    };
}

impl Default for Socks5Auth {
    fn default() -> Self {
        Socks5Auth::DEFAULT
    }
}

/// Why `user:password` for a proxy is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyUserError {
    OutOfMemory,
    /// A part decodes to a zero byte.
    Malformed,
}

impl Proxy {
    fn try_clone(&self) -> Result<Proxy, OutOfMemory> {
        Ok(Proxy {
            url: self.url.as_deref().map(copy).transpose()?,
            kind: self.kind,
            pre_proxy: self.pre_proxy.as_deref().map(copy).transpose()?,
            port: self.port,
            no_proxy: self.no_proxy.as_deref().map(copy).transpose()?,
            tunnel: self.tunnel,
            user: self.user.as_deref().map(copy).transpose()?,
            password: self.password.as_deref().map(copy).transpose()?,
            auth: self.auth,
            suppress_connect_headers: self.suppress_connect_headers,
            socks5_auth: self.socks5_auth,
            headers: self.headers.try_clone()?,
            unified_headers: self.unified_headers,
            haproxy: self.haproxy,
            haproxy_client_ip: self.haproxy_client_ip.as_deref().map(copy).transpose()?,
        })
    }

    /// The header lines an HTTP proxy is sent of its own, which replace
    /// the library's to it (`Curl_checkProxyheaders`): the origin's where
    /// the two are unified.
    pub(crate) fn own_headers<'a>(&'a self, http: &'a Http) -> &'a UserHeaders {
        if self.unified_headers {
            &http.headers
        } else {
            &self.headers
        }
    }

    /// The user and password from `user:password`, split at the first
    /// colon and each URL-decoded (`CURLOPT_PROXYUSERPWD`); none clears
    /// both.
    pub fn set_user_password(&mut self, pair: Option<&[u8]>) -> Result<(), ProxyUserError> {
        let decoded = |part: &[u8]| match crate::url::decode_but_zero(part) {
            Ok(Some(decoded)) => Ok(decoded),
            Ok(None) => Err(ProxyUserError::Malformed),
            Err(_) => Err(ProxyUserError::OutOfMemory),
        };
        let (user, password) = match pair {
            None => (None, None),
            Some(pair) => {
                let login =
                    Login::from_pair(pair).map_err(|OutOfMemory| ProxyUserError::OutOfMemory)?;
                (
                    login.user.as_deref().map(decoded).transpose()?,
                    login.password.as_deref().map(decoded).transpose()?,
                )
            }
        };
        self.user = user;
        self.password = password;
        Ok(())
    }
}

/// What a proxy speaks (`curl_proxytype`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ProxyType {
    #[default]
    Http,
    /// HTTP/1.0 for `CONNECT`.
    Http10,
    /// HTTP over TLS.
    Https,
    /// HTTP/2 over TLS.
    Https2,
    /// HTTP/3.
    Https3,
    Socks4,
    /// SOCKS4 with the name resolved by the proxy.
    Socks4a,
    Socks5,
    /// SOCKS5 with the name resolved by the proxy.
    Socks5Hostname,
}

/// Whether a `.netrc` file gives credentials, and which
/// (`CURLOPT_NETRC`, `CURLOPT_NETRC_FILE`).
#[derive(Debug)]
pub struct Netrc {
    pub mode: NetrcMode,
    /// The file; none for `$NETRC`, or `.netrc` in the home directory.
    pub file: Option<Vec<u8>>,
}

/// How a `.netrc` file is used (`CURL_NETRC_*`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum NetrcMode {
    /// Not read.
    #[default]
    Ignored,
    /// Read where the options and the URL leave a user or password out;
    /// a file missing or malformed is passed over.
    Optional,
    /// Read even where the URL has both, its user kept; a file missing
    /// or malformed fails the transfer.
    Required,
}

impl Login {
    /// `user:password`, split at the first colon; with none, a user alone
    /// (`Curl_parse_login_details`).
    pub fn from_pair(pair: &[u8]) -> Result<Login, OutOfMemory> {
        let (user, password) = match pair.iter().position(|&b| b == b':') {
            Some(at) => (&pair[..at], Some(&pair[at + 1..])),
            None => (pair, None),
        };
        Ok(Login {
            user: Some(copy(user)?),
            password: password.map(copy).transpose()?,
            bearer: None,
        })
    }

    fn try_clone(&self) -> Result<Login, OutOfMemory> {
        Ok(Login {
            user: self.user.as_deref().map(copy).transpose()?,
            password: self.password.as_deref().map(copy).transpose()?,
            bearer: self.bearer.as_deref().map(copy).transpose()?,
        })
    }
}

impl Options {
    /// The application's header lists read again from their sources, as
    /// C walks them each time it builds a request or a `CONNECT`.
    pub(crate) fn reread_headers(&mut self) -> Result<(), OutOfMemory> {
        self.http.headers.refill()?;
        match self.proxy.made_mut() {
            Some(proxy) => proxy.headers.refill(),
            None => Ok(()),
        }
    }

    /// How a multipart body's names are quoted.
    pub(crate) fn mime_escape(&self) -> Escape {
        if self.mime.form_escape {
            Escape::Backslash
        } else {
            Escape::Form
        }
    }

    /// The URL to transfer (`CURLOPT_URL`), as given: it is parsed when
    /// the transfer starts.
    pub fn url(&self) -> Option<&[u8]> {
        self.url.as_deref()
    }

    pub fn set_url(&mut self, url: Option<&[u8]>) -> Result<(), OutOfMemory> {
        self.url = url.map(copy).transpose()?;
        Ok(())
    }

    /// The URL to transfer as the application keeps it, read as each
    /// transfer starts (`CURLOPT_CURLU`): it goes before `url`, which
    /// setting it, even to none, clears.
    pub fn shared_url(&self) -> Option<&SharedUrl> {
        self.shared_url.as_ref()
    }

    pub fn set_shared_url(&mut self, url: Option<SharedUrl>) {
        self.url = None;
        self.shared_url = url;
    }

    /// The scheme a URL without one is given (`CURLOPT_DEFAULT_PROTOCOL`),
    /// as given: an unknown one fails the transfer when it starts.
    pub fn default_protocol(&self) -> Option<&[u8]> {
        self.default_protocol.as_deref()
    }

    pub fn set_default_protocol(&mut self, scheme: Option<&[u8]>) -> Result<(), OutOfMemory> {
        self.default_protocol = scheme.map(copy).transpose()?;
        Ok(())
    }

    /// The range the transfer asks for, if any (`setup_range`): the
    /// resume point's, else the application's.
    pub(crate) fn ranged(&self) -> Option<Ranged<'_>> {
        match (self.resume, &self.range) {
            (Some(resume), _) => Some(Ranged::Resume(resume)),
            (None, Some(given)) => Some(Ranged::Given(given)),
            (None, None) => None,
        }
    }

    /// A copy (`curl_easy_duphandle`).
    pub fn try_clone(&self) -> Result<Options, OutOfMemory> {
        Ok(Options {
            url: self.url.as_deref().map(copy).transpose()?,
            shared_url: self.shared_url.clone(),
            default_protocol: self.default_protocol.as_deref().map(copy).transpose()?,
            url_rules: self.url_rules,
            method: self.method,
            resume: self.resume,
            range: self.range.as_deref().map(copy).transpose()?,
            new_file_mode: self.new_file_mode,
            filetime: self.filetime,
            time_condition: self.time_condition,
            limits: self.limits,
            flow: self.flow.try_clone(|f| Ok(*f))?,
            ip_version: self.ip_version,
            address_scope: self.address_scope,
            port: self.port,
            resolve: self.resolve.try_clone()?,
            connect_to: self.connect_to.try_clone()?,
            output: self.output,
            callbacks: self.callbacks.clone(),
            progress: self.progress.clone(),
            upload: self.upload.clone(),
            mime: self.mime.try_clone(|m| Ok(*m))?,
            login: self.login.try_clone(Login::try_clone)?,
            netrc: self.netrc.try_clone(|netrc| {
                Ok(Netrc {
                    mode: netrc.mode,
                    file: netrc.file.as_deref().map(copy).transpose()?,
                })
            })?,
            proxy: self.proxy.try_clone(Proxy::try_clone)?,
            schemes: self.schemes.try_clone(|s| Ok(*s))?,
            sockets: self.sockets.try_clone(|h| Ok(h.clone()))?,
            http: self.http.try_clone()?,
            tls: self.tls.try_clone()?,
            #[cfg(any(test, feature = "test-util"))]
            script: self.script.clone(),
            #[cfg(test)]
            file_faults: self.file_faults,
            #[cfg(test)]
            layer: self.layer,
        })
    }
}

/// A group of options few transfers set, in memory of its own made the
/// first time one of them is set, as C allocates such options only when
/// they are set: a handle that sets none carries a pointer for the
/// group, not the group, and reads its defaults. A new option of such a
/// kind goes in its group, so the memory every handle pays does not grow
/// with it.
pub struct Cold<T: ColdGroup>(Option<Box<T>>);

/// A group `Cold` holds, with the defaults read while none is set.
pub trait ColdGroup: Sized + 'static {
    /// Nothing set, as the group starts out.
    const NONE: Self;
    /// The same, for reading where the group was never made.
    const UNSET: &'static Self;
}

impl<T: ColdGroup> Cold<T> {
    pub const fn new() -> Self {
        Cold(None)
    }

    /// The group, to change: made with nothing set the first time, which
    /// is what can run out of memory.
    pub fn make_mut(&mut self) -> Result<&mut T, OutOfMemory> {
        if self.0.is_none() {
            self.0 = Some(try_box(T::NONE)?);
        }
        Ok(self.0.as_deref_mut().expect("made above"))
    }

    /// The group, to change, if it was made: one never made holds only
    /// defaults, which need no change to clear.
    pub fn made_mut(&mut self) -> Option<&mut T> {
        self.0.as_deref_mut()
    }

    /// Set the option `field` names to `value`. Clearing one, to `None`,
    /// in a group never made changes nothing and makes nothing, as C
    /// allocates nothing to clear an option: the group's defaults hold
    /// none there already. Setting one makes the group.
    pub fn set<V>(
        &mut self,
        field: impl Fn(&mut T) -> &mut Option<V>,
        value: Option<V>,
    ) -> Result<(), OutOfMemory> {
        if value.is_none() && self.0.is_none() {
            let mut defaults = T::NONE;
            assert!(
                field(&mut defaults).is_none(),
                "a group's defaults clear it"
            );
            return Ok(());
        }
        *field(self.make_mut()?) = value;
        Ok(())
    }

    /// A copy, made only if this one was, copied by `copy`.
    fn try_clone(
        &self,
        copy: impl FnOnce(&T) -> Result<T, OutOfMemory>,
    ) -> Result<Cold<T>, OutOfMemory> {
        Ok(Cold(match self.0.as_deref() {
            Some(group) => Some(try_box(copy(group)?)?),
            None => None,
        }))
    }
}

impl<T: ColdGroup> Default for Cold<T> {
    fn default() -> Self {
        Cold::new()
    }
}

impl<T: ColdGroup> std::ops::Deref for Cold<T> {
    type Target = T;

    fn deref(&self) -> &T {
        self.0.as_deref().unwrap_or(T::UNSET)
    }
}

impl<T: ColdGroup + fmt::Debug> fmt::Debug for Cold<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}

impl ColdGroup for Login {
    const UNSET: &'static Login = &Login::NONE;
    const NONE: Login = Login {
        user: None,
        password: None,
        bearer: None,
    };
}

impl Default for Login {
    fn default() -> Self {
        Login::NONE
    }
}

impl ColdGroup for Proxy {
    const UNSET: &'static Proxy = &Proxy::NONE;
    const NONE: Proxy = Proxy {
        url: None,
        kind: ProxyType::Http,
        pre_proxy: None,
        port: None,
        no_proxy: None,
        tunnel: false,
        user: None,
        password: None,
        auth: HttpAuth::DEFAULT,
        suppress_connect_headers: false,
        socks5_auth: Socks5Auth::DEFAULT,
        headers: UserHeaders::NONE,
        unified_headers: false,
        haproxy: false,
        haproxy_client_ip: None,
    };
}

impl Default for Proxy {
    fn default() -> Self {
        Proxy::NONE
    }
}

/// How a multipart body is made (`CURLOPT_MIME_OPTIONS`).
#[derive(Clone, Copy, Debug, Default)]
pub struct MimeOptions {
    /// Form field names and file names are quoted with backslashes, as
    /// curl before 7.81 did, not percent-encoded
    /// (`CURLMIMEOPT_FORMESCAPE`).
    pub form_escape: bool,
}

impl ColdGroup for MimeOptions {
    const UNSET: &'static MimeOptions = &MimeOptions::NONE;
    const NONE: MimeOptions = MimeOptions { form_escape: false };
}

/// What each TCP socket a transfer opens is set to before it connects
/// (`tcpnodelay`, `tcpkeepalive`, `do_connect`), and the application's
/// own handling of its sockets, each in place of the system's
/// (`CURLOPT_OPENSOCKETFUNCTION`, `CURLOPT_SOCKOPTFUNCTION`,
/// `CURLOPT_CLOSESOCKETFUNCTION`). The closer is kept by each connection
/// the transfer makes, and closes its sockets whoever closes them.
#[derive(Clone, Debug)]
pub struct Sockets {
    /// Small sends go out at once, Nagle's algorithm off
    /// (`CURLOPT_TCP_NODELAY`): on by default, as in C.
    pub nodelay: bool,
    pub keepalive: KeepAlive,
    /// The connect is made with TCP Fast Open (`CURLOPT_TCP_FASTOPEN`).
    pub fastopen: bool,
    pub open: Option<Handler<dyn SocketOpener>>,
    pub configure: Option<Handler<dyn SocketConfigurer>>,
    pub close: Option<Handler<dyn SocketCloser>>,
}

/// The kernel's probes of an idle connection (`CURLOPT_TCP_KEEPALIVE`,
/// `CURLOPT_TCP_KEEPIDLE`, `CURLOPT_TCP_KEEPINTVL`, `CURLOPT_TCP_KEEPCNT`):
/// the times and count are kept while it is off, for when it is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeepAlive {
    pub on: bool,
    /// Idle before the first probe, in whole seconds.
    pub idle: Duration,
    /// Between probes, in whole seconds.
    pub interval: Duration,
    /// Probes unanswered before the connection is dropped.
    pub count: u32,
}

impl KeepAlive {
    /// C's: off, a minute idle and between probes, nine probes.
    pub const DEFAULT: KeepAlive = KeepAlive {
        on: false,
        idle: Duration::from_secs(60),
        interval: Duration::from_secs(60),
        count: 9,
    };
}

impl ColdGroup for Sockets {
    const UNSET: &'static Sockets = &Sockets::NONE;
    const NONE: Sockets = Sockets {
        nodelay: true,
        keepalive: KeepAlive::DEFAULT,
        fastopen: false,
        open: None,
        configure: None,
        close: None,
    };
}

impl ColdGroup for Netrc {
    const UNSET: &'static Netrc = &Netrc::NONE;
    const NONE: Netrc = Netrc {
        mode: NetrcMode::Ignored,
        file: None,
    };
}

impl Default for Netrc {
    fn default() -> Self {
        Netrc::NONE
    }
}

impl ColdGroup for Cookies {
    const UNSET: &'static Cookies = &Cookies::NONE;
    const NONE: Cookies = Cookies {
        send: None,
        files: Lines::NONE,
        save_to: None,
        new_session: false,
    };
}

impl Default for Cookies {
    fn default() -> Self {
        Cookies::NONE
    }
}

fn copy(s: &[u8]) -> Result<Vec<u8>, OutOfMemory> {
    let mut v = Vec::new();
    v.try_extend_from_slice(s)?;
    Ok(v)
}

/// What a URL may hold, beyond what parsing it always allows.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UrlRules {
    /// A user name or password in it is an error
    /// (`CURLOPT_DISALLOW_USERNAME_IN_URL`).
    pub disallow_user: bool,
    /// `.` and `..` in its path are kept, not resolved
    /// (`CURLOPT_PATH_AS_IS`).
    pub path_as_is: bool,
}

/// What a request asks for.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Method {
    /// The resource.
    #[default]
    Get,
    /// What is known of the resource, without its body
    /// (`CURLOPT_NOBODY`).
    Head,
    /// To store the body the transfer sends, from `Options::upload`
    /// (`CURLOPT_UPLOAD`).
    Upload,
    /// To send the body from `Options::upload` for the resource to take
    /// (`CURLOPT_POST`, `CURLOPT_POSTFIELDS`); `file:` reads the file.
    Post,
}

impl Method {
    /// The method as a request line names it.
    pub fn name(self) -> &'static [u8] {
        match self {
            Method::Get => b"GET",
            Method::Head => b"HEAD",
            Method::Post => b"POST",
            Method::Upload => b"PUT",
        }
    }
}

/// A condition on the remote file's time (`CURLOPT_TIMECONDITION`,
/// `CURLOPT_TIMEVALUE_LARGE`). A range asked for sets it aside, as does a
/// file whose time is not known.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimeCondition {
    pub when: Condition,
    /// Seconds since 1970-01-01 00:00:00 UTC; at 0, any file meets it.
    pub time: i64,
}

/// What a time condition asks of the file, and the HTTP header it sends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Condition {
    /// Modified after the time (`If-Modified-Since`).
    ModifiedSince,
    /// Not modified after it (`If-Unmodified-Since`).
    UnmodifiedSince,
    /// Sent as `Last-Modified`; checked as `ModifiedSince`, as C does.
    LastModified,
}

impl Condition {
    /// The header a request sends it as.
    pub(crate) fn header(self) -> &'static [u8] {
        match self {
            Condition::ModifiedSince => b"If-Modified-Since",
            Condition::UnmodifiedSince => b"If-Unmodified-Since",
            Condition::LastModified => b"Last-Modified",
        }
    }
}

/// Why a file fails a time condition, as C says it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Unmet {
    NotNewEnough,
    NotOldEnough,
}

impl fmt::Display for Unmet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Unmet::NotNewEnough => "The requested document is not new enough",
            Unmet::NotOldEnough => "The requested document is not old enough",
        })
    }
}

impl TimeCondition {
    /// Whether a file modified at `doc`, 0 for not known, meets it
    /// (`Curl_meets_timecondition`).
    pub(crate) fn met_by(self, doc: i64) -> Result<(), Unmet> {
        if doc == 0 || self.time == 0 {
            return Ok(());
        }
        match self.when {
            Condition::ModifiedSince | Condition::LastModified if doc <= self.time => {
                Err(Unmet::NotNewEnough)
            }
            Condition::UnmodifiedSince if doc >= self.time => Err(Unmet::NotOldEnough),
            _ => Ok(()),
        }
    }
}

/// Where in the resource a transfer starts (`CURLOPT_RESUME_FROM_LARGE`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resume {
    /// This many bytes in: a download skips them; an upload skips them of
    /// its body and appends the rest to what is stored.
    At(NonZeroU64),
    /// At the end (C's -1): a download gets the last byte; an upload skips
    /// as much of its body as is stored already and appends the rest.
    AtEnd,
}

/// The range a transfer asks for, as C's `state.range` holds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Ranged<'o> {
    /// From the resume point on: C's `N-`, and for its -1, `-1-`.
    Resume(Resume),
    /// The application's (`CURLOPT_RANGE`).
    Given(&'o [u8]),
}

/// The permission bits of a file a transfer creates, before the umask
/// (`CURLOPT_NEW_FILE_PERMS`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileMode(u16);

impl FileMode {
    /// `bits`, if they are permission bits alone.
    pub fn new(bits: u16) -> Option<FileMode> {
        (bits <= 0o777).then_some(FileMode(bits))
    }

    pub fn bits(self) -> u16 {
        self.0
    }
}

impl Default for FileMode {
    /// Read and write for the owner, read for the rest.
    fn default() -> FileMode {
        FileMode(0o644)
    }
}

/// Entries giving names their addresses (`CURLOPT_RESOLVE`), each as the
/// application gave it, read into the multi's cache when the next
/// transfer starts: `HOST:PORT:ADDRESS[,ADDRESS]...`, kept for good, or
/// for the cache's timeout with a `+` before; `-HOST:PORT` to forget.
#[derive(Debug, Default)]
pub struct ResolveList {
    entries: Lines,
    /// Which setting of the list this is: a transfer reads each once.
    stamp: u64,
}

impl ResolveList {
    pub fn entries(&self) -> impl Iterator<Item = &[u8]> {
        self.entries.iter()
    }

    /// The list as the application sets it again, replacing what it was:
    /// read again by the next transfer, even if it is the same.
    pub fn set<'a>(
        &mut self,
        entries: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<(), OutOfMemory> {
        self.entries.set(entries)?;
        self.stamp += 1;
        Ok(())
    }

    /// The list `source` gives, as `set` sets one: what it gives when the
    /// next transfer starts is read, and only then (`Curl_loadhostpairs`).
    pub fn set_source(&mut self, source: Handler<dyn LineSource>) -> Result<(), OutOfMemory> {
        self.entries.set_source(source)?;
        self.stamp += 1;
        Ok(())
    }

    /// The source's entries read again, as they are to be read into the
    /// cache: the same setting of the list still.
    pub(crate) fn refill(&mut self) -> Result<(), OutOfMemory> {
        self.entries.refill()
    }

    pub(crate) fn stamp(&self) -> u64 {
        self.stamp
    }

    pub(crate) fn try_clone(&self) -> Result<ResolveList, OutOfMemory> {
        Ok(ResolveList {
            entries: self.entries.try_clone()?,
            stamp: self.stamp,
        })
    }
}

/// The items of a list the application gives: kept as given, or as last
/// read from its source. As large as the `Vec` alone, so a handle pays
/// for a source only when it has one.
#[derive(Debug)]
pub(crate) enum Listed<T> {
    Given(Vec<T>),
    Read(Box<FromSource<T>>),
}

#[derive(Debug)]
pub(crate) struct FromSource<T> {
    source: Handler<dyn LineSource>,
    items: Vec<T>,
}

impl<T> Default for Listed<T> {
    fn default() -> Self {
        Listed::NONE
    }
}

impl<T> Listed<T> {
    pub(crate) const NONE: Listed<T> = Listed::Given(Vec::new());

    pub(crate) fn items(&self) -> &[T] {
        match self {
            Listed::Given(items) => items,
            Listed::Read(read) => &read.items,
        }
    }

    pub(crate) fn items_mut(&mut self) -> &mut Vec<T> {
        match self {
            Listed::Given(items) => items,
            Listed::Read(read) => &mut read.items,
        }
    }

    pub(crate) fn source(&self) -> Option<&Handler<dyn LineSource>> {
        match self {
            Listed::Given(_) => None,
            Listed::Read(read) => Some(&read.source),
        }
    }

    /// What `source` gives, each line made an item by `item`.
    pub(crate) fn from_source(
        source: Handler<dyn LineSource>,
        item: impl Fn(&[u8]) -> Result<T, OutOfMemory>,
    ) -> Result<Listed<T>, OutOfMemory> {
        let mut listed = Listed::Read(try_box(FromSource {
            source,
            items: Vec::new(),
        })?);
        listed.refill(item)?;
        Ok(listed)
    }

    /// The source's lines read again, in place of those read before; a
    /// list kept as given stays as it is.
    pub(crate) fn refill(
        &mut self,
        item: impl Fn(&[u8]) -> Result<T, OutOfMemory>,
    ) -> Result<(), OutOfMemory> {
        let Listed::Read(read) = self else {
            return Ok(());
        };
        let mut items = Vec::new();
        read.source.lines(&mut |line| items.try_push(item(line)?))?;
        read.items = items;
        Ok(())
    }

    /// A copy whose items `item` copies, reading the same source.
    pub(crate) fn try_clone(
        &self,
        item: impl Fn(&T) -> Result<T, OutOfMemory>,
    ) -> Result<Listed<T>, OutOfMemory> {
        let mut items = Vec::new();
        for i in self.items() {
            items.try_push(item(i)?)?;
        }
        Ok(match self.source() {
            None => Listed::Given(items),
            Some(source) => Listed::Read(try_box(FromSource {
                source: source.clone(),
                items,
            })?),
        })
    }
}

/// A list of lines, each as the application gave it: fixed, or read
/// from a source again each time it is used.
#[derive(Debug, Default)]
pub struct Lines(Listed<Vec<u8>>);

impl Lines {
    pub const NONE: Lines = Lines(Listed::NONE);

    pub fn iter(&self) -> impl Iterator<Item = &[u8]> {
        self.0.items().iter().map(|e| &e[..])
    }

    /// The lines given, in place of those before.
    pub fn set<'a>(
        &mut self,
        lines: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<(), OutOfMemory> {
        let mut owned = Vec::new();
        for line in lines {
            owned.try_push(copy(line)?)?;
        }
        self.0 = Listed::Given(owned);
        Ok(())
    }

    /// The lines `source` gives, in place of those before: read now, and
    /// again each time they are used.
    pub fn set_source(&mut self, source: Handler<dyn LineSource>) -> Result<(), OutOfMemory> {
        self.0 = Listed::from_source(source, copy)?;
        Ok(())
    }

    /// The source's lines read again, in place of those read before.
    pub(crate) fn refill(&mut self) -> Result<(), OutOfMemory> {
        self.0.refill(copy)
    }

    /// `line` after those given before.
    pub fn push(&mut self, line: &[u8]) -> Result<(), OutOfMemory> {
        self.0.items_mut().try_push(copy(line)?)
    }

    pub(crate) fn try_clone(&self) -> Result<Lines, OutOfMemory> {
        Ok(Lines(self.0.try_clone(|line| copy(line))?))
    }
}

/// Which addresses of a name a connection may use; an address the URL
/// names is used whatever this says.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum IpVersion {
    #[default]
    Any,
    V4,
    V6,
}

/// How long a transfer may take.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Limits {
    /// The whole transfer (`CURLOPT_TIMEOUT_MS`).
    pub total: Option<TimeLimit>,
    /// Each connection (`CURLOPT_CONNECTTIMEOUT_MS`); five minutes if none.
    pub connect: Option<TimeLimit>,
    /// The most one read from the connection takes.
    pub buffer_size: BufferSize,
    /// The most of a body read at once, and the room a request's head
    /// and body share.
    pub upload_buffer: UploadBufferSize,
    /// Which idle connections the transfer may reuse.
    pub reuse: ReuseLimits,
    pub eyeballs: EyeballsDelay,
}

/// How much a transfer may deliver, and how fast it must and may go;
/// none set unless the application sets them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Flow {
    /// The most body bytes a transfer may deliver
    /// (`CURLOPT_MAXFILESIZE_LARGE`).
    pub max_filesize: Option<NonZeroU64>,
    /// Fail a transfer slower than this for this long
    /// (`CURLOPT_LOW_SPEED_LIMIT`, `CURLOPT_LOW_SPEED_TIME`).
    pub low_speed: Option<LowSpeed>,
    /// The most bytes a second a transfer receives, counting its body
    /// as it comes, before any content coding is undone
    /// (`CURLOPT_MAX_RECV_SPEED_LARGE`).
    pub max_recv_speed: Option<NonZeroU64>,
    /// The most bytes a second a transfer sends of its body, with any
    /// framing (`CURLOPT_MAX_SEND_SPEED_LARGE`).
    pub max_send_speed: Option<NonZeroU64>,
}

impl ColdGroup for Flow {
    const UNSET: &'static Flow = &Flow::NONE;
    const NONE: Flow = Flow {
        max_filesize: None,
        low_speed: None,
        max_recv_speed: None,
        max_send_speed: None,
    };
}

/// The most bytes one read from the connection takes, and one read of a
/// file (`CURLOPT_BUFFERSIZE`): 16 KiB unless set, never under 1 KiB nor
/// over 10 MiB.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BufferSize(u32);

impl BufferSize {
    const MIN: u32 = 1024;
    const MAX: u32 = 10 * 1024 * 1024;

    /// `n` bytes, held between the least and the most, as C's setopt
    /// holds it.
    pub fn clamped(n: u64) -> BufferSize {
        let n = u32::try_from(n).unwrap_or(u32::MAX);
        BufferSize(n.clamp(Self::MIN, Self::MAX))
    }

    pub fn get(self) -> usize {
        self.0 as usize
    }
}

/// The most of an upload's body read at once, which an HTTP request's
/// head shares (`CURLOPT_UPLOAD_BUFFERSIZE`): 64 KiB unless set, never
/// under 16 KiB nor over 2 MiB.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UploadBufferSize(u32);

impl UploadBufferSize {
    const MIN: u32 = 16384;
    const MAX: u32 = 2 * 1024 * 1024;

    /// `n` bytes, held between the least and the most, as C's setopt
    /// holds it.
    pub fn clamped(n: u64) -> UploadBufferSize {
        let n = u32::try_from(n).unwrap_or(u32::MAX);
        UploadBufferSize(n.clamp(Self::MIN, Self::MAX))
    }

    pub fn get(self) -> usize {
        self.0 as usize
    }
}

impl Default for UploadBufferSize {
    /// `UPLOADBUFFER_DEFAULT`.
    fn default() -> Self {
        UploadBufferSize(65536)
    }
}

impl Default for BufferSize {
    /// `CURL_MAX_WRITE_SIZE`.
    fn default() -> Self {
        BufferSize(16384)
    }
}

/// How long a body announced with `Expect: 100-continue` waits for the
/// 100 before it is sent anyway (`CURLOPT_EXPECT_100_TIMEOUT_MS`): a
/// second unless set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContinueWait(pub Duration);

impl Default for ContinueWait {
    fn default() -> Self {
        ContinueWait(Duration::from_secs(1))
    }
}

/// How long a connect attempt runs before the next starts beside it
/// (`CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS`): 200 milliseconds unless set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EyeballsDelay(pub Duration);

impl Default for EyeballsDelay {
    fn default() -> Self {
        EyeballsDelay(Duration::from_millis(200))
    }
}

/// How long a connection may have been idle, and have lived, for a
/// transfer to reuse it, none for no limit as C's 0; and how many an
/// easy handle's own pool keeps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReuseLimits {
    /// `CURLOPT_MAXAGE_CONN`: 118 seconds unless set.
    pub max_idle: Option<TimeLimit>,
    /// `CURLOPT_MAXLIFETIME_CONN`: a day unless set.
    pub max_age: Option<TimeLimit>,
    /// `CURLOPT_MAXCONNECTS`: 5 unless set. A multi's own limit is the
    /// multi's.
    pub max_connects: NonZeroU32,
    /// `CURLOPT_FORBID_REUSE`: the connection is closed once the
    /// transfer is done with it.
    pub forbid: bool,
    /// `CURLOPT_FRESH_CONNECT`: a new connection, not an idle one.
    pub fresh: bool,
    /// `CURLOPT_DNS_CACHE_TIMEOUT`: how long a name's answer is kept, 60
    /// seconds unless set; none for ever.
    pub dns_max_age: Option<Duration>,
}

impl Default for ReuseLimits {
    fn default() -> Self {
        ReuseLimits {
            max_idle: TimeLimit::from_millis(118 * 1000),
            max_age: TimeLimit::from_millis(24 * 3600 * 1000),
            max_connects: NonZeroU32::new(5).expect("not zero"),
            forbid: false,
            fresh: false,
            dns_max_age: Some(Duration::from_secs(60)),
        }
    }
}

/// A speed a transfer must keep up, at least once in every `time`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LowSpeed {
    /// Bytes a second, up and down together.
    pub limit: NonZeroU64,
    /// Seconds.
    pub time: NonZeroU16,
}

/// What an HTTP request says, and how its response is read.
#[derive(Debug, Default)]
pub struct Http {
    /// `CURLOPT_USERAGENT`.
    pub user_agent: Option<Vec<u8>>,
    /// The application's header lines (`CURLOPT_HTTPHEADER`).
    pub headers: UserHeaders,
    pub version: HttpVersion,
    /// A response that is no HTTP is read as HTTP/0.9
    /// (`CURLOPT_HTTP09_ALLOWED`).
    pub allow_09: bool,
    /// `Content-Length` is not read (`CURLOPT_IGNORE_CONTENT_LENGTH`).
    pub ignore_content_length: bool,
    /// Transfer codings are passed on as they came, not decoded
    /// (`CURLOPT_HTTP_TRANSFER_DECODING` off).
    pub raw: bool,
    /// Codings other than chunked are asked for and decoded
    /// (`CURLOPT_TRANSFER_ENCODING`).
    pub transfer_encoding: bool,
    /// The content codings asked for, and a response's undone; without,
    /// a coded body is delivered as it came (`CURLOPT_ACCEPT_ENCODING`).
    pub accept_encoding: Option<crate::coding::AcceptEncoding>,
    /// Content codings are passed on as they came, not decoded
    /// (`CURLOPT_HTTP_CONTENT_DECODING` off).
    pub raw_content: bool,
    /// The parts of a request the application writes itself.
    pub custom: Cold<Custom>,
    /// A response code of 400 or more fails the transfer at the end of
    /// its head (`CURLOPT_FAILONERROR`).
    pub fail_on_error: bool,
    /// How long a body announced with `Expect: 100-continue` waits for
    /// the 100.
    pub continue_wait: ContinueWait,
    /// An error response before the body is all sent lets it go on
    /// rather than stop (`CURLOPT_KEEP_SENDING_ON_ERROR`).
    pub keep_sending_on_error: bool,
    /// Which redirects are followed (`CURLOPT_FOLLOWLOCATION`).
    pub follow: Follow,
    pub max_redirects: MaxRedirects,
    /// Which redirects keep a POST a POST (`CURLOPT_POSTREDIR`).
    pub post_redirect: PostRedir,
    /// A followed redirect sends the URL it came from as its referer
    /// (`CURLOPT_AUTOREFERER`).
    pub auto_referer: bool,
    /// What the application said for the first origin goes to any a
    /// redirect leads to (`CURLOPT_UNRESTRICTED_AUTH`).
    pub unrestricted_auth: bool,
    pub auth: HttpAuth,
    pub cookies: Cold<Cookies>,
    /// What a request is signed with.
    pub signing: Cold<Signing>,
}

/// The parts of a request the application writes itself, which few do.
#[derive(Debug)]
pub struct Custom {
    /// `CURLOPT_REFERER`.
    pub referer: Option<Vec<u8>>,
    /// The request's method as sent, in place of the one `method` implies,
    /// which still decides the body (`CURLOPT_CUSTOMREQUEST`).
    pub method: Option<Vec<u8>>,
    /// The request line's target, in place of the URL's path and query,
    /// or of the whole URL to a proxy; nothing else reads it
    /// (`CURLOPT_REQUEST_TARGET`).
    pub target: Option<Vec<u8>>,
}

impl ColdGroup for Custom {
    const UNSET: &'static Custom = &Custom::NONE;
    const NONE: Custom = Custom {
        referer: None,
        method: None,
        target: None,
    };
}

impl Custom {
    fn try_clone(&self) -> Result<Custom, OutOfMemory> {
        Ok(Custom {
            referer: self.referer.as_deref().map(copy).transpose()?,
            method: self.method.as_deref().map(copy).transpose()?,
            target: self.target.as_deref().map(copy).transpose()?,
        })
    }
}

/// What a request is signed with, by the methods that sign it in place
/// of credentials.
#[derive(Debug)]
pub struct Signing {
    /// What AWS Signature Version 4 signs with,
    /// `provider0[:provider1[:region[:service]]]`, if set
    /// (`CURLOPT_AWS_SIGV4`).
    pub aws_sigv4: Option<Vec<u8>>,
    pub message: MessageSignature,
}

/// What an HTTP message signature (RFC 9421) signs with: set, the
/// algorithm makes it the one method (`CURLOPT_HTTPSIG_ALGORITHM`).
#[derive(Debug)]
pub struct MessageSignature {
    pub algorithm: Option<SignatureAlgorithm>,
    /// The key, in hex (`CURLOPT_HTTPSIG_KEY`).
    pub key: Option<Vec<u8>>,
    /// What the key is known as to the server (`CURLOPT_HTTPSIG_KEYID`).
    pub key_id: Option<Vec<u8>>,
    /// The components signed, separated by blanks: `method`,
    /// `authority`, `path`, `query`, or a header's name with a colon;
    /// unless set, the first three and the query if there is one
    /// (`CURLOPT_HTTPSIG_HEADERS`).
    pub components: Option<Vec<u8>>,
}

/// An HTTP message signature's algorithm (`CURLHTTPSIG_*`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    Ed25519,
    HmacSha256,
}

impl ColdGroup for Signing {
    const UNSET: &'static Signing = &Signing::NONE;
    const NONE: Signing = Signing {
        aws_sigv4: None,
        message: MessageSignature {
            algorithm: None,
            key: None,
            key_id: None,
            components: None,
        },
    };
}

impl Signing {
    fn try_clone(&self) -> Result<Signing, OutOfMemory> {
        Ok(Signing {
            aws_sigv4: self.aws_sigv4.as_deref().map(copy).transpose()?,
            message: self.message.try_clone()?,
        })
    }
}

impl MessageSignature {
    fn try_clone(&self) -> Result<MessageSignature, OutOfMemory> {
        Ok(MessageSignature {
            algorithm: self.algorithm,
            key: self.key.as_deref().map(copy).transpose()?,
            key_id: self.key_id.as_deref().map(copy).transpose()?,
            components: self.components.as_deref().map(copy).transpose()?,
        })
    }
}

/// Where a transfer's cookies come from and go.
#[derive(Debug)]
pub struct Cookies {
    /// Sent as given, after the jar's, to the first origin only unless
    /// `Http::unrestricted_auth` says otherwise, and not beside the
    /// application's own `Cookie:` header (`CURLOPT_COOKIE`).
    pub send: Option<Vec<u8>>,
    /// Files read into the jar as each transfer starts, in the Netscape
    /// format or as `Set-Cookie:` lines; `-` is standard input
    /// (`CURLOPT_COOKIEFILE`). Any, even an empty name, turns the jar on.
    pub files: Lines,
    /// Where `Easy::save_cookies` writes the jar, `-` for standard
    /// output; set, it turns the jar on (`CURLOPT_COOKIEJAR`).
    pub save_to: Option<Vec<u8>>,
    /// The files' cookies that last the session are passed over
    /// (`CURLOPT_COOKIESESSION`).
    pub new_session: bool,
}

impl Cookies {
    /// Whether the options turn the jar on.
    pub(crate) fn wanted(&self) -> bool {
        self.files.iter().next().is_some() || self.save_to.is_some()
    }

    fn try_clone(&self) -> Result<Cookies, OutOfMemory> {
        Ok(Cookies {
            send: self.send.as_deref().map(copy).transpose()?,
            files: self.files.try_clone()?,
            save_to: self.save_to.as_deref().map(copy).transpose()?,
            new_session: self.new_session,
        })
    }
}

/// The methods a request may authenticate with (`CURLOPT_HTTPAUTH`): one
/// is used at once, more are chosen from as a server asks. Basic unless
/// set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HttpAuth(pub AuthMethods);

impl HttpAuth {
    pub const DEFAULT: HttpAuth = HttpAuth(AuthMethods::BASIC);
}

impl Default for HttpAuth {
    fn default() -> Self {
        HttpAuth::DEFAULT
    }
}

/// HTTP authentication methods, as a set (`CURLAUTH_*`); empty unless
/// set.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct AuthMethods(u8);

impl AuthMethods {
    pub const NONE: AuthMethods = AuthMethods(0);
    pub const BASIC: AuthMethods = AuthMethods(1);
    pub const DIGEST: AuthMethods = AuthMethods(2);
    pub const BEARER: AuthMethods = AuthMethods(4);
    /// AWS Signature Version 4, which no server asks for: used at once
    /// when it is the one method wanted (`CURLOPT_AWS_SIGV4`).
    pub const AWS_SIGV4: AuthMethods = AuthMethods(8);
    /// HTTP message signatures (RFC 9421), which no server asks for:
    /// used at once when it is the one method wanted, never with a proxy
    /// (`CURLOPT_HTTPSIG_ALGORITHM`).
    pub const HTTPSIG: AuthMethods = AuthMethods(0x10);
    /// Methods this library does not implement, asked for all the same:
    /// never used, but with one of the others, that one is used only once
    /// a server asks for it, as with `ONLY`.
    pub const OTHER: AuthMethods = AuthMethods(0x40);
    /// Not a method: with one, that one is used only once a server asks
    /// for it (`CURLAUTH_ONLY`).
    pub const ONLY: AuthMethods = AuthMethods(0x80);
    /// Every method there is, chosen from as a server asks
    /// (`CURLAUTH_ANY`).
    pub const ANY: AuthMethods = AuthMethods(1 | 2 | 4 | 8 | 0x40 | 0x80);
    /// Every method, and the bits beside them: `ANY` and the message
    /// signature, which `CURLAUTH_ANY` leaves out.
    const ALL: AuthMethods = AuthMethods(Self::ANY.0 | Self::HTTPSIG.0);

    pub fn contains(self, other: AuthMethods) -> bool {
        self.0 & other.0 == other.0
    }

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The one method this is, if it is exactly one this library
    /// implements; with `ONLY` or `OTHER`, none.
    pub(crate) fn single(self) -> Option<AuthMethods> {
        let known =
            Self::BASIC.0 | Self::DIGEST.0 | Self::BEARER.0 | Self::AWS_SIGV4.0 | Self::HTTPSIG.0;
        (self.0.count_ones() == 1 && self.0 & !known == 0).then_some(self)
    }

    /// The method's name, as an `Authorization` line starts.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::BASIC => "Basic",
            Self::DIGEST => "Digest",
            Self::BEARER => "Bearer",
            Self::AWS_SIGV4 => "AWS_SIGV4",
            Self::HTTPSIG => "HTTPSIG",
            _ => unreachable!("one method: {self:?}"),
        }
    }
}

impl std::ops::BitOr for AuthMethods {
    type Output = AuthMethods;
    fn bitor(self, other: AuthMethods) -> AuthMethods {
        AuthMethods(self.0 | other.0)
    }
}

impl std::ops::BitAnd for AuthMethods {
    type Output = AuthMethods;
    fn bitand(self, other: AuthMethods) -> AuthMethods {
        AuthMethods(self.0 & other.0)
    }
}

impl std::ops::Not for AuthMethods {
    type Output = AuthMethods;
    fn not(self) -> AuthMethods {
        AuthMethods(!self.0 & Self::ALL.0)
    }
}

impl fmt::Debug for AuthMethods {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names = [
            (Self::BASIC, "BASIC"),
            (Self::DIGEST, "DIGEST"),
            (Self::BEARER, "BEARER"),
            (Self::AWS_SIGV4, "AWS_SIGV4"),
            (Self::HTTPSIG, "HTTPSIG"),
            (Self::OTHER, "OTHER"),
            (Self::ONLY, "ONLY"),
        ];
        let mut set = f.debug_set();
        for (bit, name) in names {
            if self.contains(bit) {
                set.entry(&format_args!("{name}"));
            }
        }
        set.finish()
    }
}

/// Which redirects keep a POST a POST (`CURLOPT_POSTREDIR`): unless set,
/// a 301, 302 or 303 turns it into a GET.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PostRedir {
    pub post301: bool,
    pub post302: bool,
    pub post303: bool,
}

/// How many redirects a transfer follows (`CURLOPT_MAXREDIRS`): 30 unless
/// set; `None` for no limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaxRedirects(pub Option<u16>);

impl Default for MaxRedirects {
    fn default() -> Self {
        MaxRedirects(Some(30))
    }
}

/// Some of the schemes libcurl knows, built in or not: C's `curl_prot_t`,
/// a mask of `CURLPROTO_*`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Protocols(u64);

impl Protocols {
    /// Every scheme, as a transfer may use unless the application says
    /// otherwise (`CURLPROTO_64ALL`).
    pub const ALL: Protocols = Protocols(u64::MAX);

    /// None.
    pub const NONE: Protocols = Protocols(0);

    /// HTTP, HTTPS, FTP and FTPS: where a redirect may lead unless the
    /// application says otherwise (`CURLPROTO_REDIR`).
    pub const REDIRECT: Protocols = match Protocols::of(&["http", "https", "ftp", "ftps"]) {
        Some(set) => set,
        None => panic!("libcurl knows these schemes"),
    };

    /// The schemes `names`, each lowercase; none if libcurl does not know
    /// one of them.
    pub const fn of(names: &[&str]) -> Option<Protocols> {
        let mut set = 0u64;
        let mut i = 0;
        while i < names.len() {
            match crate::url::known_index(names[i].as_bytes()) {
                Some(bit) => set |= 1 << bit,
                None => return None,
            }
            i += 1;
        }
        Some(Protocols(set))
    }

    /// The scheme `name`, in any case, if this build speaks it; none for
    /// one it leaves out or libcurl does not know (`Curl_getn_scheme`
    /// and its `run`).
    pub fn built(name: &[u8]) -> Option<Protocols> {
        // No scheme libcurl knows is longer.
        let mut lower = [0u8; 7];
        let lower = lower.get_mut(..name.len())?;
        for (to, from) in lower.iter_mut().zip(name) {
            *to = from.to_ascii_lowercase();
        }
        crate::version::Protocol::of_scheme(lower)?;
        crate::url::known_index(lower).map(|bit| Protocols(1 << bit))
    }

    /// Those in either.
    pub const fn union(self, other: Protocols) -> Protocols {
        Protocols(self.0 | other.0)
    }

    /// Whether there are none.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Whether `scheme`, lowercase, is one of them.
    pub fn contains(self, scheme: &[u8]) -> bool {
        crate::url::known_index(scheme).is_some_and(|bit| self.0 & 1 << bit != 0)
    }
}

/// The schemes a transfer may use, which few applications limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Schemes {
    /// Those any URL may have (`CURLOPT_PROTOCOLS_STR`): all unless set.
    pub allowed: Protocols,
    /// Those a followed redirect may lead to, as well
    /// (`CURLOPT_REDIR_PROTOCOLS_STR`): HTTP, HTTPS, FTP and FTPS unless
    /// set.
    pub redirect: Protocols,
}

impl ColdGroup for Schemes {
    const UNSET: &'static Schemes = &Schemes::NONE;
    const NONE: Schemes = Schemes {
        allowed: Protocols::ALL,
        redirect: Protocols::REDIRECT,
    };
}

impl Schemes {
    /// Whether a URL of `scheme`, lowercase, may be used, `redirected`
    /// there or not (`url_set_conn_scheme`). One libcurl does not know is
    /// not theirs to refuse.
    pub(crate) fn permit(&self, scheme: &[u8], redirected: bool) -> bool {
        if crate::url::known_index(scheme).is_none() {
            return true;
        }
        self.allowed.contains(scheme) && (!redirected || self.redirect.contains(scheme))
    }
}

/// Which redirects a transfer follows, and how its method changes along
/// them (`CURLFOLLOW_*`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Follow {
    /// None: where a redirect leads is only reported.
    #[default]
    No,
    /// Every redirect.
    All,
    /// Every redirect, the method changing as its code says, a custom
    /// one included.
    ObeyCode,
    /// Every redirect, a custom method sent only to the first URL.
    FirstOnly,
}

impl Http {
    fn try_clone(&self) -> Result<Http, OutOfMemory> {
        Ok(Http {
            user_agent: self.user_agent.as_deref().map(copy).transpose()?,
            headers: self.headers.try_clone()?,
            version: self.version,
            allow_09: self.allow_09,
            ignore_content_length: self.ignore_content_length,
            raw: self.raw,
            transfer_encoding: self.transfer_encoding,
            accept_encoding: match &self.accept_encoding {
                None => None,
                Some(crate::coding::AcceptEncoding::All) => {
                    Some(crate::coding::AcceptEncoding::All)
                }
                Some(crate::coding::AcceptEncoding::Given(v)) => {
                    Some(crate::coding::AcceptEncoding::Given(copy(v)?))
                }
            },
            raw_content: self.raw_content,
            custom: self.custom.try_clone(Custom::try_clone)?,
            fail_on_error: self.fail_on_error,
            continue_wait: self.continue_wait,
            keep_sending_on_error: self.keep_sending_on_error,
            follow: self.follow,
            max_redirects: self.max_redirects,
            post_redirect: self.post_redirect,
            auto_referer: self.auto_referer,
            unrestricted_auth: self.unrestricted_auth,
            auth: self.auth,
            cookies: self.cookies.try_clone(Cookies::try_clone)?,
            signing: self.signing.try_clone(Signing::try_clone)?,
        })
    }
}

/// How a transfer's TLS is set up and its peer checked. The verify bits
/// every handle carries; the rest few transfers set, so they are a group
/// of their own.
#[derive(Debug)]
pub struct Tls {
    /// The peer's certificate must verify (`CURLOPT_SSL_VERIFYPEER`).
    pub verify_peer: bool,
    /// The certificate must name the host (`CURLOPT_SSL_VERIFYHOST`).
    pub verify_host: bool,
    pub options: Cold<TlsOptions>,
}

impl Default for Tls {
    fn default() -> Self {
        Tls {
            verify_peer: true,
            verify_host: true,
            options: Cold::new(),
        }
    }
}

impl Tls {
    fn try_clone(&self) -> Result<Tls, OutOfMemory> {
        Ok(Tls {
            verify_peer: self.verify_peer,
            verify_host: self.verify_host,
            options: self.options.try_clone(TlsOptions::try_clone)?,
        })
    }
}

/// The TLS options few transfers set: what to trust, who to be, which
/// versions and algorithms to allow, and the bits of `CURLOPT_SSL_OPTIONS`
/// (C's `ssl_filter_config`, but for the verify bits, which `Tls` holds).
/// Each text is as the application gave it; none is not set.
#[derive(Debug, PartialEq, Eq)]
pub struct TlsOptions {
    /// The versions allowed (`CURLOPT_SSLVERSION`).
    pub min_version: TlsMinVersion,
    pub max_version: TlsMaxVersion,
    pub ssl_options: SslOptions,
    /// The peer's certificate status must be checked, by OCSP stapling
    /// (`CURLOPT_SSL_VERIFYSTATUS`).
    pub verify_status: bool,
    /// The certificates the peer is checked against
    /// (`CURLOPT_CAINFO`), and the directory of them (`CURLOPT_CAPATH`).
    pub ca_file: CaSetting,
    pub ca_path: CaSetting,
    /// The same, given in memory (`CURLOPT_CAINFO_BLOB`).
    pub ca_blob: Option<Vec<u8>>,
    /// The revocation list (`CURLOPT_CRLFILE`).
    pub crl_file: Option<Vec<u8>>,
    /// The certificate the peer's must be issued by (`CURLOPT_ISSUERCERT`,
    /// `CURLOPT_ISSUERCERT_BLOB`).
    pub issuer_cert: Option<Vec<u8>>,
    pub issuer_cert_blob: Option<Vec<u8>>,
    /// The client's certificate and its format (`CURLOPT_SSLCERT`,
    /// `CURLOPT_SSLCERT_BLOB`, `CURLOPT_SSLCERTTYPE`).
    pub cert: Option<Vec<u8>>,
    pub cert_blob: Option<Vec<u8>>,
    pub cert_type: Option<Vec<u8>>,
    /// The client's private key, its format and its password
    /// (`CURLOPT_SSLKEY`, `CURLOPT_SSLKEY_BLOB`, `CURLOPT_SSLKEYTYPE`,
    /// `CURLOPT_KEYPASSWD`).
    pub key: Option<Vec<u8>>,
    pub key_blob: Option<Vec<u8>>,
    pub key_type: Option<Vec<u8>>,
    pub key_password: Option<Vec<u8>>,
    /// The cipher lists, before TLS 1.3 and for it
    /// (`CURLOPT_SSL_CIPHER_LIST`, `CURLOPT_TLS13_CIPHERS`), the curves
    /// (`CURLOPT_SSL_EC_CURVES`) and the signature algorithms
    /// (`CURLOPT_SSL_SIGNATURE_ALGORITHMS`).
    pub ciphers: Option<Vec<u8>>,
    pub tls13_ciphers: Option<Vec<u8>>,
    pub curves: Option<Vec<u8>>,
    pub signature_algorithms: Option<Vec<u8>>,
    /// The public key the peer's must be (`CURLOPT_PINNEDPUBLICKEY`): a
    /// file, or `sha256//` hashes.
    pub pinned_key: Option<Vec<u8>>,
    /// ALPN is offered (`CURLOPT_SSL_ENABLE_ALPN`). C keeps it on the
    /// handle, not in the TLS settings a connection is matched by.
    pub alpn: bool,
}

impl ColdGroup for TlsOptions {
    const UNSET: &'static TlsOptions = &TlsOptions::NONE;
    const NONE: TlsOptions = TlsOptions {
        min_version: TlsMinVersion::Default,
        max_version: TlsMaxVersion::None,
        ssl_options: SslOptions::NONE,
        verify_status: false,
        ca_file: CaSetting::Default,
        ca_path: CaSetting::Default,
        ca_blob: None,
        crl_file: None,
        issuer_cert: None,
        issuer_cert_blob: None,
        cert: None,
        cert_blob: None,
        cert_type: None,
        key: None,
        key_blob: None,
        key_type: None,
        key_password: None,
        ciphers: None,
        tls13_ciphers: None,
        curves: None,
        signature_algorithms: None,
        pinned_key: None,
        alpn: true,
    };
}

impl TlsOptions {
    pub(crate) fn try_clone(&self) -> Result<TlsOptions, OutOfMemory> {
        let text = |t: &Option<Vec<u8>>| t.as_deref().map(copy).transpose();
        // Every field by name, so one added is copied too.
        let TlsOptions {
            min_version,
            max_version,
            ssl_options,
            verify_status,
            ca_file,
            ca_path,
            ca_blob,
            crl_file,
            issuer_cert,
            issuer_cert_blob,
            cert,
            cert_blob,
            cert_type,
            key,
            key_blob,
            key_type,
            key_password,
            ciphers,
            tls13_ciphers,
            curves,
            signature_algorithms,
            pinned_key,
            alpn,
        } = self;
        Ok(TlsOptions {
            min_version: *min_version,
            max_version: *max_version,
            ssl_options: *ssl_options,
            verify_status: *verify_status,
            ca_file: ca_file.try_clone()?,
            ca_path: ca_path.try_clone()?,
            ca_blob: text(ca_blob)?,
            crl_file: text(crl_file)?,
            issuer_cert: text(issuer_cert)?,
            issuer_cert_blob: text(issuer_cert_blob)?,
            cert: text(cert)?,
            cert_blob: text(cert_blob)?,
            cert_type: text(cert_type)?,
            key: text(key)?,
            key_blob: text(key_blob)?,
            key_type: text(key_type)?,
            key_password: text(key_password)?,
            ciphers: text(ciphers)?,
            tls13_ciphers: text(tls13_ciphers)?,
            curves: text(curves)?,
            signature_algorithms: text(signature_algorithms)?,
            pinned_key: text(pinned_key)?,
            alpn: *alpn,
        })
    }
}

impl Default for TlsOptions {
    fn default() -> Self {
        TlsOptions::NONE
    }
}

/// Where certificates to trust are read from: the place the build found,
/// none, or the application's.
#[derive(Debug, Default, PartialEq, Eq)]
pub enum CaSetting {
    /// The TLS library's default, found as the library was built (C
    /// stores a copy of it in the option at the handle's start).
    #[default]
    Default,
    /// None: the application set it to nothing.
    Unset,
    Given(Vec<u8>),
}

impl CaSetting {
    fn try_clone(&self) -> Result<CaSetting, OutOfMemory> {
        Ok(match self {
            CaSetting::Default => CaSetting::Default,
            CaSetting::Unset => CaSetting::Unset,
            CaSetting::Given(text) => CaSetting::Given(copy(text)?),
        })
    }
}

/// The oldest TLS version a transfer allows (`CURL_SSLVERSION_*`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TlsMinVersion {
    /// The library's own floor.
    #[default]
    Default,
    /// Any TLS 1.x (`CURL_SSLVERSION_TLSv1`).
    Tls1,
    Tls1_0,
    Tls1_1,
    Tls1_2,
    Tls1_3,
}

/// The newest TLS version a transfer allows (`CURL_SSLVERSION_MAX_*`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TlsMaxVersion {
    /// None set (`CURL_SSLVERSION_MAX_NONE`).
    #[default]
    None,
    /// The library's newest (`CURL_SSLVERSION_MAX_DEFAULT`).
    Default,
    Tls1_0,
    Tls1_1,
    Tls1_2,
    Tls1_3,
}

/// The bits of `CURLOPT_SSL_OPTIONS`, as C keeps them for a connection's
/// TLS: the low eight.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SslOptions(u8);

impl SslOptions {
    pub const NONE: SslOptions = SslOptions(0);
    /// Allow the BEAST flaw's workaround off (`CURLSSLOPT_ALLOW_BEAST`).
    pub const ALLOW_BEAST: SslOptions = SslOptions(1 << 0);
    pub const NO_REVOKE: SslOptions = SslOptions(1 << 1);
    pub const NO_PARTIALCHAIN: SslOptions = SslOptions(1 << 2);
    pub const REVOKE_BEST_EFFORT: SslOptions = SslOptions(1 << 3);
    pub const NATIVE_CA: SslOptions = SslOptions(1 << 4);
    pub const AUTO_CLIENT_CERT: SslOptions = SslOptions(1 << 5);
    pub const EARLYDATA: SslOptions = SslOptions(1 << 6);

    /// Every bit of `other` is set.
    pub fn contains(self, other: SslOptions) -> bool {
        self.0 & other.0 == other.0
    }
}

impl std::ops::BitOr for SslOptions {
    type Output = SslOptions;

    fn bitor(self, other: SslOptions) -> SslOptions {
        SslOptions(self.0 | other.0)
    }
}

/// What a transfer tells the application besides the body.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Output {
    /// Header lines go to the write handler too, before the header
    /// handler (`CURLOPT_HEADER`).
    pub include_header: bool,
    /// Trace the transfer (`CURLOPT_VERBOSE`).
    pub verbose: bool,
}

/// Where a transfer's output goes. A copy of the options shares each
/// handler, as C's copies share a callback and its userdata.
#[derive(Clone, Debug, Default)]
pub struct Callbacks {
    /// The body; without one, it is dropped.
    pub write: Option<Handler<dyn WriteHandler>>,
    /// Header lines; without one, they go nowhere.
    pub header: Option<Handler<dyn HeaderHandler>>,
    /// The trace of a verbose transfer.
    pub debug: Option<Handler<dyn DebugHandler>>,
    /// Text for the user; without one, the process's standard error.
    pub stderr: Option<Handler<dyn TextSink>>,
    /// Told a transfer's first reason for failing as it is given, as C
    /// copies it into `CURLOPT_ERRORBUFFER`; the report keeps it too.
    pub failure: Option<Handler<dyn TextSink>>,
    /// The trailers a chunked request body ends with; without one, none.
    pub trailer: Option<Handler<dyn TrailerHandler>>,
}

/// Where the body a transfer sends comes from.
#[derive(Clone, Debug, Default)]
pub enum UploadSource {
    /// Nothing: an empty body.
    #[default]
    None,
    /// These bytes, shared by every copy of the options
    /// (`CURLOPT_COPYPOSTFIELDS`).
    Bytes(TryArc<Vec<u8>>),
    /// Bytes the application lends, read where they are as they are sent.
    Lent(Handler<dyn LentBytes>),
    /// A multipart body, the tree the source gives as each request is
    /// built (`CURLOPT_MIMEPOST`).
    Mime(Handler<dyn MimeSource>),
    /// What a handler reads, `size` bytes if known (`CURLOPT_READFUNCTION`,
    /// `CURLOPT_INFILESIZE_LARGE`). Without a rewind, a request that must be
    /// sent again after reading fails with SendFailRewind.
    Read {
        handler: Handler<dyn ReadHandler>,
        rewind: Option<Handler<dyn Rewind>>,
        size: Option<u64>,
    },
}

/// How a transfer shows its progress.
#[derive(Clone, Debug, Default)]
pub enum Progress {
    /// Not at all (`CURLOPT_NOPROGRESS`, on by default).
    #[default]
    Off,
    /// The meter, drawn on the standard error sink.
    Meter,
    /// A handler, which may ask for the meter too.
    Handler(Handler<dyn ProgressHandler>),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A copy keeps the lists of addresses and peers given for names.
    #[test]
    fn a_copy_keeps_the_lists_for_names() {
        let mut o = Options::default();
        o.resolve.set([&b"a:1:127.0.0.1"[..]]).unwrap();
        o.connect_to.set([&b"::b:2"[..]]).unwrap();
        let copy = o.try_clone().unwrap();
        assert!(copy.resolve.entries().eq([&b"a:1:127.0.0.1"[..]]));
        assert_eq!(copy.resolve.stamp(), o.resolve.stamp());
        assert!(copy.connect_to.iter().eq([&b"::b:2"[..]]));
    }

    /// A copy keeps the proxy, the login and the cookies' options.
    #[test]
    fn a_copy_keeps_the_proxy_login_and_cookies() {
        let mut o = Options::default();
        o.proxy.make_mut().unwrap().url = Some(b"http://proxy.example:3128".to_vec());
        o.proxy.make_mut().unwrap().user = Some(b"pu".to_vec());
        o.login.make_mut().unwrap().user = Some(b"lu".to_vec());
        o.login.make_mut().unwrap().bearer = Some(b"t".to_vec());
        o.http.cookies.make_mut().unwrap().send = Some(b"a=1".to_vec());
        o.http.cookies.make_mut().unwrap().new_session = true;
        let copy = o.try_clone().unwrap();
        assert_eq!(
            copy.proxy.url.as_deref(),
            Some(&b"http://proxy.example:3128"[..])
        );
        assert_eq!(copy.proxy.user.as_deref(), Some(&b"pu"[..]));
        assert_eq!(copy.login.user.as_deref(), Some(&b"lu"[..]));
        assert_eq!(copy.login.bearer.as_deref(), Some(&b"t"[..]));
        assert_eq!(copy.http.cookies.send.as_deref(), Some(&b"a=1"[..]));
        assert!(copy.http.cookies.new_session);
    }

    /// `CURLOPT_PROXYUSERPWD`: split at the first colon, each part
    /// URL-decoded, one that decodes to a zero byte refused; none clears
    /// both.
    #[test]
    fn a_proxy_s_user_and_password_are_split_and_decoded() {
        let mut p = Proxy::default();
        p.set_user_password(Some(b"us%3Aer:pa:ss")).unwrap();
        assert_eq!(
            (p.user.as_deref(), p.password.as_deref()),
            (Some(&b"us:er"[..]), Some(&b"pa:ss"[..]))
        );
        assert_eq!(
            p.set_user_password(Some(b"u:p%00")),
            Err(ProxyUserError::Malformed)
        );
        p.set_user_password(None).unwrap();
        assert_eq!((p.user, p.password), (None, None));
    }

    /// A list that may have a source costs a handle no more than its
    /// lines: test 751 counts the bytes of a thousand handles.
    #[test]
    fn a_listed_option_is_as_large_as_its_lines() {
        assert_eq!(size_of::<Lines>(), size_of::<Vec<Vec<u8>>>());
        assert_eq!(size_of::<UserHeaders>(), size_of::<Vec<Vec<u8>>>());
    }

    /// Methods combine as sets; a set of one method is that method, of
    /// more, or with `ONLY` or `OTHER`, none.
    #[test]
    fn auth_methods_are_sets() {
        use AuthMethods as A;
        assert_eq!(A::BASIC | A::BASIC, A::BASIC);
        assert_eq!(A::ANY | A::DIGEST, A::ANY);
        assert_eq!(A::BASIC.single(), Some(A::BASIC));
        assert_eq!((A::BASIC | A::DIGEST).single(), None);
        assert_eq!(A::ONLY.single(), None);
        assert_eq!((A::DIGEST | A::ONLY).single(), None);
        assert_eq!(A::OTHER.single(), None, "never used");
        assert_eq!((A::BASIC | A::OTHER).single(), None);
        assert!(A::ANY.contains(A::OTHER));
        assert_eq!(format!("{:?}", A::BASIC | A::OTHER), "{BASIC, OTHER}");
        assert_eq!(format!("{:?}", A::DIGEST | A::ONLY), "{DIGEST, ONLY}");
        assert_eq!(format!("{:?}", A::NONE), "{}");
    }

    /// Each method is named as its `Authorization` line starts.
    #[test]
    fn auth_methods_are_named() {
        use AuthMethods as A;
        for (m, name) in [
            (A::BASIC, "Basic"),
            (A::DIGEST, "Digest"),
            (A::BEARER, "Bearer"),
            (A::AWS_SIGV4, "AWS_SIGV4"),
            (A::HTTPSIG, "HTTPSIG"),
        ] {
            assert_eq!(m.single(), Some(m));
            assert_eq!(m.name(), name);
        }
    }

    /// A source giving one line, numbered by how often it was read.
    struct Numbered(crate::test_cell::Cell<u32>);

    impl LineSource for Numbered {
        fn lines(
            &self,
            line: &mut dyn FnMut(&[u8]) -> Result<(), OutOfMemory>,
        ) -> Result<(), OutOfMemory> {
            self.0.set(self.0.get() + 1);
            line(format!("line {}", self.0.get()).as_bytes())
        }
    }

    fn numbered() -> Handler<dyn LineSource> {
        Handler::lines(Numbered(crate::test_cell::Cell::new(0))).unwrap()
    }

    /// A list given by a source is read as it is set, and again as it is
    /// refilled; setting the resolve list either way is a new setting.
    #[test]
    fn a_source_s_lines_are_read_again_as_refilled() {
        let mut lines = Lines::NONE;
        lines.set_source(numbered()).unwrap();
        assert!(lines.iter().eq([&b"line 1"[..]]));
        lines.refill().unwrap();
        assert!(lines.iter().eq([&b"line 2"[..]]));
        let copy = lines.try_clone().unwrap();
        assert!(copy.iter().eq([&b"line 2"[..]]));
        let mut copy = copy;
        copy.refill().unwrap();
        assert!(copy.iter().eq([&b"line 3"[..]]), "the same source");

        let mut list = ResolveList::default();
        assert_eq!(list.stamp(), 0);
        list.set_source(numbered()).unwrap();
        assert_eq!(list.stamp(), 1);
        assert!(list.entries().eq([&b"line 1"[..]]));
        list.refill().unwrap();
        assert_eq!(list.stamp(), 1, "the same setting");
        assert!(list.entries().eq([&b"line 2"[..]]));
        list.set([&b"a:1:127.0.0.1"[..]]).unwrap();
        list.set_source(numbered()).unwrap();
        assert_eq!(list.stamp(), 3);
    }

    /// A group's option set makes the group; cleared, it is cleared, and
    /// clearing one in a group never made makes nothing.
    #[test]
    fn a_group_s_option_is_set_and_cleared() {
        let mut login: Cold<Login> = Cold::new();
        login.set(|l| &mut l.user, None).unwrap();
        assert!(login.made_mut().is_none());
        login.set(|l| &mut l.user, Some(b"u".to_vec())).unwrap();
        assert_eq!(login.user.as_deref(), Some(&b"u"[..]));
        login.set(|l| &mut l.user, None).unwrap();
        assert_eq!(login.user, None);
    }

    /// The buffers are held under their largest sizes.
    #[test]
    fn buffer_sizes_are_held_to_their_bounds() {
        assert_eq!(BufferSize::clamped(u64::MAX).get(), 10 * 1024 * 1024);
        assert_eq!(BufferSize::clamped(0).get(), 1024);
        assert_eq!(UploadBufferSize::clamped(u64::MAX).get(), 2 * 1024 * 1024);
        assert_eq!(UploadBufferSize::clamped(0).get(), 16384);
    }
}
