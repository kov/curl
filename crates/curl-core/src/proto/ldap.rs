//! LDAP and LDAPS through an LDAP library (`lib/openldap.c`): the URL's
//! search, sent once the connection is bound, and each entry the server
//! answers with written as LDIF, as C writes it.
//!
//! The library does the protocol: the connection's state is its session
//! over a copy of the socket, which over TLS reads and writes through
//! the connection's layers instead ([`crate::ldap::Wire`]). A connection
//! binds as it connects, simply, by SASL where a mechanism is asked for,
//! or not at all; over `ldap:` it may first be upgraded to TLS
//! (STARTTLS).

use curl_alloc::TryVec as _;

use super::{Connect, DoPhase, DoStep, Finish, ProtoStep, Waiting};
use crate::auth::creds::{CredentialGate, Credentials, Takes};
use crate::auth::sasl::{self, Mechs, Progress, Sasl, SaslError};
use crate::conn::io::{Events, Sent};
use crate::conn::layer::LayerCx;
use crate::conn::line::LineConn;
use crate::conn::mux::Carrier;
use crate::conn::{ConnLease, RecvFailed};
use crate::deliver::{self, Pause, Pipeline, Reach};
use crate::error::{ErrorKind, UrlErrorKind, url_error};
use crate::ldap::{
    Code, Kind, Ldap, LdapLibrary, Mech, Message, MsgId, Scope, Search, Session, SessionFailed,
    UrlError, Version, Wire,
};
use crate::multi::Host;
use crate::multi::state::StepCx;
use crate::options::UseSsl;
use crate::trace;
use crate::url::{GetOptions, Part, Url};

/// The largest message the library reads (`LBER_SB_OPT_SET_MAX_INCOMING`):
/// it allocates up to this much for one, and with no limit could fail to.
const MAX_INCOMING: usize = 256 * 1024;

/// LDAP's SASL (`saslldap`): a mechanism only where one is asked for, and
/// the messages as they are, in the binds' credentials.
static SASL: sasl::Params = sasl::Params {
    service: "ldap",
    max_ir: 0,
    default: Mechs::NONE,
    base64: false,
};

/// The library's words for each of its URL errors, from
/// `LDAP_URL_SUCCESS` on (`url_errs`).
const URL_ERRORS: [&str; 11] = [
    "success",
    "out of memory",
    "bad parameter",
    "unrecognized scheme",
    "unbalanced delimiter",
    "bad URL",
    "bad host or port",
    "bad or missing attributes",
    "bad or missing scope",
    "bad or missing filter",
    "bad or missing extensions",
];

/// An LDAP transfer: its search, and where reading the answer is.
#[derive(Debug)]
pub(crate) struct Request {
    /// The library its handle has.
    library: &'static dyn Ldap,
    pub(super) base: super::base::RequestBase,
    /// The URL, as the transfer names it (`state.url`).
    url_text: Vec<u8>,
    /// The search it names.
    search: Search,
    /// The URL's login options (`state.up.options`), which the
    /// connection logs in by unless the application gives its own.
    url_options: Option<Vec<u8>>,
    /// The search under way, until its result is read (`lr->msgid`).
    msgid: Option<MsgId>,
    /// The entries read (`lr->nument`).
    entries: u32,
    /// The answer is being read.
    receiving: bool,
}

/// Where a connection's set-up is (`ldapstate`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum State {
    Stop,
    /// TLS from the start, under way.
    Ssl,
    /// STARTTLS sent.
    StartTls,
    /// STARTTLS's handshake under way.
    Tls,
    /// The SASL mechanisms asked for.
    Mechs,
    /// A SASL bind's answer awaited.
    Sasl,
    /// A simple bind's answer awaited.
    Bind,
    /// The same, in protocol version 2.
    BindV2,
}

impl State {
    /// Its name, as C's debug build says it.
    fn name(self) -> &'static str {
        match self {
            State::Stop => "STOP",
            State::Ssl => "SSL",
            State::StartTls => "STARTTLS",
            State::Tls => "TLS",
            State::Mechs => "MECHS",
            State::Sasl => "SASL",
            State::Bind => "BIND",
            State::BindV2 => "BINDV2",
        }
    }
}

/// A connection's LDAP state (C's `ldapconninfo`): the library's session,
/// where its set-up is, and the message it awaits.
#[derive(Debug)]
pub(crate) struct LdapConn {
    session: Box<dyn Session>,
    state: State,
    /// The message set-up awaits the answer to (`li->msgid`).
    msgid: Option<MsgId>,
    sasl: Sasl,
}

impl LdapConn {
    /// Unbind, through the connection's layers if the session reads and
    /// writes through them (`oldap_disconnect`): said whether the
    /// connection is dead or not, as C's ignores it.
    pub(crate) fn goodbye(&mut self, cx: &mut dyn LayerCx, below: Carrier<'_>) {
        let mut wire = ConnWire { cx, carrier: below };
        self.session.unbind(&mut wire);
    }
}

/// The connection's layers, as a session over TLS reads and writes them
/// (C's `li->recv` and `li->send`, under `ldapsb_tls`).
struct ConnWire<'a, 'c> {
    cx: &'a mut dyn LayerCx,
    carrier: Carrier<'c>,
}

impl Wire for ConnWire<'_, '_> {
    fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self.carrier.recv_into(self.cx, buf) {
            Ok(Some(n)) => Ok(n),
            Ok(None) => Err(std::io::ErrorKind::WouldBlock.into()),
            Err(RecvFailed::Os(e)) => Err(e),
            Err(RecvFailed::OutOfMemory) => Err(std::io::ErrorKind::OutOfMemory.into()),
        }
    }

    fn send(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        match self.carrier.send(self.cx, bytes)? {
            Sent::Bytes(n) => Ok(n.get()),
            Sent::WouldBlock => Err(std::io::ErrorKind::WouldBlock.into()),
        }
    }

    fn pending(&mut self) -> bool {
        use crate::conn::part::Lower as _;
        self.carrier.reborrow().data_pending()
    }
}

/// The connection's LDAP state, and the connection under it.
fn ldap_of(lease: &mut ConnLease) -> (&mut LdapConn, Carrier<'_>) {
    match lease.get().line_mut() {
        Some((LineConn::Ldap(lc), carrier)) => (lc, carrier),
        _ => unreachable!("an LDAP transfer's connection keeps LDAP's state"),
    }
}

/// Map the codes C maps to their own errors, else `otherwise`
/// (`oldap_map_error`).
fn map_error(code: Code, otherwise: ErrorKind) -> ErrorKind {
    match code {
        Code::NO_MEMORY => ErrorKind::OutOfMemory,
        Code::INVALID_CREDENTIALS => ErrorKind::LoginDenied,
        Code::PROTOCOL_ERROR => ErrorKind::UnsupportedProtocol,
        Code::INSUFFICIENT_ACCESS => ErrorKind::RemoteAccessDenied,
        _ => otherwise,
    }
}

/// Whether LDIF must give `s` in base64 (`oldap_str_needs_base64`): it
/// is not RFC 2849's SAFE-STRING, starting with `:` or `<` or a blank,
/// ending with a blank, or holding a byte that does not print.
pub(crate) fn needs_base64(s: &[u8]) -> bool {
    let blank = |b: u8| b == b' ' || b == b'\t';
    match (s.first(), s.last()) {
        (Some(&first), Some(&last)) => {
            first == b':'
                || first == b'<'
                || blank(first)
                || blank(last)
                || s.iter().any(|&b| !(0x20..0x7f).contains(&b))
        }
        _ => false,
    }
}

/// `bytes` in base64.
fn base64(bytes: &[u8]) -> Result<Vec<u8>, ErrorKind> {
    let mut out = Vec::new();
    crate::base64::encode(bytes, &mut out).map_err(|_| ErrorKind::OutOfMemory)?;
    Ok(out)
}

/// What a protocol's write of one entry came to.
type Wrote = Result<(), ErrorKind>;

/// Why an entry was not written whole.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Ldif {
    /// A write failed.
    Write(ErrorKind),
    /// The entry's name could not be read.
    Name,
    /// An attribute's type is not safe in LDIF, which has no base64 form
    /// for one: it would let the server write lines of its own.
    IllegalType,
    OutOfMemory,
}

/// Write one piece of an entry, as C's `client_write`: `prefix`, its last
/// blank dropped before an empty value or none, `value` if any, then
/// `suffix` if any, each a write of its own, empty or not.
fn piece(
    write: &mut dyn FnMut(&[u8]) -> Wrote,
    prefix: &[u8],
    value: Option<&[u8]>,
    suffix: Option<&[u8]>,
) -> Result<(), Ldif> {
    let mut prefix = prefix;
    if value.is_none_or(<[u8]>::is_empty) && prefix.last() == Some(&b' ') {
        prefix = &prefix[..prefix.len() - 1];
    }
    write(prefix).map_err(Ldif::Write)?;
    if let Some(value) = value {
        write(value).map_err(Ldif::Write)?;
    }
    if let Some(suffix) = suffix {
        write(suffix).map_err(Ldif::Write)?;
    }
    Ok(())
}

/// Write the entry `msg` is as LDIF (RFC 2849) into `write`: its name,
/// then each attribute's values, in base64 where they are binary or not
/// safe as they are, a blank line after each attribute and after the
/// entry (`oldap_recv`'s `LDAP_RES_SEARCH_ENTRY`).
pub(crate) fn ldif(
    msg: &mut dyn Message,
    write: &mut dyn FnMut(&[u8]) -> Wrote,
) -> Result<(), Ldif> {
    let b64 = |bytes: &[u8]| base64(bytes).map_err(|_| Ldif::OutOfMemory);
    let dn = msg.dn().map_err(|_| Ldif::Name)?;
    if needs_base64(dn) {
        // A name with a line break would start lines of its own.
        piece(write, b"DN:: ", Some(&b64(dn)?), Some(b"\n"))?;
    } else {
        piece(write, b"DN: ", Some(dn), Some(b"\n"))?;
    }
    loop {
        let next = msg.next_attribute().map_err(|_| Ldif::OutOfMemory)?;
        let Some(attr) = next else { break };
        if needs_base64(attr.name) {
            return Err(Ldif::IllegalType);
        }
        let Some(values) = attr.values else {
            piece(write, b"\t", Some(attr.name), Some(b":\n"))?;
            continue;
        };
        let binary = attr.name.len() > 7
            && attr.name[attr.name.len() - 7..].eq_ignore_ascii_case(b";binary");
        for value in values {
            piece(write, b"\t", Some(attr.name), Some(b":"))?;
            if binary || needs_base64(value) {
                // An empty value is none at all.
                let encoded = if value.is_empty() {
                    None
                } else {
                    Some(b64(value)?)
                };
                piece(write, b": ", encoded.as_deref(), Some(b"\n"))?;
            } else {
                piece(write, b" ", Some(value), Some(b"\n"))?;
            }
        }
        piece(write, b"\n", None, None)?;
    }
    piece(write, b"\n", None, None)
}

/// What a message read in the answer was.
enum Read {
    /// The search's result: its code and words, or why they could not be
    /// read.
    Result(Result<(Code, Option<Vec<u8>>), Code>),
    /// An entry, written.
    Entry(Wrote),
    Other,
}

impl Request {
    /// A transfer of `url`, `ldaps` if `secured`: its peer, the credentials
    /// its URL and the application give, a `.netrc`'s if asked for, and
    /// the search its URL names, which the library must read
    /// (`oldap_setup_connection`).
    pub(crate) fn new<H: Host>(
        url: &Url,
        secured: bool,
        before: super::Before<'_>,
        cx: &mut StepCx<'_, H>,
    ) -> Result<Request, ErrorKind> {
        let Some(LdapLibrary::Fd(library)) = cx.easy().libraries().ldap else {
            return Err(ErrorKind::UnsupportedProtocol);
        };
        let name: &[u8] = if secured { b"ldaps" } else { b"ldap" };
        let peer = super::base::peer_of(url, name, cx)?;
        let gate = match before.first {
            None => CredentialGate::FIRST,
            Some(first) => {
                let other_hosts = cx.easy().options().http.unrestricted_auth;
                CredentialGate::new(first, &peer, other_hosts)
            }
        };
        let takes = Takes::of(Some(peer.scheme()));
        let credentials = super::request_credentials(cx, gate.trusted(), url, takes)?;
        let credentials = super::with_netrc(credentials, peer.name(), takes, cx)?;
        let url_text = url.get(Part::Url, GetOptions::NONE).map_err(url_error)?;
        let decoded = GetOptions {
            url_decode: true,
            ..GetOptions::NONE
        };
        let url_options = match url.get(Part::Options, decoded) {
            Ok(options) => Some(options),
            Err(UrlErrorKind::NoOptions) => None,
            Err(e) => return Err(url_error(e)),
        };
        // The library reads URLs with credentials or options badly, so
        // C refuses them unread (`oldap_url_parse`).
        let from_url = credentials.as_ref().is_some_and(Credentials::given_in_url);
        let parsed = if from_url || url_options.is_some() {
            Err(UrlError::BAD_URL)
        } else {
            library.parse_url(&url_text)
        };
        let search = match parsed {
            Ok(search) => search,
            Err(e) => {
                let kind = if e == UrlError::MEM {
                    ErrorKind::OutOfMemory
                } else {
                    ErrorKind::UrlMalformat
                };
                let said = usize::try_from(e.0)
                    .ok()
                    .and_then(|i| URL_ERRORS.get(i))
                    .unwrap_or(&"url parsing problem");
                return Err(trace::fail(cx, kind, format_args!("LDAP local: {said}")));
            }
        };
        Ok(Request {
            base: super::base::RequestBase {
                peer,
                pipeline: Pipeline::new(Reach::Network),
                credentials,
                gate,
            },
            library,
            url_text,
            search,
            url_options,
            msgid: None,
            entries: 0,
            receiving: false,
        })
    }

    /// Its credentials, which its route takes: a connection binds with
    /// them once (`conn->creds`).
    pub(crate) fn take_login(&mut self) -> Option<Credentials> {
        self.base.credentials.take()
    }

    /// The answer is read once the search is sent (`Curl_xfer_setup_recv`).
    pub(crate) fn exchanges(&self) -> bool {
        true
    }

    /// While the answer is read, its socket.
    pub(crate) fn interest(&self, pause: Pause) -> Events {
        if self.receiving && !pause.recv_paused() {
            Events::IN
        } else {
            Events::NONE
        }
    }

    /// Move the state on, said as C's debug build says it (`oldap_state`).
    fn to<H: Host>(cx: &mut StepCx<'_, H>, lc: &mut LdapConn, state: State) {
        if lc.state != state {
            trace::debug_info(
                cx,
                format_args!(
                    "LDAP {:p} state change from {} to {}",
                    lc as *const LdapConn,
                    lc.state.name(),
                    state.name()
                ),
            );
        }
        lc.state = state;
    }

    /// The connection's LDAP state, made the first time, and its set-up
    /// begun (`oldap_connect`): the session over a copy of its socket,
    /// set to version 3, no referrals and the largest message; then TLS,
    /// STARTTLS or the bind.
    fn connect_first<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<(), ErrorKind> {
        let library = self.library;
        let mut sasl = Sasl::new(&SASL, cx.easy().options().http.auth.0);
        let options = match cx.easy().options().line.login_options.as_deref() {
            Some(given) => Some(given),
            None => self.url_options.as_deref(),
        };
        parse_login_options(&mut sasl, options.unwrap_or_default())?;
        let scheme = self.base.peer.scheme();
        let host = if self.base.peer.ipv6() {
            self.base.peer.shown()
        } else {
            self.base.peer.name()
        };
        let mut hosturl = Vec::new();
        let port = curl_alloc::try_format(format_args!(":{}", self.base.peer.port()))
            .map_err(|_| ErrorKind::OutOfMemory)?;
        let oom = |_| ErrorKind::OutOfMemory;
        hosturl
            .try_extend_from_slice(scheme.name().as_bytes())
            .map_err(oom)?;
        hosturl.try_extend_from_slice(b"://").map_err(oom)?;
        hosturl.try_extend_from_slice(host).map_err(oom)?;
        hosturl
            .try_extend_from_slice(port.as_bytes())
            .map_err(oom)?;
        let carrier = lease.get().carrier();
        let Some(socket) = carrier.stream_socket() else {
            return Err(ErrorKind::CouldntConnect);
        };
        let made = library.session(socket.descriptor(), scheme.name().as_bytes(), &hosturl);
        let mut session = match made {
            Err(SessionFailed::NoCopy) => return Err(ErrorKind::CouldntConnect),
            Err(SessionFailed::Library(code)) => {
                return Err(trace::fail_with(
                    cx,
                    ErrorKind::CouldntConnect,
                    &[
                        b"LDAP local: Cannot connect to ",
                        &hosturl,
                        b", ",
                        library.describe(code),
                    ],
                ));
            }
            Ok(session) => session,
        };
        // Version 3 first, no referrals chased.
        session.set_version(Version::V3);
        session.set_no_referrals();
        if session.set_max_incoming(MAX_INCOMING).is_err() {
            return Err(ErrorKind::FailedInit);
        }
        let lc = LdapConn {
            session,
            state: State::Stop,
            msgid: None,
            sasl,
        };
        let line = curl_alloc::try_box(LineConn::Ldap(lc)).map_err(|_| ErrorKind::OutOfMemory)?;
        lease.get().put_line(line);
        let over_tls = lease.get().carrier().over_tls();
        if over_tls {
            return self.ssl_connect(cx, lease, State::Ssl).map(|_| ());
        }
        let use_ssl = cx.easy().options().line.use_ssl;
        if use_ssl != UseSsl::None {
            let started = self.perform_starttls(cx, lease);
            if started.is_ok() || use_ssl != UseSsl::Try {
                return started;
            }
        }
        self.login(cx, lease)
    }

    /// Ask for the SASL mechanisms where one is asked for, else bind
    /// simply: even where version 3 needs no bind, to find a server
    /// without version 3.
    fn login<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<(), ErrorKind> {
        let (lc, _) = ldap_of(lease);
        if lc.sasl.preferred() != Mechs::NONE {
            return self.perform_mechs(cx, lease);
        }
        self.perform_bind(cx, lease, State::Bind)
    }

    /// Ask the server's root for the SASL mechanisms it supports
    /// (`oldap_perform_mechs`).
    fn perform_mechs<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<(), ErrorKind> {
        let oom = |_| ErrorKind::OutOfMemory;
        let mut attrs = Vec::new();
        let mut attr = Vec::new();
        attr.try_extend_from_slice(b"supportedSASLMechanisms")
            .map_err(oom)?;
        attrs.try_push(attr).map_err(oom)?;
        let mut filter = Vec::new();
        filter
            .try_extend_from_slice(b"(objectclass=*)")
            .map_err(oom)?;
        let search = Search {
            dn: Some(Vec::new()),
            scope: Scope::Base,
            filter: Some(filter),
            attrs: Some(attrs),
        };
        let (lc, carrier) = ldap_of(lease);
        let mut wire = ConnWire {
            cx: &mut *cx,
            carrier,
        };
        let id = lc
            .session
            .search(&mut wire, &search)
            .map_err(|code| map_error(code, ErrorKind::LoginDenied))?;
        lc.msgid = Some(id);
        Self::to(cx, lc, State::Mechs);
        Ok(())
    }

    /// Run `f` on the connection's SASL with what its steps read: the
    /// connection's credentials and the transfer's options.
    fn with_sasl<H: Host, R>(
        &self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        f: impl FnOnce(&mut Sasl, &mut sasl::Ctx<'_>) -> R,
    ) -> R {
        let cold = lease.conn().net_route().and_then(|r| r.cold.clone());
        let login = cold.as_deref().and_then(|c| c.login.as_ref());
        let (lc, _) = ldap_of(lease);
        let sasl_ir = cx.easy().options().line.sasl_ir;
        let delegation = cx.easy().options().login.delegation;
        let libraries = cx.easy().shared_libraries();
        let mut random = |out: &mut [u8]| libraries.random(out).map_err(|_| ());
        let mut say = |to: sasl::Say, args: core::fmt::Arguments<'_>| match to {
            sasl::Say::Debug => trace::debug_info(cx, args),
            sasl::Say::Info => trace::info(cx, args),
        };
        let mut sx = sasl::Ctx {
            creds: login.map(Credentials::secret),
            sasl_ir,
            host: self.base.peer.name(),
            port: self.base.peer.port(),
            random: &mut random,
            security: libraries.security,
            delegation,
            said: &mut say,
        };
        f(&mut lc.sasl, &mut sx)
    }

    /// Start the SASL bind with the best mechanism both ends allow, its
    /// initial response always sent (`oldap_perform_sasl`).
    fn perform_sasl<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<(), ErrorKind> {
        let progress = self.with_sasl(cx, lease, |sasl, sx| sasl.start(sx, true));
        let mut sends = false;
        let result = match progress {
            Err(e) => Err(sasl_failed(cx, e)),
            Ok(Progress::Sends(send)) => {
                sends = true;
                self.sasl_send(cx, lease, send)
            }
            Ok(Progress::Idle | Progress::Done) => Ok(()),
        };
        let (lc, _) = ldap_of(lease);
        Self::to(cx, lc, State::Sasl);
        result?;
        if !sends {
            self.with_sasl(cx, lease, |sasl, sx| sasl.blocked(sx));
            return Err(ErrorKind::LoginDenied);
        }
        Ok(())
    }

    /// Send what SASL asks, as a bind of its own (`oldap_perform_auth`,
    /// `oldap_continue_auth`, `oldap_cancel_auth`), and tell it whether it
    /// went.
    fn sasl_send<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        send: sasl::Send,
    ) -> Result<(), ErrorKind> {
        let (lc, carrier) = ldap_of(lease);
        let current = lc.sasl.current().unwrap_or_default();
        let (mech, cred) = match &send {
            sasl::Send::Auth { mech, initial } => (Mech::Sasl(mech.as_bytes()), initial.as_deref()),
            sasl::Send::Continue(resp) => (Mech::Sasl(current.as_bytes()), Some(&resp[..])),
            sasl::Send::Cancel => (Mech::Null, None),
        };
        let mut wire = ConnWire {
            cx: &mut *cx,
            carrier,
        };
        let sent = lc.session.bind(&mut wire, None, mech, cred);
        if let Ok(id) = sent {
            lc.msgid = Some(id);
        }
        let ok = sent.is_ok();
        self.with_sasl(cx, lease, |sasl, sx| sasl.sent(sx, ok));
        sent.map(|_| ())
            .map_err(|code| map_error(code, ErrorKind::LdapCannotBind))
    }

    /// Make TLS on, or move its handshake on, and once it is done read
    /// and write through it (`oldap_ssl_connect`): whether it is done.
    fn ssl_connect<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        state: State,
    ) -> Result<bool, ErrorKind> {
        let done = if lease.get().carrier().over_tls() && state == State::Ssl {
            // The connection's TLS is made before the protocol connects.
            true
        } else {
            let upgrade = lease.conn().net_route().and_then(|r| r.upgrade().cloned());
            let Some(identity) = upgrade else {
                return Err(ErrorKind::NotBuiltIn);
            };
            let in_place = crate::multi::state::tls::InPlace::of(lease.conn());
            let mut carrier = lease.get().carrier();
            // Timed, and said established, once done, as C's connect of the
            // chain does (`oldap_ssl_connect`, `Curl_conn_connect`).
            let shaken = crate::multi::state::tls::upgrade(
                &mut carrier,
                &identity,
                &self.base.peer,
                &in_place,
                crate::multi::state::tls::Blocks::No,
                cx,
            )?;
            shaken == crate::tls::Handshake::Done
        };
        let (lc, _) = ldap_of(lease);
        Self::to(cx, lc, state);
        // C puts its layer on each time; once is the same to the library.
        if done && !lc.session.uses_wire() && lc.session.use_wire().is_err() {
            return Err(ErrorKind::FailedInit);
        }
        Ok(done)
    }

    /// Send STARTTLS (`oldap_perform_starttls`).
    fn perform_starttls<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<(), ErrorKind> {
        let (lc, carrier) = ldap_of(lease);
        let mut wire = ConnWire {
            cx: &mut *cx,
            carrier,
        };
        let id = lc
            .session
            .start_tls(&mut wire)
            .map_err(|code| map_error(code, ErrorKind::UseSslFailed))?;
        lc.msgid = Some(id);
        Self::to(cx, lc, State::StartTls);
        Ok(())
    }

    /// Send a simple bind as the connection's user, with its password, or
    /// anonymously, and go to `state` (`oldap_perform_bind`).
    fn perform_bind<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        state: State,
    ) -> Result<(), ErrorKind> {
        let cold = lease.conn().net_route().and_then(|r| r.cold.clone());
        let login = cold.as_deref().and_then(|c| c.login.as_ref());
        // The transfer's credentials (`state.creds`) tell a failed bind.
        let has_login = login.is_some();
        let secret = login.map(Credentials::secret);
        let (dn, password) = match &secret {
            Some(s) => (Some(s.user()), s.password()),
            None => (None, &[][..]),
        };
        // C passes the password as the C string it is.
        let password = c_string(password);
        let (lc, carrier) = ldap_of(lease);
        let mut wire = ConnWire {
            cx: &mut *cx,
            carrier,
        };
        let sent = lc
            .session
            .bind(&mut wire, dn.map(c_string), Mech::Simple, Some(password));
        let id = sent.map_err(|code| {
            let otherwise = if has_login {
                ErrorKind::LoginDenied
            } else {
                ErrorKind::LdapCannotBind
            };
            map_error(code, otherwise)
        })?;
        lc.msgid = Some(id);
        Self::to(cx, lc, state);
        Ok(())
    }

    /// Move the set-up on as the connection lets it now
    /// (`oldap_connecting`): whether it is done.
    fn connecting<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<bool, ErrorKind> {
        let result = self.connecting_step(cx, lease);
        let (lc, carrier) = ldap_of(lease);
        if result.is_err()
            && let Some(id) = lc.msgid.take()
        {
            let mut wire = ConnWire {
                cx: &mut *cx,
                carrier,
            };
            lc.session.abandon(&mut wire, id);
        }
        result
    }

    fn connecting_step<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<bool, ErrorKind> {
        let library = self.library;
        let (lc, _) = ldap_of(lease);
        let state = lc.state;
        // The answer to the last message: its kind, its code, a bind's
        // credentials and an entry's mechanisms.
        let mut code = Code::SUCCESS;
        let mut kind = Kind::Other(0);
        let mut servercred = None;
        let mut offered = None;
        if state != State::Ssl && state != State::Tls {
            let (lc, carrier) = ldap_of(lease);
            let id = lc.msgid.unwrap_or(MsgId(0));
            let mut wire = ConnWire {
                cx: &mut *cx,
                carrier,
            };
            // What C reads of the message: its kind, its code, a bind's
            // answer, and the mechanisms an entry offers.
            let read = match lc.session.result(&mut wire, id) {
                Ok(None) => None,
                Ok(Some(mut msg)) => {
                    let kind = msg.kind();
                    let parsed = msg.result();
                    let bound = match state {
                        State::Bind | State::BindV2 | State::Sasl => Some(msg.bind_result()),
                        _ => None,
                    };
                    if state == State::Mechs && kind == Kind::SearchEntry {
                        offered = Some(mechanisms(&mut *msg));
                    }
                    Some(Ok((kind, parsed, bound)))
                }
                Err(rc) => Some(Err(rc)),
            };
            let (read_kind, parsed, bound) = match read {
                None => return Ok(false),
                Some(Ok(read)) => read,
                Some(Err(rc)) => {
                    lc.msgid = None;
                    return Err(trace::fail_with(
                        cx,
                        map_error(rc, ErrorKind::CouldntConnect),
                        &[b"LDAP local: connecting ldap_result ", library.describe(rc)],
                    ));
                }
            };
            kind = read_kind;
            if !matches!(kind, Kind::SearchEntry | Kind::SearchReference) {
                lc.msgid = None;
            }
            match parsed {
                Err(rc) => code = rc,
                Ok((c, _)) => {
                    code = c;
                    cx.report_mut()
                        .set_reply_code(u16::try_from(c.0).unwrap_or(u16::MAX));
                }
            }
            // A server without version 3 is bound to in version 2.
            let wired = lc.session.uses_wire();
            let use_ssl = cx.easy().options().line.use_ssl;
            if code == Code::PROTOCOL_ERROR
                && state != State::BindV2
                && (wired || use_ssl <= UseSsl::Try)
                && lc.sasl.preferred() == Mechs::NONE
            {
                lc.session.set_version(Version::V2);
                self.perform_bind(cx, lease, State::BindV2)?;
                return Ok(false);
            }
            // A simple bind's answer is read only where it succeeded.
            let bound = if state == State::Sasl {
                servercred = bound;
                None
            } else {
                bound.filter(|_| code == Code::SUCCESS)
            };
            if let Some(Err(rc)) = bound {
                return Err(trace::fail_with(
                    cx,
                    map_error(rc, ErrorKind::LdapCannotBind),
                    &[
                        b"LDAP local: bind ldap_parse_sasl_bind_result ",
                        library.describe(rc),
                    ],
                ));
            }
        }
        match state {
            State::Ssl => {
                if self.ssl_connect(cx, lease, State::Ssl)? {
                    self.login(cx, lease)?;
                }
            }
            State::StartTls => {
                let use_ssl = cx.easy().options().line.use_ssl;
                if code != Code::SUCCESS {
                    if use_ssl != UseSsl::Try {
                        return Err(map_error(code, ErrorKind::UseSslFailed));
                    }
                    self.login(cx, lease)?;
                } else {
                    self.tls(cx, lease, code)?;
                }
            }
            State::Tls => self.tls(cx, lease, code)?,
            State::Bind | State::BindV2 => {
                if code != Code::SUCCESS {
                    return Err(map_error(code, ErrorKind::LdapCannotBind));
                }
                let (lc, _) = ldap_of(lease);
                Self::to(cx, lc, State::Stop);
            }
            State::Mechs => self.mechs_answer(cx, lease, kind, code, offered)?,
            State::Sasl => {
                let servercred = servercred.expect("a SASL bind's answer is read");
                self.sasl_answer(cx, lease, code, servercred)?;
            }
            State::Stop => return Err(ErrorKind::CouldntConnect),
        }
        let (lc, _) = ldap_of(lease);
        Ok(lc.state == State::Stop)
    }

    /// The answer to the question for mechanisms: an entry's, which the
    /// server offers, then the search's end, after which SASL starts if
    /// there is anything to log in with (`oldap_state_mechs_resp`).
    fn mechs_answer<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        kind: Kind,
        code: Code,
        offered: Option<Result<Mechs, Code>>,
    ) -> Result<(), ErrorKind> {
        match kind {
            Kind::SearchEntry => {
                if code != Code::SUCCESS && code != Code::NO_RESULTS_RETURNED {
                    return Err(ErrorKind::LoginDenied);
                }
                let mechs = offered
                    .expect("an entry's mechanisms are read")
                    .map_err(|rc| map_error(rc, ErrorKind::BadContentEncoding))?;
                let (lc, _) = ldap_of(lease);
                lc.sasl.offers(mechs);
                Ok(())
            }
            Kind::SearchResult => match code {
                Code::SIZELIMIT_EXCEEDED | Code::SUCCESS | Code::NO_RESULTS_RETURNED => {
                    if code == Code::SIZELIMIT_EXCEEDED {
                        trace::info(cx, format_args!("Too many authentication mechanisms"));
                    }
                    if self.with_sasl(cx, lease, |sasl, sx| sasl.can_authenticate(sx)) {
                        self.perform_sasl(cx, lease)
                    } else {
                        Err(ErrorKind::LoginDenied)
                    }
                }
                _ => Err(map_error(code, ErrorKind::LoginDenied)),
            },
            _ => Ok(()),
        }
    }

    /// The answer to a SASL bind: the exchange taken on with the server's
    /// credentials (`oldap_state_sasl_resp`).
    fn sasl_answer<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        code: Code,
        servercred: Result<Option<Vec<u8>>, Code>,
    ) -> Result<(), ErrorKind> {
        let library = self.library;
        let servercred = match servercred {
            Ok(cred) => cred,
            Err(rc) => {
                return Err(trace::fail_with(
                    cx,
                    map_error(rc, ErrorKind::LoginDenied),
                    &[b"LDAP local: sasl ldap_parse_result ", library.describe(rc)],
                ));
            }
        };
        let (lc, _) = ldap_of(lease);
        // A challenge the server did not give (`oldap_get_message`).
        if lc.sasl.wants_challenge() && servercred.is_none() {
            return Err(ErrorKind::WeirdServerReply);
        }
        let said = match code {
            Code::SASL_BIND_IN_PROGRESS => sasl::Code::Continue,
            Code::SUCCESS => sasl::Code::Final,
            _ => sasl::Code::Other,
        };
        let message = servercred.unwrap_or_default();
        let progress = self.with_sasl(cx, lease, |sasl, sx| sasl.step(sx, said, &message));
        match progress.map_err(|e| sasl_failed(cx, e))? {
            Progress::Done => {
                let (lc, _) = ldap_of(lease);
                Self::to(cx, lc, State::Stop);
                Ok(())
            }
            Progress::Idle => Err(trace::fail(
                cx,
                ErrorKind::LoginDenied,
                format_args!("Authentication cancelled"),
            )),
            Progress::Sends(send) => self.sasl_send(cx, lease, send),
        }
    }

    /// STARTTLS's handshake, moved on; once done, bound if the connection
    /// has credentials, else set up, as version 3 needs no bind
    /// (`OLDAP_TLS`).
    fn tls<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        code: Code,
    ) -> Result<(), ErrorKind> {
        let done = self
            .ssl_connect(cx, lease, State::Tls)
            .map_err(|_| map_error(code, ErrorKind::UseSslFailed))?;
        if !done {
            return Ok(());
        }
        let (lc, _) = ldap_of(lease);
        if lc.sasl.preferred() != Mechs::NONE {
            return self.perform_mechs(cx, lease);
        }
        let logs_in = lease
            .conn()
            .net_route()
            .and_then(|r| r.cold.as_deref())
            .is_some_and(|c| c.login.is_some());
        if logs_in {
            return self.perform_bind(cx, lease, State::Bind);
        }
        let (lc, _) = ldap_of(lease);
        Self::to(cx, lc, State::Stop);
        Ok(())
    }

    /// Send the search (`oldap_do`).
    fn perform_search<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<(), ErrorKind> {
        trace::info_with(cx, &[b"LDAP local: ", &self.url_text]);
        let library = self.library;
        let (lc, carrier) = ldap_of(lease);
        let mut wire = ConnWire {
            cx: &mut *cx,
            carrier,
        };
        let sent = lc.session.search(&mut wire, &self.search);
        let id = sent.map_err(|rc| {
            trace::fail_with(
                cx,
                ErrorKind::LdapSearchFailed,
                &[b"LDAP local: ldap_search_ext ", library.describe(rc)],
            )
        })?;
        self.msgid = Some(id);
        self.entries = 0;
        self.receiving = true;
        Ok(())
    }

    /// Read the answer as the connection lets it now: an entry a step, as
    /// C's receive returns after each (`oldap_recv`).
    pub(crate) fn step<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<ProtoStep, ErrorKind> {
        self.base.pipeline.flush(cx)?;
        if !self.receiving {
            return Ok(ProtoStep::Done);
        }
        if cx.pause().recv_paused() {
            return Ok(ProtoStep::Blocked);
        }
        let read = self.read(cx, lease);
        if let Err(e) = read {
            let code = e.number();
            trace::debug_info(cx, format_args!("sendrecv_dl() -> {code}"));
        }
        read
    }

    fn read<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<ProtoStep, ErrorKind> {
        let library = self.library;
        let id = self.msgid.unwrap_or(MsgId(0));
        let (lc, carrier) = ldap_of(lease);
        let mut wire = ConnWire {
            cx: &mut *cx,
            carrier,
        };
        // What C reads of the message, and an entry written.
        let read = match lc.session.result(&mut wire, id) {
            Ok(None) => return Ok(ProtoStep::Blocked),
            Err(rc) => Err(rc),
            Ok(Some(mut msg)) => Ok(match msg.kind() {
                Kind::SearchResult => Read::Result(msg.result()),
                Kind::SearchEntry => {
                    self.entries += 1;
                    Read::Entry(self.write_entry(cx, &mut *msg))
                }
                _ => Read::Other,
            }),
        };
        let read = match read {
            Ok(read) => read,
            Err(rc) => {
                return Err(trace::fail_with(
                    cx,
                    ErrorKind::RecvError,
                    &[b"LDAP local: search ldap_result ", library.describe(rc)],
                ));
            }
        };
        match read {
            Read::Result(parsed) => {
                self.msgid = None;
                let (code, info) = match parsed {
                    Ok(read) => read,
                    Err(rc) => {
                        return Err(trace::fail_with(
                            cx,
                            ErrorKind::LdapSearchFailed,
                            &[
                                b"LDAP local: search ldap_parse_result ",
                                library.describe(rc),
                            ],
                        ));
                    }
                };
                cx.report_mut()
                    .set_reply_code(u16::try_from(code.0).unwrap_or(u16::MAX));
                match code {
                    Code::SIZELIMIT_EXCEEDED => {
                        let n = self.entries;
                        trace::info(cx, format_args!("There are more than {n} entries"));
                    }
                    Code::SUCCESS => {}
                    _ => {
                        return Err(trace::fail_with(
                            cx,
                            ErrorKind::LdapSearchFailed,
                            &[
                                b"LDAP remote: search failed ",
                                library.describe(code),
                                b" ",
                                info.as_deref().unwrap_or_default(),
                            ],
                        ));
                    }
                }
                self.end(cx)
            }
            Read::Entry(wrote) => {
                wrote?;
                // After each entry, the socket is waited on, unless bytes
                // wait where a poll cannot see them (`data_pending`).
                if lease.get().data_pending() {
                    crate::multi::mstate::trace(
                        cx,
                        format_args!("sendrecv_dl() no EAGAIN/pending data, mark as dirty"),
                    );
                    Ok(ProtoStep::AtReadLimit)
                } else {
                    Ok(ProtoStep::Blocked)
                }
            }
            // Any other message ends the answer, as nothing it read.
            Read::Other => self.end(cx),
        }
    }

    /// The answer is all read (`sendrecv_dl`'s end).
    fn end<H: Host>(&mut self, cx: &mut StepCx<'_, H>) -> Result<ProtoStep, ErrorKind> {
        trace::debug_info(cx, format_args!("sendrecv_dl: we are done"));
        let ended = self.base.pipeline.end(cx);
        deliver::write_resp(cx, 0, true, ended);
        self.receiving = false;
        ended.map(|()| ProtoStep::Done)
    }

    /// Write an entry as LDIF through the pipeline, a write for each of
    /// C's (`client_write`'s parts).
    fn write_entry<H: Host>(&mut self, cx: &mut StepCx<'_, H>, msg: &mut dyn Message) -> Wrote {
        let pipeline = &mut self.base.pipeline;
        let wrote = ldif(msg, &mut |bytes| pipeline.body(cx, bytes));
        match wrote {
            Ok(()) => Ok(()),
            Err(Ldif::Write(kind)) => Err(kind),
            Err(Ldif::Name) => Err(ErrorKind::RecvError),
            Err(Ldif::OutOfMemory) => Err(ErrorKind::OutOfMemory),
            Err(Ldif::IllegalType) => Err(trace::fail(
                cx,
                ErrorKind::WeirdServerReply,
                format_args!("LDAP local: attribute type contains illegal bytes"),
            )),
        }
    }

    /// The request is over (`oldap_done`): a search still under way is
    /// given up.
    pub(crate) fn done<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        result: Result<(), ErrorKind>,
    ) -> Finish {
        self.receiving = false;
        if let Some(id) = self.msgid.take()
            && lease.conn().keeps_line()
        {
            let (lc, carrier) = ldap_of(lease);
            let mut wire = ConnWire {
                cx: &mut *cx,
                carrier,
            };
            lc.session.abandon(&mut wire, id);
        }
        Finish::Done(result)
    }
}

/// The bytes of `s` up to any NUL, as C's string would stop there.
fn c_string(s: &[u8]) -> &[u8] {
    s.iter().position(|&b| b == 0).map_or(s, |n| &s[..n])
}

/// Read the login options (`oldap_parse_login_options`): `AUTH=` and a
/// SASL mechanism, `*` for any; any other, or a mechanism unknown, is a
/// syntax error.
pub(crate) fn parse_login_options(sasl: &mut Sasl, mut options: &[u8]) -> Result<(), ErrorKind> {
    while !options.is_empty() {
        let key = options;
        let eq = options
            .iter()
            .position(|&b| b == b'=')
            .unwrap_or(options.len());
        let end = options[eq..]
            .iter()
            .position(|&b| b == b';')
            .map_or(options.len(), |p| eq + p);
        let value = &options[(eq + 1).min(end)..end];
        if !(key.len() >= 5 && key[..5].eq_ignore_ascii_case(b"AUTH=")) || !sasl.url_auth(value) {
            return Err(ErrorKind::SetoptOptionSyntax);
        }
        options = &options[end..];
        if let [b';', rest @ ..] = options {
            options = rest;
        }
    }
    Ok(())
}

/// The SASL mechanisms an entry of the server's root offers, each value
/// one only if it is one's name whole; the library's code if the entry
/// could not be read.
fn mechanisms(msg: &mut dyn Message) -> Result<Mechs, Code> {
    msg.dn()?;
    let mut offered = Mechs::NONE;
    while let Ok(Some(attr)) = msg.next_attribute() {
        for value in attr.values.into_iter().flatten() {
            if let Some((mech, n)) = sasl::decode_mech(value)
                && n == value.len()
            {
                offered = offered.or(mech);
            }
        }
    }
    Ok(offered)
}

/// What a failed SASL step comes to.
fn sasl_failed<H: Host>(cx: &mut StepCx<'_, H>, e: SaslError) -> ErrorKind {
    match e {
        SaslError::Denied => ErrorKind::LoginDenied,
        SaslError::OutOfMemory => ErrorKind::OutOfMemory,
        SaslError::Random => {
            trace::fail(cx, ErrorKind::FailedInit, format_args!("no random bytes"))
        }
        SaslError::NoAuthInfo => trace::fail(
            cx,
            ErrorKind::AuthError,
            format_args!("SSPI: could not get auth info"),
        ),
        SaslError::AuthError => ErrorKind::AuthError,
    }
}

impl super::Phases for Request {
    /// Make the session and start its set-up, then move it on
    /// (`oldap_connect`, `oldap_connecting`).
    fn connect<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<Connect, ErrorKind> {
        if !lease.conn().keeps_line() {
            self.connect_first(cx, lease)?;
            return Ok(Connect::Waiting);
        }
        Ok(if self.connecting(cx, lease)? {
            Connect::Done
        } else {
            Connect::Waiting
        })
    }

    fn make<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        asked: DoPhase,
    ) -> Result<DoStep, ErrorKind> {
        match asked {
            DoPhase::Do => {
                self.perform_search(cx, lease)?;
                Ok(DoStep::Did)
            }
            DoPhase::Doing | DoPhase::More => unreachable!("LDAP's DO is done at once"),
        }
    }

    fn waits(&self, phase: Waiting, _: Option<&crate::conn::line::LineConn>) -> Events {
        phase.c_default()
    }
}

pub(crate) mod local;

#[cfg(test)]
mod tests;
