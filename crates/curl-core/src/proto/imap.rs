//! IMAP (`lib/imap.c`): a connection that logs in once, by SASL or a
//! clear-text `LOGIN`, after `STARTTLS` if TLS is asked for and the
//! connection is not over it already, and keeps the mailbox it selected;
//! a request per transfer, each command tagged with the connection's
//! letter and a count: a `LIST`, a `SELECT` then a `FETCH` or a `SEARCH`,
//! an `APPEND` of what the transfer uploads, or the application's own.
//! A `FETCH`'s body is the literal its answer announces, `{N}` bytes,
//! read to its size and no further; the tagged answer after it, or after
//! an `APPEND`'s body, is read in DONE, as C's `imap_done` reads it.

use std::num::NonZeroU32;

use curl_alloc::{TryArc, TryVec as _};

use super::pingpong::Pingpong;
use super::pingpong::drive::{self, Read};
use super::pingpong::imap::{Continuations, Imap, ImapReply, Tag, Untagged, literal};
use super::xfer::Receive;
use super::{Connect, DoPhase, DoStep, Finish, ProtoStep, Waiting};
use crate::auth::creds::{CredentialGate, Credentials, Takes};
use crate::auth::sasl::{self, Code, Mechs, Progress, Sasl, SaslError};
use crate::conn::io::Events;
use crate::conn::line::LineConn;
use crate::conn::mux::Carrier;
use crate::conn::{ConnLease, ConnNumber, Peer, RouteCold, Scheme};
use crate::deliver::{Expect, Pause, Pipeline, Reach};
use crate::error::{ErrorKind, url_error};
use crate::idn::Idn;
use crate::multi::Host;
use crate::multi::state::StepCx;
use crate::options::{Method, UploadFlags, UploadSource, UseSsl};
use crate::time::Instant;
use crate::trace;
use crate::upload::chain::Body;
use crate::upload::{self, Upload, sending::Sending};
use crate::url::{GetOptions, Part, Url, decode_but_control};

/// IMAP's SASL (`saslimap`): an initial response of any length.
static SASL: sasl::Params = sasl::Params {
    service: "imap",
    max_ir: 0,
    default: Mechs::DEFAULT,
    base64: true,
};

/// The ways a server lets a user log in (`IMAP_TYPE_*`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AuthTypes(u8);

impl AuthTypes {
    const NONE: AuthTypes = AuthTypes(0);
    const CLEARTEXT: AuthTypes = AuthTypes(1 << 0);
    const SASL: AuthTypes = AuthTypes(1 << 1);
    const ANY: AuthTypes = AuthTypes(0b11);

    fn has(self, t: AuthTypes) -> bool {
        self.0 & t.0 != 0
    }
}

/// Where the connection's back and forth is (`imapstate`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Stop,
    ServerGreet,
    Capability,
    StartTls,
    UpgradeTls,
    Authenticate,
    Login,
    List,
    Select,
    Fetch,
    FetchFinal,
    Append,
    AppendFinal,
    Search,
}

impl State {
    fn name(self) -> &'static str {
        match self {
            State::Stop => "STOP",
            State::ServerGreet => "SERVERGREET",
            State::Capability => "CAPABILITY",
            State::StartTls => "STARTTLS",
            State::UpgradeTls => "UPGRADETLS",
            State::Authenticate => "AUTHENTICATE",
            State::Login => "LOGIN",
            State::List => "LIST",
            State::Select => "SELECT",
            State::Fetch => "FETCH",
            State::FetchFinal => "FETCH_FINAL",
            State::Append => "APPEND",
            State::AppendFinal => "APPEND_FINAL",
            State::Search => "SEARCH",
        }
    }
}

/// What IMAP keeps on its connection (`struct imap_conn`).
#[derive(Debug)]
pub(crate) struct ImapConn {
    pp: Pingpong,
    state: State,
    sasl: Sasl,
    /// The connection's number, whose letter its tags start with.
    number: ConnNumber,
    /// The tag of the command whose answer is waited for (`resptag`).
    tag: Tag,
    /// The last command's count (`cmdid`), wrapping as C's byte does.
    cmdid: u8,
    /// The mailbox selected last, and the UIDVALIDITY its `SELECT`
    /// answered with (`mailbox`, `mb_uidvalidity`).
    mailbox: Option<Vec<u8>>,
    uidvalidity: Option<u32>,
    /// How the URL's options prefer to log in (`preftype`).
    preferred: AuthTypes,
    /// The greeting said the connection is logged in (`preauth`).
    preauth: bool,
    /// The server offers `STARTTLS` (`tls_supported`).
    tls_offered: bool,
    /// The server has disabled `LOGIN` (`login_disabled`).
    login_disabled: bool,
    /// The server takes an initial response with `AUTHENTICATE`
    /// (`ir_supported`).
    ir_offered: bool,
    /// The last transfer on it set up nothing to exchange after its
    /// request (`recv_idx` and `send_idx` both -1, which
    /// `Curl_xfer_setup_nop` leaves on the connection): the next one that
    /// sets up nothing either goes from DID to DONE.
    no_socket: bool,
    /// What of its route few routes have, the credentials it logs in
    /// with among it (`conn->creds`): the route owns them.
    cold: Option<TryArc<RouteCold>>,
}

/// The credentials a connection logs in with, as its route holds them.
fn login_of(cold: &Option<TryArc<RouteCold>>) -> Option<&Credentials> {
    cold.as_deref().and_then(|c| c.login.as_ref())
}

impl ImapConn {
    /// The tag of the next command, now the one answers are waited for
    /// with (`imap_sendf`).
    fn next_tag(&mut self) -> Tag {
        self.cmdid = self.cmdid.wrapping_add(1);
        self.tag = Tag::command(self.number, self.cmdid);
        self.tag
    }

    /// Say `LOGOUT`, as the connection shuts down, unless it is `dead`
    /// or a command waits half sent (`imap_disconnect`): sent as the
    /// connection takes it now, its answer not waited on.
    pub(crate) fn goodbye(
        &mut self,
        cx: &mut dyn crate::conn::layer::LayerCx,
        mut below: Carrier<'_>,
        dead: bool,
    ) {
        if dead || self.pp.needs_flush() {
            return;
        }
        let tag = self.next_tag();
        let mut line = [0u8; 4 + 1 + 6 + 2];
        let t = tag.bytes();
        line[..t.len()].copy_from_slice(t);
        let rest = b" LOGOUT\r\n";
        line[t.len()..t.len() + rest.len()].copy_from_slice(rest);
        // What does not go now is not said.
        let _sent = below.send(cx, &line[..t.len() + rest.len()]);
    }
}

/// What the URL's path and query, and the application's command, ask
/// for (`struct IMAP`'s strings), each decoded.
#[derive(Debug, Default)]
struct Asked {
    mailbox: Option<Vec<u8>>,
    uidvalidity: Option<u32>,
    uid: Option<Vec<u8>>,
    mindex: Option<Vec<u8>>,
    section: Option<Vec<u8>>,
    partial: Option<Vec<u8>>,
    query: Option<Vec<u8>>,
    /// The application's command's first word, and the rest from the
    /// space before it (`custom`, `custom_params`).
    custom: Option<Vec<u8>>,
    custom_params: Option<Vec<u8>>,
}

/// The answer DONE reads, after the body (`imap_done`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Final {
    /// None: nothing was fetched or appended.
    None,
    /// A `FETCH`'s tagged answer.
    Fetch,
    /// An `APPEND`'s, once an empty line ends the command.
    Append,
}

/// An IMAP transfer (`struct IMAP`, and what C's request keeps of it).
#[derive(Debug)]
pub(crate) struct Request {
    pipeline: Pipeline,
    peer: Peer,
    /// The transfer's credentials, until its route takes them.
    credentials: Option<Credentials>,
    /// The URL's path, encoded, and its query, decoded: read in DO.
    path: Vec<u8>,
    query: Option<Vec<u8>>,
    /// The URL's login options, decoded (`state.up.options`).
    url_options: Option<Vec<u8>>,
    /// What DO read of the URL and the command.
    asked: Box<Asked>,
    /// No body is wanted (`req.no_body`, `PPTRANSFER_INFO`).
    no_body: bool,
    /// The request was made and its answer has no transfer after it
    /// (`Curl_xfer_setup_nop`).
    nothing_after: bool,
    /// A literal is still being read, to this size of body
    /// (`KEEP_RECV`, `req.size`).
    receive: Receive,
    /// The `APPEND`'s body, while it goes (`KEEP_SEND`).
    sending: Option<Box<Sending>>,
    /// The answer DONE reads, and where its blocking drive's round is.
    last: Final,
    round: drive::Blocking,
    /// The `APPEND`'s body is all sent (`upload_done`): the server's
    /// lines from here start the response's time.
    upload_done: bool,
    /// When DONE, as it awaits its answer, looks again.
    due: Option<Instant>,
    /// What TLS is made with and said as as the connection is upgraded.
    in_place: crate::multi::state::tls::InPlace,
    /// What the back and forth waits for on the connection.
    wants: Events,
    /// The answers' bytes (`req.headerbytecount`).
    header_bytes: u64,
}

/// The ways a step of the back and forth can fail.
type Step = Result<(), ErrorKind>;

impl Request {
    /// A transfer of `url`, `imaps` if `secured`: its peer, the
    /// credentials its URL gives and the application's where `before`
    /// lets them go, a `.netrc`'s if asked for (`imap_setup_connection`,
    /// `Curl_auth_allowed_to_host`).
    pub(crate) fn new<H: Host>(
        url: &Url,
        secured: bool,
        before: super::Before<'_>,
        cx: &mut StepCx<'_, H>,
    ) -> Result<Request, ErrorKind> {
        let host = url.get(Part::Host, GetOptions::NONE).map_err(url_error)?;
        let port = url
            .get(
                Part::Port,
                GetOptions {
                    default_port: true,
                    ..GetOptions::NONE
                },
            )
            .map_err(url_error)?;
        let port = std::str::from_utf8(&port)
            .ok()
            .and_then(|p| p.parse().ok())
            .ok_or(ErrorKind::UrlMalformat)?;
        let name: &[u8] = if secured { b"imaps" } else { b"imap" };
        let scheme = Scheme::named(name).expect("libcurl knows IMAP");
        let scope = cx.easy().options().address_scope;
        let idn = cx.easy().libraries().idn;
        let peer = super::url_peer((scheme, host, port), url, scope, idn)?;
        let gate = match before.first {
            None => CredentialGate::FIRST,
            Some(first) => {
                let other_hosts = cx.easy().options().http.unrestricted_auth;
                CredentialGate::new(first, &peer, other_hosts)
            }
        };
        let takes = Takes::of(Some(scheme));
        let credentials = super::request_credentials(cx, gate.trusted(), url, takes)?;
        let credentials = super::with_netrc(credentials, peer.name(), takes, cx)?;
        let encoded = GetOptions {
            url_encode: true,
            ..GetOptions::NONE
        };
        let path = url.get(Part::Path, encoded).map_err(url_error)?;
        let decoded = GetOptions {
            url_decode: true,
            ..GetOptions::NONE
        };
        let query = match url.get(Part::Query, decoded) {
            Ok(query) => Some(query),
            Err(crate::error::UrlErrorKind::NoQuery) => None,
            Err(crate::error::UrlErrorKind::OutOfMemory) => return Err(ErrorKind::OutOfMemory),
            Err(_) => None,
        };
        let url_options = match url.get(Part::Options, decoded) {
            Ok(options) => Some(options),
            Err(crate::error::UrlErrorKind::NoOptions) => None,
            Err(e) => return Err(url_error(e)),
        };
        Ok(Request {
            pipeline: Pipeline::new(Reach::Network),
            peer,
            credentials,
            path,
            query,
            url_options,
            asked: Box::default(),
            no_body: cx.easy().options().method == Method::Head,
            nothing_after: false,
            receive: Receive::default(),
            sending: None,
            last: Final::None,
            round: drive::Blocking::default(),
            upload_done: false,
            due: None,
            in_place: Default::default(),
            wants: Events::IN,
            header_bytes: 0,
        })
    }

    /// The peer it connects to.
    pub(crate) fn network(
        &self,
        url: &Url,
        scope: Option<NonZeroU32>,
        idn: Option<&dyn Idn>,
    ) -> Result<Peer, ErrorKind> {
        let mut host = Vec::new();
        host.try_extend_from_slice(self.peer.shown())
            .map_err(|_| ErrorKind::OutOfMemory)?;
        let (scheme, port) = (self.peer.scheme(), self.peer.port());
        super::url_peer((scheme, host, port), url, scope, idn)
    }

    /// Its scheme.
    pub(crate) fn scheme(&self) -> Scheme {
        self.peer.scheme()
    }

    /// Its credentials, which its route takes.
    pub(crate) fn take_login(&mut self) -> Option<Credentials> {
        self.credentials.take()
    }

    /// It is over TLS from the start: its scheme is `imaps`.
    pub(crate) fn secured(&self) -> bool {
        self.peer.scheme().over_tls()
    }

    pub(crate) fn pipeline_mut(&mut self) -> &mut Pipeline {
        &mut self.pipeline
    }

    pub(crate) fn holds_output(&self) -> bool {
        self.pipeline.holds_output()
    }

    /// Whether nothing came back for the request, which has not run to
    /// its end: one that may be made again on a fresh connection, its
    /// reused one having died (`Curl_retry_request` for a scheme outside
    /// HTTP's, `req.bytecount + req.headerbytecount`).
    pub(crate) fn received_nothing(&self) -> bool {
        self.header_bytes == 0 && self.pipeline.bytecount() == 0 && !self.no_body
    }

    /// When DONE, as it awaits its answer, looks again: its poll's end.
    pub(crate) fn due(&self) -> Option<Instant> {
        self.due
    }

    /// Whether the request, once made, has anything more to do over the
    /// connection before DONE: a literal to read or a body to send.
    pub(crate) fn exchanges(&self) -> bool {
        !self.nothing_after
    }

    /// Whether the `APPEND`'s body has more to send.
    pub(crate) fn sending(&self) -> bool {
        self.sending.is_some()
    }

    /// What the exchange waits for on the connection's socket.
    pub(crate) fn interest(&self, pause: Pause) -> Events {
        if self.receive.is_receiving() {
            if pause.recv_paused() {
                Events::NONE
            } else {
                Events::IN
            }
        } else if self.sending.is_some() {
            if pause.send_paused() {
                Events::NONE
            } else {
                Events::OUT
            }
        } else {
            Events::NONE
        }
    }

    /// The transfer is over (`imap_done`): one that failed or was cut
    /// short leaves its connection to close; one that fetched or appended
    /// reads the answer after its body, the empty line that ends an
    /// `APPEND` sent first, and fails as it says. `exchanged` is C's
    /// `req.done`, which the progress checked meanwhile reads.
    pub(crate) fn done<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        result: Result<(), ErrorKind>,
        premature: bool,
        exchanged: bool,
    ) -> Finish {
        if result.is_err() || premature {
            crate::multi::mstate::trace(cx, format_args!("IMAP done, not finalizing transfer"));
            lease.get().mark_close();
            return Finish::Done(result);
        }
        let (pc, mut carrier) = imap_of(lease);
        match self.last {
            Final::None => return Finish::Done(Ok(())),
            Final::Fetch => set_state(cx, pc, State::FetchFinal),
            Final::Append => {
                if let Err(e) = drive::send(cx, &mut pc.pp, &mut carrier, None, &[]) {
                    return Finish::Done(Err(e));
                }
                set_state(cx, pc, State::AppendFinal);
            }
        }
        self.finishing(cx, lease, exchanged)
    }

    /// Read on the answer `done` awaits (`imap_block_statemach`), as far
    /// as the connection lets it now.
    pub(crate) fn finishing<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        exchanged: bool,
    ) -> Finish {
        match self.run_done(cx, lease, exchanged) {
            Ok(true) => Finish::Done(Ok(())),
            Ok(false) => Finish::Waiting,
            Err(e) => Finish::Done(Err(e)),
        }
    }

    /// The exchange after the request (`Curl_sendrecv`): the literal read
    /// to its size, or the body sent.
    pub(crate) fn step<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<ProtoStep, ErrorKind> {
        self.pipeline.flush(cx)?;
        if self.receive.is_receiving() {
            let read = self.receive.read(cx, lease, &mut self.pipeline);
            if read? != ProtoStep::Done {
                return read;
            }
        }
        if self.sending.is_some() && self.send_body(cx, lease)? != ProtoStep::Done {
            return Ok(ProtoStep::Blocked);
        }
        if self.pipeline.holds_output() {
            return Ok(ProtoStep::Blocked);
        }
        Ok(ProtoStep::Done)
    }

    /// Send the `APPEND`'s body on, as the connection takes it: `Done`
    /// once it is all sent.
    fn send_body<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<ProtoStep, ErrorKind> {
        let Some(sending) = self.sending.as_deref_mut() else {
            return Ok(ProtoStep::Done);
        };
        let step = sending.send(cx, lease)?;
        if step == ProtoStep::Done {
            self.sending = None;
            self.upload_done = true;
        }
        Ok(step)
    }

    /// The connection's IMAP state, set up the first time
    /// (`imap_connect`): the URL's or the application's login options
    /// read, the greeting awaited, tagged `*`.
    fn conn_state<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        url_options: Option<&[u8]>,
    ) -> Step {
        let http = cx.easy().options().http.auth.0;
        let mut pc = ImapConn {
            pp: Pingpong::new(cx.now()),
            state: State::Stop,
            sasl: Sasl::new(&SASL, http),
            number: lease.conn().number(),
            tag: Tag::GREETING,
            cmdid: 0,
            mailbox: None,
            uidvalidity: None,
            preferred: AuthTypes::ANY,
            preauth: false,
            tls_offered: false,
            login_disabled: false,
            ir_offered: false,
            no_socket: false,
            cold: lease.conn().net_route().and_then(|r| r.cold.clone()),
        };
        let options = match cx.easy().options().line.login_options.as_deref() {
            Some(given) => Some(given),
            None => url_options,
        };
        parse_options(&mut pc, options.unwrap_or_default())?;
        let line = curl_alloc::try_box(LineConn::Imap(pc)).map_err(|_| ErrorKind::OutOfMemory)?;
        lease.get().put_line(line);
        let (pc, _) = imap_of(lease);
        set_state(cx, pc, State::ServerGreet);
        Ok(())
    }

    /// Run the back and forth as far as the connection lets it now
    /// (`imap_multi_statemach`): whether it stopped, its phase's work
    /// done.
    fn run<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<bool, ErrorKind> {
        let limit = cx.easy().options().line.server_response;
        self.in_place = crate::multi::state::tls::InPlace::of(lease.conn());
        let (pc, mut carrier) = imap_of(lease);
        if drive::runs(cx, &pc.pp, &mut carrier, limit)? {
            self.machine(cx, pc, &mut carrier)?;
        }
        self.wants = drive::waits(&pc.pp);
        Ok(pc.state == State::Stop)
    }

    /// Run the back and forth on in DONE, as C's blocking drive runs it
    /// (`imap_block_statemach`) but without waiting: whether it stopped.
    fn run_done<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        exchanged: bool,
    ) -> Result<bool, ErrorKind> {
        let limit = cx.easy().options().line.server_response;
        let (pc, mut carrier) = imap_of(lease);
        loop {
            let round = &mut self.round;
            let (runs, due) = drive::runs_done(cx, &pc.pp, &mut carrier, limit, exchanged, round)?;
            self.due = Some(due);
            if runs {
                self.machine(cx, pc, &mut carrier)?;
            }
            self.wants = drive::waits(&pc.pp);
            if pc.state == State::Stop {
                self.due = None;
                return Ok(true);
            }
            // C loops at once on what it holds; what the socket brings
            // wakes the transfer.
            if !runs || !drive::holds(&pc.pp, &mut carrier) {
                return Ok(false);
            }
        }
    }

    /// The state machine (`imap_pp_statemachine`).
    fn machine<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut ImapConn,
        carrier: &mut Carrier<'_>,
    ) -> Step {
        if pc.state == State::UpgradeTls {
            // All bytes are TLS's until its handshake is done
            // (`imap_perform_upgrade_tls`).
            let Some(identity) = pc.cold.as_ref().and_then(|c| c.upgrade.clone()) else {
                return Err(ErrorKind::NotBuiltIn);
            };
            let shaken = crate::multi::state::tls::upgrade(
                carrier,
                &identity,
                &self.peer,
                &self.in_place,
                crate::multi::state::tls::Blocks::No,
                cx,
            );
            let (code, done) = match &shaken {
                Ok(crate::tls::Handshake::Done) => (0, 1),
                Ok(crate::tls::Handshake::Waiting) => (0, 0),
                Err(kind) => (kind.number(), 0),
            };
            trace::debug_info(
                cx,
                format_args!("imap_perform_upgrade_tls, connect -> {code}, {done}"),
            );
            match shaken? {
                crate::tls::Handshake::Waiting => return Ok(()),
                // `CAPABILITY` again, under TLS.
                crate::tls::Handshake::Done => capability(cx, pc, carrier)?,
            }
        }
        if pc.pp.needs_flush() {
            return drive::flush(cx, &mut pc.pp, carrier);
        }
        loop {
            let custom = self.asked.custom.as_deref();
            let untagged = match pc.state {
                State::Capability => Untagged::Named(b"CAPABILITY"),
                State::List => match custom {
                    Some(custom) => Untagged::Custom(custom),
                    None => Untagged::Named(b"LIST"),
                },
                State::Select => Untagged::Any,
                State::Fetch => Untagged::Named(b"FETCH"),
                State::Search => Untagged::Named(b"SEARCH"),
                _ => Untagged::Ignored,
            };
            let continuations = match pc.state {
                _ if custom.is_some() => Continuations::Ignored,
                State::Authenticate | State::Append => Continuations::Expected,
                _ => Continuations::Unexpected,
            };
            let ends = Imap {
                tag: pc.tag,
                untagged,
                continuations,
            };
            let read = drive::read(
                cx,
                &mut pc.pp,
                carrier,
                &ends,
                &mut self.pipeline,
                &mut self.header_bytes,
                // The server's lines start the response's time once an
                // `APPEND`'s body is all sent (`upload_done`); before, a
                // command is sent beside a request that sends nothing.
                self.upload_done,
            )?;
            let Read::Reply(code, _) = read else {
                return Ok(());
            };
            match pc.state {
                _ if code == ImapReply::UnexpectedContinuation => {
                    return Err(trace::fail(
                        cx,
                        ErrorKind::WeirdServerReply,
                        format_args!("Unexpected continuation response"),
                    ));
                }
                State::ServerGreet => self.greeting(cx, pc, carrier, code)?,
                State::Capability => self.capability_resp(cx, pc, carrier, code)?,
                State::StartTls => {
                    self.starttls(cx, pc, carrier, code)?;
                    if pc.state == State::UpgradeTls {
                        return self.machine(cx, pc, carrier);
                    }
                }
                State::Authenticate => self.auth(cx, pc, carrier, code)?,
                State::Login => {
                    if code != ImapReply::Ok {
                        return Err(trace::fail(
                            cx,
                            ErrorKind::LoginDenied,
                            format_args!("Access denied. {}", code_number(code)),
                        ));
                    }
                    set_state(cx, pc, State::Stop);
                }
                State::List | State::Search => self.listsearch(cx, pc, code)?,
                State::Select => self.select_resp(cx, pc, carrier, code)?,
                State::Fetch => self.fetch_resp(cx, pc, code)?,
                State::FetchFinal => {
                    if code != ImapReply::Ok {
                        return Err(ErrorKind::WeirdServerReply);
                    }
                    set_state(cx, pc, State::Stop);
                }
                State::Append => self.append_resp(cx, pc, code)?,
                State::AppendFinal => {
                    if code != ImapReply::Ok {
                        return Err(ErrorKind::UploadFailed);
                    }
                    set_state(cx, pc, State::Stop);
                }
                State::Stop | State::UpgradeTls => set_state(cx, pc, State::Stop),
            }
            if pc.state == State::Stop || !pc.pp.more_data() {
                return Ok(());
            }
        }
    }

    /// The greeting (`imap_state_servergreet_resp`): `PREAUTH` noted,
    /// then `CAPABILITY`.
    fn greeting<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut ImapConn,
        carrier: &mut Carrier<'_>,
        code: ImapReply,
    ) -> Step {
        if code == ImapReply::Preauth {
            pc.preauth = true;
            trace::info(
                cx,
                format_args!("PREAUTH connection, already authenticated"),
            );
        } else if code != ImapReply::Ok {
            return Err(trace::fail(
                cx,
                ErrorKind::WeirdServerReply,
                format_args!("Got unexpected imap-server response"),
            ));
        }
        capability(cx, pc, carrier)
    }

    /// A line of the answer to `CAPABILITY`, or its end
    /// (`imap_state_capability_resp`): on to `STARTTLS` or the login.
    fn capability_resp<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut ImapConn,
        carrier: &mut Carrier<'_>,
        code: ImapReply,
    ) -> Step {
        if code == ImapReply::Untagged {
            // C reads on from the line to the end of all it holds, the
            // lines after it among it.
            let held = pc.pp.held();
            let mut rest = held.get(2..).unwrap_or_default();
            loop {
                while let [b' ' | b'\t' | b'\r' | b'\n', more @ ..] = rest {
                    rest = more;
                }
                if rest.is_empty() || rest[0] == 0 {
                    break;
                }
                let n = rest
                    .iter()
                    .position(|&b| matches!(b, 0 | b' ' | b'\t' | b'\r' | b'\n'))
                    .unwrap_or(rest.len());
                let word = &rest[..n];
                if word.eq_ignore_ascii_case(b"STARTTLS") {
                    pc.tls_offered = true;
                } else if word.eq_ignore_ascii_case(b"LOGINDISABLED") {
                    pc.login_disabled = true;
                } else if word.eq_ignore_ascii_case(b"SASL-IR") {
                    pc.ir_offered = true;
                } else if n > 5
                    && word[..5].eq_ignore_ascii_case(b"AUTH=")
                    && let Some((mech, len)) = sasl::decode_mech(&word[5..])
                    && len == n - 5
                {
                    pc.sasl.offers(mech);
                }
                rest = &rest[n..];
            }
            return Ok(());
        }
        let use_ssl = cx.easy().options().line.use_ssl;
        if use_ssl == UseSsl::None || carrier.over_tls() {
            return self.authenticate(cx, pc, carrier);
        }
        // PREAUTH is not compatible with STARTTLS.
        if code == ImapReply::Ok && pc.tls_offered && !pc.preauth {
            let tag = pc.next_tag();
            drive::send(cx, &mut pc.pp, carrier, Some(tag.bytes()), &[b"STARTTLS"])?;
            set_state(cx, pc, State::StartTls);
            Ok(())
        } else if use_ssl <= UseSsl::Try {
            self.authenticate(cx, pc, carrier)
        } else {
            Err(trace::fail(
                cx,
                ErrorKind::UseSslFailed,
                format_args!("STARTTLS not available."),
            ))
        }
    }

    /// The answer to `STARTTLS` (`imap_state_starttls_resp`): bytes after
    /// it were not sent under TLS and are refused, before what it says.
    fn starttls<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut ImapConn,
        carrier: &mut Carrier<'_>,
        code: ImapReply,
    ) -> Step {
        if pc.pp.after_reply().is_some_and(|after| !after.is_empty()) {
            return Err(ErrorKind::WeirdServerReply);
        }
        if code != ImapReply::Ok {
            if cx.easy().options().line.use_ssl != UseSsl::Try {
                return Err(trace::fail(
                    cx,
                    ErrorKind::UseSslFailed,
                    format_args!("STARTTLS denied"),
                ));
            }
            return self.authenticate(cx, pc, carrier);
        }
        set_state(cx, pc, State::UpgradeTls);
        Ok(())
    }

    /// The SASL context of a step over `pc`'s credentials.
    fn sasl_step<H: Host, R>(
        &self,
        cx: &mut StepCx<'_, H>,
        pc: &mut ImapConn,
        f: impl FnOnce(&mut Sasl, &mut sasl::Ctx<'_>) -> R,
    ) -> R {
        let sasl_ir = cx.easy().options().line.sasl_ir;
        let libraries = cx.easy().shared_libraries();
        let mut random = |out: &mut [u8]| libraries.random(out).map_err(|_| ());
        let mut say = |to: sasl::Say, args: core::fmt::Arguments<'_>| match to {
            sasl::Say::Debug => trace::debug_info(cx, args),
            sasl::Say::Info => trace::info(cx, args),
        };
        let mut sx = sasl::Ctx {
            creds: login_of(&pc.cold).map(Credentials::secret),
            sasl_ir,
            host: self.peer.name(),
            port: self.peer.port(),
            random: &mut random,
            said: &mut say,
        };
        f(&mut pc.sasl, &mut sx)
    }

    /// Log in by SASL, or else in clear text, unless the greeting said
    /// the connection is logged in already or there is nothing to log in
    /// with (`imap_perform_authentication`).
    fn authenticate<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut ImapConn,
        carrier: &mut Carrier<'_>,
    ) -> Step {
        let can = self.sasl_step(cx, pc, |sasl, sx| sasl.can_authenticate(sx));
        if pc.preauth || !can {
            set_state(cx, pc, State::Stop);
            return Ok(());
        }
        let ir = pc.ir_offered;
        let progress = self.sasl_step(cx, pc, |sasl, sx| sasl.start(sx, ir));
        match progress.map_err(|e| sasl_failed(cx, e))? {
            Progress::Sends(send) => {
                self.sasl_send(cx, pc, carrier, send)?;
                set_state(cx, pc, State::Authenticate);
                Ok(())
            }
            Progress::Idle | Progress::Done => {
                if !pc.login_disabled && pc.preferred.has(AuthTypes::CLEARTEXT) {
                    self.login(cx, pc, carrier)
                } else {
                    self.sasl_step(cx, pc, |sasl, sx| sasl.blocked(sx));
                    Err(ErrorKind::LoginDenied)
                }
            }
        }
    }

    /// `LOGIN`, the user and password as atoms (`imap_perform_login`),
    /// or nothing to log in with.
    fn login<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut ImapConn,
        carrier: &mut Carrier<'_>,
    ) -> Step {
        let Some(credentials) = login_of(&pc.cold) else {
            set_state(cx, pc, State::Stop);
            return Ok(());
        };
        let user = atom(credentials.user(), false)?;
        let password = atom(credentials.secret().password(), false)?;
        let tag = pc.next_tag();
        drive::send(
            cx,
            &mut pc.pp,
            carrier,
            Some(tag.bytes()),
            &[b"LOGIN ", &user, b" ", &password],
        )?;
        set_state(cx, pc, State::Login);
        Ok(())
    }

    /// Send what SASL asks (`imap_perform_authenticate`,
    /// `imap_continue_authenticate`, `imap_cancel_authenticate`): the
    /// command tagged, its continuations not.
    fn sasl_send<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut ImapConn,
        carrier: &mut Carrier<'_>,
        send: sasl::Send,
    ) -> Step {
        let sent = match send {
            sasl::Send::Auth { mech, initial } => {
                let tag = pc.next_tag();
                match initial {
                    None => drive::send(
                        cx,
                        &mut pc.pp,
                        carrier,
                        Some(tag.bytes()),
                        &[b"AUTHENTICATE ", mech.as_bytes()],
                    ),
                    Some(ir) => {
                        let ir: &[u8] = if ir.is_empty() { b"=" } else { &ir };
                        drive::send(
                            cx,
                            &mut pc.pp,
                            carrier,
                            Some(tag.bytes()),
                            &[b"AUTHENTICATE ", mech.as_bytes(), b" ", ir],
                        )
                    }
                }
            }
            sasl::Send::Continue(resp) => drive::send(cx, &mut pc.pp, carrier, None, &[&resp]),
            sasl::Send::Cancel => drive::send(cx, &mut pc.pp, carrier, None, &[b"*"]),
        };
        // The exchange moves on once its command is sent.
        self.sasl_step(cx, pc, |sasl, sx| sasl.sent(sx, sent.is_ok()));
        sent
    }

    /// An answer in the SASL exchange (`imap_state_auth_resp`).
    fn auth<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut ImapConn,
        carrier: &mut Carrier<'_>,
        code: ImapReply,
    ) -> Step {
        let code = match code {
            ImapReply::Ok => Code::Final,
            ImapReply::Continuation => Code::Continue,
            _ => Code::Other,
        };
        let message =
            super::pop3::server_message(pc.pp.reply_line().expect("a reply was given out"));
        let mut copied = Vec::new();
        copied
            .try_extend_from_slice(message)
            .map_err(|_| ErrorKind::OutOfMemory)?;
        let progress = self.sasl_step(cx, pc, |sasl, sx| sasl.step(sx, code, &copied));
        match progress.map_err(|e| sasl_failed(cx, e))? {
            Progress::Done => {
                set_state(cx, pc, State::Stop);
                Ok(())
            }
            Progress::Sends(send) => self.sasl_send(cx, pc, carrier, send),
            // No mechanism left after a cancel.
            Progress::Idle => {
                if !pc.login_disabled && pc.preferred.has(AuthTypes::CLEARTEXT) {
                    self.login(cx, pc, carrier)
                } else {
                    Err(trace::fail(
                        cx,
                        ErrorKind::LoginDenied,
                        format_args!("Authentication cancelled"),
                    ))
                }
            }
        }
    }

    /// Read the URL's path and the application's command (`imap_do`'s
    /// `imap_parse_url_path` and `imap_parse_custom_request`).
    fn read_asked<H: Host>(&mut self, cx: &mut StepCx<'_, H>) -> Step {
        let mut asked = Box::<Asked>::default();
        parse_path(&self.path, &mut asked, &mut |name, value| {
            trace::debug_info_with(cx, &[b"IMAP URL parameter '", name, b"' = '", value, b"'"]);
        })?;
        if asked.mailbox.is_some() && asked.uid.is_none() && asked.mindex.is_none() {
            asked.query = self.query.take();
        }
        if let Some(custom) = cx.easy().options().http.custom.method.as_deref() {
            let mut custom = decode_but_control(custom)
                .map_err(url_error)?
                .ok_or(ErrorKind::UrlMalformat)?;
            if let Some(space) = custom.iter().position(|&b| b == b' ') {
                let mut params = Vec::new();
                params
                    .try_extend_from_slice(&custom[space..])
                    .map_err(|_| ErrorKind::OutOfMemory)?;
                custom.truncate(space);
                asked.custom_params = Some(params);
            }
            asked.custom = Some(custom);
        }
        self.asked = asked;
        Ok(())
    }

    /// Whether the transfer uploads (`state.upload`, or a MIME post).
    fn uploads<H: Host>(cx: &StepCx<'_, H>) -> bool {
        let options = cx.easy().options();
        options.method == Method::Upload
            || (options.method == Method::Post && matches!(options.upload, UploadSource::Mime(_)))
    }

    /// Make the request's first command (`imap_perform`): `APPEND`, the
    /// application's own, a `FETCH` or `SEARCH` of the mailbox selected
    /// already, `SELECT` before any of those, or `LIST`.
    fn perform<H: Host>(&mut self, cx: &mut StepCx<'_, H>, lease: &mut ConnLease) -> Step {
        let asked = &*self.asked;
        let selected = {
            let (pc, _) = imap_of(lease);
            match (&asked.mailbox, &pc.mailbox) {
                (Some(want), Some(have)) => {
                    (want == have
                        || (want.eq_ignore_ascii_case(b"INBOX")
                            && have.eq_ignore_ascii_case(b"INBOX")))
                        && match (asked.uidvalidity, pc.uidvalidity) {
                            (Some(want), Some(have)) => want == have,
                            _ => true,
                        }
                }
                _ => false,
            }
        };
        if Self::uploads(cx) {
            return self.append(cx, lease);
        }
        let (pc, mut carrier) = imap_of(lease);
        let asked = &*self.asked;
        if asked.custom.is_some() && (selected || asked.mailbox.is_none()) {
            list(cx, pc, &mut carrier, asked)
        } else if asked.custom.is_none()
            && selected
            && (asked.uid.is_some() || asked.mindex.is_some())
        {
            fetch(cx, pc, &mut carrier, asked)
        } else if asked.custom.is_none() && selected && asked.query.is_some() {
            search(cx, pc, &mut carrier, asked)
        } else if asked.mailbox.is_some()
            && !selected
            && (asked.custom.is_some()
                || asked.uid.is_some()
                || asked.mindex.is_some()
                || asked.query.is_some())
        {
            select(cx, pc, &mut carrier, asked)
        } else {
            list(cx, pc, &mut carrier, asked)
        }
    }

    /// `APPEND` the body to the mailbox, its size and flags said
    /// (`imap_perform_append`): a size that is not known fails it.
    fn append<H: Host>(&mut self, cx: &mut StepCx<'_, H>, lease: &mut ConnLease) -> Step {
        let Some(mailbox) = self.asked.mailbox.as_deref() else {
            return Err(trace::fail(
                cx,
                ErrorKind::UrlMalformat,
                format_args!("Cannot APPEND without a mailbox."),
            ));
        };
        // A tree goes as a mail message (`MIMESTRATEGY_MAIL`).
        let upload = if matches!(cx.easy().options().upload, UploadSource::Mime(_)) {
            Upload::open_mail(cx)?
        } else {
            Upload::open(cx)?
        };
        upload.trace_set(cx);
        let converts = cx.easy().options().crlf;
        let mut body = Body::new(upload);
        if converts {
            body.convert_lines().map_err(|_| ErrorKind::OutOfMemory)?;
        }
        let Some(size) = body.size() else {
            let why = if converts {
                "Cannot APPEND with CRLF conversion making size unknown"
            } else {
                "Cannot APPEND with unknown input file size"
            };
            return Err(trace::fail(
                cx,
                ErrorKind::UploadFailed,
                format_args!("{why}"),
            ));
        };
        let mailbox = atom(mailbox, false)?;
        let flags = flags_of(cx.easy().options().line.upload_flags)?;
        let size_text =
            curl_alloc::try_format(format_args!("{size}")).map_err(|_| ErrorKind::OutOfMemory)?;
        let room = cx.easy().options().limits.upload_buffer.get();
        self.sending = Some(Sending::new(body, room)?);
        let (pc, mut carrier) = imap_of(lease);
        let tag = pc.next_tag();
        drive::send(
            cx,
            &mut pc.pp,
            &mut carrier,
            Some(tag.bytes()),
            &[
                b"APPEND ",
                &mailbox,
                &flags,
                b" {",
                size_text.as_bytes(),
                b"}",
            ],
        )?;
        set_state(cx, pc, State::Append);
        Ok(())
    }

    /// The answer to `APPEND` (`imap_state_append_resp`): a continuation
    /// lets the body go.
    fn append_resp<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut ImapConn,
        code: ImapReply,
    ) -> Step {
        if code != ImapReply::Continuation {
            return Err(ErrorKind::UploadFailed);
        }
        let size = self.sending.as_ref().and_then(|s| s.body().size());
        upload::announce_size(cx, size);
        // Sent, the answer read in DONE (`Curl_xfer_setup_send`).
        let ways = crate::deliver::Directions {
            recv: false,
            send: true,
        };
        crate::multi::mstate::xfer_setup(cx, ways);
        self.last = Final::Append;
        pc.no_socket = false;
        set_state(cx, pc, State::Stop);
        Ok(())
    }

    /// A line of the answer to `LIST`, `SEARCH` or the application's
    /// command, or its end (`imap_state_listsearch_resp`): each untagged
    /// line is body, and a literal one announces is read as body too.
    fn listsearch<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut ImapConn,
        code: ImapReply,
    ) -> Step {
        if code == ImapReply::Untagged && self.custom_fetch_listing() {
            // A listing of messages is not written as body.
            return Ok(());
        }
        if code == ImapReply::Untagged {
            let line = pc.pp.reply_line().expect("a reply was given out");
            let len = line.len();
            let to_cr = line.iter().position(|&b| b == b'\r').unwrap_or(len);
            let Some(size) = literal(&line[..to_cr]) else {
                return self.pipeline.body(cx, line);
            };
            trace::info(cx, format_args!("Found {size} bytes to download"));
            self.pipeline.body(cx, line)?;
            let after = pc.pp.after_reply().unwrap_or_default();
            let chunk = usize::try_from(size).map_or(after.len(), |s| s.min(after.len()));
            if chunk > 0 {
                let mut held = Vec::new();
                held.try_extend_from_slice(&after[..chunk])
                    .map_err(|_| ErrorKind::OutOfMemory)?;
                pc.pp.consume_after_reply(chunk);
                self.pipeline.body(cx, &held)?;
            } else {
                pc.pp.consume_after_reply(0);
            }
            let size = size.saturating_add(len as u64);
            self.pipeline.announce_size(cx, Some(size));
            self.receive(cx, pc, size);
            // A literal still to come is fetched, its answer after it
            // read as the transfer ends (`imap_done`'s `maxdownload`).
            if self.receive.is_receiving() && self.asked.custom.is_some() {
                self.last = Final::Fetch;
            }
            set_state(cx, pc, State::Stop);
            return Ok(());
        }
        if code != ImapReply::Ok {
            return Err(ErrorKind::QuoteError);
        }
        set_state(cx, pc, State::Stop);
        Ok(())
    }

    /// The application's command is a `FETCH` or `UID FETCH` of a range
    /// or a list of messages (`is_custom_fetch_listing`).
    fn custom_fetch_listing(&self) -> bool {
        let (Some(custom), Some(params)) = (&self.asked.custom, &self.asked.custom_params) else {
            return false;
        };
        let rest: &[u8] = if custom.eq_ignore_ascii_case(b"FETCH") {
            params
        } else if custom.eq_ignore_ascii_case(b"UID")
            && params.len() >= 7
            && params[..7].eq_ignore_ascii_case(b" FETCH ")
        {
            &params[6..]
        } else {
            return false;
        };
        let Some(rest) = rest.strip_prefix(b" ") else {
            return false;
        };
        let digits = rest.iter().take_while(|b| b.is_ascii_digit()).count();
        // Digits that end the string are no listing, as C gives up on them.
        matches!(rest.get(digits), Some(b':' | b','))
    }

    /// The literal's `size` bytes of body are to be read, as many as
    /// are delivered already counted (`maxdownload`): none left, nothing
    /// is (`Curl_xfer_setup_nop`).
    fn receive<H: Host>(&mut self, cx: &mut StepCx<'_, H>, pc: &mut ImapConn, size: u64) {
        pc.no_socket = self.pipeline.bytecount() == size;
        let ways = crate::deliver::Directions {
            recv: !pc.no_socket,
            send: false,
        };
        crate::multi::mstate::xfer_setup(cx, ways);
        if !pc.no_socket {
            self.pipeline.expect(Expect {
                size: Some(size),
                max: Some(size),
                ..Expect::default()
            });
            self.receive.start_sized(size);
        }
    }

    /// A line of the answer to `SELECT`, or its end
    /// (`imap_state_select_resp`): its UIDVALIDITY kept, then the
    /// request's command on the mailbox.
    fn select_resp<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut ImapConn,
        carrier: &mut Carrier<'_>,
        code: ImapReply,
    ) -> Step {
        match code {
            ImapReply::Untagged => {
                let line = pc.pp.reply_line().expect("a reply was given out");
                if line.len() >= 18
                    && let Some(rest) = line[2..].strip_prefix(b"OK [UIDVALIDITY ")
                    && let Some(n) = number(rest, u64::from(u32::MAX))
                {
                    pc.uidvalidity = Some(u32::try_from(n).expect("checked"));
                }
                Ok(())
            }
            ImapReply::Ok => {
                if let (Some(want), Some(have)) = (self.asked.uidvalidity, pc.uidvalidity)
                    && want != have
                {
                    return Err(trace::fail(
                        cx,
                        ErrorKind::RemoteFileNotFound,
                        format_args!("Mailbox UIDVALIDITY has changed"),
                    ));
                }
                let mut mailbox = Vec::new();
                mailbox
                    .try_extend_from_slice(self.asked.mailbox.as_deref().unwrap_or_default())
                    .map_err(|_| ErrorKind::OutOfMemory)?;
                pc.mailbox = Some(mailbox);
                let asked = &*self.asked;
                if asked.custom.is_some() {
                    list(cx, pc, carrier, asked)
                } else if asked.query.is_some() {
                    search(cx, pc, carrier, asked)
                } else {
                    fetch(cx, pc, carrier, asked)
                }
            }
            _ => Err(trace::fail(
                cx,
                ErrorKind::LoginDenied,
                format_args!("Select failed"),
            )),
        }
    }

    /// The answer to `FETCH` (`imap_state_fetch_resp`): the literal its
    /// line announces is the body, what of it came with the line written.
    fn fetch_resp<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut ImapConn,
        code: ImapReply,
    ) -> Step {
        if code != ImapReply::Untagged {
            self.pipeline.announce_size(cx, None);
            set_state(cx, pc, State::Stop);
            return Err(ErrorKind::RemoteFileNotFound);
        }
        let line = pc.pp.reply_line().expect("a reply was given out");
        let Some(size) = literal(line) else {
            set_state(cx, pc, State::Stop);
            return Err(trace::fail(
                cx,
                ErrorKind::WeirdServerReply,
                format_args!("Failed to parse FETCH response."),
            ));
        };
        trace::info(cx, format_args!("Found {size} bytes to download"));
        self.pipeline.announce_size(cx, Some(size));
        self.last = Final::Fetch;
        let after = pc.pp.after_reply().unwrap_or_default();
        if !after.is_empty() {
            let chunk = usize::try_from(size).map_or(after.len(), |s| s.min(after.len()));
            if chunk == 0 {
                // No size: done with the data.
                pc.pp.consume_after_reply(0);
                set_state(cx, pc, State::Stop);
                return Ok(());
            }
            let mut held = Vec::new();
            held.try_extend_from_slice(&after[..chunk])
                .map_err(|_| ErrorKind::OutOfMemory)?;
            pc.pp.consume_after_reply(chunk);
            self.pipeline.body(cx, &held)?;
            let left = size - chunk as u64;
            trace::info(
                cx,
                format_args!("Written {chunk} bytes, {left} bytes are left for transfer"),
            );
        }
        self.receive(cx, pc, size);
        set_state(cx, pc, State::Stop);
        Ok(())
    }
}

/// `CAPABILITY`, what the server offered forgotten
/// (`imap_perform_capability`).
fn capability<H: Host>(
    cx: &mut StepCx<'_, H>,
    pc: &mut ImapConn,
    carrier: &mut Carrier<'_>,
) -> Step {
    pc.sasl.forget_offers();
    pc.tls_offered = false;
    let tag = pc.next_tag();
    drive::send(cx, &mut pc.pp, carrier, Some(tag.bytes()), &[b"CAPABILITY"])?;
    set_state(cx, pc, State::Capability);
    Ok(())
}

/// The application's command, or `LIST` of the mailbox's children
/// (`imap_perform_list`).
fn list<H: Host>(
    cx: &mut StepCx<'_, H>,
    pc: &mut ImapConn,
    carrier: &mut Carrier<'_>,
    asked: &Asked,
) -> Step {
    let tag = pc.next_tag();
    match &asked.custom {
        Some(custom) => {
            let params = asked.custom_params.as_deref().unwrap_or_default();
            drive::send(
                cx,
                &mut pc.pp,
                carrier,
                Some(tag.bytes()),
                &[custom, params],
            )?;
        }
        None => {
            let mailbox = atom(asked.mailbox.as_deref().unwrap_or_default(), true)?;
            drive::send(
                cx,
                &mut pc.pp,
                carrier,
                Some(tag.bytes()),
                &[b"LIST \"", &mailbox, b"\" *"],
            )?;
        }
    }
    set_state(cx, pc, State::List);
    Ok(())
}

/// `SELECT` the mailbox, the one selected before forgotten
/// (`imap_perform_select`).
fn select<H: Host>(
    cx: &mut StepCx<'_, H>,
    pc: &mut ImapConn,
    carrier: &mut Carrier<'_>,
    asked: &Asked,
) -> Step {
    pc.mailbox = None;
    pc.uidvalidity = None;
    let Some(mailbox) = asked.mailbox.as_deref() else {
        return Err(trace::fail(
            cx,
            ErrorKind::UrlMalformat,
            format_args!("Cannot SELECT without a mailbox."),
        ));
    };
    let mailbox = atom(mailbox, false)?;
    let tag = pc.next_tag();
    drive::send(
        cx,
        &mut pc.pp,
        carrier,
        Some(tag.bytes()),
        &[b"SELECT ", &mailbox],
    )?;
    set_state(cx, pc, State::Select);
    Ok(())
}

/// `FETCH` the message by its UID or its index, its section and part
/// (`imap_perform_fetch`).
fn fetch<H: Host>(
    cx: &mut StepCx<'_, H>,
    pc: &mut ImapConn,
    carrier: &mut Carrier<'_>,
    asked: &Asked,
) -> Step {
    let (command, id): (&[u8], &[u8]) = match (&asked.uid, &asked.mindex) {
        (Some(uid), _) => (b"UID FETCH ", uid),
        (None, Some(mindex)) => (b"FETCH ", mindex),
        (None, None) => {
            return Err(trace::fail(
                cx,
                ErrorKind::UrlMalformat,
                format_args!("Cannot FETCH without a UID."),
            ));
        }
    };
    let section = asked.section.as_deref().unwrap_or_default();
    let tag = pc.next_tag();
    match &asked.partial {
        Some(partial) => drive::send(
            cx,
            &mut pc.pp,
            carrier,
            Some(tag.bytes()),
            &[command, id, b" BODY[", section, b"]<", partial, b">"],
        )?,
        None => drive::send(
            cx,
            &mut pc.pp,
            carrier,
            Some(tag.bytes()),
            &[command, id, b" BODY[", section, b"]"],
        )?,
    }
    set_state(cx, pc, State::Fetch);
    Ok(())
}

/// `SEARCH` the mailbox for the URL's query (`imap_perform_search`).
fn search<H: Host>(
    cx: &mut StepCx<'_, H>,
    pc: &mut ImapConn,
    carrier: &mut Carrier<'_>,
    asked: &Asked,
) -> Step {
    let Some(query) = asked.query.as_deref() else {
        return Err(trace::fail(
            cx,
            ErrorKind::UrlMalformat,
            format_args!("Cannot SEARCH without a query string."),
        ));
    };
    let tag = pc.next_tag();
    drive::send(
        cx,
        &mut pc.pp,
        carrier,
        Some(tag.bytes()),
        &[b"SEARCH ", query],
    )?;
    set_state(cx, pc, State::Search);
    Ok(())
}

/// The flags an `APPEND` gives its message, ` (\Seen ...)`, or none
/// (`imap_perform_append`'s `ulflag`).
fn flags_of(flags: UploadFlags) -> Result<Vec<u8>, ErrorKind> {
    const NAMES: [(UploadFlags, &[u8]); 5] = [
        (UploadFlags::ANSWERED, b"Answered"),
        (UploadFlags::DELETED, b"Deleted"),
        (UploadFlags::DRAFT, b"Draft"),
        (UploadFlags::FLAGGED, b"Flagged"),
        (UploadFlags::SEEN, b"Seen"),
    ];
    let mut out = Vec::new();
    if !NAMES.iter().any(|&(flag, _)| flags.contains(flag)) {
        return Ok(out);
    }
    let oom = |_| ErrorKind::OutOfMemory;
    out.try_extend_from_slice(b" (").map_err(oom)?;
    for (flag, name) in NAMES {
        if flags.contains(flag) {
            if out.len() > 2 {
                out.try_extend_from_slice(b" ").map_err(oom)?;
            }
            out.try_extend_from_slice(b"\\").map_err(oom)?;
            out.try_extend_from_slice(name).map_err(oom)?;
        }
    }
    out.try_extend_from_slice(b")").map_err(oom)?;
    Ok(out)
}

/// `text` as an IMAP atom (`imap_atom`): as it is if it has none of
/// `() {%*]\"`, else with each backslash and quote escaped, quoted unless
/// `escape_only`.
fn atom(text: &[u8], escape_only: bool) -> Result<Vec<u8>, ErrorKind> {
    let oom = |_| ErrorKind::OutOfMemory;
    let mut out = Vec::new();
    if !text.iter().any(|b| b"() {%*]\\\"".contains(b)) {
        out.try_extend_from_slice(text).map_err(oom)?;
        return Ok(out);
    }
    if !escape_only {
        out.try_push(b'"').map_err(oom)?;
    }
    for &b in text {
        if b == b'\\' || b == b'"' {
            out.try_push(b'\\').map_err(oom)?;
        }
        out.try_push(b).map_err(oom)?;
    }
    if !escape_only {
        out.try_push(b'"').map_err(oom)?;
    }
    Ok(out)
}

/// The decimal number `text` starts with, if it is one no larger than
/// `max` (`curlx_str_number`).
fn number(text: &[u8], max: u64) -> Option<u64> {
    let digits = text.iter().take_while(|b| b.is_ascii_digit()).count();
    if digits == 0 {
        return None;
    }
    text[..digits].iter().try_fold(0u64, |n, d| {
        n.checked_mul(10)
            .and_then(|n| n.checked_add(u64::from(d - b'0')))
            .filter(|&n| n <= max)
    })
}

/// A byte of a URL's path that IMAP reads (`imap_is_bchar`).
fn bchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b":@/&=-._~!$'()*+,%".contains(&b)
}

/// Read the URL's path (`imap_parse_url_path`): the mailbox, then
/// `;NAME=VALUE` parameters, each decoded, told to `said` and any but the
/// known ones malformed; anything after them is malformed too.
fn parse_path(path: &[u8], asked: &mut Asked, said: &mut dyn FnMut(&[u8], &[u8])) -> Step {
    let decode = |bytes: &[u8]| -> Result<Vec<u8>, ErrorKind> {
        decode_but_control(bytes)
            .map_err(url_error)?
            .ok_or(ErrorKind::UrlMalformat)
    };
    let path = path.strip_prefix(b"/").unwrap_or(path);
    let mut at = path.iter().take_while(|&&b| bchar(b)).count();
    if at > 0 {
        let end = if path[at - 1] == b'/' { at - 1 } else { at };
        asked.mailbox = Some(decode(&path[..end])?);
    }
    while path.get(at) == Some(&b';') {
        at += 1;
        let begin = at;
        while at < path.len() && path[at] != b'=' {
            at += 1;
        }
        if at == path.len() {
            return Err(ErrorKind::UrlMalformat);
        }
        let name = decode(&path[begin..at])?;
        at += 1;
        let begin = at;
        at += path[at..].iter().take_while(|&&b| bchar(b)).count();
        let mut value = decode(&path[begin..at])?;
        said(&name, &value);
        if value.is_empty() {
            continue;
        }
        if value.last() == Some(&b'/') {
            value.pop();
        }
        if name.eq_ignore_ascii_case(b"UIDVALIDITY") && asked.uidvalidity.is_none() {
            if let Some(n) = number(&value, u64::from(u32::MAX)) {
                asked.uidvalidity = Some(u32::try_from(n).expect("checked"));
            }
        } else if name.eq_ignore_ascii_case(b"UID") && asked.uid.is_none() {
            asked.uid = Some(value);
        } else if name.eq_ignore_ascii_case(b"MAILINDEX") && asked.mindex.is_none() {
            asked.mindex = Some(value);
        } else if name.eq_ignore_ascii_case(b"SECTION") && asked.section.is_none() {
            asked.section = Some(value);
        } else if name.eq_ignore_ascii_case(b"PARTIAL") && asked.partial.is_none() {
            asked.partial = Some(value);
        } else {
            return Err(ErrorKind::UrlMalformat);
        }
    }
    if at < path.len() {
        return Err(ErrorKind::UrlMalformat);
    }
    Ok(())
}

/// The connection's IMAP state and what it works over.
fn imap_of(lease: &mut ConnLease) -> (&mut ImapConn, Carrier<'_>) {
    match lease.get().line_mut() {
        Some((LineConn::Imap(pc), carrier)) => (pc, carrier),
        _ => unreachable!("an IMAP transfer's connection keeps IMAP's state"),
    }
}

/// Move the state on, said as C's debug build says it (`imap_state`).
fn set_state<H: Host>(cx: &mut StepCx<'_, H>, pc: &mut ImapConn, state: State) {
    if pc.state != state {
        trace::debug_info(
            cx,
            format_args!(
                "IMAP {:p} state change from {} to {}",
                pc as *const ImapConn,
                pc.state.name(),
                state.name()
            ),
        );
    }
    pc.state = state;
}

/// The reply's code as C prints it with `%c` (`IMAP_RESP_*`, `'*'`,
/// `'+'`).
fn code_number(code: ImapReply) -> char {
    match code {
        ImapReply::Ok => '\u{1}',
        ImapReply::NotOk => '\u{2}',
        ImapReply::Preauth => '\u{3}',
        ImapReply::Untagged => '*',
        ImapReply::Continuation | ImapReply::UnexpectedContinuation => '+',
    }
}

fn sasl_failed<H: Host>(cx: &mut StepCx<'_, H>, e: SaslError) -> ErrorKind {
    match e {
        SaslError::Denied => ErrorKind::LoginDenied,
        SaslError::OutOfMemory => ErrorKind::OutOfMemory,
        SaslError::Random => {
            trace::fail(cx, ErrorKind::FailedInit, format_args!("no random bytes"))
        }
    }
}

/// The URL's or the application's login options
/// (`imap_parse_url_options`): `AUTH=+LOGIN` for clear text before any
/// SASL, or `AUTH=` and a SASL mechanism, `*` for any; any other is
/// malformed.
fn parse_options(pc: &mut ImapConn, mut options: &[u8]) -> Step {
    let mut result = Ok(());
    let mut prefer_login = false;
    while result.is_ok() && !options.is_empty() {
        let key = options;
        let eq = options
            .iter()
            .position(|&b| b == b'=')
            .unwrap_or(options.len());
        let value_start = (eq + 1).min(options.len());
        let end = options[eq..]
            .iter()
            .position(|&b| b == b';')
            .map_or(options.len(), |p| eq + p);
        let value = &options[value_start.min(end)..end];
        if key.len() >= 11 && key[..11].eq_ignore_ascii_case(b"AUTH=+LOGIN") {
            prefer_login = true;
            pc.sasl.prefer_none();
        } else if key.len() >= 5 && key[..5].eq_ignore_ascii_case(b"AUTH=") {
            prefer_login = false;
            if !pc.sasl.url_auth(value) {
                result = Err(ErrorKind::UrlMalformat);
            }
        } else {
            prefer_login = false;
            result = Err(ErrorKind::UrlMalformat);
        }
        options = &options[end..];
        if let [b';', rest @ ..] = options {
            options = rest;
        }
    }
    pc.preferred = if prefer_login {
        AuthTypes::CLEARTEXT
    } else {
        let pref = pc.sasl.preferred();
        if pref == Mechs::NONE {
            AuthTypes::NONE
        } else if pref == Mechs::DEFAULT {
            AuthTypes::ANY
        } else {
            AuthTypes::SASL
        }
    };
    result
}

/// IMAP connects over its connection by logging in, and makes its
/// request in DO, on in DOING until the command is answered
/// (`imap_connect`, `imap_multi_statemach`, `imap_do`, `imap_doing`).
impl super::Phases for Request {
    fn connect<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<Connect, ErrorKind> {
        if !lease.conn().keeps_line() {
            let url_options = self.url_options.take();
            self.conn_state(cx, lease, url_options.as_deref())?;
        }
        Ok(if self.run(cx, lease)? {
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
                self.read_asked(cx)?;
                // The progress counts from nothing (`imap_regular_transfer`).
                crate::progress::reset(cx);
                trace::debug_info(cx, format_args!("DO phase starts"));
                self.perform(cx, lease)?;
                let ran = self.run(cx, lease);
                // Said as the state stops, the answer refused or not
                // (`imap_perform`).
                if imap_of(lease).0.state == State::Stop {
                    trace::debug_info(cx, format_args!("DO phase is complete"));
                }
                if !ran? {
                    return Ok(DoStep::Doing);
                }
                self.dophase_done(cx, lease);
                Ok(DoStep::Did)
            }
            DoPhase::Doing => match self.run(cx, lease) {
                Err(e) => {
                    trace::debug_info(cx, format_args!("DO phase failed"));
                    Err(e)
                }
                Ok(true) => {
                    self.dophase_done(cx, lease);
                    trace::debug_info(cx, format_args!("DO phase is complete"));
                    Ok(DoStep::Did)
                }
                Ok(false) => Ok(DoStep::Doing),
            },
            DoPhase::More => unreachable!("IMAP has no second half"),
        }
    }

    fn waits(&self, _: Waiting) -> Events {
        self.wants
    }
}

impl Request {
    /// The request is made (`imap_dophase_done`): one that wants no body
    /// transfers nothing after it. Whether anything is exchanged after
    /// it is the connection's to say, as what the transfers on it set up
    /// last.
    fn dophase_done<H: Host>(&mut self, cx: &mut StepCx<'_, H>, lease: &mut ConnLease) {
        let (pc, _) = imap_of(lease);
        if self.no_body {
            crate::multi::mstate::xfer_setup(cx, crate::deliver::Directions::default());
            pc.no_socket = true;
            self.receive.stop();
            self.sending = None;
        }
        self.nothing_after = pc.no_socket;
    }
}

#[cfg(test)]
mod tests;
