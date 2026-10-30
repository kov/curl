//! POP3 (`lib/pop3.c`): a connection that logs in once, by SASL, APOP or
//! a clear-text `USER` and `PASS`, after `STLS` if TLS is asked for and
//! the connection is not over it already, and a command per transfer, its
//! answer's body the transfer's, up to the line of a single dot.

use std::num::NonZeroU32;

use curl_alloc::{TryArc, TryVec as _};

use super::pingpong::Pingpong;
use super::pingpong::drive::{self, Read};
use super::pingpong::pop3::{Pop3, Pop3Reply};
use super::{Connect, DoPhase, DoStep, ProtoStep, Waiting};
use crate::auth::creds::{Credentials, Takes, Trusted};
use crate::auth::sasl::{self, Code, Mechs, Progress, Sasl, SaslError};
use crate::conn::io::{Events, Recv};
use crate::conn::line::LineConn;
use crate::conn::mux::Carrier;
use crate::conn::{ConnLease, Peer, RecvFailed, RouteCold, Scheme};
use crate::deliver::{self, Pause, Pipeline, Reach};
use crate::error::{ErrorKind, url_error};
use crate::hash::{Hash as _, Md5};
use crate::idn::Idn;
use crate::multi::Host;
use crate::multi::state::StepCx;
use crate::options::UseSsl;
use crate::progress::rate::Way;
use crate::time::Instant;
use crate::trace;
use crate::url::{GetOptions, Part, Url, decode_but_control};

/// POP3's SASL (`saslpop3`): the longest line less `AUTH `, a space and
/// CRLF.
static SASL: sasl::Params = sasl::Params {
    service: "pop",
    max_ir: 255 - 8,
    default: Mechs::DEFAULT,
};

/// The ways a server lets a user log in (`POP3_TYPE_*`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AuthTypes(u8);

impl AuthTypes {
    const NONE: AuthTypes = AuthTypes(0);
    const CLEARTEXT: AuthTypes = AuthTypes(1 << 0);
    const APOP: AuthTypes = AuthTypes(1 << 1);
    const SASL: AuthTypes = AuthTypes(1 << 2);
    const ANY: AuthTypes = AuthTypes(0b111);

    /// Whether both `self` and `pref` have `t`.
    fn both(self, pref: AuthTypes, t: AuthTypes) -> bool {
        self.0 & pref.0 & t.0 != 0
    }
}

/// Where the connection's back and forth is (`pop3state`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Stop,
    ServerGreet,
    Capa,
    StartTls,
    UpgradeTls,
    Auth,
    Apop,
    User,
    Pass,
    Command,
}

impl State {
    fn name(self) -> &'static str {
        match self {
            State::Stop => "STOP",
            State::ServerGreet => "SERVERGREET",
            State::Capa => "CAPA",
            State::StartTls => "STARTTLS",
            State::UpgradeTls => "UPGRADETLS",
            State::Auth => "AUTH",
            State::Apop => "APOP",
            State::User => "USER",
            State::Pass => "PASS",
            State::Command => "COMMAND",
        }
    }
}

/// What POP3 keeps on its connection (`struct pop3_conn`).
#[derive(Debug)]
pub(crate) struct Pop3Conn {
    pp: Pingpong,
    state: State,
    sasl: Sasl,
    /// The greeting's APOP timestamp, its brackets included.
    apop: Option<Vec<u8>>,
    /// How the server lets a user log in (`authtypes`).
    offered: AuthTypes,
    /// How the URL's options prefer to (`preftype`).
    preferred: AuthTypes,
    /// The server offers `STLS` (`tls_supported`).
    tls_offered: bool,
    /// What of its route few routes have, the credentials it logs in
    /// with among it, its first transfer's (`conn->creds`): the route
    /// owns them.
    cold: Option<TryArc<RouteCold>>,
}

/// The credentials a connection logs in with, as its route holds them.
fn login_of(cold: &Option<TryArc<RouteCold>>) -> Option<&Credentials> {
    cold.as_deref().and_then(|c| c.login.as_ref())
}

impl Pop3Conn {
    /// Say `QUIT`, as the connection shuts down, unless it is `dead` or
    /// a command waits half sent (`pop3_disconnect`): sent as the
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
        // What does not go now is not said.
        let _sent = below.send(cx, b"QUIT\r\n");
    }
}

/// The transfer's end of the body: how much of the end-of-body marker,
/// CRLF `.` CRLF, has been seen, and how much of what was held back is
/// not body (`eob`, `strip`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Eob {
    eob: usize,
    strip: usize,
}

/// The marker.
const EOB: &[u8; 5] = b"\r\n.\r\n";

impl Eob {
    /// As the answer's `+OK` line leaves it: its CRLF is the marker's
    /// first two bytes, and no body.
    fn after_ok() -> Eob {
        Eob { eob: 2, strip: 2 }
    }

    /// Scan `bytes` for the marker, writing what is body through `out`, a
    /// dot a line starts with stripped (`pop3_write`). Whether the body
    /// ended, its last CRLF written.
    pub(crate) fn write(
        &mut self,
        bytes: &[u8],
        out: &mut dyn FnMut(&[u8]) -> Result<(), ErrorKind>,
    ) -> Result<bool, ErrorKind> {
        let mut strip_dot = false;
        let mut last = 0;
        for (i, &b) in bytes.iter().enumerate() {
            let prev = self.eob;
            match b {
                b'\r' => {
                    if self.eob == 0 {
                        self.eob = 1;
                        if i > 0 {
                            // What did not match.
                            out(&bytes[last..i])?;
                            last = i;
                        }
                    } else if self.eob == 3 {
                        self.eob = 4;
                    } else {
                        self.eob = 1;
                    }
                }
                b'\n' => {
                    if self.eob == 1 || self.eob == 4 {
                        self.eob += 1;
                    } else {
                        self.eob = 0;
                    }
                }
                b'.' => {
                    if self.eob == 2 {
                        self.eob = 3;
                    } else if self.eob == 3 {
                        // A dot after CRLF and a dot: the server stuffed
                        // the first.
                        strip_dot = true;
                        self.eob = 0;
                    } else {
                        self.eob = 0;
                    }
                }
                _ => self.eob = 0,
            }
            // A partial match that failed.
            if prev > 0 && prev >= self.eob {
                let mut prev = prev;
                while prev > 0 && self.strip > 0 {
                    prev -= 1;
                    self.strip -= 1;
                }
                if prev > 0 {
                    // CRLF and a dot: only the CRLF, the server put the dot.
                    if strip_dot && prev - 1 > 0 {
                        out(&EOB[..prev - 1])?;
                    } else if !strip_dot {
                        out(&EOB[..prev])?;
                    }
                    last = i;
                    strip_dot = false;
                }
            }
        }
        if self.eob == EOB.len() {
            // The CRLF the marker starts with ends the message
            // (RFC 1939, 3).
            self.eob = 0;
            out(&EOB[..2])?;
            return Ok(true);
        }
        if self.eob > 0 {
            // Nothing goes while the marker may be matching.
            return Ok(false);
        }
        if bytes.len() > last {
            out(&bytes[last..])?;
        }
        Ok(false)
    }
}

/// A POP3 transfer (`struct POP3`, and what C's request keeps of it).
#[derive(Debug)]
pub(crate) struct Request {
    pipeline: Pipeline,
    peer: Peer,
    /// The transfer's credentials, until its route takes them.
    credentials: Option<Credentials>,
    /// The URL's message id, decoded.
    id: Vec<u8>,
    /// The application's command, decoded (`CURLOPT_CUSTOMREQUEST`).
    custom: Option<Vec<u8>>,
    /// The URL's login options, decoded (`state.up.options`).
    url_options: Option<Vec<u8>>,
    /// The answer has a body to deliver (`PPTRANSFER_BODY`).
    body: bool,
    /// No body is wanted (`req.no_body`): the application's `NOBODY`
    /// until the command goes, then whether the command's answer has
    /// none.
    no_body: bool,
    /// The body is still being read (`KEEP_RECV`).
    receiving: bool,
    /// The body was read to its end (`req.done`).
    received: bool,
    eob: Eob,
    /// When the server's time to answer runs out.
    due: Option<Instant>,
    /// The peer a connect-to entry names in the origin's place, which TLS
    /// is made with as the connection is upgraded.
    via: Option<TryArc<Peer>>,
    /// What the back and forth waits for on the connection.
    wants: Events,
    /// The answers' bytes (`req.headerbytecount`).
    header_bytes: u64,
}

/// The ways a step of the back and forth can fail.
type Step = Result<(), ErrorKind>;

impl Request {
    /// A transfer of `url`, `pop3s` if `secured`: its peer, the
    /// credentials its URL and the application give, a `.netrc`'s if
    /// asked for, and its message id and command, each decoded
    /// (`pop3_setup_connection`, `pop3_parse_url_path`,
    /// `pop3_parse_custom_request`).
    pub(crate) fn new<H: Host>(
        url: &Url,
        secured: bool,
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
        let name: &[u8] = if secured { b"pop3s" } else { b"pop3" };
        let scheme = Scheme::named(name).expect("libcurl knows POP3");
        let scope = cx.easy().options().address_scope;
        let idn = cx.easy().libraries().idn;
        let peer = super::url_peer((scheme, host, port), url, scope, idn)?;
        let takes = Takes::of(Some(scheme));
        let credentials = super::request_credentials(cx, Some(Trusted::own_url()), url, takes)?;
        let credentials = super::with_netrc(credentials, peer.name(), takes, cx)?;
        let encoded = GetOptions {
            url_encode: true,
            ..GetOptions::NONE
        };
        let path = url.get(Part::Path, encoded).map_err(url_error)?;
        let id = decode_but_control(path.strip_prefix(b"/").unwrap_or(&path))
            .map_err(url_error)?
            .ok_or(ErrorKind::UrlMalformat)?;
        let custom = match cx.easy().options().http.custom.method.as_deref() {
            None => None,
            Some(custom) => Some(
                decode_but_control(custom)
                    .map_err(url_error)?
                    .ok_or(ErrorKind::UrlMalformat)?,
            ),
        };
        let decoded = GetOptions {
            url_decode: true,
            ..GetOptions::NONE
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
            id,
            custom,
            url_options,
            body: true,
            no_body: cx.easy().options().method == crate::options::Method::Head,
            receiving: false,
            received: false,
            eob: Eob::default(),
            due: None,
            via: None,
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

    /// It is over TLS from the start: its scheme is `pop3s`.
    pub(crate) fn secured(&self) -> bool {
        self.peer.scheme().over_tls()
    }

    pub(crate) fn pipeline_mut(&mut self) -> &mut Pipeline {
        &mut self.pipeline
    }

    pub(crate) fn holds_output(&self) -> bool {
        self.pipeline.holds_output()
    }

    /// Whether nothing came back for the request, which waits for a body
    /// it has not read to its end: one that may be made again on a fresh
    /// connection, its reused one having died (`Curl_retry_request` for a
    /// scheme outside HTTP's, `req.bytecount + req.headerbytecount`).
    pub(crate) fn received_nothing(&self) -> bool {
        self.header_bytes == 0 && self.pipeline.bytecount() == 0 && !self.no_body && !self.received
    }

    /// When the server's time to answer runs out, while it is awaited.
    pub(crate) fn due(&self) -> Option<Instant> {
        self.due
    }

    /// What the body waits for on the connection's socket.
    pub(crate) fn interest(&self, pause: Pause) -> Events {
        if self.receiving && !pause.recv_paused() {
            Events::IN
        } else {
            Events::NONE
        }
    }

    /// The transfer is over (`pop3_done`): one that failed leaves its
    /// connection to close.
    pub(crate) fn done<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        result: Result<(), ErrorKind>,
    ) -> Result<(), ErrorKind> {
        if result.is_err() {
            crate::multi::mstate::trace(cx, format_args!("POP3 done with bad status"));
            lease.get().mark_close();
        }
        result
    }

    /// Read the body on, at most as many reads as a step makes
    /// (`sendrecv_dl`), through the end-of-body scan.
    pub(crate) fn step<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<ProtoStep, ErrorKind> {
        self.pipeline.flush(cx)?;
        let mut reads = 0;
        loop {
            if !self.receiving {
                self.received = true;
                return Ok(ProtoStep::Done);
            }
            if cx.pause().recv_paused() {
                return Ok(ProtoStep::Blocked);
            }
            if reads == super::http::MAX_READS {
                return Ok(ProtoStep::AtReadLimit);
            }
            let max = cx.easy().options().limits.buffer_size.get();
            let max = match cx.rate_allowance(Way::Recv) {
                Some(..=0) => return Ok(ProtoStep::Blocked),
                Some(allowed) => max.min(usize::try_from(allowed).unwrap_or(usize::MAX)),
                None => max,
            };
            reads += 1;
            let said = cx.easy().report().reasons();
            match lease.get().recv(cx, max) {
                Ok(Recv::WouldBlock) if lease.get().data_pending() => {
                    return Ok(ProtoStep::AtReadLimit);
                }
                Ok(Recv::WouldBlock) => return Ok(ProtoStep::Blocked),
                Ok(Recv::Eof) => {
                    trace::debug_info(cx, format_args!("sendrecv_dl: we are done"));
                    deliver::write_resp(cx, 0, true, Ok(()));
                    self.receiving = false;
                }
                Ok(Recv::Data(_)) => {
                    let mut rx = std::mem::take(lease.get().rx_mut());
                    let fed = self.body_bytes(cx, rx.filled());
                    let all = rx.filled().len();
                    rx.consume(all);
                    *lease.get().rx_mut() = rx;
                    deliver::write_resp(cx, all, false, fed);
                    fed?;
                }
                Err(RecvFailed::OutOfMemory) => return Err(ErrorKind::OutOfMemory),
                Err(RecvFailed::Os(_)) if cx.easy().report().reasons() > said => {
                    return Err(ErrorKind::RecvError);
                }
                Err(RecvFailed::Os(e)) => {
                    let why = curl_os::error::ErrorText::of(&e);
                    return Err(trace::fail_with(
                        cx,
                        ErrorKind::RecvError,
                        &[b"Recv failure: ", why.as_bytes()],
                    ));
                }
            }
        }
    }

    /// Body bytes through the end-of-body scan to the application; the
    /// body over once the marker is whole (`CURL_REQ_CLEAR_RECV`).
    fn body_bytes<H: Host>(&mut self, cx: &mut StepCx<'_, H>, bytes: &[u8]) -> Step {
        let pipeline = &mut self.pipeline;
        let ended = self.eob.write(bytes, &mut |b| pipeline.body(cx, b))?;
        if ended {
            self.receiving = false;
        }
        Ok(())
    }

    /// The connection's POP3 state, set up the first time
    /// (`pop3_connect`): the URL's or the application's login options
    /// read, the greeting awaited.
    fn conn_state<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        url_options: Option<&[u8]>,
    ) -> Step {
        let http = cx.easy().options().http.auth.0;
        let mut pc = Pop3Conn {
            pp: Pingpong::new(cx.now()),
            state: State::Stop,
            sasl: Sasl::new(&SASL, http),
            apop: None,
            offered: AuthTypes::NONE,
            preferred: AuthTypes::ANY,
            tls_offered: false,
            cold: lease.conn().net_route().and_then(|r| r.cold.clone()),
        };
        let options = match cx.easy().options().line.login_options.as_deref() {
            Some(given) => Some(given),
            None => url_options,
        };
        parse_options(&mut pc, options.unwrap_or_default())?;
        let line = curl_alloc::try_box(LineConn::Pop3(pc)).map_err(|_| ErrorKind::OutOfMemory)?;
        lease.get().put_line(line);
        let (pc, _) = pop3_of(lease);
        set_state(cx, pc, State::ServerGreet);
        Ok(())
    }

    /// Run the back and forth as far as the connection lets it now
    /// (`pop3_multi_statemach`): whether it stopped, its phase's work
    /// done.
    fn run<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<bool, ErrorKind> {
        let limit = cx.easy().options().line.server_response;
        self.via = lease.conn().net_route().and_then(|r| r.via.clone());
        let (pc, mut carrier) = pop3_of(lease);
        let (runs, due) = drive::runs(cx, &pc.pp, &mut carrier, limit)?;
        self.due = Some(due);
        if runs {
            self.machine(cx, pc, &mut carrier)?;
        }
        self.wants = drive::waits(&pc.pp);
        let stopped = pc.state == State::Stop;
        if stopped {
            self.due = None;
        }
        Ok(stopped)
    }

    /// The state machine (`pop3_statemachine`).
    fn machine<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut Pop3Conn,
        carrier: &mut Carrier<'_>,
    ) -> Step {
        if pc.state == State::UpgradeTls {
            // All bytes are TLS's until its handshake is done
            // (`pop3_perform_upgrade_tls`).
            let Some(identity) = pc.cold.as_ref().and_then(|c| c.upgrade.clone()) else {
                return Err(ErrorKind::NotBuiltIn);
            };
            let via = self.via.clone();
            let shaken = crate::multi::state::tls::upgrade(
                carrier,
                &identity,
                &self.peer,
                via.as_deref(),
                cx,
            );
            let (code, done) = match &shaken {
                Ok(crate::tls::Handshake::Done) => (0, 1),
                Ok(crate::tls::Handshake::Waiting) => (0, 0),
                Err(kind) => (kind.number(), 0),
            };
            trace::debug_info(
                cx,
                format_args!("pop3_perform_upgrade_tls, connect -> {code}, {done}"),
            );
            match shaken? {
                crate::tls::Handshake::Waiting => return Ok(()),
                // `CAPA` again, under TLS.
                crate::tls::Handshake::Done => capa(cx, pc, carrier)?,
            }
        }
        if pc.pp.needs_flush() {
            return drive::flush(cx, &mut pc.pp, carrier);
        }
        loop {
            let ends = Pop3 {
                capa: pc.state == State::Capa,
            };
            let read = drive::read(
                cx,
                &mut pc.pp,
                carrier,
                &ends,
                &mut self.pipeline,
                &mut self.header_bytes,
                // A command is sent beside the request's sending, which
                // never ends: the server's lines start no response's time
                // (`upload_done` stays unset).
                false,
            )?;
            let Read::Reply(code, _) = read else {
                return Ok(());
            };
            match pc.state {
                State::ServerGreet => self.greeting(cx, pc, carrier, code)?,
                State::Capa => self.capa(cx, pc, carrier, code)?,
                State::StartTls => {
                    self.starttls(cx, pc, carrier, code)?;
                    if pc.state == State::UpgradeTls {
                        return self.machine(cx, pc, carrier);
                    }
                }
                State::Auth => self.auth(cx, pc, carrier, code)?,
                State::Apop => {
                    if code != Pop3Reply::Ok {
                        return Err(trace::fail(
                            cx,
                            ErrorKind::LoginDenied,
                            format_args!("Authentication failed: {}", char_of(code)),
                        ));
                    }
                    set_state(cx, pc, State::Stop);
                }
                State::User => {
                    if code != Pop3Reply::Ok {
                        return Err(access_denied(cx, code));
                    }
                    let password = login_of(&pc.cold).map_or(&[][..], |c| c.secret().password());
                    let mut password_copy = Vec::new();
                    password_copy
                        .try_extend_from_slice(password)
                        .map_err(|_| ErrorKind::OutOfMemory)?;
                    drive::send(cx, &mut pc.pp, carrier, None, &[b"PASS ", &password_copy])?;
                    set_state(cx, pc, State::Pass);
                }
                State::Pass => {
                    if code != Pop3Reply::Ok {
                        return Err(access_denied(cx, code));
                    }
                    set_state(cx, pc, State::Stop);
                }
                State::Command => self.command_resp(cx, pc, code)?,
                State::Stop | State::UpgradeTls => set_state(cx, pc, State::Stop),
            }
            if pc.state == State::Stop || !pc.pp.more_data() {
                return Ok(());
            }
        }
    }

    /// The greeting (`pop3_state_servergreet_resp`): its APOP timestamp
    /// kept, then `CAPA`.
    fn greeting<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut Pop3Conn,
        carrier: &mut Carrier<'_>,
        code: Pop3Reply,
    ) -> Step {
        if code != Pop3Reply::Ok {
            return Err(trace::fail(
                cx,
                ErrorKind::WeirdServerReply,
                format_args!("Got unexpected pop3-server response"),
            ));
        }
        let line = pc.pp.reply_line().expect("a reply was given out");
        if line.len() <= 3 {
            return Ok(());
        }
        // `<...@...>`, the timestamp RFC 1939 has, an RFC 822 message id.
        if let Some(lt) = line.iter().position(|&b| b == b'<')
            && let Some(gt) = line[lt..].iter().position(|&b| b == b'>')
            && line[lt..=lt + gt].contains(&b'@')
        {
            let mut stamp = Vec::new();
            stamp
                .try_extend_from_slice(&line[lt..=lt + gt])
                .map_err(|_| ErrorKind::OutOfMemory)?;
            pc.apop = Some(stamp);
            pc.offered.0 |= AuthTypes::APOP.0;
        }
        capa(cx, pc, carrier)
    }

    /// A line of the answer to `CAPA`, or its end (`pop3_state_capa_resp`):
    /// on to `STLS` or the login.
    fn capa<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut Pop3Conn,
        carrier: &mut Carrier<'_>,
        code: Pop3Reply,
    ) -> Step {
        let line = pc.pp.reply_line().expect("a reply was given out");
        if code == Pop3Reply::More {
            if line.len() >= 4 && line[..4].eq_ignore_ascii_case(b"STLS") {
                pc.tls_offered = true;
            } else if line.len() >= 4 && line[..4].eq_ignore_ascii_case(b"USER") {
                pc.offered.0 |= AuthTypes::CLEARTEXT.0;
            } else if line.len() >= 5 && line[..5].eq_ignore_ascii_case(b"SASL ") {
                pc.offered.0 |= AuthTypes::SASL.0;
                let mut rest = &line[5..];
                loop {
                    while let [b' ' | b'\t' | b'\r' | b'\n', more @ ..] = rest {
                        rest = more;
                    }
                    if rest.is_empty() {
                        break;
                    }
                    let n = rest
                        .iter()
                        .position(|&b| matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
                        .unwrap_or(rest.len());
                    if let Some((mech, len)) = sasl::decode_mech(&rest[..n])
                        && len == n
                    {
                        pc.sasl.offers(mech);
                    }
                    rest = &rest[n..];
                }
            }
            return Ok(());
        }
        // Clear text is assumed of a server that does not know `CAPA`.
        if code != Pop3Reply::Ok {
            pc.offered.0 |= AuthTypes::CLEARTEXT.0;
        }
        let use_ssl = cx.easy().options().line.use_ssl;
        if use_ssl == UseSsl::None || carrier.over_tls() {
            self.authenticate(cx, pc, carrier)
        } else if code == Pop3Reply::Ok && pc.tls_offered {
            drive::send(cx, &mut pc.pp, carrier, None, &[b"STLS"])?;
            set_state(cx, pc, State::StartTls);
            Ok(())
        } else if use_ssl <= UseSsl::Try {
            self.authenticate(cx, pc, carrier)
        } else {
            Err(trace::fail(
                cx,
                ErrorKind::UseSslFailed,
                format_args!("STLS not supported."),
            ))
        }
    }

    /// The answer to `STLS` (`pop3_state_starttls_resp`): bytes after it
    /// were not sent under TLS and are refused, before what it says.
    fn starttls<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut Pop3Conn,
        carrier: &mut Carrier<'_>,
        code: Pop3Reply,
    ) -> Step {
        if pc.pp.after_reply().is_some_and(|after| !after.is_empty()) {
            return Err(ErrorKind::WeirdServerReply);
        }
        if code != Pop3Reply::Ok {
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
        pc: &mut Pop3Conn,
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

    /// Log in the most secure way both ends allow: SASL, APOP, clear text
    /// (`pop3_perform_authentication`).
    fn authenticate<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut Pop3Conn,
        carrier: &mut Carrier<'_>,
    ) -> Step {
        let can = self.sasl_step(cx, pc, |sasl, sx| sasl.can_authenticate(sx));
        if !can {
            set_state(cx, pc, State::Stop);
            return Ok(());
        }
        if pc.offered.both(pc.preferred, AuthTypes::SASL) {
            let progress = self.sasl_step(cx, pc, |sasl, sx| sasl.start(sx, false));
            match progress.map_err(|e| sasl_failed(cx, e))? {
                Progress::Sends(send) => {
                    self.sasl_send(cx, pc, carrier, send)?;
                    set_state(cx, pc, State::Auth);
                    return Ok(());
                }
                Progress::Idle => {}
                Progress::Done => return Ok(()),
            }
        }
        self.fallback(cx, pc, carrier, false)
    }

    /// APOP or clear text, or else nothing to log in with: what SASL
    /// leaves (`pop3_perform_authentication`, `pop3_state_auth_resp`).
    fn fallback<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut Pop3Conn,
        carrier: &mut Carrier<'_>,
        cancelled: bool,
    ) -> Step {
        if pc.offered.both(pc.preferred, AuthTypes::APOP) {
            return self.apop(cx, pc, carrier);
        }
        if pc.offered.both(pc.preferred, AuthTypes::CLEARTEXT) {
            let Some(credentials) = login_of(&pc.cold) else {
                set_state(cx, pc, State::Stop);
                return Ok(());
            };
            let mut user = Vec::new();
            user.try_extend_from_slice(credentials.user())
                .map_err(|_| ErrorKind::OutOfMemory)?;
            drive::send(cx, &mut pc.pp, carrier, None, &[b"USER ", &user])?;
            set_state(cx, pc, State::User);
            return Ok(());
        }
        if cancelled {
            return Err(trace::fail(
                cx,
                ErrorKind::LoginDenied,
                format_args!("Authentication cancelled"),
            ));
        }
        self.sasl_step(cx, pc, |sasl, sx| sasl.blocked(sx));
        Err(ErrorKind::LoginDenied)
    }

    /// `APOP`, the MD5 of the greeting's timestamp and the password
    /// (`pop3_perform_apop`).
    fn apop<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut Pop3Conn,
        carrier: &mut Carrier<'_>,
    ) -> Step {
        let Some(credentials) = login_of(&pc.cold) else {
            set_state(cx, pc, State::Stop);
            return Ok(());
        };
        let mut h = Md5::default();
        h.update(pc.apop.as_deref().unwrap_or_default());
        h.update(credentials.secret().password());
        let digest = h.finish();
        let mut secret = Vec::new();
        for b in &digest[..16] {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            secret
                .try_extend_from_slice(&[HEX[usize::from(b >> 4)], HEX[usize::from(b & 15)]])
                .map_err(|_| ErrorKind::OutOfMemory)?;
        }
        let mut user = Vec::new();
        user.try_extend_from_slice(credentials.user())
            .map_err(|_| ErrorKind::OutOfMemory)?;
        drive::send(
            cx,
            &mut pc.pp,
            carrier,
            None,
            &[b"APOP ", &user, b" ", &secret],
        )?;
        set_state(cx, pc, State::Apop);
        Ok(())
    }

    /// Send what SASL asks (`pop3_perform_auth`, `pop3_continue_auth`,
    /// `pop3_cancel_auth`).
    fn sasl_send<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut Pop3Conn,
        carrier: &mut Carrier<'_>,
        send: sasl::Send,
    ) -> Step {
        match send {
            sasl::Send::Auth {
                mech,
                initial: None,
            } => drive::send(cx, &mut pc.pp, carrier, None, &[b"AUTH ", mech.as_bytes()]),
            sasl::Send::Auth {
                mech,
                initial: Some(ir),
            } => {
                let ir: &[u8] = if ir.is_empty() { b"=" } else { &ir };
                drive::send(
                    cx,
                    &mut pc.pp,
                    carrier,
                    None,
                    &[b"AUTH ", mech.as_bytes(), b" ", ir],
                )
            }
            sasl::Send::Continue(resp) => drive::send(cx, &mut pc.pp, carrier, None, &[&resp]),
            sasl::Send::Cancel => drive::send(cx, &mut pc.pp, carrier, None, &[b"*"]),
        }
    }

    /// An answer in the SASL exchange (`pop3_state_auth_resp`).
    fn auth<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut Pop3Conn,
        carrier: &mut Carrier<'_>,
        code: Pop3Reply,
    ) -> Step {
        let code = match code {
            Pop3Reply::Ok => Code::Final,
            Pop3Reply::More => Code::Continue,
            Pop3Reply::Err => Code::Other,
        };
        let message = server_message(pc.pp.reply_line().expect("a reply was given out"));
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
            Progress::Idle => self.fallback(cx, pc, carrier, true),
        }
    }

    /// Send the transfer's command (`pop3_perform_command`): `LIST`
    /// without a message id or for a list only, `RETR` with one, or the
    /// application's; its answer has a body if the command's has lines.
    fn command<H: Host>(&mut self, cx: &mut StepCx<'_, H>, lease: &mut ConnLease) -> Step {
        let list_only = cx.easy().options().line.list_only;
        let mut command: &[u8] = if self.id.is_empty() || list_only {
            if !self.id.is_empty() {
                // A message's LIST: one line, no body.
                self.body = false;
            }
            b"LIST"
        } else {
            b"RETR"
        };
        if let Some(custom) = self.custom.as_deref().filter(|c| !c.is_empty()) {
            command = custom;
        }
        let multiline = is_multiline(command);
        let mut owned = Vec::new();
        owned
            .try_extend_from_slice(command)
            .map_err(|_| ErrorKind::OutOfMemory)?;
        let (pc, mut carrier) = pop3_of(lease);
        if self.id.is_empty() {
            drive::send(cx, &mut pc.pp, &mut carrier, None, &[&owned])?;
        } else {
            drive::send(
                cx,
                &mut pc.pp,
                &mut carrier,
                None,
                &[&owned, b" ", &self.id],
            )?;
        }
        set_state(cx, pc, State::Command);
        self.no_body = !multiline;
        if !multiline {
            self.body = false;
        }
        Ok(())
    }

    /// The answer to the transfer's command (`pop3_state_command_resp`):
    /// what came after it is the body's start.
    fn command_resp<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut Pop3Conn,
        code: Pop3Reply,
    ) -> Step {
        if code != Pop3Reply::Ok {
            set_state(cx, pc, State::Stop);
            return Err(ErrorKind::WeirdServerReply);
        }
        self.eob = Eob::after_ok();
        if self.body {
            self.receiving = true;
            let after = pc.pp.after_reply().unwrap_or_default();
            let n = after.len();
            if n > 0 {
                let mut held = Vec::new();
                held.try_extend_from_slice(after)
                    .map_err(|_| ErrorKind::OutOfMemory)?;
                pc.pp.consume_after_reply(n);
                self.body_bytes(cx, &held)?;
            }
        } else if let Some(after) = pc.pp.after_reply() {
            // What followed the answer is dropped.
            let n = after.len();
            pc.pp.consume_after_reply(n);
        }
        set_state(cx, pc, State::Stop);
        Ok(())
    }
}

/// Say `CAPA`, the server's capabilities forgotten (`pop3_perform_capa`).
fn capa<H: Host>(cx: &mut StepCx<'_, H>, pc: &mut Pop3Conn, carrier: &mut Carrier<'_>) -> Step {
    pc.sasl.forget_offers();
    pc.tls_offered = false;
    drive::send(cx, &mut pc.pp, carrier, None, &[b"CAPA"])?;
    set_state(cx, pc, State::Capa);
    Ok(())
}

/// The connection's POP3 state and what it works over.
fn pop3_of(lease: &mut ConnLease) -> (&mut Pop3Conn, Carrier<'_>) {
    match lease.get().line_mut() {
        Some((LineConn::Pop3(pc), carrier)) => (pc, carrier),
        _ => unreachable!("a POP3 transfer's connection keeps POP3's state"),
    }
}

/// Move the state on, said as C's debug build says it (`pop3_state`).
fn set_state<H: Host>(cx: &mut StepCx<'_, H>, pc: &mut Pop3Conn, state: State) {
    if pc.state != state {
        trace::debug_info(
            cx,
            format_args!(
                "POP3 {:p} state change from {} to {}",
                pc as *const Pop3Conn,
                pc.state.name(),
                state.name()
            ),
        );
    }
    pc.state = state;
}

/// The reply's character, as C prints its code.
fn char_of(code: Pop3Reply) -> char {
    match code {
        Pop3Reply::Ok => '+',
        Pop3Reply::Err => '-',
        Pop3Reply::More => '*',
    }
}

fn access_denied<H: Host>(cx: &mut StepCx<'_, H>, code: Pop3Reply) -> ErrorKind {
    trace::fail(
        cx,
        ErrorKind::LoginDenied,
        format_args!("Access denied. {}", char_of(code)),
    )
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

/// The message of a SASL answer, `line` after its first two bytes and
/// the blanks after them, without the blanks and line end at its end;
/// nothing of a line no longer than two (`pop3_get_message`).
fn server_message(line: &[u8]) -> &[u8] {
    if line.len() <= 2 {
        return &[];
    }
    let mut m = &line[2..];
    while let [b' ' | b'\t', rest @ ..] = m {
        m = rest;
    }
    while let [rest @ .., b' ' | b'\t' | b'\r' | b'\n'] = m {
        m = rest;
    }
    m
}

/// The URL's or the application's login options (`pop3_parse_url_options`):
/// `AUTH=` and a SASL mechanism, `*` for any, or `+APOP`; any other is
/// malformed.
fn parse_options(pc: &mut Pop3Conn, mut options: &[u8]) -> Step {
    let mut result = Ok(());
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
        if key.len() >= 5 && key[..5].eq_ignore_ascii_case(b"AUTH=") {
            if !pc.sasl.url_auth(value) {
                // `curl_strnequal(value, "+APOP", len)`: a prefix of it
                // will do.
                let apop = b"+APOP";
                if !value.is_empty()
                    && value.len() <= apop.len()
                    && value.eq_ignore_ascii_case(&apop[..value.len()])
                {
                    pc.preferred = AuthTypes::APOP;
                    pc.sasl.prefer_none();
                } else {
                    result = Err(ErrorKind::UrlMalformat);
                }
            }
        } else {
            result = Err(ErrorKind::UrlMalformat);
        }
        options = &options[end..];
        if let [b';', rest @ ..] = options {
            options = rest;
        }
    }
    if pc.preferred != AuthTypes::APOP {
        let pref = pc.sasl.preferred();
        pc.preferred = if pref == Mechs::NONE {
            AuthTypes::NONE
        } else if pref == Mechs::DEFAULT {
            AuthTypes::ANY
        } else {
            AuthTypes::SASL
        };
    }
    result
}

/// The commands POP3 knows: whether each answers with lines ending at a
/// dot, alone and with arguments (`pop3cmds`).
const COMMANDS: [(&[u8], bool, bool); 18] = [
    (b"APOP", false, false),
    (b"AUTH", false, false),
    (b"CAPA", true, true),
    (b"DELE", false, false),
    (b"LIST", true, false),
    (b"MSG", true, true),
    (b"NOOP", false, false),
    (b"PASS", false, false),
    (b"QUIT", false, false),
    (b"RETR", true, true),
    (b"RSET", false, false),
    (b"STAT", false, false),
    (b"STLS", false, false),
    (b"TOP", true, true),
    (b"UIDL", true, false),
    (b"USER", false, false),
    (b"UTF8", false, false),
    (b"XTND", true, true),
];

/// Whether `command` answers with lines up to a dot (`pop3_is_multiline`):
/// one POP3 does not know is taken to, as curl always did.
fn is_multiline(command: &[u8]) -> bool {
    for (name, alone, with_args) in COMMANDS {
        let n = name.len();
        if command.len() >= n && command[..n].eq_ignore_ascii_case(name) {
            match command.get(n) {
                None => return alone,
                Some(b' ') => return with_args,
                Some(_) => {}
            }
        }
    }
    true
}

/// POP3 connects over its connection by logging in, and makes its
/// request in DO, on in DOING until the command is answered
/// (`pop3_connect`, `pop3_multi_statemach`, `pop3_do`, `pop3_doing`).
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
                trace::debug_info(cx, format_args!("DO phase starts"));
                self.command(cx, lease)?;
                let ran = self.run(cx, lease);
                // Said as the state stops, the answer refused or not
                // (`pop3_perform`).
                if pop3_of(lease).0.state == State::Stop {
                    trace::debug_info(cx, format_args!("DO phase is complete"));
                }
                Ok(if ran? { DoStep::Did } else { DoStep::Doing })
            }
            DoPhase::Doing => match self.run(cx, lease) {
                Err(e) => {
                    trace::debug_info(cx, format_args!("DO phase failed"));
                    Err(e)
                }
                Ok(true) => {
                    trace::debug_info(cx, format_args!("DO phase is complete"));
                    Ok(DoStep::Did)
                }
                Ok(false) => Ok(DoStep::Doing),
            },
            DoPhase::More => unreachable!("POP3 has no second half"),
        }
    }

    fn waits(&self, _: Waiting) -> Events {
        self.wants
    }
}

#[cfg(test)]
mod tests;
