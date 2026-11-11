//! SMTP (`lib/smtp.c`): a connection that greets the server with `EHLO`,
//! or `HELO` where that is refused, upgrades with `STARTTLS` if TLS is
//! asked for and the connection is not over it already, and logs in by
//! SASL if the server offers it; a request per transfer: a mail, its
//! `MAIL FROM`, a `RCPT TO` for each recipient and its body after
//! `DATA`, or a command (`VRFY`, `EXPN`, `HELP` or the application's)
//! whose answer is the body. The answer to a mail's body is read in
//! DONE, as C's `smtp_done` reads it.

use curl_alloc::{TryArc, TryVec as _};

use super::mail::{self, sasl_failed, sasl_step};
use super::pingpong::Pingpong;
use super::pingpong::drive::{self, Read};
use super::pingpong::smtp::{Smtp, SmtpReply};
use super::{Connect, DoPhase, DoStep, Finish, ProtoStep, Waiting};
use crate::auth::creds::{Credentials, Takes};
use crate::auth::sasl::{self, Code, Mechs, Progress, Sasl};
use crate::components::Component;
use crate::conn::io::Events;
use crate::conn::line::{Goodbye, LineConn};
use crate::conn::mux::Carrier;
use crate::conn::{ConnLease, RouteCold, Scheme};
use crate::deliver::{Directions, Pause, Pipeline, Reach};
use crate::error::{ErrorKind, url_error};
use crate::idn::Idn;
use crate::multi::Host;
use crate::multi::state::StepCx;
use crate::options::{ConnectOnly, Method, UploadSource, UseSsl};
use crate::time::Instant;
use crate::trace;
use crate::upload::chain::Body;
use crate::upload::sending::Sending;
use crate::upload::{self, Readers, Upload};
use crate::url::{GetOptions, Part, Url, decode_but_control};

/// SMTP's SASL (`saslsmtp`): the longest line less `AUTH `, a space and
/// CRLF.
static SASL: sasl::Params = sasl::Params {
    service: "smtp",
    max_ir: 512 - 8,
    default: Mechs::DEFAULT,
    base64: true,
};

/// The longest host name the EHLO domain is read from (`HOSTNAME_MAX`).
const HOSTNAME_MAX: usize = 1024;

/// Where the connection's back and forth is (`smtpstate`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Stop,
    ServerGreet,
    Ehlo,
    Helo,
    StartTls,
    UpgradeTls,
    Auth,
    Command,
    Mail,
    Rcpt,
    Data,
    PostData,
}

impl State {
    fn name(self) -> &'static str {
        match self {
            State::Stop => "STOP",
            State::ServerGreet => "SERVERGREET",
            State::Ehlo => "EHLO",
            State::Helo => "HELO",
            State::StartTls => "STARTTLS",
            State::UpgradeTls => "UPGRADETLS",
            State::Auth => "AUTH",
            State::Command => "COMMAND",
            State::Mail => "MAIL",
            State::Rcpt => "RCPT",
            State::Data => "DATA",
            State::PostData => "POSTDATA",
        }
    }
}

/// What SMTP keeps on its connection (`struct smtp_conn`).
#[derive(Debug)]
pub(crate) struct SmtpConn {
    pp: Pingpong,
    state: State,
    sasl: Sasl,
    /// The name `EHLO` and `HELO` give (`domain`), decoded.
    domain: Vec<u8>,
    /// The server offers `STARTTLS` (`tls_supported`).
    tls_offered: bool,
    /// The server takes a mail's size (`size_supported`, RFC 1870).
    size_offered: bool,
    /// The server takes mailboxes in UTF-8 (`utf8_supported`, RFC 6531).
    utf8_offered: bool,
    /// The server offers `AUTH` (`auth_supported`).
    auth_offered: bool,
    /// The last transfer on it set up nothing to exchange after its
    /// request (`recv_idx` and `send_idx` both -1, which
    /// `Curl_xfer_setup_nop` leaves on the connection): the next one that
    /// sets up nothing either goes from DID to DONE.
    no_socket: bool,
    /// What of its route few routes have, the credentials it logs in
    /// with among it (`conn->creds`): the route owns them.
    cold: Option<TryArc<RouteCold>>,
    /// The TLS identity it is upgraded with, made for it as it was set
    /// up, if it may be (`NetRoute::upgrade`).
    upgrade: Option<TryArc<crate::tls::TlsIdentity>>,
}

impl SmtpConn {
    /// Say `QUIT`, as the connection shuts down, unless it is `dead` or
    /// a command waits half sent (`smtp_disconnect`): awaited while what the
    /// connection did not take of it waits to go, or its answer does,
    /// which [`goodbye_answer`](Self::goodbye_answer) moves on.
    pub(crate) fn goodbye(
        &mut self,
        cx: &mut dyn crate::conn::layer::LayerCx,
        mut below: Carrier<'_>,
        dead: bool,
    ) -> Goodbye {
        if dead || self.pp.needs_flush() {
            return Goodbye::Done;
        }
        drive::goodbye(
            cx,
            &mut self.pp,
            &mut below,
            &Smtp {
                continuations: false,
            },
            None,
            b"QUIT",
        )
    }

    /// Send the rest of `QUIT`, then read on its answer, a whole reply
    /// (`smtp_block_statemach` in `SMTP_QUIT`).
    pub(crate) fn goodbye_answer(
        &mut self,
        cx: &mut dyn crate::conn::layer::LayerCx,
        mut below: Carrier<'_>,
    ) -> Goodbye {
        drive::goodbye_answer(
            cx,
            &mut self.pp,
            &mut below,
            &Smtp {
                continuations: false,
            },
        )
    }

    /// What the goodbye waits on: to send the rest of `QUIT`, or its
    /// answer.
    pub(crate) fn goodbye_wants(&self) -> Events {
        drive::waits(&self.pp)
    }
}

/// A mailbox as a command gives it (`smtp_parse_address`): its local
/// part, its host if it names one, in ASCII where an IDN library could
/// convert it, and what followed its closing bracket.
#[derive(Debug)]
struct Mailbox {
    local: Vec<u8>,
    host: Option<Vec<u8>>,
    /// The host was converted to ASCII (`host.encalloc`).
    converted: bool,
    suffix: Vec<u8>,
}

impl Mailbox {
    /// Whether the mailbox is in UTF-8, in either part, converted or not
    /// (RFC 6531 section 3.1).
    fn in_utf8(&self) -> bool {
        self.converted
            || !self.local.is_ascii()
            || self.host.as_ref().is_some_and(|h| !h.is_ascii())
    }

    /// The mailbox in brackets, its suffix after them: `<local@host>`,
    /// or `<local>` for one the server is left to refuse.
    fn bracketed(&self) -> Result<Vec<u8>, ErrorKind> {
        let oom = |_| ErrorKind::OutOfMemory;
        let mut out = Vec::new();
        out.try_push(b'<').map_err(oom)?;
        out.try_extend_from_slice(&self.local).map_err(oom)?;
        if let Some(host) = &self.host {
            out.try_push(b'@').map_err(oom)?;
            out.try_extend_from_slice(host).map_err(oom)?;
        }
        out.try_push(b'>').map_err(oom)?;
        out.try_extend_from_slice(&self.suffix).map_err(oom)?;
        Ok(out)
    }
}

/// Why a mailbox could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AddressError {
    /// It holds a CR or LF, which would end the command and start
    /// another.
    LineEnd,
    OutOfMemory,
}

/// Read `given`, a mailbox the application names, into its parts
/// (`smtp_parse_address`): its brackets taken off, what follows the
/// closing one kept, the host after the first `@` converted to ASCII if
/// it can be, else sent as it is (RFC 6531 section 3.2).
fn mailbox(given: &[u8], idn: Option<&dyn Idn>) -> Result<Mailbox, AddressError> {
    if given.iter().any(|&b| b == b'\r' || b == b'\n') {
        return Err(AddressError::LineEnd);
    }
    let (mut local, suffix): (&[u8], &[u8]) = match given.strip_prefix(b"<") {
        Some(inner) => match inner.iter().rposition(|&b| b == b'>') {
            Some(end) => (&inner[..end], &inner[end + 1..]),
            None => (inner, b""),
        },
        None => (given.strip_suffix(b">").unwrap_or(given), b""),
    };
    let mut host = None;
    if let Some(at) = local.iter().position(|&b| b == b'@') {
        host = Some(&local[at + 1..]);
        local = &local[..at];
    }
    let copy = |bytes: &[u8]| -> Result<Vec<u8>, AddressError> {
        let mut v = Vec::new();
        v.try_extend_from_slice(bytes)
            .map_err(|_| AddressError::OutOfMemory)?;
        Ok(v)
    };
    let (host, converted) = match host {
        None => (None, false),
        // A host that cannot be converted goes in UTF-8, whatever kept it
        // from converting (`(void)Curl_idnconvert_hostname`).
        Some(name) => match crate::idn::lookup_name(idn, name) {
            Ok(Some(ascii)) => (Some(ascii), true),
            Ok(None) | Err(_) => (Some(copy(name)?), false),
        },
    };
    Ok(Mailbox {
        local: copy(local)?,
        host,
        converted,
        suffix: copy(suffix)?,
    })
}

/// [`mailbox`], its refusal said as C says it.
fn parse_address<H: Host>(
    cx: &mut StepCx<'_, H>,
    given: &[u8],
    idn: Option<&dyn Idn>,
) -> Result<Mailbox, ErrorKind> {
    mailbox(given, idn).map_err(|e| match e {
        AddressError::LineEnd => trace::fail(
            cx,
            ErrorKind::BadFunctionArgument,
            format_args!("Refusing to send email address with a CR or LF"),
        ),
        AddressError::OutOfMemory => ErrorKind::OutOfMemory,
    })
}

/// An SMTP transfer (`struct SMTP`, and what C's request keeps of it).
#[derive(Debug)]
pub(crate) struct Request {
    pub(super) base: super::base::RequestBase,
    /// The URL's path, encoded: the EHLO domain, read as the connection
    /// is first spoken over.
    path: Vec<u8>,
    /// The URL's login options, decoded (`state.up.options`).
    url_options: Option<Vec<u8>>,
    /// The application's command, decoded in DO (`custom`).
    custom: Option<Vec<u8>>,
    /// The recipient the command or `RCPT TO` is for, by its place in
    /// the application's list (`rcpt`).
    rcpt: usize,
    /// The last code a `RCPT TO` was refused with (`rcpt_last_error`).
    rcpt_last_error: u32,
    /// A `RCPT TO` was taken (`rcpt_had_ok`).
    rcpt_had_ok: bool,
    /// The mail's size as the application gave it, for the progress
    /// (`state.infilesize`).
    upload_size: Option<u64>,
    /// No body is wanted (`req.no_body`, `PPTRANSFER_INFO`).
    no_body: bool,
    /// The request was made and its answer has no transfer after it
    /// (`Curl_xfer_setup_nop`).
    nothing_after: bool,
    /// The mail's body, while it goes (`KEEP_SEND`).
    sending: Option<Box<Sending>>,
    /// Where DONE's blocking drive's round is.
    round: drive::Blocking,
    /// What DONE was told, for its trace once its answer is read.
    status: Result<(), ErrorKind>,
    premature: bool,
    /// The mail's body is all sent (`upload_done`): the server's lines
    /// from here start the response's time.
    upload_done: bool,
    /// When DONE, as it awaits its answer, looks again.
    due: Option<Instant>,
    /// What TLS is made with and said as as the connection is upgraded.
    in_place: crate::multi::state::tls::InPlace,
    /// The answers' bytes (`req.headerbytecount`).
    header_bytes: u64,
}

/// The ways a step of the back and forth can fail.
type Step = Result<(), ErrorKind>;

impl Request {
    /// Its setup for the connection went well (`smtp_setup_connection`'s
    /// trace).
    pub(crate) fn set_up_said<H: Host>(cx: &mut StepCx<'_, H>) {
        trace::of(
            cx,
            Component::Smtp,
            format_args!("smtp_setup_connection() -> 0"),
        );
    }

    /// A transfer of `url`, `smtps` if `secured`: its peer, the
    /// credentials its URL gives and the application's where `before`
    /// lets them go, a `.netrc`'s if asked for (`smtp_setup_connection`,
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
        let name: &[u8] = if secured { b"smtps" } else { b"smtp" };
        let scheme = Scheme::named(name).expect("libcurl knows SMTP");
        let scope = cx.easy().options().address_scope;
        let idn = cx.easy().libraries().idn;
        let peer = super::url_peer((scheme, host, port), url, scope, idn)?;
        let pipeline = Pipeline::new(Reach::Network);
        let mut base = super::base::RequestBase::new(peer, before.origins, pipeline);
        let takes = Takes::of(Some(scheme));
        let credentials = super::request_credentials(cx, base.gate(), url, takes)?;
        base.credentials = super::with_netrc(credentials, base.peer().name(), takes, cx)?;
        let encoded = GetOptions {
            url_encode: true,
            ..GetOptions::NONE
        };
        let path = url.get(Part::Path, encoded).map_err(url_error)?;
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
            base,
            path,
            url_options,
            custom: None,
            rcpt: 0,
            rcpt_last_error: 0,
            rcpt_had_ok: false,
            upload_size: None,
            no_body: cx.easy().options().method == Method::Head,
            nothing_after: false,
            sending: None,
            round: drive::Blocking::default(),
            status: Ok(()),
            premature: false,
            upload_done: false,
            due: None,
            in_place: Default::default(),
            header_bytes: 0,
        })
    }

    /// Its credentials, which its route takes.
    pub(crate) fn take_login(&mut self) -> Option<Credentials> {
        self.base.credentials.take()
    }

    /// Whether nothing came back for the request, which has not run to
    /// its end: one that may be made again on a fresh connection, its
    /// reused one having died (`Curl_retry_request` for a scheme outside
    /// HTTP's, `req.bytecount + req.headerbytecount`).
    pub(crate) fn received_nothing(&self) -> bool {
        self.header_bytes == 0 && self.base.pipeline.bytecount() == 0 && !self.no_body
    }

    /// When DONE, as it awaits its answer, looks again: its poll's end.
    pub(crate) fn due(&self) -> Option<Instant> {
        self.due
    }

    /// Whether the request, once made, has anything more to do over the
    /// connection before DONE: a mail's body to send.
    pub(crate) fn exchanges(&self) -> bool {
        !self.nothing_after
    }

    /// Whether the mail's body has more to send.
    pub(crate) fn sending(&self) -> bool {
        self.sending.is_some()
    }

    /// What the exchange waits for on the connection's socket.
    pub(crate) fn interest(&self, pause: Pause) -> Events {
        if self.sending.is_some() && !pause.send_paused() {
            Events::OUT
        } else {
            Events::NONE
        }
    }

    /// The transfer is over (`smtp_done`): one that failed leaves its
    /// connection to close; a mail reads the answer to its body, and fails
    /// as it says. `exchanged` is C's `req.done`, which the progress
    /// checked meanwhile reads.
    pub(crate) fn done<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        result: Result<(), ErrorKind>,
        premature: bool,
        exchanged: bool,
    ) -> Finish {
        self.status = result;
        self.premature = premature;
        if result.is_err() {
            crate::multi::mstate::trace(cx, format_args!("SMTP done with bad status"));
            lease.get().mark_close();
            return self.finished(cx, result);
        }
        if cx.easy().options().connect_only != ConnectOnly::No || !mails(cx) {
            return self.finished(cx, Ok(()));
        }
        let (pc, _) = smtp_of(lease);
        set_state(cx, pc, State::PostData);
        self.finishing(cx, lease, exchanged)
    }

    /// Read on the answer `done` awaits (`smtp_block_statemach`), as far
    /// as the connection lets it now.
    pub(crate) fn finishing<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        exchanged: bool,
    ) -> Finish {
        match self.run_done(cx, lease, exchanged) {
            Ok(true) => self.finished(cx, Ok(())),
            Ok(false) => Finish::Waiting,
            Err(e) => self.finished(cx, Err(e)),
        }
    }

    /// DONE is over with `result`, said as `smtp_done` says it.
    fn finished<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        result: Result<(), ErrorKind>,
    ) -> Finish {
        let status = trace::Code(self.status);
        let premature = u8::from(self.premature);
        let code = trace::Code(result);
        trace::of(
            cx,
            Component::Smtp,
            format_args!("smtp_done(status={status}, premature={premature}) -> {code}"),
        );
        Finish::Done(result)
    }

    /// The exchange after the request (`Curl_sendrecv`): the mail's body
    /// sent.
    pub(crate) fn step<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<ProtoStep, ErrorKind> {
        self.base.pipeline.flush(cx)?;
        if let Some(sending) = self.sending.as_deref_mut() {
            if sending.send(cx, lease)? != ProtoStep::Done {
                return Ok(ProtoStep::Blocked);
            }
            self.sending = None;
            self.upload_done = true;
        }
        if self.base.pipeline.holds_output() {
            return Ok(ProtoStep::Blocked);
        }
        Ok(ProtoStep::Done)
    }

    /// The connection's SMTP state, set up the first time
    /// (`smtp_connect`): the URL's or the application's login options
    /// read, then the domain from the URL's path, the greeting awaited.
    fn conn_state<H: Host>(&mut self, cx: &mut StepCx<'_, H>, lease: &mut ConnLease) -> Step {
        let url_options = self.url_options.take();
        let url_options = url_options.as_deref();
        let http = cx.easy().options().http.auth.0;
        let mut sasl = Sasl::new(&SASL, http);
        let options = match cx.easy().options().line.login_options.as_deref() {
            Some(given) => Some(given),
            None => url_options,
        };
        parse_options(&mut sasl, options.unwrap_or_default())?;
        let domain = domain(&self.path)?;
        let pc = SmtpConn {
            pp: Pingpong::new(cx.now()),
            state: State::Stop,
            sasl,
            domain,
            tls_offered: false,
            size_offered: false,
            utf8_offered: false,
            auth_offered: false,
            no_socket: false,
            cold: lease.conn().net_route().and_then(|r| r.cold.clone()),
            upgrade: lease.conn().net_route().and_then(|r| r.upgrade().cloned()),
        };
        let line = curl_alloc::try_box(LineConn::Smtp(pc)).map_err(|_| ErrorKind::OutOfMemory)?;
        lease.get().put_line(line);
        let (pc, _) = smtp_of(lease);
        set_state(cx, pc, State::ServerGreet);
        Ok(())
    }

    /// Run the back and forth as far as the connection lets it now
    /// (`smtp_multi_statemach`): whether it stopped, its phase's work
    /// done.
    fn run<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<bool, ErrorKind> {
        let limit = cx.easy().options().line.server_response;
        self.in_place = crate::multi::state::tls::InPlace::of(lease.conn());
        let (pc, mut carrier) = smtp_of(lease);
        let ran = match drive::runs(cx, &pc.pp, &mut carrier, limit) {
            Ok(true) => self.machine(cx, pc, &mut carrier),
            Ok(false) => Ok(()),
            Err(e) => Err(e),
        };
        ran.map(|()| pc.state == State::Stop)
    }

    /// Run the back and forth on in DONE, as C's blocking drive runs it
    /// (`smtp_block_statemach`) but without waiting: whether it stopped.
    fn run_done<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        exchanged: bool,
    ) -> Result<bool, ErrorKind> {
        let limit = cx.easy().options().line.server_response;
        let (pc, mut carrier) = smtp_of(lease);
        loop {
            let round = &mut self.round;
            let (runs, due) = drive::runs_done(cx, &pc.pp, &mut carrier, limit, exchanged, round)?;
            self.due = Some(due);
            if runs {
                self.machine(cx, pc, &mut carrier)?;
            }
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

    /// The state machine (`smtp_pp_statemachine`).
    fn machine<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut SmtpConn,
        carrier: &mut Carrier<'_>,
    ) -> Step {
        if pc.state == State::UpgradeTls {
            // All bytes are TLS's until its handshake is done
            // (`smtp_perform_upgrade_tls`).
            let Some(identity) = pc.upgrade.clone() else {
                return Err(ErrorKind::NotBuiltIn);
            };
            let shaken = crate::multi::state::tls::upgrade(
                carrier,
                &identity,
                self.base.peer(),
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
                format_args!("smtp_perform_upgrade_tls, connect -> {code}, {done}"),
            );
            match shaken? {
                crate::tls::Handshake::Waiting => return Ok(()),
                // `EHLO` again, under TLS.
                crate::tls::Handshake::Done => ehlo(cx, pc, carrier)?,
            }
        }
        if pc.pp.needs_flush() {
            return drive::flush(cx, &mut pc.pp, carrier);
        }
        loop {
            let ends = Smtp {
                continuations: matches!(pc.state, State::Ehlo | State::Command),
            };
            let read = drive::read(
                cx,
                &mut pc.pp,
                carrier,
                &ends,
                &mut self.base.pipeline,
                &mut self.header_bytes,
                // The server's lines start the response's time once the
                // mail's body is all sent (`upload_done`); before, a
                // command is sent beside a request that sends nothing.
                self.upload_done,
            )?;
            // The latest code is the transfer's, none while no reply is
            // whole (`info.httpcode`, `Curl_pp_readresp`'s 0); a line of
            // many is not a reply's end.
            let code = match read {
                Read::Reply(SmtpReply::Final(code), _) => code.get(),
                Read::Reply(SmtpReply::Continuation, _) => 1,
                Read::Waiting => 0,
            };
            if code != 1 {
                cx.report_mut()
                    .set_reply_code(u16::try_from(code).unwrap_or(u16::MAX));
            }
            if code == 0 {
                return Ok(());
            }
            match pc.state {
                State::ServerGreet => {
                    if code / 100 != 2 {
                        return Err(trace::fail(
                            cx,
                            ErrorKind::WeirdServerReply,
                            format_args!("Got unexpected smtp-server response: {code}"),
                        ));
                    }
                    ehlo(cx, pc, carrier)?;
                }
                State::Ehlo => self.ehlo_resp(cx, pc, carrier, code)?,
                State::Helo => {
                    if code / 100 != 2 {
                        return Err(trace::fail(
                            cx,
                            ErrorKind::RemoteAccessDenied,
                            format_args!("Remote access denied: {code}"),
                        ));
                    }
                    set_state(cx, pc, State::Stop);
                }
                State::StartTls => {
                    self.starttls_resp(cx, pc, carrier, code)?;
                    if pc.state == State::UpgradeTls {
                        return self.machine(cx, pc, carrier);
                    }
                }
                State::Auth => self.auth_resp(cx, pc, carrier, code)?,
                State::Command => self.command_resp(cx, pc, carrier, code)?,
                State::Mail => {
                    if code / 100 != 2 {
                        return Err(trace::fail(
                            cx,
                            ErrorKind::SendError,
                            format_args!("MAIL failed: {code}"),
                        ));
                    }
                    self.rcpt_to(cx, pc, carrier)?;
                }
                State::Rcpt => self.rcpt_resp(cx, pc, carrier, code)?,
                State::Data => self.data_resp(cx, pc, code)?,
                State::PostData => {
                    // The answer to the mail's body ends DONE, refused or
                    // not.
                    set_state(cx, pc, State::Stop);
                    if code != 250 {
                        return Err(ErrorKind::WeirdServerReply);
                    }
                }
                State::Stop | State::UpgradeTls => set_state(cx, pc, State::Stop),
            }
            if pc.state == State::Stop || !pc.pp.more_data() {
                return Ok(());
            }
        }
    }

    /// A line of the answer to `EHLO`, or its end
    /// (`smtp_state_ehlo_resp`): what the server offers noted, then on to
    /// `STARTTLS` or the login; refused, `HELO` instead where TLS is not
    /// required or the connection is over it.
    fn ehlo_resp<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut SmtpConn,
        carrier: &mut Carrier<'_>,
        code: u32,
    ) -> Step {
        let use_ssl = cx.easy().options().line.use_ssl;
        if code / 100 != 2 && code != 1 {
            if use_ssl <= UseSsl::Try || carrier.over_tls() {
                return helo(cx, pc, carrier);
            }
            return Err(trace::fail(
                cx,
                ErrorKind::RemoteAccessDenied,
                format_args!("Remote access denied: {code}"),
            ));
        }
        let line = pc.pp.reply_line().expect("a reply was given out");
        let Some(line) = line.get(4..) else {
            return Err(trace::fail(
                cx,
                ErrorKind::WeirdServerReply,
                format_args!("Unexpectedly short EHLO response"),
            ));
        };
        let starts =
            |word: &[u8]| line.len() >= word.len() && line[..word.len()].eq_ignore_ascii_case(word);
        if starts(b"STARTTLS") {
            pc.tls_offered = true;
        } else if starts(b"SIZE") {
            pc.size_offered = true;
        } else if starts(b"SMTPUTF8") {
            pc.utf8_offered = true;
        } else if starts(b"AUTH ") {
            pc.auth_offered = true;
            let mut offered = Mechs::NONE;
            let mut rest = &line[5..];
            let blank = |b: &u8| matches!(b, b' ' | b'\t' | b'\r' | b'\n');
            loop {
                while let [b, more @ ..] = rest
                    && blank(b)
                {
                    rest = more;
                }
                if rest.is_empty() {
                    break;
                }
                let n = rest.iter().position(blank).unwrap_or(rest.len());
                if let Some((mech, len)) = sasl::decode_mech(&rest[..n])
                    && len == n
                {
                    offered = offered.or(mech);
                }
                rest = &rest[n..];
            }
            pc.sasl.offers(offered);
        }
        if code == 1 {
            return Ok(());
        }
        if use_ssl != UseSsl::None && !carrier.over_tls() {
            // TLS is asked for and the connection is not over it yet.
            if pc.tls_offered {
                drive::send(cx, &mut pc.pp, carrier, None, &[b"STARTTLS"])?;
                set_state(cx, pc, State::StartTls);
                Ok(())
            } else if use_ssl == UseSsl::Try {
                self.authenticate(cx, pc, carrier)
            } else {
                Err(trace::fail(
                    cx,
                    ErrorKind::UseSslFailed,
                    format_args!("STARTTLS not supported."),
                ))
            }
        } else {
            self.authenticate(cx, pc, carrier)
        }
    }

    /// The answer to `STARTTLS` (`smtp_state_starttls_resp`): bytes after
    /// it were not sent under TLS and are refused, before what it says.
    fn starttls_resp<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut SmtpConn,
        carrier: &mut Carrier<'_>,
        code: u32,
    ) -> Step {
        if pc.pp.after_reply().is_some_and(|after| !after.is_empty()) {
            return Err(ErrorKind::WeirdServerReply);
        }
        if code != 220 {
            if cx.easy().options().line.use_ssl != UseSsl::Try {
                return Err(trace::fail(
                    cx,
                    ErrorKind::UseSslFailed,
                    format_args!("STARTTLS denied, code {code}"),
                ));
            }
            return self.authenticate(cx, pc, carrier);
        }
        set_state(cx, pc, State::UpgradeTls);
        Ok(())
    }

    /// Log in by SASL if the server offers `AUTH` and there is something
    /// to log in with, else the connect is done
    /// (`smtp_perform_authentication`).
    fn authenticate<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut SmtpConn,
        carrier: &mut Carrier<'_>,
    ) -> Step {
        let can = sasl_step(cx, self.base.peer(), &pc.cold, &mut pc.sasl, |sasl, sx| {
            sasl.can_authenticate(sx)
        });
        if !pc.auth_offered || !can {
            set_state(cx, pc, State::Stop);
            return Ok(());
        }
        let progress = sasl_step(cx, self.base.peer(), &pc.cold, &mut pc.sasl, |sasl, sx| {
            sasl.start(sx, false)
        });
        match progress.map_err(|e| sasl_failed(cx, e))? {
            Progress::Sends(send) => {
                self.sasl_send(cx, pc, carrier, send)?;
                set_state(cx, pc, State::Auth);
                Ok(())
            }
            Progress::Idle | Progress::Done => {
                sasl_step(cx, self.base.peer(), &pc.cold, &mut pc.sasl, |sasl, sx| {
                    sasl.blocked(sx)
                });
                Err(ErrorKind::LoginDenied)
            }
        }
    }

    /// Send what SASL asks (`smtp_perform_auth`, `smtp_continue_auth`,
    /// `smtp_cancel_auth`).
    fn sasl_send<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut SmtpConn,
        carrier: &mut Carrier<'_>,
        send: sasl::Send,
    ) -> Step {
        let sent = match send {
            sasl::Send::Auth { mech, initial } => match initial {
                None => drive::send(cx, &mut pc.pp, carrier, None, &[b"AUTH ", mech.as_bytes()]),
                Some(ir) => {
                    let ir: &[u8] = if ir.is_empty() { b"=" } else { &ir };
                    drive::send(
                        cx,
                        &mut pc.pp,
                        carrier,
                        None,
                        &[b"AUTH ", mech.as_bytes(), b" ", ir],
                    )
                }
            },
            sasl::Send::Continue(resp) => drive::send(cx, &mut pc.pp, carrier, None, &[&resp]),
            sasl::Send::Cancel => drive::send(cx, &mut pc.pp, carrier, None, &[b"*"]),
        };
        // The exchange moves on once its command is sent.
        sasl_step(cx, self.base.peer(), &pc.cold, &mut pc.sasl, |sasl, sx| {
            sasl.sent(sx, sent.is_ok())
        });
        sent
    }

    /// An answer in the SASL exchange (`smtp_state_auth_resp`).
    fn auth_resp<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut SmtpConn,
        carrier: &mut Carrier<'_>,
        code: u32,
    ) -> Step {
        let step = match code {
            235 => Code::Final,
            334 => Code::Continue,
            _ => Code::Other,
        };
        let message = server_message(pc.pp.reply_line().expect("a reply was given out"));
        let mut copied = Vec::new();
        copied
            .try_extend_from_slice(message)
            .map_err(|_| ErrorKind::OutOfMemory)?;
        let progress = sasl_step(cx, self.base.peer(), &pc.cold, &mut pc.sasl, |sasl, sx| {
            sasl.step(sx, step, &copied)
        });
        match progress.map_err(|e| sasl_failed(cx, e))? {
            Progress::Done => {
                set_state(cx, pc, State::Stop);
                Ok(())
            }
            Progress::Sends(send) => self.sasl_send(cx, pc, carrier, send),
            // No mechanism left after a cancel.
            Progress::Idle => Err(trace::fail(
                cx,
                ErrorKind::LoginDenied,
                format_args!("Authentication cancelled"),
            )),
        }
    }

    /// Read the application's command (`smtp_parse_custom_request`).
    fn read_custom<H: Host>(&mut self, cx: &mut StepCx<'_, H>) -> Step {
        self.custom = match cx.easy().options().http.custom.method.as_deref() {
            None => None,
            Some(custom) => Some(
                decode_but_control(custom)
                    .map_err(url_error)?
                    .ok_or(ErrorKind::UrlMalformat)?,
            ),
        };
        Ok(())
    }

    /// Make the request's first command (`smtp_perform`): a mail's
    /// `MAIL FROM`, or a command.
    fn perform<H: Host>(&mut self, cx: &mut StepCx<'_, H>, lease: &mut ConnLease) -> Step {
        trace::of(cx, Component::Smtp, format_args!("smtp_perform(), start"));
        self.rcpt = 0;
        self.rcpt_had_ok = false;
        self.rcpt_last_error = 0;
        let (pc, mut carrier) = smtp_of(lease);
        if mails(cx) {
            self.mail(cx, pc, &mut carrier)
        } else {
            self.command(cx, pc, &mut carrier)
        }
    }

    /// The recipient the request is at, copied out of the options; none
    /// past the last.
    fn recipient<H: Host>(&self, cx: &StepCx<'_, H>) -> Result<Option<Vec<u8>>, ErrorKind> {
        let Some(rcpt) = cx.easy().options().line.mail_rcpt.iter().nth(self.rcpt) else {
            return Ok(None);
        };
        let mut copy = Vec::new();
        copy.try_extend_from_slice(rcpt)
            .map_err(|_| ErrorKind::OutOfMemory)?;
        Ok(Some(copy))
    }

    /// A command (`smtp_perform_command`): `VRFY` of the recipient, the
    /// application's command of it, or with no recipient the
    /// application's command or `HELP`.
    fn command<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut SmtpConn,
        carrier: &mut Carrier<'_>,
    ) -> Step {
        let custom = self.custom.as_deref().filter(|c| !c.is_empty());
        match (self.recipient(cx)?, custom) {
            (Some(rcpt), None) => {
                let idn = cx.easy().libraries().idn;
                let mailbox = parse_address(cx, &rcpt, idn)?;
                let utf8 = pc.utf8_offered && mailbox.in_utf8();
                let (at, host): (&[u8], &[u8]) = match &mailbox.host {
                    Some(host) => (b"@", host),
                    None => (b"", b""),
                };
                let utf8: &[u8] = if utf8 { b" SMTPUTF8" } else { b"" };
                drive::send(
                    cx,
                    &mut pc.pp,
                    carrier,
                    None,
                    &[b"VRFY ", &mailbox.local, at, host, utf8],
                )?;
            }
            (Some(rcpt), Some(custom)) => {
                let utf8 = pc.utf8_offered && custom == b"EXPN";
                let utf8: &[u8] = if utf8 { b" SMTPUTF8" } else { b"" };
                drive::send(cx, &mut pc.pp, carrier, None, &[custom, b" ", &rcpt, utf8])?;
            }
            (None, custom) => {
                let command = custom.unwrap_or(b"HELP");
                drive::send(cx, &mut pc.pp, carrier, None, &[command])?;
            }
        }
        set_state(cx, pc, State::Command);
        Ok(())
    }

    /// A line of the answer to a command, or its end
    /// (`smtp_state_command_resp`): each line is the body; a recipient's
    /// answer leads to the next recipient's command.
    fn command_resp<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut SmtpConn,
        carrier: &mut Carrier<'_>,
        code: u32,
    ) -> Step {
        let has_rcpt = self.rcpt < cx.easy().options().line.mail_rcpt.iter().count();
        let refused = code / 100 != 2 && code != 1 && !(has_rcpt && code == 553);
        if refused {
            return Err(trace::fail(
                cx,
                ErrorKind::WeirdServerReply,
                format_args!("Command failed: {code}"),
            ));
        }
        if !self.no_body {
            let line = pc.pp.reply_line().expect("a reply was given out");
            self.base.pipeline.body(cx, line)?;
        }
        if code == 1 {
            return Ok(());
        }
        if has_rcpt {
            self.rcpt += 1;
            if self.recipient(cx)?.is_some() {
                return self.command(cx, pc, carrier);
            }
        }
        set_state(cx, pc, State::Stop);
        Ok(())
    }

    /// `MAIL FROM` (`smtp_perform_mail`): the sender, the submitter once
    /// logged in, the size where the server takes it and SMTPUTF8 where a
    /// mailbox needs it; the body set to go after `DATA`.
    fn mail<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut SmtpConn,
        carrier: &mut Carrier<'_>,
    ) -> Step {
        let idn = cx.easy().libraries().idn;
        let copy = |bytes: Option<&[u8]>| -> Result<Option<Vec<u8>>, ErrorKind> {
            bytes
                .map(|b| {
                    let mut v = Vec::new();
                    v.try_extend_from_slice(b)
                        .map_err(|_| ErrorKind::OutOfMemory)?;
                    Ok(v)
                })
                .transpose()
        };
        let line = &cx.easy().options().line;
        let from = copy(line.mail_from.as_deref())?;
        let auth = copy(line.mail_auth.as_deref())?;
        let mut utf8 = false;
        let from = match from {
            Some(given) => {
                let mailbox = parse_address(cx, &given, idn)?;
                utf8 = pc.utf8_offered && mailbox.in_utf8();
                mailbox.bracketed()?
            }
            // The null reverse-path (RFC 5321 section 3.6.3).
            None => copy(Some(b"<>"))?.expect("given"),
        };
        let auth = match auth {
            Some(given) if pc.sasl.used_any() => Some(if given.is_empty() {
                // An empty AUTH (RFC 4954 section 5).
                copy(Some(b"<>"))?.expect("given")
            } else {
                let mailbox = parse_address(cx, &given, idn)?;
                utf8 = utf8 || (pc.utf8_offered && mailbox.in_utf8());
                mailbox.bracketed()?
            }),
            _ => None,
        };
        // A tree goes as a mail message (`MIMESTRATEGY_MAIL`); its size is
        // the reader's, the application's size the source's.
        let mime = matches!(cx.easy().options().upload, UploadSource::Mime(_));
        let upload = if mime {
            Upload::open_mail(cx)?
        } else {
            Upload::open(cx)?
        };
        upload.trace_set(cx);
        // Converted unless empty (`do_init_reader_stack`).
        let converts = cx.easy().options().crlf && upload.size() != Some(0);
        let mut body = Body::new(upload);
        if converts {
            body.convert_lines().map_err(|_| ErrorKind::OutOfMemory)?;
        }
        let size = if mime {
            body.size()
        } else {
            body.upload().size()
        };
        self.upload_size = size;
        let size_text = match size.filter(|&n| n > 0 && pc.size_offered) {
            Some(n) => Some(
                curl_alloc::try_format(format_args!("{n}")).map_err(|_| ErrorKind::OutOfMemory)?,
            ),
            None => None,
        };
        if pc.utf8_offered && !utf8 {
            utf8 = cx
                .easy()
                .options()
                .line
                .mail_rcpt
                .iter()
                .any(|rcpt| !rcpt.is_ascii());
        }
        body.end_as_mail().map_err(|_| ErrorKind::OutOfMemory)?;
        *cx.readers_mut() = body.upload().pausing().map(|client| Readers {
            chunked: false,
            exp100: false,
            mail: true,
            lines: converts,
            client,
        });
        let room = cx.easy().options().limits.upload_buffer.get();
        self.sending = Some(Sending::new(body, room)?);
        let (auth_is, auth) = match &auth {
            Some(auth) => (&b" AUTH="[..], &auth[..]),
            None => (&b""[..], &b""[..]),
        };
        let (size_is, size) = match &size_text {
            Some(size) => (&b" SIZE="[..], size.as_bytes()),
            None => (&b""[..], &b""[..]),
        };
        let utf8: &[u8] = if utf8 { b" SMTPUTF8" } else { b"" };
        drive::send(
            cx,
            &mut pc.pp,
            carrier,
            None,
            &[b"MAIL FROM:", &from, auth_is, auth, size_is, size, utf8],
        )?;
        set_state(cx, pc, State::Mail);
        Ok(())
    }

    /// `RCPT TO` the recipient the request is at
    /// (`smtp_perform_rcpt_to`).
    fn rcpt_to<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut SmtpConn,
        carrier: &mut Carrier<'_>,
    ) -> Step {
        let rcpt = self.recipient(cx)?.expect("a mail has a recipient at hand");
        let idn = cx.easy().libraries().idn;
        let mailbox = parse_address(cx, &rcpt, idn)?.bracketed()?;
        drive::send(cx, &mut pc.pp, carrier, None, &[b"RCPT TO:", &mailbox])?;
        set_state(cx, pc, State::Rcpt);
        Ok(())
    }

    /// The answer to `RCPT TO` (`smtp_state_rcpt_resp`): a refusal fails
    /// the mail unless the application lets refused recipients pass, when
    /// it fails only once none was taken; then the next recipient, or
    /// `DATA`.
    fn rcpt_resp<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut SmtpConn,
        carrier: &mut Carrier<'_>,
        code: u32,
    ) -> Step {
        if code / 100 != 2 {
            self.rcpt_last_error = code;
            if !cx.easy().options().line.mail_rcpt_allowfails {
                return Err(trace::fail(
                    cx,
                    ErrorKind::SendError,
                    format_args!("RCPT failed: {code}"),
                ));
            }
        } else {
            self.rcpt_had_ok = true;
        }
        self.rcpt += 1;
        if self.recipient(cx)?.is_some() {
            return self.rcpt_to(cx, pc, carrier);
        }
        if !self.rcpt_had_ok {
            let last = self.rcpt_last_error;
            return Err(trace::fail(
                cx,
                ErrorKind::SendError,
                format_args!("RCPT failed: {last} (last error)"),
            ));
        }
        drive::send(cx, &mut pc.pp, carrier, None, &[b"DATA"])?;
        set_state(cx, pc, State::Data);
        Ok(())
    }

    /// The answer to `DATA` (`smtp_state_data_resp`): the go-ahead lets
    /// the body go, its answer read in DONE.
    fn data_resp<H: Host>(&mut self, cx: &mut StepCx<'_, H>, pc: &mut SmtpConn, code: u32) -> Step {
        if code != 354 {
            return Err(trace::fail(
                cx,
                ErrorKind::SendError,
                format_args!("DATA failed: {code}"),
            ));
        }
        upload::announce_size(cx, self.upload_size);
        // Sent (`Curl_xfer_setup_send`).
        let ways = Directions {
            recv: false,
            send: true,
        };
        crate::multi::mstate::xfer_setup(cx, ways);
        pc.no_socket = false;
        set_state(cx, pc, State::Stop);
        Ok(())
    }

    /// The request is made (`smtp_dophase_done`): one that wants no body
    /// transfers nothing after it. Whether anything is exchanged after it
    /// is the connection's to say, as what the transfers on it set up
    /// last.
    fn dophase_done<H: Host>(&mut self, cx: &mut StepCx<'_, H>, lease: &mut ConnLease) {
        let (pc, _) = smtp_of(lease);
        if self.no_body {
            crate::multi::mstate::xfer_setup(cx, Directions::default());
            pc.no_socket = true;
            self.sending = None;
        }
        self.nothing_after = pc.no_socket;
    }
}

/// Whether the transfer sends a mail (`state.upload`, or a MIME post,
/// with recipients): else it sends a command.
fn mails<H: Host>(cx: &StepCx<'_, H>) -> bool {
    let options = cx.easy().options();
    let uploads = options.method == Method::Upload
        || (options.method == Method::Post && matches!(options.upload, UploadSource::Mime(_)));
    uploads && options.line.mail_rcpt.iter().next().is_some()
}

/// `EHLO`, what the server offered and the login used forgotten
/// (`smtp_perform_ehlo`).
fn ehlo<H: Host>(cx: &mut StepCx<'_, H>, pc: &mut SmtpConn, carrier: &mut Carrier<'_>) -> Step {
    pc.sasl.forget_offers();
    pc.sasl.forget_used();
    pc.tls_offered = false;
    pc.auth_offered = false;
    let domain = core::mem::take(&mut pc.domain);
    let sent = drive::send(cx, &mut pc.pp, carrier, None, &[b"EHLO ", &domain]);
    pc.domain = domain;
    sent?;
    set_state(cx, pc, State::Ehlo);
    Ok(())
}

/// `HELO`, which logs in with no mechanism (`smtp_perform_helo`).
fn helo<H: Host>(cx: &mut StepCx<'_, H>, pc: &mut SmtpConn, carrier: &mut Carrier<'_>) -> Step {
    pc.sasl.forget_used();
    let domain = core::mem::take(&mut pc.domain);
    let sent = drive::send(cx, &mut pc.pp, carrier, None, &[b"HELO ", &domain]);
    pc.domain = domain;
    sent?;
    set_state(cx, pc, State::Helo);
    Ok(())
}

/// The name `EHLO` gives (`smtp_parse_url_path`): the URL's path after
/// its slash, else the machine's name or `localhost`, decoded.
fn domain(path: &[u8]) -> Result<Vec<u8>, ErrorKind> {
    let mut buf = [0u8; HOSTNAME_MAX + 1];
    let path = path.get(1..).unwrap_or_default();
    let name = if path.is_empty() {
        host_name(&mut buf).unwrap_or(b"localhost")
    } else {
        path
    };
    decode_but_control(name)
        .map_err(url_error)?
        .ok_or(ErrorKind::UrlMalformat)
}

/// The machine's name without its domain, read into `buf`
/// (`Curl_gethostname`): the debug build's `CURL_GETHOSTNAME` in its
/// place if set, none if too long for it.
fn host_name(buf: &mut [u8; HOSTNAME_MAX + 1]) -> Option<&[u8]> {
    #[cfg(feature = "debug-hooks")]
    if curl_os::env::is_set(b"CURL_GETHOSTNAME") {
        let name = fits(curl_os::env::var_into(b"CURL_GETHOSTNAME", buf)?)?;
        return Some(machine(name));
    }
    Some(machine(curl_os::net::host_name(buf)?))
}

/// The name `CURL_GETHOSTNAME` gives, read into a buffer one longer than
/// the longest name: none if it filled it, as C's copy of it needs room
/// for its NUL (`Curl_gethostname`).
#[cfg(feature = "debug-hooks")]
fn fits(name: &[u8]) -> Option<&[u8]> {
    (name.len() <= HOSTNAME_MAX).then_some(name)
}

/// A host's name without its domain: up to its first dot.
fn machine(name: &[u8]) -> &[u8] {
    let end = name.iter().position(|&b| b == b'.').unwrap_or(name.len());
    &name[..end]
}

/// The message of a SASL answer, `line` after its code and the blanks
/// after it, without the blanks and line end at its end; nothing of a
/// line no longer than the code and a space (`smtp_get_message`).
fn server_message(line: &[u8]) -> &[u8] {
    if line.len() <= 4 {
        return &[];
    }
    let mut m = &line[4..];
    while let [b' ' | b'\t', rest @ ..] = m {
        m = rest;
    }
    while let [rest @ .., b' ' | b'\t' | b'\r' | b'\n'] = m {
        m = rest;
    }
    m
}

/// The connection C made for a request that reuses another is let go,
/// never spoken over, its disconnect handler saying so
/// (`smtp_disconnect`): no QUIT goes on one whose protocol never
/// started.
pub(crate) fn let_go_unused<H: Host>(cx: &mut StepCx<'_, H>) {
    trace::of(
        cx,
        Component::Smtp,
        format_args!("smtp_disconnect(), finished"),
    );
}

/// The connection's SMTP state and what it works over.
fn smtp_of(lease: &mut ConnLease) -> (&mut SmtpConn, Carrier<'_>) {
    match lease.get().line_mut() {
        Some((LineConn::Smtp(pc), carrier)) => (pc, carrier),
        _ => unreachable!("an SMTP transfer's connection keeps SMTP's state"),
    }
}

/// Move the state on, said as C's SMTP trace says it (`smtp_state`).
fn set_state<H: Host>(cx: &mut StepCx<'_, H>, pc: &mut SmtpConn, state: State) {
    if pc.state != state {
        trace::of(
            cx,
            Component::Smtp,
            format_args!("state change from {} to {}", pc.state.name(), state.name()),
        );
    }
    pc.state = state;
}

/// The URL's or the application's login options
/// (`smtp_parse_url_options`): `AUTH=` and a SASL mechanism, `*` for
/// any; any other is malformed.
fn parse_options(sasl: &mut Sasl, mut options: &[u8]) -> Step {
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
        if !(key.len() >= 5 && key[..5].eq_ignore_ascii_case(b"AUTH=") && sasl.url_auth(value)) {
            result = Err(ErrorKind::UrlMalformat);
        }
        options = &options[end..];
        if let [b';', rest @ ..] = options {
            options = rest;
        }
    }
    result
}

/// SMTP connects over its connection by greeting the server and logging
/// in, and makes its request in DO, on in DOING until the command is
/// answered (`smtp_connect`, `smtp_multi_statemach`, `smtp_do`,
/// `smtp_doing`).
impl super::Phases for Request {
    fn connect<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<Connect, ErrorKind> {
        mail::connect(self, cx, lease, Self::conn_state, Self::run)
    }

    fn make<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        asked: DoPhase,
    ) -> Result<DoStep, ErrorKind> {
        match asked {
            DoPhase::Do => {
                self.read_custom(cx)?;
                // The progress counts from nothing (`smtp_regular_transfer`).
                crate::progress::reset(cx);
                let performed = self.perform(cx, lease);
                // Connected once the first command went, and done as the
                // state stops, the answer refused or not (`smtp_perform`).
                let connected = performed.is_ok();
                let result = performed.and_then(|()| self.run(cx, lease).map(drop));
                let done = connected && smtp_of(lease).0.state == State::Stop;
                let code = trace::Code(result);
                let (c, d) = (u8::from(connected), u8::from(done));
                trace::of(
                    cx,
                    Component::Smtp,
                    format_args!("smtp_perform() -> {code}, connected={c}, done={d}"),
                );
                if result.is_ok() && done {
                    self.dophase_done(cx, lease);
                }
                trace::of(
                    cx,
                    Component::Smtp,
                    format_args!("smtp_regular_transfer() -> {code}, done={d}"),
                );
                trace::of(
                    cx,
                    Component::Smtp,
                    format_args!("smtp_do() -> {code}, done={d}"),
                );
                result?;
                Ok(if done { DoStep::Did } else { DoStep::Doing })
            }
            DoPhase::Doing => {
                let ran = self.run(cx, lease);
                let done = smtp_of(lease).0.state == State::Stop;
                match ran {
                    Err(_) => trace::debug_info(cx, format_args!("DO phase failed")),
                    Ok(true) => {
                        self.dophase_done(cx, lease);
                        trace::debug_info(cx, format_args!("DO phase is complete"));
                    }
                    Ok(false) => {}
                }
                let code = trace::Code(ran.map(drop));
                let done_n = u8::from(done);
                trace::of(
                    cx,
                    Component::Smtp,
                    format_args!("smtp_doing() -> {code}, done={done_n}"),
                );
                Ok(if ran? { DoStep::Did } else { DoStep::Doing })
            }
            DoPhase::More => unreachable!("SMTP has no second half"),
        }
    }

    fn waits(&self, _: Waiting, line: Option<&LineConn>) -> Events {
        match line {
            Some(LineConn::Smtp(pc)) => drive::waits(&pc.pp),
            Some(_) => unreachable!("a SMTP transfer's connection keeps SMTP's state"),
            None => Events::IN,
        }
    }
}

#[cfg(test)]
mod tests;
