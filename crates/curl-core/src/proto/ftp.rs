//! FTP (`lib/ftp.c`): a control connection that logs in once, after
//! `AUTH` if TLS is asked for and it is not over TLS already, and learns
//! where it starts; then for each transfer the commands that reach its
//! directory, set its type and ask its size, and a data connection of its
//! own, its second, which the transfer's bytes go over, the server's
//! verdict on them read on the control connection as the transfer ends.

mod data;
mod list;
mod path;
mod port;
mod reply;
#[cfg(test)]
mod tests;
mod wildcard;

pub(crate) use wildcard::{Matching, Wildcard};

use std::num::NonZeroU32;

use curl_alloc::{TryArc, TryVec as _};

use self::data::{DataConn, DataTls, Reached};
use self::path::{Path, PathError, TypeCode};
use super::pingpong::Pingpong;
use super::pingpong::drive::{self, Read};
use super::pingpong::ftp::Ftp as Ends;
use super::{Connect, DoPhase, DoStep, Finish, ProtoStep, Waiting};
use crate::auth::creds::{CredentialGate, Credentials, Takes};
use crate::components::Component;
use std::net::{IpAddr, SocketAddr};

use crate::conn::io::{Closer, Events, InterfaceAddress, Recv, Remote, Sock, Socket};
use crate::conn::layer::{LayerAnswer, LayerQuery, Lower as _};
use crate::conn::line::LineConn;
use crate::conn::mux::Carrier;
use crate::conn::{ConnLease, NetRoute, Peer, RecvFailed, RouteCold, Scheme};
use crate::deliver::{self, Expect, Pause, Pipeline, Reach};
use crate::error::{ErrorKind, url_error};
use crate::idn::Idn;
use crate::multi::Host;
use crate::multi::cx::DriveCx;
use crate::multi::state::StepCx;
use crate::options::{Ccc, CreateDirs, FtpMethod, Method, SslAuth, UseSsl};
use crate::progress::rate::Way;
use crate::time::Instant;
use crate::tls::TlsWait;
use crate::trace;
use crate::upload::chain::Body;
use crate::upload::sending::Sending;
use crate::upload::{self, Upload};
use crate::url::{GetOptions, Part, Url};

/// Where the connection's back and forth is (`ftpstate`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Stop,
    Wait220,
    Auth,
    User,
    Pass,
    Acct,
    Pbsz,
    Prot,
    Ccc,
    Pwd,
    Syst,
    Namefmt,
    Quote,
    RetrPrequote,
    StorPrequote,
    ListPrequote,
    Cwd,
    Mkd,
    Mdtm,
    Type,
    ListType,
    RetrListType,
    RetrType,
    StorType,
    Size,
    RetrSize,
    StorSize,
    Rest,
    RetrRest,
    Port,
    Pret,
    Pasv,
    List,
    Retr,
    Stor,
    Quit,
}

impl State {
    fn name(self) -> &'static str {
        match self {
            State::Stop => "STOP",
            State::Wait220 => "WAIT220",
            State::Auth => "AUTH",
            State::User => "USER",
            State::Pass => "PASS",
            State::Acct => "ACCT",
            State::Pbsz => "PBSZ",
            State::Prot => "PROT",
            State::Ccc => "CCC",
            State::Pwd => "PWD",
            State::Syst => "SYST",
            State::Namefmt => "NAMEFMT",
            State::Quote => "QUOTE",
            State::RetrPrequote => "RETR_PREQUOTE",
            State::StorPrequote => "STOR_PREQUOTE",
            State::ListPrequote => "LIST_PREQUOTE",
            State::Cwd => "CWD",
            State::Mkd => "MKD",
            State::Mdtm => "MDTM",
            State::Type => "TYPE",
            State::ListType => "LIST_TYPE",
            State::RetrListType => "RETR_LIST_TYPE",
            State::RetrType => "RETR_TYPE",
            State::StorType => "STOR_TYPE",
            State::Size => "SIZE",
            State::RetrSize => "RETR_SIZE",
            State::StorSize => "STOR_SIZE",
            State::Rest => "REST",
            State::RetrRest => "RETR_REST",
            State::Port => "PORT",
            State::Pret => "PRET",
            State::Pasv => "PASV",
            State::List => "LIST",
            State::Retr => "RETR",
            State::Stor => "STOR",
            State::Quit => "QUIT",
        }
    }
}

/// What a transfer moves over the data connection (`curl_pp_transfer`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Transfer {
    /// The file or the listing (`PPTRANSFER_BODY`).
    Body,
    /// What is known of the file alone, its size and time
    /// (`PPTRANSFER_INFO`).
    Info,
    /// Nothing (`PPTRANSFER_NONE`).
    None,
}

/// How a passive data connection is asked for: its index in C's
/// `mode[]` (`count1` in `FTP_PASV`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Passive {
    Epsv,
    Pasv,
}

/// What FTP keeps on its connection (`struct ftp_conn`, and the
/// connection's FTP bits).
#[derive(Debug)]
pub(crate) struct FtpConn {
    pp: Pingpong,
    state: State,
    /// The type the server was last set to (`transfertype`).
    transfer_type: Option<u8>,
    /// Where the login left it (`entrypath`).
    entry_path: Option<Vec<u8>>,
    /// The directory the last transfer ended in (`prevpath`).
    prev_path: Option<Vec<u8>>,
    /// The server's system, once asked (`server_os`).
    server_os: Option<Vec<u8>>,
    /// The control connection is in a state to say `QUIT` in
    /// (`ctl_valid`).
    ctl_valid: bool,
    /// Passive data connections are asked for with `EPSV`
    /// (`bits.ftp_use_epsv`).
    use_epsv: bool,
    /// Active ones are offered with `EPRT` (`bits.ftp_use_eprt`).
    use_eprt: bool,
    /// The data connection is protected by TLS (`bits.ftp_use_data_ssl`).
    data_tls: bool,
    /// How far its first transfer asked for TLS (`use_ssl`).
    use_ssl: UseSsl,
    /// The data connection, while a transfer has one.
    data: Option<Box<DataConn>>,
    /// What of its route few routes have, the credentials it logs in
    /// with among it: the route owns them.
    cold: Option<TryArc<RouteCold>>,
}

/// The credentials a connection logs in with, as its route holds them.
fn login_of(cold: &Option<TryArc<RouteCold>>) -> Option<&Credentials> {
    cold.as_deref().and_then(|c| c.login.as_ref())
}

impl FtpConn {
    /// Say `QUIT` as the connection shuts down, unless it is `dead`, a
    /// command waits half sent or the control connection is not in a
    /// state for it (`ftp_disconnect`, `ftp_quit`): sent as the
    /// connection takes it now, its answer not waited on.
    pub(crate) fn goodbye(
        &mut self,
        cx: &mut dyn crate::conn::layer::LayerCx,
        mut below: Carrier<'_>,
        dead: bool,
    ) {
        if dead || self.pp.needs_flush() || !self.ctl_valid {
            return;
        }
        self.state = State::Quit;
        // What does not go now is not said.
        let _sent = below.send(cx, b"QUIT\r\n");
    }

    /// Close what it has open beside the connection: a data connection
    /// left by a transfer that never ended.
    pub(crate) fn close(&mut self, net: &mut dyn crate::conn::io::Net) {
        if let Some(data) = self.data.take() {
            data.close(net);
        }
    }

    /// The data connection's sockets, and what each waits for, the
    /// transfer wanting `wanted` of it.
    pub(crate) fn data_pollset(
        &self,
        wanted: Events,
    ) -> impl Iterator<Item = (&dyn Socket, Events)> {
        self.data
            .as_deref()
            .into_iter()
            .flat_map(move |d| d.pollset(wanted))
    }
}

/// What a transfer knows of its control connection, for the data
/// connection it makes.
#[derive(Debug)]
struct Control {
    route: NetRoute,
    number: crate::conn::ConnNumber,
    /// The address it reached, as a peer's host names it.
    remote: Option<Vec<u8>>,
    /// The address it reached, and its end here.
    remote_addr: Option<SocketAddr>,
    local: Option<SocketAddr>,
    /// It goes through a proxy (`Curl_conn_is_tunneling`).
    tunnels: bool,
}

/// Where DONE is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ending {
    /// The answer to the transfer's command is read (`ftp_done_control_reply`).
    Reply,
    /// The commands after the transfer are sent, the one at this index
    /// awaiting its answer (`ftp_sendquote`).
    Postquote(usize),
}

/// An FTP transfer (`struct FTP`, and what C's request and connection
/// keep of it while it runs).
#[derive(Debug)]
pub(crate) struct Request {
    pipeline: Pipeline,
    peer: Peer,
    /// The transfer's credentials, until its route takes them.
    credentials: Option<Credentials>,
    /// The URL's path after its first slash, encoded, its `;type=` cut
    /// off (`ftp->path`).
    encoded: Vec<u8>,
    /// The path decoded and split, in DO (`rawpath`, `dirs`, `file`);
    /// none before, or once let go.
    parsed: Option<Path>,
    /// The transfer is in ASCII (`state.prefer_ascii`).
    prefer_ascii: bool,
    /// A listing is of names alone (`state.list_only`).
    list_only: bool,
    /// The transfer stores a file (`state.upload`).
    upload: bool,
    /// No body is wanted (`req.no_body`).
    no_body: bool,
    transfer: Transfer,
    /// The size of the download, once known (`downloadsize`).
    download_size: Option<u64>,
    /// The file's size, known before asking (`known_filesize`).
    known_filesize: Option<u64>,
    /// Where in the file the transfer starts; below zero, how much of
    /// its end it takes (`state.resume_from`).
    resume_from: i64,
    /// The most of the file asked for (`req.maxdownload`).
    max_download: Option<u64>,
    /// The size the server says the download is (`req.size`).
    size: Option<u64>,
    /// The download is of a range: its end is not checked
    /// (`dont_check`).
    dont_check: bool,
    /// The second connection is to be made after DO (`bits.do_more`).
    do_more: bool,
    /// The connection carried a transfer before this one (`bits.reuse`).
    reused: bool,
    /// The control connection's TLS is being made, after `AUTH`.
    upgrading: bool,
    /// The control connection's TLS is being shut down after `CCC`, until
    /// this instant at the latest.
    clearing: Option<Instant>,
    /// The server is about to move the data, and the data connection's
    /// TLS is still being made: DO_MORE waits for it.
    initiating: bool,
    /// The size of the upload, less what a resume skips
    /// (`state.infilesize`).
    infilesize: Option<u64>,
    /// The directories are reached already (`cwddone`).
    cwd_done: bool,
    /// A `CWD` failed (`cwdfail`).
    cwd_fail: bool,
    /// The `CWD`s sent (`cwdcount`).
    cwd_count: usize,
    /// A `MKD` was tried for the directory a `CWD` failed for (`count2`
    /// in `FTP_CWD`).
    mkd_tried: bool,
    /// The `MKD`s that may fail before the `CWD` is tried again (`count3`
    /// in `FTP_MKD`).
    mkd_may_fail: u8,
    /// The quote command sent, by its index (`count1` in the quote
    /// states).
    quote_at: usize,
    /// It may fail (`count2` in the quote states).
    quote_may_fail: bool,
    /// The `AUTH` asked, by its index in C's `ftpauth[]` (`count1` in
    /// `FTP_AUTH`), the step to the next (`count2`) and the tries made
    /// after the first (`count3`).
    auth_at: usize,
    auth_next: bool,
    auth_tries: u8,
    /// How the passive data connection is asked for.
    passive: Passive,
    /// Which command offered the active one, if one was sent.
    port_cmd: Option<PortCmd>,
    /// `USER` was refused and the command the application gives in its
    /// place sent (`ftp_trying_alternative`).
    trying_alternative: bool,
    /// The upload as it goes.
    sending: Option<Box<Sending>>,
    /// The download is still being read (`KEEP_RECV`).
    receiving: bool,
    /// The upload is all sent (`upload_done`).
    upload_done: bool,
    /// The data was moved to its end (`req.done`).
    received: bool,
    control: Option<Control>,
    /// The peer a connect-to entry names in the origin's place, which TLS
    /// is made with as the connection is upgraded.
    via: Option<TryArc<Peer>>,
    /// What the back and forth waits for on the control connection.
    wants: Events,
    /// The back and forth stopped, as it last ran.
    stopped: bool,
    /// The answers' bytes (`req.headerbytecount`).
    header_bytes: u64,
    /// DONE's step, once it reads on the control connection.
    ending: Option<Ending>,
    /// The bytes of answers DONE has read (`nread`).
    ending_read: u64,
    round: drive::Blocking,
    due: Option<Instant>,
    /// What DONE was given, for its trace and the checks after the
    /// answer.
    status: Result<(), ErrorKind>,
    premature: bool,
    /// The wildcard download the request is one of, while it is made.
    wildcard: Option<Box<Wildcard>>,
}

/// The ways a step of the back and forth can fail.
type Step = Result<(), ErrorKind>;

/// C's `ftpauth[]`.
const AUTHS: [&[u8]; 2] = [b"SSL", b"TLS"];

impl Request {
    /// Its setup for the connection, said (`ftp_setup_connection`'s
    /// trace).
    pub(crate) fn set_up_said<H: Host>(cx: &mut StepCx<'_, H>) {
        trace::of(
            cx,
            Component::Ftp,
            format_args!("[STOP] setup connection -> 0"),
        );
    }

    /// A transfer of `url`, `ftps` if `secured`: its peer, the
    /// credentials its URL and the application give, a `.netrc`'s if
    /// asked for, and its path, a `;type=` cut off its end
    /// (`ftp_setup_connection`, `type_url_check`).
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
        let name: &[u8] = if secured { b"ftps" } else { b"ftp" };
        let scheme = Scheme::named(name).expect("libcurl knows FTP");
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
        let mut encoded = Vec::new();
        encoded
            .try_extend_from_slice(path.strip_prefix(b"/").unwrap_or(&path))
            .map_err(|_| ErrorKind::OutOfMemory)?;
        let options = cx.easy().options();
        let mut prefer_ascii = options.line.ftp.ascii;
        let mut list_only = options.line.list_only;
        match path::type_code(&mut encoded) {
            Some(TypeCode::Ascii) => prefer_ascii = true,
            Some(TypeCode::Names) => list_only = true,
            Some(TypeCode::Binary) => prefer_ascii = false,
            None => {}
        }
        Ok(Request {
            pipeline: Pipeline::new(Reach::Network),
            peer,
            credentials,
            encoded,
            parsed: None,
            prefer_ascii,
            list_only,
            upload: options.method == Method::Upload,
            no_body: options.method == Method::Head,
            transfer: Transfer::Body,
            download_size: Some(0),
            known_filesize: None,
            resume_from: 0,
            max_download: None,
            size: None,
            dont_check: false,
            do_more: false,
            reused: false,
            upgrading: false,
            clearing: None,
            initiating: false,
            infilesize: None,
            cwd_done: false,
            cwd_fail: false,
            cwd_count: 0,
            mkd_tried: false,
            mkd_may_fail: 0,
            quote_at: 0,
            quote_may_fail: false,
            auth_at: 0,
            auth_next: true,
            auth_tries: 0,
            passive: Passive::Epsv,
            port_cmd: None,
            trying_alternative: false,
            sending: None,
            receiving: false,
            upload_done: false,
            received: false,
            control: None,
            via: None,
            wants: Events::IN,
            stopped: false,
            header_bytes: 0,
            ending: None,
            ending_read: 0,
            round: drive::Blocking::default(),
            due: None,
            status: Ok(()),
            premature: false,
            wildcard: None,
        })
    }

    /// The request is one of `wildcard`'s, given to it until it is over.
    pub(crate) fn give_wildcard(&mut self, wildcard: Box<Wildcard>) {
        self.wildcard = Some(wildcard);
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

    /// It is over TLS from the start: its scheme is `ftps`.
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
    /// scheme outside HTTP's, which retries no upload).
    pub(crate) fn received_nothing(&self) -> bool {
        !self.upload
            && !self.no_body
            && self.header_bytes == 0
            && self.pipeline.bytecount() == 0
            && !self.received
    }

    /// Whether the request, once made, moves anything over the data
    /// connection.
    pub(crate) fn exchanges(&self) -> bool {
        self.receiving || self.sending.is_some()
    }

    /// Whether the upload has more to send.
    pub(crate) fn sending(&self) -> bool {
        self.sending.is_some()
    }

    /// When DONE, as it awaits an answer, looks again: its poll's end.
    pub(crate) fn due(&self) -> Option<Instant> {
        self.due
    }

    /// What the exchange waits for on the control connection: nothing,
    /// the data connection's bytes are its own (`Curl_xfer_setup_recv`
    /// of the second socket).
    pub(crate) fn interest(&self, _: Pause) -> Events {
        Events::NONE
    }

    /// What the transfer wants of the data connection: its bytes as the
    /// exchange moves them, unless paused; nothing while the request is
    /// made, its setup waiting for what it needs.
    pub(crate) fn data_wants(&self, pause: Pause, exchanging: bool) -> Events {
        if !exchanging {
            Events::NONE
        } else if self.sending.is_some() {
            if pause.send_paused() {
                Events::NONE
            } else {
                Events::OUT
            }
        } else if self.receiving && !pause.recv_paused() {
            Events::IN
        } else {
            Events::NONE
        }
    }

    /// What the back and forth waits for on the control connection in
    /// `phase` (`ftp_pollset`, `ftp_domore_pollset`): its answer, once
    /// DO_MORE's commands stopped to wait for the data connection.
    fn control_waits(&self, phase: Waiting) -> Events {
        if phase == Waiting::More && self.stopped {
            Events::IN
        } else {
            self.wants
        }
    }
}

/// The connection's FTP state and what it works over.
fn ftp_of(lease: &mut ConnLease) -> (&mut FtpConn, Carrier<'_>) {
    match lease.get().line_mut() {
        Some((LineConn::Ftp(pc), carrier)) => (pc, carrier),
        _ => unreachable!("an FTP transfer's connection keeps FTP's state"),
    }
}

/// Move the state on, said as C's `ftp_state` says it.
fn set_state<H: Host>(cx: &mut StepCx<'_, H>, pc: &mut FtpConn, state: State) {
    if pc.state != state {
        let (from, to) = (pc.state.name(), state.name());
        trace::of(cx, Component::Ftp, format_args!("[{from}] -> [{to}]"));
    }
    pc.state = state;
}

/// A copy of `bytes`, for a command made of what something else holds.
fn copied(bytes: &[u8]) -> Result<Vec<u8>, ErrorKind> {
    let mut v = Vec::new();
    v.try_extend_from_slice(bytes)
        .map_err(|_| ErrorKind::OutOfMemory)?;
    Ok(v)
}

/// Whether a value that becomes part of a command carries a control
/// byte, which would end the command and let another follow it
/// (`ftp_has_ctrl`).
fn has_ctrl(value: &[u8]) -> bool {
    value.iter().any(|&b| b < 0x20)
}

/// Send `parts` as one command.
fn send<H: Host>(
    cx: &mut StepCx<'_, H>,
    pc: &mut FtpConn,
    carrier: &mut Carrier<'_>,
    parts: &[&[u8]],
) -> Step {
    drive::send(cx, &mut pc.pp, carrier, None, parts)
}

impl Request {
    /// The connection's FTP state, set up the first time (`ftp_connect`,
    /// `ftp_setup_connection`'s connection half), the greeting awaited.
    fn conn_state<H: Host>(&mut self, cx: &mut StepCx<'_, H>, lease: &mut ConnLease) -> Step {
        let options = cx.easy().options();
        let pc = FtpConn {
            pp: Pingpong::new(cx.now()),
            state: State::Stop,
            transfer_type: None,
            entry_path: None,
            prev_path: None,
            server_os: None,
            ctl_valid: false,
            use_epsv: options.line.ftp.use_epsv,
            use_eprt: options.line.ftp.use_eprt,
            data_tls: false,
            use_ssl: options.line.use_ssl,
            data: None,
            cold: lease.conn().net_route().and_then(|r| r.cold.clone()),
        };
        let pc = curl_alloc::try_box(pc).map_err(|_| ErrorKind::OutOfMemory)?;
        let line = curl_alloc::try_box(LineConn::Ftp(pc)).map_err(|_| ErrorKind::OutOfMemory)?;
        lease.get().put_line(line);
        let (pc, _) = ftp_of(lease);
        set_state(cx, pc, State::Wait220);
        Ok(())
    }

    /// What the transfer knows of its control connection, read as a
    /// phase starts.
    fn know_control(&mut self, lease: &ConnLease) -> Result<(), ErrorKind> {
        let conn = lease.conn();
        let Some(route) = conn.net_route() else {
            return Err(ErrorKind::FailedInit);
        };
        let remote = match conn.remote().and_then(crate::conn::io::Remote::inet) {
            Some(std::net::SocketAddr::V4(a)) => Some(
                curl_alloc::try_format(format_args!("{}", a.ip()))
                    .map_err(|_| ErrorKind::OutOfMemory)?
                    .into_bytes(),
            ),
            Some(std::net::SocketAddr::V6(a)) => Some(
                curl_alloc::try_format(format_args!("[{}]", a.ip()))
                    .map_err(|_| ErrorKind::OutOfMemory)?
                    .into_bytes(),
            ),
            None => None,
        };
        self.control = Some(Control {
            route: route.clone(),
            number: conn.number(),
            remote,
            remote_addr: conn.remote().and_then(crate::conn::io::Remote::inet),
            local: conn.local(),
            // A SOCKS proxy's, an HTTP proxy's tunnel and an HTTPS
            // proxy's TLS each stay on the connection once it is up
            // (`CF_TYPE_PROXY`); an FTP URL asked of a proxy that
            // forwards it is HTTP's.
            tunnels: route.proxy.is_some(),
        });
        Ok(())
    }

    /// Run the back and forth as far as the connection lets it now
    /// (`ftp_statemach`): whether it stopped, its phase's commands done.
    fn run<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<bool, ErrorKind> {
        let limit = cx.easy().options().line.server_response;
        self.via = lease.conn().net_route().and_then(|r| r.via.clone());
        let (pc, mut carrier) = ftp_of(lease);
        let ran = if self.clearing.is_some() {
            // As C blocks for it, the shutdown's own time limits it, not
            // the server's to answer.
            self.clear_tls(cx, pc, &mut carrier)
        } else {
            match drive::runs(cx, &pc.pp, &mut carrier, limit) {
                Ok(true) => self.machine(cx, pc, &mut carrier),
                Ok(false) => Ok(()),
                Err(e) => Err(e),
            }
        };
        self.wants = drive::waits(&pc.pp);
        self.stopped = pc.state == State::Stop;
        ran.map(|()| pc.state == State::Stop)
    }

    /// Read the answer on, and act on a whole one (`ftp_readresp`): its
    /// code the transfer's latest; a 421 ends the back and forth, the
    /// server having given up on the connection. None while it is not
    /// whole.
    fn read_reply<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut FtpConn,
        carrier: &mut Carrier<'_>,
    ) -> Result<Option<u32>, ErrorKind> {
        let read = drive::read(
            cx,
            &mut pc.pp,
            carrier,
            &Ends,
            &mut self.pipeline,
            &mut self.header_bytes,
            self.upload_done,
        )?;
        let code = match read {
            Read::Reply(code, _) => code.get(),
            Read::Waiting => 0,
        };
        cx.report_mut()
            .set_reply_code(u16::try_from(code).unwrap_or(u16::MAX));
        if code == 421 {
            trace::info(cx, format_args!("We got a 421 - timeout"));
            set_state(cx, pc, State::Stop);
            return Err(ErrorKind::OperationTimedout);
        }
        Ok((code != 0).then_some(code))
    }

    /// The state machine, a whole answer at a time
    /// (`ftp_pp_statemachine`).
    fn machine<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut FtpConn,
        carrier: &mut Carrier<'_>,
    ) -> Step {
        if self.upgrading {
            return self.upgrade_tls(cx, pc, carrier);
        }
        if pc.pp.needs_flush() {
            return drive::flush(cx, &mut pc.pp, carrier);
        }
        let Some(code) = self.read_reply(cx, pc, carrier)? else {
            return Ok(());
        };
        match pc.state {
            State::Wait220 => self.wait_resp(cx, pc, carrier, code),
            State::Auth => self.auth_resp(cx, pc, carrier, code),
            State::User | State::Pass => self.user_resp(cx, pc, carrier, code),
            State::Acct => {
                if code != 230 {
                    return Err(trace::fail(
                        cx,
                        ErrorKind::FtpWeirdPassReply,
                        format_args!("ACCT rejected by server: {code:03}"),
                    ));
                }
                self.logged_in(cx, pc, carrier)
            }
            State::Pbsz => {
                let level: &[u8] = if self.use_ssl(pc) == UseSsl::Control {
                    b"C"
                } else {
                    b"P"
                };
                send(cx, pc, carrier, &[b"PROT ", level])?;
                set_state(cx, pc, State::Prot);
                Ok(())
            }
            State::Prot => {
                if code / 100 == 2 {
                    // The data is protected too, unless only the commands
                    // are to be.
                    pc.data_tls = self.use_ssl(pc) != UseSsl::Control;
                } else if self.use_ssl(pc) > UseSsl::Control {
                    return Err(ErrorKind::UseSslFailed);
                }
                if cx.easy().options().line.ftp.ssl_ccc != Ccc::None {
                    send(cx, pc, carrier, &[b"CCC"])?;
                    set_state(cx, pc, State::Ccc);
                    Ok(())
                } else {
                    pwd(cx, pc, carrier)
                }
            }
            State::Ccc => {
                if code < 500 {
                    // The TLS goes, in the time a shutdown has: tested
                    // with servers that say their close_notify and wait
                    // for none, so the passive way sends none.
                    trace::of(
                        cx,
                        Component::Ssl,
                        format_args!("shutdown and remove SSL, start"),
                    );
                    let time = crate::conn::shutdown::ConnSettings::DEFAULT.shutdown_time();
                    self.clearing = Some(cx.now().after(time));
                    return self.clear_tls(cx, pc, carrier);
                }
                pwd(cx, pc, carrier)
            }
            State::Pwd => self.pwd_resp(cx, pc, carrier, code),
            State::Syst => {
                if code == 215 {
                    let os = copied(reply::system(pc.pp.held()))?;
                    if os.eq_ignore_ascii_case(b"OS/400") {
                        // OS/400's name format 1, the path read again.
                        send(cx, pc, carrier, &[b"SITE NAMEFMT 1"])?;
                        pc.server_os = Some(os);
                        set_state(cx, pc, State::Namefmt);
                        return Ok(());
                    }
                    pc.server_os = Some(os);
                }
                connected(cx, pc);
                Ok(())
            }
            State::Namefmt => {
                if code == 250 {
                    return pwd(cx, pc, carrier);
                }
                connected(cx, pc);
                Ok(())
            }
            State::Quote | State::RetrPrequote | State::StorPrequote | State::ListPrequote => {
                if code >= 400 && !self.quote_may_fail {
                    return Err(trace::fail(
                        cx,
                        ErrorKind::QuoteError,
                        format_args!("QUOT command failed with {code:03}"),
                    ));
                }
                let state = pc.state;
                self.quote(cx, pc, carrier, false, state)
            }
            State::Cwd => self.cwd_resp(cx, pc, carrier, code),
            State::Mkd => {
                let may_fail = self.mkd_may_fail;
                self.mkd_may_fail = may_fail.saturating_sub(1);
                if code / 100 != 2 && may_fail == 0 {
                    return Err(trace::fail(
                        cx,
                        ErrorKind::RemoteAccessDenied,
                        format_args!("Failed to MKD dir: {code:03}"),
                    ));
                }
                set_state(cx, pc, State::Cwd);
                send(
                    cx,
                    pc,
                    carrier,
                    &[b"CWD ", self.path().dir(self.cwd_count - 1)],
                )
            }
            State::Mdtm => self.mdtm_resp(cx, pc, carrier, code),
            State::Type
            | State::ListType
            | State::RetrType
            | State::StorType
            | State::RetrListType => {
                let state = pc.state;
                self.type_resp(cx, pc, carrier, code, state)
            }
            State::Size | State::RetrSize | State::StorSize => {
                let state = pc.state;
                self.size_resp(cx, pc, carrier, code, state)
            }
            State::Rest | State::RetrRest => {
                let state = pc.state;
                self.rest_resp(cx, pc, carrier, code, state)
            }
            State::Port => self.port_resp(cx, pc, carrier, code),
            State::Pret => {
                if code != 200 {
                    return Err(trace::fail(
                        cx,
                        ErrorKind::FtpPretFailed,
                        format_args!("PRET command not accepted: {code:03}"),
                    ));
                }
                self.use_pasv(cx, pc, carrier)
            }
            State::Pasv => self.pasv_resp(cx, pc, carrier, code),
            State::List | State::Retr => {
                let state = pc.state;
                self.get_resp(cx, pc, carrier, code, state)
            }
            State::Stor => self.stor_resp(cx, pc, carrier, code),
            State::Quit | State::Stop => {
                set_state(cx, pc, State::Stop);
                Ok(())
            }
        }
    }

    /// How far the connection asks for TLS: an implicit TLS scheme asks
    /// for it on both connections (`ftp_use_ssl`).
    fn use_ssl(&self, pc: &FtpConn) -> UseSsl {
        if pc.use_ssl == UseSsl::None && self.peer.scheme().over_tls() {
            UseSsl::All
        } else {
            pc.use_ssl
        }
    }

    /// The greeting (`ftp_wait_resp`): a 230 is a login already, taken
    /// as one unless TLS is required and not up; then `AUTH` if TLS is
    /// asked for and not up, else `USER`.
    fn wait_resp<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut FtpConn,
        carrier: &mut Carrier<'_>,
        code: u32,
    ) -> Step {
        if code == 230 {
            if pc.use_ssl <= UseSsl::Try || carrier.over_tls() {
                return self.user_resp(cx, pc, carrier, code);
            }
        } else if code != 220 {
            return Err(trace::fail(
                cx,
                ErrorKind::WeirdServerReply,
                format_args!("Got a {code:03} ftp-server response when 220 was expected"),
            ));
        }
        if pc.use_ssl != UseSsl::None && !carrier.over_tls() {
            self.auth_tries = 0;
            (self.auth_at, self.auth_next) = match cx.easy().options().line.ftp.ssl_auth {
                SslAuth::Default | SslAuth::Ssl => (0, true),
                SslAuth::Tls => (1, false),
            };
            send(cx, pc, carrier, &[b"AUTH ", AUTHS[self.auth_at]])?;
            set_state(cx, pc, State::Auth);
            Ok(())
        } else {
            self.user(cx, pc, carrier)
        }
    }

    /// The answer to `AUTH`: TLS goes on at 234 or 334, else the other
    /// kind is asked once, and then the login goes on in the clear unless
    /// TLS is required.
    fn auth_resp<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut FtpConn,
        carrier: &mut Carrier<'_>,
        code: u32,
    ) -> Step {
        // What came after the answer was not under TLS: refused.
        if pc.pp.after_reply().is_some_and(|a| !a.is_empty()) {
            return Err(ErrorKind::WeirdServerReply);
        }
        if code == 234 || code == 334 {
            // TLS over the control connection, the data in the clear until
            // `PROT` says otherwise. C makes it blocking.
            self.upgrading = true;
            return self.upgrade_tls(cx, pc, carrier);
        }
        if self.auth_tries < 1 {
            self.auth_tries += 1;
            self.auth_at = if self.auth_next { 1 } else { 0 };
            send(cx, pc, carrier, &[b"AUTH ", AUTHS[self.auth_at]])
        } else if pc.use_ssl > UseSsl::Try {
            Err(ErrorKind::UseSslFailed)
        } else {
            self.user(cx, pc, carrier)
        }
    }

    /// Move the control connection's TLS handshake on, after `AUTH` was
    /// taken; once made, the login.
    fn upgrade_tls<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut FtpConn,
        carrier: &mut Carrier<'_>,
    ) -> Step {
        let Some(identity) = pc.cold.as_ref().and_then(|c| c.upgrade.clone()) else {
            return Err(ErrorKind::UseSslFailed);
        };
        let via = self.via.clone();
        let shaken =
            crate::multi::state::tls::upgrade(carrier, &identity, &self.peer, via.as_deref(), cx)?;
        if shaken == crate::tls::Handshake::Waiting {
            return Ok(());
        }
        self.upgrading = false;
        pc.data_tls = false;
        self.user(cx, pc, carrier)
    }

    /// Move the control connection's TLS shutdown on after `CCC`, its
    /// layer taken off once it is over or failed; then the login goes on
    /// in clear (`Curl_ssl_cfilter_remove`, `vtls_shutdown_blocking`).
    fn clear_tls<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut FtpConn,
        carrier: &mut Carrier<'_>,
    ) -> Step {
        let deadline = self.clearing.expect("clearing after CCC");
        let goodbye = match cx.easy().options().line.ftp.ssl_ccc {
            Ccc::Active => crate::tls::Goodbye::Mutual,
            Ccc::Passive | Ccc::None => crate::tls::Goodbye::Heard,
        };
        // A try once what it waited for is there, as C's poll returns
        // ready: on any other wake it waits on.
        let ready = match carrier.stream_mut().query(LayerQuery::TlsWaits) {
            Some(LayerAnswer::TlsWaits(TlsWait::Recv)) => carrier.ready_now(Events::IN),
            Some(LayerAnswer::TlsWaits(TlsWait::Send)) => carrier.ready_now(Events::OUT),
            _ => true,
        };
        // Out of time, the connection fails with its TLS on, and is closed
        // without the goodbye a failed connection never says.
        let cleared = if cx.now() >= deadline {
            Err(trace::fail(
                cx,
                ErrorKind::OperationTimedout,
                format_args!("SSL shutdown timeout"),
            ))
        } else if !ready {
            Ok(crate::tls::Handshake::Waiting)
        } else {
            let traced = Some(carrier.socket_component());
            carrier.stream_mut().clear_tls(cx, traced, goodbye)
        };
        match cleared {
            Ok(crate::tls::Handshake::Waiting) => {
                self.due = Some(deadline);
                Ok(())
            }
            Ok(crate::tls::Handshake::Done) => {
                self.clearing = None;
                self.due = None;
                pwd(cx, pc, carrier)
            }
            Err(kind) => {
                self.clearing = None;
                self.due = None;
                Err(trace::fail(
                    cx,
                    kind,
                    format_args!("Failed to clear the command channel (CCC)"),
                ))
            }
        }
    }

    /// `USER` (`ftp_state_user`).
    fn user<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut FtpConn,
        carrier: &mut Carrier<'_>,
    ) -> Step {
        // With none given, the anonymous login's (`CURL_DEFAULT_USER`).
        let user = copied(login_of(&pc.cold).map_or(&b"anonymous"[..], Credentials::user))?;
        send(cx, pc, carrier, &[b"USER ", &user])?;
        self.trying_alternative = false;
        set_state(cx, pc, State::User);
        Ok(())
    }

    /// The answer to `USER` or `PASS` (`ftp_state_user_resp`).
    fn user_resp<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut FtpConn,
        carrier: &mut Carrier<'_>,
        code: u32,
    ) -> Step {
        if code == 331 && pc.state == State::User {
            let password =
                login_of(&pc.cold).map_or(&b"ftp@example.com"[..], |c| c.secret().password());
            let password = copied(password)?;
            send(cx, pc, carrier, &[b"PASS ", &password])?;
            set_state(cx, pc, State::Pass);
            Ok(())
        } else if code / 100 == 2 {
            self.logged_in(cx, pc, carrier)
        } else if code == 332 {
            let Some(account) = cx.easy().options().line.ftp.account.as_deref() else {
                return Err(trace::fail(
                    cx,
                    ErrorKind::LoginDenied,
                    format_args!("ACCT requested but none available"),
                ));
            };
            if has_ctrl(account) {
                return Err(trace::fail(
                    cx,
                    ErrorKind::BadFunctionArgument,
                    format_args!("Control byte in FTP account"),
                ));
            }
            let account = copied(account)?;
            send(cx, pc, carrier, &[b"ACCT ", &account])?;
            set_state(cx, pc, State::Acct);
            Ok(())
        } else {
            let alt = cx.easy().options().line.ftp.alternative_to_user.as_deref();
            match alt {
                Some(alt) if !self.trying_alternative => {
                    if has_ctrl(alt) {
                        return Err(trace::fail(
                            cx,
                            ErrorKind::BadFunctionArgument,
                            format_args!("Control byte in FTP alternative-to-user command"),
                        ));
                    }
                    let alt = copied(alt)?;
                    send(cx, pc, carrier, &[&alt])?;
                    self.trying_alternative = true;
                    set_state(cx, pc, State::User);
                    Ok(())
                }
                _ => Err(trace::fail(
                    cx,
                    ErrorKind::LoginDenied,
                    format_args!("Access denied: {code:03}"),
                )),
            }
        }
    }

    /// Logged in (`ftp_state_loggedin`): over TLS, `PBSZ 0` first.
    fn logged_in<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut FtpConn,
        carrier: &mut Carrier<'_>,
    ) -> Step {
        if carrier.over_tls() {
            send(cx, pc, carrier, &[b"PBSZ 0"])?;
            set_state(cx, pc, State::Pbsz);
            Ok(())
        } else {
            pwd(cx, pc, carrier)
        }
    }

    /// The answer to `PWD` (`ftp_pwd_resp`): the directory the login
    /// starts in, and `SYST` if it does not look like a path, as on
    /// OS/400.
    fn pwd_resp<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut FtpConn,
        carrier: &mut Carrier<'_>,
        code: u32,
    ) -> Step {
        if code == 257 {
            match reply::entry_path(pc.pp.held()) {
                Err(reply::ReplyError::Weird) => return Err(ErrorKind::WeirdServerReply),
                Err(reply::ReplyError::OutOfMemory) => return Err(ErrorKind::OutOfMemory),
                Ok(Some(dir)) => {
                    let odd = pc.server_os.is_none() && dir.first() != Some(&b'/');
                    if odd {
                        send(cx, pc, carrier, &[b"SYST"])?;
                    }
                    trace::info_with(cx, &[b"Entry path is '", &dir, b"'"]);
                    let recent = copied(&dir)?;
                    cx.report_mut()
                        .set_ftp_entry_path(recent)
                        .map_err(|_| ErrorKind::OutOfMemory)?;
                    pc.entry_path = Some(dir);
                    if odd {
                        set_state(cx, pc, State::Syst);
                        return Ok(());
                    }
                }
                Ok(None) => trace::info(cx, format_args!("Failed to figure out path")),
            }
        }
        connected(cx, pc);
        Ok(())
    }
}

/// `PWD` (`ftp_state_pwd`). The debug test build's first transfer sends
/// nothing and stops here on request (`CURL_FTP_PWD_STOP`), its
/// connection quiet.
fn pwd<H: Host>(cx: &mut StepCx<'_, H>, pc: &mut FtpConn, carrier: &mut Carrier<'_>) -> Step {
    if cfg!(feature = "debug-hooks")
        && cx
            .easy()
            .report()
            .transfer_number()
            .is_some_and(|n| n.get() == 0)
        && curl_os::env::is_set(b"CURL_FTP_PWD_STOP")
    {
        return Ok(());
    }
    send(cx, pc, carrier, &[b"PWD"])?;
    set_state(cx, pc, State::Pwd);
    Ok(())
}

/// The connect phase is over.
fn connected<H: Host>(cx: &mut StepCx<'_, H>, pc: &mut FtpConn) {
    set_state(cx, pc, State::Stop);
    trace::of(
        cx,
        Component::Ftp,
        format_args!("[STOP] protocol connect phase DONE"),
    );
}

/// What a transfer's commands before its data connection are: the
/// states that reach its directory, ask of its file and set its type
/// (ftp.c's DO phase).
impl Request {
    /// The path as DO split it.
    fn path(&self) -> &Path {
        self.parsed.as_ref().unwrap_or(&path::UNPARSED)
    }

    /// The file the path names, copied for a command.
    fn file(&self) -> Result<Vec<u8>, ErrorKind> {
        copied(self.path().file().unwrap_or_default())
    }

    /// Decode and split the path (`ftp_parse_url_path`): an upload names
    /// a file; a path the connection's last transfer ended in, or a new
    /// connection's empty one, is not changed into again.
    fn parse_path<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut FtpConn,
        reused: bool,
    ) -> Step {
        pc.ctl_valid = false;
        self.cwd_fail = false;
        let method = cx.easy().options().line.ftp.method;
        self.parsed = Some(match Path::parse(&self.encoded, method) {
            Ok(path) => path,
            Err(PathError::Control) => {
                return Err(trace::fail(
                    cx,
                    ErrorKind::UrlMalformat,
                    format_args!("path contains control characters"),
                ));
            }
            Err(PathError::TooDeep) => return Err(ErrorKind::UrlMalformat),
            Err(PathError::OutOfMemory) => return Err(ErrorKind::OutOfMemory),
        });
        if self.upload && self.path().file().is_none() && self.transfer == Transfer::Body {
            return Err(trace::fail(
                cx,
                ErrorKind::UrlMalformat,
                format_args!("Uploading to a URL without a filename"),
            ));
        }
        self.cwd_done = false;
        if method == FtpMethod::NoCwd && self.path().absolute() {
            // Absolute paths need no `CWD`.
            self.cwd_done = true;
        } else {
            // A new connection is in its entry path.
            let old = if reused {
                pc.prev_path.as_deref()
            } else {
                Some(&b""[..])
            };
            if old == Some(self.path().working_dir(method)) {
                trace::info(
                    cx,
                    format_args!("Request has same path as previous transfer"),
                );
                self.cwd_done = true;
            }
        }
        Ok(())
    }

    /// The next quote command of the list `instate` sends, or on once
    /// they are all sent (`ftp_state_quote`); one starting with `*` may
    /// fail.
    fn quote<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut FtpConn,
        carrier: &mut Carrier<'_>,
        init: bool,
        instate: State,
    ) -> Step {
        if init {
            self.quote_at = 0;
        } else {
            self.quote_at += 1;
        }
        let line = &cx.easy().options().line;
        let list = match instate {
            State::RetrPrequote | State::StorPrequote | State::ListPrequote => &line.prequote,
            _ => &line.quote,
        };
        let next = list
            .iter()
            .nth(self.quote_at)
            .map(|cmd| match cmd.strip_prefix(b"*") {
                Some(rest) => (copied(rest), true),
                None => (copied(cmd), false),
            });
        if let Some((cmd, may_fail)) = next {
            self.quote_may_fail = may_fail;
            let cmd = cmd?;
            send(cx, pc, carrier, &[&cmd])?;
            set_state(cx, pc, instate);
            return Ok(());
        }
        match instate {
            State::RetrPrequote => {
                if self.transfer != Transfer::Body {
                    set_state(cx, pc, State::Stop);
                    Ok(())
                } else if let Some(known) = self.known_filesize {
                    self.pipeline.announce_size(cx, Some(known));
                    self.retr(cx, pc, carrier, Some(known))
                } else if cx.easy().options().http.ignore_content_length || self.prefer_ascii {
                    // A growing file's size is not asked, nor an ASCII
                    // transfer's, which servers give unconverted.
                    let file = self.file()?;
                    send(cx, pc, carrier, &[b"RETR ", &file])?;
                    set_state(cx, pc, State::Retr);
                    Ok(())
                } else {
                    let file = self.file()?;
                    send(cx, pc, carrier, &[b"SIZE ", &file])?;
                    set_state(cx, pc, State::RetrSize);
                    Ok(())
                }
            }
            State::StorPrequote => self.ul_setup(cx, pc, carrier, false),
            State::ListPrequote => {
                set_state(cx, pc, State::ListType);
                self.list(cx, pc, carrier)
            }
            _ => self.cwd(cx, pc, carrier),
        }
    }

    /// The `CWD`s to the transfer's directory, the entry path's first on
    /// a reused connection unless the path is absolute (`ftp_state_cwd`).
    fn cwd<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut FtpConn,
        carrier: &mut Carrier<'_>,
    ) -> Step {
        if self.cwd_done {
            return self.mdtm(cx, pc, carrier);
        }
        self.mkd_tried = false;
        let absolute = self.path().depth() > 0 && self.path().absolute();
        match pc.entry_path.as_deref() {
            Some(entry) if self.reused && !absolute => {
                self.cwd_count = 0;
                let entry = copied(entry)?;
                send(cx, pc, carrier, &[b"CWD ", &entry])?;
                set_state(cx, pc, State::Cwd);
                Ok(())
            }
            _ if self.path().depth() > 0 => {
                self.cwd_count = 1;
                send(cx, pc, carrier, &[b"CWD ", self.path().dir(0)])?;
                set_state(cx, pc, State::Cwd);
                Ok(())
            }
            _ => self.mdtm(cx, pc, carrier),
        }
    }

    /// The answer to a `CWD`: the next, or on; a failure makes the
    /// directory if asked, once.
    fn cwd_resp<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut FtpConn,
        carrier: &mut Carrier<'_>,
        code: u32,
    ) -> Step {
        if code / 100 != 2 {
            let create = cx.easy().options().line.ftp.create_dirs;
            if create != CreateDirs::No && self.cwd_count > 0 && !self.mkd_tried {
                self.mkd_tried = true;
                // A `MKD` that fails, another session having made the
                // directory meanwhile, is let pass once for a retry.
                self.mkd_may_fail = u8::from(create == CreateDirs::Retry);
                send(
                    cx,
                    pc,
                    carrier,
                    &[b"MKD ", self.path().dir(self.cwd_count - 1)],
                )?;
                set_state(cx, pc, State::Mkd);
                return Ok(());
            }
            // Not remembered as where the connection is.
            self.cwd_fail = true;
            return Err(trace::fail(
                cx,
                ErrorKind::RemoteAccessDenied,
                format_args!("Server denied you to change to the given directory"),
            ));
        }
        self.mkd_tried = false;
        if self.cwd_count >= self.path().depth() {
            return self.mdtm(cx, pc, carrier);
        }
        self.cwd_count += 1;
        send(
            cx,
            pc,
            carrier,
            &[b"CWD ", self.path().dir(self.cwd_count - 1)],
        )
    }

    /// `MDTM`, if the file's time is asked for or a condition on it
    /// (`ftp_state_mdtm`).
    fn mdtm<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut FtpConn,
        carrier: &mut Carrier<'_>,
    ) -> Step {
        let options = cx.easy().options();
        if (options.filetime || options.time_condition.is_some()) && self.path().file().is_some() {
            let file = self.file()?;
            send(cx, pc, carrier, &[b"MDTM ", &file])?;
            set_state(cx, pc, State::Mdtm);
            Ok(())
        } else {
            self.type_(cx, pc, carrier)
        }
    }

    /// The answer to `MDTM` (`ftp_state_mdtm_resp`): the file's time,
    /// said as HTTP would for a request of no body, then the condition on
    /// it.
    fn mdtm_resp<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut FtpConn,
        carrier: &mut Carrier<'_>,
        code: u32,
    ) -> Step {
        let mut filetime = cx.easy().report().filetime();
        match code {
            213 => {
                let time = reply::file_time(pc.pp.held()).and_then(|t| {
                    let text = curl_alloc::try_format(format_args!(
                        "{:04}{:02}{:02} {:02}:{:02}:{:02} GMT",
                        t.year, t.month, t.day, t.hour, t.minute, t.second
                    ))
                    .ok()?;
                    crate::date::parse(text.as_bytes()).ok()
                });
                if let Some(t) = time {
                    cx.report_mut().set_filetime(t);
                    filetime = Some(t);
                    let options = cx.easy().options();
                    if self.no_body && self.path().file().is_some() && options.filetime {
                        let date = crate::date::HttpDate::of(t)
                            .map_err(|_| ErrorKind::BadFunctionArgument)?;
                        let line =
                            curl_alloc::try_format(format_args!("Last-Modified: {date}\r\n"))
                                .map_err(|_| ErrorKind::OutOfMemory)?;
                        self.pipeline.included_header(cx, line.as_bytes())?;
                    }
                }
            }
            550 => trace::info(
                cx,
                format_args!("MDTM failed: file does not exist or permission problem, continuing"),
            ),
            _ => trace::info(cx, format_args!("unsupported MDTM reply format")),
        }
        if let Some(condition) = cx.easy().options().time_condition {
            match filetime {
                Some(t) if t > 0 && condition.time > 0 => {
                    let unmet = match condition.when {
                        crate::options::Condition::UnmodifiedSince => (t > condition.time)
                            .then_some("The requested document is not old enough"),
                        _ => (t <= condition.time)
                            .then_some("The requested document is not new enough"),
                    };
                    if let Some(why) = unmet {
                        trace::info(cx, format_args!("{why}"));
                        self.transfer = Transfer::None;
                        cx.report_mut().set_condition_unmet();
                        set_state(cx, pc, State::Stop);
                        return Ok(());
                    }
                }
                _ => trace::info(cx, format_args!("Skipping time comparison")),
            }
        }
        self.type_(cx, pc, carrier)
    }

    /// `TYPE` before `SIZE`, for a request of no body on a file, if the
    /// server's type is not the one wanted (`ftp_state_type`): sizes
    /// differ between them.
    fn type_<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut FtpConn,
        carrier: &mut Carrier<'_>,
    ) -> Step {
        let want = if self.prefer_ascii { b'A' } else { b'I' };
        if self.no_body && self.path().file().is_some() && pc.transfer_type != Some(want) {
            self.transfer = Transfer::Info;
            self.nb_type(cx, pc, carrier, self.prefer_ascii, State::Type)
        } else {
            self.size(cx, pc, carrier)
        }
    }

    /// `TYPE A` or `TYPE I`, unless the server is set so, then on as if
    /// it answered (`ftp_nb_type`).
    fn nb_type<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut FtpConn,
        carrier: &mut Carrier<'_>,
        ascii: bool,
        state: State,
    ) -> Step {
        let want = if ascii { b'A' } else { b'I' };
        if pc.transfer_type == Some(want) {
            set_state(cx, pc, state);
            return self.type_resp(cx, pc, carrier, 200, state);
        }
        send(cx, pc, carrier, &[b"TYPE ", &[want]])?;
        set_state(cx, pc, state);
        pc.transfer_type = Some(want);
        Ok(())
    }

    /// The answer to `TYPE` (`ftp_state_type_resp`), any 2xx taken.
    fn type_resp<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut FtpConn,
        carrier: &mut Carrier<'_>,
        code: u32,
        instate: State,
    ) -> Step {
        if code / 100 != 2 {
            return Err(trace::fail(
                cx,
                ErrorKind::FtpCouldntSetType,
                format_args!("Could not set desired mode"),
            ));
        }
        if code != 200 {
            trace::info(
                cx,
                format_args!("Got a {code:03} response code instead of the assumed 200"),
            );
        }
        match instate {
            State::Type => self.size(cx, pc, carrier),
            State::ListType => self.list(cx, pc, carrier),
            State::RetrType => self.quote(cx, pc, carrier, true, State::RetrPrequote),
            State::StorType => self.quote(cx, pc, carrier, true, State::StorPrequote),
            State::RetrListType => self.quote(cx, pc, carrier, true, State::ListPrequote),
            _ => Ok(()),
        }
    }

    /// `SIZE`, for what is known of a file (`ftp_state_size`).
    fn size<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut FtpConn,
        carrier: &mut Carrier<'_>,
    ) -> Step {
        if self.transfer == Transfer::Info && self.path().file().is_some() {
            let file = self.file()?;
            send(cx, pc, carrier, &[b"SIZE ", &file])?;
            set_state(cx, pc, State::Size);
            Ok(())
        } else {
            self.rest(cx, pc, carrier)
        }
    }

    /// The answer to `SIZE` (`ftp_state_size_resp`): the digits the line
    /// ends in, whatever comes before them.
    fn size_resp<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut FtpConn,
        carrier: &mut Carrier<'_>,
        code: u32,
        instate: State,
    ) -> Step {
        let mut filesize = None;
        if code == 213 {
            filesize = pc.pp.reply_line().and_then(reply::size);
        } else if code == 550 && instate != State::StorSize {
            // A size refused for an upload only says which command to use.
            return Err(trace::fail(
                cx,
                ErrorKind::RemoteFileNotFound,
                format_args!("The file does not exist"),
            ));
        }
        match instate {
            State::Size => {
                if let Some(size) = filesize {
                    let line = curl_alloc::try_format(format_args!("Content-Length: {size}\r\n"))
                        .map_err(|_| ErrorKind::OutOfMemory)?;
                    self.pipeline.included_header(cx, line.as_bytes())?;
                }
                self.pipeline.announce_size(cx, filesize);
                self.rest(cx, pc, carrier)
            }
            State::RetrSize => {
                self.pipeline.announce_size(cx, filesize);
                self.retr(cx, pc, carrier, filesize)
            }
            _ => {
                self.resume_from = filesize.map_or(-1, |s| i64::try_from(s).unwrap_or(i64::MAX));
                self.ul_setup(cx, pc, carrier, true)
            }
        }
    }

    /// `REST 0`, for a request of no body on a file, to learn whether the
    /// server takes ranges (`ftp_state_rest`).
    fn rest<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut FtpConn,
        carrier: &mut Carrier<'_>,
    ) -> Step {
        if self.transfer != Transfer::Body && self.path().file().is_some() {
            send(cx, pc, carrier, &[b"REST 0"])?;
            set_state(cx, pc, State::Rest);
            Ok(())
        } else {
            self.prepare_transfer(cx, pc, carrier)
        }
    }

    /// The answer to `REST` (`ftp_state_rest_resp`).
    fn rest_resp<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut FtpConn,
        carrier: &mut Carrier<'_>,
        code: u32,
        instate: State,
    ) -> Step {
        if instate == State::RetrRest {
            if code != 350 {
                return Err(trace::fail(
                    cx,
                    ErrorKind::FtpCouldntUseRest,
                    format_args!("Could not use REST"),
                ));
            }
            let file = self.file()?;
            send(cx, pc, carrier, &[b"RETR ", &file])?;
            set_state(cx, pc, State::Retr);
            return Ok(());
        }
        if code == 350 {
            self.pipeline
                .included_header(cx, b"Accept-ranges: bytes\r\n")?;
        }
        self.prepare_transfer(cx, pc, carrier)
    }

    /// The data connection asked for, passively unless an address is
    /// given to offer, `PRET` first if asked; or, for no data, the
    /// prequote commands still (`ftp_state_prepare_transfer`).
    fn prepare_transfer<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut FtpConn,
        carrier: &mut Carrier<'_>,
    ) -> Step {
        if self.transfer != Transfer::Body {
            set_state(cx, pc, State::RetrPrequote);
            return self.quote(cx, pc, carrier, true, State::RetrPrequote);
        }
        let options = cx.easy().options();
        if options.line.ftp.port.is_some() {
            return self.use_port(cx, pc, carrier, PortCmd::Eprt);
        }
        if options.line.ftp.use_pret {
            let custom = options.http.custom.method.as_deref();
            let cmd = match (self.path().file(), custom) {
                (None, Some(custom)) => copied(custom)?,
                (None, None) if self.list_only => copied(b"NLST")?,
                (None, None) => copied(b"LIST")?,
                (Some(_), _) => Vec::new(),
            };
            if self.path().file().is_none() {
                send(cx, pc, carrier, &[b"PRET ", &cmd])?;
            } else {
                let file = self.file()?;
                let what: &[u8] = if self.upload {
                    b"PRET STOR "
                } else {
                    b"PRET RETR "
                };
                send(cx, pc, carrier, &[what, &file])?;
            }
            set_state(cx, pc, State::Pret);
            return Ok(());
        }
        self.use_pasv(cx, pc, carrier)
    }

    /// Whether the control connection is to an IPv6 address
    /// (`bits.ipv6`).
    fn control_ipv6(&self) -> bool {
        self.control
            .as_ref()
            .and_then(|c| c.remote.as_deref())
            .is_some_and(|r| r.first() == Some(&b'['))
    }

    /// `EPSV`, or `PASV` if that is not to be used, as it is not over
    /// IPv4 (`ftp_state_use_pasv`).
    fn use_pasv<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut FtpConn,
        carrier: &mut Carrier<'_>,
    ) -> Step {
        if !pc.use_epsv && self.control_ipv6() {
            // Over IPv6, only EPSV can name a port.
            pc.use_epsv = true;
        }
        let (mode, cmd): (_, &[u8]) = if pc.use_epsv {
            (Passive::Epsv, b"EPSV")
        } else {
            (Passive::Pasv, b"PASV")
        };
        send(cx, pc, carrier, &[cmd])?;
        self.passive = mode;
        set_state(cx, pc, State::Pasv);
        trace::info(cx, format_args!("Connect data stream passively"));
        Ok(())
    }

    /// The control connection's address, for a passive data connection
    /// to go to; through a proxy's tunnel, the origin's name
    /// (`ftp_control_addr_dup`).
    fn control_addr<H: Host>(&self, cx: &mut StepCx<'_, H>) -> Result<Vec<u8>, ErrorKind> {
        let control = self
            .control
            .as_ref()
            .expect("DO knows its control connection");
        if control.tunnels {
            return copied(self.peer.shown());
        }
        match control.remote.as_deref() {
            Some(remote) => copied(remote),
            None => Err(trace::fail(
                cx,
                ErrorKind::FtpCantGetHost,
                format_args!("unable to get peername of DATA connection"),
            )),
        }
    }

    /// The host the control connection is said to be to: its first proxy,
    /// else the peer a connect-to names, else the origin
    /// (`CURL_CONN_HOST_DISPNAME`), which the data connection's lines name.
    fn control_host(&self) -> Result<Vec<u8>, ErrorKind> {
        let control = self
            .control
            .as_ref()
            .expect("DO knows its control connection");
        copied(control.route.destination().shown())
    }

    /// The answer to `EPSV` or `PASV` (`ftp_state_pasv_resp`): the data
    /// connection set up to the port it names, on the control
    /// connection's address or, if the server's is to be used, the one
    /// it names; a refused `EPSV` tries `PASV`.
    fn pasv_resp<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut FtpConn,
        carrier: &mut Carrier<'_>,
        code: u32,
    ) -> Step {
        let held = pc.pp.held();
        let (host, port) = match (self.passive, code) {
            (Passive::Epsv, 229) => match reply::epsv_port(held) {
                Ok(Some(port)) => (self.control_addr(cx)?, port),
                Err(()) => {
                    return Err(trace::fail(
                        cx,
                        ErrorKind::FtpWeirdPasvReply,
                        format_args!("Illegal port number in EPSV reply"),
                    ));
                }
                Ok(None) => {
                    return Err(trace::fail(
                        cx,
                        ErrorKind::FtpWeirdPasvReply,
                        format_args!("Weirdly formatted EPSV reply"),
                    ));
                }
            },
            (Passive::Pasv, 227) => {
                let Some(ip) = reply::pasv_numbers(held) else {
                    return Err(trace::fail(
                        cx,
                        ErrorKind::FtpWeird227Format,
                        format_args!("Could not interpret the 227-response"),
                    ));
                };
                let port = u16::from(ip[4]) << 8 | u16::from(ip[5]);
                let host = if cx.easy().options().line.ftp.skip_pasv_ip {
                    let [a, b, c, d, ..] = ip;
                    trace::info_with(
                        cx,
                        &[
                            curl_alloc::try_format(format_args!(
                                "Skip {a}.{b}.{c}.{d} for data connection, reuse "
                            ))
                            .map_err(|_| ErrorKind::OutOfMemory)?
                            .as_bytes(),
                            self.peer.name(),
                            b" instead",
                        ],
                    );
                    self.control_addr(cx)?
                } else {
                    let [a, b, c, d, ..] = ip;
                    curl_alloc::try_format(format_args!("{a}.{b}.{c}.{d}"))
                        .map_err(|_| ErrorKind::OutOfMemory)?
                        .into_bytes()
                };
                (host, port)
            }
            (Passive::Epsv, _) => return self.epsv_disable(cx, pc, carrier),
            _ => {
                return Err(trace::fail(
                    cx,
                    ErrorKind::FtpWeirdPasvReply,
                    format_args!("Bad PASV/EPSV response: {code:03}"),
                ));
            }
        };
        self.data_setup(cx, pc, carrier, host, port)?;
        self.do_more = true;
        set_state(cx, pc, State::Stop);
        Ok(())
    }

    /// Set the data connection up to `host` at `port`, through what the
    /// control connection goes through to its peer (`Curl_conn_setup` of
    /// the second socket), said as C says it.
    fn data_setup<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut FtpConn,
        carrier: &Carrier<'_>,
        host: Vec<u8>,
        port: u16,
    ) -> Step {
        let control = self
            .control
            .as_ref()
            .expect("DO knows its control connection");
        // An HTTP/3 proxy's tunnels are raced as its QUIC connections
        // are made, which only the transfer's own setup does.
        if control.route.proxy_over_quic() {
            return Err(ErrorKind::NotBuiltIn);
        }
        let mut route = control.route.clone();
        let origin = Peer::new(self.peer.scheme(), host, port, None);
        // A peer the control connection goes to in the origin's place,
        // the data connection does too, at the new port.
        route.via = match route.via.as_deref() {
            Some(via) => Some(
                TryArc::try_new(via.at_port(port).map_err(|_| ErrorKind::OutOfMemory)?)
                    .map_err(|_| ErrorKind::OutOfMemory)?,
            ),
            None => None,
        };
        route.tls = None;
        let tls = self.data_tls(pc, carrier)?;
        let mut said = Vec::new();
        said.try_extend_from_slice(b"Connecting to ")
            .and_then(|()| said.try_extend_from_slice(origin.name()))
            .map_err(|_| ErrorKind::OutOfMemory)?;
        route.origin = TryArc::try_new(origin).map_err(|_| ErrorKind::OutOfMemory)?;
        let closer = socket_closer(cx);
        let data = DataConn::start(control.number, route, closer, tls, cx.now())?;
        if let Some(old) = pc.data.take() {
            old.discard(cx);
        }
        pc.data = Some(curl_alloc::try_box(data).map_err(|_| ErrorKind::OutOfMemory)?);
        trace::info_with(
            cx,
            &[
                &said,
                curl_alloc::try_format(format_args!(" port {port}"))
                    .map_err(|_| ErrorKind::OutOfMemory)?
                    .as_bytes(),
            ],
        );
        Ok(())
    }

    /// Close the data connection, said as C's trace says it
    /// (`close_secondarysocket`).
    fn close_data<H: Host>(&mut self, cx: &mut StepCx<'_, H>, pc: &mut FtpConn) {
        let state = pc.state.name();
        trace::of(
            cx,
            Component::Ftp,
            format_args!("[{state}] closing DATA connection"),
        );
        if let Some(data) = pc.data.take() {
            data.discard(cx);
        }
    }

    /// `EPSV` failed: `PASV` for this transfer and those after it on the
    /// connection, unless over IPv6, where only `EPSV` names a port
    /// (`ftp_epsv_disable`).
    fn epsv_disable<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut FtpConn,
        carrier: &mut Carrier<'_>,
    ) -> Step {
        let tunnels = self.control.as_ref().is_some_and(|c| c.tunnels);
        if self.control_ipv6() && !tunnels {
            return Err(trace::fail(
                cx,
                ErrorKind::WeirdServerReply,
                format_args!("Failed EPSV attempt, exiting"),
            ));
        }
        trace::info(cx, format_args!("Failed EPSV attempt. Disabling EPSV"));
        pc.use_epsv = false;
        self.close_data(cx, pc);
        // The next failure's reason is the one kept (`state.errorbuf`).
        cx.report_mut().reset_failure();
        send(cx, pc, carrier, &[b"PASV"])?;
        self.passive = Passive::Pasv;
        set_state(cx, pc, State::Pasv);
        Ok(())
    }

    /// The listing's command: the application's, or `NLST` or `LIST`,
    /// naming the directory for a method that does not change into it
    /// (`ftp_state_list`).
    fn list<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut FtpConn,
        carrier: &mut Carrier<'_>,
    ) -> Step {
        let options = cx.easy().options();
        let cmd: &[u8] = match options.http.custom.method.as_deref() {
            Some(custom) => custom,
            None if self.list_only => b"NLST",
            None => b"LIST",
        };
        let cmd = copied(cmd)?;
        let arg = if options.line.ftp.method == FtpMethod::NoCwd {
            self.path().listed_dir()
        } else {
            None
        };
        match arg {
            Some(dir) => {
                let dir = copied(dir)?;
                send(cx, pc, carrier, &[&cmd, b" ", &dir])?;
            }
            None => send(cx, pc, carrier, &[&cmd])?,
        }
        set_state(cx, pc, State::List);
        Ok(())
    }

    /// `RETR`, or `REST` first to resume, the size known checked against
    /// the limit and the resume point (`ftp_state_retr`).
    fn retr<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut FtpConn,
        carrier: &mut Carrier<'_>,
        filesize: Option<u64>,
    ) -> Step {
        let state = pc.state.name();
        trace::of(
            cx,
            Component::Ftp,
            format_args!("[{state}] ftp_state_retr()"),
        );
        if let (Some(max), Some(size)) = (cx.easy().options().flow.max_filesize, filesize)
            && size > max.get()
        {
            return Err(trace::fail(
                cx,
                ErrorKind::FilesizeExceeded,
                format_args!("Maximum file size exceeded"),
            ));
        }
        self.download_size = filesize;
        if self.resume_from == 0 {
            let file = self.file()?;
            send(cx, pc, carrier, &[b"RETR ", &file])?;
            set_state(cx, pc, State::Retr);
            return Ok(());
        }
        match filesize {
            None => trace::info(cx, format_args!("ftp server does not support SIZE")),
            Some(size) => {
                let size = i64::try_from(size).unwrap_or(i64::MAX);
                // From the start or from the end, as far in as the file
                // goes at most.
                if size < self.resume_from.saturating_abs() {
                    let from = self.resume_from;
                    return Err(trace::fail(
                        cx,
                        ErrorKind::BadDownloadResume,
                        format_args!("Offset ({from}) was beyond file size ({size})"),
                    ));
                }
                let left = if self.resume_from < 0 {
                    // The last bytes of it, from where they start.
                    let left = -self.resume_from;
                    self.resume_from = size - left;
                    left
                } else {
                    size - self.resume_from
                };
                self.download_size = Some(u64::try_from(left).unwrap_or(0));
            }
        }
        if self.download_size == Some(0) {
            crate::multi::mstate::xfer_setup(cx, deliver::Directions::default());
            trace::info(cx, format_args!("File already completely downloaded"));
            self.transfer = Transfer::None;
            set_state(cx, pc, State::Stop);
            return Ok(());
        }
        let from = self.resume_from;
        trace::info(
            cx,
            format_args!("Instructs server to resume from offset {from}"),
        );
        let rest = curl_alloc::try_format(format_args!("REST {from}"))
            .map_err(|_| ErrorKind::OutOfMemory)?;
        send(cx, pc, carrier, &[rest.as_bytes()])?;
        set_state(cx, pc, State::RetrRest);
        Ok(())
    }

    /// The upload's start: its body opened, then `STOR`, or `APPE` to
    /// resume, the stored file's size asked first if the resume point is
    /// to be it (`ftp_state_ul_setup`).
    fn ul_setup<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut FtpConn,
        carrier: &mut Carrier<'_>,
        size_checked: bool,
    ) -> Step {
        let mut append = cx.easy().options().line.ftp.append;
        if (self.resume_from != 0 && !size_checked) || (self.resume_from > 0 && size_checked) {
            if self.resume_from < 0 {
                let file = self.file()?;
                send(cx, pc, carrier, &[b"SIZE ", &file])?;
                set_state(cx, pc, State::StorSize);
                return Ok(());
            }
            append = true;
        }
        let mut upload = Upload::open(cx)?;
        upload.trace_set(cx);
        self.infilesize = upload.size();
        if append && self.resume_from > 0 {
            let from = u64::try_from(self.resume_from).unwrap_or(0);
            skip_upload(cx, &mut upload, from)?;
            if let Some(size) = self.infilesize {
                let left = size.saturating_sub(from);
                self.infilesize = Some(left);
                if left == 0 {
                    trace::info(cx, format_args!("File already completely uploaded"));
                    crate::multi::mstate::xfer_setup(cx, deliver::Directions::default());
                    // No data to move: DONE finds no failure in that.
                    self.transfer = Transfer::None;
                    set_state(cx, pc, State::Stop);
                    return Ok(());
                }
            }
        }
        let mut body = Body::new(upload);
        if cx.easy().options().crlf || self.prefer_ascii {
            body.convert_lines().map_err(|_| ErrorKind::OutOfMemory)?;
        }
        let room = cx.easy().options().limits.upload_buffer.get();
        self.sending = Some(Sending::new(body, room)?);
        let file = self.file()?;
        let cmd: &[u8] = if append { b"APPE " } else { b"STOR " };
        send(cx, pc, carrier, &[cmd, &file])?;
        set_state(cx, pc, State::Stor);
        Ok(())
    }

    /// The answer to `STOR` or `APPE` (`ftp_state_stor_resp`).
    fn stor_resp<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut FtpConn,
        carrier: &mut Carrier<'_>,
        code: u32,
    ) -> Step {
        if code >= 400 {
            set_state(cx, pc, State::Stop);
            return Err(trace::fail(
                cx,
                ErrorKind::UploadFailed,
                format_args!("Failed FTP upload: {code}"),
            ));
        }
        if !self.accepted(cx, pc, carrier)? {
            return Ok(());
        }
        self.initiate_transfer(cx, pc)
    }

    /// The answer to `RETR` or the listing's command
    /// (`ftp_state_get_resp`): the size the server says, or the one asked
    /// before, and then the transfer; a listing of nothing (450) is no
    /// failure.
    fn get_resp<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut FtpConn,
        carrier: &mut Carrier<'_>,
        code: u32,
        instate: State,
    ) -> Step {
        if code == 150 || code == 125 {
            let mut size = None;
            let ignore_cl = cx.easy().options().http.ignore_content_length;
            if instate != State::List
                && !self.prefer_ascii
                && !ignore_cl
                && self.download_size.is_none_or(|s| s < 1)
            {
                // Listings give no size, or 0; ASCII sizes are not the
                // bytes that come.
                size = reply::transfer_size(pc.pp.held());
            } else if let Some(known) = self.download_size {
                size = Some(known);
            }
            match (size, self.max_download) {
                (Some(s), Some(max)) if s > max && max > 0 => size = Some(max),
                _ if instate != State::List && self.prefer_ascii => size = None,
                _ => {}
            }
            self.size = size;
            let max = self
                .max_download
                .map_or(-1, |m| i64::try_from(m).unwrap_or(i64::MAX));
            trace::info(cx, format_args!("Maxdownload = {max}"));
            if instate != State::List {
                let shown = size.map_or(-1, |s| i64::try_from(s).unwrap_or(i64::MAX));
                trace::info(cx, format_args!("Getting file with size: {shown}"));
            }
            if !self.accepted(cx, pc, carrier)? {
                return Ok(());
            }
            return self.initiate_transfer(cx, pc);
        }
        if instate == State::List && code == 450 {
            // No files match.
            self.transfer = Transfer::None;
            set_state(cx, pc, State::Stop);
            return Ok(());
        }
        let kind = if instate == State::Retr && code == 550 {
            ErrorKind::RemoteFileNotFound
        } else {
            ErrorKind::FtpCouldntRetrFile
        };
        Err(trace::fail(
            cx,
            kind,
            format_args!("RETR response: {code:03}"),
        ))
    }

    /// The server is about to move the data (`ftp_initiate_transfer`):
    /// its connection made all the way, TLS and all, then the transfer
    /// set to move it, the server's verdict expected on the control
    /// connection after. Until the data connection is up, the transfer
    /// waits for it in DO_MORE.
    fn initiate_transfer<H: Host>(&mut self, cx: &mut StepCx<'_, H>, pc: &mut FtpConn) -> Step {
        if !self.initiating {
            trace::of(cx, Component::Ftp, format_args!("ftp_initiate_transfer()"));
        }
        let host = self.control_host()?;
        let data = pc.data.as_deref_mut().ok_or(ErrorKind::FailedInit)?;
        if data.connect(cx, &host, self)? != Reached::Up {
            self.initiating = true;
            return Ok(());
        }
        self.initiating = false;
        if self.upload {
            upload::announce_size(cx, self.infilesize);
            crate::multi::mstate::xfer_setup_at(cx, None, Some(1));
            self.received = false;
        } else {
            crate::multi::mstate::xfer_setup_at(cx, Some(1), None);
            if let Some(size) = self.size.filter(|&s| s > 0) {
                self.pipeline.announce_size(cx, Some(size));
            }
            self.pipeline.expect(Expect {
                size: self.size,
                max: self.max_download,
                ..Expect::default()
            });
            self.receiving = true;
        }
        pc.pp.awaits_answer();
        set_state(cx, pc, State::Stop);
        Ok(())
    }
}

/// Pass over the first `from` bytes of the upload, read and dropped, as
/// C does when its source cannot seek (`ftp_state_ul_setup`'s
/// `CURL_SEEKFUNC_CANTSEEK`).
fn skip_upload<H: Host>(cx: &mut StepCx<'_, H>, upload: &mut Upload, from: u64) -> Step {
    let mut scratch = [0u8; 4 * 1024];
    let mut passed = 0;
    while passed < from {
        let want = usize::try_from(from - passed).map_or(scratch.len(), |n| n.min(scratch.len()));
        let got = upload.read(cx, &mut scratch[..want], false)?;
        if got.n == 0 || got.n > want {
            return Err(trace::fail(
                cx,
                ErrorKind::FtpCouldntUseRest,
                format_args!("Failed to read data"),
            ));
        }
        passed += got.n as u64;
    }
    Ok(())
}

/// The data connection, as an upload's body goes to it: shut down once
/// the body is all sent, a failure to taken as done, as C takes it
/// (`Curl_xfer_set_shutdown(data, TRUE, TRUE)`).
struct DataOutlet<'d>(&'d mut DataConn);

impl<H: Host> crate::upload::sending::Outlet<H> for DataOutlet<'_> {
    fn put(
        &mut self,
        cx: &mut StepCx<'_, H>,
        bytes: &[u8],
    ) -> std::io::Result<crate::conn::io::Sent> {
        let mut close = false;
        let mut carrier = self
            .0
            .carrier(&mut close)
            .expect("an upload goes over a connected data connection");
        carrier.send(cx, bytes)
    }

    fn shut(&mut self, cx: &mut StepCx<'_, H>) -> Result<bool, ErrorKind> {
        match self.0.shutdown(cx) {
            Ok(done) => Ok(done),
            Err(e) => {
                let code = e.number();
                trace::info(
                    cx,
                    format_args!(
                        "Shutdown send direction error: {code}. Broken server? Proceeding as if everything is ok."
                    ),
                );
                Ok(true)
            }
        }
    }
}

impl Request {
    /// DO (`ftp_do`, `ftp_regular_transfer`, `ftp_perform`): the path
    /// read, the quote commands and those after them started; on in
    /// DOING until they stop.
    fn do_<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<DoStep, ErrorKind> {
        self.know_control(lease)?;
        self.reused = lease.conn().reused();
        self.do_more = false;
        let reused = self.reused;
        {
            let (pc, _) = ftp_of(lease);
            if self.wildcard.is_none() {
                self.parse_path(cx, pc, reused)?;
            } else if self.wildcard_do(cx, pc, reused)? {
                return Ok(DoStep::Nothing);
            }
        }
        self.size = None;
        // The progress counts from nothing (`Curl_pgrsReset`).
        crate::progress::reset(cx);
        let started = {
            let (pc, mut carrier) = ftp_of(lease);
            pc.ctl_valid = true;
            let state = pc.state.name();
            trace::of(
                cx,
                Component::Ftp,
                format_args!("[{state}] DO phase starts"),
            );
            if self.no_body {
                self.transfer = Transfer::Info;
            }
            self.quote(cx, pc, &mut carrier, true, State::Quote)
        };
        let done = started.and_then(|()| self.run(cx, lease));
        let done = match done {
            Ok(done) => done,
            Err(e) => {
                self.parsed = None;
                return Err(e);
            }
        };
        let (pc, _) = ftp_of(lease);
        let state = pc.state.name();
        let connected = pc
            .data
            .as_deref()
            .is_some_and(|d| d.reached() == Reached::Up);
        if connected {
            trace::info(
                cx,
                format_args!("[FTP] [{state}] perform, DATA connection established"),
            );
        } else {
            trace::of(
                cx,
                Component::Ftp,
                format_args!("[{state}] perform, awaiting DATA connect"),
            );
        }
        if !done {
            return Ok(DoStep::Doing);
        }
        trace::of(
            cx,
            Component::Ftp,
            format_args!("[{state}] DO phase is complete1"),
        );
        self.dophase_done(cx, lease, connected)
    }

    /// The commands of DO are done (`ftp_dophase_done`): with the data
    /// connection up, on with its commands at once; with no data, nothing
    /// moves; else the data connection is made in DO_MORE.
    fn dophase_done<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        connected: bool,
    ) -> Result<DoStep, ErrorKind> {
        if connected && let Err(e) = self.do_more_(cx, lease) {
            let (pc, _) = ftp_of(lease);
            self.close_data(cx, pc);
            return Err(e);
        }
        if self.transfer != Transfer::Body {
            crate::multi::mstate::xfer_setup(cx, deliver::Directions::default());
        } else if !connected {
            self.do_more = true;
        }
        let (pc, _) = ftp_of(lease);
        pc.ctl_valid = true;
        Ok(if self.do_more {
            DoStep::More
        } else {
            DoStep::Did
        })
    }

    /// DO_MORE (`ftp_do_more`): the data connection made, then the
    /// commands for the data, once it is connected: `TYPE` and the
    /// listing's or the file's; done once the server is about to move the
    /// data. A data connection `EPSV` named that fails tries `PASV`, back
    /// in DOING.
    fn do_more_<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<DoStep, ErrorKind> {
        let host = self.control_host()?;
        {
            let (pc, mut carrier) = ftp_of(lease);
            let listened = pc.data.as_deref().is_some_and(DataConn::listens);
            if let Some(data) = pc.data.as_deref_mut() {
                // One the server is to connect to is not waited for here:
                // it connects once told what to move.
                let listens = listened;
                match data.connect(cx, &host, self) {
                    Err(ErrorKind::OutOfMemory) => return Err(ErrorKind::OutOfMemory),
                    Err(e) => {
                        pc.data = None;
                        if !listens && self.passive == Passive::Epsv {
                            // An `EPSV` port that cannot be reached: `PASV`.
                            self.epsv_disable(cx, pc, &mut carrier)?;
                            self.wants = drive::waits(&pc.pp);
                            self.stopped = false;
                            return Ok(DoStep::Doing);
                        }
                        return Err(e);
                    }
                    Ok(Reached::Connecting) if !listens => return Ok(DoStep::More),
                    Ok(_) => {}
                }
            }
            if self.initiating {
                if pc.data.as_deref().is_some_and(DataConn::listens) {
                    // The server has not connected back yet.
                    self.check_ctrl(cx, pc, &mut carrier)?;
                    self.stopped = pc.state == State::Stop;
                    return Ok(DoStep::More);
                }
                if listened {
                    // Accepted: the transfer starts now.
                    self.due = None;
                    self.initiating = false;
                }
                self.initiate_transfer(cx, pc)?;
                self.stopped = pc.state == State::Stop;
                return Ok(if self.initiating {
                    DoStep::More
                } else {
                    DoStep::Did
                });
            }
            if pc.state != State::Stop {
                // Its commands are under way.
                let complete = self.run(cx, lease)?;
                return Ok(if complete && !self.initiating {
                    DoStep::Did
                } else {
                    DoStep::More
                });
            }
        }
        if self.transfer == Transfer::None {
            // No data to move.
            crate::multi::mstate::xfer_setup(cx, deliver::Directions::default());
            let (pc, _) = ftp_of(lease);
            let state = pc.state.name();
            trace::of(
                cx,
                Component::Ftp,
                format_args!("[{state}] DO-MORE phase ends with 0"),
            );
            return Ok(DoStep::Did);
        }
        {
            let (pc, mut carrier) = ftp_of(lease);
            if self.upload {
                // Where it resumes, -1 for the server's file's end
                // (`state.resume_from`).
                self.resume_from = match cx.easy().options().resume {
                    None => 0,
                    Some(crate::options::Resume::At(n)) => {
                        i64::try_from(n.get()).unwrap_or(i64::MAX)
                    }
                    Some(crate::options::Resume::AtEnd) => -1,
                };
                self.nb_type(cx, pc, &mut carrier, self.prefer_ascii, State::StorType)?;
            } else {
                // A download: its size unknown as yet.
                self.download_size = None;
                let span = match super::file::span_of(cx) {
                    Ok(span) => Some(span),
                    Err(ErrorKind::OutOfMemory) => return Err(ErrorKind::OutOfMemory),
                    // C goes on with no command sent, the range's failure
                    // lost to the state machine's result after it: the
                    // transfer ends with nothing moved (test 1449).
                    Err(_) => None,
                };
                if let Some(span) = span {
                    self.resume_from = span.resume;
                    self.max_download = span.max.and_then(|m| u64::try_from(m).ok());
                    if self.max_download.is_some() {
                        // The end of a range is not checked.
                        self.dont_check = true;
                    }
                }
                let prequote = cx.easy().options().line.prequote.iter().next().is_some();
                let file = self.path().file().is_some();
                if span.is_none() {
                } else if (self.list_only || !file) && !prequote {
                    // A directory: listed, in ASCII.
                    if self.transfer == Transfer::Body {
                        self.nb_type(cx, pc, &mut carrier, true, State::ListType)?;
                    }
                } else if prequote && !file {
                    self.nb_type(cx, pc, &mut carrier, true, State::RetrListType)?;
                } else {
                    let ascii = self.prefer_ascii;
                    self.nb_type(cx, pc, &mut carrier, ascii, State::RetrType)?;
                }
            }
        }
        let complete = self.run(cx, lease)?;
        Ok(if complete && !self.initiating {
            DoStep::Did
        } else {
            DoStep::More
        })
    }

    /// The exchange (`sendrecv_dl`, `sendrecv_ul` over the second
    /// socket): the download read from the data connection to its end,
    /// or the upload sent over it, and it shut down then.
    pub(crate) fn step<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<ProtoStep, ErrorKind> {
        self.pipeline.flush(cx)?;
        let (pc, _) = ftp_of(lease);
        let Some(data) = pc.data.as_deref_mut() else {
            self.received = true;
            return Ok(ProtoStep::Done);
        };
        if let Some(sending) = self.sending.as_deref_mut() {
            if sending.send_to(cx, &mut DataOutlet(data))? != ProtoStep::Done {
                return Ok(ProtoStep::Blocked);
            }
            self.sending = None;
            self.upload_done = true;
        }
        if self.receiving {
            let read = self.read_data(cx, data);
            match read {
                Ok(ProtoStep::AtReadLimit) => crate::multi::mstate::trace(
                    cx,
                    format_args!("sendrecv_dl() no EAGAIN/pending data, mark as dirty"),
                ),
                Err(e) => {
                    let code = e.number();
                    trace::debug_info(cx, format_args!("sendrecv_dl() -> {code}"));
                }
                Ok(_) => {}
            }
            if read? != ProtoStep::Done {
                return read;
            }
        }
        if self.pipeline.holds_output() {
            return Ok(ProtoStep::Blocked);
        }
        self.received = true;
        Ok(ProtoStep::Done)
    }

    /// The download's reads of a step, until the connection's end or the
    /// most a step reads, the connection shut down at its end
    /// (`sendrecv_dl`, `xfer_recv_resp`).
    fn read_data<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        data: &mut DataConn,
    ) -> Result<ProtoStep, ErrorKind> {
        let mut reads = 0;
        loop {
            if !self.receiving {
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
            // A size said is all that is read: what follows it is not
            // asked for (`xfer_recv_resp`).
            let max = match self.size {
                Some(size) => {
                    let left = size.saturating_sub(self.pipeline.bytecount());
                    max.min(usize::try_from(left).unwrap_or(usize::MAX))
                }
                None => max,
            };
            if max == 0 {
                if let Some(step) = self.read_end(cx, data)? {
                    return Ok(step);
                }
                continue;
            }
            reads += 1;
            let said = cx.easy().report().reasons();
            let mut close = false;
            let mut carrier = data
                .carrier(&mut close)
                .expect("a download is read over a connected data connection");
            match carrier.recv(cx, max) {
                Ok(Recv::WouldBlock) if carrier.reborrow().data_pending() => {
                    return Ok(ProtoStep::AtReadLimit);
                }
                Ok(Recv::WouldBlock) => return Ok(ProtoStep::Blocked),
                Ok(Recv::Eof) => {
                    if let Some(step) = self.read_end(cx, data)? {
                        return Ok(step);
                    }
                }
                Ok(Recv::Data(_)) => {
                    let mut rx = std::mem::take(carrier.rx_mut());
                    let fed = self.pipeline.body(cx, rx.filled());
                    let all = rx.filled().len();
                    rx.consume(all);
                    *carrier.rx_mut() = rx;
                    deliver::write_resp(cx, all, false, fed);
                    fed?;
                    if self.pipeline.body_done() {
                        // The most asked for is here.
                        self.receiving = false;
                    }
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

    /// The data's end, read or reached by its size: the data connection
    /// shut down, then the end written; a step to return if the shutdown
    /// waits or the end is short.
    fn read_end<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        data: &mut DataConn,
    ) -> Result<Option<ProtoStep>, ErrorKind> {
        if !data.shutdown(cx)? {
            return Ok(Some(ProtoStep::Blocked));
        }
        trace::debug_info(cx, format_args!("sendrecv_dl: we are done"));
        deliver::write_resp(cx, 0, true, Ok(()));
        self.receiving = false;
        // The transfer is over: all its bytes came, if it said how many
        // (`Curl_sendrecv`).
        let got = self.pipeline.bytecount();
        if let Some(size) = self.size
            && size != got
        {
            let left = i128::from(size) - i128::from(got);
            return Err(trace::fail(
                cx,
                ErrorKind::PartialFile,
                format_args!("transfer closed with {left} bytes remaining to read"),
            ));
        }
        Ok(None)
    }

    /// The transfer is over (`ftp_done`): what its result says of the
    /// control connection, the directory remembered, the data connection
    /// closed, `ABOR` for a range cut short; then the server's verdict
    /// on the data read, and the commands after the transfer sent, each
    /// answer awaited.
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
        if !lease.conn().keeps_line() {
            // It failed before its connection had FTP's state.
            return Finish::Done(result);
        }
        let mut result = self.done_status(cx, lease, result, premature);
        self.wildcard_done(cx);
        self.done_path(cx, lease, result);
        result = self.done_data(cx, lease, result);
        let (pc, _) = ftp_of(lease);
        if result.is_ok()
            && self.transfer == Transfer::Body
            && pc.ctl_valid
            && pc.pp.pending_resp()
            && !premature
        {
            // The server's verdict, its time to answer from now.
            pc.pp.restart_response_timer(cx.now());
            self.ending = Some(Ending::Reply);
            self.ending_read = 0;
            self.round = drive::Blocking::default();
            return self.finishing(cx, lease, exchanged);
        }
        self.after_reply(cx, lease, result, exchanged)
    }

    /// What the result says of the control connection
    /// (`ftp_done_status`): a failure of the transfer alone leaves it
    /// usable, unless premature; any other wedges it.
    fn done_status<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        status: Result<(), ErrorKind>,
        premature: bool,
    ) -> Result<(), ErrorKind> {
        let harmless = match status {
            Ok(()) => true,
            Err(kind) => matches!(
                kind,
                ErrorKind::BadDownloadResume
                    | ErrorKind::FtpWeirdPasvReply
                    | ErrorKind::FtpPortFailed
                    | ErrorKind::FtpAcceptFailed
                    | ErrorKind::FtpAcceptTimeout
                    | ErrorKind::FtpCouldntSetType
                    | ErrorKind::FtpCouldntRetrFile
                    | ErrorKind::PartialFile
                    | ErrorKind::UploadFailed
                    | ErrorKind::RemoteAccessDenied
                    | ErrorKind::FilesizeExceeded
                    | ErrorKind::RemoteFileNotFound
                    | ErrorKind::WriteError
            ),
        };
        if harmless && !premature {
            return Ok(());
        }
        let (pc, _) = ftp_of(lease);
        pc.ctl_valid = false;
        // Not remembered: the connection goes.
        self.cwd_fail = true;
        trace::of(
            cx,
            Component::Ftp,
            format_args!("FTP ended with bad error code"),
        );
        lease.get().mark_close();
        status
    }

    /// The directory the connection is in, remembered for the next
    /// transfer on it, unless the transfer failed (`ftp_done_path`).
    fn done_path<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        result: Result<(), ErrorKind>,
    ) {
        let method = cx.easy().options().line.ftp.method;
        if result.is_err() {
            let (pc, _) = ftp_of(lease);
            pc.ctl_valid = false;
            pc.prev_path = None;
            lease.get().mark_close();
            return;
        }
        let (pc, _) = ftp_of(lease);
        if let Some(path) = &self.parsed
            && !(method == FtpMethod::NoCwd && path.absolute())
        {
            pc.prev_path = if self.cwd_fail {
                None
            } else {
                copied(path.working_dir(method)).ok()
            };
        }
        if let Some(prev) = pc.prev_path.as_deref() {
            let prev = copied(prev).unwrap_or_default();
            trace::info_with(cx, &[b"Remembering we are in directory \"", &prev, b"\""]);
        }
    }

    /// The data connection closed, `ABOR` first for a range cut short
    /// (`ftp_done_secondary_socket`).
    fn done_data<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        mut result: Result<(), ErrorKind>,
    ) -> Result<(), ErrorKind> {
        let (pc, mut carrier) = ftp_of(lease);
        if pc.data.is_none() {
            return result;
        }
        if result.is_ok() && self.dont_check && self.max_download.is_some_and(|m| m > 0) {
            // A partial download completed.
            if let Err(e) = send(cx, pc, &mut carrier, &[b"ABOR"]) {
                let why = e.message();
                result = Err(trace::fail(
                    cx,
                    e,
                    format_args!("Failure sending ABOR command: {why}"),
                ));
                pc.ctl_valid = false;
                carrier.mark_close();
            }
        }
        let (pc, _) = ftp_of(lease);
        self.close_data(cx, pc);
        result
    }

    /// Read on what DONE awaits, as far as the connection lets it now:
    /// C reads it blocking (`getftpresponse`, `ftp_sendquote`).
    pub(crate) fn finishing<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        exchanged: bool,
    ) -> Finish {
        let limit = cx.easy().options().line.server_response;
        loop {
            let read = {
                let (pc, mut carrier) = ftp_of(lease);
                let round = &mut self.round;
                let ran = drive::runs_done_said(
                    cx,
                    &pc.pp,
                    &mut carrier,
                    limit,
                    exchanged,
                    round,
                    "FTP response timeout",
                );
                let read = match ran {
                    Ok((false, due)) => {
                        self.due = Some(due);
                        self.wants = drive::waits(&pc.pp);
                        return Finish::Waiting;
                    }
                    Ok((true, _)) => {
                        let before = self.header_bytes;
                        let flushed = drive::flush(cx, &mut pc.pp, &mut carrier);
                        let read = flushed.and_then(|()| self.read_reply(cx, pc, &mut carrier));
                        self.ending_read += self.header_bytes - before;
                        read
                    }
                    Err(e) => Err(e),
                };
                self.wants = drive::waits(&pc.pp);
                read
            };
            match read {
                Ok(None) => continue,
                Ok(Some(code)) => {
                    self.due = None;
                    self.round = drive::Blocking::default();
                    if let Some(finish) = self.answered(cx, lease, code, exchanged) {
                        return finish;
                    }
                }
                Err(e) => {
                    self.due = None;
                    return self.ending_failed(cx, lease, e, exchanged);
                }
            }
        }
    }

    /// A read DONE awaited failed: one that read nothing in time says the
    /// control connection looks dead.
    fn ending_failed<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        e: ErrorKind,
        exchanged: bool,
    ) -> Finish {
        if self.ending == Some(Ending::Reply)
            && self.ending_read == 0
            && e == ErrorKind::OperationTimedout
        {
            trace::fail(cx, e, format_args!("control connection looks dead"));
            let (pc, _) = ftp_of(lease);
            pc.ctl_valid = false;
            lease.get().mark_close();
        }
        self.ending = None;
        let _ = exchanged;
        self.finished(cx, lease, Err(e))
    }

    /// The answer DONE awaited came: none if more is to be awaited, else
    /// DONE's end.
    fn answered<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        code: u32,
        exchanged: bool,
    ) -> Option<Finish> {
        match self.ending.expect("DONE awaits an answer") {
            Ending::Reply => {
                let mut result = Ok(());
                if self.dont_check && self.max_download.is_some_and(|m| m > 0) {
                    // `ABOR` went, and whether it worked is not known.
                    trace::info(
                        cx,
                        format_args!("partial download completed, closing connection"),
                    );
                    lease.get().mark_close();
                    self.ending = None;
                    return Some(self.finished(cx, lease, Ok(())));
                }
                if !self.dont_check {
                    match code {
                        226 | 250 => {}
                        552 => {
                            result = Err(trace::fail(
                                cx,
                                ErrorKind::RemoteDiskFull,
                                format_args!("Exceeded storage allocation"),
                            ));
                        }
                        _ => {
                            result = Err(trace::fail(
                                cx,
                                ErrorKind::PartialFile,
                                format_args!("server did not report OK, got {code}"),
                            ));
                        }
                    }
                }
                self.ending = None;
                Some(self.after_reply(cx, lease, result, exchanged))
            }
            Ending::Postquote(at) => {
                let cmd = cx.easy().options().line.postquote.iter().nth(at);
                let cmd = cmd.expect("the command answered is the list's");
                let (cmd, may_fail) = match cmd.strip_prefix(b"*") {
                    Some(rest) => (rest, true),
                    None => (cmd, false),
                };
                if !may_fail && code >= 400 {
                    let cmd = copied(cmd).unwrap_or_default();
                    let kind = trace::fail_with(
                        cx,
                        ErrorKind::QuoteError,
                        &[b"QUOT string not accepted: ", &cmd],
                    );
                    self.ending = None;
                    return Some(self.finished(cx, lease, Err(kind)));
                }
                self.postquote(cx, lease, at + 1)
            }
        }
    }

    /// After the verdict (`ftp_done_check_partial`, then the commands
    /// after the transfer): what moved checked against what was to.
    fn after_reply<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        result: Result<(), ErrorKind>,
        exchanged: bool,
    ) -> Finish {
        let _ = exchanged;
        let result = self.check_partial(cx, result);
        self.transfer = Transfer::Body;
        self.dont_check = false;
        let postquote = cx.easy().options().line.postquote.iter().next().is_some();
        if self.status.is_ok() && result.is_ok() && !self.premature && postquote {
            return self
                .postquote(cx, lease, 0)
                .expect("the list has a command");
        }
        self.finished(cx, lease, result)
    }

    /// The command after the transfer at `at`, sent and its answer awaited;
    /// none past the list's end (`ftp_sendquote`).
    fn postquote<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        at: usize,
    ) -> Option<Finish> {
        let Some(cmd) = cx.easy().options().line.postquote.iter().nth(at) else {
            self.ending = None;
            return Some(self.finished(cx, lease, Ok(())));
        };
        let cmd = cmd.strip_prefix(b"*").unwrap_or(cmd);
        let sent = copied(cmd).and_then(|cmd| {
            let (pc, mut carrier) = ftp_of(lease);
            send(cx, pc, &mut carrier, &[&cmd])?;
            pc.pp.restart_response_timer(cx.now());
            Ok(())
        });
        if let Err(e) = sent {
            self.ending = None;
            return Some(self.finished(cx, lease, Err(e)));
        }
        self.ending = Some(Ending::Postquote(at));
        self.round = drive::Blocking::default();
        Some(self.finishing(cx, lease, true))
    }

    /// What moved, checked against what was to (`ftp_done_check_partial`).
    fn check_partial<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        result: Result<(), ErrorKind>,
    ) -> Result<(), ErrorKind> {
        if result.is_err() || self.premature {
            return result;
        }
        if self.upload {
            let written = cx.easy().report().sizes().upload;
            let converts = cx.easy().options().crlf || self.prefer_ascii;
            if self.transfer == Transfer::Body
                && let Some(size) = self.infilesize
                && ((!converts && size != written) || (converts && size > written))
            {
                return Err(trace::fail(
                    cx,
                    ErrorKind::PartialFile,
                    format_args!("Uploaded unaligned file size ({written} out of {size} bytes)"),
                ));
            }
            return Ok(());
        }
        let got = self.pipeline.bytecount();
        if let Some(size) = self.size
            && size != got
            && self.max_download != Some(got)
        {
            return Err(trace::fail(
                cx,
                ErrorKind::PartialFile,
                format_args!("Received only partial file: {got} bytes"),
            ));
        }
        if !self.dont_check && got == 0 && self.size.is_some_and(|s| s > 0) {
            return Err(trace::fail(
                cx,
                ErrorKind::FtpCouldntRetrFile,
                format_args!("No data was received"),
            ));
        }
        Ok(())
    }

    /// DONE is over with `result`, said as `ftp_done` says it.
    fn finished<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        result: Result<(), ErrorKind>,
    ) -> Finish {
        let (pc, _) = ftp_of(lease);
        let state = pc.state.name();
        let code = result.err().map_or(0, ErrorKind::number);
        trace::of(
            cx,
            Component::Ftp,
            format_args!("[{state}] done, result={code}"),
        );
        Finish::Done(result)
    }
}

/// FTP connects over its connection by logging in, and makes its request
/// in DO and DOING, the data connection made in DO_MORE (`ftp_connect`,
/// `ftp_multi_statemach`, `ftp_do`, `ftp_doing`, `ftp_do_more`).
/// An FTP request lends its pipeline, which the answer to its data
/// connection's `CONNECT` goes through as its control connection's did;
/// its credentials are trusted as a first request's, and it speaks no
/// HTTP.
impl crate::multi::state::SetupLend for Request {
    fn trusted(&self) -> Option<crate::auth::creds::Trusted> {
        CredentialGate::FIRST.trusted()
    }

    fn pipeline(&mut self) -> &mut Pipeline {
        &mut self.pipeline
    }

    fn negotiation(&self) -> Option<crate::proto::http::Negotiation> {
        None
    }

    fn negotiation_mut(&mut self) -> Option<&mut crate::proto::http::Negotiation> {
        None
    }
}

impl super::Phases for Request {
    fn connect<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<Connect, ErrorKind> {
        if !lease.conn().keeps_line() {
            self.conn_state(cx, lease)?;
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
            DoPhase::Do => self.do_(cx, lease),
            DoPhase::Doing => match self.run(cx, lease) {
                Err(e) => {
                    let (pc, _) = ftp_of(lease);
                    let state = pc.state.name();
                    trace::of(
                        cx,
                        Component::Ftp,
                        format_args!("[{state}] DO phase failed"),
                    );
                    Err(e)
                }
                Ok(true) => {
                    let step = self.dophase_done(cx, lease, false);
                    let (pc, _) = ftp_of(lease);
                    let state = pc.state.name();
                    trace::of(
                        cx,
                        Component::Ftp,
                        format_args!("[{state}] DO phase is complete2"),
                    );
                    step
                }
                Ok(false) => Ok(DoStep::Doing),
            },
            DoPhase::More => self.do_more_(cx, lease),
        }
    }

    fn waits(&self, phase: Waiting) -> Events {
        self.control_waits(phase)
    }
}

/// Which command offers an active data connection (`ftpport`, `count1`
/// in `FTP_PORT`): `EPRT` first, then `PORT`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum PortCmd {
    Eprt,
    Port,
}

impl Request {
    /// A socket listening for the server's data connection, and the
    /// command from `cmd` on that offers it (`ftp_state_use_port`): a
    /// failure leaves nothing open, the state stopped.
    fn use_port<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut FtpConn,
        carrier: &mut Carrier<'_>,
        cmd: PortCmd,
    ) -> Step {
        let listened = self.listen(cx, pc);
        let (sock, offered, bound) = match listened {
            Ok(l) => l,
            Err(e) => {
                set_state(cx, pc, State::Stop);
                return Err(e);
            }
        };
        if let Err(e) = self.offer_port(cx, pc, carrier, cmd, offered, bound) {
            close_socket(cx, sock);
            set_state(cx, pc, State::Stop);
            return Err(e);
        }
        let tls = match self.data_tls(pc, carrier) {
            Ok(tls) => tls,
            Err(e) => {
                close_socket(cx, sock);
                set_state(cx, pc, State::Stop);
                return Err(e);
            }
        };
        let timeout = cx.easy().options().line.ftp.accept_timeout.map_or(
            std::time::Duration::from_secs(60),
            crate::time::TimeLimit::duration,
        );
        let deadline = cx.now().after(timeout);
        let data = DataConn::listening(sock, tls, deadline);
        if let Some(old) = pc.data.take() {
            old.discard(cx);
        }
        match curl_alloc::try_box_or_back(data) {
            Ok(data) => pc.data = Some(data),
            Err(data) => {
                data.discard(cx);
                set_state(cx, pc, State::Stop);
                return Err(ErrorKind::OutOfMemory);
            }
        }
        self.do_more = false;
        self.due = Some(deadline);
        Ok(())
    }

    /// The socket listening, the address the command offers and the one
    /// it is bound to (`ftp_port_parse_string`, `ftp_port_default_host`,
    /// `ftp_port_resolve_host`, `ftp_port_open_socket`,
    /// `ftp_port_bind_socket`, `ftp_port_listen`).
    fn listen<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut FtpConn,
    ) -> Result<(Sock, IpAddr, SocketAddr), ErrorKind> {
        let failed = ErrorKind::FtpPortFailed;
        let control = self
            .control
            .as_ref()
            .expect("DO knows its control connection");
        let (remote, local) = (control.remote_addr, control.local);
        let options = cx.easy().options();
        let spec_text = copied(options.line.ftp.port.as_deref().unwrap_or_default())?;
        let ip_version = options.ip_version;
        let spec = port::parse(&spec_text);
        let mut non_local = true;
        let host: Vec<u8> = match spec.addr {
            Some(addr) => {
                let Some(remote) = remote else {
                    return Err(failed);
                };
                if addr.len() >= 50 {
                    return Err(failed);
                }
                let scope = curl_os::net::ipv6_scope(remote.ip());
                let scope_id = match remote {
                    SocketAddr::V6(a) => a.scope_id(),
                    SocketAddr::V4(_) => 0,
                };
                let mut dcx = DriveCx {
                    step: cx,
                    kept: None,
                    deadlines: None,
                };
                use crate::conn::ConnCx as _;
                match dcx
                    .net()
                    .interface_address(addr, remote.is_ipv6(), scope, scope_id)
                {
                    InterfaceAddress::NotFound => copied(addr)?,
                    InterfaceAddress::OtherFamily => return Err(failed),
                    InterfaceAddress::Found(ip, _) => text_of(format_args!("{ip}"))?,
                }
            }
            None => {
                // The control connection's own address.
                let Some(local) = local else {
                    return Err(trace::fail(
                        cx,
                        failed,
                        format_args!("getsockname() failed: Bad file descriptor"),
                    ));
                };
                non_local = false;
                text_of(format_args!("{}", local.ip()))?
            }
        };
        let addrs = self.port_addresses(cx, &host, ip_version)?;
        // A socket of the first family that opens.
        let mut dcx = DriveCx {
            step: cx,
            kept: None,
            deadlines: None,
        };
        let mut opened = None;
        let mut why = None;
        for &ip in &addrs {
            use crate::conn::ConnCx as _;
            let mut at = Remote::Inet(SocketAddr::new(ip, 0));
            let open = dcx.open_socket(&mut at, crate::conn::io::SocketKind::Stream);
            match open.socket {
                Ok(socket) => {
                    if open.by_application
                        && let Err(e) = socket.set_nonblocking()
                    {
                        why = Some(e);
                        let closer = socket_closer(dcx.step);
                        crate::conn::io::Net::close(&mut dcx, Sock::new(socket, closer));
                        continue;
                    }
                    opened = Some((socket, ip));
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::OutOfMemory => {
                    return Err(ErrorKind::OutOfMemory);
                }
                Err(e) => why = Some(e),
            }
        }
        let Some((socket, offered)) = opened else {
            let why = why.unwrap_or_else(|| std::io::Error::from_raw_os_error(0));
            let why = curl_os::error::ErrorText::of(&why);
            return Err(trace::fail_with(
                cx,
                failed,
                &[b"socket failure: ", why.as_bytes()],
            ));
        };
        let sock = Sock::new(socket, socket_closer(cx));
        let state = pc.state.name();
        trace::of(
            cx,
            Component::Ftp,
            format_args!("[{state}] ftp_state_use_port(), opened socket"),
        );
        match bind_listen(cx, &sock, offered, local, spec.min, spec.max, non_local) {
            Ok(bound) => Ok((sock, offered, bound)),
            Err(e) => {
                close_socket(cx, sock);
                Err(e)
            }
        }
    }

    /// The addresses `host` names for the command to offer, as the
    /// resolver gives them (`ftp_port_resolve_host`).
    fn port_addresses<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        host: &[u8],
        ip_version: crate::options::IpVersion,
    ) -> Result<Vec<IpAddr>, ErrorKind> {
        let mut addrs = Vec::new();
        let setup = crate::multi::state::drive_options(cx);
        let mut dcx = DriveCx {
            step: cx,
            kept: None,
            deadlines: None,
        };
        let answer = crate::conn::resolve_blocking(host, ip_version, &mut dcx, setup)
            .map_err(|_| ErrorKind::OutOfMemory)?;
        match answer {
            Some(answer) => {
                addrs
                    .try_extend_from_slice(answer.addrs())
                    .map_err(|_| ErrorKind::OutOfMemory)?;
                Ok(addrs)
            }
            None => Err(trace::fail_with(
                cx,
                ErrorKind::CouldntResolveHost,
                &[b"failed to resolve the address provided to PORT: ", host],
            )),
        }
    }

    /// `EPRT`, or `PORT` from `cmd` on, offering `offered` at the port
    /// `bound` has (`ftp_port_send_command`).
    fn offer_port<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut FtpConn,
        carrier: &mut Carrier<'_>,
        cmd: PortCmd,
        offered: IpAddr,
        bound: SocketAddr,
    ) -> Step {
        if !pc.use_eprt && self.control_ipv6() {
            // Not to be done without over IPv6.
            pc.use_eprt = true;
        }
        let port = bound.port();
        let mut sent = None;
        for at in [PortCmd::Eprt, PortCmd::Port] {
            if at < cmd || (at == PortCmd::Eprt && !pc.use_eprt) {
                continue;
            }
            if at == PortCmd::Port && !bound.is_ipv4() {
                // IPv4's alone.
                continue;
            }
            let line = match at {
                PortCmd::Eprt => {
                    let family = if bound.is_ipv4() { 1 } else { 2 };
                    text_of(format_args!("EPRT |{family}|{offered}|{port}|"))?
                }
                PortCmd::Port => {
                    let dotted = text_of(format_args!("{offered}"))?;
                    let mut line = copied(b"PORT ")?;
                    for b in dotted {
                        line.try_push(if b == b'.' { b',' } else { b })
                            .map_err(|_| ErrorKind::OutOfMemory)?;
                    }
                    let tail = text_of(format_args!(",{},{}", port >> 8, port & 0xff))?;
                    line.try_extend_from_slice(&tail)
                        .map_err(|_| ErrorKind::OutOfMemory)?;
                    line
                }
            };
            if let Err(e) = send(cx, pc, carrier, &[&line]) {
                let name = if at == PortCmd::Eprt { "EPRT" } else { "PORT" };
                let why = e.message();
                return Err(trace::fail(
                    cx,
                    e,
                    format_args!("Failure sending {name} command: {why}"),
                ));
            }
            sent = Some(at);
            break;
        }
        // With none sent the state waits for an answer all the same, as
        // C's does.
        self.port_cmd = sent;
        set_state(cx, pc, State::Port);
        Ok(())
    }

    /// The answer to `EPRT` or `PORT` (`ftp_state_port_resp`): one
    /// refused tries the next, with `EPRT` not used again.
    fn port_resp<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut FtpConn,
        carrier: &mut Carrier<'_>,
        code: u32,
    ) -> Step {
        if code / 100 != 2 {
            if self.port_cmd == Some(PortCmd::Eprt) {
                trace::info(cx, format_args!("disabling EPRT usage"));
                pc.use_eprt = false;
                return self.use_port(cx, pc, carrier, PortCmd::Port);
            }
            return Err(trace::fail(
                cx,
                ErrorKind::FtpPortFailed,
                format_args!("Failed to do PORT"),
            ));
        }
        trace::info(cx, format_args!("Connect data stream actively"));
        set_state(cx, pc, State::Stop);
        Ok(())
    }

    /// The server is told to move the data and, for an active connection,
    /// it is to connect back: whether it has (`ftp_state_stor_resp`,
    /// `ftp_state_get_resp`, the `ftp_use_port` branch). Not yet, the
    /// control connection is looked at for an answer that says it never
    /// will.
    fn accepted<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut FtpConn,
        carrier: &mut Carrier<'_>,
    ) -> Result<bool, ErrorKind> {
        let host = self.control_host()?;
        if !pc.data.as_deref().is_some_and(DataConn::listens) {
            return Ok(true);
        }
        set_state(cx, pc, State::Stop);
        let data = pc.data.as_deref_mut().expect("a data connection listens");
        if data.connect(cx, &host, self)? != Reached::Connecting {
            self.due = None;
            return Ok(true);
        }
        trace::info(cx, format_args!("Data conn was not available immediately"));
        self.initiating = true;
        self.check_ctrl(cx, pc, carrier)?;
        Ok(false)
    }

    /// While the server is to connect back, an answer on the control
    /// connection says it will not (`ftp_check_ctrl_on_data_wait`): a
    /// refusal fails the accept, anything else is weird, unless it is
    /// the transfer's own end read ahead of the data.
    fn check_ctrl<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut FtpConn,
        carrier: &mut Carrier<'_>,
    ) -> Step {
        // An answer held already: one that is no go-ahead says the server
        // will not connect.
        if let Some(&first) = pc.pp.held().first()
            && (!first.is_ascii_digit() || first > b'3')
        {
            trace::info(
                cx,
                format_args!("There is negative response in cache while serv connect"),
            );
            // C reads the answer, whatever it is, and fails all the same.
            match self.read_reply(cx, pc, carrier) {
                Err(ErrorKind::OutOfMemory) => return Err(ErrorKind::OutOfMemory),
                _ => return Err(ErrorKind::FtpAcceptFailed),
            }
        }
        let response = pc.pp.unscanned() || carrier.ready_now(Events::IN);
        if !response {
            return Ok(());
        }
        trace::info(
            cx,
            format_args!("Ctrl conn has data while waiting for data conn"),
        );
        if let Some(after) = pc.pp.after_reply().filter(|_| pc.pp.unscanned())
            && after.len() > 3
            && after.get(..3) == Some(b"226")
            && after[3] == b' '
        {
            // The transfer's end read ahead of its data: the data
            // connection is read for all the same.
            trace::info(cx, format_args!("Got 226 before data activity"));
            return Ok(());
        }
        let code = match self.read_reply(cx, pc, carrier) {
            Ok(Some(code)) => code,
            // C waits for the rest of it.
            Ok(None) => return Ok(()),
            Err(ErrorKind::OutOfMemory) => return Err(ErrorKind::OutOfMemory),
            // A 421 says its timeout, its code read all the same.
            Err(ErrorKind::OperationTimedout) => 421,
            Err(_) => 0,
        };
        trace::info(cx, format_args!("FTP code: {code:03}"));
        if code / 100 > 3 {
            return Err(ErrorKind::FtpAcceptFailed);
        }
        Err(ErrorKind::WeirdServerReply)
    }

    /// What the data's TLS is made with, if it is protected: the control
    /// connection's identity and peers, and a copy of its latest session
    /// to resume, as servers may insist (`Curl_ssl_get_cf_session`).
    fn data_tls(&self, pc: &FtpConn, carrier: &Carrier<'_>) -> Result<Option<DataTls>, ErrorKind> {
        if !pc.data_tls {
            return Ok(None);
        }
        let control = self
            .control
            .as_ref()
            .expect("DO knows its control connection");
        let identity = control
            .route
            .tls
            .clone()
            .or_else(|| control.route.cold.as_ref().and_then(|c| c.upgrade.clone()));
        let identity = identity.ok_or(ErrorKind::NotBuiltIn)?;
        let resume = carrier
            .latest_session()
            .map(crate::tls::TlsTicket::try_clone)
            .transpose()
            .map_err(|_| ErrorKind::OutOfMemory)?;
        Ok(Some(DataTls {
            identity,
            origin: control.route.origin.clone(),
            via: control.route.via.clone(),
            resume,
        }))
    }
}

/// Bind `sock` to `offered` at a port from `min` to `max`, or to the
/// control connection's address `local` if `offered` is not one here
/// and `non_local` says it may not be, then listen: the address bound
/// (`ftp_port_bind_socket`, `ftp_port_listen`).
fn bind_listen<H: Host>(
    cx: &mut StepCx<'_, H>,
    sock: &Sock,
    offered: IpAddr,
    local: Option<SocketAddr>,
    min: u16,
    max: u16,
    mut non_local: bool,
) -> Result<SocketAddr, ErrorKind> {
    let failed = ErrorKind::FtpPortFailed;
    let mut ip = offered;
    let mut port = min;
    loop {
        match sock.socket().bind(SocketAddr::new(ip, port)) {
            Ok(()) => break,
            Err(e) => {
                let errno = e.raw_os_error().unwrap_or(0);
                let why = curl_os::error::ErrorText::of(&e);
                if non_local && errno == libc_errno::EADDRNOTAVAIL {
                    let line = text_of(format_args!(
                        "bind(port={port}) on non-local address failed: "
                    ))?;
                    trace::info_with(cx, &[&line, why.as_bytes()]);
                    let Some(local) = local else {
                        return Err(trace::fail(
                            cx,
                            failed,
                            format_args!("getsockname() failed: Bad file descriptor"),
                        ));
                    };
                    ip = local.ip();
                    port = min;
                    non_local = false;
                    continue;
                }
                if errno != libc_errno::EADDRINUSE && errno != libc_errno::EACCES {
                    let line = text_of(format_args!("bind(port={port}) failed: "))?;
                    return Err(trace::fail_with(cx, failed, &[&line, why.as_bytes()]));
                }
            }
        }
        if port == max {
            return Err(trace::fail(
                cx,
                failed,
                format_args!("bind() failed, ran out of ports"),
            ));
        }
        port += 1;
    }
    let bound = match sock.socket().local_addr() {
        Ok(bound) => bound,
        Err(e) => {
            let why = curl_os::error::ErrorText::of(&e);
            return Err(trace::fail_with(
                cx,
                failed,
                &[b"getsockname() failed: ", why.as_bytes()],
            ));
        }
    };
    trace::of(
        cx,
        Component::Ftp,
        format_args!("ftp_port_bind_socket(), socket bound to port {port}"),
    );
    if let Err(e) = sock.socket().listen() {
        let why = curl_os::error::ErrorText::of(&e);
        return Err(trace::fail_with(
            cx,
            failed,
            &[b"socket failure: ", why.as_bytes()],
        ));
    }
    trace::of(
        cx,
        Component::Ftp,
        format_args!("ftp_port_listen(), listening on port"),
    );
    Ok(bound)
}

/// The numbers of the system's errors the bind loop tells apart.
mod libc_errno {
    pub(super) const EACCES: i32 = 13;
    pub(super) const EADDRINUSE: i32 = 98;
    pub(super) const EADDRNOTAVAIL: i32 = 99;
}

/// The closer the transfer's sockets close with.
fn socket_closer<H: Host>(cx: &mut StepCx<'_, H>) -> Closer {
    match &cx.easy().options().sockets.close {
        Some(close) => Closer::Hook(close.clone()),
        None => Closer::System,
    }
}

/// Close `sock` for the transfer.
fn close_socket<H: Host>(cx: &mut StepCx<'_, H>, sock: Sock) {
    let mut dcx = DriveCx {
        step: cx,
        kept: None,
        deadlines: None,
    };
    crate::conn::io::Net::close(&mut dcx, sock);
}

/// `args` as text, for a command or a line.
fn text_of(args: std::fmt::Arguments<'_>) -> Result<Vec<u8>, ErrorKind> {
    curl_alloc::try_format(args)
        .map(String::into_bytes)
        .map_err(|_| ErrorKind::OutOfMemory)
}
