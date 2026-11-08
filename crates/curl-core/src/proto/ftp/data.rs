//! FTP's data connection, its second (C's `SECONDARYSOCKET`): set up to
//! the peer a passive answer names, as the control connection was, or
//! accepted from the server on a socket listening here for an active
//! one; its TLS made over it once connected if the data is protected,
//! and closed as each transfer ends. The transfer's FTP request holds it, and
//! its DONE closes it, whatever ended the transfer: no connection, and no
//! later transfer on it, can reach a data connection its own transfer is done
//! with.

use crate::handler::{Configured, SocketPurpose, SocketToSet};
use crate::multi::TransferCx;
use curl_alloc::TryArc;

use crate::components::Component;
use crate::conn::chain::{Chain, SetupPoint};
use crate::conn::io::{Closer, Events, Net, Remote, Sock, Socket};
use crate::conn::mux::Carrier;
use crate::conn::shutdown::ConnSettings;
use crate::conn::{Addresses, Answer, ConnectMachine, Drove, Late, LateLook, Progress};
use crate::conn::{ConnNumber, Dial, NetRoute, Peer, Stream};
use crate::error::ErrorKind;
use crate::multi::Host;
use crate::multi::cx::DriveCx;
use crate::multi::state::side;
use crate::multi::state::{ConnRank, SetupLend, Shaken, SideSetup, StepCx};
use crate::tls::{Handshake, TlsIdentity};
use crate::trace;

/// What the data's TLS is made with and for: the control connection's
/// settings and peers, and its latest session, which the data's resumes
/// first, for the servers that insist the data's session is the control
/// connection's (`ossl_init_session_and_alpns`).
#[derive(Debug)]
pub(crate) struct DataTls {
    pub(crate) identity: TryArc<TlsIdentity>,
    pub(crate) origin: TryArc<Peer>,
    pub(crate) via: Option<TryArc<Peer>>,
    pub(crate) resume: Option<crate::tls::TlsTicket>,
}

/// The data connection.
#[derive(Debug)]
pub(crate) struct DataConn {
    phase: Option<Phase>,
    /// Its TLS, if the data is protected (`ftp_use_data_ssl`).
    tls: Option<DataTls>,
    /// What its socket's sends and receives are traced as.
    socket: Component,
    /// Its layers shut down so far, once its shutdown started.
    shut: Option<usize>,
}

#[derive(Debug)]
#[allow(
    clippy::large_enum_variant,
    reason = "the setup is held inline, as the request boxes the data connection whole: \
              boxed apart, each pass that drives it would box it anew"
)]
enum Phase {
    /// Being set up: its first hop dialed, then the handshakes over it.
    Connecting(ConnectMachine, SideSetup),
    /// Listening for the server to connect, for `wait` from `since`
    /// (`cf_tcp_accept`).
    Listening {
        sock: Sock,
        since: crate::time::Instant,
        wait: std::time::Duration,
    },
    /// Connected, its TLS made if `shaken`; until then, the peer it is
    /// said to be connected to once it is made.
    Up {
        stream: Box<Stream>,
        shaken: bool,
        peer: Option<Remote>,
        /// The chain it was connected with, its TLS to go in it.
        chain: Chain,
        /// The resolve of its first hop's name, still going on as it came
        /// up, until its TLS is made: C's DNS filter, above the TLS
        /// filter, holds it until the chain below connects
        /// (`cf_dns_connect`).
        late: Option<Box<LateName>>,
    },
}

/// A resolve still going on beside the connection, with the route its
/// name is the first hop of and what has come of it so far.
#[derive(Debug)]
struct LateName {
    late: Late,
    route: NetRoute,
    answer: Addresses,
}

impl LateName {
    /// `late` beside a connection set up over `route`, `answer` what has
    /// come so far; none if it has ended.
    fn of(late: Late, route: NetRoute, answer: Option<TryArc<Answer>>) -> Option<LateName> {
        if !late.going() {
            return None;
        }
        let answer = answer.map_or(Addresses::Unix, Addresses::Resolved);
        Some(LateName {
            late,
            route,
            answer,
        })
    }

    /// Looked at, as the filter does in each call of the chain's connect:
    /// once it has all come, said.
    fn look<H: Host>(&mut self, cx: &mut StepCx<'_, H>) -> Result<(), ErrorKind> {
        let peer = self.route.destination();
        let polled = self
            .late
            .poll(peer, &mut self.answer, &mut DriveCx::new(cx, None));
        match polled {
            Ok(LateLook::Found(found)) => {
                let answer = match &self.answer {
                    Addresses::Resolved(answer) => Some(&**answer),
                    Addresses::Unix => None,
                };
                crate::multi::state::side_resolved_at(cx, &self.route, answer, found);
                crate::multi::state::side_answered_due(cx);
                Ok(())
            }
            Ok(LateLook::Waiting) => {
                crate::multi::state::side_late_due(cx, &self.late);
                Ok(())
            }
            Ok(LateLook::Failed(e)) => Err(crate::multi::state::connect_failed(cx, &self.route, e)),
            Err(curl_alloc::OutOfMemory) => Err(ErrorKind::OutOfMemory),
        }
    }
}

/// How far a data connection has come.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Reached {
    /// Still connecting.
    Connecting,
    /// Connected to its peer, its TLS still being made
    /// (`Curl_conn_is_ip_connected`).
    Ip,
    /// Connected all the way (`Curl_conn_is_connected`).
    Up,
}

impl DataConn {
    /// The setup of connection `number`'s second over `route`, its
    /// sockets closed with `closer`, started `now`; protected by `tls`
    /// once connected, if given.
    pub(crate) fn start<H: Host>(
        cx: &mut StepCx<'_, H>,
        number: ConnNumber,
        route: NetRoute,
        closer: Closer,
        tls: Option<DataTls>,
    ) -> Result<DataConn, ErrorKind> {
        let now = cx.now();
        crate::multi::state::side::chain_set_up(cx, &route);
        let socket = crate::conn::Dialing {
            route: &route,
            dial: Dial::Stream,
        }
        .socket_component();
        let machine = ConnectMachine::new(
            number,
            route,
            Dial::Stream,
            now,
            closer,
            ConnSettings::DEFAULT,
        );
        Ok(DataConn {
            phase: Some(Phase::Connecting(machine, SideSetup::default())),
            tls,
            socket,
            shut: None,
        })
    }

    /// One accepted on `sock`, listening for `wait` from `since`; protected by
    /// `tls` once connected, if given. The socket accepted is closed by the
    /// library, never the application's closer (`cf_socket_close`'s
    /// `!ctx->accepted`).
    pub(crate) fn listening<H: Host>(
        cx: &mut StepCx<'_, H>,
        sock: Sock,
        tls: Option<DataTls>,
        since: crate::time::Instant,
        wait: std::time::Duration,
    ) -> DataConn {
        cx.as_second(|cx| {
            let accept = Component::TcpAccept;
            trace::of(cx, accept, format_args!("added"));
            let (fd, ip, port) = listens_at(&sock);
            trace::of(
                cx,
                accept,
                format_args!("set filter for listen socket fd={fd} ip={ip}:{port}"),
            );
        });
        DataConn {
            phase: Some(Phase::Listening { sock, since, wait }),
            tls,
            socket: Component::TcpAccept,
            shut: None,
        }
    }

    /// Whether it listens for the server to connect
    /// (`Curl_conn_is_tcp_listen`).
    pub(crate) fn listens(&self) -> bool {
        matches!(self.phase, Some(Phase::Listening { .. }))
    }

    /// Move the connect on as far as it goes now, the handshakes over it
    /// among it, its proxies' for `request` and its TLS
    /// (`Curl_conn_connect` of the second socket), said as the control
    /// connection's `host` names it: how far it came. A failure leaves
    /// nothing open.
    pub(crate) fn connect<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        host: &[u8],
        request: &mut dyn SetupLend,
    ) -> Result<Reached, ErrorKind> {
        cx.as_second(|cx| {
            if let Some(Phase::Connecting(machine, _)) = self.phase.as_ref() {
                side::chain_started(cx, machine);
            }
            let mut entered = false;
            let mut chain = None;
            let made = self.connect_call(cx, host, request, &mut entered, &mut chain);
            // A setup's failure ends the chain's call; a later stage's is
            // its layer's own.
            if let (Err(kind), Some(chain)) = (&made, chain) {
                side::call_failed(cx, *kind, chain);
            }
            made
        })
    }

    fn connect_call<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        host: &[u8],
        request: &mut dyn SetupLend,
        entered: &mut bool,
        chain: &mut Option<Chain>,
    ) -> Result<Reached, ErrorKind> {
        // The name's filter heads the chain: what more came of the resolve
        // still going on is taken first, once in each call, until the
        // chain below connects (`cf_dns_connect`).
        self.look_at_late(cx)?;
        loop {
            match self
                .phase
                .take()
                .expect("a data connection is set up or up")
            {
                Phase::Connecting(mut machine, mut setup) => {
                    *chain = Some(setup.enter(&machine, cx, entered));
                    if let SetupPoint::Dialed(_) = machine.reached() {
                        match setup.shake(&mut machine, request, cx) {
                            Ok(Shaken::Waiting) => {
                                self.phase = Some(Phase::Connecting(machine, setup));
                                side::call_waits(cx, Component::DnsFilter);
                                return Ok(Reached::Connecting);
                            }
                            Ok(Shaken::Redialed) => {
                                self.phase = Some(Phase::Connecting(machine, setup));
                                continue;
                            }
                            Ok(Shaken::Up) => {
                                let route = machine.route().clone();
                                let answer = machine.answer().cloned();
                                let (conn, late) = machine.handshaken();
                                *chain = None;
                                self.up(cx, host, conn, LateName::of(late, route, answer))?;
                                continue;
                            }
                            Err(kind) => {
                                discard_in(cx, machine);
                                return Err(kind);
                            }
                        }
                    }
                    let route = machine.route().clone();
                    let answer = machine.answer().cloned();
                    match crate::multi::state::side_drive(cx, machine) {
                        Ok(Drove::Connecting(mut m, progress)) => {
                            if let Progress::Resolved(found) = progress {
                                crate::multi::state::side_resolved(cx, &m, found);
                            }
                            crate::multi::state::side_progress(cx, &route, &progress, || {
                                m.dialed().ends().0
                            });
                            self.phase = Some(Phase::Connecting(m, setup));
                            match progress {
                                // Moved on: on again at once, to its
                                // handshakes if it dialed a proxy.
                                Progress::Resolved(_)
                                | Progress::Failed
                                | Progress::Dialed
                                | Progress::Trying { at_once: true, .. } => {}
                                _ => {
                                    side::call_waits(cx, Component::DnsFilter);
                                    return Ok(Reached::Connecting);
                                }
                            }
                        }
                        Ok(Drove::Established(conn, late)) => {
                            if let Some(remote) = conn.remote() {
                                crate::multi::state::side_won(cx, &route, remote);
                            }
                            *chain = None;
                            let late = LateName::of(late, route, answer);
                            self.up(cx, host, conn, late)?;
                        }
                        Err(e) => return Err(crate::multi::state::connect_failed(cx, &route, e)),
                    }
                }
                Phase::Listening { sock, since, wait } => {
                    // Its timer wakes it when the wait is over; counted in
                    // milliseconds, as C counts them (`cf_tcp_accept_timeleft`).
                    if cx.now().ms_since(since) >= crate::time::millis(wait) {
                        close_in(cx, sock);
                        return Err(trace::fail(
                            cx,
                            ErrorKind::FtpAcceptTimeout,
                            format_args!("Accept timeout occurred while waiting server connect"),
                        ));
                    }
                    let accept = Component::TcpAccept;
                    let (fd, ip, port) = listens_at(&sock);
                    trace::of(
                        cx,
                        accept,
                        format_args!("Checking for incoming on fd={fd} ip={ip}:{port}"),
                    );
                    let accepted = match sock.socket().accept() {
                        Ok(None) => {
                            trace::of(cx, accept, format_args!("socket_check -> 0"));
                            trace::of(
                                cx,
                                accept,
                                format_args!("nothing heard from the server yet"),
                            );
                            side::call_waits(cx, accept);
                            self.phase = Some(Phase::Listening { sock, since, wait });
                            return Ok(Reached::Connecting);
                        }
                        Ok(Some(accepted)) => accepted,
                        Err(e) if e.kind() == std::io::ErrorKind::OutOfMemory => {
                            close_in(cx, sock);
                            return Err(ErrorKind::OutOfMemory);
                        }
                        Err(e) => {
                            close_in(cx, sock);
                            let why = curl_os::error::ErrorText::of(&e);
                            return Err(trace::fail_with(
                                cx,
                                ErrorKind::FtpAcceptFailed,
                                &[b"Error accept()ing server connect: ", why.as_bytes()],
                            ));
                        }
                    };
                    trace::of(cx, accept, format_args!("socket_check -> 1"));
                    trace::info(
                        cx,
                        format_args!("Ready to accept data connection from server"),
                    );
                    trace::info(cx, format_args!("Connection accepted from server"));
                    // The listening socket goes, the accepted one in its
                    // place.
                    close_in(cx, sock);
                    let peer = accepted.peer_addr().ok().map(Remote::Inet);
                    let sock = Sock::new(accepted, Closer::System);
                    if let Some(remote) = peer.as_ref() {
                        let fd = sock.key().get();
                        let mut line = trace::Line::new();
                        line.text(format_args!("accepted_set(sock={fd}, remote="));
                        line.raw(remote.shown_ip().bytes());
                        line.text(format_args!(" port={})", remote.port()));
                        trace::of_with(cx, accept, &[line.bytes()]);
                    }
                    // The application is told of it, and may refuse it.
                    if let Some(c) = cx.easy().options().sockets.configure.clone() {
                        let set = SocketToSet(sock.socket(), SocketPurpose::Accept);
                        if c.configure(&mut TransferCx::new(&mut *cx), set) == Configured::Abort {
                            close_in(cx, sock);
                            return Err(ErrorKind::AbortedByCallback);
                        }
                    }
                    let stream = Stream::new(sock);
                    self.up_with(cx, host, stream, peer, Chain::accepted(), None)?;
                }
                up @ Phase::Up { shaken: true, .. } => {
                    self.phase = Some(up);
                    return Ok(Reached::Up);
                }
                Phase::Up {
                    mut stream,
                    peer,
                    chain: connected,
                    late,
                    ..
                } => {
                    let shaking = connected.with_tls(false);
                    if !std::mem::replace(entered, true) {
                        side::entered_tls(cx, shaking);
                    }
                    *chain = Some(shaking);
                    let tls = self.tls.as_mut().expect("only protected data shakes hands");
                    let mut close = false;
                    let mut carrier = Carrier::over(&mut stream, self.socket, &mut close);
                    let shook = crate::multi::state::tls::upgrade_resuming(
                        &mut carrier,
                        &tls.identity,
                        &tls.origin,
                        tls.via.as_deref(),
                        tls.resume.take(),
                        cx,
                    );
                    match shook {
                        Ok(Handshake::Done) => {
                            *chain = None;
                            // Said once all of it is connected, its TLS
                            // too (`conn_connect_trace`).
                            let made = connected.with_tls(true);
                            let late = late.map_or_else(Late::default, |l| l.late);
                            connected_all(cx, host, peer.as_ref(), &stream, made, late);
                            self.phase = Some(Phase::Up {
                                stream,
                                shaken: true,
                                peer: None,
                                chain: made,
                                late: None,
                            });
                        }
                        Ok(Handshake::Waiting) => {
                            let top = shaking.top().unwrap_or(Component::Ssl);
                            side::call_waits(cx, top);
                            self.phase = Some(Phase::Up {
                                stream,
                                shaken: false,
                                peer,
                                chain: connected,
                                late,
                            });
                            return Ok(Reached::Ip);
                        }
                        Err(kind) => {
                            close_in(cx, stream.into_socket());
                            return Err(kind);
                        }
                    }
                }
            }
        }
    }

    /// The connection `conn` is up, its proxies' handshakes made, and
    /// counted; its TLS follows if the data is protected. `late` is the
    /// resolve of its name still going on, if it is.
    fn up<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        host: &[u8],
        conn: crate::conn::Conn,
        late: Option<LateName>,
    ) -> Result<(), ErrorKind> {
        let connected = conn
            .connected_chain()
            .expect("a second connection is over the network")
            .on(ConnRank::Second);
        let (stream, remote) = conn.into_stream();
        // Counted as the transfer's connections are
        // (`cf_ip_happy_connect`'s `numconnects`).
        cx.report_mut().count_connect();
        self.up_with(cx, host, stream, remote, connected, late)
    }

    /// The connection `stream` to `peer` is up: said as C says it once
    /// all of it is connected, at once unless its TLS is still to be
    /// made (`conn_connect_trace`). The resolve of its name still going
    /// on, `late`, goes as all of it is connected, and is held until then.
    fn up_with<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        host: &[u8],
        stream: Stream,
        peer: Option<Remote>,
        chain: Chain,
        mut late: Option<LateName>,
    ) -> Result<(), ErrorKind> {
        let chain = chain.on(ConnRank::Second);
        let shaken = self.tls.is_none();
        if shaken {
            let late = late.take().map_or_else(Late::default, |l| l.late);
            connected_all(cx, host, peer.as_ref(), &stream, chain, late);
        } else {
            side::tls_added(cx, chain.with_tls(false));
        }
        let stream = match curl_alloc::try_box_or_back(stream) {
            Ok(stream) => stream,
            Err(stream) => {
                close_in(cx, stream.into_socket());
                return Err(ErrorKind::OutOfMemory);
            }
        };
        // Held until the TLS is made; too little memory to hold it fails
        // the connection, as C's filter fails to keep its resolve.
        let late = match late.map(curl_alloc::try_box).transpose() {
            Ok(late) => late,
            Err(curl_alloc::OutOfMemory) => {
                close_in(cx, (*stream).into_socket());
                return Err(ErrorKind::OutOfMemory);
            }
        };
        let peer = if shaken { None } else { peer };
        self.phase = Some(Phase::Up {
            stream,
            shaken,
            peer,
            chain,
            late,
        });
        Ok(())
    }

    /// The resolve of its name still going on, if it is, looked at: beside
    /// its setup, or beside it up, its TLS still being made. Each call asks
    /// the name's timer for it, and for a resolve a library answered whose
    /// record is still kept, as C's DNS filter does in each pollset
    /// (`Curl_resolv_pollset`).
    fn look_at_late<H: Host>(&mut self, cx: &mut StepCx<'_, H>) -> Result<(), ErrorKind> {
        match self.phase.as_mut() {
            Some(Phase::Connecting(machine, _)) => {
                let polled = machine.poll_late(&mut DriveCx::new(cx, None));
                match polled {
                    Ok(Some(found)) => crate::multi::state::side_resolved(cx, machine, found),
                    Ok(None) => {}
                    Err(e) => {
                        let route = machine.route().clone();
                        if let Some(Phase::Connecting(machine, _)) = self.phase.take() {
                            discard_in(cx, machine);
                        }
                        return Err(crate::multi::state::connect_failed(cx, &route, e));
                    }
                }
                crate::multi::state::side_setup_due(cx, machine);
                Ok(())
            }
            Some(Phase::Up {
                late: None,
                shaken: false,
                ..
            }) => {
                crate::multi::state::side_answered_due(cx);
                Ok(())
            }
            Some(Phase::Up {
                late: Some(late), ..
            }) => {
                let looked = late.look(cx);
                if looked.is_err()
                    && let Some(Phase::Up { stream, .. }) = self.phase.take()
                {
                    close_in(cx, stream.into_socket());
                }
                looked
            }
            _ => Ok(()),
        }
    }

    /// How far it has come, without moving it on.
    pub(crate) fn reached(&self) -> Reached {
        match self.phase.as_ref() {
            Some(Phase::Connecting(..) | Phase::Listening { .. }) | None => Reached::Connecting,
            Some(Phase::Up { shaken: false, .. }) => Reached::Ip,
            Some(Phase::Up { shaken: true, .. }) => Reached::Up,
        }
    }

    /// What its bytes go over, once connected; `close` takes the mark a
    /// protocol would set at its end, which no one reads.
    pub(crate) fn carrier<'a>(&'a mut self, close: &'a mut bool) -> Option<Carrier<'a>> {
        match self.phase.as_mut() {
            Some(Phase::Up { stream, .. }) => Some(Carrier::over(stream, self.socket, close)),
            _ => None,
        }
    }

    /// Its sockets, and what each waits for: a setup's attempts to
    /// connect, or the stream for `wanted` as its layers adjust it, and
    /// for what a handshake under way waits for. Once it is up, its
    /// layers are asked only if the transfer wants anything, `transfer`
    /// being all it wants on its connections: a layer's say for a
    /// transfer wanting nothing would be ready forever
    /// (`Curl_conn_adjust_pollset`).
    pub(crate) fn pollset(
        &self,
        wanted: Events,
        transfer: Events,
    ) -> impl Iterator<Item = (&dyn Socket, Events)> {
        let mut late_wants = None;
        let (racing, up) = match self.phase.as_ref() {
            Some(Phase::Connecting(m, side)) => (Some(side.pollset(m)), None),
            Some(Phase::Listening { sock, .. }) => (None, Some((sock.socket(), Events::IN))),
            Some(Phase::Up {
                stream,
                shaken,
                late,
                ..
            }) => {
                late_wants = late.as_deref().map(|l| l.late.wants());
                let events = match self.shut {
                    Some(shut) => stream.shutdown_pollset(shut),
                    // A handshake waits for what its layer says.
                    None if !*shaken => stream.adjust_pollset(Events::IN),
                    None if transfer.is_empty() => Events::NONE,
                    None => stream.adjust_pollset(wanted),
                };
                (None, Some((stream.socket(), events)))
            }
            None => (None, None),
        };
        // The resolve's sockets first, as its filter heads the chain.
        late_wants
            .into_iter()
            .flatten()
            .chain(racing.into_iter().flatten())
            .chain(up)
    }

    /// Move the shutdown of its direction the transfer used on, once it
    /// moved all its bytes (`Curl_cshutdn_try_once_idx`): whether it is
    /// done.
    pub(crate) fn shutdown<H: Host>(&mut self, cx: &mut StepCx<'_, H>) -> Result<bool, ErrorKind> {
        let Some(Phase::Up { stream, .. }) = self.phase.as_mut() else {
            return Ok(true);
        };
        let socket = self.socket;
        let started = self.shut.is_some();
        let shut = self.shut.get_or_insert(0);
        cx.as_second(|cx| {
            if !started {
                crate::multi::mstate::trace(
                    cx,
                    format_args!("shutdown start on secondary connection"),
                );
            }
            Ok(stream.shutdown(cx, socket, shut)? == Handshake::Done)
        })
    }

    /// Close it at once for the transfer (`Curl_conn_cf_discard_all`),
    /// its sockets' closes said.
    pub(crate) fn discard<H: Host>(self, cx: &mut StepCx<'_, H>) {
        cx.as_second(|cx| {
            let open = match self.phase.as_ref() {
                Some(Phase::Up { stream, .. }) => Some(stream.socket().key().get()),
                Some(Phase::Listening { sock, .. }) => Some(sock.key().get()),
                Some(Phase::Connecting(..)) | None => None,
            };
            if let Some(fd) = open {
                trace::of(cx, self.socket, format_args!("destroy"));
                trace::of(cx, self.socket, format_args!("cf_socket_close, fd={fd}"));
            }
            let mut dcx = DriveCx::new(cx, None);
            self.close(&mut dcx);
        });
    }

    /// Close it at once.
    pub(crate) fn close(mut self, net: &mut dyn Net) {
        match self.phase.take() {
            Some(Phase::Connecting(machine, _)) => machine.close(net),
            Some(Phase::Listening { sock, .. }) => net.close(sock),
            Some(Phase::Up { stream, .. }) => net.close(stream.into_socket()),
            None => {}
        }
    }
}

/// Give up `setup` for the transfer, its sockets' closes said.
fn discard_in<H: Host>(cx: &mut StepCx<'_, H>, setup: ConnectMachine) {
    setup.discard(&mut DriveCx::new(cx, None));
}

/// Close `socket` for the transfer, said as it goes.
fn close_in<H: Host>(cx: &mut StepCx<'_, H>, socket: crate::conn::io::Sock) {
    let mut dcx = DriveCx::new(cx, None);
    dcx.close(socket);
}

/// A listening socket as the accept filter's lines name it: its number,
/// and where it listens.
fn listens_at(sock: &Sock) -> (crate::conn::io::RawSocket, trace::Ip, u16) {
    let at = sock.socket().local_addr().ok();
    let port = at.map_or(0, |at| at.port());
    (sock.key().get(), trace::Ip(at.map(|at| at.ip())), port)
}

/// All of the chain is connected: the call ends, the connection is said
/// up, and its setup filters go.
fn connected_all<H: Host>(
    cx: &mut StepCx<'_, H>,
    host: &[u8],
    remote: Option<&Remote>,
    stream: &Stream,
    chain: Chain,
    late: Late,
) {
    side::call_connected(cx, chain, late);
    established(cx, host, remote, stream);
    side::setup_filters_go(cx, chain);
}

/// The connection is up: said as C says it (`conn_connect_trace`), the
/// control connection's host named.
fn established<H: Host>(
    cx: &mut StepCx<'_, H>,
    host: &[u8],
    remote: Option<&Remote>,
    stream: &Stream,
) {
    let Some(remote) = remote else {
        return;
    };
    let local = stream.local_addr();
    let (lip, lport) = local.map_or((None, 0), |l| (Some(l.ip()), l.port()));
    let lip = trace::Ip(lip);
    let mut line = trace::Line::new();
    line.raw(b"Established 2nd connection to ")
        .raw(host)
        .raw(b" (");
    line.raw(remote.shown_ip().bytes());
    line.text(format_args!(
        " port {}) from {lip} port {lport} ",
        remote.port()
    ));
    trace::info_with(cx, &[line.bytes()]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::io::{Conversation, FakeNet, Peer};
    use crate::conn::layer::testing::Asked;
    use crate::time::ManualClock;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// unit2606's second chain, the data connection (`SECONDARYSOCKET`):
    /// up and not shutting down, its layers are asked what to wait for
    /// only if the transfer wants anything of its connections, whatever
    /// the first chain is doing or adds; shutting down, they are asked
    /// whatever the transfer wants. A data connection still being set up
    /// (`c1_connected` false) has no counterpart here: its sockets are its
    /// setup's attempts and handshake, always polled
    /// (`SideSetup::pollset`). The first chain's cases are
    /// `unit2606_first_chain`'s.
    #[test]
    fn unit2606_second_chain() {
        let cases =
            crate::c_source::table("tests/unit/unit2606.c", "TEST_CASES[] =", |c| panic!("{c}"));
        assert_eq!(cases.len(), 9);
        let clock = ManualClock::new().unwrap();
        let at = std::net::SocketAddr::from(([127, 0, 0, 1], 1));
        let mut net = FakeNet::new(clock.clone())
            .with_peer(at, Peer::Accepts)
            .with_conversation(at, Conversation::replies(&[], false));
        let mut ported = 0;
        for case in &cases {
            let v = case.group();
            let flag = |i: usize| match v[i].word() {
                "TRUE" => true,
                "FALSE" => false,
                other => panic!("{other}"),
            };
            let id = v[0].int();
            let (has_c1, c1_connected, c1_shutdown, xfer_io) = (flag(1), flag(3), flag(5), flag(6));
            let want = usize::try_from(v[9].int()).unwrap();
            if !has_c1 || !c1_connected {
                assert_eq!(want, usize::from(has_c1), "case {id}");
                continue;
            }
            let calls = Arc::new(AtomicUsize::new(0));
            let socket = Sock::new(crate::conn::io::dial(&mut net, at), Closer::System);
            let mut stream = Stream::new(socket);
            stream
                .layers_mut()
                .push(curl_alloc::try_box(Asked(calls.clone())).unwrap())
                .unwrap();
            let data = DataConn {
                phase: Some(Phase::Up {
                    stream: Box::new(stream),
                    shaken: true,
                    peer: None,
                    chain: Chain::accepted(),
                    late: None,
                }),
                tls: None,
                socket: Component::Tcp,
                shut: c1_shutdown.then_some(0),
            };
            // The transfer's own wants, before any chain adds to them.
            let transfer = if xfer_io { Events::IN } else { Events::NONE };
            let added: Vec<Events> = data.pollset(transfer, transfer).map(|(_, e)| e).collect();
            assert_eq!(calls.load(Ordering::Relaxed), want, "case {id}");
            if want == 0 {
                assert!(added.iter().all(|e| e.is_empty()), "case {id}: {added:?}");
            }
            if let Some(Phase::Up { stream, .. }) = data.phase {
                net.close(stream.into_socket());
            }
            ported += 1;
        }
        assert_eq!(ported, 6);
    }
}
