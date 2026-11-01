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
use crate::conn::chain::SetupPoint;
use crate::conn::io::{Closer, Events, Net, Remote, Sock, Socket};
use crate::conn::mux::Carrier;
use crate::conn::shutdown::ConnSettings;
use crate::conn::{ConnNumber, Dial, NetRoute, Peer, Stream};
use crate::conn::{ConnectMachine, Drove, Progress};
use crate::error::ErrorKind;
use crate::multi::Host;
use crate::multi::cx::DriveCx;
use crate::multi::state::{SetupLend, Shaken, SideSetup, StepCx};
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
enum Phase {
    /// Being set up: its first hop dialed, then the handshakes over it.
    Connecting(Box<ConnectMachine>, SideSetup),
    /// Listening for the server to connect, until `deadline`
    /// (`cf_tcp_accept`).
    Listening {
        sock: Sock,
        deadline: crate::time::Instant,
    },
    /// Connected, its TLS made if `shaken`; until then, the peer it is
    /// said to be connected to once it is made.
    Up {
        stream: Box<Stream>,
        shaken: bool,
        peer: Option<Remote>,
    },
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
    pub(crate) fn start(
        number: ConnNumber,
        route: NetRoute,
        closer: Closer,
        tls: Option<DataTls>,
        now: crate::time::Instant,
    ) -> Result<DataConn, ErrorKind> {
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
        let machine = curl_alloc::try_box(machine).map_err(|_| ErrorKind::OutOfMemory)?;
        Ok(DataConn {
            phase: Some(Phase::Connecting(machine, SideSetup::default())),
            tls,
            socket,
            shut: None,
        })
    }

    /// One accepted on `sock`, listening, before `deadline`; protected by
    /// `tls` once connected, if given. The socket accepted is closed by the
    /// library, never the application's closer (`cf_socket_close`'s
    /// `!ctx->accepted`).
    pub(crate) fn listening(
        sock: Sock,
        tls: Option<DataTls>,
        deadline: crate::time::Instant,
    ) -> DataConn {
        DataConn {
            phase: Some(Phase::Listening { sock, deadline }),
            tls,
            socket: Component::Tcp,
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
        loop {
            match self
                .phase
                .take()
                .expect("a data connection is set up or up")
            {
                Phase::Connecting(mut machine, mut side) => {
                    if let SetupPoint::Dialed(_) = machine.reached() {
                        match side.shake(&mut machine, request, cx) {
                            Ok(Shaken::Waiting) => {
                                self.phase = Some(Phase::Connecting(machine, side));
                                return Ok(Reached::Connecting);
                            }
                            Ok(Shaken::Redialed) => {
                                self.phase = Some(Phase::Connecting(machine, side));
                                continue;
                            }
                            Ok(Shaken::Up) => {
                                let conn = (*machine).handshaken();
                                crate::multi::state::side_let_go(cx);
                                self.up(cx, host, conn)?;
                                continue;
                            }
                            Err(kind) => {
                                discard_in(cx, *machine);
                                crate::multi::state::side_let_go(cx);
                                return Err(kind);
                            }
                        }
                    }
                    let route = machine.route().clone();
                    match crate::multi::state::side_drive(cx, *machine) {
                        Ok(Drove::Connecting(m, progress)) => {
                            let mut m = match curl_alloc::try_box_or_back(m) {
                                Ok(m) => m,
                                Err(m) => {
                                    let answered = m.answer().is_some();
                                    discard_in(cx, m);
                                    if answered {
                                        crate::multi::state::side_let_go(cx);
                                    }
                                    return Err(ErrorKind::OutOfMemory);
                                }
                            };
                            if let Progress::Resolved(found) = progress {
                                crate::multi::state::side_resolved(cx, &m, found);
                            }
                            crate::multi::state::side_progress(cx, &route, &progress, || {
                                m.dialed().ends().0
                            });
                            self.phase = Some(Phase::Connecting(m, side));
                            match progress {
                                // Moved on: on again at once, to its
                                // handshakes if it dialed a proxy.
                                Progress::Resolved(_)
                                | Progress::Failed
                                | Progress::Dialed
                                | Progress::Trying { at_once: true, .. } => {}
                                _ => return Ok(Reached::Connecting),
                            }
                        }
                        Ok(Drove::Established(conn)) => {
                            if let Some(remote) = conn.remote() {
                                crate::multi::state::side_won(cx, &route, remote);
                            }
                            self.up(cx, host, conn)?;
                        }
                        Err(e) => return Err(crate::multi::state::connect_failed(cx, &route, e)),
                    }
                }
                Phase::Listening { sock, deadline } => {
                    // Its timer wakes it at the deadline itself.
                    if cx.now() >= deadline {
                        close_in(cx, sock);
                        return Err(trace::fail(
                            cx,
                            ErrorKind::FtpAcceptTimeout,
                            format_args!("Accept timeout occurred while waiting server connect"),
                        ));
                    }
                    let accepted = match sock.socket().accept() {
                        Ok(None) => {
                            self.phase = Some(Phase::Listening { sock, deadline });
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
                    // The application is told of it, and may refuse it.
                    if let Some(c) = cx.easy().options().sockets.configure.clone() {
                        let set = SocketToSet(sock.socket(), SocketPurpose::Accept);
                        if c.configure(&mut TransferCx::new(&mut *cx), set) == Configured::Abort {
                            close_in(cx, sock);
                            return Err(ErrorKind::AbortedByCallback);
                        }
                    }
                    let stream = Stream::new(sock);
                    self.up_with(cx, host, stream, peer)?;
                }
                up @ Phase::Up { shaken: true, .. } => {
                    self.phase = Some(up);
                    return Ok(Reached::Up);
                }
                Phase::Up {
                    mut stream, peer, ..
                } => {
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
                            // Said once all of it is connected, its TLS
                            // too (`conn_connect_trace`).
                            established(cx, host, peer.as_ref(), &stream);
                            self.phase = Some(Phase::Up {
                                stream,
                                shaken: true,
                                peer: None,
                            });
                        }
                        Ok(Handshake::Waiting) => {
                            self.phase = Some(Phase::Up {
                                stream,
                                shaken: false,
                                peer,
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
    /// counted; its TLS follows if the data is protected.
    fn up<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        host: &[u8],
        conn: crate::conn::Conn,
    ) -> Result<(), ErrorKind> {
        let (stream, remote) = conn.into_stream();
        // Counted as the transfer's connections are
        // (`cf_ip_happy_connect`'s `numconnects`).
        cx.report_mut().count_connect();
        self.up_with(cx, host, stream, remote)
    }

    /// The connection `stream` to `peer` is up: said as C says it once
    /// all of it is connected, at once unless its TLS is still to be
    /// made (`conn_connect_trace`).
    fn up_with<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        host: &[u8],
        stream: Stream,
        peer: Option<Remote>,
    ) -> Result<(), ErrorKind> {
        let shaken = self.tls.is_none();
        if shaken {
            established(cx, host, peer.as_ref(), &stream);
        }
        let stream = match curl_alloc::try_box_or_back(stream) {
            Ok(stream) => stream,
            Err(stream) => {
                close_in(cx, stream.into_socket());
                return Err(ErrorKind::OutOfMemory);
            }
        };
        let peer = if shaken { None } else { peer };
        self.phase = Some(Phase::Up {
            stream,
            shaken,
            peer,
        });
        Ok(())
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
    /// for what a handshake under way waits for.
    pub(crate) fn pollset(&self, wanted: Events) -> impl Iterator<Item = (&dyn Socket, Events)> {
        let (racing, up) = match self.phase.as_ref() {
            Some(Phase::Connecting(m, side)) => (Some(side.pollset(m)), None),
            Some(Phase::Listening { sock, .. }) => (None, Some((sock.socket(), Events::IN))),
            Some(Phase::Up { stream, shaken, .. }) => {
                let events = match self.shut {
                    Some(shut) => stream.shutdown_pollset(shut),
                    // A handshake waits for what its layer says.
                    None if !*shaken => stream.adjust_pollset(Events::IN),
                    None => stream.adjust_pollset(wanted),
                };
                (None, Some((stream.socket(), events)))
            }
            None => (None, None),
        };
        racing.into_iter().flatten().chain(up)
    }

    /// Move the shutdown of its direction the transfer used on, once it
    /// moved all its bytes (`Curl_cshutdn_try_once_idx`): whether it is
    /// done.
    pub(crate) fn shutdown<H: Host>(&mut self, cx: &mut StepCx<'_, H>) -> Result<bool, ErrorKind> {
        let Some(Phase::Up { stream, .. }) = self.phase.as_mut() else {
            return Ok(true);
        };
        let shut = self.shut.get_or_insert(0);
        Ok(stream.shutdown(cx, shut)? == Handshake::Done)
    }

    /// Close it at once for the transfer (`Curl_conn_cf_discard_all`),
    /// its sockets' closes said.
    pub(crate) fn discard<H: Host>(self, cx: &mut StepCx<'_, H>) {
        let mut dcx = DriveCx {
            step: cx,
            kept: None,
            deadlines: None,
        };
        self.close(&mut dcx);
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
    setup.discard(&mut DriveCx {
        step: cx,
        kept: None,
        deadlines: None,
    });
}

/// Close `socket` for the transfer, said as it goes.
fn close_in<H: Host>(cx: &mut StepCx<'_, H>, socket: crate::conn::io::Sock) {
    let mut dcx = DriveCx {
        step: cx,
        kept: None,
        deadlines: None,
    };
    dcx.close(socket);
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
