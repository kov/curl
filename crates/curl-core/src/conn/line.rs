//! What a protocol keeps of a connection it speaks without a session
//! (C's `connectdata` meta data the scheme's `connect_it` hangs on it):
//! FTP's, IMAP's, POP3's, SMTP's, SSH's, LDAP's and WebSocket's state between requests, and
//! the goodbye each says as the connection shuts down (the scheme's
//! `disconnect`). The connection holds it as what it speaks, so that it
//! is one fact with a session: no protocol has both. Each is built, and
//! the test protocol's. A WebSocket's is put on the HTTP/1.1 connection
//! its upgrade switched.

use super::layer::LayerCx;
use super::mux::Carrier;

/// A protocol's state on its connection.
#[derive(Debug)]
pub(crate) enum LineConn {
    /// FTP's: its back and forth, where it is on the server, and how it
    /// logged in. The data connection is the transfer's, not the
    /// connection's.
    Ftp(crate::proto::ftp::FtpConn),
    /// POP3's: its back and forth, and how it logged in.
    Pop3(crate::proto::pop3::Pop3Conn),
    /// IMAP's: its back and forth, how it logged in, and the mailbox
    /// it selected.
    Imap(crate::proto::imap::ImapConn),
    /// SMTP's: its back and forth, what the server offered, how it
    /// logged in, and the name it greets the server with.
    Smtp(crate::proto::smtp::SmtpConn),
    /// SCP's and SFTP's: the SSH library's session over the connection's
    /// socket, and where its state machine is.
    Ssh(crate::proto::ssh::SshConn),
    /// LDAP's: the library's session over a copy of the connection's
    /// socket, and where its set-up is.
    Ldap(crate::proto::ldap::LdapConn),
    /// A WebSocket's, switched to from HTTP/1.1 by a 101: its frames'
    /// decoder and encoder and their buffers; boxed, as only a WebSocket
    /// should pay for them. It says no goodbye (C's WebSocket has no
    /// `disconnect`).
    Ws(Box<crate::proto::ws::WsConn>),
    /// RTSP's: an RTP message read in part between responses. It says no
    /// goodbye (C's RTSP has no `disconnect`).
    Rtsp(crate::proto::http::rtsp::RtspConn),
    /// `tcp:`'s, which says a goodbye of its own.
    #[cfg(any(test, feature = "test-util"))]
    Test(Farewell),
}

impl LineConn {
    /// Whether it says a goodbye as the connection shuts down, which C's
    /// debug build traces (the scheme has a `disconnect`).
    pub(crate) fn says_goodbye(&self) -> bool {
        !matches!(self, LineConn::Ws(_) | LineConn::Rtsp(_))
    }

    /// Say goodbye to the peer as the connection shuts down, asked once
    /// whatever the shutdown does after (`cshutdn_run_conn_handler`):
    /// sent as the connection takes it now. FTP's `QUIT`, POP3's and
    /// SMTP's, and IMAP's `LOGOUT` await an answer, as C's blocking waits
    /// do (`ftp_quit`, `pop3_block_statemach` and the others):
    /// [`Goodbye::Awaited`] while it has not come, which
    /// [`goodbye_answer`](Self::goodbye_answer) reads on. A connection
    /// `dead`, whose state no one knows (a transfer on it aborted), is
    /// told so and says nothing (`dead_connection`).
    pub(crate) fn goodbye(
        &mut self,
        cx: &mut dyn LayerCx,
        below: Carrier<'_>,
        dead: bool,
    ) -> Goodbye {
        match *self {
            LineConn::Ftp(ref mut p) => return p.goodbye(cx, below, dead),
            LineConn::Pop3(ref mut p) => return p.goodbye(cx, below, dead),
            LineConn::Imap(ref mut p) => return p.goodbye(cx, below, dead),
            LineConn::Smtp(ref mut p) => return p.goodbye(cx, below, dead),
            // Said dead or not, as C's SSH disconnect ignores it.
            LineConn::Ssh(ref mut p) => p.goodbye(cx),
            // Unbound dead or not, as C's LDAP disconnect ignores it.
            LineConn::Ldap(ref mut p) => p.goodbye(cx, below),
            LineConn::Ws(_) | LineConn::Rtsp(_) => {}
            #[cfg(any(test, feature = "test-util"))]
            LineConn::Test(ref mut f) => f.goodbye(cx, below, dead),
        }
        Goodbye::Done
    }

    /// Read on the answer its goodbye awaits, as far as the connection
    /// lets that now: `Done` once it came, or once the connection failed
    /// or closed.
    pub(crate) fn goodbye_answer(&mut self, cx: &mut dyn LayerCx, below: Carrier<'_>) -> Goodbye {
        match *self {
            LineConn::Ftp(ref mut p) => p.goodbye_answer(cx, below),
            LineConn::Pop3(ref mut p) => p.goodbye_answer(cx, below),
            LineConn::Imap(ref mut p) => p.goodbye_answer(cx, below),
            LineConn::Smtp(ref mut p) => p.goodbye_answer(cx, below),
            _ => panic!("only a pingpong protocol's goodbye awaits an answer"),
        }
    }

    /// What a goodbye awaiting its answer waits on: the socket to take
    /// the rest of it, or the answer.
    pub(crate) fn goodbye_wants(&self) -> super::io::Events {
        match *self {
            LineConn::Ftp(ref p) => p.goodbye_wants(),
            LineConn::Pop3(ref p) => p.goodbye_wants(),
            LineConn::Imap(ref p) => p.goodbye_wants(),
            LineConn::Smtp(ref p) => p.goodbye_wants(),
            _ => panic!("only a pingpong protocol's goodbye awaits an answer"),
        }
    }
}

/// How a protocol's goodbye stands, said or read on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Goodbye {
    /// Nothing is awaited: it awaits no answer, or the answer came, or
    /// the connection failed or closed.
    Done,
    /// Its answer is awaited; `moved` if this call sent some of the
    /// goodbye or read some of the answer.
    Awaited { moved: bool },
}

/// The test protocol's state: the goodbye it sends.
#[cfg(any(test, feature = "test-util"))]
#[derive(Debug)]
pub(crate) struct Farewell(pub(crate) Vec<u8>);

#[cfg(any(test, feature = "test-util"))]
impl Farewell {
    fn goodbye(&mut self, cx: &mut dyn LayerCx, mut below: Carrier<'_>, dead: bool) {
        if !dead {
            // What does not go now is not said, and no answer is
            // awaited.
            let _sent = below.send(cx, &self.0);
        }
    }
}
