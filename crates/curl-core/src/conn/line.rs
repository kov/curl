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
    /// logged in; boxed, as it is larger than the others'. The data
    /// connection is the transfer's, not the connection's.
    Ftp(Box<crate::proto::ftp::FtpConn>),
    /// POP3's: its back and forth, and how it logged in.
    Pop3(crate::proto::pop3::Pop3Conn),
    /// IMAP's: its back and forth, how it logged in, and the mailbox
    /// it selected.
    Imap(crate::proto::imap::ImapConn),
    /// SMTP's: its back and forth, what the server offered, how it
    /// logged in, and the name it greets the server with.
    Smtp(crate::proto::smtp::SmtpConn),
    /// SCP's and SFTP's: the SSH library's session over the connection's
    /// socket, and where its state machine is; boxed, as FTP's.
    Ssh(Box<crate::proto::ssh::SshConn>),
    /// LDAP's: the library's session over a copy of the connection's
    /// socket, and where its set-up is; boxed, as FTP's.
    Ldap(Box<crate::proto::ldap::LdapConn>),
    /// A WebSocket's, switched to from HTTP/1.1 by a 101: its frames'
    /// decoder and encoder and their buffers; boxed, as FTP's. It says
    /// no goodbye (C's WebSocket has no `disconnect`).
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
    /// sent as the connection takes it now, its answer never waited on.
    /// A connection `dead`, whose state no one knows (a transfer on it
    /// aborted), is told so and says nothing (`dead_connection`).
    pub(crate) fn goodbye(&mut self, cx: &mut dyn LayerCx, below: Carrier<'_>, dead: bool) {
        match *self {
            LineConn::Ftp(ref mut p) => p.goodbye(cx, below, dead),
            LineConn::Pop3(ref mut p) => p.goodbye(cx, below, dead),
            LineConn::Imap(ref mut p) => p.goodbye(cx, below, dead),
            LineConn::Smtp(ref mut p) => p.goodbye(cx, below, dead),
            // Said dead or not, as C's SSH disconnect ignores it.
            LineConn::Ssh(ref mut p) => p.goodbye(cx),
            // Unbound dead or not, as C's LDAP disconnect ignores it.
            LineConn::Ldap(ref mut p) => p.goodbye(cx, below),
            LineConn::Ws(_) | LineConn::Rtsp(_) => {}
            #[cfg(any(test, feature = "test-util"))]
            LineConn::Test(ref mut f) => f.goodbye(cx, below, dead),
        }
    }
}

/// The test protocol's state: the goodbye it sends.
#[cfg(any(test, feature = "test-util"))]
#[derive(Debug)]
pub(crate) struct Farewell(pub(crate) Vec<u8>);

#[cfg(any(test, feature = "test-util"))]
impl Farewell {
    fn goodbye(&mut self, cx: &mut dyn LayerCx, mut below: Carrier<'_>, dead: bool) {
        if !dead {
            // What does not go now is not said, as a shutdown waits on
            // no goodbye.
            let _sent = below.send(cx, &self.0);
        }
    }
}
