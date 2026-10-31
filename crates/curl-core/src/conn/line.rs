//! What a protocol keeps of a connection it speaks without a session
//! (C's `connectdata` meta data the scheme's `connect_it` hangs on it):
//! FTP's, IMAP's, POP3's, SMTP's and SSH's state between requests, and
//! the goodbye each says as the connection shuts down (the scheme's
//! `disconnect`). The connection holds it as what it speaks, so that it
//! is one fact with a session: no protocol has both. Each is built, and
//! the test protocol's.

use super::layer::LayerCx;
use super::mux::Carrier;

/// A protocol's state on its connection.
#[derive(Debug)]
pub(crate) enum LineConn {
    /// FTP's: its back and forth, where it is on the server, how it
    /// logged in, and the data connection a transfer has open; boxed, as
    /// it is larger than the others'.
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
    /// `tcp:`'s, which says a goodbye of its own.
    #[cfg(any(test, feature = "test-util"))]
    Test(Farewell),
}

impl LineConn {
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
            #[cfg(any(test, feature = "test-util"))]
            LineConn::Test(ref mut f) => f.goodbye(cx, below, dead),
        }
    }
}

impl LineConn {
    /// Close what it has open beside the connection, as the connection
    /// closes: FTP's data connection.
    pub(crate) fn close(&mut self, net: &mut dyn super::io::Net) {
        if let LineConn::Ftp(p) = self {
            p.close(net);
        }
    }

    /// The sockets it has open beside the connection, and what each
    /// waits for, the transfer wanting `wanted` of them.
    pub(crate) fn side_pollset(
        &self,
        wanted: super::io::Events,
    ) -> impl Iterator<Item = (&dyn super::io::Socket, super::io::Events)> {
        let ftp = match self {
            LineConn::Ftp(p) => Some(p.data_pollset(wanted)),
            _ => None,
        };
        ftp.into_iter().flatten()
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
