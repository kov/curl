//! What a protocol keeps of a connection it speaks without a session
//! (C's `connectdata` meta data the scheme's `connect_it` hangs on it):
//! FTP's, IMAP's, POP3's, SMTP's and SSH's state between requests, and
//! the goodbye each says as the connection shuts down (the scheme's
//! `disconnect`). The connection holds it as what it speaks, so that it
//! is one fact with a session: no protocol has both. IMAP's, POP3's
//! and SMTP's are built, and the test protocol's.

use super::layer::LayerCx;
use super::mux::Carrier;

/// A protocol's state on its connection.
#[derive(Debug)]
pub(crate) enum LineConn {
    /// POP3's: its back and forth, and how it logged in.
    Pop3(crate::proto::pop3::Pop3Conn),
    /// IMAP's: its back and forth, how it logged in, and the mailbox
    /// it selected.
    Imap(crate::proto::imap::ImapConn),
    /// SMTP's: its back and forth, what the server offered, how it
    /// logged in, and the name it greets the server with.
    Smtp(crate::proto::smtp::SmtpConn),
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
            LineConn::Pop3(ref mut p) => p.goodbye(cx, below, dead),
            LineConn::Imap(ref mut p) => p.goodbye(cx, below, dead),
            LineConn::Smtp(ref mut p) => p.goodbye(cx, below, dead),
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
