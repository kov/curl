//! A scripted socket for the tests of a TLS library's sessions: what the
//! library sends is kept, what the peer sent waits to be read.

// A test's wire: out of memory here fails the test, not a transfer.
#![allow(clippy::disallowed_methods)]

use curl_alloc::Lock;
use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::num::NonZeroUsize;

use crate::conn::io::{
    Connect, Events, Readiness, Recv, Remote, Sent, Socket, SocketKey, SocketOption,
};

/// A connection's socket: what the peer sends waits in `incoming`, what
/// is sent is kept in `sent`; with nothing waiting a read would block,
/// or meets the end once `closed`. `refuses` fails every call.
#[derive(Debug, Default)]
pub struct Wire {
    pub incoming: Lock<VecDeque<u8>>,
    pub sent: Lock<Vec<u8>>,
    pub closed: bool,
    pub refuses: bool,
    /// Sends take at most this many bytes, if set; 0 takes none.
    pub room: Option<usize>,
}

impl Wire {
    /// A wire the peer has sent `bytes` on.
    pub fn with(bytes: &[u8]) -> Wire {
        let wire = Wire::default();
        wire.incoming
            .lock()
            .expect("no test panics holding the wire")
            .extend(bytes);
        wire
    }

    /// What was sent on it.
    pub fn sent(&self) -> Vec<u8> {
        self.sent
            .lock()
            .expect("no test panics holding the wire")
            .clone()
    }
}

impl Socket for Wire {
    fn key(&self) -> SocketKey {
        SocketKey::new(5)
    }
    fn readiness(&self) -> Readiness<'_> {
        Readiness::Known {
            now: Events::IN | Events::OUT,
            later: None,
        }
    }
    fn take_error(&self) -> io::Result<Option<io::Error>> {
        Ok(None)
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Err(io::ErrorKind::Unsupported.into())
    }
    fn set(&self, _: SocketOption) -> io::Result<()> {
        Ok(())
    }
    fn set_nonblocking(&self) -> io::Result<()> {
        Ok(())
    }
    fn bind(&self, _: SocketAddr) -> io::Result<()> {
        Ok(())
    }
    #[cfg(target_os = "linux")]
    fn bind_to_device(&self, _: &[u8]) -> io::Result<()> {
        Ok(())
    }
    fn connect(&self, _: &Remote) -> io::Result<Connect> {
        Ok(Connect::Done)
    }
    fn recv(&self, buf: &mut [u8]) -> io::Result<Recv> {
        if self.refuses {
            return Err(io::ErrorKind::ConnectionReset.into());
        }
        let mut incoming = self
            .incoming
            .lock()
            .expect("no test panics holding the wire");
        let n = buf.len().min(incoming.len());
        for (b, c) in buf.iter_mut().zip(incoming.drain(..n)) {
            *b = c;
        }
        Ok(match NonZeroUsize::new(n) {
            Some(n) => Recv::Data(n),
            None if self.closed => Recv::Eof,
            None => Recv::WouldBlock,
        })
    }
    fn send(&self, buf: &[u8]) -> io::Result<Sent> {
        if self.refuses {
            return Err(io::ErrorKind::ConnectionReset.into());
        }
        let n = self.room.map_or(buf.len(), |r| r.min(buf.len()));
        self.sent
            .lock()
            .expect("no test panics holding the wire")
            .extend_from_slice(&buf[..n]);
        Ok(match NonZeroUsize::new(n) {
            Some(n) => Sent::Bytes(n),
            None => Sent::WouldBlock,
        })
    }
    fn release(self: Box<Self>) -> SocketKey {
        SocketKey::new(5)
    }
}
