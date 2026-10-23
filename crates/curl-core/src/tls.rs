//! TLS, as the core asks it of the library bound beside it (C's
//! `vtls`): the settings a connection's handshake is made with, which
//! decide which connections a transfer may reuse, and the seam a TLS
//! library implements. The library makes a session for each connection
//! (`TlsBackend`), and the core drives it as a layer over the
//! connection's stream (`TlsSession`), handing it the layers below to
//! read and write through (`TlsIo`). The core names no library's types.

use std::fmt;
use std::io;
use std::net::Ipv4Addr;

use curl_alloc::{OutOfMemory, TryArc};

use crate::components::Component;
use crate::conn::Peer;
use crate::conn::io::{Recv, Sent};
use crate::conn::layer::{Below, LayerCx};
use crate::error::ErrorKind;
use crate::options::{Tls, TlsOptions};

pub use crate::conn::layer::Handshake;

/// A test double: a TLS library of text lines and scrambled records.
#[cfg(any(test, feature = "test-util"))]
pub mod fake;

/// A TLS library (C's `struct Curl_ssl`). Whoever builds a handle names
/// one in its `Libraries`; without one, no scheme that needs TLS is
/// built in.
pub trait TlsBackend: Send + Sync {
    /// A client session for one connection to `peer`, made with the
    /// settings `identity` holds (C's `ssl_connect_data` and its
    /// backend's context, made as the SSL filter is added).
    fn session(
        &self,
        identity: &TlsIdentity,
        peer: &TlsPeer<'_>,
    ) -> Result<Box<dyn TlsSession>, ErrorKind>;
}

impl fmt::Debug for dyn TlsBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TlsBackend")
    }
}

/// One connection's TLS, which the core drives (C's SSL filter): the
/// handshake, then the records both ways, then the goodbye. Each call
/// reads and writes the connection through `io` as it needs, and says
/// what it waits for when it cannot go on.
pub trait TlsSession: Send {
    /// Move the handshake on: done, or waiting for what `waits` says.
    fn handshake(&mut self, io: &mut TlsIo<'_>) -> Result<Handshake, ErrorKind>;

    /// Read into `buf`, which is not empty, at most its length of what
    /// the peer sent.
    fn recv(&mut self, io: &mut TlsIo<'_>, buf: &mut [u8]) -> io::Result<Recv>;

    /// Send from `bytes`, which is not empty.
    fn send(&mut self, io: &mut TlsIo<'_>, bytes: &[u8]) -> io::Result<Sent>;

    /// Move the goodbye on (close_notify, and the peer's).
    fn shutdown(&mut self, io: &mut TlsIo<'_>) -> Result<Handshake, ErrorKind>;

    /// What its last call that could not go on waits for on the socket
    /// (C's `io_need`): to read, or to write, which it may need while it
    /// reads.
    fn waits(&self) -> TlsWait;

    /// It holds bytes it read and has not given out, which a poll of the
    /// socket cannot see.
    fn pending(&self) -> bool;
}

/// What a TLS session waits for on the socket.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TlsWait {
    /// Nothing: what the transfer wants goes as it is.
    #[default]
    Nothing,
    /// To read, whatever the transfer wants.
    Recv,
    /// To write, whatever the transfer wants: its reads wait on it.
    Send,
}

/// Who a TLS session talks to: the origin as the URL names it (C's
/// `ssl_peer`), whose name the handshake sends and checks the
/// certificate against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TlsPeer<'a> {
    /// The host, an IPv6 address without its brackets.
    pub name: &'a [u8],
    pub port: u16,
    pub kind: TlsPeerKind,
}

/// What a TLS peer's name is: an address names no server (no SNI).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsPeerKind {
    Name,
    Ipv4,
    Ipv6,
}

impl<'a> TlsPeer<'a> {
    pub(crate) fn of(peer: &'a Peer) -> TlsPeer<'a> {
        let name = peer.name();
        let kind = if peer.ipv6() {
            TlsPeerKind::Ipv6
        } else if std::str::from_utf8(name).is_ok_and(|n| n.parse::<Ipv4Addr>().is_ok()) {
            TlsPeerKind::Ipv4
        } else {
            TlsPeerKind::Name
        };
        TlsPeer {
            name,
            port: peer.port(),
            kind,
        }
    }
}

/// What a TLS session reaches while it works, for the one call it is
/// given to: the layers below it, down to the socket, and the transfer
/// it works for. The bytes the connection received before the session
/// was made, after a proxy's answer, are read first.
pub struct TlsIo<'a> {
    below: Below<'a>,
    cx: &'a mut dyn LayerCx,
    early: &'a mut Vec<u8>,
    component: Component,
}

impl TlsIo<'_> {
    /// Read into `buf`, which is not empty, from what came before the
    /// session, else from below.
    pub fn recv(&mut self, buf: &mut [u8]) -> io::Result<Recv> {
        assert!(!buf.is_empty(), "a receive needs room");
        if let Some(n) = std::num::NonZeroUsize::new(self.early.len().min(buf.len())) {
            buf[..n.get()].copy_from_slice(&self.early[..n.get()]);
            self.early.drain(..n.get());
            return Ok(Recv::Data(n));
        }
        self.below.reborrow().recv(self.cx, buf)
    }

    /// Send from `bytes`, which is not empty, through the layers below.
    pub fn send(&mut self, bytes: &[u8]) -> io::Result<Sent> {
        self.below.reborrow().send(self.cx, bytes)
    }

    /// Trace a line of the layer's (`CURL_TRC_CF`), if its component is
    /// traced.
    pub fn trace(&mut self, line: fmt::Arguments<'_>) {
        self.cx.of(self.component, line);
    }

    /// A line of the transfer's verbose output (`infof`).
    pub fn info(&mut self, line: fmt::Arguments<'_>) {
        self.cx.info(line);
    }
}

impl<'a> TlsIo<'a> {
    pub(crate) fn new(
        below: Below<'a>,
        cx: &'a mut dyn LayerCx,
        early: &'a mut Vec<u8>,
        component: Component,
    ) -> TlsIo<'a> {
        TlsIo {
            below,
            cx,
            early,
            component,
        }
    }
}

/// Every setting a connection's TLS handshake was made with that a
/// transfer must share to reuse the connection (C's `ssl_filter_config`,
/// compared by `match_ssl_primary_config`). A route to a TLS peer holds
/// one, made from the transfer's options; the connection it sets up
/// keeps it.
#[derive(Debug)]
pub struct TlsIdentity {
    /// The peer's certificate must verify.
    pub verify_peer: bool,
    /// The certificate must name the host.
    pub verify_host: bool,
    pub options: TlsOptions,
}

impl TlsIdentity {
    /// The identity the transfer's options `tls` make, shared by its
    /// route and the connection set up for it.
    pub(crate) fn of(tls: &Tls) -> Result<TryArc<TlsIdentity>, OutOfMemory> {
        TryArc::try_new(TlsIdentity {
            verify_peer: tls.verify_peer,
            verify_host: tls.verify_host,
            options: tls.options.try_clone()?,
        })
    }
}

/// A connection made with one identity serves a transfer that wants the
/// other only if every setting matches, as `match_ssl_primary_config`
/// compares them: the paths, blobs, keys and certificates exactly, the
/// lists and the formats in any case, the key's password in constant
/// time.
impl PartialEq for TlsIdentity {
    fn eq(&self, other: &TlsIdentity) -> bool {
        // Every field by name, so that one added does not compile until
        // it is compared here or said why not.
        let TlsIdentity {
            verify_peer,
            verify_host,
            options,
        } = self;
        let TlsOptions {
            min_version,
            max_version,
            ssl_options,
            verify_status,
            ca_file,
            ca_path,
            ca_blob,
            crl_file,
            issuer_cert,
            issuer_cert_blob,
            cert,
            cert_blob,
            cert_type,
            key,
            key_blob,
            key_type,
            key_password,
            ciphers,
            tls13_ciphers,
            curves,
            signature_algorithms,
            pinned_key,
            // The handle's, not the connection's: C reads it as the
            // handshake starts and matches no connection by it.
            alpn: _,
        } = options;
        let o = &other.options;
        *verify_peer == other.verify_peer
            && *verify_host == other.verify_host
            && *min_version == o.min_version
            && *max_version == o.max_version
            && *ssl_options == o.ssl_options
            && *verify_status == o.verify_status
            && *ca_file == o.ca_file
            && *ca_path == o.ca_path
            && *ca_blob == o.ca_blob
            && *crl_file == o.crl_file
            && *issuer_cert == o.issuer_cert
            && *issuer_cert_blob == o.issuer_cert_blob
            && *cert == o.cert
            && *cert_blob == o.cert_blob
            && same_name(cert_type, &o.cert_type)
            && *key == o.key
            && *key_blob == o.key_blob
            && same_name(key_type, &o.key_type)
            && same_secret(key_password, &o.key_password)
            && same_name(ciphers, &o.ciphers)
            && same_name(tls13_ciphers, &o.tls13_ciphers)
            && same_name(curves, &o.curves)
            && same_name(signature_algorithms, &o.signature_algorithms)
            && *pinned_key == o.pinned_key
    }
}

impl Eq for TlsIdentity {}

/// The same list or format, in any case (`curl_strequal`), or neither.
fn same_name(a: &Option<Vec<u8>>, b: &Option<Vec<u8>>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
        (a, b) => a.is_none() && b.is_none(),
    }
}

/// The same secret, or neither, compared in a time that does not depend
/// on where they first differ (`Curl_timestrcmp`).
fn same_secret(a: &Option<Vec<u8>>, b: &Option<Vec<u8>>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => {
            a.len() == b.len() && a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
        }
        (a, b) => a.is_none() && b.is_none(),
    }
}

#[cfg(test)]
mod tests;
