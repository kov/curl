//! A session of a TLS library ngtcp2's crypto is not built for is refused
//! before anything of it is read, as the context set up and as the
//! connection is made: never cast to the crypto's own objects.

#![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

use std::ptr::NonNull;
use std::time::Duration;

use curl_core::error::ErrorKind;
use curl_core::http3::{ClientSetup, ConnectFailed, Http3};
use curl_core::time::SystemClock;
use curl_core::tls::{DriveCall, QuicTls, TlsCx, TlsKind, TlsNative, TlsTicket};
use curl_ngtcp2::NGTCP2;

// The library ngtcp2's wolfSSL crypto calls, which nothing here names.
#[cfg(feature = "wolfssl")]
extern crate curl_wolfssl;

/// A library other than the crypto's: an application's own, and a real
/// one the crypto is not built for.
fn others() -> [TlsKind; 2] {
    let real = if cfg!(feature = "gnutls") {
        TlsKind::WolfSsl
    } else {
        TlsKind::GnuTls
    };
    [TlsKind::Other, real]
}

/// Objects no library made, which nothing may read, claimed to be
/// `kind`'s.
#[allow(unsafe_code)]
fn unreadable(kind: TlsKind) -> TlsNative {
    let (context, session) = (NonNull::dangling(), Some(NonNull::dangling()));
    if kind == TlsKind::Other {
        return TlsNative::other(context, session);
    }
    // SAFETY: broken on purpose: these are no library's objects, claimed
    // to be `kind`'s, and what is under test is that the QUIC library
    // refuses them before it reads either. Nothing else is handed them.
    unsafe { TlsNative::new(kind, context, session) }
}

/// A QUIC session claiming to be of `kind`, with objects nothing may read.
struct Claiming(TlsKind);

impl QuicTls for Claiming {
    fn native(&self) -> TlsNative {
        unreadable(self.0)
    }

    fn early_data(&self) -> Option<&TlsTicket> {
        None
    }

    fn early_data_decided(&mut self, _: &mut TlsCx<'_>, _: bool) -> Result<(), ErrorKind> {
        unreachable!("no connection is made")
    }

    fn before_recv(&mut self, _: &mut TlsCx<'_>) -> Result<(), ErrorKind> {
        unreachable!("no connection is made")
    }

    fn drive(
        &mut self,
        _: &mut TlsCx<'_>,
        _: &mut dyn FnMut() -> Option<Vec<u8>>,
        _: &mut dyn FnMut(&mut dyn DriveCall),
    ) {
        unreachable!("no connection is made")
    }
}

#[test]
fn another_library_s_session_is_refused() {
    let setup = ClientSetup {
        local: "127.0.0.1:1".parse().unwrap(),
        remote: "127.0.0.1:2".parse().unwrap(),
        now: SystemClock::new().now(),
        handshake_timeout: Duration::from_secs(10),
        max_window: 1024 * 1024,
        stream_window: 32 * 1024,
        max_streams: 100,
        qlog: None,
    };
    let why = "ngtcp2's crypto is not for the TLS library of the session";
    for kind in others() {
        assert_eq!(
            NGTCP2.setup_tls_context(unreadable(kind)),
            Err(why),
            "{kind:?}"
        );
        let made = NGTCP2.client(&setup, Box::new(Claiming(kind)));
        assert_eq!(made.unwrap_err(), ConnectFailed::Crypto { why }, "{kind:?}");
    }
    // The tests' fake, of no library ngtcp2 knows.
    let fake = curl_core::tls::fake::quic_session().unwrap();
    let made = NGTCP2.client(&setup, fake);
    assert_eq!(made.unwrap_err(), ConnectFailed::Crypto { why });
}
