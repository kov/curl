//! A session of a TLS library quiche does not run over is refused before
//! anything of it is read, as the connection is made: never handed to
//! quiche as an SSL.

#![cfg(boringssl)]
#![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

use std::ffi::c_void;
use std::ptr::NonNull;
use std::time::Duration;

use curl_core::error::ErrorKind;
use curl_core::http3::{ClientSetup, ConnectFailed, Http3};
use curl_core::time::SystemClock;
use curl_core::tls::{DriveCall, QuicTls, QuicheTls, TlsCx, TlsKind, TlsNative, TlsTicket};
use curl_quiche::QUICHE;

/// Libraries other than OpenSSL's family: an application's own, and real
/// ones.
const OTHERS: [TlsKind; 3] = [TlsKind::Other, TlsKind::GnuTls, TlsKind::WolfSsl];

/// Objects no library made, which nothing may read.
fn unreadable(kind: TlsKind) -> TlsNative {
    TlsNative::new(kind, NonNull::dangling(), Some(NonNull::dangling()))
}

/// A QUIC session claiming to be of `kind`, with objects nothing may
/// read; one that offers to hand them over (`QuicheTls`) if `offers`.
struct Claiming(TlsKind, bool);

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

    fn quiche(&mut self) -> Option<&mut dyn QuicheTls> {
        match self.1 {
            true => Some(self),
            false => None,
        }
    }
}

impl QuicheTls for Claiming {
    fn give_up_session(&mut self) -> NonNull<c_void> {
        unreachable!("refused before it is asked")
    }

    fn unverified(&mut self, _: &mut TlsCx<'_>) -> Option<ErrorKind> {
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
    let refused = ConnectFailed::Crypto {
        why: "quiche runs over OpenSSL's TLS alone",
    };
    for kind in OTHERS {
        for offers in [false, true] {
            let made = QUICHE.client(&setup, Box::new(Claiming(kind, offers)));
            assert_eq!(made.unwrap_err(), refused, "{kind:?}");
        }
    }
    // A session saying it is OpenSSL's that cannot be handed over.
    let made = QUICHE.client(&setup, Box::new(Claiming(TlsKind::OpenSsl, false)));
    assert_eq!(made.unwrap_err(), refused);
}
