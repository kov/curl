//! A TLS library's own objects, tagged with the library that made them,
//! which `curl_core::tls` re-exports.
//!
//! A crate of its own for one declaration: claiming that two pointers are
//! a named library's objects is unsafe (`TlsNative::new`), as a QUIC
//! library built for that library casts them to its own types on the
//! claim's word. `curl-core` forbids unsafe code, so the claim is made
//! here. There are no unsafe blocks outside the tests.

#![allow(unsafe_code)]

use std::ffi::c_void;
use std::ptr::NonNull;

/// Which TLS library a backend is, as far as anything bound beside it
/// tells them apart: the C ABI's backend ids, and the QUIC libraries,
/// whose crypto is built for one library and reads that library's
/// objects alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsKind {
    /// OpenSSL, or one of its forks the crate builds over (LibreSSL,
    /// BoringSSL, AWS-LC): one kind, as one build links one of them.
    OpenSsl,
    GnuTls,
    WolfSsl,
    MbedTls,
    Rustls,
    Schannel,
    /// A library none of the above: one of an application's own, or the
    /// tests' fake. No QUIC library drives its sessions.
    Other,
}

/// A TLS library's own objects for one connection, which an application
/// using that library itself may be handed (`CURLINFO_TLS_SSL_PTR`,
/// `CURLINFO_TLS_SESSION`, `CURLOPT_SSL_CTX_FUNCTION`): the context the
/// session is made from, and the session's own object once it is made.
/// The core passes them on and never looks through them: what they are
/// is the library's to say, and they live while the connection does,
/// which a transfer reaches only while it holds it. They carry the kind
/// of library that made them, which a QUIC library whose crypto reads
/// them checks before it looks through them: one built for another
/// library refuses them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TlsNative {
    kind: TlsKind,
    context: NonNull<c_void>,
    session: Option<NonNull<c_void>>,
}

impl TlsNative {
    /// The objects of a library of `kind`, which only that library's
    /// backend makes. Panics on [`TlsKind::Other`], whose objects
    /// [`TlsNative::other`] makes.
    ///
    /// # Safety
    ///
    /// `context`, and `session` when given, are live objects of the
    /// library `kind` names, of the types it hands out for them (for
    /// OpenSSL an `SSL_CTX` and an `SSL`), and they live while the
    /// connection that hands them out does. A QUIC library built for
    /// that library casts them to its own types once it has checked the
    /// kind.
    pub unsafe fn new(
        kind: TlsKind,
        context: NonNull<c_void>,
        session: Option<NonNull<c_void>>,
    ) -> TlsNative {
        assert_ne!(kind, TlsKind::Other, "an unnamed library's are other()'s");
        TlsNative {
            kind,
            context,
            session,
        }
    }

    /// The objects of a library none of the others names
    /// ([`TlsKind::Other`]): one of an application's own, or the tests'
    /// fake. Nothing that checks the kind looks through them.
    pub fn other(context: NonNull<c_void>, session: Option<NonNull<c_void>>) -> TlsNative {
        TlsNative {
            kind: TlsKind::Other,
            context,
            session,
        }
    }

    /// The kind of library that made them.
    pub fn kind(self) -> TlsKind {
        self.kind
    }

    /// The context the session is made from (OpenSSL's `SSL_CTX`).
    pub fn context(self) -> NonNull<c_void> {
        self.context
    }

    /// The session's own object (OpenSSL's `SSL`), once it is made.
    pub fn session(self) -> Option<NonNull<c_void>> {
        self.session
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn other_s_objects_are_of_no_library() {
        let n = TlsNative::other(NonNull::dangling(), None);
        assert_eq!(n.kind(), TlsKind::Other);
        assert_eq!(n.session(), None);
    }

    #[test]
    #[should_panic(expected = "other()")]
    fn a_claim_of_no_library_is_refused() {
        // SAFETY: refused before anything is made of the pointers, which
        // nothing reads.
        let _ = unsafe { TlsNative::new(TlsKind::Other, NonNull::dangling(), None) };
    }
}
