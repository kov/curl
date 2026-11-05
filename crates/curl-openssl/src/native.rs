//! Which certificates of the system's own store a session trusts, as C
//! picks them from Windows' (`ossl_win_load_store`): each valid now, able
//! to sign certificates if it says what its key is for, and meant for
//! server authentication by what it or the system says of its uses. The
//! choice is made here from what the system says of each certificate,
//! which the Windows module asks it.

/// The object id of server authentication (`szOID_PKIX_KP_SERVER_AUTH`).
const SERVER_AUTH: &[u8] = b"1.3.6.1.5.5.7.3.1";

/// `CERT_KEY_CERT_SIGN_KEY_USAGE`: the key signs certificates.
const KEY_CERT_SIGN: u8 = 0x04;

/// What the certificate's key usage extension says
/// (`CertGetIntendedKeyUsage`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KeyUsage {
    /// Its first byte of usage bits.
    Says(u8),
    /// It has none.
    Absent,
    /// It could not be read (the call failed with an error).
    Unreadable,
}

/// What the system says the certificate may be used for, from its
/// enhanced key usage extension and its properties
/// (`CertGetEnhancedKeyUsage`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Uses {
    /// The system says nothing: the call that sizes the answer failed, or
    /// sized it at nothing.
    Unsaid,
    /// The answer could not be read.
    Unreadable,
    /// No use is named, and the system says that means every use
    /// (`CRYPT_E_NOT_FOUND`).
    Every,
    /// No use is named, and the system says that means none.
    None,
    /// Uses are named, server authentication among them or not, as
    /// `names_server_auth` finds it.
    Named { server_auth: bool },
}

/// Whether the object ids `oids` of a certificate's uses name server
/// authentication, compared as C's `strcmp` compares them.
pub(crate) fn names_server_auth<'a>(mut oids: impl Iterator<Item = &'a [u8]>) -> bool {
    oids.any(|oid| oid == SERVER_AUTH)
}

/// What the system says of one certificate of its store.
#[cfg(test)]
#[derive(Clone, Copy, Debug)]
struct Seen {
    /// The certificate's validity and now, each as the system's file time
    /// (100 ns units since 1601) puts them, compared as `CompareFileTime`
    /// does.
    not_before: u64,
    not_after: u64,
    now: u64,
    key_usage: KeyUsage,
    uses: Uses,
}

/// Whether C would add the certificate `seen` describes to the store:
/// each of the checks below, in C's order, which the system is asked in.
#[cfg(test)]
fn importable(seen: &Seen) -> bool {
    valid_at(seen.not_before, seen.not_after, seen.now)
        && signs_certificates(seen.key_usage)
        && serves(seen.uses)
}

/// Valid at `now`, its bounds included.
pub(crate) fn valid_at(not_before: u64, not_after: u64, now: u64) -> bool {
    not_before <= now && now <= not_after
}

/// Its key signs certificates, if it says what it is for.
pub(crate) fn signs_certificates(key_usage: KeyUsage) -> bool {
    match key_usage {
        KeyUsage::Says(bits) => bits & KEY_CERT_SIGN != 0,
        KeyUsage::Absent => true,
        KeyUsage::Unreadable => false,
    }
}

/// Its uses take in server authentication.
pub(crate) fn serves(uses: Uses) -> bool {
    match uses {
        Uses::Unsaid | Uses::Unreadable | Uses::None => false,
        Uses::Every => true,
        Uses::Named { server_auth } => server_auth,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: Seen = Seen {
        not_before: 10,
        not_after: 20,
        now: 15,
        key_usage: KeyUsage::Says(KEY_CERT_SIGN),
        uses: Uses::Named { server_auth: true },
    };

    /// A certificate valid now, for signing certificates and for server
    /// authentication, is taken, its validity's bounds included.
    #[test]
    fn a_valid_signing_server_certificate_is_taken() {
        assert!(importable(&GOOD));
        assert!(importable(&Seen { now: 10, ..GOOD }));
        assert!(importable(&Seen { now: 20, ..GOOD }));
    }

    /// Not yet valid, or expired: left out.
    #[test]
    fn one_not_valid_now_is_left_out() {
        assert!(!importable(&Seen { now: 9, ..GOOD }));
        assert!(!importable(&Seen { now: 21, ..GOOD }));
    }

    /// A key usage that does not sign certificates leaves it out, as one
    /// that cannot be read does; none at all says nothing against it.
    #[test]
    fn its_key_must_sign_certificates_if_it_says() {
        let digital_signature = 0x80;
        let only_signing = KeyUsage::Says(digital_signature);
        assert!(!importable(&Seen {
            key_usage: only_signing,
            ..GOOD
        }));
        let with_cert_sign = KeyUsage::Says(digital_signature | KEY_CERT_SIGN);
        assert!(importable(&Seen {
            key_usage: with_cert_sign,
            ..GOOD
        }));
        assert!(importable(&Seen {
            key_usage: KeyUsage::Absent,
            ..GOOD
        }));
        assert!(!importable(&Seen {
            key_usage: KeyUsage::Unreadable,
            ..GOOD
        }));
    }

    /// Server authentication is found among the uses named by its object
    /// id alone, whole.
    #[test]
    fn server_authentication_is_found_by_its_id() {
        let client_auth: &[u8] = b"1.3.6.1.5.5.7.3.2";
        let both: [&[u8]; 2] = [client_auth, SERVER_AUTH];
        assert!(names_server_auth(both.into_iter()));
        let neither: [&[u8]; 2] = [client_auth, b"1.3.6.1.5.5.7.3.11"];
        assert!(!names_server_auth(neither.into_iter()));
        let longer: [&[u8]; 1] = [b"1.3.6.1.5.5.7.3.1.1"];
        assert!(!names_server_auth(longer.into_iter()));
        let shorter: [&[u8]; 1] = [b"1.3.6.1.5.5.7.3."];
        assert!(!names_server_auth(shorter.into_iter()));
        assert!(!names_server_auth(core::iter::empty()));
    }

    /// Its uses must take in server authentication: named among others,
    /// or every use; nothing said, nothing readable, or no use, leaves it
    /// out.
    #[test]
    fn it_must_be_for_server_authentication() {
        for (uses, taken) in [
            (Uses::Named { server_auth: true }, true),
            (Uses::Named { server_auth: false }, false),
            (Uses::Every, true),
            (Uses::None, false),
            (Uses::Unsaid, false),
            (Uses::Unreadable, false),
        ] {
            assert_eq!(importable(&Seen { uses, ..GOOD }), taken, "{uses:?}");
        }
    }
}
