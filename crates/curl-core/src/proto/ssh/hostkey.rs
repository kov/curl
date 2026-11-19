//! What the check of an SSH server's host key gives: a `HostVerified`,
//! which only this module makes, each from the evidence of one check.
//! Every authentication state of either machine holds one, so none is
//! entered before the server's key is checked as the transfer asks.

use curl_alloc::OutOfMemory;

use crate::handler::{Handler, SshHostKeyHandler, SshKeyHandler};
use crate::options::Ssh;

/// What a transfer asks the server's host key be checked against: kept
/// on the route of the connection made for it, which a transfer reusing
/// the connection must ask the same of, unless it asks nothing.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct HostAsk {
    /// The SHA-256 fingerprint, in base64
    /// (`CURLOPT_SSH_HOST_PUBLIC_KEY_SHA256`).
    pub(super) sha256: Option<Vec<u8>>,
    /// The MD5 fingerprint, in hex (`CURLOPT_SSH_HOST_PUBLIC_KEY_MD5`).
    pub(super) md5: Option<Vec<u8>>,
    /// The known-hosts file (`CURLOPT_SSH_KNOWNHOSTS`).
    pub(super) known_hosts: Option<Vec<u8>>,
    /// Decides on the key against the known-hosts file's
    /// (`CURLOPT_SSH_KEYFUNCTION`).
    pub(super) key_handler: Option<Handler<dyn SshKeyHandler>>,
    /// Decides on the key in place of the known-hosts file
    /// (`CURLOPT_SSH_HOSTKEYFUNCTION`).
    pub(super) host_key_handler: Option<Handler<dyn SshHostKeyHandler>>,
}

impl HostAsk {
    /// What `ssh` asks.
    pub(super) fn of(ssh: &Ssh) -> Result<HostAsk, OutOfMemory> {
        let copy = |v: &Option<Vec<u8>>| v.as_deref().map(crate::options::copy).transpose();
        Ok(HostAsk {
            sha256: copy(&ssh.host_key_sha256)?,
            md5: copy(&ssh.host_key_md5)?,
            known_hosts: copy(&ssh.known_hosts)?,
            key_handler: ssh.key_handler.clone(),
            host_key_handler: ssh.host_key_handler.clone(),
        })
    }

    /// A copy.
    pub(super) fn try_clone(&self) -> Result<HostAsk, OutOfMemory> {
        let HostAsk {
            sha256,
            md5,
            known_hosts,
            key_handler,
            host_key_handler,
        } = self;
        let copy = |v: &Option<Vec<u8>>| v.as_deref().map(crate::options::copy).transpose();
        Ok(HostAsk {
            sha256: copy(sha256)?,
            md5: copy(md5)?,
            known_hosts: copy(known_hosts)?,
            key_handler: key_handler.clone(),
            host_key_handler: host_key_handler.clone(),
        })
    }

    /// Whether it asks for no check at all.
    fn nothing(&self) -> bool {
        *self == HostAsk::default()
    }

    /// Whether a connection whose key was checked as `self` asks serves a
    /// transfer that asks `want`: one asking nothing takes any, as C
    /// takes it; one asking anything, only a connection checked as it
    /// asks, its handlers the same ones. C reuses the connection
    /// whatever was asked of either.
    pub(super) fn serves(&self, want: &HostAsk) -> bool {
        want.nothing() || self == want
    }
}

/// The server's host key was checked as the transfer asks, as `how` says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct HostVerified(HostCheck);

/// How a server's host key was found to be the one expected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum HostCheck {
    /// Its SHA-256 fingerprint is the one given
    /// (`CURLOPT_SSH_HOST_PUBLIC_KEY_SHA256`).
    Sha256,
    /// Its MD5 fingerprint is the one given
    /// (`CURLOPT_SSH_HOST_PUBLIC_KEY_MD5`).
    Md5,
    /// The known-hosts file, and the key handler if one is set, took it.
    KnownHosts,
    /// The application's host key handler took it
    /// (`CURLOPT_SSH_HOSTKEYFUNCTION`).
    Handler,
    /// Nothing was asked: no fingerprint, no known-hosts file, no
    /// handler. Any key is taken, as C takes it.
    NotRequested,
}

impl HostVerified {
    /// How the key was checked.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "held by the states as the proof; asked only by tests"
        )
    )]
    pub(super) fn how(self) -> HostCheck {
        self.0
    }

    /// The key's SHA-256 fingerprint, `found` in base64, is `want`, the
    /// two compared up to their padding.
    pub(super) fn sha256(want: &[u8], found: &[u8]) -> Option<HostVerified> {
        let unpadded = |s: &[u8]| s.iter().position(|&b| b == b'=').unwrap_or(s.len());
        let (w, f) = (unpadded(want), unpadded(found));
        (w == f && want[..w] == found[..w]).then_some(HostVerified(HostCheck::Sha256))
    }

    /// The key's MD5 fingerprint, `found` in hex, is `want`, whatever the
    /// case of either.
    pub(super) fn md5(want: &[u8], found: &[u8]) -> Option<HostVerified> {
        found
            .eq_ignore_ascii_case(want)
            .then_some(HostVerified(HostCheck::Md5))
    }

    /// The application's host key handler took the key.
    pub(super) fn by_handler(took: bool) -> Option<HostVerified> {
        took.then_some(HostVerified(HostCheck::Handler))
    }

    /// The known-hosts file, with the key handler deciding if one is
    /// set, took the key.
    pub(super) fn by_known_hosts(took: bool) -> Option<HostVerified> {
        took.then_some(HostVerified(HostCheck::KnownHosts))
    }

    /// No check of the key was asked: no fingerprint and no known-hosts
    /// file. The host key handler, which only libssh2's machine asks
    /// first, is the caller's to have asked.
    pub(super) fn not_requested(ask: &HostAsk) -> Option<HostVerified> {
        let asked = ask.sha256.is_some() || ask.md5.is_some() || ask.known_hosts.is_some();
        (!asked).then_some(HostVerified(HostCheck::NotRequested))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::options::ColdGroup as _;

    /// A fingerprint is taken only where it is the one given, SHA-256's
    /// up to its padding, MD5's in either case; each says which.
    #[test]
    fn a_fingerprint_is_verified_only_where_it_is_the_one_given() {
        let sha = HostVerified::sha256(b"abcd", b"abcd==");
        assert_eq!(sha.map(HostVerified::how), Some(HostCheck::Sha256));
        assert_eq!(HostVerified::sha256(b"abcd", b"abce"), None);
        assert_eq!(HostVerified::sha256(b"abc", b"abcd"), None);
        let md5 = HostVerified::md5(b"0A1b", b"0a1B");
        assert_eq!(md5.map(HostVerified::how), Some(HostCheck::Md5));
        assert_eq!(HostVerified::md5(b"0a1b", b"0a1c"), None);
        assert_eq!(HostVerified::by_handler(false), None);
        assert_eq!(HostVerified::by_known_hosts(false), None);
    }

    /// Any key is taken only where no check was asked: no fingerprint
    /// and no known-hosts file.
    #[test]
    fn a_key_is_taken_unchecked_only_where_no_check_is_asked() {
        let none = HostAsk::of(&Ssh::NONE).unwrap();
        let taken = HostVerified::not_requested(&none).map(HostVerified::how);
        assert_eq!(taken, Some(HostCheck::NotRequested));
        let asks: [fn(&mut Ssh); 3] = [
            |s| s.host_key_sha256 = Some(b"x".to_vec()),
            |s| s.host_key_md5 = Some(b"x".to_vec()),
            |s| s.known_hosts = Some(b"/kh".to_vec()),
        ];
        for ask in asks {
            let mut ssh = Ssh::NONE;
            ask(&mut ssh);
            let ask = HostAsk::of(&ssh).unwrap();
            assert_eq!(HostVerified::not_requested(&ask), None, "{ssh:?}");
        }
    }
}
