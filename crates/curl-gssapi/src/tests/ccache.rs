//! A credentials cache holding made-up tickets, and a configuration whose
//! KDC answers nothing: with them the library makes real contexts with no
//! KDC to ask, sending the cached ticket for `HTTP/127.0.0.1` as it would
//! a real one. Nothing can accept the tokens; what the library does with
//! its own side of the context is real.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const REALM: &[u8] = b"EXAMPLE.TEST";

/// The client the cache holds tickets for, as the library displays it.
pub(super) const CLIENT: &[u8] = b"alice@EXAMPLE.TEST";

/// `KRB5_NT_PRINCIPAL`, `KRB5_NT_SRV_INST`, `KRB5_NT_SRV_HST`.
const NT_PRINCIPAL: u32 = 1;
const NT_SRV_INST: u32 = 2;
const NT_SRV_HST: u32 = 3;

/// The session keys' type.
#[derive(Clone, Copy)]
pub(super) enum Key {
    /// `aes256-cts-hmac-sha1-96`.
    Aes256,
    /// `rc4-hmac`, simple enough for a test to decrypt with.
    Rc4,
}

impl Key {
    fn enctype(self) -> u16 {
        match self {
            Key::Aes256 => 18,
            Key::Rc4 => 23,
        }
    }

    /// The session key itself.
    pub(super) fn bytes(self) -> &'static [u8] {
        match self {
            Key::Aes256 => &[0x4b; 32],
            Key::Rc4 => &[0x4b; 16],
        }
    }
}

/// The cache and the configuration, in a directory of their own,
/// removed with it.
pub(super) struct Kdcless {
    dir: PathBuf,
}

impl Kdcless {
    pub(super) fn new(tag: &str, key: Key) -> Kdcless {
        let dir = std::env::temp_dir().join(format!("curl-gssapi-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // The KDC is a port nothing listens on: asked anything, it is
        // refused at once.
        let conf = "[libdefaults]\n\
            \tdefault_realm = EXAMPLE.TEST\n\
            \tdns_lookup_kdc = false\n\
            \tdns_lookup_realm = false\n\
            \tdns_canonicalize_hostname = false\n\
            \trdns = false\n\
            [realms]\n\
            \tEXAMPLE.TEST = {\n\
            \t\tkdc = 127.0.0.1:1\n\
            \t}\n\
            [domain_realm]\n\
            \t127.0.0.1 = EXAMPLE.TEST\n";
        std::fs::write(dir.join("krb5.conf"), conf).unwrap();
        std::fs::write(dir.join("cache"), cache(key)).unwrap();
        Kdcless { dir }
    }

    /// The cache's file, for a test to take away.
    pub(super) fn cache(&self) -> PathBuf {
        self.dir.join("cache")
    }

    /// The environment a child runs the library in.
    pub(super) fn env(&self) -> Vec<(String, String)> {
        vec![
            (
                "KRB5CCNAME".into(),
                format!("FILE:{}", self.cache().display()),
            ),
            (
                "KRB5_CONFIG".into(),
                self.dir.join("krb5.conf").display().to_string(),
            ),
        ]
    }
}

impl Drop for Kdcless {
    fn drop(&mut self) {
        // Left behind only by a test that is failing anyway.
        if let Err(e) = std::fs::remove_dir_all(&self.dir) {
            assert!(std::thread::panicking(), "{}: {e}", self.dir.display());
        }
    }
}

/// A DER element: `tag`, the length, `content`.
fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|&&b| b == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(content);
    out
}

fn concat(parts: &[Vec<u8>]) -> Vec<u8> {
    parts.concat()
}

/// A small non-negative INTEGER, under the context tag `n`.
fn int(n: u8, value: u8) -> Vec<u8> {
    der(0xa0 | n, &der(0x02, &[value]))
}

/// A `PrincipalName` of `kind` and `parts`.
fn principal_name(kind: u8, parts: &[&[u8]]) -> Vec<u8> {
    let strings: Vec<Vec<u8>> = parts.iter().map(|p| der(0x1b, p)).collect();
    der(
        0x30,
        &concat(&[int(0, kind), der(0xa1, &der(0x30, &strings.concat()))]),
    )
}

/// A `Ticket` for `parts`@`REALM`, its encrypted part made up: the library
/// only passes it on.
fn ticket(parts: &[&[u8]], key: Key) -> Vec<u8> {
    let enc_part = der(
        0x30,
        &concat(&[
            int(0, key.enctype() as u8),
            der(0xa2, &der(0x04, &[0x5a; 48])),
        ]),
    );
    der(
        0x61,
        &der(
            0x30,
            &concat(&[
                int(0, 5),
                der(0xa1, &der(0x1b, REALM)),
                der(0xa2, &principal_name(NT_SRV_INST as u8, parts)),
                der(0xa3, &enc_part),
            ]),
        ),
    )
}

fn data(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// A principal as the cache writes it.
fn principal(out: &mut Vec<u8>, kind: u32, parts: &[&[u8]]) {
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&(parts.len() as u32).to_be_bytes());
    data(out, REALM);
    for part in parts {
        data(out, part);
    }
}

/// One credential, from `alice` to `server`, valid for a day.
fn credential(out: &mut Vec<u8>, kind: u32, server: &[&[u8]], key: Key, now: u32) {
    principal(out, NT_PRINCIPAL, &[b"alice"]);
    principal(out, kind, server);
    out.extend_from_slice(&key.enctype().to_be_bytes());
    data(out, key.bytes());
    // Auth time, start time, end time, renewable until.
    for t in [now - 60, now - 60, now + 86400, 0] {
        out.extend_from_slice(&t.to_be_bytes());
    }
    // Not a user-to-user key; no flags, addresses or authorization data.
    out.push(0);
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    data(out, &ticket(server, key));
    data(out, b"");
}

/// The cache, in the file format's fourth version.
fn cache(key: Key) -> Vec<u8> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    let mut out = Vec::new();
    out.extend_from_slice(&0x0504u16.to_be_bytes());
    // No header fields.
    out.extend_from_slice(&0u16.to_be_bytes());
    principal(&mut out, NT_PRINCIPAL, &[b"alice"]);
    credential(&mut out, NT_SRV_INST, &[b"krbtgt", REALM], key, now);
    credential(&mut out, NT_SRV_HST, &[b"HTTP", b"127.0.0.1"], key, now);
    out
}
