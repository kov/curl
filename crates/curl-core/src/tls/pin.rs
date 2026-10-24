//! The pinned public key (`CURLOPT_PINNEDPUBLICKEY`, vtls.c's
//! `Curl_pin_peer_pubkey`): the peer's key, as the DER of its
//! SubjectPublicKeyInfo, must be the one the transfer names, by the
//! base64 of its SHA-256 (`sha256//`, `;` between several) or as a file
//! of it, in DER or PEM. The library finds the key; this compares it.

use std::fmt;
use std::io::Read as _;

use curl_alloc::{OutOfMemory, TryVec as _};

use super::TlsIo;
use crate::error::ErrorKind;
use crate::hash::{Hash as _, Sha256};

/// The largest file of a key C reads (`MAX_PINNED_PUBKEY_SIZE`).
const MAX_FILE: u64 = 1_048_576;

/// What the comparison says as it goes.
#[derive(Debug, PartialEq, Eq)]
enum Said<'a> {
    /// The key's hash (` public key hash: sha256//...`).
    Hash(&'a [u8]),
    /// One pinned hash matched (C's debug build says it).
    Matches,
    /// One pinned hash did not (C's debug build says it).
    Differs(&'a [u8]),
}

/// The peer's key `spki` is the one `pinned` names, as `Curl_pin_peer_pubkey`
/// decides: the lines it says on the way through `io`. A key that is not
/// is `SslPinnedpubkeynotmatch`, which the library says why for.
pub fn pin_peer_pubkey(io: &mut TlsIo<'_>, pinned: &[u8], spki: &[u8]) -> Result<(), ErrorKind> {
    let matched = matches(pinned, spki, &mut |said| match said {
        Said::Hash(hash) => io.info(format_args!(" public key hash: sha256//{}", Text(hash))),
        Said::Matches => io.debug_info(format_args!("public key hash matches pinned value")),
        Said::Differs(hash) => io.debug_info(format_args!(
            "public key hash does not match 'sha256//{}'",
            Text(hash)
        )),
    })
    .map_err(|OutOfMemory| ErrorKind::OutOfMemory)?;
    if matched {
        Ok(())
    } else {
        Err(ErrorKind::SslPinnedpubkeynotmatch)
    }
}

/// Bytes as text in a line, as C's `%s` prints them.
struct Text<'a>(&'a [u8]);

impl fmt::Display for Text<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for chunk in self.0.utf8_chunks() {
            f.write_str(chunk.valid())?;
            for &b in chunk.invalid() {
                write!(f, "{}", char::from(b))?;
            }
        }
        Ok(())
    }
}

/// `spki` is the key `pinned` names; `say` is told the lines C says.
fn matches(pinned: &[u8], spki: &[u8], say: &mut dyn FnMut(Said<'_>)) -> Result<bool, OutOfMemory> {
    // A C string: it ends at a zero byte.
    let pinned = until_zero(pinned);
    if spki.is_empty() {
        return Ok(false);
    }
    if pinned.starts_with(b"sha256//") {
        let mut sha = Sha256::default();
        sha.update(spki);
        let digest = sha.finish();
        let mut hash = Vec::new();
        hash.try_reserve_exact(44).map_err(|_| OutOfMemory)?;
        crate::proto::http1::auth::base64(digest.iter().copied(), 32, &mut hash)?;
        say(Said::Hash(&hash));
        let mut rest = Some(pinned);
        while let Some(list) = rest.filter(|r| r.starts_with(b"sha256//")) {
            let list = &list[b"sha256//".len()..];
            let (one, next) = match list.iter().position(|&b| b == b';') {
                Some(i) => (&list[..i], Some(&list[i + 1..])),
                None => (list, None),
            };
            if one == hash.as_slice() {
                say(Said::Matches);
                return Ok(true);
            }
            say(Said::Differs(one));
            rest = next;
        }
        return Ok(false);
    }
    // A file of the key, in DER, or else in PEM; its name copied on the
    // stack, which cannot fail for memory.
    let Ok(mut file) = curl_os::fs::with_c_name(pinned, curl_os::fs::open_read) else {
        return Ok(false);
    };
    let size = match file.metadata() {
        Ok(m) if m.len() <= MAX_FILE => usize::try_from(m.len()).expect("at most a MiB"),
        _ => return Ok(false),
    };
    if spki.len() > size {
        return Ok(false);
    }
    let mut content = Vec::new();
    content.try_reserve_exact(size).map_err(|_| OutOfMemory)?;
    let mut chunk = [0u8; 1024];
    while content.len() < size {
        let want = (size - content.len()).min(chunk.len());
        match file.read(&mut chunk[..want]) {
            Ok(0) | Err(_) => return Ok(false),
            Ok(n) => content.try_extend_from_slice(&chunk[..n])?,
        }
    }
    // Of the same size: DER, which it is or is not.
    if spki.len() == size {
        return Ok(content == spki);
    }
    Ok(pem_to_der(until_zero(&content))?.is_some_and(|der| der == spki))
}

/// `bytes` up to a zero byte, where C sees a string end.
fn until_zero(bytes: &[u8]) -> &[u8] {
    &bytes[..bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len())]
}

/// The DER of the first public key in the PEM text `pem`
/// (`pubkey_pem_to_der`): its `BEGIN` line at the start or after a
/// newline, its `END` line right after a newline, the base64 between
/// without its line ends; none if any of that is not so.
fn pem_to_der(pem: &[u8]) -> Result<Option<Vec<u8>>, OutOfMemory> {
    const BEGIN: &[u8] = b"-----BEGIN PUBLIC KEY-----";
    const END: &[u8] = b"\n-----END PUBLIC KEY-----";
    let Some(begin) = find(pem, BEGIN) else {
        return Ok(None);
    };
    if begin > 0 && pem[begin - 1] != b'\n' {
        return Ok(None);
    }
    let start = begin + BEGIN.len();
    let Some(end) = find(&pem[start..], END) else {
        return Ok(None);
    };
    let mut text = Vec::new();
    for &b in &pem[start..start + end] {
        if b != b'\n' && b != b'\r' {
            text.try_push(b)?;
        }
    }
    if text.is_empty() {
        return Ok(None);
    }
    crate::base64::decode(&text)
}

/// Where `needle` first is in `hay`.
fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A key's DER stand-in, and the base64 of its SHA-256.
    const SPKI: &[u8] = b"not really a key, but bytes to hash";

    fn hash_of(spki: &[u8]) -> Vec<u8> {
        let mut sha = Sha256::default();
        sha.update(spki);
        let mut out = Vec::new();
        crate::proto::http1::auth::base64(sha.finish().iter().copied(), 32, &mut out).unwrap();
        out
    }

    fn run(pinned: &[u8], spki: &[u8]) -> (bool, Vec<String>) {
        let mut lines = Vec::new();
        let got = matches(pinned, spki, &mut |s| {
            lines.push(match s {
                Said::Hash(h) => format!("hash {}", String::from_utf8_lossy(h)),
                Said::Matches => "matches".into(),
                Said::Differs(h) => format!("differs {}", String::from_utf8_lossy(h)),
            });
        })
        .unwrap();
        (got, lines)
    }

    #[test]
    fn a_hash_among_several_matches() {
        let hash = String::from_utf8(hash_of(SPKI)).unwrap();
        let pinned = format!("sha256//AAAA;sha256//{hash};sha256//BBBB");
        let (ok, lines) = run(pinned.as_bytes(), SPKI);
        assert!(ok);
        assert_eq!(
            lines,
            [
                format!("hash {hash}"),
                "differs AAAA".into(),
                "matches".into()
            ]
        );
    }

    #[test]
    fn no_hash_that_matches_is_a_mismatch() {
        let (ok, lines) = run(b"sha256//AAAA;sha256//BBBB", SPKI);
        assert!(!ok);
        assert_eq!(&lines[1..], ["differs AAAA", "differs BBBB"]);
        // A list not of `sha256//` past its first stops there.
        let hash = String::from_utf8(hash_of(SPKI)).unwrap();
        let (ok, _) = run(format!("sha256//A;{hash}").as_bytes(), SPKI);
        assert!(!ok);
        // No key from the library matches nothing.
        let (ok, lines) = run(format!("sha256//{hash}").as_bytes(), b"");
        assert!(!ok);
        assert!(lines.is_empty());
    }

    fn file(name: &str, content: &[u8]) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("curl-core-pin-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, content).unwrap();
        path
    }

    fn pem(der: &[u8], line_end: &str) -> Vec<u8> {
        let mut b64 = Vec::new();
        crate::proto::http1::auth::base64(der.iter().copied(), der.len(), &mut b64).unwrap();
        let mut text = format!("junk\n-----BEGIN PUBLIC KEY-----{line_end}");
        for line in b64.chunks(16) {
            text.push_str(std::str::from_utf8(line).unwrap());
            text.push_str(line_end);
        }
        text.push_str("-----END PUBLIC KEY-----\n");
        text.into_bytes()
    }

    #[test]
    fn a_file_holds_the_key_in_der_or_pem() {
        let der = file("key.der", SPKI);
        assert_eq!(run(der.to_str().unwrap().as_bytes(), SPKI), (true, vec![]));
        let other = file("other.der", b"not really a key, but other bytes!!");
        assert!(!run(other.to_str().unwrap().as_bytes(), SPKI).0);
        for end in ["\n", "\r\n"] {
            let p = file("key.pem", &pem(SPKI, end));
            assert!(run(p.to_str().unwrap().as_bytes(), SPKI).0, "{end:?}");
        }
        let p = file("other.pem", &pem(b"another key of other bytes", "\n"));
        assert!(!run(p.to_str().unwrap().as_bytes(), SPKI).0);
        // Shorter than the key: it cannot be it.
        let short = file("short", b"key");
        assert!(!run(short.to_str().unwrap().as_bytes(), SPKI).0);
        assert!(!run(b"/nonexistent/key.der", SPKI).0);
        std::fs::remove_dir_all(der.parent().unwrap()).unwrap();
    }

    #[test]
    fn pem_is_read_as_c_reads_it() {
        let ok = pem(SPKI, "\n");
        assert_eq!(pem_to_der(&ok).unwrap().as_deref(), Some(SPKI));
        // `BEGIN` not at a line's start.
        let mut bad = ok.clone();
        bad[4] = b' ';
        assert_eq!(pem_to_der(&bad).unwrap(), None);
        // No `END` right after a newline.
        let text = b"-----BEGIN PUBLIC KEY-----\nAAAA-----END PUBLIC KEY-----";
        assert_eq!(pem_to_der(text).unwrap(), None);
        // Nothing between.
        let text = b"-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----";
        assert_eq!(pem_to_der(text).unwrap(), None);
    }
}
