//! HTTP Digest (RFC 7616): a challenge read, and the response computed
//! (`lib/vauth/digest.c`'s `Curl_auth_decode_digest_http_message` and
//! `auth_create_digest_http_message`).

use curl_alloc::{OutOfMemory, TryVec as _};

use crate::hash::{Hash, Md5, Sha256, Sha512_256};

/// The longest name before a value's `=`.
const MAX_NAME: usize = 256;
/// The bytes a value is read in, its terminator among them.
const MAX_CONTENT: usize = 1024;
/// The longest quoted string sent.
const MAX_QUOTED: usize = 2048 - 1;
/// The longest response.
const MAX_RESPONSE: usize = 4096 - 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Algorithm {
    Md5,
    Sha256,
    Sha512_256,
}

/// Which protection the response is computed with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Qop {
    Auth,
    AuthInt,
}

impl Qop {
    fn name(self) -> &'static [u8] {
        match self {
            Qop::Auth => b"auth",
            Qop::AuthInt => b"auth-int",
        }
    }
}

/// What the last challenge said, and how far its nonce has been used
/// (C's `struct digestdata`).
#[derive(Debug, Default)]
pub(crate) struct Digest {
    nonce: Option<Vec<u8>>,
    cnonce: Option<Vec<u8>>,
    realm: Option<Vec<u8>>,
    opaque: Option<Vec<u8>>,
    qop: Option<Qop>,
    /// The algorithm as the server named it, sent back as it was.
    algorithm: Option<Vec<u8>>,
    algo: Option<Algorithm>,
    /// `-sess`: the first hash takes in the nonces.
    session: bool,
    /// The nonce count, from 1.
    nc: u32,
    stale: bool,
    userhash: bool,
}

/// Why a challenge was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DigestError {
    /// Malformed, without a nonce, a new nonce where one was answered and
    /// not called stale, or an algorithm not known.
    Bad,
    OutOfMemory,
}

impl From<OutOfMemory> for DigestError {
    fn from(_: OutOfMemory) -> Self {
        DigestError::OutOfMemory
    }
}

fn skip_blanks(s: &[u8]) -> &[u8] {
    let n = s.iter().take_while(|&&b| b == b' ' || b == b'\t').count();
    &s[n..]
}

/// A pair's name, its value unquoted, and what follows it.
type Pair<'a> = (&'a [u8], Vec<u8>, &'a [u8]);

/// A `name=value` pair at the start of `s`, the value quoted or not, and
/// what follows it (`Curl_auth_digest_get_pair`). None where it is
/// malformed: no `=`, a quote unclosed by the line's end or inside a bare
/// value, a value too long. A value that cannot be held is an error, not
/// the challenge's end.
fn pair(s: &[u8]) -> Result<Option<Pair<'_>>, OutOfMemory> {
    let Some(eq) = s.iter().position(|&b| b == b'=') else {
        return Ok(None);
    };
    if eq == 0 || eq > MAX_NAME {
        return Ok(None);
    }
    let name = &s[..eq];
    let mut rest = &s[eq + 1..];
    let quoted = rest.first() == Some(&b'"');
    if quoted {
        rest = &rest[1..];
    }
    let mut content = Vec::new();
    let mut escape = false;
    let mut left = MAX_CONTENT;
    let mut at = 0;
    while at < rest.len() && left > 0 {
        left -= 1;
        let b = rest[at];
        at += 1;
        if !escape {
            match b {
                b'\\' if quoted => {
                    escape = true;
                    continue;
                }
                b',' if !quoted => break,
                b'\r' | b'\n' if quoted => return Ok(None),
                b'\r' | b'\n' => break,
                b'"' if quoted => break,
                b'"' => return Ok(None),
                _ => {}
            }
        }
        if content.len() >= MAX_CONTENT - 1 {
            return Ok(None);
        }
        escape = false;
        content.try_push(b)?;
    }
    if escape {
        return Ok(None);
    }
    Ok(Some((name, content, &rest[at..])))
}

impl Digest {
    /// The challenge after `Digest `, read in place of what was known
    /// before; `had_nonce` says a nonce was answered already. The state is
    /// kept even where the challenge is refused, as C keeps it
    /// (`Curl_auth_decode_digest_http_message`).
    pub(crate) fn decode(challenge: &[u8], had_nonce: bool) -> (Digest, Result<(), DigestError>) {
        let mut d = Digest::default();
        let read = d.read(challenge);
        let checked = read.and_then(|()| {
            if had_nonce && !d.stale || d.nonce.is_none() || d.session && d.qop.is_none() {
                Err(DigestError::Bad)
            } else {
                Ok(())
            }
        });
        (d, checked)
    }

    fn read(&mut self, mut s: &[u8]) -> Result<(), DigestError> {
        loop {
            s = skip_blanks(s);
            let Some((name, content, rest)) = pair(s)? else {
                return Ok(());
            };
            s = rest;
            let is = |n: &str| name.eq_ignore_ascii_case(n.as_bytes());
            let says = |v: &str| content.eq_ignore_ascii_case(v.as_bytes());
            if is("nonce") {
                self.nonce = Some(content);
            } else if is("stale") {
                if says("true") {
                    self.stale = true;
                    self.nc = 1;
                }
            } else if is("realm") {
                self.realm = Some(content);
            } else if is("opaque") {
                self.opaque = Some(content);
            } else if is("qop") {
                let (mut auth, mut auth_int) = (false, false);
                let mut list = skip_blanks(&content);
                // Each up to a comma, at most 32 bytes long.
                loop {
                    let end = list.iter().position(|&b| b == b',').unwrap_or(list.len());
                    if end == 0 || end > 32 {
                        break;
                    }
                    let token = &list[..end];
                    auth |= token.eq_ignore_ascii_case(b"auth");
                    auth_int |= token.eq_ignore_ascii_case(b"auth-int");
                    if end == list.len() {
                        break;
                    }
                    list = skip_blanks(&list[end + 1..]);
                }
                if auth {
                    self.qop = Some(Qop::Auth);
                } else if auth_int {
                    self.qop = Some(Qop::AuthInt);
                }
            } else if is("algorithm") {
                let (algo, session) = if says("MD5-sess") {
                    (Algorithm::Md5, true)
                } else if says("MD5") {
                    (Algorithm::Md5, false)
                } else if says("SHA-256") {
                    (Algorithm::Sha256, false)
                } else if says("SHA-256-SESS") {
                    (Algorithm::Sha256, true)
                } else if says("SHA-512-256") {
                    (Algorithm::Sha512_256, false)
                } else if says("SHA-512-256-SESS") {
                    (Algorithm::Sha512_256, true)
                } else {
                    self.algorithm = Some(content);
                    return Err(DigestError::Bad);
                };
                self.algorithm = Some(content);
                self.algo = Some(algo);
                self.session = session;
            } else if is("userhash") && says("true") {
                self.userhash = true;
            }
            s = skip_blanks(s);
            if s.first() == Some(&b',') {
                s = &s[1..];
            }
        }
    }

    /// A nonce to answer.
    pub(crate) fn has_nonce(&self) -> bool {
        self.nonce.is_some()
    }

    /// The `Authorization: Digest` value for a request with `method` to
    /// `uri`, as `user` with `password` (`auth_create_digest_http_message`):
    /// the client nonce made once from `random`, the count moved on. Too
    /// long a value is out of memory, as C's bounded buffers say.
    pub(crate) fn response(
        &mut self,
        user: &[u8],
        password: &[u8],
        method: &[u8],
        uri: &[u8],
        random: impl FnOnce(&mut [u8; 12]),
    ) -> Result<Vec<u8>, OutOfMemory> {
        match self.algo.unwrap_or(Algorithm::Md5) {
            Algorithm::Md5 => self.response_with::<Md5>(user, password, method, uri, random),
            Algorithm::Sha256 => self.response_with::<Sha256>(user, password, method, uri, random),
            Algorithm::Sha512_256 => {
                self.response_with::<Sha512_256>(user, password, method, uri, random)
            }
        }
    }

    fn response_with<H: Hash>(
        &mut self,
        user: &[u8],
        password: &[u8],
        method: &[u8],
        uri: &[u8],
        random: impl FnOnce(&mut [u8; 12]),
    ) -> Result<Vec<u8>, OutOfMemory> {
        if self.nc == 0 {
            self.nc = 1;
        }
        if self.cnonce.is_none() {
            let mut bytes = [0u8; 12];
            random(&mut bytes);
            let mut cnonce = Vec::new();
            cnonce.try_reserve_exact(16)?;
            crate::proto::http1::auth::base64(bytes.iter().copied(), bytes.len(), &mut cnonce)?;
            self.cnonce = Some(cnonce);
        }
        let realm = self.realm.as_deref().unwrap_or(b"");
        let nonce = self.nonce.as_deref().expect("a response answers a nonce");
        let cnonce = self.cnonce.as_deref().expect("made above");
        let userhash = self.userhash.then(|| hex_of::<H>(&[user, b":", realm]));
        let mut ha1 = hex_of::<H>(&[user, b":", realm, b":", password]);
        if self.session {
            ha1 = hex_of::<H>(&[ha1.as_bytes(), b":", nonce, b":", cnonce]);
        }
        let empty = hex_of::<H>(&[]);
        let a2: &[&[u8]] = if self.qop == Some(Qop::AuthInt) {
            // A body is not hashed: the empty one is.
            &[method, b":", uri, b":", empty.as_bytes()]
        } else {
            &[method, b":", uri]
        };
        let ha2 = hex_of::<H>(a2);
        let mut nc_text = [0u8; 8];
        hex32(self.nc, &mut nc_text);
        let digest = match self.qop {
            Some(qop) => hex_of::<H>(&[
                ha1.as_bytes(),
                b":",
                nonce,
                b":",
                &nc_text,
                b":",
                cnonce,
                b":",
                qop.name(),
                b":",
                ha2.as_bytes(),
            ]),
            None => hex_of::<H>(&[ha1.as_bytes(), b":", nonce, b":", ha2.as_bytes()]),
        };
        let mut out = Bounded::default();
        out.put(b"username=\"")?;
        out.quoted(userhash.as_ref().map_or(user, |h| h.as_bytes()))?;
        out.put(b"\", realm=\"")?;
        out.quoted(realm)?;
        out.put(b"\", nonce=\"")?;
        out.quoted(nonce)?;
        out.put(b"\", uri=\"")?;
        out.quoted(uri)?;
        if let Some(qop) = self.qop {
            out.put(b"\", cnonce=\"")?;
            out.put(cnonce)?;
            out.put(b"\", nc=")?;
            out.put(&nc_text)?;
            out.put(b", qop=")?;
            out.put(qop.name())?;
            out.put(b", response=\"")?;
            out.put(digest.as_bytes())?;
            out.put(b"\"")?;
            self.nc = self.nc.wrapping_add(1);
        } else {
            out.put(b"\", response=\"")?;
            out.put(digest.as_bytes())?;
            out.put(b"\"")?;
        }
        if let Some(opaque) = &self.opaque {
            out.put(b", opaque=\"")?;
            out.quoted(opaque)?;
            out.put(b"\"")?;
        }
        if let Some(algorithm) = &self.algorithm {
            out.put(b", algorithm=")?;
            out.put(algorithm)?;
        }
        if self.userhash {
            out.put(b", userhash=true")?;
        }
        Ok(out.0)
    }
}

/// The response being written, at most `MAX_RESPONSE` long.
#[derive(Default)]
struct Bounded(Vec<u8>);

impl Bounded {
    fn put(&mut self, bytes: &[u8]) -> Result<(), OutOfMemory> {
        if self.0.len() + bytes.len() > MAX_RESPONSE {
            return Err(OutOfMemory);
        }
        self.0.try_extend_from_slice(bytes)
    }

    /// `s` as a quoted string's inside: quotes and backslashes escaped,
    /// control and non-ASCII bytes as `%XX`; at most `MAX_QUOTED` long
    /// (`auth_digest_string_quoted`).
    fn quoted(&mut self, s: &[u8]) -> Result<(), OutOfMemory> {
        const HEX: &[u8; 16] = b"0123456789ABCDEF";
        let start = self.0.len();
        for &b in s {
            let escaped: &[u8] = match b {
                b'"' | b'\\' => &[b'\\', b],
                b' '..=0x7e => &[b],
                _ => &[b'%', HEX[usize::from(b >> 4)], HEX[usize::from(b & 15)]],
            };
            if self.0.len() - start + escaped.len() > MAX_QUOTED {
                return Err(OutOfMemory);
            }
            self.put(escaped)?;
        }
        Ok(())
    }
}

/// The hash of `parts` joined, in lowercase hex.
fn hex_of<H: Hash>(parts: &[&[u8]]) -> HexDigest {
    let mut h = H::default();
    for part in parts {
        h.update(part);
    }
    let sum = h.finish();
    let mut text = [0u8; 64];
    for (i, b) in sum[..H::LEN].iter().enumerate() {
        text[i * 2] = HEX_LOWER[usize::from(b >> 4)];
        text[i * 2 + 1] = HEX_LOWER[usize::from(b & 15)];
    }
    HexDigest {
        text,
        len: H::LEN * 2,
    }
}

const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";

/// `n` as eight lowercase hex digits (`%08x`).
fn hex32(n: u32, out: &mut [u8; 8]) {
    for (i, d) in out.iter_mut().enumerate() {
        *d = HEX_LOWER[(n >> (28 - 4 * i) & 15) as usize];
    }
}

/// A digest in hex, held without allocating.
struct HexDigest {
    text: [u8; 64],
    len: usize,
}

impl HexDigest {
    fn as_bytes(&self) -> &[u8] {
        &self.text[..self.len]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decoded(challenge: &str) -> Result<Digest, DigestError> {
        let (d, result) = Digest::decode(challenge.as_bytes(), false);
        result.map(|()| d)
    }

    fn respond(challenge: &str, user: &str, password: &str, method: &str, uri: &str) -> String {
        let mut d = decoded(challenge).unwrap();
        let out = d
            .response(
                user.as_bytes(),
                password.as_bytes(),
                method.as_bytes(),
                uri.as_bytes(),
                |bytes| bytes.fill(b'x'),
            )
            .unwrap();
        String::from_utf8(out).unwrap()
    }

    /// Tests 64 and 2061's responses, without a qop.
    #[test]
    fn answers_as_c() {
        assert_eq!(
            respond(
                "realm=\"testrealm\", nonce=\"1053604145\"",
                "testuser",
                "testpass",
                "GET",
                "/64"
            ),
            "username=\"testuser\", realm=\"testrealm\", nonce=\"1053604145\", uri=\"/64\", \
             response=\"c55f7f30d83d774a3d2dcacf725abaca\""
        );
        assert_eq!(
            respond(
                "realm=\"testrealm\", nonce=\"1053604145\", algorithm=\"SHA-256\"",
                "testuser",
                "testpass",
                "GET",
                "/2061"
            ),
            "username=\"testuser\", realm=\"testrealm\", nonce=\"1053604145\", uri=\"/2061\", \
             response=\"9dc55255f1a2537b838311674b621d45346b862a81631bb20e4ce356ef25062d\", \
             algorithm=SHA-256"
        );
    }

    /// With a qop: the client nonce, the count and the qop are sent, the
    /// count moving on; RFC 7616's example (3.9.1) for MD5.
    #[test]
    fn answers_with_a_qop() {
        let mut d = decoded(
            "realm=\"http-auth@example.org\", qop=\"auth, auth-int\", algorithm=MD5, \
             nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\", \
             opaque=\"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS\"",
        )
        .unwrap();
        let cnonce = b"f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ";
        // The example's client nonce, taken as made.
        d.cnonce = Some(cnonce.to_vec());
        let out = d
            .response(
                b"Mufasa",
                b"Circle of Life",
                b"GET",
                b"/dir/index.html",
                |_| unreachable!("a client nonce is there"),
            )
            .unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(
            out.contains("response=\"8ca523f5e9506fed4657c9700eebdbec\""),
            "{out}"
        );
        assert!(out.contains(", nc=00000001, qop=auth, "), "{out}");
        assert!(
            out.ends_with(
                ", opaque=\"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS\", algorithm=MD5"
            )
        );
        let again = d
            .response(b"Mufasa", b"Circle of Life", b"GET", b"/", |_| {})
            .unwrap();
        assert!(
            String::from_utf8(again)
                .unwrap()
                .contains(", nc=00000002, ")
        );
        // A client nonce made: twelve bytes in base64.
        let mut d = decoded("nonce=\"n\", qop=auth").unwrap();
        let out = d
            .response(b"u", b"p", b"GET", b"/", |b| b.fill(0xff))
            .unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("cnonce=\"////////////////\""), "{out}");
    }

    /// What a challenge must have, and how its values are read.
    #[test]
    fn reads_challenges_as_c() {
        assert_eq!(
            decoded("realm=\"r\"").err(),
            Some(DigestError::Bad),
            "no nonce"
        );
        assert_eq!(
            decoded("nonce=\"n\", algorithm=MD4").err(),
            Some(DigestError::Bad)
        );
        assert_eq!(
            decoded("nonce=\"n\", algorithm=MD5-sess").err(),
            Some(DigestError::Bad),
            "a session without a qop"
        );
        assert!(decoded("nonce=\"n\", algorithm=md5-SESS, qop=auth").is_ok());
        let (_, again) = Digest::decode(b"nonce=\"n\"", true);
        assert_eq!(again, Err(DigestError::Bad), "a new nonce, not stale");
        let (d, stale) = Digest::decode(b"nonce=\"n\", stale=TRUE", true);
        assert_eq!((stale, d.nc), (Ok(()), 1));
        let d = decoded("nonce=n,realm=\"a\\\"b\"  ,  opaque=x y,qop=\"crazy, auth-int\"").unwrap();
        assert_eq!(d.nonce.as_deref(), Some(&b"n"[..]));
        assert_eq!(d.realm.as_deref(), Some(&b"a\"b"[..]));
        assert_eq!(d.opaque.as_deref(), Some(&b"x y"[..]));
        assert_eq!(d.qop, Some(Qop::AuthInt));
        let d = decoded("nonce=\"n\", qop=\"auth-int,auth\"").unwrap();
        assert_eq!(d.qop, Some(Qop::Auth), "auth wins");
        let d = decoded("nonce=\"n\", qop=\"auth-conf\"").unwrap();
        assert_eq!(d.qop, None);
        // A quote inside a bare value ends the reading there.
        let d = decoded("nonce=\"n\", realm=a\"b, opaque=o").unwrap();
        assert_eq!((d.realm, d.opaque), (None, None));
        // An unclosed quote ends with the value.
        let d = decoded("nonce=\"n").unwrap();
        assert_eq!(d.nonce.as_deref(), Some(&b"n"[..]));
        assert_eq!(decoded("nonce=\"n\r\"").err(), Some(DigestError::Bad));
        let long = format!("nonce=\"{}\"", "n".repeat(MAX_CONTENT));
        assert!(decoded(&long).is_err(), "too long to keep");
        let fits = format!("nonce=\"{}\"", "n".repeat(MAX_CONTENT - 1));
        assert!(decoded(&fits).is_ok());
    }

    /// Quoted strings escape quotes and backslashes and spell out what is
    /// not printable; userhash sends the user's hash.
    #[test]
    fn quotes_and_hashes_the_user() {
        let out = respond("nonce=\"n\"", "a\"b\\c\nd\u{e9}", "p", "GET", "/");
        assert!(
            out.starts_with("username=\"a\\\"b\\\\c%0Ad%C3%A9\""),
            "{out}"
        );
        let out = respond(
            "nonce=\"n\", realm=\"r\", userhash=true",
            "u",
            "p",
            "GET",
            "/",
        );
        let hashed = hex_of::<Md5>(&[b"u", b":", b"r"]);
        let want = format!(
            "username=\"{}\"",
            std::str::from_utf8(hashed.as_bytes()).unwrap()
        );
        assert!(
            out.starts_with(&want) && out.ends_with(", userhash=true"),
            "{out}"
        );
        let long = "/".repeat(MAX_QUOTED + 1);
        let mut d = decoded("nonce=\"n\"").unwrap();
        assert!(
            d.response(b"u", b"p", b"GET", long.as_bytes(), |_| {})
                .is_err()
        );
    }

    /// C's bounds: a pair's name of 256 bytes, a value read in 1024 bytes
    /// with its escapes, a qop token of 32, a quoted string of 2047 and a
    /// response of 4095.
    #[test]
    fn bounds_challenges_and_responses_as_c() {
        let realm = |challenge: &str| {
            decoded(challenge)
                .unwrap()
                .realm
                .map(|r| String::from_utf8(r).unwrap())
        };
        let named = |n: usize| format!("nonce=n, {}=v, realm=r", "x".repeat(n));
        assert_eq!(realm(&named(256)).as_deref(), Some("r"));
        assert_eq!(realm(&named(257)), None, "a name too long ends the reading");
        assert_eq!(
            decoded("=x, nonce=\"n\"").err(),
            Some(DigestError::Bad),
            "an empty name ends the reading"
        );
        // An escape takes one of the 1024 bytes and keeps nothing: the
        // value ends after 512 escaped quotes, the rest is no pair.
        let escaped = format!("nonce=n, realm=\"{}\", opaque=o", "\\\"".repeat(600));
        let d = decoded(&escaped).unwrap();
        assert_eq!(d.realm, Some(vec![b'"'; 512]));
        assert_eq!(d.opaque, None);
        let qop = |token: usize| {
            decoded(&format!("nonce=n, qop=\"{},auth\"", "x".repeat(token)))
                .unwrap()
                .qop
        };
        assert_eq!(qop(32), Some(Qop::Auth));
        assert_eq!(qop(33), None, "a token too long ends the list");
        assert_eq!(qop(0), None, "so does an empty one");
        let uri = |n: usize| {
            let mut d = decoded("nonce=\"n\"").unwrap();
            d.response(b"u", b"p", b"GET", "/".repeat(n).as_bytes(), |_| {})
        };
        assert!(uri(2047).is_ok());
        assert!(uri(2048).is_err());
        // What a response takes besides its user and its URI.
        let around = uri(1).unwrap().len() - 2;
        let response = |user: usize| {
            let mut d = decoded("nonce=\"n\"").unwrap();
            let uri = "/".repeat(2000);
            d.response(
                "u".repeat(user).as_bytes(),
                b"p",
                b"GET",
                uri.as_bytes(),
                |_| {},
            )
            .map(|r| r.len())
        };
        let fits = 4095 - around - 2000;
        assert_eq!(response(fits), Ok(4095));
        assert!(response(fits + 1).is_err());
    }

    /// A bare value ends at a comma or a line's end and takes a backslash
    /// as it is; only `userhash=true` asks for the user's hash.
    #[test]
    fn reads_bare_values_as_c() {
        let d = decoded("nonce=n\rrealm=a\\b").unwrap();
        assert_eq!(d.nonce.as_deref(), Some(&b"n"[..]));
        assert_eq!(d.realm.as_deref(), Some(&b"a\\b"[..]));
        let d = decoded("nonce=n\nopaque=o").unwrap();
        assert_eq!(d.nonce.as_deref(), Some(&b"n"[..]));
        assert_eq!(d.opaque.as_deref(), Some(&b"o"[..]));
        for challenge in ["nonce=n, userhash=false", "nonce=n, other=true"] {
            let out = respond(challenge, "u", "p", "GET", "/");
            assert!(out.starts_with("username=\"u\""), "{out}");
            assert!(!out.contains("userhash"), "{out}");
        }
    }

    /// The nonce count is sent as eight hex digits.
    #[test]
    fn counts_nonces_in_hex() {
        let mut d = decoded("nonce=\"n\", qop=auth").unwrap();
        d.nc = 0x1234abcd;
        let out = d.response(b"u", b"p", b"GET", b"/", |_| {}).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains(", nc=1234abcd, "), "{out}");
    }

    const WORDS: &[&[u8]] = &[
        b"realm",
        b"nonce",
        b"qop",
        b"algorithm",
        b"opaque",
        b"stale",
        b"userhash",
        b"=",
        b"\"",
        b",",
        b" ",
        b"\t",
        b"\\",
        b"auth",
        b"auth-int",
        b"MD5",
        b"MD5-sess",
        b"SHA-256",
        b"SHA-512-256-SESS",
        b"true",
        b"\r",
        b"\n",
    ];
    const SAMPLES: &[&[u8]] = &[
        b" realm=\"testrealm\", nonce=\"1053604145\"",
        b" realm=\"r\", nonce=\"n\", qop=\"auth,auth-int\", algorithm=MD5-sess, \
          opaque=\"o\", userhash=true",
        b" nonce=\"a\\\"b\", stale=true, algorithm=SHA-256, qop=auth",
    ];

    proptest::proptest! {
        #![proptest_config(crate::untrusted::config(256))]

        /// Any challenge is read or refused, its values each kept within
        /// C's buffer, and whatever nonce it left answers any request
        /// within the longest response, or fails as out of memory.
        #[test]
        fn any_challenge_is_read_and_answered(
            challenge in crate::untrusted::input(WORDS, SAMPLES, 24),
            long in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..1500),
            had_nonce in proptest::prelude::any::<bool>(),
            which in 0..4usize,
        ) {
            let (mut d, _) = Digest::decode(&challenge, had_nonce);
            for v in [&d.nonce, &d.realm, &d.opaque, &d.algorithm].into_iter().flatten() {
                proptest::prop_assert!(v.len() < MAX_CONTENT);
            }
            // Any one of the request's parts long and odd.
            let mut parts: [&[u8]; 4] = [b"user", b"password", b"GET", b"/"];
            parts[which] = &long;
            // As `answer_digest` asks: only a nonce is answered.
            if d.has_nonce()
                && let Ok(out) = d.response(parts[0], parts[1], parts[2], parts[3], |b| b.fill(7))
            {
                proptest::prop_assert!(out.len() <= MAX_RESPONSE);
            }
        }
    }
}
