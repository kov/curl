//! HTTP message signatures, RFC 9421 (`lib/http_httpsig.c`): the
//! request's method, authority, path and query, and headers the
//! application names, signed under a key the server shares and sent as
//! `Signature-Input` and `Signature`.
//!
//! HMAC-SHA256 only. Ed25519 is refused as a C build without a TLS
//! library that has it refuses it (`curl_ed25519.c`); it comes with the
//! OpenSSL binding of the TLS milestone.

use curl_alloc::{OutOfMemory, TryVec as _};

use crate::error::ErrorKind;
use crate::hash::hmac_sha256;
use crate::multi::Host;
use crate::multi::state::StepCx;
use crate::options::{MessageSignature, SignatureAlgorithm};
use crate::proto::http1::auth::base64;
use crate::proto::http1::request::UserHeaders;
use crate::trace;

/// The longest a line the signing makes may be, and a header's
/// combined value (`CURL_MAX_HTTP_HEADER`, a dynbuf's size limit, which
/// counts the zero byte after it).
const MAX_PART: usize = 100 * 1024;

/// The longest string option C takes (`CURL_MAX_INPUT_LENGTH`).
const MAX_INPUT: usize = 8_000_000;

/// The most components a signature covers (`HTTPSIG_MAX_COMPONENTS`).
const MAX_COMPONENTS: usize = 16;

/// The signature's label (`HTTPSIG_DEFAULT_LABEL`).
const LABEL: &[u8] = b"sig1";

/// What a request is, for its signature.
pub(crate) struct Request<'a> {
    pub(crate) signature: &'a MessageSignature,
    /// As the request line names it.
    pub(crate) method: &'a [u8],
    /// The authority the request's `Host` names (`@authority`).
    pub(crate) authority: &'a [u8],
    /// The URL's path, `/` if empty.
    pub(crate) path: &'a [u8],
    /// The URL's query, without its `?`, if it has one.
    pub(crate) query: Option<&'a [u8]>,
    pub(crate) headers: &'a UserHeaders,
    /// The time it is signed at, in seconds since the epoch.
    pub(crate) now: i64,
}

/// A signing: what it notes on the way, in order, and the lines it adds
/// to the request, each ended by CRLF, none if the application sends its
/// own signature; or why it failed.
pub(crate) struct Signing {
    pub(crate) notes: Vec<Vec<u8>>,
    pub(crate) result: Result<Option<Vec<u8>>, SignError>,
}

/// Why a request could not be signed.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SignError {
    NoAlgorithm,
    NoKey,
    NoKeyId,
    /// The key, its line ends left out, is empty or of an odd length.
    KeyLength(usize),
    KeyTooLong,
    /// The pair of digits at this offset is not hex.
    NotHex(usize, [u8; 2]),
    /// An Ed25519 key is not 32 bytes long.
    Ed25519KeyLength(usize),
    /// A component names a header with no name: `:`.
    EmptyHeaderName,
    /// A component is none RFC 9421 derives, lowercased.
    UnknownComponent(Vec<u8>),
    NoComponents,
    TooManyComponents,
    /// A component is named twice, as it is signed.
    DuplicateComponent(Vec<u8>),
    /// A header component the application does not send.
    HeaderNotFound(Vec<u8>),
    /// A quote or a backslash in a component, or a control character in
    /// what goes quoted; C says nothing of it.
    Unquotable,
    /// Ed25519, which this build cannot sign with.
    NotBuiltIn,
    TooLarge,
    OutOfMemory,
}

impl From<OutOfMemory> for SignError {
    fn from(_: OutOfMemory) -> SignError {
        SignError::OutOfMemory
    }
}

impl SignError {
    pub(crate) fn kind(&self) -> ErrorKind {
        match self {
            SignError::NotBuiltIn => ErrorKind::NotBuiltIn,
            SignError::TooLarge => ErrorKind::TooLarge,
            SignError::OutOfMemory => ErrorKind::OutOfMemory,
            _ => ErrorKind::BadFunctionArgument,
        }
    }

    /// Fail the transfer with it, saying what C says (`failf`).
    pub(crate) fn fail<H: Host>(&self, cx: &mut StepCx<'_, H>) -> ErrorKind {
        let kind = self.kind();
        let say = |cx: &mut StepCx<'_, H>, parts: &[&[u8]]| trace::fail_with(cx, kind, parts);
        match self {
            SignError::NoAlgorithm => say(cx, &[b"httpsig: CURLOPT_HTTPSIG_ALGORITHM is required"]),
            SignError::NoKey => say(cx, &[b"httpsig: CURLOPT_HTTPSIG_KEY is required"]),
            SignError::NoKeyId => say(cx, &[b"httpsig: CURLOPT_HTTPSIG_KEYID is required"]),
            SignError::KeyLength(n) => trace::fail(
                cx,
                kind,
                format_args!("httpsig: invalid hex key (length {n})"),
            ),
            SignError::KeyTooLong => say(cx, &[b"httpsig: hex key too long"]),
            SignError::NotHex(at, pair) => {
                let mut at_text = crate::text::Text::<24>::new();
                write_number(&mut at_text, *at);
                say(
                    cx,
                    &[
                        b"httpsig: invalid hex at position ",
                        at_text.bytes(),
                        b" ('",
                        pair,
                        b"')",
                    ],
                )
            }
            SignError::Ed25519KeyLength(n) => trace::fail(
                cx,
                kind,
                format_args!("httpsig: ed25519 requires a 32-byte key (got {n})"),
            ),
            SignError::EmptyHeaderName => say(cx, &[b"httpsig: empty header component name"]),
            SignError::UnknownComponent(name) => {
                say(cx, &[b"httpsig: unknown component '", name, b"'"])
            }
            SignError::NoComponents => say(cx, &[b"httpsig: no signature components specified"]),
            SignError::TooManyComponents => trace::fail(
                cx,
                kind,
                format_args!("httpsig: too many signature components (max {MAX_COMPONENTS})"),
            ),
            SignError::DuplicateComponent(name) => say(
                cx,
                &[b"httpsig: duplicate signature component '", name, b"'"],
            ),
            SignError::HeaderNotFound(name) => {
                say(cx, &[b"httpsig: header '", name, b"' not found in request"]);
                say(cx, &[b"httpsig: cannot resolve component '", name, b"'"])
            }
            SignError::NotBuiltIn => say(
                cx,
                &[b"httpsig: algorithm 'ed25519' not supported by TLS backend"],
            ),
            SignError::Unquotable | SignError::TooLarge | SignError::OutOfMemory => kind,
        }
    }
}

fn write_number<const N: usize>(text: &mut crate::text::Text<N>, n: impl core::fmt::Display) {
    use core::fmt::Write as _;
    write!(text, "{n}").expect("a number fits");
}

/// Sign `request` (`Curl_output_httpsig`).
pub(crate) fn sign(request: &Request<'_>) -> Signing {
    let mut notes = Vec::new();
    let result = signed(request, &mut notes);
    Signing { notes, result }
}

/// The key, zeroed when dropped.
struct Secret(Vec<u8>);

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.fill(0);
        std::hint::black_box(&self.0);
    }
}

/// The signature made, zeroed when dropped.
struct Mac([u8; 32]);

impl Drop for Mac {
    fn drop(&mut self) {
        self.0.fill(0);
        std::hint::black_box(&self.0);
    }
}

/// A line built up to `MAX_PART`, as a dynbuf of that size holds it.
struct Part(Vec<u8>);

impl Part {
    fn new() -> Part {
        Part(Vec::new())
    }

    fn put(&mut self, parts: &[&[u8]]) -> Result<(), SignError> {
        let len: usize = parts.iter().map(|p| p.len()).sum();
        if self.0.len() + len + 1 > MAX_PART {
            return Err(SignError::TooLarge);
        }
        for part in parts {
            self.0.try_extend_from_slice(part)?;
        }
        Ok(())
    }

    /// `text` quoted as an RFC 8941 string (`sf_append_quoted`).
    fn put_quoted(&mut self, text: &[u8]) -> Result<(), SignError> {
        self.put(&[b"\""])?;
        for &b in text {
            if b < 0x20 || b == 0x7f {
                return Err(SignError::Unquotable);
            }
            if b == b'\\' || b == b'"' {
                self.put(&[b"\\"])?;
            }
            self.put(&[&[b]])?;
        }
        self.put(&[b"\""])
    }
}

fn signed(request: &Request<'_>, notes: &mut Vec<Vec<u8>>) -> Result<Option<Vec<u8>>, SignError> {
    let sig = request.signature;
    let algorithm = sig.algorithm.ok_or(SignError::NoAlgorithm)?;
    let key = sig
        .key
        .as_deref()
        .filter(|k| !k.is_empty())
        .ok_or(SignError::NoKey)?;
    let key_id = sig
        .key_id
        .as_deref()
        .filter(|k| !k.is_empty())
        .ok_or(SignError::NoKeyId)?;
    // The application signs the request itself.
    if request.headers.replaces(b"Signature") || request.headers.replaces(b"Signature-Input") {
        return Ok(None);
    }
    let key = decode_hex_key(key)?;
    if algorithm == SignatureAlgorithm::Ed25519 && key.0.len() != 32 {
        return Err(SignError::Ed25519KeyLength(key.0.len()));
    }
    let mut authority = Part::new();
    authority.put(&[request.authority])?;
    // `@query` always starts with its `?`.
    let mut query = Part::new();
    query.put(&[b"?", request.query.unwrap_or_default()])?;
    let mut lowered = Vec::new();
    let components = components(
        sig.components.as_deref(),
        request.query.is_some(),
        &mut lowered,
    )?;
    let created = created(request.now);
    let mut params = Part::new();
    params.put(&[b"("])?;
    for (i, c) in components.iter().enumerate() {
        if i > 0 {
            params.put(&[b" "])?;
        }
        params.put_quoted(c.name(&lowered))?;
    }
    params.put(&[b")"])?;
    let mut digits = crate::text::Text::<24>::new();
    write_number(&mut digits, created);
    params.put(&[b";created=", digits.bytes()])?;
    params.put(&[b";keyid="])?;
    params.put_quoted(key_id)?;
    params.put(&[b";alg=\"", algorithm_name(algorithm), b"\""])?;
    notes.try_push(joined(&[b"httpsig: Signature-Input params: ", &params.0])?)?;
    let mut base = Part::new();
    let mut value = Part::new();
    for c in &components {
        let name = c.name(&lowered);
        let value: &[u8] = match c {
            Component::Method => request.method,
            Component::Authority => &authority.0,
            Component::Path => request.path,
            Component::Query => &query.0,
            Component::Header(..) => {
                header_value(request.headers, name, &mut value)?;
                &value.0
            }
        };
        base.put(&[b"\"", name, b"\": ", value, b"\n"])?;
    }
    base.put(&[b"\"@signature-params\": ", &params.0])?;
    notes.try_push(joined(&[b"httpsig: Signature base: [", &base.0, b"]"])?)?;
    let mac = match algorithm {
        // Ed25519 comes with the OpenSSL binding the TLS step of
        // milestone 3 makes; until then, refused as C refuses it built
        // without a TLS library that has it.
        SignatureAlgorithm::Ed25519 => return Err(SignError::NotBuiltIn),
        SignatureAlgorithm::HmacSha256 => Mac(hmac_sha256(&key.0, &[&base.0])),
    };
    let mut signature = Part::new();
    let mut encoded = Vec::new();
    base64(mac.0.iter().copied(), mac.0.len(), &mut encoded)?;
    signature.put(&[LABEL, b"=:", &encoded, b":"])?;
    let mut input = Part::new();
    input.put(&[LABEL, b"=", &params.0])?;
    let lines = joined(&[
        b"Signature-Input: ",
        &input.0,
        b"\r\nSignature: ",
        &signature.0,
        b"\r\n",
    ])?;
    notes.try_push(joined(&[b"httpsig: Signature-Input: ", &input.0])?)?;
    notes.try_push(joined(&[b"httpsig: Signature: ", &signature.0])?)?;
    Ok(Some(lines))
}

fn joined(parts: &[&[u8]]) -> Result<Vec<u8>, OutOfMemory> {
    let mut out = Vec::new();
    out.try_reserve_exact(parts.iter().map(|p| p.len()).sum())
        .map_err(|_| OutOfMemory)?;
    for part in parts {
        out.try_extend_from_slice(part)?;
    }
    Ok(out)
}

fn algorithm_name(algorithm: SignatureAlgorithm) -> &'static [u8] {
    match algorithm {
        SignatureAlgorithm::Ed25519 => b"ed25519",
        SignatureAlgorithm::HmacSha256 => b"hmac-sha256",
    }
}

/// The key's bytes, from its hex with its line ends left out
/// (`decode_hex_key`).
fn decode_hex_key(hex: &[u8]) -> Result<Secret, SignError> {
    let end = hex
        .iter()
        .rposition(|&b| b != b'\r' && b != b'\n')
        .map_or(0, |at| at + 1);
    let hex = &hex[..end];
    if hex.is_empty() || !hex.len().is_multiple_of(2) {
        return Err(SignError::KeyLength(hex.len()));
    }
    if hex.len() > MAX_INPUT {
        return Err(SignError::KeyTooLong);
    }
    let mut key = Secret(Vec::new());
    key.0
        .try_reserve_exact(hex.len() / 2)
        .map_err(|_| OutOfMemory)?;
    for (i, pair) in hex.as_chunks::<2>().0.iter().enumerate() {
        let digit = |b: u8| char::from(b).to_digit(16);
        let (Some(hi), Some(lo)) = (digit(pair[0]), digit(pair[1])) else {
            return Err(SignError::NotHex(i * 2, [pair[0], pair[1]]));
        };
        key.0.try_push((hi << 4 | lo) as u8)?;
    }
    Ok(key)
}

/// A component a signature covers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Component {
    Method,
    Authority,
    Path,
    Query,
    /// A header, its name where the lowercased components are.
    Header(usize, usize),
}

impl Component {
    /// Its name as signed: a derived one's with its `@`.
    fn name<'a>(&self, lowered: &'a [u8]) -> &'a [u8] {
        match *self {
            Component::Method => b"@method",
            Component::Authority => b"@authority",
            Component::Path => b"@path",
            Component::Query => b"@query",
            Component::Header(from, to) => &lowered[from..to],
        }
    }
}

/// The components `given` names, lowercased into `lowered`; unless it
/// names any, the method, the authority, the path and, if there is one,
/// the query (`parse_components`).
fn components(
    given: Option<&[u8]>,
    has_query: bool,
    lowered: &mut Vec<u8>,
) -> Result<Vec<Component>, SignError> {
    let mut out = Vec::new();
    out.try_reserve_exact(MAX_COMPONENTS)
        .map_err(|_| OutOfMemory)?;
    let Some(given) = given.filter(|g| !g.is_empty()) else {
        out.try_extend_from_slice(&[Component::Method, Component::Authority, Component::Path])?;
        if has_query {
            out.try_push(Component::Query)?;
        }
        return Ok(out);
    };
    lowered.try_extend_from_slice(given)?;
    lowered.make_ascii_lowercase();
    let blank = |b: &u8| *b == b' ' || *b == b'\t';
    let mut at = 0;
    loop {
        while lowered.get(at).is_some_and(blank) {
            at += 1;
        }
        if at == lowered.len() {
            break;
        }
        if out.len() == MAX_COMPONENTS {
            return Err(SignError::TooManyComponents);
        }
        let start = at;
        while lowered.get(at).is_some_and(|b| !blank(b)) {
            if matches!(lowered[at], b'"' | b'\\') {
                return Err(SignError::Unquotable);
            }
            at += 1;
        }
        let token = &lowered[start..at];
        let component = match token.strip_suffix(b":") {
            Some([]) => return Err(SignError::EmptyHeaderName),
            Some(name) => Component::Header(start, start + name.len()),
            None => match token {
                b"method" => Component::Method,
                b"authority" => Component::Authority,
                b"path" => Component::Path,
                b"query" => Component::Query,
                _ => {
                    let mut name = Vec::new();
                    name.try_extend_from_slice(token)?;
                    return Err(SignError::UnknownComponent(name));
                }
            },
        };
        out.try_push(component)?;
    }
    if out.is_empty() {
        return Err(SignError::NoComponents);
    }
    // RFC 9421: each component is covered once.
    for (i, a) in out.iter().enumerate() {
        if out[i + 1..]
            .iter()
            .any(|b| a.name(lowered) == b.name(lowered))
        {
            let mut name = Vec::new();
            name.try_extend_from_slice(a.name(lowered))?;
            return Err(SignError::DuplicateComponent(name));
        }
    }
    Ok(out)
}

/// The values of the application's headers `name` names, each trimmed of
/// its blanks, joined with `, ` (RFC 9421 2.1, `resolve_component`).
fn header_value(headers: &UserHeaders, name: &[u8], value: &mut Part) -> Result<(), SignError> {
    value.0.clear();
    let mut found = false;
    for line in headers.lines() {
        let named = line.len() > name.len()
            && line[..name.len()].eq_ignore_ascii_case(name)
            && matches!(line[name.len()], b':' | b';');
        let Some(colon) = line.iter().position(|&b| b == b':').filter(|_| named) else {
            continue;
        };
        let blank = |b: &u8| *b == b' ' || *b == b'\t';
        let rest = &line[colon + 1..];
        let start = rest.iter().position(|b| !blank(b)).unwrap_or(rest.len());
        let end = rest
            .iter()
            .rposition(|b| !blank(b))
            .map_or(start, |at| at + 1);
        if found {
            value.put(&[b", "])?;
        }
        value.put(&[&rest[start..end]])?;
        found = true;
    }
    if found {
        Ok(())
    } else {
        let mut copy = Vec::new();
        copy.try_extend_from_slice(name)?;
        Err(SignError::HeaderNotFound(copy))
    }
}

/// When the signature says it was made: now, but for the debug test
/// build, which takes `CURL_HTTPSIG_CREATED`, or 0, when
/// `CURL_FORCETIME` is set (`httpsig_get_created`).
fn created(now: i64) -> i64 {
    #[cfg(feature = "debug-hooks")]
    if curl_os::env::is_set(b"CURL_FORCETIME") {
        let given = curl_os::env::var(b"CURL_HTTPSIG_CREATED").ok().flatten();
        return given.as_deref().and_then(leading_number).unwrap_or(0);
    }
    now
}

/// The decimal number `text` starts with, if it starts with one that
/// fits (`curlx_str_number`).
#[cfg_attr(not(feature = "debug-hooks"), allow(dead_code))]
fn leading_number(text: &[u8]) -> Option<i64> {
    let digits = text.iter().take_while(|b| b.is_ascii_digit()).count();
    if digits == 0 {
        return None;
    }
    text[..digits].iter().try_fold(0i64, |n, &d| {
        n.checked_mul(10)?.checked_add(i64::from(d - b'0'))
    })
}

#[cfg(test)]
mod tests;
