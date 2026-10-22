//! AWS Signature Version 4 (`lib/http_aws_sigv4.c`): a request signed
//! with HMAC-SHA256 under a key the password, the date, the region and
//! the service make, sent as an `Authorization` that names the
//! provider, the credential's scope, the headers signed and the
//! signature, with the time signed at and, for S3, the payload's hash.

use curl_alloc::{OutOfMemory, TryVec as _};

use crate::error::ErrorKind;
use crate::handler::LentBytes;
use crate::hash::{Hash as _, Sha256, hmac_sha256};
use crate::proto::http1::request::UserHeaders;

/// The longest provider, region or service (`MAX_SIGV4_LEN`).
const MAX_PART: usize = 64;

/// The query components a request may have: this many is too many
/// (`MAX_QUERY_COMPONENTS`).
const MAX_QUERY: usize = 128;

/// What S3 signs when its payload is not hashed.
const UNSIGNED_PAYLOAD: &[u8] = b"UNSIGNED-PAYLOAD";

/// What a request is, for its signature.
pub(crate) struct Request<'a> {
    /// `CURLOPT_AWS_SIGV4`: `provider0[:provider1[:region[:service]]]`,
    /// "aws:amz" if none or empty.
    pub(crate) params: Option<&'a [u8]>,
    /// As the request line names it.
    pub(crate) method: &'a [u8],
    /// What the request asks, whatever the method line says.
    pub(crate) kind: Kind,
    /// The URL's host, without an IPv6 address's brackets: the service
    /// and the region, if not given, are its first two labels.
    pub(crate) hostname: &'a [u8],
    /// `Host`'s value as the library sends it, without its port.
    pub(crate) host: &'a [u8],
    /// The port `Host` names, if it names one.
    pub(crate) port: Option<u16>,
    /// The URL's path, as the request asks for it.
    pub(crate) path: &'a [u8],
    /// The URL's query, without its `?`, if it has one.
    pub(crate) query: Option<&'a [u8]>,
    pub(crate) headers: &'a UserHeaders,
    /// The body the application gives as POST data
    /// (`CURLOPT_POSTFIELDS`), whatever the method.
    pub(crate) post_fields: PostFields<'a>,
    /// The application says the upload is empty (`CURLOPT_INFILESIZE`
    /// of 0).
    pub(crate) empty_upload: bool,
    pub(crate) user: &'a [u8],
    pub(crate) password: &'a [u8],
    /// The time it is signed at, in seconds since the epoch.
    pub(crate) now: i64,
}

/// What a request asks for (C's `httpreq`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    GetOrHead,
    Post,
    Put,
}

/// The POST data, if the application gives any.
#[derive(Clone, Copy)]
pub(crate) enum PostFields<'a> {
    None,
    Bytes(&'a [u8]),
    Lent(&'a dyn LentBytes),
}

/// Why a request could not be signed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SignError {
    /// The first provider is empty or too long.
    NoProvider,
    /// No service is given, and the host has no first label to take.
    NoService,
    /// No region is given, and the host has no second label to take.
    NoRegion,
    /// The query has too many components.
    TooLarge,
    /// A date header given without a colon; C reports it as this.
    OutOfMemory,
}

impl From<OutOfMemory> for SignError {
    fn from(_: OutOfMemory) -> SignError {
        SignError::OutOfMemory
    }
}

impl SignError {
    pub(crate) fn kind(self) -> ErrorKind {
        match self {
            SignError::NoProvider => ErrorKind::BadFunctionArgument,
            SignError::NoService | SignError::NoRegion => ErrorKind::UrlMalformat,
            SignError::TooLarge => ErrorKind::TooLarge,
            SignError::OutOfMemory => ErrorKind::OutOfMemory,
        }
    }

    /// What C says of it, if it says anything (`failf`).
    pub(crate) fn message(self) -> Option<&'static str> {
        match self {
            SignError::NoProvider => Some("first aws-sigv4 provider cannot be empty"),
            SignError::NoService => Some("aws-sigv4: service missing in parameters and hostname"),
            SignError::NoRegion => Some("aws-sigv4: region missing in parameters and hostname"),
            SignError::TooLarge | SignError::OutOfMemory => None,
        }
    }
}

/// A signing: what it notes on the way, in order, and the lines it adds
/// to the request, each ended by CRLF, or why it failed.
pub(crate) struct Signing {
    pub(crate) notes: Vec<Vec<u8>>,
    pub(crate) result: Result<Vec<u8>, SignError>,
}

/// Sign `request` (`Curl_output_aws_sigv4`).
pub(crate) fn sign(request: &Request<'_>) -> Signing {
    let mut notes = Vec::new();
    let result = signed(request, &mut notes);
    Signing { notes, result }
}

/// The parameters, as `parse_sigv4_params` reads them.
#[derive(Debug, PartialEq, Eq)]
struct Params<'a> {
    provider0: &'a [u8],
    provider1: &'a [u8],
    region: &'a [u8],
    service: &'a [u8],
}

/// A word up to `delim` or the end, at least a byte and at most
/// `MAX_PART` long, and what follows it (`curlx_str_until`).
fn until(s: &[u8], delim: u8) -> Option<(&[u8], &[u8])> {
    let len = s.iter().position(|&b| b == delim).unwrap_or(s.len());
    (len > 0 && len <= MAX_PART).then(|| s.split_at(len))
}

/// `s` past `byte`, if it starts with it (`curlx_str_single`).
fn single(s: &[u8], byte: u8) -> Option<&[u8]> {
    s.strip_prefix(&[byte])
}

/// What the parameters say, the service and region taken from the
/// host's first labels where they say none (`parse_sigv4_params`).
fn params<'a>(
    given: Option<&'a [u8]>,
    hostname: &'a [u8],
    notes: &mut Vec<Vec<u8>>,
) -> Result<Params<'a>, SignError> {
    let line = given.filter(|l| !l.is_empty()).unwrap_or(b"aws:amz");
    let (provider0, rest) = until(line, b':').ok_or(SignError::NoProvider)?;
    let mut region: &[u8] = b"";
    let mut service: &[u8] = b"";
    let provider1 = match single(rest, b':').and_then(|r| until(r, b':')) {
        None => provider0,
        Some((provider1, rest)) => {
            // Each read stops at the first that fails, leaving what is
            // not read empty.
            if let Some((r, rest)) = single(rest, b':').and_then(|r| until(r, b':')) {
                region = r;
                if let Some((s, _)) = single(rest, b':').and_then(|r| until(r, b':')) {
                    service = s;
                }
            }
            provider1
        }
    };
    if service.is_empty() {
        let (s, rest) = until(hostname, b'.')
            .and_then(|(s, rest)| Some((s, single(rest, b'.')?)))
            .ok_or(SignError::NoService)?;
        service = s;
        notes.try_push(joined(&[
            b"aws_sigv4: picked service ",
            service,
            b" from host",
        ])?)?;
        if region.is_empty() {
            let (r, _) = until(rest, b'.')
                .and_then(|(r, rest)| Some((r, single(rest, b'.')?)))
                .ok_or(SignError::NoRegion)?;
            region = r;
            notes.try_push(joined(&[
                b"aws_sigv4: picked region ",
                region,
                b" from host",
            ])?)?;
        }
    }
    Ok(Params {
        provider0,
        provider1,
        region,
        service,
    })
}

fn joined(parts: &[&[u8]]) -> Result<Vec<u8>, OutOfMemory> {
    let mut out = Vec::new();
    for part in parts {
        out.try_extend_from_slice(part)?;
    }
    Ok(out)
}

fn signed(request: &Request<'_>, notes: &mut Vec<Vec<u8>>) -> Result<Vec<u8>, SignError> {
    let params = params(request.params, request.hostname, notes)?;
    let (payload_hash, content_sha256) = payload_hash(request, &params)?;
    let mut timestamp = timestamp(request.now)?;
    let canonical = canonical_headers(request, &params, &timestamp, content_sha256.as_deref())?;
    if let Some(given) = &canonical.given_time {
        timestamp.clone_from(given);
    }
    let mut canonical_request = joined(&[request.method, b"\n"])?;
    canon_path(
        request.path,
        should_encode(params.service),
        &mut canonical_request,
    )?;
    canonical_request.try_push(b'\n')?;
    canon_query(request.query, &mut canonical_request)?;
    canonical_request.try_push(b'\n')?;
    canonical_request.try_extend_from_slice(&canonical.lines)?;
    canonical_request.try_push(b'\n')?;
    canonical_request.try_extend_from_slice(&canonical.signed)?;
    canonical_request.try_push(b'\n')?;
    canonical_request.try_extend_from_slice(&payload_hash)?;
    // The date is the timestamp's first eight bytes; C copies them from
    // its buffer, which a timestamp given badly leaves starting with its
    // terminating zero.
    let date = timestamp.get(..8).unwrap_or(b"");
    let mut request_type = joined(&[params.provider0, b"4_request"])?;
    request_type[..params.provider0.len()].make_ascii_lowercase();
    let scope = joined(&[
        date,
        b"/",
        params.region,
        b"/",
        params.service,
        b"/",
        &request_type,
    ])?;
    let mut hashed = Sha256::default();
    hashed.update(&canonical_request);
    let hashed = hex(&hashed.finish())?;
    let mut to_sign = joined(&[
        params.provider0,
        b"4-HMAC-SHA256\n",
        &timestamp,
        b"\n",
        &scope,
        b"\n",
        &hashed,
    ])?;
    to_sign[..params.provider0.len()].make_ascii_uppercase();
    notes.try_push(joined(&[
        b"aws_sigv4: String to sign (enclosed in []) - [",
        &to_sign,
        b"]",
    ])?)?;
    let mut secret = joined(&[params.provider0, b"4", request.password])?;
    secret[..params.provider0.len()].make_ascii_uppercase();
    let key = hmac_sha256(&secret, &[date]);
    let key = hmac_sha256(&key, &[params.region]);
    let key = hmac_sha256(&key, &[params.service]);
    let key = hmac_sha256(&key, &[&request_type]);
    let signature = hex(&hmac_sha256(&key, &[&to_sign]))?;
    notes.try_push(joined(&[b"aws_sigv4: Signature - ", &signature])?)?;
    let user = crate::url::escape(request.user)?;
    let mut lines = joined(&[
        b"Authorization: ",
        params.provider0,
        b"4-HMAC-SHA256 Credential=",
        &user,
        b"/",
        &scope,
        b", SignedHeaders=",
        &canonical.signed,
        b", Signature=",
        &signature,
        b"\r\n",
    ])?;
    let at = b"Authorization: ".len();
    lines[at..at + params.provider0.len()].make_ascii_uppercase();
    // The time goes unless the application sends its own.
    if canonical.given_time.is_none() {
        let key = date_key(params.provider1)?;
        lines.try_extend_from_slice(&joined(&[&key, b": ", &timestamp, b"\r\n"])?)?;
    }
    if let Some(header) = content_sha256 {
        lines.try_extend_from_slice(&header)?;
        lines.try_extend_from_slice(b"\r\n")?;
    }
    Ok(lines)
}

/// `X-Provider1-Date`: the provider in lowercase but its first letter.
fn date_key(provider1: &[u8]) -> Result<Vec<u8>, OutOfMemory> {
    let mut key = joined(&[b"X-", provider1, b"-Date"])?;
    key[2..2 + provider1.len()].make_ascii_lowercase();
    key[2] = key[2].to_ascii_uppercase();
    Ok(key)
}

/// The time as SigV4 writes it, `19700101T000000Z`, in UTC; the debug
/// test build takes the epoch when `CURL_FORCETIME` is set
/// (`get_timestamp`).
fn timestamp(now: i64) -> Result<Vec<u8>, SignError> {
    #[cfg(feature = "debug-hooks")]
    let now = if std::env::var_os("CURL_FORCETIME").is_some() {
        0
    } else {
        now
    };
    let date = crate::date::HttpDate::of(now).map_err(|_| SignError::OutOfMemory)?;
    let mut text = crate::text::Text::<32>::new();
    date.write_compact(&mut text)
        .map_err(|_| SignError::OutOfMemory)?;
    Ok(joined(&[text.bytes()])?)
}

/// The payload's hash as signed, and the header S3 sends it in
/// (`get_payload_hash`): the application's
/// `x-<provider1>-content-sha256` if it sends one, else the POST data's
/// hash; for S3, `UNSIGNED-PAYLOAD` for an upload of a size not known to
/// be 0.
fn payload_hash(
    request: &Request<'_>,
    params: &Params<'_>,
) -> Result<(Vec<u8>, Option<Vec<u8>>), SignError> {
    let key = joined(&[b"x-", params.provider1, b"-content-sha256"])?;
    if let Some(line) = request.headers.line_replacing(&key)
        && let Some(colon) = line.iter().position(|&b| b == b':')
    {
        let value = &line[colon + 1..];
        let start = value
            .iter()
            .position(|&b| !is_blank(b))
            .unwrap_or(value.len());
        let end = value
            .iter()
            .rposition(|&b| !is_blank(b))
            .map_or(start, |e| e + 1);
        return Ok((joined(&[&value[start..end.max(start)]])?, None));
    }
    let s3 =
        params.provider0.eq_ignore_ascii_case(b"aws") && params.service.eq_ignore_ascii_case(b"s3");
    if !s3 {
        return Ok((post_fields_hash(request.post_fields)?, None));
    }
    let empty = request.kind == Kind::GetOrHead || request.empty_upload;
    let post = request.kind == Kind::Post && !matches!(request.post_fields, PostFields::None);
    let hash = if empty || post {
        post_fields_hash(request.post_fields)?
    } else {
        joined(&[UNSIGNED_PAYLOAD])?
    };
    let header = joined(&[b"x-", params.provider1, b"-content-sha256: ", &hash])?;
    Ok((hash, Some(header)))
}

/// The hash of the POST data, in hex; of nothing without any.
fn post_fields_hash(post: PostFields<'_>) -> Result<Vec<u8>, OutOfMemory> {
    let mut hashed = Sha256::default();
    match post {
        PostFields::None => {}
        PostFields::Bytes(b) => hashed.update(b),
        PostFields::Lent(lent) => {
            let mut buf = [0u8; 4096];
            let mut at = 0;
            while at < lent.size() {
                let n = lent.copy_at(at, &mut buf);
                if n == 0 {
                    break;
                }
                hashed.update(&buf[..n]);
                at += n as u64;
            }
        }
    }
    hex(&hashed.finish())
}

fn hex(digest: &[u8; 32]) -> Result<Vec<u8>, OutOfMemory> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = Vec::new();
    for b in digest {
        out.try_extend_from_slice(&[HEX[usize::from(b >> 4)], HEX[usize::from(b & 15)]])?;
    }
    Ok(out)
}

fn is_blank(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

/// The headers as signed, and their names (`make_headers`).
struct Canonical {
    /// Each `name:value\n`, sorted by name.
    lines: Vec<u8>,
    /// The names, joined by `;`.
    signed: Vec<u8>,
    /// The time the application's own date header gives, if it gives
    /// one: its 16 letters and digits, or nothing if it has not that many.
    given_time: Option<Vec<u8>>,
}

fn canonical_headers(
    request: &Request<'_>,
    params: &Params<'_>,
    timestamp: &[u8],
    content_sha256: Option<&[u8]>,
) -> Result<Canonical, SignError> {
    let mut list: Vec<Vec<u8>> = Vec::new();
    if !request.headers.replaces(b"Host") {
        let mut host = joined(&[b"Host: ", request.host])?;
        if let Some(port) = request.port {
            let mut digits = [0u8; 20];
            host.try_push(b':')?;
            host.try_extend_from_slice(crate::proto::http1::request::decimal(
                u64::from(port),
                &mut digits,
            ))?;
        }
        list.try_push(host)?;
    }
    if let Some(header) = content_sha256 {
        list.try_push(joined(&[header])?)?;
    }
    // The application's lines as they would go: `name:` alone takes one
    // of the library's away and is not signed, `name;` goes with no
    // value, a value of blanks alone and a line with neither goes nowhere.
    for line in request.headers.lines() {
        let Some(sep) = line
            .iter()
            .position(|&b| b == b':')
            .or_else(|| line.iter().position(|&b| b == b';'))
        else {
            continue;
        };
        let after = &line[sep + 1..];
        if line[sep] == b':' && after.is_empty() {
            continue;
        }
        if !after.is_empty() && after.iter().all(|&b| is_blank(b)) {
            continue;
        }
        let mut copy = joined(&[line])?;
        copy[sep] = b':';
        list.try_push(copy)?;
    }
    for entry in &mut list {
        trim(entry);
    }
    let date_key = date_key(params.provider1)?;
    let date = request
        .headers
        .line_replacing(&date_key)
        .or_else(|| request.headers.line_replacing(b"Date"));
    let given_time = match date {
        None => None,
        Some(line) => {
            let colon = line
                .iter()
                .position(|&b| b == b':')
                .ok_or(SignError::OutOfMemory)?;
            let value = &line[colon + 1..];
            let value = &value[value.iter().take_while(|&&b| is_blank(b)).count()..];
            let len = value
                .iter()
                .take_while(|b| b.is_ascii_alphanumeric())
                .count();
            Some(if len == 16 {
                joined(&[&value[..16]])?
            } else {
                Vec::new()
            })
        }
    };
    if given_time.is_none() {
        let mut entry = joined(&[b"x-", params.provider1, b"-date:", timestamp])?;
        entry[2..2 + params.provider1.len()].make_ascii_lowercase();
        list.try_push(entry)?;
    }
    // By name, the order given kept among the same names, which go as one
    // with their values joined by commas.
    list.sort_by(|a, b| name(a).cmp(name(b)));
    let mut merged: Vec<Vec<u8>> = Vec::new();
    for entry in list {
        match merged.last_mut() {
            Some(last) if name(last) == name(&entry) => {
                let value = entry
                    .iter()
                    .position(|&b| b == b':')
                    .map_or(&[][..], |c| &entry[c + 1..]);
                last.try_push(b',')?;
                last.try_extend_from_slice(value)?;
            }
            _ => merged.try_push(entry)?,
        }
    }
    let mut lines = Vec::new();
    let mut signed = Vec::new();
    for (i, entry) in merged.iter().enumerate() {
        lines.try_extend_from_slice(entry)?;
        lines.try_push(b'\n')?;
        if i > 0 {
            signed.try_push(b';')?;
        }
        signed.try_extend_from_slice(name(entry))?;
    }
    Ok(Canonical {
        lines,
        signed,
        given_time,
    })
}

/// An entry's name: up to its first colon.
fn name(entry: &[u8]) -> &[u8] {
    let end = entry.iter().position(|&b| b == b':').unwrap_or(entry.len());
    &entry[..end]
}

/// The name in lowercase, the value without blanks around it and each
/// run of blanks in it one space (`trim_headers`).
fn trim(entry: &mut Vec<u8>) {
    let colon = entry.iter().position(|&b| b == b':').unwrap_or(entry.len());
    entry[..colon].make_ascii_lowercase();
    if colon == entry.len() {
        return;
    }
    let mut store = colon + 1;
    let mut read = store;
    while read < entry.len() && is_blank(entry[read]) {
        read += 1;
    }
    while read < entry.len() {
        if is_blank(entry[read]) {
            while read < entry.len() && is_blank(entry[read]) {
                read += 1;
            }
            if read < entry.len() {
                entry[store] = b' ';
                store += 1;
            }
        } else {
            entry[store] = entry[read];
            store += 1;
            read += 1;
        }
    }
    entry.truncate(store);
}

/// Whether the path is encoded once more: for all but S3's services,
/// which sign it as it is (`should_urlencode`).
fn should_encode(service: &[u8]) -> bool {
    !matches!(
        service,
        b"s3" | b"s3express" | b"s3-outposts" | b"s3-object-lambda"
    )
}

/// A byte RFC 3986 leaves unreserved.
fn unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

fn percent(b: u8, out: &mut Vec<u8>) -> Result<(), OutOfMemory> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    out.try_extend_from_slice(&[b'%', HEX[usize::from(b >> 4)], HEX[usize::from(b & 15)]])
}

/// The path as signed (`canon_path`): encoded, but for its slashes and
/// unreserved bytes, unless `encode` is off; `/` if empty.
pub(super) fn canon_path(path: &[u8], encode: bool, out: &mut Vec<u8>) -> Result<(), OutOfMemory> {
    let start = out.len();
    if encode {
        for &b in path {
            if unreserved(b) || b == b'/' {
                out.try_push(b)?;
            } else {
                percent(b, out)?;
            }
        }
    } else {
        out.try_extend_from_slice(path)?;
    }
    if out.len() == start {
        out.try_push(b'/')?;
    }
    Ok(())
}

/// A query part decoded and encoded again: `%2B` stays, a `+` is a space
/// (`normalize_query`).
fn normalize(mut s: &[u8], out: &mut Vec<u8>) -> Result<(), OutOfMemory> {
    while let Some(&first) = s.first() {
        let byte = match s {
            [b'%', h, l, ..] if h.is_ascii_hexdigit() && l.is_ascii_hexdigit() => {
                s = &s[3..];
                let decoded = hex_value(*h) << 4 | hex_value(*l);
                if decoded == b'+' {
                    out.try_extend_from_slice(b"%2B")?;
                    continue;
                }
                decoded
            }
            _ => {
                s = &s[1..];
                first
            }
        };
        if unreserved(byte) {
            out.try_push(byte)?;
        } else if byte == b'+' {
            out.try_extend_from_slice(b"%20")?;
        } else {
            percent(byte, out)?;
        }
    }
    Ok(())
}

fn hex_value(h: u8) -> u8 {
    match h {
        b'0'..=b'9' => h - b'0',
        b'a'..=b'f' => h - b'a' + 10,
        _ => h - b'A' + 10,
    }
}

/// The query as signed (`canon_query`): its components, empty ones left
/// out, each key and value normalized, a value of nothing `key=`, sorted
/// by key, then value.
pub(super) fn canon_query(query: Option<&[u8]>, out: &mut Vec<u8>) -> Result<(), SignError> {
    let Some(query) = query else {
        return Ok(());
    };
    let parts = query.split(|&b| b == b'&').filter(|p| !p.is_empty());
    let mut pairs: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    for part in parts {
        if pairs.len() + 1 == MAX_QUERY {
            return Err(SignError::TooLarge);
        }
        let (key, value) = match part.iter().position(|&b| b == b'=') {
            Some(eq) => (&part[..eq], &part[eq + 1..]),
            None => (part, &[][..]),
        };
        let mut k = Vec::new();
        normalize(key, &mut k)?;
        let mut v = Vec::new();
        normalize(value, &mut v)?;
        pairs.try_push((k, v))?;
    }
    // Keys first, an empty one before any other and two empty ones the
    // same whatever their values (`compare_func`).
    pairs.sort_by(|a, b| match (a.0.is_empty(), b.0.is_empty()) {
        (true, true) => std::cmp::Ordering::Equal,
        _ => a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)),
    });
    // An empty key is written as nothing. C writes `(nil)`, its printf's
    // text for the NULL an empty buffer holds: a bug, not followed.
    for (i, (key, value)) in pairs.iter().enumerate() {
        if i > 0 {
            out.try_push(b'&')?;
        }
        out.try_extend_from_slice(key)?;
        out.try_push(b'=')?;
        out.try_extend_from_slice(value)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
