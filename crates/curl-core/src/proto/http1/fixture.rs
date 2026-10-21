//! Sections of the C test suite's cases (`tests/data/testN`), as
//! `runtests.pl` hands them to its servers and compares them
//! (`tests/testutil.pm`, `docs/tests/FILEFORMAT.md`).

/// Where the fake server is, as `%HOSTIP` and `%HTTPPORT` name it.
pub(crate) const HOST: &str = "127.0.0.1";
pub(crate) const PORT: u16 = 8990;

/// What `%VERSION` stands for: the version our user agent claims.
pub(crate) const VERSION: &str = "fixture";

/// Where `%LOGDIR` points.
pub(crate) const LOGDIR: &str = "log";

/// A section of a case: its attributes, and its text with the variables
/// substituted and its line endings as the attributes say.
#[derive(Debug)]
pub(crate) struct Section {
    pub(crate) attrs: Vec<u8>,
    pub(crate) text: Vec<u8>,
}

impl Section {
    /// Whether an attribute is set to this value, `name="value"`.
    pub(crate) fn has(&self, name: &str, value: &str) -> bool {
        find(&self.attrs, format!("{name}=\"{value}\"").as_bytes()).is_some()
    }
}

/// The case file of `test`.
pub(crate) fn case(test: u32) -> Vec<u8> {
    let path = format!("{}/../../tests/data/test{test}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(path).unwrap()
}

/// The first `<tag>` inside the first `<outer>` of `test`'s case, if there
/// is one.
pub(crate) fn section(test: u32, outer: &str, tag: &str) -> Option<Section> {
    let file = case(test);
    let from = find(&file, format!("<{outer}>").as_bytes())?;
    let to = from + find(&file[from..], format!("</{outer}>").as_bytes())?;
    let within = &file[from..to];
    let open = tag_at(within, tag)?;
    let body_at = open + find(&within[open..], b">").unwrap() + 1;
    // The whole case is substituted, its attributes too.
    let attrs = substitute(&within[open..body_at], test);
    let close = body_at + find(&within[body_at..], format!("</{tag}>").as_bytes()).unwrap();
    // The section's own lines start after the tag's line end.
    let mut text = within[body_at..close].to_vec();
    if text.first() == Some(&b'\n') {
        text.remove(0);
    }
    let mut text = substitute(&text, test);
    if find(&attrs, b"crlf=\"yes\"").is_some() {
        text = replace(&text, b"\n", b"\r\n");
    } else if find(&attrs, b"crlf=\"headers\"").is_some() {
        text = header_lines_crlf(&text);
    }
    if find(&attrs, b"nonewline=\"yes\"").is_some() && text.last() == Some(&b'\n') {
        text.pop();
        if text.last() == Some(&b'\r') {
            text.pop();
        }
    }
    Some(Section { attrs, text })
}

/// `text` with the lines that look like a head's given CRLF endings, and
/// a blank line right after one (`subnewlines` in `tests/testutil.pm`).
fn header_lines_crlf(text: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut after_update = false;
    for line in text.split_inclusive(|&b| b == b'\n') {
        if looks_like_head(line) {
            // `s/\x0d*\x0a/\x0d\x0a/`: a line with no newline is left.
            match line.strip_suffix(b"\n") {
                Some(content) => {
                    let cr = content.iter().rev().take_while(|&&b| b == b'\r').count();
                    out.extend_from_slice(&content[..content.len() - cr]);
                    out.extend_from_slice(b"\r\n");
                }
                None => out.extend_from_slice(line),
            }
            after_update = true;
        } else {
            if line == b"\n" && after_update {
                out.extend_from_slice(b"\r\n");
            } else {
                out.extend_from_slice(line);
            }
            after_update = false;
        }
    }
    out
}

/// Whether `line` is a status line, a request line or a header with no
/// carriage return in it, as `subnewlines` matches them.
fn looks_like_head(line: &[u8]) -> bool {
    let no_cr = |rest: &[u8]| !rest.contains(&b'\r');
    for version in [&b"1.1"[..], b"1.0", b"2", b"3"] {
        if let Some(rest) = line
            .strip_prefix(b"HTTP/")
            .and_then(|r| r.strip_prefix(version))
            .and_then(|r| r.strip_prefix(b" "))
            && let [code, rest @ ..] = rest
            && matches!(code, b'1'..=b'5' | b'9')
            && no_cr(rest)
        {
            return true;
        }
    }
    for method in [
        &b"GET"[..],
        b"HEAD",
        b"POST",
        b"PUT",
        b"DELETE",
        b"CONNECT",
        b"SETUP",
        b"GET_PARAMETER",
        b"OPTIONS",
        b"ANNOUNCE",
        b"DESCRIBE",
    ] {
        if let Some(rest) = line.strip_prefix(method).and_then(|r| r.strip_prefix(b" ")) {
            let target = rest.iter().take_while(|b| !b.is_ascii_whitespace()).count();
            let proto: &[u8] = if method.len() > 6 || matches!(method, b"SETUP") {
                b" RTSP/"
            } else {
                b" HTTP/"
            };
            if target > 0
                && rest[target..].starts_with(proto)
                && rest
                    .get(target + proto.len())
                    .is_some_and(u8::is_ascii_digit)
            {
                return true;
            }
        }
    }
    let name = line
        .iter()
        .take_while(|&&b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        .count();
    name > 0 && line[name..].starts_with(b": ") && no_cr(&line[name + 2..]) && !is_curl_error(line)
}

/// `curl: (N) `, which `subnewlines` leaves as it is.
fn is_curl_error(line: &[u8]) -> bool {
    line.strip_prefix(b"curl: (")
        .map(|r| {
            let digits = r.iter().take_while(|b| b.is_ascii_digit()).count();
            digits > 0 && r[digits..].starts_with(b") ")
        })
        .unwrap_or(false)
}

/// Where `<tag` starts in `within` as a whole tag name, not a prefix of a
/// longer one (`data` is not `data1`).
fn tag_at(within: &[u8], tag: &str) -> Option<usize> {
    let open = format!("<{tag}");
    let mut at = 0;
    while let Some(i) = find(&within[at..], open.as_bytes()) {
        let after = within.get(at + i + open.len());
        if matches!(after, Some(b'>' | b' ' | b'\n' | b'\t')) {
            return Some(at + i);
        }
        at += i + 1;
    }
    None
}

/// The bytes the test server replies with: the first `<data>` of
/// `<reply>`.
pub(crate) fn reply(test: u32) -> Vec<u8> {
    section(test, "reply", "data").expect("reply data").text
}

/// `text` with the case's variables replaced (`tests/testutil.pm`).
pub(crate) fn substitute(text: &[u8], test: u32) -> Vec<u8> {
    let mut text = text.to_vec();
    for (from, to) in [
        (&b"%SP"[..], &b" "[..]),
        (b"%TAB", b"\t"),
        (b"%CR", b"\r"),
        (b"%LT", b"<"),
        (b"%GT", b">"),
        (b"%AMP", b"&"),
        (b"%TESTNUMBER", test.to_string().as_bytes()),
        (b"%HOSTIP", HOST.as_bytes()),
        (b"%HTTPPORT", PORT.to_string().as_bytes()),
        (b"%VERSION", VERSION.as_bytes()),
        (b"%LOGDIR", LOGDIR.as_bytes()),
    ] {
        text = replace(&text, from, to);
    }
    // `%b64[..]b64%`, `%hex[..]hex%` and `%repeat[N x ..]%`, in that
    // order, with `%NN` bytes inside.
    while let Some(at) = find(&text, b"%b64[") {
        let end = at + find(&text[at..], b"]b64%").unwrap();
        let bytes = base64(&hex_bytes(&text[at + 5..end]));
        text.splice(at..end + 5, bytes);
    }
    while let Some(at) = find(&text, b"%hex[") {
        let end = at + find(&text[at..], b"]hex%").unwrap();
        let bytes = hex_bytes(&text[at + 5..end]);
        text.splice(at..end + 5, bytes);
    }
    while let Some(at) = find(&text, b"%repeat[") {
        let end = at + find(&text[at..], b"]%").unwrap();
        let inner = &text[at + 8..end];
        let x = find(inner, b" x ").unwrap();
        let n: usize = std::str::from_utf8(&inner[..x]).unwrap().parse().unwrap();
        let bytes = hex_bytes(&inner[x + 3..]).repeat(n);
        text.splice(at..end + 2, bytes);
    }
    text
}

/// `bytes` in base64 with padding, as Perl's `encode_base64`.
fn base64(bytes: &[u8]) -> Vec<u8> {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let (mut out, mut acc, mut bits) = (Vec::new(), 0u32, 0);
    for &b in bytes {
        acc = acc << 8 | u32::from(b);
        bits += 8;
        while bits >= 6 {
            bits -= 6;
            out.push(alphabet[(acc >> bits & 63) as usize]);
        }
    }
    if bits > 0 {
        out.push(alphabet[(acc << (6 - bits) & 63) as usize]);
    }
    while out.len() % 4 != 0 {
        out.push(b'=');
    }
    out
}

fn hex_bytes(text: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < text.len() {
        let hex = text
            .get(i + 1..i + 3)
            .filter(|h| text[i] == b'%' && h.iter().all(u8::is_ascii_hexdigit));
        match hex {
            Some(h) => {
                out.push(u8::from_str_radix(std::str::from_utf8(h).unwrap(), 16).unwrap());
                i += 3;
            }
            None => {
                out.push(text[i]);
                i += 1;
            }
        }
    }
    out
}

pub(crate) fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

pub(crate) fn replace(text: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut at = 0;
    while let Some(i) = find(&text[at..], from) {
        out.extend_from_slice(&text[at..at + i]);
        out.extend_from_slice(to);
        at += i + from.len();
    }
    out.extend_from_slice(&text[at..]);
    out
}
