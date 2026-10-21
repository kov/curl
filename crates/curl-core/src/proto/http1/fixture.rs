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
    let attrs = within[open..body_at].to_vec();
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
        let end = find(&text, b"\n\n").map_or(text.len(), |e| e + 2);
        let mut head = replace(&text[..end], b"\n", b"\r\n");
        head.extend_from_slice(&text[end..]);
        text = head;
    }
    if find(&attrs, b"nonewline=\"yes\"").is_some() && text.last() == Some(&b'\n') {
        text.pop();
        if text.last() == Some(&b'\r') {
            text.pop();
        }
    }
    Some(Section { attrs, text })
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
    // `%hex[..]hex%` and `%repeat[N x ..]%`, with `%NN` bytes inside.
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
