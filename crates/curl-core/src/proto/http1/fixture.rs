//! Sections of the C test suite's cases (`tests/data/testN`), as
//! `runtests.pl` hands them to its servers (`tests/testutil.pm`).

/// The bytes the test server replies with: the first `<data>` of
/// `<reply>`.
pub(crate) fn reply(test: u32) -> Vec<u8> {
    let path = format!("{}/../../tests/data/test{test}", env!("CARGO_MANIFEST_DIR"));
    let file = std::fs::read(path).unwrap();
    let reply = &file[find(&file, b"<reply>").expect("a reply")..];
    let open = find(reply, b"<data").expect("reply data");
    let body_at = open + find(&reply[open..], b">").unwrap() + 1;
    let attrs = &reply[open..body_at];
    let close = body_at + find(&reply[body_at..], b"</data>").unwrap();
    // The section's own lines start after the tag's line end.
    let mut text = reply[body_at..close].to_vec();
    if text.first() == Some(&b'\n') {
        text.remove(0);
    }
    let text = substitute(&text, test);
    if find(attrs, b"crlf=\"yes\"").is_some() {
        replace(&text, b"\n", b"\r\n")
    } else if find(attrs, b"crlf=\"headers\"").is_some() {
        let end = find(&text, b"\n\n").map_or(text.len(), |e| e + 2);
        let mut head = replace(&text[..end], b"\n", b"\r\n");
        head.extend_from_slice(&text[end..]);
        head
    } else {
        text
    }
}

fn substitute(text: &[u8], test: u32) -> Vec<u8> {
    let mut text = text.to_vec();
    for (from, to) in [
        (&b"%SP"[..], &b" "[..]),
        (b"%TAB", b"\t"),
        (b"%CR", b"\r"),
        (b"%LT", b"<"),
        (b"%GT", b">"),
        (b"%AMP", b"&"),
        (b"%TESTNUMBER", test.to_string().as_bytes()),
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
