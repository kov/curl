//! The C test suite's HTTP cases of the milestone, run over the fake
//! network: the case's reply played by the fake server, its command line
//! mapped to options, and the request the server got, the output and the
//! error compared with what the case expects, as `runtests.pl` compares
//! them (it adds `--include` unless the case says not to, so the output
//! holds the headers).
//!
//! A case the runner cannot map (a server command, more than one reply, an
//! option not built, a check it cannot make) is listed with why, not run.

use std::cell::RefCell;
use std::net::SocketAddr;
use std::num::NonZeroU64;
use std::rc::Rc;

use crate::conn::io::{Conversation, FakeNet, Peer};
use crate::easy::Easy;
use crate::error::ErrorKind;
use crate::handler::{Handler, HeaderHandler, HeaderOrigin, Write, WriteHandler};
use crate::id::ArenaPolicy;
use crate::multi::{Env, Multi, NoEvents, TransferCx, drive_to_completion};
use crate::options::{HttpVersion, Method, Options, UserHeaders};
use crate::proto::http1::fixture::{self, PORT, VERSION, find};
use crate::time::{ManualClock, TimeLimit};

/// The milestone's HTTP cases (MILESTONES steps 16 to 20).
const CASES: &[u32] = &[
    // Ring A.
    1, 14, 22, 23, 47, 59, 151, 260, 334, 367, 461, 1109, 1121, 1292, // Ring B.
    34, 207, 266, 319, 326, 365, 1116, 1416, 1417, 1482, 1483, 1493, 1494, 1495, 1496, 1722, 1723,
    2106, 2119, 2918, // Ring C.
    30, 37, 282, 1665, 178, 262, 394, 398, 415, 1473, 2105, 129, 1430, 1431, 1432, 1433, 1466, 497,
    747, 1154, 1205, // Ring D.
    66, 1144, 1172, 1174, 1266, 1267, 1033, 1115, 1480, 1274, 499, 1484, 395, 767, 768, 769, 770,
    771, 772, 773, // Ring E.
    292, 293, 393, 457, 24, 152, 269, 419, 26,
];

/// Cases that run but fail for want of a feature, and the step that
/// brings it.
const KNOWN: &[(u32, &str)] = &[(367, "Basic auth from the URL's credentials (step 16)")];

/// What a case asks of the transfer, mapped from its command line.
#[derive(Default)]
struct Command {
    url: Vec<u8>,
    head: bool,
    version: HttpVersion,
    allow_09: bool,
    headers: Vec<Vec<u8>>,
    raw: bool,
    max_filesize: Option<NonZeroU64>,
    ignore_length: bool,
    user_agent: Option<Vec<u8>>,
    /// `-D`: where the header lines go.
    dump: Option<Vec<u8>>,
    /// The header lines go to the output too, as runtests.pl's
    /// `--include` puts them.
    include: bool,
}

/// Why a case is not run.
type Skip = String;

/// The words of a command line, as a shell splits it: blanks part them,
/// double quotes hold them together.
fn words(line: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut word: Option<Vec<u8>> = None;
    let mut quoted = false;
    for &b in line {
        match b {
            b'"' => {
                quoted = !quoted;
                word.get_or_insert_with(Vec::new);
            }
            b' ' | b'\t' | b'\n' | b'\r' if !quoted => {
                if let Some(w) = word.take() {
                    out.push(w);
                }
            }
            _ => word.get_or_insert_with(Vec::new).push(b),
        }
    }
    out.extend(word);
    out
}

/// The command line of `test`, mapped, or why it cannot be.
fn command(test: u32) -> Result<Command, Skip> {
    let line = fixture::section(test, "client", "command").ok_or("no command")?;
    let no_include = line.has("option", "no-include");
    if !line.attrs.ends_with(b"<command>") && !no_include {
        return Err(format!("command {}", String::from_utf8_lossy(&line.attrs)));
    }
    let mut c = Command {
        include: !no_include,
        ..Command::default()
    };
    let mut urls = 0;
    let mut words = words(&line.text).into_iter();
    while let Some(w) = words.next() {
        let mut arg = || {
            words
                .next()
                .ok_or_else(|| format!("{} needs an argument", show(&w)))
        };
        match &w[..] {
            b"-i" | b"--include" => c.include = true,
            b"-s" | b"--silent" | b"-S" | b"--show-error" | b"-sS" => {}
            b"-I" | b"--head" => c.head = true,
            b"-0" | b"--http1.0" => c.version = HttpVersion::Http10,
            b"--http1.1" => c.version = HttpVersion::Http11,
            b"--http0.9" => c.allow_09 = true,
            b"--no-http0.9" => c.allow_09 = false,
            b"--raw" => c.raw = true,
            b"--ignore-content-length" => c.ignore_length = true,
            b"-H" | b"--header" => c.headers.push(arg()?),
            b"-A" | b"--user-agent" => c.user_agent = Some(arg()?),
            b"-D" | b"--dump-header" => c.dump = Some(arg()?),
            b"--max-filesize" => {
                let n = arg()?;
                let n: u64 = std::str::from_utf8(&n).unwrap().parse().unwrap();
                c.max_filesize = NonZeroU64::new(n);
            }
            w if w.starts_with(b"-") => return Err(format!("option {}", show(w))),
            _ => {
                urls += 1;
                c.url = w;
            }
        }
    }
    if urls != 1 {
        return Err(format!("{urls} URLs"));
    }
    Ok(c)
}

fn show(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// What a case expects.
struct Expected {
    reply: Vec<u8>,
    /// The request the server is to get; none if the case does not say.
    protocol: Option<Vec<u8>>,
    /// The output; none if not checked.
    output: Option<Vec<u8>>,
    /// The header lines `-D` is to write.
    dumped: Option<Vec<u8>>,
    code: u32,
}

/// What `test` expects, or why it cannot be checked.
fn expected(test: u32, c: &Command) -> Result<Expected, Skip> {
    let file = fixture::case(test);
    let verify = &file[find(&file, b"<verify>").ok_or("no verify")?..];
    let reply_part = &file[..find(&file, b"</reply>").unwrap_or(0)];
    if find(reply_part, b"<servercmd>").is_some() {
        return Err("a server command".into());
    }
    for part in [&b"<data1"[..], b"<data2", b"<data1000"] {
        if find(reply_part, part).is_some() {
            return Err("more than one reply".into());
        }
    }
    for tag in [&b"<strip"[..], b"<stderr", b"<stdout", b"<postcheck"] {
        if find(verify, tag).is_some() {
            return Err(format!("checks {}", show(&tag[1..])));
        }
    }
    let reply = fixture::section(test, "reply", "data").ok_or("no reply")?;
    // The output is checked against the datacheck parts, joined, or else
    // the reply; not at all if the reply says so or there is nothing to
    // check (runtests.pl:1452).
    let mut output = Vec::new();
    let mut parts = 0;
    for part in [
        "datacheck",
        "datacheck1",
        "datacheck2",
        "datacheck3",
        "datacheck4",
    ] {
        if let Some(s) = fixture::section(test, "reply", part) {
            output.extend_from_slice(&s.text);
            parts += 1;
        }
    }
    if parts == 0 {
        output.clone_from(&reply.text);
    }
    let output = (!reply.has("nocheck", "yes") && !output.is_empty()).then_some(output);
    let dumped = match (&c.dump, fixture::section(test, "verify", "file")) {
        (None, None) => None,
        (Some(path), Some(file))
            if find(&file.attrs, format!("name=\"{}\"", show(path)).as_bytes()).is_some() =>
        {
            Some(file.text)
        }
        (_, Some(_)) => return Err("checks a file it does not dump".into()),
        (Some(_), None) => None,
    };
    let code = fixture::section(test, "verify", "errorcode")
        .map(|s| show(&s.text).trim().parse().unwrap())
        .unwrap_or(0);
    let protocol = fixture::section(test, "verify", "protocol").map(|s| s.text);
    Ok(Expected {
        reply: reply.text,
        protocol,
        output,
        dumped,
        code,
    })
}

/// What a case's transfer wrote: the output as the tool writes it, with
/// `-i` the header lines from its header handler and the body in the
/// order they came, and the header lines alone, as `-D` writes them.
#[derive(Clone, Default)]
struct Got {
    include: bool,
    written: Rc<RefCell<(Vec<u8>, Vec<u8>)>>,
}

impl WriteHandler for Got {
    fn write(&self, _: &mut TransferCx<'_>, body: &[u8]) -> Write {
        self.written.borrow_mut().0.extend_from_slice(body);
        Write::Accepted
    }
}

impl HeaderHandler for Got {
    fn header(&self, _: &mut TransferCx<'_>, line: &[u8], _: HeaderOrigin) -> Write {
        let mut got = self.written.borrow_mut();
        if self.include {
            got.0.extend_from_slice(line);
        }
        got.1.extend_from_slice(line);
        Write::Accepted
    }
}

/// The C code of `kind`, as `curl.h` numbers it.
fn code_of(kind: ErrorKind) -> u32 {
    let header = std::fs::read_to_string(format!(
        "{}/../../include/curl/curl.h",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    let start = header.find("  CURLE_OK = 0,").unwrap();
    let end = start + header[start..].find("CURL_LAST").unwrap();
    let mut name = String::from("CURLE");
    for c in format!("{kind:?}").chars() {
        if c.is_ascii_uppercase() {
            name.push('_');
        }
        name.push(c.to_ascii_uppercase());
    }
    header[start..end]
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("CURLE_"))
        .position(|l| l.split([',', ' ']).next() == Some(name.as_str()))
        .unwrap_or_else(|| panic!("{name} in curl.h")) as u32
}

/// Run `test`: whether it went as expected, and if not, how not.
fn run(test: u32) -> Result<Result<(), String>, Skip> {
    let c = command(test)?;
    let want = expected(test, &c)?;
    let request_closes = c.version == HttpVersion::Http10
        || c.headers
            .iter()
            .any(|h| find(h, b"Connection: close").is_some());
    let close = find(&want.reply, b"swsclose").is_some() || want.reply.is_empty() || request_closes;
    let clock = ManualClock::new().unwrap();
    let at = SocketAddr::from(([127, 0, 0, 1], PORT));
    let talk = Conversation::new(&want.reply, close);
    let net = FakeNet::new(clock.clone())
        .with_peer(at, Peer::Accepts)
        .with_conversation(at, talk.clone());
    let env = Env {
        clock: Box::new(clock),
        net: Box::new(net),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    let mut m: Multi = Multi::new(env).unwrap();
    let mut e = Easy::new();
    let got = Got {
        include: c.include,
        ..Got::default()
    };
    let o: &mut Options = e.options_mut();
    o.set_url(Some(&c.url)).unwrap();
    o.limits.total = TimeLimit::from_millis(10_000);
    o.limits.max_filesize = c.max_filesize;
    if c.head {
        o.method = Method::Head;
    }
    let tool_agent = format!("curl/{VERSION}").into_bytes();
    o.http.user_agent = Some(c.user_agent.clone().unwrap_or(tool_agent));
    o.http.headers = UserHeaders::new(c.headers.iter().map(Vec::as_slice)).unwrap();
    o.http.version = c.version;
    o.http.allow_09 = c.allow_09;
    o.http.raw = c.raw;
    o.http.ignore_content_length = c.ignore_length;
    o.callbacks.write = Some(Handler::write(got.clone()).unwrap());
    o.callbacks.header = Some(Handler::header(got.clone()).unwrap());
    let id = m.add(e, (), &mut NoEvents).unwrap();
    let result = drive_to_completion(&mut m, id, &mut NoEvents).unwrap();
    let code = result.err().map_or(0, code_of);
    let (output, headers) = got.written.borrow().clone();
    let mut wrong = Vec::new();
    if code != want.code {
        wrong.push(format!("exit {code}, not {}", want.code));
    }
    if let Some(protocol) = &want.protocol
        && talk.received() != *protocol
    {
        wrong.push(format!(
            "sent {:?}, not {:?}",
            show(&talk.received()),
            show(protocol)
        ));
    }
    if let Some(expect) = &want.output
        && output != *expect
    {
        wrong.push(format!(
            "output {:?}, not {:?}",
            show(&output),
            show(expect)
        ));
    }
    if let Some(dumped) = &want.dumped
        && headers != *dumped
    {
        wrong.push(format!(
            "headers {:?}, not {:?}",
            show(&headers),
            show(dumped)
        ));
    }
    Ok(if wrong.is_empty() {
        Ok(())
    } else {
        Err(wrong.join("; "))
    })
}

/// Every case the runner can map runs as the C build runs it; at least
/// the cases known to map are among them, so a runner that skips
/// everything does not pass.
#[test]
fn the_milestone_s_http_cases() {
    let mut ran = Vec::new();
    let mut failed = Vec::new();
    let mut skipped = Vec::new();
    for &test in CASES {
        match run(test) {
            Ok(Ok(())) => ran.push(test),
            Ok(Err(why)) => failed.push((test, format!("test {test}: {why}"))),
            Err(why) => skipped.push(format!("test {test}: {why}")),
        }
    }
    eprintln!("ran {}: {ran:?}", ran.len());
    for s in &skipped {
        eprintln!("skipped {s}");
    }
    let unexpected: Vec<_> = failed
        .iter()
        .filter(|(test, _)| !KNOWN.iter().any(|(k, _)| k == test))
        .map(|(_, why)| why.as_str())
        .collect();
    assert!(
        unexpected.is_empty(),
        "{} failed:\n{}",
        unexpected.len(),
        unexpected.join("\n")
    );
    for (known, why) in KNOWN {
        assert!(
            failed.iter().any(|(test, _)| test == known),
            "test {known} passes now: drop it from KNOWN ({why})"
        );
    }
    for must in [1, 34, 207, 326, 1274, 1416, 1417, 2106, 457, 1154] {
        assert!(ran.contains(&must), "test {must} did not run");
    }
}
