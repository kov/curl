//! Reading the command line, as `parse_args` and `getparameter` in
//! `src/tool_getparam.c` read it.

use std::ffi::OsString;

use curl_core::version::version;

use super::apply::{CommandLine, Flow, Request, Value, apply};
use super::{ArgKind, MAX_OPTION_LEN, ParamError, Spec, find_long, find_short, number};
use crate::msgs::Messages;

/// A command line that parsed.
pub(crate) enum Parsed<'a> {
    /// Transfers to run.
    Run(CommandLine<'a>),
    /// Something to show instead: parsing stopped at the option asking.
    Request(Request<'a>),
}

/// Overwrites a secret in the process's own command line: argument
/// `index`, from byte `offset` to its end.
pub(crate) type Wipe<'w> = &'w mut dyn FnMut(usize, usize);

/// Parse `argv`, the program name first. A rejected command line has been
/// reported, with the hint to try `--help`, when this returns. Arguments of
/// options holding secrets are passed to `wipe` once read, as C's
/// `cleanarg` overwrites them.
pub(crate) fn parse<'a>(
    argv: &'a [OsString],
    msgs: &mut Messages,
    wipe: Wipe<'_>,
) -> Result<Parsed<'a>, ParamError> {
    let mut line = CommandLine::new()?;
    let mut still_flags = true;
    let mut i = 1;
    while let Some(arg) = argv.get(i) {
        let arg = arg.as_encoded_bytes();
        let step = if still_flags && arg.first() == Some(&b'-') {
            if arg == b"--" {
                // The end of the options: what follows are URLs, even if
                // they start with `-`.
                still_flags = false;
                Ok((Flow::Continue, false))
            } else {
                let next = argv.get(i + 1).map(|a| a.as_encoded_bytes());
                getparameter(arg, i, next, &mut line, msgs, wipe)
            }
        } else {
            // A URL: it is the argument of an implied `--url`, not a word
            // after this one to skip.
            getparameter(b"--url", i, Some(arg), &mut line, msgs, wipe)
                .map(|(flow, _)| (flow, false))
        };
        match step {
            Ok((Flow::Continue, used_next)) => i += usize::from(used_next),
            Ok((Flow::NextOperation, _)) => {
                if let Err(e) = line.next_operation(msgs) {
                    return Err(report(msgs, arg, e));
                }
            }
            Ok((Flow::Request(r), _)) => return Ok(Parsed::Request(r)),
            Err(e) => return Err(report(msgs, arg, e)),
        }
        i += 1;
    }
    // C rejects `--remote-header-name` with `--continue-at -` here; both
    // are still unimplemented, which `line.unimplemented` records.
    line.note_globs();
    Ok(Parsed::Run(line))
}

/// Report `err` about argument `arg`, as `parse_args` does.
fn report(msgs: &Messages, arg: &[u8], err: ParamError) -> ParamError {
    let reason = err.text().as_bytes();
    if arg == b":" {
        msgs.help(&[reason]);
    } else {
        msgs.help(&[b"option ", arg, b": ", reason]);
    }
    err
}

/// Whether the library speaks TLS.
fn has_tls() -> bool {
    version().features.iter().any(|f| f.name() == "SSL")
}

/// A U+2000 to U+203F punctuation mark, such as a typographic dash or
/// quote, starting `arg`: usually a copy-and-paste accident.
fn has_leading_unicode(arg: &[u8]) -> bool {
    matches!(arg, [0xe2, 0x80, third, ..] if third & 0x80 != 0)
}

/// Handle one command-line word, `flag`, argument `index`, with `next` the
/// word after it. Returns what to do next and whether `next` was used.
fn getparameter<'a>(
    flag: &'a [u8],
    index: usize,
    mut next: Option<&'a [u8]>,
    line: &mut CommandLine<'a>,
    msgs: &mut Messages,
    wipe: Wipe<'_>,
) -> Result<(Flow<'a>, bool), ParamError> {
    line.options_in_word = 0;
    let mut toggle = true;
    let mut separate = true;
    let mut long = None;
    let mut letters: &[u8] = &[];
    if flag.first() != Some(&b'-') || flag.get(1) == Some(&b'-') {
        let mut word = flag.strip_prefix(b"--").unwrap_or(flag);
        let mut negated = false;
        let mut expand = false;
        if let Some(rest) = word.strip_prefix(b"no-") {
            word = rest;
            toggle = false;
            negated = true;
        } else if let Some(rest) = word.strip_prefix(b"expand-") {
            word = rest;
            expand = true;
        }
        let spec = match word.iter().position(|&b| b == b'=') {
            // `--name=value`, when the name could be one.
            Some(at) if (1..=MAX_OPTION_LEN).contains(&at) => {
                next = Some(&word[at + 1..]);
                separate = false;
                find_long(&word[..at])
            }
            _ => find_long(word),
        }
        .ok_or(ParamError::OptionUnknown)?;
        if negated && spec.kind != ArgKind::Bool {
            return Err(ParamError::NoPrefix);
        }
        if expand && next.is_some() {
            if !spec.kind.takes_argument() {
                return Err(ParamError::ExpandError);
            }
            // Variable expansion is not implemented: the option cannot be
            // applied as asked.
            line.not_implemented(spec, "--expand-");
            return Ok((Flow::Continue, separate));
        }
        long = Some(spec);
    } else {
        letters = &flag[1..];
    }

    let mut at = 0;
    loop {
        let spec: &'static Spec = match long {
            Some(spec) => spec,
            None => {
                let spec = find_short(letters.get(at).copied().unwrap_or(0))
                    .ok_or(ParamError::OptionUnknown)?;
                toggle = !spec.short_negates;
                spec
            }
        };
        if spec.needs_tls && !has_tls() {
            return Err(ParamError::LibcurlDoesntSupport);
        }
        let mut used_next = false;
        let mut attached = false;
        let applied = if spec.kind.takes_argument() {
            let arg = if long.is_none() && letters.len() > at + 1 {
                // `-ofile`: the rest of the word is the argument.
                attached = true;
                &letters[at + 1..]
            } else if spec.opt == super::Opt::Help {
                // `--help` takes its argument only if there is one, and
                // leaves it for nothing else: parsing stops.
                return Ok((
                    Flow::Request(Request::Help(next.filter(|n| !n.is_empty()))),
                    false,
                ));
            } else {
                let arg = next.ok_or(ParamError::RequiresParameter)?;
                used_next = separate;
                arg
            };
            let applied = if spec.deprecated {
                deprecated(msgs, spec);
                Ok(Flow::Continue)
            } else {
                if has_leading_unicode(arg) {
                    unicode_warning(msgs, spec, arg);
                }
                if spec.kind == ArgKind::File && arg.len() > 1 && arg[0] == b'-' {
                    msgs.warn(&[b"The filename argument '", arg, b"' looks like a flag."]);
                }
                match spec.kind {
                    ArgKind::String | ArgKind::File => Ok(Value::Text(arg)),
                    ArgKind::Seconds => number::seconds_as_millis(arg).map(Value::Millis),
                    ArgKind::Unsigned => number::unsigned(arg).map(Value::Number),
                    ArgKind::None | ArgKind::Bool => unreachable!("takes an argument"),
                }
                .and_then(|value| apply(line, msgs, spec, value))
            };
            if spec.secret {
                // Wiped whether or not the option was accepted, as in C:
                // in this word after the option, or the whole next word.
                if used_next {
                    wipe(index + 1, 0);
                } else {
                    wipe(index, flag.len() - arg.len());
                }
            }
            applied
        } else if spec.deprecated {
            deprecated(msgs, spec);
            Ok(Flow::Continue)
        } else if spec.kind == ArgKind::Bool {
            apply(line, msgs, spec, Value::Toggle(toggle))
        } else {
            apply(line, msgs, spec, Value::Switch)
        };
        let flow = applied?;
        line.options_in_word += 1;
        at += 1;
        // A deprecated option ends the word, as in C.
        let more =
            long.is_none() && !attached && at < letters.len() && !used_next && !spec.deprecated;
        if !matches!(flow, Flow::Continue) || !more {
            return Ok((flow, used_next));
        }
    }
}

fn deprecated(msgs: &Messages, spec: &Spec) {
    msgs.warn(&[
        b"--",
        spec.long.as_bytes(),
        b" is deprecated and has no function anymore",
    ]);
}

fn unicode_warning(msgs: &Messages, spec: &Spec, arg: &[u8]) {
    const MAYBE: &[u8] = b" starts with a Unicode character. Maybe ASCII was intended?";
    if spec.secret {
        msgs.warn(&[b"The argument to --", spec.long.as_bytes(), MAYBE]);
    } else {
        msgs.warn(&[b"The argument '", arg, b"'", MAYBE]);
    }
}

#[cfg(test)]
mod tests {
    use curl_alloc::TryVec as _;

    use super::*;
    use crate::options::{Output, Trace, Unimplemented, Upload};

    fn parsed(args: &[&str]) -> Result<Parsed<'static>, ParamError> {
        let argv: Vec<OsString> = std::iter::once("curl")
            .chain(args.iter().copied())
            .map(OsString::from)
            .collect();
        let argv: &'static [OsString] = Vec::leak(argv);
        let mut msgs = Messages::new();
        msgs.silent = true;
        parse(argv, &mut msgs, &mut |_, _| {})
    }

    fn run(args: &[&str]) -> Result<(usize, Option<&'static str>, Option<String>), ParamError> {
        match parsed(args)? {
            Parsed::Run(line) => Ok((
                line.operations.len(),
                line.unimplemented.map(|u| match u {
                    Unimplemented::Option(s, _) => s.long,
                    Unimplemented::Feature(f) => f,
                }),
                None,
            )),
            Parsed::Request(r) => Ok((0, None, Some(format!("{r:?}")))),
        }
    }

    fn line(args: &[&str]) -> CommandLine<'static> {
        match parsed(args) {
            Ok(Parsed::Run(line)) => line,
            Ok(Parsed::Request(r)) => panic!("{args:?} asked for {r:?}"),
            Err(e) => panic!("{args:?} failed with {e:?}"),
        }
    }

    /// The cases checked against `build/c/src/curl`: the C tool rejects
    /// each with the same error.
    #[test]
    fn rejects_like_c() {
        use ParamError::*;
        let cases: &[(&[&str], ParamError)] = &[
            (&["--bogus"], OptionUnknown),
            (&["-"], OptionUnknown),
            (&["--=x"], OptionUnknown),
            (&["--abcdefghijklmnopqrstuvwxyzab=1"], OptionUnknown),
            (&["--no-url", "x"], NoPrefix),
            (&["-o"], RequiresParameter),
            (&["--max-time", "abc"], BadNumeric),
            (&["-m", "22222242222222222"], BadNumeric),
            (&["--retry", "-3"], NegativeNumeric),
            (&["--connect-timeout", "1."], NumberTooLarge),
            (&["--next"], BadUse),
            (&["-sS", "--next"], BadUse),
            (&["-O", "-I", "--next", "http://x/"], BadUse),
            (&["-s:"], BadUse),
            (&["--url="], BlankString),
            (&["http://x/", "--next", "--bogus"], OptionUnknown),
            (&["--expand-silent", "x"], ExpandError),
            (&["x", "--proto", "+-http"], BadUse),
            (&["x", "--proto-redir", "=nope"], BadUse),
            (&["x", "--no-clobber", "-C", "1"], BadUse),
            (&["x", "-C", "1", "--no-clobber"], BadUse),
            (&["x", "--remove-on-error", "-C", "-"], BadUse),
            (&["x", "-C", "-", "--remove-on-error"], BadUse),
            (&["x", "-C", "-1"], BadNumeric),
            (&["x", "--etag-save", ""], BlankString),
            (&["x", "y", "--etag-save", "e"], BadUse),
            (&["x", "--etag-compare", "e", "--url", "y"], BadUse),
            (&["x", "-D", ""], BlankString),
            (&["x", "--max-filesize", "a"], BadNumeric),
            (&["x", "--max-filesize", "3x"], BadUse),
            (&["x", "-I", "--no-head"], BadUse),
        ];
        for (args, want) in cases {
            assert_eq!(run(args).err(), Some(*want), "{args:?}");
        }
    }

    #[test]
    fn stops_at_the_first_request() {
        assert_eq!(
            run(&["-V", "--bogus"]).unwrap().2.as_deref(),
            Some("Version")
        );
        assert_eq!(run(&["-sV"]).unwrap().2.as_deref(), Some("Version"));
        assert_eq!(
            run(&["-h", "all"]).unwrap().2.as_deref(),
            Some("Help(Some([97, 108, 108]))")
        );
        assert_eq!(run(&["--no-version", "x"]).unwrap().2, None);
        assert_eq!(
            run(&["--bogus", "-V"]).err(),
            Some(ParamError::OptionUnknown)
        );
    }

    /// Where each secret is wiped: the argument and the byte it starts at.
    #[test]
    fn wipes_secrets_where_they_are() {
        let wiped = |args: &[&str]| {
            let argv: Vec<OsString> = std::iter::once("curl")
                .chain(args.iter().copied())
                .map(OsString::from)
                .collect();
            let mut msgs = Messages::new();
            msgs.silent = true;
            let mut at = Vec::new();
            let _ = parse(&argv, &mut msgs, &mut |i, o| at.try_push((i, o)).unwrap());
            at
        };
        assert_eq!(wiped(&["-u", "a:b", "x"]), [(2, 0)]);
        assert_eq!(wiped(&["-ua:b", "x"]), [(1, 2)]);
        assert_eq!(wiped(&["-sua:b", "x"]), [(1, 3)]);
        assert_eq!(wiped(&["-su", "a:b", "x"]), [(2, 0)]);
        assert_eq!(wiped(&["--user", "a:b", "x"]), [(2, 0)]);
        assert_eq!(wiped(&["--user=a:b", "x"]), [(1, 7)]);
        assert_eq!(
            wiped(&["x", "-U", "p:q", "--pass", "k", "--oauth2-bearer=t"]),
            [(3, 0), (5, 0), (6, 16)]
        );
        assert_eq!(wiped(&["-o", "a:b", "x", "--url", "u:p@h"]), []);
        assert_eq!(wiped(&["-u"]), [], "no argument to wipe");
        // Wiped even when parsing stops at a later error.
        assert_eq!(wiped(&["-u", "a:b", "--bogus"]), [(2, 0)]);
    }

    #[test]
    fn reads_urls_and_operations() {
        assert_eq!(
            run(&["http://a/", "--next", "http://b/"]),
            Ok((2, None, None))
        );
        assert_eq!(run(&["--", "--bogus"]), Ok((1, None, None)));
        assert_eq!(run(&["-hfoo", "http://a/"]), Ok((1, None, None)));
        // A recognised option without its meaning is recorded, not run.
        assert_eq!(run(&["--retry=3", "x"]), Ok((1, Some("retry"), None)));
        // Each operation has its own URLs and options.
        assert_eq!(
            run(&["x", "--etag-save", "e", "--next", "y", "z", "-C", "1"]),
            Ok((2, Some("etag-save"), None))
        );
        assert_eq!(
            run(&["x", "-C", "1", "--clobber", "--no-remove-on-error"]),
            Ok((1, None, None))
        );
        assert_eq!(run(&["x", "--no-clobber"]), Ok((1, None, None)));
        assert_eq!(
            run(&["x", "--remove-on-error"]),
            Ok((1, Some("remove-on-error"), None))
        );
        assert_eq!(
            run(&["x", "--proto", "=file"]),
            Ok((1, Some("proto"), None))
        );
        // What would need more than one URL, or a pattern of them, is not
        // run without it.
        assert_eq!(run(&["x{a,b}"]), Ok((1, Some("URL globbing"), None)));
        // `--globoff` anywhere in the operation takes them as they are;
        // in another operation it does not.
        assert_eq!(run(&["x{a,b}", "-g"]), Ok((1, None, None)));
        assert_eq!(run(&["-g", "-T", "{a,b}", "x"]), Ok((1, None, None)));
        assert_eq!(
            run(&["-g", "x", "--next", "y[1-2]"]),
            Ok((2, Some("URL globbing"), None))
        );
        assert_eq!(
            run(&["-T", ".", "x"]),
            Ok((1, Some("uploading standard input without blocking"), None))
        );
        assert_eq!(run(&["-w", "%{json}", "x"]), Ok((1, Some("json"), None)));
        assert_eq!(run(&["-w", "%{url}", "x"]), Ok((1, None, None)));
    }

    /// A URL, `--output` and `--upload-file` each fill the first node
    /// without one, as `add_url`, `parse_output` and `parse_upload_file`
    /// do.
    #[test]
    fn fills_nodes_in_turn() {
        let l = line(&["-o", "a", "x", "-o", "b", "-T", "u", "y", "--out-null", "z"]);
        let nodes = &l.operations[0].nodes;
        let urls: Vec<_> = nodes.iter().map(|n| n.url).collect();
        assert_eq!(urls, [Some(&b"x"[..]), Some(b"y"), Some(b"z")]);
        let outputs: Vec<_> = nodes.iter().map(|n| n.output).collect();
        assert_eq!(
            outputs,
            [Output::File(b"a"), Output::File(b"b"), Output::Null]
        );
        let uploads: Vec<_> = nodes.iter().map(|n| n.upload).collect();
        assert_eq!(uploads, [Upload::File(b"u"), Upload::Unset, Upload::Unset]);
        // More outputs than URLs leave a node without one.
        let l = line(&["x", "-o", "a", "-o", "b", "-T", ""]);
        let nodes = &l.operations[0].nodes;
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[1].url, None);
        assert_eq!(nodes[0].upload, Upload::Nothing);
        assert_eq!(run(&["-o", ""]), Err(ParamError::BlankString));
        // `--next` needs a URL in the first node, not just in any.
        assert_eq!(run(&["-o", "a", "--next", "x"]), Err(ParamError::BadUse));
        // A pattern of files to upload.
        assert_eq!(run(&["-T", "a", "x"]), Ok((1, None, None)));
        for pattern in ["a[1-2]", "{a,b}"] {
            let refused = Some("upload file globbing");
            assert_eq!(run(&["-T", pattern, "x"]), Ok((1, refused, None)));
        }
        // One URL can save its ETag.
        let etag = Some("etag-save");
        assert_eq!(run(&["--etag-save", "e", "x"]), Ok((1, etag, None)));
        assert_eq!(run(&["x", "--etag-save", "e"]), Ok((1, etag, None)));
    }

    /// `--fail` and `--fail-with-body` are one choice, the last said; off,
    /// either turns both off.
    #[test]
    fn the_last_fail_option_said_wins() {
        use crate::options::Fail;
        let fail = |args: &[&str]| line(args).operations[0].fail;
        assert_eq!(fail(&["x", "--fail-with-body", "-f"]), Fail::WithoutBody);
        assert_eq!(fail(&["x", "-f", "--fail-with-body"]), Fail::WithBody);
        assert_eq!(fail(&["x", "-f", "--no-fail-with-body"]), Fail::Off);
        assert_eq!(fail(&["x"]), Fail::Off);
    }

    #[test]
    fn reads_the_http_options() {
        let l = line(&[
            "x",
            "-H",
            "A: 1",
            "-H",
            "B;",
            "-A",
            "ua",
            "-e",
            "r;auto",
            "-0",
            "--http0.9",
            "-D",
            "h",
            "--raw",
            "--ignore-content-length",
            "--max-filesize",
            "1.5k",
            "-f",
            "-N",
            "-m",
            "1.5",
            "--connect-timeout",
            "2",
            "--happy-eyeballs-timeout-ms",
            "0",
            "-6",
            "-4",
        ]);
        let op = &l.operations[0];
        assert_eq!(op.headers, [&b"A: 1"[..], b"B;"]);
        assert_eq!(op.user_agent, Some(&b"ua"[..]));
        assert_eq!((op.referer, op.auto_referer), (Some(&b"r"[..]), true));
        assert_eq!(op.http_version, Some(crate::options::HttpVersion::Http10));
        assert!(op.http09 && op.raw && op.ignore_content_length && op.no_buffer);
        assert_eq!(op.fail, crate::options::Fail::WithoutBody);
        assert_eq!((op.dump_header, op.max_filesize), (Some(&b"h"[..]), 1536));
        assert_eq!((op.timeout_ms, op.connect_timeout_ms), (1500, 2000));
        assert_eq!(op.happy_eyeballs_ms, Some(0), "0 is a delay");
        assert_eq!(
            op.ip_version,
            Some(crate::options::IpVersion::V4),
            "the last"
        );
        // `;auto` alone sets no referer; a later `-e` without it clears it.
        let op = &line(&["x", "-e", ";auto"]).operations[0];
        assert_eq!((op.referer, op.auto_referer), (None, true));
        let op = &line(&["x", "-e", "a;auto", "-e", "b"]).operations[0];
        assert_eq!((op.referer, op.auto_referer), (Some(&b"b"[..]), false));
        // `--head` shows the headers and asks for no body; `--no-buffer`
        // is `--buffer` negated.
        let op = &line(&["x", "-I"]).operations[0];
        assert!(op.no_body && op.show_headers);
        assert_eq!(op.method, crate::options::Method::Head);
        assert!(!line(&["x", "-N", "--buffer"]).operations[0].no_buffer);
        assert_eq!(
            run(&["x", "-H", "@file"]),
            Ok((1, Some("reading headers from a file"), None))
        );
        assert_eq!(
            run(&["x", "--tr-encoding"]),
            Ok((1, Some("tr-encoding"), None))
        );
    }

    #[test]
    fn reads_the_progress_meter_switch() {
        assert!(line(&["x", "--no-progress-meter"]).global.no_progress);
        assert!(!line(&["x", "--progress-meter"]).global.no_progress);
    }

    /// `-v` counts within a word only, and resets the trace time
    /// (`parse_verbose`); the trace options override each other.
    #[test]
    fn reads_tracing_as_c() {
        let g = |args: &[&str]| {
            let l = line(args);
            (l.global.trace, l.global.trace_dump, l.global.trace_time)
        };
        assert_eq!(g(&["x", "-v"]), (Trace::Plain, Some(&b"%"[..]), false));
        assert_eq!(run(&["x", "-v", "-v"]), Ok((1, None, None)));
        assert_eq!(run(&["x", "--verbose", "--verbose"]), Ok((1, None, None)));
        assert_eq!(run(&["x", "-vv"]), Ok((1, Some("-vv"), None)));
        assert_eq!(run(&["x", "-sv"]), Ok((1, None, None)));
        assert_eq!(run(&["x", "-vsv"]), Ok((1, Some("-vv"), None)));
        assert!(!g(&["x", "--trace-time", "-v"]).2);
        assert!(g(&["x", "-v", "--trace-time"]).2);
        assert_eq!(
            g(&["x", "--trace-ascii", "t", "--trace-time"]),
            (Trace::Ascii, Some(&b"t"[..]), true)
        );
        assert_eq!(g(&["x", "-v", "--trace", "t"]).0, Trace::Binary);
        assert_eq!(
            g(&["x", "--trace", "t", "-v"]),
            (Trace::Plain, Some(&b"%"[..]), false)
        );
        assert_eq!(g(&["x", "-v", "--no-verbose"]).0, Trace::None);
        assert_eq!(run(&["x", "--trace", ""]), Err(ParamError::BlankString));
    }
}
