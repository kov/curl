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

/// Parse `argv`, the program name first. A rejected command line has been
/// reported, with the hint to try `--help`, when this returns.
pub(crate) fn parse<'a>(
    argv: &'a [OsString],
    msgs: &mut Messages,
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
                getparameter(arg, next, &mut line, msgs)
            }
        } else {
            // A URL: it is the argument of an implied `--url`, not a word
            // after this one to skip.
            getparameter(b"--url", Some(arg), &mut line, msgs).map(|(flow, _)| (flow, false))
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

/// Handle one command-line word, `flag`, with `next` the word after it.
/// Returns what to do next and whether `next` was used.
fn getparameter<'a>(
    flag: &'a [u8],
    mut next: Option<&'a [u8]>,
    line: &mut CommandLine<'a>,
    msgs: &mut Messages,
) -> Result<(Flow<'a>, bool), ParamError> {
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
        let value = if spec.kind.takes_argument() {
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
            if spec.deprecated {
                deprecated(msgs, spec);
                return Ok((Flow::Continue, used_next));
            }
            if has_leading_unicode(arg) {
                unicode_warning(msgs, spec, arg);
            }
            match spec.kind {
                ArgKind::String | ArgKind::File => Value::Text(arg),
                ArgKind::Seconds => Value::Millis(number::seconds_as_millis(arg)?),
                ArgKind::Unsigned => Value::Number(number::unsigned(arg)?),
                ArgKind::None | ArgKind::Bool => unreachable!("takes an argument"),
            }
        } else {
            if spec.deprecated {
                deprecated(msgs, spec);
                return Ok((Flow::Continue, false));
            }
            if spec.kind == ArgKind::Bool {
                Value::Toggle(toggle)
            } else {
                Value::Switch
            }
        };
        let flow = apply(line, msgs, spec, value)?;
        at += 1;
        let more = long.is_none() && !attached && at < letters.len() && !used_next;
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
    use super::*;

    fn run(args: &[&str]) -> Result<(usize, Option<&'static str>, Option<String>), ParamError> {
        let argv: Vec<OsString> = std::iter::once("curl")
            .chain(args.iter().copied())
            .map(OsString::from)
            .collect();
        let argv: &'static [OsString] = Vec::leak(argv);
        let mut msgs = Messages::new();
        msgs.silent = true;
        match parse(argv, &mut msgs)? {
            Parsed::Run(line) => Ok((
                line.operations.len(),
                line.unimplemented.map(|(s, _)| s.long),
                None,
            )),
            Parsed::Request(r) => Ok((0, None, Some(format!("{r:?}")))),
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

    #[test]
    fn reads_urls_and_operations() {
        assert_eq!(
            run(&["http://a/", "--next", "http://b/"]),
            Ok((2, None, None))
        );
        assert_eq!(run(&["--", "--bogus"]), Ok((1, None, None)));
        assert_eq!(run(&["-hfoo", "http://a/"]), Ok((1, None, None)));
        // A recognised option without its meaning is recorded, not run.
        assert_eq!(run(&["-ofile", "http://a/"]), Ok((1, Some("output"), None)));
        assert_eq!(
            run(&["-o", "file", "http://a/"]),
            Ok((1, Some("output"), None))
        );
        assert_eq!(run(&["--retry=3", "x"]), Ok((1, Some("retry"), None)));
    }
}
