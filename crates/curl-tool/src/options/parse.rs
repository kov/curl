//! Reading the command line, as `parse_args` and `getparameter` in
//! `src/tool_getparam.c` read it.

use std::ffi::OsString;

use curl_core::version::version;

use curl_alloc::{OutOfMemory, TryVec as _, try_format};

use super::apply::{CommandLine, Flow, Request, Value, apply};
use super::{ArgKind, MAX_OPTION_LEN, ParamError, Spec, find_long, find_short, number};
use crate::config::{self, Entry, Unread};
use crate::msgs::Messages;
use crate::slurp::{As, ReadFailed};

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

/// How deep configuration files may name one another, the command line
/// counted (`CONFIG_MAX_LEVELS`).
const CONFIG_LEVELS: u32 = 5;

/// Parse `argv`, the program name first, after `curlrc`, the default
/// configuration file, if it is to be read, and give `then` what was
/// parsed. A rejected command line has been reported, with the hint to try
/// `--help`, when `then` is called. Arguments of options holding secrets
/// are passed to `wipe` once read, as C's `cleanarg` overwrites them.
///
/// A configuration file is read as `--config` names it, and its text kept
/// until `then` returns: what was parsed borrows from it as it does from
/// `argv`.
pub(crate) fn parse<'a, R>(
    argv: &'a [OsString],
    curlrc: Option<&'a [u8]>,
    msgs: &mut Messages,
    wipe: Wipe<'_>,
    then: impl for<'p> FnOnce(Result<Parsed<'p>, ParamError>, &mut Messages) -> R,
) -> R {
    let parser = match Parser::new(argv) {
        Ok(parser) => parser,
        Err(e) => return then(Err(e), msgs),
    };
    let step = match curlrc {
        Some(name) => Step::Read(
            parser,
            Wanted {
                name,
                levels: CONFIG_LEVELS,
                curlrc: true,
            },
        ),
        None => parser.drive(msgs, wipe),
    };
    go_on(step, msgs, wipe, then)
}

/// Parse `argv` as `parse` does, but for files to read: none may be
/// named. For tests.
#[cfg(test)]
fn parse_args<'a>(
    argv: &'a [OsString],
    msgs: &mut Messages,
    wipe: Wipe<'_>,
) -> Result<Parsed<'a>, ParamError> {
    match Parser::new(argv)?.drive(msgs, wipe) {
        Step::Done(parsed) => parsed,
        Step::Read(..) | Step::ReadUrls(..) => panic!("a file to read was named"),
    }
}

/// Where the parse is.
enum Step<'a> {
    Done(Result<Parsed<'a>, ParamError>),
    /// It goes on once this configuration file is read.
    Read(Parser<'a>, Wanted<'a>),
    /// It goes on once the URLs in this file are read (`parse_url`).
    ReadUrls(Parser<'a>, &'a [u8]),
}

/// A configuration file to read.
struct Wanted<'a> {
    name: &'a [u8],
    /// How many more files it may name in turn.
    levels: u32,
    /// It is the default file, whose failure is ignored.
    curlrc: bool,
}

/// Read each configuration file the parse wants, then give `then` its
/// result. Each file's text lives in a frame of its own, for as long as
/// what is parsed after it.
fn go_on<'a, R>(
    step: Step<'a>,
    msgs: &mut Messages,
    wipe: Wipe<'_>,
    then: impl for<'p> FnOnce(Result<Parsed<'p>, ParamError>, &mut Messages) -> R,
) -> R {
    let (parser, wanted) = match step {
        Step::Done(parsed) => return then(parsed, msgs),
        Step::Read(parser, wanted) => (parser, wanted),
        Step::ReadUrls(parser, name) => {
            let text = match crate::slurp::read(name, As::Binary) {
                Ok(text) => text,
                // Any failure is one to read the file.
                Err(_) => {
                    let step = parser.fail(ParamError::ReadError, msgs);
                    return go_on(step, msgs, wipe, then);
                }
            };
            // What is parsed from here borrows the file's text.
            let mut parser: Parser<'_> = parser;
            let added = config::url_lines(&text).try_for_each(|url| {
                let url = url.map_err(|_| ParamError::ReadError)?;
                let op = parser.line.current();
                op.add_url(url, true, msgs)
                    .map_err(|_| ParamError::ReadError)
            });
            let step = match added {
                Ok(()) => parser.drive(msgs, wipe),
                Err(e) => parser.fail(e, msgs),
            };
            return go_on(step, msgs, wipe, then);
        }
    };
    let mut text = match crate::slurp::read(wanted.name, As::Binary) {
        Ok(text) => text,
        Err(e) => {
            let e = match e {
                ReadFailed::OutOfMemory => ParamError::NoMem,
                ReadFailed::Open | ReadFailed::Read => ParamError::ReadError,
            };
            let step = unread(parser, &wanted, e, msgs, wipe);
            return go_on(step, msgs, wipe, then);
        }
    };
    let entries = match config::entries(&mut text) {
        Ok(entries) => entries,
        Err(e) => {
            let e = match e {
                Unread::OutOfMemory => ParamError::NoMem,
                Unread::TooLong => ParamError::ReadError,
            };
            let step = unread(parser, &wanted, e, msgs, wipe);
            return go_on(step, msgs, wipe, then);
        }
    };
    // What is parsed from here borrows the file's text.
    let mut parser: Parser<'_> = parser;
    let file = Source::File {
        name: wanted.name,
        entries: &entries,
        at: 0,
        levels: wanted.levels,
        curlrc: wanted.curlrc,
    };
    let step = match parser.sources.try_push(file) {
        Ok(()) => parser.drive(msgs, wipe),
        Err(OutOfMemory) => parser.fail(ParamError::NoMem, msgs),
    };
    go_on(step, msgs, wipe, then)
}

/// Where the parse goes when `wanted` cannot be read: on without it if it
/// is the default file, which is then not one, or to failure with `e`,
/// after `cannot read config from '...'` for a file that could not be
/// read.
fn unread<'a>(
    parser: Parser<'a>,
    wanted: &Wanted<'_>,
    e: ParamError,
    msgs: &mut Messages,
    wipe: Wipe<'_>,
) -> Step<'a> {
    if wanted.curlrc {
        return parser.drive(msgs, wipe);
    }
    if e == ParamError::ReadError {
        msgs.error(&[b"cannot read config from '", shown_name(wanted.name), b"'"]);
    }
    parser.fail(e, msgs)
}

/// A configuration file's name as messages show it.
fn shown_name(name: &[u8]) -> &[u8] {
    if name == b"-" { b"<stdin>" } else { name }
}

/// The command line being read, and where from.
struct Parser<'a> {
    argv: &'a [OsString],
    line: CommandLine<'a>,
    /// The command line, then each configuration file being read from
    /// it, the innermost last.
    sources: Vec<Source<'a>>,
}

enum Source<'a> {
    Args {
        /// The next word.
        at: usize,
        /// The word being read, for its errors.
        word: usize,
        /// `--` is not met yet.
        still_flags: bool,
    },
    File {
        name: &'a [u8],
        entries: &'a [Entry<'a>],
        /// The next entry.
        at: usize,
        levels: u32,
        curlrc: bool,
    },
}

impl<'a> Parser<'a> {
    fn new(argv: &'a [OsString]) -> Result<Parser<'a>, ParamError> {
        let mut sources = Vec::new();
        sources.try_push(Source::Args {
            at: 1,
            word: 1,
            still_flags: true,
        })?;
        Ok(Parser {
            argv,
            line: CommandLine::new()?,
            sources,
        })
    }

    /// Read words until the end, an error, or a configuration file to
    /// read (`parse_args`, `parseconfig`).
    fn drive(mut self, msgs: &mut Messages, wipe: Wipe<'_>) -> Step<'a> {
        loop {
            let step = match self.sources.last_mut() {
                None => return self.finish(msgs),
                Some(Source::Args {
                    at,
                    word,
                    still_flags,
                }) => {
                    let Some(arg) = self.argv.get(*at) else {
                        self.sources.pop();
                        continue;
                    };
                    let arg = arg.as_encoded_bytes();
                    let i = *at;
                    *word = i;
                    let step = if *still_flags && arg.first() == Some(&b'-') {
                        if arg == b"--" {
                            // The end of the options: what follows are URLs,
                            // even if they start with `-`.
                            *still_flags = false;
                            Ok((Flow::Continue, false))
                        } else {
                            let next = self.argv.get(i + 1).map(|a| a.as_encoded_bytes());
                            getparameter(arg, i, next, &mut self.line, msgs, wipe)
                        }
                    } else {
                        // A URL: it is the argument of an implied `--url`, not
                        // a word after this one to skip.
                        getparameter(b"--url", i, Some(arg), &mut self.line, msgs, wipe)
                            .map(|(flow, _)| (flow, false))
                    };
                    if let Ok((_, used_next)) = &step {
                        *at = i + 1 + usize::from(*used_next);
                    }
                    match step {
                        Ok((Flow::NextOperation, _)) => {
                            self.line.next_operation(msgs).map(|()| Flow::Continue)
                        }
                        Ok((flow, _)) => Ok(flow),
                        Err(e) => Err(e),
                    }
                    .map(|flow| (flow, CONFIG_LEVELS))
                }
                Some(Source::File {
                    name,
                    entries,
                    at,
                    levels,
                    curlrc,
                }) => {
                    let (name, entries, levels) = (*name, *entries, *levels);
                    let Some(entry) = entries.get(*at) else {
                        // The default file read whole is noted.
                        self.line.read_curlrc |= *curlrc;
                        self.sources.pop();
                        continue;
                    };
                    *at += 1;
                    for warning in entry.warnings {
                        if let Ok(number) = try_format(format_args!(":{} Option '", entry.number)) {
                            msgs.warn(&[
                                shown_name(name),
                                number.as_bytes(),
                                entry.option,
                                warning.text(),
                            ]);
                        }
                    }
                    let argument = entry.argument;
                    let step = getparameter(
                        entry.option,
                        0,
                        argument,
                        &mut self.line,
                        msgs,
                        &mut |_, _| {},
                    );
                    match step {
                        // An argument given that the option takes none.
                        Ok((_, false)) if argument.is_some_and(|a| !a.is_empty()) => {
                            Err(ParamError::GotExtraParameter)
                        }
                        // `--next` in a file starts an operation only after a
                        // URL, and is no error before one.
                        Ok((Flow::NextOperation, _)) => {
                            let has_url = self
                                .line
                                .operations
                                .last()
                                .and_then(|op| op.nodes.first())
                                .is_some_and(|n| n.url.is_some());
                            if has_url {
                                self.line
                                    .operations
                                    .try_push(Default::default())
                                    .map(|()| Flow::Continue)
                                    .map_err(ParamError::from)
                            } else {
                                Ok(Flow::Continue)
                            }
                        }
                        // What a file asks to be shown is not.
                        Ok((Flow::Request(_), _)) => Ok(Flow::Continue),
                        Ok((flow, _)) => Ok(flow),
                        Err(e) => Err(e),
                    }
                    .map(|flow| (flow, levels))
                }
            };
            match step {
                Ok((Flow::Continue, _)) => {}
                Ok((Flow::NextOperation, _)) => unreachable!("started above"),
                Ok((Flow::Request(r), _)) => return Step::Done(Ok(Parsed::Request(r))),
                Ok((Flow::Urls(name), _)) => return Step::ReadUrls(self, name),
                Ok((Flow::Config(name), levels)) => {
                    // Each file read uses up a level (`C_CONFIG`).
                    if levels == 0 {
                        if let Ok(message) = try_format(format_args!(
                            "Max config file recursion level reached ({CONFIG_LEVELS})"
                        )) {
                            msgs.error(&[message.as_bytes()]);
                        }
                        return self.fail(ParamError::BadUse, msgs);
                    }
                    let wanted = Wanted {
                        name,
                        levels: levels - 1,
                        curlrc: false,
                    };
                    return Step::Read(self, wanted);
                }
                Err(e) => return self.fail(e, msgs),
            }
        }
    }

    /// The checks after the last word.
    fn finish(self, msgs: &Messages) -> Step<'a> {
        // The last operation's name cannot come from both the response and
        // the file there.
        let op = self.line.operations.last().expect("there is always one");
        if op.remote_header_name && op.resume == Some(super::Resume::FromOutput) {
            return Step::Done(Err(report(msgs, b":", ParamError::ContdispResumeFrom)));
        }
        Step::Done(Ok(Parsed::Run(self.line)))
    }

    /// Report `e`, met reading the innermost source: each file reading it
    /// reports it in turn on the line that named the next, as
    /// `process_config_result` does, then the command line, as
    /// `parse_args` does. A failure in the default file ends only that
    /// file.
    fn fail(mut self, mut e: ParamError, msgs: &mut Messages) -> Step<'a> {
        loop {
            match self.sources.last() {
                Some(Source::File {
                    name,
                    entries,
                    at,
                    curlrc,
                    ..
                }) => {
                    let entry = &entries[*at - 1];
                    if let Ok(number) =
                        try_format(format_args!(":{} config file option '", entry.number))
                    {
                        msgs.error(&[
                            shown_name(name),
                            number.as_bytes(),
                            entry.option,
                            b"' ",
                            e.text().as_bytes(),
                        ]);
                    }
                    if e == ParamError::OptionUnknown {
                        e = ParamError::ConfigOptionUnknown;
                    }
                    let curlrc = *curlrc;
                    self.sources.pop();
                    if curlrc {
                        return self.drive(msgs, &mut |_, _| {});
                    }
                }
                Some(Source::Args { word, .. }) => {
                    let arg = self.argv[*word].as_encoded_bytes();
                    return Step::Done(Err(report(msgs, arg, e)));
                }
                None => unreachable!("the command line is read last"),
            }
        }
    }
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
        parse_args(argv, &mut msgs, &mut |_, _| {})
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
            let _ = parse_args(&argv, &mut msgs, &mut |i, o| at.try_push((i, o)).unwrap());
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
        assert_eq!(
            run(&["--retry-connrefused", "x"]),
            Ok((1, Some("retry-connrefused"), None))
        );
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
        // The last operation's name cannot come from both the response and
        // the file there.
        assert_eq!(
            run(&["-J", "-C", "-", "x"]),
            Err(ParamError::ContdispResumeFrom)
        );
        assert_eq!(
            run(&["-J", "-C", "-", "x", "--next", "y"]),
            Ok((2, None, None))
        );
        assert_eq!(
            run(&["x", "--remove-on-error"]),
            Ok((1, Some("remove-on-error"), None))
        );
        assert_eq!(
            run(&["x", "--proto", "=file"]),
            Ok((1, Some("proto"), None))
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
        assert_eq!(run(&["-T", "a[1-2]", "x"]), Ok((1, None, None)));
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
        assert!(line(&["x", "--tr-encoding"]).operations[0].tr_encoding);
    }

    /// `-z`: a sign for the condition, then a date or a file's time;
    /// neither leaves no condition.
    #[test]
    fn reads_time_conditions_as_c() {
        use curl_core::options::{Condition, TimeCondition};
        let cond = |arg: &'static str| line(&["x", "-z", arg]).operations[0].time_cond;
        let at = |when, time| Some(TimeCondition { when, time });
        let dec = "dec 12 12:00:00 1999 GMT";
        let dec_1999 = 945_000_000;
        assert_eq!(cond(dec), at(Condition::ModifiedSince, dec_1999));
        assert_eq!(
            cond("+dec 12 12:00:00 1999 GMT"),
            at(Condition::ModifiedSince, dec_1999)
        );
        assert_eq!(
            cond("-dec 12 12:00:00 1999 GMT"),
            at(Condition::UnmodifiedSince, dec_1999)
        );
        assert_eq!(
            cond("=dec 12 12:00:00 1999 GMT"),
            at(Condition::LastModified, dec_1999)
        );
        // `curl_getdate` gives the second before 1970 as 0.
        assert_eq!(
            cond("31 dec 1969 23:59:59 GMT"),
            at(Condition::ModifiedSince, 0)
        );
        let mtime =
            std::os::unix::fs::MetadataExt::mtime(&std::fs::metadata("Cargo.toml").unwrap());
        assert_eq!(cond("-Cargo.toml"), at(Condition::UnmodifiedSince, mtime));
        assert_eq!(cond("no such date nor file"), None);
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
