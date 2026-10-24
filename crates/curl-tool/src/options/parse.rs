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
pub(crate) fn parse_args<'a>(
    argv: &'a [OsString],
    msgs: &mut Messages,
    wipe: Wipe<'_>,
) -> Result<Parsed<'a>, ParamError> {
    match Parser::new(argv)?.drive(msgs, wipe) {
        Step::Done(parsed) => parsed,
        Step::Read(..) | Step::ReadUrls(..) | Step::ReadHeaders(..) | Step::Grow(..) => {
            panic!("a file to read was named, or an argument expanded")
        }
    }
}

/// Where the parse is.
enum Step<'a> {
    Done(Result<Parsed<'a>, ParamError>),
    /// It goes on once this configuration file is read.
    Read(Parser<'a>, Wanted<'a>),
    /// It goes on once the URLs in this file are read (`parse_url`).
    ReadUrls(Parser<'a>, &'a [u8]),
    /// It goes on once the headers in this file are read (`parse_header`),
    /// for the proxy or not.
    ReadHeaders(Parser<'a>, &'a [u8], bool),
    /// It goes on once there is room for the argument it expanded.
    Grow(Parser<'a>),
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
        Step::Grow(parser) => {
            // Twice the room there was, so that the frames this takes
            // grow only with the logarithm of what is expanded.
            let needed = parser.room.pending.as_ref().map_or(0, Vec::len);
            let size = needed.max(parser.room.size.saturating_mul(2)).max(MIN_ROOM);
            let mut buf = Vec::new();
            if buf.try_reserve_exact(size).is_err() {
                let step = parser.fail_to_grow(msgs);
                return go_on(step, msgs, wipe, then);
            }
            #[allow(clippy::disallowed_methods, reason = "reserved above")]
            buf.resize(size, 0);
            // What is parsed from here borrows the new room.
            let mut parser: Parser<'_> = parser;
            parser.room.spare = &mut buf[..];
            parser.room.size = size;
            let step = parser.drive(msgs, wipe);
            return go_on(step, msgs, wipe, then);
        }
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
        Step::ReadHeaders(parser, name, proxy) => {
            let text = match crate::slurp::read(name, As::Binary) {
                Ok(text) => text,
                Err(e) => {
                    let e = match e {
                        ReadFailed::Open => {
                            msgs.error(&[b"Failed to open ", name]);
                            ParamError::ReadError
                        }
                        ReadFailed::Read => ParamError::ReadError,
                        ReadFailed::OutOfMemory => ParamError::NoMem,
                    };
                    let step = parser.fail(e, msgs);
                    return go_on(step, msgs, wipe, then);
                }
            };
            // What is parsed from here borrows the file's text; each line
            // is a header as it is, unchecked.
            let mut parser: Parser<'_> = parser;
            let added = config::header_lines(&text).try_for_each(|header| {
                let header = header.map_err(|_| ParamError::ReadError)?;
                let op = parser.line.current();
                let list = if proxy {
                    &mut op.proxy_headers
                } else {
                    &mut op.headers
                };
                list.try_push(header).map_err(ParamError::from)
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

/// The least room made for expanded arguments.
const MIN_ROOM: usize = 4096;

/// Where the arguments `--expand-` options expand to are kept, for as
/// long as what is parsed: the unused end of a buffer in a frame of
/// `go_on`'s. One that does not fit waits here while a larger buffer is
/// made, and its word is read again.
#[derive(Default)]
struct Room<'a> {
    spare: &'a mut [u8],
    /// The size of the buffer `spare` is the end of.
    size: usize,
    /// An expansion waiting for room.
    pending: Option<Vec<u8>>,
}

impl<'a> Room<'a> {
    /// `text` kept for the rest of the parse, or given back if there is
    /// no room for it.
    fn place(&mut self, text: Vec<u8>) -> Result<&'a [u8], Vec<u8>> {
        if text.len() > self.spare.len() {
            return Err(text);
        }
        let (used, rest) = std::mem::take(&mut self.spare).split_at_mut(text.len());
        used.copy_from_slice(&text);
        self.spare = rest;
        Ok(used)
    }
}

/// The command line being read, and where from.
struct Parser<'a> {
    argv: &'a [OsString],
    line: CommandLine<'a>,
    room: Room<'a>,
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
            room: Room::default(),
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
                            let line = &mut self.line;
                            getparameter(arg, i, next, line, &mut self.room, msgs, wipe)
                        }
                    } else {
                        // A URL: it is the argument of an implied `--url`, not
                        // a word after this one to skip.
                        let line = &mut self.line;
                        getparameter(b"--url", i, Some(arg), line, &mut self.room, msgs, wipe)
                            .map(|(flow, _)| (flow, false))
                    };
                    // A word to read again is not passed.
                    if let Ok((flow, used_next)) = &step
                        && !matches!(flow, Flow::Grow)
                    {
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
                    // Not again when the entry is read again.
                    let again = self.room.pending.is_some();
                    for warning in entry.warnings.iter().filter(|_| !again) {
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
                        &mut self.room,
                        msgs,
                        &mut |_, _| {},
                    );
                    if let Ok((Flow::Grow, _)) = step {
                        *at -= 1;
                    }
                    match step {
                        Ok((Flow::Grow, _)) => Ok(Flow::Grow),
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
                Ok((Flow::Headers { name, proxy }, _)) => {
                    return Step::ReadHeaders(self, name, proxy);
                }
                Ok((Flow::Grow, _)) => return Step::Grow(self),
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

    /// Fail for want of room for the word to be read again, which a
    /// configuration file has already stepped back over.
    fn fail_to_grow(mut self, msgs: &mut Messages) -> Step<'a> {
        if let Some(Source::File { at, .. }) = self.sources.last_mut() {
            *at += 1;
        }
        self.fail(ParamError::NoMem, msgs)
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

/// Whether the library speaks TLS (`feature_ssl`).
pub(crate) fn has_tls() -> bool {
    version().features.iter().any(|f| f.name() == "SSL")
}

/// Whether the library claims SPNEGO, which `--negotiate` and
/// `--proxy-negotiate` need (`feature_spnego`).
pub(crate) fn claims_spnego() -> bool {
    version().claims("SPNEGO")
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
    room: &mut Room<'a>,
    msgs: &mut Messages,
    wipe: Wipe<'_>,
) -> Result<(Flow<'a>, bool), ParamError> {
    line.options_in_word = 0;
    let mut toggle = true;
    let mut separate = true;
    let mut long = None;
    let mut letters: &[u8] = &[];
    // The argument is an expansion, not a word of the command line.
    let mut expanded = false;
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
        if let Some(given) = next.filter(|_| expand) {
            if !spec.kind.takes_argument() {
                return Err(ParamError::ExpandError);
            }
            // Read again, the word was expanded already.
            let text = match room.pending.take() {
                Some(text) => Some(text),
                None => line.global.variables.expand(given, msgs)?,
            };
            if let Some(text) = text {
                match room.place(text) {
                    Ok(placed) => next = Some(placed),
                    Err(text) => {
                        room.pending = Some(text);
                        return Ok((Flow::Grow, false));
                    }
                }
                expanded = true;
            }
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
            // An expansion is a copy, and only the copy is wiped in C.
            if spec.secret && !expanded {
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

    /// `--negotiate` needs a library claiming SPNEGO to be turned on,
    /// `--proxy-negotiate` even to be turned off, as C checks
    /// `feature_spnego`; the GSS-API options are read as C reads them,
    /// whatever the library has: `--delegation` by name in any case,
    /// anything else warned of and none, and `--socks5-gssapi-service`
    /// the proxy's service name.
    #[test]
    fn reads_gss_options_as_c() {
        use curl_core::options::{AuthMethods, Delegation};
        // The build claims SPNEGO, so both are taken.
        let l = line(&["--negotiate", "--proxy-negotiate", "x"]);
        assert_eq!(l.operations[0].auth, AuthMethods::NEGOTIATE);
        assert!(l.operations[0].proxy_negotiate);
        let l = line(&["--proxy-negotiate", "--no-proxy-negotiate", "x"]);
        assert!(!l.operations[0].proxy_negotiate);
        let l = line(&["--basic", "--no-negotiate", "x"]);
        assert_eq!(l.operations[0].auth, AuthMethods::BASIC);
        let delegation = |word: &str| {
            let mut got = None;
            let said = crate::msgs::captured(|mut msgs| {
                let argv: &'static [OsString] = Vec::leak(argv(&["--delegation", word, "x"]));
                got = match parse_args(argv, &mut msgs, &mut |_, _| {}) {
                    Ok(Parsed::Run(line)) => Some(line.operations[0].delegation),
                    _ => None,
                };
            });
            (got.unwrap(), said)
        };
        let (policy, always) = (
            Delegation {
                by_policy: true,
                always: false,
            },
            Delegation {
                by_policy: false,
                always: true,
            },
        );
        for (word, want) in [
            ("none", Delegation::default()),
            ("policy", policy),
            ("ALWAYS", always),
            ("Policy", policy),
        ] {
            assert_eq!(delegation(word), (want, String::new()), "{word}");
        }
        assert_eq!(
            delegation("sometimes"),
            (
                Delegation::default(),
                "Warning: unrecognized delegation method 'sometimes', using none\n".to_owned()
            )
        );
        let l = line(&[
            "--service-name",
            "s",
            "--proxy-service-name",
            "p",
            "--socks5-gssapi-service",
            "q",
            "--socks5-gssapi-nec",
            "x",
        ]);
        let op = &l.operations[0];
        assert_eq!(op.service_name, Some(&b"s"[..]));
        assert_eq!(op.proxy_service_name, Some(&b"q"[..]), "the last of either");
        assert!(op.socks5_gssapi_nec);
        assert!(l.unimplemented.is_none());
        for name in [
            "--service-name",
            "--proxy-service-name",
            "--socks5-gssapi-service",
        ] {
            assert_eq!(
                run(&[name, "", "x"]),
                Err(ParamError::BlankString),
                "{name}"
            );
        }
    }

    /// `--unix-socket` and `--abstract-unix-socket` set one path, the
    /// last given saying which namespace it is in; neither takes a blank.
    #[test]
    fn the_last_unix_socket_named_is_taken() {
        let socket = |args: &[&str]| {
            let l = line(args);
            (
                l.operations[0].unix_socket,
                l.operations[0].abstract_unix_socket,
            )
        };
        assert_eq!(
            socket(&["x", "--unix-socket", "/a"]),
            (Some(&b"/a"[..]), false)
        );
        assert_eq!(
            socket(&["x", "--unix-socket", "/a", "--abstract-unix-socket", "b"]),
            (Some(&b"b"[..]), true)
        );
        assert_eq!(
            socket(&["x", "--abstract-unix-socket", "b", "--unix-socket", "/a"]),
            (Some(&b"/a"[..]), false)
        );
        for opt in ["--unix-socket", "--abstract-unix-socket"] {
            assert!(matches!(
                parsed(&["x", opt, ""]),
                Err(ParamError::BlankString)
            ));
        }
    }

    /// `--local-port` reads a port, or a range with a blank allowed on
    /// each side of its dash, as the first port and how many to try
    /// (`parse_localport`); anything else is badly used.
    #[test]
    fn a_local_port_range_is_read_as_c_reads_it() {
        let ports = |given: &str| {
            parsed(&["x", "--local-port", given]).map(|p| match p {
                Parsed::Run(l) => (l.operations[0].local_port, l.operations[0].local_port_range),
                Parsed::Request(r) => panic!("asked for {r:?}"),
            })
        };
        assert_eq!(ports("4000"), Ok((4000, 1)));
        assert_eq!(ports("4000-4002"), Ok((4000, 3)));
        assert_eq!(ports("4000 - 4002"), Ok((4000, 3)));
        assert_eq!(ports("4000\t-4000"), Ok((4000, 1)));
        assert_eq!(ports("65535"), Ok((65535, 1)));
        assert_eq!(ports("0"), Ok((0, 1)));
        for bad in [
            "65536",
            "10-5",
            "10x",
            "-5",
            "5-",
            "10  -12",
            "",
            "4000-65536",
        ] {
            assert_eq!(ports(bad), Err(ParamError::BadUse), "{bad:?}");
        }
    }

    /// `--parallel-max` and `--parallel-max-host` cap at 65535, and below
    /// 1 fall back to their defaults (`MAX_PARALLEL`, `PARALLEL_DEFAULT`).
    #[test]
    fn parallel_caps_are_clamped_as_c_clamps_them() {
        for (given, taken) in [
            ("0", None),
            ("1", Some(1)),
            ("300", Some(300)),
            ("65535", Some(65535)),
            ("70000", Some(65535)),
        ] {
            let l = line(&[
                "x",
                "-Z",
                "--parallel-max",
                given,
                "--parallel-max-host",
                given,
            ]);
            assert!(l.global.parallel);
            assert_eq!(l.global.parallel_max.map(|n| n.get()), taken, "{given}");
            assert_eq!(l.global.parallel_host.map(|n| n.get()), taken, "{given}");
        }
        let l = line(&["x", "--parallel-immediate"]);
        assert!(l.global.parallel_immediate && !l.global.parallel);
    }

    /// `--range` is taken as given, but for a lone number, which gets a
    /// dash and loses its leading zeros, as C prints the number it read.
    #[test]
    fn a_range_is_taken_as_c_takes_it() {
        let range = |r: &str| line(&["x", "-r", r]).operations[0].range.clone();
        for (given, taken) in [
            ("1-2", "1-2"),
            ("-500", "-500"),
            ("0-10,12-15", "0-10,12-15"),
            ("1-a", "1-a"),
            ("007", "7-"),
            ("1x-5", "1-"),
            ("abc", "abc"),
            ("99999999999999999999", "99999999999999999999"),
        ] {
            assert_eq!(range(given), Some(taken.as_bytes().to_vec()), "{given}");
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
            (&["x", "-r", "1-2", "-C", "3"], BadUse),
            (&["x", "-C", "3", "-r", "1-2"], BadUse),
            (&["x", "-r", ""], BlankString),
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

    /// Every deprecated option is warned of and does nothing, wherever it
    /// is given: on the command line, as a letter, in a configuration
    /// file. One that needs TLS is refused by a library without it.
    #[test]
    fn deprecated_options_are_warned_of_and_applied_nowhere() {
        let deprecated = || super::super::table::OPTIONS.iter().filter(|s| s.deprecated);
        assert_eq!(deprecated().count(), 15);
        for spec in deprecated() {
            let flag = format!("--{}", spec.long);
            let mut args = vec![flag.as_str()];
            if spec.kind.takes_argument() {
                args.push("x");
            }
            args.push("http://h/");
            if spec.needs_tls && !has_tls() {
                assert_eq!(run(&args), Err(ParamError::LibcurlDoesntSupport));
                continue;
            }
            let mut ran = None;
            let words: &'static [OsString] = Vec::leak(argv(&args));
            let said = crate::msgs::captured(|mut msgs| {
                ran = Some(parse_args(words, &mut msgs, &mut |_, _| {}));
            });
            let Some(Ok(Parsed::Run(line))) = ran else {
                panic!("{args:?} did not parse");
            };
            assert!(line.unimplemented.is_none(), "{args:?}");
            let warning = format!("Warning: {flag} is deprecated and has no function anymore\n");
            assert_eq!(said, warning, "{args:?}");
        }
        // A deprecated letter ends its word: `v` is not read.
        for word in ["-2v", "-3v"] {
            let line = line(&[word, "http://h/"]);
            assert!(line.unimplemented.is_none());
            assert_eq!(line.global.trace, Trace::None, "{word}");
        }
        let file = TempFile::new("deprecated.cfg", b"krb = x\nsslv2\nmetalink\nnpn\n");
        let args = ["-K", file.name(), "http://h/"];
        let argv = argv(&args);
        let said = crate::msgs::captured(|mut msgs| {
            parse(&argv, None, &mut msgs, &mut |_, _| {}, |r, _| {
                let Ok(Parsed::Run(line)) = r else {
                    panic!("not parsed");
                };
                assert!(line.unimplemented.is_none());
            });
        });
        assert_eq!(
            said,
            "Warning: --krb is deprecated and has no function anymore\n\
             Warning: --sslv2 is deprecated and has no function anymore\n\
             Warning: --metalink is deprecated and has no function anymore\n\
             Warning: --npn is deprecated and has no function anymore\n"
        );
    }

    fn argv(args: &[&str]) -> Vec<OsString> {
        std::iter::once("curl")
            .chain(args.iter().copied())
            .map(OsString::from)
            .collect()
    }

    #[test]
    fn reads_urls_and_operations() {
        assert_eq!(
            run(&["http://a/", "--next", "http://b/"]),
            Ok((2, None, None))
        );
        assert_eq!(run(&["--", "--bogus"]), Ok((1, None, None)));
        // Deprecated: warned of, and nothing more, their argument taken.
        assert_eq!(
            run(&["--random-file", "f", "--egd-file", "e", "x"]),
            Ok((1, None, None))
        );
        assert_eq!(run(&["-hfoo", "http://a/"]), Ok((1, None, None)));
        // A recognised option without its meaning is recorded, not run.
        assert_eq!(
            run(&["--dns-interface", "lo", "x"]),
            Ok((1, Some("dns-interface"), None))
        );
        // Each operation has its own URLs and options.
        assert_eq!(
            run(&["x", "--dns-interface", "e", "--next", "y", "z", "-C", "1"]),
            Ok((2, Some("dns-interface"), None))
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
        assert_eq!(run(&["x", "--remove-on-error"]), Ok((1, None, None)));
        assert_eq!(run(&["x", "--use-ascii"]), Ok((1, Some("use-ascii"), None)));
        assert_eq!(run(&["-T", ".", "x"]), Ok((1, None, None)));
        assert_eq!(run(&["-w", "%time{%Y}", "x"]), Ok((1, None, None)));
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
        assert_eq!(run(&["--etag-save", "e", "x"]), Ok((1, None, None)));
        assert_eq!(run(&["x", "--etag-save", "e"]), Ok((1, None, None)));
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
        assert_eq!(cond("+Cargo.toml"), at(Condition::ModifiedSince, mtime));
        assert_eq!(cond("no such date nor file"), None);
    }

    #[test]
    fn reads_the_switches_for_every_transfer() {
        let g = |args: &[&str]| {
            let l = line(args);
            (
                l.global.fail_early,
                l.global.unstyled,
                l.global.ms_per_transfer,
            )
        };
        assert_eq!(g(&["x"]), (false, false, 0));
        assert_eq!(
            g(&["--fail-early", "--no-styled-output", "x", "--rate", "4/s"]),
            (true, true, 250)
        );
        // They are the whole command line's, whatever operation sets them.
        assert_eq!(
            g(&["x", "--fail-early", "--next", "y", "--no-fail-early"]),
            (false, false, 0)
        );
        assert_eq!(run(&["x", "--rate", "1/w"]), Err(ParamError::BadUse));
        // Styled on a terminal only, and there unless said otherwise.
        let styles = |args: &[&str], terminal| line(args).global.styles(terminal);
        assert!(styles(&["x"], true));
        assert!(!styles(&["x"], false));
        assert!(!styles(&["x", "--no-styled-output"], true));
        assert!(styles(
            &["x", "--no-styled-output", "--styled-output"],
            true
        ));
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
        assert_eq!(run(&["x", "-vv"]), Ok((1, None, None)));
        assert_eq!(run(&["x", "-sv"]), Ok((1, None, None)));
        assert_eq!(run(&["x", "-vsv"]), Ok((1, None, None)));
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

    /// `--trace-config` and each `v` past the first (`set_trace_config`,
    /// `parse_verbose`): `ids` and `time` are the tool's, `all` turns them
    /// with every component but the library's ids, and the first `-v` of
    /// a word turns everything off unless `--trace-config` was given.
    #[test]
    fn reads_the_trace_components_as_c() {
        use curl_core::components::Component;
        let on = |args: &[&str]| {
            let l = line(args);
            let c = l.global.components.clone();
            let names: Vec<&str> = Component::ALL
                .into_iter()
                .filter(|&x| c.as_ref().is_some_and(|c| c.traces(x)))
                .map(Component::name)
                .collect();
            (l.global.trace_ids, l.global.trace_time, names)
        };
        let none: Vec<&str> = Vec::new();
        assert_eq!(
            on(&["x", "--trace-config", "ids,time"]),
            (true, true, none.clone())
        );
        let all = on(&["x", "--trace-config", "all"]);
        assert_eq!(
            (all.0, all.1, all.2.len()),
            (true, true, Component::ALL.len() - 1)
        );
        assert!(!all.2.contains(&"LIB-IDS"));
        // One space after a comma is passed over; the library's ids stay
        // off even when named.
        assert_eq!(
            on(&["x", "--trace-config", "write, +read,-write,lib-ids"]),
            (false, false, vec!["READ"])
        );
        assert_eq!(
            on(&["x", "--trace-config", "all", "--trace-config", "-all,dns"]),
            (false, false, vec!["DNS"])
        );
        // `-v` keeps what `--trace-config` chose, and resets the tool's
        // own without it.
        assert_eq!(on(&["x", "--trace-config", "write", "-v"]).2, ["WRITE"]);
        assert!(!on(&["x", "--trace-ids", "-v"]).0);
        assert!(on(&["x", "-v", "--trace-ids"]).0);
        let protocol = [
            "FTP",
            "SMTP",
            "SSH",
            "WS",
            "RECVBUF",
            "SETUP",
            "HTTP/2",
            "HTTP/3",
            "HTTPS-CONNECT",
        ];
        assert_eq!(on(&["x", "-vv"]), (true, true, protocol.to_vec()));
        assert_eq!(on(&["x", "-vv", "-v"]), (false, false, none.clone()));
        let three = line(&["x", "-vvv"]);
        assert_eq!(three.global.trace, Trace::Ascii);
        let mut more = protocol.to_vec();
        more.extend(["READ", "WRITE", "SSL"]);
        more.sort();
        let mut got = on(&["x", "-vvv"]).2;
        got.sort();
        assert_eq!(got, more);
        assert!(on(&["x", "-vvvv"]).2.contains(&"TCP"));
        assert_eq!(on(&["x", "-vvvv", "--no-verbose"]), (false, false, none));
    }

    /// `--proxy` makes the proxy HTTP; `--proxy1.0` and the SOCKS options
    /// name their own kind.
    #[test]
    fn reads_the_proxy_kind() {
        use curl_core::options::ProxyType;
        let proxy = |args: &[&str]| {
            let op = &line(args).operations[0];
            (op.proxy, op.proxy_kind)
        };
        let cases = [
            ("--proxy1.0", ProxyType::Http10),
            ("--socks4", ProxyType::Socks4),
            ("--socks4a", ProxyType::Socks4a),
            ("--socks5", ProxyType::Socks5),
            ("--socks5-hostname", ProxyType::Socks5Hostname),
        ];
        for (option, kind) in cases {
            assert_eq!(
                proxy(&["x", option, "p"]),
                (Some(&b"p"[..]), kind),
                "{option}"
            );
        }
        assert_eq!(
            proxy(&["x", "--socks5", "p", "-x", "q"]),
            (Some(&b"q"[..]), ProxyType::Http)
        );
    }

    /// Each authentication option adds its method, or takes it away.
    #[test]
    fn reads_the_auth_methods() {
        use curl_core::options::AuthMethods;
        let auth = |args: &[&str]| line(args).operations[0].auth;
        let (basic, digest) = (AuthMethods::BASIC, AuthMethods::DIGEST);
        assert_eq!(auth(&["x", "--oauth2-bearer", "t"]), AuthMethods::BEARER);
        assert_eq!(auth(&["x", "--basic", "--digest"]), basic | digest);
        assert_eq!(auth(&["x", "--basic", "--digest", "--no-basic"]), digest);
        assert_eq!(auth(&["x", "--basic", "--digest", "--no-digest"]), basic);
        let sigv4 = |args: &[&str]| {
            let op = &line(args).operations[0];
            (op.auth, op.aws_sigv4)
        };
        assert_eq!(
            sigv4(&["x", "--basic", "--aws-sigv4", "a:b", "--aws-sigv4", ""]),
            (basic | AuthMethods::AWS_SIGV4, Some(&b""[..]))
        );
        // `--httpsig-algo` asks for the method; each is refused blank,
        // and so forgotten.
        let op = &line(&[
            "x",
            "--basic",
            "--httpsig-algo",
            "a",
            "--httpsig-key",
            "k",
            "--httpsig-keyid",
            "i",
            "--httpsig-headers",
            "h",
        ])
        .operations[0];
        let given = crate::options::Httpsig {
            algorithm: Some(b"a"),
            key: Some(b"k"),
            key_id: Some(b"i"),
            components: Some(b"h"),
        };
        assert_eq!((op.auth, op.httpsig), (basic | AuthMethods::HTTPSIG, given));
        for option in [
            "--httpsig-algo",
            "--httpsig-key",
            "--httpsig-keyid",
            "--httpsig-headers",
        ] {
            let parsed = parsed(&["x", option, "a", option, ""]);
            assert_eq!(parsed.err(), Some(ParamError::BlankString), "{option}");
        }
    }

    /// `--location-trusted` alone sends credentials on; `--max-redirs`
    /// takes -1 for no limit and nothing below.
    #[test]
    fn reads_the_redirect_options() {
        let op = |args: &[&str]| {
            let op = &line(args).operations[0];
            (op.unrestricted_auth, op.max_redirs)
        };
        assert_eq!(op(&["x", "-L"]), (false, None));
        assert_eq!(op(&["x", "--location-trusted"]), (true, None));
        assert_eq!(op(&["x", "--max-redirs", "-1"]), (false, Some(-1)));
        assert_eq!(op(&["x", "--max-redirs", "0"]), (false, Some(0)));
        assert_eq!(op(&["x", "--max-redirs", "12"]), (false, Some(12)));
        let refused = |n| run(&["x", "--max-redirs", n]).err();
        assert_eq!(refused("-2"), Some(ParamError::BadNumeric));
        assert_eq!(refused("1x"), Some(ParamError::BadNumeric));
        assert_eq!(refused(""), Some(ParamError::BadNumeric));
    }

    /// `--speed-limit` and `--speed-time` each fill in the other when it
    /// is not given, as `opt_unum` does: 30 seconds, 1 byte a second.
    #[test]
    fn fills_in_the_low_speed_as_c() {
        let low = |args: &[&str]| {
            let op = &line(args).operations[0];
            (op.low_speed_limit, op.low_speed_time)
        };
        assert_eq!(low(&["x"]), (0, 0));
        assert_eq!(low(&["x", "-Y", "100"]), (100, 30));
        assert_eq!(low(&["x", "-y", "5"]), (1, 5));
        assert_eq!(low(&["x", "-y", "5", "-Y", "100"]), (100, 5));
        assert_eq!(low(&["x", "-Y", "100", "-y", "5"]), (100, 5));
        assert_eq!(low(&["x", "--speed-time", "0"]), (1, 0));
        let op = &line(&[
            "x",
            "--create-file-mode",
            "0640",
            "--disallow-username-in-url",
        ]);
        let op = &op.operations[0];
        assert_eq!((op.create_file_mode, op.disallow_username), (0o640, true));
        assert_eq!(
            run(&["x", "--create-file-mode", "1000"]),
            Err(ParamError::NumberTooLarge)
        );
    }

    /// The socket options, as C reads them: `--ip-tos` a name, matched
    /// as written, or a number up to 255; `--vlan-priority` up to 7;
    /// keepalive on and Nagle off unless told otherwise. Checked against
    /// `build/c/src/curl`.
    #[test]
    fn socket_options_are_read_as_c_reads_them() {
        let op = &line(&["x"]).operations[0];
        assert!(!op.no_keepalive && !op.nagle && !op.mptcp && !op.tcp_fastopen);
        let op = &line(&[
            "x",
            "--no-keepalive",
            "--no-tcp-nodelay",
            "--mptcp",
            "--tcp-fastopen",
            "--keepalive-time",
            "30",
            "--keepalive-cnt",
            "4",
            "--vlan-priority",
            "7",
        ])
        .operations[0];
        assert!(op.no_keepalive && op.nagle && op.mptcp && op.tcp_fastopen);
        assert_eq!((op.keepalive_time, op.keepalive_cnt), (30, 4));
        assert_eq!(op.vlan_priority, 7);
        let tos = |t: &str| {
            run(&["x", "--ip-tos", t]).map(|_| line(&["x", "--ip-tos", t]).operations[0].ip_tos)
        };
        assert_eq!(tos("CS1"), Ok(0x20));
        assert_eq!(tos("LOWDELAY"), Ok(0x10));
        assert_eq!(tos("THROUGHPUT"), Ok(0x08));
        assert_eq!(tos("AF11"), Ok(0x28));
        assert_eq!(tos("255"), Ok(255));
        assert_eq!(tos("cs1"), Err(ParamError::BadNumeric), "names as written");
        assert_eq!(tos("256"), Err(ParamError::NumberTooLarge));
        assert_eq!(tos("-1"), Err(ParamError::NegativeNumeric));
        assert_eq!(
            run(&["x", "--vlan-priority", "8"]),
            Err(ParamError::NumberTooLarge)
        );
        assert_eq!(
            run(&["x", "--keepalive-time", "-1"]),
            Err(ParamError::NegativeNumeric)
        );
    }

    /// `--remote-name` names the first node without an output;
    /// `--no-remote-name` only undoes `--remote-name-all`, whose nodes
    /// take their URL's name.
    #[test]
    fn reads_remote_names() {
        let nodes = |args: &[&str]| -> Vec<(Output<'static>, bool)> {
            line(args).operations[0]
                .nodes
                .iter()
                .map(|n| (n.output, n.remote))
                .collect()
        };
        assert_eq!(nodes(&["x", "-O"]), [(Output::Remote, false)]);
        assert_eq!(
            nodes(&["-o", "a", "-O", "x", "y"]),
            [(Output::File(b"a"), false), (Output::Remote, false)]
        );
        assert_eq!(nodes(&["x", "--no-remote-name"]), [(Output::Unset, false)]);
        assert_eq!(
            nodes(&["--remote-name-all", "--no-remote-name", "x"]),
            [(Output::Stdout, true)]
        );
        assert_eq!(
            nodes(&["--remote-name-all", "-o", "a", "x"]),
            [(Output::File(b"a"), true)]
        );
    }

    /// Expanded arguments live as long as the parse, however many need
    /// more room; one that needs none is the word itself, wiped if
    /// secret, and an expanded secret is not (only C's copy is).
    #[test]
    fn keeps_every_expansion_for_the_parse() {
        let long = "x".repeat(3000);
        let mut args = vec!["curl".to_string(), "--variable".into(), format!("v={long}")];
        for i in 0..200 {
            args.push("--expand-url".into());
            args.push(format!("http://h/{i}/{{{{v}}}}"));
        }
        args.extend(["--expand-user".into(), "{{v}}:p".into()]);
        args.extend(["--expand-user".into(), "plain:p".into()]);
        let argv: Vec<OsString> = args.iter().map(OsString::from).collect();
        let mut msgs = Messages::new();
        msgs.silent = true;
        let mut wiped = Vec::new();
        let (urls, user) = parse(
            &argv,
            None,
            &mut msgs,
            &mut |i, o| wiped.push((i, o)),
            |r, _| {
                let Ok(Parsed::Run(line)) = r else {
                    panic!("not parsed");
                };
                let op = &line.operations[0];
                let urls: Vec<Vec<u8>> = op.nodes.iter().map(|n| n.url.unwrap().to_vec()).collect();
                (urls, op.user.as_deref().map(<[u8]>::to_vec))
            },
        );
        assert_eq!(urls.len(), 200);
        for (i, url) in urls.iter().enumerate() {
            assert_eq!(url, format!("http://h/{i}/{long}").as_bytes());
        }
        assert_eq!(user.as_deref(), Some(&b"plain:p"[..]));
        assert_eq!(wiped, [(406, 0)]);
    }

    /// An expansion that fills what is left of the room exactly fits.
    #[test]
    fn an_expansion_fits_the_room_to_its_last_byte() {
        let mut buf = [0u8; 4];
        let mut room = Room {
            spare: &mut buf[..],
            size: 4,
            pending: None,
        };
        assert_eq!(room.place(b"ab".to_vec()), Ok(&b"ab"[..]));
        assert_eq!(room.place(b"cde".to_vec()), Err(b"cde".to_vec()));
        assert_eq!(room.place(b"cd".to_vec()), Ok(&b"cd"[..]));
        assert_eq!(room.place(b"e".to_vec()), Err(b"e".to_vec()));
    }

    /// In a configuration file too, an entry whose expansion waits for
    /// room is read again, warned of once.
    #[test]
    fn keeps_every_expansion_of_a_config_file() {
        let long = "x".repeat(3000);
        let mut text = format!("--variable v={long}\n");
        for i in 0..50 {
            text.push_str(&format!("--expand-url http://h/{i}/{{{{v}}}}\n"));
        }
        text.push_str("--expand-url 'http://h/q/{{v}}\n");
        let file = TempFile::new("expand.cfg", text.as_bytes());
        let argv: Vec<OsString> = ["curl", "-K", file.name()]
            .iter()
            .map(OsString::from)
            .collect();
        let mut urls = Vec::new();
        let said = crate::msgs::captured(|mut msgs| {
            urls = parse(&argv, None, &mut msgs, &mut |_, _| {}, |r, _| {
                let Ok(Parsed::Run(line)) = r else {
                    panic!("not parsed");
                };
                let op = &line.operations[0];
                op.nodes
                    .iter()
                    .map(|n| n.url.unwrap().to_vec())
                    .collect::<Vec<_>>()
            });
        });
        assert_eq!(urls.len(), 51);
        for (i, url) in urls.iter().take(50).enumerate() {
            assert_eq!(url, format!("http://h/{i}/{long}").as_bytes());
        }
        assert_eq!(urls[50], format!("'http://h/q/{long}").as_bytes());
        // Unwrapped: where the lines break depends on the file's name.
        let said = said.replace("\nWarning: ", "");
        let warning = format!(
            "{}:52 Option '--expand-url' uses argument with leading single quote. \
             It is probably a mistake. Consider double quotes.",
            file.name()
        );
        assert_eq!(said.matches(&warning).count(), 1, "{said}");
    }

    /// Room that cannot be had fails the entry that wanted it, the one a
    /// configuration file stepped back over.
    #[test]
    fn a_failed_room_names_the_entry_that_wanted_it() {
        let argv: Vec<OsString> = ["curl", "-K", "f"].iter().map(OsString::from).collect();
        let entry = |number, option| Entry {
            number,
            option,
            argument: None,
            warnings: &[],
        };
        let entries = [entry(3, &b"a"[..]), entry(7, b"b"), entry(9, b"c")];
        let said = crate::msgs::captured(|mut msgs| {
            let mut parser = Parser::new(&argv).unwrap();
            if let Some(Source::Args { word, .. }) = parser.sources.last_mut() {
                *word = 1;
            }
            parser
                .sources
                .try_push(Source::File {
                    name: b"f",
                    entries: &entries,
                    at: 1,
                    levels: 1,
                    curlrc: false,
                })
                .unwrap();
            assert!(matches!(
                parser.fail_to_grow(&mut msgs),
                Step::Done(Err(ParamError::NoMem))
            ));
        });
        assert!(
            said.starts_with("curl: f:7 config file option 'b' out of memory\n"),
            "{said}"
        );
    }

    /// A variable set again is noted when a trace was asked for before
    /// it, as C's `notef` notes it then.
    #[test]
    fn notes_a_variable_set_again_when_tracing() {
        let said = |args: &[&str]| {
            let argv: Vec<OsString> = std::iter::once("curl")
                .chain(args.iter().copied())
                .map(OsString::from)
                .collect();
            crate::msgs::captured(|mut msgs| {
                assert!(parse_args(&argv, &mut msgs, &mut |_, _| {}).is_ok());
            })
        };
        let set_twice = ["--variable", "a=1", "--variable", "a=2", "x"];
        let mut traced = vec!["-v"];
        traced.extend(set_twice);
        assert_eq!(said(&traced), "Note: Overwriting variable 'a'\n");
        assert_eq!(said(&set_twice), "");
        let mut late = set_twice.to_vec();
        late.push("-v");
        assert_eq!(said(&late), "");
    }

    /// A file of the test's own, removed after it.
    struct TempFile(std::path::PathBuf);

    impl TempFile {
        fn new(name: &str, content: &[u8]) -> TempFile {
            let path =
                std::env::temp_dir().join(format!("curl-parse-{}-{name}", std::process::id()));
            std::fs::write(&path, content).unwrap();
            TempFile(path)
        }

        fn name(&self) -> &str {
            self.0.to_str().unwrap()
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            std::fs::remove_file(&self.0).unwrap();
        }
    }

    /// `@file` reads the data from the file; `--data-urlencode` escapes
    /// it after its name, `name@file` read and `name=text` as it is.
    #[test]
    fn reads_data_from_files() {
        let file = TempFile::new("data", b"a b&c");
        let post = |args: &[&str]| {
            let post = line(args).operations[0].post.clone().unwrap();
            String::from_utf8(post).unwrap()
        };
        let at = format!("@{}", file.name());
        assert_eq!(post(&["x", "-d", &at]), "a b&c");
        assert_eq!(post(&["x", "--data-binary", &at]), "a b&c");
        assert_eq!(post(&["x", "--data-urlencode", &at]), "a+b%26c");
        let named = format!("n{at}");
        assert_eq!(post(&["x", "--data-urlencode", &named]), "n=a+b%26c");
        assert_eq!(post(&["x", "--data-urlencode", "n=a b@c"]), "n=a+b%40c");
        assert_eq!(post(&["x", "--data-urlencode", "=a@b"]), "a%40b");
        assert_eq!(
            run(&["x", "-d", "@/nonexistent/x"]),
            Err(ParamError::ReadError)
        );
    }

    /// `-w @file` takes the file's text; an empty file is no format.
    #[test]
    fn reads_a_format_from_a_file() {
        let format = TempFile::new("format", b"%{url}\n");
        let empty = TempFile::new("empty", b"");
        let read = |file: &TempFile| {
            let at = format!("@{}", file.name());
            line(&["x", "-w", &at]).operations[0]
                .write_out
                .as_ref()
                .map(|f| f.bytes().to_vec())
        };
        assert_eq!(read(&format), Some(b"%{url}".to_vec()));
        assert_eq!(read(&empty), None);
    }
}
