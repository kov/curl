//! What each option does, as the option handlers of
//! `src/tool_getparam.c` (`opt_none`, `opt_bool`, `opt_string` and the
//! rest) do it.
//!
//! Options are implemented one by one. Every other option is named in the
//! one arm that records it as not implemented, so the match stays
//! exhaustive: a new option in the table does not compile until it is
//! placed, and a command line using an unimplemented option is refused
//! rather than run without it.

use std::borrow::Cow;
use std::os::unix::ffi::OsStrExt as _;

use curl_alloc::TryVec;
use curl_core::options::{AuthMethods, Condition, Follow, PostRedir, ProxyType, TimeCondition};
use curl_core::version::Protocol;

use super::protocols::{self, Protocols};
use super::table::Opt;
use super::{ParamError, Spec, number};
use crate::msgs::Messages;
use crate::slurp::{As, ReadFailed};
use crate::write_out;

/// The longest `--url-query` joined, less one (`MAX_QUERY_LEN`).
const MAX_QUERY_LEN: usize = 100_000;

/// An option's argument, read according to its kind.
#[allow(
    dead_code,
    reason = "numbers are read once numeric options are implemented"
)]
#[derive(Clone, Copy, Debug)]
pub(crate) enum Value<'a> {
    /// An option that takes nothing.
    Switch,
    /// A boolean option: false when given as `--no-...`.
    Toggle(bool),
    /// A string or file name, as given.
    Text(&'a [u8]),
    /// Seconds, in milliseconds.
    Millis(u64),
    /// A whole number.
    Number(u64),
}

impl<'a> Value<'a> {
    fn toggle(self) -> bool {
        match self {
            Value::Toggle(on) => on,
            other => unreachable!("a boolean option got {other:?}"),
        }
    }

    fn text(self) -> &'a [u8] {
        match self {
            Value::Text(text) => text,
            other => unreachable!("a string option got {other:?}"),
        }
    }

    fn millis(self) -> u64 {
        match self {
            Value::Millis(ms) => ms,
            other => unreachable!("an option of seconds got {other:?}"),
        }
    }

    fn number(self) -> u64 {
        match self {
            Value::Number(n) => n,
            other => unreachable!("a numeric option got {other:?}"),
        }
    }
}

/// What parsing does after an option.
pub(crate) enum Flow<'a> {
    Continue,
    /// `--next`: the options after it are for a new set of transfers.
    NextOperation,
    /// Stop and show something instead of running transfers.
    Request(Request<'a>),
    /// `--config`: read the options in this file next.
    Config(&'a [u8]),
    /// `--url @file`: read URLs from this file next, one a line.
    Urls(&'a [u8]),
}

/// What the command line asked to be shown.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Request<'a> {
    Version,
    Manual,
    /// `--help`, with the category or option asked about.
    Help(Option<&'a [u8]>),
    /// `--dump-ca-embed`.
    CaEmbed,
}

/// The transfers one part of the command line asks for: the whole of it,
/// or the part between two `--next`.
#[derive(Debug, Default)]
pub(crate) struct Operation<'a> {
    /// Each URL with its output and upload, in the order given.
    pub(crate) nodes: Vec<Node<'a>>,
    /// `--continue-at`.
    pub(crate) resume: Option<Resume>,
    /// `--range`, as given, or with a dash added after a lone number.
    pub(crate) range: Option<Vec<u8>>,
    /// `--clobber` and `--no-clobber`.
    pub(crate) clobber: Clobber,
    /// `--remove-on-error`.
    pub(crate) remove_on_error: bool,
    /// `--etag-save`.
    pub(crate) etag_save: Option<&'a [u8]>,
    /// `--etag-compare`.
    pub(crate) etag_compare: Option<&'a [u8]>,
    /// `--proto`: the protocols allowed, if limited.
    pub(crate) protocols: Option<Protocols>,
    /// `--proto-redir`: the protocols a redirect may go to, if set.
    pub(crate) redirect_protocols: Option<Protocols>,
    /// `--proto-default`.
    pub(crate) default_protocol: Option<Protocol>,
    /// `--include` and `--show-headers`: header lines go to the output.
    pub(crate) show_headers: bool,
    /// `--remote-time`.
    pub(crate) remote_time: bool,
    /// `--skip-existing`.
    pub(crate) skip_existing: bool,
    /// `--remote-header-name`: a file `--remote-name` names takes the name
    /// the response gives.
    pub(crate) remote_header_name: bool,
    /// `--create-dirs`: the directories an output file is in are made.
    pub(crate) create_dirs: bool,
    /// `--remote-name-all`: each URL given after it saves to its own name
    /// unless told otherwise.
    pub(crate) remote_name_all: bool,
    /// `--output-dir`: where a file output is written.
    pub(crate) output_dir: Option<&'a [u8]>,
    /// `--write-out`.
    pub(crate) write_out: Option<write_out::Format<'a>>,
    /// `--header`, in the order given.
    pub(crate) headers: Vec<&'a [u8]>,
    /// `--proxy-header`, in the order given.
    pub(crate) proxy_headers: Vec<&'a [u8]>,
    /// `--resolve`, in the order given.
    pub(crate) resolve: Vec<&'a [u8]>,
    /// `--connect-to`, in the order given.
    pub(crate) connect_to: Vec<&'a [u8]>,
    /// `--user-agent`.
    pub(crate) user_agent: Option<&'a [u8]>,
    /// `-u`: `user:password`, or a user alone until its password is
    /// asked for.
    pub(crate) user: Option<Cow<'a, [u8]>>,
    /// `--oauth2-bearer`.
    pub(crate) bearer: Option<&'a [u8]>,
    /// `--netrc`: the file is required.
    pub(crate) netrc: bool,
    /// `--netrc-optional`.
    pub(crate) netrc_optional: bool,
    /// `--netrc-file`, which requires it unless `--netrc-optional`.
    pub(crate) netrc_file: Option<&'a [u8]>,
    /// The methods to authenticate with; none for the library's default
    /// (C's `authtype`).
    pub(crate) auth: AuthMethods,
    /// `--request`.
    pub(crate) custom_request: Option<&'a [u8]>,
    /// `--referer`, without its `;auto`.
    pub(crate) referer: Option<&'a [u8]>,
    /// `--referer` ending in `;auto`: a redirect sends the URL it came
    /// from, which only matters with `--location` (not implemented).
    pub(crate) auto_referer: bool,
    /// `--cookie` strings, in the order given.
    pub(crate) cookies: Vec<&'a [u8]>,
    /// `--cookie` files, in the order given.
    pub(crate) cookie_files: Vec<&'a [u8]>,
    /// `--cookie-jar`.
    pub(crate) cookie_jar: Option<&'a [u8]>,
    /// `--proxy` and `--proxy1.0`; empty for none.
    pub(crate) proxy: Option<&'a [u8]>,
    /// What `--proxy1.0` makes the proxy.
    pub(crate) proxy_kind: ProxyType,
    /// `--noproxy`.
    pub(crate) noproxy: Option<&'a [u8]>,
    /// `--preproxy`.
    pub(crate) preproxy: Option<&'a [u8]>,
    /// `--proxytunnel`.
    pub(crate) proxytunnel: bool,
    /// `--haproxy-protocol`.
    pub(crate) haproxy_protocol: bool,
    /// `--haproxy-clientip`.
    pub(crate) haproxy_clientip: Option<&'a [u8]>,
    /// `--suppress-connect-headers`.
    pub(crate) suppress_connect_headers: bool,
    /// `--path-as-is`.
    pub(crate) path_as_is: bool,
    /// `--proxy-user`, as `-u`.
    pub(crate) proxy_user: Option<Cow<'a, [u8]>>,
    /// `--proxy-anyauth`.
    pub(crate) proxy_anyauth: bool,
    /// `--proxy-basic`.
    pub(crate) proxy_basic: bool,
    /// `--proxy-digest`.
    pub(crate) proxy_digest: bool,
    /// `--junk-session-cookies`.
    pub(crate) cookie_session: bool,
    /// `--http1.0` and `--http1.1`.
    pub(crate) http_version: Option<HttpVersion>,
    /// `--http0.9`.
    pub(crate) http09: bool,
    /// `--dump-header`: a file, `-` for standard output, `%` for standard
    /// error.
    pub(crate) dump_header: Option<&'a [u8]>,
    /// `--raw`.
    pub(crate) raw: bool,
    /// `--compressed`.
    pub(crate) compressed: bool,
    /// `--tr-encoding`.
    pub(crate) tr_encoding: bool,
    /// `--time-cond`, unless its time could not be read.
    pub(crate) time_cond: Option<TimeCondition>,
    /// `--happy-eyeballs-timeout-ms`, if given.
    pub(crate) happy_eyeballs_ms: Option<u64>,
    /// `--ipv4` or `--ipv6`, whichever came last.
    pub(crate) ip_version: Option<IpVersion>,
    /// `--ignore-content-length`.
    pub(crate) ignore_content_length: bool,
    /// `--max-filesize`, in bytes; 0 is no limit.
    pub(crate) max_filesize: u64,
    /// `--max-time`, in milliseconds; 0 is no limit.
    pub(crate) timeout_ms: u64,
    /// `--connect-timeout`, in milliseconds; 0 is the library's default.
    pub(crate) connect_timeout_ms: u64,
    /// `--expect100-timeout`, in milliseconds; 0 is the library's default.
    pub(crate) expect100_timeout_ms: u64,
    /// `--retry`: how many times a transfer that failed for a passing
    /// reason is tried again.
    pub(crate) retry: u64,
    /// `--retry-delay`, in milliseconds; 0 doubles the wait each time.
    pub(crate) retry_delay_ms: u64,
    /// `--retry-max-time`, in milliseconds; 0 is no limit.
    pub(crate) retry_max_time_ms: u64,
    /// `--retry-all-errors`: any failure is tried again.
    pub(crate) retry_all_errors: bool,
    /// `--location` and `--follow`.
    pub(crate) follow: Follow,
    /// `--location-trusted`.
    pub(crate) unrestricted_auth: bool,
    /// `--max-redirs`; -1 is no limit, and none the tool's 50.
    pub(crate) max_redirs: Option<i64>,
    /// `--post301`, `--post302` and `--post303`.
    pub(crate) post_redirect: PostRedir,
    /// `--globoff`: URLs and uploads are taken as they are.
    pub(crate) globoff: bool,
    /// `--head`: no body is asked for.
    pub(crate) no_body: bool,
    /// The HTTP method the options chose (C's `config->httpreq`).
    pub(crate) method: Method,
    /// `--fail` or `--fail-with-body`, the last one said.
    pub(crate) fail: Fail,
    /// `--no-buffer`: output is written as it comes.
    pub(crate) no_buffer: bool,
    /// What `--data` and its kin give, joined: the body a POST sends (C's
    /// `postdata`), empty if they gave nothing.
    pub(crate) post: Option<Vec<u8>>,
    /// `--json` was given: the request is typed and accepts JSON.
    pub(crate) json: bool,
    /// `--get`: what `--data` gives goes in the URL's query, asked for
    /// with a GET (C's `use_httpget`).
    pub(crate) get: bool,
    /// What `--url-query` gives, joined by `&`: added to each URL's query
    /// unless `--get` adds the data there.
    pub(crate) url_query: Option<Vec<u8>>,
    /// `--request-target`.
    pub(crate) request_target: Option<&'a [u8]>,
    /// `--ipfs-gateway`.
    pub(crate) ipfs_gateway: Option<&'a [u8]>,
}

/// The addresses `--ipv4` and `--ipv6` limit a name to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IpVersion {
    V4,
    V6,
}

/// The HTTP version `--http1.0` and `--http1.1` ask for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HttpVersion {
    Http10,
    Http11,
}

/// The HTTP method the options chose (C's `HttpReq`); only one may be.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum Method {
    #[default]
    Unset,
    Get,
    Head,
    Post,
    Put,
}

impl Method {
    /// How C names the method, with the option that asks for it.
    fn name(self) -> &'static [u8] {
        match self {
            Method::Unset => b"",
            Method::Get => b"GET (-G, --get)",
            Method::Head => b"HEAD (-I, --head)",
            Method::Post => b"POST (-d, --data)",
            Method::Put => b"PUT (-T, --upload-file)",
        }
    }

    /// The method the request is sent with when none is asked for
    /// (`customrequest_helper`'s list).
    pub(crate) fn implied(self) -> &'static [u8] {
        match self {
            Method::Unset | Method::Get => b"GET",
            Method::Head => b"HEAD",
            Method::Post => b"POST",
            Method::Put => b"PUT",
        }
    }

    /// Choose `wanted`, unless another method was chosen already
    /// (`SetHTTPrequest`): then warn and refuse.
    pub(crate) fn choose(&mut self, wanted: Method, msgs: &Messages) -> Result<(), ()> {
        if *self == Method::Unset || *self == wanted {
            *self = wanted;
            return Ok(());
        }
        msgs.warn(&[
            b"You can only select one HTTP request method! You asked for both ",
            wanted.name(),
            b" and ",
            self.name(),
            b".",
        ]);
        Err(())
    }
}

impl<'a> Operation<'a> {
    /// The URLs given.
    pub(crate) fn url_count(&self) -> usize {
        self.nodes.iter().filter(|n| n.url.is_some()).count()
    }

    /// The first node `taken` says is free of what is being set, or a new
    /// one (`add_url`, `parse_output` and `parse_upload_file` each look
    /// for theirs).
    /// Give the next node without a URL `url` (`add_url`); one `from_file`
    /// is named as `--remote-name` names it and never globbed.
    pub(crate) fn add_url(
        &mut self,
        url: &'a [u8],
        from_file: bool,
        msgs: &Messages,
    ) -> Result<(), ParamError> {
        if url.is_empty() {
            return Err(ParamError::BlankString);
        }
        let node = self.free_node(|n| n.url.is_some())?;
        node.url = Some(url);
        if from_file {
            node.remote = true;
            node.literal = true;
        }
        if self.url_count() > 1 && (self.etag_save.is_some() || self.etag_compare.is_some()) {
            return Err(etag_single_url(msgs));
        }
        Ok(())
    }

    fn free_node(
        &mut self,
        taken: impl Fn(&Node<'a>) -> bool,
    ) -> Result<&mut Node<'a>, ParamError> {
        let at = match self.nodes.iter().position(|n| !taken(n)) {
            Some(at) => at,
            None => {
                self.nodes.try_push(Node {
                    remote: self.remote_name_all,
                    ..Node::default()
                })?;
                self.nodes.len() - 1
            }
        };
        Ok(&mut self.nodes[at])
    }
}

/// A URL and where its output goes and its upload comes from (C's
/// `struct getout`). Options set them in turn: a URL, `--output` and
/// `--upload-file` each fill the first node without one.
#[derive(Debug, Default)]
pub(crate) struct Node<'a> {
    pub(crate) url: Option<&'a [u8]>,
    pub(crate) output: Output<'a>,
    pub(crate) upload: Upload<'a>,
    /// The output is the URL's own file name if not set: the node was
    /// made after `--remote-name-all` (`useremote`, from `new_getout`), or
    /// its URL read from a file.
    pub(crate) remote: bool,
    /// The URL is taken as it is, never globbed: it was read from a file
    /// (`noglob`).
    pub(crate) literal: bool,
}

/// Where a URL's output goes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum Output<'a> {
    /// Not said: standard output.
    #[default]
    Unset,
    /// `--output`; `-` is standard output.
    File(&'a [u8]),
    /// `--out-null`: nowhere.
    Null,
    /// `--remote-name`: a file named as the URL's path ends.
    Remote,
    /// `--no-remote-name` after `--remote-name-all`: standard output.
    Stdout,
}

/// What a URL uploads.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum Upload<'a> {
    #[default]
    Unset,
    /// `--upload-file ""`: nothing, as if not set.
    Nothing,
    /// `--upload-file`: this file, or standard input for `-`.
    File(&'a [u8]),
}

/// How transfers are traced (C's `global->tracetype`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum Trace {
    #[default]
    None,
    /// `--verbose`: lines marked by what they are.
    Plain,
    /// `--trace-ascii`: dumps of the text.
    Ascii,
    /// `--trace`: dumps in hexadecimal and text.
    Binary,
}

/// What the whole command line sets, for every operation (C's `global`).
#[derive(Debug, Default)]
pub(crate) struct Global<'a> {
    pub(crate) trace: Trace,
    /// Where the trace goes: a file, `-` for standard output, `%` for
    /// standard error.
    pub(crate) trace_dump: Option<&'a [u8]>,
    /// `--trace-time`.
    pub(crate) trace_time: bool,
    /// How many `-v` in one word.
    verbosity: u8,
    /// `--no-progress-meter`.
    pub(crate) no_progress: bool,
    /// `--progress-bar`: the bar in place of the meter.
    pub(crate) progress_bar: bool,
    /// `--test-event`: transfers are driven by the multi's events (the
    /// debug build's).
    #[cfg(feature = "debug-hooks")]
    pub(crate) test_event: bool,
}

/// Where a transfer resumes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Resume {
    /// At this byte.
    At(u64),
    /// Where the output file ends: `--continue-at -`.
    FromOutput,
}

/// What an HTTP error response makes of the transfer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum Fail {
    /// Nothing: it succeeds.
    #[default]
    Off,
    /// `--fail`: the library fails it, and no body is written.
    WithoutBody,
    /// `--fail-with-body`: the body is written, and the tool fails it.
    WithBody,
}

/// Whether an output file that exists is overwritten.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum Clobber {
    /// As the output options decide.
    #[default]
    Default,
    /// `--clobber`.
    Always,
    /// `--no-clobber`.
    Never,
}

/// The error the options exclusive of `--continue-at` report.
fn exclusive_with_resume(msgs: &Messages, other: &[u8]) -> ParamError {
    msgs.error(&[b"--continue-at is mutually exclusive with ", other]);
    ParamError::BadUse
}

/// `--range`'s value (`parse_range`): a lone number gets the dash a
/// range needs; any other is taken as given, with a warning for a
/// character that is no digit, dash or comma after a leading `N-`.
fn range(msgs: &Messages, given: &[u8]) -> Result<Vec<u8>, ParamError> {
    let copy = |s: &[u8]| {
        let mut v = Vec::new();
        v.try_extend_from_slice(s)
            .map(|()| v)
            .map_err(|_| ParamError::NoMem)
    };
    let digits = given.iter().take_while(|b| b.is_ascii_digit()).count();
    // The number as `curlx_str_number` reads it: one past what an offset
    // holds is none, and the text is checked from its start.
    let number = (digits > 0)
        .then(|| {
            std::str::from_utf8(&given[..digits])
                .ok()?
                .parse::<i64>()
                .ok()
        })
        .flatten();
    let checked = match number {
        Some(n) => match given[digits..].strip_prefix(b"-") {
            Some(rest) => rest,
            None => {
                msgs.warn(&[
                    b"A specified range MUST include at least one dash (-). Appending one for you",
                ]);
                // As C prints it: without the leading zeros given.
                let mut digits = [0u8; 20];
                let mut at = digits.len();
                let mut n = n;
                loop {
                    at -= 1;
                    digits[at] = b'0' + (n % 10) as u8;
                    n /= 10;
                    if n == 0 {
                        break;
                    }
                }
                let mut text = copy(&digits[at..])?;
                text.try_push(b'-').map_err(|_| ParamError::NoMem)?;
                return Ok(text);
            }
        },
        None => given,
    };
    if checked
        .iter()
        .any(|&b| !b.is_ascii_digit() && b != b'-' && b != b',')
    {
        msgs.warn(&[
            b"Invalid character is found in given range. A specified range MUST have only digits in 'start'-'stop'. The server's response to this request is uncertain.",
        ]);
    }
    if given.is_empty() {
        return Err(ParamError::BlankString);
    }
    copy(given)
}

/// The error of an etag option on more than one URL.
fn etag_single_url(msgs: &Messages) -> ParamError {
    msgs.error(&[b"The etag options only work on a single URL"]);
    ParamError::BadUse
}

/// What the command line asks for.
#[derive(Debug)]
pub(crate) struct CommandLine<'a> {
    /// Never empty: the last is the one options apply to.
    pub(crate) operations: Vec<Operation<'a>>,
    pub(crate) global: Global<'a>,
    /// The first thing asked for that is not implemented yet.
    pub(crate) unimplemented: Option<Unimplemented>,
    /// The default configuration file was read without a failure.
    pub(crate) read_curlrc: bool,
    /// Options read so far in the current word, as C's `verbose_nopts`:
    /// `-vv` counts twice, `-v -v` once.
    pub(crate) options_in_word: usize,
}

/// Something the command line asks for that is not implemented yet.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Unimplemented {
    /// An option, with the prefix it was used with.
    Option(&'static Spec, &'static str),
    /// A use of an option that is implemented otherwise.
    Feature(&'static str),
}

impl<'a> CommandLine<'a> {
    pub(crate) fn new() -> Result<Self, ParamError> {
        let mut operations = Vec::new();
        operations.try_push(Operation::default())?;
        Ok(CommandLine {
            operations,
            global: Global::default(),
            unimplemented: None,
            read_curlrc: false,
            options_in_word: 0,
        })
    }

    pub(crate) fn current(&mut self) -> &mut Operation<'a> {
        self.operations
            .last_mut()
            .expect("there is always an operation")
    }

    /// Start the operation after `--next`, whose first node needs a URL
    /// before it.
    pub(crate) fn next_operation(&mut self, msgs: &Messages) -> Result<(), ParamError> {
        if self.current().nodes.first().and_then(|n| n.url).is_none() {
            msgs.error(&[b"missing URL before --next"]);
            return Err(ParamError::BadUse);
        }
        self.operations.try_push(Operation::default())?;
        Ok(())
    }

    /// Record that `spec` was used and is not implemented.
    pub(crate) fn not_implemented(&mut self, spec: &'static Spec, prefix: &'static str) {
        self.unimplemented
            .get_or_insert(Unimplemented::Option(spec, prefix));
    }

    /// Record that `feature` was asked for and is not implemented.
    fn feature_not_implemented(&mut self, feature: &'static str) {
        self.unimplemented
            .get_or_insert(Unimplemented::Feature(feature));
    }
}

impl From<curl_alloc::OutOfMemory> for ParamError {
    fn from(_: curl_alloc::OutOfMemory) -> Self {
        ParamError::NoMem
    }
}

/// Apply option `spec` with `value` to `line`.
/// `--time-cond`'s argument: `+` or nothing for modified since, `-` for
/// not modified since, `=` for the `Last-Modified` header, then a date or
/// a file whose modification time to take (`parse_time_cond`). Neither
/// is a warning, and no condition.
fn time_cond(arg: &[u8], msgs: &Messages) -> Option<TimeCondition> {
    let (when, rest) = match arg.first() {
        Some(b'-') => (Condition::UnmodifiedSince, &arg[1..]),
        Some(b'=') => (Condition::LastModified, &arg[1..]),
        Some(b'+') => (Condition::ModifiedSince, &arg[1..]),
        _ => (Condition::ModifiedSince, arg),
    };
    // `curl_getdate`, which gives one second before 1970 as 0.
    let time = match curl_core::date::parse(rest) {
        Ok(-1) => Some(0),
        Ok(t) => Some(t),
        Err(_) => {
            let name = rest.split(|&b| b == 0).next().unwrap_or_default();
            match std::fs::metadata(std::ffi::OsStr::from_bytes(name)) {
                Ok(meta) => Some(std::os::unix::fs::MetadataExt::mtime(&meta)),
                Err(e) => {
                    let why = crate::os_message(&e);
                    msgs.warn(&[b"Failed to get filetime: ", why.as_bytes()]);
                    None
                }
            }
        }
    };
    let Some(time) = time else {
        msgs.warn(&[
            b"Illegal date format for -z, --time-cond (and not a filename). Disabling time \
              condition. See curl_getdate(3) for valid date syntax.",
        ]);
        return None;
    };
    Some(TimeCondition { when, time })
}

pub(crate) fn apply<'a>(
    line: &mut CommandLine<'a>,
    msgs: &mut Messages,
    spec: &'static Spec,
    value: Value<'a>,
) -> Result<Flow<'a>, ParamError> {
    match spec.opt {
        Opt::Url => {
            let url = value.text();
            if let Some(file) = url.strip_prefix(b"@") {
                return Ok(Flow::Urls(file));
            }
            line.current().add_url(url, false, msgs)?;
        }
        Opt::Output => {
            let file = value.text();
            if file.is_empty() {
                return Err(ParamError::BlankString);
            }
            let op = line.current();
            op.free_node(|n| n.output != Output::Unset)?.output = Output::File(file);
        }
        Opt::OutNull => {
            let op = line.current();
            op.free_node(|n| n.output != Output::Unset)?.output = Output::Null;
        }
        Opt::UploadFile => {
            let file = value.text();
            let upload = if file.is_empty() {
                Upload::Nothing
            } else {
                if file == b"." {
                    line.feature_not_implemented("uploading standard input without blocking");
                }
                Upload::File(file)
            };
            let op = line.current();
            op.free_node(|n| n.upload != Upload::Unset)?.upload = upload;
        }
        Opt::EtagSave | Opt::EtagCompare => {
            let op = line.current();
            if op.url_count() > 1 {
                return Err(etag_single_url(msgs));
            }
            let file = Some(value.text()).filter(|f| !f.is_empty());
            let file = file.ok_or(ParamError::BlankString)?;
            if spec.opt == Opt::EtagSave {
                op.etag_save = Some(file);
            } else {
                op.etag_compare = Some(file);
            }
            line.not_implemented(spec, "--");
        }
        Opt::ContinueAt => {
            let op = line.current();
            if op.range.is_some() {
                return Err(exclusive_with_resume(msgs, b"--range"));
            }
            if op.remove_on_error {
                return Err(exclusive_with_resume(msgs, b"--remove-on-error"));
            }
            if op.clobber == Clobber::Never {
                return Err(exclusive_with_resume(msgs, b"--no-clobber"));
            }
            op.resume = Some(match value.text() {
                b"-" => Resume::FromOutput,
                at => Resume::At(number::offset(at)?),
            });
        }
        Opt::Range => {
            if line.current().resume.is_some() {
                return Err(exclusive_with_resume(msgs, b"--range"));
            }
            let range = range(msgs, value.text())?;
            line.current().range = Some(range);
        }
        Opt::RemoveOnError => {
            let on = value.toggle();
            let op = line.current();
            if on && op.resume.is_some() {
                return Err(exclusive_with_resume(msgs, b"--remove-on-error"));
            }
            op.remove_on_error = on;
        }
        Opt::Clobber => {
            let on = value.toggle();
            let op = line.current();
            if !on && op.resume.is_some() {
                return Err(exclusive_with_resume(msgs, b"--no-clobber"));
            }
            // `--clobber` differs from the default only for a name the
            // server gives, which `--remote-header-name` asks for.
            op.clobber = if on { Clobber::Always } else { Clobber::Never };
        }
        Opt::Proto => {
            let set = protocols::parse(Protocols::all(), value.text(), msgs)?;
            line.current().protocols = Some(set);
            line.not_implemented(spec, "--");
        }
        Opt::ProtoRedir => {
            let set = protocols::parse(Protocols::redirect_default(), value.text(), msgs)?;
            line.current().redirect_protocols = Some(set);
            line.not_implemented(spec, "--");
        }
        Opt::ProtoDefault => {
            let name = value.text();
            if name.is_empty() {
                return Err(ParamError::BlankString);
            }
            let protocol = protocols::token(name).ok_or(ParamError::LibcurlUnsupportedProtocol)?;
            line.current().default_protocol = Some(protocol);
        }
        Opt::Include | Opt::ShowHeaders => line.current().show_headers = value.toggle(),
        Opt::Head => {
            let on = value.toggle();
            let op = line.current();
            op.no_body = on;
            op.show_headers = on;
            let wanted = if on { Method::Head } else { Method::Get };
            op.method
                .choose(wanted, msgs)
                .map_err(|()| ParamError::BadUse)?;
        }
        Opt::Header | Opt::ProxyHeader => {
            let header = value.text();
            let proxy = spec.opt == Opt::ProxyHeader;
            if header.first() == Some(&b'@') {
                line.feature_not_implemented("reading headers from a file");
            } else if !header.iter().any(|&b| b == b':' || b == b';') {
                let kind: &[u8] = if proxy { b"proxy" } else { b"HTTP" };
                msgs.warn(&[
                    b"The provided ",
                    kind,
                    b" header '",
                    header,
                    b"' does not look like a header?",
                ]);
            }
            let op = line.current();
            if proxy {
                op.proxy_headers.try_push(header)?;
            } else {
                op.headers.try_push(header)?;
            }
        }
        Opt::Cookie => {
            // A string with `=` is cookies to send, else a file to read.
            let given = value.text();
            let op = line.current();
            if given.contains(&b'=') {
                op.cookies.try_push(given)?;
            } else {
                op.cookie_files.try_push(given)?;
            }
        }
        Opt::CookieJar => {
            let op = line.current();
            op.cookie_jar = None;
            let jar = value.text();
            if jar.is_empty() {
                return Err(ParamError::BlankString);
            }
            op.cookie_jar = Some(jar);
        }
        Opt::JunkSessionCookies => line.current().cookie_session = value.toggle(),
        Opt::Proxy => {
            let op = line.current();
            op.proxy = Some(value.text());
            if !matches!(op.proxy_kind, ProxyType::Https2 | ProxyType::Https3) {
                op.proxy_kind = ProxyType::Http;
            }
        }
        Opt::Proxy10 | Opt::Socks4 | Opt::Socks4a | Opt::Socks5 | Opt::Socks5Hostname => {
            let op = line.current();
            op.proxy = None;
            let proxy = value.text();
            if proxy.is_empty() {
                return Err(ParamError::BlankString);
            }
            op.proxy = Some(proxy);
            op.proxy_kind = match spec.opt {
                Opt::Socks4 => ProxyType::Socks4,
                Opt::Socks4a => ProxyType::Socks4a,
                Opt::Socks5 => ProxyType::Socks5,
                Opt::Socks5Hostname => ProxyType::Socks5Hostname,
                _ => ProxyType::Http10,
            };
        }
        Opt::Noproxy => line.current().noproxy = Some(value.text()),
        Opt::Preproxy => {
            let url = value.text();
            if url.is_empty() {
                return Err(ParamError::BlankString);
            }
            line.current().preproxy = Some(url);
        }
        Opt::Proxytunnel => line.current().proxytunnel = value.toggle(),
        Opt::HaproxyProtocol => line.current().haproxy_protocol = value.toggle(),
        Opt::HaproxyClientip => {
            let ip = value.text();
            if ip.is_empty() {
                return Err(ParamError::BlankString);
            }
            line.current().haproxy_clientip = Some(ip);
        }
        Opt::SuppressConnectHeaders => line.current().suppress_connect_headers = value.toggle(),
        Opt::PathAsIs => line.current().path_as_is = value.toggle(),
        Opt::ProxyUser => line.current().proxy_user = Some(Cow::Borrowed(value.text())),
        Opt::ProxyAnyauth => line.current().proxy_anyauth = value.toggle(),
        Opt::ProxyBasic => line.current().proxy_basic = value.toggle(),
        Opt::ProxyDigest => line.current().proxy_digest = value.toggle(),
        Opt::Resolve => line.current().resolve.try_push(value.text())?,
        Opt::ConnectTo => line.current().connect_to.try_push(value.text())?,
        Opt::UserAgent => line.current().user_agent = Some(value.text()),
        Opt::User => line.current().user = Some(Cow::Borrowed(value.text())),
        Opt::Anyauth => line.current().auth = AuthMethods::ANY,
        Opt::Netrc => line.current().netrc = value.toggle(),
        Opt::NetrcOptional => line.current().netrc_optional = value.toggle(),
        Opt::NetrcFile => {
            let file = value.text();
            // `existingfile`.
            if std::fs::metadata(std::ffi::OsStr::from_bytes(file)).is_err() {
                msgs.error(&[
                    b"The file '",
                    file,
                    b"' provided to --netrc-file does not exist",
                ]);
                return Err(ParamError::BadUse);
            }
            line.current().netrc_file = Some(file);
        }
        Opt::Oauth2Bearer => {
            let text = value.text();
            if text.is_empty() {
                return Err(ParamError::BlankString);
            }
            let op = line.current();
            op.bearer = Some(text);
            op.auth = op.auth | AuthMethods::BEARER;
        }
        Opt::Basic => {
            let op = line.current();
            op.auth = if value.toggle() {
                op.auth | AuthMethods::BASIC
            } else {
                op.auth & !AuthMethods::BASIC
            };
        }
        Opt::Digest => {
            let op = line.current();
            op.auth = if value.toggle() {
                op.auth | AuthMethods::DIGEST
            } else {
                op.auth & !AuthMethods::DIGEST
            };
        }
        Opt::OutputDir => {
            let text = value.text();
            if text.is_empty() {
                return Err(ParamError::BlankString);
            }
            line.current().output_dir = Some(text);
        }
        Opt::Request => {
            let text = value.text();
            if text.is_empty() {
                return Err(ParamError::BlankString);
            }
            line.current().custom_request = Some(text);
        }
        Opt::Referer => {
            let text = value.text();
            let op = line.current();
            let given = match text.strip_suffix(b";auto") {
                Some(given) => {
                    op.auto_referer = true;
                    given
                }
                None => {
                    op.auto_referer = false;
                    text
                }
            };
            op.referer = (!given.is_empty()).then_some(given);
        }
        Opt::Http10 | Opt::Http11 => {
            let version = if spec.opt == Opt::Http10 {
                HttpVersion::Http10
            } else {
                HttpVersion::Http11
            };
            let op = line.current();
            if op.http_version.is_some_and(|v| v != version) {
                msgs.warn(&[b"Overrides previous HTTP version option"]);
            }
            op.http_version = Some(version);
        }
        Opt::Http09 => line.current().http09 = value.toggle(),
        Opt::DumpHeader => {
            let file = value.text();
            if file.is_empty() {
                return Err(ParamError::BlankString);
            }
            line.current().dump_header = Some(file);
        }
        Opt::Raw => line.current().raw = value.toggle(),
        Opt::Compressed => line.current().compressed = value.toggle(),
        Opt::TrEncoding => line.current().tr_encoding = value.toggle(),
        Opt::TimeCond => line.current().time_cond = time_cond(value.text(), msgs),
        Opt::HappyEyeballsTimeoutMs => line.current().happy_eyeballs_ms = Some(value.number()),
        Opt::Ipv4 => line.current().ip_version = Some(IpVersion::V4),
        Opt::Ipv6 => line.current().ip_version = Some(IpVersion::V6),
        Opt::IgnoreContentLength => line.current().ignore_content_length = value.toggle(),
        Opt::MaxFilesize => line.current().max_filesize = number::size(value.text())?,
        Opt::MaxTime => line.current().timeout_ms = value.millis(),
        Opt::ConnectTimeout => line.current().connect_timeout_ms = value.millis(),
        Opt::Expect100Timeout => line.current().expect100_timeout_ms = value.millis(),
        Opt::Retry => line.current().retry = value.number(),
        // As C keeps it, in 32 bits.
        Opt::RetryDelay => line.current().retry_delay_ms = value.millis().min(i32::MAX as u64),
        Opt::RetryMaxTime => line.current().retry_max_time_ms = value.millis(),
        Opt::RetryAllErrors => line.current().retry_all_errors = value.toggle(),
        Opt::Location | Opt::LocationTrusted => {
            let on = value.toggle();
            let op = line.current();
            if spec.opt == Opt::LocationTrusted {
                op.unrestricted_auth = on;
            }
            if op.follow == Follow::ObeyCode {
                msgs.warn(&[b"--location overrides --follow"]);
            }
            op.follow = if on { Follow::All } else { Follow::No };
        }
        Opt::Follow => {
            let on = value.toggle();
            let op = line.current();
            if op.follow == Follow::All {
                msgs.warn(&[b"--follow overrides --location"]);
            }
            op.follow = if on { Follow::ObeyCode } else { Follow::No };
        }
        Opt::Post301 => line.current().post_redirect.post301 = value.toggle(),
        Opt::Post302 => line.current().post_redirect.post302 = value.toggle(),
        Opt::Post303 => line.current().post_redirect.post303 = value.toggle(),
        Opt::MaxRedirs => {
            let n = number::signed(value.text())?;
            if n < -1 {
                return Err(ParamError::BadNumeric);
            }
            line.current().max_redirs = Some(n);
        }
        Opt::Globoff => line.current().globoff = value.toggle(),
        Opt::Get => line.current().get = value.toggle(),
        Opt::IpfsGateway => {
            let gateway = value.text();
            if gateway.is_empty() {
                return Err(ParamError::BlankString);
            }
            line.current().ipfs_gateway = Some(gateway);
        }
        Opt::RequestTarget => {
            let target = value.text();
            if target.is_empty() {
                return Err(ParamError::BlankString);
            }
            line.current().request_target = Some(target);
        }
        Opt::UrlQuery => {
            // `+` takes the rest as it is; anything else is encoded as
            // `--data-urlencode` encodes (`url_query`).
            let text = value.text();
            let query = match text.strip_prefix(b"+") {
                Some(raw) => {
                    let mut query = Vec::new();
                    query.try_extend_from_slice(raw)?;
                    query
                }
                None => url_encoded(text, msgs)?,
            };
            match &mut line.current().url_query {
                // C joins them in a buffer of at most 100000 bytes, its
                // terminating zero counted (`MAX_QUERY_LEN`).
                Some(joined) if joined.len() + 1 + query.len() >= MAX_QUERY_LEN => {
                    return Err(ParamError::NoMem);
                }
                Some(joined) => {
                    joined.try_push(b'&')?;
                    joined.try_extend_from_slice(&query)?;
                }
                none => *none = Some(query),
            }
        }
        Opt::Fail | Opt::FailWithBody => {
            let (this, other, deselects) = if spec.opt == Opt::Fail {
                (
                    Fail::WithoutBody,
                    Fail::WithBody,
                    &b"--fail deselects --fail-with-body here"[..],
                )
            } else {
                (
                    Fail::WithBody,
                    Fail::WithoutBody,
                    &b"--fail-with-body deselects --fail here"[..],
                )
            };
            let on = value.toggle();
            let op = line.current();
            if on && op.fail == other {
                msgs.warn(&[deselects]);
            }
            op.fail = if on { this } else { Fail::Off };
        }
        Opt::Buffer => line.current().no_buffer = !value.toggle(),
        Opt::Stderr => crate::output::redirect_stderr(value.text(), msgs),
        Opt::Data
        | Opt::DataAscii
        | Opt::DataBinary
        | Opt::DataRaw
        | Opt::DataUrlencode
        | Opt::Json => {
            let data = data(spec.opt, value.text(), msgs)?;
            let op = line.current();
            op.json |= spec.opt == Opt::Json;
            let post = op.post.get_or_insert_with(Vec::new);
            // `--json` adds no separator.
            if !post.is_empty() && spec.opt != Opt::Json {
                post.try_push(b'&')?;
            }
            post.try_extend_from_slice(&data)?;
        }
        // `--no-remote-name` sets an output only to undo
        // `--remote-name-all` (`parse_remote_name`).
        Opt::RemoteName => {
            let on = value.toggle();
            let op = line.current();
            if on || op.remote_name_all {
                let output = if on { Output::Remote } else { Output::Stdout };
                op.free_node(|n| n.output != Output::Unset)?.output = output;
            }
        }
        Opt::RemoteNameAll => line.current().remote_name_all = value.toggle(),
        Opt::RemoteTime => line.current().remote_time = value.toggle(),
        Opt::SkipExisting => line.current().skip_existing = value.toggle(),
        Opt::CreateDirs => line.current().create_dirs = value.toggle(),
        Opt::Config => return Ok(Flow::Config(value.text())),
        Opt::RemoteHeaderName => line.current().remote_header_name = value.toggle(),
        Opt::WriteOut => {
            let format = match value.text().strip_prefix(b"@") {
                // A file's text, or standard input's, with no line ends
                // (`parse_writeout`, `file2string`).
                Some(name) => {
                    let shown = if name == b"-" { &b"<stdin>"[..] } else { name };
                    match write_out::Format::read(name) {
                        Ok(format) if format.bytes().is_empty() => {
                            msgs.warn(&[b"Failed to read ", shown]);
                            None
                        }
                        Ok(format) => Some(format),
                        Err(crate::slurp::ReadFailed::OutOfMemory) => {
                            return Err(ParamError::NoMem);
                        }
                        Err(crate::slurp::ReadFailed::Open) => {
                            msgs.error(&[b"Failed to open ", shown]);
                            return Err(ParamError::ReadError);
                        }
                        Err(crate::slurp::ReadFailed::Read) => return Err(ParamError::ReadError),
                    }
                }
                None => Some(write_out::Format::Given(value.text())),
            };
            if let Some(missing) = format
                .as_ref()
                .and_then(|f| write_out::unimplemented(f.bytes()))
            {
                line.feature_not_implemented(missing);
            }
            line.current().write_out = format;
        }
        Opt::ProgressMeter => line.global.no_progress = !value.toggle(),
        Opt::ProgressBar => line.global.progress_bar = value.toggle(),
        Opt::Verbose => verbose(line, msgs, value.toggle()),
        Opt::Trace | Opt::TraceAscii => {
            let file = value.text();
            if file.is_empty() {
                return Err(ParamError::BlankString);
            }
            let (trace, warning): (_, &[u8]) = if spec.opt == Opt::Trace {
                (
                    Trace::Binary,
                    b"--trace overrides an earlier trace/verbose option",
                )
            } else {
                (
                    Trace::Ascii,
                    b"--trace-ascii overrides an earlier trace/verbose option",
                )
            };
            let g = &mut line.global;
            g.trace_dump = Some(file);
            if g.trace != Trace::None && g.trace != trace {
                msgs.warn(&[warning]);
            }
            g.trace = trace;
        }
        Opt::TraceTime => line.global.trace_time = value.toggle(),
        Opt::Next => return Ok(Flow::NextOperation),
        Opt::Silent => msgs.silent = value.toggle(),
        Opt::ShowError => msgs.show_error = value.toggle(),
        // `--no-version` and `--no-manual` do nothing.
        Opt::Version if value.toggle() => return Ok(Flow::Request(Request::Version)),
        Opt::Manual if value.toggle() => return Ok(Flow::Request(Request::Manual)),
        Opt::Version | Opt::Manual => {}
        // Only `-hcategory` gets here, which C ignores.
        Opt::Help => {}
        Opt::DumpCaEmbed => return Ok(Flow::Request(Request::CaEmbed)),
        // Only meaningful first, where reading the configuration file
        // already took it into account.
        Opt::Disable => {}
        #[cfg(feature = "debug-hooks")]
        Opt::TestDuphandle => line.not_implemented(spec, "--"),
        #[cfg(feature = "debug-hooks")]
        Opt::TestEvent => line.global.test_event = value.toggle(),
        Opt::AbstractUnixSocket
        | Opt::Alpn
        | Opt::AltSvc
        | Opt::Append
        | Opt::AwsSigv4
        | Opt::CaNative
        | Opt::Cacert
        | Opt::Capath
        | Opt::Cert
        | Opt::CertStatus
        | Opt::CertType
        | Opt::Ciphers
        | Opt::CompressedSsh
        | Opt::CreateFileMode
        | Opt::Crlf
        | Opt::Crlfile
        | Opt::Curves
        | Opt::Delegation
        | Opt::DisableEprt
        | Opt::DisableEpsv
        | Opt::DisallowUsernameInUrl
        | Opt::DnsInterface
        | Opt::DnsIpv4Addr
        | Opt::DnsIpv6Addr
        | Opt::DnsServers
        | Opt::DohCertStatus
        | Opt::DohInsecure
        | Opt::DohUrl
        | Opt::Ech
        | Opt::EgdFile
        | Opt::Engine
        | Opt::Eprt
        | Opt::Epsv
        | Opt::FailEarly
        | Opt::FalseStart
        | Opt::Form
        | Opt::FormEscape
        | Opt::FormString
        | Opt::FtpAccount
        | Opt::FtpAlternativeToUser
        | Opt::FtpCreateDirs
        | Opt::FtpMethod
        | Opt::FtpPasv
        | Opt::FtpPort
        | Opt::FtpPret
        | Opt::FtpSkipPasvIp
        | Opt::FtpSsl
        | Opt::FtpSslCcc
        | Opt::FtpSslCccMode
        | Opt::FtpSslControl
        | Opt::FtpSslReqd
        | Opt::Hostpubmd5
        | Opt::Hostpubsha256
        | Opt::Hsts
        | Opt::Http2
        | Opt::Http2PriorKnowledge
        | Opt::Http3
        | Opt::Http3Only
        | Opt::HttpsigAlgorithm
        | Opt::HttpsigHeaders
        | Opt::HttpsigKey
        | Opt::HttpsigKeyid
        | Opt::Insecure
        | Opt::Interface
        | Opt::IpTos
        | Opt::Keepalive
        | Opt::KeepaliveCnt
        | Opt::KeepaliveTime
        | Opt::Key
        | Opt::KeyType
        | Opt::Knownhosts
        | Opt::Krb
        | Opt::Krb4
        | Opt::Libcurl
        | Opt::LimitRate
        | Opt::ListOnly
        | Opt::LocalPort
        | Opt::LoginOptions
        | Opt::MailAuth
        | Opt::MailFrom
        | Opt::MailRcpt
        | Opt::MailRcptAllowfails
        | Opt::Metalink
        | Opt::Mptcp
        | Opt::Negotiate
        | Opt::Npn
        | Opt::Ntlm
        | Opt::NtlmWb
        | Opt::Parallel
        | Opt::ParallelImmediate
        | Opt::ParallelMax
        | Opt::ParallelHost
        | Opt::Pass
        | Opt::Pinnedpubkey
        | Opt::ProxyCaNative
        | Opt::ProxyCacert
        | Opt::ProxyCapath
        | Opt::ProxyCert
        | Opt::ProxyCertType
        | Opt::ProxyCiphers
        | Opt::ProxyCrlfile
        | Opt::ProxyHttp2
        | Opt::ProxyHttp3
        | Opt::ProxyInsecure
        | Opt::ProxyKey
        | Opt::ProxyKeyType
        | Opt::ProxyNegotiate
        | Opt::ProxyNtlm
        | Opt::ProxyPass
        | Opt::ProxyPinnedpubkey
        | Opt::ProxyServiceName
        | Opt::ProxySslAllowBeast
        | Opt::ProxySslAutoClientCert
        | Opt::ProxyTls13Ciphers
        | Opt::ProxyTlsauthtype
        | Opt::ProxyTlspassword
        | Opt::ProxyTlsuser
        | Opt::ProxyTlsv1
        | Opt::Pubkey
        | Opt::Quote
        | Opt::RandomFile
        | Opt::Rate
        | Opt::RetryConnrefused
        | Opt::SaslAuthzid
        | Opt::SaslIr
        | Opt::ServiceName
        | Opt::Sessionid
        | Opt::SignatureAlgorithms
        | Opt::Socks5Basic
        | Opt::Socks5Gssapi
        | Opt::Socks5GssapiNec
        | Opt::Socks5GssapiService
        | Opt::SpeedLimit
        | Opt::SpeedTime
        | Opt::Ssl
        | Opt::SslAllowBeast
        | Opt::SslAutoClientCert
        | Opt::SslNoRevoke
        | Opt::SslReqd
        | Opt::SslRevokeBestEffort
        | Opt::SslSessions
        | Opt::Sslv2
        | Opt::Sslv3
        | Opt::StyledOutput
        | Opt::TcpFastopen
        | Opt::TcpNodelay
        | Opt::TelnetOption
        | Opt::TftpBlksize
        | Opt::TftpNoOptions
        | Opt::TlsEarlydata
        | Opt::TlsMax
        | Opt::Tls13Ciphers
        | Opt::Tlsauthtype
        | Opt::Tlspassword
        | Opt::Tlsuser
        | Opt::Tlsv1
        | Opt::Tlsv10
        | Opt::Tlsv11
        | Opt::Tlsv12
        | Opt::Tlsv13
        | Opt::TraceConfig
        | Opt::TraceIds
        | Opt::UnixSocket
        | Opt::UploadFlags
        | Opt::UseAscii
        | Opt::Variable
        | Opt::VlanPriority
        | Opt::Xattr => line.not_implemented(spec, "--"),
    }
    Ok(Flow::Continue)
}

/// `--verbose`, which counts: `-vv` in one word is more than `-v`, while
/// `-v -v` is `-v` (`parse_verbose`).
fn verbose(line: &mut CommandLine<'_>, msgs: &Messages, on: bool) {
    let first_in_word = line.options_in_word == 0;
    let g = &mut line.global;
    if !on {
        g.verbosity = 0;
        // As `set_trace_config("-all")`, which `--trace-config` (not
        // implemented) would otherwise have to come after.
        g.trace_time = false;
        g.trace = Trace::None;
        return;
    }
    if first_in_word {
        g.verbosity = 0;
        g.trace_time = false;
    }
    if g.verbosity > 0 {
        // Each further `-v` turns on more of libcurl's trace categories.
        line.feature_not_implemented("-vv");
        return;
    }
    g.verbosity = 1;
    g.trace_dump = Some(b"%");
    if g.trace != Trace::None && g.trace != Trace::Plain {
        msgs.warn(&[b"-v, --verbose overrides an earlier trace option"]);
    }
    g.trace = Trace::Plain;
}

/// What one of the `--data` options gives (`set_data`): its text, or the
/// file `@` names (`-` standard input) for all but `--data-raw`, read as
/// text but for `--data-binary` and `--json`; `--data-urlencode` encodes.
fn data(opt: Opt, text: &[u8], msgs: &Messages) -> Result<Vec<u8>, ParamError> {
    if opt == Opt::DataUrlencode {
        return url_encoded(text, msgs);
    }
    let mut data = Vec::new();
    match text.strip_prefix(b"@").filter(|_| opt != Opt::DataRaw) {
        Some(name) => {
            let how = if matches!(opt, Opt::DataBinary | Opt::Json) {
                As::Binary
            } else {
                As::Text
            };
            data = read_named(name, how, msgs)?;
        }
        None => data.try_extend_from_slice(text)?,
    }
    Ok(data)
}

/// `--data-urlencode`'s `[name]=content` or `[name]@file`, the content
/// escaped and its spaces made `+` (`data_urlencode`).
fn url_encoded(text: &[u8], msgs: &Messages) -> Result<Vec<u8>, ParamError> {
    let at = text
        .iter()
        .position(|&b| b == b'=')
        .or_else(|| text.iter().position(|&b| b == b'@'));
    let (name, content) = match at {
        Some(at) if text[at] == b'@' => {
            (&text[..at], read_named(&text[at + 1..], As::Binary, msgs)?)
        }
        Some(at) => {
            let mut content = Vec::new();
            content.try_extend_from_slice(&text[at + 1..])?;
            (&text[..at], content)
        }
        None => {
            let mut content = Vec::new();
            content.try_extend_from_slice(text)?;
            (&text[..0], content)
        }
    };
    let escaped = curl_core::url::escape(&content)?;
    let mut out = Vec::new();
    if !name.is_empty() {
        out.try_extend_from_slice(name)?;
        out.try_push(b'=')?;
    }
    let mut rest = &escaped[..];
    while !rest.is_empty() {
        if let Some(after) = rest.strip_prefix(b"%20") {
            out.try_push(b'+')?;
            rest = after;
        } else {
            out.try_push(rest[0])?;
            rest = &rest[1..];
        }
    }
    Ok(out)
}

/// The file `name` (`-` standard input), or C's error for one that does
/// not open.
fn read_named(name: &[u8], how: As, msgs: &Messages) -> Result<Vec<u8>, ParamError> {
    match crate::slurp::read(name, how) {
        Ok(data) => Ok(data),
        Err(ReadFailed::Open) => {
            msgs.error(&[b"Failed to open ", name]);
            Err(ParamError::ReadError)
        }
        Err(ReadFailed::Read) => Err(ParamError::ReadError),
        Err(ReadFailed::OutOfMemory) => Err(ParamError::NoMem),
    }
}
