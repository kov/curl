//! What each option does, as the option handlers of
//! `src/tool_getparam.c` (`opt_none`, `opt_bool`, `opt_string` and the
//! rest) do it.
//!
//! Options are implemented one by one. Every other option is named in the
//! one arm that records it as not implemented, so the match stays
//! exhaustive: a new option in the table does not compile until it is
//! placed, and a command line using an unimplemented option is refused
//! rather than run without it.

use curl_alloc::TryVec;
use curl_core::version::Protocol;

use super::protocols::{self, Protocols};
use super::table::Opt;
use super::{ParamError, Spec, number};
use crate::msgs::Messages;
use crate::write_out;

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
}

/// What parsing does after an option.
pub(crate) enum Flow<'a> {
    Continue,
    /// `--next`: the options after it are for a new set of transfers.
    NextOperation,
    /// Stop and show something instead of running transfers.
    Request(Request<'a>),
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
    /// `--write-out`.
    pub(crate) write_out: Option<&'a [u8]>,
}

impl<'a> Operation<'a> {
    /// The URLs given.
    pub(crate) fn url_count(&self) -> usize {
        self.nodes.iter().filter(|n| n.url.is_some()).count()
    }

    /// The first node `taken` says is free of what is being set, or a new
    /// one (`add_url`, `parse_output` and `parse_upload_file` each look
    /// for theirs).
    fn free_node(
        &mut self,
        taken: impl Fn(&Node<'a>) -> bool,
    ) -> Result<&mut Node<'a>, ParamError> {
        let at = match self.nodes.iter().position(|n| !taken(n)) {
            Some(at) => at,
            None => {
                self.nodes.try_push(Node::default())?;
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
}

/// What a URL uploads.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum Upload<'a> {
    #[default]
    Unset,
    /// `--upload-file ""`: nothing, as if not set.
    Nothing,
    /// `--upload-file`: this file.
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
}

/// Where a transfer resumes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Resume {
    /// At this byte.
    At(u64),
    /// Where the output file ends: `--continue-at -`.
    FromOutput,
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
            options_in_word: 0,
        })
    }

    fn current(&mut self) -> &mut Operation<'a> {
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
pub(crate) fn apply<'a>(
    line: &mut CommandLine<'a>,
    msgs: &mut Messages,
    spec: &'static Spec,
    value: Value<'a>,
) -> Result<Flow<'a>, ParamError> {
    match spec.opt {
        Opt::Url => {
            let url = value.text();
            if url.first() == Some(&b'@') {
                // A file of URLs.
                line.not_implemented(spec, "--");
                return Ok(Flow::Continue);
            }
            if url.is_empty() {
                return Err(ParamError::BlankString);
            }
            if url.iter().any(|&b| b == b'{' || b == b'[') {
                // C expands these as a pattern unless `--globoff`.
                line.feature_not_implemented("URL globbing");
            }
            let op = line.current();
            op.free_node(|n| n.url.is_some())?.url = Some(url);
            if op.url_count() > 1 && (op.etag_save.is_some() || op.etag_compare.is_some()) {
                return Err(etag_single_url(msgs));
            }
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
                if file == b"-" || file == b"." {
                    line.feature_not_implemented("uploading standard input");
                } else if file.iter().any(|&b| b == b'{' || b == b'[') {
                    line.feature_not_implemented("upload file globbing");
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
            // `--range` is not implemented, so it is never set here.
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
        Opt::RemoveOnError => {
            let on = value.toggle();
            let op = line.current();
            if on && op.resume.is_some() {
                return Err(exclusive_with_resume(msgs, b"--remove-on-error"));
            }
            op.remove_on_error = on;
            if on {
                line.not_implemented(spec, "--");
            }
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
            if !on {
                line.not_implemented(spec, "--no-");
            }
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
        Opt::RemoteTime => line.current().remote_time = value.toggle(),
        Opt::SkipExisting => line.current().skip_existing = value.toggle(),
        Opt::WriteOut => {
            let format = value.text();
            if format.first() == Some(&b'@') {
                line.feature_not_implemented("reading --write-out from a file");
            } else if let Some(missing) = write_out::unimplemented(format) {
                line.feature_not_implemented(missing);
            }
            line.current().write_out = Some(format);
        }
        Opt::ProgressMeter => line.global.no_progress = !value.toggle(),
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
        Opt::TestEvent => line.not_implemented(spec, "--"),
        Opt::AbstractUnixSocket
        | Opt::Alpn
        | Opt::AltSvc
        | Opt::Anyauth
        | Opt::Append
        | Opt::AwsSigv4
        | Opt::Basic
        | Opt::Buffer
        | Opt::CaNative
        | Opt::Cacert
        | Opt::Capath
        | Opt::Cert
        | Opt::CertStatus
        | Opt::CertType
        | Opt::Ciphers
        | Opt::Compressed
        | Opt::CompressedSsh
        | Opt::Config
        | Opt::ConnectTimeout
        | Opt::ConnectTo
        | Opt::Cookie
        | Opt::CookieJar
        | Opt::CreateDirs
        | Opt::CreateFileMode
        | Opt::Crlf
        | Opt::Crlfile
        | Opt::Curves
        | Opt::Data
        | Opt::DataAscii
        | Opt::DataBinary
        | Opt::DataRaw
        | Opt::DataUrlencode
        | Opt::Delegation
        | Opt::Digest
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
        | Opt::DumpHeader
        | Opt::Ech
        | Opt::EgdFile
        | Opt::Engine
        | Opt::Eprt
        | Opt::Epsv
        | Opt::Expect100Timeout
        | Opt::Fail
        | Opt::FailEarly
        | Opt::FailWithBody
        | Opt::FalseStart
        | Opt::Follow
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
        | Opt::Get
        | Opt::Globoff
        | Opt::HappyEyeballsTimeoutMs
        | Opt::HaproxyClientip
        | Opt::HaproxyProtocol
        | Opt::Head
        | Opt::Header
        | Opt::Hostpubmd5
        | Opt::Hostpubsha256
        | Opt::Hsts
        | Opt::Http09
        | Opt::Http10
        | Opt::Http11
        | Opt::Http2
        | Opt::Http2PriorKnowledge
        | Opt::Http3
        | Opt::Http3Only
        | Opt::HttpsigAlgorithm
        | Opt::HttpsigHeaders
        | Opt::HttpsigKey
        | Opt::HttpsigKeyid
        | Opt::IgnoreContentLength
        | Opt::Insecure
        | Opt::Interface
        | Opt::IpTos
        | Opt::IpfsGateway
        | Opt::Ipv4
        | Opt::Ipv6
        | Opt::Json
        | Opt::JunkSessionCookies
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
        | Opt::Location
        | Opt::LocationTrusted
        | Opt::LoginOptions
        | Opt::MailAuth
        | Opt::MailFrom
        | Opt::MailRcpt
        | Opt::MailRcptAllowfails
        | Opt::MaxFilesize
        | Opt::MaxRedirs
        | Opt::MaxTime
        | Opt::Metalink
        | Opt::Mptcp
        | Opt::Negotiate
        | Opt::Netrc
        | Opt::NetrcFile
        | Opt::NetrcOptional
        | Opt::Noproxy
        | Opt::Npn
        | Opt::Ntlm
        | Opt::NtlmWb
        | Opt::Oauth2Bearer
        | Opt::OutputDir
        | Opt::Parallel
        | Opt::ParallelImmediate
        | Opt::ParallelMax
        | Opt::ParallelHost
        | Opt::Pass
        | Opt::PathAsIs
        | Opt::Pinnedpubkey
        | Opt::Post301
        | Opt::Post302
        | Opt::Post303
        | Opt::Preproxy
        | Opt::ProgressBar
        | Opt::Proxy
        | Opt::ProxyAnyauth
        | Opt::ProxyBasic
        | Opt::ProxyCaNative
        | Opt::ProxyCacert
        | Opt::ProxyCapath
        | Opt::ProxyCert
        | Opt::ProxyCertType
        | Opt::ProxyCiphers
        | Opt::ProxyCrlfile
        | Opt::ProxyDigest
        | Opt::ProxyHeader
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
        | Opt::ProxyUser
        | Opt::Proxy10
        | Opt::Proxytunnel
        | Opt::Pubkey
        | Opt::Quote
        | Opt::RandomFile
        | Opt::Range
        | Opt::Rate
        | Opt::Raw
        | Opt::Referer
        | Opt::RemoteHeaderName
        | Opt::RemoteName
        | Opt::RemoteNameAll
        | Opt::Request
        | Opt::RequestTarget
        | Opt::Resolve
        | Opt::Retry
        | Opt::RetryAllErrors
        | Opt::RetryConnrefused
        | Opt::RetryDelay
        | Opt::RetryMaxTime
        | Opt::SaslAuthzid
        | Opt::SaslIr
        | Opt::ServiceName
        | Opt::Sessionid
        | Opt::SignatureAlgorithms
        | Opt::Socks4
        | Opt::Socks4a
        | Opt::Socks5
        | Opt::Socks5Basic
        | Opt::Socks5Gssapi
        | Opt::Socks5GssapiNec
        | Opt::Socks5GssapiService
        | Opt::Socks5Hostname
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
        | Opt::Stderr
        | Opt::StyledOutput
        | Opt::SuppressConnectHeaders
        | Opt::TcpFastopen
        | Opt::TcpNodelay
        | Opt::TelnetOption
        | Opt::TftpBlksize
        | Opt::TftpNoOptions
        | Opt::TimeCond
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
        | Opt::TrEncoding
        | Opt::TraceConfig
        | Opt::TraceIds
        | Opt::UnixSocket
        | Opt::UploadFlags
        | Opt::UrlQuery
        | Opt::UseAscii
        | Opt::User
        | Opt::UserAgent
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
