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

use super::table::Opt;
use super::{ParamError, Spec};
use crate::msgs::Messages;

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
    pub(crate) urls: Vec<&'a [u8]>,
}

/// What the command line asks for.
#[derive(Debug)]
pub(crate) struct CommandLine<'a> {
    /// Never empty: the last is the one options apply to.
    pub(crate) operations: Vec<Operation<'a>>,
    /// The first option used that is not implemented yet, and the prefix
    /// it was used with.
    pub(crate) unimplemented: Option<(&'static Spec, &'static str)>,
}

impl<'a> CommandLine<'a> {
    pub(crate) fn new() -> Result<Self, ParamError> {
        let mut operations = Vec::new();
        operations.try_push(Operation::default())?;
        Ok(CommandLine {
            operations,
            unimplemented: None,
        })
    }

    fn current(&mut self) -> &mut Operation<'a> {
        self.operations
            .last_mut()
            .expect("there is always an operation")
    }

    /// Start the operation after `--next`, which needs a URL before it.
    pub(crate) fn next_operation(&mut self, msgs: &Messages) -> Result<(), ParamError> {
        if self.current().urls.is_empty() {
            msgs.error(&[b"missing URL before --next"]);
            return Err(ParamError::BadUse);
        }
        self.operations.try_push(Operation::default())?;
        Ok(())
    }

    /// Record that `spec` was used and is not implemented.
    pub(crate) fn not_implemented(&mut self, spec: &'static Spec, prefix: &'static str) {
        self.unimplemented.get_or_insert((spec, prefix));
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
            line.current().urls.try_push(url)?;
        }
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
        | Opt::Clobber
        | Opt::Compressed
        | Opt::CompressedSsh
        | Opt::Config
        | Opt::ConnectTimeout
        | Opt::ConnectTo
        | Opt::ContinueAt
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
        | Opt::EtagCompare
        | Opt::EtagSave
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
        | Opt::Include
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
        | Opt::OutNull
        | Opt::Output
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
        | Opt::ProgressMeter
        | Opt::Proto
        | Opt::ProtoDefault
        | Opt::ProtoRedir
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
        | Opt::RemoteTime
        | Opt::RemoveOnError
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
        | Opt::ShowHeaders
        | Opt::SignatureAlgorithms
        | Opt::SkipExisting
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
        | Opt::Trace
        | Opt::TraceAscii
        | Opt::TraceConfig
        | Opt::TraceIds
        | Opt::TraceTime
        | Opt::UnixSocket
        | Opt::UploadFile
        | Opt::UploadFlags
        | Opt::UrlQuery
        | Opt::UseAscii
        | Opt::User
        | Opt::UserAgent
        | Opt::Variable
        | Opt::Verbose
        | Opt::VlanPriority
        | Opt::WriteOut
        | Opt::Xattr => line.not_implemented(spec, "--"),
    }
    Ok(Flow::Continue)
}
