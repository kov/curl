//! A SOCKS proxy's handshake (`lib/socks.c`), sans-IO: the requests a
//! SOCKS4, SOCKS4a or SOCKS5 proxy is sent, made in turn, and what its
//! replies say. Whoever holds the connection to the proxy sends what
//! `to_send` gives and hands each reply to `take`, in C's words when it
//! is refused. SOCKS5's GSS-API method (RFC 1961, `lib/socks_gssapi.c`)
//! is states of the same handshake, in `gss`.

use std::fmt;
use std::net::{IpAddr, Ipv6Addr};

use curl_alloc::{OutOfMemory, TryVec as _};

use crate::gss::GssContext;
use crate::options::{IpVersion, ProxyType, Socks5Auth};

mod gss;
#[cfg(test)]
mod tests;

pub(crate) use gss::{Failed, GssError, GssLine, GssMethod};

/// What a SOCKS proxy's handshake failed at (`CURLproxycode`,
/// `CURLINFO_PROXY_ERROR`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyError {
    BadAddressType,
    BadVersion,
    Closed,
    Gssapi,
    GssapiPermsg,
    GssapiProtection,
    Identd,
    IdentdDiffer,
    LongHostname,
    LongPasswd,
    LongUser,
    NoAuth,
    RecvAddress,
    RecvAuth,
    RecvConnect,
    RecvReqack,
    ReplyAddressTypeNotSupported,
    ReplyCommandNotSupported,
    ReplyConnectionRefused,
    ReplyGeneralServerFailure,
    ReplyHostUnreachable,
    ReplyNetworkUnreachable,
    ReplyNotAllowed,
    ReplyTtlExpired,
    ReplyUnassigned,
    RequestFailed,
    ResolveHost,
    SendAuth,
    SendConnect,
    SendRequest,
    UnknownFail,
    UnknownMode,
    UserRejected,
}

/// The SOCKS versions, and who resolves the destination's name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Version {
    /// SOCKS4, the name resolved here, to an IPv4 address.
    V4,
    /// SOCKS4a, the name sent.
    V4a,
    /// SOCKS5, the name resolved here.
    V5,
    /// SOCKS5, the name sent.
    V5Hostname,
}

impl Version {
    pub(crate) fn of(kind: ProxyType) -> Option<Version> {
        match kind {
            ProxyType::Socks4 => Some(Version::V4),
            ProxyType::Socks4a => Some(Version::V4a),
            ProxyType::Socks5 => Some(Version::V5),
            ProxyType::Socks5Hostname => Some(Version::V5Hostname),
            ProxyType::Http
            | ProxyType::Http10
            | ProxyType::Https
            | ProxyType::Https2
            | ProxyType::Https3 => None,
        }
    }

    /// The destination's name is resolved here, not by the proxy
    /// (`resolve_local`).
    pub(crate) fn resolves_locally(self) -> bool {
        matches!(self, Version::V4 | Version::V5)
    }

    /// The families the destination's name is resolved in: SOCKS4 has
    /// IPv4 alone.
    pub(crate) fn ip(self, ip: IpVersion) -> IpVersion {
        match self {
            Version::V4 => IpVersion::V4,
            Version::V4a | Version::V5 | Version::V5Hostname => ip,
        }
    }
}

/// The destination, where the proxy is to connect.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Dest<'a> {
    /// The name, an address without brackets or a host (`dest->hostname`).
    pub(crate) name: &'a [u8],
    pub(crate) port: u16,
    /// What resolving the name here found, for a version that does.
    pub(crate) resolved: Resolved,
}

/// What resolving a destination's name here came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Resolved {
    /// It is not resolved here.
    Remote,
    /// The address to ask for, of the families the version takes.
    Address(IpAddr),
    /// Resolved, to no address of those families.
    NoAddress,
    /// The resolver could not resolve it.
    Failed,
}

impl Resolved {
    /// The address to ask a proxy of `version` for, of those `addrs`
    /// (`Curl_conn_dns_get_ai`): SOCKS4's first IPv4 one, SOCKS5's first
    /// IPv6 one where IPv4 is not insisted on, else its first IPv4 one.
    pub(crate) fn pick(version: Version, addrs: &[IpAddr], ip: IpVersion) -> Resolved {
        let first = |v6: bool| addrs.iter().copied().find(|a| a.is_ipv6() == v6);
        let picked = match version {
            Version::V4 => first(false),
            Version::V5 if ip != IpVersion::V4 => first(true).or_else(|| first(false)),
            Version::V5 => first(false),
            Version::V4a | Version::V5Hostname => return Resolved::Remote,
        };
        picked.map_or(Resolved::NoAddress, Resolved::Address)
    }
}

/// The user and password the proxy is given, and the service it is
/// authenticated as by GSS-API, empty for the default.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Creds<'a> {
    pub(crate) user: &'a [u8],
    pub(crate) password: &'a [u8],
    pub(crate) service: &'a [u8],
}

/// The credentials a handshake keeps.
#[derive(Debug)]
struct Kept {
    user: Vec<u8>,
    password: Vec<u8>,
    service: Vec<u8>,
}

/// A handshake under way.
#[derive(Debug)]
pub(crate) struct Handshake {
    version: Version,
    /// What is to be sent, and how much of it went.
    out: Vec<u8>,
    sent: usize,
    awaiting: Awaiting,
    /// The destination, for the requests and C's words.
    name: Vec<u8>,
    port: u16,
    resolved: Resolved,
    /// The user and password, unless SOCKS5's basic authentication is
    /// not allowed.
    creds: Option<Kept>,
    auth: Socks5Auth,
    /// The SOCKS5 proxy picked a method that authenticates
    /// (`socks5_authenticated`).
    authenticated: bool,
    /// SOCKS5's GSS-API method, where it is built in.
    gss: Option<GssMethod>,
    /// Its security context, from the method's pick until the protection
    /// is agreed on, kept after that only if some was granted.
    context: Option<Box<dyn GssContext>>,
    /// The protection the context can give, from its last step
    /// (`gss_ret_flags`).
    can: gss::Level,
    /// The protection the proxy granted (`socks5_gssapi_enctype`).
    granted: u8,
    /// What the GSS-API messages to send are, for C's words when sending
    /// them fails.
    framing: gss::Framing,
}

/// The reply the handshake waits for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Awaiting {
    /// SOCKS4's 8 bytes.
    Granted4,
    /// SOCKS5's method.
    Method,
    /// SOCKS5's answer to the user and password.
    Authenticated,
    /// SOCKS5's answer to the request, of a length its address type gives.
    Connected,
    /// Nothing yet: GSS-API was picked, and its context is to be made.
    GssStart,
    /// An RFC 1961 authentication message: its 4 bytes, then its token.
    GssToken,
    /// An RFC 1961 protection-level message, likewise.
    GssLevel,
    /// Nothing: the proxy connected to the destination.
    Done,
}

/// What a reply came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Took {
    /// At least this many bytes are needed before it can be read.
    Need(usize),
    /// It was read, from this many bytes: the next request is to send,
    /// or the handshake is done.
    Read(usize),
}

/// Why a handshake failed, said as C says it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SocksError {
    OutOfMemory,
    LongUser4,
    LongHostname4,
    NotIpv4(Vec<u8>),
    Unresolved(Vec<u8>, u16),
    Refused4 {
        code: u8,
        port: u16,
        ip: [u8; 4],
    },
    BadVersion4,
    LongHostname5,
    NoMethod,
    BadVersion5Method,
    NoAuthSelected,
    GssapiNotSupported,
    GssapiNotEnabled,
    BasicNotEnabled,
    NoneAcceptable,
    UnknownMode,
    LongUser5,
    LongPassword5,
    UserRejected(u8, u8),
    /// The GSS-API method failed.
    Gss(GssError),
    /// The proxy granted GSS-API protection, which is not implemented.
    GssProtection,
    NotResolved5(Vec<u8>),
    BadIpv6,
    BadVersion5,
    Refused5(Vec<u8>, u8),
    BadAddressType,
}

impl SocksError {
    /// The code `CURLINFO_PROXY_ERROR` gives for it.
    pub(crate) fn code(&self) -> Option<ProxyError> {
        Some(match self {
            SocksError::OutOfMemory => return None,
            SocksError::LongUser4 | SocksError::LongUser5 => ProxyError::LongUser,
            SocksError::LongHostname4 | SocksError::LongHostname5 => ProxyError::LongHostname,
            SocksError::NotIpv4(_) | SocksError::Unresolved(..) | SocksError::NotResolved5(_) => {
                ProxyError::ResolveHost
            }
            SocksError::Refused4 { code, .. } => match code {
                91 => ProxyError::RequestFailed,
                92 => ProxyError::Identd,
                93 => ProxyError::IdentdDiffer,
                _ => ProxyError::UnknownFail,
            },
            SocksError::BadVersion4 | SocksError::BadVersion5Method | SocksError::BadVersion5 => {
                ProxyError::BadVersion
            }
            SocksError::NoMethod
            | SocksError::NoAuthSelected
            | SocksError::BasicNotEnabled
            | SocksError::NoneAcceptable => ProxyError::NoAuth,
            SocksError::GssapiNotSupported | SocksError::GssapiNotEnabled => {
                ProxyError::GssapiPermsg
            }
            SocksError::UnknownMode => ProxyError::UnknownMode,
            SocksError::LongPassword5 => ProxyError::LongPasswd,
            SocksError::UserRejected(..) => ProxyError::UserRejected,
            SocksError::Gss(_) => ProxyError::Gssapi,
            SocksError::GssProtection => ProxyError::GssapiProtection,
            SocksError::BadIpv6 | SocksError::BadAddressType => ProxyError::BadAddressType,
            SocksError::Refused5(_, code) => match code {
                1 => ProxyError::ReplyGeneralServerFailure,
                2 => ProxyError::ReplyNotAllowed,
                3 => ProxyError::ReplyNetworkUnreachable,
                4 => ProxyError::ReplyHostUnreachable,
                5 => ProxyError::ReplyConnectionRefused,
                6 => ProxyError::ReplyTtlExpired,
                7 => ProxyError::ReplyCommandNotSupported,
                8 => ProxyError::ReplyAddressTypeNotSupported,
                _ => ProxyError::ReplyUnassigned,
            },
        })
    }

    /// What C says of it, if anything (`failf`); a GSS-API failure's
    /// lines are its own.
    pub(crate) fn said(&self) -> Option<Said<'_>> {
        match self {
            SocksError::OutOfMemory | SocksError::BadIpv6 | SocksError::Gss(_) => None,
            _ => Some(Said(self)),
        }
    }
}

impl From<OutOfMemory> for SocksError {
    fn from(_: OutOfMemory) -> SocksError {
        SocksError::OutOfMemory
    }
}

/// An error, as C says it.
pub(crate) struct Said<'e>(&'e SocksError);

impl fmt::Display for Said<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            SocksError::LongUser4 => f.write_str("Too long SOCKS proxy username"),
            SocksError::LongHostname4 => f.write_str("SOCKS4: too long hostname"),
            SocksError::NotIpv4(name) => {
                write!(f, "SOCKS4 connection to {} not supported", Text(name))
            }
            // C gives the resolve's CURLcode, which is the one for a host
            // not resolved.
            SocksError::Unresolved(name, port) => write!(
                f,
                "error 6 resolving SOCKS destination {}:{port}",
                Text(name)
            ),
            SocksError::Refused4 { code, port, ip } => {
                let [a, b, c, d] = ip;
                write!(
                    f,
                    "[SOCKS] cannot complete SOCKS4 connection to {a}.{b}.{c}.{d}:{port}. ({code}), "
                )?;
                f.write_str(match code {
                    91 => "request rejected or failed.",
                    92 => {
                        "request rejected because SOCKS server cannot connect to identd on \
                         the client."
                    }
                    93 => {
                        "request rejected because the client program and identd report \
                         different user-ids."
                    }
                    _ => "Unknown.",
                })
            }
            SocksError::BadVersion4 => {
                f.write_str("SOCKS4 reply has wrong version, version should be 0.")
            }
            SocksError::LongHostname5 => f.write_str(
                "SOCKS5: the destination hostname is too long to be resolved remotely by the \
                 proxy.",
            ),
            SocksError::NoMethod => {
                f.write_str("SOCKS5: no acceptable authentication method is available.")
            }
            SocksError::BadVersion5Method => {
                f.write_str("Received invalid version in initial SOCKS5 response.")
            }
            SocksError::NoAuthSelected => f.write_str("SOCKS5 proxy selected no authentication."),
            SocksError::GssapiNotSupported => {
                f.write_str("SOCKS5 GSSAPI per-message authentication is not supported.")
            }
            SocksError::GssapiNotEnabled => {
                f.write_str("SOCKS5 GSSAPI per-message authentication is not enabled.")
            }
            SocksError::BasicNotEnabled => {
                f.write_str("BASIC authentication proposed but not enabled.")
            }
            SocksError::NoneAcceptable => f.write_str("No authentication method was acceptable."),
            SocksError::UnknownMode => {
                f.write_str("Unknown SOCKS5 mode attempted to be used by server.")
            }
            SocksError::LongUser5 => f.write_str("Excessive username length for proxy auth"),
            SocksError::LongPassword5 => f.write_str("Excessive password length for proxy auth"),
            SocksError::UserRejected(a, b) => {
                write!(f, "User was rejected by the SOCKS5 server ({a} {b}).")
            }
            SocksError::NotResolved5(name) => {
                write!(
                    f,
                    "Failed to resolve \"{}\" for SOCKS5 connect.",
                    Text(name)
                )
            }
            SocksError::BadVersion5 => {
                f.write_str("SOCKS5 reply has wrong version, version should be 5.")
            }
            SocksError::Refused5(name, code) => write!(
                f,
                "cannot complete SOCKS5 connection to {}. ({code})",
                Text(name)
            ),
            SocksError::BadAddressType => f.write_str("SOCKS5 reply has wrong address type."),
            SocksError::GssProtection => {
                f.write_str("SOCKS5 GSS-API protection not yet implemented.")
            }
            SocksError::OutOfMemory | SocksError::BadIpv6 | SocksError::Gss(_) => Ok(()),
        }
    }
}

/// Bytes shown as text, as C's `%s` shows them.
struct Text<'a>(&'a [u8]);

impl fmt::Display for Text<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for chunk in self.0.utf8_chunks() {
            f.write_str(chunk.valid())?;
            if !chunk.invalid().is_empty() {
                f.write_str("\u{FFFD}")?;
            }
        }
        Ok(())
    }
}

/// The longest user, password and host name a request carries: a byte
/// says each length in SOCKS5, and SOCKS4's are held to it.
const MAX_FIELD: usize = 255;

impl Handshake {
    /// A handshake with a proxy of `version` for `dest`: its first
    /// request made, SOCKS4's whole (`socks4_connect`), SOCKS5's offer of
    /// methods (`socks5_req0_init`), GSS-API's among them where `gss`
    /// builds it in.
    pub(crate) fn new(
        version: Version,
        dest: Dest<'_>,
        creds: Option<Creds<'_>>,
        auth: Socks5Auth,
        gss: Option<GssMethod>,
    ) -> Result<Handshake, SocksError> {
        let mut name = Vec::new();
        name.try_extend_from_slice(dest.name)?;
        let creds = match creds {
            // SOCKS5 gives none unless basic authentication is allowed,
            // and with them goes the service GSS-API names (C unlinks
            // `sx->creds`, which `Curl_SOCKS5_gssapi_negotiate` reads).
            Some(_) if matches!(version, Version::V5 | Version::V5Hostname) && !auth.basic => None,
            Some(c) => {
                let mut kept = Kept {
                    user: Vec::new(),
                    password: Vec::new(),
                    service: Vec::new(),
                };
                kept.user.try_extend_from_slice(c.user)?;
                kept.password.try_extend_from_slice(c.password)?;
                kept.service.try_extend_from_slice(c.service)?;
                Some(kept)
            }
            None => None,
        };
        let mut handshake = Handshake {
            version,
            out: Vec::new(),
            sent: 0,
            awaiting: Awaiting::Done,
            name,
            port: dest.port,
            resolved: dest.resolved,
            creds,
            auth,
            authenticated: false,
            gss,
            context: None,
            can: gss::Level::None,
            granted: 0,
            framing: gss::Framing::None,
        };
        match version {
            Version::V4 | Version::V4a => handshake.request4()?,
            Version::V5 | Version::V5Hostname => handshake.offer()?,
        }
        Ok(handshake)
    }

    /// What is to be sent next.
    pub(crate) fn to_send(&self) -> &[u8] {
        &self.out[self.sent..]
    }

    /// `n` bytes of it went.
    pub(crate) fn sent(&mut self, n: usize) {
        assert!(
            n <= self.out.len() - self.sent,
            "no more is sent than was made"
        );
        self.sent += n;
    }

    /// The proxy connected to the destination.
    pub(crate) fn done(&self) -> bool {
        self.awaiting == Awaiting::Done
    }

    /// The SOCKS5 proxy picked a method that authenticates.
    pub(crate) fn authenticated(&self) -> bool {
        self.authenticated
    }

    /// How many bytes the reply awaited needs, at least, to be read: the
    /// count to give up on when the proxy closes before it.
    pub(crate) fn wants(&self) -> usize {
        match self.awaiting {
            Awaiting::Granted4 | Awaiting::Connected => 8,
            Awaiting::Method | Awaiting::Authenticated => 2,
            Awaiting::GssToken | Awaiting::GssLevel => 4,
            Awaiting::Done | Awaiting::GssStart => 0,
        }
    }

    /// Read the reply awaited from what was received, all sent first.
    #[cfg(test)]
    pub(crate) fn take(&mut self, input: &[u8]) -> Result<Took, SocksError> {
        self.take_saying(input, &mut |_| {})
    }

    /// `take`, with what C says on the way handed to `say`.
    pub(crate) fn take_saying(
        &mut self,
        input: &[u8],
        say: &mut dyn FnMut(GssLine<'_>),
    ) -> Result<Took, SocksError> {
        assert!(
            self.to_send().is_empty(),
            "the request went before its reply"
        );
        if self.awaiting == Awaiting::Connected && self.granted != 0 {
            // The request went; what follows would need the protection
            // granted (`SOCKS5_ST_REQ1_SEND`).
            return Err(SocksError::GssProtection);
        }
        let wants = self.wants();
        if input.len() < wants {
            return Ok(Took::Need(wants));
        }
        let used = match self.awaiting {
            Awaiting::Granted4 => self.granted4(input)?,
            Awaiting::Method => self.method(input)?,
            Awaiting::Authenticated => self.authenticated_reply(input)?,
            Awaiting::Connected => match self.connected(input)? {
                Some(used) => used,
                None => return Ok(Took::Need(connected_len(input)?)),
            },
            Awaiting::GssToken => match self.gss_token(input, say)? {
                Some(used) => used,
                None => return Ok(Took::Need(gss::framed_len(input))),
            },
            Awaiting::GssLevel => match self.gss_level(input, say)? {
                Some(used) => used,
                None => return Ok(Took::Need(gss::framed_len(input))),
            },
            Awaiting::GssStart => unreachable!("the context is made first"),
            Awaiting::Done => unreachable!("nothing is awaited"),
        };
        Ok(Took::Read(used))
    }

    fn queue(&mut self, parts: &[&[u8]]) -> Result<(), OutOfMemory> {
        self.out.clear();
        self.sent = 0;
        for part in parts {
            self.out.try_extend_from_slice(part)?;
        }
        Ok(())
    }

    /// SOCKS4's request, the destination's address or, for SOCKS4a, the
    /// invalid one and its name after the user.
    fn request4(&mut self) -> Result<(), SocksError> {
        let [hi, lo] = self.port.to_be_bytes();
        let head = [4, 1, hi, lo];
        let user = self.creds.as_ref().map_or(&[][..], |c| &c.user[..]);
        let addr = if self.version == Version::V4a {
            if self.name.len() + 1 > MAX_FIELD {
                return Err(SocksError::LongHostname4);
            }
            [0, 0, 0, 1]
        } else {
            match self.resolved {
                Resolved::Address(IpAddr::V4(v4)) => v4.octets(),
                Resolved::Failed => {
                    return Err(SocksError::Unresolved(take(&mut self.name), self.port));
                }
                Resolved::Address(IpAddr::V6(_)) | Resolved::NoAddress | Resolved::Remote => {
                    return Err(SocksError::NotIpv4(take(&mut self.name)));
                }
            }
        };
        if user.len() > MAX_FIELD {
            return Err(SocksError::LongUser4);
        }
        let mut out = Vec::new();
        for part in [&head[..], &addr, user, &[0]] {
            out.try_extend_from_slice(part)?;
        }
        if self.version == Version::V4a {
            out.try_extend_from_slice(&self.name)?;
            out.try_push(0)?;
        }
        self.out = out;
        self.sent = 0;
        self.awaiting = Awaiting::Granted4;
        Ok(())
    }

    /// SOCKS4's 8 bytes: granted, or why not (`socks4_check_resp`).
    fn granted4(&mut self, r: &[u8]) -> Result<usize, SocksError> {
        if r[0] != 0 {
            return Err(SocksError::BadVersion4);
        }
        if r[1] != 90 {
            return Err(SocksError::Refused4 {
                code: r[1],
                port: u16::from_be_bytes([r[2], r[3]]),
                ip: [r[4], r[5], r[6], r[7]],
            });
        }
        self.awaiting = Awaiting::Done;
        Ok(8)
    }

    /// SOCKS5's offer of methods: none unless only authenticating is
    /// allowed, and the user and password if there are any.
    fn offer(&mut self) -> Result<(), SocksError> {
        if self.version == Version::V5Hostname && self.name.len() > MAX_FIELD {
            return Err(SocksError::LongHostname5);
        }
        let mut methods = [0u8; 3];
        let mut n = 0;
        if !self.auth.only {
            methods[n] = 0;
            n += 1;
        }
        if self.auth.gssapi && self.gss.is_some() {
            methods[n] = 1;
            n += 1;
        }
        if self.creds.is_some() {
            methods[n] = 2;
            n += 1;
        }
        if n == 0 {
            return Err(SocksError::NoMethod);
        }
        let count = [5, n as u8];
        self.queue(&[&count, &methods[..n]])?;
        self.awaiting = Awaiting::Method;
        Ok(())
    }

    /// SOCKS5's pick of method (`socks5_check_resp0`).
    fn method(&mut self, r: &[u8]) -> Result<usize, SocksError> {
        if r[0] != 5 {
            return Err(SocksError::BadVersion5Method);
        }
        match r[1] {
            0 if self.auth.only => return Err(SocksError::NoAuthSelected),
            0 => self.request5()?,
            1 if self.auth.gssapi && self.gss.is_some() => {
                self.authenticated = true;
                self.awaiting = Awaiting::GssStart;
            }
            1 if self.auth.gssapi => {
                self.authenticated = true;
                return Err(SocksError::GssapiNotSupported);
            }
            1 => return Err(SocksError::GssapiNotEnabled),
            2 if self.auth.basic => {
                self.authenticated = true;
                self.login()?;
            }
            2 => return Err(SocksError::BasicNotEnabled),
            255 => return Err(SocksError::NoneAcceptable),
            _ => return Err(SocksError::UnknownMode),
        }
        Ok(2)
    }

    /// SOCKS5's user and password, each empty for none
    /// (`socks5_auth_init`).
    fn login(&mut self) -> Result<(), SocksError> {
        let (user, password) = match &self.creds {
            Some(c) => (&c.user[..], &c.password[..]),
            None => (&[][..], &[][..]),
        };
        if user.len() > MAX_FIELD {
            return Err(SocksError::LongUser5);
        }
        if password.len() > MAX_FIELD {
            return Err(SocksError::LongPassword5);
        }
        let mut out = Vec::new();
        for part in [
            &[1, user.len() as u8][..],
            user,
            &[password.len() as u8],
            password,
        ] {
            out.try_extend_from_slice(part)?;
        }
        self.out = out;
        self.sent = 0;
        self.awaiting = Awaiting::Authenticated;
        Ok(())
    }

    /// SOCKS5's answer to the user and password
    /// (`socks5_check_auth_resp`).
    fn authenticated_reply(&mut self, r: &[u8]) -> Result<usize, SocksError> {
        if r[1] != 0 {
            return Err(SocksError::UserRejected(r[0], r[1]));
        }
        self.request5()?;
        Ok(2)
    }

    /// SOCKS5's request: the address resolved here, or the name as the
    /// proxy is to resolve it, an address if it is one
    /// (`socks5_req1_init`, `socks5_resolving`).
    fn request5(&mut self) -> Result<(), SocksError> {
        let [hi, lo] = self.port.to_be_bytes();
        let (v4, v6);
        let (kind, addr): (u8, &[u8]) = match self.resolved {
            Resolved::Remote => {
                if self.name.contains(&b':') {
                    let text = std::str::from_utf8(&self.name).map_err(|_| SocksError::BadIpv6)?;
                    v6 = text
                        .parse::<Ipv6Addr>()
                        .map_err(|_| SocksError::BadIpv6)?
                        .octets();
                    (4, &v6[..])
                } else if let Some(ip) = ipv4(&self.name) {
                    v4 = ip;
                    (1, &v4[..])
                } else {
                    (3, &self.name[..])
                }
            }
            Resolved::Address(IpAddr::V4(ip)) => {
                v4 = ip.octets();
                (1, &v4[..])
            }
            Resolved::Address(IpAddr::V6(ip)) => {
                v6 = ip.octets();
                (4, &v6[..])
            }
            Resolved::NoAddress => return Err(SocksError::NotResolved5(take(&mut self.name))),
            Resolved::Failed => {
                return Err(SocksError::Unresolved(take(&mut self.name), self.port));
            }
        };
        let mut out = Vec::new();
        out.try_extend_from_slice(&[5, 1, 0, kind])?;
        if kind == 3 {
            // Held to a byte's worth when the offer was made.
            out.try_push(addr.len() as u8)?;
        }
        out.try_extend_from_slice(addr)?;
        out.try_extend_from_slice(&[hi, lo])?;
        self.out = out;
        self.sent = 0;
        self.framing = gss::Framing::None;
        self.awaiting = Awaiting::Connected;
        Ok(())
    }

    /// SOCKS5's answer to the request, if all of it is there
    /// (`socks5_recv_resp1`): its first 8 bytes checked, then its length
    /// read from its address type.
    fn connected(&mut self, r: &[u8]) -> Result<Option<usize>, SocksError> {
        if r[0] != 5 {
            return Err(SocksError::BadVersion5);
        }
        if r[1] != 0 {
            return Err(SocksError::Refused5(take(&mut self.name), r[1]));
        }
        let len = connected_len(r)?;
        if r.len() < len {
            return Ok(None);
        }
        self.awaiting = Awaiting::Done;
        Ok(Some(len))
    }
}

/// The length of a SOCKS5 answer to a request, from its first 8 bytes.
fn connected_len(r: &[u8]) -> Result<usize, SocksError> {
    Ok(match r[3] {
        1 => 4 + 4 + 2,
        3 => 4 + 1 + usize::from(r[4]) + 2,
        4 => 4 + 16 + 2,
        _ => return Err(SocksError::BadAddressType),
    })
}

/// `name` as the four bytes of the IPv4 address it is, dotted, if it is
/// one (`curlx_inet_pton`).
fn ipv4(name: &[u8]) -> Option<[u8; 4]> {
    let text = std::str::from_utf8(name).ok()?;
    text.parse::<std::net::Ipv4Addr>()
        .ok()
        .map(|ip| ip.octets())
}

/// The name, moved into an error that says it.
fn take(name: &mut Vec<u8>) -> Vec<u8> {
    std::mem::take(name)
}
