//! What an LDAP library does for `ldap:` and `ldaps:`, in either of the
//! two ways C's build drives one. The core links none; a handle's
//! `Libraries` name the one its build has ([`LdapLibrary`]). Each call is
//! one of the library's, made when C makes it, so what goes on the wire
//! is the library's as in C.
//!
//! [`Ldap`] is OpenLDAP's libldap as `lib/openldap.c` drives it: the
//! URL's search, a session over a copy of the connected socket, its binds
//! and searches, and the messages that answer them, none of them waited
//! for. Over TLS the library's reads and writes go through the
//! connection's layers, not its socket: each call that may touch the wire
//! is handed the [`Wire`] to use, for that call only.
//!
//! [`Local`] is a library as `lib/ldap.c` drives it, where libldap has no
//! `ldap_init_fd` (macOS's LDAP.framework) or the library is another
//! (WinLDAP): a session of the library's own, over a connection it makes
//! itself, each call waited for.

use std::fmt;
use std::io;
use std::time::Duration;

use curl_alloc::OutOfMemory;
use curl_os::socket::BorrowedSocket;

use crate::options::AuthMethods;

mod low_url;
pub use low_url::{LowUrlError, parse_url_low};

/// An LDAP library.
pub trait Ldap: fmt::Debug + Send + Sync {
    /// The search `url` names (`ldap_url_parse`), or the library's
    /// number for what is wrong with it (`LDAP_URL_ERR_*`).
    fn parse_url(&self, url: &[u8]) -> Result<Search, UrlError>;

    /// A session over a copy of the connected socket, which stays the
    /// caller's, for `scheme`'s connection to `url`
    /// (`ldap_pvt_url_scheme2proto`, `ldap_init_fd`). A socket with no
    /// descriptor is one a library over the system's sockets cannot copy.
    fn session(
        &self,
        socket: Option<BorrowedSocket<'_>>,
        scheme: &[u8],
        url: &[u8],
    ) -> Result<Box<dyn Session>, SessionFailed>;

    /// The library's words for `code` (`ldap_err2string`).
    fn describe(&self, code: Code) -> &'static [u8];
}

/// Why no session was made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionFailed {
    /// The connected socket could not be copied.
    NoCopy,
    /// The library's code for it.
    Library(Code),
}

/// The library refused a setting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refused;

/// The protocol version a session speaks (`LDAP_VERSION*`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Version {
    V2,
    V3,
}

/// How far below its base a search looks (`LDAP_SCOPE_*`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Scope {
    /// The base entry alone.
    #[default]
    Base,
    /// The entries right below the base.
    OneLevel,
    /// The base and everything below it.
    Subtree,
    /// Everything below the base but the base itself: OpenLDAP's
    /// `children`, which C searches with as the library read it.
    Subordinate,
}

/// A result code, the library's or the server's (`LDAP_*`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Code(pub i32);

impl Code {
    pub const SUCCESS: Code = Code(0x00);
    pub const PROTOCOL_ERROR: Code = Code(0x02);
    pub const SIZELIMIT_EXCEEDED: Code = Code(0x04);
    pub const SASL_BIND_IN_PROGRESS: Code = Code(0x0e);
    pub const INVALID_CREDENTIALS: Code = Code(0x31);
    pub const INSUFFICIENT_ACCESS: Code = Code(0x32);
    pub const NO_MEMORY: Code = Code(-10);
    pub const NO_RESULTS_RETURNED: Code = Code(-14);
}

/// What is wrong with a URL, as the library numbers it
/// (`LDAP_URL_ERR_*`, from 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UrlError(pub i32);

impl UrlError {
    /// `LDAP_URL_ERR_MEM`.
    pub const MEM: UrlError = UrlError(1);
    /// `LDAP_URL_ERR_BADURL`.
    pub const BAD_URL: UrlError = UrlError(5);
}

/// The search a URL names: its base, scope, filter and the attributes it
/// asks for, each none where the URL has none (`LDAPURLDesc`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Search {
    pub dn: Option<Vec<u8>>,
    pub scope: Scope,
    pub filter: Option<Vec<u8>>,
    pub attrs: Option<Vec<Vec<u8>>>,
}

/// A message's id, as the call that sent it gave it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MsgId(pub i32);

/// The mechanism a bind is made with (`ldap_sasl_bind`'s `mechanism`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mech<'a> {
    /// A simple bind, with a password (`LDAP_SASL_SIMPLE`).
    Simple,
    /// No mechanism, cancelling a SASL bind under way (`LDAP_SASL_NULL`).
    Null,
    /// The SASL mechanism named.
    Sasl(&'a [u8]),
}

/// What a message answers (`ldap_msgtype`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Bind,
    SearchEntry,
    SearchReference,
    SearchResult,
    Extended,
    Other(i32),
}

/// The connection a session reads and writes through over TLS: the
/// connection's layers, as C's `ldapsb_tls` calls them.
pub trait Wire {
    /// Read into `buf`: how much, none at the connection's end; a read
    /// that would wait fails as [`io::ErrorKind::WouldBlock`].
    fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize>;
    /// Send from `bytes` what the connection takes now.
    fn send(&mut self, bytes: &[u8]) -> io::Result<usize>;
    /// Whether bytes wait that a poll of the socket cannot see
    /// (`Curl_conn_data_pending`).
    fn pending(&mut self) -> bool;
}

/// A session's settings and calls, one for one with libldap's. Dropping
/// it unbinds and frees it (`ldap_unbind_ext`), its copy of the socket
/// closed.
pub trait Session: fmt::Debug + Send {
    /// The protocol version it speaks (`LDAP_OPT_PROTOCOL_VERSION`).
    fn set_version(&mut self, version: Version);
    /// Chase no referrals (`LDAP_OPT_REFERRALS`).
    fn set_no_referrals(&mut self);
    /// The largest message it reads (`LBER_SB_OPT_SET_MAX_INCOMING`).
    fn set_max_incoming(&mut self, max: usize) -> Result<(), Refused>;
    /// Read and write through the [`Wire`] each call is handed from now
    /// on, not its socket (`ber_sockbuf_add_io` of C's `ldapsb_tls`).
    fn use_wire(&mut self) -> Result<(), Refused>;
    /// Whether it does.
    fn uses_wire(&self) -> bool;

    /// Send a bind as `dn`, with `mech` and `cred` (`ldap_sasl_bind`).
    fn bind(
        &mut self,
        wire: &mut dyn Wire,
        dn: Option<&[u8]>,
        mech: Mech<'_>,
        cred: Option<&[u8]>,
    ) -> Result<MsgId, Code>;
    /// Send a search (`ldap_search_ext`).
    fn search(&mut self, wire: &mut dyn Wire, search: &Search) -> Result<MsgId, Code>;
    /// Send STARTTLS (`ldap_start_tls`).
    fn start_tls(&mut self, wire: &mut dyn Wire) -> Result<MsgId, Code>;
    /// The next message answering `id`, if one came, without waiting
    /// (`ldap_result` with `LDAP_MSG_ONE` and no time); the library's
    /// code if it failed.
    fn result<'s>(
        &'s mut self,
        wire: &mut dyn Wire,
        id: MsgId,
    ) -> Result<Option<Box<dyn Message + 's>>, Code>;
    /// Give up on `id` (`ldap_abandon_ext`).
    fn abandon(&mut self, wire: &mut dyn Wire, id: MsgId);
    /// Unbind now, through `wire` (`ldap_unbind_ext`): dropping it after
    /// says nothing more.
    fn unbind(&mut self, wire: &mut dyn Wire);
}

/// A message the server sent, freed when dropped (`ldap_msgfree`).
pub trait Message {
    fn kind(&self) -> Kind;
    /// Its result code and the server's words, if it says any
    /// (`ldap_parse_result`); the library's code if it could not be read.
    fn result(&mut self) -> Result<(Code, Option<Vec<u8>>), Code>;
    /// The credentials a bind's answer carries
    /// (`ldap_parse_sasl_bind_result`).
    fn bind_result(&mut self) -> Result<Option<Vec<u8>>, Code>;
    /// An entry's name (`ldap_get_dn_ber`), which starts the reading of
    /// its attributes.
    fn dn(&mut self) -> Result<&[u8], Code>;
    /// Its next attribute, after [`Message::dn`]: its type, and its values
    /// if it came with any (`ldap_get_attribute_ber`); none past the last
    /// or where the library could not read one.
    fn next_attribute(&mut self) -> Result<Option<Attribute<'_>>, OutOfMemory>;
}

/// An attribute of an entry: its type, and its values, if any.
#[derive(Debug)]
pub struct Attribute<'m> {
    pub name: &'m [u8],
    pub values: Option<Vec<&'m [u8]>>,
}

/// The LDAP library a build has, and the way C drives it.
#[derive(Clone, Copy, Debug)]
pub enum LdapLibrary {
    /// Over the connection's socket (`lib/openldap.c`).
    Fd(&'static dyn Ldap),
    /// Over a connection of its own (`lib/ldap.c`).
    Local(&'static dyn Local),
}

/// An LDAP library as `lib/ldap.c` drives it: it parses the URL, makes a
/// session to the host and port connected to, sets it up, binds and
/// searches, each call waiting for its answer, then hands the entries
/// found over one by one. The connection the transfer made is used for
/// nothing but its address.
pub trait Local: fmt::Debug + Send + Sync {
    /// The library's name and version as its headers give them
    /// (`LDAP_VENDOR_NAME`, `LDAP_VENDOR_VERSION`).
    fn vendor(&self) -> (&'static str, i32);

    /// The search `url` names (`ldap_url_parse`, or C's own
    /// `ldap_url_parse_low` where the library has none), or the library's
    /// number for what is wrong with it.
    fn parse_url(&self, url: &LocalUrl<'_>) -> Result<Search, UrlError>;

    /// The library's words for `code` (`ldap_err2string`).
    fn describe(&self, code: Code) -> &'static [u8];

    /// How the library is told to speak TLS, which decides the steps of
    /// an `ldaps:` session's set-up.
    fn tls(&self) -> LocalTls;

    /// How C binds with the library, which decides the call a bind is
    /// made with.
    fn binds(&self) -> Binds;

    /// The call a bind is made with, as a failed bind names it.
    fn bind_call(&self) -> &'static str;

    /// A session to `host`'s `port`, made but not connected
    /// (`ldap_init`); with TLS from the start if `secured` where the
    /// library is told so as the session is made (`ldap_sslinit`).
    fn open(&self, host: &[u8], port: u16, secured: bool) -> Result<Box<dyn LocalSession>, Opened>;
}

/// The URL a [`Local`] library is handed: the whole of it as the
/// transfer names it (`state.url`), its path as it is encoded
/// (`state.up.path`) and its query, empty where it ends in `?`
/// (`state.up.query`).
#[derive(Clone, Copy, Debug)]
pub struct LocalUrl<'a> {
    pub text: &'a [u8],
    pub path: &'a [u8],
    pub query: Option<&'a [u8]>,
}

/// How C binds with a [`Local`] library.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Binds {
    /// Simply, with the credentials if there are any
    /// (`ldap_simple_bind_s`).
    Simple,
    /// As WinLDAP's `ldap_win_bind` does: simply with credentials where
    /// Basic is asked for, else by SSPI, with them as Negotiate or Digest
    /// where asked, or as the user the process runs as.
    Windows,
}

/// A bind, as the library is asked to make it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bind<'a> {
    /// A simple bind as `user` with `password`, none for none
    /// (`ldap_simple_bind_s`).
    Simple {
        user: Option<&'a [u8]>,
        password: Option<&'a [u8]>,
    },
    /// By SSPI with `method`, as `user` (`domain\user` or `domain/user`
    /// naming a domain) with `password` (`ldap_bind_s` with an SSPI
    /// identity).
    Sspi {
        method: SspiMethod,
        user: &'a [u8],
        password: &'a [u8],
    },
    /// By SSPI's Negotiate, as the user the process runs as
    /// (`ldap_bind_s` with no identity).
    CurrentUser,
}

/// The SSPI method a bind with credentials is made with
/// (`LDAP_AUTH_NEGOTIATE`, `LDAP_AUTH_DIGEST`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SspiMethod {
    Negotiate,
    Digest,
}

impl<'a> Bind<'a> {
    /// The bind `ldap_win_bind` makes as `user` with `password`, none for
    /// none, with the methods `auth` asks for (`CURLOPT_HTTPAUTH`).
    pub fn windows(
        user: Option<&'a [u8]>,
        password: Option<&'a [u8]>,
        auth: AuthMethods,
    ) -> Bind<'a> {
        let creds = user.zip(password);
        if let Some((user, password)) = creds.filter(|_| auth.contains(AuthMethods::BASIC)) {
            return Bind::Simple {
                user: Some(user),
                password: Some(password),
            };
        }
        let method = if auth.contains(AuthMethods::NEGOTIATE) {
            Some(SspiMethod::Negotiate)
        } else if auth.contains(AuthMethods::DIGEST) {
            Some(SspiMethod::Digest)
        } else {
            None
        };
        match (method, creds) {
            (Some(method), Some((user, password))) => Bind::Sspi {
                method,
                user,
                password,
            },
            _ => Bind::CurrentUser,
        }
    }
}

/// Why no session was made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Opened {
    /// The library made none.
    Refused,
    OutOfMemory,
}

/// How a [`Local`] library speaks TLS (the branches of `ldap_do`'s
/// `ldap_ssl`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalTls {
    /// By OpenLDAP's options (`LDAP_OPT_X_TLS`): the file of
    /// certificates to trust, how hard the peer's is checked, and TLS
    /// from the start.
    OpenLdap,
    /// By WinLDAP's: TLS from the session's start (`ldap_sslinit`,
    /// `LDAP_OPT_SSL`), the peer checked against the system's store unless
    /// a callback accepts any (`LDAP_OPT_SERVER_CERTIFICATE`).
    Windows,
    /// Not at all: the library has no TLS to set.
    None,
}

/// How hard a session checks the peer's certificate
/// (`LDAP_OPT_X_TLS_REQUIRE_CERT`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequireCert {
    /// Not at all (`LDAP_OPT_X_TLS_NEVER`).
    Never,
    /// It must verify (`LDAP_OPT_X_TLS_DEMAND`).
    Demand,
}

/// A [`Local`] library's session, its settings and calls one for one with
/// the library's, each waited for. Dropping it unbinds and frees it, its
/// connection closed (`ldap_unbind_s`).
pub trait LocalSession: fmt::Debug + Send {
    /// How long a connect may take (`LDAP_OPT_NETWORK_TIMEOUT`).
    fn set_network_timeout(&mut self, timeout: Duration);
    /// The protocol version it speaks (`LDAP_OPT_PROTOCOL_VERSION`).
    fn set_version(&mut self, version: Version);
    /// Chase no referrals (`LDAP_OPT_REFERRALS`).
    fn set_no_referrals(&mut self);
    /// Trust the certificates in the file `path` names
    /// (`LDAP_OPT_X_TLS_CACERTFILE`).
    fn set_ca_file(&mut self, path: &[u8]) -> Result<(), Code>;
    /// Check the peer's certificate as `require` says
    /// (`LDAP_OPT_X_TLS_REQUIRE_CERT`).
    fn set_require_cert(&mut self, require: RequireCert) -> Result<(), Code>;
    /// Speak TLS from the start (`LDAP_OPT_X_TLS` to
    /// `LDAP_OPT_X_TLS_HARD`).
    fn set_tls_hard(&mut self) -> Result<(), Code>;
    /// Speak TLS (`LDAP_OPT_SSL` on), the library's answer not looked at,
    /// as C does not ([`LocalTls::Windows`]).
    fn set_ssl(&mut self);
    /// Accept whatever certificate the peer shows
    /// (`LDAP_OPT_SERVER_CERTIFICATE`, C's `bypass_cert_verify`), the
    /// library's answer not looked at ([`LocalTls::Windows`]).
    fn accept_any_cert(&mut self);
    /// Bind as `how` says, the connection made first if it is not yet:
    /// the library's or the server's code.
    fn bind(&mut self, how: Bind<'_>) -> Code;
    /// Search, waiting for the whole answer (`ldap_search_s`): its code,
    /// success or too many entries, and the entries; the code otherwise.
    fn search(&mut self, search: &Search) -> Result<(Code, Box<dyn Entries + '_>), Code>;
}

/// The entries a search found, read one at a time, and freed when
/// dropped (`ldap_msgfree`).
pub trait Entries {
    /// Move to the next entry, the first the first time
    /// (`ldap_first_entry`, `ldap_next_entry`): whether there is one.
    fn next_entry(&mut self) -> bool;
    /// The entry's name (`ldap_get_dn`).
    fn dn(&mut self) -> Result<&[u8], NoName>;
    /// The entry's next attribute, the first the first time
    /// (`ldap_first_attribute`, `ldap_next_attribute`): its type, and its
    /// values if the library gives any (`ldap_get_values_len`); none past
    /// the last.
    fn next_attribute(&mut self) -> Result<Option<Attribute<'_>>, OutOfMemory>;
}

/// Why an entry has no name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoName {
    /// The library gave none.
    Missing,
    OutOfMemory,
}
