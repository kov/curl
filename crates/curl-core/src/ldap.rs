//! What an LDAP library does for `ldap:` and `ldaps:`, as OpenLDAP's
//! libldap does for C (`lib/openldap.c`): the URL's search, a session
//! over a copy of the connected socket, its binds and searches, and the
//! messages that answer them. The core links none; a handle's
//! `Libraries` name the one its build has. Each call is one of the
//! library's, made when C makes it, so what goes on the wire is the
//! library's as in C.
//!
//! Over TLS the library's reads and writes go through the connection's
//! layers, not its socket: each call that may touch the wire is handed
//! the [`Wire`] to use, for that call only.

use std::fmt;
use std::io;
use std::os::fd::BorrowedFd;

use curl_alloc::OutOfMemory;

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
        socket: Option<BorrowedFd<'_>>,
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

impl Version {
    /// Its number, as the library takes it.
    pub fn number(self) -> i32 {
        match self {
            Version::V2 => 2,
            Version::V3 => 3,
        }
    }
}

/// How far below its base a search looks (`LDAP_SCOPE_*`), as the library
/// numbers it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Scope(pub i32);

impl Scope {
    pub const BASE: Scope = Scope(0);
    pub const ONE_LEVEL: Scope = Scope(1);
    pub const SUBTREE: Scope = Scope(2);
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
