//! LDAP and LDAPS through a library of the kind `lib/ldap.c` drives
//! ([`Local`]): where libldap has no `ldap_init_fd`, as macOS's
//! LDAP.framework has not, or the library is not OpenLDAP's (WinLDAP).
//!
//! The whole exchange is DO's, each call waiting for its answer, as C's
//! `ldap_do` makes it: the library makes a connection of its own to the
//! host and port the transfer's connection reached, binds and searches
//! over it, and each entry found is written as LDIF. The transfer's own
//! connection, which carries nothing, is not kept after.

use std::time::Duration;

use super::{base64, needs_base64};
use crate::auth::creds::{CredentialGate, Takes};
use crate::conn::ConnLease;
use crate::conn::io::Events;
use crate::deliver::{Pipeline, Reach};
use crate::error::{ErrorKind, UrlErrorKind, url_error};
use crate::ldap::{
    Bind, Binds, Code, Entries, Local, LocalSession, LocalTls, LocalUrl, NoName, Opened,
    RequireCert, UrlError, Version,
};
use crate::multi::Host;
use crate::multi::state::StepCx;
use crate::options::UseSsl;
use crate::proto::{Before, Connect, DoPhase, DoStep, Waiting};
use crate::trace;
use crate::url::{GetOptions, Part, Url};

/// How long the library's connect may take (`ldap_timeout`).
const NETWORK_TIMEOUT: Duration = Duration::from_secs(10);

/// An LDAP transfer over a [`Local`] library.
#[derive(Debug)]
pub(crate) struct Request {
    library: &'static dyn Local,
    pub(in crate::proto) base: crate::proto::base::RequestBase,
    /// The URL, as the transfer names it (`state.url`).
    url_text: Vec<u8>,
    /// The URL's path, as it is encoded (`state.up.path`).
    path: Vec<u8>,
    /// The URL's query, empty where it ends in `?` (`state.up.query`).
    query: Option<Vec<u8>>,
}

/// What became of the exchange before the session was let go of: the
/// search's code where it was made, and the entries read.
#[derive(Default)]
struct Ended {
    code: Option<Code>,
    entries: u32,
}

impl Request {
    /// A transfer of `url`, `ldaps` if `secured`: its peer and the
    /// credentials its URL and the application give, a `.netrc`'s if asked
    /// for. Nothing is read of the URL until DO, as C has no
    /// `setup_connection` here.
    pub(crate) fn new<H: Host>(
        library: &'static dyn Local,
        url: &Url,
        secured: bool,
        before: Before<'_>,
        cx: &mut StepCx<'_, H>,
    ) -> Result<Request, ErrorKind> {
        let name: &[u8] = if secured { b"ldaps" } else { b"ldap" };
        let peer = crate::proto::base::peer_of(url, name, cx)?;
        let gate = match before.first {
            None => CredentialGate::FIRST,
            Some(first) => {
                let other_hosts = cx.easy().options().http.unrestricted_auth;
                CredentialGate::new(first, &peer, other_hosts)
            }
        };
        let takes = Takes::of(Some(peer.scheme()));
        let credentials = crate::proto::request_credentials(cx, gate.trusted(), url, takes)?;
        let credentials = crate::proto::with_netrc(credentials, peer.name(), takes, cx)?;
        let url_text = url.get(Part::Url, GetOptions::NONE).map_err(url_error)?;
        let encoded = GetOptions {
            url_encode: true,
            ..GetOptions::NONE
        };
        let path = url.get(Part::Path, encoded).map_err(url_error)?;
        let with_empty = GetOptions {
            get_empty: true,
            ..GetOptions::NONE
        };
        let query = match url.get(Part::Query, with_empty) {
            Ok(query) => Some(query),
            Err(UrlErrorKind::NoQuery) => None,
            Err(e) => return Err(url_error(e)),
        };
        Ok(Request {
            library,
            base: crate::proto::base::RequestBase {
                peer,
                pipeline: Pipeline::new(Reach::Network),
                credentials,
            },
            url_text,
            path,
            query,
        })
    }

    /// The whole exchange (`ldap_do`), then what C does at its `quit`
    /// whatever came of it: the entries' count said if there were more,
    /// and the session let go of. C's `connclose` there has nothing to do
    /// here: an LDAP scheme's connection is never kept
    /// (`PROTOPT_CONN_REUSE` unset).
    fn exchange<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &ConnLease,
    ) -> Result<(), ErrorKind> {
        let mut ended = Ended::default();
        let mut session = None;
        let result = self.run(cx, lease, &mut session, &mut ended);
        if ended.code == Some(Code::SIZELIMIT_EXCEEDED) {
            let n = ended.entries;
            trace::info(cx, format_args!("There are more than {n} entries"));
        }
        drop(session);
        result
    }

    fn run<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &ConnLease,
        session: &mut Option<Box<dyn LocalSession>>,
        ended: &mut Ended,
    ) -> Result<(), ErrorKind> {
        let library = self.library;
        let (vendor, version) = library.vendor();
        trace::info(
            cx,
            format_args!("LDAP local: LDAP Vendor = {vendor} ; LDAP Version = {version}"),
        );
        trace::info_with(cx, &[b"LDAP local: ", &self.url_text]);
        let url = LocalUrl {
            text: &self.url_text,
            path: &self.path,
            query: self.query.as_deref(),
        };
        let search = match library.parse_url(&url) {
            Ok(search) => search,
            // The URL's number named as the library names its codes, as C
            // has it (`ldap_err2string`).
            Err(UrlError(n)) => {
                return Err(trace::fail_with(
                    cx,
                    ErrorKind::UrlMalformat,
                    &[b"Bad LDAP URL: ", library.describe(Code(n))],
                ));
            }
        };
        let conn = lease.conn();
        let Some(remote) = conn.remote() else {
            return Err(ErrorKind::FailedInit);
        };
        let port = remote.inet().map_or(0, |a| a.port());
        let ssl = conn.over_tls();
        let state = if ssl { "encrypted" } else { "cleartext" };
        trace::info(
            cx,
            format_args!("LDAP local: trying to establish {state} connection"),
        );
        let peer = &self.base.peer;
        let made = match library.open(peer.name(), port, ssl) {
            Ok(made) => made,
            Err(Opened::OutOfMemory) => return Err(ErrorKind::OutOfMemory),
            Err(Opened::Refused) => {
                let host = curl_alloc::Lossy(peer.shown());
                return Err(trace::fail(
                    cx,
                    ErrorKind::CouldntConnect,
                    format_args!("LDAP: cannot setup connect to {host}:{port}"),
                ));
            }
        };
        let s = session.insert(made);
        s.set_network_timeout(NETWORK_TIMEOUT);
        s.set_version(Version::V3);
        s.set_no_referrals();
        if ssl {
            self.secure(cx, lease, &mut **s)?;
        } else if matches!(
            cx.easy().options().line.use_ssl,
            UseSsl::Control | UseSsl::All
        ) {
            return Err(trace::fail(
                cx,
                ErrorKind::NotBuiltIn,
                format_args!("LDAP local: explicit TLS not supported"),
            ));
        }
        let secret = self.base.credentials.as_ref().map(|c| c.secret());
        let user = secret.map(|s| s.user());
        let password = secret.map(|s| s.password());
        let how = match library.binds() {
            Binds::Simple => Bind::Simple { user, password },
            Binds::Windows => Bind::windows(user, password, cx.easy().options().http.auth.0),
        };
        let mut rc = s.bind(how);
        // A bind in the clear refused in version 3 is tried in version 2.
        if !ssl && rc != Code::SUCCESS {
            s.set_version(Version::V2);
            rc = s.bind(how);
        }
        if rc != Code::SUCCESS {
            return Err(trace::fail_with(
                cx,
                ErrorKind::LdapCannotBind,
                &[
                    b"LDAP local: bind via ",
                    library.bind_call().as_bytes(),
                    b" ",
                    library.describe(rc),
                ],
            ));
        }
        crate::progress::reset(cx);
        let (code, mut entries) = match s.search(&search) {
            Ok(found) => found,
            Err(rc) => {
                return Err(trace::fail_with(
                    cx,
                    ErrorKind::LdapSearchFailed,
                    &[b"LDAP remote: ", library.describe(rc)],
                ));
            }
        };
        ended.code = Some(code);
        let pipeline = &mut self.base.pipeline;
        while entries.next_entry() {
            let wrote = write_entry(&mut *entries, &mut |bytes| pipeline.body(cx, bytes));
            match wrote {
                Ok(()) => {}
                Err(Ldif::Write(kind)) => return Err(kind),
                Err(Ldif::NoName) => return Err(ErrorKind::FailedInit),
                Err(Ldif::OutOfMemory) => return Err(ErrorKind::OutOfMemory),
                Err(Ldif::IllegalType) => {
                    return Err(trace::fail(
                        cx,
                        ErrorKind::WeirdServerReply,
                        format_args!("LDAP local: attribute type contains illegal bytes"),
                    ));
                }
            }
            ended.entries += 1;
        }
        Ok(())
    }

    /// Set the session to speak TLS from the start, checking the peer as
    /// the connection's TLS settings say, the library's way (`ldap_do`'s
    /// `ldap_ssl`).
    fn secure<H: Host>(
        &self,
        cx: &mut StepCx<'_, H>,
        lease: &ConnLease,
        s: &mut dyn LocalSession,
    ) -> Result<(), ErrorKind> {
        let library = self.library;
        let identity = lease
            .conn()
            .net_route()
            .and_then(|route| route.tls.as_deref());
        match library.tls() {
            LocalTls::OpenLdap => {
                let tls = &cx.easy().options().tls;
                let verify_peer = identity.map_or(tls.verify_peer, |i| i.verify_peer);
                let require = if verify_peer {
                    // OpenLDAP's library reads PEM files alone.
                    let cert_type = identity.map_or(tls.options.cert_type.as_deref(), |i| {
                        i.options.cert_type.as_deref()
                    });
                    if cert_type.is_some_and(|t| !t.eq_ignore_ascii_case(b"PEM")) {
                        return Err(trace::fail(
                            cx,
                            ErrorKind::SslCertproblem,
                            format_args!("LDAP local: ERROR OpenLDAP only supports PEM cert-type"),
                        ));
                    }
                    let Some(ca) = identity.and_then(|i| i.ca_file()) else {
                        return Err(trace::fail(
                            cx,
                            ErrorKind::SslCertproblem,
                            format_args!("LDAP local: ERROR PEM CA cert not set"),
                        ));
                    };
                    trace::info_with(cx, &[b"LDAP local: using PEM CA cert: ", ca]);
                    if let Err(rc) = s.set_ca_file(ca) {
                        return Err(trace::fail_with(
                            cx,
                            ErrorKind::SslCertproblem,
                            &[
                                b"LDAP local: ERROR setting PEM CA cert: ",
                                library.describe(rc),
                            ],
                        ));
                    }
                    RequireCert::Demand
                } else {
                    RequireCert::Never
                };
                if let Err(rc) = s.set_require_cert(require) {
                    return Err(trace::fail_with(
                        cx,
                        ErrorKind::SslCertproblem,
                        &[
                            b"LDAP local: ERROR setting cert verify mode: ",
                            library.describe(rc),
                        ],
                    ));
                }
                if let Err(rc) = s.set_tls_hard() {
                    return Err(trace::fail_with(
                        cx,
                        ErrorKind::SslCertproblem,
                        &[
                            b"LDAP local: ERROR setting SSL/TLS mode: ",
                            library.describe(rc),
                        ],
                    ));
                }
                Ok(())
            }
            LocalTls::Windows => {
                // The system's store checks the peer, unless told to
                // accept any; but it cannot check the name alone.
                s.set_ssl();
                let tls = &cx.easy().options().tls;
                let verify_peer = identity.map_or(tls.verify_peer, |i| i.verify_peer);
                let verify_host = identity.map_or(tls.verify_host, |i| i.verify_host);
                if !verify_peer {
                    if verify_host {
                        return Err(trace::fail(
                            cx,
                            ErrorKind::NotBuiltIn,
                            format_args!(
                                "LDAP local: host verification cannot be enabled when peer \
                                 verification is disabled for Windows native LDAP"
                            ),
                        ));
                    }
                    s.accept_any_cert();
                }
                Ok(())
            }
            LocalTls::None => Err(trace::fail(
                cx,
                ErrorKind::SslCertproblem,
                format_args!(
                    "LDAP local: SSL/TLS not supported with this version of the OpenLDAP toolkit"
                ),
            )),
        }
    }
}

/// Why an entry was not written whole.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Ldif {
    /// A write failed.
    Write(ErrorKind),
    /// The library gave the entry no name.
    NoName,
    /// An attribute's type is not safe in LDIF, which has no base64 form
    /// for one: it would let the server write lines of its own.
    IllegalType,
    OutOfMemory,
}

/// Write the entry `entries` is at as `lib/ldap.c` writes LDIF, a write
/// for each of C's: its name, then each attribute's values, each on a
/// line of its own and in base64 where binary or not safe as they are,
/// and a blank line after each attribute, none after the entry.
pub(crate) fn write_entry(
    entries: &mut dyn Entries,
    write: &mut dyn FnMut(&[u8]) -> Result<(), ErrorKind>,
) -> Result<(), Ldif> {
    let mut w = |bytes: &[u8]| write(bytes).map_err(Ldif::Write);
    let b64 = |bytes: &[u8]| base64(bytes).map_err(|_| Ldif::OutOfMemory);
    let name = entries.dn().map_err(|e| match e {
        NoName::Missing => Ldif::NoName,
        NoName::OutOfMemory => Ldif::OutOfMemory,
    })?;
    if needs_base64(name) {
        // A name with a line break would start lines of its own.
        let encoded = b64(name)?;
        w(b"DN:: ")?;
        w(&encoded)?;
    } else {
        w(b"DN: ")?;
        w(name)?;
    }
    w(b"\n")?;
    loop {
        let next = entries.next_attribute().map_err(|_| Ldif::OutOfMemory)?;
        let Some(attr) = next else { break };
        // Values the library could not read are none, and the attribute
        // only ends its line (`ldap_get_values_len`'s NULL).
        if let Some(values) = attr.values {
            if needs_base64(attr.name) {
                return Err(Ldif::IllegalType);
            }
            let binary = attr.name.len() > 7
                && attr.name[attr.name.len() - 7..].eq_ignore_ascii_case(b";binary");
            for value in values {
                w(b"\t")?;
                w(attr.name)?;
                w(b":")?;
                if binary || needs_base64(value) {
                    // An empty value is no base64 at all.
                    let encoded = if value.is_empty() {
                        Vec::new()
                    } else {
                        b64(value)?
                    };
                    w(b": ")?;
                    if !encoded.is_empty() {
                        w(&encoded)?;
                    }
                } else {
                    w(b" ")?;
                    w(value)?;
                }
                w(b"\n")?;
            }
        }
        w(b"\n")?;
    }
    Ok(())
}

impl crate::proto::Phases for Request {
    /// `lib/ldap.c` has no connect of its own; `ldaps:`'s TLS is the
    /// connection's.
    fn connect<H: Host>(
        &mut self,
        _: &mut StepCx<'_, H>,
        _: &mut ConnLease,
    ) -> Result<Connect, ErrorKind> {
        Ok(Connect::Done)
    }

    fn make<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        asked: DoPhase,
    ) -> Result<DoStep, ErrorKind> {
        match asked {
            DoPhase::Do => {
                self.exchange(cx, lease)?;
                Ok(DoStep::Did)
            }
            DoPhase::Doing | DoPhase::More => unreachable!("LDAP's DO is done at once"),
        }
    }

    fn waits(&self, phase: Waiting, _: Option<&crate::conn::line::LineConn>) -> Events {
        phase.c_default()
    }
}

#[cfg(test)]
mod tests;
