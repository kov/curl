//! The TLS sessions kept to resume (C's `lib/vtls/vtls_scache.c`): the
//! tickets a TLS library was given by a peer, kept per peer and the TLS
//! settings they were made with, for the next connection to that peer
//! with those settings to take one.
//!
//! A multi keeps one, or the share its transfers are given when it keeps
//! `Kind::SslSessions`; a transfer uses its share's in place of its
//! multi's. Each peer is a slot, as many as the cache was made with,
//! found by its key (`Curl_ssl_peer_key_make`) and the client certificate
//! and key password it was made with; a peer keeps two tickets at most.
//! What the cache does is traced as C traces it (`[SSLS]`).

use std::fmt;

use curl_alloc::{OutOfMemory, TryArc, TryVec as _};

use super::{Chosen, TlsIdentity};
use crate::conn::{Dial, Peer};
use crate::hash::{Hash as _, Sha256};
use crate::options::{TlsMaxVersion, TlsMinVersion, TlsOptions};

/// TLS 1.3's version on the wire.
pub const TLS1_3: u16 = 0x304;

/// What a session a peer gave can be resumed with: the library's own
/// form of it, and what the cache knows of it (C's `Curl_ssl_session`).
pub struct TlsTicket {
    /// The library's form of the session (OpenSSL's DER), opaque here.
    pub data: Vec<u8>,
    /// The version it was made for, as on the wire (`ietf_tls_id`).
    pub version: u16,
    /// The protocol ALPN chose on its connection, if any.
    pub alpn: Option<Chosen>,
    /// The early data it allows, in bytes.
    pub earlydata_max: usize,
    /// A QUIC session's: the transport parameters its connection had,
    /// encoded, which early data on a connection resuming it is sent
    /// under (`quic_tp`); empty for TCP's.
    pub quic_params: Vec<u8>,
    /// When it is no longer good, in seconds since 1970; 0 or less for
    /// none known.
    valid_until: i64,
}

impl TlsTicket {
    /// A session the library made, good until `valid_until`, in seconds
    /// since 1970 (`Curl_ssl_session_create`).
    pub fn new(
        data: Vec<u8>,
        version: u16,
        alpn: Option<Chosen>,
        earlydata_max: usize,
        valid_until: i64,
    ) -> TlsTicket {
        TlsTicket {
            data,
            version,
            alpn,
            earlydata_max,
            quic_params: Vec::new(),
            valid_until,
        }
    }

    /// The same, a QUIC session's, kept with its connection's transport
    /// parameters `params`, encoded.
    pub fn with_quic_params(self, params: Vec<u8>) -> TlsTicket {
        TlsTicket {
            quic_params: params,
            ..self
        }
    }

    fn expired(&self, now: i64) -> bool {
        self.valid_until > 0 && self.valid_until < now
    }
}

impl fmt::Debug for TlsTicket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsTicket")
            .field("len", &self.data.len())
            .field("version", &self.version)
            .field("alpn", &self.alpn)
            .field("quic_params", &self.quic_params.len())
            .field("valid_until", &self.valid_until)
            .finish_non_exhaustive()
    }
}

/// The ALPN of a session as C's `%s` shows it: `(nil)` for none.
struct Alpn(Option<Chosen>);

impl fmt::Display for Alpn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0.map_or("(nil)", Chosen::name))
    }
}

/// Who a connection's TLS sessions are kept for (C's `ssl_peer`'s
/// `scache_key` and the connection's `ssl_filter_config`): the peer's
/// key, and the settings its connection was made with, which a session
/// found must also match.
pub struct SessionPeer {
    key: Vec<u8>,
    identity: TryArc<TlsIdentity>,
}

impl SessionPeer {
    /// The peer `origin` reached through `via` (a connect-to's), whose
    /// connection's TLS is made with `identity` by the library `tls_id`
    /// names, over a connection dialed as `dial` says: a QUIC session's
    /// ticket never resumes a TCP one's handshake, nor the other way.
    pub(crate) fn new(
        identity: &TryArc<TlsIdentity>,
        origin: &Peer,
        via: Option<&Peer>,
        tls_id: &dyn fmt::Display,
        dial: Dial,
    ) -> Result<SessionPeer, OutOfMemory> {
        let key = peer_key(identity, origin, via, tls_id, dial)?;
        Ok(SessionPeer {
            key,
            identity: identity.clone(),
        })
    }

    /// One for `https://localhost/` with the default settings, for the
    /// tests of what holds one.
    #[cfg(test)]
    pub(crate) fn testing() -> SessionPeer {
        let tls = crate::options::Tls::default();
        let identity = TlsIdentity::of(&tls, super::CaDefaults::default()).unwrap();
        let origin = Peer::new(crate::proto::http::HTTPS, b"localhost".to_vec(), 443, None);
        SessionPeer::new(&identity, &origin, None, &"FakeTLS/1", Dial::Tcp).unwrap()
    }

    /// The key, as the trace shows it.
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    /// The connection's sessions are kept (`CURLOPT_SSL_SESSIONID_CACHE`).
    pub(crate) fn caches(&self) -> bool {
        self.identity.options.session_cache
    }

    fn auth(&self) -> Auth<'_> {
        let options = &self.identity.options;
        Auth {
            cert: options.cert.as_deref(),
            blob: options.cert.is_none() && options.cert_blob.is_some(),
            password: options.key_password.as_deref(),
        }
    }
}

impl fmt::Debug for SessionPeer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SessionPeer({})", Shown(&self.key))
    }
}

/// The client certificate and key password a lookup is made with
/// (`cf_ssl_scache_match_auth`'s `conn_config`).
#[derive(Clone, Copy)]
struct Auth<'a> {
    cert: Option<&'a [u8]>,
    /// The certificate is a blob, with no file named.
    blob: bool,
    password: Option<&'a [u8]>,
}

/// The client certificate a peer was added with: a blob is given a name
/// of its own (`cert-%p`), which no lookup's file name equals, so its
/// sessions are never found again, as in C.
#[derive(Debug, PartialEq, Eq)]
enum PeerCert {
    None,
    File(Vec<u8>),
    Blob,
}

/// One slot of the cache (`Curl_ssl_scache_peer`).
#[derive(Debug)]
struct CachePeer {
    /// None while the slot is free.
    key: Option<Vec<u8>>,
    cert: PeerCert,
    password: Option<Vec<u8>>,
    /// Oldest first; two at most, so taken from the front in place.
    sessions: Vec<TlsTicket>,
    /// The higher the more recently a session was taken from it.
    age: u64,
}

impl CachePeer {
    const FREE: CachePeer = CachePeer {
        key: None,
        cert: PeerCert::None,
        password: None,
        sessions: Vec::new(),
        age: 0,
    };

    /// Made free (`cf_ssl_scache_clear_peer`).
    fn clear(&mut self) {
        *self = CachePeer::FREE;
    }

    /// A lookup with `auth` may use it.
    fn matches(&self, auth: Auth<'_>) -> bool {
        let cert = match &self.cert {
            PeerCert::None => auth.cert.is_none(),
            PeerCert::File(name) => auth.cert == Some(name.as_slice()),
            PeerCert::Blob => false,
        };
        cert && same_secret(self.password.as_deref(), auth.password)
    }

    fn remove_expired(&mut self, now: i64) {
        self.sessions.retain(|s| !s.expired(now));
    }

    /// Add `s` (`cf_scache_peer_add_session`): a session not of TLS 1.3
    /// replaces all others; one of TLS 1.3 goes after those still good,
    /// the oldest dropped past `most`.
    fn add(&mut self, s: TlsTicket, now: i64, most: usize) -> Result<(), OutOfMemory> {
        if s.version != TLS1_3 {
            self.sessions.clear();
        } else {
            self.remove_expired(now);
            self.sessions.retain(|s| s.version == TLS1_3);
        }
        self.sessions.try_push(s)?;
        if self.sessions.len() > most {
            let extra = self.sessions.len() - most;
            self.sessions.drain(..extra);
        }
        Ok(())
    }
}

/// The same secret, or neither, compared in a time that does not depend
/// on where they first differ (`Curl_timestrcmp`).
fn same_secret(a: Option<&[u8]>, b: Option<&[u8]>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => {
            a.len() == b.len() && a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
        }
        (a, b) => a.is_none() && b.is_none(),
    }
}

/// The sessions kept to resume (`Curl_ssl_scache`).
#[derive(Debug)]
pub struct SessionCache {
    /// The slots in use or used, made as they are first needed: as many
    /// as `slots` at most.
    peers: Vec<CachePeer>,
    slots: usize,
    /// The sessions a peer keeps at most.
    per_peer: usize,
    /// Counts the sessions taken, the age a peer is given when one is.
    age: u64,
}

/// A session given a lifetime of none lives a day
/// (`default_lifetime_secs`); none lives longer than a week for TLS 1.3
/// or a day before (`CURL_SCACHE_MAX_13_LIFETIME_SEC`, `_12_`).
const DEFAULT_LIFETIME: i64 = 24 * 60 * 60;
const MOST_13: i64 = 7 * 24 * 60 * 60;
const MOST_12: i64 = 24 * 60 * 60;

impl SessionCache {
    /// The peers a multi keeps (`CURL_TLS_SESSION_SIZE`), and a share
    /// (`curl_share_setopt`'s 25).
    pub(crate) const PEERS: usize = 25;
    /// The peers `curl_easy_perform`'s own multi keeps (easy.c).
    pub(crate) const PERFORM_PEERS: usize = 3;
    /// The sessions each peer keeps.
    const PER_PEER: usize = 2;

    /// A cache of `slots` peers, which allocates nothing until one is
    /// added (`Curl_ssl_scache_create`).
    pub(crate) const fn new(slots: usize) -> SessionCache {
        SessionCache {
            peers: Vec::new(),
            slots,
            per_peer: SessionCache::PER_PEER,
            age: 1,
        }
    }

    /// The slot of the peer `key`, if it has one that `auth` matches
    /// (`cf_ssl_find_peer_by_key`).
    fn find(
        &self,
        key: &[u8],
        auth: Auth<'_>,
        trace: &mut dyn FnMut(fmt::Arguments<'_>),
    ) -> Option<usize> {
        let slots = self.slots;
        trace(format_args!(
            "find peer slot for {} among {slots} slots",
            Shown(key)
        ));
        let found = self
            .peers
            .iter()
            .position(|p| p.key.as_deref() == Some(key) && p.matches(auth));
        if found.is_none() {
            trace(format_args!("peer not found for {}", Shown(key)));
        }
        found
    }

    /// A slot to add a peer in, made free (`cf_ssl_get_free_peer`): the
    /// first free or holding no session, else one more if there is room,
    /// else the least recently used.
    fn free_slot(&mut self) -> Result<usize, OutOfMemory> {
        let idle = self
            .peers
            .iter()
            .position(|p| p.key.is_none() || p.sessions.is_empty());
        let i = match idle {
            Some(i) => i,
            None if self.peers.len() < self.slots => {
                // Room for every slot at once, as C allocates them.
                if self.peers.capacity() == 0 {
                    self.peers.try_reserve_exact(self.slots)?;
                }
                self.peers.try_push(CachePeer::FREE)?;
                self.peers.len() - 1
            }
            None => {
                let mut oldest = 0;
                for (i, p) in self.peers.iter().enumerate() {
                    if p.age < self.peers[oldest].age {
                        oldest = i;
                    }
                }
                oldest
            }
        };
        self.peers[i].clear();
        Ok(i)
    }

    /// The slot of the peer `key`, found or added (`cf_ssl_add_peer`).
    fn add_peer(
        &mut self,
        key: &[u8],
        auth: Auth<'_>,
        trace: &mut dyn FnMut(fmt::Arguments<'_>),
    ) -> Result<usize, OutOfMemory> {
        if let Some(i) = self.find(key, auth, trace) {
            return Ok(i);
        }
        let i = self.free_slot()?;
        let made = (|| {
            let cert = match (auth.cert, auth.blob) {
                (Some(name), _) => PeerCert::File(copy(name)?),
                (None, true) => PeerCert::Blob,
                (None, false) => PeerCert::None,
            };
            let password = auth.password.map(copy).transpose()?;
            Ok(CachePeer {
                key: Some(copy(key)?),
                cert,
                password,
                sessions: Vec::new(),
                age: 0,
            })
        })();
        match made {
            Ok(peer) => {
                self.peers[i] = peer;
                Ok(i)
            }
            Err(OutOfMemory) => Err(OutOfMemory),
        }
    }

    /// Keep `s` for `peer` at `now`, in seconds since 1970
    /// (`cf_scache_add_session`): its lifetime made a default if it has
    /// none, and cut to the most its version is kept. A session out of
    /// date already, or a cache of no slot, keeps nothing.
    pub(crate) fn put(
        &mut self,
        peer: &SessionPeer,
        mut s: TlsTicket,
        now: i64,
        trace: &mut dyn FnMut(fmt::Arguments<'_>),
    ) -> Result<(), OutOfMemory> {
        if self.slots == 0 {
            return Ok(());
        }
        if s.valid_until <= 0 {
            s.valid_until = now + DEFAULT_LIFETIME;
        }
        let most = if s.version == TLS1_3 {
            MOST_13
        } else {
            MOST_12
        };
        s.valid_until = s.valid_until.min(now + most);
        if s.expired(now) {
            trace(format_args!("add, session already expired"));
            return Ok(());
        }
        let key = peer.key();
        let i = match self.add_peer(key, peer.auth(), trace) {
            Ok(i) => i,
            Err(OutOfMemory) => {
                trace(format_args!("unable to add scache peer: 27"));
                return Err(OutOfMemory);
            }
        };
        let (version, valid, alpn, early, tp) = (
            s.version,
            s.valid_until - now,
            Alpn(s.alpn),
            s.earlydata_max,
            yes_no(!s.quic_params.is_empty()),
        );
        let per_peer = self.per_peer;
        let slot = &mut self.peers[i];
        if slot.add(s, now, per_peer).is_err() {
            // C's list never fails to take one: the slot is let go
            // rather than left with a session short.
            slot.clear();
            trace(format_args!("unable to add scache peer: 27"));
            return Err(OutOfMemory);
        }
        let n = slot.sessions.len();
        trace(format_args!(
            "added session for {} [proto=0x{version:x}, valid_secs={valid}, alpn={alpn}, \
             earlydata={early}, quic_tp={tp}], peer has {n} sessions now",
            Shown(key)
        ));
        Ok(())
    }

    /// A session to resume for `peer` at `now`, taken from the cache, the
    /// oldest still good (`Curl_ssl_scache_take`).
    pub(crate) fn take(
        &mut self,
        peer: &SessionPeer,
        now: i64,
        trace: &mut dyn FnMut(fmt::Arguments<'_>),
    ) -> Option<TlsTicket> {
        let key = peer.key();
        let taken = self.find(key, peer.auth(), trace).and_then(|i| {
            let slot = &mut self.peers[i];
            slot.remove_expired(now);
            if slot.sessions.is_empty() {
                return None;
            }
            let s = slot.sessions.remove(0);
            self.age += 1;
            slot.age = self.age;
            Some((s, slot.sessions.len()))
        });
        match taken {
            Some((s, left)) => {
                trace(format_args!(
                    "took session for {} [proto=0x{:x}, alpn={}, earlydata={}, quic_tp={}], \
                     {left} sessions remain",
                    Shown(key),
                    s.version,
                    Alpn(s.alpn),
                    s.earlydata_max,
                    yes_no(!s.quic_params.is_empty()),
                ));
                Some(s)
            }
            None => {
                trace(format_args!("no cached session for {}", Shown(key)));
                None
            }
        }
    }

    /// Forget every session of `peer` (`Curl_ssl_scache_remove_all`).
    pub(crate) fn remove_all(
        &mut self,
        peer: &SessionPeer,
        trace: &mut dyn FnMut(fmt::Arguments<'_>),
    ) {
        if let Some(i) = self.find(peer.key(), peer.auth(), trace) {
            self.peers[i].clear();
        }
    }
}

/// C's `"yes"` or `"no"` for a flag in a line.
fn yes_no(flag: bool) -> &'static str {
    if flag { "yes" } else { "no" }
}

fn copy(bytes: &[u8]) -> Result<Vec<u8>, OutOfMemory> {
    let mut v = Vec::new();
    v.try_reserve_exact(bytes.len())?;
    v.try_extend_from_slice(bytes)?;
    Ok(v)
}

/// Bytes as C's `%s` shows them.
pub(super) struct Shown<'a>(pub(super) &'a [u8]);

impl fmt::Display for Shown<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for chunk in self.0.utf8_chunks() {
            f.write_str(chunk.valid())?;
            for &b in chunk.invalid() {
                write!(f, "{}", char::from(b))?;
            }
        }
        Ok(())
    }
}

/// Where a key is written: counted first, then filled, so the key is one
/// allocation of its length.
trait Sink {
    fn bytes(&mut self, b: &[u8]);
}

/// Counts what would be written.
struct Count(usize);

impl Sink for Count {
    fn bytes(&mut self, b: &[u8]) {
        self.0 += b.len();
    }
}

/// Writes into room reserved for it.
struct Fill(Vec<u8>);

impl Sink for Fill {
    fn bytes(&mut self, b: &[u8]) {
        assert!(self.0.capacity() - self.0.len() >= b.len(), "counted first");
        self.0
            .try_extend_from_slice(b)
            .expect("within the room reserved");
    }
}

impl fmt::Write for dyn Sink + '_ {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.bytes(s.as_bytes());
        Ok(())
    }
}

/// C's `CURL_SSLVERSION_*` number of a transfer's oldest version.
fn min_number(v: TlsMinVersion) -> u32 {
    match v {
        TlsMinVersion::Tls1 => 1,
        TlsMinVersion::Tls1_0 => 4,
        TlsMinVersion::Tls1_1 => 5,
        TlsMinVersion::Tls1_2 => 6,
        TlsMinVersion::Tls1_3 => 7,
    }
}

/// C's `CURL_SSLVERSION_MAX_*` number of the newest, shifted down 16.
fn max_number(v: TlsMaxVersion) -> u32 {
    match v {
        TlsMaxVersion::None => 0,
        TlsMaxVersion::Default => 1,
        TlsMaxVersion::Tls1_0 => 4,
        TlsMaxVersion::Tls1_1 => 5,
        TlsMaxVersion::Tls1_2 => 6,
        TlsMaxVersion::Tls1_3 => 7,
    }
}

/// The key a peer's sessions are kept by (`Curl_ssl_peer_key_make`): the
/// origin, then every TLS setting a session must share, each text after
/// its length, and the library; `:G` at the end, or `:L` if a relative
/// path could not be made absolute, so that the key holds only in this
/// directory.
fn peer_key(
    identity: &TlsIdentity,
    origin: &Peer,
    via: Option<&Peer>,
    tls_id: &dyn fmt::Display,
    dial: Dial,
) -> Result<Vec<u8>, OutOfMemory> {
    let mut count = Count(0);
    write_key(&mut count, identity, origin, via, tls_id, dial);
    let mut fill = Fill(Vec::new());
    fill.0.try_reserve_exact(count.0)?;
    write_key(&mut fill, identity, origin, via, tls_id, dial);
    debug_assert_eq!(fill.0.len(), count.0, "written as counted");
    Ok(fill.0)
}

fn write_key(
    out: &mut dyn Sink,
    identity: &TlsIdentity,
    origin: &Peer,
    via: Option<&Peer>,
    tls_id: &dyn fmt::Display,
    dial: Dial,
) {
    use fmt::Write as _;
    let w = |out: &mut dyn Sink, args: fmt::Arguments<'_>| {
        out.write_fmt(args).expect("a sink never fails");
    };
    let text = |out: &mut dyn Sink, name: &str, value: &[u8]| {
        w(out, format_args!(":{name}-{}:", value.len()));
        out.bytes(value);
    };
    let mut local = false;
    // A path made absolute if it is not, so that the key holds in another
    // directory; one that cannot be is kept as it is, the key local.
    let mut path = |out: &mut dyn Sink, name: &str, value: Option<&[u8]>| {
        let Some(value) = value.filter(|v| !v.is_empty()) else {
            return;
        };
        if value.first() != Some(&b'/') {
            let real = curl_os::fs::with_c_name(value, |c| {
                curl_os::fs::real_path(c, |abs| text(out, name, abs))
            });
            if real.is_ok() {
                return;
            }
            local = true;
        }
        text(out, name, value);
    };
    let hash = |out: &mut dyn Sink, name: &str, blob: Option<&[u8]>| {
        let Some(blob) = blob.filter(|b| !b.is_empty()) else {
            return;
        };
        let mut sha = Sha256::default();
        sha.update(blob);
        w(out, format_args!(":{name}-"));
        for b in &sha.finish()[..Sha256::LEN] {
            w(out, format_args!("{b:02x}"));
        }
    };
    let o: &TlsOptions = &identity.options;
    w(out, format_args!("{}:", origin.scheme().name));
    out.bytes(origin.name());
    w(out, format_args!(":{}:KEY-V3", origin.port()));
    // TCP's adds nothing (`ssl_peer_key_add_transport`).
    if dial == Dial::Quic {
        out.bytes(b":QUIC");
    }
    if !identity.verify_peer {
        out.bytes(b":NO-VRFY-PEER");
    }
    if !identity.verify_host {
        out.bytes(b":NO-VRFY-HOST");
    }
    if o.verify_status {
        out.bytes(b":VRFY-STATUS");
    }
    if (!identity.verify_peer || !identity.verify_host)
        && let Some(via) = via.filter(|v| **v != *origin)
    {
        text(out, "CHOST", via.name());
        w(out, format_args!(":CPORT-{}", via.port()));
    }
    // Always: the oldest version is never C's 0.
    w(
        out,
        format_args!(
            ":TLSVER-{}-{}",
            min_number(o.min_version),
            max_number(o.max_version)
        ),
    );
    let bits = o.ssl_options.bits();
    if bits != 0 {
        w(out, format_args!(":TLSOPT-{bits:x}"));
    }
    for (name, value) in [
        ("CIPHER", &o.ciphers),
        ("CIPHER13", &o.tls13_ciphers),
        ("CURVES", &o.curves),
        ("SIGALGS", &o.signature_algorithms),
    ] {
        if let Some(value) = value {
            text(out, name, value);
        }
    }
    if identity.verify_peer {
        path(out, "CA", identity.ca_file());
        path(out, "CApath", identity.ca_path());
        path(out, "CRL", o.crl_file.as_deref());
        path(out, "Issuer", o.issuer_cert.as_deref());
        hash(out, "CAInfoBlob", o.ca_blob.as_deref());
        hash(out, "IssuerBlob", o.issuer_cert_blob.as_deref());
    }
    hash(out, "CertBlob", o.cert_blob.as_deref());
    if let Some(pinned) = o.pinned_key.as_deref().filter(|p| !p.is_empty()) {
        text(out, "Pinned", pinned);
    }
    path(out, "CCERT", o.cert.as_deref());
    path(out, "KEY", o.key.as_deref());
    hash(out, "KEYBlob", o.key_blob.as_deref());
    for (name, value) in [("CT", &o.cert_type), ("KT", &o.key_type)] {
        if let Some(value) = value.as_deref().filter(|v| !v.is_empty()) {
            w(out, format_args!(":{name}-{}:", value.len()));
            for b in value {
                out.bytes(&[b.to_ascii_uppercase()]);
            }
        }
    }
    let mut id = Count(0);
    w(&mut id, format_args!("{tls_id}"));
    w(out, format_args!(":IMPL-{}:{tls_id}", id.0));
    out.bytes(if local { b":L" } else { b":G" });
}

#[cfg(test)]
mod tests;
