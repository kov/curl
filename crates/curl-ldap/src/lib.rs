//! LDAP from OpenLDAP's libldap (`lib/openldap.c`): the URL's search, a
//! session over a copy of the connection's socket, its binds, searches
//! and the messages answering them, and the layer through which a
//! session over TLS reads and writes the connection's layers. The calls
//! are libldap's, one for one with C's.

#![allow(unsafe_code)]
#![cfg_attr(test, allow(clippy::disallowed_methods, clippy::disallowed_macros))]

mod sys;

use core::cell::Cell;
use core::ffi::{CStr, c_char, c_int, c_void};
use core::marker::PhantomData;
use core::ptr;
use std::os::fd::{BorrowedFd, FromRawFd as _, IntoRawFd as _, OwnedFd};
use std::sync::OnceLock;

use curl_alloc::{OutOfMemory, TryVec as _};
use curl_core::ldap::{
    Attribute, Code, Kind, Ldap, Mech, Message, MsgId, NoCopy, Search, Session, UrlError, Wire,
};

/// libldap, as C's build uses it.
#[derive(Debug)]
pub struct Libldap;

/// The library each handle speaks LDAP with.
pub static LIBLDAP: Libldap = Libldap;

/// The library's version, as `curl -V` names it (`Curl_ldap_version`):
/// its vendor's name and its number, `OpenLDAP/2.6.15`.
pub fn version() -> &'static str {
    static VERSION: OnceLock<([u8; 64], usize)> = OnceLock::new();
    let (buf, len) = VERSION.get_or_init(api_version);
    core::str::from_utf8(&buf[..*len]).expect("the library names itself in ASCII")
}

/// The words of [`version`], as the library gives them, else C's
/// fallback.
fn api_version() -> ([u8; 64], usize) {
    use std::io::Write as _;
    let mut buf = [0u8; 64];
    let mut api = sys::LDAPAPIInfo {
        ldapai_info_version: sys::LDAP_API_INFO_VERSION,
        ldapai_api_version: 0,
        ldapai_protocol_version: 0,
        ldapai_extensions: ptr::null_mut(),
        ldapai_vendor_name: ptr::null_mut(),
        ldapai_vendor_version: 0,
    };
    // SAFETY: with no session, the option fills the struct, whose
    // version it is told, and allocates its name and extensions.
    let rc = unsafe {
        sys::ldap_get_option(
            ptr::null_mut(),
            sys::LDAP_OPT_API_INFO,
            (&raw mut api).cast::<c_void>(),
        )
    };
    let mut out = &mut buf[..];
    let room = out.len();
    if rc == sys::LDAP_OPT_SUCCESS && !api.ldapai_vendor_name.is_null() {
        // SAFETY: a C string the library allocated, freed below.
        let vendor = unsafe { CStr::from_ptr(api.ldapai_vendor_name) };
        let v = u32::try_from(api.ldapai_vendor_version).unwrap_or(0);
        let (major, minor, patch) = (
            v / 10000,
            (v - (v / 10000) * 10000 - v % 100) / 100,
            v % 100,
        );
        let said = out
            .write_all(vendor.to_bytes())
            .and_then(|()| write!(out, "/{major}.{minor}.{patch}"));
        assert!(said.is_ok(), "the version fits its buffer");
        // SAFETY: allocated by the call above, freed once each.
        unsafe { sys::ldap_memfree(api.ldapai_vendor_name.cast::<c_void>()) };
        // SAFETY: as above; the vector is NULL or the library's.
        unsafe { sys::ber_memvfree(api.ldapai_extensions.cast::<*mut c_void>()) };
    } else {
        assert!(out.write_all(b"OpenLDAP").is_ok(), "fits");
    }
    let len = room - out.len();
    (buf, len)
}

/// `text` with a NUL after it, for libldap; none for one with a NUL
/// inside, which libldap could not be given.
fn terminated(text: &[u8]) -> Result<Option<Vec<u8>>, OutOfMemory> {
    if text.contains(&0) {
        return Ok(None);
    }
    let mut z = Vec::new();
    z.try_reserve_exact(text.len() + 1)?;
    z.try_extend_from_slice(text)?;
    z.try_push(0)?;
    Ok(Some(z))
}

/// A C string's bytes, copied; none for NULL.
///
/// # Safety
///
/// `s` is NULL or a C string that lives for the call.
unsafe fn copied(s: *const c_char) -> Result<Option<Vec<u8>>, OutOfMemory> {
    if s.is_null() {
        return Ok(None);
    }
    // SAFETY: not NULL, a C string, as the caller says.
    let bytes = unsafe { CStr::from_ptr(s) }.to_bytes();
    let mut out = Vec::new();
    out.try_extend_from_slice(bytes)?;
    Ok(Some(out))
}

/// The bytes a `berval` holds; none for one without any.
///
/// # Safety
///
/// `bv` is a value libldap filled, living as long as `'a`.
unsafe fn bytes<'a>(bv: &sys::berval) -> Option<&'a [u8]> {
    if bv.bv_val.is_null() {
        return None;
    }
    let len = usize::try_from(bv.bv_len).expect("a length in memory");
    // SAFETY: libldap's value: `bv_len` bytes at `bv_val`, which live as
    // long as the caller says.
    Some(unsafe { core::slice::from_raw_parts(bv.bv_val.cast::<u8>(), len) })
}

impl Ldap for Libldap {
    fn parse_url(&self, url: &[u8]) -> Result<Search, UrlError> {
        let mem = |OutOfMemory| UrlError::MEM;
        let Some(url) = terminated(url).map_err(mem)? else {
            return Err(UrlError::BAD_URL);
        };
        let mut lud: *mut sys::LDAPURLDesc = ptr::null_mut();
        // SAFETY: a C string, and where the description goes.
        let rc = unsafe { sys::ldap_url_parse(url.as_ptr().cast::<c_char>(), &raw mut lud) };
        if rc != sys::LDAP_URL_SUCCESS {
            if !lud.is_null() {
                // SAFETY: the library's, freed once.
                unsafe { sys::ldap_free_urldesc(lud) };
            }
            return Err(UrlError(rc));
        }
        assert!(!lud.is_null(), "a URL parsed is described");
        let search = (|| {
            // SAFETY: the description the library made, freed below.
            let d = unsafe { &*lud };
            // SAFETY: NULL or the library's C strings, alive until the
            // description is freed.
            let dn = unsafe { copied(d.lud_dn) }?;
            // SAFETY: as above.
            let filter = unsafe { copied(d.lud_filter) }?;
            let attrs = if d.lud_attrs.is_null() {
                None
            } else {
                let mut all = Vec::new();
                for i in 0.. {
                    // SAFETY: a NULL-terminated list, read up to its NULL:
                    // `i` is at most its NULL's place.
                    let at = unsafe { d.lud_attrs.add(i) };
                    // SAFETY: an element of the list, as above.
                    let a = unsafe { at.read() };
                    if a.is_null() {
                        break;
                    }
                    // SAFETY: one of the list's C strings.
                    all.try_push(unsafe { copied(a) }?.expect("not NULL"))?;
                }
                Some(all)
            };
            Ok(Search {
                dn,
                scope: d.lud_scope,
                filter,
                attrs,
            })
        })();
        // SAFETY: the library's description, freed once, not used after.
        unsafe { sys::ldap_free_urldesc(lud) };
        search.map_err(mem)
    }

    fn session(
        &self,
        fd: i32,
        scheme: &[u8],
        url: &[u8],
    ) -> Result<Result<Box<dyn Session>, Code>, NoCopy> {
        let nomem = Ok(Err(Code::NO_MEMORY));
        let (Ok(Some(scheme)), Ok(Some(url))) = (terminated(scheme), terminated(url)) else {
            return nomem;
        };
        let slot = match curl_alloc::try_box(Slot {
            wire: Cell::new(None),
        }) {
            Ok(slot) => slot,
            Err(OutOfMemory) => return nomem,
        };
        // SAFETY: the connection's socket, open while its connection is,
        // which outlives the call.
        let socket = unsafe { BorrowedFd::borrow_raw(fd) };
        // A copy of its own, close-on-exec (`F_DUPFD_CLOEXEC`): libldap
        // closes it as the session is freed.
        let copy: OwnedFd = socket.try_clone_to_owned().map_err(|_| NoCopy)?;
        // SAFETY: a C string.
        let proto = unsafe { sys::ldap_pvt_url_scheme2proto(scheme.as_ptr().cast::<c_char>()) };
        let raw = copy.into_raw_fd();
        let mut ld: *mut sys::LDAP = ptr::null_mut();
        // SAFETY: a socket of ours, a C string, and where the session goes.
        let rc =
            unsafe { sys::ldap_init_fd(raw, proto, url.as_ptr().cast::<c_char>(), &raw mut ld) };
        if rc != sys::LDAP_SUCCESS {
            // SAFETY: the copy, not taken by a session it did not make:
            // ours to close, once.
            drop(unsafe { OwnedFd::from_raw_fd(raw) });
            return Ok(Err(Code(rc)));
        }
        let made = Libsession {
            ld,
            slot,
            wired: false,
            unbound: false,
        };
        // A box that cannot be made drops the session, which frees it.
        match curl_alloc::try_box(made) {
            Ok(b) => {
                let b: Box<dyn Session> = b;
                Ok(Ok(b))
            }
            Err(OutOfMemory) => nomem,
        }
    }

    fn describe(&self, code: Code) -> &'static [u8] {
        // SAFETY: any number; the library's static words for it.
        let s = unsafe { sys::ldap_err2string(code.0) };
        assert!(!s.is_null(), "the library has words for every code");
        // SAFETY: a static C string of the library's.
        unsafe { CStr::from_ptr(s) }.to_bytes()
    }
}

/// Where a session over the connection's layers finds the wire of the
/// call it is in: set for that call only, none between calls. Boxed, so
/// its address, the layer's private pointer, stays put.
struct Slot {
    wire: Cell<Option<*mut (dyn Wire + 'static)>>,
}

/// A session: C's `ldapconninfo`'s `ld`.
struct Libsession {
    ld: *mut sys::LDAP,
    slot: Box<Slot>,
    /// Its layer over the connection's is on (C's `ssl_installed`).
    wired: bool,
    /// It unbound, and is freed.
    unbound: bool,
}

impl core::fmt::Debug for Libsession {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Libsession")
            .field("wired", &self.wired)
            .field("unbound", &self.unbound)
            .finish_non_exhaustive()
    }
}

// SAFETY: a session is tied to no thread: it is used by one thread at a
// time, whoever owns this, as C's connection uses it from whichever
// thread runs its transfer. Its slot holds a wire only during a call.
unsafe impl Send for Libsession {}

impl Libsession {
    /// Run `f` on the session with `wire` in its slot, for the layer over
    /// the connection's to use, and none after.
    fn with<R>(&mut self, wire: &mut dyn Wire, f: impl FnOnce(*mut sys::LDAP) -> R) -> R {
        assert!(!self.unbound, "a call on a session unbound");
        let wire: *mut (dyn Wire + '_) = wire;
        // SAFETY: only the lifetime is erased; the pointer leaves the
        // slot before `wire`'s borrow ends, below.
        let wire = unsafe {
            core::mem::transmute::<*mut (dyn Wire + '_), *mut (dyn Wire + 'static)>(wire)
        };
        self.slot.wire.set(Some(wire));
        let r = f(self.ld);
        self.slot.wire.set(None);
        r
    }

    /// The session's socket buffer, which its layers are on.
    fn sockbuf(&mut self) -> Option<*mut sys::Sockbuf> {
        let mut sb: *mut sys::Sockbuf = ptr::null_mut();
        // SAFETY: a live session, and where the buffer's address goes.
        let rc = unsafe {
            sys::ldap_get_option(
                self.ld,
                sys::LDAP_OPT_SOCKBUF,
                (&raw mut sb).cast::<c_void>(),
            )
        };
        (rc == sys::LDAP_OPT_SUCCESS && !sb.is_null()).then_some(sb)
    }

    fn unbind_now(&mut self) {
        if self.unbound {
            return;
        }
        self.unbound = true;
        // SAFETY: a live session, freed by the call and not used after.
        unsafe { sys::ldap_unbind_ext(self.ld, ptr::null_mut(), ptr::null_mut()) };
        self.ld = ptr::null_mut();
    }
}

impl Drop for Libsession {
    fn drop(&mut self) {
        // Its layer, if on, finds no wire: an unbind over TLS fails to
        // be sent, and the session is freed all the same.
        self.unbind_now();
    }
}

/// A message id from the call that sent it, or the library's code.
fn sent(rc: c_int, id: c_int) -> Result<MsgId, Code> {
    if rc == sys::LDAP_SUCCESS {
        Ok(MsgId(id))
    } else {
        Err(Code(rc))
    }
}

/// `items` as a NULL-terminated list of the C strings `zs` hold.
fn c_list(zs: &[Vec<u8>]) -> Result<Vec<*mut c_char>, OutOfMemory> {
    let mut list = Vec::new();
    list.try_reserve_exact(zs.len() + 1)?;
    for z in zs {
        list.try_push(z.as_ptr().cast_mut().cast::<c_char>())?;
    }
    list.try_push(ptr::null_mut())?;
    Ok(list)
}

impl Session for Libsession {
    fn set_version(&mut self, version: i32) {
        let version: c_int = version;
        // SAFETY: a live session, and the option's int.
        unsafe {
            sys::ldap_set_option(
                self.ld,
                sys::LDAP_OPT_PROTOCOL_VERSION,
                (&raw const version).cast::<c_void>(),
            )
        };
    }

    fn set_no_referrals(&mut self) {
        // SAFETY: a live session; the option takes `LDAP_OPT_OFF`, NULL.
        unsafe { sys::ldap_set_option(self.ld, sys::LDAP_OPT_REFERRALS, ptr::null()) };
    }

    fn set_max_incoming(&mut self, max: usize) -> bool {
        let Some(sb) = self.sockbuf() else {
            return false;
        };
        let mut max = sys::ber_len_t::try_from(max).expect("a length in memory");
        // SAFETY: the session's buffer, and the option's length.
        let rc = unsafe {
            sys::ber_sockbuf_ctrl(
                sb,
                sys::LBER_SB_OPT_SET_MAX_INCOMING,
                (&raw mut max).cast::<c_void>(),
            )
        };
        rc != 0
    }

    fn use_wire(&mut self) -> bool {
        let Some(sb) = self.sockbuf() else {
            return false;
        };
        let slot: *const Slot = &*self.slot;
        // SAFETY: the session's buffer; the layer's functions are a
        // static's, and its private pointer is the slot, which the
        // session owns and outlives the layer on its buffer.
        let rc = unsafe {
            sys::ber_sockbuf_add_io(
                sb,
                (&raw const LAYER).cast_mut(),
                sys::LBER_SBIOD_LEVEL_TRANSPORT,
                slot.cast_mut().cast::<c_void>(),
            )
        };
        if rc == 0 {
            self.wired = true;
        }
        rc == 0
    }

    fn uses_wire(&self) -> bool {
        self.wired
    }

    fn bind(
        &mut self,
        wire: &mut dyn Wire,
        dn: Option<&[u8]>,
        mech: Mech<'_>,
        cred: Option<&[u8]>,
    ) -> Result<MsgId, Code> {
        let nomem = |OutOfMemory| Code::NO_MEMORY;
        let dn = match dn {
            Some(dn) => Some(terminated(dn).map_err(nomem)?.ok_or(Code::NO_MEMORY)?),
            None => None,
        };
        let mech = match mech {
            Mech::Simple => None,
            Mech::Null => Some(terminated(b"").map_err(nomem)?.expect("no NUL")),
            Mech::Sasl(name) => Some(terminated(name).map_err(nomem)?.ok_or(Code::NO_MEMORY)?),
        };
        let mut bv = cred.map(|c| sys::berval {
            bv_len: sys::ber_len_t::try_from(c.len()).expect("a length in memory"),
            bv_val: c.as_ptr().cast_mut().cast::<c_char>(),
        });
        let pcred = bv.as_mut().map_or(ptr::null_mut(), ptr::from_mut);
        let mut id: c_int = 0;
        let rc = self.with(wire, |ld| {
            // SAFETY: a live session; NULL or C strings; NULL or a value
            // the library reads only; where the id goes.
            unsafe {
                sys::ldap_sasl_bind(
                    ld,
                    dn.as_ref()
                        .map_or(ptr::null(), |d| d.as_ptr().cast::<c_char>()),
                    mech.as_ref()
                        .map_or(ptr::null(), |m| m.as_ptr().cast::<c_char>()),
                    pcred,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    &raw mut id,
                )
            }
        });
        sent(rc, id)
    }

    fn search(&mut self, wire: &mut dyn Wire, search: &Search) -> Result<MsgId, Code> {
        let nomem = |OutOfMemory| Code::NO_MEMORY;
        let z = |s: &Option<Vec<u8>>| match s {
            Some(s) => terminated(s)
                .map_err(nomem)?
                .ok_or(Code::NO_MEMORY)
                .map(Some),
            None => Ok(None),
        };
        let dn = z(&search.dn)?;
        let filter = z(&search.filter)?;
        let attrs = match &search.attrs {
            Some(attrs) => {
                let mut zs = Vec::new();
                zs.try_reserve_exact(attrs.len())
                    .map_err(|_| Code::NO_MEMORY)?;
                for a in attrs {
                    zs.try_push(terminated(a).map_err(nomem)?.ok_or(Code::NO_MEMORY)?)
                        .map_err(nomem)?;
                }
                Some(zs)
            }
            None => None,
        };
        let mut list = match &attrs {
            Some(zs) => Some(c_list(zs).map_err(nomem)?),
            None => None,
        };
        let mut id: c_int = 0;
        let rc = self.with(wire, |ld| {
            // SAFETY: a live session; NULL or C strings, and NULL or a
            // NULL-terminated list of them, which the library only reads;
            // where the id goes.
            unsafe {
                sys::ldap_search_ext(
                    ld,
                    dn.as_ref()
                        .map_or(ptr::null(), |d| d.as_ptr().cast::<c_char>()),
                    search.scope,
                    filter
                        .as_ref()
                        .map_or(ptr::null(), |f| f.as_ptr().cast::<c_char>()),
                    list.as_mut().map_or(ptr::null_mut(), |l| l.as_mut_ptr()),
                    0,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    0,
                    &raw mut id,
                )
            }
        });
        sent(rc, id)
    }

    fn start_tls(&mut self, wire: &mut dyn Wire) -> Result<MsgId, Code> {
        let mut id: c_int = 0;
        let rc = self.with(wire, |ld| {
            // SAFETY: a live session, and where the id goes.
            unsafe { sys::ldap_start_tls(ld, ptr::null_mut(), ptr::null_mut(), &raw mut id) }
        });
        sent(rc, id)
    }

    fn result<'s>(
        &'s mut self,
        wire: &mut dyn Wire,
        id: MsgId,
    ) -> Result<Option<Box<dyn Message + 's>>, Code> {
        let mut msg: *mut sys::LDAPMessage = ptr::null_mut();
        let mut tv = sys::timeval {
            tv_sec: 0,
            tv_usec: 0,
        };
        let rc = self.with(wire, |ld| {
            // SAFETY: a live session, no time to wait, and where the
            // message goes.
            unsafe { sys::ldap_result(ld, id.0, sys::LDAP_MSG_ONE, &raw mut tv, &raw mut msg) }
        });
        let failed = (rc < 0).then_some(Code(rc));
        if msg.is_null() {
            return failed.map_or(Ok(None), Err);
        }
        let made = Libmessage {
            ld: self.ld,
            msg,
            ber: ptr::null_mut(),
            dn: sys::berval {
                bv_len: 0,
                bv_val: ptr::null_mut(),
            },
            vals: ptr::null_mut(),
            _session: PhantomData,
        };
        // A box that cannot be made drops the message, which frees it.
        let boxed: Box<dyn Message + 's> =
            curl_alloc::try_box(made).map_err(|OutOfMemory| Code::NO_MEMORY)?;
        Ok(Some(boxed))
    }

    fn abandon(&mut self, wire: &mut dyn Wire, id: MsgId) {
        self.with(wire, |ld| {
            // SAFETY: a live session.
            unsafe { sys::ldap_abandon_ext(ld, id.0, ptr::null_mut(), ptr::null_mut()) }
        });
    }

    fn unbind(&mut self, wire: &mut dyn Wire) {
        if self.unbound {
            return;
        }
        let wire: *mut (dyn Wire + '_) = wire;
        // SAFETY: only the lifetime is erased; the pointer leaves the
        // slot before `wire`'s borrow ends, below.
        let wire = unsafe {
            core::mem::transmute::<*mut (dyn Wire + '_), *mut (dyn Wire + 'static)>(wire)
        };
        self.slot.wire.set(Some(wire));
        self.unbind_now();
        self.slot.wire.set(None);
    }
}

/// A message, and the reading of the entry it is: C's `msg`, `ber` and
/// `bvals`, each freed when the next is read or the message dropped.
struct Libmessage<'s> {
    ld: *mut sys::LDAP,
    msg: *mut sys::LDAPMessage,
    ber: *mut sys::BerElement,
    dn: sys::berval,
    vals: *mut sys::berval,
    /// The session it came from, which outlives it.
    _session: PhantomData<&'s mut Libsession>,
}

impl Libmessage<'_> {
    fn free_vals(&mut self) {
        if !self.vals.is_null() {
            // SAFETY: the library's array, freed once.
            unsafe { sys::ber_memfree(self.vals.cast::<c_void>()) };
            self.vals = ptr::null_mut();
        }
    }
}

impl Drop for Libmessage<'_> {
    fn drop(&mut self) {
        self.free_vals();
        if !self.ber.is_null() {
            // SAFETY: the library's, freed once, its buffer the message's.
            unsafe { sys::ber_free(self.ber, 0) };
        }
        // SAFETY: the library's message, freed once.
        unsafe { sys::ldap_msgfree(self.msg) };
    }
}

impl Message for Libmessage<'_> {
    fn kind(&self) -> Kind {
        // SAFETY: a live message.
        match unsafe { sys::ldap_msgtype(self.msg) } {
            sys::LDAP_RES_BIND => Kind::Bind,
            sys::LDAP_RES_SEARCH_ENTRY => Kind::SearchEntry,
            sys::LDAP_RES_SEARCH_REFERENCE => Kind::SearchReference,
            sys::LDAP_RES_SEARCH_RESULT => Kind::SearchResult,
            sys::LDAP_RES_EXTENDED => Kind::Extended,
            other => Kind::Other(other),
        }
    }

    fn result(&mut self) -> Result<(Code, Option<Vec<u8>>), Code> {
        let mut code: c_int = 0;
        let mut info: *mut c_char = ptr::null_mut();
        // SAFETY: a live session and its message, which is kept; where
        // the code and the words go.
        let rc = unsafe {
            sys::ldap_parse_result(
                self.ld,
                self.msg,
                &raw mut code,
                ptr::null_mut(),
                &raw mut info,
                ptr::null_mut(),
                ptr::null_mut(),
                0,
            )
        };
        // SAFETY: NULL or the library's C string, freed below.
        let words = unsafe { copied(info) };
        if !info.is_null() {
            // SAFETY: allocated by the call, freed once.
            unsafe { sys::ldap_memfree(info.cast::<c_void>()) };
        }
        if rc != sys::LDAP_SUCCESS {
            return Err(Code(rc));
        }
        Ok((Code(code), words.map_err(|OutOfMemory| Code::NO_MEMORY)?))
    }

    fn bind_result(&mut self) -> Result<Option<Vec<u8>>, Code> {
        let mut cred: *mut sys::berval = ptr::null_mut();
        // SAFETY: a live session and its message, which is kept; where
        // the credentials go.
        let rc = unsafe { sys::ldap_parse_sasl_bind_result(self.ld, self.msg, &raw mut cred, 0) };
        let copy = if cred.is_null() {
            Ok(None)
        } else {
            // SAFETY: the library's value, not null, freed below.
            let cred_ref = unsafe { &*cred };
            // SAFETY: the value's bytes, alive until it is freed below.
            match unsafe { bytes(cred_ref) } {
                Some(b) => {
                    let mut v = Vec::new();
                    v.try_extend_from_slice(b).map(|()| Some(v))
                }
                None => Ok(None),
            }
        };
        if !cred.is_null() {
            // SAFETY: allocated by the call, freed once.
            unsafe { sys::ber_bvfree(cred) };
        }
        if rc != sys::LDAP_SUCCESS {
            return Err(Code(rc));
        }
        copy.map_err(|OutOfMemory| Code::NO_MEMORY)
    }

    fn dn(&mut self) -> Result<&[u8], Code> {
        assert!(self.ber.is_null(), "an entry's name is read once");
        // SAFETY: a live session and its message; where the reading and
        // the name go.
        let rc =
            unsafe { sys::ldap_get_dn_ber(self.ld, self.msg, &raw mut self.ber, &raw mut self.dn) };
        if rc < 0 {
            return Err(Code(rc));
        }
        // SAFETY: the name, in the message's buffer, alive as it is.
        Ok(unsafe { bytes(&self.dn) }.unwrap_or_default())
    }

    fn next_attribute(&mut self) -> Result<Option<Attribute<'_>>, OutOfMemory> {
        assert!(!self.ber.is_null(), "an entry's name is read first");
        self.free_vals();
        let mut name = sys::berval {
            bv_len: 0,
            bv_val: ptr::null_mut(),
        };
        // SAFETY: a live session, its message and its reading; where the
        // type and values go, the values freed with the next or the
        // message.
        let rc = unsafe {
            sys::ldap_get_attribute_ber(
                self.ld,
                self.msg,
                self.ber,
                &raw mut name,
                &raw mut self.vals,
            )
        };
        if rc != sys::LDAP_SUCCESS {
            return Ok(None);
        }
        // SAFETY: the type, in the message's buffer, alive as it is.
        let Some(name) = (unsafe { bytes(&name) }) else {
            return Ok(None);
        };
        let values = if self.vals.is_null() {
            None
        } else {
            let mut all = Vec::new();
            for i in 0.. {
                // SAFETY: an array the library ended with an empty value,
                // read up to it: `i` is at most its end's place.
                let at = unsafe { self.vals.add(i) };
                // SAFETY: an element of the array, as above.
                let bv = unsafe { &*at };
                // SAFETY: a value of the array, alive until it is freed.
                match unsafe { bytes(bv) } {
                    Some(b) => all.try_push(b)?,
                    None => break,
                }
            }
            Some(all)
        };
        Ok(Some(Attribute { name, values }))
    }
}

/// The layer through which a session over TLS reads and writes: C's
/// `ldapsb_tls`, the slot its private pointer.
static LAYER: sys::Sockbuf_IO = sys::Sockbuf_IO {
    sbi_setup: layer_setup,
    sbi_remove: layer_remove,
    sbi_ctrl: layer_ctrl,
    sbi_read: layer_read,
    sbi_write: layer_write,
    sbi_close: layer_close,
};

/// Fail a layer's call with `errno` set to `e`.
fn failing(e: c_int) -> sys::ber_slen_t {
    // SAFETY: libc's call for the calling thread's `errno`, which the
    // library reads after a failed read or write.
    let errno = unsafe { sys::__errno_location() };
    // SAFETY: the thread's `errno`, valid for the thread's life.
    unsafe { *errno = e };
    -1
}

/// The wire of the call the layer is in, if any.
///
/// # Safety
///
/// `sbiod` is the library's descriptor of the layer, its private
/// pointer the slot `use_wire` gave it.
unsafe fn wire_of<'a>(sbiod: *mut sys::Sockbuf_IO_Desc) -> Option<&'a mut dyn Wire> {
    // SAFETY: the library's descriptor, as the caller says.
    let slot = unsafe { (*sbiod).sbiod_pvt }.cast::<Slot>();
    if slot.is_null() {
        return None;
    }
    // SAFETY: the slot the session owns, which outlives its layer.
    let wire = unsafe { &*slot }.wire.get()?;
    // SAFETY: the call's wire, set for the length of the library's call
    // the layer is called within, and used by nothing else meanwhile.
    Some(unsafe { &mut *wire })
}

unsafe extern "C" fn layer_setup(sbiod: *mut sys::Sockbuf_IO_Desc, arg: *mut c_void) -> c_int {
    // SAFETY: the library's descriptor of the layer being put on.
    unsafe { (*sbiod).sbiod_pvt = arg };
    0
}

unsafe extern "C" fn layer_remove(sbiod: *mut sys::Sockbuf_IO_Desc) -> c_int {
    // SAFETY: the library's descriptor of the layer being taken off.
    unsafe { (*sbiod).sbiod_pvt = ptr::null_mut() };
    0
}

/// Nothing to close: the socket below is the session's copy, which the
/// library's own layer under this one closes.
unsafe extern "C" fn layer_close(_: *mut sys::Sockbuf_IO_Desc) -> c_int {
    0
}

unsafe extern "C" fn layer_ctrl(
    sbiod: *mut sys::Sockbuf_IO_Desc,
    opt: c_int,
    _: *mut c_void,
) -> c_int {
    if opt != sys::LBER_SB_OPT_DATA_READY {
        return 0;
    }
    // SAFETY: the library's descriptor of this layer.
    match unsafe { wire_of(sbiod) } {
        Some(wire) => c_int::from(wire.pending()),
        None => 0,
    }
}

unsafe extern "C" fn layer_read(
    sbiod: *mut sys::Sockbuf_IO_Desc,
    buf: *mut c_void,
    len: sys::ber_len_t,
) -> sys::ber_slen_t {
    // SAFETY: the library's descriptor of this layer.
    let Some(wire) = (unsafe { wire_of(sbiod) }) else {
        return failing(EINVAL);
    };
    let len = usize::try_from(len).expect("a length in memory");
    // SAFETY: the library's buffer of `len` bytes, for the call.
    let buf = unsafe { core::slice::from_raw_parts_mut(buf.cast::<u8>(), len) };
    match wire.recv(buf) {
        Ok(n) => sys::ber_slen_t::try_from(n).expect("no more than asked"),
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => failing(EWOULDBLOCK),
        Err(_) => -1,
    }
}

unsafe extern "C" fn layer_write(
    sbiod: *mut sys::Sockbuf_IO_Desc,
    buf: *mut c_void,
    len: sys::ber_len_t,
) -> sys::ber_slen_t {
    // SAFETY: the library's descriptor of this layer.
    let Some(wire) = (unsafe { wire_of(sbiod) }) else {
        return failing(EINVAL);
    };
    let len = usize::try_from(len).expect("a length in memory");
    // SAFETY: the library's `len` bytes to send, for the call.
    let bytes = unsafe { core::slice::from_raw_parts(buf.cast::<u8>().cast_const(), len) };
    match wire.send(bytes) {
        Ok(n) => sys::ber_slen_t::try_from(n).expect("no more than given"),
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => failing(EWOULDBLOCK),
        Err(_) => -1,
    }
}

/// Linux's numbers for the failures a layer gives.
const EINVAL: c_int = 22;
const EWOULDBLOCK: c_int = 11;

#[cfg(test)]
mod tests;
