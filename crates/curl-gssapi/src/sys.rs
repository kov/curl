//! MIT krb5's GSS-API (`<gssapi/gssapi.h>`): the declarations the
//! binding uses, and owners for the library's names, credentials,
//! contexts, OID sets and buffers that release them on drop. Every
//! unsafe call of the crate is here; the rest is safe.

#![allow(unsafe_code)]

use core::ffi::{c_int, c_void};
use core::ptr;

/// `OM_uint32`.
type OmUint32 = u32;

#[repr(C)]
struct GssNameStruct {
    _private: [u8; 0],
}

#[repr(C)]
struct GssCredIdStruct {
    _private: [u8; 0],
}

#[repr(C)]
struct GssCtxIdStruct {
    _private: [u8; 0],
}

/// `gss_OID_desc`. Not packed off Apple (gssapi.h:44).
#[repr(C)]
struct GssOidDesc {
    length: OmUint32,
    elements: *mut c_void,
}

/// `gss_OID_set_desc`.
#[repr(C)]
struct GssOidSetDesc {
    count: usize,
    elements: *mut GssOidDesc,
}

/// `gss_buffer_desc`.
#[repr(C)]
struct GssBufferDesc {
    length: usize,
    value: *mut c_void,
}

/// `struct gss_channel_bindings_struct`.
#[repr(C)]
struct GssChannelBindings {
    initiator_addrtype: OmUint32,
    initiator_address: GssBufferDesc,
    acceptor_addrtype: OmUint32,
    acceptor_address: GssBufferDesc,
    application_data: GssBufferDesc,
}

const EMPTY: GssBufferDesc = GssBufferDesc {
    length: 0,
    value: ptr::null_mut(),
};

pub(crate) const GSS_S_COMPLETE: u32 = 0;
pub(crate) const GSS_S_CONTINUE_NEEDED: u32 = 1;
pub(crate) const GSS_S_FAILURE: u32 = 13 << 16;

/// Whether `major` is an error: a calling or a routine error
/// (`GSS_ERROR`).
pub(crate) fn is_error(major: u32) -> bool {
    major & 0xffff_0000 != 0
}

pub(crate) const GSS_C_DELEG_FLAG: u32 = 1;
pub(crate) const GSS_C_MUTUAL_FLAG: u32 = 2;
pub(crate) const GSS_C_REPLAY_FLAG: u32 = 4;
pub(crate) const GSS_C_CONF_FLAG: u32 = 16;
pub(crate) const GSS_C_INTEG_FLAG: u32 = 32;
pub(crate) const GSS_C_DELEG_POLICY_FLAG: u32 = 32768;

const GSS_C_INITIATE: c_int = 1;
const GSS_C_INDEFINITE: OmUint32 = 0xffff_ffff;
const GSS_C_GSS_CODE: c_int = 1;
const GSS_C_MECH_CODE: c_int = 2;
const GSS_C_QOP_DEFAULT: OmUint32 = 0;

unsafe extern "C" {
    static GSS_C_NT_HOSTBASED_SERVICE: *mut GssOidDesc;

    fn gss_import_name(
        minor: *mut OmUint32,
        input_name_buffer: *mut GssBufferDesc,
        input_name_type: *mut GssOidDesc,
        output_name: *mut *mut GssNameStruct,
    ) -> OmUint32;
    fn gss_display_name(
        minor: *mut OmUint32,
        input_name: *mut GssNameStruct,
        output_name_buffer: *mut GssBufferDesc,
        output_name_type: *mut *mut GssOidDesc,
    ) -> OmUint32;
    fn gss_release_name(minor: *mut OmUint32, name: *mut *mut GssNameStruct) -> OmUint32;
    fn gss_release_buffer(minor: *mut OmUint32, buffer: *mut GssBufferDesc) -> OmUint32;
    fn gss_acquire_cred(
        minor: *mut OmUint32,
        desired_name: *mut GssNameStruct,
        time_req: OmUint32,
        desired_mechs: *mut GssOidSetDesc,
        cred_usage: c_int,
        output_cred_handle: *mut *mut GssCredIdStruct,
        actual_mechs: *mut *mut GssOidSetDesc,
        time_rec: *mut OmUint32,
    ) -> OmUint32;
    fn gss_release_cred(minor: *mut OmUint32, cred: *mut *mut GssCredIdStruct) -> OmUint32;
    fn gss_indicate_mechs(minor: *mut OmUint32, mech_set: *mut *mut GssOidSetDesc) -> OmUint32;
    fn gss_create_empty_oid_set(minor: *mut OmUint32, set: *mut *mut GssOidSetDesc) -> OmUint32;
    fn gss_add_oid_set_member(
        minor: *mut OmUint32,
        member: *mut GssOidDesc,
        set: *mut *mut GssOidSetDesc,
    ) -> OmUint32;
    fn gss_release_oid_set(minor: *mut OmUint32, set: *mut *mut GssOidSetDesc) -> OmUint32;
    fn gss_set_neg_mechs(
        minor: *mut OmUint32,
        cred: *mut GssCredIdStruct,
        mech_set: *const GssOidSetDesc,
    ) -> OmUint32;
    fn gss_init_sec_context(
        minor: *mut OmUint32,
        initiator_cred_handle: *mut GssCredIdStruct,
        context_handle: *mut *mut GssCtxIdStruct,
        target_name: *mut GssNameStruct,
        mech_type: *mut GssOidDesc,
        req_flags: OmUint32,
        time_req: OmUint32,
        input_chan_bindings: *mut GssChannelBindings,
        input_token: *mut GssBufferDesc,
        actual_mech_type: *mut *mut GssOidDesc,
        output_token: *mut GssBufferDesc,
        ret_flags: *mut OmUint32,
        time_rec: *mut OmUint32,
    ) -> OmUint32;
    fn gss_delete_sec_context(
        minor: *mut OmUint32,
        context_handle: *mut *mut GssCtxIdStruct,
        output_token: *mut GssBufferDesc,
    ) -> OmUint32;
    fn gss_inquire_context(
        minor: *mut OmUint32,
        context_handle: *mut GssCtxIdStruct,
        src_name: *mut *mut GssNameStruct,
        targ_name: *mut *mut GssNameStruct,
        lifetime_rec: *mut OmUint32,
        mech_type: *mut *mut GssOidDesc,
        ctx_flags: *mut OmUint32,
        locally_initiated: *mut c_int,
        open: *mut c_int,
    ) -> OmUint32;
    fn gss_wrap(
        minor: *mut OmUint32,
        context_handle: *mut GssCtxIdStruct,
        conf_req_flag: c_int,
        qop_req: OmUint32,
        input_message_buffer: *mut GssBufferDesc,
        conf_state: *mut c_int,
        output_message_buffer: *mut GssBufferDesc,
    ) -> OmUint32;
    fn gss_unwrap(
        minor: *mut OmUint32,
        context_handle: *mut GssCtxIdStruct,
        input_message_buffer: *mut GssBufferDesc,
        output_message_buffer: *mut GssBufferDesc,
        conf_state: *mut c_int,
        qop_state: *mut OmUint32,
    ) -> OmUint32;
    fn gss_display_status(
        minor: *mut OmUint32,
        status_value: OmUint32,
        status_type: c_int,
        mech_type: *mut GssOidDesc,
        message_context: *mut OmUint32,
        status_string: *mut GssBufferDesc,
    ) -> OmUint32;
}

/// A failed call's major and minor codes.
pub(crate) type Status = (u32, u32);

/// An input buffer over `bytes`, which the library only reads.
fn input(bytes: &[u8]) -> GssBufferDesc {
    GssBufferDesc {
        length: bytes.len(),
        value: bytes.as_ptr().cast_mut().cast(),
    }
}

/// An OID over `elements`, which the library only reads.
fn oid(elements: &'static [u8]) -> GssOidDesc {
    GssOidDesc {
        length: elements.len() as OmUint32,
        elements: elements.as_ptr().cast_mut().cast(),
    }
}

/// The bytes an OID of the library's names.
fn oid_bytes(d: &GssOidDesc) -> &[u8] {
    if d.elements.is_null() {
        return &[];
    }
    // SAFETY: an OID the library made or keeps: `elements` points to
    // `length` bytes, which live while the OID does.
    unsafe { core::slice::from_raw_parts(d.elements.cast::<u8>(), d.length as usize) }
}

/// A buffer the library filled, released with it (`gss_release_buffer`).
pub(crate) struct Buffer(GssBufferDesc);

impl Buffer {
    fn new() -> Buffer {
        Buffer(EMPTY)
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        if self.0.value.is_null() {
            return &[];
        }
        // SAFETY: the library filled the buffer: `value` points to
        // `length` bytes it allocated, which live until the release in
        // `drop`, after any borrow of `self`.
        unsafe { core::slice::from_raw_parts(self.0.value.cast::<u8>(), self.0.length) }
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        if !self.0.value.is_null() {
            let mut minor = 0;
            // SAFETY: the buffer is the library's, filled by one of its
            // calls, and released once.
            unsafe { gss_release_buffer(&mut minor, &mut self.0) };
        }
    }
}

/// How a name is to be read.
#[derive(Clone, Copy)]
pub(crate) enum NameKind {
    /// `service@host` (`GSS_C_NT_HOSTBASED_SERVICE`).
    HostBased,
    /// As the mechanism reads it (`GSS_C_NULL_OID`).
    Native,
}

/// An imported name, released with it.
pub(crate) struct Name(*mut GssNameStruct);

// SAFETY: a name is the library's object, used by one owner at a time;
// MIT krb5's names are not tied to the thread that made them.
unsafe impl Send for Name {}

impl Name {
    /// `text` imported as `kind` (`gss_import_name`).
    pub(crate) fn import(text: &[u8], kind: NameKind) -> Result<Name, Status> {
        let mut buffer = input(text);
        let mut name = ptr::null_mut();
        let mut minor = 0;
        let kind = match kind {
            // SAFETY: the library's own OID, set before any call.
            NameKind::HostBased => unsafe { GSS_C_NT_HOSTBASED_SERVICE },
            NameKind::Native => ptr::null_mut(),
        };
        // SAFETY: `buffer` points to `text`, which outlives the call and
        // which the library copies; `name` receives a new name or stays
        // NULL.
        let major = unsafe { gss_import_name(&mut minor, &mut buffer, kind, &mut name) };
        if is_error(major) || name.is_null() {
            return Err((major, minor));
        }
        Ok(Name(name))
    }

    /// The name as the library displays it (`gss_display_name`).
    pub(crate) fn display(&self) -> Result<Buffer, Status> {
        let mut out = Buffer::new();
        let mut minor = 0;
        // SAFETY: `self.0` is a live name; `out` receives a buffer the
        // library allocates, released with `out`.
        let major = unsafe { gss_display_name(&mut minor, self.0, &mut out.0, ptr::null_mut()) };
        if is_error(major) {
            return Err((major, minor));
        }
        Ok(out)
    }
}

impl Drop for Name {
    fn drop(&mut self) {
        let mut minor = 0;
        // SAFETY: `self.0` came from the library and is released once.
        unsafe { gss_release_name(&mut minor, &mut self.0) };
    }
}

/// Credentials acquired, released with them.
pub(crate) struct Cred(*mut GssCredIdStruct);

// SAFETY: as for `Name`.
unsafe impl Send for Cred {}

impl Cred {
    /// The default credentials to initiate with (`gss_acquire_cred` with
    /// no name, for as long as they last, for every mechanism).
    pub(crate) fn acquire() -> Result<Cred, Status> {
        let mut cred = ptr::null_mut();
        let mut minor = 0;
        // SAFETY: every optional argument is NULL; `cred` receives new
        // credentials or stays NULL.
        let major = unsafe {
            gss_acquire_cred(
                &mut minor,
                ptr::null_mut(),
                GSS_C_INDEFINITE,
                ptr::null_mut(),
                GSS_C_INITIATE,
                &mut cred,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        if is_error(major) || cred.is_null() {
            return Err((major, minor));
        }
        Ok(Cred(cred))
    }

    /// Narrows the mechanisms SPNEGO may negotiate with these
    /// credentials to `set` (`gss_set_neg_mechs`).
    pub(crate) fn set_neg_mechs(&self, set: &OidSet) -> Result<(), Status> {
        let mut minor = 0;
        // SAFETY: both are live objects of the library, which only reads
        // the set.
        let major = unsafe { gss_set_neg_mechs(&mut minor, self.0, set.0) };
        if is_error(major) {
            return Err((major, minor));
        }
        Ok(())
    }
}

impl Drop for Cred {
    fn drop(&mut self) {
        let mut minor = 0;
        // SAFETY: `self.0` came from the library and is released once.
        unsafe { gss_release_cred(&mut minor, &mut self.0) };
    }
}

/// A set of OIDs the library made, released with it.
pub(crate) struct OidSet(*mut GssOidSetDesc);

impl OidSet {
    /// The mechanisms the library has (`gss_indicate_mechs`).
    pub(crate) fn mechanisms() -> Result<OidSet, Status> {
        let mut set = ptr::null_mut();
        let mut minor = 0;
        // SAFETY: `set` receives a new set or stays NULL.
        let major = unsafe { gss_indicate_mechs(&mut minor, &mut set) };
        if is_error(major) || set.is_null() {
            return Err((major, minor));
        }
        Ok(OidSet(set))
    }

    /// A copy of the set without the OID `left_out`
    /// (`gss_create_empty_oid_set`, `gss_add_oid_set_member`).
    pub(crate) fn without(&self, left_out: &[u8]) -> Result<OidSet, Status> {
        let mut set = ptr::null_mut();
        let mut minor = 0;
        // SAFETY: `set` receives a new empty set or stays NULL.
        let major = unsafe { gss_create_empty_oid_set(&mut minor, &mut set) };
        if is_error(major) || set.is_null() {
            return Err((major, minor));
        }
        let mut copy = OidSet(set);
        for member in self.members() {
            if member.0 == left_out {
                continue;
            }
            let mut minor = 0;
            // SAFETY: `member.1` points into `self`'s live elements, which
            // the library copies into `copy`'s set, moving the set if it
            // must; a failure leaves the member out, as C ignores it.
            unsafe { gss_add_oid_set_member(&mut minor, member.1, &mut copy.0) };
        }
        Ok(copy)
    }

    /// Each member's bytes, and its descriptor for the library.
    fn members(&self) -> impl Iterator<Item = (&[u8], *mut GssOidDesc)> + '_ {
        // SAFETY: the set is the library's, live while `self` is:
        // `elements` points to `count` descriptors.
        let set = unsafe { &*self.0 };
        (0..set.count).map(move |i| {
            // SAFETY: `i` is below `count`.
            let desc = unsafe { set.elements.add(i) };
            // SAFETY: `desc` points to one of the set's live descriptors.
            let d = unsafe { &*desc };
            (oid_bytes(d), desc)
        })
    }
}

impl Drop for OidSet {
    fn drop(&mut self) {
        let mut minor = 0;
        // SAFETY: `self.0` came from the library and is released once.
        unsafe { gss_release_oid_set(&mut minor, &mut self.0) };
    }
}

/// What one `gss_init_sec_context` call gave back.
pub(crate) struct Init {
    pub(crate) major: u32,
    pub(crate) minor: u32,
    pub(crate) token: Buffer,
    pub(crate) flags: u32,
}

/// A security context, NULL until its first step makes one; deleted with
/// it.
pub(crate) struct Ctx(*mut GssCtxIdStruct);

// SAFETY: as for `Name`.
unsafe impl Send for Ctx {}

impl Ctx {
    pub(crate) fn new() -> Ctx {
        Ctx(ptr::null_mut())
    }

    pub(crate) fn is_made(&self) -> bool {
        !self.0.is_null()
    }

    /// One step (`gss_init_sec_context`), with `cred` or the default
    /// credentials, to `name`, by the mechanism `mech`.
    pub(crate) fn init(
        &mut self,
        cred: Option<&Cred>,
        name: &Name,
        mech: &'static [u8],
        flags: u32,
        binding: Option<&[u8]>,
        token: Option<&[u8]>,
    ) -> Init {
        let mut mech = oid(mech);
        let mut bindings = binding.map(|data| GssChannelBindings {
            initiator_addrtype: 0,
            initiator_address: EMPTY,
            acceptor_addrtype: 0,
            acceptor_address: EMPTY,
            application_data: input(data),
        });
        let bindings = bindings.as_mut().map_or(ptr::null_mut(), |b| &raw mut *b);
        let mut token = token.map_or(EMPTY, input);
        let mut out = Buffer::new();
        let mut minor = 0;
        let mut ret_flags = 0;
        // SAFETY: the name and credentials are live; `self.0` is NULL or a
        // context the library made, which it updates in place; the OID,
        // the bindings and the input token point to memory that outlives
        // the call and that the library only reads; `out` receives a
        // buffer released with it.
        let major = unsafe {
            gss_init_sec_context(
                &mut minor,
                cred.map_or(ptr::null_mut(), |c| c.0),
                &mut self.0,
                name.0,
                &mut mech,
                flags,
                0,
                bindings,
                &mut token,
                ptr::null_mut(),
                &mut out.0,
                &mut ret_flags,
                ptr::null_mut(),
            )
        };
        Init {
            major,
            minor,
            token: out,
            flags: ret_flags,
        }
    }

    /// Whether the context's mechanism is the OID `mech`
    /// (`gss_inquire_context`).
    pub(crate) fn mech_is(&self, mech: &[u8]) -> Result<bool, Status> {
        let mut mech_type = ptr::null_mut();
        let mut minor = 0;
        // SAFETY: `self.0` is a context the library made; `mech_type`
        // receives a pointer to an OID the library keeps.
        let major = unsafe {
            gss_inquire_context(
                &mut minor,
                self.0,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut mech_type,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        if is_error(major) {
            return Err((major, minor));
        }
        if mech_type.is_null() {
            return Ok(false);
        }
        // SAFETY: the library's OID, which it keeps for as long as it is
        // loaded.
        let d = unsafe { &*mech_type };
        Ok(oid_bytes(d) == mech)
    }

    /// The name the context authenticated as (`gss_inquire_context`).
    pub(crate) fn initiator(&self) -> Result<Name, Status> {
        let mut name = ptr::null_mut();
        let mut minor = 0;
        // SAFETY: `self.0` is a context the library made; `name` receives
        // a new name or stays NULL.
        let major = unsafe {
            gss_inquire_context(
                &mut minor,
                self.0,
                &mut name,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        let name = Name(name);
        if is_error(major) || name.0.is_null() {
            // A name made anyway is released with `name`.
            return Err((major, minor));
        }
        Ok(name)
    }

    /// `message` protected for integrity only (`gss_wrap`).
    pub(crate) fn wrap(&self, message: &[u8]) -> Result<Buffer, Status> {
        let mut message = input(message);
        let mut out = Buffer::new();
        let mut minor = 0;
        // SAFETY: `self.0` is a context the library made; it only reads
        // `message`; `out` receives a buffer released with it.
        let major = unsafe {
            gss_wrap(
                &mut minor,
                self.0,
                0,
                GSS_C_QOP_DEFAULT,
                &mut message,
                ptr::null_mut(),
                &mut out.0,
            )
        };
        if is_error(major) {
            return Err((major, minor));
        }
        Ok(out)
    }

    /// The message `token` protects (`gss_unwrap`).
    pub(crate) fn unwrap(&self, token: &[u8]) -> Result<Buffer, Status> {
        let mut token = input(token);
        let mut out = Buffer::new();
        let mut minor = 0;
        // SAFETY: as for `wrap`.
        let major = unsafe {
            gss_unwrap(
                &mut minor,
                self.0,
                &mut token,
                &mut out.0,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        if is_error(major) {
            return Err((major, minor));
        }
        Ok(out)
    }
}

impl Drop for Ctx {
    fn drop(&mut self) {
        if !self.0.is_null() {
            let mut minor = 0;
            // SAFETY: `self.0` came from the library and is deleted once;
            // no token is asked for.
            unsafe { gss_delete_sec_context(&mut minor, &mut self.0, ptr::null_mut()) };
        }
    }
}

/// Which code a status's text is of.
#[derive(Clone, Copy)]
pub(crate) enum Code {
    /// The major code (`GSS_C_GSS_CODE`).
    Gss,
    /// The mechanism's minor code (`GSS_C_MECH_CODE`).
    Mech,
}

/// One message of `code`'s text (`gss_display_status`): the call's major
/// result and the message, `context` saying where the next one starts (0
/// when there is none).
pub(crate) fn display_status(status: u32, code: Code, context: &mut u32) -> (u32, Buffer) {
    let kind = match code {
        Code::Gss => GSS_C_GSS_CODE,
        Code::Mech => GSS_C_MECH_CODE,
    };
    let mut out = Buffer::new();
    let mut minor = 0;
    // SAFETY: no mechanism is named; `context` is the caller's; `out`
    // receives a buffer released with it.
    let major = unsafe {
        gss_display_status(
            &mut minor,
            status,
            kind,
            ptr::null_mut(),
            context,
            &mut out.0,
        )
    };
    (major, out)
}
