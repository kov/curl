//! SSPI's calls (`secur32`), as `lib/curl_sspi.c` and the files under it
//! make them: in the build's text, the ANSI calls, or in the Unicode
//! build the wide ones, as C's `TCHAR` table (`Curl_pSecFn`) is either.
//! Handles are released as they go; buffers SSPI allocates are freed as
//! they are copied out.

#![allow(unsafe_code)]

use core::ffi::c_void;
use core::ptr::{self, NonNull};

use curl_alloc::{OutOfMemory, TryVec as _};
use windows_sys::Win32::Security::Authentication::Identity as id;
use windows_sys::Win32::Security::Credentials::SecHandle;

pub use crate::handle::kind;
pub use crate::handle::{CredHandle, Credentialed, CtxtHandle};
use crate::handle::{Token, buffer, desc, empty};

/// `SECPKG_ATTR_SIZES`.
const ATTR_SIZES: u32 = 0;
/// `SECPKG_CRED_ATTR_NAMES`.
const CRED_ATTR_NAMES: u32 = 1;
/// `SEC_WINNT_AUTH_IDENTITY_VERSION`.
const IDENTITY_VERSION: u32 = 0x200;
/// `SEC_WINNT_AUTH_IDENTITY_ANSI` and `_UNICODE`.
const IDENTITY_ANSI: u32 = 1;
const IDENTITY_UNICODE: u32 = 2;
/// `SECURITY_NATIVE_DREP`.
const NATIVE_DREP: u32 = 0x10;
/// `KERB_WRAP_NO_ENCRYPT`.
const WRAP_NO_ENCRYPT: u32 = 0x8000_0001;

/// Text in the build's form, ended by a zero: the ANSI code page's bytes,
/// or UTF-16 in the Unicode build. Made only by `Text::new`, so its form
/// is the build's, it ends in its zero, and SSPI's `u32` counts it.
pub struct Text {
    form: Form,
    /// Its length in characters, the zero not counted.
    len: u32,
}

enum Form {
    Ansi(Vec<u8>),
    Wide(Vec<u16>),
}

impl Text {
    /// `text` in the build's form, ended by a zero: as it is, or
    /// converted from UTF-8 to UTF-16 in the Unicode build, where text
    /// that is not UTF-8 does not convert, as C's
    /// `curlx_convert_UTF8_to_tchar` fails on it. Text longer than a
    /// `u32` counts is refused, not counted short.
    pub fn new(text: &[u8]) -> Result<Text, OutOfMemory> {
        let form = if curl_os::UNICODE {
            let s = core::str::from_utf8(text).map_err(|_| OutOfMemory)?;
            let mut w = Vec::new();
            w.try_reserve_exact(s.encode_utf16().count() + 1)
                .map_err(|_| OutOfMemory)?;
            for unit in s.encode_utf16() {
                w.try_push(unit)?;
            }
            w.try_push(0)?;
            Form::Wide(w)
        } else {
            let mut a = Vec::new();
            a.try_reserve_exact(text.len() + 1)
                .map_err(|_| OutOfMemory)?;
            a.try_extend_from_slice(text)?;
            a.try_push(0)?;
            Form::Ansi(a)
        };
        let n = match &form {
            Form::Ansi(t) => t.len(),
            Form::Wide(t) => t.len(),
        };
        let len = u32::try_from(n - 1).map_err(|_| OutOfMemory)?;
        Ok(Text { form, len })
    }

    /// Its length in characters, the zero not counted.
    fn len(&self) -> u32 {
        self.len
    }

    fn ansi(&self) -> *const u8 {
        match &self.form {
            Form::Ansi(t) => t.as_ptr(),
            Form::Wide(_) => unreachable!("the build's text is one form"),
        }
    }

    fn wide(&self) -> *const u16 {
        match &self.form {
            Form::Wide(t) => t.as_ptr(),
            Form::Ansi(_) => unreachable!("the build's text is one form"),
        }
    }

    fn is_wide(&self) -> bool {
        matches!(self.form, Form::Wide(_))
    }

    /// The bytes, ended by the zero, of the ANSI build's text.
    #[cfg(test)]
    pub(crate) fn ansi_bytes(&self) -> Option<&[u8]> {
        match &self.form {
            Form::Ansi(t) => Some(t),
            Form::Wide(_) => None,
        }
    }

    /// The units, ended by the zero, of the Unicode build's text.
    #[cfg(test)]
    pub(crate) fn wide_units(&self) -> Option<&[u16]> {
        match &self.form {
            Form::Wide(t) => Some(t),
            Form::Ansi(_) => None,
        }
    }
}

/// `n` bytes as an SSPI buffer counts them, or out of memory for more
/// than its `u32` counts: refused, never described as fewer.
fn counted(n: usize) -> Result<u32, OutOfMemory> {
    u32::try_from(n).map_err(|_| OutOfMemory)
}

/// The largest token `package` makes (`QuerySecurityPackageInfo`), or
/// the status.
pub fn max_token(package: &Text) -> Result<u32, i32> {
    let status;
    let max;
    if package.is_wide() {
        let mut info: *mut id::SecPkgInfoW = ptr::null_mut();
        // SAFETY: the name, ended by a zero, and room for the pointer.
        status = unsafe { id::QuerySecurityPackageInfoW(package.wide(), &mut info) };
        if status != 0 || info.is_null() {
            return Err(status);
        }
        // SAFETY: the record SSPI allocated, read before it is freed.
        max = unsafe { (*info).cbMaxToken };
        // SAFETY: as above, freed once.
        unsafe { id::FreeContextBuffer(info.cast()) };
    } else {
        let mut info: *mut id::SecPkgInfoA = ptr::null_mut();
        // SAFETY: as above.
        status = unsafe { id::QuerySecurityPackageInfoA(package.ansi(), &mut info) };
        if status != 0 || info.is_null() {
            return Err(status);
        }
        // SAFETY: as above.
        max = unsafe { (*info).cbMaxToken };
        // SAFETY: as above.
        unsafe { id::FreeContextBuffer(info.cast()) };
    }
    Ok(max)
}

/// Whose credentials: none for the process's user; else the user, the
/// domain and the password, each absent in an identity naming nothing
/// but the packages, and the packages, if any are named.
pub struct IdentityText {
    pub given: Option<[Text; 3]>,
    pub packages: Option<Text>,
}

/// Outbound credentials of `package` for `identity`
/// (`AcquireCredentialsHandle`), or the status.
pub fn acquire(package: &Text, identity: Option<&IdentityText>) -> Result<CredHandle, i32> {
    let mut handle = SecHandle::default();
    let len = |t: Option<&Text>| t.map_or(0, Text::len);
    let status = if package.is_wide() {
        let p = |t: Option<&Text>| t.map_or(ptr::null_mut(), |t| t.wide().cast_mut());
        let auth = identity.map(|i| {
            let [user, domain, password] = match &i.given {
                Some([u, d, w]) => [Some(u), Some(d), Some(w)],
                None => [None, None, None],
            };
            id::SEC_WINNT_AUTH_IDENTITY_EXW {
                Version: IDENTITY_VERSION,
                Length: u32::try_from(size_of::<id::SEC_WINNT_AUTH_IDENTITY_EXW>()).expect("small"),
                User: p(user),
                UserLength: len(user),
                Domain: p(domain),
                DomainLength: len(domain),
                Password: p(password),
                PasswordLength: len(password),
                Flags: IDENTITY_UNICODE,
                PackageList: p(i.packages.as_ref()),
                PackageListLength: len(i.packages.as_ref()),
            }
        });
        let auth: *const c_void = auth
            .as_ref()
            .map_or(ptr::null(), |a| ptr::from_ref(a).cast());
        // SAFETY: the name, the identity and what it points at are alive
        // for the call, which only reads them; the handle is written.
        unsafe {
            id::AcquireCredentialsHandleW(
                ptr::null(),
                package.wide(),
                id::SECPKG_CRED_OUTBOUND,
                ptr::null(),
                auth,
                None,
                ptr::null(),
                &mut handle,
                ptr::null_mut(),
            )
        }
    } else {
        let p = |t: Option<&Text>| t.map_or(ptr::null_mut(), |t| t.ansi().cast_mut());
        let auth = identity.map(|i| {
            let [user, domain, password] = match &i.given {
                Some([u, d, w]) => [Some(u), Some(d), Some(w)],
                None => [None, None, None],
            };
            id::SEC_WINNT_AUTH_IDENTITY_EXA {
                Version: IDENTITY_VERSION,
                Length: u32::try_from(size_of::<id::SEC_WINNT_AUTH_IDENTITY_EXA>()).expect("small"),
                User: p(user),
                UserLength: len(user),
                Domain: p(domain),
                DomainLength: len(domain),
                Password: p(password),
                PasswordLength: len(password),
                Flags: IDENTITY_ANSI,
                PackageList: p(i.packages.as_ref()),
                PackageListLength: len(i.packages.as_ref()),
            }
        });
        let auth: *const c_void = auth
            .as_ref()
            .map_or(ptr::null(), |a| ptr::from_ref(a).cast());
        // SAFETY: as above.
        unsafe {
            id::AcquireCredentialsHandleA(
                ptr::null(),
                package.ansi(),
                id::SECPKG_CRED_OUTBOUND,
                ptr::null(),
                auth,
                None,
                ptr::null(),
                &mut handle,
                ptr::null_mut(),
            )
        }
    };
    if status != 0 {
        return Err(status);
    }
    // SAFETY: the call succeeded and wrote a handle no one else owns.
    Ok(unsafe { CredHandle::adopt(handle) })
}

/// What an `InitializeSecurityContext` gave.
pub struct Initialized {
    pub status: i32,
    pub attrs: u32,
}

/// An input buffer: its kind and its bytes, which SSPI only reads.
pub struct In<'a> {
    pub kind: u32,
    pub bytes: &'a [u8],
}

/// What an `InitializeSecurityContext` is asked.
#[derive(Clone, Copy)]
pub struct Call<'a> {
    /// A new context replaces the one there is.
    pub fresh: bool,
    pub target: &'a Text,
    pub req: u32,
    /// `SECURITY_NATIVE_DREP`, else 0.
    pub native: bool,
    /// None passes no description.
    pub input: &'a [In<'a>],
    /// The output buffer's size; none for one SSPI allocates, which
    /// alone asks for `ISC_REQ_ALLOCATE_MEMORY`.
    pub room: Option<usize>,
}

/// `InitializeSecurityContext` with the session's credentials as `call`
/// says, on its context unless the call is fresh, in which case a new
/// context replaces it; the token into `out`.
pub fn initialize(
    session: &mut Credentialed,
    call: &Call<'_>,
    out: &mut Vec<u8>,
) -> Result<Initialized, OutOfMemory> {
    let (cred, context) = session.parts_mut();
    let Call {
        fresh,
        target,
        req,
        native,
        input,
        room,
    } = *call;
    out.clear();
    let mut inbufs = [empty(), empty(), empty()];
    assert!(input.len() <= inbufs.len(), "at most three input buffers");
    for (b, i) in inbufs.iter_mut().zip(input) {
        // An empty buffer points nowhere, as C's NULL ones do.
        let data = if i.bytes.is_empty() {
            ptr::null_mut()
        } else {
            i.bytes.as_ptr().cast_mut().cast()
        };
        *b = buffer(i.kind, data, counted(i.bytes.len())?);
    }
    let indesc = desc(&mut inbufs[..input.len()]);
    // The output's room, the caller's or SSPI's: the one choice says
    // where the token goes and whether SSPI is asked to allocate it.
    let (outbuf, req) = match room {
        Some(n) => {
            *out = curl_alloc::try_zeroed(n)?;
            (
                buffer(kind::TOKEN, out.as_mut_ptr().cast(), counted(n)?),
                req & !id::ISC_REQ_ALLOCATE_MEMORY,
            )
        }
        None => (
            buffer(kind::TOKEN, ptr::null_mut(), 0),
            req | id::ISC_REQ_ALLOCATE_MEMORY,
        ),
    };
    let mut outbuf = [outbuf];
    let mut outdesc = desc(&mut outbuf);
    let mut attrs = 0u32;
    // The context goes on in place, or a new one is written to room of
    // its own, which replaces the old once it is made.
    let mut fresh_room = None;
    let (old, new): (*const SecHandle, *mut SecHandle) = match context {
        // One pointer, read and written through: SSPI updates the handle
        // in place.
        Some(c) if !fresh => {
            let p = c.as_mut_ptr();
            (p.cast_const(), p)
        }
        _ => {
            let r = fresh_room.insert(CtxtHandle::room()?);
            (ptr::null(), &mut **r)
        }
    };
    let pinput = if input.is_empty() {
        ptr::null()
    } else {
        &raw const indesc
    };
    let status = if target.is_wide() {
        // SAFETY: the credential, the context, the target and the
        // buffers are alive for the call; SSPI reads the input, writes
        // the token into the room given or one it allocates, the
        // context's handle and the attributes.
        unsafe {
            id::InitializeSecurityContextW(
                cred.as_ptr(),
                old,
                target.wide(),
                req,
                0,
                if native { NATIVE_DREP } else { 0 },
                pinput,
                0,
                new,
                &mut outdesc,
                &mut attrs,
                ptr::null_mut(),
            )
        }
    } else {
        // SAFETY: as above.
        unsafe {
            id::InitializeSecurityContextA(
                cred.as_ptr(),
                old,
                target.ansi().cast(),
                req,
                0,
                if native { NATIVE_DREP } else { 0 },
                pinput,
                0,
                new,
                &mut outdesc,
                &mut attrs,
                ptr::null_mut(),
            )
        }
    };
    if let Some(room) = room {
        let n = usize::try_from(outbuf[0].cbBuffer).expect("a u32 fits");
        assert!(n <= room, "SSPI's token lies within the room it was given");
        out.truncate(n);
    } else if let Some(token) = {
        // SAFETY: the call was asked to allocate the token, which SSPI
        // then hands over.
        unsafe { Token::of(&outbuf[0]) }
    } {
        out.try_extend_from_slice(token.bytes())?;
    }
    if status >= 0
        && let Some(r) = fresh_room
    {
        // SAFETY: a first call that did not fail made the context.
        *context = Some(unsafe { CtxtHandle::adopt(r) });
    }
    Ok(Initialized { status, attrs })
}

/// The handle `CompleteAuthToken` is handed: a context's (none, which
/// SSPI refuses), or credentials'.
pub enum Completing<'a> {
    Context(Option<&'a CtxtHandle>),
    Credentials(&'a CredHandle),
}

/// `CompleteAuthToken` with `handle` over `token`, which it may change.
pub fn complete(handle: Completing<'_>, token: &mut Vec<u8>) -> i32 {
    let Ok(len) = counted(token.len()) else {
        return windows_sys::Win32::Foundation::SEC_E_INSUFFICIENT_MEMORY;
    };
    let mut b = [buffer(kind::TOKEN, token.as_mut_ptr().cast(), len)];
    let d = desc(&mut b);
    let handle = match handle {
        Completing::Context(context) => context.map_or(ptr::null(), CtxtHandle::as_ptr),
        Completing::Credentials(cred) => cred.as_ptr(),
    };
    // SAFETY: the handle (or none, which SSPI refuses) and the token,
    // alive for the call; SSPI writes within the token.
    let status = unsafe { id::CompleteAuthToken(handle, &d) };
    let n = usize::try_from(b[0].cbBuffer).expect("a u32 fits");
    assert!(
        n <= token.len(),
        "SSPI's token lies within the one it was given"
    );
    token.truncate(n);
    status
}

/// `MakeSignature` on `context` with Digest's parameters, `method` and
/// `uri`, the response written into `out`, a room of `room` bytes.
pub fn make_signature(
    context: &CtxtHandle,
    method: &[u8],
    uri: &[u8],
    room: usize,
    out: &mut Vec<u8>,
) -> Result<(), i32> {
    let oom = |OutOfMemory| windows_sys::Win32::Foundation::SEC_E_INSUFFICIENT_MEMORY;
    *out = curl_alloc::try_zeroed(room).map_err(oom)?;
    let param = |bytes: &[u8]| -> Result<id::SecBuffer, i32> {
        Ok(buffer(
            kind::PKG_PARAMS,
            bytes.as_ptr().cast_mut().cast(),
            counted(bytes.len()).map_err(oom)?,
        ))
    };
    let mut b = [
        buffer(kind::TOKEN, ptr::null_mut(), 0),
        param(method)?,
        param(uri)?,
        buffer(kind::PKG_PARAMS, ptr::null_mut(), 0),
        buffer(
            kind::PADDING,
            out.as_mut_ptr().cast(),
            counted(room).map_err(oom)?,
        ),
    ];
    let d = desc(&mut b);
    // SAFETY: the context and the buffers, alive for the call; SSPI reads
    // the parameters and writes within the room.
    let status = unsafe { id::MakeSignature(context.as_ptr(), 0, &d, 0) };
    if status != 0 {
        out.clear();
        return Err(status);
    }
    let n = usize::try_from(b[4].cbBuffer).expect("a u32 fits");
    assert!(
        n <= room,
        "SSPI's response lies within the room it was given"
    );
    out.truncate(n);
    Ok(())
}

/// The context's sizes (`SECPKG_ATTR_SIZES`): the trailer's and the
/// block's.
pub fn sizes(context: &CtxtHandle) -> Result<(u32, u32), i32> {
    let mut s = id::SecPkgContext_Sizes::default();
    // SAFETY: the context and room for the attribute, alive for the call.
    let status =
        unsafe { id::QueryContextAttributesW(context.as_ptr(), ATTR_SIZES, (&raw mut s).cast()) };
    if status != 0 {
        return Err(status);
    }
    Ok((s.cbSecurityTrailer, s.cbBlockSize))
}

/// Why a protecting call failed.
pub enum Failed {
    Status(i32),
    OutOfMemory,
}

/// `message` protected without encryption (`EncryptMessage` with
/// `KERB_WRAP_NO_ENCRYPT`) in a token of `trailer` bytes and padding of
/// `block`, the three laid end to end into `out`.
pub fn wrap(
    context: &CtxtHandle,
    trailer: u32,
    block: u32,
    message: &[u8],
    out: &mut Vec<u8>,
) -> Result<(), Failed> {
    let oom = |_| Failed::OutOfMemory;
    let zeroed = |n: u32| -> Result<Vec<u8>, Failed> {
        curl_alloc::try_zeroed(usize::try_from(n).expect("a u32 fits")).map_err(oom)
    };
    let mut token = zeroed(trailer)?;
    let mut data = Vec::new();
    data.try_extend_from_slice(message).map_err(oom)?;
    let mut padding = zeroed(block)?;
    let mut b = [
        buffer(kind::TOKEN, token.as_mut_ptr().cast(), trailer),
        buffer(
            kind::DATA,
            data.as_mut_ptr().cast(),
            counted(data.len()).map_err(oom)?,
        ),
        buffer(kind::PADDING, padding.as_mut_ptr().cast(), block),
    ];
    let d = desc(&mut b);
    // SAFETY: the context and the buffers, alive for the call; SSPI
    // writes within them and says how much of each it used.
    let status = unsafe { id::EncryptMessage(context.as_ptr(), WRAP_NO_ENCRYPT, &d, 0) };
    if status != 0 {
        return Err(Failed::Status(status));
    }
    out.clear();
    for (i, v) in [&token, &data, &padding].into_iter().enumerate() {
        let n = usize::try_from(b[i].cbBuffer).expect("a u32 fits");
        assert!(
            n <= v.len(),
            "SSPI's output lies within the buffer it was given"
        );
        out.try_extend_from_slice(&v[..n]).map_err(oom)?;
    }
    Ok(())
}

/// The message `token` protects (`DecryptMessage` of a stream), into
/// `out`.
pub fn unwrap(context: &CtxtHandle, token: &[u8], out: &mut Vec<u8>) -> Result<(), Failed> {
    let mut stream = Vec::new();
    stream
        .try_extend_from_slice(token)
        .map_err(|_| Failed::OutOfMemory)?;
    let base = stream.as_mut_ptr();
    let len = stream.len();
    let mut b = [
        buffer(
            kind::STREAM,
            base.cast(),
            counted(len).map_err(|OutOfMemory| Failed::OutOfMemory)?,
        ),
        buffer(kind::DATA, ptr::null_mut(), 0),
    ];
    let d = desc(&mut b);
    let mut qop = 0u32;
    // SAFETY: the context and the buffers, alive for the call; SSPI
    // decrypts within the stream and points the data buffer into it.
    let status = unsafe { id::DecryptMessage(context.as_ptr(), &d, 0, &mut qop) };
    if status != 0 {
        return Err(Failed::Status(status));
    }
    out.clear();
    let n = usize::try_from(b[1].cbBuffer).expect("a u32 fits");
    if n == 0 {
        return Ok(());
    }
    let at = (b[1].pvBuffer as usize)
        .checked_sub(base as usize)
        .filter(|at| at.checked_add(n).is_some_and(|end| end <= len))
        .expect("SSPI's message lies within the stream");
    out.try_extend_from_slice(&stream[at..at + n])
        .map_err(|_| Failed::OutOfMemory)
}

/// The name of `cred`'s user (`SECPKG_CRED_ATTR_NAMES`): ANSI bytes, or
/// UTF-16 units, as `wide` asks.
pub enum UserName {
    Ansi(Vec<u8>),
    Wide(Vec<u16>),
}

pub fn user_name(cred: &CredHandle, wide: bool) -> Result<UserName, Failed> {
    let mut name: *mut c_void = ptr::null_mut();
    let status = if wide {
        // SAFETY: the credential and room for the pointer, alive for the
        // call.
        unsafe {
            id::QueryCredentialsAttributesW(cred.as_ptr(), CRED_ATTR_NAMES, (&raw mut name).cast())
        }
    } else {
        // SAFETY: as above.
        unsafe {
            id::QueryCredentialsAttributesA(cred.as_ptr(), CRED_ATTR_NAMES, (&raw mut name).cast())
        }
    };
    if status != 0 {
        return Err(Failed::Status(status));
    }
    let Some(name) = NonNull::new(name) else {
        return Ok(if wide {
            UserName::Wide(Vec::new())
        } else {
            UserName::Ansi(Vec::new())
        });
    };
    // Freed as it goes, whatever is copied.
    // SAFETY: the name SSPI allocated and handed over; none of it is read
    // through the token.
    let _owned = unsafe { Token::adopt(name.cast(), 0) };
    let oom = |_| Failed::OutOfMemory;
    if wide {
        let p = name.as_ptr().cast::<u16>();
        let mut n = 0;
        // SAFETY: a string SSPI wrote, ended by a zero.
        while unsafe { *p.wrapping_add(n) } != 0 {
            n += 1;
        }
        // SAFETY: the `n` units counted above.
        let units = unsafe { core::slice::from_raw_parts(p, n) };
        let mut v = Vec::new();
        v.try_extend_from_slice(units).map_err(oom)?;
        Ok(UserName::Wide(v))
    } else {
        // SAFETY: as above, in bytes.
        let bytes = unsafe { core::ffi::CStr::from_ptr(name.as_ptr().cast()) }.to_bytes();
        let mut v = Vec::new();
        v.try_extend_from_slice(bytes).map_err(oom)?;
        Ok(UserName::Ansi(v))
    }
}
