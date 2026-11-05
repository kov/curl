//! What is generic to SSPI (`secur32`), for authentication and for
//! Schannel alike: the buffer descriptions the calls take, a buffer SSPI
//! allocated, and the credential and context handles, each released as
//! it goes.

#![allow(unsafe_code)]

use core::ffi::c_void;
use core::ptr::{self, NonNull};

use curl_alloc::OutOfMemory;
use windows_sys::Win32::Security::Authentication::Identity as id;
use windows_sys::Win32::Security::Credentials::SecHandle;

/// `SECBUFFER_*`: what a buffer holds.
pub mod kind {
    pub const EMPTY: u32 = 0;
    pub const DATA: u32 = 1;
    pub const TOKEN: u32 = 2;
    pub const PKG_PARAMS: u32 = 3;
    pub const EXTRA: u32 = 5;
    pub const STREAM_TRAILER: u32 = 6;
    pub const STREAM_HEADER: u32 = 7;
    pub const PADDING: u32 = 9;
    pub const STREAM: u32 = 10;
    pub const ALERT: u32 = 17;
    pub const APPLICATION_PROTOCOLS: u32 = 18;
}

/// `SECBUFFER_VERSION`.
const VERSION: u32 = 0;

/// A buffer description of `kind` over `len` bytes at `data`.
pub fn buffer(kind: u32, data: *mut c_void, len: u32) -> id::SecBuffer {
    id::SecBuffer {
        cbBuffer: len,
        BufferType: kind,
        pvBuffer: data,
    }
}

/// An empty buffer description.
pub fn empty() -> id::SecBuffer {
    buffer(kind::EMPTY, ptr::null_mut(), 0)
}

/// The description of `buffers`.
pub fn desc(buffers: &mut [id::SecBuffer]) -> id::SecBufferDesc {
    id::SecBufferDesc {
        ulVersion: VERSION,
        cBuffers: u32::try_from(buffers.len()).expect("a few"),
        pBuffers: buffers.as_mut_ptr(),
    }
}

/// A buffer SSPI allocated and handed over, freed as it goes.
pub struct Token {
    data: NonNull<u8>,
    len: usize,
}

// SAFETY: memory SSPI allocated for the caller, freed from any thread.
unsafe impl Send for Token {}

impl Token {
    /// Take over the buffer `b` says SSPI allocated, if it did.
    ///
    /// # Safety
    ///
    /// `b` is a buffer description a call asked to allocate
    /// (`ISC_REQ_ALLOCATE_MEMORY`, or a call that always does) and SSPI
    /// filled: its pointer, if not null, is SSPI's to free, owned by no
    /// one else, over `cbBuffer` bytes.
    pub unsafe fn of(b: &id::SecBuffer) -> Option<Token> {
        let data = NonNull::new(b.pvBuffer.cast::<u8>())?;
        Some(Token {
            data,
            len: usize::try_from(b.cbBuffer).expect("a u32 fits"),
        })
    }

    /// Take over `data`, which SSPI allocated, as a buffer of `len`
    /// bytes.
    ///
    /// # Safety
    ///
    /// `data` is SSPI's to free, owned by no one else, and at least
    /// `len` bytes long.
    pub unsafe fn adopt(data: NonNull<u8>, len: usize) -> Token {
        Token { data, len }
    }

    pub fn bytes(&self) -> &[u8] {
        // SAFETY: the `len` bytes SSPI allocated, owned here until drop.
        unsafe { core::slice::from_raw_parts(self.data.as_ptr(), self.len) }
    }
}

impl Drop for Token {
    fn drop(&mut self) {
        // SAFETY: a buffer SSPI allocated, freed once.
        unsafe { id::FreeContextBuffer(self.data.as_ptr().cast()) };
    }
}

/// A credential handle SSPI made, freed as it goes.
pub struct CredHandle(SecHandle);

// SAFETY: a credential handle may be used by any thread, and by several
// contexts at once; SSPI serialises what it must.
unsafe impl Send for CredHandle {}
// SAFETY: as above.
unsafe impl Sync for CredHandle {}

impl CredHandle {
    /// Adopt the handle a successful `AcquireCredentialsHandle` wrote.
    ///
    /// # Safety
    ///
    /// `handle` is one SSPI made, owned by no one else.
    pub unsafe fn adopt(handle: SecHandle) -> CredHandle {
        CredHandle(handle)
    }

    pub fn as_ptr(&self) -> *const SecHandle {
        &self.0
    }
}

impl Drop for CredHandle {
    fn drop(&mut self) {
        // SAFETY: a handle SSPI made, freed once, after every context
        // made with it, each of which holds it or was deleted first.
        unsafe { id::FreeCredentialsHandle(&self.0) };
    }
}

/// A security context's handle, deleted as it goes. It stays at one
/// place, which an application may be handed.
pub struct CtxtHandle(Box<SecHandle>);

// SAFETY: a context is used by one thread at a time, which `&mut self`
// ensures; it moves between threads only whole.
unsafe impl Send for CtxtHandle {}

impl CtxtHandle {
    /// Room for the handle a first `InitializeSecurityContext` writes.
    pub fn room() -> Result<Box<SecHandle>, OutOfMemory> {
        curl_alloc::try_box(SecHandle::default())
    }

    /// Adopt the handle a first call wrote in `room`.
    ///
    /// # Safety
    ///
    /// `room` holds a context SSPI made, owned by no one else: the call
    /// that wrote it did not fail.
    pub unsafe fn adopt(room: Box<SecHandle>) -> CtxtHandle {
        CtxtHandle(room)
    }

    pub fn as_ptr(&self) -> *const SecHandle {
        &*self.0
    }

    pub fn as_mut_ptr(&mut self) -> *mut SecHandle {
        &mut *self.0
    }
}

impl Drop for CtxtHandle {
    fn drop(&mut self) {
        // SAFETY: a context SSPI made, deleted once.
        unsafe { id::DeleteSecurityContext(&*self.0) };
    }
}
