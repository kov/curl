//! Schannel through SSPI (`secur32`), as `lib/vtls/schannel.c` calls it:
//! a credential for the client's side, a security context made with it
//! and moved through the handshake by `InitializeSecurityContext`, the
//! records it decrypts and encrypts in place, the goodbye it makes, and
//! what it says of itself. The system's version, which says what Schannel
//! speaks, is read here too.

#![allow(unsafe_code)]

use core::ffi::c_void;
use core::ptr::{self, NonNull};

use curl_alloc::{OutOfMemory, try_box};
use windows_sys::Win32::Security::Authentication::Identity as id;
use windows_sys::Win32::Security::Credentials::SecHandle;
use windows_sys::Win32::Security::Cryptography::CERT_CONTEXT;

use crate::crypt::{CertContext, CertStore};

/// The status codes SSPI calls return that C tells apart.
pub(crate) mod status {
    pub(crate) const OK: i32 = 0;
    pub(crate) const CONTINUE_NEEDED: i32 = 0x0009_0312;
    pub(crate) const CONTEXT_EXPIRED: i32 = 0x0009_0317;
    pub(crate) const INCOMPLETE_CREDENTIALS: i32 = 0x0009_0320;
    pub(crate) const RENEGOTIATE: i32 = 0x0009_0321;
    pub(crate) const INSUFFICIENT_MEMORY: i32 = 0x8009_0300_u32 as i32;
    pub(crate) const INCOMPLETE_MESSAGE: i32 = 0x8009_0318_u32 as i32;
    pub(crate) const WRONG_PRINCIPAL: i32 = 0x8009_0322_u32 as i32;
    pub(crate) const UNTRUSTED_ROOT: i32 = 0x8009_0325_u32 as i32;
}

/// The flags a credential is asked for with (`SCH_CRED_*`,
/// `SCH_USE_STRONG_CRYPTO`).
pub(crate) mod cred {
    pub(crate) const NO_SERVERNAME_CHECK: u32 = 0x4;
    pub(crate) const MANUAL_CRED_VALIDATION: u32 = 0x8;
    pub(crate) const NO_DEFAULT_CREDS: u32 = 0x10;
    pub(crate) const AUTO_CRED_VALIDATION: u32 = 0x20;
    pub(crate) const USE_DEFAULT_CREDS: u32 = 0x40;
    pub(crate) const REVOCATION_CHECK_CHAIN: u32 = 0x200;
    pub(crate) const IGNORE_NO_REVOCATION_CHECK: u32 = 0x800;
    pub(crate) const IGNORE_REVOCATION_OFFLINE: u32 = 0x1000;
    pub(crate) const USE_STRONG_CRYPTO: u32 = 0x0040_0000;
}

/// The client protocols a credential enables (`SP_PROT_*_CLIENT`).
pub(crate) mod protocol {
    pub(crate) const TLS1_0: u32 = 0x80;
    pub(crate) const TLS1_1: u32 = 0x200;
    pub(crate) const TLS1_2: u32 = 0x800;
    pub(crate) const TLS1_3: u32 = 0x2000;
}

/// What a context is asked to be, and says it is (`ISC_REQ_*`,
/// `ISC_RET_*`, the same bits).
pub(crate) mod req {
    pub(crate) const REPLAY_DETECT: u32 = 0x4;
    pub(crate) const SEQUENCE_DETECT: u32 = 0x8;
    pub(crate) const CONFIDENTIALITY: u32 = 0x10;
    pub(crate) const USE_SUPPLIED_CREDS: u32 = 0x80;
    pub(crate) const ALLOCATE_MEMORY: u32 = 0x100;
    pub(crate) const STREAM: u32 = 0x8000;
}

const SECBUFFER_EMPTY: u32 = 0;
const SECBUFFER_DATA: u32 = 1;
const SECBUFFER_TOKEN: u32 = 2;
const SECBUFFER_EXTRA: u32 = 5;
const SECBUFFER_STREAM_TRAILER: u32 = 6;
const SECBUFFER_STREAM_HEADER: u32 = 7;
const SECBUFFER_ALERT: u32 = 17;
const SECBUFFER_APPLICATION_PROTOCOLS: u32 = 18;
const SECBUFFER_VERSION: u32 = 0;
const SECPKG_ATTR_STREAM_SIZES: u32 = 4;
const SECPKG_ATTR_REMOTE_CERT_CONTEXT: u32 = 0x53;
const SECPKG_ATTR_APPLICATION_PROTOCOL: u32 = 35;
const SCHANNEL_CRED_VERSION: u32 = 4;
/// `SecApplicationProtocolNegotiationStatus_Success`.
const ALPN_SUCCESS: i32 = 1;

fn buffer(kind: u32, data: *mut c_void, len: u32) -> id::SecBuffer {
    id::SecBuffer {
        cbBuffer: len,
        BufferType: kind,
        pvBuffer: data,
    }
}

fn empty() -> id::SecBuffer {
    buffer(SECBUFFER_EMPTY, ptr::null_mut(), 0)
}

fn desc(buffers: &mut [id::SecBuffer]) -> id::SecBufferDesc {
    id::SecBufferDesc {
        ulVersion: SECBUFFER_VERSION,
        cBuffers: u32::try_from(buffers.len()).expect("a few"),
        pBuffers: buffers.as_mut_ptr(),
    }
}

/// A buffer SSPI allocated and handed over, freed as it goes.
pub(crate) struct Token {
    data: NonNull<u8>,
    len: usize,
}

// SAFETY: memory SSPI allocated for the caller, freed from any thread.
unsafe impl Send for Token {}

impl Token {
    /// Take over the buffer `b` says SSPI allocated, if it did.
    fn of(b: &id::SecBuffer) -> Option<Token> {
        let data = NonNull::new(b.pvBuffer.cast::<u8>())?;
        Some(Token {
            data,
            len: usize::try_from(b.cbBuffer).expect("a u32 fits"),
        })
    }

    pub(crate) fn bytes(&self) -> &[u8] {
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

/// How a credential is made (`acquire_sspi_handle`).
pub(crate) enum CredKind<'a> {
    /// `SCH_CREDENTIALS`, which can speak TLS 1.3: Windows Server 2022 and
    /// later, with no algorithm list.
    Modern,
    /// `SCHANNEL_CRED`, with the algorithms `algs` if given.
    Legacy { algs: Option<&'a [u32]> },
}

/// What a credential is made with.
pub(crate) struct CredSpec<'a> {
    pub(crate) flags: u32,
    pub(crate) protocols: u32,
    pub(crate) client: Option<&'a CertContext>,
    pub(crate) kind: CredKind<'a>,
}

/// A client credential for Schannel, freed as it goes; with the store
/// its client certificate came from, whose key was not kept on disk and
/// so lives only as long as the store.
pub(crate) struct Credentials {
    handle: SecHandle,
    _client_store: Option<CertStore>,
}

// SAFETY: a credential handle may be used by any thread, and by several
// contexts at once; SSPI serialises what it must.
unsafe impl Send for Credentials {}
// SAFETY: as above.
unsafe impl Sync for Credentials {}

impl Drop for Credentials {
    fn drop(&mut self) {
        // SAFETY: a handle acquired below, freed once, after every
        // context made with it, each of which holds the credential.
        unsafe { id::FreeCredentialsHandle(&self.handle) };
    }
}

impl Credentials {
    /// A credential made as `spec` says (`AcquireCredentialsHandle`),
    /// holding `client_store`; the status if SSPI refuses.
    pub(crate) fn acquire(
        spec: &CredSpec<'_>,
        client_store: Option<CertStore>,
    ) -> Result<Credentials, i32> {
        let mut certs: [*mut CERT_CONTEXT; 1] = [spec
            .client
            .map_or(ptr::null_mut(), |c| c.as_ptr().cast_mut())];
        let count = u32::from(spec.client.is_some());
        let mut handle = SecHandle::default();
        let status = match spec.kind {
            CredKind::Modern => {
                let mut crypto = [id::CRYPTO_SETTINGS::default()];
                let mut tls = id::TLS_PARAMETERS {
                    grbitDisabledProtocols: !spec.protocols,
                    cDisabledCrypto: 0,
                    pDisabledCrypto: crypto.as_mut_ptr(),
                    ..Default::default()
                };
                let creds = id::SCH_CREDENTIALS {
                    dwVersion: id::SCH_CREDENTIALS_VERSION,
                    dwFlags: spec.flags,
                    cTlsParameters: 1,
                    pTlsParameters: &mut tls,
                    cCreds: count,
                    paCred: if count > 0 {
                        certs.as_mut_ptr()
                    } else {
                        ptr::null_mut()
                    },
                    ..Default::default()
                };
                // SAFETY: the credentials and what they point at are alive
                // for the call; the handle is written.
                unsafe {
                    id::AcquireCredentialsHandleW(
                        ptr::null(),
                        id::UNISP_NAME_W,
                        id::SECPKG_CRED_OUTBOUND,
                        ptr::null(),
                        (&raw const creds).cast(),
                        None,
                        ptr::null(),
                        &mut handle,
                        ptr::null_mut(),
                    )
                }
            }
            CredKind::Legacy { algs } => {
                let creds = id::SCHANNEL_CRED {
                    dwVersion: SCHANNEL_CRED_VERSION,
                    dwFlags: spec.flags,
                    grbitEnabledProtocols: spec.protocols,
                    cSupportedAlgs: algs.map_or(0, |a| u32::try_from(a.len()).expect("a few")),
                    palgSupportedAlgs: algs.map_or(ptr::null_mut(), |a| a.as_ptr().cast_mut()),
                    cCreds: count,
                    paCred: if count > 0 {
                        certs.as_mut_ptr()
                    } else {
                        ptr::null_mut()
                    },
                    ..Default::default()
                };
                // SAFETY: as above.
                unsafe {
                    id::AcquireCredentialsHandleW(
                        ptr::null(),
                        id::UNISP_NAME_W,
                        id::SECPKG_CRED_OUTBOUND,
                        ptr::null(),
                        (&raw const creds).cast(),
                        None,
                        ptr::null(),
                        &mut handle,
                        ptr::null_mut(),
                    )
                }
            }
        };
        if status != status::OK {
            return Err(status);
        }
        Ok(Credentials {
            handle,
            _client_store: client_store,
        })
    }
}

/// A security context, deleted as it goes. Its handle stays at one
/// place, which an application may be handed.
pub(crate) struct Context {
    handle: Box<SecHandle>,
}

// SAFETY: a context is used by one thread at a time, which `&mut self`
// ensures; it moves between threads only whole.
unsafe impl Send for Context {}

impl Drop for Context {
    fn drop(&mut self) {
        // SAFETY: a context this module made, deleted once.
        unsafe { id::DeleteSecurityContext(&*self.handle) };
    }
}

/// The first call's outcome (`schannel_connect_step1`).
pub(crate) struct First {
    pub(crate) status: i32,
    /// Made if the call went on: its status is a success.
    pub(crate) context: Option<Context>,
    pub(crate) token: Option<Token>,
    pub(crate) attrs: u32,
}

/// The first `InitializeSecurityContext` with `cred` for `target`
/// (UTF-16, ended by a zero), asking `req`, offering the ALPN extension
/// `alpn` if given: the context made, and the token to send.
pub(crate) fn start(
    cred: &Credentials,
    target: &[u16],
    req: u32,
    alpn: Option<&mut [u8]>,
) -> Result<First, OutOfMemory> {
    assert_eq!(target.last(), Some(&0), "a name ended by a zero");
    let mut handle = try_box(SecHandle::default())?;
    let mut inbuf = [match alpn {
        Some(a) => buffer(
            SECBUFFER_APPLICATION_PROTOCOLS,
            a.as_mut_ptr().cast(),
            u32::try_from(a.len()).expect("small"),
        ),
        None => empty(),
    }];
    let has_alpn = inbuf[0].BufferType == SECBUFFER_APPLICATION_PROTOCOLS;
    let indesc = desc(&mut inbuf);
    let mut outbuf = [buffer(SECBUFFER_EMPTY, ptr::null_mut(), 0)];
    let mut outdesc = desc(&mut outbuf);
    let mut attrs = 0u32;
    // SAFETY: the credential, the target and the buffers are alive for the
    // call; SSPI writes the new context's handle, the token it allocates
    // and the attributes.
    let status = unsafe {
        id::InitializeSecurityContextW(
            &cred.handle,
            ptr::null(),
            target.as_ptr(),
            req,
            0,
            0,
            if has_alpn { &indesc } else { ptr::null() },
            0,
            &mut *handle,
            &mut outdesc,
            &mut attrs,
            ptr::null_mut(),
        )
    };
    let token = Token::of(&outbuf[0]);
    Ok(First {
        status,
        context: (status >= 0).then_some(Context { handle }),
        token,
        attrs,
    })
}

/// A later call's outcome (`schannel_connect_step2`).
pub(crate) struct Next {
    pub(crate) status: i32,
    /// The tokens to send, in order (the `SECBUFFER_TOKEN`s); the alert
    /// SSPI may write is freed unsent, as C frees it.
    pub(crate) tokens: [Option<Token>; 3],
    /// The input SSPI did not consume, at its end, in bytes.
    pub(crate) extra: Option<usize>,
    pub(crate) attrs: u32,
}

impl Context {
    /// The handle, where it lives as long as the context: what C hands
    /// an application (`CURLINFO_TLS_SSL_PTR`).
    pub(crate) fn handle_ptr(&self) -> NonNull<c_void> {
        NonNull::from(&*self.handle).cast()
    }

    /// Move the handshake on with `input` (`InitializeSecurityContext`
    /// with the context), as `start` was.
    pub(crate) fn next(
        &mut self,
        cred: &Credentials,
        target: &[u16],
        req: u32,
        input: &mut [u8],
    ) -> Next {
        assert_eq!(target.last(), Some(&0), "a name ended by a zero");
        let mut inbuf = [
            buffer(
                SECBUFFER_TOKEN,
                input.as_mut_ptr().cast(),
                u32::try_from(input.len()).unwrap_or(u32::MAX),
            ),
            empty(),
        ];
        let indesc = desc(&mut inbuf);
        let mut outbuf = [
            buffer(SECBUFFER_TOKEN, ptr::null_mut(), 0),
            buffer(SECBUFFER_ALERT, ptr::null_mut(), 0),
            empty(),
        ];
        let mut outdesc = desc(&mut outbuf);
        let mut attrs = 0u32;
        // SAFETY: the credential, the context, the target and the buffers
        // are alive for the call; SSPI reads `input`, writes the tokens it
        // allocates and the attributes.
        let status = unsafe {
            id::InitializeSecurityContextW(
                &cred.handle,
                &*self.handle,
                target.as_ptr(),
                req,
                0,
                0,
                &indesc,
                0,
                ptr::null_mut(),
                &mut outdesc,
                &mut attrs,
                ptr::null_mut(),
            )
        };
        let token = |i: usize| {
            let t = Token::of(&outbuf[i]);
            if outbuf[i].BufferType == SECBUFFER_TOKEN {
                t
            } else {
                None
            }
        };
        Next {
            status,
            tokens: [token(0), token(1), token(2)],
            extra: (inbuf[1].BufferType == SECBUFFER_EXTRA && inbuf[1].cbBuffer > 0)
                .then(|| usize::try_from(inbuf[1].cbBuffer).expect("a u32 fits")),
            attrs,
        }
    }

    /// The goodbye's token (`schannel_shutdown`): the context told to
    /// shut down (`ApplyControlToken`), then asked for what to send.
    /// `Err` with the status if the first refuses; else the second's
    /// status and token.
    pub(crate) fn goodbye(
        &mut self,
        cred: &Credentials,
        target: &[u16],
        req: u32,
    ) -> Result<(i32, Option<Token>, u32), i32> {
        let mut shut: u32 = id::SCHANNEL_SHUTDOWN;
        let mut control = [buffer(
            SECBUFFER_TOKEN,
            (&raw mut shut).cast(),
            u32::try_from(size_of::<u32>()).expect("small"),
        )];
        let controldesc = desc(&mut control);
        // SAFETY: the context and the buffer, alive for the call.
        let applied = unsafe { id::ApplyControlToken(&*self.handle, &controldesc) };
        if applied != status::OK {
            return Err(applied);
        }
        let mut outbuf = [empty()];
        let mut outdesc = desc(&mut outbuf);
        let mut attrs = 0u32;
        let h: *mut SecHandle = &mut *self.handle;
        // SAFETY: the credential, the context (as old and new, as C passes
        // it), the target and the buffer are alive for the call.
        let status = unsafe {
            id::InitializeSecurityContextW(
                &cred.handle,
                h,
                target.as_ptr(),
                req,
                0,
                0,
                ptr::null(),
                0,
                h,
                &mut outdesc,
                &mut attrs,
                ptr::null_mut(),
            )
        };
        Ok((status, Token::of(&outbuf[0]), attrs))
    }

    /// Decrypt the records at the start of `data` in place
    /// (`DecryptMessage`).
    pub(crate) fn decrypt(&mut self, data: &mut [u8]) -> Decrypted {
        let base = data.as_mut_ptr();
        let len = data.len();
        let mut bufs = [
            buffer(
                SECBUFFER_DATA,
                base.cast(),
                u32::try_from(len).unwrap_or(u32::MAX),
            ),
            empty(),
            empty(),
            empty(),
        ];
        let d = desc(&mut bufs);
        // SAFETY: the context and the buffers, alive for the call; SSPI
        // decrypts within `data` and points the buffers into it.
        let status = unsafe { id::DecryptMessage(&*self.handle, &d, 0, ptr::null_mut()) };
        let within = |b: &id::SecBuffer| -> Option<(usize, usize)> {
            let at = (b.pvBuffer as usize).checked_sub(base as usize)?;
            let n = usize::try_from(b.cbBuffer).ok()?;
            (at.checked_add(n)? <= len).then_some((at, n))
        };
        let plain = if bufs[1].BufferType == SECBUFFER_DATA {
            Some(within(&bufs[1]).expect("SSPI's plaintext lies within the data"))
        } else {
            None
        };
        let extra = (bufs[3].BufferType == SECBUFFER_EXTRA && bufs[3].cbBuffer > 0)
            .then(|| usize::try_from(bufs[3].cbBuffer).expect("a u32 fits"));
        Decrypted {
            status,
            plain,
            extra,
        }
    }

    /// Encrypt the `len` bytes of `record` after its header's room into
    /// one record in place (`EncryptMessage`): the record's whole length
    /// and the plaintext's, or the status.
    pub(crate) fn encrypt(
        &mut self,
        sizes: &StreamSizes,
        record: &mut [u8],
        len: usize,
    ) -> Result<(usize, usize), i32> {
        let header = usize::try_from(sizes.header).expect("a u32 fits");
        let trailer = usize::try_from(sizes.trailer).expect("a u32 fits");
        assert!(
            record.len() >= header + len + trailer,
            "room for the record"
        );
        let base = record.as_mut_ptr();
        // SAFETY: offsets within `record`, checked above.
        let data = unsafe { base.add(header) };
        // SAFETY: as above.
        let tail = unsafe { base.add(header + len) };
        let mut bufs = [
            buffer(SECBUFFER_STREAM_HEADER, base.cast(), sizes.header),
            buffer(
                SECBUFFER_DATA,
                data.cast(),
                u32::try_from(len).expect("at most the largest message"),
            ),
            buffer(SECBUFFER_STREAM_TRAILER, tail.cast(), sizes.trailer),
            empty(),
        ];
        let d = desc(&mut bufs);
        // SAFETY: the context and the buffers within `record`, alive for
        // the call.
        let status = unsafe { id::EncryptMessage(&*self.handle, 0, &d, 0) };
        if status != status::OK {
            return Err(status);
        }
        let n = |i: usize| usize::try_from(bufs[i].cbBuffer).expect("a u32 fits");
        Ok((n(0) + n(1) + n(2), n(1)))
    }

    /// Its record sizes (`SECPKG_ATTR_STREAM_SIZES`).
    pub(crate) fn stream_sizes(&self) -> Result<StreamSizes, i32> {
        let mut s = id::SecPkgContext_StreamSizes::default();
        // SAFETY: the context and room for the attribute, alive for the
        // call.
        let status = unsafe {
            id::QueryContextAttributesW(
                &*self.handle,
                SECPKG_ATTR_STREAM_SIZES,
                (&raw mut s).cast(),
            )
        };
        if status != status::OK {
            return Err(status);
        }
        Ok(StreamSizes {
            header: s.cbHeader,
            trailer: s.cbTrailer,
            most: s.cbMaximumMessage,
        })
    }

    /// What ALPN chose (`SECPKG_ATTR_APPLICATION_PROTOCOL`): the protocol
    /// if the negotiation succeeded, else none; the status if SSPI says
    /// nothing.
    pub(crate) fn alpn(&self) -> Result<Option<([u8; 255], usize)>, i32> {
        let mut a = id::SecPkgContext_ApplicationProtocol::default();
        // SAFETY: as above.
        let status = unsafe {
            id::QueryContextAttributesW(
                &*self.handle,
                SECPKG_ATTR_APPLICATION_PROTOCOL,
                (&raw mut a).cast(),
            )
        };
        if status != status::OK {
            return Err(status);
        }
        Ok((a.ProtoNegoStatus == ALPN_SUCCESS)
            .then_some((a.ProtocolId, usize::from(a.ProtocolIdSize))))
    }

    /// The peer's certificate, with the store of those it sent
    /// (`SECPKG_ATTR_REMOTE_CERT_CONTEXT`); the status if there is none.
    pub(crate) fn peer_cert(&self) -> Result<CertContext, i32> {
        let mut cert: *const CERT_CONTEXT = ptr::null();
        // SAFETY: as above; the context written is a reference the caller
        // owns.
        let status = unsafe {
            id::QueryContextAttributesW(
                &*self.handle,
                SECPKG_ATTR_REMOTE_CERT_CONTEXT,
                (&raw mut cert).cast(),
            )
        };
        // SAFETY: null, or the reference the call handed over.
        let cert = unsafe { CertContext::adopt(cert) };
        match cert {
            Some(c) if status == status::OK => Ok(c),
            _ => Err(status),
        }
    }
}

/// What `decrypt` made of the records.
pub(crate) struct Decrypted {
    pub(crate) status: i32,
    /// Where the plaintext is in the data, and its length, if SSPI gave a
    /// data buffer.
    pub(crate) plain: Option<(usize, usize)>,
    /// The bytes at the data's end it did not decrypt.
    pub(crate) extra: Option<usize>,
}

/// A context's record sizes.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct StreamSizes {
    pub(crate) header: u32,
    pub(crate) trailer: u32,
    /// The most plaintext a record holds.
    pub(crate) most: u32,
}

/// The system's version: its major and minor numbers and its build
/// (`RtlGetVersion`, which no manifest bends).
pub(crate) fn windows_version() -> (u32, u32, u32) {
    let mut v = windows_sys::Win32::System::SystemInformation::OSVERSIONINFOW {
        dwOSVersionInfoSize: u32::try_from(size_of::<
            windows_sys::Win32::System::SystemInformation::OSVERSIONINFOW,
        >())
        .expect("small"),
        ..Default::default()
    };
    // SAFETY: room for the version, its size given.
    unsafe { windows_sys::Wdk::System::SystemServices::RtlGetVersion(&mut v) };
    (v.dwMajorVersion, v.dwMinorVersion, v.dwBuildNumber)
}
