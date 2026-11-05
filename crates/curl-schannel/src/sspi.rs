//! Schannel through SSPI (`secur32`), as `lib/vtls/schannel.c` calls it:
//! a credential for the client's side, a security context made with it
//! and moved through the handshake by `InitializeSecurityContext`, the
//! records it decrypts and encrypts in place, the goodbye it makes, and
//! what it says of itself. The system's version, which says what Schannel
//! speaks, is read here too. The buffers and handles are SSPI's own,
//! shared with authentication (`curl_sspi::handle`).

#![allow(unsafe_code)]

use core::ffi::c_void;
use core::ptr::{self, NonNull};

use curl_alloc::OutOfMemory;
pub(crate) use curl_sspi::handle::Token;
use curl_sspi::handle::{CredHandle, CtxtHandle, buffer, desc, empty, kind};
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

const SECPKG_ATTR_STREAM_SIZES: u32 = 4;
const SECPKG_ATTR_REMOTE_CERT_CONTEXT: u32 = 0x53;
const SECPKG_ATTR_APPLICATION_PROTOCOL: u32 = 35;
const SCHANNEL_CRED_VERSION: u32 = 4;
/// `SecApplicationProtocolNegotiationStatus_Success`.
const ALPN_SUCCESS: i32 = 1;

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
/// so lives only as long as the store. The handle is freed first: the
/// fields drop in order.
pub(crate) struct Credentials {
    handle: CredHandle,
    _client_store: Option<CertStore>,
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
            // SAFETY: the call succeeded and wrote a handle no one else
            // owns.
            handle: unsafe { CredHandle::adopt(handle) },
            _client_store: client_store,
        })
    }
}

/// A security context, deleted as it goes. Its handle stays at one
/// place, which an application may be handed.
pub(crate) struct Context {
    handle: CtxtHandle,
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
    let mut handle = CtxtHandle::room()?;
    let mut inbuf = [match alpn {
        Some(a) => buffer(
            kind::APPLICATION_PROTOCOLS,
            a.as_mut_ptr().cast(),
            u32::try_from(a.len()).expect("small"),
        ),
        None => empty(),
    }];
    let has_alpn = inbuf[0].BufferType == kind::APPLICATION_PROTOCOLS;
    let indesc = desc(&mut inbuf);
    let mut outbuf = [empty()];
    let mut outdesc = desc(&mut outbuf);
    let mut attrs = 0u32;
    // SAFETY: the credential, the target and the buffers are alive for the
    // call; SSPI writes the new context's handle, the token it allocates
    // and the attributes.
    let status = unsafe {
        id::InitializeSecurityContextW(
            cred.handle.as_ptr(),
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
    // SAFETY: the context asks SSPI to allocate its tokens
    // (`ISC_REQ_ALLOCATE_MEMORY`), which it hands over.
    let token = unsafe { Token::of(&outbuf[0]) };
    Ok(First {
        status,
        context: (status >= 0).then(|| Context {
            // SAFETY: a call that did not fail made the context.
            handle: unsafe { CtxtHandle::adopt(handle) },
        }),
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
        NonNull::new(self.handle.as_ptr().cast_mut())
            .expect("a boxed handle")
            .cast()
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
                kind::TOKEN,
                input.as_mut_ptr().cast(),
                u32::try_from(input.len()).unwrap_or(u32::MAX),
            ),
            empty(),
        ];
        let indesc = desc(&mut inbuf);
        let mut outbuf = [
            buffer(kind::TOKEN, ptr::null_mut(), 0),
            buffer(kind::ALERT, ptr::null_mut(), 0),
            empty(),
        ];
        let mut outdesc = desc(&mut outbuf);
        let mut attrs = 0u32;
        // SAFETY: the credential, the context, the target and the buffers
        // are alive for the call; SSPI reads `input`, writes the tokens it
        // allocates and the attributes.
        let status = unsafe {
            id::InitializeSecurityContextW(
                cred.handle.as_ptr(),
                self.handle.as_ptr(),
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
            // SAFETY: as in `start`.
            let t = unsafe { Token::of(&outbuf[i]) };
            if outbuf[i].BufferType == kind::TOKEN {
                t
            } else {
                None
            }
        };
        Next {
            status,
            tokens: [token(0), token(1), token(2)],
            extra: (inbuf[1].BufferType == kind::EXTRA && inbuf[1].cbBuffer > 0)
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
            kind::TOKEN,
            (&raw mut shut).cast(),
            u32::try_from(size_of::<u32>()).expect("small"),
        )];
        let controldesc = desc(&mut control);
        // SAFETY: the context and the buffer, alive for the call.
        let applied = unsafe { id::ApplyControlToken(self.handle.as_ptr(), &controldesc) };
        if applied != status::OK {
            return Err(applied);
        }
        let mut outbuf = [empty()];
        let mut outdesc = desc(&mut outbuf);
        let mut attrs = 0u32;
        let h: *mut SecHandle = self.handle.as_mut_ptr();
        // SAFETY: the credential, the context (as old and new, as C passes
        // it), the target and the buffer are alive for the call.
        let status = unsafe {
            id::InitializeSecurityContextW(
                cred.handle.as_ptr(),
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
        // SAFETY: as in `start`.
        Ok((status, unsafe { Token::of(&outbuf[0]) }, attrs))
    }

    /// Decrypt the records at the start of `data` in place
    /// (`DecryptMessage`).
    pub(crate) fn decrypt(&mut self, data: &mut [u8]) -> Decrypted {
        let base = data.as_mut_ptr();
        let len = data.len();
        let mut bufs = [
            buffer(
                kind::DATA,
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
        let status = unsafe { id::DecryptMessage(self.handle.as_ptr(), &d, 0, ptr::null_mut()) };
        let within = |b: &id::SecBuffer| -> Option<(usize, usize)> {
            let at = (b.pvBuffer as usize).checked_sub(base as usize)?;
            let n = usize::try_from(b.cbBuffer).ok()?;
            (at.checked_add(n)? <= len).then_some((at, n))
        };
        let plain = if bufs[1].BufferType == kind::DATA {
            Some(within(&bufs[1]).expect("SSPI's plaintext lies within the data"))
        } else {
            None
        };
        let extra = (bufs[3].BufferType == kind::EXTRA && bufs[3].cbBuffer > 0)
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
            buffer(kind::STREAM_HEADER, base.cast(), sizes.header),
            buffer(
                kind::DATA,
                data.cast(),
                u32::try_from(len).expect("at most the largest message"),
            ),
            buffer(kind::STREAM_TRAILER, tail.cast(), sizes.trailer),
            empty(),
        ];
        let d = desc(&mut bufs);
        // SAFETY: the context and the buffers within `record`, alive for
        // the call.
        let status = unsafe { id::EncryptMessage(self.handle.as_ptr(), 0, &d, 0) };
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
                self.handle.as_ptr(),
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
                self.handle.as_ptr(),
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
                self.handle.as_ptr(),
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
