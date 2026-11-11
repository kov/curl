//! Windows' certificates (CryptoAPI, `crypt32`), as Schannel's code in C
//! uses them: stores of certificates, made in memory from PEM text,
//! imported from a PKCS #12 file or opened among the system's; the peer's
//! certificate and the store it came with; a chain built for it, against
//! the system's roots or a store of the transfer's own; and the names it
//! gives. Each handle is freed as it goes.

#![allow(unsafe_code)]

use core::ffi::c_void;
use core::ptr::{self, NonNull};

use curl_alloc::{OutOfMemory, TryVec as _};
use windows_sys::Win32::Foundation::{GetLastError, LocalFree};
use windows_sys::Win32::Security::Cryptography as wc;

/// The encodings a certificate is looked up and decoded in.
const ENCODING: u32 = wc::X509_ASN_ENCODING | wc::PKCS_7_ASN_ENCODING;

/// `CERT_ALT_NAME_IP_ADDRESS`.
const ALT_NAME_IP: u32 = 8;

/// The system's last error (`GetLastError`), for a call that failed.
pub(crate) fn last_error() -> u32 {
    // SAFETY: reads the thread's last error; no other state.
    unsafe { GetLastError() }
}

/// A store of certificates, closed as it goes.
pub(crate) struct CertStore(NonNull<c_void>);

// SAFETY: CryptoAPI stores lock themselves; a store may be used and
// closed from any thread.
unsafe impl Send for CertStore {}
// SAFETY: as above: shared, it is only read and handed to the system.
unsafe impl Sync for CertStore {}

impl Drop for CertStore {
    fn drop(&mut self) {
        // SAFETY: a store this module opened, closed once; certificates
        // still referenced keep it alive as the system counts them.
        unsafe { wc::CertCloseStore(self.0.as_ptr(), 0) };
    }
}

/// Where a system store is (`CERT_SYSTEM_STORE_*`), as a path names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StoreLocation(pub(crate) u32);

impl StoreLocation {
    /// The location `name` names (`get_cert_location`), if any.
    pub(crate) fn named(name: &[u8]) -> Option<StoreLocation> {
        let id = match name {
            b"CurrentUser" => wc::CERT_SYSTEM_STORE_CURRENT_USER_ID,
            b"LocalMachine" => wc::CERT_SYSTEM_STORE_LOCAL_MACHINE_ID,
            b"CurrentService" => wc::CERT_SYSTEM_STORE_CURRENT_SERVICE_ID,
            b"Services" => wc::CERT_SYSTEM_STORE_SERVICES_ID,
            b"Users" => wc::CERT_SYSTEM_STORE_USERS_ID,
            b"CurrentUserGroupPolicy" => wc::CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY_ID,
            b"LocalMachineGroupPolicy" => wc::CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY_ID,
            b"LocalMachineEnterprise" => wc::CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE_ID,
            _ => return None,
        };
        Some(StoreLocation(id << wc::CERT_SYSTEM_STORE_LOCATION_SHIFT))
    }
}

impl CertStore {
    /// An empty store in memory; the system's error if it cannot be made.
    pub(crate) fn memory() -> Result<CertStore, u32> {
        // SAFETY: a new memory store, of no parameter.
        let store = unsafe {
            wc::CertOpenStore(
                wc::CERT_STORE_PROV_MEMORY,
                0,
                0,
                wc::CERT_STORE_CREATE_NEW_FLAG,
                ptr::null(),
            )
        };
        NonNull::new(store).map(CertStore).ok_or_else(last_error)
    }

    /// The system store `name` (UTF-16, ended by a zero) at `location`,
    /// as it is.
    pub(crate) fn system(location: StoreLocation, name: &[u16]) -> Result<CertStore, u32> {
        assert_eq!(name.last(), Some(&0), "a name ended by a zero");
        // SAFETY: the system store provider, given a C wide string alive
        // for the call.
        let store = unsafe {
            wc::CertOpenStore(
                wc::CERT_STORE_PROV_SYSTEM_W,
                0,
                0,
                wc::CERT_STORE_OPEN_EXISTING_FLAG | location.0,
                name.as_ptr().cast(),
            )
        };
        NonNull::new(store).map(CertStore).ok_or_else(last_error)
    }

    /// The certificates and keys of the PKCS #12 data `pfx`, opened with
    /// `password` (UTF-16, ended by a zero), its keys not kept on disk
    /// (`PFXImportCertStore` with `PKCS12_NO_PERSIST_KEY`).
    pub(crate) fn pkcs12(pfx: &[u8], password: &[u16]) -> Result<CertStore, u32> {
        assert_eq!(password.last(), Some(&0), "a password ended by a zero");
        let blob = wc::CRYPT_INTEGER_BLOB {
            cbData: u32::try_from(pfx.len()).map_err(|_| 0x8007_000e_u32)?,
            pbData: pfx.as_ptr().cast_mut(),
        };
        // SAFETY: the blob names `pfx`, which the call only reads, and the
        // password is a C wide string; both alive for the call.
        let store =
            unsafe { wc::PFXImportCertStore(&blob, password.as_ptr(), wc::PKCS12_NO_PERSIST_KEY) };
        NonNull::new(store).map(CertStore).ok_or_else(last_error)
    }

    /// Add the certificate of one PEM block, `pem` (from its `-----BEGIN`
    /// line to its `-----END` line), as `add_certs_data_to_store` does:
    /// the stage that failed and the system's error if it does not go in.
    pub(crate) fn add_pem(&self, pem: &[u8]) -> Result<(), (PemStage, u32)> {
        let blob = wc::CRYPT_INTEGER_BLOB {
            cbData: u32::try_from(pem.len()).map_err(|_| (PemStage::Extract, 0))?,
            pbData: pem.as_ptr().cast_mut(),
        };
        let mut cert: *mut c_void = ptr::null_mut();
        // SAFETY: the blob names `pem`, read during the call; the
        // context, if one is made, is written to `cert` and owned here.
        let ok = unsafe {
            wc::CryptQueryObject(
                wc::CERT_QUERY_OBJECT_BLOB,
                (&raw const blob).cast(),
                wc::CERT_QUERY_CONTENT_FLAG_CERT,
                wc::CERT_QUERY_FORMAT_FLAG_BASE64_ENCODED,
                0,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut cert,
            )
        };
        if ok == 0 {
            return Err((PemStage::Extract, last_error()));
        }
        let cert = CertContext(
            NonNull::new(cert.cast::<wc::CERT_CONTEXT>()).expect("made by a call that succeeded"),
        );
        // SAFETY: the store and a certificate context, alive for the
        // call; the store takes a copy of its own.
        let added = unsafe {
            wc::CertAddCertificateContextToStore(
                self.0.as_ptr(),
                cert.0.as_ptr(),
                wc::CERT_STORE_ADD_ALWAYS,
                ptr::null_mut(),
            )
        };
        if added == 0 {
            return Err((PemStage::Add, last_error()));
        }
        Ok(())
    }

    /// The first certificate of the store that has a private key
    /// (`CERT_FIND_HAS_PRIVATE_KEY`); the system's error if none.
    pub(crate) fn first_with_key(&self) -> Result<CertContext, u32> {
        // SAFETY: the store, searched from its start with no parameter.
        let cert = unsafe {
            wc::CertFindCertificateInStore(
                self.0.as_ptr(),
                ENCODING,
                0,
                wc::CERT_FIND_HAS_PRIVATE_KEY,
                ptr::null(),
                ptr::null(),
            )
        };
        NonNull::new(cert).map(CertContext).ok_or_else(last_error)
    }

    /// The certificate of the store whose SHA-1 is `thumbprint`; none if
    /// it has none.
    pub(crate) fn find_by_hash(&self, thumbprint: &[u8; 20]) -> Option<CertContext> {
        let blob = wc::CRYPT_INTEGER_BLOB {
            cbData: 20,
            pbData: thumbprint.as_ptr().cast_mut(),
        };
        // SAFETY: the store, searched from its start for the hash the
        // blob names, alive for the call.
        let cert = unsafe {
            wc::CertFindCertificateInStore(
                self.0.as_ptr(),
                ENCODING,
                0,
                wc::CERT_FIND_HASH,
                (&raw const blob).cast(),
                ptr::null(),
            )
        };
        NonNull::new(cert).map(CertContext)
    }
}

/// Where adding a PEM certificate to a store failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PemStage {
    /// It did not decode (`CryptQueryObject`).
    Extract,
    /// The store did not take it.
    Add,
}

/// A certificate, its reference let go as it goes.
pub(crate) struct CertContext(NonNull<wc::CERT_CONTEXT>);

// SAFETY: a certificate context is reference-counted by the system and
// only read here; it may be freed from any thread.
unsafe impl Send for CertContext {}
// SAFETY: as above.
unsafe impl Sync for CertContext {}

impl Drop for CertContext {
    fn drop(&mut self) {
        // SAFETY: a reference this module holds, let go once.
        unsafe { wc::CertFreeCertificateContext(self.0.as_ptr()) };
    }
}

impl CertContext {
    /// Take over the reference `cert`, which the caller owns, if any.
    ///
    /// # Safety
    /// `cert` is null or a certificate context whose reference the caller
    /// hands over.
    pub(crate) unsafe fn adopt(cert: *const wc::CERT_CONTEXT) -> Option<CertContext> {
        NonNull::new(cert.cast_mut()).map(CertContext)
    }

    pub(crate) fn as_ptr(&self) -> *const wc::CERT_CONTEXT {
        self.0.as_ptr()
    }

    /// Its DER, if it is an X.509 certificate with any
    /// (`valid_cert_encoding`).
    pub(crate) fn der(&self) -> Option<&[u8]> {
        // SAFETY: the context is alive while `self` is; its fields are
        // the system's, read only.
        let c = unsafe { self.0.as_ref() };
        if c.dwCertEncodingType & wc::X509_ASN_ENCODING == 0
            || c.pbCertEncoded.is_null()
            || c.cbCertEncoded == 0
        {
            return None;
        }
        let len = usize::try_from(c.cbCertEncoded).expect("a u32 fits");
        // SAFETY: the encoded certificate, `cbCertEncoded` bytes the
        // context holds while it lives, borrowed no longer than `self`.
        Some(unsafe { core::slice::from_raw_parts(c.pbCertEncoded, len) })
    }

    /// The DER of each certificate in the store it came with, in the
    /// store's order, the one that is not X.509 left out; and whether the
    /// store lists the leaf last (`traverse_cert_store`: Windows 11 22H2
    /// lists the leaf first, those before it the root first). At most
    /// `most` plus one are listed.
    pub(crate) fn store_chain(&self, most: usize) -> Result<(Vec<Vec<u8>>, bool), OutOfMemory> {
        // SAFETY: the context is alive while `self` is.
        let c = unsafe { self.0.as_ref() };
        let mut out = Vec::new();
        let mut reverse = false;
        let mut current: *mut wc::CERT_CONTEXT = ptr::null_mut();
        let mut first = true;
        loop {
            // SAFETY: the store the peer's certificate came with, and the
            // context the last call gave, which this call lets go.
            current = unsafe { wc::CertEnumCertificatesInStore(c.hCertStore, current) };
            let Some(cert) = NonNull::new(current) else {
                break;
            };
            // SAFETY: a context the enumeration holds until the next call.
            let e = unsafe { cert.as_ref() };
            if first && e.pbCertEncoded != c.pbCertEncoded {
                reverse = true;
            }
            first = false;
            if e.dwCertEncodingType & wc::X509_ASN_ENCODING != 0
                && !e.pbCertEncoded.is_null()
                && e.cbCertEncoded > 0
            {
                let len = usize::try_from(e.cbCertEncoded).expect("a u32 fits");
                // SAFETY: its encoded bytes, alive until the next call.
                let der = unsafe { core::slice::from_raw_parts(e.pbCertEncoded, len) };
                let mut copy = Vec::new();
                let kept = copy
                    .try_extend_from_slice(der)
                    .and_then(|()| out.try_push(copy));
                if kept.is_err() || out.len() > most {
                    // SAFETY: the context the enumeration gave last,
                    // let go as the loop stops early.
                    unsafe { wc::CertFreeCertificateContext(current) };
                    kept?;
                    break;
                }
            }
        }
        Ok((out, reverse))
    }

    /// The DNS names the certificate gives, as `CertGetNameString` lists
    /// them with `CERT_NAME_SEARCH_ALL_NAMES_FLAG` (`cert_get_name_string`
    /// on Windows 8 and later): each as UTF-8, a name that is not left as
    /// the system's replacement. The list is refused if the system gives
    /// none, not even its end, or a second call gives it another length.
    pub(crate) fn dns_names(&self) -> Result<Vec<Vec<u8>>, NameList> {
        let flags = wc::CERT_NAME_DISABLE_IE4_UTF8_FLAG | wc::CERT_NAME_SEARCH_ALL_NAMES_FLAG;
        // SAFETY: the context, asked for the length of its names.
        let len = unsafe {
            wc::CertGetNameStringW(
                self.0.as_ptr(),
                wc::CERT_NAME_DNS_TYPE,
                flags,
                ptr::null(),
                ptr::null_mut(),
                0,
            )
        };
        if len == 0 {
            return Err(NameList::None);
        }
        let mut wide: Vec<u16> = Vec::new();
        let n = usize::try_from(len).expect("a u32 fits");
        wide.try_reserve_exact(n).map_err(|_| OutOfMemory)?;
        for _ in 0..n {
            wide.try_push(0)?;
        }
        // SAFETY: the context, and room for `len` characters.
        let got = unsafe {
            wc::CertGetNameStringW(
                self.0.as_ptr(),
                wc::CERT_NAME_DNS_TYPE,
                flags,
                ptr::null(),
                wide.as_mut_ptr(),
                len,
            )
        };
        if got != len {
            return Err(NameList::Size);
        }
        let mut names = Vec::new();
        for name in wide.split(|&c| c == 0).take_while(|n| !n.is_empty()) {
            let mut utf8 = Vec::new();
            for c in char::decode_utf16(name.iter().copied()) {
                let c = c.unwrap_or(char::REPLACEMENT_CHARACTER);
                let mut b = [0; 4];
                utf8.try_extend_from_slice(c.encode_utf8(&mut b).as_bytes())?;
            }
            names.try_push(utf8)?;
        }
        Ok(names)
    }

    /// The IP addresses its subject alternative names give, each as the
    /// bytes it holds; or why there are none to compare (C's failure
    /// texts of `get_alt_name_info`).
    pub(crate) fn ip_addresses(&self) -> Result<Vec<Vec<u8>>, AltNames> {
        // SAFETY: the context is alive while `self` is.
        let info = unsafe { self.0.as_ref() }.pCertInfo;
        if info.is_null() {
            return Err(AltNames::NoInfo);
        }
        // SAFETY: the certificate's info, the system's, read only.
        let info = unsafe { &*info };
        // SAFETY: the info's extensions, `cExtension` of them.
        let ext = unsafe {
            wc::CertFindExtension(
                wc::szOID_SUBJECT_ALT_NAME2,
                info.cExtension,
                info.rgExtension,
            )
        };
        if ext.is_null() {
            return Err(AltNames::NoExtension);
        }
        // SAFETY: an extension of the info, alive with it.
        let ext = unsafe { &*ext };
        let para = wc::CRYPT_DECODE_PARA {
            cbSize: u32::try_from(size_of::<wc::CRYPT_DECODE_PARA>()).expect("small"),
            pfnAlloc: None,
            pfnFree: None,
        };
        let mut decoded: *mut wc::CERT_ALT_NAME_INFO = ptr::null_mut();
        let mut size: u32 = 0;
        // SAFETY: the extension's value, decoded into memory the system
        // allocates (`CRYPT_DECODE_ALLOC_FLAG`), freed below with
        // `LocalFree`.
        let ok = unsafe {
            wc::CryptDecodeObjectEx(
                ENCODING,
                wc::szOID_SUBJECT_ALT_NAME2,
                ext.Value.pbData,
                ext.Value.cbData,
                wc::CRYPT_DECODE_ALLOC_FLAG | wc::CRYPT_DECODE_NOCOPY_FLAG,
                &para,
                (&raw mut decoded).cast(),
                &mut size,
            )
        };
        if ok == 0 || decoded.is_null() {
            return Err(AltNames::NoDecode);
        }
        let mut out = Vec::new();
        let mut failed = false;
        // SAFETY: the decoded names, alive until freed below.
        let names = unsafe { &*decoded };
        let count = usize::try_from(names.cAltEntry).expect("a u32 fits");
        for i in 0..count {
            // SAFETY: entry `i` of `cAltEntry`, within the array.
            let entry = unsafe { names.rgAltEntry.add(i) };
            // SAFETY: as above, alive with the decoded names.
            let entry = unsafe { &*entry };
            if entry.dwAltNameChoice != ALT_NAME_IP {
                continue;
            }
            // SAFETY: an IP address entry holds its address blob.
            let blob = unsafe { entry.Anonymous.IPAddress };
            let len = usize::try_from(blob.cbData).expect("a u32 fits");
            let bytes = if len == 0 || blob.pbData.is_null() {
                &[][..]
            } else {
                // SAFETY: the blob's bytes, alive with the decoded names.
                unsafe { core::slice::from_raw_parts(blob.pbData, len) }
            };
            let mut copy = Vec::new();
            if copy.try_extend_from_slice(bytes).is_err() || out.try_push(copy).is_err() {
                failed = true;
                break;
            }
        }
        // SAFETY: memory the decode allocated, freed once.
        unsafe { LocalFree(decoded.cast()) };
        if failed {
            return Err(AltNames::OutOfMemory);
        }
        Ok(out)
    }
}

/// Why a certificate's DNS names could not be listed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NameList {
    /// The system gave no list, not even its end.
    None,
    /// The list it gave was not as long as it said it would be.
    Size,
    OutOfMemory,
}

impl From<OutOfMemory> for NameList {
    fn from(OutOfMemory: OutOfMemory) -> Self {
        NameList::OutOfMemory
    }
}

/// Why a certificate's alternative names could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AltNames {
    NoInfo,
    NoExtension,
    NoDecode,
    OutOfMemory,
}

/// A chain engine that trusts the roots of one store alone, freed as it
/// goes.
pub(crate) struct ChainEngine(wc::HCERTCHAINENGINE);

impl Drop for ChainEngine {
    fn drop(&mut self) {
        // SAFETY: an engine this module made, freed once.
        unsafe { wc::CertFreeCertificateChainEngine(self.0) };
    }
}

impl ChainEngine {
    /// An engine whose only roots are `roots`'s, and which takes a CA
    /// among them for a root too, if `partial` (`hExclusiveRoot`,
    /// `CERT_CHAIN_EXCLUSIVE_ENABLE_CA_FLAG`).
    pub(crate) fn exclusive(roots: &CertStore, partial: bool) -> Result<ChainEngine, u32> {
        let config = wc::CERT_CHAIN_ENGINE_CONFIG {
            cbSize: u32::try_from(size_of::<wc::CERT_CHAIN_ENGINE_CONFIG>()).expect("small"),
            hExclusiveRoot: roots.0.as_ptr(),
            dwExclusiveFlags: if partial {
                wc::CERT_CHAIN_EXCLUSIVE_ENABLE_CA_FLAG
            } else {
                0
            },
            ..Default::default()
        };
        let mut engine: wc::HCERTCHAINENGINE = ptr::null_mut();
        // SAFETY: the configuration, which names the store, alive for the
        // call; the engine takes its own reference to the store.
        let ok = unsafe { wc::CertCreateCertificateChainEngine(&config, &mut engine) };
        if ok == 0 {
            return Err(last_error());
        }
        Ok(ChainEngine(engine))
    }
}

/// Build the chain of `cert` for a server's authentication, with the
/// certificates of the store it came with, by `engine` or the system's,
/// its revocation checked if `revocation`: the trust errors of its first
/// simple chain (`dwErrorStatus`), or the system's error if none could be
/// built.
pub(crate) fn chain_errors(
    engine: Option<&ChainEngine>,
    cert: &CertContext,
    revocation: bool,
) -> Result<u32, u32> {
    let mut usage = wc::szOID_PKIX_KP_SERVER_AUTH.cast_mut();
    let para = wc::CERT_CHAIN_PARA {
        cbSize: u32::try_from(size_of::<wc::CERT_CHAIN_PARA>()).expect("small"),
        RequestedUsage: wc::CERT_USAGE_MATCH {
            dwType: wc::USAGE_MATCH_TYPE_AND,
            Usage: wc::CTL_USAGE {
                cUsageIdentifier: 1,
                rgpszUsageIdentifier: &mut usage,
            },
        },
        ..Default::default()
    };
    let mut chain: *mut wc::CERT_CHAIN_CONTEXT = ptr::null_mut();
    // SAFETY: the context is alive while `cert` is.
    let more = unsafe { cert.0.as_ref() }.hCertStore;
    // SAFETY: the context is alive while `cert` is; the parameters name
    // `usage`, alive for the call; the chain made is freed below.
    let ok = unsafe {
        wc::CertGetCertificateChain(
            engine.map_or(ptr::null_mut(), |e| e.0),
            cert.0.as_ptr(),
            ptr::null(),
            more,
            &para,
            if revocation {
                wc::CERT_CHAIN_REVOCATION_CHECK_CHAIN
            } else {
                0
            },
            ptr::null(),
            &mut chain,
        )
    };
    if ok == 0 || chain.is_null() {
        return Err(last_error());
    }
    // SAFETY: the chain the call made.
    let first = unsafe { (*chain).rgpChain };
    // SAFETY: a chain context holds one simple chain at least.
    let first = unsafe { *first };
    // SAFETY: the simple chain, alive with the chain context.
    let status = unsafe { (*first).TrustStatus.dwErrorStatus };
    // SAFETY: the chain made above, freed once.
    unsafe { wc::CertFreeCertificateChain(chain) };
    Ok(status)
}

/// The trust errors `chain_errors` reports.
pub(crate) mod trust {
    use windows_sys::Win32::Security::Cryptography as wc;

    pub(crate) const NOT_TIME_VALID: u32 = wc::CERT_TRUST_IS_NOT_TIME_VALID;
    pub(crate) const NOT_TIME_NESTED: u32 = wc::CERT_TRUST_IS_NOT_TIME_NESTED;
    pub(crate) const REVOKED: u32 = wc::CERT_TRUST_IS_REVOKED;
    pub(crate) const UNTRUSTED_ROOT: u32 = wc::CERT_TRUST_IS_UNTRUSTED_ROOT;
    pub(crate) const REVOCATION_STATUS_UNKNOWN: u32 = wc::CERT_TRUST_REVOCATION_STATUS_UNKNOWN;
    pub(crate) const PARTIAL_CHAIN: u32 = wc::CERT_TRUST_IS_PARTIAL_CHAIN;
    pub(crate) const OFFLINE_REVOCATION: u32 = wc::CERT_TRUST_IS_OFFLINE_REVOCATION;
}

/// The 20 bytes of a thumbprint of 40 hex digits (`CryptStringToBinary`
/// with `CRYPT_STRING_HEX`), if it is one.
pub(crate) fn thumbprint(hex: &[u16]) -> Option<[u8; 20]> {
    let mut out = [0u8; 20];
    let mut len: u32 = 20;
    // SAFETY: `hex.len()` characters at `hex`, and room for 20 bytes.
    let ok = unsafe {
        wc::CryptStringToBinaryW(
            hex.as_ptr(),
            u32::try_from(hex.len()).ok()?,
            wc::CRYPT_STRING_HEX,
            out.as_mut_ptr(),
            &mut len,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    (ok != 0).then_some(out)
}
