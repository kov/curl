//! Ed25519 signatures, as C's `Curl_ed25519_sign` makes them with OpenSSL.

#![allow(unsafe_code)]

use core::ptr::{self, NonNull};

use curl_core::libraries::{ED25519_KEY_LEN, ED25519_SIGNATURE_LEN, Ed25519, Ed25519Error};

/// OpenSSL's Ed25519, for a handle's `Libraries`.
pub static ED25519: OpenSslEd25519 = OpenSslEd25519(());

/// Signs with OpenSSL's Ed25519; made only as `ED25519`.
pub struct OpenSslEd25519(());

impl Ed25519 for OpenSslEd25519 {
    fn sign(
        &self,
        key: &[u8; ED25519_KEY_LEN],
        message: &[u8],
    ) -> Result<[u8; ED25519_SIGNATURE_LEN], Ed25519Error> {
        crate::sys::ready().map_err(|crate::sys::TooOld| Ed25519Error::Unavailable)?;
        let key = Key::new(key).ok_or(Ed25519Error::Failed)?;
        let mut cx = DigestCx::new().ok_or(Ed25519Error::OutOfMemory)?;
        cx.sign(&key, message)
    }
}

/// An `EVP_PKEY` this owns.
struct Key(NonNull<openssl_sys::EVP_PKEY>);

impl Key {
    /// The Ed25519 key whose private part is `key`, or None if the
    /// library refuses it.
    fn new(key: &[u8; ED25519_KEY_LEN]) -> Option<Key> {
        // SAFETY: `key` is `ED25519_KEY_LEN` bytes, the length passed; the
        // library copies them, and NULL asks for no engine.
        let made = unsafe {
            openssl_sys::EVP_PKEY_new_raw_private_key(
                openssl_sys::EVP_PKEY_ED25519,
                ptr::null_mut(),
                key.as_ptr(),
                key.len(),
            )
        };
        NonNull::new(made).map(Key)
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: the key was made by `EVP_PKEY_new_raw_private_key`, is
        // owned by this and is not used again.
        unsafe { openssl_sys::EVP_PKEY_free(self.0.as_ptr()) };
    }
}

/// An `EVP_MD_CTX` this owns.
struct DigestCx(NonNull<openssl_sys::EVP_MD_CTX>);

impl DigestCx {
    /// A new context, or None if the library could not make one.
    fn new() -> Option<DigestCx> {
        // SAFETY: it takes nothing.
        NonNull::new(unsafe { openssl_sys::EVP_MD_CTX_new() }).map(DigestCx)
    }

    /// `message` signed with `key`, Ed25519 taking no digest of its own.
    fn sign(
        &mut self,
        key: &Key,
        message: &[u8],
    ) -> Result<[u8; ED25519_SIGNATURE_LEN], Ed25519Error> {
        // SAFETY: the context and the key are live; the NULLs ask for no
        // key context back, no digest (Ed25519 has its own) and no
        // engine. The context takes its own reference to the key.
        let rc = unsafe {
            openssl_sys::EVP_DigestSignInit(
                self.0.as_ptr(),
                ptr::null_mut(),
                ptr::null(),
                ptr::null_mut(),
                key.0.as_ptr(),
            )
        };
        if rc != 1 {
            return Err(Ed25519Error::Failed);
        }
        let mut signature = [0; ED25519_SIGNATURE_LEN];
        let mut len = signature.len();
        // SAFETY: the context is live and set up to sign; `signature` is
        // `len` bytes, which the library writes at most, and `message` is
        // `message.len()` bytes it only reads.
        let rc = unsafe {
            openssl_sys::EVP_DigestSign(
                self.0.as_ptr(),
                signature.as_mut_ptr(),
                &mut len,
                message.as_ptr(),
                message.len(),
            )
        };
        if rc != 1 {
            return Err(Ed25519Error::Failed);
        }
        assert_eq!(
            len, ED25519_SIGNATURE_LEN,
            "an Ed25519 signature is 64 bytes"
        );
        Ok(signature)
    }
}

impl Drop for DigestCx {
    fn drop(&mut self) {
        // SAFETY: the context was made by `EVP_MD_CTX_new`, is owned by
        // this and is not used again.
        unsafe { openssl_sys::EVP_MD_CTX_free(self.0.as_ptr()) };
    }
}
