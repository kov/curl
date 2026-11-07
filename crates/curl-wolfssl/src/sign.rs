//! Ed25519 signatures, as C's `Curl_ed25519_sign` makes them with
//! wolfCrypt: the private key imported, its public key made from it, the
//! pair imported, the message signed.

#![allow(unsafe_code)]

use core::ffi::c_int;
use core::ptr;

use curl_core::libraries::{ED25519_KEY_LEN, ED25519_SIGNATURE_LEN, Ed25519, Ed25519Error};

use crate::sys;

/// wolfCrypt's Ed25519, for a handle's `Libraries`.
pub static ED25519: WolfCryptEd25519 = WolfCryptEd25519(());

/// Signs with wolfCrypt's Ed25519; made only as `ED25519`.
pub struct WolfCryptEd25519(());

const _: () = assert!(ED25519_KEY_LEN == sys::ED25519_KEY_SIZE);
const _: () = assert!(ED25519_KEY_LEN == sys::ED25519_PUB_KEY_SIZE);
const _: () = assert!(ED25519_SIGNATURE_LEN == sys::ED25519_SIG_SIZE);

/// A key of wolfCrypt's, freed as it goes (`wc_ed25519_free`).
struct Key(ptr::NonNull<sys::ed25519_key>);

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: made by `wc_ed25519_new`, freed once.
        unsafe { sys::wc_ed25519_delete(self.0.as_ptr(), ptr::null_mut()) };
    }
}

impl Ed25519 for WolfCryptEd25519 {
    fn sign(
        &self,
        key: &[u8; ED25519_KEY_LEN],
        message: &[u8],
    ) -> Result<[u8; ED25519_SIGNATURE_LEN], Ed25519Error> {
        let len = u32::try_from(message.len()).map_err(|_| Ed25519Error::Failed)?;
        let mut rc: c_int = 0;
        // SAFETY: no heap of its own, software only; a place for its code.
        let made = unsafe { sys::wc_ed25519_new(ptr::null_mut(), sys::INVALID_DEVID, &raw mut rc) };
        let edkey = Key(ptr::NonNull::new(made).ok_or(Ed25519Error::OutOfMemory)?);
        if rc != 0 {
            return Err(Ed25519Error::Failed);
        }
        let k = edkey.0.as_ptr();
        let size = sys::ED25519_KEY_SIZE as u32;
        // SAFETY: the key's 32 bytes, which the library copies.
        if unsafe { sys::wc_ed25519_import_private_only(key.as_ptr(), size, k) } != 0 {
            return Err(Ed25519Error::Failed);
        }
        let mut public = [0u8; ED25519_KEY_LEN];
        // SAFETY: room for the public key's size.
        if unsafe { sys::wc_ed25519_make_public(k, public.as_mut_ptr(), size) } != 0 {
            return Err(Ed25519Error::Failed);
        }
        // SAFETY: both halves, of their sizes, which the library copies.
        if unsafe {
            sys::wc_ed25519_import_private_key(key.as_ptr(), size, public.as_ptr(), size, k)
        } != 0
        {
            return Err(Ed25519Error::Failed);
        }
        let mut signature = [0u8; ED25519_SIGNATURE_LEN];
        let mut out = sys::ED25519_SIG_SIZE as u32;
        // SAFETY: `len` bytes the library only reads, and room for the
        // signature's size, which it says it wrote.
        let rc = unsafe {
            sys::wc_ed25519_sign_msg(
                message.as_ptr(),
                len,
                signature.as_mut_ptr(),
                &raw mut out,
                k,
            )
        };
        if rc != 0 || out as usize != ED25519_SIGNATURE_LEN {
            return Err(Ed25519Error::Failed);
        }
        Ok(signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8032's first test vector, signed as it says.
    #[test]
    // Calls into C, which Miri cannot run.
    #[cfg_attr(miri, ignore)]
    fn signs_as_rfc_8032_says() {
        let hex = |s: &str| -> Vec<u8> {
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect()
        };
        let key: [u8; 32] = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
            .try_into()
            .unwrap();
        let want = hex(concat!(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        ));
        assert_eq!(ED25519.sign(&key, b"").unwrap().to_vec(), want);
    }
}
