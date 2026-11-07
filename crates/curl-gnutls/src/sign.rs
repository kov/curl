//! Ed25519 signatures, as C's `Curl_ed25519_sign` makes them with
//! GnuTLS's nettle.

#![allow(unsafe_code)]

use curl_core::libraries::{ED25519_KEY_LEN, ED25519_SIGNATURE_LEN, Ed25519, Ed25519Error};

use crate::sys;

/// nettle's Ed25519, for a handle's `Libraries`.
pub static ED25519: NettleEd25519 = NettleEd25519(());

/// Signs with nettle's Ed25519; made only as `ED25519`.
pub struct NettleEd25519(());

const _: () = assert!(ED25519_KEY_LEN == sys::ED25519_KEY_SIZE);
const _: () = assert!(ED25519_SIGNATURE_LEN == sys::ED25519_SIGNATURE_SIZE);

impl Ed25519 for NettleEd25519 {
    fn sign(
        &self,
        key: &[u8; ED25519_KEY_LEN],
        message: &[u8],
    ) -> Result<[u8; ED25519_SIGNATURE_LEN], Ed25519Error> {
        let mut public = [0u8; ED25519_KEY_LEN];
        // SAFETY: `public` and `key` are the key size nettle reads and
        // writes.
        unsafe { sys::nettle_ed25519_sha512_public_key(public.as_mut_ptr(), key.as_ptr()) };
        let mut signature = [0u8; ED25519_SIGNATURE_LEN];
        // SAFETY: the keys as above, `message.len()` bytes nettle only
        // reads, and room for the signature's size.
        unsafe {
            sys::nettle_ed25519_sha512_sign(
                public.as_ptr(),
                key.as_ptr(),
                message.len(),
                message.as_ptr(),
                signature.as_mut_ptr(),
            );
        }
        Ok(signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8032's first test vector, signed as it says.
    #[test]
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
