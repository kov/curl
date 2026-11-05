//! Rust's bytes as the C strings and lists of them an LDAP library is
//! handed, for every library bound here.

use core::ffi::c_char;
use core::ptr;

use curl_alloc::{OutOfMemory, TryVec as _};

/// `text` with a NUL after it, for the library; none for one with a NUL
/// inside, which the library could not be given.
pub(crate) fn terminated(text: &[u8]) -> Result<Option<Vec<u8>>, OutOfMemory> {
    if text.contains(&0) {
        return Ok(None);
    }
    let mut z = Vec::new();
    z.try_reserve_exact(text.len() + 1)?;
    z.try_extend_from_slice(text)?;
    z.try_push(0)?;
    Ok(Some(z))
}

/// A NULL-terminated list of the C strings `zs` hold.
pub(crate) fn c_list(zs: &[Vec<u8>]) -> Result<Vec<*mut c_char>, OutOfMemory> {
    let mut list = Vec::new();
    list.try_reserve_exact(zs.len() + 1)?;
    for z in zs {
        list.try_push(z.as_ptr().cast_mut().cast::<c_char>())?;
    }
    list.try_push(ptr::null_mut())?;
    Ok(list)
}
