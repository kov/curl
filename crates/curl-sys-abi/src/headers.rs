//! `curl_easy_header` and `curl_easy_nextheader` (`lib/headers.c`): the
//! report's header store, shown to C one header at a time.

#![allow(unsafe_code)]

use core::cell::{Cell, RefCell, UnsafeCell};
use core::ffi::{CStr, c_char, c_int, c_uint};
use core::ptr;

use curl_alloc::{OutOfMemory, TryVec as _};
use curl_core::handler::HeaderOrigin;
use curl_core::report::{HeaderCursor, HeaderError, HeaderView, Origins, Request};

use crate::easy;
use crate::ffi::{self, CURL, CURLHcode, curl_header};
use crate::gate::EasyCall;

/// A bit C sets in every origin it hands out, so that applications test
/// bits rather than compare (`copy_header_external`).
const RESERVED_ORIGIN_BIT: c_uint = 1 << 27;

/// What one of the two calls last handed out: the `curl_header` C points
/// at, the name and value it points into, and the place in the store it
/// stands for. Each call has its own, as C keeps `state.headerout[2]`.
pub(crate) struct HeaderOut {
    header: UnsafeCell<curl_header>,
    /// The name and the value, each ended by a zero byte.
    text: RefCell<Vec<u8>>,
    cursor: Cell<Option<HeaderCursor>>,
}

impl HeaderOut {
    pub(crate) fn new() -> HeaderOut {
        HeaderOut {
            header: UnsafeCell::new(curl_header {
                name: ptr::null_mut(),
                value: ptr::null_mut(),
                amount: 0,
                index: 0,
                origin: 0,
                anchor: ptr::null_mut(),
            }),
            text: RefCell::new(Vec::new()),
            cursor: Cell::new(None),
        }
    }

    fn header_ptr(&self) -> *mut curl_header {
        self.header.get()
    }

    /// Show `view` through this slot; the header C may now read.
    fn show(&self, view: &HeaderView<'_>) -> Result<*mut curl_header, OutOfMemory> {
        let mut text = Vec::new();
        text.try_reserve_exact(view.name.len() + view.value.len() + 2)
            .map_err(|_| OutOfMemory)?;
        text.try_extend_from_slice(view.name)?;
        text.try_push(0)?;
        text.try_extend_from_slice(view.value)?;
        text.try_push(0)?;
        let mut kept = self.text.borrow_mut();
        *kept = text;
        let name = kept.as_mut_ptr().cast::<c_char>();
        // SAFETY: the value starts after the name and its zero byte, inside
        // the buffer.
        let value = unsafe { name.add(view.name.len() + 1) };
        let header = curl_header {
            name,
            value,
            amount: view.amount,
            index: view.index,
            origin: origin_bit(view.origin) | RESERVED_ORIGIN_BIT,
            // Only tells `curl_easy_nextheader` the header is one of ours.
            anchor: self.header_ptr().cast(),
        };
        // SAFETY: the slot's header is written only here, during a call on
        // its handle, while C reads it only between calls.
        unsafe { self.header_ptr().write(header) };
        self.cursor.set(Some(view.cursor));
        Ok(self.header_ptr())
    }
}

/// C's bit for `origin` (`CURLH_*`).
fn origin_bit(origin: HeaderOrigin) -> c_uint {
    let bit = match origin {
        HeaderOrigin::Header => ffi::CURLH_HEADER,
        HeaderOrigin::Trailer => ffi::CURLH_TRAILER,
        HeaderOrigin::Connect => ffi::CURLH_CONNECT,
        HeaderOrigin::Interim => ffi::CURLH_1XX,
    };
    bit as c_uint
}

/// The origins C's bits name; `CURLH_PSEUDO` names none here, as no
/// HTTP/2 or HTTP/3 response is read.
fn origins(bits: c_uint) -> Origins {
    [
        HeaderOrigin::Header,
        HeaderOrigin::Trailer,
        HeaderOrigin::Connect,
        HeaderOrigin::Interim,
    ]
    .into_iter()
    .filter(|&o| bits & origin_bit(o) != 0)
    .fold(Origins::NONE, |set, o| set | o)
}

/// C's request number: -1 is the last, a request past any made is none
/// made (`CURLHE_NOREQUEST`).
fn request(n: c_int) -> Request {
    match u16::try_from(n) {
        Ok(n) => Request::Nth(n),
        Err(_) if n == -1 => Request::Last,
        Err(_) => Request::Nth(u16::MAX),
    }
}

/// # Safety
///
/// `curl` is NULL or a live handle; `name` is NULL or a C string; `hout`
/// is NULL or points where a pointer may be written.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_easy_header(
    curl: *mut CURL,
    name: *const c_char,
    index: usize,
    origin: c_uint,
    req: c_int,
    hout: *mut *mut curl_header,
) -> CURLHcode {
    // SAFETY: as the caller guarantees.
    let Some(easy) = (unsafe { easy::handle(curl) }) else {
        return ffi::CURLHE_BAD_ARGUMENT;
    };
    let Ok(_entry) = easy.enter(EasyCall::Header) else {
        // C cannot say recursion here.
        return ffi::CURLHE_BAD_ARGUMENT;
    };
    let every = ffi::CURLH_HEADER
        | ffi::CURLH_TRAILER
        | ffi::CURLH_CONNECT
        | ffi::CURLH_1XX
        | ffi::CURLH_PSEUDO;
    if name.is_null() || hout.is_null() || origin == 0 || origin > every as c_uint || req < -1 {
        return ffi::CURLHE_BAD_ARGUMENT;
    }
    // SAFETY: a C string, as the caller guarantees.
    let name = unsafe { CStr::from_ptr(name) }.to_bytes();
    let out = &easy.headers_out[0];
    let shown = easy.with_report(|r| {
        r.headers()
            .get(name, index, origins(origin), request(req))
            .map(|view| out.show(&view))
    });
    let header = match shown {
        Ok(Ok(Ok(header))) => header,
        Ok(Ok(Err(OutOfMemory))) => return ffi::CURLHE_OUT_OF_MEMORY,
        Ok(Err(e)) => {
            return match e {
                HeaderError::NoHeaders => ffi::CURLHE_NOHEADERS,
                HeaderError::NoRequest => ffi::CURLHE_NOREQUEST,
                HeaderError::Missing => ffi::CURLHE_MISSING,
                HeaderError::BadIndex => ffi::CURLHE_BADINDEX,
            };
        }
        Err(_) => return ffi::CURLHE_BAD_ARGUMENT,
    };
    // SAFETY: `hout` points where a pointer may be written.
    unsafe { hout.write(header) };
    ffi::CURLHE_OK
}
const _: ffi::proto::curl_easy_header = curl_easy_header;

/// # Safety
///
/// `curl` is NULL or a live handle; `prev` is NULL or a header a call on
/// it handed out.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_easy_nextheader(
    curl: *mut CURL,
    origin: c_uint,
    req: c_int,
    prev: *mut curl_header,
) -> *mut curl_header {
    // SAFETY: as the caller guarantees.
    let Some(easy) = (unsafe { easy::handle(curl) }) else {
        return ptr::null_mut();
    };
    let Ok(_entry) = easy.enter(EasyCall::Nextheader) else {
        return ptr::null_mut();
    };
    if req < -1 {
        return ptr::null_mut();
    }
    // A header from either call goes on from where it stands; any other
    // pointer, where C would follow it, leads nowhere.
    let from = if prev.is_null() {
        None
    } else {
        match easy.headers_out.iter().find(|o| o.header_ptr() == prev) {
            Some(o) => match o.cursor.get() {
                Some(cursor) => Some(cursor),
                None => return ptr::null_mut(),
            },
            None => return ptr::null_mut(),
        }
    };
    let out = &easy.headers_out[1];
    let shown = easy.with_report(|r| {
        r.headers()
            .next(origins(origin), request(req), from)
            .map(|view| out.show(&view))
    });
    match shown {
        Ok(Some(Ok(header))) => header,
        Ok(Some(Err(OutOfMemory)) | None) | Err(_) => ptr::null_mut(),
    }
}
const _: ffi::proto::curl_easy_nextheader = curl_easy_nextheader;

/// The slots a handle starts with.
pub(crate) fn slots() -> [HeaderOut; 2] {
    [HeaderOut::new(), HeaderOut::new()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origins_are_c_s_bits() {
        let all = ffi::CURLH_HEADER | ffi::CURLH_TRAILER | ffi::CURLH_CONNECT | ffi::CURLH_1XX;
        assert_eq!(origins(all as c_uint), Origins::ALL);
        assert_eq!(origins(ffi::CURLH_PSEUDO as c_uint), Origins::NONE);
        let one = origins(ffi::CURLH_TRAILER as c_uint);
        assert!(one.contains(HeaderOrigin::Trailer) && !one.contains(HeaderOrigin::Header));
        assert_eq!(request(-1), Request::Last);
        assert_eq!(request(3), Request::Nth(3));
        assert_eq!(request(70000), Request::Nth(u16::MAX));
    }
}
