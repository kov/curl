//! HTTP/1.0 and HTTP/1.1 (`lib/http.c`, `lib/http1.c`).

pub(crate) mod chunked;
pub(crate) mod fields;
#[cfg(test)]
pub(crate) mod fixture;
pub(crate) mod follow;
pub(crate) mod framing;
pub(crate) mod request;
pub(crate) mod response;
pub(crate) mod tunnel;
