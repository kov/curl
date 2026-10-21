//! HTTP/1.0 and HTTP/1.1 (`lib/http.c`, `lib/http1.c`).

// Rendered by the http protocol once transfers run it (step 14).
#![cfg_attr(
    not(test),
    expect(dead_code, reason = "no transfer makes a request yet")
)]

pub(crate) mod fields;
#[cfg(test)]
mod fixture;
pub(crate) mod request;
pub(crate) mod response;
