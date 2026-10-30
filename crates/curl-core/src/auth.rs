//! Authenticating, as C's `lib/vauth` and its callers do: who a request
//! authenticates as (`creds`), the mechanisms any protocol may use
//! (`digest`), and how HTTP picks among them from a peer's challenges
//! (`http`).

pub(crate) mod creds;
pub(crate) mod digest;
pub(crate) mod http;
