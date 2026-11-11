//! Authenticating, as C's `lib/vauth` and its callers do: which party
//! what the application said may go to (`gate`), who a request
//! authenticates as (`creds`), the mechanisms any protocol may use
//! (`digest`), how HTTP picks among them from a peer's challenges
//! (`http`), and how the line protocols log in (`sasl`).

pub(crate) mod creds;
pub(crate) mod digest;
pub(crate) mod digest_sspi;
pub(crate) mod gate;
pub(crate) mod http;
pub(crate) mod sasl;
