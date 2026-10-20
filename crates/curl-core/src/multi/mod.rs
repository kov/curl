//! The multi: transfers driven together, as libcurl's multi handle drives
//! them.
//!
//! Only its timers exist yet; the multi itself uses them from milestone 1
//! step 5 (MILESTONES.md).
#![allow(dead_code)]

mod timers;
