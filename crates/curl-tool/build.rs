//! Lay the release tool's hot functions out first (`hot.order`).

// A build script is no library: aborting on a failed allocation is fine.
#![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

include!("../../.cargo/link/hot_order.rs");

fn main() {
    hot_order("hot.order", "rustc-link-arg-bin=curl=");
}
