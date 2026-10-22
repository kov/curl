//! The environment read under allocation failure: a refused copy of a
//! value is `OutOfMemory`, never an abort, and the reads that copy
//! nothing allocate nothing. Past the tracker's limit every tracked
//! allocation fails, so this is its own test binary without the libtest
//! harness; it runs itself again with the variables it reads set.

#![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

use curl_alloc::OutOfMemory;
use curl_alloc::track::{self, Tracker};
use curl_os::env;

#[global_allocator]
static ALLOCATOR: Tracker = Tracker;

const SET: &str = "CURL_OS_ENV_OOM_SET";
const EMPTY: &str = "CURL_OS_ENV_OOM_EMPTY";

fn main() {
    if std::env::var_os(SET).is_some() {
        return in_child();
    }
    print!("test a_refused_copy_is_out_of_memory ... ");
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .env(SET, "value")
        .env(EMPTY, "")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert_eq!(out.stdout, b"child ran\n", "{stderr}");
    println!("ok");
}

fn in_child() {
    let (read, refused) = track::fail_after(0, || env::var(SET.as_bytes()));
    assert_eq!(read, Err(OutOfMemory));
    assert!(refused, "the copy was the allocation refused");

    let (read, refused) = track::fail_after(0, || env::var(EMPTY.as_bytes()));
    assert_eq!(
        read,
        Ok(Some(Vec::new())),
        "an empty copy allocates nothing"
    );
    assert!(!refused);

    let (set, refused) = track::fail_after(0, || env::is_set(SET.as_bytes()));
    assert!(set);
    assert!(!refused);

    let mut buf = [0u8; 8];
    let (read, refused) = track::fail_after(0, || {
        env::var_into(SET.as_bytes(), &mut buf).map(<[u8]>::len)
    });
    assert_eq!(read, Some(5));
    assert!(!refused);
    assert_eq!(&buf[..5], b"value");

    // The positive control: with room, the same read copies the value.
    assert_eq!(env::var(SET.as_bytes()), Ok(Some(Vec::from(&b"value"[..]))));
    println!("child ran");
}
