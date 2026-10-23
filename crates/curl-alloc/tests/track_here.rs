//! A refusal for one thread alone, in a binary of its own: the tracker's
//! state is process-wide, and the other test binary leaves its limit
//! spent.

#![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

use curl_alloc::TryRc;
use curl_alloc::track::{self, Tracker};

#[global_allocator]
static ALLOCATOR: Tracker = Tracker;

fn main() {
    a_refusal_here_spares_other_threads();
    track::untracked(|| println!("test a_refusal_here_spares_other_threads ... ok"));
}

/// A refusal for this thread alone refuses its allocation, and lets one
/// another thread makes meanwhile through.
fn a_refusal_here_spares_other_threads() {
    use std::sync::atomic::{AtomicU8, Ordering};
    // 0: wait; 1: allocate; 2: it got its block; 3: it was refused.
    static STEP: AtomicU8 = AtomicU8::new(0);
    let other = track::untracked(|| {
        std::thread::spawn(|| {
            while STEP.load(Ordering::Acquire) != 1 {
                std::hint::spin_loop();
            }
            let got = TryRc::try_new(1u8).is_ok();
            STEP.store(if got { 2 } else { 3 }, Ordering::Release);
        })
    });
    let (mine, refused) = track::fail_once_after_here(0, || {
        STEP.store(1, Ordering::Release);
        while STEP.load(Ordering::Acquire) == 1 {
            std::hint::spin_loop();
        }
        TryRc::try_new(2u8).is_ok()
    });
    track::untracked(|| other.join().unwrap());
    assert_eq!(
        STEP.load(Ordering::Acquire),
        2,
        "the other thread's went through"
    );
    assert_eq!((mine, refused), (false, true));
}
