//! What the properties that input never panics the tool are built from:
//! input made of the words a parser looks for, and valid samples with
//! random bytes spliced in, as `curl-core`'s own properties make it.
//!
//! The case counts keep `cargo test` quick; `PROPTEST_CASES` raises them
//! for a longer hunt.

use proptest::prelude::*;
use proptest::sample::{Index, select};

/// The configuration of a property: `cases` runs, unless `PROPTEST_CASES`
/// asks for another count, and no file of failures kept.
pub(crate) fn config(cases: u32) -> ProptestConfig {
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|c| c.parse().ok())
        .unwrap_or(cases);
    ProptestConfig {
        cases,
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

/// Up to `max` pieces joined: each one of `words`, or a few random bytes.
pub(crate) fn soup(words: &'static [&'static [u8]], max: usize) -> impl Strategy<Value = Vec<u8>> {
    let piece = prop_oneof![
        3 => select(words).prop_map(<[u8]>::to_vec),
        1 => proptest::collection::vec(any::<u8>(), 0..4),
    ];
    proptest::collection::vec(piece, 0..max).prop_map(|pieces| pieces.concat())
}

/// One change to a valid sample.
#[derive(Clone, Debug)]
enum Edit {
    /// Bytes put in at a point.
    Insert(Index, Vec<u8>),
    /// A run of bytes taken out.
    Remove(Index, usize),
    /// One byte replaced.
    Replace(Index, u8),
    /// The sample cut short.
    Truncate(Index),
}

fn edit() -> impl Strategy<Value = Edit> {
    prop_oneof![
        any::<(Index, Vec<u8>)>().prop_map(|(at, bytes)| Edit::Insert(at, bytes)),
        (any::<Index>(), 1..8usize).prop_map(|(at, n)| Edit::Remove(at, n)),
        any::<(Index, u8)>().prop_map(|(at, b)| Edit::Replace(at, b)),
        any::<Index>().prop_map(Edit::Truncate),
    ]
}

fn apply(sample: &[u8], edits: &[Edit]) -> Vec<u8> {
    let mut v = sample.to_vec();
    for e in edits {
        match e {
            Edit::Insert(at, bytes) => {
                let at = at.index(v.len() + 1);
                v.splice(at..at, bytes.iter().copied());
            }
            Edit::Remove(at, n) if !v.is_empty() => {
                let at = at.index(v.len());
                v.drain(at..(at + n).min(v.len()));
            }
            Edit::Replace(at, b) if !v.is_empty() => {
                let at = at.index(v.len());
                v[at] = *b;
            }
            Edit::Truncate(at) => v.truncate(at.index(v.len() + 1)),
            Edit::Remove(..) | Edit::Replace(..) => {}
        }
    }
    v
}

/// One of `samples`, as it is or with up to three edits.
pub(crate) fn mutated(samples: &'static [&'static [u8]]) -> impl Strategy<Value = Vec<u8>> {
    (select(samples), proptest::collection::vec(edit(), 0..4))
        .prop_map(|(sample, edits)| apply(sample, &edits))
}

/// Input for a parser: built from its `words`, or one of its `samples`
/// changed.
pub(crate) fn input(
    words: &'static [&'static [u8]],
    samples: &'static [&'static [u8]],
    max: usize,
) -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![soup(words, max), mutated(samples)]
}
