//! A response a server pushes: what it promised, and what the application
//! made of the offer (`CURLMOPT_PUSHFUNCTION`).

use curl_alloc::{OutOfMemory, TryVec as _};

use super::{Host, TransferId};
use crate::easy::Easy;

/// The most fields a promise may carry: C's list grows from ten, doubling,
/// and gives up once it is full past a thousand.
pub(crate) const MOST_FIELDS: usize = 1280;

/// The fields of the request a server imagines for a response it pushes
/// (a PUSH_PROMISE's), each as `name:value`, as C keeps them.
#[derive(Debug, Default)]
pub struct PushFields {
    lines: Vec<Vec<u8>>,
}

impl PushFields {
    pub fn len(&self) -> usize {
        self.lines.len()
    }

    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }

    /// The `n`th field, as `name:value` (`curl_pushheader_bynum`).
    pub fn get(&self, n: usize) -> Option<&[u8]> {
        self.lines.get(n).map(Vec::as_slice)
    }

    /// The value of the first field named `name` (`curl_pushheader_byname`):
    /// none for an empty name, `:` alone, or one with a colon past its
    /// first byte, which could match inside a value.
    pub fn by_name(&self, name: &[u8]) -> Option<&[u8]> {
        if name.is_empty() || name == b":" || name[1..].contains(&b':') {
            return None;
        }
        self.lines.iter().find_map(|line| {
            line.strip_prefix(name)
                .and_then(|rest| rest.strip_prefix(b":"))
        })
    }

    /// One more, unless there are as many as there may be.
    pub(crate) fn push(&mut self, name: &[u8], value: &[u8]) -> Result<(), Full> {
        if self.lines.len() == MOST_FIELDS {
            return Err(Full::TooMany);
        }
        let mut line = Vec::new();
        line.try_extend_from_slice(name)
            .and_then(|()| line.try_push(b':'))
            .and_then(|()| line.try_extend_from_slice(value))
            .and_then(|()| self.lines.try_push(line))
            .map_err(|OutOfMemory| Full::OutOfMemory)
    }
}

/// Why a field could not be kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Full {
    TooMany,
    OutOfMemory,
}

/// A response a server offers to push, in answer to a request it imagines
/// beside one of `parent`'s.
pub struct PushOffer<'a> {
    pub parent: TransferId,
    pub fields: &'a PushFields,
}

/// What the application made of a push.
pub enum Pushed<H: Host> {
    /// Take it, as a transfer of the multi's, owned by `owner`.
    Accepted { easy: Box<Easy>, owner: H::Transfer },
    /// Refuse it (`CURL_PUSH_DENY`).
    Denied,
    /// Refuse it, and fail the parent (`CURL_PUSH_ERROROUT`).
    Failed,
}
