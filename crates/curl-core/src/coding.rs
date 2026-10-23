//! Content codings: the names a response's body may come coded under, and
//! the decoders that undo them, which the libraries bound beside the core
//! give a handle (`lib/content_encoding.c`).

use std::fmt;

use crate::error::ErrorKind;

/// A content coding a decoder can undo.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Coding {
    Deflate,
    Gzip,
    Brotli,
    Zstd,
}

impl Coding {
    /// Every coding, in the order an `Accept-Encoding` lists them.
    pub const ALL: [Coding; 4] = [Coding::Deflate, Coding::Gzip, Coding::Brotli, Coding::Zstd];

    /// Its name in a header.
    pub fn name(self) -> &'static str {
        match self {
            Coding::Deflate => "deflate",
            Coding::Gzip => "gzip",
            Coding::Brotli => "br",
            Coding::Zstd => "zstd",
        }
    }

    /// The coding `name` names, in any case, aliases included.
    fn named(name: &[u8]) -> Option<Coding> {
        if name.eq_ignore_ascii_case(b"x-gzip") {
            return Some(Coding::Gzip);
        }
        Coding::ALL
            .into_iter()
            .find(|c| name.eq_ignore_ascii_case(c.name().as_bytes()))
    }

    const fn index(self) -> usize {
        self as usize
    }
}

/// What a coding name in a response asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Named {
    /// Nothing to undo (`identity`, `none`).
    Identity,
    Coding(Coding),
    /// No coding this build knows.
    Unknown,
}

impl Named {
    pub(crate) fn of(name: &[u8]) -> Named {
        if name.eq_ignore_ascii_case(b"identity") || name.eq_ignore_ascii_case(b"none") {
            return Named::Identity;
        }
        Coding::named(name).map_or(Named::Unknown, Named::Coding)
    }
}

/// Where a decoder's output goes, and what it may ask of the transfer.
pub trait Sink {
    /// Give `bytes`, decoded, to what is past the decoder.
    fn write(&mut self, bytes: &[u8]) -> Result<(), ErrorKind>;

    /// The transfer's time is up (`Curl_timeleft_ms` below zero): a
    /// decoder asks every 1 MiB it makes, and stops.
    fn timed_out(&self) -> bool;

    /// Say why the transfer fails, as its error message; the error.
    fn fail(&mut self, kind: ErrorKind, said: fmt::Arguments<'_>) -> ErrorKind;
}

/// A coding being undone, one response's body at a time (C's unencoding
/// writers).
pub trait Decoder: fmt::Debug + Send {
    /// Undo `input`, giving what it makes to `out` as it makes it.
    fn decode(&mut self, input: &[u8], out: &mut dyn Sink) -> Result<(), ErrorKind>;

    /// What it makes may be far larger than what it is given
    /// (`CURL_CW_FLAG_BLOWUP`): a paused transfer holds the body before
    /// it, still coded.
    fn blows_up(&self) -> bool {
        true
    }
}

/// Passes the body on as it came (`identity`): a coding all the same,
/// counted against the most a response may stack.
#[derive(Debug)]
pub(crate) struct Identity;

impl Decoder for Identity {
    fn decode(&mut self, input: &[u8], out: &mut dyn Sink) -> Result<(), ErrorKind> {
        out.write(input)
    }

    fn blows_up(&self) -> bool {
        false
    }
}

/// Stands for a coding nothing undoes: the body fails at its first byte
/// (C's `error_writer`, deferring the error to the use).
#[derive(Debug)]
pub(crate) struct Unrecognized;

impl Decoder for Unrecognized {
    fn decode(&mut self, _: &[u8], out: &mut dyn Sink) -> Result<(), ErrorKind> {
        Err(out.fail(
            ErrorKind::BadContentEncoding,
            format_args!("Unrecognized content encoding type"),
        ))
    }

    fn blows_up(&self) -> bool {
        false
    }
}

/// Makes a decoder for one response.
pub type MakeDecoder = fn() -> Result<Box<dyn Decoder>, ErrorKind>;

/// The codings a handle can undo, each with what makes its decoder: those
/// of the libraries the application was built with.
#[derive(Clone, Copy, Default)]
pub struct Decoders {
    makers: [Option<MakeDecoder>; Coding::ALL.len()],
}

impl Decoders {
    /// None: a coded body is delivered as it came, as if not asked for.
    pub const fn none() -> Decoders {
        Decoders {
            makers: [None; Coding::ALL.len()],
        }
    }

    /// These, and `coding` undone by what `make` makes.
    pub const fn with(mut self, coding: Coding, make: MakeDecoder) -> Decoders {
        self.makers[coding.index()] = Some(make);
        self
    }

    /// What makes a decoder of `coding`, if there is one.
    pub(crate) fn maker(&self, coding: Coding) -> Option<MakeDecoder> {
        self.makers[coding.index()]
    }

    /// The codings it undoes, in the order an `Accept-Encoding` lists them.
    pub fn codings(&self) -> impl Iterator<Item = Coding> + '_ {
        Coding::ALL
            .into_iter()
            .filter(|c| self.makers[c.index()].is_some())
    }
}

impl fmt::Debug for Decoders {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.codings()).finish()
    }
}

/// What a request's `Accept-Encoding` asks for, and so which codings its
/// response is decoded from (`CURLOPT_ACCEPT_ENCODING`).
#[derive(Debug, PartialEq, Eq)]
pub enum AcceptEncoding {
    /// Every coding the handle can undo.
    All,
    /// The value as given.
    Given(Vec<u8>),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_coding_is_named_in_any_case_and_by_its_alias() {
        assert_eq!(Named::of(b"GZip"), Named::Coding(Coding::Gzip));
        assert_eq!(Named::of(b"x-gzip"), Named::Coding(Coding::Gzip));
        assert_eq!(Named::of(b"br"), Named::Coding(Coding::Brotli));
        assert_eq!(Named::of(b"None"), Named::Identity);
        assert_eq!(Named::of(b"compress"), Named::Unknown);
    }
}
