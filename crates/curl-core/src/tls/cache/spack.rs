//! A TLS session packed to go out of the cache and come in again (C's
//! `lib/vtls/vtls_spack.c`): a version byte, then fields, each a tag byte
//! and its value, numbers big-endian, text and data after a 16-bit length.
//! Fields come in any order on the way in, the last of a tag winning; what
//! is packed is in C's one order, byte for byte what C's build reads.
//!
//! What comes in is the application's file, so anything at all: a blob
//! that does not parse is refused here, whatever it holds, and one that
//! parses says little. It may have no ticket, or a date in the past.

use curl_alloc::{OutOfMemory, TryVec as _};

use super::{TicketAlpn, TlsTicket, copy};
use crate::error::ErrorKind;
use crate::tls::Chosen;

const VERSION: u8 = 0x01;
const IETF_ID: u8 = 0x02;
const VALID_UNTIL: u8 = 0x03;
const TICKET: u8 = 0x04;
const ALPN: u8 = 0x05;
const EARLYDATA: u8 = 0x06;
const QUICTP: u8 = 0x07;
const SECTRUST: u8 = 0x08;

/// What a packed session may take, its terminating zero in C's buffer
/// counted (`CURL_SSL_TICKET_MAX`).
const PACKED_MAX: usize = 16 * 1024;

/// `s`, of a date not before 1970, which the export refuses first,
/// packed (`Curl_ssl_session_pack`). A field longer than its length says or
/// early data past 32 bits is a bad argument, and more than a packed
/// session may take is too large.
pub(super) fn pack(s: &TlsTicket) -> Result<Vec<u8>, ErrorKind> {
    assert!(s.valid_until >= 0, "refused by the export");
    let mut out = Packer(Vec::new());
    out.add(&[VERSION, TICKET])?;
    out.data16(&s.data)?;
    out.add(&[IETF_ID])?;
    out.add(&s.version.to_be_bytes())?;
    out.add(&[VALID_UNTIL])?;
    out.add(&s.valid_until.to_be_bytes())?;
    if let Some(name) = s.alpn_name() {
        out.add(&[ALPN])?;
        out.data16(name)?;
    }
    if s.earlydata_max != 0 {
        let early = u32::try_from(s.earlydata_max).map_err(|_| ErrorKind::BadFunctionArgument)?;
        out.add(&[EARLYDATA])?;
        out.add(&early.to_be_bytes())?;
    }
    if s.sectrust {
        out.add(&[SECTRUST])?;
    }
    if !s.quic_params.is_empty() {
        out.add(&[QUICTP])?;
        out.data16(&s.quic_params)?;
    }
    Ok(out.0)
}

struct Packer(Vec<u8>);

impl Packer {
    fn add(&mut self, bytes: &[u8]) -> Result<(), ErrorKind> {
        // As a dynbuf measures: what it holds, this and a zero byte.
        if self.0.len() + bytes.len() + 1 > PACKED_MAX {
            return Err(ErrorKind::TooLarge);
        }
        self.0.try_extend_from_slice(bytes).map_err(oom)
    }

    fn data16(&mut self, data: &[u8]) -> Result<(), ErrorKind> {
        let len = u16::try_from(data.len()).map_err(|_| ErrorKind::BadFunctionArgument)?;
        self.add(&len.to_be_bytes())?;
        self.add(data)
    }
}

/// The session `blob` holds (`Curl_ssl_session_unpack`). A blob not of this
/// version, cut short or with a tag unknown cannot be read.
pub(crate) fn unpack(blob: &[u8]) -> Result<TlsTicket, ErrorKind> {
    let mut r = Reader(blob);
    if r.array::<1>()? != [VERSION] {
        return Err(ErrorKind::ReadError);
    }
    let mut s = TlsTicket {
        data: Vec::new(),
        version: 0,
        alpn: None,
        earlydata_max: 0,
        quic_params: Vec::new(),
        valid_until: 0,
        sectrust: false,
    };
    while let [tag, rest @ ..] = r.0 {
        r.0 = rest;
        match *tag {
            ALPN => s.alpn = Some(alpn_of(r.data16()?)?),
            EARLYDATA => {
                let early = u32::from_be_bytes(r.array()?);
                s.earlydata_max = usize::try_from(early).map_err(|_| ErrorKind::ReadError)?;
            }
            IETF_ID => s.version = u16::from_be_bytes(r.array()?),
            QUICTP => s.quic_params = copy(r.data16()?).map_err(oom)?,
            TICKET => s.data = copy(r.data16()?).map_err(oom)?,
            // A date past what 63 bits hold reads as before 1970, as C's
            // cast has it; `pack` refuses it on the way out.
            VALID_UNTIL => s.valid_until = i64::from_be_bytes(r.array()?),
            SECTRUST => s.sectrust = true,
            _ => return Err(ErrorKind::ReadError),
        }
    }
    Ok(s)
}

/// The protocol a blob names: as C's string, up to any zero byte in it.
fn alpn_of(name: &[u8]) -> Result<TicketAlpn, ErrorKind> {
    let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
    let name = &name[..end];
    Ok(match Chosen::named(name) {
        Some(chosen) => TicketAlpn::Known(chosen),
        None => TicketAlpn::Other(copy(name).map_err(oom)?),
    })
}

fn oom(_: OutOfMemory) -> ErrorKind {
    ErrorKind::OutOfMemory
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn array<const N: usize>(&mut self) -> Result<[u8; N], ErrorKind> {
        let (head, rest) = self
            .0
            .split_first_chunk::<N>()
            .ok_or(ErrorKind::ReadError)?;
        self.0 = rest;
        Ok(*head)
    }

    fn data16(&mut self) -> Result<&'a [u8], ErrorKind> {
        let len = u16::from_be_bytes(self.array()?);
        let (data, rest) = self
            .0
            .split_at_checked(usize::from(len))
            .ok_or(ErrorKind::ReadError)?;
        self.0 = rest;
        Ok(data)
    }
}

#[cfg(test)]
mod tests;
