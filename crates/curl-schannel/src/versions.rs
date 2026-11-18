//! The protocols a credential enables for a range of TLS versions
//! (`schannel_set_ssl_version_min_max`). Schannel reads an empty set as
//! "the system's default", so a range enabling none is refused here and
//! never reaches it. Nothing of Windows is in it, so it is tested
//! everywhere.

use std::num::NonZeroU32;

/// The client protocols a credential enables (`SP_PROT_*_CLIENT`).
pub(crate) mod protocol {
    pub(crate) const TLS1_0: u32 = 0x80;
    pub(crate) const TLS1_1: u32 = 0x200;
    pub(crate) const TLS1_2: u32 = 0x800;
    pub(crate) const TLS1_3: u32 = 0x2000;
}

/// A set of protocols with at least one in it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Protocols(NonZeroU32);

impl Protocols {
    pub(crate) fn bits(self) -> u32 {
        self.0.get()
    }
}

/// Why a range enables no protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refused {
    /// TLS 1.3 is asked for and this Schannel does not speak it.
    Tls13Unsupported,
    /// No version is in the range.
    NoneInRange,
}

/// The protocols enabled from `min` to `max`, in C's numbers for the
/// versions (4 for TLS 1.0 to 7 for TLS 1.3, 1 for the default
/// minimum), where `tls13` says this Schannel speaks TLS 1.3.
pub(crate) fn enabled(min: u8, max: u8, tls13: bool) -> Result<Protocols, Refused> {
    let mut enabled = 0;
    for i in min..=max {
        match i {
            4 => enabled |= protocol::TLS1_0,
            5 => enabled |= protocol::TLS1_1,
            6 => enabled |= protocol::TLS1_2,
            7 if tls13 => enabled |= protocol::TLS1_3,
            7 => return Err(Refused::Tls13Unsupported),
            _ => {}
        }
    }
    NonZeroU32::new(enabled)
        .map(Protocols)
        .ok_or(Refused::NoneInRange)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A range enables each version in it, and only those.
    #[test]
    fn a_range_enables_its_versions() {
        use protocol::*;
        assert_eq!(
            enabled(1, 6, false).map(Protocols::bits),
            Ok(TLS1_0 | TLS1_1 | TLS1_2)
        );
        assert_eq!(
            enabled(6, 7, true).map(Protocols::bits),
            Ok(TLS1_2 | TLS1_3)
        );
        assert_eq!(enabled(5, 5, false).map(Protocols::bits), Ok(TLS1_1));
        assert_eq!(enabled(7, 7, false), Err(Refused::Tls13Unsupported));
    }

    /// A minimum above the maximum enables nothing, and is refused rather
    /// than handed to Schannel as the empty set it reads as its default.
    #[test]
    fn a_range_enabling_none_is_refused() {
        assert_eq!(enabled(7, 6, true), Err(Refused::NoneInRange));
        assert_eq!(enabled(6, 4, false), Err(Refused::NoneInRange));
    }
}
