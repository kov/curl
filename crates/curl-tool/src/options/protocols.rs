//! Lists of protocols, as `--proto` and `--proto-redir` take them and
//! `proto2num` in `src/tool_paramhlp.c` reads them.

use curl_core::version::{Protocol, version};

use super::ParamError;
use crate::msgs::Messages;

/// Some of the protocols the library speaks: bit `i` is
/// `version().protocols[i]`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Protocols(u64);

fn built_in() -> &'static [Protocol] {
    let all = version().protocols;
    assert!(all.len() <= 64, "every protocol has a bit");
    all
}

impl Protocols {
    /// Every protocol the library speaks.
    pub(crate) fn all() -> Self {
        Protocols(
            u64::MAX
                .checked_shr(64 - built_in().len() as u32)
                .unwrap_or(0),
        )
    }

    /// Those of HTTP, HTTPS, FTP and FTPS the library speaks: where a
    /// redirect may go unless `--proto-redir` says otherwise.
    pub(crate) fn redirect_default() -> Self {
        [b"http".as_slice(), b"https", b"ftp", b"ftps"]
            .into_iter()
            .filter_map(bit)
            .fold(Protocols(0), |set, b| Protocols(set.0 | b))
    }
}

/// Protocol `name`, in any case, if the library speaks it (`proto_token`).
pub(crate) fn token(name: &[u8]) -> Option<Protocol> {
    built_in()
        .iter()
        .copied()
        .find(|p| p.name().as_bytes().eq_ignore_ascii_case(name))
}

/// The bit of protocol `name`, in any case, if the library speaks it.
fn bit(name: &[u8]) -> Option<u64> {
    built_in()
        .iter()
        .position(|p| p.name().as_bytes().eq_ignore_ascii_case(name))
        .map(|i| 1 << i)
}

/// `start`, changed by `list`: protocols separated by commas, each added,
/// or with `-` removed, or with `=` the only one left; `all` names them
/// all. An unknown protocol is reported and rejects the list; a list that
/// leaves no protocol is rejected without a word, as in C.
pub(crate) fn parse(
    start: Protocols,
    list: &[u8],
    msgs: &Messages,
) -> Result<Protocols, ParamError> {
    let mut set = start.0;
    for token in list.split(|&b| b == b',').filter(|t| !t.is_empty()) {
        let (modifier, name) = match token {
            [m @ (b'=' | b'-' | b'+'), name @ ..] => (*m, name),
            name => (b'+', name),
        };
        if name.eq_ignore_ascii_case(b"all") {
            set = if modifier == b'-' {
                0
            } else {
                Protocols::all().0
            };
            continue;
        }
        // C copies the name into 32 bytes before looking it up.
        let name = &name[..name.len().min(31)];
        let named = bit(name).ok_or_else(|| {
            msgs.error(&[b"unrecognized protocol '", name, b"'"]);
            ParamError::BadUse
        })?;
        match modifier {
            b'-' => set &= !named,
            b'=' => set = named,
            _ => set |= named,
        }
    }
    if set == 0 {
        return Err(ParamError::BadUse);
    }
    Ok(Protocols(set))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quiet() -> Messages {
        let mut msgs = Messages::new();
        msgs.silent = true;
        msgs
    }

    /// The library speaks `file` and `http`: every other name is unknown,
    /// as test 322 checks, and a redirect may go to `http` by default.
    #[test]
    fn with_file_and_http() {
        let msgs = quiet();
        let (file, http) = (Protocols(1), Protocols(2));
        let both = Protocols(3);
        assert_eq!(Protocols::all(), both);
        assert_eq!(Protocols::redirect_default(), http);
        for (list, want) in [
            (b"".as_slice(), Ok(both)),
            (b",,=ALL,", Ok(both)),
            (b"FILE", Ok(both)),
            (b"=file", Ok(file)),
            (b"-file", Ok(http)),
            (b"-file,-HTTP", Err(ParamError::BadUse)),
            (b"-all,+file", Ok(file)),
            (b"+-http", Err(ParamError::BadUse)),
            (b"=http", Ok(http)),
            (b"https", Err(ParamError::BadUse)),
            (b"all,x", Err(ParamError::BadUse)),
            (b"+", Err(ParamError::BadUse)),
        ] {
            assert_eq!(parse(Protocols::all(), list, &msgs), want, "{list:?}");
        }
    }

    /// A list that leaves no protocol is rejected, whatever it starts
    /// from.
    #[test]
    fn rejects_an_empty_result() {
        let msgs = quiet();
        let none = Protocols(0);
        assert_eq!(parse(none, b"", &msgs), Err(ParamError::BadUse));
        assert_eq!(parse(none, b"=all", &msgs), Ok(Protocols::all()));
        assert_eq!(
            parse(Protocols::all(), b"-all", &msgs),
            Err(ParamError::BadUse)
        );
        assert_eq!(parse(Protocols::all(), b",,", &msgs), Ok(Protocols::all()));
    }

    const WORDS: &[&[u8]] = &[
        b"http",
        b"https",
        b"ftp",
        b"file",
        b"all",
        b"ALL",
        b"=",
        b"-",
        b"+",
        b",",
        b"",
        b"unknownprotocolwithaverylongnamepastthirtytwo",
        b"\0",
        b" ",
    ];
    const LISTS: &[&[u8]] = &[b"-all,+https", b"=http,-ftp", b"all,-file"];

    proptest::proptest! {
        #![proptest_config(crate::untrusted::config(512))]

        /// Any list changes any set of protocols, or is refused.
        #[test]
        fn any_list_is_read_or_refused(
            list in crate::untrusted::input(WORDS, LISTS, 10),
            start in proptest::prelude::any::<bool>(),
        ) {
            let start = if start { Protocols::all() } else { Protocols::redirect_default() };
            parse(start, &list, &quiet()).ok();
        }
    }
}
