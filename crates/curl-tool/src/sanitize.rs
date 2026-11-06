//! Output file names made fit for Windows (`src/tool_doswin.c`'s
//! `sanitize_file_name`): the characters Windows does not allow in a name
//! replaced by `_`, trailing dots and spaces cut, and the reserved device
//! names (`CON`, `NUL`, `COM1` and the like) renamed, as C does with the
//! names of `-o`, `-O` and `-J`. Only Windows does it ([`for_windows`]);
//! [`sanitize`] is built everywhere so that its table is checked
//! everywhere.

use curl_alloc::{OutOfMemory, TryVec as _};

/// What a name may keep (`SANITIZE_ALLOW_*`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Allow {
    /// Path separators and colons (`SANITIZE_ALLOW_PATH`): the name may
    /// name a file in another directory, or on another drive.
    pub(crate) path: bool,
    /// The reserved device names (`SANITIZE_ALLOW_RESERVED`).
    pub(crate) reserved: bool,
}

impl Allow {
    /// A name of one file, from the server or the URL: no path, no
    /// device.
    pub(crate) const NOTHING: Allow = Allow {
        path: false,
        reserved: false,
    };
    /// A name the user gave: a path, a device even.
    pub(crate) const EVERYTHING: Allow = Allow {
        path: true,
        reserved: true,
    };
}

/// Why a name was not made fit (`SANITIZEcode`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Unfit {
    /// The name cannot be made one (`SANITIZE_ERR_INVALID_PATH`): only
    /// the debug build's `CURL_FN_SANITIZE_BAD` says so on Windows.
    InvalidPath,
    /// `SANITIZE_ERR_OUT_OF_MEMORY`.
    OutOfMemory,
}

impl From<OutOfMemory> for Unfit {
    fn from(OutOfMemory: OutOfMemory) -> Unfit {
        Unfit::OutOfMemory
    }
}

/// `name` as the file it is saved to is named: [`sanitize`]d on Windows,
/// as it is elsewhere.
pub(crate) fn for_windows(name: Vec<u8>, allow: Allow) -> Result<Vec<u8>, Unfit> {
    if cfg!(windows) {
        sanitize(&name, allow)
    } else {
        Ok(name)
    }
}

/// `name` made fit to name a file on Windows (`sanitize_file_name`):
/// control characters and `|<>"?*` become `_`, and without
/// [`Allow::path`] so do `:`, `/` and `\`, and the dots and spaces it ends
/// with are cut; without [`Allow::reserved`] a reserved device name gets
/// a `_` before it, or in place of the `.` or `:` that follows it.
pub(crate) fn sanitize(name: &[u8], allow: Allow) -> Result<Vec<u8>, Unfit> {
    // C reads it as a string.
    let name = &name[..name.iter().position(|&b| b == 0).unwrap_or(name.len())];
    let mut target = Vec::new();
    target.try_extend_from_slice(name)?;
    // The literal-path prefix `\\?\` is kept as it is.
    let from = if allow.path && target.starts_with(b"\\\\?\\") {
        4
    } else {
        0
    };
    for b in &mut target[from..] {
        let banned = (1..=31).contains(b)
            || (!allow.path && matches!(*b, b':' | b'/' | b'\\'))
            || b"|<>\"?*".contains(b);
        if banned {
            *b = b'_';
        }
    }
    if !allow.path {
        let trailing = target
            .iter()
            .rev()
            .take_while(|&&b| b == b' ' || b == b'.')
            .count();
        target.truncate(target.len() - trailing);
    }
    if !allow.reserved {
        target = rename_if_reserved(target, allow.path)?;
    }
    if cfg!(feature = "debug-hooks") {
        if curl_os::env::is_set(b"CURL_FN_SANITIZE_BAD") {
            return Err(Unfit::InvalidPath);
        }
        if curl_os::env::is_set(b"CURL_FN_SANITIZE_OOM") {
            return Err(Unfit::OutOfMemory);
        }
    }
    Ok(target)
}

/// How long the reserved device name `name` starts with is, if it starts
/// with one (`prefix_reserved`). `COM` and `LPT` take a digit from 1 to 9,
/// or a superscript 1, 2 or 3 in Latin-1 or UTF-8, which Windows takes
/// for one.
fn prefix_reserved(name: &[u8]) -> usize {
    let starts = |prefix: &[u8]| {
        name.len() >= prefix.len() && name[..prefix.len()].eq_ignore_ascii_case(prefix)
    };
    let at = |i: usize| name.get(i).copied().unwrap_or(0);
    if starts(b"COM") || starts(b"LPT") {
        if (b'1'..=b'9').contains(&at(3)) {
            return 4;
        }
        let len = if at(3) == 0xc2 { 4 } else { 3 };
        return match at(len) {
            0xb9 | 0xb2 | 0xb3 => len + 1,
            _ => 0,
        };
    }
    if [b"CON", b"PRN", b"AUX", b"NUL"]
        .into_iter()
        .any(|p| starts(p))
    {
        return 3;
    }
    if starts(b"CLOCK$") {
        return 6;
    }
    0
}

/// Where the last component of `path` starts (`curlx_basename`).
fn basename(path: &[u8]) -> usize {
    path.iter()
        .rposition(|&b| b == b'/' || b == b'\\')
        .map_or(0, |at| at + 1)
}

/// `name` with a reserved device name at its start or its last component
/// renamed (`rename_if_reserved_dos`): `CON` to `_CON`, `CON.EXT` to
/// `CON_EXT`, `CON:ADS` to `CON_ADS`, or with a path to `_CON:ADS`. A
/// name starting `\\` keeps them when a path is allowed.
fn rename_if_reserved(mut name: Vec<u8>, path: bool) -> Result<Vec<u8>, OutOfMemory> {
    if path && name.starts_with(b"\\\\") {
        return Ok(name);
    }
    let mut base = basename(&name);
    let mut at = Some(0);
    while let Some(p) = at {
        let mut x = prefix_reserved(&name[p..]);
        if x != 0 {
            while name.get(p + x) == Some(&b' ') {
                x += 1;
            }
            let rename = match name.get(p + x) {
                Some(b'.') => {
                    name[p + x] = b'_';
                    false
                }
                Some(b':') if !path => {
                    name[p + x] = b'_';
                    false
                }
                Some(b':') | None => true,
                Some(_) => false,
            };
            if rename {
                let mut renamed = Vec::new();
                renamed.try_reserve_exact(name.len() + 1)?;
                renamed.try_extend_from_slice(&name[..p])?;
                renamed.try_push(b'_')?;
                renamed.try_extend_from_slice(&name[p..])?;
                name = renamed;
                if p == 0 {
                    base = basename(&name);
                }
            }
        }
        // The start, then the last component if it is another.
        at = (p == 0 && base != 0).then_some(base);
    }
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PATH: Allow = Allow {
        path: true,
        reserved: false,
    };

    /// Tool unit test 1604's table, read from its source, which C runs
    /// only on Windows (its rows for Windows, not MS-DOS); its last row,
    /// a NULL name refused, has no counterpart in a slice.
    #[test]
    fn tool1604_sanitizes() {
        let rows = curl_core::c_source::table("tests/tunit/tool1604.c", "data[] =", |c| match c {
            "!(defined(MSDOS))" => true,
            other => panic!("{other}"),
        });
        let mut checked = 0;
        for row in &rows {
            let [input, flags, expected, result] = row.group() else {
                panic!("{row:?}")
            };
            let Some(input) = input.bytes() else {
                assert_eq!(result.word(), "SANITIZE_ERR_BAD_ARGUMENT");
                continue;
            };
            assert_eq!(result.word(), "SANITIZE_ERR_OK");
            let mut allow = Allow::NOTHING;
            for flag in flags.word().split('|').map(str::trim) {
                match flag {
                    "0" => {}
                    "SANITIZE_ALLOW_PATH" => allow.path = true,
                    "SANITIZE_ALLOW_RESERVED" => allow.reserved = true,
                    other => panic!("{other}"),
                }
            }
            let got = sanitize(input, allow).unwrap();
            assert_eq!(
                got.escape_ascii().to_string(),
                expected.str().escape_ascii().to_string(),
                "{} with {allow:?}",
                input.escape_ascii()
            );
            checked += 1;
        }
        assert_eq!(checked, 51);
    }

    /// The cases C's table leaves out: each device name, `CLOCK$`, a
    /// digit or superscript missing, blanks before the dot, a reserved
    /// name in a path's last component and at its start, and a name cut
    /// at its first NUL as C reads it.
    #[test]
    fn sanitizes_the_cases_c_leaves_out() {
        let n = Allow::NOTHING;
        let table: &[(&[u8], Allow, &[u8])] = &[
            (b"con", n, b"_con"),
            (b"PRN", n, b"_PRN"),
            (b"aux", n, b"_aux"),
            (b"Nul", n, b"_Nul"),
            (b"clock$", n, b"_clock$"),
            (b"clock$.x", n, b"clock$_x"),
            (b"lpt9", n, b"_lpt9"),
            (b"lpt0", n, b"lpt0"),
            (b"com", n, b"com"),
            (b"co", n, b"co"),
            (b"LPT\xc2", n, b"LPT\xc2"),
            (b"LPT\xc2\xb4", n, b"LPT\xc2\xb4"),
            (b"LPT\xb4", n, b"LPT\xb4"),
            (b"console", n, b"console"),
            (b"nul  ", n, b"_nul"),
            (b"nul  .tar.gz", n, b"nul  _tar.gz"),
            (b"nul :x", n, b"nul _x"),
            (b"nul :x", PATH, b"_nul :x"),
            (b"nul :x", Allow::EVERYTHING, b"nul :x"),
            (b"d/aux", PATH, b"d/_aux"),
            (b"aux/d", PATH, b"aux/d"),
            (b"aux:/aux", PATH, b"_aux:/_aux"),
            (b"aux:\\x.y", PATH, b"_aux:\\x.y"),
            (b"a\\b/prn.txt", PATH, b"a\\b/prn_txt"),
            (b"..", n, b""),
            (b"\x1f\x7f", n, b"_\x7f"),
            (b"ab\0cd", n, b"ab"),
            (b"a. b", PATH, b"a. b"),
            (b"\\\\?\\a?b", PATH, b"\\\\?\\a_b"),
            (b"\\\\?\\", n, b"____"),
        ];
        for &(input, allow, expected) in table {
            let got = sanitize(input, allow).unwrap();
            assert_eq!(
                got.escape_ascii().to_string(),
                expected.escape_ascii().to_string(),
                "{} with {allow:?}",
                input.escape_ascii()
            );
        }
    }

    /// Only Windows sanitizes.
    #[test]
    fn sanitizes_only_on_windows() {
        let got = for_windows(b"a?b".to_vec(), Allow::EVERYTHING).unwrap();
        let want: &[u8] = if cfg!(windows) { b"a_b" } else { b"a?b" };
        assert_eq!(got, want);
    }
}
