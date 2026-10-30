//! An FTP URL's path: its `;type=` code, then the directories a transfer
//! changes into and the file it acts on, as the method of reaching them
//! splits it (`type_url_check`, `ftp_parse_url_path`).

use std::ops::Range;

use curl_alloc::TryVec as _;

use crate::options::FtpMethod;

/// The most directories a path may name (`FTP_MAX_DIR_DEPTH`).
const MAX_DEPTH: usize = 1000;

/// What a path's `;type=` asks for (RFC 1738, 3.2.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TypeCode {
    /// `A`: an ASCII transfer.
    Ascii,
    /// `D`: a listing of names alone.
    Names,
    /// `I`, or any other letter: a binary transfer.
    Binary,
}

/// Cut `;type=X` off the end of `path`, if it ends so, and say what it
/// asks for (`type_url_check`).
pub(crate) fn type_code(path: &mut Vec<u8>) -> Option<TypeCode> {
    let len = path.len();
    if len < 7 || &path[len - 7..len - 1] != b";type=" {
        return None;
    }
    let code = match path[len - 1].to_ascii_uppercase() {
        b'A' => TypeCode::Ascii,
        b'D' => TypeCode::Names,
        _ => TypeCode::Binary,
    };
    path.truncate(len - 7);
    Some(code)
}

/// Why a path cannot be used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PathError {
    /// It decodes to a control byte ("path contains control
    /// characters").
    Control,
    /// It names more directories than C takes.
    TooDeep,
    OutOfMemory,
}

/// A path, decoded, and where in it its directories and its file are.
#[derive(Debug, Default)]
pub(crate) struct Path {
    raw: Vec<u8>,
    /// Each directory to change into, a range of `raw`.
    dirs: Vec<Range<usize>>,
    /// Where the file's name starts, if it has one: it runs to the end.
    file: Option<usize>,
}

impl Path {
    /// `encoded`, the URL's path after its first slash, decoded and split
    /// as `method` reaches its file.
    pub(crate) fn parse(encoded: &[u8], method: FtpMethod) -> Result<Path, PathError> {
        let raw = crate::url::decode_but_control(encoded)
            .map_err(|_| PathError::OutOfMemory)?
            .ok_or(PathError::Control)?;
        let mut dirs = Vec::new();
        let file = match method {
            FtpMethod::NoCwd => (!raw.is_empty() && raw.last() != Some(&b'/')).then_some(0),
            FtpMethod::SingleCwd => match raw.iter().rposition(|&b| b == b'/') {
                Some(slash) => {
                    // The directory before the last slash, `/` itself for
                    // one at the start.
                    dirs.try_push(0..slash.max(1))
                        .map_err(|_| PathError::OutOfMemory)?;
                    Some(slash + 1)
                }
                None => Some(0),
            },
            FtpMethod::MultiCwd => {
                let slashes = raw.iter().filter(|&&b| b == b'/').count();
                if slashes >= MAX_DEPTH {
                    return Err(PathError::TooDeep);
                }
                dirs.try_reserve_exact(slashes)
                    .map_err(|_| PathError::OutOfMemory)?;
                let mut at = 0;
                for slash in raw
                    .iter()
                    .enumerate()
                    .filter_map(|(i, &b)| (b == b'/').then_some(i))
                {
                    let mut len = slash - at;
                    // A path that starts with a slash changes into `/`.
                    if len == 0 && dirs.is_empty() {
                        len = 1;
                    }
                    // An empty piece, as in `x//y`, is passed over: CWD
                    // takes no empty argument.
                    if len > 0 {
                        dirs.try_push(at..at + len)
                            .map_err(|_| PathError::OutOfMemory)?;
                    }
                    at = slash + 1;
                }
                Some(at)
            }
        };
        // An empty name is none.
        let file = file.filter(|&at| at < raw.len());
        Ok(Path { raw, dirs, file })
    }

    /// How many directories it changes into.
    pub(crate) fn depth(&self) -> usize {
        self.dirs.len()
    }

    /// Its `n`-th directory.
    pub(crate) fn dir(&self, n: usize) -> &[u8] {
        &self.raw[self.dirs[n].clone()]
    }

    /// The file it names, if any.
    pub(crate) fn file(&self) -> Option<&[u8]> {
        self.file.map(|at| &self.raw[at..])
    }

    /// Whether it starts at the root: C's `rawpath[0] == '/'`.
    pub(crate) fn absolute(&self) -> bool {
        self.raw.first() == Some(&b'/')
    }

    /// The part a listing's `NOCWD` argument names: up to the last slash,
    /// `/` itself for one at the start; none without a slash
    /// (`ftp_state_list`).
    pub(crate) fn listed_dir(&self) -> Option<&[u8]> {
        let slash = self.raw.iter().rposition(|&b| b == b'/')?;
        Some(&self.raw[..slash.max(1)])
    }

    /// The directory the transfer ends in, to compare with the next
    /// transfer's: the path less its file, or nothing for `NOCWD`, which
    /// stays at the entry path (`ftp_done_path`, `ftp_parse_url_path`).
    pub(crate) fn working_dir(&self, method: FtpMethod) -> &[u8] {
        if method == FtpMethod::NoCwd {
            return &[];
        }
        let file = self.file().map_or(0, <[u8]>::len);
        &self.raw[..self.raw.len() - file]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn split(path: &str, method: FtpMethod) -> (Vec<String>, Option<String>) {
        let p = Path::parse(path.as_bytes(), method).unwrap();
        let dirs = (0..p.depth())
            .map(|i| String::from_utf8(p.dir(i).to_vec()).unwrap())
            .collect();
        let file = p.file().map(|f| String::from_utf8(f.to_vec()).unwrap());
        (dirs, file)
    }

    fn strs(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_owned()).collect()
    }

    /// The default method changes into each directory in turn, an empty
    /// piece passed over, a first slash changing into `/`.
    #[test]
    fn multicwd_changes_into_each_directory() {
        let m = FtpMethod::MultiCwd;
        assert_eq!(split("a/b/c", m), (strs(&["a", "b"]), Some("c".into())));
        assert_eq!(split("a//b/", m), (strs(&["a", "b"]), None));
        assert_eq!(split("/a/f", m), (strs(&["/", "a"]), Some("f".into())));
        assert_eq!(split("f", m), (vec![], Some("f".into())));
        assert_eq!(split("", m), (vec![], None));
        // An escaped slash is decoded first, and splits too.
        assert_eq!(split("a%2fb", m), (strs(&["a"]), Some("b".into())));
        assert_eq!(split("%2f%2fx", m), (strs(&["/"]), Some("x".into())));
    }

    /// One `CWD` to the directory before the last slash, or none.
    #[test]
    fn singlecwd_changes_into_the_directory_whole() {
        let m = FtpMethod::SingleCwd;
        assert_eq!(split("a/b/c", m), (strs(&["a/b"]), Some("c".into())));
        assert_eq!(split("/f", m), (strs(&["/"]), Some("f".into())));
        assert_eq!(split("a/", m), (strs(&["a"]), None));
        assert_eq!(split("f", m), (vec![], Some("f".into())));
    }

    /// No `CWD`: the whole path is the file, unless it ends in a slash.
    #[test]
    fn nocwd_takes_the_path_as_the_file() {
        let m = FtpMethod::NoCwd;
        assert_eq!(split("a/b/c", m), (vec![], Some("a/b/c".into())));
        assert_eq!(split("a/b/", m), (vec![], None));
        assert_eq!(split("", m), (vec![], None));
    }

    #[test]
    fn a_control_byte_or_a_deep_path_is_refused() {
        let m = FtpMethod::MultiCwd;
        assert_eq!(
            Path::parse(b"a%0ab", m).map(|_| ()),
            Err(PathError::Control)
        );
        assert_eq!(Path::parse(b"a\tb", m).map(|_| ()), Err(PathError::Control));
        let deep = "a/".repeat(1000);
        assert_eq!(
            Path::parse(deep.as_bytes(), m).map(|_| ()),
            Err(PathError::TooDeep)
        );
        let deep = "a/".repeat(999);
        assert!(Path::parse(deep.as_bytes(), m).is_ok());
        // Only the default method counts them.
        let deep = "a/".repeat(1000);
        assert!(Path::parse(deep.as_bytes(), FtpMethod::SingleCwd).is_ok());
    }

    /// `;type=` is cut off the end and read, any letter but `A` and `D`
    /// binary (`type_url_check`).
    #[test]
    fn the_type_code_is_cut_off() {
        let cut = |p: &str| {
            let mut v = p.as_bytes().to_vec();
            let code = type_code(&mut v);
            (String::from_utf8(v).unwrap(), code)
        };
        assert_eq!(cut("f;type=a"), ("f".into(), Some(TypeCode::Ascii)));
        assert_eq!(cut("d/;type=D"), ("d/".into(), Some(TypeCode::Names)));
        assert_eq!(cut("f;type=i"), ("f".into(), Some(TypeCode::Binary)));
        assert_eq!(cut("f;type=x"), ("f".into(), Some(TypeCode::Binary)));
        assert_eq!(cut(";type=a"), ("".into(), Some(TypeCode::Ascii)));
        assert_eq!(cut("f;type=ab"), ("f;type=ab".into(), None));
        assert_eq!(cut("type=a"), ("type=a".into(), None));
    }

    /// What a listing names, and the directory a transfer ends in.
    #[test]
    fn the_listed_and_working_directories() {
        let p = Path::parse(b"/a/b/f", FtpMethod::NoCwd).unwrap();
        assert_eq!(p.listed_dir(), Some(&b"/a/b"[..]));
        assert_eq!(p.working_dir(FtpMethod::NoCwd), b"");
        let p = Path::parse(b"/f", FtpMethod::NoCwd).unwrap();
        assert_eq!(p.listed_dir(), Some(&b"/"[..]));
        let p = Path::parse(b"f", FtpMethod::NoCwd).unwrap();
        assert_eq!(p.listed_dir(), None);
        let p = Path::parse(b"a/b/f", FtpMethod::MultiCwd).unwrap();
        assert_eq!(p.working_dir(FtpMethod::MultiCwd), b"a/b/");
        let p = Path::parse(b"a/b/", FtpMethod::MultiCwd).unwrap();
        assert_eq!(p.working_dir(FtpMethod::MultiCwd), b"a/b/");
    }
}
