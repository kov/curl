//! A listing as a wildcard download reads it (`ftplistparser.c`): the
//! body of `LIST`, a byte at a time, in the Unix form `ls -l` writes or
//! in the form Windows NT's server writes, told apart by the listing's
//! first byte. Each line names a file, kept if its name matches the
//! pattern. The listing is the server's, so it is never trusted: a line
//! that does not read as either form fails the listing, and no later
//! byte is read.
//!
//! Each line is kept as it came, its fields cut out of it by zero bytes
//! where C writes them, as C reads each field up to the first zero byte
//! after its start: a field holds what C's string does.

use std::collections::VecDeque;

use curl_alloc::TryVec as _;

use crate::error::ErrorKind;
use crate::handler::{FileInfo, FileType};

/// The longest a line may grow (`MAX_FTPLIST_BUFFER`): its buffer holds
/// one byte less, as C's keeps room for its zero byte.
pub(crate) const MAX_LINE: usize = FileInfo::MAX_TEXT;

/// Which form the listing is in, decided by its first byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Os {
    Unknown,
    Unix,
    WinNt,
}

/// Where a line in the Unix form is (`pl_unix_mainstate` and its
/// substates).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Unix {
    /// The listing's first line, which may be `total N`: reading it
    /// once a `t` started it.
    TotalSize {
        reading: bool,
    },
    FileType,
    Permission,
    HLinks {
        number: bool,
    },
    User {
        parsing: bool,
    },
    Group {
        name: bool,
    },
    Size {
        number: bool,
    },
    Time(TimePart),
    FileName(NameEnd),
    Symlink(Link),
}

/// The three parts of a Unix line's time (`PL_UNIX_TIME_*`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TimePart {
    Pre1,
    Part1,
    Pre2,
    Part2,
    Pre3,
    Part3,
}

/// A name running to the line's end (`PL_UNIX_FILENAME_*`,
/// `PL_WINNT_FILENAME_*`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NameEnd {
    PreSpace,
    Name,
    /// A carriage return came: only a line feed may follow.
    WindowsEol,
}

/// A symbolic link's name, ` -> ` and its target (`PL_UNIX_SYMLINK_*`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Link {
    PreSpace,
    Name,
    /// ` `, `-` and `>` of the arrow came, in turn.
    PreTarget1,
    PreTarget2,
    PreTarget3,
    PreTarget4,
    Target,
    WindowsEol,
}

/// Where a line in Windows NT's form is (`pl_winNT_mainstate` and its
/// substates).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Nt {
    Date,
    Time { time: bool },
    DirOrSize { content: bool },
    FileName(NameEnd),
}

/// Where the fields of the line are, as offsets into it; kept from one
/// line to the next, as C's are (`offsets`), and none at offset 0.
#[derive(Clone, Copy, Debug, Default)]
struct Offsets {
    filename: usize,
    user: usize,
    group: usize,
    time: usize,
    perm: usize,
    symlink_target: usize,
}

/// The line being read (`struct fileinfo` as the parser fills it).
#[derive(Debug)]
struct Line {
    buf: Vec<u8>,
    kind: FileType,
    perm: Option<u32>,
    hardlinks: Option<i64>,
    /// The size, and whether the line gave it.
    size: i64,
    size_known: bool,
}

/// A file the listing names that the pattern matched, its line kept.
#[derive(Debug)]
pub(crate) struct Entry {
    line: Line,
    at: Offsets,
}

impl Entry {
    /// What its line says of it.
    pub(crate) fn info(&self) -> FileInfo<'_> {
        let buf = &self.line.buf;
        let field = |at: usize| (at != 0).then(|| cstr(buf, at));
        FileInfo {
            name: cstr(buf, self.at.filename),
            kind: self.line.kind,
            perm: self.line.perm,
            hardlinks: self.line.hardlinks,
            size: self
                .line
                .size_known
                .then(|| u64::try_from(self.line.size).expect("no sign is read")),
            time: cstr(buf, self.at.time),
            perm_text: field(self.at.perm),
            user: field(self.at.user),
            group: field(self.at.group),
            target: field(self.at.symlink_target).filter(|_| self.line.kind == FileType::Symlink),
        }
    }
}

/// The bytes of `buf` from `at` to the first zero byte after it, as C
/// reads a string there.
fn cstr(buf: &[u8], at: usize) -> &[u8] {
    let rest = buf.get(at..).unwrap_or_default();
    let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
    &rest[..end]
}

/// A listing as it is read (`struct ftp_parselist_data`), and the files
/// it named that matched (`wildcard->filelist`).
#[derive(Debug)]
pub(crate) struct Listing {
    os: Os,
    unix: Unix,
    nt: Nt,
    /// Why the listing failed; nothing is read once it has.
    error: Option<ErrorKind>,
    line: Option<Line>,
    item_length: usize,
    item_offset: usize,
    offsets: Offsets,
    files: VecDeque<Entry>,
}

/// Whether `c` is in `set` as C's `strchr` finds it: a zero byte always
/// is, as the string's own end.
fn in_set(set: &[u8], c: u8) -> bool {
    c == 0 || set.contains(&c)
}

/// The permission bits `text`'s nine letters give, or none for a letter
/// that is not one a field may hold (`ftp_pl_get_permission`).
fn permission(text: &[u8]) -> Option<u32> {
    let [ur, uw, ux, gr, gw, gx, or, ow, ox] = *text else {
        return None;
    };
    let mut perm = 0;
    let mut bit = |c: u8, letter: u8, at: u32| match c {
        _ if c == letter => {
            perm |= 1 << at;
            true
        }
        b'-' => true,
        _ => false,
    };
    let reads = bit(ur, b'r', 8) && bit(uw, b'w', 7);
    let reads = reads && bit(gr, b'r', 5) && bit(gw, b'w', 4);
    let reads = reads && bit(or, b'r', 2) && bit(ow, b'w', 1);
    if !reads {
        return None;
    }
    // Execute, with the bit above it the letter's case says.
    let exec = |c: u8, x: u8, set: u8, unset: u8, at: u32, high: u32| match c {
        _ if c == x => Some(1 << at),
        _ if c == set => Some(1 << at | 1 << high),
        _ if c == unset => Some(1 << high),
        b'-' => Some(0),
        _ => None,
    };
    Some(
        perm | exec(ux, b'x', b's', b'S', 6, 11)?
            | exec(gx, b'x', b's', b'S', 3, 10)?
            | exec(ox, b'x', b't', b'T', 0, 9)?,
    )
}

/// A file type's letter in a Unix line (`unix_filetype`).
fn unix_filetype(c: u8) -> Option<FileType> {
    Some(match c {
        b'-' => FileType::File,
        b'd' => FileType::Directory,
        b'l' => FileType::Symlink,
        b'p' => FileType::NamedPipe,
        b's' => FileType::Socket,
        b'c' => FileType::DeviceChar,
        b'b' => FileType::DeviceBlock,
        b'D' => FileType::Door,
        _ => return None,
    })
}

/// The number at the start of `s`, its digits read up to `max`
/// (`curlx_str_number`): none without a digit, or past `max`.
fn number(s: &[u8], max: i64) -> Option<(i64, &[u8])> {
    let digits = s.iter().take_while(|b| b.is_ascii_digit()).count();
    if digits == 0 {
        return None;
    }
    let mut n: i64 = 0;
    for &d in &s[..digits] {
        n = n
            .checked_mul(10)
            .and_then(|n| n.checked_add(i64::from(d - b'0')))
            .filter(|&n| n <= max)?;
    }
    Some((n, &s[digits..]))
}

/// The most a link count may be, the `long` C keeps it in (`LONG_MAX`):
/// 32 bits on Windows, 64 on the Unix targets built.
#[allow(clippy::unnecessary_cast, reason = "`c_long` is 32 bits on Windows")]
const LONG_MAX: i64 = core::ffi::c_long::MAX as i64;

/// The same after any spaces and tabs (`curlx_str_numblanks`).
fn number_after_blanks(s: &[u8]) -> Option<(i64, &[u8])> {
    let blanks = s.iter().take_while(|&&b| b == b' ' || b == b'\t').count();
    number(&s[blanks..], i64::MAX)
}

/// The listing's way to fail: any line it cannot read
/// (`CURLE_FTP_BAD_FILE_LIST`).
const BAD: ErrorKind = ErrorKind::FtpBadFileList;

impl Listing {
    pub(crate) fn new() -> Listing {
        Listing {
            os: Os::Unknown,
            unix: Unix::TotalSize { reading: false },
            nt: Nt::Date,
            error: None,
            line: None,
            item_length: 0,
            item_offset: 0,
            offsets: Offsets::default(),
            files: VecDeque::new(),
        }
    }

    /// Why the listing failed, if it did (`Curl_ftp_parselist_geterror`).
    pub(crate) fn error(&self) -> Option<ErrorKind> {
        self.error
    }

    /// The files that matched, in the listing's order.
    pub(crate) fn files(&self) -> &VecDeque<Entry> {
        &self.files
    }

    /// The first file left, which is done with.
    pub(crate) fn pass_first(&mut self) {
        self.files.pop_front();
    }

    /// Read `bytes`, the next of the listing (`Curl_ftp_parselist`):
    /// each name a line gives is given to `matches`, which says if the
    /// pattern matches it, or fails the listing. Once a line fails, nothing more is read, and
    /// the failure is kept for the download to find.
    pub(crate) fn feed(
        &mut self,
        bytes: &[u8],
        matches: &mut dyn FnMut(&[u8]) -> Result<bool, ErrorKind>,
    ) {
        if self.error.is_some() {
            return;
        }
        if self.os == Os::Unknown
            && let Some(&first) = bytes.first()
        {
            self.os = if first.is_ascii_digit() {
                Os::WinNt
            } else {
                Os::Unix
            };
        }
        for &c in bytes {
            if let Err(e) = self.byte(c, matches) {
                self.error = Some(e);
                // The line read so far goes.
                self.line = None;
                return;
            }
        }
    }

    fn byte(
        &mut self,
        c: u8,
        matches: &mut dyn FnMut(&[u8]) -> Result<bool, ErrorKind>,
    ) -> Result<(), ErrorKind> {
        let line = match &mut self.line {
            Some(line) => line,
            None => {
                self.item_offset = 0;
                self.item_length = 0;
                let mut buf = Vec::new();
                // As much as C's buffer starts with (`MIN_FIRST_ALLOC`),
                // doubled as it grows.
                buf.try_reserve_exact(32)
                    .map_err(|_| ErrorKind::OutOfMemory)?;
                self.line.insert(Line {
                    buf,
                    kind: FileType::File,
                    perm: None,
                    hardlinks: None,
                    size: 0,
                    size_known: false,
                })
            }
        };
        // Room for the byte and C's zero byte after it; a line that
        // outgrows it fails as C's buffer does.
        if line.buf.len() + 2 > MAX_LINE {
            return Err(ErrorKind::OutOfMemory);
        }
        line.buf.try_push(c).map_err(|_| ErrorKind::OutOfMemory)?;
        match self.os {
            Os::Unix => self.unix(c, matches),
            Os::WinNt => self.nt(c, matches),
            Os::Unknown => unreachable!("the first byte decided the form"),
        }
    }

    /// The line being read, which `byte` made.
    fn line(&mut self) -> &mut Line {
        self.line.as_mut().expect("a byte of a line is being read")
    }

    /// End the field that runs to `at` with a zero byte, as C writes it
    /// there.
    fn cut(&mut self, at: usize) -> Result<(), ErrorKind> {
        let byte = self.line().buf.get_mut(at).ok_or(BAD)?;
        *byte = 0;
        Ok(())
    }

    /// The text of the line from `at`, up to a zero byte.
    fn text(&mut self, at: usize) -> &[u8] {
        cstr(&self.line().buf, at)
    }

    fn unix(
        &mut self,
        c: u8,
        matches: &mut dyn FnMut(&[u8]) -> Result<bool, ErrorKind>,
    ) -> Result<(), ErrorKind> {
        // The line so far, this byte among it: never empty, so C's tests
        // that it is not (`&& len`) always pass, and are left out.
        let len = self.line().buf.len();
        match self.unix {
            Unix::TotalSize { reading } => {
                self.total_size(reading, c)?;
                // A first line that is no total starts with its file type:
                // on with the same byte, as C falls through. A total ends
                // with its line feed, which C falls through with too, and
                // fails at as the next line's file type (DIVERGENCE.md).
                if !reading && self.unix == Unix::FileType {
                    self.file_type(c)?;
                }
            }
            Unix::FileType => self.file_type(c)?,
            Unix::Permission => {
                self.item_length += 1;
                if self.item_length <= 9 && !in_set(b"rwx-tTsS", c) {
                    return Err(BAD);
                }
                if self.item_length == 10 {
                    if c != b' ' {
                        return Err(BAD);
                    }
                    self.cut(10)?;
                    let at = self.item_offset;
                    let text = self.line().buf.get(at..at + 9).ok_or(BAD)?;
                    let perm = permission(text).ok_or(BAD)?;
                    self.line().perm = Some(perm);
                    self.offsets.perm = at;
                    self.item_length = 0;
                    self.unix = Unix::HLinks { number: false };
                }
            }
            Unix::HLinks { number: false } => {
                if c != b' ' {
                    if !(c.is_ascii_digit()) {
                        return Err(BAD);
                    }
                    self.start_item(len);
                    self.unix = Unix::HLinks { number: true };
                }
            }
            Unix::HLinks { number: true } => {
                self.item_length += 1;
                if c == b' ' {
                    self.cut(self.item_end()?)?;
                    let at = self.item_offset;
                    if let Some((n, _)) = number(self.text(at), LONG_MAX) {
                        self.line().hardlinks = Some(n);
                    }
                    self.item_length = 0;
                    self.item_offset = 0;
                    self.unix = Unix::User { parsing: false };
                } else if !c.is_ascii_digit() {
                    return Err(BAD);
                }
            }
            Unix::User { parsing: false } => {
                if c != b' ' {
                    self.start_item(len);
                    self.unix = Unix::User { parsing: true };
                }
            }
            Unix::User { parsing: true } => {
                self.item_length += 1;
                if c == b' ' {
                    self.cut(self.item_end()?)?;
                    self.offsets.user = self.item_offset;
                    self.unix = Unix::Group { name: false };
                    self.item_offset = 0;
                    self.item_length = 0;
                }
            }
            Unix::Group { name: false } => {
                if c != b' ' {
                    self.start_item(len);
                    self.unix = Unix::Group { name: true };
                }
            }
            Unix::Group { name: true } => {
                self.item_length += 1;
                if c == b' ' {
                    self.cut(self.item_end()?)?;
                    self.offsets.group = self.item_offset;
                    self.unix = Unix::Size { number: false };
                    self.item_offset = 0;
                    self.item_length = 0;
                }
            }
            Unix::Size { number: false } => {
                if c != b' ' {
                    if !(c.is_ascii_digit()) {
                        return Err(BAD);
                    }
                    self.start_item(len);
                    self.unix = Unix::Size { number: true };
                }
            }
            Unix::Size { number: true } => {
                self.item_length += 1;
                if c == b' ' {
                    self.cut(self.item_end()?)?;
                    let at = self.item_offset;
                    // A size too big to read leaves the field open: C
                    // reads it again at the next space.
                    if let Some((size, rest)) = number_after_blanks(self.text(at)) {
                        if rest.is_empty() && size != i64::MAX {
                            let line = self.line();
                            line.size = size;
                            line.size_known = true;
                        }
                        self.item_length = 0;
                        self.item_offset = 0;
                        self.unix = Unix::Time(TimePart::Pre1);
                    }
                } else if !c.is_ascii_digit() {
                    return Err(BAD);
                }
            }
            Unix::Time(part) => self.time(part, c, len)?,
            Unix::FileName(end) => match end {
                NameEnd::PreSpace => {
                    if c != b' ' {
                        self.start_item(len);
                        self.unix = Unix::FileName(NameEnd::Name);
                    }
                }
                NameEnd::Name => {
                    self.item_length += 1;
                    if c == b'\r' {
                        self.unix = Unix::FileName(NameEnd::WindowsEol);
                    } else if c == b'\n' {
                        self.unix_name_ends(matches)?;
                    }
                }
                NameEnd::WindowsEol => {
                    if c != b'\n' {
                        return Err(BAD);
                    }
                    self.unix_name_ends(matches)?;
                }
            },
            Unix::Symlink(link) => self.symlink(link, c, len, matches)?,
        }
        Ok(())
    }

    /// A field starts at the byte just read, the line `len` long.
    fn start_item(&mut self, len: usize) {
        self.item_offset = len - 1;
        self.item_length = 1;
    }

    /// Where the field ends: at the byte just read.
    fn item_end(&self) -> Result<usize, ErrorKind> {
        (self.item_offset + self.item_length)
            .checked_sub(1)
            .ok_or(BAD)
    }

    /// The listing's first line, if it is `total N`
    /// (`parse_unix_totalsize`).
    fn total_size(&mut self, reading: bool, c: u8) -> Result<(), ErrorKind> {
        if !reading {
            if c == b't' {
                self.unix = Unix::TotalSize { reading: true };
                self.item_length += 1;
            } else {
                self.unix = Unix::FileType;
            }
            return Ok(());
        }
        self.item_length += 1;
        if c == b'\r' {
            // Taken back out.
            self.item_length -= 1;
            self.line().buf.pop();
        } else if c == b'\n' {
            self.cut(self.item_length.checked_sub(1).ok_or(BAD)?)?;
            let text = self.text(0);
            let Some(rest) = text.strip_prefix(b"total ") else {
                return Err(BAD);
            };
            let blanks = rest
                .iter()
                .take_while(|&&b| b == b' ' || b == b'\t')
                .count();
            if !rest[blanks..].iter().all(u8::is_ascii_digit) {
                return Err(BAD);
            }
            self.unix = Unix::FileType;
            self.line().buf.clear();
        }
        Ok(())
    }

    fn file_type(&mut self, c: u8) -> Result<(), ErrorKind> {
        self.line().kind = unix_filetype(c).ok_or(BAD)?;
        self.unix = Unix::Permission;
        self.item_length = 0;
        self.item_offset = 1;
        Ok(())
    }

    /// A Unix line's time, three parts (`parse_unix_time`).
    fn time(&mut self, part: TimePart, c: u8, len: usize) -> Result<(), ErrorKind> {
        let word = |c: u8| c.is_ascii_alphanumeric() || c == b'.';
        match part {
            TimePart::Pre1 => {
                if c != b' ' {
                    if !(c.is_ascii_alphanumeric()) {
                        return Err(BAD);
                    }
                    self.start_item(len);
                    self.unix = Unix::Time(TimePart::Part1);
                }
            }
            TimePart::Part1 | TimePart::Part2 => {
                self.item_length += 1;
                if c == b' ' {
                    let next = match part {
                        TimePart::Part1 => TimePart::Pre2,
                        _ => TimePart::Pre3,
                    };
                    self.unix = Unix::Time(next);
                } else if !word(c) {
                    return Err(BAD);
                }
            }
            TimePart::Pre2 | TimePart::Pre3 => {
                self.item_length += 1;
                if c != b' ' {
                    if !c.is_ascii_alphanumeric() {
                        return Err(BAD);
                    }
                    let next = match part {
                        TimePart::Pre2 => TimePart::Part2,
                        _ => TimePart::Part3,
                    };
                    self.unix = Unix::Time(next);
                }
            }
            TimePart::Part3 => {
                self.item_length += 1;
                if c == b' ' {
                    self.cut(self.item_end()?)?;
                    self.offsets.time = self.item_offset;
                    self.unix = if self.line().kind == FileType::Symlink {
                        Unix::Symlink(Link::PreSpace)
                    } else {
                        Unix::FileName(NameEnd::PreSpace)
                    };
                } else if !word(c) && c != b':' {
                    return Err(BAD);
                }
            }
        }
        Ok(())
    }

    /// A Unix line's name ended with the line.
    fn unix_name_ends(
        &mut self,
        matches: &mut dyn FnMut(&[u8]) -> Result<bool, ErrorKind>,
    ) -> Result<(), ErrorKind> {
        self.cut(self.item_end()?)?;
        self.offsets.filename = self.item_offset;
        self.unix = Unix::FileType;
        self.insert(matches)
    }

    /// A symbolic link's name and target (`parse_unix_symlink`).
    fn symlink(
        &mut self,
        link: Link,
        c: u8,
        len: usize,
        matches: &mut dyn FnMut(&[u8]) -> Result<bool, ErrorKind>,
    ) -> Result<(), ErrorKind> {
        let eol = c == b'\r' || c == b'\n';
        let next = match link {
            Link::PreSpace => {
                if c != b' ' {
                    self.start_item(len);
                    Link::Name
                } else {
                    link
                }
            }
            Link::Name | Link::PreTarget1 | Link::PreTarget2 | Link::PreTarget3 => {
                self.item_length += 1;
                if eol {
                    return Err(BAD);
                }
                match (link, c) {
                    (Link::Name, b' ') => Link::PreTarget1,
                    (Link::Name, _) => Link::Name,
                    (Link::PreTarget1, b'-') => Link::PreTarget2,
                    (Link::PreTarget2, b'>') => Link::PreTarget3,
                    (Link::PreTarget3, b' ') => {
                        // The name ends before the arrow.
                        self.cut(
                            (self.item_offset + self.item_length)
                                .checked_sub(4)
                                .ok_or(BAD)?,
                        )?;
                        self.offsets.filename = self.item_offset;
                        self.item_length = 0;
                        self.item_offset = 0;
                        Link::PreTarget4
                    }
                    _ => Link::Name,
                }
            }
            Link::PreTarget4 => {
                if eol || len == 0 {
                    return Err(BAD);
                }
                self.start_item(len);
                Link::Target
            }
            Link::Target => {
                self.item_length += 1;
                if c == b'\r' {
                    Link::WindowsEol
                } else if c == b'\n' {
                    return self.target_ends(matches);
                } else {
                    link
                }
            }
            Link::WindowsEol => {
                if c != b'\n' {
                    return Err(BAD);
                }
                return self.target_ends(matches);
            }
        };
        self.unix = Unix::Symlink(next);
        Ok(())
    }

    fn target_ends(
        &mut self,
        matches: &mut dyn FnMut(&[u8]) -> Result<bool, ErrorKind>,
    ) -> Result<(), ErrorKind> {
        self.cut(self.item_end()?)?;
        self.offsets.symlink_target = self.item_offset;
        self.insert(matches)?;
        self.unix = Unix::FileType;
        Ok(())
    }

    /// A line in Windows NT's form (`parse_winnt`): a date, a time, the
    /// size or `<DIR>`, the name.
    fn nt(
        &mut self,
        c: u8,
        matches: &mut dyn FnMut(&[u8]) -> Result<bool, ErrorKind>,
    ) -> Result<(), ErrorKind> {
        // As in `unix`, never empty.
        let len = self.line().buf.len();
        match self.nt {
            Nt::Date => {
                self.item_length += 1;
                if self.item_length < 9 {
                    if !in_set(b"0123456789-", c) {
                        return Err(BAD);
                    }
                } else if self.item_length == 9 && c == b' ' {
                    self.nt = Nt::Time { time: false };
                } else {
                    return Err(BAD);
                }
            }
            Nt::Time { time } => {
                self.item_length += 1;
                if !time {
                    if c != b' ' && c != b'\t' {
                        self.nt = Nt::Time { time: true };
                    }
                } else if c == b' ' {
                    self.offsets.time = self.item_offset;
                    self.cut(self.item_end()?)?;
                    self.nt = Nt::DirOrSize { content: false };
                    self.item_length = 0;
                } else if !in_set(b"APM0123456789:", c) {
                    return Err(BAD);
                }
            }
            Nt::DirOrSize { content: false } => {
                if c != b' ' {
                    self.start_item(len);
                    self.nt = Nt::DirOrSize { content: true };
                }
            }
            Nt::DirOrSize { content: true } => {
                self.item_length += 1;
                if c == b' ' {
                    self.cut(self.item_end()?)?;
                    let at = self.item_offset;
                    let (kind, size) = if self.text(at) == b"<DIR>" {
                        (FileType::Directory, 0)
                    } else {
                        let (size, _) = number_after_blanks(self.text(at)).ok_or(BAD)?;
                        (FileType::File, size)
                    };
                    let line = self.line();
                    line.kind = kind;
                    line.size = size;
                    line.size_known = true;
                    self.item_length = 0;
                    self.nt = Nt::FileName(NameEnd::PreSpace);
                }
            }
            Nt::FileName(NameEnd::PreSpace) => {
                if c != b' ' {
                    self.start_item(len);
                    self.nt = Nt::FileName(NameEnd::Name);
                }
            }
            Nt::FileName(NameEnd::Name) => {
                self.item_length += 1;
                if c == b'\r' {
                    self.nt = Nt::FileName(NameEnd::WindowsEol);
                    self.cut(len - 1)?;
                } else if c == b'\n' {
                    self.offsets.filename = self.item_offset;
                    self.cut(len - 1)?;
                    self.insert(matches)?;
                    self.nt = Nt::Date;
                }
            }
            Nt::FileName(NameEnd::WindowsEol) => {
                if c != b'\n' {
                    return Err(BAD);
                }
                self.offsets.filename = self.item_offset;
                self.insert(matches)?;
                self.nt = Nt::Date;
            }
        }
        Ok(())
    }

    /// The line is read: its file kept if its name is one and matches,
    /// and, for a link, its target points once (`ftp_pl_insert_finfo`).
    fn insert(
        &mut self,
        matches: &mut dyn FnMut(&[u8]) -> Result<bool, ErrorKind>,
    ) -> Result<(), ErrorKind> {
        let line = self.line.take().expect("a line was read");
        let entry = Entry {
            line,
            at: self.offsets,
        };
        let info = entry.info();
        // A real file's name has no slash.
        let keep = !info.name.contains(&b'/')
            && matches(info.name)?
            && !info
                .target
                .is_some_and(|t| t.windows(4).any(|w| w == b" -> "));
        if keep {
            self.files
                .try_reserve(1)
                .map_err(|_| ErrorKind::OutOfMemory)?;
            // Room was made above: it does not grow.
            #[allow(clippy::disallowed_methods)]
            self.files.push_back(entry);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
