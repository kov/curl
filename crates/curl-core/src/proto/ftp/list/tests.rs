use super::*;

/// The lines of `tests/directories.pm`'s `/fully_simulated/UNIX/`, as its
/// `ftp_createcontent` writes them.
const UNIX: &[u8] = b"drwxrwxrwx    4 ftp-default ftp-default   20480 Apr 27  5:12 .\r\n\
drwxrwxrwx    4 ftp-default ftp-default   20480 Apr 23  3:12 ..\r\n\
-r--r--r--    1 ftp-default ftp-default      38 Jan 11 10:00 chmod1\r\n\
-rw-rw-rw-    1 ftp-default ftp-default      38 Feb  1  8:00 chmod2\r\n\
-rwxrwxrwx    1 ftp-default ftp-default      38 Feb  1  8:00 chmod3\r\n\
d--S--S--t    1 ftp-default ftp-default    4096 May  4  4:31 chmod4\r\n\
d--s--s--T    1 ftp-default ftp-default    4096 May  4  4:31 chmod5\r\n\
-rw-r--r--    1 ftp-default ftp-default       0 Apr 27 11:01 empty_file.dat\r\n\
-rw-r--r--    1 ftp-default ftp-default      35 Apr 27 11:01 file.txt\r\n\
lrwxrwxrwx    1 ftp-default ftp-default       0 Jan  6  4:42 link -> file.txt\r\n\
lrwxrwxrwx    1 ftp-default ftp-default       0 Jan  6  4:45 link_absolute -> /data/ftp/file.txt\r\n\
drwxrwxrwx    4 ftp-default ftp-default    4096 Jan 23  2:05 .NeXT\r\n\
-rw-r--r--    1 ftp-default ftp-default      47 Apr 27 11:01 someothertext.txt\r\n\
drwxr-xrwx    2 ftp-default ftp-default    4096 Apr 23  3:12 weirddir.txt\r\n";

/// `/fully_simulated/DOS/`'s, the same way.
const DOS: &[u8] = b"04-27-10  05:12AM       <DIR>          .\r\n\
04-23-10  03:12AM       <DIR>          ..\r\n\
01-11-10  10:00AM                   38 chmod1\r\n\
02-01-10  08:00AM                   38 chmod2\r\n\
02-01-10  08:00AM                   38 chmod3\r\n\
05-04-10  04:31AM       <DIR>          chmod4\r\n\
05-04-10  04:31AM       <DIR>          chmod5\r\n\
04-27-10  11:01AM                    0 empty_file.dat\r\n\
04-27-10  11:01AM                   35 file.txt\r\n\
01-23-05  02:05AM       <DIR>          .NeXT\r\n\
04-27-10  11:01AM                   47 someothertext.txt\r\n\
04-23-10  03:12AM       <DIR>          weirddir.txt\r\n";

fn read(listing: &[u8], pieces: usize) -> Listing {
    let mut l = Listing::new();
    for piece in listing.chunks(pieces.max(1)) {
        l.feed(piece, &mut |_| Ok(true));
    }
    l
}

fn names(l: &Listing) -> Vec<&[u8]> {
    l.files().iter().map(|e| e.info().name).collect()
}

/// Each file type's letter and each execute letter's high bit, as C's
/// parser reads them.
#[test]
fn each_file_type_and_mode_letter_reads_as_c_reads_it() {
    let listing = b"-rwsr-Sr-t 1 u g 1 Jan 17 11:01 f\r\n\
prw-r--r-- 1 u g 0 Jan 17 11:01 p\r\n\
srwxr-sr-T 1 u g 0 Jan 17 11:01 s\r\n\
crw-r--r-- 1 u g 0 Jan 17 11:01 c\r\n\
brw-r--r-- 1 u g 0 Jan 17 11:01 b\r\n\
Drw-r--r-- 1 u g 0 Jan 17 11:01 D\r\n\
drwxr-xr-x 1 u g 0 Jan 17 11:01 d\r\n\
lrwxrwxrwx 1 u g 0 Jan 17 11:01 l -> t\r\n";
    let l = read(listing, listing.len());
    assert_eq!(l.error(), None);
    let read: Vec<_> = l
        .files()
        .iter()
        .map(|e| (e.info().kind, e.info().perm))
        .collect();
    assert_eq!(
        read,
        [
            (FileType::File, Some(0o7745)),
            (FileType::NamedPipe, Some(0o644)),
            (FileType::Socket, Some(0o3754)),
            (FileType::DeviceChar, Some(0o644)),
            (FileType::DeviceBlock, Some(0o644)),
            (FileType::Door, Some(0o644)),
            (FileType::Directory, Some(0o755)),
            (FileType::Symlink, Some(0o777)),
        ]
    );
}

/// The blanks C's parser passes over and the ones it fails on, as it
/// reads these lines.
#[test]
fn blanks_read_as_c_reads_them() {
    let one = |line: &[u8]| {
        let l = read(line, line.len());
        let first = l.files().front().map(|e| {
            let i = e.info();
            (
                i.size,
                i.user.map(<[u8]>::to_vec),
                i.group.map(<[u8]>::to_vec),
            )
        });
        (l.error(), first)
    };
    // A Windows NT size after a tab, the tab passed over with the field.
    assert_eq!(
        one(b"01-01-01  01:01AM \t5 n\r\n"),
        (None, Some((Some(5), None, None)))
    );
    // Spaces after the tab start no field of their own.
    assert_eq!(
        one(b"01-01-01  01:01AM    \t  7 n\r\n"),
        (Some(ErrorKind::FtpBadFileList), None)
    );
    // A Unix line's fields after two spaces as after one.
    assert_eq!(
        one(b"-rw-r--r-- 1  u  g 5 Jan 17 11:01 n\r\n"),
        (
            None,
            Some((Some(5), Some(b"u".to_vec()), Some(b"g".to_vec())))
        )
    );
    // Its link count and its size are digits, a tab before one no blank.
    assert_eq!(
        one(b"drwxr-xr-x x u g 0 Jan 17 11:01 n\r\n"),
        (Some(ErrorKind::FtpBadFileList), None)
    );
    assert_eq!(
        one(b"-rw-r--r-- 1 u g \t5 Jan 17 11:01 n\r\n"),
        (Some(ErrorKind::FtpBadFileList), None)
    );
}

/// A time's parts may hold dots, and no other punctuation, as C's parser
/// reads them.
#[test]
fn a_time_reads_as_c_reads_it() {
    let time = |line: &[u8]| {
        let l = read(line, line.len());
        let time = l.files().front().map(|e| e.info().time.to_vec());
        (l.error(), time)
    };
    assert_eq!(
        time(b"-rw-r--r-- 1 u g 5 Jan. 17. 11:01 n\r\n"),
        (None, Some(b"Jan. 17. 11:01".to_vec()))
    );
    assert_eq!(
        time(b"-rw-r--r-- 1 u g 5 Jan 17 11.01 n\r\n"),
        (None, Some(b"Jan 17 11.01".to_vec()))
    );
    assert_eq!(
        time(b"-rw-r--r-- 1 u g 5 Jan, 17 11:01 n\r\n"),
        (Some(ErrorKind::FtpBadFileList), None)
    );
}

#[test]
fn a_unix_listing_reads_as_c_reads_it() {
    let l = read(UNIX, UNIX.len());
    assert_eq!(l.error(), None);
    assert_eq!(l.files().len(), 14);
    let dot = l.files()[0].info();
    assert_eq!(
        dot,
        FileInfo {
            name: b".",
            kind: FileType::Directory,
            perm: Some(0o777),
            hardlinks: Some(4),
            size: Some(20480),
            time: b"Apr 27  5:12",
            perm_text: Some(b"rwxrwxrwx"),
            user: Some(b"ftp-default"),
            group: Some(b"ftp-default"),
            target: None,
        }
    );
    let perms: Vec<_> = l.files().iter().map(|e| e.info().perm).collect();
    assert_eq!(perms[2..7], [0o444, 0o666, 0o777, 0o7001, 0o7110].map(Some));
    let link = l.files()[9].info();
    assert_eq!(
        (link.name, link.kind, link.target),
        (&b"link"[..], FileType::Symlink, Some(&b"file.txt"[..]))
    );
    assert_eq!(
        l.files()[10].info().target,
        Some(&b"/data/ftp/file.txt"[..])
    );
}

#[test]
fn a_windows_nt_listing_reads_as_c_reads_it() {
    let l = read(DOS, DOS.len());
    assert_eq!(l.error(), None);
    assert_eq!(l.files().len(), 12);
    let chmod1 = l.files()[2].info();
    assert_eq!(
        chmod1,
        FileInfo {
            name: b"chmod1",
            kind: FileType::File,
            perm: None,
            hardlinks: None,
            size: Some(38),
            time: b"01-11-10  10:00AM",
            perm_text: None,
            user: None,
            group: None,
            target: None,
        }
    );
    let dot = l.files()[0].info();
    assert_eq!((dot.kind, dot.size), (FileType::Directory, Some(0)));
}

/// The listing comes in whatever pieces the data connection gives: a
/// line split anywhere reads the same.
#[test]
fn a_listing_reads_the_same_in_any_pieces() {
    for listing in [UNIX, DOS] {
        let whole = read(listing, listing.len());
        for size in [1, 2, 3, 7, 64] {
            assert_eq!(names(&read(listing, size)), names(&whole));
        }
    }
}

/// A name with a slash, one the pattern does not match and a link that
/// points through another arrow are passed over; the pattern is asked of
/// the others.
#[test]
fn only_files_whose_names_match_are_kept() {
    let listing = b"-rw-r--r--    1 u g       5 Jan 17 11:01 really/special\r\n\
-rw-r--r--    1 u g       5 Jan 17 11:01 a.txt\r\n\
-rw-r--r--    1 u g       5 Jan 17 11:01 b.dat\r\n\
lrwxrwxrwx    1 u g       0 Jan  6  4:42 two -> x -> y\r\n\
lrwxrwxrwx    1 u g       0 Jan  6  4:42 one -> x\r\n";
    let mut asked = Vec::new();
    let mut l = Listing::new();
    l.feed(listing, &mut |name| {
        asked.push(name.to_vec());
        Ok(name != b"b.dat")
    });
    assert_eq!(l.error(), None);
    assert_eq!(names(&l), [&b"a.txt"[..], b"one"]);
    assert_eq!(asked, [&b"a.txt"[..], b"b.dat", b"two", b"one"]);
}

/// A line too long for C's buffer fails the listing, as C reports it:
/// out of memory.
#[test]
fn a_line_longer_than_c_s_buffer_fails_the_listing() {
    let line = |name_len: usize| {
        let mut l = b"-rw-r--r--    1 u g       5 Jan 17 11:01 ".to_vec();
        l.resize(l.len() + name_len, b'n');
        l.extend_from_slice(b"\n");
        l
    };
    let head = line(0).len() - 1;
    // The longest line C holds: the line feed is its last byte.
    let longest = line(MAX_LINE - 2 - head);
    assert_eq!(longest.len(), MAX_LINE - 1);
    let l = read(&longest, 1000);
    assert_eq!((l.error(), l.files().len()), (None, 1));
    let l = read(&line(MAX_LINE - 1 - head), 1000);
    assert_eq!(l.error(), Some(ErrorKind::OutOfMemory));
}

/// Once a line fails, nothing after it is read: the files before it
/// stay, and the failure is kept.
#[test]
fn a_failed_listing_reads_no_more() {
    let mut l = Listing::new();
    let lines: Vec<&[u8]> = UNIX.split_inclusive(|&b| b == b'\n').collect();
    l.feed(&lines[..5].concat(), &mut |_| Ok(true));
    let before = l.files().len();
    assert_eq!(before, 5);
    l.feed(b"?garbage\r\n", &mut |_| Ok(true));
    assert_eq!(l.error(), Some(ErrorKind::FtpBadFileList));
    l.feed(UNIX, &mut |_| Ok(true));
    assert_eq!(l.files().len(), before);
}

/// A listing that starts `total N`, as `ls -l` writes it, is read past
/// its total, whatever its line ends and however it comes. C's reader
/// takes the line feed that ends the total for the next line's file
/// type, and fails every such listing (DIVERGENCE.md). A first line
/// that only starts with a `t` still fails.
#[test]
fn a_listing_that_starts_with_its_total_is_read() {
    let lf: Vec<u8> = UNIX.iter().copied().filter(|&b| b != b'\r').collect();
    for (total, rest) in [(&b"total 20\r\n"[..], UNIX), (b"total 20\n", &lf)] {
        let listing = [total, rest].concat();
        for pieces in [1, 7, listing.len()] {
            let alone = read(rest, pieces);
            let l = read(&listing, pieces);
            assert_eq!(l.error(), None, "{pieces}");
            assert_eq!(alone.files().len(), 14, "{pieces}");
            assert_eq!(names(&l), names(&alone), "{pieces}");
        }
    }
    let l = read(b"totally\r\n", 9);
    assert_eq!(l.error(), Some(ErrorKind::FtpBadFileList));
}

/// A size too big to hold is not known, and the field stays open to the
/// next space, so the line fails at the time that follows; a link count
/// too big is not known.
#[test]
fn numbers_too_big_are_not_known() {
    let big = b"-rw-r--r-- 99999999999999999999 u g 5 Jan 17 11:01 n\r\n";
    let l = read(big, big.len());
    assert_eq!(l.error(), None);
    let n = l.files()[0].info();
    assert_eq!((n.hardlinks, n.size), (None, Some(5)));
    let big = b"-rw-r--r-- 1 u g 99999999999999999999 Jan 17 11:01 n\r\n";
    assert_eq!(
        read(big, big.len()).error(),
        Some(ErrorKind::FtpBadFileList)
    );
}

/// A tiny generator of the pseudo-random choices the mutations make,
/// the same on every run.
struct Choices(u64);

impl Choices {
    fn next(&mut self, below: usize) -> usize {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 % below as u64) as usize
    }
}

/// The listings, mutated many ways (bytes changed, cut, spliced in from
/// elsewhere, repeated), are the server's to send: none panics the
/// reader, a failure is one of the listing's, and a listing reads the
/// same whatever pieces it comes in.
#[test]
fn a_hostile_listing_fails_without_a_panic() {
    let mut choose = Choices(0x9e37_79b9_7f4a_7c15);
    let interesting = b" \r\n\t\0-dlrwxsStT>:<DIR>0123456789APM/.";
    let (mut failed, mut kept) = (0, 0);
    for round in 0..4000 {
        let seed = if round % 2 == 0 { UNIX } else { DOS };
        let mut m = seed.to_vec();
        for _ in 0..1 + choose.next(8) {
            let at = choose.next(m.len().max(1));
            match choose.next(5) {
                0 if !m.is_empty() => m[at] = interesting[choose.next(interesting.len())],
                1 if !m.is_empty() => m[at] = choose.next(256) as u8,
                2 => m.truncate(at),
                3 => {
                    let from = choose.next(seed.len());
                    let len = choose.next(80).min(seed.len() - from);
                    let piece = seed[from..from + len].to_vec();
                    m.splice(at.min(m.len())..at.min(m.len()), piece);
                }
                _ => {
                    let len = choose.next(40).min(m.len().saturating_sub(at));
                    let piece = m[at..at + len].to_vec();
                    m.splice(at..at, piece);
                }
            }
        }
        let whole = read(&m, m.len());
        assert!(
            matches!(whole.error(), None | Some(ErrorKind::FtpBadFileList)),
            "round {round}"
        );
        failed += usize::from(whole.error().is_some());
        kept += whole.files().len();
        let pieces = read(&m, 1 + choose.next(16));
        assert_eq!(whole.error(), pieces.error(), "round {round}");
        assert_eq!(names(&whole), names(&pieces), "round {round}");
        for e in whole.files() {
            let info = e.info();
            assert!(!info.name.contains(&b'/'), "round {round}");
        }
    }
    // Both ways out were taken, many times.
    assert!(failed > 1000 && failed < 3500, "{failed} rounds failed");
    assert!(kept > 10_000, "{kept} files kept");
}

/// A Windows NT line's date is eight bytes and a space, its time comes
/// after any blanks, and a line may end with a bare line feed, as C's
/// parser reads them (`parse_winnt`).
#[test]
fn a_windows_nt_line_s_date_time_and_end_read_as_c_reads_them() {
    let one = |line: &[u8]| {
        let l = read(line, line.len());
        let first = l.files().front().map(|e| {
            let i = e.info();
            (i.name.to_vec(), i.time.to_vec(), i.size)
        });
        (l.error(), first)
    };
    let file = |time: &[u8]| Some((b"n".to_vec(), time.to_vec(), Some(5)));
    // The ninth byte of the date must be its space.
    assert_eq!(
        one(b"01-01-011 01:01AM 5 n\r\n"),
        (Some(ErrorKind::FtpBadFileList), None)
    );
    // One space before the time, or blanks of either kind.
    assert_eq!(
        one(b"01-01-01 01:01AM 5 n\r\n"),
        (None, file(b"01-01-01 01:01AM"))
    );
    assert_eq!(
        one(b"01-01-01 \t 01:01AM 5 n\r\n"),
        (None, file(b"01-01-01 \t 01:01AM"))
    );
    assert_eq!(
        one(b"01-01-01    01:01AM 5 n\r\n"),
        (None, file(b"01-01-01    01:01AM"))
    );
    // A bare line feed ends the name as CRLF does.
    let lf = b"01-01-01  01:01AM 5 n\n01-01-01  01:02AM <DIR> d\n";
    let l = read(lf, lf.len());
    assert_eq!(l.error(), None);
    assert_eq!(names(&l), [&b"n"[..], b"d"]);
}

/// A zero byte passes the checks a field's bytes are held to, as C's
/// `strchr` finds the string's end in any set (`parse_winnt`): such a
/// line is read, not failed.
#[test]
fn a_zero_byte_passes_a_field_s_check_as_in_c() {
    let l = read(b"01-0\x00-01  01:01AM 5 n\r\n", 64);
    assert_eq!((l.error(), names(&l)), (None, vec![&b"n"[..]]));
}

/// A first line that starts with `t` is read to its line feed, and
/// checked there as C's reader checks a `total N`, its count of the line
/// so far leaving out the CR it takes back out (`parse_unix_totalsize`):
/// a total passes, and the reader is on to the next line's file type; any
/// other line fails. C then takes the total's line feed for the file
/// type, and fails it too (DIVERGENCE.md).
#[test]
fn a_first_line_starting_with_t_is_checked_at_its_line_feed() {
    for (line, checked) in [
        (&b"total 20\r\n"[..], true),
        (b"total 20\n", true),
        (b"total \t 20\r\n", true),
        (b"total \r\n", true),
        (b"total\r\n", false),
        (b"total 2x\r\n", false),
        (b"total x2\r\n", false),
        (b"totally\r\n", false),
        (b"t\r\n", false),
    ] {
        let said = line.escape_ascii().to_string();
        let (before, lf) = line.split_at(line.len() - 1);
        let mut l = Listing::new();
        for &b in before {
            l.feed(&[b], &mut |_| Ok(true));
            assert_eq!(l.error(), None, "{said}");
        }
        let held = l.line.as_ref().map(|line| line.buf.clone());
        let unread: Vec<u8> = before.iter().copied().filter(|&b| b != b'\r').collect();
        assert_eq!(held, Some(unread.clone()), "{said}");
        assert_eq!(l.item_length, unread.len(), "{said}");
        l.feed(lf, &mut |_| Ok(true));
        assert!(l.files().is_empty());
        if checked {
            assert_eq!((l.error(), l.unix), (None, Unix::FileType), "{said}");
            assert_eq!(l.line.as_ref().map(|line| line.buf.len()), Some(0));
            l.feed(b"-rw-r--r-- 1 u g 5 Jan 17 11:01 n\r\n", &mut |_| Ok(true));
            assert_eq!((l.error(), names(&l)), (None, vec![&b"n"[..]]), "{said}");
        } else {
            let failed = (l.error(), l.unix);
            let still = Unix::TotalSize { reading: true };
            assert_eq!(failed, (Some(ErrorKind::FtpBadFileList), still), "{said}");
        }
    }
}

/// A link's name runs to the first ` -> `, spaces and part arrows and
/// all; its target runs to the line's end, CRLF or a bare line feed; a
/// line that ends before the arrow, or before a target after it, or
/// has a CR inside its target, fails, as C's parser reads them
/// (`parse_unix_symlink`).
#[test]
fn a_link_s_name_and_target_read_as_c_reads_them() {
    let link = |rest: &[u8]| {
        let line = [&b"lrwxrwxrwx 1 u g 0 Jan 17 11:01 "[..], rest].concat();
        let l = read(&line, line.len());
        let first = l.files().front().map(|e| {
            let i = e.info();
            (i.name.to_vec(), i.target.map(<[u8]>::to_vec))
        });
        (l.error(), first)
    };
    let read_as = |name: &[u8], target: &[u8]| (None, Some((name.to_vec(), Some(target.to_vec()))));
    let bad = (Some(ErrorKind::FtpBadFileList), None);
    assert_eq!(link(b"my link -> t\r\n"), read_as(b"my link", b"t"));
    assert_eq!(link(b"a -x -> t\r\n"), read_as(b"a -x", b"t"));
    assert_eq!(link(b"a ->b -> t\r\n"), read_as(b"a ->b", b"t"));
    assert_eq!(link(b"  a -> t u\n"), read_as(b"a", b"t u"));
    for cut in [
        &b"a\r\n"[..],
        b"a \r\n",
        b"a -\r\n",
        b"a ->\r\n",
        b"a -> \r\n",
        b"a -> \n",
        b"a -> t\rx\r\n",
    ] {
        assert_eq!(link(cut), bad, "{}", cut.escape_ascii());
    }
    // The next line is read after a link's, however it ended.
    let two = b"lrwxrwxrwx 1 u g 0 Jan 17 11:01 a -> t\n\
lrwxrwxrwx 1 u g 0 Jan 17 11:01 b -> u\r\n\
-rw-r--r-- 1 u g 5 Jan 17 11:01 c\r\n";
    let l = read(two, two.len());
    assert_eq!(l.error(), None);
    assert_eq!(names(&l), [&b"a"[..], b"b", b"c"]);
}
