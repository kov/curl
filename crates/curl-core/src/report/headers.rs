//! The response headers of a transfer, every request's, for the
//! application to look up (`lib/headers.c`, `curl_easy_header`,
//! `curl_easy_nextheader`).

use std::ops::Range;

use curl_alloc::TryVec;

use crate::error::ErrorKind;
use crate::handler::HeaderOrigin;

/// The most headers a transfer stores (`MAX_HTTP_RESP_HEADER_COUNT`).
pub(crate) const MAX_HEADERS: usize = 5000;

/// A transfer's response headers, in the order they came.
#[derive(Clone, Debug, Default)]
pub struct HeaderStore {
    /// Tells this store's cursors from an earlier one's.
    generation: u32,
    /// The request headers are stored for now, counting from 0: one more
    /// for each redirect followed (C's `state.requests`).
    request: u16,
    bytes: Vec<u8>,
    entries: Vec<Entry>,
}

#[derive(Clone, Debug)]
struct Entry {
    name: Range<u32>,
    value: Range<u32>,
    origin: HeaderOrigin,
    request: u16,
}

/// Which origins to look among (`CURLH_*` bits).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Origins(u8);

impl Origins {
    pub const NONE: Origins = Origins(0);
    pub const ALL: Origins = Origins(0b1111);

    pub fn contains(self, origin: HeaderOrigin) -> bool {
        self.0 & Origins::from(origin).0 != 0
    }
}

impl From<HeaderOrigin> for Origins {
    fn from(origin: HeaderOrigin) -> Origins {
        Origins(match origin {
            HeaderOrigin::Header => 1,
            HeaderOrigin::Trailer => 2,
            HeaderOrigin::Connect => 4,
            HeaderOrigin::Interim => 8,
        })
    }
}

impl std::ops::BitOr for Origins {
    type Output = Origins;

    fn bitor(self, other: Origins) -> Origins {
        Origins(self.0 | other.0)
    }
}

impl std::ops::BitOr<HeaderOrigin> for Origins {
    type Output = Origins;

    fn bitor(self, other: HeaderOrigin) -> Origins {
        self | Origins::from(other)
    }
}

/// Which request's headers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Request {
    /// The last one so far (C's -1).
    Last,
    /// Counting from 0: one more for each redirect followed.
    Nth(u16),
}

/// Where `next` goes on from: a header it returned. One from an earlier
/// transfer of the same `Easy` leads nowhere.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeaderCursor {
    generation: u32,
    entry: u32,
}

/// A stored header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeaderView<'a> {
    pub name: &'a [u8],
    pub value: &'a [u8],
    pub origin: HeaderOrigin,
    /// This one's place among those of its name, origins and request.
    pub index: usize,
    /// How many of its name, origins and request there are.
    pub amount: usize,
    pub cursor: HeaderCursor,
}

/// Why a lookup found nothing (`CURLHcode`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderError {
    /// No headers at all (yet).
    NoHeaders,
    /// No request with that number was made.
    NoRequest,
    /// None of that name.
    Missing,
    /// Fewer of that name than the index asked for.
    BadIndex,
}

/// Space and tab (`ISBLANK`).
fn is_blank(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

impl HeaderStore {
    /// An empty store whose cursors are not `earlier`'s.
    pub(crate) fn after(earlier: &HeaderStore) -> HeaderStore {
        HeaderStore {
            generation: earlier.generation.wrapping_add(1),
            ..HeaderStore::default()
        }
    }

    /// Store one response header line, with its line ending
    /// (`Curl_headers_push`). The blank line ending a head is not one.
    pub(crate) fn push(&mut self, line: &[u8], origin: HeaderOrigin) -> Result<(), ErrorKind> {
        if matches!(line.first(), Some(b'\r' | b'\n')) {
            return Ok(());
        }
        let mut header = line.strip_suffix(b"\n").unwrap_or(line);
        header = header.strip_suffix(b"\r").unwrap_or(header);
        if header.len() == line.len() {
            // Not ended by CR or LF.
            return Err(ErrorKind::WeirdServerReply);
        }
        let leading = header.iter().take_while(|&&b| is_blank(b)).count();
        let header = &header[leading..];
        if header.is_empty() {
            return Err(ErrorKind::WeirdServerReply);
        }
        if self.entries.len() >= MAX_HEADERS {
            // "Too many response headers, 5000 is max"
            return Err(ErrorKind::TooLarge);
        }
        // The name runs to the colon; C's ends at a NUL too.
        let Some(colon) = header.iter().position(|&b| b == b':' || b == 0) else {
            return Err(ErrorKind::BadFunctionArgument);
        };
        if header[colon] == 0 {
            // "Invalid response header"
            return Err(ErrorKind::BadFunctionArgument);
        }
        let rest = &header[colon + 1..];
        let start = rest.iter().take_while(|&&b| is_blank(b)).count();
        let end = rest.len()
            - rest[start..]
                .iter()
                .rev()
                .take_while(|&&b| is_blank(b))
                .count();
        let base = self.bytes.len();
        self.bytes
            .try_extend_from_slice(header)
            .map_err(|_| ErrorKind::OutOfMemory)?;
        self.entries
            .try_push(Entry {
                name: span(base, 0..colon),
                value: span(base, colon + 1 + start..colon + 1 + end),
                origin,
                request: self.request,
            })
            .map_err(|_| ErrorKind::OutOfMemory)?;
        Ok(())
    }

    /// The `index`th header named `name`, ignoring case, among those of
    /// `origins` for `request` (`curl_easy_header`).
    pub fn get(
        &self,
        name: &[u8],
        index: usize,
        origins: Origins,
        request: Request,
    ) -> Result<HeaderView<'_>, HeaderError> {
        if self.entries.is_empty() {
            return Err(HeaderError::NoHeaders);
        }
        let request = self.request_number(request).ok_or(HeaderError::NoRequest)?;
        let amount = self.matching(name, origins, request).count();
        if amount == 0 {
            return Err(HeaderError::Missing);
        }
        let (at, _) = self
            .matching(name, origins, request)
            .nth(index)
            .ok_or(HeaderError::BadIndex)?;
        Ok(self.view(at, index, amount))
    }

    /// The header after `prev`, or the first, among those of `origins` for
    /// `request` (`curl_easy_nextheader`).
    pub fn next(
        &self,
        origins: Origins,
        request: Request,
        prev: Option<HeaderCursor>,
    ) -> Option<HeaderView<'_>> {
        let request = self.request_number(request)?;
        let from = match prev {
            None => 0,
            Some(c) if c.generation == self.generation => c.entry as usize + 1,
            Some(_) => return None,
        };
        let (at, e) = self
            .entries
            .iter()
            .enumerate()
            .skip(from)
            .find(|(_, e)| origins.contains(e.origin) && e.request == request)?;
        let name = self.text(&e.name);
        let index = self
            .matching(name, origins, request)
            .take_while(|&(i, _)| i < at)
            .count();
        let amount = self.matching(name, origins, request).count();
        Some(self.view(at, index, amount))
    }

    fn request_number(&self, request: Request) -> Option<u16> {
        match request {
            Request::Last => Some(self.request),
            Request::Nth(n) if n <= self.request => Some(n),
            Request::Nth(_) => None,
        }
    }

    /// The entries named `name`, of `origins`, for `request`, with their
    /// places.
    fn matching<'s>(
        &'s self,
        name: &'s [u8],
        origins: Origins,
        request: u16,
    ) -> impl Iterator<Item = (usize, &'s Entry)> + 's {
        self.entries.iter().enumerate().filter(move |(_, e)| {
            origins.contains(e.origin)
                && e.request == request
                && self.text(&e.name).eq_ignore_ascii_case(name)
        })
    }

    fn view(&self, at: usize, index: usize, amount: usize) -> HeaderView<'_> {
        let e = &self.entries[at];
        HeaderView {
            name: self.text(&e.name),
            value: self.text(&e.value),
            origin: e.origin,
            index,
            amount,
            cursor: HeaderCursor {
                generation: self.generation,
                entry: u32::try_from(at).expect("at most MAX_HEADERS entries"),
            },
        }
    }

    fn text(&self, r: &Range<u32>) -> &[u8] {
        &self.bytes[r.start as usize..r.end as usize]
    }
}

/// `r` within a line stored from `base`.
fn span(base: usize, r: Range<usize>) -> Range<u32> {
    let at = |i: usize| u32::try_from(base + i).expect("the store's bytes fit u32");
    at(r.start)..at(r.end)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(lines: &[(&[u8], HeaderOrigin)]) -> HeaderStore {
        let mut s = HeaderStore::default();
        for (line, origin) in lines {
            s.push(line, *origin).unwrap();
        }
        s
    }

    const H: HeaderOrigin = HeaderOrigin::Header;

    #[test]
    fn a_line_is_split_into_name_and_trimmed_value() {
        let s = store(&[
            (b"  Content-Type: \t text/plain \t\r\n", H),
            (b"Empty:\n", H),
        ]);
        let h = s
            .get(b"content-type", 0, Origins::ALL, Request::Last)
            .unwrap();
        assert_eq!(
            (h.name, h.value),
            (&b"Content-Type"[..], &b"text/plain"[..])
        );
        assert_eq!((h.index, h.amount, h.origin), (0, 1, H));
        let h = s.get(b"EMPTY", 0, Origins::ALL, Request::Last).unwrap();
        assert_eq!(h.value, b"");
    }

    #[test]
    fn what_is_not_a_header_line_is_refused_or_skipped() {
        let mut s = HeaderStore::default();
        assert_eq!(s.push(b"\r\n", H), Ok(()), "the end of the head");
        assert_eq!(s.push(b"\n", H), Ok(()));
        assert_eq!(s.push(b"a: b", H), Err(ErrorKind::WeirdServerReply));
        assert_eq!(s.push(b" \t\r\n", H), Err(ErrorKind::WeirdServerReply));
        assert_eq!(
            s.push(b"no colon\r\n", H),
            Err(ErrorKind::BadFunctionArgument)
        );
        assert_eq!(
            s.push(b"nul\0: x\r\n", H),
            Err(ErrorKind::BadFunctionArgument)
        );
        assert_eq!(
            s.get(b"a", 0, Origins::ALL, Request::Last),
            Err(HeaderError::NoHeaders)
        );
        // The name keeps what is before the colon, blanks and all.
        s.push(b"Name : v\r\n", H).unwrap();
        assert_eq!(
            s.get(b"Name", 0, Origins::ALL, Request::Last),
            Err(HeaderError::Missing)
        );
        assert!(s.get(b"Name ", 0, Origins::ALL, Request::Last).is_ok());
    }

    #[test]
    fn at_most_5000_headers_are_stored() {
        let mut s = HeaderStore::default();
        for _ in 0..MAX_HEADERS {
            s.push(b"a: b\r\n", H).unwrap();
        }
        assert_eq!(s.push(b"a: b\r\n", H), Err(ErrorKind::TooLarge));
        let h = s
            .get(b"a", MAX_HEADERS - 1, Origins::ALL, Request::Last)
            .unwrap();
        assert_eq!(h.amount, MAX_HEADERS);
    }

    #[test]
    fn origins_join() {
        let both = Origins::from(H) | HeaderOrigin::Trailer;
        assert!(both.contains(H) && both.contains(HeaderOrigin::Trailer));
        assert!(!both.contains(HeaderOrigin::Connect));
        assert_eq!(Origins::from(H) | H, Origins::from(H));
        assert!(!Origins::NONE.contains(H));
    }

    #[test]
    fn lookups_count_by_name_origin_and_index() {
        let s = store(&[
            (b"Set-Cookie: a\r\n", H),
            (b"Other: x\r\n", H),
            (b"set-cookie: b\r\n", H),
            (b"Set-Cookie: c\r\n", HeaderOrigin::Trailer),
        ]);
        let all = Origins::ALL;
        let h = s.get(b"Set-Cookie", 1, all, Request::Last).unwrap();
        assert_eq!((h.value, h.index, h.amount), (&b"b"[..], 1, 3));
        let h = s.get(b"Set-Cookie", 2, all, Request::Last).unwrap();
        assert_eq!((h.value, h.origin), (&b"c"[..], HeaderOrigin::Trailer));
        let only = Origins::from(H);
        assert_eq!(
            s.get(b"Set-Cookie", 2, only, Request::Last),
            Err(HeaderError::BadIndex)
        );
        assert_eq!(
            s.get(b"Set-Cookie", 1, only, Request::Last).unwrap().amount,
            2
        );
        assert_eq!(
            s.get(
                b"Set-Cookie",
                0,
                Origins::from(HeaderOrigin::Connect),
                Request::Last
            ),
            Err(HeaderError::Missing)
        );
        assert_eq!(
            s.get(b"Set-Cookie", 0, all, Request::Nth(1)),
            Err(HeaderError::NoRequest)
        );
        assert!(s.get(b"Set-Cookie", 0, all, Request::Nth(0)).is_ok());
    }

    #[test]
    fn next_walks_the_headers_in_order_with_their_counts() {
        let s = store(&[
            (b"A: 1\r\n", H),
            (b"B: 2\r\n", HeaderOrigin::Interim),
            (b"a: 3\r\n", H),
        ]);
        let mut seen = Vec::new();
        let mut prev = None;
        while let Some(h) = s.next(Origins::from(H), Request::Last, prev) {
            seen.push((h.value.to_vec(), h.index, h.amount));
            prev = Some(h.cursor);
        }
        assert_eq!(seen, [(b"1".to_vec(), 0, 2), (b"3".to_vec(), 1, 2)]);
        let first = s.next(Origins::ALL, Request::Last, None).unwrap();
        let second = s
            .next(Origins::ALL, Request::Last, Some(first.cursor))
            .unwrap();
        assert_eq!(second.value, b"2");
        assert_eq!(s.next(Origins::ALL, Request::Nth(1), None), None);
    }

    /// A cursor from an earlier store leads nowhere, where C reads freed
    /// memory.
    #[test]
    fn a_cursor_from_an_earlier_transfer_leads_nowhere() {
        let old = store(&[(b"A: 1\r\n", H)]);
        let cursor = old.next(Origins::ALL, Request::Last, None).unwrap().cursor;
        let mut new = HeaderStore::after(&old);
        new.push(b"A: 1\r\n", H).unwrap();
        new.push(b"B: 2\r\n", H).unwrap();
        assert_eq!(new.next(Origins::ALL, Request::Last, Some(cursor)), None);
    }
}
