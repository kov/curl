//! `CURLINFO_CERTINFO`: the transfer's report of the peer's chain, as
//! the `struct curl_certinfo` C hands out, a list of `label:value` lines
//! per certificate, owned by the handle.

#![allow(unsafe_code)]

use core::ffi::c_int;
use core::ptr;

use curl_alloc::{OutOfMemory, TryVec as _};
use curl_core::report::CertInfo;

use crate::ffi;

/// The chain as C reads it, made again only when the report's differs,
/// so a pointer handed out lives until a later transfer's chain differs,
/// or the handle goes.
pub(crate) struct Kept {
    /// Each certificate's lines, each ended by a zero byte.
    lines: Vec<Vec<Vec<u8>>>,
    /// The list nodes, every certificate's in turn, pointing into
    /// `lines`.
    nodes: Vec<ffi::curl_slist>,
    /// Each certificate's first node, or null for one with no lines.
    heads: Vec<*mut ffi::curl_slist>,
    view: ffi::curl_certinfo,
}

impl Default for Kept {
    fn default() -> Kept {
        Kept {
            lines: Vec::new(),
            nodes: Vec::new(),
            heads: Vec::new(),
            view: ffi::curl_certinfo {
                num_of_certs: 0,
                certinfo: ptr::null_mut(),
            },
        }
    }
}

impl Kept {
    /// The chain `info` reports, none being none, as C's
    /// `struct curl_certinfo`: a pointer to the handle's, alive as long
    /// as `self` is not moved and made again.
    pub(crate) fn view(
        &mut self,
        info: Option<&CertInfo>,
    ) -> Result<*mut ffi::curl_certinfo, OutOfMemory> {
        let certs = info.map_or(&[][..], CertInfo::certs);
        if !self.same(certs) {
            *self = Kept::default();
            self.make(certs)?;
        }
        Ok(&raw mut self.view)
    }

    fn same(&self, certs: &[Vec<Vec<u8>>]) -> bool {
        self.lines.len() == certs.len()
            && self.lines.iter().zip(certs).all(|(kept, lines)| {
                kept.len() == lines.len()
                    && kept
                        .iter()
                        .zip(lines)
                        .all(|(k, l)| k.strip_suffix(b"\0") == Some(l.as_slice()))
            })
    }

    /// Make the view of `certs`, on a `Kept` just made.
    fn make(&mut self, certs: &[Vec<Vec<u8>>]) -> Result<(), OutOfMemory> {
        let total = certs.iter().map(Vec::len).sum();
        self.lines
            .try_reserve_exact(certs.len())
            .map_err(|_| OutOfMemory)?;
        self.heads
            .try_reserve_exact(certs.len())
            .map_err(|_| OutOfMemory)?;
        self.nodes
            .try_reserve_exact(total)
            .map_err(|_| OutOfMemory)?;
        for cert in certs {
            let mut kept = Vec::new();
            kept.try_reserve_exact(cert.len())
                .map_err(|_| OutOfMemory)?;
            for line in cert {
                let mut c = Vec::new();
                c.try_reserve_exact(line.len() + 1)
                    .map_err(|_| OutOfMemory)?;
                c.try_extend_from_slice(line)?;
                c.try_push(0)?;
                kept.try_push(c)?;
            }
            self.lines.try_push(kept)?;
        }
        // The room for every node is reserved: no push below moves them,
        // and a node's pointer to the next stays good.
        for kept in &self.lines {
            for line in kept {
                self.nodes.try_push(ffi::curl_slist {
                    data: line.as_ptr().cast_mut().cast(),
                    next: ptr::null_mut(),
                })?;
            }
        }
        let base = self.nodes.as_mut_ptr();
        let mut at = 0;
        for kept in &self.lines {
            let n = kept.len();
            for j in at..(at + n).saturating_sub(1) {
                // SAFETY: `j` and `j + 1` are nodes of this certificate's,
                // within the vector `base` points at the first of; every
                // node is reached through `base` alone.
                unsafe { (*base.wrapping_add(j)).next = base.wrapping_add(j + 1) };
            }
            // `at` is this certificate's first node, if it has any.
            let head = if n == 0 {
                ptr::null_mut()
            } else {
                base.wrapping_add(at)
            };
            self.heads.try_push(head)?;
            at += n;
        }
        self.view = ffi::curl_certinfo {
            num_of_certs: c_int::try_from(certs.len()).map_err(|_| OutOfMemory)?,
            certinfo: if certs.is_empty() {
                ptr::null_mut()
            } else {
                self.heads.as_mut_ptr()
            },
        };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ffi::CStr;

    /// Each certificate's lines, read as C reads them.
    fn read(view: *mut ffi::curl_certinfo) -> Vec<Vec<String>> {
        // SAFETY: a view `Kept` made, alive here.
        let view = unsafe { &*view };
        (0..usize::try_from(view.num_of_certs).unwrap())
            .map(|i| {
                // SAFETY: as above: `num_of_certs` heads.
                let mut node = unsafe { *view.certinfo.wrapping_add(i) };
                let mut lines = Vec::new();
                while !node.is_null() {
                    // SAFETY: a node of the view, its data a C string.
                    let n = unsafe { &*node };
                    // SAFETY: as above.
                    lines.push(
                        unsafe { CStr::from_ptr(n.data) }
                            .to_str()
                            .unwrap()
                            .to_owned(),
                    );
                    node = n.next;
                }
                lines
            })
            .collect()
    }

    #[test]
    fn the_chain_reads_as_c_s_lists_and_lives_while_unchanged() {
        let mut kept = Kept::default();
        let none = kept.view(None).unwrap();
        // SAFETY: as above.
        assert_eq!(unsafe { (*none).num_of_certs }, 0);
        // SAFETY: as above.
        assert!(unsafe { (*none).certinfo }.is_null());
        let mut info = CertInfo::new(3).unwrap();
        info.push(0, b"Subject", b"CN = localhost").unwrap();
        info.push(0, b"Cert", b"PEM").unwrap();
        info.push(2, b"Subject", b"CN = ca").unwrap();
        let view = kept.view(Some(&info)).unwrap();
        assert_eq!(
            read(view),
            [
                vec!["Subject:CN = localhost", "Cert:PEM"],
                vec![],
                vec!["Subject:CN = ca"]
            ]
        );
        // SAFETY: as above.
        let first = unsafe { (*view).certinfo };
        // SAFETY: as above.
        let first = unsafe { *first };
        // Asked again for the same chain, the same lists.
        let again = kept.view(Some(&info)).unwrap();
        // SAFETY: as above.
        let again = unsafe { (*again).certinfo };
        // SAFETY: as above.
        assert_eq!(unsafe { *again }, first);
        let mut other = CertInfo::new(1).unwrap();
        other.push(0, b"Subject", b"CN = other").unwrap();
        assert_eq!(
            read(kept.view(Some(&other)).unwrap()),
            [vec!["Subject:CN = other"]]
        );
    }
}
