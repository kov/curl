#!/usr/bin/env python3
"""
Generate the curl tool's built-in manual (`--manual`, `--help <option>`).

As C's build makes src/tool_hugehelp.c: `scripts/managen ascii` turns the
option pages listed in docs/cmdline-opts/Makefile.inc (DPAGES) into the
text manual, and src/mkhelp.pl puts its banner first. C's build compresses
the text with gzip where it has zlib (HAVE_LIBZ, which the reference build
has), so this does too:

  crates/curl-tool/src/manual.txt.gz: the text, gzip-compressed;

  crates/curl-tool/src/manual.rs: the compressed text, included, with the
  length and FNV-1a hash of the text it must inflate to, which a test of
  the tool checks. The header's hashes make `generated_is_fresh` fail when
  a page changes, so the compressed file, whose bytes depend on the zlib
  that made them, is never compared itself.
"""

import gzip
import pathlib
import re
import subprocess
import sys

import genlib
from genlib import ROOT, check

HERE = pathlib.Path(__file__).resolve()
OPTS = ROOT / "docs" / "cmdline-opts"
MAKEFILE = OPTS / "Makefile.inc"
MANAGEN = ROOT / "scripts" / "managen"
MKHELP = ROOT / "src" / "mkhelp.pl"
GZ_OUT = ROOT / "crates" / "curl-tool" / "src" / "manual.txt.gz"
RS_OUT = ROOT / "crates" / "curl-tool" / "src" / "manual.rs"


def dpages():
    """The option pages, in Makefile.inc's order."""
    text = MAKEFILE.read_text().replace("\\\n", " ")
    m = re.search(r"^DPAGES\s*=(.*)$", text, re.MULTILINE)
    check(m is not None, "no DPAGES in Makefile.inc")
    pages = m.group(1).split()
    check(len(pages) > 200, f"only {len(pages)} pages in DPAGES")
    return pages


def banner():
    """The lines mkhelp.pl puts before the manual, as Perl reads them."""
    lines = re.findall(r'^push @out, "(.*)";$', MKHELP.read_text(), re.MULTILINE)
    check(len(lines) == 5, f"{len(lines)} banner lines in mkhelp.pl")
    unescape = {"\\\\": "\\", "\\n": "\n", '\\"': '"'}
    return "".join(re.sub(r'\\[\\n"]', lambda e: unescape[e.group(0)], line)
                   for line in lines)


def manual():
    """The text the C build embeds."""
    ascii_page = subprocess.run(
        ["perl", str(MANAGEN), "ascii", *dpages()], cwd=OPTS, check=True,
        capture_output=True).stdout
    return banner().encode() + ascii_page


def main():
    text = manual()
    inputs = [MAKEFILE, OPTS / "mainpage.idx", *sorted(OPTS.glob("*.md")),
              MANAGEN, MKHELP]
    rs = genlib.header(HERE, inputs) + f"""\
//! The built-in manual (`src/tool_hugehelp.c`): the text
//! `scripts/managen ascii` makes of docs/cmdline-opts, after mkhelp.pl's
//! banner, compressed with gzip as C's build compresses it.

/// The manual, gzip-compressed.
pub(crate) static GZIPPED: &[u8] = include_bytes!("manual.txt.gz");

/// The length of the text it inflates to.
#[cfg(test)]
pub(crate) const LEN: usize = {len(text)};

/// The FNV-1a hash of the text it inflates to.
#[cfg(test)]
pub(crate) const HASH: u64 = 0x{genlib.fnv1a(text):016x};
"""
    genlib.write(RS_OUT, rs)
    if "--check" in sys.argv[1:]:
        check(GZ_OUT.exists() and gzip.decompress(GZ_OUT.read_bytes()) == text,
              f"{GZ_OUT.relative_to(ROOT)} is stale; run gen/all.py")
        return
    GZ_OUT.write_bytes(gzip.compress(text, compresslevel=9, mtime=0))


if __name__ == "__main__":
    main()
