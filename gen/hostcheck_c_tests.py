#!/usr/bin/env python3
"""
Generate the certificate host check's test cases from C's own test.

From tests/unit/unit1397.c, which tests `Curl_cert_hostcheck`:

  crates/curl-openssl/src/hostcheck/c_tests.rs: each host, the pattern a
  certificate names, and whether they match; and the patterns with a
  zero byte inside that must match nothing.
"""

import ast
import pathlib
import re

import genlib
from genlib import ROOT, check

HERE = pathlib.Path(__file__).resolve()
UNIT1397 = ROOT / "tests" / "unit" / "unit1397.c"
OUT = ROOT / "crates" / "curl-openssl" / "src" / "hostcheck" / "c_tests.rs"

# One or more C string literals side by side, as C joins them.
LITERALS = r'((?:"(?:[^"\\]|\\.)*"\s*)+)'
ROW = re.compile(r"\{\s*" + LITERALS + r",\s*" + LITERALS + r",\s*(TRUE|FALSE)\s*\}")
# A call of the check with a pattern of a given length and a host.
NUL_CALL = re.compile(r'Curl_cert_hostcheck\(("(?:[^"\\]|\\.)*"), (\d+), ("(?:[^"\\]|\\.)*"), (\d+)\)')


def joined(literals):
    """Side-by-side C literals as one Rust byte string literal. Their only
    escapes are `\\x` of two digits not followed by a third, which Rust
    reads as C does."""
    parts = re.findall(r'"((?:[^"\\]|\\.)*)"', literals)
    text = "".join(parts)
    for m in re.finditer(r"\\(.)", text):
        check(m[1] in "x0", f"an escape unit1397's table was not expected to use: {m[0]}")
    for m in re.finditer(r"\\x([0-9a-fA-F]*)", text):
        check(len(m[1]) == 2, f"a \\x escape C reads otherwise than Rust: {m[0]}")
    return f'b"{text}"'


def table():
    src = UNIT1397.read_text()
    body = src[src.index("static const struct testcase tests[] = {"):]
    body = body[:body.index("{ NULL, NULL, FALSE }")]
    rows = ROW.findall(body)
    check(len(rows) == body.count("TRUE }") + body.count("FALSE }"), "a unit1397 row did not parse")
    check(len(rows) > 40, "unit1397's rows did not parse")
    return "".join(f"    ({joined(h)}, {joined(p)}, {m == 'TRUE'}),\n".replace("True", "true")
                   .replace("False", "false") for h, p, m in rows)


def nul_cases():
    src = UNIT1397.read_text()
    calls = NUL_CALL.findall(src)
    check(len(calls) == 2, "unit1397's zero-byte checks did not parse")
    out = []
    for pattern, plen, host, hlen in calls:
        p, h = joined(pattern), joined(host)
        check(len(ast.literal_eval(p)) == int(plen) and len(ast.literal_eval(h)) == int(hlen),
              "a zero-byte check's lengths are not its strings'")
        out.append(f"({p}, {h})")
    # On one line, as rustfmt puts a list that fits.
    line = "    &[" + ", ".join(out) + "];"
    check(len(line) <= 100, "the zero-byte cases no longer fit a line: lay them out as rustfmt does")
    return line


def main():
    inputs = [UNIT1397, ROOT / "gen" / "genlib.py", HERE]
    genlib.write(OUT, f"""{genlib.header(HERE, inputs)}\
//! Test cases of C's host check test.

/// unit1397: a host, the name a certificate gives, and whether the
/// certificate names the host.
pub(super) static UNIT1397: &[(&[u8], &[u8], bool)] = &[
{table()}];

/// unit1397: a name with a zero byte inside, which names neither host.
pub(super) static UNIT1397_NUL: &[(&[u8], &[u8])] =
{nul_cases()}
""")


if __name__ == "__main__":
    main()
