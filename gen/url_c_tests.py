#!/usr/bin/env python3
"""
Generate the URL parser's test cases from C's own tests.

From tests/libtest/lib1560.c, which tests the URL API, and
tests/unit/unit1395.c, which tests the removal of dot segments:

  crates/curl-core/src/url/c_tests.rs: lib1560's `get_parts_list` (a URL
  and every part C gets from it, or the error parsing it gives) and
  `get_url_list` (a URL and the URL C gets back), and unit1395's pairs.

Rows inside `#if` blocks are kept or dropped as the reference build
compiles them, by its features and protocols in inventory/baseline.json.
Rows that ask for IDN conversions are dropped: the rewrite has none yet.
"""

import json
import pathlib
import re

import genlib
from genlib import ABI, ROOT, check

HERE = pathlib.Path(__file__).resolve()
LIB1560 = ROOT / "tests" / "libtest" / "lib1560.c"
UNIT1395 = ROOT / "tests" / "unit" / "unit1395.c"
OUT = ROOT / "crates" / "curl-core" / "src" / "url" / "c_tests.rs"

BASELINE = ROOT / "inventory" / "baseline.json"


def defined():
    """Which of the macros the tables test the reference build defines."""
    build = json.loads(BASELINE.read_text())["data"]
    check(build["system"][0].startswith("* curl ") and "(Linux)" in build["system"][0],
          "the reference build is not a Linux build")
    return {"USE_IDN": "IDN" in build["features"], "_WIN32": False,
            "CURL_DISABLE_LDAP": "ldap" not in build["protocols"],
            "CURL_DISABLE_WEBSOCKETS": "ws" not in build["protocols"]}

PARSE_FLAGS = {
    "CURLU_DEFAULT_SCHEME": "default_scheme",
    "CURLU_GUESS_SCHEME": "guess_scheme",
    "CURLU_NON_SUPPORT_SCHEME": "non_support_scheme",
    "CURLU_NO_AUTHORITY": "no_authority",
    "CURLU_PATH_AS_IS": "path_as_is",
    "CURLU_DISALLOW_USER": "disallow_user",
    "CURLU_ALLOW_SPACE": "allow_space",
    "CURLU_URLENCODE": "url_encode",
}
GET_FLAGS = {
    "CURLU_DEFAULT_PORT": "default_port",
    "CURLU_NO_DEFAULT_PORT": "no_default_port",
    "CURLU_DEFAULT_SCHEME": "default_scheme",
    "CURLU_URLDECODE": "url_decode",
    "CURLU_URLENCODE": "url_encode",
    "CURLU_GET_EMPTY": "get_empty",
    "CURLU_NO_GUESS_SCHEME": "no_guess_scheme",
}
IDN_FLAGS = {"CURLU_PUNYCODE", "CURLU_PUNY2IDN"}

TOKEN = re.compile(r'"(?:[^"\\]|\\.)*"|[A-Za-z_]\w*|\d+|[{}|,]')
ESCAPES = {"n": 10, "r": 13, "t": 9, "\\": 92, '"': 34, "'": 39}


def literal(tok):
    """The bytes of a C string literal."""
    out = bytearray()
    s = tok[1:-1].encode("latin-1")
    i = 0
    while i < len(s):
        c = s[i]
        if c != 0x5C:
            out.append(c)
            i += 1
            continue
        e = chr(s[i + 1])
        if e == "x":
            m = re.match(rb"[0-9a-fA-F]+", s[i + 2:])
            out.append(int(m[0], 16) & 0xFF)
            i += 2 + len(m[0])
        elif e in "01234567":
            m = re.match(rb"[0-7]{1,3}", s[i + 1:])
            out.append(int(m[0], 8) & 0xFF)
            i += 1 + len(m[0])
        else:
            check(e in ESCAPES, f"unknown escape \\{e}")
            out.append(ESCAPES[e])
            i += 2
    return bytes(out)


def table(src, name, macros, terminated=True):
    """The rows of the C array `name`, as lists of fields; a field is
    bytes, None for NULL, or a list of identifiers or numbers OR-ed."""
    start = src.index(f" {name}[] = {{")
    body = src[src.index("{", start) + 1:]
    lines, stack = [], []
    for line in body.splitlines():
        s = line.strip()
        if s.startswith("#"):
            word = s.split()
            if word[0] in ("#ifdef", "#ifndef", "#if"):
                check(word[0] != "#if", f"cannot evaluate {s}")
                check(word[1] in macros, f"unknown macro in {s}")
                stack.append(macros[word[1]] == (word[0] == "#ifdef"))
            elif word[0] == "#else":
                stack[-1] = not stack[-1]
            elif word[0] == "#endif":
                stack.pop()
            continue
        if all(stack):
            lines.append(line)
        if s == "};" and not stack:
            break
    text = re.sub(r"/\*.*?\*/", "", "\n".join(lines), flags=re.DOTALL)
    rows, row, field, depth = [], [], None, 0
    for tok in TOKEN.findall(text):
        if tok == "{":
            depth += 1
            row, field = [], None
        elif tok in (",", "}"):
            if depth == 1 and field is not None:
                row.append(field)
                field = None
            if tok == "}":
                depth -= 1
                if depth < 0:
                    break
                rows.append(row)
        elif tok == "|":
            pass
        elif tok.startswith('"'):
            field = (field or b"") + literal(tok)
        elif tok == "NULL":
            row.append(None)
        else:
            field = (field or []) + [tok]
    if not terminated:
        return rows
    check(rows and rows[-1][0] is None, f"{name} does not end with a NULL row")
    return rows[:-1]


def rust_bytes(b):
    out = []
    for c in b:
        if c in (0x22, 0x5C):
            out.append("\\" + chr(c))
        elif 0x20 <= c < 0x7F:
            out.append(chr(c))
        else:
            out.append(f"\\x{c:02x}")
    return 'b"' + "".join(out) + '"'


def flags(names, known, ty):
    if names == ["0"]:
        return f"{ty}::NONE"
    check(all(n in known for n in names), f"unknown flags {names}")
    fields = ", ".join(f"{known[n]}: true" for n in names)
    return f"{ty} {{ {fields}, ..{ty}::NONE }}"


def code(names, codes):
    check(len(names) == 1 and names[0] in codes, f"bad code {names}")
    if names[0] == "CURLUE_OK":
        return "None"
    kind = "".join(w.capitalize() for w in names[0][len("CURLUE_"):].split("_"))
    return f"Some(UrlErrorKind::{kind})"


def rows_of(rows, codes, what):
    out, dropped = [], 0
    for r in rows:
        check(len(r) == 5, f"{what} row has {len(r)} fields: {r}")
        url, expect, parse, get, ucode = r
        if set(get) & IDN_FLAGS:
            dropped += 1
            continue
        out.append(f"    Case {{ url: {rust_bytes(url)}, expect: {rust_bytes(expect)}, "
                   f"parse: {flags(parse, PARSE_FLAGS, 'ParseOptions')}, "
                   f"get: {flags(get, GET_FLAGS, 'GetOptions')}, code: {code(ucode, codes)} }},\n")
    return "".join(out), dropped


def main():
    abi = json.loads(ABI.read_text())["data"]["constants"]
    codes = {c["name"] for c in abi if c.get("enum") == "CURLUcode"}
    macros = defined()
    lib1560 = LIB1560.read_text(encoding="latin-1")
    parts, parts_dropped = rows_of(table(lib1560, "get_parts_list", macros), codes, "get_parts_list")
    urls, urls_dropped = rows_of(table(lib1560, "get_url_list", macros), codes, "get_url_list")
    pairs = table(UNIT1395.read_text(encoding="latin-1"), "pairs", macros, terminated=False)
    dots = "".join(
        f"    ({rust_bytes(i)}, {'None' if o is None else 'Some(' + rust_bytes(o) + ')'}),\n"
        for i, o in pairs)
    inputs = [LIB1560, UNIT1395, ABI, BASELINE, ROOT / "gen" / "genlib.py", HERE]
    genlib.write(OUT, f"""{genlib.header(HERE, inputs)}\
//! Test cases of C's URL API tests.

use super::{{GetOptions, ParseOptions}};
use crate::error::UrlErrorKind;

/// A URL, the flags it is parsed and got with, and what C gets: the parts
/// as lib1560's `checkparts` prints them, or the whole URL.
pub(super) struct Case {{
    pub(super) url: &'static [u8],
    pub(super) expect: &'static [u8],
    pub(super) parse: ParseOptions,
    pub(super) get: GetOptions,
    pub(super) code: Option<UrlErrorKind>,
}}

/// lib1560's `get_parts_list`; rows asking for IDN conversions left out: {parts_dropped}.
pub(super) static PARTS: &[Case] = &[
{parts}];

/// lib1560's `get_url_list`; rows asking for IDN conversions left out: {urls_dropped}.
pub(super) static URLS: &[Case] = &[
{urls}];

/// unit1395's pairs: a path, and the path with its dot segments removed,
/// or `None` if it has none.
pub(super) static DOT_SEGMENTS: &[(&[u8], Option<&[u8]>)] = &[
{dots}];
""")


if __name__ == "__main__":
    main()
