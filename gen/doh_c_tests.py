#!/usr/bin/env python3
"""
Generate the DNS message tests' cases from C's own tests.

From tests/unit/unit1650.c (queries and answers), tests/unit/unit1655.c
(names for queries) and tests/unit/unit1658.c (HTTPS records):

  crates/curl-core/src/doh/c_tests.rs: their tables, the C strings evaluated
  as C evaluates them, cut to the size each row gives.
"""

import pathlib
import re

import genlib
from genlib import ROOT, check

HERE = pathlib.Path(__file__).resolve()
UNIT1650 = ROOT / "tests" / "unit" / "unit1650.c"
UNIT1655 = ROOT / "tests" / "unit" / "unit1655.c"
UNIT1658 = ROOT / "tests" / "unit" / "unit1658.c"
OUT = ROOT / "crates" / "curl-core" / "src" / "doh" / "c_tests.rs"

STRING = re.compile(r'"((?:[^"\\]|\\.)*)"')


def c_string(text):
    """The bytes of one C string literal's body: a hexadecimal escape takes
    every hexadecimal digit after it, as C's does."""
    out = bytearray()
    i = 0
    while i < len(text):
        c = text[i]
        if c != "\\":
            out.append(ord(c))
            i += 1
            continue
        i += 1
        c = text[i]
        if c == "x":
            m = re.match(r"[0-9a-fA-F]+", text[i + 1:])
            check(m, f"a bad escape in {text!r}")
            value = int(m[0], 16)
            check(value < 256, f"an escape out of range in {text!r}")
            out.append(value)
            i += 1 + len(m[0])
        elif c in "01234567":
            m = re.match(r"[0-7]{1,3}", text[i:])
            out.append(int(m[0], 8))
            i += len(m[0])
        else:
            check(c in '\\"', f"an unknown escape in {text!r}")
            out.append(ord(c))
            i += 1
    return bytes(out)


def strip_comments(src):
    return re.sub(r"/\*.*?\*/", "", src, flags=re.S)


def macros(src):
    """The string macros of unit1650, each expanded."""
    found = {}
    for m in re.finditer(r"#define (\w+)\s+((?:.*\\\n)*.*)", src):
        name, body = m[1], m[2].replace("\\\n", " ")
        if '"' in body or re.fullmatch(r"[\s\w]+", body):
            found[name] = body
    return found


def expand(text, known):
    """A concatenation of strings and macros as bytes."""
    out = b""
    for m in re.finditer(r'"((?:[^"\\]|\\.)*)"|([A-Z_][A-Z0-9_]*)', text):
        if m[2]:
            check(m[2] in known, f"an unknown macro {m[2]}")
            out += expand(known[m[2]], known)
        else:
            out += c_string(m[1])
    return out


def rust_bytes(b):
    return 'b"' + "".join(f"\\x{x:02x}" for x in b) + '"'


def rows_of(src, start):
    """The brace-delimited rows of the table starting at `start`."""
    body = src[src.index(start) + len(start):]
    rows, depth, begun, in_string, prev = [], 0, 0, False, ""
    for i, c in enumerate(body):
        if in_string:
            if c == '"' and prev != "\\":
                in_string = False
            prev = "" if prev == "\\" and c == "\\" else c
            continue
        if c == '"':
            in_string, prev = True, ""
        elif c == "{":
            if depth == 0:
                begun = i + 1
            depth += 1
        elif c == "}":
            if depth == 0:
                return rows
            depth -= 1
            if depth == 0:
                rows.append(body[begun:i])
    raise AssertionError("an unterminated table")


def split_fields(row):
    fields, depth, cur, in_string, prev = [], 0, "", False, ""
    for c in row:
        if in_string:
            cur += c
            if c == '"' and prev != "\\":
                in_string = False
            prev = "" if prev == "\\" and c == "\\" else c
            continue
        if c == '"':
            in_string, prev = True, ""
        if c == "," and depth == 0:
            fields.append(cur.strip())
            cur = ""
            continue
        cur += c
    if cur.strip():
        fields.append(cur.strip())
    return fields


KINDS = {"CURL_DNS_TYPE_A": "QueryType::A", "CURL_DNS_TYPE_AAAA": "QueryType::Aaaa"}
CODES = {
    "DOH_OK": "Ok",
    "DOH_DNS_BAD_LABEL": "Err(DohError::BadLabel)",
    "DOH_DNS_OUT_OF_RANGE": "Err(DohError::OutOfRange)",
    "DOH_TOO_SMALL_BUFFER": "Err(DohError::TooSmall)",
    "DOH_DNS_BAD_ID": "Err(DohError::BadId)",
    "DOH_DNS_BAD_RCODE": "Err(DohError::BadRcode)",
    "DOH_DNS_NXDOMAIN": "Err(DohError::NoSuchName)",
    "DOH_DNS_NAME_TOO_LONG": "Err(DohError::NameTooLong)",
}


def code(text):
    check(text in CODES, f"an unknown code {text}")
    return CODES[text]


def unit1650():
    src = UNIT1650.read_text()
    known = macros(src)
    clean = strip_comments(src)
    requests = ""
    for row in rows_of(clean, "static const struct dohrequest req[] = {"):
        name, kind, packet, _size, rc = split_fields(row)
        name = expand(name, known)
        want = "None" if packet == "NULL" else f"Some({rust_bytes(expand(packet, known))})"
        requests += f"    ({rust_bytes(name)}, {KINDS[kind]}, {want}, {code(rc)}),\n"
    check(requests.count("\n") == 3, "unit1650's requests did not parse")
    answers = ""
    for row in rows_of(clean, "static const struct dohresp resp[] = {"):
        packet, size, kind, rc, out = split_fields(row)
        size = eval(size, {"__builtins__": {}})
        whole = expand(packet, known)
        check(size <= len(whole) + 1, f"a row longer than its packet: {packet}")
        # A size past the literal reaches its terminating NUL.
        data = (whole + b"\0")[:size]
        want = "None" if out == "NULL" else f"Some({out})"
        answers += f"    ({rust_bytes(data)}, {KINDS[kind]}, {code(rc)}, {want}),\n"
    check(answers.count("\n") == 14, "unit1650's answers did not parse")
    full = expand("DNS_FOO_EXAMPLE_COM", known)
    return requests, answers, rust_bytes(full)


def unit1655():
    src = strip_comments(UNIT1655.read_text())
    names = {}
    for name in ("max", "toolong", "emptylabel", "outsizelabel"):
        m = re.search(rf"static const char {name}\[\] =\s*(.*?);", src, flags=re.S)
        check(m, f"unit1655's {name} did not parse")
        names[name] = expand(m[1], {})
    rows = ""
    for name, rc in re.findall(r"\{ (\w+), (DOH_\w+) \}", src):
        rows += f"    ({rust_bytes(names[name])}, {code(rc)}),\n"
    check(rows.count("\n") == 4, "unit1655's playlist did not parse")
    return rows


def unit1658():
    src = strip_comments(UNIT1658.read_text())
    rows = ""
    for row in rows_of(src, "static const struct test t[] = {"):
        name, dns, size, expect = split_fields(row)[:4]
        dns = dns.replace("(const unsigned char *)", "")
        size = int(size)
        whole = expand(dns, {})
        check(size <= len(whole) + 1, f"a row longer than its data: {name}")
        data = (whole + b"\0")[:size]
        want = b"".join(c_string(s) for s in STRING.findall(expect)).decode()
        rows += f"    ({name}, {rust_bytes(data)}, {want!r}),\n".replace(f"{want!r}", '"' + want + '"')
    check(rows.count("\n") == 30, f"unit1658's table did not parse: {rows.count(chr(10))}")
    return rows


def main():
    inputs = [UNIT1650, UNIT1655, UNIT1658, ROOT / "gen" / "genlib.py", HERE]
    requests, answers, full = unit1650()
    genlib.write(OUT, f"""{genlib.header(HERE, inputs)}\
//! Test cases of C's DNS message tests.

use super::{{DohError, QueryType}};

type Code = Result<(), DohError>;
type Query = (&'static [u8], QueryType, Option<&'static [u8]>, Code);
type Answer = (&'static [u8], QueryType, Code, Option<&'static str>);

/// unit1650: a name and type, the query C makes of them, and its result.
pub(super) static UNIT1650_QUERIES: &[Query] = &[
{requests.replace(", Ok)", ", Ok(()))")}];

/// unit1650: an answer, what it was asked, how C takes it, and, where the
/// test looks, the addresses and time to live it gave.
pub(super) static UNIT1650_ANSWERS: &[Answer] = &[
{answers.replace(", Ok,", ", Ok(()),")}];

/// unit1650: the answer whose every truncation fails.
pub(super) static UNIT1650_FULL: &[u8] = {full};

/// unit1655: a name for a query, and how C takes it.
pub(super) static UNIT1655_NAMES: &[(&[u8], Result<(), DohError>)] = &[
{unit1655().replace(", Ok)", ", Ok(()))")}];

/// unit1658: a test's name, an HTTPS record's data, and C's account of it.
pub(super) static UNIT1658: &[(&str, &[u8], &str)] = &[
{unit1658()}];
""")


if __name__ == "__main__":
    main()
