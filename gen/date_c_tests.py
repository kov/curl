#!/usr/bin/env python3
"""
Generate the date parser's test cases from C's own tests.

From tests/libtest/lib517.c, which tests `curl_getdate`, and
tests/unit/unit4781.c, which tests the names of days, months and time
zones:

  crates/curl-core/src/date/c_tests.rs: lib517's dates and what C makes of
  them with a signed 64-bit `time_t`, and unit4781's names.
"""

import pathlib
import re

import genlib
from genlib import ROOT, check

HERE = pathlib.Path(__file__).resolve()
LIB517 = ROOT / "tests" / "libtest" / "lib517.c"
UNIT4781 = ROOT / "tests" / "unit" / "unit4781.c"
OUT = ROOT / "crates" / "curl-core" / "src" / "date" / "c_tests.rs"

# A row: the C string literal, copied as it is (its escapes are Rust's
# too), and the value.
ROW = re.compile(r'\{ ("(?:[^"\\]|\\.)*"), ([^}]*?) \}')

# The conditions lib517 tests, as this build has them.
CONDITIONS = {
    "#if SIZEOF_TIME_T > 4": True,
    "#ifndef HAVE_TIME_T_UNSIGNED": True,
}


def preprocess(lines):
    """The lines a 64-bit signed `time_t` build compiles."""
    stack = []
    for line in lines:
        s = line.strip()
        if s.startswith("#if"):
            check(s in CONDITIONS, f"an unknown condition in lib517: {s}")
            stack.append(CONDITIONS[s])
        elif s.startswith("#else"):
            stack[-1] = not stack[-1]
        elif s.startswith("#endif"):
            stack.pop()
        elif all(stack):
            yield line


def value(text):
    """A row's value as an integer: C's casts and suffixes removed."""
    text = re.sub(r"\(time_t\)", "", text).strip()
    text = re.sub(r"LL$", "", text)
    return int(text)


def lib517():
    src = LIB517.read_text()
    table = src[src.index("static const struct dcheck dates[] = {"):]
    table = table[:table.index("{ NULL, 0 }")]
    rows = [m for line in preprocess(table.splitlines()) for m in ROW.findall(line)]
    check(len(rows) > 150, "lib517's rows did not parse")
    return "".join(f"    ({literal}, {value(v)}),\n" for literal, v in rows)


def unit4781(name):
    src = UNIT4781.read_text()
    table = src[src.index(f"static const struct day {name}[] = {{"):]
    table = table[:table.index("};")]
    rows = ROW.findall(table)
    check(len(rows) == table.count('{ "'), f"a unit4781 {name} row did not parse")
    return "".join(f"    ({literal}, {int(v)}),\n" for literal, v in rows)


def main():
    inputs = [LIB517, UNIT4781, ROOT / "gen" / "genlib.py", HERE]
    genlib.write(OUT, f"""{genlib.header(HERE, inputs)}\
//! Test cases of C's date tests.

/// lib517: a date, and the seconds `curl_getdate` makes of it with a
/// signed 64-bit `time_t` (-1: not a date).
pub(super) static LIB517: &[(&str, i64)] = &[
{lib517()}];

/// unit4781: names of days and what they are, 0 for Monday (-1: none).
pub(super) static UNIT4781_DAYS: &[(&str, i32)] = &[
{unit4781("days")}];

/// unit4781: names of months, 0 for January (-1: none).
pub(super) static UNIT4781_MONTHS: &[(&str, i32)] = &[
{unit4781("months")}];

/// unit4781: names of time zones and the seconds to add for UTC (-1:
/// none).
pub(super) static UNIT4781_ZONES: &[(&str, i32)] = &[
{unit4781("timezones")}];
""")


if __name__ == "__main__":
    main()
