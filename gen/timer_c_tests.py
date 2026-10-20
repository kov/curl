#!/usr/bin/env python3
"""
Generate the transfer timers' test cases from C's own tests.

From tests/unit/unit1303.c, which tests the time left of a transfer, and
tests/data/test1309, the expected output of unit1309.c, which tests the
timer tree:

  crates/curl-core/src/multi/timers/c_tests.rs: unit1303's cases, and the
  order unit1309 sees transfers come due in, each with the time of the pass
  that found it due.
"""

import pathlib
import re

import genlib
from genlib import ROOT, check

HERE = pathlib.Path(__file__).resolve()
UNIT1303 = ROOT / "tests" / "unit" / "unit1303.c"
TEST1309 = ROOT / "tests" / "data" / "test1309"
OUT = ROOT / "crates" / "curl-core" / "src" / "multi" / "timers" / "c_tests.rs"

ROW = re.compile(r'\{\s*BASE \+ (\d+),\s*(\d+),\s*(\d+),\s*(\d+),\s*(TRUE|FALSE),'
                 r'\s*(-?\d+),\s*"([^"]*)"\s*\}')


def unit1303():
    src = UNIT1303.read_text()
    base = int(re.search(r"#define BASE (\d+)", src)[1])
    table = src[src.index("static const struct timetest run[] = {"):]
    table = table[:table.index("};")]
    rows = ROW.findall(table)
    check(len(rows) == table.count("{BASE"), "a unit1303 row did not parse")
    out = "".join(
        f"    Case1303 {{ now_s: {base + int(s)}, now_us: {us}, timeout_ms: {t}, "
        f"connect_timeout_ms: {c}, connecting: {conn.lower()}, result: {r}, "
        f'comment: "{comment}" }},\n'
        for s, us, t, c, conn, r, comment in rows)
    return base, out, len(rows)


def unit1309():
    data = TEST1309.read_text()
    stdout = data[data.index("<stdout>"):data.index("</stdout>")]
    copies, shared, now = [], [], None
    for line in stdout.splitlines():
        if m := re.fullmatch(r"Removing nodes not larger than (\d+)", line):
            now = int(m[1])
        elif m := re.fullmatch(r"removed payload (\d+)\[(\d+)\]", line):
            check(not shared, "a copies line after the shared-key lines")
            copies.append(f"({now}, {m[1]}, {m[2]})")
        elif m := re.fullmatch(r"removed payload (\d+)\[timeout=(\d+)\]", line):
            shared.append(f"({now}, {m[1]}, {m[2]})")
    check(copies and shared, "no removal lines in test1309")
    return copies, shared


def table(rows):
    return "".join(f"    {r},\n" for r in rows)


def main():
    base, cases, n = unit1303()
    copies, shared = unit1309()
    inputs = [UNIT1303, TEST1309, ROOT / "gen" / "genlib.py", HERE]
    genlib.write(OUT, f"""{genlib.header(HERE, inputs)}\
//! Test cases of C's timer tests.

/// unit1303's `BASE`: the second the transfer starts at.
pub(super) const UNIT1303_BASE: u64 = {base};

/// A row of unit1303: the time, the limits, the phase, and the
/// milliseconds left (0 for no limit, negative once passed).
pub(super) struct Case1303 {{
    pub(super) now_s: u64,
    pub(super) now_us: u64,
    pub(super) timeout_ms: u64,
    pub(super) connect_timeout_ms: u64,
    pub(super) connecting: bool,
    pub(super) result: i64,
    pub(super) comment: &'static str,
}}

/// unit1303's {n} cases.
pub(super) static UNIT1303: &[Case1303] = &[
{cases}];

/// unit1309, with each key queued 1 to 3 times: the pass's time, the key
/// and the copy, in the order test1309 expects them out.
pub(super) static UNIT1309_DUE_WITH_COPIES: &[(u64, u64, u64)] = &[
{table(copies)}];

/// unit1309, with keys shared by several transfers: the pass's time, the
/// transfer and its key, in the order test1309 expects them out.
pub(super) static UNIT1309_DUE_SHARED: &[(u64, u64, u64)] = &[
{table(shared)}];
""")


if __name__ == "__main__":
    main()
