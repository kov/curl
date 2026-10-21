#!/usr/bin/env python3
"""
Generate the progress code's test cases from C's own tests.

From tests/unit/unit1606.c, which runs the low-speed check over a second
a step, and tests/data/test1636, the expected output of unit1636.c, which
formats the meter's durations and byte counts:

  crates/curl-core/src/progress/c_tests.rs: unit1606's runs, and every
  duration and byte count test1636 shows with the text it shows for it.
"""

import pathlib
import re

import genlib
from genlib import ROOT, check

HERE = pathlib.Path(__file__).resolve()
UNIT1606 = ROOT / "tests" / "unit" / "unit1606.c"
TEST1636 = ROOT / "tests" / "data" / "test1636"
OUT = ROOT / "crates" / "curl-core" / "src" / "progress" / "c_tests.rs"

RUN = re.compile(r'runawhile\(easy, (\d+), (\d+), (\d+), (\d+)\) == (\d+),\s*"([^"]*)"')
SHOWN = re.compile(r"\s*(\d+) - (.*)")


def unit1606():
    rows = RUN.findall(UNIT1606.read_text())
    check(len(rows) == 6, "unit1606 does not have its six runs")
    return "".join(
        f"    Case1606 {{ time: {t}, limit: {lim}, speed: {sp}, dec: {dec}, "
        f'last_second: {end}, comment: "{comment}" }},\n'
        for t, lim, sp, dec, end, comment in rows)


def test1636():
    data = TEST1636.read_text()
    stdout = data[data.index("<stdout"):data.index("</stdout>")]
    sections = {"time2str": [], "max6out": []}
    current = None
    for line in stdout.splitlines()[1:]:
        if line in sections:
            current = sections[line]
        elif m := SHOWN.fullmatch(line):
            check(current is not None, "a test1636 value before its section")
            current.append((int(m[1]), m[2].replace("%SP", " ")))
        else:
            check(False, f"a test1636 line did not parse: {line!r}")
    check(all(sections.values()), "a test1636 section is empty")
    return [
        "".join(f'    ({n}, "{text}"),\n' for n, text in sections[name])
        for name in ("time2str", "max6out")
    ]


def main():
    runs = unit1606()
    durations, counts = test1636()
    inputs = [UNIT1606, TEST1636, ROOT / "gen" / "genlib.py", HERE]
    genlib.write(OUT, f"""{genlib.header(HERE, inputs)}\
//! Test cases of C's progress tests.

/// A run of unit1606: the low-speed time and limit, the speed it starts at
/// and how much it drops each second, and the last second it reaches (99
/// if it never times out).
pub(super) struct Case1606 {{
    pub(super) time: u16,
    pub(super) limit: u64,
    pub(super) speed: u64,
    pub(super) dec: u64,
    pub(super) last_second: u64,
    pub(super) comment: &'static str,
}}

pub(super) static UNIT1606: &[Case1606] = &[
{runs}];

/// test1636's durations, in seconds, and how the meter shows them.
pub(super) static TIME2STR: &[(i64, &str)] = &[
{durations}];

/// test1636's byte counts, and how the meter shows them.
pub(super) static MAX6OUT: &[(u64, &str)] = &[
{counts}];
""")


if __name__ == "__main__":
    main()
