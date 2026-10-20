#!/usr/bin/env python3
"""
Generate the order C's multi hands out transfer ids, for the arena's test.

Builds gen/csrc/mids.c against the C build's libcurlu with the flags of
its unit-test program, replays a seeded add/remove churn on the two kinds
of multi C makes (curl_easy_perform's, 16 rows, and curl_multi_init's,
128 rows), and writes each churn with the id C gave every add:

  crates/curl-core/src/id/c_order.rs

The churn grows the table, frees rows in a random order and wraps
around, so the slot policy and the growth policy of multi.c are both
exercised.
"""

import pathlib
import random
import shlex
import subprocess
import tempfile

import genlib
from genlib import ROOT, check

HERE = pathlib.Path(__file__).resolve()
HARNESS = ROOT / "gen" / "csrc" / "mids.c"
C_BUILD = ROOT / "build" / "c"
OUT = ROOT / "crates" / "curl-core" / "src" / "id" / "c_order.rs"
# The C code whose behaviour the table records.
C_SOURCES = [ROOT / "lib" / "multi.c", ROOT / "lib" / "uint-table.c"]
HANDLES = 1024


def unit_commands():
    """Return the compile and link commands of the C build's unit tests."""
    out = subprocess.run(["ninja", "-C", str(C_BUILD), "-t", "commands",
                          "tests/unit/units"], check=True,
                         capture_output=True, text=True).stdout
    lines = out.splitlines()
    compile_ = next((l for l in lines if "units.c.o -c " in l), None)
    link = next((l for l in lines if " -o tests/unit/units " in l), None)
    check(compile_ and link, "no unit-test commands in the C build")
    return shlex.split(compile_), shlex.split(link.strip(": &")
                                              .removesuffix("&& :"))


def flags():
    """Return the compiler flags and the libraries to link the harness."""
    compile_, link = unit_commands()
    cflags = []
    for i, arg in enumerate(compile_):
        if arg.startswith(("-D", "-I")):
            cflags.append(arg)
        elif arg == "-isystem":
            cflags += [arg, compile_[i + 1]]
    libs = []
    after = link[link.index("tests/unit/units") + 1:]
    for arg in after:
        if arg.endswith(".a") and not arg.startswith("/"):
            libs.append(str(C_BUILD / arg))
        elif arg.startswith(("-l", "-L", "-Wl,-rpath")) or arg.endswith(".so"):
            libs.append(arg)
    check(any(a.endswith("libcurlu-d.a") for a in libs),
          "the unit tests do not link libcurlu-d.a")
    return cflags, libs


def churn(rng, size):
    """Return add/remove operations that grow, fragment and wrap a table."""
    ops, live = [], []
    free = list(range(HANDLES))

    def add():
        h = free.pop(rng.randrange(len(free)))
        live.append(h)
        ops.append(("+", h))

    def remove():
        h = live.pop(rng.randrange(len(live)))
        free.append(h)
        ops.append(("-", h))

    while len(live) < size + size // 4:
        add()
    for _ in range(3 * size):
        if len(live) <= size // 4 or (len(live) < 2 * size and rng.random() < 0.5):
            add()
        else:
            remove()
    while len(live) > 3:
        remove()
    for _ in range(10):
        add()
    return ops


def replay(binary, size, ops):
    """Return the mid C gives each add of `ops`."""
    script = f"{size}\n" + "".join(f"{op} {h}\n" for op, h in ops)
    run = subprocess.run([str(binary)], input=script, capture_output=True,
                         text=True, check=False)
    check(run.returncode == 0, f"the harness failed on the {size}-row churn")
    mids = [int(m) for m in run.stdout.split()]
    check(len(mids) == sum(op == "+" for op, _ in ops),
          "the harness printed a mid per add")
    return mids


def rust(name, size, ops, mids):
    mids = iter(mids)
    items = [f"A({h}, {next(mids)})" if op == "+" else f"R({h})"
             for op, h in ops]
    rows = "".join("    " + ", ".join(items[i:i + 8]) + ",\n"
                   for i in range(0, len(items), 8))
    return f"pub(super) static {name}: Churn = Churn {{ rows: {size}, ops: &[\n{rows}] }};\n"


def main():
    cflags, libs = flags()
    rng = random.Random(1)
    with tempfile.TemporaryDirectory() as tmp:
        binary = pathlib.Path(tmp) / "mids"
        subprocess.run(["cc", *cflags, "-o", str(binary), str(HARNESS),
                        *libs], check=True)
        tables = []
        for name, size in (("PERFORM", 16), ("MULTI", 128)):
            ops = churn(rng, size)
            tables.append(rust(name, size, ops, replay(binary, size, ops)))
    inputs = [HARNESS, *C_SOURCES, ROOT / "gen" / "genlib.py", HERE]
    genlib.write(OUT, f"""{genlib.header(HERE, inputs)}\
//! The ids C's multi gave each add of a seeded add/remove churn, by
//! gen/csrc/mids.c: `A(handle, id)` adds a handle, `R(handle)` removes it.

use super::tests::{{Churn, Op::Add as A, Op::Remove as R}};

{"".join(tables)}""")


if __name__ == "__main__":
    main()
