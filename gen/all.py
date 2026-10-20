#!/usr/bin/env python3
"""Run every generator of Rust code; `--check` fails on stale output."""

import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent

for gen in sorted(HERE.glob("*.py")):
    if gen.name in ("all.py", "genlib.py"):
        continue
    subprocess.run([sys.executable, str(gen), *sys.argv[1:]], check=True)
