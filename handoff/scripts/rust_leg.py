# Lays out build/rust as score.py does and runs runtests.pl there on the tests named.
# usage: rust_leg.py [--no-build] [runtests args...]
import os, sys, subprocess, pathlib
ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "inventory/measure"))
sys.path.insert(0, str(ROOT / "inventory/gen"))
import score
args = sys.argv[1:]
if args[:1] == ["--no-build"]:
    args = args[1:]
else:
    score.assemble("rust", "rust")
    score.check_loading("rust")
env = score.environment()
r = subprocess.run(["perl", str(ROOT / "tests/runtests.pl"), *args],
                   cwd=score.BUILD / "tests", env=env)
sys.exit(r.returncode)
