# Runs the C suite on build/c as baseline.py --run does, without rebuilding
# (this container's build/c is configured by hand: Ubuntu paths, no ngtcp2).
import json, os, sys, pathlib
ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "inventory/measure"))
sys.path.insert(0, str(ROOT / "inventory/gen"))
import common, suite
BUILD = common.ROOT / "build" / "c"
RESULTS = BUILD / "baseline"
meta = suite.run(BUILD, RESULTS, dict(os.environ))
(RESULTS / "run.json").write_text(json.dumps({"c-commit": common.c_commit(), **meta}, indent=1) + "\n")
print(meta)
